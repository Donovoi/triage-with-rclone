#!/usr/bin/env python3
"""Verify fixed public Maven bytes on a hosted Linux runner; never run Maven.

Only the sanitized report may be uploaded. All downloaded bytes, the isolated
public keyring and raw GPG status/diagnostics are deleted with the owned tempdir.
This is bootstrap integrity evidence, not resolver, HDFS or ledger evidence.
"""
import argparse
import datetime as dt
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request

VERSION = "3.9.16"
BASE = "https://downloads.apache.org/maven/maven-3/3.9.16/binaries/apache-maven-3.9.16-bin.tar.gz"
ARCHIVE_SHA512 = "831a8591fe20c8243b1dbe7d71e3244f31d1665b0804b2e825e38cbbe5ce0cafb8338851f90780735568773e0a6cd07bbec107cda0b896b008b861075358b6f6"
FINGERPRINT = "84789D24DF77A32433CE1F079EB80E92EB2135B1"
# Reviewed official public bytes, not values obtained from the download itself.
INPUTS = {
    "archive": ("maven.tar.gz", BASE, 64 * 1024 * 1024, "sha512", ARCHIVE_SHA512),
    "signature": ("maven.tar.gz.asc", BASE + ".asc", 16384, "sha256", "a034782f2cab6a037143d3e4a703804a9280fcbb28b0b97a5ea8dae79ebcba39"),
    "keys": ("maven-KEYS.txt", "https://downloads.apache.org/maven/KEYS", 1024 * 1024, "sha256", "1e53a10e6b65c64ae0f5a241c8ef289c7578f1109d8a78512dff7de2b29117b3"),
}
FETCH_SECONDS = 240
GPG_SECONDS = 45
LOG_LIMIT = 1024 * 1024
GPG = "/usr/bin/gpg"
CA_FILE = "/etc/ssl/certs/ca-certificates.crt"
CODES = frozenset({
    "host_not_supported", "source_invalid", "source_changed", "temporary_failed",
    "download_failed", "download_timeout", "download_worker_failed", "download_invalid",
    "checksum_mismatch", "gpg_unavailable", "gpg_failed", "gpg_timeout",
    "gpg_output_limit", "gpg_import_failed", "gpg_status_invalid", "signature_invalid",
    "children_cleanup_failed", "temporary_cleanup_failed", "verification_failed",
})


class Failure(Exception):
    def __init__(self, code):
        if code not in CODES:
            raise ValueError("unknown_error_code")
        self.code = code
        super().__init__(code)


def need(condition, code):
    if not condition:
        raise Failure(code)


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def regular(path, maximum):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
         and 0 < info.st_size <= maximum, "source_invalid")
    return info


def digest(path, algorithm="sha256"):
    value = hashlib.new(algorithm)
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            value.update(chunk)
    return value.hexdigest()


def hosted_guard():
    need(platform.system() == "Linux" and platform.machine() == "x86_64"
         and os.getuid() != 0 and os.environ.get("GITHUB_ACTIONS") == "true"
         and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
         and os.environ.get("RUNNER_OS") == "Linux", "host_not_supported")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Failure("download_invalid")


def fetch_one(root, spec, opener, deadline):
    name, url, limit, _, _ = spec
    need(time.monotonic() < deadline, "download_timeout")
    request = urllib.request.Request(url, headers={"Accept-Encoding": "identity"}, method="GET")
    with opener.open(request, timeout=20) as response:
        need(response.status == 200 and response.geturl() == url, "download_invalid")
        need(response.headers.get("Content-Encoding", "identity") == "identity", "download_invalid")
        lengths = response.headers.get_all("Content-Length", [])
        need(len(lengths) <= 1 and (not lengths or re.fullmatch(r"[0-9]{1,10}", lengths[0])), "download_invalid")
        expected = int(lengths[0]) if lengths else None
        need(expected is None or 0 < expected <= limit, "download_invalid")
        size = 0
        fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as target:
            while True:
                need(time.monotonic() < deadline, "download_timeout")
                chunk = response.read1(min(65536, limit + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                need(size <= limit, "download_invalid")
                target.write(chunk)
            need(size > 0 and (expected is None or size == expected), "download_invalid")
            target.flush()
            os.fsync(target.fileno())


def download_worker(directory):
    """No exception text leaves this worker; its parent enforces wall time."""
    root = Path(directory)
    code = None
    try:
        # Explicit installed trust store avoids SSL_CERT_FILE/SSL_CERT_DIR overrides.
        context = ssl.create_default_context(cafile=CA_FILE)
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=context))
        deadline = time.monotonic() + FETCH_SECONDS
        for spec in INPUTS.values():
            fetch_one(root, spec, opener, deadline)
    except Failure as exc:
        code = exc.code
    except BaseException:
        code = "download_failed"
    try:
        with (root / "fetch-status.json").open("x", encoding="ascii") as output:
            json.dump({"error": code}, output)
    except BaseException:
        # multiprocessing handles SystemExit without printing a private traceback.
        raise SystemExit(1) from None


def stop_worker(process, activity):
    if process.is_alive():
        process.terminate()
        process.join(3)
    if process.is_alive():
        process.kill()
        process.join(3)
    if process.is_alive():
        raise Failure("children_cleanup_failed")
    activity["children_stopped"] = True
    process.close()


def download_inputs(root, activity):
    # This single-threaded Linux program forks before constructing SSL state.
    # Avoid spawn's additional long-lived resource-tracker process.
    process = multiprocessing.get_context("fork").Process(
        target=download_worker, args=(str(root),), daemon=True)
    started = False
    code = None
    try:
        process.start()
        started = True
        activity["children_stopped"] = False
        process.join(FETCH_SECONDS)
        if process.is_alive():
            code = "download_timeout"
        elif process.exitcode != 0:
            code = "download_worker_failed"
    finally:
        if started:
            stop_worker(process, activity)
        else:
            process.close()
    if code:
        raise Failure(code)
    status_path = root / "fetch-status.json"
    regular(status_path, 128)
    status = json.loads(status_path.read_text(encoding="ascii"))
    need(type(status) is dict and set(status) == {"error"}
         and status["error"] in {None, "download_failed", "download_timeout", "download_invalid"},
         "download_worker_failed")
    if status["error"]:
        raise Failure(status["error"])


def verify_hashes(root):
    results = {}
    for key, (name, url, limit, algorithm, expected) in INPUTS.items():
        path = root / name
        info = regular(path, limit)
        actual = {"url": url, "bytes": info.st_size,
                  "sha256": digest(path), "sha512": digest(path, "sha512")}
        need(actual[algorithm] == expected, "checksum_mismatch")
        results[key] = actual
    return results


def limit_gpg_files():
    # Linux-only child hook. Hard bound applies even between parent polling ticks.
    import resource
    resource.setrlimit(resource.RLIMIT_FSIZE, (LOG_LIMIT, LOG_LIMIT))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run_gpg(root, label, args, activity):
    info = regular(Path(GPG), 32 * 1024 * 1024)
    need(info.st_uid == 0 and not info.st_mode & 0o022, "gpg_unavailable")
    command = [GPG, "--no-options", "--homedir", str(root / "gnupg"),
               "--batch", "--no-tty", "--no-autostart", "--disable-dirmngr",
               "--no-auto-key-retrieve", "--no-auto-key-import", "--auto-key-locate", "clear",
               "--status-fd", "1", *args]
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(root), "GNUPGHOME": str(root / "gnupg"),
                   "LANG": "C", "LC_ALL": "C"}
    paths = [root / (label + ".status"), root / (label + ".stderr")]
    process = None
    code = None
    result = None
    with paths[0].open("xb") as output, paths[1].open("xb") as errors:
        try:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=errors,
                                       cwd=root, env=environment, start_new_session=True,
                                       preexec_fn=limit_gpg_files, close_fds=True)
            activity["children_stopped"] = False
            deadline = time.monotonic() + GPG_SECONDS
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    code = "gpg_timeout"
                    break
                if any(path.stat().st_size >= LOG_LIMIT for path in paths):
                    code = "gpg_output_limit"
                    break
                time.sleep(0.02)
        finally:
            if process is not None:
                # Also terminate any descendant in the owned group after parent exit.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    result = process.wait(timeout=3)
                    deadline = time.monotonic() + 3
                    while True:
                        try:
                            os.killpg(process.pid, 0)
                        except ProcessLookupError:
                            activity["children_stopped"] = True
                            break
                        if time.monotonic() >= deadline:
                            code = "children_cleanup_failed"
                            break
                        time.sleep(0.02)
                except subprocess.TimeoutExpired:
                    code = "children_cleanup_failed"
    if any(path.stat().st_size >= LOG_LIMIT for path in paths):
        code = code or "gpg_output_limit"
    if code:
        raise Failure(code)
    need(result == 0, "gpg_import_failed" if label == "import" else "signature_invalid")
    return paths[0].read_bytes()


def status_lines(data):
    need(0 < len(data) <= LOG_LIMIT, "gpg_status_invalid")
    lines = data.decode("utf-8", errors="strict").splitlines()
    need(all(line.startswith("[GNUPG:] ") for line in lines), "gpg_status_invalid")
    return [line[9:].split() for line in lines]


def verify_status(data):
    lines = status_lines(data)
    allowed = {"NEWSIG", "KEY_CONSIDERED", "SIG_ID", "GOODSIG", "VALIDSIG",
               "NOTATION_NAME", "NOTATION_FLAGS", "NOTATION_DATA", "POLICY_URL",
               "TRUST_UNDEFINED", "TRUST_MARGINAL", "TRUST_FULLY", "TRUST_ULTIMATE"}
    need(all(fields and fields[0] in allowed for fields in lines), "signature_invalid")
    valid = [fields[1:] for fields in lines if fields[0] == "VALIDSIG"]
    good = [fields[1:] for fields in lines if fields[0] == "GOODSIG"]
    # Exact pinned v4 RSA/SHA512 binary signature, including primary-key identity.
    need(len(valid) == 1 and len(good) == 1 and good[0]
         and good[0][0] == FINGERPRINT[-16:], "signature_invalid")
    fields = valid[0]
    need(len(fields) == 10 and fields[0] == FINGERPRINT and fields[9] == FINGERPRINT
         and fields[1] == "2026-05-13" and fields[2] == "1778708341"
         and fields[3:9] == ["0", "4", "0", "1", "10", "00"], "signature_invalid")


def signature_check(root, activity):
    (root / "gnupg").mkdir(mode=0o700)
    imported = status_lines(run_gpg(root, "import", ["--import", str(root / INPUTS["keys"][0])], activity))
    need(any(len(fields) == 3 and fields[0] == "IMPORT_OK" and fields[2] == FINGERPRINT
             for fields in imported), "gpg_import_failed")
    need(not any(fields and fields[0] in {"FAILURE", "ERROR", "IMPORT_PROBLEM"} for fields in imported),
         "gpg_import_failed")
    verify_status(run_gpg(root, "verify", ["--verify", str(root / INPUTS["signature"][0]),
                                          str(root / INPUTS["archive"][0])], activity))


def remove_owned(root, identity):
    info = root.lstat()
    need(stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == identity,
         "temporary_cleanup_failed")
    shutil.rmtree(root)
    need(not root.exists() and not root.is_symlink(), "temporary_cleanup_failed")


def run():
    started = time.monotonic()
    report = {
        "schema_version": 1, "scope": "hdfs_bootstrap_integrity_verification", "ledger_eligible": False,
        "started_utc": utc_now(), "finished_utc": None, "duration_seconds": None,
        "source_sha256": None, "maven_version": VERSION, "publisher_fingerprint": FINGERPRINT,
        "publisher_trust_scope": "official_apache_https_published_key_no_out_of_band_identity_claim",
        "inputs": {}, "checks": {key: False for key in (
            "hosted_linux", "downloads_complete", "checksums_verified", "signature_verified", "source_preserved")},
        "cleanup": {"children_stopped": True, "temporary_removed": True}, "success": False, "errors": [],
    }
    root = None
    identity = None
    source = Path(__file__).absolute()
    old_umask = os.umask(0o077)
    try:
        hosted_guard()
        report["checks"]["hosted_linux"] = True
        regular(source, 128 * 1024)
        report["source_sha256"] = digest(source)
        root = Path(tempfile.mkdtemp(prefix="hdfs-bootstrap-", dir="/tmp"))
        info = root.lstat()
        identity = (info.st_dev, info.st_ino)
        report["cleanup"]["temporary_removed"] = False
        need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
             and info.st_uid == os.getuid(), "temporary_failed")
        download_inputs(root, report["cleanup"])
        report["checks"]["downloads_complete"] = True
        report["inputs"] = verify_hashes(root)
        report["checks"]["checksums_verified"] = True
        signature_check(root, report["cleanup"])
        report["checks"]["signature_verified"] = True
        need(verify_hashes(root) == report["inputs"], "checksum_mismatch")
        need(digest(source) == report["source_sha256"], "source_changed")
        report["checks"]["source_preserved"] = True
    except Failure as exc:
        report["errors"].append(exc.code)
    except BaseException:
        report["errors"].append("verification_failed")
    finally:
        if root is not None and report["cleanup"]["children_stopped"]:
            try:
                remove_owned(root, identity)
                report["cleanup"]["temporary_removed"] = True
            except BaseException:
                report["errors"].append("temporary_cleanup_failed")
        elif root is not None:
            # Never delete a directory that an unconfirmed child could still write.
            report["errors"].append("temporary_cleanup_failed")
        if not report["cleanup"]["children_stopped"] and "children_cleanup_failed" not in report["errors"]:
            report["errors"].append("children_cleanup_failed")
        os.umask(old_umask)
    report["finished_utc"] = utc_now()
    report["duration_seconds"] = round(time.monotonic() - started, 3)
    report["success"] = all(report["checks"].values()) and all(report["cleanup"].values()) and not report["errors"]
    return report


def report_fd(path):
    """Create-new report outside the owned tempdir; never follow path aliases."""
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise ValueError("report_path_invalid")
    for ancestor in (path.parent, *path.parent.parents):
        info = ancestor.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("report_path_invalid")
    return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        fd = report_fd(args.report)
    except (OSError, ValueError):
        print("report_create_failed", file=sys.stderr)
        return 1
    try:
        with os.fdopen(fd, "w", encoding="ascii", newline="\n") as output:
            report = run()
            json.dump(report, output, sort_keys=True, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        print("report_write_failed", file=sys.stderr)
        return 1
    return 0 if report["success"] else 1


if __name__ == "__main__":
    multiprocessing.freeze_support()
    raise SystemExit(main())
