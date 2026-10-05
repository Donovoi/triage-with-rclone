#!/usr/bin/env python3
"""Stage only three fixed public JDK metadata files in an owned private lease.

No images/layers or runtime dependencies are fetched or executed. Anonymous
registry authorization exists only in the bounded worker's memory. Never upload
the raw files, which may contain public account identifiers. Only report is safe
for publication. Metadata identity is not image/runtime execution evidence.
"""
import argparse
import copy
import datetime as dt
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import platform
import re
import shutil
import ssl
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

TOKEN_URL = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/eclipse-temurin:pull"
MANIFEST_HASH = "e1c09a9ee23feb81f94016547826c1e694086cd927356fb57fccc312fcc32f85"
CONFIG_HASH = "d0e6e16acb7f941e5206d99ec38e5bba18545c43462541958f84b22e0fc006e8"
SOURCE_HASH = "109562d9f45342ba0a5dbd16a35f20d96d7c667367b2e151c998ca57aa252fbf"
FILES = (
    ("jdk-manifest.json", "https://registry-1.docker.io/v2/library/eclipse-temurin/manifests/sha256:" + MANIFEST_HASH, MANIFEST_HASH, 65536),
    ("jdk-config.json", "https://registry-1.docker.io/v2/library/eclipse-temurin/blobs/sha256:" + CONFIG_HASH, CONFIG_HASH, 65536),
    ("jdk-source-Dockerfile.txt", "https://raw.githubusercontent.com/adoptium/containers/511f9356dc4d50932a0a5f8cfb0f87ed1aef4f07/17/jdk/ubuntu/noble/Dockerfile", SOURCE_HASH, 65536),
)
DEADLINE_SECONDS = 90
CA_FILE = "/etc/ssl/certs/ca-certificates.crt"
CDN_HOST = "production.cloudfront.docker.com"
CODES = frozenset({"metadata_host_invalid", "metadata_redirect_rejected", "metadata_response_invalid",
                   "metadata_auth_invalid", "metadata_hash_mismatch", "metadata_fetch_failed", "metadata_timeout",
                   "metadata_worker_failed", "metadata_source_changed", "metadata_path_invalid", "metadata_lease_reused",
                   "metadata_consumer_failed", "metadata_children_cleanup_failed", "metadata_temporary_cleanup_failed"})


class MetadataError(Exception):
    def __init__(self, code):
        if code not in CODES:
            raise ValueError("unknown_metadata_code")
        self.code = code
        super().__init__(code)


def need(condition, code):
    if not condition:
        raise MetadataError(code)


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def hosted_guard():
    need(platform.system() == "Linux" and platform.machine() == "x86_64" and os.getuid() != 0
         and os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
         and os.environ.get("RUNNER_OS") == "Linux", "metadata_host_invalid")


def file_bytes(path, limit):
    path = Path(path)
    need(path.is_absolute(), "metadata_path_invalid")
    for ancestor in (path.parent, *path.parent.parents):
        info = ancestor.lstat()
        need(stat.S_ISDIR(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400, "metadata_path_invalid")
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= limit
         and not getattr(info, "st_file_attributes", 0) & 0x400, "metadata_path_invalid")
    return path.read_bytes()


def source_hash():
    return hashlib.sha256(file_bytes(Path(__file__).absolute(), 128 * 1024)).hexdigest()


def write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        # urllib returns the original redirect as HTTPError; never auto-follow.
        return None


def config_redirect(url, status, headers):
    # Root's metadata-only preflight observed precisely this config-blob hop.
    # Docker lists this CDN: https://docs.docker.com/desktop/enterprise/allow-list/
    locations = headers.get_all("Location", [])
    need(url == FILES[1][1] and status == 307 and len(locations) == 1, "metadata_redirect_rejected")
    target = locations[0]
    need(type(target) is str and 1 <= len(target) <= 8192
         and all(33 <= ord(char) <= 126 for char in target) and "\\" not in target, "metadata_redirect_rejected")
    try:
        parsed = urllib.parse.urlsplit(target)
    except ValueError:
        raise MetadataError("metadata_redirect_rejected") from None
    need(parsed.scheme == "https" and parsed.netloc in {CDN_HOST, CDN_HOST + ":443"}
         and not parsed.fragment and parsed.path.startswith("/"), "metadata_redirect_rejected")
    return target


def get_bytes(opener, url, maximum, deadline, *, token=None):
    need(url == TOKEN_URL or url in {item[1] for item in FILES}, "metadata_response_invalid")
    need(token is None or url in {FILES[0][1], FILES[1][1]}, "metadata_auth_invalid")
    headers = {"Accept-Encoding": "identity", "Accept": "application/json"}
    if url == FILES[0][1]:
        headers["Accept"] = "application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json"
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    need(time.monotonic() < deadline, "metadata_timeout")
    request = urllib.request.Request(url, headers=headers, method="GET")
    redirected = None
    try:
        response = opener.open(request, timeout=15)
    except urllib.error.HTTPError as error:
        try:
            if error.code in (301, 302, 303, 307, 308):
                redirected = config_redirect(url, error.code, error.headers)
            else:
                raise MetadataError("metadata_response_invalid") from None
        finally:
            error.close()
    if redirected is not None:
        # Explicit new request: no Authorization, cookies or inherited headers.
        need(time.monotonic() < deadline, "metadata_timeout")
        request = urllib.request.Request(redirected, headers={"Accept-Encoding": "identity"}, method="GET")
        try:
            response = opener.open(request, timeout=15)
        except urllib.error.HTTPError as error:
            code = "metadata_redirect_rejected" if error.code in (301, 302, 303, 307, 308) else "metadata_response_invalid"
            error.close()
            raise MetadataError(code) from None
        url = redirected
    with response:
        need(response.status == 200 and response.geturl() == url, "metadata_response_invalid")
        encoding = response.headers.get_all("Content-Encoding", [])
        lengths = response.headers.get_all("Content-Length", [])
        need(encoding in ([], ["identity"]) and len(lengths) <= 1
             and (not lengths or re.fullmatch(r"[0-9]{1,8}", lengths[0])), "metadata_response_invalid")
        expected = int(lengths[0]) if lengths else None
        need(expected is None or 0 < expected <= maximum, "metadata_response_invalid")
        result = bytearray()
        while True:
            need(time.monotonic() < deadline, "metadata_timeout")
            chunk = response.read1(min(16384, maximum + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
            need(len(result) <= maximum, "metadata_response_invalid")
        need(result and (expected is None or len(result) == expected), "metadata_response_invalid")
        return bytes(result)


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "metadata_auth_invalid")
        result[key] = value
    return result


def parse_token(data):
    try:
        value = json.loads(data, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(MetadataError("metadata_auth_invalid")))
        need(type(value) is dict and not set(value) - {"token", "access_token", "expires_in", "issued_at"}, "metadata_auth_invalid")
        token = value.get("token", value.get("access_token"))
        need(type(token) is str and 16 <= len(token) <= 16384
             and re.fullmatch(r"[A-Za-z0-9._~+/=-]+", token), "metadata_auth_invalid")
        need(all(value[name] == token for name in ("token", "access_token") if name in value), "metadata_auth_invalid")
        if "expires_in" in value:
            need(type(value["expires_in"]) is int and 1 <= value["expires_in"] <= 3600, "metadata_auth_invalid")
        if "issued_at" in value:
            need(type(value["issued_at"]) is str and len(value["issued_at"]) <= 40, "metadata_auth_invalid")
        return token
    except (ValueError, TypeError, UnicodeError):
        raise MetadataError("metadata_auth_invalid") from None


def fetch_worker(directory):
    root, error = Path(directory), None
    try:
        context = ssl.create_default_context(cafile=CA_FILE)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                             urllib.request.HTTPSHandler(context=context))
        deadline = time.monotonic() + DEADLINE_SECONDS
        token = parse_token(get_bytes(opener, TOKEN_URL, 32768, deadline))
        for index, (name, url, expected, maximum) in enumerate(FILES):
            data = get_bytes(opener, url, maximum, deadline, token=token if index < 2 else None)
            need(hashlib.sha256(data).hexdigest() == expected, "metadata_hash_mismatch")
            write_new(root / name, data)
        token = None
    except MetadataError as exc:
        error = exc.code
    except BaseException:
        error = "metadata_fetch_failed"
    try:
        write_new(root / "status.json", json.dumps({"error": error}, separators=(",", ":")).encode("ascii"))
    except BaseException:
        raise SystemExit(1) from None


def run_worker(root, cleanup):
    process = multiprocessing.get_context("fork").Process(target=fetch_worker, args=(str(root),), daemon=True)
    started, error = False, None
    try:
        process.start()
        started = True
        cleanup["children_stopped"] = False
        process.join(DEADLINE_SECONDS)
        if process.is_alive():
            error = "metadata_timeout"
        elif process.exitcode != 0:
            error = "metadata_worker_failed"
    finally:
        if started:
            if process.is_alive():
                process.terminate()
                process.join(3)
            if process.is_alive():
                process.kill()
                process.join(3)
            if process.is_alive():
                raise MetadataError("metadata_children_cleanup_failed")
            cleanup["children_stopped"] = True
        process.close()
    if error:
        raise MetadataError(error)
    value = json.loads(file_bytes(root / "status.json", 128), object_pairs_hook=unique)
    need(type(value) is dict and set(value) == {"error"}
         and (value["error"] is None or type(value["error"]) is str and value["error"] in CODES), "metadata_worker_failed")
    if value["error"]:
        raise MetadataError(value["error"])


def verified_files(root):
    result = {}
    for name, _, expected, limit in FILES:
        data = file_bytes(root / name, limit)
        actual = hashlib.sha256(data).hexdigest()
        need(actual == expected, "metadata_hash_mismatch")
        result[name] = {"sha256": actual, "bytes": len(data)}
    return result


def remove_owned(root, identity):
    info = root.lstat()
    need(stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == identity
         and not getattr(info, "st_file_attributes", 0) & 0x400, "metadata_temporary_cleanup_failed")
    shutil.rmtree(root)
    need(not root.exists() and not root.is_symlink(), "metadata_temporary_cleanup_failed")


class JdkMetadataLease:
    def __init__(self):
        self.root = None
        self._identity = None
        self._used = False
        self._ready = False
        self._umask = None
        self._clock = None
        self._report = {"schema_version": 1, "scope": "jdk_metadata_staging", "ledger_eligible": False,
                        "started_utc": None, "finished_utc": None, "duration_seconds": None,
                        "source_sha256": None, "files": {}, "metadata_only": True,
                        "images_pulled": False, "runtime_executed": False, "success": False, "errors": [],
                        "cleanup": {"children_stopped": True, "temporary_removed": True}}

    @property
    def paths(self):
        need(self._ready and self._report["finished_utc"] is None, "metadata_path_invalid")
        return tuple(self.root / item[0] for item in FILES)

    @property
    def report(self):
        return copy.deepcopy(self._report)

    def _record(self, error):
        code = getattr(error, "code", None)
        self._report["errors"].append(code if type(code) is str and code in CODES else "metadata_fetch_failed")

    def __enter__(self):
        need(not self._used, "metadata_lease_reused")
        self._used = True
        self._clock = time.monotonic()
        self._report["started_utc"] = utc_now()
        self._umask = os.umask(0o077)
        failed = False
        try:
            hosted_guard()
            self._report["source_sha256"] = source_hash()
            self.root = Path(tempfile.mkdtemp(prefix="hdfs-jdk-metadata-", dir="/tmp"))
            self._report["cleanup"]["temporary_removed"] = False
            info = self.root.lstat()
            self._identity = info.st_dev, info.st_ino
            need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.getuid(), "metadata_path_invalid")
            run_worker(self.root, self._report["cleanup"])
            self._report["files"] = verified_files(self.root)
            self._ready = True
        except BaseException as error:
            self._record(error)
            failed = True
        if failed:
            self._finish()
            raise MetadataError(self._report["errors"][0]) from None
        return self

    def _finish(self):
        if self.root is not None and self._report["cleanup"]["children_stopped"]:
            try:
                remove_owned(self.root, self._identity)
                self._report["cleanup"]["temporary_removed"] = True
            except BaseException:
                self._report["errors"].append("metadata_temporary_cleanup_failed")
        elif self.root is not None:
            self._report["errors"].append("metadata_temporary_cleanup_failed")
        if not self._report["cleanup"]["children_stopped"] and "metadata_children_cleanup_failed" not in self._report["errors"]:
            self._report["errors"].append("metadata_children_cleanup_failed")
        if self._umask is not None:
            os.umask(self._umask)
            self._umask = None
        self._report["finished_utc"] = utc_now()
        self._report["duration_seconds"] = round(time.monotonic() - self._clock, 6)
        self._report["success"] = self._ready and not self._report["errors"] and all(self._report["cleanup"].values())

    def __exit__(self, kind, error, traceback):
        if kind is not None:
            self._report["errors"].append("metadata_consumer_failed")
        try:
            need(verified_files(self.root) == self._report["files"], "metadata_hash_mismatch")
            need(source_hash() == self._report["source_sha256"], "metadata_source_changed")
        except BaseException as failure:
            self._record(failure)
        self._finish()
        if kind is None and not self._report["success"]:
            raise MetadataError(self._report["errors"][0]) from None
        return False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        need(args.report.is_absolute(), "metadata_path_invalid")
        for parent in (args.report.parent, *args.report.parent.parents):
            need(stat.S_ISDIR(parent.lstat().st_mode), "metadata_path_invalid")
        fd = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except (OSError, MetadataError):
        print("report_create_failed", file=sys.stderr)
        return 1
    lease = JdkMetadataLease()
    try:
        with os.fdopen(fd, "w", encoding="ascii", newline="\n") as output:
            try:
                with lease:
                    pass
            except MetadataError:
                pass
            json.dump(lease.report, output, sort_keys=True, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        print("report_write_failed", file=sys.stderr)
        return 1
    return 0 if lease.report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
