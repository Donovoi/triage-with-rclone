#!/usr/bin/env python3
"""Account-free rclone backend protocol checks; never a hosted-provider verdict.

Only an explicitly supplied absolute, manifest-pinned rclone is executed. The
application under test is NOT executed by this layer. See protocol scope in the
receipt; rclone's SFTP/S3 servers are not independent conformance or vendor tests.
"""

import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
import zlib

from fixture_servers import FILES, State, probe_write_rejection, serve


BACKENDS = ("local", "http", "webdav", "ftp", "sftp", "s3", "archive")
HARNESS_FILES = ("fixture_servers.py", "run_lab.py")
MAX_OUTPUT = 2 * 1024 * 1024
COMMAND_TIMEOUT = 20


class LabError(Exception):
    """Only static error codes are exported, never child diagnostics."""


def digest(path):
    hasher = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def compute_harness_sha256(root):
    hasher = hashlib.sha256()
    for name in sorted(HARNESS_FILES):
        hasher.update(name.encode() + b"\0" + (Path(root) / name).read_bytes() + b"\0")
    return hasher.hexdigest()


def fixture_manifest():
    return [{"path": name, "size": len(body), "sha256": hashlib.sha256(body).hexdigest()}
            for name, body in sorted(FILES.items())]


def fixture_manifest_sha256():
    return hashlib.sha256(json.dumps(fixture_manifest(), separators=(",", ":")).encode()).hexdigest()


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def verified_runtime(path, manifest):
    path = Path(path)
    if not path.is_absolute() or not path.is_file():
        raise LabError("absolute_runtime_required")
    path = path.resolve(strict=True)
    pins = {}
    for line in Path(manifest).read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            key, sep, value = line.partition("=")
            if not sep or key in pins:
                raise LabError("invalid_runtime_manifest")
            pins[key] = value
    platform = "windows" if sys.platform == "win32" else "linux" if sys.platform == "linux" else None
    if platform is None:
        raise LabError("unsupported_platform")
    key = "RCLONE_EXE_SHA256" if platform == "windows" else "RCLONE_LINUX_EXE_SHA256"
    expected = pins.get(key, "")
    version = pins.get("RCLONE_VERSION", "")
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise LabError("invalid_runtime_manifest")
    if digest(path) != expected:
        raise LabError("runtime_hash_mismatch")
    return path, {"version": version, "sha256": expected}, platform


def isolated_environment(root):
    # Whitelist instead of a denylist: no cloud credentials, proxies, rclone
    # overrides, SSH agent, external command hooks, or systemd socket activation.
    env = {key: os.environ[key] for key in ("SystemRoot", "WINDIR", "SYSTEMROOT") if key in os.environ}
    for key in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TMP", "TEMP",
                "TMPDIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"):
        env[key] = str(root)
    env.update({"LANG": "C.UTF-8", "NO_PROXY": "*", "AWS_EC2_METADATA_DISABLED": "true"})
    return env


def write_private(path, data):
    path = Path(path)
    with path.open("xb") as handle:
        handle.write(data if isinstance(data, bytes) else data.encode())
    path.chmod(0o600)


def validate_report_path(path):
    path = Path(path)
    if not path.is_absolute() or not path.parent.is_dir() or path.exists() or path.is_symlink():
        raise LabError("new_absolute_report_required")
    if any(parent.is_symlink() for parent in (path.parent, *path.parents)):
        raise LabError("report_symlink_refused")
    return path


def atomic_report(path, report):
    """Publish fully written bytes without replacing any existing target."""
    path = validate_report_path(path)
    fd, temporary = tempfile.mkstemp(prefix=".provider-lab-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write((json.dumps(report, sort_keys=True, indent=2) + "\n").encode())
            handle.flush()
            os.fsync(handle.fileno())
        # Both NTFS and Linux support same-directory hardlinks. This fails closed
        # on unsupported filesystems or if another writer claimed the target.
        os.link(temporary, path)
    finally:
        os.unlink(temporary)


class Runtime:
    def __init__(self, original, identity, root):
        self.root = root
        self.binary = root / ("rclone.exe" if os.name == "nt" else "rclone")
        shutil.copyfile(original, self.binary)
        self.binary.chmod(0o700)
        if digest(self.binary) != identity["sha256"]:
            raise LabError("copied_runtime_hash_mismatch")
        self.env = isolated_environment(root)
        self.config = root / "empty.conf"
        write_private(self.config, "")
        self.children = []
        self.sequence = 0
        self.cache = root / "cache"
        self.cache.mkdir(mode=0o700)

    def start(self, args, config=None, notice=False):
        self.sequence += 1
        prefix = self.root / f"process-{self.sequence}"
        stdout = prefix.with_suffix(".out")
        stderr = prefix.with_suffix(".err")
        command = [str(self.binary), "--config", str(config or self.config),
                   "--cache-dir", str(self.cache), "--log-level", "NOTICE" if notice else "ERROR",
                   "--stats", "0", "--retries", "1", "--low-level-retries", "1",
                   "--contimeout", "3s", "--timeout", "5s", *args]
        with stdout.open("xb") as out, stderr.open("xb") as err:
            process = subprocess.Popen(command, cwd=self.root, env=self.env,
                                       stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                       creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW) if os.name == "nt" else 0,
                                       start_new_session=os.name != "nt")
        record = (process, stdout, stderr)
        self.children.append(record)
        return record

    @staticmethod
    def stop(record):
        process = record[0]
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(3)
        return process.returncode

    def run(self, args, config=None, timeout=COMMAND_TIMEOUT):
        record = self.start(args, config)
        process, stdout, stderr = record
        deadline = time.monotonic() + timeout
        try:
            while process.poll() is None:
                if stdout.stat().st_size + stderr.stat().st_size > MAX_OUTPUT:
                    raise LabError("child_output_limit")
                if time.monotonic() > deadline:
                    raise LabError("child_timeout")
                time.sleep(0.02)
            if stdout.stat().st_size + stderr.stat().st_size > MAX_OUTPUT:
                raise LabError("child_output_limit")
            return process.returncode, stdout.read_bytes(), stderr.read_bytes()
        finally:
            self.stop(record)

    def close(self):
        failed = False
        for record in self.children:
            try:
                self.stop(record)
            except (OSError, subprocess.TimeoutExpired):
                failed = True
        return not failed and all(record[0].poll() is not None for record in self.children)


def check(condition, code):
    if not condition:
        raise LabError(code)


def config_file(root, name, options):
    path = root / name
    # Only generated values enter this writer; never import external config.
    check(all("\n" not in str(value) and "\r" not in str(value) for value in options.values()), "invalid_fixture_option")
    write_private(path, "[Synthetic]\n" + "".join(f"{key} = {value}\n" for key, value in options.items()))
    return path


def prepare_files(root):
    root.mkdir(mode=0o700)
    for name, payload in FILES.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        write_private(path, payload)


def source_unchanged(root, expected=None):
    expected = fixture_manifest() if expected is None else expected
    actual = sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file())
    return actual == [item["path"] for item in expected] and all(
        not (root / item["path"]).is_symlink()
        and digest(root / item["path"]) == item["sha256"] for item in expected)


def served_source_unchanged(state, expected):
    actual = [{"path": name, "size": len(body), "sha256": hashlib.sha256(body).hexdigest()}
              for name, body in sorted(state.files.items())]
    return actual == expected


def listener_closed(port):
    with socket.socket() as probe:
        probe.settimeout(0.2)
        return probe.connect_ex(("127.0.0.1", port)) != 0


@contextmanager
def rclone_server(runtime, kind, source, user, password):
    args = ["serve", kind, str(source), "--addr", "127.0.0.1:0", "--read-only"]
    if kind == "sftp":
        # Empty string skips authorized_keys loading, avoiding the real user's
        # default file; all host keys are freshly generated in our private cache.
        args += ["--user", user, "--pass", password, "--authorized-keys", ""]
    else:
        args += ["--auth-key", user + "," + password]
    record = runtime.start(args, notice=True)
    port = None
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            check(record[0].poll() is None, "fixture_server_start_failed")
            check(record[2].stat().st_size < MAX_OUTPUT, "fixture_server_output_limit")
            message = record[2].read_text(errors="replace")
            # The address comes only from this owned process's startup output.
            match = re.search(r"(?:SFTP server listening on |Starting s3 server on \[?http://)127\.0\.0\.1:(\d+)", message, re.IGNORECASE)
            if match:
                port = int(match.group(1))
                check(0 < port < 65536, "invalid_fixture_port")
                break
            time.sleep(0.05)
        check(port is not None, "fixture_server_not_ready")
        yield port, record
    finally:
        runtime.stop(record)
        if port is not None:
            check(listener_closed(port), "fixture_listener_cleanup_failed")


def pin_sftp_key(runtime, port, directory):
    public_files = sorted((runtime.cache / "serve-sftp").glob("*.pub"))
    check(len(public_files) == 3, "missing_fixture_host_keys")
    lines = []
    for public in public_files:
        value = public.read_text().strip().split()
        check(len(value) >= 2 and value[0] in ("ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256"), "invalid_fixture_host_key")
        lines.append(f"[127.0.0.1]:{port} {value[0]} {value[1]}\n")
    path = directory / "known_hosts"
    write_private(path, "".join(lines))
    return path


def mismatched_sftp_key(known, port, directory):
    # Keep a valid SSH Ed25519 wire format but change the owned server's public
    # key bytes. A malformed key or unknown host must not satisfy this test.
    prefix = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"
    host = f"[127.0.0.1]:{port}"
    entries = [line.split() for line in known.read_text().splitlines()]
    entries = [entry for entry in entries if len(entry) == 3 and entry[:2] == [host, "ssh-ed25519"]]
    check(len(entries) == 1, "missing_fixture_ed25519_key")
    try:
        original = base64.b64decode(entries[0][2], validate=True)
    except ValueError:
        raise LabError("invalid_fixture_ed25519_key") from None
    check(len(original) == len(prefix) + 32 and original.startswith(prefix), "invalid_fixture_ed25519_key")
    changed = original[:-1] + bytes([original[-1] ^ 1])
    path = directory / "mismatched_known_hosts"
    write_private(path, f"{host} ssh-ed25519 {base64.b64encode(changed).decode()}\n")
    return path


def sftp_host_key_check(runtime, root, options, target, row):
    known = Path(options["known_hosts_file"])
    before = digest(known)
    mismatch = mismatched_sftp_key(known, int(options["port"]), root)
    # Credentials, endpoint, agent and shell settings remain identical to the
    # succeeding client. Only the trusted public key is different.
    config = config_file(root, "mismatched-host.conf", dict(options, known_hosts_file=str(mismatch)))
    destination = root / "host-key-mismatch-must-not-exist"
    for args in (["cat", target + "README-synthetic.txt"],
                 ["copyto", target + "README-synthetic.txt", str(destination)]):
        code, output, error = runtime.run(args, config)
        check(code != 0 and not output and not destination.exists(), "host_key_mismatch_returned_data")
        check(b"knownhosts: key mismatch" in error.lower(), "host_key_rejection_not_observed")
    check(digest(known) == before, "fixture_host_keys_changed")
    row["capabilities"]["host_key_rejection"] = "passed"


def stat_has_no_file(code, output):
    if code != 0:
        return True
    try:
        value = json.loads(output)
    except ValueError:
        return False
    # Object stores expose absent prefixes as virtual directories. A directory
    # stat cannot authorize a file acquisition; a reported file is a failure.
    return isinstance(value, dict) and value.get("IsDir") is True


def common_checks(runtime, root, good, bad, target, row, state=None, auth_marker=None, expected=None):
    expected = fixture_manifest() if expected is None else expected
    caps = row["capabilities"]
    if bad is not None:
        before = state.payload_bytes if state else 0
        denied = state.denied if state else 0
        code, output, error = runtime.run(["cat", target + "README-synthetic.txt"], bad)
        check(code != 0 and not output, "bad_auth_returned_data")
        if state:
            check(state.denied > denied and state.payload_bytes == before, "bad_auth_not_observed")
        else:
            check(any(marker in error.lower() for marker in auth_marker), "bad_auth_not_observed")
        caps["authentication_rejection"] = "passed"
    code, output, _ = runtime.run(["lsjson", "--recursive", "--files-only", "--no-modtime", "--no-mimetype", target], good)
    check(code == 0, "listing_failed")
    try:
        entries = json.loads(output)
        got = sorted((entry["Path"], entry["Size"], entry["IsDir"]) for entry in entries)
    except (KeyError, TypeError, ValueError):
        raise LabError("listing_invalid") from None
    check(got == [(item["path"], item["size"], False) for item in expected], "listing_mismatch")
    caps["listing"] = "passed"
    downloads = root / "downloads"
    downloads.mkdir(mode=0o700)
    source_fs, separator, source_prefix = target.partition(":")
    check(separator == ":" and bool(source_fs), "invalid_fixture_source")
    for index, item in enumerate(expected):
        # Match the application's split, including an absolute local path or
        # bucket prefix in the object name. Never list this broader fs root.
        exact_file_stat(runtime, good, source_fs + ":", source_prefix + item["path"], item["size"])
        destination = downloads / f"verified-{index}"
        code, _, _ = runtime.run(["copyto", target + item["path"], str(destination)], good)
        check(code == 0 and destination.is_file(), "download_failed")
        check(destination.stat().st_size == item["size"] and digest(destination) == item["sha256"], "download_hash_mismatch")
    caps["download_hash"] = "passed"
    missing = downloads / "missing-must-not-exist"
    code, output, _ = runtime.run(["lsjson", "--stat", target + "absent-synthetic.txt"], good)
    check(stat_has_no_file(code, output), "missing_stat_reported_file")
    # Some object stores interpret an absent source as an empty prefix. Force
    # an empty transfer to fail rather than treating that no-op as acquisition.
    code, _, _ = runtime.run(["copyto", "--error-on-no-transfer", target + "absent-synthetic.txt", str(missing)], good)
    check(code != 0 and not missing.exists(), "missing_object_accepted")
    caps["missing_object_rejection"] = "passed"
    if state and row["backend"] in ("http", "webdav"):
        state.mode = "truncate"
        truncated = downloads / "truncated-must-not-exist"
        code, _, _ = runtime.run(["copyto", target + "README-synthetic.txt", str(truncated)], good)
        check(code != 0 and not truncated.exists(), "truncated_object_accepted")
        caps["truncated_download_rejection"] = "passed"
        state.mode = "stall"
        cancelled = downloads / "cancelled-must-not-exist"
        record = runtime.start(["copyto", target + "README-synthetic.txt", str(cancelled)], good)
        try:
            check(state.stalled.wait(5), "cancellation_not_in_transfer")
        finally:
            runtime.stop(record)
            state.stopping.set()
        check(record[0].returncode != 0 and not cancelled.exists(), "cancelled_object_accepted")
        # Partial staging artifacts are never accepted and removed with the
        # owned temporary directory. This tests harness cancellation, not TUI.
        caps["cancellation_cleanup"] = "passed"


def archive_zip(payloads):
    """Reproducible bounded ZIP: no compression, external paths or timestamps."""
    directories = {"/".join(name.split("/")[:index]) + "/"
                   for name in payloads for index in range(1, len(name.split("/")))}
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        for name in sorted(set(payloads) | directories):
            entry = zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.compress_type = zipfile.ZIP_STORED
            entry.external_attr = ((0o40755 << 16) | 0x10) if name in directories else (0o100644 << 16)
            archive.writestr(entry, b"" if name in directories else payloads[name])
    return output.getvalue()


def corrupt_archive_member(original, name):
    # Corrupt only one stored member byte, leaving its recorded CRC and ZIP
    # directory intact. This must exercise CRC checking, not a parser failure.
    with zipfile.ZipFile(io.BytesIO(original)) as archive:
        entry = archive.getinfo(name)
        check(entry.compress_type == zipfile.ZIP_STORED and entry.file_size > 0, "invalid_archive_fixture")
        offset = entry.header_offset
    check(original[offset:offset + 4] == b"PK\x03\x04", "invalid_archive_fixture")
    name_size, extra_size = struct.unpack_from("<HH", original, offset + 26)
    start = offset + 30 + name_size + extra_size
    changed = bytearray(original)
    changed[start] ^= 1
    return bytes(changed)


def archive_inventory(output, payloads):
    """Validate exact entry identity, type, size and independently computed CRC."""
    directories = {"/".join(name.split("/")[:index])
                   for name in payloads for index in range(1, len(name.split("/")))}
    try:
        entries = json.loads(output)
        check(isinstance(entries, list), "archive_listing_invalid")
        check(len(entries) == len(payloads) + len(directories), "archive_listing_mismatch")
        seen = set()
        for entry in entries:
            name = entry["Path"]
            check(name not in seen, "archive_listing_mismatch")
            seen.add(name)
            if name in directories:
                check(entry["IsDir"] is True, "archive_listing_mismatch")
            else:
                check(name in payloads and entry["IsDir"] is False, "archive_listing_mismatch")
                check(type(entry["Size"]) is int and entry["Size"] == len(payloads[name]), "archive_listing_mismatch")
                check(entry["Hashes"]["crc32"] == f"{zlib.crc32(payloads[name]):08x}", "archive_crc32_mismatch")
        check(seen == set(payloads) | directories, "archive_listing_mismatch")
    except (KeyError, TypeError, ValueError):
        raise LabError("archive_listing_invalid") from None


def exact_copy(runtime, config, source_fs, source_name, destination_fs, destination_name):
    # In-process loopback RC opens one object; no network RC listener and no
    # copyto fallback that might recursively acquire a directory.
    return runtime.run(["rc", "--loopback", "operations/copyfile", f"srcFs={source_fs}",
                        f"srcRemote={source_name}", f"dstFs={destination_fs}",
                        f"dstRemote={destination_name}"], config)


def exact_file_stat(runtime, config, source_fs, source_name, expected_size):
    # Keep the filesystem root separate from the object. lsjson --stat combines
    # them before NewFs, which breaks archive members even with valid ZIP paths.
    code, output, _ = runtime.run(["rc", "--loopback", "operations/stat", f"fs={source_fs}",
                                   f"remote={source_name}", 'opt={"noModTime":true,"noMimeType":true,"filesOnly":true}'], config)
    check(code == 0, "exact_stat_failed")
    try:
        result = json.loads(output)
        item = result["item"]
        check(isinstance(item, dict) and item.get("IsDir") is False, "exact_stat_not_file")
        check(item.get("Path") == source_name, "exact_stat_path_mismatch")
        check(type(item.get("Size")) is int and item["Size"] == expected_size, "exact_stat_size_mismatch")
    except (KeyError, TypeError, ValueError):
        raise LabError("exact_stat_invalid") from None


def archive_checks(runtime, root, row):
    caps = row["capabilities"]
    payloads = dict(FILES)
    expected = {name: (len(body), hashlib.sha256(body).hexdigest()) for name, body in payloads.items()}
    original = archive_zip(payloads)
    check(original[-22:-18] == b"PK\x05\x06", "invalid_archive_fixture")
    containers = {"original": original,
                  "corrupt": corrupt_archive_member(original, "README-synthetic.txt"),
                  "truncated": original[:-22]}
    configs, preserved = {}, {}
    for kind, contents in containers.items():
        path = root / f"{kind}.zip"
        write_private(path, contents)
        config = config_file(root, f"{kind}.conf", {"type": "archive", "remote": path.as_posix()})
        configs[kind] = config
        preserved[path] = (contents, hashlib.sha256(contents).hexdigest())
        data = config.read_bytes()
        preserved[config] = (data, hashlib.sha256(data).hexdigest())
    good = configs["original"]
    downloads = root / "downloads"
    downloads.mkdir(mode=0o700)
    try:
        code, output, _ = runtime.run(["lsjson", "--recursive", "--hash", "--no-modtime", "--no-mimetype", "Synthetic:"], good)
        check(code == 0, "archive_listing_failed")
        archive_inventory(output, payloads)
        caps.update(listing="passed", archive_crc32="passed")
        for index, (name, (size, expected_hash)) in enumerate(sorted(expected.items())):
            exact_file_stat(runtime, good, "Synthetic:", name, size)
            destination = downloads / f"verified-{index}"
            code, _, _ = exact_copy(runtime, good, "Synthetic:", name, downloads.as_posix(), destination.name)
            check(code == 0 and destination.is_file(), "archive_download_failed")
            check(destination.stat().st_size == size and digest(destination) == expected_hash, "archive_download_hash_mismatch")
        caps["download_hash"] = "passed"
        for name, capability, marker in (("absent-synthetic.txt", "missing_object_rejection", b"object not found"),
                                         ("nested", "directory_as_file_rejection", b"is not a regular file")):
            destination = downloads / f"{capability}-must-not-exist"
            code, output, error = exact_copy(runtime, good, "Synthetic:", name, downloads.as_posix(), destination.name)
            check(code != 0 and not destination.exists(), "archive_invalid_object_accepted")
            check(marker in (output + error).lower(), "archive_object_rejection_not_observed")
            caps[capability] = "passed"
        destination = downloads / "corrupt-must-not-exist"
        code, output, error = exact_copy(runtime, configs["corrupt"], "Synthetic:", "README-synthetic.txt",
                                         downloads.as_posix(), destination.name)
        check(code != 0 and not destination.exists(), "corrupt_archive_member_accepted")
        check(b"zip: checksum error" in (output + error).lower(), "archive_crc_rejection_not_observed")
        caps["corrupt_member_rejection"] = "passed"
        code, output, error = runtime.run(["lsjson", "--recursive", "Synthetic:"], configs["truncated"])
        check(code != 0 and b"zip: not a valid zip file" in (output + error).lower(), "truncated_archive_accepted")
        caps["truncated_archive_rejection"] = "passed"
        upload = root / "synthetic-write.txt"
        write_private(upload, b"Synthetic rejected archive write.\n")
        code, output, error = exact_copy(runtime, good, root.as_posix(), upload.name,
                                         "Synthetic:", "write-must-not-exist.txt")
        check(code != 0 and b"read only file system" in (output + error).lower(), "archive_write_rejection_not_observed")
        code, output, _ = runtime.run(["lsjson", "--recursive", "--hash", "--no-modtime", "--no-mimetype", "Synthetic:"], good)
        check(code == 0, "archive_post_write_listing_failed")
        archive_inventory(output, payloads)
        caps["fixture_write_rejection"] = "passed"
    finally:
        for path, (contents, sha256) in preserved.items():
            check(path.is_file() and path.read_bytes() == contents and digest(path) == sha256,
                  "archive_config_changed" if path.suffix == ".conf" else "archive_container_changed")
        caps.update(source_preservation="passed", config_preservation="passed")


def local_fixture_target(runtime, files_root):
    # Named local remotes accept relative object names. Absolute drive objects
    # are rejected by the app planner and are not this fixture's contract.
    # Runtime.start always sets cwd to this private owned root.
    try:
        relative = files_root.resolve(strict=True).relative_to(runtime.root.resolve(strict=True))
    except ValueError:
        raise LabError("local_source_outside_owned_root") from None
    check(bool(relative.parts) and files_root.is_dir(), "invalid_local_fixture_root")
    return "Synthetic:" + relative.as_posix() + "/"


def run_backend(runtime, backend, root):
    root.mkdir(mode=0o700)
    independent = backend in ("http", "webdav", "ftp")
    row = {"backend": backend,
           "fixture_kind": "local" if backend in ("local", "archive") else "independent_loopback" if independent else "rclone_loopback",
           "capabilities": {key: "not_run" for key in (
               "listing", "download_hash", "missing_object_rejection", "source_preservation", "authentication_rejection", "cleanup")},
           "errors": []}
    if backend in ("local", "archive"):
        row["capabilities"]["authentication_rejection"] = "not_applicable"
    if backend == "archive":
        row["capabilities"].update({key: "not_run" for key in ("archive_crc32", "directory_as_file_rejection",
            "corrupt_member_rejection", "truncated_archive_rejection", "fixture_write_rejection", "config_preservation")})
    if backend == "sftp":
        row["capabilities"]["host_key_rejection"] = "not_run"
    if independent:
        row["capabilities"]["fixture_write_rejection"] = "not_run"
    if backend in ("http", "webdav"):
        row["capabilities"].update(truncated_download_rejection="not_run", cancellation_cleanup="not_run")
    source = root / "source"
    # Snapshot independent expected names/lengths/hashes before any requests.
    # State owns a different mapping; mutations cannot change this snapshot.
    expected = fixture_manifest()
    # Serve S3 exposes child directories as buckets, keeping this bucket wholly
    # synthetic and excluding any host data outside the fresh fixture root.
    files_root = source / "synthetic-bucket" if backend == "s3" else source / "files"
    if not independent and backend != "archive":
        source.mkdir(mode=0o700)
        prepare_files(files_root)
    port = None
    try:
        if backend == "archive":
            archive_checks(runtime, root, row)
            return row
        user, password = "synthetic", "synthetic-" + uuid.uuid4().hex
        code, obscured, _ = runtime.run(["obscure", password])
        check(code == 0, "fixture_password_setup_failed")
        code, wrong_obscured, _ = runtime.run(["obscure", "wrong-synthetic-password"])
        check(code == 0, "fixture_password_setup_failed")
        if backend == "local":
            config = config_file(root, "local.conf", {"type": "local"})
            common_checks(runtime, root, config, None, local_fixture_target(runtime, files_root), row, expected=expected)
        elif independent:
            state = State(user, password)
            with serve(backend, state) as port:
                if backend == "http":
                    opts = {"type": "http", "url": f"http://{user}:{password}@127.0.0.1:{port}/"}
                    bad_opts = dict(opts, url=f"http://{user}:wrong@127.0.0.1:{port}/")
                else:
                    opts = {"type": backend, "user": user, "pass": obscured.decode().strip()}
                    if backend == "ftp":
                        opts.update(host="127.0.0.1", port=str(port), tls="false")
                    else:
                        opts.update(url=f"http://127.0.0.1:{port}/", vendor="other")
                    bad_opts = dict(opts, **{"pass": wrong_obscured.decode().strip()})
                good = config_file(root, "good.conf", opts)
                bad = config_file(root, "bad.conf", bad_opts)
                common_checks(runtime, root, good, bad, "Synthetic:", row, state, expected=expected)
                check(state.rejected_mutations == 0, "unexpected_mutation_attempt")
                probe_write_rejection(backend, port, state)
                row["capabilities"]["fixture_write_rejection"] = "passed"
        else:
            with rclone_server(runtime, backend, source if backend == "s3" else files_root, user, password) as (port, _):
                if backend == "sftp":
                    known = pin_sftp_key(runtime, port, root)
                    opts = {"type": "sftp", "host": "127.0.0.1", "port": str(port), "user": user,
                            "pass": obscured.decode().strip(), "known_hosts_file": str(known),
                            "key_use_agent": "false", "disable_hashcheck": "true", "shell_type": "none"}
                    bad_opts = dict(opts, **{"pass": wrong_obscured.decode().strip()})
                    auth_marker = (b"unable to authenticate", b"password rejected")
                    target = "Synthetic:"
                else:
                    opts = {"type": "s3", "provider": "Other", "env_auth": "false", "access_key_id": user,
                            "secret_access_key": password, "endpoint": f"http://127.0.0.1:{port}",
                            "region": "us-east-1", "force_path_style": "true"}
                    bad_opts = dict(opts, secret_access_key="wrong-synthetic-password")
                    auth_marker = (b"signaturedoesnotmatch", b"accessdenied", b"invalidaccesskeyid")
                    target = "Synthetic:synthetic-bucket/"
                good = config_file(root, "good.conf", opts)
                bad = config_file(root, "bad.conf", bad_opts)
                common_checks(runtime, root, good, bad, target, row, auth_marker=auth_marker, expected=expected)
                if backend == "sftp":
                    sftp_host_key_check(runtime, root, opts, target, row)
        check(served_source_unchanged(state, expected) if independent else source_unchanged(files_root, expected), "source_changed")
        row["capabilities"]["source_preservation"] = "passed"
    except (LabError, OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        row["errors"].append(str(error) if isinstance(error, LabError) else "fixture_error")
    finally:
        closed = port is None or listener_closed(port)
        if closed:
            row["capabilities"]["cleanup"] = "passed"
        else:
            row["capabilities"]["cleanup"] = "failed"
            row["errors"].append("listener_still_open")
    return row


def run_lab(binary, report_path, backends=BACKENDS):
    validate_report_path(report_path)
    repository = Path(__file__).resolve().parents[2]
    original, identity, platform = verified_runtime(binary, repository / "rclone-version.env")
    report = {"schema_version": 1, "scope": "rclone_backend_protocol_fixture", "runtime": identity,
              "harness_sha256": compute_harness_sha256(Path(__file__).parent),
              "fixture_manifest_sha256": fixture_manifest_sha256(), "started_utc": utc_now(),
              "finished_utc": None, "platform": platform, "success": False,
              "cleanup_passed": False, "backends": [], "errors": []}
    root = Path(tempfile.mkdtemp(prefix="triage-provider-lab-"))
    runtime = None
    try:
        runtime = Runtime(original, identity, root)
        code, output, _ = runtime.run(["version"])
        check(code == 0 and output.decode().splitlines()[0] == "rclone v" + identity["version"], "runtime_version_mismatch")
        for backend in backends:
            report["backends"].append(run_backend(runtime, backend, root / backend))
    except (LabError, OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        report["errors"].append(str(error) if isinstance(error, LabError) else "lab_setup_failed")
    except KeyboardInterrupt:
        report["errors"].append("lab_interrupted")
    finally:
        try:
            processes_closed = runtime.close() if runtime else True
            shutil.rmtree(root)
            report["cleanup_passed"] = processes_closed and not root.exists()
        except OSError:
            report["errors"].append("lab_cleanup_failed")
        report["finished_utc"] = utc_now()
        report["success"] = (report["cleanup_passed"] and not report["errors"]
                             and len(report["backends"]) == len(backends)
                             and all(not row["errors"] and all(value in ("passed", "not_applicable")
                                     for value in row["capabilities"].values()) for row in report["backends"]))
        atomic_report(report_path, report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rclone", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--backends", default=",".join(BACKENDS))
    args = parser.parse_args()
    selected = args.backends.split(",")
    if not selected or len(set(selected)) != len(selected) or any(item not in BACKENDS for item in selected):
        parser.error("backends must be a unique comma-separated subset of supported fixture IDs")
    try:
        report = run_lab(args.rclone, args.report, selected)
    except (LabError, OSError):
        print("Provider fixture preflight/report failure", file=sys.stderr)
        return 1
    print(json.dumps({"success": report["success"], "cleanup_passed": report["cleanup_passed"],
                      "backends": len(report["backends"])}))
    return 0 if report["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
