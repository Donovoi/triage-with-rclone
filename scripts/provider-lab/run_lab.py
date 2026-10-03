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
import hmac
import http.client
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

from fixture_servers import FILES, State, SwiftState, B2State, AzureBlobState, AzureFilesState, SeafileState, azure_string_to_sign, probe_write_rejection, serve
from email.utils import format_datetime


BACKENDS = ("local", "http", "webdav", "ftp", "sftp", "s3", "archive", "swift", "b2", "azureblob", "azurefiles", "seafile")
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

    def start(self, args, config=None, notice=False, low_level_attempts=1):
        check(type(low_level_attempts) is int and low_level_attempts in (1, 2), "invalid_attempt_budget")
        self.sequence += 1
        prefix = self.root / f"process-{self.sequence}"
        stdout = prefix.with_suffix(".out")
        stderr = prefix.with_suffix(".err")
        command = [str(self.binary), "--config", str(config or self.config),
                   "--cache-dir", str(self.cache), "--log-level", "NOTICE" if notice else "ERROR",
                   "--stats", "0", "--retries", "1", "--low-level-retries", str(low_level_attempts),
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

    def run(self, args, config=None, timeout=COMMAND_TIMEOUT, low_level_attempts=1):
        record = self.start(args, config, low_level_attempts=low_level_attempts)
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


def exact_copy(runtime, config, source_fs, source_name, destination_fs, destination_name, *, low_level_attempts=1):
    # In-process loopback RC opens one object; no network RC listener and no
    # copyto fallback that might recursively acquire a directory.
    budget = {} if low_level_attempts == 1 else {"low_level_attempts": low_level_attempts}
    return runtime.run(["rc", "--loopback", "operations/copyfile", f"srcFs={source_fs}",
                        f"srcRemote={source_name}", f"dstFs={destination_fs}",
                        f"dstRemote={destination_name}"], config, **budget)


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


def swift_options(state, port):
    # Do not set auth_token/storage_url: those override renewed authorization.
    return {"type": "swift", "env_auth": "false", "user": state.user, "key": state.password,
            "auth": f"http://127.0.0.1:{port}/auth/v1.0", "auth_version": "1",
            "endpoint_type": "public", "no_large_objects": "true"}


def swift_renewal_matches(state, denial, size):
    """Attest ordered server-observed replacement, not two separate logins."""
    if (state.mode != ("deny" if denial else "renew") or state.forced_401 != 1
            or state.budget_exceeded or state.unexpected or state.auth_denied or state.storage_denied
            or state.rejected_payload_bytes or state.rejected_mutations or len(state.revoked) != 1):
        return False
    expected = [("grant", 1), ("head", 1), ("get_401", 1)]
    expected += [("renewal_denied", 1)] if denial else [("grant", 2), ("get", 2)]
    try:
        positions = [state.events.index(event) for event in expected]
    except ValueError:
        return False
    if positions != sorted(positions) or len(set(positions)) != len(positions):
        return False
    grants = [event for event in state.events if event[0] == "grant"]
    gets = [event for event in state.events if event[0] == "get"]
    if denial:
        return (grants == [("grant", 1)] and not gets and state.generation == 1
                and len(state.tokens) == 1 and state.token in state.revoked
                and 1 <= state.renewal_denied <= 8 and state.payload_bytes == 0)
    return (grants == [("grant", 1), ("grant", 2)] and gets == [("get", 2)]
            and state.generation == 2 and len(state.tokens) == 2 and state.token not in state.revoked
            and state.renewal_denied == 0 and state.payload_bytes == size)


def swift_renewal_case(runtime, root, state, config, row):
    denial = state.mode == "deny"
    payload = FILES["README-synthetic.txt"]
    expected_hash = hashlib.sha256(payload).hexdigest()
    destination = root / ("denied-must-not-exist" if denial else "renewed-verified")
    before = runtime.sequence
    code, output, _ = exact_copy(runtime, config, "Synthetic:", "synthetic-bucket/README-synthetic.txt",
                                root.as_posix(), destination.name)
    check(runtime.sequence == before + 1, "swift_renewal_not_single_process")
    check(swift_renewal_matches(state, denial, len(payload)), "swift_renewal_sequence_not_observed")
    if denial:
        # RC's stdout may contain an error JSON envelope; no file payload may
        # be accepted. The server independently accounts for all payload bytes.
        check(code != 0 and not destination.exists() and payload not in output, "swift_denied_renewal_returned_data")
        row["capabilities"]["renewal_denial"] = "passed"
    else:
        check(code == 0 and destination.is_file() and destination.stat().st_size == len(payload)
              and digest(destination) == expected_hash, "swift_renewed_download_mismatch")
        row["capabilities"]["service_token_reacquisition"] = "passed"


def swift_checks(runtime, root, row, expected):
    caps = row["capabilities"]
    states, ports, preserved = [], [], {}

    def save_config(name, options):
        path = config_file(root, name, options)
        data = path.read_bytes()
        preserved[path] = (data, hashlib.sha256(data).hexdigest())
        return path

    try:
        baseline = SwiftState("synthetic", "synthetic-" + uuid.uuid4().hex)
        states.append(baseline)
        with serve("swift", baseline) as port:
            ports.append(port)
            opts = swift_options(baseline, port)
            good = save_config("swift-baseline.conf", opts)
            bad = save_config("swift-denied.conf", dict(opts, key="wrong-synthetic-key"))
            code, output, _ = runtime.run(["cat", "Synthetic:synthetic-bucket/README-synthetic.txt"], bad)
            check(code != 0 and not output and baseline.auth_denied > 0 and baseline.generation == 0
                  and baseline.payload_bytes == 0, "swift_bad_auth_not_observed")
            caps["authentication_rejection"] = "passed"
            code, output, _ = runtime.run(["lsjson", "--recursive", "--files-only", "--no-modtime",
                                            "--no-mimetype", "Synthetic:synthetic-bucket"], good)
            check(code == 0, "swift_listing_failed")
            try:
                got = sorted((entry["Path"], entry["Size"], entry["IsDir"]) for entry in json.loads(output))
            except (KeyError, TypeError, ValueError):
                raise LabError("swift_listing_invalid") from None
            check(got == [(item["path"], item["size"], False) for item in expected], "swift_listing_mismatch")
            caps["listing"] = "passed"
            downloads = root / "downloads"
            downloads.mkdir(mode=0o700)
            for index, item in enumerate(expected):
                source = "synthetic-bucket/" + item["path"]
                exact_file_stat(runtime, good, "Synthetic:", source, item["size"])
                destination = downloads / f"verified-{index}"
                code, _, _ = exact_copy(runtime, good, "Synthetic:", source, downloads.as_posix(), destination.name)
                check(code == 0 and destination.is_file() and destination.stat().st_size == item["size"]
                      and digest(destination) == item["sha256"], "swift_download_mismatch")
            caps["download_hash"] = "passed"
            missing = "synthetic-bucket/absent-synthetic.txt"
            code, output, _ = runtime.run(["rc", "--loopback", "operations/stat", "fs=Synthetic:", "remote=" + missing,
                'opt={"noModTime":true,"noMimeType":true,"filesOnly":true}'], good)
            check(code == 0 and json.loads(output) == {"item": None}, "swift_missing_stat_mismatch")
            destination = downloads / "missing-must-not-exist"
            code, output, error = exact_copy(runtime, good, "Synthetic:", missing, downloads.as_posix(), destination.name)
            check(code != 0 and not destination.exists() and baseline.missing >= 2
                  and b"object not found" in (output + error).lower(), "swift_missing_object_accepted")
            caps["missing_object_rejection"] = "passed"
            check(baseline.rejected_mutations == 0, "swift_unexpected_mutation")
            upload = root / "synthetic-write.txt"
            write_private(upload, b"Synthetic rejected Swift write.\n")
            code, _, _ = exact_copy(runtime, good, root.as_posix(), upload.name,
                                    "Synthetic:", "synthetic-bucket/write-must-not-exist.txt")
            check(code != 0 and 1 <= baseline.rejected_mutations <= 4, "swift_write_rejection_not_observed")
            caps["fixture_write_rejection"] = "passed"
        for mode in ("renew", "deny"):
            state = SwiftState("synthetic", "synthetic-" + uuid.uuid4().hex, mode)
            states.append(state)
            with serve("swift", state) as port:
                ports.append(port)
                config = save_config(f"swift-{mode}.conf", swift_options(state, port))
                swift_renewal_case(runtime, root, state, config, row)
    finally:
        closed = all(state.cleanup_complete for state in states) and all(listener_closed(port) for port in ports)
        caps["cleanup"] = "passed" if closed else "failed"
        check(closed, "swift_listener_cleanup_failed")
        check(all(not state.budget_exceeded and not state.unexpected and not state.rejected_payload_bytes
                  and not state.storage_denied for state in states),
              "swift_unexpected_request_or_budget")
        check(all(served_source_unchanged(state, expected) for state in states), "swift_source_changed")
        caps["source_preservation"] = "passed"
        check(all(path.is_file() and path.read_bytes() == data and digest(path) == sha256
                  for path, (data, sha256) in preserved.items()), "swift_config_changed")
        caps["config_preservation"] = "passed"


def b2_options(state, port):
    return {"type": "b2", "account": state.user, "key": state.password,
            "endpoint": f"http://127.0.0.1:{port}"}


def b2_renewal_matches(state, denial, size):
    if (state.mode != ("deny" if denial else "renew") or state.forced_401 != 1
            or state.budget_exceeded or state.unexpected or state.auth_denied or state.storage_denied
            or state.rejected_payload_bytes or state.rejected_mutations or state.missing
            or len(state.revoked) != 1 or state.requests > 14 or state.requests != len(state.events)):
        return False
    prefix = [("grant", 1), ("head", 1), ("get_401", 1)]
    if state.events[:3] != prefix:
        return False
    if denial:
        tail = state.events[3:]
        # The pinned Copy retry wraps the two-attempt B2 pacer: at most four
        # expired GETs, each followed by up to two denied authorization calls.
        groups = [[]]
        for event in tail:
            if event == ("expired_retry", 1) and len(groups) < 4 and groups[-1]:
                groups.append([])
            elif event == ("renewal_denied", 1):
                groups[-1].append(event)
            else:
                return False
        return (all(1 <= len(group) <= 2 for group in groups) and state.expired_gets == len(groups)
                and state.renewal_denied == sum(map(len, groups)) and state.generation == 1
                and len(state.tokens) == 1 and state.token in state.revoked and state.payload_bytes == 0)
    return (state.events == prefix + [("grant", 2), ("get", 2)]
            and state.expired_gets == 1 and state.renewal_denied == 0 and state.generation == 2
            and len(state.tokens) == 2 and state.token not in state.revoked and state.payload_bytes == size)


def b2_renewal_case(runtime, root, state, config, row):
    denial = state.mode == "deny"
    payload = FILES["README-synthetic.txt"]
    expected_sha = hashlib.sha256(payload).hexdigest()
    destination = root / ("denied-must-not-exist" if denial else "renewed-verified")
    before = runtime.sequence
    code, output, _ = exact_copy(runtime, config, "Synthetic:synthetic-bucket", "README-synthetic.txt",
                                 root.as_posix(), destination.name, low_level_attempts=2)
    check(runtime.sequence == before + 1, "b2_renewal_not_single_process")
    check(b2_renewal_matches(state, denial, len(payload)), "b2_renewal_sequence_mismatch")
    if denial:
        check(code != 0 and not destination.exists() and payload not in output
              and not list(root.glob(destination.name + "*")), "b2_denied_renewal_returned_data")
        row["capabilities"]["renewal_denial"] = "passed"
    else:
        check(code == 0 and destination.is_file() and destination.stat().st_size == len(payload)
              and digest(destination) == expected_sha, "b2_renewed_download_mismatch")
        row["capabilities"]["account_token_reacquisition"] = "passed"


def b2_checks(runtime, root, row, expected):
    caps, states, ports, preserved = row["capabilities"], [], [], {}

    def save_config(name, options):
        path = config_file(root, name, options)
        data = path.read_bytes()
        preserved[path] = (data, hashlib.sha256(data).hexdigest())
        return path

    try:
        baseline = B2State("synthetic-" + uuid.uuid4().hex, "synthetic-" + uuid.uuid4().hex)
        states.append(baseline)
        with serve("b2", baseline) as port:
            ports.append(port)
            opts = b2_options(baseline, port)
            good = save_config("b2-baseline.conf", opts)
            bad = save_config("b2-denied.conf", dict(opts, key="wrong-synthetic-key"))
            code, output, _ = runtime.run(["cat", "Synthetic:synthetic-bucket/README-synthetic.txt"], bad)
            check(code != 0 and not output and baseline.auth_denied > 0 and baseline.generation == 0
                  and baseline.payload_bytes == 0, "b2_bad_auth_not_observed")
            caps["authentication_rejection"] = "passed"
            code, output, _ = runtime.run(["lsjson", "--recursive", "--files-only", "--no-modtime",
                                            "--no-mimetype", "Synthetic:synthetic-bucket"], good)
            check(code == 0, "b2_listing_failed")
            try:
                got = sorted((entry["Path"], entry["Size"], entry["IsDir"]) for entry in json.loads(output))
            except (KeyError, TypeError, ValueError):
                raise LabError("b2_listing_invalid") from None
            check(got == [(item["path"], item["size"], False) for item in expected], "b2_listing_mismatch")
            caps["listing"] = "passed"
            downloads = root / "downloads"
            downloads.mkdir(mode=0o700)
            for index, item in enumerate(expected):
                exact_file_stat(runtime, good, "Synthetic:synthetic-bucket", item["path"], item["size"])
                destination = downloads / f"verified-{index}"
                code, _, _ = exact_copy(runtime, good, "Synthetic:synthetic-bucket", item["path"],
                                        downloads.as_posix(), destination.name)
                check(code == 0 and destination.is_file() and destination.stat().st_size == item["size"]
                      and digest(destination) == item["sha256"], "b2_download_mismatch")
            caps["download_hash"] = "passed"
            missing = "absent-synthetic.txt"
            code, output, _ = runtime.run(["rc", "--loopback", "operations/stat", "fs=Synthetic:synthetic-bucket",
                "remote=" + missing, 'opt={"noModTime":true,"noMimeType":true,"filesOnly":true}'], good)
            check(code == 0 and json.loads(output) == {"item": None}, "b2_missing_stat_mismatch")
            destination = downloads / "missing-must-not-exist"
            code, output, error = exact_copy(runtime, good, "Synthetic:synthetic-bucket", missing,
                                            downloads.as_posix(), destination.name)
            check(code != 0 and not list(downloads.glob(destination.name + "*")) and baseline.missing >= 2
                  and b"object not found" in (output + error).lower(), "b2_missing_object_accepted")
            caps["missing_object_rejection"] = "passed"
            check(baseline.rejected_mutations == 0, "b2_unexpected_mutation")
            # This proves only the independent fixture write guard. No upload
            # implementation or native/vendor write-path acceptance is implied.
            client = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            try:
                client.request("POST", "/b2api/v1/b2_get_upload_url",
                    body=json.dumps({"bucketId": baseline.bucket_id}),
                    headers={"Authorization": baseline.token, "Content-Type": "application/json"})
                response = client.getresponse()
                body = response.read(4097)
                check(response.status == 403 and len(body) <= 4096 and baseline.rejected_mutations == 1
                      and json.loads(body).get("code") == "unauthorized", "b2_write_guard_not_observed")
            finally:
                client.close()
            caps["fixture_write_rejection"] = "passed"
        for mode in ("renew", "deny"):
            state = B2State("synthetic-" + uuid.uuid4().hex, "synthetic-" + uuid.uuid4().hex, mode)
            states.append(state)
            with serve("b2", state) as port:
                ports.append(port)
                config = save_config(f"b2-{mode}.conf", b2_options(state, port))
                b2_renewal_case(runtime, root, state, config, row)
    finally:
        closed = all(state.cleanup_complete for state in states) and all(listener_closed(port) for port in ports)
        caps["cleanup"] = "passed" if closed else "failed"
        check(closed, "b2_listener_cleanup_failed")
        check(all(not state.budget_exceeded and not state.unexpected and not state.rejected_payload_bytes
                  and not state.storage_denied for state in states), "b2_unexpected_request_or_budget")
        check(all(served_source_unchanged(state, expected) for state in states), "b2_source_changed")
        caps["source_preservation"] = "passed"
        check(all(path.is_file() and path.read_bytes() == data and digest(path) == sha256
                  for path, (data, sha256) in preserved.items()), "b2_config_changed")
        caps["config_preservation"] = "passed"


def azureblob_options(state, port):
    return {"type": "azureblob", "env_auth": "false", "use_emulator": "true", "account": state.account,
            "key": state.password, "endpoint": f"http://127.0.0.1:{port}/{state.account}", "use_arrow_list": "false"}


def azureblob_checks(runtime, root, row, expected):
    caps, preserved = row["capabilities"], {}
    state = AzureBlobState(base64.b64encode(os.urandom(32)).decode())
    port = None

    def save_config(name, options):
        path = config_file(root, name, options)
        data = path.read_bytes()
        preserved[path] = (data, hashlib.sha256(data).hexdigest())
        return path

    try:
        with serve("azureblob", state) as port:
            opts = azureblob_options(state, port)
            good = save_config("azureblob-baseline.conf", opts)
            wrong_key = base64.b64encode(bytes(value ^ 1 for value in state.key_bytes)).decode()
            bad = save_config("azureblob-denied.conf", dict(opts, key=wrong_key))
            code, output, _ = runtime.run(["cat", "Synthetic:synthetic-container/README-synthetic.txt"], bad)
            check(code != 0 and not output and state.auth_denied > 0 and state.authenticated == 0
                  and state.payload_bytes == 0, "azureblob_bad_auth_not_observed")
            denied_before = state.auth_denied
            caps["authentication_rejection"] = "passed"
            code, output, _ = runtime.run(["lsjson", "--recursive", "--files-only", "--no-modtime",
                                            "--no-mimetype", "Synthetic:synthetic-container"], good)
            check(code == 0, "azureblob_listing_failed")
            try:
                got = sorted((entry["Path"], entry["Size"], entry["IsDir"]) for entry in json.loads(output))
            except (KeyError, TypeError, ValueError):
                raise LabError("azureblob_listing_invalid") from None
            check(got == [(item["path"], item["size"], False) for item in expected], "azureblob_listing_mismatch")
            caps["listing"] = "passed"
            downloads = root / "downloads"
            downloads.mkdir(mode=0o700)
            for index, item in enumerate(expected):
                exact_file_stat(runtime, good, "Synthetic:synthetic-container", item["path"], item["size"])
                destination = downloads / f"verified-{index}"
                code, _, _ = exact_copy(runtime, good, "Synthetic:synthetic-container", item["path"],
                                        downloads.as_posix(), destination.name)
                check(code == 0 and destination.is_file() and destination.stat().st_size == item["size"]
                      and digest(destination) == item["sha256"], "azureblob_download_mismatch")
            caps["download_hash"] = "passed"
            missing = "absent-synthetic.txt"
            code, output, _ = runtime.run(["rc", "--loopback", "operations/stat", "fs=Synthetic:synthetic-container",
                "remote=" + missing, 'opt={"noModTime":true,"noMimeType":true,"filesOnly":true}'], good)
            check(code == 0 and json.loads(output) == {"item": None}, "azureblob_missing_stat_mismatch")
            destination = downloads / "missing-must-not-exist"
            code, output, error = exact_copy(runtime, good, "Synthetic:synthetic-container", missing,
                                            downloads.as_posix(), destination.name)
            check(code != 0 and not list(downloads.glob(destination.name + "*")) and state.missing >= 2
                  and b"object not found" in (output + error).lower(), "azureblob_missing_object_accepted")
            caps["missing_object_rejection"] = "passed"
            check(state.rejected_mutations == 0 and state.auth_denied == denied_before,
                  "azureblob_unexpected_native_denial_or_mutation")
            # This request only exercises the fixture's mutation guard. Native
            # read/auth acceptance above remains independent of this signer.
            target = f"/{state.account}/{state.container}/write-must-not-exist.txt"
            headers = {"x-ms-date": format_datetime(datetime.now(timezone.utc), usegmt=True),
                       "x-ms-version": "2026-06-06", "Content-Length": "0"}
            signed = azure_string_to_sign(state.account, "PUT", target, headers.items())
            signature = base64.b64encode(hmac.new(state.key_bytes, signed.encode(), hashlib.sha256).digest()).decode()
            headers["Authorization"] = f"SharedKey {state.account}:{signature}"
            client = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            try:
                client.request("PUT", target, body=b"", headers=headers)
                response = client.getresponse()
                body = response.read(4097)
                check(response.status == 403 and response.getheader("x-ms-error-code") == "AuthorizationPermissionMismatch"
                      and len(body) <= 4096 and state.rejected_mutations == 1
                      and state.auth_denied == denied_before, "azureblob_write_guard_not_observed")
            finally:
                client.close()
            caps["fixture_write_rejection"] = "passed"
    finally:
        closed = state.cleanup_complete and (port is None or listener_closed(port))
        caps["cleanup"] = "passed" if closed else "failed"
        check(closed, "azureblob_listener_cleanup_failed")
        check(not state.budget_exceeded and not state.unexpected and not state.rejected_payload_bytes,
              "azureblob_unexpected_request_or_budget")
        check(served_source_unchanged(state, expected), "azureblob_source_changed")
        caps["source_preservation"] = "passed"
        check(all(path.is_file() and path.read_bytes() == data and digest(path) == sha256
                  for path, (data, sha256) in preserved.items()), "azureblob_config_changed")
        caps["config_preservation"] = "passed"


def azurefiles_options(state, port):
    return {"type": "azurefiles", "env_auth": "false", "use_emulator": "false", "account": state.account,
            "key": state.password, "endpoint": f"http://127.0.0.1:{port}/{state.account}", "share_name": state.share}


def azurefiles_listing_matches(output, expected):
    try:
        rows = json.loads(output)
        actual = []
        for entry in rows:
            if entry["IsDir"] is not False or type(entry["Size"]) is not int or not isinstance(entry["ModTime"], str):
                return False
            # datetime alone truncates 100ns differences. This fixed fixture
            # accepts only zero fractions and UTC, preserving Files precision.
            if not re.fullmatch(r"2024-01-01T00:00:00(?:\.0{1,9})?(?:Z|\+00:00)", entry["ModTime"]):
                return False
            timestamp = datetime.fromisoformat(entry["ModTime"].replace("Z", "+00:00"))
            if timestamp != datetime(2024, 1, 1, tzinfo=timezone.utc):
                return False
            actual.append((entry["Path"], entry["Size"]))
        return sorted(actual) == [(item["path"], item["size"]) for item in expected]
    except (ValueError, TypeError, KeyError):
        return False


def azurefiles_checks(runtime, root, row, expected):
    caps, preserved = row["capabilities"], {}
    state = AzureFilesState(base64.b64encode(os.urandom(32)).decode())
    port = None

    def save_config(name, options):
        path = config_file(root, name, options)
        data = path.read_bytes()
        preserved[path] = (data, hashlib.sha256(data).hexdigest())
        return path

    try:
        with serve("azurefiles", state) as port:
            opts = azurefiles_options(state, port)
            good = save_config("azurefiles-baseline.conf", opts)
            wrong_key = base64.b64encode(bytes(value ^ 1 for value in state.key_bytes)).decode()
            bad = save_config("azurefiles-denied.conf", dict(opts, key=wrong_key))
            code, output, _ = runtime.run(["cat", "Synthetic:README-synthetic.txt"], bad)
            check(code != 0 and not output and state.auth_denied > 0 and state.authenticated == 0
                  and state.payload_bytes == 0 and state.read_auth_denied > 0, "azurefiles_bad_auth_not_observed")
            denied_before = state.auth_denied
            caps["authentication_rejection"] = "passed"
            code, output, _ = runtime.run(["lsjson", "--recursive", "--files-only",
                                            "--no-mimetype", "Synthetic:"], good)
            check(code == 0, "azurefiles_listing_failed")
            check(azurefiles_listing_matches(output, expected), "azurefiles_listing_or_timestamp_mismatch")
            caps["listing"] = "passed"
            downloads = root / "downloads"
            downloads.mkdir(mode=0o700)
            for index, item in enumerate(expected):
                exact_file_stat(runtime, good, "Synthetic:", item["path"], item["size"])
                destination = downloads / f"verified-{index}"
                code, _, _ = exact_copy(runtime, good, "Synthetic:", item["path"],
                                        downloads.as_posix(), destination.name)
                check(code == 0 and destination.is_file() and destination.stat().st_size == item["size"]
                      and digest(destination) == item["sha256"], "azurefiles_download_mismatch")
            caps["download_hash"] = "passed"
            missing = "absent-synthetic.txt"
            code, output, _ = runtime.run(["rc", "--loopback", "operations/stat", "fs=Synthetic:",
                "remote=" + missing, 'opt={"noModTime":true,"noMimeType":true,"filesOnly":true}'], good)
            check(code == 0 and json.loads(output) == {"item": None}, "azurefiles_missing_stat_mismatch")
            destination = downloads / "missing-must-not-exist"
            code, output, error = exact_copy(runtime, good, "Synthetic:", missing,
                                            downloads.as_posix(), destination.name)
            check(code != 0 and not list(downloads.glob(destination.name + "*")) and state.missing >= 2
                  and b"object not found" in (output + error).lower(), "azurefiles_missing_object_accepted")
            caps["missing_object_rejection"] = "passed"
            check(state.rejected_mutations == 0 and state.auth_denied == denied_before
                  and state.directory_properties > 0 and state.directory_lists > 0 and state.root_file_probes > 0,
                  "azurefiles_unexpected_native_denial_or_mutation")
            # This request only exercises the fixture's mutation guard. Native
            # read/auth acceptance above remains independent of this signer.
            target = f"/{state.account}/{state.share}/write-must-not-exist.txt"
            headers = {"x-ms-date": format_datetime(datetime.now(timezone.utc), usegmt=True),
                       "x-ms-version": "2026-06-06", "x-ms-file-request-intent": "backup", "Content-Length": "0"}
            signed = azure_string_to_sign(state.account, "PUT", target, headers.items())
            signature = base64.b64encode(hmac.new(state.key_bytes, signed.encode(), hashlib.sha256).digest()).decode()
            headers["Authorization"] = f"SharedKey {state.account}:{signature}"
            client = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            try:
                client.request("PUT", target, body=b"", headers=headers)
                response = client.getresponse()
                body = response.read(4097)
                check(response.status == 403 and response.getheader("x-ms-error-code") == "AuthorizationPermissionMismatch"
                      and len(body) <= 4096 and state.rejected_mutations == 1
                      and state.auth_denied == denied_before, "azurefiles_write_guard_not_observed")
            finally:
                client.close()
            caps["fixture_write_rejection"] = "passed"
    finally:
        closed = state.cleanup_complete and (port is None or listener_closed(port))
        caps["cleanup"] = "passed" if closed else "failed"
        check(closed, "azurefiles_listener_cleanup_failed")
        check(not state.budget_exceeded and not state.unexpected and not state.rejected_payload_bytes,
              "azurefiles_unexpected_request_or_budget")
        check(served_source_unchanged(state, expected), "azurefiles_source_changed")
        caps["source_preservation"] = "passed"
        check(all(path.is_file() and path.read_bytes() == data and digest(path) == sha256
                  for path, (data, sha256) in preserved.items()), "azurefiles_config_changed")
        caps["config_preservation"] = "passed"


def seafile_options(state, port, obscured_password):
    return {"type": "seafile", "url": f"http://127.0.0.1:{port}/", "user": state.user, "pass": obscured_password,
            "2fa": "false", "library": state.library_name, "create_library": "false"}


def seafile_listing_matches(output, expected):
    try:
        rows = json.loads(output)
        if not isinstance(rows, list):
            return False
        actual = []
        for entry in rows:
            if (not isinstance(entry, dict) or entry["IsDir"] is not False or type(entry["Size"]) is not int
                    or not isinstance(entry["Path"], str) or not isinstance(entry["ModTime"], str)):
                return False
            # Unix mtimes may render in the host's local zone. Compare the
            # instant, but reject subsecond drift before datetime truncates it.
            value = entry["ModTime"]
            if (not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
                                 r"(?:\.0{1,9})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])", value)
                    or value.endswith("-00:00")):  # RFC3339's unknown local offset is not an observed zone.
                return False
            timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if timestamp.astimezone(timezone.utc) != datetime(2024, 1, 1, tzinfo=timezone.utc):
                return False
            actual.append((entry["Path"], entry["Size"]))
        return sorted(actual) == [(item["path"], item["size"]) for item in expected]
    except (ValueError, TypeError, KeyError, OverflowError):
        return False


def seafile_flow_matches(state, kind, member="", expected_size=0):
    if (state.unexpected or state.budget_exceeded or state.rejected_payload_bytes
            or state.requests != len(state.events) or state.requests > 16):
        return False
    if kind == "wrong_password":
        return (state.events == [("server_info", ""), ("auth_denied", "")] and state.login_attempts == 1
                and state.auth_denied == 1 and state.grants == 0 and state.auth_uses == 0 and state.payload_bytes == 0)
    if kind == "cached_token":
        return (state.events == [("server_info", ""), ("cached_denied", "")] and state.login_attempts == 0
                and state.cached_denied == 1 and state.grants == 0 and state.auth_uses == 0 and state.payload_bytes == 0)
    if (state.events[:3] != [("server_info", ""), ("auth_granted", ""), ("libraries", "")]
            or state.login_attempts != 1 or state.grants != 1 or not state.token
            or state.auth_uses != state.requests - 2 or state.auth_denied or state.cached_denied or state.rejected_mutations):
        return False
    tail = state.events[3:]
    if kind == "listing":
        return (1 <= len(tail) <= 8 and all(event == "directory_list" for event, _ in tail)
                and any(name == "" for _, name in tail) and state.payload_bytes == 0)
    if kind in ("stat", "missing"):
        event = "file_detail" if kind == "stat" else "file_missing"
        return 1 <= len(tail) <= 4 and all(item == (event, member) for item in tail) and state.payload_bytes == 0
    if kind == "download":
        return (3 <= len(tail) <= 6 and all(item == ("file_detail", member) for item in tail[:-2])
                and tail[-2:] == [("link_issued", member), ("payload", member)] and state.payload_bytes == expected_size)
    return False


def seafile_one_process(runtime, action):
    before = runtime.sequence
    result = action()
    check(runtime.sequence == before + 1, "seafile_case_not_single_process")
    return result


def seafile_exact_stat(runtime, config, item):
    code, output, _ = runtime.run(["rc", "--loopback", "operations/stat", "fs=Synthetic:", "remote=" + item["path"],
                                  'opt={"noModTime":false,"noMimeType":true,"filesOnly":true}'], config)
    try:
        entry = json.loads(output)["item"]
    except (KeyError, TypeError, ValueError):
        raise LabError("seafile_stat_invalid") from None
    check(code == 0 and seafile_listing_matches(json.dumps([entry]), [item]), "seafile_stat_metadata_mismatch")


def seafile_checks(runtime, root, row, expected):
    caps, states, ports, preserved = row["capabilities"], [], [], {}
    user, password = "synthetic-" + uuid.uuid4().hex, "synthetic-" + uuid.uuid4().hex

    @contextmanager
    def case(label, mode="good"):
        state = SeafileState(user, password)
        states.append(state)
        with serve("seafile", state) as port:
            ports.append(port)
            options = seafile_options(state, port, wrong_obscured if mode == "wrong_password" else obscured)
            if mode == "cached_token":
                options["auth_token"] = state.invalid_cached_token
            config = config_file(root, "seafile-" + label + ".conf", options)
            data = config.read_bytes()
            preserved[config] = (data, hashlib.sha256(data).hexdigest())
            yield state, config, port

    try:
        code, output, _ = runtime.run(["obscure", password])
        check(code == 0 and output.strip(), "seafile_password_setup_failed")
        obscured = output.decode().strip()
        code, output, _ = runtime.run(["obscure", "wrong-synthetic-password"])
        check(code == 0 and output.strip(), "seafile_password_setup_failed")
        wrong_obscured = output.decode().strip()
        downloads = root / "downloads"
        downloads.mkdir(mode=0o700)
        for mode in ("wrong_password", "cached_token"):
            with case(mode, mode) as (state, config, _):
                destination = downloads / (mode + "-must-not-exist")
                code, output, _ = seafile_one_process(runtime, lambda: exact_copy(runtime, config, "Synthetic:",
                    "README-synthetic.txt", downloads.as_posix(), destination.name))
                check(code != 0 and not list(downloads.glob(destination.name + "*"))
                      and FILES["README-synthetic.txt"] not in output and seafile_flow_matches(state, mode),
                      "seafile_" + mode + "_denial_not_observed")
        caps["authentication_rejection"] = "passed"
        with case("listing") as (state, config, port):
            code, output, _ = seafile_one_process(runtime, lambda: runtime.run(
                ["lsjson", "--recursive", "--files-only", "--no-mimetype", "Synthetic:"], config))
            # Both fixtures intentionally use the same fixed UTC instant. The
            # validator checks exact names/sizes and rejects sub-microsecond drift.
            check(code == 0 and seafile_listing_matches(output, expected) and seafile_flow_matches(state, "listing"),
                  "seafile_listing_or_login_sequence_mismatch")
            caps["listing"] = "passed"
            client = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            try:
                target = "/api2/repos/" + state.library_id + "/file/?p=%2FREADME-synthetic.txt"
                client.request("DELETE", target, body=b"", headers={"Authorization": "Token " + state.token})
                response = client.getresponse()
                body = response.read(4097)
                check(response.status == 403 and len(body) <= 4096 and state.rejected_mutations == 1
                      and state.events[-1] == ("write_denied", "README-synthetic.txt"), "seafile_write_guard_not_observed")
            finally:
                client.close()
            caps["fixture_write_rejection"] = "passed"
        for index, item in enumerate(expected):
            with case("stat-" + str(index)) as (state, config, _):
                seafile_one_process(runtime, lambda: seafile_exact_stat(runtime, config, item))
                check(seafile_flow_matches(state, "stat", item["path"]), "seafile_stat_login_sequence_mismatch")
            with case("download-" + str(index)) as (state, config, _):
                destination = downloads / ("verified-" + str(index))
                code, _, _ = seafile_one_process(runtime, lambda: exact_copy(runtime, config, "Synthetic:", item["path"],
                                                                             downloads.as_posix(), destination.name))
                check(code == 0 and destination.is_file() and destination.stat().st_size == item["size"]
                      and digest(destination) == item["sha256"]
                      and seafile_flow_matches(state, "download", item["path"], item["size"]),
                      "seafile_download_or_login_sequence_mismatch")
        caps["download_hash"] = "passed"
        missing = "absent-synthetic.txt"
        with case("missing-stat") as (state, config, _):
            code, output, _ = seafile_one_process(runtime, lambda: runtime.run(
                ["rc", "--loopback", "operations/stat", "fs=Synthetic:", "remote=" + missing,
                 'opt={"noModTime":true,"noMimeType":true,"filesOnly":true}'], config))
            check(code == 0 and json.loads(output) == {"item": None} and seafile_flow_matches(state, "missing", missing),
                  "seafile_missing_stat_mismatch")
        with case("missing-copy") as (state, config, _):
            destination = downloads / "missing-must-not-exist"
            code, output, error = seafile_one_process(runtime, lambda: exact_copy(runtime, config, "Synthetic:", missing,
                                                                                 downloads.as_posix(), destination.name))
            check(code != 0 and not list(downloads.glob(destination.name + "*"))
                  and b"object not found" in (output + error).lower() and seafile_flow_matches(state, "missing", missing),
                  "seafile_missing_object_accepted")
        caps["missing_object_rejection"] = "passed"
    finally:
        closed = all(state.cleanup_complete for state in states) and all(listener_closed(port) for port in ports)
        caps["cleanup"] = "passed" if closed else "failed"
        check(closed, "seafile_listener_cleanup_failed")
        check(all(not state.budget_exceeded and not state.unexpected and not state.rejected_payload_bytes for state in states),
              "seafile_unexpected_request_or_budget")
        check(all(served_source_unchanged(state, expected) for state in states), "seafile_source_changed")
        caps["source_preservation"] = "passed"
        check(all(path.is_file() and path.read_bytes() == data and digest(path) == sha256
                  for path, (data, sha256) in preserved.items()), "seafile_config_changed")
        caps["config_preservation"] = "passed"


def run_backend(runtime, backend, root):
    root.mkdir(mode=0o700)
    independent = backend in ("http", "webdav", "ftp", "swift", "b2", "azureblob", "azurefiles", "seafile")
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
    if backend == "swift":
        row["capabilities"].update(config_preservation="not_run", service_token_reacquisition="not_run", renewal_denial="not_run")
    if backend == "b2":
        row["capabilities"].update(config_preservation="not_run", account_token_reacquisition="not_run", renewal_denial="not_run")
    if backend in ("azureblob", "azurefiles", "seafile"):
        row["capabilities"]["config_preservation"] = "not_run"
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
        if backend == "seafile":
            seafile_checks(runtime, root, row, expected)
            return row
        if backend == "azurefiles":
            azurefiles_checks(runtime, root, row, expected)
            return row
        if backend == "azureblob":
            azureblob_checks(runtime, root, row, expected)
            return row
        if backend == "b2":
            b2_checks(runtime, root, row, expected)
            return row
        if backend == "swift":
            swift_checks(runtime, root, row, expected)
            return row
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
        closed = (port is None or listener_closed(port)) and row["capabilities"]["cleanup"] != "failed"
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
