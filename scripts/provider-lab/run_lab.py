#!/usr/bin/env python3
"""Account-free rclone backend protocol checks; never a hosted-provider verdict.

Only an explicitly supplied absolute, manifest-pinned rclone is executed. The
application under test is NOT executed by this layer. See protocol scope in the
receipt; rclone's SFTP/S3 servers are not independent conformance or vendor tests.
"""

import argparse
import base64
import configparser
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
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
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid
import urllib.parse
import zipfile
import zlib

from fixture_servers import FILES, State, SwiftState, B2State, AzureBlobState, AzureFilesState, SeafileState, KoofrState, PixeldrainState, FileFabricState, FileFabricSessionState, InternetArchiveState, InternetArchiveLowState, NetStorageState, azure_string_to_sign, probe_write_rejection, serve
from email.utils import format_datetime


BACKENDS = ("local", "http", "webdav", "ftp", "sftp", "s3", "archive", "swift", "b2", "azureblob", "azurefiles", "seafile", "memory", "koofr", "pixeldrain", "filefabric", "internetarchive", "netstorage", "pcloud")
HARNESS_FILES = ("fixture_servers.py", "run_lab.py", "fixture_tls.py", "fixture_pcloud.py", "requirements-fixture.txt")
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
        # CreateProcess counts UTF-16 code units, including quoting and NUL.
        if os.name == "nt":
            check(len(subprocess.list2cmdline(command).encode("utf-16-le")) // 2 < 32767,
                  "child_command_line_limit")
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


MEMORY_MTIME_NS = 1704067200 * 1_000_000_000
MEMORY_MISSING = "missing-synthetic-object.bin"


def memory_plain_path(path):
    """Refuse links/reparse points, including ancestors, before following paths."""
    path = Path(path)
    if not path.is_absolute():
        return False
    try:
        for part in (path, *path.parents):
            info = part.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                return False
        return True
    except OSError:
        return False


def memory_tree_matches(root, expected, *, seed=False):
    """Exact bounded inventories, not just hashes of whichever files exist."""
    try:
        if not memory_plain_path(root) or not root.is_dir():
            return False
        files, directories, pending = {}, set(), [root]
        while pending:
            directory = pending.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    path = Path(entry.path)
                    # DirEntry.stat reports st_nlink=0 on Windows; lstat both
                    # refuses reparse traversal and obtains the real link count.
                    info = path.lstat()
                    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                        return False
                    name = path.relative_to(root).as_posix()
                    if stat.S_ISDIR(info.st_mode):
                        directories.add(name)
                        pending.append(path)
                    elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                        files[name] = info
                    else:
                        return False
                    if len(files) + len(directories) > 32:
                        return False
        expected_dirs = {parent.as_posix() for item in expected for parent in Path(item["path"]).parents
                         if parent != Path(".")}
        if set(files) != {item["path"] for item in expected} or directories != expected_dirs:
            return False
        return all(files[item["path"]].st_size == item["size"]
                   and (not seed or files[item["path"]].st_mtime_ns == MEMORY_MTIME_NS)
                   and digest(root / item["path"]) == item["sha256"] for item in expected)
    except OSError:
        return False


def memory_batch(root, bucket, expected):
    """Only fixed generated calls: no arbitrary RC methods, options or paths."""
    check(memory_plain_path(root) and root.is_dir(), "memory_unsafe_root")
    check(isinstance(bucket, str) and re.fullmatch(r"synthetic-[0-9a-f]{32}", bucket), "memory_invalid_bucket")
    # The shared three-file manifest is snapshotted before execution. No caller
    # may use this fixture as a general RC request or local-path interface.
    check(expected == fixture_manifest() and len(expected) == 3, "memory_invalid_manifest")
    names = [item["path"] for item in expected]
    fs = "Synthetic:" + bucket
    file_options = {"filesOnly": True, "showHash": True, "hashTypes": ["MD5"],
                    "noMimeType": True, "noModTime": False}
    root_list = {"_path": "operations/list", "fs": "Synthetic:", "remote": "",
                 "opt": {"dirsOnly": True, "noMimeType": True, "noModTime": True}}

    def copy(source_fs, name, destination):
        return {"_path": "operations/copyfile", "srcFs": source_fs, "srcRemote": name,
                "dstFs": destination, "dstRemote": name}

    def listing():
        return {"_path": "operations/list", "fs": fs, "remote": "",
                "opt": dict(file_options, recurse=True)}

    calls = [{"_path": "core/pid"}, dict(root_list)]
    calls += [copy(str(root / "seed"), name, fs) for name in names]
    calls += [{"_path": "core/pid"}, listing()]
    calls += [{"_path": "operations/stat", "fs": fs, "remote": name, "opt": dict(file_options)} for name in names]
    calls += [copy(fs, name, str(root / "first")) for name in names]
    calls += [{"_path": "operations/stat", "fs": fs, "remote": MEMORY_MISSING, "opt": dict(file_options)},
              copy(fs, MEMORY_MISSING, str(root / "missing")), {"_path": "core/pid"}, listing()]
    calls += [copy(fs, name, str(root / "audit")) for name in names]
    calls += [dict(root_list), {"_path": "core/pid"}]
    check(len(calls) == 22, "memory_invalid_batch_size")
    return {"concurrency": 1, "inputs": calls}


def memory_json(output):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    def invalid_constant(_):
        raise ValueError("non-finite JSON")

    check(isinstance(output, bytes) and len(output) <= MAX_OUTPUT, "memory_invalid_output")
    try:
        return json.loads(output.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise LabError("memory_invalid_json") from None


def memory_item_matches(item, expected):
    if (not isinstance(item, dict) or set(item) != {"Path", "Name", "Size", "ModTime", "IsDir", "Hashes"}
            or item["Path"] != expected["path"] or item["Name"] != expected["path"].rsplit("/", 1)[-1]
            or type(item["Size"]) is not int or item["Size"] != expected["size"] or item["IsDir"] is not False
            or item["Hashes"] != {"md5": expected["md5"]} or not isinstance(item["ModTime"], str)):
        return False
    value = item["ModTime"]
    if (not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
                         r"(?:\.0{1,9})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])", value)
            or value.endswith("-00:00")):
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc) == datetime(2024, 1, 1, tzinfo=timezone.utc)
    except (ValueError, OverflowError):
        return False


def memory_results_match(output, batch, bucket, expected, pid):
    """Outer success never substitutes for the 22 individually typed results."""
    data = memory_json(output)
    check(type(pid) is int and pid > 0, "memory_invalid_child_pid")
    check(isinstance(data, dict) and set(data) == {"results"} and isinstance(data["results"], list)
          and len(data["results"]) == 22, "memory_invalid_results")
    results = data["results"]
    for index in (0, 5, 15, 21):
        result = results[index]
        check(isinstance(result, dict) and set(result) == {"pid"} and type(result["pid"]) is int
              and result["pid"] == pid, "memory_pid_mismatch")
    check(results[1] == {"list": []}, "memory_initial_state_not_empty")
    for index in (2, 3, 4, 10, 11, 12, 17, 18, 19):
        check(results[index] == {}, "memory_copy_not_completed")
    for index in (6, 16):
        result = results[index]
        check(isinstance(result, dict) and set(result) == {"list"} and isinstance(result["list"], list)
              and len(result["list"]) == 3, "memory_inventory_mismatch")
        entries = result["list"]
        check(all(isinstance(entry, dict) and isinstance(entry.get("Path"), str) for entry in entries), "memory_inventory_mismatch")
        check(all(memory_item_matches(entry, item) for entry, item in zip(sorted(entries, key=lambda entry: entry["Path"]), expected)),
              "memory_inventory_mismatch")
    for index, item in zip((7, 8, 9), expected):
        result = results[index]
        check(isinstance(result, dict) and set(result) == {"item"} and memory_item_matches(result["item"], item),
              "memory_stat_mismatch")
    check(results[13] == {"item": None}, "memory_missing_stat_not_null")
    error = results[14]
    check(isinstance(error, dict) and set(error) == {"status", "error", "path", "input"}
          and type(error["status"]) is int and error["status"] == 404 and error["error"] == "object not found"
          and error["path"] == "operations/copyfile" and isinstance(error["input"], dict), "memory_wrong_missing_error")
    echoed = dict(error["input"])
    if "_group" in echoed:
        group = echoed.pop("_group")
        check(isinstance(group, str) and re.fullmatch(r"job/[1-9][0-9]{0,18}", group), "memory_wrong_error_group")
    check(echoed == {key: value for key, value in batch["inputs"][14].items() if key != "_path"}, "memory_wrong_error_input")
    # noModTime on root avoids making a claim about unknown bucket timestamps.
    bucket_item = {"Path": bucket, "Name": bucket, "Size": -1, "ModTime": "", "IsDir": True, "IsBucket": True}
    root_result = results[20]
    check(root_result == {"list": [bucket_item]} and type(root_result["list"][0]["Size"]) is int
          and root_result["list"][0]["IsDir"] is True and root_result["list"][0]["IsBucket"] is True,
          "memory_root_inventory_mismatch")


def memory_checks(runtime, root, row, expected):
    caps = row["capabilities"]
    before, normal_exit = len(runtime.children), False
    try:
        check(memory_plain_path(root), "memory_unsafe_root")
        prepare_files(root / "seed")
        for item in expected:
            os.utime(root / "seed" / item["path"], ns=(MEMORY_MTIME_NS, MEMORY_MTIME_NS))
        for name in ("first", "audit", "missing"):
            (root / name).mkdir(mode=0o700)
            check(memory_tree_matches(root / name, []), "memory_destination_not_empty")
        check(memory_tree_matches(root / "seed", expected, seed=True), "memory_seed_invalid")
        metadata = [dict(item, md5=hashlib.md5(FILES[item["path"]]).hexdigest()) for item in expected]
        config = config_file(root, "memory.conf", {"type": "memory", "discard": "false"})
        config_bytes, config_sha = config.read_bytes(), digest(config)
        bucket = "synthetic-" + uuid.uuid4().hex
        batch = memory_batch(root, bucket, expected)
        encoded = json.dumps(batch, separators=(",", ":"), ensure_ascii=True)
        check(len(encoded.encode()) <= 16 * 1024, "memory_batch_input_limit")
        plan = root / "batch-input.json"
        write_private(plan, encoded)
        plan_sha = digest(plan)
        code, output, _ = runtime.run(["rc", "--loopback", "job/batch", "--json", encoded], config)
        records = runtime.children[before:]
        check(len(records) == 1, "memory_not_single_process")
        process = records[0][0]
        normal_exit = type(code) is int and code == 0 and process.poll() == 0
        check(normal_exit, "memory_batch_exit_failed")
        memory_results_match(output, batch, bucket, metadata, process.pid)
        check(memory_tree_matches(root / "first", expected) and memory_tree_matches(root / "audit", expected),
              "memory_download_inventory_or_hash")
        check(memory_tree_matches(root / "missing", []), "memory_missing_artifact")
        check(memory_tree_matches(root / "seed", expected, seed=True), "memory_source_changed")
        check(memory_plain_path(config) and config.is_file() and config.stat().st_nlink == 1
              and config.read_bytes() == config_bytes and digest(config) == config_sha, "memory_config_changed")
        check(memory_plain_path(plan) and digest(plan) == plan_sha, "memory_plan_changed")
        for name in ("listing", "download_hash", "missing_object_rejection", "source_preservation", "config_preservation"):
            caps[name] = "passed"
    finally:
        records = runtime.children[before:]
        caps["cleanup"] = "passed" if normal_exit and len(records) == 1 and records[0][0].poll() == 0 else "failed"


KOOFR_MISSING = "missing-synthetic-object.bin"
KOOFR_MEMBER = "README-synthetic.txt"


def koofr_options(state, port, obscured_password):
    check(type(port) is int and 0 < port < 65536 and state.mount_id == "synthetic-mount"
          and type(state.modified_ms) is int and state.modified_ms == 1704067200123, "koofr_invalid_fixture")
    return {"type": "koofr", "provider": "other", "endpoint": f"http://127.0.0.1:{port}",
            "mountid": "synthetic-mount", "user": state.user, "password": obscured_password, "setmtime": "true"}


def koofr_metadata_matches(output, expected, *, stat_result=False):
    try:
        data = memory_json(output)  # Strict UTF-8/duplicate-key/non-finite JSON rejection.
        key = "item" if stat_result else "list"
        if not isinstance(data, dict) or set(data) != {key}:
            return False
        entries = [data[key]] if stat_result else data[key]
        if not isinstance(entries, list) or len(entries) != len(expected):
            return False
        actual = []
        for entry in entries:
            if (not isinstance(entry, dict) or set(entry) != {"Path", "Name", "Size", "ModTime", "IsDir", "Hashes"}
                    or not isinstance(entry["Path"], str) or entry["Name"] != entry["Path"].rsplit("/", 1)[-1]
                    or type(entry["Size"]) is not int or entry["IsDir"] is not False
                    or not isinstance(entry["Hashes"], dict) or set(entry["Hashes"]) != {"md5"}
                    or not isinstance(entry["ModTime"], str)):
                return False
            # Koofr stores milliseconds. Do not truncate unverified nanosecond
            # drift when normalizing an equivalent local-zone timestamp.
            match = re.fullmatch(r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})"
                                 r"\.([0-9]{1,9})(Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])", entry["ModTime"])
            if not match or match[2].ljust(9, "0") != "123000000" or match[3] == "-00:00":
                return False
            instant = datetime.fromisoformat(match[1] + match[3].replace("Z", "+00:00"))
            if instant.astimezone(timezone.utc) != datetime(2024, 1, 1, tzinfo=timezone.utc):
                return False
            actual.append((entry["Path"], entry["Size"], entry["Hashes"]["md5"]))
        return sorted(actual) == [(item["path"], item["size"], item["md5"]) for item in expected]
    except (LabError, ValueError, TypeError, KeyError, OverflowError):
        return False


def koofr_absent_mount_error_matches(output):
    try:
        data = memory_json(output)
        # RC loopback writes call failures to stdout, independently of stderr.
        return (isinstance(data, dict) and set(data) == {"error", "path", "status"}
                and type(data["status"]) is int and data["status"] == 500
                and data["path"] == "operations/copyfile"
                and data["error"] == "loopback: call failed: failed to find mount absent-synthetic-mount")
    except LabError:
        return False


def koofr_flow_matches(state, kind, member="", size=0):
    counts = ("requests", "authenticated", "auth_denied", "member_denied", "missing", "rejected_mutations",
              "payload_bytes", "unexpected", "rejected_payload_bytes")
    if (any(type(getattr(state, name)) is not int or getattr(state, name) < 0 for name in counts)
            or state.unexpected or state.budget_exceeded or state.rejected_payload_bytes
            or state.requests != len(state.events)):
        return False
    setup = [("mounts", ""), ("root_info", "/")]
    events, auth_denied, member_denied, missing, writes, payload = [], 0, 0, 0, 0, 0
    if kind == "listing":
        events = setup + [("list", "/"), ("list", "/nested")]
    elif kind in ("stat", "download") and member in FILES:
        events = setup + [("member_info", "/" + member)]
        if kind == "download":
            if type(size) is not int or size != len(FILES[member]):
                return False
            events += [("content", "/" + member)]
            payload = size
    elif kind == "missing" and member == KOOFR_MISSING:
        events, missing = setup + [("file_missing", "/" + KOOFR_MISSING)], 1
    elif kind == "wrong_password":
        events, auth_denied = [("auth_denied", "")], 1
    elif kind == "member_denied":
        events, member_denied = setup + [("member_denied", "/" + KOOFR_MEMBER)], 1
    elif kind == "absent_mount":
        events = [("mounts", "")]
    elif kind == "write":
        events, writes = setup + [("member_info", "/" + KOOFR_MEMBER), ("write_denied", "/" + KOOFR_MEMBER)], 1
    else:
        return False
    return (state.events == events and state.authenticated == len(events) - auth_denied
            and state.auth_denied == auth_denied and state.member_denied == member_denied
            and state.missing == missing and state.rejected_mutations == writes and state.payload_bytes == payload)


def koofr_one_process(runtime, action):
    before = len(runtime.children)
    result = action()
    records = runtime.children[before:]
    check(len(records) == 1 and type(result[0]) is int and result[0] >= 0
          and type(records[0][0].poll()) is int and records[0][0].poll() == result[0], "koofr_child_not_completed")
    return result


def koofr_metadata_args(kind, member=""):
    check((kind == "list" and member == "") or (kind == "stat" and member in (*FILES, KOOFR_MISSING)), "koofr_invalid_read")
    options = {"filesOnly": True, "showHash": True, "hashTypes": ["MD5"], "noModTime": False, "noMimeType": True}
    if kind == "list":
        options["recurse"] = True
    return ["rc", "--loopback", "operations/" + kind, "--json",
            json.dumps({"fs": "Synthetic:", "remote": member, "opt": options}, separators=(",", ":"))]


def koofr_checks(runtime, root, row, expected):
    caps, states, ports, preserved, empty_directories = row["capabilities"], [], [], {}, []
    before, completed = len(runtime.children), False
    user, password = "synthetic-" + uuid.uuid4().hex, "synthetic-" + uuid.uuid4().hex
    wrong_password = "wrong-synthetic-password"
    metadata = [dict(item, md5=hashlib.md5(FILES[item["path"]]).hexdigest()) for item in expected]

    @contextmanager
    def case(label, mode="normal"):
        state = KoofrState(user, password, mode="member_denied" if mode == "member_denied" else "normal",
                           wrong_password=wrong_password)
        states.append(state)
        with serve("koofr", state) as port:
            ports.append(port)
            options = koofr_options(state, port, wrong_obscured if mode == "wrong_password" else obscured)
            if mode == "absent_mount":
                options["mountid"] = "absent-synthetic-mount"
            config = config_file(root, "koofr-" + label + ".conf", options)
            data = config.read_bytes()
            preserved[config] = (data, hashlib.sha256(data).hexdigest())
            yield state, config, port

    def negative_directory(name):
        directory = root / ("negative-" + name)
        directory.mkdir(mode=0o700)
        empty_directories.append(directory)
        return directory

    try:
        check(memory_plain_path(root), "koofr_unsafe_root")
        obscured_values = []
        for value in (password, wrong_password):
            code, output, _ = koofr_one_process(runtime, lambda: runtime.run(["obscure", value]))
            check(code == 0 and re.fullmatch(rb"[A-Za-z0-9_-]{22,512}", output.strip()), "koofr_password_setup_failed")
            obscured_values.append(output.decode("ascii").strip())
        obscured, wrong_obscured = obscured_values
        downloads = root / "downloads"
        downloads.mkdir(mode=0o700)
        for phase in ("initial", "final"):
            # Final listing uses a fresh instance, not a renewal test. Every
            # earlier served state is also compared with the source snapshot.
            with case("listing-" + phase) as (state, config, _):
                code, output, _ = koofr_one_process(runtime, lambda: runtime.run(koofr_metadata_args("list"), config))
                check(code == 0 and koofr_metadata_matches(output, metadata) and koofr_flow_matches(state, "listing"),
                      "koofr_listing_mismatch")
            if phase == "final":
                break
            for index, item in enumerate(metadata):
                with case("stat-" + str(index)) as (state, config, _):
                    code, output, _ = koofr_one_process(runtime, lambda: runtime.run(koofr_metadata_args("stat", item["path"]), config))
                    check(code == 0 and koofr_metadata_matches(output, [item], stat_result=True)
                          and koofr_flow_matches(state, "stat", item["path"]), "koofr_stat_mismatch")
                with case("download-" + str(index)) as (state, config, _):
                    code, _, _ = koofr_one_process(runtime, lambda: exact_copy(runtime, config, "Synthetic:", item["path"],
                                                                               str(downloads), item["path"]))
                    check(code == 0 and memory_tree_matches(downloads, expected[:index + 1])
                          and koofr_flow_matches(state, "download", item["path"], item["size"]), "koofr_download_mismatch")
            with case("missing-stat") as (state, config, _):
                code, output, _ = koofr_one_process(runtime, lambda: runtime.run(koofr_metadata_args("stat", KOOFR_MISSING), config))
                check(code == 0 and memory_json(output) == {"item": None} and koofr_flow_matches(state, "missing", KOOFR_MISSING),
                      "koofr_missing_stat_mismatch")
            with case("missing-copy") as (state, config, _):
                destination = negative_directory("missing")
                code, output, error = koofr_one_process(runtime, lambda: exact_copy(runtime, config, "Synthetic:", KOOFR_MISSING,
                                                                                   str(destination), KOOFR_MISSING))
                check(code > 0 and b"object not found" in (output + error).lower() and memory_tree_matches(destination, [])
                      and koofr_flow_matches(state, "missing", KOOFR_MISSING), "koofr_missing_copy_mismatch")
            for mode in ("wrong_password", "member_denied", "absent_mount"):
                with case(mode, mode) as (state, config, _):
                    destination = negative_directory(mode)
                    code, output, _ = koofr_one_process(runtime, lambda: exact_copy(runtime, config, "Synthetic:", KOOFR_MEMBER,
                                                                                   str(destination), KOOFR_MEMBER))
                    check(code > 0 and memory_tree_matches(destination, []) and koofr_flow_matches(state, mode),
                          "koofr_" + mode + "_not_observed")
                    if mode == "absent_mount":
                        check(koofr_absent_mount_error_matches(output), "koofr_wrong_mount_error")
            with case("write-guard") as (state, config, port):
                item = next(item for item in metadata if item["path"] == KOOFR_MEMBER)
                code, output, _ = koofr_one_process(runtime, lambda: runtime.run(koofr_metadata_args("stat", KOOFR_MEMBER), config))
                check(code == 0 and koofr_metadata_matches(output, [item], stat_result=True)
                      and koofr_flow_matches(state, "stat", KOOFR_MEMBER), "koofr_write_setup_failed")
                client = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                try:
                    token = base64.b64encode((user + ":" + password).encode()).decode()
                    client.request("DELETE", "/api/v2/mounts/synthetic-mount/files/remove?path=%2FREADME-synthetic.txt",
                                   headers={"Authorization": "Basic " + token})
                    response = client.getresponse()
                    check(response.status == 405 and len(response.read(1025)) <= 1024 and koofr_flow_matches(state, "write"),
                          "koofr_write_guard_not_observed")
                finally:
                    client.close()
        check(memory_tree_matches(downloads, expected) and all(memory_tree_matches(path, []) for path in empty_directories),
              "koofr_final_inventory_changed")
        completed = True
    finally:
        closed = (all(state.cleanup_complete for state in states) and all(listener_closed(port) for port in ports)
                  and all(record[0].poll() is not None for record in runtime.children[before:]))
        caps["cleanup"] = "passed" if closed else "failed"
        check(closed, "koofr_cleanup_failed")
        check(all(not state.unexpected and not state.budget_exceeded and not state.rejected_payload_bytes for state in states),
              "koofr_unexpected_request_or_budget")
        check(all(served_source_unchanged(state, expected) and state.modified_ms == 1704067200123
                  and state.mount_id == "synthetic-mount" and state.user == user and state.password == password
                  and state.wrong_password == wrong_password for state in states), "koofr_source_changed")
        check(all(memory_plain_path(path) and path.is_file() and path.stat().st_nlink == 1
                  and path.read_bytes() == data and digest(path) == sha256 for path, (data, sha256) in preserved.items()),
              "koofr_config_changed")
        if completed:
            for name in caps:
                caps[name] = "passed"


PIXELDRAIN_MEMBER = "README-synthetic.txt"
PIXELDRAIN_MISSING = "missing-synthetic-object.bin"


def pixeldrain_options(state, port, *, wrong_key=False):
    check(type(port) is int and 0 < port < 65536 and type(wrong_key) is bool
          and state.root == "me" and state.modified == "2024-01-01T00:00:00.123Z"
          and state.created == "2023-12-31T00:00:00Z", "pixeldrain_invalid_fixture")
    return {"type": "pixeldrain", "api_url": f"http://127.0.0.1:{port}/api", "root_folder_id": "me",
            "api_key": state.wrong_key if wrong_key else state.api_key}


def pixeldrain_metadata_matches(output, expected, *, stat_result=False):
    try:
        data = memory_json(output)
        key = "item" if stat_result else "list"
        if not isinstance(data, dict) or set(data) != {key}:
            return False
        entries = [data[key]] if stat_result else data[key]
        if not isinstance(entries, list) or len(entries) != len(expected):
            return False
        actual = []
        for entry in entries:
            if (not isinstance(entry, dict) or set(entry) != {"Path", "Name", "Size", "ModTime", "IsDir", "Hashes"}
                    or not isinstance(entry["Path"], str) or entry["Name"] != entry["Path"].rsplit("/", 1)[-1]
                    or type(entry["Size"]) is not int or entry["IsDir"] is not False
                    or not isinstance(entry["Hashes"], dict) or set(entry["Hashes"]) != {"sha256"}
                    or not isinstance(entry["ModTime"], str)):
                return False
            match = re.fullmatch(r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})"
                                 r"\.([0-9]{1,9})(Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])", entry["ModTime"])
            if not match or match[2].ljust(9, "0") != "123000000" or match[3] == "-00:00":
                return False
            instant = datetime.fromisoformat(match[1] + match[3].replace("Z", "+00:00"))
            if instant.astimezone(timezone.utc) != datetime(2024, 1, 1, tzinfo=timezone.utc):
                return False
            actual.append((entry["Path"], entry["Size"], entry["Hashes"]["sha256"]))
        return sorted(actual) == [(item["path"], item["size"], item["sha256"]) for item in expected]
    except (LabError, ValueError, TypeError, KeyError, OverflowError):
        return False


def pixeldrain_error_matches(output, kind):
    # Pinned API error translation -> NewFs/NewObject -> RC loopback errorf.
    causes = {"missing": "object not found", "member_denied": "permission denied",
              "wrong_key": "failed to get user data: pd api: authentication failed"}
    if kind not in causes:
        return False
    try:
        data = memory_json(output)
        return (isinstance(data, dict) and set(data) == {"error", "path", "status"}
                and type(data["status"]) is int and data["status"] == 500
                and data["path"] == "operations/copyfile"
                and data["error"] == "loopback: call failed: " + causes[kind])
    except LabError:
        return False


def pixeldrain_flow_matches(state, kind, member="", size=0):
    counts = ("requests", "authenticated", "auth_denied", "member_denied", "missing", "rejected_mutations",
              "payload_bytes", "unexpected", "rejected_payload_bytes", "root_stats")
    if any(type(getattr(state, key)) is not int or getattr(state, key) < 0 for key in counts):
        return False
    if state.budget_exceeded or state.unexpected or state.rejected_payload_bytes or type(size) is not int or size < 0:
        return False
    setup = [("user_info", ""), ("root_stat", "/")]
    auth_denied = denied = missing = writes = payload = 0
    roots, user_checked = 1, True
    if kind == "listing":
        events, roots = setup + [("root_stat", "/"), ("directory_stat", "nested")], 2
    elif kind in ("stat", "download") and member in FILES:
        events = setup + [("member_stat", member)]
        if kind == "download":
            events += [("content", member)]
            payload = size
    elif kind == "missing" and member == PIXELDRAIN_MISSING:
        events, missing = setup + [("file_missing", PIXELDRAIN_MISSING)], 1
    elif kind == "wrong_key":
        events, auth_denied, roots, user_checked = [("auth_denied", "")], 1, 0, False
    elif kind == "member_denied":
        events, denied = setup + [("member_denied", PIXELDRAIN_MEMBER)], 1
    elif kind == "write":
        events = setup + [("member_stat", PIXELDRAIN_MEMBER), ("write_denied", PIXELDRAIN_MEMBER)]
        writes = 1
    else:
        return False
    return (state.events == events and state.requests == len(events)
            and state.authenticated == len(events) - auth_denied and state.auth_denied == auth_denied
            and state.member_denied == denied and state.missing == missing and state.rejected_mutations == writes
            and state.payload_bytes == payload and state.root_stats == roots and state.user_checked is user_checked)


def pixeldrain_one_process(runtime, action):
    before = len(runtime.children)
    result = action()
    check(len(runtime.children) == before + 1 and type(result[0]) is int and result[0] >= 0,
          "pixeldrain_process_count_or_exit")
    observed_exit = runtime.children[-1][0].poll()
    check(type(observed_exit) is int and observed_exit == result[0], "pixeldrain_process_not_reaped")
    return result


def pixeldrain_metadata_args(kind, member=""):
    check((kind == "list" and member == "") or (kind == "stat" and member in (*FILES, PIXELDRAIN_MISSING)),
          "pixeldrain_invalid_metadata_request")
    options = {"filesOnly": True, "showHash": True, "hashTypes": ["sha256"], "noModTime": False, "noMimeType": True}
    if kind == "list":
        options["recurse"] = True
    return ["rc", "--loopback", "operations/" + kind, "--json",
            json.dumps({"fs": "Synthetic:", "remote": member, "opt": options}, separators=(",", ":"))]


def pixeldrain_checks(runtime, root, row, expected):
    caps, states, ports, preserved, empty_directories = row["capabilities"], [], [], {}, []
    before, completed = len(runtime.children), False
    api_key, wrong_key = "synthetic-" + uuid.uuid4().hex, "wrong-synthetic-key"

    @contextmanager
    def case(label, mode="normal"):
        state = PixeldrainState(api_key, mode="member_denied" if mode == "member_denied" else "normal", wrong_key=wrong_key)
        states.append(state)
        with serve("pixeldrain", state) as port:
            ports.append(port)
            config = config_file(root, "pixeldrain-" + label + ".conf", pixeldrain_options(state, port, wrong_key=mode == "wrong_key"))
            data = config.read_bytes()
            preserved[config] = (data, hashlib.sha256(data).hexdigest())
            yield state, config, port

    def negative_directory(name):
        directory = root / ("negative-" + name)
        directory.mkdir(mode=0o700)
        empty_directories.append(directory)
        return directory

    try:
        check(memory_plain_path(root), "pixeldrain_unsafe_root")
        downloads = root / "downloads"
        downloads.mkdir(mode=0o700)
        for phase in ("initial", "final"):
            with case("listing-" + phase) as (state, config, _):
                code, output, _ = pixeldrain_one_process(runtime, lambda: runtime.run(pixeldrain_metadata_args("list"), config))
                check(code == 0 and pixeldrain_metadata_matches(output, expected) and pixeldrain_flow_matches(state, "listing"),
                      "pixeldrain_listing_mismatch")
            if phase == "final":
                break
            for index, item in enumerate(expected):
                with case("stat-" + str(index)) as (state, config, _):
                    code, output, _ = pixeldrain_one_process(runtime, lambda: runtime.run(pixeldrain_metadata_args("stat", item["path"]), config))
                    check(code == 0 and pixeldrain_metadata_matches(output, [item], stat_result=True)
                          and pixeldrain_flow_matches(state, "stat", item["path"]), "pixeldrain_stat_mismatch")
                with case("download-" + str(index)) as (state, config, _):
                    code, _, _ = pixeldrain_one_process(runtime, lambda: exact_copy(runtime, config, "Synthetic:", item["path"],
                                                                                    str(downloads), item["path"]))
                    check(code == 0 and memory_tree_matches(downloads, expected[:index + 1])
                          and pixeldrain_flow_matches(state, "download", item["path"], item["size"]), "pixeldrain_download_mismatch")
            with case("missing-stat") as (state, config, _):
                code, output, _ = pixeldrain_one_process(runtime, lambda: runtime.run(pixeldrain_metadata_args("stat", PIXELDRAIN_MISSING), config))
                check(code == 0 and memory_json(output) == {"item": None}
                      and pixeldrain_flow_matches(state, "missing", PIXELDRAIN_MISSING), "pixeldrain_missing_stat_mismatch")
            for label, kind, member in (("missing-copy", "missing", PIXELDRAIN_MISSING),
                                        ("wrong_key", "wrong_key", PIXELDRAIN_MEMBER),
                                        ("member_denied", "member_denied", PIXELDRAIN_MEMBER)):
                with case(label, kind) as (state, config, _):
                    destination = negative_directory(kind)
                    code, output, _ = pixeldrain_one_process(runtime, lambda: exact_copy(runtime, config, "Synthetic:", member,
                                                                                        str(destination), member))
                    check(code > 0 and pixeldrain_error_matches(output, kind) and memory_tree_matches(destination, [])
                          and pixeldrain_flow_matches(state, kind, member), "pixeldrain_" + kind + "_not_observed")
            with case("write-guard") as (state, config, port):
                item = next(item for item in expected if item["path"] == PIXELDRAIN_MEMBER)
                code, output, _ = pixeldrain_one_process(runtime, lambda: runtime.run(pixeldrain_metadata_args("stat", PIXELDRAIN_MEMBER), config))
                check(code == 0 and pixeldrain_metadata_matches(output, [item], stat_result=True)
                      and pixeldrain_flow_matches(state, "stat", PIXELDRAIN_MEMBER), "pixeldrain_write_setup_failed")
                client = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                try:
                    token = base64.b64encode((":" + api_key).encode()).decode()
                    client.request("DELETE", "/api/filesystem/me/README-synthetic.txt", headers={"Authorization": "Basic " + token})
                    response = client.getresponse()
                    body = response.read(1025)
                    check(response.status == 405 and len(body) <= 1024
                          and memory_json(body) == {"value": "fixture_read_only", "message": "Synthetic fixture is read only"}
                          and pixeldrain_flow_matches(state, "write"), "pixeldrain_write_guard_not_observed")
                finally:
                    client.close()
        check(memory_tree_matches(downloads, expected) and all(memory_tree_matches(path, []) for path in empty_directories),
              "pixeldrain_final_inventory_changed")
        completed = True
    finally:
        closed = (all(state.cleanup_complete for state in states) and all(listener_closed(port) for port in ports)
                  and all(record[0].poll() is not None for record in runtime.children[before:]))
        caps["cleanup"] = "passed" if closed else "failed"
        check(closed, "pixeldrain_cleanup_failed")
        check(all(not state.unexpected and not state.budget_exceeded and not state.rejected_payload_bytes for state in states),
              "pixeldrain_unexpected_request_or_budget")
        check(all(served_source_unchanged(state, expected) and state.root == "me"
                  and state.modified == "2024-01-01T00:00:00.123Z" and state.created == "2023-12-31T00:00:00Z"
                  and state.api_key == api_key and state.wrong_key == wrong_key for state in states), "pixeldrain_source_changed")
        check(all(memory_plain_path(path) and path.is_file() and path.stat().st_nlink == 1
                  and path.read_bytes() == data and digest(path) == sha256 for path, (data, sha256) in preserved.items()),
              "pixeldrain_config_changed")
        if completed:
            for name in caps:
                caps[name] = "passed"


FILEFABRIC_MISSING = "missing-synthetic-object.bin"
PCLOUD_MEMBER = "README-synthetic.txt"
PCLOUD_MISSING = "missing-synthetic-object.bin"
PCLOUD_IDS = {"README-synthetic.txt": "f301", "nested/space name.txt": "f302", "nested/bytes.bin": "f303"}
PCLOUD_CAPABILITIES = ("listing", "download_hash", "missing_object_rejection", "saved_token_read",
                       "saved_token_rejection", "read_denial", "source_preservation", "config_preservation",
                       "fixture_write_rejection", "cleanup")


def pcloud_dependencies():
    # Bind the installed metadata AND the modules actually loaded to the hashed
    # lock. This is not an attestation of wheel contents or an ambient install.
    import importlib
    import importlib.metadata
    expected = {"cffi": "2.1.1", "cryptography": "50.0.2", "pycparser": "3.0"}
    # The pycparser 3.0 wheel reports the literal module version "3.00".
    loaded_versions = dict(expected, pycparser="3.00")
    lock = (Path(__file__).parent / "requirements-fixture.txt").read_text(encoding="utf-8")
    declared = re.findall(r"^([a-z][a-z0-9_-]*)==([0-9.]+) \\", lock, re.MULTILINE)
    check(len(declared) == len(expected) and dict(declared) == expected, "pcloud_dependency_lock_mismatch")
    try:
        for name, version in expected.items():
            check(importlib.metadata.version(name) == version, "pcloud_dependency_version_mismatch")
            check(getattr(importlib.import_module(name), "__version__", None) == loaded_versions[name],
                  "pcloud_loaded_dependency_version_mismatch")
    except (ImportError, importlib.metadata.PackageNotFoundError):
        raise LabError("pcloud_dependencies_missing") from None


def pcloud_options(state, port, *, wrong_token=False):
    check(type(port) is int and 0 < port < 65536 and type(wrong_token) is bool
          and all(isinstance(token, str) and re.fullmatch(r"[A-Za-z0-9_-]{24,96}", token)
                  for token in (state.token, state.wrong_token)) and state.token != state.wrong_token,
          "pcloud_invalid_fixture")
    authority = f"127.0.0.1:{port}"
    # NewClient precedes the backend's token-URL update. Both overrides are
    # necessary even though this closed saved-token mode permits no OAuth calls.
    return {"type": "pcloud", "hostname": authority, "root_folder_id": "d100",
            "client_id": "synthetic-client", "client_secret": "", "client_credentials": "false",
            "auth_url": "https://" + authority + "/oauth2/authorize",
            "token_url": "https://" + authority + "/oauth2_token",
            "token": json.dumps({"access_token": state.wrong_token if wrong_token else state.token,
                                 "token_type": "Bearer", "expiry": "0001-01-01T00:00:00Z"}, separators=(",", ":"))}


def pcloud_metadata_matches(output, expected, *, stat_result=False):
    try:
        data = memory_json(output)
        key = "item" if stat_result else "list"
        if not isinstance(data, dict) or set(data) != {key}:
            return False
        entries = [data[key]] if stat_result else data[key]
        if not isinstance(entries, list) or len(entries) != len(expected):
            return False
        actual = []
        for entry in entries:
            if (not isinstance(entry, dict) or set(entry) != {"Path", "Name", "Size", "ModTime", "IsDir", "ID", "Hashes"}
                    or not isinstance(entry["Path"], str) or entry["Path"] not in FILES
                    or entry["Name"] != entry["Path"].rsplit("/", 1)[-1]
                    or entry["ID"] != PCLOUD_IDS[entry["Path"]] or type(entry["Size"]) is not int
                    or entry["IsDir"] is not False or not isinstance(entry["ModTime"], str)
                    or entry["Hashes"] != {"md5": hashlib.md5(FILES[entry["Path"]]).hexdigest(),
                                           "sha1": hashlib.sha1(FILES[entry["Path"]]).hexdigest()}):
                return False
            match = re.fullmatch(r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])", entry["ModTime"])
            if not match or match[2] == "-00:00":
                return False
            instant = datetime.fromisoformat(entry["ModTime"].replace("Z", "+00:00"))
            if instant.astimezone(timezone.utc) != datetime(2024, 1, 1, tzinfo=timezone.utc):
                return False
            actual.append((entry["Path"], entry["Size"]))
        return sorted(actual) == [(item["path"], item["size"]) for item in expected]
    except (LabError, ValueError, TypeError, KeyError, OverflowError):
        return False


def pcloud_error_matches(output, kind):
    causes = {"missing": "object not found",
              "wrong_token": "couldn't list files: pcloud error: synthetic token rejected (2000)",
              "member_denied": "failed to open source object: pcloud error: synthetic member denied (2003)"}
    if kind not in causes:
        return False
    try:
        data = memory_json(output)
        return (isinstance(data, dict) and set(data) == {"error", "path", "status"}
                and type(data["status"]) is int and data["status"] == 500
                and data["path"] == "operations/copyfile" and data["error"] == "loopback: call failed: " + causes[kind])
    except LabError:
        return False


def pcloud_flow_matches(state, kind, member="", size=0):
    counts = ("requests", "authenticated", "auth_denied", "member_denied", "rejected_mutations", "payload_bytes",
              "unexpected", "rejected_payload_bytes", "oauth_requests")
    if any(type(getattr(state, key)) is not int or getattr(state, key) < 0 for key in counts):
        return False
    if state.budget_exceeded or state.unexpected or state.rejected_payload_bytes or state.oauth_requests:
        return False
    auth_denied = denied = writes = payload = 0
    events = [("root_list", "")]
    if kind == "listing" and member == "":
        # Listing can schedule independent checksum calls in either order.
        expected_tail = sorted(("checksum", name) for name in FILES)
        if (state.events[:1] != [("list_recursive", "")] or sorted(state.events[1:]) != expected_tail):
            return False
        events = state.events
    elif kind in ("stat", "download") and member in FILES:
        if member.startswith("nested/"):
            events.append(("nested_list", "nested"))
        # Native copy fingerprints the source for its local partial-file name
        # before Open; pCloud caches those hashes for post-copy verification.
        events.append(("checksum", member))
        if kind == "download":
            if type(size) is not int or size != len(FILES[member]):
                return False
            events.extend((("link", member), ("content", member)))
            payload = size
    elif kind == "missing" and member == PCLOUD_MISSING:
        pass
    elif kind == "wrong_token" and member == PCLOUD_MEMBER:
        events = [("auth_denied", "")]
        auth_denied = 1
    elif kind == "member_denied" and member == PCLOUD_MEMBER:
        events.extend((("checksum", member), ("link", member), ("content_denied", member)))
        denied = 1
    elif kind == "write" and member == PCLOUD_MEMBER:
        events.extend((("checksum", member), ("write_denied", member)))
        writes = 1
    else:
        return False
    return (state.events == events and state.requests == len(events) and state.authenticated == len(events) - auth_denied
            and state.auth_denied == auth_denied and state.member_denied == denied
            and state.rejected_mutations == writes and state.payload_bytes == payload)


def pcloud_metadata_args(kind, member=""):
    check((kind == "list" and member == "") or (kind == "stat" and member in (*FILES, PCLOUD_MISSING)),
          "pcloud_invalid_metadata_request")
    options = {"filesOnly": True, "showHash": True, "noModTime": False, "noMimeType": True}
    if kind == "list":
        options["recurse"] = True
    return ["rc", "--loopback", "operations/" + kind, "--json",
            json.dumps({"fs": "Synthetic:", "remote": member, "opt": options}, separators=(",", ":"))]


def pcloud_checks(runtime, root, row, expected):
    from fixture_pcloud import PCloudState, serve_pcloud
    caps, states, fixtures, preserved, empty_directories = row["capabilities"], [], [], {}, []
    before, completed = len(runtime.children), False
    token, wrong_token = "synthetic-" + uuid.uuid4().hex, "wrong-synthetic-" + uuid.uuid4().hex

    @contextmanager
    def case(label, mode="normal"):
        state = PCloudState(FILES, token, wrong_token, PCLOUD_MEMBER if mode == "member_denied" else None)
        states.append(state)
        with serve_pcloud(root, state) as fixture:
            fixtures.append(fixture)
            options = pcloud_options(state, fixture.port)
            if mode == "wrong_token":
                valid = config_file(root, "pcloud-" + label + "-valid.conf", options)
                data = valid.read_bytes()
                preserved[valid] = (data, hashlib.sha256(data).hexdigest())
                options = pcloud_options(state, fixture.port, wrong_token=True)
            config = config_file(root, "pcloud-" + label + ".conf", options)
            data = config.read_bytes()
            preserved[config] = (data, hashlib.sha256(data).hexdigest())
            yield state, config, fixture

    def run(fixture, config, args):
        # Revalidate dependency and CA bindings immediately before every child.
        pcloud_dependencies()
        start = len(runtime.children)
        result = runtime.run([*fixture.rclone_ca_args(), *args], config)
        check(len(runtime.children) == start + 1 and type(result[0]) is int and result[0] >= 0
              and runtime.children[-1][0].poll() == result[0], "pcloud_process_count_or_exit")
        return result

    def copy(fixture, config, member, destination):
        return run(fixture, config, ["rc", "--loopback", "operations/copyfile", "srcFs=Synthetic:",
                   "srcRemote=" + member, "dstFs=" + str(destination), "dstRemote=" + member])

    try:
        check(memory_plain_path(root), "pcloud_unsafe_root")
        pcloud_dependencies()
        downloads = root / "downloads"
        downloads.mkdir(mode=0o700)
        for phase in ("initial", "final"):
            with case("listing-" + phase) as (state, config, fixture):
                code, output, _ = run(fixture, config, pcloud_metadata_args("list"))
                check(code == 0 and pcloud_metadata_matches(output, expected) and pcloud_flow_matches(state, "listing"),
                      "pcloud_listing_mismatch")
            if phase == "final":
                break
            for index, item in enumerate(expected):
                with case("stat-" + str(index)) as (state, config, fixture):
                    code, output, _ = run(fixture, config, pcloud_metadata_args("stat", item["path"]))
                    check(code == 0 and pcloud_metadata_matches(output, [item], stat_result=True)
                          and pcloud_flow_matches(state, "stat", item["path"]), "pcloud_stat_mismatch")
                with case("download-" + str(index)) as (state, config, fixture):
                    code, _, _ = copy(fixture, config, item["path"], downloads)
                    check(code == 0 and memory_tree_matches(downloads, expected[:index + 1])
                          and pcloud_flow_matches(state, "download", item["path"], item["size"]), "pcloud_download_mismatch")
            with case("missing-stat") as (state, config, fixture):
                code, output, _ = run(fixture, config, pcloud_metadata_args("stat", PCLOUD_MISSING))
                check(code == 0 and memory_json(output) == {"item": None} and pcloud_flow_matches(state, "missing", PCLOUD_MISSING),
                      "pcloud_missing_stat_mismatch")
            for label, member in (("missing", PCLOUD_MISSING), ("wrong_token", PCLOUD_MEMBER), ("member_denied", PCLOUD_MEMBER)):
                with case(label, label) as (state, config, fixture):
                    destination = root / ("negative-" + label)
                    destination.mkdir(mode=0o700)
                    empty_directories.append(destination)
                    code, output, _ = copy(fixture, config, member, destination)
                    check(code > 0 and pcloud_error_matches(output, label) and memory_tree_matches(destination, [])
                          and pcloud_flow_matches(state, label, member), "pcloud_" + label + "_not_observed")
            item = next(item for item in expected if item["path"] == PCLOUD_MEMBER)
            with case("write-guard") as (state, config, fixture):
                code, output, _ = run(fixture, config, pcloud_metadata_args("stat", PCLOUD_MEMBER))
                check(code == 0 and pcloud_metadata_matches(output, [item], stat_result=True)
                      and pcloud_flow_matches(state, "stat", PCLOUD_MEMBER), "pcloud_write_setup_failed")
                client = http.client.HTTPSConnection("127.0.0.1", fixture.port, timeout=3, context=fixture.client_context())
                try:
                    client.request("POST", "/deletefile?fileid=301", headers={"Authorization": "Bearer " + token})
                    response = client.getresponse()
                    body = response.read(1025)
                    check(response.status == 405 and len(body) <= 1024 and memory_json(body) == {"status": "fixture_read_only"}
                          and pcloud_flow_matches(state, "write", PCLOUD_MEMBER), "pcloud_write_guard_not_observed")
                finally:
                    client.close()
        check(len(runtime.children) == before + 13 and sum(state.requests for state in states) == 40,
              "pcloud_total_process_or_request_mismatch")
        check(memory_tree_matches(downloads, expected) and all(memory_tree_matches(path, []) for path in empty_directories),
              "pcloud_final_inventory_changed")
        completed = True
    finally:
        closed = (all(state.cleanup_complete for state in states) and all(fixture.cleanup_complete for fixture in fixtures)
                  and all(listener_closed(fixture.port) for fixture in fixtures)
                  and all(record[0].poll() is not None for record in runtime.children[before:]))
        caps["cleanup"] = "passed" if closed else "failed"
        check(closed, "pcloud_cleanup_failed")
        check(all(not fixture.snapshot()["transport"]["failure_codes"] for fixture in fixtures), "pcloud_transport_failure")
        check(all(not state.unexpected and not state.budget_exceeded and not state.rejected_payload_bytes
                  and not state.oauth_requests for state in states), "pcloud_unexpected_request_or_budget")
        check(all(state.source_preserved() and served_source_unchanged(state, expected) for state in states), "pcloud_source_changed")
        check(all(memory_plain_path(path) and path.is_file() and path.stat().st_nlink == 1
                  and path.read_bytes() == data and digest(path) == sha256 for path, (data, sha256) in preserved.items()),
              "pcloud_config_changed")
        if completed:
            for name in caps:
                caps[name] = "passed"


NETSTORAGE_MEMBER = "README-synthetic.txt"
NETSTORAGE_MISSING = "missing-synthetic-object.bin"
NETSTORAGE_FS = "Synthetic:"
NETSTORAGE_CAPABILITIES = ("listing", "download_hash", "missing_object_rejection", "authentication_rejection",
                                "source_preservation", "config_preservation", "fixture_write_rejection", "cleanup")


def netstorage_options(state, port, obscured):
    check(type(port) is int and 0 < port < 65536 and state.prefix == "/123456/synthetic"
          and state.account == "synthetic-account" and isinstance(obscured, str)
          and re.fullmatch(r"[A-Za-z0-9_-]{22,512}", obscured), "netstorage_invalid_fixture")
    return {"type": "netstorage", "protocol": "http", "host": f"127.0.0.1:{port}/123456/synthetic/",
            "account": "synthetic-account", "secret": obscured}


def netstorage_metadata_matches(output, expected, *, stat_result=False):
    try:
        data = memory_json(output)
        key = "item" if stat_result else "list"
        if not isinstance(data, dict) or set(data) != {key}:
            return False
        entries = [data[key]] if stat_result else data[key]
        if not isinstance(entries, list) or len(entries) != len(expected):
            return False
        actual = []
        for entry in entries:
            if (not isinstance(entry, dict) or set(entry) != {"Path", "Name", "Size", "ModTime", "IsDir", "Hashes"}
                    or not isinstance(entry["Path"], str) or entry["Path"] not in FILES
                    or entry["Name"] != entry["Path"].rsplit("/", 1)[-1]
                    or type(entry["Size"]) is not int or entry["IsDir"] is not False
                    or not isinstance(entry["ModTime"], str)
                    or entry["Hashes"] != {"md5": hashlib.md5(FILES[entry["Path"]]).hexdigest()}):
                return False
            match = re.fullmatch(r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])", entry["ModTime"])
            if not match or match[2] == "-00:00":
                return False
            instant = datetime.fromisoformat(entry["ModTime"].replace("Z", "+00:00"))
            if instant.astimezone(timezone.utc) != datetime(2024, 1, 1, tzinfo=timezone.utc):
                return False
            actual.append((entry["Path"], entry["Size"]))
        return sorted(actual) == [(item["path"], item["size"]) for item in expected]
    except (LabError, ValueError, TypeError, KeyError, OverflowError):
        return False


def netstorage_error_matches(output, kind):
    causes = {"missing": "object not found",
              "wrong_secret": 'failed to call NetStorage API: HTTP error 403 (403 Forbidden) returned body: "Synthetic authentication denied"',
              "member_denied": 'failed to open source object: failed to call NetStorage API: HTTP error 403 (403 Forbidden) returned body: "Synthetic member denied"'}
    if kind not in causes:
        return False
    try:
        data = memory_json(output)
        return (isinstance(data, dict) and set(data) == {"error", "path", "status"}
                and type(data["status"]) is int and data["status"] == 500
                and data["path"] == "operations/copyfile" and data["error"] == "loopback: call failed: " + causes[kind])
    except LabError:
        return False


def netstorage_flow_matches(state, kind, member="", size=0):
    counts = ("requests", "authenticated", "auth_denied", "member_denied", "missing", "rejected_mutations", "payload_bytes",
              "unexpected", "rejected_payload_bytes")
    if any(type(getattr(state, key)) is not int or getattr(state, key) < 0 for key in counts):
        return False
    if state.budget_exceeded or state.unexpected or state.rejected_payload_bytes or type(size) is not int or size < 0:
        return False
    events = [("root_stat", "")]
    auth_denied = denied = missing = writes = payload = 0
    if kind == "listing" and member == "":
        events.append(("listing", ""))
    elif kind in ("stat", "download") and member in FILES:
        events.append(("member_stat", member))
        if kind == "download":
            if size != len(FILES[member]):
                return False
            events.append(("content", member))
            payload = size
    elif kind == "missing" and member == NETSTORAGE_MISSING:
        events.append(("file_missing", member))
        missing = 1
    elif kind == "wrong_secret" and member == NETSTORAGE_MEMBER:
        events = [("auth_denied", ""), ("auth_denied", member)]
        auth_denied = 2
    elif kind in ("member_denied", "write") and member == NETSTORAGE_MEMBER:
        events += [("member_stat", member), ("content_denied" if kind == "member_denied" else "write_denied", member)]
        denied, writes = (1, 0) if kind == "member_denied" else (0, 1)
    else:
        return False
    return (state.events == events and state.requests == len(events) and state.authenticated == len(events) - auth_denied
            and state.auth_denied == auth_denied and state.missing == missing and state.member_denied == denied
            and state.rejected_mutations == writes and state.payload_bytes == payload)


def netstorage_guard_headers(secret):
    # The only direct mutation-shaped call is a signed fixture safety probe.
    uri, action = "/123456/synthetic/README-synthetic.txt", "version=1&action=delete"
    data = f"5, 0.0.0.0, 0.0.0.0, {int(time.time())}, {uuid.uuid4().int % (2**63)},synthetic-account"
    message = data + uri + "\nx-akamai-acs-action:" + action + "\n"
    signature = base64.b64encode(hmac.new(secret.encode("ascii"), message.encode("ascii"), hashlib.sha256).digest()).decode("ascii")
    return {"X-Akamai-ACS-Action": action, "X-Akamai-ACS-Auth-Data": data, "X-Akamai-ACS-Auth-Sign": signature}


def netstorage_one_process(runtime, action):
    before = len(runtime.children)
    result = action()
    check(len(runtime.children) == before + 1 and type(result[0]) is int and result[0] >= 0,
          "netstorage_process_count_or_exit")
    observed_exit = runtime.children[-1][0].poll()
    check(type(observed_exit) is int and observed_exit == result[0], "netstorage_process_not_reaped")
    return result


def netstorage_metadata_args(kind, member=""):
    check((kind == "list" and member == "") or (kind == "stat" and member in (*FILES, NETSTORAGE_MISSING)),
          "netstorage_invalid_metadata_request")
    options = {"filesOnly": True, "showHash": True, "noModTime": False, "noMimeType": True}
    if kind == "list":
        options["recurse"] = True
    return ["rc", "--loopback", "operations/" + kind, "--json",
            json.dumps({"fs": NETSTORAGE_FS, "remote": member, "opt": options}, separators=(",", ":"))]


def netstorage_checks(runtime, root, row, expected):
    caps, states, ports, preserved, snapshots, empty_directories = row["capabilities"], [], [], {}, [], []
    before, completed = len(runtime.children), False
    secret, wrong_secret = "synthetic-" + uuid.uuid4().hex, "wrong-synthetic-" + uuid.uuid4().hex

    @contextmanager
    def case(label, mode="normal"):
        state = NetStorageState(secret, wrong_secret, mode)
        states.append(state)
        snapshots.append(json.dumps(state.metadata, sort_keys=True, separators=(",", ":")))
        with serve("netstorage", state) as port:
            ports.append(port)
            options = netstorage_options(state, port, obscured)
            if mode == "wrong_secret":
                valid = config_file(root, "netstorage-" + label + "-valid.conf", options)
                original = valid.read_bytes()
                preserved[valid] = (original, hashlib.sha256(original).hexdigest())
                options = dict(options, secret=wrong_obscured)
            config = config_file(root, "netstorage-" + label + ".conf", options)
            data = config.read_bytes()
            preserved[config] = (data, hashlib.sha256(data).hexdigest())
            yield state, config, port

    def negative_directory(name):
        directory = root / ("negative-" + name)
        directory.mkdir(mode=0o700)
        empty_directories.append(directory)
        return directory

    try:
        check(memory_plain_path(root), "netstorage_unsafe_root")
        obscured_values = []
        for value in (secret, wrong_secret):
            code, output, _ = netstorage_one_process(runtime, lambda: runtime.run(["obscure", value]))
            check(code == 0 and re.fullmatch(rb"[A-Za-z0-9_-]{22,512}", output.strip()), "netstorage_secret_setup_failed")
            obscured_values.append(output.decode("ascii").strip())
        obscured, wrong_obscured = obscured_values
        check(obscured != wrong_obscured, "netstorage_secret_setup_not_distinct")
        downloads = root / "downloads"
        downloads.mkdir(mode=0o700)
        for phase in ("initial", "final"):
            with case("listing-" + phase) as (state, config, _):
                code, output, _ = netstorage_one_process(runtime, lambda: runtime.run(netstorage_metadata_args("list"), config))
                check(code == 0 and netstorage_metadata_matches(output, expected) and netstorage_flow_matches(state, "listing"),
                      "netstorage_listing_mismatch")
            if phase == "final":
                break
            for index, item in enumerate(expected):
                with case("stat-" + str(index)) as (state, config, _):
                    code, output, _ = netstorage_one_process(runtime, lambda: runtime.run(netstorage_metadata_args("stat", item["path"]), config))
                    check(code == 0 and netstorage_metadata_matches(output, [item], stat_result=True)
                          and netstorage_flow_matches(state, "stat", item["path"]), "netstorage_stat_mismatch")
                with case("download-" + str(index)) as (state, config, _):
                    code, _, _ = netstorage_one_process(runtime, lambda: exact_copy(runtime, config, NETSTORAGE_FS, item["path"],
                                                                                       str(downloads), item["path"]))
                    check(code == 0 and memory_tree_matches(downloads, expected[:index + 1])
                          and netstorage_flow_matches(state, "download", item["path"], item["size"]), "netstorage_download_mismatch")
            with case("missing-stat") as (state, config, _):
                code, output, _ = netstorage_one_process(runtime, lambda: runtime.run(netstorage_metadata_args("stat", NETSTORAGE_MISSING), config))
                check(code == 0 and memory_json(output) == {"item": None}
                      and netstorage_flow_matches(state, "missing", NETSTORAGE_MISSING), "netstorage_missing_stat_mismatch")
            for label, member in (("missing", NETSTORAGE_MISSING), ("wrong_secret", NETSTORAGE_MEMBER), ("member_denied", NETSTORAGE_MEMBER)):
                with case(label, label if label in ("member_denied", "wrong_secret") else "normal") as (state, config, _):
                    destination = negative_directory(label)
                    code, output, _ = netstorage_one_process(runtime, lambda: exact_copy(runtime, config, NETSTORAGE_FS, member,
                                                                                       str(destination), member))
                    check(code > 0 and netstorage_error_matches(output, label) and memory_tree_matches(destination, [])
                          and netstorage_flow_matches(state, label, member), "netstorage_" + label + "_not_observed")
            item = next(item for item in expected if item["path"] == NETSTORAGE_MEMBER)
            with case("write-guard") as (state, config, port):
                code, output, _ = netstorage_one_process(runtime, lambda: runtime.run(netstorage_metadata_args("stat", NETSTORAGE_MEMBER), config))
                check(code == 0 and netstorage_metadata_matches(output, [item], stat_result=True)
                      and netstorage_flow_matches(state, "stat", NETSTORAGE_MEMBER), "netstorage_write_setup_failed")
                client = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                try:
                    client.request("POST", "/123456/synthetic/README-synthetic.txt", headers=netstorage_guard_headers(secret))
                    response = client.getresponse()
                    body = response.read(1025)
                    check(response.status == 405 and len(body) <= 1024 and memory_json(body) == {"status": "fixture_read_only"}
                          and netstorage_flow_matches(state, "write", NETSTORAGE_MEMBER), "netstorage_write_guard_not_observed")
                finally:
                    client.close()
        check(memory_tree_matches(downloads, expected)
              and all(memory_tree_matches(path, []) for path in empty_directories), "netstorage_final_inventory_changed")
        completed = True
    finally:
        closed = (all(state.cleanup_complete for state in states) and all(listener_closed(port) for port in ports)
                  and all(record[0].poll() is not None for record in runtime.children[before:]))
        caps["cleanup"] = "passed" if closed else "failed"
        check(closed, "netstorage_cleanup_failed")
        check(all(not state.unexpected and not state.budget_exceeded and not state.rejected_payload_bytes for state in states),
              "netstorage_unexpected_request_or_budget")
        check(all(served_source_unchanged(state, expected) and state.prefix == "/123456/synthetic"
                  and state.account == state.user == "synthetic-account" and state.secret == state.password == secret
                  and state.wrong_secret == wrong_secret and state.modified == 1704067200
                  and state.missing_path == NETSTORAGE_MISSING and state.denied_path == NETSTORAGE_MEMBER
                  and json.dumps(state.metadata, sort_keys=True, separators=(",", ":")) == snapshot
                  for state, snapshot in zip(states, snapshots)), "netstorage_source_changed")
        check(all(memory_plain_path(path) and path.is_file() and path.stat().st_nlink == 1
                  and path.read_bytes() == data and digest(path) == sha256 for path, (data, sha256) in preserved.items()),
              "netstorage_config_changed")
        if completed:
            for name in caps:
                caps[name] = "passed"


INTERNETARCHIVE_MEMBER = "README-synthetic.txt"
INTERNETARCHIVE_MISSING = "missing-synthetic-object.bin"
INTERNETARCHIVE_FS = "Synthetic:synthetic-item"
INTERNETARCHIVE_CAPABILITIES = ("listing", "download_hash", "missing_object_rejection", "anonymous_read", "read_denial",
                                "source_preservation", "config_preservation", "fixture_write_rejection", "cleanup")


def internetarchive_options(state, port):
    check(type(port) is int and 0 < port < 65536 and state.item == "synthetic-item"
          and state.user == state.password == "", "internetarchive_invalid_fixture")
    # Nonzero wait_archive selects nanosecond Precision(); this fixture never
    # invokes a mutation, archive task or wait-for-upload operation.
    return {"type": "internetarchive", "endpoint": f"http://127.0.0.1:{port}/ias3",
            "front_endpoint": f"http://127.0.0.1:{port}/front", "access_key_id": "", "secret_access_key": "",
            "wait_archive": "1ns", "item_derive": "false"}


def internetarchive_metadata_matches(output, expected, *, stat_result=False, summation=False):
    try:
        data = memory_json(output)
        key = "item" if stat_result else "list"
        if not isinstance(data, dict) or set(data) != {key}:
            return False
        entries = [data[key]] if stat_result else data[key]
        if not isinstance(entries, list) or len(entries) != len(expected):
            return False
        actual = []
        for entry in entries:
            if (not isinstance(entry, dict) or set(entry) not in ({"Path", "Name", "Size", "ModTime", "IsDir"},
                                                                {"Path", "Name", "Size", "ModTime", "IsDir", "Hashes"})
                    or not isinstance(entry["Path"], str) or entry["Path"] not in FILES
                    or entry["Name"] != entry["Path"].rsplit("/", 1)[-1]
                    or type(entry["Size"]) is not int or entry["IsDir"] is not False
                    or entry["ModTime"] != "2024-01-01T00:00:00.123456789Z"):
                return False
            body = FILES[entry["Path"]]
            hashes = {} if summation and entry["Path"] == INTERNETARCHIVE_MEMBER else {
                "md5": hashlib.md5(body).hexdigest(), "sha1": hashlib.sha1(body).hexdigest(),
                "crc32": f"{zlib.crc32(body) & 0xffffffff:08x}"}
            if entry.get("Hashes", {}) != hashes:
                return False
            actual.append((entry["Path"], entry["Size"]))
        return sorted(actual) == [(item["path"], item["size"]) for item in expected]
    except (LabError, ValueError, TypeError, KeyError):
        return False


def internetarchive_error_matches(output, kind):
    causes = {"missing": "object not found",
              "member_denied": 'failed to open source object: HTTP error 403 (403 Forbidden) returned body: "Synthetic member denied"'}
    if kind not in causes:
        return False
    try:
        data = memory_json(output)
        return (isinstance(data, dict) and set(data) == {"error", "path", "status"}
                and type(data["status"]) is int and data["status"] == 500
                and data["path"] == "operations/copyfile" and data["error"] == "loopback: call failed: " + causes[kind])
    except LabError:
        return False


def internetarchive_flow_matches(state, kind, member="", size=0):
    counts = ("requests", "anonymous", "metadata_reads", "member_denied", "rejected_mutations", "payload_bytes",
              "unexpected", "rejected_payload_bytes")
    if any(type(getattr(state, key)) is not int or getattr(state, key) < 0 for key in counts):
        return False
    if state.budget_exceeded or state.unexpected or state.rejected_payload_bytes or type(size) is not int or size < 0:
        return False
    events = [("metadata", "1"), ("metadata", "2")]
    denied = writes = payload = 0
    if kind == "listing" and member == "":
        pass
    elif kind == "stat" and member in FILES:
        pass
    elif kind == "missing" and member == INTERNETARCHIVE_MISSING:
        pass
    elif kind == "download" and member in FILES and size == len(FILES[member]):
        events.append(("content", member))
        payload = size
    elif kind == "member_denied" and member == INTERNETARCHIVE_MEMBER:
        events.append(("content_denied", member))
        denied = 1
    elif kind == "write" and member == INTERNETARCHIVE_MEMBER:
        events.append(("write_denied", member))
        writes = 1
    else:
        return False
    return (state.events == events and state.requests == state.anonymous == len(events) and state.metadata_reads == 2
            and state.member_denied == denied and state.rejected_mutations == writes and state.payload_bytes == payload)


def internetarchive_one_process(runtime, action):
    before = len(runtime.children)
    result = action()
    check(len(runtime.children) == before + 1 and type(result[0]) is int and result[0] >= 0,
          "internetarchive_process_count_or_exit")
    observed_exit = runtime.children[-1][0].poll()
    check(type(observed_exit) is int and observed_exit == result[0], "internetarchive_process_not_reaped")
    return result


def internetarchive_metadata_args(kind, member=""):
    check((kind == "list" and member == "") or (kind == "stat" and member in (*FILES, INTERNETARCHIVE_MISSING)),
          "internetarchive_invalid_metadata_request")
    options = {"filesOnly": True, "showHash": True, "noModTime": False, "noMimeType": True}
    if kind == "list":
        options["recurse"] = True
    return ["rc", "--loopback", "operations/" + kind, "--json",
            json.dumps({"fs": INTERNETARCHIVE_FS, "remote": member, "opt": options}, separators=(",", ":"))]


def internetarchive_checks(runtime, root, row, expected):
    caps, states, ports, preserved, snapshots, empty_directories = row["capabilities"], [], [], {}, [], []
    before, completed = len(runtime.children), False

    @contextmanager
    def case(label, mode="normal"):
        state = InternetArchiveState(mode)
        states.append(state)
        snapshots.append(json.dumps(state.metadata, sort_keys=True, separators=(",", ":")))
        with serve("internetarchive", state) as port:
            ports.append(port)
            config = config_file(root, "internetarchive-" + label + ".conf", internetarchive_options(state, port))
            data = config.read_bytes()
            preserved[config] = (data, hashlib.sha256(data).hexdigest())
            yield state, config, port

    def negative_directory(name):
        directory = root / ("negative-" + name)
        directory.mkdir(mode=0o700)
        empty_directories.append(directory)
        return directory

    try:
        check(memory_plain_path(root), "internetarchive_unsafe_root")
        downloads = root / "downloads"
        downloads.mkdir(mode=0o700)
        for phase in ("initial", "final"):
            with case("listing-" + phase) as (state, config, _):
                code, output, _ = internetarchive_one_process(runtime, lambda: runtime.run(internetarchive_metadata_args("list"), config))
                check(code == 0 and internetarchive_metadata_matches(output, expected) and internetarchive_flow_matches(state, "listing"),
                      "internetarchive_listing_mismatch")
            if phase == "final":
                break
            for index, item in enumerate(expected):
                with case("stat-" + str(index)) as (state, config, _):
                    code, output, _ = internetarchive_one_process(runtime, lambda: runtime.run(internetarchive_metadata_args("stat", item["path"]), config))
                    check(code == 0 and internetarchive_metadata_matches(output, [item], stat_result=True)
                          and internetarchive_flow_matches(state, "stat", item["path"]), "internetarchive_stat_mismatch")
                with case("download-" + str(index)) as (state, config, _):
                    code, _, _ = internetarchive_one_process(runtime, lambda: exact_copy(runtime, config, INTERNETARCHIVE_FS, item["path"],
                                                                                       str(downloads), item["path"]))
                    check(code == 0 and memory_tree_matches(downloads, expected[:index + 1])
                          and internetarchive_flow_matches(state, "download", item["path"], item["size"]), "internetarchive_download_mismatch")
            with case("missing-stat") as (state, config, _):
                code, output, _ = internetarchive_one_process(runtime, lambda: runtime.run(internetarchive_metadata_args("stat", INTERNETARCHIVE_MISSING), config))
                check(code == 0 and memory_json(output) == {"item": None}
                      and internetarchive_flow_matches(state, "missing", INTERNETARCHIVE_MISSING), "internetarchive_missing_stat_mismatch")
            for label, member in (("missing", INTERNETARCHIVE_MISSING), ("member_denied", INTERNETARCHIVE_MEMBER)):
                with case(label, "member_denied" if label == "member_denied" else "normal") as (state, config, _):
                    destination = negative_directory(label)
                    code, output, _ = internetarchive_one_process(runtime, lambda: exact_copy(runtime, config, INTERNETARCHIVE_FS, member,
                                                                                       str(destination), member))
                    check(code > 0 and internetarchive_error_matches(output, label) and memory_tree_matches(destination, [])
                          and internetarchive_flow_matches(state, label, member), "internetarchive_" + label + "_not_observed")
            item = next(item for item in expected if item["path"] == INTERNETARCHIVE_MEMBER)
            with case("summation-stat", "summation") as (state, config, _):
                code, output, _ = internetarchive_one_process(runtime, lambda: runtime.run(internetarchive_metadata_args("stat", INTERNETARCHIVE_MEMBER), config))
                check(code == 0 and internetarchive_metadata_matches(output, [item], stat_result=True, summation=True)
                      and internetarchive_flow_matches(state, "stat", INTERNETARCHIVE_MEMBER), "internetarchive_summation_stat_mismatch")
            summation = root / "summation-download"
            summation.mkdir(mode=0o700)
            with case("summation-copy", "summation") as (state, config, _):
                code, _, _ = internetarchive_one_process(runtime, lambda: exact_copy(runtime, config, INTERNETARCHIVE_FS, INTERNETARCHIVE_MEMBER,
                                                                                   str(summation), INTERNETARCHIVE_MEMBER))
                check(code == 0 and memory_tree_matches(summation, [item])
                      and internetarchive_flow_matches(state, "download", INTERNETARCHIVE_MEMBER, item["size"]), "internetarchive_summation_download_mismatch")
            with case("write-guard") as (state, config, port):
                code, output, _ = internetarchive_one_process(runtime, lambda: runtime.run(internetarchive_metadata_args("stat", INTERNETARCHIVE_MEMBER), config))
                check(code == 0 and internetarchive_metadata_matches(output, [item], stat_result=True)
                      and internetarchive_flow_matches(state, "stat", INTERNETARCHIVE_MEMBER), "internetarchive_write_setup_failed")
                client = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                try:
                    client.request("DELETE", "/ias3/synthetic-item%2FREADME-synthetic.txt")
                    response = client.getresponse()
                    body = response.read(1025)
                    check(response.status == 405 and len(body) <= 1024 and memory_json(body) == {"status": "fixture_read_only"}
                          and internetarchive_flow_matches(state, "write", INTERNETARCHIVE_MEMBER), "internetarchive_write_guard_not_observed")
                finally:
                    client.close()
        check(memory_tree_matches(downloads, expected) and memory_tree_matches(summation, [item])
              and all(memory_tree_matches(path, []) for path in empty_directories), "internetarchive_final_inventory_changed")
        completed = True
    finally:
        closed = (all(state.cleanup_complete for state in states) and all(listener_closed(port) for port in ports)
                  and all(record[0].poll() is not None for record in runtime.children[before:]))
        caps["cleanup"] = "passed" if closed else "failed"
        check(closed, "internetarchive_cleanup_failed")
        check(all(not state.unexpected and not state.budget_exceeded and not state.rejected_payload_bytes for state in states),
              "internetarchive_unexpected_request_or_budget")
        check(all(served_source_unchanged(state, expected) and state.item == "synthetic-item" and state.user == state.password == ""
                  and state.modified == "2024-01-01T00:00:00.123456789Z" and state.raw_mtime == "1704153600.999"
                  and json.dumps(state.metadata, sort_keys=True, separators=(",", ":")) == snapshot
                  for state, snapshot in zip(states, snapshots)), "internetarchive_source_changed")
        check(all(memory_plain_path(path) and path.is_file() and path.stat().st_nlink == 1
                  and path.read_bytes() == data and digest(path) == sha256 for path, (data, sha256) in preserved.items()),
              "internetarchive_config_changed")
        if completed:
            for name in caps:
                caps[name] = "passed"


INTERNETARCHIVE_LOW_MODE = "internetarchive_low_read_auth_v1"
INTERNETARCHIVE_LOW_CAPABILITIES = ("authentication_rejection", "source_preservation", "config_preservation", "cleanup")
INTERNETARCHIVE_LOW_CASES = (
    ("valid-before", "valid", "valid", "normal"),
    ("wrong-secret", "wrong_secret", "wrong_secret", "normal"),
    ("valid-after", "valid", "valid", "normal"),
    ("both-empty", "absent", "both_empty", "normal"),
    ("key-only", "absent", "key_only", "normal"),
    ("secret-only", "absent", "secret_only", "normal"),
    ("content-denied", "valid", "valid", "member_denied"),
)


def internetarchive_low_options(state, port, variant):
    check(variant in ("valid", "wrong_secret", "both_empty", "key_only", "secret_only"), "internetarchive_low_invalid_variant")
    options = internetarchive_options(state, port)
    options.update(access_key_id=state.key if variant not in ("both_empty", "secret_only") else "",
                   secret_access_key=(state.wrong_secret if variant == "wrong_secret" else
                                      state.secret if variant not in ("both_empty", "key_only") else ""))
    return options


def internetarchive_low_error_matches(output, member_denied=False):
    if member_denied:
        return internetarchive_error_matches(output, "member_denied")
    try:
        value = memory_json(output)
        return (type(value) is dict and set(value) == {"error", "path", "status"}
                and type(value["status"]) is int and value["status"] == 500
                and value["path"] == "operations/copyfile"
                and value["error"] == 'loopback: call failed: HTTP error 403 (403 Forbidden) returned body: "Synthetic credentials denied"')
    except LabError:
        return False


def internetarchive_low_flow_matches(state, auth_case, mode, size):
    counts = ("requests", "authenticated", "auth_denied", "anonymous", "metadata_reads", "member_denied", "rejected_mutations",
              "payload_bytes", "response_bytes", "unexpected", "rejected_payload_bytes", "accepted_connections", "admission_denied")
    if (auth_case not in ("valid", "wrong_secret", "absent") or mode not in ("normal", "member_denied")
            or type(size) is not int or size != len(FILES[INTERNETARCHIVE_MEMBER])
            or any(type(getattr(state, name)) is not int or getattr(state, name) < 0 for name in counts)
            or state.budget_exceeded is not False or state.unexpected or state.rejected_payload_bytes
            or state.rejected_mutations or state.admission_denied or state.anonymous != 0
            or not 0 < state.accepted_connections <= state.connection_limit
            or not 0 < state.response_bytes <= state.byte_limit):
        return False
    if auth_case != "valid":
        return (state.events == [("auth_denied", "1"), ("auth_denied", "2")]
                and state.requests == state.auth_denied == 2 and state.authenticated == state.metadata_reads == 0
                and state.member_denied == state.payload_bytes == 0)
    denied = mode == "member_denied"
    return (state.events == [("metadata", "1"), ("metadata", "2"),
                             ("content_denied" if denied else "content", INTERNETARCHIVE_MEMBER)]
            and state.requests == state.authenticated == 3 and state.metadata_reads == 2 and state.auth_denied == 0
            and state.member_denied == int(denied) and state.payload_bytes == (0 if denied else size))


def internetarchive_low_checks(runtime, root, row, expected):
    """Seven independent LOW-header cases; no live account or renewal claim."""
    caps, states, ports, preserved, snapshots, destinations = row["capabilities"], [], [], {}, [], []
    before, completed = len(runtime.children), False
    key, secret, wrong_secret = ("synthetic-" + uuid.uuid4().hex for _ in range(3))
    try:
        check(memory_plain_path(root) and expected == fixture_manifest(), "internetarchive_low_invalid_fixture")
        check(len({key, secret, wrong_secret}) == 3, "internetarchive_low_credential_collision")
        item = next(item for item in expected if item["path"] == INTERNETARCHIVE_MEMBER)
        for label, auth_case, variant, mode in INTERNETARCHIVE_LOW_CASES:
            state = InternetArchiveLowState(key, secret, wrong_secret, mode=mode, auth_case=auth_case)
            states.append(state)
            snapshots.append(json.dumps(state.metadata, sort_keys=True, separators=(",", ":")))
            destination = root / label
            destination.mkdir(mode=0o700)
            wanted = [item] if auth_case == "valid" and mode == "normal" else []
            destinations.append((destination, wanted))
            with serve("internetarchive-low-auth", state) as port:
                ports.append(port)
                config = config_file(root, "internetarchive-low-" + label + ".conf", internetarchive_low_options(state, port, variant))
                data = config.read_bytes()
                preserved[config] = (data, hashlib.sha256(data).hexdigest())
                code, output, _ = internetarchive_one_process(runtime, lambda: exact_copy(
                    runtime, config, INTERNETARCHIVE_FS, INTERNETARCHIVE_MEMBER, str(destination), INTERNETARCHIVE_MEMBER))
                check(internetarchive_low_flow_matches(state, auth_case, mode, item["size"]), "internetarchive_low_flow_mismatch")
                check(memory_tree_matches(destination, wanted), "internetarchive_low_output_mismatch")
                if wanted:
                    check(code == 0 and memory_json(output) == {}, "internetarchive_low_positive_failed")
                else:
                    check(code > 0 and internetarchive_low_error_matches(output, mode == "member_denied"),
                          "internetarchive_low_denial_mismatch")
        check(len(runtime.children) - before == len(INTERNETARCHIVE_LOW_CASES) == len(states) == 7
              and sum(state.requests for state in states) == 17, "internetarchive_low_case_budget")
        check(all(memory_tree_matches(path, wanted) for path, wanted in destinations), "internetarchive_low_final_outputs_changed")
        completed = True
    finally:
        closed = (all(state.cleanup_complete is True for state in states) and all(listener_closed(port) for port in ports)
                  and all(record[0].poll() is not None for record in runtime.children[before:]))
        caps["cleanup"] = "passed" if closed else "failed"
        check(closed, "internetarchive_low_cleanup_failed")
        check(all(not state.unexpected and not state.budget_exceeded and not state.rejected_payload_bytes
                  and not state.admission_denied for state in states), "internetarchive_low_unexpected_request_or_budget")
        check(all(served_source_unchanged(state, expected) and state.source_preserved()
                  and (state.key, state.secret, state.wrong_secret) == (key, secret, wrong_secret)
                  and (state.auth_case, state.mode) == (INTERNETARCHIVE_LOW_CASES[index][1], INTERNETARCHIVE_LOW_CASES[index][3])
                  and state.item == "synthetic-item" and state.user == state.password == ""
                  and state.modified == "2024-01-01T00:00:00.123456789Z" and state.raw_mtime == "1704153600.999"
                  and json.dumps(state.metadata, sort_keys=True, separators=(",", ":")) == snapshots[index]
                  for index, state in enumerate(states)), "internetarchive_low_source_changed")
        check(all(memory_plain_path(path) and path.is_file() and path.stat().st_nlink == 1
                  and path.read_bytes() == data and digest(path) == sha256 for path, (data, sha256) in preserved.items()),
              "internetarchive_low_config_changed")
        if completed:
            for name in caps:
                caps[name] = "passed"


FILEFABRIC_MEMBER = "README-synthetic.txt"


def filefabric_options(state, port, *, wrong_token=False):
    check(type(port) is int and 0 < port < 65536 and type(wrong_token) is bool
          and state.root_id == "100" and state.nested_id == "200", "filefabric_invalid_fixture")
    expiry = (datetime.now(timezone.utc) + timedelta(hours=2)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return {"type": "filefabric", "url": f"http://127.0.0.1:{port}", "root_folder_id": "100",
            "permanent_token": "unused-synthetic-" + uuid.uuid4().hex,
            "token": state.wrong_token if wrong_token else state.token, "token_expiry": expiry, "version": "2006.02"}


def filefabric_cache_fresh(config):
    # A fresh cached session is the contract. Expiry must never turn this into a grant test.
    lines = config.read_text().splitlines()
    expires = [line.split("=", 1)[1].strip() for line in lines if line.startswith("token_expiry =")]
    check(len(expires) == 1, "filefabric_cache_expiry_invalid")
    expiry = datetime.fromisoformat(expires[0].replace("Z", "+00:00"))
    check(expiry.tzinfo is not None and expiry > datetime.now(timezone.utc) + timedelta(hours=1),
          "filefabric_cache_expiry_too_close")


def filefabric_metadata_matches(output, expected, *, stat_result=False):
    try:
        data = memory_json(output)
        key = "item" if stat_result else "list"
        if not isinstance(data, dict) or set(data) != {key}:
            return False
        entries = [data[key]] if stat_result else data[key]
        if not isinstance(entries, list) or len(entries) != len(expected):
            return False
        actual = []
        for entry in entries:
            if (not isinstance(entry, dict) or set(entry) not in ({"Path", "Name", "Size", "ModTime", "IsDir", "ID"},
                                                                {"Path", "Name", "Size", "ModTime", "IsDir", "ID", "Hashes"})
                    or not isinstance(entry["Path"], str) or entry["Name"] != entry["Path"].rsplit("/", 1)[-1]
                    or entry.get("ID") != {"README-synthetic.txt": "301", "nested/bytes.bin": "302", "nested/space name.txt": "303"}.get(entry["Path"])
                    or type(entry["Size"]) is not int or entry["IsDir"] is not False
                    or entry.get("Hashes", {}) != {} or not isinstance(entry["ModTime"], str)):
                return False
            match = re.fullmatch(r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])", entry["ModTime"])
            if not match or match[2] == "-00:00":
                return False
            instant = datetime.fromisoformat(entry["ModTime"].replace("Z", "+00:00"))
            if instant.astimezone(timezone.utc) != datetime(2024, 1, 1, tzinfo=timezone.utc):
                return False
            actual.append((entry["Path"], entry["Size"]))
        return sorted(actual) == [(item["path"], item["size"]) for item in expected]
    except (LabError, ValueError, TypeError, KeyError, OverflowError):
        return False


def filefabric_error_matches(output, kind):
    # Pinned readMetaDataForPath wraps Status.Error; no same-call refresh retry.
    causes = {"missing": "object not found",
              "wrong_token": "failed to check path exists: Synthetic cached session denied (login_token_expired)",
              "member_denied": "failed to check path exists: Synthetic member denied (fixture_member_denied)"}
    if kind not in causes:
        return False
    try:
        data = memory_json(output)
        return (isinstance(data, dict) and set(data) == {"error", "path", "status"}
                and type(data["status"]) is int and data["status"] == 500
                and data["path"] == "operations/copyfile"
                and data["error"] == "loopback: call failed: " + causes[kind])
    except LabError:
        return False


def filefabric_flow_matches(state, kind, member="", size=0):
    counts = ("requests", "authenticated", "auth_denied", "member_denied", "missing", "rejected_mutations",
              "payload_bytes", "unexpected", "rejected_payload_bytes")
    if any(type(getattr(state, key)) is not int or getattr(state, key) < 0 for key in counts):
        return False
    if state.budget_exceeded or state.unexpected or state.rejected_payload_bytes or type(size) is not int or size < 0:
        return False
    auth_denied = denied = missing = writes = payload = 0
    if kind == "listing":
        events = [("listing", "100"), ("listing", "200")]
    elif kind in ("stat", "download") and member in FILES:
        events = [("member_stat", member)]
        if kind == "download":
            events += [("content", member)]
            payload = size
    elif kind == "missing" and member == FILEFABRIC_MISSING:
        events, missing = [("file_missing", FILEFABRIC_MISSING)], 1
    elif kind == "wrong_token" and member == FILEFABRIC_MEMBER:
        events, auth_denied = [("auth_denied", FILEFABRIC_MEMBER)], 1
    elif kind == "member_denied" and member == FILEFABRIC_MEMBER:
        events, denied = [("member_denied", FILEFABRIC_MEMBER)], 1
    elif kind == "write":
        events = [("member_stat", FILEFABRIC_MEMBER), ("write_denied", FILEFABRIC_MEMBER)]
        writes = 1
    else:
        return False
    return (state.events == events and state.requests == len(events)
            and state.authenticated == len(events) - auth_denied and state.auth_denied == auth_denied
            and state.member_denied == denied and state.missing == missing and state.rejected_mutations == writes
            and state.payload_bytes == payload)


def filefabric_one_process(runtime, config, action):
    filefabric_cache_fresh(config)
    before = len(runtime.children)
    result = action()
    check(len(runtime.children) == before + 1 and type(result[0]) is int and result[0] >= 0,
          "filefabric_process_count_or_exit")
    observed_exit = runtime.children[-1][0].poll()
    check(type(observed_exit) is int and observed_exit == result[0], "filefabric_process_not_reaped")
    return result


def filefabric_metadata_args(kind, member=""):
    check((kind == "list" and member == "") or (kind == "stat" and member in (*FILES, FILEFABRIC_MISSING)),
          "filefabric_invalid_metadata_request")
    options = {"filesOnly": True, "showHash": True, "noModTime": False, "noMimeType": True}
    if kind == "list":
        options["recurse"] = True
    return ["rc", "--loopback", "operations/" + kind, "--json",
            json.dumps({"fs": "Synthetic:", "remote": member, "opt": options}, separators=(",", ":"))]


def filefabric_checks(runtime, root, row, expected):
    caps, states, ports, preserved, empty_directories = row["capabilities"], [], [], {}, []
    before, completed = len(runtime.children), False
    token, wrong_token = "synthetic-" + uuid.uuid4().hex, "wrong-synthetic-session"

    @contextmanager
    def case(label, mode="normal"):
        state = FileFabricState(token, mode="member_denied" if mode == "member_denied" else "normal", wrong_token=wrong_token)
        states.append(state)
        with serve("filefabric", state) as port:
            ports.append(port)
            options = filefabric_options(state, port)
            if mode == "wrong_token":
                # Preserve an exact valid configuration counterpart: only the cached
                # session changes, never root/version/expiry/permanent-token scope.
                valid = config_file(root, "filefabric-" + label + "-valid.conf", options)
                original = valid.read_bytes()
                preserved[valid] = (original, hashlib.sha256(original).hexdigest())
                options = dict(options, token=state.wrong_token)
            config = config_file(root, "filefabric-" + label + ".conf", options)
            data = config.read_bytes()
            preserved[config] = (data, hashlib.sha256(data).hexdigest())
            filefabric_cache_fresh(config)
            yield state, config, port

    def negative_directory(name):
        directory = root / ("negative-" + name)
        directory.mkdir(mode=0o700)
        empty_directories.append(directory)
        return directory

    try:
        check(memory_plain_path(root), "filefabric_unsafe_root")
        downloads = root / "downloads"
        downloads.mkdir(mode=0o700)
        for phase in ("initial", "final"):
            with case("listing-" + phase) as (state, config, _):
                code, output, _ = filefabric_one_process(runtime, config, lambda: runtime.run(filefabric_metadata_args("list"), config))
                check(code == 0 and filefabric_metadata_matches(output, expected) and filefabric_flow_matches(state, "listing"),
                      "filefabric_listing_mismatch")
            if phase == "final":
                break
            for index, item in enumerate(expected):
                with case("stat-" + str(index)) as (state, config, _):
                    code, output, _ = filefabric_one_process(runtime, config, lambda: runtime.run(filefabric_metadata_args("stat", item["path"]), config))
                    check(code == 0 and filefabric_metadata_matches(output, [item], stat_result=True)
                          and filefabric_flow_matches(state, "stat", item["path"]), "filefabric_stat_mismatch")
                with case("download-" + str(index)) as (state, config, _):
                    code, _, _ = filefabric_one_process(runtime, config, lambda: exact_copy(runtime, config, "Synthetic:", item["path"],
                                                                                    str(downloads), item["path"]))
                    check(code == 0 and memory_tree_matches(downloads, expected[:index + 1])
                          and filefabric_flow_matches(state, "download", item["path"], item["size"]), "filefabric_download_mismatch")
            with case("missing-stat") as (state, config, _):
                code, output, _ = filefabric_one_process(runtime, config, lambda: runtime.run(filefabric_metadata_args("stat", FILEFABRIC_MISSING), config))
                check(code == 0 and memory_json(output) == {"item": None}
                      and filefabric_flow_matches(state, "missing", FILEFABRIC_MISSING), "filefabric_missing_stat_mismatch")
            for label, kind, member in (("missing-copy", "missing", FILEFABRIC_MISSING),
                                        ("wrong_token", "wrong_token", FILEFABRIC_MEMBER),
                                        ("member_denied", "member_denied", FILEFABRIC_MEMBER)):
                with case(label, kind) as (state, config, _):
                    destination = negative_directory(kind)
                    code, output, _ = filefabric_one_process(runtime, config, lambda: exact_copy(runtime, config, "Synthetic:", member,
                                                                                        str(destination), member))
                    check(code > 0 and filefabric_error_matches(output, kind) and memory_tree_matches(destination, [])
                          and filefabric_flow_matches(state, kind, member), "filefabric_" + kind + "_not_observed")
            with case("write-guard") as (state, config, port):
                item = next(item for item in expected if item["path"] == FILEFABRIC_MEMBER)
                code, output, _ = filefabric_one_process(runtime, config, lambda: runtime.run(filefabric_metadata_args("stat", FILEFABRIC_MEMBER), config))
                check(code == 0 and filefabric_metadata_matches(output, [item], stat_result=True)
                      and filefabric_flow_matches(state, "stat", FILEFABRIC_MEMBER), "filefabric_write_setup_failed")
                client = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                try:
                    body = urllib.parse.urlencode({"apiformat": "json", "function": "doDeleteFile", "token": token,
                                                   "fi_id": "301", "completedeletion": "n"})
                    client.request("POST", "/api/rpc.php", body=body,
                                   headers={"Content-Type": "application/x-www-form-urlencoded"})
                    response = client.getresponse()
                    body = response.read(1025)
                    check(response.status == 405 and len(body) <= 1024
                          and memory_json(body) == {"status": "fixture_read_only"}
                          and filefabric_flow_matches(state, "write"), "filefabric_write_guard_not_observed")
                finally:
                    client.close()
        check(memory_tree_matches(downloads, expected) and all(memory_tree_matches(path, []) for path in empty_directories),
              "filefabric_final_inventory_changed")
        completed = True
    finally:
        closed = (all(state.cleanup_complete for state in states) and all(listener_closed(port) for port in ports)
                  and all(record[0].poll() is not None for record in runtime.children[before:]))
        caps["cleanup"] = "passed" if closed else "failed"
        check(closed, "filefabric_cleanup_failed")
        check(all(not state.unexpected and not state.budget_exceeded and not state.rejected_payload_bytes for state in states),
              "filefabric_unexpected_request_or_budget")
        check(all(served_source_unchanged(state, expected) and state.root_id == "100" and state.nested_id == "200"
                  and state.modified == "2024-01-02 00:00:00" and state.localtime == "2024-01-01 00:00:00"
                  and state.ids == {"README-synthetic.txt": "301", "nested/bytes.bin": "302", "nested/space name.txt": "303"}
                  and state.token == token and state.wrong_token == wrong_token for state in states), "filefabric_source_changed")
        check(all(memory_plain_path(path) and path.is_file() and path.stat().st_nlink == 1
                  and path.read_bytes() == data and digest(path) == sha256 for path, (data, sha256) in preserved.items()),
              "filefabric_config_changed")
        if completed:
            for name in caps:
                caps[name] = "passed"


FILEFABRIC_SESSION_CAPABILITIES = ("session_token_reacquisition", "renewal_denial", "config_scope_preservation",
                                   "saved_token_reuse", "source_preservation", "cleanup")


def filefabric_session_options(state, port):
    options = filefabric_options(state, port)
    check(state.seed_version == "2006.01" and state.issued_version == "2006.02", "filefabric_session_version_changed")
    return dict(options, permanent_token=state.permanent_token, version=state.seed_version)


def filefabric_session_batch(destination, mode):
    check(mode in ("success", "deny", "reuse") and memory_plain_path(destination) and destination.is_dir()
          and destination.name == {"success": "downloads", "deny": "denied-downloads", "reuse": "reuse-downloads"}[mode],
          "filefabric_session_invalid_batch")
    metadata = {"_path": "operations/stat", "fs": "Synthetic:", "remote": FILEFABRIC_MEMBER,
                "opt": {"filesOnly": True, "showHash": True, "noModTime": False, "noMimeType": True}}
    pid = {"_path": "core/pid"}
    acquire = {"_path": "operations/copyfile", "srcFs": "Synthetic:", "srcRemote": FILEFABRIC_MEMBER,
               "dstFs": str(destination), "dstRemote": FILEFABRIC_MEMBER}
    calls = [pid, metadata, acquire, pid] if mode == "reuse" else [pid, metadata, metadata, pid, metadata]
    if mode == "success":
        calls += [acquire]
    if mode != "reuse":
        calls += [pid]
    # Copy input objects so expected error inputs cannot alias mutable callers.
    return json.loads(json.dumps({"concurrency": 1, "inputs": calls}))


def filefabric_session_error_matches(result, expected_input, kind):
    causes = {"expired": "failed to check path exists: Synthetic cached session expired (login_token_expired)",
              "grant_denied": "failed to check path exists: failed to get session token: Synthetic grant denied (fixture_grant_denied)"}
    if (kind not in causes or not isinstance(result, dict) or set(result) != {"error", "input", "path", "status"}
            or result["error"] != causes[kind] or result["path"] != "operations/stat"
            or type(result["status"]) is not int or result["status"] != 500 or not isinstance(result["input"], dict)):
        return False
    actual = dict(result["input"])
    group = actual.pop("_group", None)
    if "_group" in result["input"] and (not isinstance(group, str) or not re.fullmatch(r"job/[1-9][0-9]{0,11}", group)):
        return False
    expected = {key: value for key, value in expected_input.items() if key != "_path"}
    return json.dumps(actual, sort_keys=True, separators=(",", ":")) == json.dumps(expected, sort_keys=True, separators=(",", ":"))


def filefabric_session_results(output, inputs, mode, pid, expected):
    try:
        parsed = memory_json(output)
        if (type(pid) is not int or pid <= 0 or not isinstance(parsed, dict) or set(parsed) != {"results"}
                or not isinstance(parsed["results"], list) or len(parsed["results"]) != len(inputs)):
            return False
        for index, (result, request) in enumerate(zip(parsed["results"], inputs)):
            if request["_path"] == "core/pid":
                if not isinstance(result, dict) or set(result) != {"pid"} or type(result["pid"]) is not int or result["pid"] != pid:
                    return False
            elif mode != "reuse" and index == 2:
                if not filefabric_session_error_matches(result, request, "expired"):
                    return False
            elif mode == "deny" and index == 4:
                if not filefabric_session_error_matches(result, request, "grant_denied"):
                    return False
            elif request["_path"] == "operations/stat":
                if not filefabric_metadata_matches(json.dumps(result).encode(), expected, stat_result=True):
                    return False
            elif result != {}:
                return False
        return True
    except (LabError, ValueError, TypeError, KeyError):
        return False


def filefabric_session_flow(state, mode, size):
    keys = ("requests", "authenticated", "expirations", "grant_attempts", "grants", "grant_denials", "appliance_calls",
            "payload_bytes", "unexpected", "rejected_payload_bytes", "rejected_mutations", "auth_denied", "member_denied", "missing")
    if (any(type(getattr(state, key)) is not int or getattr(state, key) < 0 for key in keys)
            or state.budget_exceeded or any(getattr(state, key) for key in keys[-6:]) or type(size) is not int or size <= 0):
        return False
    member = FILEFABRIC_MEMBER
    if mode == "success":
        events = [("initial_stat", member), ("expired", member), ("grant", ""), ("appliance", ""),
                  ("renewed_stat", member), ("copy_stat", member), ("content", member)]
        counts, phase = (7, 4, 1, 1, 1, 0, 1, size), "complete"
    elif mode == "deny":
        events = [("initial_stat", member), ("expired", member), ("grant_denied", "")]
        counts, phase = (3, 1, 1, 1, 0, 1, 0, 0), "denied"
        if state.issued_token is not None:
            return False
    elif mode == "reuse":
        events = [("reuse_stat", member), ("reuse_copy_stat", member), ("reuse_content", member)]
        counts, phase = (3, 3, 0, 0, 0, 0, 0, size), "reuse_complete"
    else:
        return False
    return state.phase == phase and state.events == events and tuple(getattr(state, key) for key in keys[:8]) == counts


def filefabric_session_config(path):
    check(memory_plain_path(path) and path.is_file() and path.stat().st_nlink == 1 and path.stat().st_size <= 8192
          and memory_plain_path(path.parent) and sorted(child.name for child in path.parent.iterdir()) == [path.name],
          "filefabric_session_config_inventory")
    if os.name != "nt":
        check(path.stat().st_uid == os.getuid() and path.stat().st_mode & 0o077 == 0, "filefabric_session_config_permissions")
    data = path.read_bytes()
    parser = configparser.ConfigParser(interpolation=None, strict=True, delimiters=("=",), empty_lines_in_values=False)
    parser.optionxform = str
    try:
        parser.read_string(data.decode("utf-8"))
        check(parser.sections() == ["Synthetic"] and not parser.defaults(), "filefabric_session_config_shape")
        values = dict(parser.items("Synthetic", raw=True))
        check(set(values) == {"type", "url", "root_folder_id", "permanent_token", "token", "token_expiry", "version"}
              and all("\n" not in value and "\r" not in value for value in values.values()), "filefabric_session_config_shape")
    except (UnicodeError, configparser.Error):
        raise LabError("filefabric_session_config_shape") from None
    return data, values


def filefabric_session_saved_config(state, original, saved):
    if (set(original) != set(saved) or any(original[key] != saved[key] for key in original if key not in ("token", "token_expiry", "version"))
            or not isinstance(state.issued_token, str) or not state.issued_token or state.issued_token == original["token"]
            or saved["token"] != state.issued_token or original["version"] != "2006.01" or saved["version"] != "2006.02"):
        return False
    try:
        if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])", saved["token_expiry"]):
            return False
        if saved["token_expiry"].endswith("-00:00"):
            return False
        expiry = datetime.fromisoformat(saved["token_expiry"].replace("Z", "+00:00")).astimezone(timezone.utc)
        lower, upper = state.expiry_lower, state.grant_upper
        wall = (upper - lower).total_seconds()
        monotonic = state.grant_upper_monotonic - state.expiry_lower_monotonic
        if (lower.tzinfo is None or upper.tzinfo is None or not 0 <= wall <= 20 or not 0 <= monotonic <= 20
                or abs(wall - monotonic) > 1):
            return False
        return ((lower + timedelta(minutes=55)).replace(microsecond=0) <= expiry
                <= (upper + timedelta(minutes=55)).replace(microsecond=0))
    except (ValueError, TypeError, AttributeError, OverflowError):
        return False


def filefabric_session_drain(state):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        with state.lock:
            if state.active_handlers == 0 and not state.sockets:
                return
        time.sleep(0.01)
    raise LabError("filefabric_session_handlers_not_drained")


def filefabric_session_child(runtime, config, destination, mode, expected):
    batch = filefabric_session_batch(destination, mode)
    before = len(runtime.children)
    code, output, _ = runtime.run(["rc", "--loopback", "job/batch", "--json", json.dumps(batch, separators=(",", ":"))], config, timeout=20)
    check(len(runtime.children) == before + 1, "filefabric_session_child_count")
    child = runtime.children[-1][0]
    check(type(code) is int and code == 0 and type(child.poll()) is int and child.poll() == 0,
          "filefabric_session_child_exit")
    check(filefabric_session_results(output, batch["inputs"], mode, child.pid, expected), "filefabric_session_batch_results")


def filefabric_session_checks(runtime, root, row, expected):
    caps, states, ports = row["capabilities"], [], []
    before, complete = len(runtime.children), False
    check(expected == fixture_manifest(), "filefabric_session_manifest_changed")
    member = [item for item in expected if item["path"] == FILEFABRIC_MEMBER]
    check(len(member) == 1, "filefabric_session_member_missing")
    snapshots, source_settings = [], []
    try:
        for mode in ("success", "deny"):
            case_root = root / mode
            case_root.mkdir(mode=0o700)
            private = case_root / "config"
            private.mkdir(mode=0o700)
            destination = case_root / ("downloads" if mode == "success" else "denied-downloads")
            destination.mkdir(mode=0o700)
            state = FileFabricSessionState("synthetic-" + uuid.uuid4().hex, "permanent-synthetic-" + uuid.uuid4().hex, deny=mode == "deny")
            states.append(state)
            source_settings.append((state.token, state.permanent_token, state.deny))
            with serve("filefabric-renewal", state) as port:
                ports.append(port)
                config = config_file(private, "session.conf", filefabric_session_options(state, port))
                original_bytes, original = filefabric_session_config(config)
                filefabric_cache_fresh(config)
                filefabric_session_child(runtime, config, destination, mode, member)
                filefabric_session_drain(state)
                check(filefabric_session_flow(state, mode, member[0]["size"]), "filefabric_session_" + mode + "_flow")
                saved_bytes, saved = filefabric_session_config(config)
                check(memory_tree_matches(destination, [] if mode == "deny" else member), "filefabric_session_download_inventory")
                if mode == "deny":
                    check(saved_bytes == original_bytes and saved == original, "filefabric_session_denial_config_changed")
                else:
                    check(filefabric_session_saved_config(state, original, saved), "filefabric_session_saved_config_mismatch")
                    state.begin_reuse()
                    reuse = case_root / "reuse-downloads"
                    reuse.mkdir(mode=0o700)
                    filefabric_session_child(runtime, config, reuse, "reuse", member)
                    filefabric_session_drain(state)
                    check(filefabric_session_flow(state, "reuse", member[0]["size"]), "filefabric_session_reuse_flow")
                    check(memory_tree_matches(reuse, member) and memory_tree_matches(destination, member), "filefabric_session_reuse_inventory")
                    snapshots.append((reuse, member))
                    after_bytes, after = filefabric_session_config(config)
                    check(after_bytes == saved_bytes and after == saved, "filefabric_session_reuse_config_changed")
                snapshots.append((destination, [] if mode == "deny" else member))
                snapshots.append((config, saved_bytes))
        complete = True
    finally:
        closed = (all(state.cleanup_complete for state in states) and all(listener_closed(port) for port in ports)
                  and all(record[0].poll() is not None for record in runtime.children[before:]))
        caps["cleanup"] = "passed" if closed else "failed"
        check(closed, "filefabric_session_cleanup_failed")
        check(all(not state.unexpected and not state.budget_exceeded and not state.rejected_payload_bytes
                  and state.active_handlers == 0 and not state.sockets
                  and type(state.lifetime_requests) is int and 0 < state.lifetime_requests <= 128 for state in states),
              "filefabric_session_unexpected_or_budget")
        check(all(served_source_unchanged(state, expected) and state.root_id == "100" and state.nested_id == "200"
                  and state.modified == "2024-01-02 00:00:00" and state.localtime == "2024-01-01 00:00:00"
                  and state.seed_version == "2006.01" and state.issued_version == "2006.02"
                  and state.ids == {"README-synthetic.txt": "301", "nested/bytes.bin": "302", "nested/space name.txt": "303"}
                  and (state.token, state.permanent_token, state.deny) == original
                  for state, original in zip(states, source_settings)), "filefabric_session_source_changed")
        for path, wanted in snapshots:
            if isinstance(wanted, bytes):
                check(filefabric_session_config(path)[0] == wanted, "filefabric_session_final_config_changed")
            else:
                check(memory_tree_matches(path, wanted), "filefabric_session_final_inventory_changed")
        if complete:
            for capability in FILEFABRIC_SESSION_CAPABILITIES:
                caps[capability] = "passed"


def run_backend(runtime, backend, root):
    root.mkdir(mode=0o700)
    independent = backend in ("http", "webdav", "ftp", "swift", "b2", "azureblob", "azurefiles", "seafile", "koofr", "pixeldrain", "filefabric", "internetarchive", "netstorage", "pcloud")
    row = {"backend": backend,
           "fixture_kind": "local" if backend in ("local", "archive", "memory") else "independent_loopback" if independent else "rclone_loopback",
           "capabilities": {key: "not_run" for key in (
               "listing", "download_hash", "missing_object_rejection", "source_preservation", "authentication_rejection", "cleanup")},
           "errors": []}
    if backend in ("local", "archive", "memory"):
        row["capabilities"]["authentication_rejection"] = "not_applicable"
    if backend == "netstorage":
        row["capabilities"] = {key: "not_run" for key in NETSTORAGE_CAPABILITIES}
    if backend == "pcloud":
        row["capabilities"] = {key: "not_run" for key in PCLOUD_CAPABILITIES}
    if backend == "internetarchive":
        row["capabilities"] = {key: "not_run" for key in INTERNETARCHIVE_CAPABILITIES}
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
    if backend in ("azureblob", "azurefiles", "seafile", "memory", "koofr", "pixeldrain", "filefabric", "internetarchive", "netstorage"):
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
    if not independent and backend not in ("archive", "memory"):
        source.mkdir(mode=0o700)
        prepare_files(files_root)
    port = None
    try:
        if backend == "pcloud":
            pcloud_checks(runtime, root, row, expected)
            return row
        if backend == "netstorage":
            netstorage_checks(runtime, root, row, expected)
            return row
        if backend == "internetarchive":
            internetarchive_checks(runtime, root, row, expected)
            return row
        if backend == "filefabric":
            filefabric_checks(runtime, root, row, expected)
            return row
        if backend == "pixeldrain":
            pixeldrain_checks(runtime, root, row, expected)
            return row
        if backend == "koofr":
            koofr_checks(runtime, root, row, expected)
            return row
        if backend == "memory":
            memory_checks(runtime, root, row, expected)
            return row
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
            row["errors"].append("memory_child_cleanup_failed" if backend == "memory" else "listener_still_open")
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


def run_filefabric_renewal(binary, report_path):
    validate_report_path(report_path)
    repository = Path(__file__).resolve().parents[2]
    original, identity, platform = verified_runtime(binary, repository / "rclone-version.env")
    report = {"schema_version": 2, "scope": "rclone_backend_protocol_fixture", "runtime": identity,
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
        case_root = root / "filefabric-renewal"
        case_root.mkdir(mode=0o700)
        row = {"backend": "filefabric", "fixture_kind": "independent_loopback",
               "fixture_mode": "filefabric_later_call_renewal_v1",
               "capabilities": {name: "not_run" for name in FILEFABRIC_SESSION_CAPABILITIES}, "errors": []}
        report["backends"].append(row)
        filefabric_session_checks(runtime, case_root, row, fixture_manifest())
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
                             and len(report["backends"]) == 1
                             and all(not row["errors"] and all(value == "passed"
                                     for value in row["capabilities"].values()) for row in report["backends"]))
        atomic_report(report_path, report)
    return report


def run_internetarchive_low_auth(binary, report_path):
    validate_report_path(report_path)
    repository = Path(__file__).resolve().parents[2]
    original, identity, platform = verified_runtime(binary, repository / "rclone-version.env")
    report = {"schema_version": 4, "scope": "rclone_backend_protocol_fixture", "runtime": identity,
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
        case_root = root / "internetarchive-low-auth"
        case_root.mkdir(mode=0o700)
        row = {"backend": "internetarchive", "fixture_kind": "independent_loopback",
               "fixture_mode": INTERNETARCHIVE_LOW_MODE,
               "capabilities": {name: "not_run" for name in INTERNETARCHIVE_LOW_CAPABILITIES}, "errors": []}
        report["backends"].append(row)
        internetarchive_low_checks(runtime, case_root, row, fixture_manifest())
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
        if not report["cleanup_passed"]:
            for row in report["backends"]:
                row["capabilities"]["cleanup"] = "failed"
        report["finished_utc"] = utc_now()
        report["success"] = (report["cleanup_passed"] and not report["errors"] and len(report["backends"]) == 1
                             and all(not row["errors"] and set(row["capabilities"]) == set(INTERNETARCHIVE_LOW_CAPABILITIES)
                                     and all(value == "passed" for value in row["capabilities"].values()) for row in report["backends"]))
        atomic_report(report_path, report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rclone", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--backends")
    selection.add_argument("--filefabric-renewal", action="store_true")
    selection.add_argument("--internetarchive-low-auth", action="store_true")
    args = parser.parse_args()
    selected = args.backends.split(",") if args.backends is not None else list(BACKENDS)
    if not selected or len(set(selected)) != len(selected) or any(item not in BACKENDS for item in selected):
        parser.error("backends must be a unique comma-separated subset of supported fixture IDs")
    try:
        if args.internetarchive_low_auth:
            report = run_internetarchive_low_auth(args.rclone, args.report)
        elif args.filefabric_renewal:
            report = run_filefabric_renewal(args.rclone, args.report)
        else:
            report = run_lab(args.rclone, args.report, selected)
    except (LabError, OSError):
        print("Provider fixture preflight/report failure", file=sys.stderr)
        return 1
    print(json.dumps({"success": report["success"], "cleanup_passed": report["cleanup_passed"],
                      "backends": len(report["backends"])}))
    return 0 if report["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
