#!/usr/bin/env python3
"""Hosted, source-bound local/ZIP application reads and active cancellation.

Imports do not launch processes or call native APIs. This staged producer never
claims full application, provider or vendor acceptance.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import io
import os
from pathlib import Path
import re
import signal
import stat
import time
import types
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def load(name, path):
    data = path.read_bytes()
    if len(data) > 512 * 1024:
        raise ValueError("binding_failed")
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(data, str(path), "exec"), module.__dict__)
    module.loaded_source_sha256 = hashlib.sha256(data).hexdigest()
    return module


C = load("filesystem_controller", HERE / "filesystem_controller.py")
H = C.H
E = load("filesystem_application_evidence", ROOT / "scripts/filesystem_application_evidence.py")
F = load("filesystem_fixture", HERE / "fixture_filesystem.py")
SELF_SHA256 = H.sha(H.read(Path(__file__), 512 * 1024))
need = H.need
REMOTE, CASE_NAME = "Synthetic", "synthetic-case"
MODIFIED = "2025-01-02T03:04:06+00:00"
MODIFIED_NS = 1735787046 * 1_000_000_000
ROWS = (
    ("README-synthetic.txt", 30, "64d5b40a5f4773b14940a6ce1dd57cf87b44ce5940c097088732ffc71be280cf", "4bdad4b7"),
    ("empty.bin", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "00000000"),
    ("large/cancel.bin", 2097152, "91d3beb88a9b2f778a6c44a1c53b63d3c79931845a9aef84b3fb414610bd1938", "f2a904a4"),
    ("nested/binary.bin", 256, "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880", "29058c73"),
    ("nested/caf\u00e9-\u96ea.txt", 27, "90bf78859b2ed84141735dae7df2ed9894593643772ca8a8a1a8d3b58c0af23f", "0fe1e113"),
    ("nested/spaced name.txt", 20, "0c6308d568f8ec30fbf044baac7827edac83a2465a60439ff653e277a5d9619e", "60fd99b6"),
)
ACQUISITIONS = dict(zip(("acquisition_readme", "acquisition_empty", "acquisition_large", "acquisition_binary",
                         "acquisition_unicode", "acquisition_spaced"), ROWS))
DIRECTORIES = ("empty-dir", "large", "nested")
SOURCE_DIRECTORIES = frozenset({"source", *("source/" + name for name in DIRECTORIES)})
SOURCE_FILES = frozenset({"source/fixture.zip", *("source/" + row[0] for row in ROWS)})
PROGRESS_BLOCK = 65536
PROGRESS_MAX = 1048576


def loaded_sources_preserved():
    H.loaded_sources_preserved()
    need(all(H.sha(H.read(module.__file__, 512 * 1024)) == module.loaded_source_sha256
             for module in (C, H, E, F)) and H.sha(H.read(__file__, 512 * 1024)) == SELF_SHA256,
         "preservation_failed")


def source_member(case, member, body=None):
    """The existing atomic creator, restricted to this literal fixture namespace."""
    H.hosted_guard()
    directory = body is None
    need(member in (SOURCE_DIRECTORIES if directory else SOURCE_FILES) and
         (directory or type(body) is bytes and len(body) <= F.MAX_ARCHIVE_BYTES), "case_setup_failed")
    path = case / member
    root_id, parent_id = H.identity(case), H.identity(path.parent)
    stream = H._native_private_create(case, path, directory)
    if directory:
        need(stream is None, "case_setup_failed")
        H.plain(path, True)
    else:
        with stream:
            opened = os.fstat(stream.fileno())
            need(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1 and opened.st_size == 0,
                 "case_setup_failed")
            need(stream.write(body) == len(body), "case_setup_failed")
            stream.flush()
            os.fsync(stream.fileno())
            after = H.plain(path)
            need((after.st_dev, after.st_ino, after.st_size) == (opened.st_dev, opened.st_ino, len(body)),
                 "preservation_failed")
    need(H.identity(case) == root_id and H.identity(path.parent) == parent_id, "preservation_failed")


def variant(name):
    return name if name == "corrupt_member" else "truncated" if name == "truncated_archive" else "valid"


def source_snapshot(case, backend, name):
    root = case / "source"
    entries = H.inventory(root)
    expected = ({row[0]: (row[1], row[2]) for row in ROWS} if backend == "local" else
                {"fixture.zip": next((row["size"], row["sha256"]) for row in F.archive_manifest()
                                     if row["variant"] == variant(name))})
    directories = set(DIRECTORIES) if backend == "local" else set()
    need(set(entries) == set(expected) | directories, "preservation_failed")
    snapshot = {"": (H.identity(root), H.plain(root, True).st_mtime_ns)}
    for member, info in entries.items():
        path = root / member
        need(info[0] is (member in directories), "preservation_failed")
        node = H.plain(path, info[0])
        digest = None
        if not info[0]:
            data = H.read(path, F.MAX_ARCHIVE_BYTES)
            digest = H.sha(data)
            need((len(data), digest) == expected[member], "preservation_failed")
        snapshot[member] = (info[0], node.st_dev, node.st_ino, node.st_size if not info[0] else None,
                            node.st_mtime_ns, digest)
    return snapshot


def create_source(case, backend, name):
    need(F.manifest() == [dict(path=p, size=s, sha256=h, crc32=c) for p, s, h, c in ROWS], "binding_failed")
    source_member(case, "source")
    if backend == "local":
        for directory in DIRECTORIES:
            source_member(case, "source/" + directory)
        for path, body in F.payloads().items():
            source_member(case, "source/" + path, body)
    else:
        source_member(case, "source/fixture.zip", F.archive_bytes(variant(name)))
    config = ("[Synthetic]\ntype = local\n" if backend == "local" else
              "[Synthetic]\ntype = archive\nremote = " + (case / "source/fixture.zip").as_posix() + "\n").encode("utf-8")
    return config, source_snapshot(case, backend, name)


def queue_row(backend, name):
    row = ACQUISITIONS.get(name, ROWS[2] if name == "cancellation" else ROWS[3] if name == "corrupt_member" else ROWS[0])
    path, size, sha, crc = row
    kind, digest = ("sha256", sha) if backend == "local" else ("CRC32", crc)
    if name == "mismatch":
        digest = "0" * len(digest)
    if name in {"missing", "directory_as_file"}:
        return ("missing-synthetic.txt" if name == "missing" else "empty-dir", None, None, None)
    return path, size, digest, kind


def queue_bytes(backend, name):
    text = io.StringIO(newline="")
    writer = csv.writer(text, lineterminator="\n")
    writer.writerow(["Path", "Remote", "Size", "Hash", "HashType"])
    path, size, digest, kind = queue_row(backend, name)
    writer.writerow([path, REMOTE, size, digest, kind])
    return text.getvalue().encode("utf-8")


def app_args(name, case):
    args = ["--name", CASE_NAME, "--output-dir", str(case / "output"),
            "--rclone-config-path", str(case / "source.conf")]
    return args + (["--list-remote", REMOTE] if name == "listing" else
                   ["--download", str(case / "queue.csv"), "--remote", REMOTE]) + (
                   ["--download-bytes-per-second", "65536"] if name == "cancellation" else [])


def timestamp_ns(value):
    match = re.fullmatch(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(?:Z|\+00:00)", value)
    need(match is not None, "listing_invalid")
    try:
        seconds = int(datetime.fromisoformat(match[1]).replace(tzinfo=timezone.utc).timestamp())
    except ValueError:
        raise H.ProducerError("listing_invalid") from None
    return seconds * 1_000_000_000 + int((match[2] or "").ljust(9, "0"))


def check_listing(case, backend):
    path = case / "output" / CASE_NAME / "listings/inventory.csv"
    data = H.read(path, 65536)
    need(data.startswith(b"\xef\xbb\xbf"), "listing_invalid")
    try:
        rows = list(csv.reader(io.StringIO(data.decode("utf-8-sig"), newline=""), strict=True))
    except (UnicodeError, csv.Error):
        raise H.ProducerError("listing_invalid") from None
    expected = {p: ["excel-safe-v1", REMOTE, p, str(s), "false", "", ""] for p, s, _, _ in ROWS}
    expected.update({p: ["excel-safe-v1", REMOTE, p, "", "true", "", ""] for p in DIRECTORIES})
    need(rows and rows[0] == H.HEADERS and len(rows) == len(expected) + 1, "listing_invalid")
    for row in rows[1:]:
        need(len(row) == 8 and row[2] in expected, "listing_invalid")
        expected_time = (H.plain(case / "source" / row[2], row[2] in DIRECTORIES).st_mtime_ns
                         if backend == "local" else MODIFIED_NS)
        need(timestamp_ns(row[4]) == expected_time and row[:4] + row[5:] == expected.pop(row[2]), "listing_invalid")
    need(not expected, "listing_invalid")
    need(not H.inventory(case / "output" / CASE_NAME / "downloads"), "outputs_invalid")
    application_inventory(case, "listing", None, None)
    return dict(inventory_exact=True, listing_complete=True)


def application_inventory(case, name, manifest_name, member):
    base = case / "output" / CASE_NAME
    entries = H.inventory(base)
    files = {p for p, info in entries.items() if not info[0]}
    configs = {p for p in files if p.startswith("config/")}
    need(len(configs) == 2, "outputs_invalid")
    wanted = set(configs)
    dirs = {"config", "downloads", "logs", "listings"}
    allowed_dirs = set(dirs)
    if name == "listing":
        wanted.add("listings/inventory.csv")
    else:
        stem = manifest_name.removesuffix(".json")
        wanted.update({manifest_name, stem + ".txt", "logs/" + stem + ".log", "logs/" + stem + ".checkpoint.json"})
        if name in ACQUISITIONS or name == "mismatch":
            wanted.add("downloads/" + REMOTE + "/" + member)
        parts = ("downloads/" + REMOTE + "/" + member).split("/")
        allowed_dirs.update("/".join(parts[:i]) for i in range(1, len(parts)))
    need(files == wanted and dirs <= {p for p, info in entries.items() if info[0]} <= allowed_dirs, "outputs_invalid")
    need(set(H.inventory(case / "output")) == {CASE_NAME} | {CASE_NAME + "/" + p for p in entries}, "outputs_invalid")


def check_manifest(case, backend, name, config, runtime):
    base = case / "output" / CASE_NAME
    entries = H.inventory(base)
    names = [p for p, info in entries.items() if "/" not in p and not info[0] and re.fullmatch(r"acquisition-[0-9T.]+\.json", p)]
    need(len(names) == 1, "manifest_invalid")
    value = H.strict_json(H.read(base / names[0]))
    need(type(value) is dict and set(value) == {"schema_version", "written_at", "rclone_version", "config_path", "plan", "results", "complete"}
         and type(value["schema_version"]) is int and value["schema_version"] == 1 and
         value["rclone_version"] == runtime["version"] and H.valid_time(value["written_at"]) and
         H.same_path(value["config_path"], config) and type(value["complete"]) is bool, "manifest_invalid")
    plan, results = value["plan"], value["results"]
    need(type(plan) is dict and set(plan) == {"files", "skipped_directories"} and
         type(plan["skipped_directories"]) is int and plan["skipped_directories"] == 0 and
         type(plan["files"]) is list and len(plan["files"]) == 1 and type(results) is list and len(results) == 1, "manifest_invalid")
    path, size, digest, kind = queue_row(backend, name)
    destination = base / "downloads" / REMOTE / path
    planned, result = plan["files"][0], results[0]
    need(type(planned) is dict and set(planned) == {"remote_name", "path", "request"} and
         planned["remote_name"] == REMOTE and planned["path"] == path, "manifest_invalid")
    request = planned["request"]
    need(type(request) is dict and set(request) == {"source", "destination", "mode", "expected_hash", "expected_hash_type", "expected_size"}
         and request["source"] == REMOTE + ":" + path and H.same_path(request["destination"], destination) and
         request["mode"] == "CopyTo" and request["expected_hash"] == digest and request["expected_hash_type"] == kind and
         request["expected_size"] == size and (size is None or type(request["expected_size"]) is int), "manifest_invalid")
    need(type(result) is dict and set(result) == {"local_sha256", "integrity", "source", "destination", "success", "error", "size", "hash", "hash_type", "hash_verified", "hash_error"}
         and type(result["success"]) is bool and result["source"] == REMOTE + ":" + path and
         H.same_path(result["destination"], destination), "manifest_invalid")
    acquired = name in ACQUISITIONS
    if acquired or name == "mismatch":
        _, actual_size, actual_sha, actual_crc = next(row for row in ROWS if row[0] == path)
        actual_hash = actual_sha if backend == "local" else actual_crc
        expected = dict(local_sha256=actual_sha, integrity="Verified" if acquired else "Mismatch", source=REMOTE + ":" + path,
            destination=result["destination"], success=acquired, error=None if acquired else "Downloaded bytes do not match the expected source hash",
            size=actual_size, hash=actual_hash, hash_type=kind, hash_verified=acquired, hash_error=None)
        need(result == expected and type(result["size"]) is int and type(result["hash_verified"]) is bool, "manifest_invalid")
        data = H.read(destination, F.MAX_MEMBER_BYTES)
        expected_time = H.plain(case / "source" / path).st_mtime_ns if backend == "local" else MODIFIED_NS
        need((len(data), H.sha(data)) == (actual_size, actual_sha) and H.plain(destination).st_mtime_ns == expected_time, "outputs_invalid")
        checks = (dict(manifest_complete=True, manifest_exact=True, output_hashes_exact=True, outputs_exact=True) if acquired else
                  dict(manifest_incomplete=True, mismatch_exact=True, retained_bytes_exact=True, outputs_exact=True))
        if acquired and backend == "archive":
            checks["archive_crc32"] = True
    else:
        need(result["success"] is False and result["integrity"] == ("Cancelled" if name == "cancellation" else "Failed") and
             all(result[key] is None for key in ("local_sha256", "size", "hash", "hash_type", "hash_verified", "hash_error")) and
             type(result["error"]) is str and 0 < len(result["error"]) <= 65536 and
             "staging cleanup failed" not in result["error"].lower(), "manifest_invalid")
        error = result["error"]
        if name == "cancellation":
            check = "cancelled_result_exact"
        elif name == "missing":
            need(error == "Source was not found or is not an individual file: Synthetic:missing-synthetic.txt", "manifest_invalid")
            check = "missing_failure_exact"
        elif name == "directory_as_file":
            need(error == "Source was not found or is not an individual file: Synthetic:empty-dir" or
                 error.startswith("Cannot stat source: ") and "is not a regular file" in error, "manifest_invalid")
            check = "directory_failure_exact"
        elif name == "corrupt_member":
            need("zip: checksum error" in error, "manifest_invalid")
            check = "corruption_failure_exact"
        else:
            need(name == "truncated_archive" and error.startswith("Cannot stat source: ") and
                 "zip: not a valid zip file" in error, "manifest_invalid")
            check = "archive_failure_exact"
        need(not H.output_files(base / "downloads"), "outputs_invalid")
        checks = dict(manifest_incomplete=True, no_download_outputs=True, **{check: True})
        if name == "cancellation":
            checks["no_partial_outputs"] = True  # Exact inventory below also refuses a staging directory.
    need(value["complete"] is acquired, "manifest_invalid")
    application_inventory(case, name, names[0], path)
    return checks


def final_observation(value, backend, name, runtime):
    expected = E.EXPECTED_LAUNCHES[backend][name]
    C.validate_observed_snapshot(value, "finish", runtime["sha256"], 1, expected)
    need(value["ok"] and value["state"] == "finished" and not value["forced_termination"] and
         all(value[key] for key in H.SESSION_CLEANUP) and value["launch_image_observed"] and
         value["launch_sha256"] == runtime["sha256"] and value["runtime_launch_count"] == expected and
         value["peak_runtime_processes"] == 1 and value["system_helper_image_observed"] and
         1 <= value["system_helper_launch_count"] <= expected and
         1 <= value["peak_system_helper_processes"] <= min(2, value["system_helper_launch_count"]) and
         all(value[key] for key in ("debug_events_drained", "debug_pump_joined", "debug_handles_closed", "system_helper_reference_closed")),
         "session_failed")
    return dict(kind="launch_image", runtime_launch_count=expected, peak_runtime_processes=1,
                debug_event_count=value["debug_event_count"], system_helper_sha256=value["system_helper_sha256"],
                system_helper_launch_count=value["system_helper_launch_count"],
                peak_system_helper_processes=value["peak_system_helper_processes"])


class ContentWitness:
    """Two bounded reads of one retained staged file; length never proves progress."""
    def __init__(self, case, case_lease, relative, entries, cleanup):
        self.case, self.case_lease = case, case_lease
        self.base = case / "output" / CASE_NAME / "downloads"
        self.path = self.base / relative
        self.parents = [case / "output", case / "output" / CASE_NAME, self.base,
                        self.base / REMOTE, self.base / REMOTE / "large", self.path.parent]
        self.identities = [H.identity(path) for path in self.parents]
        observed = entries[relative]
        need(not observed[0], "cancellation_failed")
        self.leaf = observed[2:4]
        self.cleanup, self.close_attempted = cleanup, False
        self.stream = self.path.open("rb", buffering=0)
        self.cleanup["closed"] = False
        try:
            self.verify()
        except BaseException:
            try:
                self.close()
            except BaseException:
                pass  # Keep the original verification error and sticky close uncertainty.
            raise

    def verify(self):
        need(H.identity(self.case) == self.case_lease and
             [H.identity(path) for path in self.parents] == self.identities, "preservation_failed")
        path_info, info = H.plain(self.path), os.fstat(self.stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
             not getattr(info, "st_file_attributes", 0) & 0x400 and
             (info.st_dev, info.st_ino) == self.leaf == (path_info.st_dev, path_info.st_ino) and
             0 <= info.st_size <= ROWS[2][1] and 0 <= path_info.st_size <= ROWS[2][1], "preservation_failed")
        return max(info.st_size, path_info.st_size)

    def sample(self):
        before = self.verify()
        self.stream.seek(0)
        data = self.stream.read(PROGRESS_MAX + PROGRESS_BLOCK)
        after = self.verify()
        # Raw FileIO.read may return short even before EOF. Only an actual extent
        # no larger than the bytes read can prove the later block absent. Growth
        # during a short read is uncertain and cannot earn a content witness.
        need(len(data) >= min(max(before, after), PROGRESS_MAX + PROGRESS_BLOCK), "cancellation_failed")
        # A zero-filled preallocation, wrong bytes, or a completed image does not
        # qualify. The next whole block is absent/incomplete or differs from the
        # literal pattern; the next sample must incorporate it fully and exactly.
        expected = bytes(range(256)) * (PROGRESS_BLOCK // 256)
        matched = 0
        while data[matched:matched + PROGRESS_BLOCK] == expected:
            matched += PROGRESS_BLOCK
            if matched > PROGRESS_MAX:
                raise H.ProducerError("cancellation_failed")
        return matched

    def close(self):
        if self.close_attempted:
            need(self.cleanup["closed"] and not self.cleanup["failed"], "cleanup_failed")
            return
        self.close_attempted = True
        try:
            self.stream.close()
            self.cleanup["closed"] = True
        except BaseException:
            self.cleanup["failed"] = True
            raise H.ProducerError("cleanup_failed") from None


def cancellation_witness(case, lease, cleanup=None):
    cleanup = {"closed": True, "failed": False} if cleanup is None else cleanup
    need(H.identity(case) == lease, "preservation_failed")
    base = case / "output" / CASE_NAME / "downloads"
    if not base.exists():
        return None
    base_lease = H.identity(base)
    entries = H.inventory(base)
    matches = [path for path, info in entries.items() if not info[0] and re.fullmatch(
        r"Synthetic/large/\.triage-transfer-[0-9a-f]{32}/payload\.[0-9a-f]{8}\.partial", path)]
    need(len(matches) <= 1, "cancellation_failed")
    if not matches:
        need(all(info[0] for info in entries.values()), "cancellation_failed")
        return None
    relative = matches[0]
    expected_dirs = {REMOTE, REMOTE + "/large", relative.rsplit("/", 1)[0]}
    need(set(entries) == expected_dirs | {relative} and
         all(entries[path][0] for path in expected_dirs) and H.identity(base) == base_lease and
         H.identity(case) == lease, "cancellation_failed")
    return ContentWitness(case, lease, relative, entries, cleanup)


def live_running(value, action):
    C.validate_snapshot(value, action)
    need(value["ok"] and value["state"] == "running" and not value["app_exited"] and
         not value["forced_termination"] and not value["output_limit_exceeded"] and
         not value["ctrl_c_sent"], "cancellation_failed")


def observe_live(bridge, case, runtime):
    value = bridge.command("observe_runtime", extraction_root=str(case / "temp"), expected_sha256=runtime["sha256"])
    live_running(value, "observe_runtime")
    need(value["runtime_image_observed"] and value["runtime_sha256"] == runtime["sha256"] and
         value["runtime_process_count"] == 1, "runtime_unobserved")


def cancel_active_transfer(bridge, case, lease, runtime, deadline, cleanup=None):
    witness = None
    first = last = 0
    primary_failure = False
    try:
        while witness is None:
            need(time.monotonic() < deadline, "deadline_exceeded")
            live_running(bridge.command("poll"), "poll")
            witness = cancellation_witness(case, lease, cleanup)
            if witness is None:
                time.sleep(0.05)
        observe_live(bridge, case, runtime)
        need(time.monotonic() < deadline, "deadline_exceeded")
        while not first or last <= first:
            need(time.monotonic() < deadline, "deadline_exceeded")
            live_running(bridge.command("poll"), "poll")
            matched = witness.sample()
            need(time.monotonic() < deadline, "deadline_exceeded")
            if first:
                need(matched >= first, "cancellation_failed")
                last = matched
            elif matched:
                first = matched
            if last <= first:
                time.sleep(0.05)
        observe_live(bridge, case, runtime)
        need(time.monotonic() < deadline, "deadline_exceeded")
        need(PROGRESS_BLOCK <= first < last <= PROGRESS_MAX and
             first % PROGRESS_BLOCK == last % PROGRESS_BLOCK == 0, "cancellation_failed")
    except BaseException:
        primary_failure = True
        raise
    finally:
        if witness is not None:
            try:
                witness.close()  # Never obstruct rclone's staging removal after Ctrl+C.
            except BaseException:
                if not primary_failure:
                    raise
    need(time.monotonic() < deadline, "deadline_exceeded")
    live_running(bridge.command("poll"), "poll")
    need(time.monotonic() < deadline, "deadline_exceeded")
    value = bridge.command("ctrl_c")
    need(time.monotonic() < deadline, "deadline_exceeded")
    C.validate_snapshot(value, "ctrl_c")
    need(value["ok"] and value["ctrl_c_sent"] and not value["forced_termination"], "cancellation_failed")
    return dict(kind="live_image", runtime_process_count=1, first_verified_bytes=first, last_verified_bytes=last), value


def final_live_observation(value, runtime):
    C.validate_snapshot(value, "finish")
    need(value["ok"] and value["state"] == "finished" and value["ctrl_c_sent"] and
         not value["forced_termination"] and not value["output_limit_exceeded"] and
         all(value[key] for key in H.SESSION_CLEANUP) and value["runtime_image_observed"] and
         value["runtime_sha256"] == runtime["sha256"] and value["runtime_process_count"] == 1,
         "session_failed")


def case_inventory(case, name, helper_current):
    """No unrelated file or directory can hide outside the output/source oracle."""
    entries = H.inventory(case)
    wanted_dirs = set(H.PRIVATE_LOCATIONS) | {"helper-env", "source", "output"}
    wanted_dirs.update("helper-env/" + path for path in helper_current)
    wanted_files = {"application.exe", "source.conf", "transcript.private", "bridge-stdout.private", "bridge-stderr.private"}
    if name != "listing":
        wanted_files.add("queue.csv")
    for root in ("source", "output"):
        for path, info in H.inventory(case / root).items():
            (wanted_dirs if info[0] else wanted_files).add(root + "/" + path)
    need({p for p, info in entries.items() if info[0]} == wanted_dirs and
         {p for p, info in entries.items() if not info[0]} == wanted_files, "cleanup_failed")
    need(all(entries[name][1] <= 8 * 1024 * 1024 for name in
             ("transcript.private", "bridge-stdout.private", "bridge-stderr.private")), "cleanup_failed")


def run_case(backend, name, suite, application, application_sha, runtime, session_factory=None):
    H.hosted_guard()
    need(name in E.CASE_ORDER[backend], "case_setup_failed")
    record = dict(status="failed", exit_code=None, runtime_sha256=None, observation=None,
                  failure_code=None, checks=dict.fromkeys(E.CASE_CHECKS[backend][name], False))
    checks = record["checks"]
    case_name = "fs-" + backend + "-" + name.replace("_", "-")
    case = suite / case_name
    lease = bridge = roots = helper_before = baseline = config_bytes = None
    attempted = False
    witness_cleanup = {"closed": True, "failed": False}
    def fail(code):
        if record["failure_code"] is None:
            record["failure_code"] = code if code in E.FAILURE_CODES else "unexpected_failure"
    try:
        H.prepare(suite, case_name)
        lease = H.identity(case)
        roots = H.create_private_roots(case)
        H.private_directory(case, "output")
        H.private_write(case, "application.exe", H.read(application, 512 * 1024 * 1024, allow_hardlinks=True))
        need(H.sha(H.read(case / "application.exe", 512 * 1024 * 1024)) == application_sha, "binding_failed")
        config_bytes, baseline = create_source(case, backend, name)
        checks["fixture_valid"] = True
        H.private_write(case, "source.conf", config_bytes)
        if name != "listing":
            H.private_write(case, "queue.csv", queue_bytes(backend, name))
        attempted = True
        bridge = (session_factory or (C.SourceBridge if name == "cancellation" else C.ObservedSourceBridge))(case)
        H.validate_ready(bridge.command("ready"))
        helper_before = H.helper_baseline(case, roots)
        H.application_roots_empty(case, roots)
        deadline = time.monotonic() + H.CASE_SECONDS
        start = dict(app_path=str(case / "application.exe"), app_sha256=application_sha,
            args=app_args(name, case), case_root=str(case), environment=H.environment(case),
            transcript_path=str(case / "transcript.private"), max_output_bytes=8 * 1024 * 1024, deadline_ms=150000,
            max_runtime_processes=1)
        if name == "cancellation":
            response = bridge.command("start_source", **start)
            live_running(response, "start_source")
            observation, response = cancel_active_transfer(bridge, case, lease, runtime, deadline, witness_cleanup)
            record["observation"], record["runtime_sha256"] = observation, runtime["sha256"]
            checks["runtime_observed"] = checks["transfer_active"] = checks["content_progress_exact"] = checks["ctrl_c_sent"] = True
        else:
            start.update(expected_runtime_sha256=runtime["sha256"], max_runtime_launches=E.EXPECTED_LAUNCHES[backend][name])
            response = bridge.command("start_source_observed", **start)
        while not response["app_exited"]:
            need(response["ok"] and time.monotonic() < deadline, "session_failed")
            response = bridge.command("poll")
            time.sleep(0.05)
        response = bridge.command("finish", grace_ms=10000)
        bridge.last = response
        record["exit_code"] = response["app_exit_code"]
        if name == "cancellation":
            final_live_observation(response, runtime)
        else:
            record["observation"] = final_observation(response, backend, name, runtime)
        record["runtime_sha256"] = runtime["sha256"]
        checks["runtime_observed"] = checks["orderly_exit"] = True
        positive = name == "listing" or name in ACQUISITIONS
        need((record["exit_code"] == 0) is positive, "session_failed")
        checks["exit_success" if positive else "exit_failure"] = True
        config = H.configuration_preserved(case, config_bytes)
        checks["configuration_preserved"] = True
        checks.update(check_listing(case, backend) if name == "listing" else check_manifest(case, backend, name, config, runtime))
    except H.ProducerError as error:
        fail(str(error))
    except BaseException:
        fail("unexpected_failure")
    finally:
        if bridge is not None:
            try:
                checks["process_cleanup"] = bridge.close()
            except BaseException:
                fail("cleanup_failed")
        else:
            checks["process_cleanup"] = not attempted
        # There is no server. Fixture closure means all source users are reaped;
        # exact bytes/identity and the source-CWD lease are separately checked.
        checks["fixture_cleanup"] = checks["process_cleanup"] and witness_cleanup["closed"] and not witness_cleanup["failed"]
        if not witness_cleanup["closed"] or witness_cleanup["failed"]:
            fail("cleanup_failed")
        if lease is not None and checks["process_cleanup"] and checks["fixture_cleanup"]:
            try:
                need(H.identity(case) == lease, "preservation_failed")
                need(baseline is not None and source_snapshot(case, backend, name) == baseline, "preservation_failed")
                checks["source_preserved"] = True
                need(config_bytes is not None and H.read(case / "source.conf", 8192) == config_bytes and
                     H.sha(H.read(case / "application.exe", 512 * 1024 * 1024)) == application_sha, "preservation_failed")
                if name != "listing":
                    need(H.read(case / "queue.csv", 65536) == queue_bytes(backend, name), "preservation_failed")
                if checks["configuration_preserved"]:
                    H.configuration_preserved(case, config_bytes)
                H.application_roots_empty(case, roots)
                helper_current = H.helper_baseline(case, roots)
                H.helper_cleanup_preserved(helper_current, helper_before)
                case_inventory(case, name, helper_current)
                checks["process_cleanup"] = checks["fixture_cleanup"] = False
                H.prepare(suite, case_name, "Verify")
                checks["process_cleanup"] = checks["fixture_cleanup"] = True
                need(source_snapshot(case, backend, name) == baseline, "preservation_failed")
                H.remove_owned(case, lease)
                checks["temp_cleanup"] = True
            except BaseException:
                fail("cleanup_failed")
    if not all(checks.values()):
        fail("session_failed")
    if record["failure_code"] is None and all(checks.values()):
        record["status"] = "passed"
    return record


def run(backend, application, application_sha, build_commit):
    H.hosted_guard()
    need(backend in E.CASE_ORDER, "binding_failed")
    application = Path(application).absolute()
    loaded_sources_preserved()
    runtime = H.runtime_pins(ROOT / "rclone-version.env")
    bindings = E.compute_bindings(ROOT, application, build_commit)
    need(bindings["application_sha256"] == application_sha and os.environ.get("GITHUB_SHA") == build_commit, "binding_failed")
    cases, errors = E.empty_cases(backend), []
    suite = lease = None
    cleaned = False
    try:
        parent = Path(os.environ["RUNNER_TEMP"]).absolute()
        suite = parent / ("app-filesystem-" + uuid.uuid4().hex)
        H.prepare(parent, suite.name)
        lease = H.identity(suite)
        for name in E.CASE_ORDER[backend]:
            need(H.identity(suite) == lease, "preservation_failed")
            cases[name] = run_case(backend, name, suite, application, application_sha, runtime)
            if cases[name]["status"] != "passed":
                errors.append(cases[name]["failure_code"])
                break
    except H.ProducerError as error:
        errors.append(str(error) if str(error) in E.FAILURE_CODES else "unexpected_failure")
    except BaseException:
        errors.append("unexpected_failure")
    finally:
        try:
            loaded_sources_preserved()
            need(E.compute_bindings(ROOT, application, build_commit) == bindings and
                 H.runtime_pins(ROOT / "rclone-version.env") == runtime, "preservation_failed")
        except BaseException:
            errors.append("preservation_failed")
        if lease is not None:
            try:
                need(all(row["status"] == "not_run" or all(row["checks"][key] for key in
                     ("process_cleanup", "fixture_cleanup", "temp_cleanup")) for row in cases.values()), "cleanup_failed")
                need(H.identity(suite) == lease and not H.inventory(suite), "cleanup_failed")
                H.prepare(suite.parent, suite.name, "Verify")
                H.remove_owned(suite, lease)
                cleaned = True
            except BaseException:
                errors.append("cleanup_failed")
    errors = list(dict.fromkeys(errors))
    ordinary = [row for name, row in cases.items() if name != "cancellation"]
    cancelled = cleaned and cases["cancellation"]["status"] == "passed"
    complete = cleaned and not errors and all(row["status"] == "passed" for row in cases.values())
    receipt = dict(schema_version=2, scope=E.SCOPE, fixture_mode=E.MODE[backend], backend=backend, platform="windows",
        created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), runtime=runtime, bindings=bindings,
        cases=cases, capabilities=E.derive_capabilities(backend, cases, cleaned), cleanup_complete=cleaned,
        result="passed" if complete else "partial" if cleaned and not errors and
            cases["cancellation"]["status"] == "not_run" and all(row["status"] == "passed" for row in ordinary) else "failed",
        errors=errors, claims={**dict.fromkeys(E.FALSE_CLAIMS, False), "cancellation_verified": cancelled})
    E.validate_receipt(receipt, runtime, bindings)
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", choices=("local", "archive"), required=True)
    for flag in ("application", "application-sha256", "build-commit", "report"):
        parser.add_argument("--" + flag, required=True)
    args = parser.parse_args(argv)
    descriptor = prior = None
    try:
        H.hosted_guard()
        def interrupted(_signal, _frame):
            raise KeyboardInterrupt()
        prior = signal.signal(signal.SIGTERM, interrupted)
        path = Path(args.report).absolute()
        H.plain(path.parent, True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        receipt = run(args.backend, args.application, args.application_sha256, args.build_commit)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(E.compact(receipt) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        return 0 if receipt["result"] == "passed" else 1
    except BaseException:
        print("application_filesystem_probe_failed", file=__import__("sys").stderr)
        return 1
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if prior is not None:
            signal.signal(signal.SIGTERM, prior)


if __name__ == "__main__":
    raise SystemExit(main())
