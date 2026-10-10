"""Pure filesystem/mocked process tests; never start a native helper or app."""
from contextlib import ExitStack, redirect_stdout
import copy
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch
import zlib


ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "scripts/application-lab/run_windows_filesystem.py"
P = types.ModuleType("filesystem_producer_test")
P.__file__ = str(PATH)
exec(compile(PATH.read_bytes(), str(PATH), "exec"), P.__dict__)
BODY = {"README-synthetic.txt": b"synthetic application fixture\n", "empty.bin": b"",
        "large/cancel.bin": bytes(range(256)) * 8192, "nested/binary.bin": bytes(range(256)),
        "nested/caf\u00e9-\u96ea.txt": "\u00e9 and \u96ea: synthetic only\n".encode(),
        "nested/spaced name.txt": b"spaces remain exact\n"}
RUNTIME = {"version": "1.75.2", "sha256": "a" * 64, "platform": "windows"}


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def snapshot(count, exit_code):
    value = dict(schema_version=3, action="finish", ok=True, state="finished", app_exit_code=exit_code,
        runtime_image_observed=False, runtime_sha256=None, runtime_process_count=None, ctrl_c_sent=False,
        output_bytes=50, output_limit_exceeded=False, forced_termination=False, app_exited=True,
        observed_children_exited=True, job_zero_confirmed=True, reader_joined=True, conpty_closed=True, errors=[],
        observation_kind="launch_image", launch_image_observed=True, launch_sha256="a" * 64,
        runtime_launch_count=count, peak_runtime_processes=1, debug_event_count=20 + count * 8,
        debug_events_drained=True, debug_pump_joined=True, debug_handles_closed=True,
        system_helper_image_observed=True, system_helper_sha256="b" * 64, system_helper_launch_count=count,
        peak_system_helper_processes=1, system_helper_reference_closed=True)
    return value


def artifacts(case, backend, name):
    """Literal app schema and byte oracle, independent of producer builders."""
    base = case / "output/synthetic-case"
    for part in ("config", "downloads", "listings", "logs"):
        (base / part).mkdir(parents=True, exist_ok=True)
    conf = (case / "source.conf").read_bytes()
    working = base / "config/working-test.conf"
    write(working, conf)
    write(working.with_suffix(".provenance.json"), json.dumps(dict(schema_version=1, source_path=str(case / "source.conf"),
        source_sha256=hashlib.sha256(conf).hexdigest(), working_path=str(working), snapshotted_at="2025-01-02T03:04:06Z")).encode())
    if name == "listing":
        text = io.StringIO(newline="")
        writer = csv.writer(text)
        writer.writerow(["path_encoding", "remote", "path", "size", "modified", "is_dir", "hash", "hash_type"])
        def modified(member):
            if backend == "archive":
                return "2025-01-02T03:04:06+00:00"
            seconds, nanos = divmod((case / "source" / member).stat().st_mtime_ns, 1000000000)
            return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + f".{nanos:09d}+00:00"
        for member, body in BODY.items():
            writer.writerow(["excel-safe-v1", "Synthetic", member, len(body), modified(member), "false", "", ""])
        for directory in ("empty-dir", "large", "nested"):
            size = (case / "source" / directory).stat().st_size if backend == "local" else ""
            writer.writerow(["excel-safe-v1", "Synthetic", directory, size, modified(directory), "true", "", ""])
        write(base / "listings/inventory.csv", b"\xef\xbb\xbf" + text.getvalue().encode())
        return
    rows = list(csv.DictReader(io.StringIO((case / "queue.csv").read_text(encoding="utf-8"))))
    assert len(rows) == 1
    row = rows[0]
    member = row["Path"]
    destination = base / "downloads/Synthetic" / member
    request = dict(source="Synthetic:" + member, destination=str(destination), mode="CopyTo",
        expected_hash=row["Hash"] or None, expected_hash_type=row["HashType"] or None,
        expected_size=int(row["Size"]) if row["Size"] else None)
    acquired = name.startswith("acquisition_")
    result = dict(source=request["source"], destination=str(destination), success=acquired, error=None,
        local_sha256=None, integrity="Failed", size=None, hash=None, hash_type=None, hash_verified=None, hash_error=None)
    if acquired or name == "mismatch":
        body = BODY[member]
        write(destination, body)
        mtime = (case / "source" / member).stat().st_mtime_ns if backend == "local" else 1735787046000000000
        os.utime(destination, ns=(mtime, mtime))
        result.update(local_sha256=hashlib.sha256(body).hexdigest(), integrity="Verified" if acquired else "Mismatch",
            size=len(body), hash=hashlib.sha256(body).hexdigest() if backend == "local" else f"{zlib.crc32(body):08x}",
            hash_type="sha256" if backend == "local" else "CRC32", hash_verified=acquired,
            error=None if acquired else "Downloaded bytes do not match the expected source hash")
    else:
        result["error"] = {"missing": "Source was not found or is not an individual file: Synthetic:missing-synthetic.txt",
            "directory_as_file": "Cannot stat source: read metadata failed: is not a regular file",
            "corrupt_member": "ERROR: failed to copy: zip: checksum error",
            "truncated_archive": "Cannot stat source: zip: not a valid zip file",
            "cancellation": "Operation cancelled"}[name]
        if name == "cancellation":
            result["integrity"] = "Cancelled"
    stem = "acquisition-20250102T030406.123"
    value = dict(schema_version=1, written_at="2025-01-02T03:04:06Z", rclone_version="1.75.2",
        config_path=str(working), plan=dict(files=[dict(remote_name="Synthetic", path=member, request=request)], skipped_directories=0),
        results=[result], complete=acquired)
    write(base / (stem + ".json"), json.dumps(value).encode())
    for suffix in (stem + ".txt", "logs/" + stem + ".log", "logs/" + stem + ".checkpoint.json"):
        write(base / suffix, b"synthetic artifact\n")


class FakeBridge:
    backend = "local"
    name = "listing"
    mutate = None
    close_ok = True
    calls = []
    def __init__(self, case):
        self.case, self.last = case, None
        for path in ("bridge-stdout.private", "bridge-stderr.private"):
            write(case / path, b"")
    def command(self, action, **fields):
        self.calls.append((action, copy.deepcopy(fields)))
        if action == "ready":
            return dict(schema_version=1, action="ready", state="ready", ok=True)
        if action == "start_source_observed":
            assert fields["environment"] == {"SYNTHETIC_CASE": str(self.case)}
            assert fields["max_runtime_processes"] == 1
            assert fields["expected_runtime_sha256"] == "a" * 64
            assert fields["args"][0:2] == ["--name", "synthetic-case"]
            write(self.case / "transcript.private", b"private fixture output\n")
            artifacts(self.case, self.backend, self.name)
            value = snapshot(fields["max_runtime_launches"], 0 if self.name == "listing" or self.name.startswith("acquisition_") else 1)
            value.update(state="running", action=action, system_helper_reference_closed=False, debug_handles_closed=False)
            self.last = value
            return value
        assert action == "finish" and fields == {"grace_ms": 10000}
        value = snapshot(self.last["runtime_launch_count"], self.last["app_exit_code"])
        if self.mutate is not None:
            self.mutate(value, self.case)
        self.last = value
        return value
    def close(self):
        self.calls.append(("close", {}))
        # The real close path finishes a still-running session before closing its
        # transport. Never repair an already-final malformed/uncertain snapshot.
        if self.close_ok and type(self.last) is dict and self.last.get("state") == "running":
            value = copy.deepcopy(self.last)
            forced = not value["app_exited"]
            value.update(action="finish", state="finished", app_exited=True,
                         app_exit_code=value["app_exit_code"] if value["app_exit_code"] is not None else 1)
            for key in P.H.SESSION_CLEANUP:
                value[key] = True
            if value["schema_version"] == 3:
                for key in P.C.OBSERVED_CLEANUP:
                    value[key] = True
            if forced:
                value.update(ok=False, errors=["forced_termination"], forced_termination=True)
            self.last = value
        return self.close_ok


def live_snapshot(action, finished=False, observed=True, cancelled=False):
    return dict(schema_version=1, action=action, ok=True, state="finished" if finished else "running",
        app_exit_code=1 if finished else None, runtime_image_observed=observed,
        runtime_sha256="a" * 64 if observed else None, runtime_process_count=1 if observed else None,
        ctrl_c_sent=cancelled, output_bytes=50, output_limit_exceeded=False, forced_termination=False,
        app_exited=finished, observed_children_exited=finished, job_zero_confirmed=finished,
        reader_joined=finished, conpty_closed=finished, errors=[])


class FakeLiveBridge(FakeBridge):
    name = "cancellation"
    progress = "advance"
    change_response = None
    def __init__(self, case):
        super().__init__(case)
        self.polls, self.cancelled = 0, False
        self.partial = case / ("output/synthetic-case/downloads/Synthetic/large/" +
                              ".triage-transfer-" + "a" * 32 + "/payload.1234abcd.partial")
    def command(self, action, **fields):
        self.calls.append((action, copy.deepcopy(fields)))
        if action == "ready":
            return dict(schema_version=1, action="ready", state="ready", ok=True)
        if action == "start_source":
            assert fields["environment"] == {"SYNTHETIC_CASE": str(self.case)}
            assert "max_runtime_launches" not in fields and "expected_runtime_sha256" not in fields
            assert fields["max_runtime_processes"] == 1
            assert fields["args"][-2:] == ["--download-bytes-per-second", "65536"]
            row = list(csv.DictReader(io.StringIO((self.case / "queue.csv").read_text())))[0]
            assert row["Path"] == "large/cancel.bin" and row["Size"] == "2097152"
            assert row["HashType"] == ("sha256" if self.backend == "local" else "CRC32")
            write(self.case / "transcript.private", b"private cancellation output\n")
            write(self.partial, b"\0" * 2097152)  # Full preallocation cannot be the witness.
            value = live_snapshot(action, observed=False)
        elif action == "poll":
            self.polls += 1
            if not self.cancelled and self.polls in (2, 3):
                size = 65536 if self.polls == 2 or self.progress == "static" else 131072
                with self.partial.open("r+b") as stream:
                    stream.write(BODY["large/cancel.bin"][:size])
            value = live_snapshot(action, finished=self.cancelled or self.polls > 4, cancelled=self.cancelled)
        elif action == "observe_runtime":
            assert fields == dict(extraction_root=str(self.case / "temp"), expected_sha256="a" * 64)
            value = live_snapshot(action)
        elif action == "ctrl_c":
            assert not fields
            # On Windows, this also detects if the producer still owns its read handle.
            self.partial.unlink()
            self.partial.parent.rmdir()
            artifacts(self.case, self.backend, "cancellation")
            self.cancelled = True
            value = live_snapshot(action, cancelled=True)
        else:
            assert action == "finish" and fields == {"grace_ms": 10000}
            value = live_snapshot(action, finished=True, cancelled=self.cancelled)
            if self.mutate is not None:
                self.mutate(value, self.case)
        if self.change_response is not None:
            self.change_response(value, self.polls)
        self.last = value
        return value


class FilesystemProducerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.app = self.root / "fixture-app.bin"
        self.app.write_bytes(b"synthetic, never executed")
        self.sha = hashlib.sha256(self.app.read_bytes()).hexdigest()
        self.suite = self.root / "suite"
        self.suite.mkdir()
        self.stack = ExitStack()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(subprocess, "Popen", side_effect=AssertionError("native_forbidden")))
        self.stack.enter_context(patch.object(socket, "socket", side_effect=AssertionError("socket_forbidden")))
        self.stack.enter_context(patch.object(socket, "create_connection", side_effect=AssertionError("socket_forbidden")))
        self.stack.enter_context(patch.object(P.H, "hosted_guard"))
        # These fake launches must not depend on Windows host variables on Linux.
        # The real scrubbed environment builder and hosted guard stay unchanged.
        self.environment = self.stack.enter_context(patch.object(P.H, "environment",
            side_effect=lambda case: {"SYNTHETIC_CASE": str(case)}))
        self.stack.enter_context(patch.object(P.time, "sleep"))
        self.stack.enter_context(patch.object(P.H, "prepare", side_effect=self.prepare))
        self.stack.enter_context(patch.object(P.H, "_native_private_create", side_effect=self.create))
    @staticmethod
    def prepare(parent, name, action="Create"):
        target = parent / name
        if action == "Create":
            target.mkdir()
        else:
            assert action == "Verify" and target.is_dir()
        return target
    @staticmethod
    def create(case, path, directory):
        assert path.is_relative_to(case)
        if directory:
            path.mkdir()
            return None
        return path.open("x+b")
    def run_case(self, backend="local", name="listing", mutate=None, close_ok=True):
        factory = type("CaseBridge", (FakeLiveBridge if name == "cancellation" else FakeBridge,), dict(backend=backend, name=name, calls=[],
            mutate=staticmethod(mutate) if mutate else None, close_ok=close_ok))
        result = P.run_case(backend, name, self.suite, self.app, self.sha, RUNTIME, factory)
        return result, factory.calls
    def test_all_twenty_two_real_case_orchestrations_with_literal_outputs(self):
        counts = {"local": 10, "archive": 12}
        for backend in ("local", "archive"):
            ran = 0
            for name in P.E.CASE_ORDER[backend]:
                if name == "cancellation":
                    continue
                with self.subTest(backend=backend, name=name):
                    value, calls = self.run_case(backend, name)
                    self.assertEqual(value["status"], "passed", value)
                    self.assertEqual([call[0] for call in calls], ["ready", "start_source_observed", "finish", "close"])
                    expected = (2 if name == "corrupt_member" else 3 if backend == "archive" and
                        (name.startswith("acquisition_") or name == "mismatch") else 2 if
                        name.startswith("acquisition_") or name == "mismatch" else 1)
                    self.assertEqual(value["observation"]["runtime_launch_count"], expected)
                    self.assertEqual(list(self.suite.iterdir()), [])
                ran += 1
            self.assertEqual(ran, counts[backend])

    def test_fake_launch_environment_does_not_require_systemroot(self):
        with patch.dict(os.environ):
            os.environ.pop("SYSTEMROOT", None)
            for name in ("listing", "cancellation"):
                result, calls = self.run_case(name=name)
                self.assertEqual(result["status"], "passed", result)
                case = self.suite / ("fs-local-" + name)
                start = next(fields for action, fields in calls if action in {"start_source", "start_source_observed"})
                self.assertEqual(start["environment"], {"SYNTHETIC_CASE": str(case)})
                self.assertEqual(self.environment.call_args.args, (case,))
            self.assertEqual(self.environment.call_count, 2)
    def test_runtime_hash_count_helper_reference_and_legacy_mutations_fail(self):
        for key, replacement in (("launch_sha256", "c" * 64), ("runtime_launch_count", 0),
            ("peak_runtime_processes", 2), ("system_helper_reference_closed", False),
            ("system_helper_image_observed", False), ("runtime_image_observed", True),
            ("debug_handles_closed", False), ("forced_termination", True), ("app_exit_code", 1)):
            with self.subTest(key=key):
                self.suite = self.root / ("runtime-mutation-" + key)
                self.suite.mkdir()
                value, _ = self.run_case(mutate=lambda v, _p: v.update({key: replacement}))
                self.assertEqual(value["status"], "failed")
                self.assertFalse(value["checks"]["runtime_observed"] if key != "app_exit_code" else value["checks"]["exit_success"])
    def test_incorrect_acquired_bytes_and_hash_claims_do_not_pass(self):
        def change(_value, case):
            path = case / "output/synthetic-case/downloads/Synthetic/README-synthetic.txt"
            path.write_bytes(b"wrong bytes")
        value, _ = self.run_case(name="acquisition_readme", mutate=change)
        self.assertEqual(value["status"], "failed")
        self.assertFalse(value["checks"]["output_hashes_exact"])
    def test_missing_generic_nonzero_and_staging_cleanup_marker_do_not_pass(self):
        for error in ("some failure", "Source was not found or is not an individual file: Synthetic:missing-synthetic.txt; transfer staging cleanup failed: private"):
            def change(_value, case):
                path = next((case / "output/synthetic-case").glob("acquisition-*.json"))
                value = json.loads(path.read_text())
                value["results"][0]["error"] = error
                path.write_text(json.dumps(value))
            result, _ = self.run_case(name="missing", mutate=change)
            self.assertEqual(result["status"], "failed")
            self.assertFalse(result["checks"]["missing_failure_exact"])
    def test_source_changes_or_unexpected_top_level_output_retain_case(self):
        for target in ("source/README-synthetic.txt", "unexpected.private"):
            result, _ = self.run_case(mutate=lambda _v, case: (case / target).write_bytes(b"CANARY_PRIVATE"))
            self.assertEqual(result["status"], "failed")
            self.assertFalse(result["checks"]["temp_cleanup"])
            self.assertNotIn("CANARY_PRIVATE", json.dumps(result))
            shutil.rmtree(self.suite / "fs-local-listing")  # Test-owned synthetic state only.
    def test_unconfirmed_bridge_close_retains_source_and_does_not_claim_cleanup(self):
        value, _ = self.run_case(close_ok=False)
        self.assertFalse(value["checks"]["process_cleanup"])
        self.assertFalse(value["checks"]["fixture_cleanup"])
        self.assertFalse(value["checks"]["temp_cleanup"])
        self.assertTrue((self.suite / "fs-local-listing/source").is_dir())
    def test_attempted_constructor_failure_retains_case(self):
        value = P.run_case("local", "listing", self.suite, self.app, self.sha, RUNTIME,
                           lambda _case: (_ for _ in ()).throw(RuntimeError("PRIVATE")))
        self.assertEqual(value["status"], "failed")
        self.assertFalse(value["checks"]["process_cleanup"])
        self.assertFalse(value["checks"]["temp_cleanup"])
        self.assertNotIn("PRIVATE", json.dumps(value))

    def test_transport_exit_cannot_replace_every_helper_cleanup_proof(self):
        common = ("app_exited", "observed_children_exited", "job_zero_confirmed", "reader_joined", "conpty_closed")
        observed = ("debug_events_drained", "debug_pump_joined", "debug_handles_closed", "system_helper_reference_closed")
        for name, fields in (("listing", common + observed), ("cancellation", common)):
            for key in fields:
                with self.subTest(name=name, key=key):
                    self.suite = self.root / ("cleanup-flag-" + name + "-" + key)
                    self.suite.mkdir()
                    def mutate(value, _case):
                        value.update(ok=False, errors=["forced_termination"], forced_termination=True)
                        value[key] = False
                    with patch.object(P.H, "remove_owned") as remove:
                        result, calls = self.run_case(name=name, mutate=mutate)
                    self.assertEqual(result["status"], "failed")
                    for field in ("process_cleanup", "fixture_cleanup", "temp_cleanup"):
                        self.assertFalse(result["checks"][field], field)
                    self.assertEqual([action for action, _ in calls].count("close"), 1)
                    remove.assert_not_called()
                    self.assertTrue((self.suite / ("fs-local-" + name)).is_dir())

    def test_explicit_cleanup_uncertainty_cannot_be_cleared_by_all_true_flags(self):
        codes = ("termination_failed", "process_cleanup_failed", "input_cleanup_failed", "reader_cleanup_failed",
                 "console_cleanup_failed", "console_cleanup_timeout", "source_directory_cleanup_failed",
                 "debug_cleanup_failed", "source_directory_invalid")
        for code in codes:
            with self.subTest(code=code):
                self.suite = self.root / ("cleanup-code-" + code)
                self.suite.mkdir()
                with patch.object(P.H, "remove_owned") as remove:
                    value, calls = self.run_case(mutate=lambda v, _case: v.update(ok=False, errors=[code]))
                self.assertEqual(value["status"], "failed")
                self.assertFalse(value["checks"]["process_cleanup"])
                self.assertFalse(value["checks"]["fixture_cleanup"])
                self.assertFalse(value["checks"]["temp_cleanup"])
                self.assertEqual([action for action, _ in calls].count("close"), 1)
                remove.assert_not_called()
        # Live mode has no debug error category; each of its known uncertainty
        # codes still refuses cleanup, and the foreign category is also invalid.
        for code in codes:
            value = live_snapshot("finish", finished=True, cancelled=True)
            value.update(ok=False, errors=[code])
            with self.subTest(live_code=code), self.assertRaises(P.H.ProducerError):
                P.confirmed_helper_cleanup(value, "local", "cancellation", RUNTIME)

    def test_unknown_or_malformed_final_transport_snapshot_retains_tree(self):
        changes = (None, {"schema_version": 1, "action": "close_ready", "ok": True, "state": "finished"},
                   {"action": "unknown"}, {"private-canary": True}, {"reader_joined": 1},
                   {"app_exit_code": False}, {"schema_version": True})
        for name in ("listing", "cancellation"):
            for index, change in enumerate(changes):
                self.suite = self.root / ("bad-final-" + name + str(index))
                self.suite.mkdir()
                class Bridge(FakeLiveBridge if name == "cancellation" else FakeBridge):
                    calls = []
                    def close(self):
                        super().close()
                        if change is None or change.get("action") == "close_ready":
                            self.last = change
                        else:
                            self.last.update(change)
                        return True
                with patch.object(P.H, "remove_owned") as remove:
                    result = P.run_case("local", name, self.suite, self.app, self.sha, RUNTIME, Bridge)
                self.assertEqual(result["failure_code"], "cleanup_failed", (name, change, result))
                for field in ("process_cleanup", "fixture_cleanup", "temp_cleanup"):
                    self.assertFalse(result["checks"][field])
                remove.assert_not_called()
                self.assertEqual([action for action, _ in Bridge.calls].count("close"), 1)
                self.assertNotIn("private-canary", json.dumps(result))

    def test_forced_operation_failure_may_be_reaped_but_never_passes(self):
        for name in ("listing", "cancellation"):
            value, calls = self.run_case(name=name, mutate=lambda v, _case: v.update(
                ok=False, errors=["forced_termination"], forced_termination=True))
            self.assertEqual(value["status"], "failed")
            self.assertEqual(value["failure_code"], "session_failed")
            self.assertFalse(value["checks"]["orderly_exit"])
            self.assertTrue(value["checks"]["process_cleanup"])
            self.assertTrue(value["checks"]["fixture_cleanup"])
            self.assertTrue(value["checks"]["temp_cleanup"])
            self.assertEqual([action for action, _ in calls].count("close"), 1)

    def test_verify_failure_revokes_process_and_fixture_cleanup_before_removal(self):
        def prepare(parent, name, action="Create"):
            if action == "Verify":
                raise OSError("private verify error")
            return self.prepare(parent, name, action)
        output = io.StringIO()
        with patch.object(P.H, "prepare", side_effect=prepare), patch.object(P.H, "remove_owned") as remove, redirect_stdout(output):
            value, _ = self.run_case()
        self.assertEqual(value["failure_code"], "cleanup_failed")
        self.assertFalse(value["checks"]["process_cleanup"])
        self.assertFalse(value["checks"]["fixture_cleanup"])
        remove.assert_not_called()
        self.assertEqual(json.loads(output.getvalue().split("=", 1)[1]), dict(
            backend="local", case="listing", phase="cleanup", stage="verify", code="cleanup_failed"))
    def test_source_creation_rejects_unknown_escape_and_existing_paths(self):
        for member in ("../other", "source/../outside", "source/unexpected.txt", "C:/outside"):
            with self.assertRaises(P.H.ProducerError):
                P.source_member(self.suite, member, b"no")
        P.source_member(self.suite, "source")
        with self.assertRaises(FileExistsError):
            P.source_member(self.suite, "source")
    def test_listing_missing_unicode_duplicate_or_unexpected_row_fails(self):
        for kind in ("missing", "duplicate", "wrong_remote", "mtime"):
            def change(_value, case):
                path = case / "output/synthetic-case/listings/inventory.csv"
                rows = list(csv.reader(io.StringIO(path.read_text(encoding="utf-8-sig"))))
                if kind == "missing":
                    rows = [row for row in rows if "nested/caf\u00e9-\u96ea.txt" not in row]
                elif kind == "duplicate":
                    rows.append(rows[1])
                elif kind == "wrong_remote":
                    rows[1][1] = "Other"
                else:
                    # Native NTFS precision matters: a 100ns drift is not equal.
                    nanos = int(rows[1][4][20:29])
                    rows[1][4] = rows[1][4][:20] + f"{(nanos + 100) % 1000000000:09d}" + "+00:00"
                out = io.StringIO(newline="")
                csv.writer(out).writerows(rows)
                path.write_bytes(b"\xef\xbb\xbf" + out.getvalue().encode())
            value, _ = self.run_case(mutate=change)
            self.assertFalse(value["checks"]["inventory_exact"])
            self.assertEqual(value["status"], "failed")
    def test_listing_directory_size_matches_native_local_and_unknown_archive_size(self):
        for backend in ("local", "archive"):
            def inspect(_value, case):
                path = case / "output/synthetic-case/listings/inventory.csv"
                rows = list(csv.DictReader(io.StringIO(path.read_text(encoding="utf-8-sig"))))
                directories = {row["path"]: row["size"] for row in rows if row["is_dir"] == "true"}
                self.assertEqual(set(directories), {"empty-dir", "large", "nested"})
                for member, size in directories.items():
                    expected = str((case / "source" / member).stat().st_size) if backend == "local" else ""
                    self.assertEqual(size, expected)
            value, _ = self.run_case(backend=backend, mutate=inspect)
            self.assertEqual(value["status"], "passed", value)
            self.assertTrue(value["checks"]["inventory_exact"])
            self.assertTrue(value["checks"]["source_preserved"])

    def test_listing_rejects_blank_malformed_and_wrong_local_directory_sizes(self):
        for backend, replacement in (("local", ""), ("local", "-1"), ("local", "00"),
            ("local", "+0"), ("local", "0.0"), ("local", "wrong"), ("local", None), ("archive", "0")):
            with self.subTest(backend=backend, replacement=replacement):
                def change(_value, case):
                    path = case / "output/synthetic-case/listings/inventory.csv"
                    rows = list(csv.reader(io.StringIO(path.read_text(encoding="utf-8-sig"))))
                    row = next(row for row in rows[1:] if row[2] == "empty-dir")
                    row[3] = replacement if replacement is not None else str((case / "source/empty-dir").stat().st_size + 1)
                    out = io.StringIO(newline="")
                    csv.writer(out).writerows(rows)
                    path.write_bytes(b"\xef\xbb\xbf" + out.getvalue().encode())
                value, _ = self.run_case(backend=backend, mutate=change)
                self.assertEqual(value["failure_code"], "listing_invalid", value)
                self.assertFalse(value["checks"]["inventory_exact"])
                self.assertFalse(value["checks"]["listing_complete"])
                self.assertTrue(value["checks"]["source_preserved"])
                self.assertTrue(value["checks"]["temp_cleanup"])

    def test_changed_local_directory_size_or_identity_cannot_supply_listing_expectation(self):
        original = P.H.plain
        for field in ("st_size", "st_ino"):
            with self.subTest(field=field):
                changed = False
                def metadata(path, *args, **kwargs):
                    info = original(path, *args, **kwargs)
                    if changed and Path(path) == self.suite / "fs-local-listing/source/empty-dir":
                        fields = {key: getattr(info, key) for key in dir(info) if key.startswith("st_")}
                        fields[field] += 1
                        return types.SimpleNamespace(**fields)
                    return info
                def change(_value, _case):
                    nonlocal changed
                    changed = True
                with patch.object(P.H, "plain", side_effect=metadata):
                    value, _ = self.run_case(mutate=change)
                self.assertEqual(value["failure_code"], "preservation_failed", value)
                self.assertFalse(value["checks"]["source_preserved"])
                self.assertFalse(value["checks"]["temp_cleanup"])
                self.assertTrue((self.suite / "fs-local-listing/source").is_dir())
                shutil.rmtree(self.suite / "fs-local-listing")  # Only the test-owned retained fixture.
    def test_full_run_requires_both_live_cancellations_and_keeps_other_claims_false(self):
        bindings = {key: "d" * 64 for key in P.E.A.BINDING_KEYS}
        bindings.update(application_sha256=self.sha, build_commit="e" * 40, build_target="x86_64-pc-windows-msvc", build_profile="release")
        def invoke(backend, name, suite, app, sha, runtime):
            factory = type("CaseBridge", (FakeLiveBridge if name == "cancellation" else FakeBridge,), dict(backend=backend, name=name, calls=[]))
            return P.run_case(backend, name, suite, app, sha, runtime, factory)
        real = P.run_case
        def dispatch(*args):
            with patch.object(P, "run_case", real):
                return invoke(*args)
        with patch.dict(os.environ, RUNNER_TEMP=str(self.root), GITHUB_SHA="e" * 40), \
             patch.object(P, "loaded_sources_preserved"), patch.object(P.E, "compute_bindings", return_value=bindings), \
             patch.object(P.H, "runtime_pins", return_value=RUNTIME), patch.object(P, "run_case", side_effect=dispatch):
            for backend in ("local", "archive"):
                result = P.run(backend, self.app, self.sha, "e" * 40)
                self.assertEqual(result["result"], "passed", result)
                self.assertEqual(result["cases"]["cancellation"]["status"], "passed")
                self.assertEqual(result["capabilities"]["cancellation"], "passed")
                self.assertTrue(result["claims"]["cancellation_verified"])
                self.assertTrue(all(value is False for name, value in result["claims"].items() if name != "cancellation_verified"))
                self.assertTrue(result["cleanup_complete"])
    def test_failure_stops_later_cases_and_retained_tree_blocks_global_cleanup(self):
        bindings = {key: "d" * 64 for key in P.E.A.BINDING_KEYS}
        bindings.update(application_sha256=self.sha, build_commit="e" * 40, build_target="x86_64-pc-windows-msvc", build_profile="release")
        calls = []
        def fail_case(backend, name, suite, *_args):
            calls.append(name)
            (suite / "retained").mkdir()
            row = P.E.empty_cases(backend)[name]
            row.update(status="failed", failure_code="cleanup_failed",
                       checks=dict.fromkeys(P.E.CASE_CHECKS[backend][name], False))
            return row
        with patch.dict(os.environ, RUNNER_TEMP=str(self.root), GITHUB_SHA="e" * 40), \
             patch.object(P, "loaded_sources_preserved"), patch.object(P.E, "compute_bindings", return_value=bindings), \
             patch.object(P.H, "runtime_pins", return_value=RUNTIME), patch.object(P, "run_case", side_effect=fail_case):
            value = P.run("local", self.app, self.sha, "e" * 40)
        self.assertEqual(calls, ["listing"])
        self.assertEqual(value["result"], "failed")
        self.assertFalse(value["cleanup_complete"])
        self.assertTrue(all(row["status"] == "not_run" for name, row in value["cases"].items() if name != "listing"))
        self.assertTrue(all(item == "unverified" for item in value["capabilities"].values()))
        self.assertEqual(len(list(self.root.glob("app-filesystem-*/retained"))), 1)
    def test_setup_namespace_is_finite(self):
        self.assertEqual(P.H.setup_scope("app-filesystem-" + "a" * 32), "filesystem_suite")
        for backend, names in P.E.CASE_ORDER.items():
            for name in names:
                label = "fs-" + backend + "-" + name.replace("_", "-")
                self.assertEqual(P.H.setup_scope(label), label)
        for label in ("fs-local-corrupt-member", "fs-archive-future", "app-filesystem-" + "A" * 32, "../fs-local-listing"):
            with self.assertRaises(P.H.ProducerError):
                P.H.setup_scope(label)
    def test_hosted_guard_precedes_run_effects_and_report_creation(self):
        with patch.object(P.H, "hosted_guard", side_effect=P.H.ProducerError("hosted_only")), \
             patch.object(P.E, "compute_bindings", side_effect=AssertionError("binding_effect")):
            with self.assertRaises(P.H.ProducerError):
                P.run("local", self.app, self.sha, "e" * 40)
            report = self.root / "never.json"
            self.assertEqual(P.main(["--backend", "local", "--application", str(self.app), "--application-sha256", self.sha,
                "--build-commit", "e" * 40, "--report", str(report)]), 1)
            self.assertFalse(report.exists())

    def test_cancellation_uses_live_runtime_twice_then_ctrl_c_and_exact_cancelled_outputs(self):
        for backend in ("local", "archive"):
            value, calls = self.run_case(backend, "cancellation")
            self.assertEqual(value["status"], "passed", value)
            self.assertEqual(value["observation"], dict(kind="live_image", runtime_process_count=1,
                first_verified_bytes=65536, last_verified_bytes=131072))
            self.assertEqual([name for name, _ in calls], ["ready", "start_source", "poll", "observe_runtime",
                "poll", "poll", "observe_runtime", "poll", "ctrl_c", "poll", "finish", "close"])
            self.assertTrue(all(value["checks"].values()))
            self.assertEqual(list(self.suite.iterdir()), [])

    def partial(self, body, suffix="payload.1234abcd.partial"):
        path = self.suite / ("output/synthetic-case/downloads/Synthetic/large/" +
            ".triage-transfer-" + "a" * 32) / suffix
        write(path, body)
        return path

    def test_content_witness_requires_advancing_bytes_despite_full_preallocation(self):
        path = self.partial(b"\0" * 2097152)
        witness = P.cancellation_witness(self.suite, P.H.identity(self.suite))
        self.addCleanup(witness.close)
        self.assertEqual(witness.sample(), 0)
        with path.open("r+b") as stream:
            stream.write(BODY["large/cancel.bin"][:65536])
        self.assertEqual(witness.sample(), 65536)
        self.assertEqual(witness.sample(), 65536)  # A static prefix is not a second extent.
        with path.open("r+b") as stream:
            stream.seek(65536)
            stream.write(BODY["large/cancel.bin"][65536:98304])
        self.assertEqual(witness.sample(), 65536)  # Half the next block is still incomplete.
        with path.open("r+b") as stream:
            stream.seek(65536)
            stream.write(BODY["large/cancel.bin"][65536:131072])
        self.assertEqual(witness.sample(), 131072)
        self.assertEqual(path.stat().st_size, 2097152)  # Length never changed.

    def test_completed_too_advanced_or_wrong_content_never_qualifies_progress(self):
        path = self.partial(BODY["large/cancel.bin"])
        witness = P.cancellation_witness(self.suite, P.H.identity(self.suite))
        self.addCleanup(witness.close)
        with self.assertRaisesRegex(P.H.ProducerError, "^cancellation_failed$"):
            witness.sample()
        with path.open("r+b") as stream:
            stream.write(b"x" * 2097152)
        self.assertEqual(witness.sample(), 0)
        with path.open("r+b") as stream:
            stream.write(BODY["large/cancel.bin"][:1048576])
        self.assertEqual(witness.sample(), 1048576)
        with path.open("r+b") as stream:
            stream.seek(1048576)
            stream.write(BODY["large/cancel.bin"][1048576:1114112])
        with self.assertRaisesRegex(P.H.ProducerError, "^cancellation_failed$"):
            witness.sample()

    def test_completed_file_short_raw_reads_cannot_mimic_content_progress(self):
        self.partial(BODY["large/cancel.bin"])
        witness = P.cancellation_witness(self.suite, P.H.identity(self.suite))
        self.addCleanup(witness.close)
        original = witness.stream
        class ShortReader:
            def __init__(self):
                self.lengths = iter((65536, 131072, 1114112))
            def fileno(self):
                return original.fileno()
            def seek(self, offset):
                return original.seek(offset)
            def read(self, _limit):
                return original.read(next(self.lengths))
            def close(self):
                original.close()
        witness.stream = ShortReader()
        for _ in range(2):
            self.assertIsNone(witness.sample())
        with self.assertRaisesRegex(P.H.ProducerError, "^cancellation_failed$"):
            witness.sample()  # A complete bounded read proves it has no headroom.

    def test_growth_between_read_and_extent_check_is_pending_then_requires_stable_content(self):
        path = self.partial(BODY["large/cancel.bin"][:65536])
        witness = P.cancellation_witness(self.suite, P.H.identity(self.suite))
        self.addCleanup(witness.close)
        original = witness.stream
        class GrowingReader:
            def fileno(self):
                return original.fileno()
            def seek(self, offset):
                return original.seek(offset)
            def read(self, limit):
                data = original.read(limit)
                with path.open("ab") as writer:
                    writer.write(BODY["large/cancel.bin"][65536:131072])
                return data
            def close(self):
                original.close()
        witness.stream = GrowingReader()
        self.assertIsNone(witness.sample())
        witness.stream = original
        self.assertEqual(witness.sample(), 131072)

    def test_pending_samples_preserve_first_proof_and_never_reset_deadline(self):
        for permanent in (False, True):
            clock, calls, stages = [0.0], [], {}
            class Witness:
                values = iter((65536, None, 131072))
                closed = 0
                def sample(self):
                    return None if permanent else next(self.values)
                def close(self):
                    self.closed += 1
            class Bridge:
                def command(self, action, **_fields):
                    calls.append(action)
                    return live_snapshot(action, cancelled=action == "ctrl_c")
            witness = Witness()
            def advance(_delay):
                clock[0] += 1.0
            with patch.object(P, "cancellation_witness", return_value=witness), \
                 patch.object(P.time, "monotonic", side_effect=lambda: clock[0]), \
                 patch.object(P.time, "sleep", side_effect=advance):
                if permanent:
                    with self.assertRaisesRegex(P.H.ProducerError, "^deadline_exceeded$"):
                        P.cancel_active_transfer(Bridge(), self.suite, (1, 2), RUNTIME, 3.0, progress=stages)
                    self.assertEqual(clock[0], 3.0)
                    self.assertEqual(calls.count("observe_runtime"), 1)
                    self.assertNotIn("ctrl_c", calls)
                    self.assertEqual(stages, {"operation": "content_poll"})
                else:
                    observation, _ = P.cancel_active_transfer(Bridge(), self.suite, (1, 2), RUNTIME, 3.0)
                    self.assertEqual(observation, dict(kind="live_image", runtime_process_count=1,
                        first_verified_bytes=65536, last_verified_bytes=131072))
                    self.assertEqual(calls.count("observe_runtime"), 2)
                    self.assertEqual(calls.count("ctrl_c"), 1)
            self.assertEqual(witness.closed, 1)

    def test_failure_diagnostics_preserve_original_stage_before_forced_cleanup(self):
        output = io.StringIO()
        boundaries = []
        class Bridge(FakeLiveBridge):
            calls = []
            def close(self):
                boundaries.append(output.getvalue())
                return super().close()
        roots = P.H.application_roots_empty
        root_calls = []
        def check_roots(*args):
            root_calls.append(1)
            if len(root_calls) > 1:
                raise OSError("PRIVATE_CLEANUP_CANARY")
            return roots(*args)
        with patch.object(P.ContentWitness, "sample", side_effect=P.H.ProducerError("cancellation_failed")), \
             patch.object(P.H, "application_roots_empty", side_effect=check_roots), redirect_stdout(output):
            value = P.run_case("archive", "cancellation", self.suite, self.app, self.sha, RUNTIME,
                              type("ArchiveBridge", (Bridge,), {"backend": "archive"}))
        prefix = "application_filesystem_case_failure="
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(all(line.startswith(prefix) and len(line.encode("ascii")) + 1 <= 1024 for line in lines))
        records = [json.loads(line[len(prefix):]) for line in lines]
        self.assertEqual(records, [dict(backend="archive", case="cancellation", phase="operation",
            stage="content_sample", code="cancellation_failed"), dict(backend="archive", case="cancellation",
            phase="cleanup", stage="application_roots", code="cleanup_failed")])
        self.assertEqual(boundaries, [lines[0] + "\n"])
        self.assertEqual(value["failure_code"], "cancellation_failed")
        self.assertTrue(value["checks"]["process_cleanup"])
        self.assertFalse(value["checks"]["temp_cleanup"])
        self.assertEqual([action for action, _ in Bridge.calls].count("close"), 1)
        self.assertNotIn("PRIVATE_CLEANUP_CANARY", output.getvalue() + json.dumps(value))

    def test_diagnostic_printer_failure_or_private_exception_never_replaces_primary(self):
        for broken_print in (False, True):
            self.suite = self.root / ("diagnostic-failure-" + str(broken_print))
            self.suite.mkdir()
            output = io.StringIO()
            with ExitStack() as stack:
                stack.enter_context(redirect_stdout(output))
                stack.enter_context(patch.object(P.ContentWitness, "sample", side_effect=ValueError("PRIVATE_EXCEPTION_CANARY")))
                if broken_print:
                    stack.enter_context(patch("builtins.print", side_effect=OSError("PRIVATE_PRINTER_CANARY")))
                value, calls = self.run_case(name="cancellation")
            self.assertEqual(value["failure_code"], "unexpected_failure")
            self.assertEqual([action for action, _ in calls].count("close"), 1)
            self.assertNotIn("PRIVATE_", output.getvalue() + json.dumps(value))
            if broken_print:
                self.assertEqual(output.getvalue(), "")
            else:
                first = json.loads(output.getvalue().splitlines()[0].split("=", 1)[1])
                self.assertEqual(first, dict(backend="local", case="cancellation", phase="operation",
                    stage="content_sample", code="unexpected_failure"))

    def test_diagnostic_rejects_forged_fields_and_success_emits_nothing(self):
        class PrivateValue:
            def __str__(self):
                raise AssertionError("private value must never be stringified")
        valid = ("local", "cancellation", "operation", "content_sample", "cancellation_failed")
        output = io.StringIO()
        with redirect_stdout(output):
            for index in range(5):
                for forged in ("PRIVATE_FIELD_CANARY", PrivateValue()):
                    values = list(valid)
                    values[index] = forged
                    P.failure_diagnostic(*values)
            result, _ = self.run_case(name="cancellation")
        self.assertEqual(result["status"], "passed")
        self.assertEqual(output.getvalue(), "")

    def test_every_late_cancellation_boundary_fails_before_credit(self):
        for phase in ("first_observe", "first_sample", "last_sample", "second_observe", "close", "final_poll", "ctrl_c"):
            clock, calls = [0.0], []
            class Witness:
                samples, closed = 0, False
                def sample(self):
                    self.samples += 1
                    if phase == ("first_sample" if self.samples == 1 else "last_sample"):
                        clock[0] = 151.0
                    return 65536 * self.samples
                def close(self):
                    self.closed = True
                    if phase == "close":
                        clock[0] = 151.0
            class Bridge:
                polls, observed = 0, 0
                def command(self, action, **_fields):
                    calls.append(action)
                    if action == "poll":
                        self.polls += 1
                        if self.polls == 4 and phase == "final_poll":
                            clock[0] = 151.0
                    if action == "observe_runtime":
                        self.observed += 1
                        if phase == ("first_observe" if self.observed == 1 else "second_observe"):
                            clock[0] = 151.0
                    if action == "ctrl_c" and phase == "ctrl_c":
                        clock[0] = 151.0
                    return live_snapshot(action, finished=action == "ctrl_c", cancelled=action == "ctrl_c")
            witness = Witness()
            with patch.object(P, "cancellation_witness", return_value=witness), \
                 patch.object(P.time, "monotonic", side_effect=lambda: clock[0]):
                with self.assertRaisesRegex(P.H.ProducerError, "^deadline_exceeded$"):
                    P.cancel_active_transfer(Bridge(), self.suite, (1, 2), RUNTIME, 150.0)
            self.assertTrue(witness.closed, phase)
            self.assertEqual("ctrl_c" in calls, phase == "ctrl_c", phase)

    def test_witness_close_uncertainty_retains_case_even_after_confirmed_process_reap(self):
        native_open = Path.open
        for construction_failure in (False, True):
            self.suite = self.root / ("close-uncertain-" + str(construction_failure))
            self.suite.mkdir()
            closes = []
            class FaultyClose:
                def __init__(self, stream):
                    self.stream = stream
                def fileno(self):
                    return self.stream.fileno()
                def seek(self, offset):
                    return self.stream.seek(offset)
                def read(self, maximum):
                    return self.stream.read(maximum)
                def close(self):
                    closes.append(1)
                    self.stream.close()
                    raise OSError("private close uncertainty")
            def opening(path, *args, **kwargs):
                stream = native_open(path, *args, **kwargs)
                return FaultyClose(stream) if path.name == "payload.1234abcd.partial" and args == ("rb",) else stream
            with patch.object(Path, "open", new=opening), ExitStack() as stack:
                if construction_failure:
                    stack.enter_context(patch.object(P.ContentWitness, "verify", side_effect=P.H.ProducerError("preservation_failed")))
                value, calls = self.run_case(name="cancellation")
            self.assertEqual(value["status"], "failed")
            self.assertEqual(value["failure_code"], "preservation_failed" if construction_failure else "cleanup_failed")
            self.assertEqual(len(closes), 1)  # No explicit retry after uncertain close.
            self.assertTrue(value["checks"]["process_cleanup"])
            self.assertFalse(value["checks"]["fixture_cleanup"])
            self.assertFalse(value["checks"]["temp_cleanup"])
            self.assertNotIn("ctrl_c", [name for name, _ in calls])
            self.assertTrue((self.suite / "fs-local-cancellation").is_dir())
            self.assertNotIn("private close uncertainty", json.dumps(value))

    def test_staged_identity_and_closed_namespace_are_required_on_every_read(self):
        path = self.partial(BODY["large/cancel.bin"][:65536])
        witness = P.cancellation_witness(self.suite, P.H.identity(self.suite))
        self.addCleanup(witness.close)
        original = P.H.identity
        for changed in (self.suite / "output", self.suite / "output/synthetic-case", path.parent):
            with patch.object(P.H, "identity", side_effect=lambda target: (0, 0) if target == changed else original(target)):
                with self.assertRaisesRegex(P.H.ProducerError, "^preservation_failed$"):
                    witness.sample()
        native_stat = os.fstat
        with patch.object(os, "fstat", side_effect=lambda fd: types.SimpleNamespace(
                **{key: getattr(native_stat(fd), key) for key in ("st_mode", "st_nlink", "st_size", "st_dev")}, st_ino=-1)):
            with self.assertRaisesRegex(P.H.ProducerError, "^preservation_failed$"):
                witness.sample()
        witness.close()
        write(path.parent / "unexpected.private", b"private-canary")
        with self.assertRaisesRegex(P.H.ProducerError, "^cancellation_failed$"):
            P.cancellation_witness(self.suite, P.H.identity(self.suite))

    def test_static_content_or_finished_app_cannot_reach_ctrl_c(self):
        factory = type("StaticBridge", (FakeLiveBridge,), dict(calls=[], progress="static"))
        value = P.run_case("local", "cancellation", self.suite, self.app, self.sha, RUNTIME, factory)
        self.assertEqual(value["status"], "failed")
        self.assertFalse(value["checks"]["content_progress_exact"])
        self.assertNotIn("ctrl_c", [name for name, _ in factory.calls])

    def test_live_hash_observation_before_and_after_witness_and_real_ctrl_c_are_required(self):
        for index, gate in enumerate(("first_hash", "second_hash", "runtime_count", "before_ctrl_c", "ctrl_c")):
            self.suite = self.root / ("live-failure-" + str(index))
            self.suite.mkdir()
            observations = []
            def mutate(value, _polls):
                if value["action"] == "observe_runtime":
                    observations.append(1)
                    if gate == "first_hash" and len(observations) == 1 or gate == "second_hash" and len(observations) == 2:
                        value["runtime_sha256"] = "c" * 64
                    if gate == "runtime_count":
                        value["runtime_process_count"] = 2
                if gate == "ctrl_c" and value["action"] == "ctrl_c":
                    value["ctrl_c_sent"] = False
                if gate == "before_ctrl_c" and value["action"] == "poll" and _polls == 4:
                    value.update(state="finished", app_exited=True, app_exit_code=0)
            factory = type("BadLiveBridge", (FakeLiveBridge,), dict(calls=[], change_response=staticmethod(mutate)))
            value = P.run_case("local", "cancellation", self.suite, self.app, self.sha, RUNTIME, factory)
            self.assertEqual(value["status"], "failed", gate)
            self.assertFalse(value["checks"]["transfer_active"], gate)
            if gate != "ctrl_c":
                self.assertNotIn("ctrl_c", [name for name, _ in factory.calls])

    def test_cancelled_manifest_and_cleanup_cannot_be_substituted_by_generic_failure(self):
        for index, mutation in enumerate(("integrity", "hash", "cleanup_marker", "residue", "forced", "zero_exit", "reader")):
            self.suite = self.root / ("cancel-final-" + str(index))
            self.suite.mkdir()
            def mutate(value, case):
                if mutation in {"forced", "zero_exit", "reader"}:
                    key, change = {"forced": ("forced_termination", True), "zero_exit": ("app_exit_code", 0),
                                   "reader": ("reader_joined", False)}[mutation]
                    value[key] = change
                elif mutation == "residue":
                    write(case / "output/synthetic-case/downloads/Synthetic/large/unexpected.partial", b"x")
                else:
                    path = next((case / "output/synthetic-case").glob("acquisition-*.json"))
                    manifest = json.loads(path.read_text())
                    result = manifest["results"][0]
                    if mutation == "integrity":
                        result["integrity"] = "Failed"
                    elif mutation == "hash":
                        result["local_sha256"] = "a" * 64
                    else:
                        result["error"] += "; transfer staging cleanup failed: private-canary"
                    path.write_text(json.dumps(manifest))
            value, _ = self.run_case(name="cancellation", mutate=mutate)
            self.assertEqual(value["status"], "failed", mutation)
            self.assertNotIn("private-canary", json.dumps(value))


if __name__ == "__main__":
    unittest.main()
