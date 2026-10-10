"""Adversarial receipt mutations only; never run native applications."""
from copy import deepcopy
from contextlib import redirect_stdout
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "filesystem_application_evidence.py"
E = types.ModuleType("filesystem_evidence_tested")
E.__file__ = str(SOURCE)
with patch.object(subprocess, "Popen", side_effect=AssertionError("no process")), \
        patch.object(socket, "socket", side_effect=AssertionError("no listener")):
    exec(compile(SOURCE.read_bytes(), str(SOURCE), "exec"), E.__dict__)
NOW = datetime(2026, 10, 10, tzinfo=timezone.utc)
RUNTIME = dict(version="1.75.2", sha256="a" * 64, platform="windows")
BINDINGS = dict(application_sha256="b" * 64, application_source_sha256="c" * 64,
    build_commit="d" * 40, build_target="x86_64-pc-windows-msvc", build_profile="release",
    cargo_lock_sha256="e" * 64, runtime_manifest_sha256="f" * 64,
    harness_sha256="1" * 64, fixture_manifest_sha256="2" * 64)


def receipt(backend="local", complete=False):
    cases = E.empty_cases(backend)
    for name, case in cases.items():
        if name == "cancellation":
            continue
        count = E.EXPECTED_LAUNCHES[backend][name]
        case.update(status="passed", exit_code=0 if name == "listing" or name in E.ACQUISITIONS else 1,
            runtime_sha256=RUNTIME["sha256"], checks={key: True for key in case["checks"]},
            observation=dict(kind="launch_image", runtime_launch_count=count, peak_runtime_processes=1,
                debug_event_count=3 * (1 + 2 * count), system_helper_launch_count=count,
                peak_system_helper_processes=1, system_helper_sha256="3" * 64))
    if complete:
        case = cases["cancellation"]
        case.update(status="passed", exit_code=1, runtime_sha256=RUNTIME["sha256"],
            checks={key: True for key in case["checks"]},
            observation=dict(kind="live_image", runtime_process_count=1,
                first_verified_bytes=65536, last_verified_bytes=131072))
    return dict(schema_version=2, scope=E.SCOPE, fixture_mode=E.MODE[backend], backend=backend,
        platform="windows", created_at="2026-10-10T00:00:00Z", runtime=dict(RUNTIME), bindings=dict(BINDINGS),
        cases=cases, capabilities=E.derive_capabilities(backend, cases, True), result="passed" if complete else "partial",
        cleanup_complete=True, errors=[], claims={**dict.fromkeys(E.FALSE_CLAIMS, False), "cancellation_verified": complete})


class FilesystemEvidenceTests(unittest.TestCase):
    def check(self, value, **kwargs):
        return E.validate_receipt(value, RUNTIME, BINDINGS, now=NOW, **kwargs)

    def reject(self, value, **kwargs):
        with self.assertRaises(E.ApplicationEvidenceError):
            self.check(value, **kwargs)

    def test_short_operations_never_complete_cancellation_or_provider(self):
        for backend in ("local", "archive"):
            value = receipt(backend)
            self.assertIs(self.check(value), value)
            self.assertEqual(value["capabilities"]["cancellation"], "unverified")
            self.assertEqual(value["cases"]["cancellation"]["status"], "not_run")
            value["result"] = "passed"
            self.reject(value)
        for key in E.FALSE_CLAIMS:
            value = receipt()
            value["claims"][key] = True
            self.reject(value)
            value["claims"][key] = 0
            self.reject(value)

    def test_cancelled_record_cannot_be_forged_from_a_short_operation(self):
        value = receipt()
        case = value["cases"]["cancellation"]
        case.update(status="passed", exit_code=1, runtime_sha256=RUNTIME["sha256"],
            observation=deepcopy(value["cases"]["mismatch"]["observation"]),
            checks={key: True for key in case["checks"]})
        self.reject(value)

    def test_disjoint_live_observation_qualifies_only_complete_cancelled_case(self):
        for backend in ("local", "archive"):
            value = receipt(backend, complete=True)
            self.assertIs(self.check(value), value)
            self.assertTrue(value["claims"]["cancellation_verified"])
            self.assertEqual(value["capabilities"]["cancellation"], "passed")
            self.assertTrue(all(value["claims"][key] is False for key in E.FALSE_CLAIMS))
            value["cases"]["cancellation"]["checks"]["content_progress_exact"] = False
            self.reject(value)
        value = receipt()
        value["claims"]["cancellation_verified"] = True
        self.reject(value)

    def test_cancelled_content_progress_has_exact_bounds_and_real_advancement(self):
        for key, changes in (("first_verified_bytes", (0, True, 65537, 131072)),
                             ("last_verified_bytes", (65536, True, 131073, 1114112)),
                             ("runtime_process_count", (0, True, 2)),
                             ("kind", ("launch_image", "time_limit"))):
            for changed in changes:
                with self.subTest(key=key, changed=changed):
                    value = receipt(complete=True)
                    value["cases"]["cancellation"]["observation"][key] = changed
                    self.reject(value)
        for key in E.LIVE_OBSERVATION_KEYS:
            value = receipt(complete=True)
            del value["cases"]["cancellation"]["observation"][key]
            self.reject(value)

    def test_cancellation_credit_requires_cleanup_and_new_contract_version(self):
        value = receipt(complete=True)
        value.update(result="failed", cleanup_complete=False, errors=["cleanup_failed"])
        value["capabilities"] = E.derive_capabilities("local", value["cases"], False)
        self.reject(value)
        value["claims"]["cancellation_verified"] = False
        self.assertIs(self.check(value), value)
        for schema in (1, True, 3):
            value = receipt(complete=True)
            value["schema_version"] = schema
            self.reject(value)

    def test_each_case_and_check_is_required_and_strictly_boolean(self):
        for backend in ("local", "archive"):
            original = receipt(backend)
            for name, case in original["cases"].items():
                value = deepcopy(original)
                del value["cases"][name]
                self.reject(value)
                for key in case["checks"]:
                    with self.subTest(backend=backend, case=name, check=key):
                        for mutation in ("remove", "integer", "false"):
                            value = deepcopy(original)
                            checks = value["cases"][name]["checks"]
                            if mutation == "remove":
                                del checks[key]
                            else:
                                checks[key] = 1 if mutation == "integer" else False
                            self.reject(value)

    def test_every_external_binding_matters(self):
        for key in BINDINGS:
            value = receipt()
            value["bindings"][key] = "0" * 64 if key.endswith("_sha256") else "different"
            self.reject(value)
        for field, replacement in (("version", "1.75.1"), ("sha256", "0" * 64), ("platform", "linux")):
            value = receipt()
            value["runtime"][field] = replacement
            self.reject(value)

    def test_observation_cannot_be_replaced_by_claimed_digest(self):
        for change in (None, {}, {"kind": "live_image"}):
            value = receipt()
            value["cases"]["listing"]["observation"] = change
            self.reject(value)
        for change in (None, "0" * 64, True, []):
            value = receipt()
            value["cases"]["listing"]["runtime_sha256"] = change
            self.reject(value)

    def test_launch_and_helper_bounds_are_independent(self):
        mutations = {"runtime_launch_count": (0, 1, 3, True), "peak_runtime_processes": (0, 2, True),
            "debug_event_count": (0, 4097, True), "system_helper_launch_count": (0, 3, True),
            "peak_system_helper_processes": (0, 3, True), "system_helper_sha256": (None, "private-canary"),
            "kind": ("live_image", "vendor")}
        for key, values in mutations.items():
            for changed in values:
                with self.subTest(key=key, changed=changed):
                    value = receipt()
                    value["cases"]["acquisition_binary"]["observation"][key] = changed
                    self.reject(value)
        value = receipt()
        value["cases"]["listing"]["observation"]["peak_system_helper_processes"] = 2
        self.reject(value)

    def test_each_created_process_requires_breakpoint_and_exit_events(self):
        value = receipt("archive")
        observation = value["cases"]["acquisition_binary"]["observation"]
        self.assertEqual(observation["debug_event_count"], 21)
        self.assertIs(self.check(value), value)
        observation["debug_event_count"] = 20
        self.reject(value)

    def test_no_unrun_or_cross_backend_credit(self):
        value = receipt()
        value["cases"]["acquisition_empty"] = E.empty_cases("local")["acquisition_empty"]
        self.reject(value)
        value["result"] = "failed"
        value["capabilities"] = E.derive_capabilities("local", value["cases"], True)
        self.assertIs(self.check(value), value)
        self.assertEqual(value["capabilities"]["download_hash"], "unverified")
        for backend, key in (("local", "archive_crc32"), ("local", "corrupt_member_rejection"),
                             ("local", "truncated_archive_rejection"), ("archive", "cancellation")):
            value = receipt(backend)
            value["capabilities"][key] = "passed"
            self.reject(value)

    def test_cleanup_failure_removes_all_earned_capabilities(self):
        value = receipt()
        value["cleanup_complete"] = False
        self.reject(value)
        value.update(result="failed", errors=["cleanup_failed"])
        value["capabilities"] = E.derive_capabilities("local", value["cases"], False)
        self.assertIs(self.check(value), value)
        self.assertTrue(all(status == "unverified" for status in value["capabilities"].values()))

    def test_failure_and_exit_semantics_are_not_success_inflation(self):
        for case_name in ("listing", "acquisition_empty", "missing", "directory_as_file", "mismatch"):
            value = receipt()
            value["cases"][case_name]["exit_code"] = 1 if case_name in ("listing", "acquisition_empty") else 0
            self.reject(value)
        value = receipt()
        case = value["cases"]["missing"]
        case.update(status="failed", failure_code="outputs_invalid")
        case["checks"]["no_download_outputs"] = False
        value.update(result="failed", errors=["outputs_invalid"])
        value["capabilities"] = E.derive_capabilities("local", value["cases"], True)
        self.assertIs(self.check(value), value)

    def test_receipt_cannot_carry_private_or_unknown_data(self):
        for position in ("top", "case", "observation", "claims", "capabilities"):
            value = receipt()
            target = value if position == "top" else value["cases"]["listing"] if position == "case" else \
                value["cases"]["listing"]["observation"] if position == "observation" else value[position]
            target["account"] = "private-canary"
            self.reject(value)
        value = receipt()
        value["errors"] = ["private-canary"]
        self.reject(value)

    def test_stale_future_and_bool_freshness_rejected(self):
        for stamp in ("2026-10-08T00:00:00Z", "2026-10-11T00:00:00Z", "2026-02-30T00:00:00Z", "private"):
            value = receipt()
            value["created_at"] = stamp
            self.reject(value)
        for limit in (True, 0, 25, float("nan"), float("inf")):
            self.reject(receipt(), max_age_hours=limit)

    def test_fixture_identity_and_harness_include_the_actual_path(self):
        fixture = E.fixture_manifest()
        self.assertEqual(len(fixture["files"]), 6)
        self.assertEqual({row["variant"] for row in fixture["archives"]}, {"valid", "corrupt_member", "truncated"})
        self.assertEqual(next(row["sha256"] for row in fixture["files"] if row["path"] == "empty.bin"),
                         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        for name in ("filesystem_controller.py", "hosted_session.ps1", "HostedConPtySession.cs",
                     "prepare_case.ps1", "fixture_filesystem.py", "run_windows_filesystem.py"):
            self.assertIn("scripts/application-lab/" + name, E.HARNESS_FILES)
        self.assertEqual(len(E.HARNESS_FILES), len(set(E.HARNESS_FILES)))

    def test_duplicate_nonfinite_and_invalid_json_are_rejected(self):
        for data in (b'{"a":1,"a":2}', b'{"nested":{"a":1,"a":2}}', b'{"a":NaN}',
                     b'{"a":Infinity}', b'\xef\xbb\xbf{}', b'\xff', b'[' * 1200):
            with self.subTest(data=data[:30]), self.assertRaises(E.ApplicationEvidenceError):
                E.strict_json(data)

    def test_bounded_file_reader_and_exclusive_sanitized_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            path.write_bytes(b"{}")
            self.assertEqual(E.read_bounded(path, 2), b"{}")
            with self.assertRaises(E.ApplicationEvidenceError):
                E.read_bounded(path, 1)
            with self.assertRaises(FileExistsError):
                E.write_new_report(path, {"unchanged": False})
            self.assertEqual(path.read_bytes(), b"{}")
            fresh = Path(directory) / "validated.json"
            E.write_new_report(fresh, {"validated": True})
            self.assertEqual(json.loads(fresh.read_bytes()), {"validated": True})

    def test_replaced_open_file_identity_and_extra_links_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            path.write_bytes(b"{}")
            info = path.stat()
            changed = types.SimpleNamespace(**{name: getattr(info, name) for name in
                ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink")})
            changed.st_ino += 1
            with patch.object(E.os, "fstat", return_value=changed), self.assertRaises(E.ApplicationEvidenceError):
                E.read_bounded(path)
            alias = Path(directory) / "second.json"
            os.link(path, alias)
            with self.assertRaises(E.ApplicationEvidenceError):
                E.read_bounded(path)

    def test_current_manifest_and_duplicate_pin_rejection(self):
        expected = E.runtime_pins(SOURCE.parents[1])
        self.assertEqual(expected["platform"], "windows")
        self.assertTrue(E.valid_hash(expected["sha256"]))
        original = (SOURCE.parents[1] / "rclone-version.env").read_bytes()
        with patch.object(E, "read_bounded", return_value=original + b"\nRCLONE_VERSION=0.0.0\n"), \
                self.assertRaises(E.ApplicationEvidenceError):
            E.runtime_pins(SOURCE.parents[1])

    def test_cli_uses_external_bindings_and_redacts_invalid_input(self):
        args = ["--backend", "local", "--receipt", "unused", "--application", "unused", "--build-commit",
                BINDINGS["build_commit"], "--report", "unused"]
        value = receipt(complete=True)
        value["created_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with patch.object(E, "read_bounded", return_value=E.compact(value)), \
                patch.object(E, "runtime_pins", return_value=RUNTIME), \
                patch.object(E, "compute_bindings", return_value=BINDINGS) as binding_call, \
                patch.object(E, "write_new_report") as write, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(E.main(args), 0)
            self.assertFalse(json.loads(output.getvalue())["provider_accepted"])
            self.assertEqual(binding_call.call_args.args[2], BINDINGS["build_commit"])
            self.assertTrue(write.call_args.args[1]["validated"])
        value = receipt()
        value["created_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with patch.object(E, "read_bounded", return_value=E.compact(value)), \
                patch.object(E, "runtime_pins", return_value=RUNTIME), \
                patch.object(E, "compute_bindings", return_value=BINDINGS), \
                patch.object(E, "write_new_report"), redirect_stdout(io.StringIO()):
            self.assertEqual(E.main(args), 1)
        with patch.object(E, "read_bounded", side_effect=OSError("private-canary")), \
                patch.object(E, "write_new_report") as write, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(E.main(args), 1)
            self.assertNotIn("private-canary", output.getvalue())
            write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
