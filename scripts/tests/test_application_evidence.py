"""Mutation tests for evidence boundaries; no native application is executed."""

from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "application_evidence.py"
SPEC = importlib.util.spec_from_file_location("application_evidence_tested", SOURCE)
EVIDENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVIDENCE)
NOW = datetime(2026, 10, 5, 0, 0, tzinfo=timezone.utc)
RUNTIME = {"version": "1.75.1", "sha256": "a" * 64, "platform": "windows"}


def bindings():
    return {
        "application_sha256": "b" * 64, "application_source_sha256": "c" * 64,
        "build_commit": "d" * 40, "build_target": "x86_64-pc-windows-msvc",
        "build_profile": "release", "cargo_lock_sha256": "e" * 64,
        "runtime_manifest_sha256": "f" * 64, "harness_sha256": "1" * 64,
        "fixture_manifest_sha256": "2" * 64,
    }


def receipt():
    cases = EVIDENCE.empty_cases()
    for name, case in cases.items():
        case.update(status="passed", exit_code=0 if name in ("listing", "acquisition") else 1,
                    runtime_sha256=RUNTIME["sha256"], checks={key: True for key in case["checks"]})
    return {
        "schema_version": 1, "scope": "windows_hosted_application", "fixture_mode": "http_anonymous_cli_v1",
        "backend": "http", "platform": "windows", "created_at": "2026-10-05T00:00:00Z",
        "runtime": dict(RUNTIME), "bindings": bindings(), "cases": cases,
        "capabilities": {key: "passed" for key in EVIDENCE.CAPABILITIES},
        "result": "passed", "cleanup_complete": True, "errors": [],
    }


class ApplicationEvidenceTests(unittest.TestCase):
    def check(self, value, **options):
        return EVIDENCE.validate_receipt(value, RUNTIME, bindings(), now=NOW, **options)

    def reject(self, value):
        with self.assertRaises(EVIDENCE.ApplicationEvidenceError):
            self.check(value)

    def test_complete_contract_accepts_exact_build_only(self):
        self.assertEqual(set(EVIDENCE.CASE_ORDER),
                         {"listing", "acquisition", "mismatch", "missing", "denial", "cancellation"})
        self.assertEqual(EVIDENCE.CAPABILITIES,
                         {"listing", "download_hash", "manifest_integrity", "source_preservation", "cancellation", "cleanup"})
        value = receipt()
        self.assertIs(self.check(value), value)

    def test_every_binding_is_independently_required(self):
        for key in bindings():
            with self.subTest(key=key):
                value = receipt()
                value["bindings"][key] = "0" * 64 if key.endswith("_sha256") else "changed"
                self.reject(value)
                del value["bindings"][key]
                self.reject(value)

    def test_old_protocol_or_vendor_claims_cannot_enter_application_scope(self):
        for key, changed in (("scope", "local_protocol"), ("scope", "vendor"), ("backend", "gcs"),
                             ("fixture_mode", "gcs_static_token_read_v1"), ("schema_version", True),
                             ("platform", "linux")):
            with self.subTest(key=key, changed=changed):
                value = receipt()
                value[key] = changed
                self.reject(value)
        for key in ("account", "credentials", "raw_transcript", "vendor_acceptance"):
            value = receipt()
            value[key] = "must-not-be-public"
            self.reject(value)

    def test_all_cases_and_checks_are_mandatory_even_for_a_weakened_policy(self):
        for name, case in receipt()["cases"].items():
            with self.subTest(case=name):
                value = receipt()
                del value["cases"][name]
                self.reject(value)
            for key in case["checks"]:
                with self.subTest(case=name, check=key):
                    value = receipt()
                    del value["cases"][name]["checks"][key]
                    self.reject(value)
                    value = receipt()
                    value["cases"][name]["checks"][key] = 1
                    self.reject(value)
                    value["cases"][name]["checks"][key] = False
                    self.reject(value)

    def test_unobserved_or_different_extracted_child_cannot_pass(self):
        for runtime_hash in (None, "0" * 64, [], True):
            value = receipt()
            value["cases"]["listing"]["runtime_sha256"] = runtime_hash
            self.reject(value)
        value = receipt()
        value["runtime"]["sha256"] = "0" * 64
        self.reject(value)

    def test_expected_negative_case_exit_cannot_be_zero_or_absent(self):
        for name in ("mismatch", "missing", "denial", "cancellation"):
            for exit_code in (0, None, True, "1", 2 ** 32):
                with self.subTest(case=name, exit=exit_code):
                    value = receipt()
                    value["cases"][name]["exit_code"] = exit_code
                    self.reject(value)

    def test_failed_cancel_stays_failed_despite_successful_download(self):
        value = receipt()
        case = value["cases"]["cancellation"]
        case["status"], case["failure_code"] = "failed", "cancellation_failed"
        case["checks"]["transfer_active"] = False
        value["capabilities"] = EVIDENCE.derive_capabilities(value["cases"])
        value["result"] = "failed"
        self.check(value)
        self.assertEqual(value["capabilities"]["download_hash"], "passed")
        self.assertEqual(value["capabilities"]["cancellation"], "failed")
        value["capabilities"]["cancellation"] = "passed"
        self.reject(value)

    def test_cleanup_failure_cannot_be_hidden_by_final_flag(self):
        value = receipt()
        case = value["cases"]["listing"]
        case["status"], case["failure_code"] = "failed", "cleanup_failed"
        case["checks"]["process_cleanup"] = False
        value["capabilities"] = EVIDENCE.derive_capabilities(value["cases"])
        value["result"] = "failed"
        self.reject(value)
        value["cleanup_complete"] = False
        self.check(value)
        value["result"] = "passed"
        self.reject(value)

    def test_unrun_cases_are_not_evidence(self):
        value = receipt()
        value["cases"] = EVIDENCE.empty_cases()
        value["capabilities"] = EVIDENCE.derive_capabilities(value["cases"])
        value["result"] = "failed"
        self.check(value)
        self.assertEqual(set(value["capabilities"].values()), {"not_verified"})
        value["cases"]["listing"]["checks"]["inventory_exact"] = True
        self.reject(value)

    def test_late_supervisor_cleanup_failure_changes_cleanup_capability(self):
        value = receipt()
        value["cleanup_complete"] = False
        value["result"] = "failed"
        value["errors"] = ["cleanup_failed"]
        self.reject(value)
        value["capabilities"] = EVIDENCE.derive_capabilities(value["cases"], False)
        self.check(value)
        self.assertEqual(value["capabilities"]["cleanup"], "failed")

    def test_public_error_fields_are_finite_typed_and_closed(self):
        for changed in (["a private diagnostic"], ["cleanup_failed", "cleanup_failed"], [["cleanup_failed"]], None):
            value = receipt()
            value["errors"] = changed
            self.reject(value)
        for changed in ([], {}, "raw child output"):
            value = receipt()
            value["cases"]["listing"]["failure_code"] = changed
            self.reject(value)

    def test_expired_future_and_noncanonical_timestamps_are_rejected(self):
        for changed in ("2026-10-03T23:59:59Z", "2026-10-05T00:05:01Z",
                        "2026-13-01T00:00:00Z", "2026-10-05T00:00:00+00:00", 1):
            value = receipt()
            value["created_at"] = changed
            self.reject(value)
        for changed in (True, 0, -1, 25, float("inf"), float("nan")):
            with self.assertRaises(EVIDENCE.ApplicationEvidenceError):
                self.check(receipt(), max_age_hours=changed)

    def test_source_and_harness_mutations_change_expected_bindings(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            names = (*EVIDENCE.HARNESS_FILES, "rclone-triage/Cargo.toml", "rclone-triage/Cargo.lock",
                     "rclone-triage/build.rs", "rclone-triage/.cargo/config.toml",
                     "rclone-triage/src/main.rs", "rclone-version.env", "app.exe")
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"synthetic source only")
            before = EVIDENCE.compute_bindings(root, root / "app.exe", "d" * 40, {"synthetic": "manifest"})
            (root / "rclone-triage/src/main.rs").write_bytes(b"changed source")
            after = EVIDENCE.compute_bindings(root, root / "app.exe", "d" * 40, {"synthetic": "manifest"})
            self.assertNotEqual(before["application_source_sha256"], after["application_source_sha256"])
            self.assertEqual(before["harness_sha256"], after["harness_sha256"])
            (root / "rclone-triage/.cargo/config.toml").write_bytes(b"changed build flags")
            flags_changed = EVIDENCE.compute_bindings(root, root / "app.exe", "d" * 40, {"synthetic": "manifest"})
            self.assertNotEqual(after["application_source_sha256"], flags_changed["application_source_sha256"])
            (root / EVIDENCE.HARNESS_FILES[-1]).write_bytes(b"changed producer")
            final = EVIDENCE.compute_bindings(root, root / "app.exe", "d" * 40, {"synthetic": "manifest"})
            self.assertNotEqual(after["harness_sha256"], final["harness_sha256"])
            (root / "app.exe").unlink()
            with self.assertRaises(EVIDENCE.ApplicationEvidenceError):
                EVIDENCE.compute_bindings(root, root / "app.exe", "d" * 40, {})


if __name__ == "__main__":
    unittest.main()
