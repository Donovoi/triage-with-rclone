"""Independent literal TUI evidence mutations; no app/process/socket execution."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "tui_application_evidence.py"
SPEC = importlib.util.spec_from_file_location("tested_tui_application_evidence", SOURCE)
E = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(E)
NOW = datetime(2026, 10, 10, 0, 0, tzinfo=timezone.utc)
ORDER = ("manual_acquisition", "escape_cancellation", "session_reset")
COMMON = {"manual_setup", "runtime_setup", "listing_artifacts", "selection_exact", "runtime_transfer",
          "manifest_and_payloads", "configuration_preserved", "fixture_valid", "source_preserved",
          "orderly_exit", "terminal_closed", "process_cleanup", "fixture_cleanup", "temp_cleanup"}
CHECKS = {"manual_acquisition": COMMON,
          "escape_cancellation": COMMON | {"active_partial", "cancel_requested", "cancelled_result"},
          "session_reset": COMMON | {"reset_source_replaced", "prior_acquisition_preserved"}}
RUNTIME = {"version": "1.75.2", "sha256": "a" * 64, "platform": "windows"}
LIMITS = ["no_vendor_acceptance", "no_oauth_or_refresh", "no_listing_cancel_recovery", "no_resize_acceptance",
          "no_mount_or_webgui", "no_all_provider_qualification"]


def bindings():
    return {"application_sha256": "b" * 64, "application_source_sha256": "c" * 64,
            "build_commit": "d" * 40, "build_target": "x86_64-pc-windows-msvc", "build_profile": "release",
            "cargo_lock_sha256": "e" * 64, "runtime_manifest_sha256": "f" * 64, "harness_sha256": "1" * 64,
            "fixture_manifest_sha256": "2" * 64, "tui_harness_sha256": "3" * 64}


def receipt():
    cases = {}
    for name in ORDER:
        cases[name] = dict(status="passed", failure_code=None, failure_phase=None, exit_code=0,
            checks={key: True for key in CHECKS[name]}, listing_observations=[
                dict(files=4, directories=2, csv_sha256="4" * 64, xlsx_sha256="5" * 64)
                for _ in range(2 if name == "session_reset" else 1)])
    return dict(schema_version=1, scope="windows_manual_http_tui_experiment", platform="windows", backend="http",
                created_at="2026-10-10T00:00:00Z", runtime=dict(RUNTIME), bindings=bindings(), cases=cases,
                errors=[], cleanup_complete=True, result="passed", limitations=list(LIMITS))


def unrun(case):
    case.update(status="not_run", failure_code=None, failure_phase=None, exit_code=None,
                checks={key: False for key in case["checks"]}, listing_observations=[])


def fail_case(value, index=0, code="navigation_timeout", phase="provider_selection"):
    case = value["cases"][ORDER[index]]
    unrun(case)
    case.update(status="failed", failure_code=code, failure_phase=phase)
    for key in ("process_cleanup", "fixture_cleanup", "temp_cleanup"):
        case["checks"][key] = True
    for name in ORDER[index+1:]:
        unrun(value["cases"][name])
    value.update(result="failed", errors=[code])
    return case


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch.object(subprocess, "Popen", side_effect=AssertionError("no native process")).start()
        patch.object(socket, "socket", side_effect=AssertionError("no sockets")).start()

    def check(self, value, **kwargs):
        return E.validate_receipt(value, RUNTIME, bindings(), now=NOW, **kwargs)

    def reject(self, value, code=None):
        with self.assertRaises(E.TuiEvidenceError) as result:
            self.check(value)
        if code:
            self.assertEqual(result.exception.code, code)

    def test_literal_complete_contract_and_defensive_copy(self):
        self.assertEqual(E.CASE_ORDER, ORDER)
        self.assertEqual(E.CASE_CHECKS, CHECKS)
        self.assertEqual(sum(map(len, CHECKS.values())), 47)
        value = receipt()
        actual = self.check(value)
        self.assertEqual(actual, value)
        actual["cases"][ORDER[0]]["checks"]["manual_setup"] = False
        self.assertTrue(value["cases"][ORDER[0]]["checks"]["manual_setup"])

    def test_all_bindings_and_runtime_fields_are_independent(self):
        for key in bindings():
            with self.subTest(key=key):
                value = receipt()
                value["bindings"][key] = "0" * 64 if key.endswith("_sha256") else "changed"
                self.reject(value)
                del value["bindings"][key]
                self.reject(value)
        for key, wrong in (("version", "1.75.1"), ("sha256", "0" * 64), ("platform", "linux")):
            value = receipt(); value["runtime"][key] = wrong
            self.reject(value)

    def test_cli_vendor_other_scope_and_extra_metadata_rejected(self):
        for key, wrong in (("scope", "windows_hosted_application"), ("scope", "vendor"),
                           ("backend", "gcs"), ("platform", "linux"), ("schema_version", True)):
            value = receipt(); value[key] = wrong
            self.reject(value)
        for key in ("account", "raw_transcript", "capabilities", "ledger_eligible", "application_accepted"):
            value = receipt(); value[key] = "private-canary"
            self.reject(value)
        for location in (lambda v: v["runtime"], lambda v: v["bindings"], lambda v: v["cases"][ORDER[0]]):
            value = receipt(); location(value)["private_path"] = "private-canary"
            self.reject(value)

    def test_every_case_check_must_exist_be_bool_and_pass_for_success(self):
        for name, required in CHECKS.items():
            value = receipt(); del value["cases"][name]
            self.reject(value)
            for key in required:
                for wrong in (False, 1, None, "true"):
                    with self.subTest(case=name, check=key, wrong=wrong):
                        value = receipt(); value["cases"][name]["checks"][key] = wrong
                        self.reject(value)
                value = receipt(); del value["cases"][name]["checks"][key]
                self.reject(value)

    def test_listing_count_shape_digest_and_integer_types(self):
        for name in ORDER:
            for key, wrong in (("files", 3), ("files", True), ("directories", 1), ("directories", 2.0),
                               ("csv_sha256", "A" * 64), ("xlsx_sha256", "private-canary")):
                value = receipt(); value["cases"][name]["listing_observations"][0][key] = wrong
                self.reject(value, "listing_invalid")
            value = receipt(); value["cases"][name]["listing_observations"].pop()
            self.reject(value)
            value = receipt(); value["cases"][name]["listing_observations"].append(
                dict(files=4, directories=2, csv_sha256="4" * 64, xlsx_sha256="5" * 64))
            self.reject(value)
        value = receipt(); value["cases"][ORDER[0]]["listing_observations"][0]["path"] = "canary"
        self.reject(value)

    def test_not_run_cannot_claim_any_fields(self):
        value = receipt(); fail_case(value)
        self.check(value)
        for key, wrong in (("exit_code", 0), ("failure_code", "cleanup_failed"), ("failure_phase", "case_cleanup")):
            mutated = copy.deepcopy(value); mutated["cases"][ORDER[1]][key] = wrong
            self.reject(mutated)
        mutated = copy.deepcopy(value); mutated["cases"][ORDER[1]]["checks"]["fixture_cleanup"] = True
        self.reject(mutated)
        mutated = copy.deepcopy(value); mutated["cases"][ORDER[1]]["listing_observations"] = receipt()["cases"][ORDER[1]]["listing_observations"]
        self.reject(mutated)

    def test_execution_prefix_and_first_failure_are_sticky(self):
        for index in range(3):
            value = receipt(); fail_case(value, index)
            self.assertEqual(self.check(value)["result"], "failed")
            for later in ORDER[index+1:]:
                changed = copy.deepcopy(value); changed["cases"][later] = receipt()["cases"][later]
                self.reject(changed, "execution_order_invalid")
        value = receipt(); unrun(value["cases"][ORDER[0]])
        value.update(errors=["case_setup_failed"], result="failed")
        self.reject(value, "execution_order_invalid")

    def test_valid_outer_failures_before_between_and_after_cases(self):
        for completed in range(4):
            value = receipt()
            for name in ORDER[completed:]:
                unrun(value["cases"][name])
            value.update(errors=["cleanup_failed"], result="failed", cleanup_complete=False)
            self.assertEqual(self.check(value)["result"], "failed")
        value = receipt(); value.update(errors=["preservation_failed"], result="failed")
        self.check(value)

    def test_failure_codes_phases_errors_and_exit_types_are_closed(self):
        base = receipt(); fail_case(base)
        for key, wrong in (("failure_code", None), ("failure_code", "private-canary"),
                           ("failure_phase", None), ("failure_phase", "private-canary"),
                           ("exit_code", True), ("exit_code", 2 ** 32)):
            value = copy.deepcopy(base); value["cases"][ORDER[0]][key] = wrong
            self.reject(value)
        for errors in ([], ["navigation_timeout"] * 2, ["private-canary"], [True]):
            value = copy.deepcopy(base); value["errors"] = errors
            self.reject(value)
        for name in ORDER:
            for wrong in (1, None, True):
                value = receipt(); value["cases"][name]["exit_code"] = wrong
                self.reject(value)
        value = receipt(); value["cases"][ORDER[0]]["failure_phase"] = "completion"
        self.reject(value)

    def test_cleanup_and_partial_observation_implications(self):
        for name in ORDER:
            for key in ("process_cleanup", "fixture_cleanup", "temp_cleanup"):
                value = receipt(); index = ORDER.index(name); case = fail_case(value, index, "cleanup_failed", "case_cleanup")
                case["checks"][key] = False
                self.reject(value, "cleanup_invalid")
        value = receipt(); fail_case(value, 1)
        case = value["cases"][ORDER[1]]
        case["checks"]["cancel_requested"] = True
        self.reject(value, "checks_invalid")
        value = receipt(); fail_case(value, 2)
        case = value["cases"][ORDER[2]]
        case["checks"]["reset_source_replaced"] = True
        self.reject(value, "checks_invalid")
        # A failed reset may retain a valid first listing without second-source credit.
        case["checks"]["reset_source_replaced"] = False
        case["checks"]["listing_artifacts"] = True
        case["listing_observations"] = receipt()["cases"][ORDER[0]]["listing_observations"]
        self.check(value)

    def test_freshness_and_limitations_exact(self):
        for created in (NOW - timedelta(hours=24, seconds=1), NOW + timedelta(minutes=5, seconds=1)):
            value = receipt(); value["created_at"] = created.strftime("%Y-%m-%dT%H:%M:%SZ")
            self.reject(value, "freshness_invalid")
        for wrong in ("2026-02-30T00:00:00Z", "2026-10-10T00:00:00+00:00", "2026-10-10T00:00:00.0Z"):
            value = receipt(); value["created_at"] = wrong
            self.reject(value, "freshness_invalid")
        for limit in (0, 25, True, 24.0):
            with self.assertRaises(E.TuiEvidenceError):
                self.check(receipt(), max_age_hours=limit)
        with self.assertRaises(E.TuiEvidenceError):
            E.validate_receipt(receipt(), RUNTIME, bindings(), now=NOW.replace(tzinfo=None))
        for wrong in ([], list(reversed(LIMITS)), LIMITS + ["native_success"]):
            value = receipt(); value["limitations"] = wrong
            self.reject(value, "limitations_invalid")

    def test_json_duplicate_nonfinite_depth_and_size_refused_privately(self):
        for data in (b'{"scope":"a","scope":"b"}', b'{"x":{"a":1,"a":2}}', b'{"x":NaN}',
                     b'{"x":1e999}', b'\xff', b'[' * 14 + b'0' + b']' * 14,
                     b' ' * (128 * 1024 + 1), b'{"private-canary":null}'):
            audit = E.audit_bytes(data, RUNTIME, bindings(), now=NOW)
            self.assertFalse(audit["valid"])
            self.assertIsNone(audit["receipt"])
            self.assertNotIn("private-canary", json.dumps(audit))
            self.assertTrue(set(audit["errors"]) <= E.VALIDATION_CODES)

    def test_sanitized_audit_never_grants_ledger_or_provider_credit(self):
        for failed in (False, True):
            value = receipt()
            if failed:
                fail_case(value)
            audit = E.audit_bytes(E.compact(value), RUNTIME, bindings(), now=NOW)
            self.assertTrue(audit["valid"])
            self.assertEqual(audit["result"], "failed" if failed else "passed")
            self.assertEqual(audit["receipt"], value)
            self.assertTrue(all(audit[key] is False for key in
                ("ledger_eligible", "application_accepted", "vendor_accepted", "provider_accepted")))


class BindingCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = self.root / "synthetic-image.data"
        self.app.write_bytes(b"synthetic bytes, never executable")
        for name in set(E.HARNESS_FILES) | {"rclone-triage/Cargo.toml", "rclone-triage/Cargo.lock",
                "rclone-triage/build.rs", "rclone-triage/.cargo/config.toml", "rclone-triage/src/main.rs"}:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("synthetic " + name, encoding="utf-8")
        self.pin_names = ("RCLONE_EXE_SHA256", "RCLONE_WINDOWS_ZIP_SHA256", "RCLONE_LINUX_ZIP_SHA256",
                          "RCLONE_LINUX_EXE_SHA256", "RCLONE_WINDOWS_X86_EXE_SHA256", "RCLONE_WINDOWS_X86_ZIP_SHA256",
                          "RCLONE_WINDOWS_ARM64_EXE_SHA256", "RCLONE_WINDOWS_ARM64_ZIP_SHA256")
        self.pins = self.root / "rclone-version.env"
        self.pins.write_text("RCLONE_VERSION=1.75.2\n" + "".join(name + "=" + "a" * 64 + "\n" for name in self.pin_names), encoding="ascii")
        self.addCleanup(patch.stopall)
        patch.object(E, "ROOT", self.root).start()
        patch.object(subprocess, "Popen", side_effect=AssertionError("no process")).start()
        patch.object(socket, "socket", side_effect=AssertionError("no socket")).start()

    def value(self):
        value = receipt()
        value["created_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        value["bindings"] = E.compute_bindings(self.root, self.app, "d" * 40)
        return value

    def cli(self, value, name="audit.json"):
        raw = self.root / "receipt.json"
        raw.write_bytes(E.compact(value))
        output = self.root / name
        result = E.main(["--receipt", str(raw), "--application", str(self.app), "--build-commit", "d" * 40,
                         "--report", str(output)])
        return result, json.loads(output.read_bytes())

    def test_bindings_use_exact_source_closure_and_literal_payload_manifest(self):
        value = self.value()["bindings"]
        self.assertEqual(len(E.HARNESS_FILES), 14)
        self.assertIn("scripts/tui_application_evidence.py", E.HARNESS_FILES)
        self.assertEqual(value["application_sha256"], hashlib.sha256(self.app.read_bytes()).hexdigest())
        names = ["rclone-triage/Cargo.toml", "rclone-triage/Cargo.lock", "rclone-triage/build.rs",
                 "rclone-triage/.cargo/config.toml", "rclone-triage/src/main.rs"]
        rows = [[name, hashlib.sha256((self.root / name).read_bytes()).hexdigest()] for name in sorted(names)]
        expected = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(value["application_source_sha256"], expected)
        payloads = {"README-synthetic.txt": b"synthetic application fixture\n", "large/cancel.bin": bytes(range(256))*8192,
                    "nested/binary.bin": bytes(range(256)), "nested/spaced name.txt": b"spaces remain exact\n"}
        self.assertEqual(E.fixture_manifest(), [{"path": p, "size": len(payloads[p]),
                          "sha256": hashlib.sha256(payloads[p]).hexdigest()} for p in sorted(payloads)])
        for name in ("rclone-triage/src/main.rs", "rclone-triage/.cargo/config.toml", "scripts/application-lab/tui_screen.py"):
            path = self.root / name; original = path.read_bytes()
            path.write_bytes(original + b"changed")
            self.assertNotEqual(value, E.compute_bindings(self.root, self.app, "d" * 40))
            path.write_bytes(original)

    def test_runtime_manifest_keys_duplicates_architecture_and_shape(self):
        original = self.pins.read_bytes()
        self.assertEqual(E.runtime_pins(self.root), RUNTIME)
        for bad in (original + b"RCLONE_VERSION=1.75.2\n", original.replace(b"=1.75.2", b"=01.75.2"),
                    original + b"UNREVIEWED=secret\n", original.replace(b"a" * 64, b"A" * 64)):
            self.pins.write_bytes(bad)
            with self.assertRaises(E.TuiEvidenceError):
                E.runtime_pins(self.root)
        self.pins.write_bytes(original)
        self.pins.write_bytes(original.replace(b"RCLONE_WINDOWS_ARM64_EXE_SHA256=" + b"a" * 64, b"RCLONE_WINDOWS_ARM64_EXE_SHA256=" + b"b" * 64))
        self.assertEqual(E.runtime_pins(self.root)["sha256"], "a" * 64)

    def test_cli_pass_failed_invalid_and_create_new_only(self):
        result, audit = self.cli(self.value())
        self.assertEqual(result, 0); self.assertTrue(audit["valid"])
        value = self.value(); fail_case(value)
        result, audit = self.cli(value, "failed.json")
        self.assertEqual(result, 1); self.assertEqual(audit["receipt"]["result"], "failed")
        value = self.value(); value["private-canary"] = "private-account"
        result, audit = self.cli(value, "invalid.json")
        self.assertEqual(result, 2); self.assertIsNone(audit["receipt"])
        self.assertNotIn("private-account", json.dumps(audit))
        before = (self.root / "audit.json").read_bytes()
        with patch("sys.stderr", io.StringIO()) as output:
            result, _ = self.cli(self.value())
        self.assertEqual(result, 2)
        self.assertEqual((self.root / "audit.json").read_bytes(), before)
        self.assertEqual(output.getvalue(), "tui_validation_report_write_failed\n")

    def test_cli_rechecks_current_bytes_after_validation(self):
        value = self.value()
        original = E.audit_bytes
        def mutate(*args, **kwargs):
            audit = original(*args, **kwargs)
            self.app.write_bytes(b"changed after initial binding")
            return audit
        with patch.object(E, "audit_bytes", side_effect=mutate):
            result, audit = self.cli(value)
        self.assertEqual(result, 2)
        self.assertEqual(audit["errors"], ["input_changed"])
        self.assertIsNone(audit["receipt"])

    def test_cli_invalid_input_and_report_errors_do_not_echo_values(self):
        with patch("sys.stderr", io.StringIO()) as output:
            self.assertEqual(E.main(["--unknown", "private-canary"]), 2)
        self.assertEqual(output.getvalue(), "tui_validation_input_invalid\n")
        self.assertNotIn("private-canary", output.getvalue())


if __name__ == "__main__":
    unittest.main()
