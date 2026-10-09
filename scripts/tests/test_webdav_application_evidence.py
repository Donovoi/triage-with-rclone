"""Pure independent WebDAV application-receipt mutations; no processes or sockets."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "webdav_application_evidence.py"
SPEC = importlib.util.spec_from_file_location("tested_webdav_application_contract", SOURCE)
E = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(E)
NOW = datetime(2026, 10, 10, 0, 0, tzinfo=timezone.utc)
RUNTIME = {"version": "1.75.2", "sha256": "a" * 64, "platform": "windows"}
COMMON = {"runtime_observed", "configuration_preserved", "source_preserved", "fixture_valid", "orderly_exit",
          "temp_cleanup", "process_cleanup", "fixture_cleanup", "authority_exact", "request_credentials_exact"}
READ = {"exit_success", "manifest_complete", "manifest_exact", "output_hashes_exact", "outputs_exact", "basic_auth_observed"}
DENIED = {"exit_failure", "manifest_incomplete", "credential_denial_observed", "failed_result_exact",
          "no_download_outputs", "no_payload_served", "no_authority_fallback"}
CHECKS = {
    "listing": COMMON | {"exit_success", "inventory_exact", "listing_complete", "basic_auth_observed"},
    "acquisition": COMMON | READ,
    "mismatch": COMMON | {"exit_failure", "manifest_incomplete", "mismatch_exact", "retained_bytes_exact",
                          "outputs_exact", "basic_auth_observed"},
    "missing": COMMON | {"exit_failure", "manifest_incomplete", "missing_failure_exact", "not_found_observed",
                         "no_download_outputs", "basic_auth_observed"},
    "wrong_credentials": COMMON | DENIED,
    "accepted_a": COMMON | READ | {"group_finalized"},
    "revoked_a": COMMON | DENIED | {"same_config_as_accepted", "group_finalized"},
    "replacement_b": COMMON | READ | {"credential_changed", "group_finalized"},
    "permission_denied": COMMON | {"exit_failure", "manifest_incomplete", "permission_denial_observed",
                                   "failed_result_exact", "no_download_outputs", "no_payload_served", "basic_auth_observed"},
    "truncated_transfer": COMMON | {"exit_failure", "manifest_incomplete", "truncation_observed",
                                    "failed_result_exact", "no_partial_outputs", "no_download_outputs", "basic_auth_observed"},
    "cancellation": COMMON | {"exit_failure", "transfer_active", "ctrl_c_sent", "client_disconnect_observed",
                              "cancelled_result_exact", "manifest_incomplete", "no_partial_outputs",
                              "no_download_outputs", "basic_auth_observed"},
}
SCENARIOS = {
    "listing": ("listing",), "acquisition": ("acquisition",), "mismatch": ("mismatch",), "missing": ("missing",),
    "wrong_credentials": ("wrong_credentials",), "revoked_credentials": ("accepted_a", "revoked_a"),
    "replacement_credentials": ("replacement_b",), "permission_denied": ("permission_denied",),
    "truncated_transfer": ("truncated_transfer",), "cancellation": ("cancellation",),
}
GROUP = {"same_fixture_authority", "epoch_ordered", "transitions_reaped", "deadline_preserved", "revocation_observed",
         "replacement_observed", "config_a_preserved", "accepted_a_preserved", "no_credential_poisoning",
         "all_processes_reaped", "fixture_cleanup", "temp_cleanup"}
CLAIMS = {"setup_verified", "interactive_login_verified", "authentication_verified", "renewal_verified",
          "reauthorization_verified", "connection_session_reauthentication_verified", "tls_verified",
          "vendor_accepted", "provider_accepted", "full_application_accepted"}
CAPS = {"listing", "download_hash", "manifest_integrity", "source_preservation", "cancellation", "cleanup"}
POSITIVE = {"listing", "acquisition", "accepted_a", "replacement_b"}


def bindings():
    return {"application_sha256": "b" * 64, "application_source_sha256": "c" * 64, "build_commit": "d" * 40,
            "build_target": "x86_64-pc-windows-msvc", "build_profile": "release", "cargo_lock_sha256": "e" * 64,
            "runtime_manifest_sha256": "f" * 64, "harness_sha256": "1" * 64, "fixture_manifest_sha256": "2" * 64}


def receipt():
    cases = {}
    for name, leaves in SCENARIOS.items():
        invocations = {leaf: {"status": "passed", "exit_code": 0 if leaf in POSITIVE else 1,
                              "runtime_sha256": RUNTIME["sha256"], "failure_code": None,
                              "checks": {key: True for key in CHECKS[leaf]}} for leaf in leaves}
        cases[name] = {"status": "passed", "failure_code": None, "invocations": invocations}
    return {"schema_version": 1, "scope": "windows_hosted_application", "fixture_mode": "webdav_basic_loopback_cli_v1",
            "backend": "webdav", "platform": "windows", "created_at": "2026-10-10T00:00:00Z",
            "runtime": dict(RUNTIME), "bindings": bindings(), "cases": cases, "claims": {key: False for key in CLAIMS},
            "credential_group": {"status": "passed", "failure_code": None, "checks": {key: True for key in GROUP}},
            "capabilities": {key: "passed" for key in CAPS}, "result": "passed", "cleanup_complete": True, "errors": []}


def invocation(value, leaf):
    name = next(name for name, leaves in SCENARIOS.items() if leaf in leaves)
    return value["cases"][name]["invocations"][leaf]


def suffix_unrun(value, first):
    start = list(CHECKS).index(first)
    empty = E.empty_cases()
    for name, leaves in SCENARIOS.items():
        for leaf in leaves:
            if list(CHECKS).index(leaf) >= start:
                value["cases"][name]["invocations"][leaf] = deepcopy(empty[name]["invocations"][leaf])
    project(value)


def project(value):
    for case in value["cases"].values():
        statuses = [item["status"] for item in case["invocations"].values()]
        case["status"] = "passed" if all(s == "passed" for s in statuses) else "not_run" if all(
            s == "not_run" for s in statuses) else "failed"
        case["failure_code"] = next((item["failure_code"] for item in case["invocations"].values()
                                     if item["status"] == "failed"), None)
    value["capabilities"] = E.derive_capabilities(value["cases"], value["cleanup_complete"])
    value["result"] = "failed"


def failed_group(check="config_a_preserved"):
    value = receipt()
    suffix_unrun(value, "permission_denied")
    value["errors"] = ["group_failed"]
    value["credential_group"].update(status="failed", failure_code="group_failed")
    value["credential_group"]["checks"][check] = False
    for leaf in ("accepted_a", "revoked_a", "replacement_b"):
        item = invocation(value, leaf)
        item.update(status="failed", failure_code="group_failed")
        item["checks"]["group_finalized"] = False
        if check in ("fixture_cleanup", "temp_cleanup"):
            item["checks"][check] = False
    if check in ("all_processes_reaped", "fixture_cleanup", "temp_cleanup"):
        value["cleanup_complete"] = False
    project(value)
    return value


class WebdavApplicationEvidenceTests(unittest.TestCase):
    def check(self, value, **options):
        return E.validate_receipt(value, RUNTIME, bindings(), now=NOW, **options)

    def reject(self, value, code=None):
        with self.assertRaises(E.ApplicationEvidenceError) as raised:
            self.check(value)
        if code:
            self.assertEqual(str(raised.exception), code)

    def test_literal_contract_and_complete_receipt(self):
        self.assertEqual(E.CASE_INVOCATIONS, SCENARIOS)
        self.assertEqual(E.INVOCATION_CHECKS, CHECKS)
        self.assertEqual(E.GROUP_CHECKS, GROUP)
        self.assertEqual(E.FALSE_CLAIMS, CLAIMS)
        self.assertEqual(E.CAPABILITIES, CAPS)
        self.assertEqual(len(SCENARIOS), 10)
        self.assertEqual(sum(map(len, SCENARIOS.values())), 11)
        value = receipt()
        self.assertIs(self.check(value), value)
        self.assertEqual(E.parse_receipt(E.compact(value)), value)

    def test_every_closed_container_rejects_missing_and_extra_fields(self):
        paths = [(), ("runtime",), ("bindings",), ("claims",), ("credential_group",),
                 ("credential_group", "checks"), ("capabilities",), ("cases",)]
        for name, leaves in SCENARIOS.items():
            paths.extend([("cases", name), ("cases", name, "invocations")])
            for leaf in leaves:
                paths.extend([("cases", name, "invocations", leaf), ("cases", name, "invocations", leaf, "checks")])
        for path in paths:
            original = receipt()
            container = original
            for key in path:
                container = container[key]
            for key in list(container) + [None]:
                with self.subTest(path=path, key=key):
                    value, target = deepcopy(original), None
                    target = value
                    for part in path:
                        target = target[part]
                    if key is None:
                        target["PRIVATE_CANARY"] = "not-public"
                    else:
                        del target[key]
                    self.reject(value)

    def test_no_scope_mode_platform_or_auth_variant_substitution(self):
        for key, value in (("scope", "local_protocol"), ("scope", "vendor"), ("schema_version", True),
                           ("schema_version", 2), ("backend", "http"), ("platform", "linux"),
                           ("fixture_mode", "http_anonymous_cli_v1"), ("fixture_mode", "webdav_ntlm"),
                           ("fixture_mode", "webdav_bearer"), ("fixture_mode", "webdav_tls_cli_v1")):
            changed = receipt()
            changed[key] = value
            self.reject(changed)

    def test_every_binding_and_runtime_field_must_match_independent_pins(self):
        for key in bindings():
            value = receipt()
            value["bindings"][key] = "0" * 64 if key.endswith("_sha256") else "different"
            self.reject(value)
        for key, replacement in (("version", "1.75.3"), ("sha256", "0" * 64), ("platform", "linux")):
            value = receipt()
            value["runtime"][key] = replacement
            self.reject(value)
        for bad in (None, 1, True, "0" * 63, "A" * 64, [], {}):
            value = receipt()
            value["bindings"]["application_sha256"] = bad
            self.reject(value)

    def test_all_invocation_checks_are_mandatory_strict_booleans(self):
        for leaf, checks in CHECKS.items():
            for key in checks:
                for bad in (False, None, 1, "true", [], {}):
                    with self.subTest(leaf=leaf, key=key, bad=bad):
                        value = receipt()
                        invocation(value, leaf)["checks"][key] = bad
                        self.reject(value)

    def test_all_group_checks_are_mandatory_and_typed(self):
        for key in GROUP:
            for bad in (False, None, 1, "true", [], {}):
                value = receipt()
                value["credential_group"]["checks"][key] = bad
                self.reject(value)

    def test_no_full_provider_login_tls_or_vendor_promotion(self):
        for key in CLAIMS:
            for bad in (True, 0, None, "false", [], {}):
                value = receipt()
                value["claims"][key] = bad
                self.reject(value)

    def test_all_exit_signs_observed_runtime_and_failure_fields(self):
        for leaf in CHECKS:
            for bad in (None, True, "0", -2 ** 31 - 1, 2 ** 32, 1 if leaf in POSITIVE else 0):
                value = receipt()
                invocation(value, leaf)["exit_code"] = bad
                self.reject(value)
            for bad in (None, True, [], {}, "0" * 64):
                value = receipt()
                invocation(value, leaf)["runtime_sha256"] = bad
                self.reject(value)
            value = receipt()
            invocation(value, leaf)["failure_code"] = "unexpected_failure"
            self.reject(value)

    def test_preliminary_accepted_a_cannot_be_omitted_or_replaced(self):
        value = receipt()
        del value["cases"]["revoked_credentials"]["invocations"]["accepted_a"]
        self.reject(value, "webdav_invocations_invalid")
        value = receipt()
        value["cases"]["revoked_credentials"]["invocations"]["accepted_a"] = deepcopy(
            invocation(value, "replacement_b"))
        self.reject(value, "webdav_checks_invalid")

    def test_failed_records_cannot_claim_an_exit_opposite_to_observed_code(self):
        for leaf in CHECKS:
            for code in (None, 1 if leaf in POSITIVE else 0):
                value = receipt()
                item = invocation(value, leaf)
                item.update(status="failed", failure_code="unexpected_failure", exit_code=code)
                value["errors"] = ["unexpected_failure"]
                project(value)
                self.reject(value, "webdav_exit_observation_invalid")
        # A failed prevalidation is permitted to leave its exit predicate false,
        # including when no observed application exit is available yet.
        value = receipt()
        suffix_unrun(value, "acquisition")
        value["credential_group"] = E.empty_group()
        item = invocation(value, "listing")
        item.update(status="failed", failure_code="session_failed", exit_code=None)
        item["checks"]["exit_success"] = False
        value["errors"] = ["session_failed"]
        project(value)
        self.check(value)

    def test_unrun_claims_and_attempted_suffix_are_refused(self):
        value = receipt()
        value["cases"] = E.empty_cases()
        value["credential_group"] = E.empty_group()
        value["errors"] = ["case_setup_failed"]
        project(value)
        self.check(value)
        self.assertEqual(set(value["capabilities"].values()), {"not_verified"})
        for leaf in CHECKS:
            changed = deepcopy(value)
            invocation(changed, leaf)["checks"][next(iter(CHECKS[leaf]))] = False
            self.reject(changed, "webdav_unrun_claims")
        value = receipt()
        value["cases"]["listing"] = E.empty_cases()["listing"]
        project(value)
        value["errors"] = ["case_setup_failed"]
        self.reject(value, "webdav_execution_order_invalid")

    def test_valid_top_level_failures_before_cases_and_after_passed_prefix(self):
        for first in ("listing", "acquisition", "mismatch"):
            value = receipt()
            suffix_unrun(value, first)
            value["credential_group"] = E.empty_group()
            value["errors"] = ["case_setup_failed"]
            self.check(value)
        value = receipt()
        value.update(result="failed", errors=["preservation_failed"])
        self.check(value)
        value["result"] = "passed"
        self.reject(value, "webdav_result_inconsistent")

    def test_first_operational_failure_blocks_later_attempts(self):
        value = receipt()
        item = invocation(value, "acquisition")
        item.update(status="failed", failure_code="outputs_invalid")
        item["checks"]["output_hashes_exact"] = False
        value["errors"] = ["outputs_invalid"]
        project(value)
        self.reject(value, "webdav_execution_order_invalid")
        suffix_unrun(value, "mismatch")
        value["credential_group"] = E.empty_group()
        self.check(value)

    def test_group_late_failure_projects_without_erasing_factual_observations(self):
        value = failed_group()
        self.check(value)
        for leaf in ("accepted_a", "revoked_a", "replacement_b"):
            item = invocation(value, leaf)
            self.assertEqual(item["status"], "failed")
            self.assertTrue(item["checks"]["runtime_observed"])
            self.assertTrue(item["checks"]["configuration_preserved"])
            self.assertTrue(item["checks"]["process_cleanup"])
            self.assertFalse(item["checks"]["group_finalized"])
        self.assertEqual(value["capabilities"]["source_preservation"], "failed")
        for leaf in ("accepted_a", "revoked_a", "replacement_b"):
            changed = deepcopy(value)
            item = invocation(changed, leaf)
            item.update(status="passed", failure_code=None)
            item["checks"]["group_finalized"] = True
            project(changed)
            self.reject(changed, "webdav_group_failure_not_projected")

    def test_each_group_cleanup_failure_is_sticky_across_all_epochs(self):
        for key in ("fixture_cleanup", "temp_cleanup", "all_processes_reaped"):
            value = failed_group(key)
            self.check(value)
            self.assertEqual(value["capabilities"]["cleanup"], "failed")
            value["cleanup_complete"] = True
            self.reject(value, "webdav_cleanup_inconsistent")
        value = failed_group("fixture_cleanup")
        invocation(value, "accepted_a")["checks"]["fixture_cleanup"] = True
        self.reject(value, "webdav_group_cleanup_not_projected")

    def test_failed_epoch_cannot_allow_replacement_or_erase_unrun_successors(self):
        value = failed_group()
        invocation(value, "revoked_a")["checks"]["credential_denial_observed"] = False
        self.reject(value, "webdav_execution_order_invalid")
        suffix_unrun(value, "replacement_b")
        self.check(value)
        self.assertEqual(invocation(value, "replacement_b")["status"], "not_run")
        self.assertIsNone(invocation(value, "replacement_b")["checks"]["group_finalized"])
        invocation(value, "accepted_a")["checks"]["process_cleanup"] = False
        value["cleanup_complete"] = False
        project(value)
        self.reject(value, "webdav_execution_order_invalid")

    def test_group_failure_prevents_later_standalone_execution(self):
        value = failed_group()
        value["cases"]["permission_denied"] = receipt()["cases"]["permission_denied"]
        project(value)
        self.reject(value, "webdav_execution_order_invalid")

    def test_every_cleanup_observation_gates_top_level_truth(self):
        for leaf in CHECKS:
            for key in ("temp_cleanup", "process_cleanup", "fixture_cleanup"):
                value = receipt()
                item = invocation(value, leaf)
                item.update(status="failed", failure_code="cleanup_failed")
                item["checks"][key] = False
                value["errors"] = ["cleanup_failed"]
                project(value)
                self.reject(value)
        value = receipt()
        value.update(cleanup_complete=False, result="failed", errors=["cleanup_failed"])
        self.reject(value, "webdav_capabilities_inconsistent")
        project(value)
        self.check(value)

    def test_public_errors_and_statuses_are_finite_typed_and_cross_bound(self):
        for bad in (["PRIVATE_CANARY"], ["cleanup_failed", "cleanup_failed"], [["cleanup_failed"]], None, True):
            value = receipt()
            value["errors"] = bad
            self.reject(value, "webdav_errors_invalid")
        for bad in (True, [], {}, "unknown"):
            value = receipt()
            invocation(value, "listing")["status"] = bad
            self.reject(value, "webdav_status_invalid")
        value = failed_group()
        value["errors"] = ["cleanup_failed"]
        self.reject(value, "webdav_failure_invalid")
        value = receipt()
        value.update(result="failed", errors=[])
        self.reject(value)

    def test_freshness_time_types_and_bounds(self):
        for value in ("2026-10-08T23:59:59Z", "2026-10-10T00:05:01Z", "2026-13-01T00:00:00Z",
                      "2026-10-10T00:00:00+00:00", "2026-10-10T00:00:00.0Z", 1, None):
            changed = receipt()
            changed["created_at"] = value
            self.reject(changed)
        for value in (True, 0, -1, 25, float("inf"), float("nan"), "24"):
            with self.assertRaises(E.ApplicationEvidenceError):
                self.check(receipt(), max_age_hours=value)
        for now in (datetime(2026, 10, 10), "2026-10-10", False):
            with self.assertRaises(E.ApplicationEvidenceError):
                E.validate_receipt(receipt(), RUNTIME, bindings(), now=now)
        value = receipt()
        value["created_at"] = (NOW - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.check(value)

    def test_bounded_json_no_duplicate_keys_nonfinite_or_private_error_echo(self):
        for data in (b'', b'{"x":1,"x":2}', b'{"x":{"y":1,"y":2}}', b'{"x":NaN}', b'{"x":Infinity}',
                     b'\xff', b'[' * 2000, b' ' * (256 * 1024 + 1), 'not-bytes'):
            with self.assertRaises(E.ApplicationEvidenceError) as raised:
                E.parse_receipt(data)
            self.assertNotIn("PRIVATE_CANARY", str(raised.exception))
        self.assertEqual(E.parse_receipt(E.compact(receipt())), receipt())

    def test_independent_literal_payloads_directory_time_and_hash_semantics(self):
        data = {"README-synthetic.txt": b"synthetic application fixture\n", "large/cancel.bin": bytes(range(256)) * 8192,
                "nested/binary.bin": bytes(range(256)), "nested/spaced name.txt": b"spaces remain exact\n"}
        expected = {"remote": "Synthetic", "vendor": "other", "transport": "loopback_http", "auth_redirect": False,
                    "modified": "2025-01-02T03:04:05Z", "directories": ["large", "nested"], "listing_hashes": "unavailable",
                    "files": [{"path": name, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
                              for name, payload in sorted(data.items())]}
        self.assertEqual(E.fixture_manifest(), expected)

    def prepare_tree(self, root):
        for name in (*E.HARNESS_FILES, "rclone-triage/Cargo.toml", "rclone-triage/Cargo.lock", "rclone-triage/build.rs",
                     "rclone-triage/.cargo/config.toml", "rclone-triage/src/main.rs", "rclone-version.env", "application.exe"):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"synthetic bytes\n")
        (root / "scripts/application_evidence.py").write_bytes(SOURCE.with_name("application_evidence.py").read_bytes())

    def test_each_fixed_harness_and_build_input_is_bound_without_loading_producer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.prepare_tree(root)
            before = E.compute_bindings(root, root / "application.exe", "d" * 40)
            self.assertEqual(len(E.HARNESS_FILES), 9)
            for name in E.HARNESS_FILES:
                path = root / name
                data = path.read_bytes()
                path.write_bytes(data + b"mutation\n")
                try:
                    if name == "scripts/application_evidence.py":
                        with self.assertRaisesRegex(E.ApplicationEvidenceError, "webdav_shared_contract_changed"):
                            E.compute_bindings(root, root / "application.exe", "d" * 40)
                    else:
                        after = E.compute_bindings(root, root / "application.exe", "d" * 40)
                        self.assertNotEqual(after["harness_sha256"], before["harness_sha256"])
                finally:
                    path.write_bytes(data)
            for name, key in (("application.exe", "application_sha256"), ("rclone-version.env", "runtime_manifest_sha256"),
                              ("rclone-triage/Cargo.lock", "cargo_lock_sha256"),
                              ("rclone-triage/.cargo/config.toml", "application_source_sha256"),
                              ("rclone-triage/src/main.rs", "application_source_sha256")):
                path = root / name
                data = path.read_bytes()
                path.write_bytes(data + b"changed")
                self.assertNotEqual(E.compute_bindings(root, root / "application.exe", "d" * 40)[key], before[key])
                path.write_bytes(data)

    def test_runtime_manifest_is_closed_x64_and_never_invoked(self):
        keys = ("RCLONE_EXE_SHA256", "RCLONE_WINDOWS_ZIP_SHA256", "RCLONE_LINUX_ZIP_SHA256", "RCLONE_LINUX_EXE_SHA256")
        valid = "# synthetic\nRCLONE_VERSION=1.75.2\n" + "".join(key + "=" + "a" * 64 + "\n" for key in keys)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "rclone-version.env"
            path.write_text(valid, encoding="ascii")
            self.assertEqual(E.runtime_binding(root), RUNTIME)
            for bad in (valid + "RCLONE_VERSION=1.75.2\n", valid + "OTHER=private\n", valid.replace("1.75.2", "01.75.2"),
                        valid.replace("a" * 64, "A" * 64), valid + "RCLONE_WINDOWS_X86_EXE_SHA256=" + "b" * 64 + "\n"):
                path.write_text(bad, encoding="ascii")
                with self.assertRaises(E.ApplicationEvidenceError):
                    E.runtime_binding(root)
            architecture = ("RCLONE_WINDOWS_X86_EXE_SHA256", "RCLONE_WINDOWS_X86_ZIP_SHA256",
                            "RCLONE_WINDOWS_ARM64_EXE_SHA256", "RCLONE_WINDOWS_ARM64_ZIP_SHA256")
            path.write_text(valid + "".join(key + "=" + "b" * 64 + "\n" for key in architecture), encoding="ascii")
            self.assertEqual(E.runtime_binding(root), RUNTIME)

    def test_same_handle_receipt_read_rejects_replacement_or_midread_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            path.write_bytes(E.compact(receipt()))
            self.assertEqual(E.load_receipt(path), receipt())
            original = E.os.fstat
            count = 0
            def changed(fd):
                nonlocal count
                result = original(fd)
                count += 1
                if count == 2:
                    class Changed:
                        st_dev, st_ino, st_size = result.st_dev, result.st_ino, result.st_size
                        st_mtime_ns, st_ctime_ns = result.st_mtime_ns + 1, result.st_ctime_ns
                    return Changed()
                return result
            with patch.object(E.os, "fstat", side_effect=changed):
                with self.assertRaisesRegex(E.ApplicationEvidenceError, "webdav_file_changed"):
                    E.load_receipt(path)


if __name__ == "__main__":
    unittest.main()
