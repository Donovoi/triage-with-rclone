"""Pure finite-registry integration tests; no runtime, server or app executes."""
from copy import deepcopy
import contextlib
from datetime import datetime
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from test_application_evidence import bindings as http_bindings, receipt as original_http_receipt
from test_provider_coverage import coverage as C, policy_for, schema
from test_webdav_application_evidence import E as W, NOW, RUNTIME, receipt as original_webdav_receipt

HTTP = ("http", "http_anonymous_cli_v1", "windows")
DAV = ("webdav", "webdav_basic_loopback_cli_v1", "windows")
CAPS = {"listing", "download_hash", "manifest_integrity", "source_preservation", "cancellation", "cleanup"}


def webdav_bindings():
    value = http_bindings()
    value.update(harness_sha256="3" * 64, fixture_manifest_sha256="4" * 64)
    return value


def receipt(key):
    value = original_http_receipt() if key == HTTP else original_webdav_receipt()
    value.update(runtime=dict(RUNTIME), created_at="2026-10-10T00:00:00Z",
                 bindings=http_bindings() if key == HTTP else webdav_bindings())
    return value


class FixedDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW


class ApplicationModeLedgerTests(unittest.TestCase):
    def setUp(self):
        self.catalog = C.catalog_from_schemas([schema("http"), schema("webdav")])
        self.policy = policy_for(self.catalog, application=False, vendor=False)
        self.policy["reviewed_runtime_version"] = RUNTIME["version"]
        self.policy["profiles"]["test"]["required"]["application"] = sorted(CAPS)
        self.bindings = {HTTP: http_bindings(), DAV: webdav_bindings()}
        for target in ("subprocess.Popen", "socket.socket", "socket.create_connection"):
            boundary = patch(target, side_effect=AssertionError("native_boundary_forbidden"))
            boundary.start()
            self.addCleanup(boundary.stop)

    def evaluate(self, receipts, **kwargs):
        options = dict(now=NOW, application_receipts=receipts, application_bindings=deepcopy(self.bindings))
        options.update(kwargs)
        return C.evaluate(self.catalog, self.policy, RUNTIME, [], None, **options)

    def row(self, report, backend):
        return next(row for row in report["providers"] if row["backend"] == backend)

    def app(self, report, backend):
        return self.row(report, backend)["evidence"]["application"]

    def test_registry_is_exact_finite_read_only_and_has_distinct_completion_rights(self):
        self.assertEqual(set(C.APPLICATION_REGISTRY), {HTTP, DAV,
            ("local", "local_filesystem_cli_v1", "windows"),
            ("archive", "archive_zip_local_cli_v1", "windows")})
        self.assertEqual(dict(C.APPLICATION_REGISTRY[HTTP]), {"module": "application_evidence.py",
            "producer": "application-lab/run_windows_http.py", "can_complete_application": True})
        self.assertEqual(dict(C.APPLICATION_REGISTRY[DAV]), {"module": "webdav_application_evidence.py",
            "producer": "application-lab/run_windows_webdav.py", "can_complete_application": False})
        with self.assertRaises(TypeError):
            C.APPLICATION_REGISTRY[DAV]["can_complete_application"] = True

    def test_legacy_http_flat_bindings_have_identical_report_to_explicit_map(self):
        flat = self.evaluate([receipt(HTTP)], application_bindings=http_bindings())
        keyed = self.evaluate([receipt(HTTP)], application_bindings={HTTP: http_bindings()})
        self.assertEqual(flat, keyed)
        app = self.app(flat, "http")
        self.assertEqual(set(app), {"status", "capabilities", "runs", "modes"})
        self.assertEqual(app["status"], "passed")
        self.assertEqual(app["capabilities"], dict.fromkeys(CAPS, "passed"))
        self.assertEqual(set(app["modes"]), {"http_anonymous_cli_v1"})
        self.assertEqual(app["modes"][HTTP[1]]["runs"], app["runs"])
        self.assertEqual(C.gate_errors(flat, require_application=["http"]), [])

    def test_mixed_receipts_keep_independent_mode_bindings_in_either_order(self):
        for keys in ((HTTP, DAV), (DAV, HTTP)):
            with self.subTest(keys=keys):
                report = self.evaluate([receipt(key) for key in keys])
                self.assertEqual(report["errors"], [])
                for key in keys:
                    app = self.app(report, key[0])
                    self.assertEqual(set(app["modes"]), {key[1]})
                    self.assertEqual(app["modes"][key[1]]["status"], "passed")
                    self.assertEqual(app["runs"][0]["bindings"], self.bindings[key])
                self.assertEqual(self.app(report, "http")["status"], "passed")
                self.assertEqual(self.app(report, "webdav")["status"], "not_verified")
                self.assertEqual(C.gate_errors(report, require_application_modes=[HTTP, DAV]), [])
                self.assertEqual(C.gate_errors(report, require_application=["webdav"]), ["required_application_not_verified"])
                self.assertFalse(report["all_complete"])

    def test_webdav_does_not_upgrade_authentication_vendor_or_weakened_application(self):
        for needed in (sorted(CAPS), ["cleanup"]):
            self.policy["profiles"]["test"]["required"]["application"] = needed
            report = self.evaluate([receipt(DAV)])
            row = self.row(report, "webdav")
            self.assertEqual(row["evidence"]["application"]["status"], "not_verified")
            self.assertEqual(row["evidence"]["local_protocol"]["status"], "not_verified")
            self.assertEqual(row["evidence"]["vendor"]["status"], "not_applicable")
            self.assertFalse(row["complete"])
            self.assertEqual(C.gate_errors(report, require_application_modes=[DAV]), [])
        self.policy = policy_for(self.catalog, application=True, vendor=True)
        self.policy["reviewed_runtime_version"] = RUNTIME["version"]
        report = self.evaluate([receipt(DAV)])
        app = self.app(report, "webdav")
        self.assertEqual(app["capabilities"]["authentication"], "not_verified")
        self.assertEqual(app["capabilities"]["refresh"], "not_verified")
        self.assertEqual(self.row(report, "webdav")["evidence"]["vendor"]["status"], "not_verified")

    def test_flat_http_expectations_cannot_be_reused_for_webdav(self):
        value = receipt(DAV)
        value["bindings"] = http_bindings()
        report = self.evaluate([value], application_bindings=http_bindings())
        self.assertIn("application_bindings_invalid", report["errors"])
        self.assertNotIn("modes", self.app(report, "webdav"))

    def test_swapped_or_missing_mode_bindings_fail_instead_of_using_other_mode(self):
        for expected in ({HTTP: webdav_bindings(), DAV: http_bindings()}, {HTTP: http_bindings()},
                         {DAV: webdav_bindings()}, None, {}, {**http_bindings(), DAV: webdav_bindings()},
                         {DAV: None}, {("webdav", "future", "windows"): webdav_bindings()}):
            with self.subTest(keys=str(type(expected))):
                report = self.evaluate([receipt(HTTP), receipt(DAV)], application_bindings=expected)
                self.assertTrue(report["errors"])
                self.assertTrue(C.gate_errors(report, require_application_modes=[HTTP, DAV]))

    def test_unknown_unhashable_and_path_shaped_receipt_keys_never_load_code(self):
        mutations = (("backend", "../PRIVATE_CANARY"), ("fixture_mode", "future_mode"),
                     ("platform", "linux"), ("backend", ["webdav"]), ("fixture_mode", {}),
                     ("platform", True), ("fixture_mode", None))
        for field, value in mutations:
            candidate = receipt(DAV)
            candidate[field] = value
            with self.subTest(field=field, kind=type(value).__name__), \
                    patch.object(C, "application_module", side_effect=AssertionError("import_forbidden")):
                report = self.evaluate([candidate])
            self.assertIn("application_mode_unsupported", report["errors"])
            self.assertNotIn("PRIVATE_CANARY", json.dumps(report))
            self.assertNotIn("modes", self.app(report, "webdav"))

    def test_unknown_binding_map_keys_fail_before_any_receipt_helper_import(self):
        with patch.object(C, "application_module", side_effect=AssertionError("import_forbidden")):
            report = self.evaluate([receipt(DAV)], application_bindings={
                DAV: webdav_bindings(), ("webdav", "../PRIVATE_CANARY", "windows"): webdav_bindings()})
        self.assertTrue(report["errors"])
        self.assertNotIn("PRIVATE_CANARY", json.dumps(report))
        self.assertNotIn("modes", self.app(report, "webdav"))

    def test_helper_error_classes_are_caught_per_mode_and_never_erase_other_backend(self):
        for failed_key, passed_key in ((HTTP, DAV), (DAV, HTTP)):
            invalid = receipt(failed_key)
            invalid["private_field"] = "PRIVATE_CANARY"
            for values in ([invalid, receipt(passed_key)], [receipt(passed_key), invalid]):
                report = self.evaluate(values)
                self.assertTrue(report["errors"])
                self.assertNotIn("PRIVATE_CANARY", json.dumps(report))
                self.assertEqual(self.app(report, passed_key[0])["modes"][passed_key[1]]["status"], "passed")
                self.assertNotIn("modes", self.app(report, failed_key[0]))

    def test_failed_mode_and_backend_are_sticky_in_both_orders(self):
        for key in (HTTP, DAV):
            failed = receipt(key)
            failed.update(result="failed", errors=["session_failed"])
            for values in ([failed, receipt(key)], [receipt(key), failed]):
                report = self.evaluate(values)
                app = self.app(report, key[0])
                self.assertEqual(report["errors"], [])
                self.assertEqual(app["status"], "failed")
                self.assertEqual(app["capabilities"], dict.fromkeys(CAPS, "passed"))
                self.assertEqual(app["modes"][key[1]]["status"], "failed")
                self.assertEqual(len(app["modes"][key[1]]["runs"]), 2)
                self.assertIn("required_application_mode_not_verified",
                              C.gate_errors(report, require_application_modes=[key]))

    def test_webdav_cleanup_failure_cannot_be_repaired_by_successful_receipt(self):
        failed = receipt(DAV)
        failed.update(cleanup_complete=False, errors=["cleanup_failed"], result="failed")
        failed["capabilities"] = W.derive_capabilities(failed["cases"], False)
        for batch in ([failed, receipt(DAV)], [receipt(DAV), failed]):
            report = self.evaluate(batch)
            app = self.app(report, "webdav")
            self.assertEqual(report["errors"], [])
            self.assertEqual(app["status"], "failed")
            self.assertEqual(app["capabilities"]["cleanup"], "failed")
            self.assertEqual(app["modes"][DAV[1]]["capabilities"]["cleanup"], "failed")

    def test_failure_on_one_backend_does_not_select_or_poison_another_helper(self):
        failed = receipt(DAV)
        failed.update(result="failed", errors=["session_failed"])
        for values in ([failed, receipt(HTTP)], [receipt(HTTP), failed]):
            report = self.evaluate(values)
            self.assertEqual(self.app(report, "webdav")["status"], "failed")
            self.assertEqual(self.app(report, "http")["status"], "passed")
            self.assertEqual(C.gate_errors(report, require_application=["http"], require_application_modes=[HTTP]), [])

    def test_full_webdav_contract_required_even_when_policy_needs_only_cleanup(self):
        self.policy["profiles"]["test"]["required"]["application"] = ["cleanup"]
        for mutation in ("missing_invocation", "missing_check", "overclaim", "missing_group"):
            candidate = receipt(DAV)
            if mutation == "missing_invocation":
                del candidate["cases"]["revoked_credentials"]["invocations"]["accepted_a"]
            elif mutation == "missing_check":
                del candidate["cases"]["truncated_transfer"]["invocations"]["truncated_transfer"]["checks"]["truncation_observed"]
            elif mutation == "overclaim":
                candidate["claims"]["authentication_verified"] = True
            else:
                del candidate["credential_group"]
            report = self.evaluate([candidate])
            self.assertTrue(report["errors"])
            self.assertTrue(C.gate_errors(report, require_application_modes=[DAV]))
            self.assertNotIn("modes", self.app(report, "webdav"))

    def test_stale_future_runtime_and_source_binding_failures_cannot_satisfy_gate(self):
        candidates = []
        for changed in ("2026-10-08T23:59:59Z", "2026-10-10T00:05:01Z"):
            candidate = receipt(DAV)
            candidate["created_at"] = changed
            candidates.append(candidate)
        candidate = receipt(DAV)
        candidate["runtime"]["sha256"] = "0" * 64
        candidates.append(candidate)
        for field in webdav_bindings():
            candidate = receipt(DAV)
            candidate["bindings"][field] = "0" * 64 if field.endswith("sha256") else "changed"
            candidates.append(candidate)
        for candidate in candidates:
            report = self.evaluate([candidate])
            self.assertTrue(report["errors"])
            self.assertTrue(C.gate_errors(report, require_application_modes=[DAV]))

    def test_catalog_and_policy_currentness_are_mandatory_for_mode_gate(self):
        original = deepcopy(self.policy)
        for mutation in ("runtime_review", "schema", "review_required"):
            self.policy = deepcopy(original)
            if mutation == "runtime_review":
                self.policy["reviewed_runtime_version"] = "1.75.1"
            elif mutation == "schema":
                self.policy["providers"]["webdav"]["schema_sha256"] = "0" * 64
            else:
                self.policy["profiles"]["test"]["review_required"] = True
            report = self.evaluate([receipt(DAV)])
            self.assertEqual(report["errors"], [])
            self.assertEqual(self.app(report, "webdav")["status"], "not_verified")
            self.assertIn("required_application_mode_not_verified", C.gate_errors(report, require_application_modes=[DAV]))
        self.policy = original
        self.catalog = [row for row in self.catalog if row["backend"] == "http"]
        report = self.evaluate([receipt(DAV)])
        self.assertIn("application_backend_absent_from_catalog", report["errors"])
        self.assertTrue(C.gate_errors(report, require_application_modes=[DAV]))

    def test_mode_gate_rechecks_complete_contract_backend_failure_and_exact_platform(self):
        for mutation in ("cap_missing", "cap_failed", "backend_failed", "platform", "unknown"):
            report = self.evaluate([receipt(DAV)])
            app = self.app(report, "webdav")
            if mutation == "cap_missing":
                del app["modes"][DAV[1]]["capabilities"]["cancellation"]
            elif mutation == "cap_failed":
                app["modes"][DAV[1]]["capabilities"]["cleanup"] = "failed"
            elif mutation == "backend_failed":
                app["status"] = "failed"
            elif mutation == "platform":
                report["runtime"]["platform"] = "linux"
            requested = ("webdav", "future_mode", "windows") if mutation == "unknown" else DAV
            self.assertTrue(C.gate_errors(report, require_application_modes=[requested]))

    def test_mode_cli_parser_accepts_only_registered_exact_triplets(self):
        self.assertEqual(C.parse_required_application_modes([":".join(DAV), ":".join(HTTP), ":".join(DAV)]), [HTTP, DAV])
        for value in ("webdav", DAV[1], ":".join(DAV) + ":extra", ":".join(DAV) + " ",
                      "webdav:future:windows", "webdav:webdav_basic_loopback_cli_v1:linux", "", None):
            with self.subTest(value=value), self.assertRaises(C.CoverageError):
                C.parse_required_application_modes([value])

    def test_fixed_binding_computation_uses_http_producer_and_webdav_literal_manifest_api(self):
        http = SimpleNamespace(compute_bindings=Mock(return_value=http_bindings()))
        dav = SimpleNamespace(compute_bindings=Mock(return_value=webdav_bindings()))
        producer = SimpleNamespace(fixture_manifest=Mock(return_value={"literal_http": True}))
        def module(producer=False, *, key=HTTP):
            return globals_producer if producer else http if key == HTTP else dav
        globals_producer = producer
        with patch.object(C, "application_module", side_effect=module) as load:
            self.assertEqual(C.compute_application_bindings(Path("app.exe"), "d" * 40), http_bindings())
            self.assertEqual(C.compute_application_bindings(Path("app.exe"), "d" * 40, key=DAV), webdav_bindings())
        http.compute_bindings.assert_called_once_with(C.ROOT, Path("app.exe"), "d" * 40, {"literal_http": True})
        dav.compute_bindings.assert_called_once_with(C.ROOT, Path("app.exe"), "d" * 40)
        self.assertEqual(load.call_count, 3)
        with patch.object(C, "application_module", side_effect=AssertionError("import_forbidden")):
            with self.assertRaises(C.CoverageError):
                C.compute_application_bindings(Path("app.exe"), "d" * 40, key=("webdav", "future", "windows"))

    def test_cli_computes_both_bindings_and_writes_failure_for_full_webdav_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy, output, http, dav = [root / name for name in ("policy.json", "report.json", "http.json", "dav.json")]
            policy.write_text(json.dumps(self.policy), encoding="utf-8")
            http.write_text(json.dumps(receipt(HTTP)), encoding="utf-8")
            dav.write_text(json.dumps(receipt(DAV)), encoding="utf-8")
            args = ["--rclone", str(root / "never-executed"), "--policy", str(policy), "--report", str(output),
                    "--application", str(root / "app.exe"), "--application-build-commit", "d" * 40,
                    "--application-receipt", str(http), "--application-receipt", str(dav),
                    "--require-application-mode", ":".join(HTTP), "--require-application-mode", ":".join(DAV)]
            def compute(_application, _commit, *, key=HTTP):
                return deepcopy(self.bindings[key])
            with patch.object(C, "query_runtime", return_value=(RUNTIME, self.catalog)), \
                    patch.object(C, "compute_application_bindings", side_effect=compute) as binding, \
                    patch.object(C, "datetime", FixedDatetime), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(C.main(args), 0)
                self.assertEqual({call.kwargs["key"] for call in binding.call_args_list}, {HTTP, DAV})
                result = json.loads(output.read_text())
                self.assertEqual(self.app(result, "webdav")["status"], "not_verified")
                output.unlink()
                self.assertEqual(C.main(args + ["--require-application", "webdav"]), 1)
                self.assertEqual(json.loads(output.read_text())["gate_errors"], ["required_application_not_verified"])
                output.unlink()
                dav.write_text('{"backend":"webdav","backend":"webdav"}', encoding="utf-8")
                self.assertEqual(C.main(args), 1)
                self.assertTrue(json.loads(output.read_text())["gate_errors"])


if __name__ == "__main__":
    unittest.main()
