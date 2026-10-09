"""Application ledger integration: no native app, runtime or helper execution."""

import contextlib
from datetime import datetime
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_application_evidence import EVIDENCE, NOW, RUNTIME, bindings, receipt
from test_provider_coverage import coverage, policy_for, schema


class FixedDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW


class ApplicationLedgerTests(unittest.TestCase):
    def setUp(self):
        self.catalog = coverage.catalog_from_schemas([schema()])
        self.policy = policy_for(self.catalog, application=False, vendor=False)
        self.policy["profiles"]["test"]["required"]["application"] = [
            "listing", "download_hash", "manifest_integrity", "source_preservation", "cancellation", "cleanup"]

    def evaluate(self, receipts, **options):
        parameters = dict(now=NOW, application_receipts=receipts, application_bindings=bindings())
        parameters.update(options)
        return coverage.evaluate(self.catalog, self.policy, RUNTIME, [], None, **parameters)

    def app(self, report):
        return report["providers"][0]["evidence"]["application"]

    def test_valid_same_build_receipt_credits_only_windows_application(self):
        report = self.evaluate([receipt()])
        self.assertEqual(report["errors"], [])
        self.assertEqual(self.app(report)["status"], "passed")
        self.assertEqual(report["providers"][0]["evidence"]["local_protocol"]["status"], "not_verified")
        self.assertEqual(report["providers"][0]["evidence"]["vendor"]["status"], "not_applicable")
        self.assertFalse(report["all_complete"])
        mode = self.app(report)["modes"]["http_anonymous_cli_v1"]
        self.assertEqual(mode["status"], "passed")
        self.assertEqual(mode["runs"][0]["bindings"], bindings())
        self.assertEqual(mode["runs"][0]["expires_utc"], "2026-10-06T00:00:00Z")
        self.assertEqual(coverage.gate_errors(report, require_application=["http"]), [])
        self.assertIn("required_fixture_not_verified", coverage.gate_errors(report, require_fixtures=["http"]))

    def test_late_global_error_is_sticky_even_after_pass(self):
        failed = receipt()
        failed["errors"] = ["session_failed"]
        failed["result"] = "failed"
        for batch in ([failed, receipt()], [receipt(), failed]):
            with self.subTest(failed_first=batch[0]["result"] == "failed"):
                report = self.evaluate(batch)
                app = self.app(report)
                self.assertEqual(report["errors"], [])
                self.assertEqual(set(app["capabilities"].values()), {"passed"})
                self.assertEqual(app["status"], "failed")
                self.assertEqual(app["modes"]["http_anonymous_cli_v1"]["status"], "failed")
                self.assertEqual(len(app["runs"]), 2)
                self.assertIn("required_application_not_verified", coverage.gate_errors(report, require_application=["http"]))

    def test_late_cleanup_failure_is_sticky(self):
        failed = receipt()
        failed.update(cleanup_complete=False, result="failed", errors=["cleanup_failed"])
        failed["capabilities"] = EVIDENCE.derive_capabilities(failed["cases"], False)
        report = self.evaluate([failed, receipt()])
        self.assertEqual(self.app(report)["capabilities"]["cleanup"], "failed")
        self.assertEqual(self.app(report)["status"], "failed")

    def test_weakened_policy_cannot_hide_missing_or_failed_case(self):
        self.policy["profiles"]["test"]["required"]["application"] = ["cleanup"]
        missing = receipt()
        del missing["cases"]["denial"]
        report = self.evaluate([missing])
        self.assertTrue(report["errors"])
        self.assertEqual(self.app(report)["status"], "not_verified")
        failed = receipt()
        failed["cases"]["denial"].update(status="failed", failure_code="manifest_invalid")
        failed["cases"]["denial"]["checks"]["failed_result_exact"] = False
        failed["capabilities"] = EVIDENCE.derive_capabilities(failed["cases"])
        failed["result"] = "failed"
        report = self.evaluate([failed])
        self.assertEqual(report["errors"], [])
        self.assertEqual(self.app(report)["status"], "failed")

    def test_build_source_runtime_and_platform_mismatches_cannot_pass(self):
        for key in bindings():
            expected = bindings()
            expected[key] = "0" * 64 if key.endswith("sha256") else "changed"
            with self.subTest(binding=key):
                report = self.evaluate([receipt()], application_bindings=expected)
                self.assertTrue(report["errors"])
                self.assertNotEqual(self.app(report)["status"], "passed")
        for runtime in (dict(RUNTIME, platform="linux"), dict(RUNTIME, sha256="0" * 64)):
            report = coverage.evaluate(self.catalog, self.policy, runtime, [], None, now=NOW,
                                       application_receipts=[receipt()], application_bindings=bindings())
            self.assertTrue(report["errors"])
            self.assertNotEqual(self.app(report)["status"], "passed")

    def test_receipt_needs_independent_build_expectations(self):
        report = self.evaluate([receipt()], application_bindings=None)
        self.assertTrue(report["errors"])
        self.assertEqual(self.app(report)["status"], "not_verified")

    def test_application_receipt_cannot_enter_protocol_input(self):
        report = coverage.evaluate(self.catalog, self.policy, RUNTIME, [receipt()], "b" * 64, now=NOW)
        self.assertTrue(report["errors"])
        for tier in ("local_protocol", "application"):
            self.assertEqual(report["providers"][0]["evidence"][tier]["status"], "not_verified")

    def test_historical_cloud_summary_and_raw_fields_are_rejected(self):
        for value in ({"ledger_importable": False, "success": True}, dict(receipt(), account="PRIVATE_CANARY")):
            report = self.evaluate([value])
            self.assertTrue(report["errors"])
            self.assertNotIn("PRIVATE_CANARY", json.dumps(report))
            self.assertEqual(self.app(report)["status"], "not_verified")

    def test_new_and_retired_backends_remain_visible_without_inherited_credit(self):
        catalog = coverage.catalog_from_schemas([schema("newbackend")])
        report = coverage.evaluate(catalog, self.policy, RUNTIME, [], None, now=NOW,
                                   application_receipts=[receipt()], application_bindings=bindings())
        self.assertIn("application_backend_absent_from_catalog", report["errors"])
        self.assertEqual(report["retired_policy_backends"], ["http"])
        self.assertEqual(report["providers"][0]["policy_status"], "missing_plan")
        self.assertEqual(self.app(report)["status"], "not_verified")

    def test_cli_application_gate_and_binding_requirements(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy, report_path, receipt_path = [root / name for name in ("policy.json", "report.json", "receipt.json")]
            policy.write_text(json.dumps(self.policy), encoding="utf-8")
            receipt_path.write_text(json.dumps(receipt()), encoding="utf-8")
            common = ["--rclone", str(root / "unused-runtime"), "--policy", str(policy),
                      "--report", str(report_path), "--require-application", "http"]
            with patch.object(coverage, "query_runtime", return_value=(RUNTIME, self.catalog)), \
                    patch.object(coverage, "compute_application_bindings", return_value=bindings()) as compute, \
                    patch.object(coverage, "datetime", FixedDatetime), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(coverage.main(common), 1)
                compute.assert_not_called()
                report_path.unlink()
                args = common + ["--application-receipt", str(receipt_path)]
                self.assertEqual(coverage.main(args), 1)
                self.assertIn("application_build_binding_required", json.loads(report_path.read_text())["errors"])
                report_path.unlink()
                complete = args + ["--application", str(root / "app.exe"), "--application-build-commit", "d" * 40]
                self.assertEqual(coverage.main(complete), 0)
                compute.assert_called_once_with(root / "app.exe", "d" * 40)
                self.assertEqual(self.app(json.loads(report_path.read_text()))["status"], "passed")
                report_path.unlink()
                # Duplicate JSON keys must not silently choose the last value.
                receipt_path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
                self.assertEqual(coverage.main(complete), 1)
                self.assertTrue(json.loads(report_path.read_text())["errors"])


if __name__ == "__main__":
    unittest.main()
