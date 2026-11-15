"""Sia receipt rejection and scope tests, independent of native success."""
import copy
import json
from pathlib import Path
import unittest
from test_provider_coverage import coverage as C, NOW, RUNTIME, HARNESS, schema, receipt

ROOT = Path(__file__).resolve().parents[2]
CAPS = {"listing", "download_hash", "missing_object_rejection", "authentication_rejection",
        "read_denial", "source_preservation", "config_preservation", "fixture_write_rejection", "cleanup"}


class SiaCoverageTests(unittest.TestCase):
    def setUp(self):
        self.actual = json.loads((ROOT / "provider-coverage-policy.json").read_text())
        entry = copy.deepcopy(self.actual["providers"]["sia"])
        self.catalog = C.catalog_from_schemas([schema("sia")])
        entry["schema_sha256"] = self.catalog[0]["schema_sha256"]
        self.policy = {"schema_version": 2, "reviewed_runtime_version": RUNTIME["version"],
                       "providers": {"sia": entry}, "profiles": {
                           entry["profile"]: copy.deepcopy(self.actual["profiles"][entry["profile"]])}}

    def receipt(self):
        candidate = receipt("sia")
        candidate["backends"][0]["capabilities"] = dict.fromkeys(CAPS, "passed")
        return candidate

    def evaluate(self, receipts):
        return C.evaluate(self.catalog, self.policy, RUNTIME, receipts, HARNESS,
                          now=NOW, fixture_manifest_sha256="c" * 64)

    def reject(self, candidate):
        report = self.evaluate([candidate])
        self.assertTrue(report["errors"])
        self.assertNotEqual(report["providers"][0]["evidence"]["local_protocol"]["status"], "passed")
        self.assertIn("required_fixture_not_verified", C.gate_errors(report, require_fixtures=["sia"]))

    def test_exact_receipt_passes_protocol_only(self):
        report = self.evaluate([self.receipt()])
        self.assertEqual(report["errors"], [])
        self.assertEqual(C.gate_errors(report, require_plans=True, require_fixtures=["sia"]), [])
        row = report["providers"][0]
        self.assertEqual(row["evidence"]["local_protocol"]["status"], "passed")
        self.assertEqual(row["evidence"]["local_protocol"]["capabilities"], dict.fromkeys(CAPS, "passed"))
        for tier in ("application", "vendor"):
            self.assertEqual(row["evidence"][tier]["status"], "not_verified")
        self.assertFalse(row["complete"])
        self.assertIn("provider_coverage_incomplete", C.gate_errors(report, require_complete=True))

    def test_hosted_lifecycle_requirements_and_fingerprint_are_preserved(self):
        entry = self.actual["providers"]["sia"]
        profile = copy.deepcopy(self.actual["profiles"][entry["profile"]])
        self.assertEqual(set(profile["required"].pop("local_protocol")), CAPS)
        self.assertEqual(profile, self.actual["profiles"]["hosted-static-credentials-session-review"])
        self.assertEqual(entry["schema_sha256"], "d867d95aab13cd2c5127a23b6a16898b30aaf01f5e27a41abf2af7fa435d1409")
        self.assertEqual(entry["refresh_applicability"], "not_applicable")
        self.assertEqual(entry["reauthentication_applicability"], "review_required")

    def test_no_evidence_never_passes(self):
        report = self.evaluate([])
        self.assertIn("required_fixture_not_verified", C.gate_errors(report, require_fixtures=["sia"]))

    def test_missing_or_extra_capability_fails_even_with_weaker_policy(self):
        next(iter(self.policy["profiles"].values()))["required"]["local_protocol"] = ["listing"]
        for cap in CAPS:
            with self.subTest(missing=cap):
                candidate = self.receipt()
                del candidate["backends"][0]["capabilities"][cap]
                self.reject(candidate)
        for cap in ("refresh", "reauthentication", "authentication", "cancellation", "revocation"):
            with self.subTest(extra=cap):
                candidate = self.receipt()
                candidate["backends"][0]["capabilities"][cap] = "passed"
                self.reject(candidate)

    def test_stale_mismatched_or_relabelled_receipts_fail(self):
        for key, value in (("harness_sha256", "d" * 64), ("fixture_manifest_sha256", "d" * 64),
                           ("platform", "windows"), ("finished_utc", "2026-10-01T00:00:00Z"),
                           ("cleanup_passed", False), ("fixture_mode", "unreviewed")):
            with self.subTest(field=key):
                candidate = self.receipt()
                candidate[key] = value
                self.reject(candidate)
        for key, value in (("fixture_kind", "local"), ("fixture_mode", "unsecured"), ("new_field", True)):
            candidate = self.receipt()
            candidate["backends"][0][key] = value
            self.reject(candidate)
        candidate = self.receipt()
        candidate["runtime"]["sha256"] = "d" * 64
        self.reject(candidate)

    def test_failure_survives_a_later_pass(self):
        failed = self.receipt()
        failed["success"] = False
        failed["backends"][0]["capabilities"]["read_denial"] = "failed"
        failed["backends"][0]["errors"] = ["sia_read_denial_not_observed"]
        for candidates in ((failed, self.receipt()), (self.receipt(), failed)):
            report = self.evaluate(list(candidates))
            self.assertEqual(report["providers"][0]["evidence"]["local_protocol"]["status"], "failed")
            self.assertIn("required_fixture_not_verified", C.gate_errors(report, require_fixtures=["sia"]))


if __name__ == "__main__":
    unittest.main()
