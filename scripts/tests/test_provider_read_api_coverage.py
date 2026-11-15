"""Closed configured-read protocol receipts never promote broader acceptance."""
import copy
import json
from pathlib import Path
import unittest
from test_provider_coverage import coverage as C, NOW, RUNTIME, HARNESS, schema, receipt

ROOT = Path(__file__).resolve().parents[2]
COMMON = {"listing", "download_hash", "missing_object_rejection", "read_denial",
          "source_preservation", "config_preservation", "fixture_write_rejection", "cleanup"}
CAPS = {"shade": COMMON | {"shade_saved_token_read", "shade_saved_token_rejection"},
        "sharefile": COMMON | {"sharefile_saved_token_read", "sharefile_saved_token_rejection"},
        "quatrix": COMMON | {"authentication_rejection"},
        "hidrive": COMMON | {"hidrive_saved_token_read", "hidrive_saved_token_rejection"},
        "doi": COMMON | {"anonymous_read", "dataverse_read", "invenio_read", "zenodo_read",
                         "resolver_rejection", "native_write_rejection"}}
PROFILES = {
    "shade": "hosted-renewal", "sharefile": "hosted-renewal-session-review",
    "quatrix": "hosted-static-credentials", "hidrive": "hosted-renewal-session-review",
    "doi": "public-read",
}
FINGERPRINTS = {
    "shade": "11fae1d2dbe98923f926912b19dde9d1e24390d55e89d65eb642d30675f41621",
    "sharefile": "93f298c423ecefef1f719c07812642728abd3c8fb4e741194b3167a70e8aeccf",
    "quatrix": "f90fa0650d2d29240abe716966a00a67fe2cbebb8c11404c719867ee814a8b49",
    "hidrive": "5170bdd6ed2be46aa6d09a4ad70ba0251db0d979b06710feca5977789338fd3c",
    "doi": "bf1688a020f582f70c21120e596325f8f84f03877b8e70cc1ef79d870a8217f0",
}


class ReadApiCoverageTests(unittest.TestCase):
    def setUp(self):
        self.actual = json.loads((ROOT / "provider-coverage-policy.json").read_text())

    def setup_backend(self, backend):
        self.backend = backend
        entry = copy.deepcopy(self.actual["providers"][backend])
        self.catalog = C.catalog_from_schemas([schema(backend)])
        entry["schema_sha256"] = self.catalog[0]["schema_sha256"]
        self.policy = {"schema_version": 2, "reviewed_runtime_version": RUNTIME["version"],
                       "providers": {backend: entry}, "profiles": {
                           entry["profile"]: copy.deepcopy(self.actual["profiles"][entry["profile"]])}}

    def receipt(self):
        candidate = receipt(self.backend)
        candidate["backends"][0]["capabilities"] = dict.fromkeys(CAPS[self.backend], "passed")
        return candidate

    def evaluate(self, receipts):
        return C.evaluate(self.catalog, self.policy, RUNTIME, receipts, HARNESS,
                          now=NOW, fixture_manifest_sha256="c" * 64)

    def reject(self, candidate):
        report = self.evaluate([candidate])
        self.assertTrue(report["errors"])
        self.assertNotEqual(report["providers"][0]["evidence"]["local_protocol"]["status"], "passed")
        self.assertIn("required_fixture_not_verified", C.gate_errors(report, require_fixtures=[self.backend]))

    def test_exact_receipts_qualify_only_the_reviewed_protocol_layer(self):
        for backend in CAPS:
            with self.subTest(backend=backend):
                self.setup_backend(backend)
                report = self.evaluate([self.receipt()])
                self.assertEqual(report["errors"], [])
                self.assertEqual(C.gate_errors(report, require_plans=True, require_fixtures=[backend]), [])
                row = report["providers"][0]
                self.assertEqual(row["evidence"]["local_protocol"]["capabilities"], dict.fromkeys(CAPS[backend], "passed"))
                self.assertEqual(row["evidence"]["application"]["status"], "not_verified")
                self.assertFalse(row["complete"])
                self.assertIn("provider_coverage_incomplete", C.gate_errors(report, require_complete=True))

    def test_prior_application_vendor_lifecycle_and_schema_obligations_remain(self):
        for backend in CAPS:
            entry = self.actual["providers"][backend]
            profile = copy.deepcopy(self.actual["profiles"][entry["profile"]])
            self.assertEqual(set(profile["required"].pop("local_protocol")), CAPS[backend])
            self.assertEqual(profile, self.actual["profiles"][PROFILES[backend]])
            self.assertEqual(entry["schema_sha256"], FINGERPRINTS[backend])
        hi = self.actual["providers"]["hidrive"]
        self.assertEqual(hi["refresh_applicability"], "required")
        self.assertEqual(hi["reauthentication_applicability"], "review_required")
        self.assertEqual(self.actual["providers"]["doi"]["auth_applicability"], "none")

    def test_absence_and_each_missing_capability_fail_even_with_weaker_policy(self):
        for backend in CAPS:
            self.setup_backend(backend)
            self.assertIn("required_fixture_not_verified", C.gate_errors(self.evaluate([]), require_fixtures=[backend]))
            next(iter(self.policy["profiles"].values()))["required"]["local_protocol"] = ["listing"]
            for cap in CAPS[backend]:
                with self.subTest(backend=backend, missing=cap):
                    candidate = self.receipt()
                    del candidate["backends"][0]["capabilities"][cap]
                    self.reject(candidate)

    def test_authentication_lifecycle_and_cross_backend_claims_cannot_be_smuggled(self):
        for backend in CAPS:
            self.setup_backend(backend)
            for cap in ({"authentication", "authentication_rejection", "refresh", "reauthentication",
                         "revocation", "cancellation", "anonymous_read", "saved_token_read",
                         "dataverse_read", "invenio_read", "zenodo_read", "native_write_rejection",
                         "hidrive_saved_token_read", "hidrive_saved_token_rejection",
                         "shade_saved_token_read", "shade_saved_token_rejection",
                         "sharefile_saved_token_read", "sharefile_saved_token_rejection"} - CAPS[backend]):
                candidate = self.receipt()
                candidate["backends"][0]["capabilities"][cap] = "passed"
                self.reject(candidate)

    def test_source_runtime_platform_and_freshness_bindings_fail_closed(self):
        for backend in CAPS:
            self.setup_backend(backend)
            for key, value in (("harness_sha256", "d" * 64), ("fixture_manifest_sha256", "d" * 64),
                               ("platform", "windows"), ("finished_utc", "2026-10-01T00:00:00Z"),
                               ("cleanup_passed", False), ("fixture_mode", "unreviewed"), ("scope_extra", "vendor")):
                with self.subTest(backend=backend, key=key):
                    candidate = self.receipt()
                    candidate[key] = value
                    self.reject(candidate)
            for key, value in (("sha256", "d" * 64), ("extra", "unreviewed")):
                candidate = self.receipt()
                candidate["runtime"][key] = value
                self.reject(candidate)
            for key, value in (("fixture_kind", "local"), ("fixture_mode", "other"), ("extra", True)):
                candidate = self.receipt()
                candidate["backends"][0][key] = value
                self.reject(candidate)

    def test_failed_mode_cannot_be_hidden_by_a_later_success(self):
        for backend in CAPS:
            self.setup_backend(backend)
            for cap in CAPS[backend]:
                failed = self.receipt()
                failed["success"] = False
                failed["backends"][0]["capabilities"][cap] = "failed"
                failed["backends"][0]["errors"] = ["observed_case_failure"]
                for candidates in ((failed, self.receipt()), (self.receipt(), failed)):
                    report = self.evaluate(list(candidates))
                    self.assertEqual(report["providers"][0]["evidence"]["local_protocol"]["status"], "failed")
                    self.assertIn("required_fixture_not_verified", C.gate_errors(report, require_fixtures=[backend]))


if __name__ == "__main__":
    unittest.main()
