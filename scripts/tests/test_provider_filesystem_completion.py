"""Pure combined-evidence gates for the two reviewed Windows baselines."""
from copy import deepcopy
from datetime import timedelta
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from test_provider_filesystem_application_modes import C, FILESYSTEM, NOW, RUNTIME, receipt
from test_provider_coverage import receipt as protocol_template, schema


HARNESS = "7" * 64
MANIFEST = "8" * 64
PROTOCOL = {
    "local": ("listing", "download_hash", "missing_object_rejection", "source_preservation", "cleanup"),
    "archive": ("listing", "download_hash", "missing_object_rejection", "source_preservation", "cleanup",
                "archive_crc32", "directory_as_file_rejection", "corrupt_member_rejection",
                "truncated_archive_rejection", "fixture_write_rejection", "config_preservation"),
}


def protocol(backend):
    value = protocol_template(backend)
    value.update(runtime={key: RUNTIME[key] for key in ("version", "sha256")}, platform="windows",
                 harness_sha256=HARNESS, fixture_manifest_sha256=MANIFEST,
                 started_utc=C.utc_text(NOW - timedelta(minutes=2)),
                 finished_utc=C.utc_text(NOW - timedelta(minutes=1)))
    value["backends"][0]["capabilities"] = dict.fromkeys(PROTOCOL[backend], "passed")
    value["backends"][0]["capabilities"]["authentication_rejection"] = "not_applicable"
    return value


class FilesystemCompletionTests(unittest.TestCase):
    def setUp(self):
        for target in ("subprocess.Popen", "socket.socket", "socket.create_connection", "threading.Thread.start"):
            guard = patch(target, side_effect=AssertionError("native_boundary_forbidden"))
            guard.start()
            self.addCleanup(guard.stop)
        self.catalog = C.catalog_from_schemas([schema(key[0]) for key in FILESYSTEM])
        # Exercise the actual policy profiles/applicability for this pure
        # two-backend catalog; substitute only its synthetic schema identities.
        path = Path(__file__).resolve().parents[2] / "provider-coverage-policy.json"
        self.policy = json.loads(path.read_text(encoding="utf-8"))
        self.policy["providers"] = {key[0]: self.policy["providers"][key[0]] for key in FILESYSTEM}
        for row in self.catalog:
            plan = self.policy["providers"][row["backend"]]
            if "schema_sha256_by_platform" in plan:
                plan["schema_sha256_by_platform"]["windows"] = row["schema_sha256"]
            else:
                plan["schema_sha256"] = row["schema_sha256"]
        self.bindings = {key: deepcopy(receipt(key)["bindings"]) for key in FILESYSTEM}

    def evaluate(self, protocols, applications=None):
        return C.evaluate(self.catalog, self.policy, RUNTIME, protocols, HARNESS, now=NOW,
                          fixture_manifest_sha256=MANIFEST,
                          application_receipts=applications if applications is not None else
                          [receipt(key) for key in FILESYSTEM], application_bindings=self.bindings)

    def row(self, report, backend):
        return next(row for row in report["providers"] if row["backend"] == backend)

    def gates(self, report, key):
        return C.gate_errors(report, require_plans=True, require_fixtures=[key[0]],
                             require_application=[key[0]], require_application_modes=[key])

    def test_current_policy_needs_both_receipts_for_each_exact_windows_baseline(self):
        for key in FILESYSTEM:
            with self.subTest(backend=key[0]):
                report = self.evaluate([protocol(key[0])], [receipt(key)])
                row = self.row(report, key[0])
                self.assertEqual(self.gates(report, key), [])
                self.assertTrue(row["complete"])
                for tier in ("application", "local_protocol"):
                    self.assertEqual(row["evidence"][tier]["status"], "passed")
                self.assertEqual(row["evidence"]["vendor"]["status"], "not_applicable")
                self.assertFalse(report["all_complete"])
                # Completion is ledger aggregation, never a producer overclaim.
                self.assertFalse(receipt(key)["claims"]["provider_accepted"])

    def test_missing_or_other_backend_protocol_cannot_complete_requested_provider(self):
        for key, other in (FILESYSTEM, tuple(reversed(FILESYSTEM))):
            for values in ([], [protocol(other[0])]):
                report = self.evaluate(values, [receipt(key)])
                self.assertEqual(self.row(report, key[0])["evidence"]["application"]["status"], "passed")
                self.assertFalse(self.row(report, key[0])["complete"])
                self.assertIn("required_fixture_not_verified", self.gates(report, key))

    def test_protocol_cannot_replace_missing_or_partial_application(self):
        for key in FILESYSTEM:
            for values in ([], [receipt(key, complete=False)]):
                report = self.evaluate([protocol(key[0])], values)
                self.assertEqual(self.row(report, key[0])["evidence"]["local_protocol"]["status"], "passed")
                self.assertFalse(self.row(report, key[0])["complete"])
                self.assertIn("required_application_not_verified", self.gates(report, key))

    def test_stale_runtime_platform_and_source_protocol_mismatches_fail_closed(self):
        for key in FILESYSTEM:
            for mutation in ("stale", "version", "sha256", "platform", "harness", "manifest"):
                value = protocol(key[0])
                if mutation == "stale":
                    value.update(started_utc=C.utc_text(NOW - timedelta(hours=25, minutes=2)),
                                 finished_utc=C.utc_text(NOW - timedelta(hours=25)))
                elif mutation in ("version", "sha256"):
                    value["runtime"][mutation] = "1.75.1" if mutation == "version" else "0" * 64
                elif mutation == "platform":
                    value["platform"] = "linux"
                else:
                    value["harness_sha256" if mutation == "harness" else "fixture_manifest_sha256"] = "0" * 64
                with self.subTest(backend=key[0], mutation=mutation):
                    report = self.evaluate([value])
                    expected = {"stale": "expired_receipt", "version": "receipt_runtime_mismatch",
                                "sha256": "receipt_runtime_mismatch", "platform": "receipt_runtime_mismatch",
                                "harness": "receipt_harness_mismatch", "manifest": "receipt_fixture_manifest_mismatch"}
                    self.assertEqual(report["errors"], [expected[mutation]])
                    self.assertTrue(self.gates(report, key))
                    self.assertFalse(self.row(report, key[0])["complete"])

    def test_failed_protocol_or_cleanup_stays_failed_beside_good_receipt(self):
        for key in FILESYSTEM:
            good = protocol(key[0])
            for failure in ("cleanup", "download"):
                failed = deepcopy(good)
                failed["success"] = False
                if failure == "cleanup":
                    failed["cleanup_passed"] = False
                else:
                    failed["backends"][0]["capabilities"]["download_hash"] = "failed"
                for values in ([good, failed], [failed, good]):
                    report = self.evaluate(values)
                    self.assertFalse(self.row(report, key[0])["complete"])
                    self.assertIn("required_fixture_not_verified", self.gates(report, key))

    def test_no_application_mode_or_capability_is_borrowed_between_backends(self):
        for key, other in (FILESYSTEM, tuple(reversed(FILESYSTEM))):
            report = self.evaluate([protocol(key[0])], [receipt(other)])
            self.assertFalse(self.row(report, key[0])["complete"])
            self.assertIn("required_application_not_verified", self.gates(report, key))
            for capability in PROTOCOL[key[0]]:
                value = protocol(key[0])
                value["backends"][0]["capabilities"][capability] = "not_run"
                report = self.evaluate([value])
                self.assertFalse(self.row(report, key[0])["complete"], capability)
                self.assertTrue(self.gates(report, key), capability)


if __name__ == "__main__":
    unittest.main()
