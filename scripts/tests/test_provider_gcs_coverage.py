"""Independent configured-token GCS ledger oracles; no native/network actions."""
import contextlib
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("gcs_coverage_subject", ROOT / "scripts/provider_coverage.py")
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)
NOW = datetime(2026, 10, 5, 12, tzinfo=timezone.utc)
RUNTIME = {"version": "1.76.2", "sha256": "a" * 64, "platform": "linux"}
MODE = "gcs_static_token_read_v1"
CAPS = ("listing", "download_hash", "missing_object_rejection", "authentication_rejection",
        "read_denial", "source_preservation", "config_preservation", "cleanup")


def receipt():
    return {"schema_version": 1, "scope": "rclone_backend_protocol_fixture",
            "runtime": {"version": "1.76.2", "sha256": "a" * 64}, "platform": "linux",
            "harness_sha256": "b" * 64, "fixture_manifest_sha256": "c" * 64,
            "started_utc": "2026-10-05T11:58:00Z", "finished_utc": "2026-10-05T11:59:00Z",
            "success": True, "cleanup_passed": True, "errors": [], "backends": [
                {"backend": "gcs", "fixture_kind": "independent_loopback",
                 "capabilities": dict.fromkeys(CAPS, "passed"), "errors": []}]}


class GcsCoverageTests(unittest.TestCase):
    def setUp(self):
        self.actual = json.loads((ROOT / "provider-coverage-policy.json").read_bytes())
        entry = copy.deepcopy(self.actual["providers"]["gcs"])
        self.catalog = C.catalog_from_schemas([{"Name": "google cloud storage", "Prefix": "gcs", "Options": []}])
        entry["schema_sha256"] = self.catalog[0]["schema_sha256"]
        self.policy = {"schema_version": 2, "reviewed_runtime_version": RUNTIME["version"],
                       "providers": {"gcs": entry}, "profiles": {
                           entry["profile"]: copy.deepcopy(self.actual["profiles"][entry["profile"]])}}

    def evaluate(self, receipts, **kwargs):
        return C.evaluate(self.catalog, self.policy, RUNTIME, receipts, kwargs.pop("harness", "b" * 64),
                          now=NOW, fixture_manifest_sha256=kwargs.pop("manifest", "c" * 64), **kwargs)

    def local(self, report):
        return report["providers"][0]["evidence"]["local_protocol"]

    def reject(self, candidate, **kwargs):
        report = self.evaluate([candidate], **kwargs)
        self.assertTrue(report["errors"])
        self.assertEqual(self.local(report)["status"], "not_verified")
        self.assertIn("required_fixture_not_verified", C.gate_errors(report, require_fixtures=["gcs"]))
        return report

    def test_exact_static_mode_passes_baseline_gate_but_not_full_lifecycle(self):
        report = self.evaluate([receipt()])
        self.assertEqual(report["errors"], [])
        self.assertEqual(C.gate_errors(report, require_plans=True, require_gcs_static_token=True), [])
        local = self.local(report)
        self.assertEqual(local["status"], "not_verified")
        self.assertEqual(local["capabilities"], dict(dict.fromkeys(CAPS, "passed"), **dict.fromkeys(
            ("authentication", "refresh", "renewal_denial", "cancellation_cleanup"), "not_verified")))
        self.assertEqual(set(local["modes"]), {MODE, "gcs_oauth_lifecycle_v1"})
        self.assertEqual(local["modes"][MODE]["status"], "passed")
        self.assertEqual(local["runs"][0]["fixture_mode"], MODE)
        self.assertEqual(local["modes"][MODE]["runs"], local["runs"])
        row = report["providers"][0]
        for tier in ("application", "vendor"):
            self.assertEqual(row["evidence"][tier]["status"], "not_verified")
            self.assertTrue(all(v == "not_verified" for v in row["evidence"][tier]["capabilities"].values()))
        self.assertEqual(row["lifecycle_applicability"], {
            "credential_renewal": "required", "connection_session_reauthentication": "review_required"})
        self.assertFalse(row["complete"])
        self.assertIn("provider_coverage_incomplete", C.gate_errors(report, require_complete=True))

    def test_policy_keeps_hosted_requirements_and_current_fingerprint(self):
        old = self.actual["profiles"]["hosted-renewal-session-review"]
        entry = self.actual["providers"]["gcs"]
        new = self.actual["profiles"][entry["profile"]]
        remaining = copy.deepcopy(new); del remaining["required"]["local_protocol"]
        self.assertEqual(remaining, old)
        self.assertEqual(set(new["required"]["local_protocol"]), set(CAPS) | {"authentication", "refresh", "renewal_denial", "cancellation_cleanup"})
        self.assertEqual(entry["schema_sha256"], "35f3d13d23fd498bb3ea4fbd72acf1b7c2f0717fc18e5e77669821675606b236")
        self.assertEqual(entry["auth_applicability"], "provider_specific")
        self.assertEqual(entry["refresh_applicability"], "required")
        self.assertEqual(entry["reauthentication_applicability"], "review_required")
        self.assertTrue(entry["renewal_modes"])

    def test_no_receipt_never_passes(self):
        report = self.evaluate([])
        self.assertEqual(self.local(report)["status"], "not_verified")
        self.assertIn("required_fixture_not_verified", C.gate_errors(report, require_fixtures=["gcs"]))

    def test_exact_capabilities_required_even_with_weakened_policy(self):
        profile = next(iter(self.policy["profiles"].values()))
        profile["required"]["local_protocol"] = ["listing"]
        for name in CAPS:
            with self.subTest(missing=name):
                candidate = receipt(); del candidate["backends"][0]["capabilities"][name]
                self.reject(candidate)
        for name in ("authentication", "refresh", "reauthentication", "revocation", "fixture_write_rejection",
                     "saved_token_read", "anonymous_read", "service_token_reacquisition", "renewal_denial"):
            with self.subTest(extra=name):
                candidate = receipt(); candidate["backends"][0]["capabilities"][name] = "passed"
                self.reject(candidate)

    def test_nonstring_and_not_applicable_statuses_rejected(self):
        for name in CAPS:
            for value in (True, False, 1, None, "not_applicable"):
                with self.subTest(name=name, value=value):
                    candidate = receipt(); candidate["backends"][0]["capabilities"][name] = value
                    self.reject(candidate)

    def test_scope_and_auth_overrides_rejected_at_each_envelope(self):
        for field in ("fixture_mode", "modes", "subscenarios", "auth_mode", "profile", "scope", "source_sha256"):
            for level in ("top", "row"):
                with self.subTest(field=field, level=level):
                    candidate = receipt(); target = candidate if level == "top" else candidate["backends"][0]
                    target[field] = MODE
                    self.reject(candidate)
        candidate = receipt(); candidate["runtime"]["auth_mode"] = "service_account"
        self.reject(candidate)

    def test_other_receipt_schemas_cannot_carry_gcs(self):
        for value in (0, 2, 3, 4, 5, True, 1.0, "1", None):
            with self.subTest(schema=value):
                candidate = receipt(); candidate["schema_version"] = value
                self.reject(candidate)

    def test_kind_duplicate_and_other_backend_transplants_rejected(self):
        for value in ("local", "rclone_loopback", "vendor", "independent_oauth_container"):
            candidate = receipt(); candidate["backends"][0]["fixture_kind"] = value
            self.reject(candidate)
        candidate = receipt(); candidate["backends"].append(copy.deepcopy(candidate["backends"][0]))
        self.reject(candidate)
        for backend in ("http", "webdav", "azureblob", "pcloud", "internetarchive", "filefabric", "smb"):
            candidate = receipt(); candidate["backends"][0]["backend"] = backend
            self.reject(candidate)

    def test_runtime_platform_harness_and_manifest_drift_rejected(self):
        for field, value in (("platform", "windows"), ("harness_sha256", "d" * 64),
                             ("fixture_manifest_sha256", "d" * 64)):
            candidate = receipt(); candidate[field] = value; self.reject(candidate)
        for field, value in (("version", "1.76.3"), ("sha256", "d" * 64)):
            candidate = receipt(); candidate["runtime"][field] = value; self.reject(candidate)

    def test_freshness_duration_and_cleanup_truth_are_strict(self):
        for changes in ({"started_utc": "2026-10-05T12:01:00Z", "finished_utc": "2026-10-05T12:02:00Z"},
                        {"started_utc": "2026-10-03T11:58:00Z", "finished_utc": "2026-10-03T11:59:00Z"},
                        {"started_utc": "2026-10-05T11:00:00Z"}, {"cleanup_passed": False},
                        {"cleanup_passed": 1}, {"success": 1}, {"errors": ["fixture_failed"]}):
            candidate = receipt(); candidate.update(changes); self.reject(candidate)
        for value in ("failed", "not_run"):
            candidate = receipt(); candidate["backends"][0]["capabilities"]["cleanup"] = value
            self.reject(candidate)

    def test_late_failure_is_sticky_in_both_orders_and_mode(self):
        for reason in ("cleanup", "source_preservation", "config_preservation", "read_denial"):
            bad = receipt(); bad["success"] = False; bad["backends"][0]["capabilities"][reason] = "failed"
            bad["backends"][0]["errors"] = ["synthetic_failure"]
            if reason == "cleanup": bad["cleanup_passed"] = False
            for batch in ([bad, receipt()], [receipt(), bad]):
                report = self.evaluate(batch)
                self.assertEqual(report["errors"], [])
                self.assertEqual(self.local(report)["status"], "failed")
                self.assertEqual(self.local(report)["modes"][MODE]["status"], "failed")
                self.assertEqual(self.local(report)["capabilities"][reason], "failed")
                self.assertIn("required_fixture_not_verified", C.gate_errors(report, require_fixtures=["gcs"]))

    def test_failed_unrun_case_cannot_become_success(self):
        bad = receipt(); bad["success"] = False
        bad["backends"][0]["capabilities"] = dict.fromkeys(CAPS, "not_run")
        self.assertEqual(self.local(self.evaluate([bad, receipt()]))["status"], "failed")

    def test_reviewed_version_and_catalog_fingerprint_remain_independent_gates(self):
        self.policy["reviewed_runtime_version"] = "1.76.1"
        report = self.evaluate([receipt()])
        self.assertEqual(report["providers"][0]["policy_status"], "unreviewed_runtime")
        self.assertEqual(self.local(report)["status"], "not_verified")
        self.policy["reviewed_runtime_version"] = RUNTIME["version"]
        self.policy["providers"]["gcs"]["schema_sha256"] = "0" * 64
        report = self.evaluate([receipt()])
        self.assertEqual(report["providers"][0]["policy_status"], "stale_schema")
        self.assertEqual(self.local(report)["status"], "not_verified")

    def test_each_of_six_harness_files_and_legacy_framing_are_bound(self):
        names = {"fixture_servers.py", "run_lab.py", "fixture_tls.py", "fixture_pcloud.py", "fixture_gcs.py", "requirements-fixture.txt"}
        self.assertEqual(set(C.HARNESSES), names)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in names: (root / name).write_bytes(b"synthetic source\n")
            expected = hashlib.sha256(b"".join(name.encode()+b"\0synthetic source\n\0" for name in sorted(names))).hexdigest()
            self.assertEqual(C.compute_harness_sha256(root), expected)
            candidate = receipt(); candidate["harness_sha256"] = expected
            self.assertEqual(self.evaluate([candidate], harness=expected)["errors"], [])
            for name in names:
                (root / name).write_bytes(b"changed source\n")
                self.reject(candidate, harness=C.compute_harness_sha256(root))
                (root / name).write_bytes(b"synthetic source\n")
            legacy = hashlib.sha256(b"".join(name.encode()+b"\0synthetic source\n\0" for name in sorted(names-{"fixture_gcs.py"}))).hexdigest()
            candidate["harness_sha256"] = legacy; self.reject(candidate, harness=expected)

    def test_cli_requires_valid_current_evidence_and_keeps_other_tiers_unverified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); policy = root / "policy.json"; policy.write_text(json.dumps(self.policy))
            evidence = root / "fixture.json"; evidence.write_text(json.dumps(receipt()))
            for index, use_receipt in enumerate((False, True)):
                output = root / (str(index)+".json")
                args = ["--rclone", str(root / "never-executed"), "--policy", str(policy), "--report", str(output),
                        "--require-plans", "--require-gcs-static-token"]
                if use_receipt: args += ["--fixture-receipt", str(evidence)]
                with patch.object(C, "query_runtime", return_value=(RUNTIME, self.catalog)), \
                        patch.object(C, "compute_harness_sha256", return_value="b" * 64), \
                        patch.object(C, "compute_fixture_manifest_sha256", return_value="c" * 64), \
                        patch.object(C.subprocess, "Popen", side_effect=AssertionError("native forbidden")), \
                        patch.object(C, "datetime", wraps=datetime) as clock, contextlib.redirect_stdout(io.StringIO()):
                    clock.now.return_value = NOW
                    self.assertEqual(C.main(args), 0 if use_receipt else 1)
                report = json.loads(output.read_bytes())
                self.assertEqual(report["providers"][0]["evidence"]["application"]["status"], "not_verified")
                self.assertEqual(report["providers"][0]["evidence"]["vendor"]["status"], "not_verified")


if __name__ == "__main__":
    unittest.main()
