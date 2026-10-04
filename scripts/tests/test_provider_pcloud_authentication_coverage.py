"""Closed schema-5 composition tests. No native runtime or container is executed."""
import contextlib
import copy
from datetime import datetime
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_provider_pcloud_authentication_container as oracle

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("pcloud_auth_coverage_subject", ROOT / "scripts/provider_coverage.py")
C = importlib.util.module_from_spec(SPEC)
exec(compile(SPEC.loader.get_data(str(ROOT / "scripts/provider_coverage.py")), str(ROOT / "scripts/provider_coverage.py"), "exec"), C.__dict__)
RUNTIME = dict(oracle.IDENTITY, platform="linux")
BASELINE_CAPS = ("listing", "download_hash", "missing_object_rejection", "saved_token_read", "saved_token_rejection",
                 "read_denial", "source_preservation", "config_preservation", "fixture_write_rejection", "cleanup")


def saved_token_receipt():
    return {"schema_version": 1, "scope": "rclone_backend_protocol_fixture", "runtime": dict(oracle.IDENTITY),
            "platform": "linux", "harness_sha256": "a" * 64, "fixture_manifest_sha256": oracle.FIXTURE,
            "started_utc": "2026-10-04T11:58:00Z", "finished_utc": "2026-10-04T11:59:00Z",
            "success": True, "cleanup_passed": True, "errors": [],
            "backends": [{"backend": "pcloud", "fixture_kind": "independent_loopback",
                          "capabilities": dict.fromkeys(BASELINE_CAPS, "passed"), "errors": []}]}


def policy_catalog():
    actual = json.loads((ROOT / "provider-coverage-policy.json").read_bytes())
    entry = copy.deepcopy(actual["providers"]["pcloud"])
    catalog = C.catalog_from_schemas([{"Name": "pcloud", "Prefix": "pcloud", "Options": []}])
    entry.pop("schema_sha256_by_platform", None); entry["schema_sha256"] = catalog[0]["schema_sha256"]
    return {"schema_version": 2, "reviewed_runtime_version": RUNTIME["version"], "providers": {"pcloud": entry},
            "profiles": {entry["profile"]: copy.deepcopy(actual["profiles"][entry["profile"]])}}, catalog


class PCloudAuthenticationCoverage(unittest.TestCase):
    def setUp(self):
        self.policy, self.catalog = policy_catalog()

    def evaluate(self, receipts, **kwargs):
        options = {"now": oracle.NOW, "fixture_manifest_sha256": oracle.FIXTURE,
                   "pcloud_bindings": copy.deepcopy(oracle.BINDINGS)}
        options.update(kwargs)
        return C.evaluate(self.catalog, self.policy, RUNTIME, receipts, "a" * 64, **options)

    def local(self, report):
        return report["providers"][0]["evidence"]["local_protocol"]

    def rejected(self, item, **kwargs):
        report = self.evaluate([item], **kwargs)
        self.assertTrue(report["errors"])
        self.assertEqual(self.local(report)["status"], "not_verified")
        self.assertIn("required_fixture_not_verified", C.gate_errors(report, require_fixtures=["pcloud"]))
        return report

    def test_current_policy_requires_both_modes_and_leaves_other_layers_unverified(self):
        for receipts in ([saved_token_receipt()], [oracle.evidence()], [saved_token_receipt(), oracle.evidence()],
                         [oracle.evidence(), saved_token_receipt()]):
            with self.subTest(schemas=[x["schema_version"] for x in receipts]):
                report = self.evaluate(receipts); self.assertEqual(report["errors"], [])
                self.assertEqual(self.local(report)["status"], "passed" if len(receipts) == 2 else "not_verified")
                self.assertEqual(C.gate_errors(report, require_fixtures=["pcloud"]), [] if len(receipts) == 2 else ["required_fixture_not_verified"])
                for tier in ("application", "vendor"):
                    self.assertEqual(report["providers"][0]["evidence"][tier]["status"], "not_verified")
                    self.assertTrue(all(value == "not_verified" for value in report["providers"][0]["evidence"][tier]["capabilities"].values()))
                self.assertFalse(report["all_complete"])
                self.assertEqual(report["providers"][0]["lifecycle_applicability"],
                                 {"credential_renewal": "review_required", "connection_session_reauthentication": "review_required"})
        local = self.local(self.evaluate([saved_token_receipt(), oracle.evidence()]))
        self.assertEqual(set(local["modes"]), {"pcloud_saved_token_read_v1", "pcloud_oauth_authentication_v1"})
        self.assertEqual(local["modes"]["pcloud_oauth_authentication_v1"]["capabilities"], {"authentication": "passed"})
        run = local["modes"]["pcloud_oauth_authentication_v1"]["runs"][0]
        self.assertEqual((run["platform"], run["architecture"]), ("linux", "amd64"))
        self.assertEqual(run["source_sha256"], oracle.SOURCES)
        self.assertNotEqual(run["harness_sha256"], "a" * 64)

    def test_valid_authentication_failure_is_sticky_in_every_order(self):
        for failed in (oracle.failed_prefix(), oracle.failed_prefix(cleanup=False)):
            for receipts in ([failed, oracle.evidence(), saved_token_receipt()], [saved_token_receipt(), oracle.evidence(), failed]):
                report = self.evaluate(receipts); self.assertEqual(report["errors"], [])
                self.assertEqual(self.local(report)["status"], "failed")
                self.assertEqual(self.local(report)["capabilities"]["authentication"], "failed")
                self.assertEqual(self.local(report)["modes"]["pcloud_oauth_authentication_v1"]["status"], "failed")

    def test_saved_token_failure_cannot_be_hidden_by_authentication(self):
        failed = saved_token_receipt(); failed.update(success=False, errors=["synthetic_failure"])
        failed["backends"][0]["capabilities"]["download_hash"] = "failed"
        failed["backends"][0]["errors"] = ["synthetic_failure"]
        for receipts in ([failed, saved_token_receipt(), oracle.evidence()], [oracle.evidence(), saved_token_receipt(), failed]):
            report = self.evaluate(receipts); self.assertEqual(report["errors"], [])
            self.assertEqual(self.local(report)["status"], "failed")
            self.assertEqual(self.local(report)["modes"]["pcloud_saved_token_read_v1"]["status"], "failed")

    def test_no_bindings_or_foreign_platform_fixture_or_runtime_rejected(self):
        self.rejected(oracle.evidence(), pcloud_bindings=None)
        self.rejected(oracle.evidence(), fixture_manifest_sha256="f" * 64)
        for field, value in (("version", "1.77.0"), ("sha256", "f" * 64)):
            item = oracle.evidence(); item["runtime"][field] = value
            self.rejected(item)
        for field, value in (("platform", "windows"), ("architecture", "arm64"), ("harness_sha256", "a" * 64)):
            item = oracle.evidence(); item[field] = value; self.rejected(item)
        with self.assertRaises(C.CoverageError):
            C.validate_receipt(oracle.evidence(), dict(RUNTIME, platform="windows"), "a" * 64, oracle.NOW,
                               fixture_manifest_sha256=oracle.FIXTURE, pcloud_bindings=oracle.BINDINGS)

    def test_closed_shape_even_with_weaker_policy_and_no_scope_transplant(self):
        self.policy["profiles"][self.policy["providers"]["pcloud"]["profile"]]["required"]["local_protocol"] = ["authentication"]
        for field, value in (("fixture_kind", "independent_loopback"), ("fixture_mode", "pcloud_saved_token_read_v1"),
                             ("backend", "drive"), ("capabilities", {}), ("scope", "vendor")):
            item = oracle.evidence(); item["backends"][0][field] = value; self.rejected(item)
        for cap in (*BASELINE_CAPS, "refresh", "reauthentication", "revocation", "authentication_rejection"):
            item = oracle.evidence(); item["backends"][0]["capabilities"][cap] = "passed"; self.rejected(item)
        for status in (True, 1, "not_applicable", "not_run", "PASS"):
            item = oracle.evidence(); item["backends"][0]["capabilities"]["authentication"] = status; self.rejected(item)
        item = oracle.evidence(); item["backends"].append(copy.deepcopy(item["backends"][0])); self.rejected(item)

    def test_legacy_feasibility_schema_aliases_and_schema1_auth_spoof_rejected(self):
        for item in (oracle.native(), oracle.suite(), oracle.baseline.probe()): self.rejected(item)
        for schema in (True, 1, 2, 3, 4, 6, "5"):
            item = oracle.evidence(); item["schema_version"] = schema; self.rejected(item)
        item = saved_token_receipt(); item["backends"][0]["capabilities"]["authentication"] = "passed"; self.rejected(item)
        item = saved_token_receipt(); item["backends"][0]["fixture_mode"] = "pcloud_oauth_authentication_v1"; self.rejected(item)

    def test_each_nested_identity_source_dependency_clock_and_outcome_is_required(self):
        mutations = (("source_digest", "f" * 64), ("dependency_lock_sha256", "f" * 64), ("base_image", "python:latest"),
                     ("base_config_digest", "sha256:" + "f" * 64), ("python_version", "3.13.0"),
                     ("container_isolation_verified", False), ("container_exit_code", True), ("container_oom_killed", True),
                     ("container_stdout_bytes", 0), ("container_stderr_bytes", 1), ("container_start_error_present", True),
                     ("stage", "probe"), ("scope", "pcloud_oauth_container_feasibility"), ("ledger_eligible", True),
                     ("probe_started_utc", "2026-10-04T12:00:10Z"))
        for field, value in mutations:
            item = oracle.evidence(); item["native_evidence"][field] = value
            with self.subTest(field=field): self.rejected(item)
        for name in oracle.SOURCES:
            item = oracle.evidence(); item["native_evidence"]["source_sha256"][name] = "f" * 64
            with self.subTest(source=name): self.rejected(item)
        for field in ("container_removed", "image_removed", "temporary_removed"):
            item = oracle.evidence(); item["native_evidence"]["cleanup"][field] = False; self.rejected(item)

    def test_current_sources_are_hashed_without_importing_fixture_or_executing_process(self):
        with patch.object(C.subprocess, "Popen", side_effect=AssertionError("native forbidden")), \
             patch("importlib.machinery.SourceFileLoader.exec_module", side_effect=AssertionError("cached bytecode forbidden")):
            bindings = C.compute_pcloud_bindings(ROOT / "scripts/provider-lab/pcloud-oauth")
        names = ["scripts/provider-lab/pcloud-oauth/" + name for name in ("Dockerfile", "build-lock.json", "run_container.py", "probe.py", "fixture_oauth.py")]
        names += ["scripts/provider-lab/fixture_tls.py", "scripts/provider-lab/fixture_pcloud.py", "scripts/provider-lab/requirements-fixture.txt", "rclone-version.env"]
        independent = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in sorted(names)}
        self.assertEqual(bindings["source_sha256"], independent)
        self.assertEqual(bindings["harness_sha256"], hashlib.sha256(json.dumps(independent, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
        self.assertEqual(bindings["fixture_manifest_sha256"], C.compute_fixture_manifest_sha256(ROOT / "scripts/provider-lab"))
        self.assertEqual(len(C.HARNESSES), 5)

    def test_cli_requires_both_receipts_and_computes_only_needed_current_bindings(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); policy = root / "policy.json"; policy.write_text(json.dumps(self.policy))
            paths = []
            for index, item in enumerate((saved_token_receipt(), oracle.evidence())):
                path = root / f"receipt-{index}.json"; path.write_text(json.dumps(item)); paths.append(path)
            for index, (selected, expected) in enumerate(((paths[:1], 1), (paths[1:], 1), (paths, 0))):
                output = root / f"ledger-{index}.json"
                argv = ["--rclone", str(root / "never-executed"), "--policy", str(policy), "--report", str(output),
                        "--require-plans", "--require-fixtures", "pcloud"]
                for path in selected: argv += ["--fixture-receipt", str(path)]
                with patch.object(C, "query_runtime", return_value=(RUNTIME, self.catalog)), \
                     patch.object(C, "compute_harness_sha256", return_value="a" * 64), \
                     patch.object(C, "compute_fixture_manifest_sha256", return_value=oracle.FIXTURE), \
                     patch.object(C, "compute_pcloud_bindings", return_value=oracle.BINDINGS) as binding, \
                     patch.object(C, "compute_smb_bindings", side_effect=AssertionError("unrelated helper forbidden")), \
                     patch.object(C.subprocess, "Popen", side_effect=AssertionError("native forbidden")), \
                     patch.object(C, "datetime", wraps=datetime) as clock, contextlib.redirect_stdout(io.StringIO()):
                    clock.now.return_value = oracle.NOW
                    self.assertEqual(C.main(argv), expected)
                    self.assertEqual(binding.call_count, int(paths[1] in selected))
                report = json.loads(output.read_text()); self.assertEqual(report["errors"], [])
                self.assertEqual(report["providers"][0]["evidence"]["application"]["status"], "not_verified")


if __name__ == "__main__":
    unittest.main()
