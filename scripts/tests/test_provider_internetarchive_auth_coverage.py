"""Independent IA anonymous/LOW ledger oracles; no native or network actions."""
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
SPEC = importlib.util.spec_from_file_location("ia_auth_coverage_subject", ROOT / "scripts/provider_coverage.py")
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)
NOW = datetime(2026, 10, 4, 12, tzinfo=timezone.utc)
RUNTIME = {"version": "1.76.2", "sha256": "a" * 64, "platform": "linux"}
ANONYMOUS = "internetarchive_anonymous_read_v1"
LOW = "internetarchive_low_read_auth_v1"
ANONYMOUS_CAPS = ("listing", "download_hash", "missing_object_rejection", "anonymous_read", "read_denial",
                  "source_preservation", "config_preservation", "fixture_write_rejection", "cleanup")
LOW_CAPS = ("authentication_rejection", "source_preservation", "config_preservation", "cleanup")


def literal_receipt(low=False):
    # These strings are the independently specified wire contract, not imported
    # producer or validator constants. No credential or synthetic account value.
    row = {"backend": "internetarchive", "fixture_kind": "independent_loopback",
           "capabilities": dict.fromkeys(LOW_CAPS if low else ANONYMOUS_CAPS, "passed"), "errors": []}
    if low:
        row["fixture_mode"] = "internetarchive_low_read_auth_v1"
    return {
        "schema_version": 4 if low else 1, "scope": "rclone_backend_protocol_fixture",
        "runtime": {"version": "1.76.2", "sha256": "a" * 64}, "platform": "linux",
        "harness_sha256": "b" * 64, "fixture_manifest_sha256": "c" * 64,
        "started_utc": "2026-10-04T11:58:00Z", "finished_utc": "2026-10-04T11:59:00Z",
        "success": True, "cleanup_passed": True, "errors": [], "backends": [row],
    }


def policy_and_catalog():
    actual = json.loads((ROOT / "provider-coverage-policy.json").read_text(encoding="utf-8"))
    entry = copy.deepcopy(actual["providers"]["internetarchive"])
    catalog = C.catalog_from_schemas([{"Name": "internetarchive", "Prefix": "internetarchive", "Options": []}])
    entry.pop("schema_sha256_by_platform", None)
    entry["schema_sha256"] = catalog[0]["schema_sha256"]
    return {"schema_version": 2, "reviewed_runtime_version": RUNTIME["version"], "providers": {"internetarchive": entry},
            "profiles": {entry["profile"]: copy.deepcopy(actual["profiles"][entry["profile"]])}}, catalog


def replace(candidate, path, value):
    current = candidate
    for key in path[:-1]:
        current = current[key]
    current[path[-1]] = value


class InternetArchiveAuthCoverageTests(unittest.TestCase):
    def setUp(self):
        self.policy, self.catalog = policy_and_catalog()

    def evaluate(self, receipts, **kwargs):
        arguments = {"now": NOW, "fixture_manifest_sha256": "c" * 64}
        arguments.update(kwargs)
        return C.evaluate(self.catalog, self.policy, RUNTIME, receipts, "b" * 64, **arguments)

    def local(self, report):
        return report["providers"][0]["evidence"]["local_protocol"]

    def assert_rejected(self, candidate, **kwargs):
        report = self.evaluate([candidate], **kwargs)
        self.assertTrue(report["errors"])
        self.assertEqual(self.local(report)["status"], "not_verified")
        self.assertIn("required_fixture_not_verified", C.gate_errors(report, require_fixtures=["internetarchive"]))
        return report

    def test_both_modes_meet_current_ten_local_obligations_only(self):
        for receipts in ([literal_receipt(), literal_receipt(True)], [literal_receipt(True), literal_receipt()]):
            with self.subTest(order=[r["schema_version"] for r in receipts]):
                report = self.evaluate(receipts)
                self.assertEqual(report["errors"], [])
                local = self.local(report)
                self.assertEqual(local["status"], "passed")
                self.assertEqual(local["capabilities"], dict.fromkeys((*ANONYMOUS_CAPS, "authentication_rejection"), "passed"))
                self.assertEqual(set(local["modes"]), {ANONYMOUS, LOW})
                for mode, caps in ((ANONYMOUS, ANONYMOUS_CAPS), (LOW, LOW_CAPS)):
                    self.assertEqual(local["modes"][mode]["capabilities"], dict.fromkeys(caps, "passed"))
                    self.assertEqual(local["modes"][mode]["status"], "passed")
                    self.assertEqual(local["modes"][mode]["runs"][0]["fixture_mode"], mode)
                self.assertEqual(C.gate_errors(report, require_plans=True, require_fixtures=["internetarchive"]), [])
                self.assertFalse(report["all_complete"])
                self.assertIn("provider_coverage_incomplete", C.gate_errors(report, require_complete=True))
                for tier in ("application", "vendor"):
                    evidence = report["providers"][0]["evidence"][tier]
                    self.assertEqual(evidence["status"], "not_verified")
                    self.assertTrue(all(value == "not_verified" for value in evidence["capabilities"].values()))
                entry = self.policy["providers"]["internetarchive"]
                self.assertEqual(report["providers"][0]["lifecycle_applicability"], {
                    "credential_renewal": entry["refresh_applicability"],
                    "connection_session_reauthentication": entry["reauthentication_applicability"],
                })

    def test_neither_mode_alone_can_supply_the_other_scope(self):
        for low, absent_mode in ((False, LOW), (True, ANONYMOUS)):
            with self.subTest(low=low):
                report = self.evaluate([literal_receipt(low)])
                self.assertEqual(report["errors"], [])
                local = self.local(report)
                self.assertEqual(local["status"], "not_verified")
                self.assertEqual(local["modes"][absent_mode]["status"], "not_verified")
                self.assertEqual(local["modes"][absent_mode]["runs"], [])
                self.assertEqual(local["capabilities"]["listing" if low else "authentication_rejection"], "not_verified")
                self.assertIn("required_fixture_not_verified", C.gate_errors(report, require_fixtures=["internetarchive"]))

    def test_low_cannot_use_legacy_retired_or_untyped_schemas(self):
        for schema in (0, 1, 2, 3, 5, True, 4.0, "4", None):
            with self.subTest(schema=schema):
                candidate = literal_receipt(True); candidate["schema_version"] = schema
                self.assert_rejected(candidate)
        candidate = literal_receipt(True)
        candidate["schema_version"] = 1
        del candidate["backends"][0]["fixture_mode"]
        self.assert_rejected(candidate)
        candidate["backends"][0]["capabilities"].update(dict.fromkeys(ANONYMOUS_CAPS, "passed"))
        self.assert_rejected(candidate)

    def test_schema_four_requires_exact_mode_kind_backend_and_singleton(self):
        for path, value in (
            (["backends", 0, "fixture_mode"], ANONYMOUS),
            (["backends", 0, "fixture_mode"], "filefabric_later_call_renewal_v1"),
            (["backends", 0, "fixture_mode"], None),
            (["backends", 0, "fixture_kind"], "vendor"),
            (["backends", 0, "fixture_kind"], "rclone_loopback"),
            (["backends", 0, "backend"], "archive"),
            (["backends", 0, "backend"], "filefabric"),
            (["backends", 0, "backend"], "smb"),
        ):
            with self.subTest(path=path, value=value):
                candidate = literal_receipt(True); replace(candidate, path, value)
                self.assert_rejected(candidate)
        for extra in (literal_receipt()["backends"][0], literal_receipt(True)["backends"][0],
                      {"backend": "http", "fixture_kind": "independent_loopback", "errors": [],
                       "capabilities": {"listing": "passed", "download_hash": "passed", "cleanup": "passed"}}):
            candidate = literal_receipt(True); candidate["backends"].append(extra)
            self.assert_rejected(candidate)

    def test_closed_scope_rejects_missing_and_extra_top_row_runtime_fields(self):
        for location in ((), ("backends", 0), ("runtime",)):
            template = literal_receipt(True)
            current = template
            for key in location:
                current = current[key]
            for field in list(current):
                with self.subTest(location=location, removed=field):
                    candidate = copy.deepcopy(template); target = candidate
                    for key in location:
                        target = target[key]
                    del target[field]
                    self.assert_rejected(candidate)
            for field in ("fixture_mode", "modes", "subscenarios", "scope", "profile", "auth", "private_log"):
                if field in current:
                    continue
                with self.subTest(location=location, extra=field):
                    candidate = copy.deepcopy(template); target = candidate
                    for key in location:
                        target = target[key]
                    target[field] = "private-value-canary"
                    report = self.assert_rejected(candidate)
                    self.assertNotIn("private-value-canary", json.dumps(report))

    def test_exact_four_caps_remain_required_under_weakened_policy(self):
        profile = self.policy["profiles"][self.policy["providers"]["internetarchive"]["profile"]]
        profile["required"]["local_protocol"] = ["cleanup"]
        for omitted in LOW_CAPS:
            candidate = literal_receipt(True); del candidate["backends"][0]["capabilities"][omitted]
            self.assert_rejected(candidate)
        for extra in (*ANONYMOUS_CAPS, "authentication", "refresh", "reauthentication", "revocation",
                      "saved_token_read", "session_token_reacquisition", "account_login"):
            if extra in LOW_CAPS:
                continue
            with self.subTest(extra=extra):
                candidate = literal_receipt(True); candidate["backends"][0]["capabilities"][extra] = "passed"
                self.assert_rejected(candidate)

    def test_statuses_and_boolean_outcomes_are_not_coercible(self):
        for cap in LOW_CAPS:
            for value in (True, False, 1, 0, None, [], {}, "PASS", "not_applicable"):
                with self.subTest(cap=cap, value=value):
                    candidate = literal_receipt(True); candidate["backends"][0]["capabilities"][cap] = value
                    self.assert_rejected(candidate)
        for field in ("success", "cleanup_passed"):
            for value in (1, 0, "true", None):
                candidate = literal_receipt(True); candidate[field] = value
                self.assert_rejected(candidate)

    def test_success_cannot_mask_failed_unrun_capability_or_cleanup(self):
        for cap in LOW_CAPS:
            for value in ("failed", "not_run"):
                candidate = literal_receipt(True); candidate["backends"][0]["capabilities"][cap] = value
                self.assert_rejected(candidate)
        candidate = literal_receipt(True); candidate["cleanup_passed"] = False
        self.assert_rejected(candidate)
        for location in ((), ("backends", 0)):
            candidate = literal_receipt(True); target = candidate
            for key in location:
                target = target[key]
            target["errors"] = ["observed_failure"]
            self.assert_rejected(candidate)

    def test_runtime_harness_fixture_and_platform_must_match_current_bindings(self):
        for path, value in ((["runtime", "version"], "1.75.1"), (["runtime", "sha256"], "d" * 64),
                            (["platform"], "windows"), (["platform"], "darwin"),
                            (["harness_sha256"], "d" * 64), (["fixture_manifest_sha256"], "d" * 64)):
            with self.subTest(path=path):
                candidate = literal_receipt(True); replace(candidate, path, value)
                self.assert_rejected(candidate)
        self.assert_rejected(literal_receipt(True), fixture_manifest_sha256=None)
        candidate = literal_receipt(True); candidate["platform"] = "windows"
        C.validate_receipt(candidate, dict(RUNTIME, platform="windows"), "b" * 64, NOW,
                           fixture_manifest_sha256="c" * 64)

    def test_future_stale_malformed_and_overlong_times_are_rejected(self):
        cases = (
            ("2026-10-04T12:00:01Z", "2026-10-04T12:00:02Z"),
            ("2026-10-02T11:58:00Z", "2026-10-02T11:59:00Z"),
            ("2026-10-04T11:59:00Z", "2026-10-04T11:58:00Z"),
            ("2026-10-04T11:00:00Z", "2026-10-04T11:59:00Z"),
            ("2026-10-04T11:58:00+00:00", "2026-10-04T11:59:00Z"),
            ("2026-99-04T11:58:00Z", "2026-10-04T11:59:00Z"),
        )
        for start, finish in cases:
            candidate = literal_receipt(True); candidate.update(started_utc=start, finished_utc=finish)
            self.assert_rejected(candidate)

    def test_failed_mode_is_sticky_across_later_success_and_other_mode(self):
        for low in (False, True):
            for cap in (LOW_CAPS if low else ANONYMOUS_CAPS):
                failed = literal_receipt(low)
                failed["success"] = False
                failed["backends"][0]["capabilities"][cap] = "failed"
                for receipts in ([failed, literal_receipt(), literal_receipt(True)],
                                 [literal_receipt(True), literal_receipt(), failed]):
                    with self.subTest(low=low, cap=cap, failed_first=receipts[0] is failed):
                        report = self.evaluate(receipts)
                        self.assertEqual(report["errors"], [])
                        local = self.local(report)
                        self.assertEqual(local["status"], "failed")
                        self.assertEqual(local["capabilities"][cap], "failed")
                        self.assertEqual(local["modes"][LOW if low else ANONYMOUS]["status"], "failed")
                        self.assertIn("required_fixture_not_verified", C.gate_errors(report, require_fixtures=["internetarchive"]))

    def test_late_cleanup_failure_cannot_be_repaired_by_capabilities_or_later_receipt(self):
        failed = literal_receipt(True)
        failed.update(success=False, cleanup_passed=False, errors=["cleanup_failed"])
        # Nominal capability successes are not promoted when final cleanup failed.
        for receipts in ([failed, literal_receipt(), literal_receipt(True)],
                         [literal_receipt(), literal_receipt(True), failed]):
            report = self.evaluate(receipts)
            self.assertEqual(report["errors"], [])
            self.assertEqual(self.local(report)["status"], "failed")
            self.assertEqual(self.local(report)["modes"][LOW]["status"], "failed")

    def test_failed_or_not_run_low_observation_remains_failed_without_invented_pass(self):
        candidate = literal_receipt(True); candidate["success"] = False
        candidate["backends"][0]["capabilities"] = dict.fromkeys(LOW_CAPS, "not_run")
        report = self.evaluate([literal_receipt(), candidate])
        self.assertEqual(report["errors"], [])
        self.assertEqual(self.local(report)["status"], "failed")
        self.assertEqual(self.local(report)["capabilities"]["authentication_rejection"], "not_verified")

    def test_mode_labels_cannot_be_transplanted_into_anonymous_or_other_schemas(self):
        for mode in (ANONYMOUS, LOW):
            candidate = literal_receipt(); candidate["backends"][0]["fixture_mode"] = mode
            self.assert_rejected(candidate)
        candidate = literal_receipt(); candidate["schema_version"] = 4
        candidate["backends"][0]["fixture_mode"] = LOW
        self.assert_rejected(candidate)
        for backend in ("http", "archive", "pcloud", "netstorage", "filefabric", "smb"):
            candidate = literal_receipt(True); candidate["backends"][0]["backend"] = backend
            self.assert_rejected(candidate)

    def test_stale_or_retired_plan_never_becomes_current_from_both_receipts(self):
        self.policy["providers"]["internetarchive"]["schema_sha256"] = "0" * 64
        report = self.evaluate([literal_receipt(), literal_receipt(True)])
        self.assertEqual(report["providers"][0]["policy_status"], "stale_schema")
        self.assertEqual(self.local(report)["status"], "not_verified")
        policy, _ = policy_and_catalog()
        catalog = C.catalog_from_schemas([{"Name": "http", "Prefix": "http", "Options": []}])
        report = C.evaluate(catalog, policy, RUNTIME, [literal_receipt(True)], "b" * 64, NOW,
                            fixture_manifest_sha256="c" * 64)
        self.assertIn("fixture_backend_absent_from_catalog", report["errors"])
        self.assertEqual(report["retired_policy_backends"], ["internetarchive"])

    def test_current_six_file_harness_and_three_payload_manifest_are_independently_bound(self):
        lab = ROOT / "scripts/provider-lab"
        names = ("fixture_servers.py", "run_lab.py", "fixture_tls.py", "fixture_pcloud.py", "fixture_gcs.py", "requirements-fixture.txt")
        self.assertEqual(set(C.HARNESSES), set(names))
        digest = hashlib.sha256()
        for name in sorted(names):
            digest.update(name.encode() + b"\0" + (lab / name).read_bytes() + b"\0")
        self.assertEqual(C.compute_harness_sha256(lab), digest.hexdigest())
        files = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
                 "nested/space name.txt": b"Nested synthetic payload.\n", "nested/bytes.bin": bytes(range(256)) * 8}
        manifest = [{"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                    for name, data in sorted(files.items())]
        fixture_sha = hashlib.sha256(json.dumps(manifest, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(C.compute_fixture_manifest_sha256(lab), fixture_sha)
        receipts = [literal_receipt(), literal_receipt(True)]
        for receipt in receipts:
            receipt.update(harness_sha256=digest.hexdigest(), fixture_manifest_sha256=fixture_sha)
        report = C.evaluate(self.catalog, self.policy, RUNTIME, receipts, digest.hexdigest(), NOW,
                            fixture_manifest_sha256=fixture_sha)
        self.assertEqual(self.local(report)["status"], "passed")
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary)
            for name in names:
                (copied / name).write_bytes((lab / name).read_bytes())
            for name in names:
                path = copied / name; original = path.read_bytes()
                path.write_bytes(original + b"\n# source drift\n")
                with self.subTest(drift=name):
                    report = C.evaluate(self.catalog, self.policy, RUNTIME, receipts,
                                        C.compute_harness_sha256(copied), NOW, fixture_manifest_sha256=fixture_sha)
                    self.assertIn("receipt_harness_mismatch", report["errors"])
                    self.assertEqual(self.local(report)["status"], "not_verified")
                path.write_bytes(original)

    def test_cli_requires_both_current_receipts_and_keeps_application_unverified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); policy = root / "policy.json"
            policy.write_text(json.dumps(self.policy), encoding="utf-8")
            lab = ROOT / "scripts/provider-lab"
            harness, fixture = C.compute_harness_sha256(lab), C.compute_fixture_manifest_sha256(lab)
            paths = []
            for low in (False, True):
                candidate = literal_receipt(low)
                candidate.update(harness_sha256=harness, fixture_manifest_sha256=fixture)
                path = root / ("low.json" if low else "anonymous.json")
                path.write_text(json.dumps(candidate), encoding="utf-8"); paths.append(path)
            for index, (selected, expected) in enumerate(((paths[:1], 1), (paths[1:], 1), (paths, 0))):
                output = root / f"ledger-{index}.json"
                argv = ["--rclone", str(root / "never-executed"), "--policy", str(policy), "--report", str(output),
                        "--require-plans", "--require-fixtures", "internetarchive"]
                for path in selected:
                    argv.extend(["--fixture-receipt", str(path)])
                with patch.object(C, "query_runtime", return_value=(RUNTIME, self.catalog)), \
                        patch.object(C.subprocess, "Popen", side_effect=AssertionError("native execution forbidden")), \
                        patch.object(C, "compute_smb_bindings", side_effect=AssertionError("unrelated bindings forbidden")), \
                        patch.object(C, "datetime", wraps=datetime) as clock, contextlib.redirect_stdout(io.StringIO()):
                    clock.now.return_value = NOW
                    status = C.main(argv)
                self.assertEqual(status, expected)
                report = json.loads(output.read_text())
                self.assertEqual(report["providers"][0]["evidence"]["application"]["status"], "not_verified")
                self.assertEqual(report["providers"][0]["evidence"]["vendor"]["status"], "not_verified")


if __name__ == "__main__":
    unittest.main()
