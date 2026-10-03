"""Offline ledger regressions: no rclone, server, credentials or cloud calls."""
import contextlib
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("provider_coverage", ROOT / "scripts" / "provider_coverage.py")
coverage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(coverage)
NOW = datetime(2026, 10, 3, 10, 0, 0, tzinfo=timezone.utc)
RUNTIME = {"version": "1.75.1", "sha256": "a" * 64, "platform": "linux"}
HARNESS = "b" * 64


def schema(backend="http"):
    return {"Name": backend, "Prefix": backend, "Options": [
        {"Name": "url", "Required": True, "IsPassword": False, "Default": "/home/private"},
        {"Name": "pass", "IsPassword": True, "Help": "Private value omitted"},
    ]}


def policy_for(catalog, application=True, vendor=True):
    required = {"local_protocol": ["listing", "download_hash", "cleanup"]}
    if application:
        required["application"] = ["authentication", "download_hash", "manifest_integrity", "cleanup"]
    if vendor:
        required["vendor"] = ["authentication", "refresh", "cleanup"]
    return {"schema_version": 1, "profiles": {"test": {"required": required}},
            "providers": {row["backend"]: {"canonical_name": row["canonical_name"],
                 "schema_sha256": row["schema_sha256"], "profile": "test"} for row in catalog}}


def receipt(backend="http"):
    return {"schema_version": 1, "scope": "rclone_backend_protocol_fixture",
            "runtime": {key: RUNTIME[key] for key in ("version", "sha256")},
            "platform": RUNTIME["platform"], "harness_sha256": HARNESS,
            "fixture_manifest_sha256": "c" * 64,
            "started_utc": coverage.utc_text(NOW - timedelta(minutes=2)),
            "finished_utc": coverage.utc_text(NOW - timedelta(minutes=1)),
            "success": True, "cleanup_passed": True, "errors": [], "backends": [{
                "backend": backend, "fixture_kind": coverage.FIXTURE_KINDS[backend],
                "capabilities": {"listing": "passed", "download_hash": "passed", "cleanup": "passed"},
                "errors": [],
            }]}


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.catalog = coverage.catalog_from_schemas([schema()])
        self.policy = policy_for(self.catalog)

    def evaluate(self, receipts=(), policy=None, catalog=None):
        return coverage.evaluate(catalog or self.catalog, policy or self.policy, RUNTIME,
                                 receipts, HARNESS, NOW, fixture_manifest_sha256="c" * 64)

    def test_digest_ignores_os_defaults_and_help_but_not_schema(self):
        first = schema()
        second = schema()
        second["Options"].reverse()
        second["Options"][1]["Default"] = "C:\\PrivateCanary\\secret"
        second["Description"] = "another OS"
        second["Options"][0]["Help"] = "changed prose"
        self.assertEqual(coverage.schema_digest(first), coverage.schema_digest(second))
        for field, value in [("Required", False), ("IsPassword", True), ("Advanced", True),
                             ("Exclusive", True), ("Provider", "different")]:
            changed = schema()
            changed["Options"][0][field] = value
            self.assertNotEqual(coverage.schema_digest(first), coverage.schema_digest(changed))

    def test_catalog_uses_prefix_and_canonical_name_not_friendly_description(self):
        entry = schema("gphotos")
        entry["Name"] = "google photos"
        entry["Description"] = "Friendly display label"
        row = coverage.catalog_from_schemas([entry])[0]
        self.assertEqual((row["backend"], row["canonical_name"]), ("gphotos", "google photos"))
        self.assertEqual(len(coverage.catalog_from_schemas([entry, schema("crypt")])), 1)

    def test_catalog_rejects_duplicate_and_malformed_contracts(self):
        for data in [[schema(), schema()], [{"Name": "http", "Prefix": "../private"}],
                     [{"Name": "http", "Options": [{"Name": "x", "Required": "true"}]}]]:
            with self.assertRaises(coverage.CoverageError):
                coverage.catalog_from_schemas(data)

    def test_provider_specific_options_can_share_a_name(self):
        native_shape = {"Name": "koofr", "Prefix": "koofr", "Options": [
            {"Name": "password", "Provider": "koofr", "IsPassword": True},
            {"Name": "password", "Provider": "digistorage", "IsPassword": True},
            {"Name": "password", "Provider": "custom", "IsPassword": True},
        ]}
        first = coverage.schema_digest(native_shape)
        native_shape["Options"].reverse()
        self.assertEqual(first, coverage.schema_digest(native_shape))
        native_shape["Options"].append(dict(native_shape["Options"][0]))
        with self.assertRaises(coverage.CoverageError):
            coverage.schema_digest(native_shape)

    def test_new_backend_does_not_inherit_pass_or_not_applicable(self):
        catalog = coverage.catalog_from_schemas([schema(), schema("future")])
        report = self.evaluate([receipt()], catalog=catalog)
        row = next(row for row in report["providers"] if row["backend"] == "future")
        self.assertEqual(row["policy_status"], "missing_plan")
        self.assertTrue(all(layer["status"] == "not_verified" for layer in row["evidence"].values()))
        self.assertFalse(report["all_plans_current"])
        self.assertIn("provider_plans_incomplete", coverage.gate_errors(report, require_plans=True))

    def test_changed_name_or_schema_is_stale(self):
        for change in ("name", "schema"):
            changed = schema()
            if change == "name":
                changed["Name"] = "http new"
            else:
                changed["Options"][0]["Required"] = False
            report = self.evaluate([receipt()], catalog=coverage.catalog_from_schemas([changed]))
            self.assertEqual(report["providers"][0]["policy_status"], "stale_schema")
            self.assertFalse(report["all_complete"])

    def test_native_local_platform_difference_uses_full_reviewed_contracts(self):
        # Pinned rclone v1.75.1 backend/local/local.go:85-88 declares nounc
        # Advanced only outside Windows. All other contract fields stay hashed.
        names = ("case_insensitive case_sensitive copy_links description encoding fatal_if_no_space "
                 "hashes links metadata_restore_special_bits no_check_updated no_clone no_preallocate "
                 "no_set_modtime no_sparse nounc one_file_system skip_links skip_specials time_type "
                 "unicode_normalization zero_size_links").split()
        native = {"Name": "local", "Prefix": "local", "Options": [
            {"Name": name, "Advanced": name != "nounc"} for name in names]}
        windows = coverage.catalog_from_schemas([native])
        self.assertEqual(windows[0]["schema_sha256"], "8f722fecb6aba29e595af50499ede2ec7b2ff348f22982ae9215256fcf5dc40b")
        next(option for option in native["Options"] if option["Name"] == "nounc")["Advanced"] = True
        linux = coverage.catalog_from_schemas([native])
        self.assertEqual(linux[0]["schema_sha256"], "547137991c5322935df6a48146252597515ec1a13e3058c370e47e0fbc99897c")
        policy = policy_for(windows)
        entry = policy["providers"]["local"]
        del entry["schema_sha256"]
        entry["schema_sha256_by_platform"] = {
            "windows": windows[0]["schema_sha256"], "linux": linux[0]["schema_sha256"]}
        for platform, catalog, other in (("windows", windows, linux), ("linux", linux, windows)):
            runtime = dict(RUNTIME, platform=platform)
            report = coverage.evaluate(catalog, policy, runtime, [], None, NOW)
            self.assertTrue(report["all_plans_current"])
            self.assertFalse(report["all_complete"])
            wrong = coverage.evaluate(other, policy, runtime, [], None, NOW)
            self.assertEqual(wrong["providers"][0]["policy_status"], "stale_schema")
            self.assertIn("provider_plans_incomplete", coverage.gate_errors(wrong, require_plans=True))
        native["Options"][0]["Required"] = True
        drift = coverage.evaluate(coverage.catalog_from_schemas([native]), policy, RUNTIME, [], None, NOW)
        self.assertEqual(drift["providers"][0]["policy_status"], "stale_schema")

    def test_unreviewed_platform_has_no_other_platform_fallback(self):
        entry = self.policy["providers"]["http"]
        expected = entry.pop("schema_sha256")
        entry["schema_sha256_by_platform"] = {"windows": expected}
        result = self.evaluate()
        self.assertEqual(result["providers"][0]["policy_status"], "unreviewed_platform")
        self.assertFalse(result["all_plans_current"])
        self.assertTrue(all(layer["status"] == "not_verified" for layer in result["providers"][0]["evidence"].values()))
        for platform in ("darwin", "Windows", "", None, ["windows"]):
            with self.assertRaisesRegex(coverage.CoverageError, "unsupported_runtime_platform"):
                coverage.evaluate(self.catalog, self.policy, dict(RUNTIME, platform=platform), [], None, NOW)

    def test_policy_platform_variants_reject_ambiguous_or_unknown_mapping(self):
        variants = ({}, {"darwin": "a" * 64}, {"linux": "invalid"}, None, ["a" * 64])
        for value in variants:
            policy = policy_for(self.catalog)
            entry = policy["providers"]["http"]
            del entry["schema_sha256"]
            entry["schema_sha256_by_platform"] = value
            with self.assertRaisesRegex(coverage.CoverageError, "invalid_policy"):
                coverage.validate_policy(policy)
        self.policy["providers"]["http"]["schema_sha256_by_platform"] = {"linux": "a" * 64}
        with self.assertRaisesRegex(coverage.CoverageError, "invalid_policy"):
            coverage.validate_policy(self.policy)
        del self.policy["providers"]["http"]["schema_sha256_by_platform"]
        del self.policy["providers"]["http"]["schema_sha256"]
        with self.assertRaisesRegex(coverage.CoverageError, "invalid_policy"):
            coverage.validate_policy(self.policy)

    def test_review_required_plan_is_not_current(self):
        self.policy["profiles"]["test"]["review_required"] = True
        report = self.evaluate([receipt()])
        self.assertEqual(report["providers"][0]["policy_status"], "review_required")
        self.assertFalse(report["all_plans_current"])

    def test_unresolved_applicability_is_a_reviewed_plan_but_not_complete(self):
        policy = policy_for(self.catalog, application=False, vendor=False)
        policy["profiles"]["test"]["unresolved_applicability"] = ["refresh"]
        report = self.evaluate([receipt()], policy=policy)
        self.assertTrue(report["all_plans_current"])
        self.assertFalse(report["all_complete"])
        self.assertEqual(report["providers"][0]["capability_applicability_review_required"], ["refresh"])
        self.assertEqual(coverage.gate_errors(report, require_plans=True), [])
        self.assertIn("provider_coverage_incomplete", coverage.gate_errors(report, require_complete=True))

    def test_retired_backend_requires_explicit_policy_retirement(self):
        self.policy["providers"]["retired"] = dict(self.policy["providers"]["http"])
        report = self.evaluate()
        self.assertEqual(report["retired_policy_backends"], ["retired"])
        self.assertFalse(report["all_plans_current"])
        self.assertIn("provider_plans_incomplete", coverage.gate_errors(report, require_plans=True))

    def test_synthetic_pass_never_becomes_vendor_or_app_acceptance(self):
        report = self.evaluate([receipt()])
        evidence = report["providers"][0]["evidence"]
        self.assertEqual(evidence["local_protocol"]["status"], "passed")
        self.assertEqual(evidence["vendor"]["status"], "not_verified")
        self.assertEqual(evidence["application"]["status"], "not_verified")
        self.assertFalse(report["all_complete"])

    def test_stale_future_runtime_platform_and_harness_receipts_rejected(self):
        cases = []
        old = receipt()
        old["started_utc"] = coverage.utc_text(NOW - timedelta(days=2, minutes=1))
        old["finished_utc"] = coverage.utc_text(NOW - timedelta(days=2))
        cases.append((old, "expired_receipt"))
        future = receipt()
        future["finished_utc"] = coverage.utc_text(NOW + timedelta(seconds=1))
        cases.append((future, "future_receipt"))
        for location, field, value, error in [
            ("runtime", "sha256", "d" * 64, "receipt_runtime_mismatch"),
            ("runtime", "version", "1.75.2", "receipt_runtime_mismatch"),
            (None, "platform", "windows", "receipt_runtime_mismatch"),
            (None, "harness_sha256", "d" * 64, "receipt_harness_mismatch"),
            (None, "fixture_manifest_sha256", "d" * 64, "receipt_fixture_manifest_mismatch"),
            (None, "schema_version", 2, "unknown_receipt_schema"),
            (None, "schema_version", True, "unknown_receipt_schema"),
        ]:
            changed = receipt()
            (changed[location] if location else changed)[field] = value
            cases.append((changed, error))
        for changed, error in cases:
            with self.subTest(error=error):
                report = self.evaluate([changed])
                self.assertIn(error, report["errors"])
                self.assertNotEqual(report["providers"][0]["evidence"]["local_protocol"]["status"], "passed")

    def test_future_start_and_duration_bounds(self):
        for start, finish in [(NOW + timedelta(seconds=1), NOW + timedelta(seconds=2)),
                              (NOW - timedelta(hours=1), NOW), (NOW, NOW - timedelta(seconds=1))]:
            changed = receipt()
            changed["started_utc"], changed["finished_utc"] = map(coverage.utc_text, (start, finish))
            self.assertTrue(self.evaluate([changed])["errors"])

    def test_failures_stay_failed_in_either_batch_order(self):
        bad = receipt()
        bad["success"] = False
        bad["backends"][0]["capabilities"]["download_hash"] = "failed"
        for batch in ([bad, receipt()], [receipt(), bad]):
            result = self.evaluate(batch)
            evidence = result["providers"][0]["evidence"]["local_protocol"]
            self.assertEqual(evidence["status"], "failed")
            self.assertEqual(evidence["capabilities"]["download_hash"], "failed")

    def test_cleanup_failure_and_inconsistent_success_cannot_pass(self):
        bad = receipt()
        bad["cleanup_passed"] = False
        self.assertIn("inconsistent_fixture_success", self.evaluate([bad])["errors"])
        bad["success"] = False
        self.assertEqual(self.evaluate([bad])["providers"][0]["evidence"]["local_protocol"]["status"], "failed")

    def test_top_level_errors_are_validated_and_cannot_be_hidden(self):
        bad = receipt()
        bad["errors"] = ["cleanup_failed"]
        self.assertIn("inconsistent_fixture_success", self.evaluate([bad])["errors"])
        bad["success"] = False
        self.assertEqual(self.evaluate([bad])["providers"][0]["evidence"]["local_protocol"]["status"], "failed")
        bad["errors"] = ["PRIVATE_CANARY https://account.invalid"]
        result = self.evaluate([bad])
        self.assertIn("invalid_fixture_errors", result["errors"])
        self.assertNotIn("PRIVATE_CANARY", json.dumps(result))

    def test_success_requires_every_emitted_capability_to_have_run(self):
        bad = receipt()
        # Even optional checks omitted from this policy cannot remain not_run
        # when the producer claims the entire fixture batch succeeded.
        bad["backends"][0]["capabilities"]["fixture_write_rejection"] = "not_run"
        self.assertIn("inconsistent_fixture_success", self.evaluate([bad])["errors"])
        bad["success"] = False
        self.assertEqual(self.evaluate([bad])["providers"][0]["evidence"]["local_protocol"]["status"], "failed")

    def test_unverified_fixture_manifest_cannot_pass(self):
        result = coverage.evaluate(self.catalog, self.policy, RUNTIME, [receipt()], HARNESS, NOW)
        self.assertIn("receipt_fixture_manifest_mismatch", result["errors"])

    def test_unknown_backend_kind_capability_or_forged_na_rejected(self):
        for field, value in [("backend", "future"), ("fixture_kind", "vendor"),
                             ("capabilities", {"refresh": "passed"}),
                             ("capabilities", {"listing": "not_applicable"})]:
            bad = receipt()
            bad["backends"][0][field] = value
            self.assertTrue(self.evaluate([bad])["errors"])

    def test_capabilities_never_inherit_unimplemented_backend_fixtures(self):
        catalog = coverage.catalog_from_schemas([schema("s3")])
        policy = policy_for(catalog)
        for capability in ("fixture_write_rejection", "truncated_download_rejection", "cancellation_cleanup"):
            bad = receipt("s3")
            bad["backends"][0]["capabilities"][capability] = "passed"
            self.assertIn("invalid_fixture_capability", self.evaluate([bad], policy, catalog)["errors"])

    def test_not_applicable_only_from_reviewed_policy(self):
        policy = policy_for(self.catalog, application=False, vendor=False)
        report = self.evaluate([receipt()], policy=policy)
        self.assertTrue(report["all_complete"])
        self.assertEqual(report["providers"][0]["evidence"]["vendor"]["status"], "not_applicable")
        policy["profiles"]["test"]["required"] = {}
        with self.assertRaises(coverage.CoverageError):
            self.evaluate([receipt()], policy=policy)

    def test_gates_distinguish_catalog_fixture_and_complete(self):
        report = self.evaluate([receipt()])
        self.assertEqual(coverage.gate_errors(report, True, ["http"]), [])
        self.assertEqual(coverage.gate_errors(report, require_fixtures=["ftp"]), ["required_fixture_not_verified"])
        self.assertIn("provider_coverage_incomplete", coverage.gate_errors(report, require_complete=True))

    def test_privacy_canaries_are_not_exported(self):
        canary = "PRIVATE_CANARY_token_account_C:\\secret_https://host.invalid"
        self.policy["providers"]["http"]["notes"] = canary
        candidate = receipt()
        candidate["raw_stderr"] = canary
        candidate["backends"][0]["remote_name"] = canary
        report = self.evaluate([candidate])
        self.assertNotIn(canary, json.dumps(report))
        candidate["backends"][0]["errors"] = [canary]
        rejected = self.evaluate([candidate])
        self.assertNotIn(canary, json.dumps(rejected))
        self.assertIn("invalid_fixture_errors", rejected["errors"])

    def test_harness_digest_is_fixed_file_list_and_detects_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for filename in coverage.HARNESSES:
                (root / filename).write_bytes(b"synthetic source\n")
            first = coverage.compute_harness_sha256(root)
            (root / "ignored-secret-file").write_bytes(b"not part of digest")
            self.assertEqual(first, coverage.compute_harness_sha256(root))
            (root / "run_lab.py").write_bytes(b"changed source")
            self.assertNotEqual(first, coverage.compute_harness_sha256(root))

    def test_fixture_manifest_recomputed_from_fixed_definition(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "fixture_servers.py"
            fixture.write_text("FILES = {'test.txt': b'synthetic'}\n")
            expected = [{"path": "test.txt", "size": 9, "sha256": coverage.sha256_bytes(b"synthetic")}]
            self.assertEqual(coverage.compute_fixture_manifest_sha256(root),
                             coverage.sha256_bytes(json.dumps(expected, separators=(",", ":")).encode()))
            fixture.write_text("FILES = {'../escape.txt': b'synthetic'}\n")
            with self.assertRaisesRegex(coverage.CoverageError, "invalid_fixture_definition"):
                coverage.compute_fixture_manifest_sha256(root)
            fixture.write_text("MISSING_FILES = 'PRIVATE_CANARY'\n")
            with self.assertRaisesRegex(coverage.CoverageError, "^invalid_fixture_definition$"):
                coverage.compute_fixture_manifest_sha256(root)

    def test_environment_excludes_ambient_auth_and_proxies(self):
        with patch.dict(os.environ, {"RCLONE_CONFIG": "private", "AWS_SECRET_ACCESS_KEY": "private", "HTTPS_PROXY": "private", "SSH_AUTH_SOCK": "private"}):
            result = coverage.isolated_environment(Path("synthetic-home"))
        self.assertFalse(any(key in result for key in ("RCLONE_CONFIG", "AWS_SECRET_ACCESS_KEY", "HTTPS_PROXY", "SSH_AUTH_SOCK")))
        self.assertEqual(result["HOME"], "synthetic-home")

    def test_runtime_hash_mismatch_precedes_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary, manifest = root / "rclone", root / "pins.env"
            binary.write_bytes(b"not a runtime")
            manifest.write_text("RCLONE_VERSION=1.75.1\nRCLONE_LINUX_EXE_SHA256=" + "a" * 64)
            with patch.object(coverage.platform_module, "system", return_value="Linux"), patch.object(coverage, "run_metadata") as run:
                with self.assertRaisesRegex(coverage.CoverageError, "runtime_hash_mismatch"):
                    coverage.query_runtime(binary, manifest)
                run.assert_not_called()

    def test_metadata_runs_only_rehashed_private_copy_and_removes_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary, manifest = root / "rclone", root / "pins.env"
            payload = b"synthetic nonexecutable runtime"
            binary.write_bytes(payload)
            manifest.write_text("RCLONE_VERSION=1.75.1\nRCLONE_LINUX_EXE_SHA256=" + coverage.sha256_bytes(payload))
            executed = []

            def metadata(executable, arguments, config, environment):
                self.assertNotEqual(executable, binary)
                self.assertEqual(executable.read_bytes(), payload)
                self.assertEqual(config.read_bytes(), b"")
                self.assertEqual(executable.parent, config.parent)
                executed.append(executable)
                return b"rclone v1.75.1\n" if arguments == ["version"] else json.dumps([schema()]).encode()

            with patch.object(coverage.platform_module, "system", return_value="Linux"), patch.object(coverage, "run_metadata", side_effect=metadata):
                coverage.query_runtime(binary, manifest)
            self.assertEqual(len(executed), 2)
            self.assertTrue(all(not path.exists() for path in executed))
            self.assertEqual(binary.read_bytes(), payload)

    def test_runtime_copy_mutation_fails_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary, manifest = root / "rclone", root / "pins.env"
            binary.write_bytes(b"original")
            manifest.write_text("RCLONE_VERSION=1.75.1\nRCLONE_LINUX_EXE_SHA256=" + coverage.sha256_bytes(b"original"))
            with patch.object(coverage.platform_module, "system", return_value="Linux"), patch.object(coverage, "run_metadata") as run, patch.object(coverage.shutil, "copyfile", side_effect=lambda source, target: target.write_bytes(b"changed")):
                with self.assertRaisesRegex(coverage.CoverageError, "runtime_copy_hash_mismatch"):
                    coverage.query_runtime(binary, manifest)
                run.assert_not_called()

    def test_report_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "report.json"
            coverage.write_report({"test": "original"}, target)
            original = target.read_bytes()
            with self.assertRaisesRegex(coverage.CoverageError, "report_already_exists"):
                coverage.write_report({"test": "replacement"}, target)
            self.assertEqual(target.read_bytes(), original)

    def test_cli_writes_report_before_failing_completion_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy, output = root / "policy.json", root / "report.json"
            policy.write_text(json.dumps(self.policy))
            with patch.object(coverage, "query_runtime", return_value=(RUNTIME, self.catalog)), contextlib.redirect_stdout(io.StringIO()):
                status = coverage.main(["--rclone", str(root / "unused"), "--policy", str(policy), "--report", str(output), "--require-complete"])
            self.assertEqual(status, 1)
            report = json.loads(output.read_text())
            self.assertEqual(len(report["providers"]), 1)
            self.assertIn("provider_coverage_incomplete", report["gate_errors"])

    def test_cli_preserves_catalog_when_policy_is_malformed_and_suppresses_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy, output = root / "policy.json", root / "report.json"
            policy.write_text("PRIVATE_CANARY-invalid-JSON")
            captured = io.StringIO()
            with patch.object(coverage, "query_runtime", return_value=(RUNTIME, self.catalog)), contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
                status = coverage.main(["--rclone", str(root / "unused"), "--policy", str(policy), "--report", str(output)])
            self.assertEqual(status, 1)
            report = json.loads(output.read_text())
            self.assertEqual(len(report["providers"]), 1)
            self.assertNotIn("PRIVATE_CANARY", captured.getvalue() + output.read_text())

    def test_invalid_freshness_or_filter_cannot_weaken_gates(self):
        for value in [0, -1, 169]:
            with self.assertRaises(coverage.CoverageError):
                coverage.evaluate(self.catalog, self.policy, RUNTIME, [], HARNESS, NOW, value)
        for value in [",", "http,", "https://private"]:
            with self.assertRaises(coverage.CoverageError):
                coverage.parse_required(value)


if __name__ == "__main__":
    unittest.main()
