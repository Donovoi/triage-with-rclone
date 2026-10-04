"""Offline ledger regressions: no rclone, server, credentials or cloud calls."""
import contextlib
import copy
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
        {"Name": "url", "Type": "string", "Required": True, "IsPassword": False, "Default": "/home/private"},
        {"Name": "pass", "Type": "string", "IsPassword": True, "Help": "Private value omitted"},
    ]}


def policy_for(catalog, application=True, vendor=True):
    required = {"local_protocol": ["listing", "download_hash", "cleanup"],
                "application": ["download_hash", "manifest_integrity", "cleanup"]}
    if application:
        required["application"].append("authentication")
    if vendor:
        required["vendor"] = ["authentication", "refresh", "cleanup"]
        required["application"].append("refresh")
        if "authentication" not in required["application"]:
            required["application"].append("authentication")
    refresh = "required" if vendor else "not_applicable"
    return {"schema_version": 2, "profiles": {"test": {"required": required}},
            "providers": {row["backend"]: {"canonical_name": row["canonical_name"],
                 "schema_sha256": row["schema_sha256"], "profile": "test",
                 "auth_applicability": "credentials" if application or vendor else "none",
                 "refresh_applicability": refresh,
                 "reauthentication_applicability": "not_applicable",
                 "source_links": ["https://example.invalid/official-provider-documentation"],
                 "renewal_modes": [renewal_mode(refresh)]} for row in catalog}}


def renewal_mode(requirement="required", reauthentication="not_applicable"):
    return {"auth_mode": "synthetic reviewed mode", "credential_renewal_requirement": requirement,
            "connection_session_reauthentication_requirement": reauthentication,
            "renewal_kind": "provider_specific" if requirement == "review_required" else
                            "oauth_refresh_token" if requirement == "required" else "none",
            "source_supported_behavior": "Synthetic source-backed behavior for validation.",
            "required_lifecycle_scenarios": ["verify lifecycle using synthetic data"]}


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


def swift_receipt():
    candidate = receipt("swift")
    candidate["backends"][0]["capabilities"] = {
        capability: "passed" for capability in coverage.SWIFT_REQUIRED_CAPABILITIES
    }
    return candidate


def b2_receipt():
    candidate = receipt("b2")
    candidate["backends"][0]["capabilities"] = {
        capability: "passed" for capability in coverage.B2_REQUIRED_CAPABILITIES
    }
    return candidate


def read_fixture_receipt(backend):
    candidate = receipt(backend)
    candidate["backends"][0]["capabilities"] = {
        capability: "passed" for capability in coverage.READ_FIXTURE_CONTRACTS[backend]
    }
    return candidate


def azureblob_receipt():
    return read_fixture_receipt("azureblob")


def azurefiles_receipt():
    return read_fixture_receipt("azurefiles")


def seafile_receipt():
    return read_fixture_receipt("seafile")


def koofr_receipt():
    return read_fixture_receipt("koofr")


def filefabric_receipt():
    return read_fixture_receipt("filefabric")


def pixeldrain_receipt():
    return read_fixture_receipt("pixeldrain")


def memory_receipt():
    candidate = receipt("memory")
    candidate["backends"][0]["capabilities"] = {
        capability: "passed" for capability in coverage.MEMORY_REQUIRED_CAPABILITIES
    }
    candidate["backends"][0]["capabilities"]["authentication_rejection"] = "not_applicable"
    return candidate


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
                             ("Exclusive", True), ("Provider", "different"), ("Type", "bool"), ("Type", "Duration")]:
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
                     [{"Name": "http", "Options": [{"Name": "x", "Type": "string", "Required": "true"}]}]]:
            with self.assertRaises(coverage.CoverageError):
                coverage.catalog_from_schemas(data)

    def test_type_is_required_and_type_only_drift_invalidates_plan(self):
        for value in (None, "", False, [], "string\nprivate", "string/unsafe", "string|"):
            changed = schema()
            changed["Options"][0]["Type"] = value
            with self.assertRaises(coverage.CoverageError):
                coverage.canonical_schema(changed)
        missing = schema()
        del missing["Options"][0]["Type"]
        with self.assertRaises(coverage.CoverageError):
            coverage.canonical_schema(missing)
        for value in ("bool", "Duration", "mtime|atime|btime|ctime"):
            changed = schema()
            changed["Options"][0]["Type"] = value
            report = self.evaluate(catalog=coverage.catalog_from_schemas([changed]))
            self.assertEqual(report["providers"][0]["policy_status"], "stale_schema")
            self.assertIn("provider_plans_incomplete", coverage.gate_errors(report, require_plans=True))

    def test_plan_requires_auth_refresh_sources_and_renewal_modes(self):
        for field in ("auth_applicability", "refresh_applicability", "reauthentication_applicability", "source_links", "renewal_modes"):
            policy = copy.deepcopy(self.policy)
            del policy["providers"]["http"][field]
            with self.assertRaisesRegex(coverage.CoverageError, "invalid_policy"):
                coverage.validate_policy(policy)
        for field, value in (("auth_applicability", "maybe"), ("refresh_applicability", "maybe"),
                             ("source_links", []), ("source_links", "https://example.invalid/docs"),
                             ("renewal_modes", [])):
            policy = copy.deepcopy(self.policy)
            policy["providers"]["http"][field] = value
            with self.assertRaisesRegex(coverage.CoverageError, "invalid_policy"):
                coverage.validate_policy(policy)

    def test_source_links_are_https_without_userinfo_or_malformed_host(self):
        for source in ("http://example.invalid/docs", "https://user:password@example.invalid/docs",
                       "https://user@example.invalid/docs", "/relative", "https:///no-host",
                       "https://example.invalid:99999/docs", "https://example.invalid\\private",
                       "https://example.invalid/with space", "https://[invalid/docs"):
            policy = copy.deepcopy(self.policy)
            policy["providers"]["http"]["source_links"] = [source]
            with self.subTest(source=source), self.assertRaisesRegex(coverage.CoverageError, "invalid_policy"):
                coverage.validate_policy(policy)
        self.policy["providers"]["http"]["source_links"] = ["https://github.com/rclone/rclone/blob/v1.75.1/backend/local/local.go#L85-L88"]
        coverage.validate_policy(self.policy)

    def test_mode_fields_types_and_lifecycle_requirements_are_validated(self):
        invalid = []
        missing = renewal_mode()
        del missing["source_supported_behavior"]
        invalid.append(missing)
        invalid.append(dict(renewal_mode(), ignored_decision="must not be silently ignored"))
        for field, value in (("auth_mode", ""), ("renewal_kind", "unknown kind"),
                             ("source_supported_behavior", " "), ("credential_renewal_requirement", "maybe"),
                             ("connection_session_reauthentication_requirement", "maybe"),
                             ("required_lifecycle_scenarios", []), ("required_lifecycle_scenarios", "untyped"),
                             ("required_lifecycle_scenarios", [""]), ("required_lifecycle_scenarios", [False])):
            invalid.append(dict(renewal_mode(), **{field: value}))
        for mode in invalid:
            policy = copy.deepcopy(self.policy)
            policy["providers"]["http"]["renewal_modes"] = [mode]
            with self.assertRaisesRegex(coverage.CoverageError, "invalid_policy"):
                coverage.validate_policy(policy)
        self.policy["providers"]["http"]["renewal_modes"].append(renewal_mode())
        with self.assertRaisesRegex(coverage.CoverageError, "invalid_policy"):
            coverage.validate_policy(self.policy)

    def test_mode_aggregate_and_profile_refresh_decisions_must_agree(self):
        for requirement in ("required", "not_applicable", "review_required"):
            policy = policy_for(self.catalog, vendor=requirement == "required")
            entry = policy["providers"]["http"]
            entry["refresh_applicability"] = requirement
            entry["renewal_modes"] = [renewal_mode(requirement)]
            if requirement == "review_required":
                policy["profiles"]["test"]["unresolved_applicability"] = ["refresh"]
            coverage.validate_policy(policy)
            for wrong in coverage.LIFECYCLE_APPLICABILITY - {requirement}:
                entry["refresh_applicability"] = wrong
                with self.assertRaisesRegex(coverage.CoverageError, "invalid_policy"):
                    coverage.validate_policy(policy)
        # A known renewal requirement remains mandatory alongside unresolved modes.
        policy = copy.deepcopy(self.policy)
        policy["providers"]["http"]["refresh_applicability"] = "review_required"
        policy["providers"]["http"]["renewal_modes"].append(dict(renewal_mode("review_required"), auth_mode="unresolved mode"))
        policy["profiles"]["test"]["unresolved_applicability"] = ["refresh"]
        coverage.validate_policy(policy)
        del policy["profiles"]["test"]["unresolved_applicability"]
        with self.assertRaisesRegex(coverage.CoverageError, "invalid_policy"):
            coverage.validate_policy(policy)
        policy = copy.deepcopy(self.policy)
        policy["profiles"]["test"]["unresolved_applicability"] = ["refresh"]
        with self.assertRaisesRegex(coverage.CoverageError, "invalid_policy"):
            coverage.validate_policy(policy)

    def test_app_tier_and_applicable_auth_refresh_cannot_be_omitted(self):
        missing_app = copy.deepcopy(self.policy)
        del missing_app["profiles"]["test"]["required"]["application"]
        with self.assertRaisesRegex(coverage.CoverageError, "invalid_policy"):
            coverage.validate_policy(missing_app)
        for tier in ("application", "vendor"):
            for capability in ("authentication", "refresh"):
                policy = copy.deepcopy(self.policy)
                policy["profiles"]["test"]["required"][tier].remove(capability)
                with self.assertRaisesRegex(coverage.CoverageError, "invalid_policy"):
                    coverage.validate_policy(policy)
        policy = policy_for(self.catalog, application=False, vendor=False)
        policy["profiles"]["test"]["required"]["application"].append("refresh")
        with self.assertRaisesRegex(coverage.CoverageError, "invalid_policy"):
            coverage.validate_policy(policy)
        del policy["profiles"]["test"]["required"]["local_protocol"]
        policy["profiles"]["test"]["required"]["application"].remove("refresh")
        report = self.evaluate(policy=policy)
        self.assertTrue(report["all_plans_current"])
        self.assertEqual(report["providers"][0]["evidence"]["local_protocol"]["status"], "not_applicable")
        self.assertFalse(report["all_complete"])

    def test_policy_v1_and_conflated_mode_field_are_rejected(self):
        old = copy.deepcopy(self.policy)
        old["schema_version"] = 1
        with self.assertRaisesRegex(coverage.CoverageError, "invalid_policy"):
            coverage.validate_policy(old)
        old = copy.deepcopy(self.policy)
        mode = old["providers"]["http"]["renewal_modes"][0]
        mode["refresh_capability_requirement"] = mode.pop("credential_renewal_requirement")
        with self.assertRaisesRegex(coverage.CoverageError, "invalid_policy"):
            coverage.validate_policy(old)
        mode["credential_renewal_requirement"] = mode.pop("refresh_capability_requirement")
        del mode["connection_session_reauthentication_requirement"]
        with self.assertRaisesRegex(coverage.CoverageError, "invalid_policy"):
            coverage.validate_policy(old)

    def test_reauthentication_is_independent_of_credential_renewal(self):
        policy = copy.deepcopy(self.policy)
        entry = policy["providers"]["http"]
        entry["refresh_applicability"] = "not_applicable"
        entry["reauthentication_applicability"] = "required"
        entry["renewal_modes"] = [renewal_mode("not_applicable", "required")]
        for tier in ("application", "vendor"):
            capabilities = policy["profiles"]["test"]["required"][tier]
            capabilities.remove("refresh")
            capabilities.append("reauthentication")
        result = self.evaluate([receipt()], policy=policy)
        self.assertTrue(result["all_plans_current"])
        self.assertFalse(result["all_complete"])
        self.assertEqual(result["policy_schema_version"], 2)
        self.assertEqual(result["providers"][0]["lifecycle_applicability"], {
            "credential_renewal": "not_applicable", "connection_session_reauthentication": "required"})
        self.assertEqual(result["applicability_summary"]["credential_renewal"]["not_applicable"], 1)
        self.assertEqual(result["applicability_summary"]["connection_session_reauthentication"]["required"], 1)
        for tier in ("application", "vendor"):
            broken = copy.deepcopy(policy)
            broken["profiles"]["test"]["required"][tier].remove("reauthentication")
            with self.assertRaisesRegex(coverage.CoverageError, "invalid_policy"):
                coverage.validate_policy(broken)

    def test_pinned_kerberos_service_ticket_obligations_are_not_waived_by_external_tgt_lifecycle(self):
        # Both pinned adapters call gokrb5/v8 GetServiceTicket: v8.4.4's
        # cache.go:99-132 can renew a service ticket, and TGSExchange.go:84-107
        # can acquire another using the session TGT. NewFromCCache's lack of
        # automatic TGT renewal must not erase these distinct obligations.
        policy = coverage.read_json(ROOT / "provider-coverage-policy.json")
        for backend, name in (("hdfs", "Kerberos FILE credential cache"),
                              ("smb", "Kerberos credential cache")):
            entry = policy["providers"][backend]
            mode = next(mode for mode in entry["renewal_modes"] if mode["auth_mode"] == name)
            self.assertEqual(mode["credential_renewal_requirement"], "required")
            self.assertEqual(mode["connection_session_reauthentication_requirement"], "required")
            required = policy["profiles"][entry["profile"]]["required"]["application"]
            self.assertTrue({"refresh", "reauthentication"}.issubset(required))

    def test_unknown_session_modes_block_completion_without_waiving_known_modes(self):
        policy = copy.deepcopy(self.policy)
        entry = policy["providers"]["http"]
        entry["reauthentication_applicability"] = "review_required"
        entry["renewal_modes"] = [renewal_mode("required", "required"),
            dict(renewal_mode("required", "review_required"), auth_mode="session semantics unreviewed")]
        profile = policy["profiles"]["test"]
        profile["unresolved_applicability"] = ["reauthentication"]
        for tier in ("application", "vendor"):
            profile["required"][tier].append("reauthentication")
        report = self.evaluate([receipt()], policy=policy)
        self.assertEqual(coverage.gate_errors(report, require_plans=True), [])
        self.assertFalse(report["all_complete"])
        self.assertEqual(report["providers"][0]["capability_applicability_review_required"], ["reauthentication"])
        self.assertEqual(report["applicability_summary"]["credential_renewal"]["required"], 1)
        self.assertEqual(report["applicability_summary"]["connection_session_reauthentication"]["review_required"], 1)
        for tier in ("application", "vendor"):
            broken = copy.deepcopy(policy)
            broken["profiles"]["test"]["required"][tier].remove("reauthentication")
            with self.assertRaisesRegex(coverage.CoverageError, "invalid_policy"):
                coverage.validate_policy(broken)
        for decision in ("required", "not_applicable"):
            broken = copy.deepcopy(policy)
            broken["providers"]["http"]["reauthentication_applicability"] = decision
            with self.assertRaisesRegex(coverage.CoverageError, "invalid_policy"):
                coverage.validate_policy(broken)
        profile["unresolved_applicability"] = []
        with self.assertRaisesRegex(coverage.CoverageError, "invalid_policy"):
            coverage.validate_policy(policy)

    def test_stale_and_missing_plans_do_not_report_reviewed_lifecycle_decisions(self):
        changed = schema()
        changed["Options"][0]["Type"] = "Duration"
        catalog = coverage.catalog_from_schemas([changed, schema("future")])
        report = self.evaluate(catalog=catalog)
        for summary in report["applicability_summary"].values():
            self.assertEqual(summary["not_verified"], 2)
            self.assertEqual(sum(summary[state] for state in coverage.LIFECYCLE_APPLICABILITY), 0)
        for row in report["providers"]:
            self.assertEqual(set(row["lifecycle_applicability"].values()), {"not_verified"})

    def test_provider_specific_options_can_share_a_name(self):
        native_shape = {"Name": "koofr", "Prefix": "koofr", "Options": [
            {"Name": "password", "Type": "string", "Provider": "koofr", "IsPassword": True},
            {"Name": "password", "Type": "string", "Provider": "digistorage", "IsPassword": True},
            {"Name": "password", "Type": "string", "Provider": "custom", "IsPassword": True},
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
        types = {"time_type": "mtime|atime|btime|ctime", "hashes": "CommaSepList", "encoding": "Encoding", "description": "string"}
        native = {"Name": "local", "Prefix": "local", "Options": [
            {"Name": name, "Type": types.get(name, "bool"), "Advanced": name != "nounc"} for name in names]}
        windows = coverage.catalog_from_schemas([native])
        self.assertEqual(windows[0]["schema_sha256"], "f99eb9bf2ab8d3a4af2234b84e22db1f9a5d57b7b3b931e912a2a269a351d67c")
        next(option for option in native["Options"] if option["Name"] == "nounc")["Advanced"] = True
        linux = coverage.catalog_from_schemas([native])
        self.assertEqual(linux[0]["schema_sha256"], "a901743e50c3c5839c644f8fef3d77c525d4d2b9909ca894c7dc8449e73256fb")
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
        policy = policy_for(self.catalog)
        policy["profiles"]["test"]["unresolved_applicability"] = ["refresh"]
        policy["providers"]["http"]["refresh_applicability"] = "review_required"
        policy["providers"]["http"]["renewal_modes"].append(dict(renewal_mode("review_required"), auth_mode="unresolved mode"))
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

    def test_host_key_rejection_is_supported_only_for_sftp(self):
        for backend in coverage.FIXTURE_KINDS:
            catalog = coverage.catalog_from_schemas([schema(backend)])
            policy = policy_for(catalog)
            policy["profiles"]["test"]["required"]["local_protocol"].append("host_key_rejection")
            candidate = receipt(backend)
            candidate["backends"][0]["capabilities"]["host_key_rejection"] = "passed"
            report = self.evaluate([candidate], policy, catalog)
            if backend == "sftp":
                self.assertEqual(report["providers"][0]["evidence"]["local_protocol"]["status"], "passed")
                self.assertFalse(report["all_complete"])
            else:
                self.assertIn("invalid_fixture_capability", report["errors"])

    def test_archive_protocol_receipt_is_bound_and_cannot_qualify_application(self):
        catalog = coverage.catalog_from_schemas([schema("archive")])
        policy = policy_for(catalog, application=False, vendor=False)
        required = ["listing", "download_hash", "missing_object_rejection", "source_preservation",
                    "cleanup", "fixture_write_rejection", *sorted(coverage.ARCHIVE_CAPABILITIES)]
        policy["profiles"]["test"]["required"]["local_protocol"] = required
        candidate = receipt("archive")
        candidate["backends"][0]["capabilities"] = {capability: "passed" for capability in required}
        candidate["backends"][0]["capabilities"]["authentication_rejection"] = "not_applicable"
        report = self.evaluate([candidate], policy, catalog)
        row = report["providers"][0]
        self.assertEqual(row["evidence"]["local_protocol"]["status"], "passed")
        self.assertEqual(row["evidence"]["application"]["status"], "not_verified")
        self.assertFalse(report["all_complete"])
        self.assertEqual(coverage.gate_errors(report, require_fixtures=["archive"]), [])
        for capability in required:
            incomplete = copy.deepcopy(candidate)
            del incomplete["backends"][0]["capabilities"][capability]
            result = self.evaluate([incomplete], policy, catalog)
            self.assertIn("required_fixture_not_verified", coverage.gate_errors(result, require_fixtures=["archive"]))
        failed = copy.deepcopy(candidate)
        failed["success"] = False
        failed["backends"][0]["capabilities"]["archive_crc32"] = "failed"
        sticky = self.evaluate([failed, candidate], policy, catalog)
        self.assertEqual(sticky["providers"][0]["evidence"]["local_protocol"]["status"], "failed")
        forged = copy.deepcopy(candidate)
        forged["backends"][0]["fixture_kind"] = "rclone_loopback"
        self.assertIn("unknown_fixture_backend", self.evaluate([forged], policy, catalog)["errors"])

    def test_archive_capabilities_and_auth_na_cannot_be_reused_by_other_backends(self):
        for backend in set(coverage.FIXTURE_KINDS) - {"archive"}:
            catalog = coverage.catalog_from_schemas([schema(backend)])
            policy = policy_for(catalog)
            for capability in coverage.ARCHIVE_ONLY_CAPABILITIES:
                candidate = receipt(backend)
                candidate["backends"][0]["capabilities"][capability] = "passed"
                self.assertIn("invalid_fixture_capability", self.evaluate([candidate], policy, catalog)["errors"])
            if backend not in ("local", "memory"):
                candidate = receipt(backend)
                candidate["backends"][0]["capabilities"]["authentication_rejection"] = "not_applicable"
                self.assertIn("invalid_fixture_not_applicable", self.evaluate([candidate], policy, catalog)["errors"])
        candidate = receipt("archive")
        candidate["backends"][0]["capabilities"]["config_preservation"] = "not_applicable"
        catalog = coverage.catalog_from_schemas([schema("archive")])
        self.assertIn("invalid_fixture_not_applicable", self.evaluate([candidate], policy_for(catalog), catalog)["errors"])

    def test_archive_cannot_skip_negative_checks_even_if_policy_is_weaker(self):
        catalog = coverage.catalog_from_schemas([schema("archive")])
        policy = policy_for(catalog, application=False, vendor=False)
        candidate = receipt("archive")
        candidate["backends"][0]["capabilities"] = {capability: "passed" for capability in coverage.ARCHIVE_REQUIRED_CAPABILITIES}
        candidate["backends"][0]["capabilities"]["authentication_rejection"] = "not_applicable"
        for omitted in coverage.ARCHIVE_REQUIRED_CAPABILITIES:
            incomplete = copy.deepcopy(candidate)
            del incomplete["backends"][0]["capabilities"][omitted]
            self.assertIn("invalid_fixture_capability", self.evaluate([incomplete], policy, catalog)["errors"])
        candidate["backends"][0]["capabilities"]["authentication_rejection"] = "passed"
        self.assertIn("invalid_fixture_capability", self.evaluate([candidate], policy, catalog)["errors"])

    def test_protocol_fixtures_cannot_claim_reauthentication(self):
        candidate = receipt()
        candidate["backends"][0]["capabilities"]["reauthentication"] = "passed"
        self.assertIn("invalid_fixture_capability", self.evaluate([candidate])["errors"])

    def test_swift_contract_cannot_qualify_application_or_vendor_lifecycle(self):
        catalog = coverage.catalog_from_schemas([schema("swift")])
        policy = policy_for(catalog)
        required = policy["profiles"]["test"]["required"]
        required["local_protocol"] = sorted(coverage.SWIFT_REQUIRED_CAPABILITIES)
        for tier in ("application", "vendor"):
            required[tier].append("reauthentication")
        entry = policy["providers"]["swift"]
        entry["reauthentication_applicability"] = "required"
        entry["renewal_modes"][0]["connection_session_reauthentication_requirement"] = "required"
        report = self.evaluate([swift_receipt()], policy, catalog)
        evidence = report["providers"][0]["evidence"]
        self.assertEqual(evidence["local_protocol"]["status"], "passed")
        self.assertEqual(set(evidence["local_protocol"]["capabilities"]), coverage.SWIFT_REQUIRED_CAPABILITIES)
        for tier in ("application", "vendor"):
            self.assertEqual(evidence[tier]["status"], "not_verified")
            self.assertEqual(evidence[tier]["capabilities"]["refresh"], "not_verified")
            self.assertEqual(evidence[tier]["capabilities"]["reauthentication"], "not_verified")
        self.assertEqual(coverage.gate_errors(report, require_plans=True, require_fixtures=["swift"]), [])
        self.assertIn("provider_coverage_incomplete", coverage.gate_errors(report, require_complete=True))

    def test_swift_requires_every_capability_even_with_weaker_policy(self):
        catalog = coverage.catalog_from_schemas([schema("swift")])
        policy = policy_for(catalog)
        for omitted in coverage.SWIFT_REQUIRED_CAPABILITIES:
            candidate = swift_receipt()
            del candidate["backends"][0]["capabilities"][omitted]
            with self.subTest(omitted=omitted):
                report = self.evaluate([candidate], policy, catalog)
                self.assertIn("invalid_fixture_capability", report["errors"])
                self.assertIn("required_fixture_not_verified", coverage.gate_errors(report, require_fixtures=["swift"]))
        for extra in ("refresh", "reauthentication", "host_key_rejection", "archive_crc32",
                      "truncated_download_rejection", "cancellation_cleanup"):
            candidate = swift_receipt()
            candidate["backends"][0]["capabilities"][extra] = "passed"
            with self.subTest(extra=extra):
                self.assertIn("invalid_fixture_capability", self.evaluate([candidate], policy, catalog)["errors"])

    def test_swift_does_not_accept_wrong_fixture_kind_or_na_outcomes(self):
        catalog = coverage.catalog_from_schemas([schema("swift")])
        policy = policy_for(catalog)
        for kind in ("local", "rclone_loopback", "vendor"):
            candidate = swift_receipt()
            candidate["backends"][0]["fixture_kind"] = kind
            self.assertIn("unknown_fixture_backend", self.evaluate([candidate], policy, catalog)["errors"])
        for capability in coverage.SWIFT_REQUIRED_CAPABILITIES:
            for value, error in (("not_applicable", "invalid_fixture_not_applicable"),
                                 (True, "invalid_fixture_outcome"),
                                 ("not_run", "inconsistent_fixture_success"),
                                 ("failed", "inconsistent_fixture_success")):
                candidate = swift_receipt()
                candidate["backends"][0]["capabilities"][capability] = value
                with self.subTest(capability=capability, value=value):
                    self.assertIn(error, self.evaluate([candidate], policy, catalog)["errors"])

    def test_swift_renewal_capabilities_cannot_be_forged_for_other_backends(self):
        for backend in set(coverage.FIXTURE_KINDS) - {"swift"}:
            catalog = coverage.catalog_from_schemas([schema(backend)])
            policy = policy_for(catalog)
            for capability in coverage.SWIFT_ONLY_CAPABILITIES:
                candidate = receipt(backend)
                if backend == "archive":
                    candidate["backends"][0]["capabilities"] = {
                        key: "passed" for key in coverage.ARCHIVE_REQUIRED_CAPABILITIES
                    }
                    candidate["backends"][0]["capabilities"]["authentication_rejection"] = "not_applicable"
                candidate["backends"][0]["capabilities"][capability] = "passed"
                with self.subTest(backend=backend, capability=capability):
                    self.assertIn("invalid_fixture_capability", self.evaluate([candidate], policy, catalog)["errors"])

    def test_config_preservation_supported_only_for_reviewed_fixtures(self):
        for backend in coverage.FIXTURE_KINDS:
            catalog = coverage.catalog_from_schemas([schema(backend)])
            policy = policy_for(catalog)
            candidate = {"swift": swift_receipt, "b2": b2_receipt, "azureblob": azureblob_receipt,
                         "azurefiles": azurefiles_receipt, "seafile": seafile_receipt,
                         "memory": memory_receipt, "koofr": koofr_receipt,
                         "pixeldrain": pixeldrain_receipt, "filefabric": filefabric_receipt}.get(backend, lambda: receipt(backend))()
            if backend == "archive":
                candidate["backends"][0]["capabilities"] = {
                    key: "passed" for key in coverage.ARCHIVE_REQUIRED_CAPABILITIES
                }
                candidate["backends"][0]["capabilities"]["authentication_rejection"] = "not_applicable"
            candidate["backends"][0]["capabilities"]["config_preservation"] = "passed"
            report = self.evaluate([candidate], policy, catalog)
            with self.subTest(backend=backend):
                if backend in ("archive", "memory", "swift", "b2", "azureblob", "azurefiles", "seafile", "koofr", "pixeldrain", "filefabric"):
                    self.assertEqual(report["providers"][0]["evidence"]["local_protocol"]["status"], "passed")
                else:
                    self.assertIn("invalid_fixture_capability", report["errors"])

    def test_swift_renewal_failure_is_sticky_and_current_provenance_required(self):
        catalog = coverage.catalog_from_schemas([schema("swift")])
        policy = policy_for(catalog)
        for capability in coverage.SWIFT_ONLY_CAPABILITIES | {"renewal_denial"}:
            failed = swift_receipt()
            failed["success"] = False
            failed["backends"][0]["capabilities"][capability] = "failed"
            for batch in ([failed, swift_receipt()], [swift_receipt(), failed]):
                result = self.evaluate(batch, policy, catalog)
                self.assertEqual(result["providers"][0]["evidence"]["local_protocol"]["status"], "failed")
        for field, value, error in (("harness_sha256", "d" * 64, "receipt_harness_mismatch"),
                                    ("fixture_manifest_sha256", "d" * 64, "receipt_fixture_manifest_mismatch"),
                                    ("platform", "windows", "receipt_runtime_mismatch"),
                                    ("finished_utc", coverage.utc_text(NOW + timedelta(seconds=1)), "future_receipt")):
            candidate = swift_receipt()
            candidate[field] = value
            self.assertIn(error, self.evaluate([candidate], policy, catalog)["errors"])
        candidate = swift_receipt()
        candidate["started_utc"] = coverage.utc_text(NOW - timedelta(days=2, minutes=1))
        candidate["finished_utc"] = coverage.utc_text(NOW - timedelta(days=2))
        self.assertIn("expired_receipt", self.evaluate([candidate], policy, catalog)["errors"])

    def test_b2_contract_never_qualifies_application_vendor_or_other_lifecycle(self):
        catalog = coverage.catalog_from_schemas([schema("b2")])
        policy = policy_for(catalog)
        required = policy["profiles"]["test"]["required"]
        required["local_protocol"] = sorted(coverage.B2_REQUIRED_CAPABILITIES)
        for tier in ("application", "vendor"):
            required[tier].append("reauthentication")
        entry = policy["providers"]["b2"]
        entry["reauthentication_applicability"] = "required"
        entry["renewal_modes"][0]["connection_session_reauthentication_requirement"] = "required"
        result = self.evaluate([b2_receipt()], policy, catalog)
        evidence = result["providers"][0]["evidence"]
        self.assertEqual(evidence["local_protocol"]["status"], "passed")
        self.assertEqual(set(evidence["local_protocol"]["capabilities"]), coverage.B2_REQUIRED_CAPABILITIES)
        for tier in ("application", "vendor"):
            self.assertEqual(evidence[tier]["status"], "not_verified")
            for capability in ("authentication", "refresh", "reauthentication"):
                self.assertEqual(evidence[tier]["capabilities"][capability], "not_verified")
        self.assertEqual(coverage.gate_errors(result, require_plans=True, require_fixtures=["b2"]), [])
        self.assertIn("provider_coverage_incomplete", coverage.gate_errors(result, require_complete=True))

    def test_b2_contract_requires_exact_capabilities_and_executed_outcomes(self):
        catalog = coverage.catalog_from_schemas([schema("b2")])
        # A weaker profile cannot bypass the producer's mandatory negative cases.
        policy = policy_for(catalog)
        for capability in coverage.B2_REQUIRED_CAPABILITIES:
            for value, error in ((None, "invalid_fixture_capability"),
                                 ("not_applicable", "invalid_fixture_not_applicable"),
                                 (True, "invalid_fixture_outcome"),
                                 ("failed", "inconsistent_fixture_success"),
                                 ("not_run", "inconsistent_fixture_success")):
                candidate = b2_receipt()
                if value is None:
                    del candidate["backends"][0]["capabilities"][capability]
                else:
                    candidate["backends"][0]["capabilities"][capability] = value
                with self.subTest(capability=capability, value=value):
                    result = self.evaluate([candidate], policy, catalog)
                    self.assertIn(error, result["errors"])
                    self.assertIn("required_fixture_not_verified", coverage.gate_errors(result, require_fixtures=["b2"]))
        for capability in ("service_token_reacquisition", "refresh", "reauthentication", "archive_crc32",
                           "host_key_rejection", "truncated_download_rejection", "cancellation_cleanup"):
            candidate = b2_receipt()
            candidate["backends"][0]["capabilities"][capability] = "passed"
            self.assertIn("invalid_fixture_capability", self.evaluate([candidate], policy, catalog)["errors"])

    def test_b2_and_shared_renewal_capabilities_are_backend_scoped(self):
        for backend in coverage.FIXTURE_KINDS:
            catalog = coverage.catalog_from_schemas([schema(backend)])
            policy = policy_for(catalog)
            for capability, allowed in (("account_token_reacquisition", {"b2"}),
                                        ("service_token_reacquisition", {"swift"}),
                                        ("renewal_denial", {"swift", "b2"})):
                candidate = {"swift": swift_receipt, "b2": b2_receipt, "azureblob": azureblob_receipt,
                             "azurefiles": azurefiles_receipt, "seafile": seafile_receipt}.get(backend, lambda: receipt(backend))()
                if backend == "archive":
                    candidate["backends"][0]["capabilities"] = {
                        key: "passed" for key in coverage.ARCHIVE_REQUIRED_CAPABILITIES
                    }
                    candidate["backends"][0]["capabilities"]["authentication_rejection"] = "not_applicable"
                candidate["backends"][0]["capabilities"][capability] = "passed"
                result = self.evaluate([candidate], policy, catalog)
                with self.subTest(backend=backend, capability=capability):
                    if backend in allowed:
                        self.assertEqual(result["providers"][0]["evidence"]["local_protocol"]["status"], "passed")
                    else:
                        self.assertIn("invalid_fixture_capability", result["errors"])

    def test_b2_requires_independent_fixture_and_current_runtime_harness_manifest(self):
        catalog = coverage.catalog_from_schemas([schema("b2")])
        policy = policy_for(catalog)
        for kind in ("local", "rclone_loopback", "vendor"):
            candidate = b2_receipt()
            candidate["backends"][0]["fixture_kind"] = kind
            self.assertIn("unknown_fixture_backend", self.evaluate([candidate], policy, catalog)["errors"])
        cases = []
        for field in ("version", "sha256"):
            candidate = b2_receipt()
            candidate["runtime"][field] = "1.75.2" if field == "version" else "d" * 64
            cases.append((candidate, "receipt_runtime_mismatch"))
        for field, value, error in (("platform", "windows", "receipt_runtime_mismatch"),
                                    ("harness_sha256", "d" * 64, "receipt_harness_mismatch"),
                                    ("fixture_manifest_sha256", "d" * 64, "receipt_fixture_manifest_mismatch"),
                                    ("finished_utc", coverage.utc_text(NOW + timedelta(seconds=1)), "future_receipt")):
            candidate = b2_receipt()
            candidate[field] = value
            cases.append((candidate, error))
        candidate = b2_receipt()
        candidate["started_utc"] = coverage.utc_text(NOW - timedelta(days=2, minutes=1))
        candidate["finished_utc"] = coverage.utc_text(NOW - timedelta(days=2))
        cases.append((candidate, "expired_receipt"))
        for candidate, error in cases:
            result = self.evaluate([candidate], policy, catalog)
            self.assertIn(error, result["errors"])
            self.assertIn("required_fixture_not_verified", coverage.gate_errors(result, require_fixtures=["b2"]))

    def test_b2_renewal_failure_remains_failed_and_private_details_are_omitted(self):
        catalog = coverage.catalog_from_schemas([schema("b2")])
        policy = policy_for(catalog)
        policy["profiles"]["test"]["required"]["local_protocol"] = sorted(coverage.B2_REQUIRED_CAPABILITIES)
        for capability in ("account_token_reacquisition", "renewal_denial"):
            failed = b2_receipt()
            failed["success"] = False
            failed["backends"][0]["capabilities"][capability] = "failed"
            for batch in ([failed, b2_receipt()], [b2_receipt(), failed]):
                result = self.evaluate(batch, policy, catalog)
                evidence = result["providers"][0]["evidence"]["local_protocol"]
                self.assertEqual(evidence["status"], "failed")
                self.assertEqual(evidence["capabilities"][capability], "failed")
        canary = "PRIVATE_B2_TOKEN_KEY_ACCOUNT_https://private.invalid"
        candidate = b2_receipt()
        candidate["raw_stderr"] = canary
        candidate["backends"][0]["authorizationToken"] = canary
        self.assertNotIn(canary, json.dumps(self.evaluate([candidate], policy, catalog)))
        candidate["backends"][0]["errors"] = [canary]
        result = self.evaluate([candidate], policy, catalog)
        self.assertIn("invalid_fixture_errors", result["errors"])
        self.assertNotIn(canary, json.dumps(result))

    def assert_read_fixture_never_qualifies_other_modes_or_acceptance_tiers(self, backend):
        catalog = coverage.catalog_from_schemas([schema(backend)])
        policy = policy_for(catalog)
        profile = policy["profiles"]["test"]
        profile["required"]["local_protocol"] = sorted(coverage.READ_FIXTURE_CONTRACTS[backend])
        profile["unresolved_applicability"] = ["refresh", "reauthentication"]
        entry = policy["providers"][backend]
        entry["refresh_applicability"] = entry["reauthentication_applicability"] = "review_required"
        entry["renewal_modes"] = [renewal_mode("not_applicable"), renewal_mode("required"),
                                  renewal_mode("review_required", "review_required")]
        for mode, name in zip(entry["renewal_modes"], ("fixed credential", "renewable credential", "unreviewed alternative")):
            mode["auth_mode"] = name
        result = self.evaluate([read_fixture_receipt(backend)], policy, catalog)
        row = result["providers"][0]
        evidence = row["evidence"]
        self.assertEqual(evidence["local_protocol"]["status"], "passed")
        self.assertEqual(set(evidence["local_protocol"]["capabilities"]), coverage.READ_FIXTURE_CONTRACTS[backend])
        for tier in ("application", "vendor"):
            self.assertEqual(evidence[tier]["status"], "not_verified")
            for capability in ("authentication", "refresh"):
                self.assertEqual(evidence[tier]["capabilities"][capability], "not_verified")
        self.assertEqual(coverage.gate_errors(result, require_plans=True, require_fixtures=[backend]), [])
        self.assertIn("provider_coverage_incomplete", coverage.gate_errors(result, require_complete=True))
        self.assertEqual(row["capability_applicability_review_required"], ["reauthentication", "refresh"])
        self.assertEqual(row["lifecycle_applicability"], {
            "credential_renewal": "review_required", "connection_session_reauthentication": "review_required"})

    def assert_read_fixture_requires_exact_capabilities_despite_weaker_policy(self, backend):
        catalog = coverage.catalog_from_schemas([schema(backend)])
        policy = policy_for(catalog)
        for capability in coverage.READ_FIXTURE_CONTRACTS[backend]:
            candidate = read_fixture_receipt(backend)
            del candidate["backends"][0]["capabilities"][capability]
            result = self.evaluate([candidate], policy, catalog)
            with self.subTest(omitted=capability):
                self.assertIn("invalid_fixture_capability", result["errors"])
                self.assertIn("required_fixture_not_verified", coverage.gate_errors(result, require_fixtures=[backend]))
        for capability in coverage.CAPABILITIES - coverage.READ_FIXTURE_CONTRACTS[backend]:
            candidate = read_fixture_receipt(backend)
            candidate["backends"][0]["capabilities"][capability] = "passed"
            with self.subTest(extra=capability):
                self.assertIn("invalid_fixture_capability", self.evaluate([candidate], policy, catalog)["errors"])

    def assert_read_fixture_requires_executed_typed_outcomes_and_independent_kind(self, backend):
        catalog = coverage.catalog_from_schemas([schema(backend)])
        policy = policy_for(catalog)
        for capability in coverage.READ_FIXTURE_CONTRACTS[backend]:
            for value, error in (("not_applicable", "invalid_fixture_not_applicable"),
                                 (True, "invalid_fixture_outcome"), (None, "invalid_fixture_outcome"),
                                 ("failed", "inconsistent_fixture_success"),
                                 ("not_run", "inconsistent_fixture_success")):
                candidate = read_fixture_receipt(backend)
                candidate["backends"][0]["capabilities"][capability] = value
                with self.subTest(capability=capability, value=value):
                    self.assertIn(error, self.evaluate([candidate], policy, catalog)["errors"])
        for kind in ("local", "rclone_loopback", "vendor"):
            candidate = read_fixture_receipt(backend)
            candidate["backends"][0]["fixture_kind"] = kind
            self.assertIn("unknown_fixture_backend", self.evaluate([candidate], policy, catalog)["errors"])

    def assert_read_fixture_requires_current_runtime_harness_manifest_and_time(self, backend):
        catalog = coverage.catalog_from_schemas([schema(backend)])
        policy = policy_for(catalog)
        cases = []
        for field in ("version", "sha256"):
            candidate = read_fixture_receipt(backend)
            candidate["runtime"][field] = "1.75.2" if field == "version" else "d" * 64
            cases.append((candidate, "receipt_runtime_mismatch"))
        for field, value, error in (("platform", "windows", "receipt_runtime_mismatch"),
                                    ("harness_sha256", "d" * 64, "receipt_harness_mismatch"),
                                    ("fixture_manifest_sha256", "d" * 64, "receipt_fixture_manifest_mismatch"),
                                    ("finished_utc", coverage.utc_text(NOW + timedelta(seconds=1)), "future_receipt")):
            candidate = read_fixture_receipt(backend)
            candidate[field] = value
            cases.append((candidate, error))
        candidate = read_fixture_receipt(backend)
        candidate["started_utc"] = coverage.utc_text(NOW - timedelta(days=2, minutes=1))
        candidate["finished_utc"] = coverage.utc_text(NOW - timedelta(days=2))
        cases.append((candidate, "expired_receipt"))
        for candidate, error in cases:
            result = self.evaluate([candidate], policy, catalog)
            self.assertIn(error, result["errors"])
            self.assertIn("required_fixture_not_verified", coverage.gate_errors(result, require_fixtures=[backend]))

    def assert_read_fixture_failures_are_sticky_and_private_fields_omitted(self, backend):
        catalog = coverage.catalog_from_schemas([schema(backend)])
        policy = policy_for(catalog)
        policy["profiles"]["test"]["required"]["local_protocol"] = sorted(coverage.READ_FIXTURE_CONTRACTS[backend])
        for capability in coverage.READ_FIXTURE_CONTRACTS[backend]:
            failed = read_fixture_receipt(backend)
            failed["success"] = False
            failed["backends"][0]["capabilities"][capability] = "failed"
            for batch in ([failed, read_fixture_receipt(backend)], [read_fixture_receipt(backend), failed]):
                result = self.evaluate(batch, policy, catalog)
                evidence = result["providers"][0]["evidence"]["local_protocol"]
                self.assertEqual(evidence["status"], "failed")
                self.assertEqual(evidence["capabilities"][capability], "failed")
        canary = "PRIVATE_PROTOCOL_CREDENTIAL_SIGNATURE_https://private.invalid/account"
        candidate = read_fixture_receipt(backend)
        candidate["raw_stderr"] = canary
        candidate["backends"][0]["Authorization"] = canary
        self.assertNotIn(canary, json.dumps(self.evaluate([candidate], policy, catalog)))
        candidate["backends"][0]["errors"] = [canary]
        result = self.evaluate([candidate], policy, catalog)
        self.assertIn("invalid_fixture_errors", result["errors"])
        self.assertNotIn(canary, json.dumps(result))

    def test_azureblob_fixture_never_qualifies_other_modes_or_acceptance_tiers(self):
        self.assert_read_fixture_never_qualifies_other_modes_or_acceptance_tiers("azureblob")

    def test_azureblob_requires_exact_capabilities_despite_weaker_policy(self):
        self.assert_read_fixture_requires_exact_capabilities_despite_weaker_policy("azureblob")

    def test_azureblob_requires_executed_typed_outcomes_and_independent_kind(self):
        self.assert_read_fixture_requires_executed_typed_outcomes_and_independent_kind("azureblob")

    def test_azureblob_requires_current_runtime_harness_manifest_and_time(self):
        self.assert_read_fixture_requires_current_runtime_harness_manifest_and_time("azureblob")

    def test_azureblob_failures_are_sticky_and_private_fields_omitted(self):
        self.assert_read_fixture_failures_are_sticky_and_private_fields_omitted("azureblob")

    def test_azurefiles_fixture_never_qualifies_other_modes_or_acceptance_tiers(self):
        self.assert_read_fixture_never_qualifies_other_modes_or_acceptance_tiers("azurefiles")

    def test_azurefiles_requires_exact_capabilities_despite_weaker_policy(self):
        self.assert_read_fixture_requires_exact_capabilities_despite_weaker_policy("azurefiles")

    def test_azurefiles_requires_executed_typed_outcomes_and_independent_kind(self):
        self.assert_read_fixture_requires_executed_typed_outcomes_and_independent_kind("azurefiles")

    def test_azurefiles_requires_current_runtime_harness_manifest_and_time(self):
        self.assert_read_fixture_requires_current_runtime_harness_manifest_and_time("azurefiles")

    def test_azurefiles_failures_are_sticky_and_private_fields_omitted(self):
        self.assert_read_fixture_failures_are_sticky_and_private_fields_omitted("azurefiles")

    def test_seafile_fixture_never_qualifies_other_modes_or_acceptance_tiers(self):
        self.assert_read_fixture_never_qualifies_other_modes_or_acceptance_tiers("seafile")

    def test_seafile_requires_exact_capabilities_despite_weaker_policy(self):
        self.assert_read_fixture_requires_exact_capabilities_despite_weaker_policy("seafile")

    def test_seafile_requires_executed_typed_outcomes_and_independent_kind(self):
        self.assert_read_fixture_requires_executed_typed_outcomes_and_independent_kind("seafile")

    def test_seafile_requires_current_runtime_harness_manifest_and_time(self):
        self.assert_read_fixture_requires_current_runtime_harness_manifest_and_time("seafile")

    def test_seafile_failures_are_sticky_and_private_fields_omitted(self):
        self.assert_read_fixture_failures_are_sticky_and_private_fields_omitted("seafile")

    def test_koofr_fixture_never_qualifies_other_modes_or_acceptance_tiers(self):
        self.assert_read_fixture_never_qualifies_other_modes_or_acceptance_tiers("koofr")

    def test_koofr_requires_exact_capabilities_despite_weaker_policy(self):
        self.assert_read_fixture_requires_exact_capabilities_despite_weaker_policy("koofr")
        catalog = coverage.catalog_from_schemas([schema("koofr")])
        candidate = koofr_receipt()
        candidate["backends"][0]["capabilities"]["account_login"] = "passed"
        self.assertIn("invalid_fixture_capability", self.evaluate([candidate], policy_for(catalog), catalog)["errors"])

    def test_koofr_requires_executed_typed_outcomes_and_independent_kind(self):
        self.assert_read_fixture_requires_executed_typed_outcomes_and_independent_kind("koofr")

    def test_koofr_requires_current_runtime_harness_manifest_and_time(self):
        self.assert_read_fixture_requires_current_runtime_harness_manifest_and_time("koofr")

    def test_koofr_failures_are_sticky_and_private_fields_omitted(self):
        self.assert_read_fixture_failures_are_sticky_and_private_fields_omitted("koofr")

    def test_pixeldrain_fixture_never_qualifies_other_modes_or_acceptance_tiers(self):
        self.assert_read_fixture_never_qualifies_other_modes_or_acceptance_tiers("pixeldrain")

    def test_pixeldrain_requires_exact_capabilities_despite_weaker_policy(self):
        self.assert_read_fixture_requires_exact_capabilities_despite_weaker_policy("pixeldrain")
        catalog = coverage.catalog_from_schemas([schema("pixeldrain")])
        for claim in ("account_login", "key_rotation", "anonymous_root_access"):
            candidate = pixeldrain_receipt()
            candidate["backends"][0]["capabilities"][claim] = "passed"
            self.assertIn("invalid_fixture_capability", self.evaluate([candidate], policy_for(catalog), catalog)["errors"])

    def test_pixeldrain_requires_executed_typed_outcomes_and_independent_kind(self):
        self.assert_read_fixture_requires_executed_typed_outcomes_and_independent_kind("pixeldrain")

    def test_pixeldrain_requires_current_runtime_harness_manifest_and_time(self):
        self.assert_read_fixture_requires_current_runtime_harness_manifest_and_time("pixeldrain")

    def test_pixeldrain_failures_are_sticky_and_private_fields_omitted(self):
        self.assert_read_fixture_failures_are_sticky_and_private_fields_omitted("pixeldrain")

    def test_read_fixture_services_never_inherit_each_others_result(self):
        backends = ("azureblob", "azurefiles", "seafile", "koofr", "pixeldrain", "filefabric")
        catalog = coverage.catalog_from_schemas([schema(backend) for backend in backends])
        policy = policy_for(catalog)
        policy["profiles"]["test"]["required"]["local_protocol"] = sorted(coverage.SEAFILE_REQUIRED_CAPABILITIES)
        for backend in backends:
            others = [other for other in backends if other != backend]
            result = self.evaluate([read_fixture_receipt(backend)], policy, catalog)
            statuses = {row["backend"]: row["evidence"]["local_protocol"]["status"] for row in result["providers"]}
            self.assertEqual(statuses, {backend: "passed", **{other: "not_verified" for other in others}})
            for other in others:
                self.assertIn("required_fixture_not_verified", coverage.gate_errors(result, require_fixtures=[other]))

    def test_filefabric_never_qualifies_other_modes_or_acceptance_tiers(self):
        self.assert_read_fixture_never_qualifies_other_modes_or_acceptance_tiers("filefabric")

    def test_filefabric_requires_exact_capabilities_despite_weaker_policy(self):
        self.assert_read_fixture_requires_exact_capabilities_despite_weaker_policy("filefabric")

    def test_filefabric_requires_executed_typed_outcomes_and_independent_kind(self):
        self.assert_read_fixture_requires_executed_typed_outcomes_and_independent_kind("filefabric")

    def test_filefabric_requires_current_runtime_harness_manifest_and_time(self):
        self.assert_read_fixture_requires_current_runtime_harness_manifest_and_time("filefabric")

    def test_filefabric_failures_are_sticky_and_private_fields_omitted(self):
        self.assert_read_fixture_failures_are_sticky_and_private_fields_omitted("filefabric")

    def test_memory_receipt_is_local_only_and_never_qualifies_other_acceptance(self):
        catalog = coverage.catalog_from_schemas([schema("memory")])
        policy = policy_for(catalog)
        observed = coverage.MEMORY_REQUIRED_CAPABILITIES - {"authentication_rejection"}
        policy["profiles"]["test"]["required"]["local_protocol"] = sorted(observed)
        result = self.evaluate([memory_receipt()], policy, catalog)
        evidence = result["providers"][0]["evidence"]
        self.assertEqual(evidence["local_protocol"]["status"], "passed")
        self.assertEqual(set(evidence["local_protocol"]["capabilities"]), observed)
        for tier in ("application", "vendor"):
            self.assertEqual(evidence[tier]["status"], "not_verified")
            self.assertEqual(evidence[tier]["capabilities"]["authentication"], "not_verified")
            self.assertEqual(evidence[tier]["capabilities"]["refresh"], "not_verified")
        self.assertEqual(coverage.gate_errors(result, require_plans=True, require_fixtures=["memory"]), [])
        self.assertIn("provider_coverage_incomplete", coverage.gate_errors(result, require_complete=True))

    def test_memory_requires_exact_seven_capabilities_even_under_weaker_policy(self):
        catalog = coverage.catalog_from_schemas([schema("memory")])
        policy = policy_for(catalog)
        for omitted in coverage.MEMORY_REQUIRED_CAPABILITIES:
            candidate = memory_receipt()
            del candidate["backends"][0]["capabilities"][omitted]
            result = self.evaluate([candidate], policy, catalog)
            with self.subTest(omitted=omitted):
                self.assertIn("invalid_fixture_capability", result["errors"])
                self.assertIn("required_fixture_not_verified", coverage.gate_errors(result, require_fixtures=["memory"]))
        for extra in coverage.CAPABILITIES - coverage.MEMORY_REQUIRED_CAPABILITIES | {"unknown_capability"}:
            candidate = memory_receipt()
            candidate["backends"][0]["capabilities"][extra] = "passed"
            with self.subTest(extra=extra):
                self.assertIn("invalid_fixture_capability", self.evaluate([candidate], policy, catalog)["errors"])

    def test_memory_auth_is_only_na_and_observed_capabilities_require_typed_execution(self):
        catalog = coverage.catalog_from_schemas([schema("memory")])
        policy = policy_for(catalog)
        for capability in coverage.MEMORY_REQUIRED_CAPABILITIES:
            cases = [(True, "invalid_fixture_outcome"), (None, "invalid_fixture_outcome"),
                     (1, "invalid_fixture_outcome"), ({}, "invalid_fixture_outcome")]
            if capability == "authentication_rejection":
                cases += [(value, "invalid_fixture_capability") for value in ("passed", "failed", "not_run")]
            else:
                cases += [("not_applicable", "invalid_fixture_not_applicable"),
                          ("failed", "inconsistent_fixture_success"), ("not_run", "inconsistent_fixture_success")]
            for value, error in cases:
                candidate = memory_receipt()
                candidate["backends"][0]["capabilities"][capability] = value
                with self.subTest(capability=capability, value=value):
                    self.assertIn(error, self.evaluate([candidate], policy, catalog)["errors"])
        for kind in ("independent_loopback", "rclone_loopback", "vendor", None):
            candidate = memory_receipt()
            candidate["backends"][0]["fixture_kind"] = kind
            self.assertIn("unknown_fixture_backend", self.evaluate([candidate], policy, catalog)["errors"])

    def test_memory_requires_current_runtime_harness_manifest_and_fresh_evidence(self):
        catalog = coverage.catalog_from_schemas([schema("memory")])
        policy = policy_for(catalog)
        cases = []
        for key, value in (("version", "1.75.2"), ("sha256", "d" * 64)):
            candidate = memory_receipt()
            candidate["runtime"][key] = value
            cases.append((candidate, "receipt_runtime_mismatch"))
        for key, value, error in (("platform", "windows", "receipt_runtime_mismatch"),
                                 ("harness_sha256", "d" * 64, "receipt_harness_mismatch"),
                                 ("fixture_manifest_sha256", "d" * 64, "receipt_fixture_manifest_mismatch"),
                                 ("finished_utc", coverage.utc_text(NOW + timedelta(seconds=1)), "future_receipt")):
            candidate = memory_receipt()
            candidate[key] = value
            cases.append((candidate, error))
        candidate = memory_receipt()
        candidate["started_utc"] = coverage.utc_text(NOW - timedelta(days=2, minutes=1))
        candidate["finished_utc"] = coverage.utc_text(NOW - timedelta(days=2))
        cases.append((candidate, "expired_receipt"))
        for candidate, error in cases:
            result = self.evaluate([candidate], policy, catalog)
            self.assertIn(error, result["errors"])
            self.assertIn("required_fixture_not_verified", coverage.gate_errors(result, require_fixtures=["memory"]))

    def test_memory_failures_stick_in_either_order_and_never_export_private_echoes(self):
        catalog = coverage.catalog_from_schemas([schema("memory")])
        policy = policy_for(catalog)
        observed = coverage.MEMORY_REQUIRED_CAPABILITIES - {"authentication_rejection"}
        policy["profiles"]["test"]["required"]["local_protocol"] = sorted(observed)
        for capability in observed:
            failed = memory_receipt()
            failed["success"] = False
            failed["backends"][0]["capabilities"][capability] = "failed"
            for batch in ([failed, memory_receipt()], [memory_receipt(), failed]):
                result = self.evaluate(batch, policy, catalog)
                evidence = result["providers"][0]["evidence"]["local_protocol"]
                self.assertEqual(evidence["status"], "failed")
                self.assertEqual(evidence["capabilities"][capability], "failed")
        for level in ("receipt", "backend"):
            failed = memory_receipt()
            failed["success"] = False
            target = failed if level == "receipt" else failed["backends"][0]
            target["errors"] = ["synthetic_batch_error"]
            result = self.evaluate([memory_receipt(), failed], policy, catalog)
            self.assertEqual(result["providers"][0]["evidence"]["local_protocol"]["status"], "failed")
        candidate = memory_receipt()
        canary = "PRIVATE_MEMORY_PATH_C:/private-owner/job/123"
        candidate["raw_stderr"] = canary
        candidate["backends"][0]["input"] = {"srcFs": canary}
        self.assertNotIn(canary, json.dumps(self.evaluate([candidate], policy, catalog)))
        candidate["backends"][0]["errors"] = [canary]
        result = self.evaluate([candidate], policy, catalog)
        self.assertIn("invalid_fixture_errors", result["errors"])
        self.assertNotIn(canary, json.dumps(result))

    def test_memory_and_other_local_or_authenticated_services_do_not_inherit_results(self):
        backends = ("memory", "local", "archive", "seafile")
        catalog = coverage.catalog_from_schemas([schema(backend) for backend in backends])
        policy = policy_for(catalog)
        for candidate in (memory_receipt(), receipt("local"), seafile_receipt()):
            accepted_backend = candidate["backends"][0]["backend"]
            result = self.evaluate([candidate], policy, catalog)
            statuses = {row["backend"]: row["evidence"]["local_protocol"]["status"] for row in result["providers"]}
            self.assertEqual(statuses, {backend: "passed" if backend == accepted_backend else "not_verified"
                                        for backend in backends})
        for backend in coverage.FIXTURE_KINDS:
            if backend == "memory":
                continue
            candidate = memory_receipt()
            candidate["backends"][0]["backend"] = backend
            candidate["backends"][0]["fixture_kind"] = coverage.FIXTURE_KINDS[backend]
            single = coverage.catalog_from_schemas([schema(backend)])
            with self.subTest(relabeled=backend):
                self.assertTrue(self.evaluate([candidate], policy_for(single), single)["errors"])

    def test_not_applicable_only_from_reviewed_policy(self):
        policy = policy_for(self.catalog, application=False, vendor=False)
        report = self.evaluate([receipt()], policy=policy)
        self.assertFalse(report["all_complete"])
        self.assertEqual(report["providers"][0]["evidence"]["application"]["status"], "not_verified")
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
