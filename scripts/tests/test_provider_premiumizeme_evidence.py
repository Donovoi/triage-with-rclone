"""Schema-13 Premiumizeme evidence composition, with no Docker or native execution."""
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import test_provider_premiumizeme_container as O

S = O.S
ROOT = Path(__file__).resolve().parents[2]
C = O.load("premiumizeme_coverage_subject", ROOT / "scripts/provider_coverage.py")
NOW = datetime(2026, 11, 15, 4, 1, tzinfo=timezone.utc)
RUNTIME = dict(O.IDENTITY, platform="linux")

def bindings():
    return {"harness_sha256": S.canonical_hash(O.SOURCES), "fixture_manifest_sha256": S.FIXTURE_SHA256,
            "source_sha256": copy.deepcopy(O.SOURCES), "lock": S.read_lock()}

def native():
    lock = S.read_lock()
    value = {"schema_version": 1, "scope": "premiumizeme_fixed_api_read_supervision", "ledger_eligible": False,
        "started_utc": O.FIRST, "finished_utc": O.LAST, "success": True, "runtime": dict(O.IDENTITY),
        "platform": "linux/amd64", "source_sha256": copy.deepcopy(O.SOURCES),
        "source_digest": S.canonical_hash(O.SOURCES), "dependency_lock_sha256": lock["requirements"]["sha256"],
        "dependency_versions": copy.deepcopy(lock["requirements"]["distributions"]),
        "python_version": lock["python_version"], "base_image": lock["base_image"],
        "base_config_digest": lock["base_config_digest"], "image_id": O.IMAGE,
        "container_isolation_verified": True, "probe": O.probe(lock), "errors": [],
        "cleanup": dict.fromkeys(("container_removed", "image_removed", "temporary_removed"), True),
        "stage": "completed", "build_phase": "manifest", "container_exit_code": 0,
        "container_stdout_bytes": 0, "container_stderr_bytes": 0, "container_oom_killed": False,
        "container_start_error_present": False, "build_cache_scope": "shared_daemon_cache_not_pruned",
        "probe_started_utc": O.FIRST, "probe_finished_utc": O.LAST}
    bind_output(value)
    return value

def bind_output(value):
    value["container_stdout_bytes"] = len((json.dumps(value["probe"], sort_keys=True, separators=(",", ":")) + "\n").encode())

def evidence(value=None):
    return S.read_evidence(native() if value is None else value, bindings())

def failed(cleanup=True):
    value = native()
    value["success"] = False
    value["errors"] = ["premiumizeme_probe_failed"]
    value["stage"] = "probe"
    value["probe"]["success"] = False
    value["probe"]["errors"] = ["premiumizeme_protocol_failed"]
    value["probe"]["checks"]["protocol"] = False
    value["probe"]["capabilities"]["download_hash"] = "not_run"
    if not cleanup:
        value["cleanup"]["image_removed"] = False
    bind_output(value)
    return evidence(value)

class PremiumizemeNativeEvidenceTests(unittest.TestCase):
    def validate(self, value, **kwargs):
        return S.validate_read_evidence(value, kwargs.pop("runtime", RUNTIME),
                                        kwargs.pop("expected", bindings()), kwargs.pop("now", NOW), **kwargs)

    def test_success_projection_is_exact_and_preserves_only_the_read_profile(self):
        value = evidence()
        self.validate(value)
        self.assertEqual((value["schema_version"], value["platform"], value["architecture"]), (13, "linux", "amd64"))
        self.assertEqual(value["backends"], [{"backend": "premiumizeme", "fixture_kind": "independent_api_container",
            "fixture_mode": "premiumizeme_saved_token_read_v1", "capabilities": dict.fromkeys(S.CAPABILITIES, "passed"), "errors": []}])
        self.assertNotIn("authentication", value["backends"][0]["capabilities"])

    def test_raw_feasibility_and_old_scope_cannot_be_promoted(self):
        for value in (native(), dict(native(), scope="premiumizeme_fixed_api_read_feasibility")):
            with self.assertRaises(S.SupervisorError):
                self.validate(value)
        value = native(); value["scope"] = "premiumizeme_fixed_api_read_feasibility"
        with self.assertRaises(S.SupervisorError):
            evidence(value)

    def test_outer_field_changes_unknown_fields_types_and_extra_rows_fail(self):
        for field, replacement in (("schema_version", True), ("schema_version", 1), ("scope", "vendor"),
                ("platform", "windows"), ("architecture", "arm64"), ("success", 1), ("cleanup_passed", 1),
                ("harness_sha256", "f" * 64), ("fixture_manifest_sha256", "f" * 64),
                ("unknown", "synthetic"), ("runtime", dict(O.IDENTITY, account="unreviewed"))):
            value = evidence(); value[field] = replacement
            with self.subTest(field=field), self.assertRaises(S.SupervisorError):
                self.validate(value)
        value = evidence(); value["backends"].append(copy.deepcopy(value["backends"][0]))
        with self.assertRaises(S.SupervisorError):
            self.validate(value)

    def test_every_capability_scope_and_cleanup_mutation_is_rejected(self):
        for key in S.CAPABILITIES:
            value = evidence(); value["backends"][0]["capabilities"][key] = "not_run"
            with self.subTest(capability=key), self.assertRaises(S.SupervisorError):
                self.validate(value)
        for key in native()["cleanup"]:
            value = evidence(); value["native_evidence"]["cleanup"][key] = False
            with self.subTest(cleanup=key), self.assertRaises(S.SupervisorError):
                self.validate(value)
        for key in ("backend", "fixture_kind", "fixture_mode"):
            value = evidence(); value["backends"][0][key] = "unreviewed"
            with self.subTest(key=key), self.assertRaises(S.SupervisorError):
                self.validate(value)
        for key in ("authentication", "refresh", "revocation", "cancellation", "native_write_rejection"):
            value = evidence(); value["backends"][0]["capabilities"][key] = "passed"
            with self.subTest(key=key), self.assertRaises(S.SupervisorError):
                self.validate(value)

    def test_isolation_dependencies_build_state_and_native_output_are_bound(self):
        changes = {"container_isolation_verified": False, "platform": "windows/amd64", "image_id": None,
            "base_image": "python:latest", "base_config_digest": "sha256:" + "f" * 64,
            "python_version": "3.12.0", "dependency_lock_sha256": "f" * 64, "dependency_versions": {},
            "container_exit_code": True, "container_stdout_bytes": 1, "container_stderr_bytes": 1,
            "container_oom_killed": True, "container_start_error_present": True,
            "stage": "probe", "build_phase": None, "build_cache_scope": "unreviewed",
            "probe_started_utc": O.LAST, "probe_finished_utc": O.FIRST, "unknown": "private"}
        for key, replacement in changes.items():
            value = evidence(); value["native_evidence"][key] = replacement
            with self.subTest(key=key), self.assertRaises(S.SupervisorError):
                self.validate(value)

    def test_source_runtime_manifest_and_freshness_cannot_be_substituted(self):
        for name in O.SOURCES:
            value = evidence(); value["native_evidence"]["source_sha256"][name] = "f" * 64
            with self.subTest(path=name), self.assertRaises(S.SupervisorError):
                self.validate(value)
        for runtime in (dict(RUNTIME, platform="windows"), dict(RUNTIME, version="9.9.9"), dict(RUNTIME, sha256="f" * 64)):
            with self.assertRaises(S.SupervisorError):
                self.validate(evidence(), runtime=runtime)
        for now in (NOW - timedelta(minutes=2), NOW + timedelta(days=2)):
            with self.assertRaises(S.SupervisorError):
                self.validate(evidence(), now=now)
        for age in (True, 0, 169, 1.5):
            with self.assertRaises(S.SupervisorError):
                self.validate(evidence(), max_age_hours=age)

    def test_genuine_failed_and_cleanup_failed_runs_remain_failed(self):
        for cleaned in (True, False):
            value = failed(cleaned)
            self.validate(value)
            self.assertFalse(value["success"])
            self.assertEqual(value["cleanup_passed"], cleaned)
            self.assertEqual(set(value["backends"][0]["capabilities"].values()), {"failed"})

    def test_binding_inspection_is_read_only_and_uses_current_closed_sources(self):
        with patch.object(S.subprocess, "Popen", side_effect=AssertionError("no execution")):
            actual = S.compute_bindings()
            other = C.compute_premiumizeme_bindings(ROOT / "scripts/provider-lab/premiumizeme-fixed-api")
        self.assertEqual(actual, other)
        self.assertEqual(set(actual["source_sha256"]), set(S.SOURCE_FILES))
        self.assertEqual(actual["harness_sha256"], S.canonical_hash(actual["source_sha256"]))

class PremiumizemeCoverageTests(unittest.TestCase):
    def setUp(self):
        actual = json.loads((ROOT / "provider-coverage-policy.json").read_bytes())
        entry = copy.deepcopy(actual["providers"]["premiumizeme"])
        self.catalog = C.catalog_from_schemas([{"Name": "premiumizeme", "Prefix": "premiumizeme", "Options": []}])
        entry.pop("schema_sha256_by_platform", None); entry["schema_sha256"] = self.catalog[0]["schema_sha256"]
        self.policy = {"schema_version": 2, "reviewed_runtime_version": RUNTIME["version"],
            "providers": {"premiumizeme": entry}, "profiles": {entry["profile"]: copy.deepcopy(actual["profiles"][entry["profile"]])}}

    def evaluate(self, receipts, **kwargs):
        options = {"now": NOW, "fixture_manifest_sha256": S.FIXTURE_SHA256, "premiumizeme_bindings": bindings()}
        options.update(kwargs)
        return C.evaluate(self.catalog, self.policy, RUNTIME, receipts, "a" * 64, **options)

    def test_local_read_pass_does_not_supply_application_vendor_or_lifecycle_claims(self):
        report = self.evaluate([evidence()])
        self.assertEqual(report["errors"], [])
        row = report["providers"][0]
        self.assertEqual(C.gate_errors(report, require_fixtures=["premiumizeme"]), [])
        self.assertEqual(row["evidence"]["local_protocol"]["status"], "passed")
        self.assertEqual(set(row["evidence"]["local_protocol"]["modes"]), {S.READ_MODE})
        self.assertFalse(row["complete"]); self.assertFalse(report["all_complete"])
        for tier in ("application", "vendor"):
            self.assertEqual(row["evidence"][tier]["status"], "not_verified")
        actual = json.loads((ROOT / "provider-coverage-policy.json").read_bytes())
        original = actual["profiles"]["hosted-renewal-session-review"]
        profile = actual["profiles"][actual["providers"]["premiumizeme"]["profile"]]
        for tier in ("application", "vendor"):
            self.assertEqual(profile["required"][tier], original["required"][tier])
        self.assertEqual(profile["unresolved_applicability"], original["unresolved_applicability"])
        self.assertEqual(actual["providers"]["premiumizeme"]["reauthentication_applicability"], "review_required")
        self.assertEqual(actual["providers"]["premiumizeme"]["refresh_applicability"], "required")

    def test_failed_evidence_is_sticky_in_both_orders(self):
        for failure in (failed(), failed(False)):
            for receipts in ([failure, evidence()], [evidence(), failure]):
                report = self.evaluate(receipts)
                self.assertEqual(report["errors"], [])
                self.assertEqual(report["providers"][0]["evidence"]["local_protocol"]["status"], "failed")
                self.assertIn("required_fixture_not_verified", C.gate_errors(report, require_fixtures=["premiumizeme"]))

    def test_missing_bindings_and_forged_baseline_rows_remain_unverified(self):
        raw = evidence()
        raw["schema_version"] = 1
        raw["backends"][0].pop("fixture_mode")
        raw["backends"][0]["fixture_kind"] = "independent_loopback"
        raw.pop("native_evidence"); raw.pop("architecture")
        for item, options in ((raw, {}), (native(), {}), (evidence(), {"premiumizeme_bindings": None}),
                              (evidence(), {"fixture_manifest_sha256": "f" * 64})):
            report = self.evaluate([item], **options)
            self.assertTrue(report["errors"])
            self.assertEqual(report["providers"][0]["evidence"]["local_protocol"]["status"], "not_verified")

    def test_weaker_policy_cannot_admit_partial_or_cross_provider_receipts(self):
        profile = self.policy["profiles"][self.policy["providers"]["premiumizeme"]["profile"]]
        profile["required"]["local_protocol"] = ["listing"]
        for change in ("missing_capability", "extra_scope", "wrong_backend"):
            item = evidence()
            if change == "missing_capability":
                item["backends"][0]["capabilities"].pop("read_denial")
            elif change == "extra_scope":
                item["backends"][0]["capabilities"]["refresh"] = "passed"
            else:
                item["backends"][0]["backend"] = "quatrix"
            report = self.evaluate([item])
            self.assertTrue(report["errors"])
            self.assertEqual(report["providers"][0]["evidence"]["local_protocol"]["status"], "not_verified")


def validate_workflows(ci, smoke):
    from test_gcs_oauth_workflow_contract import command, jobs, require, scalar
    from test_provider_gcs_lifecycle_workflow import steps
    import re
    definitions = jobs(ci)
    job = definitions["premiumizeme-fixed-api"]
    fields = re.findall(r"^    ([a-z-]+):", job, re.MULTILINE)
    require(set(fields) == {"name", "needs", "runs-on", "timeout-minutes", "steps"} and len(fields) == 5,
            "premiumizeme_required_job")
    require(scalar(job, "needs", 4) == "revision" and scalar(job, "runs-on", 4) == "ubuntu-latest"
            and scalar(job, "timeout-minutes", 4) == "12", "premiumizeme_job_bound")
    parts = steps(job)
    require(len(parts) == 5 and "persist-credentials: false" in parts[0], "premiumizeme_closed_setup")
    require(command(parts[2]) == ["bash", "scripts/download-rclone.sh", "--linux", "$RUNNER_TEMP/rclone-premiumizeme"],
            "premiumizeme_pinned_runtime")
    require(command(parts[3]) == ["python", "-B", "scripts/provider-lab/premiumizeme-fixed-api/run_container.py",
            "--rclone", "$RUNNER_TEMP/rclone-premiumizeme", "--protocol-evidence", "--report",
            "$RUNNER_TEMP/premiumizeme-read-protocol.json"], "premiumizeme_qualification_required")
    require(scalar(parts[4], "if", 8) == "always()"
            and scalar(parts[4], "name", 10) == "premiumizeme-read-protocol"
            and scalar(parts[4], "path", 10) == "${{ runner.temp }}/premiumizeme-read-protocol.json",
            "premiumizeme_receipt_retained")
    require("continue-on-error" not in job, "premiumizeme_failure_required")
    combined = definitions["linux-provider-evidence"]
    require("premiumizeme-fixed-api" in scalar(combined, "needs", 4).strip("[]").split(", "), "premiumizeme_same_run_dependency")
    downloads = [p for p in steps(combined) if "name: premiumizeme-read-protocol" in p]
    require(len(downloads) == 1 and re.findall(r"^          ([a-z-]+):", downloads[0], re.MULTILINE) == ["name", "path"]
            and scalar(downloads[0], "path", 10) == "${{ runner.temp }}/provider-premiumizeme",
            "premiumizeme_same_run_artifact")
    require("linux-provider-evidence" in scalar(definitions["release"], "needs", 4).strip("[]").split(", "),
            "premiumizeme_release_gate")
    require("premiumizeme-read-protocol.json" not in definitions["test"], "premiumizeme_no_portable_borrowing")
    daily = [p for p in re.split(r"(?=^      - )", smoke, flags=re.MULTILINE) if p.strip()]
    runs = [p for p in daily if "premiumizeme-fixed-api/run_container.py" in p]
    require(len(runs) == 1 and command(runs[0]) == ["python", "-B", "../scripts/provider-lab/premiumizeme-fixed-api/run_container.py",
            "--rclone", "$RUNNER_TEMP/rclone-smoke", "--protocol-evidence", "--report", "$RUNNER_TEMP/premiumizeme-read-protocol.json"],
            "premiumizeme_daily_fresh_run")
    require("            ${{ runner.temp }}/premiumizeme-read-protocol.json\n" in smoke, "premiumizeme_daily_retention")
    for parts, path in ((steps(combined), "$RUNNER_TEMP/provider-premiumizeme/premiumizeme-read-protocol.json"),
                        (daily, "$RUNNER_TEMP/premiumizeme-read-protocol.json")):
        gates = [p for p in parts if "--require-fixtures" in p]
        require(len(gates) == 1, "premiumizeme_single_gate")
        args = command(gates[0])
        require("premiumizeme" in args[args.index("--require-fixtures") + 1].split(","), "premiumizeme_required_fixture")
        receipts = [args[i + 1] for i, v in enumerate(args) if v == "--fixture-receipt"]
        require(receipts.count(path) == 1, "premiumizeme_qualified_import")

class PremiumizemeWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.ci = (ROOT / ".github/workflows/ci.yml").read_text()
        self.smoke = (ROOT / ".github/workflows/provider-smoke.yml").read_text()

    def test_required_fresh_job_and_both_ledger_gates(self):
        validate_workflows(self.ci, self.smoke)

    def test_ci_cannot_skip_qualification_borrow_or_omit_receipt(self):
        for before, after in (
            ("  premiumizeme-fixed-api:\n", "  premiumizeme-fixed-api:\n    if: false\n"),
            ("--rclone \"$RUNNER_TEMP/rclone-premiumizeme\" --protocol-evidence", "--rclone \"$RUNNER_TEMP/rclone-premiumizeme\""),
            ("fichier-fixed-api, premiumizeme-fixed-api, putio-fixed-api, linkbox-fixed-api, yandex-fixed-api, box-fixed-api, onedrive-fixed-api, filelu-fixed-api, qingstor-fixed-api, drive-fixed-api, dropbox-fixed-api, oos-fixed-api, zoho-fixed-api, jottacloud-fixed-api, sugarsync-fixed-api]", "fichier-fixed-api, putio-fixed-api, linkbox-fixed-api, yandex-fixed-api, box-fixed-api, onedrive-fixed-api, filelu-fixed-api, qingstor-fixed-api, drive-fixed-api, dropbox-fixed-api, oos-fixed-api, zoho-fixed-api, jottacloud-fixed-api, sugarsync-fixed-api]"),
            ("          path: ${{ runner.temp }}/provider-premiumizeme",
             "          run-id: 123\n          path: ${{ runner.temp }}/provider-premiumizeme"),
            ('--fixture-receipt "$RUNNER_TEMP/provider-premiumizeme/premiumizeme-read-protocol.json"', ""),
            ("sharefile,cloudinary,opendrive,gofile,drime,fichier,premiumizeme,putio,linkbox,yandex,box,onedrive,filelu,qingstor,drive,dropbox,oos,zoho,jottacloud,sugarsync\n", "sharefile,cloudinary,opendrive,gofile,drime,fichier,putio,linkbox,yandex,box,onedrive,filelu,qingstor,drive,dropbox,oos,zoho,jottacloud,sugarsync\n")):
            with self.subTest(before=before):
                self.assertIn(before, self.ci)
                with self.assertRaises(ValueError):
                    validate_workflows(self.ci.replace(before, after, 1), self.smoke)

    def test_smoke_cannot_omit_qualification_import_or_retention(self):
        for before, after in (
            ('../scripts/provider-lab/premiumizeme-fixed-api/run_container.py \\\n            --rclone "$RUNNER_TEMP/rclone-smoke" --protocol-evidence', '../scripts/provider-lab/premiumizeme-fixed-api/run_container.py \\\n            --rclone "$RUNNER_TEMP/rclone-smoke"'),
            ('--fixture-receipt "$RUNNER_TEMP/premiumizeme-read-protocol.json"', ""),
            ("sharefile,cloudinary,opendrive,gofile,drime,fichier,premiumizeme,putio,linkbox,yandex,box,onedrive,filelu,qingstor,drive,dropbox,oos,zoho,jottacloud,sugarsync\n", "sharefile,cloudinary,opendrive,gofile,drime,fichier,putio,linkbox,yandex,box,onedrive,filelu,qingstor,drive,dropbox,oos,zoho,jottacloud,sugarsync\n"),
            ("            ${{ runner.temp }}/premiumizeme-read-protocol.json\n", "")):
            with self.subTest(before=before):
                self.assertIn(before, self.smoke)
                with self.assertRaises(ValueError):
                    validate_workflows(self.ci, self.smoke.replace(before, after, 1))

if __name__ == "__main__":
    unittest.main()
