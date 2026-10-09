"""Independent schema-6/mode composition oracles; no processes or sockets."""
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


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


C = load("gcs_lifecycle_coverage", ROOT / "scripts/provider_coverage.py")
S = load("gcs_lifecycle_supervisor", ROOT / "scripts/provider-lab/gcs-oauth/run_container.py")
NOW = datetime(2026, 10, 9, 12, tzinfo=timezone.utc)
IDENTITY = {"version": "1.75.1", "sha256": "a" * 64}
RUNTIME = dict(IDENTITY, platform="linux")
FIXTURE = "c990bbd4909b227aae4c70d26f9da5534740a2eb10337ced47977f915fa617be"
MODE = "gcs_oauth_lifecycle_v1"
STATIC_MODE = "gcs_static_token_read_v1"
STATIC = ("listing", "download_hash", "missing_object_rejection", "authentication_rejection",
          "read_denial", "source_preservation", "config_preservation", "cleanup")
LIFECYCLE = ("authentication", "refresh", "renewal_denial", "cancellation_cleanup")
NAMES = ("positive", "wrong_state", "blank_state", "consent_denied", "invalid_code",
         "wrong_client_secret", "callback_cancel", "refresh", "refresh_denied", "refresh_cancel")
COMMON = ("environment", "version_binding", "initial_config_question", "callback_ownership",
          "source_preserved", "request_sequence")
EXTRAS = (
    ("authorize", "token_exchange", "config_persisted", "fresh_child_read", "config_preserved"),
    *(("authorize", "callback_denial", "no_token_persisted", "config_preserved", "no_read"),) * 3,
    *(("authorize", "token_denial", "no_token_persisted", "config_preserved", "no_read"),) * 2,
    ("owned_process_cancel", "no_token_persisted", "config_preserved", "no_read"),
    ("authorize", "token_exchange", "config_persisted", "expired_before_read", "replacement_read",
     "replacement_persisted", "non_token_config_preserved"),
    ("authorize", "token_exchange", "config_persisted", "expired_before_read", "refresh_denial",
     "config_preserved", "no_read"),
    ("authorize", "token_exchange", "config_persisted", "expired_before_read", "owned_process_cancel",
     "config_preserved", "no_read"),
)
COUNTS = ((4, 2, 5), (3, 2, 1), (3, 2, 1), (3, 2, 1), (3, 2, 3),
          (3, 2, 3), (3, 0, 0), (4, 2, 7), (4, 2, 5), (4, 2, 5))
FILES = sorted(["scripts/provider-lab/gcs-oauth/" + name for name in
                ("Dockerfile", "build-lock.json", "run_container.py", "probe.py", "fixture_oauth.py")]
               + ["scripts/provider-lab/fixture_tls.py", "scripts/provider-lab/fixture_pcloud.py",
                  "scripts/provider-lab/requirements-fixture.txt", "rclone-version.env"])
SOURCES = {name: hashlib.sha256(name.encode()).hexdigest() for name in FILES}
LOCK = json.loads((ROOT / "scripts/provider-lab/gcs-oauth/build-lock.json").read_bytes())


def canonical(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


BINDINGS = {"harness_sha256": canonical(SOURCES), "fixture_manifest_sha256": FIXTURE,
            "source_sha256": SOURCES, "lock": LOCK}


def native():
    runtime = {"platform": "linux", "architecture": "amd64", "uid": 10001, "gid": 10001,
               "python_version": LOCK["python_version"], "cryptography_version": "50.0.2",
               "rclone_version": IDENTITY["version"], "rclone_sha256": IDENTITY["sha256"],
               "probe_sha256": SOURCES["scripts/provider-lab/gcs-oauth/probe.py"], "fixture_manifest_sha256": FIXTURE}
    cases = []
    for index, (name, extra, (commands, callbacks, https)) in enumerate(zip(NAMES, EXTRAS, COUNTS)):
        cases.append({"name": name, "report": {
            "schema_version": 1, "scope": "gcs_oauth_lifecycle_case", "ledger_eligible": False,
            "started_utc": f"2026-10-09T11:58:{index * 2:02d}Z",
            "finished_utc": f"2026-10-09T11:58:{index * 2 + 1:02d}Z", "runtime": dict(runtime),
            "checks": dict.fromkeys(COMMON + extra, True),
            "observations": {"native_commands": commands, "callback_requests": callbacks,
                             "https_requests": https, "http_transactions": callbacks + https},
            "cleanup": dict.fromkeys(("children_stopped", "listeners_closed", "temporary_removed"), True),
            "success": True, "errors": []}})
    suite = {"schema_version": 1, "scope": "gcs_oauth_lifecycle_suite", "ledger_eligible": False,
             "started_utc": "2026-10-09T11:58:00Z", "finished_utc": "2026-10-09T11:58:20Z",
             "runtime": dict(runtime), "cases": cases, "success": True, "errors": []}
    return {"schema_version": 1, "scope": "gcs_oauth_lifecycle_qualified_supervision", "ledger_eligible": False,
            "started_utc": "2026-10-09T11:57:00Z", "finished_utc": "2026-10-09T11:59:00Z",
            "success": True, "runtime": dict(IDENTITY), "platform": "linux/amd64",
            "source_sha256": dict(SOURCES), "source_digest": canonical(SOURCES),
            "dependency_lock_sha256": LOCK["requirements"]["sha256"],
            "dependency_versions": dict(LOCK["requirements"]["distributions"]),
            "python_version": LOCK["python_version"], "base_image": LOCK["base_image"],
            "base_config_digest": LOCK["base_config_digest"], "image_id": "sha256:" + "b" * 64,
            "container_isolation_verified": True, "probe": suite, "errors": [],
            "cleanup": dict.fromkeys(("commands_stopped", "container_removed", "image_removed", "temporary_removed"), True),
            "stage": "completed", "build_phase": "manifest", "container_exit_code": 0,
            "container_stdout_bytes": len(json.dumps(suite, sort_keys=True, separators=(",", ":")).encode()) + 1, "container_stderr_bytes": 0, "container_oom_killed": False,
            "container_start_error_present": False, "build_cache_scope": "shared_daemon_cache_not_pruned",
            "probe_started_utc": "2026-10-09T11:58:00Z", "probe_finished_utc": "2026-10-09T11:58:21Z"}


def evidence(value=None):
    return S.lifecycle_evidence(native() if value is None else value, BINDINGS)


def static_receipt():
    return {"schema_version": 1, "scope": "rclone_backend_protocol_fixture", "runtime": dict(IDENTITY),
            "platform": "linux", "harness_sha256": "c" * 64, "fixture_manifest_sha256": FIXTURE,
            "started_utc": "2026-10-09T11:57:00Z", "finished_utc": "2026-10-09T11:59:00Z",
            "success": True, "cleanup_passed": True, "errors": [], "backends": [
                {"backend": "gcs", "fixture_kind": "independent_loopback",
                 "capabilities": dict.fromkeys(STATIC, "passed"), "errors": []}]}


def failed_prefix(index=8, cleanup=True):
    value = native(); suite = value["probe"]
    suite["cases"] = suite["cases"][:index + 1]
    row = suite["cases"][-1]["report"]
    row.update(success=False, errors=["synthetic_failure"])
    row["checks"][EXTRAS[index][-1]] = False
    row["cleanup"]["temporary_removed"] = cleanup
    suite.update(success=False, errors=["lifecycle_case_failed"])
    value.update(success=False, stage="probe", errors=["oauth_probe_failed"], container_exit_code=1)
    value["container_stdout_bytes"] = len(json.dumps(suite, sort_keys=True, separators=(",", ":")).encode()) + 1
    return evidence(value)


class GcsLifecycleTests(unittest.TestCase):
    def setUp(self):
        actual = json.loads((ROOT / "provider-coverage-policy.json").read_bytes())
        entry = copy.deepcopy(actual["providers"]["gcs"])
        self.catalog = C.catalog_from_schemas([{"Name": "google cloud storage", "Prefix": "gcs", "Options": []}])
        entry["schema_sha256"] = self.catalog[0]["schema_sha256"]
        self.policy = {"schema_version": 2, "reviewed_runtime_version": IDENTITY["version"],
                       "providers": {"gcs": entry}, "profiles": {entry["profile"]: actual["profiles"][entry["profile"]]}}

    def evaluate(self, receipts, **kwargs):
        options = {"now": NOW, "fixture_manifest_sha256": FIXTURE, "gcs_bindings": copy.deepcopy(BINDINGS)}
        options.update(kwargs)
        return C.evaluate(self.catalog, self.policy, RUNTIME, receipts, "c" * 64, **options)

    def local(self, report):
        return report["providers"][0]["evidence"]["local_protocol"]

    def rejected(self, item, **kwargs):
        report = self.evaluate([item], **kwargs)
        self.assertTrue(report["errors"])
        self.assertEqual(self.local(report)["status"], "not_verified")
        self.assertIn("required_fixture_not_verified", C.gate_errors(report, require_fixtures=["gcs"]))

    def test_exact_ten_cases_and_independent_counts_only_pass_with_both_modes(self):
        value = native()
        self.assertEqual(sum(len(x["report"]["checks"]) for x in value["probe"]["cases"]), 115)
        self.assertEqual(tuple(sum(x[i] for x in COUNTS) for i in range(3)), (34, 18, 31))
        for items in ([static_receipt()], [evidence()], [static_receipt(), evidence()], [evidence(), static_receipt()]):
            report = self.evaluate(items); local = self.local(report)
            self.assertEqual(report["errors"], [])
            self.assertEqual(local["status"], "passed" if len(items) == 2 else "not_verified")
            self.assertEqual(set(local["modes"]), {MODE, STATIC_MODE})
            self.assertEqual(set(local["modes"][MODE]["capabilities"]), set(LIFECYCLE))
            for tier in ("application", "vendor"):
                self.assertEqual(report["providers"][0]["evidence"][tier]["status"], "not_verified")
                self.assertTrue(all(x == "not_verified" for x in report["providers"][0]["evidence"][tier]["capabilities"].values()))
            self.assertEqual(report["providers"][0]["capability_applicability_review_required"], ["reauthentication"])
            self.assertFalse(report["all_complete"])
        run = self.local(self.evaluate([evidence()]))["modes"][MODE]["runs"][0]
        self.assertEqual(run["source_sha256"], SOURCES)
        self.assertEqual((run["platform"], run["architecture"]), ("linux", "amd64"))

    def test_baseline_gate_requires_all_eight_caps_without_promoting_missing_lifecycle(self):
        report = self.evaluate([static_receipt()])
        self.assertEqual(C.gate_errors(report, require_gcs_static_token=True), [])
        self.assertEqual(C.gate_errors(report, require_fixtures=["gcs"]), ["required_fixture_not_verified"])
        self.assertEqual(self.local(report)["modes"][MODE]["status"], "not_verified")
        for cap in STATIC:
            item = static_receipt(); del item["backends"][0]["capabilities"][cap]
            self.assertIn("required_gcs_static_token_not_verified", C.gate_errors(self.evaluate([item]), require_gcs_static_token=True))
        self.assertIn("required_gcs_static_token_not_verified", C.gate_errors(self.evaluate([evidence()]), require_gcs_static_token=True))

    def test_weakened_policy_cannot_remove_either_complete_mode(self):
        for caps in (["authentication"], ["listing"], list(STATIC), list(LIFECYCLE)):
            self.policy["profiles"][self.policy["providers"]["gcs"]["profile"]]["required"]["local_protocol"] = caps
            for item in (static_receipt(), evidence()):
                self.assertEqual(self.local(self.evaluate([item]))["status"], "not_verified")

    def test_all_valid_failed_prefixes_and_late_cleanup_are_sticky_in_both_orders(self):
        failures = [failed_prefix(i) for i in range(10)] + [failed_prefix(cleanup=False)]
        for key in ("commands_stopped", "container_removed", "image_removed", "temporary_removed"):
            value = native(); value["cleanup"][key] = False
            value.update(success=False, errors=["supervisor_cleanup_failed"])
            failures.append(evidence(value))
        value = native(); value.update(success=False, errors=["source_or_runtime_changed"])
        failures.append(evidence(value))
        for failure in failures:
            for items in ([failure, static_receipt(), evidence()], [evidence(), static_receipt(), failure]):
                report = self.evaluate(items); self.assertEqual(report["errors"], [])
                self.assertEqual(self.local(report)["status"], "failed")
                self.assertEqual(self.local(report)["modes"][MODE]["status"], "failed")
                self.assertEqual(self.local(report)["modes"][MODE]["capabilities"], dict.fromkeys(LIFECYCLE, "failed"))
                self.assertIn("required_gcs_static_token_not_verified", C.gate_errors(report, require_gcs_static_token=True))

    def test_static_failure_remains_failed_despite_successful_lifecycle(self):
        item = static_receipt(); item.update(success=False, errors=["synthetic_failure"])
        item["backends"][0]["capabilities"]["download_hash"] = "failed"
        item["backends"][0]["errors"] = ["synthetic_failure"]
        for items in ([item, evidence(), static_receipt()], [static_receipt(), evidence(), item]):
            self.assertEqual(self.local(self.evaluate(items))["status"], "failed")

    def test_current_source_default_experiment_cannot_be_converted_or_imported(self):
        value = native(); value["scope"] = "gcs_oauth_lifecycle_supervision"
        with self.assertRaisesRegex(S.SupervisorError, "native_scope_mismatch"):
            evidence(value)
        self.rejected(value)
        item = evidence(); item["native_evidence"] = value; self.rejected(item)
        for schema in (True, "6", 1, 2, 3, 4, 5):
            item = evidence(); item["schema_version"] = schema; self.rejected(item)
        for key in ("fixture_mode", "scope", "auth_mode"):
            item = static_receipt(); item["backends"][0][key] = MODE; self.rejected(item)

    def test_each_check_cleanup_and_observation_is_required_not_success_flag_alone(self):
        for index in range(10):
            for field in ("checks", "cleanup", "observations"):
                values = native()["probe"]["cases"][index]["report"][field]
                for key, original in values.items():
                    for change in (None, 1 if field != "observations" else True,
                                   False if field != "observations" else original + 1):
                        item = evidence(); item["native_evidence"]["probe"]["cases"][index]["report"][field][key] = change
                        with self.subTest(case=NAMES[index], field=field, key=key, value=change): self.rejected(item)
        for key in native()["cleanup"]:
            for change in (False, 1, None):
                item = evidence(); item["native_evidence"]["cleanup"][key] = change; self.rejected(item)

    def test_closed_ordered_prefix_and_exact_envelopes(self):
        mutations = (lambda x: x["cases"].pop(), lambda x: x["cases"].reverse(),
                     lambda x: x["cases"].append(copy.deepcopy(x["cases"][-1])),
                     lambda x: x["cases"][1].update(name="positive"),
                     lambda x: x["cases"][1]["report"].update(started_utc="2026-10-09T11:58:00Z"),
                     lambda x: x.update(ledger_eligible=True), lambda x: x.update(extra="CANARY"))
        for mutate in mutations:
            item = evidence(); mutate(item["native_evidence"]["probe"]); self.rejected(item)
        item = failed_prefix(2); item["native_evidence"]["probe"]["cases"][0]["report"].update(success=False, errors=["failed"])
        self.rejected(item)
        for field, value in (("backend", "drive"), ("fixture_kind", "independent_loopback"),
                             ("fixture_mode", STATIC_MODE), ("scope", "application")):
            item = evidence(); item["backends"][0][field] = value; self.rejected(item)
        for cap in (*STATIC, "revocation", "reauthentication", "manifest_integrity"):
            item = evidence(); item["backends"][0]["capabilities"][cap] = "passed"; self.rejected(item)

    def test_runtime_sources_dependencies_time_and_os_cannot_be_borrowed(self):
        fields = (("source_digest", "f" * 64), ("base_image", "python:latest"), ("base_config_digest", "sha256:" + "f" * 64),
                  ("dependency_lock_sha256", "f" * 64), ("python_version", "3.13.0"), ("platform", "windows/amd64"),
                  ("container_isolation_verified", False), ("container_exit_code", True), ("container_stdout_bytes", 0),
                  ("container_stderr_bytes", 1), ("container_oom_killed", True), ("container_start_error_present", True),
                  ("stage", "probe"), ("build_phase", "dependencies"), ("probe_started_utc", "2026-10-09T11:58:10Z"))
        for field, value in fields:
            item = evidence(); item["native_evidence"][field] = value; self.rejected(item)
        for name in FILES:
            item = evidence(); item["native_evidence"]["source_sha256"][name] = "f" * 64; self.rejected(item)
        for field, value in (("version", "1.75.2"), ("sha256", "f" * 64), ("platform", "windows")):
            with self.assertRaises((S.SupervisorError, KeyError)):
                S.validate_lifecycle_evidence(evidence(), dict(RUNTIME, **{field: value}), BINDINGS, NOW)
        for now in (datetime(2026, 10, 9, 11, tzinfo=timezone.utc), datetime(2026, 10, 11, tzinfo=timezone.utc)):
            self.rejected(evidence(), now=now)
        for age in (True, 0, 169, 24.0):
            with self.assertRaises(S.SupervisorError):
                S.validate_lifecycle_evidence(evidence(), RUNTIME, BINDINGS, NOW, age)
        self.rejected(evidence(), gcs_bindings=None)
        self.rejected(evidence(), fixture_manifest_sha256="f" * 64)

    def test_exact_stdout_framing_and_fresh_cli_only(self):
        for delta in (-1, 1):
            item = evidence(); item["native_evidence"]["container_stdout_bytes"] += delta
            self.rejected(item)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "existing.json"; path.write_text("{}")
            with patch.object(S.sys, "platform", "linux"), \
                 patch.dict(S.os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}), \
                 patch.object(S, "runtime_identity", side_effect=AssertionError("no prior receipt conversion")), \
                 patch.object(S, "Docker", side_effect=AssertionError("native forbidden")):
                with self.assertRaisesRegex(S.SupervisorError, "new_absolute_report_required"):
                    S.run(Path(temporary) / "unused", path, lifecycle=True)
        for flag in ([], ["--lifecycle-evidence"]):
            argv = ["run_container.py", "--rclone", "/synthetic/rclone", "--report", "/synthetic/new.json", *flag]
            with patch.object(S.sys, "argv", argv), patch.object(S.signal, "signal"), \
                 patch.object(S, "run", return_value={"success": True, "errors": []}) as run, \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(S.main(), 0)
                self.assertEqual(run.call_args.kwargs, {"lifecycle": bool(flag)})
        with patch.object(S.sys, "argv", ["run_container.py", "--rclone", "unused", "--report", "unused", "--receipt", "old.json"]), \
             patch.object(S, "run", side_effect=AssertionError("conversion forbidden")), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit): S.main()

    def test_current_source_binding_does_not_import_probe_or_execute(self):
        with patch.object(C.subprocess, "Popen", side_effect=AssertionError("native forbidden")), \
             patch("importlib.machinery.SourceFileLoader.exec_module", side_effect=AssertionError("cached import forbidden")):
            bindings = C.compute_gcs_bindings(ROOT / "scripts/provider-lab/gcs-oauth")
        expected = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in FILES}
        self.assertEqual(bindings["source_sha256"], expected)
        self.assertEqual(bindings["harness_sha256"], canonical(expected))
        self.assertEqual(bindings["fixture_manifest_sha256"], C.compute_fixture_manifest_sha256(ROOT / "scripts/provider-lab"))
        self.assertEqual(len(C.HARNESSES), 6)

    def test_cli_baseline_and_full_modes_compute_only_needed_bindings(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); policy = root / "policy.json"; policy.write_text(json.dumps(self.policy))
            paths = []
            for index, item in enumerate((static_receipt(), evidence())):
                path = root / f"receipt-{index}.json"; path.write_text(json.dumps(item)); paths.append(path)
            for index, (selected, flags, code) in enumerate(((paths[:1], ["--require-gcs-static-token"], 0),
                    (paths[:1], ["--require-fixtures", "gcs"], 1), (paths[1:], ["--require-gcs-static-token"], 1),
                    (paths, ["--require-fixtures", "gcs"], 0))):
                report = root / f"ledger-{index}.json"
                argv = ["--rclone", str(root / "never-run"), "--policy", str(policy), "--report", str(report), *flags]
                for path in selected: argv += ["--fixture-receipt", str(path)]
                with patch.object(C, "query_runtime", return_value=(RUNTIME, self.catalog)), \
                     patch.object(C, "compute_harness_sha256", return_value="c" * 64), \
                     patch.object(C, "compute_fixture_manifest_sha256", return_value=FIXTURE), \
                     patch.object(C, "compute_gcs_bindings", return_value=BINDINGS) as binding, \
                     patch.object(C.subprocess, "Popen", side_effect=AssertionError("native forbidden")), \
                     patch.object(C, "datetime", wraps=datetime) as clock, contextlib.redirect_stdout(io.StringIO()):
                    clock.now.return_value = NOW
                    self.assertEqual(C.main(argv), code)
                    self.assertEqual(binding.call_count, int(paths[1] in selected))
                self.assertEqual(json.loads(report.read_text())["errors"], [])


if __name__ == "__main__":
    unittest.main()
