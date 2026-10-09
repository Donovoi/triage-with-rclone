"""Independent authentication-suite oracles. All container operations are mocked."""
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import test_provider_pcloud_oauth_container as baseline

S = baseline.S
NAMES = ("positive", "wrong_state", "blank_state", "invalid_hostname", "consent_denied", "invalid_code", "wrong_client_secret", "cancelled")
IDENTITY = baseline.IDENTITY
SOURCES = baseline.SOURCES
LOCK = baseline.LOCK
FIXTURE = "c990bbd4909b227aae4c70d26f9da5534740a2eb10337ced47977f915fa617be"
BINDINGS = {"harness_sha256": hashlib.sha256(json.dumps(SOURCES, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "fixture_manifest_sha256": FIXTURE, "source_sha256": SOURCES, "lock": LOCK}
NOW = datetime(2026, 10, 4, 12, 1, tzinfo=timezone.utc)


def suite():
    cases = []
    for index, name in enumerate(NAMES):
        report = baseline.probe()
        report["started_utc"] = "2026-10-04T12:00:%02dZ" % (2 + index * 5)
        report["finished_utc"] = "2026-10-04T12:00:%02dZ" % (4 + index * 5)
        if index:
            report["scope"] = "pcloud_oauth_authentication_case"
            report["checks"] = dict.fromkeys(("environment", "tls_authority_bound", "authority_preserved", "version_binding", "initial_config_question", "callback_ownership",
                "no_token_persisted", "config_preserved", "no_read", "source_preserved", "request_sequence"), True)
            extra = (("owned_process_cancel",) if name == "cancelled" else ("authorize", "hostname_denial") if name == "invalid_hostname" else ("authorize", "token_denial") if name in ("invalid_code", "wrong_client_secret") else ("authorize", "callback_denial"))
            report["checks"].update(dict.fromkeys(extra, True))
            https = 0 if name == "cancelled" else 3 if name in ("invalid_code", "wrong_client_secret") else 1
            callbacks = 0 if name == "cancelled" else 2
            report["observations"] = {"native_commands": 3, "http_transactions": https + callbacks,
                                      "callback_requests": callbacks, "https_requests": https}
        cases.append({"name": name, "report": report})
    return {"schema_version": 1, "scope": "pcloud_oauth_authentication_suite", "ledger_eligible": False,
            "started_utc": "2026-10-04T12:00:01Z", "finished_utc": "2026-10-04T12:00:40Z",
            "runtime": copy.deepcopy(cases[0]["report"]["runtime"]), "cases": cases, "success": True, "errors": []}


def native():
    return {"schema_version": 1, "scope": "pcloud_oauth_authentication_supervision", "ledger_eligible": False,
            "started_utc": "2026-10-04T12:00:00Z", "finished_utc": "2026-10-04T12:00:45Z", "success": True,
            "runtime": dict(IDENTITY), "platform": "linux/amd64", "source_sha256": dict(SOURCES),
            "source_digest": BINDINGS["harness_sha256"], "dependency_lock_sha256": LOCK["requirements"]["sha256"],
            "dependency_versions": {"cryptography": "50.0.2", "cffi": "2.1.1", "pycparser": "3.0"},
            "python_version": "3.12.15", "base_image": LOCK["base_image"], "base_config_digest": LOCK["base_config_digest"],
            "image_id": baseline.IMAGE, "container_isolation_verified": True, "probe": suite(), "errors": [],
            "cleanup": {"container_removed": True, "image_removed": True, "temporary_removed": True},
            "stage": "completed", "build_phase": "manifest", "container_exit_code": 0, "container_stdout_bytes": 12000,
            "container_stderr_bytes": 0, "container_oom_killed": False, "container_start_error_present": False,
            "build_cache_scope": "shared_daemon_cache_not_pruned", "probe_started_utc": "2026-10-04T12:00:01Z",
            "probe_finished_utc": "2026-10-04T12:00:41Z"}


def evidence():
    # Deliberately not generated with authentication_evidence().
    return {"schema_version": 5, "scope": "rclone_backend_protocol_fixture", "runtime": dict(IDENTITY),
            "platform": "linux", "architecture": "amd64", "harness_sha256": BINDINGS["harness_sha256"],
            "fixture_manifest_sha256": FIXTURE, "started_utc": "2026-10-04T12:00:00Z",
            "finished_utc": "2026-10-04T12:00:45Z", "success": True, "cleanup_passed": True, "errors": [],
            "backends": [{"backend": "pcloud", "fixture_kind": "independent_oauth_container",
                          "fixture_mode": "pcloud_oauth_authentication_v1", "capabilities": {"authentication": "passed"}, "errors": []}],
            "native_evidence": native()}


def failed_prefix(length=3, cleanup=True):
    item = evidence(); report = item["native_evidence"]; inner = report["probe"]
    inner["cases"] = inner["cases"][:length]
    last = inner["cases"][-1]["report"]
    last["success"] = False; last["checks"]["request_sequence"] = False; last["errors"] = ["sequence_failed"]
    last["cleanup"]["children_stopped"] = cleanup
    inner.update(success=False, errors=["authentication_case_failed"])
    report.update(success=False, stage="probe", container_exit_code=1, errors=["oauth_probe_failed"])
    item.update(success=False, cleanup_passed=cleanup, errors=["pcloud_authentication_failed"])
    item["backends"][0].update(capabilities={"authentication": "failed"}, errors=["pcloud_authentication_failed"])
    return item


class AuthenticationContract(unittest.TestCase):
    def validate(self, item):
        return S.validate_authentication_evidence(item, dict(IDENTITY, platform="linux"), BINDINGS, NOW)

    def test_independent_success_exact_counts_and_capability(self):
        item = evidence(); self.assertIs(self.validate(item), item)
        self.assertEqual(S.authentication_evidence(native(), BINDINGS), item)
        totals = {k: sum(row["report"]["observations"][k] for row in suite()["cases"]) for k in ("native_commands", "http_transactions", "callback_requests", "https_requests")}
        self.assertEqual(totals, {"native_commands": 25, "http_transactions": 30, "callback_requests": 14, "https_requests": 16})

    def test_each_failed_prefix_is_preserved_without_fabricating_unrun_cases(self):
        for length in range(1, 9):
            for cleaned in (True, False):
                with self.subTest(length=length, cleaned=cleaned):
                    self.validate(failed_prefix(length, cleaned))

    def test_unexplained_prefix_skipped_duplicate_or_reordered_case_is_rejected(self):
        for mode in ("empty", "prefix", "duplicate", "reorder", "extra", "continue"):
            item = evidence(); cases = item["native_evidence"]["probe"]["cases"]
            if mode == "empty": cases.clear()
            elif mode == "prefix": cases.pop()
            elif mode == "duplicate": cases[2] = copy.deepcopy(cases[1])
            elif mode == "reorder": cases[1], cases[2] = cases[2], cases[1]
            elif mode == "extra": cases.append(copy.deepcopy(cases[-1]))
            else:
                cases[1]["report"].update(success=False, errors=["failed"])
                cases[1]["report"]["checks"]["request_sequence"] = False
            with self.subTest(mode=mode), self.assertRaises(S.SupervisorError): self.validate(item)

    def test_every_case_check_count_cleanup_and_runtime_is_enforced(self):
        for index, row in enumerate(suite()["cases"]):
            for field in ("checks", "cleanup", "observations", "runtime"):
                for key, value in row["report"][field].items():
                    item = evidence()
                    item["native_evidence"]["probe"]["cases"][index]["report"][field][key] = (False if type(value) is bool else value + 1 if type(value) is int else "wrong")
                    with self.subTest(case=row["name"], field=field, key=key), self.assertRaises(S.SupervisorError): self.validate(item)

    def test_bool_integer_aliases_extra_fields_and_lifecycle_claims_rejected(self):
        mutations = [("schema_version", True), ("success", 1), ("cleanup_passed", 1), ("scope", "vendor"), ("fixture_mode", "auth")]
        for key, value in mutations:
            item = evidence(); item[key] = value
            with self.assertRaises(S.SupervisorError): self.validate(item)
        for cap in ("refresh", "reauthentication", "listing", "source_preservation", "cleanup"):
            item = evidence(); item["backends"][0]["capabilities"][cap] = "passed"
            with self.assertRaises(S.SupervisorError): self.validate(item)
        item = evidence(); item["native_evidence"]["probe"]["runtime"]["uid"] = True
        with self.assertRaises(S.SupervisorError): self.validate(item)

    def test_clocks_overlap_future_stale_and_deadline_rejected(self):
        for field, value in (("started_utc", "2026-10-04T12:00:00Z"), ("finished_utc", "2026-10-04T12:10:00Z")):
            item = evidence(); item["native_evidence"]["probe"]["cases"][0]["report"][field] = value
            with self.assertRaises(S.SupervisorError): self.validate(item)
        item = evidence(); item["native_evidence"]["probe"]["cases"][1]["report"]["started_utc"] = "2026-10-04T12:00:03Z"
        with self.assertRaises(S.SupervisorError): self.validate(item)
        for now in (datetime(2026, 10, 4, 12, tzinfo=timezone.utc), datetime(2026, 10, 6, tzinfo=timezone.utc)):
            with self.assertRaises(S.SupervisorError): S.validate_authentication_evidence(evidence(), dict(IDENTITY, platform="linux"), BINDINGS, now)

    def test_preflight_failure_and_known_empty_runtime_do_not_supply_authentication(self):
        item = failed_prefix(1)
        report = item["native_evidence"]["probe"]["cases"][0]["report"]
        report["checks"]["version_binding"] = False
        for key in ("cryptography_version", "rclone_version", "rclone_sha256"): report["runtime"][key] = ""
        item["native_evidence"]["probe"]["runtime"] = copy.deepcopy(report["runtime"])
        self.validate(item)
        for key in ("cryptography_version", "rclone_version", "rclone_sha256"):
            changed = copy.deepcopy(item); changed["native_evidence"]["probe"]["cases"][0]["report"]["runtime"][key] = "wrong"
            with self.assertRaises(S.SupervisorError): self.validate(changed)

    def test_default_feasibility_and_wrong_platform_or_bindings_cannot_be_imported(self):
        for candidate in (baseline.probe(), native(), suite()):
            with self.assertRaises(S.SupervisorError): self.validate(candidate)
        for key in SOURCES:
            bindings = copy.deepcopy(BINDINGS); bindings["source_sha256"][key] = "e" * 64
            with self.assertRaises(S.SupervisorError): S.validate_authentication_evidence(evidence(), dict(IDENTITY, platform="linux"), bindings, NOW)
        with self.assertRaises(S.SupervisorError): S.validate_authentication_evidence(evidence(), dict(IDENTITY, platform="windows"), BINDINGS, NOW)

    def test_freshness_window_requires_a_bounded_actual_integer(self):
        for value in (True, False, 1.0, "24", None, 0, 169):
            with self.subTest(value=value), self.assertRaises(S.SupervisorError):
                S.validate_authentication_evidence(evidence(), dict(IDENTITY, platform="linux"), BINDINGS, NOW, value)
        for value in (1, 24, 168):
            self.assertEqual(S.validate_authentication_evidence(evidence(), dict(IDENTITY, platform="linux"), BINDINGS, NOW, value), evidence())


class AuthenticationOrchestration(unittest.TestCase):
    def execute(self, cleanup_failure=False, drift=False, failed=False):
        class AuthDocker(baseline.FakeDocker):
            def __init__(self, directory):
                super().__init__(directory); self.inner = suite(); self.cleanup_failure = cleanup_failure
                if failed: self.inner = failed_prefix()["native_evidence"]["probe"]
            def inspect(self, kind, target):
                result = super().inspect(kind, target)
                if kind == "container" and result is not None:
                    result["Config"]["Cmd"].append("--authentication-suite")
                    if failed and self.started: result["State"]["ExitCode"] = 1
                return result
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve(); instances = []
            def factory(root):
                obj = AuthDocker(root); instances.append(obj); return obj
            changed = dict(SOURCES); changed["rclone-version.env"] = "e" * 64
            with mock.patch.object(S.sys, "platform", "linux"), mock.patch.dict(S.os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}), \
                 mock.patch.object(S, "runtime_identity", return_value=IDENTITY), mock.patch.object(S, "source_hashes", side_effect=[SOURCES, changed if drift else SOURCES]), \
                 mock.patch.object(S, "read_lock", return_value=LOCK), mock.patch.object(S, "stage_context"), mock.patch.object(S, "Docker", side_effect=factory), \
                 mock.patch.object(S.uuid, "uuid4", return_value=mock.Mock(hex=baseline.RUN)), \
                 mock.patch.object(S, "utc_now", side_effect=["2026-10-04T12:00:00Z", "2026-10-04T12:00:01Z", "2026-10-04T12:00:41Z", "2026-10-04T12:00:45Z"]), \
                 mock.patch.object(S.subprocess, "Popen", side_effect=AssertionError("native_execution_forbidden")):
                result = S.run(path / "rclone", path / "receipt.json", authentication=True)
            self.assertEqual(json.loads((path / "receipt.json").read_bytes()), result)
            self.assertFalse(instances[0].root.exists())
            return result, instances[0]

    def test_explicit_fresh_suite_argv_deadline_and_schema5(self):
        result, docker = self.execute()
        self.assertTrue(result["success"]); self.assertEqual(result["schema_version"], 5)
        create = next(args for args, _ in docker.calls if args[0] == "create")
        self.assertEqual(create[-1], "--authentication-suite")
        start = next((args, kw) for args, kw in docker.calls if args[0] == "start")
        self.assertEqual(start[0], ["start", "--attach", baseline.CONTAINER]); self.assertEqual(start[1]["timeout"], 240)
        self.assertEqual(result["backends"][0]["capabilities"], {"authentication": "passed"})
        S.validate_authentication_evidence(result, dict(IDENTITY, platform="linux"), BINDINGS, NOW)

    def test_late_cleanup_or_source_failure_cannot_promote_successful_suite(self):
        for args in ({"cleanup_failure": True}, {"drift": True}):
            result, _ = self.execute(**args)
            self.assertFalse(result["success"]); self.assertTrue(result["native_evidence"]["probe"]["success"])
            self.assertEqual(result["backends"][0]["capabilities"], {"authentication": "failed"})
            S.validate_authentication_evidence(result, dict(IDENTITY, platform="linux"), BINDINGS, NOW)

    def test_failed_native_prefix_is_recorded_with_owned_cleanup(self):
        result, _ = self.execute(failed=True)
        self.assertFalse(result["success"]); self.assertTrue(result["cleanup_passed"])
        self.assertEqual(len(result["native_evidence"]["probe"]["cases"]), 3)
        S.validate_authentication_evidence(result, dict(IDENTITY, platform="linux"), BINDINGS, NOW)


if __name__ == "__main__":
    unittest.main()
