"""Independent SMB ledger oracles; no Docker, rclone, services or credentials."""
import contextlib
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("smb_coverage_subject", ROOT / "scripts/provider_coverage.py")
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)
NOW = datetime(2026, 10, 4, 12, tzinfo=timezone.utc)
RUNTIME = {"version": "1.76.2", "sha256": "a" * 64, "platform": "linux"}
CAPS = ("listing", "download_hash", "missing_object_rejection", "authentication_rejection",
        "source_preservation", "config_preservation", "cleanup")
SOURCE = {"Dockerfile": "1" * 64, "build-lock.json": "2" * 64,
          "probe_samba.py": "3" * 64, "run_container.py": "4" * 64}
BINDINGS = {"harness_sha256": "b" * 64, "fixture_manifest_sha256": "c" * 64,
            "source_sha256": SOURCE, "base_image": "docker.io/library/debian@sha256:" + "d" * 64,
            "samba_version": "4.22.11-Debian-4.22.11+dfsg-0+deb13u1"}


def literal_receipt():
    """Written independently of the receipt producer and its capability maps."""
    native = {
        "schema_version": 1, "scope": "smb_samba_container_feasibility_only", "ledger_eligible": False,
        "success": True, "runtime": {"version": "1.76.2", "sha256": "a" * 64},
        "source_sha256": dict(SOURCE), "base_image": BINDINGS["base_image"],
        "image_id": "sha256:" + "e" * 64, "container_isolation_verified": True,
        "probe": {
            "schema_version": 1, "scope": "smb_samba_feasibility_only", "ledger_eligible": False,
            "status": "passed", "commands_total": 16, "errors": [],
            "runtime": {"platform": "linux/amd64", "uid": 10001, "gid": 10001,
                        "samba_version": BINDINGS["samba_version"], "rclone_version": "1.76.2",
                        "smbd_sha256": "f" * 64, "rclone_sha256": "a" * 64,
                        "probe_sha256": "3" * 64, "lock_sha256": "2" * 64},
            "checks": {
                "environment": True, "version_binding": True, "config_validation": True,
                "good_listing_before": True, "good_downloads_before": True, "bad_password_rejected": True,
                "good_listing_after": True, "good_downloads_after": True, "missing_rejected": True,
                "source_preserved": True, "config_preserved": True, "seed_preserved": True,
            },
            "cleanup": {"children_stopped": True, "listeners_closed": True, "temporary_removed": True},
        },
        "errors": [], "cleanup": {"container_removed": True, "image_removed": True, "temporary_removed": True},
        "stage": "completed", "build_phase": "manifest", "build_diagnostic": "bootstrap_cleanup_complete",
        "container_exit_code": 0, "container_stdout_bytes": 998, "container_stderr_bytes": 0,
        "container_startup_diagnostic": None, "container_oom_killed": False, "container_start_error_present": False,
        "build_cache_scope": "shared_daemon_cache_not_pruned",
    }
    return {
        "schema_version": 3, "scope": "rclone_backend_protocol_fixture",
        "runtime": {"version": "1.76.2", "sha256": "a" * 64}, "platform": "linux", "architecture": "amd64",
        "harness_sha256": "b" * 64, "fixture_manifest_sha256": "c" * 64,
        "started_utc": "2026-10-04T11:58:00Z", "finished_utc": "2026-10-04T11:59:00Z",
        "success": True, "cleanup_passed": True, "errors": [], "native_evidence": native,
        "backends": [{"backend": "smb", "fixture_kind": "independent_samba_container",
                      "fixture_mode": "smb_samba_ntlm_read_v1", "capabilities": dict.fromkeys(CAPS, "passed"),
                      "errors": []}],
    }


def policy_and_catalog():
    original = json.loads((ROOT / "provider-coverage-policy.json").read_text())
    entry = copy.deepcopy(original["providers"]["smb"])
    catalog = C.catalog_from_schemas([{"Name": "smb", "Prefix": "smb", "Options": []}])
    entry.pop("schema_sha256_by_platform", None)
    entry["schema_sha256"] = catalog[0]["schema_sha256"]
    return {"schema_version": 2, "reviewed_runtime_version": RUNTIME["version"], "providers": {"smb": entry},
            "profiles": {entry["profile"]: copy.deepcopy(original["profiles"][entry["profile"]])}}, catalog


def replace(candidate, path, value):
    current = candidate
    for part in path[:-1]:
        current = current[part]
    current[path[-1]] = value


class SmbCoverageTests(unittest.TestCase):
    def setUp(self):
        self.policy, self.catalog = policy_and_catalog()

    def evaluate(self, receipts, **kwargs):
        arguments = {"now": NOW, "fixture_manifest_sha256": "c" * 64,
                     "smb_bindings": copy.deepcopy(BINDINGS)}
        arguments.update(kwargs)
        return C.evaluate(self.catalog, self.policy, RUNTIME, receipts, "0" * 64, **arguments)

    def assert_rejected(self, candidate, **kwargs):
        report = self.evaluate([candidate], **kwargs)
        self.assertTrue(report["errors"])
        self.assertEqual(report["providers"][0]["evidence"]["local_protocol"]["status"], "not_verified")
        self.assertIn("required_fixture_not_verified", C.gate_errors(report, require_fixtures=["smb"]))

    def test_success_meets_existing_six_obligations_and_exposes_seven_scoped_results(self):
        report = self.evaluate([literal_receipt()])
        self.assertEqual(report["errors"], [])
        evidence = report["providers"][0]["evidence"]
        self.assertEqual(evidence["local_protocol"]["status"], "passed")
        self.assertEqual(evidence["application"]["status"], "not_verified")
        self.assertNotEqual(evidence["vendor"]["status"], "passed")
        self.assertFalse(report["all_complete"])
        self.assertEqual(C.gate_errors(report, require_plans=True, require_fixtures=["smb"]), [])
        mode = evidence["local_protocol"]["modes"]["smb_samba_ntlm_read_v1"]
        self.assertEqual(mode["capabilities"], dict.fromkeys(CAPS, "passed"))
        run = mode["runs"][0]
        self.assertEqual((run["platform"], run["architecture"]), ("linux", "amd64"))
        self.assertEqual(run["source_sha256"], SOURCE)
        self.assertEqual(run["harness_sha256"], BINDINGS["harness_sha256"])
        self.assertEqual(run["samba_version"], BINDINGS["samba_version"])
        self.assertEqual(run["base_image"], BINDINGS["base_image"])
        self.assertEqual(run["image_id"], "sha256:" + "e" * 64)
        self.assertEqual(report["providers"][0]["lifecycle_applicability"], {
            "credential_renewal": "required", "connection_session_reauthentication": "required"})
        self.assertEqual(evidence["application"]["capabilities"]["refresh"], "not_verified")
        self.assertEqual(evidence["application"]["capabilities"]["reauthentication"], "not_verified")

    def test_optional_bindings_default_rejects_schema_three(self):
        self.assert_rejected(literal_receipt(), smb_bindings=None)
        with self.assertRaisesRegex(C.CoverageError, "unknown_receipt_schema"):
            C.validate_receipt(literal_receipt(), RUNTIME, "b" * 64, NOW, fixture_manifest_sha256="c" * 64)

    def test_old_feasibility_is_never_importable(self):
        self.assert_rejected(literal_receipt()["native_evidence"])
        self.assert_rejected(literal_receipt()["native_evidence"]["probe"])

    def test_schema_one_two_and_boolean_cannot_spoof_smb(self):
        for schema in (1, 2, True, 3.0, "3", 4):
            with self.subTest(schema=schema):
                candidate = literal_receipt()
                candidate["schema_version"] = schema
                self.assert_rejected(candidate)

    def test_windows_runtime_and_non_amd64_receipts_remain_unverified(self):
        windows = dict(RUNTIME, platform="windows")
        report = C.evaluate(self.catalog, self.policy, windows, [literal_receipt()], "0" * 64, now=NOW,
                            fixture_manifest_sha256="c" * 64, smb_bindings=BINDINGS)
        self.assertIn("required_fixture_not_verified", C.gate_errors(report, require_fixtures=["smb"]))
        for path, value in ((["platform"], "windows"), (["architecture"], "arm64"),
                            (["native_evidence", "probe", "runtime", "platform"], "linux/arm64")):
            with self.subTest(path=path):
                candidate = literal_receipt(); replace(candidate, path, value)
                self.assert_rejected(candidate)

    def test_complete_capability_set_remains_mandatory_under_weakened_policy(self):
        profile = next(iter(self.policy["profiles"].values()))
        profile["required"]["local_protocol"] = ["cleanup"]
        for missing in CAPS:
            with self.subTest(missing=missing):
                candidate = literal_receipt(); del candidate["backends"][0]["capabilities"][missing]
                self.assert_rejected(candidate)
        for extra in ("authentication", "refresh", "reauthentication", "cancellation", "fixture_write_rejection"):
            with self.subTest(extra=extra):
                candidate = literal_receipt(); candidate["backends"][0]["capabilities"][extra] = "passed"
                self.assert_rejected(candidate)

    def test_closed_backend_mode_kind_and_scope(self):
        for path, value in ((["backends", 0, "backend"], "sftp"),
                            (["backends", 0, "fixture_kind"], "rclone_loopback"),
                            (["backends", 0, "fixture_mode"], "smb_kerberos_v1"),
                            (["scope"], "application")):
            with self.subTest(path=path):
                candidate = literal_receipt(); replace(candidate, path, value)
                self.assert_rejected(candidate)

    def test_capability_statuses_cannot_hide_missing_auth_or_partial_results(self):
        for value in ("not_applicable", "not_run", False, 1, None, [], "failed"):
            with self.subTest(value=value):
                candidate = literal_receipt()
                candidate["backends"][0]["capabilities"]["authentication_rejection"] = value
                self.assert_rejected(candidate)
        for path, value in ((["backends"], {}), (["native_evidence"], []),
                            (["native_evidence", "probe"], []), (["runtime"], []),
                            (["errors"], ["private failure details"]),
                            (["native_evidence", "build_diagnostic"], {})):
            with self.subTest(path=path):
                candidate = literal_receipt(); replace(candidate, path, value)
                self.assert_rejected(candidate)

    def test_vendor_requirements_never_receive_protocol_credit(self):
        next(iter(self.policy["profiles"].values()))["required"]["vendor"] = [
            "authentication", "refresh", "reauthentication", "cleanup"]
        report = self.evaluate([literal_receipt()])
        self.assertEqual(report["errors"], [])
        self.assertEqual(report["providers"][0]["evidence"]["vendor"], {
            "status": "not_verified", "capabilities": dict.fromkeys(
                ("authentication", "refresh", "reauthentication", "cleanup"), "not_verified")})

    def test_mixed_backends_and_extra_scope_fields_are_rejected(self):
        candidate = literal_receipt(); candidate["backends"].append(copy.deepcopy(candidate["backends"][0]))
        self.assert_rejected(candidate)
        for path in ([], ["backends", 0], ["native_evidence"], ["native_evidence", "probe"]):
            with self.subTest(extra_at=path):
                candidate = literal_receipt(); replace(candidate, path + ["unreviewed_scope"], "private-placeholder")
                self.assert_rejected(candidate)

    def test_runtime_manifest_harness_and_all_four_source_hashes_bind(self):
        paths = [["runtime", "sha256"], ["harness_sha256"], ["fixture_manifest_sha256"],
                 ["native_evidence", "runtime", "sha256"],
                 ["native_evidence", "probe", "runtime", "rclone_sha256"],
                 ["native_evidence", "probe", "runtime", "probe_sha256"],
                 ["native_evidence", "probe", "runtime", "lock_sha256"]]
        paths += [["native_evidence", "source_sha256", name] for name in SOURCE]
        for path in paths:
            with self.subTest(path=path):
                candidate = literal_receipt(); replace(candidate, path, "9" * 64)
                self.assert_rejected(candidate)
        for path in (["runtime", "version"], ["native_evidence", "probe", "runtime", "rclone_version"]):
            candidate = literal_receipt(); replace(candidate, path, "1.76.3")
            self.assert_rejected(candidate)

    def test_base_samba_and_manifest_binding_cannot_be_substituted(self):
        for path, value in ((["native_evidence", "base_image"], "docker.io/library/debian@sha256:" + "9" * 64),
                            (["native_evidence", "probe", "runtime", "samba_version"], "4.99.0-Debian"),
                            (["native_evidence", "image_id"], "latest")):
            candidate = literal_receipt(); replace(candidate, path, value)
            self.assert_rejected(candidate)
        for key in ("harness_sha256", "fixture_manifest_sha256", "base_image", "samba_version"):
            bindings = copy.deepcopy(BINDINGS); bindings[key] = "untrusted"
            self.assert_rejected(literal_receipt(), smb_bindings=bindings)

    def test_freshness_and_bounded_duration(self):
        for path, value in ((["finished_utc"], "2026-10-05T11:59:00Z"),
                            (["started_utc"], "2026-10-04T12:01:00Z"),
                            (["started_utc"], "2026-10-04T11:00:00Z"),
                            (["finished_utc"], "2026-10-04T11:59:00")):
            candidate = literal_receipt(); replace(candidate, path, value)
            self.assert_rejected(candidate)
        self.assert_rejected(literal_receipt(), now=NOW + timedelta(days=2))

    def test_every_probe_check_and_cleanup_field_must_support_success(self):
        paths = [["native_evidence", "probe", "checks", key]
                 for key in literal_receipt()["native_evidence"]["probe"]["checks"]]
        paths += [["native_evidence", "probe", "cleanup", key] for key in
                  ("children_stopped", "listeners_closed", "temporary_removed")]
        paths += [["native_evidence", "cleanup", key] for key in
                  ("container_removed", "image_removed", "temporary_removed")]
        paths += [["native_evidence", "container_isolation_verified"], ["cleanup_passed"]]
        for path in paths:
            with self.subTest(path=path):
                candidate = literal_receipt(); replace(candidate, path, False)
                self.assert_rejected(candidate)

    def test_bool_int_confusion_and_nonzero_container_exit_rejected(self):
        for path, value in ((["success"], 1), (["cleanup_passed"], 1),
                            (["native_evidence", "container_exit_code"], False),
                            (["native_evidence", "container_exit_code"], 1),
                            (["native_evidence", "probe", "commands_total"], True),
                            (["native_evidence", "probe", "commands_total"], 15),
                            (["native_evidence", "probe", "runtime", "uid"], True),
                            (["native_evidence", "probe", "checks", "environment"], 1),
                            (["native_evidence", "container_oom_killed"], True)):
            candidate = literal_receipt(); replace(candidate, path, value)
            self.assert_rejected(candidate)

    def test_failure_is_sticky_after_later_pass_in_either_order(self):
        failed = literal_receipt()
        failed["success"] = failed["cleanup_passed"] = False
        failed["errors"] = failed["backends"][0]["errors"] = ["smb_native_run_failed"]
        failed["backends"][0]["capabilities"] = dict.fromkeys(CAPS, "failed")
        native = failed["native_evidence"]
        native["success"] = native["cleanup"]["temporary_removed"] = False
        native["errors"] = ["supervisor_cleanup_failed"]
        for sequence in ([failed, literal_receipt()], [literal_receipt(), failed]):
            report = self.evaluate(sequence)
            self.assertEqual(report["errors"], [])
            evidence = report["providers"][0]["evidence"]["local_protocol"]
            self.assertEqual(evidence["status"], "failed")
            self.assertEqual(evidence["modes"]["smb_samba_ntlm_read_v1"]["status"], "failed")
            self.assertIn("required_fixture_not_verified", C.gate_errors(report, require_fixtures=["smb"]))

    def test_private_extra_values_never_enter_the_ledger(self):
        candidate = literal_receipt(); candidate["native_evidence"]["raw_stdout"] = "private-token-placeholder"
        report = self.evaluate([candidate])
        self.assertNotIn("private-token-placeholder", json.dumps(report))
        self.assertTrue(report["errors"])

    def test_current_bindings_hash_every_fixed_file_and_shared_payload(self):
        source = ROOT / "scripts/provider-lab/smb"
        bindings = C.compute_smb_bindings(source)
        digest = hashlib.sha256()
        for name in sorted(("Dockerfile", "build-lock.json", "probe_samba.py", "run_container.py", "protocol_evidence.py")):
            digest.update(name.encode() + b"\0" + (source / name).read_bytes() + b"\0")
        self.assertEqual(bindings["harness_sha256"], digest.hexdigest())
        self.assertEqual(bindings["fixture_manifest_sha256"],
                         C.compute_fixture_manifest_sha256(ROOT / "scripts/provider-lab"))
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary)
            for name in ("Dockerfile", "build-lock.json", "probe_samba.py", "run_container.py", "protocol_evidence.py"):
                shutil.copyfile(source / name, copied / name)
            for name in ("Dockerfile", "build-lock.json", "probe_samba.py", "run_container.py", "protocol_evidence.py"):
                path = copied / name; original = path.read_bytes()
                path.write_bytes(original + (b"\n " if name == "build-lock.json" else b"\n# reviewed source drift\n"))
                changed = C.compute_smb_bindings(copied)
                self.assertNotEqual(changed["harness_sha256"], bindings["harness_sha256"])
                path.write_bytes(original)

    def test_cli_computes_current_smb_bindings_and_uses_linux_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); policy = root / "policy.json"; receipt = root / "receipt.json"
            output = root / "ledger.json"
            policy.write_text(json.dumps(self.policy)); receipt.write_text(json.dumps(literal_receipt()))
            with patch.object(C, "query_runtime", return_value=(RUNTIME, self.catalog)), \
                    patch.object(C, "compute_harness_sha256", return_value="0" * 64), \
                    patch.object(C, "compute_fixture_manifest_sha256", return_value="c" * 64), \
                    patch.object(C, "compute_smb_bindings", return_value=BINDINGS) as bind, \
                    patch.object(C, "datetime", wraps=datetime) as clock, \
                    contextlib.redirect_stdout(io.StringIO()):
                clock.now.return_value = NOW
                status = C.main(["--rclone", str(root / "unused"), "--policy", str(policy), "--report", str(output),
                                 "--fixture-receipt", str(receipt), "--require-plans", "--require-fixtures", "smb"])
            self.assertEqual(status, 0)
            bind.assert_called_once_with(ROOT / "scripts/provider-lab/smb")
            self.assertEqual(json.loads(output.read_text())["providers"][0]["evidence"]["local_protocol"]["status"], "passed")


if __name__ == "__main__":
    unittest.main()
