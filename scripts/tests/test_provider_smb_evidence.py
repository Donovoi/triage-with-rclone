"""Pure/mocked evidence checks; never runs Docker, Samba or rclone."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).parents[1] / "provider-lab" / "smb"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


E = load("smb_evidence", "protocol_evidence.py")
S = load("smb_supervisor_evidence", "run_container.py")
BINDINGS = E.compute_bindings(ROOT.absolute())
RUNTIME = {"version": "99.88.77", "sha256": "a" * 64}
NOW = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)


def native():
    return {
        "schema_version": 1, "scope": "smb_samba_container_feasibility_only", "ledger_eligible": False,
        "success": True, "runtime": dict(RUNTIME), "source_sha256": dict(BINDINGS["source_sha256"]),
        "base_image": BINDINGS["base_image"], "image_id": "sha256:" + "b" * 64,
        "container_isolation_verified": True, "errors": [],
        "cleanup": {"container_removed": True, "image_removed": True, "temporary_removed": True},
        "stage": "completed", "build_phase": "manifest", "build_diagnostic": "bootstrap_cleanup_complete",
        "container_exit_code": 0, "container_stdout_bytes": 1000, "container_stderr_bytes": 0,
        "container_startup_diagnostic": None, "container_oom_killed": False, "container_start_error_present": False,
        "build_cache_scope": "shared_daemon_cache_not_pruned",
        "probe": {"schema_version": 1, "scope": "smb_samba_feasibility_only", "status": "passed", "ledger_eligible": False,
                  "commands_total": 16, "errors": [],
                  "runtime": {"platform": "linux/amd64", "uid": 10001, "gid": 10001,
                              "samba_version": BINDINGS["samba_version"], "rclone_version": RUNTIME["version"],
                              "smbd_sha256": "c" * 64, "rclone_sha256": RUNTIME["sha256"],
                              "probe_sha256": BINDINGS["source_sha256"]["probe_samba.py"],
                              "lock_sha256": BINDINGS["source_sha256"]["build-lock.json"]},
                  "checks": dict.fromkeys(("environment", "version_binding", "config_validation", "good_listing_before",
                                            "good_downloads_before", "bad_password_rejected", "good_listing_after",
                                            "good_downloads_after", "missing_rejected", "source_preserved",
                                            "config_preserved", "seed_preserved"), True),
                  "cleanup": {"children_stopped": True, "listeners_closed": True, "temporary_removed": True}},
    }


def receipt(value=None, source_errors=None):
    return S.protocol_result(value or native(), E, BINDINGS, "2026-10-04T11:59:00Z", "2026-10-04T12:00:00Z", source_errors or [])


def validate(value, *, runtime=None, now=NOW, max_age_hours=24):
    return E.validate_evidence(value, runtime or RUNTIME, BINDINGS["harness_sha256"], BINDINGS["fixture_manifest_sha256"],
                               BINDINGS["source_sha256"], now, max_age_hours,
                               expected_base_image=BINDINGS["base_image"], expected_samba_version=BINDINGS["samba_version"])


class ContractTests(unittest.TestCase):
    def test_exact_pass_and_coverage_runtime_with_platform(self):
        self.assertIsNone(validate(receipt()))
        self.assertIsNone(validate(receipt(), runtime={**RUNTIME, "platform": "linux"}))
        self.assertFalse(receipt()["native_evidence"]["ledger_eligible"])
        self.assertFalse(receipt()["native_evidence"]["probe"]["ledger_eligible"])
        self.assertEqual(set(receipt()["backends"][0]["capabilities"]), {
            "listing", "download_hash", "missing_object_rejection", "authentication_rejection",
            "source_preservation", "config_preservation", "cleanup"})

    def test_extra_or_missing_keys_are_rejected_at_every_closed_level(self):
        selectors = [lambda r: r, lambda r: r["runtime"], lambda r: r["backends"][0],
                     lambda r: r["backends"][0]["capabilities"], lambda r: r["native_evidence"],
                     lambda r: r["native_evidence"]["runtime"], lambda r: r["native_evidence"]["source_sha256"],
                     lambda r: r["native_evidence"]["cleanup"], lambda r: r["native_evidence"]["probe"],
                     lambda r: r["native_evidence"]["probe"]["runtime"], lambda r: r["native_evidence"]["probe"]["checks"],
                     lambda r: r["native_evidence"]["probe"]["cleanup"]]
        for index, select in enumerate(selectors):
            for extra in (True, False):
                with self.subTest(index=index, extra=extra):
                    value = receipt()
                    obj = select(value)
                    if extra:
                        obj["unapproved"] = True
                    else:
                        del obj[next(iter(obj))]
                    with self.assertRaises(ValueError):
                        validate(value)

    def test_modes_runtime_manifest_source_and_image_substitutions_fail(self):
        changes = [(["schema_version"], True), (["schema_version"], 1), (["scope"], "vendor_acceptance"),
                   (["platform"], "windows"), (["architecture"], "arm64"), (["harness_sha256"], "0" * 64),
                   (["fixture_manifest_sha256"], "0" * 64), (["runtime", "version"], "1.75.1"),
                   (["native_evidence", "runtime", "sha256"], "0" * 64),
                   (["native_evidence", "base_image"], "debian:latest"), (["native_evidence", "image_id"], "mutable:tag"),
                   (["native_evidence", "container_isolation_verified"], 1),
                   (["native_evidence", "probe", "runtime", "samba_version"], "0.0.0"),
                   (["native_evidence", "probe", "runtime", "uid"], True),
                   (["native_evidence", "probe", "runtime", "lock_sha256"], "0" * 64),
                   (["native_evidence", "probe", "runtime", "probe_sha256"], "0" * 64)]
        for path, changed in changes:
            with self.subTest(path=path):
                value, target = receipt(), None
                target = value
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = changed
                with self.assertRaises(ValueError):
                    validate(value)
        for key, changed in (("backend", "pcloud"), ("fixture_kind", "vendor"), ("fixture_mode", "fresh_login")):
            value = receipt()
            value["backends"][0][key] = changed
            with self.assertRaises(ValueError):
                validate(value)

    def test_every_probe_observation_and_both_cleanup_maps_are_required(self):
        for where in (("probe", "checks"), ("probe", "cleanup"), ("cleanup",)):
            target = native()
            for part in where:
                target = target[part]
            for name in target:
                for changed in (False, 1, None):
                    with self.subTest(where=where, name=name, changed=changed):
                        value = receipt()
                        obj = value["native_evidence"]
                        for part in where:
                            obj = obj[part]
                        obj[name] = changed
                        with self.assertRaises(ValueError):
                            validate(value)

    def test_counts_diagnostics_and_unsafe_errors_fail_closed(self):
        for changed in (True, 0, 15, 17, 21):
            value = receipt()
            value["native_evidence"]["probe"]["commands_total"] = changed
            with self.assertRaises(ValueError):
                validate(value)
        for field, changed in (("container_exit_code", False), ("container_stdout_bytes", True),
                               ("container_stdout_bytes", 0), ("container_stderr_bytes", 5000000),
                               ("container_oom_killed", True), ("container_start_error_present", True),
                               ("container_startup_diagnostic", "private account"), ("build_diagnostic", "private_value")):
            value = receipt()
            value["native_evidence"][field] = changed
            with self.assertRaises(ValueError):
                validate(value)
        value = receipt()
        value["native_evidence"]["errors"] = ["token=private"]
        with self.assertRaises(ValueError):
            validate(value)

    def test_freshness_duration_and_strict_utc(self):
        for start, finish in (("2026-10-04T12:00:00Z", "2026-10-04T12:00:01Z"),
                              ("2026-10-04T12:00:00Z", "2026-10-04T11:59:59Z"),
                              ("2026-10-04T11:29:59Z", "2026-10-04T12:00:00Z"),
                              ("2026-10-03T11:58:59Z", "2026-10-03T11:59:59Z"),
                              ("2026-10-04T11:59:00", "2026-10-04T12:00:00Z"),
                              ("2026-10-04T11:59:00.1Z", "2026-10-04T12:00:00Z")):
            value = receipt()
            value.update(started_utc=start, finished_utc=finish)
            with self.assertRaises(ValueError):
                validate(value)
        self.assertIsNone(validate(receipt(), now=NOW + timedelta(hours=168), max_age_hours=168))
        for age in (True, 0, 169, 1.5):
            with self.assertRaises(ValueError):
                validate(receipt(), max_age_hours=age)

    def test_failed_cleanup_and_early_build_failure_remain_all_failed(self):
        value = native()
        value.update(success=False, errors=["temporary_cleanup_failed"])
        value["cleanup"]["temporary_removed"] = False
        failed = receipt(value)
        self.assertIsNone(validate(failed))
        self.assertFalse(failed["cleanup_passed"])
        self.assertEqual(set(failed["backends"][0]["capabilities"].values()), {"failed"})
        early = native()
        early.update(success=False, errors=["docker_command_failed"], stage="build", build_phase="install",
                     build_diagnostic="install_apt_failed", probe=None, image_id=None, container_isolation_verified=False,
                     container_exit_code=None, container_stdout_bytes=None, container_stderr_bytes=None,
                     container_oom_killed=None, container_start_error_present=None)
        self.assertIsNone(validate(receipt(early)))
        for field in ("success", "cleanup_passed"):
            corrupt = copy.deepcopy(failed)
            corrupt[field] = True
            with self.assertRaises(ValueError):
                validate(corrupt)
        failed["backends"][0]["capabilities"]["listing"] = "passed"
        with self.assertRaises(ValueError):
            validate(failed)

    def test_source_failure_cannot_promote_pass_and_no_offline_receipts(self):
        self.assertIsNone(validate(receipt(source_errors=["smb_source_changed"])))
        with self.assertRaises(ValueError):
            validate(native())
        for value in ([], [receipt()["backends"][0]] * 2):
            item = receipt()
            item["backends"] = value
            with self.assertRaises(ValueError):
                validate(item)
        for status in ("not_applicable", "verified", True):
            item = receipt()
            item["backends"][0]["capabilities"]["listing"] = status
            with self.assertRaises(ValueError):
                validate(item)


class BindingTests(unittest.TestCase):
    def test_contract_loader_uses_source_without_bytecode_cache_or_execution(self):
        with mock.patch("importlib.machinery.SourceFileLoader.exec_module", side_effect=AssertionError("bytecode loader forbidden")), \
                mock.patch.object(S.subprocess, "Popen", side_effect=AssertionError("native execution forbidden")):
            contract = S.load_protocol_contract()
        self.assertEqual(contract.MODE, E.MODE)
        self.assertEqual(contract.compute_harness_sha256(ROOT.absolute()), E.compute_harness_sha256(ROOT.absolute()))

    def test_harness_exact_framing_and_independent_fixture_manifest(self):
        digest = hashlib.sha256()
        for name in sorted(("Dockerfile", "build-lock.json", "probe_samba.py", "run_container.py", "protocol_evidence.py")):
            digest.update(name.encode() + b"\0" + (ROOT / name).read_bytes() + b"\0")
        self.assertEqual(E.compute_harness_sha256(ROOT.absolute()), digest.hexdigest())
        files = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
                 "nested/space name.txt": b"Nested synthetic payload.\n", "nested/bytes.bin": bytes(range(256)) * 8}
        manifest = [{"path": name, "size": len(body), "sha256": hashlib.sha256(body).hexdigest()}
                    for name, body in sorted(files.items())]
        self.assertEqual(E.compute_fixture_manifest_sha256(ROOT.absolute()),
                         hashlib.sha256(json.dumps(manifest, separators=(",", ":")).encode()).hexdigest())

    def test_regular_file_bounds_and_source_change_are_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source"
            path.write_bytes(b"synthetic")
            self.assertEqual(E.file_bytes(path), b"synthetic")
            with self.assertRaises(ValueError):
                E.file_bytes(Path(directory))
            with self.assertRaises(ValueError):
                E.file_bytes(Path("relative"))
            with mock.patch.object(E.os, "fstat", return_value=path.parent.stat()):
                with self.assertRaisesRegex(ValueError, "smb_source_changed"):
                    E.file_bytes(path)
            path.write_bytes(b"x" * (1024 * 1024 + 1))
            with self.assertRaises(ValueError):
                E.file_bytes(path)


class ProducerTests(unittest.TestCase):
    def execute(self, *, evidence=True, bad_probe=False, bad_cleanup=False, changed_sources=False, invalid_wrapper=False):
        with tempfile.TemporaryDirectory() as directory:
            binary, output = Path(directory) / "synthetic", Path(directory) / "result.json"
            binary.write_bytes(b"never executed")
            trace = []
            probe = native()["probe"]
            if bad_probe:
                probe["status"] = "failed"
                probe["checks"]["good_listing_before"] = False
                probe["errors"] = ["listing_mismatch"]
            docker = mock.Mock(build_phase="manifest", build_diagnostic="bootstrap_cleanup_complete", last_stderr=b"")
            def command(args, **kwargs):
                trace.append(args[0])
                docker.last_stderr = b""
                if args[0] == "info":
                    return 0, b'{"OSType":"linux","Architecture":"amd64"}'
                if args[0] == "build":
                    Path(args[args.index("--iidfile") + 1]).write_text("sha256:" + "b" * 64)
                if args[0] == "start":
                    return int(bad_probe), json.dumps(probe).encode()
                return 0, b""
            def inspect(kind, target):
                if kind == "image":
                    return {"Architecture": "amd64", "Os": "linux", "Config": {"Labels": {
                        S.LABEL: "1" * 32, S.KIND: "smb-probe"}}}
                return {"State": {"Running": False, "ExitCode": int(bad_probe), "OOMKilled": False, "Error": ""}}
            def cleanup(*args):
                trace.append("owned_cleanup")
                if bad_cleanup:
                    raise S.SupervisorError("supervisor_cleanup_failed")
                return {"container_removed": True, "image_removed": True}
            times = iter(("2026-10-04T11:59:00Z", "2026-10-04T12:00:00Z"))
            def timestamp():
                trace.append("timestamp")
                return next(times)
            updated = dict(BINDINGS, harness_sha256="0" * 64) if changed_sources else BINDINGS
            docker.run.side_effect, docker.inspect.side_effect = command, inspect
            real_protocol_result = S.protocol_result
            def wrap(*args):
                value = real_protocol_result(*args)
                if invalid_wrapper:
                    value["backends"][0]["capabilities"]["fresh_authentication"] = "passed"
                return value
            with mock.patch.object(S.sys, "platform", "linux"), \
                    mock.patch.dict(S.os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}), \
                    mock.patch.object(S, "runtime_identity", return_value=RUNTIME), \
                    mock.patch.object(S, "digest", side_effect=lambda path: RUNTIME["sha256"] if Path(path).name in ("rclone", "synthetic")
                                      else hashlib.sha256(Path(path).read_bytes()).hexdigest()), \
                    mock.patch.object(S.uuid, "uuid4", return_value=mock.Mock(hex="1" * 32)), \
                    mock.patch.object(S, "Docker", return_value=docker), mock.patch.object(S, "validate_container") as isolation, \
                    mock.patch.object(S, "cleanup_owned", side_effect=cleanup), mock.patch.object(S, "utc_now", side_effect=timestamp), \
                    mock.patch.object(S, "load_protocol_contract", return_value=E), \
                    mock.patch.object(E, "compute_bindings", side_effect=[BINDINGS, updated]) as bind, \
                    mock.patch.object(S, "datetime") as clock, mock.patch.object(S, "protocol_result", side_effect=wrap):
                clock.now.return_value = NOW
                if invalid_wrapper:
                    with self.assertRaises(ValueError):
                        S.run(binary, output, protocol_evidence=evidence)
                    self.assertFalse(output.exists())
                    self.assertIn("owned_cleanup", trace)
                    return None
                result = S.run(binary, output, protocol_evidence=evidence)
                self.assertEqual(json.loads(output.read_text()), result)
                self.assertEqual(bind.call_count, 2 if evidence else 0)
                self.assertEqual(isolation.call_count, 2)
            self.assertEqual(trace.count("start"), 1)
            self.assertEqual(trace.count("build"), 1)
            if evidence:
                self.assertLess(trace.index("timestamp"), trace.index("start"))
                self.assertGreater(len(trace) - 1 - trace[::-1].index("timestamp"), trace.index("owned_cleanup"))
                self.assertIsNone(validate(result))
            return result

    def test_fresh_supervisor_run_emits_valid_wrapper_only_after_cleanup(self):
        result = self.execute()
        self.assertTrue(result["success"])
        self.assertEqual(result["native_evidence"]["probe"]["commands_total"], 16)

    def test_failed_native_cleanup_and_source_changes_cannot_emit_pass(self):
        for option in ("bad_probe", "bad_cleanup", "changed_sources"):
            with self.subTest(option=option):
                result = self.execute(**{option: True})
                self.assertFalse(result["success"])
                self.assertEqual(set(result["backends"][0]["capabilities"].values()), {"failed"})

    def test_wrapper_is_self_validated_before_publication(self):
        self.execute(invalid_wrapper=True)

    def test_default_native_supervisor_still_emits_ineligible_schema1(self):
        result = self.execute(evidence=False)
        self.assertEqual(result["schema_version"], 1)
        self.assertFalse(result["ledger_eligible"])
        self.assertNotIn("backends", result)

    def test_cli_opt_in_starts_run_and_default_remains_feasibility(self):
        args = ["supervisor", "--rclone", "synthetic", "--report", "new.json"]
        for evidence in (False, True):
            with mock.patch.object(S.sys, "argv", args + (["--protocol-evidence"] if evidence else [])), \
                    mock.patch.object(S, "run", return_value=receipt() if evidence else native()) as run, \
                    mock.patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(S.main(), 0)
                self.assertEqual(run.call_args.kwargs, {"protocol_evidence": True} if evidence else {})
                self.assertEqual(json.loads(output.getvalue())["ledger_eligible"], evidence)
        with mock.patch.object(S.sys, "argv", args + ["--convert-receipt", "old.json"]), \
                mock.patch("sys.stderr", new_callable=io.StringIO), mock.patch.object(S, "run") as run:
            with self.assertRaises(SystemExit):
                S.main()
            run.assert_not_called()

