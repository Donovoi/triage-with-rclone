"""Offline lifecycle/failure tests; no metadata worker, Docker or Maven runs."""
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import hosted_kerberos_discovery as H


CANDIDATE = {"pom.xml": "1" * 64, "settings.xml": "2" * 64,
             "global-settings.xml": "3" * 64}
SOURCES = {"hosted_kerberos_discovery.py": "4" * 64, "verify_bootstrap.py": "5" * 64}
CANARY = "PRIVATE_SYNTHETIC_CANARY"


def discovery():
    return dict(success=True, errors=[], mode="online", ledger_eligible=False,
                daemon_accepted=False, offline_reproduced=False, cache_preparation=None,
                inputs={"candidate_profile": "kerberos", "candidate_sha256": dict(CANDIDATE),
                        "seed_cache": None}, manifest={"synthetic": "bounded graph"},
                cleanup=dict(container_removed=True, image_removed=True, context_removed=True))


class FakeLease:
    def __init__(self, name, events, root, failure=None):
        self.name, self.events, self.root, self.failure = name, events, root, failure
        self.paths = tuple(root / name for name in ("manifest", "config", "recipe"))
        self.material = {"synthetic": "verified material"}
        self.entered = self.exited = False
        self.report = dict(success=False, errors=[], ledger_eligible=False,
                           cleanup=dict(children_stopped=True, temporary_removed=True))

    def __enter__(self):
        self.events.append(self.name + "_enter")
        self.entered = True
        if self.failure == "enter":
            kind = H.J.MetadataError if self.name == "metadata" else H.B.MaterialError
            raise kind(CANARY)
        return self

    def __exit__(self, kind, error, traceback):
        self.events.append(self.name + "_exit")
        self.exited = True
        self.report["success"] = kind is None and self.failure is None
        if self.failure in {"children", "temporary"}:
            key = "children_stopped" if self.failure == "children" else "temporary_removed"
            self.report["cleanup"][key] = False
        if self.failure == "raised_exit":
            self.report["cleanup"]["temporary_removed"] = False
            raise RuntimeError(CANARY)
        return False


class HostedKerberosTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.sequence = 0
        self.no_native = patch.object(H.D.subprocess, "Popen", side_effect=AssertionError("native forbidden"))
        self.popen = self.no_native.start()
        self.addCleanup(self.no_native.stop)
        self.addCleanup(self.popen.assert_not_called)

    def invoke(self, *, result=None, failure=None, metadata_failure=None, bootstrap_failure=None,
               guard_error=None, candidate_error=None, candidate_after=None, sources_after=None,
               replace_root=False, remove_failure=False):
        self.sequence += 1
        output = self.root / ("owned-%02d" % self.sequence)
        events = []
        metadata = FakeLease("metadata", events, self.root, metadata_failure)
        bootstrap = FakeLease("bootstrap", events, self.root, bootstrap_failure)
        chosen = discovery() if result is None else result
        candidate_calls = source_calls = 0
        def candidate_binding(candidate):
            nonlocal candidate_calls
            self.assertEqual(candidate, self.root / "candidate")
            events.append("candidate")
            candidate_calls += 1
            if candidate_error:
                raise candidate_error
            return dict(candidate_after if candidate_calls > 1 and candidate_after is not None else CANDIDATE)
        def source_binding(verifier):
            nonlocal source_calls
            self.assertEqual(verifier, self.root / "verify_bootstrap.py")
            events.append("sources")
            source_calls += 1
            return dict(sources_after if source_calls > 1 and sources_after is not None else SOURCES)
        def mkdir(**kwargs):
            self.assertEqual(kwargs, {"prefix": "hdfs-kerberos-discovery-", "dir": "/tmp"})
            output.mkdir()
            (output / "private.log").write_text(CANARY)
            events.append("raw_root")
            return str(output)
        def bootstrap_factory(*args):
            self.assertTrue(metadata.entered and not metadata.exited)
            self.assertEqual(args, (self.root / "verify_bootstrap.py", *metadata.paths))
            return bootstrap
        def discover(*args, **kwargs):
            events.append("discover")
            self.assertTrue(metadata.entered and bootstrap.entered)
            self.assertFalse(metadata.exited or bootstrap.exited)
            self.assertEqual(args, (self.root / "candidate", bootstrap.material,
                                    bootstrap.root / "maven.tar.gz", output))
            self.assertEqual(kwargs, {"candidate_profile": "kerberos"})
            if replace_root:
                output.rename(output.with_name(output.name + "-original"))
                output.mkdir()
                (output / "foreign.txt").write_text("FOREIGN_SYNTHETIC")
            if failure:
                raise failure
            return copy.deepcopy(chosen)
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(H.D, "hosted_guard", side_effect=guard_error))
            stack.enter_context(patch.object(H, "candidate_binding", side_effect=candidate_binding))
            stack.enter_context(patch.object(H, "source_bindings", side_effect=source_binding))
            stack.enter_context(patch.object(H.J, "JdkMetadataLease", return_value=metadata))
            stack.enter_context(patch.object(H.B, "BootstrapLease", side_effect=bootstrap_factory))
            stack.enter_context(patch.object(H.tempfile, "mkdtemp", side_effect=mkdir))
            stack.enter_context(patch.object(H.stat, "S_IMODE", return_value=0o700))
            stack.enter_context(patch.object(H.os, "getuid", return_value=self.root.stat().st_uid, create=True))
            native = stack.enter_context(patch.object(H.D, "discover", side_effect=discover))
            if remove_failure:
                stack.enter_context(patch.object(H.shutil, "rmtree", side_effect=OSError(CANARY)))
            report = H.run(self.root / "candidate", self.root / "verify_bootstrap.py")
        self.assertNotIn(CANARY, json.dumps(report))
        self.assertLessEqual(native.call_count, 1)
        return report, output, events

    def test_success_has_one_online_call_after_both_inputs_and_before_lease_exits(self):
        report, output, events = self.invoke()
        self.assertEqual(events, ["candidate", "sources", "metadata_enter", "bootstrap_enter",
                                  "raw_root", "discover", "bootstrap_exit", "metadata_exit",
                                  "sources", "candidate"])
        self.assertIs(report["success"], True)
        self.assertFalse(output.exists())
        self.assertEqual(report["scope"], "hdfs_kerberos_dependency_discovery")
        self.assertEqual(report["candidate_sha256"], CANDIDATE)
        self.assertEqual(report["source_sha256"], SOURCES)
        self.assertTrue(report["metadata"]["success"] and report["bootstrap"]["success"])
        for key in ("ledger_eligible", "authentication_verified", "daemon_accepted", "provider_accepted",
                    "application_accepted", "vendor_accepted", "offline_reproduced",
                    "vulnerability_audited", "publisher_audit_completed"):
            self.assertIs(report[key], False)
        self.assertIsNotNone(report["finished_utc"])
        self.assertGreaterEqual(report["duration_seconds"], 0)

    def test_host_and_candidate_rejection_precede_all_leases_or_native(self):
        for change in ({"guard_error": RuntimeError(CANARY)}, {"candidate_error": ValueError(CANARY)}):
            with self.subTest(change=next(iter(change))):
                report, output, events = self.invoke(**change)
                self.assertEqual(report["errors"], ["preflight_failed"])
                self.assertFalse(report["success"] or output.exists())
                self.assertNotIn("metadata_enter", events)
                self.assertNotIn("discover", events)

    def test_lease_acquisition_failure_prevents_discovery(self):
        for kind in ("metadata", "bootstrap"):
            with self.subTest(kind=kind):
                report, output, events = self.invoke(**{kind + "_failure": "enter"})
                self.assertFalse(report["success"] or output.exists())
                self.assertEqual(report["errors"], [kind + "_failed"])
                self.assertNotIn("discover", events)
                if kind == "bootstrap": self.assertIn("metadata_exit", events)

    def test_each_late_lease_cleanup_failure_blocks_success_and_preserves_raw(self):
        for kind in ("metadata", "bootstrap"):
            for failure in ("children", "temporary", "raised_exit"):
                with self.subTest(kind=kind, failure=failure):
                    report, output, _ = self.invoke(**{kind + "_failure": failure})
                    self.assertFalse(report["success"])
                    self.assertTrue(output.exists())
                    self.assertIn("raw_cleanup_unconfirmed", report["errors"])

    def test_failed_discovery_with_proven_cleanup_removes_only_owned_raw_data(self):
        failed = discovery(); failed.update(success=False, errors=["container_failed"])
        report, output, _ = self.invoke(result=failed)
        self.assertFalse(report["success"] or output.exists())
        self.assertEqual(report["errors"], ["discovery_failed"])
        self.assertEqual(report["cleanup"], {"raw_evidence_removed": True})

    def test_unreturned_and_interrupted_discovery_preserve_raw_and_exit_both_leases(self):
        for failure in (RuntimeError(CANARY), KeyboardInterrupt(), H.D.DiscoveryError("command_cleanup_failed")):
            with self.subTest(kind=type(failure).__name__):
                report, output, events = self.invoke(failure=failure)
                self.assertFalse(report["success"])
                self.assertTrue(output.exists())
                self.assertIn("raw_cleanup_unconfirmed", report["errors"])
                self.assertIn("bootstrap_exit", events); self.assertIn("metadata_exit", events)
                if isinstance(failure, KeyboardInterrupt):
                    self.assertIn("preparation_interrupted", report["errors"])

    def test_discovery_cleanup_cannot_be_missing_false_numeric_or_have_live_child(self):
        for change in ("missing", "false", "numeric", "malformed", "command", "cache"):
            with self.subTest(change=change):
                value = discovery()
                if change == "missing": value.pop("cleanup")
                elif change == "false": value["cleanup"]["container_removed"] = False
                elif change == "numeric": value["cleanup"]["image_removed"] = 1
                elif change == "malformed": value["errors"] = None
                else: value["errors"] = [change + "_cleanup_failed"]
                report, output, _ = self.invoke(result=value)
                self.assertFalse(report["success"])
                self.assertTrue(output.exists())

    def test_wrong_profile_cache_mode_or_input_binding_never_qualifies(self):
        for change in ("profile", "inputs", "offline", "cache", "seed", "ledger", "daemon", "false_offline"):
            with self.subTest(change=change):
                value = discovery()
                if change == "profile": value["inputs"]["candidate_profile"] = "hdfs"
                elif change == "inputs": value["inputs"]["candidate_sha256"]["pom.xml"] = "9" * 64
                elif change == "offline": value["mode"] = "offline"
                elif change == "cache": value["cache_preparation"] = {"success": True}
                elif change == "seed": value["inputs"]["seed_cache"] = {"success": True}
                else: value[{"ledger": "ledger_eligible", "daemon": "daemon_accepted",
                             "false_offline": "offline_reproduced"}[change]] = True
                report, output, _ = self.invoke(result=value)
                self.assertFalse(report["success"] or output.exists())
                self.assertIn("discovery_failed", report["errors"])

    def test_late_source_or_candidate_change_is_sticky(self):
        for kind, replacement in (("sources", {**SOURCES, "verify_bootstrap.py": "6" * 64}),
                                  ("candidate", {**CANDIDATE, "pom.xml": "6" * 64})):
            with self.subTest(kind=kind):
                report, output, _ = self.invoke(**{kind + "_after": replacement})
                self.assertFalse(report["success"] or output.exists())
                self.assertIn("source_changed" if kind == "sources" else "candidate_changed", report["errors"])

    def test_replaced_root_is_not_deleted(self):
        report, output, _ = self.invoke(replace_root=True)
        self.assertFalse(report["success"])
        self.assertEqual((output / "foreign.txt").read_text(), "FOREIGN_SYNTHETIC")
        self.assertTrue(output.with_name(output.name + "-original").exists())
        self.assertIn("raw_cleanup_failed", report["errors"])

    def test_raw_removal_failure_stays_failed(self):
        report, output, _ = self.invoke(remove_failure=True)
        self.assertFalse(report["success"])
        self.assertTrue(output.exists())
        self.assertIn("raw_cleanup_failed", report["errors"])

    def test_candidate_hash_binds_returned_bytes_not_only_prior_file_check(self):
        body = {"pom.xml": b"synthetic"}
        expected = {"pom.xml": hashlib.sha256(b"synthetic").hexdigest()}
        with patch.object(H.D, "candidate_inputs", return_value=body) as inputs, \
                patch.object(H.D, "candidate_hashes", return_value=expected):
            self.assertEqual(H.candidate_binding(self.root), expected)
            inputs.assert_called_once_with(self.root, "kerberos")
            body["pom.xml"] = b"changed after original check"
            with self.assertRaisesRegex(ValueError, "^candidate_invalid$"):
                H.candidate_binding(self.root)

    def test_source_binding_rejects_changed_verifier_and_hashes_helper_closure(self):
        verifier = self.root / "verify_bootstrap.py"; verifier.write_bytes(b"synthetic verifier")
        expected = hashlib.sha256(verifier.read_bytes()).hexdigest()
        with patch.object(H.B, "VERIFIER_SHA256", expected):
            hashes = H.source_bindings(verifier)
            self.assertEqual(set(hashes), {"hosted_kerberos_discovery.py", "verify_bootstrap.py",
                "bootstrap_material.py", "jdk_metadata.py", "resolver_discovery.py", "run_discovery.py",
                "graph_export.py", "offline_cache.py"})
            verifier.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "^source_invalid$"):
                H.source_bindings(verifier)

    def test_cli_exclusive_report_restores_sigterm_and_has_no_offline_options(self):
        output = self.root / "report.json"
        args = ["--candidate", "synthetic", "--verifier", "synthetic", "--report", str(output)]
        previous = object()
        with patch.object(H.signal, "getsignal", return_value=previous), \
                patch.object(H.signal, "signal") as signals, \
                patch.object(H, "run", return_value={"success": True, **H.FALSE_CLAIMS}) as run:
            self.assertEqual(H.main(args), 0)
            original = output.read_bytes()
            with contextlib.redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(H.main(args), 1)
            self.assertEqual(stdout.getvalue(), "report_create_failed\n")
            self.assertEqual(output.read_bytes(), original)
            self.assertEqual(run.call_count, 1)
            with self.assertRaises(KeyboardInterrupt): signals.call_args_list[0].args[1](H.signal.SIGTERM, None)
            self.assertEqual(signals.call_args_list[-1].args, (H.signal.SIGTERM, previous))
        for option in ("--mode", "--seed-cache", "--cache-destination"):
            with patch.object(H, "run") as run, contextlib.redirect_stderr(io.StringIO()) as stderr:
                with self.assertRaises(SystemExit) as error: H.main([*args, option, CANARY])
            self.assertEqual(error.exception.code, 2)
            self.assertEqual(stderr.getvalue(), "arguments_invalid\n")
            run.assert_not_called()

    def test_report_write_failure_is_static_and_cannot_return_success(self):
        output = self.root / "failed-report.json"
        with patch.object(H, "run", side_effect=RuntimeError(CANARY)), \
                contextlib.redirect_stdout(io.StringIO()) as stdout:
            code = H.main(["--candidate", "synthetic", "--verifier", "synthetic", "--report", str(output)])
        self.assertEqual(code, 1)
        self.assertEqual(stdout.getvalue(), "report_write_failed\n")
        self.assertNotIn(CANARY.encode(), output.read_bytes())


if __name__ == "__main__":
    unittest.main()
