"""Integration lifecycle tests with a fake lease and no native subprocesses."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run_discovery as R


class FakeLease:
    def __init__(self, root, failure=None):
        self.root, self.failure = root, failure
        self.material = {"schema_version": 2}
        self.report = {"success": False, "ledger_eligible": False, "errors": []}

    def __enter__(self):
        if self.failure == "enter":
            raise ValueError("PRIVATE_SYNTHETIC_CANARY")
        return self

    def __exit__(self, *args):
        self.report["success"] = self.failure != "cleanup"
        return False


def discovery_result():
    return {"success": True, "ledger_eligible": False, "errors": [],
            "cleanup": {"container_removed": True, "image_removed": True, "context_removed": True}}


class LifecycleTests(unittest.TestCase):
    def invoke(self, root, result=None, error=None, lease_failure=None):
        output = root / "owned-output"
        output.mkdir()
        (output / "private.log").write_text("PRIVATE_SYNTHETIC_CANARY")
        fake = FakeLease(root, lease_failure)
        def discover(*args):
            self.assertFalse(fake.report["success"])
            if error:
                raise error
            return copy.deepcopy(result if result is not None else discovery_result())
        with patch.object(R.D, "hosted_guard"), patch.object(R.tempfile, "mkdtemp", return_value=str(output)), \
                patch.object(R.stat, "S_IMODE", return_value=0o700), \
                patch.object(R.B, "BootstrapLease", return_value=fake), \
                patch.object(R.D, "discover", side_effect=discover), \
                patch.object(R.D.subprocess, "Popen", side_effect=AssertionError("native forbidden")) as popen:
            report = R.run(root, root, root, root, root)
        popen.assert_not_called()
        self.assertNotIn("PRIVATE_SYNTHETIC_CANARY", str(report))
        return report, output

    def test_success_requires_lease_exit_and_raw_cleanup(self):
        with tempfile.TemporaryDirectory() as temp:
            report, output = self.invoke(Path(temp))
            self.assertTrue(report["success"])
            self.assertFalse(output.exists())
            self.assertTrue(report["bootstrap"]["success"])
            self.assertTrue(report["cleanup"]["raw_evidence_removed"])
            self.assertFalse(report["ledger_eligible"])
            self.assertFalse(report["daemon_accepted"])

    def test_failed_lease_cleanup_prevents_success(self):
        with tempfile.TemporaryDirectory() as temp:
            report, output = self.invoke(Path(temp), lease_failure="cleanup")
            self.assertFalse(report["success"])
            self.assertFalse(report["bootstrap"]["success"])
            self.assertFalse(output.exists())

    def test_acquisition_failure_does_not_claim_discovery(self):
        with tempfile.TemporaryDirectory() as temp:
            report, output = self.invoke(Path(temp), lease_failure="enter")
            self.assertFalse(report["success"])
            self.assertIsNone(report["discovery"])
            self.assertFalse(output.exists())

    def test_unreturned_discovery_preserves_raw_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            report, output = self.invoke(Path(temp), error=RuntimeError("PRIVATE_SYNTHETIC_CANARY"))
            self.assertFalse(report["success"])
            self.assertTrue(output.exists())
            self.assertIn("raw_cleanup_unconfirmed", report["errors"])

    def test_cleanup_failure_or_unreaped_command_preserves_raw_directory(self):
        changes = [{"container_removed": False}, {"image_removed": False}, {"context_removed": False},
                   {"container_removed": 1}]
        for changed in changes:
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temp:
                result = discovery_result()
                result["success"] = False
                result["cleanup"].update(changed)
                report, output = self.invoke(Path(temp), result=result)
                self.assertFalse(report["success"])
                self.assertTrue(output.exists())
        with tempfile.TemporaryDirectory() as temp:
            result = discovery_result()
            result.update(success=False, errors=["command_cleanup_failed"])
            report, output = self.invoke(Path(temp), result=result)
            self.assertTrue(output.exists())
            self.assertFalse(report["success"])

    def test_failed_resolution_with_confirmed_cleanup_removes_raw_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            result = discovery_result()
            result.update(success=False, errors=["artifact_semantics_tree_mismatch"])
            report, output = self.invoke(Path(temp), result=result)
            self.assertFalse(output.exists())
            self.assertFalse(report["success"])
            self.assertEqual(report["errors"], ["discovery_failed"])
            self.assertEqual(report["discovery"]["errors"], ["artifact_semantics_tree_mismatch"])

    def test_report_cannot_overwrite_existing_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp).resolve() / "report.json"
            path.write_bytes(b"original")
            with self.assertRaises(FileExistsError):
                R.report_fd(path)
            self.assertEqual(path.read_bytes(), b"original")

    def test_cli_installs_and_restores_interrupt_handler(self):
        previous = object()
        calls = []
        def signal(signum, handler):
            calls.append((signum, handler))
        def write(_args):
            self.assertEqual(calls[0][0], R.signal.SIGTERM)
            with self.assertRaises(KeyboardInterrupt):
                calls[0][1](R.signal.SIGTERM, None)
            return 1
        args = [part for name in ("candidate", "verifier", "jdk-manifest", "jdk-config", "jdk-source", "report")
                for part in ("--" + name, "unused")]
        with patch.object(R.signal, "getsignal", return_value=previous), \
                patch.object(R.signal, "signal", side_effect=signal), patch.object(R, "write_report", side_effect=write):
            self.assertEqual(R.main(args), 1)
        self.assertEqual(calls[-1], (R.signal.SIGTERM, previous))


if __name__ == "__main__":
    unittest.main()
