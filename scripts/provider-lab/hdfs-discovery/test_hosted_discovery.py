"""Mocked ordering, cleanup and inspection/discovery scope checks."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import hosted_discovery as H


class FakeLease:
    def __init__(self, failure=None):
        self.failure = failure
        self.paths = (Path("manifest"), Path("config"), Path("recipe"))
        self.report = {"success": False, "ledger_eligible": False, "errors": []}
        self.entered = self.exited = False

    def __enter__(self):
        self.entered = True
        if self.failure == "enter":
            raise RuntimeError("PRIVATE_SYNTHETIC_CANARY")
        return self

    def __exit__(self, kind, error, traceback):
        self.exited = True
        self.report["success"] = kind is None and self.failure != "cleanup"


class HostedTests(unittest.TestCase):
    def test_inspection_default_never_calls_discovery(self):
        metadata, material = FakeLease(), FakeLease()
        with patch.object(H.J, "JdkMetadataLease", return_value=metadata), \
                patch.object(H.B, "BootstrapLease", return_value=material), patch.object(H.R, "run") as discover:
            result = H.run(Path("candidate"), Path("verifier"), "inspect")
        discover.assert_not_called()
        self.assertTrue(result["success"])
        self.assertTrue(metadata.exited and material.exited)
        self.assertFalse(result["ledger_eligible"])
        self.assertFalse(result["daemon_accepted"])

    def test_discovery_waits_for_metadata_and_requires_both_cleanups(self):
        for failure in (None, "cleanup"):
            with self.subTest(failure=failure):
                metadata = FakeLease(failure)
                def discover(*args):
                    self.assertTrue(metadata.entered)
                    self.assertFalse(metadata.exited)
                    self.assertEqual(args[2:], metadata.paths)
                    return {"success": True, "ledger_eligible": False}
                with patch.object(H.J, "JdkMetadataLease", return_value=metadata), \
                        patch.object(H.B, "BootstrapLease") as bootstrap, patch.object(H.R, "run", side_effect=discover):
                    result = H.run(Path("candidate"), Path("verifier"), "discover")
                bootstrap.assert_not_called()
                self.assertEqual(result["success"], failure is None)
                self.assertTrue(metadata.exited)

    def test_metadata_failure_prevents_all_consumers_and_hides_exception_text(self):
        with patch.object(H.J, "JdkMetadataLease", return_value=FakeLease("enter")), \
                patch.object(H.B, "BootstrapLease") as bootstrap, patch.object(H.R, "run") as discover:
            result = H.run(Path("candidate"), Path("verifier"), "discover")
        bootstrap.assert_not_called()
        discover.assert_not_called()
        self.assertFalse(result["success"])
        self.assertIsNone(result["result"])
        self.assertNotIn("PRIVATE_SYNTHETIC_CANARY", str(result))

    def test_failed_discovery_is_not_promoted_by_metadata_cleanup(self):
        with patch.object(H.J, "JdkMetadataLease", return_value=FakeLease()), \
                patch.object(H.R, "run", return_value={"success": False, "ledger_eligible": False}):
            result = H.run(Path("candidate"), Path("verifier"), "discover")
        self.assertFalse(result["success"])
        self.assertTrue(result["metadata"]["success"])

    def test_cli_defaults_to_inspection_and_restores_sigterm(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp).resolve() / "result.json"
            previous = object()
            with patch.object(H.signal, "getsignal", return_value=previous), patch.object(H.signal, "signal") as signal, \
                    patch.object(H, "run", return_value={"success": True, "ledger_eligible": False}) as run:
                self.assertEqual(H.main(["--candidate", "unused", "--verifier", "unused", "--report", str(output)]), 0)
            self.assertEqual(run.call_args.args[2], "inspect")
            handler = signal.call_args_list[0].args[1]
            with self.assertRaises(KeyboardInterrupt):
                handler(H.signal.SIGTERM, None)
            self.assertEqual(signal.call_args_list[-1].args, (H.signal.SIGTERM, previous))


if __name__ == "__main__":
    unittest.main()
