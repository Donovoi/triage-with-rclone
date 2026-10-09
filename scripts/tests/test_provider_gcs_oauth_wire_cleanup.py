"""Pure cleanup diagnostics tests; never starts the hosted wire test class."""
import ast
import errno
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import Mock, patch


SOURCE = Path(__file__).with_name("test_provider_gcs_oauth_wire.py")
W = types.ModuleType("gcs_wire_cleanup_contract")
W.__file__ = str(SOURCE)
exec(compile(SOURCE.read_bytes(), str(SOURCE), "exec"), W.__dict__)


class WireCleanupContractTests(unittest.TestCase):
    def setUp(self):
        self.sockets = patch.object(W.socket, "socket", side_effect=AssertionError("real socket forbidden"))
        self.sockets.start()
        self.addCleanup(self.sockets.stop)

    @staticmethod
    def fixture():
        return types.SimpleNamespace(
            port=23456, close=Mock(return_value=True),
            state=types.SimpleNamespace(source_preserved=Mock(return_value=True)),
            snapshot=Mock(return_value={"cleanup_complete": True, "transport": {
                "cleanup_complete": True, "active_connections": 0, "active_workers": 0, "active_timers": 0}}))

    def test_explicit_refusal_passes_with_exact_five_second_bound(self):
        for error in (ConnectionRefusedError(), OSError(errno.ECONNREFUSED, "private-canary"),
                      OSError(10061, "private-canary")):
            with self.subTest(category=type(error).__name__), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "owned"
                root.mkdir()
                with patch.object(W.socket, "create_connection", side_effect=error) as connect:
                    failures = W._finish_cleanup([(self.fixture(), root)], root, False)
                connect.assert_called_once_with(("127.0.0.1", 23456), timeout=5)
                self.assertEqual(failures, [])
                self.assertFalse(root.exists())

    def test_timeout_acceptance_and_other_errors_fail_and_retain_root(self):
        cases = ((TimeoutError("private-canary"), "listener_timeout"),
                 (OSError(errno.EACCES, "private-canary"), "listener_other_os_error"),
                 (RuntimeError("private-canary"), "listener_probe_error"),
                 (None, "listener_accepted"))
        for error, code in cases:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                connection = Mock()
                with patch.object(W.socket, "create_connection", side_effect=error, return_value=connection) as connect:
                    failures = W._finish_cleanup([(self.fixture(), root)], root, False)
                connect.assert_called_once_with(("127.0.0.1", 23456), timeout=5)
                self.assertEqual(failures, [code])
                self.assertTrue(root.exists())
                self.assertNotIn("private-canary", str(failures))
                if error is None:
                    connection.close.assert_called_once_with()

    def test_accepted_connection_close_failure_remains_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            connection = Mock()
            connection.close.side_effect = OSError("private-canary")
            with patch.object(W.socket, "create_connection", return_value=connection):
                failures = W._finish_cleanup([(self.fixture(), root)], root, False)
            self.assertEqual(failures, ["listener_connection_close_failed"])
            self.assertTrue(root.exists())

    def test_all_predicates_observed_after_first_failure_with_static_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "synthetic-material").write_bytes(b"private-canary")
            fixture = self.fixture()
            fixture.close.side_effect = RuntimeError("private-canary")
            fixture.state.source_preserved.return_value = False
            fixture.snapshot.return_value = {"cleanup_complete": False, "transport": {
                "cleanup_complete": False, "active_connections": 1, "active_workers": 2, "active_timers": 1}}
            with patch.object(W.socket, "create_connection", side_effect=TimeoutError("private-canary")) as connect:
                failures = W._finish_cleanup([(fixture, root)], root, False)
            fixture.snapshot.assert_called_once_with()
            fixture.state.source_preserved.assert_called_once_with()
            connect.assert_called_once()
            self.assertEqual(failures, sorted(("fixture_closed", "fixture_complete", "source_preserved",
                "transport_complete", "connections_closed", "workers_joined", "timers_joined",
                "material_removed", "listener_timeout")))
            self.assertTrue((root / "synthetic-material").exists())
            self.assertNotIn("private-canary", str(failures))

    def test_malformed_snapshot_or_counts_do_not_become_cleanup_proof(self):
        for snapshot in (None, {"cleanup_complete": True, "transport": {
                "cleanup_complete": True, "active_connections": False, "active_workers": "0", "active_timers": 0.0}}):
            with self.subTest(snapshot_kind=type(snapshot).__name__), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                fixture = self.fixture()
                fixture.snapshot.return_value = snapshot
                with patch.object(W.socket, "create_connection", side_effect=ConnectionRefusedError()):
                    failures = W._finish_cleanup([(fixture, root)], root, False)
                self.assertTrue({"connections_closed", "workers_joined", "timers_joined"} <= set(failures))
                self.assertTrue(root.exists())

    def test_uncertain_constructor_and_remove_failure_remain_static_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(W.socket, "create_connection") as connect:
                self.assertEqual(W._finish_cleanup([], root, True), ["constructor_unproved"])
            connect.assert_not_called()
            self.assertTrue(root.exists())
            with patch.object(W.shutil, "rmtree", side_effect=OSError("private-canary")):
                self.assertEqual(W._finish_cleanup([], root, False), ["temporary_remove_failed"])
            self.assertTrue(root.exists())

    def test_hosted_guard_precedes_fixture_import_and_is_not_bypassed(self):
        tree = ast.parse(SOURCE.read_bytes())
        case = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "GcsOAuthWireTests")
        setup = next(node for node in case.body if isinstance(node, ast.FunctionDef) and node.name == "setUpClass")
        guard = setup.body[0]
        self.assertIsInstance(guard, ast.If)
        self.assertIsInstance(guard.body[0], ast.Raise)
        self.assertEqual(ast.unparse(guard.test),
            "os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'")


if __name__ == "__main__":
    unittest.main()
