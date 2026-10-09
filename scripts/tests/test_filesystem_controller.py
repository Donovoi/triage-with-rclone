"""Pure source-folder protocol checks; never launch a native session."""
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import socket
import subprocess
import threading
import types
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / "application-lab" / "filesystem_controller.py"
F = types.ModuleType("filesystem_controller_tests")
F.__file__ = str(PATH)
with patch.object(subprocess, "Popen", side_effect=AssertionError("no process")), \
        patch.object(socket, "socket", side_effect=AssertionError("no socket")):
    exec(compile(PATH.read_bytes(), str(PATH), "exec"), F.__dict__)


def snapshot(action="start_source"):
    return dict(schema_version=1, action=action, ok=True, state="running", app_exit_code=None,
        runtime_image_observed=False, runtime_sha256=None, runtime_process_count=None,
        ctrl_c_sent=False, output_bytes=0, output_limit_exceeded=False, forced_termination=False,
        app_exited=False, observed_children_exited=False, job_zero_confirmed=False,
        reader_joined=False, conpty_closed=False, errors=[])


class SourceControllerTests(unittest.TestCase):
    def test_loaded_support_is_bound_to_actual_source_bytes(self):
        source = PATH.with_name("run_windows_http.py").read_bytes()
        self.assertEqual(F.H.loaded_source_sha256, hashlib.sha256(source).hexdigest())

    def test_host_guard_precedes_base_constructor_and_any_native_work(self):
        with patch.object(F.H, "hosted_guard", side_effect=F.H.ProducerError("binding_failed")), \
                patch.object(F.H.Bridge, "__init__", side_effect=AssertionError("base entered")) as base:
            with self.assertRaisesRegex(F.H.ProducerError, "^binding_failed$"):
                F.SourceBridge(Path("unused"))
            base.assert_not_called()

    def test_source_actions_share_strict_existing_snapshot_contract(self):
        for action in F.SESSION_ACTIONS:
            value = snapshot(action)
            self.assertIs(F.validate_snapshot(value, action), value)
        for action in ("start", "start_tui", "start_observed_source", "private-canary", None):
            with self.assertRaises(F.H.ProducerError):
                F.validate_snapshot(snapshot(action), action)

    def test_source_errors_survive_validation_without_entering_legacy_vocabulary(self):
        value = snapshot("finish")
        value.update(ok=False, errors=["source_directory_invalid", "source_directory_cleanup_failed"])
        original = dict(value, errors=list(value["errors"]))
        self.assertIs(F.validate_snapshot(value, "finish"), value)
        self.assertEqual(value, original)
        with self.assertRaises(F.H.ProducerError):
            F.H.validate_session(value, "finish")

    def test_foreign_fields_types_and_success_inflation_are_rejected(self):
        value = snapshot()
        for changes in (dict(extra="private-canary"), dict(schema_version=2), dict(state="accepted"),
                dict(errors=["private-canary"], ok=False), dict(errors=["source_directory_invalid"]),
                dict(errors=["source_directory_invalid"] * 2, ok=False), dict(runtime_process_count=True),
                dict(runtime_process_count=65), dict(runtime_image_observed=True), dict(app_exited=True),
                dict(output_bytes=-1), dict(runtime_launches=1)):
            with self.subTest(changes=changes), self.assertRaises(F.H.ProducerError):
                F.validate_snapshot(dict(value, **changes), "start_source")

    def test_base_bridge_refuses_generic_start_before_io(self):
        bridge = object.__new__(F.SourceBridge)
        bridge.failed = threading.Event()
        with patch.object(bridge, "_diagnostic"), patch.object(subprocess, "Popen", side_effect=AssertionError("no process")):
            # A bare instance deliberately has no process or pipe attributes.
            # Refusal must happen before attempting to access either.
            for action in ("start", "start_observed_source", "start_tui"):
                with self.assertRaises(F.H.ProducerError):
                    bridge.command(action)

    def test_start_diagnostic_keeps_source_action_and_rejects_private_data(self):
        bridge = object.__new__(F.SourceBridge)
        bridge.response_lock = threading.Lock()
        bridge.stage_invalid = False
        bridge.stage_bytes = b"application_bridge_stage=compile\n"
        with redirect_stdout(io.StringIO()) as output:
            bridge._diagnostic("start_source", "wait", "timeout")
        self.assertEqual(json.loads(output.getvalue().split("=", 1)[1]), dict(
            action="start_source", phase="wait", outcome="timeout", last_stage="compile"))
        with redirect_stdout(io.StringIO()) as output:
            bridge._diagnostic("private-canary", "wait", "timeout")
        self.assertNotIn("private-canary", output.getvalue())
        self.assertEqual(json.loads(output.getvalue().split("=", 1)[1])["action"], "invalid")
        with redirect_stdout(io.StringIO()) as output:
            bridge._diagnostic("start_source", "private-canary", "timeout")
            bridge._diagnostic("start_source", "wait", "private-canary")
        self.assertEqual(output.getvalue(), "")

    def test_failure_diagnostic_preserves_both_errors_without_private_fields(self):
        bridge = object.__new__(F.SourceBridge)
        value = snapshot("finish")
        value.update(ok=False, errors=["source_directory_invalid", "source_directory_cleanup_failed"])
        with redirect_stdout(io.StringIO()) as output:
            bridge.failure_diagnostic(value, "finish")
        line = output.getvalue()
        self.assertLess(len(line.encode()), 4096)
        self.assertEqual(json.loads(line.split("=", 1)[1]), dict(action="finish", errors=value["errors"],
            forced_termination=False, app_exited=False, runtime_process_count=None))
        for altered in (dict(value, secret="private-canary"), dict(value, errors=["private-canary"]), snapshot("finish")):
            with redirect_stdout(io.StringIO()) as output, self.assertRaises(F.H.ProducerError):
                bridge.failure_diagnostic(altered, "finish")
            self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
