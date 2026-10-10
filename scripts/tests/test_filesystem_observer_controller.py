"""Pure observed-source transport checks. No processes, sockets or native calls."""
from contextlib import redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import queue
import socket
import subprocess
import threading
import time
import types
import unittest
from unittest.mock import Mock, patch

PATH = Path(__file__).resolve().parents[1] / "application-lab" / "filesystem_controller.py"
F = types.ModuleType("filesystem_observer_tests")
F.__file__ = str(PATH)
with patch.object(subprocess, "Popen", side_effect=AssertionError("no process")), \
        patch.object(socket, "socket", side_effect=AssertionError("no socket")):
    exec(compile(PATH.read_bytes(), str(PATH), "exec"), F.__dict__)
RUNTIME, HELPER = "1" * 64, "2" * 64


def snapshot(action="start_source_observed", finished=False, helpers=1):
    value = dict(schema_version=3, action=action, ok=True, state="running", app_exit_code=None,
        runtime_image_observed=False, runtime_sha256=None, runtime_process_count=None,
        ctrl_c_sent=False, output_bytes=0, output_limit_exceeded=False, forced_termination=False,
        app_exited=False, observed_children_exited=False, job_zero_confirmed=False,
        reader_joined=False, conpty_closed=False, errors=[], observation_kind="launch_image",
        launch_image_observed=False, launch_sha256=None, runtime_launch_count=0, peak_runtime_processes=0,
        debug_event_count=0, debug_events_drained=False, debug_pump_joined=False, debug_handles_closed=False,
        system_helper_image_observed=False, system_helper_sha256=None, system_helper_launch_count=0,
        peak_system_helper_processes=0, system_helper_reference_closed=False)
    if finished:
        value.update(state="finished", app_exit_code=0, output_bytes=20, launch_image_observed=True,
            launch_sha256=RUNTIME, runtime_launch_count=1, peak_runtime_processes=1, debug_event_count=20,
            system_helper_image_observed=bool(helpers), system_helper_sha256=HELPER if helpers else None,
            system_helper_launch_count=helpers, peak_system_helper_processes=helpers)
        for key in (*F.H.SESSION_CLEANUP, *F.OBSERVED_CLEANUP):
            value[key] = True
    return value


def request():
    return dict(app_path="C:/private/application.exe", app_sha256="3" * 64,
        args=["--list-remote", "Owned", "--rclone-config-path", "private.conf"],
        case_root="C:/private/case", environment={"TEMP": "C:/private/case/temp"},
        transcript_path="C:/private/case/transcript", max_output_bytes=1048576, deadline_ms=60000,
        max_runtime_processes=1, expected_runtime_sha256=RUNTIME, max_runtime_launches=3)


def bare_bridge():
    bridge = object.__new__(F.ObservedSourceBridge)
    bridge.observer_started = False
    bridge.expected_runtime_sha256 = None
    bridge.max_runtime_processes = bridge.max_runtime_launches = 0
    bridge.observer_previous = bridge.observer_helper_hash = None
    bridge.last = None
    bridge.failed = threading.Event()
    bridge._diagnostic = Mock()
    return bridge


def armed_bridge():
    bridge = bare_bridge()
    bridge.observer_started = True
    bridge.expected_runtime_sha256 = RUNTIME
    bridge.max_runtime_processes, bridge.max_runtime_launches = 1, 3
    return bridge


class ObservedControllerTests(unittest.TestCase):
    def setUp(self):
        self.no_process = patch.object(subprocess, "Popen", side_effect=AssertionError("no process"))
        self.no_socket = patch.object(socket, "socket", side_effect=AssertionError("no socket"))
        self.no_process.start(); self.no_socket.start()
        self.addCleanup(self.no_process.stop); self.addCleanup(self.no_socket.stop)

    def validate(self, value, action=None, concurrent=1, launches=3):
        return F.validate_observed_snapshot(value, action or value.get("action", "start_source_observed"), RUNTIME, concurrent, launches)

    def reject(self, value, **kwargs):
        with self.assertRaises(F.H.ProducerError):
            self.validate(value, **kwargs)

    def test_guard_runs_before_native_constructor(self):
        with patch.object(F.H, "hosted_guard", side_effect=F.H.ProducerError("binding_failed")), \
                patch.object(F.H.Bridge, "__init__") as base:
            with self.assertRaises(F.H.ProducerError):
                F.ObservedSourceBridge(Path("unused"))
            base.assert_not_called()

    def test_exact_schema_and_strict_scalar_types(self):
        original = snapshot()
        self.assertIs(self.validate(original), original)
        for key in original:
            value = deepcopy(original); del value[key]
            with self.subTest(missing=key): self.reject(value)
        for changes in (dict(private="canary"), dict(schema_version=True), dict(schema_version=1),
                dict(action="poll"), dict(observation_kind="live_image"), dict(state=[]),
                dict(runtime_image_observed=True), dict(runtime_sha256=RUNTIME), dict(runtime_process_count=0),
                dict(ctrl_c_sent=True), dict(app_exited=True), dict(errors=["private-canary"], ok=False),
                dict(ok=False), dict(errors=["debug_start_failed"] * 2, ok=False)):
            with self.subTest(changes=changes): self.reject(dict(original, **changes), action=original["action"])
        for key, val in original.items():
            if type(val) in {bool, int}:
                value = dict(original); value[key] = 1 if type(val) is bool else True
                with self.subTest(wrong_type=key): self.reject(value)

    def test_zero_running_observations_are_transport_only(self):
        for action in ("start_source_observed", "poll"):
            value = snapshot(action)
            self.assertEqual(self.validate(value), value)
            value.update(state="finished", app_exit_code=0, app_exited=True)
            self.reject(value)
        self.reject(snapshot("finish"))

    def test_final_success_requires_every_common_and_debug_cleanup(self):
        value = snapshot("finish", True)
        self.assertEqual(self.validate(value), value)
        for key in (*F.H.SESSION_CLEANUP, *F.OBSERVED_CLEANUP, "launch_image_observed", "system_helper_image_observed"):
            with self.subTest(key=key): self.reject(dict(value, **{key: False}))
        for changes in (dict(app_exit_code=None), dict(launch_sha256="4" * 64),
                dict(system_helper_sha256="4" * 63), dict(forced_termination=True),
                dict(output_limit_exceeded=True), dict(runtime_launch_count=0)):
            with self.subTest(changes=changes): self.reject(dict(value, **changes))
        # Exit success/failure is the application oracle's obligation, not transport.
        self.validate(dict(value, app_exit_code=1))

    def test_helpers_are_separate_and_never_invented(self):
        self.validate(snapshot("finish", True, helpers=0))
        for changes in (dict(system_helper_launch_count=2, peak_system_helper_processes=1),
                dict(system_helper_launch_count=3, peak_system_helper_processes=3, runtime_launch_count=3),
                dict(system_helper_image_observed=False, system_helper_sha256=HELPER),
                dict(system_helper_image_observed=True, system_helper_sha256=None)):
            with self.subTest(changes=changes): self.reject(dict(snapshot("finish", True), **changes))

    def test_successful_finish_requires_create_initial_breakpoint_and_exit_per_process(self):
        value = snapshot("finish", True)
        self.validate(dict(value, debug_event_count=9))
        self.reject(dict(value, debug_event_count=8))
        self.validate(dict(snapshot("finish", True, helpers=0), debug_event_count=6))
        self.reject(dict(snapshot("finish", True, helpers=0), debug_event_count=5))
        # Failed/active snapshots do not claim every process reached those events.
        self.validate(dict(value, ok=False, errors=["debug_event_failed"], debug_event_count=3))

    def test_configured_and_absolute_budgets_are_distinct(self):
        value = snapshot("finish", True)
        value.update(runtime_launch_count=3, peak_runtime_processes=2)
        self.reject(value)
        self.validate(value, concurrent=2)
        value.update(runtime_launch_count=4)
        self.reject(value, concurrent=2)
        # Failed attempts can exceed an admission bound but remain finite evidence.
        value.update(ok=False, errors=["debug_launch_limit"], system_helper_launch_count=3,
                     peak_system_helper_processes=3)
        self.validate(value)
        for changes in (dict(runtime_launch_count=34), dict(runtime_launch_count=32, system_helper_launch_count=2),
                dict(debug_event_count=4097), dict(debug_event_count=1), dict(peak_runtime_processes=0)):
            with self.subTest(changes=changes): self.reject(dict(value, **changes))
        for limit in (0, 33, True, "3"):
            with self.subTest(launch_limit=limit): self.reject(snapshot(), launches=limit)
        for limit in (0, 5, True):
            with self.subTest(concurrent_limit=limit): self.reject(snapshot(), concurrent=limit)

    def test_failed_startup_and_closed_error_vocabulary_are_retained(self):
        for error in F.DEBUG_ERRORS | F.SOURCE_ERRORS | F.H.SESSION_ERRORS:
            value = snapshot("invalid")
            value.update(ok=False, state="finished", errors=[error], app_exited=True)
            self.assertEqual(self.validate(value), value)
        value = snapshot("eof"); value.update(ok=False, state="finished", errors=["protocol_invalid"])
        self.validate(value)
        self.reject(dict(value, ok=True, errors=[]))
        self.reject(dict(value, debug_handles_closed=True))
        self.reject(dict(snapshot(), system_helper_reference_closed=True))

    def test_monotone_observations_and_hashes(self):
        initial = snapshot("poll", True); initial.update(state="running")
        for key in (*F.H.SESSION_CLEANUP, *F.OBSERVED_CLEANUP): initial[key] = False
        initial["app_exit_code"] = None
        for changes in (dict(runtime_launch_count=0, peak_runtime_processes=0, launch_image_observed=False, launch_sha256=None,
                             system_helper_launch_count=0, peak_system_helper_processes=0, system_helper_image_observed=False, system_helper_sha256=None),
                dict(output_bytes=0), dict(debug_event_count=19), dict(system_helper_sha256="5" * 64)):
            bridge = armed_bridge(); bridge.validate_session(initial, "poll")
            with self.subTest(changes=changes), self.assertRaises(F.H.ProducerError):
                bridge.validate_session(dict(initial, **changes), "poll")
        # A pending additional helper temporarily makes its aggregate unverified.
        bridge = armed_bridge(); bridge.validate_session(initial, "poll")
        pending = dict(initial, runtime_launch_count=2, system_helper_launch_count=2,
                       system_helper_image_observed=False, system_helper_sha256=None)
        bridge.validate_session(pending, "poll")
        bridge.validate_session(dict(pending, system_helper_image_observed=True, system_helper_sha256=HELPER), "poll")

    def test_errors_forced_exit_and_finished_state_never_regress(self):
        prior = snapshot("poll"); prior.update(ok=False, errors=["debug_event_failed"], forced_termination=True, app_exit_code=99)
        for changes in (dict(errors=[], ok=True), dict(forced_termination=False), dict(app_exit_code=None), dict(app_exit_code=0)):
            bridge = armed_bridge(); bridge.validate_session(prior, "poll")
            with self.subTest(changes=changes), self.assertRaises(F.H.ProducerError):
                bridge.validate_session(dict(prior, **changes), "poll")
        bridge = armed_bridge(); bridge.validate_session(snapshot("finish", True), "finish")
        with self.assertRaises(F.H.ProducerError): bridge.validate_session(snapshot("poll"), "poll")

    def test_prohibited_and_out_of_order_requests_never_reach_transport(self):
        for action in ("start", "start_source", "observe_runtime", "ctrl_c", "start_tui", "private-canary", "poll", "finish"):
            bridge = bare_bridge()
            with patch.object(F.H.Bridge, "command") as transport, self.subTest(action=action), self.assertRaises(F.H.ProducerError):
                bridge.command(action)
            transport.assert_not_called(); self.assertTrue(bridge.failed.is_set())

    def test_start_request_closed_fields_bounds_and_types(self):
        bad = [dict(extra="canary"), dict(expected_runtime_sha256="A" * 64), dict(max_runtime_launches=True),
            dict(max_runtime_launches=33), dict(max_runtime_processes=5), dict(app_sha256="bad"),
            dict(args="bad"), dict(args=["\0"]), dict(environment={"TEMP": 1}), dict(deadline_ms=999),
            dict(deadline_ms=True), dict(max_output_bytes=8388609), dict(case_root="")]
        for changes in bad:
            bridge = bare_bridge()
            with patch.object(F.H.Bridge, "command") as transport, self.subTest(changes=changes), self.assertRaises(F.H.ProducerError):
                bridge.command("start_source_observed", **dict(request(), **changes))
            transport.assert_not_called()
        for key in request():
            fields = request(); del fields[key]
            with patch.object(F.H.Bridge, "command") as transport, self.subTest(missing=key), self.assertRaises(F.H.ProducerError):
                bare_bridge().command("start_source_observed", **fields)
            transport.assert_not_called()

    def test_prearm_is_fixed_before_write_and_cannot_be_retried(self):
        bridge = bare_bridge()
        def broken_write(action, **fields):
            self.assertTrue(bridge.observer_started)
            self.assertEqual((bridge.expected_runtime_sha256, bridge.max_runtime_processes, bridge.max_runtime_launches), (RUNTIME, 1, 3))
            raise F.H.ProducerError("session_failed")
        with patch.object(F.H.Bridge, "command", side_effect=broken_write) as transport:
            with self.assertRaises(F.H.ProducerError): bridge.command("start_source_observed", **request())
            with self.assertRaises(F.H.ProducerError): bridge.command("start_source_observed", **request())
            self.assertEqual(transport.call_count, 1)

    def test_started_handshake_finish_shape_and_post_finished_refusals(self):
        for action, fields in (("ready", {}), ("close_ready", {}), ("poll", {"extra": 1}),
                ("finish", {}), ("finish", {"grace_ms": True}), ("finish", {"grace_ms": 10001})):
            bridge = armed_bridge()
            with patch.object(F.H.Bridge, "command") as transport, self.subTest(action=action, fields=fields), self.assertRaises(F.H.ProducerError):
                bridge.command(action, **fields)
            transport.assert_not_called()
        for action in ("poll", "finish", "start_source_observed"):
            bridge = armed_bridge(); bridge.last = snapshot("finish", True)
            with patch.object(F.H.Bridge, "command") as transport, self.subTest(after_finished=action), self.assertRaises(F.H.ProducerError):
                bridge.command(action, **({"grace_ms": 0} if action == "finish" else {}))
            transport.assert_not_called()

    def test_ordinary_schema_cannot_be_relabelled_as_observer_evidence(self):
        value = snapshot("poll")
        legacy = {key: value[key] for key in F.H.SESSION_KEYS}
        legacy["schema_version"] = 1
        self.assertEqual(F.validate_snapshot(legacy, "poll"), legacy)
        self.reject(legacy)
        with self.assertRaises(F.H.ProducerError): F.validate_snapshot(value, "poll")
        for action in ("observe_runtime", "ctrl_c", "start_source"):
            self.reject(dict(value, action=action))

    def test_real_base_transport_roundtrip_uses_schema3_without_process(self):
        bridge = bare_bridge()
        bridge.closed_ready = bridge.forced = bridge.ready = False
        bridge.calls = bridge.responses = 0
        bridge.response_lock = threading.Lock(); bridge.messages = queue.Queue()
        bridge.deadline = time.monotonic() + 60
        bridge.process = Mock(); bridge.process.poll.return_value = None
        bridge.process.stdin = io.BytesIO()
        # The actual command method requires the queue to be empty until write.
        class Input(io.BytesIO):
            def write(self, data):
                result = super().write(data); action = json.loads(data)["action"]
                value = (dict(schema_version=1, action="ready", ok=True, state="ready") if action == "ready"
                         else snapshot(action, action == "finish"))
                bridge.responses = bridge.calls
                bridge.messages.put(F.H.E.compact(value))
                return result
        bridge.process.stdin = Input()
        self.assertEqual(bridge.command("ready")["schema_version"], 1)
        self.assertEqual(bridge.command("start_source_observed", **request())["schema_version"], 3)
        self.assertEqual(bridge.command("poll")["runtime_launch_count"], 0)
        self.assertTrue(bridge.command("finish", grace_ms=10000)["debug_handles_closed"])
        commands = [json.loads(line) for line in bridge.process.stdin.getvalue().splitlines()]
        self.assertEqual([row["action"] for row in commands], ["ready", "start_source_observed", "poll", "finish"])
        self.assertEqual(commands[1], dict(action="start_source_observed", **request()))
        before = bridge.process.stdin.getvalue()
        with self.assertRaises(F.H.ProducerError): bridge.command("poll")
        self.assertEqual(bridge.process.stdin.getvalue(), before)

    def test_diagnostics_are_failure_only_and_never_include_hashes_or_private_values(self):
        bridge = armed_bridge(); value = snapshot("finish", True)
        value.update(ok=False, errors=["source_directory_cleanup_failed", "debug_cleanup_failed"], debug_handles_closed=False)
        with redirect_stdout(io.StringIO()) as output: bridge.failure_diagnostic(value, "finish")
        line = output.getvalue(); self.assertLess(len(line), 4096)
        self.assertTrue(line.startswith("application_filesystem_launch_failure="))
        self.assertNotIn(RUNTIME, line); self.assertNotIn(HELPER, line)
        self.assertEqual(json.loads(line.split("=", 1)[1])["errors"], value["errors"])
        for altered in (snapshot("finish", True), dict(value, extra="private-canary"), dict(value, errors=["private-canary"])):
            with redirect_stdout(io.StringIO()) as output, self.assertRaises(F.H.ProducerError):
                bridge.failure_diagnostic(altered, "finish")
            self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
