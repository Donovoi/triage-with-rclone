"""Pure transport/observation checks. Never create a native session."""
import importlib.util
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

PATH = Path(__file__).resolve().parents[1] / "application-lab" / "tui_controller.py"
SPEC = importlib.util.spec_from_file_location("tui_controller_tests", PATH)
T = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(T)


def snapshot(action="start"):
    return dict(schema_version=2, action=action, ok=True, state="running", app_exit_code=None,
        runtime_image_observed=False, runtime_sha256=None, runtime_process_count=None, ctrl_c_sent=False,
        output_bytes=0, output_limit_exceeded=False, forced_termination=False, app_exited=False,
        observed_children_exited=False, job_zero_confirmed=False, reader_joined=False, conpty_closed=False,
        errors=[], input_commands=0, input_bytes=0, resize_count=0, columns=120, rows=34,
        protocol_commands=2, protocol_bytes=200)


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        # Deliberately bypass the constructor, which owns hosted native resources.
        self.bridge = object.__new__(T.TuiBridge)
        self.bridge.last = None
        self.bridge.calls = 2
        self.bridge.wire_bytes = 200
        self.bridge.request = {"action": "start"}

    def rejects(self, value, action="start"):
        with self.assertRaises(T.H.ProducerError):
            self.bridge.validate_session(value, action)

    def test_cli_snapshot_is_not_tui_credit(self):
        cli = {key: value for key, value in snapshot().items() if key in T.H.SESSION_KEYS}
        cli["schema_version"] = 1
        self.rejects(cli)
        self.assertEqual(T.H.Bridge.script_name, "hosted_session.ps1")
        self.assertNotIn("text", T.H.Bridge.actions)

    def test_exact_start_response_and_wire_binding(self):
        value = snapshot()
        self.assertIs(self.bridge.validate_session(value, "start"), value)
        for key in ("protocol_commands", "protocol_bytes"):
            for amount in (-1, 1):
                altered = dict(value, **{key: value[key] + amount})
                self.rejects(altered)

    def test_closed_fields_types_and_error_vocabulary(self):
        for key, value in (("extra", True), ("input_bytes", True), ("resize_count", -1),
                           ("input_commands", 257), ("columns", 119), ("errors", ["raw private diagnostic"]),
                           ("errors", [{}]), ("errors", ["resize_failed", "resize_failed"])):
            self.rejects(dict(snapshot(), **{key: value}))

    def test_input_receipt_requires_exact_successful_byte_delta(self):
        previous = snapshot()
        self.bridge.last = previous
        self.bridge.calls = 3
        self.bridge.wire_bytes = 240
        self.bridge.request = {"action": "key", "key": "page_down"}
        value = dict(previous, action="key", input_commands=1, input_bytes=4,
                     protocol_commands=3, protocol_bytes=240)
        self.assertIs(self.bridge.validate_session(value, "key"), value)
        for amount in (0, 1, 3, 5, 8193):
            self.rejects(dict(value, input_bytes=amount), "key")

    def test_poll_cannot_invent_input_or_a_resize(self):
        self.bridge.last = snapshot()
        self.bridge.request = {"action": "poll"}
        for key in ("input_commands", "input_bytes", "resize_count"):
            self.rejects(dict(snapshot("poll"), **{key: 1}), "poll")

    def test_resize_response_must_match_requested_geometry(self):
        self.bridge.last = snapshot()
        self.bridge.request = {"action": "resize", "columns": 80, "rows": 24}
        value = dict(snapshot("resize"), resize_count=1, columns=80, rows=24)
        self.assertIs(self.bridge.validate_session(value, "resize"), value)
        self.rejects(dict(value, columns=120, rows=34), "resize")

    def test_sticky_native_failure_remains_failure(self):
        value = dict(snapshot(), ok=False, errors=["resize_timeout"], forced_termination=True)
        self.assertFalse(self.bridge.validate_session(value, "start")["ok"])
        self.rejects(dict(value, ok=True))

    def test_cli_diagnostic_hook_delegates_without_changing_the_contract(self):
        bridge = object.__new__(T.H.Bridge)
        value = {"synthetic": "not interpreted by the delegate"}
        with patch.object(T.H, "session_failure_diagnostic", return_value=None) as diagnostic:
            self.assertIsNone(bridge.failure_diagnostic(value, "poll"))
        diagnostic.assert_called_once_with(value, "poll")

    def test_tui_diagnostic_is_closed_and_does_not_replay_counter_transitions(self):
        for count, classification in ((None, "unavailable"), (0, "none"), (1, "single"), (4, "multiple"), (64, "multiple")):
            value = dict(snapshot("text"), ok=False, errors=["input_timeout", "tui_input_refused"],
                         forced_termination=True, runtime_process_count=count, input_commands=1, input_bytes=7)
            self.bridge.last = None
            self.bridge.last = self.bridge.validate_session(value, "text")
            with redirect_stdout(io.StringIO()) as output, patch.object(
                    self.bridge, "validate_session", side_effect=AssertionError("must not replay a transition")):
                self.bridge.failure_diagnostic(value, "text")
            rendered = output.getvalue()
            self.assertTrue(rendered.startswith("application_tui_session_failure="))
            self.assertLessEqual(len(rendered.encode("ascii")), 4096)
            expected = dict(action="text", errors=value["errors"], forced_termination=True,
                            app_exited=False, runtime_process_count=count, count_classification=classification,
                            output_bytes=0, **{key: value[key] for key in T.TUI_FIELDS})
            self.assertEqual(json.loads(rendered.split("=", 1)[1]), expected)
            self.assertFalse(value["ok"])

    def test_tui_diagnostic_refuses_forged_private_or_unknown_fields_before_printing(self):
        failure = dict(snapshot(), ok=False, errors=["tui_input_refused"])
        variants = [dict(failure, secret="private-canary"), dict(failure, errors=["private-canary"]),
                    dict(failure, errors=[{}]), dict(failure, errors=["resize_failed", "resize_failed"]),
                    dict(failure, action="private-canary"), dict(failure, schema_version=True),
                    dict(failure, runtime_process_count=True), dict(failure, runtime_process_count=65),
                    dict(failure, runtime_sha256="private-canary"), dict(failure, forced_termination=1),
                    dict(failure, app_exited="private-canary"), dict(failure, output_bytes=-1),
                    dict(failure, columns=80, rows=34), dict(failure, ok=True), snapshot()]
        for key, bound in T.COUNTER_BOUNDS.items():
            variants.extend(dict(failure, **{key: value}) for value in (True, -1, bound + 1, "private-canary"))
        variants.extend((dict(failure, protocol_commands=1), dict(failure, protocol_bytes=199)))
        for index, value in enumerate(variants):
            self.bridge.last = value
            with self.subTest(index=index), redirect_stdout(io.StringIO()) as output, self.assertRaises(T.H.ProducerError):
                self.bridge.failure_diagnostic(value, "start")
            self.assertEqual(output.getvalue(), "")
        self.bridge.last = failure
        for value, action in ((dict(failure), "start"), (failure, "ready"), (failure, "private-canary"), (failure, [])):
            with redirect_stdout(io.StringIO()) as output, self.assertRaises(T.H.ProducerError):
                self.bridge.failure_diagnostic(value, action)
            self.assertEqual(output.getvalue(), "")

    def test_tui_diagnostic_remains_bounded_at_all_static_limits(self):
        value = dict(snapshot(), ok=False, errors=sorted(T.H.SESSION_ERRORS | T.TUI_ERRORS)[:24],
                     runtime_process_count=64, forced_termination=True, output_bytes=8 * 1024 * 1024 + 65536,
                     **T.COUNTER_BOUNDS)
        self.bridge.last = value
        self.bridge.calls = value["protocol_commands"]
        self.bridge.wire_bytes = value["protocol_bytes"]
        with redirect_stdout(io.StringIO()) as output:
            self.bridge.failure_diagnostic(value, "start")
        self.assertLessEqual(len(output.getvalue().encode("ascii")), 4096)

    def test_command_emits_only_failure_and_printing_cannot_change_the_saved_response(self):
        for failure, print_failure in ((True, False), (True, True), (False, False)):
            bridge = object.__new__(T.TuiBridge)
            bridge.last = None
            bridge.calls = bridge.responses = 1
            bridge.wire_bytes = len(T.H.E.compact({"action": "ready"})) + 1
            bridge.request = None
            bridge.ready, bridge.closed_ready, bridge.forced = True, False, False
            bridge.failed = T.H.threading.Event()
            bridge.response_lock = T.H.threading.Lock()
            bridge.messages = T.H.queue.Queue()
            bridge.process = Mock()
            bridge.process.poll.return_value = None
            bridge.deadline = T.time.monotonic() + 60
            sent = []
            def reply(_payload):
                value = dict(snapshot("text"), input_commands=1, input_bytes=len("private-canary"),
                             protocol_commands=bridge.calls, protocol_bytes=bridge.wire_bytes,
                             ok=not failure, errors=["tui_input_refused"] if failure else [])
                sent.append(value)
                bridge.responses += 1
                bridge.messages.put_nowait(T.H.E.compact(value))
            bridge.process.stdin.write.side_effect = reply
            with redirect_stdout(io.StringIO()) as output, patch.object(
                    T.H, "session_failure_diagnostic", side_effect=AssertionError("CLI diagnostic called")):
                if print_failure:
                    with patch("builtins.print", side_effect=OSError("private-canary")):
                        result = bridge.command("text", text="private-canary")
                else:
                    result = bridge.command("text", text="private-canary")
            self.assertEqual(result, sent[0])
            self.assertIs(bridge.last, result)
            self.assertEqual(result["ok"], not failure)
            self.assertNotIn("private-canary", output.getvalue())
            if failure and not print_failure:
                self.assertEqual(json.loads(output.getvalue().split("=", 1)[1])["errors"], ["tui_input_refused"])
            else:
                self.assertEqual(output.getvalue(), "")


class WaitDiagnosticTests(unittest.TestCase):
    def capture(self, error, screen=None, stage="poll", invoked=False):
        with redirect_stdout(io.StringIO()) as output:
            T.wait_failure_diagnostic(error, stage, T.S.Screen() if screen is None else screen, invoked)
        rendered = output.getvalue()
        self.assertLessEqual(len(rendered.encode("ascii")), 1024)
        self.assertNotIn("private-canary", rendered)
        self.assertTrue(rendered.startswith("application_tui_wait_failure="))
        result = json.loads(rendered.split("=", 1)[1])
        self.assertEqual(set(result), {"stage", "reason_type", "reason_code", "screen_ready",
                                      "screen_pending", "screen_bytes", "predicate_invoked"})
        return result

    def test_closed_screen_codes_without_private_text(self):
        screen = T.S.Screen()
        screen.feed(b"private-canary")
        for code in T.S.CODES:
            with self.subTest(code=code):
                result = self.capture(T.S.ScreenError(code), screen)
                self.assertEqual((result["reason_type"], result["reason_code"]), ("screen", code))
                self.assertEqual(result["screen_bytes"], 14)

    def test_controller_codes_and_unknown_errors_are_never_formatted(self):
        class PrivateError(Exception):
            def __str__(self):
                raise AssertionError("private-canary")
        for code in T.WAIT_ERRORS:
            self.assertEqual(self.capture(T.H.ProducerError(code))["reason_code"], code)
        for error in (PrivateError("private-canary"), T.H.ProducerError("private-canary"),
                      T.H.ProducerError([]), T.H.ProducerError("session_failed", "private-canary")):
            result = self.capture(error)
            self.assertEqual((result["reason_type"], result["reason_code"]),
                             ("unexpected", "unexpected_failure"))
        error = T.S.ScreenError("sequence_unsupported")
        error.code = {"private-canary": 1}
        self.assertEqual(self.capture(error)["reason_code"], "unexpected_failure")

    def test_untrusted_screen_properties_are_not_read(self):
        class PrivateScreen:
            @property
            def ready(self):
                raise AssertionError("private-canary")
        result = self.capture(ValueError(), PrivateScreen())
        self.assertIsNone(result["screen_ready"])
        self.assertIsNone(result["screen_pending"])
        self.assertIsNone(result["screen_bytes"])

    def test_invalid_fields_and_broken_output_cannot_replace_error(self):
        for stage, invoked in (("private-canary", False), ([], False), ("poll", 1)):
            with redirect_stdout(io.StringIO()) as output:
                T.wait_failure_diagnostic(ValueError(), stage, T.S.Screen(), invoked)
            self.assertEqual(output.getvalue(), "")
        with patch("builtins.print", side_effect=OSError("private-canary")):
            T.wait_failure_diagnostic(ValueError(), "poll", T.S.Screen(), False)


class ControllerFailureDiagnosticTests(unittest.TestCase):
    def setUp(self):
        for module, name in ((subprocess, "Popen"), (socket, "socket")):
            guard = patch.object(module, name, side_effect=AssertionError("native or network execution forbidden"))
            guard.start()
            self.addCleanup(guard.stop)
        clock = patch.object(T.time, "monotonic", return_value=0)
        clock.start()
        self.addCleanup(clock.stop)
        # Only in-memory fake transport/reader. No session constructor or files.
        self.controller = object.__new__(T.Controller)
        self.controller.deadline = 100
        self.controller.resize_unproven = False
        self.controller.bridge = Mock()
        self.controller.transcript = Mock()
        self.controller.main_menu_failure = T.MainMenuFailure()
        self.controller.main_menu_tail_needed = False
        self.controller.main_menu_tail_attempted = False
        self.controller.screen = Mock()

    def projected(self, output):
        line = output.getvalue()
        self.assertLessEqual(len(line.encode("ascii")), 512)
        self.assertNotIn("private-canary", line)
        self.assertTrue(line.startswith("application_tui_controller_failure="))
        value = json.loads(line.split("=", 1)[1])
        self.assertEqual(set(value), {"stage", "state", "ok", "app_exited", "app_exit_code", "forced_termination"})
        return value

    def test_running_predicate_failure_keeps_original_error_and_never_drains(self):
        cases = (
            dict(snapshot("poll"), app_exited=True, app_exit_code=1),
            dict(snapshot("poll"), state="finished"),
            dict(snapshot("poll"), ok=False, errors=["reader_failed"], forced_termination=True),
        )
        original_need = T.H.need
        for value in cases:
            T.validate_snapshot(value, "poll")
            self.controller.bridge.command.reset_mock()
            self.controller.bridge.command.return_value = value
            error = T.H.ProducerError("session_failed")
            def need(condition, code):
                if not condition:
                    self.assertEqual(code, "session_failed")
                    raise error
                return original_need(condition, code)
            with patch.object(T.H, "need", side_effect=need), redirect_stdout(io.StringIO()) as output:
                with self.assertRaises(T.H.ProducerError) as caught:
                    self.controller.poll()
            self.assertIs(caught.exception, error)
            self.assertEqual(self.projected(output), dict(stage="running_predicate", **{
                key: value[key] for key in ("state", "ok", "app_exited", "app_exit_code", "forced_termination")}))
            self.controller.bridge.command.assert_called_once_with("poll")
            self.controller.transcript.available.assert_not_called()

    def test_original_drain_bound_has_129_reads_and_null_reply(self):
        value = snapshot("poll")
        events = []
        self.controller.bridge.command.side_effect = lambda action: events.append(action) or value
        self.controller.transcript.available.side_effect = lambda: events.append("read") or b"x"
        with redirect_stdout(io.StringIO()) as output, self.assertRaisesRegex(T.H.ProducerError, "^session_failed$"):
            self.controller.poll()
        self.assertEqual(events, ["poll"] + ["read"] * 129)
        self.assertEqual(self.controller.screen.feed.call_count, 129)
        self.assertEqual(self.projected(output), dict(stage="drain_bound", state=None, ok=None,
            app_exited=None, app_exit_code=None, forced_termination=None))

    def test_wait_preserves_drain_exception_and_existing_poll_stage(self):
        self.controller.bridge.command.return_value = snapshot("poll")
        self.controller.transcript.available.return_value = b"x"
        with patch.object(T, "wait_failure_diagnostic") as diagnostic, redirect_stdout(io.StringIO()) as output:
            with self.assertRaisesRegex(T.H.ProducerError, "^session_failed$") as caught:
                self.controller.wait(lambda _: True)
        self.assertIs(diagnostic.call_args.args[0], caught.exception)
        self.assertEqual(diagnostic.call_args.args[1], "poll")
        self.assertEqual(self.projected(output)["stage"], "drain_bound")

    def test_success_at_last_permitted_read_is_silent(self):
        value = snapshot("poll")
        self.controller.bridge.command.return_value = value
        self.controller.transcript.available.side_effect = [b"x"] * 128 + [b""]
        with redirect_stdout(io.StringIO()) as output:
            self.assertIs(self.controller.poll(), value)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(self.controller.transcript.available.call_count, 129)
        self.assertEqual(self.controller.screen.feed.call_count, 128)
        self.controller.bridge.command.assert_called_once_with("poll")

    def test_bridge_error_and_deadline_do_not_invent_a_poll_predicate_or_drain_bound(self):
        error = T.H.ProducerError("session_failed")
        self.controller.bridge.command.side_effect = error
        with redirect_stdout(io.StringIO()) as output, self.assertRaises(T.H.ProducerError) as caught:
            self.controller.poll()
        self.assertIs(caught.exception, error)
        self.assertEqual(output.getvalue(), "")
        self.controller.transcript.available.assert_not_called()
        self.controller.bridge.command.side_effect = None
        self.controller.bridge.command.return_value = snapshot("poll")
        self.controller.deadline = 0
        with redirect_stdout(io.StringIO()) as output, self.assertRaisesRegex(T.H.ProducerError, "^deadline_exceeded$"):
            self.controller.poll()
        self.assertEqual(output.getvalue(), "")
        self.controller.transcript.available.assert_not_called()

    def test_broken_diagnostic_output_keeps_both_original_failures(self):
        for drain in (False, True):
            value = snapshot("poll") if drain else dict(snapshot("poll"), app_exited=True, app_exit_code=1)
            self.controller.bridge.command.return_value = value
            self.controller.transcript.available.return_value = b"x"
            with patch("builtins.print", side_effect=OSError("private-canary")), \
                    self.assertRaisesRegex(T.H.ProducerError, "^session_failed$"):
                self.controller.poll()
        self.assertEqual(self.controller.transcript.available.call_count, 129)

    def test_only_closed_validated_failed_reply_is_projected(self):
        valid = dict(snapshot("poll"), app_exited=True, app_exit_code=2**32 - 1)
        variants = [None, "private-canary", [], dict(valid, private="private-canary"),
                    dict(valid, action="start"), dict(valid, state="private-canary"),
                    dict(valid, app_exited=1), dict(valid, app_exit_code=True),
                    dict(valid, app_exit_code=-1), dict(valid, app_exit_code=2**32),
                    dict(valid, errors=["private-canary"]), dict(valid, forced_termination=1),
                    dict(valid, schema_version=True), dict(valid, ok=1), snapshot("poll")]
        for value in variants:
            with redirect_stdout(io.StringIO()) as output:
                T.controller_failure_diagnostic("running_predicate", value)
            self.assertEqual(output.getvalue(), "")
        for stage, value in (("private-canary", valid), ([], valid), (None, valid),
                             ("running_predicate\0", valid), ("drain_bound", valid)):
            with redirect_stdout(io.StringIO()) as output:
                T.controller_failure_diagnostic(stage, value)
            self.assertEqual(output.getvalue(), "")
        with patch.object(T.TuiBridge, "validate_session", side_effect=AssertionError("counter replay forbidden")), \
                redirect_stdout(io.StringIO()) as output:
            T.controller_failure_diagnostic("running_predicate", valid)
        self.assertEqual(self.projected(output)["app_exit_code"], 2**32 - 1)
        self.controller.bridge.command.return_value = dict(valid, private="private-canary")
        with redirect_stdout(io.StringIO()) as output, self.assertRaisesRegex(T.H.ProducerError, "^session_failed$"):
            self.controller.poll()
        self.assertEqual(output.getvalue(), "")
        self.controller.transcript.available.assert_not_called()


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.reader = T.Transcript(self.root)
        self.addCleanup(self.reader.close)

    def test_transcript_reads_only_new_bytes_and_detects_truncation(self):
        self.assertEqual(self.reader.available(), b"")
        path = self.root / "transcript.private"
        path.write_bytes(b"first")
        self.assertEqual(self.reader.available(), b"first")
        self.assertEqual(self.reader.available(), b"")
        with path.open("ab") as stream:
            stream.write(b" second")
        self.assertEqual(self.reader.available(), b" second")
        path.write_bytes(b"x")
        with self.assertRaises(T.H.ProducerError):
            self.reader.available()

    def test_transcript_rejects_replaced_root_before_read(self):
        with patch.object(T.H, "identity", return_value=(-1, -1)):
            with self.assertRaises(T.H.ProducerError):
                self.reader.available()

    def test_transcript_enforces_cap_before_read(self):
        info = Mock(st_dev=1, st_ino=2, st_size=8 * 1024 * 1024 + 1)
        self.reader.stream = Mock()
        self.reader.file_identity = (1, 2)
        with patch.object(T.H, "plain", return_value=info), patch.object(T.os, "fstat", return_value=info):
            with self.assertRaises(T.H.ProducerError):
                self.reader.available()
        self.reader.stream.read.assert_not_called()

    def test_transcript_rechecks_identity_and_requires_all_reported_bytes(self):
        before = Mock(st_dev=1, st_ino=2, st_size=5)
        replaced = Mock(st_dev=1, st_ino=3, st_size=5)
        self.reader.stream = Mock()
        self.reader.file_identity = (1, 2)
        self.reader.stream.read.return_value = b"first"
        with patch.object(T.H, "plain", side_effect=[before, replaced]), patch.object(T.os, "fstat", return_value=before):
            with self.assertRaises(T.H.ProducerError):
                self.reader.available()
        self.assertEqual(self.reader.offset, 0)
        self.reader.stream.read.return_value = b""
        with patch.object(T.H, "plain", return_value=before), patch.object(T.os, "fstat", return_value=before):
            with self.assertRaises(T.H.ProducerError):
                self.reader.available()
        self.assertEqual(self.reader.offset, 0)

    def test_wait_cannot_pass_when_poll_observation_or_predicate_overruns(self):
        for where in ("poll", "observe", "predicate"):
            controller = T.Controller(self.root, Mock())
            self.addCleanup(controller.close)
            controller.screen = Mock(ready=True, pending=False)
            controller.deadline = 100
            clock = [0]
            def bump(*_):
                clock[0] = 2
                return True
            with patch.object(T.time, "monotonic", side_effect=lambda: clock[0]), patch.object(controller, "poll", side_effect=bump if where == "poll" else lambda: {}):
                with self.assertRaises(T.H.ProducerError):
                    controller.wait(bump if where == "predicate" else lambda _: True, seconds=1,
                                    observe=bump if where == "observe" else None)

    def test_wait_reports_actual_failure_stage_and_rethrows_original_exception(self):
        for where in ("poll", "observe", "predicate"):
            with self.subTest(where=where):
                controller = T.Controller(self.root, Mock())
                self.addCleanup(controller.close)
                error = (T.S.ScreenError("sequence_unsupported") if where == "poll" else
                         T.H.ProducerError("preservation_failed") if where == "observe" else
                         ValueError("private-canary"))
                def fail(*_):
                    raise error
                with patch.object(controller, "poll", side_effect=fail if where == "poll" else lambda: {}), redirect_stdout(io.StringIO()) as output:
                    with self.assertRaises(type(error)) as caught:
                        controller.wait(fail if where == "predicate" else lambda _: True,
                                        observe=fail if where == "observe" else None)
                self.assertIs(caught.exception, error)
                rendered = output.getvalue()
                self.assertNotIn("private-canary", rendered)
                result = json.loads(rendered.split("=", 1)[1])
                self.assertEqual(result["stage"], where)
                self.assertEqual(result["predicate_invoked"], where == "predicate")
                self.assertEqual(result["reason_code"], error.args[0] if where != "predicate" else "unexpected_failure")

    def test_wait_output_failure_preserves_error_and_success_is_quiet(self):
        controller = T.Controller(self.root, Mock())
        self.addCleanup(controller.close)
        error = T.H.ProducerError("session_failed")
        with patch.object(controller, "poll", side_effect=error), patch("builtins.print", side_effect=OSError("private-canary")):
            with self.assertRaises(T.H.ProducerError) as caught:
                controller.wait(lambda _: True)
        self.assertIs(caught.exception, error)
        with patch.object(controller, "poll", return_value={}), redirect_stdout(io.StringIO()) as output:
            controller.wait(lambda _: True)
        self.assertEqual(output.getvalue(), "")

    def test_expired_controller_cannot_send_key_or_text(self):
        bridge = Mock()
        controller = T.Controller(self.root, bridge)
        self.addCleanup(controller.close)
        controller.deadline = 0
        for action in (lambda: controller.key("enter"), lambda: controller.text("x")):
            with self.assertRaises(T.H.ProducerError):
                action()
        bridge.command.assert_not_called()

    def test_slow_final_drain_cannot_qualify_an_observation_after_deadline(self):
        for where in ("empty_read", "nonempty_read", "feed"):
            with self.subTest(where=where):
                controller = T.Controller(self.root, Mock())
                self.addCleanup(controller.close)
                controller.deadline = 1
                clock = [0]
                def read():
                    if where != "feed":
                        clock[0] = 2
                    return b"" if where == "empty_read" else b"screen"
                def feed(_data):
                    clock[0] = 2
                controller.transcript = Mock()
                controller.transcript.available.side_effect = read
                controller.screen = Mock()
                controller.screen.feed.side_effect = feed
                with patch.object(T.time, "monotonic", side_effect=lambda: clock[0]):
                    with self.assertRaisesRegex(T.H.ProducerError, "deadline_exceeded"):
                        controller.drain()
                controller.transcript.available.assert_called_once_with()
                self.assertEqual(controller.screen.feed.call_count, int(where == "feed"))

    def test_control_input_rejects_terminal_injection_before_transport(self):
        bridge = Mock()
        controller = T.Controller(self.root, bridge)
        self.addCleanup(controller.close)
        for text in ("", "x" * 257, "x\n", "\x1b[A", "\x7f", "é", 4):
            with self.assertRaises(T.H.ProducerError):
                controller.text(text)
        for key in ("ctrl_c", "\x1b[A", [], None):
            with self.assertRaises(T.H.ProducerError):
                controller.key(key)
        bridge.command.assert_not_called()

    def test_resize_acknowledgment_cannot_make_screen_ready(self):
        bridge = Mock()
        bridge.command.return_value = {"ok": True}
        controller = T.Controller(self.root, bridge)
        self.addCleanup(controller.close)
        controller.screen.feed(b"\x1b[2J\x1b[Hold frame")
        controller.resize(80, 24)
        self.assertFalse(controller.screen.ready)

    def test_delayed_old_frame_after_resize_cannot_pass_wait(self):
        bridge = Mock()
        bridge.command.return_value = {"ok": True}
        controller = T.Controller(self.root, bridge)
        self.addCleanup(controller.close)
        controller.resize(80, 24)
        controller.screen.feed(b"\x1b[2J\x1b[Hold frame")
        self.assertTrue(controller.screen.ready)
        with self.assertRaises(T.H.ProducerError):
            controller.wait(lambda _: True)



class MainMenuFailureTests(unittest.TestCase):
    def record(self, operation="flow_reset", typed=False):
        return dict(operation=operation, category="typed_runtime_cleanup" if typed else "unknown",
                    cleanup=dict(stage="remove_tree", kind="other", os_code=32) if typed else None)

    def wire(self, value=None):
        return T.MainMenuFailure.PREFIX + json.dumps(self.record() if value is None else value,
                    separators=(",", ":")).encode("ascii") + b"\r\n"

    def test_both_operations_and_unknown_remain_exact(self):
        for operation in ("flow_reset", "provider_refresh"):
            for typed in (False, True):
                value=self.record(operation, typed);reader=T.MainMenuFailure();reader.feed(self.wire(value))
                self.assertEqual(reader.projection(),dict(status="observed",**value))

    def test_every_split_and_single_byte_chunks_preserve_one_record(self):
        wire=b"private-prefix\x1b[0m"+self.wire(self.record("provider_refresh",True))+b"\x1b[?25h"
        for split in range(len(wire)+1):
            reader=T.MainMenuFailure();reader.feed(wire[:split]);reader.feed(wire[split:])
            self.assertEqual(reader.projection()["status"],"observed")
        reader=T.MainMenuFailure()
        for value in wire:reader.feed(bytes([value]))
        self.assertEqual(reader.projection()["cleanup"]["os_code"],32)

    def test_duplicate_records_are_ambiguous_without_selecting_one(self):
        for wire in (self.wire()*2,self.wire()+self.wire(self.record("provider_refresh",True))):
            reader=T.MainMenuFailure();reader.feed(wire)
            self.assertEqual(reader.projection(),dict(status="ambiguous",operation=None,category=None,cleanup=None))

    def test_duplicate_keys_private_canaries_and_unknown_fields_rejected(self):
        raw=b'{"operation":"flow_reset","category":"unknown","cleanup":null,"operation":"provider_refresh"}'
        variants=[raw,b'{',b'null',b'{"private":"canary"}',json.dumps(dict(self.record(),private="canary")).encode()]
        for payload in variants:
            reader=T.MainMenuFailure();reader.feed(reader.PREFIX+payload+b"\n")
            self.assertEqual(reader.projection()["status"],"invalid")
            self.assertNotIn("canary",json.dumps(reader.projection()))

    def test_cleanup_types_bounds_and_conditional_fields_are_strict(self):
        mutations=[dict(self.record(),operation="flow_reset\x00"),dict(self.record(),operation=True),
                   dict(self.record(),category="remove_tree"),dict(self.record(),cleanup={}),
                   dict(self.record(typed=True),cleanup=None)]
        for key,val in (("stage","unknown"),("kind","canary"),("os_code",True),("os_code",-1),("os_code",65536),("os_code","32"),("extra","canary")):
            value=self.record(typed=True);value["cleanup"][key]=val;mutations.append(value)
        for value in mutations:
            with self.assertRaises(ValueError):T.MainMenuFailure.parse(json.dumps(value).encode())
        for code in (None,0,65535):
            value=self.record(typed=True);value["cleanup"]["os_code"]=code
            self.assertEqual(T.MainMenuFailure.parse(json.dumps(value).encode()),value)

    def test_incomplete_and_oversized_record_never_observed(self):
        for wire in (self.wire()[:-2],T.MainMenuFailure.PREFIX+b"x"*513,T.MainMenuFailure.PREFIX+b"x"*513+b"\n",b"x"*65537):
            reader=T.MainMenuFailure();reader.feed(wire)
            self.assertEqual(reader.projection()["status"],"invalid")
            self.assertLessEqual(len(reader.buffer),512)

    def test_large_unrelated_chunks_keep_only_bounded_prefix_tail(self):
        reader=T.MainMenuFailure()
        for _ in range(129):
            reader.feed(b"private-canary"*4096)
            self.assertLess(len(reader.buffer),len(reader.PREFIX))
        self.assertEqual(reader.projection()["status"],"not_observed")
        output=io.StringIO()
        with redirect_stdout(output):reader.emit()
        self.assertEqual(output.getvalue(),"")

    def test_emit_once_is_finite_and_output_failure_is_not_retried(self):
        reader=T.MainMenuFailure();reader.feed(self.wire(self.record("provider_refresh",True)))
        output=io.StringIO()
        with redirect_stdout(output):reader.emit();reader.emit()
        lines=output.getvalue().splitlines();self.assertEqual(len(lines),1)
        self.assertLess(len(lines[0])+1,1024)
        self.assertTrue(lines[0].startswith("application_tui_main_menu_failure="))
        reader=T.MainMenuFailure();reader.feed(self.wire())
        with patch("builtins.print",side_effect=OSError("private-canary")) as printing:
            reader.emit();reader.emit();self.assertEqual(printing.call_count,1)

    def controller(self):
        value=object.__new__(T.Controller);value.deadline=10**30
        value.transcript=Mock();value.screen=Mock();value.main_menu_failure=T.MainMenuFailure()
        value.main_menu_tail_needed=False;value.main_menu_tail_attempted=False
        return value

    def test_original_reads_and_screen_failure_remain_unchanged(self):
        controller=self.controller();wire=self.wire()
        controller.transcript.available.side_effect=[wire,b""]
        controller.drain()
        self.assertEqual(controller.transcript.available.call_count,2)
        controller.screen.feed.assert_called_once_with(wire)
        controller=self.controller();error=RuntimeError("original-screen-error")
        controller.transcript.available.return_value=wire;controller.screen.feed.side_effect=error
        with self.assertRaises(RuntimeError) as raised:controller.drain()
        self.assertIs(raised.exception,error);controller.transcript.available.assert_called_once_with()
        self.assertEqual(controller.main_menu_failure.projection()["status"],"observed")

    def test_parser_failure_cannot_replace_screen_or_change_read_count(self):
        controller=self.controller();error=RuntimeError("original-screen-error")
        controller.transcript.available.return_value=b"data";controller.screen.feed.side_effect=error
        controller.main_menu_failure=Mock();controller.main_menu_failure.feed.side_effect=ValueError("private-canary")
        with self.assertRaises(RuntimeError) as raised:controller.drain()
        self.assertIs(raised.exception,error);controller.transcript.available.assert_called_once_with()
        controller.screen.feed.assert_called_once_with(b"data")

    def test_close_failure_is_same_object_before_best_effort_emission(self):
        controller=self.controller();events=[];error=OSError("original-close-error")
        def close():events.append("close");raise error
        def emit():events.append("emit");raise ValueError("private-canary")
        controller.transcript.close.side_effect=close
        controller.main_menu_failure=Mock();controller.main_menu_failure.emit.side_effect=emit
        with self.assertRaises(OSError) as raised:controller.close()
        self.assertIs(raised.exception,error);self.assertEqual(events,["close","emit"])
        controller.transcript.available.assert_not_called()


class MainMenuTailTests(unittest.TestCase):
    record = MainMenuFailureTests.record
    wire = MainMenuFailureTests.wire
    controller = MainMenuFailureTests.controller

    def test_failed_poll_retains_error_then_close_reads_without_screen_or_commands(self):
        controller=self.controller();controller.bridge=Mock()
        controller.bridge.command.return_value=dict(snapshot("poll"),app_exited=True,app_exit_code=1)
        original=T.H.ProducerError("session_failed")
        with patch.object(T.H,"need",side_effect=original),patch("builtins.print"):
            with self.assertRaises(T.H.ProducerError) as raised:controller.poll()
        self.assertIs(raised.exception,original)
        controller.transcript.available.assert_not_called()
        events=[]
        def bridge_close():events.append("bridge_close")
        controller.bridge.close.side_effect=bridge_close
        def available():events.append("read");return self.wire() if events.count("read")==1 else b""
        controller.transcript.available.side_effect=available
        controller.transcript.close.side_effect=lambda:events.append("transcript_close")
        controller.bridge.close()
        with patch("builtins.print") as printing:controller.close()
        self.assertEqual(events,["bridge_close","read","read","transcript_close"])
        controller.bridge.command.assert_called_once_with("poll")
        controller.screen.feed.assert_not_called()
        self.assertIn('"status":"observed"',printing.call_args.args[0])

    def test_every_tail_split_and_previously_drained_prefix(self):
        wire=self.wire()
        for split in range(1,len(wire)):
            with self.subTest(split=split):
                controller=self.controller();controller.main_menu_tail_needed=True
                controller.main_menu_failure.feed(wire[:split])
                controller.transcript.available.side_effect=[wire[split:],b""]
                with patch("builtins.print"):controller.close()
                self.assertEqual(controller.main_menu_failure.projection()["status"],"observed")
                self.assertEqual(controller.transcript.available.call_count,2)
                controller.screen.feed.assert_not_called()

    def test_read_error_invalidates_previously_complete_record(self):
        for error in (OSError("private-canary"),T.H.ProducerError("preservation_failed")):
            controller=self.controller();controller.main_menu_tail_needed=True
            controller.main_menu_failure.feed(self.wire())
            controller.transcript.available.side_effect=error
            with patch("builtins.print") as printing:controller.close()
            self.assertEqual(controller.main_menu_failure.projection(),dict(status="invalid",operation=None,category=None,cleanup=None))
            controller.transcript.close.assert_called_once_with()
            self.assertNotIn("private-canary",printing.call_args.args[0])

    def test_bad_tail_never_selects_partial_cause(self):
        cases=[([self.wire(),self.wire(),b""],"ambiguous"),
               ([self.wire()[:-2],b""],"invalid"),
               ([T.MainMenuFailure.PREFIX+b"private-canary\n",b""],"invalid"),
               ([b"x"*65537,b""],"invalid")]
        for chunks,status in cases:
            controller=self.controller();controller.main_menu_tail_needed=True
            controller.transcript.available.side_effect=chunks
            with patch("builtins.print") as printing:controller.close()
            self.assertEqual(controller.main_menu_failure.projection(),dict(status=status,operation=None,category=None,cleanup=None))
            self.assertNotIn("private-canary",printing.call_args.args[0])

    def test_bound_is_consumed_once_and_invalidates_prior_record(self):
        controller=self.controller();controller.main_menu_tail_needed=True
        controller.main_menu_failure.feed(self.wire())
        controller.transcript.available.return_value=b"x"
        with patch("builtins.print") as printing:controller.close();controller.close()
        self.assertEqual(controller.transcript.available.call_count,129)
        self.assertEqual(controller.transcript.close.call_count,2)
        self.assertEqual(printing.call_count,1)
        self.assertEqual(controller.main_menu_failure.projection()["status"],"invalid")

    def test_success_close_never_reads_and_empty_stops_immediately(self):
        controller=self.controller()
        with patch("builtins.print"):controller.close()
        controller.transcript.available.assert_not_called()
        controller=self.controller();controller.main_menu_tail_needed=True
        controller.transcript.available.return_value=b""
        with patch("builtins.print") as printing:controller.close();controller.close()
        controller.transcript.available.assert_called_once_with();printing.assert_not_called()

    def test_parser_and_close_errors_preserve_original_close_object(self):
        controller=self.controller();controller.main_menu_tail_needed=True
        controller.transcript.available.return_value=self.wire()
        controller.main_menu_failure.feed=Mock(side_effect=ValueError("private-canary"))
        original=OSError("original-close-error");controller.transcript.close.side_effect=original
        with patch("builtins.print") as printing:
            with self.assertRaises(OSError) as raised:controller.close()
        self.assertIs(raised.exception,original)
        controller.transcript.available.assert_called_once_with()
        self.assertEqual(controller.main_menu_failure.projection()["status"],"invalid")
        self.assertNotIn("private-canary",printing.call_args.args[0])

    def test_no_clock_or_retry_when_original_deadline_already_elapsed(self):
        controller=self.controller();controller.main_menu_tail_needed=True;controller.deadline=-1
        controller.transcript.available.side_effect=[self.wire(),b""]
        with patch.object(T.time,"monotonic",side_effect=AssertionError("new_clock")),patch.object(T.time,"sleep",side_effect=AssertionError("new_wait")),patch("builtins.print"):
            controller.close()
        self.assertEqual(controller.main_menu_failure.projection()["status"],"observed")


if __name__ == "__main__":
    unittest.main()
