"""Pure policy/receipt controls; no process, compiler or application is invoked."""
import importlib.util
import io
import json
from pathlib import Path
import queue
import tempfile
import threading
import types
import unittest
from unittest import mock
from contextlib import ExitStack, redirect_stdout, redirect_stderr

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("readiness_calibration", ROOT / "scripts/application-lab/calibrate_helper_readiness.py")
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)
H = C.H


class CalibrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def bridge(self, cls=C.CalibrationBridge):
        bridge = object.__new__(cls)
        bridge.case, bridge.last = self.root, None
        bridge.messages = queue.Queue()
        bridge.failed, bridge.done = threading.Event(), threading.Event()
        bridge.response_lock = threading.Lock()
        bridge.calls = bridge.responses = 0
        bridge.ready = bridge.closed_ready = bridge.forced = False
        bridge.stage_bytes = bytearray(b"application_bridge_stage=compile\napplication_bridge_stage=compiled\n")
        bridge.stage_invalid = False
        bridge.ready_timing = cls.ready_timing_type(0)
        bridge.ready_timing.stage_value = (bytes(bridge.stage_bytes), 0.2, 69)
        bridge.deadline = 165
        bridge.process = mock.Mock(returncode=0)
        bridge.process.poll.return_value = None
        bridge.process.finalize.return_value = True
        bridge.close_calls, bridge.close_result = 0, None
        bridge.threads, bridge.transport = [], {}
        bridge.watchdog = mock.Mock()
        bridge.watchdog.is_alive.return_value = False
        return bridge

    def reply(self, bridge, action):
        def write(_):
            bridge.responses += 1
            bridge.messages.put(json.dumps(dict(schema_version=1, action=action, ok=True,
                state="ready" if action == "ready" else "closed")).encode())
        bridge.process.stdin.write.side_effect = write

    def test_distinct_ready_budget_uses_remaining_lifetime_without_reset(self):
        for cls, cap in ((H.Bridge, 90), (C.CalibrationBridge, 120)):
            for remaining in (165, 90, 89.5, 12.5):
                with self.subTest(cls=cls.__name__, remaining=remaining):
                    bridge = self.bridge(cls)
                    bridge.deadline = remaining
                    self.reply(bridge, "ready")
                    bridge.messages.get = mock.Mock(wraps=bridge.messages.get)
                    with mock.patch.object(H.time, "monotonic", return_value=0), redirect_stdout(io.StringIO()):
                        bridge.command("ready")
                    bridge.messages.get.assert_called_once_with(timeout=min(cap, remaining))
                    self.assertEqual(bridge.deadline, remaining)
        for cls in (H.Bridge, C.CalibrationBridge):
            for remaining in (165, 35, 34.5, 12.5):
                with self.subTest(cls=cls.__name__, later_remaining=remaining):
                    bridge = self.bridge(cls)
                    bridge.deadline = remaining
                    bridge.ready = True
                    bridge.calls = bridge.responses = 1
                    self.reply(bridge, "close_ready")
                    bridge.messages.get = mock.Mock(wraps=bridge.messages.get)
                    with mock.patch.object(H.time, "monotonic", return_value=0):
                        bridge.command("close_ready")
                    bridge.messages.get.assert_called_once_with(timeout=min(35, remaining))
                    self.assertEqual(bridge.deadline, remaining)
                    self.assertTrue(bridge.closed_ready)

    def test_normal_ninety_timeout_poison_cannot_be_reset_or_closed_as_success(self):
        bridge = self.bridge(H.Bridge)
        bridge.messages.get = mock.Mock(side_effect=queue.Empty)
        with mock.patch.object(H.time, "monotonic", side_effect=[.01, .02, 90.02]), redirect_stdout(io.StringIO()):
            with self.assertRaises(H.ProducerError):
                bridge.command("ready")
        bridge.messages.get.assert_called_once_with(timeout=90)
        self.assertEqual(bridge.deadline, 165)
        self.assertTrue(bridge.failed.is_set())
        writes = bridge.process.stdin.write.call_count
        bridge.ready_timing.stage(bytes(bridge.stage_bytes), False)
        with redirect_stdout(io.StringIO()), self.assertRaises(H.ProducerError):
            bridge.command("ready")
        self.assertEqual(bridge.process.stdin.write.call_count, writes)
        bridge.process.poll.return_value = 0
        with redirect_stdout(io.StringIO()):
            self.assertFalse(bridge.close())
        bridge.process.mark_uncertain.assert_called_once()
        self.assertEqual(bridge.deadline, 165)

    def test_normal_timing_accepts_ninety_bound_but_not_calibration_allowance(self):
        value = H.ready_timing_projection((0, .2, 59.266, .01, .02, 90, 90.02), "wait", "timeout")
        self.assertEqual(value["status"], "observed")
        self.assertEqual(value["wait_budget_ms"], 90000)
        for budget in (90.001, 120, True):
            with self.subTest(budget=budget):
                value = H.ready_timing_projection((0, .2, 59.266, .01, .02, budget, 121), "wait", "timeout")
                self.assertEqual(value["status"], "unavailable")

    def test_calibration_can_observe_ready_after_sixty_without_changing_normal_schema(self):
        bridge = self.bridge()
        self.reply(bridge, "ready")
        with mock.patch.object(H.time, "monotonic", side_effect=[0.01, 0.02, 70]):
            bridge.command("ready")
        self.assertEqual(bridge.ready_timing.record["status"], "observed")
        self.assertEqual(bridge.ready_timing.record["observed_end_ms"], 70000)
        self.assertEqual(bridge.ready_timing.record["wait_budget_ms"], 120000)
        self.assertEqual(H.ready_timing_projection((0, 1, 2, 3, 4, 120, 70), "wait", "timeout")["status"], "unavailable")

    def test_all_application_actions_are_rejected_before_transport(self):
        for action in ("start", "start_source", "start_source_observed", "poll", "finish", "ctrl_c", "observe_runtime"):
            with self.subTest(action=action), redirect_stdout(io.StringIO()):
                bridge = self.bridge()
                bridge.ready = True
                bridge.calls = bridge.responses = 1
                with self.assertRaises(H.ProducerError):
                    bridge.command(action)
                bridge.process.stdin.write.assert_not_called()
                self.assertTrue(bridge.failed.is_set())

    def test_ready_timeout_stays_failed_after_late_marker_and_zero_exit(self):
        bridge = self.bridge()
        bridge.ready_timing.stage_value = (b"application_bridge_stage=compile\n", 0.2, None)
        bridge.stage_bytes = bytearray(bridge.ready_timing.stage_value[0])
        bridge.messages.get = mock.Mock(side_effect=queue.Empty)
        with mock.patch.object(H.time, "monotonic", side_effect=[0.01, 0.02, 120.02]), redirect_stdout(io.StringIO()):
            with self.assertRaises(H.ProducerError):
                bridge.command("ready")
        first = dict(bridge.ready_timing.record)
        bridge.ready_timing.stage(b"application_bridge_stage=compile\napplication_bridge_stage=compiled\n", False)
        bridge.ready_timing.capture(b"", False, "reply", "passed")
        self.assertEqual(bridge.ready_timing.record, first)
        self.assertEqual(first["outcome"], "timeout")
        self.assertIsNone(first["compiled_seen_ms"])
        bridge.process.poll.return_value = 0
        with redirect_stdout(io.StringIO()):
            self.assertFalse(bridge.close())
        self.assertTrue(bridge.failed.is_set())
        self.assertEqual(bridge.close_calls, 1)
        bridge.process.mark_uncertain.assert_called_once()

    def test_invalid_late_or_regressing_clocks_cannot_make_passed_timing(self):
        for snapshot in ((0, .2, 69, .01, .02, 120, 121), (0, .2, 69, .01, .02, 120, 166),
                (0, 5, 4, .01, .02, 120, 70), (0, .2, 69, .01, .02, True, 70),
                (0, .2, None, .01, .02, 120, 70), (0, .2, 69, .01, .02, 120, float("nan"))):
            with self.subTest(snapshot=snapshot):
                value = C.projection(snapshot, "reply", "passed")
                self.assertEqual(value["status"], "unavailable")
                self.assertTrue(all(value[key] is None for key in C.TIMING_FIELDS))

    def successful_instance(self):
        return types.SimpleNamespace(close_calls=1, close_result=True, closed_ready=True,
            failed=threading.Event(), forced=False, calls=2, responses=2,
            ready_timing=types.SimpleNamespace(record=C.projection((0, .2, 69, .01, .02, 120, 70), "reply", "passed")))

    def fake_run(self, instance=None, *, probe_result=0, second_rows=None, source_error=None):
        instance = instance or self.successful_instance()
        rows = [dict(path="synthetic-source", bytes=1, sha256="a"*64)]
        def probe(factory):
            factory(self.root)
            return probe_result
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(H, "hosted_guard"))
            stack.enter_context(mock.patch.dict(C.os.environ, {"GITHUB_SHA":"b"*40,
                "ImageOS":"win25", "ImageVersion":"20261018.275.1"}))
            stack.enter_context(mock.patch.object(C, "CalibrationBridge", return_value=instance))
            stack.enter_context(mock.patch.object(H, "bridge_probe", side_effect=probe))
            stack.enter_context(mock.patch.object(C, "source_rows", side_effect=[rows,
                source_error if source_error is not None else rows if second_rows is None else second_rows]))
            return C.run()

    def test_report_pass_requires_probe_closure_timing_and_sources(self):
        result = self.fake_run()
        self.assertEqual(result["result"], "passed")
        self.assertTrue(result["helper_closed"] and result["sources_unchanged"])
        self.assertEqual(result["runner_image"], {"os":"win25", "version":"20261018.275.1"})
        for key in ("application_started", "runtime_observed", "provider_accepted"):
            self.assertIs(result[key], False)
        self.assertLess(len(json.dumps(result)), 16384)

    def test_failed_or_uncertain_close_never_earns_calibration_pass(self):
        for field, value in (("close_result", False), ("close_calls", 2), ("forced", True),
                ("closed_ready", False), ("responses", 1)):
            with self.subTest(field=field):
                instance = self.successful_instance()
                setattr(instance, field, value)
                self.assertEqual(self.fake_run(instance)["result"], "failed")
        instance = self.successful_instance()
        instance.failed.set()
        self.assertEqual(self.fake_run(instance)["result"], "failed")
        self.assertEqual(self.fake_run(probe_result=1)["result"], "failed")

    def test_late_source_change_or_read_failure_preserves_timing_without_credit(self):
        for kwargs in (dict(second_rows=[]), dict(source_error=H.ProducerError("private-canary"))):
            result = self.fake_run(**kwargs)
            self.assertEqual(result["result"], "failed")
            self.assertFalse(result["sources_unchanged"])
            self.assertEqual(result["timing"]["observed_end_ms"], 70000)
            self.assertNotIn("private-canary", json.dumps(result))

    def test_duplicate_or_malformed_ready_reply_cannot_be_promoted(self):
        for raw in (b'{}', b'{"schema_version":true,"action":"ready","ok":true,"state":"ready"}'):
            bridge = self.bridge()
            def write(_):
                bridge.responses += 1
                bridge.messages.put(raw)
            bridge.process.stdin.write.side_effect = write
            with mock.patch.object(H.time, "monotonic", side_effect=[.01, .02, 1]), redirect_stdout(io.StringIO()):
                with self.assertRaises(H.ProducerError):
                    bridge.command("ready")
            self.assertTrue(bridge.failed.is_set())
            self.assertFalse(bridge.ready)

    def test_create_only_report_refuses_existing_destination_before_probe(self):
        report = self.root / "report.json"
        report.write_bytes(b"original")
        with mock.patch.object(H, "hosted_guard"), mock.patch.object(C, "run") as run, redirect_stderr(io.StringIO()):
            self.assertEqual(C.main(["--report", str(report)]), 1)
        run.assert_not_called()
        self.assertEqual(report.read_bytes(), b"original")

    def test_cli_rejects_application_options_and_writes_only_closed_report(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            C.main(["--report", "unused", "--application", "private-canary"])
        report = self.root / "report.json"
        result = self.fake_run()
        with mock.patch.object(H, "hosted_guard"), mock.patch.object(C, "run", return_value=result), \
                mock.patch.object(C.signal, "signal", return_value=None), redirect_stdout(io.StringIO()):
            self.assertEqual(C.main(["--report", str(report)]), 0)
        self.assertEqual(json.loads(report.read_bytes()), result)

    def test_pr_job_does_not_warm_or_replace_any_application_or_nightly_gate(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        job = workflow.split("  helper-readiness-calibration:\n", 1)[1].split("  audit:\n", 1)[0]
        self.assertIn("if: github.event_name == 'pull_request'", job)
        self.assertIn("needs: revision", job)
        self.assertIn("runs-on: windows-latest", job)
        self.assertEqual(job.count("calibrate_helper_readiness.py"), 1)
        self.assertNotIn("continue-on-error", job)
        self.assertNotIn("download-artifact", job)
        self.assertNotIn("--application", job)
        release = workflow.split("  release:\n", 1)[1]
        self.assertNotIn("helper-readiness-calibration", release.split("    if:", 1)[0])
        self.assertIn("--bridge-probe", workflow)
        self.assertIn("--backend $env:FILESYSTEM_BACKEND", workflow)


if __name__ == "__main__":
    unittest.main()
