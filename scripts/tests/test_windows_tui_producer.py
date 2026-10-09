"""Mocked producer lifecycle regressions; never launch the app or HTTP servers."""
from contextlib import ExitStack
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

PATH = Path(__file__).resolve().parents[1] / "application-lab/run_windows_tui.py"
SPEC = importlib.util.spec_from_file_location("tui_producer_tested", PATH)
P = importlib.util.module_from_spec(SPEC)
with patch.object(subprocess, "Popen", side_effect=AssertionError("no processes")), \
        patch.object(socket, "socket", side_effect=AssertionError("no sockets")):
    SPEC.loader.exec_module(P)

RUNTIME = {"version": "1.75.2", "sha256": "a" * 64, "platform": "windows"}
APP = b"mock application bytes"
APP_SHA = P.H.sha(APP)


class ProducerFlowTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.directory = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.root = Path(self.directory)
        self.stack.enter_context(patch.object(subprocess, "Popen", side_effect=AssertionError("no processes")))
        self.stack.enter_context(patch.object(socket, "socket", side_effect=AssertionError("no sockets")))
        self.fixtures = []
        self.config = types.SimpleNamespace(data=b"config")
        self.removed = self.mock(P.H, "remove_owned")
        self.mock(P.H, "prepare")
        self.mock(P.H, "identity", return_value=(1, 2))
        self.mock(P.H, "create_private_roots", return_value={})
        self.mock(P.H, "private_directory")
        self.mock(P.H, "private_write")
        self.mock(P.H, "prestart_baseline", return_value={})
        self.mock(P.H, "post_helper_preserved")
        self.mock(P.H, "environment", return_value={})
        self.mock(P.H, "read", side_effect=lambda path, *_args, **_kwargs:
                  APP if Path(path).name == "application.exe" or Path(path).name == "source.exe" else b"config")
        self.mock(P.O, "validate_manual_config", return_value=self.config)
        self.listing = self.mock(P.O, "validate_listing", return_value={"files": 4, "directories": 2,
            "csv_sha256": "b" * 64, "xlsx_sha256": "c" * 64})
        self.acquisition = self.mock(P.O, "validate_acquisition", side_effect=lambda *_a, **kw:
            types.SimpleNamespace(cancelled=kw.get("outcome") == "cancelled"))
        self.partial = self.mock(P, "partial_active", return_value=True)
        self.bridge = Mock()
        self.finished = False
        self.bridge.command.side_effect = self.command
        self.bridge.close.side_effect = lambda: self.finished
        self.mock(P.T, "TuiBridge", return_value=self.bridge)
        self.controller = Mock(deadline=float("inf"))
        self.controller.screen.alternate = False
        self.controller.screen.cursor_visible = True
        self.controller.wait.side_effect = self.wait
        self.mock(P.T, "Controller", return_value=self.controller)
        self.mock(P.F, "serve_http", side_effect=self.serve)
        self.nav = Mock(state="unknown")
        self.nav.configure_http.side_effect = self.configure
        self.nav.begin_acquisition.side_effect = self.begin
        self.nav.wait_complete.side_effect = lambda: setattr(self.nav, "state", "complete")
        self.nav.cancel_acquisition.side_effect = self.cancel
        self.mock(P.N, "Navigator", side_effect=self.navigator)

    def mock(self, target, name, **kwargs):
        return self.stack.enter_context(patch.object(target, name, **kwargs))

    def command(self, action, **fields):
        if action == "ready":
            return {"schema_version": 1, "action": "ready", "ok": True, "state": "ready"}
        result = dict(action=action, ok=True, state="running", app_exited=action == "poll",
                      app_exit_code=0 if action in ("poll", "finish") else None,
                      runtime_image_observed=True, runtime_sha256=RUNTIME["sha256"], runtime_process_count=1,
                      forced_termination=False)
        if action == "finish":
            result.update(state="finished", **{key: True for key in P.H.SESSION_CLEANUP})
            self.finished = True
        self.bridge.last = result
        return result

    def serve(self, state):
        server = Mock(endpoint="http://127.0.0.1:" + str(21000 + len(self.fixtures)) + "/", cleanup_complete=True)
        def snapshot():
            value = state.snapshot()
            value["transport"] = dict(cleanup_complete=True, active=0, workers_alive=0,
                                      watchdog_alive=False, acceptor_alive=False)
            return value
        server.snapshot.side_effect = snapshot
        context = Mock()
        context.__enter__ = Mock(return_value=server)
        context.__exit__ = Mock(return_value=False)
        self.fixtures.append((state, server, context))
        return context

    def navigator(self, _controller, observe):
        self.observe = observe
        return self.nav

    def configure(self, remote, endpoint):
        self.remote = remote
        state = self.fixtures[-1][0]
        state._event("observation")
        state.observation_started.set()
        state.counters.update(requests=6, heads=4, gets=2, directory_reads=2)
        self.observe("files", {})

    def begin(self):
        state = self.fixtures[-1][0]
        state._event("download_observation", state.selected_member)
        state.download_started.set()
        self.observe("acquisition", {})
        state._event("content", state.selected_member)
        state.counters["content_reads"] = 1
        if state.mode == "cancellation":
            state._event("cancel_prefix", state.selected_member)
            state.cancel_started.set()
        self.nav.state = "acquiring"

    def wait(self, predicate, *, seconds, observe):
        observe({})
        if not predicate(self.controller.screen):
            raise P.H.ProducerError("deadline_exceeded")

    def cancel(self):
        state = self.fixtures[-1][0]
        state.cancel_disconnected = True
        state._event("cancel_disconnected", state.selected_member)
        self.nav.state = "complete"

    def execute(self, name="manual_acquisition"):
        return P.run_case(name, self.root, self.root / "source.exe", APP_SHA, RUNTIME)

    def test_all_three_mocked_flows_finish_with_exact_case_checks(self):
        # Separate test instances avoid sharing observations between cases.
        result = self.execute()
        self.assertEqual(result["status"], "passed")
        self.assertEqual(set(result["checks"]), P.CHECKS["manual_acquisition"])
        self.assertTrue(all(result["checks"].values()))
        self.nav.wait_main.assert_called_once_with()
        self.assertEqual(self.listing.call_count, 2)
        self.removed.assert_called_once()

    def test_active_cancellation_requires_partial_runtime_and_manifest(self):
        result = self.execute("escape_cancellation")
        self.assertEqual(result["status"], "passed")
        self.nav.cancel_acquisition.assert_called_once_with()
        self.assertTrue(result["checks"]["active_partial"])
        self.assertTrue(result["checks"]["cancelled_result"])

    def test_reset_rechecks_second_listing_and_preserves_prior_acquisition(self):
        result = self.execute("session_reset")
        self.assertEqual(result["status"], "passed")
        self.assertEqual(len(result["listing_observations"]), 2)
        self.assertEqual(self.listing.call_count, 3)
        self.nav.back_to_main.assert_called_once_with()
        self.assertEqual(len(self.acquisition.call_args.kwargs["prior"]), 1)

    def test_missing_active_partial_cannot_send_cancel(self):
        self.partial.return_value = False
        result = self.execute("escape_cancellation")
        self.assertEqual(result["status"], "failed")
        self.nav.cancel_acquisition.assert_not_called()
        self.assertFalse(result["checks"]["process_cleanup"])
        self.removed.assert_not_called()

    def test_late_listing_mutation_cannot_retain_a_pass(self):
        original = self.listing.return_value
        self.listing.side_effect = [original, dict(original, csv_sha256="d" * 64)]
        result = self.execute()
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["checks"]["listing_artifacts"])
        self.assertEqual(result["failure_code"], "tui_artifacts_invalid")

    def test_bridge_constructor_failure_cannot_authorize_removal(self):
        self.mock(P.T, "TuiBridge", side_effect=RuntimeError("private-canary"))
        result = self.execute()
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["checks"]["process_cleanup"])
        self.removed.assert_not_called()
        self.assertNotIn("private-canary", str(result))

    def test_uncertain_fixture_start_cannot_authorize_removal(self):
        context = Mock()
        context.__enter__ = Mock(side_effect=RuntimeError("private-canary"))
        self.mock(P.F, "serve_http", return_value=context)
        result = self.execute()
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["checks"]["fixture_cleanup"])
        self.removed.assert_not_called()

    def test_transcript_close_failure_preserves_case(self):
        self.controller.close.side_effect = RuntimeError("private-canary")
        result = self.execute()
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["checks"]["process_cleanup"])
        self.removed.assert_not_called()

    def test_runtime_mismatch_is_sticky_even_if_other_components_succeed(self):
        def wrong(action, **fields):
            value = self.command(action, **fields)
            if action == "observe_runtime":
                value["runtime_sha256"] = "0" * 64
            return value
        self.bridge.command.side_effect = wrong
        result = self.execute()
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["checks"]["runtime_setup"])
        self.nav.select_one.assert_not_called()

    def test_late_old_source_request_invalidates_reset(self):
        def late_close():
            self.fixtures[0][0].counters["heads"] += 1
            return self.finished
        self.bridge.close.side_effect = late_close
        result = self.execute("session_reset")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failure_code"], "tui_fixture_invalid")
        self.assertEqual(result["failure_phase"], "artifact_validation")

        self.assertFalse(result["checks"]["reset_source_replaced"])
        self.assertFalse(result["checks"]["prior_acquisition_preserved"])

    def test_failed_second_fixture_never_credits_source_replacement(self):
        def start(state):
            second = bool(self.fixtures)
            context = self.serve(state)
            if second:
                context.__enter__.side_effect = RuntimeError("private diagnostic must not enter receipt")
            return context
        P.F.serve_http.side_effect = start
        self.bridge.close.side_effect = lambda: bool(self.command("finish"))
        result = self.execute("session_reset")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failure_phase"], "fixture_start")
        self.assertEqual(result["failure_code"], "unexpected_failure")
        self.assertFalse(result["checks"]["reset_source_replaced"])
        self.assertFalse(result["checks"]["prior_acquisition_preserved"])
        self.assertFalse(result["checks"]["fixture_cleanup"])
        self.removed.assert_not_called()

    def test_failure_phase_keeps_first_error_and_never_copies_diagnostics(self):
        self.nav.wait_main.side_effect = RuntimeError("private diagnostic")
        self.controller.close.side_effect = RuntimeError("second private diagnostic")
        result = self.execute("manual_acquisition")
        self.assertEqual(result["failure_phase"], "main_menu")
        self.assertEqual(result["failure_code"], "unexpected_failure")
        self.assertNotIn("private diagnostic", str(result))

    def test_final_screen_processing_cannot_cross_deadline_and_pass(self):
        self.controller.screen.finish.side_effect = lambda: setattr(self.controller, "deadline", 0)
        result = self.execute("manual_acquisition")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failure_phase"], "session_cleanup")
        self.assertFalse(result["checks"]["terminal_closed"])


class SourceBindingTests(unittest.TestCase):
    def test_independent_receipt_validator_matches_producer_contract_and_bindings(self):
        source = PATH.parents[1] / "tui_application_evidence.py"
        spec = importlib.util.spec_from_file_location("independent_tui_validator", source)
        evidence = importlib.util.module_from_spec(spec)
        with patch.object(subprocess, "Popen", side_effect=AssertionError("no processes")), \
                patch.object(socket, "socket", side_effect=AssertionError("no sockets")):
            spec.loader.exec_module(evidence)
            self.assertEqual(P.CASE_ORDER, evidence.CASE_ORDER)
            self.assertEqual(P.CHECKS, evidence.CASE_CHECKS)
            self.assertEqual(P.FAILURES, evidence.FAILURE_CODES)
            self.assertEqual(P.PHASES, evidence.FAILURE_PHASES)
            self.assertEqual(P.SCOPE, evidence.SCOPE)
            self.assertEqual(P.HARNESS, evidence.HARNESS_FILES)
            with tempfile.TemporaryDirectory() as directory:
                application = Path(directory) / "fixture.exe"
                application.write_bytes(b"Non-executable binding fixture; never run")
                commit = "a" * 40
                with patch.dict(os.environ, {"GITHUB_SHA": commit}):
                    bindings = P.source_binding(application, P.H.sha(application.read_bytes()), commit)
                self.assertEqual(bindings, evidence.compute_bindings(P.H.ROOT, application, commit))
                self.assertEqual(P.H.runtime_pins(P.H.ROOT / "rclone-version.env"), evidence.runtime_pins(P.H.ROOT))

    def test_each_loaded_module_must_match_before_first_binding(self):
        for module in (P.T, P.N, P.O, P.F, P.T.H, P.T.S, P.F.F):
            with patch.object(module, "loaded_source_sha256", "0" * 64), \
                    patch.object(P.H.E, "compute_bindings", side_effect=AssertionError("must_not_bind")):
                with self.assertRaises(P.H.ProducerError):
                    P.source_binding(Path("not-opened.exe"), "a" * 64, "b" * 40)


if __name__ == "__main__":
    unittest.main()
