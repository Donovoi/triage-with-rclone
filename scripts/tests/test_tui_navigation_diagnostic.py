"""Failure-only facts over synthetic screens; no native or terminal execution."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock


PATH = Path(__file__).resolve().parents[1] / "application-lab" / "tui_navigation.py"
SPEC = importlib.util.spec_from_file_location("tui_navigation_diagnostic_subject", PATH)
N = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(N)
PREFIX = "application_tui_navigation_failure="
FACTS = {"screen_ready", "screen_pending", "remote_title", "remote_panel", "remote_hint",
         "remote_empty_echo", "remote_zero_length", "manual_status", "manual_extract_failed",
         "manual_config_failed", "manual_remote_name_failed"}
CANARY = "private-credential-path-canary"


class Screen:
    columns, rows, ready, pending = 120, 34, True, False

    def __init__(self):
        self.grid = [list(" " * self.columns) for _ in range(self.rows)]
        self.reads = 0

    def put(self, y, x, text):
        assert 0 <= x <= x + len(text) <= self.columns
        self.grid[y][x:x + len(text)] = text
        return self

    def panel(self, title, *, x, y, width, height):
        self.put(y, x, "\u250c" + title + "\u2500" * (width - len(title) - 2) + "\u2510")
        for row in range(y + 1, y + height - 1):
            self.put(row, x, "\u2502" + " " * (width - 2) + "\u2502")
        return self.put(y + height - 1, x, "\u2514" + "\u2500" * (width - 2) + "\u2518")

    def lines(self):
        self.reads += 1
        return tuple("".join(row) for row in self.grid)


def prompt():
    screen = Screen().panel("Authentication", x=0, y=0, width=120, height=31)
    screen.put(1, 1, "Authenticating: HTTP").put(2, 1, "Manual backend configuration")
    screen.panel("Remote Name", x=12, y=10, width=96, height=14)
    return screen.put(11, 13, "Enter remote name.").put(17, 13, "> <empty>").put(19, 13, "Len: 0 char(s)")


class NavigationDiagnosticTests(unittest.TestCase):
    def setUp(self):
        for name in ("subprocess.Popen", "subprocess.run", "socket.socket", "threading.Thread.start"):
            patch = mock.patch(name, side_effect=AssertionError("native_forbidden"))
            patch.start()
            self.addCleanup(patch.stop)

    def record(self, screen, phase="remote_prompt"):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            N.navigation_failure_diagnostic(phase, screen)
        raw = output.getvalue()
        self.assertEqual(raw.count("\n"), 1)
        self.assertTrue(raw.startswith(PREFIX))
        self.assertLessEqual(len(raw.rstrip("\n").encode("ascii")), 1024)
        self.assertNotIn(CANARY, raw)
        value = json.loads(raw[len(PREFIX):])
        self.assertEqual(set(value), {"phase", *FACTS})
        self.assertEqual(value["phase"], phase)
        self.assertTrue(all(v is None or type(v) is bool for k, v in value.items() if k != "phase"))
        return value

    def test_exact_remote_prompt_facts_from_one_snapshot(self):
        screen = prompt()
        value = self.record(screen)
        self.assertEqual(screen.reads, 1)
        for key in ("screen_ready", "remote_title", "remote_panel", "remote_hint",
                    "remote_empty_echo", "remote_zero_length", "manual_status"):
            self.assertIs(value[key], True)
        for key in ("screen_pending", "manual_extract_failed", "manual_config_failed", "manual_remote_name_failed"):
            self.assertIs(value[key], False)

    def test_title_is_distinct_from_complete_panel_and_row_facts_are_scoped(self):
        screen = prompt().put(23, 12, " ")
        value = self.record(screen)
        self.assertTrue(value["remote_title"])
        self.assertFalse(value["remote_panel"])
        for key in ("remote_hint", "remote_empty_echo", "remote_zero_length"):
            self.assertFalse(value[key])
        outside = Screen().put(0, 0, "Enter remote name.").put(1, 0, "> <empty>").put(2, 0, "Len: 0 char(s)")
        self.assertFalse(self.record(outside)["remote_hint"])
        sibling = Screen().panel("Remote Name Extra", x=12, y=10, width=96, height=14)
        self.assertFalse(self.record(sibling)["remote_title"])

    def test_source_failure_prefixes_discard_all_private_suffixes(self):
        for stage, key in (("extract", "manual_extract_failed"), ("config", "manual_config_failed"),
                           ("remote name", "manual_remote_name_failed")):
            screen = Screen().panel("Authentication", x=0, y=0, width=120, height=31)
            screen.put(2, 1, "Manual config failed (" + stage + "): " + CANARY)
            value = self.record(screen)
            self.assertTrue(value[key])
            self.assertFalse(value["remote_panel"])
            outside = Screen().put(2, 0, "Manual config failed (" + stage + "): " + CANARY)
            self.assertFalse(self.record(outside)[key])

    def test_incomplete_and_malformed_screens_have_unknown_facts(self):
        for mutation in ("not_ready", "pending", "bad_type", "bad_dimensions", "bad_lines", "read_error"):
            screen = prompt()
            if mutation == "not_ready":
                screen.ready = False
            elif mutation == "pending":
                screen.pending = True
            elif mutation == "bad_type":
                screen.ready = CANARY
            elif mutation == "bad_dimensions":
                screen.rows = True
            elif mutation == "bad_lines":
                screen.lines = mock.Mock(return_value=(CANARY,))
            else:
                screen.lines = mock.Mock(side_effect=ValueError(CANARY))
            value = self.record(screen)
            self.assertTrue(all(value[key] is None for key in FACTS - {"screen_ready", "screen_pending"}))
            if mutation in {"not_ready", "pending", "bad_type", "bad_dimensions"}:
                self.assertEqual(screen.reads, 0)
        self.record(None)

    def test_phase_is_closed_and_private_unknown_values_emit_nothing(self):
        for phase in (CANARY, "REMOTE_PROMPT", "remote_prompt\n", 1, True, None, ["remote_prompt"]):
            screen = prompt()
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                N.navigation_failure_diagnostic(phase, screen)
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(screen.reads, 0)

    def test_exact_subwait_phase_and_original_navigation_error_preserved(self):
        for phase in ("remote_prompt", "provider_debounce"):
            error = N.NavigationError("navigation_observer")
            predicate = mock.Mock(side_effect=AssertionError("no_predicate_retry"))
            controller = SimpleNamespace(screen=prompt(), wait=mock.Mock(side_effect=error))
            navigator = N.Navigator(controller)
            output = io.StringIO()
            with contextlib.redirect_stdout(output), self.assertRaises(N.NavigationError) as caught:
                navigator._wait(phase, predicate, 1)
            self.assertIs(caught.exception, error)
            self.assertEqual(json.loads(output.getvalue()[len(PREFIX):])["phase"], phase)
            self.assertEqual(controller.wait.call_count, 1)
            self.assertEqual(controller.wait.call_args.args, (predicate,))
            self.assertEqual(controller.wait.call_args.kwargs["seconds"], 1)
            self.assertEqual(navigator.waits, 1)
            self.assertEqual(navigator.inputs, 0)
            predicate.assert_not_called()

    def test_non_navigation_conversion_and_diagnostic_failures_stay_unchanged(self):
        class PrivateError(Exception):
            def __str__(self):
                raise AssertionError("private_exception_formatted")

        for fault in ("printer", "snapshot", "diagnostic"):
            for original in (N.NavigationError("navigation_observer"), PrivateError()):
                controller = SimpleNamespace(screen=prompt(), wait=mock.Mock(side_effect=original))
                navigator = N.Navigator(controller)
                if fault == "printer":
                    patch = mock.patch("builtins.print", side_effect=OSError(CANARY))
                elif fault == "snapshot":
                    patch = mock.patch.object(controller.screen, "lines", side_effect=ValueError(CANARY))
                else:
                    patch = mock.patch.object(N, "navigation_failure_diagnostic", side_effect=RuntimeError(CANARY))
                with patch, contextlib.redirect_stdout(io.StringIO()), self.assertRaises(N.NavigationError) as caught:
                    navigator._wait("remote_prompt", lambda _screen: False)
                if isinstance(original, N.NavigationError):
                    self.assertIs(caught.exception, original)
                else:
                    self.assertEqual(caught.exception.code, "navigation_timeout")
                    self.assertTrue(caught.exception.__suppress_context__)
                self.assertEqual(controller.wait.call_count, 1)

    def test_success_emits_nothing_and_does_not_read_screen_again(self):
        controller = SimpleNamespace(screen=prompt(), wait=mock.Mock())
        navigator = N.Navigator(controller)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            navigator._wait("remote_prompt", lambda _screen: True)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(controller.screen.reads, 0)

    def test_screen_property_failure_cannot_replace_original_wait_failure(self):
        error = N.NavigationError("navigation_observer")

        class Controller:
            @property
            def screen(self):
                raise ValueError(CANARY)

            def wait(self, *_args, **_kwargs):
                raise error

        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(N.NavigationError) as caught:
            N.Navigator(Controller())._wait("remote_prompt", lambda _screen: False)
        self.assertIs(caught.exception, error)


if __name__ == "__main__":
    unittest.main()
