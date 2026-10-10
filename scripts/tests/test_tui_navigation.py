"""Literal screen/input transcripts; no app, terminal, process or network work.

The fake Controller models only wait/key/text and its documented resize gate.
These are navigation unit tests, never native TUI or acquisition acceptance.
"""
from collections import deque, namedtuple
import importlib.util
from pathlib import Path
import socket
import subprocess
import sys
import textwrap
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1] / "application-lab"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("no processes")), \
        mock.patch.object(socket, "socket", side_effect=AssertionError("no sockets")):
    N = load("tested_tui_navigation", ROOT / "tui_navigation.py")

Style = namedtuple("Style", "background flags")
Cell = namedtuple("Cell", "character style")
PLAIN = Style((), frozenset())
FOCUS = Style(("rgb", 42, 55, 84), frozenset({1}))
URL_A, URL_B = "http://127.0.0.1:45121/", "http://127.0.0.1:45122/"
MEMBERS = ("README-synthetic.txt", "large/cancel.bin", "nested/binary.bin", "nested/spaced name.txt")
# Literal public pinned catalog label, independent of the navigation parser.
S3_LABEL = ("Amazon S3 Compliant Storage Providers including AWS, Alibaba, ArvanCloud, "
            "BizflyCloud, Ceph, ChinaMobile, Cloudflare, Cubbit, DigitalOcean, Dreamhost, "
            "Exaba, Fastly, FileLu, FlashBlade, GCS, HCP, Hetzner, HuaweiOBS, IBMCOS, "
            "IDrive, ImpossibleCloud, Intercolo, IONOS, Leviia, Liara, Linode, LyveCloud, "
            "Magalu, Mega, Minio, Netease, Outscale, OVHcloud, Petabox, Qiniu, Rabata, "
            "RackCorp, Rclone, Scaleway, Scality, SeaweedFS, Selectel, Servercore, "
            "SpectraLogic, Storj, Synology, TencentCOS, US3, Wasabi, Zadara, Zata, "
            "ZeroServices, Other")


class Frame:
    columns, rows, ready, pending = 120, 34, True, False

    def __init__(self):
        self.grid = [[Cell(" ", PLAIN) for _ in range(120)] for _ in range(34)]

    def put(self, row, col, text, style=PLAIN):
        assert 0 <= row < 34 and col >= 0 and col + len(text) <= 120
        self.grid[row][col:col+len(text)] = [Cell(c, style) for c in text]
        return self

    def panel(self, title, entries, *, left=0, top=0, width=120, height=30, focus=None, marker=">", style=FOCUS):
        self.put(top, left, "\u250c" + title + "\u2500" * (width-len(title)-2) + "\u2510")
        for row in range(top+1, top+height-1):
            self.put(row, left, "\u2502" + " " * (width-2) + "\u2502")
        self.put(top+height-1, left, "\u2514" + "\u2500" * (width-2) + "\u2518")
        for index, entry in enumerate(entries):
            prefix = marker + " " if focus == index else "  "
            self.put(top+1+index, left+1, prefix+entry, style if focus == index else PLAIN)
        return self

    def lines(self):
        return tuple("".join(c.character for c in row) for row in self.grid)

    def cells(self):
        return tuple(tuple(row) for row in self.grid)


def main():
    return Frame().panel("rclone-triage // mission menu", ["[AUTH] Browser auth on suspect device", "[CONFIG] Use configuration"], top=4, height=25, focus=0)


def provider(backend="drive", *, count=3, dynamic=True, marker=">", style=FOCUS,
             checked=(), checked_total=None):
    names = {"drive": "Google Drive", "local": "Local", "http": "HTTP", "combine": "Combine several remotes into one", "gcs": "Google Cloud Storage (this is not Google Drive)", "s3": S3_LABEL}
    order = ("combine", "gcs", "drive", "http", "local") if count == 5 else ("s3", "combine", "gcs", "drive", "http", "local") if count == 6 else ("drive", "local", "http")
    index = order.index(backend)
    # Actual source layout at120 columns:65% Providers(78),35% Status(42).
    result = Frame().panel(f"Providers ({count})", [], width=78, height=30)
    row = 1
    for item_index, item in enumerate(order):
        parts = textwrap.wrap(names[item], width=70 if item_index == index else 72)
        for part_index, part in enumerate(parts):
            if row >= 29:
                break
            prefix = marker+" " if item_index == index and part_index == 0 else "  "
            content = (("[x] " if item in checked else "[ ] ") if part_index == 0 else "    ")+part
            # Unselected rows may be clipped by List's reserved marker columns.
            result.put(row, 1, (prefix+content)[:76], style if item_index == index else PLAIN)
            row += 1
    # Discovery drops Description when it equals display_name; do not duplicate
    # the long S3 label and invent a Status layout that the app never emits.
    total = len(checked) if checked_total is None else checked_total
    logical = ["Mode: Authenticate with the chosen Browsers & Providers (TO BE RUN ON SUSPECT DEVICE)", f"Checked: {total} of {count}", f"Selected: {names[backend]}", f"Backend: {backend}", "Auth: Unknown/manual", "Hashes: unknown", "", f"Providers: {count}", "Last update: 2026-10-10 12:00:00", "Last error: none"]
    logical += [f"Status: Loaded {count} providers from rclone."] if dynamic else ["Status: Provider discovery failed.", "Using built-in list."]
    physical = [part for line in logical for part in (textwrap.wrap(line, width=40) if line else [""])]
    result.panel("Status", [], left=78, width=42, height=30)
    for index, line in enumerate(physical[:28]):
        result.put(index+1, 79, line)
    return result


def prompt(title, value="", *, hint=None):
    hints = {"Remote Name": "Enter remote name.", "Required Option": "Required option: url", "Backend Option Key": "Enter an option key (blank to finish).", "Find file": "Path or remote name (n finds next match)"}
    # Literal application hints and the complete 60%-height prompt layout.
    content = {
        "Remote Name": [hints[title], "", "Default: http", "", "Enter submit | Esc cancel"],
        "Required Option": [hints[title], "", "URL of HTTP host to connect to.", "", 'E.g. "https://example.com", or "https://user:pass@example.com" to use a username and password.', "", "Blank is not allowed for required options.", "", "Enter submit | Esc cancel"],
        "Backend Option Key": [hints[title], "", "Example: access_key_id", "", "Known keys: description, headers, no_escape, no_head, no_slash, url", "", "Enter submit | Esc cancel"],
        "Find file": [hints[title]],
    }[title]
    if hint is not None:
        content[0] = hint
    content += ["", "Ctrl+V / Shift+Insert paste | Ctrl+U clear | Ctrl+W delete word",
                "> " + (value or "<empty>"), f"Len: {len(value)} char(s)",
                "Enter submit | Esc cancel | Backspace delete"]
    # Real Paragraph has no List marker/indent and clips at the inner height.
    frame = Frame().panel(title, [], left=12, top=7, width=96, height=20)
    for index, text in enumerate(content[:18]):
        frame.put(8+index, 13, text)
    return frame


def files(remote="TuiHttpA", selected=None, focus="README-synthetic.txt", *, marker=">", style=FOCUS):
    rows = ["[ ] README-synthetic.txt", "[dir] large", "[ ] large/cancel.bin", "[dir] nested", "[ ] nested/binary.bin", "[ ] nested/spaced name.txt"]
    if selected is not None:
        rows = [r.replace("[ ] "+selected, "[x] "+selected) for r in rows]
    focus_index = next(i for i, row in enumerate(rows) if row.split("] ", 1)[1] == focus)
    return Frame().panel("Files", rows, height=31, focus=focus_index, marker=marker, style=style).put(31, 0, f"6 of 6 entries \u2022 {int(selected is not None)} selected \u2022 Source: {remote}")


def acquiring():
    return Frame().put(30, 0, "Acquiring selected files \u2022 Esc cancel and keep completed evidence \u2022 Ctrl+C stop")


def complete(remote="TuiHttpA", cancelled=False):
    return Frame().put(0, 0, "=== Acquisition complete ===").put(1, 0, f"Acquired {0 if cancelled else 1}/1 files (0 source hashes verified, {1 if cancelled else 0} failed or cancelled)").put(2, 0, "Source: "+remote)


def postauth():
    f = Frame().put(0, 0, "Authenticated: HTTP")
    for i, label in enumerate(("List all files to CSV/XLSX", "Mount as drive (File Explorer)", "Skip to file list (empty)", "Add another provider")):
        f.put(5+i*3, 0, ("\u25b6   " if i == 0 else "    ")+label)
    return f


def back_steps(remote="TuiHttpA", selected=None, from_complete=False):
    steps = [("key", "backspace", files(remote, selected))] if from_complete else []
    return steps + [("key", "backspace", postauth()), ("key", "backspace", Frame().panel("Authentication", ["Authenticated: HTTP"])), ("key", "backspace", Frame().panel("Browsers", ["System Default"])), ("key", "backspace", provider("http", dynamic=False, checked=("http",))), ("key", "backspace", main())]


def setup_steps(remote="TuiHttpA", url=URL_A, *, listing=None):
    return [("key", "enter", provider()), ("key", "down", provider("local")), ("key", "down", provider("http")), ("key", "space", provider("http", checked=("http",))), ("key", "enter", prompt("Remote Name")), ("text", remote, prompt("Remote Name", remote)), ("key", "enter", prompt("Required Option")), ("text", url, prompt("Required Option", url)), ("key", "enter", prompt("Backend Option Key")), ("key", "enter", listing or files(remote))]


def select_steps(member="README-synthetic.txt", remote="TuiHttpA", *, highlighted=None, checked=None):
    return [("text", "/", prompt("Find file")), ("text", member, prompt("Find file", member)), ("key", "enter", highlighted or files(remote, focus=member)), ("key", "space", checked or files(remote, member, member))]


class Controller:
    """Independent input transcript; waits advance a fake clock, not wall time."""
    def __init__(self, screen, steps=()):
        self.screen, self.steps = screen, deque(steps)
        self.inputs, self.observed, self.wait_arguments = [], [], []
        self.now = 0.0
        self.resize_unproven = False
        self.next_screen = None

    def clock(self):
        return self.now

    def wait(self, predicate, *, seconds=20, observe=None):
        if self.resize_unproven:
            raise ValueError("private-resize-canary")
        self.wait_arguments.append(seconds)
        deadline = self.now + seconds
        while self.now < deadline:
            self.now += .05
            if observe:
                value = {"ok": True, "running": True, "exited": False}
                self.observed.append(value)
                observe(value)
            if self.next_screen is not None:
                self.screen, self.next_screen = self.next_screen, None
            if self.screen.ready and not self.screen.pending and predicate(self.screen):
                return
        raise TimeoutError("private-transcript-canary")

    def apply(self, kind, value):
        self.inputs.append((kind, value, self.now))
        if not self.steps:
            raise AssertionError("unexpected input")
        expected_kind, expected_value, screen = self.steps.popleft()
        if (kind, value) != (expected_kind, expected_value):
            raise AssertionError("wrong input")
        self.screen = screen

    def key(self, value):
        self.apply("key", value)

    def text(self, value):
        self.apply("text", value)


class NavigationTests(unittest.TestCase):
    def setUp(self):
        self.no_process = mock.patch.object(subprocess, "Popen", side_effect=AssertionError("no processes"))
        self.no_socket = mock.patch.object(socket, "socket", side_effect=AssertionError("no sockets"))
        self.no_process.start()
        self.no_socket.start()
        self.addCleanup(self.no_process.stop)
        self.addCleanup(self.no_socket.stop)

    def navigation(self, steps, initial=None, observe=None):
        c = Controller(initial or main(), steps)
        n = N.Navigator(c, observe, clock=c.clock)
        return n, c

    def setup(self, n, remote="TuiHttpA", url=URL_A, **kwargs):
        n.wait_main()
        n.open_manual_http()
        n.configure_http(remote, url, **kwargs)

    def rejected(self, action, code=None):
        with self.assertRaises(N.NavigationError) as caught:
            action()
        self.assertIn(str(caught.exception), N.ERRORS)
        self.assertNotIn("canary", str(caught.exception))
        if code:
            self.assertEqual(str(caught.exception), code)

    def test_full_setup_search_acquire_back_reset_and_distinct_second_remote(self):
        phases = []
        steps = setup_steps() + select_steps() + [("key", "enter", acquiring())] + back_steps(selected=MEMBERS[0], from_complete=True) + setup_steps("TuiHttpB", URL_B)
        n, c = self.navigation(steps, observe=lambda phase, value: phases.append((phase, value)))
        self.setup(n)
        n.select_one(MEMBERS[0])
        self.assertEqual(n.begin_acquisition(), "acquiring")
        c.next_screen = complete()
        n.wait_complete()
        n.back_to_main()
        self.setup(n, "TuiHttpB", URL_B)
        self.assertEqual((n.state, n.remote, n.selected), ("files", "TuiHttpB", None))
        self.assertEqual(n.configured, {"TuiHttpA": URL_A, "TuiHttpB": URL_B})
        self.assertFalse(c.steps)
        self.assertTrue(all(phase in N.PHASES and value["running"] for phase, value in phases))
        self.assertIn("provider_debounce", [phase for phase, _ in phases])
        downs = [stamp for kind, value, stamp in c.inputs if (kind, value) == ("key", "down")]
        self.assertGreaterEqual(downs[1]-downs[0], .08)
        self.assertNotIn(("key", "escape"), [(k, v) for k, v, _ in c.inputs])

    def test_submission_can_stop_before_listing_and_observer_releases_wait(self):
        n, c = self.navigation(setup_steps(listing=Frame()))
        self.setup(n, wait_files=False)
        self.assertEqual(n.state, "listing")
        def observe(phase, _):
            self.assertEqual(phase, "files")
            c.next_screen = files()
        n.observe = observe
        n.wait_files()
        self.assertEqual(n.state, "files")

    def test_remote_prompt_cancel_then_reopen_without_config_submission(self):
        steps = setup_steps()[:5] + [("key", "escape", provider("http", checked=("http",))), ("key", "space", provider("http")), ("key", "space", provider("http", checked=("http",))), ("key", "enter", prompt("Remote Name"))]
        n, c = self.navigation(steps)
        n.wait_main(); n.open_manual_http(); n.cancel_remote_prompt(); n.open_manual_http()
        self.assertEqual(n.state, "remote_prompt")
        self.assertFalse(n.configured)
        self.assertFalse(any(kind == "text" for kind, _, _ in c.inputs))
        self.assertEqual([(kind, value) for kind, value, _ in c.inputs][-4:],
                         [("key", "escape"), ("key", "space"), ("key", "space"), ("key", "enter")])

    def test_http_requires_observed_zero_then_checked_one_before_enter(self):
        n, c = self.navigation(setup_steps()[:5])
        n.wait_main(); n.open_manual_http()
        self.assertEqual([(kind, value) for kind, value, _ in c.inputs],
                         [("key", "enter"), ("key", "down"), ("key", "down"),
                          ("key", "space"), ("key", "enter")])
        self.assertEqual(n.state, "remote_prompt")
        self.assertFalse(c.steps)

    def test_initial_hidden_visible_or_malformed_checks_prevent_space(self):
        invalid = [provider("http", checked_total=1),
                   provider("http", checked=("local",), checked_total=0),
                   provider("http", checked=("http",)),
                   provider("http").put(4, 79, "Checked: 0 of 4".ljust(40)),
                   provider("http").put(4, 79, "Checked: 0 of 3 extra".ljust(40)),
                   provider("http").put(4, 79, " ".ljust(40)),
                   provider("http").put(28, 79, "Checked: 0 of 3".ljust(40))]
        for screen in invalid:
            with self.subTest(lines=screen.lines()[4]):
                n, c = self.navigation([("key", "enter", screen)])
                n.wait_main()
                self.rejected(n.open_manual_http, "navigation_timeout")
                self.assertEqual([(k, v) for k, v, _ in c.inputs], [("key", "enter")])

    def test_space_requires_exact_styled_http_and_complete_catalog_count(self):
        invalid = [provider("http"), provider("http", checked_total=1),
                   provider("http", checked=("http",), checked_total=2),
                   provider("http", checked=("http", "local"), checked_total=1),
                   provider("local", checked=("local",)),
                   provider("http", checked=("http",), style=PLAIN),
                   provider("http", checked=("http",), count=4),
                   provider("http", checked=("http",)).put(4, 79, "Checked: 1 of 4".ljust(40)),
                   provider("http", checked=("http",)).put(28, 79, "Checked: 1 of 3".ljust(40))]
        for screen in invalid:
            with self.subTest(lines=screen.lines()[4]):
                n, c = self.navigation([("key", "enter", provider("http")), ("key", "space", screen)])
                n.wait_main()
                self.rejected(n.open_manual_http, "navigation_timeout")
                self.assertEqual([(k, v) for k, v, _ in c.inputs], [("key", "enter"), ("key", "space")])
                self.rejected(n.open_manual_http, "navigation_failed")

    def test_prompt_cancel_requires_retained_http_before_deselecting(self):
        for screen in (provider("http"), provider("http", checked=("http",), checked_total=2),
                       provider("local", checked=("local",))):
            n, c = self.navigation(setup_steps()[:5] + [("key", "escape", screen)])
            n.wait_main(); n.open_manual_http()
            self.rejected(n.cancel_remote_prompt, "navigation_timeout")
            self.assertEqual([(k, v) for k, v, _ in c.inputs][-1], ("key", "escape"))
            self.assertFalse(n.configured)

    def test_prompt_cancel_requires_observed_clear_and_cannot_retry_on_uncertainty(self):
        for screen in (provider("http", checked=("http",)), provider("http", checked_total=1)):
            n, c = self.navigation(setup_steps()[:5] + [
                ("key", "escape", provider("http", checked=("http",))), ("key", "space", screen)])
            n.wait_main(); n.open_manual_http()
            self.rejected(n.cancel_remote_prompt, "navigation_timeout")
            count = len(c.inputs)
            self.rejected(n.open_manual_http, "navigation_failed")
            self.assertEqual(len(c.inputs), count)

    def test_prompt_cancel_back_to_main_does_not_toggle_again(self):
        n, c = self.navigation(setup_steps()[:5] + [
            ("key", "escape", provider("http", checked=("http",))),
            ("key", "space", provider("http")), ("key", "backspace", main())])
        n.wait_main(); n.open_manual_http(); n.cancel_remote_prompt(); n.back_to_main()
        self.assertEqual(n.state, "main")
        self.assertFalse(c.steps)
        self.assertEqual([(k, v) for k, v, _ in c.inputs].count(("key", "space")), 2)

    def test_main_reset_must_clear_retained_provider_check_before_new_setup(self):
        n, c = self.navigation(setup_steps() + back_steps() + [
            ("key", "enter", provider("http", checked=("http",)))])
        self.setup(n); n.back_to_main()
        prior = len(c.inputs)
        n.wait_main()
        self.rejected(n.open_manual_http, "navigation_timeout")
        self.assertEqual([(k, v) for k, v, _ in c.inputs[prior:]], [("key", "enter")])
        self.assertEqual(n.configured, {"TuiHttpA": URL_A})

    def test_dynamic_count_without_loaded_status_cannot_enter_provider(self):
        n, c = self.navigation([("key", "enter", provider("http", dynamic=False))])
        n.wait_main()
        self.rejected(n.open_manual_http, "navigation_timeout")
        self.assertEqual([(k, v) for k, v, _ in c.inputs], [("key", "enter")])

    def test_provider_change_count_repeat_and_unchanged_selection_fail_bounded(self):
        for changed in (provider("local", count=4), provider(), provider("local")):
            with self.subTest(lines=changed.lines()[0]):
                steps = [("key", "enter", provider()), ("key", "down", changed), ("key", "down", provider())]
                n, c = self.navigation(steps)
                n.wait_main()
                self.rejected(n.open_manual_http)
                self.assertLessEqual(len(c.inputs), 3)
                self.assertNotEqual(n.state, "remote_prompt")

    def test_provider_marker_and_full_selection_style_are_required(self):
        for style, marker in ((Style((), frozenset({1})), ">"), (Style(FOCUS.background, frozenset()), ">"), (FOCUS, "?")):
            n, c = self.navigation([("key", "enter", provider("http", marker=marker, style=style))])
            n.wait_main()
            self.rejected(n.open_manual_http)
            self.assertEqual(len(c.inputs), 1)

    def test_backend_status_change_without_matching_selected_row_is_refused(self):
        mismatch = provider("local").put(5, 79, "Selected: Google Drive".ljust(40))
        n, c = self.navigation([("key", "enter", provider()), ("key", "down", mismatch)])
        n.wait_main()
        self.rejected(n.open_manual_http)
        self.assertEqual([(k, v) for k, v, _ in c.inputs], [("key", "enter"), ("key", "down")])

    def test_wrapped_combine_and_gcs_status_traversal_reaches_http(self):
        combine, gcs = provider("combine", count=5), provider("gcs", count=5)
        # Literal expectations independently bind the physical40-column wrap.
        self.assertEqual(combine.lines()[5][79:119].rstrip(), "Selected: Combine several remotes into")
        self.assertEqual(combine.lines()[6][79:119].rstrip(), "one")
        self.assertEqual(gcs.lines()[5][79:119].rstrip(), "Selected: Google Cloud Storage (this is")
        self.assertEqual(gcs.lines()[6][79:119].rstrip(), "not Google Drive)")
        steps = [("key", "enter", combine), ("key", "down", gcs), ("key", "down", provider("drive", count=5)), ("key", "down", provider("http", count=5)), ("key", "space", provider("http", count=5, checked=("http",))), ("key", "enter", prompt("Remote Name"))]
        n, c = self.navigation(steps)
        n.wait_main(); n.open_manual_http()
        self.assertEqual(n.state, "remote_prompt")
        self.assertFalse(c.steps)
        downs = [stamp for kind, value, stamp in c.inputs if (kind, value) == ("key", "down")]
        self.assertTrue(all(b-a >= .08 for a, b in zip(downs, downs[1:])))

    def test_wrapped_selected_field_refuses_missing_extra_duplicate_or_wrong_continuation(self):
        for replacement in ("", "other provider", "Backend: gcs", "Selected: one", "Description: one"):
            with self.subTest(replacement=replacement):
                changed = provider("combine", count=5).put(6, 79, replacement.ljust(40))
                n, c = self.navigation([("key", "enter", changed)])
                n.wait_main()
                self.rejected(n.open_manual_http)
                self.assertEqual([(k, v) for k, v, _ in c.inputs], [("key", "enter")])

    def test_wrapped_selected_field_cannot_absorb_unrelated_intervening_fields(self):
        changed = provider("combine", count=5)
        # Keep the full expected label in a later Description; omit its actual
        # Selected continuation. The field boundary must not search/fill it.
        changed.put(6, 79, "Description: one".ljust(40))
        changed.put(7, 79, "Auth: Unknown/manual".ljust(40))
        changed.put(8, 79, "Backend: combine".ljust(40))
        n, c = self.navigation([("key", "enter", changed)])
        n.wait_main()
        self.rejected(n.open_manual_http)
        self.assertEqual(len(c.inputs), 1)

    def test_long_pinned_s3_highlight_and_status_are_both_complete_before_traversal(self):
        first = provider("s3", count=6)
        self.assertEqual(first.lines()[1][1:77].rstrip(), "> [ ] Amazon S3 Compliant Storage Providers including AWS, Alibaba,")
        self.assertEqual(first.lines()[2][1:77].rstrip(), "      ArvanCloud, BizflyCloud, Ceph, ChinaMobile, Cloudflare, Cubbit,")
        self.assertIn("Backend: s3", [line[79:119].strip() for line in first.lines()])
        self.assertEqual(first.lines()[4][79:119].rstrip(), "Checked: 0 of 6")
        self.assertEqual(first.lines()[27][79:119].rstrip(), "Last error: none")
        self.assertEqual(first.lines()[28][79:119].rstrip(), "Status: Loaded 6 providers from rclone.")
        steps = [("key", "enter", first)] + [("key", "down", provider(name, count=6)) for name in ("combine", "gcs", "drive", "http")] + [("key", "space", provider("http", count=6, checked=("http",))), ("key", "enter", prompt("Remote Name"))]
        n, c = self.navigation(steps)
        n.wait_main(); n.open_manual_http()
        self.assertEqual(n.state, "remote_prompt")
        self.assertFalse(c.steps)

    def test_long_provider_continuation_requires_exact_text_style_indent_and_no_gap(self):
        base = provider("s3", count=6)
        changes = [
            (2, "      wrong continuation", FOCUS),
            (2, base.lines()[2][1:77], PLAIN),
            (2, "    "+base.lines()[2][1:77].strip(), FOCUS),
            (2, "", PLAIN),
            (2, "      [ ] extra row", FOCUS),
            (2, "> [ ] extra row", FOCUS),
        ]
        for row, text, style in changes:
            with self.subTest(text=text[:25], style=style):
                changed = provider("s3", count=6).put(row, 1, text.ljust(76), style)
                n, c = self.navigation([("key", "enter", changed)])
                n.wait_main()
                self.rejected(n.open_manual_http)
                self.assertEqual(len(c.inputs), 1)

    def test_long_provider_clipped_status_never_uses_prefix_as_full_name(self):
        changed = provider("s3", count=6)
        # Remove the final visible selected fragment while retaining Backend and
        # the loaded status. Full left-side equality must catch the lost suffix.
        rows = [i for i, line in enumerate(changed.lines()) if line[79:119].startswith("Backend: ")]
        changed.put(rows[0]-1, 79, " " * 40)
        n, c = self.navigation([("key", "enter", changed)])
        n.wait_main()
        self.rejected(n.open_manual_http)
        self.assertEqual(len(c.inputs), 1)

    def test_only_frozen_remote_and_literal_owned_loopback_inputs_are_accepted(self):
        pairs = [("Other", URL_A), ("TuiHttpA", "http://localhost:45121/"), ("TuiHttpA", "http://127.0.0.1:65536/"), ("TuiHttpA", "https://127.0.0.1:45121/"), ("TuiHttpA", URL_A+"extra"), ("TuiHttpA", "http://user@127.0.0.1:45121/"), ("TuiHttpA", "http://127.0.0.1:04512/")]
        for remote, url in pairs:
            n, c = self.navigation(setup_steps()[:5])
            n.wait_main(); n.open_manual_http()
            count = len(c.inputs)
            self.rejected(lambda: n.configure_http(remote, url), "navigation_input")
            self.assertEqual(len(c.inputs), count)

    def test_second_remote_cannot_reuse_first_endpoint(self):
        n, c = self.navigation(setup_steps() + back_steps() + setup_steps("TuiHttpB", URL_B)[:5])
        self.setup(n); n.back_to_main(); n.open_manual_http()
        count = len(c.inputs)
        self.rejected(lambda: n.configure_http("TuiHttpB", URL_A), "navigation_input")
        self.assertEqual(len(c.inputs), count)

    def test_wrong_prompt_and_missing_echo_prevent_next_submission(self):
        for index, wrong in ((5, prompt("Remote Name")), (6, prompt("Required Option", hint="Required option: password")), (7, prompt("Required Option")), (8, prompt("Backend Option Key", "token"))):
            steps = setup_steps()
            kind, text, _ = steps[index]
            steps[index] = (kind, text, wrong)
            n, c = self.navigation(steps)
            n.wait_main(); n.open_manual_http()
            self.rejected(lambda: n.configure_http("TuiHttpA", URL_A))
            self.assertEqual(len(c.inputs), index+1)
            self.assertFalse(n.configured)

    def test_source_shaped_url_prompt_requires_full_echo_length_and_controls(self):
        observed = prompt("Required Option", URL_A)
        self.assertTrue(any(f"Len: {len(URL_A)} char(s)" in line for line in observed.lines()))
        self.assertTrue(any("Ctrl+V / Shift+Insert paste" in line for line in observed.lines()))
        n, c = self.navigation(setup_steps())
        self.setup(n)
        self.assertEqual(n.state, "files")
        # Missing or mismatched evidence must stop before any URL is submitted.
        for row, replacement in ((18, ""), (19, ""), (20, ""),
                                 (20, "Len: 1 char(s)"), (21, "")):
            with self.subTest(row=row, replacement=replacement):
                missing = prompt("Required Option").put(row, 13, replacement.ljust(94))
                steps = setup_steps()
                steps[6] = ("key", "enter", missing)
                n, c = self.navigation(steps)
                n.wait_main(); n.open_manual_http()
                self.rejected(lambda: n.configure_http("TuiHttpA", URL_A))
                self.assertEqual(len(c.inputs), 7)

    def test_listing_requires_exact_source_inventory_and_zero_selected(self):
        malformed = [files("TuiHttpB"), files(selected=MEMBERS[0]), files().put(8, 3, "[ ] extra.txt"), files().put(31, 0, "5 of 6 entries \u2022 0 selected \u2022 Source: TuiHttpA".ljust(120))]
        for screen in malformed:
            n, _ = self.navigation(setup_steps(listing=screen))
            self.rejected(lambda: self.setup(n))
            self.assertEqual(n.state, "listing")

    def test_search_must_highlight_exact_file_before_space(self):
        for wrong in (files(focus="nested/binary.bin"), files(style=Style((), frozenset({1}))), files(marker="?")):
            n, c = self.navigation(setup_steps()+select_steps(highlighted=wrong))
            self.setup(n)
            self.rejected(lambda: n.select_one(MEMBERS[0]))
            self.assertEqual([(k, v) for k, v, _ in c.inputs].count(("key", "space")), 1)

    def test_checked_count_and_exact_row_required_before_acquisition(self):
        n, c = self.navigation(setup_steps()+select_steps(checked=files()))
        self.setup(n)
        self.rejected(lambda: n.select_one(MEMBERS[0]))
        count = len(c.inputs)
        self.rejected(n.begin_acquisition, "navigation_failed")
        self.assertEqual(len(c.inputs), count)

    def test_each_fixed_member_and_animated_marker_can_be_selected(self):
        for member, marker in zip(MEMBERS, (">", "\u00bb", "\u25b8", "\u25b6")):
            n, c = self.navigation(setup_steps()+select_steps(member, highlighted=files(focus=member, marker=marker), checked=files(selected=member, focus=member, marker=marker)))
            self.setup(n); n.select_one(member)
            self.assertEqual((n.state, n.selected), ("selected", member))
            self.assertFalse(c.steps)

    def test_fast_complete_is_not_active_transfer_and_cannot_be_cancelled(self):
        n, c = self.navigation(setup_steps()+select_steps()+[("key", "enter", complete())])
        self.setup(n); n.select_one(MEMBERS[0])
        self.assertEqual(n.begin_acquisition(), "complete")
        n.wait_complete()
        count = len(c.inputs)
        self.rejected(n.cancel_acquisition, "navigation_state")
        self.assertEqual(len(c.inputs), count)

    def test_active_large_cancel_requires_exact_cancelled_completion(self):
        steps = setup_steps()+select_steps("large/cancel.bin")+[("key", "enter", acquiring()), ("key", "escape", complete(cancelled=True))]
        n, c = self.navigation(steps)
        self.setup(n); n.select_one("large/cancel.bin"); n.begin_acquisition(); n.cancel_acquisition()
        self.assertEqual(n.state, "complete")
        self.assertFalse(c.steps)
        self.rejected(n.wait_complete)  # cancelled screen never becomes success

    def test_wrong_completion_source_or_success_count_is_rejected(self):
        for screen in (complete("TuiHttpB"), complete(cancelled=True), Frame().put(3, 0, "=== Acquisition complete ===")):
            n, _ = self.navigation(setup_steps()+select_steps()+[("key", "enter", screen)])
            self.setup(n); n.select_one(MEMBERS[0])
            self.rejected(n.begin_acquisition)

    def test_cancel_cannot_target_short_file_or_unobserved_activity(self):
        n, c = self.navigation(setup_steps()+select_steps()+[("key", "enter", acquiring())])
        self.setup(n); n.select_one(MEMBERS[0]); n.begin_acquisition()
        count = len(c.inputs)
        self.rejected(n.cancel_acquisition, "navigation_state")
        self.assertEqual(len(c.inputs), count)

    def test_wrong_back_screen_stops_without_browser_or_mount_action(self):
        n, c = self.navigation(setup_steps()+[("key", "backspace", Frame().panel("Browsers", ["System Default"]))])
        self.setup(n)
        count = len(c.inputs)
        self.rejected(n.back_to_main)
        self.assertEqual([(k, v) for k, v, _ in c.inputs[count:]], [("key", "backspace")])

    def test_observer_failure_and_controller_error_are_static_and_sticky(self):
        n, c = self.navigation([], observe=lambda *_: (_ for _ in ()).throw(ValueError("secret-canary")))
        self.rejected(n.wait_main, "navigation_observer")
        self.rejected(n.wait_main, "navigation_failed")
        self.assertFalse(c.inputs)
        n, c = self.navigation([], initial=Frame())
        self.rejected(n.wait_main, "navigation_timeout")

    def test_resize_readiness_gate_is_never_unlocked(self):
        n, c = self.navigation([])
        c.resize_unproven = True
        self.rejected(n.wait_main)
        self.assertTrue(c.resize_unproven)
        self.assertFalse(c.inputs)

    def test_global_input_and_wait_budgets_are_fail_closed(self):
        n, c = self.navigation(setup_steps())
        n.wait_main(); n.inputs = 192
        self.rejected(n.open_manual_http, "navigation_budget")
        self.assertFalse(c.inputs)
        n, c = self.navigation([])
        n.waits = 256
        self.rejected(n.wait_main, "navigation_budget")
        self.assertFalse(c.wait_arguments)

    def test_phase_contract_is_closed_unique_and_observable(self):
        expected = ("main", "providers", "provider_step", "provider_debounce", "remote_prompt", "remote_echo", "url_prompt", "url_echo", "options_prompt", "files", "search_prompt", "search_echo", "selection_highlight", "selection_checked", "acquisition", "completion", "prompt_cancel", "cancel_acquisition", "back_files", "back_postauth", "back_auth", "back_browser", "back_providers", "back_main")
        self.assertEqual(N.PHASES, expected)
        self.assertEqual(len(N.PHASES), len(set(N.PHASES)))

    def test_actual_pure_vt_grid_preserves_selection_cells_for_navigation(self):
        screen_module = load("tested_navigation_vt_grid", ROOT / "tui_screen.py")
        literal = main()
        screen = screen_module.Screen(120, 34)
        wire = "\x1b[2J\x1b[H"
        for index, line in enumerate(literal.lines()):
            wire += f"\x1b[{index+1};1H" + line.rstrip()
        text = "> [AUTH] Browser auth on suspect device"
        wire += "\x1b[6;2H\x1b[1;48;2;42;55;84m" + text + "\x1b[0m"
        screen.feed(wire.encode("utf-8"))
        n, _ = self.navigation([], initial=screen)
        n.wait_main()
        self.assertEqual(n.state, "main")


if __name__ == "__main__":
    unittest.main()
