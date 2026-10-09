"""Bounded navigation for the manual synthetic HTTP TUI experiment.

Consumes Controller.wait/key/text; no I/O, process, socket or terminal control of
its own. Screen observations authorize the next input, never acceptance credit.
Artifact, fixture, actual runtime identity and owned cleanup remain producer
obligations. A displayed dynamic-load status is not independent proof that the
observed executable performed discovery. No resize gate is cleared here.

Source: ui/render.rs, runner.rs, prompt.rs, flows/manual_config.rs,
flows/download.rs, widgets/{menu_list,provider_list,file_tree}.rs and theme.rs at
main 994970f plus ProviderSelect's explicit Checked aggregate. Enter confirms
checked providers, not the highlighted row; Remote Name cancellation retains
that checkbox until the navigator explicitly clears and observes it.
"""
from __future__ import annotations

import functools
import json
import re
import time
from types import SimpleNamespace


PHASES = (
    "main", "providers", "provider_step", "provider_debounce", "remote_prompt",
    "remote_echo", "url_prompt", "url_echo", "options_prompt", "files",
    "search_prompt", "search_echo", "selection_highlight", "selection_checked",
    "acquisition", "completion", "prompt_cancel", "cancel_acquisition",
    "back_files", "back_postauth", "back_auth", "back_browser", "back_providers", "back_main",
)
ERRORS = frozenset({"navigation_state", "navigation_input", "navigation_budget", "navigation_failed",
                    "navigation_timeout", "navigation_observer", "navigation_screen", "navigation_catalog"})
REMOTES = ("TuiHttpA", "TuiHttpB")
FILE_ROWS = (
    ("file", "README-synthetic.txt"), ("directory", "large"),
    ("file", "large/cancel.bin"), ("directory", "nested"),
    ("file", "nested/binary.bin"), ("file", "nested/spaced name.txt"),
)
MARKERS = (">", "\u00bb", "\u25b8", "\u25b6")
PROMPTS = ("Remote Name", "Required Option", "Backend Option Key", "Backend Option Value", "Find file")
AUTH_ITEM = "[AUTH] Browser auth on suspect device"
SELECTION_BG = ("rgb", 42, 55, 84)
REQUIRED_URL_HINT = (
    "Required option: url", "", "URL of HTTP host to connect to.", "",
    'E.g. "https://example.com", or "https://user:pass@example.com" to use a username and password.',
    "", "Blank is not allowed for required options.", "", "Enter submit | Esc cancel",
)


class NavigationError(ValueError):
    """Closed code only; never copy text, endpoint, paths or exceptions to output."""

    def __init__(self, code):
        self.code = code if code in ERRORS else "navigation_failed"
        super().__init__(self.code)


def _operation(method):
    @functools.wraps(method)
    def wrapped(self, *args, **kwargs):
        self._check()
        try:
            return method(self, *args, **kwargs)
        except NavigationError:
            self.failed = True
            raise
        except Exception:
            self.failed = True
            raise NavigationError("navigation_failed") from None
    return wrapped


def _panel(screen, title):
    """Read one complete plain-border panel, excluding surrounding private text."""
    lines = screen.lines()
    matches = []
    pattern = re.compile("\u250c" + title + "\u2500*\u2510")
    for top, line in enumerate(lines):
        for match in pattern.finditer(line):
            left, right = match.start(), match.end() - 1
            for bottom in range(top + 1, len(lines)):
                if lines[bottom][left:right+1] == "\u2514" + "\u2500" * (right-left-1) + "\u2518":
                    if all(row[left] == row[right] == "\u2502" for row in lines[top+1:bottom]):
                        matches.append((left, top, right, bottom))
                    break
    if len(matches) != 1:
        return None
    left, top, right, bottom = matches[0]
    return tuple((row, left+1, lines[row][left+1:right]) for row in range(top+1, bottom))


def navigation_failure_diagnostic(phase, screen):
    """Failure-only fixed facts from one bounded snapshot; never screen text.

    Source: prompt.rs and manual_config.rs before the first Remote Name prompt.
    Missing or malformed screen state is unknown, not a new navigation result.
    """
    try:
        if type(phase) is not str or phase not in PHASES:
            return
        value = dict(phase=phase, screen_ready=None, screen_pending=None,
                     remote_title=None, remote_panel=None, remote_hint=None,
                     remote_empty_echo=None, remote_zero_length=None, manual_status=None,
                     manual_extract_failed=None, manual_config_failed=None,
                     manual_remote_name_failed=None)
        try:
            ready, pending = screen.ready, screen.pending
            if type(ready) is bool and type(pending) is bool:
                value.update(screen_ready=ready, screen_pending=pending)
            columns, rows = screen.columns, screen.rows
            if (ready is True and pending is False and type(columns) is int and
                    type(rows) is int and 80 <= columns <= 120 and 24 <= rows <= 34):
                lines = screen.lines()
                if (type(lines) is tuple and len(lines) == rows and
                        all(type(line) is str and len(line) == columns and
                            all(ord(char) >= 32 and ord(char) != 127 for char in line)
                            for line in lines)):
                    snapshot = SimpleNamespace(lines=lambda: lines)
                    remote = _panel(snapshot, re.escape("Remote Name"))
                    auth = _panel(snapshot, "Authentication")
                    remote_lines = [text.strip() for _, _, text in remote or ()]
                    auth_lines = [text.strip() for _, _, text in auth or ()]
                    value.update(
                        remote_title=any(re.search("\u250cRemote Name[\u2500\u2510]", line) is not None
                                         for line in lines),
                        remote_panel=remote is not None,
                        remote_hint="Enter remote name." in remote_lines,
                        remote_empty_echo=remote_lines.count("> <empty>") == 1,
                        remote_zero_length=remote_lines.count("Len: 0 char(s)") == 1,
                        manual_status="Manual backend configuration" in auth_lines,
                        manual_extract_failed=any(line.startswith("Manual config failed (extract):")
                                                  for line in auth_lines),
                        manual_config_failed=any(line.startswith("Manual config failed (config):")
                                                 for line in auth_lines),
                        manual_remote_name_failed=any(line.startswith("Manual config failed (remote name):")
                                                      for line in auth_lines))
        except Exception:
            pass
        # Only phase plus locally generated nullable booleans enter stdout.
        if any(item is not None and type(item) is not bool
               for key, item in value.items() if key != "phase"):
            return
        line = "application_tui_navigation_failure=" + json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        if len(line.encode("ascii")) <= 1024:
            print(line, flush=True)
    except Exception:
        pass


def _has_prompt(screen):
    return any(_panel(screen, re.escape(title)) is not None for title in PROMPTS)


def _highlighted(screen, panel):
    result = []
    if panel is None:
        return result
    cells = screen.cells()
    for row, start, raw in panel:
        text = raw.strip()
        if len(text) >= 2 and text[0] in MARKERS and text[1] == " ":
            payload = text[2:].strip()
            offset = raw.index(text)
            selected = cells[row][start+offset:start+offset+len(text)]
            if payload and all(cell.style.background == SELECTION_BG and 1 in cell.style.flags
                               for cell in selected if cell.character != " "):
                result.append(payload)
    return result


def _main(screen):
    return not _has_prompt(screen) and _highlighted(
        screen, _panel(screen, re.escape("rclone-triage // mission menu"))) == [AUTH_ITEM]


def _provider_highlighted(screen, panel):
    """Reconstruct one fully visible, word-wrapped selected provider item."""
    if panel is None:
        return None
    starts = [i for i, (_, _, raw) in enumerate(panel)
              if len(raw.strip()) > 1 and raw.strip()[0] in MARKERS and raw.strip()[1] == " "]
    if len(starts) != 1:
        return None
    cells, parts = screen.cells(), []
    for index in range(starts[0], len(panel)):
        row, left, raw = panel[index]
        text = raw.strip()
        selected = bool(text) and all(
            cell.style.background == SELECTION_BG and 1 in cell.style.flags
            for cell in cells[row][left:left+len(raw)] if cell.character != " ")
        if index == starts[0]:
            if not selected or not text[2:].startswith(("[ ] ", "[x] ")):
                return None
            parts.append(text[2:])
        elif selected:
            # List reserves two marker columns; wrap_line indents the four
            # checkbox columns on continuation lines. Never absorb a new row.
            if not raw.startswith(" " * 6) or text.startswith(("[", *MARKERS)):
                return None
            parts.append(text)
        else:
            # An unstyled row ends the item. A selected continuation after a
            # blank/unstyled gap would otherwise silently accept truncation.
            for later_row, later_left, later_raw in panel[index+1:]:
                if later_raw.strip() and any(
                    cell.style.background == SELECTION_BG
                    for cell in cells[later_row][later_left:later_left+len(later_raw)]
                    if cell.character != " "):
                    return None
            break
    value = " ".join(parts)
    return value if len(value) <= 1028 else None


def _provider(screen, *, dynamic, checked=False):
    if _has_prompt(screen):
        return None
    lines = screen.lines()
    counts = [int(m.group(1)) for row in lines for m in re.finditer(r"\u250cProviders \(([1-9][0-9]{0,2})\)\u2500", row)]
    if len(counts) != 1 or not 1 <= counts[0] <= 96:
        return None
    count = counts[0]
    panel = _panel(screen, re.escape(f"Providers ({count})"))
    status = _panel(screen, "Status")
    highlighted = _provider_highlighted(screen, panel)
    if panel is None or status is None or highlighted is None:
        return None
    if sum(text.count("[x]") for _, _, text in panel) != int(checked):
        return None
    status_lines = [text.strip() for _, _, text in status]
    # This source-rendered aggregate covers every catalog entry, including
    # offscreen rows. A visible checkbox alone cannot exclude hidden checks.
    if [line for line in status_lines if line.startswith("Checked:")] != [
            f"Checked: {int(checked)} of {count}"]:
        return None
    backend_rows = [i for i, line in enumerate(status_lines) if line.startswith("Backend: ")]
    selected_rows = [i for i, line in enumerate(status_lines) if line.startswith("Selected: ")]
    if len(backend_rows) != 1 or len(selected_rows) != 1:
        return None
    start, end = selected_rows[0], backend_rows[0]
    # render_state emits Selected immediately before Backend, but Paragraph's
    # Wrap(trim=true) splits long names at the 40-column Status interior. Rejoin
    # only that bounded contiguous field; descriptions/later fields cannot fill
    # a missing or truncated label. The full left highlight must still match.
    if not 1 <= end - start <= 24:
        return None
    fragments = [status_lines[start][10:], *status_lines[start+1:end]]
    if any(not fragment or ":" in fragment for fragment in fragments):
        return None
    selected = [" ".join(fragments)]
    backend = [status_lines[end][9:]]
    if len(selected[0]) > 1024 or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", backend[0]):
        return None
    prefix = "[x] " if checked else "[ ] "
    if highlighted != prefix + selected[0]:
        return None
    if dynamic:
        combined = " ".join(status_lines)
        if (f"Status: Loaded {count} providers from rclone." not in combined or
                "Last error: none" not in status_lines or "Last update: never" in status_lines):
            return None
    if checked and backend[0] != "http":
        return None
    if backend[0] == "http" and (selected[0] != "HTTP" or highlighted != prefix + "HTTP"):
        return None
    return count, backend[0]


def _prompt(screen, title, value=""):
    panel = _panel(screen, re.escape(title))
    if panel is None:
        return False
    lines = [text.strip() for _, _, text in panel]
    hints = {"Remote Name": "Enter remote name.", "Required Option": "Required option: url",
             "Backend Option Key": "Enter an option key (blank to finish).",
             "Find file": "Path or remote name (n finds next match)"}
    if title == "Required Option":
        # The pinned HTTP schema's nine-line hint puts Len below the 40%-height
        # modal at 120x34. Require that exact visible source layout and the full
        # short URL echo instead; never infer an offscreen value or resize.
        visible = [*REQUIRED_URL_HINT, "", "> " + (value or "<empty>")]
        return (screen.columns == 120 and screen.rows == 34 and
                len(lines) in (11, 12) and lines[:11] == visible and
                all(not line for line in lines[11:]))
    return (title in hints and hints[title] in lines and
            lines.count("> " + (value or "<empty>")) == 1 and
            lines.count(f"Len: {len(value)} char(s)") == 1)


def _files(screen, remote, selected=None, highlighted=None):
    if _has_prompt(screen):
        return False
    panel = _panel(screen, "Files")
    if panel is None:
        return False
    actual = []
    for _, _, raw in panel:
        text = raw.strip()
        if not text:
            continue
        if len(text) > 1 and text[0] in MARKERS and text[1] == " ":
            text = text[2:].strip()
        actual.append(text)
    expected = [f"[dir] {name}" if kind == "directory" else
                f"[x] {name}" if name == selected else f"[ ] {name}" for kind, name in FILE_ROWS]
    footer = f"6 of 6 entries \u2022 {int(selected is not None)} selected \u2022 Source: {remote}"
    if sorted(actual) != sorted(expected) or screen.lines().count(footer.ljust(screen.columns)) != 1:
        return False
    focus = _highlighted(screen, panel)
    if len(focus) != 1:
        return False
    return highlighted is None or focus == [f"[{'x' if selected == highlighted else ' '}] {highlighted}"]


def _acquiring(screen):
    return (not _has_prompt(screen) and any(line.strip() ==
            "Acquiring selected files \u2022 Esc cancel and keep completed evidence \u2022 Ctrl+C stop"
            for line in screen.lines()))


def _complete(screen, remote, cancelled):
    lines = [line.rstrip() for line in screen.lines()]
    expected = ["=== Acquisition complete ===",
                f"Acquired {0 if cancelled else 1}/1 files (0 source hashes verified, {1 if cancelled else 0} failed or cancelled)",
                f"Source: {remote}"]
    # ReportScreen begins at the origin; a matching stale footer is insufficient.
    return not _has_prompt(screen) and lines[:3] == expected


def _post_auth(screen):
    if _has_prompt(screen) or _panel(screen, "Authentication") is not None:
        return False
    lines = [line.strip() for line in screen.lines()]
    choices = ("List all files to CSV/XLSX", "Mount as drive (File Explorer)",
               "Skip to file list (empty)", "Add another provider")
    stripped = [line.removeprefix("\u25b6").strip() for line in lines]
    return "Authenticated: HTTP" in lines and all(stripped.count(choice) == 1 for choice in choices)


def _auth(screen):
    panel = _panel(screen, "Authentication")
    return panel is not None and not _has_prompt(screen) and any(
        text.strip() in ("Authenticated: HTTP", "Authenticating: HTTP") for _, _, text in panel)


def _browser(screen):
    panel = _panel(screen, "Browsers")
    return panel is not None and not _has_prompt(screen) and any("System Default" in text for _, _, text in panel)


class Navigator:
    """State-bound input, with an observer called during every Controller.wait.

    observe(phase, session_snapshot) receives a PHASES member and the controller's
    validated session snapshot. It can collect runtime/fixture evidence or release
    a held request, but must not inject UI input itself. Exceptions stop navigation.
    Only the current fixed four-file/two-directory fixture and TuiHttpA/B are in
    scope. No result from this class means artifact/acquisition/cleanup acceptance.
    """
    def __init__(self, controller, observe=None, *, clock=time.monotonic):
        self.controller = controller
        self.observe = observe
        self.clock = clock
        self.state = "unknown"
        self.failed = False
        self.inputs = self.waits = 0
        self.remote = self.selected = None
        self.provider_count = None
        self.configured = {}
        if observe is not None and not callable(observe):
            raise NavigationError("navigation_input")

    def _check(self):
        if self.failed:
            raise NavigationError("navigation_failed")
        if self.inputs > 192 or self.waits > 256:
            self.failed = True
            raise NavigationError("navigation_budget")

    def _require(self, condition, code="navigation_state"):
        if not condition:
            raise NavigationError(code)

    def _wait(self, phase, predicate, seconds=20):
        self._check()
        self._require(phase in PHASES, "navigation_state")
        self.waits += 1
        self._check()

        def observe(value):
            if self.observe is not None:
                try:
                    self.observe(phase, value)
                except Exception:
                    raise NavigationError("navigation_observer") from None
        try:
            self.controller.wait(predicate, seconds=seconds, observe=observe)
        except NavigationError:
            try:
                navigation_failure_diagnostic(phase, self.controller.screen)
            except Exception:
                pass
            raise
        except Exception:
            try:
                navigation_failure_diagnostic(phase, self.controller.screen)
            except Exception:
                pass
            raise NavigationError("navigation_timeout") from None

    def _key(self, key):
        self.inputs += 1
        self._check()
        self.controller.key(key)

    def _text(self, text):
        self.inputs += 1
        self._check()
        self.controller.text(text)

    @_operation
    def wait_main(self):
        self._require(self.state in ("unknown", "main"))
        self._wait("main", _main)
        self.state = "main"

    @_operation
    def open_manual_http(self):
        self._require(self.state in ("main", "providers"))
        if self.state == "main":
            self._wait("main", _main)
            self._key("enter")  # This MainMenu action performs reset_flow_state.
        self._wait("providers", lambda screen: _provider(screen, dynamic=True) is not None, 30)
        count, backend = _provider(self.controller.screen, dynamic=True)
        self.provider_count = count
        visited = {backend}
        for _ in range(count):
            if backend == "http":
                self._key("space")
                self._wait("provider_step", lambda screen: _provider(
                    screen, dynamic=True, checked=True) == (count, "http"))
                self._key("enter")
                self._wait("remote_prompt", lambda screen: _prompt(screen, "Remote Name"))
                self.state = "remote_prompt"
                self.remote = self.selected = None
                return
            self._key("down")
            sent = self.clock()
            prior = backend
            self._wait("provider_step", lambda screen: (value := _provider(screen, dynamic=True)) is not None
                       and value[0] == count and value[1] != prior, 4)
            _, backend = _provider(self.controller.screen, dynamic=True)
            self._require(backend not in visited, "navigation_catalog")
            visited.add(backend)
            self._wait("provider_debounce", lambda screen: self.clock() - sent >= 0.080 and
                       _provider(screen, dynamic=True) == (count, backend), 1)
        raise NavigationError("navigation_catalog")

    @_operation
    def configure_http(self, remote, url, *, wait_files=True):
        self._require(self.state == "remote_prompt")
        self._require(remote in REMOTES and remote not in self.configured and type(wait_files) is bool,
                      "navigation_input")
        self._require(type(url) is str and re.fullmatch(r"http://127\.0\.0\.1:[1-9][0-9]{0,4}/", url)
                      and int(url.rsplit(":", 1)[1][:-1]) <= 65535 and url not in self.configured.values(),
                      "navigation_input")
        self._wait("remote_prompt", lambda screen: _prompt(screen, "Remote Name"))
        self._text(remote)
        self._wait("remote_echo", lambda screen: _prompt(screen, "Remote Name", remote))
        self._key("enter")
        self._wait("url_prompt", lambda screen: _prompt(screen, "Required Option"))
        self._text(url)
        self._wait("url_echo", lambda screen: _prompt(screen, "Required Option", url))
        self._key("enter")
        self._wait("options_prompt", lambda screen: _prompt(screen, "Backend Option Key"))
        self._key("enter")  # Empty optional key ends configuration; listing is automatic.
        self.remote, self.selected = remote, None
        self.configured[remote] = url
        self.state = "listing"
        if wait_files:
            self.wait_files()

    @_operation
    def wait_files(self):
        self._require(self.state in ("listing", "files"))
        self._wait("files", lambda screen: _files(screen, self.remote), 30)
        self.state = "files"

    @_operation
    def cancel_remote_prompt(self):
        self._require(self.state == "remote_prompt")
        self._wait("remote_prompt", lambda screen: _prompt(screen, "Remote Name"))
        self._key("escape")
        self._wait("prompt_cancel", lambda screen: _provider(
            screen, dynamic=True, checked=True) == (self.provider_count, "http"))
        self._key("space")
        self._wait("prompt_cancel", lambda screen: _provider(
            screen, dynamic=True) == (self.provider_count, "http"))
        self.state = "providers"

    @_operation
    def select_one(self, member):
        self._require(self.state == "files")
        self._require(("file", member) in FILE_ROWS, "navigation_input")
        self._wait("files", lambda screen: _files(screen, self.remote))
        self._text("/")
        self._wait("search_prompt", lambda screen: _prompt(screen, "Find file"))
        self._text(member)
        self._wait("search_echo", lambda screen: _prompt(screen, "Find file", member))
        self._key("enter")
        self._wait("selection_highlight", lambda screen: _files(screen, self.remote, highlighted=member))
        self._key("space")
        self._wait("selection_checked", lambda screen: _files(screen, self.remote, selected=member, highlighted=member))
        self.selected = member
        self.state = "selected"

    @_operation
    def begin_acquisition(self):
        self._require(self.state == "selected")
        self._wait("selection_checked", lambda screen: _files(screen, self.remote, self.selected, self.selected))
        self._key("enter")
        self._wait("acquisition", lambda screen: _acquiring(screen) or _complete(screen, self.remote, False), 30)
        # A short transfer can finish before the next poll. This never claims
        # an active-transfer observation; cancellation requires acquiring below.
        self.state = "acquiring" if _acquiring(self.controller.screen) else "complete"
        return self.state

    @_operation
    def wait_complete(self):
        self._require(self.state in ("acquiring", "complete"))
        self._wait("completion", lambda screen: _complete(screen, self.remote, False), 30)
        self.state = "complete"

    @_operation
    def cancel_acquisition(self):
        """Producer must first prove held transfer/prefix/partial/runtime activity."""
        self._require(self.state == "acquiring" and self.selected == "large/cancel.bin")
        self._wait("cancel_acquisition", _acquiring)
        self._key("escape")
        self._wait("completion", lambda screen: _complete(screen, self.remote, True), 30)
        self.state = "complete"

    @_operation
    def back_to_main(self):
        self._require(self.state in ("complete", "selected", "files", "providers"))
        # Returning from a configured source preserves checked HTTP; returning
        # after prompt cancellation has already observed its explicit removal.
        # Backspace does not toggle either state. The next MainMenu reset must
        # independently render a zero aggregate before another setup begins.
        def providers(screen):
            return _provider(screen, dynamic=False, checked=self.remote is not None) == (
                self.provider_count, "http")
        if self.state == "complete":
            self._require(_complete(self.controller.screen, self.remote, False) or
                          _complete(self.controller.screen, self.remote, True), "navigation_screen")
            self._key("backspace")
            self._wait("back_files", lambda screen: _files(screen, self.remote, self.selected))
            self.state = "selected" if self.selected is not None else "files"
        if self.state in ("files", "selected"):
            self._wait("back_files", lambda screen: _files(screen, self.remote, self.selected))
            for phase, predicate in (("back_postauth", _post_auth), ("back_auth", _auth), ("back_browser", _browser),
                                     ("back_providers", providers)):
                self._key("backspace")
                self._wait(phase, predicate)
            self.state = "providers"
        self._wait("back_providers", providers)
        self._key("backspace")
        self._wait("back_main", _main)
        self.remote = self.selected = None
        self.provider_count = None
        self.state = "main"
