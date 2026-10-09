"""Bounded TUI transport and private screen observation, not acceptance evidence.

Native work occurs only when the hosted producer explicitly constructs a bridge.
Screen text must remain private; file and request oracles establish acquisition.
"""
from __future__ import annotations

import os
import hashlib
from pathlib import Path
import time
import types

HERE = Path(__file__).resolve().parent


def _load(name, path):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    data = path.read_bytes()
    exec(compile(data, str(path), "exec"), module.__dict__)
    module.loaded_source_sha256 = hashlib.sha256(data).hexdigest()
    return module


H = _load("tui_http_support", HERE / "run_windows_http.py")
S = _load("tui_screen_support", HERE / "tui_screen.py")
KEY_BYTES = {
    "enter": b"\r", "escape": b"\x1b", "up": b"\x1b[A", "down": b"\x1b[B",
    "right": b"\x1b[C", "left": b"\x1b[D", "tab": b"\t", "backspace": b"\x7f",
    "home": b"\x1b[H", "end": b"\x1b[F", "page_up": b"\x1b[5~",
    "page_down": b"\x1b[6~", "space": b" ",
}
TUI_FIELDS = frozenset({"input_commands", "input_bytes", "resize_count", "columns", "rows",
                        "protocol_commands", "protocol_bytes"})
# Kept separate from the legacy CLI protocol's closed failure vocabulary.
TUI_ERRORS = frozenset({"tui_input_refused", "tui_resize_refused", "resize_failed",
                       "resize_timeout", "resize_cleanup_failed"})
SIZES = frozenset({(120, 34), (80, 24)})
SESSION_ACTIONS = frozenset({"start", "poll", "observe_runtime", "key", "text", "resize", "ctrl_c", "finish"})
COUNTER_BOUNDS = {"input_commands": 256, "input_bytes": 8192, "resize_count": 16,
                  "protocol_commands": 1024, "protocol_bytes": 1024 * 1024,
                  "columns": 120, "rows": 34}


def validate_snapshot(value, action):
    """Validate closed fields without replaying a session's counter transition."""
    H.need(type(action) is str and action in SESSION_ACTIONS and
           type(value) is dict and set(value) == H.SESSION_KEYS | TUI_FIELDS and
           type(value["schema_version"]) is int and value["schema_version"] == 2, "session_failed")
    errors = value["errors"]
    H.need(type(errors) is list and len(errors) <= 24 and
           all(type(e) is str and e in H.SESSION_ERRORS | TUI_ERRORS for e in errors) and
           len(set(errors)) == len(errors), "session_failed")
    common = {key: value[key] for key in H.SESSION_KEYS}
    common["schema_version"] = 1
    common["errors"] = list(dict.fromkeys(e if e in H.SESSION_ERRORS else "protocol_invalid" for e in errors))
    H.validate_session(common, action)
    H.need(all(type(value[k]) is int and 0 <= value[k] <= limit for k, limit in COUNTER_BOUNDS.items()) and
           (value["columns"], value["rows"]) in SIZES, "session_failed")
    return value


class TuiBridge(H.Bridge):
    script_name = "hosted_tui_session.ps1"
    actions = H.BRIDGE_ACTIONS | {"key", "text", "resize"}

    def __init__(self, case):
        self.wire_bytes = 0
        self.request = None
        super().__init__(case)

    def command(self, action, **fields):
        self.request = dict(action=action, **fields)
        self.wire_bytes += len(H.E.compact(self.request)) + 1
        H.need(self.wire_bytes <= 1024 * 1024, "session_failed")
        return super().command(action, **fields)

    def validate_session(self, value, action):
        validate_snapshot(value, action)
        H.need(value["protocol_commands"] == self.calls and value["protocol_bytes"] == self.wire_bytes,
               "session_failed")
        previous = self.last if self.last and self.last.get("schema_version") == 2 else {
            "input_commands": 0, "input_bytes": 0, "resize_count": 0, "columns": 120, "rows": 34}
        H.need(all(value[key] >= previous[key] for key in ("input_commands", "input_bytes", "resize_count")),
               "session_failed")
        if value["ok"]:
            request = self.request
            added = (len(KEY_BYTES.get(request.get("key"), b"")) if action == "key" else
                     len(request.get("text", "").encode("ascii")) if action == "text" else 0)
            H.need(action not in {"key", "text"} or added > 0, "session_failed")
            H.need(value["input_commands"] == previous["input_commands"] + int(action in {"key", "text"}) and
                   value["input_bytes"] == previous["input_bytes"] + added and
                   value["resize_count"] == previous["resize_count"] + int(action == "resize"), "session_failed")
            size = ((request["columns"], request["rows"]) if action == "resize" else
                    (previous["columns"], previous["rows"]))
            H.need((value["columns"], value["rows"]) == size, "session_failed")
        return value

    def failure_diagnostic(self, value, action):
        # Bridge has already saved this reply. Do not replay counter deltas
        # against self.last, which now refers to the same response.
        validate_snapshot(value, action)
        H.need(value is self.last and not value["ok"] and
               value["protocol_commands"] == self.calls and value["protocol_bytes"] == self.wire_bytes,
               "session_failed")
        count = value["runtime_process_count"]
        classification = "unavailable" if count is None else "none" if count == 0 else "single" if count == 1 else "multiple"
        payload = H.E.compact(dict(action=action, errors=value["errors"], forced_termination=value["forced_termination"],
            app_exited=value["app_exited"], runtime_process_count=count, count_classification=classification,
            output_bytes=value["output_bytes"], **{key: value[key] for key in sorted(TUI_FIELDS)}))
        line = b"application_tui_session_failure=" + payload
        H.need(len(line) + 1 <= 4096, "session_failed")
        print(line.decode("ascii"), flush=True)


class Transcript:
    """Read only appended bytes of the same regular file in the owned case.

    The native helper retains the transcript writer without write/delete sharing.
    This reader never interprets terminal text as proof of a successful transfer.
    """
    def __init__(self, case):
        self.case = Path(case)
        self.root_identity = H.identity(self.case)
        self.path = self.case / "transcript.private"
        self.stream = None
        self.file_identity = None
        self.offset = 0
        self.maximum_seen = 0

    def available(self):
        H.need(H.identity(self.case) == self.root_identity, "preservation_failed")
        if self.stream is None:
            if not self.path.exists():
                return b""
            before = H.plain(self.path)
            self.stream = self.path.open("rb", buffering=0)
            current = os.fstat(self.stream.fileno())
            H.need((before.st_dev, before.st_ino) == (current.st_dev, current.st_ino), "preservation_failed")
            self.file_identity = current.st_dev, current.st_ino
        info = H.plain(self.path)
        opened = os.fstat(self.stream.fileno())
        H.need((info.st_dev, info.st_ino) == (opened.st_dev, opened.st_ino) == self.file_identity and
               self.maximum_seen <= info.st_size <= 8 * 1024 * 1024, "preservation_failed")
        self.maximum_seen = info.st_size
        requested = min(65536, info.st_size - self.offset)
        data = self.stream.read(requested)
        after = H.plain(self.path)
        held = os.fstat(self.stream.fileno())
        H.need(H.identity(self.case) == self.root_identity and
               (after.st_dev, after.st_ino) == (held.st_dev, held.st_ino) == self.file_identity and
               info.st_size <= after.st_size <= 8 * 1024 * 1024 and held.st_size >= info.st_size and
               type(data) is bytes and len(data) == requested, "preservation_failed")
        self.offset += len(data)
        return data

    def close(self):
        if self.stream is not None:
            self.stream.close()


class Controller:
    """A finite interaction budget; predicates inspect private screen state only."""
    def __init__(self, case, bridge, *, seconds=120):
        H.need(type(seconds) is int and 1 <= seconds <= 120, "deadline_exceeded")
        self.bridge = bridge
        self.transcript = Transcript(case)
        self.screen = S.Screen(columns=120, rows=34)
        self.resize_unproven = False
        self.deadline = time.monotonic() + seconds

    def drain(self):
        H.need(time.monotonic() < self.deadline, "deadline_exceeded")
        # At most the entire native output budget, never an unbounded writer tail.
        for _ in range(129):
            data = self.transcript.available()
            H.need(time.monotonic() < self.deadline, "deadline_exceeded")
            if not data:
                return
            self.screen.feed(data)
            H.need(time.monotonic() < self.deadline, "deadline_exceeded")
        raise H.ProducerError("session_failed")

    def poll(self):
        value = self.bridge.command("poll")
        H.need(value["ok"] and not value["app_exited"] and value["state"] == "running", "session_failed")
        self.drain()
        return value

    def wait(self, predicate, *, seconds=20, observe=None):
        H.need(type(seconds) is int and 1 <= seconds <= 60, "deadline_exceeded")
        H.need(not self.resize_unproven, "session_failed")
        end = min(self.deadline, time.monotonic() + seconds)
        while time.monotonic() < end:
            value = self.poll()
            H.need(time.monotonic() < end, "deadline_exceeded")
            if observe is not None:
                observe(value)
            H.need(time.monotonic() < end, "deadline_exceeded")
            matched = self.screen.ready and not self.screen.pending and predicate(self.screen)
            H.need(time.monotonic() < end, "deadline_exceeded")
            if matched:
                H.need(not self.resize_unproven, "session_failed")
                return
            time.sleep(0.05)
        raise H.ProducerError("deadline_exceeded")

    def key(self, key):
        H.need(time.monotonic() < self.deadline, "deadline_exceeded")
        H.need(type(key) is str and key in KEY_BYTES, "session_failed")
        H.need(self.bridge.command("key", key=key)["ok"], "session_failed")
        H.need(time.monotonic() < self.deadline, "deadline_exceeded")

    def text(self, text):
        H.need(time.monotonic() < self.deadline, "deadline_exceeded")
        H.need(type(text) is str and 1 <= len(text) <= 256 and all(32 <= ord(c) <= 126 for c in text),
               "session_failed")
        H.need(self.bridge.command("text", text=text)["ok"], "session_failed")
        H.need(time.monotonic() < self.deadline, "deadline_exceeded")

    def resize(self, columns, rows):
        H.need(type(columns) is int and type(rows) is int and (columns, rows) in SIZES, "session_failed")
        self.drain()
        H.need(self.bridge.command("resize", columns=columns, rows=rows)["ok"], "session_failed")
        H.need(time.monotonic() < self.deadline, "deadline_exceeded")
        # Buffered old-size frames can arrive after acknowledgment. Parser
        # readiness alone cannot prove freshness. A future producer must supply
        # independently reviewed causal evidence before resize waits can pass.
        self.resize_unproven = True
        self.screen.resize(columns, rows)

    def close(self):
        self.transcript.close()
