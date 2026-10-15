"""Bounded TUI transport and private screen observation, not acceptance evidence.

Native work occurs only when the hosted producer explicitly constructs a bridge.
Screen text must remain private; file and request oracles establish acquisition.
"""
from __future__ import annotations

import os
import hashlib
import json
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
WAIT_STAGES = frozenset({"precondition", "poll", "observe", "predicate", "deadline"})
WAIT_ERRORS = frozenset({"deadline_exceeded", "session_failed", "preservation_failed"})


class MainMenuFailure:
    """Closed self-report from already-read bytes; never an acceptance oracle."""
    PREFIX = b"ui_main_menu_failure="
    MAX_RECORD = 512
    OPERATIONS = frozenset({"flow_reset", "provider_refresh"})
    STAGES = frozenset({"target", "open_root", "identity", "security", "remove_tree"})
    KINDS = frozenset({"not_found", "permission_denied", "already_exists", "invalid_input",
                       "unsupported", "interrupted", "other"})

    def __init__(self):
        self.buffer = b""
        self.collecting = False
        self.records = 0
        self.invalid = False
        self.value = None
        self.emitted = False

    @classmethod
    def parse(cls, raw):
        if type(raw) is not bytes or len(raw) > cls.MAX_RECORD:
            raise ValueError("diagnostic_invalid")
        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("diagnostic_invalid")
                value[key] = item
            return value
        value = json.loads(raw.decode("ascii"), object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("diagnostic_invalid")))
        if (type(value) is not dict or set(value) != {"operation", "category", "cleanup"} or
                type(value["operation"]) is not str or value["operation"] not in cls.OPERATIONS or
                type(value["category"]) is not str):
            raise ValueError("diagnostic_invalid")
        detail = value["cleanup"]
        if value["category"] == "unknown":
            if detail is not None:
                raise ValueError("diagnostic_invalid")
        elif value["category"] == "typed_runtime_cleanup":
            if (type(detail) is not dict or set(detail) != {"stage", "kind", "os_code"} or
                    type(detail["stage"]) is not str or detail["stage"] not in cls.STAGES or
                    type(detail["kind"]) is not str or detail["kind"] not in cls.KINDS or
                    not (detail["os_code"] is None or type(detail["os_code"]) is int and 0 <= detail["os_code"] <= 65535)):
                raise ValueError("diagnostic_invalid")
        else:
            raise ValueError("diagnostic_invalid")
        return value

    def feed(self, data):
        if self.invalid or self.records > 1:
            return
        try:
            if type(data) is not bytes or len(data) > 65536:
                raise ValueError("diagnostic_invalid")
            self.buffer += data
            while True:
                if not self.collecting:
                    index = self.buffer.find(self.PREFIX)
                    if index < 0:
                        self.buffer = self.buffer[-(len(self.PREFIX) - 1):]
                        return
                    self.records += 1
                    if self.records > 1:
                        self.buffer = b""
                        return
                    self.collecting = True
                    self.buffer = self.buffer[index + len(self.PREFIX):]
                end = self.buffer.find(b"\n")
                if end < 0:
                    if len(self.buffer) > self.MAX_RECORD:
                        raise ValueError("diagnostic_invalid")
                    return
                raw = self.buffer[:end]
                if raw.endswith(b"\r"):
                    raw = raw[:-1]
                self.value = self.parse(raw)
                self.collecting = False
                self.buffer = self.buffer[end + 1:]
        except Exception:
            self.invalid = True
            self.buffer = b""

    def projection(self):
        status = ("invalid" if self.invalid or self.collecting else
                  "ambiguous" if self.records > 1 else "observed" if self.value is not None else "not_observed")
        fields = self.value if status == "observed" else dict(operation=None, category=None, cleanup=None)
        return dict(status=status, **fields)

    def emit(self):
        try:
            if self.emitted:
                return
            self.emitted = True
            value = self.projection()
            if value["status"] == "not_observed":
                return
            line = b"application_tui_main_menu_failure=" + H.E.compact(value)
            if len(line) + 1 <= 1024:
                print(line.decode("ascii"), flush=True)
        except Exception:
            pass


def wait_failure_diagnostic(error, stage, screen, predicate_invoked):
    """Finite facts only; no exception formatting or private screen contents.

    Navigation deliberately has a smaller public failure vocabulary. Keep the
    originating parser/transport failure visible before that translation. This
    diagnostic never changes the acceptance result or replaces its exception.
    """
    try:
        if type(stage) is not str or stage not in WAIT_STAGES or type(predicate_invoked) is not bool:
            return
        kind, code = "unexpected", "unexpected_failure"
        if type(error) is S.ScreenError and type(error.code) is str and error.code in S.CODES:
            kind, code = "screen", error.code
        elif (type(error) is H.ProducerError and len(error.args) == 1 and
              type(error.args[0]) is str and error.args[0] in WAIT_ERRORS):
            kind, code = "controller", error.args[0]
        # Require the actual parser, so arbitrary object properties cannot
        # inject values or execute while constructing this public diagnostic.
        ready = pending = byte_count = None
        if type(screen) is S.Screen:
            ready, pending, byte_count = screen.ready, screen.pending, screen.total_bytes
            if (type(ready) is not bool or type(pending) is not bool or
                    type(byte_count) is not int or not 0 <= byte_count <= S.MAX_BYTES):
                return
        payload = H.E.compact(dict(stage=stage, reason_type=kind, reason_code=code,
            screen_ready=ready, screen_pending=pending, screen_bytes=byte_count,
            predicate_invoked=predicate_invoked))
        line = b"application_tui_wait_failure=" + payload
        if len(line) + 1 <= 1024:
            print(line.decode("ascii"), flush=True)
    except Exception:
        # Broken output must not hide the original failure or enable a retry.
        pass


def controller_failure_diagnostic(stage, value=None):
    """Distinguish two existing failures without another poll or transcript read."""
    try:
        if type(stage) is not str or stage not in {"running_predicate", "drain_bound"}:
            return
        fields = {key: None for key in ("state", "ok", "app_exited", "app_exit_code", "forced_termination")}
        if stage == "running_predicate":
            # Pure schema validation only; never replay bridge counter transitions.
            validate_snapshot(value, "poll")
            if type(value["state"]) is not str or (value["ok"] and not value["app_exited"] and value["state"] == "running"):
                return
            fields = {key: value[key] for key in fields}
        elif value is not None:
            return
        # drain() also serves non-poll callers. Its bound has no supplied reply;
        # null means unavailable, not a second observation or an inferred exit.
        line = b"application_tui_controller_failure=" + H.E.compact(dict(stage=stage, **fields))
        if len(line) + 1 <= 512:
            print(line.decode("ascii"), flush=True)
    except Exception:
        pass  # Diagnostics cannot replace the original controller failure.


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
        self.main_menu_failure = MainMenuFailure()
        self.main_menu_tail_needed = False
        self.main_menu_tail_attempted = False
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
            try:
                self.main_menu_failure.feed(data)
            except Exception:
                pass
            self.screen.feed(data)
            H.need(time.monotonic() < self.deadline, "deadline_exceeded")
        controller_failure_diagnostic("drain_bound")
        raise H.ProducerError("session_failed")

    def poll(self):
        value = self.bridge.command("poll")
        try:
            H.need(value["ok"] and not value["app_exited"] and value["state"] == "running", "session_failed")
        except H.ProducerError:
            self.main_menu_tail_needed = True
            controller_failure_diagnostic("running_predicate", value)
            raise
        self.drain()
        return value

    def wait(self, predicate, *, seconds=20, observe=None):
        stage, invoked = "precondition", False
        try:
            H.need(type(seconds) is int and 1 <= seconds <= 60, "deadline_exceeded")
            H.need(not self.resize_unproven, "session_failed")
            end = min(self.deadline, time.monotonic() + seconds)
            while time.monotonic() < end:
                stage = "poll"
                value = self.poll()
                H.need(time.monotonic() < end, "deadline_exceeded")
                stage = "observe"
                if observe is not None:
                    observe(value)
                H.need(time.monotonic() < end, "deadline_exceeded")
                stage = "predicate"
                matched = False
                if self.screen.ready and not self.screen.pending:
                    invoked = True
                    matched = predicate(self.screen)
                H.need(time.monotonic() < end, "deadline_exceeded")
                if matched:
                    H.need(not self.resize_unproven, "session_failed")
                    return
                stage = "deadline"
                time.sleep(0.05)
            stage = "deadline"
            raise H.ProducerError("deadline_exceeded")
        except Exception as error:
            wait_failure_diagnostic(error, stage, self.screen, invoked)
            raise

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

    def capture_main_menu_tail(self):
        # Called only at close, after the caller's original bridge close attempt.
        # A finite diagnostic read is not a wait for a writer or an acceptance drain.
        if not self.main_menu_tail_needed or self.main_menu_tail_attempted:
            return
        self.main_menu_tail_attempted = True
        try:
            for _ in range(129):
                data = self.transcript.available()
                if data == b"":
                    return
                self.main_menu_failure.feed(data)
            raise ValueError("diagnostic_invalid")
        except Exception:
            self.main_menu_failure.invalid = True
            self.main_menu_failure.buffer = b""
            self.main_menu_failure.value = None

    def close(self):
        try:
            self.capture_main_menu_tail()
        except Exception:
            # Diagnostic state failures must not bypass the original close.
            try:
                self.main_menu_failure.invalid = True
                self.main_menu_failure.value = None
            except Exception:
                pass
        try:
            self.transcript.close()
        finally:
            try:
                self.main_menu_failure.emit()
            except Exception:
                pass
