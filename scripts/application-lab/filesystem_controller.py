"""Fixed source-folder transport for hosted filesystem tests, not evidence.

This is the ordinary non-debug session used by the cancellation path. A future
launch-image observer must use its own explicit response contract.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import types

HERE = Path(__file__).resolve().parent


def _load_support():
    path = HERE / "run_windows_http.py"
    data = path.read_bytes()
    module = types.ModuleType("filesystem_http_support")
    module.__file__ = str(path)
    exec(compile(data, str(path), "exec"), module.__dict__)
    module.loaded_source_sha256 = hashlib.sha256(data).hexdigest()
    return module


H = _load_support()
SOURCE_ERRORS = frozenset({"source_directory_invalid", "source_directory_cleanup_failed"})
SESSION_ACTIONS = frozenset({"start_source", "poll", "observe_runtime", "ctrl_c", "finish"})


def validate_snapshot(value, action):
    """Keep the existing live-image contract and only add source-folder errors."""
    H.need(type(action) is str and action in SESSION_ACTIONS and
           type(value) is dict and set(value) == H.SESSION_KEYS, "session_failed")
    errors = value["errors"]
    H.need(type(errors) is list and len(errors) <= 24 and
           all(type(error) is str and error in H.SESSION_ERRORS | SOURCE_ERRORS for error in errors) and
           len(set(errors)) == len(errors), "session_failed")
    common = dict(value)
    common["errors"] = list(dict.fromkeys(error if error in H.SESSION_ERRORS else "protocol_invalid"
                                         for error in errors))
    H.validate_session(common, action)
    return value


class SourceBridge(H.Bridge):
    """Use only the helper's fixed case/source mode; no caller-selected cwd."""
    actions = (H.BRIDGE_ACTIONS - {"start"}) | {"start_source"}

    def __init__(self, case):
        # Refuse before the base constructor creates files or starts a helper.
        H.hosted_guard()
        super().__init__(case)

    def validate_session(self, value, action):
        return validate_snapshot(value, action)

    def _diagnostic(self, action, phase, outcome):
        try:
            with self.response_lock:
                stage = None if self.stage_invalid else H.bridge_stage(bytes(self.stage_bytes))
            action = action if type(action) is str and action in self.actions else "invalid"
            H.need(type(phase) is str and phase in H.BRIDGE_PHASES and
                   type(outcome) is str and outcome in H.BRIDGE_OUTCOMES, "session_failed")
            print("application_filesystem_session_diagnostic=" + H.E.compact(dict(
                action=action, phase=phase, outcome=outcome, last_stage=stage)).decode("ascii"), flush=True)
        except BaseException:
            pass  # Diagnostics must preserve the original failure.

    def failure_diagnostic(self, value, action):
        value = validate_snapshot(value, action)
        H.need(not value["ok"], "session_failed")
        payload = H.E.compact(dict(action=action, errors=value["errors"],
            forced_termination=value["forced_termination"], app_exited=value["app_exited"],
            runtime_process_count=value["runtime_process_count"]))
        H.need(len(payload) <= 4096, "session_failed")
        print("application_filesystem_session_failure=" + payload.decode("ascii"), flush=True)
