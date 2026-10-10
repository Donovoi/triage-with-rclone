"""Fixed source-folder transport for hosted filesystem tests, not evidence.

SourceBridge is the ordinary session used by cancellation. ObservedSourceBridge
is an opt-in launch-image transport; its observations alone earn no acceptance.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
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


DEBUG_ERRORS = frozenset({"debug_start_failed", "debug_event_failed", "debug_image_invalid",
    "debug_launch_limit", "debug_exception_failed", "debug_event_limit", "debug_cleanup_failed"})
OBSERVED_ACTIONS = frozenset({"start_source_observed", "poll", "finish", "invalid", "eof"})
OBSERVED_KEYS = H.SESSION_KEYS | frozenset({"observation_kind", "launch_image_observed", "launch_sha256",
    "runtime_launch_count", "peak_runtime_processes", "debug_event_count", "debug_events_drained",
    "debug_pump_joined", "debug_handles_closed", "system_helper_image_observed", "system_helper_sha256",
    "system_helper_launch_count", "peak_system_helper_processes", "system_helper_reference_closed"})
OBSERVED_START_FIELDS = frozenset({"app_path", "app_sha256", "args", "case_root", "environment",
    "transcript_path", "max_output_bytes", "deadline_ms", "max_runtime_processes",
    "expected_runtime_sha256", "max_runtime_launches"})
OBSERVED_CLEANUP = ("debug_events_drained", "debug_pump_joined", "debug_handles_closed",
                    "system_helper_reference_closed")


def _hash(value):
    return type(value) is str and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def validate_observed_snapshot(value, action, expected_runtime_sha256, max_runtime_processes, max_runtime_launches):
    """Closed transport schema; running/failed observations are never final credit."""
    H.need(_hash(expected_runtime_sha256) and type(max_runtime_processes) is int and
           1 <= max_runtime_processes <= 4 and type(max_runtime_launches) is int and
           1 <= max_runtime_launches <= 32, "session_failed")
    H.need(type(action) is str and action in OBSERVED_ACTIONS and type(value) is dict and
           set(value) == OBSERVED_KEYS and type(value["schema_version"]) is int and
           value["schema_version"] == 3 and value["action"] == action and
           value["observation_kind"] == "launch_image" and type(value["state"]) is str, "session_failed")
    errors = value["errors"]
    allowed = H.SESSION_ERRORS | SOURCE_ERRORS | DEBUG_ERRORS
    H.need(type(errors) is list and len(errors) <= len(allowed) and
           all(type(error) is str and error in allowed for error in errors) and len(set(errors)) == len(errors), "session_failed")
    common = {key: value[key] for key in H.SESSION_KEYS}
    common["schema_version"] = 1
    common["errors"] = list(dict.fromkeys(error if error in H.SESSION_ERRORS else "protocol_invalid" for error in errors))
    # A failed prelaunch Finish can confirm there is no app without an exit code.
    # This exception cannot qualify a successful completed observation.
    if value["ok"] is False and value["app_exit_code"] is None:
        H.need(type(value["app_exited"]) is bool, "session_failed")
        common["app_exited"] = False
    H.validate_session(common, action)
    H.need(value["runtime_image_observed"] is False and value["runtime_sha256"] is None and
           value["runtime_process_count"] is None and value["ctrl_c_sent"] is False, "session_failed")
    for key in ("launch_image_observed", "system_helper_image_observed", *OBSERVED_CLEANUP):
        H.need(type(value[key]) is bool, "session_failed")
    for key in ("runtime_launch_count", "peak_runtime_processes", "system_helper_launch_count", "peak_system_helper_processes"):
        H.need(type(value[key]) is int and 0 <= value[key] <= 33, "session_failed")
    launches, helpers = value["runtime_launch_count"], value["system_helper_launch_count"]
    H.need(launches + helpers <= 33 and type(value["debug_event_count"]) is int and
           0 <= value["debug_event_count"] <= 4096 and
           (launches + helpers == 0 or value["debug_event_count"] >= launches + helpers + 1), "session_failed")
    for count, peak in ((launches, value["peak_runtime_processes"]), (helpers, value["peak_system_helper_processes"])):
        H.need((count == 0 and peak == 0) or 1 <= peak <= count, "session_failed")
    H.need((value["launch_image_observed"] and launches > 0 and value["launch_sha256"] == expected_runtime_sha256) or
           (not value["launch_image_observed"] and value["launch_sha256"] is None), "session_failed")
    H.need((value["system_helper_image_observed"] and helpers > 0 and _hash(value["system_helper_sha256"])) or
           (not value["system_helper_image_observed"] and value["system_helper_sha256"] is None), "session_failed")
    H.need(not value["debug_handles_closed"] or all(value[key] for key in OBSERVED_CLEANUP), "session_failed")
    H.need(not value["system_helper_reference_closed"] or value["state"] == "finished", "session_failed")
    if action in {"invalid", "eof"}:
        H.need(value["ok"] is False and value["state"] == "finished", "session_failed")
    if value["ok"]:
        H.need(launches <= max_runtime_launches and value["peak_runtime_processes"] <= max_runtime_processes and
               helpers <= launches and helpers <= max_runtime_launches and value["peak_system_helper_processes"] <= 2 and
               1 + launches + helpers <= min(34, 1 + 2 * max_runtime_launches), "session_failed")
        if value["state"] == "finished":
            H.need(launches >= 1 and value["launch_image_observed"] and
                   (helpers == 0 or value["system_helper_image_observed"]) and
                   value["debug_event_count"] >= 3 * (1 + launches + helpers) and
                   all(value[key] for key in (*H.SESSION_CLEANUP, *OBSERVED_CLEANUP)) and
                   not value["forced_termination"] and not value["output_limit_exceeded"], "session_failed")
    if action == "finish":
        H.need(value["state"] == "finished", "session_failed")
    return value


class ObservedSourceBridge(SourceBridge):
    """Prearmed launch-image mode. No live-image or Ctrl+C substitution."""
    actions = frozenset({"invalid", "ready", "close_ready", "start_source_observed", "poll", "finish", "close"})

    def __init__(self, case):
        self.observer_started = False
        self.expected_runtime_sha256 = None
        self.max_runtime_processes = self.max_runtime_launches = 0
        self.observer_previous = None
        self.observer_helper_hash = None
        super().__init__(case)  # The unchanged SourceBridge guard precedes native work.

    def command(self, action, **fields):
        try:
            H.need(type(action) is str and action in self.actions - {"invalid", "close"}, "session_failed")
            H.need(self.last is None or self.last["state"] not in {"finished", "closed"}, "session_failed")
            if action == "start_source_observed":
                H.need(not self.observer_started and set(fields) == OBSERVED_START_FIELDS and
                       _hash(fields["app_sha256"]) and
                       all(type(fields[key]) is str and 1 <= len(fields[key]) <= 4096 and "\0" not in fields[key]
                           for key in ("app_path", "case_root", "transcript_path")) and
                       type(fields["args"]) is list and len(fields["args"]) <= 64 and
                       all(type(arg) is str and len(arg) <= 4096 and "\0" not in arg for arg in fields["args"]) and
                       type(fields["environment"]) is dict and
                       all(type(key) is str and type(item) is str and "\0" not in key + item
                           for key, item in fields["environment"].items()) and
                       type(fields["max_output_bytes"]) is int and 1024 <= fields["max_output_bytes"] <= 8388608 and
                       type(fields["deadline_ms"]) is int and 1000 <= fields["deadline_ms"] <= 180000 and
                       _hash(fields["expected_runtime_sha256"]) and type(fields["max_runtime_processes"]) is int and
                       1 <= fields["max_runtime_processes"] <= 4 and type(fields["max_runtime_launches"]) is int and
                       1 <= fields["max_runtime_launches"] <= 32, "session_failed")
                self.observer_started = True  # A possibly issued launch is never retried.
                self.expected_runtime_sha256 = fields["expected_runtime_sha256"]
                self.max_runtime_processes = fields["max_runtime_processes"]
                self.max_runtime_launches = fields["max_runtime_launches"]
            elif action in {"poll", "finish"}:
                H.need(self.observer_started and set(fields) == ({"grace_ms"} if action == "finish" else set()), "session_failed")
                if action == "finish":
                    H.need(type(fields["grace_ms"]) is int and 0 <= fields["grace_ms"] <= 10000, "session_failed")
            else:
                H.need(not self.observer_started and not fields, "session_failed")
        except H.ProducerError:
            self.failed.set(); self._diagnostic(action, "preflight", "rejected")
            raise H.ProducerError("session_failed") from None
        return super().command(action, **fields)

    def validate_session(self, value, action):
        value = validate_observed_snapshot(value, action, self.expected_runtime_sha256,
                                          self.max_runtime_processes, self.max_runtime_launches)
        previous = self.observer_previous
        if previous is not None:
            for key in ("runtime_launch_count", "peak_runtime_processes", "system_helper_launch_count",
                        "peak_system_helper_processes", "debug_event_count", "output_bytes"):
                H.need(value[key] >= previous[key], "session_failed")
            H.need(set(previous["errors"]) <= set(value["errors"]) and
                   (previous["state"] != "finished" or value["state"] == "finished") and
                   (not previous["launch_image_observed"] or value["launch_image_observed"]) and
                   (not previous["forced_termination"] or value["forced_termination"]) and
                   (previous["app_exit_code"] is None or value["app_exit_code"] == previous["app_exit_code"]), "session_failed")
        if value["system_helper_sha256"] is not None:
            H.need(self.observer_helper_hash in (None, value["system_helper_sha256"]), "session_failed")
            self.observer_helper_hash = value["system_helper_sha256"]
        self.observer_previous = dict(value, errors=list(value["errors"]))
        return value

    def failure_diagnostic(self, value, action):
        value = validate_observed_snapshot(value, action, self.expected_runtime_sha256,
                                          self.max_runtime_processes, self.max_runtime_launches)
        H.need(not value["ok"], "session_failed")
        payload = H.E.compact(dict(action=action, errors=value["errors"],
            forced_termination=value["forced_termination"], app_exited=value["app_exited"],
            runtime_launch_count=value["runtime_launch_count"], peak_runtime_processes=value["peak_runtime_processes"],
            system_helper_launch_count=value["system_helper_launch_count"], debug_event_count=value["debug_event_count"],
            debug_handles_closed=value["debug_handles_closed"], system_helper_reference_closed=value["system_helper_reference_closed"]))
        H.need(len(payload) <= 4096, "session_failed")
        print("application_filesystem_launch_failure=" + payload.decode("ascii"), flush=True)
