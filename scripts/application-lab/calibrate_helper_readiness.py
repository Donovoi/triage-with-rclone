#!/usr/bin/env python3
"""One hosted first-helper readiness calibration; no application or provider run."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sys
import types

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
with (HERE / "run_windows_http.py").open("rb") as stream:
    _source = stream.read(512 * 1024 + 1)
if len(_source) > 512 * 1024:
    raise ValueError("source_limit")
H = types.ModuleType("readiness_http")
H.__file__ = str(HERE / "run_windows_http.py")
exec(compile(_source, H.__file__, "exec"), H.__dict__)
H.need(H.SELF_SHA256 == H.sha(_source), "preservation_failed")
SELF_SHA256 = H.sha(H.read(Path(__file__), 65536))
SOURCE_FILES = (
    ".github/workflows/ci.yml", "scripts/application-lab/calibrate_helper_readiness.py",
    "scripts/application-lab/run_windows_http.py", "scripts/application-lab/HostedConPtySession.cs",
    "scripts/application-lab/hosted_session.ps1", "scripts/application-lab/prepare_case.ps1",
    "scripts/application-lab/owned_helper_process.py", "scripts/application-lab/fixture_http.py",
    "scripts/application_evidence.py", "scripts/application_source_snapshot.py",
)
TIMING_FIELDS = ("compile_seen_ms", "compiled_seen_ms", "write_returned_ms",
                 "wait_started_ms", "wait_budget_ms", "observed_end_ms")


def projection(snapshot, phase, outcome):
    """Parent marker/response arrival facts, not compiler duration or causation."""
    H.need(phase in {"preflight", "write", "wait", "reply"} and
           outcome in {"passed", "timeout", "io_failed", "protocol_failed", "rejected"}, "session_failed")
    value = dict(clock="parent_monotonic", phase=phase, outcome=outcome,
                 status="unavailable", **dict.fromkeys(TIMING_FIELDS))
    if type(snapshot) is not tuple or len(snapshot) != 7:
        return value
    origin, first, second, written, waiting, budget, end = snapshot
    clocks = (origin, first, second, written, waiting, end)
    present = tuple(item for item in clocks if item is not None)
    if origin is None or end is None or not all(type(item) in (int, float) and
            float("-inf") < item < float("inf") for item in present):
        return value
    if not (origin <= end and all(origin <= item <= end for item in present) and
            (second is None or first is not None and first <= second) and
            (waiting is None or written is not None and written <= waiting) and
            ((waiting is None and budget is None) or waiting is not None and
             type(budget) in (int, float) and 0.01 <= budget <= 120) and
            all(0 <= item - origin <= 2147483.647 for item in present)):
        return value
    if (phase in {"wait", "reply"} and (written is None or waiting is None) or
            phase not in {"wait", "reply"} and (written is not None or waiting is not None)):
        return value
    if outcome == "passed" and (phase != "reply" or first is None or second is None or
            end > origin + 165 or end > waiting + budget):
        return value
    values = (first, second, written, waiting, None, end)
    milliseconds = [None if item is None else int((item-origin)*1000) for item in values]
    milliseconds[4] = None if budget is None else int(budget*1000)
    value.update(status="observed", **dict(zip(TIMING_FIELDS, milliseconds)))
    return value


class CalibrationTiming(H._ReadyTiming):
    """Uses the existing marker cache; freezes once before cleanup can backfill it."""
    def capture(self, raw, invalid, phase, outcome):
        if self.frozen:
            return
        self.frozen = True
        stage, first, second = self.stage_value
        end = H.time.monotonic()
        snapshot = (self.origin, first, second, self.written, *self.waiting, end)
        coherent = (raw == b"" and first is None and second is None or
                    H.bridge_stage(raw) == "compile" and first is not None and second is None or
                    H.bridge_stage(raw) == "compiled" and first is not None and second is not None)
        self.snapshot = snapshot if not self.invalid and not invalid and raw == stage and coherent else None
        self.record = projection(self.snapshot, phase, outcome)

    def failure(self, raw, invalid, phase, outcome):
        self.capture(raw, invalid, phase, outcome)


class CalibrationBridge(H.Bridge):
    # No runtime CLI/env knob; normal Bridge and all application paths stay at90.
    actions = frozenset({"ready", "close_ready", "close"})
    ready_wait_seconds = 120
    ready_timing_type = CalibrationTiming

    def __init__(self, case):
        self.close_calls = 0
        self.close_result = None
        super().__init__(case)

    def command(self, action, **fields):
        value = super().command(action, **fields)
        if action == "ready":
            with self.response_lock:
                self._startup_best_effort(lambda: self.ready_timing.capture(
                    bytes(self.stage_bytes), self.stage_invalid, "reply", "passed"))
        return value

    def close(self):
        self.close_calls += 1
        self.close_result = super().close()
        return self.close_result


def source_rows():
    H.loaded_sources_preserved()
    rows = []
    for name in SOURCE_FILES:
        data = H.read(ROOT / name, 512 * 1024)
        rows.append(dict(path=name, bytes=len(data), sha256=H.sha(data)))
    H.need(next(row["sha256"] for row in rows if row["path"].endswith(
        "/calibrate_helper_readiness.py")) == SELF_SHA256, "preservation_failed")
    return rows


def run():
    record = dict(schema_version=1, kind="hosted_helper_readiness_calibration_v1", result="failed",
        build_commit=None, runner_image=dict(os=None, version=None),
        ready_limit_ms=120000, later_command_limit_ms=35000,
        watchdog_lifetime_ms=165000, probe_result=None, helper_closed=False,
        sources_unchanged=False, timing=projection(None, "preflight", "rejected"), sources=[],
        application_started=False, runtime_observed=False, provider_accepted=False)
    instances = []
    def factory(case):
        bridge = CalibrationBridge(case)
        instances.append(bridge)
        return bridge
    try:
        H.hosted_guard()
        revision = os.environ.get("GITHUB_SHA", "")
        H.need(re.fullmatch(r"[0-9a-f]{40}", revision) is not None, "binding_failed")
        record["build_commit"] = revision
        for key, env, pattern in (("os", "ImageOS", r"win[0-9]{2}"),
                                  ("version", "ImageVersion", r"[0-9]{8}\.[0-9]{1,4}\.[0-9]{1,4}")):
            value = os.environ.get(env, "")
            if re.fullmatch(pattern, value):
                record["runner_image"][key] = value
        record["sources"] = source_rows()
        record["probe_result"] = H.bridge_probe(factory)
        H.need(len(instances) == 1, "session_failed")
        bridge = instances[0]
        record["timing"] = getattr(bridge.ready_timing, "record", record["timing"])
        record["helper_closed"] = (bridge.close_calls == 1 and bridge.close_result is True and
            bridge.closed_ready is True and not bridge.failed.is_set() and not bridge.forced and
            bridge.calls == bridge.responses == 2)
        record["sources_unchanged"] = source_rows() == record["sources"]
        if (record["probe_result"] == 0 and record["sources_unchanged"] and record["helper_closed"] and
                record["timing"]["status"] == "observed" and record["timing"]["outcome"] == "passed"):
            record["result"] = "passed"
    except BaseException:
        pass  # Closed failed record; never print paths, exception text or raw pipes.
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True)
    args = parser.parse_args(argv)
    descriptor = prior_signal = None
    try:
        H.hosted_guard()
        report = Path(args.report).absolute()
        H.plain(report.parent, True)
        descriptor = os.open(report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        def interrupted(_signal, _frame):
            raise KeyboardInterrupt()
        prior_signal = signal.signal(signal.SIGTERM, interrupted)
        result = run()
        data = H.E.compact(result) + b"\n"
        H.need(len(data) <= 16384, "session_failed")
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            H.need(stream.write(data) == len(data), "session_failed")
            stream.flush()
            os.fsync(stream.fileno())
        print("helper_readiness_calibration=" + H.E.compact(dict(
            result=result["result"], timing=result["timing"], helper_closed=result["helper_closed"],
            sources_unchanged=result["sources_unchanged"])).decode("ascii"), flush=True)
        return 0 if result["result"] == "passed" else 1
    except BaseException:
        print("helper_readiness_calibration_failed", file=sys.stderr)
        return 1
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if prior_signal is not None:
            signal.signal(signal.SIGTERM, prior_signal)


if __name__ == "__main__":
    raise SystemExit(main())
