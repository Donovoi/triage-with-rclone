#!/usr/bin/env python3
"""Hosted x64 inert three-pipe close controls. No app, provider, or credentials."""
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import queue
import sys
import threading
import time
import types
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
QUALIFIER_SHA256 = "bc400833538c990b0f251bbb7532f61f0e466f490b91573ba2e9886b1f418c50"
SELF_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
MODES = {"delayed_release", "persistent_child"}


def need(value):
    if not value:
        raise ValueError("session_owner_calibration_failed")


def load_qualifier():
    path = HERE / "qualify_helper_owner.py"
    raw = path.read_bytes()
    need(len(raw) <= 512 * 1024 and hashlib.sha256(raw).hexdigest() == QUALIFIER_SHA256)
    module = types.ModuleType("session_owner_prerequisites")
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def drain(pipe, failed, counts, index):
    try:
        count = 0
        while True:
            raw = pipe.read1(4096)
            need(type(raw) is bytes)
            if not raw:
                break
            count += len(raw)
            need(count <= 4096)
        counts[index] = count
    except BaseException:
        failed.set()


class _ControlWorker:
    """Preregister a target before start; late unclaimed targets can be revoked."""
    def __init__(self, bridge, pipe=None, counts=None, index=None):
        self.bridge, self.pipe, self.counts, self.index = bridge, pipe, counts, index
        self.lock, self.thread = threading.Lock(), None
        self.attempted = self.returned = self.claimed = self.revoked = self.completed = False

    def run(self):
        with self.lock:
            if self.revoked:
                self.completed = True
                return
            self.claimed = True
        try:
            if self.pipe is None:
                self.bridge.done.wait()
            else:
                drain(self.pipe, self.bridge.failed, self.counts, self.index)
        except BaseException:
            self.bridge.failed.set()
        finally:
            with self.lock:
                self.completed = True

    def start(self):
        need(self.thread is not None and not self.attempted)
        self.attempted = True
        self.thread.start()
        self.returned = True

    def restore(self, deadline):
        with self.lock:
            if not self.returned and not self.claimed:
                self.revoked = True
            revoked = self.revoked
        joined = not self.attempted
        if self.attempted:
            try:
                self.thread.join(remaining(deadline))
                with self.lock:
                    joined = not self.thread.is_alive() and self.completed
            except BaseException:
                joined = False
        # An unclaimed target cannot touch its pipe after revocation. A claimed
        # target keeps that pipe until both completion and thread exit are proved.
        if self.pipe is not None and (revoked or joined):
            try:
                self.pipe.close()
            except BaseException:
                return False
        return joined


def remaining(deadline):
    now = time.monotonic()
    need(type(deadline) in (int, float) and math.isfinite(deadline) and
         type(now) in (int, float) and math.isfinite(now) and now >= 0)
    return max(0, deadline - now)


def start_bridge(bridge, counts):
    # main already retains bridge. Every worker record exists before allocation
    # or start can fail; no interrupted Thread.start is ever retried.
    try:
        bridge.workers = [_ControlWorker(bridge, pipe, counts, index)
                          for index, pipe in enumerate((bridge.process.stdout, bridge.process.stderr))]
        bridge.workers.append(_ControlWorker(bridge))
        for worker in bridge.workers:
            worker.thread = threading.Thread(target=worker.run, daemon=True)
        bridge.threads = [worker.thread for worker in bridge.workers[:2]]
        bridge.watchdog = bridge.workers[2].thread
        for worker in bridge.workers:
            worker.start()
        bridge.control_started = True
    except BaseException:
        bridge.failed.set()
        bridge.done.set()
        try:
            bridge.process.mark_uncertain()
        except BaseException:
            pass
        raise


def restore_partial_bridge(bridge, deadline):
    """Best effort over independent known resources; never grants clean-close credit."""
    restored = True
    bridge.done.set()
    try:
        bridge.process.mark_uncertain()
    except BaseException:
        restored = False
    try:
        bridge.process.stdin.close()
    except BaseException:
        restored = False
    try:
        bridge.process.wait(timeout=remaining(deadline))
    except BaseException:
        restored = False
    for worker in bridge.workers:
        try:
            if not worker.restore(deadline):
                restored = False
        except BaseException:
            restored = False
    for pipe in (bridge.process.stdout, bridge.process.stderr):
        if all(worker.pipe is not pipe for worker in bridge.workers):
            try:
                pipe.close()
            except BaseException:
                restored = False
    try:
        # A failed start stays uncertain even if all known resources are closed.
        bridge.process.finalize()
    except BaseException:
        restored = False
    return restored


def prepare_bridge(H, process, deadline):
    # Only the public Bridge close path is under test. No request protocol or app
    # session is synthesized or credited by these two inert ownership controls.
    bridge = object.__new__(H.Bridge)
    bridge.process, bridge.deadline = process, deadline
    bridge.last = {"state": "finished"}
    bridge.failed, bridge.done = threading.Event(), threading.Event()
    bridge.response_lock, bridge.messages = threading.Lock(), queue.Queue()
    bridge.transport, bridge.stage_bytes = {}, bytearray()
    bridge.calls = bridge.responses = 0
    bridge.ready = bridge.forced = bridge.stage_invalid = False
    bridge.workers, bridge.threads, bridge.watchdog = [], [], None
    bridge.control_started = False
    return bridge, [None, None]


def main():
    report = dict(schema_version=1, scope="hosted_x64_inert_session_close", mode=None,
                  result="failed", reason="host", sources_sha256=None, controller_sha256=SELF_SHA256,
                  python_sha256=None, app_executed=False, provider_acceptance=False,
                  parent_exit=None, child_exit=None, child_in_job=False, clean_transport=False,
                  close_result=None, owner_sticky_failed=False, parent_handle_closed_before_query=False,
                  first_active=None, first_total=None, final_active=None, final_total=None,
                  queries=0, observation_queries=0, observation_status=None, deadline_expired=None,
                  deadline_preserved=False, observation_budget_seconds=20,
                  release_after_first_query=False, cleanup_complete=False)
    Q = F = H = api = process = bridge = directory = directory_identity = None
    release = ready = child = query_job = None
    handles, hashes, samples = [], {}, []
    closed_handles, child_closed = set(), False
    original_accounting = wrapped_accounting = original_observer = observer_factory = None
    observations = []
    phase, checks_passed, cleanup_passed = "host", False, False
    try:
        need(len(sys.argv) == 2 and sys.argv[1] in MODES)
        mode = sys.argv[1]; report["mode"] = mode
        need(os.name == "nt" and ctypes.sizeof(ctypes.c_void_p) == 8)
        need(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_OS") == "Windows" and
             os.environ.get("RUNNER_ARCH") == "X64" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted")
        phase = "sources"
        Q = load_qualifier()
        name = "scripts/application-lab/helper_owner_fixture.py"
        F = Q.load("session_owner_fixture", ROOT / name, Q.SOURCE_PINS[name]["sha256"])
        report["sources_sha256"] = Q.verify_sources(F)
        need(F.digest(Path(__file__), 512 * 1024) == SELF_SHA256)
        H = Q.load("session_owner_http", HERE / "run_windows_http.py",
                   Q.SOURCE_PINS["scripts/application-lab/run_windows_http.py"]["sha256"])
        H.loaded_sources_preserved()
        phase = "identity"
        api = F.Native()
        current = api.identify(api.current())
        api.x64(api.current())
        image = F.read(current["image"], 32 * 1024 * 1024)
        Q.pe_x64(image)
        report["python_sha256"] = hashlib.sha256(image).hexdigest()
        parent = Path(os.environ["RUNNER_TEMP"]).absolute()
        F.plain(parent, True)
        directory = parent / ("session-owner-" + uuid.uuid4().hex)
        directory.mkdir()
        info = F.plain(directory, True); directory_identity = (info.st_dev, info.st_ino)
        release = api.event(); handles.append(release)
        ready = api.event(); handles.append(ready)
        need(release != ready and not api.wait(release, 0) and not api.wait(ready, 0))
        expected = dict(schema_version=1, nonce=uuid.uuid4().hex, controller=current,
                        python_sha256=report["python_sha256"], fixture_sha256=Q.SOURCE_PINS[name]["sha256"],
                        release=release, ready=ready)
        F.request(expected)
        request_path = directory / "request.json"
        F.publish(request_path, expected); hashes["request.json"] = F.digest(request_path, 4096)
        args = [current["image"], "-B", "-I", "-S", str(ROOT / name), "session_parent", str(request_path)]
        environment = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP") if key in os.environ}
        need(environment.get("SYSTEMROOT"))
        phase = "create"
        origin = time.monotonic(); need(type(origin) in (int, float) and math.isfinite(origin) and origin >= 0)
        deadline = origin + 20
        process = H.O.spawn(args, env=environment)
        bridge, counts = prepare_bridge(H, process, deadline)
        start_bridge(bridge, counts)
        process.stdin.close()
        process.wait(timeout=max(0, deadline - time.monotonic()))
        need(type(process.returncode) is int and process.returncode == 0 and not process.forced and not process.uncertain)
        phase = "transfer"
        transfer_path = directory / "transfer.json"
        child = Q.accept_transfer(F, api, F.record(transfer_path), expected); handles.append(child)
        hashes["transfer.json"] = F.digest(transfer_path, 4096)
        need(api.wait(ready, max(0, min(5000, int((deadline - time.monotonic()) * 1000)))))
        need(not api.wait(child, 0))
        with process.job.borrow() as job:
            query_job = api.duplicate(api.current(), job, api.current(), 0x0004)
            handles.append(query_job)
            member = ctypes.c_int32()
            need(process.api.k.IsProcessInJob(child, query_job, ctypes.byref(member)) != 0 and member.value == 1)
        report["child_in_job"] = True
        phase = "close"
        original_accounting = process.api.accounting
        def accounting(handle):
            nonlocal child_closed
            if mode == "delayed_release" and report["release_after_first_query"] and not child_closed and api.wait(child, 0):
                report["child_exit"] = api.exit_code(child)
                need(type(report["child_exit"]) is int and report["child_exit"] == 0 and child not in closed_handles)
                closed_handles.add(child)
                api.close(child)
                child_closed = True
            value = original_accounting(handle)
            # Retain the real native result unchanged. Release only the inspected
            # synthetic child after the first positive sample, never a guessed PID.
            Q.counts(value)
            need(len(samples) < 402 and handle == process.job.value and process.process.closed is True)
            samples.append(value)
            if len(samples) == 1:
                need(0 < value[0] <= value[1] == 2 and not api.wait(child, 0))
                report["parent_handle_closed_before_query"] = True
                if mode == "delayed_release":
                    api.signal(release)
                    report["release_after_first_query"] = True
            return value
        wrapped_accounting = accounting
        process.api.accounting = accounting
        original_observer = H.O._SessionQuiescence
        def make_observer():
            need(not observations)
            item = original_observer()
            observations.append(item)
            return item
        observer_factory = make_observer
        H.O._SessionQuiescence = observer_factory
        closed = bridge.close()
        need(H.O._SessionQuiescence is observer_factory and len(observations) == 1)
        H.O._SessionQuiescence = original_observer
        observer_factory = None
        observed = observations[0]
        report["observation_status"] = observed.status
        report["observation_queries"] = observed.queries
        report["deadline_expired"] = observed.deadline_expired
        need(len(samples) == observed.queries + 1)
        need(process.api.accounting is wrapped_accounting)
        del process.api.accounting
        wrapped_accounting = None
        report["close_result"] = closed
        report["deadline_preserved"] = bridge.deadline == deadline
        report["parent_exit"] = process.returncode
        report["clean_transport"] = (counts == [0, 0] and not bridge.failed.is_set() and not bridge.forced and
                                     not bridge.watchdog.is_alive() and all(not t.is_alive() for t in bridge.threads) and
                                     process.stdin.closed and process.stdout.closed and process.stderr.closed)
        need(report["clean_transport"] and report["deadline_preserved"] and 0 < samples[0][0] <= samples[0][1] == 2)
        need(not process.forced and process.finalized and process.process.closed is True and process.job.closed is True)
        Q.owner_handles_closed(process)
        if mode == "delayed_release":
            need(closed is True and process.final_result is True and not process.uncertain and H.O._active is None)
            need(len(samples) >= 3 and samples[-2:] == [(0, 2), (0, 2)])
            need(observed.status == "zero_observed" and observed.deadline_expired is False)
        else:
            need(closed is False and process.final_result is False and process.uncertain and H.O._active is process)
            need(H.O._poisoned and not api.wait(child, 0) and all(0 < row[0] <= row[1] == 2 for row in samples))
            need(not report["release_after_first_query"])
            need((observed.status == "deadline_exhausted" and observed.deadline_expired is True) or
                 (observed.status == "observation_cap" and observed.queries == 401 and observed.deadline_expired is False))
            # No native creation should be reached once this failed owner is retained.
            Q.admission(H.O, process, args, environment)
            need(process.finalize() is False)
            report["owner_sticky_failed"] = True
        checks_passed = True
        report["reason"] = None
    except BaseException:
        report["reason"] = phase
    finally:
        restoration_ok = True
        def close_once(handle):
            nonlocal restoration_ok
            need(handle not in closed_handles)
            closed_handles.add(handle)
            try:
                api.close(handle)
                return True
            except BaseException:
                restoration_ok = False
                return False
        try:
            if process is not None and wrapped_accounting is not None:
                need(process.api.accounting is wrapped_accounting)
                del process.api.accounting
                wrapped_accounting = None
        except BaseException:
            restoration_ok = False
        try:
            if H is not None and observer_factory is not None:
                need(H.O._SessionQuiescence is observer_factory)
                H.O._SessionQuiescence = original_observer
                observer_factory = None
        except BaseException:
            restoration_ok = False
        # Always release the exact owned event, even after an earlier check fails.
        try:
            need(api is not None and release is not None)
            api.signal(release)
        except BaseException:
            restoration_ok = False
        # Failure-path closure remains the existing bounded Bridge close. It never
        # upgrades this control's failed checks or resets a retained owner verdict.
        try:
            if bridge is not None and process is not None and not process.finalized and bridge.control_started:
                bridge.close()
        except BaseException:
            restoration_ok = False
        # The separate five-second restoration bound cannot extend observation
        # admission or convert a failed Bridge close into success.
        cleanup_deadline = time.monotonic() + 5
        if bridge is not None and not bridge.control_started:
            try:
                if not restore_partial_bridge(bridge, cleanup_deadline):
                    restoration_ok = False
            except BaseException:
                restoration_ok = False
        try:
            need(child is not None)
            if not child_closed:
                need(child not in closed_handles)
                need(api.wait(child, max(0, int((cleanup_deadline - time.monotonic()) * 1000))))
                report["child_exit"] = api.exit_code(child)
            need(type(report["child_exit"]) is int and report["child_exit"] == 0)
            if not child_closed:
                child_closed = close_once(child)
        except BaseException:
            # Retain the exact child capability when exit could not be proved.
            restoration_ok = False
        try:
            need(bridge is not None and process is not None)
            bridge.done.set()
            if bridge.control_started:
                for thread in (*bridge.threads, bridge.watchdog):
                    thread.join(max(0, cleanup_deadline - time.monotonic()))
                    need(not thread.is_alive())
            else:
                need(all(not worker.attempted or
                         (worker.completed and not worker.thread.is_alive()) for worker in bridge.workers))
            need(process.finalized)
            Q.owner_handles_closed(process)
        except BaseException:
            restoration_ok = False
        try:
            need(child_closed and query_job is not None and original_accounting is not None)
            quiet = False
            for _ in range(101):
                need(time.monotonic() < cleanup_deadline)
                current_counts = Q.counts(original_accounting(query_job))
                if current_counts == (0, 2):
                    quiet = True
                    break
                need(0 < current_counts[0] <= current_counts[1] == 2)
                time.sleep(min(0.05, max(0, cleanup_deadline - time.monotonic())))
            need(quiet)
        except BaseException:
            restoration_ok = False
        for handle in reversed(handles):
            if handle != child and handle not in closed_handles:
                close_once(handle)
        try:
            need(restoration_ok and time.monotonic() <= cleanup_deadline)
            need(Q.verify_sources(F) == report["sources_sha256"])
            need(F.digest(Path(__file__), 512 * 1024) == SELF_SHA256 and
                 F.digest(HERE / "qualify_helper_owner.py", 512 * 1024) == QUALIFIER_SHA256)
            H.loaded_sources_preserved()
            Q.remove_owned(F, directory, directory_identity, hashes)
            cleanup_passed = True
        except BaseException:
            report["reason"] = report["reason"] or "restoration"
        report["cleanup_complete"] = cleanup_passed
        report["queries"] = len(samples)
        if samples:
            report["first_active"], report["first_total"] = samples[0]
            report["final_active"], report["final_total"] = samples[-1]
    report["result"] = "passed" if checks_passed and cleanup_passed and report["reason"] is None else "failed"
    raw = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    need(len(raw.encode("ascii")) <= 2048)
    print("session_owner_calibration=" + raw, flush=True)
    return 0 if report["result"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
