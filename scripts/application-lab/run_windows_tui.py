"""Draft hosted manual-HTTP menu experiment; no local native execution.

The experiment has its own report and cannot satisfy the existing CLI ledger.
Unimplemented menu/provider capabilities remain explicitly outside its scope.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.util
import hashlib
import os
from pathlib import Path
import re
import signal
import sys
import time
import uuid

HERE = Path(__file__).resolve().parent


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses resolve postponed annotations here.
    data = (HERE / filename).read_bytes()
    exec(compile(data, str(HERE / filename), "exec"), module.__dict__)
    module.loaded_source_sha256 = hashlib.sha256(data).hexdigest()
    return module


T = _load("tui_experiment_controller", "tui_controller.py")
H = T.H
N = _load("tui_experiment_navigation", "tui_navigation.py")
O = _load("tui_experiment_oracles", "tui_oracles.py")
F = _load("tui_experiment_fixture", "fixture_tui_http.py")
CASE_ORDER = ("manual_acquisition", "escape_cancellation", "session_reset")
ALIASES = dict(zip(CASE_ORDER, ("acquisition", "cancellation", "listing")))
COMMON = frozenset({"manual_setup", "runtime_setup", "listing_artifacts", "selection_exact",
    "runtime_transfer", "manifest_and_payloads", "configuration_preserved", "fixture_valid",
    "source_preserved", "orderly_exit", "terminal_closed", "process_cleanup", "fixture_cleanup", "temp_cleanup"})
CHECKS = {name: COMMON | ({"active_partial", "cancel_requested", "cancelled_result"} if name == "escape_cancellation"
    else {"reset_source_replaced", "prior_acquisition_preserved"} if name == "session_reset" else set()) for name in CASE_ORDER}
FAILURES = H.E.FAILURE_CODES | N.ERRORS | frozenset({"tui_artifacts_invalid", "tui_screen_invalid", "tui_fixture_invalid"})
HARNESS = tuple(sorted(set(H.E.HARNESS_FILES) | {
    "scripts/tui_application_evidence.py",
    "scripts/application-lab/run_windows_tui.py", "scripts/application-lab/tui_controller.py",
    "scripts/application-lab/tui_navigation.py", "scripts/application-lab/tui_screen.py",
    "scripts/application-lab/tui_oracles.py", "scripts/application-lab/fixture_tui_http.py",
    "scripts/application-lab/hosted_tui_session.ps1"}))
SCOPE = "windows_manual_http_tui_experiment"
PHASES = frozenset({"case_setup", "fixture_start", "session_start", "main_menu", "provider_selection",
    "manual_setup", "listing_validation", "file_selection", "acquisition_start", "active_partial",
    "cancellation", "completion", "acquisition_validation", "source_reset", "orderly_exit",
    "session_cleanup", "fixture_cleanup", "artifact_validation", "case_cleanup", "final_validation"})
SELF_SHA256 = H.sha(H.read(Path(__file__), 512 * 1024))


def source_binding(application, application_sha, build_commit):
    H.loaded_sources_preserved()
    H.need(H.sha(H.read(Path(__file__), 512 * 1024)) == SELF_SHA256 and
           all(H.sha(H.read(module.__file__, 512 * 1024)) == module.loaded_source_sha256
               for module in (T, N, O, F, T.H, T.S, F.F)), "preservation_failed")
    result = H.E.compute_bindings(H.ROOT, application, build_commit, H.fixture_manifest())
    H.need(result["application_sha256"] == application_sha and os.environ.get("GITHUB_SHA") == build_commit,
           "binding_failed")
    result["tui_harness_sha256"] = H.E.tree_hash(H.ROOT, HARNESS)
    return result


def partial_active(case, lease, remote):
    H.need(remote in N.REMOTES and H.identity(case) == lease, "preservation_failed")
    root = case / "output" / H.CASE_NAME / "downloads"
    if not root.exists():
        H.need(H.identity(case) == lease, "preservation_failed")
        return False
    root_id = H.identity(root)
    entries = H.inventory(root)
    H.need(H.identity(root) == root_id and H.identity(case) == lease, "preservation_failed")
    matches = [(path, value) for path, value in entries.items() if not value[0] and re.fullmatch(
        re.escape(remote) + r"/large/\.triage-transfer-[0-9a-f]{32}/payload\.[0-9a-f]{8}\.partial", path)]
    H.need(len(matches) <= 1, "cancellation_failed")
    if not matches:
        return False
    member, info = matches[0]
    H.need(all(value[0] or path == member for path, value in entries.items()), "cancellation_failed")
    stage = member.rsplit("/", 1)[0]
    stage_id = H.identity(root / stage)
    H.need(entries[stage][0] and entries[stage][2:4] == stage_id, "preservation_failed")
    current = H.plain(root / member)
    H.need((current.st_dev, current.st_ino) == info[2:4] and H.identity(root / stage) == stage_id and
           H.identity(root) == root_id and H.identity(case) == lease, "preservation_failed")
    return 0 < info[1] < O.MEMBERS["large/cancel.bin"][0] and 0 < current.st_size < O.MEMBERS["large/cancel.bin"][0]


def observe_runtime(bridge, case, runtime):
    value = bridge.command("observe_runtime", extraction_root=str(case / "temp"), expected_sha256=runtime["sha256"])
    H.need(value["ok"] and not value["app_exited"] and value["state"] == "running" and
           value["runtime_image_observed"] and value["runtime_sha256"] == runtime["sha256"] and
           type(value["runtime_process_count"]) is int and value["runtime_process_count"] == 1, "runtime_unobserved")


def fixture_valid(snapshot, member, *, cancelled):
    H.need(not snapshot["errors"] and snapshot["source_preserved"] and snapshot["rejected"] == 0 and
           snapshot["observation_started"] and snapshot["observation_released"] and
           snapshot["download_started"] and snapshot["download_released"] and
           not snapshot["listing_started"] and not snapshot["listing_disconnected"], "tui_fixture_invalid")
    events = snapshot["events"]
    H.need(sum(kind == "observation" for kind, _ in events) == 1 and
           [path for kind, path in events if kind == "download_observation"] == [member] and
           [path for kind, path in events if kind == "content"] == [member] and
           snapshot["content_reads"] == 1 and snapshot["missing"] == snapshot["denied"] == 0,
           "tui_fixture_invalid")
    if cancelled:
        H.need(snapshot["cancel_started"] and snapshot["cancel_disconnected"] and
               [path for kind, path in events if kind == "cancel_prefix"] == [member] and
               [path for kind, path in events if kind == "cancel_disconnected"] == [member], "tui_fixture_invalid")
    else:
        H.need(not snapshot["cancel_started"] and not snapshot["cancel_disconnected"], "tui_fixture_invalid")
    transport = snapshot["transport"]
    H.need(transport["cleanup_complete"] and all(transport[key] == 0 for key in
        ("active", "workers_alive", "watchdog_alive", "acceptor_alive")), "cleanup_failed")


def run_case(name, suite, application, application_sha, runtime):
    H.need(name in CASE_ORDER, "binding_failed")
    checks = {key: False for key in sorted(CHECKS[name])}
    record = dict(status="failed", failure_code=None, failure_phase=None, exit_code=None,
                  checks=checks, listing_observations=[])
    phase = "case_setup"
    alias = ALIASES[name]
    case = suite / alias
    lease = private_leases = baseline = bridge = controller = None
    fixtures, observations, expectations = [], {}, []
    session_attempted = False
    unresolved_fixture_start = False
    cancelled = name == "escape_cancellation"
    config = None
    config_bytes = None
    before_reset = None
    request_fields = ("requests", "heads", "gets", "events", "payload_bytes")

    def fail(error):
        if record["failure_code"] is None:
            record["failure_code"] = str(error) if str(error) in FAILURES else "unexpected_failure"
            record["failure_phase"] = phase

    def observe(_phase, _session):
        H.need(H.identity(case) == lease, "preservation_failed")
        for index, (state, _, _) in enumerate(fixtures):
            if state.observation_started.is_set() and not observations.get((index, "setup")):
                observe_runtime(bridge, case, runtime)
                observations[index, "setup"] = True
                state.release_observation()
            if state.download_started.is_set() and not observations.get((index, "transfer")):
                observe_runtime(bridge, case, runtime)
                observations[index, "transfer"] = True
                state.release_download()

    def add_fixture(member, cancel=False):
        nonlocal unresolved_fixture_start
        state = F.TuiHttpState(H.payloads(), member, cancel_download=cancel)
        context = F.serve_http(state)
        unresolved_fixture_start = True
        server = context.__enter__()
        fixtures.append((state, server, context))
        unresolved_fixture_start = False
        return server.endpoint

    try:
        H.prepare(suite, alias)
        lease = H.identity(case)
        private_leases = H.create_private_roots(case)
        H.private_directory(case, "output")
        raw = H.read(application, 512 * 1024 * 1024, allow_hardlinks=True)
        H.need(H.sha(raw) == application_sha, "binding_failed")
        H.private_write(case, "application.exe", raw)
        del raw
        member = "large/cancel.bin" if cancelled else "README-synthetic.txt"
        phase = "fixture_start"
        endpoint = add_fixture(member, cancelled)
        phase = "session_start"
        session_attempted = True
        bridge = T.TuiBridge(case)
        H.validate_ready(bridge.command("ready"))
        baseline = H.prestart_baseline(alias, case, private_leases)
        controller = T.Controller(case, bridge, seconds=120)
        response = bridge.command("start", app_path=str(case / "application.exe"), app_sha256=application_sha,
            args=["--tui", "--name", H.CASE_NAME, "--output-dir", str(case / "output")], case_root=str(case),
            environment=H.environment(case), transcript_path=str(case / "transcript.private"),
            max_output_bytes=8 * 1024 * 1024, deadline_ms=150000, max_runtime_processes=1)
        H.need(response["ok"] and response["state"] == "running", "session_failed")
        nav = N.Navigator(controller, observe=observe)
        phase = "main_menu"
        nav.wait_main()
        phase = "provider_selection"
        nav.open_manual_http()
        phase = "manual_setup"
        nav.configure_http("TuiHttpA", endpoint)
        phase = "listing_validation"
        root = case / "output" / H.CASE_NAME
        config = O.validate_manual_config(root, {"TuiHttpA": endpoint})
        record["listing_observations"].append(O.validate_listing(root, config, "TuiHttpA"))
        checks["manual_setup"] = True
        phase = "file_selection"
        nav.select_one(member)
        checks["selection_exact"] = True
        phase = "acquisition_start"
        nav.begin_acquisition()
        if cancelled:
            phase = "active_partial"
            H.need(nav.state == "acquiring", "cancellation_failed")
            state = fixtures[0][0]
            controller.wait(lambda screen: state.cancel_started.is_set() and partial_active(case, lease, "TuiHttpA"),
                            seconds=30, observe=lambda value: observe("active_partial", value))
            observe_runtime(bridge, case, runtime)
            checks["active_partial"] = True
            phase = "cancellation"
            nav.cancel_acquisition()
            checks["cancel_requested"] = True
        else:
            phase = "completion"
            nav.wait_complete()
        phase = "acquisition_validation"
        first = O.validate_acquisition(root, config, "TuiHttpA", (member,), runtime["version"],
                                       outcome="cancelled" if cancelled else "success")
        expectations.append(("TuiHttpA", member, cancelled, ()))
        if cancelled:
            checks["cancelled_result"] = first.cancelled
        if name == "session_reset":
            phase = "source_reset"
            before_reset = fixtures[0][0].snapshot()
            nav.back_to_main()
            phase = "fixture_start"
            second_endpoint = add_fixture("nested/binary.bin")
            H.need(second_endpoint != endpoint, "tui_fixture_invalid")
            phase = "provider_selection"
            nav.open_manual_http()
            phase = "manual_setup"
            nav.configure_http("TuiHttpB", second_endpoint)
            phase = "listing_validation"
            config = O.validate_manual_config(root, {"TuiHttpA": endpoint, "TuiHttpB": second_endpoint}, previous=config)
            record["listing_observations"].append(O.validate_listing(root, config, "TuiHttpB"))
            phase = "file_selection"
            nav.select_one("nested/binary.bin")
            phase = "acquisition_start"
            nav.begin_acquisition()
            phase = "completion"
            nav.wait_complete()
            phase = "acquisition_validation"
            O.validate_acquisition(root, config, "TuiHttpB", ("nested/binary.bin",), runtime["version"], prior=(first,))
            expectations.append(("TuiHttpB", "nested/binary.bin", False, (first,)))
            after = fixtures[0][0].snapshot()
            H.need(all(before_reset[key] == after[key] for key in request_fields),
                   "tui_fixture_invalid")
        config_bytes = config.data
        checks["runtime_setup"] = all(observations.get((i, "setup")) is True for i in range(len(fixtures)))
        checks["runtime_transfer"] = all(observations.get((i, "transfer")) is True for i in range(len(fixtures)))
        H.need(checks["runtime_setup"] and checks["runtime_transfer"], "runtime_unobserved")
        H.need(nav.state == "complete", "tui_screen_invalid")
        phase = "orderly_exit"
        controller.text("q")
        while True:
            H.need(time.monotonic() < controller.deadline, "deadline_exceeded")
            response = bridge.command("poll")
            H.need(response["ok"], "session_failed")
            if response["app_exited"]:
                break
            time.sleep(0.05)
        response = bridge.command("finish", grace_ms=15000)
        record["exit_code"] = response["app_exit_code"]
        H.need(response["state"] == "finished" and response["ok"] and not response["forced_termination"] and
               response["app_exit_code"] == 0 and all(response[key] for key in H.SESSION_CLEANUP), "session_failed")
        checks["orderly_exit"] = True
    except (O.OracleError,):
        fail("tui_artifacts_invalid")
    except T.S.ScreenError:
        fail("tui_screen_invalid")
    except BaseException as error:
        fail(error)
    finally:
        phase = "session_cleanup"
        if bridge is not None:
            try:
                closed = bridge.close()
                final = bridge.last
                checks["process_cleanup"] = bool(closed and final and final["state"] == "finished" and
                                                  final["ok"] and all(final[key] for key in H.SESSION_CLEANUP))
                if controller is not None and checks["process_cleanup"]:
                    controller.drain()
                    controller.screen.finish()
                    H.need(time.monotonic() < controller.deadline, "deadline_exceeded")
                    checks["terminal_closed"] = not controller.screen.alternate and controller.screen.cursor_visible
            except BaseException:
                fail("cleanup_failed")
        else:
            checks["process_cleanup"] = not session_attempted
        if controller is not None:
            try:
                controller.close()
            except BaseException:
                checks["process_cleanup"] = False
                fail("cleanup_failed")
        fixture_snapshots = []
        phase = "fixture_cleanup"
        checks["fixture_cleanup"] = not unresolved_fixture_start
        for state, server, context in reversed(fixtures):
            try:
                context.__exit__(None, None, None)
                checks["fixture_cleanup"] &= server.cleanup_complete
            except BaseException:
                checks["fixture_cleanup"] = False
                fail("cleanup_failed")
        try:
            phase = "artifact_validation"
            H.need(bool(fixtures) and len(expectations) == len(fixtures), "tui_fixture_invalid")
            for (_, server, _), (_, expected, was_cancelled, _) in zip(fixtures, expectations):
                snapshot = server.snapshot()
                fixture_valid(snapshot, expected, cancelled=was_cancelled)
                fixture_snapshots.append(snapshot)
            checks["fixture_valid"] = True
            checks["source_preserved"] = all(s["source_preserved"] for s in fixture_snapshots)
            if before_reset is not None:
                H.need(all(before_reset[key] == fixture_snapshots[0][key] for key in request_fields), "tui_fixture_invalid")
            H.need(checks["process_cleanup"] and config is not None, "cleanup_failed")
            final_remote, final_member, final_cancelled, history = expectations[-1]
            H.need(O.validate_listing(case / "output" / H.CASE_NAME, config, final_remote) ==
                   record["listing_observations"][-1], "tui_artifacts_invalid")
            checks["listing_artifacts"] = True
            O.validate_acquisition(case / "output" / H.CASE_NAME, config, final_remote, (final_member,),
                                   runtime["version"], outcome="cancelled" if final_cancelled else "success", prior=history)
            checks["manifest_and_payloads"] = True
            H.need(H.read(case / "output" / H.CASE_NAME / "config/rclone.conf", 65536) == config_bytes,
                   "preservation_failed")
            checks["configuration_preserved"] = True
            if before_reset is not None:
                H.need(len(expectations) == 2 and len(record["listing_observations"]) == 2 and
                       final_remote == "TuiHttpB" and len(history) == 1, "tui_artifacts_invalid")
                checks["reset_source_replaced"] = checks["prior_acquisition_preserved"] = True
        except (O.OracleError,):
            fail("tui_artifacts_invalid")
        except BaseException as error:
            fail(error)
        if lease is not None and checks["process_cleanup"] and checks["fixture_cleanup"]:
            try:
                phase = "case_cleanup"
                H.need(H.identity(case) == lease and H.sha(H.read(case / "application.exe", 512 * 1024 * 1024)) == application_sha,
                       "preservation_failed")
                H.post_helper_preserved(alias, case, private_leases, baseline)
                H.prepare(suite, alias, "Verify")
                H.remove_owned(case, lease)
                checks["temp_cleanup"] = True
            except BaseException:
                fail("cleanup_failed")
    phase = "final_validation"
    if record["failure_code"] is None and all(checks.values()):
        record["status"] = "passed"
    elif record["failure_code"] is None:
        fail("session_failed")
    return record


def run(application, application_sha, build_commit):
    H.hosted_guard()
    application = Path(application).absolute()
    H.need(H.E.valid_hash(application_sha) and
           H.plain(application, allow_hardlinks=True).st_size <= 512 * 1024 * 1024, "binding_failed")
    bindings = source_binding(application, application_sha, build_commit)
    runtime = H.runtime_pins(H.ROOT / "rclone-version.env")
    cases = {name: dict(status="not_run", failure_code=None, failure_phase=None, exit_code=None,
                       checks={key: False for key in sorted(CHECKS[name])}, listing_observations=[]) for name in CASE_ORDER}
    suite = lease = None
    errors = []
    cleanup = False
    try:
        parent = Path(os.environ["RUNNER_TEMP"]).absolute()
        suite = parent / ("app-http-" + uuid.uuid4().hex)
        H.need(not suite.exists(), "case_setup_failed")
        H.prepare(parent, suite.name)
        lease = H.identity(suite)
        for name in CASE_ORDER:
            H.need(H.identity(suite) == lease, "preservation_failed")
            cases[name] = run_case(name, suite, application, application_sha, runtime)
            if cases[name]["status"] != "passed":
                errors.append(cases[name]["failure_code"])
                break
    except BaseException as error:
        errors.append(str(error) if str(error) in FAILURES else "unexpected_failure")
    finally:
        try:
            H.need(source_binding(application, application_sha, build_commit) == bindings and
                   H.runtime_pins(H.ROOT / "rclone-version.env") == runtime, "preservation_failed")
            if lease is not None:
                H.need(H.identity(suite) == lease and not H.inventory(suite) and
                       all(c["status"] == "not_run" or all(c["checks"][key] for key in
                           ("process_cleanup", "fixture_cleanup", "temp_cleanup")) for c in cases.values()), "cleanup_failed")
                H.prepare(suite.parent, suite.name, "Verify")
                H.remove_owned(suite, lease)
                cleanup = True
        except BaseException:
            errors.append("cleanup_failed")
    return dict(schema_version=1, scope=SCOPE, platform="windows", backend="http",
        created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), runtime=runtime, bindings=bindings,
        cases=cases, errors=list(dict.fromkeys(errors)), cleanup_complete=cleanup,
        result="passed" if cleanup and not errors and all(c["status"] == "passed" for c in cases.values()) else "failed",
        limitations=["no_vendor_acceptance", "no_oauth_or_refresh", "no_listing_cancel_recovery", "no_resize_acceptance",
                     "no_mount_or_webgui", "no_all_provider_qualification"])


def main(argv=None):
    parser = argparse.ArgumentParser()
    for name in ("application", "application-sha256", "build-commit", "report"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    descriptor = None
    prior_signal = None
    try:
        H.hosted_guard()
        def interrupted(_signal, _frame):
            raise KeyboardInterrupt()
        prior_signal = signal.signal(signal.SIGTERM, interrupted)
        report = Path(args.report).absolute()
        H.plain(report.parent, True)
        descriptor = os.open(report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        result = run(args.application, args.application_sha256, args.build_commit)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(H.E.compact(result) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        return 0 if result["result"] == "passed" else 1
    except BaseException:
        print("tui_experiment_failed", file=sys.stderr)
        return 1
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if prior_signal is not None:
            signal.signal(signal.SIGTERM, prior_signal)


if __name__ == "__main__":
    raise SystemExit(main())
