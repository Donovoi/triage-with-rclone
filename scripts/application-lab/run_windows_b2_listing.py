#!/usr/bin/env python3
"""Hosted-only metadata B2 listing experiment; no work on import."""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import io
import os
from pathlib import Path
import re
import secrets
import signal
import time
import types
import uuid

HERE = Path(__file__).absolute().parent
ROOT = HERE.parent.parent


def load(name, path):
    data = path.read_bytes()
    if not 0 < len(data) <= 512 * 1024:
        raise ValueError("binding_failed")
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(data, str(path), "exec"), module.__dict__)
    module.loaded_source_sha256 = hashlib.sha256(data).hexdigest()
    return module


H = load("b2_listing_http_support", HERE / "run_windows_http.py")
W = load("b2_listing_preservation_support", HERE / "run_windows_webdav.py")
C = load("b2_listing_observer_transport", HERE / "filesystem_controller.py")
F = load("b2_listing_fixture", HERE / "fixture_b2_listing.py")
E = load("b2_listing_contract", HERE.parent / "b2_listing_application_evidence.py")
SELF_HASH = H.sha(H.read(Path(__file__), 512 * 1024))
need, ProducerError = H.need, H.ProducerError
CLEANUP_UNCERTAIN = frozenset({"termination_failed", "process_cleanup_failed", "input_cleanup_failed",
    "reader_cleanup_failed", "console_cleanup_failed", "console_cleanup_timeout", "source_directory_cleanup_failed",
    "debug_cleanup_failed", "source_directory_invalid"})
# Existing generic HTTP private-directory names; no shared allowlist changes.
CASE_DIRECTORIES = {"account_listing": "listing", "alias_nested_listing": "acquisition"}

def bindings(application, commit, mode=E.MODE):
    H.loaded_sources_preserved()
    W.bindings(application, commit)  # Includes W's loaded transitive dependencies.
    C.H.loaded_sources_preserved()
    for module in (H, W, C, C.H, F, E):
        need(H.sha(H.read(module.__file__, 512 * 1024)) == module.loaded_source_sha256, "preservation_failed")
    need(H.sha(H.read(Path(__file__), 512 * 1024)) == SELF_HASH, "preservation_failed")
    need(H.sha(H.read(F._PATH, 512 * 1024)) == F.loaded_http_source_sha256, "preservation_failed")
    return E.compute_bindings(ROOT, application, commit, mode)

def failure(error):
    return str(error) if isinstance(error, (ProducerError, W.ProducerError, C.H.ProducerError)) and str(error) in E.FAILURE_CODES else "unexpected_failure"

def mark(record, code, errors):
    record["status"] = "failed"
    record["failure_code"] = record["failure_code"] or code
    if code not in errors:
        errors.append(code)

def config_bytes(endpoint, user, key, name):
    need(type(endpoint) is str and re.fullmatch(r"http://127\.0\.0\.1:[1-9][0-9]{0,4}/", endpoint) and
         1 <= int(endpoint.split(":")[-1][:-1]) <= 65535 and type(name) is str and name in E.CASES and
         all(type(v) is str and re.fullmatch(r"[a-f0-9]{64}", v) for v in (user, key)), "binding_failed")
    direct = name == "account_listing"
    section = "Synthetic" if direct else "B2Source"
    config = f"[{section}]\ntype = b2\naccount = {user}\nkey = {key}\nendpoint = {endpoint[:-1]}\n"
    if not direct:
        config += "\n[Synthetic]\ntype = alias\nremote = B2Source:synthetic-bucket/nested\n"
    return config.encode("ascii")


def create_source(case):
    H.hosted_guard()
    identity = H.identity(case)
    need(H._native_private_create(case, case / "source", True) is None and H.identity(case) == identity, "case_setup_failed")
    H.plain(case / "source", True)
    need(not H.inventory(case / "source"), "case_setup_failed")
    return H.identity(case / "source")

def observed_final(value, name, runtime):
    C.validate_observed_snapshot(value, value.get("action"), runtime["sha256"], 1, E.EXPECTED_LAUNCHES[name])
    need(value["state"] == "finished" and value["ok"] is True and value["runtime_launch_count"] == E.EXPECTED_LAUNCHES[name], "runtime_unobserved")
    normalized = {key: value[key] for key in E.OBSERVATION_KEYS}
    E.observation(normalized, name)
    return normalized

def cleanup_proved(bridge, closed, name, runtime):
    if closed is not True or type(bridge.last) is not dict:
        return False
    final = bridge.last
    C.validate_observed_snapshot(final, final.get("action"), runtime["sha256"], 1, E.EXPECTED_LAUNCHES[name])
    return (final["state"] == "finished" and not set(final["errors"]) & CLEANUP_UNCERTAIN and
            all(final[k] is True for k in (*H.SESSION_CLEANUP, *C.OBSERVED_CLEANUP)))

def close_session(bridge, ready, start_attempted, name, runtime):
    """Close the exact phase; ready-only proof cannot stand in for app cleanup."""
    ready_closed = False
    try:
        if ready and not start_attempted:
            need(bridge.observer_started is False, "cleanup_failed")
            H.validate_close_ready(bridge.command("close_ready"))
            ready_closed = True
    finally:
        # Retain the existing owned process/pipe/thread teardown even on an
        # invalid reply. Its normal-exit result alone is not a ready proof.
        closed = bridge.close()
    if not start_attempted:
        return ready_closed and closed is True and H.validate_close_ready(bridge.last)["ok"] is True
    return cleanup_proved(bridge, closed, name, runtime)

def preserved(item, app_sha, *, before_start=False):
    case = item["case"]
    need(H.identity(case) == item["lease"] and H.identity(case / "source") == item["source"] and not H.inventory(case / "source") and
         H.sha(H.read(case / "application.exe", 512 * 1024 * 1024)) == app_sha, "preservation_failed")
    need("queue.csv" not in H.inventory(case), "preservation_failed")
    if before_start and not item["config_written"]:
        need("source.conf" not in H.inventory(case), "preservation_failed")
    else:
        need(H.read(case / "source.conf", 8192) == item["config"], "preservation_failed")
    if before_start:
        need(not H.inventory(case / "output"), "preservation_failed")
    if item["record"]["checks"]["configuration_preserved"]:
        H.configuration_preserved(case, item["config"])
    if item["artifact"] is not None:
        need(W.fingerprint(case) == item["artifact"], "preservation_failed")

def fixture_closed(server):
    if server is None:
        return False
    value = server.transport_snapshot()
    return value["cleanup_complete"] is True and value["active"] == value["workers_alive"] == 0 and value["watchdog_alive"] is False and value["acceptor_alive"] is False

def listing_csv(data, name, invocation):
    need(type(data) is bytes and 0 < len(data) <= 16384 and data.startswith(b"\xef\xbb\xbf"), "listing_invalid")
    try:
        rows = list(csv.reader(io.StringIO(data.decode("utf-8-sig"), newline=""), strict=True))
    except (UnicodeError, csv.Error):
        raise ProducerError("listing_invalid") from None
    # Literal schema/oracle belongs to the independent evidence module. No
    # apostrophe stripping, case folding, path normalization or hash borrowing.
    need(rows and rows[0] == H.HEADERS and all(len(row) == 8 for row in rows[1:]), "listing_invalid")
    implicit = [dict(path=row[2], modified=row[4]) for row in rows[1:] if row[2] in E.implicit_paths(name)]
    observation = dict(invocation=invocation, implicit_directories=implicit, rows=rows[1:])
    try:
        E.inventory_observation(observation, name)
    except E.A.ApplicationEvidenceError:
        raise ProducerError("listing_invalid") from None
    expected = E.listing_rows(name) + [["excel-safe-v1", "Synthetic", row["path"], "", row["modified"], "true", "", ""] for row in implicit]
    need(sorted(rows[1:]) == sorted(expected), "listing_invalid")
    return observation

def listing_output(case, name, invocation):
    base = case / "output" / H.CASE_NAME
    observation = listing_csv(H.read(base / "listings/inventory.csv", 16384), name, invocation)
    W.output_inventory("listing", case)
    need(not H.inventory(base / "downloads"), "outputs_invalid")
    return dict.fromkeys(("inventory_exact", "listing_complete", "outputs_exact", "no_download_outputs",
                          "implicit_directories_exact", "invocation_time_bounded"), True), observation

def listing_committed(state, deadline):
    # Bytes received by the client may precede the worker's sendall/commit return.
    # Teardown must not turn that scheduling window into a fabricated failure.
    while True:
        need(time.monotonic() < deadline, "deadline_exceeded")
        value = E.fixture_observation(state.snapshot(), state.case)
        need(not value["errors"] and value["source_preserved"] and len(value["events"]) <= 4, "fixture_failed")
        if len(value["events"]) == 4:
            E.fixture_observation(value, state.case, successful=True)
            need(time.monotonic() < deadline, "deadline_exceeded")
            return
        time.sleep(min(0.02, max(0, deadline - time.monotonic())))

def execute(name, suite, application, app_sha, runtime, errors):
    record = dict(status="failed", exit_code=None, runtime_sha256=None, observation=None, continuity=None, fixture=None, inventory_observation=None,
        failure_code=None, checks=dict.fromkeys(E.CHECKS[name], False))
    item = dict(name=name, record=record, case=suite / CASE_DIRECTORIES[name], lease=None,
        source=None, roots=None, baseline=None, artifact=None, config=None, config_written=False)
    case, checks = item["case"], record["checks"]
    bridge = server = state = context = None
    entered = ready = start_attempted = fixture_attempted = False
    deadline = time.monotonic() + 120
    try:
        H.prepare(suite, case.name)
        item["lease"] = H.identity(case)
        item["roots"] = H.create_private_roots(case)
        H.private_directory(case, "output")
        item["source"] = create_source(case)
        body = H.read(application, 512 * 1024 * 1024, allow_hardlinks=True)
        need(H.sha(body) == app_sha, "binding_failed")
        H.private_write(case, "application.exe", body)
        bridge = C.ObservedSourceBridge(case)
        H.validate_ready(bridge.command("ready"))
        ready = True
        # Capture helper-only identity/layout before later fixture/config setup
        # can fail. An unavailable baseline remains a cleanup failure.
        H.application_roots_empty(case, item["roots"])
        item["baseline"] = H.helper_baseline(case, item["roots"])
        # Fresh fixture starts after readiness, inside the original case deadline.
        user, key = secrets.token_hex(32), secrets.token_hex(32)
        state = F.AppB2ListingState(name, user, key)
        context = F.serve_b2_listing(state)
        fixture_attempted = True
        server = context.__enter__()
        entered = True
        deadline = min(deadline, server.deadline)
        config = item["config"] = config_bytes(server.endpoint, user, key, name)
        H.private_write(case, "source.conf", config)
        item["config_written"] = True
        H.application_roots_empty(case, item["roots"])
        # Normal launch keeps the original latest pre-start baseline. The earlier
        # ready-only snapshot is only needed when setup never reaches this point.
        item["baseline"] = H.helper_baseline(case, item["roots"])
        remaining = int((deadline - time.monotonic()) * 1000)
        need(1000 <= remaining <= 120000, "deadline_exceeded")
        start_fields = dict(app_path=str(case / "application.exe"), app_sha256=app_sha,
            args=H.app_args("listing", case), case_root=str(case), environment=H.environment(case),
            transcript_path=str(case / "transcript.private"), max_output_bytes=8 * 1024 * 1024,
            deadline_ms=remaining, max_runtime_processes=1, expected_runtime_sha256=runtime["sha256"], max_runtime_launches=E.EXPECTED_LAUNCHES[name])
        invocation_start_ns = time.monotonic_ns()
        invocation_start_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        start_attempted = True  # A possibly issued start never uses ready-only cleanup.
        response = bridge.command("start_source_observed", **start_fields)
        need(response["ok"], "session_failed")
        while not response["app_exited"]:
            need(time.monotonic() < deadline, "deadline_exceeded")
            response = bridge.command("poll")
            need(response["ok"], "session_failed")
            if not response["app_exited"]:
                time.sleep(0.02)
        if response["state"] != "finished":
            response = bridge.command("finish", grace_ms=5000)
        need(time.monotonic() < deadline, "deadline_exceeded")
        invocation_end_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        invocation_elapsed_ns = time.monotonic_ns() - invocation_start_ns
        invocation = dict(started_at=invocation_start_utc, finished_at=invocation_end_utc, elapsed_ns=invocation_elapsed_ns)
        E.invocation_interval(invocation)
        record["observation"] = observed_final(response, name, runtime)
        record["exit_code"] = response["app_exit_code"]
        record["runtime_sha256"] = runtime["sha256"]
        checks.update(runtime_observed=True, orderly_exit=True)
        need(type(record["exit_code"]) is int and record["exit_code"] == 0, "session_failed")
        checks["exit_success"] = True
        working = H.configuration_preserved(case, config)
        checks["configuration_preserved"] = True
        listing_committed(state, deadline)
        output_checks, output_observation = listing_output(case, name, invocation)
        record["inventory_observation"] = output_observation
        checks.update(output_checks)
        item["artifact"] = W.fingerprint(case)
    except BaseException as error:
        mark(record, failure(error), errors)
    finally:
        if bridge is not None:
            try:
                checks["process_cleanup"] = close_session(bridge, ready, start_attempted, name, runtime)
                if start_attempted and checks["process_cleanup"] and record["exit_code"] is None:
                    record["exit_code"] = bridge.last.get("app_exit_code")
            except BaseException:
                checks["process_cleanup"] = False
        if entered:
            try:
                context.__exit__(None, None, None)
            except BaseException:
                mark(record, "cleanup_failed", errors)
        elif state is not None:
            server = state._transport
        checks["fixture_cleanup"] = not fixture_attempted or fixture_closed(server)
        if state is not None:
            record["fixture"] = state.snapshot()
            try:
                E.fixture_observation(record["fixture"], name, successful=True)
                checks.update(fixture_valid=True, source_preserved=True)
                checks.update(authenticated=True, no_payload=True)
            except BaseException:
                mark(record, "fixture_failed", errors)
        if item["lease"] is not None and all(checks[k] for k in ("process_cleanup", "fixture_cleanup")):
            try:
                preserved(item, app_sha, before_start=not start_attempted)
                H.application_roots_empty(case, item["roots"])
                H.helper_cleanup_preserved(H.helper_baseline(case, item["roots"]), item["baseline"])
                checks["process_cleanup"] = False
                H.prepare(suite, case.name, "Verify")
                checks["process_cleanup"] = True
                H.remove_owned(case, item["lease"])
                checks["temp_cleanup"] = True
            except BaseException:
                mark(record, "cleanup_failed", errors)
        if not all(checks[k] for k in ("process_cleanup", "fixture_cleanup", "temp_cleanup")):
            mark(record, "cleanup_failed", errors)
    return item

def run(application, application_sha, commit, mode=E.MODE):
    H.hosted_guard()
    names = E.mode_cases(mode)
    application = Path(application).absolute()
    runtime, bound = E.runtime_binding(ROOT), E.compute_bindings(ROOT, application, commit, mode)
    cases, group, errors, items = E.empty_cases(mode), E.empty_group(), [], []
    suite = suite_id = None
    clean = False
    try:
        need(bound["application_sha256"] == application_sha and os.environ.get("GITHUB_SHA") == commit and bindings(application, commit, mode) == bound, "binding_failed")
        parent = Path(os.environ["RUNNER_TEMP"]).absolute()
        suite = parent / ("app-http-" + uuid.uuid4().hex)
        H.prepare(parent, suite.name)
        suite_id = H.identity(suite)
        group.update(status="failed", checks=dict.fromkeys(E.GROUP_CHECKS, False))
        for name in names:
            item = execute(name, suite, application, application_sha, runtime, errors)
            items.append(item)
            cases[name] = item["record"]
            if errors:
                break
    except BaseException as error:
        errors.append(failure(error))
    finally:
        try:
            need(bindings(application, commit, mode) == bound and E.runtime_binding(ROOT) == runtime, "preservation_failed")
        except BaseException:
            errors.append("preservation_failed")
        if group["status"] != "not_run":
            group["checks"].update(configs_preserved=len(items) == len(names) and all(i["record"]["checks"]["configuration_preserved"] for i in items),
                artifacts_preserved=len(items) == len(names) and all(i["artifact"] is not None and i["record"]["checks"]["temp_cleanup"] for i in items),
                all_processes_reaped=bool(items) and all(i["record"]["checks"]["process_cleanup"] for i in items),
                fixture_cleanup=bool(items) and all(i["record"]["checks"]["fixture_cleanup"] for i in items))
        if suite_id is not None:
            try:
                need(bool(items) and all(i["record"]["checks"]["temp_cleanup"] for i in items) and not H.inventory(suite), "cleanup_failed")
                group["checks"]["all_processes_reaped"] = False
                H.prepare(suite.parent, suite.name, "Verify")
                group["checks"]["all_processes_reaped"] = True
                H.remove_owned(suite, suite_id)
                group["checks"]["temp_cleanup"] = True
                clean = True
            except BaseException:
                errors.append("cleanup_failed")
        elif suite is None:
            clean = True
        else:
            errors.append("cleanup_failed")
    errors = list(dict.fromkeys(errors))
    success = len(items) == len(names) and not errors and clean and all(group["checks"].values()) and all(
        all(v for k, v in i["record"]["checks"].items() if k != "group_finalized") for i in items)
    if success:
        group["status"] = "passed"
        for row in cases.values():
            row["status"], row["checks"]["group_finalized"] = "passed", True
    elif group["status"] != "not_run":
        mark(group, "group_failed", errors)
        for row in cases.values():
            if row["status"] != "not_run":
                mark(row, row["failure_code"] or "group_failed", errors)
    receipt = dict(schema_version=1, scope=E.SCOPE, fixture_mode=mode, backend="b2", platform="windows",
        created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), runtime=runtime, bindings=bound, cases=cases,
        experiment=group, authentication="synthetic_basic_then_authorization_token", claims=dict.fromkeys(E.false_claims(mode), False), cleanup_complete=clean,
        errors=errors, capabilities=E.derive_capabilities(cases, clean, mode), result="passed" if success else "failed")
    E.validate_receipt(receipt, runtime, bound, mode=mode)
    return receipt

def main(argv=None):
    parser = argparse.ArgumentParser()
    for flag in ("application", "application-sha256", "build-commit", "report"):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--fixture-mode", choices=E.MODES, default=E.MODE)
    args = parser.parse_args(argv)
    descriptor = prior = None
    try:
        H.hosted_guard()
        def interrupted(_signal, _frame):
            raise KeyboardInterrupt()
        prior = signal.signal(signal.SIGTERM, interrupted)
        path = Path(args.report).absolute()
        H.plain(path.parent, True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        receipt = run(args.application, args.application_sha256, args.build_commit, args.fixture_mode)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(E.compact(receipt) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        return 0 if receipt["result"] == "passed" else 1
    except BaseException:
        print("application_probe_failed", file=__import__("sys").stderr)
        return 1
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if prior is not None:
            signal.signal(signal.SIGTERM, prior)


if __name__ == "__main__":
    raise SystemExit(main())

