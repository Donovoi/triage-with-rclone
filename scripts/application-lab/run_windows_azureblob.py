#!/usr/bin/env python3
"""Hosted-only two-invocation Azure SharedKey experiment; no work on import."""
import argparse
import base64
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


H = load("azureblob_http_support", HERE / "run_windows_http.py")
W = load("azureblob_preservation_support", HERE / "run_windows_webdav.py")
C = load("azureblob_observer_transport", HERE / "filesystem_controller.py")
F = load("azureblob_fixture", HERE / "fixture_azureblob.py")
E = load("azureblob_contract", HERE.parent / "azureblob_application_evidence.py")
SELF_HASH = H.sha(H.read(Path(__file__), 512 * 1024))
need, ProducerError = H.need, H.ProducerError
CLEANUP_UNCERTAIN = frozenset({"termination_failed", "process_cleanup_failed", "input_cleanup_failed",
    "reader_cleanup_failed", "console_cleanup_failed", "console_cleanup_timeout", "source_directory_cleanup_failed",
    "debug_cleanup_failed", "source_directory_invalid"})
# Existing generic HTTP private-directory names; no shared allowlist changes.
CASE_DIRECTORIES = {"acquisition": "acquisition", "denial": "denial"}


def bindings(application, commit):
    H.loaded_sources_preserved()
    W.bindings(application, commit)  # Includes W's loaded transitive dependencies.
    C.H.loaded_sources_preserved()
    for module in (H, W, C, C.H, F, E):
        need(H.sha(H.read(module.__file__, 512 * 1024)) == module.loaded_source_sha256, "preservation_failed")
    need(H.sha(H.read(Path(__file__), 512 * 1024)) == SELF_HASH, "preservation_failed")
    need(H.sha(H.read(F._PATH, 512 * 1024)) == F.loaded_http_source_sha256, "preservation_failed")
    need(H.sha(H.read(F._SIGNER_PATH, 512 * 1024)) == F.loaded_signer_source_sha256, "preservation_failed")
    return E.compute_bindings(ROOT, application, commit)


def failure(error):
    return str(error) if isinstance(error, (ProducerError, W.ProducerError, C.H.ProducerError)) and str(error) in E.FAILURE_CODES else "unexpected_failure"


def mark(record, code, errors):
    record["status"] = "failed"
    record["failure_code"] = record["failure_code"] or code
    if code not in errors:
        errors.append(code)


def queue_bytes():
    f = E.fixture_manifest()
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\r\n")
    writer.writerow(H.HEADERS)
    writer.writerow(["excel-safe-v1", "Synthetic", f["member"], f["size"], H.MODIFIED, "false", f["sha256"], "sha256"])
    return b"\xef\xbb\xbf" + stream.getvalue().encode("utf-8")


def config_bytes(endpoint, key):
    need(type(endpoint) is str and re.fullmatch(r"http://127\.0\.0\.1:[1-9][0-9]{0,4}/", endpoint) and
         1 <= int(endpoint.split(":")[-1][:-1]) <= 65535 and type(key) is str, "binding_failed")
    try:
        decoded=base64.b64decode(key,validate=True)
        need(len(decoded)==32 and base64.b64encode(decoded).decode("ascii")==key,"binding_failed")
    except (ValueError,UnicodeError):
        raise ProducerError("binding_failed") from None
    return ("[Synthetic]\ntype = azureblob\nenv_auth = false\nuse_emulator = true\naccount = syntheticaccount\n"
        +f"key = {key}\nendpoint = {endpoint}syntheticaccount\nuse_arrow_list = false\n").encode("ascii")


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


def exact_stat_denial(value, endpoint):
    # SDK v1.23.1 ResponseError is a complete multiline block, not a last-line cause.
    if type(value) is not str or not 0 < len(value) <= 65536 or "\x00" in value or "\r" in value:
        return False
    if type(endpoint) is not str or not re.fullmatch(r"http://127\.0\.0\.1:[1-9][0-9]{0,4}/",endpoint):
        return False
    if not 1 <= int(endpoint.split(":")[-1][:-1]) <= 65535 or not value.startswith("Cannot stat source: "):
        return False
    value=value[len("Cannot stat source: "):]
    lines=value.rstrip("\n").split("\n")
    separator="-"*80
    expected=[separator,"RESPONSE 403: 403 Forbidden","ERROR CODE: AuthenticationFailed",separator,
              "Response contained no body",separator]
    cause="loopback: call failed: HEAD "+endpoint+"syntheticaccount/synthetic-container/nested%2Fspace%20name.txt"
    return (len(lines)==7 and re.fullmatch(W.NOTICE+re.escape(cause),lines[0]) is not None and
            lines[1:]==expected and sum("NOTICE: Failed to rc:" in line for line in lines)==1)


def manifest(name, case, working, runtime, endpoint):
    f = E.fixture_manifest()
    base = case / "output" / H.CASE_NAME
    inventory = H.inventory(base)
    names = [p for p, v in inventory.items() if not v[0] and re.fullmatch(r"acquisition-[0-9T.]+\.json", p)]
    need(len(names) == 1, "manifest_invalid")
    value = H.strict_json(H.read(base / names[0], 128 * 1024))
    positive = name == "acquisition"
    need(type(value) is dict and set(value) == {"schema_version", "written_at", "rclone_version", "config_path", "plan", "results", "complete"} and
         type(value["schema_version"]) is int and value["schema_version"] == 1 and H.valid_time(value["written_at"]) and
         value["rclone_version"] == runtime["version"] and H.same_path(value["config_path"], working) and value["complete"] is positive, "manifest_invalid")
    plan, results = value["plan"], value["results"]
    need(type(plan) is dict and set(plan) == {"files", "skipped_directories"} and type(plan["skipped_directories"]) is int and
         plan["skipped_directories"] == 0 and type(plan["files"]) is list and len(plan["files"]) == 1 and type(results) is list and len(results) == 1, "manifest_invalid")
    selected, result = plan["files"][0], results[0]
    destination = base / "downloads/Synthetic" / f["member"]
    need(type(selected) is dict and set(selected) == {"remote_name", "path", "request"} and selected["remote_name"] == "Synthetic" and
         selected["path"] == f["member"], "manifest_invalid")
    request = selected["request"]
    need(type(request) is dict and set(request) == {"source", "destination", "mode", "expected_hash", "expected_hash_type", "expected_size"} and
         request["source"] == "Synthetic:" + f["member"] and H.same_path(request["destination"], destination) and request["mode"] == "CopyTo" and
         request["expected_hash"] == f["sha256"] and request["expected_hash_type"] == "sha256" and type(request["expected_size"]) is int and request["expected_size"] == f["size"], "manifest_invalid")
    need(type(result) is dict and set(result) == {"local_sha256", "integrity", "source", "destination", "success", "error", "size", "hash", "hash_type", "hash_verified", "hash_error"} and
         result["source"] == request["source"] and H.same_path(result["destination"], destination), "manifest_invalid")
    if positive:
        expected = dict(local_sha256=f["sha256"], integrity="Verified", source=request["source"], destination=result["destination"],
            success=True, error=None, size=f["size"], hash=f["sha256"], hash_type="sha256", hash_verified=True, hash_error=None)
        need(result == expected and result["success"] is True and result["hash_verified"] is True and type(result["size"]) is int, "manifest_invalid")
        body = H.read(destination, f["size"])
        need(len(body) == f["size"] and H.sha(body) == f["sha256"], "outputs_invalid")
    else:
        need(result["success"] is False and result["integrity"] == "Failed" and
             all(result[k] is None for k in ("local_sha256", "size", "hash", "hash_type", "hash_verified", "hash_error")), "manifest_invalid")
        need(exact_stat_denial(result["error"], endpoint), "denial_failed")
    wanted = {"Synthetic/" + f["member"]} if positive else set()
    need(set(H.output_files(base / "downloads")) == wanted, "outputs_invalid")
    files = {p for p, row in inventory.items() if not row[0]}
    config = {p for p in files if p.startswith("config/")}
    stem = names[0][:-5]
    allowed = config | {names[0], stem + ".txt", "logs/" + stem + ".log", "logs/" + stem + ".checkpoint.json"} | {"downloads/" + p for p in wanted}
    dirs = {p for p, row in inventory.items() if row[0]}
    need(len(config) == 2 and files == allowed and {"logs", "downloads", "listings", "config"} <= dirs <=
         {"logs", "downloads", "listings", "config", "downloads/Synthetic", "downloads/Synthetic/synthetic-container", "downloads/Synthetic/synthetic-container/nested"} and
         set(H.inventory(case / "output")) == {H.CASE_NAME} | {H.CASE_NAME + "/" + p for p in inventory}, "outputs_invalid")
    return dict.fromkeys(("manifest_exact", "output_hash_exact", "outputs_exact") if positive else ("manifest_exact", "no_download_outputs"), True)


def preserved(item, app_sha, *, before_start=False):
    case = item["case"]
    need(H.identity(case) == item["lease"] and H.identity(case / "source") == item["source"] and not H.inventory(case / "source") and
         H.sha(H.read(case / "application.exe", 512 * 1024 * 1024)) == app_sha and
         H.read(case / "queue.csv", 8192) == queue_bytes(), "preservation_failed")
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


def execute(name, suite, application, app_sha, runtime, errors):
    record = dict(status="failed", exit_code=None, runtime_sha256=None, observation=None, continuity=None, fixture=None,
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
        H.private_write(case, "queue.csv", queue_bytes())
        bridge = C.ObservedSourceBridge(case)
        H.validate_ready(bridge.command("ready"))
        ready = True
        # Capture helper-only identity/layout before later fixture/config setup
        # can fail. An unavailable baseline remains a cleanup failure.
        H.application_roots_empty(case, item["roots"])
        item["baseline"] = H.helper_baseline(case, item["roots"])
        # Fresh fixture starts after readiness, inside the original case deadline.
        correct = secrets.token_bytes(32)
        wrong = bytes(value ^ 1 for value in correct)
        state = F.AppAzureBlobState(name, base64.b64encode(correct).decode("ascii"), base64.b64encode(wrong).decode("ascii"))
        key = base64.b64encode(correct if name == "acquisition" else wrong).decode("ascii")
        context = F.serve_azureblob(state)
        fixture_attempted = True
        server = context.__enter__()
        entered = True
        deadline = min(deadline, server.deadline)
        config = item["config"] = config_bytes(server.endpoint, key)
        H.private_write(case, "source.conf", config)
        item["config_written"] = True
        H.application_roots_empty(case, item["roots"])
        # Normal launch keeps the original latest pre-start baseline. The earlier
        # ready-only snapshot is only needed when setup never reaches this point.
        item["baseline"] = H.helper_baseline(case, item["roots"])
        remaining = int((deadline - time.monotonic()) * 1000)
        need(1000 <= remaining <= 120000, "deadline_exceeded")
        start_fields = dict(app_path=str(case / "application.exe"), app_sha256=app_sha,
            args=H.app_args("acquisition", case), case_root=str(case), environment=H.environment(case),
            transcript_path=str(case / "transcript.private"), max_output_bytes=8 * 1024 * 1024,
            deadline_ms=remaining, max_runtime_processes=1, expected_runtime_sha256=runtime["sha256"], max_runtime_launches=E.EXPECTED_LAUNCHES[name])
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
        record["observation"] = observed_final(response, name, runtime)
        record["exit_code"] = response["app_exit_code"]
        record["runtime_sha256"] = runtime["sha256"]
        checks.update(runtime_observed=True, orderly_exit=True)
        positive = name == "acquisition"
        need(type(record["exit_code"]) is int and record["exit_code"] == (0 if positive else 1), "session_failed")
        checks["exit_success" if positive else "exit_failure"] = True
        working = H.configuration_preserved(case, config)
        checks["configuration_preserved"] = True
        checks.update(manifest(name, case, working, runtime, server.endpoint))
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
                checks.update(dict(authenticated=True) if name == "acquisition" else dict(wrong_key_denied=True, no_payload=True))
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


def run(application, application_sha, commit):
    H.hosted_guard()
    application = Path(application).absolute()
    runtime, bound = E.runtime_binding(ROOT), E.compute_bindings(ROOT, application, commit)
    cases, group, errors, items = E.empty_cases(), E.empty_group(), [], []
    suite = suite_id = None
    clean = False
    try:
        need(bound["application_sha256"] == application_sha and os.environ.get("GITHUB_SHA") == commit and bindings(application, commit) == bound, "binding_failed")
        parent = Path(os.environ["RUNNER_TEMP"]).absolute()
        suite = parent / ("app-http-" + uuid.uuid4().hex)
        H.prepare(parent, suite.name)
        suite_id = H.identity(suite)
        group.update(status="failed", checks=dict.fromkeys(E.GROUP_CHECKS, False))
        for name in E.CASES:
            item = execute(name, suite, application, application_sha, runtime, errors)
            items.append(item)
            cases[name] = item["record"]
            if errors:
                break
    except BaseException as error:
        errors.append(failure(error))
    finally:
        try:
            need(bindings(application, commit) == bound and E.runtime_binding(ROOT) == runtime, "preservation_failed")
        except BaseException:
            errors.append("preservation_failed")
        if group["status"] != "not_run":
            group["checks"].update(configs_preserved=len(items) == 2 and all(i["record"]["checks"]["configuration_preserved"] for i in items),
                artifacts_preserved=len(items) == 2 and all(i["artifact"] is not None and i["record"]["checks"]["temp_cleanup"] for i in items),
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
    success = len(items) == 2 and not errors and clean and all(group["checks"].values()) and all(
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
    receipt = dict(schema_version=1, scope=E.SCOPE, fixture_mode=E.MODE, backend="azureblob", platform="windows",
        created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), runtime=runtime, bindings=bound, cases=cases,
        experiment=group, authentication="static_shared_key", claims=dict.fromkeys(E.FALSE_CLAIMS, False), cleanup_complete=clean,
        errors=errors, capabilities=E.derive_capabilities(cases, clean), result="passed" if success else "failed")
    E.validate_receipt(receipt, runtime, bound)
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser()
    for flag in ("application", "application-sha256", "build-commit", "report"):
        parser.add_argument("--" + flag, required=True)
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
        receipt = run(args.application, args.application_sha256, args.build_commit)
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
