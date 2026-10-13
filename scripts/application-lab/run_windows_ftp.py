#!/usr/bin/env python3
"""Hosted-only three-invocation FTP reconnect experiment; no work on import."""
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


H = load("ftp_http_support", HERE / "run_windows_http.py")
W = load("ftp_obscure_support", HERE / "run_windows_webdav.py")
C = load("ftp_observer_transport", HERE / "filesystem_controller.py")
F = load("ftp_fixture", HERE / "fixture_ftp.py")
E = load("ftp_contract", HERE.parent / "ftp_application_evidence.py")
SELF_HASH = H.sha(H.read(Path(__file__), 512 * 1024))
need, ProducerError = H.need, H.ProducerError
CLEANUP_UNCERTAIN = frozenset({"termination_failed", "process_cleanup_failed", "input_cleanup_failed",
    "reader_cleanup_failed", "console_cleanup_failed", "console_cleanup_timeout", "source_directory_cleanup_failed",
    "debug_cleanup_failed", "source_directory_invalid"})


def bindings(application, commit):
    H.loaded_sources_preserved()
    W.bindings(application, commit)  # Includes W's loaded transitive dependencies.
    C.H.loaded_sources_preserved()
    for module in (H, W, C, C.H, F, E):
        need(H.sha(H.read(module.__file__, 512 * 1024)) == module.loaded_source_sha256, "preservation_failed")
    need(H.sha(H.read(Path(__file__), 512 * 1024)) == SELF_HASH, "preservation_failed")
    return E.compute_bindings(ROOT, application, commit)


def failure(error):
    return str(error) if isinstance(error, (ProducerError, W.ProducerError, C.H.ProducerError)) and str(error) in E.FAILURE_CODES else "unexpected_failure"


def mark(record, code, errors):
    record["status"] = "failed"
    record["failure_code"] = record["failure_code"] or code
    if code not in errors:
        errors.append(code)


def denial_terminal_detail(terminal):
    # Text observations only; never accepted causes. Pinned Go 1.26 io/context,
    # internal/poll, net.OpError and textproto reader; jlaffaye/ftp 6602e981 Login.
    exact = {"530 Login incorrect": "login_incorrect", "530 Login required": "login_required",
             "Login incorrect": "login_message_only", "context canceled": "context_canceled_text",
             "context deadline exceeded": "context_deadline_text"}
    if terminal in exact:
        return exact[terminal]
    for text, category in (("EOF", "eof_text"), ("unexpected EOF", "unexpected_eof_text"),
                           ("i/o timeout", "io_timeout_text"),
                           ("use of closed network connection", "closed_connection_text")):
        if terminal == text or terminal.endswith(": " + text):
            return category
    for prefix, category in (("short response: ", "textproto_short_response"),
                             ("invalid response code: ", "textproto_invalid_code")):
        if terminal.startswith(prefix):
            return category
    return "other"


def denial_error_diagnostic(value, cause):
    """Failure-only shape observations; never publish the error or endpoint."""
    try:
        record = dict(schema_version=1, case="revoked_a", stage="manifest_denial",
            error_is_string=type(value) is str,
            error_within_bound=type(value) is str and 0 < len(value) <= 65536,
            error_text_valid=False, cannot_stat_prefix=None, line_limit_ok=None,
            notice_count=None, final_notice_grammar=None, expected_cause_equal=None,
            expected_connection_prefix_equal=None, terminal_category=None,
            terminal_reply_prefix=None, terminal_contains_reply=None, terminal_length_relation=None,
            terminal_detail=None)
        if record["error_within_bound"]:
            record["error_text_valid"] = "\x00" not in value and "\r" not in value
            if record["error_text_valid"]:
                prefix = "Cannot stat source: "
                record["cannot_stat_prefix"] = value.startswith(prefix)
                if record["cannot_stat_prefix"]:
                    lines = value[len(prefix):].rstrip("\n").split("\n")
                    record["line_limit_ok"] = len(lines) <= 128
                    if record["line_limit_ok"]:
                        record["notice_count"] = sum("NOTICE: Failed to rc:" in line for line in lines)
                        match = re.fullmatch(W.NOTICE + r"loopback: call failed: (.+)", lines[-1])
                        record["final_notice_grammar"] = match is not None
                        if match is not None and type(cause) is str and 0 < len(cause) <= 512:
                            record["expected_cause_equal"] = match[1] == cause
                            connection = re.fullmatch(
                                r'(NewFs: failed to make FTP connection to "127\.0\.0\.1:([1-9][0-9]{0,4})": )530 Login incorrect', cause)
                            if connection is not None and int(connection[2]) <= 65535:
                                record["expected_connection_prefix_equal"] = match[1].startswith(connection[1])
                                if record["expected_connection_prefix_equal"]:
                                    # Exact replies emitted by the fixed fixture, not a generic status-code matcher.
                                    terminal = match[1][len(connection[1]):]
                                    record["terminal_category"] = {"530 Login incorrect": "login_incorrect",
                                        "530 Login required": "login_required"}.get(terminal, "other")
                                    if record["notice_count"] == 1:
                                        reply = "530 Login incorrect"
                                        record.update(terminal_reply_prefix=terminal.startswith("530 "),
                                            terminal_contains_reply=reply in terminal,
                                            terminal_length_relation=("shorter" if len(terminal) < len(reply) else
                                                                      "equal" if len(terminal) == len(reply) else "longer"),
                                            terminal_detail=denial_terminal_detail(terminal))
        line = "application_ftp_denial_error=" + E.compact(record).decode("ascii")
        if len(line.encode("ascii")) + 1 <= 1024:
            print(line, flush=True)
    except BaseException:
        pass


def denial_fixture_diagnostic(state, closed):
    """One post-teardown nonblocking copy of owned epoch-2 facts; no reread."""
    try:
        if type(closed) is not bool:
            return
        record = dict(schema_version=1, case="revoked_a", stage="manifest_denial",
                      timing="after_fixture_teardown_attempt", fixture_cleanup_complete=closed,
                      epoch=2, snapshot_available=False, availability_reason="state_type", counts=None, errors=None,
                      denial_send_availability="snapshot_unavailable", denial_sendall_attempted=None,
                      denial_sendall_returned=None)
        if type(state) is F.AppFtpState:
            record["availability_reason"] = "lock_busy"
        if type(state) is F.AppFtpState and state.lock.acquire(blocking=False):
            try:
                events, errors = state.events, state.errors
                fields = {"ordinal", "kind", "epoch", "session", "transfer", "member", "bytes"}
                limits = {"epoch": (1, 3), "session": (0, F.MAX_SESSIONS), "transfer": (0, F.MAX_TRANSFERS),
                          "member": (0, len(F.MANIFEST)), "bytes": (0, F.MAX_WIRE_BYTES)}
                if type(state.epoch) is not int or state.epoch != 2:
                    record["availability_reason"] = "epoch_invalid"
                elif type(events) is not list or len(events) > F.MAX_EVENTS:
                    record["availability_reason"] = "events_shape"
                elif (type(errors) is not list or len(errors) > len(F.ERROR_CODES) or
                      not all(type(e) is str and e in F.ERROR_CODES for e in errors) or len(set(errors)) != len(errors)):
                    record["availability_reason"] = "errors_shape"
                elif not all(type(e) is dict and set(e) == fields and type(e["ordinal"]) is int and e["ordinal"] == index and
                        type(e["kind"]) is str and e["kind"] in F.EVENT_KINDS and
                        all(type(e[k]) is int and lo <= e[k] <= hi for k, (lo, hi) in limits.items())
                        for index, e in enumerate(events, 1)):
                    record["availability_reason"] = "event_invalid"
                else:
                    kinds = ("session_open", "user", "login_a", "login_b", "denied_a", "denied_b",
                             "denied_other", "transfer_start", "content_sent")
                    record.update(snapshot_available=True, availability_reason="available", errors=sorted(errors),
                        counts={kind: sum(e["epoch"] == 2 and e["kind"] == kind for e in events) for kind in kinds})
                    denied = [e for e in events if e["epoch"] == 2 and e["kind"] == "denied_a"]
                    record["denial_send_availability"] = "not_observed" if not denied else "ambiguous"
                    if len(denied) == 1:
                        witness = getattr(state, "_denial_send", None)
                        record["denial_send_availability"] = "cache_unavailable"
                        if (type(witness) is tuple and len(witness) == 5 and
                                all(type(v) is int for v in witness[:3]) and
                                witness[:3] == (2, denied[0]["ordinal"], denied[0]["session"]) and
                                ((witness[3] is None and witness[4] is None) or
                                 (witness[3] is True and (witness[4] is None or type(witness[4]) is bool)))):
                            record.update(denial_send_availability="available",
                                          denial_sendall_attempted=witness[3], denial_sendall_returned=witness[4])
            finally:
                state.lock.release()
        line = "application_ftp_denial_fixture=" + E.compact(record).decode("ascii")
        if len(line.encode("ascii")) + 1 <= 1024:
            print(line, flush=True)
    except BaseException:
        pass


def queue_bytes():
    f = E.fixture_manifest()
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\r\n")
    writer.writerow(H.HEADERS)
    writer.writerow(["excel-safe-v1", "Synthetic", f["member"], f["size"], H.MODIFIED, "false", f["sha256"], "sha256"])
    return b"\xef\xbb\xbf" + stream.getvalue().encode("utf-8")


def config_bytes(endpoint, user, token):
    need(type(endpoint) is tuple and len(endpoint) == 2 and endpoint[0] == "127.0.0.1" and
         type(endpoint[1]) is int and 1 <= endpoint[1] <= 65535 and type(user) is str and
         re.fullmatch(r"[a-f0-9]{64}", user) and type(token) is str and re.fullmatch(r"[A-Za-z0-9_-]{107}", token), "binding_failed")
    return (f"[Synthetic]\ntype = ftp\nhost = 127.0.0.1\nport = {endpoint[1]}\nuser = {user}\npass = {token}\n"
            "tls = false\nexplicit_tls = false\n").encode("ascii")


def credentials(suite, executable, runtime, errors):
    case = suite / "ftp-credential-setup"
    lease = roots = baseline = None
    safe, clean, result = True, False, None
    try:
        H.prepare(suite, case.name)
        lease = H.identity(case)
        roots = H.create_private_roots(case)
        baseline = H.helper_baseline(case, roots)
        data = H.read(executable, 128 * 1024 * 1024, allow_hardlinks=True)
        need(H.sha(data) == runtime["sha256"], "binding_failed")
        H.private_write(case, "application.exe", data)
        H.private_write(case, "source.conf", b"")
        user, a, b = (secrets.token_hex(32) for _ in range(3))
        need(a != b, "case_setup_failed")
        tokens = []
        for password in (a, b):
            safe = False
            tokens.append(W.obscure_once(case / "application.exe", case, password, runtime["sha256"]))
            safe = True
        result = user, a, b, *tokens
    except BaseException as error:
        errors.append(failure(error))
    finally:
        if lease is not None and safe and roots is not None and baseline is not None:
            try:
                need(H.identity(case) == lease and H.read(case / "source.conf", 8192) == b"" and
                     H.sha(H.read(case / "application.exe", 128 * 1024 * 1024)) == runtime["sha256"] and
                     H.sha(H.read(executable, 128 * 1024 * 1024, allow_hardlinks=True)) == runtime["sha256"], "preservation_failed")
                H.application_roots_empty(case, roots)
                H.helper_cleanup_preserved(H.helper_baseline(case, roots), baseline)
                H.prepare(suite, case.name, "Verify")
                H.remove_owned(case, lease)
                clean = True
            except BaseException:
                errors.append("cleanup_failed")
        if not clean:
            errors.append("cleanup_failed")
    return result, clean


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
    # A failed continuity response has one additional null field. Only its exact
    # closed transport shape may be stripped; successful live proof is not final.
    if final.get("action") == "observe_continuity":
        if set(final) != C.OBSERVED_KEYS | {"continuity"} or final["continuity"] is not None:
            return False
        final = {key: final[key] for key in C.OBSERVED_KEYS}
    C.validate_observed_snapshot(final, final.get("action"), runtime["sha256"], 1, E.EXPECTED_LAUNCHES[name])
    return (final["state"] == "finished" and not set(final["errors"]) & CLEANUP_UNCERTAIN and
            all(final[k] is True for k in (*H.SESSION_CLEANUP, *C.OBSERVED_CLEANUP)))


def continuity(bridge, state, server, deadline, runtime):
    proofs = {}
    for gate, phase in zip(F.GATES, ("arm", "verify")):
        while True:
            need(time.monotonic() < deadline and not state.errors, "continuity_failed")
            gates = state.gate_snapshot()
            need(type(gates) is dict and set(gates) == set(F.GATES), "continuity_failed")
            if gates[gate]["entered"] is not None:
                need(gates[gate]["released"] is False, "continuity_failed")
                break
            response = bridge.command("poll")
            need(response["ok"] and response["state"] == "running" and not response["app_exited"], "continuity_failed")
            time.sleep(0.02)
        response = bridge.command("observe_continuity", phase=phase)
        need(time.monotonic() < deadline and response["ok"] and response["state"] == "running" and
             response["app_exited"] is False, "continuity_failed")
        proof = response.get("continuity")
        C.validate_continuity(proof, phase, runtime["sha256"])
        proofs[phase] = dict(proof)
        state.release_gate(gate)
        need(time.monotonic() < deadline, "deadline_exceeded")
    return proofs


def manifest(name, case, working, runtime, endpoint):
    f = E.fixture_manifest()
    base = case / "output" / H.CASE_NAME
    inventory = H.inventory(base)
    names = [p for p, v in inventory.items() if not v[0] and re.fullmatch(r"acquisition-[0-9T.]+\.json", p)]
    need(len(names) == 1, "manifest_invalid")
    value = H.strict_json(H.read(base / names[0], 128 * 1024))
    positive = name != "revoked_a"
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
        cause = f'NewFs: failed to make FTP connection to "127.0.0.1:{endpoint[1]}": 530 Login incorrect'
        try:
            need(W.exact_rc_error(result["error"], cause, stat=True), "denial_failed")
        except ProducerError:
            denial_error_diagnostic(result["error"], cause)
            raise
    wanted = {"Synthetic/" + f["member"]} if positive else set()
    need(set(H.output_files(base / "downloads")) == wanted, "outputs_invalid")
    files = {p for p, row in inventory.items() if not row[0]}
    config = {p for p in files if p.startswith("config/")}
    stem = names[0][:-5]
    allowed = config | {names[0], stem + ".txt", "logs/" + stem + ".log", "logs/" + stem + ".checkpoint.json"} | {"downloads/" + p for p in wanted}
    dirs = {p for p, row in inventory.items() if row[0]}
    need(len(config) == 2 and files == allowed and {"logs", "downloads", "listings", "config"} <= dirs <=
         {"logs", "downloads", "listings", "config", "downloads/Synthetic", "downloads/Synthetic/large"} and
         set(H.inventory(case / "output")) == {H.CASE_NAME} | {H.CASE_NAME + "/" + p for p in inventory}, "outputs_invalid")
    return dict.fromkeys(("manifest_exact", "output_hash_exact", "outputs_exact") if positive else ("manifest_exact", "no_download_outputs"), True)


def fixture_checks(name, state):
    snap = state.snapshot()
    need(not snap["errors"] and snap["source_preserved"], "fixture_failed")
    epoch = E.CASES.index(name) + 1
    events = [e for e in snap["events"] if e["epoch"] == epoch]
    def matching(kind):
        return [e for e in events if e["kind"] == kind]
    need(events and (name == "revoked_a" or not any(e["kind"].startswith("denied_") for e in events)), "fixture_failed")
    result = dict(fixture_valid=True, source_preserved=True)
    if name == "accepted_a":
        kinds = ("gate_pre_drop", "drop_prefix_sent", "drop_fin", "gate_restart", "content_sent", "restart_served")
        need(all(len(matching(k)) == 1 for k in kinds) and len(matching("transfer_start")) == 2 and len(matching("gate_released")) == 2, "continuity_failed")
        first, prefix, drop, second, content, restart = [matching(k)[0] for k in kinds]
        need(first["ordinal"] < prefix["ordinal"] < drop["ordinal"] < second["ordinal"] < content["ordinal"] < restart["ordinal"] and
             first["session"] == prefix["session"] == drop["session"] and second["session"] == content["session"] == restart["session"] and
             first["session"] != second["session"] and all(e["member"] == 2 for e in (first, prefix, drop, second, content, restart)) and
             prefix["bytes"] == drop["bytes"] == 65536 and content["bytes"] == restart["bytes"] == 2097152 and
             any(e["kind"] == "session_open" and e["session"] == second["session"] and drop["ordinal"] < e["ordinal"] for e in events) and
             any(e["kind"] == "login_a" and e["session"] == second["session"] and drop["ordinal"] < e["ordinal"] < second["ordinal"] for e in events), "continuity_failed")
        result.update(pre_prefix_gate=True, post_relogin_gate=True, drop_once=True, fresh_login_after_drop=True)
    elif name == "revoked_a":
        need(matching("denied_a") and not any(e["kind"] in {"login_a", "login_b", "denied_b", "denied_other", "transfer_start", "content_sent"} for e in events), "denial_failed")
        result.update(credential_denial=True, no_payload=True)
    else:
        need(matching("login_b") and not matching("login_a") and len(matching("content_sent")) == len(matching("transfer_start")) == 1 and
             matching("content_sent")[0]["member"] == 2 and matching("content_sent")[0]["bytes"] == 2097152, "fixture_failed")
    return result


def preserved(item, app_sha):
    case = item["case"]
    need(H.identity(case) == item["lease"] and H.identity(case / "source") == item["source"] and not H.inventory(case / "source") and
         H.sha(H.read(case / "application.exe", 512 * 1024 * 1024)) == app_sha and H.read(case / "source.conf", 8192) == item["config"] and
         H.read(case / "queue.csv", 8192) == queue_bytes(), "preservation_failed")
    if item["record"]["checks"]["configuration_preserved"]:
        H.configuration_preserved(case, item["config"])
    if item["artifact"] is not None:
        need(W.fingerprint(case) == item["artifact"], "preservation_failed")


def execute(name, owner, application, app_sha, runtime, server, state, config, errors):
    record = dict(status="failed", exit_code=None, runtime_sha256=None, observation=None, continuity=None,
                  failure_code=None, checks=dict.fromkeys(E.CHECKS[name], False))
    item = dict(name=name, record=record, case=owner / ("ftp-" + name.replace("_", "-")), lease=None,
                source=None, roots=None, baseline=None, artifact=None, config=config, attempted=False)
    case, checks, bridge = item["case"], record["checks"], None
    try:
        H.prepare(owner, case.name)
        item["lease"] = H.identity(case)
        item["roots"] = H.create_private_roots(case)
        H.private_directory(case, "output")
        item["source"] = create_source(case)
        body = H.read(application, 512 * 1024 * 1024, allow_hardlinks=True)
        need(H.sha(body) == app_sha, "binding_failed")
        H.private_write(case, "application.exe", body)
        H.private_write(case, "source.conf", config)
        H.private_write(case, "queue.csv", queue_bytes())
        deadline = min(time.monotonic() + 120, server.deadline)
        item["attempted"] = True
        bridge = C.ObservedSourceBridge(case)
        H.validate_ready(bridge.command("ready"))
        H.application_roots_empty(case, item["roots"])
        item["baseline"] = H.helper_baseline(case, item["roots"])
        remaining = int((deadline - time.monotonic()) * 1000)
        need(1000 <= remaining <= 120000, "deadline_exceeded")
        response = bridge.command("start_source_observed", app_path=str(case / "application.exe"), app_sha256=app_sha,
            args=H.app_args("acquisition", case), case_root=str(case), environment=H.environment(case),
            transcript_path=str(case / "transcript.private"), max_output_bytes=8 * 1024 * 1024,
            deadline_ms=remaining, max_runtime_processes=1, expected_runtime_sha256=runtime["sha256"], max_runtime_launches=E.EXPECTED_LAUNCHES[name])
        need(response["ok"], "session_failed")
        if name == "accepted_a":
            record["continuity"] = continuity(bridge, state, server, deadline, runtime)
            checks["same_copy_process"] = True
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
        positive = name != "revoked_a"
        need(type(record["exit_code"]) is int and (record["exit_code"] == 0 if positive else record["exit_code"] != 0), "session_failed")
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
                checks["process_cleanup"] = cleanup_proved(bridge, bridge.close(), name, runtime)
                if checks["process_cleanup"] and record["exit_code"] is None:
                    record["exit_code"] = bridge.last.get("app_exit_code")
            except BaseException:
                checks["process_cleanup"] = False
        if not checks["process_cleanup"]:
            mark(record, "cleanup_failed", errors)
    return item


def fixture_closed(server):
    if server is None:
        return False
    snap = server.snapshot()
    return snap["cleanup_complete"] is True and all(snap[k] == 0 for k in
        ("control_listener", "control", "data_listener", "data", "workers_alive")) and snap["acceptor_alive"] is False


def exercise(suite, application, app_sha, runtime, secret, errors):
    owner = suite / "ftp-credentials"
    owner_id = server = state = context = None
    entered = attempted = False
    items = []
    group = dict(status="failed", failure_code=None, checks=dict.fromkeys(E.GROUP_CHECKS, False))
    try:
        H.prepare(suite, owner.name)
        owner_id = H.identity(owner)
        user, a, b, token_a, token_b = secret
        state = F.AppFtpState(user, a, password_b=b, continuity_gates=True)
        need(state.unchanged() and (len(state.files[E.fixture_manifest()["member"]]), H.sha(state.files[E.fixture_manifest()["member"]])) ==
             (E.fixture_manifest()["size"], E.fixture_manifest()["sha256"]), "binding_failed")
        context = F.serve_ftp(state)
        attempted = True
        server = context.__enter__()
        entered = True
        endpoint, deadline = server.endpoint, server.deadline
        for index, name in enumerate(E.CASES):
            need(server.endpoint == endpoint and server.deadline == deadline and time.monotonic() < deadline, "credential_transition_failed")
            config = config_bytes(endpoint, user, token_b if name == "replacement_b" else token_a)
            item = execute(name, owner, application, app_sha, runtime, server, state, config, errors)
            items.append(item)
            need(item["record"]["failure_code"] is None, item["record"]["failure_code"] or "session_failed")
            while not server.quiescent():
                need(time.monotonic() < deadline, "deadline_exceeded")
                time.sleep(0.02)
            item["record"]["checks"].update(fixture_checks(name, state))
            if name == "revoked_a":
                need(config == items[0]["config"], "preservation_failed")
                item["record"]["checks"]["same_config_as_accepted"] = True
            if name == "replacement_b":
                need(config != items[0]["config"] and config.replace(token_b.encode(), token_a.encode()) == items[0]["config"], "preservation_failed")
                item["record"]["checks"]["credential_changed"] = True
            if index < 2:
                state.advance_epoch(E.CASES[index + 1], invocation_succeeded=True, processes_reaped=item["record"]["checks"]["process_cleanup"])
        group["checks"].update(same_fixture=True, deadline_preserved=True, epochs_ordered=True, transitions_reaped=True)
    except BaseException as error:
        mark(group, failure(error), errors)
    finally:
        closed = not attempted
        if entered:
            try:
                context.__exit__(None, None, None)
                closed = fixture_closed(server)
            except BaseException:
                closed = False
        elif attempted:
            closed = state is not None and fixture_closed(state._transport)
        if any(item["name"] == "revoked_a" and item["record"]["failure_code"] == "denial_failed" for item in items):
            denial_fixture_diagnostic(state, closed)
        group["checks"]["fixture_cleanup"] = closed
        group["checks"]["all_processes_reaped"] = owner_id is not None and len(items) > 0 and all(i["record"]["checks"]["process_cleanup"] for i in items)
        preserved_all = True
        for item in items:
            item["record"]["checks"]["fixture_cleanup"] = closed
            try:
                preserved(item, app_sha)
                need(state.unchanged(), "preservation_failed")
            except BaseException as error:
                preserved_all = False
                mark(item["record"], failure(error), errors)
        if len(items) == 3 and preserved_all and all(i["record"]["checks"]["configuration_preserved"] for i in items) and items[0]["artifact"] is not None:
            group["checks"].update(configs_preserved=True, accepted_artifact_preserved=True)
        for item in items:
            checks = item["record"]["checks"]
            if closed and preserved_all and checks["process_cleanup"]:
                try:
                    H.application_roots_empty(item["case"], item["roots"])
                    H.helper_cleanup_preserved(H.helper_baseline(item["case"], item["roots"]), item["baseline"])
                    group["checks"]["all_processes_reaped"] = False
                    checks["process_cleanup"] = False
                    H.prepare(owner, item["case"].name, "Verify")
                    checks["process_cleanup"] = True
                    group["checks"]["all_processes_reaped"] = all(i["record"]["checks"]["process_cleanup"] for i in items)
                    H.remove_owned(item["case"], item["lease"])
                    checks["temp_cleanup"] = True
                except BaseException:
                    mark(item["record"], "cleanup_failed", errors)
                    preserved_all = False
            if not all(checks[k] for k in ("process_cleanup", "fixture_cleanup", "temp_cleanup")):
                mark(item["record"], "cleanup_failed", errors)
        if owner_id is not None and closed and all(i["record"]["checks"]["temp_cleanup"] for i in items):
            try:
                need(H.identity(owner) == owner_id and not H.inventory(owner), "cleanup_failed")
                prior = group["checks"]["all_processes_reaped"]
                group["checks"]["all_processes_reaped"] = False
                H.prepare(suite, owner.name, "Verify")
                group["checks"]["all_processes_reaped"] = prior
                H.remove_owned(owner, owner_id)
                group["checks"]["temp_cleanup"] = True
            except BaseException:
                errors.append("cleanup_failed")
        if not closed or not group["checks"]["temp_cleanup"]:
            errors.append("cleanup_failed")
        success = len(items) == 3 and all(group["checks"].values()) and not errors and all(
            i["record"]["failure_code"] is None and all(v for k, v in i["record"]["checks"].items() if k != "group_finalized") for i in items)
        if success:
            group["status"] = "passed"
            for item in items:
                item["record"]["status"] = "passed"
                item["record"]["checks"]["group_finalized"] = True
        else:
            mark(group, group["failure_code"] or "group_failed", errors)
            for item in items:
                mark(item["record"], item["record"]["failure_code"] or "group_failed", errors)
    return items, group, closed


def run(application, application_sha, commit, rclone):
    H.hosted_guard()
    application, rclone = Path(application).absolute(), Path(rclone).absolute()
    runtime, bound = E.runtime_binding(ROOT), E.compute_bindings(ROOT, application, commit)
    cases, group, errors = E.empty_cases(), E.empty_group(), []
    suite = suite_id = None
    clean = setup_clean = False
    try:
        need(bound["application_sha256"] == application_sha and os.environ.get("GITHUB_SHA") == commit and bindings(application, commit) == bound, "binding_failed")
        parent = Path(os.environ["RUNNER_TEMP"]).absolute()
        suite = parent / ("app-ftp-" + uuid.uuid4().hex)
        H.prepare(parent, suite.name)
        suite_id = H.identity(suite)
        secret, setup_clean = credentials(suite, rclone, runtime, errors)
        need(secret is not None and setup_clean, "case_setup_failed")
        items, group, _ = exercise(suite, application, application_sha, runtime, secret, errors)
        for item in items:
            cases[item["name"]] = item["record"]
    except BaseException as error:
        errors.append(failure(error))
    finally:
        try:
            need(bindings(application, commit) == bound and E.runtime_binding(ROOT) == runtime, "preservation_failed")
        except BaseException:
            errors.append("preservation_failed")
        if suite_id is not None:
            try:
                need(setup_clean and group["checks"]["temp_cleanup"] is True and not H.inventory(suite), "cleanup_failed")
                prior = group["checks"]["all_processes_reaped"]
                group["checks"]["all_processes_reaped"] = False
                H.prepare(suite.parent, suite.name, "Verify")
                group["checks"]["all_processes_reaped"] = prior
                H.remove_owned(suite, suite_id)
                clean = True
            except BaseException:
                errors.append("cleanup_failed")
        elif suite is None:
            clean = True
        else:
            errors.append("cleanup_failed")
    errors = list(dict.fromkeys(errors))
    if errors and group["status"] == "passed":
        mark(group, "group_failed", errors)
        for r in cases.values():
            mark(r, "group_failed", errors)
            r["checks"]["group_finalized"] = False
    receipt = dict(schema_version=1, scope=E.SCOPE, fixture_mode=E.MODE, backend="ftp", platform="windows",
        created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), runtime=runtime, bindings=bound, cases=cases,
        credential_group=group, claims=dict.fromkeys(E.FALSE_CLAIMS, False), cleanup_complete=clean, errors=errors,
        capabilities=E.derive_capabilities(cases, clean), result="passed" if clean and not errors and group["status"] == "passed" else "failed")
    E.validate_receipt(receipt, runtime, bound)
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser()
    for flag in ("application", "application-sha256", "build-commit", "rclone", "report"):
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
        receipt = run(args.application, args.application_sha256, args.build_commit, args.rclone)
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
