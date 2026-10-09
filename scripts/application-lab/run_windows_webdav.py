#!/usr/bin/env python3
"""Hosted-only configured Basic WebDAV application experiment.

No process or listener starts on import. Synthetic credentials stay in owned
private files/pipes; only the closed observation contract is published.
"""
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
import subprocess
import threading
import time
import types
import uuid

HERE = Path(__file__).absolute().parent
ROOT = HERE.parent.parent


def _load(name, path):
    data = path.read_bytes()
    if not 0 < len(data) <= 512 * 1024:
        raise ValueError("binding_failed")
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(data, str(path), "exec"), module.__dict__)
    module.loaded_source_sha256 = hashlib.sha256(data).hexdigest()
    return module


H = _load("webdav_owned_http_supervisor", HERE / "run_windows_http.py")
E = _load("webdav_owned_contract", HERE.parent / "webdav_application_evidence.py")
F = _load("webdav_owned_fixture", HERE / "fixture_webdav.py")
SELF_SHA256 = H.sha(H.read(Path(__file__), 512 * 1024))
need, ProducerError = H.need, H.ProducerError
GROUP = ("accepted_a", "revoked_a", "replacement_b")
READS = frozenset({"acquisition", "accepted_a", "replacement_b"})
DENIED = frozenset({"wrong_credentials", "revoked_a"})
CASE_SECONDS = 120
SETUP_SECONDS = 20
NOTICE = r"\d{4}/\d\d/\d\d \d\d:\d\d:\d\d NOTICE: Failed to rc: "


def bindings(application, build_commit):
    H.loaded_sources_preserved()
    for module, path in ((H, HERE / "run_windows_http.py"), (E, HERE.parent / "webdav_application_evidence.py"),
                         (F, HERE / "fixture_webdav.py")):
        need(H.sha(H.read(path, 512 * 1024)) == module.loaded_source_sha256, "preservation_failed")
    need(H.sha(H.read(HERE / "fixture_http.py", 512 * 1024)) == F.loaded_http_source_sha256 and
         H.sha(H.read(HERE.parent / "application_evidence.py", 512 * 1024)) == E._BASE_SHA256 and
         H.sha(H.read(Path(__file__), 512 * 1024)) == SELF_SHA256, "preservation_failed")
    return E.compute_bindings(ROOT, application, build_commit)


def payloads():
    values = {"README-synthetic.txt": b"synthetic application fixture\n", "nested/binary.bin": bytes(range(256)),
              "nested/spaced name.txt": b"spaces remain exact\n", "large/cancel.bin": bytes(range(256)) * 8192}
    need([(p, len(values[p]), H.sha(values[p])) for p in sorted(values)] ==
         [(r["path"], r["size"], r["sha256"]) for r in E.fixture_manifest()["files"]], "binding_failed")
    return values


def failure(error):
    return str(error) if isinstance(error, ProducerError) and str(error) in E.FAILURE_CODES else "unexpected_failure"


def mark(record, code, errors):
    record["status"] = "failed"
    record["failure_code"] = record["failure_code"] or code
    if code not in errors:
        errors.append(code)


def active_record(name):
    return {"status": "failed", "exit_code": None, "runtime_sha256": None, "failure_code": None,
            "checks": dict.fromkeys(E.INVOCATION_CHECKS[name], False)}


def config_bytes(endpoint, user, password):
    need(re.fullmatch(r"http://127\.0\.0\.1:[1-9][0-9]{0,4}/", endpoint) is not None and
         1 <= int(endpoint.split(":")[-1][:-1]) <= 65535 and re.fullmatch(r"[0-9a-f]{64}", user) is not None and
         re.fullmatch(r"[A-Za-z0-9_-]{107}", password) is not None, "authority_failed")
    return ("[Synthetic]\ntype = webdav\nurl = " + endpoint + "\nvendor = other\nuser = " + user +
            "\npass = " + password + "\nauth_redirect = false\n").encode("ascii")


def obscure_once(executable, case, plaintext, expected_sha):
    """Own one pipe-only setup process; return no output on uncertain cleanup."""
    need(re.fullmatch(r"[0-9a-f]{64}", plaintext) is not None and
         H.sha(H.read(executable, 128 * 1024 * 1024)) == expected_sha, "binding_failed")
    process, threads, outputs = None, [], [bytearray(), bytearray()]
    bad = threading.Event()
    stopped = False
    error = None
    def drain(stream, output):
        try:
            while True:
                data = stream.read(1024)
                if not data:
                    break
                if len(output) + len(data) > 4096:
                    bad.set()
                    break
                output.extend(data)
        except BaseException:
            bad.set()
    def write_input():
        try:
            process.stdin.write(plaintext.encode("ascii") + b"\n")
            process.stdin.flush()
            process.stdin.close()
        except BaseException:
            bad.set()
    try:
        process = subprocess.Popen([str(executable), "obscure", "-", "--config", str(case / "source.conf")],
            cwd=case, env=H.environment(case), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            **H.hidden(), close_fds=True)
        for target, args in ((drain, (process.stdout, outputs[0])), (drain, (process.stderr, outputs[1])),
                             (write_input, ())):
            thread = threading.Thread(target=target, args=args, daemon=True)
            threads.append(thread)
            thread.start()
        deadline = time.monotonic() + SETUP_SECONDS
        while process.poll() is None:
            need(not bad.is_set() and time.monotonic() < deadline, "case_setup_failed")
            time.sleep(0.02)
        need(process.returncode == 0, "case_setup_failed")
    except BaseException as caught:
        error = caught
    finally:
        if process is not None:
            try:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
                for thread in threads:
                    if thread.ident is not None:
                        thread.join(timeout=2)
                stopped = process.poll() is not None and all(not thread.is_alive() for thread in threads)
                if stopped:
                    for stream in (process.stdin, process.stdout, process.stderr):
                        stream.close()
            except BaseException:
                stopped = False
    if not stopped:
        # Includes Popen raising after a possibly partial native launch.
        raise ProducerError("cleanup_failed") from None
    if error is not None:
        raise ProducerError(failure(error)) from None
    need(not bad.is_set() and not outputs[1] and
         re.fullmatch(rb"[A-Za-z0-9_-]{107}\r?\n", outputs[0]) is not None, "case_setup_failed")
    token = bytes(outputs[0]).rstrip(b"\r\n").decode("ascii")
    decoded = base64.urlsafe_b64decode(token + "=")
    need(len(decoded) == 80 and base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") == token and
         H.sha(H.read(executable, 128 * 1024 * 1024)) == expected_sha, "preservation_failed")
    return token


def credentials(suite, runtime_path, runtime, errors):
    """Auxiliary setup is never an application invocation or authentication credit."""
    case = suite / "webdav-credential-setup"
    lease = roots = baseline = None
    safe = True
    clean = False
    result = None
    try:
        H.prepare(suite, case.name)
        lease = H.identity(case)
        roots = H.create_private_roots(case)
        baseline = H.helper_baseline(case, roots)
        data = H.read(runtime_path, 128 * 1024 * 1024, allow_hardlinks=True)
        need(H.sha(data) == runtime["sha256"], "binding_failed")
        H.private_write(case, "application.exe", data)
        H.private_write(case, "source.conf", b"")
        user, password_a, wrong, password_b = (secrets.token_hex(32) for _ in range(4))
        need(len({password_a, wrong, password_b}) == 3, "case_setup_failed")
        tokens = []
        for password in (password_a, wrong, password_b):
            safe = False
            tokens.append(obscure_once(case / "application.exe", case, password, runtime["sha256"]))
            safe = True
        result = (user, password_a, wrong, password_b, *tokens)
    except BaseException as error:
        errors.append(failure(error))
    finally:
        if lease is not None and safe and roots is not None and baseline is not None:
            try:
                need(H.identity(case) == lease and H.read(case / "source.conf", 8192) == b"" and
                     H.sha(H.read(case / "application.exe", 128 * 1024 * 1024)) == runtime["sha256"] and
                     H.sha(H.read(runtime_path, 128 * 1024 * 1024, allow_hardlinks=True)) == runtime["sha256"], "preservation_failed")
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


def listing(case):
    path = case / "output" / H.CASE_NAME / "listings" / "inventory.csv"
    data = H.read(path, 65536)
    need(data.startswith(b"\xef\xbb\xbf"), "listing_invalid")
    try:
        rows = list(csv.reader(io.StringIO(data.decode("utf-8-sig"), newline=""), strict=True))
    except (UnicodeError, csv.Error):
        raise ProducerError("listing_invalid") from None
    expected = [["excel-safe-v1", "Synthetic", p, str(n), H.MODIFIED, "false", "", ""] for p, n, _ in H.ROWS]
    expected += [["excel-safe-v1", "Synthetic", p, "", H.MODIFIED, "true", "", ""] for p in ("large", "nested")]
    need(rows and rows[0] == H.HEADERS and sorted(rows[1:]) == sorted(expected), "listing_invalid")
    output_inventory("listing", case)
    return {"inventory_exact": True, "listing_complete": True}


def output_inventory(name, case, manifest_name=None):
    base = case / "output" / H.CASE_NAME
    entries = H.inventory(base)
    files = {p for p, v in entries.items() if not v[0]}
    config = {p for p in files if p.startswith("config/")}
    need(len(config) == 2, "outputs_invalid")
    allowed = set(config)
    if name == "listing":
        allowed.add("listings/inventory.csv")
    else:
        stem = manifest_name.removesuffix(".json")
        allowed.update({manifest_name, stem + ".txt", "logs/" + stem + ".log", "logs/" + stem + ".checkpoint.json"})
        if name in READS or name == "mismatch":
            allowed.update("downloads/Synthetic/" + p for p, _, _ in H.queue_rows(name))
    need(files == allowed, "outputs_invalid")
    required = {"logs", "downloads", "listings", "config"}
    permitted = set(required)
    for path, _, _ in ([] if name == "listing" else H.queue_rows(name)):
        parts = ("downloads/Synthetic/" + path).split("/")
        permitted.update("/".join(parts[:i]) for i in range(1, len(parts)))
    need(required <= {p for p, v in entries.items() if v[0]} <= permitted and
         set(H.inventory(case / "output")) == {H.CASE_NAME} | {H.CASE_NAME + "/" + p for p in entries}, "outputs_invalid")


def exact_rc_error(value, cause, *, stat=False):
    # Pinned cmd/rc errorf/doCall + cmd.Run. No raw diagnostic is published.
    if type(value) is not str or not 0 < len(value) <= 65536 or "\x00" in value or "\r" in value:
        return False
    if stat:
        if not value.startswith("Cannot stat source: "):
            return False
        value = value[len("Cannot stat source: "):]
    lines = value.rstrip("\n").split("\n")
    expected = NOTICE + re.escape("loopback: call failed: " + cause)
    return len(lines) <= 128 and re.fullmatch(expected, lines[-1]) is not None and sum(
        "NOTICE: Failed to rc:" in line for line in lines) == 1


def manifest(name, case, config, runtime):
    base = case / "output" / H.CASE_NAME
    names = [p for p, v in H.inventory(base).items() if not v[0] and re.fullmatch(r"acquisition-[0-9T.]+\.json", p)]
    need(len(names) == 1, "manifest_invalid")
    value = H.strict_json(H.read(base / names[0]))
    need(type(value) is dict and set(value) == {"schema_version", "written_at", "rclone_version", "config_path", "plan", "results", "complete"}
         and type(value["schema_version"]) is int and value["schema_version"] == 1 and H.valid_time(value["written_at"])
         and value["rclone_version"] == runtime["version"] and H.same_path(value["config_path"], config)
         and type(value["complete"]) is bool and value["complete"] is (name in READS), "manifest_invalid")
    plan, rows, results = value["plan"], H.queue_rows(name), value["results"]
    need(type(plan) is dict and set(plan) == {"files", "skipped_directories"} and
         type(plan["skipped_directories"]) is int and plan["skipped_directories"] == 0 and type(plan["files"]) is list
         and type(results) is list and len(plan["files"]) == len(results) == len(rows), "manifest_invalid")
    for planned, result, (path, size, digest) in zip(plan["files"], results, rows):
        destination = base / "downloads" / "Synthetic" / path
        need(type(planned) is dict and set(planned) == {"remote_name", "path", "request"} and
             planned["remote_name"] == "Synthetic" and planned["path"] == path, "manifest_invalid")
        request = planned["request"]
        need(type(request) is dict and set(request) == {"source", "destination", "mode", "expected_hash", "expected_hash_type", "expected_size"}
             and request["source"] == "Synthetic:" + path and H.same_path(request["destination"], destination)
             and request["mode"] == "CopyTo" and request["expected_hash"] == digest and request["expected_hash_type"] == "sha256"
             and type(request["expected_size"]) is int and request["expected_size"] == size, "manifest_invalid")
        need(type(result) is dict and set(result) == {"local_sha256", "integrity", "source", "destination", "success", "error", "size", "hash", "hash_type", "hash_verified", "hash_error"}
             and type(result["success"]) is bool and result["source"] == "Synthetic:" + path and
             H.same_path(result["destination"], destination), "manifest_invalid")
        if name in READS or name == "mismatch":
            actual = next(row[2] for row in H.ROWS if row[0] == path)
            good = name in READS
            expected = dict(local_sha256=actual, integrity="Verified" if good else "Mismatch", source="Synthetic:" + path,
                destination=result["destination"], success=good, error=None if good else "Downloaded bytes do not match the expected source hash",
                size=size, hash=actual, hash_type="sha256", hash_verified=good, hash_error=None)
            need(result == expected and type(result["size"]) is int and type(result["hash_verified"]) is bool, "manifest_invalid")
            data = H.read(destination)
            need(len(data) == size and H.sha(data) == actual, "outputs_invalid")
        else:
            need(result["success"] is False and result["integrity"] == ("Cancelled" if name == "cancellation" else "Failed")
                 and all(result[k] is None for k in ("local_sha256", "size", "hash", "hash_type", "hash_verified", "hash_error"))
                 and type(result["error"]) is str and 0 < len(result["error"]) <= 65536, "manifest_invalid")
            error = result["error"]
            if name == "missing":
                need(error == "Source was not found or is not an individual file: Synthetic:missing-synthetic.txt", "manifest_invalid")
            elif name in DENIED or name == "permission_denied":
                status = "401 Unauthorized" if name in DENIED else "403 Forbidden"
                need(exact_rc_error(error, "read metadata failed: " + status, stat=True), "denial_failed")
            elif name == "truncated_transfer":
                # ReOpen.Read may return the original truncated-body error, or
                # its stored reopen-limit error on a later Read. Both are fixed
                # pinned-source causes; neither alone proves fixture behavior.
                need(any(exact_rc_error(error, cause) for cause in
                         ("unexpected EOF", "failed to reopen: too many retries")), "truncation_failed")
            elif name == "cancellation":
                need("transfer staging cleanup failed:" not in error, "cleanup_failed")
    wanted = {"Synthetic/" + p for p, _, _ in rows} if name in READS or name == "mismatch" else set()
    need(set(H.output_files(base / "downloads")) == wanted, "outputs_invalid")
    output_inventory(name, case, names[0])
    if name in READS:
        return dict.fromkeys(("manifest_complete", "manifest_exact", "output_hashes_exact", "outputs_exact"), True)
    common = {"manifest_incomplete": True}
    if name == "mismatch":
        common.update(mismatch_exact=True, retained_bytes_exact=True, outputs_exact=True)
    else:
        common["no_download_outputs"] = True
        common[{"missing": "missing_failure_exact", "cancellation": "cancelled_result_exact"}.get(name, "failed_result_exact")] = True
        if name in {"cancellation", "truncated_transfer"}:
            common["no_partial_outputs"] = True
    return common


def fingerprint(case):
    root = case / "output"
    before = H.inventory(root)
    rows = [(p, value[0], value[1], None if value[0] else H.sha(H.read(root / p))) for p, value in sorted(before.items())]
    need(H.inventory(root) == before, "preservation_failed")
    return H.sha(E.compact(rows))


def fixture_checks(name, snapshot, epoch):
    need(snapshot["errors"] == [] and snapshot["transition_failed"] is False and snapshot["source_preserved"] is True and
         snapshot["transport_attempted"] is True and snapshot["active_requests"] == 0 and
         type(snapshot["total_requests"]) is int and 0 < snapshot["total_requests"] <= 128, "fixture_failed")
    views = [*snapshot["history"], snapshot]
    rows = [v for v in views if v["epoch"] == epoch and v["invocation"] == name]
    need(len(rows) == 1, "fixture_failed")
    row = rows[0]
    need(all(type(row[k]) is int and 0 <= row[k] <= 32 * 1024 * 1024 for k in F.COUNTERS) and
         0 < row["requests"] <= 128 and row["requests"] == row["credential_attempts"] == row["authenticated"] + row["auth_denied"]
         and row["requests"] == row["propfinds"] + row["gets"] + row["auth_denied"] + row["missing"] + row["permission_denied"]
         and row["rejected"] == 0 and
         row["observation_started"] is True and row["observation_released"] is True, "fixture_failed")
    events = snapshot["events"]
    need(type(events) is list and len(events) <= 512 and all(type(e) is list and len(e) == 3 and
         type(e[0]) is int and 1 <= e[0] <= 3 and e[1] in F.EVENTS and type(e[2]) is int and 0 <= e[2] < 8 for e in events), "fixture_failed")
    selected = [(e[1], e[2]) for e in events if e[0] == epoch]
    need(sum(label == "observation" for label, _ in selected) == 1 and selected[0][0] == "observation" and
         sum(label == "basic_accepted" for label, _ in selected) == row["authenticated"] and
         sum(label == "basic_denied" for label, _ in selected) == row["auth_denied"], "fixture_failed")
    checks = dict(fixture_valid=True, source_preserved=True, authority_exact=True, request_credentials_exact=True)
    if name in DENIED:
        need(row["auth_denied"] > 0 and row["authenticated"] == row["gets"] == row["payload_bytes"] == 0 and
             set(label for label, _ in selected) == {"observation", "basic_denied"} and all(member == 1 for _, member in selected), "denial_failed")
        checks.update(credential_denial_observed=True, no_payload_served=True, no_authority_fallback=True)
    else:
        need(row["authenticated"] > 0 and row["auth_denied"] == 0, "fixture_failed")
        checks["basic_auth_observed"] = True
        if name == "listing":
            need(row["gets"] == row["payload_bytes"] == 0 and {member for label, member in selected if label == "directory"} == {0, 5, 6}, "fixture_failed")
        elif name in READS or name == "mismatch":
            members = {1, 2, 3, 4} if name == "acquisition" else {1}
            need({member for label, member in selected if label == "content"} == members and
                 row["gets"] == len(members) and row["ranges"] == 0 and
                 row["completed_payload_bytes"] == row["payload_bytes"] == sum(n for _, n, _ in H.queue_rows(name)), "fixture_failed")
        elif name in {"missing", "permission_denied"}:
            label, member = ("missing", 7) if name == "missing" else ("permission_denied", 1)
            need(row[label] > 0 and (label, member) in selected and row["gets"] == row["payload_bytes"] == 0, "denial_failed")
            checks["not_found_observed" if name == "missing" else "permission_denial_observed"] = True
            if name == "permission_denied":
                checks["no_payload_served"] = True
        elif name == "truncated_transfer":
            need(0 < row["truncated"] == row["gets"] <= 100 and row["completed_payload_bytes"] == 0 and
                 0 < row["payload_bytes"] < 30 * row["gets"] and ("truncated", 1) in selected, "truncation_failed")
            checks["truncation_observed"] = True
        else:
            need(row["gets"] == 1 and row["ranges"] == 0 and row["payload_bytes"] == 65536 and
                 row["completed_payload_bytes"] == 0 and row["cancel_started"] is True and row["cancel_disconnected"] is True
                 and ("cancel_prefix", 2) in selected and ("cancel_disconnected", 2) in selected, "cancellation_failed")
            checks["client_disconnect_observed"] = True
    return checks


def idle(server, deadline):
    while True:
        need(time.monotonic() < deadline, "deadline_exceeded")
        snapshot = server.snapshot()
        if snapshot["active_requests"] == 0 and snapshot["transport"]["active"] == 0:
            return snapshot
        time.sleep(0.02)


def execute(name, owner, application, app_sha, runtime, server, state, config, errors):
    """Reap one application; retain its case for final fixture/group preservation."""
    record = active_record(name)
    item = dict(name=name, record=record, case=owner / H.WEBDAV_CASE_NAMES[name], lease=None, roots=None,
                baseline=None, config=config, artifact=None, epoch=state.epoch, prepared=False, session_attempted=False)
    case, checks, bridge = item["case"], record["checks"], None
    try:
        H.prepare(owner, case.name)
        item["prepared"] = True
        item["lease"] = H.identity(case)
        item["roots"] = H.create_private_roots(case)
        H.private_directory(case, "output")
        data = H.read(application, 512 * 1024 * 1024, allow_hardlinks=True)
        need(H.sha(data) == app_sha, "binding_failed")
        H.private_write(case, "application.exe", data)
        H.private_write(case, "source.conf", config)
        if name != "listing":
            H.private_write(case, "queue.csv", H.queue_bytes(name))
        deadline = min(time.monotonic() + CASE_SECONDS, server.deadline)
        item["session_attempted"] = True
        bridge = H.Bridge(case)
        H.validate_ready(bridge.command("ready"))
        H.application_roots_empty(case, item["roots"])
        item["baseline"] = H.helper_baseline(case, item["roots"])
        limit = 4 if name == "acquisition" else 1
        need(time.monotonic() < deadline, "deadline_exceeded")
        response = bridge.command("start", app_path=str(case / "application.exe"), app_sha256=app_sha,
            args=H.app_args(name, case), case_root=str(case), environment=H.environment(case),
            transcript_path=str(case / "transcript.private"), max_output_bytes=8 * 1024 * 1024,
            deadline_ms=max(1, min(150000, int((deadline - time.monotonic()) * 1000))), max_runtime_processes=limit)
        while not state.observation_started.wait(0.05):
            need(time.monotonic() < deadline, "deadline_exceeded")
            response = bridge.command("poll")
            need(response["ok"] and not response["app_exited"], "runtime_unobserved")
        need(time.monotonic() < deadline, "deadline_exceeded")
        response = bridge.command("observe_runtime", extraction_root=str(case / "temp"), expected_sha256=runtime["sha256"])
        need(time.monotonic() < deadline, "deadline_exceeded")
        need(response["ok"] and response["runtime_image_observed"] and response["runtime_sha256"] == runtime["sha256"] and
             type(response["runtime_process_count"]) is int and 1 <= response["runtime_process_count"] <= limit, "runtime_unobserved")
        checks["runtime_observed"], record["runtime_sha256"] = True, runtime["sha256"]
        state.release_observation()
        if name == "cancellation":
            while not (state.cancel_started.is_set() and H.partial_active(case, item["lease"])):
                need(time.monotonic() < deadline, "deadline_exceeded")
                response = bridge.command("poll")
                need(response["ok"] and not response["app_exited"], "cancellation_failed")
                time.sleep(0.05)
            checks["transfer_active"] = True
            response = bridge.command("ctrl_c")
            need(time.monotonic() < deadline, "deadline_exceeded")
            checks["ctrl_c_sent"] = response["ok"] and response["ctrl_c_sent"]
            need(checks["ctrl_c_sent"], "cancellation_failed")
        while not response["app_exited"]:
            need(time.monotonic() < deadline, "deadline_exceeded")
            response = bridge.command("poll")
            need(response["ok"], "session_failed")
            time.sleep(0.05)
        if response["state"] != "finished":
            response = bridge.command("finish", grace_ms=15000)
        bridge.last = response
        record["exit_code"] = response["app_exit_code"]
        need(time.monotonic() < deadline, "deadline_exceeded")
        need(response["state"] == "finished" and response["ok"] and not response["forced_termination"] and
             response["runtime_image_observed"] and response["runtime_sha256"] == runtime["sha256"], "session_failed")
        checks["orderly_exit"] = all(response[k] for k in H.SESSION_CLEANUP)
        positive = name in E.POSITIVE_INVOCATIONS
        checks["exit_success" if positive else "exit_failure"] = type(record["exit_code"]) is int and (
            record["exit_code"] == 0 if positive else record["exit_code"] != 0)
        need(checks["orderly_exit"] and checks["exit_success" if positive else "exit_failure"], "session_failed")
        working = H.configuration_preserved(case, config)
        checks["configuration_preserved"] = True
        checks.update(listing(case) if name == "listing" else manifest(name, case, working, runtime))
        item["artifact"] = fingerprint(case)
    except BaseException as error:
        mark(record, failure(error), errors)
    finally:
        if bridge is not None:
            try:
                closed = bridge.close()
                final = bridge.last
                checks["process_cleanup"] = bool(closed and final and final["state"] == "finished" and
                                                  all(final[k] for k in H.SESSION_CLEANUP))
                if final and record["exit_code"] is None:
                    record["exit_code"] = final["app_exit_code"]
            except BaseException:
                mark(record, "cleanup_failed", errors)
        else:
            checks["process_cleanup"] = item["prepared"] and not item["session_attempted"]
        if not checks["process_cleanup"]:
            mark(record, "cleanup_failed", errors)
    if record["failure_code"] is None:
        try:
            checks.update(fixture_checks(name, idle(server, min(time.monotonic() + 5, server.deadline)), item["epoch"]))
        except BaseException as error:
            mark(record, failure(error), errors)
    return item


def preserved(item, app_sha):
    case = item["case"]
    need(H.identity(case) == item["lease"], "preservation_failed")
    need(H.sha(H.read(case / "application.exe", 512 * 1024 * 1024)) == app_sha and
         H.read(case / "source.conf", 8192) == item["config"], "preservation_failed")
    if item["name"] != "listing":
        need(H.read(case / "queue.csv", 65536) == H.queue_bytes(item["name"]), "preservation_failed")
    if item["record"]["checks"]["configuration_preserved"]:
        H.configuration_preserved(case, item["config"])
    if item["artifact"] is not None:
        need(fingerprint(case) == item["artifact"], "preservation_failed")


def remove_case(item, app_sha, errors, *, group=None):
    record, checks = item["record"], item["record"]["checks"]
    if item["lease"] is None or not checks["process_cleanup"] or not checks["fixture_cleanup"]:
        mark(record, "cleanup_failed", errors)
        return
    try:
        preserved(item, app_sha)
        H.application_roots_empty(item["case"], item["roots"])
        H.helper_cleanup_preserved(H.helper_baseline(item["case"], item["roots"]), item["baseline"])
        # The verifier is another owned helper invocation; a thrown/partial
        # invocation cannot leave the earlier application reap as global proof.
        item["final_helper_reaped"] = False
        prior_group_reaped = group["checks"]["all_processes_reaped"] if group is not None else None
        if group is None:
            checks["process_cleanup"] = False
        else:
            group["checks"]["all_processes_reaped"] = False
        H.prepare(item["case"].parent, item["case"].name, "Verify")
        item["final_helper_reaped"] = True
        if group is None:
            checks["process_cleanup"] = True
        else:
            group["checks"]["all_processes_reaped"] = prior_group_reaped
        H.remove_owned(item["case"], item["lease"])
        checks["temp_cleanup"] = True
    except BaseException:
        mark(record, "cleanup_failed", errors)


def finish_record(record, errors):
    if record["failure_code"] is None and all(record["checks"].values()):
        record["status"] = "passed"
    elif record["failure_code"] is None:
        mark(record, "fixture_failed", errors)


def fixture_closed(server):
    if server is None or server.cleanup_complete is not True:
        return False
    snap = server.snapshot()
    transport = snap["transport"]
    return (snap["active_requests"] == 0 and transport["active"] == transport["workers_alive"] == 0 and
            transport["watchdog_alive"] is False and transport["acceptor_alive"] is False and transport["cleanup_complete"] is True)


def exercise(names, suite, application, app_sha, runtime, secret, errors):
    """A standalone fixture or the exact three-invocation credential group."""
    grouped = names == GROUP
    owner, owner_id = suite, None
    group = {"status": "failed", "failure_code": None, "checks": dict.fromkeys(E.GROUP_CHECKS, False)} if grouped else None
    state = context = server = None
    entered = attempted = False
    items = []
    try:
        if grouped:
            owner = suite / "webdav-credentials"
            H.prepare(suite, owner.name)
            owner_id = H.identity(owner)
        user, password_a, wrong, password_b, token_a, token_wrong, token_b = secret
        state = F.AppWebDavState(payloads(), names[0], user, password_a, wrong_password=wrong, password_b=password_b)
        context = F.serve_webdav(state)
        attempted = True
        server = context.__enter__()
        entered = True
        deadline, endpoint = server.deadline, server.endpoint
        for index, name in enumerate(names):
            need(server.deadline == deadline and server.endpoint == endpoint and time.monotonic() < deadline, "credential_transition_failed")
            token = token_wrong if name == "wrong_credentials" else token_b if name == "replacement_b" else token_a
            item = execute(name, owner, application, app_sha, runtime, server, state, config_bytes(endpoint, user, token), errors)
            items.append(item)
            need(item["record"]["failure_code"] is None, item["record"]["failure_code"] or "session_failed")
            if name == "revoked_a":
                need(item["config"] == items[0]["config"], "preservation_failed")
                item["record"]["checks"]["same_config_as_accepted"] = True
            if name == "replacement_b":
                need(item["config"] != items[0]["config"] and item["config"].replace(token_b.encode(), token_a.encode()) == items[0]["config"], "preservation_failed")
                item["record"]["checks"]["credential_changed"] = True
            if index + 1 < len(names):
                idle(server, min(time.monotonic() + 5, deadline))
                state.advance_epoch(names[index + 1], successful=True, reaped=item["record"]["checks"]["process_cleanup"])
        if grouped:
            need(len(items) == 3 and server.deadline == deadline and server.endpoint == endpoint and
                 [v["invocation"] for v in server.snapshot()["history"]] == ["accepted_a", "revoked_a"], "credential_transition_failed")
            group["checks"].update(dict.fromkeys(("same_fixture_authority", "epoch_ordered", "transitions_reaped", "deadline_preserved",
                "revocation_observed", "replacement_observed"), True))
    except BaseException as error:
        code = failure(error)
        if grouped:
            mark(group, code, errors)
        elif items:
            mark(items[-1]["record"], code, errors)
        else:
            errors.append(code)
    finally:
        closed = not attempted
        if entered:
            try:
                context.__exit__(None, None, None)
                closed = fixture_closed(server)
            except BaseException:
                closed = False
        if not closed:
            errors.append("cleanup_failed")
        final_ok = True
        for item in items:
            item["record"]["checks"]["fixture_cleanup"] = closed
            try:
                preserved(item, app_sha)
                item["record"]["checks"]["source_preserved"] = state.source_preserved()
                if item["record"]["failure_code"] is None:
                    item["record"]["checks"].update(fixture_checks(item["name"], server.snapshot(), item["epoch"]))
            except BaseException as error:
                final_ok = False
                mark(item["record"], failure(error), errors)
        if grouped:
            group["checks"]["fixture_cleanup"] = closed
            group["checks"]["all_processes_reaped"] = owner_id is not None and all(i["record"]["checks"]["process_cleanup"] for i in items)
            if len(items) == 3 and final_ok:
                group["checks"].update(config_a_preserved=True, accepted_a_preserved=True, no_credential_poisoning=True)
            # Check every retained output before the first case can be removed.
            for item in items:
                if closed and final_ok:
                    remove_case(item, app_sha, errors, group=group)
                    if not item["record"]["checks"]["temp_cleanup"]:
                        final_ok = False
                        break
            group_temp = False
            if owner_id is not None and closed and final_ok and all(i["record"]["checks"]["temp_cleanup"] for i in items):
                try:
                    need(not H.inventory(owner) and H.identity(owner) == owner_id, "cleanup_failed")
                    prior_group_reaped = group["checks"]["all_processes_reaped"]
                    group["checks"]["all_processes_reaped"] = False
                    H.prepare(suite, owner.name, "Verify")
                    group["checks"]["all_processes_reaped"] = prior_group_reaped
                    H.remove_owned(owner, owner_id)
                    group_temp = True
                except BaseException:
                    errors.append("cleanup_failed")
            group["checks"]["all_processes_reaped"] = group["checks"]["all_processes_reaped"] and all(
                i["record"]["checks"]["process_cleanup"] and i.get("final_helper_reaped", True) for i in items)
            group["checks"]["temp_cleanup"] = group_temp
            good = len(items) == 3 and all(group["checks"].values()) and group["failure_code"] is None and all(
                i["record"]["failure_code"] is None for i in items)
            if good:
                group["status"] = "passed"
            else:
                mark(group, "group_failed", errors)
            for item in items:
                item["record"]["checks"].update(group_finalized=good, fixture_cleanup=closed, temp_cleanup=group_temp)
                if not good:
                    mark(item["record"], group["failure_code"], errors)
                finish_record(item["record"], errors)
        else:
            for item in items:
                if closed and final_ok:
                    remove_case(item, app_sha, errors)
                finish_record(item["record"], errors)
    return items, group, closed


def assign(cases, items):
    for item in items:
        for name, leaves in E.CASE_INVOCATIONS.items():
            if item["name"] in leaves:
                cases[name]["invocations"][item["name"]] = item["record"]
    for case in cases.values():
        records = list(case["invocations"].values())
        case["status"] = "passed" if all(r["status"] == "passed" for r in records) else "not_run" if all(
            r["status"] == "not_run" for r in records) else "failed"
        case["failure_code"] = next((r["failure_code"] for r in records if r["failure_code"]), None)


def run(application, application_sha, build_commit, rclone):
    H.hosted_guard()
    application, rclone = Path(application).absolute(), Path(rclone).absolute()
    runtime = E.runtime_binding(ROOT)
    # A source-current envelope lets a loaded-source mismatch publish an honest
    # all-not-run failure. Invalid/unreadable independent bindings cannot be invented.
    bound = E.compute_bindings(ROOT, application, build_commit)
    cases, group, errors = E.empty_cases(), E.empty_group(), []
    suite = suite_id = None
    clean = False
    setup_clean = False
    fixtures_closed = True
    try:
        need(bound["application_sha256"] == application_sha and os.environ.get("GITHUB_SHA") == build_commit and
             bindings(application, build_commit) == bound, "binding_failed")
        parent = Path(os.environ["RUNNER_TEMP"]).absolute()
        suite = parent / ("app-webdav-" + uuid.uuid4().hex)
        H.prepare(parent, suite.name)
        suite_id = H.identity(suite)
        secret, setup_clean = credentials(suite, rclone, runtime, errors)
        need(secret is not None and setup_clean, "case_setup_failed")
        for names in (("listing",), ("acquisition",), ("mismatch",), ("missing",), ("wrong_credentials",), GROUP,
                      ("permission_denied",), ("truncated_transfer",), ("cancellation",)):
            need(H.identity(suite) == suite_id, "preservation_failed")
            items, result_group, closed = exercise(names, suite, application, application_sha, runtime, secret, errors)
            fixtures_closed = fixtures_closed and closed
            assign(cases, items)
            if result_group is not None:
                group = result_group
            need(len(items) == len(names) and all(i["record"]["status"] == "passed" for i in items), "fixture_failed")
    except BaseException as error:
        errors.append(failure(error))
    finally:
        try:
            need(bindings(application, build_commit) == bound and E.runtime_binding(ROOT) == runtime, "preservation_failed")
        except BaseException:
            errors.append("preservation_failed")
        if suite_id is not None:
            try:
                need(setup_clean and fixtures_closed and all(r["status"] == "not_run" or all(r["checks"][k] for k in E.CLEANUP_CHECKS)
                     for c in cases.values() for r in c["invocations"].values()) and not H.inventory(suite), "cleanup_failed")
                H.prepare(suite.parent, suite.name, "Verify")
                H.remove_owned(suite, suite_id)
                clean = True
            except BaseException:
                errors.append("cleanup_failed")
        elif suite is None:
            clean = True
        else:
            errors.append("cleanup_failed")
    errors = list(dict.fromkeys(errors))
    receipt = dict(schema_version=1, scope=E.SCOPE, fixture_mode=E.MODE, backend="webdav", platform="windows",
        created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), runtime=runtime, bindings=bound,
        cases=cases, credential_group=group, claims=dict.fromkeys(E.FALSE_CLAIMS, False), cleanup_complete=clean,
        capabilities=E.derive_capabilities(cases, clean), errors=errors,
        result="passed" if clean and not errors and all(c["status"] == "passed" for c in cases.values()) else "failed")
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
        report = run(args.application, args.application_sha256, args.build_commit, args.rclone)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(E.compact(report) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        return 0 if report["result"] == "passed" else 1
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
