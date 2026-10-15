#!/usr/bin/env python3
"""Hosted-only two-invocation Swift replacement experiment; no work on import."""
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


H = load("swift_http_support", HERE / "run_windows_http.py")
W = load("swift_preservation_support", HERE / "run_windows_webdav.py")
C = load("swift_observer_transport", HERE / "filesystem_controller.py")
F = load("swift_fixture", HERE / "fixture_swift.py")
E = load("swift_contract", HERE.parent / "swift_application_evidence.py")
SELF_HASH = H.sha(H.read(Path(__file__), 512 * 1024))
need, ProducerError = H.need, H.ProducerError
CLEANUP_UNCERTAIN = frozenset({"termination_failed", "process_cleanup_failed", "input_cleanup_failed",
    "reader_cleanup_failed", "console_cleanup_failed", "console_cleanup_timeout", "source_directory_cleanup_failed",
    "debug_cleanup_failed", "source_directory_invalid"})
# Existing generic HTTP private-directory names; no shared allowlist changes.
CASE_DIRECTORIES = {"token_replacement": "acquisition", "renewal_denial": "denial"}


def bindings(application, commit):
    H.loaded_sources_preserved()
    W.bindings(application, commit)  # Includes W's loaded transitive dependencies.
    C.H.loaded_sources_preserved()
    for module in (H, W, C, C.H, F, E):
        need(H.sha(H.read(module.__file__, 512 * 1024)) == module.loaded_source_sha256, "preservation_failed")
    need(H.sha(H.read(Path(__file__), 512 * 1024)) == SELF_HASH, "preservation_failed")
    need(H.sha(H.read(F._PATH, 512 * 1024)) == F.loaded_http_source_sha256, "preservation_failed")
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
    writer.writerow(["excel-safe-v1", "Synthetic", f["member"], f["size"], "2024-01-01T00:00:00+00:00", "false", f["sha256"], "sha256"])
    return b"\xef\xbb\xbf" + stream.getvalue().encode("utf-8")


def config_bytes(endpoint, user, key):
    need(type(endpoint) is str and re.fullmatch(r"http://127\.0\.0\.1:[1-9][0-9]{0,4}/", endpoint) and
         1 <= int(endpoint.split(":")[-1][:-1]) <= 65535 and all(type(v) is str and re.fullmatch(r"[a-f0-9]{64}", v) for v in (user, key)), "binding_failed")
    return (f"[Synthetic]\ntype = swift\nenv_auth = false\nuser = {user}\nkey = {key}\nauth = {endpoint}auth/v1.0\nauth_version = 1\nendpoint_type = public\nno_large_objects = true\n").encode("ascii")


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


def continuity(bridge, state, server, deadline, runtime):
    proofs = {}
    gates = ("first_get", "replacement_get" if state.case == "token_replacement" else "renewal_auth")
    for gate in gates:
        while True:
            need(time.monotonic() < deadline and not state.errors, "continuity_failed")
            current = state.gate_snapshot()
            need(type(current) is dict and set(current) == set(F.GATES), "continuity_failed")
            if current[gate]["entered"] is not None:
                need(current[gate]["released"] is False, "continuity_failed")
                break
            response = bridge.command("poll")
            need(response["ok"] and response["state"] == "running" and not response["app_exited"], "continuity_failed")
            time.sleep(0.02)
        phases = ("arm",) if gate == "first_get" else ("verify",)
        for phase in phases:
            response = bridge.command("observe_continuity", phase=phase)
            need(time.monotonic() < deadline and response["ok"] and response["state"] == "running" and response["app_exited"] is False, "continuity_failed")
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
    positive = name == "token_replacement"
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
        cause = "failed to open source object: Operation forbidden"
        need(W.exact_rc_error(result["error"], cause), "denial_failed")
    wanted = {"Synthetic/" + f["member"]} if positive else set()
    need(set(H.output_files(base / "downloads")) == wanted, "outputs_invalid")
    files = {p for p, row in inventory.items() if not row[0]}
    config = {p for p in files if p.startswith("config/")}
    stem = names[0][:-5]
    allowed = config | {names[0], stem + ".txt", "logs/" + stem + ".log", "logs/" + stem + ".checkpoint.json"} | {"downloads/" + p for p in wanted}
    dirs = {p for p, row in inventory.items() if row[0]}
    need(len(config) == 2 and files == allowed and {"logs", "downloads", "listings", "config"} <= dirs <=
         {"logs", "downloads", "listings", "config", "downloads/Synthetic", "downloads/Synthetic/synthetic-bucket"} and
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
    try:
        value = server.transport_snapshot()
        return (type(value) is dict and set(value) == {"accepted", "active", "workers_alive", "watchdog_alive", "acceptor_alive", "cleanup_complete"} and
                all(type(value[k]) is int and 0 <= value[k] <= 128 for k in ("accepted", "active", "workers_alive")) and
                value["cleanup_complete"] is True and value["active"] == value["workers_alive"] == 0 and
                value["watchdog_alive"] is False and value["acceptor_alive"] is False)
    except BaseException:
        return False


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
        user, key = secrets.token_hex(32), secrets.token_hex(32)
        state = F.AppSwiftState(name, user, key)
        context = F.serve_swift(state)
        fixture_attempted = True
        server = context.__enter__()
        entered = True
        deadline = min(deadline, server.deadline)
        config = item["config"] = config_bytes(server.endpoint, user, key)
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
            deadline_ms=remaining, max_runtime_processes=1, expected_runtime_sha256=runtime["sha256"], max_runtime_launches=2)
        start_attempted = True  # A possibly issued start never uses ready-only cleanup.
        response = bridge.command("start_source_observed", **start_fields)
        need(response["ok"], "session_failed")
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
        positive = name == "token_replacement"
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
            try:
                record["fixture"] = state.snapshot()
                E.fixture_observation(record["fixture"], name, successful=True)
                checks.update(fixture_valid=True, source_preserved=True)
                checks.update(dict(token_replaced=True) if name == "token_replacement" else dict(renewal_denied=True, no_payload=True))
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
    receipt = dict(schema_version=1, scope=E.SCOPE, fixture_mode=E.MODE, backend="swift", platform="windows",
        created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), runtime=runtime, bindings=bound, cases=cases,
        experiment=group, lifecycle_scope="injected_storage_401_reauthentication", claims=dict.fromkeys(E.FALSE_CLAIMS, False), cleanup_complete=clean,
        errors=errors, capabilities=E.derive_capabilities(cases, clean), result="passed" if success else "failed")
    E.validate_receipt(receipt, runtime, bound)
    return receipt



def cancellation_bindings(application, commit):
    value = bindings(application, commit)  # Preserve all loaded-source checks.
    value["fixture_manifest_sha256"] = H.sha(E.compact(E.cancellation_manifest()))
    return value


def cancellation_partial(case, lease):
    need(H.identity(case) == lease, "preservation_failed")
    base = case / "output" / H.CASE_NAME / "downloads"
    if not base.exists():
        return None
    root = H.identity(base)
    entries = H.inventory(base)
    need(len(entries) <= 5, "cancellation_failed")
    chain = ["Synthetic", "Synthetic/synthetic-bucket", "Synthetic/synthetic-bucket/large"]
    stages = [n for n, r in entries.items() if r[0] and re.fullmatch(
        r"Synthetic/synthetic-bucket/large/\.triage-transfer-[0-9a-f]{32}", n)]
    leaves = [n for n, r in entries.items() if not r[0]]
    need(len(stages) <= 1 and len(leaves) <= 1 and
         all(n in chain or n in stages or n in leaves for n in entries) and
         all(entries[n][0] for n in chain if n in entries), "cancellation_failed")
    if not leaves:
        dirs = chain + stages
        need(set(entries) == set(dirs[:len(entries)]), "cancellation_failed")
        return None
    relative = leaves[0]
    need(len(stages) == 1 and re.fullmatch(re.escape(stages[0]) + r"/payload\.[0-9a-f]{8}\.partial", relative) and
         set(entries) == set(chain + stages + leaves) and H.identity(base) == root and H.identity(case) == lease,
         "cancellation_failed")
    return relative, entries[relative][2:4]


class CancellationWitness:
    def __init__(self, case, lease, selected, cleanup):
        self.case, self.lease, self.selected, self.cleanup = case, lease, selected, cleanup
        self.base = case / "output" / H.CASE_NAME / "downloads"
        self.path = self.base / selected[0]
        self.parents = [case / "output", self.base.parent, self.base, self.base / "Synthetic",
            self.base / "Synthetic/synthetic-bucket", self.base / "Synthetic/synthetic-bucket/large", self.path.parent]
        self.identities = [H.identity(q) for q in self.parents]
        self.close_attempted = False
        self.stream = self.path.open("rb", buffering=0)
        self.cleanup["closed"] = False
        try:
            self.verify()
        except BaseException:
            try:
                self.close()
            except BaseException:
                pass
            raise

    def verify(self):
        need(H.identity(self.case) == self.lease and [H.identity(q) for q in self.parents] == self.identities and
             cancellation_partial(self.case, self.lease) == self.selected, "preservation_failed")
        named, held = H.plain(self.path), os.fstat(self.stream.fileno())
        need(H.stat.S_ISREG(held.st_mode) and held.st_nlink == 1 and not getattr(held, "st_file_attributes", 0) & 0x400 and
             (held.st_dev, held.st_ino) == self.selected[1] == (named.st_dev, named.st_ino) and
             0 <= held.st_size <= 262144 and 0 <= named.st_size <= 262144, "preservation_failed")
        return max(held.st_size, named.st_size)

    def sample(self):
        before = self.verify()
        self.stream.seek(0)
        data = self.stream.read(196608)
        after = self.verify()
        if len(data) < min(max(before, after), 196608):
            return None
        block = bytes(range(256)) * 256
        matched = 0
        while data[matched:matched + 65536] == block:
            matched += 65536
            need(matched <= 131072, "cancellation_failed")
        return matched

    def close(self):
        if self.close_attempted:
            need(self.cleanup["closed"] and not self.cleanup["failed"], "cleanup_failed")
            return
        self.close_attempted = True
        try:
            self.stream.close()
            self.cleanup["closed"] = True
        except BaseException:
            self.cleanup["failed"] = True
            raise ProducerError("cleanup_failed") from None


def cancellation_running(value, action):
    C.validate_snapshot(value, action)
    need(value["ok"] and value["state"] == "running" and not value["app_exited"] and
         not value["forced_termination"] and not value["output_limit_exceeded"] and not value["ctrl_c_sent"], "cancellation_failed")


def cancellation_live(bridge, case, runtime, deadline):
    value = bridge.command("observe_runtime", extraction_root=str(case / "temp"), expected_sha256=runtime["sha256"])
    need(time.monotonic() < deadline, "deadline_exceeded")
    cancellation_running(value, "observe_runtime")
    need(value["runtime_image_observed"] and value["runtime_sha256"] == runtime["sha256"] and
         value["runtime_process_count"] == 1, "runtime_unobserved")


def cancellation_transfer(bridge, case, lease, runtime, state, deadline, cleanup):
    witness = None
    failed = False
    try:
        while witness is None:
            need(time.monotonic() < deadline, "deadline_exceeded")
            cancellation_running(bridge.command("poll"), "poll")
            need(time.monotonic() < deadline, "deadline_exceeded")
            selected = cancellation_partial(case, lease)
            if selected is not None:
                witness = CancellationWitness(case, lease, selected, cleanup)
            else:
                time.sleep(0.02)
        cancellation_live(bridge, case, runtime, deadline)
        for expected in (65536, 131072):
            while True:
                need(time.monotonic() < deadline, "deadline_exceeded")
                cancellation_running(bridge.command("poll"), "poll")
                need(time.monotonic() < deadline, "deadline_exceeded")
                matched = witness.sample()
                need(time.monotonic() < deadline, "deadline_exceeded")
                snapshot = state.snapshot()
                need(not snapshot["errors"], "fixture_failed")
                if matched is not None:
                    need(matched in ({0, 65536} if expected == 65536 else {65536, 131072}), "cancellation_failed")
                    # Peer bytes may reach disk before sendall returns. The
                    # independent byte witness remains necessary; gate release
                    # also waits for the original send's committed observation.
                    if matched == expected and state.cancel_snapshot()["chunks"] == expected // 65536:
                        break
                time.sleep(0.02)
            if expected == 65536:
                state.release_prefix()
                need(time.monotonic() < deadline, "deadline_exceeded")
        cancellation_live(bridge, case, runtime, deadline)
    except BaseException:
        failed = True
        raise
    finally:
        if witness is not None:
            try:
                witness.close()
            except BaseException:
                if not failed:
                    raise
    need(cleanup["closed"] and not cleanup["failed"] and time.monotonic() < deadline, "cancellation_failed")
    cancellation_running(bridge.command("poll"), "poll")
    need(time.monotonic() < deadline, "deadline_exceeded")
    state.arm_cancel()
    need(time.monotonic() < deadline, "deadline_exceeded")
    value = bridge.command("ctrl_c")  # Exactly one real owned-session signal attempt.
    need(time.monotonic() < deadline, "deadline_exceeded")
    C.validate_snapshot(value, "ctrl_c")
    need(value["ok"] and value["ctrl_c_sent"] and not value["forced_termination"] and not value["output_limit_exceeded"], "cancellation_failed")
    return dict(kind="live_image", runtime_process_count=1, first_verified_bytes=65536, last_verified_bytes=131072), value


def cancellation_final(value, runtime):
    C.validate_snapshot(value, value.get("action"))
    need(value["ok"] and value["state"] == "finished" and value["ctrl_c_sent"] and not value["forced_termination"] and
         not value["output_limit_exceeded"] and all(value[k] for k in H.SESSION_CLEANUP) and
         value["runtime_image_observed"] and value["runtime_sha256"] == runtime["sha256"] and
         value["runtime_process_count"] == 1, "session_failed")


def close_cancellation_session(bridge, ready, start_attempted):
    ready_proof = False
    try:
        if ready and not start_attempted:
            H.validate_close_ready(bridge.command("close_ready"))
            ready_proof = True
    finally:
        closed = bridge.close()
    if ready_proof:
        return closed is True
    if closed is not True or not isinstance(bridge.last, dict):
        return False
    value = C.validate_snapshot(bridge.last, bridge.last.get("action"))
    return (value["state"] == "finished" and not any(e in CLEANUP_UNCERTAIN for e in value["errors"]) and
            all(value[k] for k in H.SESSION_CLEANUP))


def cancellation_queue_bytes():
    f = E.cancellation_manifest()
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\r\n")
    writer.writerow(H.HEADERS)
    writer.writerow(["excel-safe-v1", "Synthetic", f["member"], f["size"], "2024-01-01T00:00:00+00:00", "false", f["sha256"], "sha256"])
    return b"\xef\xbb\xbf" + stream.getvalue().encode("utf-8")

def cancellation_preserved(item, app_sha, *, before_start=False):
    case = item["case"]
    need(H.identity(case) == item["lease"] and H.identity(case / "source") == item["source"] and not H.inventory(case / "source") and
         H.sha(H.read(case / "application.exe", 512 * 1024 * 1024)) == app_sha and
         H.read(case / "queue.csv", 8192) == cancellation_queue_bytes(), "preservation_failed")
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

def cancellation_manifest(case, working, runtime):
    f = E.cancellation_manifest()
    base = case / "output" / H.CASE_NAME
    inventory = H.inventory(base)
    names = [p for p, v in inventory.items() if not v[0] and re.fullmatch(r"acquisition-[0-9T.]+\.json", p)]
    need(len(names) == 1, "manifest_invalid")
    value = H.strict_json(H.read(base / names[0], 128 * 1024))
    positive = False
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
    need(result["success"] is False and result["integrity"] == "Cancelled" and
         all(result[k] is None for k in ("local_sha256", "size", "hash", "hash_type", "hash_verified", "hash_error")) and
         type(result["error"]) is str and 0 < len(result["error"]) <= 65536, "manifest_invalid")
    wanted = {"Synthetic/" + f["member"]} if positive else set()
    need(set(H.output_files(base / "downloads")) == wanted, "outputs_invalid")
    files = {p for p, row in inventory.items() if not row[0]}
    config = {p for p in files if p.startswith("config/")}
    stem = names[0][:-5]
    allowed = config | {names[0], stem + ".txt", "logs/" + stem + ".log", "logs/" + stem + ".checkpoint.json"} | {"downloads/" + p for p in wanted}
    dirs = {p for p, row in inventory.items() if row[0]}
    need(len(config) == 2 and files == allowed and {"logs", "downloads", "listings", "config"} <= dirs <=
         {"logs", "downloads", "listings", "config", "downloads/Synthetic", "downloads/Synthetic/synthetic-bucket", "downloads/Synthetic/synthetic-bucket/large"} and
         set(H.inventory(case / "output")) == {H.CASE_NAME} | {H.CASE_NAME + "/" + p for p in inventory}, "outputs_invalid")
    return dict.fromkeys(("manifest_exact", "cancelled_result_exact", "manifest_incomplete", "no_partial_outputs", "no_download_outputs"), True)

def execute_cancellation(name, suite, application, app_sha, runtime, errors):
    record = dict(status="failed", exit_code=None, runtime_sha256=None, observation=None, continuity=None, fixture=None,
        failure_code=None, checks=dict.fromkeys(E.CANCEL_CHECKS[name], False))
    item = dict(name=name, record=record, case=suite / "cancellation", lease=None,
        source=None, roots=None, baseline=None, artifact=None, config=None, config_written=False)
    case, checks = item["case"], record["checks"]
    bridge = server = state = context = None
    entered = ready = start_attempted = fixture_attempted = False
    witness_cleanup = dict(closed=True, failed=False)
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
        H.private_write(case, "queue.csv", cancellation_queue_bytes())
        bridge = C.SourceBridge(case)
        H.validate_ready(bridge.command("ready"))
        ready = True
        # Capture helper-only identity/layout before later fixture/config setup
        # can fail. An unavailable baseline remains a cleanup failure.
        H.application_roots_empty(case, item["roots"])
        item["baseline"] = H.helper_baseline(case, item["roots"])
        # Fresh fixture starts after readiness, inside the original case deadline.
        user, key = secrets.token_hex(32), secrets.token_hex(32)
        state = F.AppSwiftCancellationState(user, key)
        context = F.serve_swift_cancellation(state)
        fixture_attempted = True
        server = context.__enter__()
        entered = True
        deadline = min(deadline, server.deadline)
        config = item["config"] = config_bytes(server.endpoint, user, key)
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
            deadline_ms=remaining, max_runtime_processes=1)
        start_attempted = True  # A possibly issued start never uses ready-only cleanup.
        response = bridge.command("start_source", **start_fields)
        need(response["ok"], "session_failed")
        cancellation_running(response, "start_source")
        record["observation"], response = cancellation_transfer(bridge, case, item["lease"], runtime, state, deadline, witness_cleanup)
        record["runtime_sha256"] = runtime["sha256"]
        checks.update(transfer_active=True, content_progress_exact=True, witness_closed=True, ctrl_c_sent=True)
        while not response["app_exited"]:
            need(time.monotonic() < deadline, "deadline_exceeded")
            response = bridge.command("poll")
            need(response["ok"], "session_failed")
            if not response["app_exited"]:
                time.sleep(0.02)
        if response["state"] != "finished":
            response = bridge.command("finish", grace_ms=5000)
        need(time.monotonic() < deadline, "deadline_exceeded")
        cancellation_final(response, runtime)
        record["exit_code"] = response["app_exit_code"]
        record["runtime_sha256"] = runtime["sha256"]
        checks.update(runtime_observed=True, orderly_exit=True)
        need(type(record["exit_code"]) is int and record["exit_code"] == 1, "session_failed")
        checks["exit_failure"] = True
        working = H.configuration_preserved(case, config)
        checks["configuration_preserved"] = True
        checks.update(cancellation_manifest(case, working, runtime))
        item["artifact"] = W.fingerprint(case)
    except BaseException as error:
        mark(record, failure(error), errors)
    finally:
        if bridge is not None:
            try:
                checks["process_cleanup"] = close_cancellation_session(bridge, ready, start_attempted)
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
            try:
                record["fixture"] = state.snapshot()
                E.cancellation_fixture(record["fixture"], successful=True)
                checks.update(fixture_valid=True, source_preserved=True)
            except BaseException:
                mark(record, "fixture_failed", errors)
        if item["lease"] is not None and witness_cleanup["closed"] and not witness_cleanup["failed"] and all(checks[k] for k in ("process_cleanup", "fixture_cleanup")):
            try:
                cancellation_preserved(item, app_sha, before_start=not start_attempted)
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

def run_cancellation(application, application_sha, commit):
    H.hosted_guard()
    application = Path(application).absolute()
    runtime, bound = E.runtime_binding(ROOT), E.compute_cancellation_bindings(ROOT, application, commit)
    cases, group, errors, items = E.empty_cancellation_cases(), E.empty_group(), [], []
    suite = suite_id = None
    clean = False
    try:
        need(bound["application_sha256"] == application_sha and os.environ.get("GITHUB_SHA") == commit and cancellation_bindings(application, commit) == bound, "binding_failed")
        parent = Path(os.environ["RUNNER_TEMP"]).absolute()
        suite = parent / ("app-http-" + uuid.uuid4().hex)
        H.prepare(parent, suite.name)
        suite_id = H.identity(suite)
        group.update(status="failed", checks=dict.fromkeys(E.GROUP_CHECKS, False))
        for name in E.CANCEL_CASES:
            item = execute_cancellation(name, suite, application, application_sha, runtime, errors)
            items.append(item)
            cases[name] = item["record"]
            if errors:
                break
    except BaseException as error:
        errors.append(failure(error))
    finally:
        try:
            need(cancellation_bindings(application, commit) == bound and E.runtime_binding(ROOT) == runtime, "preservation_failed")
        except BaseException:
            errors.append("preservation_failed")
        if group["status"] != "not_run":
            group["checks"].update(configs_preserved=len(items) == 1 and all(i["record"]["checks"]["configuration_preserved"] for i in items),
                artifacts_preserved=len(items) == 1 and all(i["artifact"] is not None and i["record"]["checks"]["temp_cleanup"] for i in items),
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
    success = len(items) == 1 and not errors and clean and all(group["checks"].values()) and all(
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
    receipt = dict(schema_version=2, scope=E.SCOPE, fixture_mode=E.CANCEL_MODE, backend="swift", platform="windows",
        created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), runtime=runtime, bindings=bound, cases=cases,
        experiment=group, lifecycle_scope="content_verified_incomplete_transfer", claims=dict.fromkeys(E.CANCEL_FALSE_CLAIMS, False), cleanup_complete=clean,
        errors=errors, capabilities=E.cancellation_capabilities(cases, clean), result="passed" if success else "failed")
    E.validate_cancellation_receipt(receipt, runtime, bound)
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser()
    for flag in ("application", "application-sha256", "build-commit", "report"):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--cancellation-only", action="store_true")
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
        runner = run_cancellation if args.cancellation_only else run
        receipt = runner(args.application, args.application_sha256, args.build_commit)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(E.compact(receipt) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        return 0 if receipt["result"] == "passed" else 1
    except BaseException:
        try:
            print("application_probe_failed", file=__import__("sys").stderr)
        except BaseException:
            pass  # Diagnostic output cannot replace the original failure.
        return 1
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if prior is not None:
            signal.signal(signal.SIGTERM, prior)


if __name__ == "__main__":
    raise SystemExit(main())
