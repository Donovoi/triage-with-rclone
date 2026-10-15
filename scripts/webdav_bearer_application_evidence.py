#!/usr/bin/env python3
"""Pure closed fixed-Bearer control/denial contract. No provider/ledger completion."""
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import re
import types

_PATH = Path(__file__).absolute().with_name("webdav_application_evidence.py")
_BYTES = _PATH.read_bytes()
_SHA = hashlib.sha256(_BYTES).hexdigest()
W = types.ModuleType("webdav_bearer_shared_evidence")
W.__file__ = str(_PATH)
exec(compile(_BYTES, str(_PATH), "exec"), W.__dict__)
A = W.A
compact, fail, valid_hash = A.compact, A.fail, A.valid_hash
read_bounded, parse_receipt, runtime_binding = W.read_bounded, W.parse_receipt, W.runtime_binding
SCOPE, MODE = "windows_hosted_application", "webdav_fixed_bearer_invalidation_cli_v1"
CASES = ("accepted_token", "invalidated_token")
EXPECTED_LAUNCHES = dict.fromkeys(CASES, 2)
COMMON = frozenset({"runtime_observed", "configuration_preserved", "source_preserved", "orderly_exit",
    "fixture_valid", "process_cleanup", "fixture_cleanup", "temp_cleanup", "group_finalized", "same_copy_process", "manifest_exact"})
CHECKS = {"accepted_token": COMMON | {"exit_success", "output_hash_exact", "outputs_exact", "bearer_accepted"},
    "invalidated_token": COMMON | {"exit_failure", "bearer_denied", "no_payload", "no_download_outputs"}}
GROUP_CHECKS = frozenset({"configs_preserved", "artifacts_preserved", "all_processes_reaped", "fixture_cleanup", "temp_cleanup", "same_config_authority", "epoch_ordered"})
FALSE_CLAIMS = frozenset({"provider_accepted", "vendor_accepted", "full_application_accepted", "ledger_eligible",
    "cancellation_verified", "tls_verified", "remote_vendor_verified", "elapsed_expiry_verified", "key_revocation_verified", "listing_verified", "automatic_renewal_verified", "authentication_verified", "setup_verified"})
FAILURE_CODES = A.FAILURE_CODES | {"continuity_failed", "denial_failed", "group_failed"}
OBSERVATION_KEYS = frozenset({"runtime_launch_count", "peak_runtime_processes", "system_helper_sha256",
    "system_helper_launch_count", "peak_system_helper_processes", "debug_event_count"})
PROOF_KEYS = frozenset({"phase", "runtime_ordinal", "runtime_sha256", "application_live", "runtime_live", "same_process", "reference_closed"})
RECORD_KEYS = frozenset({"status", "exit_code", "runtime_sha256", "observation", "continuity", "failure_code", "checks", "fixture"})
RECEIPT_KEYS = A.RECEIPT_KEYS | {"claims", "experiment", "lifecycle_scope"}
HARNESS_FILES = (
    "scripts/application_evidence.py", "scripts/webdav_application_evidence.py", "scripts/webdav_bearer_application_evidence.py",
    "scripts/application-lab/fixture_http.py", "scripts/application-lab/fixture_webdav.py", "scripts/application-lab/fixture_webdav_bearer.py",
    "scripts/application-lab/run_windows_http.py", "scripts/application-lab/owned_helper_process.py", "scripts/application-lab/run_windows_webdav.py",
    "scripts/application-lab/run_windows_webdav_bearer.py", "scripts/application-lab/filesystem_controller.py",
    "scripts/application-lab/HostedConPtySession.cs", "scripts/application-lab/hosted_session.ps1", "scripts/application-lab/prepare_case.ps1")


def fixture_manifest():
    # Independent literals: no fixture or producer import.
    return dict(transport="plain_http_ipv4_loopback", remote="Synthetic", member="README-synthetic.txt",
        size=30, sha256="64d5b40a5f4773b14940a6ce1dd57cf87b44ce5940c097088732ffc71be280cf",
        request_cap_per_case=3, metadata_requests_per_case=2, get_requests_per_case=1,
        event_cap=512, response_cap=524288, fixture_seconds=180, request_seconds=15,
        fault="copy_get_401_empty_body", credential="fixed_bearer_without_command")


def compute_bindings(root, application, build_commit):
    if A.file_hash(_PATH) != _SHA or A.file_hash(Path(root) / "scripts/webdav_application_evidence.py") != _SHA:
        fail("webdav_bearer_source_changed")
    result = W.compute_bindings(root, application, build_commit)
    result["harness_sha256"] = A.tree_hash(root, HARNESS_FILES)
    result["fixture_manifest_sha256"] = hashlib.sha256(compact(fixture_manifest())).hexdigest()
    return result


def empty_cases():
    return {name: dict(status="not_run", exit_code=None, runtime_sha256=None, observation=None, continuity=None, fixture=None,
        failure_code=None, checks=dict.fromkeys(CHECKS[name], None)) for name in CASES}


def empty_group():
    return dict(status="not_run", failure_code=None, checks=dict.fromkeys(GROUP_CHECKS, None))


def need(value):
    if not value:
        fail("webdav_bearer_receipt_invalid")


def proof(value, phase, runtime):
    need(type(value) is dict and set(value) == PROOF_KEYS and type(value["phase"]) is str and value["phase"] == phase and
         type(value["runtime_ordinal"]) is int and value["runtime_ordinal"] == 2 and value["runtime_sha256"] == runtime and
         value["application_live"] is True and value["runtime_live"] is True and
         value["same_process"] is (phase == "verify") and value["reference_closed"] is (phase == "verify"))


def observation(value, name):
    need(type(value) is dict and set(value) == OBSERVATION_KEYS)
    for key in OBSERVATION_KEYS - {"system_helper_sha256"}:
        need(type(value[key]) is int)
    n = EXPECTED_LAUNCHES[name]
    need(value["runtime_launch_count"] == n and value["peak_runtime_processes"] == 1 and
         0 <= value["system_helper_launch_count"] <= n and
         (value["system_helper_launch_count"] == 0 and value["peak_system_helper_processes"] == 0 and value["system_helper_sha256"] is None or
          1 <= value["peak_system_helper_processes"] <= min(2, value["system_helper_launch_count"]) and valid_hash(value["system_helper_sha256"])) and
         3 * (1 + n + value["system_helper_launch_count"]) <= value["debug_event_count"] <= 4096)


def fixture_observation(value, name, *, successful=False):
    need(type(value) is dict and set(value) == {"case", "requests", "payload_bytes", "response_bytes", "source_preserved", "errors", "events"}
         and value["case"] == name and type(value["source_preserved"]) is bool)
    for key, limit in (("requests", 3), ("payload_bytes", 30), ("response_bytes", 524288)):
        need(type(value[key]) is int and 0 <= value[key] <= limit)
    codes = {"input_invalid", "event_limit", "thread_start_failed", "accept_failed", "admission_limit", "lifetime_limit",
        "request_timeout", "socket_unowned", "unexpected_input", "client_aborted", "request_invalid", "headers_invalid",
        "method_rejected", "route_invalid", "byte_limit", "source_changed", "request_limit", "cancel_replayed",
        "request_body_rejected", "connection_failed", "worker_failed", "cleanup_failed", "credentials_invalid",
        "sequence_invalid", "gate_invalid"}
    need(type(value["errors"]) is list and len(value["errors"]) <= len(codes) and
         all(type(v) is str and v in codes for v in value["errors"]) and len(set(value["errors"])) == len(value["errors"]))
    events = value["events"]
    need(type(events) is list and len(events) <= 512)
    status = {"metadata": 207, "get_held": 0, "gate_released": 0, "content": 200, "bearer_denied": 401}
    for ordinal, event in enumerate(events, 1):
        need(type(event) is dict and set(event) == {"ordinal", "kind", "status", "object_bytes"} and
             type(event["ordinal"]) is int and event["ordinal"] == ordinal and type(event["kind"]) is str and event["kind"] in status and
             type(event["status"]) is int and event["status"] == status[event["kind"]] and type(event["object_bytes"]) is int and
             event["object_bytes"] == (30 if event["kind"] == "content" else 0))
    if successful:
        need(not value["errors"] and value["source_preserved"] and value["requests"] == 3 and
             [e["kind"] for e in events] == ["metadata", "metadata", "get_held", "gate_released",
                "content" if name == "accepted_token" else "bearer_denied"] and
             value["payload_bytes"] == (30 if name == "accepted_token" else 0) and 0 < value["response_bytes"] <= 524288)


def derive_capabilities(cases, cleanup_complete):
    passed = cleanup_complete and all(cases[n]["status"] == "passed" for n in CASES)
    return {k: "passed" if passed else "not_verified" for k in ("configured_bearer_acquisition", "fixed_bearer_denial", "cleanup")}


def validate_receipt(receipt, expected_runtime, expected_bindings, now=None, max_age_hours=24):
    need(type(receipt) is dict and set(receipt) == RECEIPT_KEYS and type(receipt["schema_version"]) is int and
         receipt["schema_version"] == 1 and receipt["scope"] == SCOPE and receipt["fixture_mode"] == MODE and
         receipt["backend"] == "webdav" and receipt["lifecycle_scope"] == "injected_fixed_bearer_401_no_renewal" and receipt["platform"] == "windows")
    A.validate_bindings(expected_bindings)
    A.validate_bindings(receipt["bindings"])
    need(receipt["bindings"] == expected_bindings and receipt["runtime"] == expected_runtime and
         type(expected_runtime) is dict and set(expected_runtime) == {"version", "sha256", "platform"} and
         valid_hash(expected_runtime["sha256"]) and expected_runtime["platform"] == "windows" and
         type(expected_runtime["version"]) is str and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", expected_runtime["version"]))
    need(type(receipt["created_at"]) is str and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", receipt["created_at"]))
    try:
        stamp = datetime.strptime(receipt["created_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        fail("webdav_bearer_receipt_invalid")
    now = now or datetime.now(timezone.utc)
    need(now - timedelta(hours=max_age_hours) <= stamp <= now + timedelta(minutes=5))
    need(type(receipt["claims"]) is dict and set(receipt["claims"]) == FALSE_CLAIMS and
         all(v is False for v in receipt["claims"].values()) and type(receipt["cleanup_complete"]) is bool)
    errors = receipt["errors"]
    need(type(errors) is list and all(type(e) is str and e in FAILURE_CODES for e in errors) and len(set(errors)) == len(errors))
    cases, group = receipt["cases"], receipt["experiment"]
    need(type(cases) is dict and set(cases) == set(CASES) and type(group) is dict and
         set(group) == {"status", "failure_code", "checks"} and type(group["checks"]) is dict and set(group["checks"]) == GROUP_CHECKS)
    stopped = False
    for name in CASES:
        r = cases[name]
        need(type(r) is dict and set(r) == RECORD_KEYS and type(r["status"]) is str and r["status"] in {"passed", "failed", "not_run"} and
             type(r["checks"]) is dict and set(r["checks"]) == CHECKS[name])
        if r["status"] == "not_run":
            stopped = True
            need(all(r[k] is None for k in RECORD_KEYS - {"status", "checks"}) and all(v is None for v in r["checks"].values()))
            continue
        need(not stopped and all(type(v) is bool for v in r["checks"].values()) and
             (r["exit_code"] is None or type(r["exit_code"]) is int and 0 <= r["exit_code"] < 2**32) and
             (r["runtime_sha256"] is None or r["runtime_sha256"] == expected_runtime["sha256"]))
        if r["observation"] is not None:
            observation(r["observation"], name)
            need(r["runtime_sha256"] == expected_runtime["sha256"])
        need(not r["checks"]["runtime_observed"] or r["observation"] is not None)
        if r["continuity"] is not None:
            need(type(r["continuity"]) is dict and set(r["continuity"]) == {"arm", "verify"})
            for phase in ("arm", "verify"):
                proof(r["continuity"][phase], phase, expected_runtime["sha256"])
        need(not r["checks"]["same_copy_process"] or r["continuity"] is not None)
        if r["fixture"] is not None:
            fixture_observation(r["fixture"], name, successful=r["status"] == "passed")
        need(not r["checks"]["fixture_valid"] or r["fixture"] is not None)
        if r["status"] == "passed":
            need(r["failure_code"] is None and all(r["checks"].values()) and r["observation"] is not None and
                 (r["continuity"] is not None and r["fixture"] is not None) and
                 type(r["exit_code"]) is int and (r["exit_code"] == 1 if name == "invalidated_token" else r["exit_code"] == 0))
        else:
            need(type(r["failure_code"]) is str and r["failure_code"] in errors)
    attempted = any(r["status"] != "not_run" for r in cases.values())
    if group["status"] == "not_run":
        need(not attempted and group["failure_code"] is None and all(v is None for v in group["checks"].values()))
    else:
        need(group["status"] in {"passed", "failed"} and all(type(v) is bool for v in group["checks"].values()))
        if group["status"] == "passed":
            need(not errors and group["failure_code"] is None and all(group["checks"].values()) and all(r["status"] == "passed" for r in cases.values()))
        else:
            need(type(group["failure_code"]) is str and group["failure_code"] in errors and not any(r["status"] == "passed" for r in cases.values()))
        for r in cases.values():
            if r["status"] != "not_run":
                need(not r["checks"]["group_finalized"] or group["status"] == "passed")
    passed = group["status"] == "passed" and receipt["cleanup_complete"] and not errors
    if attempted and receipt["cleanup_complete"]:
        need(all(group["checks"][k] is True for k in ("all_processes_reaped", "fixture_cleanup", "temp_cleanup")) and
             all(all(r["checks"][k] is True for k in ("process_cleanup", "fixture_cleanup", "temp_cleanup"))
                 for r in cases.values() if r["status"] != "not_run"))
    need(receipt["result"] == ("passed" if passed else "failed") and receipt["capabilities"] == derive_capabilities(cases, receipt["cleanup_complete"]) and
         (receipt["cleanup_complete"] or "cleanup_failed" in errors))
    return receipt


def main(argv=None):
    import argparse
    import os
    parser = argparse.ArgumentParser()
    for flag in ("receipt", "application", "build-commit", "report"):
        parser.add_argument("--" + flag, required=True)
    args = parser.parse_args(argv)
    normalized = None
    digest = None
    try:
        raw = read_bounded(args.receipt, 128 * 1024)
        digest = hashlib.sha256(raw).hexdigest()
        root = Path(__file__).absolute().parent.parent
        normalized = validate_receipt(parse_receipt(raw), runtime_binding(root), compute_bindings(root, args.application, args.build_commit))
        result, errors, code = normalized["result"], [], 0 if normalized["result"] == "passed" else 1
    except Exception:
        result, errors, code = "invalid", ["validation_failed"], 2
    report = dict(schema_version=1, scope="webdav_bearer_application_experiment_validation", receipt_sha256=digest,
        valid=normalized is not None, result=result, errors=errors, receipt=normalized, ledger_eligible=False,
        application_accepted=False, vendor_accepted=False, provider_accepted=False)
    try:
        descriptor = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(compact(report) + b"\n")
    except Exception:
        return 2
    return code


if __name__ == "__main__":
    raise SystemExit(main())
