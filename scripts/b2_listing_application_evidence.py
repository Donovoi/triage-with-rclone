#!/usr/bin/env python3
"""Closed B2 application listing contract; protocol/application/vendor are distinct."""
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import re
import types

_PATH = Path(__file__).absolute().with_name("webdav_application_evidence.py")
_BYTES = _PATH.read_bytes()
_SHA = hashlib.sha256(_BYTES).hexdigest()
W = types.ModuleType("b2_listing_shared_evidence")
W.__file__ = str(_PATH)
exec(compile(_BYTES, str(_PATH), "exec"), W.__dict__)
A = W.A
compact, fail, valid_hash = A.compact, A.fail, A.valid_hash
read_bounded, parse_receipt, runtime_binding = W.read_bounded, W.parse_receipt, W.runtime_binding
SCOPE, MODE = "windows_hosted_application", "b2_native_listing_cli_v1"
MODES = (MODE,)
CASES = ("account_listing", "alias_nested_listing")
EXPECTED_LAUNCHES = dict.fromkeys(CASES, 1)
COMMON = frozenset({"runtime_observed", "configuration_preserved", "source_preserved", "orderly_exit",
    "fixture_valid", "process_cleanup", "fixture_cleanup", "temp_cleanup", "group_finalized", "exit_success",
    "inventory_exact", "listing_complete", "outputs_exact", "no_download_outputs", "authenticated", "no_payload", "implicit_directories_exact", "invocation_time_bounded"})
CHECKS = dict.fromkeys(CASES, COMMON)
MODE_CAPABILITIES = {MODE: ("configured_account_listing", "configured_alias_nested_listing", "inventory_export", "metadata_continuation", "cleanup")}
GROUP_CHECKS = frozenset({"configs_preserved", "artifacts_preserved", "all_processes_reaped", "fixture_cleanup", "temp_cleanup"})
FALSE_CLAIMS = frozenset({"provider_accepted", "vendor_accepted", "full_application_accepted", "ledger_eligible",
    "credential_renewal_verified", "revocation_verified", "content_acquisition_verified", "cancellation_verified", "tls_verified", "remote_vendor_verified",
    "direct_b2_nested_root_verified", "nonrecursive_listp_verified"})
FAILURE_CODES = A.FAILURE_CODES | {"group_failed"}
OBSERVATION_KEYS = frozenset({"runtime_launch_count", "peak_runtime_processes", "system_helper_sha256",
    "system_helper_launch_count", "peak_system_helper_processes", "debug_event_count"})
RECORD_KEYS = frozenset({"status", "exit_code", "runtime_sha256", "observation", "continuity", "failure_code", "checks", "fixture", "inventory_observation"})
RECEIPT_KEYS = A.RECEIPT_KEYS | {"claims", "experiment", "authentication"}
HARNESS_FILES = (
    "scripts/application_evidence.py", "scripts/application_source_snapshot.py", "scripts/webdav_application_evidence.py", "scripts/b2_listing_application_evidence.py",
    "scripts/provider-lab/fixture_servers.py", "scripts/application-lab/fixture_http.py", "scripts/application-lab/fixture_webdav.py", "scripts/application-lab/fixture_b2_listing.py",
    "scripts/application-lab/run_windows_http.py", "scripts/application-lab/owned_helper_process.py", "scripts/application-lab/run_windows_webdav.py",
    "scripts/application-lab/run_windows_b2_listing.py", "scripts/application-lab/filesystem_controller.py",
    "scripts/application-lab/HostedConPtySession.cs", "scripts/application-lab/hosted_session.ps1", "scripts/application-lab/prepare_case.ps1")


def mode_cases(mode):
    need(type(mode) is str and mode == MODE)
    return CASES


def false_claims(mode):
    mode_cases(mode)
    return FALSE_CLAIMS


def listing_manifest():
    # Independent literal oracle: retain the explicit nested/ marker and also
    # require walk.dirMap to synthesize unmarked from its child with time.Now().
    # Both recursive pages omit delimiter; continuation is a filename, not an ID.
    return dict(transport="plain_http_ipv4_loopback", remote="Synthetic", bucket="synthetic-bucket",
        alias_target="B2Source:synthetic-bucket/nested", directory_marker="nested/",
        members=[dict(name="README-synthetic.txt", size=20), dict(name="nested/empty.txt", size=0),
                 dict(name="nested/space name.txt", size=26), dict(name="unmarked/leaf.txt", size=17)], account_rows=7, alias_rows=2,
        directory_modified="2000-01-01T00:00:00+00:00", file_modified="2024-01-01T00:00:00+00:00",
        exported_hashes=False, request_cap=32, event_cap=4, response_cap=16384,
        connection_cap=128, active_connection_cap=8, fixture_seconds=60, request_seconds=3,
        request_body_cap=1024, wire_response_cap=4096,
        authentication="synthetic_basic_then_authorization_token", granted_capabilities=["listBuckets", "listFiles", "readFiles"],
        listing="recursive_b2_listr_two_pages_account_and_alias_nested", next_file_name="nested/space name.txt",
        delimiter_omitted=True, payload_routes=False, implicit_directories=["synthetic-bucket/unmarked"],
        invocation_max_ns=60000000000, receipt_interval_max_age_seconds=600)


def fixture_manifest(mode=MODE):
    mode_cases(mode)
    return listing_manifest()


def listing_rows(name):
    need(type(name) is str and name in CASES)
    f = listing_manifest()
    if name == "alias_nested_listing":
        return [["excel-safe-v1", "Synthetic", r["name"][7:], str(r["size"]), f["file_modified"], "false", "", ""] for r in f["members"][1:3]]
    return [["excel-safe-v1", "Synthetic", f["bucket"], "", f["directory_modified"], "true", "", ""],
            ["excel-safe-v1", "Synthetic", f["bucket"] + "/nested", "", f["directory_modified"], "true", "", ""]] + [
        ["excel-safe-v1", "Synthetic", f["bucket"] + "/" + r["name"], str(r["size"]), f["file_modified"], "false", "", ""] for r in f["members"]]


def implicit_paths(name):
    need(type(name) is str and name in CASES)
    return ("synthetic-bucket/unmarked",) if name == "account_listing" else ()


def timestamp_ns(value, *, csv=False):
    """Validate the exact UTC shape and preserve all nanoseconds as integers."""
    need(type(value) is str)
    pattern = (r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{3}|[0-9]{6}|[0-9]{9}))?\+00:00"
               if csv else r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})\.([0-9]{6})Z")
    match = re.fullmatch(pattern, value)
    need(match is not None)
    try:
        base = datetime.strptime(match[1], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        fail("b2_listing_receipt_invalid")
    delta = base - datetime(1970, 1, 1, tzinfo=timezone.utc)
    fraction = (match[2] or "").ljust(9, "0")
    return (delta.days * 86400 + delta.seconds) * 1000000000 + int(fraction)


def invocation_interval(value):
    need(type(value) is dict and set(value) == {"started_at", "finished_at", "elapsed_ns"})
    start, end = timestamp_ns(value["started_at"]), timestamp_ns(value["finished_at"])
    need(type(value["elapsed_ns"]) is int and 0 < value["elapsed_ns"] <= 60000000000 and
         0 <= end - start <= 60000000000)
    return start, end


def inventory_observation(value, name):
    need(type(value) is dict and set(value) == {"invocation", "implicit_directories", "rows"})
    start, end = invocation_interval(value["invocation"])
    rows = value["implicit_directories"]
    expected = implicit_paths(name)
    need(type(rows) is list and len(rows) == len(expected))
    paths = []
    for row in rows:
        need(type(row) is dict and set(row) == {"path", "modified"} and type(row["path"]) is str)
        paths.append(row["path"])
        need(start <= timestamp_ns(row["modified"], csv=True) <= end)
    need(sorted(paths) == sorted(expected))
    # Replay all exported data columns independently; never infer a valid CSV
    # merely from a timestamp list or producer success flags.
    exported = value["rows"]
    need(type(exported) is list and len(exported) == (7 if name == "account_listing" else 2) and
         all(type(row) is list and len(row) == 8 and all(type(cell) is str for cell in row) for row in exported))
    literal = listing_rows(name)
    implicit = [["excel-safe-v1", "Synthetic", row["path"], "", row["modified"], "true", "", ""] for row in rows]
    need(sorted(exported) == sorted(literal + implicit))
    return value


def expected_events(name):
    need(type(name) is str and name in CASES)
    second = ("bucket_discovery", "restricted_bucket", 200) if name == "account_listing" else ("root_probe", "nested_absent_object", 404)
    return [("grant", "account", 200), second, ("file_names", "first_page", 200), ("file_names", "continuation_page", 200)]


def fixture_observation(value, name, *, successful=False):
    expected = expected_events(name)
    need(type(value) is dict and set(value) == {"case", "requests", "payload_bytes", "response_bytes", "source_preserved", "errors", "events", "granted_capabilities"}
         and value["case"] == name and type(value["source_preserved"]) is bool)
    for key, limit in (("requests", 32), ("payload_bytes", 0), ("response_bytes", 16384)):
        need(type(value[key]) is int and 0 <= value[key] <= limit)
    codes = {"input_invalid", "event_limit", "thread_start_failed", "accept_failed", "admission_limit", "lifetime_limit",
        "request_timeout", "socket_unowned", "unexpected_input", "client_aborted", "request_invalid", "headers_invalid",
        "method_rejected", "route_invalid", "byte_limit", "source_changed", "request_limit", "cancel_replayed",
        "request_body_rejected", "connection_failed", "worker_failed", "cleanup_failed", "credentials_invalid", "sequence_invalid", "token_invalid", "capability_denied"}
    need(type(value["errors"]) is list and len(value["errors"]) <= len(codes) and
         all(type(e) is str and e in codes for e in value["errors"]) and len(set(value["errors"])) == len(value["errors"]))
    events = value["events"]
    need(type(events) is list and len(events) <= 4)
    caps = value["granted_capabilities"]
    allowed = ["listBuckets", "listFiles", "readFiles"]
    need(caps is None if not events else type(caps) is list and
         all(type(c) is str and c in allowed for c in caps) and [c for c in allowed if c in caps] == caps)
    for ordinal, row in enumerate(events, 1):
        need(type(row) is dict and set(row) == {"ordinal", "kind", "role", "status", "object_bytes"} and
             type(row["ordinal"]) is int and row["ordinal"] == ordinal and type(row["kind"]) is str and type(row["role"]) is str and
             type(row["status"]) is int and (row["kind"], row["role"], row["status"]) == expected[ordinal - 1] and
             type(row["object_bytes"]) is int and row["object_bytes"] == 0)
    if successful:
        need(not value["errors"] and value["source_preserved"] and caps == allowed and value["requests"] == 4 and
             0 < value["response_bytes"] <= 16384 and len(events) == 4)
    return value


def compute_bindings(root, application, build_commit, mode=MODE):
    mode_cases(mode)
    if A.file_hash(_PATH) != _SHA or A.file_hash(Path(root) / "scripts/webdav_application_evidence.py") != _SHA:
        fail("b2_listing_source_changed")
    result = W.compute_bindings(root, application, build_commit, _harness_files=HARNESS_FILES)
    result["fixture_manifest_sha256"] = hashlib.sha256(compact(fixture_manifest(mode))).hexdigest()
    return result

def empty_cases(mode=MODE):
    return {name: dict(status="not_run", exit_code=None, runtime_sha256=None, observation=None, continuity=None, fixture=None, inventory_observation=None,
        failure_code=None, checks=dict.fromkeys(CHECKS[name], None)) for name in mode_cases(mode)}

def empty_group():
    return dict(status="not_run", failure_code=None, checks=dict.fromkeys(GROUP_CHECKS, None))

def need(value):
    if not value:
        fail("b2_listing_receipt_invalid")

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

def derive_capabilities(cases, cleanup_complete, mode=MODE):
    passed = cleanup_complete and all(cases[n]["status"] == "passed" for n in mode_cases(mode))
    return {k: "passed" if passed else "not_verified" for k in MODE_CAPABILITIES[mode]}

def validate_receipt(receipt, expected_runtime, expected_bindings, now=None, max_age_hours=24, mode=MODE):
    names = mode_cases(mode)
    need(type(receipt) is dict and set(receipt) == RECEIPT_KEYS and type(receipt["schema_version"]) is int and
         receipt["schema_version"] == 1 and receipt["scope"] == SCOPE and receipt["fixture_mode"] == mode and
         receipt["backend"] == "b2" and receipt["authentication"] == "synthetic_basic_then_authorization_token" and receipt["platform"] == "windows")
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
        fail("b2_listing_receipt_invalid")
    now = now or datetime.now(timezone.utc)
    need(now - timedelta(hours=max_age_hours) <= stamp <= now + timedelta(minutes=5))
    need(type(receipt["claims"]) is dict and set(receipt["claims"]) == false_claims(mode) and
         all(v is False for v in receipt["claims"].values()) and type(receipt["cleanup_complete"]) is bool)
    errors = receipt["errors"]
    need(type(errors) is list and all(type(e) is str and e in FAILURE_CODES for e in errors) and len(set(errors)) == len(errors))
    cases, group = receipt["cases"], receipt["experiment"]
    need(type(cases) is dict and set(cases) == set(names) and type(group) is dict and
         set(group) == {"status", "failure_code", "checks"} and type(group["checks"]) is dict and set(group["checks"]) == GROUP_CHECKS)
    stopped = False
    previous_end = None
    for name in names:
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
        need(r["continuity"] is None)
        if r["fixture"] is not None:
            fixture_observation(r["fixture"], name, successful=r["status"] == "passed")
        need(not r["checks"]["fixture_valid"] or r["fixture"] is not None)
        if r["inventory_observation"] is not None:
            inventory_observation(r["inventory_observation"], name)
            start, end = invocation_interval(r["inventory_observation"]["invocation"])
            stamp_ns = timestamp_ns(stamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
            need(stamp_ns - 600000000000 <= start <= end < stamp_ns + 1000000000 and
                 (previous_end is None or previous_end <= start))
            previous_end = end
        need(not any(r["checks"][k] for k in ("inventory_exact", "listing_complete", "implicit_directories_exact", "invocation_time_bounded")) or
             r["inventory_observation"] is not None)
        if r["status"] == "passed":
            need(r["failure_code"] is None and all(r["checks"].values()) and r["observation"] is not None and
                 r["fixture"] is not None and r["inventory_observation"] is not None and
                 type(r["exit_code"]) is int and r["exit_code"] == 0)
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
    need(receipt["result"] == ("passed" if passed else "failed") and receipt["capabilities"] == derive_capabilities(cases, receipt["cleanup_complete"], mode) and
         (receipt["cleanup_complete"] or "cleanup_failed" in errors))
    return receipt

def main(argv=None):
    import argparse
    import os
    parser = argparse.ArgumentParser()
    for flag in ("receipt", "application", "build-commit", "report"):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--fixture-mode", choices=MODES, default=MODE)
    args = parser.parse_args(argv)
    normalized = None
    digest = None
    try:
        raw = read_bounded(args.receipt, 128 * 1024)
        digest = hashlib.sha256(raw).hexdigest()
        root = Path(__file__).absolute().parent.parent
        normalized = validate_receipt(parse_receipt(raw), runtime_binding(root),
            compute_bindings(root, args.application, args.build_commit, args.fixture_mode), mode=args.fixture_mode)
        result, errors, code = normalized["result"], [], 0 if normalized["result"] == "passed" else 1
    except Exception:
        result, errors, code = "invalid", ["validation_failed"], 2
    report = dict(schema_version=1, scope="b2_listing_application_experiment_validation", receipt_sha256=digest,
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

