#!/usr/bin/env python3
"""Pure closed Azure SharedKey experiment contract. No provider/ledger completion."""
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import re
import types

_PATH = Path(__file__).absolute().with_name("webdav_application_evidence.py")
_BYTES = _PATH.read_bytes()
_SHA = hashlib.sha256(_BYTES).hexdigest()
W = types.ModuleType("azureblob_shared_evidence")
W.__file__ = str(_PATH)
exec(compile(_BYTES, str(_PATH), "exec"), W.__dict__)
A = W.A
compact, fail, valid_hash = A.compact, A.fail, A.valid_hash
read_bounded, parse_receipt, runtime_binding = W.read_bounded, W.parse_receipt, W.runtime_binding
SCOPE, MODE = "windows_hosted_application", "azureblob_sharedkey_acquisition_cli_v1"
DOWNLOAD_DENIAL_MODE = "azureblob_sharedkey_download_denial_cli_v1"
LIST_MODE = "azureblob_sharedkey_listing_cli_v1"
MODES = (MODE, DOWNLOAD_DENIAL_MODE, LIST_MODE)
CASES = ("acquisition", "denial")
MODE_CASES = {MODE: CASES, DOWNLOAD_DENIAL_MODE: ("acquisition", "download_denial"), LIST_MODE: ("listing",)}
EXPECTED_LAUNCHES = {"acquisition": 2, "denial": 1, "download_denial": 2, "listing": 1}
COMMON = frozenset({"runtime_observed", "configuration_preserved", "source_preserved", "orderly_exit",
    "fixture_valid", "process_cleanup", "fixture_cleanup", "temp_cleanup", "group_finalized", "manifest_exact"})
CHECKS = {"acquisition": COMMON | {"exit_success", "output_hash_exact", "outputs_exact", "authenticated"},
    "denial": COMMON | {"exit_failure", "wrong_key_denied", "no_payload", "no_download_outputs"},
    "download_denial": COMMON | {"exit_failure", "authenticated_download_denied", "no_payload", "no_download_outputs"}}
CHECKS["listing"] = (COMMON - {"manifest_exact"}) | {"exit_success", "inventory_exact", "listing_complete",
    "outputs_exact", "no_download_outputs", "authenticated", "no_payload"}
MODE_CAPABILITIES = {
    LIST_MODE: ("configured_account_listing", "inventory_export", "shared_key_authentication", "cleanup"),
    MODE: ("configured_acquisition", "shared_key_authentication", "wrong_key_rejection", "cleanup"),
    DOWNLOAD_DENIAL_MODE: ("configured_acquisition", "shared_key_authentication", "authenticated_download_rejection", "cleanup"),
}
GROUP_CHECKS = frozenset({"configs_preserved", "artifacts_preserved", "all_processes_reaped", "fixture_cleanup", "temp_cleanup"})
FALSE_CLAIMS = frozenset({"provider_accepted", "vendor_accepted", "full_application_accepted", "ledger_eligible",
    "credential_renewal_verified", "revocation_verified", "listing_verified", "cancellation_verified", "tls_verified", "remote_vendor_verified"})
LIST_FALSE_CLAIMS = (FALSE_CLAIMS - {"listing_verified"}) | {"content_acquisition_verified"}


def false_claims(mode):
    mode_cases(mode)
    return LIST_FALSE_CLAIMS if mode == LIST_MODE else FALSE_CLAIMS


FAILURE_CODES = A.FAILURE_CODES | {"denial_failed", "group_failed"}
OBSERVATION_KEYS = frozenset({"runtime_launch_count", "peak_runtime_processes", "system_helper_sha256",
    "system_helper_launch_count", "peak_system_helper_processes", "debug_event_count"})
RECORD_KEYS = frozenset({"status", "exit_code", "runtime_sha256", "observation", "continuity", "failure_code", "checks", "fixture"})
RECEIPT_KEYS = A.RECEIPT_KEYS | {"claims", "experiment", "authentication"}
HARNESS_FILES = (
    "scripts/application_evidence.py", "scripts/application_source_snapshot.py", "scripts/webdav_application_evidence.py", "scripts/azureblob_application_evidence.py",
    "scripts/provider-lab/fixture_servers.py", "scripts/application-lab/fixture_http.py", "scripts/application-lab/fixture_webdav.py", "scripts/application-lab/fixture_azureblob.py",
    "scripts/application-lab/run_windows_http.py", "scripts/application-lab/owned_helper_process.py", "scripts/application-lab/run_windows_webdav.py",
    "scripts/application-lab/run_windows_azureblob.py", "scripts/application-lab/filesystem_controller.py",
    "scripts/application-lab/HostedConPtySession.cs", "scripts/application-lab/hosted_session.ps1", "scripts/application-lab/prepare_case.ps1")


def mode_cases(mode):
    need(type(mode) is str and mode in MODES)
    return MODE_CASES[mode]


def fixture_manifest(mode=MODE):
    # Independent literal expected values; no fixture or producer import.
    mode_cases(mode)
    if mode == LIST_MODE:
        return listing_manifest()
    return dict(transport="plain_http_ipv4_loopback", remote="Synthetic", member="synthetic-container/nested/space name.txt",
        size=26, sha256="e019c52fe70badce27affda5e408659399ff764985f07104029a42ade38125bd",
        md5="371d24ba264bcaac3332a3ed564a93f8", request_cap=128, event_cap=512, response_cap=524288,
        fixture_seconds=60, request_seconds=3, authentication="explicit_emulator_shared_key",
        denial=("known_wrong_key_stat_403_AuthenticationFailed" if mode == MODE else
                "correct_key_HEAD_200_HEAD_200_GET_403_AuthorizationFailure_single_stderr_block"))


def compute_bindings(root, application, build_commit, mode=MODE):
    mode_cases(mode)
    if A.file_hash(_PATH) != _SHA or A.file_hash(Path(root) / "scripts/webdav_application_evidence.py") != _SHA:
        fail("azureblob_source_changed")
    result = W.compute_bindings(root, application, build_commit, _harness_files=HARNESS_FILES)
    result["fixture_manifest_sha256"] = hashlib.sha256(compact(fixture_manifest(mode))).hexdigest()
    return result


def empty_cases(mode=MODE):
    return {name: dict(status="not_run", exit_code=None, runtime_sha256=None, observation=None, continuity=None, fixture=None,
        failure_code=None, checks=dict.fromkeys(CHECKS[name], None)) for name in mode_cases(mode)}


def empty_group():
    return dict(status="not_run", failure_code=None, checks=dict.fromkeys(GROUP_CHECKS, None))


def need(value):
    if not value:
        fail("azureblob_receipt_invalid")





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
    need(type(name) is str and name in EXPECTED_LAUNCHES)
    if name == "listing":
        return listing_fixture(value, successful=successful)
    need(type(value) is dict and set(value) == {"case", "requests", "payload_bytes", "response_bytes", "source_preserved", "errors", "events"}
         and value["case"] == name and type(value["source_preserved"]) is bool)
    for key, limit in (("requests",128),("payload_bytes",26),("response_bytes",524288)):
        need(type(value[key]) is int and 0 <= value[key] <= limit)
    codes={"input_invalid","event_limit","thread_start_failed","accept_failed","admission_limit","lifetime_limit",
        "request_timeout","socket_unowned","unexpected_input","client_aborted","request_invalid","headers_invalid",
        "method_rejected","route_invalid","byte_limit","source_changed","request_limit","cancel_replayed",
        "request_body_rejected","connection_failed","worker_failed","cleanup_failed","credentials_invalid","sequence_invalid"}
    need(type(value["errors"]) is list and len(value["errors"]) <= len(codes) and
         all(type(v) is str and v in codes for v in value["errors"]) and len(set(value["errors"])) == len(value["errors"]))
    events=value["events"]
    need(type(events) is list and len(events) <= 512)
    kinds = ({"head_authenticated", "download_denied"} if name == "download_denial" else
             {"head_authenticated", "content_authenticated", "wrong_key_denied"})
    for ordinal,row in enumerate(events,1):
        need(type(row) is dict and set(row)=={"ordinal","kind","role","status","object_bytes"} and
             type(row["ordinal"]) is int and row["ordinal"]==ordinal and type(row["kind"]) is str and
             row["kind"] in kinds and
             type(row["role"]) is str and row["role"] in {"stat","copy"} and type(row["status"]) is int and
             row["status"] in ({200,206} if row["kind"]=="content_authenticated" else
                               {403} if row["kind"] in {"wrong_key_denied","download_denied"} else {200}) and
             type(row["object_bytes"]) is int and row["object_bytes"]==(26 if row["kind"]=="content_authenticated" else 0))
    if successful:
        expected=([("head_authenticated","stat"),("head_authenticated","copy"),("content_authenticated","copy")]
                  if name=="acquisition" else [("wrong_key_denied","stat")] if name=="denial" else
                  [("head_authenticated","stat"),("head_authenticated","copy"),("download_denied","copy")])
        need(not value["errors"] and value["source_preserved"] and value["requests"]==len(expected) and
             value["payload_bytes"]==(26 if name=="acquisition" else 0) and 0<value["response_bytes"]<=524288 and
             [(row["kind"],row["role"]) for row in events]==expected)


def derive_capabilities(cases, cleanup_complete, mode=MODE):
    passed = cleanup_complete and all(cases[n]["status"] == "passed" for n in mode_cases(mode))
    return {k: "passed" if passed else "not_verified" for k in MODE_CAPABILITIES[mode]}


def validate_receipt(receipt, expected_runtime, expected_bindings, now=None, max_age_hours=24, mode=MODE):
    names = mode_cases(mode)
    need(type(receipt) is dict and set(receipt) == RECEIPT_KEYS and type(receipt["schema_version"]) is int and
         receipt["schema_version"] == 1 and receipt["scope"] == SCOPE and receipt["fixture_mode"] == mode and
         receipt["backend"] == "azureblob" and receipt["authentication"] == "static_shared_key" and receipt["platform"] == "windows")
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
        fail("azureblob_receipt_invalid")
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
        if r["status"] == "passed":
            need(r["failure_code"] is None and all(r["checks"].values()) and r["observation"] is not None and
                 r["fixture"] is not None and
                 type(r["exit_code"]) is int and (r["exit_code"] == 0 if name in {"acquisition", "listing"} else r["exit_code"] == 1))
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


def listing_manifest():
    # Literal independent oracle. Flat Blob XML includes an explicit zero-byte
    # nested/ marker; rclone assigns its fixed default directory timestamp.
    # Omitting the marker would synthesize a current-time directory instead.
    return dict(transport="plain_http_ipv4_loopback", remote="Synthetic", container="synthetic-container",
        directory_marker="nested/", members=[dict(name="README-synthetic.txt", size=20), dict(name="empty.txt", size=0),
                 dict(name="nested/space name.txt", size=26)], rows=5,
        container_modified="2024-01-01T00:00:00+00:00", directory_modified="2000-01-01T00:00:00+00:00",
        file_modified="2024-01-01T00:00:00+00:00", exported_hashes=False,
        request_cap=128, event_cap=512, response_cap=524288, fixture_seconds=60, request_seconds=3,
        authentication="explicit_emulator_shared_key", listing="account_then_complete_flat_container_no_continuation")


def listing_rows():
    f = listing_manifest()
    return [["excel-safe-v1", "Synthetic", f["container"], "", f["container_modified"], "true", "", ""],
            ["excel-safe-v1", "Synthetic", f["container"] + "/nested", "", f["directory_modified"], "true", "", ""]] + [
        ["excel-safe-v1", "Synthetic", f["container"] + "/" + row["name"], str(row["size"]),
         f["file_modified"], "false", "", ""] for row in f["members"]]


def listing_fixture(value, *, successful=False):
    need(type(value) is dict and set(value) == {"case", "requests", "payload_bytes", "response_bytes", "source_preserved", "errors", "events"}
         and value["case"] == "listing" and type(value["source_preserved"]) is bool)
    for key, limit in (("requests",128),("payload_bytes",0),("response_bytes",524288)):
        need(type(value[key]) is int and 0 <= value[key] <= limit)
    codes={"input_invalid","event_limit","thread_start_failed","accept_failed","admission_limit","lifetime_limit",
        "request_timeout","socket_unowned","unexpected_input","client_aborted","request_invalid","headers_invalid",
        "method_rejected","route_invalid","byte_limit","source_changed","request_limit","cancel_replayed",
        "request_body_rejected","connection_failed","worker_failed","cleanup_failed","credentials_invalid","sequence_invalid"}
    need(type(value["errors"]) is list and len(value["errors"]) <= len(codes) and
         all(type(e) is str and e in codes for e in value["errors"]) and len(set(value["errors"])) == len(value["errors"]))
    events=value["events"]
    need(type(events) is list and len(events) <= 512)
    expected=[("account_authenticated","account"),("listing_authenticated","flat")]
    for ordinal,row in enumerate(events,1):
        need(type(row) is dict and set(row)=={"ordinal","kind","role","status","object_bytes"} and
             type(row["ordinal"]) is int and row["ordinal"]==ordinal and type(row["kind"]) is str and type(row["role"]) is str and
             (row["kind"],row["role"]) in expected and type(row["status"]) is int and row["status"]==200 and
             type(row["object_bytes"]) is int and row["object_bytes"]==0)
    if successful:
        need(not value["errors"] and value["source_preserved"] and value["requests"]==2 and
             0<value["response_bytes"]<=524288 and [(r["kind"],r["role"]) for r in events]==expected)
    return value


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
    report = dict(schema_version=1, scope="azureblob_application_experiment_validation", receipt_sha256=digest,
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
