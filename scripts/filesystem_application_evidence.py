"""Closed evidence for Windows local-file and local-ZIP CLI tests.

Launch and live-image observations have separate, closed evidence contracts.
Expected runtime/build bindings must come from the verifier, never the receipt.
This module imports only pure contracts and fixed synthetic byte definitions.
"""
from datetime import datetime, timedelta, timezone
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import types


HERE = Path(__file__).resolve().parent


def _load(name, path):
    data = path.read_bytes()
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(data, str(path), "exec"), module.__dict__)
    return module, hashlib.sha256(data).hexdigest()


A, _BASE_SHA = _load("filesystem_base_contract", HERE / "application_evidence.py")
F, _FIXTURE_SHA = _load("filesystem_fixed_fixture", HERE / "application-lab/fixture_filesystem.py")
ApplicationEvidenceError = A.ApplicationEvidenceError
compact, valid_hash, fail = A.compact, A.valid_hash, A.fail
SCOPE = "windows_hosted_application"
MODE = {"local": "local_filesystem_cli_v1", "archive": "archive_zip_local_cli_v1"}
ACQUISITIONS = ("acquisition_readme", "acquisition_empty", "acquisition_large",
                "acquisition_binary", "acquisition_unicode", "acquisition_spaced")
ORDINARY = ("listing", *ACQUISITIONS, "mismatch", "missing", "directory_as_file")
CASE_ORDER = {"local": (*ORDINARY, "cancellation"),
              "archive": (*ORDINARY, "corrupt_member", "truncated_archive", "cancellation")}
COMMON_CHECKS = frozenset({"runtime_observed", "configuration_preserved", "source_preserved",
    "fixture_valid", "orderly_exit", "temp_cleanup", "process_cleanup", "fixture_cleanup"})
CLEANUP_CHECKS = frozenset({"temp_cleanup", "process_cleanup", "fixture_cleanup"})
_EXTRAS = {
    "listing": {"exit_success", "inventory_exact", "listing_complete"},
    **{name: {"exit_success", "manifest_complete", "manifest_exact", "output_hashes_exact", "outputs_exact"}
       for name in ACQUISITIONS},
    "mismatch": {"exit_failure", "manifest_incomplete", "mismatch_exact", "retained_bytes_exact", "outputs_exact"},
    "missing": {"exit_failure", "manifest_incomplete", "missing_failure_exact", "no_download_outputs"},
    "directory_as_file": {"exit_failure", "manifest_incomplete", "directory_failure_exact", "no_download_outputs"},
    "corrupt_member": {"exit_failure", "manifest_incomplete", "corruption_failure_exact", "no_download_outputs"},
    "truncated_archive": {"exit_failure", "manifest_incomplete", "archive_failure_exact", "no_download_outputs"},
    "cancellation": {"exit_failure", "transfer_active", "ctrl_c_sent", "cancelled_result_exact",
                     "manifest_incomplete", "no_partial_outputs", "no_download_outputs", "content_progress_exact"},
}
CASE_CHECKS = {backend: {name: COMMON_CHECKS | _EXTRAS[name] |
    ({"archive_crc32"} if backend == "archive" and name in ACQUISITIONS else set())
    for name in names} for backend, names in CASE_ORDER.items()}
EXPECTED_LAUNCHES = {backend: {name: (2 if name == "corrupt_member" else
    (3 if backend == "archive" else 2) if name in (*ACQUISITIONS, "mismatch") else 1)
    for name in names if name != "cancellation"} for backend, names in CASE_ORDER.items()}
FALSE_CLAIMS = frozenset({"provider_accepted", "full_application_accepted", "vendor_accepted",
                        "authentication_verified", "refresh_verified"})
CLAIMS = FALSE_CLAIMS | {"cancellation_verified"}
CAPABILITIES = A.CAPABILITIES | {"missing_object_rejection", "directory_as_file_rejection",
    "corrupt_member_rejection", "truncated_archive_rejection", "archive_crc32"}
FAILURE_CODES = A.FAILURE_CODES | {"source_invalid", "observation_invalid"}
HARNESS_FILES = (*A.HARNESS_FILES, "scripts/filesystem_application_evidence.py",
    "scripts/application-lab/filesystem_controller.py", "scripts/application-lab/fixture_filesystem.py",
    "scripts/application-lab/run_windows_filesystem.py")
RECEIPT_KEYS = A.RECEIPT_KEYS | {"claims"}
OBSERVATION_KEYS = frozenset({"kind", "runtime_launch_count", "peak_runtime_processes", "debug_event_count",
    "system_helper_launch_count", "peak_system_helper_processes", "system_helper_sha256"})
LIVE_OBSERVATION_KEYS = frozenset({"kind", "runtime_process_count", "first_verified_bytes", "last_verified_bytes"})
CONTENT_BLOCK_BYTES = 65536
CONTENT_MAX_PREFIX_BYTES = 1048576


def _need(value, code):
    if not value:
        fail(code)


def _fields(value, names, code):
    _need(type(value) is dict and set(value) == set(names), code)


def fixture_manifest():
    return {"files": F.manifest(), "archives": F.archive_manifest(),
            "directories": list(F.DIRECTORIES), "zip_timestamp": list(F.ZIP_TIMESTAMP)}


def compute_bindings(root, application, build_commit):
    # Reject an in-process source change rather than hash new bytes while still
    # executing old imported definitions.
    _need(A.file_hash(HERE / "application_evidence.py") == _BASE_SHA and
          A.file_hash(HERE / "application-lab/fixture_filesystem.py") == _FIXTURE_SHA,
          "filesystem_contract_changed")
    result = A.compute_bindings(root, application, build_commit, fixture_manifest())
    result["harness_sha256"] = A.tree_hash(root, HARNESS_FILES)
    return result


def empty_cases(backend):
    _need(type(backend) is str and backend in CASE_ORDER, "filesystem_backend_invalid")
    return {name: dict(status="not_run", exit_code=None, runtime_sha256=None, observation=None,
        failure_code=None, checks={key: None for key in sorted(CASE_CHECKS[backend][name])})
        for name in CASE_ORDER[backend]}


def derive_capabilities(backend, cases, cleanup_complete=False):
    _need(type(backend) is str and backend in CASE_ORDER, "filesystem_backend_invalid")
    groups = {"listing": ("listing",), "download_hash": ACQUISITIONS,
        "manifest_integrity": CASE_ORDER[backend][1:], "source_preservation": CASE_ORDER[backend],
        "cleanup": CASE_ORDER[backend], "cancellation": ("cancellation",), "missing_object_rejection": ("missing",),
        "directory_as_file_rejection": ("directory_as_file",)}
    if backend == "archive":
        groups.update(corrupt_member_rejection=("corrupt_member",),
                      truncated_archive_rejection=("truncated_archive",), archive_crc32=ACQUISITIONS)
    # A failed cleanup invalidates every capability, including successful reads.
    return {key: "passed" if cleanup_complete and key in groups and
        all(cases.get(name, {}).get("status") == "passed" for name in groups[key]) else "unverified"
        for key in sorted(CAPABILITIES)}


def _observation(value, launches):
    _fields(value, OBSERVATION_KEYS, "filesystem_observation_fields")
    _need(value["kind"] == "launch_image" and valid_hash(value["system_helper_sha256"]),
          "filesystem_observation_kind")
    bounds = {"runtime_launch_count": (launches, launches), "peak_runtime_processes": (1, 1),
              "debug_event_count": (2 * (launches + 1), 4096),
              "system_helper_launch_count": (1, launches), "peak_system_helper_processes": (1, 2)}
    for name, (low, high) in bounds.items():
        _need(type(value[name]) is int and low <= value[name] <= high, "filesystem_observation_count")
    _need(value["peak_system_helper_processes"] <= value["system_helper_launch_count"],
          "filesystem_observation_count")
    _need(value["debug_event_count"] >= 3 * (1 + value["runtime_launch_count"] +
                                           value["system_helper_launch_count"]),
          "filesystem_observation_count")


def _live_observation(value):
    _fields(value, LIVE_OBSERVATION_KEYS, "filesystem_live_observation_fields")
    _need(value["kind"] == "live_image" and type(value["runtime_process_count"]) is int and
          value["runtime_process_count"] == 1, "filesystem_live_observation_invalid")
    first, last = value["first_verified_bytes"], value["last_verified_bytes"]
    _need(type(first) is int and type(last) is int and CONTENT_BLOCK_BYTES <= first < last <= CONTENT_MAX_PREFIX_BYTES and
          first % CONTENT_BLOCK_BYTES == last % CONTENT_BLOCK_BYTES == 0,
          "filesystem_live_progress_invalid")


def validate_receipt(receipt, expected_runtime, expected_bindings, now=None, max_age_hours=24):
    A.validate_bindings(expected_bindings)
    _fields(receipt, RECEIPT_KEYS, "filesystem_receipt_fields")
    backend = receipt["backend"]
    _need(type(backend) is str and backend in MODE, "filesystem_backend_invalid")
    _need(type(receipt["schema_version"]) is int and receipt["schema_version"] == 2 and
          receipt["scope"] == SCOPE and receipt["fixture_mode"] == MODE[backend] and
          receipt["platform"] == "windows", "filesystem_scope_invalid")
    A.validate_bindings(receipt["bindings"])
    _need(receipt["bindings"] == expected_bindings, "filesystem_bindings_mismatch")
    runtime = receipt["runtime"]
    _fields(runtime, {"version", "sha256", "platform"}, "filesystem_runtime_invalid")
    _need(runtime == expected_runtime and runtime["platform"] == "windows" and
          valid_hash(runtime["sha256"]) and type(runtime["version"]) is str and
          re.fullmatch(r"\d+\.\d+\.\d+", runtime["version"]), "filesystem_runtime_mismatch")
    _fields(receipt["claims"], CLAIMS, "filesystem_claims_invalid")
    _need(all(receipt["claims"][key] is False for key in FALSE_CLAIMS) and
          type(receipt["claims"]["cancellation_verified"]) is bool, "filesystem_unsupported_claim")
    _need(type(max_age_hours) in (int, float) and math.isfinite(max_age_hours) and
          0 < max_age_hours <= 24, "filesystem_freshness_invalid")
    created = receipt["created_at"]
    _need(type(created) is str and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", created),
          "filesystem_timestamp_invalid")
    try:
        created = datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        fail("filesystem_timestamp_invalid")
    now = now or datetime.now(timezone.utc)
    _need(created <= now + timedelta(minutes=5) and now - created <= timedelta(hours=max_age_hours),
          "filesystem_receipt_stale_or_future")
    cases = receipt["cases"]
    _fields(cases, CASE_ORDER[backend], "filesystem_cases_invalid")
    for name in CASE_ORDER[backend]:
        case = cases[name]
        _fields(case, {"status", "exit_code", "runtime_sha256", "observation", "failure_code", "checks"},
                "filesystem_case_fields")
        checks = case["checks"]
        _fields(checks, CASE_CHECKS[backend][name], "filesystem_check_fields")
        _need(type(case["status"]) is str and case["status"] in {"not_run", "passed", "failed"},
              "filesystem_case_status")
        if case["status"] == "not_run":
            _need(all(value is None for value in checks.values()) and
                  all(case[key] is None for key in ("exit_code", "runtime_sha256", "observation", "failure_code")),
                  "filesystem_unrun_claims")
            continue
        _need(all(type(value) is bool for value in checks.values()), "filesystem_check_type")
        code = case["exit_code"]
        _need(code is None or type(code) is int and -(2**31) <= code < 2**32, "filesystem_exit_invalid")
        _need(case["runtime_sha256"] in (None, runtime["sha256"]), "filesystem_runtime_observed_mismatch")
        if case["observation"] is not None:
            if name == "cancellation":
                _live_observation(case["observation"])
            else:
                _observation(case["observation"], EXPECTED_LAUNCHES[backend][name])
            _need(case["runtime_sha256"] == runtime["sha256"], "filesystem_runtime_observation_missing")
        _need(not checks["runtime_observed"] or case["observation"] is not None,
              "filesystem_runtime_observation_missing")
        failure = case["failure_code"]
        _need(failure is None or type(failure) is str and failure in FAILURE_CODES, "filesystem_failure_code")
        if case["status"] == "passed":
            positive = name == "listing" or name in ACQUISITIONS
            _need(all(checks.values()) and failure is None and
                  (code == 0 if positive else code is not None and code != 0), "filesystem_pass_inconsistent")
        else:
            _need(failure is not None, "filesystem_failure_inconsistent")
    errors = receipt["errors"]
    _need(type(errors) is list and len(errors) <= len(FAILURE_CODES) and
          all(type(code) is str and code in FAILURE_CODES for code in errors) and
          len(errors) == len(set(errors)), "filesystem_errors_invalid")
    cleanup = receipt["cleanup_complete"]
    _need(type(cleanup) is bool, "filesystem_cleanup_type")
    _need(not cleanup or all(case["status"] == "not_run" or all(case["checks"][key] for key in CLEANUP_CHECKS)
          for case in cases.values()), "filesystem_cleanup_inconsistent")
    expected_capabilities = derive_capabilities(backend, cases, cleanup)
    _fields(receipt["capabilities"], CAPABILITIES, "filesystem_capability_fields")
    _need(receipt["capabilities"] == expected_capabilities, "filesystem_capabilities_inconsistent")
    _need(receipt["claims"]["cancellation_verified"] is
          (cleanup and cases["cancellation"]["status"] == "passed"), "filesystem_cancellation_claim_inconsistent")
    ordinary_passed = all(case["status"] == "passed" for name, case in cases.items() if name != "cancellation")
    completed = cleanup and not errors and ordinary_passed and cases["cancellation"]["status"] == "passed"
    partial = cleanup and not errors and ordinary_passed and cases["cancellation"]["status"] == "not_run"
    _need(receipt["result"] == ("passed" if completed else "partial" if partial else "failed"),
          "filesystem_result_inconsistent")
    return receipt


def read_bounded(path, maximum=512 * 1024):
    """Reject changed, linked or oversized input before parsing any receipt."""
    path = A.plain_file(path)
    before = path.stat()
    _need(0 < before.st_size <= maximum and before.st_nlink == 1, "filesystem_input_invalid")
    def fingerprint(info):
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_nlink)
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        _need(fingerprint(opened) == fingerprint(before), "filesystem_input_changed")
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        # Windows path stat and fstat can expose different ctime semantics.
        # Compare ctime within each API, keeping identity/size/mtime cross-bound.
        _need(fingerprint(after) == fingerprint(opened) and after.st_ctime_ns == opened.st_ctime_ns,
              "filesystem_input_changed")
    last = A.plain_file(path).stat()
    _need(len(data) == before.st_size and fingerprint(last) == fingerprint(before) and
          last.st_ctime_ns == before.st_ctime_ns,
          "filesystem_input_changed")
    return data


def strict_json(data):
    def pairs(rows):
        result = {}
        for key, value in rows:
            _need(key not in result, "filesystem_duplicate_key")
            result[key] = value
        return result
    def constant(_):
        fail("filesystem_json_invalid")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        fail("filesystem_json_invalid")


def runtime_pins(root):
    values = {}
    try:
        for line in read_bounded(Path(root) / "rclone-version.env", 65536).decode("ascii").splitlines():
            if not line or line.startswith("#"):
                continue
            key, value = line.split("=", 1)
            _need(key not in values, "filesystem_pins_invalid")
            values[key] = value
    except (UnicodeDecodeError, ValueError):
        fail("filesystem_pins_invalid")
    hashes = {"RCLONE_EXE_SHA256", "RCLONE_WINDOWS_ZIP_SHA256", "RCLONE_LINUX_ZIP_SHA256",
              "RCLONE_LINUX_EXE_SHA256", "RCLONE_WINDOWS_X86_EXE_SHA256", "RCLONE_WINDOWS_X86_ZIP_SHA256",
              "RCLONE_WINDOWS_ARM64_EXE_SHA256", "RCLONE_WINDOWS_ARM64_ZIP_SHA256"}
    _need(set(values) == hashes | {"RCLONE_VERSION"} and
          re.fullmatch(r"\d+\.\d+\.\d+", values["RCLONE_VERSION"]) and
          all(valid_hash(values[key]) for key in hashes), "filesystem_pins_invalid")
    return dict(version=values["RCLONE_VERSION"], sha256=values["RCLONE_EXE_SHA256"], platform="windows")


def write_new_report(path, value):
    path = Path(path).absolute()
    for parent in path.parents:
        info = parent.lstat()
        _need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and
              not getattr(info, "st_file_attributes", 0) & 0x400, "filesystem_report_parent")
    data = compact(value) + b"\n"
    _need(len(data) <= 512 * 1024, "filesystem_report_size")
    with path.open("xb") as stream:
        _need(stream.write(data) == len(data), "filesystem_report_write")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Verify staged filesystem evidence without running an application.")
    parser.add_argument("--backend", choices=tuple(MODE), required=True)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--application", required=True)
    parser.add_argument("--build-commit", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args(argv)
    try:
        root = HERE.parent
        data = read_bounded(args.receipt)
        value = strict_json(data)
        runtime = runtime_pins(root)
        bindings = compute_bindings(root, args.application, args.build_commit)
        validate_receipt(value, runtime, bindings)
        _need(value["backend"] == args.backend, "filesystem_backend_mismatch")
        report = dict(schema_version=1, validated=True, receipt_sha256=hashlib.sha256(data).hexdigest(),
                      receipt=value)
        write_new_report(args.report, report)
        print(compact(dict(validated=True, backend=args.backend, result=value["result"],
                           provider_accepted=False, cancellation_verified=value["claims"]["cancellation_verified"])).decode("ascii"))
        return 0 if value["result"] == "passed" else 1
    except (ApplicationEvidenceError, OSError, ValueError):
        print('{"validated":false,"error":"filesystem_evidence_invalid"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
