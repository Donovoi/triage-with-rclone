#!/usr/bin/env python3
"""Closed evidence contract for the real Windows application's anonymous HTTP mode.

This is neither Hyper-V guest acceptance nor vendor/account evidence. Importers
must independently supply the exact expected application/build/harness bindings.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import stat


SCOPE = "windows_hosted_application"
MODE = "http_anonymous_cli_v1"
CAPABILITIES = frozenset({"listing", "download_hash", "manifest_integrity",
                          "source_preservation", "cancellation", "cleanup"})
COMMON_CHECKS = frozenset({"runtime_observed", "configuration_preserved",
                         "source_preserved", "fixture_valid", "orderly_exit",
                         "temp_cleanup", "process_cleanup", "fixture_cleanup"})
CASE_CHECKS = {
    "listing": COMMON_CHECKS | {"exit_success", "inventory_exact", "listing_complete"},
    "acquisition": COMMON_CHECKS | {"exit_success", "manifest_complete", "manifest_exact",
                                    "output_hashes_exact", "outputs_exact"},
    "mismatch": COMMON_CHECKS | {"exit_failure", "manifest_incomplete", "mismatch_exact",
                                 "retained_bytes_exact", "outputs_exact"},
    "missing": COMMON_CHECKS | {"exit_failure", "manifest_incomplete", "missing_failure_exact",
                                "no_download_outputs"},
    "denial": COMMON_CHECKS | {"exit_failure", "manifest_incomplete", "denial_observed",
                               "failed_result_exact", "no_download_outputs"},
    "cancellation": COMMON_CHECKS | {"exit_failure", "transfer_active", "ctrl_c_sent",
                                     "cancelled_result_exact", "manifest_incomplete",
                                     "no_partial_outputs", "no_download_outputs"},
}
CASE_ORDER = tuple(CASE_CHECKS)
FAILURE_CODES = frozenset({"binding_failed", "case_setup_failed", "session_failed",
                           "runtime_unobserved", "fixture_failed", "deadline_exceeded",
                           "listing_invalid", "manifest_invalid", "outputs_invalid",
                           "preservation_failed", "cancellation_failed", "cleanup_failed",
                           "unexpected_failure"})
HARNESS_FILES = (
    "scripts/application_evidence.py",
    "scripts/application-lab/fixture_http.py",
    "scripts/application-lab/HostedConPtySession.cs",
    "scripts/application-lab/hosted_session.ps1",
    "scripts/application-lab/prepare_case.ps1",
    "scripts/application-lab/run_windows_http.py",
)
BINDING_KEYS = frozenset({"application_sha256", "application_source_sha256", "build_commit",
                         "build_target", "build_profile", "cargo_lock_sha256",
                         "runtime_manifest_sha256", "harness_sha256", "fixture_manifest_sha256"})
RECEIPT_KEYS = frozenset({"schema_version", "scope", "fixture_mode", "backend", "platform",
                         "created_at", "runtime", "bindings", "cases", "capabilities",
                         "result", "cleanup_complete", "errors"})


class ApplicationEvidenceError(ValueError):
    """A static error code, never a path or diagnostic copied from a child."""


def fail(code):
    raise ApplicationEvidenceError(code)


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def valid_hash(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def plain_file(path):
    path = Path(path).absolute()
    try:
        for item in (path, *path.parents):
            info = item.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                fail("application_binding_reparse_path")
        if not stat.S_ISREG(path.stat().st_mode):
            fail("application_binding_not_file")
    except OSError:
        fail("application_binding_unreadable")
    return path


def file_hash(path):
    try:
        with plain_file(path).open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()
    except OSError:
        fail("application_binding_unreadable")


def tree_hash(root, names):
    root = Path(root)
    rows = [[name, file_hash(root / name)] for name in sorted(names)]
    if not rows or len({row[0] for row in rows}) != len(rows):
        fail("application_binding_empty_or_duplicate_tree")
    return hashlib.sha256(compact(rows)).hexdigest()


def application_source_hash(root):
    root = Path(root)
    source = root / "rclone-triage" / "src"
    names = ["rclone-triage/Cargo.toml", "rclone-triage/Cargo.lock", "rclone-triage/build.rs",
             "rclone-triage/.cargo/config.toml"]
    try:
        for path in source.rglob("*"):
            # Validate directories too; rglob must not hide a linked source tree.
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                fail("application_binding_reparse_path")
            if path.is_file():
                names.append(path.relative_to(root).as_posix())
    except OSError:
        fail("application_source_unreadable")
    if len(names) == 4:
        fail("application_source_empty")
    return tree_hash(root, names)


def compute_bindings(root, application, build_commit, fixture_manifest):
    """Read current files only. This function never runs an application/runtime."""
    if not isinstance(build_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", build_commit):
        fail("application_build_commit_invalid")
    root = Path(root)
    return {
        "application_sha256": file_hash(application),
        "application_source_sha256": application_source_hash(root),
        "build_commit": build_commit,
        "build_target": "x86_64-pc-windows-msvc",
        "build_profile": "release",
        "cargo_lock_sha256": file_hash(root / "rclone-triage/Cargo.lock"),
        "runtime_manifest_sha256": file_hash(root / "rclone-version.env"),
        "harness_sha256": tree_hash(root, HARNESS_FILES),
        "fixture_manifest_sha256": hashlib.sha256(compact(fixture_manifest)).hexdigest(),
    }


def validate_bindings(bindings):
    if not isinstance(bindings, dict) or set(bindings) != BINDING_KEYS:
        fail("application_bindings_invalid")
    for key, value in bindings.items():
        if key.endswith("_sha256") and not valid_hash(value):
            fail("application_binding_hash_invalid")
    if (not isinstance(bindings["build_commit"], str)
            or re.fullmatch(r"[0-9a-f]{40}", bindings["build_commit"]) is None
            or bindings["build_target"] != "x86_64-pc-windows-msvc"
            or bindings["build_profile"] != "release"):
        fail("application_build_invalid")


def derive_capabilities(cases, cleanup_complete=True):
    """A failed scenario can never be promoted by another scenario's pass."""
    contributors = {
        "listing": ("listing",),
        "download_hash": ("acquisition", "mismatch"),
        "manifest_integrity": CASE_ORDER[1:],
        "source_preservation": CASE_ORDER,
        "cancellation": ("cancellation",),
        "cleanup": CASE_ORDER,
    }
    results = {}
    for capability, names in contributors.items():
        statuses = [cases[name]["status"] for name in names]
        results[capability] = ("failed" if "failed" in statuses else "passed"
                               if all(item == "passed" for item in statuses) else "not_verified")
    if not cleanup_complete:
        results["cleanup"] = "failed"
    return results


def empty_cases():
    return {name: {"status": "not_run", "exit_code": None, "runtime_sha256": None,
                   "failure_code": None, "checks": {key: None for key in sorted(checks)}}
            for name, checks in CASE_CHECKS.items()}


def validate_receipt(receipt, expected_runtime, expected_bindings, now=None, max_age_hours=24):
    """Validate against independently obtained bindings, not receipt-supplied pins."""
    validate_bindings(expected_bindings)
    if (type(max_age_hours) not in (int, float) or not math.isfinite(max_age_hours)
            or not 0 < max_age_hours <= 24):
        fail("application_freshness_limit_invalid")
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_KEYS:
        fail("application_receipt_fields_invalid")
    if (type(receipt["schema_version"]) is not int or receipt["schema_version"] != 1
            or receipt["scope"] != SCOPE or receipt["fixture_mode"] != MODE
            or receipt["backend"] != "http" or receipt["platform"] != "windows"):
        fail("application_receipt_scope_invalid")
    validate_bindings(receipt["bindings"])
    if receipt["bindings"] != expected_bindings:
        fail("application_bindings_mismatch")
    runtime = receipt["runtime"]
    if (not isinstance(runtime, dict) or set(runtime) != {"version", "sha256", "platform"}
            or runtime != expected_runtime or runtime.get("platform") != "windows"
            or not valid_hash(runtime.get("sha256"))
            or not isinstance(runtime.get("version"), str)
            or not re.fullmatch(r"\d+\.\d+\.\d+", runtime["version"])):
        fail("application_runtime_mismatch")
    created = receipt["created_at"]
    if not isinstance(created, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", created):
        fail("application_timestamp_invalid")
    try:
        created = datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        fail("application_timestamp_invalid")
    now = now or datetime.now(timezone.utc)
    if created > now + timedelta(minutes=5) or now - created > timedelta(hours=max_age_hours):
        fail("application_receipt_stale_or_future")
    cases = receipt["cases"]
    if not isinstance(cases, dict) or set(cases) != set(CASE_ORDER):
        fail("application_cases_invalid")
    for name, required in CASE_CHECKS.items():
        case = cases[name]
        if not isinstance(case, dict) or set(case) != {"status", "exit_code", "runtime_sha256", "failure_code", "checks"}:
            fail("application_case_fields_invalid")
        checks = case["checks"]
        if not isinstance(checks, dict) or set(checks) != required:
            fail("application_case_checks_invalid")
        status = case["status"]
        if status not in ("passed", "failed", "not_run"):
            fail("application_case_status_invalid")
        if status == "not_run":
            if (any(value is not None for value in checks.values())
                    or any(case[key] is not None for key in ("exit_code", "runtime_sha256", "failure_code"))):
                fail("application_unrun_case_claims")
            continue
        if any(type(value) is not bool for value in checks.values()):
            fail("application_case_check_type_invalid")
        exit_code = case["exit_code"]
        if exit_code is not None and (type(exit_code) is not int or not -(2 ** 31) <= exit_code < 2 ** 32):
            fail("application_exit_code_invalid")
        if case["runtime_sha256"] not in (None, runtime["sha256"]):
            fail("application_observed_runtime_mismatch")
        if checks["runtime_observed"] and case["runtime_sha256"] != runtime["sha256"]:
            fail("application_runtime_observation_missing")
        if case["failure_code"] is not None and (not isinstance(case["failure_code"], str)
                                                or case["failure_code"] not in FAILURE_CODES):
            fail("application_failure_code_invalid")
        if status == "passed":
            expected_exit = exit_code == 0 if name in ("listing", "acquisition") else exit_code is not None and exit_code != 0
            if not all(checks.values()) or not expected_exit or case["failure_code"] is not None:
                fail("application_pass_inconsistent")
        elif all(checks.values()) and case["failure_code"] is None:
            fail("application_failure_inconsistent")
    errors = receipt["errors"]
    if (not isinstance(errors, list) or len(errors) > len(FAILURE_CODES)
            or any(not isinstance(code, str) or code not in FAILURE_CODES for code in errors)
            or len(set(errors)) != len(errors)):
        fail("application_errors_invalid")
    if type(receipt["cleanup_complete"]) is not bool:
        fail("application_cleanup_invalid")
    if receipt["cleanup_complete"] and any(
            case["status"] != "not_run" and not all(case["checks"][key] for key in
                                                     ("temp_cleanup", "process_cleanup", "fixture_cleanup"))
            for case in cases.values()):
        fail("application_cleanup_inconsistent")
    if receipt["capabilities"] != derive_capabilities(cases, receipt["cleanup_complete"]):
        fail("application_capabilities_inconsistent")
    passed = (all(case["status"] == "passed" for case in cases.values())
              and receipt["cleanup_complete"] and not errors)
    if receipt["result"] != ("passed" if passed else "failed"):
        fail("application_result_inconsistent")
    return receipt
