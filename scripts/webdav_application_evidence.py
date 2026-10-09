#!/usr/bin/env python3
"""Closed, pure contract for configured Basic WebDAV Windows CLI evidence.

The six common application capabilities do not qualify a provider, interactive
login, credential renewal, TLS, or vendor acceptance. No producer is imported.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import types


_BASE_PATH = Path(__file__).absolute().with_name("application_evidence.py")
_BASE_BYTES = _BASE_PATH.read_bytes()
_BASE_SHA256 = hashlib.sha256(_BASE_BYTES).hexdigest()
A = types.ModuleType("webdav_shared_application_contract")
A.__file__ = str(_BASE_PATH)
exec(compile(_BASE_BYTES, str(_BASE_PATH), "exec"), A.__dict__)
ApplicationEvidenceError = A.ApplicationEvidenceError
compact, valid_hash, fail = A.compact, A.valid_hash, A.fail

SCOPE = "windows_hosted_application"
MODE = "webdav_basic_loopback_cli_v1"
CAPABILITIES = A.CAPABILITIES
COMMON_CHECKS = A.COMMON_CHECKS | {"authority_exact", "request_credentials_exact"}
CLEANUP_CHECKS = frozenset({"temp_cleanup", "process_cleanup", "fixture_cleanup"})
READ_CHECKS = frozenset({"exit_success", "manifest_complete", "manifest_exact",
                         "output_hashes_exact", "outputs_exact", "basic_auth_observed"})
REJECTED_CHECKS = frozenset({"exit_failure", "manifest_incomplete", "credential_denial_observed",
                             "failed_result_exact", "no_download_outputs", "no_payload_served",
                             "no_authority_fallback"})
INVOCATION_CHECKS = {
    "listing": COMMON_CHECKS | {"exit_success", "inventory_exact", "listing_complete", "basic_auth_observed"},
    "acquisition": COMMON_CHECKS | READ_CHECKS,
    "mismatch": COMMON_CHECKS | {"exit_failure", "manifest_incomplete", "mismatch_exact",
                                  "retained_bytes_exact", "outputs_exact", "basic_auth_observed"},
    "missing": COMMON_CHECKS | {"exit_failure", "manifest_incomplete", "missing_failure_exact",
                                 "not_found_observed", "no_download_outputs", "basic_auth_observed"},
    "wrong_credentials": COMMON_CHECKS | REJECTED_CHECKS,
    "accepted_a": COMMON_CHECKS | READ_CHECKS | {"group_finalized"},
    "revoked_a": COMMON_CHECKS | REJECTED_CHECKS | {"same_config_as_accepted", "group_finalized"},
    "replacement_b": COMMON_CHECKS | READ_CHECKS | {"credential_changed", "group_finalized"},
    "permission_denied": COMMON_CHECKS | {"exit_failure", "manifest_incomplete", "permission_denial_observed",
                                           "failed_result_exact", "no_download_outputs", "no_payload_served",
                                           "basic_auth_observed"},
    "truncated_transfer": COMMON_CHECKS | {"exit_failure", "manifest_incomplete", "truncation_observed",
                                            "failed_result_exact", "no_partial_outputs", "no_download_outputs",
                                            "basic_auth_observed"},
    "cancellation": COMMON_CHECKS | {"exit_failure", "transfer_active", "ctrl_c_sent",
                                      "client_disconnect_observed", "cancelled_result_exact", "manifest_incomplete",
                                      "no_partial_outputs", "no_download_outputs", "basic_auth_observed"},
}
CASE_INVOCATIONS = {
    "listing": ("listing",), "acquisition": ("acquisition",), "mismatch": ("mismatch",),
    "missing": ("missing",), "wrong_credentials": ("wrong_credentials",),
    "revoked_credentials": ("accepted_a", "revoked_a"),
    "replacement_credentials": ("replacement_b",),
    "permission_denied": ("permission_denied",), "truncated_transfer": ("truncated_transfer",),
    "cancellation": ("cancellation",),
}
CASE_ORDER = tuple(CASE_INVOCATIONS)
INVOCATION_ORDER = tuple(INVOCATION_CHECKS)
GROUP_INVOCATIONS = ("accepted_a", "revoked_a", "replacement_b")
POSITIVE_INVOCATIONS = frozenset({"listing", "acquisition", "accepted_a", "replacement_b"})
GROUP_CHECKS = frozenset({"same_fixture_authority", "epoch_ordered", "transitions_reaped", "deadline_preserved",
                          "revocation_observed", "replacement_observed", "config_a_preserved", "accepted_a_preserved",
                          "no_credential_poisoning", "all_processes_reaped", "fixture_cleanup", "temp_cleanup"})
FALSE_CLAIMS = frozenset({"setup_verified", "interactive_login_verified", "authentication_verified",
                          "renewal_verified", "reauthorization_verified", "connection_session_reauthentication_verified",
                          "tls_verified", "vendor_accepted",
                          "provider_accepted", "full_application_accepted"})
FAILURE_CODES = A.FAILURE_CODES | {"authority_failed", "credential_transition_failed", "denial_failed",
                                   "truncation_failed", "group_failed"}
HARNESS_FILES = (
    "scripts/application_evidence.py", "scripts/webdav_application_evidence.py",
    "scripts/application-lab/fixture_http.py", "scripts/application-lab/fixture_webdav.py",
    "scripts/application-lab/HostedConPtySession.cs", "scripts/application-lab/hosted_session.ps1",
    "scripts/application-lab/prepare_case.ps1", "scripts/application-lab/run_windows_http.py",
    "scripts/application-lab/run_windows_webdav.py",
)
BINDING_KEYS = A.BINDING_KEYS
RECEIPT_KEYS = A.RECEIPT_KEYS | {"claims", "credential_group"}
MAX_RECEIPT_BYTES = 256 * 1024


def fixture_manifest():
    """Independent literals, including WebDAV directory times and absent source hashes."""
    return {"remote": "Synthetic", "vendor": "other", "transport": "loopback_http", "auth_redirect": False,
            "modified": "2025-01-02T03:04:05Z", "directories": ["large", "nested"],
            "listing_hashes": "unavailable", "files": [
                {"path": "README-synthetic.txt", "size": 30,
                 "sha256": "64d5b40a5f4773b14940a6ce1dd57cf87b44ce5940c097088732ffc71be280cf"},
                {"path": "large/cancel.bin", "size": 2097152,
                 "sha256": "91d3beb88a9b2f778a6c44a1c53b63d3c79931845a9aef84b3fb414610bd1938"},
                {"path": "nested/binary.bin", "size": 256,
                 "sha256": "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880"},
                {"path": "nested/spaced name.txt", "size": 20,
                 "sha256": "0c6308d568f8ec30fbf044baac7827edac83a2465a60439ff653e277a5d9619e"},
            ]}


def read_bounded(path, maximum=MAX_RECEIPT_BYTES):
    """One bounded regular-file read with path/handle identity and mutation checks."""
    try:
        path = A.plain_file(path)
        before = path.stat()
        if not 0 < before.st_size <= maximum:
            fail("webdav_file_bound")
        def stamp(value):
            return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if stamp(opened) != stamp(before):
                fail("webdav_file_changed")
            data = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
            if stamp(opened) != stamp(after) or opened.st_ctime_ns != after.st_ctime_ns:
                fail("webdav_file_changed")
        last = A.plain_file(path).stat()
        if stamp(last) != stamp(before) or last.st_ctime_ns != before.st_ctime_ns or len(data) != before.st_size:
            fail("webdav_file_changed")
        return data
    except OSError:
        fail("webdav_file_unreadable")


def load_receipt(path):
    return parse_receipt(read_bounded(path))


def parse_receipt(data):
    if type(data) is not bytes or not 0 < len(data) <= MAX_RECEIPT_BYTES:
        fail("webdav_receipt_bound")
    def pairs(rows):
        out = {}
        for key, value in rows:
            if key in out:
                fail("webdav_duplicate_key")
            out[key] = value
        return out
    def constant(_):
        fail("webdav_json_invalid")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError) as error:
        if isinstance(error, ApplicationEvidenceError):
            raise
        fail("webdav_json_invalid")


def runtime_binding(root):
    try:
        lines = read_bounded(Path(root) / "rclone-version.env", 4096).decode("ascii").splitlines()
    except UnicodeError:
        fail("webdav_runtime_pin_invalid")
    values = {}
    for line in lines:
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or key in values:
            fail("webdav_runtime_pin_invalid")
        values[key] = value
    base = {"RCLONE_VERSION", "RCLONE_EXE_SHA256", "RCLONE_WINDOWS_ZIP_SHA256",
            "RCLONE_LINUX_ZIP_SHA256", "RCLONE_LINUX_EXE_SHA256"}
    extra = {"RCLONE_WINDOWS_X86_EXE_SHA256", "RCLONE_WINDOWS_X86_ZIP_SHA256",
             "RCLONE_WINDOWS_ARM64_EXE_SHA256", "RCLONE_WINDOWS_ARM64_ZIP_SHA256"}
    if (set(values) not in (base, base | extra)
            or not re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)", values["RCLONE_VERSION"])
            or any(not valid_hash(value) for key, value in values.items() if key != "RCLONE_VERSION")):
        fail("webdav_runtime_pin_invalid")
    return {"version": values["RCLONE_VERSION"], "sha256": values["RCLONE_EXE_SHA256"], "platform": "windows"}


def compute_bindings(root, application, build_commit):
    """Fixed source names and literal manifest only; never receipt-directed imports."""
    root = Path(root)
    if A.file_hash(_BASE_PATH) != _BASE_SHA256 or A.file_hash(root / "scripts/application_evidence.py") != _BASE_SHA256:
        fail("webdav_shared_contract_changed")
    bindings = A.compute_bindings(root, application, build_commit, fixture_manifest())
    bindings["harness_sha256"] = A.tree_hash(root, HARNESS_FILES)
    return bindings


def empty_cases():
    return {name: {"status": "not_run", "failure_code": None,
                   "invocations": {leaf: {"status": "not_run", "exit_code": None, "runtime_sha256": None,
                                           "failure_code": None,
                                           "checks": {key: None for key in sorted(INVOCATION_CHECKS[leaf])}}
                                   for leaf in leaves}}
            for name, leaves in CASE_INVOCATIONS.items()}


def empty_group():
    return {"status": "not_run", "failure_code": None, "checks": {key: None for key in sorted(GROUP_CHECKS)}}


def derive_capabilities(cases, cleanup_complete=True):
    # The common contributor rules are identical; scenario statuses are projected
    # here rather than changing the HTTP contract's fixed case list.
    contributors = {"listing": ("listing",), "download_hash": ("acquisition", "mismatch"),
                    "manifest_integrity": CASE_ORDER[1:], "source_preservation": CASE_ORDER,
                    "cancellation": ("cancellation",), "cleanup": CASE_ORDER}
    result = {}
    for capability, names in contributors.items():
        statuses = [cases[name]["status"] for name in names]
        result[capability] = ("failed" if "failed" in statuses else "passed"
                              if all(value == "passed" for value in statuses) else "not_verified")
    if not cleanup_complete:
        result["cleanup"] = "failed"
    return result


def _fields(value, keys, code):
    if type(value) is not dict or set(value) != keys:
        fail(code)


def _status(value):
    if type(value) is not str or value not in ("not_run", "failed", "passed"):
        fail("webdav_status_invalid")


def _failure(value, status, errors):
    if status == "failed":
        if type(value) is not str or value not in FAILURE_CODES or value not in errors:
            fail("webdav_failure_invalid")
    elif value is not None:
        fail("webdav_failure_invalid")


def _checks(value, required, status):
    _fields(value, required, "webdav_checks_invalid")
    if status == "not_run":
        if any(item is not None for item in value.values()):
            fail("webdav_unrun_claims")
    elif any(type(item) is not bool for item in value.values()):
        fail("webdav_check_type_invalid")


def _expected_exit(name, value):
    return type(value) is int and (value == 0 if name in POSITIVE_INVOCATIONS else value != 0)


def validate_receipt(receipt, expected_runtime, expected_bindings, now=None, max_age_hours=24):
    """Validate observations; expected bindings must come from trusted current files."""
    A.validate_bindings(expected_bindings)
    _fields(receipt, RECEIPT_KEYS, "webdav_receipt_fields_invalid")
    if (type(receipt["schema_version"]) is not int or receipt["schema_version"] != 1
            or receipt["scope"] != SCOPE or receipt["fixture_mode"] != MODE
            or receipt["backend"] != "webdav" or receipt["platform"] != "windows"):
        fail("webdav_scope_invalid")
    A.validate_bindings(receipt["bindings"])
    if receipt["bindings"] != expected_bindings:
        fail("webdav_bindings_mismatch")
    runtime = receipt["runtime"]
    _fields(runtime, {"version", "sha256", "platform"}, "webdav_runtime_invalid")
    if (runtime != expected_runtime or runtime["platform"] != "windows" or not valid_hash(runtime["sha256"])
            or type(runtime["version"]) is not str
            or not re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)", runtime["version"])):
        fail("webdav_runtime_invalid")
    if (type(max_age_hours) not in (int, float) or not math.isfinite(max_age_hours)
            or not 0 < max_age_hours <= 24):
        fail("webdav_freshness_limit_invalid")
    created = receipt["created_at"]
    if type(created) is not str or re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", created) is None:
        fail("webdav_timestamp_invalid")
    try:
        created = datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        fail("webdav_timestamp_invalid")
    now = datetime.now(timezone.utc) if now is None else now
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        fail("webdav_now_invalid")
    if created > now + timedelta(minutes=5) or now - created > timedelta(hours=max_age_hours):
        fail("webdav_receipt_stale_or_future")
    _fields(receipt["claims"], FALSE_CLAIMS, "webdav_claims_invalid")
    if any(value is not False for value in receipt["claims"].values()):
        fail("webdav_claims_invalid")
    errors = receipt["errors"]
    if (type(errors) is not list or len(errors) > len(FAILURE_CODES)
            or any(type(code) is not str or code not in FAILURE_CODES for code in errors)
            or len(set(errors)) != len(errors)):
        fail("webdav_errors_invalid")
    if type(receipt["cleanup_complete"]) is not bool:
        fail("webdav_cleanup_invalid")
    cases = receipt["cases"]
    _fields(cases, set(CASE_ORDER), "webdav_cases_invalid")
    leaves = {}
    for name, names in CASE_INVOCATIONS.items():
        case = cases[name]
        _fields(case, {"status", "failure_code", "invocations"}, "webdav_case_fields_invalid")
        _status(case["status"])
        _failure(case["failure_code"], case["status"], errors)
        _fields(case["invocations"], set(names), "webdav_invocations_invalid")
        for leaf, invocation in case["invocations"].items():
            _fields(invocation, {"status", "exit_code", "runtime_sha256", "failure_code", "checks"},
                    "webdav_invocation_fields_invalid")
            status, checks = invocation["status"], invocation["checks"]
            _status(status)
            _failure(invocation["failure_code"], status, errors)
            _checks(checks, INVOCATION_CHECKS[leaf], status)
            code = invocation["exit_code"]
            if code is not None and (type(code) is not int or not -(2 ** 31) <= code < 2 ** 32):
                fail("webdav_exit_invalid")
            if ((checks.get("exit_success") is True and (type(code) is not int or code != 0))
                    or (checks.get("exit_failure") is True and (type(code) is not int or code == 0))):
                fail("webdav_exit_observation_invalid")
            observed = invocation["runtime_sha256"]
            if observed is not None and (not valid_hash(observed) or observed != runtime["sha256"]):
                fail("webdav_runtime_observation_invalid")
            if status == "not_run":
                if code is not None or observed is not None:
                    fail("webdav_unrun_claims")
            elif checks["runtime_observed"] != (observed is not None):
                fail("webdav_runtime_observation_invalid")
            if status == "passed" and (not all(checks.values()) or not _expected_exit(leaf, code)):
                fail("webdav_pass_inconsistent")
            leaves[leaf] = invocation
        statuses = [case["invocations"][leaf]["status"] for leaf in names]
        derived = "passed" if all(value == "passed" for value in statuses) else "not_run" if all(
            value == "not_run" for value in statuses) else "failed"
        if case["status"] != derived:
            fail("webdav_case_status_inconsistent")
    group = receipt["credential_group"]
    _fields(group, {"status", "failure_code", "checks"}, "webdav_group_fields_invalid")
    _status(group["status"])
    _failure(group["failure_code"], group["status"], errors)
    _checks(group["checks"], GROUP_CHECKS, group["status"])
    attempted = [leaves[name] for name in GROUP_INVOCATIONS if leaves[name]["status"] != "not_run"]
    if group["status"] == "not_run" and attempted:
        fail("webdav_group_inconsistent")
    if group["status"] == "passed" and (len(attempted) != 3 or not all(group["checks"].values())):
        fail("webdav_group_inconsistent")
    for invocation in attempted:
        if group["status"] == "failed":
            if invocation["status"] != "failed" or invocation["checks"]["group_finalized"] is not False:
                fail("webdav_group_failure_not_projected")
        elif group["status"] != "passed" or invocation["status"] != "passed":
            fail("webdav_group_inconsistent")
        for key in ("fixture_cleanup", "temp_cleanup"):
            if invocation["checks"][key] != group["checks"][key]:
                fail("webdav_group_cleanup_not_projected")
    # No new invocation can follow a failed operation. Final group observations
    # may invalidate earlier completed epochs; keep those observations truthful.
    stopped = False
    for name in INVOCATION_ORDER:
        invocation = leaves[name]
        if invocation["status"] == "not_run":
            stopped = True
            continue
        if stopped:
            fail("webdav_execution_order_invalid")
        if invocation["status"] == "failed":
            core = INVOCATION_CHECKS[name] - {"fixture_cleanup", "temp_cleanup", "group_finalized"}
            retroactive = (name in GROUP_INVOCATIONS and group["status"] == "failed"
                           and all(invocation["checks"][key] for key in core)
                           and _expected_exit(name, invocation["exit_code"]))
            if not retroactive:
                stopped = True
        if name == "replacement_b" and group["status"] != "passed":
            stopped = True
    if receipt["cleanup_complete"] and (any(
            invocation["status"] != "not_run" and not all(invocation["checks"][key] for key in CLEANUP_CHECKS)
            for invocation in leaves.values()) or (group["status"] != "not_run" and not all(
                group["checks"][key] for key in ("all_processes_reaped", "fixture_cleanup", "temp_cleanup")))):
        fail("webdav_cleanup_inconsistent")
    _fields(receipt["capabilities"], CAPABILITIES, "webdav_capabilities_invalid")
    if receipt["capabilities"] != derive_capabilities(cases, receipt["cleanup_complete"]):
        fail("webdav_capabilities_inconsistent")
    passed = (all(case["status"] == "passed" for case in cases.values()) and group["status"] == "passed"
              and receipt["cleanup_complete"] and not errors)
    if receipt["result"] != ("passed" if passed else "failed"):
        fail("webdav_result_inconsistent")
    if not passed and not errors:
        fail("webdav_failed_without_error")
    return receipt
