#!/usr/bin/env python3
"""Pure validation of the separate hosted manual-HTTP TUI experiment.

No producer imports or native execution. A valid receipt remains a source-bound
harness assertion, not CLI-ledger, vendor, or all-provider acceptance. The caller
must separately verify that the supplied build commit produced the binary.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


ROOT = Path(__file__).resolve().parents[1]
SCOPE = "windows_manual_http_tui_experiment"
AUDIT_SCOPE = "windows_manual_http_tui_validation"
CASE_ORDER = ("manual_acquisition", "escape_cancellation", "session_reset")
COMMON_CHECKS = frozenset({"manual_setup", "runtime_setup", "listing_artifacts", "selection_exact",
    "runtime_transfer", "manifest_and_payloads", "configuration_preserved", "fixture_valid",
    "source_preserved", "orderly_exit", "terminal_closed", "process_cleanup", "fixture_cleanup", "temp_cleanup"})
CASE_CHECKS = {
    "manual_acquisition": COMMON_CHECKS,
    "escape_cancellation": COMMON_CHECKS | {"active_partial", "cancel_requested", "cancelled_result"},
    "session_reset": COMMON_CHECKS | {"reset_source_replaced", "prior_acquisition_preserved"},
}
FAILURE_CODES = frozenset({"binding_failed", "case_setup_failed", "session_failed", "runtime_unobserved",
    "fixture_failed", "deadline_exceeded", "listing_invalid", "manifest_invalid", "outputs_invalid",
    "preservation_failed", "cancellation_failed", "cleanup_failed", "unexpected_failure",
    "navigation_state", "navigation_input", "navigation_budget", "navigation_failed", "navigation_timeout",
    "navigation_observer", "navigation_screen", "navigation_catalog", "tui_artifacts_invalid",
    "tui_screen_invalid", "tui_fixture_invalid"})
FAILURE_PHASES = frozenset({"case_setup", "fixture_start", "session_start", "main_menu", "provider_selection",
    "manual_setup", "listing_validation", "file_selection", "acquisition_start", "active_partial",
    "cancellation", "completion", "acquisition_validation", "source_reset", "orderly_exit", "session_cleanup",
    "fixture_cleanup", "artifact_validation", "case_cleanup", "final_validation"})
LIMITATIONS = ("no_vendor_acceptance", "no_oauth_or_refresh", "no_listing_cancel_recovery",
    "no_resize_acceptance", "no_mount_or_webgui", "no_all_provider_qualification")
CLI_HARNESS_FILES = (
    "scripts/application_evidence.py", "scripts/application-lab/fixture_http.py",
    "scripts/application-lab/HostedConPtySession.cs", "scripts/application-lab/hosted_session.ps1",
    "scripts/application-lab/prepare_case.ps1", "scripts/application-lab/run_windows_http.py",
)
HARNESS_FILES = tuple(sorted(CLI_HARNESS_FILES + (
    "scripts/tui_application_evidence.py", "scripts/application-lab/run_windows_tui.py",
    "scripts/application-lab/tui_controller.py", "scripts/application-lab/tui_navigation.py",
    "scripts/application-lab/tui_screen.py", "scripts/application-lab/tui_oracles.py",
    "scripts/application-lab/fixture_tui_http.py", "scripts/application-lab/hosted_tui_session.ps1",
)))
BINDING_KEYS = frozenset({"application_sha256", "application_source_sha256", "build_commit", "build_target",
    "build_profile", "cargo_lock_sha256", "runtime_manifest_sha256", "harness_sha256",
    "fixture_manifest_sha256", "tui_harness_sha256"})
RECEIPT_KEYS = frozenset({"schema_version", "scope", "platform", "backend", "created_at", "runtime",
    "bindings", "cases", "errors", "cleanup_complete", "result", "limitations"})
CASE_KEYS = frozenset({"status", "failure_code", "failure_phase", "exit_code", "checks", "listing_observations"})
MAX_RECEIPT_BYTES = 128 * 1024
MAX_SOURCE_FILES = 1024
VALIDATION_CODES = frozenset({"input_invalid", "input_unreadable", "input_changed", "input_limit",
    "json_invalid", "fields_invalid", "scope_invalid", "bindings_invalid", "bindings_mismatch",
    "runtime_invalid", "runtime_mismatch", "freshness_invalid", "case_invalid", "checks_invalid",
    "listing_invalid", "execution_order_invalid", "failure_invalid", "cleanup_invalid", "result_invalid",
    "limitations_invalid", "report_write_failed"})


class TuiEvidenceError(ValueError):
    def __init__(self, code):
        self.code = code if code in VALIDATION_CODES else "input_invalid"
        super().__init__(self.code)


def need(condition, code):
    if not condition:
        raise TuiEvidenceError(code)


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def valid_hash(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _shape(value, keys, code):
    need(type(value) is dict and set(value) == set(keys), code)


def _stamp(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _path_state(path, directory=False):
    path = Path(path).absolute()
    states = []
    for index, item in enumerate((path, *path.parents)):
        info = item.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
             "input_invalid")
        need(stat.S_ISDIR(info.st_mode) if index or directory else stat.S_ISREG(info.st_mode), "input_invalid")
        states.append((info.st_dev, info.st_ino))
    return tuple(states)


def _file(path, limit, *, content=False):
    """Bounded same-handle reads; path/handle identity checked before and after."""
    path = Path(path).absolute()
    try:
        parents = _path_state(path)
        before = path.lstat()
        need(before.st_size <= limit, "input_limit")
        digest, chunks, size = hashlib.sha256(), [], 0
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            need(_stamp(opened) == _stamp(before), "input_changed")
            while True:
                data = stream.read(min(1024 * 1024, limit - size + 1))
                if not data:
                    break
                size += len(data)
                need(size <= limit, "input_limit")
                digest.update(data)
                if content:
                    chunks.append(data)
            after = os.fstat(stream.fileno())
            need(_stamp(after) == _stamp(opened) and after.st_ctime_ns == opened.st_ctime_ns,
                 "input_changed")
        final = path.lstat()
        need(size == before.st_size and _stamp(final) == _stamp(before)
             and final.st_ctime_ns == before.st_ctime_ns and _path_state(path) == parents, "input_changed")
        return b"".join(chunks) if content else digest.hexdigest()
    except OSError:
        raise TuiEvidenceError("input_unreadable") from None


def _source_names(root):
    source = root / "rclone-triage/src"
    _path_state(source, True)
    names = ["rclone-triage/Cargo.toml", "rclone-triage/Cargo.lock", "rclone-triage/build.rs",
             "rclone-triage/.cargo/config.toml"]
    stack, seen = [source], 0
    while stack:
        parent = stack.pop()
        with os.scandir(parent) as entries:
            for entry in entries:
                seen += 1
                need(seen <= MAX_SOURCE_FILES, "input_limit")
                info = entry.stat(follow_symlinks=False)
                need(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
                     "input_invalid")
                if stat.S_ISDIR(info.st_mode):
                    stack.append(Path(entry.path))
                else:
                    need(stat.S_ISREG(info.st_mode), "input_invalid")
                    names.append(Path(entry.path).relative_to(root).as_posix())
    need(len(names) > 4, "bindings_invalid")
    return tuple(sorted(names))


def tree_hash(root, names):
    need(len(names) == len(set(names)) and 0 < len(names) <= MAX_SOURCE_FILES, "bindings_invalid")
    rows = [[name, _file(Path(root) / name, 2 * 1024 * 1024)] for name in sorted(names)]
    return hashlib.sha256(compact(rows)).hexdigest()


def fixture_manifest():
    # Independent fixed bytes, never read values from a running fixture/producer.
    return [{"path": path, "size": size, "sha256": digest} for path, size, digest in (
        ("README-synthetic.txt", 30, "64d5b40a5f4773b14940a6ce1dd57cf87b44ce5940c097088732ffc71be280cf"),
        ("large/cancel.bin", 2097152, "91d3beb88a9b2f778a6c44a1c53b63d3c79931845a9aef84b3fb414610bd1938"),
        ("nested/binary.bin", 256, "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880"),
        ("nested/spaced name.txt", 20, "0c6308d568f8ec30fbf044baac7827edac83a2465a60439ff653e277a5d9619e"),
    )]


def compute_bindings(root, application, build_commit):
    need(type(build_commit) is str and re.fullmatch(r"[0-9a-f]{40}", build_commit), "bindings_invalid")
    root = Path(root).absolute()
    try:
        names = _source_names(root)
        result = dict(application_sha256=_file(application, 512 * 1024 * 1024),
            application_source_sha256=tree_hash(root, names), build_commit=build_commit,
            build_target="x86_64-pc-windows-msvc", build_profile="release",
            cargo_lock_sha256=_file(root / "rclone-triage/Cargo.lock", 2 * 1024 * 1024),
            runtime_manifest_sha256=_file(root / "rclone-version.env", 4096),
            harness_sha256=tree_hash(root, CLI_HARNESS_FILES),
            fixture_manifest_sha256=hashlib.sha256(compact(fixture_manifest())).hexdigest(),
            tui_harness_sha256=tree_hash(root, HARNESS_FILES))
        need(names == _source_names(root), "input_changed")
        return result
    except OSError:
        raise TuiEvidenceError("input_unreadable") from None


def runtime_pins(root):
    values = {}
    try:
        for line in _file(Path(root) / "rclone-version.env", 4096, content=True).decode("ascii").splitlines():
            if not line or line.startswith("#"):
                continue
            key, separator, value = line.partition("=")
            need(separator and key not in values, "runtime_invalid")
            values[key] = value
    except UnicodeError:
        raise TuiEvidenceError("runtime_invalid") from None
    keys = {"RCLONE_VERSION", "RCLONE_EXE_SHA256", "RCLONE_WINDOWS_ZIP_SHA256",
            "RCLONE_LINUX_ZIP_SHA256", "RCLONE_LINUX_EXE_SHA256", "RCLONE_WINDOWS_X86_EXE_SHA256",
            "RCLONE_WINDOWS_X86_ZIP_SHA256", "RCLONE_WINDOWS_ARM64_EXE_SHA256", "RCLONE_WINDOWS_ARM64_ZIP_SHA256"}
    need(set(values) == keys and re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)",
                                           values["RCLONE_VERSION"]), "runtime_invalid")
    need(all(valid_hash(value) for key, value in values.items() if key != "RCLONE_VERSION"), "runtime_invalid")
    return {"version": values["RCLONE_VERSION"], "sha256": values["RCLONE_EXE_SHA256"], "platform": "windows"}


def decode_receipt(data):
    need(type(data) is bytes and 0 < len(data) <= MAX_RECEIPT_BYTES, "input_limit")
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "json_invalid")
            result[key] = value
        return result
    def constant(_value):
        raise TuiEvidenceError("json_invalid")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError):
        raise TuiEvidenceError("json_invalid") from None
    pending, count = [(value, 0)], 0
    while pending:
        node, depth = pending.pop()
        count += 1
        need(count <= 4096 and depth <= 12, "input_limit")
        if type(node) is dict:
            pending.extend((item, depth + 1) for pair in node.items() for item in pair)
        elif type(node) is list:
            pending.extend((item, depth + 1) for item in node)
        elif type(node) is str:
            need(len(node) <= 1024, "input_limit")
        else:
            need(node is None or type(node) is bool or type(node) is int and -(2 ** 63) <= node < 2 ** 64,
                 "json_invalid")
    return value


def _bindings(value):
    _shape(value, BINDING_KEYS, "bindings_invalid")
    need(all(valid_hash(v) for k, v in value.items() if k.endswith("_sha256")), "bindings_invalid")
    need(type(value["build_commit"]) is str and re.fullmatch(r"[0-9a-f]{40}", value["build_commit"])
         and value["build_target"] == "x86_64-pc-windows-msvc" and value["build_profile"] == "release",
         "bindings_invalid")


def _runtime(value):
    _shape(value, {"version", "sha256", "platform"}, "runtime_invalid")
    need(value["platform"] == "windows" and valid_hash(value["sha256"]) and type(value["version"]) is str
         and re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", value["version"]),
         "runtime_invalid")


def validate_receipt(receipt, expected_runtime, expected_bindings, *, now=None, max_age_hours=24):
    """Return a defensive normalized copy; a valid failed receipt stays failed."""
    _runtime(expected_runtime)
    _bindings(expected_bindings)
    _shape(receipt, RECEIPT_KEYS, "fields_invalid")
    need(type(receipt["schema_version"]) is int and receipt["schema_version"] == 1
         and receipt["scope"] == SCOPE and receipt["platform"] == "windows" and receipt["backend"] == "http",
         "scope_invalid")
    _runtime(receipt["runtime"])
    _bindings(receipt["bindings"])
    need(receipt["runtime"] == expected_runtime, "runtime_mismatch")
    need(receipt["bindings"] == expected_bindings, "bindings_mismatch")
    created = receipt["created_at"]
    need(type(created) is str and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", created),
         "freshness_invalid")
    try:
        created = datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise TuiEvidenceError("freshness_invalid") from None
    now = datetime.now(timezone.utc) if now is None else now
    need(type(now) is datetime and now.tzinfo is not None and now.utcoffset() is not None
         and type(max_age_hours) is int and 0 < max_age_hours <= 24, "freshness_invalid")
    need(created <= now + timedelta(minutes=5) and now - created <= timedelta(hours=max_age_hours), "freshness_invalid")
    need(type(receipt["limitations"]) is list and receipt["limitations"] == list(LIMITATIONS), "limitations_invalid")
    _shape(receipt["cases"], CASE_ORDER, "case_invalid")
    errors = receipt["errors"]
    need(type(errors) is list and len(errors) <= len(FAILURE_CODES)
         and all(type(code) is str and code in FAILURE_CODES for code in errors)
         and len(errors) == len(set(errors)), "failure_invalid")
    need(type(receipt["cleanup_complete"]) is bool, "cleanup_invalid")
    stopped = False
    for name in CASE_ORDER:
        case = receipt["cases"][name]
        _shape(case, CASE_KEYS, "case_invalid")
        checks = case["checks"]
        _shape(checks, CASE_CHECKS[name], "checks_invalid")
        need(all(type(value) is bool for value in checks.values()), "checks_invalid")
        status, code, phase, exit_code = (case[key] for key in ("status", "failure_code", "failure_phase", "exit_code"))
        need(type(status) is str and status in ("passed", "failed", "not_run"), "case_invalid")
        need(exit_code is None or type(exit_code) is int and -(2 ** 31) <= exit_code < 2 ** 32, "case_invalid")
        observations = case["listing_observations"]
        required = 2 if name == "session_reset" else 1
        need(type(observations) is list and len(observations) <= required, "listing_invalid")
        for observation in observations:
            _shape(observation, {"files", "directories", "csv_sha256", "xlsx_sha256"}, "listing_invalid")
            need(type(observation["files"]) is int and observation["files"] == 4
                 and type(observation["directories"]) is int and observation["directories"] == 2
                 and valid_hash(observation["csv_sha256"]) and valid_hash(observation["xlsx_sha256"]), "listing_invalid")
        if status == "not_run":
            need(not any(checks.values()) and code is None and phase is None and exit_code is None and not observations,
                 "case_invalid")
            stopped = True
            continue
        need(not stopped, "execution_order_invalid")
        if status == "passed":
            need(all(checks.values()) and exit_code == 0 and code is None and phase is None
                 and len(observations) == required, "case_invalid")
        else:
            need(type(code) is str and code in FAILURE_CODES and type(phase) is str
                 and phase in FAILURE_PHASES and code in errors, "failure_invalid")
            stopped = True
        need(not checks["orderly_exit"] or exit_code == 0, "case_invalid")
        need(not checks["temp_cleanup"] or checks["process_cleanup"] and checks["fixture_cleanup"], "cleanup_invalid")
        need(not checks["listing_artifacts"] or bool(observations), "listing_invalid")
        need(not checks["manual_setup"] or bool(observations), "listing_invalid")
        if name == "escape_cancellation":
            need(not checks["cancel_requested"] or checks["active_partial"], "checks_invalid")
            need(not checks["cancelled_result"] or checks["cancel_requested"], "checks_invalid")
        if name == "session_reset":
            need(not (checks["reset_source_replaced"] or checks["prior_acquisition_preserved"])
                 or len(observations) == 2 and all(checks[key] for key in
                    ("manifest_and_payloads", "listing_artifacts", "configuration_preserved", "fixture_valid", "source_preserved")),
                 "checks_invalid")
        if receipt["cleanup_complete"]:
            need(all(checks[key] for key in ("process_cleanup", "fixture_cleanup", "temp_cleanup")), "cleanup_invalid")
    passed = all(receipt["cases"][name]["status"] == "passed" for name in CASE_ORDER)
    expected_result = "passed" if passed and receipt["cleanup_complete"] and not errors else "failed"
    need(receipt["result"] == expected_result and (expected_result == "passed" or bool(errors)), "result_invalid")
    return json.loads(compact(receipt))


def audit_bytes(data, expected_runtime, expected_bindings, *, now=None):
    digest = hashlib.sha256(data).hexdigest() if type(data) is bytes else None
    try:
        receipt = validate_receipt(decode_receipt(data), expected_runtime, expected_bindings, now=now)
        valid, result, errors = True, receipt["result"], []
    except TuiEvidenceError as error:
        valid, result, errors, receipt = False, "invalid", [error.code], None
    return dict(schema_version=1, scope=AUDIT_SCOPE, receipt_sha256=digest, valid=valid, result=result,
                errors=errors, receipt=receipt, ledger_eligible=False, application_accepted=False,
                vendor_accepted=False, provider_accepted=False)


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise TuiEvidenceError("input_invalid")


def main(argv=None):
    parser = _Parser(description=__doc__)
    for name in ("receipt", "application", "build-commit", "report"):
        parser.add_argument("--" + name, required=True)
    try:
        args = parser.parse_args(argv)
    except TuiEvidenceError:
        print("tui_validation_input_invalid", file=sys.stderr)
        return 2
    audit = None
    data = None
    try:
        data = _file(args.receipt, MAX_RECEIPT_BYTES, content=True)
        bindings = compute_bindings(ROOT, args.application, args.build_commit)
        runtime = runtime_pins(ROOT)
        audit = audit_bytes(data, runtime, bindings)
        need(bindings == compute_bindings(ROOT, args.application, args.build_commit)
             and runtime == runtime_pins(ROOT)
             and data == _file(args.receipt, MAX_RECEIPT_BYTES, content=True), "input_changed")
    except (TuiEvidenceError, OSError, ValueError) as error:
        code = error.code if isinstance(error, TuiEvidenceError) else "input_invalid"
        audit = dict(schema_version=1, scope=AUDIT_SCOPE,
                     receipt_sha256=hashlib.sha256(data).hexdigest() if data is not None else None,
                     valid=False, result="invalid", errors=[code], receipt=None, ledger_eligible=False,
                     application_accepted=False, vendor_accepted=False, provider_accepted=False)
    try:
        output = compact(audit) + b"\n"
        need(len(output) <= MAX_RECEIPT_BYTES, "input_limit")
        path = Path(args.report).absolute()
        parent_state = _path_state(path.parent, True)
        # Sanitized create-new output only; never replace an input or old report.
        with path.open("xb") as stream:
            stream.write(output)
            stream.flush()
            os.fsync(stream.fileno())
        need(_path_state(path.parent, True) == parent_state, "input_changed")
    except (OSError, TuiEvidenceError):
        print("tui_validation_report_write_failed", file=sys.stderr)
        return 2
    return 0 if audit["result"] == "passed" else 1 if audit["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
