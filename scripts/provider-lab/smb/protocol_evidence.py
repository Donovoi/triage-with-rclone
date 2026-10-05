"""Pure contract for fresh, isolated Samba NTLM read evidence; no CLI or services."""
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat

MODE = "smb_samba_ntlm_read_v1"
CAPABILITIES = ("listing", "download_hash", "missing_object_rejection", "authentication_rejection",
                "source_preservation", "config_preservation", "cleanup")
SOURCE_FILES = ("Dockerfile", "build-lock.json", "probe_samba.py", "run_container.py")
HARNESS_FILES = (*SOURCE_FILES, "protocol_evidence.py")
TOP_KEYS = {"schema_version", "scope", "runtime", "platform", "architecture", "harness_sha256",
            "fixture_manifest_sha256", "started_utc", "finished_utc", "success", "cleanup_passed",
            "backends", "errors", "native_evidence"}
NATIVE_KEYS = {"schema_version", "scope", "ledger_eligible", "success", "runtime", "source_sha256",
               "base_image", "image_id", "container_isolation_verified", "probe", "errors", "cleanup",
               "stage", "build_phase", "build_diagnostic", "container_exit_code", "container_stdout_bytes",
               "container_stderr_bytes", "container_startup_diagnostic", "container_oom_killed",
               "container_start_error_present", "build_cache_scope"}
PROBE_KEYS = {"schema_version", "scope", "status", "ledger_eligible", "runtime", "checks", "cleanup",
              "commands_total", "errors"}
PROBE_CHECKS = {"environment", "version_binding", "config_validation", "good_listing_before",
                "good_downloads_before", "bad_password_rejected", "good_listing_after", "good_downloads_after",
                "missing_rejected", "source_preserved", "config_preserved", "seed_preserved"}
PROBE_RUNTIME = {"platform", "uid", "gid", "samba_version", "rclone_version", "smbd_sha256",
                 "rclone_sha256", "probe_sha256", "lock_sha256"}
OUTER_CLEANUP = {"container_removed", "image_removed", "temporary_removed"}
INNER_CLEANUP = {"children_stopped", "listeners_closed", "temporary_removed"}
BUILD_CODES = {
    "bootstrap_cleanup_complete", "bootstrap_cleanup_failed", "bootstrap_cleanup_started",
    "install_apt_failed", "install_apt_passed", "install_apt_started",
    "install_cache_failed", "install_cache_passed", "install_cache_started",
    "install_dependency_check_failed", "install_dependency_check_passed", "install_dependency_check_started",
    "validation_artifact_parity_failed", "validation_complete", "validation_excluded_package_present",
    "validation_input_read_failed", "validation_locked_version_failed", "validation_package_inventory_failed",
    "validation_package_removed", "validation_python_version_failed", "validation_started",
    "validation_unexpected_error", "validation_unlocked_package_change",
}
STARTUP_CODES = {"python_module_missing", "python_import_error", "python_permission_error", "python_syntax_error",
                 "python_startup_failure", "native_loader_failure", "python_exception", "entrypoint_permission_denied"}
WRAPPER_ERRORS = {"smb_native_run_failed", "smb_source_changed", "smb_source_check_failed"}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def hash_value(value):
    return type(value) is str and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def file_bytes(path):
    path = Path(path)
    require(path.is_absolute(), "smb_absolute_source_required")
    for item in (path, *path.parents):
        info = item.lstat()
        require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
                "smb_source_link_refused")
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode), "smb_regular_source_required")
    require(info.st_nlink == 1 and info.st_size <= 1024 * 1024, "smb_source_size_or_link_invalid")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_size, value.st_mtime_ns)
        require(identity(info) == identity(opened), "smb_source_changed")
        body = stream.read(1024 * 1024 + 1)
        require(identity(info) == identity(os.fstat(stream.fileno())), "smb_source_changed")
    require(identity(info) == identity(path.lstat()), "smb_source_changed")
    require(len(body) <= 1024 * 1024, "smb_source_size_or_link_invalid")
    return body


def compute_harness_sha256(smb_root):
    digest = hashlib.sha256()
    for name in sorted(HARNESS_FILES):
        digest.update(name.encode("utf-8") + b"\0" + file_bytes(Path(smb_root) / name) + b"\0")
    return digest.hexdigest()


def compute_source_hashes(smb_root):
    return {name: hashlib.sha256(file_bytes(Path(smb_root) / name)).hexdigest() for name in SOURCE_FILES}


def compute_fixture_manifest_sha256(smb_root):
    path = Path(smb_root) / "probe_samba.py"
    source = file_bytes(path)
    spec = importlib.util.spec_from_file_location("synthetic_smb_manifest", path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(source, str(path), "exec"), module.__dict__)  # Pure definitions; no main or bytecode files.
    files = module.FILES
    require(type(files) is dict and len(files) == 3 and all(type(k) is str and type(v) is bytes for k, v in files.items()),
            "smb_fixture_manifest_invalid")
    manifest = [{"path": name, "size": len(body), "sha256": hashlib.sha256(body).hexdigest()}
                for name, body in sorted(files.items())]
    return hashlib.sha256(json.dumps(manifest, separators=(",", ":")).encode()).hexdigest()


def compute_bindings(smb_root):
    lock = json.loads(file_bytes(Path(smb_root) / "build-lock.json"))
    base, version = lock["base_image"], lock["runtime_expected"]["samba_version"]
    require(type(base) is str and re.fullmatch(r"docker\.io/library/debian@sha256:[a-f0-9]{64}", base), "smb_base_image_invalid")
    require(type(version) is str and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+:~_-]{0,60}", version),
            "smb_server_version_invalid")
    return {"harness_sha256": compute_harness_sha256(smb_root),
            "fixture_manifest_sha256": compute_fixture_manifest_sha256(smb_root),
            "source_sha256": compute_source_hashes(smb_root), "base_image": base, "samba_version": version}


def exact_object(value, keys, code):
    require(type(value) is dict and set(value) == keys, code)


def bool_map(value, keys):
    exact_object(value, keys, "smb_boolean_shape_invalid")
    require(all(type(x) is bool for x in value.values()), "smb_boolean_type_invalid")


def errors(value):
    require(type(value) is list and len(value) <= 32 and len(set(x for x in value if type(x) is str)) == len(value)
            and all(type(x) is str and re.fullmatch(r"[a-z][a-z0-9_]{0,79}", x) for x in value), "smb_errors_invalid")


def utc(value):
    require(type(value) is str and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value),
            "smb_time_invalid")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("smb_time_invalid") from None


def runtime_matches(value, expected):
    exact_object(value, {"version", "sha256"}, "smb_runtime_shape_invalid")
    require(type(value["version"]) is str and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value["version"])
            and hash_value(value["sha256"]) and value == {key: expected.get(key) for key in ("version", "sha256")}
            and expected.get("platform", "linux") == "linux", "smb_runtime_mismatch")


def validate_evidence(receipt, runtime, expected_harness_sha256, expected_fixture_manifest_sha256,
                      expected_source_hashes, now, max_age_hours=24, *, expected_base_image, expected_samba_version):
    """Validate against trusted current bindings; return None or a static ValueError."""
    exact_object(receipt, TOP_KEYS, "smb_receipt_shape_invalid")
    require(type(receipt["schema_version"]) is int and receipt["schema_version"] == 3
            and receipt["scope"] == "rclone_backend_protocol_fixture" and receipt["platform"] == "linux"
            and receipt["architecture"] == "amd64", "smb_receipt_scope_invalid")
    runtime_matches(receipt["runtime"], runtime)
    require(hash_value(expected_harness_sha256) and receipt["harness_sha256"] == expected_harness_sha256
            and hash_value(expected_fixture_manifest_sha256) and receipt["fixture_manifest_sha256"] == expected_fixture_manifest_sha256,
            "smb_source_binding_mismatch")
    exact_object(expected_source_hashes, set(SOURCE_FILES), "smb_expected_sources_invalid")
    require(all(hash_value(x) for x in expected_source_hashes.values()), "smb_expected_sources_invalid")
    start, finish = utc(receipt["started_utc"]), utc(receipt["finished_utc"])
    require(isinstance(now, datetime) and now.tzinfo is not None and now.utcoffset() is not None
            and type(max_age_hours) is int and 1 <= max_age_hours <= 168, "smb_freshness_policy_invalid")
    require(start <= finish <= now and finish >= now - timedelta(hours=max_age_hours)
            and finish - start <= timedelta(minutes=30), "smb_receipt_stale_or_duration_invalid")
    require(type(receipt["success"]) is bool and type(receipt["cleanup_passed"]) is bool, "smb_status_type_invalid")
    errors(receipt["errors"])
    require(set(receipt["errors"]) <= WRAPPER_ERRORS, "smb_wrapper_errors_invalid")
    rows = receipt["backends"]
    require(type(rows) is list and len(rows) == 1, "smb_backend_count_invalid")
    row = rows[0]
    exact_object(row, {"backend", "fixture_kind", "fixture_mode", "capabilities", "errors"}, "smb_backend_shape_invalid")
    require(row["backend"] == "smb" and row["fixture_kind"] == "independent_samba_container"
            and row["fixture_mode"] == MODE, "smb_backend_scope_invalid")
    exact_object(row["capabilities"], set(CAPABILITIES), "smb_capabilities_invalid")
    require(row["errors"] == receipt["errors"], "smb_backend_errors_mismatch")

    native = receipt["native_evidence"]
    exact_object(native, NATIVE_KEYS, "smb_native_shape_invalid")
    require(type(native["schema_version"]) is int and native["schema_version"] == 1
            and native["scope"] == "smb_samba_container_feasibility_only" and native["ledger_eligible"] is False
            and native["build_cache_scope"] == "shared_daemon_cache_not_pruned", "smb_native_scope_invalid")
    runtime_matches(native["runtime"], runtime)
    require(native["source_sha256"] == expected_source_hashes and type(native["source_sha256"]) is dict
            and native["base_image"] == expected_base_image, "smb_native_binding_mismatch")
    require(type(native["success"]) is bool and type(native["container_isolation_verified"]) is bool, "smb_native_status_invalid")
    require(native["image_id"] is None or type(native["image_id"]) is str
            and re.fullmatch(r"sha256:[a-f0-9]{64}", native["image_id"]), "smb_image_id_invalid")
    require(native["stage"] in ("preflight", "pull", "build", "create", "probe", "completed")
            and native["build_phase"] in (None, "metadata", "deb-download", "install", "seed", "manifest")
            and (native["build_diagnostic"] is None or type(native["build_diagnostic"]) is str and native["build_diagnostic"] in BUILD_CODES)
            and (native["container_startup_diagnostic"] is None or type(native["container_startup_diagnostic"]) is str
                 and native["container_startup_diagnostic"] in STARTUP_CODES), "smb_diagnostic_invalid")
    for field, limit in (("container_stdout_bytes", 4 * 1024 * 1024), ("container_stderr_bytes", 4 * 1024 * 1024)):
        require(native[field] is None or type(native[field]) is int and 0 <= native[field] <= limit, "smb_output_size_invalid")
    require(native["container_exit_code"] is None or type(native["container_exit_code"]) is int
            and -255 <= native["container_exit_code"] <= 255, "smb_exit_code_invalid")
    require(all(native[x] is None or type(native[x]) is bool for x in ("container_oom_killed", "container_start_error_present")),
            "smb_native_status_invalid")
    bool_map(native["cleanup"], OUTER_CLEANUP)
    errors(native["errors"])
    probe = native["probe"]
    inner_pass, inner_cleanup = False, False
    if probe is not None:
        exact_object(probe, PROBE_KEYS, "smb_probe_shape_invalid")
        require(type(probe["schema_version"]) is int and probe["schema_version"] == 1
                and probe["scope"] == "smb_samba_feasibility_only" and probe["ledger_eligible"] is False
                and probe["status"] in ("passed", "failed"), "smb_probe_scope_invalid")
        bool_map(probe["checks"], PROBE_CHECKS)
        bool_map(probe["cleanup"], INNER_CLEANUP)
        errors(probe["errors"])
        require(type(probe["commands_total"]) is int and 0 <= probe["commands_total"] <= 20, "smb_probe_commands_invalid")
        identity = probe["runtime"]
        exact_object(identity, PROBE_RUNTIME, "smb_probe_runtime_invalid")
        require(identity["platform"] == "linux/amd64" and type(identity["uid"]) is int and identity["uid"] == 10001
                and type(identity["gid"]) is int and identity["gid"] == 10001
                and identity["rclone_version"] == runtime["version"] and identity["rclone_sha256"] == runtime["sha256"],
                "smb_probe_runtime_mismatch")
        for field, expected in (("probe_sha256", expected_source_hashes["probe_samba.py"]),
                                ("lock_sha256", expected_source_hashes["build-lock.json"]), ("samba_version", expected_samba_version)):
            require(identity[field] is None or identity[field] == expected, "smb_probe_source_mismatch")
        require(identity["smbd_sha256"] is None or hash_value(identity["smbd_sha256"]), "smb_probe_hash_invalid")
        inner_cleanup = all(probe["cleanup"].values())
        inner_pass = (not probe["errors"] and all(probe["checks"].values()) and inner_cleanup
                      and probe["commands_total"] == 16 and all(identity[x] is not None for x in PROBE_RUNTIME))
        require((probe["status"] == "passed") is inner_pass, "smb_probe_success_contradiction")
    cleanup = all(native["cleanup"].values()) and inner_cleanup
    native_pass = (inner_pass and cleanup and native["container_isolation_verified"] and native["image_id"] is not None
                   and not native["errors"] and native["stage"] == "completed" and native["build_phase"] == "manifest"
                   and native["build_diagnostic"] == "bootstrap_cleanup_complete" and native["container_exit_code"] == 0
                   and type(native["container_exit_code"]) is int and native["container_oom_killed"] is False
                   and native["container_start_error_present"] is False and native["container_startup_diagnostic"] is None
                   and type(native["container_stdout_bytes"]) is int and native["container_stdout_bytes"] > 0
                   and type(native["container_stderr_bytes"]) is int)
    require(native["success"] is native_pass, "smb_native_success_contradiction")
    success = native_pass and not receipt["errors"]
    require(receipt["success"] is success and receipt["cleanup_passed"] is cleanup
            and (native_pass or "smb_native_run_failed" in receipt["errors"]), "smb_success_contradiction")
    require(all(type(value) is str and value == ("passed" if success else "failed")
                for value in row["capabilities"].values()), "smb_capability_promotion_invalid")
