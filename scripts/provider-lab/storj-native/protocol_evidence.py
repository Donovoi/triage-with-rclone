"""Pure, fail-closed contract for native Storj and Tardigrade read evidence."""
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path
import re
import stat

MODE = "storj_saved_access_grant_native_read_v1"
BACKENDS = ("storj", "tardigrade")
CAPABILITIES = ("listing", "download_hash", "missing_object_rejection", "authentication_rejection",
                "read_denial", "source_preservation", "config_preservation", "fixture_write_rejection", "cleanup")
SOURCE_FILES = ("Dockerfile", "pins.json", "planet_test.go", "entrypoint.sh", "build_fixture.py", "run_container.py")
HARNESS_FILES = (*SOURCE_FILES, "protocol_evidence.py")
TOP_KEYS = {"schema_version", "scope", "runtime", "platform", "architecture", "harness_sha256",
            "fixture_manifest_sha256", "started_utc", "finished_utc", "success", "cleanup_passed",
            "backends", "errors", "native_evidence"}
NATIVE_KEYS = {"source_sha256", "build", "base_image", "image_id", "isolation_verified",
               "probe", "exit_code", "oom_killed", "stdout_bytes", "stderr_bytes", "cleanup"}
BUILD_KEYS = {"schema_version", "success", "source_commit", "source_archive_sha256", "helper_sha256",
              "compiler_image", "compiler_version", "builder_removed", "scratch_removed",
              "binary_sha256", "binary_bytes", "resources_sha256", "seconds"}
PROBE_KEYS = {"success", "backends", "configuration_preserved", "source_preserved", "inline_segments",
              "remote_segments", "remote_pieces", "native_checks"}
CLEANUP_KEYS = {"container_removed", "image_removed", "temporary_removed"}
HASH = re.compile(r"[a-f0-9]{64}")

def require(value, code):
    if not value:
        raise ValueError("storj_" + code)

def exact(value, keys, code):
    require(type(value) is dict and set(value) == set(keys), code)

def integer(value, low, high):
    return type(value) is int and low <= value <= high

def sha(value):
    return type(value) is str and HASH.fullmatch(value) is not None

def file_bytes(path, maximum=1024*1024):
    path = Path(path)
    require(path.is_absolute(), "absolute_source_required")
    for item in (path, *path.parents):
        require(not item.is_symlink(), "source_link_refused")
    before = path.stat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum,
            "source_file_invalid")
    data = path.read_bytes()
    after = path.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) and len(data) <= maximum,
            "source_changed")
    return data

def manifest():
    files = {
        "README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
        "nested/space name.txt": b"Nested synthetic payload.\n",
        "nested/bytes.bin": bytes(range(256))*8,
        "nested/remote-piece.bin": bytes((i*17+i//257)%256 for i in range(1024*1024)),
    }
    return [{"path": k, "size": len(v), "sha256": hashlib.sha256(v).hexdigest()}
            for k, v in sorted(files.items())]

def compact_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def compute_bindings(root):
    root = Path(root).absolute()
    sources = {name: hashlib.sha256(file_bytes(root/name)).hexdigest() for name in HARNESS_FILES}
    digest = hashlib.sha256()
    for name in sorted(HARNESS_FILES):
        digest.update(name.encode()+b"\0"+file_bytes(root/name)+b"\0")
    pins = json.loads(file_bytes(root/"pins.json"))
    require(pins["storj_commit"] == "b2fe6e00c07c42711217c1c60c283d5e000b18ba"
            and pins["rclone_version"] == "1.76.0"
            and pins["rclone_sha256"] == "62e4d3e5432f2c685f1834b8bb342058ff0611c99d048aeb44bb8d8fd611527e",
            "pin_revision_invalid")
    return {"source_sha256": {k: sources[k] for k in SOURCE_FILES},
            "harness_sha256": digest.hexdigest(), "fixture_manifest_sha256": compact_hash(manifest()),
            "pins": pins}

def validate_build(build, bindings):
    exact(build, BUILD_KEYS, "build_shape_invalid")
    pins = bindings["pins"]
    require(type(build["schema_version"]) is int and build["schema_version"] == 1
            and build["success"] is True and build["builder_removed"] is True
            and build["scratch_removed"] is True, "build_incomplete")
    for key in ("source_commit", "source_archive_sha256", "compiler_image", "compiler_version"):
        pin = {"source_commit": "storj_commit", "compiler_version": "go_version"}.get(key, key)
        require(build[key] == pins[pin], "build_source_mismatch")
    require(build["helper_sha256"] == bindings["source_sha256"]["planet_test.go"]
            and sha(build["binary_sha256"]) and integer(build["binary_bytes"], 1024*1024, 192*1024*1024),
            "build_binary_invalid")
    require(type(build["seconds"]) in (int, float) and 0 < build["seconds"] < 1200, "build_duration_invalid")
    resources = build["resources_sha256"]
    require(type(resources) is dict and len(resources) == 99 and all(
        type(k) is str and re.fullmatch(r"static/(emails|errors)/[A-Za-z0-9_.-]+", k) and sha(v)
        for k,v in resources.items()) and compact_hash(resources) == pins["resources_manifest_sha256"],
        "build_resources_mismatch")

def expected_commands():
    commands = [("listing-read", 0, None), ("listing-list-only", 0, None)]
    for row in manifest():
        commands += [("cat:"+row["path"], 0, row["size"]), ("copy:"+row["path"], 0, 0)]
    commands += [("range:nested/bytes.bin", 0, 11), ("range:nested/remote-piece.bin", 0, 8193),
                 ("unknown-key-list-denied", 1, 2), ("expired-list-denied", 1, 2), ("cat-denied", 1, 0), ("copy-denied", 1, 0),
                 ("cat-denied", 1, 0), ("copy-denied", 1, 0), ("missing-copy", 9, 0),
                 ("delete-denied", 1, 0), ("upload-denied", 1, 0), ("listing-read", 0, None)]
    return [(backend,*row) for backend in BACKENDS for row in commands]

def validate_probe(probe):
    exact(probe, PROBE_KEYS, "probe_shape_invalid")
    require(probe["success"] is True and probe["backends"] == list(BACKENDS)
            and probe["configuration_preserved"] is True and probe["source_preserved"] is True,
            "probe_incomplete")
    require(integer(probe["inline_segments"], 3, 3) and integer(probe["remote_segments"], 1, 8)
            and integer(probe["remote_pieces"], 2, 24), "remote_storage_unproven")
    checks = probe["native_checks"]; expected = expected_commands()
    require(type(checks) is list and len(checks) == len(expected), "native_command_count_invalid")
    for row, (backend, label, code, size) in zip(checks, expected):
        exact(row, {"backend", "case", "exit", "bytes"}, "native_command_shape_invalid")
        require(row["backend"] == backend and row["case"] == label
                and integer(row["exit"], code, code) and integer(row["bytes"], 0, 2*1024*1024)
                and (row["bytes"] == size if size is not None else 400 <= row["bytes"] <= 4096),
                "native_command_mismatch")

def utc(value):
    require(type(value) is str and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value),
            "time_invalid")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("storj_time_invalid") from None

def validate_evidence(receipt, runtime, bindings, now, max_age_hours=24):
    exact(receipt, TOP_KEYS, "receipt_shape_invalid")
    require(type(receipt["schema_version"]) is int and receipt["schema_version"] == 36
            and receipt["scope"] == "rclone_backend_protocol_fixture" and receipt["platform"] == "linux"
            and receipt["architecture"] == "amd64", "receipt_scope_invalid")
    exact(receipt["runtime"], {"version", "sha256"}, "runtime_shape_invalid")
    require(receipt["runtime"] == {k:runtime.get(k) for k in ("version","sha256")}
            and receipt["runtime"] == {"version":bindings["pins"]["rclone_version"], "sha256":bindings["pins"]["rclone_sha256"]}
            and runtime.get("platform","linux") == "linux", "runtime_mismatch")
    for key in ("harness_sha256", "fixture_manifest_sha256"):
        require(sha(bindings[key]) and receipt[key] == bindings[key], "source_binding_mismatch")
    start,finish=utc(receipt["started_utc"]),utc(receipt["finished_utc"])
    require(isinstance(now,datetime) and now.tzinfo is not None and integer(max_age_hours,1,168),
            "freshness_policy_invalid")
    require(start <= finish <= now and finish >= now-timedelta(hours=max_age_hours)
            and finish-start <= timedelta(minutes=5), "receipt_stale_or_duration_invalid")
    require(receipt["success"] is True and receipt["cleanup_passed"] is True and receipt["errors"] == [],
            "receipt_incomplete")
    native=receipt["native_evidence"];exact(native,NATIVE_KEYS,"native_shape_invalid")
    require(native["source_sha256"] == bindings["source_sha256"]
            and native["base_image"] == bindings["pins"]["runtime_image"]
            and type(native["image_id"]) is str and re.fullmatch(r"sha256:[a-f0-9]{64}",native["image_id"]),
            "native_binding_invalid")
    validate_build(native["build"],bindings);validate_probe(native["probe"])
    require(native["isolation_verified"] is True and integer(native["exit_code"],0,0)
            and native["oom_killed"] is False and integer(native["stdout_bytes"],1,4*1024*1024)
            and integer(native["stderr_bytes"],0,4*1024*1024), "native_execution_invalid")
    exact(native["cleanup"],CLEANUP_KEYS,"cleanup_shape_invalid")
    require(all(x is True for x in native["cleanup"].values()), "cleanup_incomplete")
    rows=receipt["backends"];require(type(rows) is list and len(rows)==2,"backend_count_invalid")
    for row,backend in zip(rows,BACKENDS):
        exact(row,{"backend","fixture_kind","fixture_mode","capabilities","errors"},"backend_shape_invalid")
        require(row["backend"]==backend and row["fixture_kind"]=="independent_storj_test_network"
                and row["fixture_mode"]==MODE and row["errors"]==[],"backend_scope_invalid")
        exact(row["capabilities"],CAPABILITIES,"capability_shape_invalid")
        require(all(x=="passed" and type(x) is str for x in row["capabilities"].values()),"capability_promotion_invalid")
