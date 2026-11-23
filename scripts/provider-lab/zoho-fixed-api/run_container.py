#!/usr/bin/env python3
"""Isolated Zoho fixed-authority read feasibility.

Linux Docker, an exact minimal context and owned image/container
labels are accepted. Private process transcripts never enter the public receipt.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parents[2]
LABEL = "org.openai.triage.fixture-id"
KIND = "org.openai.triage.fixture-kind"
SOURCE_LABEL = "org.openai.triage.fixture-source-sha256"
TMPFS = "rw,nosuid,nodev,noexec,size=128m,mode=0700,uid=10001,gid=10001"
HASH = re.compile(r"[a-f0-9]{64}")
BUILD_PHASE = re.compile(rb"^(?:#[0-9]+ +[0-9.]+ +)?ZOHO_BUILD_PHASE=(verify|dependencies|manifest)\r?$", re.MULTILINE)
PREFIX = "scripts/provider-lab/zoho-fixed-api/"
HARNESS = ("fixture_servers.py", "run_lab.py", "fixture_tls.py", "fixture_pcloud.py", "fixture_gcs.py",
           "fixture_sia.py", "fixture_read_api.py", "fixture_hidrive.py", "fixture_doi.py", "fixture_quatrix.py",
           "fixture_shade.py", "fixture_sharefile.py", "fixture_cloudinary.py", "fixture_opendrive.py", "fixture_gofile.py", "fixture_drime.py", "fixture_fichier.py", "fixture_premiumizeme.py", "fixture_putio.py", "fixture_linkbox.py", "fixture_yandex.py", "fixture_box.py", "fixture_onedrive.py", "fixture_filelu.py", "fixture_qingstor.py", "fixture_drive.py", "fixture_dropbox.py", "fixture_zoho.py", "fixture_jottacloud.py", "fixture_sugarsync.py", "fixture_pikpak.py", "fixture_dosya.py", "fixture_kdrive.py", "fixture_gphotos.py", "fixture_huaweidrive.py", "fixture_mailru.py", "fixture_ulozto.py", "fixture_iclouddrive.py", "fixture_internxt.py", "fixture_mega.py", "fixture_oos.py", "requirements-fixture.txt")
SOURCE_FILES = tuple(sorted([PREFIX + p for p in ("Dockerfile", "build-lock.json", "run_container.py", "probe.py")]
    + ["scripts/provider-lab/" + p for p in HARNESS] + ["rclone-version.env"]))
FIXTURE_SHA256 = "c990bbd4909b227aae4c70d26f9da5534740a2eb10337ced47977f915fa617be"
READ_MODE = "zoho_saved_token_folder_read_v1"
CAPABILITIES = {"listing", "download_hash", "missing_object_rejection", "read_denial", "source_preservation",
                "config_preservation", "fixture_write_rejection", "authentication_rejection", "cleanup"}
PROBE_CHECKS = {"environment", "authority_preserved", "runtime_binding", "source_binding", "protocol"}
PROBE_CLEANUP = {"children_stopped", "listeners_closed", "temporary_removed"}
ENTRYPOINT = ["/opt/fixture/venv/bin/python"]
COMMAND = ["/opt/fixture/scripts/provider-lab/zoho-fixed-api/probe.py"]

class SupervisorError(RuntimeError):
    """Static public code only."""

def check(condition, code):
    if not condition:
        raise SupervisorError(code)

def plain(path):
    path = Path(path)
    try:
        return path.is_absolute() and all(not stat.S_ISLNK(p.lstat().st_mode)
            and not getattr(p.lstat(), "st_file_attributes", 0) & 0x400 for p in (path, *path.parents))
    except OSError:
        return False

def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        check(key not in result, "duplicate_json_key")
        result[key] = value
    return result

def bad_constant(value):
    raise SupervisorError("nonfinite_json")

def parse_json(data):
    check(len(data) <= 262144, "json_size_limit")
    try:
        return json.loads(data, object_pairs_hook=unique_object, parse_constant=bad_constant)
    except (ValueError, UnicodeError):
        raise SupervisorError("invalid_json") from None

def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()

def regular(path, limit=None):
    check(plain(path) and path.is_file() and path.stat().st_nlink == 1, "regular_owned_input_required")
    check(limit is None or path.stat().st_size <= limit, "input_size_limit")

def runtime_identity(binary):
    regular(binary)
    path = REPOSITORY / "rclone-version.env"
    regular(path, 4096)
    keys = {"RCLONE_VERSION", "RCLONE_EXE_SHA256", "RCLONE_WINDOWS_ZIP_SHA256", "RCLONE_LINUX_ZIP_SHA256", "RCLONE_LINUX_EXE_SHA256"}
    extended = keys | {"RCLONE_WINDOWS_X86_EXE_SHA256", "RCLONE_WINDOWS_X86_ZIP_SHA256",
                       "RCLONE_WINDOWS_ARM64_EXE_SHA256", "RCLONE_WINDOWS_ARM64_ZIP_SHA256"}
    pins = {}
    try:
        for line in path.read_bytes().decode("ascii").splitlines():
            if not line or line.startswith("#"):
                continue
            key, sep, value = line.partition("=")
            check(sep and key in extended and key not in pins, "invalid_runtime_manifest")
            check(re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)" if key == "RCLONE_VERSION" else r"[a-f0-9]{64}", value), "invalid_runtime_manifest")
            pins[key] = value
    except UnicodeError:
        raise SupervisorError("invalid_runtime_manifest") from None
    check(set(pins) in (keys, extended), "invalid_runtime_manifest")
    check(digest(binary) == pins["RCLONE_LINUX_EXE_SHA256"], "runtime_hash_mismatch")
    return {"version": pins["RCLONE_VERSION"], "sha256": pins["RCLONE_LINUX_EXE_SHA256"]}

def source_hashes(repository=None):
    repository = REPOSITORY if repository is None else repository
    result = {}
    for name in SOURCE_FILES:
        path = repository / name
        regular(path, 1024 * 1024)
        result[name] = digest(path)
    return result

def read_lock(root=None):
    root = ROOT if root is None else root
    repository = root.parents[2]
    path = root / "build-lock.json"
    regular(path, 16384)
    lock = parse_json(path.read_bytes())
    check(type(lock) is dict and set(lock) == {"schema_version", "platform", "base_image", "base_config_digest", "python_version", "requirements", "provenance"}, "lock_schema_invalid")
    check(type(lock["schema_version"]) is int and lock["schema_version"] == 1 and lock["platform"] == "linux/amd64"
          and type(lock["base_image"]) is str and re.fullmatch(r"docker\.io/library/python@sha256:[a-f0-9]{64}", lock["base_image"])
          and type(lock["base_config_digest"]) is str and re.fullmatch(r"sha256:[a-f0-9]{64}", lock["base_config_digest"])
          and type(lock["python_version"]) is str and re.fullmatch(r"3\.12\.[0-9]+", lock["python_version"]), "lock_identity_invalid")
    req = lock["requirements"]
    check(type(req) is dict and set(req) == {"path", "sha256", "distributions"}
          and req["path"] == "scripts/provider-lab/requirements-fixture.txt" and type(req["sha256"]) is str
          and HASH.fullmatch(req["sha256"]) and req["distributions"] == {"cryptography": "50.0.2", "cffi": "2.1.1", "pycparser": "3.1"}, "dependency_lock_invalid")
    check(digest(repository / req["path"]) == req["sha256"], "dependency_lock_changed")
    # Docker's FROM and the in-build lock assertion must match the reviewed lock.
    recipe = (root / "Dockerfile").read_text(encoding="utf-8")
    check(re.findall(r"^FROM (.+)$", recipe, re.MULTILINE) == [lock["base_image"]]
          and digest(path) in recipe, "recipe_lock_mismatch")
    return lock

def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")

def parse_time(value):
    check(type(value) is str and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z", value), "probe_time_invalid")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise SupervisorError("probe_time_invalid") from None


def create_args(name, image, run_id):
    check(re.fullmatch(r"triage-zoho-fixed-api-[a-f0-9]{32}", name) and re.fullmatch(r"sha256:[a-f0-9]{64}", image)
          and re.fullmatch(r"[a-f0-9]{32}", run_id), "invalid_owned_identity")
    return ["create", "--name", name, "--label", LABEL + "=" + run_id, "--label", KIND + "=zoho-fixed-api-probe",
            "--network", "none", "--add-host", "workdrive.zoho.eu:127.0.0.1", "--add-host", "download.zoho.eu:127.0.0.2", "--read-only", "--user", "10001:10001", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--pids-limit", "96", "--memory", "512m", "--cpus", "1",
            "--sysctl", "net.ipv4.ip_unprivileged_port_start=0", "--cgroupns", "private", "--ipc", "private", "--init", "--hostname", "synthetic-zoho",
            "--tmpfs", "/work:" + TMPFS, "--entrypoint", ENTRYPOINT[0], image, *COMMAND]

def validate_image(info, image, run_id, source_digest):
    check(type(info) is dict and info.get("Id") == image and info.get("Architecture") == "amd64" and info.get("Os") == "linux", "built_image_mismatch")
    config = info.get("Config", {})
    check(type(config) is dict and type(config.get("Labels")) is dict
          and config["Labels"].get(LABEL) == run_id and config["Labels"].get(KIND) == "zoho-fixed-api-probe"
          and config["Labels"].get(SOURCE_LABEL) == source_digest and config.get("User") == "10001:10001"
          and config.get("Entrypoint") == ENTRYPOINT and config.get("Cmd") == COMMAND
          and config.get("WorkingDir") == "/work" and not config.get("Volumes") and not config.get("ExposedPorts")
          and not config.get("Healthcheck"), "image_config_mismatch")

def validate_container(info, image, run_id, expected_env):
    check(type(info) is dict, "container_inspect_invalid")
    config, host = info.get("Config", {}), info.get("HostConfig", {})
    check(type(config) is dict and type(host) is dict and type(config.get("Labels")) is dict, "container_inspect_invalid")
    check(info.get("Image") == image and config["Labels"].get(LABEL) == run_id and config["Labels"].get(KIND) == "zoho-fixed-api-probe", "container_ownership_mismatch")
    check(config.get("User") == "10001:10001" and host.get("NetworkMode") == "none" and host.get("ReadonlyRootfs") is True
          and host.get("Privileged") is False and host.get("CapDrop") == ["ALL"] and not host.get("CapAdd")
          and host.get("SecurityOpt") == ["no-new-privileges"] and host.get("CgroupnsMode") == "private"
          and host.get("IpcMode") == "private" and not host.get("PidMode") and not host.get("UTSMode") and not host.get("UsernsMode")
          and host.get("Init") is True, "container_isolation_mismatch")
    check(host.get("Memory") == 536870912 and host.get("NanoCpus") == 1000000000 and host.get("PidsLimit") == 96
          and host.get("Tmpfs") == {"/work": TMPFS}, "container_budget_mismatch")
    check(host.get("ExtraHosts") == ["workdrive.zoho.eu:127.0.0.1", "download.zoho.eu:127.0.0.2"]
          and host.get("Sysctls") == {"net.ipv4.ip_unprivileged_port_start": "0"}, "container_hosts_mismatch")
    check(not any(host.get(k) for k in ("Binds", "Mounts", "VolumesFrom", "Devices", "DeviceRequests", "PortBindings", "Links", "Dns", "DnsSearch", "DnsOptions"))
          and not config.get("Volumes") and not config.get("ExposedPorts") and not config.get("Healthcheck"), "container_extra_resource")
    mounts = info.get("Mounts", [])
    check(type(mounts) is list and len(mounts) <= 1 and all(type(m) is dict and m.get("Type") == "tmpfs"
          and m.get("Destination") == "/work" and not m.get("Source") for m in mounts), "container_unexpected_mount")
    check(config.get("Entrypoint") == ENTRYPOINT and config.get("Cmd") == COMMAND and config.get("WorkingDir") == "/work"
          and config.get("Env") == expected_env, "container_command_mismatch")
    network = info.get("NetworkSettings")
    check(type(network) is dict and type(network.get("Networks")) is dict and set(network["Networks"]) <= {"none"}, "container_unexpected_network")

class Docker:
    def __init__(self, root):
        self.root, self.sequence = root, 0
        self.last_stderr = b""
        self.build_phase = None
        self.config = root / "docker-config"
        self.config.mkdir(mode=0o700)
        binary = shutil.which("docker")
        check(binary is not None, "docker_missing")
        self.command = [binary, "--config", str(self.config), "--host", "unix:///var/run/docker.sock"]
        self.env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(root), "LANG": "C.UTF-8"}

    def run(self, args, *, timeout=30, allow_failure=False, output_limit=4 * 1024 * 1024):
        self.sequence += 1
        output, error = self.root / f"docker-{self.sequence}.out", self.root / f"docker-{self.sequence}.err"
        with output.open("xb") as out, error.open("xb") as err:
            child = subprocess.Popen([*self.command, *args], cwd=self.root, env=self.env, stdin=subprocess.DEVNULL,
                                     stdout=out, stderr=err, start_new_session=True)
        deadline = time.monotonic() + timeout
        try:
            while child.poll() is None:
                check(output.stat().st_size + error.stat().st_size <= output_limit, "docker_output_limit")
                check(time.monotonic() < deadline, "docker_command_timeout")
                time.sleep(0.1)
            check(output.stat().st_size + error.stat().st_size <= output_limit, "docker_output_limit")
            self.last_stderr = error.read_bytes()
            check(allow_failure or child.returncode == 0, "docker_command_failed")
            return child.returncode, output.read_bytes()
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(3)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(3)
            if args and args[0] == "build":
                # Fixed markers only. Neither the transcript nor arbitrary error
                # text may enter the public report, even when the build fails.
                with error.open("rb") as stream:
                    transcript = stream.read(4 * 1024 * 1024)
                phases = BUILD_PHASE.findall(transcript)
                if phases:
                    self.build_phase = phases[-1].decode("ascii")

    def inspect(self, kind, target):
        code, data = self.run([kind, "inspect", target], allow_failure=True)
        if code:
            # An unavailable daemon/permission error is not proof of absence.
            expected = re.escape(target)
            missing = re.fullmatch(r"(?:Error response from daemon: |Error: )No such " + kind + r": " + expected,
                                   self.last_stderr.decode("utf-8", errors="replace").strip())
            check(code == 1 and missing is not None, "docker_inspection_failed")
            return None
        parsed = parse_json(data)
        check(isinstance(parsed, list) and len(parsed) == 1 and isinstance(parsed[0], dict), "docker_inspect_invalid")
        return parsed[0]


def cleanup_owned(docker, name, tag, image, run_id):
    container_removed = image_removed = False
    container = docker.inspect("container", name)
    if container is not None:
        config = container.get("Config")
        check(isinstance(config, dict) and isinstance(config.get("Labels"), dict)
              and config["Labels"].get(LABEL) == run_id
              and config["Labels"].get(KIND) == "zoho-fixed-api-probe", "cleanup_container_ownership_mismatch")
        container_id = container.get("Id", "")
        check(HASH.fullmatch(container_id), "cleanup_container_id_invalid")
        check(isinstance(container.get("State"), dict), "cleanup_container_state_invalid")
        if container["State"].get("Running"):
            docker.run(["stop", "--time", "5", container_id], timeout=15, allow_failure=True)
        docker.run(["rm", "--force", container_id], timeout=15)
    container_removed = docker.inspect("container", name) is None
    info = docker.inspect("image", image or tag)
    if info is not None:
        config = info.get("Config")
        check(isinstance(config, dict) and isinstance(config.get("Labels"), dict)
              and config["Labels"].get(LABEL) == run_id
              and config["Labels"].get(KIND) == "zoho-fixed-api-probe", "cleanup_image_ownership_mismatch")
        image_id = info.get("Id", "")
        check(re.fullmatch(r"sha256:[a-f0-9]{64}", image_id), "cleanup_image_id_invalid")
        tagged = docker.inspect("image", tag)
        check(isinstance(tagged, dict) and tagged.get("Id") == image_id
              and tagged.get("Config") == info.get("Config"), "cleanup_image_tag_changed")
        # Exact immutable ID, no force/prune. Docker refuses multiple references;
        # a concurrently retargeted tag cannot redirect deletion to another image.
        docker.run(["image", "rm", image_id], timeout=30)
        image_removed = docker.inspect("image", image_id) is None and docker.inspect("image", tag) is None
    else:
        image_removed = True
    return {"container_removed": container_removed, "image_removed": image_removed}


def cleanup_temporary(root, identity):
    check(plain(root) and root.name.startswith("triage-zoho-fixed-api-")
          and (root.stat().st_dev, root.stat().st_ino) == identity, "temporary_ownership_mismatch")
    shutil.rmtree(root)
    return not root.exists()


def stage_context(context, binary, identity, sources):
    context.mkdir(mode=0o700)
    for name, expected in sources.items():
        destination = context / name
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copyfile(REPOSITORY / name, destination)
        check(digest(destination) == expected, "staged_source_changed")
    shutil.copyfile(context / PREFIX / "Dockerfile", context / "Dockerfile")
    shutil.copyfile(binary, context / "rclone")
    check(digest(context / "rclone") == identity["sha256"], "staged_runtime_changed")
    with (context / "source-manifest.json").open("x", encoding="ascii") as stream:
        json.dump(sources, stream, sort_keys=True, separators=(",", ":"))



def validate_probe(probe, identity, sources, lock, started, finished):
    check(type(probe) is dict and set(probe) == {"schema_version", "scope", "ledger_eligible", "started_utc",
          "finished_utc", "runtime", "checks", "capabilities", "cleanup", "success", "errors"}, "probe_schema_mismatch")
    check(type(probe["schema_version"]) is int and probe["schema_version"] == 1
          and probe["scope"] == "zoho_fixed_api_read_probe" and probe["ledger_eligible"] is False
          and type(probe["success"]) is bool, "probe_scope_mismatch")
    first, last = parse_time(probe["started_utc"]), parse_time(probe["finished_utc"])
    check(parse_time(started) <= first <= last <= parse_time(finished)
          and (last - first).total_seconds() <= 120, "probe_time_unbound")
    for field, keys in (("checks", PROBE_CHECKS), ("cleanup", PROBE_CLEANUP)):
        check(type(probe[field]) is dict and set(probe[field]) == keys
              and all(type(v) is bool for v in probe[field].values()), "probe_boolean_contract_invalid")
    check(type(probe["capabilities"]) is dict and set(probe["capabilities"]) == CAPABILITIES
          and all(type(v) is str and v in ("not_run", "failed", "passed") for v in probe["capabilities"].values()),
          "probe_capabilities_invalid")
    check(type(probe["errors"]) is list and len(probe["errors"]) <= 8 and all(type(x) is str
          and re.fullmatch(r"[a-z][a-z0-9_]{0,79}", x) for x in probe["errors"]), "probe_errors_invalid")
    runtime = probe["runtime"]
    expected = {"platform": "linux", "architecture": "amd64", "uid": 10001, "gid": 10001,
                "python_version": lock["python_version"], "cryptography_version": lock["requirements"]["distributions"]["cryptography"],
                "rclone_version": identity["version"], "rclone_sha256": identity["sha256"],
                "source_digest": canonical_hash(sources), "fixture_manifest_sha256": FIXTURE_SHA256}
    check(type(runtime) is dict and set(runtime) == set(expected)
          and type(runtime["uid"]) is int and type(runtime["gid"]) is int, "probe_runtime_mismatch")
    if not probe["checks"]["source_binding"] and runtime["source_digest"] == "":
        expected["source_digest"] = ""
    pending = ("cryptography_version", "rclone_version", "rclone_sha256")
    if not probe["checks"]["runtime_binding"] and all(runtime[k] == "" for k in pending):
        expected.update(dict.fromkeys(pending, ""))
    check(runtime == expected, "probe_runtime_mismatch")
    protocol_passed = all(v == "passed" for v in probe["capabilities"].values())
    check(not probe["checks"]["protocol"] or protocol_passed, "probe_protocol_contradiction")
    complete = all(probe["checks"].values()) and protocol_passed and all(probe["cleanup"].values()) and not probe["errors"]
    check(probe["success"] == complete, "probe_success_contradiction")
    return probe


def compute_bindings(root=None):
    """Read the fixed reviewed source closure; no executable or network actions."""
    root = ROOT if root is None else Path(root)
    check(plain(root) and root.is_dir(), "invalid_binding_root")
    sources = source_hashes(root.parents[2])
    return {"harness_sha256": canonical_hash(sources), "fixture_manifest_sha256": FIXTURE_SHA256,
            "source_sha256": sources, "lock": read_lock(root)}


def validate_native_read(native, identity, bindings):
    keys = {"schema_version", "scope", "ledger_eligible", "started_utc", "finished_utc", "success", "runtime",
            "platform", "source_sha256", "source_digest", "dependency_lock_sha256", "dependency_versions",
            "python_version", "base_image", "base_config_digest", "image_id", "container_isolation_verified", "probe",
            "errors", "cleanup", "stage", "build_phase", "container_exit_code", "container_stdout_bytes",
            "container_stderr_bytes", "container_oom_killed", "container_start_error_present", "build_cache_scope",
            "probe_started_utc", "probe_finished_utc"}
    check(type(native) is dict and set(native) == keys, "native_schema_mismatch")
    check(type(native["schema_version"]) is int and native["schema_version"] == 1
          and native["scope"] == "zoho_fixed_api_read_supervision" and native["ledger_eligible"] is False
          and type(native["success"]) is bool and native["platform"] == "linux/amd64", "native_scope_mismatch")
    sources, lock = bindings["source_sha256"], bindings["lock"]
    check(native["runtime"] == identity and type(native["runtime"]) is dict and set(native["runtime"]) == {"version", "sha256"}
          and native["source_sha256"] == sources and native["source_digest"] == bindings["harness_sha256"], "native_source_mismatch")
    check(native["dependency_lock_sha256"] == lock["requirements"]["sha256"]
          and native["dependency_versions"] == lock["requirements"]["distributions"]
          and native["python_version"] == lock["python_version"] and native["base_image"] == lock["base_image"]
          and native["base_config_digest"] == lock["base_config_digest"], "native_dependency_mismatch")
    start, finish = parse_time(native["started_utc"]), parse_time(native["finished_utc"])
    check(0 <= (finish - start).total_seconds() <= 900, "native_time_invalid")
    check(type(native["container_isolation_verified"]) is bool
          and (native["image_id"] is None or type(native["image_id"]) is str and re.fullmatch(r"sha256:[a-f0-9]{64}", native["image_id"]))
          and native["build_cache_scope"] == "shared_daemon_cache_not_pruned"
          and native["stage"] in ("preflight", "pull", "build", "create", "probe", "completed")
          and native["build_phase"] in (None, "verify", "dependencies", "manifest"), "native_state_invalid")
    check(type(native["cleanup"]) is dict and set(native["cleanup"]) == {"container_removed", "image_removed", "temporary_removed"}
          and all(type(v) is bool for v in native["cleanup"].values()), "native_cleanup_invalid")
    check(type(native["errors"]) is list and len(native["errors"]) <= 32
          and all(type(x) is str and re.fullmatch(r"[a-z][a-z0-9_]{0,79}", x) for x in native["errors"]), "native_errors_invalid")
    for field, maximum in (("container_exit_code", 255), ("container_stdout_bytes", 262144), ("container_stderr_bytes", 262144)):
        value = native[field]
        check(value is None or type(value) is int and (-255 if field == "container_exit_code" else 0) <= value <= maximum,
              "native_diagnostic_invalid")
    for field in ("container_oom_killed", "container_start_error_present"):
        check(native[field] is None or type(native[field]) is bool, "native_diagnostic_invalid")
    probe = native["probe"]
    if probe is not None:
        check(native["container_isolation_verified"] and native["image_id"] is not None
              and all(native[key] is not None for key in ("container_exit_code", "container_stdout_bytes", "container_stderr_bytes",
                                                          "container_oom_killed", "container_start_error_present")), "native_probe_unbound")
        first, last = parse_time(native["probe_started_utc"]), parse_time(native["probe_finished_utc"])
        check(start <= first <= last <= finish and (last - first).total_seconds() <= 120, "native_probe_time_invalid")
        validate_probe(probe, identity, sources, lock, native["probe_started_utc"], native["probe_finished_utc"])
        check(native["container_stdout_bytes"] == len((json.dumps(probe, sort_keys=True, separators=(",", ":")) + "\n").encode())
              and native["container_stdout_bytes"] + native["container_stderr_bytes"] <= 262144,
              "native_probe_output_unbound")
    else:
        check(native["success"] is False, "native_probe_missing")
        for value in (native["probe_started_utc"], native["probe_finished_utc"]):
            check(value is None or start <= parse_time(value) <= finish, "native_probe_time_invalid")
    inner_cleanup = probe is not None and all(probe["cleanup"].values())
    cleaned = inner_cleanup and all(native["cleanup"].values())
    complete = (probe is not None and probe["success"] and cleaned and native["stage"] == "completed"
                and native["build_phase"] == "manifest" and native["container_exit_code"] == 0
                and native["container_stdout_bytes"] > 0 and native["container_stderr_bytes"] == 0
                and native["container_oom_killed"] is False and native["container_start_error_present"] is False
                and not native["errors"])
    check(native["success"] == complete, "native_success_contradiction")
    return cleaned


def read_evidence(native, bindings):
    cleaned = validate_native_read(native, native["runtime"], bindings)
    errors = [] if native["success"] else ["zoho_protocol_failed"]
    return {"schema_version": 24, "scope": "rclone_backend_protocol_fixture", "runtime": dict(native["runtime"]),
            "platform": "linux", "architecture": "amd64", "harness_sha256": bindings["harness_sha256"],
            "fixture_manifest_sha256": bindings["fixture_manifest_sha256"],
            "started_utc": native["started_utc"], "finished_utc": native["finished_utc"],
            "success": native["success"], "cleanup_passed": cleaned, "errors": errors,
            "backends": [{"backend": "zoho", "fixture_kind": "independent_api_container", "fixture_mode": READ_MODE,
                          "capabilities": {key: "passed" if native["success"] else "failed" for key in CAPABILITIES}, "errors": errors.copy()}],
            "native_evidence": native}


def validate_read_evidence(receipt, runtime, bindings, now, max_age_hours=24):
    check(type(bindings) is dict and set(bindings) == {"harness_sha256", "fixture_manifest_sha256", "source_sha256", "lock"}
          and bindings["fixture_manifest_sha256"] == FIXTURE_SHA256
          and set(bindings["source_sha256"]) == set(SOURCE_FILES)
          and all(type(v) is str and HASH.fullmatch(v) for v in bindings["source_sha256"].values())
          and bindings["harness_sha256"] == canonical_hash(bindings["source_sha256"]), "zoho_bindings_invalid")
    check(type(receipt) is dict and set(receipt) == {"schema_version", "scope", "runtime", "platform", "architecture",
          "harness_sha256", "fixture_manifest_sha256", "started_utc", "finished_utc", "success", "cleanup_passed",
          "errors", "backends", "native_evidence"}, "zoho_receipt_schema_invalid")
    identity = {key: runtime[key] for key in ("version", "sha256")}
    check(runtime.get("platform") == "linux", "zoho_platform_invalid")
    expected = read_evidence(receipt["native_evidence"], bindings)
    # Canonical JSON preserves bool/int distinctions at every nested level.
    check(canonical_hash(receipt) == canonical_hash(expected) and receipt["runtime"] == identity, "zoho_receipt_mismatch")
    finished = parse_time(receipt["finished_utc"])
    check(type(max_age_hours) is int and 1 <= max_age_hours <= 168
          and 0 <= (now - finished).total_seconds() <= max_age_hours * 3600,
          "zoho_receipt_stale_or_future")
    return receipt


def run(binary, report_path, protocol=False):
    check(sys.platform == "linux", "linux_required")
    check(report_path.is_absolute() and plain(report_path.parent) and report_path.parent.is_dir()
          and not report_path.exists() and not report_path.is_symlink(), "new_absolute_report_required")
    identity, sources, lock = runtime_identity(binary), source_hashes(), read_lock()
    source_digest = canonical_hash(sources)
    run_id = uuid.uuid4().hex
    name, tag = "triage-zoho-fixed-api-" + run_id, "triage-zoho-fixed-api-fixture:" + run_id
    report = {"schema_version": 1, "scope": "zoho_fixed_api_read_feasibility", "ledger_eligible": False,
              "started_utc": utc_now(), "finished_utc": None, "success": False, "runtime": identity,
              "platform": "linux/amd64", "source_sha256": sources, "source_digest": source_digest,
              "dependency_lock_sha256": lock["requirements"]["sha256"],
              "dependency_versions": dict(lock["requirements"]["distributions"]), "python_version": lock["python_version"],
              "base_image": lock["base_image"], "base_config_digest": lock["base_config_digest"],
              "image_id": None, "container_isolation_verified": False, "probe": None, "errors": [],
              "cleanup": {"container_removed": False, "image_removed": False, "temporary_removed": False},
              "stage": "preflight", "build_phase": None, "container_exit_code": None,
              "container_stdout_bytes": None, "container_stderr_bytes": None,
              "container_oom_killed": None, "container_start_error_present": None,
              "build_cache_scope": "shared_daemon_cache_not_pruned"}
    if protocol:
        report.update(scope="zoho_fixed_api_read_supervision", probe_started_utc=None, probe_finished_utc=None)
    bindings = {"harness_sha256": source_digest, "fixture_manifest_sha256": FIXTURE_SHA256, "source_sha256": sources, "lock": lock}
    root = Path(tempfile.mkdtemp(prefix="triage-zoho-fixed-api-"))
    root_identity = (root.stat().st_dev, root.stat().st_ino)
    docker, image, attempted_build, attempted_create = None, None, False, False
    try:
        check(plain(root), "unsafe_temporary_root")
        docker = Docker(root)
        _, raw = docker.run(["info", "--format", "{{json .}}"])
        info = parse_json(raw)
        check(type(info) is dict and info.get("OSType") == "linux" and info.get("Architecture") in ("x86_64", "amd64"), "docker_platform_mismatch")
        context = root / "context"
        stage_context(context, binary, identity, sources)
        report["stage"] = "pull"
        docker.run(["image", "pull", "--quiet", "--platform", "linux/amd64", lock["base_image"]], timeout=120)
        base = docker.inspect("image", lock["base_image"])
        check(type(base) is dict and base.get("Id") in {lock["base_config_digest"], lock["base_image"].rsplit("@", 1)[1]}
              and base.get("Architecture") == "amd64" and base.get("Os") == "linux", "base_image_mismatch")
        attempted_build = True
        report["stage"] = "build"
        iid = root / "image-id"
        docker.run(["build", "--no-cache", "--force-rm", "--platform", "linux/amd64", "--label", LABEL + "=" + run_id,
                    "--label", SOURCE_LABEL + "=" + source_digest, "--tag", tag, "--iidfile", str(iid), str(context)], timeout=300)
        regular(iid, 80)
        image = iid.read_text(encoding="ascii").strip()
        check(re.fullmatch(r"sha256:[a-f0-9]{64}", image), "built_image_id_invalid")
        built = docker.inspect("image", image)
        validate_image(built, image, run_id, source_digest)
        report["image_id"] = image
        expected_env = built["Config"].get("Env")
        check(type(expected_env) is list and all(type(x) is str for x in expected_env), "image_environment_invalid")
        attempted_create = True
        report["stage"] = "create"
        docker.run(create_args(name, image, run_id))
        initial = docker.inspect("container", name) or {}
        validate_container(initial, image, run_id, expected_env)
        check(type(initial.get("State")) is dict and initial["State"].get("Running") is False
              and initial["State"].get("Status") == "created" and type(initial.get("Id")) is str
              and HASH.fullmatch(initial["Id"]), "container_initial_state_invalid")
        container_id = initial["Id"]
        report["container_isolation_verified"] = True
        report["stage"] = "probe"
        probe_started = utc_now()
        if protocol:
            report["probe_started_utc"] = probe_started
        code, raw = docker.run(["start", "--attach", container_id], timeout=120, allow_failure=True, output_limit=262144)
        probe_finished = utc_now()
        if protocol:
            report["probe_finished_utc"] = probe_finished
        stderr = docker.last_stderr
        final = docker.inspect("container", container_id) or {}
        validate_container(final, image, run_id, expected_env)
        check(final.get("Id") == container_id and type(final.get("State")) is dict
              and final["State"].get("Running") is False and final["State"].get("Status") == "exited", "container_final_state_invalid")
        state = final["State"]
        check(type(state.get("ExitCode")) is int and -255 <= state["ExitCode"] <= 255
              and type(state.get("OOMKilled")) is bool and type(state.get("Error")) is str, "container_state_invalid")
        report.update(container_exit_code=state["ExitCode"], container_stdout_bytes=len(raw), container_stderr_bytes=len(stderr),
                      container_oom_killed=state["OOMKilled"], container_start_error_present=bool(state["Error"]))
        report["probe"] = validate_probe(parse_json(raw), identity, sources, lock, probe_started, probe_finished)
        check(code == 0 and state["ExitCode"] == 0 and not state["OOMKilled"] and not state["Error"]
              and not stderr and report["probe"]["success"], "zoho_probe_failed")
        report["success"] = True
        report["stage"] = "completed"
    except KeyboardInterrupt:
        report["errors"].append("supervisor_interrupted")
    except (SupervisorError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report["errors"].append(str(error) if isinstance(error, SupervisorError) else "supervisor_operation_failed")
    finally:
        if docker is not None:
            report["build_phase"] = docker.build_phase
        try:
            if docker is not None and (attempted_build or attempted_create):
                report["cleanup"].update(cleanup_owned(docker, name, tag, image, run_id))
            else:
                report["cleanup"].update(container_removed=True, image_removed=True)
        except (SupervisorError, OSError, ValueError, TypeError, subprocess.SubprocessError):
            report["errors"].append("supervisor_cleanup_failed")
        try:
            report["cleanup"]["temporary_removed"] = cleanup_temporary(root, root_identity)
        except (SupervisorError, OSError):
            report["errors"].append("temporary_cleanup_failed")
        try:
            check(source_hashes() == sources and runtime_identity(binary) == identity, "source_or_runtime_changed")
        except (SupervisorError, OSError, ValueError, TypeError):
            report["errors"].append("source_or_runtime_changed")
        report["success"] = report["success"] and not report["errors"] and all(report["cleanup"].values())
        report["finished_utc"] = utc_now()
        if protocol:
            report = read_evidence(report, bindings)
        with report_path.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rclone", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--protocol-evidence", action="store_true", help="Emit closed schema-24 configured raw-read evidence")
    args = parser.parse_args()
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        report = run(args.rclone, args.report, protocol=args.protocol_evidence)
    except (SupervisorError, OSError, ValueError, KeyError, TypeError, KeyboardInterrupt):
        print("Zoho fixed-API preflight failed", file=sys.stderr)
        return 1
    print(json.dumps({"success": report["success"], "errors": report["errors"],
                      "schema_version": report["schema_version"], "scope": report["scope"]}))
    return 0 if report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
