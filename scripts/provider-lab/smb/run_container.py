#!/usr/bin/env python3
"""GitHub-hosted Linux Samba feasibility supervisor, never provider evidence.

Only exact labeled container/image resources created by this invocation can be
removed. No host services, system configuration, volumes or trust are changed.
Raw build/server/child transcripts are private temporary inputs, not artifacts.
"""

import argparse
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
TMPFS = "rw,nosuid,nodev,noexec,size=32m,mode=0700,uid=10001,gid=10001"
HASH = re.compile(r"[a-f0-9]{64}")
PROBE_CHECKS = {"environment", "version_binding", "config_validation", "good_listing_before",
                "good_downloads_before", "bad_password_rejected", "good_listing_after", "good_downloads_after",
                "missing_rejected", "source_preserved", "config_preserved", "seed_preserved"}
PROBE_CLEANUP = {"children_stopped", "listeners_closed", "temporary_removed"}
PROBE_RUNTIME = {"platform", "uid", "gid", "samba_version", "rclone_version", "smbd_sha256",
                 "rclone_sha256", "probe_sha256", "lock_sha256"}
BUILD_PHASE = re.compile(rb"^(?:#[0-9]+ +[0-9.]+ +)?SMB_BUILD_PHASE=(metadata|deb-download|install|seed|manifest)\r?$", re.MULTILINE)


class SupervisorError(RuntimeError):
    """Static public code only; never a subprocess transcript."""


def check(condition, code):
    if not condition:
        raise SupervisorError(code)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def plain(path):
    path = Path(path)
    return path.is_absolute() and all(not stat.S_ISLNK(p.lstat().st_mode) for p in (path, *path.parents))


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        check(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def parse_json(data):
    check(len(data) <= 262144, "json_size_limit")
    try:
        return json.loads(data, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError):
        raise SupervisorError("invalid_json") from None


def runtime_identity(binary):
    check(binary.is_absolute() and plain(binary) and binary.is_file(), "absolute_regular_runtime_required")
    pins = {}
    for line in (REPOSITORY / "rclone-version.env").read_text().splitlines():
        if line and not line.startswith("#"):
            key, sep, value = line.partition("=")
            check(sep and key not in pins, "invalid_runtime_manifest")
            pins[key] = value
    version, expected = pins.get("RCLONE_VERSION", ""), pins.get("RCLONE_LINUX_EXE_SHA256", "")
    check(re.fullmatch(r"\d+\.\d+\.\d+", version) and HASH.fullmatch(expected), "invalid_runtime_manifest")
    check(digest(binary) == expected, "runtime_hash_mismatch")
    return {"version": version, "sha256": expected}


def validate_probe(probe, identity, source_hashes):
    check(isinstance(probe, dict) and set(probe) == {"schema_version", "scope", "status", "ledger_eligible",
          "runtime", "checks", "cleanup", "commands_total", "errors"}, "probe_schema_mismatch")
    check(type(probe["schema_version"]) is int and probe["schema_version"] == 1
          and probe["scope"] == "smb_samba_feasibility_only" and probe["ledger_eligible"] is False
          and probe["status"] in ("passed", "failed"), "probe_scope_mismatch")
    check(type(probe["commands_total"]) is int and 0 <= probe["commands_total"] <= 64, "probe_command_count_invalid")
    check(isinstance(probe["errors"], list) and len(probe["errors"]) <= 32
          and all(isinstance(code, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,79}", code) for code in probe["errors"]),
          "probe_errors_invalid")
    for field, keys in (("checks", PROBE_CHECKS), ("cleanup", PROBE_CLEANUP)):
        check(isinstance(probe[field], dict) and set(probe[field]) == keys
              and all(type(value) is bool for value in probe[field].values()), "probe_boolean_contract_invalid")
    runtime = probe["runtime"]
    check(isinstance(runtime, dict) and set(runtime) == PROBE_RUNTIME, "probe_runtime_contract_invalid")
    check(runtime["platform"] == "linux/amd64" and type(runtime["uid"]) is int and runtime["uid"] == 10001
          and type(runtime["gid"]) is int and runtime["gid"] == 10001
          and runtime["rclone_version"] == identity["version"] and runtime["rclone_sha256"] == identity["sha256"],
          "probe_runtime_mismatch")
    for key in ("smbd_sha256", "probe_sha256", "lock_sha256"):
        check(runtime[key] is None or isinstance(runtime[key], str) and HASH.fullmatch(runtime[key]), "probe_hash_invalid")
    check(runtime["samba_version"] is None or isinstance(runtime["samba_version"], str)
          and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+:~_-]{0,60}", runtime["samba_version"]),
          "probe_server_version_invalid")
    if probe["status"] == "passed":
        check(not probe["errors"] and all(probe["checks"].values()) and all(probe["cleanup"].values())
              and probe["commands_total"] == 16 and runtime["samba_version"] is not None
              and runtime["smbd_sha256"] is not None and runtime["probe_sha256"] == source_hashes["probe_samba.py"]
              and runtime["lock_sha256"] == source_hashes["build-lock.json"], "probe_success_contradiction")
    else:
        check(bool(probe["errors"]) or not all(probe["checks"].values()) or not all(probe["cleanup"].values()),
              "probe_failure_contradiction")
    return probe


def create_args(name, image, run_id):
    check(re.fullmatch(r"triage-smb-[a-f0-9]{32}", name) and re.fullmatch(r"sha256:[a-f0-9]{64}", image)
          and re.fullmatch(r"[a-f0-9]{32}", run_id), "invalid_owned_identity")
    return ["create", "--name", name, "--label", LABEL + "=" + run_id, "--label", KIND + "=smb-probe",
            "--network", "none", "--read-only", "--user", "10001:10001", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--pids-limit", "64", "--memory", "512m", "--cpus", "1",
            "--cgroupns", "private", "--init", "--hostname", "synthetic-smb",
            "--tmpfs", "/run/synthetic-smb:" + TMPFS,
            "--env", "HOME=/run/synthetic-smb", "--env", "LANG=C.UTF-8", "--env", "PYTHONDONTWRITEBYTECODE=1",
            "--entrypoint", "/usr/bin/python3", image, "/opt/synthetic-smb/probe_samba.py",
            "--lock", "/opt/synthetic-smb/build-lock.json"]


def validate_container(info, image, run_id):
    check(isinstance(info, dict), "container_inspect_invalid")
    config, host = info.get("Config", {}), info.get("HostConfig", {})
    check(isinstance(config, dict) and isinstance(host, dict)
          and isinstance(config.get("Labels"), dict), "container_inspect_invalid")
    labels = config["Labels"]
    check(info.get("Image") == image and labels.get(LABEL) == run_id
          and labels.get(KIND) == "smb-probe", "container_ownership_mismatch")
    check(config.get("User") == "10001:10001" and host.get("NetworkMode") == "none"
          and host.get("ReadonlyRootfs") is True and host.get("Privileged") is False
          and host.get("CapDrop") == ["ALL"] and not host.get("CapAdd")
          and host.get("SecurityOpt") == ["no-new-privileges"]
          and host.get("CgroupnsMode") == "private" and host.get("IpcMode") == "private"
          and not host.get("PidMode") and not host.get("UTSMode") and not host.get("UsernsMode")
          and host.get("Init") is True, "container_isolation_mismatch")
    check(host.get("Memory") == 512 * 1024 * 1024 and host.get("NanoCpus") == 1000000000
          and host.get("PidsLimit") == 64 and host.get("Tmpfs") == {"/run/synthetic-smb": TMPFS},
          "container_budget_mismatch")
    check(not any(host.get(key) for key in ("Binds", "Mounts", "VolumesFrom", "Devices", "DeviceRequests",
                                         "PortBindings", "ExtraHosts"))
          and not config.get("Volumes") and not config.get("ExposedPorts"), "container_extra_resource")
    mounts = info.get("Mounts", [])
    check(isinstance(mounts, list) and all(isinstance(m, dict) and m.get("Type") == "tmpfs" and m.get("Destination") == "/run/synthetic-smb"
          and not m.get("Source") for m in mounts) and len(mounts) <= 1, "container_unexpected_mount")
    check(config.get("Entrypoint") == ["/usr/bin/python3"]
          and config.get("Cmd") == ["/opt/synthetic-smb/probe_samba.py", "--lock", "/opt/synthetic-smb/build-lock.json"],
          "container_command_mismatch")
    network = info.get("NetworkSettings")
    check(isinstance(network, dict) and isinstance(network.get("Networks"), dict)
          and set(network["Networks"]) <= {"none"}, "container_unexpected_network")


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

    def run(self, args, *, timeout=30, allow_failure=False):
        self.sequence += 1
        output, error = self.root / f"docker-{self.sequence}.out", self.root / f"docker-{self.sequence}.err"
        with output.open("xb") as out, error.open("xb") as err:
            child = subprocess.Popen([*self.command, *args], cwd=self.root, env=self.env, stdin=subprocess.DEVNULL,
                                     stdout=out, stderr=err, start_new_session=True)
        deadline = time.monotonic() + timeout
        try:
            while child.poll() is None:
                check(output.stat().st_size + error.stat().st_size <= 4 * 1024 * 1024, "docker_output_limit")
                check(time.monotonic() < deadline, "docker_command_timeout")
                time.sleep(0.1)
            check(output.stat().st_size + error.stat().st_size <= 4 * 1024 * 1024, "docker_output_limit")
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
                    phases = BUILD_PHASE.findall(stream.read(4 * 1024 * 1024))
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
              and config["Labels"].get(KIND) == "smb-probe", "cleanup_container_ownership_mismatch")
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
              and config["Labels"].get(KIND) == "smb-probe", "cleanup_image_ownership_mismatch")
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
    check(plain(root) and root.name.startswith("triage-smb-container-")
          and (root.stat().st_dev, root.stat().st_ino) == identity, "temporary_ownership_mismatch")
    shutil.rmtree(root)
    return not root.exists()


def run(binary, report_path):
    check(sys.platform == "linux" and os.environ.get("GITHUB_ACTIONS") == "true"
          and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted", "github_hosted_linux_required")
    check(report_path.is_absolute() and plain(report_path.parent) and report_path.parent.is_dir()
          and not report_path.exists() and not report_path.is_symlink(), "new_absolute_report_required")
    identity = runtime_identity(binary)
    lock_path = ROOT / "build-lock.json"
    for filename in ("Dockerfile", "build-lock.json", "probe_samba.py"):
        check(plain(ROOT / filename) and (ROOT / filename).is_file(), "regular_fixture_source_required")
    lock = parse_json(lock_path.read_bytes())
    check(isinstance(lock, dict) and type(lock.get("schema_version")) is int
          and lock["schema_version"] == 1 and lock.get("platform") == "linux/amd64"
          and isinstance(lock.get("base_image"), str)
          and re.fullmatch(r"docker\.io/library/debian@sha256:[a-f0-9]{64}", lock["base_image"]), "image_lock_invalid")
    source_hashes = {name: digest(ROOT / name) for name in ("Dockerfile", "build-lock.json", "probe_samba.py")}
    source_hashes["run_container.py"] = digest(Path(__file__))
    run_id = uuid.uuid4().hex
    name, tag = "triage-smb-" + run_id, "triage-smb-fixture:" + run_id
    report = {"schema_version": 1, "scope": "smb_samba_container_feasibility_only", "ledger_eligible": False,
              "success": False, "runtime": identity, "source_sha256": source_hashes, "base_image": lock["base_image"],
              "image_id": None, "container_isolation_verified": False, "probe": None, "errors": [],
              "cleanup": {"container_removed": False, "image_removed": False, "temporary_removed": False},
              "stage": "preflight", "build_phase": None,
              "build_cache_scope": "shared_daemon_cache_not_pruned"}
    root = Path(tempfile.mkdtemp(prefix="triage-smb-container-"))
    root_identity = (root.stat().st_dev, root.stat().st_ino)
    docker, image, attempted_build, attempted_create = None, None, False, False
    try:
        check(plain(root), "unsafe_temporary_root")
        docker = Docker(root)
        _, raw = docker.run(["info", "--format", "{{json .}}"])
        info = parse_json(raw)
        check(info.get("OSType") == "linux" and info.get("Architecture") in ("x86_64", "amd64"), "docker_platform_mismatch")
        context = root / "context"
        context.mkdir(mode=0o700)
        for filename in ("Dockerfile", "build-lock.json", "probe_samba.py"):
            shutil.copyfile(ROOT / filename, context / filename)
            check(digest(context / filename) == source_hashes[filename], "staged_source_changed")
        shutil.copyfile(binary, context / "rclone")
        check(digest(context / "rclone") == identity["sha256"], "staged_runtime_changed")
        shutil.copyfile(REPOSITORY / "rclone-version.env", context / "rclone-version.env")
        report["stage"] = "pull"
        docker.run(["image", "pull", "--quiet", "--platform", "linux/amd64", lock["base_image"]], timeout=120)
        attempted_build = True
        report["stage"] = "build"
        iid = root / "image-id"
        docker.run(["build", "--no-cache", "--force-rm", "--platform", "linux/amd64", "--label", LABEL + "=" + run_id,
                    "--tag", tag, "--iidfile", str(iid), str(context)], timeout=600)
        image = iid.read_text().strip()
        check(re.fullmatch(r"sha256:[a-f0-9]{64}", image), "built_image_id_invalid")
        built = docker.inspect("image", image)
        check(built is not None and built.get("Config", {}).get("Labels", {}).get(LABEL) == run_id
              and built.get("Config", {}).get("Labels", {}).get(KIND) == "smb-probe"
              and built.get("Architecture") == "amd64" and built.get("Os") == "linux", "built_image_mismatch")
        report["image_id"] = image
        attempted_create = True
        report["stage"] = "create"
        docker.run(create_args(name, image, run_id))
        validate_container(docker.inspect("container", name) or {}, image, run_id)
        report["container_isolation_verified"] = True
        report["stage"] = "probe"
        code, raw = docker.run(["start", "--attach", name], timeout=180, allow_failure=True)
        final = docker.inspect("container", name) or {}
        validate_container(final, image, run_id)
        check(final.get("State", {}).get("Running") is False, "container_still_running")
        report["probe"] = validate_probe(parse_json(raw), identity, source_hashes)
        check(code == 0 and final.get("State", {}).get("ExitCode") == 0
              and report["probe"]["status"] == "passed", "samba_probe_failed")
        report["success"] = True
        report["stage"] = "completed"
    except (SupervisorError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report["errors"].append(str(error) if isinstance(error, SupervisorError) else "supervisor_operation_failed")
    finally:
        if docker is not None:
            report["build_phase"] = docker.build_phase
        try:
            if docker is not None and (attempted_build or attempted_create):
                report["cleanup"].update(cleanup_owned(docker, name, tag, image, run_id))
            else:
                report["cleanup"].update(container_removed=True, image_removed=True)
        except (SupervisorError, OSError, subprocess.SubprocessError):
            report["errors"].append("supervisor_cleanup_failed")
        try:
            report["cleanup"]["temporary_removed"] = cleanup_temporary(root, root_identity)
        except (SupervisorError, OSError):
            report["errors"].append("temporary_cleanup_failed")
        report["success"] = report["success"] and not report["errors"] and all(report["cleanup"].values())
        with report_path.open("x", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rclone", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = run(args.rclone, args.report)
    except (SupervisorError, OSError):
        print("Samba feasibility preflight failed", file=sys.stderr)
        return 1
    print(json.dumps({"success": result["success"], "ledger_eligible": False, "errors": result["errors"]}))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
