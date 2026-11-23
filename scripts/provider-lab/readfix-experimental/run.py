#!/usr/bin/env python3
"""Run the four unqualified native experiments in separate networkless containers."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import uuid

HERE = Path(__file__).resolve().parent
LAB = HERE.parent
RECIPE = LAB.parent / "runtime-readfix"
PROVIDERS = {"filescom": 19, "imagekit": 21, "filen": 25, "protondrive": 26}
AUTHORITIES = {
    "filescom": (),
    "imagekit": ("api.imagekit.io", "synthetic-content.imagekit.invalid"),
    "filen": ("gateway.filen.io", "egest.filen.io"),
    "protondrive": ("drive-api.proton.me", "synthetic-content.proton.invalid"),
}
CAPABILITIES = frozenset(("listing", "authentication_rejection", "download_hash", "read_denial",
    "missing_object_rejection", "fixture_write_rejection", "source_preservation", "config_preservation", "cleanup"))


class ExperimentError(Exception):
    pass


def require(value, reason):
    if not value:
        raise ExperimentError(reason)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load_recipe():
    spec = importlib.util.spec_from_file_location("readfix_recipe", RECIPE / "build.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def checked(args, *, cwd=None, env=None, timeout=180):
    result = subprocess.run([str(x) for x in args], cwd=cwd, env=env, capture_output=True,
                            text=True, timeout=timeout, check=False)
    require(result.returncode == 0, "command_failed:" + Path(str(args[0])).name)
    return result.stdout.strip()


def validate_report(report, provider, runtime):
    require(type(report) is dict and report.get("success") is True, "native_failed")
    require(report.get("scope") == "experimental_patched_runtime_native_" + provider + "_reads"
            and report.get("ledger_eligible") is False and report.get("backend") == provider,
            "native_scope_mismatch")
    require(report.get("errors") == [] and report.get("native_commands") == PROVIDERS[provider],
            "native_checks_incomplete")
    require(report.get("runtime") == runtime, "native_runtime_mismatch")
    require(report.get("capabilities") == dict.fromkeys(CAPABILITIES, "passed"), "native_capability_missing")
    cleanup = {"children_stopped", "listeners_closed", "temporary_removed"}
    if AUTHORITIES[provider]:
        cleanup.add("certificates_removed")
    require(type(report.get("cleanup")) is dict and set(report["cleanup"]) == cleanup
            and all(report["cleanup"][key] is True for key in cleanup), "native_cleanup_failed")
    observations = report.get("observations", {})
    require(type(observations.get("requests")) is int and 0 < observations["requests"] <= (512 if provider == "protondrive" else 128)
            and observations.get("unexpected") == 0 and observations.get("denied", 0) > 0
            and observations.get("read_denied") == 2 and observations.get("rejected_mutations") == 1,
            "native_witness_missing")
    if AUTHORITIES[provider]:
        tls = report.get("tls")
        require(type(tls) is list and len(tls) == 2, "native_tls_missing")
        for snapshot in tls:
            require(all(type(snapshot.get(k)) is int for k in ("accepted_connections", "closed_connections", "handshake_successes")),
                    "native_tls_counter_invalid")
            require(snapshot.get("failure_codes") == [] and snapshot.get("cleanup_complete") is True
                    and snapshot.get("stopping") is True
                    and snapshot.get("handshake_successes", 0) > 0
                    and snapshot.get("accepted_connections") == snapshot.get("closed_connections") == snapshot.get("handshake_successes")
                    and all(snapshot.get(k) == 0 for k in ("admission_denied", "handshake_failures",
                        "request_timeouts", "handler_failures", "aborted_connections",
                        "active_connections", "active_workers", "active_timers")), "native_tls_failed")
    if provider == "filen":
        require(report.get("tampered_ciphertext_rejected") is True, "filen_tamper_check_missing")
    if provider == "protondrive":
        require(report.get("tampered_reads_rejected") == {
            "tampered_ciphertext": 2, "wrong_block_hash": 2, "wrong_block_signature": 2},
            "proton_tamper_checks_missing")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-root", type=Path, required=True, help="Verified experimental runtime work root")
    parser.add_argument("--go", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="New private output directory")
    parser.add_argument("--cgroup-parent", help="Optional existing VM resource slice")
    args = parser.parse_args(argv)
    work, go, output = args.work_root.resolve(), args.go.resolve(), args.output.resolve()
    require(sys.platform == "linux", "linux_controller_required")
    require(not output.exists() and not output.is_relative_to(HERE.parents[2]), "fresh_external_output_required")
    output.mkdir(mode=0o700)
    summary = {"scope": "experimental_native_reads_not_provider_acceptance", "ledger_eligible": False,
               "success": False, "errors": [], "providers": {}}
    try:
        recipe = load_recipe()
        lock = json.loads((RECIPE / "build-lock.json").read_text())
        recipe.verify_source(work / "rclone", lock, True)
        recipe.verify_prepared(work, lock)
        identity = recipe.recipe_identity()
        checks = json.loads((work / "checks.json").read_text())
        require(checks.get("success") is True and checks.get("recipe") == identity, "current_regressions_required")
        for field, action in (("baseline", "fail"), ("fixed", "pass"), ("race", "pass")):
            expected = [{"package": p, "test": t, "outcome": action} for p, t in sorted(recipe.EXPECTED_TESTS)]
            require(checks.get(field) == expected, "complete_regressions_required")
        artifact = work / "artifacts/linux-amd64"
        binary = artifact / "rclone"
        build = json.loads((artifact / "build.json").read_text())
        require(not binary.is_symlink() and build.get("success") is True
                and build.get("recipe") == identity and build.get("runtime_version") == lock["runtime_version"]
                and build.get("source_commit") == lock["rclone_commit"]
                and build.get("source_tree_sha256") == json.loads((work / "prepared.json").read_text())["source_tree_sha256"]
                and build.get("different_root_rebuild_matched") is True and build.get("execution_verified") is True
                and build.get("ledger_eligible") is False and build.get("platform") == "linux-amd64"
                and build.get("sha256") == digest(binary) and build.get("bytes") == binary.stat().st_size,
                "verified_experimental_runtime_required")
        recipe.verify_binary(binary, "linux-amd64")
        runtime = {k: build[k] for k in ("runtime_version", "sha256", "source_commit")}
        summary["runtime"] = runtime
        env = recipe.environment(go, True)
        require(checked([go, "version"], env=env).startswith("go version " + lock["toolchain"] + " linux/amd64"),
                "pinned_go_required")
        bundle = output / "bundle"
        foundation = bundle / "foundation"
        foundation.mkdir(parents=True, mode=0o755)
        bundle.chmod(0o755)
        sources = [p for p in HERE.iterdir() if p.suffix in (".py", ".go")] + list(LAB.glob("*.py"))
        manifest = {}
        for source in sorted(sources):
            require(source.is_file() and not source.is_symlink(), "plain_fixture_source_required")
            destination = bundle / source.name if source.parent == HERE else foundation / source.name
            shutil.copyfile(source, destination)
            manifest[source.relative_to(LAB).as_posix()] = digest(source)
        repeat = output / "different-generator-root"
        repeat.mkdir(mode=0o700)
        shutil.copyfile(HERE / "generate.go", repeat / "generate.go")
        gen_env = dict(env, CGO_ENABLED="0", GOOS="linux", GOARCH="amd64")
        for directory in (bundle, repeat):
            checked([go, "build", "-trimpath", "-buildvcs=false", "-mod=readonly", "-modfile=readfix.mod",
                     "-p=2", "-o", directory / "generate", directory / "generate.go"],
                    cwd=work / "rclone", env=gen_env)
        require(digest(bundle / "generate") == digest(repeat / "generate"), "generator_rebuild_mismatch")
        summary["generator_sha256"] = digest(bundle / "generate")
        context = output / "image-context"
        context.mkdir(mode=0o700)
        for source in (HERE / "Dockerfile", LAB / "requirements-fixture.txt"):
            shutil.copyfile(source, context / source.name)
            manifest[source.relative_to(LAB).as_posix()] = digest(source)
        summary["source_sha256"] = manifest
        image_tag = "triage-readfix-native:" + uuid.uuid4().hex
        build_args = ["docker", "build", "--quiet", "--tag", image_tag]
        if args.cgroup_parent:
            build_args += ["--cgroup-parent", args.cgroup_parent]
        checked([*build_args, context], timeout=300)
        image_id = checked(["docker", "image", "inspect", "--format", "{{.Id}}", image_tag])
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", image_id), "immutable_image_required")
        summary["image_id"] = image_id
        for provider in PROVIDERS:
            record = {"success": False}
            summary["providers"][provider] = record
            name = "triage-readfix-" + provider + "-" + uuid.uuid4().hex
            command = ["docker", "create", "--name", name, "--network", "none", "--read-only",
                "--user", "10001:10001", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--pids-limit", "96", "--memory", "512m", "--memory-swap", "512m", "--cpus", "1",
                "--cgroupns", "private", "--ipc", "private", "--init", "--hostname", "synthetic-" + provider,
                "--sysctl", "net.ipv4.ip_unprivileged_port_start=0",
                "--tmpfs", "/work:rw,nosuid,nodev,noexec,size=268435456,mode=0700,uid=10001,gid=10001",
                "--mount", "type=bind,src=" + str(bundle) + ",dst=/opt/prototype,readonly",
                "--mount", "type=bind,src=" + str(artifact) + ",dst=/opt/runtime,readonly"]
            if args.cgroup_parent:
                command += ["--cgroup-parent", args.cgroup_parent]
            for index, host in enumerate(AUTHORITIES[provider], 1):
                command += ["--add-host", host + ":127.0.0." + str(index)]
            identifier = checked([*command, image_id, "/opt/prototype/probe_" + provider + ".py"])
            require(re.fullmatch(r"[0-9a-f]{64}", identifier), "owned_container_id_required")
            try:
                result = subprocess.run(["docker", "start", "--attach", identifier],
                    capture_output=True, text=True, timeout=180, check=False)
                require(len(result.stdout) + len(result.stderr) <= 65536, "native_output_limit")
                # Provider stdout is a bounded JSON receipt. Never retain raw stderr,
                # which may contain SDK diagnostics with generated credential material.
                if result.stdout.strip():
                    parsed_output = json.loads(result.stdout)
                    (output / (provider + ".log")).write_text(json.dumps(parsed_output, sort_keys=True) + "\n")
                info = json.loads(checked(["docker", "inspect", identifier]))[0]
                require(info["Config"]["Image"] == image_id and info["HostConfig"]["NetworkMode"] == "none"
                        and info["HostConfig"]["ReadonlyRootfs"] is True and info["Config"]["User"] == "10001:10001"
                        and info["HostConfig"]["Memory"] == 536870912 and info["HostConfig"]["NanoCpus"] == 1000000000
                        and info["State"]["OOMKilled"] is False and info["State"]["ExitCode"] == 0
                        and result.returncode == 0, "isolated_native_execution_failed")
                native = json.loads(result.stdout)
                validate_report(native, provider, runtime)
                record["native"] = native
            finally:
                checked(["docker", "rm", "--force", identifier])
                absent = subprocess.run(["docker", "inspect", identifier], capture_output=True, check=False).returncode != 0
                require(absent, "native_container_cleanup_failed")
                record["container_removed"] = True
            record["success"] = True
        summary["success"] = True
    except Exception as error:
        summary["errors"].append(str(error) if isinstance(error, ExperimentError) else type(error).__name__)
    finally:
        (output / "report.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"success": summary["success"], "providers": {
        k: v.get("success", False) for k, v in summary["providers"].items()}, "errors": summary["errors"],
        "report": str(output / "report.json")}))
    return 0 if summary["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
