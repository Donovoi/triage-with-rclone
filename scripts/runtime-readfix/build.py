#!/usr/bin/env python3
"""Build an explicitly experimental rclone from pinned source and read fixes.

Preparation may download source and modules. Checks and builds use the verified
module cache with Go network access disabled. No installed runtime is replaced.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
PACKAGES = (
    "./backend/filescom", "./backend/imagekit",
    "github.com/FilenCloudDienste/filen-sdk-go/filen/client",
    "github.com/rclone/go-proton-api",
)
EXPECTED_TESTS = frozenset({
    ("github.com/rclone/rclone/backend/filescom", "TestOpenReadStatus"),
    ("github.com/rclone/rclone/backend/imagekit", "TestOpenReadStatus"),
    ("github.com/rclone/rclone/backend/imagekit", "TestOpenHonorsCancelledContext"),
    ("github.com/FilenCloudDienste/filen-sdk-go/filen/client", "TestSyntheticChunkHTTPStatus"),
    ("github.com/rclone/go-proton-api", "TestSyntheticBlockHTTPStatus"),
})
TEST_PATTERN = "^(TestOpen(ReadStatus|HonorsCancelledContext)|TestSynthetic(Chunk|Block)HTTPStatus)$"


class BuildError(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise BuildError(reason)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def recipe_identity():
    return {p.name: digest(p) for p in sorted(HERE.iterdir())
            if p.is_file() and p.suffix in (".py", ".json", ".patch", ".go")}


def source_tree_digest(root, patches=()):
    # Normalize only already-verified patched files to their original hashes.
    # Every other source, module, test, and newly added file remains covered.
    overrides = {patch["source"]: patch["before_sha256"] for patch in patches}
    entries = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if relative.parts[0] == ".git":
            continue
        require(not path.is_symlink(), "source_tree_symlink")
        if path.is_file():
            name = relative.as_posix()
            entries[name] = overrides[name] if name in overrides else digest(path)
        else:
            require(path.is_dir(), "source_tree_special_file")
    return hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def environment(go, offline):
    env = {k: v for k, v in os.environ.items()
           if k not in ("GOFLAGS", "GOOS", "GOARCH", "CGO_ENABLED", "GOTOOLCHAIN", "GOWORK",
                        "GOPRIVATE", "GONOPROXY", "GONOSUMDB", "GOINSECURE")}
    env.update(
        PATH=str(go.parent) + os.pathsep + os.environ.get("PATH", ""),
        GOTOOLCHAIN="local", GOWORK="off", GOMAXPROCS="2", GOGC="35",
        GOMEMLIMIT="2560MiB", RCLONE_CONFIG="/nonexistent-triage-readfix-config",
        GOPROXY="off" if offline else "https://proxy.golang.org",
        GOSUMDB="off" if offline else "sum.golang.org", GIT_TERMINAL_PROMPT="0",
        GOAMD64="v1", GO386="sse2", GOARM64="v8.0",
    )
    # Go tests here use only local synthetic endpoints or in-process transports.
    for key in list(env):
        if key.upper().endswith("_PROXY") or key.startswith("RCLONE_") and key != "RCLONE_CONFIG":
            env.pop(key)
    return env


def run(args, cwd, env, log, expected=0, timeout=900):
    start = time.monotonic()
    with log.open("xb") as output:
        result = subprocess.run([str(v) for v in args], cwd=cwd, env=env,
                                stdout=output, stderr=subprocess.STDOUT, timeout=timeout)
    print(json.dumps({"step": log.stem, "exit": result.returncode,
                      "seconds": round(time.monotonic() - start, 2)}), flush=True)
    require(result.returncode == expected, "command_failed:" + log.name)
    return result.returncode


def output(args, cwd, env, timeout=180):
    result = subprocess.run([str(v) for v in args], cwd=cwd, env=env,
                            capture_output=True, text=True, timeout=timeout)
    require(result.returncode == 0, "command_query_failed")
    return result.stdout.strip()


def test_result(log, expected_action):
    """Require the actual named Go tests; a build failure cannot prove a defect."""
    terminal = {}
    packages = {}
    skipped = []
    for line in log.read_text().splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue  # Go tool diagnostics are kept in the raw log.
        if not isinstance(event, dict):
            continue
        package, test, action = event.get("Package"), event.get("Test"), event.get("Action")
        if action == "skip":
            skipped.append((package, test))
        if test and "/" not in test and action in ("pass", "fail"):
            terminal[(package, test)] = action
        elif not test and action in ("pass", "fail"):
            packages[package] = action
    require(not skipped, "regression_test_skipped")
    require(set(terminal) == EXPECTED_TESTS, "regression_test_inventory_mismatch")
    require(all(value == expected_action for value in terminal.values()),
            "regression_test_outcome_mismatch")
    require(set(packages) == {p for p, _ in EXPECTED_TESTS}
            and all(value == expected_action for value in packages.values()),
            "regression_package_outcome_mismatch")
    return [{"package": package, "test": test, "outcome": terminal[(package, test)]}
            for package, test in sorted(terminal)]


def verify_source(root, lock, patched):
    key = "after_sha256" if patched else "before_sha256"
    for patch in lock["patches"]:
        require(digest(root / patch["source"]) == patch[key], "source_digest_mismatch")
    for test in lock["tests"]:
        require(digest(root / test["target"]) == test["sha256"], "test_digest_mismatch")


def verify_binary(path, platform):
    with path.open("rb") as stream:
        prefix = stream.read(4096)
    if platform == "linux-amd64":
        require(prefix[:6] == b"\x7fELF\x02\x01" and len(prefix) >= 20
                and struct.unpack_from("<H", prefix, 18)[0] == 62, "invalid_linux_binary")
    else:
        require(prefix[:2] == b"MZ" and len(prefix) >= 64, "invalid_windows_binary")
        offset = struct.unpack_from("<I", prefix, 60)[0]
        machine = {"windows-amd64": 0x8664, "windows-386": 0x14c, "windows-arm64": 0xaa64}[platform]
        require(64 <= offset <= len(prefix) - 6 and prefix[offset:offset + 4] == b"PE\0\0"
                and struct.unpack_from("<H", prefix, offset + 4)[0] == machine,
                "invalid_windows_architecture")


def copy_module(source, destination):
    # The Go cache is read-only; make only the owned copy writable.
    shutil.copytree(source, destination, symlinks=True)
    for path in (destination, *destination.rglob("*")):
        require(not path.is_symlink(), "module_symlink")
        path.chmod(0o755 if path.is_dir() else 0o644)


def prepare(work, go, lock, env, source_repo):
    require(not work.exists(), "work_directory_already_exists")
    work.mkdir(parents=True, mode=0o700)
    logs = work / "logs"
    logs.mkdir()
    root = work / "rclone"
    root.mkdir()
    run(["git", "init", "--quiet"], root, env, logs / "git-init.log")
    origin = str(source_repo.resolve()) if source_repo else lock["rclone_repository"]
    run(["git", "fetch", "--no-tags", "--depth=1", origin, lock["rclone_commit"]],
        root, env, logs / "git-fetch.log")
    run(["git", "checkout", "--quiet", "--detach", "FETCH_HEAD"],
        root, env, logs / "git-checkout.log")
    require(output(["git", "rev-parse", "HEAD"], root, env) == lock["rclone_commit"],
            "source_commit_mismatch")
    require(not output(["git", "status", "--porcelain"], root, env), "source_not_clean")
    run([go, "mod", "download", "all"], root, env, logs / "module-download.log")
    run([go, "mod", "verify"], root, env, logs / "module-verify.log")
    for module in lock["modules"]:
        info = json.loads(output([go, "mod", "download", "-json",
                                  module["module"] + "@" + module["version"]], root, env))
        require(info.get("Sum") == module["sum"], "module_checksum_mismatch")
        destination = root / module["directory"]
        copy_module(info["Dir"], destination)
    shutil.copyfile(root / "go.mod", root / "readfix.mod")
    shutil.copyfile(root / "go.sum", root / "readfix.sum")
    for module in lock["modules"]:
        output([go, "mod", "edit", "-modfile=readfix.mod",
                "-replace=" + module["module"] + "=./" + module["directory"]], root, env)
    for test in lock["tests"]:
        target = root / test["target"]
        require(not target.exists(), "regression_test_already_exists")
        shutil.copyfile(HERE / test["name"], target)
    verify_source(root, lock, False)
    write_json(work / "prepared.json", {
        "scope": lock["scope"], "source_commit": lock["rclone_commit"],
        "recipe": recipe_identity(), "toolchain": lock["toolchain"],
        "source_tree_sha256": source_tree_digest(root),
        "original_go_mod_sha256": digest(root / "go.mod"),
        "original_go_sum_sha256": digest(root / "go.sum"),
        "readfix_mod_sha256": digest(root / "readfix.mod"),
        "readfix_sum_sha256": digest(root / "readfix.sum"),
    })


def verify_prepared(work, lock):
    prepared = json.loads((work / "prepared.json").read_text())
    require(prepared["recipe"] == recipe_identity(), "recipe_changed_after_preparation")
    require(prepared["source_commit"] == lock["rclone_commit"], "prepared_commit_mismatch")
    root = work / "rclone"
    require(source_tree_digest(root, lock["patches"]) == prepared["source_tree_sha256"],
            "prepared_source_tree_changed")
    for name, key in (("go.mod", "original_go_mod_sha256"), ("go.sum", "original_go_sum_sha256"),
                      ("readfix.mod", "readfix_mod_sha256"), ("readfix.sum", "readfix_sum_sha256")):
        require(digest(root / name) == prepared[key], "module_manifest_changed")


def check(work, go, lock, env):
    root, logs = work / "rclone", work / "logs"
    verify_source(root, lock, False)
    command = [go, "test", "-json", "-modfile=readfix.mod", "-mod=readonly",
               "-p=2", "-count=1", "-run", TEST_PATTERN, *PACKAGES]
    run(command, root, env, logs / "baseline-tests.jsonl", expected=1)
    baseline = test_result(logs / "baseline-tests.jsonl", "fail")
    for patch in lock["patches"]:
        directory = root / patch["directory"]
        # SDK copies are inside the source checkout but are not tracked in it.
        run(["git", "apply", "--no-index", "--check", HERE / patch["name"]],
            directory, env, logs / (patch["name"] + "-check.log"))
        run(["git", "apply", "--no-index", HERE / patch["name"]],
            directory, env, logs / (patch["name"] + "-apply.log"))
    verify_source(root, lock, True)
    run(command, root, env, logs / "fixed-tests.jsonl")
    fixed = test_result(logs / "fixed-tests.jsonl", "pass")
    run([*command[:2], "-race", *command[2:]], root, dict(env, CGO_ENABLED="1"),
        logs / "race-tests.jsonl")
    race = test_result(logs / "race-tests.jsonl", "pass")
    verify_prepared(work, lock)
    write_json(work / "checks.json", {
        "scope": lock["scope"], "ledger_eligible": False, "success": True,
        "recipe": recipe_identity(), "baseline": baseline, "fixed": fixed, "race": race,
    })


def build(work, go, lock, env, platform):
    checks = json.loads((work / "checks.json").read_text())
    require(checks.get("success") is True and checks.get("recipe") == recipe_identity(),
            "missing_current_passing_checks")
    root, logs = work / "rclone", work / "logs"
    verify_source(root, lock, True)
    other = work / "different-build-root" / "rclone"
    if not other.exists():
        shutil.copytree(root, other, ignore=shutil.ignore_patterns(".git"))
    verify_source(other, lock, True)
    prepared = json.loads((work / "prepared.json").read_text())
    require(source_tree_digest(other, lock["patches"]) == prepared["source_tree_sha256"],
            "repeat_source_tree_changed")
    artifacts = work / "artifacts"
    artifacts.mkdir(exist_ok=True)
    os_name, arch = platform.split("-")
    binary = "rclone.exe" if os_name == "windows" else "rclone"
    first, second = artifacts / platform, work / "repeat-artifacts" / platform
    first.mkdir(parents=True)
    second.mkdir(parents=True)
    build_env = dict(env, CGO_ENABLED="0", GOOS=os_name, GOARCH=arch)
    flags = [go, "build", "-trimpath", "-buildvcs=false", "-modfile=readfix.mod",
             "-mod=readonly", "-p=2",
             "-ldflags=-s -w -X github.com/rclone/rclone/fs.Version=" + lock["runtime_version"]]
    for directory, target, suffix in ((root, first, "first"), (other, second, "repeat")):
        run([*flags, "-o", target / binary, "."], directory, build_env,
            logs / (platform + "-" + suffix + ".log"), timeout=1200)
        verify_binary(target / binary, platform)
    require(digest(first / binary) == digest(second / binary), "build_not_reproducible")
    if platform == "linux-amd64":
        version = output([first / binary, "version"], root, env)
        require(version.splitlines()[0] == "rclone " + lock["runtime_version"],
                "runtime_version_mismatch")
        (logs / "runtime-version.log").write_text(version + "\n")
    metadata = output([go, "version", "-m", first / binary], root, env)
    (logs / (platform + "-buildinfo.log")).write_text(metadata + "\n")
    require("CGO_ENABLED=0" in metadata and "GOARCH=" + arch in metadata
            and "GOOS=" + os_name in metadata, "build_metadata_mismatch")
    verify_prepared(work, lock)
    require(source_tree_digest(other, lock["patches"]) == prepared["source_tree_sha256"],
            "repeat_source_tree_changed")
    receipt = {
        "scope": lock["scope"], "ledger_eligible": False, "success": True,
        "runtime_version": lock["runtime_version"], "source_commit": lock["rclone_commit"],
        "toolchain": lock["toolchain"], "platform": platform,
        "source_tree_sha256": prepared["source_tree_sha256"],
        "sha256": digest(first / binary), "bytes": (first / binary).stat().st_size,
        "different_root_rebuild_matched": True, "recipe": recipe_identity(),
        "execution_verified": platform == "linux-amd64",
    }
    write_json(first / "build.json", receipt)
    print(json.dumps({k: receipt[k] for k in ("platform", "sha256", "bytes",
                                             "different_root_rebuild_matched")}), flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "check", "build"))
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--go", type=Path, required=True)
    parser.add_argument("--source-repo", type=Path, help="optional local Git mirror, still pinned by commit")
    parser.add_argument("--platform", choices=("linux-amd64", "windows-amd64", "windows-386", "windows-arm64"))
    args = parser.parse_args(argv)
    lock = json.loads((HERE / "build-lock.json").read_text())
    go, work = args.go.resolve(), args.work_root.resolve()
    env = environment(go, args.operation != "prepare")
    try:
        require(output([go, "version"], HERE, env).split()[2] == lock["toolchain"],
                "toolchain_version_mismatch")
        for item in (*lock["patches"], *lock["tests"]):
            require(digest(HERE / item["name"]) == item["sha256"], "recipe_input_digest_mismatch")
        if args.operation == "prepare":
            require(args.platform is None, "platform_only_valid_for_build")
            prepare(work, go, lock, env, args.source_repo)
        else:
            require(args.source_repo is None, "source_repo_only_valid_for_prepare")
            verify_prepared(work, lock)
            if args.operation == "check":
                require(args.platform is None, "platform_only_valid_for_build")
                check(work, go, lock, env)
            else:
                require(args.platform is not None, "platform_required")
                build(work, go, lock, env, args.platform)
        return 0
    except (BuildError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print("Experimental readfix refused: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
