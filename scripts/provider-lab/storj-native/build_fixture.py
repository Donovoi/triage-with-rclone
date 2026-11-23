"""Build the pinned Storj test network in a disposable, resource-limited compiler."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import tarfile
import tempfile
import time

ROOT = Path(__file__).absolute().parent
LABEL = "org.triage.storj-build"

def require(value, code):
    if not value:
        raise ValueError(code)

def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(part)
    return h.hexdigest()

def regular(path, maximum):
    path = Path(path).absolute()
    for item in (path, *path.parents):
        require(not item.is_symlink(), "source_link_refused")
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= maximum,
            "source_file_invalid")
    return path

def call(args, timeout=60):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=True)

def inspect(kind, reference):
    return json.loads(call(["docker", *kind, "inspect", reference]).stdout)[0]

def remove_scratch(path, parent):
    require(path.parent == parent and path.resolve().parent == parent.resolve() and not path.is_symlink(),
            "scratch_ownership_invalid")
    # Go's downloaded module cache deliberately has non-writable directories.
    for folder, dirs, files in os.walk(path, followlinks=False):
        current = Path(folder)
        if not current.is_symlink():
            current.chmod(current.stat().st_mode | stat.S_IRWXU)
    shutil.rmtree(path)
    require(not path.exists(), "scratch_cleanup_failed")

def build(source, output):
    pins = json.loads(regular(ROOT / "pins.json", 65536).read_text())
    helper = regular(ROOT / "planet_test.go", 65536)
    source = Path(source).absolute()
    output = Path(output).absolute()
    require(not output.exists() and output.parent.is_dir() and not output.parent.is_symlink(),
            "new_build_output_required")
    output.mkdir(mode=0o700)
    scratch = Path(tempfile.mkdtemp(prefix="private-build-", dir=output))
    inputs, work = scratch / "input", scratch / "work"
    inputs.mkdir(); work.mkdir(); (work / "tmp").mkdir()
    cid = None
    runid = scratch.name
    label = LABEL + "=" + runid
    record = {"schema_version": 1, "success": False, "source_commit": pins["storj_commit"],
              "source_archive_sha256": pins["source_archive_sha256"],
              "helper_sha256": digest(helper), "compiler_image": pins["compiler_image"],
              "compiler_version": pins["go_version"], "builder_removed": False,
              "scratch_removed": False}
    started = time.monotonic()
    try:
        sha = call(["git", "-C", str(source), "rev-parse", "HEAD"]).stdout.strip()
        require(sha == pins["storj_commit"], "storj_revision_mismatch")
        archive = scratch / "source.tar"
        call(["git", "-C", str(source), "archive", "--format=tar", "--output", str(archive), sha], 120)
        regular(archive, 64 * 1024 * 1024)
        require(digest(archive) == pins["source_archive_sha256"], "storj_archive_mismatch")
        with tarfile.open(archive) as tar:
            members = tar.getmembers()
            require(len(members) < 15000 and all(x.isfile() or x.isdir() for x in members),
                    "storj_archive_member_invalid")
            require(sum(x.size for x in members) < 64 * 1024 * 1024, "storj_archive_size_invalid")
            tar.extractall(inputs, members=members, filter="data")
        fixture = inputs / "private" / "triagefixture"
        require(not fixture.exists(), "upstream_fixture_collision")
        fixture.mkdir()
        shutil.copyfile(helper, fixture / "planet_test.go")
        call(["docker", "pull", pins["compiler_image"]], 300)
        image = inspect(["image"], pins["compiler_image"])
        require(image["Os"] == "linux" and image["Architecture"] == "amd64"
                and not image["Config"].get("Volumes"), "compiler_platform_invalid")
        argv = ["docker", "create", "--name", "triage-storj-build-" + runid, "--label", label,
                "--network", "bridge", "--read-only", "--user", f"{os.getuid()}:{os.getgid()}",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--cpus", "1.5", "--memory", "3g", "--memory-swap", "3g",
                "--pids-limit", "384", "--init",
                "--mount", f"type=bind,src={inputs},dst=/src,readonly",
                "--mount", f"type=bind,src={work},dst=/work",
                "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m,mode=1777", "--workdir", "/src"]
        for key, value in {"HOME": "/work", "TMPDIR": "/work/tmp", "GOPATH": "/work/gopath", "GOCACHE": "/work/go-build",
                           "GOTOOLCHAIN": "local", "GOMAXPROCS": "2", "GOGC": "35",
                           "GOMEMLIMIT": "2560MiB", "CGO_ENABLED": "1",
                           "GOPROXY": "https://proxy.golang.org", "GOSUMDB": "sum.golang.org"}.items():
            argv += ["--env", key + "=" + value]
        argv += [pins["compiler_image"], "go", "test", "-mod=readonly", "-p", "2", "-c",
                 "-o", "/work/planet.test", "./private/triagefixture"]
        cid = call(argv).stdout.strip()
        owned = inspect([], cid)
        require(owned["Config"]["Labels"][LABEL] == runid and owned["Image"] == image["Id"],
                "compiler_container_ownership_invalid")
        with (output / "build.log").open("w") as log:
            result = subprocess.run(["docker", "start", "--attach", cid], stdout=log,
                                    stderr=subprocess.STDOUT, timeout=1100)
        ended = inspect([], cid)
        require(result.returncode == 0 and ended["State"]["ExitCode"] == 0
                and ended["State"]["OOMKilled"] is False, "compiler_failed")
        binary = regular(work / "planet.test", 192 * 1024 * 1024)
        shutil.copyfile(binary, output / "planet.test")
        (output / "planet.test").chmod(0o555)
        resources = {}
        for folder in ("emails", "errors"):
            destination = output / "resources" / "static" / folder
            destination.mkdir(parents=True)
            for path in sorted((inputs / "web" / "satellite" / "static" / folder).iterdir()):
                regular(path, 1024 * 1024)
                shutil.copyfile(path, destination / path.name)
                resources["static/" + folder + "/" + path.name] = digest(path)
        record.update(binary_sha256=digest(binary), binary_bytes=binary.stat().st_size,
                      resources_sha256=resources, seconds=round(time.monotonic() - started, 2),
                      success=True)
    finally:
        if cid:
            owned = inspect([], cid)
            require(owned["Config"]["Labels"][LABEL] == runid, "compiler_cleanup_ownership_invalid")
            call(["docker", "rm", "--force", "--volumes", cid])
            record["builder_removed"] = True
        remove_scratch(scratch, output)
        record["scratch_removed"] = True
        record["success"] = record["success"] and record["builder_removed"] and record["scratch_removed"]
        (output / "build.json").write_text(json.dumps(record, indent=2) + "\n")
    require(record["success"], "build_incomplete")
    return record

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, help="Checkout of the exact pinned public Storj revision")
    parser.add_argument("--output", required=True, help="New private build output directory")
    args = parser.parse_args()
    def interrupted(signum, frame):
        raise ValueError("build_interrupted")
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, interrupted)
    try:
        result = build(args.source, args.output)
    except (OSError, ValueError, subprocess.SubprocessError, KeyError, tarfile.TarError):
        print(json.dumps({"success": False, "error": "storj_build_failed"}))
        return 1
    print(json.dumps({k: result[k] for k in ("success", "binary_sha256", "seconds", "builder_removed", "scratch_removed")}))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
