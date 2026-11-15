#!/usr/bin/env python3
"""Private SugarSync protocol experiment; no vendor or application acceptance."""
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import stat
import sys
import tempfile
from datetime import datetime, timezone

ROOT = Path("/opt/fixture")
WORK = Path("/work")
UID = 10001
AUTHORITY = "api.sugarsync.com"
MANIFEST_SHA = "c990bbd4909b227aae4c70d26f9da5534740a2eb10337ced47977f915fa617be"
sys.path.insert(0, str(ROOT / "scripts/provider-lab"))
import run_lab as lab

class ProbeError(RuntimeError):
    """Static diagnostic only."""

def require(condition, code):
    if not condition:
        raise ProbeError(code)

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")

def listeners():
    result = []
    for name in ("tcp", "tcp6"):
        lines = Path("/proc/net", name).read_text().splitlines()[1:]
        result.extend((name, fields[1]) for line in lines if len(fields := line.split()) >= 10 and fields[3] == "0A")
    return result

def environment_checks():
    require(sys.platform == "linux" and platform.machine() == "x86_64", "linux_amd64_required")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    require(os.getuid() == os.getgid() == UID
            and all(status.get(key, "").split() == [str(UID)] * 4 for key in ("Uid", "Gid")), "identity_mismatch")
    require(status.get("Groups", "").split() in ([], [str(UID)]) and status.get("NoNewPrivs", "").strip() == "1"
            and status.get("Seccomp", "").strip() == "2", "privilege_boundary_required")
    require(all(status.get(key, "").strip() == "0" * 16 for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")),
            "capabilities_present")
    mounts = {}
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        left, right = line.split(" - ", 1)
        fields = left.split()
        mounts[fields[4]] = (set(fields[5].split(",")), right.split()[0])
    require("ro" in mounts["/"][0] and mounts.get("/work", (set(), ""))[1] == "tmpfs"
            and {"rw", "nosuid", "nodev", "noexec"} <= mounts["/work"][0], "mount_boundary_required")
    interfaces = {line.split(":", 1)[0].strip() for line in Path("/proc/net/dev").read_text().splitlines() if ":" in line}
    require(interfaces == {"lo"} and not listeners(), "empty_loopback_namespace_required")
    require({int(p.name) for p in Path("/proc").iterdir() if p.name.isdecimal()} == {1, os.getpid()},
            "unexpected_initial_process")
    require(Path("/proc/1/cmdline").read_bytes().split(b"\0")[0].rsplit(b"/", 1)[-1] in (b"docker-init", b"tini"),
            "container_init_required")
    require(WORK.is_dir() and not WORK.is_symlink() and WORK.stat().st_uid == UID
            and stat.S_IMODE(WORK.stat().st_mode) == 0o700 and not any(WORK.iterdir()), "empty_private_tmpfs_required")
    require(lab.fixture_manifest_sha256() == MANIFEST_SHA, "literal_manifest_mismatch")

def authority_environment():
    with Path("/etc/hosts").open("rb") as stream:
        hosts = stream.read(16385)
    require(len(hosts) <= 16384, "hosts_size_limit")
    try:
        rows = [line.split("#", 1)[0].split() for line in hosts.decode("ascii").splitlines()]
    except UnicodeError:
        raise ProbeError("hosts_encoding_invalid") from None
    matches = [row for row in rows if any(n.lower().rstrip(".") == AUTHORITY for n in row[1:])]
    require(matches == [["127.0.0.1", AUTHORITY]], "hosts_authority_mismatch")
    raw = Path("/proc/sys/net/ipv4/ip_unprivileged_port_start").read_bytes()
    require(raw == b"0\n", "unprivileged_https_unavailable")
    answers = socket.getaddrinfo(AUTHORITY, 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    require(0 < len(answers) <= 8 and all(row[0] == socket.AF_INET and row[1] == socket.SOCK_STREAM
            and row[2] == socket.IPPROTO_TCP and row[4] == ("127.0.0.1", 443) for row in answers),
            "authority_resolution_mismatch")
    return hashlib.sha256(hosts).hexdigest(), raw

def verify_sources():
    # Exact source closure and duplicate-safe parsing are shared with the supervisor.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import run_container as controller
    raw = (ROOT / "source-manifest.json").read_bytes()
    sources = controller.parse_json(raw)
    require(type(sources) is dict and set(sources) == set(controller.SOURCE_FILES), "source_manifest_mismatch")
    for name, sha in sources.items():
        path = ROOT / name
        require(type(sha) is str and re.fullmatch("[a-f0-9]{64}", sha) is not None
                and path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1
                and digest(path) == sha, "source_binding_failed")
    return controller.canonical_hash(sources)

def run():
    caps = {k: "not_run" for k in lab.QUATRIX_CAPABILITIES}
    report = {"schema_version": 1, "scope": "sugarsync_fixed_api_read_probe", "ledger_eligible": False,
              "started_utc": utc_now(), "finished_utc": None,
              "runtime": {"platform": "linux", "architecture": "amd64", "uid": os.getuid(), "gid": os.getgid(),
                          "python_version": platform.python_version(), "cryptography_version": "",
                          "rclone_version": "", "rclone_sha256": "", "source_digest": "",
                          "fixture_manifest_sha256": MANIFEST_SHA},
              "checks": dict.fromkeys(("environment", "authority_preserved", "runtime_binding", "source_binding", "protocol"), False),
              "capabilities": caps, "cleanup": dict.fromkeys(("children_stopped", "listeners_closed", "temporary_removed"), False),
              "success": False, "errors": []}
    root = native = None
    try:
        environment_checks()
        report["checks"]["environment"] = True
        authority = authority_environment()
        source_digest = verify_sources()
        report["runtime"]["source_digest"] = source_digest
        report["checks"]["source_binding"] = True
        original, identity, _ = lab.verified_runtime(ROOT / "rclone", ROOT / "rclone-version.env")
        lab.pcloud_dependencies()
        report["runtime"].update(rclone_version=identity["version"], rclone_sha256=identity["sha256"],
                                 cryptography_version=importlib.metadata.version("cryptography"))
        root = Path(tempfile.mkdtemp(prefix="sugarsync-probe-", dir=WORK))
        root_identity = (root.stat().st_dev, root.stat().st_ino)
        native = lab.Runtime(original, identity, root)
        # The shared runner ordinarily executes its private copy. In this profile
        # /work is noexec; use the already verified binary on the read-only image.
        native.binary.unlink()
        native.binary = original
        code, output, _ = native.run(["version"])
        require(code == 0 and output.decode().splitlines()[0] == "rclone v" + identity["version"], "runtime_version_mismatch")
        report["checks"]["runtime_binding"] = True
        row = lab.run_backend(native, "sugarsync", root / "sugarsync")
        report["capabilities"] = row["capabilities"]
        require(not row["errors"] and set(row["capabilities"]) == set(caps)
                and all(v == "passed" for v in row["capabilities"].values()), "sugarsync_protocol_failed")
        report["checks"]["protocol"] = True
        require(authority_environment() == authority and verify_sources() == source_digest
                and digest(original) == identity["sha256"], "bindings_changed")
        report["checks"]["authority_preserved"] = True
    except (ProbeError, lab.LabError, OSError, ValueError, RuntimeError) as error:
        report["errors"].append(str(error) if isinstance(error, (ProbeError, lab.LabError)) else "probe_operation_failed")
    finally:
        try:
            report["cleanup"]["children_stopped"] = native is None or native.close()
            report["cleanup"]["listeners_closed"] = not listeners()
        except (OSError, RuntimeError):
            report["errors"].append("probe_resource_cleanup_failed")
        try:
            if root is not None:
                require(root.parent == WORK and not root.is_symlink()
                        and (root.stat().st_dev, root.stat().st_ino) == root_identity, "temporary_ownership_changed")
                shutil.rmtree(root)
            report["cleanup"]["temporary_removed"] = root is None or not root.exists()
        except (OSError, ProbeError):
            report["errors"].append("probe_temporary_cleanup_failed")
        report["finished_utc"] = utc_now()
        report["success"] = all(report["checks"].values()) and all(report["cleanup"].values()) and not report["errors"]
    return report

if __name__ == "__main__":
    result = run()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    raise SystemExit(0 if result["success"] else 1)
