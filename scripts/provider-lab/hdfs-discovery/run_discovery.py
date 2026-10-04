"""Hosted dependency discovery with a live verified bootstrap lease.

Only the closed JSON report may be retained. Raw graphs, POMs and command logs
are removed after confirmed cleanup. This does not start a provider or app.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import tempfile
import time

import bootstrap_material as B
import resolver_discovery as D


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def run(candidate, verifier, jdk_manifest, jdk_config, jdk_source):
    started = time.monotonic()
    source_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report = {
        "schema_version": 1, "scope": "hdfs_dependency_discovery_integration",
        "ledger_eligible": False, "offline_reproduced": False, "daemon_accepted": False,
        "review_status": "quarantined", "success": False, "errors": [],
        "started_utc": utc_now(), "finished_utc": None, "duration_seconds": None,
        "source_sha256": source_hash, "bootstrap": None, "discovery": None,
        "cleanup": {"raw_evidence_removed": True},
    }
    root = lease = identity = None
    discovery_started = False
    old_umask = os.umask(0o077)
    try:
        D.hosted_guard()
        root = Path(tempfile.mkdtemp(prefix="hdfs-discovery-integration-", dir="/tmp"))
        info = root.lstat()
        identity = (info.st_dev, info.st_ino)
        report["cleanup"]["raw_evidence_removed"] = False
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("private_directory_invalid")
        lease = B.BootstrapLease(verifier, jdk_manifest, jdk_config, jdk_source)
        with lease:
            discovery_started = True
            report["discovery"] = D.discover(
                candidate, lease.material, lease.root / "maven.tar.gz", root)
            if not report["discovery"]["success"]:
                report["errors"].append("discovery_failed")
    except B.MaterialError:
        report["errors"].append("bootstrap_failed")
    except D.DiscoveryError:
        report["errors"].append("discovery_failed")
    except BaseException:
        report["errors"].append("integration_failed")
    finally:
        if lease is not None:
            report["bootstrap"] = lease.report
        if root is not None:
            discovery = report["discovery"]
            safe = not discovery_started or (
                type(discovery) is dict and all(value is True for value in discovery.get("cleanup", {}).values())
                and set(discovery.get("cleanup", {})) == {"container_removed", "image_removed", "context_removed"}
                and "command_cleanup_failed" not in discovery.get("errors", []))
            if safe:
                try:
                    info = root.lstat()
                    if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != identity:
                        raise ValueError("private_directory_changed")
                    shutil.rmtree(root)
                    report["cleanup"]["raw_evidence_removed"] = not root.exists() and not root.is_symlink()
                except BaseException:
                    report["errors"].append("raw_cleanup_failed")
            else:
                report["errors"].append("raw_cleanup_unconfirmed")
        os.umask(old_umask)
    try:
        unchanged = hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == source_hash
    except OSError:
        unchanged = False
    if not unchanged:
        report["errors"].append("source_changed")
    report["finished_utc"] = utc_now()
    report["duration_seconds"] = round(time.monotonic() - started, 3)
    report["success"] = (
        not report["errors"] and report["cleanup"]["raw_evidence_removed"]
        and type(report["bootstrap"]) is dict and report["bootstrap"].get("success") is True
        and type(report["discovery"]) is dict and report["discovery"].get("success") is True)
    return report


def report_fd(path):
    if not path.is_absolute():
        raise ValueError("report_path_invalid")
    for ancestor in (path.parent, *path.parent.parents):
        if not stat.S_ISDIR(ancestor.lstat().st_mode):
            raise ValueError("report_path_invalid")
    return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)


def write_report(args):
    """The caller installs interruption handling before entering this scope."""
    try:
        fd = report_fd(args.report)
    except (OSError, ValueError):
        print("report_create_failed")
        return 1
    try:
        with os.fdopen(fd, "w", encoding="ascii", newline="\n") as stream:
            result = run(args.candidate, args.verifier, args.jdk_manifest, args.jdk_config, args.jdk_source)
            json.dump(result, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        print("report_write_failed")
        return 1
    return 0 if result["success"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("candidate", "verifier", "jdk-manifest", "jdk-config", "jdk-source", "report"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args(argv)
    previous = signal.getsignal(signal.SIGTERM)
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        return write_report(args)
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    raise SystemExit(main())
