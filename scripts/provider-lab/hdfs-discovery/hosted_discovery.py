"""Fresh public metadata plus verified Maven material on a disposable runner.

The default inspects archive data only. Discovery is an explicit build-tool
experiment; neither mode starts Hadoop daemons or earns provider coverage.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal

import bootstrap_material as B
import jdk_metadata as J
import run_discovery as R


def run(candidate, verifier, mode):
    if mode not in {"inspect", "discover"}:
        raise ValueError("mode_invalid")
    source_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    result = {"schema_version": 1, "scope": "hdfs_hosted_preparation", "mode": mode,
              "ledger_eligible": False, "offline_reproduced": False, "daemon_accepted": False,
              "review_status": "quarantined", "success": False, "errors": [],
              "launcher_source_sha256": source_hash, "metadata": None, "result": None}
    metadata = J.JdkMetadataLease()
    material = None
    try:
        with metadata:
            if mode == "inspect":
                material = B.BootstrapLease(verifier, *metadata.paths)
                with material:
                    pass
                result["result"] = material.report
            else:
                result["result"] = R.run(candidate, verifier, *metadata.paths)
    except J.MetadataError:
        result["errors"].append("metadata_failed")
    except B.MaterialError:
        result["errors"].append("bootstrap_failed")
    except BaseException:
        result["errors"].append("preparation_failed")
    finally:
        result["metadata"] = metadata.report
        if material is not None:
            result["result"] = material.report
    try:
        unchanged = hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == source_hash
    except OSError:
        unchanged = False
    if not unchanged:
        result["errors"].append("source_changed")
    result["success"] = (
        not result["errors"] and result["metadata"].get("success") is True
        and type(result["result"]) is dict and result["result"].get("success") is True)
    result["offline_reproduced"] = (result["success"] and mode == "discover"
                                    and result["result"].get("offline_reproduced") is True)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--verifier", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--mode", choices=("inspect", "discover"), default="inspect")
    args = parser.parse_args(argv)
    previous = signal.getsignal(signal.SIGTERM)
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        try:
            fd = R.report_fd(args.report)
        except (OSError, ValueError):
            print("report_create_failed")
            return 1
        try:
            with os.fdopen(fd, "w", encoding="ascii", newline="\n") as stream:
                result = run(args.candidate, args.verifier, args.mode)
                json.dump(result, stream, sort_keys=True, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            print("report_write_failed")
            return 1
        return 0 if result["success"] else 1
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    raise SystemExit(main())
