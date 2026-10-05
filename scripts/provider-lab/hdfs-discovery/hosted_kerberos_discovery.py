"""Hosted Kerberos dependency preparation; optional isolated offline repeat."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import tempfile
import time

import bootstrap_material as B
import jdk_metadata as J
import resolver_discovery as D
import run_discovery as R


FALSE_CLAIMS = dict(ledger_eligible=False, authentication_verified=False,
                    daemon_accepted=False, provider_accepted=False,
                    application_accepted=False, vendor_accepted=False,
                    offline_reproduced=False, vulnerability_audited=False,
                    publisher_audit_completed=False)


def candidate_binding(candidate):
    contents = D.candidate_inputs(candidate, "kerberos")
    actual = {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()}
    if actual != D.candidate_hashes("kerberos"):
        raise ValueError("candidate_invalid")
    return actual


def source_bindings(verifier):
    paths = [Path(__file__).absolute(), Path(verifier).absolute()]
    paths.extend(Path(module.__file__).absolute()
                 for module in (B, J, D, R, D.graph_export, D.offline_cache))
    paths.append(D.offline_cache.lock_path("kerberos"))
    if len({path.name for path in paths}) != len(paths):
        raise ValueError("source_invalid")
    result = {path.name: D.file_hash(path, maximum=256 * 1024) for path in paths}
    if result[Path(verifier).name] != B.VERIFIER_SHA256:
        raise ValueError("source_invalid")
    if result["artifact-lock-kerberos.json"] != D.offline_cache.KERBEROS_LOCK_SHA256:
        raise ValueError("source_invalid")
    return result


def clean_lease(value):
    return (type(value) is dict and type(value.get("cleanup")) is dict
            and set(value["cleanup"]) == {"children_stopped", "temporary_removed"}
            and all(flag is True for flag in value["cleanup"].values()))


def clean_discovery(value):
    # Treat malformed/absent cleanup as uncertainty, never as permission to erase.
    try:
        return R.clean_discovery(value)
    except (TypeError, ValueError):
        return False


def discovery_matches(value, candidate, *, mode="online", seed=None, prepare=False):
    return (type(value) is dict and value.get("success") is True
            and value.get("errors") == [] and value.get("mode") == mode
            and value.get("ledger_eligible") is False
            and value.get("offline_reproduced") is False
            and value.get("daemon_accepted") is False
            and (cache_matches(value.get("cache_preparation")) if prepare
                 else value.get("cache_preparation") is None)
            and type(value.get("manifest")) is dict
            and type(value.get("inputs")) is dict
            and value["inputs"].get("candidate_profile") == "kerberos"
            and value["inputs"].get("candidate_sha256") == candidate
            and value["inputs"].get("seed_cache") == seed
            and clean_discovery(value))


COUNTS = dict(artifacts=645, poms=447, selected_runtime_jars=142, other_jars=56,
              artifact_bytes=98990688)


def profile_receipt_matches(value, scope):
    return (type(value) is dict and value.get("scope") == scope
            and type(value.get("schema_version")) is int and value["schema_version"] == 1
            and value.get("candidate_profile") == "kerberos"
            and value.get("lock_sha256") == D.offline_cache.KERBEROS_LOCK_SHA256
            and type(value.get("counts")) is dict and value["counts"] == COUNTS
            and all(type(item) is int for item in value["counts"].values())
            and value.get("success") is True and value.get("preparation_only") is True
            and value.get("advisory_work_pending") is True
            and all(value.get(key) is False for key in
                    (*D.offline_cache.FALSE_CLAIMS, "authentication_verified",
                     "application_accepted", "vendor_accepted")))


def cache_matches(value):
    return (profile_receipt_matches(value, "hdfs_offline_cache_preparation")
            and type(value.get("sha256")) is str and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is not None
            and type(value.get("size")) is int and 0 < value["size"] <= D.offline_cache.MAX_ARCHIVE
            and value.get("metadata_reconstructed") is True
            and value.get("original_auxiliary_copied") is False)


def stage_inputs_match(value, candidate, sources, material, seed):
    try:
        expected = dict(supervisor_sha256=sources["resolver_discovery.py"],
            graph_export_sha256=sources["graph_export.py"], cache_source_sha256=sources["offline_cache.py"],
            cache_lock_sha256=sources["artifact-lock-kerberos.json"], seed_cache=seed,
            candidate_profile="kerberos", candidate_sha256=candidate,
            maven=dict(version=material["maven_version"], archive_sha256=material["maven_archive_sha256"],
                       archive_sha512=material["maven_archive_sha512"]),
            jdk=dict(manifest=material["jdk_image"], config_id=material["jdk_image_id"]),
            bootstrap_material=material)
        return type(value) is dict and value.get("inputs") == expected
    except (KeyError, TypeError):
        return False


def comparison_matches(value, manifest):
    try:
        return (profile_receipt_matches(value, "hdfs_offline_manifest_comparison")
                and value.get("artifact_runtime_graph_match") is True
                and value.get("auxiliary_cache_identity_claimed") is False
                and value.get("runtime_classpath_sha256") == manifest["runtime_classpath"]["normalized_sha256"]
                and value.get("graph_outputs_sha256") == D.offline_cache.sha(D.offline_cache.encoded(manifest["graph_outputs"]))
                and value.get("dependency_semantics_sha256") == D.offline_cache.sha(D.offline_cache.encoded(manifest["dependency_semantics"])))
    except (KeyError, TypeError, D.offline_cache.CacheError):
        return False


def run(candidate, verifier, mode="online"):
    if mode not in ("online", "repeat"):
        raise ValueError("mode_invalid")
    started = time.monotonic()
    report = dict(schema_version=1, scope="hdfs_kerberos_dependency_discovery",
                  candidate_profile="kerberos", mode=mode, review_status="quarantined",
                  success=False, errors=[], started_utc=R.utc_now(), finished_utc=None,
                  duration_seconds=None, source_sha256={}, candidate_sha256={},
                  metadata=None, bootstrap=None, discovery=None, offline_discovery=None, comparison=None,
                  cleanup={"raw_evidence_removed": True}, **FALSE_CLAIMS)
    root = identity = metadata = bootstrap = None
    discovery_started = offline_started = False
    material = None
    stage = "preflight_failed"
    old_umask = os.umask(0o077)
    try:
        D.hosted_guard()
        report["candidate_sha256"] = candidate_binding(candidate)
        report["source_sha256"] = source_bindings(verifier)
        stage = "metadata_failed"
        metadata = J.JdkMetadataLease()
        with metadata:
            stage = "bootstrap_failed"
            bootstrap = B.BootstrapLease(verifier, *metadata.paths)
            with bootstrap:
                material = copy.deepcopy(bootstrap.material)
                root = Path(tempfile.mkdtemp(prefix="hdfs-kerberos-discovery-", dir="/tmp"))
                report["cleanup"]["raw_evidence_removed"] = False
                info = root.lstat()
                identity = info.st_dev, info.st_ino
                if (not stat.S_ISDIR(info.st_mode) or root.is_symlink()
                        or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid()):
                    raise ValueError("private_directory_invalid")
                stage = "discovery_failed"
                discovery_started = True
                seed = root / "offline-seed.tar"
                report["discovery"] = D.discover(
                    candidate, copy.deepcopy(material), bootstrap.root / "maven.tar.gz", root,
                    candidate_profile="kerberos", **({"cache_destination": seed} if mode == "repeat" else {}))
                if not discovery_matches(report["discovery"], report["candidate_sha256"], prepare=mode == "repeat"):
                    report["errors"].append("discovery_failed")
                elif mode == "repeat":
                    if not stage_inputs_match(report["discovery"], report["candidate_sha256"],
                                              report["source_sha256"], material, None):
                        raise ValueError("online_inputs_changed")
                    stage = "offline_discovery_failed"
                    offline_started = True
                    report["offline_discovery"] = D.discover(
                        candidate, copy.deepcopy(material), bootstrap.root / "maven.tar.gz", root,
                        candidate_profile="kerberos", seed_cache=seed)
                    seed_receipt = report["discovery"]["cache_preparation"]
                    if (not discovery_matches(report["offline_discovery"], report["candidate_sha256"],
                                              mode="offline", seed=seed_receipt)
                            or not stage_inputs_match(report["offline_discovery"], report["candidate_sha256"],
                                                      report["source_sha256"], material, seed_receipt)
                            or not R.matching_stage_inputs(report["discovery"], report["offline_discovery"])):
                        report["errors"].append("offline_discovery_failed")
                    else:
                        stage = "offline_comparison_failed"
                        report["comparison"] = D.offline_cache.compare_manifests(
                            report["discovery"]["manifest"], report["offline_discovery"]["manifest"], profile="kerberos")
                        if not comparison_matches(report["comparison"], report["discovery"]["manifest"]):
                            report["errors"].append("offline_comparison_failed")
                if bootstrap.material != material:
                    report["errors"].append("bootstrap_changed")
    except J.MetadataError:
        report["errors"].append("metadata_failed")
    except B.MaterialError:
        report["errors"].append("bootstrap_failed")
    except KeyboardInterrupt:
        report["errors"].append("preparation_interrupted")
    except BaseException:
        report["errors"].append(stage)
    finally:
        if metadata is not None:
            report["metadata"] = metadata.report
        if bootstrap is not None:
            report["bootstrap"] = bootstrap.report
        if root is not None:
            safe = ((not discovery_started or clean_discovery(report["discovery"]))
                    and (not offline_started or clean_discovery(report["offline_discovery"])))
            safe = safe and clean_lease(report["metadata"]) and clean_lease(report["bootstrap"])
            if safe:
                try:
                    info = root.lstat()
                    if (not stat.S_ISDIR(info.st_mode) or root.is_symlink()
                            or (info.st_dev, info.st_ino) != identity):
                        raise ValueError("private_directory_changed")
                    shutil.rmtree(root)
                    if root.exists() or root.is_symlink():
                        raise ValueError("private_directory_remaining")
                    report["cleanup"]["raw_evidence_removed"] = True
                except BaseException:
                    report["errors"].append("raw_cleanup_failed")
            else:
                report["errors"].append("raw_cleanup_unconfirmed")
        os.umask(old_umask)
    if report["source_sha256"]:
        try:
            if source_bindings(verifier) != report["source_sha256"]:
                raise ValueError("source_changed")
        except BaseException:
            report["errors"].append("source_changed")
    if report["candidate_sha256"]:
        try:
            if candidate_binding(candidate) != report["candidate_sha256"]:
                raise ValueError("candidate_changed")
        except BaseException:
            report["errors"].append("candidate_changed")
    report["success"] = (
        not report["errors"] and report["cleanup"]["raw_evidence_removed"] is True
        and clean_lease(report["metadata"]) and report["metadata"].get("success") is True
        and clean_lease(report["bootstrap"]) and report["bootstrap"].get("success") is True
        and discovery_matches(report["discovery"], report["candidate_sha256"], prepare=mode == "repeat"))
    if mode == "repeat":
        report["success"] = (report["success"]
            and discovery_matches(report["offline_discovery"], report["candidate_sha256"], mode="offline",
                                  seed=report["discovery"]["cache_preparation"])
            and comparison_matches(report["comparison"], report["discovery"]["manifest"]))
        report["offline_reproduced"] = report["success"]
    report["finished_utc"] = R.utc_now()
    report["duration_seconds"] = round(time.monotonic() - started, 6)
    return report


class ClosedParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "arguments_invalid\n")


def main(argv=None):
    parser = ClosedParser(description=__doc__, allow_abbrev=False)
    for name in ("candidate", "verifier", "report"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--mode", choices=("online", "repeat"), default="online")
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
                stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
        except BaseException:
            print("report_write_failed")
            return 1
        return 0 if result["success"] else 1
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    raise SystemExit(main())
