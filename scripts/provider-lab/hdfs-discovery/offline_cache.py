"""Build and verify a data-only Maven seed; no extraction or code execution.

Only reviewed artifact bytes enter the seed. Checksum and repository-tracking
files are reconstructed, not copied from the online cache. Matching this seed
does not establish an audit, offline execution, or provider acceptance.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile

LOCK_SHA256 = "e0c4a34dc8999bc0b53ec5d8fc5d4d5fd2b72400424b4e110d45e70f8ab780e6"
ARTIFACTS_SHA256 = "c360e17bfb67c21a71304fb38b72ff249d28b232eb353985626017c54685bc3b"
MAX_ARCHIVE = 1024 * 1024 * 1024
MAX_MEMBERS = 12000
MAX_FILE = 128 * 1024 * 1024
MAX_PAYLOAD = 900 * 1024 * 1024
MAX_SEMANTICS = 32 * 1024 * 1024
# Two 512-byte end blocks followed by padding to a 10,240-byte record can
# produce 10,752 zero bytes when the last payload ends at record offset 9,728.
MAX_ZERO_TAIL = 10752
CHUNK = 65536
GRAPH_NAMES = {"runtime-tree.json", "runtime-tree.txt", "runtime-classpath.txt"}
OUTPUT_NAMES = {"status", "java-version.log", "maven-version.log", "enforce.log",
                "tree_json.log", "tree_text.log", "classpath.log"} | GRAPH_NAMES
FALSE_CLAIMS = {"ledger_eligible": False, "offline_reproduced": False,
                "publisher_audit_completed": False, "vulnerability_audited": False,
                "graph_semantics_reviewed": False, "daemon_accepted": False,
                "provider_accepted": False}
CODES = frozenset({"lock_invalid", "path_invalid", "archive_invalid", "archive_limit",
    "duplicate_member", "unexpected_member", "artifact_missing", "artifact_mismatch",
    "metadata_mismatch", "seed_mismatch", "source_changed", "destination_exists",
    "cache_io_failed", "cleanup_failed", "manifest_invalid", "manifest_mismatch"})


class CacheError(Exception):
    def __init__(self, code, *, cleanup_failed=False):
        self.code = code if code in CODES else "cache_io_failed"
        self.cleanup_failed = cleanup_failed is True
        super().__init__(self.code)


def need(condition, code):
    if not condition:
        raise CacheError(code)


def encoded(value):
    try:
        result = json.dumps(value, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=True, allow_nan=False).encode("ascii")
        need(len(result) <= MAX_SEMANTICS, "manifest_invalid")
        return result
    except (ValueError, TypeError, RecursionError):
        raise CacheError("manifest_invalid") from None


def sha(data):
    return hashlib.sha256(data).hexdigest()


def _load_lock():
    try:
        data = Path(__file__).with_name("artifact-lock.json").read_bytes()
        need(len(data) <= 512 * 1024 and sha(data) == LOCK_SHA256, "lock_invalid")
        value = json.loads(data)
        rows = value["artifacts"]
        need(len(rows) == 605 and sha(encoded(rows)) == ARTIFACTS_SHA256, "lock_invalid")
        return rows
    except (OSError, ValueError, TypeError, KeyError):
        raise CacheError("lock_invalid") from None


def _artifact_path(row):
    classifier = "-" + row["classifier"] if row["classifier"] else ""
    return ("m2/" + row["group"].replace(".", "/") + "/" + row["artifact"] + "/" +
            row["version"] + "/" + row["artifact"] + "-" + row["version"] +
            classifier + "." + row["type"])


def _counts(rows):
    return {"artifacts": len(rows), "poms": sum(r["type"] == "pom" for r in rows),
            "selected_runtime_jars": sum(r["selected_runtime"] for r in rows),
            "other_jars": sum(r["type"] == "jar" and not r["selected_runtime"] for r in rows),
            "artifact_bytes": sum(r["size"] for r in rows)}


def _tracking(paths):
    records = {}
    for path in paths:
        parent, name = path.rsplit("/", 1)
        records.setdefault(parent + "/_remote.repositories", []).append(name)
    return {path: "".join(name + ">owned-central=\n" for name in sorted(names)).encode("ascii")
            for path, names in records.items()}


def _regular(path, maximum=MAX_ARCHIVE, *, allow_empty=False):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode)
         and not getattr(info, "st_file_attributes", 0) & 0x400
         and info.st_nlink == 1 and (0 <= info.st_size if allow_empty else 0 < info.st_size)
         and info.st_size <= maximum, "path_invalid")
    return info


def _path(value):
    path = Path(value)
    need(path.is_absolute() and ".." not in path.parts, "path_invalid")
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat()
        need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
             and not getattr(info, "st_file_attributes", 0) & 0x400, "path_invalid")
    return path


def _file_hash(path):
    _regular(path)
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _scan(archive, expected, seed=False):
    """Closed final names/types, bounded GNU/USTAR input, no extraction.

    tarfile resolves GNU long-name records needed by the reviewed online tar.
    PAX attributes are refused; only final canonical regular/directory paths
    in the closed set below are eligible. Nothing executes archive contents.
    """
    size = _regular(archive).st_size
    need(size % 512 == 0, "archive_invalid")
    tracking = _tracking(expected)
    metadata = {path + ".sha1" for path in expected} | set(tracking)
    allowed = set(expected) | metadata
    if not seed:
        allowed |= {"output/" + name for name in OUTPUT_NAMES}
    directories = {str(parent) for name in allowed for parent in PurePosixPath(name).parents
                   if str(parent) != "."}
    seen, members, sha1s, total, last = set(), {}, {}, 0, 0
    try:
        with tarfile.open(archive, "r:") as source:
            for member in source:
                name = member.name
                canonical = PurePosixPath(name).as_posix()
                need(len(seen) < MAX_MEMBERS and 0 <= member.size <= MAX_FILE, "archive_limit")
                need(not member.pax_headers and (member.isreg() or member.isdir()) and not member.linkname
                     and not member.issparse() and name == canonical and not name.startswith("/")
                     and ".." not in PurePosixPath(name).parts and "\\" not in name
                     and all(32 < ord(c) < 127 for c in name), "archive_invalid")
                need(name not in seen, "duplicate_member")
                seen.add(name)
                total += member.size
                need(total <= MAX_PAYLOAD, "archive_limit")
                last = member.offset_data + ((member.size + 511) // 512) * 512
                need(last <= size - 1024, "archive_invalid")
                if member.isdir():
                    need(not seed and member.size == 0 and name in directories, "unexpected_member")
                    continue
                need(name in allowed, "unexpected_member")
                if seed:
                    need(member.type == tarfile.REGTYPE and member.mode == 0o600 and
                         member.uid == member.gid == member.mtime == 0 and
                         member.uname == member.gname == "", "seed_mismatch")
                members[name] = member
                if name in expected:
                    row = expected[name]
                    need(member.size == row["size"], "artifact_mismatch")
                    h256, h1, count = hashlib.sha256(), hashlib.sha1(), 0
                    with source.extractfile(member) as stream:
                        while block := stream.read(CHUNK):
                            count += len(block)
                            need(count <= row["size"], "artifact_mismatch")
                            h256.update(block); h1.update(block)
                    need(count == row["size"] and h256.hexdigest() == row["sha256"], "artifact_mismatch")
                    sha1s[name] = h1.hexdigest().encode("ascii") + b"\n"
            need(set(expected) <= set(members), "artifact_missing")
            if seed:
                need(set(members) == allowed and list(members) == sorted(allowed), "seed_mismatch")
                derived = {path + ".sha1": value for path, value in sha1s.items()} | tracking
                for name, value in derived.items():
                    need(members[name].size == len(value), "metadata_mismatch")
                    with source.extractfile(members[name]) as stream:
                        need(stream.read(len(value) + 1) == value, "metadata_mismatch")
        with archive.open("rb") as stream:
            stream.seek(last)
            tail = stream.read(MAX_ZERO_TAIL + 1)
            need(1024 <= len(tail) <= MAX_ZERO_TAIL and not any(tail) and not stream.read(1), "archive_invalid")
    except (tarfile.TarError, UnicodeError, ValueError, IndexError):
        raise CacheError("archive_invalid") from None
    return members, sha1s


def _receipt(archive, rows):
    paths = {_artifact_path(row): row for row in rows}
    return {"schema_version": 1, "scope": "hdfs_offline_cache_preparation",
            "sha256": _file_hash(archive), "size": archive.stat().st_size,
            "lock_sha256": LOCK_SHA256, "counts": _counts(rows),
            "seed_regular_files": 2 * len(rows) + len(_tracking(paths)),
            "sha1_files": len(rows), "repository_tracking_files": len(_tracking(paths)),
            "metadata_reconstructed": True, "original_auxiliary_copied": False,
            "success": True, "preparation_only": True, "advisory_work_pending": True,
            **FALSE_CLAIMS}


def verify_cache(seed_tar):
    try:
        rows = _load_lock()
        path = _path(seed_tar)
        initial_hash = _file_hash(path)
        _scan(path, {_artifact_path(row): row for row in rows}, seed=True)
        receipt = _receipt(path, rows)
        need(receipt["sha256"] == initial_hash, "source_changed")
        return receipt
    except CacheError:
        raise
    except (OSError, TypeError, ValueError):
        raise CacheError("cache_io_failed") from None


def prepare_cache(source_tar, destination_tar):
    destination, identity, owned, failure, result = None, None, False, None, None
    try:
        rows = _load_lock()
        source, destination = _path(source_tar), _path(destination_tar)
        need(not destination.exists() and not destination.is_symlink(), "destination_exists")
        initial_hash = _file_hash(source)
        expected = {_artifact_path(row): row for row in rows}
        members, sha1s = _scan(source, expected)
        need(_file_hash(source) == initial_hash, "source_changed")
        derived = {path + ".sha1": value for path, value in sha1s.items()} | _tracking(expected)
        fd = os.open(destination, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        owned = True
        info = os.fstat(fd); identity = (info.st_dev, info.st_ino)
        try:
            output = os.fdopen(fd, "w+b")
        except BaseException:
            os.close(fd)
            raise
        with output, tarfile.open(source, "r:") as original:
            with tarfile.open(fileobj=output, mode="w:", format=tarfile.USTAR_FORMAT) as target:
                for name in sorted(set(expected) | set(derived)):
                    info = tarfile.TarInfo(name)
                    info.mode, info.uid, info.gid, info.mtime = 0o600, 0, 0, 0
                    info.uname = info.gname = ""
                    info.size = expected[name]["size"] if name in expected else len(derived[name])
                    stream = original.extractfile(members[name]) if name in expected else io.BytesIO(derived[name])
                    with stream:
                        target.addfile(info, stream)
            output.flush(); os.fsync(output.fileno())
        need(_file_hash(source) == initial_hash, "source_changed")
        info = _regular(destination)
        need((info.st_dev, info.st_ino) == identity, "source_changed")
        result = verify_cache(destination)
        info = _regular(destination)
        need((info.st_dev, info.st_ino) == identity, "source_changed")
    except CacheError as error:
        failure = error.code
    except (OSError, tarfile.TarError, ValueError, TypeError):
        failure = "cache_io_failed"
    if failure is not None:
        cleanup_failed = False
        if owned:
            try:
                info = _regular(destination, allow_empty=True)
                need((info.st_dev, info.st_ino) == identity, "cleanup_failed")
                destination.unlink()
            except (CacheError, OSError):
                cleanup_failed = True
        raise CacheError(failure, cleanup_failed=cleanup_failed) from None
    return result


def _manifest_parts(value, rows):
    need(type(value) is dict and type(value.get("artifacts")) is list, "manifest_invalid")
    key = lambda row: tuple(row[k] for k in ("group", "artifact", "version", "type", "classifier"))
    try:
        need(encoded(sorted(value["artifacts"], key=key)) == encoded(sorted(rows, key=key)), "manifest_mismatch")
        runtime = value["runtime_classpath"]
        need(type(runtime) is dict and set(runtime) == {"schema_version", "entries", "normalized_sha256"}
             and type(runtime["schema_version"]) is int and runtime["schema_version"] == 1
             and type(runtime["entries"]) is list, "manifest_invalid")
        selected = [{k: r[k] for k in ("group", "artifact", "version", "type", "classifier", "size", "sha256")}
                    for r in rows if r["selected_runtime"]]
        need(encoded(sorted(runtime["entries"], key=key)) == encoded(sorted(selected, key=key))
             and runtime["normalized_sha256"] == sha(encoded(runtime["entries"])), "manifest_mismatch")
        graphs = value["graph_outputs"]
        need(type(graphs) is dict and set(graphs) == GRAPH_NAMES, "manifest_invalid")
        for graph in graphs.values():
            need(type(graph) is dict and set(graph) == {"size", "sha256"} and type(graph["size"]) is int
                 and 0 < graph["size"] <= 8 * 1024 * 1024 and type(graph["sha256"]) is str
                 and re.fullmatch(r"[0-9a-f]{64}", graph["sha256"]), "manifest_invalid")
        semantics = value["dependency_semantics"]
        need(type(semantics) is dict and semantics, "manifest_invalid")
        return runtime, graphs, encoded(semantics)
    except (KeyError, TypeError, ValueError):
        raise CacheError("manifest_invalid") from None


def compare_manifests(online, offline):
    rows = _load_lock()
    first, second = _manifest_parts(online, rows), _manifest_parts(offline, rows)
    need(encoded(first[:2]) == encoded(second[:2]) and first[2] == second[2], "manifest_mismatch")
    return {"schema_version": 1, "scope": "hdfs_offline_manifest_comparison",
            "lock_sha256": LOCK_SHA256, "counts": _counts(rows),
            "runtime_classpath_sha256": first[0]["normalized_sha256"],
            "graph_outputs_sha256": sha(encoded(first[1])), "dependency_semantics_sha256": sha(first[2]),
            "artifact_runtime_graph_match": True, "auxiliary_cache_identity_claimed": False,
            "success": True, "preparation_only": True, "advisory_work_pending": True, **FALSE_CLAIMS}
