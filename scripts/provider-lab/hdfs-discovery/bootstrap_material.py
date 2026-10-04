#!/usr/bin/env python3
"""Private verified Maven-byte lease and data-only layout inspection.

The report-only verifier remains unchanged. This adapter never starts Maven,
Java or Docker. A later reviewed consumer owns its own processes and must stop
them before leaving the lease. Bootstrap success is not consumer acceptance.
"""
import argparse
import copy
import datetime as dt
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import tempfile
import time
import types

VERIFIER_SHA256 = "9e541bdc7686ecf2c7687980b2e810ad334251c30cf7e28a9d6b81f3897a56d3"
ARCHIVE_SHA256 = "80ffca22aed9e8b9713a232f3394fd81d7f20322df75efdb2b047dbd3e3a23bb"
ARCHIVE_SHA512 = "831a8591fe20c8243b1dbe7d71e3244f31d1665b0804b2e825e38cbbe5ce0cafb8338851f90780735568773e0a6cd07bbec107cda0b896b008b861075358b6f6"
SIGNATURE_SHA256 = "a034782f2cab6a037143d3e4a703804a9280fcbb28b0b97a5ea8dae79ebcba39"
KEYS_SHA256 = "1e53a10e6b65c64ae0f5a241c8ef289c7578f1109d8a78512dff7de2b29117b3"
FINGERPRINT = "84789D24DF77A32433CE1F079EB80E92EB2135B1"
TRUST_SCOPE = "official_apache_https_published_key_no_out_of_band_identity_claim"
JDK_MANIFEST_SHA256 = "e1c09a9ee23feb81f94016547826c1e694086cd927356fb57fccc312fcc32f85"
JDK_CONFIG_SHA256 = "d0e6e16acb7f941e5206d99ec38e5bba18545c43462541958f84b22e0fc006e8"
JDK_SOURCE_SHA256 = "109562d9f45342ba0a5dbd16a35f20d96d7c667367b2e151c998ca57aa252fbf"
JDK_VERSION = "jdk-17.0.20.1+1"
JDK_RECIPE = "https://github.com/adoptium/containers.git#511f9356dc4d50932a0a5f8cfb0f87ed1aef4f07:17/jdk/ubuntu/noble"
ARCHIVE_BYTES = 9278065
MAX_MEMBERS = 8192
MAX_PAYLOAD = 128 * 1024 * 1024
MAX_TAR = 160 * 1024 * 1024
MAVEN_ROOT = "apache-maven-3.9.16"
MATERIAL_KEYS = frozenset({
    "schema_version", "scope", "maven_version", "maven_archive_sha256", "maven_archive_sha512",
    "signature_sha256", "publisher_keys_sha256", "publisher_fingerprint", "publisher_trust_scope",
    "signature_verified", "verifier_source_sha256", "adapter_source_sha256", "verification_receipt_sha256",
    "jdk_image", "jdk_image_id", "jdk_major", "jdk_java_version", "jdk_manifest_sha256",
    "jdk_config_sha256", "jdk_source_sha256", "layout_sha256",
})
CODES = frozenset({
    "material_invalid", "source_invalid", "source_changed", "jdk_metadata_invalid", "receipt_invalid",
    "layout_invalid", "layout_pax_unsupported", "layout_link_unsupported", "layout_alias",
    "layout_duplicate", "layout_bounds", "layout_mvn_invalid", "layout_truncated", "layout_trailing_data",
    "temporary_failed", "temporary_cleanup_failed", "children_cleanup_failed", "consumer_failed",
    "lease_reused", "lease_failed",
    # Exact finite failures of the reviewed verifier, never arbitrary text.
    "host_not_supported", "download_failed", "download_timeout", "download_worker_failed", "download_invalid",
    "checksum_mismatch", "gpg_unavailable", "gpg_failed", "gpg_timeout", "gpg_output_limit",
    "gpg_import_failed", "gpg_status_invalid", "signature_invalid", "verification_failed",
})


class MaterialError(Exception):
    def __init__(self, code, diagnostic=None):
        if code not in CODES:
            raise ValueError("unknown_material_error")
        if diagnostic is not None and code != "layout_duplicate":
            raise ValueError("invalid_layout_diagnostic")
        self.code = code
        self.diagnostic = validate_layout_diagnostic(diagnostic) if diagnostic is not None else None
        super().__init__(code)


def validate_layout_diagnostic(value):
    """Closed public data only; never retain an archive name or exception text."""
    keys = {"schema_version", "code", "canonical_path_sha256", "existing", "new",
            "same_type", "same_size", "same_mode", "same_content"}
    entry_keys = {"index", "type", "size", "mode", "payload_sha256"}
    def digest(item):
        return type(item) is str and re.fullmatch(r"[0-9a-f]{64}", item) is not None
    valid = (type(value) is dict and set(value) == keys
             and type(value["schema_version"]) is int and value["schema_version"] == 1
             and type(value["code"]) is str and value["code"] == "layout_duplicate"
             and digest(value["canonical_path_sha256"]))
    if not valid:
        raise ValueError("invalid_layout_diagnostic")
    for item in (value["existing"], value["new"]):
        valid = (type(item) is dict and set(item) == entry_keys
                 and type(item["index"]) is int and 1 <= item["index"] <= MAX_MEMBERS
                 and type(item["type"]) is str and item["type"] in {"file", "directory"}
                 and type(item["size"]) is int and 0 <= item["size"] <= MAX_PAYLOAD
                 and type(item["mode"]) is int and 0 <= item["mode"] <= 0o777
                 and (digest(item["payload_sha256"]) if item["type"] == "file"
                      else item["size"] == 0 and item["payload_sha256"] is None))
        if not valid:
            raise ValueError("invalid_layout_diagnostic")
    old, new = value["existing"], value["new"]
    # Directories have zero bytes and null hashes; two directories share empty content.
    expected = {"same_type": old["type"] == new["type"], "same_size": old["size"] == new["size"],
                "same_mode": old["mode"] == new["mode"],
                "same_content": old["type"] == new["type"] and old["size"] == new["size"]
                    and old["payload_sha256"] == new["payload_sha256"]}
    if not old["index"] < new["index"] or any(type(value[key]) is not bool or value[key] != flag
                                              for key, flag in expected.items()):
        raise ValueError("invalid_layout_diagnostic")
    return copy.deepcopy(value)


def need(condition, code):
    if not condition:
        raise MaterialError(code)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "material_invalid")
        result[key] = value
    return result


def decode(data):
    try:
        return json.loads(data, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(MaterialError("material_invalid")))
    except (ValueError, UnicodeError):
        raise MaterialError("material_invalid") from None


def safe_file(path, maximum):
    path = Path(path)
    need(path.is_absolute(), "source_invalid")
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat()
        need(stat.S_ISDIR(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400, "source_invalid")
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not getattr(info, "st_file_attributes", 0) & 0x400
         and 0 < info.st_size <= maximum, "source_invalid")
    return path


def sha(path, algorithm="sha256", maximum=64 * 1024 * 1024):
    value = hashlib.new(algorithm)
    with safe_file(path, maximum).open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            value.update(chunk)
    return value.hexdigest()


def read(path, maximum=1024 * 1024):
    return safe_file(path, maximum).read_bytes()


def write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def load_verifier(path):
    data = read(path, 128 * 1024)
    need(hashlib.sha256(data).hexdigest() == VERIFIER_SHA256, "source_changed")
    # Execute only the reviewed source bytes; never a stale adjacent bytecode file.
    module = types.ModuleType("_reviewed_hdfs_verifier")
    module.__file__ = str(path)
    exec(compile(data, str(path), "exec"), module.__dict__)
    return module


def jdk_bindings(root):
    manifest_bytes = read(root / "jdk-manifest.json")
    config_bytes = read(root / "jdk-config.json")
    recipe = read(root / "jdk-source-Dockerfile.txt")
    need(hashlib.sha256(manifest_bytes).hexdigest() == JDK_MANIFEST_SHA256
         and hashlib.sha256(config_bytes).hexdigest() == JDK_CONFIG_SHA256
         and hashlib.sha256(recipe).hexdigest() == JDK_SOURCE_SHA256, "jdk_metadata_invalid")
    manifest, config = decode(manifest_bytes), decode(config_bytes)
    need(type(manifest) is dict and type(config) is dict and manifest.get("schemaVersion") == 2
         and manifest.get("config", {}).get("digest") == "sha256:" + JDK_CONFIG_SHA256
         and manifest.get("config", {}).get("size") == len(config_bytes)
         and manifest.get("annotations", {}).get("org.opencontainers.image.source") == JDK_RECIPE
         and config.get("os") == "linux" and config.get("architecture") == "amd64"
         and [item for item in config.get("config", {}).get("Env", []) if item.startswith("JAVA_VERSION=")]
             == ["JAVA_VERSION=" + JDK_VERSION], "jdk_metadata_invalid")
    return {"jdk_image": "docker.io/library/eclipse-temurin@sha256:" + JDK_MANIFEST_SHA256,
            "jdk_image_id": "sha256:" + JDK_CONFIG_SHA256, "jdk_major": 17, "jdk_java_version": JDK_VERSION,
            "jdk_manifest_sha256": JDK_MANIFEST_SHA256, "jdk_config_sha256": JDK_CONFIG_SHA256,
            "jdk_source_sha256": JDK_SOURCE_SHA256}


def inspect_layout(path):
    """Read bounded gzip/tar records; never extract or execute archive content.

    Parse each physical header before tarfile can consume PAX/longname payloads.
    Only ordinary files/directories are accepted; require and drain end padding.
    """
    try:
        archive_hash = sha(path)
    except OSError:
        raise MaterialError("source_invalid") from None
    rows, names, size_total, decompressed, mvn = [], {}, 0, 0, None
    try:
        with gzip.open(path, "rb") as source:
            def take(amount):
                nonlocal decompressed
                need(0 <= amount <= 65536, "layout_bounds")
                data = source.read(amount)
                decompressed += len(data)
                need(decompressed <= MAX_TAR, "layout_bounds")
                return data
            while True:
                header = take(512)
                need(len(header) == 512, "layout_truncated")
                if header == b"\0" * 512:
                    need(take(512) == b"\0" * 512, "layout_truncated")
                    while True:
                        tail = take(65536)
                        if not tail:
                            break
                        need(not any(tail), "layout_trailing_data")
                    break
                info = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
                need(info.type not in {tarfile.XHDTYPE, tarfile.XGLTYPE}, "layout_pax_unsupported")
                need(info.type not in {tarfile.LNKTYPE, tarfile.SYMTYPE}, "layout_link_unsupported")
                need(info.type in {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE}, "layout_invalid")
                raw = header[:100].split(b"\0", 1)[0].decode("utf-8")
                if header[257:263] == b"ustar\0":
                    prefix = header[345:500].split(b"\0", 1)[0].decode("utf-8")
                    raw = prefix + "/" + raw if prefix else raw
                name = raw[:-1] if info.isdir() and raw.endswith("/") else raw
                parts = PurePosixPath(name)
                need(name and not parts.is_absolute() and name == parts.as_posix()
                     and ".." not in parts.parts and "\\" not in name
                     and all(ord(char) >= 32 and ord(char) != 127 for char in name)
                     and parts.parts[0] == MAVEN_ROOT and (info.isdir() or not raw.endswith("/")), "layout_alias")
                need(len(rows) < MAX_MEMBERS and type(info.size) is int and info.size >= 0
                     and size_total + info.size <= MAX_PAYLOAD, "layout_bounds")
                need(not info.isdir() or info.size == 0, "layout_invalid")
                need(type(info.mode) is int and 0 <= info.mode <= 0o777, "layout_invalid")
                content = hashlib.sha256()
                remaining = info.size
                while remaining:
                    chunk = take(min(65536, remaining))
                    need(chunk, "layout_truncated")
                    content.update(chunk)
                    remaining -= len(chunk)
                padding = (-info.size) % 512
                pad = take(padding)
                need(len(pad) == padding, "layout_truncated")
                need(pad == b"\0" * padding, "layout_invalid")
                kind = "directory" if info.isdir() else "file"
                entry = {"index": len(rows) + 1, "type": kind, "size": info.size, "mode": info.mode,
                         "payload_sha256": content.hexdigest() if kind == "file" else None}
                if name in names:
                    old = names[name]
                    raise MaterialError("layout_duplicate", {
                        "schema_version": 1, "code": "layout_duplicate",
                        "canonical_path_sha256": hashlib.sha256(name.encode("utf-8")).hexdigest(),
                        "existing": old, "new": entry,
                        "same_type": old["type"] == kind, "same_size": old["size"] == info.size,
                        "same_mode": old["mode"] == info.mode,
                        "same_content": old["type"] == kind and old["size"] == info.size
                            and old["payload_sha256"] == entry["payload_sha256"],
                    })
                row = {"path": name, "type": kind, "size": info.size, "mode": info.mode,
                       "sha256": content.hexdigest() if kind == "file" else None}
                rows.append(row)
                names[name] = entry
                size_total += info.size
                if name == MAVEN_ROOT + "/bin/mvn":
                    need(kind == "file" and info.size > 0 and info.mode & 0o111, "layout_mvn_invalid")
                    mvn = {"size": info.size, "sha256": content.hexdigest(), "executable": True}
            for name in names:
                need(all(names.get(str(parent), {"type": "directory"})["type"] == "directory"
                         for parent in PurePosixPath(name).parents if str(parent) != "."), "layout_invalid")
        need(mvn is not None, "layout_mvn_invalid")
    except (OSError, EOFError, UnicodeError, tarfile.TarError, ValueError):
        raise MaterialError("layout_invalid") from None
    return {"schema_version": 1, "scope": "maven_archive_data_only_layout", "archive_sha256": archive_hash,
            "members": len(rows), "files": sum(row["type"] == "file" for row in rows),
            "directories": sum(row["type"] == "directory" for row in rows), "payload_bytes": size_total,
            "decompressed_bytes": decompressed, "members_sha256": hashlib.sha256(canonical(rows)).hexdigest(),
            "mvn": mvn, "extracted": False, "executed": False}


def identity(root):
    info = root.lstat()
    need(root.is_absolute() and stat.S_ISDIR(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400
         and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.getuid(), "temporary_failed")
    return info.st_dev, info.st_ino


def artifact_hashes(root):
    need((root / "maven.tar.gz").stat().st_size == ARCHIVE_BYTES
         and sha(root / "maven.tar.gz") == ARCHIVE_SHA256
         and sha(root / "maven.tar.gz", "sha512") == ARCHIVE_SHA512
         and sha(root / "maven.tar.gz.asc", maximum=16384) == SIGNATURE_SHA256
         and sha(root / "maven-KEYS.txt", maximum=1024 * 1024) == KEYS_SHA256
         and sha(root / "verify_bootstrap.py", maximum=128 * 1024) == VERIFIER_SHA256, "checksum_mismatch")


def material_value(root, adapter_sha):
    return {"schema_version": 2, "scope": "hdfs_verified_bootstrap_material", "maven_version": "3.9.16",
            "maven_archive_sha256": ARCHIVE_SHA256, "maven_archive_sha512": ARCHIVE_SHA512,
            "signature_sha256": SIGNATURE_SHA256, "publisher_keys_sha256": KEYS_SHA256,
            "publisher_fingerprint": FINGERPRINT, "publisher_trust_scope": TRUST_SCOPE,
            "signature_verified": True, "verifier_source_sha256": VERIFIER_SHA256,
            "adapter_source_sha256": adapter_sha,
            "verification_receipt_sha256": sha(root / "verification-receipt.json", maximum=16384),
            "layout_sha256": sha(root / "maven-layout.json", maximum=16384), **jdk_bindings(root)}


def validate_material(value, root):
    """Pure current-file revalidation; no import/download/subprocess or trust upgrade."""
    try:
        root = Path(root)
        identity(root)
        need(type(value) is dict and set(value) == MATERIAL_KEYS and type(value["schema_version"]) is int
             and type(value["jdk_major"]) is int and value["signature_verified"] is True, "material_invalid")
        artifact_hashes(root)
        adapter_sha = sha(Path(__file__).absolute(), maximum=128 * 1024)
        need(canonical(value) == canonical(material_value(root, adapter_sha)), "material_invalid")
        layout_bytes = read(root / "maven-layout.json", 16384)
        need(layout_bytes == canonical(inspect_layout(root / "maven.tar.gz")), "layout_invalid")
        receipt = decode(read(root / "verification-receipt.json", 16384))
        expected = verification_fields(adapter_sha)
        need(type(receipt) is dict and set(receipt) == set(expected) | {"started_utc", "finished_utc"}, "receipt_invalid")
        need(all(type(receipt[key]) is type(item) and canonical(receipt[key]) == canonical(item)
                 for key, item in expected.items()), "receipt_invalid")
        need(all(type(receipt[key]) is str and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z", receipt[key])
                 for key in ("started_utc", "finished_utc")), "receipt_invalid")
        start, end = (dt.datetime.fromisoformat(receipt[key].replace("Z", "+00:00"))
                      for key in ("started_utc", "finished_utc"))
        need(0 <= (end - start).total_seconds() <= 400
             and 0 <= (dt.datetime.now(dt.timezone.utc) - end).total_seconds() <= 7200, "receipt_invalid")
        return copy.deepcopy(value)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        raise MaterialError("material_invalid") from None


def verification_fields(adapter_sha):
    return {"schema_version": 1, "scope": "hdfs_bootstrap_material_verification", "ledger_eligible": False,
            "maven_version": "3.9.16", "archive_sha256": ARCHIVE_SHA256, "archive_sha512": ARCHIVE_SHA512,
            "signature_sha256": SIGNATURE_SHA256, "publisher_keys_sha256": KEYS_SHA256,
            "publisher_fingerprint": FINGERPRINT, "publisher_trust_scope": TRUST_SCOPE,
            "verifier_source_sha256": VERIFIER_SHA256, "adapter_source_sha256": adapter_sha,
            "checks": {name: True for name in ("hosted_linux", "checksums_verified", "signature_verified",
                                               "jdk_metadata_verified", "layout_inspected")}}


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


class BootstrapLease:
    def __init__(self, verifier_path, jdk_manifest_path, jdk_config_path, jdk_source_path):
        self.paths = tuple(Path(item).absolute() for item in (verifier_path, jdk_manifest_path, jdk_config_path, jdk_source_path))
        self.root = None
        self._identity = None
        self._verifier = None
        self._used = False
        self._material = None
        self._verification = None
        self._layout = None
        self._old_umask = None
        self._clock = None
        self._report = {"schema_version": 1, "scope": "hdfs_bootstrap_material_inspection", "ledger_eligible": False,
                        "started_utc": None, "finished_utc": None, "duration_seconds": None,
                        "material": None, "verification": None, "layout": None,
                        "adapter_source_sha256": None, "layout_diagnostic": None,
                        "checks": {name: False for name in ("checksums_verified", "signature_verified", "layout_inspected")},
                        "success": False, "errors": [],
                        "cleanup": {"children_stopped": True, "temporary_removed": True}}

    @property
    def report(self):
        return copy.deepcopy(self._report)

    @property
    def material(self):
        need(self._material is not None and self._report["finished_utc"] is None, "material_invalid")
        return copy.deepcopy(self._material)

    def _record(self, error):
        candidate = getattr(error, "code", None)
        code = candidate if type(candidate) is str and candidate in CODES else "lease_failed"
        self._report["errors"].append(code)
        if code == "layout_duplicate":
            try:
                diagnostic = validate_layout_diagnostic(getattr(error, "diagnostic", None))
            except (ValueError, TypeError, KeyError):
                return
            self._report["layout_diagnostic"] = diagnostic

    def __enter__(self):
        need(not self._used, "lease_reused")
        self._used = True
        self._clock = time.monotonic()
        self._report["started_utc"] = utc_now()
        self._old_umask = os.umask(0o077)
        failed = False
        try:
            self._adapter_sha = sha(Path(__file__).absolute(), maximum=128 * 1024)
            self._report["adapter_source_sha256"] = self._adapter_sha
            self._verifier = load_verifier(self.paths[0])
            self._verifier.hosted_guard()
            self.root = Path(tempfile.mkdtemp(prefix="hdfs-material-", dir="/tmp"))
            self._report["cleanup"]["temporary_removed"] = False
            self._identity = identity(self.root)
            for source, name in zip(self.paths, ("verify_bootstrap.py", "jdk-manifest.json", "jdk-config.json", "jdk-source-Dockerfile.txt")):
                write_new(self.root / name, read(source))
            need(sha(self.root / "verify_bootstrap.py") == VERIFIER_SHA256, "source_changed")
            jdk_bindings(self.root)
            self._verifier.download_inputs(self.root, self._report["cleanup"])
            self._verifier.verify_hashes(self.root)
            artifact_hashes(self.root)
            self._report["checks"]["checksums_verified"] = True
            self._verifier.signature_check(self.root, self._report["cleanup"])
            self._report["checks"]["signature_verified"] = True
            artifact_hashes(self.root)
            layout = inspect_layout(self.root / "maven.tar.gz")
            self._report["checks"]["layout_inspected"] = True
            write_new(self.root / "maven-layout.json", canonical(layout))
            verification = {**verification_fields(self._adapter_sha), "started_utc": self._report["started_utc"],
                            "finished_utc": utc_now()}
            write_new(self.root / "verification-receipt.json", canonical(verification))
            self._material = material_value(self.root, self._adapter_sha)
            validate_material(self._material, self.root)
            self._verification, self._layout = verification, layout
        except BaseException as error:
            self._record(error)
            failed = True
        if failed:
            self._finish()
            raise MaterialError(self._report["errors"][0]) from None
        return self

    def _finish(self):
        if self.root is not None and self._report["cleanup"]["children_stopped"]:
            try:
                self._verifier.remove_owned(self.root, self._identity)
                self._report["cleanup"]["temporary_removed"] = True
            except BaseException:
                self._report["errors"].append("temporary_cleanup_failed")
        elif self.root is not None:
            self._report["errors"].append("temporary_cleanup_failed")
        if not self._report["cleanup"]["children_stopped"]:
            if "children_cleanup_failed" not in self._report["errors"]:
                self._report["errors"].append("children_cleanup_failed")
        if self._old_umask is not None:
            os.umask(self._old_umask)
            self._old_umask = None
        self._report["finished_utc"] = utc_now()
        self._report["duration_seconds"] = round(time.monotonic() - self._clock, 6)
        self._report["success"] = self._material is not None and not self._report["errors"] and all(self._report["cleanup"].values())
        if self._report["success"]:
            self._report.update(material=copy.deepcopy(self._material), verification=self._verification, layout=self._layout)

    def __exit__(self, exc_type, exc, traceback):
        if exc_type is not None:
            self._report["errors"].append("consumer_failed")
        try:
            validate_material(self._material, self.root)
            need(sha(self.paths[0]) == VERIFIER_SHA256
                 and sha(Path(__file__).absolute()) == self._adapter_sha, "source_changed")
        except BaseException as error:
            self._record(error)
        self._finish()
        if exc_type is None and not self._report["success"]:
            raise MaterialError(self._report["errors"][0]) from None
        return False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("verifier", "jdk-manifest", "jdk-config", "jdk-source", "report"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args(argv)
    lease = BootstrapLease(args.verifier, args.jdk_manifest, args.jdk_config, args.jdk_source)
    try:
        need(args.report.is_absolute(), "source_invalid")
        for ancestor in (args.report.parent, *args.report.parent.parents):
            need(stat.S_ISDIR(ancestor.lstat().st_mode), "source_invalid")
        fd = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except (OSError, MaterialError):
        print("report_create_failed", file=sys.stderr)
        return 1
    try:
        with os.fdopen(fd, "wb") as output:
            try:
                with lease:
                    pass
            except MaterialError:
                pass
            output.write(canonical(lease.report))
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        print("report_write_failed", file=sys.stderr)
        return 1
    return 0 if lease.report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
