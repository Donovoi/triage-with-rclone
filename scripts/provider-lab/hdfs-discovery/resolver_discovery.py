"""Private hosted-only dependency discovery; no offline or daemon acceptance.

Imports and plan construction are pure. Native execution is available only via
discover(), after closed bootstrap bindings and the hosted Linux guard pass.
Networked Maven/plugin code is NOT destination-confined by repository XML.
"""
from dataclasses import dataclass
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time
import uuid
import bootstrap_material
import graph_export
import offline_cache


INPUT_HASHES = {
    "pom.xml": "c1234134333255ae53df8714471011c490c0cf60e66109743703fcd0abceece2",
    "settings.xml": "73c88f4d9660338f35a6e56978f8567f89f5a85641d5338f189fc489440b364c",
    "global-settings.xml": "aeb786c97c2a0103b71c04ab1b29508d7ec1c402a9d36e22301407b23670edf2",
}
# This is a separate, online-only dependency experiment. Its additional KDC
# closure has no reviewed offline lock yet; never reuse the SIMPLE cache.
KERBEROS_INPUT_HASHES = {
    "pom.xml": "f2b4397a3e096770be70663bcb801ff942ee4d84f294b75826a4934b13e7bb28",
    "settings.xml": "73c88f4d9660338f35a6e56978f8567f89f5a85641d5338f189fc489440b364c",
    "global-settings.xml": "aeb786c97c2a0103b71c04ab1b29508d7ec1c402a9d36e22301407b23670edf2",
}
MAVEN_SHA512 = "831a8591fe20c8243b1dbe7d71e3244f31d1665b0804b2e825e38cbbe5ce0cafb8338851f90780735568773e0a6cd07bbec107cda0b896b008b861075358b6f6"
HASH = re.compile(r"[a-f0-9]{64}\Z")
COMPONENT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.+-]{0,127}\Z")
LABEL = "org.openai.triage.hdfs-discovery"
MAX_ARCHIVE = 1024 * 1024 * 1024
MAX_FILES = 12000
# Two end blocks plus record padding can exceed one record by one block.
MAX_ZERO_TAIL = tarfile.RECORDSIZE + tarfile.BLOCKSIZE
STATUS_RECORDS = {
    ("failed\n" + stage + "\n").encode("ascii"): "maven_status_failed_" + stage
    for stage in ("bootstrap", "versions", "enforce", "tree_json", "tree_text", "classpath", "complete")
}
STATUS_RECORDS[b"resolved\ncomplete\n"] = "maven_status_resolved_complete"
GOALS = (
    ("enforce", ("org.apache.maven.plugins:maven-enforcer-plugin:3.6.3:enforce",)),
    ("tree_json", ("org.apache.maven.plugins:maven-dependency-plugin:3.11.0:tree", "-Dscope=runtime", "-Dverbose=true", "-DoutputType=json", "-DoutputFile=/work/output/runtime-tree.json")),
    ("tree_text", ("org.apache.maven.plugins:maven-dependency-plugin:3.11.0:tree", "-Dscope=runtime", "-Dverbose=true", "-DoutputType=text", "-DoutputFile=/work/output/runtime-tree.txt")),
    ("classpath", ("org.apache.maven.plugins:maven-dependency-plugin:3.11.0:build-classpath", "-DincludeScope=runtime", "-Dmdep.outputFile=/work/output/runtime-classpath.txt")),
)
CODES = frozenset({
    "bootstrap_unresolved", "bootstrap_invalid", "bootstrap_archive_mismatch", "bootstrap_archive_unsafe",
    "candidate_invalid", "unsafe_path", "hosted_linux_required", "private_directory_required",
    "command_timeout", "command_output_limit", "command_failed", "command_start_failed", "command_cleanup_failed",
    "docker_json_invalid", "docker_platform_invalid", "base_image_mismatch", "image_binding_invalid",
    "container_binding_invalid", "container_failed", "container_cleanup_failed", "image_cleanup_failed",
    "context_cleanup_failed", "source_changed", "discovery_failed", "discovery_interrupted", "artifact_archive_invalid", "artifact_limit",
    "artifact_coordinate_invalid", "artifact_metadata_invalid", "artifact_status_invalid", "classpath_invalid",
    "artifact_semantics_invalid", "offline_cache_invalid", "cache_cleanup_failed",
}) | frozenset(STATUS_RECORDS.values()) | frozenset("artifact_semantics_" + code for code in graph_export.CODES)


class DiscoveryError(Exception):
    def __init__(self, code, pom_diagnostic=None):
        if code not in CODES:
            raise ValueError("invalid_diagnostic_code")
        self.code = code
        self.pom_diagnostic = None
        if pom_diagnostic is not None:
            diagnostic = graph_export.validate_pom_diagnostic(pom_diagnostic)
            if code != "artifact_semantics_" + diagnostic["code"]:
                raise ValueError("invalid_diagnostic_code")
            self.pom_diagnostic = diagnostic
        super().__init__(code)


def need(condition, code):
    if not condition:
        raise DiscoveryError(code)


def regular(path, maximum):
    path = Path(path)
    need(path.is_absolute(), "unsafe_path")
    for ancestor in (path, *path.parents):
        item = ancestor.lstat()
        need(not stat.S_ISLNK(item.st_mode) and not getattr(item, "st_file_attributes", 0) & 0x400, "unsafe_path")
    item = path.stat()
    need(stat.S_ISREG(item.st_mode) and item.st_nlink == 1 and item.st_size <= maximum, "unsafe_path")
    return path


def file_hash(path, algorithm="sha256", maximum=MAX_ARCHIVE):
    path = regular(path, maximum)
    before = path.stat()
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        need((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), "unsafe_path")
        result = hashlib.file_digest(stream, algorithm).hexdigest()
        after = os.fstat(stream.fileno())
    end = path.stat()
    need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) ==
         (end.st_dev, end.st_ino, end.st_size, end.st_mtime_ns), "unsafe_path")
    return result


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "docker_json_invalid")
        result[key] = value
    return result


def json_value(raw):
    need(type(raw) is bytes and len(raw) <= 1024 * 1024, "docker_json_invalid")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(DiscoveryError("docker_json_invalid")))
    except (UnicodeError, ValueError):
        raise DiscoveryError("docker_json_invalid") from None


def candidate_hashes(profile):
    need(type(profile) is str and profile in {"hdfs", "kerberos"}, "candidate_invalid")
    return dict(INPUT_HASHES if profile == "hdfs" else KERBEROS_INPUT_HASHES)


def candidate_inputs(root, profile="hdfs"):
    hashes = candidate_hashes(profile)
    root = Path(root).absolute()
    need(root.is_dir() and {p.name for p in root.iterdir()} == set(hashes), "candidate_invalid")
    result = {}
    for name, digest in hashes.items():
        path = regular(root / name, 256 * 1024)
        need(file_hash(path) == digest, "candidate_invalid")
        result[name] = path.read_bytes()
    return result


def validate_bootstrap(value, archive):
    # The adapter binds a live verified-byte lease, whole KEYS bundle, actual
    # archive layout and immutable JDK provenance. A past success flag alone
    # cannot authorize use of newly supplied archive bytes.
    try:
        archive = Path(archive).absolute()
        need(archive.name == "maven.tar.gz", "bootstrap_invalid")
        return bootstrap_material.validate_material(value, archive.parent)
    except (bootstrap_material.MaterialError, OSError, ValueError, TypeError):
        raise DiscoveryError("bootstrap_invalid") from None


def driver_script(*, offline=False):
    lines = ["#!/bin/sh", "set -eu", "umask 077", "mkdir -p /work/project /work/m2 /work/output /work/home /work/tmp",
             "cp /opt/resolver/*.xml /work/project/", "status=failed", "stage=bootstrap",
             "finish() { code=$?; trap - EXIT; printf '%s\\n%s\\n' \"$status\" \"$stage\" > /work/output/status; tar -C /work -cf - m2 output; exit \"$code\"; }",
             "trap finish EXIT", "stage=versions",
             "/opt/java/openjdk/bin/java -version > /work/output/java-version.log 2>&1",
             "grep -Eq '^openjdk version \"17[.]' /work/output/java-version.log",
             # Maven 3.9.16's documented -B disables color, including version output.
             "/opt/apache-maven-3.9.16/bin/mvn -B -version > /work/output/maven-version.log 2>&1",
             "grep -Eq '^Apache Maven 3[.]9[.]16([[:space:]]|$)' /work/output/maven-version.log"]
    if offline:
        lines += ["tar --no-same-owner -xf /opt/resolver/offline-seed.tar -C /work"]
    prefix = "/opt/apache-maven-3.9.16/bin/mvn " + ("-o " if offline else "") + "-B -ntp -C -nsu -s /work/project/settings.xml -gs /work/project/global-settings.xml -Dmaven.repo.local=/work/m2 -f /work/project/pom.xml"
    for name, args in GOALS:
        lines += ["stage=" + name,
                  "timeout --signal=TERM --kill-after=3s 150s " + prefix + " " + " ".join(args) +
                  " > /work/output/" + name + ".log 2>&1"]
    lines += ["stage=complete", "status=resolved"]
    return "\n".join(lines) + "\n"


def dockerfile(bootstrap, *, offline=False, seed_sha256=None):
    need(not offline or type(seed_sha256) is str and HASH.fullmatch(seed_sha256), "offline_cache_invalid")
    return ("FROM " + bootstrap["jdk_image"] + "\nUSER 0\n"
            "COPY maven.tar.gz /tmp/maven.tar.gz\n"
            "RUN echo '" + MAVEN_SHA512 + "  /tmp/maven.tar.gz' | sha512sum -c - && "
            "tar --no-same-owner -xzf /tmp/maven.tar.gz -C /opt && rm /tmp/maven.tar.gz && "
            "mkdir -p /opt/resolver && chmod -R a-w /opt/apache-maven-3.9.16\n"
            "COPY pom.xml settings.xml global-settings.xml driver.sh /opt/resolver/\n"
            + ("COPY offline-seed.tar /opt/resolver/offline-seed.tar\nRUN echo '" + seed_sha256 +
               "  /opt/resolver/offline-seed.tar' | sha256sum -c -\n" if offline else "") +
            "RUN chmod -R a=rX /opt/resolver\nUSER 10001:10001\nWORKDIR /work\n")


def container_args(name, image, run_id, *, offline=False):
    need(re.fullmatch(r"hdfs-discovery-[a-f0-9]{32}", name) and name == "hdfs-discovery-" + run_id
         and re.fullmatch(r"sha256:[a-f0-9]{64}", image), "container_binding_invalid")
    return ["create", "--name", name, "--label", LABEL + "=" + run_id, "--network", "none" if offline else "bridge",
            "--read-only", "--user", "10001:10001", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", "128", "--memory", "4g", "--cpus", "2", "--init", "--cgroupns", "private", "--ipc", "private",
            "--tmpfs", "/work:rw,nosuid,nodev,noexec,size=2g,mode=0700,uid=10001,gid=10001",
            "--entrypoint", "/usr/bin/env", image, "-i", "HOME=/work/home", "PATH=/opt/java/openjdk/bin:/usr/bin:/bin",
            "JAVA_HOME=/opt/java/openjdk", "MAVEN_OPTS=-Duser.home=/work/home -Djava.io.tmpdir=/work/tmp -XX:MaxRAMPercentage=50.0",
            "LANG=C", "LC_ALL=C", "/bin/sh", "/opt/resolver/driver.sh"]


@dataclass(frozen=True)
class Result:
    code: int
    stdout: Path
    stderr: Path


class Docker:
    """Bounded Linux pipe capture. Raw bytes remain only in the private run root."""
    def __init__(self, root, *, max_calls=30):
        need(type(max_calls) is int and 30 <= max_calls <= 120, "command_output_limit")
        self.root, self.calls = root, 0
        self.max_calls = max_calls
        self.environment = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL") if key in os.environ}
        self.environment.update(HOME=str(root), DOCKER_CONFIG=str(root / "docker-config"))
        (root / "docker-config").mkdir(mode=0o700)

    def call(self, arguments, timeout=15, limit=1024 * 1024, allow_failure=False):
        self.calls += 1
        need(self.calls <= self.max_calls and type(timeout) is int and 1 <= timeout <= 630
             and type(limit) is int and 1 <= limit <= MAX_ARCHIVE, "command_output_limit")
        out, err = (self.root / ("command-%02d." % self.calls + suffix) for suffix in ("out", "err"))
        process = None
        try:
            with out.open("xb") as stdout, err.open("xb") as stderr, selectors.DefaultSelector() as selector:
                os.chmod(out, 0o600); os.chmod(err, 0o600)
                process = subprocess.Popen(["/usr/bin/docker", *arguments], stdin=subprocess.DEVNULL,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.root,
                                           env=self.environment, start_new_session=True)
                for pipe, target, bound in ((process.stdout, stdout, limit), (process.stderr, stderr, 8 * 1024 * 1024)):
                    os.set_blocking(pipe.fileno(), False)
                    selector.register(pipe, selectors.EVENT_READ, [target, bound, 0])
                deadline = time.monotonic() + timeout
                while selector.get_map():
                    need(time.monotonic() < deadline, "command_timeout")
                    for key, _ in selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                        data = os.read(key.fileobj.fileno(), 65536)
                        if not data:
                            selector.unregister(key.fileobj); continue
                        key.data[2] += len(data)
                        need(key.data[2] <= key.data[1], "command_output_limit")
                        key.data[0].write(data)
                try:
                    process.wait(timeout=max(0.01, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    raise DiscoveryError("command_timeout") from None
                need(allow_failure or process.returncode == 0, "command_failed")
                return Result(process.returncode, out, err)
        except OSError:
            raise DiscoveryError("command_start_failed") from None
        finally:
            if process is not None:
                try:
                    if process.poll() is None:
                        need(os.getpgid(process.pid) == process.pid, "command_cleanup_failed")
                        os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=3)
                except (OSError, subprocess.TimeoutExpired):
                    raise DiscoveryError("command_cleanup_failed") from None
                finally:
                    for pipe in (process.stdout, process.stderr):
                        if pipe is not None: pipe.close()

    def inspect(self, kind, identity, allow_missing=False):
        result = self.call([kind, "inspect", identity], allow_failure=True)
        if result.code:
            need(allow_missing, "container_binding_invalid")
            # Inspect failure is never absence by itself. The exact-name/ID
            # filtered listing must itself succeed and contain zero objects.
            immutable = bool(re.fullmatch(r"(?:sha256:)?[a-f0-9]{64}", identity))
            if kind == "image" and immutable:
                listed = self.call(["image", "ls", "--all", "--no-trunc", "--quiet"])
                values = listed.stdout.read_text(encoding="ascii").splitlines()
                need(all(re.fullmatch(r"sha256:[a-f0-9]{64}", value) for value in values)
                     and identity not in values, "container_binding_invalid")
                return None
            filter_value = ("id=" + identity if immutable else "name=^/" + identity + "$" if kind == "container"
                            else "reference=" + identity)
            args = [kind, "ls", "--all", "--no-trunc", "--quiet", "--filter", filter_value]
            listed = self.call(args)
            need(listed.stdout.read_bytes() == b"", "container_binding_invalid")
            return None
        value = json_value(result.stdout.read_bytes())
        need(type(value) is list and len(value) == 1 and type(value[0]) is dict, "docker_json_invalid")
        return value[0]


def inspect_container(value, name, image, run_id, *, offline=False):
    need(type(value) is dict and value.get("Name") == "/" + name and value.get("Image") == image
         and re.fullmatch(r"[a-f0-9]{64}", value.get("Id", "")), "container_binding_invalid")
    config, host = value.get("Config", {}), value.get("HostConfig", {})
    need(config.get("Labels", {}).get(LABEL) == run_id and config.get("User") == "10001:10001"
         and config.get("Entrypoint") == ["/usr/bin/env"] and config.get("Cmd") == container_args(name, image, run_id, offline=offline)[container_args(name, image, run_id, offline=offline).index(image)+1:]
         and not config.get("Volumes") and not config.get("ExposedPorts") and not config.get("Healthcheck"), "container_binding_invalid")
    need(host.get("NetworkMode") == ("none" if offline else "bridge") and host.get("ReadonlyRootfs") is True and not host.get("Privileged")
         and not host.get("Binds") and not host.get("PortBindings") and host.get("CapDrop") == ["ALL"]
         and not host.get("CapAdd") and host.get("SecurityOpt") in (["no-new-privileges"], ["no-new-privileges=true"])
         and host.get("Memory") == 4 * 1024**3 and host.get("NanoCpus") == 2 * 10**9 and host.get("PidsLimit") == 128
         and host.get("Init") is True and host.get("IpcMode") == "private" and host.get("CgroupnsMode") == "private"
         and host.get("Tmpfs") == {"/work": "rw,nosuid,nodev,noexec,size=2g,mode=0700,uid=10001,gid=10001"}
         and not host.get("Devices") and not host.get("DeviceRequests") and not host.get("ExtraHosts")
         and not host.get("PidMode"), "container_binding_invalid")
    mounts = value.get("Mounts")
    need(type(mounts) is list and all(m.get("Type") == "tmpfs" and m.get("Destination") == "/work" for m in mounts), "container_binding_invalid")


def artifact_coordinate(name):
    parts = PurePosixPath(name).parts
    need(len(parts) >= 5 and parts[0] == "m2", "artifact_coordinate_invalid")
    group, artifact, version, filename = ".".join(parts[1:-3]), parts[-3], parts[-2], parts[-1]
    need(all(COMPONENT.fullmatch(x) and x not in (".", "..") for x in parts[1:])
         and not any(x in version.upper() for x in ("SNAPSHOT", "LATEST", "RELEASE")), "artifact_coordinate_invalid")
    match = re.fullmatch(re.escape(artifact + "-" + version) + r"(?:-([A-Za-z0-9_][A-Za-z0-9_.+-]{0,63}))?\.(jar|pom)", filename)
    need(match is not None and match.group(1) not in ("tests", "test", "test-sources"), "artifact_coordinate_invalid")
    return {"group": group, "artifact": artifact, "version": version, "classifier": match.group(1) or "", "type": match.group(2)}


def discovery_status(archive):
    """Diagnostic only: accept one finite status from a complete bounded tar.

    The child supplies this stage. It does not prove the failure cause and can
    never qualify dependency inventory or override a nonzero container exit.
    Malformed or partial output supplies no additional diagnostic.
    """
    try:
        archive = regular(archive, MAX_ARCHIVE)
        need(archive.stat().st_size % 512 == 0, "artifact_archive_invalid")
        seen, total, last, status = set(), 0, 0, None
        with tarfile.open(archive, "r:") as source:
            for member in source:
                path = PurePosixPath(member.name)
                canonical = path.as_posix()
                need(len(seen) < MAX_FILES and canonical not in seen and not member.pax_headers
                     and (member.isfile() or member.isdir()) and 0 <= member.size <= 128 * 1024 * 1024
                     and not path.is_absolute() and ".." not in path.parts and "\\" not in member.name
                     and path.parts[0] in ("m2", "output")
                     and (member.name == canonical or member.isdir() and member.name == canonical + "/")
                     and all(32 < ord(c) < 127 for c in member.name), "artifact_archive_invalid")
                seen.add(canonical)
                total += member.size
                need(total <= 900 * 1024 * 1024, "artifact_limit")
                last = max(last, member.offset_data + ((member.size + 511) // 512) * 512)
                if member.name == "output/status":
                    need(member.isfile() and member.size <= 128, "artifact_status_invalid")
                    status = source.extractfile(member).read()
            need(status in STATUS_RECORDS, "artifact_status_invalid")
        with archive.open("rb") as stream:
            stream.seek(last)
            tail = stream.read(MAX_ZERO_TAIL + 1)
            need(1024 <= len(tail) <= MAX_ZERO_TAIL and len(tail) % 512 == 0
                 and not any(tail) and not stream.read(1), "artifact_archive_invalid")
        return STATUS_RECORDS[status]
    except (DiscoveryError, tarfile.TarError, OSError, ValueError, IndexError, UnicodeError):
        return None


def artifact_manifest(archive):
    regular(archive, MAX_ARCHIVE)
    records, files, total, last, graphs = [], {}, 0, 0, {}
    poms, pom_bytes = [], 0
    directories, output_files, output_bytes = 0, 0, 0
    # Publish only finite categories and totals for auxiliary cache data. Its
    # names and contents may contain repository addresses or local identities.
    metadata_suffixes = {
        ".sha1": "sha1_checksum", ".sha256": "sha256_checksum",
        ".sha512": "sha512_checksum", ".md5": "md5_checksum",
        "/_remote.repositories": "repository_tracking",
        ".lastUpdated": "download_status",
        "resolver-status.properties": "resolver_status",
        "maven-metadata-owned-central.xml": "repository_metadata",
        "maven-metadata-central.xml": "repository_metadata",
    }
    auxiliary = {kind: {"files": 0, "bytes": 0} for kind in sorted(set(metadata_suffixes.values()))}
    try:
        with tarfile.open(archive, "r:") as source:
            for member in source:
                path = PurePosixPath(member.name)
                canonical = path.as_posix()
                need(len(files) < MAX_FILES and not member.pax_headers and (member.isfile() or member.isdir())
                     and not path.is_absolute() and ".." not in path.parts and "\\" not in member.name
                     and path.parts[0] in ("m2", "output") and canonical not in files
                     and (member.name == canonical or member.isdir() and member.name == canonical + "/")
                     and all(32 < ord(c) < 127 for c in member.name), "artifact_archive_invalid")
                total += member.size
                need(total <= 900 * 1024 * 1024 and 0 <= member.size <= 128 * 1024 * 1024
                     and (member.isfile() or member.size == 0), "artifact_limit")
                last = max(last, member.offset_data + ((member.size + 511) // 512) * 512)
                files[canonical] = None
                if not member.isfile():
                    directories += 1
                    continue
                if path.parts[0] == "output":
                    need(member.name in {"output/" + n for n in ("status", "java-version.log", "maven-version.log",
                         "enforce.log", "tree_json.log", "tree_text.log", "classpath.log", "runtime-tree.json",
                         "runtime-tree.txt", "runtime-classpath.txt")}, "artifact_metadata_invalid")
                    output_files += 1
                    output_bytes += member.size
                stream = source.extractfile(member)
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
                files[member.name] = (member, digest)
                if path.parts[0] == "m2" and path.suffix in (".jar", ".pom"):
                    coordinate = artifact_coordinate(member.name)
                    records.append(dict(coordinate, size=member.size, sha256=digest,
                                        selected_runtime=False, origin="unverified_private_cache"))
                    if path.suffix == ".pom":
                        pom_bytes += member.size
                        need(member.size <= 4 * 1024 * 1024 and pom_bytes <= 32 * 1024 * 1024, "artifact_limit")
                        poms.append({"coordinate": coordinate, "size": member.size, "sha256": digest,
                                     "content": source.extractfile(member).read()})
                elif path.parts[0] == "m2":
                    kinds = [kind for suffix, kind in metadata_suffixes.items() if member.name.endswith(suffix)]
                    need(len(kinds) == 1, "artifact_metadata_invalid")
                    auxiliary[kinds[0]]["files"] += 1
                    auxiliary[kinds[0]]["bytes"] += member.size
            def small(name, maximum):
                entry = files.get(name)
                need(entry is not None and entry[0].size <= maximum, "artifact_status_invalid")
                return source.extractfile(entry[0]).read()
            need(small("output/status", 128) == b"resolved\ncomplete\n", "discovery_failed")
            for name in ("runtime-tree.json", "runtime-tree.txt", "runtime-classpath.txt"):
                need(bool(small("output/"+name, 8*1024*1024)), "artifact_metadata_invalid")
                entry, sha256 = files["output/"+name]
                graphs[name] = {"size": entry.size, "sha256": sha256}
            try:
                tree = json.loads(small("output/runtime-tree.json", 8*1024*1024), object_pairs_hook=unique)
                need(type(tree) is dict, "artifact_metadata_invalid")
                classpath = small("output/runtime-classpath.txt", 1024*1024).decode("ascii").rstrip("\r\n")
            except (ValueError, UnicodeError, RecursionError):
                raise DiscoveryError("artifact_metadata_invalid") from None
            selected = classpath.split(":")
            need(1 <= len(selected) <= 2048 and len(selected) == len(set(selected)), "classpath_invalid")
            ordered_runtime = []
            for name in selected:
                need(name.startswith("/work/m2/") and name[6:] in files and name.endswith(".jar"), "classpath_invalid")
                coordinate = artifact_coordinate(name[6:])
                matching = [r for r in records if all(r[k] == coordinate[k] for k in coordinate)]
                need(len(matching) == 1, "classpath_invalid")
                matching[0]["selected_runtime"] = True
                ordered_runtime.append(dict(coordinate, size=matching[0]["size"], sha256=matching[0]["sha256"]))
            need(all(any(r["group"] == "org.apache.hadoop" and r["artifact"] == artifact and r["version"] == "3.5.0"
                         and r["selected_runtime"] and r["type"] == "jar" and not r["classifier"] for r in records)
                     for artifact in ("hadoop-common", "hadoop-hdfs-client", "hadoop-hdfs")), "classpath_invalid")
            try:
                selected_coordinates = [{key: row[key] for key in ("group", "artifact", "version", "classifier", "type")}
                                        for row in records if row["selected_runtime"]]
                semantics = graph_export.export_semantics(
                    small("output/runtime-tree.json", 8 * 1024 * 1024),
                    small("output/runtime-tree.txt", 8 * 1024 * 1024), poms, selected_coordinates)
            except graph_export.ExportError as error:
                raise DiscoveryError("artifact_semantics_" + error.code,
                                     graph_export.pom_failure_diagnostic(error)) from None
            except (ValueError, TypeError, KeyError, RecursionError):
                raise DiscoveryError("artifact_semantics_invalid") from None
        with archive.open("rb") as stream:
            stream.seek(last)
            tail = stream.read(MAX_ZERO_TAIL + 1)
            need(1024 <= len(tail) <= MAX_ZERO_TAIL and len(tail) % 512 == 0
                 and not any(tail) and not stream.read(1), "artifact_archive_invalid")
    except (tarfile.TarError, OSError, IndexError):
        raise DiscoveryError("artifact_archive_invalid") from None
    need(records and len(records) <= 4096, "artifact_limit")
    artifact_bytes = sum(row["size"] for row in records)
    need(directories + output_files + len(records) + sum(row["files"] for row in auxiliary.values()) == len(files)
         and output_bytes + artifact_bytes + sum(row["bytes"] for row in auxiliary.values()) == total,
         "artifact_metadata_invalid")
    normalized = json.dumps(ordered_runtime, sort_keys=True, separators=(",", ":")).encode("ascii")
    return {"schema_version": 1, "scope": "hdfs_dependency_discovery", "ledger_eligible": False,
            "review_status": "quarantined", "offline_reproduced": False, "daemon_accepted": False,
            "repository_policy_is_os_egress_confinement": False, "graph_semantics_reviewed": False,
            "publisher_audit_completed": False, "artifacts": sorted(records, key=lambda r: (r["group"], r["artifact"], r["version"], r["classifier"], r["type"])),
            "graph_outputs": graphs,
            "runtime_classpath": {"schema_version": 1, "entries": ordered_runtime,
                                  "normalized_sha256": hashlib.sha256(normalized).hexdigest()},
            "archive_inventory": {
                "total_entries": len(files), "directories": directories, "total_file_bytes": total,
                "artifacts": {"files": len(records), "bytes": artifact_bytes,
                              "poms": sum(row["type"] == "pom" for row in records),
                              "selected_runtime_jars": len(ordered_runtime),
                              "other_jars": sum(row["type"] == "jar" and not row["selected_runtime"] for row in records)},
                "auxiliary_cache": auxiliary, "outputs": {"files": output_files, "bytes": output_bytes},
                "auxiliary_contents_reviewed": False, "plugin_dependency_closure_reviewed": False},
            "dependency_semantics": semantics,
            "private_archive_sha256": file_hash(archive), "private_file_count": len(files)}


def validate_profile_manifest(manifest, profile):
    candidate_hashes(profile)
    if profile == "hdfs":
        return  # artifact_manifest already requires all three Hadoop roots.
    expected = {"group": "org.apache.kerby", "artifact": "kerb-simplekdc",
                "version": "2.1.2", "classifier": "", "type": "jar"}
    family = [r for r in manifest["artifacts"]
              if r["group"] == "org.apache.kerby" and r["selected_runtime"] is True]
    # Hadoop also brings older Kerby libraries. The imported BOM must replace
    # every selected family member, including the vulnerable server and ASN1.
    need({"kerb-simplekdc", "kerb-server", "kerby-asn1"} <= {r["artifact"] for r in family}
         and all(r["version"] == "2.1.2" and r["type"] == "jar" and not r["classifier"] for r in family),
         "classpath_invalid")
    selected = [r for r in manifest["artifacts"]
                if r["group"] == expected["group"] and r["artifact"] == expected["artifact"]
                and r["selected_runtime"] is True]
    need(len(selected) == 1 and all(selected[0][key] == value for key, value in expected.items()),
         "classpath_invalid")
    roots = [n for n in manifest["dependency_semantics"]["nodes"]
             if n["parent"] == 0 and n["coordinate"] == expected]
    need(len(roots) == 1 and roots[0]["resolution"] == "included"
         and roots[0]["reachable_included"] is True and roots[0]["selected_classpath"] is True,
         "artifact_semantics_invalid")


def hosted_guard():
    need(sys.platform == "linux" and os.environ.get("GITHUB_ACTIONS") == "true"
         and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and os.environ.get("RUNNER_OS") == "Linux",
         "hosted_linux_required")


def discover(candidate, bootstrap, archive, output_parent, *, runner_factory=Docker,
             cache_destination=None, seed_cache=None, candidate_profile="hdfs"):
    """One fresh hosted discovery; raw logs/archive stay private, never uploaded here."""
    hosted_guard()
    hashes = candidate_hashes(candidate_profile)
    started_utc = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    started_clock = time.monotonic()
    supervisor_sha = file_hash(Path(__file__).resolve())
    exporter_source = Path(graph_export.__file__).absolute()
    exporter_sha = file_hash(exporter_source)
    cache_source = Path(offline_cache.__file__).absolute()
    cache_lock = offline_cache.lock_path(candidate_profile)
    cache_source_sha, cache_lock_sha = file_hash(cache_source), file_hash(cache_lock)
    expected_lock_sha = (offline_cache.LOCK_SHA256 if candidate_profile == "hdfs"
                         else offline_cache.KERBEROS_LOCK_SHA256)
    need(cache_lock_sha == expected_lock_sha, "offline_cache_invalid")
    inputs = candidate_inputs(candidate, candidate_profile)
    bootstrap = validate_bootstrap(bootstrap, archive)
    parent = Path(output_parent).absolute()
    for path in (parent, *parent.parents):
        item = path.lstat()
        need(not stat.S_ISLNK(item.st_mode) and not getattr(item, "st_file_attributes", 0) & 0x400, "unsafe_path")
    need(parent.is_dir() and not parent.is_symlink() and stat.S_IMODE(parent.stat().st_mode) == 0o700,
         "private_directory_required")
    need(cache_destination is None or seed_cache is None, "offline_cache_invalid")
    offline = seed_cache is not None
    seed_receipt = None
    for value in (cache_destination, seed_cache):
        if value is not None:
            need(Path(value).is_absolute() and Path(value).parent == parent
                 and Path(value).name == "offline-seed.tar", "offline_cache_invalid")
    if offline:
        try:
            seed_receipt = offline_cache.verify_cache(seed_cache, profile=candidate_profile)
        except offline_cache.CacheError:
            raise DiscoveryError("offline_cache_invalid") from None
    run_id = uuid.uuid4().hex
    root = parent / ("hdfs-discovery-" + run_id)
    root.mkdir(mode=0o700)
    context = root / "context"; context.mkdir(mode=0o700)
    context_identity = (context.stat().st_dev, context.stat().st_ino)
    report = {"schema_version": 1, "scope": "hdfs_dependency_discovery", "ledger_eligible": False,
              "success": False, "offline_reproduced": False, "daemon_accepted": False,
              "review_status": "quarantined", "errors": [], "manifest": None, "pom_diagnostic": None,
              "mode": "offline" if offline else "online", "cache_preparation": None,
              "started_utc": started_utc, "finished_utc": None, "duration_seconds": None,
              "inputs": {"supervisor_sha256": supervisor_sha, "graph_export_sha256": exporter_sha,
                         "cache_source_sha256": cache_source_sha, "cache_lock_sha256": cache_lock_sha,
                         "seed_cache": seed_receipt,
                         "candidate_profile": candidate_profile, "candidate_sha256": hashes,
                         "maven": {"version": bootstrap["maven_version"], "archive_sha256": bootstrap["maven_archive_sha256"],
                                   "archive_sha512": bootstrap["maven_archive_sha512"]},
                         "jdk": {"manifest": bootstrap["jdk_image"], "config_id": bootstrap["jdk_image_id"]},
                         "bootstrap_material": dict(bootstrap)},
              "image_id": None,
              "cleanup": {"container_removed": False, "image_removed": False, "context_removed": False}}
    name, tag = "hdfs-discovery-" + run_id, "hdfs-discovery:" + run_id
    docker, image, container = None, None, None
    attempted_build = attempted_create = False
    status_diagnostic = None
    try:
        docker = runner_factory(root)
        for filename in ("pom.xml", "settings.xml", "global-settings.xml"):
            (context / filename).write_bytes(inputs[filename])
        shutil.copyfile(archive, context / "maven.tar.gz")
        need(file_hash(context / "maven.tar.gz") == bootstrap["maven_archive_sha256"], "bootstrap_archive_mismatch")
        if offline:
            shutil.copyfile(seed_cache, context / "offline-seed.tar")
            need(offline_cache.verify_cache(context / "offline-seed.tar", profile=candidate_profile) == seed_receipt,
                 "offline_cache_invalid")
        (context / "Dockerfile").write_text(dockerfile(bootstrap, offline=offline,
                                                     seed_sha256=seed_receipt["sha256"] if offline else None), newline="\n")
        (context / "driver.sh").write_text(driver_script(offline=offline), newline="\n")
        info = json_value(docker.call(["info", "--format", "{{json .}}"] ).stdout.read_bytes())
        need(info.get("OSType") == "linux" and info.get("Architecture") in ("amd64", "x86_64"), "docker_platform_invalid")
        if not offline:
            docker.call(["image", "pull", "--quiet", "--platform", "linux/amd64", bootstrap["jdk_image"]], timeout=120)
        base = docker.inspect("image", bootstrap["jdk_image"])
        need(base is not None and base.get("Id") == bootstrap["jdk_image_id"] and base.get("Os") == "linux"
             and base.get("Architecture") == "amd64", "base_image_mismatch")
        iid = root / "image-id"
        attempted_build = True
        docker.call(["build", "--no-cache", "--force-rm", "--network", "none", "--platform", "linux/amd64",
                     "--label", LABEL + "=" + run_id, "--tag", tag, "--iidfile", str(iid), str(context)], timeout=180)
        image = regular(iid, 80).read_text().strip()
        need(re.fullmatch(r"sha256:[a-f0-9]{64}", image), "image_binding_invalid")
        built = docker.inspect("image", image)
        need(built is not None and built.get("Id") == image and built.get("Config", {}).get("Labels", {}).get(LABEL) == run_id,
             "image_binding_invalid")
        report["image_id"] = image
        attempted_create = True
        docker.call(container_args(name, image, run_id, offline=offline))
        created = docker.inspect("container", name)
        inspect_container(created, name, image, run_id, offline=offline)
        need(created.get("State", {}).get("Status") == "created" and created["State"].get("Running") is False,
             "container_binding_invalid")
        container = created["Id"]
        result = docker.call(["start", "--attach", container], timeout=630, limit=MAX_ARCHIVE, allow_failure=True)
        ended = docker.inspect("container", container)
        inspect_container(ended, name, image, run_id, offline=offline)
        need(ended["Id"] == container and ended.get("State", {}).get("Running") is False
             and ended["State"].get("Status") == "exited" and ended["State"].get("OOMKilled") is False
             and type(ended["State"].get("ExitCode")) is int,
             "container_failed")
        if ended["State"]["ExitCode"] != 0 or result.code != 0:
            status_diagnostic = discovery_status(result.stdout)
            raise DiscoveryError("container_failed")
        report["manifest"] = artifact_manifest(result.stdout)
        validate_profile_manifest(report["manifest"], candidate_profile)
        if cache_destination is not None:
            report["cache_preparation"] = offline_cache.prepare_cache(result.stdout, cache_destination,
                                                                       profile=candidate_profile)
        report["success"] = True
    except offline_cache.CacheError as error:
        report["errors"].append("offline_cache_invalid")
        if error.cleanup_failed:
            report["errors"].append("cache_cleanup_failed")
    except DiscoveryError as error:
        report["errors"].append(error.code)
        if error.pom_diagnostic is not None:
            try:
                diagnostic = graph_export.validate_pom_diagnostic(error.pom_diagnostic)
                need(error.code == "artifact_semantics_" + diagnostic["code"], "artifact_semantics_invalid")
                report["pom_diagnostic"] = diagnostic
            except (graph_export.ExportError, DiscoveryError, ValueError, TypeError, KeyError):
                report["errors"].append("artifact_semantics_invalid")
        if status_diagnostic is not None:
            report["errors"].append(status_diagnostic)
    except KeyboardInterrupt:
        report["errors"].append("discovery_interrupted")
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        report["errors"].append("discovery_failed")
    finally:
        try:
            if attempted_create:
                current = docker.inspect("container", container or name, allow_missing=True)
                if current is not None:
                    need(current.get("Name") == "/" + name and current.get("Config", {}).get("Labels", {}).get(LABEL) == run_id
                         and current.get("Image") == image and (container is None or current.get("Id") == container), "container_cleanup_failed")
                    owned_id = current["Id"]
                    docker.call(["container", "rm", "--force", owned_id])
                    need(docker.inspect("container", owned_id, allow_missing=True) is None, "container_cleanup_failed")
            report["cleanup"]["container_removed"] = True
        except (DiscoveryError, OSError, ValueError, KeyError, TypeError): report["errors"].append("container_cleanup_failed")
        try:
            if attempted_build:
                current = docker.inspect("image", image or tag, allow_missing=True)
                if current is not None:
                    need(current.get("Config", {}).get("Labels", {}).get(LABEL) == run_id
                         and (image is None or current.get("Id") == image)
                         and current.get("RepoTags") == [tag + ":latest" if ":" not in tag else tag], "image_cleanup_failed")
                    owned_id = current["Id"]
                    docker.call(["image", "rm", owned_id])
                    need(docker.inspect("image", owned_id, allow_missing=True) is None, "image_cleanup_failed")
            report["cleanup"]["image_removed"] = True
        except (DiscoveryError, OSError, ValueError, KeyError, TypeError): report["errors"].append("image_cleanup_failed")
        try:
            need("command_cleanup_failed" not in report["errors"], "context_cleanup_failed")
            need(not context.is_symlink() and (context.stat().st_dev, context.stat().st_ino) == context_identity,
                 "context_cleanup_failed")
            shutil.rmtree(context)
            report["cleanup"]["context_removed"] = not context.exists()
        except (DiscoveryError, OSError): report["errors"].append("context_cleanup_failed")
        try:
            need(candidate_inputs(candidate, candidate_profile) == inputs
                 and candidate_hashes(candidate_profile) == hashes
                 and file_hash(archive) == bootstrap["maven_archive_sha256"]
                 and file_hash(Path(__file__).resolve()) == supervisor_sha
                 and file_hash(exporter_source) == exporter_sha
                 and file_hash(cache_source) == cache_source_sha and file_hash(cache_lock) == cache_lock_sha, "source_changed")
            need(validate_bootstrap(bootstrap, archive) == bootstrap, "source_changed")
            if offline:
                need(offline_cache.verify_cache(seed_cache, profile=candidate_profile) == seed_receipt, "source_changed")
            elif cache_destination is not None and report["cache_preparation"] is not None:
                need(offline_cache.verify_cache(cache_destination, profile=candidate_profile)
                     == report["cache_preparation"], "source_changed")
        except (DiscoveryError, offline_cache.CacheError, OSError): report["errors"].append("source_changed")
        report["success"] = report["success"] and not report["errors"] and all(report["cleanup"].values())
        report["finished_utc"] = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
        report["duration_seconds"] = round(time.monotonic() - started_clock, 6)
        with (root / "sanitized-discovery.json").open("x", encoding="utf-8") as stream:
            json.dump(report, stream, sort_keys=True, indent=2)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--bootstrap", type=Path, required=True)
    parser.add_argument("--maven-archive", type=Path, required=True)
    parser.add_argument("--private-output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        bootstrap = json_value(regular(args.bootstrap.absolute(), 16384).read_bytes())
        report = discover(args.candidate, bootstrap, args.maven_archive, args.private_output_dir)
    except DiscoveryError as error:
        print(json.dumps({"success": False, "ledger_eligible": False, "errors": [error.code]}))
        return 1
    except KeyboardInterrupt:
        print(json.dumps({"success": False, "ledger_eligible": False, "errors": ["discovery_interrupted"]}))
        return 1
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        print(json.dumps({"success": False, "ledger_eligible": False, "errors": ["discovery_failed"]}))
        return 1
    print(json.dumps({"success": report["success"], "ledger_eligible": False, "errors": report["errors"],
                      "review_status": "quarantined", "cleanup": report["cleanup"]}))
    return 0 if report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
