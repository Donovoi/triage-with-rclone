"""Hosted-only ticket feasibility supervisor. Imports are inert; no provider credit.

Expected repository layout: HERE is a ticket directory beside hdfs-discovery.
Offline tests can inject DISCOVERY without executing a JVM or container.
Only the closed returned report is publishable.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import types
import urllib.error
import urllib.request
import uuid

HERE = Path(__file__).resolve().parent
DISCOVERY = HERE.parent / "hdfs-discovery"
BASE = "docker.io/library/eclipse-temurin@sha256:e1c09a9ee23feb81f94016547826c1e694086cd927356fb57fccc312fcc32f85"
BASE_ID = "sha256:d0e6e16acb7f941e5206d99ec38e5bba18545c43462541958f84b22e0fc006e8"
JAVA_SHA = "0da61ea91a8c321183f59e1e953a4febc2411aa0dbc876fe06e4e91f83c8d11a"
RUNTIME_SHA = "8944f0db4899d9e8f166feb28ce56d99278321ce0d3b1a9b9b993b5c0d508c2a"
ORDER_SHA = "a482109e5170b0a6885af7c52902e89600c226f6e1fe1487083d736c13187632"
LOCK_SHA = "a62e2a60bbb3f6c8b95b849760ff597e4e05e1c93bf61987c175502c3fe2ac74"
LABEL = "org.openai.triage.kerberos-ticket"
TMPFS = "rw,nosuid,nodev,noexec,size=128m,mode=0700,uid=10001,gid=10001"
HELPERS = ("bootstrap_material", "graph_export", "offline_cache", "resolver_discovery")
FALSE_CLAIMS = dict(ledger_eligible=False, authentication_verified=False, hdfs_authenticated=False,
    renewal_verified=False, daemon_accepted=False, provider_accepted=False, application_accepted=False,
    vendor_accepted=False, vulnerability_audited=False, publisher_audit_completed=False)
JAVA_FALSE = set(FALSE_CLAIMS) - {"publisher_audit_completed"}
JAVA_CHECKS = frozenset(("environment", "endpoint_settings", "positive_tgt", "file_cache_v3",
    "nonrenewable", "client_request_failed_with_integrity_error", "wrong_principal_denied", "cache_preserved"))
JAVA_CLEANUP = frozenset(("kdc_stop_returned", "threads_terminated", "listeners_absent",
    "private_material_removed", "process_property_restored", "cleanup_completed"))
JAVA_CODES = frozenset("""environment_invalid path_invalid source_changed unexpected_files
listener_mismatch configuration_invalid deadline_exceeded positive_ticket_failed
wrong_password_failure_mismatch wrong_principal_not_rejected cache_invalid ticket_time_mismatch
ticket_flags_mismatch background_failure io_failure krb_failure interrupted unclassified cleanup_failed""".split())
CODES = frozenset(("hosted_linux_required", "input_invalid", "input_changed", "unsafe_path", "download_failed",
    "download_cleanup_failed", "docker_failed", "command_cleanup_failed", "platform_invalid", "base_invalid",
    "image_invalid", "container_invalid", "java_report_invalid", "java_probe_failed", "interrupted",
    "container_cleanup_failed", "image_cleanup_failed", "raw_cleanup_failed", "report_failed", "probe_failed"))


class ProbeError(Exception):
    def __init__(self, code):
        self.code = code if code in CODES else "probe_failed"
        super().__init__(self.code)


def need(value, code):
    if not value: raise ProbeError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def sha(value):
    return hashlib.sha256(value).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "input_invalid"); result[key] = value
    return result


def parse(raw, maximum=1024 * 1024):
    need(type(raw) is bytes and len(raw) <= maximum, "input_invalid")
    try:
        return json.loads(raw, object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ProbeError("input_invalid")))
    except (ValueError, TypeError, RecursionError):
        raise ProbeError("input_invalid") from None


def regular(path, maximum):
    path = Path(path)
    need(path.is_absolute(), "unsafe_path")
    for ancestor in (path, *path.parents):
        info = ancestor.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400, "unsafe_path")
    info = path.stat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 <= info.st_size <= maximum, "unsafe_path")
    return info


def read(path, maximum):
    before = regular(path, maximum)
    stamp = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno()); need(stamp(before) == stamp(opened), "input_changed")
        data = stream.read(maximum + 1); after = os.fstat(stream.fileno())
    need(len(data) == before.st_size and stamp(before) == stamp(after) == stamp(regular(path, maximum)), "input_changed")
    return data


def file_hash(path, maximum=128 * 1024 * 1024):
    # Artifact reads remain bytes, never ZIP extraction/import/bytecode execution.
    return sha(read(path, maximum))


def directory(path, identity=None):
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and not path.is_symlink()
         and not getattr(info, "st_file_attributes", 0) & 0x400, "unsafe_path")
    actual = (info.st_dev, info.st_ino)
    need(identity is None or actual == identity, "input_changed")
    return actual


def hosted_guard():
    need(sys.platform == "linux" and os.environ.get("GITHUB_ACTIONS") == "true"
         and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and os.environ.get("RUNNER_OS") == "Linux",
         "hosted_linux_required")


def runtime_rows(runtime_raw, lock_raw):
    need(sha(runtime_raw) == RUNTIME_SHA and sha(lock_raw) == LOCK_SHA, "input_invalid")
    runtime, lock = parse(runtime_raw), parse(lock_raw)
    need(type(runtime) is dict and set(runtime) == {"schema_version", "entries", "normalized_sha256"}
         and type(runtime["schema_version"]) is int and runtime["schema_version"] == 1, "input_invalid")
    rows = runtime["entries"]
    selected = [{key: row[key] for key in ("group", "artifact", "version", "type", "classifier", "size", "sha256")}
                for row in lock["artifacts"] if row["selected_runtime"]]
    need(type(rows) is list and len(rows) == 142 and len(selected) == 142
         and sha(canonical(rows)) == runtime["normalized_sha256"] == ORDER_SHA
         and sorted(map(canonical, rows)) == sorted(map(canonical, selected)), "input_invalid")
    need(sum(row["group"] == "org.apache.kerby" for row in rows) == 15
         and all(row["version"] == "2.1.2" for row in rows if row["group"] == "org.apache.kerby"), "input_invalid")
    return rows


def load_helpers():
    """Compile exact inspected source bytes, avoiding stale bytecode caches."""
    saved, hashes, loaded = {}, {}, {}
    try:
        for name in HELPERS:
            path = DISCOVERY / (name + ".py"); data = read(path, 512 * 1024)
            hashes[path] = sha(data); saved[name] = sys.modules.get(name)
            module = types.ModuleType(name); module.__file__ = str(path)
            sys.modules[name] = module
            exec(compile(data, str(path), "exec"), module.__dict__); loaded[name] = module
        return loaded["resolver_discovery"], hashes
    finally:
        for name, old in saved.items():
            if old is None: sys.modules.pop(name, None)
            else: sys.modules[name] = old


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): raise ProbeError("download_failed")


def download_rows(context, rows, *, opener=None, clock=time.monotonic):
    opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    jars = context / "jars"; jars.mkdir(mode=0o700)
    context_id = directory(context); jar_id = directory(jars); deadline = clock() + 270
    for index, row in enumerate(rows):
        directory(context, context_id); directory(jars, jar_id)
        classifier = "-" + row["classifier"] if row["classifier"] else ""
        relative = row["group"].replace(".", "/") + "/" + row["artifact"] + "/" + row["version"] + "/"
        relative += row["artifact"] + "-" + row["version"] + classifier + ".jar"
        url = "https://repo.maven.apache.org/maven2/" + relative
        need(clock() < deadline and row["type"] == "jar", "download_failed")
        request = urllib.request.Request(url, headers={"User-Agent": "triage-synthetic-ticket", "Accept-Encoding": "identity"})
        count, digest = 0, hashlib.sha256()
        try:
            with opener.open(request, timeout=min(20, max(1, int(deadline - clock())))) as response:
                need(response.status == 200 and response.url == url, "download_failed")
                lengths = response.headers.get_all("Content-Length", [])
                need(lengths == [str(row["size"])] and not response.headers.get_all("Transfer-Encoding", [])
                     and not response.headers.get_all("Content-Encoding", []), "download_failed")
                with (jars / ("%03d.jar" % index)).open("xb") as output:
                    while True:
                        need(clock() < deadline, "download_failed")
                        chunk = response.read(min(65536, row["size"] - count + 1))
                        if not chunk: break
                        count += len(chunk); need(count <= row["size"], "download_failed")
                        output.write(chunk); digest.update(chunk)
            need(count == row["size"] and digest.hexdigest() == row["sha256"], "download_failed")
        except (OSError, urllib.error.URLError, ValueError):
            raise ProbeError("download_failed") from None
    directory(context, context_id); directory(jars, jar_id)


def download(context, rows):
    process = None; context_id = directory(context); source = Path(__file__).resolve()
    source_hash = file_hash(source, 512 * 1024)
    environment = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL", "GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "RUNNER_OS") if key in os.environ}
    try:
        process = subprocess.Popen([sys.executable, "-I", "-S", "-B", str(source), "--download-worker",
            str(context), str(context_id[0]), str(context_id[1]), source_hash], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=context, env=environment, start_new_session=True)
        try: code = process.wait(timeout=300)
        except subprocess.TimeoutExpired: raise ProbeError("download_failed") from None
        need(code == 0, "download_failed")
    except OSError:
        raise ProbeError("download_failed") from None
    finally:
        if process is not None:
            try:
                if process.poll() is None:
                    need(os.getpgid(process.pid) == process.pid, "download_cleanup_failed")
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                raise ProbeError("download_cleanup_failed") from None
    directory(context, context_id)
    need(file_hash(source, 512 * 1024) == source_hash, "input_changed")
    verify_jars(context, rows)


def verify_jars(context, rows):
    jars = context / "jars"; directory(jars)
    need({p.name for p in jars.iterdir()} == {"%03d.jar" % i for i in range(len(rows))}, "input_changed")
    for i, row in enumerate(rows):
        path = jars / ("%03d.jar" % i)
        need(regular(path, row["size"]).st_size == row["size"] and file_hash(path, row["size"]) == row["sha256"], "input_changed")


def build_files(rows):
    cp = ":".join("/opt/ticket/jars/%03d.jar" % i for i in range(len(rows)))
    driver = ("#!/bin/sh\nset -eu\numask 077\nmkdir /work/home /work/tmp\n"
        "exec /usr/bin/timeout --signal=TERM --kill-after=5s 60s /opt/java/openjdk/bin/java "
        "-Xmx512m -Djava.net.preferIPv4Stack=true -Djava.io.tmpdir=/work/tmp -Duser.home=/work/home "
        "-cp \"$(cat /opt/ticket/classpath)\" KerberosTicketProbe\n")
    checks = "".join(row["sha256"] + "  /opt/ticket/jars/%03d.jar\n" % i for i, row in enumerate(rows))
    checks += JAVA_SHA + "  /opt/ticket/KerberosTicketProbe.java\n" + sha(driver.encode()) + "  /opt/ticket/driver.sh\n"
    classpath = "/opt/ticket/classes:" + cp + "\n"
    checks += sha(classpath.encode()) + "  /opt/ticket/classpath\n"
    dockerfile = ("FROM " + BASE + "\nUSER 0\nCOPY jars /opt/ticket/jars/\n"
        "COPY KerberosTicketProbe.java checksums driver.sh classpath /opt/ticket/\n"
        "RUN sha256sum -c /opt/ticket/checksums && mkdir /opt/ticket/classes && "
        "/opt/java/openjdk/bin/javac -J-Xmx512m -proc:none -implicit:none -encoding UTF-8 -cp '" + cp +
        "' -d /opt/ticket/classes /opt/ticket/KerberosTicketProbe.java && chmod -R a=rX /opt/ticket\n"
        "USER 10001:10001\nWORKDIR /work\n")
    return {"Dockerfile": dockerfile.encode(), "checksums": checks.encode(), "driver.sh": driver.encode(), "classpath": classpath.encode()}


def command_args(name, image, run_id):
    need(type(run_id) is str and re.fullmatch(r"[a-f0-9]{32}", run_id) and name == "kerberos-ticket-" + run_id
         and type(image) is str and re.fullmatch(r"sha256:[a-f0-9]{64}", image), "container_invalid")
    return ["create", "--name", name, "--label", LABEL + "=" + run_id, "--network", "none", "--read-only",
        "--user", "10001:10001", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "128",
        "--memory", "2g", "--cpus", "2", "--init", "--cgroupns", "private", "--ipc", "private", "--log-driver", "none",
        "--stop-timeout", "5", "--tmpfs", "/work:" + TMPFS, "--entrypoint", "/usr/bin/env", image,
        "-i", "HOME=/work/home", "PATH=/opt/java/openjdk/bin:/usr/bin:/bin", "JAVA_HOME=/opt/java/openjdk",
        "LANG=C", "LC_ALL=C", "/bin/sh", "/opt/ticket/driver.sh"]


def inspect_container(value, name, image, run_id):
    need(type(value) is dict and value.get("Name") == "/" + name and value.get("Image") == image
         and re.fullmatch(r"[a-f0-9]{64}", value.get("Id", "")), "container_invalid")
    config, host = value.get("Config", {}), value.get("HostConfig", {})
    args = command_args(name, image, run_id)
    need(config.get("Labels", {}).get(LABEL) == run_id and config.get("User") == "10001:10001"
         and config.get("Entrypoint") == ["/usr/bin/env"] and config.get("Cmd") == args[args.index(image)+1:]
         and not config.get("Volumes") and not config.get("ExposedPorts") and not config.get("Healthcheck"), "container_invalid")
    need(host.get("NetworkMode") == "none" and host.get("ReadonlyRootfs") is True and host.get("Privileged") is False
         and host.get("CapDrop") == ["ALL"] and not host.get("CapAdd") and not host.get("Binds") and not host.get("PortBindings")
         and host.get("SecurityOpt") in (["no-new-privileges"], ["no-new-privileges=true"])
         and type(host.get("Memory")) is int and host["Memory"] == 2 * 1024**3
         and type(host.get("NanoCpus")) is int and host["NanoCpus"] == 2 * 10**9
         and type(host.get("PidsLimit")) is int and host["PidsLimit"] == 128
         and host.get("Init") is True and host.get("IpcMode") == "private" and host.get("CgroupnsMode") == "private"
         and host.get("Tmpfs") == {"/work": TMPFS} and host.get("LogConfig", {}).get("Type") == "none"
         and not host.get("Devices") and not host.get("DeviceRequests") and not host.get("ExtraHosts")
         and not host.get("PidMode"), "container_invalid")
    mounts = value.get("Mounts")
    need(type(mounts) is list and len(mounts) <= 1 and all(type(m) is dict and m.get("Type") == "tmpfs"
         and m.get("Destination") == "/work" for m in mounts), "container_invalid")


def validate_java(raw, exit_code):
    try:
        value = parse(raw, 16384)
        keys = {"schema_version", "scope", "success", "expected_kerby_version", "runtime_binding_required", "checks",
                "cleanup", "cache_bytes", "observed_lifetime_seconds", "error"} | JAVA_FALSE
        need(type(value) is dict and set(value) == keys and type(value["schema_version"]) is int
             and value["schema_version"] == 1 and value["scope"] == "kerby_ticket_feasibility"
             and value["expected_kerby_version"] == "2.1.2" and value["runtime_binding_required"] is True
             and type(value["success"]) is bool and all(value[key] is False for key in JAVA_FALSE), "java_report_invalid")
        for key, expected in (("checks", JAVA_CHECKS), ("cleanup", JAVA_CLEANUP)):
            need(type(value[key]) is dict and set(value[key]) == expected
                 and all(type(x) is bool for x in value[key].values()), "java_report_invalid")
        need(type(value["cache_bytes"]) is int and 0 <= value["cache_bytes"] <= 65536
             and type(value["observed_lifetime_seconds"]) is int and 0 <= value["observed_lifetime_seconds"] <= 120
             and (value["error"] is None or type(value["error"]) is str and value["error"] in JAVA_CODES), "java_report_invalid")
        passed = all(value["checks"].values()) and all(value["cleanup"].values()) and value["error"] is None
        need(type(exit_code) is int and exit_code in (0, 1) and value["success"] is passed
             and exit_code == (0 if passed else 1), "java_report_invalid")
        if passed: need(100 < value["cache_bytes"] <= 65536 and 110 <= value["observed_lifetime_seconds"] <= 120, "java_report_invalid")
        return value
    except ProbeError:
        raise ProbeError("java_report_invalid") from None


def tree_hashes(root):
    result = {}
    for count, path in enumerate(root.rglob("*"), 1):
        need(count <= 300 and not path.is_symlink(), "unsafe_path")
        if path.is_dir(): directory(path)
        else: result[path.relative_to(root).as_posix()] = file_hash(path)
    return result


def run(*, loader=load_helpers, downloader=download, runner_factory=None):
    started = time.monotonic()
    report = dict(schema_version=1, scope="kerberos_ticket_container_feasibility", success=False,
        started_utc=datetime.now(timezone.utc).isoformat(), finished_utc=None, duration_seconds=None,
        stage="preflight", inputs=None, result=None, errors=[], cleanup=dict(container_removed=False,
        image_removed=False, context_removed=False, raw_evidence_removed=False),
        cleanup_excludes=["shared_base_image", "shared_build_cache"], **FALSE_CLAIMS)
    root = context = root_id = context_id = docker = D = None
    source_hashes = {}; image = container = None; built_attempted = created_attempted = False
    run_id = uuid.uuid4().hex; tag = name = "kerberos-ticket-" + run_id
    old_umask = os.umask(0o077)
    try:
        hosted_guard()
        D, source_hashes = loader()
        java_path, runtime_path = HERE / "KerberosTicketProbe.java", HERE / "runtime-classpath.json"
        lock_path = DISCOVERY / "artifact-lock-kerberos.json"
        java, runtime_raw, lock_raw = read(java_path, 128 * 1024), read(runtime_path, 512 * 1024), read(lock_path, 512 * 1024)
        need(sha(java) == JAVA_SHA, "input_invalid"); rows = runtime_rows(runtime_raw, lock_raw)
        for path, raw in ((java_path, java), (runtime_path, runtime_raw), (lock_path, lock_raw),
                (Path(__file__).resolve(), read(Path(__file__).resolve(), 512 * 1024))): source_hashes[path] = sha(raw)
        report["inputs"] = dict(source_sha256={p.name: h for p, h in source_hashes.items()}, jdk_manifest=BASE,
            jdk_config_id=BASE_ID, runtime_jars=142, runtime_bytes=sum(row["size"] for row in rows),
            runtime_classpath_sha256=ORDER_SHA, lock_sha256=LOCK_SHA, context_sha256=None, image_id=None, container_id=None)
        need(shutil.disk_usage("/tmp").free >= 512 * 1024**2, "unsafe_path")
        root = Path(tempfile.mkdtemp(prefix="kerberos-ticket-", dir="/tmp")); root_id = directory(root)
        context = root / "context"; context.mkdir(mode=0o700); context_id = directory(context)
        (context / "runtime-classpath.json").write_bytes(runtime_raw)
        (context / "artifact-lock-kerberos.json").write_bytes(lock_raw)
        report["stage"] = "download"; downloader(context, rows); verify_jars(context, rows)
        (context / "KerberosTicketProbe.java").write_bytes(java)
        for filename, content in build_files(rows).items(): (context / filename).write_bytes(content)
        context_hashes = tree_hashes(context); report["inputs"]["context_sha256"] = sha(canonical(context_hashes))
        docker = (runner_factory or D.Docker)(root, max_calls=40)
        host = parse(read(docker.call(["info", "--format", "{{json .}}"]).stdout, 1024 * 1024))
        need(host.get("OSType") == "linux" and host.get("Architecture") in ("amd64", "x86_64"), "platform_invalid")
        report["stage"] = "base"
        docker.call(["image", "pull", "--quiet", "--platform", "linux/amd64", BASE], timeout=120)
        base = docker.inspect("image", BASE)
        need(base.get("Id") == BASE_ID and base.get("Os") == "linux" and base.get("Architecture") == "amd64", "base_invalid")
        need(not any(s.split("=", 1)[0] in {"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"}
             for s in base.get("Config", {}).get("Env", [])), "base_invalid")
        need(docker.inspect("image", tag, allow_missing=True) is None, "image_invalid")
        report["stage"] = "build"; built_attempted = True
        docker.call(["build", "--network", "none", "--pull=false", "--label", LABEL + "=" + run_id,
            "--tag", tag, str(context)], timeout=180, limit=4 * 1024 * 1024)
        built = docker.inspect("image", tag); image = built.get("Id")
        need(type(image) is str and re.fullmatch(r"sha256:[a-f0-9]{64}", image)
             and built.get("Config", {}).get("Labels", {}).get(LABEL) == run_id
             and built.get("Config", {}).get("User") == "10001:10001", "image_invalid")
        need(tree_hashes(context) == context_hashes, "input_changed")
        report["inputs"]["image_id"] = image
        need(docker.inspect("container", name, allow_missing=True) is None, "container_invalid")
        report["stage"] = "create"; created_attempted = True
        docker.call(command_args(name, image, run_id))
        initial = docker.inspect("container", name); inspect_container(initial, name, image, run_id)
        need(initial.get("State", {}).get("Status") == "created" and initial["State"].get("Running") is False, "container_invalid")
        container = initial["Id"]; report["inputs"]["container_id"] = container
        report["stage"] = "ticket_probe"
        result = docker.call(["start", "--attach", container], timeout=75, limit=16384, allow_failure=True)
        ended = docker.inspect("container", container); inspect_container(ended, name, image, run_id)
        state = ended.get("State", {})
        need(ended["Id"] == container and state.get("Running") is False and state.get("Status") == "exited"
             and state.get("OOMKilled") is False and type(state.get("ExitCode")) is int
             and state["ExitCode"] == result.code, "container_invalid")
        report["result"] = validate_java(read(result.stdout, 16384), result.code)
        need(report["result"]["success"] is True, "java_probe_failed")
        report["success"] = True; report["stage"] = "completed"
    except KeyboardInterrupt: report["errors"].append("interrupted")
    except BaseException as error:
        code = error.code if isinstance(error, ProbeError) else "command_cleanup_failed" if D is not None and isinstance(error, D.DiscoveryError) and error.code == "command_cleanup_failed" else "probe_failed"
        report["errors"].append(code)
    finally:
        for kind, attempted, reference, exact in (("container", created_attempted, container or name, container),
                                                 ("image", built_attempted, image or tag, image)):
            try:
                if attempted:
                    current = docker.inspect(kind, reference, allow_missing=True)
                    if current is not None:
                        need(current.get("Config", {}).get("Labels", {}).get(LABEL) == run_id
                             and (exact is None or current.get("Id") == exact), kind + "_cleanup_failed")
                        owned = current.get("Id")
                        if kind == "container":
                            need(re.fullmatch(r"[a-f0-9]{64}", owned or "") and current.get("Name") == "/" + name
                                 and current.get("Image") == image, "container_cleanup_failed")
                        else:
                            need(re.fullmatch(r"sha256:[a-f0-9]{64}", owned or "")
                                 and current.get("RepoTags") == [tag + ":latest"], "image_cleanup_failed")
                        docker.call([kind, "rm", *(["--force"] if kind == "container" else []), owned])
                        need(docker.inspect(kind, owned, allow_missing=True) is None, kind + "_cleanup_failed")
                report["cleanup"][kind + "_removed"] = True
            except BaseException as error:
                if getattr(error, "code", None) == "command_cleanup_failed": report["errors"].append("command_cleanup_failed")
                report["errors"].append(kind + "_cleanup_failed")
        try:
            for path, expected in source_hashes.items(): need(file_hash(path, 512 * 1024) == expected, "input_changed")
        except BaseException: report["errors"].append("input_changed")
        safe = all(report["cleanup"][key] for key in ("container_removed", "image_removed"))
        safe = safe and not {"command_cleanup_failed", "download_cleanup_failed"}.intersection(report["errors"])
        try:
            if context is not None:
                need(safe, "raw_cleanup_failed"); directory(root, root_id); directory(context, context_id)
                tree_hashes(context); shutil.rmtree(context); need(not context.exists(), "raw_cleanup_failed")
            report["cleanup"]["context_removed"] = True
            if root is not None:
                need(safe, "raw_cleanup_failed"); directory(root, root_id)
                # All Docker output/credentialless config is private; reject links before deleting.
                for path in root.rglob("*"):
                    need(not path.is_symlink(), "unsafe_path")
                    if path.is_file(): regular(path, 8 * 1024 * 1024)
                shutil.rmtree(root); need(not root.exists(), "raw_cleanup_failed")
            report["cleanup"]["raw_evidence_removed"] = True
        except BaseException: report["errors"].append("raw_cleanup_failed")
        os.umask(old_umask)
    report["success"] = report["success"] and not report["errors"] and all(report["cleanup"].values())
    report["finished_utc"] = datetime.now(timezone.utc).isoformat()
    report["duration_seconds"] = round(time.monotonic() - started, 3)
    return report


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args and args[0] == "--download-worker":
        try:
            hosted_guard(); need(len(args) == 5, "input_invalid")
            context = Path(args[1]); need(context.is_absolute() and context.name == "context", "unsafe_path")
            directory(context, (int(args[2]), int(args[3])))
            need(file_hash(Path(__file__).resolve(), 512 * 1024) == args[4], "input_changed")
            rows = runtime_rows(read(context / "runtime-classpath.json", 512 * 1024),
                                read(context / "artifact-lock-kerberos.json", 512 * 1024))
            download_rows(context, rows); return 0
        except BaseException: return 1
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--report", type=Path, required=True)
    parsed = parser.parse_args(args)
    previous = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        hosted_guard(); path = parsed.report
        need(path.is_absolute(), "unsafe_path")
        for parent in path.parents: directory(parent)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            result = run(); data = canonical(result) + b"\n"; need(len(data) <= 65536, "report_failed")
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        return 0 if result["success"] else 1
    except BaseException:
        sys.stderr.write("ticket_probe_failed\n"); return 1
    finally: signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    raise SystemExit(main())
