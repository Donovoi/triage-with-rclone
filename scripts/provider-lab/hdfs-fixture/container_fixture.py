"""Hosted-only SIMPLE protocol experiment; never authentication or app evidence."""
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
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

HERE = Path(__file__).resolve().parent
DISCOVERY = HERE.parent / "hdfs-discovery"
sys.path.insert(0, str(DISCOVERY))
import resolver_discovery as D
import offline_cache as O
import run_discovery as R

BASE = "docker.io/library/eclipse-temurin@sha256:e1c09a9ee23feb81f94016547826c1e694086cd927356fb57fccc312fcc32f85"
BASE_ID = "sha256:d0e6e16acb7f941e5206d99ec38e5bba18545c43462541958f84b22e0fc006e8"
ORDER_HASH = "60d20de9f26f3b5421738bea16f8f4fe3300aa51c9909ee79b52b9cb85eaafc3"
CLASSPATH_HASH = "5af73aa99d5c3dd038270d44a22e7735ee52ab2cf422e25763cedc7c520434fd"
PIN_FILE = HERE.parents[2] / "rclone-version.env"
LABEL = "org.openai.triage.hdfs-fixture"
PORTS = dict(namenode_rpc=19000, datanode_data=19001, datanode_ipc=19002,
             namenode_http=19003, datanode_http=19004, datanode_internal_http=19005)
FALSE_CLAIMS = dict(ledger_eligible=False, authentication_verified=False,
                    provider_accepted=False, application_accepted=False, vendor_accepted=False,
                    vulnerability_audited=False, publisher_audit_completed=False)
CODES = frozenset({"runtime_lock_invalid", "download_failed", "input_changed", "fixture_failed",
    "oracle_invalid", "listing_invalid", "sample_mismatch", "negative_case_failed",
    "listeners_invalid", "runtime_invalid", "shutdown_failed", "raw_cleanup_failed",
    "fixture_interrupted", "command_cleanup_failed"}) | D.CODES
JAVA_CODES = frozenset("""
advertised_endpoint_mismatch arguments_invalid configuration_changed datanode_missing
datanode_not_ready directory_changed endpoint_mismatch environment_invalid extra_service
hadoop_version_invalid ipv4_required java_version_invalid listener_duplicate listener_inventory_bound
listener_inventory_invalid listener_not_loopback listener_set_mismatch missing_member_present
mkdir_failed output_identity_changed output_identity_unavailable report_bound shutdown_invalid
shutdown_preexisting shutdown_timeout simple_required source_bytes_changed source_duplicate
source_inventory_bound source_inventory_changed source_metadata_changed source_preexisting
source_scope startup_timeout unexpected_directory unexpected_file work_invalid work_owner_invalid
work_permissions_invalid exit_requested halt_requested missing_class resource_failure invalid_config
linkage_failure io_failure unclassified environment_failed startup_failed seed_failed ready_report_failed
shutdown_request_failed source_preservation_failed configuration_preservation_failed client_close_failed
datanode_shutdown_failed namenode_shutdown_failed termination_requested final_report_failed
format_failed namenode_start_failed datanode_start_failed client_start_failed readiness_failed
file_missing http_webapp_missing
webapp_resources_invalid webapp_resources_failed
""".split())


class FixtureError(Exception):
    def __init__(self, code):
        self.code = code if code in CODES else "fixture_failed"
        super().__init__(self.code)


def need(condition, code):
    if not condition:
        raise FixtureError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def digest(value):
    return hashlib.sha256(value).hexdigest()


def runtime_pin(path=PIN_FILE):
    values = {}
    for line in D.regular(path, 4096).read_text(encoding="ascii").splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        need(separator and key not in values, "runtime_invalid")
        values[key] = value
    keys = {"RCLONE_VERSION", "RCLONE_EXE_SHA256", "RCLONE_WINDOWS_ZIP_SHA256",
            "RCLONE_LINUX_ZIP_SHA256", "RCLONE_LINUX_EXE_SHA256"}
    need(set(values) == keys and re.fullmatch(r"[1-9][0-9]*\.[0-9]+\.[0-9]+", values["RCLONE_VERSION"])
         and all(re.fullmatch(r"[a-f0-9]{64}", value) for key, value in values.items()
                 if key != "RCLONE_VERSION"), "runtime_invalid")
    return values["RCLONE_VERSION"], values["RCLONE_LINUX_EXE_SHA256"]


RCLONE_VERSION, RCLONE_SHA = runtime_pin()


def samples():
    return {"README.txt": b"HDFS synthetic fixture\n", "empty.bin": b"",
            "nested/alpha.txt": b"alpha\n", "nested/space name.txt": b"space name\n",
            "nested/deeper/data.bin": bytes(range(256)), "unicode/utf8.txt": b"caf\xc3\xa9\n",
            "private/owner-only.txt": b"private synthetic bytes\n",
            "large/cancel.bin": bytes(range(256)) * 8192}


def expected_files():
    return [dict(path=path, size=len(data), sha256=digest(data),
                 mode="0600" if path == "private/owner-only.txt" else "0644")
            for path, data in sorted(samples().items())]


def webapp_resources():
    """Minimal fixture scaffolding for Hadoop's programmatic HTTP services."""
    descriptor = (b'<?xml version="1.0" encoding="UTF-8"?>\n'
                  b'<web-app xmlns="http://java.sun.com/xml/ns/j2ee" version="2.4"></web-app>\n')
    index = b"<!doctype html><title>Synthetic fixture</title><p>Protocol test only.</p>\n"
    return {"webapps/hdfs/WEB-INF/web.xml": descriptor,
            "webapps/datanode/WEB-INF/web.xml": descriptor,
            "webapps/hdfs/index.html": index, "webapps/datanode/index.html": index,
            "webapps/static/fixture.txt": b"Protocol test resources only.\n"}


def runtime_rows():
    path = HERE / "runtime-classpath.json"
    need(D.file_hash(path) == ORDER_HASH, "runtime_lock_invalid")
    value = D.json_value(path.read_bytes())
    rows = value["entries"]
    selected = [{k: row[k] for k in ("group", "artifact", "version", "classifier", "type", "size", "sha256")}
                for row in O._load_lock() if row["selected_runtime"]]
    need(len(rows) == 128 and sorted(map(canonical, rows)) == sorted(map(canonical, selected))
         and digest(canonical(rows)) == CLASSPATH_HASH == value["normalized_sha256"], "runtime_lock_invalid")
    return rows


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise FixtureError("download_failed")


def download_jars(context, rows, *, opener=None, clock=time.monotonic):
    opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    jars = context / "jars"
    jars.mkdir(mode=0o700)
    deadline = clock() + 240
    for index, row in enumerate(rows):
        relative = O._artifact_path(row)[3:]
        url = "https://repo.maven.apache.org/maven2/" + relative
        need(clock() < deadline, "download_failed")
        request = urllib.request.Request(url, headers={"User-Agent": "triage-synthetic-hdfs-fixture"})
        path = jars / ("%03d.jar" % index)
        count, h = 0, hashlib.sha256()
        try:
            with opener.open(request, timeout=min(20, max(1, int(deadline - clock())))) as response, path.open("xb") as output:
                need(response.status == 200 and response.url == url, "download_failed")
                while True:
                    need(clock() < deadline, "download_failed")
                    block = response.read(65536)
                    if not block:
                        break
                    count += len(block)
                    need(count <= row["size"], "download_failed")
                    h.update(block); output.write(block)
            os.chmod(path, 0o600)
            need(count == row["size"] and h.hexdigest() == row["sha256"], "download_failed")
        except (OSError, urllib.error.URLError, ValueError):
            raise FixtureError("download_failed") from None


def driver_script():
    return """#!/bin/sh
set -eu
umask 077
mkdir -p /work/home /work/tmp /work/download
set +e
timeout --signal=TERM --kill-after=5s 240s /opt/java/openjdk/bin/java -Xmx1536m -Djava.net.preferIPv4Stack=true -Djava.io.tmpdir=/work/tmp -Duser.home=/work/home -cp "$(cat /opt/hdfs/classpath)" HdfsFixture > /work/java.log 2>&1
code=$?
printf '%s\n' "$code" > /work/java-exit
while [ ! -e /work/exit ]; do sleep 1; done
exit "$code"
"""


def dockerfile(rows, java_hash):
    classpath = ":".join("/opt/hdfs/jars/%03d.jar" % i for i in range(len(rows)))
    checks = "\n".join(row["sha256"] + "  /opt/hdfs/jars/%03d.jar" % i for i, row in enumerate(rows))
    checks += "\n" + RCLONE_SHA + "  /opt/hdfs/rclone\n" + java_hash + "  /opt/hdfs/HdfsFixture.java\n"
    checks += "".join(digest(data) + "  /opt/hdfs/resources/" + path + "\n"
                      for path, data in sorted(webapp_resources().items()))
    source = (
        "FROM " + BASE + "\nUSER 0\nCOPY . /opt/hdfs/\n"
        "RUN sha256sum -c /opt/hdfs/checksums && mkdir /opt/hdfs/classes && "
        "/opt/java/openjdk/bin/javac -J-Xmx768m -proc:none -implicit:none -encoding UTF-8 -cp '" + classpath +
        "' -d /opt/hdfs/classes /opt/hdfs/HdfsFixture.java && "
        "cp -R /opt/hdfs/resources/webapps /opt/hdfs/classes/ && "
        "chmod -R a=rX /opt/hdfs && chmod 0555 /opt/hdfs/rclone\n"
        "USER 10001:10001\nWORKDIR /work\n")
    return source, checks, "/opt/hdfs/classes:" + classpath + "\n"


def command_args(name, image, run_id):
    need(name == "hdfs-fixture-" + run_id and re.fullmatch(r"[a-f0-9]{32}", run_id)
         and re.fullmatch(r"sha256:[a-f0-9]{64}", image), "container_binding_invalid")
    return ["create", "--name", name, "--label", LABEL + "=" + run_id, "--network", "none",
            "--read-only", "--user", "10001:10001", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", "128", "--memory", "4g", "--cpus", "2", "--init", "--cgroupns", "private",
            "--ipc", "private", "--log-driver", "none", "--stop-timeout", "10",
            "--tmpfs", "/work:rw,nosuid,nodev,noexec,size=2g,mode=0700,uid=10001,gid=10001",
            "--entrypoint", "/usr/bin/env", image, "-i", "HOME=/work/home",
            "PATH=/opt/java/openjdk/bin:/usr/bin:/bin", "JAVA_HOME=/opt/java/openjdk",
            "LANG=C", "LC_ALL=C", "/usr/bin/timeout", "--signal=TERM", "--kill-after=5s",
            "300s", "/bin/sh", "/opt/hdfs/driver.sh"]


def inspect_container(value, name, image, run_id):
    need(type(value) is dict and value.get("Name") == "/" + name and value.get("Image") == image
         and re.fullmatch(r"[a-f0-9]{64}", value.get("Id", "")), "container_binding_invalid")
    config, host = value.get("Config", {}), value.get("HostConfig", {})
    args = command_args(name, image, run_id)
    need(config.get("Labels", {}).get(LABEL) == run_id and config.get("User") == "10001:10001"
         and config.get("Entrypoint") == ["/usr/bin/env"] and config.get("Cmd") == args[args.index(image)+1:]
         and not config.get("Volumes") and not config.get("ExposedPorts") and not config.get("Healthcheck"),
         "container_binding_invalid")
    need(host.get("NetworkMode") == "none" and host.get("ReadonlyRootfs") is True and not host.get("Privileged")
         and not host.get("Binds") and not host.get("PortBindings") and host.get("CapDrop") == ["ALL"]
         and not host.get("CapAdd") and host.get("SecurityOpt") in (["no-new-privileges"], ["no-new-privileges=true"])
         and host.get("Memory") == 4 * 1024**3 and host.get("NanoCpus") == 2 * 10**9
         and host.get("PidsLimit") == 128 and host.get("Init") is True
         and host.get("IpcMode") == host.get("CgroupnsMode") == "private"
         and host.get("Tmpfs") == {"/work": "rw,nosuid,nodev,noexec,size=2g,mode=0700,uid=10001,gid=10001"}
         and host.get("LogConfig", {}).get("Type") == "none"
         and not host.get("Devices") and not host.get("DeviceRequests") and not host.get("ExtraHosts")
         and not host.get("PidMode"), "container_binding_invalid")
    mounts = value.get("Mounts")
    need(type(mounts) is list and all(m.get("Type") == "tmpfs" and m.get("Destination") == "/work" for m in mounts),
         "container_binding_invalid")


def validate_oracle(value, phase, prior=None):
    expected = dict(schema_version=1, scope="hdfs_simple_fixture", phase=phase, ledger_eligible=False,
                    authentication_verified=False, authentication_mode="SIMPLE", success=True,
                    source_preserved=True, configuration_preserved=True, api_shutdown_complete=phase == "final",
                    owner="fixture-owner", root="/synthetic", mtime_ms=1704067200000,
                    ports=PORTS, files=expected_files(), errors=[])
    need(type(value) is dict and set(value) == set(expected) | {"configuration_sha256"}, "oracle_invalid")
    need(all(canonical(value[k]) == canonical(v) for k, v in expected.items())
         and type(value["configuration_sha256"]) is str
         and re.fullmatch(r"[0-9a-f]{64}", value["configuration_sha256"]), "oracle_invalid")
    if prior is not None:
        need(value["configuration_sha256"] == prior["configuration_sha256"], "oracle_invalid")
    return value


def failure_diagnostic(docker, container, name, image, run_id):
    """Read only fixed final-report fields from the exact owned live container."""
    current = docker.inspect("container", container, allow_missing=True)
    if current is None:
        return dict(status="unavailable")
    inspect_container(current, name, image, run_id)
    need(current.get("Id") == container, "container_binding_invalid")
    if current.get("State", {}).get("Running") is not True:
        return dict(status="unavailable")
    result = docker.call(["exec", container, "/bin/cat", "/work/output/final.json"],
                         timeout=5, limit=16384, allow_failure=True)
    if result.code:
        return dict(status="unavailable")
    try:
        value = D.json_value(D.regular(result.stdout, 16384).read_bytes())
        fixed = dict(schema_version=1, scope="hdfs_simple_fixture", phase="final", ledger_eligible=False,
                     authentication_verified=False, authentication_mode="SIMPLE", owner="fixture-owner",
                     root="/synthetic", mtime_ms=1704067200000, ports=PORTS, files=expected_files())
        flags = ("success", "source_preserved", "configuration_preserved", "api_shutdown_complete")
        need(type(value) is dict and set(value) == set(fixed) | set(flags) | {"errors", "configuration_sha256"}
             and all(canonical(value[k]) == canonical(v) for k, v in fixed.items())
             and all(type(value[k]) is bool for k in flags), "oracle_invalid")
        codes, config = value["errors"], value["configuration_sha256"]
        need(type(codes) is list and len(codes) <= 12
             and all(type(code) is str and code in JAVA_CODES for code in codes)
             and (config is None or type(config) is str and re.fullmatch(r"[0-9a-f]{64}", config)), "oracle_invalid")
        # Diagnostics can never promote a failed run or transfer source fields.
        return dict(status="reported", java_success=value["success"], errors=codes)
    except (FixtureError, D.DiscoveryError, ValueError, TypeError, KeyError):
        return dict(status="invalid")


def listener_ports(data):
    need(type(data) is bytes and len(data) <= 65536, "listeners_invalid")
    ports = []
    for line in data.decode("ascii").splitlines():
        values = line.split()
        if not values or values[0] == "sl":
            continue
        need(len(values) >= 10, "listeners_invalid")
        if values[3] != "0A":
            continue
        address, port = values[1].split(":")
        need(address == "0100007F" and re.fullmatch(r"[0-9A-F]{4}", port), "listeners_invalid")
        ports.append(int(port, 16))
    need(len(ports) == len(set(ports)), "listeners_invalid")
    return sorted(ports)


def rclone_args(*args, user="fixture-owner"):
    need(user in ("fixture-owner", "fixture-other"), "runtime_invalid")
    return ["/usr/bin/env", "-i", "HOME=/work/home", "PATH=/usr/bin:/bin", "/opt/hdfs/rclone",
            "--config", "/dev/null", "--retries", "1", "--low-level-retries", "1",
            "--contimeout", "3s", "--timeout", "8s", "--hdfs-namenode", "127.0.0.1:19000",
            "--hdfs-username", user, *args]


def remote(path=""):
    need(path in samples() or path in ("", "missing-synthetic-file"), "fixture_failed")
    return ":hdfs:/synthetic" + ("/" + path if path else "")


def verify_sample(path, expected):
    need(D.file_hash(path) == expected, "sample_mismatch")


def wait_file(docker, container, path):
    need(path in ("/work/output/ready.json", "/work/java-exit"), "fixture_failed")
    limit = 90 if path.endswith("ready.json") else 30
    script = ("i=0; while [ ! -s " + path + " ] && [ \"$i\" -lt " + str(limit) + " ]; do "
              + ("[ ! -e /work/java-exit ] || exit 2; " if path.endswith("ready.json") else "")
              + "sleep 1; i=$((i+1)); done; test -s " + path + " && cat " + path)
    return docker.call(["exec", container, "/bin/sh", "-c", script], timeout=limit + 5, limit=16384).stdout.read_bytes()


def check_missing(result):
    text = result.stderr.read_bytes().lower()
    # HDFS treats a missing root passed to cat as a missing directory.
    need(result.code != 0 and result.stdout.stat().st_size == 0
         and (b"object not found" in text or b"directory not found" in text), "negative_case_failed")


def validate_listing(listing):
    need(type(listing) is list and len(listing) == len(samples()) and
         all(type(row) is dict and type(row.get("Path")) is str and type(row.get("Size")) is int
             and row.get("IsDir") is False and type(row.get("ModTime")) is str for row in listing),
         "listing_invalid")
    need(sorted((row["Path"], row["Size"]) for row in listing) ==
         sorted((path, len(data)) for path, data in samples().items()), "listing_invalid")
    try:
        for row in listing:
            need(re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
                              r"(?:\.0{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})", row["ModTime"]),
                 "listing_invalid")
            moment = datetime.fromisoformat(row["ModTime"])
            need(moment.tzinfo is not None and moment.timestamp() == 1704067200, "listing_invalid")
    except (ValueError, OverflowError):
        raise FixtureError("listing_invalid") from None


def cancellation_script():
    # Observe bytes before rclone removes a failed in-place download.
    return """set -eu
test ! -e /work/download/cancel.bin
/usr/bin/timeout --signal=INT --kill-after=3s 8s "$@" > /work/cancel.out 2> /work/cancel.err &
child=$!
observed=0
i=0
while [ "$i" -lt 6 ]; do
  if [ -f /work/download/cancel.bin ]; then
    size=$(stat -c %s /work/download/cancel.bin 2>/dev/null || printf '0')
    if [ "$size" -gt "$observed" ]; then observed=$size; fi
  fi
  sleep 1
  i=$((i+1))
done
set +e
wait "$child"
code=$?
set -e
printf '%s %s\\n' "$code" "$observed"
"""


def probe(docker, container, progress=None):
    progress = {} if progress is None else progress
    def execute(args, **kwargs):
        return docker.call(["exec", container, *args], **kwargs)
    progress["stage"] = "java_ready"
    ready = validate_oracle(D.json_value(wait_file(docker, container, "/work/output/ready.json")), "ready")
    progress["stage"] = "listeners"
    ports = listener_ports(execute(["/bin/cat", "/proc/net/tcp", "/proc/net/tcp6"], limit=65536).stdout.read_bytes())
    need(ports == sorted(PORTS.values()), "listeners_invalid")
    progress["stage"] = "rclone_version"
    version = execute(["/usr/bin/env", "-i", "/opt/hdfs/rclone", "version"], limit=8192).stdout.read_bytes()
    need(version.splitlines()[0] == ("rclone v" + RCLONE_VERSION).encode("ascii"), "runtime_invalid")
    progress["stage"] = "listing"
    listing = D.json_value(execute(rclone_args("lsjson", remote(), "--recursive", "--files-only"),
                                   timeout=30, limit=32768).stdout.read_bytes())
    validate_listing(listing)
    progress["stage"] = "acquisition"
    acquired = []
    for path, data in sorted(samples().items()):
        result = execute(rclone_args("cat", remote(path)), timeout=30, limit=max(1, len(data) + 1))
        need(result.stdout.stat().st_size == len(data), "sample_mismatch")
        verify_sample(result.stdout, digest(data))
        acquired.append(dict(path=path, size=len(data), sha256=D.file_hash(result.stdout)))
    # Exercise the same acquisition verifier with a deliberately wrong hash.
    try:
        verify_sample(result.stdout, "0" * 64)
    except FixtureError as error:
        need(error.code == "sample_mismatch", "negative_case_failed")
    else:
        raise FixtureError("negative_case_failed")
    progress["stage"] = "missing_path"
    missing = execute(rclone_args("cat", remote("missing-synthetic-file")), timeout=20, allow_failure=True)
    check_missing(missing)
    progress["stage"] = "permission_denial"
    denied = execute(rclone_args("cat", remote("private/owner-only.txt"), user="fixture-other"),
                     timeout=20, allow_failure=True)
    text = denied.stderr.read_bytes().lower()
    need(denied.code != 0 and denied.stdout.stat().st_size == 0
         and (b"permission denied" in text or b"accesscontrolexception" in text), "negative_case_failed")
    progress["stage"] = "cancellation"
    cancelled = execute(["/bin/sh", "-c", cancellation_script(), "hdfs-cancel",
                         *rclone_args("copyto", remote("large/cancel.bin"), "/work/download/cancel.bin",
                                      "--inplace", "--buffer-size", "0", "--bwlimit", "32k")],
                        timeout=16, limit=128)
    cancellation = cancelled.stdout.read_bytes()
    match = re.fullmatch(rb"124 ([0-9]+)\n", cancellation)
    need(match is not None and 0 < int(match.group(1)) < len(samples()["large/cancel.bin"]), "negative_case_failed")
    progress["stage"] = "shutdown"
    execute(["/bin/sh", "-c",
             "for f in /proc/[0-9]*/comm; do [ \"$(cat \"$f\" 2>/dev/null)\" != rclone ] || exit 1; done"])
    execute(["/bin/rm", "-f", "--", "/work/download/cancel.bin"])
    execute(["/bin/sh", "-c", "set -eu; test ! -e /work/download/cancel.bin; set -C; printf 'shutdown\\n' > /work/shutdown"])
    need(wait_file(docker, container, "/work/java-exit") == b"0\n", "shutdown_failed")
    final = validate_oracle(D.json_value(execute(["/bin/cat", "/work/output/final.json"],
                                                limit=16384).stdout.read_bytes()), "final", ready)
    need(listener_ports(execute(["/bin/cat", "/proc/net/tcp", "/proc/net/tcp6"],
                                 limit=65536).stdout.read_bytes()) == [], "shutdown_failed")
    execute(["/bin/sh", "-c", "set -C; printf 'exit\\n' > /work/exit"])
    ended = docker.call(["wait", container], timeout=15)
    need(ended.stdout.read_bytes() == b"0\n", "shutdown_failed")
    return {"samples": acquired, "configuration_sha256": ready["configuration_sha256"],
            "listeners": ports, "checks": dict(listing=True, modification_times=True, download_hash=True,
                wrong_expected_hash_rejection=True, missing_source_path_rejection=True,
                simple_permission_denial=True, cancellation=True, cancelled_child_stopped=True,
                partial_download_removed=True, source_preservation=final["source_preserved"],
                configuration_preservation=final["configuration_preserved"],
                java_exited=True, listeners_closed=True)}


def run(rclone, *, runner_factory=D.Docker, downloader=download_jars):
    start = time.monotonic()
    report = dict(schema_version=1, scope="hdfs_simple_protocol_experiment", success=False,
                  started_utc=R.utc_now(), errors=[], inputs={}, result=None,
                  stage="preflight", java_diagnostic=dict(status="not_requested"),
                  cleanup_excludes=["shared_base_image", "shared_build_cache"],
                  webapp_scope="synthetic_scaffolding_not_vendor_ui",
                  review_status="partial_protocol_only", authentication_mode="SIMPLE",
                  http_services_present=True, network_scope="network_none_container_not_host_or_build_registry",
                  cleanup=dict(container_removed=False, image_removed=False, context_removed=False,
                               raw_evidence_removed=False), **FALSE_CLAIMS)
    root = context = identity = context_identity = docker = None
    attempted_build = attempted_create = False
    image = container = None
    run_id = uuid.uuid4().hex
    name = tag = "hdfs-fixture-" + run_id
    sources = {}
    old_umask = os.umask(0o077)
    try:
        D.hosted_guard()
        need(runtime_pin(PIN_FILE) == (RCLONE_VERSION, RCLONE_SHA), "input_changed")
        rows = runtime_rows()
        rclone = D.regular(Path(rclone), 128 * 1024 * 1024)
        need(D.file_hash(rclone) == RCLONE_SHA, "runtime_invalid")
        for path in (Path(__file__).resolve(), HERE / "HdfsFixture.java", HERE / "runtime-classpath.json",
                     DISCOVERY / "resolver_discovery.py", DISCOVERY / "offline_cache.py",
                     DISCOVERY / "artifact-lock.json", DISCOVERY / "run_discovery.py", PIN_FILE):
            sources[str(path)] = D.file_hash(path)
        report["inputs"] = dict(source_sha256={Path(p).name: h for p, h in sources.items()},
            rclone=dict(version=RCLONE_VERSION, sha256=RCLONE_SHA),
            jdk=dict(manifest=BASE, config_id=BASE_ID), runtime_jars=128,
            runtime_bytes=sum(row["size"] for row in rows), classpath_sha256=CLASSPATH_HASH,
            lock_sha256=O.LOCK_SHA256)
        root = Path(tempfile.mkdtemp(prefix="hdfs-simple-fixture-", dir="/tmp"))
        info = root.lstat(); identity = (info.st_dev, info.st_ino)
        need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700, "unsafe_path")
        context = root / "context"; context.mkdir(mode=0o700)
        info = context.lstat(); context_identity = (info.st_dev, info.st_ino)
        report["stage"] = "download"
        downloader(context, rows)
        shutil.copyfile(rclone, context / "rclone")
        shutil.copyfile(HERE / "HdfsFixture.java", context / "HdfsFixture.java")
        need(D.file_hash(context / "rclone") == RCLONE_SHA and
             D.file_hash(context / "HdfsFixture.java") == sources[str(HERE / "HdfsFixture.java")], "input_changed")
        for index, row in enumerate(rows):
            need(D.file_hash(context / "jars" / ("%03d.jar" % index)) == row["sha256"], "input_changed")
        build, checks, classpath = dockerfile(rows, sources[str(HERE / "HdfsFixture.java")])
        for filename, data in {"Dockerfile": build, "checksums": checks, "classpath": classpath,
                               "driver.sh": driver_script()}.items():
            (context / filename).write_text(data, encoding="ascii", newline="\n")
        for path, data in webapp_resources().items():
            target = context / "resources" / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        report["inputs"]["webapp_resources_sha256"] = digest(canonical(
            {path: digest(data) for path, data in webapp_resources().items()}))
        context_hashes = {p.relative_to(context).as_posix(): D.file_hash(p) for p in context.rglob("*") if p.is_file()}
        report["inputs"]["context_sha256"] = digest(canonical(context_hashes))
        report["stage"] = "docker_preflight"
        docker = runner_factory(root, max_calls=120)
        host = D.json_value(docker.call(["info", "--format", "{{json .}}"]).stdout.read_bytes())
        need(host.get("OSType") == "linux" and host.get("Architecture") in ("amd64", "x86_64"), "docker_platform_invalid")
        docker.call(["image", "pull", "--quiet", "--platform", "linux/amd64", BASE], timeout=120)
        base = docker.inspect("image", BASE)
        need(base.get("Id") == BASE_ID and base.get("Os") == "linux" and base.get("Architecture") == "amd64",
             "base_image_mismatch")
        need(docker.inspect("image", tag, allow_missing=True) is None, "image_binding_invalid")
        report["stage"] = "build"
        attempted_build = True
        docker.call(["build", "--network", "none", "--pull=false", "--label", LABEL + "=" + run_id,
                     "--tag", tag, str(context)], timeout=180, limit=4 * 1024 * 1024)
        built = docker.inspect("image", tag)
        image = built.get("Id")
        need(re.fullmatch(r"sha256:[0-9a-f]{64}", image or "")
             and built.get("Config", {}).get("Labels", {}).get(LABEL) == run_id
             and built.get("Config", {}).get("User") == "10001:10001", "image_binding_invalid")
        need(context_hashes == {p.relative_to(context).as_posix(): D.file_hash(p)
                                for p in context.rglob("*") if p.is_file()}, "input_changed")
        report["inputs"]["fixture_image_id"] = image
        need(docker.inspect("container", name, allow_missing=True) is None, "container_binding_invalid")
        report["stage"] = "create"
        attempted_create = True
        docker.call(command_args(name, image, run_id))
        current = docker.inspect("container", name); inspect_container(current, name, image, run_id)
        need(current.get("State", {}).get("Status") == "created" and current["State"].get("Running") is False,
             "container_binding_invalid")
        container = current["Id"]
        report["stage"] = "start"
        docker.call(["start", container])
        current = docker.inspect("container", container); inspect_container(current, name, image, run_id)
        need(current.get("Id") == container and current.get("State", {}).get("Running") is True, "container_failed")
        report["result"] = probe(docker, container, progress=report)
        report["stage"] = "exit_inspection"
        ended = docker.inspect("container", container); inspect_container(ended, name, image, run_id)
        need(ended.get("Id") == container and ended.get("State", {}).get("Running") is False
             and ended["State"].get("Status") == "exited" and ended["State"].get("ExitCode") == 0
             and ended["State"].get("OOMKilled") is False, "container_failed")
        report["success"] = True
        report["stage"] = "completed"
    except (FixtureError, D.DiscoveryError, O.CacheError) as error:
        report["errors"].append(error.code if error.code in CODES else "fixture_failed")
    except KeyboardInterrupt:
        report["errors"].append("fixture_interrupted")
    except BaseException:
        report["errors"].append("fixture_failed")
    finally:
        if report["errors"] and docker is not None and container is not None:
            report["java_diagnostic"] = dict(status="unavailable")
            if "command_cleanup_failed" not in report["errors"]:
                try:
                    report["java_diagnostic"] = failure_diagnostic(docker, container, name, image, run_id)
                except D.DiscoveryError as error:
                    if error.code == "command_cleanup_failed":
                        report["errors"].append("command_cleanup_failed")
                except BaseException:
                    pass
        for kind, attempted, reference, expected_id in (
                ("container", attempted_create, container or name, container),
                ("image", attempted_build, image or tag, image)):
            try:
                if attempted:
                    current = docker.inspect(kind, reference, allow_missing=True)
                    if current is not None:
                        need(current.get("Config", {}).get("Labels", {}).get(LABEL) == run_id
                             and (expected_id is None or current.get("Id") == expected_id),
                             kind + "_cleanup_failed")
                        if kind == "container":
                            need(current.get("Name") == "/" + name and current.get("Image") == image,
                                 "container_cleanup_failed")
                        else:
                            need(current.get("RepoTags") == [tag + ":latest"], "image_cleanup_failed")
                        owned = current["Id"]
                        docker.call([kind, "rm", *(["--force"] if kind == "container" else []), owned])
                        need(docker.inspect(kind, owned, allow_missing=True) is None, kind + "_cleanup_failed")
                report["cleanup"][kind + "_removed"] = True
            except BaseException:
                report["errors"].append(kind + "_cleanup_failed")
        try:
            if context is not None:
                info = context.lstat()
                need(stat.S_ISDIR(info.st_mode) and not context.is_symlink()
                     and (info.st_dev, info.st_ino) == context_identity
                     and "command_cleanup_failed" not in report["errors"], "context_cleanup_failed")
                shutil.rmtree(context)
                need(not context.exists() and not context.is_symlink(), "context_cleanup_failed")
            report["cleanup"]["context_removed"] = True
        except BaseException:
            report["errors"].append("context_cleanup_failed")
        try:
            for path, expected in sources.items():
                need(D.file_hash(Path(path)) == expected, "input_changed")
            if sources:
                need(D.file_hash(rclone) == RCLONE_SHA, "input_changed")
        except BaseException:
            report["errors"].append("input_changed")
        try:
            if root is not None:
                info = root.lstat()
                need(all(report["cleanup"][key] is True for key in ("container_removed", "image_removed", "context_removed"))
                     and "command_cleanup_failed" not in report["errors"] and stat.S_ISDIR(info.st_mode)
                     and not root.is_symlink() and (info.st_dev, info.st_ino) == identity, "raw_cleanup_failed")
                shutil.rmtree(root)
                need(not root.exists() and not root.is_symlink(), "raw_cleanup_failed")
            report["cleanup"]["raw_evidence_removed"] = True
        except BaseException:
            report["errors"].append("raw_cleanup_failed")
        os.umask(old_umask)
    report["success"] = report["success"] and not report["errors"] and all(report["cleanup"].values())
    report["finished_utc"] = R.utc_now()
    report["duration_seconds"] = round(time.monotonic() - start, 3)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rclone", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    previous = signal.getsignal(signal.SIGTERM)
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        fd = R.report_fd(args.report)
        with os.fdopen(fd, "w", encoding="ascii", newline="\n") as stream:
            result = run(args.rclone)
            json.dump(result, stream, sort_keys=True, indent=2)
            stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
        return 0 if result["success"] else 1
    except BaseException:
        print("fixture_report_failed")
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    raise SystemExit(main())
