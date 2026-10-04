"""Hosted-only secure HDFS experiment; no application or vendor acceptance.

Deploy beside hdfs-discovery and hdfs-kerberos-ticket. Java inputs are pinned
to reviewed source. Imports perform no native work.
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
import sys
import tempfile
import time
import types
import uuid

HERE = Path(__file__).resolve().parent
SUPPORT = HERE.parent / "hdfs-kerberos-ticket" / "ticket_probe_container.py"
SUPPORT_SHA = "538a81005d67123930fb9711474f3b681861fb0866a2443661e401833982624f"
JAVA_INPUTS = {"SecureKdc.java": "d7e9d712400f386c1c688fad7d7482c854d88a7cf61285a1a05473ad3e8764bb",
    "SecureHdfsRoles.java": "dfdb5407dabc1ac5b32ce4cd0203feb70ada6adb633cef05c5a05887d52627f8",
    "SecureHdfsController.java": "c4b376ebb2946175e67613561139351d78b93b24abaf9c21eda08f5e654033b6"}
LABEL = "org.openai.triage.hdfs-kerberos-fixture"
TMPFS = "rw,nosuid,nodev,noexec,size=1g,mode=0700,uid=10001,gid=10001"
FALSE_CLAIMS = dict(ledger_eligible=False, authentication_verified=False, hdfs_authenticated=False,
    renewal_verified=False, daemon_accepted=False, provider_accepted=False, application_accepted=False,
    vendor_accepted=False, vulnerability_audited=False)
READY_CHECKS = frozenset("environment private_runtime tls_material kdc_ready format_complete nn_ready dn_ready "
    "listeners_exact https_verified https_wrong_host_rejected https_wrong_ca_rejected simple_rpc_rejected seed_verified ticket_ready".split())
FINAL_CHECKS = READY_CHECKS | {"stop_requested", "source_verified"}
FINAL_CLEANUP = frozenset("dn_stopped nn_stopped kdc_stopped processes_reaped listeners_absent "
    "private_material_removed no_forced_termination".split())
CONTROLLER_CODES = frozenset("environment_invalid path_invalid input_changed classpath_invalid arguments_invalid "
    "deadline_exceeded child_start_failed child_failed child_timeout output_failed output_limit receipt_invalid "
    "listener_mismatch tls_generation_failed tls_material_invalid tls_verification_failed tls_negative_mismatch "
    "kdc_start_failed format_failed nn_start_failed dn_start_failed seed_failed ticket_failed stop_invalid "
    "source_verification_failed role_stop_failed forced_termination process_cleanup_failed private_cleanup_failed "
    "report_failed simple_rpc_rejection_failed io_failure interrupted unclassified "
    "role_environment_failed role_material_failed role_configuration_failed role_login_failed role_format_failed "
    "role_format_preexisting role_format_incomplete role_source_failed role_service_start_failed role_cleanup_failed "
    "role_preservation_failed role_report_failed role_invalid_config role_io_failure role_file_missing role_security_failure "
    "role_illegal_state role_null_state role_missing_class role_linkage_failure role_resource_failure role_exit_requested "
    "role_halt_requested role_unclassified".split())
CODES = frozenset("hosted_linux_required input_invalid input_changed unsafe_path support_invalid runtime_invalid "
    "source_not_frozen download_failed download_cleanup_failed command_cleanup_failed platform_invalid base_invalid "
    "image_invalid container_invalid controller_invalid controller_failed listing_invalid sample_mismatch "
    "negative_failed cancellation_failed client_deadline shutdown_failed container_cleanup_failed image_cleanup_failed "
    "raw_cleanup_failed interrupted fixture_failed".split())


class FixtureError(Exception):
    def __init__(self, code):
        self.code = code if code in CODES else "fixture_failed"
        super().__init__(self.code)


def need(value, code):
    if not value: raise FixtureError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(value):
    return hashlib.sha256(value).hexdigest()


def hosted_guard():
    need(sys.platform == "linux" and os.environ.get("GITHUB_ACTIONS") == "true"
         and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and os.environ.get("RUNNER_OS") == "Linux",
         "hosted_linux_required")


def load_support():
    path = SUPPORT
    for item in (path, *path.parents):
        info = item.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400, "unsafe_path")
    need(path.is_file() and path.stat().st_size < 128 * 1024, "support_invalid")
    raw = path.read_bytes(); need(digest(raw) == SUPPORT_SHA, "support_invalid")
    module = types.ModuleType("secure_hdfs_ticket_support"); module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    need(module.file_hash(path) == SUPPORT_SHA, "input_changed")
    return module


def runtime_pin(T):
    path = HERE.parents[2] / "rclone-version.env"
    values = {}
    for line in T.read(path, 4096).decode("ascii").splitlines():
        if not line or line.startswith("#"): continue
        key, sep, value = line.partition("=")
        need(sep and key not in values, "runtime_invalid"); values[key] = value
    need(set(values) == {"RCLONE_VERSION", "RCLONE_EXE_SHA256", "RCLONE_WINDOWS_ZIP_SHA256",
        "RCLONE_LINUX_ZIP_SHA256", "RCLONE_LINUX_EXE_SHA256"}
        and re.fullmatch(r"[1-9][0-9]*\.[0-9]+\.[0-9]+", values["RCLONE_VERSION"])
        and all(re.fullmatch(r"[a-f0-9]{64}", value) for key, value in values.items() if key != "RCLONE_VERSION"),
        "runtime_invalid")
    return path, values["RCLONE_VERSION"], values["RCLONE_LINUX_EXE_SHA256"]


def samples():
    return {"README.txt": b"HDFS synthetic fixture\n", "empty.bin": b"", "nested/alpha.txt": b"alpha\n",
        "nested/space name.txt": b"space name\n", "nested/deeper/data.bin": bytes(range(256)),
        "unicode/utf8.txt": b"caf\xc3\xa9\n", "private/owner-only.txt": b"private synthetic bytes\n",
        "large/cancel.bin": bytes(range(256)) * 8192}


def webapp_resources():
    descriptor = b'<?xml version="1.0" encoding="UTF-8"?>\n<web-app xmlns="http://java.sun.com/xml/ns/j2ee" version="2.4"></web-app>\n'
    index = b"<!doctype html><title>Synthetic fixture</title><p>Protocol test only.</p>\n"
    return {"webapps/hdfs/WEB-INF/web.xml": descriptor, "webapps/datanode/WEB-INF/web.xml": descriptor,
        "webapps/hdfs/index.html": index, "webapps/datanode/index.html": index,
        "webapps/static/fixture.txt": b"Protocol test resources only.\n"}


def build_files(T, rows, rclone_sha):
    cp = ":".join("/opt/secure/jars/%03d.jar" % index for index in range(len(rows)))
    classpath = "/opt/secure/classes:" + cp + "\n"
    driver = """#!/bin/sh
set -eu
umask 077
mkdir /work/home /work/tmp /work/download
set +e
/usr/bin/timeout --signal=TERM --kill-after=5s 360s /opt/java/openjdk/bin/java -Xmx512m -Djava.net.preferIPv4Stack=true -Djava.io.tmpdir=/work/tmp -Duser.home=/work/home -cp "$(cat /opt/secure/classpath)" SecureHdfsController > /work/controller.log 2>&1
code=$?
set -e
printf '%s\\n' "$code" > /work/controller-exit
while [ ! -e /work/exit ]; do sleep 1; done
exit "$code"
"""
    checks = "".join(row["sha256"] + "  /opt/secure/jars/%03d.jar\n" % i for i, row in enumerate(rows))
    checks += "".join(value + "  /opt/secure/" + name + "\n" for name, value in sorted(JAVA_INPUTS.items()))
    checks += rclone_sha + "  /opt/secure/rclone\n" + digest(driver.encode()) + "  /opt/secure/driver.sh\n"
    checks += digest(classpath.encode()) + "  /opt/secure/classpath\n"
    checks += "".join(digest(data) + "  /opt/secure/resources/" + name + "\n" for name, data in sorted(webapp_resources().items()))
    names = " ".join("/opt/secure/" + name for name in sorted(JAVA_INPUTS))
    dockerfile = ("FROM " + T.BASE + "\nUSER 0\nCOPY . /opt/secure/\n"
        "RUN sha256sum -c /opt/secure/checksums && mkdir /opt/secure/classes && "
        "/opt/java/openjdk/bin/javac -J-Xmx768m -proc:none -implicit:none -encoding UTF-8 -cp '" + cp +
        "' -d /opt/secure/classes " + names + " && cp -R /opt/secure/resources/webapps /opt/secure/classes/ && "
        "chmod -R a=rX /opt/secure && chmod 0555 /opt/secure/rclone\nUSER 10001:10001\nWORKDIR /work\n")
    return {"Dockerfile": dockerfile.encode(), "checksums": checks.encode(), "classpath": classpath.encode(), "driver.sh": driver.encode()}


def command_args(name, image, run_id):
    need(type(run_id) is str and re.fullmatch(r"[a-f0-9]{32}", run_id) and name == "hdfs-kerberos-" + run_id
        and type(image) is str and re.fullmatch(r"sha256:[a-f0-9]{64}", image), "container_invalid")
    return ["create", "--name", name, "--label", LABEL + "=" + run_id, "--network", "none", "--read-only",
        "--user", "10001:10001", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "384",
        "--memory", "6g", "--cpus", "2", "--init", "--cgroupns", "private", "--ipc", "private", "--log-driver", "none",
        "--stop-timeout", "10", "--tmpfs", "/work:" + TMPFS, "--entrypoint", "/usr/bin/env", image,
        "-i", "HOME=/work/home", "PATH=/opt/java/openjdk/bin:/usr/bin:/bin", "JAVA_HOME=/opt/java/openjdk",
        "LANG=C", "LC_ALL=C", "/bin/sh", "/opt/secure/driver.sh"]


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
        and type(host.get("Memory")) is int and host["Memory"] == 6 * 1024**3
        and type(host.get("NanoCpus")) is int and host["NanoCpus"] == 2 * 10**9
        and type(host.get("PidsLimit")) is int and host["PidsLimit"] == 384
        and host.get("Init") is True and host.get("IpcMode") == "private" and host.get("CgroupnsMode") == "private"
        and host.get("Tmpfs") == {"/work": TMPFS} and host.get("LogConfig", {}).get("Type") == "none"
        and not host.get("Devices") and not host.get("DeviceRequests") and not host.get("ExtraHosts")
        and not host.get("PidMode"), "container_invalid")
    mounts = value.get("Mounts")
    need(type(mounts) is list and len(mounts) <= 1 and all(type(m) is dict and m.get("Type") == "tmpfs"
        and m.get("Destination") == "/work" for m in mounts), "container_invalid")


def validate_controller(T, raw, phase):
    value = T.parse(raw, 32768)
    need(phase in {"ready", "final"} and type(value) is dict
        and set(value) == {"schema_version", "scope", "phase", "success", "checks", "cleanup", "errors"} | set(FALSE_CLAIMS)
        and type(value["schema_version"]) is int and value["schema_version"] == 1
        and value["scope"] == "secure_hdfs_controller_feasibility" and value["phase"] == phase
        and type(value["success"]) is bool and all(value[k] is False for k in FALSE_CLAIMS), "controller_invalid")
    for field, keys in (("checks", READY_CHECKS if phase == "ready" else FINAL_CHECKS),
                        ("cleanup", set() if phase == "ready" else FINAL_CLEANUP)):
        need(type(value[field]) is dict and set(value[field]) == keys
            and all(type(x) is bool for x in value[field].values()), "controller_invalid")
    need(type(value["errors"]) is list and len(value["errors"]) <= len(CONTROLLER_CODES)
        and all(type(x) is str and x in CONTROLLER_CODES for x in value["errors"])
        and len(set(value["errors"])) == len(value["errors"]), "controller_invalid")
    passed = all(value["checks"].values()) and all(value["cleanup"].values()) and not value["errors"]
    need(value["success"] is passed, "controller_invalid")
    return value


def rclone_args(*args, simple=False):
    need(type(simple) is bool, "runtime_invalid")
    env = ["/usr/bin/env", "-i", "HOME=/work/home", "PATH=/usr/bin:/bin"]
    if not simple: env += ["KRB5_CONFIG=/work/secure/auth/krb5.conf", "KRB5CCNAME=FILE:/work/secure/auth/reader.ccache"]
    return env + ["/opt/secure/rclone", "--config", "/work/secure/auth/" + ("simple.conf" if simple else "rclone.conf"),
        "--retries", "1", "--low-level-retries", "1", "--contimeout", "3s", "--timeout", "8s", *args]


def remote(path=""):
    need(path in samples() or path in ("", "missing-synthetic-file"), "input_invalid")
    return "test:/synthetic" + ("/" + path if path else "")


def validate_listing(value):
    need(type(value) is list and len(value) == len(samples()) and all(type(row) is dict
        and type(row.get("Path")) is str and type(row.get("Size")) is int and row.get("IsDir") is False
        and type(row.get("ModTime")) is str for row in value), "listing_invalid")
    need(sorted((row["Path"], row["Size"]) for row in value) == sorted((p, len(v)) for p, v in samples().items()), "listing_invalid")
    for row in value:
        try:
            need(re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.0{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})", row["ModTime"]), "listing_invalid")
            timestamp = datetime.fromisoformat(row["ModTime"])
            need(timestamp.tzinfo is not None and timestamp.timestamp() == 1704067200, "listing_invalid")
        except (ValueError, OverflowError): raise FixtureError("listing_invalid") from None


def verify_sample(data, expected):
    need(type(data) is bytes and type(expected) is str and re.fullmatch(r"[a-f0-9]{64}", expected)
        and digest(data) == expected, "sample_mismatch")


def simple_failed(T, result):
    # Go hdfs v2.4 checks response sequence before status; Hadoop sends its
    # authorization-failed call ID. This proves only client failure. The
    # controller separately checks the server's typed raw RPC rejection.
    error = T.read(result.stderr, 65536)
    need(type(result.code) is int and result.code != 0 and T.read(result.stdout, 1) == b""
        and b"unexpected sequence number" in error, "negative_failed")


def missing_rejected(T, result):
    error = T.read(result.stderr, 65536).lower()
    need(type(result.code) is int and result.code != 0 and T.read(result.stdout, 1) == b""
        and (b"object not found" in error or b"directory not found" in error), "negative_failed")


def cancellation_script():
    # Observe partial bytes before rclone can remove its failed in-place copy.
    return """set -eu
umask 077
test ! -e /work/download/cancel.bin && test ! -L /work/download/cancel.bin
/usr/bin/timeout --signal=INT --kill-after=3s 8s "$@" > /work/cancel.out 2> /work/cancel.err &
child=$!
observed=0
i=0
while [ "$i" -lt 6 ]; do
  if [ -f /work/download/cancel.bin ]; then
    test ! -L /work/download/cancel.bin
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


def partial_cleanup_script():
    return """set -eu
for f in /proc/[0-9]*/comm; do [ "$(cat "$f" 2>/dev/null)" != rclone ] || exit 1; done
test ! -L /work && test ! -L /work/download && test ! -L /work/download/cancel.bin
test "$(stat -c '%u:%g:%a' /work/download)" = '10001:10001:700'
if [ -e /work/download/cancel.bin ]; then
  test -f /work/download/cancel.bin
  test "$(stat -c '%u:%g:%h' /work/download/cancel.bin)" = '10001:10001:1'
  /bin/rm -- /work/download/cancel.bin
fi
test ! -e /work/download/cancel.bin && test ! -L /work/download/cancel.bin
"""


def wait_file(T, docker, container, phase):
    need(phase in ("ready", "final"), "input_invalid")
    path = "/work/secure/ready.json" if phase == "ready" else "/work/controller-exit"
    seconds = 180 if phase == "ready" else 90
    script = ("i=0; while [ ! -s " + path + " ] && [ \"$i\" -lt " + str(seconds) + " ]; do "
        + ("[ ! -e /work/controller-exit ] || exit 2; " if phase == "ready" else "")
        + "sleep 1; i=$((i+1)); done; test -s " + path + " && cat " + path)
    result = docker.call(["exec", container, "/bin/sh", "-c", script], timeout=seconds+5, limit=32768)
    return T.read(result.stdout, 32768)


def capture_failure(T, docker, container, name, image, run_id):
    # Only this closed receipt can leave the lab; never return stderr/log text.
    current = docker.inspect("container", container)
    inspect_container(current, name, image, run_id)
    need(current.get("Id") == container and current.get("State", {}).get("Running") is True, "container_invalid")
    result = docker.call(["exec", container, "/bin/cat", "/work/secure-final.json"],
        timeout=5, limit=32768, allow_failure=True)
    if result.code != 0: return None
    return validate_controller(T, T.read(result.stdout, 32768), "final")


def probe(T, docker, container, version, report):
    client_until = None
    def execute(args, **kw):
        if client_until is not None:
            remaining = int(client_until-time.monotonic())
            need(remaining >= 1, "client_deadline")
            kw["timeout"] = min(kw.get("timeout", 20), remaining)
        return docker.call(["exec", container, *args], **kw)
    report["stage"] = "controller_ready"
    ready = validate_controller(T, wait_file(T, docker, container, "ready"), "ready")
    report["controller_ready"] = ready; need(ready["success"], "controller_failed")
    client_until = time.monotonic()+90
    report["stage"] = "rclone_version"
    actual = T.read(execute(["/usr/bin/env", "-i", "/opt/secure/rclone", "version"], limit=8192).stdout, 8192)
    need(actual.splitlines()[0] == ("rclone v" + version).encode("ascii"), "runtime_invalid")
    report["stage"] = "listing"
    listing = T.parse(T.read(execute(rclone_args("lsjson", remote(), "--recursive", "--files-only"), timeout=25, limit=32768).stdout, 32768))
    validate_listing(listing)
    report["stage"] = "acquisition"; acquired = []
    for path, value in sorted(samples().items()):
        result = execute(rclone_args("cat", remote(path)), timeout=20, limit=max(1, len(value)+1))
        data = T.read(result.stdout, len(value)+1)
        need(len(data) == len(value), "sample_mismatch"); verify_sample(data, digest(value))
        acquired.append(dict(path=path, size=len(data), sha256=digest(data)))
    try: verify_sample(data, "0"*64)
    except FixtureError as error: need(error.code == "sample_mismatch", "negative_failed")
    else: raise FixtureError("negative_failed")
    report["stage"] = "missing_path"
    missing = execute(rclone_args("cat", remote("missing-synthetic-file")), timeout=20, limit=65536, allow_failure=True)
    missing_rejected(T, missing)
    report["stage"] = "simple_denial"
    denied = execute(rclone_args("cat", remote("nested/alpha.txt"), simple=True), timeout=20, limit=65536, allow_failure=True)
    simple_failed(T, denied)
    report["stage"] = "authenticated_recovery"
    restored = T.read(execute(rclone_args("cat", remote("nested/alpha.txt")), timeout=20, limit=16).stdout, 16)
    verify_sample(restored, digest(samples()["nested/alpha.txt"]))
    report["stage"] = "cancellation"
    cancelled = execute(["/bin/sh", "-c", cancellation_script(), "hdfs-cancel", *rclone_args("copyto",
        remote("large/cancel.bin"), "/work/download/cancel.bin", "--inplace", "--buffer-size", "0", "--bwlimit", "32k")], timeout=16, limit=65536)
    match = re.fullmatch(rb"124 ([0-9]+)\n", T.read(cancelled.stdout, 128))
    need(match is not None and 0 < int(match.group(1)) < len(samples()["large/cancel.bin"]), "cancellation_failed")
    execute(["/bin/sh", "-c", partial_cleanup_script()])
    client_until = None
    report["stage"] = "shutdown"
    execute(["/bin/sh", "-c", "set -eu; umask 077; set -C; : > /work/secure/stop"])
    need(wait_file(T, docker, container, "final") == b"0\n", "shutdown_failed")
    final = validate_controller(T, T.read(execute(["/bin/cat", "/work/secure-final.json"], limit=32768).stdout, 32768), "final")
    report["controller_final"] = final; need(final["success"], "controller_failed")
    execute(["/bin/sh", "-c", "set -eu; umask 077; set -C; : > /work/exit"])
    need(T.read(docker.call(["wait", container], timeout=15, limit=128).stdout, 128) == b"0\n", "shutdown_failed")
    return dict(samples=acquired, checks=dict(listing=True, modification_times=True, download_hashes=True,
        wrong_expected_hash_rejection=True, missing_source_path_rejection=True, simple_client_failed=True,
        simple_rpc_rejected=ready["checks"]["simple_rpc_rejected"], authenticated_read_after_denial=True,
        cancellation=True, cancelled_child_stopped=True, partial_download_removed=True, source_preservation=True,
        orderly_shutdown=True), missing_path_verified=True, permission_denial_verified=False,
        cancellation_verified=True, renewal_verified=False)


def run(rclone, *, support_loader=load_support, runner_factory=None, downloader=None):
    started = time.monotonic()
    report = dict(schema_version=1, scope="hdfs_kerberos_container_feasibility", success=False,
        started_utc=datetime.now(timezone.utc).isoformat(), finished_utc=None, duration_seconds=None,
        stage="preflight", inputs=None, result=None, controller_ready=None, controller_final=None, errors=[],
        cleanup=dict(container_removed=False, image_removed=False, context_removed=False, raw_evidence_removed=False),
        cleanup_excludes=["shared_base_image", "shared_build_cache"], rpc_privacy_verified=False, **FALSE_CLAIMS)
    T = D = docker = root = root_id = context = context_id = None
    sources = {}; image = container = None; build_attempted = create_attempted = False
    run_id = uuid.uuid4().hex; name = tag = "hdfs-kerberos-" + run_id
    old_umask = os.umask(0o077)
    try:
        hosted_guard()
        need(all(re.fullmatch(r"[a-f0-9]{64}", value) for value in JAVA_INPUTS.values()), "source_not_frozen")
        T = support_loader(); D, sources = T.load_helpers()
        source_paths = [Path(__file__).resolve(), SUPPORT, T.HERE / "runtime-classpath.json", T.DISCOVERY / "artifact-lock-kerberos.json"]
        pin, version, rclone_sha = runtime_pin(T); source_paths += [pin]
        java = {name: T.read(HERE / name, 256 * 1024) for name in JAVA_INPUTS}
        need(all(digest(value) == JAVA_INPUTS[name] for name, value in java.items()), "input_invalid")
        source_paths += [HERE / name for name in java]
        for path in source_paths: sources[path] = T.file_hash(path, 512 * 1024)
        rows = T.runtime_rows(T.read(source_paths[2], 512 * 1024), T.read(source_paths[3], 512 * 1024))
        rclone = Path(rclone).absolute(); need(T.file_hash(rclone) == rclone_sha, "runtime_invalid")
        report["inputs"] = dict(source_sha256={p.name: h for p, h in sources.items()}, rclone_version=version,
            rclone_sha256=rclone_sha, jdk_manifest=T.BASE, jdk_config_id=T.BASE_ID, runtime_jars=len(rows),
            runtime_bytes=sum(row["size"] for row in rows), runtime_classpath_sha256=T.ORDER_SHA,
            lock_sha256=T.LOCK_SHA, context_sha256=None, image_id=None, container_id=None)
        need(shutil.disk_usage("/tmp").free >= 1024**3, "unsafe_path")
        root = Path(tempfile.mkdtemp(prefix="hdfs-kerberos-", dir="/tmp")); root_id = T.directory(root)
        context = root / "context"; context.mkdir(mode=0o700); context_id = T.directory(context)
        for path in source_paths[2:4]: (context / path.name).write_bytes(T.read(path, 512 * 1024))
        report["stage"] = "download"; (downloader or T.download)(context, rows); T.verify_jars(context, rows)
        shutil.copyfile(rclone, context / "rclone"); need(T.file_hash(context / "rclone") == rclone_sha, "input_changed")
        for name_, data in java.items(): (context / name_).write_bytes(data)
        for name_, data in build_files(T, rows, rclone_sha).items(): (context / name_).write_bytes(data)
        for path, data in webapp_resources().items():
            target = context / "resources" / path; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
        context_hashes = T.tree_hashes(context); report["inputs"]["context_sha256"] = digest(canonical(context_hashes))
        docker = (runner_factory or D.Docker)(root, max_calls=90)
        host = T.parse(T.read(docker.call(["info", "--format", "{{json .}}"]).stdout, 1024 * 1024))
        need(host.get("OSType") == "linux" and host.get("Architecture") in ("amd64", "x86_64"), "platform_invalid")
        report["stage"] = "base"; docker.call(["image", "pull", "--quiet", "--platform", "linux/amd64", T.BASE], timeout=120)
        base = docker.inspect("image", T.BASE)
        need(base.get("Id") == T.BASE_ID and base.get("Os") == "linux" and base.get("Architecture") == "amd64", "base_invalid")
        need(docker.inspect("image", tag, allow_missing=True) is None, "image_invalid")
        report["stage"] = "build"; build_attempted = True
        docker.call(["build", "--network", "none", "--pull=false", "--label", LABEL+"="+run_id, "--tag", tag, str(context)], timeout=180, limit=4*1024*1024)
        built = docker.inspect("image", tag); image = built.get("Id")
        need(type(image) is str and re.fullmatch(r"sha256:[a-f0-9]{64}", image)
            and built.get("Config", {}).get("Labels", {}).get(LABEL) == run_id
            and built.get("Config", {}).get("User") == "10001:10001", "image_invalid")
        need(T.tree_hashes(context) == context_hashes, "input_changed"); report["inputs"]["image_id"] = image
        need(docker.inspect("container", name, allow_missing=True) is None, "container_invalid")
        report["stage"] = "create"; create_attempted = True; docker.call(command_args(name, image, run_id))
        initial = docker.inspect("container", name); inspect_container(initial, name, image, run_id)
        need(initial.get("State", {}).get("Status") == "created" and initial["State"].get("Running") is False, "container_invalid")
        container = initial["Id"]; report["inputs"]["container_id"] = container
        docker.call(["start", container]); running = docker.inspect("container", container); inspect_container(running, name, image, run_id)
        need(running["Id"] == container and running.get("State", {}).get("Running") is True, "container_invalid")
        report["result"] = probe(T, docker, container, version, report)
        ended = docker.inspect("container", container); inspect_container(ended, name, image, run_id)
        state = ended.get("State", {})
        need(ended["Id"] == container and state.get("Running") is False and state.get("Status") == "exited"
            and state.get("OOMKilled") is False and type(state.get("ExitCode")) is int and state["ExitCode"] == 0, "container_invalid")
        report["success"] = True; report["stage"] = "completed"
    except KeyboardInterrupt: report["errors"].append("interrupted")
    except BaseException as error:
        code = getattr(error, "code", "fixture_failed")
        report["errors"].append(code if code in CODES else "fixture_failed")
    finally:
        if container is not None and report["errors"] and report["controller_final"] is None:
            try: report["controller_final"] = capture_failure(T, docker, container, name, image, run_id)
            except BaseException as error:
                if getattr(error, "code", None) == "command_cleanup_failed": report["errors"].append("command_cleanup_failed")
        for kind, attempted, ref, exact in (("container", create_attempted, container or name, container), ("image", build_attempted, image or tag, image)):
            try:
                if attempted:
                    current = docker.inspect(kind, ref, allow_missing=True)
                    if current is not None:
                        need(current.get("Config", {}).get("Labels", {}).get(LABEL) == run_id
                            and (exact is None or current.get("Id") == exact), kind+"_cleanup_failed")
                        owned = current.get("Id")
                        if kind == "container": need(re.fullmatch(r"[a-f0-9]{64}", owned or "") and current.get("Name") == "/"+name and current.get("Image") == image, "container_cleanup_failed")
                        else: need(re.fullmatch(r"sha256:[a-f0-9]{64}", owned or "") and current.get("RepoTags") == [tag+":latest"], "image_cleanup_failed")
                        docker.call([kind, "rm", *(["--force"] if kind == "container" else []), owned])
                        need(docker.inspect(kind, owned, allow_missing=True) is None, kind+"_cleanup_failed")
                report["cleanup"][kind+"_removed"] = True
            except BaseException as error:
                if getattr(error, "code", None) == "command_cleanup_failed": report["errors"].append("command_cleanup_failed")
                report["errors"].append(kind+"_cleanup_failed")
        try:
            if T is not None:
                for path, expected in sources.items(): need(T.file_hash(path, 512 * 1024) == expected, "input_changed")
                if sources: need(T.file_hash(rclone) == rclone_sha, "input_changed")
        except BaseException: report["errors"].append("input_changed")
        safe = all(report["cleanup"][k] for k in ("container_removed", "image_removed"))
        safe = safe and not {"command_cleanup_failed", "download_cleanup_failed"}.intersection(report["errors"])
        try:
            if context is not None:
                need(safe, "raw_cleanup_failed"); T.directory(root, root_id); T.directory(context, context_id)
                T.tree_hashes(context); shutil.rmtree(context); need(not context.exists(), "raw_cleanup_failed")
            report["cleanup"]["context_removed"] = True
            if root is not None:
                need(safe, "raw_cleanup_failed"); T.directory(root, root_id)
                for path in root.rglob("*"):
                    need(not path.is_symlink(), "unsafe_path")
                    if path.is_file(): T.regular(path, 8 * 1024 * 1024)
                shutil.rmtree(root); need(not root.exists(), "raw_cleanup_failed")
            report["cleanup"]["raw_evidence_removed"] = True
        except BaseException: report["errors"].append("raw_cleanup_failed")
        os.umask(old_umask)
    report["success"] = report["success"] and not report["errors"] and all(report["cleanup"].values())
    report["finished_utc"] = datetime.now(timezone.utc).isoformat(); report["duration_seconds"] = round(time.monotonic()-started, 3)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rclone", type=Path, required=True); parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv); prior = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        hosted_guard(); T = load_support(); need(args.report.is_absolute(), "unsafe_path")
        for parent in args.report.parents: T.directory(parent)
        fd = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            report = run(args.rclone); data = canonical(report)+b"\n"; need(len(data) <= 65536, "input_invalid")
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        return 0 if report["success"] else 1
    except BaseException:
        sys.stderr.write("secure_hdfs_fixture_failed\n"); return 1
    finally: signal.signal(signal.SIGTERM, prior)


if __name__ == "__main__":
    raise SystemExit(main())
