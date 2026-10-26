"""Hosted-only one-DataNode Kerberos transfer feasibility supervisor. Imports are inert; no provider credit.

Expected repository layout: HERE is the transfer directory beside hdfs-discovery.
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
REMEDIATION_RUNTIME = HERE.parent / "hdfs-kerberos-rpc" / "runtime-classpath-remediation.json"
PIN_FILE = HERE.parents[2] / "rclone-version.env"
RCLONE_VERSION = "1.75.2"
RCLONE_SHA = "ed7ab1f17876bb006c3df3949a3044959671afd9112362dacaa5dd1647735bc1"
DENIAL = "SIMPLE authentication is not enabled.  Available:[TOKEN, KERBEROS]"
EXCEPTION = "org.apache.hadoop.security.AccessControlException"
STAGES = frozenset("environment tls filesystem datanode_start tls_endpoints empty small missing payload_before payload_after rclone_version kdc_init principals kdc_start owner_login format namenode_start relay_start seed reader_tgt listing_before rclone_none wire_none listing_after preservation completed".split())
DIAGNOSTIC_CATEGORIES = frozenset("none unclassified assertion exit_requested halt_requested missing_class resource_failure invalid_config linkage_failure linkage_no_such_method linkage_no_such_field linkage_abstract_method linkage_illegal_access linkage_instantiation linkage_incompatible_class linkage_initializer linkage_bootstrap linkage_circularity linkage_class_format linkage_class_version linkage_native linkage_verify metrics_failure null_state illegal_state unsupported_operation security_failure krb_failure file_missing io_failure interrupted".split())
DIAGNOSTIC_ORIGINS = frozenset("none namenode_constructor namenode_initialize namenode_login namenode_format namenode_http hadoop_http hadoop_metrics default_metrics_get_impl default_metrics_init default_metrics_shutdown_instance default_metrics_set_impl metrics_system_constructor metrics_system_init metrics_system_start metrics_system_stop metrics_system_unregister_source metrics_system_register_sink metrics_system_get_proxy_for_callback metrics_system_start_metrics_mbeans metrics_system_stop_metrics_mbeans metrics_system_current_config metrics_system_start_timer metrics_system_on_timer_event metrics_system_publish_metrics_now metrics_system_sample_metrics metrics_system_snapshot_metrics metrics_system_publish_metrics metrics_system_stop_timer metrics_system_stop_sources metrics_system_stop_sinks metrics_system_configure metrics_system_configure_system metrics_system_configure_sinks metrics_system_new_sink metrics_system_configure_sources metrics_system_clear_configs metrics_system_get_hostname metrics_system_register_system_source metrics_system_get_metrics metrics_system_init_system_mbean metrics_system_shutdown metrics_system_get_source metrics_system_get_source_adapter metrics_system_get_sink_adapter metrics_system_init_mode default_metrics_initialize default_metrics_instance default_metrics_shutdown default_metrics_set_instance default_metrics_set_mini_cluster_mode default_metrics_in_mini_cluster_mode default_metrics_new_mbean_name default_metrics_remove_mbean_name default_metrics_remove_source_name default_metrics_source_name default_metrics_new_object_name default_metrics_remove_object_name default_metrics_remove_source default_metrics_new_source_name metrics_system_register metrics_system_register_source datanode_metrics_constructor datanode_metrics_create metrics_source_builder_constructor metrics_source_builder_registry metrics_source_builder_add metrics_source_builder_build metrics_source_builder_info metrics_factory_field metrics_factory_method metrics_factory_info metrics_factory_name metrics_annotations_builder method_metric_constructor jvm_metrics_create jvm_metrics_register metrics_registry_counter metrics_registry_gauge metrics_registry_rate metrics_registry_rates_aggregation metrics_registry_stat metrics_registry_rolling metrics_registry_quantiles http_authentication ugi block_manager namesystem metrics_config_constructor metrics_config_static_initializer metrics_config_create metrics_config_load_first metrics_config_subset metrics_config_get_instance_configs metrics_config_get_class_name metrics_config_get_plugin metrics_config_get_plugin_loader metrics_config_get_filter metrics_config_get_property_internal metrics_config_to_string metrics_config_keys config_properties_constructor config_properties_static_initializer config_properties_create_layout config_properties_install_layout config_properties_read config_abstract_constructor config_abstract_init_logger config_abstract_install_default_interpolator config_abstract_install_interpolator config_abstract_interpolate config_abstract_interpolated_configuration config_file_constructor config_file_static_initializer config_file_load config_file_load_from_reader config_file_load_from_stream config_file_load_from_stream_directly config_file_load_from_transformed_stream config_interpolator_constructor config_interpolator_static_initializer config_interpolator_create_interpolator config_interpolator_from_specification config_interpolator_get_default_prefix_lookups config_interpolator_init_substitutor config_interpolator_interpolate config_interpolator_resolve config_interpolator_resolve_single_variable config_lookup_holder_constructor config_lookup_holder_static_initializer config_lookup_holder_add_lookup config_lookup_holder_create_default_lookups config_lookup_holder_parse_lookups config_lookup_holder_get_default_prefix_lookups config_default_lookups_constructor config_default_lookups_static_initializer config_subset_constructor config_subset_init_interpolator".split())
THREAD_CATEGORIES = frozenset("probe_task jdk_process_reaper jdk_timer jdk_executor jdk_cleaner hadoop_metrics hadoop_rpc hadoop_fs hadoop_namenode hadoop_blockmanagement hadoop_util jetty kerby other".split())
THREAD_INTERVALS = frozenset("tls kdc owner_login format namenode filesystem datanode reader controls shutdown unattributed".split())
OWNED_CLEANUP_STATES = frozenset("not_attempted observation_incomplete services_not_stopped scan_failed missing ambiguous preexisting unobserved late not_daemon deadline shutdown_failed still_alive terminated".split())
TIMER_KINDS = frozenset("namenode_metrics rpc_idle snapshot_gc shell_timeout ssl_store unknown".split())
BASE = "docker.io/library/eclipse-temurin@sha256:e1c09a9ee23feb81f94016547826c1e694086cd927356fb57fccc312fcc32f85"
BASE_ID = "sha256:d0e6e16acb7f941e5206d99ec38e5bba18545c43462541958f84b22e0fc006e8"
JAVA_SHA = "b60c7febcde39efd32cce476bd083b9c3fd54516515a2a50a40dc689ff11cad8"
REMEDIATION_RUNTIME_SHA = "01095cf92c20a65a479aafdcd52538e11313610230c17b011a5e5146a81bb127"
REMEDIATION_ORDER_SHA = "74206f7ff8e05475fd310648003cd570c620e92cf670ee1965c66b96eb3ba15d"
REMEDIATION_LOCK_SHA = "a0fc4edc8ea5fa9df5c26cac0be9f638650c7a657260b9da5eaad16195746e95"
PROFILES = ("kerberos-remediation",)
LABEL = "org.openai.triage.kerberos-transfer"
TMPFS = "rw,nosuid,nodev,noexec,size=128m,mode=0700,uid=10001,gid=10001"
HELPERS = ("bootstrap_material", "graph_export", "offline_cache", "resolver_discovery")
FALSE_CLAIMS = dict(ledger_eligible=False, authentication_verified=False, hdfs_authenticated=False,
    renewal_verified=False, daemon_accepted=False, provider_accepted=False, application_accepted=False,
    vendor_accepted=False, vulnerability_audited=False, publisher_audit_completed=False)
JAVA_FALSE = set(FALSE_CLAIMS) - {"publisher_audit_completed"}
JAVA_CHECKS = frozenset(("environment", "endpoint_settings", "positive_tgt", "file_cache_v3",
    "nonrenewable", "secure_namenode", "secure_datanode", "tls_material", "tls_endpoints", "registered_datanode", "seed_hashes", "empty_acquired", "small_acquired", "missing_path_rejected", "payload_before", "payload_after", "listing_before", "rclone_auth_boundary_rejection",
    "wire_auth_boundary_rejection", "listing_after", "source_preserved", "cache_preserved"))
JAVA_CLEANUP = frozenset(("children_reaped", "relay_closed", "filesystem_closed", "namenode_stop_returned", "owner_logged_out", "kdc_stop_returned", "threads_terminated", "listeners_absent",
    "private_material_removed", "process_property_restored", "cleanup_completed", "gc_monitor_reaped", "fs_statistics_cleaner_reaped", "format_ssl_timer_reaped", "datanode_stop_returned", "datanode_ssl_timer_reaped"))
JAVA_CODES = frozenset("""environment_invalid path_invalid source_changed unexpected_files
listener_mismatch configuration_invalid deadline_exceeded positive_ticket_failed
wrong_password_failure_mismatch wrong_principal_not_rejected cache_invalid ticket_time_mismatch
ticket_flags_mismatch background_failure io_failure krb_failure interrupted unclassified cleanup_failed namenode_failed child_failed child_output_invalid wire_invalid rclone_positive_failed rclone_denial_mismatch source_invalid relay_invalid tls_invalid tls_keytool_exit_invalid tls_store_shape_invalid tls_certificate_key_invalid tls_certificate_signature_invalid tls_certificate_lifetime_invalid tls_certificate_san_invalid tls_resource_missing tls_resource_identity_invalid tls_resource_ambiguous datanode_failed missing_path_mismatch acquisition_invalid
child_descendant_found child_reap_failed child_streams_alive child_process_drift
rclone_denial_exit_zero rclone_denial_output_invalid
rclone_version_nonzero rclone_version_stderr rclone_version_mismatch""".split())
CODES = frozenset(("hosted_linux_required", "input_invalid", "input_changed", "unsafe_path", "download_failed",
    "download_cleanup_failed", "docker_failed", "command_cleanup_failed", "platform_invalid", "base_invalid",
    "image_invalid", "container_invalid", "wire_invalid", "java_report_invalid", "java_probe_failed", "interrupted",
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


def profile_settings(profile):
    """Closed identities; no caller-supplied paths or digest overrides."""
    need(type(profile) is str and profile in PROFILES, "input_invalid")
    return dict(profile=profile, runtime=REMEDIATION_RUNTIME, runtime_sha256=REMEDIATION_RUNTIME_SHA,
                order_sha256=REMEDIATION_ORDER_SHA, lock=DISCOVERY / "artifact-lock-kerberos-remediation.json",
                lock_sha256=REMEDIATION_LOCK_SHA)


def runtime_rows(runtime_raw, lock_raw, *, profile="kerberos-remediation"):
    pins = profile_settings(profile)
    need(sha(runtime_raw) == pins["runtime_sha256"] and sha(lock_raw) == pins["lock_sha256"], "input_invalid")
    runtime, lock = parse(runtime_raw), parse(lock_raw)
    need(type(runtime) is dict and set(runtime) == {"schema_version", "entries", "normalized_sha256"}
         and type(runtime["schema_version"]) is int and runtime["schema_version"] == 1, "input_invalid")
    rows = runtime["entries"]
    selected = [{key: row[key] for key in ("group", "artifact", "version", "type", "classifier", "size", "sha256")}
                for row in lock["artifacts"] if row["selected_runtime"]]
    need(type(rows) is list and len(rows) == 142 and len(selected) == 142
         and sha(canonical(rows)) == runtime["normalized_sha256"] == pins["order_sha256"]
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
                        # This is an acceptance deadline, not cancellation of blocking I/O.
                        # The owned worker retains its separate 300s kill/reap bound.
                        need(clock() < deadline, "download_failed")
                        if not chunk: break
                        count += len(chunk); need(count <= row["size"], "download_failed")
                        output.write(chunk); digest.update(chunk)
            observed_digest = digest.hexdigest()
            need(clock() < deadline and count == row["size"] and observed_digest == row["sha256"], "download_failed")
        except (OSError, urllib.error.URLError, ValueError):
            raise ProbeError("download_failed") from None
    directory(context, context_id); directory(jars, jar_id)
    need(clock() < deadline, "download_failed")


def download(context, rows, *, profile="kerberos-remediation"):
    profile_settings(profile)
    process = None; context_id = directory(context); source = Path(__file__).resolve()
    source_hash = file_hash(source, 512 * 1024)
    environment = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL", "GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "RUNNER_OS") if key in os.environ}
    try:
        process = subprocess.Popen([sys.executable, "-I", "-S", "-B", str(source), "--download-worker",
            str(context), str(context_id[0]), str(context_id[1]), source_hash, profile], stdin=subprocess.DEVNULL,
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


def webapp_resources():
    # Same minimal scaffolding as hdfs-fixture; no downloaded WAR or test JAR.
    return {
        "webapps/hdfs/WEB-INF/web.xml": b'<?xml version="1.0" encoding="UTF-8"?>\n<web-app xmlns="http://java.sun.com/xml/ns/j2ee" version="2.4"></web-app>\n',
        "webapps/hdfs/index.html": b"<!doctype html><title>Synthetic fixture</title><p>Protocol test only.</p>\n",
        "webapps/datanode/WEB-INF/web.xml": b'<?xml version="1.0" encoding="UTF-8"?>\n<web-app xmlns="http://java.sun.com/xml/ns/j2ee" version="2.4"></web-app>\n',
        "webapps/datanode/index.html": b"<!doctype html><title>Synthetic fixture</title><p>Protocol test only.</p>\n",
        "webapps/static/fixture.txt": b"Protocol test resources only.\n",
    }


def build_files(rows):
    cp = ":".join("/opt/transfer/jars/%03d.jar" % i for i in range(len(rows)))
    driver = ("#!/bin/sh\nset -eu\numask 077\nmkdir /work/home /work/tmp /work/tls-resources\n"
        "exec /usr/bin/timeout --signal=TERM --kill-after=5s 185s /opt/java/openjdk/bin/java "
        "-Xmx512m -Djava.net.preferIPv4Stack=true -Djava.io.tmpdir=/work/tmp -Duser.home=/work/home "
        "-cp \"$(cat /opt/transfer/classpath)\" HdfsKerberosTransferProbe\n")
    checks = "".join(row["sha256"] + "  /opt/transfer/jars/%03d.jar\n" % i for i, row in enumerate(rows))
    checks += RCLONE_SHA + "  /opt/transfer/rclone\n"
    checks += "".join(sha(data) + "  /opt/transfer/resources/" + path + "\n"
                      for path, data in sorted(webapp_resources().items()))
    checks += JAVA_SHA + "  /opt/transfer/HdfsKerberosTransferProbe.java\n" + sha(driver.encode()) + "  /opt/transfer/driver.sh\n"
    classpath = "/opt/transfer/classes:" + cp + ":/work/tls-resources\n"
    checks += sha(classpath.encode()) + "  /opt/transfer/classpath\n"
    dockerfile = ("FROM " + BASE + "\nUSER 0\nCOPY jars /opt/transfer/jars/\nCOPY rclone /opt/transfer/rclone\nCOPY resources /opt/transfer/resources\n"
        "COPY HdfsKerberosTransferProbe.java checksums driver.sh classpath /opt/transfer/\n"
        "RUN sha256sum -c /opt/transfer/checksums && mkdir /opt/transfer/classes && "
        "/opt/java/openjdk/bin/javac -J-Xmx512m -proc:none -implicit:none -encoding UTF-8 -cp '" + cp +
        "' -d /opt/transfer/classes /opt/transfer/HdfsKerberosTransferProbe.java && cp -R /opt/transfer/resources/webapps /opt/transfer/classes/ && chmod -R a=rX /opt/transfer && chmod 0555 /opt/transfer/rclone\n"
        "USER 10001:10001\nWORKDIR /work\n")
    return {"Dockerfile": dockerfile.encode(), "checksums": checks.encode(), "driver.sh": driver.encode(), "classpath": classpath.encode()}


def command_args(name, image, run_id):
    need(type(run_id) is str and re.fullmatch(r"[a-f0-9]{32}", run_id) and name == "kerberos-transfer-" + run_id
         and type(image) is str and re.fullmatch(r"sha256:[a-f0-9]{64}", image), "container_invalid")
    return ["create", "--name", name, "--label", LABEL + "=" + run_id, "--network", "none", "--read-only",
        "--user", "10001:10001", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "128",
        "--memory", "2g", "--cpus", "2", "--init", "--cgroupns", "private", "--ipc", "private", "--log-driver", "none",
        "--stop-timeout", "5", "--tmpfs", "/work:" + TMPFS, "--entrypoint", "/usr/bin/env", image,
        "-i", "HOME=/work/home", "PATH=/opt/java/openjdk/bin:/usr/bin:/bin", "JAVA_HOME=/opt/java/openjdk",
        "LANG=C", "LC_ALL=C", "/bin/sh", "/opt/transfer/driver.sh"]


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



def parse_wire(raw):
    """Independent closed protobuf wire oracle; never allocates from an unchecked length.

    Hadoop 3.5.0 RpcHeader.proto and RpcConstants.java: FATAL=2,
    FATAL_UNAUTHORIZED=15, authorization callId=uint32(-1), RPC version=9.
    An aligned NameNode may append stateId; no other extension is accepted.
    """
    need(type(raw) is bytes and 5 <= len(raw) <= 4100, "wire_invalid")
    size = int.from_bytes(raw[:4], "big", signed=True)
    need(0 < size <= 4096 and len(raw) == size + 4, "wire_invalid")
    data = raw[4:]; offset = 0
    def varint():
        nonlocal offset
        value = 0
        for index in range(10):
            need(offset < len(data), "wire_invalid")
            byte = data[offset]; offset += 1
            need(index < 9 or byte <= 1, "wire_invalid")
            value |= (byte & 127) << (7 * index)
            if byte < 128:
                need(index == 0 or byte != 0, "wire_invalid")
                return value
        raise ProbeError("wire_invalid")
    header_size = varint()
    need(header_size == len(data) - offset, "wire_invalid")
    fields = {}
    expected_types = {1: 0, 2: 0, 3: 0, 4: 2, 5: 2, 6: 0, 7: 2, 8: 0, 9: 0}
    while offset < len(data):
        tag = varint(); field, kind = tag >> 3, tag & 7
        need(field in expected_types and expected_types[field] == kind and field not in fields, "wire_invalid")
        if kind == 0: fields[field] = varint()
        else:
            length = varint(); need(length <= 512 and length <= len(data) - offset, "wire_invalid")
            fields[field] = data[offset:offset + length]; offset += length
    need(set(fields) in (set(range(1, 9)), set(range(1, 10))) and
         fields[1] == 0xffffffff and fields[2] == 2 and fields[3] == 9
         and fields[4] == EXCEPTION.encode("ascii") and fields[5] == DENIAL.encode("ascii")
         and fields[6] == 15 and fields[7] == b"" and fields[8] == 1
         and (9 not in fields or fields[9] <= 0x7fffffffffffffff), "wire_invalid")
    return dict(status="FATAL", detail="FATAL_UNAUTHORIZED", category="simple_disabled_kerberos_offered",
                rpc_version=9, endpoint="namenode_loopback", bounded_single_response=True)


PHASES = ("inventory_before", "empty", "small", "missing", "before", "negative", "after", "inventory_after")
EMPTY_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SMALL_SHA = "c8f5d0341d54d951a71b136e6e2afcb14d11ed8489a7ae126a8fee0df6ecf193"
PAYLOAD_SHA = "ac6f8d639b2e2c683c08d7deae690d1b6120bd74bc80a39a895481450082c571"
ACQUISITIONS = {"empty": (0, EMPTY_SHA), "small": (4096, SMALL_SHA), "missing": (0, EMPTY_SHA),
                "before": (1052673, PAYLOAD_SHA), "negative": (0, EMPTY_SHA), "after": (1052673, PAYLOAD_SHA)}


def validate_relay(value, complete):
    need(type(complete) is bool, "java_report_invalid")
    if value is None:
        need(not complete, "java_report_invalid"); return
    keys = {"phase_connections", "none_headers", "fatal_responses", "unexpected_connections", "bytes_forwarded_unchanged"}
    need(type(value) is dict and set(value) == keys and type(value["bytes_forwarded_unchanged"]) is bool, "java_report_invalid")
    counts = value["phase_connections"]
    need(type(counts) is dict and set(counts) == set(PHASES)
         and all(type(n) is int and 0 <= n <= 1 for n in counts.values()), "java_report_invalid")
    for key in ("none_headers", "fatal_responses", "unexpected_connections"):
        need(type(value[key]) is int and 0 <= value[key] <= 1, "java_report_invalid")
    need(value["fatal_responses"] <= value["none_headers"] <= counts["negative"], "java_report_invalid")
    if complete:
        need(all(n == 1 for n in counts.values()) and value["none_headers"] == value["fatal_responses"] == 1
             and value["unexpected_connections"] == 0 and value["bytes_forwarded_unchanged"] is True, "java_report_invalid")


def validate_acquisitions(value, passed):
    need(type(value["child_count"]) is int and 0 <= value["child_count"] <= 10
         and (not passed or value["child_count"] == 10), "java_report_invalid")
    acquisitions = value["acquisitions"]
    need(type(acquisitions) is dict and set(acquisitions) == set(ACQUISITIONS), "java_report_invalid")
    need(type(value["acquired_bytes"]) is int and 0 <= value["acquired_bytes"] <= 2109442, "java_report_invalid")
    need(value["missing_category"] == ("directory_not_found" if value["checks"]["missing_path_rejected"] else "not_observed"), "java_report_invalid")
    checks = dict(empty="empty_acquired", small="small_acquired", missing="missing_path_rejected", before="payload_before",
                  negative="rclone_auth_boundary_rejection", after="payload_after")
    verified_total = 0
    for name, (size, digest) in ACQUISITIONS.items():
        row = acquisitions[name]
        if row is None:
            need(not value["checks"][checks[name]], "java_report_invalid"); continue
        need(type(row) is dict and set(row) == {"bytes", "sha256"} and type(row["bytes"]) is int
             and 0 <= row["bytes"] <= 1052674 and type(row["sha256"]) is str
             and row["sha256"] in {EMPTY_SHA, SMALL_SHA, PAYLOAD_SHA, "mismatch"}, "java_report_invalid")
        if value["checks"][checks[name]]:
            need(row == {"bytes": size, "sha256": digest}, "java_report_invalid")
            verified_total += size
    need(verified_total == value["acquired_bytes"], "java_report_invalid")
    if passed: need(verified_total == 2109442, "java_report_invalid")


def validate_diagnostics(value, remaining, intervals, matrix, timers, observation_complete, error, cleanup, passed):
    need(type(value) is dict and set(value) == {"category", "origin"}
         and type(value["category"]) is str and value["category"] in DIAGNOSTIC_CATEGORIES
         and type(value["origin"]) is str and value["origin"] in DIAGNOSTIC_ORIGINS, "java_report_invalid")
    if error not in (None, "cleanup_failed", "background_failure"):
        need(value["category"] != "none", "java_report_invalid")
    need(type(observation_complete) is bool, "java_report_invalid")
    if remaining is None:
        need(intervals is None and matrix is None and timers is None and not passed and cleanup["threads_terminated"] is False, "java_report_invalid")
    else:
        need(type(remaining) is dict and set(remaining) == THREAD_CATEGORIES
             and all(type(count) is int and 0 <= count <= 128 for count in remaining.values())
             and sum(remaining.values()) <= 128, "java_report_invalid")
        if any(remaining.values()): need(cleanup["threads_terminated"] is False, "java_report_invalid")
        need(type(intervals) is dict and set(intervals) == THREAD_INTERVALS
             and all(type(count) is int and 0 <= count <= 128 for count in intervals.values())
             and sum(intervals.values()) == sum(remaining.values()), "java_report_invalid")
        if not observation_complete:
            need(intervals["unattributed"] == sum(remaining.values()), "java_report_invalid")
        need(type(matrix) is dict and set(matrix) == THREAD_CATEGORIES, "java_report_invalid")
        for category, row in matrix.items():
            need(type(row) is dict and set(row) == THREAD_INTERVALS
                 and all(type(count) is int and 0 <= count <= 128 for count in row.values())
                 and sum(row.values()) == remaining[category], "java_report_invalid")
        need(all(sum(row[phase] for row in matrix.values()) == intervals[phase] for phase in THREAD_INTERVALS)
             and sum(sum(row.values()) for row in matrix.values()) == sum(remaining.values()) <= 128,
             "java_report_invalid")
        need(type(timers) is dict and set(timers) == TIMER_KINDS
             and all(type(count) is int and 0 <= count <= 128 for count in timers.values())
             and sum(timers.values()) == remaining["jdk_timer"], "java_report_invalid")
    if passed:
        need(value == {"category": "none", "origin": "none"} and remaining is not None
             and not any(remaining.values()) and observation_complete, "java_report_invalid")


def validate_owned_cleanup(value, cleanup):
    need(type(value) is dict and set(value) == {"gc_monitor", "fs_statistics_cleaner", "format_ssl_timer"}, "java_report_invalid")
    for helper, state in value.items():
        need(type(state) is str and state in OWNED_CLEANUP_STATES
             and cleanup[helper + "_reaped"] is (state == "terminated"), "java_report_invalid")


def validate_java(raw, exit_code):
    try:
        value = parse(raw, 32768)
        keys = {"schema_version", "scope", "success", "expected_kerby_version", "runtime_binding_required", "checks",
                "cleanup", "cache_bytes", "child_count", "acquired_bytes", "acquisitions", "missing_category", "observed_lifetime_seconds", "stage", "wire_hex", "rclone_wire_hex", "relay", "error", "diagnostic", "remaining_threads", "remaining_thread_intervals", "remaining_thread_matrix", "remaining_timer_kinds", "thread_observation_complete", "owned_thread_cleanup"} | JAVA_FALSE
        need(type(value) is dict and set(value) == keys and type(value["schema_version"]) is int
             and value["schema_version"] == 1 and value["scope"] == "hdfs_kerberos_transfer_feasibility"
             and value["expected_kerby_version"] == "2.1.2" and value["runtime_binding_required"] is True
             and type(value["success"]) is bool and all(value[key] is False for key in JAVA_FALSE), "java_report_invalid")
        for key, expected in (("checks", JAVA_CHECKS), ("cleanup", JAVA_CLEANUP)):
            need(type(value[key]) is dict and set(value[key]) == expected
                 and all(type(x) is bool for x in value[key].values()), "java_report_invalid")
        need(type(value["cache_bytes"]) is int and 0 <= value["cache_bytes"] <= 65536
             and type(value["observed_lifetime_seconds"]) is int and 0 <= value["observed_lifetime_seconds"] <= 120
             and (value["error"] is None or type(value["error"]) is str and value["error"] in JAVA_CODES), "java_report_invalid")
        need(type(value["stage"]) is str and value["stage"] in STAGES, "java_report_invalid")
        oracles = {}
        for key, check in (("wire_hex", "wire_auth_boundary_rejection"), ("rclone_wire_hex", "rclone_auth_boundary_rejection")):
            need(type(value[key]) is str and re.fullmatch(r"(?:[0-9a-f]{2}){0,4100}", value[key]), "java_report_invalid")
            need(not value["checks"][check] or bool(value[key]), "java_report_invalid")
            oracles[key] = parse_wire(bytes.fromhex(value[key])) if value[key] else None
        passed = all(value["checks"].values()) and all(value["cleanup"].values()) and value["error"] is None
        need(type(exit_code) is int and exit_code in (0, 1) and value["success"] is passed
             and exit_code == (0 if passed else 1), "java_report_invalid")
        if passed: need(100 < value["cache_bytes"] <= 65536 and 110 <= value["observed_lifetime_seconds"] <= 120, "java_report_invalid")
        validate_relay(value["relay"], passed)
        validate_acquisitions(value, passed)
        validate_diagnostics(value["diagnostic"], value["remaining_threads"], value["remaining_thread_intervals"],
                             value["remaining_thread_matrix"], value["remaining_timer_kinds"], value["thread_observation_complete"], value["error"], value["cleanup"], passed)
        validate_owned_cleanup(value["owned_thread_cleanup"], value["cleanup"])
        if passed:
            need(value["stage"] == "completed" and value["wire_hex"] == value["rclone_wire_hex"], "java_report_invalid")
        del value["wire_hex"]  # Raw RPC bytes stay private; publish only finite categories.
        del value["rclone_wire_hex"]
        value["wire_oracle"] = oracles["wire_hex"]
        value["rclone_wire_oracle"] = oracles["rclone_wire_hex"]
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


def run(rclone=None, *, loader=load_helpers, downloader=download, runner_factory=None, profile="kerberos-remediation"):
    started = time.monotonic()
    report = dict(schema_version=1, scope="hdfs_kerberos_transfer_container_feasibility", success=False,
        started_utc=datetime.now(timezone.utc).isoformat(), finished_utc=None, duration_seconds=None,
        stage="preflight", candidate_profile=None, inputs=None, result=None, errors=[], cleanup=dict(container_removed=False,
        image_removed=False, context_removed=False, raw_evidence_removed=False),
        cleanup_excludes=["shared_base_image", "shared_build_cache"], **FALSE_CLAIMS)
    root = context = root_id = context_id = docker = D = None
    source_hashes = {}; image = container = None; built_attempted = created_attempted = False
    run_id = uuid.uuid4().hex; tag = name = "kerberos-transfer-" + run_id
    old_umask = os.umask(0o077)
    try:
        pins = profile_settings(profile)
        report["candidate_profile"] = profile
        hosted_guard()
        D, source_hashes = loader()
        java_path, runtime_path = HERE / "HdfsKerberosTransferProbe.java", pins["runtime"]
        lock_path = pins["lock"]
        java, runtime_raw, lock_raw = read(java_path, 128 * 1024), read(runtime_path, 512 * 1024), read(lock_path, 512 * 1024)
        need(sha(java) == JAVA_SHA, "input_invalid"); rows = runtime_rows(runtime_raw, lock_raw, profile=profile)
        rclone_pins = read(PIN_FILE, 4096).decode("ascii").splitlines()
        need("RCLONE_VERSION=" + RCLONE_VERSION in rclone_pins and "RCLONE_LINUX_EXE_SHA256=" + RCLONE_SHA in rclone_pins, "input_invalid")
        rclone = Path(rclone); binary = read(rclone, 128 * 1024 * 1024)
        need(sha(binary) == RCLONE_SHA, "input_invalid")
        source_hashes[rclone] = RCLONE_SHA; source_hashes[PIN_FILE] = sha(read(PIN_FILE, 4096))
        for path, raw in ((java_path, java), (runtime_path, runtime_raw), (lock_path, lock_raw),
                (Path(__file__).resolve(), read(Path(__file__).resolve(), 512 * 1024))): source_hashes[path] = sha(raw)
        report["inputs"] = dict(candidate_profile=profile, source_sha256={p.name: h for p, h in source_hashes.items()}, jdk_manifest=BASE,
            jdk_config_id=BASE_ID, hadoop_version="3.5.0", kerby_version="2.1.2",
            runtime_jars=142, runtime_bytes=sum(row["size"] for row in rows),
            runtime_file_sha256=pins["runtime_sha256"], runtime_classpath_sha256=pins["order_sha256"],
            lock_sha256=pins["lock_sha256"], rclone_version=RCLONE_VERSION, rclone_sha256=RCLONE_SHA, context_sha256=None, image_id=None, container_id=None)
        need(shutil.disk_usage("/tmp").free >= 512 * 1024**2, "unsafe_path")
        root = Path(tempfile.mkdtemp(prefix="kerberos-transfer-", dir="/tmp")); root_id = directory(root)
        context = root / "context"; context.mkdir(mode=0o700); context_id = directory(context)
        (context / "runtime-classpath.json").write_bytes(runtime_raw)
        (context / lock_path.name).write_bytes(lock_raw)
        report["stage"] = "download"; downloader(context, rows, profile=profile); verify_jars(context, rows)
        (context / "HdfsKerberosTransferProbe.java").write_bytes(java)
        (context / "rclone").write_bytes(binary)
        need(file_hash(context / "rclone") == RCLONE_SHA, "input_changed")
        for filename, data in webapp_resources().items():
            target = context / "resources" / filename; target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            target.write_bytes(data)
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
        report["stage"] = "transfer_probe"
        result = docker.call(["start", "--attach", container], timeout=195, limit=32768, allow_failure=True)
        ended = docker.inspect("container", container); inspect_container(ended, name, image, run_id)
        state = ended.get("State", {})
        need(ended["Id"] == container and state.get("Running") is False and state.get("Status") == "exited"
             and state.get("OOMKilled") is False and type(state.get("ExitCode")) is int
             and state["ExitCode"] == result.code, "container_invalid")
        report["result"] = validate_java(read(result.stdout, 32768), result.code)
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
            for path, expected in source_hashes.items(): need(file_hash(path, 128 * 1024 * 1024 if path == rclone else 512 * 1024) == expected, "input_changed")
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
            need(len(args) == 6, "input_invalid")
            profile = args[5]; pins = profile_settings(profile)
            hosted_guard()
            context = Path(args[1]); need(context.is_absolute() and context.name == "context", "unsafe_path")
            directory(context, (int(args[2]), int(args[3])))
            need(file_hash(Path(__file__).resolve(), 512 * 1024) == args[4], "input_changed")
            rows = runtime_rows(read(context / "runtime-classpath.json", 512 * 1024),
                                read(context / pins["lock"].name, 512 * 1024), profile=profile)
            download_rows(context, rows); return 0
        except BaseException: return 1
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--rclone", type=Path, required=True)
    parser.add_argument("--profile", choices=PROFILES, default="kerberos-remediation")
    parsed = parser.parse_args(args)
    previous = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        hosted_guard(); path = parsed.report
        need(path.is_absolute(), "unsafe_path")
        for parent in path.parents: directory(parent)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            result = run(parsed.rclone, profile=parsed.profile); data = canonical(result) + b"\n"; need(len(data) <= 65536, "report_failed")
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        return 0 if result["success"] else 1
    except BaseException:
        sys.stderr.write("transfer_probe_failed\n"); return 1
    finally: signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    raise SystemExit(main())
