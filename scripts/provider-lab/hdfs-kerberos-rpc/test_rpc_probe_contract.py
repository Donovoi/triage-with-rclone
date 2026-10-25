"""Offline contracts and failure injection; no JVM, Docker, or network calls."""
import copy
from contextlib import ExitStack
from email.message import Message
import importlib.util
import io
import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch, Mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("ticket_fixture_under_test", HERE / "rpc_probe_container.py")
F = importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)


def varint(value):
    result = bytearray()
    while value > 127: result.append((value & 127) | 128); value >>= 7
    result.append(value); return bytes(result)


def wire_fields(overrides=None):
    # Independent literal expected wire values, not supervisor constants.
    fields = {1: 0xffffffff, 2: 2, 3: 9,
        4: b"org.apache.hadoop.security.AccessControlException",
        5: b"SIMPLE authentication is not enabled.  Available:[TOKEN, KERBEROS]",
        6: 15, 7: b"", 8: 1}
    fields.update(overrides or {})
    return fields


def wire(fields=None, suffix=b""):
    fields = wire_fields() if fields is None else fields
    header = b""
    for key, value in fields.items():
        if type(value) is bytes: header += varint(key * 8 + 2) + varint(len(value)) + value
        else: header += varint(key * 8) + varint(value)
    body = varint(len(header)) + header + suffix
    return len(body).to_bytes(4, "big") + body


def projected():
    value = positive(); del value["wire_hex"]; del value["rclone_wire_hex"]
    value["wire_oracle"] = dict(status="FATAL", detail="FATAL_UNAUTHORIZED",
        category="simple_disabled_kerberos_offered", rpc_version=9,
        endpoint="namenode_loopback", bounded_single_response=True)
    value["rclone_wire_oracle"] = value["wire_oracle"].copy()
    return value


def positive():
    # Independent literal wire record, including deliberately narrow evidence label.
    return dict(schema_version=1, scope="hdfs_kerberos_rpc_feasibility", success=True,
        expected_kerby_version="2.1.2", runtime_binding_required=True,
        checks=dict(environment=True, endpoint_settings=True, positive_tgt=True, file_cache_v3=True,
            nonrenewable=True, secure_namenode=True, listing_before=True, rclone_auth_boundary_rejection=True,
            wire_auth_boundary_rejection=True, listing_after=True, source_preserved=True, cache_preserved=True),
        cleanup=dict(children_reaped=True, relay_closed=True, filesystem_closed=True, namenode_stop_returned=True, owner_logged_out=True, kdc_stop_returned=True, threads_terminated=True, listeners_absent=True,
            private_material_removed=True, process_property_restored=True, cleanup_completed=True),
        cache_bytes=400, observed_lifetime_seconds=119, stage="completed", wire_hex=wire().hex(), rclone_wire_hex=wire().hex(),
        relay=dict(before_connections=1, negative_connections=1, after_connections=1, none_headers=1,
                   fatal_responses=1, unexpected_connections=0, bytes_forwarded_unchanged=True), error=None, ledger_eligible=False,
        diagnostic=dict(category="none", origin="none"),
        remaining_threads=dict(probe_task=0, jdk_process_reaper=0, jdk_timer=0, jdk_executor=0,
            hadoop_metrics=0, hadoop_rpc=0, jetty=0, kerby=0, other=0),
        authentication_verified=False, hdfs_authenticated=False, renewal_verified=False,
        daemon_accepted=False, provider_accepted=False, application_accepted=False,
        vendor_accepted=False, vulnerability_audited=False)


def inspected(name, image, run_id):
    return dict(Id="c" * 64, Name="/" + name, Image=image,
        Config=dict(Labels={F.LABEL: run_id}, User="10001:10001", Entrypoint=["/usr/bin/env"],
            Cmd=["-i", "HOME=/work/home", "PATH=/opt/java/openjdk/bin:/usr/bin:/bin",
                 "JAVA_HOME=/opt/java/openjdk", "LANG=C", "LC_ALL=C", "/bin/sh", "/opt/rpc/driver.sh"]),
        HostConfig=dict(NetworkMode="none", ReadonlyRootfs=True, Privileged=False, CapDrop=["ALL"],
            SecurityOpt=["no-new-privileges"], Memory=2147483648, NanoCpus=2000000000,
            PidsLimit=128, Init=True, IpcMode="private", CgroupnsMode="private",
            Tmpfs={"/work": "rw,nosuid,nodev,noexec,size=128m,mode=0700,uid=10001,gid=10001"},
            LogConfig={"Type": "none"}), Mounts=[], State=dict(Status="created", Running=False))


class FakeDocker:
    def __init__(self, root, *, max_calls):
        assert max_calls == 40
        self.root, self.calls, self.built, self.container = root, [], None, None
        self.image = "sha256:" + "b" * 64
        self.java, self.exit_code, self.action = positive(), 0, None

    def call(self, args, **kwargs):
        self.calls.append((list(args), kwargs))
        output = b""
        if args[0] == "info": output = b'{"OSType":"linux","Architecture":"amd64"}'
        elif args[0] == "build":
            self.tag = args[args.index("--tag") + 1]
            self.run_id = args[args.index("--label") + 1].split("=", 1)[1]
            self.built = dict(Id=self.image, RepoTags=[self.tag + ":latest"],
                Config=dict(Labels={F.LABEL: self.run_id}, User="10001:10001"))
        elif args[0] == "create":
            self.container = inspected(args[args.index("--name") + 1], self.image, self.run_id)
        elif args[0] == "start":
            self.container["State"] = dict(Status="exited", Running=False, OOMKilled=False, ExitCode=self.exit_code)
            output = F.canonical(self.java)
            if self.action: self.action(self)
        elif args[:2] == ["container", "rm"]: self.container = None
        elif args[:2] == ["image", "rm"]: self.built = None
        path = self.root / ("result-%02d" % len(self.calls)); path.write_bytes(output)
        return types.SimpleNamespace(stdout=path, code=self.exit_code if args[0] == "start" else 0)

    def inspect(self, kind, reference, allow_missing=False):
        if kind == "image" and reference == F.BASE:
            return dict(Id=F.BASE_ID, Os="linux", Architecture="amd64", Config={})
        return copy.deepcopy(self.built if kind == "image" else self.container)


class TicketTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.stack = ExitStack()
        self.stack.enter_context(patch.object(F.subprocess, "Popen", side_effect=AssertionError("native forbidden")))
        self.stack.enter_context(patch.object(F.urllib.request, "build_opener", side_effect=AssertionError("network forbidden")))

    def tearDown(self):
        try: self.stack.close()
        finally: self.temp.cleanup()

    def rejected(self, value, code=0):
        with self.assertRaisesRegex(F.ProbeError, "^java_report_invalid$"):
            F.validate_java(F.canonical(value), code)

    def test_literal_result_and_failure_are_distinct(self):
        self.assertEqual(F.validate_java(F.canonical(positive()), 0), projected())
        value = positive(); value.update(success=False, error="cleanup_failed")
        value["cleanup"]["threads_terminated"] = False
        self.assertFalse(F.validate_java(F.canonical(value), 1)["success"])
        self.rejected(value, 0)

    def test_closed_result_types_scopes_and_no_coverage_promotion(self):
        for field, bad in (("schema_version", True), ("cache_bytes", True), ("success", 1),
                           ("observed_lifetime_seconds", 119.0), ("authentication_verified", True),
                           ("scope", "provider_acceptance"), ("error", "private diagnostic"),
                           ("expected_kerby_version", "2.0.3"), ("extra", "private")):
            with self.subTest(field=field):
                value = positive(); value[field] = bad; self.rejected(value)
        value = positive(); value["checks"]["wrong_password_denied"] = value["checks"].pop("rclone_auth_boundary_rejection")
        self.rejected(value)
        value = positive(); value["cleanup"]["threads_terminated"] = 1; self.rejected(value)
        self.rejected(positive(), True)

    def test_corrupt_json_and_duplicate_fields_never_pass(self):
        for raw in (b"{}\n{}", b'{"success":true,"success":false}', b'{"value":NaN}', b"x" * 16385, b"\xff"):
            with self.subTest(raw=raw[:20]), self.assertRaises(F.ProbeError): F.validate_java(raw, 0)

    def startup_failure(self):
        value = positive(); value.update(success=False, error="unclassified", stage="namenode_start",
            wire_hex="", rclone_wire_hex="", relay=None, cache_bytes=0, observed_lifetime_seconds=0,
            diagnostic=dict(category="metrics_failure", origin="hadoop_metrics"))
        for key in value["checks"]: value["checks"][key] = key in ("environment", "endpoint_settings")
        value["remaining_threads"]["hadoop_metrics"] = 1
        value["cleanup"].update(threads_terminated=False, private_material_removed=False)
        return value

    def test_finite_startup_diagnostic_and_residual_threads_never_grant_credit(self):
        value = self.startup_failure()
        result = F.validate_java(F.canonical(value), 1)
        self.assertEqual(result["diagnostic"], dict(category="metrics_failure", origin="hadoop_metrics"))
        self.assertEqual(result["remaining_threads"]["hadoop_metrics"], 1)
        self.assertFalse(result["success"])
        for key in ("threads_terminated", "private_material_removed"):
            self.assertIs(result["cleanup"][key], False)
        self.assertTrue(all(result[key] is False for key in F.JAVA_FALSE))
        self.rejected(value, 0)

    def test_diagnostic_schema_rejects_raw_unknown_and_incomplete_values(self):
        for bad in (None, {}, {"category": "metrics_failure"},
                    {"category": "none", "origin": "none"},
                    {"category": "private diagnostic", "origin": "none"},
                    {"category": "metrics_failure", "origin": "org.example.Private.method"},
                    {"category": True, "origin": "none"},
                    {"category": "metrics_failure", "origin": "none", "message": "private"}):
            value = self.startup_failure(); value["diagnostic"] = bad
            with self.subTest(bad=bad): self.rejected(value, 1)
        for field in ("diagnostic", "remaining_threads"):
            value = self.startup_failure(); del value[field]; self.rejected(value, 1)
        for category in F.DIAGNOSTIC_CATEGORIES - {"none"}:
            value = self.startup_failure(); value["diagnostic"]["category"] = category
            self.assertFalse(F.validate_java(F.canonical(value), 1)["success"])
            value = positive(); value["diagnostic"]["category"] = category; self.rejected(value)

    def test_thread_count_vector_is_closed_bounded_and_cannot_clear_cleanup_failure(self):
        for bad in (True, -1, 129, 1.0, "1"):
            value = self.startup_failure(); value["remaining_threads"]["other"] = bad
            with self.subTest(bad=bad): self.rejected(value, 1)
        for bad in ({}, [], {"private_thread_name": 1}):
            value = self.startup_failure(); value["remaining_threads"] = bad; self.rejected(value, 1)
        value = self.startup_failure(); value["remaining_threads"]["other"] = 128; self.rejected(value, 1)
        for category in positive()["remaining_threads"]:
            value = positive(); value["remaining_threads"][category] = 1; self.rejected(value)
        value = positive(); value["remaining_threads"] = None; self.rejected(value)
        value = self.startup_failure(); value["remaining_threads"] = None
        self.assertFalse(F.validate_java(F.canonical(value), 1)["cleanup"]["threads_terminated"])
        value["remaining_threads"] = positive()["remaining_threads"]
        self.assertFalse(F.validate_java(F.canonical(value), 1)["cleanup"]["threads_terminated"])

    def test_result_lifetime_cache_and_success_contradictions(self):
        for field, bad in (("cache_bytes", 100), ("cache_bytes", 65537), ("observed_lifetime_seconds", 109),
                           ("observed_lifetime_seconds", 121), ("success", False)):
            value = positive(); value[field] = bad; self.rejected(value)
        value = positive(); value["cleanup"]["listeners_absent"] = False; self.rejected(value)
        value = positive(); value["checks"]["positive_tgt"] = False; self.rejected(value)

    def test_fixed_real_runtime_selection_is_exact_and_ordered(self):
        runtime = F.RUNTIME.read_bytes()
        lock = (F.DISCOVERY / "artifact-lock-kerberos.json").read_bytes()
        rows = F.runtime_rows(runtime, lock)
        self.assertEqual(len(rows), 142)
        self.assertEqual(sum(x["group"] == "org.apache.kerby" for x in rows), 15)
        modified = json.loads(runtime); modified["entries"].reverse()
        for wrong_runtime, wrong_lock in ((F.canonical(modified), lock), (runtime, lock + b" ")):
            with self.assertRaisesRegex(F.ProbeError, "input_invalid"): F.runtime_rows(wrong_runtime, wrong_lock)

    def test_security_inspection_and_build_have_closed_native_surface(self):
        run_id = "a" * 32; name = "kerberos-rpc-" + run_id; image = "sha256:" + "b" * 64
        value = inspected(name, image, run_id)
        F.inspect_container(value, name, image, run_id)
        for field, bad in (("NetworkMode", "bridge"), ("ReadonlyRootfs", False), ("Privileged", True),
                           ("CapAdd", ["SYS_ADMIN"]), ("Binds", ["/tmp:/work"]), ("PidsLimit", True),
                           ("PortBindings", {"19006/tcp": [{}]}), ("LogConfig", {"Type": "json-file"})):
            altered = copy.deepcopy(value); altered["HostConfig"][field] = bad
            with self.subTest(field=field), self.assertRaises(F.ProbeError): F.inspect_container(altered, name, image, run_id)
        files = F.build_files([dict(sha256="d" * 64)])
        self.assertIn(b"-proc:none -implicit:none", files["Dockerfile"])
        self.assertIn(b"--kill-after=5s 180s", files["driver.sh"])
        self.assertIn(b"-Duser.home=/work/home", files["driver.sh"])

    def fake_run(self, action=None, failure=None):
        here = self.root / "input"; discovery = self.root / "discovery"
        here.mkdir(); discovery.mkdir()
        java = b"inert Java source"
        (here / "HdfsKerberosRpcProbe.java").write_bytes(java)
        (here / "runtime-classpath.json").write_bytes(b"{}")
        binary = here / "rclone"; binary.write_bytes(b"inert rclone")
        pin = here / "rclone-version.env"
        pin.write_text("RCLONE_VERSION=1.75.2\nRCLONE_LINUX_EXE_SHA256=" + F.sha(b"inert rclone") + "\n")
        (discovery / "artifact-lock-kerberos.json").write_bytes(b"{}")
        helper = discovery / "helper.py"; helper.write_bytes(b"# inert helper\n")
        rows = [dict(size=3, sha256=F.sha(b"jar"))]
        made = []
        def loader(): return types.SimpleNamespace(DiscoveryError=F.ProbeError), {helper: F.file_hash(helper)}
        def downloader(context, rows):
            (context / "jars").mkdir(); (context / "jars" / "000.jar").write_bytes(b"jar")
        def factory(root, **kwargs):
            docker = FakeDocker(root, **kwargs); made.append(docker)
            if failure:
                docker.java["checks"]["positive_tgt"] = False
                docker.java.update(success=False, error="positive_ticket_failed",
                    diagnostic=dict(category="assertion", origin="none")); docker.exit_code = 1
            if action: docker.action = lambda d: action(d, helper)
            return docker
        real_mkdtemp = tempfile.mkdtemp
        with patch.multiple(F, HERE=here, DISCOVERY=discovery, JAVA_SHA=F.sha(java), RUNTIME=here / "runtime-classpath.json", PIN_FILE=pin, RCLONE_SHA=F.sha(b"inert rclone")), \
             patch.object(F, "hosted_guard"), patch.object(F, "runtime_rows", return_value=rows), \
             patch.object(F.shutil, "disk_usage", return_value=types.SimpleNamespace(free=1024**3)), \
             patch.object(F.tempfile, "mkdtemp", side_effect=lambda **kw: real_mkdtemp(prefix=kw["prefix"], dir=self.root)):
            report = F.run(binary, loader=loader, downloader=downloader, runner_factory=factory)
        return report, made[0]

    def test_full_mock_success_binds_context_and_cleans(self):
        report, docker = self.fake_run()
        self.assertTrue(report["success"], report["errors"])
        self.assertTrue(all(report["cleanup"].values()))
        self.assertFalse(docker.root.exists())
        self.assertEqual(report["result"], projected())
        self.assertTrue(all(report[key] is False for key in F.FALSE_CLAIMS))
        self.assertEqual(report["cleanup_excludes"], ["shared_base_image", "shared_build_cache"])
        build = next(args for args, _ in docker.calls if args[0] == "build")
        self.assertEqual(build[1:4], ["--network", "none", "--pull=false"])
        start = next(options for args, options in docker.calls if args[0] == "start")
        self.assertEqual(start, dict(timeout=195, limit=32768, allow_failure=True))

    def test_failed_java_result_stays_failed_after_clean_removal(self):
        report, _ = self.fake_run(failure=True)
        self.assertFalse(report["success"])
        self.assertEqual(report["errors"], ["java_probe_failed"])
        self.assertTrue(all(report["cleanup"].values()))

    def test_late_source_mutation_cannot_promote_success(self):
        report, _ = self.fake_run(action=lambda d, source: source.write_bytes(b"# changed\n"))
        self.assertFalse(report["success"])
        self.assertIn("input_changed", report["errors"])

    def test_foreign_container_is_never_removed_and_raw_is_preserved(self):
        def change(docker, source): docker.container["Config"]["Labels"] = {F.LABEL: "foreign"}
        report, docker = self.fake_run(action=change)
        self.assertFalse(report["success"])
        self.assertFalse(report["cleanup"]["container_removed"])
        self.assertFalse(report["cleanup"]["raw_evidence_removed"])
        self.assertTrue(docker.root.is_dir())
        self.assertFalse(any(args[:2] == ["container", "rm"] for args, _ in docker.calls))

    def test_uncertain_command_reap_preserves_raw_even_if_resources_removed(self):
        def fail(docker, source): raise F.ProbeError("command_cleanup_failed")
        report, docker = self.fake_run(action=fail)
        self.assertFalse(report["success"])
        self.assertIn("command_cleanup_failed", report["errors"])
        self.assertTrue(docker.root.is_dir())
        self.assertTrue(report["cleanup"]["container_removed"])
        self.assertFalse(report["cleanup"]["context_removed"])

    def test_hosted_guard_precedes_helper_loading_and_writes(self):
        loader = Mock(side_effect=AssertionError("must not load"))
        with patch.object(F, "hosted_guard", side_effect=F.ProbeError("hosted_linux_required")):
            result = F.run(loader=loader)
        loader.assert_not_called()
        self.assertFalse(result["success"])
        self.assertEqual(result["inputs"], None)

    def test_downloader_child_envelope_and_successful_reap_are_bounded(self):
        context = self.root / "context"; context.mkdir()
        proc = Mock(pid=456); proc.wait.return_value = 0; proc.poll.return_value = 0
        with patch.object(F.subprocess, "Popen", return_value=proc) as launch, \
             patch.object(F, "verify_jars") as verify, patch.dict(F.os.environ, {"HTTP_PROXY": "private", "JAVA_TOOL_OPTIONS": "private"}):
            F.download(context, [])
        args, kwargs = launch.call_args
        self.assertEqual(args[0][1:4], ["-I", "-S", "-B"])
        self.assertEqual(args[0][5], "--download-worker")
        self.assertTrue(kwargs["start_new_session"])
        self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
        self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
        self.assertNotIn("HTTP_PROXY", kwargs["env"])
        self.assertNotIn("JAVA_TOOL_OPTIONS", kwargs["env"])
        self.assertEqual([c.kwargs["timeout"] for c in proc.wait.call_args_list], [300, 3])
        verify.assert_called_once_with(context, [])

    def test_downloader_timeout_kills_only_owned_group_and_reaps(self):
        context = self.root / "context"; context.mkdir()
        proc = Mock(pid=456); proc.wait.side_effect = [subprocess.TimeoutExpired("synthetic", 300), 0]; proc.poll.return_value = None
        with patch.object(F.subprocess, "Popen", return_value=proc), \
             patch.object(F.os, "getpgid", return_value=456, create=True), \
             patch.object(F.os, "killpg", create=True) as kill, patch.object(F.signal, "SIGKILL", 9, create=True):
            with self.assertRaisesRegex(F.ProbeError, "^download_failed$"): F.download(context, [])
        kill.assert_called_once_with(456, 9)
        self.assertEqual(proc.wait.call_args.kwargs["timeout"], 3)

    def test_downloader_uncertain_identity_or_reap_is_sticky(self):
        context = self.root / "context"; context.mkdir()
        for foreign in (True, False):
            proc = Mock(pid=456); proc.wait.side_effect = subprocess.TimeoutExpired("synthetic", 300); proc.poll.return_value = None
            with self.subTest(foreign=foreign), patch.object(F.subprocess, "Popen", return_value=proc), \
                 patch.object(F.os, "getpgid", return_value=123 if foreign else 456, create=True), \
                 patch.object(F.os, "killpg", create=True) as kill, patch.object(F.signal, "SIGKILL", 9, create=True):
                with self.assertRaisesRegex(F.ProbeError, "^download_cleanup_failed$"): F.download(context, [])
                self.assertEqual(kill.call_count, 0 if foreign else 1)

    def test_transport_content_and_redirect_fail_closed_without_retry(self):
        class Response(io.BytesIO):
            status = 200
            url = "https://repo.maven.apache.org/maven2/synthetic/bytes/1/bytes-1.jar"
            def __init__(self, body, length):
                super().__init__(body); self.headers = Message(); self.headers["Content-Length"] = length
        row = dict(group="synthetic", artifact="bytes", version="1", classifier="", type="jar", size=3, sha256=F.sha(b"jar"))
        for index, (body, length) in enumerate(((b"jar", "3"), (b"bad", "3"), (b"jars", "3"), (b"jar", "4"))):
            context = self.root / str(index); context.mkdir()
            opener = Mock(); opener.open.return_value = Response(body, length)
            if index == 0: F.download_rows(context, [row], opener=opener)
            else:
                with self.assertRaises(F.ProbeError): F.download_rows(context, [row], opener=opener)
            opener.open.assert_called_once()
        with self.assertRaises(F.ProbeError): F.NoRedirect().redirect_request(None, None, None, None, None, None)

    def test_helper_loading_is_exact_source_and_restores_imports(self):
        originals = {name: sys.modules.get(name) for name in F.HELPERS}
        old = object(); sys.modules["graph_export"] = old
        try:
            with patch.object(F.subprocess, "Popen", side_effect=AssertionError("native forbidden")):
                module, bindings = F.load_helpers()
            self.assertTrue(callable(module.Docker))
            self.assertEqual(len(bindings), 4)
            self.assertIs(sys.modules["graph_export"], old)
            self.assertEqual({p.stem for p in bindings}, set(F.HELPERS))
            for path, digest in bindings.items(): self.assertEqual(F.sha(path.read_bytes()), digest)
        finally:
            for name, value in originals.items():
                if value is None: sys.modules.pop(name, None)
                else: sys.modules[name] = value



class WireTests(unittest.TestCase):
    def rejected(self, raw):
        with self.assertRaisesRegex(F.ProbeError, "wire_invalid"): F.parse_wire(raw)

    def test_exact_single_auth_boundary_and_alignment(self):
        self.assertEqual(F.parse_wire(wire()), projected()["wire_oracle"])
        self.assertEqual(F.parse_wire(wire(wire_fields({9: 23}))), projected()["wire_oracle"])

    def test_transport_size_negative_zero_oversize_truncation_and_extra(self):
        raw = wire()
        for bad in (b"", b"\xff" * 4, b"\x00" * 4, (4097).to_bytes(4, "big") + b"x" * 4097,
                    raw[:-1], raw + b"\x00", wire(suffix=b"\x00"), raw[:4] + b"\x80" * 10):
            self.rejected(bad)

    def test_wrong_status_detail_version_class_or_message_never_auth(self):
        for field, bad in ((1, 0), (2, 1), (3, 8), (4, b"java.io.IOException"), (6, 1),
            (5, b"Permission denied: user=reader, access=READ_EXECUTE"),
            (5, b"SIMPLE authentication is not enabled.  Available:[SIMPLE, KERBEROS]"),
            (5, b"SIMPLE authentication is not enabled.  Available:[TOKEN]"),
            (5, b"SIMPLE authentication is not enabled.  Available:[TOKEN, KERBEROS] extra"),
            (7, b"private"), (8, 0), (9, 1 << 63)):
            with self.subTest(field=field, bad=bad): self.rejected(wire(wire_fields({field: bad})))

    def test_missing_duplicate_unknown_and_malformed_fields(self):
        fields = wire_fields(); del fields[3]; self.rejected(wire(fields))
        self.rejected(wire(wire_fields({10: b"extension"})))
        original = wire(); body = original[4:]
        # The first header length is a two-byte varint for this independent literal.
        offset = 0
        while body[offset] & 128: offset += 1
        header = body[offset + 1:]
        duplicate = header + b"\x10\x02"
        framed = varint(len(duplicate)) + duplicate
        self.rejected(len(framed).to_bytes(4, "big") + framed)
        for bad_header in (b"\x08\x80", b"\x0f\x00", b"\x08\x80\x00", b"\x22\xff\x7f"):
            framed = varint(len(bad_header)) + bad_header
            self.rejected(len(framed).to_bytes(4, "big") + framed)

    def test_no_control_or_cleanup_may_be_omitted_or_false(self):
        for group in ("checks", "cleanup"):
            for key in positive()[group]:
                for mutation in ("missing", "false", "extra"):
                    value = positive()
                    if mutation == "missing": del value[group][key]
                    elif mutation == "false": value[group][key] = False
                    else: value[group]["extra"] = True
                    with self.subTest(group=group, key=key, mutation=mutation), self.assertRaises(F.ProbeError):
                        F.validate_java(F.canonical(value), 0)

    def test_false_or_substituted_oracle_cannot_promote(self):
        for field, bad in (("wire_hex", wire(wire_fields({5: b"Permission denied"})).hex()),
                           ("wire_hex", ""), ("wire_hex", "zz"), ("stage", "reader_tgt")):
            value = positive(); value[field] = bad
            with self.assertRaises(F.ProbeError): F.validate_java(F.canonical(value), 0)

    def test_actual_rclone_capture_is_required_and_cannot_be_replaced_by_direct_oracle(self):
        for raw in ("", wire(wire_fields({2: 1})).hex(), wire(wire_fields({9: 77})).hex()):
            value = positive(); value["rclone_wire_hex"] = raw
            with self.assertRaises(F.ProbeError): F.validate_java(F.canonical(value), 0)

    def test_relay_rejects_missing_phase_misattribution_extra_connections_and_capture_loss(self):
        mutations = (("before_connections", 0), ("after_connections", 0), ("negative_connections", 0),
            ("negative_connections", 5), ("negative_connections", True), ("negative_connections", 2),
            ("none_headers", 0), ("none_headers", 2), ("fatal_responses", 0),
            ("unexpected_connections", 1), ("unexpected_connections", 2), ("bytes_forwarded_unchanged", False))
        for key, bad in mutations:
            value = positive(); value["relay"][key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(F.ProbeError):
                F.validate_java(F.canonical(value), 0)
        for bad in (None, {}, dict(positive()["relay"], extra=1)):
            value = positive(); value["relay"] = bad
            with self.assertRaises(F.ProbeError): F.validate_java(F.canonical(value), 0)

    def test_partial_failed_relay_preserves_finite_diagnostics_without_credit(self):
        value = positive(); value.update(success=False, error="relay_invalid", stage="rclone_none")
        value["diagnostic"] = dict(category="assertion", origin="none")
        value["checks"]["listing_after"] = False
        value["relay"]["unexpected_connections"] = 1
        value["relay"]["bytes_forwarded_unchanged"] = False
        result = F.validate_java(F.canonical(value), 1)
        self.assertFalse(result["success"])
        self.assertNotIn("wire_hex", result); self.assertNotIn("rclone_wire_hex", result)


class JavaSourceTests(unittest.TestCase):
    def test_throwable_projection_preserves_causes_without_exporting_messages(self):
        source = (HERE / "HdfsKerberosRpcProbe.java").read_text()
        self.assertIn('Failure(Code value, Throwable cause) { super(value.name(), cause); code = value; }', source)
        self.assertIn('throw new Failure(Code.unclassified, cause);', source)
        body = source[source.index('    private static String originFrame('):
                      source.index('    private static String threadCategory(')]
        self.assertIn('depth < 8 && seen.add(failure)', body)
        self.assertIn('new java.util.IdentityHashMap<>()', body)
        self.assertIn('i < frames.length && i < 32', body)
        for forbidden in ('getMessage(', 'getLocalizedMessage(', 'toString(', 'printStackTrace(', 'System.out', 'System.err'):
            self.assertNotIn(forbidden, body)
        for marker in ('"missing_class"', '"metrics_failure"', '"namenode_http"', '"http_authentication"'):
            self.assertIn(marker, body)

    def test_thread_projection_counts_all_residuals_and_keeps_cleanup_gate(self):
        source = (HERE / "HdfsKerberosRpcProbe.java").read_text()
        body = source[source.index('    private static String threadCategory('):
                      source.index('    private static String boolMap(')]
        self.assertIn('i < frames.length && i < 32', body)
        self.assertIn('if (!thread.isAlive() || baseline.contains(thread.getId())) continue;', body)
        self.assertEqual(body.count('continue;'), 1)
        self.assertIn('need(++total <= 128, Code.cleanup_failed)', body)
        self.assertIn('remainingThreads.values().stream().allMatch(count -> count == 0)', body)
        self.assertIn('&& TASKS.stream().noneMatch(Thread::isAlive)', body)
        self.assertIn('rootOwned && stopped && threadsClean && noListeners', body)
        self.assertNotIn('getName(', body)
        self.assertNotIn('printStackTrace(', body)

    def test_secure_namenode_requires_block_tokens_without_datanode(self):
        source = (HERE / "HdfsKerberosRpcProbe.java").read_text()
        body = source[source.index('    private static Configuration configuration('):
                      source.index('    private static void topology()')]
        pairs = re.findall(r'conf\.set\("([^"\n]+)", "([^"\n]*)"\);', body)
        settings = dict(pairs)
        self.assertEqual(len(settings), len(pairs), 'duplicate configuration keys')
        self.assertEqual(settings['hadoop.security.authentication'], 'kerberos')
        self.assertEqual(settings['dfs.block.access.token.enable'], 'true')
        self.assertEqual(settings['ipc.client.fallback-to-simple-auth-allowed'], 'false')
        self.assertNotIn('DataNode.createDataNode', source)

    def test_version_child_uses_explicit_private_home_and_null_config(self):
        source = (HERE / "HdfsKerberosRpcProbe.java").read_text()
        start = source.index('            stage = "rclone_version";')
        end = source.index('            baseline = threadIds();', start)
        version = source[start:end]
        self.assertIn('List.of("/opt/rpc/rclone", "version", "--config", "/dev/null", "--log-level", "ERROR")', version)
        self.assertIn('Map.of("HOME", "/work/home", "PATH", "/usr/bin:/bin", "LANG", "C", "LC_ALL", "C")', version)
        self.assertNotIn('KRB5_', version)
        for predicate, code in (
            ('version.code == 0', 'rclone_version_nonzero'),
            ('version.err.length == 0', 'rclone_version_stderr'),
            ('startsWith("rclone v1.75.2\\n")', 'rclone_version_mismatch'),
            ('processIds().equals(processBaseline)', 'child_process_drift')):
            self.assertIn(predicate, version); self.assertIn('Code.' + code, version)
        self.assertIn('builder.environment().clear()', source)

    def test_finite_version_and_child_failures_remain_failures(self):
        for code in ('rclone_version_nonzero', 'rclone_version_stderr', 'rclone_version_mismatch',
                     'child_descendant_found', 'child_reap_failed', 'child_streams_alive', 'child_process_drift'):
            value = positive(); value.update(success=False, error=code, stage='rclone_version')
            value['diagnostic'] = dict(category='assertion', origin='none')
            for key in value['checks']:
                value['checks'][key] = key == 'environment'
            value.update(wire_hex='', rclone_wire_hex='', relay=None, cache_bytes=0, observed_lifetime_seconds=0)
            value['cleanup']['threads_terminated'] = False
            result = F.validate_java(F.canonical(value), 1)
            self.assertFalse(result['success']); self.assertEqual(result['error'], code)
            self.assertFalse(result['cleanup']['threads_terminated'])
            self.assertTrue(all(result[key] is False for key in F.JAVA_FALSE))
            with self.assertRaises(F.ProbeError): F.validate_java(F.canonical(value), 0)

    def test_java_source_pin_and_fixed_runtime(self):
        raw = (HERE / "HdfsKerberosRpcProbe.java").read_bytes()
        self.assertEqual(F.sha(raw), F.JAVA_SHA)
        self.assertNotIn(b"MiniDFSCluster", raw)
        self.assertNotIn(b"DataNode.createDataNode", raw)
        self.assertNotIn(b"ignore.secure.ports.for.testing", raw)
        self.assertIn(b'"hadoop.security.authentication", "kerberos"', raw)
        self.assertIn(b'"ipc.client.fallback-to-simple-auth-allowed", "false"', raw)

    def test_same_reader_fixed_endpoint_and_no_inherited_environment(self):
        source = (HERE / "HdfsKerberosRpcProbe.java").read_text()
        self.assertIn('builder.environment().clear()', source)
        self.assertIn('"--hdfs-username", reader', source)
        positive_block = source[source.index('        if (authenticated) {'):source.index('        return child(command, env);')]
        self.assertIn('"KRB5CCNAME", "FILE:" + CACHE', positive_block)
        self.assertIn('"--hdfs-service-principal-name", "hdfs/127.0.0.1"', positive_block)
        self.assertIn('"--hdfs-data-transfer-protection", "privacy"', positive_block)
        order = [source.index('stage = "' + stage + '";') for stage in
                 ('listing_before', 'rclone_none', 'wire_none', 'listing_after', 'preservation')]
        self.assertEqual(order, sorted(order))
        self.assertIn('socket.getOutputStream().write(new byte[]{\'h\',\'r\',\'p\',\'c\',9,0,0})', source)
        self.assertIn('length > 0 && length <= 4096', source)
        self.assertIn('frame.available() == 0', source)
        self.assertIn('input.read() == -1', source)

    def test_private_cleanup_never_precedes_service_shutdown(self):
        source = (HERE / "HdfsKerberosRpcProbe.java").read_text()
        final = source[source.index('        finally {\n            if (serialized'):]
        self.assertLess(final.index('stopServices();'), final.index('cleanup(server, baseline)'))
        self.assertIn('entry.getValue().verify(entry.getKey()); Files.delete(entry.getKey())', source)
        self.assertIn('"children_reaped", "relay_closed", "filesystem_closed", "namenode_stop_returned", "owner_logged_out"', source)
        self.assertIn('controlDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60)', source)

    def test_relay_has_one_fixed_endpoint_bounded_unchanged_forwarding_and_owned_shutdown(self):
        source = (HERE / "HdfsKerberosRpcProbe.java").read_text()
        self.assertIn('"--hdfs-namenode", "127.0.0.1:19007"', source)
        self.assertIn('new byte[]{127,0,0,1}), 19007), 4)', source)
        self.assertIn('counts[ownedPhase] >= 4', source)
        self.assertIn('total <= 131072', source)
        self.assertIn('incoming.getOutputStream().write(response)', source)
        self.assertIn('upstream.getOutputStream().write(header)', source)
        self.assertIn('need(phase == ownedPhase', source)
        self.assertIn('relay.noneHeaders == relay.counts[1]', source)
        self.assertIn('relay.fatalResponses == relay.counts[1]', source)
        self.assertIn('listener.isClosed() && sockets.stream().allMatch(Socket::isClosed)', source)
        self.assertIn('Arrays.fill(buffer, (byte)0)', source)


if __name__ == "__main__":
    unittest.main()
