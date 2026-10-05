"""Offline contracts and failure injection; no JVM, Docker, or network calls."""
import copy
from contextlib import ExitStack
from email.message import Message
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch, Mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("ticket_fixture_under_test", HERE / "ticket_probe_container.py")
F = importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)


def positive():
    # Independent literal wire record, including deliberately narrow evidence label.
    return dict(schema_version=1, scope="kerby_ticket_feasibility", success=True,
        expected_kerby_version="2.1.2", runtime_binding_required=True,
        checks=dict(environment=True, endpoint_settings=True, positive_tgt=True, file_cache_v3=True,
            nonrenewable=True, client_request_failed_with_integrity_error=True,
            wrong_principal_denied=True, cache_preserved=True),
        cleanup=dict(kdc_stop_returned=True, threads_terminated=True, listeners_absent=True,
            private_material_removed=True, process_property_restored=True, cleanup_completed=True),
        cache_bytes=400, observed_lifetime_seconds=119, error=None, ledger_eligible=False,
        authentication_verified=False, hdfs_authenticated=False, renewal_verified=False,
        daemon_accepted=False, provider_accepted=False, application_accepted=False,
        vendor_accepted=False, vulnerability_audited=False)


def inspected(name, image, run_id):
    return dict(Id="c" * 64, Name="/" + name, Image=image,
        Config=dict(Labels={F.LABEL: run_id}, User="10001:10001", Entrypoint=["/usr/bin/env"],
            Cmd=["-i", "HOME=/work/home", "PATH=/opt/java/openjdk/bin:/usr/bin:/bin",
                 "JAVA_HOME=/opt/java/openjdk", "LANG=C", "LC_ALL=C", "/bin/sh", "/opt/ticket/driver.sh"]),
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
        self.assertEqual(F.validate_java(F.canonical(positive()), 0), positive())
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
        value = positive(); value["checks"]["wrong_password_denied"] = value["checks"].pop("client_request_failed_with_integrity_error")
        self.rejected(value)
        value = positive(); value["cleanup"]["threads_terminated"] = 1; self.rejected(value)
        self.rejected(positive(), True)

    def test_corrupt_json_and_duplicate_fields_never_pass(self):
        for raw in (b"{}\n{}", b'{"success":true,"success":false}', b'{"value":NaN}', b"x" * 16385, b"\xff"):
            with self.subTest(raw=raw[:20]), self.assertRaises(F.ProbeError): F.validate_java(raw, 0)

    def test_result_lifetime_cache_and_success_contradictions(self):
        for field, bad in (("cache_bytes", 100), ("cache_bytes", 65537), ("observed_lifetime_seconds", 109),
                           ("observed_lifetime_seconds", 121), ("success", False)):
            value = positive(); value[field] = bad; self.rejected(value)
        value = positive(); value["cleanup"]["listeners_absent"] = False; self.rejected(value)
        value = positive(); value["checks"]["positive_tgt"] = False; self.rejected(value)

    def test_fixed_real_runtime_selection_is_exact_and_ordered(self):
        runtime = (HERE / "runtime-classpath.json").read_bytes()
        lock = (F.DISCOVERY / "artifact-lock-kerberos.json").read_bytes()
        rows = F.runtime_rows(runtime, lock)
        self.assertEqual(len(rows), 142)
        self.assertEqual(sum(x["group"] == "org.apache.kerby" for x in rows), 15)
        modified = json.loads(runtime); modified["entries"].reverse()
        for wrong_runtime, wrong_lock in ((F.canonical(modified), lock), (runtime, lock + b" ")):
            with self.assertRaisesRegex(F.ProbeError, "input_invalid"): F.runtime_rows(wrong_runtime, wrong_lock)

    def test_security_inspection_and_build_have_closed_native_surface(self):
        run_id = "a" * 32; name = "kerberos-ticket-" + run_id; image = "sha256:" + "b" * 64
        value = inspected(name, image, run_id)
        F.inspect_container(value, name, image, run_id)
        for field, bad in (("NetworkMode", "bridge"), ("ReadonlyRootfs", False), ("Privileged", True),
                           ("CapAdd", ["SYS_ADMIN"]), ("Binds", ["/tmp:/work"]), ("PidsLimit", True),
                           ("PortBindings", {"19006/tcp": [{}]}), ("LogConfig", {"Type": "json-file"})):
            altered = copy.deepcopy(value); altered["HostConfig"][field] = bad
            with self.subTest(field=field), self.assertRaises(F.ProbeError): F.inspect_container(altered, name, image, run_id)
        files = F.build_files([dict(sha256="d" * 64)])
        self.assertIn(b"-proc:none -implicit:none", files["Dockerfile"])
        self.assertIn(b"--kill-after=5s 60s", files["driver.sh"])
        self.assertIn(b"-Duser.home=/work/home", files["driver.sh"])

    def fake_run(self, action=None, failure=None):
        here = self.root / "input"; discovery = self.root / "discovery"
        here.mkdir(); discovery.mkdir()
        java = b"inert Java source"
        (here / "KerberosTicketProbe.java").write_bytes(java)
        (here / "runtime-classpath.json").write_bytes(b"{}")
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
                docker.java.update(success=False, error="positive_ticket_failed"); docker.exit_code = 1
            if action: docker.action = lambda d: action(d, helper)
            return docker
        real_mkdtemp = tempfile.mkdtemp
        with patch.multiple(F, HERE=here, DISCOVERY=discovery, JAVA_SHA=F.sha(java)), \
             patch.object(F, "hosted_guard"), patch.object(F, "runtime_rows", return_value=rows), \
             patch.object(F.shutil, "disk_usage", return_value=types.SimpleNamespace(free=1024**3)), \
             patch.object(F.tempfile, "mkdtemp", side_effect=lambda **kw: real_mkdtemp(prefix=kw["prefix"], dir=self.root)):
            report = F.run(loader=loader, downloader=downloader, runner_factory=factory)
        return report, made[0]

    def test_full_mock_success_binds_context_and_cleans(self):
        report, docker = self.fake_run()
        self.assertTrue(report["success"], report["errors"])
        self.assertTrue(all(report["cleanup"].values()))
        self.assertFalse(docker.root.exists())
        self.assertEqual(report["result"], positive())
        self.assertTrue(all(report[key] is False for key in F.FALSE_CLAIMS))
        self.assertEqual(report["cleanup_excludes"], ["shared_base_image", "shared_build_cache"])
        build = next(args for args, _ in docker.calls if args[0] == "build")
        self.assertEqual(build[1:4], ["--network", "none", "--pull=false"])
        start = next(options for args, options in docker.calls if args[0] == "start")
        self.assertEqual(start, dict(timeout=75, limit=16384, allow_failure=True))

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


if __name__ == "__main__":
    unittest.main()
