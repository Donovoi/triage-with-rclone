"""Data-only and mocked lifecycle checks; never launch Java, rclone or Docker."""
from contextlib import ExitStack
import copy
import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
import container_fixture as F

RUN = "1" * 32
IMAGE = "sha256:" + "2" * 64
CONTAINER = "3" * 64


def oracle(phase="ready"):
    return dict(schema_version=1, scope="hdfs_simple_fixture", phase=phase, ledger_eligible=False,
        authentication_verified=False, authentication_mode="SIMPLE", success=True, source_preserved=True,
        configuration_preserved=True, api_shutdown_complete=phase == "final", owner="fixture-owner",
        root="/synthetic", mtime_ms=1704067200000, ports=copy.deepcopy(F.PORTS), files=F.expected_files(),
        configuration_sha256="a" * 64, errors=[])


def record(running=False):
    args = F.command_args("hdfs-fixture-" + RUN, IMAGE, RUN)
    return dict(Name="/hdfs-fixture-" + RUN, Image=IMAGE, Id=CONTAINER,
        Config=dict(Labels={F.LABEL: RUN}, User="10001:10001", Entrypoint=["/usr/bin/env"],
                    Cmd=args[args.index(IMAGE)+1:]),
        HostConfig=dict(NetworkMode="none", ReadonlyRootfs=True, Privileged=False, CapDrop=["ALL"],
            SecurityOpt=["no-new-privileges"], Memory=4*1024**3, NanoCpus=2*10**9, PidsLimit=128,
            Init=True, IpcMode="private", CgroupnsMode="private", LogConfig={"Type": "none"},
            Tmpfs={"/work": "rw,nosuid,nodev,noexec,size=2g,mode=0700,uid=10001,gid=10001"}),
        Mounts=[], State=dict(Running=running, Status="running" if running else "exited",
                              ExitCode=0, OOMKilled=False))


class FakeDocker:
    def __init__(self, root, *, max_calls, failure=None):
        self.root, self.calls, self.max_calls, self.failure = root, [], max_calls, failure
        self.built = self.created = self.started = self.probed = False
    def call(self, args, **kwargs):
        self.calls.append(args)
        code, data = 0, b""
        if args[0] == "info": data = b'{"OSType":"linux","Architecture":"amd64"}'
        if args[0] == "build":
            self.built = True
            if self.failure == "build": raise F.D.DiscoveryError("command_failed")
        if args[0] == "create": self.created = True
        if args[0] == "start": self.started = True
        if args[:2] == ["container", "rm"]: self.created = False
        if args[:2] == ["image", "rm"]: self.built = False
        out, err = self.root / (str(len(self.calls)) + ".out"), self.root / (str(len(self.calls)) + ".err")
        out.write_bytes(data); err.write_bytes(b"PRIVATE_SYNTHETIC_CANARY")
        return F.D.Result(code, out, err)
    def inspect(self, kind, reference, allow_missing=False):
        if reference == F.BASE:
            return dict(Id=F.BASE_ID, Os="linux", Architecture="amd64")
        if kind == "image":
            if not self.built: return None
            return dict(Id=IMAGE, RepoTags=["hdfs-fixture-" + RUN + ":latest"],
                        Config=dict(Labels={F.LABEL: RUN}, User="10001:10001"))
        if not self.created: return None
        value = record(self.started and not self.probed)
        if not self.started: value["State"]["Status"] = "created"
        if self.failure == "foreign" and self.probed: value["Config"]["Labels"][F.LABEL] = "9" * 32
        return value


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.stack.enter_context(patch.object(F.D.subprocess, "Popen", side_effect=AssertionError("native forbidden")))

    def test_runtime_lock_keeps_exact_reviewed_order(self):
        rows = F.runtime_rows()
        self.assertEqual(len(rows), 128)
        self.assertEqual(F.digest(F.canonical(rows)), F.CLASSPATH_HASH)

    def test_bad_runtime_lock_hash_fails(self):
        with patch.object(F.D, "file_hash", return_value="0"*64):
            with self.assertRaisesRegex(F.FixtureError, "runtime_lock_invalid"): F.runtime_rows()

    def test_runtime_pin_is_closed_and_accepts_a_future_reviewed_release(self):
        pin = "RCLONE_VERSION=1.75.1\n" + "".join(
            key + "=" + "a"*64 + "\n" for key in ("RCLONE_EXE_SHA256", "RCLONE_WINDOWS_ZIP_SHA256",
                "RCLONE_LINUX_ZIP_SHA256", "RCLONE_LINUX_EXE_SHA256"))
        path = self.root/"runtime.env"
        path.write_text(pin.replace("RCLONE_VERSION=1.75.1", "RCLONE_VERSION=1.76.0"),encoding="ascii")
        self.assertEqual(F.runtime_pin(path)[0], "1.76.0")
        for changed in (pin + "\nRCLONE_VERSION=1.75.1\n", pin + "\nOTHER=value\n",
                        pin.replace("RCLONE_VERSION=1.75.1", "RCLONE_VERSION=1.75.1;command"),
                        pin.replace("a"*64, "NOT_A_HASH")):
            path.write_text(changed,encoding="ascii")
            with self.assertRaises(F.FixtureError): F.runtime_pin(path)

    def test_changed_pin_after_import_fails_before_download_or_native(self):
        with patch.object(F.D,"hosted_guard"), patch.object(F,"runtime_pin",return_value=("1.76.0","0"*64)):
            result=F.run(self.root/"absent",runner_factory=lambda *a,**k:self.fail("native"),
                         downloader=lambda *a:self.fail("download"))
        self.assertEqual(result["errors"], ["input_changed"])
        self.assertFalse(result["success"])

    def test_listing_requires_exact_instant_including_submicrosecond_precision(self):
        listing = [dict(Path=p, Size=len(b), IsDir=False, ModTime="2024-01-01T00:00:00Z")
                   for p,b in F.samples().items()]
        for value in ("2024-01-01T00:00:00Z", "2024-01-01T00:00:00.000000000Z",
                      "2024-01-01T01:00:00+01:00"):
            for row in listing: row["ModTime"] = value
            F.validate_listing(listing)
        for value in ("2024-01-01T00:00:00", "2024-01-01T00:00:00.000000001Z",
                      "2024-01-01T00:00:00.0000000001Z", "2024-01-01 00:00:00Z",
                      "2024-01-01T00:00:01Z"):
            for row in listing: row["ModTime"] = value
            with self.assertRaises(F.FixtureError): F.validate_listing(listing)

    def test_literal_samples_cover_empty_binary_utf8_and_cancellation(self):
        files = F.samples()
        self.assertEqual(len(files), 8)
        self.assertEqual(files["empty.bin"], b"")
        self.assertEqual(files["unicode/utf8.txt"].decode("utf-8"), "caf\u00e9\n")
        self.assertEqual(len(files["large/cancel.bin"]), 2*1024**2)
        self.assertEqual(files["nested/deeper/data.bin"], bytes(range(256)))

    def test_oracle_must_match_independent_inventory_and_strict_types(self):
        F.validate_oracle(oracle(), "ready")
        for key, value in (("schema_version", True), ("authentication_verified", True),
                           ("source_preserved", False), ("api_shutdown_complete", True),
                           ("configuration_sha256", None), ("errors", ["PRIVATE_SYNTHETIC_CANARY"])):
            changed = oracle(); changed[key] = value
            with self.subTest(key=key), self.assertRaises(F.FixtureError):
                F.validate_oracle(changed, "ready")
        for field, value in (("path", "../escape"), ("size", True), ("sha256", "0"*64), ("mode", "0777")):
            changed = oracle(); changed["files"][0][field] = value
            with self.subTest(field=field), self.assertRaises(F.FixtureError):
                F.validate_oracle(changed, "ready")

    def test_final_requires_same_config_and_shutdown(self):
        F.validate_oracle(oracle("final"), "final", oracle())
        final = oracle("final"); final["configuration_sha256"] = "b"*64
        with self.assertRaises(F.FixtureError): F.validate_oracle(final, "final", oracle())

    def test_public_oracle_rejects_extra_fields(self):
        value = oracle(); value["raw_log"] = "PRIVATE_SYNTHETIC_CANARY"
        with self.assertRaises(F.FixtureError): F.validate_oracle(value, "ready")

    def test_listener_parser_rejects_wildcard_ipv6_alias_and_duplicates(self):
        row = b"0: 0100007F:4A38 00000000:0000 0A 0 0 0 0 0 0\n"
        self.assertEqual(F.listener_ports(row), [19000])
        for bad in (row.replace(b"0100007F", b"00000000"), row.replace(b"0100007F", b"00000000000000000000000000000000"),
                    row + row, b"malformed"):
            with self.assertRaises(F.FixtureError): F.listener_ports(bad)

    def test_containment_inspection_rejects_each_unsafe_change(self):
        F.inspect_container(record(), "hdfs-fixture-"+RUN, IMAGE, RUN)
        changes = {"NetworkMode":"bridge", "Privileged":True, "ReadonlyRootfs":False,
                   "Binds":["/host:/work"], "PortBindings":{"19000/tcp":[{"HostPort":"19000"}]},
                   "CapAdd":["SYS_ADMIN"], "PidsLimit":-1, "Memory":0,
                   "LogConfig":{"Type":"json-file"}, "PidMode":"host",
                   "ExtraHosts":["external:1.2.3.4"]}
        for key, value in changes.items():
            changed = record(); changed["HostConfig"][key] = value
            with self.subTest(key=key), self.assertRaises(F.FixtureError):
                F.inspect_container(changed, "hdfs-fixture-"+RUN, IMAGE, RUN)
        changed = record(); changed["Mounts"] = [{"Type":"bind", "Destination":"/host"}]
        with self.assertRaises(F.FixtureError): F.inspect_container(changed, "hdfs-fixture-"+RUN, IMAGE, RUN)

    def test_compile_disables_processors_and_checks_bytes(self):
        source, checks, classpath = F.dockerfile(F.runtime_rows(), "a"*64)
        self.assertIn("-proc:none -implicit:none", source)
        self.assertIn("sha256sum -c", source)
        self.assertEqual(len(checks.splitlines()), 135)
        self.assertEqual(classpath.count(".jar"), 128)
        self.assertIn("240s", F.driver_script())
        args = F.command_args("hdfs-fixture-"+RUN, IMAGE, RUN)
        self.assertIn("300s", args)
        self.assertNotIn("--publish", args)

    def test_webapp_scaffolding_has_fixed_bytes_and_is_verified_before_copy(self):
        resources = F.webapp_resources()
        expected = {
            "webapps/hdfs/WEB-INF/web.xml": (113, "6d0d825985f36b71b961bcf21a33c0f21d5b732bd571962549585287071c48a9"),
            "webapps/datanode/WEB-INF/web.xml": (113, "6d0d825985f36b71b961bcf21a33c0f21d5b732bd571962549585287071c48a9"),
            "webapps/hdfs/index.html": (74, "c91ab4f8efeb470f733249fa2077f6cdfa2a0b185092bb6cd7ef94a6f1500c5e"),
            "webapps/datanode/index.html": (74, "c91ab4f8efeb470f733249fa2077f6cdfa2a0b185092bb6cd7ef94a6f1500c5e"),
            "webapps/static/fixture.txt": (30, "a934e6055b850ef89bab9e02e895da2d13ad073d49e8054a59a5bdee4d7b04af"),
        }
        self.assertEqual({path: (len(data), F.digest(data)) for path, data in resources.items()}, expected)
        build, checks, _ = F.dockerfile(F.runtime_rows(), "a"*64)
        for path, (_, sha256) in expected.items():
            self.assertIn(sha256 + "  /opt/hdfs/resources/" + path + "\n", checks)
        self.assertLess(build.index("sha256sum -c"), build.index("cp -R /opt/hdfs/resources/webapps"))
        self.assertLess(build.index("cp -R /opt/hdfs/resources/webapps"), build.index("chmod -R a=rX"))
        import xml.etree.ElementTree as ET
        for path, data in resources.items():
            if path.endswith(".xml"):
                root = ET.fromstring(data)
                self.assertEqual(root.tag, "{http://java.sun.com/xml/ns/j2ee}web-app")
                self.assertEqual(len(root), 0)

    def test_cli_never_uses_ambient_config_or_kerberos(self):
        args = F.rclone_args("lsjson", F.remote())
        self.assertEqual(args[:2], ["/usr/bin/env", "-i"])
        self.assertEqual(args[args.index("--config")+1], "/dev/null")
        self.assertNotIn("--hdfs-service-principal-name", args)
        with self.assertRaises(F.FixtureError): F.remote("../user-data")
        with self.assertRaises(F.FixtureError): F.rclone_args("cat", user="unreviewed")

    def test_download_exact_bytes_and_no_redirect(self):
        payload = b"synthetic jar data, never executed"
        row = dict(group="synthetic.example", artifact="fixture", version="1", classifier="",
                   type="jar", size=len(payload), sha256=F.digest(payload))
        class Response(io.BytesIO):
            status = 200
        class Opener:
            def __init__(self, data, redirected=False): self.data, self.redirected = data, redirected
            def open(self, request, **kwargs):
                response = Response(self.data)
                response.url = request.full_url if not self.redirected else "https://example.invalid/unreviewed"
                return response
        for label, data, redirect, success in (("ok",payload,False,True), ("bytes",payload+b"x",False,False),
                                                ("short",payload[:-1],False,False), ("redirect",payload,True,False)):
            context = self.root / label; context.mkdir()
            if success:
                F.download_jars(context,[row],opener=Opener(data,redirect))
                self.assertEqual((context/"jars/000.jar").read_bytes(), payload)
            else:
                with self.assertRaises(F.FixtureError): F.download_jars(context,[row],opener=Opener(data,redirect))
        with self.assertRaises(F.FixtureError): F.NoRedirect().redirect_request(None, None, None, None, None, None)

    def test_wrong_expected_hash_rejected_by_acquisition_verifier(self):
        path = self.root / "sample"; path.write_bytes(b"independent bytes")
        F.verify_sample(path, F.digest(path.read_bytes()))
        with self.assertRaisesRegex(F.FixtureError, "sample_mismatch"): F.verify_sample(path, "0"*64)

    def test_missing_path_requires_specific_failure_and_no_acquired_bytes(self):
        out, err = self.root/"out", self.root/"err"
        out.write_bytes(b"")
        for text in (b"object not found", b"directory not found"):
            err.write_bytes(text); F.check_missing(F.D.Result(3,out,err))
        for code, text, data in ((0,b"object not found",b""), (3,b"timeout",b""),
                                 (3,b"permission denied",b""), (3,b"object not found",b"unexpected")):
            out.write_bytes(data); err.write_bytes(text)
            with self.assertRaises(F.FixtureError): F.check_missing(F.D.Result(code,out,err))

    def invoke(self, failure=None):
        output = self.root / "owned"; output.mkdir()
        binary = self.root / "rclone"; binary.write_bytes(b"mock binary never executed")
        row = dict(group="example",artifact="synthetic",version="1",classifier="",type="jar",size=3,sha256=F.digest(b"jar"))
        instance = FakeDocker(output, max_calls=120, failure=failure)
        def download(context, rows):
            (context/"jars").mkdir(); (context/"jars/000.jar").write_bytes(b"jar")
            if failure == "download": raise F.FixtureError("download_failed")
        def probe(docker, container, progress=None):
            instance.probed = True
            progress["stage"] = "acquisition"
            if failure == "probe": raise F.FixtureError("sample_mismatch")
            if failure == "command_cleanup": raise F.D.DiscoveryError("command_cleanup_failed")
            return dict(checks={"synthetic_mock":True})
        with patch.object(F.D,"hosted_guard"), patch.object(F,"runtime_rows",return_value=[row]), \
             patch.object(F,"RCLONE_SHA",F.digest(binary.read_bytes())), \
             patch.object(F,"runtime_pin",return_value=(F.RCLONE_VERSION,F.digest(binary.read_bytes()))), \
             patch.object(F.tempfile,"mkdtemp",return_value=str(output)), \
             patch.object(F.stat,"S_IMODE",return_value=0o700), \
             patch.object(F.uuid,"uuid4",return_value=types.SimpleNamespace(hex=RUN)), \
             patch.object(F,"probe",side_effect=probe):
            result = F.run(binary, runner_factory=lambda *args,**kwargs:instance, downloader=download)
        self.assertNotIn("PRIVATE_SYNTHETIC_CANARY", json.dumps(result))
        return result, instance, output

    def test_success_requires_exact_cleanup_and_keeps_all_acceptance_false(self):
        result, docker, output = self.invoke()
        self.assertTrue(result["success"])
        self.assertTrue(all(result["cleanup"].values()))
        self.assertEqual(result["cleanup_excludes"], ["shared_base_image", "shared_build_cache"])
        self.assertEqual(result["webapp_scope"], "synthetic_scaffolding_not_vendor_ui")
        self.assertEqual(result["metrics_scope"], "shared_metrics_for_colocated_test_daemons")
        self.assertFalse(output.exists())
        for key in F.FALSE_CLAIMS: self.assertIs(result[key], False)

    def test_download_failure_has_no_native_calls(self):
        result, docker, output = self.invoke("download")
        self.assertFalse(result["success"]); self.assertEqual(docker.calls, [])
        self.assertEqual(result["stage"], "download")
        self.assertFalse(output.exists())

    def test_build_and_probe_failures_remove_only_owned_resources(self):
        for failure in ("build", "probe"):
            with self.subTest(failure=failure):
                # Each invocation owns a separate test root.
                original = self.root; self.root = original/failure; self.root.mkdir()
                try: result, docker, output = self.invoke(failure)
                finally: self.root = original
                self.assertFalse(result["success"]); self.assertTrue(all(result["cleanup"].values()))
                self.assertEqual(result["stage"], "build" if failure == "build" else "acquisition")
                self.assertFalse(output.exists())

    def diagnostic(self, value, *, current=None, code=0):
        path = self.root / "diagnostic.json"
        path.write_text(json.dumps(value), encoding="ascii")
        docker = types.SimpleNamespace(
            inspect=lambda *a, **k: record(True) if current is None else current,
            call=lambda *a, **k: F.D.Result(code, path, path))
        return F.failure_diagnostic(docker, CONTAINER, "hdfs-fixture-"+RUN, IMAGE, RUN)

    def test_diagnostic_emits_only_allowlisted_codes_and_no_source_fields(self):
        value = oracle("final")
        value.update(success=False, errors=["startup_failed", "invalid_config"])
        self.assertEqual(self.diagnostic(value), dict(status="reported", java_success=False,
                                                     errors=["startup_failed", "invalid_config"]))
        self.assertEqual(self.diagnostic(value, code=1), dict(status="unavailable"))

    def test_diagnostic_rejects_untrusted_text_and_malformed_fields(self):
        changes = [dict(errors=["PRIVATE_SYNTHETIC_CANARY"]), dict(errors=[[]]),
                   dict(errors=["io_failure"]*13), dict(extra="PRIVATE_SYNTHETIC_CANARY"),
                   dict(configuration_sha256="PRIVATE_SYNTHETIC_CANARY"), dict(success=1),
                   dict(files=[]), dict(scope="PRIVATE_SYNTHETIC_CANARY")]
        for change in changes:
            with self.subTest(change=change):
                value = oracle("final"); value.update(change)
                self.assertEqual(self.diagnostic(value), dict(status="invalid"))

    def test_diagnostic_never_reads_foreign_or_stopped_container(self):
        for field in ("Id", "Image", "Name"):
            value = record(True); value[field] = "foreign"
            with patch.object(F.D, "regular", side_effect=AssertionError("read forbidden")):
                with self.assertRaises(F.FixtureError):
                    self.diagnostic(oracle("final"), current=value)
        self.assertEqual(self.diagnostic(oracle("final"), current=record(False)),
                         dict(status="unavailable"))

    def test_diagnostic_cleanup_failure_remains_sticky_and_preserves_raw_context(self):
        with patch.object(F, "failure_diagnostic", side_effect=F.D.DiscoveryError("command_cleanup_failed")):
            result, docker, output = self.invoke("probe")
        self.assertIn("command_cleanup_failed", result["errors"])
        self.assertFalse(result["success"])
        self.assertFalse(result["cleanup"]["context_removed"])
        self.assertFalse(result["cleanup"]["raw_evidence_removed"])
        self.assertTrue(output.exists())

    def test_diagnostic_codes_cover_only_reviewed_java_assertions_and_stages(self):
        source = (F.HERE / "HdfsFixture.java").read_text(encoding="ascii")
        import re
        block = source.split("REQUIRE_CODES = Set.of(", 1)[1].split(");", 1)[0]
        codes = set(re.findall(r'"([a-z0-9_]+)"', block))
        codes.update(re.findall(r'(?:stage = |recordFailure\(errors, )"([a-z_]+)"', source))
        codes.update(re.findall(r'(?:return |category = |selected = )"([a-z_]+)"', source))
        codes.update(re.findall(r'-> "(origin_[a-z_]+)"', source))
        self.assertEqual(codes, F.JAVA_CODES)

    def test_foreign_container_or_unreaped_command_preserves_raw_context(self):
        for failure in ("foreign", "command_cleanup"):
            with self.subTest(failure=failure):
                original=self.root; self.root=original/failure; self.root.mkdir()
                try: result,docker,output=self.invoke(failure)
                finally: self.root=original
                self.assertFalse(result["success"]); self.assertFalse(result["cleanup"]["raw_evidence_removed"])
                self.assertTrue(output.exists())
                if failure == "foreign": self.assertNotIn(["container","rm","--force",CONTAINER], docker.calls)

    def test_host_guard_fails_before_download_or_native(self):
        with patch.object(F.D,"hosted_guard",side_effect=F.D.DiscoveryError("hosted_linux_required")):
            result = F.run(self.root/"absent", runner_factory=lambda *a,**k:self.fail("native"),
                           downloader=lambda *a:self.fail("download"))
        self.assertFalse(result["success"])

    def test_docker_call_budget_is_explicit_bounded_and_default_unchanged(self):
        for value in (True,29,121,1.5):
            with self.assertRaises(F.D.DiscoveryError): F.D.Docker(self.root, max_calls=value)
        first=self.root/"first"; first.mkdir()
        self.assertEqual(F.D.Docker(first).max_calls,30)
        second=self.root/"second"; second.mkdir()
        self.assertEqual(F.D.Docker(second,max_calls=120).max_calls,120)


if __name__ == "__main__":
    unittest.main()
