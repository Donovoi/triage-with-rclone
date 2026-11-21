"""Offline contract tests. No Java, rclone, Docker or service is executed."""
import importlib.util
import json
from contextlib import ExitStack
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("secure_hdfs_fixture_tests", Path(__file__).with_name("container_fixture.py"))
F = importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)


class Support:
    @staticmethod
    def read(value, maximum=16*1024*1024):
        if type(value) is not bytes or len(value) > maximum: raise ValueError("bounded_read")
        return value

    @staticmethod
    def parse(raw, maximum=65536):
        Support.read(raw, maximum)
        def unique(pairs):
            out = {}
            for key, value in pairs:
                if key in out: raise ValueError("duplicate")
                out[key] = value
            return out
        return json.loads(raw, object_pairs_hook=unique)


def receipt(phase="ready"):
    return dict(schema_version=1, scope="secure_hdfs_controller_feasibility", phase=phase, success=True,
        checks={key: True for key in (F.READY_CHECKS if phase == "ready" else F.FINAL_CHECKS)},
        cleanup={} if phase == "ready" else {key: True for key in F.FINAL_CLEANUP}, errors=[], **F.FALSE_CLAIMS)


def listing():
    return [dict(Path=key, Size=len(value), IsDir=False, ModTime="2024-01-01T00:00:00Z") for key, value in F.samples().items()]


def result(stdout=b"", stderr=b"", code=0):
    return types.SimpleNamespace(stdout=stdout, stderr=stderr, code=code)


RUN = "a"*32
NAME = "hdfs-kerberos-"+RUN
IMAGE = "sha256:"+"b"*64
CONTAINER = "c"*64


def inspected():
    return dict(Id=CONTAINER, Name="/"+NAME, Image=IMAGE, State=dict(Running=True), Mounts=[],
        Config=dict(User="10001:10001", Labels={F.LABEL: RUN}, Volumes=None, ExposedPorts=None, Healthcheck=None,
            Entrypoint=["/usr/bin/env"], Cmd=["-i", "HOME=/work/home", "PATH=/opt/java/openjdk/bin:/usr/bin:/bin",
                "JAVA_HOME=/opt/java/openjdk", "LANG=C", "LC_ALL=C", "/bin/sh", "/opt/secure/driver.sh"]),
        HostConfig=dict(NetworkMode="none", ReadonlyRootfs=True, Privileged=False, CapDrop=["ALL"], CapAdd=None,
            Binds=None, PortBindings=None, SecurityOpt=["no-new-privileges"], Memory=6*1024**3, NanoCpus=2*10**9,
            PidsLimit=384, Init=True, IpcMode="private", CgroupnsMode="private", Tmpfs={"/work": F.TMPFS},
            LogConfig=dict(Type="none"), Devices=None, DeviceRequests=None, ExtraHosts=None, PidMode=""))


class Docker:
    def __init__(self):
        self.calls = []; self.listing = listing(); self.cancel = b"124 32768\n"
        self.simple = result(stderr=b"unexpected sequence number\n", code=1)
        self.final = receipt("final"); self.view = inspected()
    def inspect(self, *args, **kw): return self.view
    def call(self, args, **kw):
        self.calls.append((args, kw))
        if args[0] == "wait": return result(b"0\n")
        if args[:2] != ["exec", CONTAINER]: raise AssertionError("wrong_container")
        cmd = args[2:]
        if cmd[:2] == ["/bin/cat", "/work/secure-final.json"]: return result(F.canonical(self.final))
        if cmd[:2] == ["/bin/sh", "-c"]:
            script = cmd[2]
            if "/work/secure/ready.json" in script: return result(F.canonical(receipt()))
            if "/work/controller-exit" in script: return result(b"0\n")
            if script == F.cancellation_script(): return result(self.cancel)
            return result()
        if "/opt/secure/rclone" in cmd:
            if cmd[-1] == "version": return result(b"rclone v1.75.1\n")
            if "lsjson" in cmd: return result(F.canonical(self.listing))
            if "cat" in cmd:
                if "/work/secure/auth/simple.conf" in cmd: return self.simple
                remote = cmd[cmd.index("cat")+1]
                if remote.endswith("missing-synthetic-file"): return result(stderr=b"directory not found\n", code=3)
                return result(F.samples()[remote.removeprefix("test:/synthetic/")])
        raise AssertionError("unexpected_command")


class RunSupport(Support):
    """Synthetic local files only; never loads the native support modules."""
    BASE = "synthetic-base"
    BASE_ID = "sha256:" + "d" * 64
    ORDER_SHA = "e" * 64
    LOCK_SHA = "f" * 64

    def __init__(self, root):
        self.HERE = root / "ticket"; self.HERE.mkdir()
        self.DISCOVERY = root / "discovery"; self.DISCOVERY.mkdir()
        (self.HERE / "runtime-classpath.json").write_bytes(b"[]")
        (self.DISCOVERY / "artifact-lock-kerberos.json").write_bytes(b"{}")

    @staticmethod
    def read(value, maximum=16*1024*1024):
        return Support.read(value if type(value) is bytes else Path(value).read_bytes(), maximum)

    @staticmethod
    def file_hash(path, maximum=16*1024*1024):
        return F.digest(RunSupport.read(path, maximum))

    @staticmethod
    def directory(path, identity=None):
        info = Path(path).stat(); actual = (info.st_dev, info.st_ino)
        if identity is not None and identity != actual: raise AssertionError("directory_changed")
        return actual

    @staticmethod
    def regular(path, maximum):
        RunSupport.read(path, maximum)

    @staticmethod
    def tree_hashes(path):
        return {p.relative_to(path).as_posix(): RunSupport.file_hash(p)
                for p in path.rglob("*") if p.is_file()}

    def load_helpers(self): return types.SimpleNamespace(), {}
    def runtime_rows(self, *_): return [dict(size=1)]
    def verify_jars(self, *_): pass


class RunDocker(Docker):
    def __init__(self):
        super().__init__(); self.built = False; self.created = False; self.running = False

    def inspect(self, kind, identity, **kw):
        if kind == "image":
            if identity == RunSupport.BASE:
                return dict(Id=RunSupport.BASE_ID, Os="linux", Architecture="amd64")
            if not self.built: return None
            return dict(Id=IMAGE, RepoTags=[NAME + ":latest"],
                        Config=dict(User="10001:10001", Labels={F.LABEL: RUN}))
        if not self.created: return None
        value = inspected()
        value["State"] = dict(Running=self.running, Status="running" if self.running else "created")
        return value

    def call(self, args, **kw):
        if args[0] == "info": return result(b'{"OSType":"linux","Architecture":"amd64"}')
        if args[:2] == ["image", "pull"]: return result()
        if args[0] == "build": self.built = True; return result()
        if args[0] == "create": self.created = True; return result()
        if args[0] == "start": self.running = True; return result()
        if args[:2] in (["container", "rm"], ["image", "rm"]):
            self.calls.append((args, kw))
            if args[0] == "container": self.created = self.running = False
            else: self.built = False
            return result()
        return super().call(args, **kw)


class RecoveryDocker(RunDocker):
    def __init__(self):
        super().__init__()
        self.final_available = False; self.clients = 0; self.stop_error = None
        self.ended = False; self.wrong_owner = False

    def inspect(self, kind, identity, **kw):
        value = super().inspect(kind, identity, **kw)
        if kind == "container" and value is not None:
            if self.wrong_owner: value["Config"]["Labels"][F.LABEL] = "unowned"
            if self.ended:
                value["State"] = dict(Running=False, Status="exited", OOMKilled=False,
                                      ExitCode=0 if self.final["success"] else 1)
        return value

    def call(self, args, **kw):
        exit_bytes = b"0\n" if self.final["success"] else b"1\n"
        if args[:2] == ["exec", CONTAINER]:
            cmd = args[2:]
            if cmd == ["/bin/cat", "/work/secure-final.json"]:
                self.calls.append((args, kw))
                return result(F.canonical(self.final)) if self.final_available else result(code=1)
            if cmd[:2] == ["/bin/sh", "-c"]:
                script = cmd[2]
                if script == F.no_client_script():
                    self.calls.append((args, kw)); return result(code=self.clients)
                if script == F.failure_marker_script("stop"):
                    self.calls.append((args, kw))
                    if self.stop_error: raise F.FixtureError(self.stop_error)
                    self.final_available = True; return result()
                if script == F.failure_marker_script("exit"):
                    self.calls.append((args, kw)); return result()
                if "/work/controller-exit" in script and "/work/secure/ready.json" not in script:
                    self.calls.append((args, kw)); return result(exit_bytes)
        if args == ["wait", CONTAINER]:
            self.calls.append((args, kw)); self.running = False; self.ended = True
            return result(exit_bytes)
        return super().call(args, **kw)


class ContractTests(unittest.TestCase):
    def failure(self, code, call, *args):
        with self.assertRaises(F.FixtureError) as caught: call(*args)
        self.assertEqual(caught.exception.code, code)

    def test_controller_success_ready_and_final(self):
        for phase in ("ready", "final"):
            self.assertEqual(F.validate_controller(Support, F.canonical(receipt(phase)), phase), receipt(phase))

    def test_controller_rejects_wrong_scope_types_unknown_fields(self):
        for key, value in (("schema_version", True), ("success", 1), ("scope", "vendor"), ("phase", "final"), ("unknown", "private")):
            item = receipt(); item[key] = value
            self.failure("controller_invalid", F.validate_controller, Support, F.canonical(item), "ready")

    def test_controller_rejects_any_promoted_claim(self):
        for key in F.FALSE_CLAIMS:
            item = receipt(); item[key] = True
            self.failure("controller_invalid", F.validate_controller, Support, F.canonical(item), "ready")

    def test_controller_rejects_incomplete_or_untyped_checks(self):
        for checks in ({}, {**receipt()["checks"], "ticket_ready": 1}, {**receipt()["checks"], "extra": True}):
            item = receipt(); item["checks"] = checks
            self.failure("controller_invalid", F.validate_controller, Support, F.canonical(item), "ready")

    def test_controller_does_not_accept_false_success_or_arbitrary_error(self):
        for modify in (lambda r: r.update(success=False), lambda r: r["checks"].update(ticket_ready=False),
                       lambda r: r.update(errors=["private error text"])):
            item = receipt(); modify(item)
            self.failure("controller_invalid", F.validate_controller, Support, F.canonical(item), "ready")

    def test_failed_controller_receipt_stays_failed(self):
        item = receipt("final"); item.update(success=False, errors=[next(iter(F.CONTROLLER_CODES))])
        item["cleanup"]["processes_reaped"] = False
        self.assertFalse(F.validate_controller(Support, F.canonical(item), "final")["success"])

    def test_listing_exact_inventory_and_mtime(self):
        F.validate_listing(listing())
        mutations = [lambda x: x.pop(), lambda x: x.append(x[0]), lambda x: x[0].update(Size=True),
            lambda x: x[0].update(Path="../unexpected"), lambda x: x[0].update(ModTime="2024-01-01T00:00:01Z"),
            lambda x: x[0].update(ModTime="2024-01-01T00:00:00"), lambda x: x[0].update(IsDir=True)]
        for mutate in mutations:
            value = listing(); mutate(value); self.failure("listing_invalid", F.validate_listing, value)

    def test_download_verifier_rejects_corruption_and_wrong_expectation(self):
        expected = F.digest(b"independent bytes")
        F.verify_sample(b"independent bytes", expected)
        self.failure("sample_mismatch", F.verify_sample, b"corrupt bytes", expected)
        self.failure("sample_mismatch", F.verify_sample, b"independent bytes", "0"*64)

    def test_simple_failure_does_not_accept_timeout_or_nonempty_output(self):
        F.simple_failed(Support, result(stderr=b"unexpected sequence number", code=1))
        for value in (result(stderr=b"timeout", code=1), result(stderr=b"unexpected sequence number"),
                      result(b"x", b"unexpected sequence number", 1), result(stderr=b"unexpected sequence number", code=True)):
            self.failure("negative_failed", F.simple_failed, Support, value)

    def test_missing_failure_needs_specific_reason_and_empty_output(self):
        for reason in (b"object not found", b"directory not found"):
            F.missing_rejected(Support, result(stderr=reason, code=1))
        for value in (result(stderr=b"timeout", code=1), result(stderr=b"directory not found"), result(b"x", b"object not found", 1)):
            self.failure("negative_failed", F.missing_rejected, Support, value)

    def test_secure_and_simple_client_environments_are_separate(self):
        secured = F.rclone_args("cat", F.remote("README.txt")); simple = F.rclone_args("cat", F.remote("README.txt"), simple=True)
        self.assertIn("KRB5CCNAME=FILE:/work/secure/auth/reader.ccache", secured)
        self.assertFalse(any("KRB5" in arg for arg in simple)); self.assertIn("/work/secure/auth/simple.conf", simple)
        self.failure("input_invalid", F.remote, "../../private")

    def test_isolation_inspection_rejects_each_weakened_constraint(self):
        F.inspect_container(inspected(), NAME, IMAGE, RUN)
        for key, value in (("NetworkMode", "host"), ("ReadonlyRootfs", False), ("Privileged", True),
            ("CapAdd", ["SYS_ADMIN"]), ("Binds", ["/:/host"]), ("SecurityOpt", []), ("Memory", True),
            ("PidsLimit", -1), ("Init", False), ("ExtraHosts", ["example.invalid:1.2.3.4"]),
            ("PidMode", "host"), ("LogConfig", dict(Type="json-file"))):
            view = inspected(); view["HostConfig"][key] = value
            self.failure("container_invalid", F.inspect_container, view, NAME, IMAGE, RUN)

    def test_create_rejects_ambiguous_image_or_name(self):
        F.command_args(NAME, IMAGE, RUN)
        self.failure("container_invalid", F.command_args, NAME, "mutable:latest", RUN)
        self.failure("container_invalid", F.command_args, "another-container", IMAGE, RUN)

    def test_full_probe_reads_actual_samples_and_keeps_vendor_unverified(self):
        docker = Docker(); progress = {}
        value = F.probe(Support, docker, CONTAINER, "1.75.1", progress)
        self.assertEqual(len(value["samples"]), 8); self.assertTrue(all(value["checks"].values()))
        self.assertFalse(value["renewal_verified"]); self.assertFalse(value["permission_denial_verified"])
        self.assertEqual(progress["stage"], "shutdown")
        self.assertTrue(all(progress["controller_final"][key] is False for key in F.FALSE_CLAIMS))
        calls = [call for call, _ in docker.calls]
        self.assertTrue(any(F.partial_cleanup_script() in call for call in calls))

    def test_probe_rejects_no_partial_bytes_and_forced_kill(self):
        for invalid in (b"124 0\n", b"137 32768\n", b"124 2097152\n", b"0 32768\n"):
            docker = Docker(); docker.cancel = invalid
            self.failure("cancellation_failed", F.probe, Support, docker, CONTAINER, "1.75.1", {})

    def test_probe_rejects_changed_listing_before_acquisition(self):
        docker = Docker(); docker.listing[0]["Size"] += 1
        self.failure("listing_invalid", F.probe, Support, docker, CONTAINER, "1.75.1", {})
        self.assertFalse(any("cat" in args for args, _ in docker.calls))

    def test_client_deadline_stops_without_reissuing_tickets(self):
        docker = Docker()
        with patch.object(F.time, "monotonic", side_effect=[100, 191]):
            self.failure("client_deadline", F.probe, Support, docker, CONTAINER, "1.75.1", {})
        self.assertEqual(len(docker.calls), 1)

    def test_failure_capture_checks_container_identity_before_reading(self):
        docker = Docker(); docker.view["Id"] = "d"*64
        self.failure("container_invalid", F.capture_failure, Support, docker, CONTAINER, NAME, IMAGE, RUN)
        self.assertEqual(docker.calls, [])

    def test_failure_capture_keeps_only_closed_receipt(self):
        docker = Docker(); docker.final.update(success=False, errors=[next(iter(F.CONTROLLER_CODES))])
        self.assertFalse(F.capture_failure(Support, docker, CONTAINER, NAME, IMAGE, RUN)["success"])
        docker.final["raw_log"] = "private"
        self.failure("controller_invalid", F.capture_failure, Support, docker, CONTAINER, NAME, IMAGE, RUN)

    def test_unfrozen_native_sources_stop_before_support_or_commands(self):
        with patch.object(F, "hosted_guard"), patch.object(F, "JAVA_INPUTS", {"test.java": "PENDING"}):
            def never(): raise AssertionError("support must not load")
            value = F.run("unused", support_loader=never)
        self.assertEqual(value["errors"], ["source_not_frozen"]); self.assertFalse(value["success"])


class FailurePathTests(unittest.TestCase):
    def failure(self, code, call, *args, **kwargs):
        with self.assertRaises(F.FixtureError) as caught: call(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(str(caught.exception), code)

    def run_failed_probe(self, probe, docker=None):
        docker = docker or RunDocker()
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            inputs = Path(directory); support = RunSupport(inputs)
            java = inputs / "Synthetic.java"; java.write_bytes(b"synthetic source")
            helper = inputs / "support.py"; helper.write_bytes(b"synthetic support")
            pin = inputs / "runtime.env"; pin.write_bytes(b"synthetic pin")
            binary = inputs / "rclone"; binary.write_bytes(b"inert bytes, never executable")
            private = inputs / "owned-run"
            def make_root(**kw):
                self.assertEqual(kw, dict(prefix="hdfs-kerberos-", dir="/tmp"))
                private.mkdir(); return str(private)
            for name, replacement in {
                "hosted_guard": lambda: None, "HERE": inputs, "SUPPORT": helper,
                "JAVA_INPUTS": {java.name: F.digest(java.read_bytes())},
                "runtime_pin": lambda _: (pin, "1.75.1", F.digest(binary.read_bytes())),
                "build_files": lambda *_: {}, "webapp_resources": lambda: {}, "probe": probe,
            }.items(): stack.enter_context(patch.object(F, name, replacement))
            stack.enter_context(patch.object(F.tempfile, "mkdtemp", make_root))
            stack.enter_context(patch.object(F.shutil, "disk_usage", return_value=types.SimpleNamespace(free=2*1024**3)))
            stack.enter_context(patch.object(F.uuid, "uuid4", return_value=types.SimpleNamespace(hex=RUN)))
            value = F.run(binary, support_loader=lambda: support,
                          runner_factory=lambda *args, **kw: docker, downloader=lambda *_: None)
            return value, docker, private.exists()

    def test_finite_support_failures_survive_without_exception_text(self):
        class SupportFailure(Exception):
            def __init__(self, code): self.code = code; super().__init__("private diagnostic canary")
        for code in ("command_failed", "command_timeout", "command_output_limit",
                     "command_start_failed", "command_cleanup_failed"):
            with self.subTest(code=code), patch.object(F, "hosted_guard"):
                def fail(): raise SupportFailure(code)
                value = F.run("unused", support_loader=fail)
            self.assertEqual(value["errors"], [code]); self.assertFalse(value["success"])
            self.assertIsNone(value["client_failure"])
            self.assertNotIn("canary", F.canonical(value).decode())
        with patch.object(F, "hosted_guard"):
            def unknown(): raise SupportFailure("private diagnostic canary")
            value = F.run("unused", support_loader=unknown)
        self.assertEqual(value["errors"], ["fixture_failed"])

    def test_client_failure_classification_is_exact_bounded_and_private(self):
        for operation in ("version", "lsjson", "cat"):
            for reason, code in (("EOF", "client_error_eof"), ("unexpected EOF", "client_error_unexpected_eof")):
                with self.subTest(operation=operation, reason=reason):
                    private = b"private@example.invalid /private/path\n"
                    error = private + ("2026/10/05 01:02:03 NOTICE: Failed to " + operation + ": " + reason + "\n").encode()
                    self.failure(code, F.require_client_success, Support, result(b"untrusted output", error, 1), operation)
        for error in (b"EOF\n", b"NOTICE: Failed to cat: EOF appended\n",
                      b"NOTICE: Failed to cat: EOF\nprivate trailing data\n",
                      b"NOTICE: Failed to lsjson: EOF\n", b"unrecognized private cause\n"):
            self.failure("client_failed", F.require_client_success, Support, result(stderr=error, code=1), "cat")
        self.failure("client_diagnostic_unavailable", F.require_client_success, Support,
                     result(stderr=b"x" * 65537, code=1), "cat")
        self.failure("client_error_eof", F.require_client_success, Support,
                     result(stderr=b"NOTICE: Failed to cat with 2 errors: last error was: EOF\n", code=1), "cat")
        for error in (b"NOTICE: Failed to cat with 1 errors: last error was: EOF\n",
                      b"NOTICE: Failed to cat with 10000 errors: last error was: EOF\n",
                      b"x\n" * 128 + b"NOTICE: Failed to cat: EOF\n"):
            self.failure("client_failed", F.require_client_success, Support, result(stderr=error, code=1), "cat")

    def test_client_result_type_and_operation_are_closed(self):
        for code in (True, False, None, "1", 1.0, 256, -256):
            self.failure("client_result_invalid", F.require_client_success, Support, result(code=code), "cat")
        self.failure("client_result_invalid", F.require_client_success, Support, result(code=1), "unknown")
        F.require_client_success(Support, result(stderr=b"unparsed successful stderr", code=0), "cat")

    @staticmethod
    def cat_failures():
        # Literal expected categories, independent of the producer's patterns.
        return (
            (b"rspauth did not match digest", "client_sasl_rspauth_mismatch"),
            (b"rspauth not in ''", "client_sasl_empty_rspauth"),
            (b"invalid response from datanode", "client_datanode_invalid_response"),
            (b"invalid response from datanode: bad response length", "client_datanode_response_length"),
            (b"invalid response from datanode: HMAC check failed", "client_datanode_hmac_failed"),
            (b"no available cipher among choices: [private-canary aes128]", "client_sasl_cipher_unavailable"),
            (b"negotiating data protection: invalid qop: [private-canary]", "client_sasl_qop_rejected"),
            (b"negotiating data protection: invalid qop: 'integrity'", "client_sasl_qop_rejected"),
            (b"rspauth not in 'private-canary'", "client_sasl_rspauth_format"),
            (b"invalid token challenge: private-canary", "client_sasl_challenge_format"),
            (b"failed to reopen: too many retries", "client_reopen_limit"),
        )

    def test_cat_failure_categories_use_exact_final_notice_envelope(self):
        for payload, code in self.cat_failures():
            for prefix in (b"NOTICE: Failed to cat: ",
                           b"2026/10/05 01:02:03 NOTICE: Failed to cat with 2 errors: last error was: "):
                with self.subTest(payload=payload, prefix=prefix):
                    raw = b"private@example.invalid /private/path\n" + prefix + payload + b"\n"
                    self.failure(code, F.require_client_success, Support, result(b"untrusted output", raw, 1), "cat")

    def test_sasl_and_datanode_categories_are_cat_only_and_require_nonzero_exit(self):
        for payload, _ in self.cat_failures():
            for operation in ("version", "lsjson"):
                with self.subTest(payload=payload, operation=operation):
                    raw = b"NOTICE: Failed to " + operation.encode() + b": " + payload + b"\n"
                    self.failure("client_failed", F.require_client_success, Support, result(stderr=raw, code=1), operation)
                    self.failure("client_failed", F.require_client_success, Support, result(stderr=raw, code=1), "cat")
            F.require_client_success(Support, result(stderr=b"NOTICE: Failed to cat: " + payload, code=0), "cat")

    def test_cipher_and_qop_lists_have_exact_positive_token_boundaries(self):
        lists = (b"[]", b"[0]", b"[aes128]", b"[a-]", b"[" + b"a" * 32 + b"]",
                 b"[a b c d e f g h]")
        for prefix, code in (
            (b"no available cipher among choices: ", "client_sasl_cipher_unavailable"),
            (b"negotiating data protection: invalid qop: ", "client_sasl_qop_rejected"),
        ):
            for value in lists:
                with self.subTest(prefix=prefix, value=value):
                    self.failure(code, F.require_client_success, Support,
                                 result(stderr=b"NOTICE: Failed to cat: " + prefix + value + b"\n", code=1), "cat")

    def test_cat_payloads_reject_malformed_lists_controls_and_unknown_templates(self):
        malformed = (b"[a b c d e f g h i]", b"[" + b"a" * 33 + b"]", b"[ a]", b"[a ]",
                     b"[a  b]", b"[a\tb]", b"[a\x00b]", b"[a\x1bb]", b"[a\nb]", b"[a\rb]",
                     b"[A]", b"[-a]", b"[a_b]", b"[a,b]", b"[a/b]", b"[a=b]", b"[caf\xc3\xa9]",
                     b"['a']", b"[a][b]", b"a", b"[a", b"a]", b"[] trailing")
        for prefix in (b"no available cipher among choices: ", b"negotiating data protection: invalid qop: "):
            for value in malformed:
                with self.subTest(prefix=prefix, value=value):
                    self.failure("client_failed", F.require_client_success, Support,
                                 result(stderr=b"NOTICE: Failed to cat: " + prefix + value + b"\n", code=1), "cat")
        for payload in (
            b"rspauth did not match digest: expected=private-canary actual=private-canary",
            b"rspauth did not match digest private-canary", b"invalid response from datanode: private-canary",
            b"rspauth not in '\x00'",
            b'rspauth not in ""', b"rspauth not in '' trailing",
            b"invalid response from datanode: HMAC check failed: private-canary",
            b"invalid response from datanode: bad response length 1234",
            b"negotiating data protection: invalid qop: 'auth'",
            b"negotiating data protection: invalid qop: 'integrity' trailing",
            b"no available cipher among choices: 'integrity'",
        ):
            with self.subTest(payload=payload):
                self.failure("client_failed", F.require_client_success, Support,
                             result(stderr=b"NOTICE: Failed to cat: " + payload + b"\n", code=1), "cat")

    def test_cat_categories_keep_existing_count_and_diagnostic_bounds(self):
        payload = b"rspauth did not match digest"
        for raw in (
            payload + b"\n", b"ERROR: Failed to cat: " + payload + b"\n",
            b"NOTICE: Failed to cat with 1 errors: last error was: " + payload + b"\n",
            b"NOTICE: Failed to cat with 02 errors: last error was: " + payload + b"\n",
            b"NOTICE: Failed to cat with 10000 errors: last error was: " + payload + b"\n",
            b"NOTICE: Failed to cat: " + payload + b"\nprivate trailing line\n",
            b"x\n" * 128 + b"NOTICE: Failed to cat: " + payload + b"\n",
            b"x" * 4097 + b"\nNOTICE: Failed to cat: " + payload + b"\n",
        ):
            self.failure("client_failed", F.require_client_success, Support, result(stderr=raw, code=1), "cat")
        self.failure("client_diagnostic_unavailable", F.require_client_success, Support,
                     result(stderr=b"x" * 65537, code=1), "cat")
        self.failure("client_sasl_rspauth_mismatch", F.require_client_success, Support,
                     result(stderr=b"NOTICE: Failed to cat with 9999 errors: last error was: " + payload + b"\n", code=1), "cat")

    def test_dynamic_families_have_literal_templates_and_printable_byte_bounds(self):
        families = (
            (b"rspauth not in '", b"'", "client_sasl_rspauth_format"),
            (b"invalid token challenge: ", b"", "client_sasl_challenge_format"),
        )
        for prefix, suffix, code in families:
            for opaque in (b"", b" ", b"'quoted' [opaque] \\", b"x" * 1024):
                expected = "client_sasl_empty_rspauth" if prefix == b"rspauth not in '" and not opaque else code
                raw = b"NOTICE: Failed to cat: " + prefix + opaque + suffix + b"\n"
                with self.subTest(prefix=prefix, length=len(opaque)):
                    self.failure(expected, F.require_client_success, Support, result(stderr=raw, code=1), "cat")
            for opaque in (b"x" * 1025, b"\x00", b"\t", b"\r", b"\n", b"\x1b", b"\x7f", b"\x80", b"caf\xc3\xa9"):
                raw = b"NOTICE: Failed to cat: " + prefix + opaque + suffix + b"\n"
                with self.subTest(prefix=prefix, opaque=opaque[:8]):
                    self.failure("client_failed", F.require_client_success, Support, result(stderr=raw, code=1), "cat")
        for payload in (b"Rspauth not in 'x'", b"rspauth not in x", b"rspauth not in 'x' suffix",
                        b"invalid token challenge:x", b"Invalid token challenge: x",
                        b"failed to reopen: too many retries suffix", b"failed to reopen: too many retries\x00"):
            self.failure("client_failed", F.require_client_success, Support,
                         result(stderr=b"NOTICE: Failed to cat: " + payload + b"\n", code=1), "cat")

    def test_object_stage_matches_literal_basename_and_equal_final_payload(self):
        # These labels are literal expectations for the closed eight-file fixture.
        labels = (b"README.txt", b"empty.bin", b"cancel.bin", b"alpha.txt",
                  b"data.bin", b"space name.txt", b"owner-only.txt", b"utf8.txt")
        payload = b"unrecognized private@example.invalid /private/path"
        for ordinal, label in enumerate(labels, 1):
            for message, stage in ((b"open", "open"), (b"send to output", "send_output")):
                raw = (b"2026/10/05 01:02:03 ERROR : " + label + b": Failed to " + message + b": " + payload
                       + b"\n2026/10/05 01:02:04 NOTICE: Failed to cat: " + payload + b"\n")
                report = {}
                with self.subTest(ordinal=ordinal, stage=stage):
                    self.failure("client_failed", F.require_client_success, Support, result(stderr=raw, code=1),
                                 "cat", report=report, sample_ordinal=ordinal)
                    self.assertEqual(report["client_failure"]["object_error_stage"], stage)
                    self.assertTrue(report["client_failure"]["final_error_template"])
                    public = F.canonical(report)
                    for private in (label, payload, b"private@example.invalid", b"/private/path"):
                        self.assertNotIn(private, public)

    def test_object_stage_rejects_unknown_contradictory_and_nonmatching_records(self):
        final = b"NOTICE: Failed to cat: private-canary\n"
        good = b"ERROR : README.txt: Failed to open: private-canary\n"
        other_stage = b"ERROR : README.txt: Failed to send to output: private-canary\n"
        for records in (
            b"", b"private preamble\n", good + good, good + other_stage, other_stage + good,
            b"ERROR : other.txt: Failed to open: private-canary\n", good + b"ERROR : other.txt: unknown\n",
            b"ERROR: README.txt: Failed to open: private-canary\n",
            b"ERROR : /synthetic/README.txt: Failed to open: private-canary\n",
            b"ERROR : README.txt: Failed to open: different-private-canary\n",
            b"ERROR : README.txt: Failed to read: private-canary\n",
            b"ERROR : README.txt: Failed to open: private-canary\x00\n",
        ):
            report = {}
            self.failure("client_failed", F.require_client_success, Support, result(stderr=records + final, code=1),
                         "cat", report=report, sample_ordinal=1)
            self.assertEqual(report["client_failure"]["object_error_stage"], "unrecognized")
            self.assertNotIn(b"private-canary", F.canonical(report))
        report = {}
        self.failure("client_failed", F.require_client_success, Support,
                     result(stderr=good + b"NOTICE: Failed to cat with 1 errors: last error was: private-canary\n", code=1),
                     "cat", report=report, sample_ordinal=1)
        self.assertFalse(report["client_failure"]["final_error_template"])
        self.assertEqual(report["client_failure"]["object_error_stage"], "unrecognized")
        report = {}
        self.failure("client_failed", F.require_client_success, Support, result(stderr=good + final, code=1),
                     "cat", report=report)
        self.assertIsNone(report["client_failure"]["object_error_stage"])

    def test_real_probe_dynamic_family_stage_survives_cleanup_without_promotion(self):
        for payload, expected in (
            (b"rspauth not in 'private-canary'", "client_sasl_rspauth_format"),
            (b"invalid token challenge: private-canary", "client_sasl_challenge_format"),
            (b"failed to reopen: too many retries", "client_reopen_limit"),
        ):
            raw = b"ERROR : README.txt: Failed to send to output: " + payload + b"\nNOTICE: Failed to cat: " + payload + b"\n"
            class FailedAcquisition(RecoveryDocker):
                def call(inner, args, **kw):
                    if "cat" in args and "test:/synthetic/README.txt" in args:
                        inner.calls.append((args, kw)); return result(b"", raw, 1)
                    return super(FailedAcquisition, inner).call(args, **kw)
            with self.subTest(expected=expected):
                value, _, retained = self.run_failed_probe(F.probe, FailedAcquisition())
                self.assertEqual(value["errors"], [expected]); self.assertFalse(value["success"])
                self.assertEqual(value["stage"], "acquisition"); self.assertIsNone(value["result"])
                self.assertEqual(value["client_failure"], dict(operation="cat", exit_code=1, sample_ordinal=1,
                    stderr_bytes=len(raw), stderr_line_count=2, final_error_template=True, object_error_stage="send_output"))
                self.assertTrue(value["controller_final"]["success"])
                self.assertTrue(all(value["cleanup"].values())); self.assertFalse(retained)
                for secret in (b"private-canary", b"README.txt", payload): self.assertNotIn(secret, F.canonical(value))
                for claim in F.FALSE_CLAIMS: self.assertIs(value[claim], False)

    def test_each_cat_category_survives_orderly_cleanup_without_raw_values_or_promotion(self):
        for payload, code in self.cat_failures():
            def fail(_support, _docker, _container, _version, report):
                report["controller_ready"] = receipt(); report["stage"] = "acquisition"
                raw = b"private@example.invalid /private/path\nNOTICE: Failed to cat: " + payload + b"\n"
                F.require_client_success(Support, result(b"private stdout canary", raw, 1), "cat")
            with self.subTest(code=code, payload=payload):
                value, _, retained = self.run_failed_probe(fail, RecoveryDocker())
                self.assertEqual(value["errors"], [code]); self.assertFalse(value["success"])
                self.assertEqual(value["stage"], "acquisition"); self.assertIsNone(value["result"])
                self.assertTrue(value["controller_final"]["success"])
                self.assertTrue(all(value["cleanup"].values())); self.assertFalse(retained)
                public = F.canonical(value)
                for secret in (b"private-canary", b"private@example.invalid", b"/private/path", b"private stdout canary", payload):
                    self.assertNotIn(secret, public)
                for claim in F.FALSE_CLAIMS: self.assertIs(value[claim], False)

    @staticmethod
    def hdfs_read_failures():
        # Independent literals from pinned HDFS/protobuf sources, not producer patterns.
        return (
            (b"invalid offset", "client_hdfs_invalid_offset"),
            (b"no available datanodes", "client_hdfs_no_datanodes"),
            (b"invalid checksum", "client_hdfs_checksum_invalid"),
            (b"proto: cannot parse invalid wire-format data", "client_hdfs_protobuf_invalid_wire"),
            (b"proto:\xc2\xa0cannot parse invalid wire-format data", "client_hdfs_protobuf_invalid_wire"),
            (b"read failed: ERROR_ACCESS_TOKEN (private-canary)", "client_hdfs_read_status_rejected"),
        )

    @staticmethod
    def read_stderr(payload, label=b"README.txt", stage=b"send to output"):
        return (b"ERROR : " + label + b": Failed to " + stage + b": " + payload
                + b"\nNOTICE: Failed to cat: " + payload + b"\n")

    def test_read_families_require_exact_send_output_for_each_acquisition_ordinal(self):
        labels = (b"README.txt", b"empty.bin", b"cancel.bin", b"alpha.txt",
                  b"data.bin", b"space name.txt", b"owner-only.txt", b"utf8.txt")
        for payload, code in self.hdfs_read_failures():
            for ordinal, label in enumerate(labels, 1):
                raw = self.read_stderr(payload, label)
                report = {}
                with self.subTest(code=code, ordinal=ordinal):
                    self.failure(code, F.require_client_success, Support, result(stderr=raw, code=1),
                                 "cat", report=report, sample_ordinal=ordinal)
                    self.assertEqual(report["client_failure"], dict(operation="cat", exit_code=1,
                        sample_ordinal=ordinal, stderr_bytes=len(raw), stderr_line_count=2,
                        final_error_template=True, object_error_stage="send_output"))
                    for private in (payload, label, b"private-canary"):
                        self.assertNotIn(private, F.canonical(report))
            raw = self.read_stderr(payload).replace(b"ERROR :", b"2026/10/05 01:02:03 ERROR :").replace(
                b"NOTICE: Failed to cat: ", b"2026/10/05 01:02:04 NOTICE: Failed to cat with 2 errors: last error was: ")
            self.failure(code, F.require_client_success, Support, result(stderr=raw, code=1), "cat", sample_ordinal=1)
            untouched = {"client_failure": None}
            F.require_client_success(Support, result(stderr=raw, code=0), "cat", report=untouched, sample_ordinal=1)
            self.assertEqual(untouched, {"client_failure": None})

    def test_new_read_families_do_not_relabel_unobserved_open_or_other_operations(self):
        for payload, _ in self.hdfs_read_failures():
            final = b"NOTICE: Failed to cat: " + payload + b"\n"
            record = b"ERROR : README.txt: Failed to send to output: " + payload + b"\n"
            for raw, ordinal, expected_stage in (
                (record + final, None, None),
                (self.read_stderr(payload, stage=b"open"), 1, "open"),
                (final, 1, "unrecognized"),
                (record + final, 2, "unrecognized"),
                (self.read_stderr(payload, label=b"/synthetic/README.txt"), 1, "unrecognized"),
                (record + record + final, 1, "unrecognized"),
                (record + b"ERROR : README.txt: Failed to open: " + payload + b"\n" + final, 1, "unrecognized"),
                (record + b"NOTICE: Failed to cat: different-private-canary\n", 1, "unrecognized"),
            ):
                report = {}
                with self.subTest(payload=payload, ordinal=ordinal, stage=expected_stage):
                    self.failure("client_failed", F.require_client_success, Support, result(stderr=raw, code=1),
                                 "cat", report=report, sample_ordinal=ordinal)
                    self.assertEqual(report["client_failure"]["object_error_stage"], expected_stage)
            for operation in ("version", "lsjson"):
                raw = b"NOTICE: Failed to " + operation.encode() + b": " + payload + b"\n"
                self.failure("client_failed", F.require_client_success, Support, result(stderr=raw, code=1), operation)

    def test_read_status_names_are_closed_and_opaque_bytes_are_bounded(self):
        statuses = (b"ERROR", b"ERROR_CHECKSUM", b"ERROR_INVALID", b"ERROR_EXISTS", b"ERROR_ACCESS_TOKEN",
                    b"CHECKSUM_OK", b"ERROR_UNSUPPORTED", b"OOB_RESTART", b"OOB_RESERVED1", b"OOB_RESERVED2",
                    b"OOB_RESERVED3", b"IN_PROGRESS", b"ERROR_BLOCK_PINNED")
        for status in statuses:
            for opaque in (b"", b"private-canary", b"'quoted' (opaque) [value] \\", b"x" * 1024):
                payload = b"read failed: " + status + b" (" + opaque + b")"
                with self.subTest(status=status, size=len(opaque)):
                    self.failure("client_hdfs_read_status_rejected", F.require_client_success, Support,
                                 result(stderr=self.read_stderr(payload), code=1), "cat", sample_ordinal=1)
        for status in (b"SUCCESS", b"0", b"5", b"14", b"-1", b"ERROR_UNKNOWN", b"error", b"ERROR ", b"ERROR\t"):
            payload = b"read failed: " + status + b" (private-canary)"
            self.failure("client_failed", F.require_client_success, Support,
                         result(stderr=self.read_stderr(payload), code=1), "cat", sample_ordinal=1)
        for opaque in (b"x" * 1025, b"\x00", b"\t", b"\r", b"\n", b"\x1b", b"\x7f", b"\x80", b"caf\xc3\xa9", b"\xc2\xa0"):
            payload = b"read failed: ERROR (" + opaque + b")"
            self.failure("client_failed", F.require_client_success, Support,
                         result(stderr=self.read_stderr(payload), code=1), "cat", sample_ordinal=1)

    def test_read_literal_templates_do_not_strip_or_normalize_error_payloads(self):
        bad = (
            b" invalid checksum", b"invalid checksum ", b"invalid checksum\r", b"invalid checksum\x00",
            b"Invalid checksum", b"invalid checksum: private-canary", b"wrapped: invalid offset",
            b"proto:  cannot parse invalid wire-format data", b"proto:\tcannot parse invalid wire-format data",
            b"proto: \xc2\xa0cannot parse invalid wire-format data", b"proto:\xa0cannot parse invalid wire-format data",
            b"proto:\xe2\x80\x83cannot parse invalid wire-format data", b"proto: cannot parse invalid wire-format data suffix",
            b"read failed: ERROR(private-canary)", b"read failed: ERROR (private-canary",
            b"Read failed: ERROR (private-canary)", b"read failed: ERROR (private-canary) suffix",
        )
        for payload in bad:
            with self.subTest(payload=payload):
                self.failure("client_failed", F.require_client_success, Support,
                             result(stderr=self.read_stderr(payload), code=1), "cat", sample_ordinal=1)
        # Existing more-specific categories still win even with the observed read stage.
        for payload, code in ((b"unexpected EOF", "client_error_unexpected_eof"),
                              (b"rspauth not in ''", "client_sasl_empty_rspauth"),
                              (b"invalid response from datanode: HMAC check failed", "client_datanode_hmac_failed")):
            self.failure(code, F.require_client_success, Support,
                         result(stderr=self.read_stderr(payload), code=1), "cat", sample_ordinal=1)

    def test_observed_read_failure_survives_orderly_cleanup_without_promotion(self):
        for payload, code in self.hdfs_read_failures():
            raw = self.read_stderr(payload)
            class FailedRead(RecoveryDocker):
                def call(inner, args, **kw):
                    if "cat" in args and "test:/synthetic/README.txt" in args:
                        inner.calls.append((args, kw)); return result(b"", raw, 1)
                    return super(FailedRead, inner).call(args, **kw)
            with self.subTest(code=code):
                value, _, retained = self.run_failed_probe(F.probe, FailedRead())
                self.assertEqual(value["errors"], [code]); self.assertFalse(value["success"])
                self.assertEqual(value["stage"], "acquisition"); self.assertIsNone(value["result"])
                self.assertEqual(value["client_failure"]["object_error_stage"], "send_output")
                self.assertTrue(value["controller_final"]["success"])
                self.assertTrue(all(value["cleanup"].values())); self.assertFalse(retained)
                for private in (payload, b"private-canary", b"README.txt"):
                    self.assertNotIn(private, F.canonical(value))
                for claim in F.FALSE_CLAIMS: self.assertIs(value[claim], False)

    def test_client_failure_metadata_has_closed_typed_fields_and_no_raw_values(self):
        raw = b"private@example.invalid /private/path\nNOTICE: Failed to cat: rspauth not in ''\n"
        report = {}
        self.failure("client_sasl_empty_rspauth", F.require_client_success, Support,
                     result(b"private stdout canary", raw, 1), "cat", report=report, sample_ordinal=8)
        expected = dict(operation="cat", exit_code=1, sample_ordinal=8, stderr_bytes=len(raw),
                        stderr_line_count=2, final_error_template=True, object_error_stage="unrecognized")
        self.assertEqual(report, {"client_failure": expected})
        self.assertEqual({key: type(value) for key, value in report["client_failure"].items()},
                         dict(operation=str, exit_code=int, sample_ordinal=int, stderr_bytes=int,
                              stderr_line_count=int, final_error_template=bool, object_error_stage=str))
        public = F.canonical(report)
        for private in (b"private@example.invalid", b"/private/path", b"private stdout canary", b"rspauth not in"):
            self.assertNotIn(private, public)

    def test_client_failure_metadata_rejects_invalid_report_and_ordinal_before_mutation(self):
        class DictSubclass(dict): pass
        for invalid in ([], "report", True, 1, DictSubclass()):
            self.failure("client_result_invalid", F.require_client_success, Support,
                         result(code=1), "cat", report=invalid)
        for ordinal in (False, True, 0, -1, 9, 1.0, "1", [], {}):
            report = {"client_failure": None}
            self.failure("client_result_invalid", F.require_client_success, Support,
                         result(code=1), "cat", report=report, sample_ordinal=ordinal)
            self.assertEqual(report, {"client_failure": None})
        for operation in ("version", "lsjson"):
            report = {}
            self.failure("client_result_invalid", F.require_client_success, Support,
                         result(code=1), operation, report=report, sample_ordinal=1)
            self.assertEqual(report, {})
        for ordinal in (None, 1, 8):
            report = {}
            self.failure("client_error_eof", F.require_client_success, Support,
                         result(stderr=b"NOTICE: Failed to cat: EOF\n", code=1), "cat",
                         report=report, sample_ordinal=ordinal)
            self.assertEqual(report["client_failure"]["sample_ordinal"], ordinal)

    def test_successful_client_never_creates_or_overwrites_failure_metadata(self):
        for report in ({}, {"client_failure": None}, {"client_failure": {"prior": "unchanged"}}):
            before = F.canonical(report)
            F.require_client_success(Support, result(stderr=b"not read" * 10000, code=0),
                                     "cat", report=report, sample_ordinal=1)
            self.assertEqual(F.canonical(report), before)

    def test_unknown_payload_has_template_metadata_but_unrecognized_format_does_not(self):
        for operation in ("version", "lsjson", "cat"):
            for raw, template in (
                (b"NOTICE: Failed to " + operation.encode() + b": private challenge data\n", True),
                (b"NOTICE: Failed to " + operation.encode() + b" with 2 errors: last error was: private data\n", True),
                (b"ERROR: Failed to " + operation.encode() + b": private data\n", False),
                (b"NOTICE: Failed to " + operation.encode() + b" with 1 errors: last error was: private data\n", False),
                (b"NOTICE: Failed to " + operation.encode() + b": \n", False),
                (b"private data\n", False),
            ):
                with self.subTest(operation=operation, raw=raw):
                    report = {}
                    self.failure("client_failed", F.require_client_success, Support,
                                 result(stderr=raw, code=1), operation, report=report)
                    self.assertEqual(report, {"client_failure": dict(operation=operation, exit_code=1,
                        sample_ordinal=None, stderr_bytes=len(raw), stderr_line_count=len(raw.splitlines()),
                        final_error_template=template, object_error_stage=None)})
                    self.assertNotIn(b"private", F.canonical(report))

    def test_unreadable_or_oversize_diagnostics_keep_null_measurements(self):
        class Unreadable(Support):
            @staticmethod
            def read(*_): raise OSError("private path and error")
        for support, raw in ((Unreadable, b"x"), (Support, b"x" * 65537)):
            report = {}
            self.failure("client_diagnostic_unavailable", F.require_client_success, support,
                         result(stderr=raw, code=1), "cat", report=report, sample_ordinal=2)
            self.assertEqual(report, {"client_failure": dict(operation="cat", exit_code=1,
                sample_ordinal=2, stderr_bytes=None, stderr_line_count=None, final_error_template=False,
                object_error_stage="unrecognized")})
        for raw in (b"", b"x" * 4097, b"x\n" * 128 + b"NOTICE: Failed to cat: EOF\n"):
            report = {}
            self.failure("client_failed", F.require_client_success, Support,
                         result(stderr=raw, code=1), "cat", report=report)
            self.assertEqual(report["client_failure"]["stderr_bytes"], len(raw))
            self.assertEqual(report["client_failure"]["stderr_line_count"], len(raw.splitlines()))
            self.assertIs(report["client_failure"]["final_error_template"], False)

    def test_real_probe_reports_literal_sorted_acquisition_ordinal(self):
        ordered = ("README.txt", "empty.bin", "large/cancel.bin", "nested/alpha.txt",
                   "nested/deeper/data.bin", "nested/space name.txt", "private/owner-only.txt", "unicode/utf8.txt")
        raw = b"NOTICE: Failed to cat: rspauth not in ''\n"
        for ordinal, path in enumerate(ordered, 1):
            class FailedAcquisition(Docker):
                def call(inner, args, **kw):
                    if "cat" in args and "test:/synthetic/" + path in args:
                        inner.calls.append((args, kw)); return result(stderr=raw, code=1)
                    return super(FailedAcquisition, inner).call(args, **kw)
            report = {}; docker = FailedAcquisition()
            with self.subTest(ordinal=ordinal):
                self.failure("client_sasl_empty_rspauth", F.probe, Support, docker, CONTAINER, "1.75.1", report)
                self.assertEqual(report["stage"], "acquisition")
                self.assertEqual(report["client_failure"], dict(operation="cat", exit_code=1,
                    sample_ordinal=ordinal, stderr_bytes=len(raw), stderr_line_count=1, final_error_template=True,
                    object_error_stage="unrecognized"))
                cats = [args for args, _ in docker.calls if "cat" in args]
                self.assertEqual(len(cats), ordinal)

    def test_real_probe_metadata_survives_orderly_cleanup_and_remains_failed(self):
        raw = b"private@example.invalid /private/path\nNOTICE: Failed to cat: rspauth not in ''\n"
        class FailedAcquisition(RecoveryDocker):
            def call(inner, args, **kw):
                if "cat" in args and "test:/synthetic/empty.bin" in args:
                    inner.calls.append((args, kw)); return result(b"", raw, 1)
                return super(FailedAcquisition, inner).call(args, **kw)
        value, _, retained = self.run_failed_probe(F.probe, FailedAcquisition())
        self.assertEqual(value["errors"], ["client_sasl_empty_rspauth"])
        self.assertFalse(value["success"]); self.assertIsNone(value["result"])
        self.assertEqual(value["stage"], "acquisition")
        self.assertEqual(value["client_failure"], dict(operation="cat", exit_code=1, sample_ordinal=2,
            stderr_bytes=len(raw), stderr_line_count=2, final_error_template=True, object_error_stage="unrecognized"))
        self.assertTrue(value["controller_final"]["success"])
        self.assertTrue(all(value["cleanup"].values())); self.assertFalse(retained)
        for private in (b"private@example.invalid", b"/private/path", b"private stdout canary", b"rspauth not in"):
            self.assertNotIn(private, F.canonical(value))
        for claim in F.FALSE_CLAIMS: self.assertIs(value[claim], False)

    def test_authenticated_recovery_failure_does_not_reuse_acquisition_ordinal(self):
        raw = b"NOTICE: Failed to cat: rspauth not in ''\n"
        class FailedRecovery(Docker):
            alpha_reads = 0
            def call(inner, args, **kw):
                if ("cat" in args and "test:/synthetic/nested/alpha.txt" in args
                        and "/work/secure/auth/simple.conf" not in args):
                    inner.alpha_reads += 1
                    if inner.alpha_reads == 2:
                        inner.calls.append((args, kw)); return result(stderr=raw, code=1)
                return super(FailedRecovery, inner).call(args, **kw)
        report = {"client_failure": None}
        self.failure("client_sasl_empty_rspauth", F.probe, Support, FailedRecovery(), CONTAINER, "1.75.1", report)
        self.assertEqual(report["stage"], "authenticated_recovery")
        self.assertEqual(report["client_failure"], dict(operation="cat", exit_code=1, sample_ordinal=None,
            stderr_bytes=len(raw), stderr_line_count=1, final_error_template=True, object_error_stage=None))

    def test_positive_nonzero_listing_is_not_accepted_despite_valid_stdout(self):
        class FailedListing(Docker):
            def call(inner, args, **kw):
                if "lsjson" in args:
                    self.assertIs(kw.get("allow_failure"), True)
                    return result(F.canonical(listing()), b"private listing failure", 1)
                return super(FailedListing, inner).call(args, **kw)
        self.failure("client_failed", F.probe, Support, FailedListing(), CONTAINER, "1.75.1", {})

    def test_empty_payload_limit_is_independent_of_private_stderr(self):
        for code in (0, 1):
            class EmptyPayload(Docker):
                def call(inner, args, **kw):
                    if "cat" in args and "test:/synthetic/empty.bin" in args:
                        self.assertEqual(kw.get("limit"), 1)
                        self.assertIs(kw.get("allow_failure"), True)
                        return result(b"", b"NOTICE: Failed to cat: EOF\n", code)
                    return super(EmptyPayload, inner).call(args, **kw)
            with self.subTest(code=code):
                if code:
                    self.failure("client_error_eof", F.probe, Support, EmptyPayload(), CONTAINER, "1.75.1", {})
                else:
                    self.assertTrue(all(F.probe(Support, EmptyPayload(), CONTAINER, "1.75.1", {})["checks"].values()))

    @staticmethod
    def failed_client(_support, _docker, _container, _version, report):
        report["controller_ready"] = receipt(); report["stage"] = "listing"
        F.require_client_success(Support, result(stderr=b"NOTICE: Failed to lsjson: EOF\n", code=1), "lsjson")

    @staticmethod
    def recovery_report():
        return dict(errors=["client_error_eof"], stage="listing", controller_ready=receipt(), controller_final=None)

    @staticmethod
    def ready_docker():
        docker = RecoveryDocker(); docker.built = docker.created = docker.running = True
        return docker

    def test_failed_client_recovers_final_cleanup_without_promoting_original_failure(self):
        value, docker, retained = self.run_failed_probe(self.failed_client, RecoveryDocker())
        self.assertEqual(value["errors"], ["client_error_eof"])
        self.assertEqual(value["stage"], "listing"); self.assertFalse(value["success"])
        self.assertIsNone(value["result"]); self.assertTrue(value["controller_final"]["success"])
        self.assertTrue(all(value["controller_final"]["cleanup"].values()))
        self.assertTrue(all(value["cleanup"].values())); self.assertFalse(retained)
        for key in F.FALSE_CLAIMS: self.assertIs(value[key], False)
        scripts = [args[4] for args, _ in docker.calls if args[:4] == ["exec", CONTAINER, "/bin/sh", "-c"]]
        self.assertLess(scripts.index(F.no_client_script()), scripts.index(F.failure_marker_script("stop")))
        self.assertLess(scripts.index(F.failure_marker_script("stop")), scripts.index(F.failure_marker_script("exit")))

    def test_orderly_shutdown_requires_valid_ready_and_exact_ownership_before_commands(self):
        for ready in (None, {**receipt(), "success": False}, {**receipt(), "extra": "canary"}):
            report = self.recovery_report(); report["controller_ready"] = ready; docker = self.ready_docker()
            with self.assertRaises(F.FixtureError):
                F.orderly_failure_shutdown(Support, docker, CONTAINER, NAME, IMAGE, RUN, report)
            self.assertEqual(docker.calls, [])
            self.assertEqual(report["errors"], ["client_error_eof"])
        report = self.recovery_report(); docker = self.ready_docker(); docker.wrong_owner = True
        self.failure("container_invalid", F.orderly_failure_shutdown, Support, docker, CONTAINER, NAME, IMAGE, RUN, report)
        self.assertEqual(docker.calls, [])

    def test_live_client_prevents_stop_without_killing_or_inventing_final(self):
        report = self.recovery_report(); docker = self.ready_docker(); docker.clients = 3
        self.failure("failure_shutdown_clients_present", F.orderly_failure_shutdown,
                     Support, docker, CONTAINER, NAME, IMAGE, RUN, report)
        self.assertEqual(len(docker.calls), 1)
        args, options = docker.calls[0]
        self.assertEqual(args, ["exec", CONTAINER, "/bin/sh", "-c", F.no_client_script()])
        self.assertEqual(options, dict(timeout=8, limit=1, allow_failure=True))
        self.assertIsNone(report["controller_final"]); self.assertEqual(report["errors"], ["client_error_eof"])
        script = F.no_client_script()
        self.assertIn('while [ "$i" -lt 5 ]', script)
        self.assertIn('[ ! -d "$p" ] || return 1', script)
        self.assertNotIn("kill", script)

    def test_failed_final_remains_failed_and_existing_final_avoids_duplicate_stop(self):
        report = self.recovery_report(); docker = self.ready_docker(); docker.final_available = True
        docker.final.update(success=False, errors=["source_verification_failed"])
        docker.final["checks"]["source_verified"] = False
        F.orderly_failure_shutdown(Support, docker, CONTAINER, NAME, IMAGE, RUN, report)
        self.assertEqual(report["errors"], ["client_error_eof", "controller_failed"])
        self.assertFalse(report["controller_final"]["success"])
        self.assertFalse(any(F.failure_marker_script("stop") in args for args, _ in docker.calls))
        self.assertTrue(docker.ended)

    def test_failed_final_with_unconfirmed_process_or_listener_cleanup_cannot_release(self):
        for key in ("processes_reaped", "listeners_absent"):
            report = self.recovery_report(); docker = self.ready_docker(); docker.final_available = True
            docker.final.update(success=False, errors=["process_cleanup_failed"])
            docker.final["cleanup"][key] = False
            with self.subTest(key=key):
                self.failure("failure_shutdown_release_failed", F.orderly_failure_shutdown,
                             Support, docker, CONTAINER, NAME, IMAGE, RUN, report)
            self.assertFalse(report["controller_final"]["success"])
            self.assertFalse(any(F.failure_marker_script("exit") in args for args, _ in docker.calls))
            self.assertFalse(docker.ended)

    def test_malformed_final_cannot_be_copied_to_report_or_release_container(self):
        report = self.recovery_report(); docker = self.ready_docker(); docker.final_available = True
        docker.final["raw_log"] = "private diagnostic canary"
        self.failure("controller_invalid", F.orderly_failure_shutdown,
                     Support, docker, CONTAINER, NAME, IMAGE, RUN, report)
        self.assertIsNone(report["controller_final"])
        self.assertNotIn("canary", F.canonical(report).decode())
        self.assertFalse(any(F.failure_marker_script("exit") in args for args, _ in docker.calls))

    def test_bounded_stop_failure_falls_back_without_clearing_original_error(self):
        docker = RecoveryDocker(); docker.stop_error = "command_timeout"
        value, docker, retained = self.run_failed_probe(self.failed_client, docker)
        self.assertFalse(value["success"]); self.assertEqual(value["stage"], "listing")
        self.assertEqual(value["errors"], ["client_error_eof", "command_timeout", "failure_shutdown_failed"])
        self.assertIsNone(value["controller_final"]); self.assertIsNone(value["result"])
        self.assertTrue(all(value["cleanup"].values())); self.assertFalse(retained)
        stops = [(args, opts) for args, opts in docker.calls if F.failure_marker_script("stop") in args]
        self.assertEqual(len(stops), 1); self.assertEqual(stops[0][1]["timeout"], 5)
        self.assertFalse(any(F.failure_marker_script("exit") in args for args, _ in docker.calls))
        self.assertTrue(any(args == ["container", "rm", "--force", CONTAINER] for args, _ in docker.calls))

    def test_unconfirmed_command_cleanup_keeps_raw_evidence(self):
        def unreaped(_support, _docker, _container, _version, report):
            report["controller_ready"] = receipt(); report["stage"] = "listing"
            raise F.FixtureError("command_cleanup_failed")
        value, docker, retained = self.run_failed_probe(unreaped, RecoveryDocker())
        self.assertFalse(value["success"]); self.assertIn("command_cleanup_failed", value["errors"])
        self.assertFalse(value["cleanup"]["raw_evidence_removed"]); self.assertTrue(retained)
        self.assertFalse(any(F.failure_marker_script("stop") in args for args, _ in docker.calls))


if __name__ == "__main__": unittest.main()
