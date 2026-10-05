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
                if "/work/controller-exit" in script:
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
    def failure(self, code, call, *args):
        with self.assertRaises(F.FixtureError) as caught: call(*args)
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
            (b"invalid response from datanode", "client_datanode_invalid_response"),
            (b"invalid response from datanode: bad response length", "client_datanode_response_length"),
            (b"invalid response from datanode: HMAC check failed", "client_datanode_hmac_failed"),
            (b"no available cipher among choices: [private-canary aes128]", "client_sasl_cipher_unavailable"),
            (b"negotiating data protection: invalid qop: [private-canary]", "client_sasl_qop_rejected"),
            (b"negotiating data protection: invalid qop: 'integrity'", "client_sasl_qop_rejected"),
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

    def test_cat_payloads_reject_malformed_lists_controls_and_dynamic_challenges(self):
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
