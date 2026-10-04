"""Offline contract tests. No Java, rclone, Docker or service is executed."""
import importlib.util
import json
from pathlib import Path
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


if __name__ == "__main__": unittest.main()
