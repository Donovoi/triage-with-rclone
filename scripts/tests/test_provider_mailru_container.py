"""Closed Mailru container/receipt contracts; no Docker or native execution."""
import ast
import copy
import importlib.util
import io
import json
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

LAB = Path(__file__).resolve().parents[1] / "provider-lab"
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module
S = load("mailru_containment_test", LAB / "mailru-fixed-api/run_container.py")
saved_path = list(sys.path)
sys.path.insert(0, str(LAB))
try:
    P = load("mailru_probe_test", LAB / "mailru-fixed-api/probe.py")
finally:
    sys.path[:] = saved_path

RUN = "a" * 32
IMAGE = "sha256:" + "b" * 64
CID = "c" * 64
SOURCES = {name: "d" * 64 for name in S.SOURCE_FILES}
IDENTITY = {"version": "1.75.2", "sha256": "e" * 64}
ENV = ["HOME=/work", "LANG=C.UTF-8"]
FIRST, LAST = "2026-11-15T04:00:00Z", "2026-11-15T04:00:02Z"

def container():
    return {"Id": CID, "Image": IMAGE, "Config": {"Labels": {S.LABEL: RUN, S.KIND: "mailru-fixed-api-probe"},
        "User": "10001:10001", "Entrypoint": S.ENTRYPOINT, "Cmd": S.COMMAND, "WorkingDir": "/work", "Env": ENV},
        "HostConfig": {"NetworkMode": "none", "ReadonlyRootfs": True, "Privileged": False, "CapDrop": ["ALL"],
        "SecurityOpt": ["no-new-privileges"], "CgroupnsMode": "private", "IpcMode": "private", "Init": True,
        "Memory": 536870912, "NanoCpus": 1000000000, "PidsLimit": 96, "Tmpfs": {"/work": S.TMPFS},
        "ExtraHosts": ["cloud.mail.ru:127.0.0.1", "dispatcher.cloud.mail.ru:127.0.0.2", "synthetic-content.mailru.invalid:127.0.0.3"], "Sysctls": {"net.ipv4.ip_unprivileged_port_start": "0"}},
        "Mounts": [], "NetworkSettings": {"Networks": {"none": {}}}, "State": {"Running": False}}

def probe(lock):
    return {"schema_version": 1, "scope": "mailru_fixed_api_read_probe", "ledger_eligible": False,
        "started_utc": FIRST, "finished_utc": LAST, "success": True, "errors": [],
        "checks": dict.fromkeys(S.PROBE_CHECKS, True), "cleanup": dict.fromkeys(S.PROBE_CLEANUP, True),
        "capabilities": dict.fromkeys(S.CAPABILITIES, "passed"),
        "runtime": {"platform": "linux", "architecture": "amd64", "uid": 10001, "gid": 10001,
        "python_version": lock["python_version"], "cryptography_version": "50.0.2",
        "rclone_version": IDENTITY["version"], "rclone_sha256": IDENTITY["sha256"],
        "source_digest": S.canonical_hash(SOURCES), "fixture_manifest_sha256": S.FIXTURE_SHA256}}

class MailruContainerTests(unittest.TestCase):
    def setUp(self):
        self.lock = S.read_lock()
        self.assertEqual(len(S.source_hashes()), len(S.SOURCE_FILES))

    def validate(self, value):
        return S.validate_probe(value, IDENTITY, SOURCES, self.lock, FIRST, LAST)

    def test_probe_success_is_bound_and_never_eligible_for_vendor_acceptance(self):
        self.assertIs(self.validate(value := probe(self.lock)), value)
        self.assertFalse(value["ledger_eligible"])
        self.assertEqual(len(value["capabilities"]), 9)

    def test_claimed_pass_requires_every_exact_typed_check_capability_and_cleanup(self):
        for field in ("checks", "cleanup", "capabilities"):
            for key in probe(self.lock)[field]:
                for replacement in (None, False, 1, "passed" if field != "capabilities" else "not_run"):
                    value = probe(self.lock)
                    value[field][key] = replacement
                    with self.subTest(field=field, key=key, replacement=replacement), self.assertRaises(S.SupervisorError):
                        self.validate(value)
                value = probe(self.lock)
                value[field]["unreviewed"] = True
                with self.assertRaises(S.SupervisorError):
                    self.validate(value)

    def test_scope_time_runtime_and_source_mutations_are_rejected(self):
        for key, replacement in (("schema_version", True), ("scope", "rclone_backend_protocol_fixture"),
                ("ledger_eligible", True), ("success", 1), ("started_utc", "2026-11-15T03:59:59Z"),
                ("finished_utc", "2026-11-15T04:00:03Z"), ("errors", ["private/path"]), ("unknown", True)):
            value = probe(self.lock); value[key] = replacement
            with self.subTest(key=key), self.assertRaises(S.SupervisorError):
                self.validate(value)
        for key in probe(self.lock)["runtime"]:
            value = probe(self.lock); value["runtime"][key] = "unbound"
            with self.subTest(key=key), self.assertRaises(S.SupervisorError):
                self.validate(value)

    def test_partial_failure_can_be_retained_but_never_promoted(self):
        value = probe(self.lock)
        value.update(success=False, errors=["probe_operation_failed"])
        value["checks"]["protocol"] = False
        value["capabilities"]["download_hash"] = "not_run"
        self.validate(value)
        value["success"] = True
        with self.assertRaises(S.SupervisorError):
            self.validate(value)

    def test_json_duplicate_keys_nonfinite_and_size_are_rejected(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b"x" * 262145, b"\xff"):
            with self.subTest(raw=raw[:30]), self.assertRaises(S.SupervisorError):
                S.parse_json(raw)

    def test_create_selects_exact_namespace_and_no_host_mounts(self):
        args = S.create_args("triage-mailru-fixed-api-" + RUN, IMAGE, RUN)
        for key, value in (("--network", "none"), ("--user", "10001:10001"), ("--cap-drop", "ALL"),
                ("--add-host", "cloud.mail.ru:127.0.0.1"), ("--sysctl", "net.ipv4.ip_unprivileged_port_start=0"),
                ("--tmpfs", "/work:" + S.TMPFS)):
            self.assertEqual(args[args.index(key)+1], value)
        self.assertEqual([args[i + 1] for i, value in enumerate(args) if value == "--add-host"],
                         ["cloud.mail.ru:127.0.0.1", "dispatcher.cloud.mail.ru:127.0.0.2", "synthetic-content.mailru.invalid:127.0.0.3"])
        self.assertIn("noexec", S.TMPFS)
        self.assertNotIn("--volume", args)
        self.assertNotIn("--mount", args)
        self.assertEqual(args[-len(S.COMMAND):], S.COMMAND)
        for name in ("other", "triage-mailru-fixed-api-" + "g" * 32):
            with self.assertRaises(S.SupervisorError):
                S.create_args(name, IMAGE, RUN)

    def test_container_inspection_rejects_every_escape_and_resource_expansion(self):
        S.validate_container(container(), IMAGE, RUN, ENV)
        mutations = {"NetworkMode": "host", "ReadonlyRootfs": False, "Privileged": True, "CapDrop": [],
            "CapAdd": ["NET_ADMIN"], "SecurityOpt": ["seccomp=unconfined"], "CgroupnsMode": "host",
            "IpcMode": "host", "PidMode": "host", "UTSMode": "host", "UsernsMode": "host", "Init": False,
            "Memory": 0, "NanoCpus": 0, "PidsLimit": 0, "Tmpfs": {"/work": "rw,exec"},
            "ExtraHosts": ["cloud.mail.ru:192.0.2.1"], "Sysctls": {"net.ipv4.ip_unprivileged_port_start": "443"},
            "Binds": ["/mnt/c:/data"], "Mounts": [{"Type": "bind"}], "VolumesFrom": ["foreign"], "Devices": ["/dev/sda"],
            "DeviceRequests": [{"Count": -1}], "PortBindings": {"443/tcp": [{}]}, "Links": ["foreign"],
            "Dns": ["192.0.2.1"], "DnsSearch": ["invalid"], "DnsOptions": ["rotate"]}
        for key, value in mutations.items():
            info = container(); info["HostConfig"][key] = value
            with self.subTest(key=key), self.assertRaises(S.SupervisorError):
                S.validate_container(info, IMAGE, RUN, ENV)

    def test_container_command_identity_environment_and_mounts_are_bound(self):
        mutations = (("User", "0:0"), ("Entrypoint", ["/bin/sh"]), ("Cmd", ["-c", "true"]),
                     ("WorkingDir", "/tmp"), ("Env", ENV + ["HTTP_PROXY=http://invalid"]),
                     ("Volumes", {"/data": {}}), ("ExposedPorts", {"443/tcp": {}}), ("Healthcheck", {"Test": ["CMD", "true"]}))
        for key, value in mutations:
            info = container(); info["Config"][key] = value
            with self.subTest(key=key), self.assertRaises(S.SupervisorError):
                S.validate_container(info, IMAGE, RUN, ENV)
        for key, value in (("Image", "sha256:" + "f" * 64), ("Mounts", [{"Type": "bind", "Source": "/tmp", "Destination": "/work"}]),
                          ("NetworkSettings", {"Networks": {"bridge": {}}})):
            info = container(); info[key] = value
            with self.subTest(key=key), self.assertRaises(S.SupervisorError):
                S.validate_container(info, IMAGE, RUN, ENV)

    def test_cleanup_refuses_unowned_container_without_any_delete(self):
        docker = Mock()
        info = container(); info["Config"]["Labels"][S.LABEL] = "f" * 32
        docker.inspect.return_value = info
        with self.assertRaisesRegex(S.SupervisorError, "ownership_mismatch"):
            S.cleanup_owned(docker, "triage-mailru-fixed-api-" + RUN, "fixture:" + RUN, IMAGE, RUN)
        docker.run.assert_not_called()

    def test_inspection_permission_error_is_not_treated_as_absence(self):
        docker = object.__new__(S.Docker)
        docker.run = Mock(return_value=(1, b""))
        docker.last_stderr = b"permission denied"
        with self.assertRaisesRegex(S.SupervisorError, "docker_inspection_failed"):
            docker.inspect("container", CID)
        docker.last_stderr = ("Error response from daemon: No such container: " + CID).encode()
        self.assertIsNone(docker.inspect("container", CID))

    def test_source_closure_and_dependency_pins_are_explicit(self):
        self.assertEqual(set(S.HARNESS), set(P.lab.HARNESS_FILES))
        tree = ast.parse((LAB.parent / "provider_coverage.py").read_text())
        importer = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                        and any(isinstance(target, ast.Name) and target.id == "HARNESSES" for target in node.targets))
        self.assertEqual(set(S.HARNESS), set(importer))

        self.assertNotIn("mailru", P.lab.BACKENDS)
        self.assertIn("fixture_mailru.py", S.HARNESS)
        self.assertEqual(self.lock["requirements"]["distributions"], {"cryptography": "50.0.2", "cffi": "2.1.1", "pycparser": "3.1"})
        self.assertTrue(self.lock["base_image"].startswith("docker.io/library/python@sha256:"))
        self.assertEqual(len(S.SOURCE_FILES), len(set(S.SOURCE_FILES)))

    def test_owned_temporary_cleanup_refuses_replaced_root(self):
        with tempfile.TemporaryDirectory(prefix="triage-mailru-fixed-api-") as directory:
            root = Path(directory).resolve()
            marker = root / "preserve"
            marker.write_text("synthetic")
            info = root.stat()
            with self.assertRaisesRegex(S.SupervisorError, "ownership_mismatch"):
                S.cleanup_temporary(root, (info.st_dev, info.st_ino + 1))
            self.assertTrue(marker.exists())


    def test_isolated_job_and_nightly_dependency_are_required(self):
        from test_gcs_oauth_workflow_contract import command, jobs, require, scalar
        from test_provider_gcs_lifecycle_workflow import steps
        workflow = (LAB.parents[1] / ".github/workflows/ci.yml").read_text()
        def validate(text):
            definitions = jobs(text)
            job = definitions["mailru-fixed-api"]
            require(scalar(job, "needs", 4) == "revision" and scalar(job, "runs-on", 4) == "ubuntu-latest"
                    and scalar(job, "timeout-minutes", 4) == "12", "bounded_required_job")
            require("\n    if:" not in job and "continue-on-error" not in job, "no_optional_job")
            parts = steps(job)
            require(len(parts) == 5 and "persist-credentials: false" in parts[0], "closed_job")
            require(command(parts[3]) == ["python", "-B", "scripts/provider-lab/mailru-fixed-api/run_container.py",
                    "--rclone", "$RUNNER_TEMP/rclone-mailru", "--protocol-evidence", "--report", "$RUNNER_TEMP/mailru-read-protocol.json"],
                    "native_qualification_required")
            require(scalar(parts[4], "path", 10) == "${{ runner.temp }}/mailru-read-protocol.json",
                    "sanitized_receipt_only")
            require("mailru-fixed-api" in scalar(definitions["release"], "needs", 4).strip("[]").split(", "),
                    "nightly_dependency_required")
            require("mailru-fixed-api-feasibility.json" not in definitions["linux-provider-evidence"],
                    "no_unqualified_ledger_import")
        validate(workflow)
        for before, after in (("  mailru-fixed-api:\n", "  mailru-fixed-api:\n    if: false\n"),
                              ('--rclone "$RUNNER_TEMP/rclone-mailru"', '--rclone "$RUNNER_TEMP/other"'),
                              ("windows-webdav-bearer, opendrive-fixed-api, gofile-fixed-api, drime-fixed-api, fichier-fixed-api, premiumizeme-fixed-api, putio-fixed-api, linkbox-fixed-api, yandex-fixed-api, box-fixed-api, onedrive-fixed-api, filelu-fixed-api, qingstor-fixed-api, drive-fixed-api, dropbox-fixed-api, oos-fixed-api, zoho-fixed-api, jottacloud-fixed-api, sugarsync-fixed-api, pikpak-fixed-api, dosya-fixed-api, kdrive-fixed-api, gphotos-fixed-api, huaweidrive-fixed-api, mailru-fixed-api, ulozto-fixed-api, iclouddrive-fixed-api, internxt-fixed-api, storj-protocol, mega-fixed-api]", "windows-webdav-bearer, opendrive-fixed-api, gofile-fixed-api, drime-fixed-api, fichier-fixed-api, premiumizeme-fixed-api, putio-fixed-api, linkbox-fixed-api, yandex-fixed-api, box-fixed-api, onedrive-fixed-api, filelu-fixed-api, qingstor-fixed-api, drive-fixed-api, dropbox-fixed-api, oos-fixed-api, zoho-fixed-api, jottacloud-fixed-api, sugarsync-fixed-api, pikpak-fixed-api, dosya-fixed-api, kdrive-fixed-api, gphotos-fixed-api, huaweidrive-fixed-api, storj-protocol, mega-fixed-api]")):
            self.assertIn(before, workflow)
            with self.assertRaises(ValueError):
                validate(workflow.replace(before, after, 1))

class MailruProbeAuthorityTests(unittest.TestCase):
    HOSTS = b"127.0.0.1 cloud.mail.ru\n127.0.0.2 dispatcher.cloud.mail.ru\n127.0.0.3 synthetic-content.mailru.invalid\n"
    def environment(self, hosts=None, start=b"0\n", answers=None):
        hosts = self.HOSTS if hosts is None else hosts
        if answers is None:
            answers = {name: [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 443))]
                       for name, address in (("cloud.mail.ru", "127.0.0.1"), ("dispatcher.cloud.mail.ru", "127.0.0.2"), ("synthetic-content.mailru.invalid", "127.0.0.3"))}
        with patch.object(P.Path, "open", lambda path, mode: io.BytesIO(hosts)), \
             patch.object(P.Path, "read_bytes", return_value=start), \
             patch.object(P.socket, "getaddrinfo", side_effect=lambda name, *args, **kwargs: answers[name]):
            return P.authority_environment()

    def test_three_exact_distinct_private_authorities_and_zero_port_floor_are_required(self):
        self.environment()
        bad = [b"", b"\xff", b"x" * 16385]
        for row in self.HOSTS.splitlines(keepends=True):
            bad += [self.HOSTS.replace(row, b""), self.HOSTS + row,
                    self.HOSTS.replace(row, row.rstrip() + b" alias\n"),
                    self.HOSTS.replace(row, b"::1 " + row.split(b" ", 1)[1]),
                    self.HOSTS.replace(row, row.rstrip() + b".\n")]
        bad += [self.HOSTS.replace(b"127.0.0.2", b"127.0.0.1"),
                self.HOSTS.replace(b"127.0.0.1", b"127.0.0.2")]
        for hosts in bad:
            with self.subTest(hosts=hosts[:60]), self.assertRaises(P.ProbeError):
                self.environment(hosts=hosts)
        for start in (b"1\n", b"443\n", b"00\n", b"0"):
            with self.subTest(start=start), self.assertRaises(P.ProbeError):
                self.environment(start=start)

    def test_each_resolver_must_only_return_its_own_expected_ipv4_socket(self):
        for name in ("cloud.mail.ru", "dispatcher.cloud.mail.ru", "synthetic-content.mailru.invalid"):
            for bad in ([], [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.1", 443))],
                        [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("::1", 443))],
                        [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.2" if name == "cloud.mail.ru" else "127.0.0.1", 443))]):
                answers = {host: [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 443))]
                           for host, address in (("cloud.mail.ru", "127.0.0.1"), ("dispatcher.cloud.mail.ru", "127.0.0.2"), ("synthetic-content.mailru.invalid", "127.0.0.3"))}
                answers[name] = bad
                with self.subTest(authority=name, answers=bad), self.assertRaises(P.ProbeError):
                    self.environment(answers=answers)

if __name__ == "__main__":
    unittest.main()
