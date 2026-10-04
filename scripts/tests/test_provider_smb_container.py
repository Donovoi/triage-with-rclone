"""Pure supervisor contracts: no Docker, network, service or native execution."""

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1] / "provider-lab" / "smb" / "run_container.py"
SPEC = importlib.util.spec_from_file_location("smb_container_test_subject", SOURCE)
SUBJECT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUBJECT)
RUN = "b" * 32
IMAGE = "sha256:" + "a" * 64
NAME = "triage-smb-" + RUN
TAG = "triage-smb-fixture:" + RUN
IDENTITY = {"version": "1.75.1", "sha256": "c" * 64}
SOURCES = {"probe_samba.py": "d" * 64, "build-lock.json": "e" * 64}


def probe():
    return {
        "schema_version": 1, "scope": "smb_samba_feasibility_only", "status": "passed",
        "ledger_eligible": False, "commands_total": 16, "errors": [],
        "runtime": {"platform": "linux/amd64", "uid": 10001, "gid": 10001,
                    "samba_version": "4.22.11-Debian", "rclone_version": IDENTITY["version"],
                    "rclone_sha256": IDENTITY["sha256"], "smbd_sha256": "f" * 64,
                    "probe_sha256": SOURCES["probe_samba.py"], "lock_sha256": SOURCES["build-lock.json"]},
        "checks": dict.fromkeys(SUBJECT.PROBE_CHECKS, True),
        "cleanup": dict.fromkeys(SUBJECT.PROBE_CLEANUP, True),
    }


def container():
    return {
        "Id": "f" * 64, "Image": IMAGE,
        "Config": {"Labels": {SUBJECT.LABEL: RUN, SUBJECT.KIND: "smb-probe"},
                   "User": "10001:10001", "Entrypoint": ["/usr/bin/python3"],
                   "Cmd": ["/opt/synthetic-smb/probe_samba.py", "--lock", "/opt/synthetic-smb/build-lock.json"]},
        "HostConfig": {"NetworkMode": "none", "ReadonlyRootfs": True, "Privileged": False,
                       "CapDrop": ["ALL"], "CapAdd": None, "SecurityOpt": ["no-new-privileges"],
                       "CgroupnsMode": "private", "IpcMode": "private", "Init": True,
                       "Memory": 536870912, "NanoCpus": 1000000000, "PidsLimit": 64,
                       "Tmpfs": {"/run/synthetic-smb": SUBJECT.TMPFS}},
        "Mounts": [], "NetworkSettings": {"Networks": {"none": {}}}, "State": {"Running": False},
    }


class ProbeContract(unittest.TestCase):
    def test_success_is_feasibility_only(self):
        self.assertEqual(SUBJECT.validate_probe(probe(), IDENTITY, SOURCES), probe())

    def test_scope_types_extra_fields_and_contradictions_fail_closed(self):
        mutations = [
            ("schema_version", True), ("scope", "provider_pass"), ("ledger_eligible", True),
            ("commands_total", True), ("commands_total", 0), ("commands_total", 65), ("commands_total", 15),
            ("errors", ["token=private"]), ("errors", ["failure"]),
            ("status", "failed"), ("account", "unexpected"), ("checks", []),
        ]
        for key, value in mutations:
            with self.subTest(field=key, value=value):
                item = probe()
                item[key] = value
                with self.assertRaises(SUBJECT.SupervisorError):
                    SUBJECT.validate_probe(item, IDENTITY, SOURCES)

    def test_runtime_binding_is_exact(self):
        for key in SUBJECT.PROBE_RUNTIME:
            with self.subTest(field=key):
                item = probe()
                item["runtime"][key] = None
                with self.assertRaises(SUBJECT.SupervisorError):
                    SUBJECT.validate_probe(item, IDENTITY, SOURCES)

    def test_each_observation_and_cleanup_is_required(self):
        for field in ("checks", "cleanup"):
            for key in probe()[field]:
                with self.subTest(field=field, key=key):
                    item = probe()
                    item[field][key] = False
                    with self.assertRaises(SUBJECT.SupervisorError):
                        SUBJECT.validate_probe(item, IDENTITY, SOURCES)

    def test_honest_failure_can_be_retained_without_promotion(self):
        item = probe()
        item["status"] = "failed"
        item["checks"]["bad_password_rejected"] = False
        self.assertEqual(SUBJECT.validate_probe(item, IDENTITY, SOURCES), item)

    def test_json_rejects_duplicate_keys_and_excessive_output(self):
        for data in (b'{"status":1,"status":2}', b"x" * 262145, b"not json"):
            with self.assertRaises(SUBJECT.SupervisorError):
                SUBJECT.parse_json(data)


class IsolationContract(unittest.TestCase):
    def test_expected_container_and_tmpfs_inspection(self):
        info = container()
        SUBJECT.validate_container(info, IMAGE, RUN)
        info["Mounts"] = [{"Type": "tmpfs", "Destination": "/run/synthetic-smb", "Source": ""}]
        SUBJECT.validate_container(info, IMAGE, RUN)

    def test_isolation_changes_are_rejected(self):
        mutations = [("NetworkMode", "bridge"), ("ReadonlyRootfs", False), ("Privileged", True),
                     ("CapDrop", []), ("CapAdd", ["SYS_ADMIN"]), ("SecurityOpt", []),
                     ("CgroupnsMode", "host"), ("IpcMode", "host"), ("PidMode", "host"),
                     ("UTSMode", "host"), ("UsernsMode", "host"), ("Init", False),
                     ("Memory", 0), ("NanoCpus", 0), ("PidsLimit", 0), ("Tmpfs", {}),
                     ("Binds", ["/:/host"]), ("Devices", [{}]), ("DeviceRequests", [{}]),
                     ("PortBindings", {"445/tcp": [{}]}), ("ExtraHosts", ["host:1.2.3.4"])]
        for key, value in mutations:
            with self.subTest(field=key):
                info = container()
                info["HostConfig"][key] = value
                with self.assertRaises(SUBJECT.SupervisorError):
                    SUBJECT.validate_container(info, IMAGE, RUN)

    def test_malformed_and_inherited_resources_rejected(self):
        cases = []
        for field in ("Config", "HostConfig", "NetworkSettings"):
            item = container()
            item[field] = None
            cases.append(item)
        for key, value in (("Labels", None), ("User", "0"), ("Volumes", {"/data": {}}),
                           ("ExposedPorts", {"445/tcp": {}}), ("Entrypoint", ["/bin/sh"])):
            item = container()
            item["Config"][key] = value
            cases.append(item)
        for mounts in ([None], [{"Type": "bind", "Destination": "/run/synthetic-smb"}]):
            item = container()
            item["Mounts"] = mounts
            cases.append(item)
        item = container()
        item["NetworkSettings"]["Networks"]["bridge"] = {}
        cases.append(item)
        for item in cases:
            with self.assertRaises(SUBJECT.SupervisorError):
                SUBJECT.validate_container(item, IMAGE, RUN)

    def test_command_has_no_mounts_ports_or_privileges(self):
        args = SUBJECT.create_args(NAME, IMAGE, RUN)
        self.assertEqual(args[args.index("--network") + 1], "none")
        self.assertEqual(args[args.index("--cap-drop") + 1], "ALL")
        self.assertIn("--read-only", args)
        self.assertIn("--init", args)
        self.assertEqual(args.count("--tmpfs"), 1)
        self.assertFalse(set(args) & {"--privileged", "--mount", "--volume", "-v", "--publish", "-p"})
        with self.assertRaises(SUBJECT.SupervisorError):
            SUBJECT.create_args("unrelated", IMAGE, RUN)


class CleanupContract(unittest.TestCase):
    def test_inspect_only_exact_not_found_counts_as_absence(self):
        docker = object.__new__(SUBJECT.Docker)
        for kind, target in (("container", NAME), ("image", IMAGE)):
            for prefix in ("Error: ", "Error response from daemon: "):
                docker.last_stderr = (prefix + "No such " + kind + ": " + target + "\n").encode()
                with mock.patch.object(docker, "run", return_value=(1, b"[]")):
                    self.assertIsNone(docker.inspect(kind, target))
        for message in (b"Cannot connect to Docker daemon", b"permission denied", b"", b"Error: No such image: other"):
            docker.last_stderr = message
            with mock.patch.object(docker, "run", return_value=(1, b"[]")):
                with self.assertRaisesRegex(SUBJECT.SupervisorError, "docker_inspection_failed"):
                    docker.inspect("image", IMAGE)

    def test_owned_cleanup_is_exact_and_bounded(self):
        docker = mock.Mock()
        item = container()
        item["State"]["Running"] = True
        owned_image = {"Id": IMAGE, "Config": copy.deepcopy(item["Config"])}
        docker.inspect.side_effect = [item, None, owned_image, owned_image, None, None]
        self.assertEqual(SUBJECT.cleanup_owned(docker, NAME, TAG, IMAGE, RUN),
                         {"container_removed": True, "image_removed": True})
        self.assertEqual(docker.run.call_args_list, [
            mock.call(["stop", "--time", "5", "f" * 64], timeout=15, allow_failure=True),
            mock.call(["rm", "--force", "f" * 64], timeout=15),
            mock.call(["image", "rm", IMAGE], timeout=30)])

    def test_foreign_container_is_not_removed(self):
        docker = mock.Mock()
        item = container()
        item["Config"]["Labels"][SUBJECT.LABEL] = "another-run"
        docker.inspect.return_value = item
        with self.assertRaisesRegex(SUBJECT.SupervisorError, "cleanup_container_ownership_mismatch"):
            SUBJECT.cleanup_owned(docker, NAME, TAG, IMAGE, RUN)
        docker.run.assert_not_called()

    def test_foreign_image_is_not_removed(self):
        docker = mock.Mock()
        docker.inspect.side_effect = [None, None, {"Id": IMAGE, "Config": {"Labels": {}}}]
        with self.assertRaisesRegex(SUBJECT.SupervisorError, "cleanup_image_ownership_mismatch"):
            SUBJECT.cleanup_owned(docker, NAME, TAG, IMAGE, RUN)
        docker.run.assert_not_called()

    def test_retained_reference_never_counts_as_image_cleanup(self):
        docker = mock.Mock()
        owned = {"Id": IMAGE, "Config": copy.deepcopy(container()["Config"])}
        docker.inspect.side_effect = [None, None, owned, owned, owned]
        self.assertFalse(SUBJECT.cleanup_owned(docker, NAME, TAG, IMAGE, RUN)["image_removed"])
        docker.run.assert_called_once_with(["image", "rm", IMAGE], timeout=30)

    def test_retargeted_tag_is_not_removed(self):
        docker = mock.Mock()
        owned = {"Id": IMAGE, "Config": copy.deepcopy(container()["Config"])}
        foreign = copy.deepcopy(owned)
        foreign["Id"] = "sha256:" + "0" * 64
        docker.inspect.side_effect = [None, None, owned, foreign]
        with self.assertRaisesRegex(SUBJECT.SupervisorError, "cleanup_image_tag_changed"):
            SUBJECT.cleanup_owned(docker, NAME, TAG, IMAGE, RUN)
        docker.run.assert_not_called()

    def test_replaced_temporary_directory_is_preserved(self):
        with tempfile.TemporaryDirectory(prefix="triage-smb-container-") as directory:
            root = Path(directory)
            marker = root / "preserve"
            marker.write_text("owned test")
            with self.assertRaisesRegex(SUBJECT.SupervisorError, "temporary_ownership_mismatch"):
                SUBJECT.cleanup_temporary(root, (-1, -1))
            self.assertTrue(marker.exists())

    def test_build_phase_parser_rejects_arbitrary_text(self):
        data = (b"#8 0.250 SMB_BUILD_PHASE=metadata\n#8 0.300 SMB_BUILD_PHASE=deb-download\n"
                b"echo SMB_BUILD_PHASE=install\nSMB_BUILD_PHASE=secret-value\n")
        self.assertEqual(SUBJECT.BUILD_PHASE.findall(data), [b"metadata", b"deb-download"])

    def test_resource_cleanup_failure_still_removes_private_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            binary, output = Path(directory) / "synthetic", Path(directory) / "receipt.json"
            binary.write_bytes(b"synthetic non-executable input")
            identity = {"version": "1.75.1", "sha256": SUBJECT.digest(binary)}
            docker = mock.Mock(build_phase="metadata")
            docker.run.side_effect = [(0, b'{"OSType":"linux","Architecture":"amd64"}'),
                                     (0, b""), SUBJECT.SupervisorError("docker_command_failed")]
            cleanup = SUBJECT.cleanup_temporary
            with mock.patch.object(SUBJECT.sys, "platform", "linux"), \
                    mock.patch.dict(SUBJECT.os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}), \
                    mock.patch.object(SUBJECT, "runtime_identity", return_value=identity), \
                    mock.patch.object(SUBJECT, "Docker", return_value=docker), \
                    mock.patch.object(SUBJECT, "cleanup_owned", side_effect=SUBJECT.SupervisorError("docker_inspection_failed")), \
                    mock.patch.object(SUBJECT, "cleanup_temporary", wraps=cleanup) as remove:
                result = SUBJECT.run(binary, output)
            self.assertFalse(result["success"])
            self.assertTrue(result["cleanup"]["temporary_removed"])
            self.assertEqual(result["errors"], ["docker_command_failed", "supervisor_cleanup_failed"])
            self.assertEqual(result["build_phase"], "metadata")
            remove.assert_called_once()
            self.assertFalse(remove.call_args.args[0].exists())
            self.assertEqual(json.loads(output.read_text()), result)


if __name__ == "__main__":
    unittest.main()
