"""Independent container contract tests: no Docker, native binary or listener."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1] / "provider-lab/pcloud-oauth/run_container.py"
SPEC = importlib.util.spec_from_file_location("pcloud_oauth_container_subject", SOURCE)
S = importlib.util.module_from_spec(SPEC)
exec(compile(SOURCE.read_bytes(), str(SOURCE), "exec"), S.__dict__)
RUN = "b" * 32
IMAGE = "sha256:" + "a" * 64
CONTAINER = "f" * 64
NAME = "triage-pcloud-oauth-" + RUN
TAG = "triage-pcloud-oauth-fixture:" + RUN
IDENTITY = {"version": "1.76.2", "sha256": "c" * 64}
SOURCES = {name: "d" * 64 for name in S.SOURCE_FILES}
LOCK = json.loads((SOURCE.parent / "build-lock.json").read_bytes())
START = "2026-10-04T12:00:01.000000Z"
FINISH = "2026-10-04T12:00:05.000000Z"
ENV = ["LANG=C.UTF-8", "HOME=/work"]


def probe():
    return {"schema_version": 1, "scope": "pcloud_oauth_callback_feasibility", "ledger_eligible": False,
            "started_utc": "2026-10-04T12:00:02.000000Z", "finished_utc": "2026-10-04T12:00:04.000000Z",
            "runtime": {"platform": "linux", "architecture": "amd64", "uid": 10001, "gid": 10001,
                        "python_version": "3.12.15", "cryptography_version": "50.0.2",
                        "rclone_version": "1.76.2", "rclone_sha256": "c" * 64, "probe_sha256": "d" * 64,
                        "fixture_manifest_sha256": "c990bbd4909b227aae4c70d26f9da5534740a2eb10337ced47977f915fa617be"},
            "checks": {"environment": True, "version_binding": True, "initial_config_question": True,
                       "callback_ownership": True, "authorize": True, "token_exchange": True,
                       "config_persisted": True, "fresh_child_read": True, "source_preserved": True,
                       "post_auth_config_preserved": True, "request_sequence": True},
            "observations": {"native_commands": 4, "http_transactions": 8, "callback_requests": 2, "https_requests": 6},
            "cleanup": {"children_stopped": True, "listeners_closed": True, "temporary_removed": True},
            "success": True, "errors": []}


def image():
    return {"Id": IMAGE, "Architecture": "amd64", "Os": "linux", "Config": {
        "Labels": {S.LABEL: RUN, S.KIND: "pcloud-oauth-probe", S.SOURCE_LABEL: S.canonical_hash(SOURCES)},
        "User": "10001:10001", "Entrypoint": ["/opt/fixture/venv/bin/python"],
        "Cmd": ["/opt/fixture/scripts/provider-lab/pcloud-oauth/probe.py", "--rclone", "/opt/fixture/rclone",
                "--manifest", "/opt/fixture/rclone-version.env"], "WorkingDir": "/work", "Env": ENV}}


def container(status="created"):
    return {"Id": CONTAINER, "Image": IMAGE, "Config": copy.deepcopy(image()["Config"]),
            "HostConfig": {"NetworkMode": "none", "ReadonlyRootfs": True, "Privileged": False,
                           "CapDrop": ["ALL"], "CapAdd": None, "SecurityOpt": ["no-new-privileges"],
                           "CgroupnsMode": "private", "IpcMode": "private", "Init": True,
                           "Memory": 536870912, "NanoCpus": 1000000000, "PidsLimit": 64,
                           "Tmpfs": {"/work": "rw,nosuid,nodev,noexec,size=32m,mode=0700,uid=10001,gid=10001"}},
            "Mounts": [], "NetworkSettings": {"Networks": {"none": {}}},
            "State": {"Running": False, "Status": status, "ExitCode": 0, "OOMKilled": False, "Error": ""}}


class ProbeContract(unittest.TestCase):
    def validate(self, item):
        return S.validate_probe(item, IDENTITY, SOURCES, LOCK, START, FINISH)

    def test_positive_is_only_feasibility_and_accepts_future_manifest_pin(self):
        self.assertEqual(self.validate(probe()), probe())
        self.assertFalse(probe()["ledger_eligible"])

    def test_closed_schema_types_and_promotion_rejected(self):
        for key, value in (("schema_version", True), ("scope", "rclone_backend_protocol_fixture"),
                           ("ledger_eligible", True), ("success", 1), ("errors", ["private=token"]),
                           ("extra", True), ("observations", []), ("cleanup", {})):
            with self.subTest(key=key):
                item = probe(); item[key] = value
                with self.assertRaises(S.SupervisorError):
                    self.validate(item)

    def test_every_required_check_and_cleanup_blocks_success(self):
        for field in ("checks", "cleanup"):
            for key in probe()[field]:
                for value in (False, 1, "true"):
                    with self.subTest(field=field, key=key, value=value):
                        item = probe(); item[field][key] = value
                        with self.assertRaises(S.SupervisorError):
                            self.validate(item)

    def test_explicit_failed_probe_is_preserved(self):
        item = probe(); item["checks"]["callback_ownership"] = False
        item["success"] = False; item["errors"] = ["callback_not_owned"]
        self.assertIs(self.validate(item), item)

    def test_exact_observed_counts_and_no_inflation(self):
        for key in probe()["observations"]:
            for value in (True, -1, 0, probe()["observations"][key] + 1):
                with self.subTest(key=key, value=value):
                    item = probe(); item["observations"][key] = value
                    with self.assertRaises(S.SupervisorError):
                        self.validate(item)

    def test_runtime_sources_platform_and_deps_are_bound(self):
        for key, value in (("platform", "windows"), ("architecture", "arm64"), ("uid", 0), ("gid", True),
                           ("python_version", "3.13.0"), ("cryptography_version", "46.0.5"),
                           ("rclone_version", "1.75.1"), ("rclone_sha256", "e" * 64),
                           ("probe_sha256", "e" * 64), ("fixture_manifest_sha256", "e" * 64)):
            with self.subTest(key=key):
                item = probe(); item["runtime"][key] = value
                with self.assertRaises(S.SupervisorError):
                    self.validate(item)

    def test_initial_empty_runtime_preserves_failed_preflight_only(self):
        item = probe()
        item["success"] = False
        item["checks"]["version_binding"] = False
        item["errors"] = ["privilege_boundary_required"]
        for key in ("cryptography_version", "rclone_version", "rclone_sha256"):
            item["runtime"][key] = ""
        self.assertIs(self.validate(item), item)
        for field, key, value in (("runtime", "probe_sha256", "e" * 64),
                                  ("runtime", "fixture_manifest_sha256", "e" * 64),
                                  ("runtime", "python_version", ""),
                                  ("runtime", "uid", 0),
                                  ("checks", "version_binding", True)):
            with self.subTest(field=field, key=key):
                changed = copy.deepcopy(item); changed[field][key] = value
                with self.assertRaises(S.SupervisorError):
                    self.validate(changed)
        item["success"] = True
        with self.assertRaises(S.SupervisorError):
            self.validate(item)

    def test_partial_or_mixed_runtime_placeholders_are_rejected(self):
        fields = ("cryptography_version", "rclone_version", "rclone_sha256")
        for mask in range(1, 7):
            with self.subTest(mask=mask):
                item = probe(); item["success"] = False
                item["checks"]["version_binding"] = False; item["errors"] = ["preflight_failed"]
                for index, key in enumerate(fields):
                    if mask & (1 << index):
                        item["runtime"][key] = ""
                with self.assertRaises(S.SupervisorError):
                    self.validate(item)

    def test_times_are_real_utc_and_inside_this_invocation(self):
        for key, value in (("started_utc", "2026-10-04T12:00:00Z"), ("finished_utc", "2026-10-04T12:00:06Z"),
                           ("finished_utc", "2026-10-04T12:00:01Z"), ("started_utc", "2026-99-04T12:00:02Z"),
                           ("started_utc", "2026-10-04T12:00:02+00:00"), ("finished_utc", True)):
            with self.subTest(key=key, value=value):
                item = probe(); item[key] = value
                with self.assertRaises(S.SupervisorError):
                    self.validate(item)

    def test_duplicate_nonfinite_and_large_json_are_rejected(self):
        for raw in (b'{"success":true,"success":false}', b'{"x":NaN}', b'{"x":Infinity}', b'{}{}', b'x' * 262145):
            with self.subTest(raw=raw[:50]), self.assertRaises(S.SupervisorError):
                S.parse_json(raw)


class Isolation(unittest.TestCase):
    def test_exact_create_has_no_network_mount_or_mutable_image(self):
        argv = S.create_args(NAME, IMAGE, RUN)
        self.assertEqual(argv[argv.index("--network") + 1], "none")
        self.assertEqual(argv[argv.index("--tmpfs") + 1], "/work:rw,nosuid,nodev,noexec,size=32m,mode=0700,uid=10001,gid=10001")
        self.assertNotIn("--mount", argv); self.assertNotIn("--volume", argv); self.assertNotIn("--publish", argv)
        self.assertIn("/opt/fixture/rclone", argv)
        self.assertNotIn("/work/rclone", argv)
        with self.assertRaises(S.SupervisorError):
            S.create_args(NAME, "python:3.12", RUN)
        S.validate_container(container(), IMAGE, RUN, ENV)

    def test_every_material_isolation_drift_is_rejected(self):
        mutations = {"NetworkMode": "bridge", "ReadonlyRootfs": False, "Privileged": True, "CapAdd": ["SYS_ADMIN"],
                     "CapDrop": [], "SecurityOpt": [], "PidMode": "host", "IpcMode": "host", "UTSMode": "host",
                     "CgroupnsMode": "host", "UsernsMode": "host", "Init": False, "Memory": 0, "NanoCpus": 0,
                     "PidsLimit": 0, "Tmpfs": {"/work": "rw,exec"}, "Binds": ["/:/host"], "Mounts": [{}],
                     "Devices": [{}], "DeviceRequests": [{}], "PortBindings": {"53682/tcp": [{}]}, "ExtraHosts": ["x:1.2.3.4"]}
        for key, value in mutations.items():
            with self.subTest(key=key):
                item = container(); item["HostConfig"][key] = value
                with self.assertRaises(S.SupervisorError):
                    S.validate_container(item, IMAGE, RUN, ENV)

    def test_image_and_command_or_environment_substitution_rejected(self):
        S.validate_image(image(), IMAGE, RUN, S.canonical_hash(SOURCES))
        for key, value in (("User", "0"), ("Cmd", ["/bin/sh"]), ("Entrypoint", ["/bin/sh"]),
                           ("Env", ["HTTPS_PROXY=https://unowned"]), ("Volumes", {"/host": {}}),
                           ("Healthcheck", {"Test": ["CMD", "unsafe"]})):
            with self.subTest(key=key):
                item = container(); item["Config"][key] = value
                with self.assertRaises(S.SupervisorError):
                    S.validate_container(item, IMAGE, RUN, ENV)

    def test_cleanup_never_removes_unowned_container(self):
        docker = mock.Mock(); item = container(); item["Config"]["Labels"][S.LABEL] = "e" * 32
        docker.inspect.return_value = item
        with self.assertRaisesRegex(S.SupervisorError, "ownership"):
            S.cleanup_owned(docker, NAME, TAG, IMAGE, RUN)
        docker.run.assert_not_called()

    def test_cleanup_never_removes_retargeted_image(self):
        docker = mock.Mock(); changed = image(); changed["Id"] = "sha256:" + "e" * 64
        docker.inspect.side_effect = [None, None, image(), changed]
        with self.assertRaisesRegex(S.SupervisorError, "tag_changed"):
            S.cleanup_owned(docker, NAME, TAG, IMAGE, RUN)
        docker.run.assert_not_called()

    def test_docker_client_drops_ambient_proxies_and_remote_daemon(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(S.shutil, "which", return_value="/usr/bin/docker"), \
             mock.patch.dict(S.os.environ, {"DOCKER_HOST": "tcp://unowned:2375", "HTTPS_PROXY": "https://unowned",
                                           "RCLONE_CONFIG": "unowned", "HTTPCLIENT_TRACE": "1"}):
            docker = S.Docker(Path(tmp).resolve())
            self.assertEqual(docker.command[-2:], ["--host", "unix:///var/run/docker.sock"])
            self.assertEqual(set(docker.env), {"PATH", "HOME", "LANG"})
            self.assertEqual(list(docker.config.iterdir()), [])


class Packaging(unittest.TestCase):
    def test_lock_recipe_and_dependency_file_are_consistent(self):
        lock = S.read_lock()
        self.assertEqual(lock["base_image"], "docker.io/library/python@sha256:9901e0a8d75037d8242ed43155cbcb2d1f61be1356383d8054afb59fd50e39c4")
        self.assertEqual(lock["base_config_digest"], "sha256:3abf66fa95bf9285d35eac802319797d29d01fbcfef9c0cd560f73d97f4289e8")
        recipe = (SOURCE.parent / "Dockerfile").read_text()
        for required in ("--require-hashes", "--only-binary=:all:", "--index-url https://pypi.org/simple", "USER 10001:10001"):
            self.assertIn(required, recipe)
        self.assertNotIn("RCLONE_VERSION=1.75.1", recipe)

    def test_future_runtime_manifest_not_duplicate_package_pin(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); binary = root / "rclone"
            binary.write_bytes(b"synthetic never executed")
            sha = hashlib.sha256(binary.read_bytes()).hexdigest()
            lines = ["RCLONE_VERSION=1.76.2"] + [key + "=" + sha for key in (
                "RCLONE_EXE_SHA256", "RCLONE_WINDOWS_ZIP_SHA256", "RCLONE_LINUX_ZIP_SHA256", "RCLONE_LINUX_EXE_SHA256")]
            manifest = root / "rclone-version.env"; manifest.write_text("\n".join(lines) + "\n")
            with mock.patch.object(S, "REPOSITORY", root):
                self.assertEqual(S.runtime_identity(binary), {"version": "1.76.2", "sha256": sha})
                for extra in ("RCLONE_VERSION=1.76.2", "OTHER=1", "RCLONE_VERSION=true"):
                    manifest.write_text("\n".join(lines + [extra]) + "\n")
                    with self.assertRaises(S.SupervisorError):
                        S.runtime_identity(binary)

    def test_context_is_exact_and_source_changes_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); repo = root / "repo"; repo.mkdir()
            source = repo / "scripts/provider-lab/pcloud-oauth/Dockerfile"
            source.parent.mkdir(parents=True); source.write_bytes(b"FROM synthetic\n")
            binary = root / "rclone"; binary.write_bytes(b"synthetic")
            hashes = {"scripts/provider-lab/pcloud-oauth/Dockerfile": S.digest(source)}
            with mock.patch.object(S, "REPOSITORY", repo):
                S.stage_context(root / "context", binary, {"sha256": S.digest(binary)}, hashes)
                self.assertEqual({p.relative_to(root / "context").as_posix() for p in (root / "context").rglob("*") if p.is_file()},
                                 set(hashes) | {"Dockerfile", "rclone", "source-manifest.json"})
                source.write_bytes(b"changed")
                with self.assertRaisesRegex(S.SupervisorError, "staged_source_changed"):
                    S.stage_context(root / "context2", binary, {"sha256": S.digest(binary)}, hashes)


class FakeDocker:
    """Only the expected supervisor operations exist; nothing executes."""
    def __init__(self, root):
        self.root = root; self.last_stderr = b""; self.build_phase = "manifest"
        self.created = False; self.started = False; self.built = False; self.calls = []
        self.inner = probe(); self.final_mutation = None; self.cleanup_failure = False
        self.interrupt = False

    def run(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if args[0] == "info":
            return 0, b'{"OSType":"linux","Architecture":"x86_64"}'
        if args[:2] == ["image", "pull"]:
            return 0, b""
        if args[0] == "build":
            Path(args[args.index("--iidfile") + 1]).write_text(IMAGE)
            self.built = True; return 0, b""
        if args[0] == "create":
            self.created = True; return 0, CONTAINER.encode()
        if args[0] == "start":
            if self.interrupt:
                raise KeyboardInterrupt
            self.started = True; return 0, json.dumps(self.inner).encode()
        if args[0] == "rm":
            if self.cleanup_failure:
                raise S.SupervisorError("docker_command_failed")
            self.created = False; return 0, b""
        if args[:2] == ["image", "rm"]:
            self.built = False; return 0, b""
        raise AssertionError(args)

    def inspect(self, kind, target):
        if target == LOCK["base_image"]:
            return {"Id": LOCK["base_config_digest"], "Architecture": "amd64", "Os": "linux"}
        if kind == "image":
            return image() if self.built else None
        if kind == "container":
            if not self.created:
                return None
            item = container("exited" if self.started else "created")
            if self.started and self.final_mutation:
                self.final_mutation(item)
            return item
        raise AssertionError((kind, target))


class Orchestration(unittest.TestCase):
    def execute(self, prepare=None, drift=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); report = root / "report.json"
            instances = []
            def factory(directory):
                obj = FakeDocker(directory)
                if prepare:
                    prepare(obj)
                instances.append(obj); return obj
            changed = dict(SOURCES); changed["rclone-version.env"] = "e" * 64
            with mock.patch.object(S.sys, "platform", "linux"), mock.patch.dict(S.os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}), \
                 mock.patch.object(S, "runtime_identity", return_value=IDENTITY), mock.patch.object(S, "source_hashes", side_effect=[SOURCES, changed if drift else SOURCES]), \
                 mock.patch.object(S, "read_lock", return_value=LOCK), mock.patch.object(S, "stage_context"), \
                 mock.patch.object(S, "Docker", side_effect=factory), mock.patch.object(S.uuid, "uuid4", return_value=mock.Mock(hex=RUN)), \
                 mock.patch.object(S, "utc_now", side_effect=["2026-10-04T12:00:00Z", START, FINISH, "2026-10-04T12:00:06Z"]), \
                 mock.patch.object(S.subprocess, "Popen", side_effect=AssertionError("native_execution_forbidden")):
                result = S.run(root / "rclone", report)
            self.assertEqual(json.loads(report.read_bytes()), result)
            self.assertFalse(result["ledger_eligible"])
            self.assertFalse(instances[0].root.exists())
            return result, instances[0]

    def test_nominal_success_binds_source_and_cleans_owned_resources(self):
        result, docker = self.execute()
        self.assertTrue(result["success"]); self.assertTrue(all(result["cleanup"].values()))
        self.assertEqual(result["source_sha256"], SOURCES)
        self.assertEqual(result["dependency_lock_sha256"], LOCK["requirements"]["sha256"])
        start = next(x for x in docker.calls if x[0][0] == "start")
        self.assertEqual(start[0], ["start", "--attach", CONTAINER])
        self.assertEqual(start[1]["timeout"], 90); self.assertEqual(start[1]["output_limit"], 262144)
        self.assertFalse(docker.created); self.assertFalse(docker.built)

    def test_cleanup_failure_cannot_promote_inner_success(self):
        result, _ = self.execute(lambda d: setattr(d, "cleanup_failure", True))
        self.assertFalse(result["success"]); self.assertTrue(result["probe"]["success"])
        self.assertIn("supervisor_cleanup_failed", result["errors"])

    def test_source_change_after_pass_is_sticky_failure(self):
        result, _ = self.execute(drift=True)
        self.assertFalse(result["success"]); self.assertIn("source_or_runtime_changed", result["errors"])

    def test_interrupt_preserves_failure_and_still_cleans_owned_resources(self):
        result, docker = self.execute(lambda d: setattr(d, "interrupt", True))
        self.assertFalse(result["success"])
        self.assertIn("supervisor_interrupted", result["errors"])
        self.assertTrue(all(result["cleanup"].values()))
        self.assertFalse(docker.created); self.assertFalse(docker.built)

    def test_late_container_network_or_oom_change_fails(self):
        for mutate in (lambda item: item["HostConfig"].update(NetworkMode="bridge"),
                       lambda item: item["State"].update(OOMKilled=True),
                       lambda item: item["State"].update(ExitCode=1)):
            with self.subTest(mutate=mutate):
                result, _ = self.execute(lambda d: setattr(d, "final_mutation", mutate))
                self.assertFalse(result["success"]); self.assertTrue(result["errors"])

    def test_inner_failed_check_no_cleanup_or_inflated_mode_never_passes(self):
        for field in ("checks", "cleanup"):
            def prepare(d):
                key = next(iter(d.inner[field])); d.inner[field][key] = False
            result, _ = self.execute(prepare)
            self.assertFalse(result["success"]); self.assertIn("probe_success_contradiction", result["errors"])

    def test_host_execution_gate_stops_before_docker(self):
        with mock.patch.object(S.sys, "platform", "win32"), mock.patch.object(S, "Docker") as docker:
            with self.assertRaisesRegex(S.SupervisorError, "github_hosted_linux_required"):
                S.run(Path("rclone"), Path("report"))
            docker.assert_not_called()


if __name__ == "__main__":
    unittest.main()
