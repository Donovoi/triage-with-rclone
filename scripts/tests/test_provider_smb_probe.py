"""Pure/mocked Samba feasibility tests. Never starts Samba, Docker or rclone."""
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

SOURCE = Path(__file__).parents[1] / "provider-lab" / "smb" / "probe_samba.py"
spec = importlib.util.spec_from_file_location("smb_probe", SOURCE)
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)


def runtime_manifest(binary_hash, version="1.76.2"):
    return ("# Synthetic future stable runtime\n"
            f"RCLONE_VERSION={version}\nRCLONE_EXE_SHA256={'a' * 64}\n"
            f"RCLONE_WINDOWS_ZIP_SHA256={'b' * 64}\nRCLONE_LINUX_ZIP_SHA256={'c' * 64}\n"
            f"RCLONE_LINUX_EXE_SHA256={binary_hash}\n")


def listing():
    return {"list": [{"Path": name, "Name": name.rsplit("/", 1)[-1], "Size": len(body),
                      "IsDir": False, "ModTime": "2024-01-01T00:00:00.123Z"}
                     for name, body in P.FILES.items()]}


def error(kind):
    return json.dumps({"error": "loopback: call failed: " + (P.AUTH_CAUSE if kind == "password" else "object not found"),
                       "path": "operations/copyfile", "status": 500}).encode()


def status():
    return "\n".join(["Uid:\t10001\t10001\t10001\t10001", "Gid:\t10001\t10001\t10001\t10001",
                      "Groups:\t10001", "NoNewPrivs:\t1"] + [key + ":\t0000000000000000"
                      for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")])


def mounts():
    return ("20 1 0:1 / / ro,relatime - overlay overlay ro\n"
            "21 20 0:2 / /run/synthetic-smb rw,nosuid,nodev,noexec - tmpfs tmpfs rw,size=32768k\n")


class PureTests(unittest.TestCase):
    def test_fixed_config_scope_and_security(self):
        config = P.samba_config()
        for value in ("interfaces = 127.0.0.1", "smb ports = 15445", "map to guest = Never",
                      "server signing = mandatory", "security = user", "ntlm auth = ntlmv2-only",
                      "read only = yes", "guest ok = no", "printable = no", "disable netbios = yes",
                      "follow symlinks = no", "wide links = no", "rpc_server:default = disabled"):
            self.assertIn(value, config)
        self.assertEqual([line for line in config.splitlines() if line.startswith("[")], ["[global]", "[SYNTHETIC]"])
        for forbidden in ("include =", "[homes]", "force user", "admin users", "preexec", "root preexec"):
            self.assertNotIn(forbidden, config)
        with self.assertRaisesRegex(P.ProbeError, "fixed_runtime_root_required"):
            P.samba_config(Path("/arbitrary"))

    def test_rclone_config_rejects_injected_password(self):
        config = P.rclone_config("a" * 40)
        self.assertIn("host = 127.0.0.1\nport = 15445", config)
        self.assertIn("use_kerberos = false", config)
        for value in ("a\ntype = local", "", "x" * 257, "secret space"):
            with self.subTest(value_length=len(value)), self.assertRaises(P.ProbeError):
                P.rclone_config(value)

    def test_json_is_typed_duplicate_free_and_finite(self):
        for body in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'\xff'):
            with self.subTest(body=body), self.assertRaises(P.ProbeError):
                P.strict_json(body)

    def test_complete_listing_exact_size_time_and_names(self):
        self.assertTrue(P.listing_matches(json.dumps(listing()).encode()))
        data = listing()
        for row in data["list"]:
            row["ModTime"] = "2024-01-01T11:00:00.123+11:00"
        self.assertTrue(P.listing_matches(json.dumps(data).encode()))

    def test_listing_rejects_missing_duplicates_extra_fields_and_wrong_types(self):
        mutations = [lambda d: d["list"].pop(), lambda d: d["list"].append(d["list"][0]),
                     lambda d: d.update(extra=True), lambda d: d["list"][0].update(Hashes={}),
                     lambda d: d["list"][0].update(Size=True), lambda d: d["list"][0].update(IsDir=0),
                     lambda d: d["list"][0].update(Path="../outside"),
                     lambda d: d["list"][0].update(Name="other")]
        for mutate in mutations:
            data = listing()
            mutate(data)
            self.assertFalse(P.listing_matches(json.dumps(data).encode()))

    def test_listing_rejects_timestamp_imprecision_and_unknown_zone(self):
        for stamp in ("2024-01-01T00:00:00Z", "2024-01-01T00:00:00.123", "2024-01-01T00:00:00.123-00:00",
                      "2024-01-01T00:00:00.124Z", "2024-01-01T00:00:00.123000001Z", "2024-01-01T00:00:00.123+99:99"):
            data = listing()
            data["list"][0]["ModTime"] = stamp
            self.assertFalse(P.listing_matches(json.dumps(data).encode()))

    def test_only_exact_ntstatus_logon_failure_is_authentication_rejection(self):
        self.assertTrue(P.rejection_matches(error("password"), "password"))
        self.assertFalse(P.rejection_matches(error("missing"), "password"))
        for cause in ("connection refused", "access denied", "STATUS_LOGON_FAILURE", "smbd exited", P.AUTH_CAUSE + " extra"):
            data = json.loads(error("password"))
            data["error"] = "loopback: call failed: " + cause
            self.assertFalse(P.rejection_matches(json.dumps(data).encode(), "password"))

    def test_rejection_requires_exact_typed_envelope(self):
        for kind in ("password", "missing"):
            self.assertTrue(P.rejection_matches(error(kind), kind))
            for mutate in (lambda d: d.update(status="500"), lambda d: d.update(status=True),
                           lambda d: d.update(path="operations/list"), lambda d: d.update(extra="x")):
                data = json.loads(error(kind))
                mutate(data)
                self.assertFalse(P.rejection_matches(json.dumps(data).encode(), kind))

    def test_uid_gid_all_capability_sets_and_no_new_privileges(self):
        P.proc_status(status())
        for old, new in (("10001", "0"), ("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
                         ("Groups:\t10001", "Groups:\t10001 0")):
            with self.assertRaises(P.ProbeError):
                P.proc_status(status().replace(old, new, 1))
        for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
            with self.assertRaisesRegex(P.ProbeError, "capabilities_present"):
                P.proc_status(status().replace(key + ":\t0000000000000000", key + ":\t0000000000000001"))

    def test_mount_requires_readonly_root_and_exact_private_tmpfs(self):
        P.mount_checks(mounts())
        for old, new in (("/ ro,relatime", "/ rw,relatime"), ("nodev,", ""), ("noexec", "exec"),
                         ("- tmpfs tmpfs", "- ext4 disk"), ("/run/synthetic-smb", "/run/other")):
            with self.assertRaises(P.ProbeError):
                P.mount_checks(mounts().replace(old, new))
        with self.assertRaisesRegex(P.ProbeError, "nested_mount_refused"):
            P.mount_checks(mounts() + "22 21 0:3 / /run/synthetic-smb/source rw - tmpfs tmpfs rw\n")

    def test_tcp_parser_reports_listeners_not_established_connections(self):
        table = "header\n0: 0100007F:3C55 00000000:0000 0A 0:0 0:0 0 10001 0 123\n"
        self.assertEqual(P.tcp_listeners(table), ["0100007F:3C55"])
        self.assertEqual(P.tcp_listeners(table.replace(" 0A ", " 01 ")), [])
        with self.assertRaises(P.ProbeError):
            P.tcp_listeners("header\nbroken\n")

    def test_initial_report_is_never_ledger_eligible_or_passed(self):
        report = P.new_report()
        self.assertEqual(report["status"], "failed")
        self.assertIs(report["ledger_eligible"], False)
        self.assertTrue(all(value is False for value in report["checks"].values()))
        self.assertEqual(set(report), {"schema_version", "scope", "status", "ledger_eligible", "runtime", "checks", "cleanup", "commands_total", "errors"})

    def test_fixture_bytes_match_existing_lab_without_importing_it(self):
        # Source literal contract remains independent of the implementation.
        self.assertEqual(P.FILES, {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
                                  "nested/space name.txt": b"Nested synthetic payload.\n",
                                  "nested/bytes.bin": bytes(range(256)) * 8})


class Scenario:
    def __init__(self, mutation=None, cleanup=True, observed_version="1.76.2"):
        self.count, self.calls, self.server = 0, [], None
        self.mutation, self.cleanup = mutation, cleanup
        self.closed = False
        self.server_handle = SimpleNamespace(poll=lambda: None)
        self.observed_version = observed_version

    def prepare(self):
        for name in ("logs", "source", "output", "cache"):
            (P.ROOT / name).mkdir()
        for name, body in P.FILES.items():
            target = P.ROOT / "source" / name
            target.parent.mkdir(exist_ok=True)
            target.write_bytes(body)
        for name in ("smb.conf", "empty.conf"):
            (P.ROOT / name).write_text("synthetic-config")
        return "s" * 40

    def run(self, binary, args, **kwargs):
        self.count += 1
        self.calls.append((binary, args, kwargs))
        if binary == P.SMBD:
            return 0, b"Version 4.22.11-Debian-4.22.11+dfsg-0+deb13u1\n", b""
        if binary == P.TESTPARM:
            return 0, b"valid", b""
        raise AssertionError("unexpected mock command")

    def start(self, binary, args, **kwargs):
        self.count += 1
        self.calls.append((binary, args, kwargs))
        assert binary == P.SMBD and kwargs == {"keep_stdin": True}
        return self.server_handle, None, None

    def guard(self):
        pass

    def rclone(self, args, config=None, stdin=None):
        self.count += 1
        self.calls.append((P.RCLONE, args, {"config": config, "stdin": stdin}))
        if args == ["version"]:
            return 0, ("rclone v" + self.observed_version + "\n").encode(), b""
        if args == ["obscure", "-"]:
            return 0, (b"a" if self.count == 3 else b"b") * 40 + b"\n", b""
        assert args[:2] == ["rc", "--loopback"]
        if args[2] == "operations/list":
            assert args[3:5] == ["fs=loopback:SYNTHETIC/", "remote="]
            result = [0, json.dumps(listing()).encode(), b""]
        else:
            assert args[2] == "operations/copyfile" and args[3] == "srcFs=loopback:SYNTHETIC/"
            name = args[4].removeprefix("srcRemote=")
            target = Path(args[5].removeprefix("dstFs="))
            assert args[6] == "dstRemote=payload"
            if config.name == "bad.conf":
                result = [1, error("password"), b"private diagnostic"]
            elif name == "absent-synthetic.txt":
                result = [1, error("missing"), b"private diagnostic"]
            else:
                (target / "payload").write_bytes(P.FILES[name])
                result = [0, b"{}", b""]
        if self.mutation:
            self.mutation(args, config, result)
        return tuple(result)

    def close(self):
        self.closed = True
        return self.cleanup


class OrchestrationTests(unittest.TestCase):
    def execute(self, scenario, *, preflight_error=False, remove_error=False):
        with tempfile.TemporaryDirectory() as directory:
            base, root = Path(directory) / "base", Path(directory) / "root"
            (base / "seed").mkdir(parents=True)
            (base / "seed" / "passdb.tdb").write_bytes(b"synthetic seed")
            binary = base / "rclone"
            binary.write_bytes(b"synthetic never executed runtime")
            (base / "rclone-version.env").write_text(runtime_manifest(P.sha256(binary)))
            root.mkdir()
            def verify(report):
                report["runtime"].update(samba_version="4.22.11-Debian-4.22.11+dfsg-0+deb13u1",
                                         smbd_sha256="a" * 64, probe_sha256="b" * 64, lock_sha256="c" * 64)
                return {}
            def remove(_):
                if remove_error:
                    raise P.ProbeError("runtime_root_replaced")
                for path in root.iterdir():
                    shutil.rmtree(path) if path.is_dir() else path.unlink()
                return True
            with mock.patch.object(P, "BASE", base), mock.patch.object(P, "ROOT", root), mock.patch.object(P, "RCLONE", binary), \
                 mock.patch.object(P, "environment_checks", side_effect=P.ProbeError("capabilities_present") if preflight_error else None), \
                 mock.patch.object(P, "verify_build", side_effect=verify), \
                 mock.patch.object(P, "prepare", side_effect=scenario.prepare), \
                 mock.patch.object(P, "Children", return_value=scenario) as factory, \
                 mock.patch.object(P, "listeners", side_effect=[(["0100007F:3C55"], []), ([], [])]), \
                 mock.patch.object(P, "remove_owned_contents", side_effect=remove):
                report = P.run_probe()
                if preflight_error:
                    factory.assert_not_called()
                return report

    def test_complete_sequence_same_server_and_two_independent_read_sets(self):
        scenario = Scenario()
        report = self.execute(scenario)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["runtime"]["rclone_version"], "1.76.2")
        self.assertEqual(report["commands_total"], 16)
        self.assertTrue(all(report["checks"].values()))
        self.assertTrue(all(report["cleanup"].values()))
        self.assertTrue(scenario.closed)
        self.assertIs(scenario.server, scenario.server_handle)
        rc = [args for _, args, _ in scenario.calls if args[:2] == ["rc", "--loopback"]]
        self.assertEqual(len(rc), 10)
        self.assertEqual([args[2] for args in rc], ["operations/list"] + ["operations/copyfile"] * 4
                         + ["operations/list"] + ["operations/copyfile"] * 4)
        self.assertNotIn("private diagnostic", json.dumps(report))
        self.assertNotIn("s" * 40, json.dumps(report))
        self.assertNotIn("synthetic-smb", json.dumps(report))

    def test_preflight_denial_starts_nothing(self):
        report = self.execute(Scenario(), preflight_error=True)
        self.assertEqual(report["commands_total"], 0)
        self.assertEqual(report["status"], "failed")
        self.assertIn("capabilities_present", report["errors"])
        self.assertEqual(report["runtime"]["rclone_version"], "1.76.2")
        self.assertRegex(report["runtime"]["rclone_sha256"], r"^[a-f0-9]{64}$")

    def test_observed_runtime_version_must_match_verified_manifest(self):
        scenario = Scenario(observed_version="1.75.1")
        report = self.execute(scenario)
        self.assertEqual(report["status"], "failed")
        self.assertIn("rclone_version_mismatch", report["errors"])
        self.assertFalse(report["checks"]["version_binding"])
        self.assertEqual(report["commands_total"], 2)
        self.assertEqual(report["runtime"]["rclone_version"], "1.76.2")

    def test_generic_connection_failure_cannot_pass_auth(self):
        def mutate(args, config, result):
            if config.name == "bad.conf":
                result[1] = b'{"error":"connection refused","path":"operations/copyfile","status":500}'
        report = self.execute(Scenario(mutate))
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["checks"]["bad_password_rejected"])
        self.assertIn("password_rejection_mismatch", report["errors"])

    def test_denied_artifact_cannot_pass(self):
        def mutate(args, config, result):
            if config.name == "bad.conf":
                Path(args[5].removeprefix("dstFs=")).joinpath("partial").write_bytes(b"bad")
        report = self.execute(Scenario(mutate))
        self.assertIn("password_rejection_mismatch", report["errors"])

    def test_correct_size_wrong_bytes_cannot_pass(self):
        def mutate(args, config, result):
            if args[2] == "operations/copyfile" and config.name == "good.conf" and result[0] == 0:
                path = Path(args[5].removeprefix("dstFs=")) / "payload"
                path.write_bytes(b"x" * path.stat().st_size)
        report = self.execute(Scenario(mutate))
        self.assertIn("download_hash_mismatch", report["errors"])

    def test_cleanup_failure_is_sticky(self):
        report = self.execute(Scenario(cleanup=False))
        self.assertEqual(report["status"], "failed")
        self.assertIn("cleanup_incomplete", report["errors"])
        self.assertFalse(report["cleanup"]["temporary_removed"])

    def test_replaced_root_refuses_cleanup_and_pass(self):
        report = self.execute(Scenario(), remove_error=True)
        self.assertEqual(report["status"], "failed")
        self.assertIn("private_cleanup_failed", report["errors"])

    def test_preservation_failure_after_last_case_is_sticky(self):
        for kind in ("source", "config", "seed"):
            def mutate(args, config, result):
                if "srcRemote=absent-synthetic.txt" in args:
                    path = {"source": P.ROOT / "source" / "README-synthetic.txt",
                            "config": P.ROOT / "good.conf", "seed": P.BASE / "seed" / "passdb.tdb"}[kind]
                    path.write_bytes(b"changed")
            report = self.execute(Scenario(mutate))
            self.assertEqual(report["status"], "failed")
            self.assertFalse(report["checks"][kind + "_preserved"])
            self.assertTrue(report["cleanup"]["temporary_removed"])

    def test_preservation_read_exception_still_attempts_cleanup(self):
        def mutate(args, config, result):
            if "srcRemote=absent-synthetic.txt" in args:
                (P.ROOT / "good.conf").unlink()
        report = self.execute(Scenario(mutate))
        self.assertEqual(report["status"], "failed")
        self.assertIn("preservation_check_failed", report["errors"])
        self.assertTrue(report["cleanup"]["temporary_removed"])


class ExecutionGuardsTests(unittest.TestCase):
    def test_start_uses_fixed_hashed_binary_private_stdin_and_no_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "logs").mkdir()
            binary = root / "synthetic-executable"
            binary.write_bytes(b"never executed")
            handle = SimpleNamespace(stdin=None)
            with mock.patch.object(P, "ROOT", root), mock.patch.object(P.subprocess, "Popen", return_value=handle) as spawn:
                children = P.Children({binary: P.sha256(binary)})
                children.start(binary, ["obscure", "-"], b"synthetic password\n")
                args, kwargs = spawn.call_args
                self.assertEqual(args[0], [str(binary), "obscure", "-"])
                self.assertNotIn("shell", kwargs)
                self.assertTrue(kwargs["close_fds"])
                self.assertFalse(kwargs["start_new_session"])
                self.assertNotIn("synthetic password", repr(args))
                self.assertEqual((root / "child-1.in").read_bytes(), b"synthetic password\n")
                self.assertEqual(kwargs["env"]["NO_PROXY"], "*")
                self.assertNotIn("HTTP_PROXY", kwargs["env"])
                self.assertNotIn("RCLONE_CONFIG", kwargs["env"])

    def test_only_daemon_has_private_session_and_retained_stdin(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "logs").mkdir()
            binary = root / "smbd"
            binary.write_bytes(b"never executed")
            with mock.patch.object(P, "ROOT", root), mock.patch.object(P, "SMBD", binary), \
                 mock.patch.object(P.subprocess, "Popen", return_value=SimpleNamespace(stdin=io.BytesIO())) as spawn:
                children = P.Children({binary: P.sha256(binary)})
                children.start(binary, ["--foreground", "--no-process-group"], keep_stdin=True)
                self.assertEqual(spawn.call_args.kwargs["stdin"], P.subprocess.PIPE)
                self.assertTrue(spawn.call_args.kwargs["start_new_session"])
                children.start(binary, ["--version"])
                self.assertFalse(spawn.call_args.kwargs["start_new_session"])
                self.assertNotEqual(spawn.call_args.kwargs["stdin"], P.subprocess.PIPE)

    def test_binary_change_unknown_command_deadline_and_budget_prevent_spawn(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "logs").mkdir()
            binary = root / "binary"
            binary.write_bytes(b"before")
            with mock.patch.object(P, "ROOT", root), mock.patch.object(P.subprocess, "Popen") as spawn:
                children = P.Children({binary: P.sha256(binary)})
                with self.assertRaisesRegex(P.ProbeError, "command_not_allowed"):
                    children.start(root / "unknown", [])
                binary.write_bytes(b"after")
                with self.assertRaisesRegex(P.ProbeError, "executable_changed"):
                    children.start(binary, [])
                children.count = P.MAX_COMMANDS
                with self.assertRaisesRegex(P.ProbeError, "command_not_allowed"):
                    children.start(binary, [])
                children.count = 0
                children.deadline = 0
                with self.assertRaisesRegex(P.ProbeError, "probe_deadline"):
                    children.start(binary, [])
                spawn.assert_not_called()

    def test_private_output_and_daemon_exit_are_failure_conditions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "logs").mkdir()
            out, err = root / "output", root / "error"
            out.write_bytes(b"x" * (P.MAX_OUTPUT + 1))
            err.write_bytes(b"")
            with mock.patch.object(P, "ROOT", root):
                children = P.Children({})
                children.records.append((None, out, err))
                with self.assertRaisesRegex(P.ProbeError, "child_output_limit"):
                    children.guard()
                children.server = SimpleNamespace(poll=lambda: 1)
                with self.assertRaisesRegex(P.ProbeError, "samba_exited"):
                    children.guard()

    def test_cleanup_only_signals_matching_owned_pid_identity(self):
        owned = (1234, P.UID, os.getpid(), "S")
        baseline = {1: (1, P.UID, 0, "S"), os.getpid(): (2, P.UID, 1, "R")}
        with mock.patch.object(P, "namespace_processes", side_effect=[{**baseline, 800: owned}, baseline, baseline, baseline]), \
             mock.patch.object(P, "proc_identity", return_value=owned), \
             mock.patch.object(P.os, "kill", create=True) as kill, \
             mock.patch.object(P.signal, "SIGKILL", 9, create=True), mock.patch.object(P.time, "sleep"):
            children = P.Children({})
            self.assertTrue(children.close())
            kill.assert_called_once_with(800, P.signal.SIGTERM)

    def test_cleanup_refuses_foreign_uid(self):
        with mock.patch.object(P, "namespace_processes", return_value={800: (1234, 0, 1, "S")}), \
             mock.patch.object(P.os, "kill", create=True) as kill, \
             mock.patch.object(P.signal, "SIGKILL", 9, create=True):
            with self.assertRaisesRegex(P.ProbeError, "foreign_process_refused"):
                P.Children({}).close()
            kill.assert_not_called()

    def test_orphan_zombie_requires_init_reap_before_cleanup_pass(self):
        zombie = {800: (1234, P.UID, 1, "Z")}
        with mock.patch.object(P, "namespace_processes", side_effect=[zombie, zombie, zombie, {}]), \
             mock.patch.object(P.os, "kill", create=True) as kill, \
             mock.patch.object(P.signal, "SIGKILL", 9, create=True), mock.patch.object(P.time, "sleep") as pause:
            self.assertTrue(P.Children({}).close())
            kill.assert_not_called()
            pause.assert_called_once_with(0.03)

    def test_recursive_cleanup_refuses_replaced_root_and_hardlinked_file(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "owned"
            root.mkdir()
            original = base / "original"
            original.write_bytes(b"preserve")
            os.link(original, root / "link")
            info = root.stat()
            with mock.patch.object(P, "ROOT", root), mock.patch.object(P, "UID", info.st_uid), \
                 mock.patch.object(P, "mount_checks"), mock.patch.object(Path, "read_text", return_value=""):
                with self.assertRaisesRegex(P.ProbeError, "runtime_root_replaced"):
                    P.remove_owned_contents((info.st_dev, info.st_ino + 1))
                with self.assertRaisesRegex(P.ProbeError, "cleanup_entry_refused"):
                    P.remove_owned_contents((info.st_dev, info.st_ino))
            self.assertEqual(original.read_bytes(), b"preserve")

    def test_manifest_binds_binary_probe_lock_and_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            smbd, testparm, rclone = (root / name for name in ("smbd", "testparm", "rclone"))
            for path in (smbd, testparm, rclone, root / "probe_samba.py"):
                path.write_bytes(path.name.encode())
            version = "4.22.11-Debian-4.22.11+dfsg-0+deb13u1"
            (root / "build-lock.json").write_text(json.dumps({"runtime_expected": {
                "samba_version": version, "uid": P.UID, "gid": P.UID, "username": P.USER}}))
            pins_path = root / "rclone-version.env"
            pins_path.write_text(runtime_manifest(P.sha256(rclone)))
            manifest = {"schema_version": 1, "samba_version": version, "rclone_version": "1.76.2", **{key: P.sha256(path) for key, path in (
                ("smbd_sha256", smbd), ("testparm_sha256", testparm), ("rclone_sha256", rclone),
                ("probe_sha256", root / "probe_samba.py"), ("lock_sha256", root / "build-lock.json"),
                ("rclone_manifest_sha256", pins_path))}}
            (root / "runtime-manifest.json").write_text(json.dumps(manifest))
            with mock.patch.object(P, "BASE", root), mock.patch.object(P, "SMBD", smbd), \
                 mock.patch.object(P, "TESTPARM", testparm), mock.patch.object(P, "RCLONE", rclone):
                report = P.new_report()
                result = P.verify_build(report)
                self.assertEqual(set(result), {smbd, testparm, rclone})
                self.assertEqual(report["runtime"]["samba_version"], version)
                self.assertEqual(report["runtime"]["rclone_version"], "1.76.2")
                original_pins = pins_path.read_bytes()
                for field, value, code in (("rclone_version", "1.75.1", "rclone_pin_mismatch"),
                                           ("rclone_sha256", "d" * 64, "build_hash_mismatch"),
                                           ("rclone_manifest_sha256", "e" * 64, "build_hash_mismatch")):
                    with self.subTest(field=field):
                        changed = dict(manifest, **{field: value})
                        (root / "runtime-manifest.json").write_text(json.dumps(changed))
                        with self.assertRaisesRegex(P.ProbeError, code):
                            P.verify_build(P.new_report())
                (root / "runtime-manifest.json").write_text(json.dumps(manifest))
                pins_path.write_bytes(original_pins + b"# changed manifest bytes\n")
                with self.assertRaisesRegex(P.ProbeError, "build_hash_mismatch"):
                    P.verify_build(P.new_report())
                pins_path.write_bytes(original_pins)
                smbd.write_bytes(b"replaced")
                with self.assertRaisesRegex(P.ProbeError, "build_hash_mismatch"):
                    P.verify_build(P.new_report())


class RuntimePinTests(unittest.TestCase):
    def test_exact_manifest_accepts_future_stable_and_crlf_comments(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rclone-version.env"
            path.write_bytes(runtime_manifest("d" * 64).replace("\n", "\r\n").encode())
            self.assertEqual(P.read_runtime_pins(path), {"version": "1.76.2", "sha256": "d" * 64})

    def test_manifest_rejects_duplicate_unknown_missing_and_malformed_values(self):
        original = runtime_manifest("d" * 64)
        changed = [original + "RCLONE_VERSION=1.76.2\n", original + "UNKNOWN_KEY=value\n",
                   original.replace("RCLONE_VERSION=1.76.2\n", ""),
                   original.replace("1.76.2", "v1.76.2"), original.replace("1.76.2", "1.76.2-beta"),
                   original.replace("1.76.2", "01.76.2"), original.replace("1.76.2", '"1.76.2"'),
                   original.replace("d" * 64, "D" * 64), original.replace("a" * 64, "a" * 63),
                   original.replace("b" * 64, "g" * 64), original.replace("c" * 64, "0" * 65)]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rclone-version.env"
            for index, body in enumerate(changed):
                with self.subTest(index=index):
                    path.write_text(body)
                    with self.assertRaisesRegex(P.ProbeError, "rclone_manifest_invalid"):
                        P.read_runtime_pins(path)
            path.write_bytes(b"#" * 4097)
            with self.assertRaisesRegex(P.ProbeError, "rclone_manifest_size_limit"):
                P.read_runtime_pins(path)
            path.write_bytes(original.encode() + b"\xff")
            with self.assertRaisesRegex(P.ProbeError, "rclone_manifest_invalid"):
                P.read_runtime_pins(path)

    def test_mismatched_binary_pins_never_promote_identity_or_start_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "rclone"
            binary.write_bytes(b"synthetic never executed")
            (root / "rclone-version.env").write_text(runtime_manifest("d" * 64))
            with mock.patch.object(P, "BASE", root), mock.patch.object(P, "RCLONE", binary), \
                    mock.patch.object(P, "environment_checks") as environment, mock.patch.object(P, "Children") as children:
                report = P.run_probe()
            self.assertEqual(report["status"], "failed")
            self.assertIn("rclone_pin_mismatch", report["errors"])
            self.assertIsNone(report["runtime"]["rclone_version"])
            self.assertIsNone(report["runtime"]["rclone_sha256"])
            environment.assert_not_called()
            children.assert_not_called()


if __name__ == "__main__":
    unittest.main()
