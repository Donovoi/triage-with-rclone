"""Offline producer tests. No application, helper, runtime or listener executes."""
import copy
import ctypes
from contextlib import redirect_stderr, redirect_stdout
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import sys
import threading
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "scripts/application-lab/run_windows_http.py"
SPEC = importlib.util.spec_from_file_location("application_producer_test", SOURCE)
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
RUNTIME = {"version": "1.75.1", "sha256": "a" * 64, "platform": "windows"}
BODIES = {"README-synthetic.txt": b"synthetic application fixture\n",
          "large/cancel.bin": bytes(range(256)) * 8192,
          "nested/binary.bin": bytes(range(256)), "nested/spaced name.txt": b"spaces remain exact\n"}
HEADER = ["path_encoding", "remote", "path", "size", "modified", "is_dir", "hash", "hash_type"]


def dump(path, value):
    path.write_bytes(json.dumps(value, separators=(",", ":")).encode())


def session(action, *, final=False, observed=True, cancelled=False, exit_code=0):
    return {"schema_version": 1, "action": action, "ok": True,
        "state": "finished" if final else "running", "app_exit_code": exit_code if final else None,
        "runtime_image_observed": observed, "runtime_sha256": RUNTIME["sha256"] if observed else None,
        "runtime_process_count": 1 if observed else None,
        "ctrl_c_sent": cancelled, "output_bytes": 500, "output_limit_exceeded": False,
        "forced_termination": False, "app_exited": final, "observed_children_exited": final,
        "job_zero_confirmed": final, "reader_joined": final, "conpty_closed": final, "errors": []}


def fake_prepare(parent, name, action="Create"):
    path = Path(parent) / name
    if action == "Create":
        path.mkdir()
    else:
        assert path.is_dir()
    return path


def materialize(case, name):
    """Independent literal application artifact shapes, not producer builders."""
    base = case / "output/synthetic-case"
    for part in ("logs", "downloads", "listings", "config"):
        (base / part).mkdir(parents=True, exist_ok=True)
    config = base / "config/working-SYNTHETIC.conf"
    original = (case / "source.conf").read_bytes()
    config.write_bytes(original)
    dump(config.with_suffix(".provenance.json"), {
        "schema_version": 1, "source_path": str(case / "source.conf"),
        "source_sha256": hashlib.sha256(original).hexdigest(), "working_path": str(config),
        "snapshotted_at": "2026-01-01T00:00:00Z"})
    if name == "listing":
        out = io.StringIO(newline="")
        writer = csv.writer(out)
        writer.writerow(HEADER)
        for path, body in sorted(BODIES.items()):
            writer.writerow(["excel-safe-v1", "Synthetic", path, len(body), "2025-01-02T03:04:05+00:00", "false", "", ""])
        for path in ("large", "nested"):
            writer.writerow(["excel-safe-v1", "Synthetic", path, "", "2000-01-01T00:00:00+00:00", "true", "", ""])
        (base / "listings/inventory.csv").write_bytes(b"\xef\xbb\xbf" + out.getvalue().encode())
        return config
    names = sorted(BODIES) if name == "acquisition" else ["missing-synthetic.txt" if name == "missing" else
        "large/cancel.bin" if name == "cancellation" else "README-synthetic.txt"]
    plan, results = [], []
    for path in names:
        destination = base / "downloads/Synthetic" / path
        body = BODIES.get(path, b"x")
        digest = hashlib.sha256(body).hexdigest()
        expected = "0" * 64 if name in {"mismatch", "missing"} else digest
        plan.append({"remote_name": "Synthetic", "path": path, "request": {
            "source": "Synthetic:" + path, "destination": str(destination), "mode": "CopyTo",
            "expected_hash": expected, "expected_hash_type": "sha256", "expected_size": len(body)}})
        success = name == "acquisition"
        has_bytes = name in {"acquisition", "mismatch"}
        error = {"acquisition": None, "mismatch": "Downloaded bytes do not match the expected source hash",
            "missing": "Source was not found or is not an individual file: Synthetic:missing-synthetic.txt",
            "denial": "Cannot stat source: synthetic HTTP 403 Forbidden",
            "cancellation": "Operation cancelled"}[name]
        results.append({"local_sha256": digest if has_bytes else None,
            "integrity": {"acquisition": "Verified", "mismatch": "Mismatch", "cancellation": "Cancelled"}.get(name, "Failed"),
            "source": "Synthetic:" + path, "destination": str(destination), "success": success,
            "error": error, "size": len(body) if has_bytes else None, "hash": digest if has_bytes else None,
            "hash_type": "sha256" if has_bytes else None, "hash_verified": success if has_bytes else None, "hash_error": None})
        if has_bytes:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(body)
    stem = "acquisition-20260101T000000.123456789"
    dump(base / (stem + ".json"), {"schema_version": 1, "written_at": "2026-01-01T00:00:00Z",
        "rclone_version": "1.75.1", "config_path": str(config), "plan": {"files": plan, "skipped_directories": 0},
        "results": results, "complete": name == "acquisition"})
    for path in (stem + ".txt", "logs/" + stem + ".log", "logs/" + stem + ".checkpoint.json"):
        (base / path).write_bytes(b"private synthetic support")
    return config


class Flow:
    def __init__(self, name, *, late_error=None, enter_error=False, close_ok=True, grow=True, forced=False,
                 before_app=None, after_app=None, ready_result=None, runtime_count=1, close_final=False):
        self.name, self.late_error, self.enter_error, self.close_ok, self.grow = name, late_error, enter_error, close_ok, grow
        self.forced = forced
        self.before_app, self.after_app, self.ready_result = before_app, after_app, ready_result
        self.runtime_count, self.close_final = runtime_count, close_final
        self.events, self.server = [], None

    def serve(self, state):
        flow = self
        self.state = state
        class Context:
            def __enter__(self):
                if flow.enter_error:
                    raise P.ProducerError("fixture_failed")
                flow.server = types.SimpleNamespace(endpoint="http://127.0.0.1:54321/", cleanup_complete=False,
                    snapshot=state.snapshot)
                return flow.server
            def __exit__(self, *args):
                flow.events.append("fixture_closed")
                flow.server.cleanup_complete = True
                if flow.late_error:
                    state.errors.append(flow.late_error)
        return Context()

    def factory(self, case):
        flow = self
        class Session:
            last = None
            def command(self, action, **fields):
                flow.events.append(action)
                if action == "ready":
                    if flow.before_app:
                        flow.before_app(case)
                    self.last = ({"schema_version": 1, "action": "ready", "ok": True, "state": "ready"}
                                 if flow.ready_result is None else flow.ready_result)
                elif action == "start":
                    assert flow.events == ["ready", "start"]
                    for key, folder in (("TEMP", "temp"), ("TMP", "temp"), ("HOME", "home"),
                            ("USERPROFILE", "profile"), ("APPDATA", "appdata"), ("LOCALAPPDATA", "localappdata")):
                        assert fields["environment"][key] == str(case / folder)
                    assert Path(fields["app_path"]) == case / "application.exe"
                    assert Path(fields["app_path"]).read_bytes() == b"inert application bytes"
                    assert "--rclone-config-path" in fields["args"] and "--rclone-config" not in fields["args"]
                    assert type(fields["max_runtime_processes"]) is int
                    assert fields["max_runtime_processes"] == (4 if flow.name == "acquisition" else 1)
                    flow.state._event("observation", "")
                    flow.state.observation_started.set()
                    self.last = session(action, observed=False)
                elif action == "observe_runtime":
                    assert not flow.state._observation_release.is_set()
                    self.last = session(action)
                    self.last["runtime_process_count"] = flow.runtime_count
                    if flow.name == "cancellation":
                        flow.state.cancel_started.set()
                        if flow.grow:
                            partial = case / "output/synthetic-case/downloads/Synthetic/large/.triage-transfer-0123456789abcdef0123456789abcdef/payload.89abcdef.partial"
                            partial.parent.mkdir(parents=True)
                            partial.write_bytes(b"synthetic prefix")
                else:
                    assert flow.state._observation_release.is_set()
                    if flow.name == "cancellation":
                        assert action == "ctrl_c"
                        partial = case / "output/synthetic-case/downloads/Synthetic/large/.triage-transfer-0123456789abcdef0123456789abcdef/payload.89abcdef.partial"
                        assert partial.stat().st_size > 0
                        partial.unlink()
                        partial.parent.rmdir()
                        flow.state.cancel_disconnected = True
                        flow.state._event("cancel_prefix", "large/cancel.bin")
                        flow.state._event("cancel_disconnected", "large/cancel.bin")
                    materialize(case, flow.name)
                    if flow.after_app:
                        flow.after_app(case)
                    contents = sorted(BODIES) if flow.name == "acquisition" else ["README-synthetic.txt"] if flow.name == "mismatch" else ["large/cancel.bin"] if flow.name == "cancellation" else []
                    for path in contents:
                        flow.state._event("content", path)
                    if flow.name in {"missing", "denial"}:
                        flow.state.counters["missing" if flow.name == "missing" else "denied"] = 1
                    # HTML bodies are completed even when a content GET is cancelled.
                    flow.state.counters["completed_payload_bytes"] = 300
                    self.last = session(action, final=True, cancelled=flow.name == "cancellation",
                        exit_code=0 if flow.name in {"listing", "acquisition"} else 1)
                    self.last["forced_termination"] = flow.forced
                return self.last
            def close(self):
                flow.events.append("helper_closed")
                if flow.close_final:
                    self.last = session("finish", final=True, observed=False, exit_code=99)
                    self.last.update(ok=False, forced_termination=True, errors=["runtime_observation_failed", "forced_termination"])
                return flow.close_ok
        return Session()


class PrivateApi:
    """Inert Win32 API model: only ordinary files inside this test's temp root."""
    def __init__(self, case, member="source.conf", directory=False, failure=None):
        from ctypes import wintypes as w
        self.w, self.case, self.path = w, case, case / member
        self.directory, self.failure = directory, failure
        self.token, self.sid, self.sd = 0x100000001, 0x100000002, 0x100000003
        self.text = ctypes.create_unicode_buffer("S-1-5-21-11-22-33-1001")
        self.live, self.freed, self.closed, self.transferred = {}, [], [], []
        self.fd, self.sddl, self.attributes, self.flags = None, None, [], []
        self.kernel, self.security = types.SimpleNamespace(), types.SimpleNamespace()
        class TokenUser(ctypes.Structure):
            _fields_ = [("sid", ctypes.c_void_p), ("attributes", w.DWORD)]
        self.TokenUser = TokenUser
        for library, name, function in (
            (self.kernel, "GetCurrentProcess", lambda: 0x100000004),
            (self.kernel, "CloseHandle", self.close), (self.kernel, "LocalFree", self.free),
            (self.security, "OpenProcessToken", self.open_token),
            (self.security, "GetTokenInformation", self.token_info),
            (self.security, "ConvertSidToStringSidW", self.sid_text),
            (self.security, "ConvertStringSecurityDescriptorToSecurityDescriptorW", self.descriptor),
            (self.kernel, "CreateDirectoryW", self.mkdir), (self.kernel, "CreateFileW", self.create),
            (self.kernel, "GetFileInformationByHandle", self.information),
            (self.kernel, "GetFinalPathNameByHandleW", self.final_path)):
            setattr(library, name, mock.Mock(side_effect=function))

    @staticmethod
    def number(value):
        return value.value if hasattr(value, "value") else value

    def dll(self, name, **kwargs):
        assert kwargs == dict(use_last_error=True, winmode=0x800)
        return {"kernel32.dll": self.kernel, "advapi32.dll": self.security}[name]

    def open_token(self, process, access, out):
        assert process == 0x100000004 and access == 8
        if self.failure == "token":
            return False
        out._obj.value = self.token
        self.live[self.token] = None
        return True

    def token_info(self, token, kind, buffer, size, count):
        assert self.number(token) == self.token and kind == 1
        count._obj.value = ctypes.sizeof(self.TokenUser)
        if buffer is None:
            return False
        if self.failure == "token_info":
            return False
        ctypes.cast(buffer, ctypes.POINTER(self.TokenUser)).contents.sid = self.sid
        return True

    def sid_text(self, sid, out):
        assert sid == self.sid  # More than 32 bits must survive the API boundary.
        if self.failure == "sid":
            return False
        out._obj.value = ctypes.addressof(self.text)
        return True

    def descriptor(self, sddl, revision, out, count):
        self.sddl = sddl
        assert revision == 1
        if self.failure == "descriptor":
            return False
        out._obj.value = self.sd
        count._obj.value = 0 if self.failure == "descriptor_size" else 64
        return True

    def free(self, pointer):
        self.freed.append(self.number(pointer))
        return 0

    def close(self, handle):
        handle = self.number(handle)
        assert handle in self.live and handle not in self.transferred
        self.closed.append(handle)
        self.live.pop(handle)
        if self.fd is not None and handle == 0x100000100:
            os.close(self.fd)
            self.fd = None
        return not (self.failure == "cleanup" and handle == self.token)

    def capture_attributes(self, attributes):
        item = attributes._obj
        self.attributes.append((item.length, ctypes.sizeof(item), item.descriptor, item.inherit))

    def mkdir(self, path, attributes):
        self.capture_attributes(attributes)
        if self.failure == "create":
            return False
        try:
            Path(path).mkdir()
        except FileExistsError:
            return False
        return True

    def create(self, path, access, share, attributes, disposition, flags, template):
        self.flags.append((path, access, share, disposition, flags, template))
        if disposition == 1:
            self.capture_attributes(attributes)
            assert (access, share, flags, template) == (0x40000080, 1, 0x00200080, None)
            if self.failure == "create":
                return ctypes.c_void_p(-1).value
            try:
                self.fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0))
            except FileExistsError:
                return ctypes.c_void_p(-1).value
            handle = 0x100000100
        else:
            assert (access, share, attributes, disposition, flags, template) == (0x80, 3, None, 3, 0x02200000, None)
            if self.failure == "parent":
                return ctypes.c_void_p(-1).value
            handle = 0x100000010 + len(self.live)
        self.live[handle] = Path(path)
        return handle

    def information(self, handle, info):
        path = self.live[handle]
        if path == self.path and self.failure == "information":
            return False
        info._obj.attributes = 0x10 if path.is_dir() else 0x80
        info._obj.links = 1
        if path == self.path:
            if self.failure == "reparse":
                info._obj.attributes |= 0x400
            if self.failure == "links":
                info._obj.links = 2
        return True

    def final_path(self, handle, buffer, capacity, flags):
        path = self.live[handle]
        buffer.value = str(path)
        if path == self.path and self.failure in ("path_zero", "path_truncated"):
            return 0 if self.failure == "path_zero" else capacity
        return len(buffer.value)

    def open_fd(self, handle, flags):
        assert handle == 0x100000100 and flags & getattr(os, "O_NOINHERIT", 0x80)
        if self.failure == "open_fd":
            raise OSError("private-canary")
        self.transferred.append(handle)
        self.live.pop(handle)
        fd, self.fd = self.fd, None
        self.returned_fd = fd
        return fd

    def invoke(self, function):
        with mock.patch.object(P, "hosted_guard"), \
             mock.patch.object(ctypes, "WinDLL", side_effect=self.dll, create=True), \
             mock.patch.dict(sys.modules, {"msvcrt": types.SimpleNamespace(open_osfhandle=self.open_fd)}), \
             mock.patch.object(os, "O_BINARY", getattr(os, "O_BINARY", 0), create=True), \
             mock.patch.object(os, "O_NOINHERIT", getattr(os, "O_NOINHERIT", 0x80), create=True):
            return function(self.case, self.path, self.directory)


class ProducerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.app = self.root / "built.exe"
        self.app.write_bytes(b"inert application bytes")
        (self.root / "System32").mkdir()
        self.profile = self.root / "ci-profile"
        (self.profile / "AppData/Roaming").mkdir(parents=True)
        (self.profile / "AppData/Local").mkdir()
        self.digest = hashlib.sha256(self.app.read_bytes()).hexdigest()
        self.no_native = mock.patch.object(P.subprocess, "Popen", side_effect=AssertionError("native forbidden"))
        self.no_native.start()
        self.real_private_create = P._private_create
        self.real_native_create = P._native_private_create
        self.created_streams = []
        self.private_calls = []
        self.private_creation = mock.patch.object(P, "_private_create", side_effect=self.fake_private_create)
        self.private_creation.start()
        self.no_native_creation = mock.patch.object(P, "_native_private_create", side_effect=AssertionError("native creation forbidden"))
        self.no_native_creation.start()
        self.env = mock.patch.dict(os.environ, {"SYSTEMROOT": str(self.root), "GITHUB_SHA": "b" * 40,
            "RUNNER_TEMP": str(self.root), "USERPROFILE": str(self.profile),
            "APPDATA": str(self.profile / "AppData/Roaming"), "LOCALAPPDATA": str(self.profile / "AppData/Local"),
            "TEMP": str(self.root), "TMP": str(self.root)})
        self.env.start()
    def tearDown(self):
        self.no_native_creation.stop()
        self.private_creation.stop()
        for stream in self.created_streams:
            if not stream.closed:
                stream.close()
        self.env.stop()
        self.no_native.stop()
        self.temp.cleanup()

    def fake_private_create(self, case, member, directory):
        self.assertIn(member, P.PRIVATE_DIRECTORIES if directory else P.PRIVATE_FILES)
        self.private_calls.append((str(case), member, directory))
        if directory:
            (Path(case) / member).mkdir()
            return None
        stream = (Path(case) / member).open("xb", buffering=0)
        self.created_streams.append(stream)
        return stream

    def test_private_creation_guard_precedes_bindings_and_paths_are_closed(self):
        with mock.patch.object(P, "hosted_guard", side_effect=P.ProducerError("hosted_only")), \
             mock.patch.object(ctypes, "WinDLL", create=True) as native:
            with self.assertRaisesRegex(P.ProducerError, "^hosted_only$"):
                self.real_native_create(self.root, self.root / "source.conf", False)
            native.assert_not_called()
        for name in ("../outside", "output/synthetic-case", "transcript.private", "source.conf/extra", "C:/private-canary"):
            with mock.patch.object(P, "hosted_guard"), self.assertRaisesRegex(P.ProducerError, "^case_setup_failed$"):
                self.real_private_create(self.root, name, False)
        P._native_private_create.assert_not_called()
        self.assertEqual(P.private_sddl("S-1-5-21-11-22-33-1001", True),
            "O:S-1-5-21-11-22-33-1001D:P(A;OICI;FA;;;S-1-5-21-11-22-33-1001)(A;OICI;FA;;;SY)")
        for sid in (None, "private-canary", "S-1-5-18)(A;;FA;;;WD)", "S-1-5-１８"):
            with self.assertRaisesRegex(P.ProducerError, "^case_setup_failed$"):
                P.private_sddl(sid, False)

    def test_private_native_file_abi_descriptor_new_only_and_single_handle_transfer(self):
        api = PrivateApi(self.root)
        stream = api.invoke(self.real_native_create)
        try:
            self.assertFalse(os.get_inheritable(stream.fileno()))
            self.assertEqual(stream.write(b"inert"), 5)
            self.assertEqual(api.transferred, [0x100000100])
            self.assertNotIn(0x100000100, api.closed)
            self.assertEqual(api.live, {})
            self.assertEqual(set(api.freed), {api.sd, ctypes.addressof(api.text)})
            self.assertEqual(api.sddl, "O:S-1-5-21-11-22-33-1001D:P(A;;FA;;;S-1-5-21-11-22-33-1001)(A;;FA;;;SY)")
            self.assertEqual(len(api.attributes), 1)
            size, expected_size, descriptor, inherit = api.attributes[0]
            self.assertEqual((size, descriptor, inherit), (expected_size, api.sd, 0))
            self.assertEqual([call[3] for call in api.flags], [3, 1])
            self.assertIs(api.kernel.CreateFileW.restype, ctypes.wintypes.HANDLE)
            self.assertIs(api.kernel.LocalFree.restype, ctypes.c_void_p)
            self.assertEqual(api.kernel.CloseHandle.argtypes, [ctypes.wintypes.HANDLE])
            self.assertIs(api.security.ConvertSidToStringSidW.argtypes[0], ctypes.c_void_p)
            self.assertEqual(len(api.kernel.CreateFileW.argtypes), 7)
        finally:
            stream.close()
        with self.assertRaises(OSError):
            os.fstat(api.returned_fd)
        second = PrivateApi(self.root)
        with self.assertRaisesRegex(P.ProducerError, "^case_setup_failed$"):
            second.invoke(self.real_native_create)
        self.assertEqual((self.root / "source.conf").read_bytes(), b"inert")
        self.assertEqual(second.live, {})
        self.assertFalse(second.transferred)

    def test_private_native_directory_is_atomic_explicit_and_metadata_reopen_only(self):
        api = PrivateApi(self.root, "temp", True)
        self.assertIsNone(api.invoke(self.real_native_create))
        self.assertTrue(api.path.is_dir())
        self.assertEqual(api.live, {})
        self.assertEqual(len(api.attributes), 1)
        self.assertIn("(A;OICI;FA;;;", api.sddl)
        self.assertTrue(all(call[1] == 0x80 and call[3] == 3 for call in api.flags))
        self.assertFalse(api.transferred)
        with self.assertRaisesRegex(P.ProducerError, "^case_setup_failed$"):
            api.invoke(self.real_native_create)
        self.assertTrue(api.path.is_dir())

    def test_private_native_partial_failures_release_correct_resources_and_retain_file(self):
        for failure in ("token", "token_info", "sid", "descriptor", "descriptor_size", "parent", "create",
                        "information", "path_zero", "path_truncated", "reparse", "links", "open_fd", "cleanup"):
            with self.subTest(failure=failure):
                case = self.root / failure
                case.mkdir()
                api = PrivateApi(case, failure=failure)
                with self.assertRaises(P.ProducerError) as raised:
                    api.invoke(self.real_native_create)
                self.assertIn(str(raised.exception), {"case_setup_failed", "preservation_failed", "cleanup_failed"})
                self.assertNotIn("canary", str(raised.exception))
                self.assertIn(raised.exception.creation_stage, P.CREATION_STAGES)
                self.assertEqual(api.live, {})
                self.assertEqual(len(api.closed), len(set(api.closed)))
                self.assertEqual(len(api.freed), len(set(api.freed)))
                if failure in {"information", "path_zero", "path_truncated", "reparse", "links", "open_fd", "cleanup"}:
                    self.assertTrue(api.path.exists())  # No uncertain-path deletion.
                if failure == "descriptor_size":
                    self.assertIn(api.sd, api.freed)
                if api.transferred:
                    with self.assertRaises(OSError):
                        os.fstat(api.returned_fd)

    def test_private_native_fdopen_and_inheritance_failure_close_transferred_descriptor(self):
        for failure in ("fdopen", "inheritable"):
            case = self.root / failure
            case.mkdir()
            api = PrivateApi(case)
            change = (mock.patch.object(P.os, "fdopen", side_effect=OSError("private-canary")) if failure == "fdopen" else
                      mock.patch.object(P.os, "get_inheritable", return_value=True))
            with change, self.assertRaises(P.ProducerError):
                api.invoke(self.real_native_create)
            self.assertEqual(api.live, {})
            self.assertEqual(api.transferred, [0x100000100])
            self.assertNotIn(0x100000100, api.closed)
            with self.assertRaises(OSError):
                os.fstat(api.returned_fd)

    def test_private_creation_verifies_stream_identity_and_emits_only_static_failure(self):
        wrong = self.root / "private-canary"
        wrong.write_bytes(b"")
        held = wrong.open("r+b")
        (self.root / "source.conf").write_bytes(b"")
        with mock.patch.object(P, "hosted_guard"), mock.patch.object(P, "_native_private_create", return_value=held), \
             redirect_stdout(io.StringIO()) as output:
            with self.assertRaisesRegex(P.ProducerError, "^preservation_failed$"):
                self.real_private_create(self.root, "source.conf", False)
        self.assertTrue(held.closed)
        self.assertTrue(wrong.exists())
        self.assertTrue((self.root / "source.conf").exists())
        self.assertEqual(json.loads(output.getvalue().split("=", 1)[1]), {"category": "harness_file", "stage": "identity"})
        self.assertNotIn("canary", output.getvalue())
        with mock.patch.object(P, "hosted_guard"), mock.patch.object(P, "_native_private_create", side_effect=OSError("private SID/path/SDDL canary")), \
             redirect_stdout(io.StringIO()) as output, self.assertRaisesRegex(P.ProducerError, "^case_setup_failed$"):
            self.real_private_create(self.root, "queue.csv", False)
        self.assertNotIn("canary", output.getvalue())

    def test_private_write_flushes_and_syncs_retained_stream_and_propagates_failures(self):
        for failure in (None, "write", "flush", "sync", "close"):
            case = self.root / str(failure)
            case.mkdir()
            raw = (case / "source.conf").open("xb", buffering=0)
            stream = mock.MagicMock(wraps=raw)
            stream.__enter__.return_value = stream
            stream.__exit__.side_effect = lambda *args: raw.close()
            if failure == "write":
                stream.write.return_value = 0
            elif failure == "flush":
                stream.flush.side_effect = OSError("private-canary")
            elif failure == "close":
                def failed_close(*args):
                    raw.close()
                    raise OSError("private-canary")
                stream.__exit__.side_effect = failed_close
            with mock.patch.object(P, "private_file", return_value=stream), \
                 mock.patch.object(P.os, "fsync", side_effect=OSError("private-canary") if failure == "sync" else None) as sync:
                if failure is None:
                    P.private_write(case, "source.conf", b"synthetic")
                    stream.flush.assert_called_once()
                    sync.assert_called_once()
                else:
                    with self.assertRaises((P.ProducerError, OSError)):
                        P.private_write(case, "source.conf", b"synthetic")
            self.assertTrue(raw.closed)

    def test_fixed_creation_wiring_never_precreates_application_outputs(self):
        result, _, _ = self.execute_case("acquisition")
        self.assertEqual(result["status"], "passed")
        directories = [member for _, member, directory in self.private_calls if directory]
        files = [member for _, member, directory in self.private_calls if not directory]
        self.assertEqual(set(directories), P.PRIVATE_DIRECTORIES)
        self.assertEqual(len(directories), len(P.PRIVATE_DIRECTORIES))
        self.assertEqual(files, ["application.exe", "source.conf", "queue.csv"])
        self.assertFalse(any("synthetic-case" in value for value in directories + files))
        with mock.patch.object(P, "private_write", side_effect=OSError("private-canary")):
            result, _, suite = self.execute_case("listing")
        self.assertEqual(result["status"], "failed")
        self.assertNotIn("private-canary", json.dumps(result))
        self.assertTrue((suite / "listing").exists())

    def test_bridge_logs_precede_launch_and_all_close_on_launch_or_creation_failure(self):
        for failure in ("second_log", "launch"):
            case = self.root / failure
            case.mkdir()
            def create(case, member):
                if failure == "second_log" and member == "bridge-stderr.private":
                    raise P.ProducerError("case_setup_failed")
                return self.fake_private_create(case, member, False)
            def launch(*args, **kwargs):
                self.assertTrue(all((case / ("bridge-" + name + ".private")).exists() for name in ("stdout", "stderr")))
                self.assertTrue(all(not stream.closed for stream in self.created_streams if str(case) in stream.name))
                raise OSError("private-canary")
            with mock.patch.object(P, "private_file", side_effect=create), mock.patch.object(P, "powershell", return_value="fixed"), \
                 mock.patch.object(P, "hidden", return_value={}), mock.patch.object(P.subprocess, "Popen", side_effect=launch) as child, \
                 redirect_stdout(io.StringIO()) as output, self.assertRaises((P.ProducerError, OSError)):
                P.Bridge(case)
            self.assertEqual(child.call_count, failure == "launch")
            self.assertTrue(all(stream.closed for stream in self.created_streams))
            self.assertNotIn("canary", output.getvalue())

    def test_bridge_reader_start_failure_closes_unowned_pipes_and_logs(self):
        for fail_at in (0, 1, 2):
            for live in (False, True) if fail_at else (False,):
                with self.subTest(fail_at=fail_at, live=live):
                    case = self.root / f"thread-{fail_at}-{live}"
                    case.mkdir()
                    process = mock.Mock(returncode=-1)
                    threads = [mock.Mock() for _ in range(3)]
                    for index, thread in enumerate(threads):
                        thread.is_alive.return_value = live and index < fail_at and index < 2
                    threads[fail_at].start.side_effect = RuntimeError("private-canary")
                    with mock.patch.object(P, "powershell", return_value="fixed"), mock.patch.object(P, "hidden", return_value={}), \
                         mock.patch.object(P.subprocess, "Popen", return_value=process), \
                         mock.patch.object(P.threading, "Thread", side_effect=threads), redirect_stdout(io.StringIO()) as output:
                        with self.assertRaisesRegex(RuntimeError, "private-canary"):
                            P.Bridge(case)
                    process.kill.assert_called_once()
                    process.wait.assert_called_once_with(timeout=5)
                    process.stdin.close.assert_called_once()
                    for index, pipe in enumerate((process.stdout, process.stderr)):
                        if index < fail_at and live:
                            pipe.close.assert_not_called()
                        else:
                            pipe.close.assert_called_once()
                    self.assertTrue(all(stream.closed for stream in self.created_streams))
                    self.assertNotIn("canary", output.getvalue())

    def execute_case(self, name, *, suite_name=None, **kwargs):
        flow = Flow(name, **kwargs)
        suite = self.root / (suite_name or name)
        suite.mkdir()
        with mock.patch.object(P, "prepare", side_effect=fake_prepare), mock.patch.object(P.F, "serve_http", side_effect=flow.serve), mock.patch.object(P.time, "sleep"):
            result = P.run_case(name, suite, self.app, self.digest, RUNTIME, session_factory=flow.factory)
        return result, flow, suite

    def test_six_complete_flows_with_real_disk_oracles(self):
        for name in ("listing", "acquisition", "mismatch", "missing", "denial", "cancellation"):
            with self.subTest(name=name):
                result, flow, suite = self.execute_case(name)
                self.assertEqual(result["status"], "passed", result)
                self.assertTrue(all(result["checks"].values()))
                self.assertEqual(result["runtime_sha256"], "a" * 64)
                self.assertLess(flow.events.index("observe_runtime"), flow.events.index("poll" if name != "cancellation" else "ctrl_c"))
                self.assertLess(flow.events.index("helper_closed"), flow.events.index("fixture_closed"))
                self.assertEqual(list(suite.iterdir()), [])

    def test_helper_baseline_predates_start_and_full_owned_case_is_removed(self):
        def before_app(case):
            (case / "helper-env/profile/pre-existing-canary/child").mkdir(parents=True)
        with redirect_stdout(io.StringIO()) as output:
            result, flow, suite = self.execute_case("listing", before_app=before_app)
        self.assertEqual(flow.events[:2], ["ready", "start"])
        self.assertEqual(result["status"], "passed")
        self.assertTrue(result["checks"]["temp_cleanup"])
        self.assertEqual(list(suite.iterdir()), [])
        self.assertNotIn("pre-existing-canary", output.getvalue() + json.dumps(result))

    def execute_profile_flow(self, index, *, before_app=None, after_app=None, ready_result=None, output=None):
        suite = self.root / ("profile-case-" + str(index))
        suite.mkdir()
        flow = Flow("listing", before_app=before_app, after_app=after_app, ready_result=ready_result)
        output = io.StringIO() if output is None else output
        with mock.patch.object(P, "prepare", side_effect=fake_prepare), mock.patch.object(P.F, "serve_http", side_effect=flow.serve), \
             mock.patch.object(P.time, "sleep"), redirect_stdout(output):
            result = P.run_case("listing", suite, self.app, self.digest, RUNTIME, session_factory=flow.factory)
        self.assertNotIn("private-canary", output.getvalue() + json.dumps(result))
        return result, flow, suite

    def prestart_observation(self, output):
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("application_prestart_diagnostic="))
        value = json.loads(lines[0].split("=", 1)[1])
        self.assertEqual(set(value), {"scope", "stage", "location", "entries", "directories", "files", "total_bytes"})
        self.assertNotIn(str(self.root), output.getvalue())
        self.assertNotIn("canary", output.getvalue())
        return value

    def test_prestart_helper_failures_report_precise_counts_without_start_or_delete(self):
        def replace(case):
            (case / "helper-env/profile").rename(case / "private-canary-old")
            (case / "helper-env/profile").mkdir()
        def large(case):
            for index in range(26):
                (case / "helper-env/profile" / ("private-canary-" + str(index))).mkdir()
        mutations = [(lambda c: (c / "helper-env/profile/private-canary").write_bytes(b"xyz"),
                      "helper_directories", (8, 7, 1, 3)),
                     (large, "helper_limit", (33, 33, 0, 0)),
                     (replace, "helper_identity", (None, None, None, None)),
                     (lambda c: (c / "helper-env/private-canary").mkdir(), "helper_layout", (8, 8, 0, 0))]
        for index, (mutate, stage, counts) in enumerate(mutations):
            with self.subTest(stage=stage), mock.patch.object(P, "remove_owned") as remove:
                output = io.StringIO()
                result, flow, suite = self.execute_profile_flow(index, before_app=mutate, output=output)
                self.assertEqual(self.prestart_observation(output), dict(scope="listing", stage=stage, location="helper_env",
                    **dict(zip(("entries", "directories", "files", "total_bytes"), counts))))
                self.assertEqual(result["failure_code"], "cleanup_failed")
                self.assertEqual(result["status"], "failed")
                self.assertNotIn("start", flow.events)
                self.assertFalse(result["checks"]["temp_cleanup"])
                self.assertFalse(result["checks"]["runtime_observed"])
                self.assertTrue((suite / "listing").is_dir())
                remove.assert_not_called()

    def test_prestart_all_application_roots_require_empty_and_report_fixed_location(self):
        for location in ("temp", "home", "profile", "appdata", "localappdata"):
            def residue(case):
                (case / location / "private-canary-dir").mkdir()
                (case / location / "private-canary-content").write_bytes(b"xyz")
            with self.subTest(location=location), mock.patch.object(P, "remove_owned") as remove:
                output = io.StringIO()
                result, flow, suite = self.execute_profile_flow(location, before_app=residue, output=output)
                self.assertEqual(self.prestart_observation(output), dict(scope="listing", stage="private_empty", location=location,
                    entries=2, directories=1, files=1, total_bytes=3))
                self.assertEqual(result["failure_code"], "cleanup_failed")
                self.assertNotIn("start", flow.events)
                self.assertFalse(result["checks"]["temp_cleanup"])
                self.assertTrue((suite / "listing").is_dir())
                remove.assert_not_called()

    def test_prestart_unreadable_or_link_inventory_reports_unknown_counts(self):
        original = P.inventory
        for location in ("helper-env", "home"):
            for error in (OSError("private-canary-path"), P.ProducerError("preservation_failed")):
                def failed(path):
                    if Path(path).name == location:
                        raise error
                    return original(path)
                with self.subTest(location=location, failure=type(error).__name__), \
                     mock.patch.object(P, "inventory", side_effect=failed), mock.patch.object(P, "remove_owned") as remove:
                    output = io.StringIO()
                    result, flow, suite = self.execute_profile_flow(location + type(error).__name__, output=output)
                    stage = "helper_inventory" if location == "helper-env" else "private_inventory"
                    self.assertEqual(self.prestart_observation(output), dict(scope="listing", stage=stage,
                        location="helper_env" if location == "helper-env" else location,
                        entries=None, directories=None, files=None, total_bytes=None))
                    self.assertEqual(result["failure_code"], "unexpected_failure" if isinstance(error, OSError) else "preservation_failed")
                    self.assertNotIn("start", flow.events)
                    self.assertFalse(result["checks"]["temp_cleanup"])
                    self.assertTrue((suite / "listing").is_dir())
                    remove.assert_not_called()

    def test_prestart_original_exception_survives_even_failed_diagnostic(self):
        case = self.root / "prestart-direct"
        case.mkdir()
        leases = P.create_private_roots(case)
        error = OSError("private-canary")
        with mock.patch.object(P, "inventory", side_effect=error), \
             mock.patch.object(P, "prestart_diagnostic", side_effect=RuntimeError("private-canary-output")):
            with self.assertRaises(OSError) as caught:
                P.prestart_baseline("listing", case, leases)
        self.assertIs(caught.exception, error)

    def test_prestart_diagnostic_rejects_unbounded_untyped_or_foreign_fields(self):
        counts = dict(entries=1, directories=0, files=1, total_bytes=3)
        for fields in (("private-canary", "helper_directories", "helper_env", counts),
                       ("listing", "private-canary", "helper_env", counts),
                       ("listing", "private_empty", "private-canary", counts),
                       ("listing", "helper_limit", "temp", counts),
                       ("listing", "private_empty", "helper_env", counts),
                       ("listing", "helper_inventory", "helper_env", counts),
                       ("listing", "helper_directories", "helper_env", dict(counts, entries=True)),
                       ("listing", "helper_directories", "helper_env", dict(counts, entries=1025)),
                       ("listing", "helper_directories", "helper_env", dict(counts, files=0)),
                       ("listing", "helper_directories", "helper_env", dict(counts, total_bytes=512 * 1024 * 1024 + 1)),
                       ("listing", "helper_directories", "helper_env", dict(counts, extra="private-canary"))):
            with self.subTest(stage=fields[1]), redirect_stdout(io.StringIO()) as output:
                with self.assertRaisesRegex(P.ProducerError, "^cleanup_failed$"):
                    P.prestart_diagnostic(*fields)
                self.assertEqual(output.getvalue(), "")

    def test_bad_ready_or_prestart_profile_never_starts_or_deletes(self):
        def replace_root(case):
            (case / "profile").rename(case / "old-profile")
            (case / "profile").mkdir()
        def too_many(case):
            for index in range(33):
                (case / "profile" / str(index)).mkdir()
        def missing_ready(case):
            raise P.ProducerError("session_failed")
        mutations = [lambda c: (c / "profile/private-canary").write_bytes(b"x"), replace_root, too_many,
            lambda c: (c / "temp/private-canary").mkdir(), missing_ready]
        with mock.patch.object(P, "remove_owned") as remove:
            for index, mutate in enumerate(mutations):
                with self.subTest(mutation=index):
                    result, flow, suite = self.execute_profile_flow(index, before_app=mutate)
                    self.assertEqual(result["status"], "failed")
                    self.assertNotIn("start", flow.events)
                    self.assertFalse(result["checks"]["temp_cleanup"])
                    self.assertTrue((suite / "listing").exists())
            for index, response in enumerate(({}, {"schema_version": True, "action": "ready", "ok": True, "state": "ready"},
                    {"schema_version": 1, "action": "ready", "ok": True, "state": "ready", "extra": "private-canary"}), 10):
                with self.subTest(response=index):
                    result, flow, suite = self.execute_profile_flow(index, ready_result=response)
                    self.assertEqual(result["failure_code"], "session_failed")
                    self.assertNotIn("start", flow.events)
                    self.assertFalse(result["checks"]["temp_cleanup"])
                    self.assertTrue((suite / "listing").exists())
            remove.assert_not_called()

    def test_application_profile_link_guard_prevents_start(self):
        original_plain = P.plain
        def guarded(path, directory=False, **kwargs):
            if Path(path).name == "private-canary":
                raise P.ProducerError("preservation_failed")
            return original_plain(path, directory, **kwargs)
        with mock.patch.object(P, "plain", side_effect=guarded), mock.patch.object(P, "remove_owned") as remove:
            result, flow, _ = self.execute_profile_flow("link", before_app=lambda c: (c / "profile/private-canary").mkdir())
        self.assertNotIn("start", flow.events)
        self.assertFalse(result["checks"]["temp_cleanup"])
        remove.assert_not_called()

    def test_helper_baseline_add_replace_files_and_fixed_root_changes_are_sticky_failures(self):
        def baseline(case):
            (case / "helper-env/profile/owned-child").mkdir()
        def replace_child(case):
            (case / "helper-env/profile/owned-child").rename(case / "old-child")
            (case / "helper-env/profile/owned-child").mkdir()
        def replace_root(case, name):
            root = case / "helper-env" / name if name else case / "helper-env"
            root.rename(case / "old-root")
            root.mkdir()
        mutations = [lambda c: (c / "helper-env/profile/new-child").mkdir(), replace_child,
            lambda c: replace_root(c, "profile"), lambda c: replace_root(c, ""),
            lambda c: (c / "helper-env/home").rmdir(),
            lambda c: (c / "helper-env/profile/private-canary").write_bytes(b"x"),
            lambda c: (c / "helper-env/private-canary").mkdir(),
            lambda c: (c / "profile/private-canary").mkdir()]
        with mock.patch.object(P, "remove_owned") as remove:
            for index, mutate in enumerate(mutations):
                with self.subTest(mutation=index):
                    result, flow, suite = self.execute_profile_flow(index, before_app=baseline, after_app=mutate)
                    self.assertEqual(result["status"], "failed")
                    self.assertEqual(result["failure_code"], "cleanup_failed")
                    self.assertIn("start", flow.events)
                    self.assertTrue(result["checks"]["inventory_exact"])
                    self.assertTrue(result["checks"]["process_cleanup"])
                    self.assertFalse(result["checks"]["temp_cleanup"])
                    self.assertTrue((suite / "listing").exists())
            remove.assert_not_called()

    def test_only_baseline_helper_descendants_may_disappear_at_cleanup(self):
        def baseline(case):
            (case / "helper-env/temp/owned-child/nested").mkdir(parents=True)
        def remove_descendants(case):
            (case / "helper-env/temp/owned-child/nested").rmdir()
            (case / "helper-env/temp/owned-child").rmdir()
        result, flow, suite = self.execute_profile_flow("remove-helper", before_app=baseline, after_app=remove_descendants)
        self.assertEqual(result["status"], "passed")
        self.assertTrue(result["checks"]["temp_cleanup"])
        self.assertEqual(list(suite.iterdir()), [])
        self.assertIn("start", flow.events)

    def test_helper_baseline_total_bound_and_link_guard_remain_strict(self):
        case = self.root / "helper-bound"
        case.mkdir()
        leases = P.create_private_roots(case)
        for index in range(25):
            (case / "helper-env/temp" / str(index)).mkdir()
        baseline = P.prestart_baseline("listing", case, leases)
        self.assertEqual(len(baseline), 32)
        (case / "helper-env/temp/extra").mkdir()
        with redirect_stdout(io.StringIO()), self.assertRaisesRegex(P.ProducerError, "^cleanup_failed$"):
            P.prestart_baseline("listing", case, leases)
        original_plain = P.plain
        def guarded(path, directory=False, **kwargs):
            if Path(path).name == "private-canary":
                raise P.ProducerError("preservation_failed")
            return original_plain(path, directory, **kwargs)
        with mock.patch.object(P, "plain", side_effect=guarded), mock.patch.object(P, "remove_owned") as remove:
            result, flow, _ = self.execute_profile_flow("helper-link", before_app=lambda c: (c / "helper-env/temp/private-canary").mkdir())
        self.assertNotIn("start", flow.events)
        self.assertFalse(result["checks"]["temp_cleanup"])
        remove.assert_not_called()

    def test_observed_helper_support_directories_use_atomic_creator_and_fixed_leases(self):
        case = self.root / "helper-support"
        case.mkdir()
        leases = P.create_private_roots(case)
        fixed = {"temp", "home", "profile", "appdata", "localappdata",
                 "profile/AppData", "profile/AppData/Roaming"}
        self.assertEqual(set(leases["helper"]), fixed)
        self.assertEqual([member for _, member, _ in self.private_calls][-2:],
            ["helper-env/profile/AppData", "helper-env/profile/AppData/Roaming"])
        self.assertEqual(set(P.prestart_baseline("listing", case, leases)), fixed)
        for member in fixed:
            self.assertEqual(leases["helper"][member], P.identity(case / "helper-env" / member))
        for member in ("temp", "home", "profile", "appdata", "localappdata"):
            self.assertEqual(P.inventory(case / member), {})
        self.assertEqual(P.environment(case)["USERPROFILE"], str(case / "profile"))
        self.assertEqual(P.environment(case)["APPDATA"], str(case / "appdata"))
        self.assertFalse((case / "helper-env/profile/AppData/Local").exists())
        self.assertFalse((case / "helper-env/profile/Documents").exists())
        for index, member in enumerate(("helper-env/profile/AppData", "helper-env/profile/AppData/Roaming")):
            other = self.root / ("helper-existing-" + str(index))
            other.mkdir()
            created = []
            def competing_entry(root, current, directory):
                if current == member:
                    (Path(root) / current).mkdir()
                    created.append(P.identity(Path(root) / current))
                return self.fake_private_create(root, current, directory)
            with mock.patch.object(P, "_private_create", side_effect=competing_entry), self.assertRaises(FileExistsError):
                P.create_private_roots(other)
            self.assertEqual(P.identity(other / member), created[0])
            self.assertEqual(P.inventory(other / member), {})

    def test_fixed_helper_support_removal_or_replacement_never_starts_or_passes(self):
        for phase in ("prestart", "post_helper"):
            for member in ("AppData", "AppData/Roaming"):
                for replace in (False, True):
                    def mutate(case):
                        node = case / "helper-env/profile" / member
                        node.rename(case / "private-canary-old")
                        if replace:
                            node.mkdir()
                    label = phase + member.replace("/", "-") + str(replace)
                    options = {"before_app" if phase == "prestart" else "after_app": mutate}
                    output = io.StringIO()
                    with self.subTest(phase=phase, member=member, replace=replace), mock.patch.object(P, "remove_owned") as remove:
                        result, flow, suite = self.execute_profile_flow(label, output=output, **options)
                    self.assertEqual(result["status"], "failed")
                    self.assertFalse(result["checks"]["temp_cleanup"])
                    self.assertEqual("start" in flow.events, phase == "post_helper")
                    diagnostic = self.prestart_observation(output) if phase == "prestart" else self.post_helper_observation(output)
                    self.assertEqual((diagnostic["stage"], diagnostic["location"]), ("helper_identity", "helper_env"))
                    self.assertIsNone(diagnostic["entries"])
                    self.assertTrue((suite / "listing/private-canary-old").exists())
                    remove.assert_not_called()

    def test_fixed_helper_support_identity_is_rechecked_after_inventory(self):
        for member in ("AppData", "AppData/Roaming"):
            case = self.root / ("helper-swap-" + member.replace("/", "-"))
            case.mkdir()
            leases = P.create_private_roots(case)
            original_inventory = P.inventory
            def changing_inventory(root):
                value = original_inventory(root)
                if Path(root) == case / "helper-env":
                    node = case / "helper-env/profile" / member
                    node.rename(case / "private-canary-old")
                    node.mkdir()
                return value
            with mock.patch.object(P, "inventory", side_effect=changing_inventory), redirect_stdout(io.StringIO()) as output:
                with self.assertRaisesRegex(P.ProducerError, "^cleanup_failed$"):
                    P.prestart_baseline("listing", case, leases)
            self.assertEqual(self.prestart_observation(output)["stage"], "helper_identity")
            self.assertTrue((case / "private-canary-old").exists())

    def test_app_root_replacement_inside_inventory_never_establishes_a_new_lease(self):
        original_inventory = P.inventory
        for when in ("prestart", "cleanup"):
            changed = []
            def inventory(path):
                path = Path(path)
                listing_exists = (path.parent / "output/synthetic-case/listings/inventory.csv").exists()
                if not changed and path.name == "profile" and path.parent.name == "listing" and listing_exists == (when == "cleanup"):
                    path.rename(path.parent / "old-profile")
                    path.mkdir()
                    changed.append(True)
                return original_inventory(path)
            with self.subTest(when=when), mock.patch.object(P, "inventory", side_effect=inventory), \
                 mock.patch.object(P, "remove_owned") as remove:
                output = io.StringIO()
                result, flow, suite = self.execute_profile_flow(when, output=output)
            self.assertEqual(changed, [True])
            self.assertEqual(result["failure_code"], "cleanup_failed")
            self.assertFalse(result["checks"]["temp_cleanup"])
            self.assertEqual("start" in flow.events, when == "cleanup")
            self.assertTrue((suite / "listing").is_dir())
            if when == "cleanup":
                self.assertEqual(self.post_helper_observation(output), dict(scope="listing", stage="private_identity", location="profile",
                    entries=None, directories=None, files=None, total_bytes=None, comparison=None, allowlist=None))
            remove.assert_not_called()

    def test_late_fixture_failure_cannot_promote(self):
        result, _, suite = self.execute_case("acquisition", late_error="worker_failed")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failure_code"], "fixture_failed")
        self.assertTrue(result["checks"]["output_hashes_exact"])
        self.assertFalse(result["checks"]["fixture_valid"])
        self.assertEqual(list(suite.iterdir()), [])

    def test_unjoined_helper_retains_case(self):
        result, _, suite = self.execute_case("acquisition", close_ok=False)
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["checks"]["process_cleanup"])
        self.assertFalse(result["checks"]["temp_cleanup"])
        self.assertTrue((suite / "acquisition/source.conf").exists())

    def test_fixture_enter_uncertainty_retains_case(self):
        result, flow, suite = self.execute_case("listing", enter_error=True)
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["checks"]["fixture_cleanup"])
        self.assertFalse(result["checks"]["temp_cleanup"])
        self.assertNotIn("start", flow.events)
        self.assertTrue((suite / "listing").exists())

    def test_cancellation_requires_actual_partial_file_growth(self):
        with mock.patch.object(P.time, "monotonic", side_effect=[0, 121]):
            result, flow, _ = self.execute_case("cancellation", grow=False)
        self.assertFalse(result["checks"]["transfer_active"])
        self.assertFalse(result["checks"]["ctrl_c_sent"])
        self.assertNotIn("ctrl_c", flow.events)
        self.assertEqual(result["status"], "failed")

    def cancellation_partial_case(self, label, relative=None, size=32):
        case = self.root / label
        case.mkdir()
        base = case / "output/synthetic-case/downloads"
        path = base / (relative or "Synthetic/large/.triage-transfer-0123456789abcdef0123456789abcdef/payload.89abcdef.partial")
        path.parent.mkdir(parents=True)
        path.write_bytes(b"x" * size)
        return case, base, path

    def test_cancellation_partial_requires_exact_pinned_filename_and_incomplete_size(self):
        for index, size in enumerate((0, 1, 65536, 2097151, 2097152, 2097153)):
            case, _, _ = self.cancellation_partial_case("partial-size-" + str(index), size=size)
            self.assertEqual(P.partial_active(case, P.identity(case)), 0 < size < 2097152)
        root = "Synthetic/large/.triage-transfer-0123456789abcdef0123456789abcdef/"
        bad = [root + "payload", root + "payload.partial", root + "payload.89ABCDEF.partial",
               root + "payload.89abcde.partial", root + "payload.089abcdef.partial",
               root + "payload.89abcdef.partial.extra", root + "other.89abcdef.partial",
               root + "nested/payload.89abcdef.partial", "Synthetic/large/cancel.bin",
               "Synthetic/large/.triage-transfer-synthetic/payload.89abcdef.partial",
               "Synthetic/large/.triage-transfer-0123456789ABCDEF0123456789abcdef/payload.89abcdef.partial",
               "Synthetic/large-sibling/.triage-transfer-0123456789abcdef0123456789abcdef/payload.89abcdef.partial",
               "Synthetic-other/large/.triage-transfer-0123456789abcdef0123456789abcdef/payload.89abcdef.partial"]
        for index, name in enumerate(bad):
            with self.subTest(index=index):
                case, _, _ = self.cancellation_partial_case("partial-name-" + str(index), name)
                self.assertFalse(P.partial_active(case, P.identity(case)))

    def test_cancellation_partial_rejects_duplicate_or_other_completed_file(self):
        for extra in ("Synthetic/large/.triage-transfer-ffffffffffffffffffffffffffffffff/payload.12345678.partial",
                      "Synthetic/large/cancel.bin", "Synthetic/large/private-canary"):
            case, base, _ = self.cancellation_partial_case("partial-extra-" + str(len(list(self.root.iterdir()))))
            second = base / extra
            second.parent.mkdir(parents=True, exist_ok=True)
            second.write_bytes(b"inert")
            with self.assertRaisesRegex(P.ProducerError, "^cancellation_failed$"):
                P.partial_active(case, P.identity(case))

    def test_cancellation_partial_rejects_case_stage_and_file_identity_replacement(self):
        case, _, _ = self.cancellation_partial_case("partial-case-replaced")
        lease = P.identity(case)
        with mock.patch.object(P, "identity", return_value=(lease[0], lease[1] + 1)), \
             mock.patch.object(P, "inventory") as inventory:
            with self.assertRaisesRegex(P.ProducerError, "^preservation_failed$"):
                P.partial_active(case, lease)
            inventory.assert_not_called()
        for kind in ("stage", "file", "downloads"):
            case, base, path = self.cancellation_partial_case("partial-replaced-" + kind)
            lease, snapshot = P.identity(case), P.inventory(base)
            def replace(_):
                if kind == "file":
                    path.rename(case / "retained-original-file")
                    path.write_bytes(b"replacement")
                elif kind == "stage":
                    path.parent.rename(case / "retained-original-stage")
                    path.parent.mkdir()
                    path.write_bytes(b"replacement")
                else:
                    base.rename(case / "retained-original-downloads")
                    base.mkdir()
                return snapshot
            with mock.patch.object(P, "inventory", side_effect=replace):
                with self.assertRaisesRegex(P.ProducerError, "^preservation_failed$"):
                    P.partial_active(case, lease)

    def test_cancellation_partial_inventory_or_link_refusal_remains_failed(self):
        directory_case, _, directory_path = self.cancellation_partial_case("partial-directory")
        directory_path.unlink()
        directory_path.mkdir()
        self.assertFalse(P.partial_active(directory_case, P.identity(directory_case)))
        case, _, path = self.cancellation_partial_case("partial-link-refusal")
        lease = P.identity(case)
        real_plain = P.plain
        def reject(path_to_check, *args, **kwargs):
            if Path(path_to_check) == path:
                raise P.ProducerError("preservation_failed")
            return real_plain(path_to_check, *args, **kwargs)
        with mock.patch.object(P, "plain", side_effect=reject):
            with self.assertRaisesRegex(P.ProducerError, "^preservation_failed$"):
                P.partial_active(case, lease)
        with mock.patch.object(P, "inventory", side_effect=OSError("private-canary")):
            with self.assertRaises(OSError):
                P.partial_active(case, lease)

    def test_literal_manifest_queue_and_payload_are_independent(self):
        expected = [{"path": path, "size": len(body), "sha256": hashlib.sha256(body).hexdigest()} for path, body in sorted(BODIES.items())]
        self.assertEqual(P.fixture_manifest(), expected)
        for name in ("acquisition", "mismatch", "missing", "denial", "cancellation"):
            data = P.queue_bytes(name)
            self.assertTrue(data.startswith(b"\xef\xbb\xbf"))
            rows = list(csv.reader(io.StringIO(data.decode("utf-8-sig"))))
            self.assertEqual(rows[0], HEADER)
            self.assertTrue(all(len(row) == 8 and row[0] == "excel-safe-v1" for row in rows[1:]))
        self.assertEqual(P.payloads(), BODIES)

    def prepared_oracle(self, name):
        case = self.root / "oracle"
        case.mkdir()
        (case / "source.conf").write_bytes(b"[Synthetic]\ntype = http\nurl = http://127.0.0.1:54321/\n")
        config = materialize(case, name)
        return case, config

    def test_manifest_rejects_corrupt_bytes_extra_file_and_wrong_result(self):
        case, config = self.prepared_oracle("acquisition")
        base = case / "output/synthetic-case"
        manifest = next(base.glob("acquisition-*.json"))
        original = manifest.read_bytes()
        mutations = [lambda: (base / "downloads/Synthetic/README-synthetic.txt").write_bytes(b"wrong"),
            lambda: (base / "extra.private").write_bytes(b"canary"),
            lambda: dump(manifest, dict(json.loads(original), complete=False))]
        for mutate in mutations:
            with self.subTest(mutation=mutations.index(mutate)):
                mutate()
                with self.assertRaises(P.ProducerError):
                    P.check_manifest("acquisition", case, config, RUNTIME)
                (base / "downloads/Synthetic/README-synthetic.txt").write_bytes(BODIES["README-synthetic.txt"])
                (base / "extra.private").unlink(missing_ok=True)
                manifest.write_bytes(original)

    def test_listing_uses_exact_default_directory_time_and_keeps_full_row_oracle(self):
        case, _ = self.prepared_oracle("listing")
        path = case / "output/synthetic-case/listings/inventory.csv"
        original = list(csv.reader(io.StringIO(path.read_bytes().decode("utf-8-sig"), newline="")))
        self.assertEqual(P.check_listing(case), {"inventory_exact": True, "listing_complete": True})
        self.assertEqual(len(original), 7)
        self.assertEqual([row[4] for row in original[1:] if row[5] == "true"],
                         ["2000-01-01T00:00:00+00:00"] * 2)
        mutations = []
        for index in (5, 6):
            for timestamp in ("0001-01-01T00:00:00+00:00", "2001-01-01T00:00:00+00:00", "2000-01-01T00:00:00Z", ""):
                rows = copy.deepcopy(original)
                rows[index][4] = timestamp
                mutations.append(rows)
        for column in range(8):
            rows = copy.deepcopy(original)
            rows[1][column] = "invalid-synthetic-cell"
            mutations.append(rows)
        mutations.extend([original[:-1], original + [original[1]], [original[0]] + original[2:]])
        for index, rows in enumerate(mutations):
            with self.subTest(mutation=index):
                text = io.StringIO(newline="")
                csv.writer(text).writerows(rows)
                path.write_bytes(b"\xef\xbb\xbf" + text.getvalue().encode("utf-8"))
                with self.assertRaisesRegex(P.ProducerError, "^listing_invalid$"):
                    P.check_listing(case)

    def cleanup_observation(self, output):
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("application_cleanup_diagnostic="))
        value = json.loads(lines[0].split("=", 1)[1])
        self.assertEqual(set(value), {"scope", "stage", "location", "entries", "directories", "files", "total_bytes"})
        return value

    def post_helper_observation(self, output):
        lines = [line for line in output.getvalue().splitlines() if line.startswith("application_post_helper_diagnostic=")]
        self.assertEqual(len(lines), 1)
        value = json.loads(lines[0].split("=", 1)[1])
        self.assertEqual(set(value), {"scope", "stage", "location", "entries", "directories", "files", "total_bytes", "comparison", "allowlist"})
        self.assertNotIn("canary", output.getvalue())
        self.assertNotIn(str(self.root), output.getvalue())
        return value

    def test_cleanup_residue_reports_only_counts_and_preserves_primary_listing_failure(self):
        original_materialize = materialize
        def with_residue(case, name):
            config = original_materialize(case, name)
            path = case / "output/synthetic-case/listings/inventory.csv"
            path.write_bytes(path.read_bytes().replace(b"2000-01-01", b"0001-01-01"))
            private = case / "profile/private-name-canary"
            private.mkdir()
            (private / "private-content-canary").write_bytes(b"xyz")
            return config
        output = io.StringIO()
        with mock.patch(__name__ + ".materialize", side_effect=with_residue), \
             mock.patch.object(P, "remove_owned") as remove, redirect_stdout(output):
            result, _, suite = self.execute_case("listing")
        self.assertEqual(result["failure_code"], "listing_invalid")
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["checks"]["process_cleanup"])
        self.assertFalse(result["checks"]["temp_cleanup"])
        remove.assert_not_called()
        self.assertEqual((suite / "listing/profile/private-name-canary/private-content-canary").read_bytes(), b"xyz")
        self.assertEqual(self.post_helper_observation(output), dict(scope="listing", stage="private_empty", location="profile",
            entries=2, directories=1, files=1, total_bytes=3, comparison=None, allowlist=None))
        self.assertNotIn("canary", output.getvalue())
        self.assertNotIn(str(self.root), output.getvalue())

    def test_cleanup_unreadable_inventory_has_unknown_counts_and_no_delete(self):
        original_inventory = P.inventory
        def failed(path):
            if Path(path).name == "appdata" and (Path(path).parent / "output/synthetic-case/listings/inventory.csv").exists():
                raise OSError("private-path-canary")
            return original_inventory(path)
        output = io.StringIO()
        with mock.patch.object(P, "inventory", side_effect=failed), mock.patch.object(P, "remove_owned") as remove, redirect_stdout(output):
            result, _, suite = self.execute_case("listing")
        self.assertEqual(result["failure_code"], "cleanup_failed")
        self.assertTrue(result["checks"]["inventory_exact"])
        self.assertFalse(result["checks"]["temp_cleanup"])
        self.assertTrue((suite / "listing").is_dir())
        remove.assert_not_called()
        self.assertEqual(self.post_helper_observation(output), dict(scope="listing", stage="private_inventory", location="appdata",
            entries=None, directories=None, files=None, total_bytes=None, comparison=None, allowlist=None))
        self.assertNotIn("canary", output.getvalue())

    def test_cleanup_removal_failure_is_distinct_from_successful_acl_verification(self):
        output = io.StringIO()
        with mock.patch.object(P, "remove_owned", side_effect=OSError("private-removal-canary")), redirect_stdout(output):
            result, _, suite = self.execute_case("listing")
        self.assertEqual(result["failure_code"], "cleanup_failed")
        self.assertTrue(result["checks"]["process_cleanup"])
        self.assertFalse(result["checks"]["temp_cleanup"])
        self.assertTrue((suite / "listing").is_dir())
        self.assertEqual(self.cleanup_observation(output), dict(scope="listing", stage="owned_removal", location=None,
            entries=None, directories=None, files=None, total_bytes=None))
        self.assertNotIn("canary", output.getvalue())

    def test_post_helper_structure_and_difference_diagnostics_never_allow_removal(self):
        def baseline(case):
            (case / "helper-env/temp/owned-child").mkdir()
        def replace(case):
            (case / "helper-env/temp/owned-child").rename(case / "private-canary-old")
            (case / "helper-env/temp/owned-child").mkdir()
        def different(case):
            (case / "helper-env/temp/owned-child").rmdir()
            (case / "helper-env/temp/private-canary-new").mkdir()
        def root_swap(case):
            (case / "helper-env/profile").rename(case / "private-canary-profile")
            (case / "helper-env/profile").mkdir()
        def over_limit(case):
            for index in range(28):
                (case / "helper-env/home" / str(index)).mkdir()
        variants = [
            (lambda c: (c / "helper-env/temp/private-canary-new").mkdir(), "helper_comparison", (1, 0, 0)),
            (replace, "helper_comparison", (0, 0, 1)), (different, "helper_comparison", (1, 1, 0)),
            (root_swap, "helper_identity", None), (over_limit, "helper_limit", None),
            (lambda c: (c / "helper-env/temp/private-canary-file").write_bytes(b"xyz"), "helper_directories", None),
            (lambda c: (c / "helper-env/private-canary-root").mkdir(), "helper_layout", None)]
        for index, (mutation, stage, counts) in enumerate(variants):
            output = io.StringIO()
            with self.subTest(stage=stage, index=index), mock.patch.object(P, "remove_owned") as remove:
                result, flow, suite = self.execute_profile_flow("post-helper-" + str(index), before_app=baseline,
                    after_app=mutation, output=output)
            value = self.post_helper_observation(output)
            self.assertEqual((value["stage"], value["location"]), (stage, "helper_env"))
            self.assertEqual(value["comparison"], None if counts is None else
                dict(zip(("new_entries", "removed_entries", "replaced_entries"), counts)))
            self.assertIsNone(value["allowlist"])
            if stage == "helper_identity":
                self.assertIsNone(value["entries"])
            else:
                self.assertIs(type(value["entries"]), int)
            self.assertEqual(result["failure_code"], "cleanup_failed")
            self.assertTrue(result["checks"]["inventory_exact"])
            self.assertTrue(result["checks"]["process_cleanup"])
            self.assertFalse(result["checks"]["temp_cleanup"])
            self.assertIn("start", flow.events)
            self.assertTrue((suite / "listing").exists())
            remove.assert_not_called()

    def test_post_helper_unknown_inventory_and_diagnostic_failure_preserve_original(self):
        case = self.root / "post-helper-direct"
        case.mkdir()
        leases = P.create_private_roots(case)
        baseline = P.prestart_baseline("listing", case, leases)
        original_inventory = P.inventory
        error = OSError("private-canary")
        for fail_output in (False, True):
            def inventory(path):
                if Path(path).name == "helper-env":
                    raise error
                return original_inventory(path)
            with mock.patch.object(P, "inventory", side_effect=inventory), redirect_stdout(io.StringIO()) as output:
                if fail_output:
                    with mock.patch.object(P, "post_helper_diagnostic", side_effect=RuntimeError("private-canary-output")), \
                         self.assertRaises(OSError) as caught:
                        P.post_helper_preserved("listing", case, leases, baseline)
                else:
                    with self.assertRaises(OSError) as caught:
                        P.post_helper_preserved("listing", case, leases, baseline)
            self.assertIs(caught.exception, error)
            if not fail_output:
                self.assertEqual(self.post_helper_observation(output), dict(scope="listing", stage="helper_inventory", location="helper_env",
                    entries=None, directories=None, files=None, total_bytes=None, comparison=None, allowlist=None))
        for invalid in (None, {"private-canary": ("private-canary", 0)}):
            with redirect_stdout(io.StringIO()) as output, self.assertRaisesRegex(P.ProducerError, "^cleanup_failed$"):
                P.post_helper_preserved("listing", case, leases, invalid)
            value = self.post_helper_observation(output)
            self.assertEqual(value["stage"], "helper_comparison")
            self.assertIsNone(value["comparison"])

    def test_probe_case_allowlist_and_size_failure_diagnostics_are_closed_counts(self):
        def extra(case):
            (case / "private-canary-dir").mkdir()
            (case / "private-canary-file").write_bytes(b"xyz")
        variants = [(extra, "case_layout", (1, 0, 1, 0)),
            (lambda c: (c / "bridge-stderr.private").unlink(), "case_layout", (0, 0, 0, 1)),
            (lambda c: (c / "bridge-stderr.private").write_bytes(b"x" * (1024 * 1024 + 1)), "case_file_limit", None)]
        for index, (mutation, stage, counts) in enumerate(variants):
            with self.subTest(index=index), self.probe_patches(), mock.patch.object(P, "prepare", side_effect=fake_prepare), \
                 mock.patch.object(P, "remove_owned") as remove, redirect_stdout(io.StringIO()) as output:
                self.assertEqual(P.bridge_probe(self.probe_bridge_factory(after_close=mutation)), 1)
            value = self.post_helper_observation(output)
            self.assertEqual((value["stage"], value["location"]), (stage, "case_root"))
            self.assertIsNone(value["comparison"])
            self.assertEqual(value["allowlist"], None if counts is None else
                dict(zip(("unexpected_directories", "missing_directories", "unexpected_files", "missing_files"), counts)))
            remove.assert_not_called()
        # A directory disappearing from the final whole-case inventory must be
        # reported distinctly even after its earlier leased-root check passed.
        original_inventory = P.inventory
        def missing_directory(path):
            value = original_inventory(path)
            if Path(path).name == "listing" and "bridge-stdout.private" in value:
                value.pop("profile")
            return value
        with self.probe_patches(), mock.patch.object(P, "prepare", side_effect=fake_prepare), \
             mock.patch.object(P, "inventory", side_effect=missing_directory), mock.patch.object(P, "remove_owned") as remove, \
             redirect_stdout(io.StringIO()) as output:
            self.assertEqual(P.bridge_probe(self.probe_bridge_factory()), 1)
        self.assertEqual(self.post_helper_observation(output)["allowlist"], dict(unexpected_directories=0,
            missing_directories=1, unexpected_files=0, missing_files=0))
        remove.assert_not_called()

    def test_probe_exact_cache_layout_diagnostic_never_allows_acceptance(self):
        def cache(case, filename="ModuleAnalysisCache", directory=False):
            parent = case / "Microsoft/Windows/PowerShell"
            parent.mkdir(parents=True)
            target = parent / filename
            if directory:
                target.mkdir()
            else:
                target.write_bytes(b"private-content-canary")
        def extra(case, directory=False):
            cache(case)
            if directory:
                (case / "private-name-canary").mkdir()
            else:
                (case / "private-name-canary").write_bytes(b"private-content-canary")
        def missing(case):
            cache(case)
            (case / "bridge-stderr.private").unlink()
        variants = [
            (cache, "powershell_module_cache_path_layout"),
            (lambda c: cache(c, "ModuleAnalysisCache-private-canary"), "unknown"),
            (extra, "unknown"), (lambda c: extra(c, True), "unknown"),
            (lambda c: cache(c, directory=True), "unknown"),
            (lambda c: (c / "Microsoft").write_bytes(b"private-content-canary"), "unknown"),
            (missing, "unknown"),
        ]
        for index, (mutation, label) in enumerate(variants):
            with self.subTest(index=index), self.probe_patches(), mock.patch.object(P, "prepare", side_effect=fake_prepare), \
                 mock.patch.object(P, "remove_owned") as remove, redirect_stdout(io.StringIO()) as output:
                self.assertEqual(P.bridge_probe(self.probe_bridge_factory(after_close=mutation)), 1)
            lines = [line for line in output.getvalue().splitlines() if line.startswith("application_case_layout_diagnostic=")]
            self.assertEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0].split("=", 1)[1]), dict(scope="listing", classification=label))
            self.assertEqual(self.post_helper_observation(output)["stage"], "case_layout")
            self.assertNotIn("ModuleAnalysisCache", output.getvalue())
            self.assertNotIn("Microsoft/", output.getvalue())
            self.assertNotIn("application_bridge_probe_passed", output.getvalue())
            remove.assert_not_called()

    def test_probe_unsafe_inventory_never_classifies_a_layout(self):
        original_inventory = P.inventory
        def unsafe(path):
            if Path(path).name == "listing" and (Path(path) / "bridge-stdout.private").exists():
                raise OSError("private-content-canary")
            return original_inventory(path)
        with self.probe_patches(), mock.patch.object(P, "prepare", side_effect=fake_prepare), \
             mock.patch.object(P, "inventory", side_effect=unsafe), mock.patch.object(P, "remove_owned") as remove, \
             redirect_stdout(io.StringIO()) as output:
            self.assertEqual(P.bridge_probe(self.probe_bridge_factory()), 1)
        self.assertEqual(self.post_helper_observation(output)["stage"], "case_inventory")
        self.assertNotIn("application_case_layout_diagnostic=", output.getvalue())
        remove.assert_not_called()

    def test_case_layout_diagnostic_failure_preserves_original_exception(self):
        case = self.root / "layout-diagnostic"
        case.mkdir()
        leases = P.create_private_roots(case)
        baseline = P.prestart_baseline("listing", case, leases)
        # Missing required transcript files force the unchanged layout check.
        original = P.ProducerError("cleanup_failed")
        original_need = P.need
        def need(condition, code):
            if not condition and code == "cleanup_failed":
                raise original
            return original_need(condition, code)
        with mock.patch.object(P, "need", side_effect=need), \
             mock.patch.object(P, "case_layout_diagnostic", side_effect=OSError("private-content-canary")) as diagnostic, \
             redirect_stdout(io.StringIO()) as output, self.assertRaises(P.ProducerError) as caught:
            P.post_helper_preserved("listing", case, leases, baseline, probe=True)
        self.assertIs(caught.exception, original)
        diagnostic.assert_called_once()
        self.assertNotIn("canary", output.getvalue())
        self.assertTrue(case.is_dir())
        with redirect_stdout(io.StringIO()) as output, self.assertRaises(P.ProducerError):
            P.case_layout_diagnostic("private-name-canary", set(), set(), set(), set())
        self.assertEqual(output.getvalue(), "")

    def test_post_helper_diagnostic_rejects_unknown_fields_and_unsafe_counts(self):
        summary = dict(entries=5, directories=5, files=0, total_bytes=0)
        base = dict(name="listing", stage="helper_comparison", location="helper_env", summary=summary,
            comparison=dict(new_entries=1, removed_entries=0, replaced_entries=0))
        mutations = [dict(name="private-canary"), dict(stage="private-canary"), dict(location="private-canary"),
            dict(stage="helper_identity"), dict(summary=dict(summary, entries=True)),
            dict(comparison=dict(new_entries=33, removed_entries=0, replaced_entries=0)),
            dict(comparison=dict(new_entries="1", removed_entries=0, replaced_entries=0)),
            dict(comparison=dict(new_entries=1, removed_entries=0, replaced_entries=0, private_canary=1)),
            dict(allowlist=dict(unexpected_directories=0, missing_directories=0, unexpected_files=0, missing_files=0))]
        for mutation in mutations:
            with redirect_stdout(io.StringIO()) as output, self.assertRaises(P.ProducerError):
                P.post_helper_diagnostic(**dict(base, **mutation))
            self.assertEqual(output.getvalue(), "")
        for bad in (True, -1, 1025, "1"):
            with redirect_stdout(io.StringIO()) as output, self.assertRaises(P.ProducerError):
                P.post_helper_diagnostic("listing", "case_layout", "case_root", allowlist=dict(
                    unexpected_directories=bad, missing_directories=0, unexpected_files=0, missing_files=0))
            self.assertEqual(output.getvalue(), "")

    def test_cleanup_diagnostic_rejects_unbounded_or_nonfinite_fields(self):
        counts = dict(entries=2, directories=1, files=1, total_bytes=3)
        for fields in (("private-case", "private_inventory", "profile", counts),
                       ("listing", "private-stage", "profile", counts),
                       ("listing", "private_inventory", "private-path", counts),
                       ("listing", "private_inventory", "profile", dict(counts, entries=True)),
                       ("listing", "private_inventory", "profile", dict(counts, entries=1025)),
                       ("listing", "private_inventory", "profile", dict(counts, files=0)),
                       ("listing", "private_inventory", "profile", dict(counts, total_bytes=512 * 1024 * 1024 + 1)),
                       ("listing", "private_inventory", "profile", dict(counts, extra="private-canary")),
                       ("listing", "owned_removal", None, counts)):
            with self.subTest(fields=fields[:3]), redirect_stdout(io.StringIO()) as output:
                with self.assertRaisesRegex(P.ProducerError, "^cleanup_failed$"):
                    P.cleanup_diagnostic(*fields)
                self.assertEqual(output.getvalue(), "")

    def test_wrong_hash_must_retain_exact_original_bytes(self):
        case, config = self.prepared_oracle("mismatch")
        self.assertTrue(P.check_manifest("mismatch", case, config, RUNTIME)["retained_bytes_exact"])
        (case / "output/synthetic-case/downloads/Synthetic/README-synthetic.txt").unlink()
        with self.assertRaises(P.ProducerError):
            P.check_manifest("mismatch", case, config, RUNTIME)

    def test_config_snapshot_and_original_are_both_required(self):
        case, config = self.prepared_oracle("listing")
        original = (case / "source.conf").read_bytes()
        self.assertEqual(P.configuration_preserved(case, original), config)
        for path in (case / "source.conf", config):
            path.write_bytes(b"mutated")
            with self.assertRaises(P.ProducerError):
                P.configuration_preserved(case, original)
            path.write_bytes(original)

    def test_strict_json_and_session_privacy(self):
        for value in (b'{"x":1,"x":2}', b'{"x":NaN}'):
            with self.assertRaises(P.ProducerError):
                P.strict_json(value)
        good = session("finish", final=True)
        self.assertEqual(P.validate_session(good, "finish"), good)
        mutations = [dict(good, unknown="private canary"), dict(good, app_exit_code=True),
            dict(good, runtime_sha256=None), dict(good, errors=["private canary"], ok=False),
            dict(good, schema_version=True), dict(good, action="poll")]
        for value in mutations:
            with self.assertRaisesRegex(P.ProducerError, "^session_failed$"):
                P.validate_session(value, "finish")

    def test_runtime_cleanup_parser_accepts_only_complete_closed_native_records(self):
        stages = ("target", "open_root", "identity", "security", "remove_tree")
        kinds = ("not_found", "permission_denied", "already_exists", "invalid_input", "unsupported", "interrupted", "other")
        for stage in stages:
            for kind in kinds:
                for code in (None, 0, 32, 65535):
                    value = dict(stage=stage, kind=kind, os_code=code)
                    line = b"runtime_cleanup_diagnostic=" + json.dumps(value, separators=(",", ":")).encode("ascii")
                    self.assertLessEqual(len(line), 112)
                    for ending in (b"\n", b"\r\n"):
                        with self.subTest(stage=stage, kind=kind, code=code, ending=ending):
                            self.assertEqual(P.parse_runtime_cleanup_diagnostic(b"private-canary\n" + line + ending + b"other private text"), value)

    def test_runtime_cleanup_parser_refuses_duplicates_canaries_types_and_terminal_normalization(self):
        good = b'runtime_cleanup_diagnostic={"stage":"remove_tree","kind":"permission_denied","os_code":32}\n'
        bad = [None, "private-canary", bytearray(good), b"", b"x" * (8 * 1024 * 1024 + 1),
               good[:-1], good + good, good + b"runtime_cleanup_diagnostic=private-canary\n",
               good.replace(b"remove_tree", b"remove_\ntree"), good.replace(b"remove_tree", b"remove_\x1b[0mtree"),
               good.replace(b"=", b":", 1), good.replace(b"=", b"= ", 1),
               good.replace(b"remove_tree", b"private-canary"), good.replace(b"permission_denied", b"private-canary"),
               good.replace(b'"stage":"remove_tree"', b'"stage":true'), good.replace(b'"kind":"permission_denied"', b'"kind":null'),
               good.replace(b'"stage":"remove_tree"', b'"stage":"remove_tree","stage":"target"'),
               good.replace(b'"stage":"remove_tree","kind":"permission_denied"', b'"kind":"permission_denied","stage":"remove_tree"'),
               good.replace(b"32}", b'32,"path":"private-canary"}'), good.replace(b"32}", b'32,"x":null}'),
               good.replace(b'"os_code":32', b'"os_code":null,"os_code":32'),
               good.replace(b"remove_tree", b"remove\\u005ftree"), good.replace(b"remove_tree", b"remove\x00tree"),
               good.replace(b"remove_tree", "remove_\u00a0tree".encode()), b"x" * 4096 + good]
        for token in (b"true", b"false", b"-1", b"65536", b"32.0", b'"32"', b"[]", b"{}", b"NaN", b"Infinity"):
            bad.append(good.replace(b"32}", token + b"}"))
        with redirect_stdout(io.StringIO()) as output:
            for index, data in enumerate(bad):
                with self.subTest(index=index):
                    self.assertIsNone(P.parse_runtime_cleanup_diagnostic(data))
        self.assertEqual(output.getvalue(), "")

    def test_runtime_cleanup_intact_record_discards_bounded_terminal_decoration(self):
        record = b'runtime_cleanup_diagnostic={"stage":"remove_tree","kind":"permission_denied","os_code":32}'
        expected = dict(stage="remove_tree", kind="permission_denied", os_code=32)
        for prefix, suffix in ((b" ", b" "), (b"\x1b[0m", b"\x1b[0m"),
                               (b"private-canary-prefix\x1b[20;1H", b"private-canary-suffix\r"),
                               (b"x" * (4096 - len(record)), b"")):
            with self.subTest(prefix_bytes=len(prefix), suffix_bytes=len(suffix)), redirect_stdout(io.StringIO()) as output:
                parsed = P.parse_runtime_cleanup_diagnostic(prefix + record + suffix + b"\r\n")
                self.assertEqual(parsed, expected)
                P.runtime_cleanup_diagnostic("listing", parsed)
                self.assertEqual(json.loads(output.getvalue().split("=", 1)[1]), dict(scope="listing", **expected))
                self.assertNotIn("private-canary", output.getvalue())
                self.assertNotIn("\x1b", output.getvalue())
        self.assertIsNone(P.parse_runtime_cleanup_diagnostic(b"x" * (4097 - len(record)) + record + b"\n"))
        self.assertIsNone(P.parse_runtime_cleanup_diagnostic(b"runtime_cleanup_diagnostic=bad\x1b[0m" + record + b"\n"))

    def test_runtime_cleanup_read_requires_unchanged_case_and_bounded_private_file(self):
        case = self.root / "runtime-diagnostic-read"
        case.mkdir()
        data = b'runtime_cleanup_diagnostic={"stage":"identity","kind":"other","os_code":null}\n'
        (case / "transcript.private").write_bytes(data)
        lease = P.identity(case)
        self.assertEqual(P.read_runtime_cleanup_diagnostic(case, lease), dict(stage="identity", kind="other", os_code=None))
        with mock.patch.object(P, "identity", return_value=(lease[0], lease[1] + 1)), mock.patch.object(P, "read") as read:
            self.assertIsNone(P.read_runtime_cleanup_diagnostic(case, lease))
            read.assert_not_called()
        with mock.patch.object(P, "identity", side_effect=[lease, (lease[0], lease[1] + 1)]):
            self.assertIsNone(P.read_runtime_cleanup_diagnostic(case, lease))
        for error in (OSError("private-canary"), P.ProducerError("preservation_failed")):
            with mock.patch.object(P, "read", side_effect=error), redirect_stdout(io.StringIO()) as output:
                self.assertIsNone(P.read_runtime_cleanup_diagnostic(case, lease))
                self.assertEqual(output.getvalue(), "")
        (case / "transcript.private").write_bytes(b"x" * (8 * 1024 * 1024 + 1))
        self.assertIsNone(P.read_runtime_cleanup_diagnostic(case, lease))

    def test_runtime_cleanup_diagnostic_preserves_late_cleanup_failure_and_private_tree(self):
        def residue(case):
            (case / "transcript.private").write_bytes(b'private-canary\nruntime_cleanup_diagnostic={"stage":"remove_tree","kind":"permission_denied","os_code":32}\n')
            directory = case / "temp/private-canary-runtime"
            directory.mkdir()
            (directory / "private-canary.exe").write_bytes(b"inert")
        with redirect_stdout(io.StringIO()) as output:
            record, _, suite = self.execute_case("listing", after_app=residue)
        self.assertEqual((record["status"], record["failure_code"], record["exit_code"]), ("failed", "cleanup_failed", 0))
        self.assertFalse(record["checks"]["temp_cleanup"])
        self.assertTrue(all(value for key, value in record["checks"].items() if key != "temp_cleanup"))
        self.assertTrue((suite / "listing/temp/private-canary-runtime/private-canary.exe").is_file())
        lines = [line for line in output.getvalue().splitlines() if line.startswith("application_runtime_cleanup_diagnostic=")]
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0].split("=", 1)[1]), dict(scope="listing", stage="remove_tree", kind="permission_denied", os_code=32))
        self.assertNotIn("private-canary", output.getvalue())

    def residue_pair(self, **changes):
        value = dict(root="same_private_directory", executable="regular_file", other_files=0,
                     other_directories=0, other_reparse_points=0, other_entries=0, complete=True)
        value.update(changes)
        diagnostic = b'runtime_cleanup_diagnostic={"stage":"remove_tree","kind":"other","os_code":32}\n'
        line = b"runtime_cleanup_residue=" + json.dumps(value, separators=(",", ":")).encode("ascii") + b"\n"
        return value, diagnostic + line

    def test_runtime_residue_pair_accepts_only_complete_bounded_observations(self):
        for kind in ("absent", "regular_file", "directory", "reparse_point", "other"):
            for count in (0, 1, 7):
                value, pair = self.residue_pair(executable=kind, other_files=count)
                self.assertEqual(P.parse_runtime_cleanup_residue(pair), value)
                self.assertEqual(P.parse_runtime_cleanup_residue(pair.replace(b"\n", b"\r\n")), value)
        value, pair = self.residue_pair(root="unavailable", executable="unavailable", complete=False,
            other_files=None, other_directories=None, other_reparse_points=None, other_entries=None)
        self.assertEqual(P.parse_runtime_cleanup_residue(pair), value)
        value, pair = self.residue_pair(executable="absent", other_directories=8)
        self.assertEqual(P.parse_runtime_cleanup_residue(pair), value)

    def test_runtime_residue_parser_rejects_ambiguous_private_or_normalized_records(self):
        _, pair = self.residue_pair()
        diagnostic, residue, _ = pair.split(b"\n")
        bad = [None, "private-canary", bytearray(pair), b"", b"x" * (8 * 1024 * 1024 + 1),
            residue + b"\n", pair[:-1], pair + pair, pair + b"runtime_cleanup_residue=private-canary\n",
            diagnostic + b"\ninterleaved\n" + residue + b"\n", residue + b"\n" + diagnostic + b"\n",
            pair.replace(b"remove_tree", b"security"), pair.replace(b"same_private_directory", b"private-canary"),
            pair.replace(b"regular_file", b"private-canary"), pair.replace(b"regular_file", b"regular_\x1b[0mfile"),
            pair.replace(b"regular_file", b"regular_\nfile"), pair.replace(b"regular_file", b"regular\\u005ffile"),
            pair.replace(b'"other_files":0', b'"other_files":true'),
            pair.replace(b'"other_files":0', b'"other_files":0,"other_files":1'),
            pair.replace(b'"complete":true', b'"complete":true,"path":"private-canary"'),
            pair.replace(b'"complete":true', b'"complete":true,"owner":"private-canary"'),
            pair.replace(b'"complete":true', b'"complete":true,"pid":123'),
            pair.replace(b"residue=", b"residue= "), pair.replace(b"residue=", b"residue:"),
            diagnostic + b"\n" + b"x" * 4096 + residue + b"\n"]
        for data in bad:
            self.assertIsNone(P.parse_runtime_cleanup_residue(data))
        for changes in ({"complete": 1}, {"complete": False}, {"other_files": -1},
            {"other_files": 8}, {"other_files": 4, "other_entries": 4}, {"other_files": 0.0},
            {"other_files": None}, {"executable": "unavailable"}, {"root": "unavailable"}):
            _, data = self.residue_pair(**changes)
            self.assertIsNone(P.parse_runtime_cleanup_residue(data))

    def test_runtime_residue_output_excludes_surrounding_terminal_and_private_text(self):
        expected, pair = self.residue_pair()
        lines = pair.splitlines()
        decorated = b"private-canary\n" + b"\n".join(b"\x1b[0m" + line + b" private-canary" for line in lines) + b"\n"
        with redirect_stdout(io.StringIO()) as output:
            P.runtime_cleanup_residue("missing", P.parse_runtime_cleanup_residue(decorated))
        self.assertEqual(json.loads(output.getvalue().split("=", 1)[1]), dict(scope="missing", **expected))
        self.assertNotIn("private-canary", output.getvalue())
        self.assertNotIn("\x1b", output.getvalue())

    def test_runtime_residue_retains_failure_and_owned_material(self):
        expected, pair = self.residue_pair()
        def residue(case):
            (case / "transcript.private").write_bytes(b"private-canary\n" + pair)
            (case / "temp/private-canary").mkdir()
        with redirect_stdout(io.StringIO()) as output:
            record, _, suite = self.execute_case("listing", after_app=residue)
        self.assertEqual((record["status"], record["failure_code"]), ("failed", "cleanup_failed"))
        self.assertFalse(record["checks"]["temp_cleanup"])
        self.assertTrue((suite / "listing/temp/private-canary").is_dir())
        lines = [s for s in output.getvalue().splitlines() if s.startswith("application_runtime_cleanup_residue=")]
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0].split("=", 1)[1]), dict(scope="listing", **expected))
        self.assertNotIn("private-canary", output.getvalue())

    def test_runtime_residue_reader_binds_pair_to_saved_diagnostic_and_case(self):
        value, pair = self.residue_pair()
        case = self.root / "paired-diagnostic"
        case.mkdir()
        (case / "transcript.private").write_bytes(pair)
        lease = P.identity(case)
        diagnostic = dict(stage="remove_tree", kind="other", os_code=32)
        self.assertEqual(P.read_runtime_cleanup_residue(case, lease, diagnostic), value)
        for changed in (dict(diagnostic, os_code=None), dict(diagnostic, kind="permission_denied"),
                        dict(diagnostic, stage="identity"), None):
            self.assertIsNone(P.read_runtime_cleanup_residue(case, lease, changed))
        with mock.patch.object(P, "identity", side_effect=[lease, (-1, -1)]):
            self.assertIsNone(P.read_runtime_cleanup_residue(case, lease, diagnostic))
        with mock.patch.object(P, "read", side_effect=OSError("private-canary")), redirect_stdout(io.StringIO()) as output:
            self.assertIsNone(P.read_runtime_cleanup_residue(case, lease, diagnostic))
        self.assertEqual(output.getvalue(), "")

    def test_runtime_residue_changed_between_reads_keeps_original_failure_only(self):
        _, pair = self.residue_pair()
        original_read = P.read_runtime_cleanup_diagnostic
        def after_app(case):
            (case / "transcript.private").write_bytes(pair)
            (case / "temp/private-canary").mkdir()
        def change_after_first_read(case, lease):
            first = original_read(case, lease)
            (case / "transcript.private").write_bytes(pair.replace(b'"os_code":32', b'"os_code":5'))
            return first
        with mock.patch.object(P, "read_runtime_cleanup_diagnostic", side_effect=change_after_first_read), redirect_stdout(io.StringIO()) as output:
            record, _, suite = self.execute_case("listing", after_app=after_app)
        self.assertEqual((record["status"], record["failure_code"]), ("failed", "cleanup_failed"))
        self.assertFalse(record["checks"]["temp_cleanup"])
        self.assertTrue((suite / "listing/temp/private-canary").is_dir())
        lines = [s for s in output.getvalue().splitlines() if s.startswith("application_runtime_cleanup_diagnostic=")]
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0].split("=", 1)[1])["os_code"], 32)
        self.assertNotIn("application_runtime_cleanup_residue=", output.getvalue())
        self.assertNotIn("private-canary", output.getvalue())

    def test_runtime_residue_is_not_read_on_success_or_unconfirmed_helper_close(self):
        _, pair = self.residue_pair()
        def transcript(case):
            (case / "transcript.private").write_bytes(pair)
        with mock.patch.object(P, "read_runtime_cleanup_residue", side_effect=AssertionError("must not read")) as read:
            passed, _, _ = self.execute_case("listing", after_app=transcript)
            failed, _, suite = self.execute_case("listing", suite_name="unconfirmed", after_app=transcript, close_ok=False)
        read.assert_not_called()
        self.assertEqual(passed["status"], "passed")
        self.assertEqual(failed["status"], "failed")
        self.assertTrue((suite / "listing").is_dir())

    def test_runtime_residue_diagnostic_errors_never_replace_original_failure(self):
        _, pair = self.residue_pair()
        def residue(case):
            (case / "transcript.private").write_bytes(pair)
            (case / "temp/private-canary").mkdir()
        for function in ("read_runtime_cleanup_residue", "runtime_cleanup_residue"):
            with mock.patch.object(P, function, side_effect=RuntimeError("private-canary")), redirect_stdout(io.StringIO()) as output:
                record, _, suite = self.execute_case("listing", suite_name=function, after_app=residue)
            self.assertEqual((record["status"], record["failure_code"]), ("failed", "cleanup_failed"))
            self.assertTrue((suite / "listing/temp/private-canary").is_dir())
            self.assertNotIn("private-canary", output.getvalue())

    def test_runtime_cleanup_diagnostic_captures_early_failure_before_existing_removal(self):
        def failed_listing(case):
            (case / "transcript.private").write_bytes(b'runtime_cleanup_diagnostic={"stage":"security","kind":"other","os_code":null}\n')
            (case / "output/synthetic-case/listings/inventory.csv").write_bytes(b"private-canary-invalid-inventory")
        with redirect_stdout(io.StringIO()) as output:
            record, _, suite = self.execute_case("listing", after_app=failed_listing)
        self.assertEqual((record["status"], record["failure_code"]), ("failed", "listing_invalid"))
        self.assertTrue(record["checks"]["temp_cleanup"])
        self.assertFalse((suite / "listing").exists())
        self.assertEqual(output.getvalue().count("application_runtime_cleanup_diagnostic="), 1)
        self.assertNotIn("private-canary", output.getvalue())

    def test_runtime_cleanup_transcript_never_read_for_success_or_uncertain_helper_close(self):
        def transcript(case):
            (case / "transcript.private").write_bytes(b'runtime_cleanup_diagnostic={"stage":"target","kind":"other","os_code":null}\n')
        with mock.patch.object(P, "read_runtime_cleanup_diagnostic", side_effect=AssertionError("must not read")) as read, redirect_stdout(io.StringIO()) as output:
            passed, _, _ = self.execute_case("listing", after_app=transcript)
            failed, _, suite = self.execute_case("listing", suite_name="uncertain-reader", after_app=transcript, close_ok=False)
        read.assert_not_called()
        self.assertEqual(passed["status"], "passed")
        self.assertEqual(failed["status"], "failed")
        self.assertFalse(failed["checks"]["process_cleanup"])
        self.assertTrue((suite / "listing").exists())
        self.assertNotIn("application_runtime_cleanup_diagnostic=", output.getvalue())

    def test_runtime_cleanup_diagnostic_failures_cannot_replace_original_failure(self):
        def residue(case):
            (case / "transcript.private").write_bytes(b'runtime_cleanup_diagnostic={"stage":"remove_tree","kind":"other","os_code":null}\n')
            (case / "temp/private-canary").mkdir()
        for function in ("read_runtime_cleanup_diagnostic", "runtime_cleanup_diagnostic"):
            with mock.patch.object(P, function, side_effect=RuntimeError("private-canary-error")), redirect_stdout(io.StringIO()) as output:
                record, _, suite = self.execute_case("listing", suite_name=function, after_app=residue)
            self.assertEqual((record["status"], record["failure_code"]), ("failed", "cleanup_failed"))
            self.assertFalse(record["checks"]["temp_cleanup"])
            self.assertTrue((suite / "listing/temp/private-canary").exists())
            self.assertNotIn("private-canary", output.getvalue())

    def test_runtime_limits_and_observed_counts_are_strict_and_per_case(self):
        for name in ("listing", "acquisition", "mismatch", "missing", "denial", "cancellation"):
            self.assertEqual(P.runtime_process_limit(name), 4 if name == "acquisition" else 1)
        with mock.patch.object(P, "queue_rows", return_value=list(range(9))):
            self.assertEqual(P.runtime_process_limit("acquisition"), 4)
        with self.assertRaises(P.ProducerError):
            P.runtime_process_limit("private-canary")
        good = session("observe_runtime")
        for count in (None, 0, 1, 4, 5, 64):
            self.assertEqual(P.validate_session(dict(good, runtime_process_count=count), "observe_runtime")["runtime_process_count"], count)
        for count in (True, False, -1, 65, 1.0, "1", [], {}):
            with self.subTest(count=count), self.assertRaises(P.ProducerError):
                P.validate_session(dict(good, runtime_process_count=count), "observe_runtime")
        incomplete = dict(good)
        del incomplete["runtime_process_count"]
        with self.assertRaises(P.ProducerError):
            P.validate_session(incomplete, "observe_runtime")

    def test_runtime_failure_diagnostic_is_closed_bounded_and_never_contains_raw_values(self):
        for count, classification in ((None, "unavailable"), (0, "none"), (1, "single"), (4, "multiple"), (64, "multiple")):
            value = session("observe_runtime", final=True, observed=False, exit_code=99)
            value.update(ok=False, runtime_process_count=count, forced_termination=True,
                         errors=["runtime_observation_failed", "forced_termination"])
            with redirect_stdout(io.StringIO()) as output:
                P.session_failure_diagnostic(value, "observe_runtime")
            rendered = output.getvalue()
            self.assertLessEqual(len(rendered.encode()), 4096)
            self.assertEqual(json.loads(rendered.split("=", 1)[1]), dict(action="observe_runtime",
                errors=value["errors"], forced_termination=True, app_exited=True,
                runtime_process_count=count, count_classification=classification))
        for bad in (dict(value, errors=["private-canary"]), dict(value, secret="private-canary"),
                    dict(value, runtime_process_count=True), dict(value, forced_termination=1),
                    dict(value, app_exited="private-canary"), session("observe_runtime")):
            with redirect_stdout(io.StringIO()) as output, self.assertRaises(P.ProducerError):
                P.session_failure_diagnostic(bad, "observe_runtime")
            self.assertEqual(output.getvalue(), "")

    def test_parallel_runtime_bound_is_required_even_when_later_cleanup_completes(self):
        for index, (name, count) in enumerate((("acquisition", 0), ("acquisition", 5), ("acquisition", True),
                            ("listing", 2), ("mismatch", None))):
            with self.subTest(name=name, count=count), redirect_stdout(io.StringIO()):
                record, flow, _ = self.execute_case(name, suite_name="runtime-negative-" + str(index), runtime_count=count, close_final=True)
            self.assertEqual(record["status"], "failed")
            self.assertEqual(record["failure_code"], "runtime_unobserved")
            self.assertFalse(record["checks"]["runtime_observed"])
            self.assertTrue(record["checks"]["process_cleanup"])
            self.assertTrue(record["checks"]["fixture_cleanup"])
            self.assertEqual(record["exit_code"], 99)
            self.assertNotIn("poll", flow.events)
        for count in (1, 2, 4):
            with self.subTest(count=count):
                record, _, _ = self.execute_case("acquisition", suite_name="runtime-positive-" + str(count), runtime_count=count)
            self.assertEqual(record["status"], "passed")

    def test_bridge_failure_diagnostic_does_not_replace_or_promote_failed_response(self):
        failure = session("observe_runtime", final=True, observed=False, exit_code=99)
        failure.update(ok=False, runtime_process_count=5, forced_termination=True,
                       errors=["runtime_observation_failed", "forced_termination"])
        for printing_failure in (False, True):
            bridge = self.bare_bridge("runtime-diagnostic-" + str(printing_failure))
            self.reply_on_write(bridge)
            bridge.command("ready")
            self.reply_on_write(bridge, json.dumps(failure).encode())
            with redirect_stdout(io.StringIO()) as output:
                if printing_failure:
                    with mock.patch.object(P, "session_failure_diagnostic", side_effect=OSError("private-canary")):
                        result = bridge.command("observe_runtime")
                else:
                    result = bridge.command("observe_runtime")
            self.assertEqual(result, failure)
            self.assertEqual(bridge.last, failure)
            self.assertFalse(result["ok"])
            self.assertNotIn("canary", output.getvalue())
            if not printing_failure:
                self.assertEqual(json.loads(output.getvalue().split("=", 1)[1])["count_classification"], "multiple")

    def test_fixed_pins_are_closed(self):
        path = self.root / "pins"
        content = ("RCLONE_VERSION=9.8.7\n" + "".join(key + "=" + "a" * 64 + "\n" for key in (
            "RCLONE_EXE_SHA256", "RCLONE_WINDOWS_ZIP_SHA256", "RCLONE_LINUX_ZIP_SHA256", "RCLONE_LINUX_EXE_SHA256"))).encode()
        path.write_bytes(content)
        self.assertEqual(P.runtime_pins(path)["version"], "9.8.7")
        for bad in (content + b"RCLONE_VERSION=9.9.9\n", content.replace(b"9.8.7", b"latest"), content + b"UNKNOWN=x\n"):
            path.write_bytes(bad)
            with self.assertRaises(P.ProducerError):
                P.runtime_pins(path)

    def test_runtime_pin_architectures_require_legacy_or_complete_schema(self):
        path = self.root / "pins"
        content = ("RCLONE_VERSION=9.8.7\n" + "".join(key + "=" + "a" * 64 + "\n" for key in (
            "RCLONE_EXE_SHA256", "RCLONE_WINDOWS_ZIP_SHA256", "RCLONE_LINUX_ZIP_SHA256", "RCLONE_LINUX_EXE_SHA256")))
        extra = [f"{key}={digest * 64}\n" for key, digest in (
            ("RCLONE_WINDOWS_X86_EXE_SHA256", "b"), ("RCLONE_WINDOWS_X86_ZIP_SHA256", "c"),
            ("RCLONE_WINDOWS_ARM64_EXE_SHA256", "d"), ("RCLONE_WINDOWS_ARM64_ZIP_SHA256", "e"))]
        for mask in range(16):
            with self.subTest(mask=mask):
                path.write_text(content + "".join(line for index, line in enumerate(extra) if mask & (1 << index)), encoding="ascii")
                if mask in (0, 15):
                    self.assertEqual(P.runtime_pins(path), {"version": "9.8.7", "sha256": "a" * 64, "platform": "windows"})
                else:
                    with self.assertRaisesRegex(P.ProducerError, "^binding_failed$"):
                        P.runtime_pins(path)

    def test_runtime_pin_extra_hashes_cannot_escape_validation(self):
        path = self.root / "pins"
        extra_keys = ("RCLONE_WINDOWS_X86_EXE_SHA256", "RCLONE_WINDOWS_X86_ZIP_SHA256",
                      "RCLONE_WINDOWS_ARM64_EXE_SHA256", "RCLONE_WINDOWS_ARM64_ZIP_SHA256")
        pins = {key: "a" * 64 for key in ("RCLONE_EXE_SHA256", "RCLONE_WINDOWS_ZIP_SHA256",
                "RCLONE_LINUX_ZIP_SHA256", "RCLONE_LINUX_EXE_SHA256", *extra_keys)}
        pins["RCLONE_VERSION"] = "9.8.7"
        content = "".join(f"{key}={value}\n" for key, value in pins.items())
        for key in extra_keys:
            for bad in ("", "A" * 64, "a" * 63, "a" * 65, "sha256:" + "a" * 64):
                with self.subTest(key=key, bad=bad):
                    path.write_text(content.replace(f"{key}={'a' * 64}\n", f"{key}={bad}\n"), encoding="ascii")
                    with self.assertRaisesRegex(P.ProducerError, "^binding_failed$"):
                        P.runtime_pins(path)
            path.write_text(content + f"{key}={'a' * 64}\n", encoding="ascii")
            with self.assertRaisesRegex(P.ProducerError, "^binding_failed$"):
                P.runtime_pins(path)
        path.write_text(content + "UNKNOWN=value\n", encoding="ascii")
        with self.assertRaisesRegex(P.ProducerError, "^binding_failed$"):
            P.runtime_pins(path)

    def test_private_file_reader_rejects_links_but_release_source_can_be_copied(self):
        alias = self.root / "alias.exe"
        os.link(self.app, alias)
        with self.assertRaises(P.ProducerError):
            P.read(self.app)
        self.assertEqual(P.read(self.app, allow_hardlinks=True), b"inert application bytes")
        result, _, _ = self.execute_case("listing")
        self.assertEqual(result["status"], "passed")

    def test_prepare_unknown_outcome_never_claims_case_process_cleanup(self):
        with mock.patch.object(P, "prepare", side_effect=P.ProducerError("case_setup_failed")):
            result = P.run_case("listing", self.root, self.app, self.digest, RUNTIME)
        self.assertFalse(result["checks"]["process_cleanup"])
        self.assertEqual(result["failure_code"], "case_setup_failed")

    def test_case_verify_timeout_keeps_cleanup_false_and_directory(self):
        flow = Flow("listing")
        def prepare(parent, name, action="Create"):
            if action == "Verify":
                raise P.ProducerError("case_setup_failed")
            return fake_prepare(parent, name, action)
        with mock.patch.object(P, "prepare", side_effect=prepare), mock.patch.object(P.F, "serve_http", side_effect=flow.serve), mock.patch.object(P.time, "sleep"):
            result = P.run_case("listing", self.root, self.app, self.digest, RUNTIME, session_factory=flow.factory)
        self.assertFalse(result["checks"]["process_cleanup"])
        self.assertFalse(result["checks"]["temp_cleanup"])
        self.assertTrue((self.root / "listing/source.conf").exists())
        self.assertEqual(result["status"], "failed")

    def test_forced_app_exit_cannot_pass(self):
        result, _, _ = self.execute_case("acquisition", forced=True)
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["checks"]["orderly_exit"])
        self.assertEqual(result["failure_code"], "session_failed")

    def test_suite_creation_verification_failure_retains_uncertain_directory(self):
        def failed(parent, name, action="Create"):
            (parent / name).mkdir()
            raise P.ProducerError("case_setup_failed")
        with mock.patch.object(P, "hosted_guard"), mock.patch.object(P, "prepare", side_effect=failed):
            result = P.run(self.app, self.digest, "b" * 40)
        self.assertFalse(result["cleanup_complete"])
        self.assertEqual(result["capabilities"]["cleanup"], "failed")
        self.assertEqual(result["result"], "failed")
        self.assertIn("cleanup_failed", result["errors"])
        self.assertEqual(len(list(self.root.glob("app-http-*"))), 1)

    def test_suite_late_source_binding_failure_remains_failed(self):
        bindings = P.E.compute_bindings(ROOT, self.app, "b" * 40, P.fixture_manifest())
        drift = dict(bindings, application_source_sha256="0" * 64)
        def passed(name, *_):
            return {"status": "passed", "exit_code": 0 if name in {"listing", "acquisition"} else 1,
                "runtime_sha256": P.runtime_pins(ROOT / "rclone-version.env")["sha256"], "failure_code": None,
                "checks": {key: True for key in P.E.CASE_CHECKS[name]}}
        with mock.patch.object(P, "hosted_guard"), mock.patch.object(P, "prepare", side_effect=fake_prepare), \
             mock.patch.object(P, "run_case", side_effect=passed), mock.patch.object(P.E, "compute_bindings", side_effect=[bindings, drift]):
            result = P.run(self.app, self.digest, "b" * 40)
        self.assertTrue(result["cleanup_complete"])
        self.assertEqual(result["result"], "failed")
        self.assertEqual(result["errors"], ["preservation_failed"])

    def test_bridge_close_does_not_close_pipe_locked_by_live_reader(self):
        bridge = P.Bridge.__new__(P.Bridge)
        bridge.last = session("finish", final=True)
        bridge.forced = False
        bridge.done, bridge.failed = threading.Event(), threading.Event()
        bridge.messages = P.queue.Queue()
        bridge.watchdog = mock.Mock()
        bridge.watchdog.is_alive.return_value = False
        alive, dead = mock.Mock(), mock.Mock()
        alive.is_alive.return_value, dead.is_alive.return_value = True, False
        bridge.threads = [alive, dead]
        bridge.process = mock.Mock(returncode=0)
        bridge.process.poll.return_value = 0
        self.assertFalse(bridge.close())
        bridge.process.stdout.close.assert_not_called()
        bridge.process.stderr.close.assert_called_once()

    def bare_bridge(self, name):
        bridge = P.Bridge.__new__(P.Bridge)
        bridge.case = self.root / name
        bridge.case.mkdir()
        bridge.last, bridge.forced, bridge.ready = None, False, False
        bridge.closed_ready = False
        bridge.stage_bytes, bridge.stage_invalid = bytearray(), False
        bridge.failed, bridge.done = threading.Event(), threading.Event()
        bridge.response_lock = threading.Lock()
        bridge.responses = bridge.calls = 0
        bridge.messages = P.queue.Queue()
        bridge.deadline = P.time.monotonic() + 60
        bridge.process = mock.Mock(returncode=0)
        bridge.process.poll.return_value = None
        bridge.threads = []
        bridge.watchdog = mock.Mock()
        bridge.watchdog.is_alive.return_value = False
        actual_reader = bridge._reader
        bridge._reader = lambda stream, name: actual_reader(stream, name, P.private_file(bridge.case, "bridge-" + name + ".private"))
        return bridge

    def reply_on_write(self, bridge, raw=b'{"schema_version":1,"action":"ready","ok":true,"state":"ready"}'):
        def write(_):
            bridge.responses += 1
            bridge.messages.put(raw)
        bridge.process.stdin.write.side_effect = write

    def test_bridge_ready_preflight_errors_are_sticky_and_prevent_start(self):
        for scenario in ("missing", "repeat", "queued_duplicate"):
            with self.subTest(scenario=scenario):
                bridge = self.bare_bridge(scenario)
                self.reply_on_write(bridge)
                if scenario != "missing":
                    self.assertEqual(bridge.command("ready"), {"schema_version": 1, "action": "ready", "ok": True, "state": "ready"})
                if scenario == "queued_duplicate":
                    bridge.messages.put(b'{"schema_version":1,"action":"ready","ok":true,"state":"ready"}')
                before = bridge.process.stdin.write.call_count
                with self.assertRaisesRegex(P.ProducerError, "^session_failed$"):
                    bridge.command("ready" if scenario == "repeat" else "start")
                self.assertTrue(bridge.failed.is_set())
                with self.assertRaisesRegex(P.ProducerError, "^session_failed$"):
                    bridge.command("start")
                self.assertEqual(bridge.process.stdin.write.call_count, before)

    def test_bridge_bad_or_missing_ready_response_poisons_session(self):
        for index, raw in enumerate((b'{}', b'{"schema_version":true,"action":"ready","ok":true,"state":"ready"}',
                b'{"schema_version":1,"action":"ready","ok":true,"state":"ready","private-canary":1}',
                b'{"schema_version":1,"action":"ready","ok":false,"state":"ready"}', None)):
            with self.subTest(response=index):
                bridge = self.bare_bridge("bad-ready-" + str(index))
                if raw is None:
                    bridge.messages.get = mock.Mock(side_effect=P.queue.Empty)
                else:
                    self.reply_on_write(bridge, raw)
                with self.assertRaisesRegex(P.ProducerError, "^session_failed$"):
                    bridge.command("ready")
                self.assertTrue(bridge.failed.is_set())
                self.assertFalse(bridge.ready)
                self.assertEqual(bridge.process.stdin.write.call_count, 1)
                with self.assertRaisesRegex(P.ProducerError, "^session_failed$"):
                    bridge.command("start")
                self.assertEqual(bridge.process.stdin.write.call_count, 1)

    def test_bridge_cold_ready_wait_is_separate_and_never_resets_lifetime(self):
        for action in ("ready", "start", "poll", "finish", "close_ready"):
            for remaining in (165, 10.5):
                with self.subTest(action=action, remaining=remaining):
                    bridge = self.bare_bridge(f"wait-{action}-{remaining}")
                    bridge.deadline = remaining
                    if action == "ready":
                        reply = dict(schema_version=1, action=action, ok=True, state="ready")
                    else:
                        bridge.ready = True
                        bridge.calls = bridge.responses = 1
                        reply = (dict(schema_version=1, action=action, ok=True, state="closed") if action == "close_ready"
                                 else session(action, final=action == "finish"))
                    self.reply_on_write(bridge, json.dumps(reply).encode())
                    bridge.messages.get = mock.Mock(wraps=bridge.messages.get)
                    with mock.patch.object(P.time, "monotonic", return_value=0):
                        bridge.command(action)
                    bridge.messages.get.assert_called_once_with(timeout=min(60 if action == "ready" else 35, remaining))
                    self.assertEqual(bridge.deadline, remaining)

    def test_reader_duplicate_ready_and_late_unsolicited_reply_are_sticky(self):
        line = b'{"schema_version":1,"action":"ready","ok":true,"state":"ready"}\n'
        bridge = self.bare_bridge("duplicate-wire")
        bridge.process.stdin.write.side_effect = lambda _: bridge._reader(io.BytesIO(line + line), "stdout")
        with self.assertRaisesRegex(P.ProducerError, "^session_failed$"):
            bridge.command("ready")
        self.assertTrue(bridge.failed.is_set())
        with self.assertRaisesRegex(P.ProducerError, "^session_failed$"):
            bridge.command("start")
        self.assertEqual(bridge.process.stdin.write.call_count, 1)

        # A duplicate arriving after Start cannot be excluded in advance. It
        # must still poison final cleanup, even with an orderly final response.
        late = self.bare_bridge("late-wire")
        late.ready = True
        late.calls = late.responses = 2
        late.last = session("finish", final=True)
        late.process.poll.return_value = 0
        late._reader(io.BytesIO(line), "stdout")
        self.assertTrue(late.failed.is_set())
        self.assertFalse(late.close())

    def test_close_ready_is_exact_terminal_and_never_native_completion(self):
        bridge = self.bare_bridge("close-ready")
        self.reply_on_write(bridge)
        bridge.command("ready")
        raw = b'{"schema_version":1,"action":"close_ready","ok":true,"state":"closed"}'
        self.reply_on_write(bridge, raw)
        self.assertEqual(bridge.command("close_ready"), json.loads(raw))
        self.assertTrue(bridge.closed_ready)
        self.assertNotIn("app_exit_code", bridge.last)
        for action in ("start", "ready", "close_ready", "poll"):
            with self.subTest(action=action), redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(P.ProducerError, "^session_failed$"):
                    bridge.command(action)
        self.assertEqual(bridge.process.stdin.write.call_count, 2)
        self.assertTrue(bridge.failed.is_set())
        for value in ({}, dict(json.loads(raw), schema_version=True), dict(json.loads(raw), extra="private-canary"),
                      dict(json.loads(raw), ok=False), dict(json.loads(raw), state="finished")):
            with self.assertRaises(P.ProducerError):
                P.validate_close_ready(value)

    def test_close_ready_before_ready_after_start_and_extra_reply_are_rejected(self):
        for scenario in ("before", "after", "extra"):
            with self.subTest(scenario=scenario), redirect_stdout(io.StringIO()):
                bridge = self.bare_bridge("close-order-" + scenario)
                if scenario != "before":
                    self.reply_on_write(bridge)
                    bridge.command("ready")
                if scenario == "after":
                    self.reply_on_write(bridge, json.dumps(session("start")).encode())
                    bridge.command("start")
                if scenario == "extra":
                    raw = b'{"schema_version":1,"action":"close_ready","ok":true,"state":"closed"}\n'
                    bridge.process.stdin.write.side_effect = lambda _: bridge._reader(io.BytesIO(raw + raw), "stdout")
                before = bridge.process.stdin.write.call_count
                with self.assertRaisesRegex(P.ProducerError, "^session_failed$"):
                    bridge.command("close_ready")
                self.assertTrue(bridge.failed.is_set())
                self.assertEqual(bridge.process.stdin.write.call_count, before + (scenario == "extra"))

    def test_bridge_compile_markers_require_exact_complete_ordered_prefix(self):
        first = b"application_bridge_stage=compile\n"
        second = b"application_bridge_stage=compiled\n"
        self.assertEqual(P.bridge_stage(first), "compile")
        self.assertEqual(P.bridge_stage((first + second).replace(b"\n", b"\r\n")), "compiled")
        for raw in (b"", first[:-1], first + second[:-1], second, first + first, first + b"\n",
                    first + second + b"private-canary\n", b"private-canary\n" + first,
                    first.replace(b"=", b"=\r"), first + b"x" * 4097):
            with self.subTest(length=len(raw)):
                self.assertIsNone(P.bridge_stage(raw))
        bridge = self.bare_bridge("marker-reader")
        bridge._reader(io.BytesIO(first + second + b"private-canary\n"), "stderr")
        with redirect_stdout(io.StringIO()) as output:
            bridge._diagnostic("ready", "wait", "timeout")
        self.assertEqual(json.loads(output.getvalue().split("=", 1)[1]),
            dict(action="ready", phase="wait", outcome="timeout", last_stage=None))
        self.assertNotIn("canary", output.getvalue())

    def test_session_timeout_protocol_and_io_diagnostics_preserve_failure(self):
        for failure in ("timeout", "protocol", "write"):
            bridge = self.bare_bridge("session-diagnostic-" + failure)
            bridge.stage_bytes.extend(b"application_bridge_stage=compile\n")
            if failure == "timeout":
                bridge.messages.get = mock.Mock(side_effect=P.queue.Empty)
            elif failure == "protocol":
                self.reply_on_write(bridge, b'{"private-canary":"private-path"}')
            else:
                bridge.process.stdin.write.side_effect = OSError("private-canary")
            with self.subTest(failure=failure), redirect_stdout(io.StringIO()) as output:
                with self.assertRaisesRegex(P.ProducerError, "^session_failed$"):
                    bridge.command("ready")
            value = json.loads(output.getvalue().split("=", 1)[1])
            expected = {"timeout": ("wait", "timeout"), "protocol": ("reply", "protocol_failed"), "write": ("write", "io_failed")}[failure]
            self.assertEqual(value, dict(action="ready", phase=expected[0], outcome=expected[1], last_stage="compile"))
            self.assertTrue(bridge.failed.is_set())
            self.assertNotIn("canary", output.getvalue())
            if failure == "timeout":
                self.assertLessEqual(bridge.messages.get.call_args.kwargs["timeout"], 60)
        for fields in (("private-canary", "wait", "timeout", None), ("ready", "private-canary", "timeout", None),
                       ("ready", "wait", "private-canary", None), ("ready", "wait", "timeout", "private-canary")):
            with redirect_stdout(io.StringIO()) as output, self.assertRaises(P.ProducerError):
                P.session_diagnostic(*fields)
            self.assertEqual(output.getvalue(), "")

    def test_hosted_guard_rejects_self_hosted_before_setup(self):
        with mock.patch.object(P.os, "name", "nt"), mock.patch.dict(os.environ, {
                "GITHUB_ACTIONS": "true", "RUNNER_OS": "Windows", "RUNNER_ENVIRONMENT": "self-hosted"}):
            with self.assertRaisesRegex(P.ProducerError, "binding_failed"):
                P.hosted_guard()

    def test_fallback_cancel_release_is_not_a_disconnect(self):
        state = P.F.AppHttpState(P.payloads(), "cancellation")
        state.observation_started.set()
        state.release_observation()
        state.cancel_started.set()
        state.release_cancel()
        state.events = [["observation", ""], ["content", "large/cancel.bin"], ["cancel_prefix", "large/cancel.bin"]]
        with self.assertRaisesRegex(P.ProducerError, "cancellation_failed"):
            P.fixture_valid("cancellation", state.snapshot())

    @staticmethod
    def setup_stream(action="Create", stages=None, final=True, failure=None):
        # Literal sequence is independent of the parser's constants.
        if stages is None:
            stages = ["input", "parent", "identity", "acl", "compile", "create", "verify", "complete"] if action == "Create" else ["input", "parent", "identity", "verify", "complete"]
        records = [{"schema_version": 1, "stage": stage} for stage in stages]
        if final is not None:
            records.append({"schema_version": 1, "ok": final})
            if failure is not None:
                records[-1]["failure"] = failure
        return b"".join(json.dumps(value, separators=(",", ":")).encode() + b"\r\n" for value in records)

    def prepare_result(self, result=None, error=None, identity_effect=None, action="Create", failure=None):
        output = io.StringIO()
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_OS": "Windows", "RUNNER_ENVIRONMENT": "github-hosted"}), \
             mock.patch.object(P, "hosted_guard"), mock.patch.object(P, "powershell", return_value="fixed-system-powershell"), \
             mock.patch.object(P, "hidden", return_value={}), mock.patch.object(P.subprocess, "run", return_value=result, side_effect=error) as child:
            if identity_effect is not None:
                with mock.patch.object(P, "identity", side_effect=identity_effect), redirect_stdout(output):
                    with self.assertRaisesRegex(P.ProducerError, "^case_setup_failed$"):
                        P.prepare(self.root, "app-http-" + "c" * 32, action)
            else:
                with redirect_stdout(output):
                    with self.assertRaisesRegex(P.ProducerError, "^case_setup_failed$"):
                        P.prepare(self.root, "app-http-" + "c" * 32, action)
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("application_setup_diagnostic="))
        value = json.loads(lines[0].split("=", 1)[1])
        self.assertEqual(set(value), {"outcome", "action", "scope", "exit_code", "last_stage"} | ({"failure"} if failure is not None else set()))
        if failure is not None:
            self.assertEqual(value["failure"], failure)
        self.assertEqual(value["scope"], "suite")
        self.assertEqual(value["action"], action)
        self.assertNotIn("private-canary", output.getvalue())
        self.assertNotIn(str(self.root), output.getvalue())
        self.assertNotIn("c" * 32, output.getvalue())
        self.assertEqual(child.call_args.kwargs["timeout"], 20)
        self.assertEqual(child.call_args.kwargs["env"]["RUNNER_ENVIRONMENT"], "github-hosted")
        return value

    def test_prepare_accepts_only_complete_exact_success_protocol(self):
        for action in ("Create", "Verify"):
            with self.subTest(action=action):
                result = types.SimpleNamespace(returncode=0, stdout=self.setup_stream(action))
                with mock.patch.object(P, "hosted_guard"), mock.patch.object(P, "powershell", return_value="fixed-system-powershell"), \
                     mock.patch.object(P, "hidden", return_value={}), mock.patch.object(P.subprocess, "run", return_value=result), redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(P.prepare(self.root, "listing", action), self.root / "listing")
                self.assertEqual(output.getvalue(), "")
        missing = self.setup_stream(stages=["input", "parent", "identity", "compile", "create", "verify", "complete"])
        value = self.prepare_result(types.SimpleNamespace(returncode=0, stdout=missing))
        self.assertEqual(value, {"outcome": "protocol_failed", "action": "Create", "scope": "suite", "exit_code": 0, "last_stage": None})

    def test_prepare_timeout_retains_only_validated_finite_prefix(self):
        prefix = self.setup_stream(stages=["input", "parent", "identity", "acl", "compile"], final=None)
        for raw, expected in ((prefix, "compile"), (prefix + b'private-canary', None),
                              (prefix + b'{"schema_version":1,"stage":"create"', None), (None, None)):
            with self.subTest(expected=expected, raw_present=raw is not None):
                error = P.subprocess.TimeoutExpired(["private-canary"], 20, output=raw, stderr=b"private-canary")
                value = self.prepare_result(error=error)
                self.assertEqual(value["outcome"], "timeout")
                self.assertIsNone(value["exit_code"])
                self.assertEqual(value["last_stage"], expected)

    def test_prepare_exit_launch_protocol_and_parent_drift_are_distinct(self):
        failed = self.setup_stream(stages=["input", "parent", "identity", "acl", "compile", "create"], final=False)
        value = self.prepare_result(types.SimpleNamespace(returncode=1, stdout=failed))
        self.assertEqual((value["outcome"], value["exit_code"], value["last_stage"]), ("exit_failed", 1, "create"))
        value = self.prepare_result(error=OSError("private-canary"))
        self.assertEqual((value["outcome"], value["exit_code"], value["last_stage"]), ("launch_failed", None, None))
        value = self.prepare_result(types.SimpleNamespace(returncode=0, stdout=b"private-canary\n"))
        self.assertEqual((value["outcome"], value["last_stage"]), ("protocol_failed", None))
        value = self.prepare_result(types.SimpleNamespace(returncode=0, stdout=self.setup_stream()), identity_effect=[(1, 2), (1, 3)])
        self.assertEqual((value["outcome"], value["last_stage"]), ("parent_changed", "complete"))

    def test_setup_parser_rejects_forged_unknown_oversize_or_partial_data(self):
        valid = self.setup_stream()
        mutations = [valid.replace(b'"input"', b'"private-canary"'), valid.replace(b'"schema_version":1', b'"schema_version":true', 1),
            valid.replace(b'"stage":"input"', b'"stage":"input","extra":"private-canary"'),
            valid.replace(b'"stage":"input"', b'"stage":"input","stage":"input"'),
            valid + b"\n", valid[:-1], b"x" * 4097, valid.replace(b'"input"', b'NaN')]
        for raw in mutations:
            with self.assertRaises(P.ProducerError):
                P.setup_progress(raw, "Create")
        value = self.prepare_result(types.SimpleNamespace(returncode=True, stdout=valid))
        self.assertEqual((value["outcome"], value["exit_code"]), ("protocol_failed", None))

    @staticmethod
    def acl_failure(reason="owner_invalid", category="application_root"):
        return dict(reason=reason, category=category, owner_is_user=False if reason == "owner_invalid" else None,
                    owner_is_token_owner=None, token_owner_is_user=None)

    def test_setup_verification_failure_has_closed_reasons_categories_and_nullable_owner_facts(self):
        reasons = ("verification_failed", "entry_limit", "metadata_read_failed", "reparse", "owner_invalid",
                   "root_unprotected", "acl_invalid", "acl_incomplete", "enumeration_failed")
        categories = ("root", "application_root", "helper_root", "helper_private_root", "helper_descendant",
                      "helper_temp_direct", "helper_temp_deeper", "helper_home_descendant", "helper_profile_descendant",
                      "helper_appdata_descendant", "helper_localappdata_descendant", "bridge_log", "other", "unknown",
                      "application_binary", "source_config", "acquisition_queue", "session_transcript", "output_root",
                      "case_root", "case_logs", "case_downloads", "case_listings", "case_config", "listing_inventory",
                      "working_config", "config_provenance")
        self.assertEqual(P.SETUP_NODE_CATEGORIES, frozenset(categories))
        for action in ("Create", "Verify"):
            stages = ["input", "parent", "identity", "verify"] if action == "Verify" else ["input", "parent", "identity", "acl", "compile", "create", "verify"]
            for reason in reasons:
                for category in categories:
                    pairs = ((None, None), (True, False), (False, True), (False, False)) if reason == "owner_invalid" else ((None, None),)
                    for pair in pairs:
                        failure = self.acl_failure(reason, category)
                        failure.update(owner_is_token_owner=pair[0], token_owner_is_user=pair[1])
                        raw = self.setup_stream(action, stages, False, failure)
                        self.assertLessEqual(max(map(len, raw.splitlines())), 256)
                        self.assertEqual(P.setup_progress(raw, action), ("verify", False, failure))
        for pair in ((None, None), (True, False), (False, True), (False, False)):
            failure = self.acl_failure()
            failure.update(owner_is_token_owner=pair[0], token_owner_is_user=pair[1])
            self.assertEqual(P.setup_failure(failure), failure)

    def test_setup_verification_diagnostic_rejects_private_untyped_or_contradictory_metadata(self):
        original = self.acl_failure()
        mutations = []
        for key, value in (("reason", "private-canary"), ("category", str(self.root)),
                           ("category", "helper_temp_direct/private-canary"),
                           ("category", "helper_profile_descendant_private-canary"),
                           ("category", "case_root/private-canary"), ("category", "working_config_private-canary"),
                           ("category", "config_provenance/private-canary"), ("reason", []),
                           ("category", None), ("owner_is_user", True), ("owner_is_user", 0),
                           ("owner_is_token_owner", 1), ("token_owner_is_user", "false")):
            mutations.append(dict(original, **{key: value}))
        mutations += [dict(original, sid="private-canary"), dict(original, owner_is_token_owner=True),
                      dict(original, owner_is_token_owner=True, token_owner_is_user=True),
                      dict(original, reason="acl_invalid"), {key: value for key, value in original.items() if key != "category"}]
        for failure in mutations:
            raw = self.setup_stream("Verify", ["input", "parent", "identity", "verify"], False, failure)
            with self.assertRaises(P.ProducerError):
                P.setup_progress(raw, "Verify")
        valid = self.setup_stream("Verify", ["input", "parent", "identity", "verify"], False, original)
        invalid = [valid[:-1], valid + valid.splitlines(keepends=True)[-1],
                   valid.replace(b'"reason":"owner_invalid"', b'"reason":"owner_invalid","reason":"owner_invalid"'),
                   valid.replace(b'"owner_is_user":false', b'"owner_is_user":NaN'),
                   valid.replace(b'"category":"application_root"', b'"category":"' + b'x' * 256 + b'"'),
                   valid.replace(b'"ok":false', b'"ok":true'),
                   self.setup_stream("Verify", final=True, failure=original),
                   self.setup_stream("Verify", ["input", "parent", "identity"], False, original),
                   self.setup_stream("Verify", final=False, failure=original)]
        for raw in invalid:
            with self.assertRaises(P.ProducerError):
                P.setup_progress(raw, "Verify")

    def test_prepare_verification_diagnostic_does_not_replace_failure_or_expose_private_values(self):
        failure = self.acl_failure()
        failure.update(owner_is_token_owner=True, token_owner_is_user=False)
        raw = self.setup_stream("Verify", ["input", "parent", "identity", "verify"], False, failure)
        retained = self.root / "private-canary"
        retained.write_bytes(b"private-canary")
        result = types.SimpleNamespace(returncode=1, stdout=raw, stderr=b"private-canary")
        value = self.prepare_result(result, action="Verify", failure=failure)
        self.assertEqual((value["outcome"], value["last_stage"], value["exit_code"]), ("exit_failed", "verify", 1))
        self.assertEqual(retained.read_bytes(), b"private-canary")

    def test_prepare_verification_metadata_requires_failed_terminal_nonzero_and_stable_parent(self):
        failure = self.acl_failure()
        raw = self.setup_stream("Verify", ["input", "parent", "identity", "verify"], False, failure)
        value = self.prepare_result(types.SimpleNamespace(returncode=0, stdout=raw), action="Verify")
        self.assertEqual(value["outcome"], "protocol_failed")
        value = self.prepare_result(types.SimpleNamespace(returncode=1, stdout=raw), action="Verify", identity_effect=[(1, 2), (1, 3)])
        self.assertEqual(value["outcome"], "parent_changed")
        value = self.prepare_result(error=P.subprocess.TimeoutExpired(["private-canary"], 20, output=raw), action="Verify")
        self.assertEqual((value["outcome"], value["last_stage"]), ("timeout", "verify"))
        bad = raw.replace(b'"owner_invalid"', b'"private-canary"')
        value = self.prepare_result(types.SimpleNamespace(returncode=1, stdout=bad), action="Verify")
        self.assertIsNone(value["last_stage"])
        for outcome, code, stage in (("timeout", None, "verify"), ("protocol_failed", 0, "verify"), ("exit_failed", 1, "identity")):
            with self.assertRaises(P.ProducerError), redirect_stdout(io.StringIO()) as output:
                P.setup_diagnostic(outcome, "Verify", "listing", code, stage, failure)
            self.assertEqual(output.getvalue(), "")

    def test_prepare_diagnostic_error_still_raises_original_setup_failure_and_retains_tree(self):
        raw = self.setup_stream("Verify", ["input", "parent", "identity", "verify"], False, self.acl_failure())
        retained = self.root / "private-canary"
        retained.write_bytes(b"private-canary")
        with mock.patch.object(P, "hosted_guard"), mock.patch.object(P, "powershell", return_value="fixed-system-powershell"), \
             mock.patch.object(P, "hidden", return_value={}), mock.patch.object(P.subprocess, "run", return_value=types.SimpleNamespace(returncode=1, stdout=raw)), \
             mock.patch.object(P, "setup_diagnostic", side_effect=RuntimeError("private-canary")), redirect_stdout(io.StringIO()) as output:
            with self.assertRaisesRegex(P.ProducerError, "^case_setup_failed$"):
                P.prepare(self.root, "listing", "Verify")
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(retained.read_bytes(), b"private-canary")

    def test_profile_owner_marker_requires_exact_validated_failed_verify(self):
        for action, reason, category, code in (
                ("Verify", "owner_invalid", "helper_profile_descendant", 1),
                ("Verify", "owner_invalid", "helper_temp_direct", 1),
                ("Verify", "owner_invalid", "application_root", 1),
                ("Verify", "acl_invalid", "helper_profile_descendant", 1),
                ("Verify", "owner_invalid", "helper_profile_descendant", 0),
                ("Create", "owner_invalid", "helper_profile_descendant", 1)):
            failure = self.acl_failure(reason, category)
            stages = ["input", "parent", "identity", "verify"] if action == "Verify" else [
                "input", "parent", "identity", "acl", "compile", "create", "verify"]
            raw = self.setup_stream(action, stages, False, failure)
            with self.subTest(action=action, category=category, code=code), \
                 mock.patch.object(P, "hosted_guard"), mock.patch.object(P, "powershell", return_value="fixed-system-powershell"), \
                 mock.patch.object(P, "hidden", return_value={}), mock.patch.object(P.subprocess, "run", return_value=types.SimpleNamespace(returncode=code, stdout=raw)), \
                 redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(P.ProducerError, "^case_setup_failed$") as caught:
                    P.prepare(self.root, "listing", action)
            self.assertIs(getattr(caught.exception, "helper_profile_owner_failure", None),
                action == "Verify" and reason == "owner_invalid" and category == "helper_profile_descendant" and code == 1)

    def test_profile_layout_has_literal_nodes_and_only_unknown_counts(self):
        paths = ["AppData", "AppData/Local", "AppData/LocalLow", "AppData/Roaming", "Documents",
                 "Documents/WindowsPowerShell", "Documents/WindowsPowerShell/Modules",
                 "AppData/Local/Microsoft", "AppData/Local/Microsoft/Windows", "AppData/Local/Microsoft/Windows/PowerShell",
                 "AppData/Roaming/Microsoft", "AppData/Roaming/Microsoft/Windows", "AppData/Roaming/Microsoft/Windows/PowerShell"]
        entries = {path: (True, 0, 1, index + 1) for index, path in enumerate(paths)}
        expected = ["appdata", "local_appdata", "low_appdata", "roaming_appdata", "documents", "powershell_documents",
                    "powershell_modules", "local_microsoft", "local_windows", "local_powershell", "roaming_microsoft",
                    "roaming_windows", "roaming_powershell"]
        self.assertEqual(P.helper_profile_layout(entries), dict(known_nodes=sorted(expected), unknown_directory_count=0, unknown_file_count=0))
        unknowns = ("private-canary", "AppDataSibling", "Documents/WindowsPowerShellSibling",
                    "AppData/Local/Microsoft/Windows/PowerShellSibling", "AppData/Local/Microsoft/Windows/PowerShеll",
                    "elsewhere/AppData/Local")
        for path in unknowns:
            entries[path] = (True, 0, 1, 99)
        entries["AppData/Local/Microsoft/Windows/PowerShell/private-canary-file"] = (False, 8, 1, 100)
        value = P.helper_profile_layout(entries)
        self.assertEqual(value, dict(known_nodes=sorted(expected), unknown_directory_count=6, unknown_file_count=1))
        self.assertNotIn("canary", json.dumps(value))
        self.assertEqual(P.helper_profile_layout({"APPDATA/LOCAL": (True, 0, 1, 1), "Documents": (False, 2, 1, 2)}),
            dict(known_nodes=["local_appdata"], unknown_directory_count=0, unknown_file_count=1))
        for invalid in (None, {str(i): (True, 0, 1, i) for i in range(33)},
                {"Documents": (True, 0, 1, 1), "DOCUMENTS": (True, 0, 1, 2)},
                {"PowerShell": (True, 0, 1, 1), "Powerſhell": (True, 0, 1, 2)},
                {"Documents": (1, 0, 1, 1)}, {"Documents": (True, 0, True, 1)}, {"Documents": (True, -1, 1, 1)}):
            with self.subTest(invalid_type=type(invalid).__name__), self.assertRaises(P.ProducerError):
                P.helper_profile_layout(invalid)

    def test_profile_diagnostic_uses_two_safe_inventories_and_original_leases(self):
        case = self.root / "profile-observation"
        case.mkdir()
        leases = P.create_private_roots(case)
        profile = case / "helper-env/profile"
        (profile / "AppData/Local").mkdir(parents=True)
        (profile / "private-canary").mkdir()
        (profile / "private-canary-file").write_bytes(b"private-canary-body")
        error = P.ProducerError("case_setup_failed")
        error.helper_profile_owner_failure = True
        with mock.patch.object(P, "inventory", wraps=P.inventory) as inv, redirect_stdout(io.StringIO()) as output:
            P.helper_profile_failure_diagnostic("listing", case, P.identity(case), leases, error)
        inv.assert_has_calls([mock.call(profile), mock.call(profile)])
        self.assertEqual(inv.call_count, 2)
        self.assertLessEqual(len(output.getvalue().encode()), 4096)
        self.assertEqual(json.loads(output.getvalue().split("=", 1)[1]), dict(scope="listing",
            known_nodes=["appdata", "local_appdata", "roaming_appdata"], unknown_directory_count=1, unknown_file_count=1))
        self.assertNotIn("canary", output.getvalue())
        self.assertNotIn(str(case), output.getvalue())
        self.assertTrue((profile / "private-canary-file").exists())

    def test_profile_diagnostic_suppresses_unknown_context_and_inventory_uncertainty(self):
        case = self.root / "profile-uncertainty"
        case.mkdir()
        leases = P.create_private_roots(case)
        original = P.identity(case)
        profile = case / "helper-env/profile"
        error = P.ProducerError("case_setup_failed")
        error.helper_profile_owner_failure = True
        for invalid in (P.ProducerError("case_setup_failed"), ValueError("private-canary"), P.ProducerError("cleanup_failed")):
            with mock.patch.object(P, "inventory") as inv, redirect_stdout(io.StringIO()) as output:
                P.helper_profile_failure_diagnostic("listing", case, original, leases, invalid)
            inv.assert_not_called()
            self.assertEqual(output.getvalue(), "")
        for bad in ("case", "helper_root", "profile"):
            changed = copy.deepcopy(leases)
            case_id = original
            if bad == "case":
                case_id = (-1, -1)
            elif bad == "profile":
                changed["helper"]["profile"] = (-1, -1)
            else:
                changed[bad] = (-1, -1)
            with mock.patch.object(P, "inventory") as inv, redirect_stdout(io.StringIO()) as output:
                P.helper_profile_failure_diagnostic("listing", case, case_id, changed, error)
            inv.assert_not_called()
            self.assertEqual(output.getvalue(), "")
        for effects in ([OSError("private-canary")], [{}, {"private-canary": (True, 0, 1, 1)}],
                        [{str(i): (True, 0, 1, i) for i in range(33)}]):
            with mock.patch.object(P, "inventory", side_effect=effects), redirect_stdout(io.StringIO()) as output:
                P.helper_profile_failure_diagnostic("listing", case, original, leases, error)
            self.assertEqual(output.getvalue(), "")
        identity = P.identity
        for replaced_after in (1, 2):
            count = 0
            def inv(path):
                nonlocal count
                count += 1
                return {}
            def identity_after(path):
                return (-1, -1) if Path(path) == profile and count >= replaced_after else identity(path)
            with mock.patch.object(P, "inventory", side_effect=inv), mock.patch.object(P, "identity", side_effect=identity_after), \
                 redirect_stdout(io.StringIO()) as output:
                P.helper_profile_failure_diagnostic("listing", case, original, leases, error)
            self.assertEqual(output.getvalue(), "")
        with mock.patch.object(P, "plain", side_effect=P.ProducerError("private-canary")), redirect_stdout(io.StringIO()) as output:
            P.helper_profile_failure_diagnostic("listing", case, original, leases, error)
        self.assertEqual(output.getvalue(), "")

    def test_profile_diagnostic_failure_never_replaces_failed_probe_or_allows_removal(self):
        for printing_fails in (False, True):
            error = P.ProducerError("case_setup_failed")
            error.helper_profile_owner_failure = True
            events = []
            def prepare(parent, name, action="Create"):
                value = fake_prepare(parent, name, action)
                if name == "listing" and action == "Verify":
                    raise error
                return value
            def baseline(case):
                (case / "helper-env/profile/AppData/Local/Microsoft/Windows/PowerShell").mkdir(parents=True)
                (case / "helper-env/profile/private-canary").mkdir()
            original_print = print
            def printing(*args, **kwargs):
                if printing_fails and str(args[0]).startswith("application_helper_profile_diagnostic="):
                    raise OSError("private-canary")
                original_print(*args, **kwargs)
            with self.subTest(printing_fails=printing_fails), self.probe_patches(), \
                 mock.patch.object(P, "prepare", side_effect=prepare), mock.patch.object(P, "remove_owned") as remove, \
                 mock.patch("builtins.print", side_effect=printing), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(P.bridge_probe(self.probe_bridge_factory(before_ready=baseline, events=events)), 1)
            self.assertEqual(events, ["ready", "close_ready", "close"])
            lines = output.getvalue().splitlines()
            self.assertEqual(lines[-1], "application_bridge_probe_failed")
            self.assertEqual(json.loads(next(line.split("=", 1)[1] for line in lines if line.startswith("application_bridge_probe_diagnostic="))),
                dict(stage="case_acl", failure_code="case_setup_failed"))
            observations = [line for line in lines if line.startswith("application_helper_profile_diagnostic=")]
            self.assertEqual(len(observations), 0 if printing_fails else 1)
            if observations:
                self.assertEqual(json.loads(observations[0].split("=", 1)[1]), dict(scope="listing",
                    known_nodes=["appdata", "local_appdata", "local_microsoft", "local_powershell", "local_windows", "roaming_appdata"],
                    unknown_directory_count=1, unknown_file_count=0))
            self.assertNotIn("canary", output.getvalue())
            self.assertNotIn(str(self.root), output.getvalue())
            remove.assert_not_called()
        self.assertEqual(len(list(self.root.glob("app-http-*"))), 2)

    def test_profile_observation_does_not_promote_application_or_cleanup(self):
        error = P.ProducerError("case_setup_failed")
        error.helper_profile_owner_failure = True
        def prepare(parent, name, action="Create"):
            result = fake_prepare(parent, name, action)
            if action == "Verify":
                raise error
            return result
        def baseline(case):
            (case / "helper-env/profile/Documents/WindowsPowerShell").mkdir(parents=True)
        flow = Flow("listing", before_app=baseline)
        suite = self.root / "application-profile-failure"
        suite.mkdir()
        with mock.patch.object(P, "prepare", side_effect=prepare), mock.patch.object(P.F, "serve_http", side_effect=flow.serve), \
             mock.patch.object(P.time, "sleep"), mock.patch.object(P, "remove_owned") as remove, redirect_stdout(io.StringIO()) as output:
            record = P.run_case("listing", suite, self.app, self.digest, RUNTIME, session_factory=flow.factory)
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["failure_code"], "cleanup_failed")
        self.assertFalse(record["checks"]["temp_cleanup"])
        self.assertFalse(record["checks"]["process_cleanup"])
        self.assertTrue(record["checks"]["inventory_exact"])
        self.assertIn("application_helper_profile_diagnostic=", output.getvalue())
        self.assertTrue((suite / "listing").exists())
        remove.assert_not_called()

    def probe_patches(self):
        # App, fixture and session entry points must remain unreachable.
        stack = __import__("contextlib").ExitStack()
        stack.enter_context(mock.patch.object(P, "hosted_guard"))
        stack.enter_context(mock.patch.object(P, "run", side_effect=AssertionError("application forbidden")))
        stack.enter_context(mock.patch.object(P, "run_case", side_effect=AssertionError("case forbidden")))
        stack.enter_context(mock.patch.object(P.F, "serve_http", side_effect=AssertionError("listener forbidden")))
        return stack

    def test_setup_probe_cli_only_verifies_and_removes_exact_empty_suite(self):
        with self.probe_patches(), mock.patch.object(P, "prepare", side_effect=fake_prepare) as prep, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(P.main(["--setup-probe"]), 0)
        self.assertEqual(output.getvalue(), "application_setup_probe_passed\n")
        self.assertEqual(prep.call_count, 2)
        self.assertEqual(prep.call_args_list[0].args[:2], prep.call_args_list[1].args[:2])
        self.assertEqual(prep.call_args_list[1].args[2], "Verify")
        self.assertEqual(list(self.root.glob("app-http-*")), [])
        self.assertEqual(list(self.root.glob("*.json")), [])

    def probe_bridge_factory(self, *, ready=None, close_ok=True, before_ready=None, after_close=None, events=None):
        events = [] if events is None else events
        def factory(case):
            (case / "bridge-stdout.private").write_bytes(b"private-canary")
            (case / "bridge-stderr.private").write_bytes(b"private-canary")
            class Session:
                def command(self, action):
                    events.append(action)
                    if action == "ready":
                        if before_ready:
                            before_ready(case)
                        if isinstance(ready, BaseException):
                            raise ready
                        return ready if ready is not None else {"schema_version": 1, "action": "ready", "ok": True, "state": "ready"}
                    if action != "close_ready":
                        raise AssertionError("app action forbidden")
                    return {"schema_version": 1, "action": "close_ready", "ok": True, "state": "closed"}
                def close(self):
                    events.append("close")
                    if after_close:
                        after_close(case)
                    return close_ok
            return Session()
        return factory

    def test_bridge_probe_cli_has_no_application_or_receipt_and_removes_owned_tree(self):
        events = []
        def baseline(case):
            (case / "helper-env/temp/private-canary-dir/child").mkdir(parents=True)
        def remove_descendant(case):
            (case / "helper-env/temp/private-canary-dir/child").rmdir()
        with self.probe_patches(), mock.patch.object(P, "prepare", side_effect=fake_prepare) as prep, \
             mock.patch.object(P, "Bridge", side_effect=self.probe_bridge_factory(before_ready=baseline, after_close=remove_descendant, events=events)), \
             redirect_stdout(io.StringIO()) as output:
            self.assertEqual(P.main(["--bridge-probe"]), 0)
        self.assertEqual(output.getvalue(), "application_bridge_probe_passed\n")
        self.assertEqual(events, ["ready", "close_ready", "close"])
        self.assertEqual([c.args[2] if len(c.args) == 3 else "Create" for c in prep.call_args_list], ["Create", "Create", "Verify", "Verify"])
        self.assertEqual(list(self.root.glob("app-http-*")), [])
        self.assertEqual(list(self.root.glob("*.json")), [])

    def test_bridge_probe_cli_rejects_mixed_preflight_and_application_flags(self):
        for extra in (["--setup-probe"], *[[flag, "synthetic"] for flag in
                ("--application", "--application-sha256", "--build-commit", "--report")]):
            with self.subTest(flags=extra), mock.patch.object(P, "bridge_probe") as probe, \
                 redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                P.main(["--bridge-probe", *extra])
            self.assertEqual(error.exception.code, 2)
            probe.assert_not_called()

    def test_bridge_probe_ready_cleanup_and_directory_uncertainty_retain_root(self):
        def replace(case):
            (case / "home").rename(case / "old-home")
            (case / "home").mkdir()
        variants = [dict(ready={}), dict(ready=P.ProducerError("session_failed")), dict(close_ok=False),
                    dict(before_ready=lambda c: (c / "temp/private-canary").write_bytes(b"x")),
                    dict(before_ready=replace), dict(after_close=replace),
                    dict(after_close=lambda c: (c / "profile/private-canary").mkdir()),
                    dict(after_close=lambda c: (c / "helper-env/temp/private-canary").write_bytes(b"x")),
                    dict(after_close=lambda c: (c / "helper-env/home").rmdir())]
        phases = ("ready", "ready", "helper_cleanup", "prestart", "prestart", "private_inventory", "private_inventory",
                  "private_inventory", "private_inventory")
        for index, options in enumerate(variants):
            events = []
            with self.subTest(variant=index), self.probe_patches(), mock.patch.object(P, "prepare", side_effect=fake_prepare), \
                 mock.patch.object(P, "remove_owned") as remove, redirect_stdout(io.StringIO()) as output:
                self.assertEqual(P.bridge_probe(self.probe_bridge_factory(events=events, **options)), 1)
            self.assertNotIn("start", events)
            self.assertEqual(events.count("close"), 1)
            self.assertTrue(output.getvalue().endswith("application_bridge_probe_failed\n"))
            self.assertNotIn("canary", output.getvalue())
            self.assertNotIn(str(self.root), output.getvalue())
            line = next(line for line in output.getvalue().splitlines() if line.startswith("application_bridge_probe_diagnostic="))
            value = json.loads(line.split("=", 1)[1])
            self.assertEqual(set(value), {"stage", "failure_code"})
            self.assertEqual(value["stage"], phases[index])
            self.assertIn(value["failure_code"], P.E.FAILURE_CODES)
            remove.assert_not_called()
        self.assertEqual(len(list(self.root.glob("app-http-*"))), len(variants))

    def test_bridge_probe_setup_acl_and_removal_failure_never_promote(self):
        for phase in ("Create", "Verify", "remove"):
            events = []
            def prepare(parent, name, action="Create"):
                result = fake_prepare(parent, name, action)
                if action == phase:
                    raise P.ProducerError("case_setup_failed")
                return result
            with self.subTest(phase=phase), self.probe_patches(), mock.patch.object(P, "prepare", side_effect=prepare), \
                 mock.patch.object(P, "remove_owned", side_effect=P.ProducerError("cleanup_failed")) as remove, \
                 redirect_stdout(io.StringIO()) as output:
                self.assertEqual(P.bridge_probe(self.probe_bridge_factory(events=events)), 1)
            self.assertNotIn("start", events)
            self.assertNotIn("passed", output.getvalue())
            if phase != "remove":
                remove.assert_not_called()
        self.assertEqual(len(list(self.root.glob("app-http-*"))), 3)

    def test_bridge_probe_source_unknown_and_reparse_failure_diagnostics_are_finite(self):
        for variant in ("source", "unknown", "reparse"):
            original_plain = P.plain
            def plain(path, directory=False, **kwargs):
                if variant == "reparse" and Path(path).name == "profile" and (Path(path).parent / "bridge-stdout.private").exists():
                    raise P.ProducerError("preservation_failed")
                return original_plain(path, directory, **kwargs)
            factory = self.probe_bridge_factory(ready=ValueError("private-canary") if variant == "unknown" else None)
            source_checks = [None, P.ProducerError("binding_failed")] if variant == "source" else [None, None, None]
            with self.subTest(variant=variant), self.probe_patches(), mock.patch.object(P, "prepare", side_effect=fake_prepare), \
                 mock.patch.object(P, "plain", side_effect=plain), mock.patch.object(P, "loaded_sources_preserved", side_effect=source_checks), \
                 mock.patch.object(P, "remove_owned") as remove, redirect_stdout(io.StringIO()) as output:
                self.assertEqual(P.bridge_probe(factory), 1)
            value = json.loads(next(line.split("=", 1)[1] for line in output.getvalue().splitlines()
                if line.startswith("application_bridge_probe_diagnostic=")))
            stage, code = {"source": ("source", "binding_failed"), "unknown": ("ready", "unexpected_failure"),
                           "reparse": ("prestart", "preservation_failed")}[variant]
            self.assertEqual(value, dict(stage=stage, failure_code=code))
            self.assertNotIn("canary", output.getvalue())
            self.assertNotIn(str(self.root), output.getvalue())
            remove.assert_not_called()
        for stage, code in (("private-canary", "cleanup_failed"), ("source", "private-canary")):
            with redirect_stdout(io.StringIO()) as output, self.assertRaises(P.ProducerError):
                P.bridge_probe_diagnostic(stage, code)
            self.assertEqual(output.getvalue(), "")

    def test_setup_probe_rejects_all_application_receipt_arguments(self):
        for flag in ("--application", "--application-sha256", "--build-commit", "--report"):
            with mock.patch.object(P, "setup_probe") as run_probe, redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                P.main(["--setup-probe", flag, "synthetic"])
            self.assertEqual(error.exception.code, 2)
            run_probe.assert_not_called()

    def test_setup_probe_timeout_or_verification_failure_never_deletes(self):
        for failing_action in ("Create", "Verify"):
            with self.subTest(action=failing_action):
                def prepare(parent, name, action="Create"):
                    if action == "Create":
                        (parent / name).mkdir()
                    if action == failing_action:
                        raise P.ProducerError("case_setup_failed")
                    return parent / name
                with self.probe_patches(), mock.patch.object(P, "prepare", side_effect=prepare), \
                     mock.patch.object(P, "remove_owned") as remove, redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(P.setup_probe(), 1)
                self.assertEqual(output.getvalue(), "application_setup_probe_failed\n")
                remove.assert_not_called()
        self.assertEqual(len(list(self.root.glob("app-http-*"))), 2)

    def test_setup_probe_cleanup_failure_and_unexpected_content_fail_closed(self):
        with self.probe_patches(), mock.patch.object(P, "prepare", side_effect=fake_prepare), \
             mock.patch.object(P, "remove_owned", side_effect=P.ProducerError("cleanup_failed")), redirect_stdout(io.StringIO()):
            self.assertEqual(P.setup_probe(), 1)
        self.assertEqual(len(list(self.root.glob("app-http-*"))), 1)
        def extra(parent, name, action="Create"):
            root = fake_prepare(parent, name, action)
            if action == "Verify":
                (root / "unexpected").write_bytes(b"private-canary")
            return root
        with self.probe_patches(), mock.patch.object(P, "prepare", side_effect=extra), \
             mock.patch.object(P, "remove_owned") as remove, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(P.setup_probe(), 1)
        self.assertNotIn("private-canary", output.getvalue())
        remove.assert_not_called()

    def synthetic_setup_environment(self, **extras):
        return {"SYSTEMROOT": str(self.root), "USERPROFILE": str(self.profile),
            "APPDATA": str(self.profile / "AppData/Roaming"), "LOCALAPPDATA": str(self.profile / "AppData/Local"),
            "TEMP": str(self.root), "TMP": str(self.root), "GITHUB_ACTIONS": "true",
            "RUNNER_OS": "Windows", "RUNNER_ENVIRONMENT": "github-hosted", **extras}

    def test_only_trusted_setup_inherits_a_snapshot_of_the_hosted_environment(self):
        extras = {"PATH": "private-canary", "AWS_SECRET_ACCESS_KEY": "private-canary",
                  "RCLONE_CONFIG": "private-canary", "HTTP_PROXY": "private-canary",
                  "HTTPS_PROXY": "private-canary", "GITHUB_TOKEN": "private-canary",
                  "APPLICATION_LAB_SENTINEL": "private-canary"}
        before = sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*"))
        with mock.patch.dict(os.environ, self.synthetic_setup_environment(**extras), clear=True):
            value = P.setup_environment()
            self.assertEqual(value, dict(os.environ))
            os.environ["APPLICATION_LAB_SENTINEL"] = "changed-after-snapshot"
            self.assertEqual(value["APPLICATION_LAB_SENTINEL"], "private-canary")
            self.assertNotIn("private-canary", repr(P.environment(self.root)))
            self.assertNotIn("changed-after-snapshot", repr(P.environment(self.root)))
        self.assertEqual(before, sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*")))

    def test_bridge_and_app_maps_stay_scrubbed_and_private_values_never_enter_evidence(self):
        extras = {"APPLICATION_LAB_SENTINEL": "private-canary", "AWS_SECRET_ACCESS_KEY": "private-canary",
                  "RCLONE_CONFIG": "private-canary", "HTTPS_PROXY": "private-canary", "PATH": "private-canary",
                  "PSModuleAnalysisCachePath": "private-canary"}
        with mock.patch.dict(os.environ, self.synthetic_setup_environment(**extras), clear=True):
            with mock.patch.object(P, "powershell", return_value="fixed-system-powershell"), \
                 mock.patch.object(P, "hidden", return_value={}), \
                 mock.patch.object(P.subprocess, "Popen", return_value=mock.Mock()) as child, \
                 mock.patch.object(P.threading, "Thread"):
                P.Bridge(self.root)
            application_env = P.environment(self.root)
            self.assertEqual(set(application_env), {"SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "COMSPEC", "PATH",
                "TEMP", "TMP", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA"})
            helper_env = P.environment(self.root / "helper-env")
            self.assertEqual(child.call_args.kwargs["env"], dict(helper_env,
                GITHUB_ACTIONS="true", RUNNER_OS="Windows", RUNNER_ENVIRONMENT="github-hosted",
                PSModuleAnalysisCachePath="nul"))
            self.assertEqual(os.environ["PSModuleAnalysisCachePath"], "private-canary")
            for key, folder in (("TEMP", "temp"), ("TMP", "temp"), ("HOME", "home"), ("USERPROFILE", "profile"),
                                ("APPDATA", "appdata"), ("LOCALAPPDATA", "localappdata")):
                self.assertEqual(application_env[key], str(self.root / folder))
                self.assertEqual(helper_env[key], str(self.root / "helper-env" / folder))
                self.assertNotEqual(application_env[key], helper_env[key])
            self.assertNotIn("private-canary", repr(child.call_args))
            result, _, _ = self.execute_case("listing")
            self.assertNotIn("private-canary", json.dumps(result))
            prefix = self.setup_stream(stages=["input", "parent", "identity", "acl", "compile"], final=None)
            diagnostic = self.prepare_result(error=P.subprocess.TimeoutExpired("private-canary", 20, output=prefix))
            self.assertNotIn("private-canary", json.dumps(diagnostic))

    def test_setup_environment_rejects_missing_relative_unc_nonexistent_and_wrong_profile_dirs(self):
        mutations = [("USERPROFILE", ""), ("APPDATA", "relative"), ("TMP", r"\\synthetic.invalid\share"),
            ("TEMP", str(self.root / "absent")), ("LOCALAPPDATA", str(self.root)),
            ("APPDATA", str(self.profile / "AppData/Local")), ("SYSTEMROOT", str(self.app))]
        for name, value in mutations:
            with self.subTest(name=name, value_kind=mutations.index((name, value))), mock.patch.dict(os.environ, {name: value}):
                with self.assertRaises(P.ProducerError):
                    P.setup_environment()
        saved = os.environ.pop("APPDATA")
        try:
            with self.assertRaises(P.ProducerError):
                P.setup_environment()
        finally:
            os.environ["APPDATA"] = saved

    def test_setup_environment_reparse_guard_failure_blocks_launch_with_static_diagnostic(self):
        actual_plain = P.plain
        def linked(path, directory=False, **kwargs):
            if Path(path) == self.profile:
                raise P.ProducerError("preservation_failed")
            return actual_plain(path, directory, **kwargs)
        with mock.patch.object(P, "hosted_guard"), mock.patch.object(P, "plain", side_effect=linked), \
             mock.patch.object(P.subprocess, "run") as child, redirect_stdout(io.StringIO()) as output:
            with self.assertRaisesRegex(P.ProducerError, "^case_setup_failed$"):
                P.prepare(self.root, "listing")
        child.assert_not_called()
        self.assertEqual(output.getvalue(), 'application_setup_diagnostic={"action":"Create","exit_code":null,"last_stage":null,"outcome":"environment_invalid","scope":"listing"}\n')

    def test_setup_mixed_separator_unc_is_rejected_before_filesystem_lookup(self):
        for value in (r"\/synthetic.invalid/share/path", r"/\synthetic.invalid/share/path", r"\\?\C:\synthetic"):
            with self.subTest(grammar=value[:4]), mock.patch.dict(os.environ, {"TEMP": value}), \
                 mock.patch.object(P, "plain", wraps=P.plain) as inspect:
                # Pure Windows grammar is checked even in the Linux test job.
                self.assertTrue(P.PureWindowsPath(value).drive.startswith("\\\\"))
                with self.assertRaises(P.ProducerError):
                    P.setup_environment()
                self.assertFalse(any(str(call.args[0]) == str(Path(value)) for call in inspect.call_args_list))

    def test_setup_child_gets_job_snapshot_with_existing_timeout_and_fixed_command(self):
        result = types.SimpleNamespace(returncode=0, stdout=self.setup_stream())
        with mock.patch.dict(os.environ, self.synthetic_setup_environment(APPLICATION_LAB_SENTINEL="private-canary"), clear=True), \
             mock.patch.object(P, "hosted_guard"), mock.patch.object(P, "powershell", return_value="fixed-system-powershell"), \
             mock.patch.object(P, "hidden", return_value={}), mock.patch.object(P.subprocess, "run", return_value=result) as child:
            with redirect_stdout(io.StringIO()) as output:
                P.prepare(self.root, "listing")
            self.assertEqual(child.call_args.kwargs["env"], dict(os.environ))
            self.assertEqual(child.call_args.kwargs["env"]["APPLICATION_LAB_SENTINEL"], "private-canary")
            self.assertEqual(output.getvalue(), "")
        self.assertEqual(child.call_args.kwargs["timeout"], 20)
        self.assertEqual(child.call_args.kwargs["stderr"], P.subprocess.DEVNULL)
        self.assertEqual(child.call_args.args[0][1:5], ["-NoProfile", "-NonInteractive", "-File", str(P.HERE / "prepare_case.ps1")])


if __name__ == "__main__":
    unittest.main()
