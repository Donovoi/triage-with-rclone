"""Definition-only imports and wholly fake owners; never starts native work."""
import builtins
from contextlib import redirect_stdout
import ctypes
import io
import json
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
OWNER = ROOT / "scripts/application-lab/owned_helper_process.py"
HTTP = ROOT / "scripts/application-lab/run_windows_http.py"


def owner_module():
    module = types.ModuleType("fake_owned_helper")
    module.__file__ = str(OWNER)
    exec(compile(OWNER.read_bytes(), str(OWNER), "exec"), module.__dict__)
    # Isolation is entirely fake, never deletion/reset of the production slot.
    module.sys = types.SimpleNamespace()
    token = object()
    envelope = dict(state="ready", api=1, module=module, token=token, preserved=lambda: None)
    module._registration, module._registration_token, module._module_identity = envelope, token, module
    setattr(module.sys, module.SLOT, envelope)
    return module


class Native:
    def __init__(self, body=b"ok", active=0):
        self.calls, self.next, self.body, self.active = [], 10, body, active
        self.exited = True

    def handle(self, kind):
        self.next += 1
        self.calls.append((kind, self.next))
        return self.next

    def job(self):
        return self.handle("job")

    def null(self, readable):
        return self.handle("null")

    def pipe(self, a, b, parent):
        a.value, b.value = self.handle("pipe"), self.handle("pipe")

    def create(self, owner, *args):
        self.calls.append(("create",))
        owner.creation_attempted = owner.creation_resolved = owner.created = True
        owner.process.value, owner.primary_thread.value = self.handle("process"), self.handle("thread")

    def identity(self, process, job, expected):
        self.calls.append(("identity", process, job))
        return 42

    def resume(self, handle):
        self.calls.append(("resume", handle))

    def close(self, handle):
        self.calls.append(("close", handle))

    def wait(self, handle, seconds):
        self.calls.append(("wait", seconds))
        return 0 if self.exited else None

    def kill(self, handle):
        self.calls.append(("kill", handle))
        self.exited = True

    def accounting(self, handle):
        self.calls.append(("accounting", handle))
        return self.active, 1 + self.active

    def read(self, handle, size):
        result, self.body = self.body[:size], self.body[size:]
        return result

    def write(self, handle, data):
        return len(data)


class InlineThread:
    def __init__(self, *, target, daemon):
        self.target, self.joins = target, []

    def start(self):
        self.target()

    def join(self, seconds):
        self.joins.append(seconds)

    def is_alive(self):
        return False


class OwnershipTests(unittest.TestCase):
    def make(self, **kwargs):
        module, native = owner_module(), Native(**kwargs)
        module._native_factory = lambda: native
        return module, native

    def spawn(self, module):
        return module.spawn(["fixed-powershell", "-NoProfile"], env={"FIXED": "value"})

    def finish(self, process):
        process.wait(0)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()
        return process.finalize()

    def test_success_silent_close_before_authoritative_job_accounting_and_release(self):
        module, native = self.make()
        with redirect_stdout(io.StringIO()) as output:
            process = self.spawn(module)
            self.assertTrue(self.finish(process))
            self.assertTrue(process.finalize())
        self.assertEqual(output.getvalue(), "")
        names = [row[0] for row in native.calls]
        self.assertLess(names.index("identity"), names.index("resume"))
        self.assertLess(native.calls.index(("close", process.process.value)), names.index("accounting"))
        self.assertLess(names.index("accounting"), native.calls.index(("close", process.job.value)))
        self.assertEqual(len([x for x in native.calls if x[0] == "close"]), len({x[1] for x in native.calls if x[0] == "close"}))
        self.assertIsNone(module._active)
        self.assertTrue(self.finish(self.spawn(module)))

    def test_overlap_immediate_and_original_reservation_retained(self):
        module, native = self.make()
        original = self.spawn(module)
        calls = list(native.calls)
        with self.assertRaises(module.OwnershipError):
            self.spawn(module)
        self.assertIs(module._active, original)
        self.assertEqual(native.calls, calls)
        self.assertTrue(self.finish(original))

    def test_ambiguous_constructor_is_retained_before_caller_assignment(self):
        module, native = self.make()
        first = KeyboardInterrupt("private-canary")
        def create(owner, *args):
            owner.creation_attempted = True
            owner.pi = types.SimpleNamespace(process=999, thread=998)
            raise first
        native.create = create
        with redirect_stdout(io.StringIO()), self.assertRaises(KeyboardInterrupt) as caught:
            self.spawn(module)
        self.assertIs(caught.exception, first)
        retained = module._active
        self.assertEqual(retained.pi.process, 999)
        self.assertTrue(retained.uncertain)
        self.assertNotIn(("close", 999), native.calls)
        self.assertFalse(any(x[0] in {"kill", "wait", "accounting"} for x in native.calls))
        with self.assertRaises(module.OwnershipError):
            self.spawn(module)
        self.assertIs(module._active, retained)

    def test_creation_failure_preserves_primary_across_secondary_cleanup(self):
        module, native = self.make()
        first = SystemExit("private-canary")
        def identity(*args):
            raise first
        native.identity = identity
        native.kill = mock.Mock(side_effect=KeyboardInterrupt())
        native.close = mock.Mock(side_effect=KeyboardInterrupt())
        # Reach identity first; child closes succeed, then cleanup closes fail.
        count = [0]
        def close(handle):
            count[0] += 1
            if count[0] > 3:
                raise KeyboardInterrupt()
        native.close = close
        with redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as caught:
            self.spawn(module)
        self.assertIs(caught.exception, first)
        self.assertTrue(module._active.uncertain)

    def test_active_descendant_unknown_accounting_and_failed_close_never_release(self):
        for mode in ("active", "unknown", "close"):
            with self.subTest(mode=mode):
                module, native = self.make(active=1 if mode == "active" else 0)
                process = self.spawn(module)
                if mode == "unknown":
                    native.accounting = lambda _: (False, 1)
                if mode == "close":
                    old_close = native.close
                    def close(handle):
                        if handle == process.process.value:
                            raise OSError("private-canary")
                        old_close(handle)
                    native.close = close
                with redirect_stdout(io.StringIO()):
                    self.assertFalse(self.finish(process))
                self.assertIs(module._active, process)
                with self.assertRaises(module.OwnershipError):
                    self.spawn(module)

    def test_borrow_blocks_close_and_retains_failure_even_after_return(self):
        module, native = self.make()
        process = self.spawn(module)
        handle = process.stdout.handle
        with handle.borrow():
            process.stdout.close()
            self.assertNotIn(("close", handle.value), native.calls)
            self.assertTrue(process.uncertain)
        process.stdout.close()
        self.assertEqual(native.calls.count(("close", handle.value)), 1)
        with redirect_stdout(io.StringIO()):
            self.assertFalse(self.finish(process))

    def test_termination_is_nonwaiting_once_only_and_borrow_protected(self):
        module, native = self.make()
        process = self.spawn(module)
        native.exited = False
        calls = []
        def kill(handle):
            calls.append(handle)
            self.assertFalse(process.process.close())
            with self.assertRaises(module.OwnershipError):
                process.kill()
        native.kill = kill
        process.kill()
        process.kill()
        self.assertEqual(calls, [process.process.value])
        self.assertTrue(process.uncertain)
        process.returncode = 0
        process.kill()
        self.assertEqual(len(calls), 1)

    def test_setup_exact_capture_limit_and_original_exit(self):
        for length in (0, 4096, 4097):
            module, native = self.make(body=b"x" * length)
            native.wait = lambda *_: 7
            with self.subTest(length=length), mock.patch.object(module.threading, "Thread", InlineThread), redirect_stdout(io.StringIO()):
                if length > 4096:
                    with self.assertRaises(module.OwnershipError):
                        module.run_setup(["fixed"], env={"FIXED": "value"})
                else:
                    result = module.run_setup(["fixed"], env={"FIXED": "value"})
                    self.assertEqual((result.returncode, result.stdout), (7, b"x" * length))
                    self.assertIsNone(module._active)

    def test_setup_timeout_uses_one_aggregate_five_second_failure_drain(self):
        module, native = self.make()
        clock = types.SimpleNamespace(value=0.0)
        module.time = types.SimpleNamespace(monotonic=lambda: clock.value)
        joins = []
        class Held(InlineThread):
            def start(self):
                pass
            def join(self, seconds):
                joins.append(seconds)
                clock.value += seconds
            def is_alive(self):
                return True
        def wait(handle, seconds):
            native.calls.append(("wait", seconds))
            clock.value += seconds
            return None
        native.wait = wait
        with mock.patch.object(module.threading, "Thread", Held), redirect_stdout(io.StringIO()), self.assertRaises(subprocess.TimeoutExpired) as caught:
            module.run_setup(["fixed"], env={"FIXED": "value"})
        self.assertEqual(caught.exception.timeout, 20)
        self.assertEqual(clock.value, 25)
        self.assertEqual(joins, [20, 0])
        self.assertEqual(len([x for x in native.calls if x[0] == "kill"]), 1)
        self.assertTrue(module._active.uncertain)

    def test_setup_interrupted_unclaimed_start_revokes_late_target(self):
        module, native = self.make()
        first, created = KeyboardInterrupt("private-canary"), []
        class Interrupted(InlineThread):
            def __init__(self, **kwargs):
                super().__init__(**kwargs)
                created.append(self)
            def start(self):
                raise first
        with mock.patch.object(module.threading, "Thread", Interrupted), redirect_stdout(io.StringIO()), self.assertRaises(KeyboardInterrupt) as caught:
            module.run_setup(["fixed"], env={"FIXED": "value"})
        self.assertIs(caught.exception, first)
        calls = list(native.calls)
        created[0].target()
        self.assertEqual(native.calls, calls)
        self.assertTrue(module._active.uncertain)

    def test_setup_interrupted_claimed_start_stays_uncertain_after_joined_close(self):
        module, native = self.make()
        first = KeyboardInterrupt("private-canary")
        class Interrupted(InlineThread):
            def start(self):
                self.target()
                raise first
        with mock.patch.object(module.threading, "Thread", Interrupted), redirect_stdout(io.StringIO()), self.assertRaises(KeyboardInterrupt) as caught:
            module.run_setup(["fixed"], env={"FIXED": "value"})
        self.assertIs(caught.exception, first)
        self.assertTrue(module._active.uncertain)
        self.assertFalse(module._active.final_result)

    def test_partial_allocation_identity_resume_and_close_failures_keep_first_error(self):
        for stage in ("job", "pipe", "create", "identity", "resume", "close"):
            with self.subTest(stage=stage):
                module, native = self.make()
                first = KeyboardInterrupt("private-canary")
                original = getattr(native, stage)
                def fail(*args):
                    if stage == "create":
                        owner = args[0]
                        owner.creation_attempted = owner.creation_resolved = True
                    elif stage in {"pipe", "close"}:
                        original(*args)
                    raise first
                setattr(native, stage, fail)
                with redirect_stdout(io.StringIO()), self.assertRaises(KeyboardInterrupt) as caught:
                    self.spawn(module)
                self.assertIs(caught.exception, first)
                self.assertLessEqual(len([row for row in native.calls if row[0] == "kill"]), 1)
                self.assertTrue(all(row[1] <= 5 for row in native.calls if row[0] == "wait"))

    def test_native_creation_fake_proves_only_explicit_child_handles_and_job_before_resume(self):
        module = owner_module()
        calls = []
        class Kernel:
            def __getattr__(self, name):
                def function(*args):
                    calls.append((name, args))
                    if name == "InitializeProcThreadAttributeList":
                        ctypes.cast(args[3], ctypes.POINTER(ctypes.c_size_t))[0] = 128
                        return bool(args[0])
                    if name == "CreateProcessW":
                        pi = ctypes.cast(args[-1], ctypes.POINTER(abi.PI)).contents
                        pi.process, pi.thread = 71, 72
                    return 1
                return function
        with mock.patch.object(module.C, "WinDLL", return_value=Kernel(), create=True), mock.patch.object(module.os, "name", "nt"):
            abi = module._Win32()
        owner = types.SimpleNamespace(job=types.SimpleNamespace(value=50),
            child=[types.SimpleNamespace(value=n) for n in (61, 62, 63)],
            process=types.SimpleNamespace(value=None), primary_thread=types.SimpleNamespace(value=None),
            creation_attempted=False, creation_resolved=False, created=False)
        abi.create(owner, ["fixed path", "arg with space"], {"FIXED": "value"}, None, 0x08000000, None)
        attributes = [args for name, args in calls if name == "UpdateProcThreadAttribute"]
        self.assertEqual([args[2] for args in attributes], [0x20002, 0x2000D])
        self.assertEqual(list(attributes[0][3]), [61, 62, 63])
        self.assertEqual(list(attributes[1][3]), [50])
        create = next(args for name, args in calls if name == "CreateProcessW")
        self.assertEqual(create[4:6], (1, 0x08000000 | 0x80000 | 0x400 | 4))
        self.assertEqual(create[0], "fixed path")
        self.assertEqual((owner.process.value, owner.primary_thread.value), (71, 72))
        self.assertTrue(owner.creation_resolved and owner.created)
        self.assertEqual(calls[-1][0], "DeleteProcThreadAttributeList")
        self.assertFalse(any(name in {"ResumeThread", "AssignProcessToJobObject"} for name, _ in calls))

    def test_native_wait_unknown_status_is_not_exit_and_signaled_259_is_exit(self):
        module = owner_module()
        abi = object.__new__(module._Win32)
        def exit_code(handle, pointer):
            ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32))[0] = 259
            return 1
        abi.k = types.SimpleNamespace(WaitForSingleObject=lambda *_: 0, GetExitCodeProcess=exit_code)
        self.assertEqual(abi.wait(1, 0), 259)
        abi.k.WaitForSingleObject = lambda *_: 258
        self.assertIsNone(abi.wait(1, 1))
        for outcome in (128, 0xffffffff):
            abi.k.WaitForSingleObject = lambda *_, value=outcome: value
            with self.assertRaises(module.OwnershipError):
                abi.wait(1, 0)

    def test_unknown_diagnostic_fields_and_printer_failure_remain_private(self):
        module, native = self.make()
        process = self.spawn(module)
        process.stage, process.active_count, process.total_count = "private-canary", True, float("nan")
        process.returncode, process.forced = "private-canary", 1
        with redirect_stdout(io.StringIO()) as output:
            process.diagnostic()
        line = output.getvalue()
        self.assertLessEqual(len(line.encode("ascii")), 1024)
        self.assertNotIn("canary", line)
        value = json.loads(line.split("=", 1)[1])
        self.assertTrue(all(value[key] is None for key in ("stage", "active", "total", "exit_code", "forced")))
        with mock.patch.object(builtins, "print", side_effect=KeyboardInterrupt()):
            process.diagnostic()

    def test_interrupted_native_boundaries_report_unknown_and_do_not_retry_close(self):
        module, native = self.make()
        process = self.spawn(module)
        native.close = mock.Mock(side_effect=KeyboardInterrupt("private-canary"))
        with self.assertRaises(KeyboardInterrupt):
            process.process.close()
        self.assertIsNone(process.process.closed)
        self.assertFalse(process.process.close())
        native.close.assert_called_once()
        process.creation_attempted, process.creation_resolved, process.created = True, False, False
        process.resume_attempted, process.resumed = True, False
        with redirect_stdout(io.StringIO()) as output:
            process.diagnostic()
        value = json.loads(output.getvalue().split("=", 1)[1])
        self.assertIsNone(value["created"])
        self.assertIsNone(value["resumed"])
        self.assertIsNone(value["process_handle_closed"])
        self.assertNotIn("private", output.getvalue())

    def test_fixed_width_win32_signatures_are_defined_without_loading_native(self):
        module = owner_module()
        functions = types.SimpleNamespace()
        def dll(*args, **kwargs):
            class Kernel:
                def __getattr__(self, name):
                    function = lambda *args: None
                    setattr(functions, name, function)
                    return function
            return Kernel()
        with mock.patch.object(module.C, "WinDLL", side_effect=dll, create=True), mock.patch.object(module.os, "name", "nt"):
            abi = module._Win32()
        self.assertEqual(ctypes.sizeof(abi.ACCOUNT), 48)
        self.assertEqual(ctypes.sizeof(abi.PI), 24 if ctypes.sizeof(ctypes.c_void_p) == 8 else 16)
        self.assertEqual(functions.CreateProcessW.argtypes[-1], ctypes.POINTER(abi.PI))
        self.assertEqual(functions.WaitForSingleObject.restype, ctypes.c_uint32)
        self.assertEqual(len(functions.UpdateProcThreadAttribute.argtypes), 7)


class LoaderTests(unittest.TestCase):
    def setUp(self):
        self.namespace = types.SimpleNamespace()
        actual_import = builtins.__import__
        def isolated(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "sys" and globals and Path(globals.get("__file__", "")).name in {HTTP.name, OWNER.name}:
                return self.namespace
            return actual_import(name, globals, locals, fromlist, level)
        self.patch = mock.patch.object(builtins, "__import__", side_effect=isolated)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def load(self, path):
        module = types.ModuleType("fake_alias")
        module.__file__ = str(path)
        exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
        return module

    def test_actual_swift_h_webdav_h_controller_h_share_sticky_owner(self):
        producer = self.load(ROOT / "scripts/application-lab/run_windows_swift.py")
        aliases = [producer.H, producer.W.H, producer.C.H]
        owner = aliases[0].O
        self.assertTrue(all(alias.O is owner for alias in aliases))
        native = Native()
        owner._native_factory = lambda: native
        first = owner.spawn(["fixed"], env={"FIXED": "value"})
        first.mark_uncertain()
        calls = list(native.calls)
        for alias in aliases:
            with self.assertRaises(owner.OwnershipError):
                alias.O.run_setup(["fixed"], env={"FIXED": "value"})
        self.assertEqual(native.calls, calls)
        self.assertIs(owner._active, first)
        fresh = self.load(HTTP)
        self.assertIs(fresh.O, owner)
        with self.assertRaises(owner.OwnershipError):
            fresh.O.spawn(["fixed"], env={"FIXED": "value"})

    def test_source_path_size_digest_and_failed_slot_conflicts_do_not_replace_owner(self):
        first = self.load(HTTP)
        envelope = getattr(self.namespace, first.O.SLOT)
        for key, value in (("path", "different"), ("bytes", -1), ("sha256", "0" * 64), ("state", "failed")):
            original = envelope[key]
            envelope[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.load(HTTP)
            self.assertIs(getattr(self.namespace, first.O.SLOT), envelope)
            envelope[key] = original  # Wholly fake namespace only.
        real_read = first.read
        with mock.patch.object(first, "read", side_effect=lambda path, *args, **kw: real_read(path, *args, **kw) + (b"# mutation" if Path(path) == OWNER else b"")):
            with self.assertRaises(ValueError):
                first._load_owned_helper()
        self.assertIs(envelope["module"], first.O)

    def test_non_main_loader_fails_before_publishing(self):
        module = self.load(HTTP)
        with mock.patch.object(module.threading, "current_thread", return_value=object()), self.assertRaises(ValueError):
            module._load_owned_helper()

    def test_all_eight_receipt_closures_bind_owner_missing_and_changed_bytes(self):
        base = self.load(ROOT / "scripts/application_evidence.py")
        modules = [self.load(ROOT / ("scripts/" + name + "_application_evidence.py")) for name in
                   ("tui", "webdav", "webdav_bearer", "b2", "ftp", "swift", "azureblob")]
        member = "scripts/application-lab/owned_helper_process.py"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for module in [base, *modules]:
                self.assertEqual(module.HARNESS_FILES.count(member), 1)
                for name in module.HARNESS_FILES:
                    path = root / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b"inert source bytes")
                expected = base.tree_hash(root, module.HARNESS_FILES)
                (root / member).write_bytes(b"changed inert bytes")
                self.assertNotEqual(base.tree_hash(root, module.HARNESS_FILES), expected)
                (root / member).unlink()
                with self.assertRaises((ValueError, OSError)):
                    base.tree_hash(root, module.HARNESS_FILES)
            filesystem = self.load(ROOT / "scripts/filesystem_application_evidence.py")
            self.assertTrue(set(base.HARNESS_FILES).issubset(filesystem.HARNESS_FILES))
        http = self.load(HTTP)
        with mock.patch.object(http.O, "loaded_source_sha256", "0" * 64), self.assertRaises(ValueError):
            http.loaded_sources_preserved()

    def test_bridge_final_thread_uncertainty_blocks_every_later_setup_before_release(self):
        for mode in ("watchdog_live", "watchdog_query_error", "reader_query_error"):
            with self.subTest(mode=mode):
                # A separate synthetic interpreter namespace for each schedule.
                self.namespace = types.SimpleNamespace()
                http = self.load(HTTP)
                native = Native()
                http.O._native_factory = lambda: native
                process = http.O.spawn(["fixed"], env={"FIXED": "value"})
                bridge = object.__new__(http.Bridge)
                bridge.process, bridge.last = process, {"state": "finished"}
                bridge.failed, bridge.done = http.threading.Event(), http.threading.Event()
                bridge.response_lock = http.threading.Lock()
                bridge.messages, bridge.transport = http.queue.Queue(), {}
                bridge.calls = bridge.responses = 0
                bridge.ready = bridge.forced = bridge.stage_invalid = False
                bridge.stage_bytes = bytearray()
                bridge.watchdog, bridge.threads = mock.Mock(), [mock.Mock(), mock.Mock()]
                bridge.watchdog.is_alive.return_value = mode == "watchdog_live"
                for thread in bridge.threads:
                    thread.is_alive.return_value = False
                primary = KeyboardInterrupt("private-canary")
                if mode == "watchdog_query_error":
                    bridge.watchdog.is_alive.side_effect = primary
                if mode == "reader_query_error":
                    bridge.threads[0].is_alive.side_effect = [False, primary]
                with redirect_stdout(io.StringIO()):
                    if mode == "watchdog_live":
                        self.assertFalse(bridge.close())
                    else:
                        with self.assertRaises(KeyboardInterrupt) as caught:
                            bridge.close()
                        self.assertIs(caught.exception, primary)
                self.assertIs(http.O._active, process)
                self.assertTrue(process.uncertain)
                calls = list(native.calls)
                with self.assertRaises(http.O.OwnershipError):
                    http.O.run_setup(["fixed", "Verify"], env={"FIXED": "value"})
                self.assertEqual(native.calls, calls)


if __name__ == "__main__":
    unittest.main()
