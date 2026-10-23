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


class SetupQuiescenceTests(unittest.TestCase):
    class Clock:
        def __init__(self):
            self.value, self.paces = 0.0, []
        def monotonic(self):
            return self.value
        def sleep(self, seconds):
            self.paces.append(seconds)
            self.value += seconds

    def make(self):
        module, native, clock = owner_module(), Native(body=b"synthetic setup\n"), self.Clock()
        module._native_factory = lambda: native
        module.time = clock
        original = native.create
        def create(process, *args):
            native.owner = process
            original(process, *args)
        native.create = create
        return module, native, clock

    def invoke(self, module, thread=InlineThread):
        with mock.patch.object(module.threading, "Thread", thread):
            return module.run_setup(["fixed", "Verify"], env={"FIXED": "value"})

    def prepare(self, module):
        process = module.spawn(["fixed"], env={"FIXED": "value"},
            stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with mock.patch.object(module.threading, "Thread", InlineThread):
            capture = module._Capture(process)
            capture.start()
            self.assertTrue(capture.join(20))
        process.wait(0)
        return process, capture, module._SetupQuiescence()

    def diagnostic(self, output):
        records = [json.loads(line.split("=", 1)[1]) for line in output.getvalue().splitlines()
                   if line.startswith("application_helper_setup_quiescence=")]
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(set(record), {"schema_version", "status", "queries", "active", "total", "deadline_expired"})
        self.assertEqual(record["schema_version"], 1)
        self.assertNotIn("private-canary", output.getvalue())
        return record

    def assert_retained(self, module, native, *, kills=0):
        self.assertIs(module._active, native.owner)
        self.assertTrue(module._poisoned)
        self.assertTrue(native.owner.uncertain)
        self.assertFalse(native.owner.final_result)
        self.assertEqual(sum(row[0] == "kill" for row in native.calls), kills)
        closes = [row[1] for row in native.calls if row[0] == "close"]
        self.assertEqual(len(closes), len(set(closes)))

    def test_parent_reference_released_before_immediate_zero_and_independent_final_proof(self):
        module, native, clock = self.make()
        observations = []
        def accounting(handle):
            observations.append((handle, native.owner.process.closed, module._active is native.owner))
            native.calls.append(("accounting", handle))
            return (0 if native.owner.process.closed is True else 1, 1)
        native.accounting = accounting
        with redirect_stdout(io.StringIO()) as output:
            result = self.invoke(module)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b"synthetic setup\n", None))
        self.assertEqual(output.getvalue(), "")
        process = native.owner
        self.assertEqual(observations, [(process.job.value, True, True)] * 2)
        self.assertEqual(clock.paces, [])
        self.assertEqual(native.calls.count(("close", process.process.value)), 1)
        self.assertLess(native.calls.index(("close", process.process.value)), native.calls.index(("accounting", process.job.value)))
        self.assertEqual(native.calls[-1], ("close", process.job.value))
        self.assertTrue(process.final_result)
        self.assertIsNone(module._active)
        self.assertFalse(any(row[0] == "kill" for row in native.calls))

    def test_pending_members_allow_active_and_cumulative_total_growth_then_zero(self):
        module, native, clock = self.make()
        samples = iter(((1, 2), (2, 3), (1, 3), (0, 3), (0, 3)))
        seen = []
        def accounting(handle):
            value = next(samples); seen.append(value); return value
        native.accounting = accounting
        with redirect_stdout(io.StringIO()) as output:
            self.invoke(module)
        self.assertEqual(seen, [(1, 2), (2, 3), (1, 3), (0, 3), (0, 3)])
        self.assertEqual(clock.paces, [0.05] * 3)
        self.assertEqual(output.getvalue(), "")
        self.assertTrue(native.owner.final_result)

    def test_capture_and_parent_wait_consume_original_budget_with_residual_pacing(self):
        module, native, clock = self.make()
        joins, waits, queries = [], [], []
        class CaptureTime(InlineThread):
            def join(self, seconds):
                joins.append(seconds); clock.value += 12
        def wait(handle, seconds):
            waits.append(seconds); clock.value += 7.98; return 0
        native.wait = wait
        def accounting(handle):
            queries.append(clock.value)
            return (1, 2) if len(queries) == 1 else (0, 2)
        native.accounting = accounting
        with redirect_stdout(io.StringIO()) as output, self.assertRaises(module.OwnershipError):
            self.invoke(module, CaptureTime)
        self.assertEqual(joins[0], 20)
        self.assertEqual(waits, [8])
        self.assertEqual(len(clock.paces), 1)
        self.assertAlmostEqual(clock.paces[0], 0.02)
        record = self.diagnostic(output)
        self.assertEqual((record["status"], record["queries"]), ("deadline_exhausted", 1))
        # Only the unchanged finalizer can query again, after poisoning.
        self.assertEqual(len(queries), 2)
        self.assert_retained(module, native)

    def test_no_new_query_at_expiry_and_zero_completed_exactly_at_deadline_can_pass(self):
        for mode in ("expired", "exact_zero", "late_zero"):
            with self.subTest(mode=mode):
                module, native, clock = self.make()
                calls = []
                def wait(handle, seconds):
                    clock.value = 20 if mode == "expired" else 19.9
                    return 0
                native.wait = wait
                def accounting(handle):
                    calls.append(clock.value)
                    if len(calls) == 1 and mode != "expired":
                        clock.value = 20 if mode == "exact_zero" else 20.001
                    return 0, 1
                native.accounting = accounting
                with redirect_stdout(io.StringIO()) as output:
                    if mode == "exact_zero":
                        self.invoke(module)
                        self.assertTrue(native.owner.final_result)
                        self.assertEqual(output.getvalue(), "")
                    else:
                        with self.assertRaises(module.OwnershipError): self.invoke(module)
                        record = self.diagnostic(output)
                        self.assertEqual(record["status"], "deadline_exhausted")
                        self.assertEqual(record["queries"], 0 if mode == "expired" else 1)
                        self.assertTrue(record["deadline_expired"])
                        self.assert_retained(module, native)
                self.assertEqual(len(calls), 1 if mode == "expired" else 2)
                self.assertEqual(clock.paces, [])

    def test_parent_handle_close_time_is_charged_before_first_query(self):
        module, native, clock = self.make()
        original = native.close
        def close(handle):
            original(handle)
            if handle == native.owner.process.value: clock.value = 20.01
        native.close = close
        with redirect_stdout(io.StringIO()) as output, self.assertRaises(module.OwnershipError):
            self.invoke(module)
        record = self.diagnostic(output)
        self.assertEqual((record["status"], record["queries"]), ("deadline_exhausted", 0))
        self.assertEqual(sum(row[0] == "accounting" for row in native.calls), 1)
        self.assert_retained(module, native)

    def test_stalled_clock_caps_401_queries_and_400_paces_without_recovery(self):
        module, native, clock = self.make()
        clock.sleep = lambda seconds: clock.paces.append(seconds)
        native.active = 1
        with redirect_stdout(io.StringIO()) as output, self.assertRaises(module.OwnershipError):
            self.invoke(module)
        record = self.diagnostic(output)
        self.assertEqual((record["status"], record["queries"], record["active"], record["total"]),
                         ("observation_cap", 401, 1, 2))
        self.assertEqual(clock.paces, [0.05] * 400)
        self.assertEqual(sum(row[0] == "accounting" for row in native.calls), 402)
        self.assert_retained(module, native)

    def test_invalid_or_regressing_clocks_fail_before_further_polling(self):
        for bad in (True, float("nan"), float("inf"), -1, "private-canary", 4.0):
            with self.subTest(bad=bad):
                module, native, clock = self.make()
                process, capture, observation = self.prepare(module)
                values = iter((5.0, bad))
                clock.monotonic = lambda: next(values)
                with self.assertRaises(module.OwnershipError): observation.observe(process, capture, 20)
                self.assertEqual(observation.status, "clock_failed")
                self.assertIsNone(observation.deadline_expired)
                self.assertEqual(observation.queries, 0)
                self.assertTrue(process.uncertain)
                self.assertEqual(observation.last_clock, 5.0)
                self.assertFalse(any(row[0] == "accounting" for row in native.calls))

    def test_invalid_deadline_is_terminal_before_parent_close(self):
        for bad in (True, float("nan"), float("inf"), "private-canary"):
            module, native, clock = self.make()
            process, capture, observation = self.prepare(module)
            with self.subTest(bad=bad), self.assertRaises(module.OwnershipError):
                observation.observe(process, capture, bad)
            self.assertEqual(observation.status, "clock_failed")
            self.assertFalse(process.process.attempted)
            self.assertTrue(process.uncertain)

    def test_query_failure_keeps_primary_and_stops_polling_despite_cleanup_zero(self):
        module, native, clock = self.make()
        first, calls = KeyboardInterrupt("private-canary"), []
        def accounting(handle):
            calls.append(handle)
            if len(calls) == 1: raise first
            return 0, 2
        native.accounting = accounting
        with redirect_stdout(io.StringIO()) as output, self.assertRaises(KeyboardInterrupt) as caught:
            self.invoke(module)
        self.assertIs(caught.exception, first)
        self.assertEqual(len(calls), 2)
        record = self.diagnostic(output)
        self.assertEqual((record["status"], record["queries"], record["active"]), ("query_failed", 1, None))
        self.assertEqual(clock.paces, [])
        self.assert_retained(module, native)

    def test_malformed_or_decreasing_counts_never_retry_a_later_polling_zero(self):
        for invalid in ((True, 1), (0, True), (-1, 1), (2, 1), (0, 0), (0, 2**32), (0, 1), [0, 3], (0,), None):
            with self.subTest(invalid=invalid):
                module, native, clock = self.make()
                values = iter(((1, 2), invalid, (0, 2)))
                calls = []
                def accounting(handle):
                    value = next(values); calls.append(value); return value
                native.accounting = accounting
                with redirect_stdout(io.StringIO()) as output, self.assertRaises(module.OwnershipError):
                    self.invoke(module)
                record = self.diagnostic(output)
                self.assertEqual((record["status"], record["queries"], record["active"], record["total"]),
                                 ("invalid_accounting", 2, 1, 2))
                self.assertEqual(len(calls), 3)
                self.assertEqual(clock.paces, [0.05])
                self.assert_retained(module, native)

    def test_pace_failure_or_overshoot_is_terminal_and_keeps_last_valid_sample(self):
        for mode in ("raise", "overshoot", "backward"):
            module, native, clock = self.make()
            first = SystemExit("private-canary")
            native.active = 1
            def pace(seconds):
                clock.paces.append(seconds)
                if mode == "raise": raise first
                clock.value = 21 if mode == "overshoot" else -0.01
            clock.sleep = pace
            with self.subTest(mode=mode), redirect_stdout(io.StringIO()) as output:
                with self.assertRaises(SystemExit if mode == "raise" else module.OwnershipError) as caught:
                    self.invoke(module)
                if mode == "raise": self.assertIs(caught.exception, first)
            record = self.diagnostic(output)
            self.assertEqual(record["status"], {"raise": "pace_failed", "overshoot": "deadline_exhausted", "backward": "clock_failed"}[mode])
            self.assertEqual((record["queries"], record["active"], record["total"]), (1, 1, 2))
            self.assertEqual(clock.paces, [0.05])
            self.assertEqual(sum(row[0] == "accounting" for row in native.calls), 2)
            self.assert_retained(module, native)

    def test_parent_close_failure_is_once_only_and_never_authorizes_accounting(self):
        module, native, clock = self.make()
        first, original = KeyboardInterrupt("private-canary"), native.close
        def close(handle):
            original(handle)
            if handle == native.owner.process.value: raise first
        native.close = close
        with redirect_stdout(io.StringIO()) as output, self.assertRaises(KeyboardInterrupt) as caught:
            self.invoke(module)
        self.assertIs(caught.exception, first)
        record = self.diagnostic(output)
        self.assertEqual((record["status"], record["queries"]), ("parent_close_failed", 0))
        self.assertFalse(any(row[0] == "accounting" for row in native.calls))
        self.assertEqual(native.calls.count(("close", native.owner.process.value)), 1)
        self.assert_retained(module, native)

    def test_zero_observation_cannot_override_failed_final_proof_or_job_close(self):
        for mode in ("active", "job_close"):
            module, native, clock = self.make()
            calls, original = [], native.close
            def accounting(handle):
                calls.append(handle)
                return (1 if mode == "active" and len(calls) == 2 else 0), 2
            native.accounting = accounting
            def close(handle):
                original(handle)
                if mode == "job_close" and handle == native.owner.job.value:
                    raise OSError("private-canary")
            native.close = close
            with self.subTest(mode=mode), redirect_stdout(io.StringIO()) as output, self.assertRaises(module.OwnershipError):
                self.invoke(module)
            record = self.diagnostic(output)
            self.assertEqual((record["status"], record["queries"], record["active"], record["total"]),
                             ("zero_observed", 1, 0, 2))
            self.assertEqual(len(calls), 2)
            self.assert_retained(module, native)

    def test_admission_rejects_incomplete_or_foreign_state_without_native_poll(self):
        for mode in ("reader_live", "pipe_open", "foreign", "poisoned", "forced", "finalized", "ambiguous_close", "process_borrow", "job_borrow", "not_resumed", "exit_bool"):
            with self.subTest(mode=mode):
                module, native, clock = self.make()
                process, capture, observation = self.prepare(module)
                if mode == "reader_live": capture.thread.is_alive = lambda: True
                elif mode == "pipe_open": process.parent[1].closed = False
                elif mode == "foreign": module._active = object()
                elif mode == "poisoned": module._poisoned = True
                elif mode == "forced": process.forced = True
                elif mode == "finalized": process.finalized = True
                elif mode == "ambiguous_close": process.process.attempted = True
                elif mode == "process_borrow": process.process.users = 1
                elif mode == "job_borrow": process.job.users = 1
                elif mode == "not_resumed": process.resumed = False
                elif mode == "exit_bool": process.returncode = False
                before, reservation = list(native.calls), module._active
                with self.assertRaises(module.OwnershipError): observation.observe(process, capture, 20)
                self.assertEqual(native.calls, before)
                self.assertIs(module._active, reservation)
                self.assertTrue(process.uncertain)
                self.assertEqual((observation.status, observation.queries), ("admission_failed", 0))

    def test_nonzero_exit_skips_success_observation_and_retains_old_finalizer_path(self):
        module, native, clock = self.make()
        native.wait = lambda *_: 7
        module._SetupQuiescence = mock.Mock(side_effect=AssertionError("must not construct"))
        with redirect_stdout(io.StringIO()) as output:
            result = self.invoke(module)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout, b"synthetic setup\n")
        self.assertEqual(sum(row[0] == "accounting" for row in native.calls), 1)
        self.assertEqual(clock.paces, [])
        self.assertEqual(output.getvalue(), "")
        module._SetupQuiescence.assert_not_called()

    def test_successful_exit_preserves_capture_limit_before_new_observation(self):
        for length in (0, 4096, 4097):
            with self.subTest(length=length):
                module, native, clock = self.make()
                native.body = b"x" * length
                with redirect_stdout(io.StringIO()) as output:
                    if length > 4096:
                        with self.assertRaises(module.OwnershipError): self.invoke(module)
                        self.assertEqual(sum(row[0] == "accounting" for row in native.calls), 1)
                        self.assertNotIn("application_helper_setup_quiescence=", output.getvalue())
                    else:
                        result = self.invoke(module)
                        self.assertEqual(result.stdout, b"x" * length)
                        self.assertEqual(result.returncode, 0)
                        self.assertEqual(sum(row[0] == "accounting" for row in native.calls), 2)
                        self.assertIsNone(module._active)
                        self.assertEqual(output.getvalue(), "")
                self.assertEqual(clock.paces, [])

    def test_closed_diagnostic_rejects_private_values_and_printer_failure_keeps_primary(self):
        module, native, clock = self.make()
        observation = module._SetupQuiescence()
        for field, bad in (("status", "private-canary"), ("queries", 402), ("active", "private-canary"), ("deadline_expired", "private-canary")):
            with self.subTest(field=field), mock.patch.object(observation, field, bad), redirect_stdout(io.StringIO()) as output:
                observation.diagnostic()
                self.assertEqual(output.getvalue(), "")
        first = KeyboardInterrupt("private-canary")
        native.accounting = mock.Mock(side_effect=[first, (0, 1)])
        with mock.patch.object(module, "print", side_effect=SystemExit("printer"), create=True), self.assertRaises(KeyboardInterrupt) as caught:
            self.invoke(module)
        self.assertIs(caught.exception, first)
        self.assert_retained(module, native)

    def test_persistent_clock_failure_preserves_primary_and_always_finalizes_without_join(self):
        for mode in ("raise", "nan", "inf", "bool"):
            with self.subTest(mode=mode):
                module, native, clock = self.make()
                first, primary, waits, finalizations = KeyboardInterrupt("private-canary"), [], [], []
                original_create, original_observe = native.create, module._SetupQuiescence.observe
                def create(process, *args):
                    original_create(process, *args)
                    original_wait, original_finalize = process.wait, process.finalize
                    def wait(timeout=None):
                        waits.append(timeout); return original_wait(timeout)
                    def finalize():
                        finalizations.append(True); return original_finalize()
                    process.wait, process.finalize = wait, finalize
                native.create = create
                def broken():
                    if mode == "raise": raise first
                    return {"nan": float("nan"), "inf": float("inf"), "bool": True}[mode]
                def accounting(handle):
                    native.calls.append(("accounting", handle))
                    clock.monotonic = broken
                    return 0, 1
                native.accounting = accounting
                def observe(observation, *args):
                    try: return original_observe(observation, *args)
                    except BaseException as error:
                        primary.append(error); raise
                with mock.patch.object(module._SetupQuiescence, "observe", observe), \
                     mock.patch.object(module._Capture, "failure_close", side_effect=AssertionError("no timed join")), \
                     redirect_stdout(io.StringIO()) as output, self.assertRaises(BaseException) as caught:
                    self.invoke(module)
                self.assertEqual(len(primary), 1)
                self.assertIs(caught.exception, primary[0])
                if mode == "raise": self.assertIs(caught.exception, first)
                self.assertEqual(waits, [20, 0])
                self.assertEqual(finalizations, [True])
                self.assertEqual(clock.paces, [])
                self.assertEqual(self.diagnostic(output)["status"], "clock_failed")
                self.assert_retained(module, native)

    def test_clockless_fallback_preserves_claimed_reader_or_revokes_unclaimed_start(self):
        for claimed in (False, True):
            with self.subTest(claimed=claimed):
                module, native, clock = self.make()
                first, captures, joins = SystemExit("private-canary"), [], []
                def broken(): raise OSError("private-canary-clock")
                class Interrupted(InlineThread):
                    def start(self):
                        capture = self.target.__self__
                        capture.claimed = claimed
                        captures.append(capture)
                        clock.monotonic = broken
                        raise first
                    def join(self, seconds):
                        joins.append(seconds); raise AssertionError("no join authority")
                with redirect_stdout(io.StringIO()) as output, self.assertRaises(SystemExit) as caught:
                    self.invoke(module, Interrupted)
                self.assertIs(caught.exception, first)
                self.assertEqual(joins, [])
                capture, process = captures[0], native.owner
                self.assertEqual(capture.revoked, not claimed)
                self.assertTrue(capture.stop)
                self.assertEqual(process.stdout.closed, not claimed)
                self.assertTrue(process.finalized)
                self.assertEqual([row for row in native.calls if row[0] == "wait"], [("wait", 0)])
                if not claimed:
                    before = list(native.calls); capture.run(); self.assertEqual(native.calls, before)
                self.assertNotIn("application_helper_setup_quiescence=", output.getvalue())
                self.assert_retained(module, native, kills=1)

    def test_clockless_secondary_cleanup_errors_do_not_skip_finalization_or_replace_primary(self):
        module, native, clock = self.make()
        first, calls, original = KeyboardInterrupt("private-canary"), [], native.create
        def fail(name):
            def inner(*args, **kwargs):
                calls.append(name); raise SystemExit("secondary")
            return inner
        def create(process, *args):
            original(process, *args)
            process.kill, process.wait, process.finalize = fail("kill"), fail("wait"), fail("finalize")
        native.create = create
        class Interrupted(InlineThread):
            def start(self):
                clock.monotonic = lambda: float("nan")
                raise first
        with redirect_stdout(io.StringIO()), self.assertRaises(KeyboardInterrupt) as caught:
            self.invoke(module, Interrupted)
        self.assertIs(caught.exception, first)
        self.assertEqual(calls, ["kill", "wait", "finalize"])
        self.assertTrue(module._poisoned)
        self.assertIs(module._active, native.owner)


class SessionQuiescenceTests(unittest.TestCase):
    """Fake three-pipe owners; no OS process, real clock, or native API."""
    def make(self):
        module, native, clock = owner_module(), Native(body=b""), SetupQuiescenceTests.Clock()
        module._native_factory = lambda: native
        module.time = clock
        process = module.spawn(["fixed"], env={"FIXED": "value"})
        for pipe in (process.stdin, process.stdout, process.stderr):
            pipe.close()
        process.wait(0)
        return module, native, clock, process, module._SessionQuiescence()

    def fail(self, module, native, process, observation, deadline=1, error_type=None):
        with self.assertRaises(error_type or module.OwnershipError) as caught:
            observation.observe(process, deadline)
        with redirect_stdout(io.StringIO()):
            self.assertFalse(process.finalize())
            self.assertFalse(process.finalize())
        self.assertIs(module._active, process)
        self.assertTrue(module._poisoned)
        self.assertTrue(process.uncertain)
        before = list(native.calls)
        with self.assertRaises(module.OwnershipError):
            module.spawn(["later"], env={"FIXED": "value"})
        self.assertEqual(native.calls, before)
        self.assertFalse(any(row[0] == "kill" for row in native.calls))
        return caught.exception

    def test_parent_handle_closes_before_zero_and_finalizer_proves_zero_again(self):
        module, native, clock, process, observation = self.make()
        seen = []
        def accounting(handle):
            seen.append((process.process.closed, process.job.closed, module._active is process))
            return 0, 1
        native.accounting = accounting
        observation.observe(process, 1)
        self.assertEqual(observation.status, "zero_observed")
        self.assertTrue(process.finalize())
        self.assertEqual(seen, [(True, None, True)] * 2)
        self.assertEqual(clock.paces, [])
        self.assertEqual(native.calls.count(("close", process.process.value)), 1)
        self.assertIsNone(module._active)

    def test_active_and_total_may_grow_before_zero_with_bounded_pacing(self):
        module, native, clock, process, observation = self.make()
        samples = iter(((1, 2), (2, 3), (1, 3), (0, 3), (0, 3)))
        native.accounting = lambda handle: next(samples)
        observation.observe(process, 1)
        self.assertEqual(observation.queries, 4)
        self.assertEqual(clock.paces, [0.05] * 3)
        self.assertTrue(process.finalize())

    def test_original_residual_budget_is_never_restarted(self):
        module, native, clock, process, observation = self.make()
        clock.value = 0.98
        native.active = 1
        self.fail(module, native, process, observation, 1)
        self.assertEqual(observation.status, "deadline_exhausted")
        self.assertEqual(observation.queries, 1)
        self.assertEqual(len(clock.paces), 1)
        self.assertAlmostEqual(clock.paces[0], 0.02)
        self.assertEqual(clock.value, 1)

    def test_expired_deadline_rejects_before_parent_handle_or_accounting(self):
        module, native, clock, process, observation = self.make()
        clock.value = 1
        with self.assertRaises(module.OwnershipError):
            observation.observe(process, 1)
        self.assertIsNone(process.process.closed)
        self.assertEqual(observation.queries, 0)
        self.assertEqual(clock.paces, [])

    def test_zero_returned_after_deadline_cannot_succeed(self):
        module, native, clock, process, observation = self.make()
        def accounting(handle):
            clock.value = 2
            return 0, 1
        native.accounting = accounting
        self.fail(module, native, process, observation, 1)
        self.assertEqual(observation.status, "deadline_exhausted")

    def test_nonadvancing_clock_still_has_finite_observation_cap(self):
        module, native, clock, process, observation = self.make()
        native.active = 1
        clock.sleep = lambda seconds: clock.paces.append(seconds)
        self.fail(module, native, process, observation, 165)
        self.assertEqual(observation.status, "observation_cap")
        self.assertEqual(observation.queries, 401)
        self.assertEqual(clock.paces, [0.05] * 400)

    def test_malformed_or_decreasing_accounting_remains_failed(self):
        for sample in ((True, 1), (0, True), (-1, 1), (2, 1), (0, 0), (0, 2**32), [0, 1], (0, 2)):
            with self.subTest(sample=sample):
                module, native, clock, process, observation = self.make()
                samples = iter(((1, 3), sample))
                native.accounting = lambda handle: next(samples)
                self.fail(module, native, process, observation)
                self.assertEqual(observation.status, "invalid_accounting")

    def test_bad_clock_and_deadline_types_are_rejected(self):
        for value in (True, float("nan"), float("inf"), "1"):
            with self.subTest(value=value):
                module, native, clock, process, observation = self.make()
                self.fail(module, native, process, observation, value)
                self.assertEqual(observation.status, "clock_failed")
        module, native, clock, process, observation = self.make()
        clock.monotonic = iter((0.5, 0.4)).__next__
        self.fail(module, native, process, observation)
        self.assertEqual(observation.status, "clock_failed")

    def test_forced_uncertain_nonzero_and_open_pipes_are_not_admitted(self):
        for mode in ("forced", "uncertain", "nonzero", "open_pipe", "borrowed_pipe", "wrong_owner", "poisoned"):
            with self.subTest(mode=mode):
                module, native, clock, process, observation = self.make()
                if mode in ("forced", "uncertain"):
                    setattr(process, mode, True)
                elif mode == "nonzero":
                    process.returncode = 1
                elif mode == "open_pipe":
                    process.stdout.handle.closed = None
                elif mode == "borrowed_pipe":
                    process.parent[1].users = 1
                elif mode == "wrong_owner":
                    process.stderr.owner = object()
                else:
                    module._poisoned = True
                with self.assertRaises(module.OwnershipError):
                    observation.observe(process, 1)
                self.assertEqual(observation.queries, 0)
                self.assertIsNone(process.process.closed)

    def test_parent_handle_failure_is_not_retried_or_slept(self):
        module, native, clock, process, observation = self.make()
        original = native.close
        error = OSError("private-canary")
        def close(handle):
            if handle == process.process.value:
                native.calls.append(("failed_close", handle))
                raise error
            original(handle)
        native.close = close
        self.assertIs(self.fail(module, native, process, observation, error_type=OSError), error)
        self.assertEqual(observation.status, "parent_close_failed")
        self.assertEqual(native.calls.count(("failed_close", process.process.value)), 1)
        self.assertEqual(clock.paces, [])

    def test_query_exception_and_interrupt_keep_original_error_and_poison(self):
        for error in (OSError("private-canary"), KeyboardInterrupt("private-canary")):
            module, native, clock, process, observation = self.make()
            native.accounting = mock.Mock(side_effect=error)
            with self.assertRaises(type(error)) as caught:
                observation.observe(process, 1)
            self.assertIs(caught.exception, error)
            self.assertTrue(process.uncertain)
            self.assertTrue(module._poisoned)
            self.assertEqual(observation.status, "query_failed")

    def test_sleep_exception_is_sticky_and_diagnostic_is_closed(self):
        module, native, clock, process, observation = self.make()
        native.active = 1
        clock.sleep = mock.Mock(side_effect=OSError("private-canary"))
        with self.assertRaises(OSError):
            observation.observe(process, 1)
        with redirect_stdout(io.StringIO()) as output:
            observation.diagnostic()
        prefix = "application_helper_session_quiescence="
        self.assertTrue(output.getvalue().startswith(prefix))
        record = json.loads(output.getvalue()[len(prefix):])
        self.assertEqual(set(record), {"schema_version", "status", "queries", "active", "total", "deadline_expired"})
        self.assertEqual(record["status"], "pace_failed")
        self.assertNotIn("private-canary", output.getvalue())
        self.assertTrue(module._poisoned)

    def test_successful_observation_does_not_replace_fresh_finalizer_accounting(self):
        module, native, clock, process, observation = self.make()
        native.accounting = mock.Mock(side_effect=[(0, 1), (1, 2)])
        observation.observe(process, 1)
        with redirect_stdout(io.StringIO()):
            self.assertFalse(process.finalize())
        self.assertTrue(process.uncertain)
        self.assertIs(module._active, process)

    def test_final_job_close_failure_stays_failed(self):
        module, native, clock, process, observation = self.make()
        observation.observe(process, 1)
        original = native.close
        def close(handle):
            if handle == process.job.value:
                raise OSError("private-canary")
            original(handle)
        native.close = close
        with redirect_stdout(io.StringIO()):
            self.assertFalse(process.finalize())
        self.assertTrue(module._poisoned)


class SessionBridgeQuiescenceTests(unittest.TestCase):
    def setUp(self):
        LoaderTests.setUp(self)
        self.http = LoaderTests.load(self, HTTP)
        self.native, self.clock = Native(body=b""), SetupQuiescenceTests.Clock()
        self.http.O._native_factory = lambda: self.native
        self.http.O.time = self.clock
        self.process = self.http.O.spawn(["fixed"], env={"FIXED": "value"})
        bridge = object.__new__(self.http.Bridge)
        bridge.process, bridge.last = self.process, {"state": "finished"}
        bridge.failed, bridge.done = self.http.threading.Event(), self.http.threading.Event()
        bridge.response_lock = self.http.threading.Lock()
        bridge.messages, bridge.transport = self.http.queue.Queue(), {}
        bridge.calls = bridge.responses = 0
        bridge.ready = bridge.forced = bridge.stage_invalid = False
        bridge.stage_bytes = bytearray()
        bridge.watchdog, bridge.threads = mock.Mock(), [mock.Mock(), mock.Mock()]
        bridge.watchdog.is_alive.return_value = False
        for thread in bridge.threads:
            thread.is_alive.return_value = False
        bridge.deadline = 1
        self.bridge = bridge

    def test_clean_close_waits_for_owned_job_then_releases(self):
        self.native.accounting = mock.Mock(side_effect=[(1, 2), (0, 2), (0, 2)])
        with redirect_stdout(io.StringIO()) as output:
            self.assertTrue(self.bridge.close())
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(self.clock.paces, [0.05])
        self.assertEqual(self.bridge.deadline, 1)
        self.assertIsNone(self.http.O._active)
        self.assertFalse(self.process.forced)

    def test_repeated_clean_close_keeps_cached_final_proof_without_new_observation(self):
        with redirect_stdout(io.StringIO()):
            self.assertTrue(self.bridge.close())
        before = list(self.native.calls)
        self.clock.value = 2
        with mock.patch.object(self.http.O, "_SessionQuiescence") as observer, redirect_stdout(io.StringIO()):
            self.assertTrue(self.bridge.close())
        observer.assert_not_called()
        self.assertEqual(self.native.calls, before)
        self.assertIsNone(self.http.O._active)
        self.assertFalse(self.http.O._poisoned)

    def test_failed_transport_never_starts_quiescence(self):
        self.bridge.failed.set()
        with mock.patch.object(self.http.O, "_SessionQuiescence") as observer, redirect_stdout(io.StringIO()):
            self.assertFalse(self.bridge.close())
        observer.assert_not_called()
        self.assertTrue(self.http.O._poisoned)
        self.assertEqual(self.clock.paces, [])

    def test_live_reader_never_starts_quiescence_or_closes_its_pipe(self):
        self.bridge.threads[0].is_alive.return_value = True
        with mock.patch.object(self.http.O, "_SessionQuiescence") as observer, redirect_stdout(io.StringIO()):
            self.assertFalse(self.bridge.close())
        observer.assert_not_called()
        self.assertFalse(self.process.stdout.closed)
        self.assertTrue(self.http.O._poisoned)

    def test_close_work_consumes_original_deadline_without_new_window(self):
        self.bridge.watchdog.join.side_effect = lambda seconds: setattr(self.clock, "value", 1)
        with redirect_stdout(io.StringIO()) as output:
            self.assertFalse(self.bridge.close())
        self.assertIn('"status":"deadline_exhausted"', output.getvalue())
        self.assertEqual(self.clock.paces, [])
        self.assertEqual(self.bridge.deadline, 1)
        self.assertTrue(self.http.O._poisoned)

    def test_observation_interrupt_finalizes_without_hiding_interrupt(self):
        first = KeyboardInterrupt("private-canary")
        self.native.accounting = mock.Mock(side_effect=first)
        with redirect_stdout(io.StringIO()) as output, self.assertRaises(KeyboardInterrupt) as caught:
            self.bridge.close()
        self.assertIs(caught.exception, first)
        self.assertTrue(self.process.finalized)
        self.assertTrue(self.http.O._poisoned)
        self.assertNotIn("private-canary", output.getvalue())

    def test_independent_final_proof_failure_is_not_converted_to_success(self):
        self.native.accounting = mock.Mock(side_effect=[(0, 1), (1, 2)])
        with redirect_stdout(io.StringIO()):
            self.assertFalse(self.bridge.close())
        self.assertTrue(self.http.O._poisoned)
        self.assertTrue(self.process.uncertain)


if __name__ == "__main__":
    unittest.main()
