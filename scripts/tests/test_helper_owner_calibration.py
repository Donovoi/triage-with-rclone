"""Pure contracts and deterministic fakes; never starts a native fixture or thread."""
import ast
from contextlib import redirect_stdout
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import struct
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
def load(name, path):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module
F = load('calibration_fixture_test', ROOT / 'scripts/application-lab/helper_owner_fixture.py')
Q = load('calibration_controller_test', ROOT / 'scripts/application-lab/qualify_helper_owner.py')


def windows_source_view(target, origin=ROOT):
    """Test-only Windows materialization; exact pinned bytes remain mandatory."""
    windows_text = {'HostedConPtySession.cs', 'hosted_session.ps1', 'prepare_case.ps1'}
    for name, pin in Q.SOURCE_PINS.items():
        raw = (origin/name).read_bytes()
        matches = lambda data: len(data) == pin['bytes'] and hashlib.sha256(data).hexdigest() == pin['sha256']
        if not matches(raw):
            assert Path(name).name in windows_text
            lf = raw.replace(b'\r\n', b'\n')
            alternatives = {v for v in (lf, lf.replace(b'\n', b'\r\n')) if matches(v)}
            assert len(alternatives) == 1
            raw = alternatives.pop()
        path = target/name; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)


def request():
    return dict(schema_version=1, nonce='a'*32, controller=dict(pid=10, created=20, image=str(ROOT / 'python.exe')),
                python_sha256='b'*64, fixture_sha256='c'*64, release=101, ready=102)


def transfer(expected=None):
    expected = request() if expected is None else expected
    result = {k: expected[k] for k in ('schema_version', 'nonce', 'controller', 'python_sha256', 'fixture_sha256')}
    result.update(child=dict(pid=11, created=21, image=expected['controller']['image']), child_handle=900)
    return result


class Parent:
    PI = lambda self: types.SimpleNamespace(process=None, thread=None, pid=None)
    def __init__(self):
        self.calls, self.next = [], iter((103, 104, 107, 900))
        self.controller, self.child = request()['controller'], transfer()['child']
    def current(self): return -1
    def open_controller(self, value): self.calls.append(('open', value['pid'])); return 100
    def identify(self, handle): self.calls.append(('identity', handle)); return self.controller if handle == 100 else self.child
    def wait(self, handle, ms): self.calls.append(('wait', handle, ms)); return False
    def flags(self, handle, flags): self.calls.append(('flags', handle, flags))
    def duplicate(self, *args): self.calls.append(('duplicate', args)); return next(self.next)
    def null(self, readable): self.calls.append(('null', readable)); return 105 if readable else 106
    def stdout(self): self.calls.append(('stdout',)); return 99
    def create_child(self, args, handles, result):
        self.calls.append(('create', args, handles))
        result.process, result.thread, result.pid = 201, 202, 11
    def x64(self, handle): self.calls.append(('x64', handle)); return True
    def close(self, handle): self.calls.append(('close', handle))


class FakeProcess:
    def __init__(self):
        self.returncode, self.finalized, self.final_result, self.uncertain, self.forced = 0, True, False, True, True
        self.created = self.creation_resolved = self.resumed = True
        handle = lambda value=1, closed=True: types.SimpleNamespace(value=value, closed=closed, users=0)
        self.process, self.primary_thread, self.job = handle(1), handle(2), handle(3)
        self.child = [handle(4), handle(5), handle(6)]
        self.parent = [handle(None, None), handle(7, False), handle(None, None)]
        self.stdout = types.SimpleNamespace(closed=False, handle=self.parent[1])
        self.active_count, self.total_count = 1, 2


class FakeCapture:
    def __init__(self, process):
        self.process = process
        self.returned = self.claimed = True
        self.revoked = self.eof = self.failed = self.overflow = False
        self.pipe = process.stdout
        self.thread = mock.Mock()
        self.thread.is_alive.return_value = True
        self.snapshot = mock.Mock(return_value=b'')
    def finish(self, seconds):
        self.thread.is_alive.return_value = False
        self.eof, self.pipe.closed = True, True
        self.pipe.handle.closed = True


class FakeOwner:
    HelperProcess, _Capture = FakeProcess, FakeCapture
    class OwnershipError(OSError): pass
    def __init__(self):
        self._active, self.calls, self.on_start = None, [], None
        self.before, self.after, self.native_calls = (2, 4), (0, 4), []
        owner = self
        class Native:
            def __init__(self):
                def member(child, job, output):
                    owner.native_calls.append(('member', child, job)); output._obj.value = 1
                    return 1
                self.k = types.SimpleNamespace(IsProcessInJob=mock.Mock(side_effect=member))
            def accounting(self, job):
                owner.native_calls.append(('accounting', job))
                return owner.before if job == 3 else owner.after
        self._Win32 = self._native_factory = Native
    def run_setup(self, args, **kwargs):
        self.calls.append((list(args), dict(kwargs)))
        if self._active is not None:
            raise self.OwnershipError('fixed')
        process = FakeProcess()
        capture = FakeCapture(process)
        self._active, self.capture = process, capture
        process.api = self._Win32()
        process.job.owner, process.job.attempted = process, False
        if self.on_start:
            self.on_start(args)
        process.job.closed, process.job.users = None, 1
        try:
            process.active_count, process.total_count = process.api.accounting(process.job.value)
        finally:
            process.job.closed, process.job.users, process.job.attempted = True, 0, True
        error = subprocess.TimeoutExpired(args, 20, output=b'')
        raise error


class Contracts(unittest.TestCase):
    def test_request_transfer_closed_types_sources_nonce_and_aliases(self):
        expected = request(); value = transfer(expected)
        self.assertIs(F.request(expected), expected)
        self.assertIs(F.transfer(value, expected), value)
        for key, bad in [('schema_version', True), ('nonce', 'x'*32), ('release', True), ('ready', 101),
                         ('release', 2**64-1), ('python_sha256', 'private-canary')]:
            changed = dict(expected); changed[key] = bad
            with self.subTest(key=key), self.assertRaises(F.FixtureError): F.request(changed)
        for key, bad in [('nonce', 'b'*32), ('fixture_sha256', 'd'*64), ('child_handle', 101),
                         ('child_handle', 1.0), ('child', dict(value['child'], pid=10)),
                         ('child', dict(value['child'], image=str(ROOT / 'other.exe')))]:
            changed = dict(value); changed[key] = bad
            with self.subTest(key=key), self.assertRaises(F.FixtureError): F.transfer(changed, expected)
        with self.assertRaises(F.FixtureError): F.transfer(dict(value, extra=0), expected)

    def test_bounded_private_records_reject_duplicate_partial_and_overflow(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'request.json'
            for raw in (b'{"x":1,"x":2}', b'{', b' '*4097, b'{"x":NaN}'):
                path.write_bytes(raw)
                with self.subTest(raw=raw[:30]), self.assertRaises((F.FixtureError, ValueError)):
                    F.record(path)
            path.unlink()
            F.publish(path, request())
            self.assertEqual(F.record(path), request())
            with self.assertRaises(FileExistsError): F.publish(path, request())

    def test_read_keeps_path_and_descriptor_ctime_domains_separate_and_stable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixed'; path.write_bytes(b'known')
            before = path.stat()
            fields = {key:getattr(before, key) for key in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns')}
            opened = types.SimpleNamespace(**fields, st_ctime_ns=1)
            with mock.patch.object(F.os, 'fstat', return_value=opened):
                self.assertEqual(F.read(path, 5), b'known')
            changed = types.SimpleNamespace(**fields, st_ctime_ns=2)
            with mock.patch.object(F.os, 'fstat', side_effect=[opened, changed]), self.assertRaises(F.FixtureError):
                F.read(path, 5)

    def test_parent_verifies_controller_before_any_duplicate(self):
        for field, bad in [('pid', 12), ('created', 22), ('image', str(ROOT / 'different.exe'))]:
            api = Parent(); api.controller = dict(api.controller, **{field: bad})
            with mock.patch.object(F, 'record', return_value=request()), mock.patch.object(F, 'source_identity'), self.assertRaises(F.FixtureError):
                F.parent(api, ROOT / 'request.json')
            self.assertEqual([c for c in api.calls if c[0] == 'duplicate'], [])
            self.assertEqual([c for c in api.calls if c[0] == 'close'], [('close', 100)])

    def test_parent_exact_creation_transfer_and_once_only_known_closes(self):
        api = Parent()
        with mock.patch.object(F, 'record', return_value=request()), mock.patch.object(F, 'source_identity'), mock.patch.object(F, 'publish') as write:
            self.assertEqual(F.parent(api, ROOT / 'request.json'), 0)
        calls = api.calls
        self.assertEqual([c for c in calls if c[0] == 'open'], [('open', 10)])
        created = next(c for c in calls if c[0] == 'create')
        self.assertEqual(created[2], [105, 107, 106, 103, 104])
        self.assertEqual(created[1][1:4], ['-B', '-I', '-S'])
        self.assertEqual([c[1] for c in calls if c[0] == 'duplicate'][-1], (-1, 201, 100, F.SYNC | F.QUERY))
        self.assertEqual([c[1] for c in calls if c[0] == 'close'], [201, 202, 107, 106, 105, 104, 103, 100])
        self.assertEqual(write.call_args.args[1], transfer())

    def test_interrupted_creation_or_publication_never_returns_success_or_reopens_child(self):
        for boundary in ('create_child', 'publish'):
            api = Parent(); error = KeyboardInterrupt('private-canary')
            with mock.patch.object(F, 'record', return_value=request()), mock.patch.object(F, 'source_identity'), \
                 mock.patch.object(F, 'publish') as publication:
                if boundary == 'create_child': api.create_child = mock.Mock(side_effect=error)
                else: publication.side_effect = error
                with self.assertRaises(KeyboardInterrupt) as caught: F.parent(api, ROOT / 'request.json')
            self.assertIs(caught.exception, error)
            self.assertEqual([c for c in api.calls if c[0] == 'open'], [('open', 10)])
            self.assertEqual(len([c for c in api.calls if c[0] == 'close']), len(set(c[1] for c in api.calls if c[0] == 'close')))

    def test_child_release_and_fail_safe_have_distinct_exit_with_known_closes(self):
        for released, code in ((True, 0), (False, 33)):
            api = mock.Mock(); api.wait.side_effect = [False, released]
            with mock.patch.object(F, 'record', return_value=request()), mock.patch.object(F, 'source_identity'):
                self.assertEqual(F.child(api, ROOT / 'request.json', 103, 104), code)
            self.assertEqual(api.wait.call_args_list, [mock.call(103, 0), mock.call(103, 45000)])
            api.signal.assert_called_once_with(104)
            self.assertEqual(api.close.call_args_list, [mock.call(104), mock.call(103)])

    def test_transfer_requires_actual_handle_identity_rights_x64_and_live_state(self):
        value = transfer()
        for mutation in ('identity', 'rights', 'arch', 'exited'):
            api = mock.Mock(); api.identify.return_value = value['child']; api.wait.return_value = False
            if mutation == 'identity': api.identify.return_value = dict(value['child'], created=22)
            if mutation == 'rights': api.flags.side_effect = OSError('private-canary')
            if mutation == 'arch': api.x64.side_effect = OSError('private-canary')
            if mutation == 'exited': api.wait.return_value = True
            with self.assertRaises((Q.CalibrationError, OSError)): Q.accept_transfer(F, api, value, request())
            api.close.assert_not_called()
        api = mock.Mock(); api.identify.return_value = value['child']; api.wait.return_value = False
        self.assertEqual(Q.accept_transfer(F, api, value, request()), 900)

    def recover(self):
        owner = FakeOwner()
        try: owner.run_setup(['fixed'])
        except subprocess.TimeoutExpired as error:
            return owner, error
        self.fail('must raise')

    def test_exact_traceback_and_expected_negative_reject_missing_or_false_facts(self):
        owner, error = self.recover()
        process, capture = Q.recover(owner, error)
        Q.expected_failure(owner, process, capture, error)
        for target, field, bad in [(process, 'returncode', 1), (process, 'active_count', True), (process, 'total_count', 1),
                                   (process, 'final_result', True), (process, 'uncertain', False),
                                   (capture, 'eof', True), (capture, 'claimed', False), (capture, 'returned', False)]:
            old = getattr(target, field); setattr(target, field, bad)
            with self.assertRaises(Q.CalibrationError): Q.expected_failure(owner, process, capture, error)
            setattr(target, field, old)
        with self.assertRaises(Q.CalibrationError): Q.recover(owner, subprocess.TimeoutExpired(['fixed'], 20))
        error.timeout = 19
        with self.assertRaises(Q.CalibrationError): Q.recover(owner, error)

    def test_sticky_admission_no_second_native_creation_or_reset(self):
        owner, error = self.recover(); process = owner._active
        Q.admission(owner, process, ['fixed'], {'FIXED': 'yes'})
        self.assertIs(owner._active, process)
        self.assertEqual(owner.calls[-1][1], dict(env={'FIXED': 'yes'}, timeout=20, failure_drain_seconds=5, capture_limit=4096, check=False))
        owner.run_setup = mock.Mock(return_value=None)
        with self.assertRaises(Q.CalibrationError): Q.admission(owner, process, ['fixed'], {'FIXED': 'yes'})

    def test_all_production_owned_handles_must_be_proved_closed_not_just_reader(self):
        owner, error = self.recover(); process, capture = Q.recover(owner, error)
        for handle in [process.job, process.primary_thread, *process.child]:
            for unknown in (None, False):
                handle.closed = unknown
                with self.assertRaises(Q.CalibrationError): Q.expected_failure(owner, process, capture, error)
            handle.closed = True
        capture.finish(0)
        Q.owner_handles_closed(process)
        for handle in [process.process, process.job, process.primary_thread, *process.child, process.parent[1]]:
            handle.closed = None
            with self.assertRaises(Q.CalibrationError): Q.owner_handles_closed(process)
            handle.closed = True
            handle.users = 1
            with self.assertRaises(Q.CalibrationError): Q.owner_handles_closed(process)
            handle.users = 0

    def cleanup_case(self):
        api = mock.Mock(); api.wait.return_value = True; api.exit_code.return_value = 0
        capture = FakeCapture(FakeProcess()); capture.thread.join.side_effect = capture.finish
        return api, capture

    def test_one_release_wait_and_existing_reader_join_share_ten_seconds(self):
        api, capture = self.cleanup_case()
        result = Q.observe_cleanup(api, 101, 900, capture, clock=mock.Mock(side_effect=[0, 1, 3]))
        self.assertTrue(result['complete'])
        api.signal.assert_called_once_with(101)
        api.wait.assert_called_once_with(900, 9000)
        api.exit_code.assert_called_once_with(900)
        capture.thread.join.assert_called_once_with(7)
        capture.pipe = mock.Mock()
        api.close.assert_not_called()

    def test_cleanup_uncertainty_cannot_credit_production_or_calibration(self):
        for mode in ('release', 'timeout', 'exit', 'join', 'alive', 'no_eof', 'pipe', 'borrow', 'output'):
            api, capture = self.cleanup_case()
            if mode == 'release': api.signal.side_effect = KeyboardInterrupt('private-canary')
            if mode == 'timeout': api.wait.return_value = False
            if mode == 'exit': api.exit_code.return_value = 33
            if mode == 'join': capture.thread.join.side_effect = KeyboardInterrupt('private-canary')
            if mode in {'alive', 'no_eof', 'pipe', 'borrow', 'output'}:
                def finish(seconds, mode=mode):
                    capture.finish(seconds)
                    if mode == 'alive': capture.thread.is_alive.return_value = True
                    if mode == 'no_eof': capture.eof = False
                    if mode == 'pipe': capture.pipe.closed = False
                    if mode == 'borrow': capture.pipe.handle.users = 1
                    if mode == 'output': capture.snapshot.return_value = b'unexpected'
                capture.thread.join.side_effect = finish
            result = Q.observe_cleanup(api, 101, 900, capture, clock=mock.Mock(side_effect=[0, 1, 3]))
            self.assertFalse(result['complete'], mode)
            self.assertEqual(api.signal.call_count, 1)
            self.assertEqual(api.wait.call_count, 1)
            self.assertEqual(capture.thread.join.call_count, 1)
            if mode == 'timeout': api.exit_code.assert_not_called()

    def test_remaining_invalid_or_exhausted_clock_never_adds_budget(self):
        self.assertEqual(Q.remaining(10, lambda: 11), 0)
        for invalid in (float('nan'), float('inf'), True, -1):
            with self.assertRaises(Q.CalibrationError): Q.remaining(10, lambda: invalid)

    def test_invalid_cleanup_clock_still_releases_once_without_guessing_a_wait(self):
        api, capture = self.cleanup_case()
        result = Q.observe_cleanup(api, 101, 900, capture, clock=lambda: float('nan'))
        self.assertFalse(result['complete'])
        self.assertEqual(result['error'], 'unexpected')
        api.signal.assert_called_once_with(101)
        api.wait.assert_not_called()
        capture.thread.join.assert_not_called()

    def test_exact_flat_temp_members_hashes_identity_and_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); owned = root / 'owned'; owned.mkdir()
            for name in ('request.json', 'transfer.json'): (owned/name).write_bytes(b'{}')
            info = owned.stat(); expected = (info.st_dev, info.st_ino)
            hashes = {n: F.digest(owned/n, 4096) for n in ('request.json', 'transfer.json')}
            (owned/'extra').write_bytes(b'private-canary')
            with self.assertRaises(Q.CalibrationError): Q.remove_owned(F, owned, expected, hashes)
            self.assertTrue((owned/'request.json').exists()); (owned/'extra').unlink()
            with self.assertRaises(Q.CalibrationError): Q.remove_owned(F, owned, (0, 0), hashes)
            with self.assertRaises(Q.CalibrationError): Q.remove_owned(F, owned, expected, dict(hashes, **{'request.json':'0'*64}))
            Q.remove_owned(F, owned, expected, hashes)
            self.assertFalse(owned.exists())

    def test_actual_source_header_and_registration_reject_each_changed_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            windows_source_view(root)
            with mock.patch.object(Q, 'ROOT', root):
                Q.verify_sources(F)
                for name in Q.SOURCE_PINS:
                    path = root/name; original = path.read_bytes(); path.write_bytes(original+b'changed')
                    with self.subTest(name=name), self.assertRaises(Q.CalibrationError): Q.verify_sources(F)
                    path.write_bytes(original)

    def test_linux_text_view_is_not_an_alternate_production_source_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); linux, windows = root/'linux', root/'windows'
            windows_source_view(linux)
            changed = 0
            for name in Q.SOURCE_PINS:
                path = linux/name
                if path.name in {'HostedConPtySession.cs', 'hosted_session.ps1', 'prepare_case.ps1'}:
                    old = path.read_bytes(); new = old.replace(b'\r\n', b'\n'); changed += old != new; path.write_bytes(new)
            self.assertGreater(changed, 0)
            with mock.patch.object(Q, 'ROOT', linux), self.assertRaises(Q.CalibrationError): Q.verify_sources(F)
            windows_source_view(windows, linux)
            with mock.patch.object(Q, 'ROOT', windows): self.assertEqual(len(Q.verify_sources(F)), 64)
            name = 'scripts/application-lab/HostedConPtySession.cs'
            (linux/name).write_bytes((linux/name).read_bytes()+b'changed')
            with self.assertRaises(AssertionError): windows_source_view(root/'bad', linux)

    def test_workflow_only_x64_step_and_original_probes_still_registered(self):
        workflow = (ROOT/'.github/workflows/ci.yml').read_text()
        self.assertEqual(workflow.count(Q.REGISTRATION), 1)
        self.assertIn("if: runner.os == 'Windows' && runner.arch == 'X64'", Q.REGISTRATION)
        self.assertIn('timeout-minutes: 2', Q.REGISTRATION)
        self.assertEqual(Q.REGISTRATION.count('qualify_helper_owner.py'), 1)
        self.assertNotIn('continue-on-error', Q.REGISTRATION)
        for mode in ('setup', 'bridge'):
            self.assertEqual(workflow.count('run_windows_http.py --'+mode+'-probe'), 1)

    def test_native_abi_definitions_and_no_child_kill_or_pid_reopen_surface(self):
        functions = {}
        class Kernel:
            def __getattr__(self, name):
                function = mock.Mock(side_effect=AssertionError('native function cannot run'))
                functions[name] = function
                return function
        with mock.patch.object(F.C, 'WinDLL', return_value=Kernel(), create=True), mock.patch.object(F.os, 'name', 'nt'):
            api = F.Native()
        self.assertEqual(ctypes.sizeof(api.PI), 24)
        self.assertEqual(len(functions['DuplicateHandle'].argtypes), 7)
        self.assertEqual(functions['WaitForSingleObject'].restype, ctypes.c_uint32)
        self.assertNotIn('TerminateProcess', functions)
        self.assertNotIn('CreateToolhelp32Snapshot', functions)
        tree = ast.parse(Path(F.__file__).read_bytes())
        opens = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'OpenProcess']
        self.assertEqual(len(opens), 1)
        self.assertEqual(ast.unparse(opens[0].args[-1]), "value['pid']")

    def test_native_fake_creation_has_only_five_handles_no_suspend_or_extra_job(self):
        calls = []
        class Kernel:
            def __getattr__(self, name):
                function = mock.Mock(side_effect=lambda *args: calls.append((name, args)) or 1)
                setattr(self, name, function)
                return function
        kernel = Kernel()
        with mock.patch.object(F.C, 'WinDLL', return_value=kernel, create=True), mock.patch.object(F.os, 'name', 'nt'):
            api = F.Native()
        api.flags = mock.Mock()
        def initialize(storage, count, flags, size):
            size._obj.value = 128
            return int(storage is not None)
        kernel.InitializeProcThreadAttributeList.side_effect = initialize
        def created(*args):
            self.assertEqual(args[4], 1)
            self.assertEqual(args[5], 0x80000 | 0x08000000)
            self.assertEqual([args[-2]._obj.startup.stdin, args[-2]._obj.startup.stdout, args[-2]._obj.startup.stderr], [10, 11, 12])
            args[-1]._obj.process, args[-1]._obj.thread, args[-1]._obj.pid = 201, 202, 13
            return 1
        kernel.CreateProcessW.side_effect = created
        result = api.PI()
        api.create_child(['fixed.exe', '-B', '-I', '-S'], [10, 11, 12, 14, 15], result)
        self.assertEqual((result.process, result.thread, result.pid), (201, 202, 13))
        update = kernel.UpdateProcThreadAttribute.call_args.args
        self.assertEqual(update[2], 0x20002)
        self.assertEqual(list(update[3]), [10, 11, 12, 14, 15])
        self.assertEqual(kernel.UpdateProcThreadAttribute.call_count, 1)
        self.assertEqual(kernel.CreateProcessW.call_count, 1)
        self.assertEqual(kernel.DeleteProcThreadAttributeList.call_count, 1)

    def controller_case(self, fault=None):
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            source_view = temp / 'source'; windows_source_view(source_view)
            image = temp / 'python.exe'
            data = bytearray(128); data[:2] = b'MZ'; struct.pack_into('<I', data, 60, 64)
            data[64:68] = b'PE\0\0'; struct.pack_into('<H', data, 68, 0x8664); struct.pack_into('<H', data, 88, 0x20b)
            image.write_bytes(data)
            owner = FakeOwner()
            current = dict(pid=10, created=20, image=str(image))
            api = mock.Mock(); api.current.return_value = -1; api.event.side_effect = [101, 102]
            api.duplicate.return_value = 901
            def close(handle):
                owner.native_calls.append(('close', handle))
                if (fault, handle) in {('child_close', 900), ('job_close', 901)}:
                    raise KeyboardInterrupt('close-canary')
            api.close.side_effect = close
            if fault == 'nonzero': owner.after = (1, 4)
            if fault == 'decreasing_total': owner.after = (0, 1)
            if fault == 'query':
                original = owner._Win32.accounting
                def accounting(native, handle):
                    if handle == 901:
                        owner.native_calls.append(('accounting', handle))
                        raise KeyboardInterrupt('query-canary')
                    return original(native, handle)
                owner._Win32.accounting = accounting
            api.identify.side_effect = lambda h: current if h == -1 else dict(current, pid=11, created=21)
            api.wait.side_effect = lambda handle, ms: handle == 102 and owner._active is not None or handle == 900 and ms > 0
            api.exit_code.return_value = 0
            def started(args):
                request_path = Path(args[-1]); expected = F.record(request_path)
                F.publish(request_path.with_name('transfer.json'), transfer(expected))
                owner.capture.thread.join.side_effect = owner.capture.finish
                if fault == 'membership': owner._active.api.k.IsProcessInJob.side_effect = lambda *args: 0
            owner.on_start = started
            H = types.SimpleNamespace(O=owner, loaded_sources_preserved=lambda: None, powershell=lambda: str(image),
                                      read=lambda p, limit, **kwargs: F.read(p, limit))
            with mock.patch.object(Q, 'load', side_effect=[F, H]), mock.patch.object(F, 'Native', return_value=api), \
                 mock.patch.object(Q, 'ROOT', source_view), \
                 mock.patch.object(Q, 'os', types.SimpleNamespace(name='nt', environ=os.environ)), mock.patch.object(Q.sys, 'argv', ['fixed']), \
                 mock.patch.dict(os.environ, dict(GITHUB_ACTIONS='true', RUNNER_OS='Windows', RUNNER_ARCH='X64',
                    RUNNER_ENVIRONMENT='github-hosted', RUNNER_TEMP=str(temp), SYSTEMROOT='fixed', WINDIR='fixed')), \
                 redirect_stdout(io.StringIO()) as output:
                code = Q.main()
            value = json.loads(output.getvalue().split('=', 1)[1])
            return code, value, owner, api, {p.name for p in temp.iterdir()}

    def test_full_controller_fake_preserves_expected_failure_and_independent_cleanup(self):
        code, value, owner, api, remaining = self.controller_case()
        self.assertEqual(code, 0)
        self.assertEqual(value['result'], 'passed')
        self.assertTrue(value['expected_failure'] and value['owner_sticky_failed'] and value['cleanup_complete'])
        self.assertEqual(value['schema_version'], 2)
        self.assertEqual(value['contract'], Q.CONTRACT)
        self.assertEqual((value['before_active'], value['before_total']), (2, 4))
        self.assertEqual((value['final_active'], value['final_total']), (0, 4))
        self.assertTrue(value['child_in_job'] and value['query_job_closed'] and value['observation_complete'])
        self.assertIs(owner._active.final_result, False)
        self.assertEqual(len(owner.calls), 2)
        self.assertEqual(owner.calls[0], owner.calls[1])
        self.assertEqual(owner.calls[0][1]['timeout'], 20)
        self.assertEqual(owner.calls[0][1]['failure_drain_seconds'], 5)
        api.signal.assert_called_once_with(101)
        self.assertEqual(api.close.call_args_list, [mock.call(900), mock.call(102), mock.call(101), mock.call(901)])
        api.duplicate.assert_called_once_with(-1, 3, -1, 0x0004)
        self.assertEqual(owner.native_calls, [('accounting', 3), ('member', 900, 901),
            ('close', 900), ('close', 102), ('close', 101), ('accounting', 901), ('close', 901)])
        self.assertEqual(remaining, {'python.exe', 'source'})

    def test_full_controller_query_membership_or_reference_close_failure_cannot_pass(self):
        for fault in ('nonzero', 'query', 'child_close', 'job_close', 'membership'):
            with self.subTest(fault=fault):
                code, value, owner, api, remaining = self.controller_case(fault)
                self.assertEqual(code, 1); self.assertEqual(value['result'], 'failed')
                self.assertFalse(value['cleanup_complete'] or value['observation_complete'])
                self.assertIs(owner._active.final_result, False)
                self.assertTrue(owner._active.uncertain)
                self.assertEqual(len(remaining - {'python.exe', 'source'}), 1)
                self.assertEqual(api.close.call_args_list, [mock.call(900), mock.call(102), mock.call(101), mock.call(901)])
                api.signal.assert_called_once_with(101)
                final_calls = owner.native_calls.count(('accounting', 901))
                self.assertEqual(final_calls, 0 if fault in {'child_close', 'membership'} else 1)
                if fault == 'job_close': self.assertIsNone(value['query_job_closed'])
                if fault == 'nonzero': self.assertEqual(value['final_active'], 1)
                self.assertNotIn('canary', json.dumps(value))

    def test_full_controller_decreasing_total_retains_failed_observations(self):
        code, value, owner, api, remaining = self.controller_case('decreasing_total')
        self.assertEqual(code, 1)
        self.assertEqual((value['result'], value['reason']), ('failed', 'job_quiescence'))
        self.assertEqual((value['before_active'], value['before_total']), (2, 4))
        self.assertEqual((value['final_active'], value['final_total']), (0, 1))
        self.assertFalse(value['observation_complete'] or value['cleanup_complete'])
        self.assertTrue(value['expected_failure'] and value['owner_sticky_failed'])
        self.assertTrue(value['child_in_job'] and value['query_job_closed'])
        self.assertIs(owner._active.final_result, False)
        self.assertTrue(owner._active.uncertain)
        self.assertEqual(owner.native_calls.count(('accounting', 901)), 1)
        api.signal.assert_called_once_with(101)
        self.assertEqual(api.close.call_args_list, [mock.call(900), mock.call(102), mock.call(101), mock.call(901)])
        self.assertEqual(len(remaining - {'python.exe', 'source'}), 1)

    def observe(self, api=None, owner=None):
        owner = FakeOwner() if owner is None else owner
        if api is None:
            api = mock.Mock(); api.current.return_value = -1
            api.duplicate.return_value = 901; api.wait.return_value = False
        observation = Q.JobObservation(owner, api)
        try:
            observation.install()
            owner.run_setup(['fixed'])
        except subprocess.TimeoutExpired as error:
            pending = error
            trace = error.__traceback__
        finally:
            observation.restore()
        self.assertIs(pending.__traceback__, trace)
        return owner, api, observation, pending

    def test_job_wrapper_retains_exact_capability_and_original_accounting_tuple(self):
        owner, api, observation, error = self.observe()
        process, capture = Q.recover(owner, error)
        Q.expected_failure(owner, process, capture, error)
        observation.ready(process)
        self.assertIs(observation.before, owner.before)
        self.assertIs(owner._Win32.accounting, observation.original)
        self.assertIs(owner._active.final_result, False)
        self.assertEqual(owner.native_calls, [('accounting', 3)])
        api.duplicate.assert_called_once_with(-1, 3, -1, 0x0004)
        api.flags.assert_called_once_with(901, 0)
        self.assertEqual(observation.calls, 1)
        self.assertTrue(observation.close())
        self.assertTrue(observation.close())
        api.close.assert_called_once_with(901)

    def test_duplicate_failed_bool_or_interruption_nonnull_is_never_close_authority(self):
        for outcome in (0, KeyboardInterrupt('private-canary'), 1):
            with self.subTest(outcome=type(outcome).__name__):
                api = object.__new__(F.Native)
                def duplicate(source, handle, target, output, access, inherit, options):
                    self.assertEqual((source, handle, target, access, inherit, options), (-1, 3, -1, 4, 0, 0))
                    output._obj.value = 901
                    if isinstance(outcome, BaseException): raise outcome
                    return outcome
                api.k = types.SimpleNamespace(DuplicateHandle=mock.Mock(side_effect=duplicate))
                api.current = lambda: -1; api.flags = mock.Mock(); api.close = mock.Mock()
                owner, _, observation, error = self.observe(api)
                self.assertIs(type(error), subprocess.TimeoutExpired)
                if outcome == 1:
                    self.assertEqual(observation.job, 901)
                    observation.close(); api.close.assert_called_once_with(901)
                else:
                    self.assertIsNone(observation.job)
                    self.assertTrue(observation.failed)
                    self.assertFalse(observation.close())
                    api.close.assert_not_called(); api.flags.assert_not_called()
                api.k.DuplicateHandle.assert_called_once()

    def test_successful_duplicate_invalid_output_or_later_failure_keeps_authority_precise(self):
        for output_value in (None, 0, 2**64-1):
            api = object.__new__(F.Native)
            def duplicate(source, handle, target, output, *rest):
                output._obj.value = output_value; return 1
            api.k = types.SimpleNamespace(DuplicateHandle=mock.Mock(side_effect=duplicate))
            api.current = lambda: -1; api.flags = mock.Mock(); api.close = mock.Mock()
            _, _, observation, _ = self.observe(api)
            self.assertIsNone(observation.job); observation.close(); api.close.assert_not_called()
        api = mock.Mock(); api.current.return_value = -1; api.duplicate.return_value = 901
        api.flags.side_effect = KeyboardInterrupt('private-canary')
        _, _, observation, _ = self.observe(api)
        self.assertEqual(observation.job, 901)
        self.assertTrue(observation.failed)
        observation.close(); observation.close(); api.close.assert_called_once_with(901)

    def test_repeated_or_foreign_wrapper_never_repeats_or_suppresses_original_call(self):
        owner, api, observation, _ = self.observe()
        result = observation.wrapper(owner._active.api, 3)
        self.assertIs(result, owner.before)
        self.assertEqual(owner.native_calls, [('accounting', 3), ('accounting', 3)])
        api.duplicate.assert_called_once(); self.assertTrue(observation.failed)
        observation.close()
        for mutation in ('active', 'api', 'closed', 'borrow', 'handle'):
            owner = FakeOwner(); api = mock.Mock(); api.current.return_value = -1
            observation = Q.JobObservation(owner, api)
            process = FakeProcess(); process.api = owner._Win32(); owner._active = process
            process.job.owner, process.job.attempted, process.job.closed, process.job.users = process, False, None, 1
            native, handle = process.api, 3
            if mutation == 'active': owner._active = object()
            elif mutation == 'api': process.api = object()
            elif mutation == 'closed': process.job.closed = True
            elif mutation == 'borrow': process.job.users = 0
            else: handle = 4
            result = observation.wrapper(native, handle)
            self.assertIs(result, owner.before if handle == 3 else owner.after)
            self.assertEqual(owner.native_calls, [('accounting', handle)])
            api.duplicate.assert_not_called(); self.assertTrue(observation.failed)

    def test_original_accounting_baseexception_and_restore_preserve_pending_primary(self):
        owner = FakeOwner(); primary = KeyboardInterrupt('private-canary')
        def original(native, handle): raise primary
        owner._Win32.accounting = original
        api = mock.Mock(); observation = Q.JobObservation(owner, api)
        with self.assertRaises(KeyboardInterrupt) as caught:
            observation.wrapper(object(), 3)
        self.assertIs(caught.exception, primary); api.duplicate.assert_not_called()
        owner = FakeOwner(); api = mock.Mock(); api.current.return_value = -1; api.duplicate.return_value = 901
        observation = Q.JobObservation(owner, api)
        import builtins
        sets = []
        def set_attribute(target, name, value):
            sets.append(value)
            if value is observation.original: raise KeyboardInterrupt('restore-canary')
            return builtins.setattr(target, name, value)
        with mock.patch.object(Q, 'setattr', side_effect=set_attribute, create=True):
            try:
                try:
                    observation.install()
                    try: owner.run_setup(['fixed'])
                    except subprocess.TimeoutExpired as error:
                        primary, trace = error, error.__traceback__
                        raise
                finally: observation.restore()
            except subprocess.TimeoutExpired as error:
                self.assertIs(error, primary); self.assertIs(error.__traceback__, trace)
                self.assertEqual(Q.recover(owner, error), (owner._active, owner.capture))
            observation.restore()
        self.assertEqual(sets, [observation.wrapper, observation.original])
        self.assertTrue(observation.failed); self.assertFalse(observation.restored)
        with self.assertRaises(Q.CalibrationError): observation.ready(owner._active)
        observation.close(); api.close.assert_called_once_with(901)

    def test_known_child_membership_and_live_state_required_without_pid_open(self):
        for output, returned, exited in ((1, 1, False), (0, 1, False), (2, 1, False), (1, 0, False), (1, 1, True)):
            owner, api, observation, _ = self.observe()
            def member(child, job, value): value._obj.value = output; return returned
            owner._active.api.k.IsProcessInJob.side_effect = member
            api.wait.return_value = exited
            if (output, returned, exited) == (1, 1, False):
                observation.membership(900); self.assertIs(observation.member, True)
            else:
                with self.assertRaises(Q.CalibrationError): observation.membership(900)
                self.assertTrue(observation.failed); self.assertIsNone(observation.member)
            owner._active.api.k.IsProcessInJob.assert_called_once()
            api.open_controller.assert_not_called()
            observation.close()
        self.assertNotIn('OpenProcess', (ROOT/'scripts/application-lab/qualify_helper_owner.py').read_text())

    def test_single_final_query_requires_zero_and_successful_once_only_job_close(self):
        for result in ((0, 4), (0, 5), (0, 1), (1, 4), (True, 4), (0, True), (4, 2)):
            owner, api, observation, _ = self.observe(); owner.after = result
            observation.membership(900)
            if result in ((0, 4), (0, 5)): observation.quiescence()
            else:
                with self.assertRaises(Q.CalibrationError): observation.quiescence()
            if result == (0, 1) and type(result[1]) is int:
                self.assertEqual(observation.before, (2, 4))
                self.assertEqual(observation.after, (0, 1))
                self.assertTrue(observation.failed)
            with self.assertRaises(Q.CalibrationError): observation.quiescence()
            self.assertEqual(owner.native_calls.count(('accounting', 901)), 1)
            observation.close(); observation.close(); api.close.assert_called_once_with(901)
        owner, api, observation, _ = self.observe(); observation.membership(900)
        api.close.side_effect = KeyboardInterrupt('close-canary')
        observation.quiescence()
        self.assertFalse(observation.close()); self.assertFalse(observation.close())
        self.assertTrue(observation.failed); self.assertIsNone(observation.closed)
        api.close.assert_called_once_with(901)

    def test_final_query_error_or_missing_member_never_becomes_quiet(self):
        owner, api, observation, _ = self.observe()
        with self.assertRaises(Q.CalibrationError): observation.quiescence()
        self.assertNotIn(('accounting', 901), owner.native_calls); observation.close()
        owner, api, observation, _ = self.observe(); observation.membership(900)
        primary = KeyboardInterrupt('query-canary')
        original = observation.original
        def query(native, handle):
            if handle == 901: raise primary
            return original(native, handle)
        observation.original = query
        with self.assertRaises(KeyboardInterrupt) as caught: observation.quiescence()
        self.assertIs(caught.exception, primary)
        self.assertIsNone(observation.after); self.assertTrue(observation.failed)
        observation.close(); api.close.assert_called_once_with(901)

    def test_emitter_monotonic_total_required_only_for_complete_observation(self):
        value = dict(schema_version=2, contract=Q.CONTRACT, scope='hosted_windows_x64_inert_descendant',
            result='passed', reason=None, expected_failure=True, owner_sticky_failed=True, cleanup_complete=True,
            parent_exit=0, child_exit=0, forced=True, architecture='native_x64', sources_sha256='1'*64,
            controller_sha256='2'*64, python_sha256='3'*64, powershell_file_sha256='4'*64,
            child_in_job=True, query_job_closed=True, observation_complete=True,
            before_active=2, before_total=4, final_active=0, final_total=4)
        for total in (4, 5):
            with redirect_stdout(io.StringIO()) as output:
                self.assertTrue(Q.emit(dict(value, final_total=total)))
            self.assertEqual(json.loads(output.getvalue().split('=', 1)[1])['final_total'], total)
        for result in ('passed', 'failed'):
            with redirect_stdout(io.StringIO()) as output:
                self.assertFalse(Q.emit(dict(value, result=result, final_total=1)))
            self.assertEqual(output.getvalue(), '')
        failed = dict(value, result='failed', reason='job_quiescence', cleanup_complete=False,
                      observation_complete=False, final_total=1)
        with redirect_stdout(io.StringIO()) as output:
            self.assertTrue(Q.emit(failed))
        self.assertEqual(json.loads(output.getvalue().split('=', 1)[1]), failed)

    def test_closed_public_record_rejects_private_strings_and_printer_failure(self):
        value = dict(schema_version=2, contract=Q.CONTRACT, scope='hosted_windows_x64_inert_descendant', result='failed', reason='transfer',
            expected_failure=False, owner_sticky_failed=False, cleanup_complete=False, parent_exit=None, child_exit=None,
            forced=None, architecture=None, sources_sha256=None, controller_sha256=None, python_sha256=None, powershell_file_sha256=None,
            child_in_job=None, query_job_closed=None, observation_complete=False, before_active=None, before_total=None,
            final_active=None, final_total=None)
        with redirect_stdout(io.StringIO()) as output:
            self.assertTrue(Q.emit(value))
        self.assertLess(len(output.getvalue().encode()), 2048)
        for key in ('reason', 'sources_sha256', 'forced', 'child_exit', 'contract', 'child_in_job', 'final_active', 'query_job_closed'):
            with redirect_stdout(io.StringIO()) as output:
                self.assertFalse(Q.emit(dict(value, **{key:'private-canary'})))
            self.assertEqual(output.getvalue(), '')
        with mock.patch('builtins.print', side_effect=KeyboardInterrupt('private-canary')):
            self.assertFalse(Q.emit(value))
        for mutation in ({'schema_version':1}, {'observation_complete':True}, {'final_active':0},
                         {'final_active':1, 'final_total':0}, {'child_in_job':1}):
            with redirect_stdout(io.StringIO()) as output:
                self.assertFalse(Q.emit(dict(value, **mutation)))
            self.assertEqual(output.getvalue(), '')


if __name__ == '__main__':
    unittest.main()
