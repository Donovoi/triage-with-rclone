"""Definition-only source imports and fake kernel/process/thread controls. No native launch."""
from pathlib import Path
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


F = load("session_fixture_test", ROOT / "scripts/application-lab/helper_owner_fixture.py")
S = load("session_controller_test", ROOT / "scripts/application-lab/qualify_session_owner.py")


class SessionFixtureContracts(unittest.TestCase):
    def test_stdout_default_requires_pipe_and_session_requires_character(self):
        for file_type in (0, 1, 2, 3):
            for character in (False, True):
                with self.subTest(file_type=file_type, character=character):
                    api = object.__new__(F.Native)
                    api.k = types.SimpleNamespace(GetStdHandle=mock.Mock(return_value=77),
                                                  GetFileType=mock.Mock(return_value=file_type))
                    call = (lambda: api.stdout(character=True)) if character else api.stdout
                    if file_type == (2 if character else 3):
                        self.assertEqual(call(), 77)
                    else:
                        with self.assertRaises(F.FixtureError):
                            call()
                    api.k.GetStdHandle.assert_called_once_with((-11) & 0xffffffff)
                    api.k.GetFileType.assert_called_once_with(77)

    def test_child_modes_validate_matching_stdout_before_ready(self):
        for session, file_type in ((False, 3), (True, 2)):
            for actual_type in (2, 3):
                with self.subTest(session=session, actual_type=actual_type):
                    api = mock.Mock()
                    native = object.__new__(F.Native)
                    native.k = types.SimpleNamespace(GetStdHandle=lambda code: 77,
                                                    GetFileType=lambda handle: actual_type)
                    api.stdout = native.stdout
                    api.wait.side_effect = [False, True]
                    with mock.patch.object(F, "record", return_value={}), mock.patch.object(F, "request"), \
                         mock.patch.object(F, "source_identity"):
                        if actual_type == file_type:
                            self.assertEqual(F.child(api, ROOT / "request.json", 103, 104, session=session), 0)
                            api.signal.assert_called_once_with(104)
                            self.assertEqual(api.close.call_args_list, [mock.call(104), mock.call(103)])
                        else:
                            with self.assertRaises(F.FixtureError):
                                F.child(api, ROOT / "request.json", 103, 104, session=session)
                            api.signal.assert_not_called()
                            api.wait.assert_not_called()

    def test_explicit_session_child_dispatch_preserves_default_child(self):
        for mode in ("child", "session_child"):
            with mock.patch.object(F, "Native") as native, mock.patch.object(F, "plain"), \
                 mock.patch.object(F, "child", return_value=0) as child:
                path = ROOT / "request.json"
                self.assertEqual(F.main([mode, str(path), "103", "104"]), 0)
                if mode == "session_child":
                    child.assert_called_once_with(native.return_value, path, 103, 104, session=True)
                else:
                    child.assert_called_once_with(native.return_value, path, 103, 104)
        with mock.patch.object(F, "Native") as native:
            self.assertEqual(F.main(["session_child", str(ROOT / "request.json")]), 31)
            native.assert_not_called()

    def test_parent_selects_session_child_only_for_null_stdout(self):
        expected = dict(controller=dict(pid=10, created=20, image="fixed-python"), release=101, ready=102,
                        schema_version=1, nonce="a" * 32, python_sha256="b" * 64, fixture_sha256="c" * 64)
        for inherit in (False, True):
            with self.subTest(inherit=inherit):
                api = mock.Mock()
                api.PI.return_value = types.SimpleNamespace(process=None, thread=None, pid=None)
                api.open_controller.return_value, api.current.return_value = 100, -1
                api.identify.side_effect = [expected["controller"], dict(pid=11, created=21, image="fixed-python")]
                api.wait.return_value = False
                api.null.side_effect = [105, 106, 107]
                api.stdout.return_value = 99
                api.duplicate.side_effect = [103, 104, 107, 900] if inherit else [103, 104, 900]
                def create(args, handles, result):
                    result.process, result.thread, result.pid = 201, 202, 11
                api.create_child.side_effect = create
                with mock.patch.object(F, "record", return_value=expected), mock.patch.object(F, "source_identity"), \
                     mock.patch.object(F, "request", side_effect=lambda value: value), \
                     mock.patch.object(F, "transfer"), mock.patch.object(F, "publish"):
                    self.assertEqual(F.parent(api, ROOT / "request.json", inherit_stdout=inherit), 0)
                args, handles, result = api.create_child.call_args.args
                self.assertEqual(args[5], "child" if inherit else "session_child")
                self.assertEqual(handles, [105, 107, 106, 103, 104])
                if inherit:
                    api.stdout.assert_called_once_with()
                else:
                    api.stdout.assert_not_called()


class FakeLock:
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False


class FakeEvent:
    def __init__(self):
        self.flag = False
    def set(self):
        self.flag = True
    def is_set(self):
        return self.flag
    def wait(self, timeout=None):
        return self.flag


class FakeClock:
    def __init__(self):
        self.now = 0
    def monotonic(self):
        return self.now


class FakePipe:
    def __init__(self):
        self.closed, self.reads, self.closes = False, 0, 0
        self.close_error = None
    def read1(self, size):
        if self.closed:
            raise AssertionError("late read after close")
        self.reads += 1
        return b""
    def close(self):
        self.closes += 1
        if self.close_error is not None:
            raise self.close_error
        self.closed = True


class FakeProcess:
    def __init__(self, clock):
        self.clock = clock
        self.stdin, self.stdout, self.stderr = FakePipe(), FakePipe(), FakePipe()
        self.uncertain = self.finalized = False
        self.final_result, self.returncode = None, None
        self.waits, self.finalizes, self.wait_advance = [], 0, 0
        self.wait_error = None
    def mark_uncertain(self):
        self.uncertain = True
    def wait(self, timeout):
        self.waits.append(timeout)
        self.clock.now += self.wait_advance
        if self.wait_error is not None:
            raise self.wait_error
        self.returncode = 0
        return 0
    def finalize(self):
        self.finalizes += 1
        self.finalized, self.final_result = True, False
        return False


class FakeThread:
    def __init__(self, target, mode):
        self.target, self.mode = target, mode
        self.started = self.alive = self.ran = self.blocked = False
        self.starts, self.joins = 0, []
    def start(self):
        self.starts += 1
        if self.mode == "before":
            raise RuntimeError("start_failed")
        self.started = self.alive = True
        if self.mode == "after":
            raise KeyboardInterrupt("start_interrupted")
        if self.mode == "claimed":
            self.target.__self__.claimed = True
            self.blocked = True
            raise KeyboardInterrupt("claimed_start_interrupted")
        if self.mode == "completed":
            self.target()
            self.ran, self.alive = True, False
            raise KeyboardInterrupt("completed_start_interrupted")
    def join(self, timeout):
        self.joins.append(timeout)
        if not self.started:
            raise RuntimeError("cannot_join_unstarted")
        if not self.blocked and not self.ran:
            self.target()
            self.ran, self.alive = True, False
    def is_alive(self):
        return self.alive


class FakeThreads:
    Lock, Event = FakeLock, FakeEvent
    def __init__(self, index=None, mode=None, allocation=None):
        self.index, self.mode, self.allocation = index, mode, allocation
        self.threads, self.allocations = [], 0
    def Thread(self, *, target, daemon):
        if daemon is not True:
            raise AssertionError("control thread must be daemon")
        index = self.allocations
        self.allocations += 1
        if index == self.allocation:
            raise RuntimeError("allocation_failed")
        thread = FakeThread(target, self.mode if index == self.index else None)
        self.threads.append(thread)
        return thread


class PartialStartContracts(unittest.TestCase):
    def make(self, index=None, mode=None, allocation=None):
        clock, threads = FakeClock(), FakeThreads(index, mode, allocation)
        process = FakeProcess(clock)
        for name, value in (("threading", threads), ("time", clock)):
            patcher = mock.patch.object(S, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        bridge, counts = S.prepare_bridge(types.SimpleNamespace(Bridge=type("Bridge", (), {})), process, 20)
        return clock, threads, process, bridge, counts

    def test_prepare_retains_owner_without_allocating_or_starting_threads(self):
        clock, threads, process, bridge, counts = self.make()
        self.assertIs(bridge.process, process)
        self.assertEqual(bridge.deadline, 20)
        self.assertEqual(threads.allocations, 0)
        self.assertEqual(bridge.workers, [])
        self.assertEqual(counts, [None, None])
        self.assertFalse(bridge.control_started)

    def test_each_thread_allocation_failure_keeps_pipes_available_for_restoration(self):
        for index in range(3):
            with self.subTest(index=index):
                clock, threads, process, bridge, counts = self.make(allocation=index)
                with self.assertRaisesRegex(RuntimeError, "allocation_failed"):
                    S.start_bridge(bridge, counts)
                self.assertTrue(S.restore_partial_bridge(bridge, 5))
                self.assertTrue(all(pipe.closed for pipe in (process.stdin, process.stdout, process.stderr)))
                self.assertTrue(process.uncertain and process.finalized)
                self.assertFalse(process.final_result)
                self.assertTrue(all(thread.starts == 0 for thread in threads.threads))

    def test_each_prestart_failure_closes_unclaimed_pipes_without_retry(self):
        for index in range(3):
            with self.subTest(index=index):
                clock, threads, process, bridge, counts = self.make(index, "before")
                with self.assertRaisesRegex(RuntimeError, "start_failed"):
                    S.start_bridge(bridge, counts)
                self.assertFalse(S.restore_partial_bridge(bridge, 5))
                self.assertTrue(bridge.failed.is_set() and bridge.done.is_set())
                self.assertTrue(all(pipe.closed for pipe in (process.stdin, process.stdout, process.stderr)))
                self.assertEqual([thread.starts for thread in threads.threads],
                                 [1 if number <= index else 0 for number in range(3)])
                self.assertEqual(process.finalizes, 1)
                self.assertTrue(process.uncertain)
                self.assertFalse(bridge.control_started)

    def test_each_after_start_interrupt_revokes_late_target_before_pipe_close(self):
        for index in range(3):
            with self.subTest(index=index):
                clock, threads, process, bridge, counts = self.make(index, "after")
                with self.assertRaisesRegex(KeyboardInterrupt, "start_interrupted"):
                    S.start_bridge(bridge, counts)
                self.assertTrue(S.restore_partial_bridge(bridge, 5))
                self.assertTrue(bridge.workers[index].revoked and bridge.workers[index].completed)
                self.assertFalse(bridge.workers[index].claimed)
                if index < 2:
                    self.assertEqual(bridge.workers[index].pipe.reads, 0)
                self.assertTrue(all(pipe.closed for pipe in (process.stdin, process.stdout, process.stderr)))
                self.assertEqual(threads.threads[index].starts, 1)
                self.assertTrue(process.uncertain)
                self.assertFalse(process.final_result)

    def test_each_completed_start_interrupt_joins_once_without_repeating_read(self):
        for index in range(3):
            with self.subTest(index=index):
                clock, threads, process, bridge, counts = self.make(index, "completed")
                with self.assertRaisesRegex(KeyboardInterrupt, "completed_start_interrupted"):
                    S.start_bridge(bridge, counts)
                self.assertTrue(S.restore_partial_bridge(bridge, 5))
                self.assertTrue(bridge.workers[index].claimed and bridge.workers[index].completed)
                self.assertFalse(bridge.workers[index].revoked)
                self.assertEqual(len(threads.threads[index].joins), 1)
                if index < 2:
                    self.assertEqual(bridge.workers[index].pipe.reads, 1)
                self.assertFalse(process.final_result)

    def test_claimed_reader_keeps_its_pipe_when_join_does_not_prove_exit(self):
        for index in range(2):
            with self.subTest(index=index):
                clock, threads, process, bridge, counts = self.make(index, "claimed")
                with self.assertRaises(KeyboardInterrupt):
                    S.start_bridge(bridge, counts)
                self.assertFalse(S.restore_partial_bridge(bridge, 5))
                self.assertFalse(bridge.workers[index].revoked)
                self.assertEqual(bridge.workers[index].pipe.closes, 0)
                self.assertTrue(threads.threads[index].is_alive())
                self.assertTrue(process.stdin.closed)
                self.assertTrue(process.uncertain and process.finalized)
                self.assertEqual(process.finalizes, 1)

    def test_partial_restoration_uses_residual_deadline_after_parent_wait(self):
        clock, threads, process, bridge, counts = self.make(2, "after")
        with self.assertRaises(KeyboardInterrupt):
            S.start_bridge(bridge, counts)
        process.wait_advance = 4
        self.assertTrue(S.restore_partial_bridge(bridge, 5))
        self.assertEqual(process.waits, [5])
        self.assertEqual([thread.joins for thread in threads.threads], [[1], [1], [1]])
        self.assertEqual(bridge.deadline, 20)

    def test_parent_wait_failure_still_restores_independent_reader_pipes(self):
        clock, threads, process, bridge, counts = self.make(2, "after")
        with self.assertRaises(KeyboardInterrupt):
            S.start_bridge(bridge, counts)
        process.wait_error = OSError("wait_failed")
        self.assertFalse(S.restore_partial_bridge(bridge, 5))
        self.assertTrue(all(pipe.closed for pipe in (process.stdin, process.stdout, process.stderr)))
        self.assertEqual(process.finalizes, 1)
        self.assertTrue(process.uncertain)

    def test_ambiguous_pipe_close_is_not_retried_and_other_resources_continue(self):
        clock, threads, process, bridge, counts = self.make(2, "after")
        with self.assertRaises(KeyboardInterrupt):
            S.start_bridge(bridge, counts)
        process.stdout.close_error = KeyboardInterrupt("close_interrupted")
        self.assertFalse(S.restore_partial_bridge(bridge, 5))
        self.assertEqual(process.stdout.closes, 1)
        self.assertTrue(process.stdin.closed and process.stderr.closed)
        self.assertEqual(process.finalizes, 1)

    def test_successful_start_keeps_original_bridge_thread_surface(self):
        clock, threads, process, bridge, counts = self.make()
        S.start_bridge(bridge, counts)
        self.assertTrue(bridge.control_started)
        self.assertEqual(bridge.threads, threads.threads[:2])
        self.assertIs(bridge.watchdog, threads.threads[2])
        self.assertTrue(all(worker.returned for worker in bridge.workers))
        self.assertFalse(process.uncertain)
        self.assertEqual(bridge.deadline, 20)


if __name__ == "__main__":
    unittest.main()
