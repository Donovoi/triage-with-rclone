"""Metadata child lifecycle checks; all children and reader threads are fake."""
import importlib.util
import inspect
import io
import json
from pathlib import Path
import sys
import unittest
from contextlib import ExitStack
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('coverage_process_tests', ROOT / 'scripts/provider_coverage.py')
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


class Pipe(io.BytesIO):
    def __init__(self, value, role, events, close_error=None, boundary=lambda: None):
        super().__init__(value)
        self.role, self.events, self.close_error = role, events, close_error
        self.read_calls = 0
        self.close_attempts = 0
        self.boundary = boundary

    def read(self, count):
        self.boundary()
        self.read_calls += 1
        return super().read(count)

    def close(self):
        self.boundary()
        self.close_attempts += 1
        if self.closed:
            return
        self.events.append(self.role + '_close')
        super().close()
        if self.close_error is not None:
            raise self.close_error


class MetadataProcessTests(unittest.TestCase):
    def exercise(self, *, constructor_failure=None, start_failure=None,
                 kill_failure=False, wait_failure=False, close_failure=False,
                 returncode=None, alive_reader=None, primary_error=None,
                 cleanup_errors=None, emitter_error=None, formatter_error=None,
                 writer_error=None, start_mode=None, post_return_interrupt=False,
                 lock_failures=None):
        events, workers = [], []
        output = b'synthetic metadata'
        cleanup_errors = dict(cleanup_errors or {})
        if kill_failure:
            cleanup_errors['kill'] = OSError('synthetic_kill_failure')
        if wait_failure:
            cleanup_errors['wait'] = OSError('synthetic_wait_failure')
        if close_failure:
            cleanup_errors['stdout_close'] = OSError('synthetic_close_failure')
        if primary_error is None:
            primary_error = RuntimeError('synthetic_startup_failure')
        self.last_primary = primary_error
        self.last_cleanup_errors = cleanup_errors
        locks = []
        lock_failures = dict(lock_failures or {})

        class Event:
            value = False

            def set(self):
                self.value = True

            def is_set(self):
                return self.value

        class Lock:
            def __init__(self):
                self.index, self.entries, self.held = len(locks), 0, False
                locks.append(self)

            def __enter__(self):
                if self.held:
                    raise AssertionError('recursive_lock')
                self.entries += 1
                if (self.index, self.entries) in lock_failures:
                    raise lock_failures[(self.index, self.entries)]
                self.held = True
                return self

            def __exit__(self, *ignored):
                self.held = False

        def assert_unlocked():
            if any(lock.held for lock in locks):
                raise AssertionError('blocking_operation_with_ownership_lock')

        class Child:
            def __init__(self):
                self.stdout = Pipe(output, 'stdout', events, cleanup_errors.get('stdout_close'), assert_unlocked)
                self.stderr = Pipe(b'', 'stderr', events, cleanup_errors.get('stderr_close'), assert_unlocked)
                self.returncode = returncode

            def poll(self):
                return self.returncode

            def kill(self):
                assert_unlocked()
                events.append('kill')
                if 'kill' in cleanup_errors:
                    raise cleanup_errors['kill']
                self.returncode = -9

            def wait(self, timeout):
                assert_unlocked()
                self.assert_timeout(timeout)
                events.append('wait')
                if 'wait' in cleanup_errors:
                    raise cleanup_errors['wait']
                return self.returncode

            @staticmethod
            def assert_timeout(timeout):
                if timeout != 5:
                    raise AssertionError('changed_wait_budget')

        child = Child()

        class Worker:
            def __init__(self, target, args, daemon):
                self.index = len(workers)
                events.append('construct_' + str(self.index))
                if self.index == constructor_failure:
                    raise primary_error
                self.target, self.args, self.started = target, args, False
                self.target_called = False
                workers.append(self)

            def run_target(self):
                self.target_called = True
                self.target(*self.args)

            def start(self):
                events.append('start_' + str(self.index))
                if self.index == start_failure:
                    if start_mode == 'claim_then_raise':
                        self.started = True
                        self.run_target()
                    elif start_mode == 'late_raise':
                        self.started = True
                    raise primary_error
                self.started = True
                if start_mode != 'defer_success':
                    self.run_target()

            def join(self, timeout):
                assert_unlocked()
                if not self.started or timeout != 5:
                    raise AssertionError('invalid_join')
                events.append('join_' + str(self.index))
                if 'join_' + str(self.index) in cleanup_errors:
                    raise cleanup_errors['join_' + str(self.index)]
                if not self.target_called:
                    self.run_target()

            def is_alive(self):
                return self.index == alive_reader

        diagnostics = io.StringIO()

        class BrokenWriter:
            def write(self, value):
                raise writer_error

        with ExitStack() as patches:
            patches.enter_context(patch.object(C.subprocess, 'Popen', return_value=child))
            patches.enter_context(patch.object(C.threading, 'Thread', Worker))
            patches.enter_context(patch.object(C.threading, 'Event', Event))
            patches.enter_context(patch.object(C.threading, 'Lock', Lock))
            patches.enter_context(patch.object(C.time, 'sleep', side_effect=AssertionError('unexpected_sleep')))
            patches.enter_context(patch.object(C.sys, 'stderr', BrokenWriter() if writer_error is not None else diagnostics))
            if emitter_error is not None:
                patches.enter_context(patch.object(C, 'emit_metadata_process_diagnostic', side_effect=emitter_error))
            if formatter_error is not None:
                patches.enter_context(patch.object(C.json, 'dumps', side_effect=formatter_error))
            result, failure = None, None
            interrupt_count = 0
            old_trace = sys.gettrace()
            if post_return_interrupt:
                lines, first_line = inspect.getsourcelines(C.run_metadata)
                interrupt_line = first_line + next(index for index, text in enumerate(lines)
                                                   if 'reader["start_returned"] = True' in text)

                def trace(frame, event, argument):
                    nonlocal interrupt_count
                    if frame.f_code is C.run_metadata.__code__ and event == 'line' and frame.f_lineno == interrupt_line:
                        interrupt_count += 1
                        raise primary_error
                    return trace

                sys.settrace(trace)
            try:
                result = C.run_metadata(Path('synthetic-runtime'), ['version'], Path('empty.conf'), {})
            except BaseException as error:
                failure = error
            finally:
                if post_return_interrupt:
                    sys.settrace(old_trace)
        self.last_lines = diagnostics.getvalue().splitlines(keepends=True)
        self.last_diagnostics = [json.loads(line.split('=', 1)[1]) for line in self.last_lines]
        self.last_workers, self.last_locks = workers, locks
        self.last_interrupt_count = interrupt_count
        return child, events, result, failure

    def test_reader_construction_failure_reaps_child_and_closes_both_pipes(self):
        for index in (0, 1):
            with self.subTest(index=index):
                child, events, result, error = self.exercise(constructor_failure=index)
                self.assertIsInstance(error, RuntimeError)
                self.assertIsNone(result)
                self.assertEqual(events.count('kill'), 1)
                self.assertEqual(events.count('wait'), 1)
                self.assertTrue(child.stdout.closed and child.stderr.closed)
                self.assertFalse(any(event.startswith('join_') for event in events))

    def test_reader_start_failure_reaps_child_and_joins_only_started_readers(self):
        for index in (0, 1):
            with self.subTest(index=index):
                child, events, result, error = self.exercise(start_failure=index)
                self.assertIsInstance(error, RuntimeError)
                self.assertIsNone(result)
                self.assertEqual(events.count('kill'), 1)
                self.assertEqual(events.count('wait'), 1)
                self.assertTrue(child.stdout.closed and child.stderr.closed)
                self.assertEqual([event for event in events if event.startswith('join_')], [] if index == 0 else ['join_0'])
                if index == 1:
                    self.assertLess(events.index('wait'), events.index('join_0'))

    def test_failed_kill_or_wait_still_joins_reader_and_closes_unowned_pipe(self):
        for failures in ({'kill_failure': True}, {'wait_failure': True}):
            with self.subTest(failures=failures):
                child, events, result, error = self.exercise(start_failure=1, **failures)
                self.assertIs(error, self.last_primary)
                self.assertIsNone(result)
                self.assertIn('join_0', events)
                self.assertTrue(child.stdout.closed and child.stderr.closed)
                self.assertEqual(events.count('kill'), 1)

    def test_first_unowned_pipe_close_failure_does_not_skip_second_close(self):
        child, events, result, error = self.exercise(start_failure=0, close_failure=True)
        self.assertIs(error, self.last_primary)
        self.assertIsNone(result)
        self.assertTrue(child.stdout.closed and child.stderr.closed)
        self.assertEqual(events.count('stderr_close'), 1)

    def test_success_returns_same_bytes_after_wait_and_both_joins(self):
        child, events, result, error = self.exercise(returncode=0)
        self.assertIsNone(error)
        self.assertEqual(result, b'synthetic metadata')
        self.assertNotIn('kill', events)
        self.assertEqual(events.count('wait'), 1)
        self.assertEqual(events[-2:], ['join_0', 'join_1'])
        self.assertEqual(events.count('stdout_close'), 1)
        self.assertEqual(events.count('stderr_close'), 1)
        self.assertEqual((child.stdout.close_attempts, child.stderr.close_attempts), (1, 1))

    def test_failed_child_or_live_reader_cannot_return_metadata(self):
        for arguments, code in (({'returncode': 1}, 'metadata_command_failed'),
                                ({'returncode': 0, 'alive_reader': 1}, 'metadata_bound_exceeded')):
            with self.subTest(arguments=arguments):
                child, events, result, error = self.exercise(**arguments)
                self.assertIsInstance(error, C.CoverageError)
                self.assertEqual(str(error), code)
                self.assertIsNone(result)
                self.assertEqual(events[-2:], ['join_0', 'join_1'])

    def test_primary_identity_and_secondary_order_are_preserved(self):
        primary = KeyboardInterrupt('private_primary_canary')
        failures = {'kill': OSError('private_stop_canary'),
                    'join_0': RuntimeError('private_join_canary'),
                    'stderr_close': ValueError('private_close_canary')}
        child, events, result, error = self.exercise(start_failure=1, primary_error=primary,
                                                    cleanup_errors=failures)
        self.assertIs(error, primary)
        self.assertIsNone(result)
        self.assertEqual(events[-3:], ['kill', 'join_0', 'stderr_close'])
        self.assertNotIn('wait', events)
        self.assertEqual([item['stage'] for item in self.last_diagnostics],
                         ['process_stop', 'reader_join', 'unowned_pipe_close'])
        self.assertEqual([item['category'] for item in self.last_diagnostics],
                         ['os_error', 'runtime_error', 'value_error'])
        self.assertTrue(all(item['primary_failed'] for item in self.last_diagnostics))
        self.assertTrue(child.stdout.closed and child.stderr.closed)

    def test_first_cleanup_identity_and_remaining_joins_are_preserved(self):
        first = RuntimeError('private_first_join')
        second = OSError('private_second_join')
        _, events, result, error = self.exercise(returncode=0,
                                                cleanup_errors={'join_0': first, 'join_1': second})
        self.assertIs(error, first)
        self.assertIsNone(result)
        self.assertEqual(events[-2:], ['join_0', 'join_1'])
        self.assertEqual(events.count('wait'), 1)
        self.assertTrue(all(item['primary_failed'] is False for item in self.last_diagnostics))
        # The function-local first-error binding must be cleared before propagation.
        trace = error.__traceback__
        while trace is not None:
            if trace.tb_frame.f_code.co_name == 'run_metadata':
                self.assertIsNone(trace.tb_frame.f_locals['first_cleanup_error'])
            trace = trace.tb_next

    def test_both_parent_closes_attempted_once_after_primary_and_stop_failure(self):
        primary = RuntimeError('private_start')
        errors = {'kill': OSError('private_kill'), 'stdout_close': ValueError('private_stdout'),
                  'stderr_close': KeyError('private_stderr')}
        _, events, result, error = self.exercise(start_failure=0, primary_error=primary,
                                                cleanup_errors=errors)
        self.assertIs(error, primary)
        self.assertIsNone(result)
        self.assertEqual(events[-3:], ['kill', 'stdout_close', 'stderr_close'])
        self.assertEqual(events.count('kill'), 1)
        self.assertNotIn('wait', events)
        self.assertEqual([record['stage'] for record in self.last_diagnostics],
                         ['process_stop', 'unowned_pipe_close', 'unowned_pipe_close'])

    def test_emitter_format_and_writer_baseexception_cannot_mask_failures(self):
        for boundary in ('emitter_error', 'formatter_error', 'writer_error'):
            for primary in (True, False):
                with self.subTest(boundary=boundary, primary=primary):
                    original = RuntimeError('private_original')
                    options = {boundary: SystemExit('private_diagnostic_failure')}
                    if primary:
                        options.update(start_failure=1, primary_error=original,
                                       cleanup_errors={'join_0': OSError('secondary')})
                    else:
                        options.update(returncode=0, cleanup_errors={'join_0': original})
                    _, events, result, error = self.exercise(**options)
                    self.assertIs(error, original)
                    self.assertIsNone(result)
                    self.assertIn('join_0', events)
                    self.assertIn('stderr_close' if primary else 'join_1', events)

    def test_active_caller_exception_does_not_become_function_primary(self):
        first = OSError('private_cleanup')
        try:
            raise ValueError('private_caller')
        except ValueError:
            _, _, _, error = self.exercise(returncode=0, cleanup_errors={'join_0': first})
        self.assertIs(error, first)
        self.assertEqual(self.last_diagnostics[0]['primary_failed'], False)

    def test_diagnostic_closed_schema_byte_bound_and_unknown_category(self):
        class PrivateFailure(BaseException):
            def __str__(self):
                raise AssertionError('exception_text_must_not_be_read')

        _, _, _, error = self.exercise(start_failure=0,
                                      cleanup_errors={'kill': PrivateFailure(),
                                                      'stdout_close': OSError('secret'),
                                                      'stderr_close': KeyError('secret')})
        self.assertIs(error, self.last_primary)
        self.assertLessEqual(len(self.last_lines), 5)
        for line, record in zip(self.last_lines, self.last_diagnostics):
            self.assertTrue(line.startswith('provider_metadata_process_diagnostic='))
            self.assertLessEqual(len(line.encode('ascii')), 256)
            self.assertNotIn('secret', line)
            self.assertEqual(set(record), {'schema_version', 'stage', 'category', 'primary_failed', 'attempt'})
            self.assertEqual(record['schema_version'], 1)
            self.assertEqual(record['attempt'], 1)
            self.assertIs(type(record['primary_failed']), bool)
        self.assertEqual(self.last_diagnostics[0]['category'], 'unknown')
        for stage, flag in (('private_stage', True), ('reader_join', 1)):
            with patch.object(C.sys, 'stderr', io.StringIO()) as stream:
                C.emit_metadata_process_diagnostic(stage, RuntimeError('secret'), flag)
                self.assertEqual(stream.getvalue(), '')

    def test_success_has_no_cleanup_diagnostic(self):
        _, _, result, error = self.exercise(returncode=0)
        self.assertIsNone(error)
        self.assertEqual(result, b'synthetic metadata')
        self.assertEqual(self.last_lines, [])

    def test_late_unclaimed_target_after_failed_start_never_touches_pipe(self):
        primary = KeyboardInterrupt('private_start_interrupted')
        child, events, result, error = self.exercise(start_failure=0, start_mode='late_raise',
                                                    primary_error=primary)
        self.assertIs(error, primary)
        self.assertIsNone(result)
        self.assertEqual(events[-3:], ['wait', 'stdout_close', 'stderr_close'])
        reader = self.last_workers[0].args[0]
        self.assertTrue(reader['revoked'])
        self.assertFalse(reader['claimed'])
        before = (child.stdout.read_calls, events[:])
        self.last_workers[0].run_target()
        self.assertEqual((child.stdout.read_calls, events), before)
        self.assertNotIn('join_0', events)

    def test_claimed_target_before_failed_start_return_is_joined_not_revoked(self):
        primary = KeyboardInterrupt('private_claimed_start_interrupted')
        child, events, result, error = self.exercise(start_failure=0, start_mode='claim_then_raise',
                                                    primary_error=primary)
        self.assertIs(error, primary)
        self.assertIsNone(result)
        reader = self.last_workers[0].args[0]
        self.assertTrue(reader['claimed'])
        self.assertFalse(reader['revoked'] or reader['start_returned'])
        self.assertEqual(events.count('join_0'), 1)
        self.assertEqual(events.count('stdout_close'), 1)
        self.assertEqual(child.stdout.close_attempts, 1)
        self.assertLess(events.index('stdout_close'), events.index('kill'))
        self.assertTrue(child.stderr.closed)

    def test_returned_start_before_claim_joins_and_drains_both_readers(self):
        child, events, result, error = self.exercise(returncode=0, start_mode='defer_success')
        self.assertIsNone(error)
        self.assertEqual(result, b'synthetic metadata')
        for index, worker in enumerate(self.last_workers):
            reader = worker.args[0]
            self.assertTrue(reader['start_returned'] and reader['claimed'])
            self.assertFalse(reader['revoked'])
            self.assertLess(events.index('join_' + str(index)), events.index(('stdout' if index == 0 else 'stderr') + '_close'))
        self.assertTrue(child.stdout.closed and child.stderr.closed)

    def test_interrupt_after_start_returns_before_flag_revokes_pending_target(self):
        primary = KeyboardInterrupt('private_post_return_interrupted')
        child, events, result, error = self.exercise(start_mode='defer_success',
                                                    post_return_interrupt=True, primary_error=primary)
        self.assertIs(error, primary)
        self.assertIsNone(result)
        self.assertEqual(self.last_interrupt_count, 1)
        self.assertTrue(self.last_workers[0].started)
        self.assertFalse(self.last_workers[0].args[0]['start_returned'])
        self.assertTrue(all(worker.args[0]['revoked'] for worker in self.last_workers))
        self.assertFalse(any(event.startswith('join_') for event in events))
        before = (child.stdout.read_calls, events[:])
        self.last_workers[0].run_target()
        self.assertEqual((child.stdout.read_calls, events), before)

    def test_constructor_phase_finishes_before_any_start_and_owns_known_pipes(self):
        for index in (0, 1):
            with self.subTest(index=index):
                child, events, result, error = self.exercise(constructor_failure=index)
                self.assertIs(error, self.last_primary)
                self.assertIsNone(result)
                self.assertEqual(len(self.last_locks), 2)
                self.assertFalse(any(event.startswith('start_') for event in events))
                self.assertTrue(child.stdout.closed and child.stderr.closed)
        _, events, _, _ = self.exercise(returncode=0)
        self.assertLess(events.index('construct_1'), events.index('start_0'))

    def test_failed_ownership_observation_never_guesses_parent_close(self):
        primary = RuntimeError('private_start')
        lock_error = OSError('private_lock')
        child, events, result, error = self.exercise(start_failure=0, primary_error=primary,
                                                    lock_failures={(0, 1): lock_error})
        self.assertIs(error, primary)
        self.assertIsNone(result)
        self.assertFalse(child.stdout.closed)
        self.assertTrue(child.stderr.closed)
        self.assertNotIn('stdout_close', events)
        self.assertNotIn('join_0', events)
        self.assertEqual(self.last_diagnostics, [{'schema_version': 1, 'stage': 'reader_ownership',
                                                'category': 'os_error', 'primary_failed': True, 'attempt': 1}])
        # This is fake in-memory test cleanup, not an operational ownership guess.
        child.stdout.close()

    def test_target_claim_failure_is_fatal_without_read_or_parent_close(self):
        child, events, result, error = self.exercise(returncode=0,
                                                    lock_failures={(0, 1): OSError('private_claim')})
        self.assertIsInstance(error, RuntimeError)
        self.assertEqual(str(error), 'metadata_reader_ownership_unverified')
        self.assertIsNone(result)
        self.assertFalse(child.stdout.closed)
        self.assertEqual(child.stdout.read_calls, 0)
        self.assertNotIn('join_0', events)
        self.assertIn('join_1', events)
        self.assertEqual(self.last_diagnostics[0]['stage'], 'reader_ownership')
        self.assertFalse(self.last_diagnostics[0]['primary_failed'])
        child.stdout.close()


if __name__ == '__main__':
    unittest.main()
