"""Exercise real transport methods with fake owners; no native import or execution."""
import ast
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import queue
import threading
import types
import unittest
from unittest.mock import Mock

LAB = Path(__file__).resolve().parents[1] / 'application-lab'


def selected_classes(filename, names, namespace):
    path = LAB / filename
    tree = ast.parse(path.read_bytes(), filename=str(path))
    nodes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name in names]
    if [node.name for node in nodes] != list(names):
        raise AssertionError('class_inventory')
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), namespace)


def selected_timing(namespace):
    path = LAB / 'run_windows_http.py'
    tree = ast.parse(path.read_bytes(), filename=str(path))
    constants = {'BRIDGE_PHASES', 'BRIDGE_OUTCOMES', 'READY_TIMING_FIELDS'}
    definitions = {'bridge_stage', 'ready_timing_projection', '_ReadyTiming'}
    nodes, found = [], set()
    for node in tree.body:
        name = (node.targets[0].id if isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) else
                node.name if isinstance(node, (ast.FunctionDef, ast.ClassDef)) else None)
        if name in constants | definitions:
            nodes.append(node)
            found.add(name)
    if found != constants | definitions or len(nodes) != len(found):
        raise AssertionError('timing_definition_inventory')
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), namespace)


class DeadlineTests(unittest.TestCase):
    def setUp(self):
        self.clock = types.SimpleNamespace(now=0.0)
        self.time = types.SimpleNamespace(monotonic=lambda: self.clock.now)
        self.error = type('ProducerError', (RuntimeError,), {})
        def need(value, code):
            if not value:
                raise self.error(code)
        self.need = need
        self.process = Mock(returncode=None)
        self.process.poll.return_value = None
        self.spawn = Mock(return_value=self.process)
        self.private = Mock(side_effect=lambda *args: io.BytesIO())
        self.environment = Mock(return_value={})
        self.started_deadlines = []
        starts = self.started_deadlines
        class Worker:
            def __init__(self, bridge, stream=None, name=None, log=None):
                self.bridge, self.name = bridge, name
                self.thread = Mock()
            def start(self):
                starts.append(self.bridge.deadline)
        actions = frozenset({'invalid','ready','close_ready','start','poll','observe_runtime','ctrl_c','finish','close'})
        def ready(value):
            need(value == dict(schema_version=1, action='ready', ok=True, state='ready'), 'session_failed')
            return value
        env = dict(__name__='pure_deadline_transport', time=self.time, threading=threading, queue=queue,
            ProducerError=self.error, need=need, BRIDGE_ACTIONS=actions,
            environment=self.environment, private_file=self.private, _BridgeWorker=Worker,
            O=types.SimpleNamespace(spawn=self.spawn), powershell=lambda: 'owned-powershell',
            HERE=Path('owned-source'), subprocess=types.SimpleNamespace(PIPE=-1), hidden=lambda: {},
            E=types.SimpleNamespace(compact=lambda v: json.dumps(v, sort_keys=True, separators=(',',':')).encode()),
            strict_json=lambda raw, limit: json.loads(raw), validate_ready=ready,
            validate_close_ready=lambda value: value,
            session_diagnostic=Mock(), session_failure_diagnostic=Mock(), validate_session=lambda value, action: value)
        selected_timing(env)
        selected_classes('run_windows_http.py', ('Bridge',), env)
        self.H = types.SimpleNamespace(Bridge=env['Bridge'], BRIDGE_ACTIONS=actions,
            ProducerError=self.error, need=need, hosted_guard=Mock(),
            _ReadyTiming=env['_ReadyTiming'], ready_timing_projection=env['ready_timing_projection'],
            READY_TIMING_FIELDS=env['READY_TIMING_FIELDS'])
        controller = dict(__name__='pure_deadline_source', H=self.H)
        selected_classes('filesystem_controller.py', ('SourceBridge','ObservedSourceBridge'), controller)
        self.C = types.SimpleNamespace(SourceBridge=controller['SourceBridge'], ObservedSourceBridge=controller['ObservedSourceBridge'])
        swift = dict(__name__='pure_deadline_swift', H=self.H, C=self.C, time=self.time, need=need)
        selected_classes('run_windows_swift.py', ('SwiftReadyTiming', 'SwiftReadyBridge'), swift)
        self.Swift = swift['SwiftReadyBridge']

    def make(self, cls, **kwargs):
        bridge = cls.__new__(cls)
        expected = kwargs.get('deadline', self.clock.now + 165)
        def spawn(*args, **fields):
            self.assertEqual(bridge.deadline, expected)
            return self.process
        self.spawn.side_effect = spawn
        cls.__init__(bridge, Path('owned-case'), **kwargs)
        return bridge

    def replies_after(self, bridge, delay, payload=None):
        bridge.messages = Mock()
        bridge.messages.empty.return_value = True
        bridge.waits = []
        def receive(*, timeout):
            bridge.waits.append(timeout)
            if delay > timeout:
                self.clock.now += timeout
                raise queue.Empty()
            self.clock.now += delay
            bridge.responses = bridge.calls
            value = payload if payload is not None else dict(schema_version=1, action='ready', ok=True, state='ready')
            return json.dumps(value).encode()
        bridge.messages.get.side_effect = receive

    def test_ordinary_helper_keeps_90_second_ready_and_165_second_lifetime(self):
        bridge = self.make(self.H.Bridge)
        self.assertEqual(bridge.deadline, 165)
        self.assertEqual(self.started_deadlines, [165,165,165])
        self.replies_after(bridge, 1)
        bridge.command('ready')
        self.assertEqual(bridge.waits, [90])
        self.assertTrue(bridge.ready)

    def test_default_observer_preserves_existing_constructor_and_guard(self):
        bridge = self.make(self.C.ObservedSourceBridge)
        self.H.hosted_guard.assert_called_once_with()
        self.assertFalse(bridge.observer_started)
        self.assertEqual(bridge.ready_wait_seconds, 90)
        self.assertEqual(bridge.deadline, 165)

    def test_case_deadline_is_installed_before_helper_launch_and_all_workers(self):
        bridge = self.make(self.Swift, deadline=120)
        self.assertEqual(self.started_deadlines, [120,120,120])
        self.spawn.assert_called_once()
        self.H.hosted_guard.assert_called_once_with()
        self.assertEqual(bridge.deadline, 120)

    def test_reply_after_old_ready_cap_can_pass_within_original_case_budget(self):
        bridge = self.make(self.Swift, deadline=120)
        self.clock.now = 20
        self.replies_after(bridge, 92)
        bridge.command('ready')
        self.assertEqual(bridge.waits, [100])
        self.assertEqual(self.clock.now, 112)
        self.assertTrue(bridge.ready)
        self.assertFalse(bridge.failed.is_set())
        self.assertEqual(bridge.calls, 1)

    def test_default_policy_remains_a_negative_control_for_late_reply(self):
        bridge = self.make(self.C.ObservedSourceBridge, deadline=120)
        self.clock.now = 20
        self.replies_after(bridge, 92)
        with self.assertRaisesRegex(self.error, '^session_failed$'):
            bridge.command('ready')
        self.assertEqual(bridge.waits, [90])
        self.assertTrue(bridge.failed.is_set())
        self.assertFalse(bridge.ready)

    def test_case_deadline_caps_ready_wait_even_below_90_seconds(self):
        bridge = self.make(self.Swift, deadline=120)
        self.clock.now = 45
        self.replies_after(bridge, 76)
        with self.assertRaises(self.error):
            bridge.command('ready')
        self.assertEqual(bridge.waits, [75])
        self.assertEqual(self.clock.now, 120)
        self.assertFalse(bridge.ready)
        self.assertTrue(bridge.failed.is_set())

    def test_timeout_does_not_retry_or_accept_a_later_ready_reply(self):
        bridge = self.make(self.Swift, deadline=120)
        self.clock.now = 119
        self.replies_after(bridge, 2)
        with self.assertRaises(self.error):
            bridge.command('ready')
        with self.assertRaises(self.error):
            bridge.command('ready')
        self.assertEqual(bridge.waits, [1])
        self.assertEqual(bridge.calls, 1)
        self.assertEqual(self.process.stdin.write.call_count, 1)

    def test_later_commands_keep_their_35_second_cap(self):
        bridge = self.make(self.Swift, deadline=120)
        self.replies_after(bridge, 1)
        bridge.command('ready')
        bridge.observer_started = True
        self.replies_after(bridge, 36)
        with self.assertRaises(self.error):
            bridge.command('poll')
        self.assertEqual(bridge.waits, [35])
        self.assertTrue(bridge.failed.is_set())

    def test_later_commands_cannot_extend_the_case_deadline(self):
        bridge = self.make(self.Swift, deadline=120)
        self.replies_after(bridge, 1)
        bridge.command('ready')
        bridge.observer_started = True
        self.clock.now = 110
        self.replies_after(bridge, 11)
        with self.assertRaises(self.error):
            bridge.command('poll')
        self.assertEqual(bridge.waits, [10])
        self.assertEqual(self.clock.now, 120)

    def test_invalid_base_deadlines_refuse_before_files_or_process_launch(self):
        for deadline in (True,False,0,-1,166,float('nan'),float('inf'),float('-inf'),'120'):
            with self.subTest(deadline=deadline), self.assertRaises(self.error):
                self.H.Bridge(Path('unused'), deadline=deadline)
        self.spawn.assert_not_called()
        self.private.assert_not_called()
        self.environment.assert_not_called()
        self.assertEqual(self.started_deadlines, [])

    def test_swift_cannot_request_a_case_longer_than_120_seconds(self):
        for deadline in (121,165,True,0,float('nan'),float('inf')):
            with self.subTest(deadline=deadline), self.assertRaises(self.error):
                self.Swift(Path('unused'), deadline=deadline)
        self.spawn.assert_not_called()
        self.private.assert_not_called()
        self.H.hosted_guard.assert_not_called()

    def test_expired_case_refuses_before_helper_launch(self):
        self.clock.now = 120
        with self.assertRaises(self.error):
            self.Swift(Path('unused'), deadline=120)
        self.spawn.assert_not_called()
        self.private.assert_not_called()

    def test_hosted_guard_still_precedes_base_constructor_with_deadline(self):
        self.H.hosted_guard.side_effect = self.error('hosted_only')
        with self.assertRaisesRegex(self.error, 'hosted_only'):
            self.Swift(Path('unused'), deadline=120)
        self.spawn.assert_not_called()
        self.private.assert_not_called()
        self.environment.assert_not_called()

    def test_late_reply_still_requires_the_original_ready_contract(self):
        bridge = self.make(self.Swift, deadline=120)
        self.clock.now = 20
        self.replies_after(bridge, 92, dict(schema_version=1, action='ready', ok=False, state='ready'))
        with self.assertRaises(self.error):
            bridge.command('ready')
        self.assertFalse(bridge.ready)
        self.assertTrue(bridge.failed.is_set())
        self.assertEqual(bridge.waits, [100])

    def test_host_budget_is_absolute_not_restarted_at_ready(self):
        self.clock.now = 30
        bridge = self.make(self.Swift, deadline=120)
        self.assertEqual(bridge.deadline, 120)
        self.clock.now = 80
        self.replies_after(bridge, 1)
        bridge.command('ready')
        self.assertEqual(bridge.waits, [40])
        self.assertEqual(bridge.deadline, 120)

    def mark_compile(self, bridge, compiled=False):
        raw = b'application_bridge_stage=compile\n'
        if compiled:
            raw += b'application_bridge_stage=compiled\n'
        bridge.stage_bytes[:] = raw
        bridge.ready_timing.stage(raw, False)

    def recorded_ready_failure(self, bridge):
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaisesRegex(self.error, '^session_failed$'):
            bridge.command('ready')
        lines = [line for line in output.getvalue().splitlines()
                 if line.startswith('application_helper_ready_timing=')]
        self.assertEqual(len(lines), 1)
        self.assertLess(len(lines[0]), 1024)
        value = json.loads(lines[0].split('=', 1)[1])
        self.assertEqual(set(value), {'schema_version', 'clock', 'action', 'phase', 'outcome',
                                     'status', *self.H.READY_TIMING_FIELDS})
        self.assertFalse(bridge.ready)
        self.assertTrue(bridge.failed.is_set())
        return value

    def test_extended_timeout_keeps_real_compile_marker_and_remaining_budget(self):
        bridge = self.make(self.Swift, deadline=120)
        self.assertIsInstance(bridge.ready_timing, self.H._ReadyTiming)
        self.clock.now = 1
        self.mark_compile(bridge)
        self.clock.now = 20
        self.replies_after(bridge, 101)
        value = self.recorded_ready_failure(bridge)
        self.assertEqual(value, dict(schema_version=1, clock='parent_monotonic', action='ready',
            phase='wait', outcome='timeout', status='observed', compile_seen_ms=1000,
            compiled_seen_ms=None, write_returned_ms=20000, wait_started_ms=20000,
            wait_budget_ms=100000, failure_seen_ms=120000))
        self.assertEqual(bridge.calls, 1)

    def test_malformed_late_reply_keeps_real_compiled_marker(self):
        bridge = self.make(self.Swift, deadline=120)
        self.clock.now = 1
        self.mark_compile(bridge)
        self.clock.now = 20
        self.replies_after(bridge, 92)
        def malformed(*, timeout):
            bridge.waits.append(timeout)
            self.clock.now = 95
            self.mark_compile(bridge, compiled=True)
            self.clock.now = 112
            bridge.responses = bridge.calls
            return json.dumps(dict(schema_version=1, action='ready', ok=False, state='ready')).encode()
        bridge.messages.get.side_effect = malformed
        value = self.recorded_ready_failure(bridge)
        self.assertEqual(value['status'], 'observed')
        self.assertEqual((value['phase'], value['outcome']), ('reply', 'protocol_failed'))
        self.assertEqual(value['compile_seen_ms'], 1000)
        self.assertEqual(value['compiled_seen_ms'], 95000)
        self.assertEqual(value['wait_budget_ms'], 100000)
        self.assertEqual(value['failure_seen_ms'], 112000)

    def test_full_120_second_wait_is_projected_without_acceptance(self):
        bridge = self.make(self.Swift, deadline=120)
        self.mark_compile(bridge)
        self.replies_after(bridge, 121)
        value = self.recorded_ready_failure(bridge)
        self.assertEqual(value['status'], 'observed')
        self.assertEqual(value['compile_seen_ms'], 0)
        self.assertEqual(value['wait_budget_ms'], 120000)
        self.assertEqual(value['failure_seen_ms'], 120000)

    def test_default_timing_policy_still_rejects_budgets_above_90(self):
        snapshot = (0, 1, None, 20, 20, 100, 120)
        value = self.H.ready_timing_projection(snapshot, 'wait', 'timeout')
        self.assertEqual(value['status'], 'unavailable')
        self.assertTrue(all(value[k] is None for k in self.H.READY_TIMING_FIELDS))
        self.assertEqual(self.H._ReadyTiming.wait_limit_seconds, 90)

    def test_swift_projection_rejects_budgets_beyond_its_fixed_policy(self):
        for budget in (120.001, 165, True, float('nan'), float('inf'), '100'):
            with self.subTest(budget=budget):
                value = self.H.ready_timing_projection((0, 1, None, 20, 20, budget, 200),
                    'wait', 'timeout', wait_limit_seconds=120)
                self.assertEqual(value['status'], 'unavailable')
                self.assertTrue(all(value[k] is None for k in self.H.READY_TIMING_FIELDS))

    def test_timing_policy_selector_is_closed(self):
        for limit in (True, False, 90.0, 120.0, 91, 121, 165, None, '120'):
            with self.subTest(limit=limit), self.assertRaises(self.error):
                self.H.ready_timing_projection((0, 1, None, 20, 20, 100, 120),
                    'wait', 'timeout', wait_limit_seconds=limit)

    def test_swift_invalid_marker_stays_unavailable_with_long_budget(self):
        bridge = self.make(self.Swift, deadline=120)
        self.clock.now = 1
        self.mark_compile(bridge)
        bridge.stage_bytes[:] = b'application_bridge_stage=compile\nprivate-extra\n'
        bridge.ready_timing.stage(bytes(bridge.stage_bytes), False)
        self.clock.now = 20
        self.replies_after(bridge, 101)
        value = self.recorded_ready_failure(bridge)
        self.assertEqual(value['status'], 'unavailable')
        self.assertTrue(all(value[k] is None for k in self.H.READY_TIMING_FIELDS))
        self.assertNotIn('private-extra', json.dumps(value))

    def test_swift_failure_snapshot_is_frozen_before_cleanup_markers(self):
        bridge = self.make(self.Swift, deadline=120)
        self.clock.now = 1
        self.mark_compile(bridge)
        self.clock.now = 20
        self.replies_after(bridge, 101)
        value = self.recorded_ready_failure(bridge)
        frozen = bridge.ready_timing.snapshot
        self.clock.now = 121
        self.mark_compile(bridge, compiled=True)
        later = io.StringIO()
        with redirect_stdout(later):
            bridge.ready_timing.failure(bytes(bridge.stage_bytes), False, 'wait', 'timeout')
        self.assertEqual(later.getvalue(), '')
        self.assertEqual(bridge.ready_timing.snapshot, frozen)
        self.assertIsNone(value['compiled_seen_ms'])
