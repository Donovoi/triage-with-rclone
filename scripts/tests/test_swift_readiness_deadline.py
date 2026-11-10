"""Exercise real transport methods with fake owners; no native import or execution."""
import ast
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
        self.timing = Mock()
        actions = frozenset({'invalid','ready','close_ready','start','poll','observe_runtime','ctrl_c','finish','close'})
        def ready(value):
            need(value == dict(schema_version=1, action='ready', ok=True, state='ready'), 'session_failed')
            return value
        env = dict(__name__='pure_deadline_transport', time=self.time, threading=threading, queue=queue,
            ProducerError=self.error, need=need, BRIDGE_ACTIONS=actions, _ReadyTiming=lambda origin: self.timing,
            environment=self.environment, private_file=self.private, _BridgeWorker=Worker,
            O=types.SimpleNamespace(spawn=self.spawn), powershell=lambda: 'owned-powershell',
            HERE=Path('owned-source'), subprocess=types.SimpleNamespace(PIPE=-1), hidden=lambda: {},
            E=types.SimpleNamespace(compact=lambda v: json.dumps(v, sort_keys=True, separators=(',',':')).encode()),
            strict_json=lambda raw, limit: json.loads(raw), validate_ready=ready,
            validate_close_ready=lambda value: value, bridge_stage=lambda raw: None,
            session_diagnostic=Mock(), session_failure_diagnostic=Mock(), validate_session=lambda value, action: value)
        selected_classes('run_windows_http.py', ('Bridge',), env)
        self.H = types.SimpleNamespace(Bridge=env['Bridge'], BRIDGE_ACTIONS=actions,
            ProducerError=self.error, need=need, hosted_guard=Mock())
        controller = dict(__name__='pure_deadline_source', H=self.H)
        selected_classes('filesystem_controller.py', ('SourceBridge','ObservedSourceBridge'), controller)
        self.C = types.SimpleNamespace(SourceBridge=controller['SourceBridge'], ObservedSourceBridge=controller['ObservedSourceBridge'])
        swift = dict(__name__='pure_deadline_swift', C=self.C, time=self.time, need=need)
        selected_classes('run_windows_swift.py', ('SwiftReadyBridge',), swift)
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
