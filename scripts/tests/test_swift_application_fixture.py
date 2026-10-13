"""Pure Swift state and fake transport tests; prohibited boundaries guarded."""
import hashlib
import io
import json
from pathlib import Path
import socket
import subprocess
import threading
import types
import unittest
from unittest.mock import Mock, patch

PATH = Path(__file__).resolve().parents[1] / "application-lab/fixture_swift.py"
F = types.ModuleType("swift_fixture_test"); F.__file__ = str(PATH)
with patch.object(subprocess, "Popen", side_effect=AssertionError("forbidden")), patch.object(socket, "socket", side_effect=AssertionError("forbidden")), patch.object(threading.Thread, "start", side_effect=AssertionError("forbidden")):
    exec(compile(PATH.read_bytes(), str(PATH), "exec"), F.__dict__)
USER, KEY = "a" * 64, "b" * 64
ORIGIN = "http://127.0.0.1:1234"


def complete(state, method, path, token=None):
    request = state.begin(method, path, USER if path == F.AUTH else None, KEY if path == F.AUTH else None, token)
    if request[2] is not None:
        state.release_gate(request[2])
    result = state.response(request, ORIGIN)
    state.commit(request, result[0], 256 + len(result[1]), result[3])
    return request[3], result


def metadata(state):
    stat, _ = complete(state, "GET", F.AUTH)
    complete(state, "HEAD", F.OBJECT, stat)
    copy, _ = complete(state, "GET", F.AUTH)
    complete(state, "HEAD", F.OBJECT, copy)
    return stat, copy


class FakeDispatchLock:
    """Cooperative scheduler seam; never starts or waits on a thread."""
    def __init__(self, held=False, on_wait=None, on_acquired=None, on_release=None):
        self.held, self.on_wait = held, on_wait
        self.on_acquired, self.on_release = on_acquired, on_release
        self.timeouts, self.releases = [], 0

    def acquire(self, *, timeout):
        self.timeouts.append(timeout)
        if self.held:
            if self.on_wait: self.on_wait()
            return False
        self.held = True
        if self.on_acquired: self.on_acquired()
        return True

    def release(self):
        if not self.held: raise AssertionError("unowned release")
        if self.on_release: self.on_release()
        self.held = False
        self.releases += 1


def worker_server(state, fields):
    server = F._Server.__new__(F._Server)
    server.state, server.endpoint = state, ORIGIN + "/"
    server.lock, server.stopping = threading.RLock(), threading.Event()
    server.deadline = 180.0
    server._dispatch_lock = FakeDispatchLock()
    sock = Mock(); sock.fileno.return_value = 1
    server.sockets = {sock: 15.0}
    server._parse, server._close_socket = Mock(return_value=fields), Mock()
    sock.makefile.return_value.__enter__ = Mock(return_value=io.BytesIO())
    sock.makefile.return_value.__exit__ = Mock(return_value=False)
    return server, sock


class FixtureTests(unittest.TestCase):
    def setUp(self):
        for obj, name in ((subprocess, "Popen"), (socket, "socket"), (socket, "create_connection"), (threading.Thread, "start")):
            p = patch.object(obj, name, side_effect=AssertionError("forbidden")); p.start(); self.addCleanup(p.stop)

    def test_independent_literal_oracle(self):
        literal = b"Synthetic provider protocol fixture. No account or user data.\n"
        self.assertEqual((len(literal), hashlib.sha256(literal).hexdigest(), hashlib.md5(literal).hexdigest()),
            (62, "1e901527b93ae84dc9d95a8aa76bbc12d7d77dbf8ab449333c172cfc909c639e", "f9ac90560b9929242009ee0c24c9e5d8"))
        self.assertEqual(F.BODY, literal)

    def test_positive_and_denied_reauth_have_distinct_two_gate_paths(self):
        for name in F.CASES:
            s = F.AppSwiftState(name, USER, KEY)
            stat, copy = metadata(s)
            request = s.begin("GET", F.OBJECT, token=copy)
            with self.assertRaises(F.FixtureError): s.response(request, ORIGIN)
            s.release_gate("first_get")
            result = s.response(request, ORIGIN)
            self.assertEqual(result, (401, b"", {}, 0))
            self.assertFalse(s.injected)
            s.commit(request, 401, 100, 0)
            self.assertTrue(s.injected)
            if name == "renewal_denial":
                request = s.begin("GET", F.AUTH, USER, KEY)
                self.assertEqual(request[:3], ("deny", "copy_initial", "renewal_auth"))
                self.assertFalse(s.denied)
                with self.assertRaises(F.FixtureError): s.response(request, ORIGIN)
                s.release_gate("renewal_auth")
                self.assertEqual(s.response(request, ORIGIN), (403, b"", {}, 0))
                s.commit(request, 403, 100, 0)
                self.assertEqual((len(s.tokens), s.requests, s.payload_bytes), (2, 6, 0))
            else:
                replacement, _ = complete(s, "GET", F.AUTH)
                self.assertNotIn(replacement, (stat, copy))
                _, result = complete(s, "GET", F.OBJECT, replacement)
                self.assertEqual(result[1], F.BODY)
                self.assertEqual((s.requests, s.payload_bytes), (7, 62))
            serialized = json.dumps(s.snapshot())
            for secret in (USER, KEY, stat, copy, ORIGIN, *s.tokens): self.assertNotIn(secret, serialized)
            with self.assertRaises(F.FixtureError): s.begin("GET", F.AUTH, USER, KEY)

    def test_real_model_trace_replays_in_independent_validator_with_metadata_repeats(self):
        path = PATH.parents[1] / "swift_application_evidence.py"
        evidence = types.ModuleType("swift_independent_replay"); evidence.__file__ = str(path)
        exec(compile(path.read_bytes(), str(path), "exec"), evidence.__dict__)
        for name in F.CASES:
            for repeats in (0, 3):
                s = F.AppSwiftState(name, USER, KEY); _, copy = metadata(s)
                for _ in range(repeats): complete(s, "HEAD", F.OBJECT, copy)
                complete(s, "GET", F.OBJECT, copy)
                token, _ = complete(s, "GET", F.AUTH)
                if name == "token_replacement":
                    for _ in range(repeats): complete(s, "HEAD", F.OBJECT, token)
                    complete(s, "GET", F.OBJECT, token)
                evidence.fixture_observation(s.snapshot(), name, successful=True)

    def test_stat_cannot_be_copy_or_reused_after_copy_grant(self):
        s = F.AppSwiftState("token_replacement", USER, KEY)
        stat, _ = complete(s, "GET", F.AUTH)
        with self.assertRaises(F.FixtureError): s.begin("GET", F.OBJECT, token=stat)
        with self.assertRaises(F.FixtureError): s.begin("GET", F.AUTH, USER, KEY)
        complete(s, "HEAD", F.OBJECT, stat)
        copy, _ = complete(s, "GET", F.AUTH)
        for method, token in (("HEAD", stat), ("GET", stat), ("GET", copy)):
            with self.assertRaises(F.FixtureError): s.begin(method, F.OBJECT, token=token)

    def test_old_tokens_extra_grant_and_duplicate_replacement_rejected(self):
        s = F.AppSwiftState("token_replacement", USER, KEY); stat, copy = metadata(s)
        with self.assertRaises(F.FixtureError): s.begin("GET", F.AUTH, USER, KEY)
        complete(s, "GET", F.OBJECT, copy)
        for token in (stat, copy, "canary"):
            with self.assertRaises(F.FixtureError): s.begin("GET", F.OBJECT, token=token)
        with patch.object(F.secrets, "token_hex", return_value=copy.removeprefix("synthetic-")):
            with self.assertRaises(F.FixtureError): s.begin("GET", F.AUTH, USER, KEY)

    def test_pending_response_and_commit_identity_are_once_only(self):
        s = F.AppSwiftState("token_replacement", USER, KEY)
        request = s.begin("GET", F.AUTH, USER, KEY)
        with self.assertRaises(F.FixtureError): s.begin("GET", F.AUTH, USER, KEY)
        with self.assertRaises(F.FixtureError): s.commit(request, 200, 100, 0)
        s.response(request, ORIGIN)
        for status, sent, payload in ((True, 100, 0), (403, 100, 0), (200, True, 0), (200, 0, 0), (200, 4097, 0), (200, 100, True)):
            with self.assertRaises(F.FixtureError): s.commit(request, status, sent, payload)
        with self.assertRaises(F.FixtureError): s.commit(tuple(list(request)), 200, 100, 0)
        s.commit(request, 200, 100, 0)
        with self.assertRaises(F.FixtureError): s.commit(request, 200, 100, 0)

    def test_metadata_repeat_cap_and_teardown_gate_are_not_credit(self):
        s = F.AppSwiftState("token_replacement", USER, KEY); _, copy = metadata(s)
        for _ in range(3): complete(s, "HEAD", F.OBJECT, copy)
        with self.assertRaises(F.FixtureError): s.begin("HEAD", F.OBJECT, token=copy)
        request = s.begin("GET", F.OBJECT, token=copy); s.release_observation()
        self.assertFalse(s.gates["first_get"]["released"])
        with self.assertRaises(F.FixtureError): s.response(request, ORIGIN)
        for gate in ("replacement_get", "renewal_auth", "canary"):
            with self.assertRaises(F.FixtureError): s.release_gate(gate)

    def test_budget_source_and_private_errors_fail_closed(self):
        s = F.AppSwiftState("token_replacement", USER, KEY); s.requests = 128
        for _ in range(3):
            with self.assertRaises(F.FixtureError): s.begin("GET", F.AUTH, USER, KEY)
        self.assertEqual(s.requests, 128)
        s._error("private canary"); self.assertNotIn("private canary", json.dumps(s.snapshot()))
        t = F.AppSwiftState("token_replacement", USER, KEY); t._body = b"wrong"
        with self.assertRaisesRegex(F.FixtureError, "source_changed"): t.begin("GET", F.AUTH, USER, KEY)
        t.events = [("head", "stat", 200, 0)] * 512
        with self.assertRaisesRegex(F.FixtureError, "event_limit"): t._event("head", "stat")

    def test_parser_exact_routes_headers_and_no_credentials_confusion(self):
        server = F._Server.__new__(F._Server); server.port = 1234
        raw = f"GET {F.AUTH} HTTP/1.1\r\nHost: 127.0.0.1:1234\r\nX-Auth-User: {USER}\r\nX-Auth-Key: {KEY}\r\n\r\n".encode()
        self.assertEqual(server._parse(io.BytesIO(raw)), ("GET", F.AUTH, USER, KEY, None))
        for data in (raw.replace(b"1234", b"1235"), raw.replace(b"/auth/v1.0", b"/v1/AUTH_synthetic"),
                raw.replace(b"\r\n\r\n", b"\r\nTransfer-Encoding: chunked\r\n\r\n"),
                raw.replace(b"\r\n\r\n", b"\r\nRange: bytes=0-\r\n\r\n"),
                raw.replace(b"\r\n\r\n", b"\r\nHost: duplicate\r\n\r\n")):
            with self.assertRaises(F.FixtureError): server._parse(io.BytesIO(data))
        s = F.AppSwiftState("token_replacement", USER, KEY)
        for user, key, token in ((USER, "x", None), (None, KEY, None), (USER, KEY, "token")):
            with self.assertRaises(F.FixtureError): s.begin("GET", F.AUTH, user, key, token)

    def test_fake_worker_records_only_returned_send_and_closes_owned_socket(self):
        for broken in (False, True):
            s = F.AppSwiftState("token_replacement", USER, KEY)
            server = F._Server.__new__(F._Server); server.state = s; server.endpoint = ORIGIN + "/"
            server.lock = threading.RLock(); sock = Mock(); server.sockets = {sock: float("inf")}
            server.deadline = float("inf"); server._dispatch_lock = FakeDispatchLock()
            server._parse = Mock(return_value=("GET", F.AUTH, USER, KEY, None))
            server._live = Mock(); server._close_socket = Mock()
            sock.makefile.return_value.__enter__ = Mock(return_value=io.BytesIO())
            sock.makefile.return_value.__exit__ = Mock(return_value=False)
            def send(wire):
                self.assertFalse(s.lock._is_owned())
                self.assertIn(b"X-Auth-Token: synthetic-", wire)
                if broken: raise OSError("private canary")
            sock.sendall.side_effect = send
            with patch.object(F.select, "select", return_value=([], [], [])): server._worker(sock)
            self.assertEqual(len(s.tokens), 0 if broken else 1)
            self.assertEqual(s.response_bytes == 0, broken)
            self.assertEqual(s.errors, ["connection_failed"] if broken else [])
            self.assertNotIn(sock, server.sockets); server._close_socket.assert_called_once_with(sock)
            self.assertFalse(server._dispatch_lock.held)
            self.assertEqual(server._dispatch_lock.releases, 1)

    def test_worker_holds_dispatch_when_bytes_visible_and_after_send_return(self):
        s = F.AppSwiftState("token_replacement", USER, KEY)
        server, sock = worker_server(s, ("GET", F.AUTH, USER, KEY, None))
        trace, commit = [], s.commit
        def contender(label):
            self.assertFalse(s.lock._is_owned())
            self.assertTrue(server._dispatch_lock.held)
            self.assertFalse(server._dispatch_lock.acquire(timeout=0.01))
            self.assertEqual(s.events, [])
            trace.append(label)
        def send(wire):
            self.assertTrue(wire.endswith(b"\r\n\r\n"))
            contender("complete_response_visible_before_send_return")
        def commit_after_return(*args):
            contender("descheduled_after_send_return_before_commit")
            commit(*args)
        sock.sendall.side_effect = send
        with patch.object(F.time, "monotonic", return_value=0), patch.object(F.select, "select", return_value=([], [], [])), patch.object(s, "commit", side_effect=commit_after_return):
            server._worker(sock)
        self.assertEqual(trace, ["complete_response_visible_before_send_return", "descheduled_after_send_return_before_commit"])
        self.assertEqual(s.events, [("grant", "stat", 200, 0)])
        self.assertEqual(s.errors, [])
        self.assertEqual(server._dispatch_lock.releases, 1)
        self.assertFalse(server._dispatch_lock.held)

    def test_queued_successor_waits_for_predecessor_commit_in_both_schedules(self):
        for already_returned in (False, True):
            with self.subTest(already_returned=already_returned):
                s = F.AppSwiftState("token_replacement", USER, KEY)
                prior = s.begin("GET", F.AUTH, USER, KEY)
                reply = s.response(prior, ORIGIN)
                server, sock = worker_server(s, ("HEAD", F.OBJECT, None, None, prior[3]))
                trace = ["complete_response_visible"] + (["send_returned"] if already_returned else [])
                begin = s.begin
                def finish_predecessor():
                    self.assertFalse(s.lock._is_owned())
                    self.assertFalse(server.lock._is_owned())
                    self.assertEqual(s.events, [])
                    self.assertEqual(s.requests, 1)
                    trace.append("successor_waiting")
                    if not already_returned: trace.append("send_returned")
                    s.commit(prior, reply[0], 256, reply[3])
                    trace.append("predecessor_committed")
                    server._dispatch_lock.release()
                server._dispatch_lock = FakeDispatchLock(held=True, on_wait=finish_predecessor)
                def successor_begin(*fields):
                    self.assertEqual(trace[-1], "predecessor_committed")
                    self.assertTrue(server._dispatch_lock.held)
                    trace.append("successor_begin")
                    return begin(*fields)
                with patch.object(F.time, "monotonic", return_value=0), patch.object(F.select, "select", return_value=([], [], [])), patch.object(s, "begin", side_effect=successor_begin):
                    server._worker(sock)
                self.assertEqual(s.events, [("grant", "stat", 200, 0), ("head", "stat", 200, 0)])
                self.assertEqual(s.errors, [])
                self.assertEqual(server._dispatch_lock.timeouts, [0.05, 0.05])
                self.assertEqual(server._dispatch_lock.releases, 2)
                self.assertFalse(server._dispatch_lock.held)
                self.assertLess(trace.index("send_returned"), trace.index("predecessor_committed"))
                self.assertLess(trace.index("predecessor_committed"), trace.index("successor_begin"))

    def test_send_failure_is_recorded_before_dispatch_release_without_credit(self):
        for failure, code in ((OSError("private canary"), "connection_failed"), (BaseException("private canary"), "worker_failed")):
            s = F.AppSwiftState("token_replacement", USER, KEY)
            server, sock = worker_server(s, ("GET", F.AUTH, USER, KEY, None))
            def released():
                self.assertEqual(s.errors, [code])
                self.assertEqual((s.events, s.tokens, s.response_bytes), ([], {}, 0))
            server._dispatch_lock.on_release = released
            sock.sendall.side_effect = failure
            with patch.object(F.time, "monotonic", return_value=0), patch.object(F.select, "select", return_value=([], [], [])):
                server._worker(sock)
            self.assertFalse(server._dispatch_lock.held)
            self.assertEqual(server._dispatch_lock.releases, 1)
            self.assertNotIn("private canary", json.dumps(s.snapshot()))
            with self.assertRaises(F.FixtureError): s.begin("HEAD", F.OBJECT, token=s._pending[3])
            server._close_socket.assert_called_once_with(sock)

    def test_wait_failure_never_releases_predecessor_or_resets_deadline(self):
        for failure in ("request_deadline", "fixture_deadline", "stopped", "closed", "unowned"):
            with self.subTest(failure=failure):
                s = F.AppSwiftState("token_replacement", USER, KEY)
                server, sock = worker_server(s, ("GET", F.AUTH, USER, KEY, None))
                now = [0.0]
                if failure == "fixture_deadline": server.deadline = 0.02
                deadline = server.sockets[sock]
                def expire():
                    if failure == "request_deadline": now[0] = deadline
                    elif failure == "fixture_deadline": now[0] = server.deadline
                    elif failure == "stopped": server.stopping.set()
                    elif failure == "closed": sock.fileno.return_value = -1
                    else: server.sockets.pop(sock)
                server._dispatch_lock = FakeDispatchLock(held=True, on_wait=expire)
                with patch.object(F.time, "monotonic", side_effect=lambda: now[0]), patch.object(F.select, "select", return_value=([], [], [])):
                    server._worker(sock)
                self.assertEqual(s.requests, 0)
                self.assertEqual(s.events, [])
                self.assertEqual(s.errors, ["request_timeout"])
                self.assertTrue(server._dispatch_lock.held)
                self.assertEqual(server._dispatch_lock.releases, 0)
                self.assertEqual(server._dispatch_lock.timeouts, [0.02 if failure == "fixture_deadline" else 0.05])
                sock.sendall.assert_not_called()
                server._close_socket.assert_called_once_with(sock)

    def test_original_short_request_budget_caps_wait(self):
        s = F.AppSwiftState("token_replacement", USER, KEY)
        server, sock = worker_server(s, ("GET", F.AUTH, USER, KEY, None))
        now = [0.0]; server.sockets[sock] = 0.02
        def expire():
            self.assertEqual(server.sockets[sock], 0.02)
            now[0] = 0.02
        server._dispatch_lock = FakeDispatchLock(held=True, on_wait=expire)
        with patch.object(F.time, "monotonic", side_effect=lambda: now[0]), patch.object(F.select, "select", return_value=([], [], [])):
            server._worker(sock)
        self.assertEqual(server._dispatch_lock.timeouts, [0.02])
        self.assertEqual(server._dispatch_lock.releases, 0)
        self.assertEqual(s.errors, ["request_timeout"])
        self.assertEqual(s.requests, 0)

    def test_post_acquisition_live_failure_releases_exactly_once(self):
        for failure in ("deadline", "stopped", "closed", "unowned"):
            with self.subTest(failure=failure):
                s = F.AppSwiftState("token_replacement", USER, KEY)
                server, sock = worker_server(s, ("GET", F.AUTH, USER, KEY, None))
                now = [0.0]
                def acquired():
                    if failure == "deadline": now[0] = server.sockets[sock]
                    elif failure == "stopped": server.stopping.set()
                    elif failure == "closed": sock.fileno.return_value = -1
                    else: server.sockets.pop(sock)
                server._dispatch_lock.on_acquired = acquired
                with patch.object(F.time, "monotonic", side_effect=lambda: now[0]), patch.object(F.select, "select", return_value=([], [], [])):
                    server._worker(sock)
                self.assertEqual(s.requests, 0)
                self.assertEqual(s.errors, ["request_timeout"])
                self.assertFalse(server._dispatch_lock.held)
                self.assertEqual(server._dispatch_lock.releases, 1)
                sock.sendall.assert_not_called()
                server._close_socket.assert_called_once_with(sock)


if __name__ == "__main__": unittest.main()
