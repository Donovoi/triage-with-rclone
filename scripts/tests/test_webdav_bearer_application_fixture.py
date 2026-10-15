"""Pure fixed-Bearer model, parser and fake transport; no native acceptance."""
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

PATH = Path(__file__).resolve().parents[1] / "application-lab/fixture_webdav_bearer.py"
F = types.ModuleType("bearer_fixture_test"); F.__file__ = str(PATH)
with patch.object(subprocess, "Popen", side_effect=AssertionError("forbidden")), patch.object(socket, "socket", side_effect=AssertionError("forbidden")):
    exec(compile(PATH.read_bytes(), str(PATH), "exec"), F.__dict__)
TOKEN = "a" * 64
AUTH = "Bearer " + TOKEN
ORIGIN = "http://127.0.0.1:1234/"


def complete(state, method):
    request = state.begin(method, F.MEMBER, AUTH)
    if request[2]: state.release_gate(request[2])
    result = state.response(request, ORIGIN)
    state.commit(request, result[0], 256 + len(result[1]), result[3])
    return result


def control(state):
    complete(state, "PROPFIND"); complete(state, "PROPFIND")
    return complete(state, "GET")


class FakeDispatchLock:
    def __init__(self, held=False, on_wait=None, on_release=None):
        self.held, self.on_wait, self.on_release = held, on_wait, on_release
        self.timeouts, self.releases = [], 0

    def acquire(self, *, timeout):
        self.timeouts.append(timeout)
        if self.held:
            if self.on_wait: self.on_wait()
            return False
        self.held = True
        return True

    def release(self):
        if not self.held: raise AssertionError("unowned release")
        if self.on_release: self.on_release()
        self.held = False
        self.releases += 1


def worker_server(state, fields):
    server = F._Server.__new__(F._Server)
    server.state, server.endpoint = state, ORIGIN
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

    def test_independent_known_byte_oracle_and_xml(self):
        self.assertEqual(F.BODY, b"synthetic application fixture\n")
        self.assertEqual(len(F.BODY), 30)
        self.assertEqual(hashlib.sha256(F.BODY).hexdigest(), "64d5b40a5f4773b14940a6ce1dd57cf87b44ce5940c097088732ffc71be280cf")
        import xml.etree.ElementTree as ET
        tree = ET.fromstring(F.METADATA)
        self.assertEqual(tree.findtext(".//{DAV:}href"), "/README-synthetic.txt")
        self.assertEqual(tree.findtext(".//{DAV:}getcontentlength"), "30")
        self.assertIsNone(tree.find(".//{DAV:}collection"))

    def test_control_then_same_token_denial_replays_independent_contract(self):
        from test_webdav_bearer_application_evidence import E
        state = F.AppBearerState(TOKEN)
        result = control(state)
        self.assertEqual((result[0], result[1]), (200, F.BODY))
        state.advance(successful=True, reaped=True)
        result = control(state)
        self.assertEqual((result[0], result[1], result[3]), (401, b"", 0))
        for name in F.CASES:
            E.fixture_observation(state.snapshot_case(name), name, successful=True)
        wire = json.dumps([state.snapshot_case(n) for n in F.CASES])
        self.assertNotIn(TOKEN, wire)
        self.assertNotIn(ORIGIN, wire)
        self.assertEqual(state.snapshot_case(F.CASES[0])["payload_bytes"], 30)
        self.assertEqual(state.snapshot_case(F.CASES[1])["payload_bytes"], 0)

    def test_epoch_transition_requires_complete_reaped_control_and_is_once_only(self):
        state = F.AppBearerState(TOKEN)
        with self.assertRaises(F.FixtureError): state.advance(successful=True, reaped=True)
        control(state)
        for successful, reaped in ((False, True), (True, False), (1, True), (True, 1)):
            with self.assertRaises(F.FixtureError): state.advance(successful=successful, reaped=reaped)
        state.advance(successful=True, reaped=True)
        with self.assertRaises(F.FixtureError): state.advance(successful=True, reaped=True)

    def test_method_authority_credentials_and_extra_read_cannot_fall_back(self):
        for method, path, auth in (("GET", F.MEMBER, AUTH), ("PUT", F.MEMBER, AUTH),
                                  ("PROPFIND", "", AUTH), ("PROPFIND", F.MEMBER, None),
                                  ("PROPFIND", F.MEMBER, "Basic " + TOKEN),
                                  ("PROPFIND", F.MEMBER, "Bearer " + "b" * 64)):
            state = F.AppBearerState(TOKEN)
            with self.assertRaises(F.FixtureError): state.begin(method, path, auth)
            self.assertEqual(state.requests, 0)
        state = F.AppBearerState(TOKEN); control(state)
        with self.assertRaises(F.FixtureError): state.begin("GET", F.MEMBER, AUTH)
        state._error("private canary")
        self.assertEqual(state.errors, ["worker_failed"])
        with self.assertRaises(F.FixtureError): state.advance(successful=True, reaped=True)

    def test_commit_is_send_return_identity_bound_and_once_only(self):
        state = F.AppBearerState(TOKEN)
        request = state.begin("PROPFIND", F.MEMBER, AUTH)
        with self.assertRaises(F.FixtureError): state.begin("PROPFIND", F.MEMBER, AUTH)
        result = state.response(request, ORIGIN)
        for changed in ((tuple(list(request)), result[0], 500, result[3]), (request, True, 500, 0),
                        (request, result[0], True, 0), (request, result[0], 500, 1)):
            with self.assertRaises(F.FixtureError): state.commit(*changed)
        self.assertEqual(state.events, [])
        state.commit(request, result[0], 500, result[3])
        with self.assertRaises(F.FixtureError): state.commit(request, result[0], 500, result[3])

    def test_teardown_wake_never_earns_gate_or_content_credit(self):
        state = F.AppBearerState(TOKEN)
        complete(state, "PROPFIND"); complete(state, "PROPFIND")
        request = state.begin("GET", F.MEMBER, AUTH)
        state.release_observation()
        with self.assertRaises(F.FixtureError): state.response(request, ORIGIN)
        self.assertFalse(state.gate_snapshot()["first_get"]["released"])
        self.assertEqual(state.payload_bytes, 0)

    def test_held_get_retains_original_request_deadline(self):
        for released in (False, True):
            state = F.AppBearerState(TOKEN)
            complete(state, "PROPFIND"); complete(state, "PROPFIND")
            state.begin("GET", F.MEMBER, AUTH)
            server, sock = worker_server(state, ("GET", F.MEMBER, AUTH))
            now = [14.0]
            def select(*args): now[0] = 15.0; return ([], [], [])
            if released: state.release_gate("first_get")
            with patch.object(F.time, "monotonic", side_effect=lambda: now[0]), patch.object(F.select, "select", side_effect=select):
                if released: server._wait_gate(sock, "first_get")
                else:
                    with self.assertRaisesRegex(F.FixtureError, "^request_timeout$"): server._wait_gate(sock, "first_get")
            self.assertEqual(server.sockets[sock], 15.0)
            self.assertEqual(server.deadline, 180.0)
            self.assertFalse(state.completed)
            self.assertEqual(state.payload_bytes, 0)

    def test_parser_is_exact_and_rejects_body_route_header_range_confusion(self):
        server = F._Server.__new__(F._Server); server.port = 1234; server.endpoint = ORIGIN
        headers = f"Host: 127.0.0.1:1234\r\nReferer: {ORIGIN}\r\nAuthorization: {AUTH}\r\nDepth: 0\r\n"
        raw = (f"PROPFIND /{F.MEMBER} HTTP/1.1\r\n" + headers + f"Content-Length: {len(F.PROPFIND_BODY)}\r\n\r\n").encode() + F.PROPFIND_BODY
        self.assertEqual(server._parse(io.BytesIO(raw)), ("PROPFIND", F.MEMBER, AUTH))
        get = (f"GET /{F.MEMBER} HTTP/1.1\r\n" + headers + "\r\n").encode()
        self.assertEqual(server._parse(io.BytesIO(get)), ("GET", F.MEMBER, AUTH))
        for value in (raw.replace(b"Depth: 0", b"Depth: 1"), raw[:-1], raw.replace(b"displayname", b"displaynamf"),
                      raw.replace(b"Host: 127.0.0.1:1234", b"Host: external.invalid"),
                      raw.replace(b"/README-synthetic.txt", b"/other.txt"),
                      raw.replace(b"\r\n\r\n", b"\r\nRange: bytes=0-\r\n\r\n"),
                      get.replace(b"\r\n\r\n", b"\r\nHost: duplicate\r\n\r\n"),
                      get.replace(b"\r\n\r\n", b"\r\nRange: bytes=1-29\r\n\r\n")):
            with self.assertRaises(F.FixtureError): server._parse(io.BytesIO(value))

    def test_fake_send_failure_is_recorded_before_dispatch_release(self):
        for failure, code in ((OSError("private canary"), "connection_failed"), (BaseException("private canary"), "worker_failed")):
            state = F.AppBearerState(TOKEN)
            server, sock = worker_server(state, ("PROPFIND", F.MEMBER, AUTH))
            def released():
                self.assertEqual(state.errors, [code])
                self.assertEqual((state.events, state.response_bytes), ([], 0))
            server._dispatch_lock.on_release = released
            sock.sendall.side_effect = failure
            with patch.object(F.time, "monotonic", return_value=0), patch.object(F.select, "select", return_value=([], [], [])):
                server._worker(sock)
            self.assertEqual(server._dispatch_lock.releases, 1)
            self.assertNotIn("private canary", json.dumps(state.snapshot_case(state.case)))
            server._close_socket.assert_called_once_with(sock)

    def test_successor_waits_when_bytes_visible_before_send_return_or_commit(self):
        for already_returned in (False, True):
            state = F.AppBearerState(TOKEN)
            prior = state.begin("PROPFIND", F.MEMBER, AUTH)
            reply = state.response(prior, ORIGIN)
            server, sock = worker_server(state, ("PROPFIND", F.MEMBER, AUTH))
            trace = ["visible"] + (["send_returned"] if already_returned else [])
            def predecessor():
                self.assertFalse(state.lock._is_owned())
                self.assertFalse(server.lock._is_owned())
                self.assertEqual(state.events, [])
                trace.append("waiting")
                if not already_returned: trace.append("send_returned")
                state.commit(prior, reply[0], 500, reply[3])
                trace.append("committed")
                server._dispatch_lock.release()
            server._dispatch_lock = FakeDispatchLock(held=True, on_wait=predecessor)
            begin = state.begin
            def successor(*args):
                self.assertEqual(trace[-1], "committed")
                self.assertTrue(server._dispatch_lock.held)
                trace.append("begin")
                return begin(*args)
            with patch.object(F.time, "monotonic", return_value=0), patch.object(F.select, "select", return_value=([], [], [])), patch.object(state, "begin", side_effect=successor):
                server._worker(sock)
            self.assertEqual(state.events, [("metadata", 207, 0), ("metadata", 207, 0)])
            self.assertEqual(state.errors, [])
            self.assertEqual(server._dispatch_lock.timeouts, [0.05, 0.05])
            self.assertEqual(server._dispatch_lock.releases, 2)

    def test_original_request_and_fixture_deadlines_stop_waiters_without_release(self):
        for reason in ("request", "fixture", "stop", "closed", "unowned"):
            state = F.AppBearerState(TOKEN)
            server, sock = worker_server(state, ("PROPFIND", F.MEMBER, AUTH))
            now = [0.0]
            if reason == "fixture": server.deadline = 0.02
            def expire():
                if reason == "request": now[0] = 15.0
                elif reason == "fixture": now[0] = 0.02
                elif reason == "stop": server.stopping.set()
                elif reason == "closed": sock.fileno.return_value = -1
                else: server.sockets.pop(sock)
            server._dispatch_lock = FakeDispatchLock(held=True, on_wait=expire)
            with patch.object(F.time, "monotonic", side_effect=lambda: now[0]), patch.object(F.select, "select", return_value=([], [], [])):
                server._worker(sock)
            self.assertEqual(state.requests, 0)
            self.assertEqual(state.errors, ["request_timeout"])
            self.assertEqual(server._dispatch_lock.releases, 0)
            self.assertEqual(server._dispatch_lock.timeouts, [0.02 if reason == "fixture" else 0.05])
            sock.sendall.assert_not_called()


if __name__ == "__main__": unittest.main()
