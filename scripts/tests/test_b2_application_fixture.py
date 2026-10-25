"""Pure state/fake stream tests; never bind a listener, thread or process."""
import base64
import io
import json
from pathlib import Path
import socket
import subprocess
import threading
import types
import unittest
from unittest.mock import Mock, patch

PATH = Path(__file__).resolve().parents[1] / "application-lab/fixture_b2.py"
F = types.ModuleType("b2_fixture_test")
F.__file__ = str(PATH)
with patch.object(subprocess, "Popen", side_effect=AssertionError("forbidden")), patch.object(socket, "socket", side_effect=AssertionError("forbidden")):
    exec(compile(PATH.read_bytes(), str(PATH), "exec"), F.__dict__)
USER, KEY = "a" * 64, "b" * 64
BASIC = "Basic " + base64.b64encode((USER + ":" + KEY).encode()).decode()


def complete(state, method, path, token):
    request = state.begin(method, path, token)
    response = state.response(request, "http://127.0.0.1:1234")
    status, body, _, payload = response
    state.commit(request, status, len(body) if method == "GET" else 0, payload)
    return request[1], response


def metadata(state):
    stat, _ = complete(state, "GET", F.AUTH, BASIC)
    complete(state, "HEAD", F.HEAD, stat)
    copy, _ = complete(state, "GET", F.AUTH, BASIC)
    complete(state, "HEAD", F.HEAD, copy)
    return stat, copy


class FixtureTests(unittest.TestCase):
    def setUp(self):
        for obj, name in ((subprocess, "Popen"), (socket, "socket"), (socket, "create_connection"), (threading.Thread, "start")):
            p = patch.object(obj, name, side_effect=AssertionError("native_forbidden")); p.start(); self.addCleanup(p.stop)

    def test_positive_keeps_stat_token_distinct_and_gates_both_gets(self):
        s = F.AppB2State("token_replacement", USER, KEY)
        stat, copy = metadata(s)
        request = s.begin("GET", F.GET, copy)
        self.assertNotEqual(stat, copy)
        self.assertEqual(s.initial, copy)
        with self.assertRaises(F.FixtureError): s.response(request, "origin")
        s.release_gate("first_get")
        status, body, headers, payload = s.response(request, "origin")
        self.assertEqual((status, payload, headers), (401, 0, {"Content-Type": "application/json"}))
        self.assertEqual(json.loads(body), dict(status=401, code="expired_auth_token", message=F.ERROR_MESSAGE))
        s.commit(request, status, len(body), payload)
        replacement, _ = complete(s, "GET", F.AUTH, BASIC)
        self.assertNotIn(replacement, (stat, copy))
        request = s.begin("GET", F.GET, replacement)
        with self.assertRaises(F.FixtureError): s.response(request, "origin")
        s.release_gate("replacement_get")
        status, body, _, payload = s.response(request, "origin")
        s.commit(request, status, len(body), payload)
        self.assertEqual(body, F.BODY)
        snap = s.snapshot()
        self.assertEqual((snap["requests"], snap["payload_bytes"]), (7, len(F.BODY)))
        self.assertEqual([e["role"] for e in snap["events"][:4]], ["pre_copy", "pre_copy", "copy_initial", "copy_initial"])
        for secret in (USER, KEY, BASIC, stat, copy, replacement, "127.0.0.1"):
            self.assertNotIn(secret, json.dumps(snap))

    def test_terminal_cap_denial_is_not_renewal_denial(self):
        s = F.AppB2State("download_cap_denial", USER, KEY)
        _, copy = metadata(s)
        request = s.begin("GET", F.GET, copy)
        s.release_gate("first_get")
        status, body, _, payload = s.response(request, "origin")
        self.assertEqual((status, payload), (403, 0))
        self.assertEqual(json.loads(body)["code"], "download_cap_exceeded")
        s.commit(request, status, len(body), payload)
        self.assertFalse(s.injected)
        self.assertEqual(s.snapshot()["payload_bytes"], 0)
        for args in (("GET", F.GET, copy), ("GET", F.AUTH, BASIC)):
            with self.assertRaises(F.FixtureError): s.begin(*args)

    def test_first_grant_or_missing_head_cannot_be_copy(self):
        for head in (False, True):
            s = F.AppB2State("token_replacement", USER, KEY)
            token, _ = complete(s, "GET", F.AUTH, BASIC)
            if head: complete(s, "HEAD", F.HEAD, token)
            with self.assertRaises(F.FixtureError): s.begin("GET", F.GET, token)
        s = F.AppB2State("token_replacement", USER, KEY)
        _, copy = metadata(s)
        s.heads.remove(copy)
        with self.assertRaises(F.FixtureError): s.begin("GET", F.GET, copy)

    def test_rejected_tokens_paths_and_extra_grants_cannot_enter_gate(self):
        for method, path, token in (("POST", F.GET, "x"), ("GET", F.GET + "&extra=1", "x"),
                ("GET", F.AUTH, "Basic invalid"), ("GET", "https://example.test", "x")):
            s = F.AppB2State("token_replacement", USER, KEY)
            with self.assertRaises(F.FixtureError): s.begin(method, path, token)
        s = F.AppB2State("token_replacement", USER, KEY)
        _, copy = metadata(s)
        s.begin("GET", F.GET, copy)
        with self.assertRaises(F.FixtureError): s.begin("GET", F.AUTH, BASIC)
        with self.assertRaises(F.FixtureError): s.begin("GET", F.GET, copy)

    def test_teardown_wakeup_never_releases_a_gate(self):
        s = F.AppB2State("token_replacement", USER, KEY)
        _, copy = metadata(s)
        request = s.begin("GET", F.GET, copy)
        s.release_observation()
        self.assertFalse(s.gates["first_get"]["released"])
        with self.assertRaises(F.FixtureError): s.response(request, "origin")
        for gate in ("unknown", "replacement_get"):
            with self.assertRaises(F.FixtureError): s.release_gate(gate)
        s.release_gate("first_get")
        with self.assertRaises(F.FixtureError): s.release_gate("first_get")

    def test_replacement_must_be_fresh_and_revoked_token_never_served(self):
        s = F.AppB2State("token_replacement", USER, KEY)
        stat, copy = metadata(s)
        request = s.begin("GET", F.GET, copy); s.release_gate("first_get")
        status, body, _, payload = s.response(request, "origin"); s.commit(request, status, len(body), payload)
        with patch.object(F.secrets, "token_hex", return_value=copy.removeprefix("synthetic-")):
            with self.assertRaises(F.FixtureError): s.begin("GET", F.AUTH, BASIC)
        for token in (copy, stat, "unknown"):
            with self.assertRaises(F.FixtureError): s.begin("GET", F.GET, token)

    def test_fixed_caps_fail_instead_of_truncating(self):
        s = F.AppB2State("token_replacement", USER, KEY)
        s.requests = 32
        with self.assertRaisesRegex(F.FixtureError, "request_limit"): s.begin("GET", F.AUTH, BASIC)
        s.events = [("head", "x", 200, 0)] * 32
        with self.assertRaisesRegex(F.FixtureError, "event_limit"): s._event("head", "x", 200)
        s._error("a secret message")
        self.assertEqual(s.errors, ["request_limit", "worker_failed"])
        self.assertNotIn("a secret message", json.dumps(s.snapshot()))

    def test_rejection_storm_preserves_terminal_bounded_accounting(self):
        state = F.AppB2State("token_replacement", USER, KEY)
        for _ in range(128):
            try:
                state.begin("GET", F.AUTH, "invalid synthetic authorization")
            except F.FixtureError as error:
                # Same exception-to-sticky-error transition as the real worker.
                state._error(str(error))
        self.assertEqual(state.requests, 1)
        self.assertEqual(state.errors, ["credentials_invalid", "sequence_invalid"])
        self.assertEqual(state.snapshot()["payload_bytes"], 0)

    def test_request_overflow_latches_inside_lock_before_worker_catch(self):
        state = F.AppB2State("token_replacement", USER, KEY)
        # Exercise repeated begin before the caller records its thrown errors.
        # This models a worker interleaving, without spawning any thread.
        for _ in range(128):
            with self.assertRaises(F.FixtureError):
                state.begin("GET", "/rejected", "unknown")
        self.assertEqual(state.requests, 32)
        self.assertEqual(state.errors, ["request_limit"])

    def test_parser_exact_origin_routes_and_no_request_body(self):
        server = F._Server.__new__(F._Server); server.port = 1234
        valid = f"GET {F.AUTH} HTTP/1.1\r\nHost: 127.0.0.1:1234\r\nAuthorization: {BASIC}\r\n\r\n".encode()
        self.assertEqual(server._parse(io.BytesIO(valid)), ("GET", F.AUTH, BASIC))
        for raw in (valid.replace(b"127.0.0.1", b"localhost"), valid.replace(b"\r\n\r\n", b"\r\nContent-Length: 1\r\n\r\n"),
                valid.replace(b"\r\n\r\n", b"\r\nHost: canary\r\n\r\n"), valid.replace(b"GET ", b"POST "),
                valid.replace(F.AUTH.encode(), b"/unknown"), valid.replace(b"\r\n\r\n", b"\r\nTransfer-Encoding: chunked\r\n\r\n"),
                valid.replace(b"\r\n\r\n", b"\r\nRange: bytes=1-\r\n\r\n")):
            with self.assertRaises(F.FixtureError): server._parse(io.BytesIO(raw))

    def test_wait_rejects_stopped_or_unreleased_wakeup(self):
        server = F._Server.__new__(F._Server)
        server.lock = threading.RLock(); server.state = F.AppB2State("token_replacement", USER, KEY)
        sock = Mock(); server.sockets = {sock: 1}; server.deadline = 10
        server.stopping = threading.Event(); server.stopping.set()
        with self.assertRaises(F.FixtureError): server._wait_gate(sock, "first_get")
        self.assertFalse(server.state.gates["first_get"]["released"])

    def test_input_contract_and_source_change_are_not_accepted(self):
        for case, user, key in (("other", USER, KEY), ("token_replacement", USER + "\0", KEY), ("token_replacement", True, KEY)):
            with self.assertRaises(ValueError): F.AppB2State(case, user, key)
        s = F.AppB2State("token_replacement", USER, KEY); s._body += b"changed"
        self.assertFalse(s.source_preserved())
        with self.assertRaises(F.FixtureError): s.begin("GET", F.AUTH, BASIC)

    def test_worker_emits_valid_error_json_zero_object_bytes_and_closes_owned_socket(self):
        for name, status in (("token_replacement", 401), ("download_cap_denial", 403)):
            server = F._Server.__new__(F._Server)
            server.lock = threading.RLock(); server.state = F.AppB2State(name, USER, KEY)
            _, token = metadata(server.state)
            server.deadline = F.time.monotonic() + 60; server.endpoint = "http://127.0.0.1:1234/"; server.port = 1234
            server.stopping = threading.Event(); sock = Mock(); server.sockets = {sock: server.deadline}
            raw = f"GET {F.GET} HTTP/1.1\r\nHost: 127.0.0.1:1234\r\nAuthorization: {token}\r\n\r\n".encode()
            sock.makefile.return_value = io.BytesIO(raw)
            with patch.object(F.select, "select", return_value=([], [], [])), patch.object(server, "_live"), \
                    patch.object(server, "_wait_gate", side_effect=lambda s,g: server.state.release_gate(g)):
                server._worker(sock)
            wire = sock.sendall.call_args.args[0]
            self.assertIn(f"HTTP/1.1 {status} ".encode(), wire)
            self.assertEqual(json.loads(wire.partition(b"\r\n\r\n")[2])["status"], status)
            self.assertEqual(server.state.payload_bytes, 0)
            self.assertEqual(server.state.errors, [])
            self.assertEqual(server.sockets, {})
            sock.close.assert_called_once()

    def test_failed_write_never_commits_and_failed_close_retains_uncertainty(self):
        server = F._Server.__new__(F._Server); server.lock = threading.RLock()
        server.state = F.AppB2State("token_replacement", USER, KEY)
        server.deadline = F.time.monotonic()+60; server.endpoint = "http://127.0.0.1:1234/"; server.port = 1234
        server.stopping = threading.Event(); sock = Mock(); server.sockets = {sock: server.deadline}
        sock.makefile.return_value = io.BytesIO(f"GET {F.AUTH} HTTP/1.1\r\nHost: 127.0.0.1:1234\r\nAuthorization: {BASIC}\r\n\r\n".encode())
        sock.sendall.side_effect = OSError("private message must not escape")
        sock.close.side_effect = OSError("private close canary")
        with patch.object(F.select, "select", return_value=([], [], [])), patch.object(server, "_live"):
            server._worker(sock)
        self.assertEqual(server.state.events, [])
        self.assertEqual(server.state.errors, ["connection_failed", "cleanup_failed"])
        self.assertIn(sock, server.sockets)
        self.assertNotIn("private", json.dumps(server.state.snapshot()))

    def test_close_is_once_only_and_does_not_retry_uncertain_cleanup(self):
        for succeeded in (True, False):
            server = F._Server.__new__(F._Server); server._close_attempted = False; server.cleanup_complete = False
            def close(s):
                s.cleanup_complete = succeeded
                if not succeeded: raise F.FixtureError("cleanup_failed")
            with patch.object(F._http._Server, "close", autospec=True, side_effect=close) as called:
                if succeeded:
                    server.close(); server.close()
                else:
                    with self.assertRaises(F.FixtureError): server.close()
                    with self.assertRaises(F.FixtureError): server.close()
                self.assertEqual(called.call_count, 1)


if __name__ == "__main__":
    unittest.main()
