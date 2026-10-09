"""Synthetic localhost tests; no application or rclone execution."""
import http.client
import importlib.util
from pathlib import Path
import socket
import threading
import time
import unittest
from unittest import mock

PATH = Path(__file__).resolve().parents[1] / "application-lab" / "fixture_http.py"
SPEC = importlib.util.spec_from_file_location("application_http_fixture", PATH)
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
FILES = {"README-synthetic.txt": b"synthetic application fixture\n",
         "nested/spaced name.txt": b"spaces remain exact\n", "nested/binary.bin": bytes(range(256)),
         "large/cancel.bin": bytes(range(256)) * 1024}


class AppHttpFixtureTests(unittest.TestCase):
    def setUp(self):
        self.contexts, self.clients, self.threads = [], [], []

    def tearDown(self):
        failures = []
        for client in self.clients:
            try:
                client.close()
            except Exception:
                failures.append("client_cleanup")
        for context, server in reversed(self.contexts):
            try:
                context.__exit__(None, None, None)
                if not server.cleanup_complete:
                    failures.append("server_cleanup")
            except Exception:
                failures.append("server_cleanup_exception")
        for thread in self.threads:
            thread.join(2)
            if thread.is_alive():
                failures.append("client_thread_cleanup")
        self.assertEqual(failures, [])

    def start(self, mode="baseline", released=True, files=None):
        state = F.AppHttpState(dict(FILES if files is None else files), mode)
        if released:
            state.release_observation()
        context = F.serve_http(state)
        server = context.__enter__()
        self.contexts.append((context, server))
        return state, server

    def wait_for(self, predicate, seconds=2):
        deadline = time.monotonic() + seconds
        while not predicate() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(predicate())

    def request(self, server, path, method="GET", headers=None):
        client = http.client.HTTPConnection("127.0.0.1", server.port, timeout=2)
        self.clients.append(client)
        client.request(method, path, headers=headers or {})
        response = client.getresponse()
        answer = response.status, response.read(), dict(response.getheaders())
        client.close()
        self.wait_for(lambda: server.transport_snapshot()["active"] == 0)
        return answer

    def raw(self, server, data):
        client = socket.create_connection(("127.0.0.1", server.port), timeout=2)
        self.clients.append(client)
        client.sendall(data)
        answer = bytearray()
        try:
            while part := client.recv(8192):
                answer.extend(part)
        except ConnectionResetError:
            pass
        client.close()
        self.wait_for(lambda: server.transport_snapshot()["active"] == 0)
        return bytes(answer)

    def test_recursive_listing_links_and_metadata_are_exact(self):
        state, server = self.start("listing")
        status, body, headers = self.request(server, "/")
        self.assertEqual(status, 200)
        self.assertEqual(body, b'<!doctype html><html><body>\n<a href="README-synthetic.txt">README-synthetic.txt</a>\n<a href="large/">large/</a>\n<a href="nested/">nested/</a>\n</body></html>\n')
        self.assertEqual(headers["Content-Type"], "text/html; charset=utf-8")
        status, body, _ = self.request(server, "/nested/")
        self.assertEqual(status, 200)
        self.assertIn(b'href="spaced%20name.txt"', body)
        status, body, headers = self.request(server, "/nested/spaced%20name.txt", "HEAD")
        self.assertEqual((status, body), (200, b""))
        self.assertEqual(headers["Content-Length"], "20")
        self.assertEqual(headers["Last-Modified"], "Thu, 02 Jan 2025 03:04:05 GMT")
        self.assertEqual(state.snapshot()["errors"], [])

    def test_all_literal_bodies_and_completion_bytes(self):
        state, server = self.start()
        for path, expected in FILES.items():
            status, actual, _ = self.request(server, "/" + path.replace(" ", "%20"))
            self.assertEqual((status, actual), (200, expected))
        result = state.snapshot()
        self.assertEqual(result["content_reads"], 4)
        self.assertEqual(result["payload_bytes"], 262450)
        self.assertEqual(result["completed_payload_bytes"], 262450)
        self.assertTrue(result["source_preserved"])

    def test_first_native_request_is_held_until_observation_release(self):
        state, server = self.start(released=False)
        results = []
        def client():
            try:
                results.append(self.request(server, "/README-synthetic.txt"))
            except Exception as error:
                results.append(type(error).__name__)
        thread = threading.Thread(target=client)
        self.threads.append(thread)
        thread.start()
        self.assertTrue(state.observation_started.wait(1))
        self.assertEqual(results, [])
        self.assertEqual(state.snapshot()["payload_bytes"], 0)
        self.assertEqual(state.snapshot()["events"], [["observation", "README-synthetic.txt"]])
        state.release_observation()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results[0][0:2], (200, b"synthetic application fixture\n"))

    def test_cancellation_requires_flushed_prefix_and_actual_disconnect(self):
        state, server = self.start("cancellation")
        client = http.client.HTTPConnection("127.0.0.1", server.port, timeout=2)
        self.clients.append(client)
        client.request("GET", "/large/cancel.bin")
        response = client.getresponse()
        self.assertEqual(response.read(1024), bytes(range(256)) * 4)
        self.assertTrue(state.cancel_started.wait(1))
        before = state.snapshot()
        self.assertEqual(before["payload_bytes"], 65536)
        self.assertEqual(before["completed_payload_bytes"], 0)
        self.assertFalse(before["cancel_disconnected"])
        self.assertFalse(before["cancel_released"])
        response.close()
        client.close()
        self.wait_for(lambda: state.snapshot()["cancel_disconnected"])
        self.wait_for(lambda: server.transport_snapshot()["active"] == 0)
        self.assertIn(["cancel_disconnected", "large/cancel.bin"], state.snapshot()["events"])
        self.assertEqual(state.snapshot()["errors"], [])

    def test_cancel_teardown_release_is_not_disconnect_evidence(self):
        state, server = self.start("cancellation")
        client = http.client.HTTPConnection("127.0.0.1", server.port, timeout=2)
        self.clients.append(client)
        client.request("GET", "/large/cancel.bin")
        response = client.getresponse()
        self.assertEqual(len(response.read(1024)), 1024)
        self.assertTrue(state.cancel_started.wait(1))
        state.release_cancel()
        self.wait_for(lambda: server.transport_snapshot()["active"] == 0)
        self.assertFalse(state.snapshot()["cancel_disconnected"])
        self.assertTrue(state.snapshot()["cancel_released"])
        self.assertEqual(state.snapshot()["completed_payload_bytes"], 0)
        response.close()

    def test_missing_and_denial_have_distinct_exact_known_routes(self):
        for mode, path, code, body in [("missing", "/missing-synthetic.txt", 404, b"synthetic missing\n"),
                                     ("denial", "/README-synthetic.txt", 403, b"synthetic denied\n")]:
            with self.subTest(mode=mode):
                state, server = self.start(mode)
                self.assertEqual(self.request(server, path)[:2], (code, body))
                self.assertEqual(state.snapshot()["errors"], [])
                self.assertTrue(state.source_preserved())

    def test_mismatch_never_changes_source_content(self):
        state, server = self.start("mismatch")
        self.assertEqual(self.request(server, "/README-synthetic.txt")[:2], (200, FILES["README-synthetic.txt"]))
        self.assertTrue(state.source_preserved())

    def test_rejects_method_authority_routes_and_headers_without_observation(self):
        invalid = [b"POST /README-synthetic.txt HTTP/1.1\r\n", b"GET /unknown HTTP/1.1\r\n",
                   b"GET /README-synthetic.txt?x=1 HTTP/1.1\r\n", b"GET /nested%2Fbinary.bin HTTP/1.1\r\n",
                   b"GET //README-synthetic.txt HTTP/1.1\r\n", b"GET /../README-synthetic.txt HTTP/1.1\r\n",
                   b"GET http://127.0.0.1/ HTTP/1.1\r\n"]
        extras = [b"Cookie: synthetic\r\n", b"Authorization: synthetic\r\n", b"Range: bytes=0-\r\n",
                  b"Transfer-Encoding: chunked\r\n", b"Content-Length: 1\r\n", b"Host: foreign\r\n",
                  b"Authorization : synthetic\r\n", b": synthetic\r\n", b"X-Extra: synthetic\r\n"]
        for line, extra in [(v, b"") for v in invalid] + [(b"GET / HTTP/1.1\r\n", v) for v in extras]:
            with self.subTest(line=line, extra=extra):
                state, server = self.start(released=False)
                host = f"Host: 127.0.0.1:{server.port}\r\n".encode()
                self.raw(server, line + host + extra + b"\r\n")
                result = state.snapshot()
                self.assertFalse(result["observation_started"])
                self.assertEqual(result["events"], [])
                self.assertGreater(result["rejected"], 0)
                self.assertTrue(result["errors"])

    def test_unframed_body_and_duplicate_headers_reject(self):
        for suffix in (b"\r\nextra", b"User-Agent: first\r\nUser-Agent: second\r\n\r\n",
                       b"Invalid Field: value\r\n\r\n", b"\n"):
            with self.subTest(suffix=suffix):
                state, server = self.start(released=False)
                self.raw(server, f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{server.port}\r\n".encode() + suffix)
                self.assertFalse(state.observation_started.is_set())
                self.assertTrue(state.snapshot()["errors"])

    def test_header_limits_and_slow_header_deadline(self):
        with mock.patch.object(F, "REQUEST_SECONDS", 0.15):
            state, server = self.start()
            client = socket.create_connection(("127.0.0.1", server.port), timeout=2)
            self.clients.append(client)
            client.sendall(b"GET / HTTP/1.1\r\nHost:")
            self.wait_for(lambda: server.transport_snapshot()["active"] == 0 and bool(state.errors))
            self.assertFalse(state.observation_started.is_set())
        state, server = self.start()
        self.raw(server, f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{server.port}\r\nUser-Agent: ".encode() + b"a" * 16384 + b"\r\n\r\n")
        self.assertIn("headers_invalid", state.errors)

    def test_response_and_request_limits_are_sticky(self):
        with mock.patch.object(F, "MAX_BODY_BYTES", 1):
            state, server = self.start()
            self.raw(server, f"GET /README-synthetic.txt HTTP/1.1\r\nHost: 127.0.0.1:{server.port}\r\n\r\n".encode())
            self.assertIn("byte_limit", state.errors)
            self.assertEqual(state.snapshot()["payload_bytes"], 0)
        with mock.patch.object(F, "MAX_REQUESTS", 1):
            state, server = self.start()
            self.assertEqual(self.request(server, "/README-synthetic.txt", "HEAD")[0], 200)
            self.assertEqual(self.request(server, "/README-synthetic.txt", "HEAD")[0], 400)
            self.assertIn("request_limit", state.errors)

    def test_active_admission_is_bounded(self):
        with mock.patch.object(F, "MAX_ACTIVE", 1):
            state, server = self.start()
            first = socket.create_connection(("127.0.0.1", server.port), timeout=2)
            self.clients.append(first)
            self.wait_for(lambda: server.transport_snapshot()["active"] == 1)
            second = socket.create_connection(("127.0.0.1", server.port), timeout=2)
            self.clients.append(second)
            self.wait_for(lambda: "admission_limit" in state.errors)
            self.assertEqual(server.transport_snapshot()["active"], 1)

    def test_overall_deadline_terminates_held_observation(self):
        with mock.patch.object(F, "MAX_LIFETIME", 0.2):
            state, server = self.start(released=False)
            client = socket.create_connection(("127.0.0.1", server.port), timeout=2)
            self.clients.append(client)
            client.sendall(f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{server.port}\r\n\r\n".encode())
            self.assertTrue(state.observation_started.wait(1))
            self.wait_for(lambda: "lifetime_limit" in state.errors)
            self.wait_for(lambda: server.transport_snapshot()["active"] == 0)
            self.assertEqual(state.snapshot()["payload_bytes"], 0)

    def test_close_reaps_held_request_and_proves_listener_absent(self):
        state, server = self.start(released=False)
        client = socket.create_connection(("127.0.0.1", server.port), timeout=2)
        self.clients.append(client)
        client.sendall(f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{server.port}\r\n\r\n".encode())
        self.assertTrue(state.observation_started.wait(1))
        server.close()
        result = server.snapshot()["transport"]
        self.assertEqual(result, dict(accepted=1, active=0, workers_alive=0, watchdog_alive=False,
                                     acceptor_alive=False, cleanup_complete=True))
        with socket.socket() as probe:
            probe.settimeout(0.2)
            self.assertNotEqual(probe.connect_ex(("127.0.0.1", server.port)), 0)

    def test_source_change_is_sticky_and_reuse_refused(self):
        state, server = self.start()
        state.mode = "mismatch"
        self.assertEqual(self.request(server, "/README-synthetic.txt")[0], 400)
        self.assertIn("source_changed", state.errors)
        self.assertFalse(state.source_preserved())
        with self.assertRaisesRegex(ValueError, "state_reused"):
            with F.serve_http(state):
                self.fail("reused state")

    def test_constructor_rejects_aliases_mutable_values_and_bad_cancellation(self):
        for files, mode in [({"../escape": b"x"}, "baseline"), ({"x": bytearray(b"x")}, "baseline"),
                            ({"x": b"x", "x/y": b"y"}, "baseline"), ({"large/cancel.bin": b"x"}, "cancellation"),
                            ({"x": b"x"}, "denial"), ({"x": b"x"}, "unknown"),
                            ({"missing-synthetic.txt": b"x"}, "baseline")]:
            with self.subTest(mode=mode, files=list(files)):
                with self.assertRaisesRegex(ValueError, "input_invalid"):
                    F.AppHttpState(files, mode)

    def test_worker_start_failure_closes_owned_socket(self):
        state, server = self.start()
        original = threading.Thread.start
        def start(thread):
            if thread.name == "app-http-request":
                raise RuntimeError("synthetic")
            return original(thread)
        with mock.patch.object(F.threading.Thread, "start", start):
            client = socket.create_connection(("127.0.0.1", server.port), timeout=2)
            self.clients.append(client)
            self.wait_for(lambda: "thread_start_failed" in state.errors)
            self.assertEqual(server.transport_snapshot()["active"], 0)

    def test_reply_reserves_whole_budget_before_first_write(self):
        state, server = self.start()
        sock = mock.Mock()
        sock.fileno.return_value = 100
        server.sockets[sock] = time.monotonic() + 2
        def inspect_reservation(data):
            self.assertEqual(state._allocated_bytes, 4)
            with self.assertRaisesRegex(F.FixtureError, "byte_limit"):
                server._reply(sock, 200, b"x", "GET")
        sock.sendall.side_effect = inspect_reservation
        try:
            with mock.patch.object(F, "MAX_BODY_BYTES", 4):
                server._reply(sock, 200, b"1234", "GET")
            self.assertEqual(state.snapshot()["payload_bytes"], 4)
            self.assertEqual(state.snapshot()["completed_payload_bytes"], 4)
        finally:
            server.sockets.pop(sock)

    def test_expired_connection_cannot_dispatch_after_header_parse(self):
        state, server = self.start()
        sock = mock.Mock()
        sock.fileno.return_value = 100
        server.sockets[sock] = time.monotonic() - 1
        try:
            with self.assertRaisesRegex(F.FixtureError, "request_timeout"):
                server._dispatch(sock, "GET", "README-synthetic.txt")
            self.assertEqual(state.snapshot()["requests"], 0)
            self.assertEqual(state.snapshot()["events"], [])
            sock.sendall.assert_not_called()
        finally:
            server.sockets.pop(sock)

    def test_transport_start_failure_closes_listener_and_marks_cleanup(self):
        state = F.AppHttpState(dict(FILES), "baseline")
        server = F._Server(state)
        with mock.patch.object(F.threading.Thread, "start", side_effect=RuntimeError("synthetic")):
            with self.assertRaises(RuntimeError):
                server.start()
        self.assertEqual(server.listener.fileno(), -1)
        self.assertTrue(server.cleanup_complete)
        self.assertEqual(state.errors, ["thread_start_failed"])


if __name__ == "__main__":
    unittest.main()
