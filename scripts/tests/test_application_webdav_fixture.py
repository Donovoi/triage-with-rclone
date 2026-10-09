"""Pure byte-stream/state tests: socket, process and thread starts are forbidden.

These exercise the real fixture parser/dispatcher/serializer and ownership unwind
with in-memory sockets. They do not establish HTTP/native application acceptance.
"""
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import socket
import threading
import time
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

PATH = Path(__file__).resolve().parents[1] / "application-lab" / "fixture_webdav.py"
with mock.patch("socket.socket", side_effect=AssertionError("socket_forbidden")), \
        mock.patch("subprocess.Popen", side_effect=AssertionError("process_forbidden")):
    SPEC = importlib.util.spec_from_file_location("application_webdav_fixture_test", PATH)
    F = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(F)

FILES = {"README-synthetic.txt": b"synthetic application fixture\n",
         "large/cancel.bin": bytes(range(256)) * 8192,
         "nested/binary.bin": bytes(range(256)),
         "nested/spaced name.txt": b"spaces remain exact\n"}
HASHES = {"README-synthetic.txt": "64d5b40a5f4773b14940a6ce1dd57cf87b44ce5940c097088732ffc71be280cf",
          "large/cancel.bin": "91d3beb88a9b2f778a6c44a1c53b63d3c79931845a9aef84b3fb414610bd1938",
          "nested/binary.bin": "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880",
          "nested/spaced name.txt": "0c6308d568f8ec30fbf044baac7827edac83a2465a60439ff653e277a5d9619e"}
XML_REQUEST = (b'<?xml version="1.0"?>\n<d:propfind xmlns:d="DAV:">\n <d:prop>\n'
               b'  <d:displayname/>\n  <d:getlastmodified/>\n  <d:getcontentlength/>\n'
               b'  <d:resourcetype/>\n </d:prop>\n</d:propfind>\n')
USER, A, WRONG, B = "synthetic-user", "A-synthetic-secret", "wrong-synthetic-secret", "B-synthetic-secret"


class FakeSocket:
    def __init__(self, incoming=b""):
        self.stream = io.BytesIO(incoming)
        self.output = bytearray()
        self.closed = False

    def fileno(self):
        return -1 if self.closed else 42

    def settimeout(self, _seconds):
        pass

    def makefile(self, *_args, **_kwargs):
        return self.stream

    def recv(self, size, _flags=0):
        position = self.stream.tell()
        value = self.stream.read(size)
        self.stream.seek(position)
        return value

    def sendall(self, value):
        self.output.extend(value)

    def shutdown(self, _how):
        pass

    def close(self):
        self.closed = True


def basic(password=A, user=USER):
    return "Basic " + base64.b64encode((user + ":" + password).encode("ascii")).decode("ascii")


class WebDavFixtureTests(unittest.TestCase):
    def setUp(self):
        for name in ("socket.socket", "socket.create_connection", "subprocess.Popen", "threading.Thread.start"):
            patch = mock.patch(name, side_effect=AssertionError("live_boundary_forbidden"))
            patch.start()
            self.addCleanup(patch.stop)

    def state_server(self, invocation="acquisition", released=True):
        state = F.AppWebDavState(dict(FILES), invocation, USER, A, wrong_password=WRONG, password_b=B)
        server = object.__new__(F._Server)
        server.state = state
        server.lock = threading.RLock()
        server.stopping = threading.Event()
        server.sockets, server.workers = {}, []
        server.accepted = 0
        server.cleanup_complete = False
        server.deadline = time.monotonic() + 180
        server.acceptor = server.watchdog = None
        server.listener = FakeSocket()
        server.port = 32123
        server.endpoint = "http://127.0.0.1:32123/"
        state._transport = server
        if released:
            state.release_observation()
        return state, server

    def wire(self, path="README-synthetic.txt", method="PROPFIND", password=A, depth="0", extra=None, body=None):
        payload = XML_REQUEST if method == "PROPFIND" and body is None else (body or b"")
        headers = {"Host": "127.0.0.1:32123", "Referer": "http://127.0.0.1:32123/",
                   "Authorization": basic(password), "Depth": depth, "User-Agent": "rclone/v1.75.2"}
        if method == "PROPFIND" or payload:
            headers["Content-Length"] = str(len(payload))
        headers.update(extra or {})
        return ((method + " /" + path + " HTTP/1.1\r\n" + "".join(k + ": " + v + "\r\n" for k, v in headers.items()) + "\r\n").encode("ascii") + payload)

    def run_wire(self, server, wire):
        sock = FakeSocket(wire)
        server.sockets[sock] = min(server.deadline, time.monotonic() + 15)
        server.accepted += 1
        with mock.patch.object(F.select, "select", side_effect=lambda readers, *_: ([s for s in readers if s.recv(1)], [], [])):
            server._worker(sock)
        self.assertTrue(sock.closed)
        self.assertNotIn(sock, server.sockets)
        self.assertEqual(server.state._active_requests, 0)
        return bytes(sock.output)

    def request(self, server, **kwargs):
        result = self.run_wire(server, self.wire(**kwargs))
        head, separator, body = result.partition(b"\r\n\r\n")
        self.assertEqual(separator, b"\r\n\r\n")
        rows = head.decode("ascii").split("\r\n")
        headers = dict(line.split(": ", 1) for line in rows[1:])
        return int(rows[0].split()[1]), headers, body

    def metadata(self, server, member="README-synthetic.txt", password=A):
        return self.request(server, path=member.replace(" ", "%20"), password=password)

    def read(self, server, member="README-synthetic.txt", password=A, extra=None):
        return self.request(server, path=member.replace(" ", "%20"), method="GET", password=password, extra=extra)

    def test_independent_fixed_manifest_and_loaded_transport_digest(self):
        self.assertEqual(F.PROPFIND_BODY, XML_REQUEST)
        self.assertEqual({k: hashlib.sha256(v).hexdigest() for k, v in FILES.items()}, HASHES)
        self.assertEqual(F.loaded_http_source_sha256, hashlib.sha256(PATH.with_name("fixture_http.py").read_bytes()).hexdigest())
        for changed in ({}, {**FILES, "extra": b"x"}, {**FILES, "README-synthetic.txt": b"x"}):
            with self.assertRaisesRegex(ValueError, "^input_invalid$"):
                F.AppWebDavState(changed, "listing", USER, A, wrong_password=WRONG, password_b=B)

    def test_literal_recursive_xml_inventory_and_no_remote_hash(self):
        state, server = self.state_server("listing")
        seen = {}
        ns = {"d": "DAV:"}
        for directory, expected in (("", {"/", "/README-synthetic.txt", "/large/", "/nested/"}),
                                    ("large/", {"/large/", "/large/cancel.bin"}),
                                    ("nested/", {"/nested/", "/nested/binary.bin", "/nested/spaced%20name.txt"})):
            status, headers, body = self.request(server, path=directory, depth="1")
            self.assertEqual(status, 207)
            self.assertEqual(int(headers["Content-Length"]), len(body))
            root = ET.fromstring(body)
            self.assertEqual(root.tag, "{DAV:}multistatus")
            hrefs = set()
            for row in root.findall("d:response", ns):
                href = row.findtext("d:href", namespaces=ns)
                hrefs.add(href)
                self.assertEqual(row.findtext("d:propstat/d:status", namespaces=ns), "HTTP/1.1 200 OK")
                prop = row.find("d:propstat/d:prop", ns)
                self.assertEqual({node.tag for node in prop}, {"{DAV:}" + name for name in
                    ("displayname", "getlastmodified", "getcontentlength", "resourcetype")})
                self.assertEqual(prop.findtext("d:getlastmodified", namespaces=ns), "Thu, 02 Jan 2025 03:04:05 GMT")
                is_dir = prop.find("d:resourcetype/d:collection", ns) is not None
                seen[href] = (int(prop.findtext("d:getcontentlength", namespaces=ns)), is_dir)
            self.assertEqual(hrefs, expected)
        self.assertEqual(seen, {"/": (0, True), "/README-synthetic.txt": (30, False),
            "/large/": (0, True), "/nested/": (0, True), "/large/cancel.bin": (2097152, False),
            "/nested/binary.bin": (256, False), "/nested/spaced%20name.txt": (20, False)})
        self.assertEqual(state.counters["payload_bytes"], 0)
        self.assertEqual(state.errors, [])

    def test_full_acquisition_all_four_independent_hashes_and_metadata_before_content(self):
        state, server = self.state_server()
        for member, expected in HASHES.items():
            self.assertEqual(self.metadata(server, member)[0], 207)
            status, headers, body = self.read(server, member)
            self.assertEqual(status, 200)
            self.assertEqual(hashlib.sha256(body).hexdigest(), expected)
            self.assertEqual(len(body), int(headers["Content-Length"]))
        self.assertEqual(state.counters["payload_bytes"], 2097458)
        self.assertEqual(state.counters["completed_payload_bytes"], 2097458)
        self.assertEqual(state._completed, set(FILES))
        self.assertTrue(state.source_preserved())
        self.assertEqual(state.errors, [])

    def test_mismatch_serves_unchanged_source_not_queue_expectation(self):
        state, server = self.state_server("mismatch")
        self.metadata(server)
        self.assertEqual(self.read(server)[2], b"synthetic application fixture\n")
        self.assertEqual(state._completed, {"README-synthetic.txt"})
        self.assertEqual(state.errors, [])

    def test_missing_is_exact_authenticated_metadata_404_without_object_bytes(self):
        state, server = self.state_server("missing")
        status, headers, body = self.metadata(server, "missing-synthetic.txt")
        self.assertEqual((status, body, headers["Content-Length"]), (404, b"", "0"))
        self.assertEqual(state.events[-2:], [[1, "basic_accepted", 7], [1, "missing", 7]])
        self.assertEqual((state.counters["missing"], state.counters["auth_denied"], state.counters["payload_bytes"]), (1, 0, 0))

    def test_wrong_credentials_hold_known_attempt_before_401(self):
        state, server = self.state_server("wrong_credentials", released=False)
        def hold(sock, cancel=False):
            self.assertFalse(cancel)
            self.assertTrue(state.observation_started.is_set())
            self.assertEqual(state.counters["credential_attempts"], 1)
            self.assertEqual(state.counters["auth_denied"], 0)
            self.assertEqual(sock.output, b"")
            state.release_observation()
        with mock.patch.object(server, "_wait", side_effect=hold) as waited:
            status, headers, body = self.metadata(server, password=WRONG)
        waited.assert_called_once()
        self.assertEqual((status, body), (401, b""))
        self.assertEqual(headers["WWW-Authenticate"], 'Basic realm="synthetic"')
        self.assertEqual((state.counters["auth_denied"], state.counters["authenticated"], state.counters["payload_bytes"]), (1, 0, 0))

    def test_unexpected_or_malformed_credentials_never_open_observation(self):
        for auth in (basic(B), basic(A, "different-user"), "Bearer synthetic", "basic " + basic()[6:],
                     "Basic YTpi====", "Basic dXNlcg==", "Basic " + "a" * 400, ""):
            with self.subTest(auth_kind=len(auth)):
                state, server = self.state_server(released=False)
                with mock.patch.object(server, "_wait", side_effect=AssertionError("hold_forbidden")):
                    status, _, body = self.request(server, extra={"Authorization": auth})
                self.assertEqual((status, body), (400, b""))
                self.assertFalse(state.observation_started.is_set())
                self.assertEqual(state.errors, ["credentials_invalid"])
                self.assertEqual(state.counters["payload_bytes"], 0)

    def test_shared_three_epoch_fixture_keeps_deadline_and_closed_event_history(self):
        state, server = self.state_server("accepted_a")
        original_deadline = server.deadline
        self.metadata(server)
        self.read(server)
        state.advance_epoch("revoked_a", successful=True, reaped=True)
        state.release_observation()
        self.assertEqual(self.metadata(server)[0], 401)
        state.advance_epoch("replacement_b", successful=True, reaped=True)
        state.release_observation()
        self.assertEqual(self.metadata(server, password=B)[0], 207)
        self.assertEqual(self.read(server, password=B)[2], FILES["README-synthetic.txt"])
        self.assertEqual(server.deadline, original_deadline)
        self.assertEqual([h["invocation"] for h in state.history], ["accepted_a", "revoked_a"])
        self.assertEqual([h["payload_bytes"] for h in state.history], [30, 0])
        self.assertEqual(state.snapshot()["total_requests"], 5)
        self.assertEqual({e[0] for e in state.events}, {1, 2, 3})
        self.assertEqual(state.errors, [])

    def test_epoch_advance_requires_complete_read_success_reap_idle_and_no_failures(self):
        for mutation in ("no_read", "operation_failure", "not_reaped", "active", "socket", "expired", "error", "wrong_next"):
            with self.subTest(mutation=mutation):
                state, server = self.state_server("accepted_a")
                self.metadata(server)
                if mutation != "no_read":
                    self.read(server)
                if mutation == "active":
                    state._active_requests = 1
                if mutation == "socket":
                    server.sockets[FakeSocket()] = server.deadline
                if mutation == "expired":
                    server.deadline = 0
                if mutation == "error":
                    state._error("request_timeout")
                before = server.deadline
                with self.assertRaisesRegex(F.FixtureError, "^epoch_failed$"):
                    state.advance_epoch("replacement_b" if mutation == "wrong_next" else "revoked_a",
                                        successful=mutation != "operation_failure", reaped=mutation != "not_reaped")
                self.assertEqual(state.invocation, "accepted_a")
                self.assertEqual(server.deadline, before)
                self.assertTrue(state.snapshot()["transition_failed"])
                state._active_requests = 0
                server.sockets.clear()
                with self.assertRaises(F.FixtureError):
                    state.advance_epoch("revoked_a", successful=True, reaped=True)

    def test_replacement_rejects_old_credentials_without_resetting_prior_denial(self):
        state, server = self.state_server("accepted_a")
        self.metadata(server)
        self.read(server)
        state.advance_epoch("revoked_a", successful=True, reaped=True)
        state.release_observation()
        self.metadata(server)
        state.advance_epoch("replacement_b", successful=True, reaped=True)
        self.assertEqual(self.metadata(server)[0], 400)
        self.assertFalse(state.observation_started.is_set())
        self.assertEqual(state.history[1]["auth_denied"], 1)
        self.assertEqual(state.errors, ["credentials_invalid"])

    def test_permission_denial_differs_from_credential_denial(self):
        state, server = self.state_server("permission_denied")
        status, _, body = self.metadata(server)
        self.assertEqual((status, body), (403, b""))
        self.assertEqual((state.counters["authenticated"], state.counters["auth_denied"], state.counters["permission_denied"]), (1, 0, 1))
        self.assertEqual(state.events[-1], [1, "permission_denied", 1])
        self.assertEqual(state.counters["payload_bytes"], 0)

    def test_every_truncation_retry_and_exact_resume_stays_incomplete(self):
        state, server = self.state_server("truncated_transfer")
        self.metadata(server)
        offset = 0
        for _ in range(12):
            extra = {"Range": f"bytes={offset}-29"} if offset else None
            status, headers, body = self.read(server, extra=extra)
            self.assertEqual(status, 206 if offset else 200)
            self.assertLess(len(body), int(headers["Content-Length"]))
            self.assertEqual(body, FILES["README-synthetic.txt"][offset:offset + len(body)])
            if offset:
                self.assertEqual(headers["Content-Range"], f"bytes {offset}-29/30")
            offset += len(body)
        self.assertEqual(offset, 29)
        self.assertEqual(state.counters["truncated"], 12)
        self.assertEqual(state.counters["completed_payload_bytes"], 0)
        self.assertEqual(state._completed, set())
        self.assertEqual(state.errors, [])

    def test_truncation_source_bounded_nested_retry_budget_never_repairs_suffix(self):
        state, server = self.state_server("truncated_transfer")
        for _ in range(10):
            self.metadata(server)
            offset = 0
            for _ in range(10):
                _, headers, body = self.read(server, extra={"Range": f"bytes={offset}-29"} if offset else None)
                self.assertLess(len(body), int(headers["Content-Length"]))
                offset += len(body)
            self.assertEqual(offset, 29)
        self.assertEqual(state.counters["truncated"], 100)
        self.assertEqual(state._total_requests, 110)
        self.assertEqual(state.counters["completed_payload_bytes"], 0)
        self.assertEqual(state.errors, [])

    def test_range_refusal_is_bounded_and_never_serves_invalid_suffix(self):
        for value in ("bytes=0-29", "bytes=1-", "bytes=-2", "bytes=1-28", "bytes=1-30", "bytes=30-29",
                      "bytes=01-29", "bytes=1-29,2-29", "bytes=" + "9" * 5000 + "-29"):
            with self.subTest(length=len(value)):
                state, server = self.state_server()
                self.metadata(server)
                status, _, body = self.read(server, extra={"Range": value})
                self.assertEqual((status, body), (400, b""))
                self.assertEqual(state.errors, ["range_invalid"])
                self.assertEqual(state.counters["payload_bytes"], 0)

    def test_cancel_prefix_disconnection_is_distinct_from_teardown_release(self):
        for disconnected in (True, False):
            state, server = self.state_server("cancellation")
            self.metadata(server, "large/cancel.bin")
            def held(sock, cancel=False):
                self.assertTrue(cancel)
                self.assertTrue(state.cancel_started.is_set())
                self.assertEqual(state.counters["payload_bytes"], 65536)
                if disconnected:
                    with mock.patch.object(F._http.select, "select", return_value=([sock], [], [])):
                        F._http._Server._wait(server, sock, cancel=True)
                else:
                    state.release_cancel()
                    F._http._Server._wait(server, sock, cancel=True)
            with mock.patch.object(server, "_wait", side_effect=held):
                status, headers, body = self.read(server, "large/cancel.bin")
            self.assertEqual((status, len(body), headers["Content-Length"]), (200, 65536, "2097152"))
            self.assertEqual(state.cancel_disconnected, disconnected)
            self.assertEqual(state._cancel_release.is_set(), not disconnected)
            self.assertEqual(state.counters["completed_payload_bytes"], 0)
            self.assertEqual(state._completed, set())

    def test_cancel_replay_rejected_and_never_sends_remainder(self):
        state, server = self.state_server("cancellation")
        state.release_cancel()
        self.metadata(server, "large/cancel.bin")
        self.read(server, "large/cancel.bin")
        status, _, body = self.read(server, "large/cancel.bin")
        self.assertEqual((status, body), (400, b""))
        self.assertEqual(state.errors, ["cancel_replayed"])
        self.assertEqual(state.counters["payload_bytes"], 65536)

    def test_headers_raw_paths_body_and_method_errors_never_authenticate(self):
        valid = self.wire()
        variants = [valid.replace(b"Host: 127.0.0.1:32123", b"Host: example.invalid"),
                    valid.replace(b"Referer: http://127.0.0.1:32123/", b"Referer: http://127.0.0.1:1/"),
                    valid.replace(b"Depth: 0", b"Depth: infinity"),
                    valid.replace(b"Depth: 0", b"Depth: 0\r\nDepth: 0"),
                    valid.replace(b"Depth: 0", b"Depth: 0\r\nTransfer-Encoding: chunked"),
                    valid.replace(b"Depth: 0", b"Depth: 0\r\nContent-Type: application/xml"),
                    valid.replace(b"/README-synthetic.txt HTTP", b"//README-synthetic.txt HTTP"),
                    valid.replace(b"/README-synthetic.txt HTTP", b"/README-synthetic.txt# HTTP"),
                    valid.replace(b"/README-synthetic.txt HTTP", b"/%52EADME-synthetic.txt HTTP"),
                    valid.replace(b"/README-synthetic.txt HTTP", b"/../README-synthetic.txt HTTP"),
                    valid.replace(b"/README-synthetic.txt HTTP", b"/README-synthetic.txt?x=1 HTTP"),
                    valid[:-1], valid.replace(b"<d:displayname/>", b"<d:displaynamX/>"),
                    self.wire(method="DELETE"), self.wire(method="HEAD")]
        for index, wire in enumerate(variants):
            with self.subTest(index=index):
                state, server = self.state_server(released=False)
                output = self.run_wire(server, wire)
                self.assertRegex(output, rb"^HTTP/1.1 (400|405) ")
                self.assertFalse(state.observation_started.is_set())
                self.assertEqual(state.counters["authenticated"], 0)
                self.assertEqual(state.counters["payload_bytes"], 0)
                self.assertTrue(state.errors)

    def test_trailing_request_or_body_is_refused(self):
        for trailing in (b"x", self.wire(method="GET")):
            state, server = self.state_server()
            output = self.run_wire(server, self.wire() + trailing)
            self.assertTrue(output.startswith(b"HTTP/1.1 400 "))
            self.assertEqual(state.errors, ["request_body_rejected"])
            self.assertEqual(state.counters["authenticated"], 0)

    def test_metadata_required_and_scenario_paths_are_closed(self):
        for invocation, member, method in (("acquisition", "README-synthetic.txt", "GET"),
                                           ("missing", "README-synthetic.txt", "PROPFIND"),
                                           ("permission_denied", "nested/binary.bin", "PROPFIND"),
                                           ("wrong_credentials", "", "PROPFIND")):
            state, server = self.state_server(invocation)
            self.assertEqual(self.request(server, path=member, method=method)[0], 400)
            self.assertEqual(state.counters["payload_bytes"], 0)
            self.assertTrue(state.errors)

    def test_preservation_request_and_response_budgets_fail_closed(self):
        for mutation in ("source", "requests", "bytes"):
            state, server = self.state_server()
            if mutation == "source":
                state.files = {**FILES, "README-synthetic.txt": b"changed"}
            elif mutation == "requests":
                state._total_requests = 128
            else:
                state._allocated_bytes = 32 * 1024 * 1024
            self.assertEqual(self.metadata(server)[0], 400)
            self.assertIn({"source": "source_changed", "requests": "request_limit", "bytes": "byte_limit"}[mutation], state.errors)
            self.assertEqual(state.counters["payload_bytes"], 0)

    def test_watchdog_absolute_deadline_closes_slow_or_idle_owned_requests(self):
        state, server = self.state_server()
        sock = FakeSocket()
        server.sockets[sock] = 99
        with mock.patch.object(server.stopping, "wait", side_effect=[False, True]), \
                mock.patch.object(F._http.time, "monotonic", return_value=100):
            server._watch()
        self.assertTrue(sock.closed)
        self.assertEqual(state.errors, ["request_timeout"])
        self.assertEqual(state.counters["payload_bytes"], 0)

    def test_request_body_connection_failure_is_counted_and_owned_socket_closed(self):
        state, server = self.state_server()
        sock = FakeSocket(self.wire())
        server.sockets[sock] = server.deadline
        with mock.patch.object(sock.stream, "read", side_effect=TimeoutError), \
                mock.patch.object(F.select, "select", return_value=([], [], [])):
            server._worker(sock)
        self.assertTrue(sock.closed)
        self.assertEqual(state.errors, ["connection_failed"])
        self.assertEqual(state._active_requests, 0)
        self.assertFalse(state.observation_started.is_set())

    def test_transport_admission_preserves_total_connection_budget(self):
        state, server = self.state_server()
        incoming = FakeSocket()
        server.accepted = 128
        server.listener.accept = mock.Mock(return_value=(incoming, ("127.0.0.1", 1234)))
        server._accept()
        self.assertTrue(incoming.closed)
        self.assertTrue(server.listener.closed)
        self.assertEqual(state.errors, ["admission_limit"])

    def test_cleanup_proof_requires_all_owned_threads_and_source_preservation(self):
        for alive in (False, True):
            state, server = self.state_server()
            worker = mock.Mock(ident=1)
            worker.is_alive.return_value = alive
            server.workers = [worker]
            if alive:
                with self.assertRaisesRegex(F.FixtureError, "^cleanup_failed$"):
                    server.close()
            else:
                server.close()
            self.assertEqual(server.cleanup_complete, not alive)
            self.assertTrue(server.listener.closed)
            self.assertTrue(state._observation_release.is_set())
            self.assertTrue(state._cancel_release.is_set())
            self.assertFalse(state.cancel_disconnected)
            worker.join.assert_called_once()

    def test_context_constructor_and_start_failure_never_reuse_state(self):
        state = F.AppWebDavState(dict(FILES), "listing", USER, A, wrong_password=WRONG, password_b=B)
        with mock.patch.object(F, "_Server", side_effect=RuntimeError("private canary")):
            with self.assertRaises(RuntimeError):
                with F.serve_webdav(state):
                    self.fail("must_not_yield")
        self.assertTrue(state.snapshot()["transport_attempted"])
        self.assertIsNone(state.snapshot()["transport"])
        with self.assertRaisesRegex(ValueError, "^state_reused$"):
            with F.serve_webdav(state):
                self.fail("must_not_yield")
        state, server = self.state_server()
        with mock.patch.object(F, "_Server", return_value=server), \
                mock.patch.object(server, "start", side_effect=F.FixtureError("thread_start_failed")):
            with self.assertRaises(F.FixtureError):
                with F.serve_webdav(state):
                    self.fail("must_not_yield")
        self.assertTrue(server.cleanup_complete)

    def test_unconfirmed_socket_close_retains_owned_inventory_and_blocks_epoch(self):
        state, server = self.state_server("accepted_a")
        sock = FakeSocket(self.wire())
        server.sockets[sock] = server.deadline
        with mock.patch.object(sock, "close", side_effect=OSError("private path")), \
                mock.patch.object(F.select, "select", return_value=([], [], [])):
            server._worker(sock)
        self.assertIn(sock, server.sockets)
        self.assertEqual(state._active_requests, 1)
        self.assertEqual(state.errors, ["cleanup_failed"])
        with self.assertRaisesRegex(F.FixtureError, "^epoch_failed$"):
            state.advance_epoch("revoked_a", successful=True, reaped=True)
        with self.assertRaisesRegex(F.FixtureError, "^cleanup_failed$"):
            server.close()
        self.assertFalse(server.cleanup_complete)

    def test_public_snapshots_never_include_credentials_endpoint_body_or_raw_error(self):
        state, server = self.state_server("wrong_credentials")
        self.metadata(server, password=WRONG)
        state._error("private-canary-password-path")
        serialized = json.dumps(state.snapshot(), sort_keys=True)
        for forbidden in (USER, A, B, WRONG, basic(WRONG), server.endpoint, "README", "private-canary", "<?xml"):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(state.errors, ["worker_failed"])
        self.assertEqual(state.events, [[1, "observation", 1], [1, "basic_denied", 1]])


if __name__ == "__main__":
    unittest.main()
