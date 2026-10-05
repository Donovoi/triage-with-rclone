"""Synthetic loopback HTTP only: no rclone, account, OAuth or cloud execution."""
import base64
import hashlib
import http.client
import json
from pathlib import Path
import socket
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parents[1] / "provider-lab"))
try:
    import fixture_gcs as G
finally:
    sys.path.pop(0)


FILES = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
         "nested/space name.txt": b"Nested synthetic payload.\n", "nested/bytes.bin": bytes(range(256)) * 8}
TOKEN, WRONG = "synthetic_valid_token_12345", "synthetic_wrong_token_12345"
LIST = "/storage/v1/b/synthetic-bucket/o?alt=json&maxResults=1000&prefix=&prettyPrint=false"
META = "/storage/v1/b/synthetic-bucket/o/README-synthetic.txt?alt=json&prettyPrint=false"
MEDIA = "/media/README-synthetic.txt"
PATHS = {"README-synthetic.txt": "README-synthetic.txt", "nested/space name.txt": "nested%2Fspace%20name.txt",
         "nested/bytes.bin": "nested%2Fbytes.bin"}
UNSET = object()


class GcsFixtureTests(unittest.TestCase):
    def setUp(self):
        self.fixtures = []

    def tearDown(self):
        failures = []
        for fixture in self.fixtures:
            try:
                if not fixture.close():
                    failures.append("cleanup")
                snap = fixture.snapshot()["transport"]
                if (not snap["listener_closed"] or snap["sockets_open"] or snap["workers_alive"] or snap["timers_alive"]):
                    failures.append("resources")
            except Exception:
                failures.append("cleanup_exception")
        self.assertEqual(failures, [])

    def start(self, **kwargs):
        state = G.GcsState(dict(FILES), TOKEN, WRONG, **kwargs)
        fixture = G.GcsFixture(state)
        self.fixtures.append(fixture)
        return fixture

    def request(self, fixture, path=META, *, method="GET", auth=UNSET, extra=(), omit=()):
        if auth is UNSET:
            auth = "Bearer " + TOKEN
        connection = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=2)
        try:
            connection.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            headers = [("Host", f"127.0.0.1:{fixture.port}"), ("Content-Length", "0")]
            if auth is not None:
                headers.append(("Authorization", auth))
            for key, value in headers + list(extra):
                if key not in omit:
                    connection.putheader(key, value)
            connection.endheaders()
            response = connection.getresponse()
            result = response.status, dict(response.getheaders()), response.read(65537)
            # Response bytes may arrive before handler bookkeeping finishes.
            with fixture.state.lock:
                pass
            return result
        finally:
            connection.close()

    def raw(self, fixture, data):
        connection = socket.create_connection(("127.0.0.1", fixture.port), timeout=2)
        try:
            connection.sendall(data)
            connection.shutdown(socket.SHUT_WR)
            chunks = []
            try:
                while len(b"".join(chunks)) < 65537:
                    data = connection.recv(4096)
                    if not data:
                        break
                    chunks.append(data)
            except ConnectionResetError:
                pass
            return b"".join(chunks)
        finally:
            connection.close()

    def test_three_file_listing_has_exact_metadata_and_owned_media_authority(self):
        fixture = self.start()
        status, headers, body = self.request(fixture, LIST)
        self.assertEqual(status, 200)
        self.assertNotIn("Location", headers)
        actual = json.loads(body)
        expected = {"kind": "storage#objects", "items": []}
        for name, data in FILES.items():
            expected["items"].append({"kind": "storage#object", "bucket": "synthetic-bucket", "name": name,
                                      "size": str(len(data)), "md5Hash": base64.b64encode(hashlib.md5(data).digest()).decode(),
                                      "contentType": "application/octet-stream", "updated": "2024-01-01T00:00:00Z",
                                      "mediaLink": f"http://127.0.0.1:{fixture.port}/media/" + PATHS[name]})
        self.assertEqual(actual, expected)
        self.assertEqual(fixture.state.events, [("list", "")])
        self.assertEqual((fixture.state.requests, fixture.state.authenticated, fixture.state.payload_bytes), (1, 1, 0))
        self.assertTrue(fixture.state.source_preserved())

    def test_all_three_downloads_require_metadata_and_independent_bytes(self):
        expected_hashes = ("1e901527b93ae84dc9d95a8aa76bbc12d7d77dbf8ab449333c172cfc909c639e",
                           "e019c52fe70badce27affda5e408659399ff764985f07104029a42ade38125bd",
                           "10fc3c51a152e90e5b90319b601d92ccf37290ef53c35ff92507687d8a911a08")
        for (name, data), digest in zip(FILES.items(), expected_hashes):
            with self.subTest(member=name):
                fixture = self.start()
                path = "/storage/v1/b/synthetic-bucket/o/" + PATHS[name] + "?alt=json&prettyPrint=false"
                self.assertEqual(self.request(fixture, path)[0], 200)
                status, _, payload = self.request(fixture, "/media/" + PATHS[name])
                self.assertEqual((status, payload), (200, data))
                self.assertEqual(hashlib.sha256(payload).hexdigest(), digest)
                self.assertEqual(fixture.state.events, [("metadata", name), ("content", name)])
                self.assertEqual(fixture.state.payload_bytes, len(data))
                self.assertEqual(fixture.snapshot()["transport"]["failure_codes"], [])

    def test_missing_member_is_authenticated_404_and_no_content(self):
        fixture = self.start()
        path = "/storage/v1/b/synthetic-bucket/o/missing-synthetic-object.bin?alt=json&prettyPrint=false"
        status, _, body = self.request(fixture, path)
        self.assertEqual((status, json.loads(body)["error"]["code"]), (404, 404))
        self.assertEqual(fixture.state.events, [("missing", "missing-synthetic-object.bin")])
        self.assertEqual((fixture.state.missing, fixture.state.authenticated, fixture.state.payload_bytes), (1, 1, 0))

    def test_only_exact_wrong_token_on_known_metadata_counts_denial(self):
        fixture = self.start()
        status, _, body = self.request(fixture, auth="Bearer " + WRONG)
        self.assertEqual((status, json.loads(body)["error"]["errors"][0]["reason"]), (401, "authError"))
        self.assertEqual(fixture.state.events, [("auth_denied", "README-synthetic.txt")])
        self.assertEqual((fixture.state.auth_denied, fixture.state.authenticated, fixture.state.payload_bytes), (1, 0, 0))
        self.assertEqual(self.request(fixture, auth="Bearer " + WRONG)[0], 400)
        self.assertEqual(fixture.state.auth_denied, 1)

    def test_absent_arbitrary_and_wrong_route_tokens_are_not_auth_evidence(self):
        for auth, target in ((None, META), ("Bearer arbitrary-canary", META), ("Basic " + WRONG, META),
                             ("Bearer " + WRONG, LIST), ("Bearer " + WRONG, MEDIA)):
            with self.subTest(auth_case=auth is None, path=target):
                fixture = self.start()
                self.assertEqual(self.request(fixture, target, auth=auth)[0], 400)
                self.assertEqual((fixture.state.auth_denied, fixture.state.events, fixture.state.payload_bytes), (0, [], 0))

    def test_known_media_denial_requires_positive_metadata(self):
        fixture = self.start(deny_member="README-synthetic.txt")
        self.assertEqual(self.request(fixture, MEDIA)[0], 400)
        self.assertEqual((fixture.state.member_denied, fixture.state.events), (0, []))
        self.assertEqual(self.request(fixture)[0], 200)
        self.assertEqual(self.request(fixture, MEDIA)[0], 403)
        self.assertEqual(fixture.state.events, [("metadata", "README-synthetic.txt"), ("content_denied", "README-synthetic.txt")])
        self.assertEqual((fixture.state.member_denied, fixture.state.payload_bytes), (1, 0))

    def test_media_order_replay_and_member_substitution_rejected(self):
        for first, second in ((MEDIA, None), (META, META), (LIST, MEDIA), (META, "/media/nested%2Fbytes.bin")):
            fixture = self.start()
            if second is not None:
                self.assertEqual(self.request(fixture, first)[0], 200)
            self.assertEqual(self.request(fixture, second or first)[0], 400)
            self.assertEqual(fixture.state.payload_bytes, 0)
        fixture = self.start()
        self.request(fixture)
        self.assertEqual(self.request(fixture, MEDIA)[0], 200)
        self.assertEqual(self.request(fixture, MEDIA)[0], 400)
        self.assertEqual(fixture.state.payload_bytes, 62)

    def test_raw_routes_query_order_encoding_and_authority_are_closed(self):
        invalid = [META + "&alt=json", META + "&userProject=other", META.replace("alt=json&prettyPrint=false", "prettyPrint=false&alt=json"),
                   META.replace("synthetic-bucket", "other-bucket"), META.replace("README-synthetic.txt", "nested%2fbytes.bin"),
                   META.replace("README-synthetic.txt", "nested/bytes.bin"), META.replace("README-synthetic.txt", "../README-synthetic.txt"),
                   META.replace("README-synthetic.txt", "nested%252Fbytes.bin"), "/oauth2/token", "http://elsewhere.invalid" + META,
                   LIST + "&pageToken=next", LIST.replace("prefix=&", "prefix=nested%2F&")]
        for target in invalid:
            with self.subTest(target=target):
                fixture = self.start()
                self.assertEqual(self.request(fixture, target)[0], 400)
                self.assertEqual(fixture.state.events, [])

    def test_headers_duplicates_bodies_and_mutations_never_grant(self):
        for extra in (("Host", "elsewhere.invalid"), ("Authorization", "Bearer " + TOKEN), ("Range", "bytes=0-1"),
                      ("Cookie", "canary"), ("Proxy-Authorization", "canary"), ("Transfer-Encoding", "chunked"),
                      ("X-Unknown", "canary"), ("Content-Length", "1")):
            fixture = self.start()
            self.assertEqual(self.request(fixture, extra=(extra,))[0], 400)
            self.assertEqual(fixture.state.events, [])
        # A separate raw framing check retains a positive declared length.
        fixture = self.start()
        wire = f"GET {META} HTTP/1.1\r\nHost: 127.0.0.1:{fixture.port}\r\nAuthorization: Bearer {TOKEN}\r\nContent-Length: 1\r\n\r\n"
        self.raw(fixture, wire.encode())
        fixture.close()
        self.assertEqual((fixture.state.rejected_payload_bytes, fixture.state.events), (1, []))
        for method in ("POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
            fixture = self.start()
            self.assertEqual(self.request(fixture, method=method)[0], 405)
            self.assertEqual((fixture.state.rejected_mutations, fixture.state.events, fixture.state.payload_bytes), (1, [], 0))

    def test_malformed_and_truncated_crlf_never_dispatch(self):
        for suffix in (b"Authorization : Bearer canary\r\n\r\n", b": hidden\r\n\r\n", b"Authorization: hidden\r\n",
                       b"Authorization: hidden\n\n", b"\tcontinued: hidden\r\n\r\n", b"X: " + b"x" * 9000 + b"\r\n\r\n"):
            fixture = self.start()
            prefix = f"GET {META} HTTP/1.1\r\nHost: 127.0.0.1:{fixture.port}\r\n".encode()
            self.raw(fixture, prefix + suffix)
            fixture.close()
            self.assertEqual((fixture.state.events, fixture.state.auth_denied, fixture.state.payload_bytes), ([], 0, 0))
            self.assertGreater(fixture.state.unexpected, 0)

    def test_request_and_response_limits_are_sticky(self):
        fixture = self.start()
        fixture.state.request_limit = 0
        self.assertEqual(self.request(fixture)[0], 429)
        self.assertTrue(fixture.state.budget_exceeded)
        self.assertEqual(fixture.state.events, [])
        fixture = self.start()
        fixture.state.byte_limit = 1
        with self.assertRaises(http.client.RemoteDisconnected):
            self.request(fixture)
        fixture.close()
        self.assertTrue(fixture.state.budget_exceeded)
        self.assertEqual((fixture.state.response_bytes, fixture.state.payload_bytes), (0, 0))

    def test_connection_admission_is_bounded(self):
        for limit in ("connection_limit", "active_connection_limit"):
            fixture = self.start()
            setattr(fixture.state, limit, 0)
            with self.assertRaises((ConnectionResetError, http.client.RemoteDisconnected)):
                self.request(fixture)
            fixture.close()
            self.assertEqual(fixture.state.admission_denied, 1)
            self.assertTrue(fixture.state.budget_exceeded)
            self.assertEqual(fixture.state.events, [])

    def test_incomplete_payload_write_cannot_count_completed_content(self):
        state = G.GcsState(FILES, TOKEN, WRONG)
        handler = object.__new__(G._GcsHandler)
        handler.server = mock.Mock(state=state)
        handler.wfile = mock.Mock()
        handler.wfile.flush.side_effect = OSError("private-socket-diagnostic")
        handler.send_response = mock.Mock()
        handler.send_header = mock.Mock()
        handler.end_headers = mock.Mock()
        with self.assertRaises(OSError):
            handler._reply(200, FILES["README-synthetic.txt"], payload=True)
        self.assertEqual((state.response_bytes, state.payload_bytes), (62, 0))

    def test_context_manager_cleanup_failure_propagates(self):
        fixture = self.start()
        with mock.patch.object(G, "GcsFixture", return_value=fixture), mock.patch.object(fixture, "close", return_value=False):
            with self.assertRaisesRegex(G.GcsError, "^gcs_cleanup_failed$"):
                with G.serve_gcs(fixture.state):
                    pass

    def test_partial_header_deadline_and_early_close_reap_everything(self):
        for close_early in (False, True):
            fixture = self.start()
            fixture.state.request_timeout = 0.08
            connection = socket.create_connection(("127.0.0.1", fixture.port), timeout=2)
            try:
                connection.sendall(f"GET {META} HTTP/1.1\r\nHost:".encode())
                if close_early:
                    fixture.close()
                else:
                    self.assertEqual(connection.recv(64), b"")
                    fixture.close()
                    self.assertTrue(fixture.state.budget_exceeded)
                self.assertEqual(fixture.state.events, [])
                self.assertTrue(fixture.cleanup_complete)
            finally:
                connection.close()

    def test_lifetime_stops_listener_with_sticky_failure(self):
        fixture = self.start()
        fixture._expire()
        fixture.close()
        self.assertEqual(fixture.snapshot()["transport"]["failure_codes"], ["gcs_lifetime_exceeded"])
        self.assertTrue(fixture.state.budget_exceeded)
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", fixture.port), timeout=0.2)

    def test_initial_state_and_same_state_reuse_rejected(self):
        for files, token, wrong, deny in (({}, TOKEN, WRONG, None), (dict(FILES, extra=b""), TOKEN, WRONG, None),
                                        (dict(FILES, **{"README-synthetic.txt": b"changed"}), TOKEN, WRONG, None),
                                        (FILES, "", WRONG, None), (FILES, TOKEN, TOKEN, None), (FILES, TOKEN, WRONG, "nested/bytes.bin")):
            with self.assertRaisesRegex(G.GcsError, "^gcs_invalid_fixture_state$"):
                G.GcsState(files, token, wrong, deny)
        fixture = self.start()
        fixture.close()
        with self.assertRaises(G.GcsError):
            G.GcsFixture(fixture.state)

    def test_immutable_source_auth_and_metadata_checked_at_teardown(self):
        mutations = [lambda s: s.files.update({"README-synthetic.txt": b"changed"}),
                     lambda s: s.metadata["README-synthetic.txt"].update({"mediaLink": "http://elsewhere.invalid"}),
                     lambda s: setattr(s, "token", "other_synthetic_token"), lambda s: setattr(s, "wrong_token", TOKEN),
                     lambda s: setattr(s, "deny_member", "README-synthetic.txt")]
        for mutation in mutations:
            state = G.GcsState(FILES, TOKEN, WRONG)
            with self.assertRaisesRegex(G.GcsError, "^gcs_source_changed$"):
                with G.serve_gcs(state) as fixture:
                    self.fixtures.append(fixture)
                    mutation(state)
                    self.assertEqual(self.request(fixture)[0], 400)
            self.assertFalse(state.source_preserved())
            self.assertTrue(state.cleanup_complete)

    def test_snapshot_omits_auth_values_and_transport_failure_is_sticky(self):
        fixture = self.start()
        self.request(fixture, auth="Bearer arbitrary-private-canary")
        fixture.server.handle_error(None, None)
        fixture.close()
        snapshot = fixture.snapshot()
        wire = json.dumps(snapshot)
        for secret in (TOKEN, WRONG, "arbitrary-private-canary"):
            self.assertNotIn(secret, wire)
        self.assertEqual(snapshot["transport"]["failure_codes"], ["gcs_handler_failed"])
        self.assertTrue(snapshot["cleanup_complete"])

    def test_start_failures_close_bound_listener(self):
        captured = []
        original = G._GcsServer

        def server(state):
            result = original(state)
            captured.append(result)
            return result

        for target in ("thread", "timer"):
            state = G.GcsState(FILES, TOKEN, WRONG)
            patch_target = G.threading.Thread if target == "thread" else G.threading.Timer
            with mock.patch.object(G, "_GcsServer", side_effect=server), mock.patch.object(patch_target, "start", side_effect=RuntimeError("private")):
                with self.assertRaisesRegex(G.GcsError, "^gcs_start_failed$"):
                    G.GcsFixture(state)
            self.assertEqual(captured[-1].socket.fileno(), -1)
            self.assertTrue(state.cleanup_complete)

    def test_worker_start_failure_closes_accepted_socket(self):
        fixture = self.start()
        server_socket, peer = socket.socketpair()
        fixture.state.sockets.add(server_socket)
        try:
            with mock.patch.object(G.threading.Thread, "start", side_effect=RuntimeError("private")):
                with self.assertRaises(RuntimeError):
                    fixture.server.process_request(server_socket, ("127.0.0.1", 1))
            self.assertEqual(server_socket.fileno(), -1)
            self.assertFalse(fixture.state.sockets)
            self.assertIn("gcs_worker_start_failed", fixture.state.failure_codes)
        finally:
            peer.close()


if __name__ == "__main__":
    unittest.main()
