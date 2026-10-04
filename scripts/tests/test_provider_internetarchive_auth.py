"""Protected synthetic LOW HTTP requests only; never native rclone or cloud."""
import copy
import hashlib
import http.client
import json
from pathlib import Path
import socket
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parents[1] / "provider-lab"))
try:
    import fixture_servers as F
finally:
    sys.path.pop(0)

KEY = "synthetic_access_key_1234"
SECRET = "synthetic_correct_secret_1234"
WRONG = "synthetic_wrong_secret_1234"
META = "/front/metadata/synthetic-item"
CONTENT = "/front/download/synthetic-item/README-synthetic.txt"
PAYLOAD = b"Synthetic provider protocol fixture. No account or user data.\n"
EXPECTED_SHA256 = hashlib.sha256(PAYLOAD).hexdigest()
UNSET = object()


class InternetArchiveLowTests(unittest.TestCase):
    def state(self, mode="normal", auth_case="valid"):
        return F.InternetArchiveLowState(KEY, SECRET, WRONG, mode, auth_case)

    def request(self, port, target=META, *, auth=UNSET, method="GET", extra=(), omit=(), body=b""):
        if auth is UNSET:
            auth = "LOW " + KEY + ":" + SECRET
        client = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        try:
            client.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
            headers = [("Host", f"127.0.0.1:{port}"), ("Content-Length", str(len(body)))]
            if auth is not None:
                headers.append(("Authorization", auth))
            for name, value in headers:
                if name not in omit:
                    client.putheader(name, value)
            for name, value in extra:
                client.putheader(name, value)
            client.endheaders(body)
            response = client.getresponse()
            return response.status, dict(response.getheaders()), response.read(65537)
        finally:
            client.close()

    def assert_closed(self, state, port):
        self.assertTrue(state.cleanup_complete)
        self.assertFalse(state.sockets)
        with socket.socket() as probe:
            self.assertNotEqual(probe.connect_ex(("127.0.0.1", port)), 0)

    def metadata(self, state, port):
        for _ in range(2):
            status, headers, body = self.request(port)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body), state.metadata)
            self.assertNotIn("Location", headers)

    def test_valid_full_metadata_and_known_member_independent_bytes(self):
        state = self.state()
        anonymous = F.InternetArchiveState()
        self.assertEqual(state.metadata, anonymous.metadata)
        self.assertEqual(len(state.metadata["files"]), 3)
        with F.serve("internetarchive-low-auth", state) as port:
            self.metadata(state, port)
            status, headers, body = self.request(port, CONTENT)
            self.assertEqual((status, body), (200, PAYLOAD))
            self.assertEqual(hashlib.sha256(body).hexdigest(), EXPECTED_SHA256)
            self.assertNotIn("Location", headers)
        self.assertEqual(state.events, [("metadata", "1"), ("metadata", "2"), ("content", "README-synthetic.txt")])
        self.assertEqual((state.requests, state.authenticated, state.auth_denied, state.metadata_reads), (3, 3, 0, 2))
        self.assertEqual(state.payload_bytes, len(PAYLOAD))
        self.assertEqual((state.unexpected, state.rejected_payload_bytes, state.rejected_mutations, state.anonymous), (0, 0, 0, 0))
        self.assertTrue(state.source_preserved())
        self.assert_closed(state, port)

    def test_wrong_secret_requires_two_distinct_denials_and_no_content(self):
        state = self.state(auth_case="wrong_secret")
        with F.serve("internetarchive-low-auth", state) as port:
            for _ in range(2):
                status, headers, body = self.request(port, auth="LOW " + KEY + ":" + WRONG)
                self.assertEqual((status, body), (403, b"Synthetic credentials denied"))
                self.assertNotIn("Location", headers)
        self.assertEqual(state.events, [("auth_denied", "1"), ("auth_denied", "2")])
        self.assertEqual((state.requests, state.auth_denied, state.authenticated, state.metadata_reads), (2, 2, 0, 0))
        self.assertEqual((state.payload_bytes, state.rejected_payload_bytes, state.unexpected), (0, 0, 0))
        self.assertTrue(state.source_preserved())
        self.assert_closed(state, port)

    def test_empty_and_each_one_sided_config_have_identical_absent_header_contract(self):
        # Pinned NewFs installs LOW only when both keys are nonempty. The
        # fixture observes headers, never a client config or inferred identity.
        for client_key, client_secret in (("", ""), (KEY, ""), ("", SECRET)):
            with self.subTest(config_shape=(bool(client_key), bool(client_secret))):
                state = self.state(auth_case="absent")
                with F.serve("internetarchive-low-auth", state) as port:
                    for _ in range(2):
                        self.assertEqual(self.request(port, auth=None)[::2], (403, b"Synthetic credentials denied"))
                self.assertEqual(state.events, [("auth_denied", "1"), ("auth_denied", "2")])
                self.assertEqual((state.auth_denied, state.metadata_reads, state.authenticated, state.payload_bytes), (2, 0, 0, 0))
                self.assert_closed(state, port)

    def test_known_member_denial_requires_two_positive_metadata_reads(self):
        state = self.state(mode="member_denied")
        with F.serve("internetarchive-low-auth", state) as port:
            self.metadata(state, port)
            status, headers, body = self.request(port, CONTENT)
            self.assertEqual((status, body), (403, b"Synthetic member denied"))
            self.assertNotIn("Location", headers)
        self.assertEqual(state.events, [("metadata", "1"), ("metadata", "2"), ("content_denied", "README-synthetic.txt")])
        self.assertEqual((state.authenticated, state.auth_denied, state.member_denied, state.payload_bytes), (3, 0, 1, 0))
        self.assertTrue(state.source_preserved())
        self.assert_closed(state, port)

    def test_authorization_is_compared_in_constant_time(self):
        state = self.state()
        with F.serve("internetarchive-low-auth", state) as port, mock.patch.object(
                F.hmac, "compare_digest", wraps=F.hmac.compare_digest) as compare:
            self.assertEqual(self.request(port)[0], 200)
            compare.assert_called_once_with(("LOW " + KEY + ":" + SECRET).encode(), ("LOW " + KEY + ":" + SECRET).encode())

    def test_arbitrary_or_wrong_case_authorization_is_unexpected_not_auth_evidence(self):
        for case, authorization in (("valid", None), ("valid", "low " + KEY + ":" + SECRET),
                                    ("valid", "LOW " + KEY + ":" + WRONG), ("valid", "LOW other:other"),
                                    ("valid", "Basic synthetic"), ("valid", "LOW " + KEY + ":" + SECRET + " "),
                                    ("wrong_secret", "LOW " + KEY + ":" + SECRET),
                                    ("wrong_secret", None), ("absent", "LOW " + KEY + ":" + WRONG),
                                    ("valid", "LOW \u00e9:synthetic")):
            with self.subTest(case=case), F.serve("internetarchive-low-auth", state := self.state(auth_case=case)) as port:
                self.assertEqual(self.request(port, auth=authorization)[0], 400)
            self.assertEqual((state.auth_denied, state.authenticated, state.metadata_reads, state.payload_bytes), (0, 0, 0, 0))
            self.assertEqual(state.unexpected, 1)
            self.assertEqual(state.events, [])

    def test_duplicate_forbidden_unknown_headers_and_nonempty_body_fail_closed(self):
        cases = [("Authorization", "LOW " + KEY + ":" + SECRET), ("Host", "127.0.0.1"),
                 ("Content-Length", "0"), ("Cookie", "synthetic=1"), ("Proxy-Authorization", "Basic synthetic"),
                 ("Transfer-Encoding", "chunked"), ("Content-Encoding", "gzip"), ("Range", "bytes=0-1"),
                 ("Expect", "100-continue"), ("X-Unknown", "synthetic")]
        for header in cases:
            with self.subTest(header=header[0]), F.serve("internetarchive-low-auth", state := self.state()) as port:
                self.assertEqual(self.request(port, extra=[header])[0], 400)
            self.assertEqual((state.authenticated, state.metadata_reads, state.payload_bytes), (0, 0, 0))
        for arguments in ({"omit": ["Host"]}, {"body": b"x"}, {"omit": ["Content-Length"], "extra": [("Content-Length", "00")]}):
            with self.subTest(arguments=arguments), F.serve("internetarchive-low-auth", state := self.state()) as port:
                self.assertEqual(self.request(port, **arguments)[0], 400)
            self.assertEqual(state.events, [])

    def test_exact_host_route_and_method_allowlist_forbid_aliases_writes_and_other_members(self):
        targets = [META + "?", META + "?x=1", META + "/", META + "#x", "/metadata/synthetic-item",
                   "/ias3/metadata/synthetic-item", "/front/metadata/other-item", "http://external.invalid" + META,
                   "/front/download/synthetic-item/nested/bytes.bin", CONTENT.replace("README", "%52EADME"),
                   "/front/download/synthetic-item/nested/../README-synthetic.txt", CONTENT + "/"]
        for target in targets:
            with self.subTest(target=target), F.serve("internetarchive-low-auth", state := self.state()) as port:
                self.assertEqual(self.request(port, target)[0], 400)
            self.assertEqual(state.events, [])
        for method in ("HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "PROPFIND"):
            with self.subTest(method=method), F.serve("internetarchive-low-auth", state := self.state()) as port:
                self.assertEqual(self.request(port, method=method)[0], 400)
            self.assertTrue(state.source_preserved())
            self.assertEqual(state.events, [])
        with F.serve("internetarchive-low-auth", state := self.state()) as port:
            self.assertEqual(self.request(port, omit=["Host"], extra=[("Host", "localhost:" + str(port))])[0], 400)

    def test_content_before_metadata_and_metadata_or_content_replay_cannot_advance(self):
        state = self.state()
        state.request_limit = state.connection_limit = 10
        with F.serve("internetarchive-low-auth", state) as port:
            self.assertEqual(self.request(port, CONTENT)[0], 400)
            self.assertEqual(self.request(port)[0], 200)
            self.assertEqual(self.request(port, CONTENT)[0], 400)
            self.assertEqual(self.request(port)[0], 200)
            self.assertEqual(self.request(port)[0], 400)
            self.assertEqual(self.request(port, CONTENT)[0], 200)
            self.assertEqual(self.request(port, CONTENT)[0], 400)
        self.assertEqual(state.events, [("metadata", "1"), ("metadata", "2"), ("content", "README-synthetic.txt")])
        self.assertEqual(state.unexpected, 4)
        self.assert_closed(state, port)

    def test_denial_replay_and_content_attempt_cannot_be_used_as_positive_evidence(self):
        state = self.state(auth_case="wrong_secret")
        state.request_limit = state.connection_limit = 5
        with F.serve("internetarchive-low-auth", state) as port:
            auth = "LOW " + KEY + ":" + WRONG
            for _ in range(2):
                self.assertEqual(self.request(port, auth=auth)[0], 403)
            self.assertEqual(self.request(port, CONTENT, auth=auth)[0], 400)
            self.assertEqual(self.request(port, auth=auth)[0], 400)
        self.assertEqual(state.events, [("auth_denied", "1"), ("auth_denied", "2")])
        self.assertEqual((state.authenticated, state.payload_bytes, state.unexpected), (0, 0, 2))

    def test_request_response_byte_and_admission_limits_are_sticky(self):
        for key, value in (("request_limit", 0), ("byte_limit", 1)):
            with self.subTest(key=key), F.serve("internetarchive-low-auth", state := self.state()) as port:
                setattr(state, key, value)
                self.assertEqual(self.request(port)[0], 429)
            self.assertTrue(state.budget_exceeded)
            self.assertEqual(state.payload_bytes, 0)
            self.assert_closed(state, port)
        for key in ("connection_limit", "active_connection_limit"):
            with self.subTest(key=key), F.serve("internetarchive-low-auth", state := self.state()) as port:
                setattr(state, key, 0)
                with self.assertRaises((OSError, http.client.HTTPException)):
                    self.request(port)
            self.assertTrue(state.budget_exceeded)
            self.assertEqual(state.admission_denied, 1)
            self.assertEqual(state.events, [])
            self.assert_closed(state, port)

    def test_object_payload_exceeding_remaining_budget_is_never_delivered(self):
        state = self.state()
        with F.serve("internetarchive-low-auth", state) as port:
            self.metadata(state, port)
            state.byte_limit = state.response_bytes + len(PAYLOAD) - 1
            status, _, body = self.request(port, CONTENT)
            self.assertEqual(status, 429)
            self.assertNotEqual(body, PAYLOAD)
        self.assertTrue(state.budget_exceeded)
        self.assertEqual((state.payload_bytes, state.rejected_payload_bytes), (0, 0))
        self.assert_closed(state, port)

    def test_idle_and_partial_header_deadline_and_shutdown_leave_no_owned_sockets(self):
        for prefix in (b"", b"GET /front/metadata/synthetic-item HTTP/1.1\r\nHost: "):
            with self.subTest(partial=bool(prefix)):
                state = self.state()
                state.request_timeout = 0.05
                with F.serve("internetarchive-low-auth", state) as port:
                    with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
                        if prefix:
                            client.sendall(prefix)
                        self.assertEqual(client.recv(1), b"")
                self.assertTrue(state.budget_exceeded)
                self.assertEqual(state.events, [])
                self.assert_closed(state, port)
        state = self.state()
        with F.serve("internetarchive-low-auth", state) as port:
            client = socket.create_connection(("127.0.0.1", port), timeout=2)
            # Wait for owned admission, then exit while its request is idle.
            limit = time.monotonic() + 2
            while not state.sockets and time.monotonic() < limit:
                time.sleep(0.001)
            self.assertTrue(state.sockets)
        try:
            self.assertEqual(client.recv(1), b"")
        finally:
            client.close()
        self.assert_closed(state, port)

    def test_truncated_folded_and_oversized_headers_never_dispatch(self):
        for tail in (b"", b"\r\n folded\r\n\r\n", b"\r\nX-Large: " + b"x" * 8200 + b"\r\n\r\n"):
            with self.subTest(kind=len(tail)), F.serve("internetarchive-low-auth", state := self.state()) as port:
                with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
                    data = ("GET " + META + " HTTP/1.1\r\nHost: 127.0.0.1:" + str(port)
                            + "\r\nAuthorization: LOW " + KEY + ":" + SECRET).encode() + tail
                    client.sendall(data)
                    client.shutdown(socket.SHUT_WR)
                    self.assertEqual(client.recv(1), b"")
            self.assertEqual(state.events, [])
            self.assertGreater(state.unexpected, 0)
            self.assert_closed(state, port)

    def test_expired_global_deadline_never_dispatches(self):
        state = self.state()
        state.deadline = time.monotonic() - 1
        with F.serve("internetarchive-low-auth", state) as port:
            with self.assertRaises((OSError, http.client.HTTPException)):
                self.request(port)
        self.assertTrue(state.budget_exceeded)
        self.assertEqual(state.events, [])
        self.assert_closed(state, port)

    def test_malformed_request_line_ending_never_counts_as_auth_evidence(self):
        for ending in (b"\n", b"\r\r\n"):
            for auth_case in ("valid", "wrong_secret", "absent"):
                with self.subTest(ending=ending, auth_case=auth_case), F.serve(
                        "internetarchive-low-auth", state := self.state(auth_case=auth_case)) as port:
                    secret = WRONG if auth_case == "wrong_secret" else SECRET
                    authorization = (b"" if auth_case == "absent" else
                                     ("Authorization: LOW " + KEY + ":" + secret + "\r\n").encode())
                    with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
                        client.sendall(("GET " + META + " HTTP/1.1").encode() + ending
                                       + ("Host: 127.0.0.1:" + str(port) + "\r\n").encode()
                                       + authorization + b"\r\n")
                        self.assertEqual(client.recv(1), b"")
                self.assertEqual(state.events, [])
                self.assertEqual((state.auth_denied, state.authenticated, state.requests), (0, 0, 0))
                self.assertGreater(state.unexpected, 0)
                self.assert_closed(state, port)

    def test_malformed_authorization_name_is_not_an_absent_credential(self):
        for field in (b"Authorization : LOW synthetic:synthetic", b": LOW synthetic:synthetic",
                      b"Authorization\t: LOW synthetic:synthetic", b"NoColonHeader"):
            with self.subTest(field=field), F.serve("internetarchive-low-auth", state := self.state(auth_case="absent")) as port:
                with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
                    client.sendall(("GET " + META + " HTTP/1.1\r\nHost: 127.0.0.1:" + str(port)
                                    + "\r\n").encode() + field + b"\r\n\r\n")
                    self.assertEqual(client.recv(1), b"")
            self.assertEqual(state.events, [])
            self.assertEqual((state.auth_denied, state.authenticated, state.requests), (0, 0, 0))
            self.assertGreater(state.unexpected, 0)
            self.assert_closed(state, port)

    def test_source_or_secret_mode_mutation_fails_teardown_after_transport_cleanup(self):
        mutations = {"key": "changed_synthetic_key_123", "secret": "changed_synthetic_secret_123",
                     "wrong_secret": "changed_synthetic_wrong_123", "mode": "member_denied", "auth_case": "absent",
                     "user": "synthetic-other", "item": "other-synthetic", "modified": "2024-01-02T00:00:00Z",
                     "files": {"README-synthetic.txt": b"changed"}, "metadata": {"files": []}}
        for key, value in mutations.items():
            with self.subTest(field=key):
                state = self.state()
                with self.assertRaisesRegex(RuntimeError, "^internetarchive_low_source_changed$"):
                    with F.serve("internetarchive-low-auth", state) as port:
                        setattr(state, key, value)
                        self.assertFalse(state.source_preserved())
                        self.assertEqual(self.request(port)[0], 400)
                self.assertEqual(state.events, [])
                self.assert_closed(state, port)

    def test_nested_metadata_snapshot_is_independent_and_events_contain_no_credentials(self):
        state = self.state()
        original = copy.deepcopy(state.metadata)
        state.metadata["files"][0]["md5"] = "0" * 32
        self.assertFalse(state.source_preserved())
        state.metadata = original
        self.assertTrue(state.source_preserved())
        with F.serve("internetarchive-low-auth", state) as port:
            self.metadata(state, port)
        events = json.dumps(state.events)
        for value in (KEY, SECRET, WRONG):
            self.assertNotIn(value, events)

    def test_invalid_constructor_shapes_are_rejected_before_any_listener(self):
        cases = [("short", SECRET, WRONG, "normal", "valid"), (KEY, SECRET, SECRET, "normal", "valid"),
                 (KEY, SECRET, WRONG, "summation", "valid"), (KEY, SECRET, WRONG, "normal", "arbitrary"),
                 (KEY, SECRET, WRONG, "member_denied", "wrong_secret"), (None, SECRET, WRONG, "normal", "valid"),
                 (KEY, SECRET + "\n", WRONG, "normal", "valid"), (KEY, "x" * 129, WRONG, "normal", "valid")]
        for args in cases:
            with self.subTest(case=cases.index(args)), self.assertRaisesRegex(ValueError, "^invalid_internetarchive_low_fixture$"):
                F.InternetArchiveLowState(*args)


if __name__ == "__main__":
    unittest.main()
