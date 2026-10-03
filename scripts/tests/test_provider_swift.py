"""Independent synthetic Swift HTTP contract tests; never launch rclone or the app."""

import hashlib
import http.client
import json
from pathlib import Path
import socket
import sys
import time
import unittest


LAB_ROOT = Path(__file__).parents[1] / "provider-lab"
sys.path.insert(0, str(LAB_ROOT))
try:
    import fixture_servers as FIXTURES
finally:
    sys.path.pop(0)

# Expectations are independent of the server's mutable FILES/state mapping.
EXPECTED = {
    "README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
    "nested/space name.txt": b"Nested synthetic payload.\n",
    "nested/bytes.bin": bytes(range(256)) * 8,
}
BASE = "/v1/AUTH_synthetic/synthetic-bucket"
README = BASE + "/README-synthetic.txt"


class SwiftServerTests(unittest.TestCase):
    def start(self, mode="normal"):
        self.state = FIXTURES.SwiftState("synthetic-user", "synthetic-key", mode)
        self.port = self.enterContext(FIXTURES.serve("swift", self.state))

    def request(self, method, path, *, token=None, headers=(), body=None, host=True):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            connection.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            if host:
                connection.putheader("Host", f"127.0.0.1:{self.port}")
            if token is not None:
                connection.putheader("X-Auth-Token", token)
            for key, value in headers:
                connection.putheader(key, value)
            connection.endheaders(body)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def grant(self):
        status, headers, body = self.request("GET", "/auth/v1.0", headers=(
            ("X-Auth-User", "synthetic-user"), ("X-Auth-Key", "synthetic-key")))
        self.assertEqual(status, 200)
        self.assertEqual(body, b"")
        self.assertEqual(headers["X-Storage-Url"], f"http://127.0.0.1:{self.port}/v1/AUTH_synthetic")
        self.assertNotIn("Location", headers)
        return headers["X-Auth-Token"]

    def reject_without_payload(self, method, path, *, status=400, **kwargs):
        code, headers, body = self.request(method, path, **kwargs)
        self.assertEqual(code, status)
        self.assertEqual(body, b"")
        self.assertEqual(headers["Content-Length"], "0")
        self.assertNotIn("X-Auth-Token", headers)
        self.assertNotIn("Location", headers)

    def test_grants_are_distinct_and_the_previous_token_is_not_current(self):
        self.start()
        first, second = self.grant(), self.grant()
        self.assertNotEqual(first, second)
        self.reject_without_payload("GET", README, status=401, token=first)
        status, _, body = self.request("GET", README, token=second)
        self.assertEqual((status, body), (200, EXPECTED["README-synthetic.txt"]))
        self.assertEqual(self.state.generation, 2)
        self.assertEqual(len(self.state.tokens), 2)

    def test_invalid_or_duplicate_login_headers_never_issue_a_token(self):
        self.start()
        cases = [(), (("X-Auth-User", "synthetic-user"), ("X-Auth-Key", "wrong")),
                 (("X-Auth-User", "synthetic-user"), ("X-Auth-User", "synthetic-user"), ("X-Auth-Key", "synthetic-key")),
                 (("X-Auth-User", "synthetic-user"), ("X-Auth-Key", "synthetic-key"), ("X-Auth-Key", "synthetic-key"))]
        for headers in cases:
            with self.subTest(headers=len(headers)):
                self.reject_without_payload("GET", "/auth/v1.0", status=401, headers=headers)
        self.assertEqual(self.state.auth_denied, len(cases))
        self.assertEqual(self.state.generation, 0)
        self.assertEqual(self.state.payload_bytes, 0)
        self.assertEqual(self.state.rejected_payload_bytes, 0)

    def test_storage_requires_one_exact_current_token(self):
        self.start()
        token = self.grant()
        self.reject_without_payload("GET", README, status=401)
        self.reject_without_payload("GET", README, status=401, token="wrong")
        self.reject_without_payload("GET", README, status=401, token=token,
                                    headers=(("X-Auth-Token", token),))
        self.assertEqual(self.state.storage_denied, 3)
        self.assertEqual(self.state.payload_bytes, 0)
        self.assertEqual(self.state.rejected_payload_bytes, 0)

    def test_renewal_requires_metadata_before_forced_rejection(self):
        self.start("renew")
        token = self.grant()
        self.reject_without_payload("GET", README, token=token)
        self.assertEqual(self.state.forced_401, 0)
        self.assertEqual(self.state.payload_bytes, 0)
        self.assertEqual(self.request("HEAD", README, token=token)[0], 200)
        self.reject_without_payload("GET", README, status=401, token=token)
        self.assertEqual(self.state.forced_401, 1)

    def test_renewal_sequence_revokes_old_token_and_serves_only_new_generation(self):
        self.start("renew")
        first = self.grant()
        self.assertEqual(self.request("HEAD", README, token=first)[0], 200)
        self.reject_without_payload("GET", README, status=401, token=first)
        self.assertEqual(self.state.payload_bytes, 0)
        second = self.grant()
        self.assertNotEqual(first, second)
        self.reject_without_payload("GET", README, status=401, token=first)
        status, _, body = self.request("GET", README, token=second)
        self.assertEqual((status, body), (200, EXPECTED["README-synthetic.txt"]))
        self.assertEqual(self.state.events, [("grant", 1), ("head", 1), ("get_401", 1),
                                           ("grant", 2), ("storage_denied", 2), ("get", 2)])
        self.assertEqual(self.state.revoked, {first})
        self.assertEqual(self.state.forced_401, 1)
        self.assertEqual(self.state.rejected_payload_bytes, 0)
        self.assertEqual(self.state.payload_bytes, len(EXPECTED["README-synthetic.txt"]))

    def test_renewal_denial_does_not_release_payload_or_issue_replacement(self):
        self.start("deny")
        token = self.grant()
        self.assertEqual(self.request("HEAD", README, token=token)[0], 200)
        self.reject_without_payload("GET", README, status=401, token=token)
        self.reject_without_payload("GET", "/auth/v1.0", status=403, headers=(
            ("X-Auth-User", "synthetic-user"), ("X-Auth-Key", "synthetic-key")))
        self.reject_without_payload("GET", README, status=401, token=token)
        self.assertEqual(self.state.generation, 1)
        self.assertEqual(self.state.renewal_denied, 1)
        self.assertEqual(self.state.payload_bytes, 0)
        self.assertEqual(self.state.rejected_payload_bytes, 0)
        self.assertNotIn(("get", 1), self.state.events)
        self.assertEqual(self.state.files, EXPECTED)

    def test_inventory_and_metadata_match_independent_bytes_and_md5(self):
        self.start()
        token = self.grant()
        status, _, body = self.request("GET", BASE + "?format=json", token=token)
        self.assertEqual(status, 200)
        rows = json.loads(body)
        self.assertEqual([row["name"] for row in rows], sorted(EXPECTED))
        for row in rows:
            payload = EXPECTED[row["name"]]
            self.assertEqual(row["bytes"], len(payload))
            self.assertEqual(row["hash"], hashlib.md5(payload).hexdigest())
        status, headers, body = self.request("HEAD", README, token=token)
        self.assertEqual((status, body), (200, b""))
        self.assertEqual(int(headers["Content-Length"]), len(EXPECTED["README-synthetic.txt"]))
        self.assertEqual(headers["Etag"], hashlib.md5(EXPECTED["README-synthetic.txt"]).hexdigest())
        self.assertEqual(self.state.payload_bytes, 0)
        self.assertEqual(self.state.files, EXPECTED)

    def test_listing_prefix_delimiter_marker_and_limit_are_scoped(self):
        self.start()
        token = self.grant()
        status, _, body = self.request("GET", BASE + "?format=json&delimiter=%2F", token=token)
        self.assertEqual(status, 200)
        rows = json.loads(body)
        self.assertEqual([row.get("name", row.get("subdir")) for row in rows],
                         ["README-synthetic.txt", "nested/"])
        status, _, body = self.request("GET", BASE + "?format=json&prefix=nested%2F&marker=nested%2Fbytes.bin&end_marker=z&limit=1", token=token)
        self.assertEqual(status, 200)
        self.assertEqual([row["name"] for row in json.loads(body)], ["nested/space name.txt"])
        self.assertEqual(self.state.payload_bytes, 0)

    def test_complete_and_range_reads_preserve_independent_payloads(self):
        self.start()
        token = self.grant()
        status, headers, body = self.request("GET", BASE + "/nested/bytes.bin", token=token,
                                             headers=(("Range", "bytes=20-39"),))
        self.assertEqual((status, body), (206, EXPECTED["nested/bytes.bin"][20:40]))
        self.assertEqual(headers["Content-Range"], "bytes 20-39/2048")
        status, _, body = self.request("GET", README, token=token, headers=(("Range", "bytes=10-"),))
        self.assertEqual((status, body), (206, EXPECTED["README-synthetic.txt"][10:]))
        status, _, body = self.request("GET", BASE + "/nested/space%20name.txt", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(hashlib.sha256(body).digest(), hashlib.sha256(EXPECTED["nested/space name.txt"]).digest())
        self.assertEqual(self.state.files, EXPECTED)

    def test_malformed_or_unbounded_ranges_are_rejected_without_object_bytes(self):
        self.start()
        token = self.grant()
        for value in ("bytes=0-9999", "bytes=9-2", "bytes=-4", "bytes=0-1,3-4", "items=0-1", "bytes=x-y"):
            with self.subTest(value=value):
                self.reject_without_payload("GET", README, status=416, token=token, headers=(("Range", value),))
        self.reject_without_payload("GET", README, status=416, token=token,
                                    headers=(("Range", "bytes=0-1"), ("Range", "bytes=0-1")))
        self.assertEqual(self.state.payload_bytes, 0)

    def test_exact_loopback_host_is_required_and_oversized_headers_are_rejected(self):
        self.start()
        for headers in ((), (("Host", "localhost"),), (("Host", "127.0.0.2:1"),),
                        (("Host", f"127.0.0.1:{self.port}"), ("Host", f"127.0.0.1:{self.port}"))):
            with self.subTest(count=len(headers)):
                self.reject_without_payload("GET", "/auth/v1.0", headers=headers, host=False)
        self.reject_without_payload("GET", "/auth/v1.0", headers=(("X-Padding", "x" * 8200),))
        self.assertEqual(self.state.generation, 0)

    def test_unsafe_or_out_of_scope_paths_cannot_read_or_redirect(self):
        self.start()
        token = self.grant()
        for path in ("/v1/AUTH_synthetic", "/v1/AUTH_synthetic/other/README-synthetic.txt", "/other"):
            with self.subTest(path=path):
                self.reject_without_payload("GET", path, status=404, token=token)
        for path in (BASE + "/../README-synthetic.txt", BASE + "/%2e%2e/README-synthetic.txt",
                     BASE + "/nested%5Cbytes.bin", BASE + "/%00", README + "#fragment",
                     "http://127.0.0.1:1/auth/v1.0", "/" + "x" * 2048):
            with self.subTest(path=path[:60]):
                self.reject_without_payload("GET", path, token=token)
        self.assertEqual(self.state.payload_bytes, 0)
        self.assertEqual(self.state.files, EXPECTED)

    def test_query_contract_rejects_unknown_duplicate_or_unsafe_fields(self):
        self.start()
        token = self.grant()
        cases = (BASE, BASE + "?format=xml", BASE + "?format=json&format=json",
                 BASE + "?format=json&unknown=1", BASE + "?format=json&prefix=..%2F",
                 BASE + "?format=json&marker=%00", BASE + "?format=json&delimiter=x",
                 BASE + "?format=json&limit=0", BASE + "?format=json&limit=1001",
                 BASE + "?format=json&" + "&".join(f"x{i}=1" for i in range(8)),
                 README + "?format=json", "/auth/v1.0?unexpected=1")
        for path in cases:
            with self.subTest(path=path):
                self.reject_without_payload("GET", path, token=token)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_request_body_framing_is_bounded_and_no_data_is_served(self):
        self.start()
        token = self.grant()
        cases = [(("Transfer-Encoding", "chunked"),), (("Content-Length", "4097"),),
                 (("Content-Length", "-1"),), (("Content-Length", "x"),),
                 (("Content-Length", "0"), ("Content-Length", "0")), (("Content-Length", "1"),)]
        for headers in cases:
            with self.subTest(headers=headers):
                self.reject_without_payload("GET", README, token=token, headers=headers)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_authenticated_writes_and_missing_members_do_not_mutate_source(self):
        self.start()
        token = self.grant()
        for method in ("PUT", "POST", "DELETE", "COPY"):
            with self.subTest(method=method):
                self.reject_without_payload(method, README, status=405, token=token,
                                            headers=(("Content-Length", "5"),), body=b"write")
        for path in (BASE + "/missing.txt", BASE + "/nested"):
            self.reject_without_payload("GET", path, status=404, token=token)
        self.assertEqual(self.state.rejected_mutations, 4)
        self.assertEqual(self.state.missing, 2)
        self.assertEqual(self.state.files, EXPECTED)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_request_budget_stops_before_authentication(self):
        self.start()
        self.state.request_limit = 0
        self.reject_without_payload("GET", "/auth/v1.0", status=429)
        self.assertTrue(self.state.budget_exceeded)
        self.assertEqual(self.state.generation, 0)

    def test_expired_fixture_deadline_stops_before_authentication(self):
        self.start()
        self.state.deadline = time.monotonic() - 1
        self.reject_without_payload("GET", "/auth/v1.0", status=429)
        self.assertTrue(self.state.budget_exceeded)
        self.assertEqual(self.state.generation, 0)

    def test_cleanup_closes_idle_client_and_owned_listener(self):
        state = FIXTURES.SwiftState("synthetic-user", "synthetic-key")
        with FIXTURES.serve("swift", state) as port:
            idle = socket.create_connection(("127.0.0.1", port), timeout=3)
            self.addCleanup(idle.close)
            # A partial request ensures the owned worker has an idle input to close.
            idle.sendall(b"GET /auth/v1.0 HTTP/1.1\r\n")
        self.assertTrue(state.stopping.is_set())
        self.assertEqual(state.sockets, set())
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=0.2)
        try:
            self.assertEqual(idle.recv(1), b"")
        except ConnectionResetError:
            pass


if __name__ == "__main__":
    unittest.main()
