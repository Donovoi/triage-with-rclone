"""Independent Pixeldrain HTTP subset tests; no native binary or account."""

import base64
import copy
import hashlib
import http.client
import json
from pathlib import Path
import socket
import sys
import time
import unittest
import urllib.parse

sys.path.insert(0, str(Path(__file__).parents[1] / "provider-lab"))
try:
    import fixture_servers as FIXTURES
finally:
    sys.path.pop(0)

KEY, WRONG = "synthetic-key", "wrong-synthetic-key"
ROOT = "/api/filesystem/me/"
PAYLOADS = {
    "README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
    "nested/bytes.bin": bytes(range(256)) * 8,
    "nested/space name.txt": b"Nested synthetic payload.\n",
}


def basic(key=KEY, user=""):
    return "Basic " + base64.b64encode((user + ":" + key).encode()).decode()


def target(member="", stat=True):
    return ROOT + urllib.parse.quote(member, safe="/") + ("?stat=" if stat else "")


def literal_node(member, files=PAYLOADS):
    payload = files.get(member)
    return {"type": "file" if payload is not None else "dir", "path": "/me/" + member,
            "name": member.rsplit("/", 1)[-1] if member else "me", "created": "2023-12-31T00:00:00Z",
            "modified": "2024-01-01T00:00:00.123Z", "mode_octal": "0644" if payload is not None else "0755",
            "file_size": len(payload) if payload is not None else 0,
            "file_type": "application/octet-stream" if payload is not None else "inode/directory",
            "sha256_sum": hashlib.sha256(payload).hexdigest() if payload is not None else ""}


class PixeldrainServerTests(unittest.TestCase):
    def start(self, mode="normal"):
        self.state = FIXTURES.PixeldrainState(KEY, mode)
        self.port = self.enterContext(FIXTURES.serve("pixeldrain", self.state))

    def request(self, method, path, *, auth=None, extra=(), body=None, host=True):
        client = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            client.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            if host:
                client.putheader("Host", f"127.0.0.1:{self.port}")
            if auth is not False:
                client.putheader("Authorization", basic() if auth is None else auth)
            for name, value in extra:
                client.putheader(name, value)
            client.endheaders(body)
            response = client.getresponse()
            return response.status, dict(response.getheaders()), response.read(16385)
        finally:
            client.close()

    def setup_reads(self):
        status, _, body = self.request("GET", "/api/user")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"username": "synthetic-user", "subscription": {"name": "synthetic-plan", "storage_space": 1048576},
                                           "storage_space_used": 0})
        status, _, body = self.request("GET", target())
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"path": [literal_node("")], "base_index": 0,
                                           "children": [literal_node("README-synthetic.txt"), literal_node("nested")]})

    def raw_request(self, path):
        with socket.create_connection(("127.0.0.1", self.port), timeout=3) as client:
            client.sendall(("GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1:" + str(self.port)
                            + "\r\nAuthorization: " + basic() + "\r\n\r\n").encode("ascii"))
            response = http.client.HTTPResponse(client)
            try:
                response.begin()
                return response.status, dict(response.getheaders()), response.read(16385)
            finally:
                response.close()

    def error(self, response, status, value="fixture_request_rejected"):
        code, headers, body = response
        self.assertEqual(code, status)
        self.assertLessEqual(len(body), 1024)
        self.assertNotIn("Location", headers)
        self.assertNotIn("Set-Cookie", headers)
        if body:
            parsed = json.loads(body)
            self.assertEqual(set(parsed), {"value", "message"})
            self.assertEqual(parsed["value"], value)
            self.assertIsInstance(parsed["message"], str)
        for private in (KEY.encode(), basic().encode(), *PAYLOADS.values()):
            self.assertNotIn(private, body)

    def test_exact_user_root_twice_and_complete_nested_envelope(self):
        self.start()
        self.setup_reads()
        self.assertEqual(self.request("GET", target())[0], 200)
        code, _, body = self.request("GET", target("nested"))
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body), {"path": [literal_node(""), literal_node("nested")], "base_index": 1,
                                           "children": [literal_node("nested/bytes.bin"), literal_node("nested/space name.txt")]})
        self.assertEqual(self.state.events, [("user_info", ""), ("root_stat", "/"), ("root_stat", "/"), ("directory_stat", "nested")])
        self.assertEqual(self.state.requests, 4)
        self.assertEqual(self.state.authenticated, 4)
        self.assertEqual(self.state.payload_bytes, 0)
        self.error(self.request("GET", target()), 400)

    def test_exact_member_ancestor_index_metadata_and_independent_bytes(self):
        self.start()
        self.setup_reads()
        for name, payload in PAYLOADS.items():
            code, _, body = self.request("GET", target(name))
            self.assertEqual(code, 200)
            ancestors = [literal_node("")] + ([literal_node("nested")] if name.startswith("nested/") else [])
            expected = {"path": ancestors + [literal_node(name)], "base_index": len(ancestors), "children": []}
            self.assertEqual(json.loads(body), expected)
            code, headers, body = self.request("GET", target(name, False))
            self.assertEqual((code, body), (200, payload))
            self.assertEqual(int(headers["Content-Length"]), len(payload))
            self.assertEqual(hashlib.sha256(body).hexdigest(), hashlib.sha256(payload).hexdigest())
        self.assertEqual(self.state.payload_bytes, sum(map(len, PAYLOADS.values())))
        self.assertEqual(self.state.unexpected, 0)

    def test_envelope_guard_rejects_invalid_baseindex_prefix_and_typed_metadata(self):
        expected = {"path": [literal_node(""), literal_node("README-synthetic.txt")], "base_index": 1, "children": []}
        def valid(value):
            return FIXTURES.pixeldrain_envelope_valid(value, "README-synthetic.txt", PAYLOADS,
                                                      "2024-01-01T00:00:00.123Z", "2023-12-31T00:00:00Z")
        self.assertTrue(valid(expected))
        for index in (-1, 0, 2, True, 1.0, None):
            self.assertFalse(valid(dict(expected, base_index=index)))
        for key, value in (("path", "/other/README-synthetic.txt"), ("type", "unknown"), ("file_size", True),
                           ("file_size", 0), ("sha256_sum", "0" * 64), ("modified", "2024-01-01T00:00:00.1230001Z"),
                           ("name", "nested/README-synthetic.txt"), ("mode_octal", "0777")):
            broken = copy.deepcopy(expected)
            broken["path"][-1][key] = value
            self.assertFalse(valid(broken), key)
        for change in ({"path": []}, {"children": [literal_node("nested")]}, {"extra": True}):
            self.assertFalse(valid(dict(expected, **change)))

    def test_exact_wrong_key_is_distinct_from_missing_random_and_wrong_user(self):
        self.start()
        self.error(self.request("GET", "/api/user", auth=basic(WRONG)), 401, "authentication_failed")
        self.assertEqual(self.state.events, [("auth_denied", "")])
        for auth in (False, "Basic invalid", basic("unregistered"), basic(KEY, "user")):
            self.error(self.request("GET", "/api/user", auth=auth), 401, "authentication_failed")
        self.assertEqual((self.state.auth_denied, self.state.authenticated, self.state.payload_bytes), (1, 0, 0))
        self.assertEqual(self.state.unexpected, 4)

    def test_correct_key_member_denial_requires_setup_and_grants_no_content(self):
        self.start("member_denied")
        self.error(self.request("GET", target("README-synthetic.txt")), 400)
        self.setup_reads()
        response = self.request("GET", target("README-synthetic.txt"))
        self.error(response, 403, "permission_denied")
        self.assertEqual(json.loads(response[2])["message"], "Synthetic permission denied")
        self.assertEqual(self.state.events, [("user_info", ""), ("root_stat", "/"), ("member_denied", "README-synthetic.txt")])
        self.error(self.request("GET", target("README-synthetic.txt", False)), 400)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_missing_metadata_content_and_arbitrary_unknown_path_are_distinct(self):
        self.start()
        self.setup_reads()
        for stat, event in ((True, "file_missing"), (False, "content_missing")):
            response = self.request("GET", target("missing-synthetic-object.bin", stat))
            self.error(response, 404, "path_not_found")
            self.assertEqual(json.loads(response[2])["message"], "Synthetic path not found")
            self.assertEqual(self.state.events[-1], (event, "missing-synthetic-object.bin"))
        self.error(self.request("GET", target("unapproved-missing")), 400)
        self.assertEqual(self.state.missing, 2)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_content_and_nested_listing_require_exact_setup_and_member_metadata(self):
        self.start()
        self.error(self.request("GET", target()), 400)
        self.assertEqual(self.request("GET", "/api/user")[0], 200)
        self.error(self.request("GET", target("README-synthetic.txt")), 400)
        self.assertEqual(self.request("GET", target())[0], 200)
        self.error(self.request("GET", target("nested")), 400)
        self.assertEqual(self.request("GET", target("nested/bytes.bin"))[0], 200)
        self.error(self.request("GET", target("README-synthetic.txt", False)), 400)
        self.error(self.request("GET", target()), 400)  # Cannot turn a member read into a new listing phase.
        self.error(self.request("GET", "/api/user"), 400)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_authenticated_write_rejection_preserves_payload_and_metadata(self):
        self.start()
        before = dict(self.state.files)
        self.setup_reads()
        self.assertEqual(self.request("GET", target("README-synthetic.txt"))[0], 200)
        original = self.state.envelope("README-synthetic.txt")
        self.error(self.request("DELETE", target("README-synthetic.txt", False)), 405, "fixture_read_only")
        self.assertEqual(self.state.events[-1], ("write_denied", "README-synthetic.txt"))
        self.assertEqual(self.state.rejected_mutations, 1)
        self.assertEqual(self.state.files, before)
        self.assertEqual(self.state.envelope("README-synthetic.txt"), original)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_ranges_compare_exact_bytes_and_reject_giant_or_malformed_numbers(self):
        self.start()
        self.setup_reads()
        self.assertEqual(self.request("GET", target("nested/bytes.bin"))[0], 200)
        for header, expected, content_range in (("bytes=2-4", PAYLOADS["nested/bytes.bin"][2:5], "bytes 2-4/2048"),
                                                ("bytes=2046-9999", PAYLOADS["nested/bytes.bin"][-2:], "bytes 2046-2047/2048"),
                                                ("bytes=2047-", PAYLOADS["nested/bytes.bin"][-1:], "bytes 2047-2047/2048")):
            code, headers, body = self.request("GET", target("nested/bytes.bin", False), extra=[("Range", header)])
            self.assertEqual((code, body, headers["Content-Range"]), (206, expected, content_range))
        before = self.state.payload_bytes
        for header in ("bytes=-1", "bytes=3-2", "bytes=2048-", "bytes=0-1,3-4", "bytes=+1-2",
                       "bytes=" + "9" * 5000 + "-", "bytes=0-" + "9" * 5000):
            self.error(self.request("GET", target("nested/bytes.bin", False), extra=[("Range", header)]), 416)
        self.assertEqual(self.state.payload_bytes, before)

    def test_empty_file_is_unit_only_and_keeps_shared_native_manifest_unchanged(self):
        self.start()
        self.state.files["empty.bin"] = b""
        self.assertEqual(self.request("GET", "/api/user")[0], 200)
        self.assertEqual(self.request("GET", target())[0], 200)
        code, _, body = self.request("GET", target("empty.bin"))
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)["path"][-1]["sha256_sum"], hashlib.sha256(b"").hexdigest())
        self.assertEqual(self.request("GET", target("empty.bin", False))[::2], (200, b""))
        self.error(self.request("GET", target("empty.bin", False), extra=[("Range", "bytes=0-")]), 416)
        self.assertEqual(FIXTURES.FILES, PAYLOADS)

    def test_strict_raw_query_percent_namespace_and_control_rejections(self):
        self.start()
        paths = ["//api/user", "http://127.0.0.1/api/user", "/api/user?x=1", ROOT + "?stat", ROOT + "?stat=&stat=",
                 ROOT + "?stat=&x=1", ROOT + "?", ROOT + "?stat=%00", ROOT + "../README-synthetic.txt?stat=",
                 ROOT + "%2E%2E/README-synthetic.txt?stat=", ROOT + "nested%2Fbytes.bin?stat=", ROOT + "nested//bytes.bin?stat=",
                 ROOT + "nested/?stat=", ROOT + "nested%5Cbytes.bin?stat=", ROOT + "nested%252Fbytes.bin?stat=",
                 ROOT + "%6Eested?stat=", ROOT + "%FF?stat=", ROOT + "%C2%85?stat=", ROOT + "%00?stat=",
                 ROOT + "%0D%0A?stat=", ROOT + "%?stat=", "/api/filesystem/other/?stat="]
        for path in paths:
            with self.subTest(path=path):
                self.error(self.request("GET", path), 400)
        self.assertEqual(self.state.events, [])
        self.assertEqual(self.state.authenticated, 0)

    def test_headers_bodies_methods_and_unknown_parser_errors_are_observable(self):
        self.start()
        for extra, body in (([("Host", "127.0.0.1")], None), ([("Authorization", basic())], None),
                            ([("Transfer-Encoding", "chunked")], None), ([("Content-Length", "1")], b"x"),
                            ([("Content-Length", "00")], None), ([("Range", "bytes=0-1")], None),
                            ([("X-Synthetic", "x" * 16385)], None)):
            self.error(self.request("GET", "/api/user", extra=extra, body=body), 400)
        self.error(self.request("GET", "/api/user", host=False), 400)
        for method in ("POST", "PUT", "DELETE", "HEAD"):
            self.error(self.request(method, "/api/user"), 400)
        for method in ("PATCH", "OPTIONS", "BOGUS"):
            self.error(self.request(method, "/api/user"), 501)
        self.assertGreaterEqual(self.state.unexpected, 15)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_raw_empty_and_nonempty_fragments_cannot_alias_stat_or_content(self):
        self.start()
        self.setup_reads()
        self.assertEqual(self.request("GET", target("README-synthetic.txt"))[0], 200)
        before = list(self.state.events), self.state.authenticated, self.state.payload_bytes
        for path in (ROOT + "?stat=#", ROOT + "?stat=#fragment", target("README-synthetic.txt") + "#",
                     target("README-synthetic.txt", False) + "#", target("README-synthetic.txt", False) + "#fragment",
                     "/api/user#", "//api/user"):
            self.error(self.raw_request(path), 400)
            self.assertEqual((self.state.events, self.state.authenticated, self.state.payload_bytes), before)
        # Escaped # is a namespace character, not a URI fragment; this member
        # is unapproved and cannot alias the known README.
        self.error(self.raw_request(target("README-synthetic.txt", False) + "%23"), 400)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_request_response_and_lifetime_budgets_reject_without_data(self):
        for mode in ("requests", "bytes", "lifetime"):
            with self.subTest(mode=mode):
                state = FIXTURES.PixeldrainState(KEY)
                if mode == "requests": state.request_limit = 0
                if mode == "bytes": state.byte_limit = 1
                if mode == "lifetime": state.deadline = time.monotonic() - 1
                with FIXTURES.serve("pixeldrain", state) as port:
                    self.state, self.port = state, port
                    try:
                        result = self.request("GET", "/api/user")
                        self.assertEqual(result[0], 429)
                    except (http.client.RemoteDisconnected, ConnectionResetError, ConnectionAbortedError):
                        self.assertEqual(mode, "lifetime")
                self.assertTrue(state.budget_exceeded)
                self.assertTrue(state.cleanup_complete)
                self.assertEqual(state.payload_bytes, 0)

    def test_slow_header_and_total_active_connection_caps_close_owned_resources(self):
        for mode in ("slow", "total", "active"):
            state = FIXTURES.PixeldrainState(KEY)
            state.request_timeout = 0.15
            if mode == "total": state.connection_limit = 0
            if mode == "active": state.active_connection_limit = 1
            started, sockets = time.monotonic(), []
            with FIXTURES.serve("pixeldrain", state) as port:
                try:
                    first = socket.create_connection(("127.0.0.1", port), timeout=2)
                    sockets.append(first)
                    if mode == "slow": first.sendall(b"GET /api/user HTTP/1.1\r\nHost:")
                    if mode == "active":
                        deadline = time.monotonic() + 1
                        while not state.accepted_connections and time.monotonic() < deadline: time.sleep(0.005)
                        sockets.append(socket.create_connection(("127.0.0.1", port), timeout=2))
                    try:
                        self.assertEqual(sockets[-1].recv(4096), b"")
                    except (ConnectionResetError, ConnectionAbortedError):
                        pass
                finally:
                    for client in sockets: client.close()
            self.assertLess(time.monotonic() - started, 2)
            self.assertTrue(state.cleanup_complete)
            self.assertTrue(state.budget_exceeded)
            self.assertEqual(state.sockets, set())
            self.assertEqual(state.payload_bytes, 0)
            if mode != "slow": self.assertGreaterEqual(state.admission_denied, 1)


if __name__ == "__main__":
    unittest.main()
