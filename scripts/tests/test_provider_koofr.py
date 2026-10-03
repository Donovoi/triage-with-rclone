"""Independent Koofr HTTP subset tests; no native binary or real account."""

import base64
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

USER, PASSWORD, WRONG = "synthetic-user", "synthetic-password", "wrong-synthetic-password"
MOUNTS = "/api/v2/mounts"
API = MOUNTS + "/synthetic-mount/files/"
CONTENT = "/content/api/v2/mounts/synthetic-mount/files/get"
PAYLOADS = {
    "README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
    "nested/bytes.bin": bytes(range(256)) * 8,
    "nested/space name.txt": b"Nested synthetic payload.\n",
}


def basic(password=PASSWORD, user=USER):
    return "Basic " + base64.b64encode((user + ":" + password).encode()).decode()


def target(route, path):
    return route + "?" + urllib.parse.urlencode({"path": path})


def expected_info(path):
    data = PAYLOADS.get(path[1:])
    return {"name": path.rsplit("/", 1)[-1] if path != "/" else "/", "path": path,
            "type": "file" if data is not None else "dir", "modified": 1704067200123,
            "size": len(data) if data is not None else 0, "contentType": "application/octet-stream" if data is not None else "",
            "hash": hashlib.md5(data).hexdigest() if data is not None else ""}


class KoofrServerTests(unittest.TestCase):
    def start(self, mode="normal"):
        self.state = FIXTURES.KoofrState(USER, PASSWORD, mode)
        self.port = self.enterContext(FIXTURES.serve("koofr", self.state))

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
        status, _, body = self.request("GET", MOUNTS)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"mounts": [{"id": "synthetic-mount", "name": "Synthetic fixture",
                                                       "type": "device", "isPrimary": False}]})
        status, _, body = self.request("GET", target(API + "info", "/"))
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), expected_info("/"))

    def info(self, path):
        return self.request("GET", target(API + "info", path))

    def error(self, response, status):
        code, headers, body = response
        self.assertEqual(code, status)
        self.assertLessEqual(len(body), 1024)
        self.assertNotIn("Location", headers)
        self.assertNotIn("Set-Cookie", headers)
        if body:
            self.assertEqual(set(json.loads(body)), {"detail"})
        for value in (PASSWORD.encode(), basic().encode(), *PAYLOADS.values()):
            self.assertNotIn(value, body)

    def test_nonprimary_mount_root_and_complete_immediate_inventories(self):
        self.start()
        self.setup_reads()
        for directory, paths in (("/", ["/README-synthetic.txt", "/nested"]),
                                 ("/nested", ["/nested/bytes.bin", "/nested/space name.txt"])):
            code, _, body = self.request("GET", target(API + "list", directory))
            self.assertEqual(code, 200)
            self.assertEqual(json.loads(body), {"files": [expected_info(path) for path in paths]})
        self.assertEqual(self.state.events, [("mounts", ""), ("root_info", "/"), ("list", "/"), ("list", "/nested")])
        self.assertEqual(self.state.payload_bytes, 0)
        self.assertEqual(self.state.unexpected, 0)

    def test_exact_metadata_md5_millisecond_timestamp_and_payload(self):
        self.start()
        self.setup_reads()
        for name, expected in PAYLOADS.items():
            path = "/" + name
            code, _, body = self.info(path)
            self.assertEqual(code, 200)
            self.assertEqual(json.loads(body), expected_info(path))
            code, headers, body = self.request("GET", target(CONTENT, path))
            self.assertEqual(code, 200)
            self.assertEqual(body, expected)
            self.assertEqual(int(headers["Content-Length"]), len(expected))
            self.assertEqual(hashlib.sha256(body).digest(), hashlib.sha256(expected).digest())
        self.assertEqual(self.state.payload_bytes, sum(map(len, PAYLOADS.values())))
        self.assertEqual(self.state.rejected_payload_bytes, 0)
        self.assertEqual(self.state.unexpected, 0)

    def test_only_designated_wrong_tuple_qualifies_auth_denial(self):
        self.start()
        self.error(self.request("GET", MOUNTS, auth=basic(WRONG)), 401)
        self.assertEqual(self.state.events, [("auth_denied", "")])
        self.assertEqual(self.state.auth_denied, 1)
        self.assertEqual(self.state.authenticated, 0)
        self.assertEqual(self.state.payload_bytes, 0)
        for auth in (False, "Basic malformed", basic(WRONG, "other-user"), basic("unregistered-wrong")):
            self.error(self.request("GET", MOUNTS, auth=auth), 401)
        self.assertEqual(self.state.auth_denied, 1)
        self.assertEqual(self.state.unexpected, 4)

    def test_correct_basic_member_denial_requires_successful_mount_and_root(self):
        self.start("member_denied")
        self.setup_reads()
        self.error(self.info("/README-synthetic.txt"), 401)
        self.assertEqual(self.state.events, [("mounts", ""), ("root_info", "/"), ("member_denied", "/README-synthetic.txt")])
        self.assertEqual(self.state.member_denied, 1)
        self.assertEqual(self.state.auth_denied, 0)
        self.error(self.request("GET", target(CONTENT, "/README-synthetic.txt")), 400)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_root_probe_and_same_member_info_cannot_be_skipped(self):
        self.start()
        self.error(self.info("/README-synthetic.txt"), 400)
        self.request("GET", MOUNTS)
        self.error(self.info("/README-synthetic.txt"), 400)
        self.info("/")
        self.info("/nested/bytes.bin")
        self.error(self.request("GET", target(CONTENT, "/README-synthetic.txt")), 400)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_missing_info_is_distinct_from_missing_content_or_malformed_path(self):
        self.start()
        self.setup_reads()
        path = "/missing-synthetic-object.bin"
        self.error(self.info(path), 404)
        self.assertEqual(self.state.events[-1], ("file_missing", path))
        self.error(self.request("GET", target(CONTENT, path)), 404)
        self.assertEqual(self.state.events[-1], ("content_missing", path))
        self.error(self.info("/unregistered-missing"), 400)
        self.assertEqual(self.state.missing, 2)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_known_authenticated_delete_is_rejected_without_source_or_metadata_change(self):
        self.start()
        self.setup_reads()
        before = dict(self.state.files)
        self.error(self.request("DELETE", target(API + "remove", "/README-synthetic.txt")), 405)
        self.assertEqual(self.state.rejected_mutations, 1)
        self.assertEqual(self.state.events[-1], ("write_denied", "/README-synthetic.txt"))
        self.assertEqual(self.state.files, before)
        self.assertEqual(self.state.modified_ms, 1704067200123)
        self.error(self.request("DELETE", target(API + "remove", "/nested/bytes.bin")), 400)
        self.assertEqual(self.state.rejected_mutations, 1)

    def test_ranges_are_unit_only_and_match_independent_bytes_with_clamping(self):
        self.start()
        self.setup_reads()
        self.info("/nested/bytes.bin")
        for value, start, end in (("bytes=3-7", 3, 7), ("bytes=2046-", 2046, 2047), ("bytes=2046-99999", 2046, 2047)):
            code, headers, body = self.request("GET", target(CONTENT, "/nested/bytes.bin"), extra=[("Range", value)])
            self.assertEqual(code, 206)
            self.assertEqual(headers["Content-Range"], f"bytes {start}-{end}/2048")
            self.assertEqual(body, PAYLOADS["nested/bytes.bin"][start:end + 1])
        before = self.state.payload_bytes
        for value in ("bytes=-3", "bytes=8-3", "bytes=2048-", "bytes=0-1,3-4", "items=0-1",
                      "bytes=" + "9" * 5000 + "-", "bytes=0-" + "9" * 5000):
            self.error(self.request("GET", target(CONTENT, "/nested/bytes.bin"), extra=[("Range", value)]), 416)
        self.assertEqual(self.state.payload_bytes, before)

    def test_empty_payload_is_unit_only_and_not_added_to_native_manifest(self):
        self.start()
        self.state.files["empty-unit-only.txt"] = b""
        self.setup_reads()
        self.assertEqual(self.info("/empty-unit-only.txt")[0], 200)
        code, headers, body = self.request("GET", target(CONTENT, "/empty-unit-only.txt"))
        self.assertEqual((code, headers["Content-Length"], body), (200, "0", b""))
        self.error(self.request("GET", target(CONTENT, "/empty-unit-only.txt"), extra=[("Range", "bytes=0-")]), 416)
        self.assertEqual(len(FIXTURES.FILES), 3)

    def test_path_queries_reject_alias_controls_malformed_utf8_and_duplicates(self):
        self.start()
        self.setup_reads()
        bad = ["", "README-synthetic.txt", "//nested", "/nested/", "/nested/../README-synthetic.txt", "/nested\\bytes.bin",
               "/nested%2Fbytes.bin", "/x\x00", "/x\r", "/x\n", "/x\x85"]
        for path in bad:
            self.error(self.info(path), 400)
        for query in ("path=%FF", "path=%", "path=%Q1", "path=%2F&path=%2F", "path=%2F&extra=1", "path"):
            self.error(self.request("GET", API + "info?" + query), 400)
        self.assertEqual(self.state.payload_bytes, 0)
        self.assertEqual(self.state.missing, 0)

    def test_duplicate_headers_wrong_host_bodies_and_ranges_on_metadata_are_rejected(self):
        self.start()
        for extra, body, host in (([("Host", f"127.0.0.1:{self.port}")], None, True),
                                  ([("Authorization", basic())], None, True),
                                  ([("Content-Length", "0"), ("Content-Length", "0")], None, True),
                                  ([("Transfer-Encoding", "chunked")], None, True),
                                  ([("Content-Length", "1")], b"x", True),
                                  ([("Range", "bytes=0-1")], None, True),
                                  ([("Host", "localhost")], None, False)):
            self.error(self.request("GET", MOUNTS, extra=extra, body=body, host=host), 400)
        self.assertEqual(self.state.authenticated, 0)
        self.assertEqual(self.state.events, [])

    def test_unknown_mount_route_method_and_absolute_or_normalized_wire_target_are_observable(self):
        self.start()
        for method, path, status in (("GET", "/api/v2/mounts/other/files/info?path=%2F", 400),
                                     ("POST", MOUNTS, 400), ("PATCH", MOUNTS, 501), ("OPTIONS", MOUNTS, 501)):
            self.error(self.request(method, path), status)
        for path in ("//api/v2/mounts", "http://127.0.0.1:" + str(self.port) + MOUNTS):
            request = f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\nAuthorization: {basic()}\r\n\r\n"
            with socket.create_connection(("127.0.0.1", self.port), timeout=3) as client:
                client.sendall(request.encode())
                with http.client.HTTPResponse(client) as response:
                    response.begin()
                    self.error((response.status, dict(response.getheaders()), response.read(16385)), 400)
        self.assertEqual(self.state.unexpected, 6)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_budget_exhaustion_prevents_further_authenticated_data(self):
        for limit in ("requests", "bytes"):
            state = FIXTURES.KoofrState(USER, PASSWORD)
            with FIXTURES.serve("koofr", state) as self.port:
                if limit == "requests": state.request_limit = 0
                else: state.byte_limit = 0
                self.error(self.request("GET", MOUNTS), 429)
                self.assertTrue(state.budget_exceeded)
                self.assertEqual(state.payload_bytes, 0)
            self.assertTrue(state.cleanup_complete)

    def test_absolute_deadline_and_admission_caps_close_owned_sockets(self):
        for mode in ("slow", "total", "active"):
            state = FIXTURES.KoofrState(USER, PASSWORD)
            state.request_timeout = 0.2
            if mode == "total": state.connection_limit = 0
            if mode == "active": state.active_connection_limit = 1
            started = time.monotonic()
            sockets = []
            with FIXTURES.serve("koofr", state) as port:
                try:
                    first = socket.create_connection(("127.0.0.1", port), timeout=2)
                    sockets.append(first)
                    if mode == "slow": first.sendall(b"GET /api/v2/mounts HTTP/1.1\r\nHost:")
                    if mode == "active":
                        # Wait only for the first owned socket's admission.
                        deadline = time.monotonic() + 1
                        while not state.accepted_connections and time.monotonic() < deadline: time.sleep(0.005)
                        second = socket.create_connection(("127.0.0.1", port), timeout=2)
                        sockets.append(second)
                    try:
                        self.assertEqual(sockets[-1].recv(4096), b"")
                    except (ConnectionResetError, ConnectionAbortedError):
                        pass
                finally:
                    for client in sockets: client.close()
            self.assertLess(time.monotonic() - started, 2)
            self.assertTrue(state.cleanup_complete)
            self.assertTrue(state.budget_exceeded)
            self.assertEqual(state.payload_bytes, 0)
            self.assertEqual(state.sockets, set())
            if mode != "slow": self.assertGreaterEqual(state.admission_denied, 1)


if __name__ == "__main__":
    unittest.main()
