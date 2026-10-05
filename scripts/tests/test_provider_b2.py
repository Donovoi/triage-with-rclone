"""Independent native-B2 protocol subset tests; never execute rclone or the app."""

import base64
import hashlib
import http.client
import json
from pathlib import Path
import socket
import sys
import threading
import time
import unittest
import urllib.parse

sys.path.insert(0, str(Path(__file__).parents[1] / "provider-lab"))
try:
    import fixture_servers as FIXTURES
finally:
    sys.path.pop(0)

EXPECTED = {
    "README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
    "nested/space name.txt": b"Nested synthetic payload.\n",
    "nested/bytes.bin": bytes(range(256)) * 8,
}
AUTH = "/b2api/v4/b2_authorize_account"
LIST = "/b2api/v1/b2_list_file_names"
HEAD = "/file/synthetic-bucket/README-synthetic.txt"
BASIC = "Basic " + base64.b64encode(b"synthetic-key-id:synthetic-key").decode()


class B2ServerTests(unittest.TestCase):
    def start(self, mode="normal"):
        self.state = FIXTURES.B2State("synthetic-key-id", "synthetic-key", mode)
        self.port = self.enterContext(FIXTURES.serve("b2", self.state))

    def request(self, method, path, token=None, body=None, headers=(), host=True):
        client = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            client.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            if host:
                client.putheader("Host", f"127.0.0.1:{self.port}")
            if token is not None:
                client.putheader("Authorization", token)
            for key, value in headers:
                client.putheader(key, value)
            client.endheaders(body)
            response = client.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            client.close()

    def post(self, path, token, value):
        body = json.dumps(value).encode()
        return self.request("POST", path, token, body,
                            (("Content-Type", "application/json"), ("Content-Length", str(len(body)))))

    def grant(self):
        status, headers, raw = self.request("GET", AUTH, BASIC)
        self.assertEqual(status, 200)
        self.assertNotIn("Location", headers)
        value = json.loads(raw)
        storage = value["apiInfo"]["storageApi"]
        self.assertEqual(storage["apiUrl"], f"http://127.0.0.1:{self.port}")
        self.assertEqual(storage["downloadUrl"], storage["apiUrl"])
        self.assertEqual(storage["allowed"], {"buckets": [{"id": self.state.bucket_id, "name": "synthetic-bucket"}],
                                            "capabilities": ["listFiles", "readFiles"], "namePrefix": None})
        return value["authorizationToken"]

    def download(self, token, name="README-synthetic.txt", headers=()):
        return self.request("GET", "/b2api/v1/b2_download_file_by_id?fileId=" + self.state.ids[name], token, headers=headers)

    def assert_error(self, response, status):
        code, headers, body = response
        self.assertEqual(code, status)
        self.assertNotIn("Location", headers)
        self.assertLessEqual(len(body), 256)
        if body:
            self.assertEqual(json.loads(body)["status"], status)
        for payload in EXPECTED.values():
            self.assertNotIn(payload, body)
        self.assertNotIn(b"authorizationToken", body)

    def test_bad_basic_and_duplicate_authorization_never_grant_or_serve_data(self):
        self.start()
        for token, headers in ((None, ()), ("Basic wrong", ()), (BASIC, (("Authorization", BASIC),))):
            self.assert_error(self.request("GET", AUTH, token, headers=headers), 401)
        self.assertEqual((self.state.generation, self.state.payload_bytes, self.state.auth_denied), (0, 0, 3))

    def test_tokens_are_distinct_and_previous_token_cannot_read(self):
        self.start()
        first, second = self.grant(), self.grant()
        self.assertNotEqual(first, second)
        self.assert_error(self.download(first), 401)
        self.assertEqual(self.download(second)[2], EXPECTED["README-synthetic.txt"])

    def test_listing_v1_sizes_sha1_prefix_delimiter_and_inclusive_marker(self):
        self.start()
        token = self.grant()
        code, _, body = self.post(LIST, token, {"bucketId": self.state.bucket_id, "maxFileCount": 1000})
        self.assertEqual(code, 200)
        rows = json.loads(body)
        self.assertIsNone(rows["nextFileName"])
        self.assertEqual({item["fileName"] for item in rows["files"]}, set(EXPECTED))
        for item in rows["files"]:
            payload = EXPECTED[item["fileName"]]
            self.assertEqual(item["size"], len(payload))
            self.assertEqual(item["contentSha1"], hashlib.sha1(payload).hexdigest())
        _, _, body = self.post(LIST, token, {"bucketId": self.state.bucket_id, "delimiter": "/"})
        rows = json.loads(body)["files"]
        self.assertEqual([(item["fileName"], item["action"]) for item in rows],
                         [("README-synthetic.txt", "upload"), ("nested/", "folder")])
        _, _, body = self.post(LIST, token, {"bucketId": self.state.bucket_id, "prefix": "nested/",
                                          "startFileName": "nested/bytes.bin", "maxFileCount": 1})
        rows = json.loads(body)
        self.assertEqual(rows["files"][0]["fileName"], "nested/bytes.bin")
        self.assertEqual(rows["nextFileName"], "nested/space name.txt")

    def test_head_and_exact_id_download_have_independent_hashes_and_metadata(self):
        self.start()
        token = self.grant()
        for name, expected in EXPECTED.items():
            status, headers, body = self.request("HEAD", "/file/synthetic-bucket/" + urllib.parse.quote(name), token)
            self.assertEqual((status, body), (200, b""))
            self.assertEqual(int(headers["Content-Length"]), len(expected))
            self.assertEqual(urllib.parse.unquote(headers["X-Bz-File-Name"]), name)
            self.assertEqual(headers["X-Bz-Content-Sha1"], hashlib.sha1(expected).hexdigest())
            code, _, payload = self.download(token, name)
            self.assertEqual(code, 200)
            self.assertEqual(hashlib.sha256(payload).digest(), hashlib.sha256(expected).digest())

    def test_renewal_is_head_then_expired_get_then_new_token_retry(self):
        self.start("renew")
        first = self.grant()
        self.assertEqual(self.request("HEAD", HEAD, first)[0], 200)
        response = self.download(first)
        self.assert_error(response, 401)
        self.assertEqual(json.loads(response[2])["code"], "expired_auth_token")
        self.assertEqual(self.state.payload_bytes, 0)
        second = self.grant()
        self.assertNotEqual(first, second)
        self.assertEqual(self.download(second)[2], EXPECTED["README-synthetic.txt"])
        self.assertEqual(self.state.events, [("grant", 1), ("head", 1), ("get_401", 1), ("grant", 2), ("get", 2)])
        self.assertEqual(self.state.rejected_payload_bytes, 0)

    def test_denial_permits_only_expired_retry_and_never_a_second_grant(self):
        self.start("deny")
        token = self.grant()
        self.request("HEAD", HEAD, token)
        for _ in range(2):
            self.assert_error(self.download(token), 401)
            for _ in range(2):
                self.assert_error(self.request("GET", AUTH, BASIC), 401)
        self.assertEqual((self.state.expired_gets, self.state.renewal_denied, self.state.generation), (2, 4, 1))
        self.assertEqual(self.state.payload_bytes, 0)
        self.assertEqual(self.state.storage_denied, 0)

    def test_renewal_refuses_get_without_head_and_wrong_target(self):
        for name, with_head in (("README-synthetic.txt", False), ("nested/bytes.bin", True)):
            with self.subTest(name=name):
                state = FIXTURES.B2State("synthetic-key-id", "synthetic-key", "renew")
                with FIXTURES.serve("b2", state) as self.port:
                    self.state = state
                    token = self.grant()
                    if with_head:
                        self.request("HEAD", HEAD, token)
                    self.assert_error(self.download(token, name), 400)
                    self.assertEqual(state.payload_bytes, 0)

    def test_unknown_file_directory_and_ids_have_no_payload(self):
        self.start()
        token = self.grant()
        for method, path in (("HEAD", "/file/synthetic-bucket/missing"), ("HEAD", "/file/synthetic-bucket/nested"),
                             ("GET", "/b2api/v1/b2_download_file_by_id?fileId=unknown")):
            self.assert_error(self.request(method, path, token), 404)
        self.assertEqual(self.state.missing, 3)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_unrelated_head_cannot_enable_renewal_and_head_ranges_are_rejected(self):
        self.start("renew")
        token = self.grant()
        self.assert_error(self.request("HEAD", "/file/synthetic-bucket/nested/bytes.bin", token), 400)
        self.assert_error(self.download(token), 400)
        self.assertNotIn(("head", 1), self.state.events)
        self.assertEqual(self.state.forced_401, 0)
        self.assert_error(self.request("HEAD", HEAD, token, headers=(("Range", "bytes=0-1"),)), 400)
        self.assert_error(self.post(LIST, token, {"bucketId": self.state.bucket_id}), 400)

    def test_storage_auth_duplicate_headers_and_foreign_bucket_fail_closed(self):
        self.start()
        token = self.grant()
        self.assert_error(self.request("HEAD", HEAD), 401)
        self.assert_error(self.request("HEAD", HEAD, token, headers=(("Authorization", token),)), 401)
        self.assert_error(self.request("HEAD", "/file/wrong-bucket/README-synthetic.txt", token), 400)
        self.assert_error(self.post(LIST, token, {"bucketId": "wrong"}), 400)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_list_rejects_invalid_shapes_keys_types_duplicates_and_discovery(self):
        self.start()
        token = self.grant()
        for value in ([], {"bucketId": self.state.bucket_id, "maxFileCount": True},
                      {"bucketId": self.state.bucket_id, "maxFileCount": 1001},
                      {"bucketId": self.state.bucket_id, "prefix": "../"},
                      {"bucketId": self.state.bucket_id, "prefix": []},
                      {"bucketId": self.state.bucket_id, "delimiter": "?"},
                      {"bucketId": self.state.bucket_id, "unknown": "value"}):
            self.assert_error(self.post(LIST, token, value), 400)
        raw = b'{"bucketId":"synthetic-bucket-id","bucketId":"synthetic-bucket-id"}'
        self.assert_error(self.request("POST", LIST, token, raw,
            (("Content-Type", "application/json"), ("Content-Length", str(len(raw))))), 400)
        self.assert_error(self.post("/b2api/v1/b2_list_buckets", token, {"accountId": "synthetic-account"}), 400)

    def test_exact_authenticated_upload_guard_preserves_served_mapping(self):
        self.start()
        token = self.grant()
        before = dict(self.state.files)
        self.assert_error(self.post("/b2api/v1/b2_get_upload_url", token, {"bucketId": self.state.bucket_id}), 403)
        self.assertEqual(self.state.rejected_mutations, 1)
        self.assertEqual(self.state.files, before)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_host_framing_query_and_traversal_are_rejected(self):
        self.start()
        token = self.grant()
        cases = [(AUTH, {"host": False}), (AUTH, {"headers": (("Host", "127.0.0.1:1"),)}),
                 (AUTH, {"headers": (("Content-Length", "1"),), "body": b"x"}),
                 (AUTH, {"headers": (("Transfer-Encoding", "chunked"),)}),
                 (AUTH, {"headers": (("Content-Length", "0"), ("Content-Length", "0"))}),
                 (AUTH + "?unexpected=1", {}), ("http://example.invalid" + AUTH, {}),
                 ("/b2api//v4/b2_authorize_account", {}), ("/b2api/./v4/b2_authorize_account", {}),
                 ("/%622api/v4/b2_authorize_account", {}),
                 ("/file/synthetic-bucket/%2e%2e/README-synthetic.txt", {}),
                 ("/b2api/v1/b2_download_file_by_id?fileId=a&fileId=b", {})]
        for case, (path, kwargs) in enumerate(cases, start=1):
            with self.subTest(case=case):
                self.assert_error(self.request("GET", path, token, **kwargs), 400)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_range_is_single_bounded_and_exact(self):
        self.start()
        token = self.grant()
        code, headers, body = self.download(token, headers=(("Range", "bytes=2-5"),))
        self.assertEqual((code, body), (206, EXPECTED["README-synthetic.txt"][2:6]))
        self.assertEqual(headers["Content-Range"], f"bytes 2-5/{len(EXPECTED['README-synthetic.txt'])}")
        for value in ("bytes=-2", "bytes=0-9999", "bytes=0-1,3-4", "bytes=9-2"):
            self.assert_error(self.download(token, headers=(("Range", value),)), 416)

    def test_request_deadline_and_count_fail_closed(self):
        self.start()
        self.state.request_limit = 0
        self.assert_error(self.request("GET", AUTH, BASIC), 429)
        self.state.request_limit = 128
        self.state.deadline = time.monotonic() - 1
        self.assert_error(self.request("GET", AUTH, BASIC), 429)
        self.assertTrue(self.state.budget_exceeded)
        self.assertEqual(self.state.generation, 0)

    def test_incomplete_post_body_fails_without_waiting_for_inactivity(self):
        self.start()
        token = self.grant()
        with socket.create_connection(("127.0.0.1", self.port), timeout=2) as client:
            client.sendall((f"POST {LIST} HTTP/1.0\r\nHost: 127.0.0.1:{self.port}\r\n"
                            f"Authorization: {token}\r\nContent-Type: application/json\r\n"
                            "Content-Length: 100\r\n\r\n{").encode())
            client.shutdown(socket.SHUT_WR)
            response = http.client.HTTPResponse(client)
            response.begin()
            self.assertEqual(response.status, 400)
            self.assertNotIn(EXPECTED["README-synthetic.txt"], response.read())
        self.assertEqual(self.state.unexpected, 1)

    def test_slow_post_body_hits_absolute_deadline_and_releases_cleanup_lock(self):
        state = FIXTURES.B2State("synthetic-key-id", "synthetic-key")
        with FIXTURES.serve("b2", state) as self.port:
            self.state = state
            token = self.grant()
            state.deadline = time.monotonic() + 0.2
            stop = threading.Event()
            with socket.create_connection(("127.0.0.1", self.port), timeout=2) as client:
                client.sendall((f"POST {LIST} HTTP/1.0\r\nHost: 127.0.0.1:{self.port}\r\n"
                                f"Authorization: {token}\r\nContent-Type: application/json\r\n"
                                "Content-Length: 100\r\n\r\n").encode())

                def feed():
                    for _ in range(40):
                        if stop.wait(0.025):
                            return
                        try:
                            client.sendall(b" ")
                        except OSError:
                            return

                thread = threading.Thread(target=feed)
                thread.start()
                started = time.monotonic()
                try:
                    try:
                        self.assertEqual(client.recv(1024), b"")
                    except (ConnectionResetError, ConnectionAbortedError):
                        pass  # A final feed byte racing close can reset or abort on Windows.
                    self.assertLess(time.monotonic() - started, 1.5)
                finally:
                    stop.set()
                    thread.join(2)
                self.assertFalse(thread.is_alive())
            self.assertTrue(state.budget_exceeded)
            self.assertEqual(state.payload_bytes, 0)
        self.assertTrue(state.cleanup_complete)

    def test_cleanup_closes_owned_threads_listener_and_sockets_even_on_failure(self):
        state = FIXTURES.B2State("synthetic", "synthetic")
        with self.assertRaisesRegex(RuntimeError, "synthetic_failure"):
            with FIXTURES.serve("b2", state) as port:
                connection = socket.create_connection(("127.0.0.1", port), timeout=2)
                connection.sendall(b"GET / HTTP/1.0\r\n")
                connection.close()
                raise RuntimeError("synthetic_failure")
        self.assertTrue(state.cleanup_complete)
        self.assertFalse(state.sockets)
        with socket.socket() as probe:
            self.assertNotEqual(probe.connect_ex(("127.0.0.1", port)), 0)


if __name__ == "__main__":
    unittest.main()
