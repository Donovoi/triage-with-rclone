"""Independent Seafile HTTP contract tests; no native client or account access."""

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

# Literal expectations come from pinned rclone v1.75.1 backend/seafile/{webapi,
# api/types}.go and lib/rest/rest.go, not the server's route/entry helpers.
LIBRARY = "11111111-2222-4333-8444-555555555555"
REPOS = "/api2/repos/"
API = REPOS + LIBRARY
DIRECTORY = "/api/v2.1/repos/" + LIBRARY + "/dir/"
INFO = "/api2/server-info/"
LOGIN = "/api2/auth-token/"
USER, PASSWORD = "fixture-user", "synthetic-password"
EXPECTED = {
    "README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
    "nested/space name.txt": b"Nested synthetic payload.\n",
    "nested/bytes.bin": bytes(range(256)) * 8,
}


class SeafileHttpTests(unittest.TestCase):
    def start(self, files=None):
        self.state = FIXTURES.SeafileState(USER, PASSWORD)
        if files is not None:
            self.state.files = dict(files)
        before = set(threading.enumerate())
        context = FIXTURES.serve("seafile", self.state)
        self.port = context.__enter__()
        self.addCleanup(self.finish, context, self.state, self.port, before)
        self.token = None

    def finish(self, context, state, port, before):
        context.__exit__(None, None, None)
        self.assertTrue(state.cleanup_complete)
        self.assertFalse(state.sockets)
        self.assertFalse(set(threading.enumerate()) - before)
        with socket.socket() as probe:
            probe.settimeout(0.3)
            self.assertNotEqual(probe.connect_ex(("127.0.0.1", port)), 0)

    def request(self, method, path, headers=(), body=None, host=True):
        client = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        try:
            client.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            if host:
                client.putheader("Host", f"127.0.0.1:{self.port}")
            pairs = list(headers)
            if body is not None and not any(k.lower() == "content-length" for k, _ in pairs):
                pairs.append(("Content-Length", str(len(body))))
            for name, value in pairs:
                client.putheader(name, value)
            client.endheaders(body)
            response = client.getresponse()
            return response.status, dict(response.getheaders()), response.read(8193)
        finally:
            client.close()

    def authorized(self, method, path, headers=(), body=None):
        return self.request(method, path, [("Authorization", "Token " + self.token), *headers], body)

    def json_ok(self, response):
        status, headers, body = response
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(int(headers["Content-Length"]), len(body))
        self.assertNotIn("Location", headers)
        return json.loads(body)

    def error(self, response, status):
        code, headers, body = response
        self.assertEqual(code, status)
        self.assertLess(len(body), 512)
        self.assertNotIn("Location", headers)
        self.assertNotIn(USER.encode(), body)
        self.assertNotIn(PASSWORD.encode(), body)
        if self.token:
            self.assertNotIn(self.token.encode(), body)
        for payload in EXPECTED.values():
            self.assertNotIn(payload, body)
        return json.loads(body) if body else None

    def server_info(self):
        self.assertEqual(self.json_ok(self.request("GET", INFO)), {"version": "7.0.0"})

    def login(self):
        self.server_info()
        body = json.dumps({"username": USER, "password": PASSWORD}).encode()
        result = self.json_ok(self.request("POST", LOGIN, [("Content-Type", "application/json")], body))
        self.assertEqual(set(result), {"token"})
        self.assertIsInstance(result["token"], str)
        self.assertGreaterEqual(len(result["token"]), 32)
        self.token = result["token"]

    def inventory(self):
        result = self.json_ok(self.authorized("GET", REPOS))
        self.assertEqual(result, [{"encrypted": False, "id": LIBRARY, "name": "Synthetic Library",
                                   "size": sum(len(value) for value in self.state.files.values()), "mtime": 1704067200}])

    def ready(self, files=None):
        self.start(files)
        self.login()
        self.inventory()

    @staticmethod
    def member_path(suffix, name):
        return API + suffix + "?" + urllib.parse.urlencode({"p": "/" + name})

    def link(self, name):
        detail = self.json_ok(self.authorized("GET", self.member_path("/file/detail/", name)))
        self.assertEqual(detail["type"], "file")
        self.assertEqual(detail["name"], name.rsplit("/", 1)[-1])
        self.assertEqual(detail["parent_dir"], "/" + name.rsplit("/", 1)[0] if "/" in name else "/")
        self.assertEqual(detail["last_modified"], "2024-01-01T00:00:00Z")
        link = self.json_ok(self.authorized("GET", self.member_path("/file/", name)))
        self.assertIsInstance(link, str)
        self.assertRegex(link, r"^fixture-download/[0-9a-f]{32}$")
        self.assertFalse(urllib.parse.urlsplit(link).scheme)
        return "/" + link, detail

    def test_account_acquisition_then_exact_member_bytes(self):
        self.ready()
        self.assertEqual(self.state.files, EXPECTED)
        name = "nested/space name.txt"
        link, detail = self.link(name)
        status, headers, body = self.authorized("GET", link)
        self.assertEqual(status, 200)
        self.assertEqual(detail["size"], len(EXPECTED[name]))
        self.assertEqual(int(headers["Content-Length"]), len(EXPECTED[name]))
        self.assertEqual(body, EXPECTED[name])
        self.assertEqual(hashlib.sha256(body).digest(), hashlib.sha256(EXPECTED[name]).digest())
        self.assertEqual(self.state.events, [("server_info", ""), ("auth_granted", ""), ("libraries", ""),
                                             ("file_detail", name), ("link_issued", name), ("payload", name)])
        self.assertEqual((self.state.login_attempts, self.state.grants, self.state.auth_uses), (1, 1, 4))
        self.assertEqual(self.state.requests, 6)
        self.assertEqual(self.state.rejected_payload_bytes, 0)

    def test_recursive_and_immediate_listing_names_parents_sizes_times(self):
        self.ready()
        cases = [('/', '0', {"README-synthetic.txt", "nested"}),
                 ('/', '1', set(EXPECTED) | {"nested"}),
                 ('/nested', '0', {"nested/space name.txt", "nested/bytes.bin"})]
        for root, recursive, expected in cases:
            with self.subTest(root=root, recursive=recursive):
                result = self.json_ok(self.authorized("GET", DIRECTORY + "?" + urllib.parse.urlencode({"p": root, "recursive": recursive})))
                self.assertEqual(set(result), {"dirent_list"})
                actual = {}
                for item in result["dirent_list"]:
                    name = (item["parent_dir"].rstrip("/") + "/" + item["name"]).lstrip("/")
                    self.assertNotIn(name, actual)
                    actual[name] = item
                    self.assertEqual(item["mtime"], 1704067200)
                    self.assertEqual(item["type"], "file" if name in EXPECTED else "dir")
                    self.assertEqual(item["size"], len(EXPECTED[name]) if name in EXPECTED else 0)
                self.assertEqual(set(actual), expected)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_wrong_password_is_json_auth_denial_without_token_or_read(self):
        self.start()
        self.server_info()
        body = json.dumps({"username": USER, "password": PASSWORD + "-wrong"}).encode()
        result = self.error(self.request("POST", LOGIN, [("Content-Type", "application/json")], body), 400)
        self.assertEqual(result, {"non_field_errors": ["fixture authentication denied"]})
        self.assertEqual(self.state.events, [("server_info", ""), ("auth_denied", "")])
        self.assertEqual((self.state.login_attempts, self.state.auth_denied, self.state.grants), (1, 1, 0))
        self.assertIsNone(self.state.token)
        self.assertEqual((self.state.auth_uses, self.state.payload_bytes), (0, 0))

    def test_designated_invalid_cached_token_skips_login(self):
        self.start()
        self.server_info()
        response = self.request("GET", REPOS, [("Authorization", "Token " + self.state.invalid_cached_token)])
        self.error(response, 403)
        self.assertEqual(self.state.events, [("server_info", ""), ("cached_denied", "")])
        self.assertEqual((self.state.cached_denied, self.state.login_attempts, self.state.grants), (1, 0, 0))
        self.assertEqual((self.state.auth_uses, self.state.payload_bytes), (0, 0))

    def test_unrelated_missing_or_malformed_token_cannot_count_cached_denial(self):
        self.start()
        self.server_info()
        for value in (None, "Basic arbitrary", "Token unrelated", "Token "):
            with self.subTest(value=value):
                self.error(self.request("GET", REPOS, [] if value is None else [("Authorization", value)]), 403)
        self.assertEqual(self.state.cached_denied, 0)
        self.assertEqual((self.state.grants, self.state.payload_bytes), (0, 0))

    def test_metadata_inventory_and_link_order_cannot_be_bypassed(self):
        self.start()
        body = json.dumps({"username": USER, "password": PASSWORD}).encode()
        self.error(self.request("POST", LOGIN, [("Content-Type", "application/json")], body), 400)
        self.assertFalse(self.state.events)
        self.login()
        self.error(self.authorized("GET", self.member_path("/file/detail/", "README-synthetic.txt")), 400)
        self.inventory()
        self.error(self.authorized("GET", self.member_path("/file/", "README-synthetic.txt")), 400)
        self.error(self.authorized("GET", "/fixture-download/" + "a" * 32), 400)
        self.assertEqual((self.state.payload_bytes, len(self.state.links)), (0, 0))

    def test_links_are_member_bound_and_wrong_token_never_returns_bytes(self):
        self.ready()
        first, _ = self.link("README-synthetic.txt")
        second, _ = self.link("nested/bytes.bin")
        self.assertNotEqual(first, second)
        self.error(self.request("GET", first, [("Authorization", "Token wrong")]), 403)
        self.assertEqual(self.state.payload_bytes, 0)
        self.assertEqual(self.authorized("GET", second)[2], EXPECTED["nested/bytes.bin"])
        self.assertEqual(self.authorized("GET", first)[2], EXPECTED["README-synthetic.txt"])

    def test_missing_and_directory_members_return_no_file_payload(self):
        self.ready()
        for name in ("absent.txt", "nested"):
            for suffix in ("/file/detail/", "/file/"):
                with self.subTest(name=name, suffix=suffix):
                    self.error(self.authorized("GET", self.member_path(suffix, name)), 404)
        self.error(self.authorized("GET", DIRECTORY + "?p=%2Fabsent&recursive=0"), 404)
        self.assertEqual(self.state.missing, 5)
        self.assertEqual((self.state.payload_bytes, len(self.state.links)), (0, 0))

    def test_valid_ranges_have_actual_206_and_only_requested_bytes(self):
        self.ready()
        link, _ = self.link("nested/bytes.bin")
        payload = EXPECTED["nested/bytes.bin"]
        total = 0
        for value, start, end in (("bytes=3-7", 3, 7), ("bytes=2045-", 2045, 2047)):
            code, headers, body = self.authorized("GET", link, [("Range", value)])
            self.assertEqual(code, 206)
            self.assertEqual(headers["Content-Range"], f"bytes {start}-{end}/{len(payload)}")
            self.assertEqual(int(headers["Content-Length"]), end - start + 1)
            self.assertEqual(body, payload[start:end + 1])
            total += len(body)
        self.assertEqual(self.state.payload_bytes, total)

    def test_invalid_ranges_reject_without_file_bytes(self):
        self.ready()
        link, _ = self.link("README-synthetic.txt")
        for value in ("bytes=8-3", "bytes=0-9999", "bytes=9999-", "bytes=0-1,4-5", "bytes=-3", "items=0-1", "bytes=a-b"):
            with self.subTest(value=value):
                self.error(self.authorized("GET", link, [("Range", value)]), 416)
        self.assertEqual((self.state.payload_bytes, self.state.rejected_payload_bytes), (0, 0))

    def test_empty_file_http_only_does_not_expand_native_shared_manifest(self):
        self.assertEqual(FIXTURES.FILES, EXPECTED)
        self.ready(dict(EXPECTED, **{"unit-only-empty.bin": b""}))
        link, detail = self.link("unit-only-empty.bin")
        self.assertEqual(detail["size"], 0)
        code, headers, body = self.authorized("GET", link)
        self.assertEqual((code, headers["Content-Length"], body), (200, "0", b""))
        self.error(self.authorized("GET", link, [("Range", "bytes=0-")]), 416)
        self.assertEqual(FIXTURES.FILES, EXPECTED)

    def test_malformed_auth_json_and_unicode_never_grant(self):
        self.start()
        self.server_info()
        bodies = [b'username=fixture-user&password=synthetic-password', b'[]', b'null',
                  b'{"username":"fixture-user","username":"other","password":"synthetic-password"}',
                  b'{"username":"fixture-user","password":"synthetic-password","extra":1}',
                  b'{"username":null,"password":"synthetic-password"}', b'{"username":"\xff","password":"p"}',
                  b'{"username":"\\ud800","password":"synthetic-password"}',
                  b'{"username":"fixture-user","password":"\\udfff"}']
        for body in bodies:
            with self.subTest(body=body):
                self.error(self.request("POST", LOGIN, [("Content-Type", "application/json")], body), 400)
        self.assertEqual((self.state.grants, self.state.login_attempts, self.state.payload_bytes), (0, 0, 0))
        self.assertEqual(self.state.events, [("server_info", "")])

    def test_exact_namespace_queries_and_decoded_controls(self):
        self.ready()
        invalid = [DIRECTORY + '?p=%2F&recursive=2', DIRECTORY + '?p=%2F&recursive=0&recursive=1',
                   DIRECTORY + '?p=%2F&recursive=0&extra=x', DIRECTORY + '?recursive=0',
                   API + '/file/detail/?p=relative', API + '/file/detail/?p=%2F..%2Fx',
                   API + '/file/detail/?p=%2Fnested%2F.%2Fx', API + '/file/detail/?p=%2Fnested%5Cx',
                   API + '/file/detail/?p=%2F%252e%252e%2Fx', API + '/file/detail/?p=%2Fx%00',
                   API + '/file/detail/?p=%2Fx%0A', API + '/file/detail/?p=%2Fx%7F',
                   API + '/file/detail/?p=%2Fx%C2%85', API + '/file/detail/?p=%FF',
                   API + '/file/detail/?p=%2G', API + '/file/detail/?p=%2Fx&p=%2Fy',
                   API + '/file/detail/?p=%2FREADME-synthetic.txt#fragment',
                   '/api2/repos/not-owned/file/detail/?p=%2FREADME-synthetic.txt',
                   '/api2/account/info/', '/api2/repos/' + LIBRARY + '/%66ile/detail/?p=%2Fx']
        for path in invalid:
            with self.subTest(path=path):
                self.error(self.authorized("GET", path), 400)
        self.assertEqual((self.state.missing, self.state.payload_bytes), (0, 0))

    def test_duplicate_headers_body_and_host_boundaries(self):
        self.ready()
        path = self.member_path('/file/detail/', 'README-synthetic.txt')
        cases = [([('Host', f'127.0.0.1:{self.port}')], None),
                 ([('Authorization', 'Token ' + self.token)], None),
                 ([('Transfer-Encoding', 'chunked')], None), ([('X-SEAFILE-OTP', '123456')], None),
                 ([('Content-Length', '1')], b'x'), ([('Content-Length', '-1')], None),
                 ([('Content-Length', '4097')], None), ([('Range', 'bytes=0-1')], None)]
        for headers, body in cases:
            with self.subTest(headers=headers):
                self.error(self.authorized('GET', path, headers, body), 400)
        self.error(self.request('GET', INFO, [('Host', f'localhost:{self.port}')], host=False), 400)
        self.error(self.request('GET', INFO, host=False), 400)
        self.error(self.authorized('GET', f'http://127.0.0.1:{self.port}' + path), 400)
        self.error(self.authorized('GET', '/' + path), 400)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_auth_headers_and_oversized_body_rejected_before_attempt(self):
        self.start()
        self.server_info()
        body = json.dumps({'username': USER, 'password': PASSWORD}).encode()
        for extra in ([('Authorization', 'Token unwanted')], [('X-SEAFILE-OTP', '123456')],
                      [('Content-Type', 'application/x-www-form-urlencoded')], [('Content-Length', '4097')]):
            headers = [('Content-Type', 'application/json'), *extra]
            self.error(self.request('POST', LOGIN, headers, body), 400)
        self.assertEqual((self.state.login_attempts, self.state.grants), (0, 0))

    def test_authenticated_mutations_preserve_all_source_bytes(self):
        self.ready()
        before = {name: hashlib.sha256(body).hexdigest() for name, body in EXPECTED.items()}
        for method in ('PUT', 'POST', 'DELETE'):
            self.error(self.authorized(method, self.member_path('/file/', 'README-synthetic.txt')), 403)
        self.assertEqual(self.state.rejected_mutations, 3)
        self.assertEqual(before, {name: hashlib.sha256(body).hexdigest() for name, body in self.state.files.items()})
        self.assertEqual((self.state.payload_bytes, self.state.rejected_payload_bytes), (0, 0))

    def test_unknown_methods_are_counted_rejections(self):
        self.ready()
        before = self.state.unexpected
        for method in ('PATCH', 'OPTIONS', 'CONNECT'):
            response = self.authorized(method, self.member_path('/file/', 'README-synthetic.txt'))
            self.error(response, 501)
        self.assertEqual(self.state.unexpected - before, 3)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_request_and_response_byte_budgets_stop_payload(self):
        self.ready()
        link, _ = self.link('README-synthetic.txt')
        self.state.byte_limit = self.state.response_bytes + 1
        self.error(self.authorized('GET', link), 429)
        self.assertTrue(self.state.budget_exceeded)
        self.assertEqual(self.state.payload_bytes, 0)
        self.state.request_limit = self.state.requests
        self.error(self.authorized('GET', link), 429)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_total_connection_admission_cap_closes_new_socket(self):
        self.start()
        self.state.connection_limit = 1
        self.server_info()
        client = socket.create_connection(('127.0.0.1', self.port), timeout=1)
        self.addCleanup(client.close)
        try:
            self.assertEqual(client.recv(4096), b'')
        except (ConnectionResetError, ConnectionAbortedError):
            pass
        self.assertEqual(self.state.accepted_connections, 2)
        self.assertEqual(self.state.admission_denied, 1)
        self.assertTrue(self.state.budget_exceeded)
        self.assertEqual((self.state.requests, self.state.grants, self.state.payload_bytes), (1, 0, 0))

    def test_active_connection_cap_does_not_spawn_another_handler(self):
        self.start()
        self.state.active_connection_limit = 1
        self.state.request_timeout = 0.5
        first = socket.create_connection(('127.0.0.1', self.port), timeout=1)
        self.addCleanup(first.close)
        first.sendall(b'GET /api2/server-info/ HTTP/1.0\r\n')
        deadline = time.monotonic() + 1
        while not self.state.accepted_connections and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(self.state.accepted_connections, 1)
        second = socket.create_connection(('127.0.0.1', self.port), timeout=1)
        self.addCleanup(second.close)
        try:
            self.assertEqual(second.recv(4096), b'')
        except (ConnectionResetError, ConnectionAbortedError):
            pass
        self.assertEqual(self.state.admission_denied, 1)
        self.assertTrue(self.state.budget_exceeded)
        self.assertLessEqual(len(self.state.sockets), 1)
        self.assertEqual((self.state.requests, self.state.grants, self.state.payload_bytes), (0, 0, 0))

    def test_absolute_body_deadline_and_cleanup_on_slow_feed(self):
        self.start()
        self.server_info()
        self.state.request_timeout = 0.3
        client = socket.create_connection(('127.0.0.1', self.port), timeout=1)
        self.addCleanup(client.close)
        started = time.monotonic()
        head = (f'POST {LOGIN} HTTP/1.0\r\nHost: 127.0.0.1:{self.port}\r\n'
                'Content-Type: application/json\r\nContent-Length: 100\r\n\r\n')
        client.sendall(head.encode())
        for _ in range(12):
            try:
                client.sendall(b' ')
            except OSError:
                break
            time.sleep(0.04)
        try:
            response = client.recv(4096)
        except (ConnectionResetError, ConnectionAbortedError):
            response = b''
        self.assertLess(time.monotonic() - started, 2)
        self.assertNotIn(b'"token"', response)
        deadline = time.monotonic() + 1
        while not self.state.budget_exceeded and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(self.state.budget_exceeded)
        self.assertEqual((self.state.grants, self.state.payload_bytes), (0, 0))

    def test_cleanup_closes_idle_accepted_socket(self):
        self.start()
        self.state.request_timeout = 0.25
        client = socket.create_connection(('127.0.0.1', self.port), timeout=1)
        self.addCleanup(client.close)
        client.sendall(b'GET /api2/server-info/ HTTP/1.0\r\n')
        try:
            self.assertEqual(client.recv(4096), b'')
        except (ConnectionResetError, ConnectionAbortedError):
            pass
        self.assertEqual(self.state.grants, 0)


if __name__ == '__main__':
    unittest.main()
