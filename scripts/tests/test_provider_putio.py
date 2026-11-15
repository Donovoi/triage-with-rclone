"""Independent Putio wire oracles; no vendor or native acceptance."""
import urllib.parse
import hashlib
import http.client
import json
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

LAB = Path(__file__).resolve().parents[1] / "provider-lab"
sys.path.insert(0, str(LAB))
try:
    import fixture_putio as C
    import fixture_tls as T
finally:
    sys.path.pop(0)

NAME = "api.put.io"
API = "/v2/files/list"
KEY, SECRET = "synthetic-key", "synthetic-secret"
PAYLOADS = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
            "nested/bytes.bin": bytes(range(256)) * 8, "nested/space name.txt": b"Nested synthetic payload.\n"}

CRC32 = {"README-synthetic.txt": "d8bd62dd", "nested/bytes.bin": "9f5edd58", "nested/space name.txt": "065f565f"}

class PutioWireTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.state = C.PutioState(SECRET)
        # Wire tests use ephemeral IP TLS, so they also run on Windows without
        # DNS/privileged ports. The contained native probe owns fixed-host TLS.
        self.certificates = self.enterContext(T.FixtureCertificates.create(self.root))
        self.transport = self.enterContext(T.BoundedHttpsServer(self.certificates, C.PutioHandler, state=self.state))

    def request(self, method, path, data=None, auth="Bearer " + SECRET, headers=(), raw_body=None, host=NAME):
        body = raw_body if raw_body is not None else json.dumps(data).encode() if data is not None else b""
        client = http.client.HTTPSConnection("127.0.0.1", self.transport.port, timeout=3,
                                             context=self.certificates.client_context())
        try:
            client.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            client.putheader("Host", host)
            if auth is not None:
                client.putheader("Authorization", auth)
            if body:
                client.putheader("Content-Length", str(len(body)))
                client.putheader("Content-Type", "application/json")
            for k, v in headers:
                client.putheader(k, v)
            client.endheaders(body)
            response = client.getresponse()
            return response.status, dict(response.getheaders()), response.read(65537)
        finally:
            client.close()




    def list(self, identity="0", **kwargs):
        return self.request("GET", API + "?parent_id=" + identity + "&per_page=1000", **kwargs)

    def continuation(self, cursor, **kwargs):
        return self.request("POST", "/v2/files/list/continue", {"cursor": cursor}, **kwargs)

    def inventory(self, identity="0"):
        status, _, raw = self.list(identity)
        self.assertEqual(status, 200)
        first = json.loads(raw)
        status, _, raw = self.continuation(first["cursor"])
        self.assertEqual(status, 200)
        last = json.loads(raw)
        self.assertEqual(last["cursor"], "")
        return first, last

    def link(self, identity="1101"):
        status, _, raw = self.request("GET", "/v2/files/" + identity + "/url?notunnel=0")
        self.assertEqual(status, 200)
        url = urllib.parse.urlsplit(json.loads(raw)["url"])
        self.assertEqual((url.scheme, url.netloc, url.query, url.fragment), ("https", NAME, "", ""))
        self.assertRegex(url.path, r"^/content/[a-f0-9]{32}$")
        return url.path

    def test_saved_bearer_is_required_for_all_api_routes(self):
        for auth in (None, "", "Bearer wrong", "bearer " + SECRET, "Bearer " + SECRET + "x"):
            for method, path, data in (("GET", API + "?parent_id=0&per_page=1000", None),
                                      ("GET", "/v2/files/0/child?name=README-synthetic.txt", None),
                                      ("GET", "/v2/files/1101/url?notunnel=0", None),
                                      ("POST", "/v2/files/list/continue", {"cursor": "unknown"})):
                with self.subTest(auth=auth, path=path):
                    status, _, raw = self.request(method, path, data, auth=auth)
                    self.assertEqual((status, json.loads(raw)), (401, {"error_type": "SyntheticError", "error_message": "synthetic invalid token"}))
        self.assertEqual((self.state.denied, self.state.payload_bytes), (20, 0))
        self.assertEqual((self.state.listed, self.state.links, self.state.cursors), (set(), {}, {}))

    def test_two_page_inventory_has_independent_crc32_ids_types_sizes_and_times(self):
        for folder, names in (("0", ["README-synthetic.txt"]), ("10", ["nested/bytes.bin", "nested/space name.txt"])):
            first, last = self.inventory(folder)
            expected = []
            for name in names:
                expected.append({"id": 1101 + list(PAYLOADS).index(name), "parent_id": int(folder),
                    "name": name.rsplit("/", 1)[-1], "size": len(PAYLOADS[name]),
                    "content_type": "application/octet-stream", "created_at": "2024-01-01T00:00:00",
                    "updated_at": "2024-01-01T00:00:00", "crc32": CRC32[name]})
            if folder == "0":
                expected.append({"id": 10, "parent_id": 0, "name": "nested", "size": 0,
                    "content_type": "application/x-directory", "created_at": "2024-01-01T00:00:00",
                    "updated_at": "2024-01-01T00:00:00"})
            self.assertEqual(first["files"] + last["files"], expected)
            self.assertEqual(len(first["files"]), 1)
            self.assertEqual(set(first), {"files", "parent", "cursor"})
            self.assertEqual(set(last), {"files", "cursor"})
            self.assertEqual(first["parent"], {"id": int(folder), "parent_id": 0,
                "name": "synthetic" if folder == "0" else "nested", "size": 0,
                "content_type": "application/x-directory", "created_at": "2024-01-01T00:00:00",
                "updated_at": "2024-01-01T00:00:00"})
        self.assertEqual((self.state.continuations, self.state.cursors), (2, {}))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_cursor_requires_issuance_exact_json_and_single_consumption(self):
        self.assertEqual(self.continuation("unknown")[0], 400)
        first = json.loads(self.list()[2])
        cursor = first["cursor"]
        self.assertEqual(self.continuation(cursor, auth="Bearer wrong")[0], 401)
        for data in ({}, {"cursor": None}, {"cursor": 1}, {"cursor": []}, {"cursor": cursor, "extra": 1}):
            self.assertEqual(self.request("POST", "/v2/files/list/continue", data)[0], 400)
        for raw in (b'[]', b'{"cursor":"one","cursor":"two"}'):
            self.assertEqual(self.request("POST", "/v2/files/list/continue", raw_body=raw)[0], 400)
        self.assertEqual(self.continuation(cursor)[0], 200)
        self.assertEqual(self.continuation(cursor)[0], 400)
        self.assertEqual(self.state.continuations, 1)

    def test_unreturned_page_cannot_authorize_link_issuance(self):
        first = json.loads(self.list("10")[2])
        self.assertEqual(self.state.listed, {"1102"})
        self.assertEqual(self.request("GET", "/v2/files/1103/url?notunnel=0")[0], 400)
        self.continuation(first["cursor"])
        self.assertEqual(self.request("GET", "/v2/files/1103/url?notunnel=0")[0], 200)

    def test_child_lookup_matches_encoded_name_and_reports_missing(self):
        for target, name in (("/v2/files/0/child?name=README-synthetic.txt", "README-synthetic.txt"),
                             ("/v2/files/10/child?name=space+name.txt", "nested/space name.txt")):
            status, _, raw = self.request("GET", target)
            result = json.loads(raw)
            self.assertEqual(status, 200)
            self.assertEqual((result["file"]["name"], result["file"]["crc32"]), (name.rsplit("/", 1)[-1], CRC32[name]))
        status, _, raw = self.request("GET", "/v2/files/0/child?name=absent-synthetic.txt")
        self.assertEqual((status, json.loads(raw)), (404, {"error_type": "SyntheticError", "error_message": "synthetic child not found"}))
        self.assertEqual(self.state.missing, 1)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_issued_download_links_deliver_all_literal_bytes_without_bearer(self):
        self.inventory(); self.inventory("10")
        paths = []
        for identity, (name, payload) in enumerate(PAYLOADS.items(), 1101):
            path = self.link(str(identity)); paths.append(path)
            self.assertEqual(self.request("GET", path, auth=None)[::2], (200, payload))
        self.assertEqual(len(set(paths)), 3)
        self.assertEqual(self.state.payload_bytes, sum(map(len, PAYLOADS.values())))
        self.assertEqual(self.state.content_authorizations, 0)

    def test_download_rejects_forwarded_bearer_and_unknown_links(self):
        self.inventory(); path = self.link()
        for auth in ("Bearer " + SECRET, "Bearer wrong", ""):
            self.assertEqual(self.request("GET", path, auth=auth)[0], 400)
        self.assertEqual(self.request("GET", "/content/" + "0" * 32, auth=None)[0], 401)
        self.assertEqual((self.state.content_authorizations, self.state.payload_bytes), (3, 0))
        self.assertEqual(self.request("GET", path, auth=None)[::2], (200, PAYLOADS["README-synthetic.txt"]))

    def test_denied_download_and_authenticated_fixture_guard_preserve_sources(self):
        self.inventory(); path = self.link()
        self.state.mode = "read_denied"
        status, _, raw = self.request("GET", path, auth=None)
        self.assertEqual((status, json.loads(raw)), (403, {"error": "synthetic content denied"}))
        self.state.mode = "normal"
        self.assertEqual(self.request("DELETE", path, auth=None)[0], 401)
        self.assertEqual(self.request("DELETE", path)[0], 405)
        self.assertEqual((self.state.read_denied, self.state.rejected_mutations, self.state.payload_bytes), (1, 1, 0))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_unknown_routes_oauth_account_and_native_writes_are_outside_profile(self):
        for method, path in (("POST", "/v2/oauth2/access_token"), ("GET", "/v2/oauth2/validate"),
                             ("GET", "/v2/account/info"), ("POST", "/v2/files/delete"),
                             ("POST", "/v2/files/create-folder"), ("GET", "/content/foreign"),
                             ("HEAD", "/v2/files/list"), ("GET", "https://elsewhere.invalid/")):
            self.assertEqual(self.request(method, path)[0], 400)
        self.assertEqual((self.state.payload_bytes, self.state.rejected_mutations), (0, 0))

    def test_query_contract_rejects_wrong_ids_fields_encoding_and_tunnel_modes(self):
        for query in ("", "parent_id=0", "parent_id=0&per_page=1", "parent_id=1&per_page=1000",
                      "parent_id=0&per_page=1000&parent_id=0", "parent_id=0&per_page=1000&extra=1",
                      "parent_id=%GG&per_page=1000", "parent_id=%ff&per_page=1000"):
            self.assertEqual(self.request("GET", API + "?" + query)[0], 400)
        for value in ("", "name=%2F", "name=%5C", "name=%00", "name=%0a", "name=..", "name=x&name=x"):
            self.assertEqual(self.request("GET", "/v2/files/0/child?" + value)[0], 400)
        self.inventory()
        for query in ("", "notunnel=1", "notunnel=false", "notunnel=0&extra=1", "notunnel=0&notunnel=0"):
            self.assertEqual(self.request("GET", "/v2/files/1101/url?" + query)[0], 400)
        self.assertEqual(self.state.links, {})

    def test_authority_duplicate_headers_framing_and_metadata_ranges_are_exact(self):
        target = API + "?parent_id=0&per_page=1000"
        for host in ("127.0.0.1", NAME + ":443", NAME + ".", "API.put.io"):
            self.assertEqual(self.request("GET", target, host=host)[0], 400)
        for headers in ((("Host", NAME),), (("Authorization", "Bearer " + SECRET),),
                        (("Content-Length", "00"),), (("Content-Length", "4097"),),
                        (("Transfer-Encoding", "chunked"),), (("Range", "bytes=0-1"),)):
            self.assertEqual(self.request("GET", target, headers=headers)[0], 400)
        self.assertEqual(self.request("GET", target, raw_body=b"x")[0], 400)
        self.assertEqual(self.state.listed, set())

    def test_content_ranges_are_bounded(self):
        self.inventory("10"); path = self.link("1102")
        status, headers, raw = self.request("GET", path, auth=None, headers=(("Range", "bytes=256-511"),))
        self.assertEqual((status, headers["Content-Range"], raw), (206, "bytes 256-511/2048", bytes(range(256))))
        for value in ("bytes=0--1", "bytes=-1", "bytes=2048-", "bytes=2-1", "bytes=0-1,3-4"):
            self.assertEqual(self.request("GET", path, auth=None, headers=(("Range", value),))[0], 416)
        self.assertEqual(self.state.files, PAYLOADS)

    def test_request_and_response_budgets_prevent_success(self):
        self.state.request_limit = 1
        self.assertEqual(self.list()[0], 200)
        self.assertEqual(self.list()[0], 429)
        self.assertTrue(self.state.budget_exceeded)
        self.state.request_limit = 10
        self.state.byte_limit = 1
        self.assertEqual(self.list()[0], 429)

    def test_tls_deadline_stops_partial_headers(self):
        timer = threading.Timer
        with T.FixtureCertificates.create(self.root) as certificates, patch.object(
                T.threading, "Timer", side_effect=lambda delay, callback: timer(delay + 0.3, callback)):
            with T.BoundedHttpsServer(certificates, C.PutioHandler, state=C.PutioState(SECRET),
                    limits=T.TlsLimits(request_seconds=0.15)) as transport:
                with socket.create_connection(("127.0.0.1", transport.port), timeout=2) as raw:
                    with certificates.client_context().wrap_socket(raw, server_hostname="127.0.0.1") as client:
                        client.sendall(("GET " + API + "?parent_id=0&per_page=1000 HTTP/1.1\r\nHost: " + NAME).encode())
                        self.assertEqual(client.recv(1), b"")
            self.assertIn("tls_request_deadline", transport.snapshot()["failure_codes"])
            self.assertTrue(transport.cleanup_complete)
        self.assertTrue(certificates.cleanup_complete)

    def test_tls_deadline_stops_partial_json_without_an_http_reply(self):
        timer = threading.Timer
        with T.FixtureCertificates.create(self.root) as certificates, patch.object(
                T.threading, "Timer", side_effect=lambda delay, callback: timer(delay + 0.3, callback)):
            with T.BoundedHttpsServer(certificates, C.PutioHandler, state=C.PutioState(SECRET),
                    limits=T.TlsLimits(request_seconds=0.15)) as transport:
                with socket.create_connection(("127.0.0.1", transport.port), timeout=2) as raw:
                    with certificates.client_context().wrap_socket(raw, server_hostname="127.0.0.1") as client:
                        client.sendall(("POST " + API + "/file/ls.cgi HTTP/1.1\r\nHost: " + NAME
                            + "\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{").encode())
                        self.assertEqual(client.recv(1), b"")
            self.assertIn("tls_request_deadline", transport.snapshot()["failure_codes"])
            self.assertTrue(transport.cleanup_complete)
        self.assertTrue(certificates.cleanup_complete)

class PutioAuthorityTests(unittest.TestCase):
    def test_reviewed_name_has_its_own_exact_sni_and_san(self):
        with tempfile.TemporaryDirectory() as directory:
            with T.FixtureCertificates.create(Path(directory).resolve(), server_name=NAME) as certificates:
                from cryptography import x509
                leaf = x509.load_pem_x509_certificate((certificates.directory / "leaf.pem").read_bytes())
                self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value), [x509.DNSName(NAME)])
        self.assertIsNone(T._putio_sni(None, NAME, None))
        for name in (None, "", "fixture.pcloud.com", "api.cloudinary.com", "127.0.0.1", NAME + ".", NAME + ":443"):
            self.assertEqual(T._putio_sni(None, name, None), ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)
        self.assertEqual(T._pcloud_sni(None, NAME, None), ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)
        self.assertEqual(T._cloudinary_sni(None, NAME, None), ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)

    def test_fixed_port_is_linux_only_and_never_falls_back(self):
        calls = []
        def init(server, address, handler):
            calls.append(address)
            server.server_address = address
        with patch.object(T.HTTPServer, "__init__", init), patch.object(T.sys, "platform", "linux"):
            server = T._HttpServer(SimpleNamespace(_server_name=NAME), object, None)
            self.assertEqual(server.authority, NAME)
        self.assertEqual(calls, [("127.0.0.1", 443)])
        with patch.object(T.HTTPServer, "__init__") as bind, patch.object(T.sys, "platform", "win32"):
            with self.assertRaisesRegex(T.TlsError, "requires_linux"):
                T._HttpServer(SimpleNamespace(_server_name=NAME), object, None)
            bind.assert_not_called()

if __name__ == "__main__":
    unittest.main()
