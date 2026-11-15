"""Independent Cloudinary wire oracles; no vendor or native acceptance."""
import base64
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
    import fixture_cloudinary as C
    import fixture_tls as T
finally:
    sys.path.pop(0)

NAME = "api.cloudinary.com"
API = "/v1_1/synthetic-cloud/"
KEY, SECRET = "synthetic-key", "synthetic-secret"
AUTH = "Basic " + base64.b64encode((KEY + ":" + SECRET).encode()).decode()
PAYLOADS = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
            "nested/bytes.bin": bytes(range(256)) * 8, "nested/space name.txt": b"Nested synthetic payload.\n"}

class CloudinaryWireTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.state = C.CloudinaryState(KEY, SECRET)
        # Wire tests use ephemeral IP TLS, so they also run on Windows without
        # DNS/privileged ports. The contained native probe owns fixed-host TLS.
        self.certificates = self.enterContext(T.FixtureCertificates.create(self.root))
        self.transport = self.enterContext(T.BoundedHttpsServer(self.certificates, C.CloudinaryHandler, state=self.state))

    def request(self, method, path, data=None, auth=AUTH, headers=(), raw_body=None, host=NAME):
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
                client.putheader("Content-Type", "application/json; charset=utf-8")
            for k, v in headers:
                client.putheader(k, v)
            client.endheaders(body)
            response = client.getresponse()
            return response.status, dict(response.getheaders()), response.read(65537)
        finally:
            client.close()

    def search(self, name="README-synthetic.txt", **kwargs):
        folder, _, leaf = name.rpartition("/")
        value = {"expression": f'asset_folder:"{folder}" AND display_name:"{leaf}"',
                 "sort_by": [{"uploaded_at": "desc"}], "max_results": 2}
        return self.request("POST", API + "resources/search", value, **kwargs)

    def test_folder_inventory_is_exact_and_has_no_user_data(self):
        status, _, raw = self.request("GET", API + "folders?max_results=500")
        self.assertEqual((status, json.loads(raw)), (200, {"folders": [{"name": "nested", "path": "nested"}]}))
        status, _, raw = self.request("GET", API + "folders/nested/?max_results=500")
        self.assertEqual((status, json.loads(raw)), (200, {"folders": []}))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_assets_have_independent_sizes_hashes_names_and_bound_urls(self):
        for folder, expected in (("", ["README-synthetic.txt"]), ("nested%2F", ["nested/bytes.bin", "nested/space name.txt"])):
            status, _, raw = self.request("GET", API + "resources/by_asset_folder?asset_folder=" + folder + "&max_results=500")
            self.assertEqual(status, 200)
            assets = json.loads(raw)["resources"]
            self.assertEqual(len(assets), len(expected))
            for asset, name in zip(assets, expected):
                self.assertEqual(asset, {"public_id": "synthetic-" + asset["asset_id"], "asset_id": str(301 + list(PAYLOADS).index(name)),
                    "display_name": name.rsplit("/", 1)[-1], "asset_folder": name.rpartition("/")[0],
                    "resource_type": "raw", "type": "upload", "bytes": len(PAYLOADS[name]),
                    "created_at": "2024-01-01T00:00:00Z", "uploaded_at": "2024-01-01T00:00:00Z",
                    "etag": hashlib.md5(PAYLOADS[name]).hexdigest(), "secure_url": "https://" + NAME + "/content/" + asset["asset_id"]})

    def test_search_and_issued_public_links_return_literal_payloads(self):
        self.assertEqual(self.request("GET", "/content/301", auth=None)[0], 400)
        for i, (name, body) in enumerate(PAYLOADS.items(), 301):
            status, _, raw = self.search(name)
            self.assertEqual((status, json.loads(raw)["total_count"]), (200, 1))
            self.assertEqual(self.request("GET", "/content/" + str(i), auth=None)[::2], (200, body))
            self.assertEqual(self.request("GET", "/content/" + str(i))[0], 400)
        self.assertEqual(self.state.payload_bytes, sum(map(len, PAYLOADS.values())))

    def test_missing_object_is_empty_search_and_missing_folder_is_404(self):
        status, _, raw = self.search("absent-synthetic.txt")
        self.assertEqual((status, json.loads(raw)), (200, {"total_count": 0, "resources": []}))
        self.assertEqual(self.request("GET", API + "folders/absent-synthetic.txt/?max_results=500")[0], 404)
        self.assertEqual((self.state.missing, self.state.payload_bytes), (2, 0))

    def test_credentials_deny_without_challenge_link_or_payload(self):
        for auth in (None, "Basic wrong", "Bearer synthetic", AUTH + "x"):
            status, headers, _ = self.search(auth=auth)
            self.assertEqual(status, 401)
            self.assertNotIn("WWW-Authenticate", headers)
        self.assertEqual((self.state.denied, self.state.links, self.state.payload_bytes), (4, set(), 0))

    def test_known_content_denial_and_fixture_write_guard_preserve_sources(self):
        self.search()
        self.state.mode = "read_denied"
        status, _, raw = self.request("GET", "/content/301", auth=None)
        self.assertEqual(status, 403)
        self.assertNotIn(PAYLOADS["README-synthetic.txt"], raw)
        self.state.mode = "normal"
        self.assertEqual(self.request("DELETE", "/content/301")[0], 405)
        self.assertEqual((self.state.read_denied, self.state.rejected_mutations, self.state.payload_bytes), (1, 1, 0))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_unknown_routes_methods_and_query_shapes_fail_closed(self):
        for method, path, value in (("GET", API + "resources/search", None), ("POST", API + "resources/search", {}),
                ("GET", API + "folders", None), ("GET", API + "folders?max_results=1", None),
                ("GET", API + "folders?max_results=500&max_results=500", None),
                ("GET", API + "resources/by_asset_folder?asset_folder=foreign&max_results=500", None),
                ("GET", API + "%66olders?max_results=500", None), ("GET", "https://elsewhere.invalid/", None),
                ("DELETE", API + "folders", None), ("PUT", "/content/301", None)):
            with self.subTest(path=path):
                self.assertEqual(self.request(method, path, value)[0], 400)
        self.assertEqual((self.state.payload_bytes, self.state.rejected_mutations), (0, 0))

    def test_duplicate_nonobject_and_ambiguous_search_bodies_fail(self):
        for raw in (b"[]", b'{"max_results":2,"max_results":2}', b'{"expression":',
                    b'{"expression":null,"sort_by":[{"uploaded_at":"desc"}],"max_results":2}',
                    b'{"expression":"x","sort_by":[{"uploaded_at":"desc"}],"max_results":true}'):
            self.assertEqual(self.request("POST", API + "resources/search", raw_body=raw)[0], 400)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_host_headers_framing_and_api_ranges_are_exact(self):
        for host in ("127.0.0.1", NAME + ":443", NAME + ".", "API.cloudinary.com"):
            self.assertEqual(self.request("GET", API + "folders?max_results=500", host=host)[0], 400)
        for headers in ((("Host", NAME),), (("Authorization", AUTH),), (("Content-Length", "00"),),
                        (("Content-Length", "4097"),), (("Transfer-Encoding", "chunked"),), (("Range", "bytes=0-1"),)):
            self.assertEqual(self.request("GET", API + "folders?max_results=500", headers=headers)[0], 400)

    def test_content_ranges_are_bounded_and_do_not_change_bytes(self):
        self.search("nested/bytes.bin")
        status, headers, raw = self.request("GET", "/content/302", auth=None, headers=(("Range", "bytes=256-511"),))
        self.assertEqual((status, headers["Content-Range"], raw), (206, "bytes 256-511/2048", bytes(range(256))))
        for value in ("bytes=0--1", "bytes=-1", "bytes=2048-", "bytes=2-1", "bytes=0-1,3-4"):
            self.assertEqual(self.request("GET", "/content/302", auth=None, headers=(("Range", value),))[0], 416)
        self.assertEqual(self.state.files, PAYLOADS)

    def test_request_and_response_budgets_prevent_success(self):
        self.state.request_limit = 1
        self.assertEqual(self.search()[0], 200)
        self.assertEqual(self.search()[0], 429)
        self.assertTrue(self.state.budget_exceeded)
        self.state.request_limit = 10
        self.state.byte_limit = 1
        self.assertEqual(self.search()[0], 429)

    def test_tls_deadline_stops_a_partial_json_body(self):
        timer = threading.Timer
        # Exercise the socket-timeout-first race independently of scheduling.
        with T.FixtureCertificates.create(self.root) as certificates, patch.object(
                T.threading, "Timer", side_effect=lambda delay, callback: timer(delay + 0.3, callback)):
            with T.BoundedHttpsServer(certificates, C.CloudinaryHandler, state=C.CloudinaryState(KEY, SECRET),
                    limits=T.TlsLimits(request_seconds=0.15)) as transport:
                with socket.create_connection(("127.0.0.1", transport.port), timeout=2) as raw:
                    with certificates.client_context().wrap_socket(raw, server_hostname="127.0.0.1") as client:
                        client.sendall(("POST " + API + "resources/search HTTP/1.1\r\nHost: " + NAME
                            + "\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: 100\r\n\r\n{").encode())
                        self.assertEqual(client.recv(1), b"")
            self.assertIn("tls_request_deadline", transport.snapshot()["failure_codes"])
            self.assertTrue(transport.cleanup_complete)
        self.assertTrue(certificates.cleanup_complete)

class CloudinaryAuthorityTests(unittest.TestCase):
    def test_reviewed_name_has_its_own_exact_sni_and_san(self):
        with tempfile.TemporaryDirectory() as directory:
            with T.FixtureCertificates.create(Path(directory).resolve(), server_name=NAME) as certificates:
                from cryptography import x509
                leaf = x509.load_pem_x509_certificate((certificates.directory / "leaf.pem").read_bytes())
                self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value), [x509.DNSName(NAME)])
        self.assertIsNone(T._cloudinary_sni(None, NAME, None))
        for name in (None, "", "fixture.pcloud.com", "127.0.0.1", NAME + ".", NAME + ":443"):
            self.assertEqual(T._cloudinary_sni(None, name, None), ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)
        self.assertEqual(T._pcloud_sni(None, NAME, None), ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)

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
