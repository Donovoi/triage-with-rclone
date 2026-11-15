"""Independent Premiumizeme wire oracles; no vendor or native acceptance."""
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
    import fixture_premiumizeme as C
    import fixture_tls as T
finally:
    sys.path.pop(0)

NAME = "www.premiumize.me"
API = "/api/folder/list"
KEY, SECRET = "synthetic-key", "synthetic-secret"
PAYLOADS = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
            "nested/bytes.bin": bytes(range(256)) * 8, "nested/space name.txt": b"Nested synthetic payload.\n"}

class PremiumizemeWireTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.state = C.PremiumizemeState(SECRET)
        # Wire tests use ephemeral IP TLS, so they also run on Windows without
        # DNS/privileged ports. The contained native probe owns fixed-host TLS.
        self.certificates = self.enterContext(T.FixtureCertificates.create(self.root))
        self.transport = self.enterContext(T.BoundedHttpsServer(self.certificates, C.PremiumizemeHandler, state=self.state))

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




    def list(self, identity="", extra="", **kwargs):
        return self.request("GET", API + "?includebreadcrumbs=false" + ("&id=" + identity if identity else "") + extra, **kwargs)

    def test_exact_saved_bearer_is_required_for_listing_content_and_guard(self):
        for auth in (None, "", "Bearer wrong", "bearer " + SECRET, "Bearer " + SECRET + "x"):
            for method, path in (("GET", API + "?includebreadcrumbs=false"),
                                 ("GET", "/content/file1001"), ("DELETE", "/content/file1001")):
                with self.subTest(auth=auth, method=method):
                    status, headers, raw = self.request(method, path, auth=auth)
                    self.assertEqual((status, json.loads(raw)), (401, {"status": "error", "message": "synthetic invalid token"}))
                    self.assertNotIn("WWW-Authenticate", headers)
        self.assertEqual((self.state.denied, self.state.payload_bytes, self.state.rejected_mutations), (15, 0, 0))
        self.assertEqual(self.state.links, set())

    def test_independent_inventory_types_ids_times_and_absolute_links(self):
        for folder, names in (("", ["README-synthetic.txt"]), ("folder10", ["nested/bytes.bin", "nested/space name.txt"])):
            status, _, raw = self.list(folder)
            expected = []
            for name in names:
                identity = "file" + str(1001 + list(PAYLOADS).index(name))
                expected.append({"id": identity, "type": "file", "name": name.rsplit("/", 1)[-1],
                    "size": len(PAYLOADS[name]), "created_at": 1704067200,
                    "mime_type": "application/octet-stream",
                    "link": "https://www.premiumize.me/content/" + identity})
            if not folder:
                expected.append({"id": "folder10", "type": "folder", "name": "nested", "created_at": 1704067200})
            self.assertEqual((status, json.loads(raw)), (200, {"status": "success", "content": expected,
                "folder_id": folder or "0", "name": "nested" if folder else "synthetic", "parent_id": "0"}))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_content_requires_previously_authenticated_inventory(self):
        self.assertEqual(self.request("GET", "/content/file1001")[0], 400)
        self.list(); self.list("folder10")
        for identity, (name, payload) in enumerate(PAYLOADS.items(), 1001):
            self.assertEqual(self.request("GET", "/content/file" + str(identity))[::2], (200, payload))
        self.assertEqual(self.state.payload_bytes, sum(map(len, PAYLOADS.values())))

    def test_complete_inventory_contains_no_missing_object_or_invented_name_filter(self):
        status, _, raw = self.list()
        self.assertEqual((status, {x["name"] for x in json.loads(raw)["content"]}),
                         (200, {"README-synthetic.txt", "nested"}))
        self.assertEqual(self.list(extra="&name=absent-synthetic.txt")[0], 400)
        self.assertEqual((self.state.missing, self.state.payload_bytes), (0, 0))

    def test_wrong_token_does_not_revoke_or_authorize_issued_link(self):
        self.list()
        self.assertEqual(self.request("GET", "/content/file1001", auth="Bearer wrong")[0], 401)
        self.assertEqual(self.state.payload_bytes, 0)
        self.assertEqual(self.request("GET", "/content/file1001")[::2], (200, PAYLOADS["README-synthetic.txt"]))

    def test_denied_read_and_direct_fixture_guard_preserve_sources(self):
        self.list()
        self.state.mode = "read_denied"
        status, _, raw = self.request("GET", "/content/file1001")
        self.assertEqual((status, json.loads(raw)), (403, {"message": "synthetic read denied"}))
        self.state.mode = "normal"
        self.assertEqual(self.request("DELETE", "/content/file1001")[0], 405)
        self.assertEqual((self.state.read_denied, self.state.rejected_mutations, self.state.payload_bytes), (1, 1, 0))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_oauth_grants_account_calls_and_native_writes_are_outside_profile(self):
        for method, path in (("POST", "/token"), ("GET", "/authorize"), ("GET", "/api/account/info"),
                             ("POST", "/api/file/delete"), ("POST", "/api/folder/create"),
                             ("POST", "/api/transfer/create"), ("HEAD", "/content/file1001"),
                             ("GET", "/content/foreign"), ("GET", "https://elsewhere.invalid/")):
            with self.subTest(method=method, path=path):
                self.assertEqual(self.request(method, path)[0], 400)
        self.assertEqual((self.state.payload_bytes, self.state.rejected_mutations), (0, 0))

    def test_query_contract_rejects_api_keys_breadcrumbs_unknown_ids_and_duplicates(self):
        for query in ("", "id=folder10", "includebreadcrumbs=true", "includebreadcrumbs=False",
                      "includebreadcrumbs=false&id=0", "includebreadcrumbs=false&id=unknown",
                      "includebreadcrumbs=false&id=", "includebreadcrumbs=false&page=2",
                      "includebreadcrumbs=false&apikey=synthetic", "includebreadcrumbs=false&includebreadcrumbs=false",
                      "includebreadcrumbs=false&id=folder10&id=folder10", "includebreadcrumbs=false&id=%ff",
                      "includebreadcrumbs=false&id=%GG", "includebreadcrumbs=false&id=%00",
                      "includebreadcrumbs=false&a=1&b=2&c=3&d=4"):
            with self.subTest(query=query):
                self.assertEqual(self.request("GET", API + "?" + query)[0], 400)
        self.assertEqual(self.request("GET", "/api/%66older/list?includebreadcrumbs=false")[0], 400)
        self.assertEqual(self.state.links, set())
    def test_authority_duplicate_headers_framing_and_metadata_ranges_are_exact(self):
        target = API + "?includebreadcrumbs=false"
        for host in ("127.0.0.1", NAME + ":443", NAME + ".", "WWW.premiumize.me"):
            self.assertEqual(self.request("GET", target, host=host)[0], 400)
        for headers in ((("Host", NAME),), (("Authorization", "Bearer " + SECRET),),
                        (("Content-Length", "00"),), (("Content-Length", "4097"),),
                        (("Transfer-Encoding", "chunked"),), (("Range", "bytes=0-1"),)):
            self.assertEqual(self.request("GET", target, headers=headers)[0], 400)
        self.assertEqual(self.request("GET", target, raw_body=b"x")[0], 400)
        self.assertEqual(self.state.links, set())

    def test_content_ranges_are_bounded(self):
        self.list("folder10")
        status, headers, raw = self.request("GET", "/content/file1002", headers=(("Range", "bytes=256-511"),))
        self.assertEqual((status, headers["Content-Range"], raw), (206, "bytes 256-511/2048", bytes(range(256))))
        for value in ("bytes=0--1", "bytes=-1", "bytes=2048-", "bytes=2-1", "bytes=0-1,3-4"):
            self.assertEqual(self.request("GET", "/content/file1002", headers=(("Range", value),))[0], 416)
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
            with T.BoundedHttpsServer(certificates, C.PremiumizemeHandler, state=C.PremiumizemeState(SECRET),
                    limits=T.TlsLimits(request_seconds=0.15)) as transport:
                with socket.create_connection(("127.0.0.1", transport.port), timeout=2) as raw:
                    with certificates.client_context().wrap_socket(raw, server_hostname="127.0.0.1") as client:
                        client.sendall(("GET " + API + "?includebreadcrumbs=false HTTP/1.1\r\nHost: " + NAME).encode())
                        self.assertEqual(client.recv(1), b"")
            self.assertIn("tls_request_deadline", transport.snapshot()["failure_codes"])
            self.assertTrue(transport.cleanup_complete)
        self.assertTrue(certificates.cleanup_complete)

class PremiumizemeAuthorityTests(unittest.TestCase):
    def test_reviewed_name_has_its_own_exact_sni_and_san(self):
        with tempfile.TemporaryDirectory() as directory:
            with T.FixtureCertificates.create(Path(directory).resolve(), server_name=NAME) as certificates:
                from cryptography import x509
                leaf = x509.load_pem_x509_certificate((certificates.directory / "leaf.pem").read_bytes())
                self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value), [x509.DNSName(NAME)])
        self.assertIsNone(T._premiumizeme_sni(None, NAME, None))
        for name in (None, "", "fixture.pcloud.com", "api.cloudinary.com", "127.0.0.1", NAME + ".", NAME + ":443"):
            self.assertEqual(T._premiumizeme_sni(None, name, None), ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)
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
