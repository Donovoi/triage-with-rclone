"""Independent Drime wire oracles; no vendor or native acceptance."""
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
    import fixture_drime as C
    import fixture_tls as T
finally:
    sys.path.pop(0)

NAME = "app.drime.cloud"
API = "/api/v1/drive/file-entries"
KEY, SECRET = "synthetic-key", "synthetic-secret"
PAYLOADS = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
            "nested/bytes.bin": bytes(range(256)) * 8, "nested/space name.txt": b"Nested synthetic payload.\n"}

class DrimeWireTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.state = C.DrimeState(SECRET)
        # Wire tests use ephemeral IP TLS, so they also run on Windows without
        # DNS/privileged ports. The contained native probe owns fixed-host TLS.
        self.certificates = self.enterContext(T.FixtureCertificates.create(self.root))
        self.transport = self.enterContext(T.BoundedHttpsServer(self.certificates, C.DrimeHandler, state=self.state))

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




    def list(self, identity="1", extra=""):
        return self.request("GET", API + "?folderId=" + identity + "&page=1&perPage=1000" + extra)

    def test_exact_bearer_is_required_for_listing_content_and_guard(self):
        for auth in (None, "", "Bearer wrong", "bearer " + SECRET, "Bearer " + SECRET + "x"):
            for method, path in (("GET", API + "?folderId=1&page=1&perPage=1000"),
                                 ("GET", "/content/801"), ("DELETE", "/content/801")):
                with self.subTest(auth=auth, method=method):
                    status, headers, raw = self.request(method, path, auth=auth)
                    self.assertEqual((status, json.loads(raw)), (401, {"message": "synthetic invalid token"}))
                    self.assertNotIn("WWW-Authenticate", headers)
        self.assertEqual((self.state.denied, self.state.payload_bytes, self.state.rejected_mutations), (15, 0, 0))
        self.assertEqual(self.state.links, set())

    def test_inventory_has_independent_ids_hashes_sizes_times_and_links(self):
        for folder, names in (("1", ["README-synthetic.txt"]), ("10", ["nested/bytes.bin", "nested/space name.txt"])):
            status, _, raw = self.list(folder)
            self.assertEqual(status, 200)
            result = json.loads(raw)
            expected = []
            for name in names:
                identity = 801 + list(PAYLOADS).index(name)
                expected.append({"id": identity, "parent_id": int(folder), "type": "file",
                    "name": name.rsplit("/", 1)[-1], "file_name": name.rsplit("/", 1)[-1],
                    "file_size": len(PAYLOADS[name]), "created_at": "2024-01-01T00:00:00Z",
                    "updated_at": "2024-01-01T00:00:00Z", "hash": hashlib.md5(PAYLOADS[name]).hexdigest(),
                    "mime": "application/octet-stream", "url": "content/" + str(identity)})
            if folder == "1":
                expected.append({"id": 10, "parent_id": 1, "type": "folder", "name": "nested",
                    "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z", "file_size": 0})
            self.assertEqual(result, {"current_page": 1, "last_page": 1, "per_page": 1000,
                "data": expected, "from": 1, "to": 2, "total": 2, "next_page_url": "", "prev_page_url": ""})
        self.assertEqual(self.state.files, PAYLOADS)

    def test_folder_only_lookup_never_issues_file_links(self):
        status, _, raw = self.list(extra="&type=folder")
        result = json.loads(raw)
        self.assertEqual((status, [x["name"] for x in result["data"]]), (200, ["nested"]))
        self.assertEqual((result["total"], result["from"], result["to"]), (1, 1, 1))
        status, _, raw = self.list("10", "&type=folder")
        result = json.loads(raw)
        self.assertEqual((status, result["data"], result["from"], result["to"], result["total"]), (200, [], 0, 0, 0))
        self.assertEqual(self.state.links, set())
        self.assertEqual(self.state.events, [("folder_lookup", ""), ("folder_lookup", "nested")])

    def test_content_requires_a_link_from_authenticated_inventory(self):
        self.assertEqual(self.request("GET", "/content/801")[0], 400)
        self.list(); self.list("10")
        for identity, (name, payload) in enumerate(PAYLOADS.items(), 801):
            self.assertEqual(self.request("GET", "/content/" + str(identity))[::2], (200, payload))
        self.assertEqual(self.state.payload_bytes, sum(map(len, PAYLOADS.values())))

    def test_complete_inventory_contains_no_missing_object_or_invented_name_filter(self):
        status, _, raw = self.list()
        names = {x["name"] for x in json.loads(raw)["data"]}
        self.assertEqual((status, names), (200, {"README-synthetic.txt", "nested"}))
        self.assertNotIn("absent-synthetic.txt", names)
        # The backend selects names client-side; the fixture never invents a
        # server-side missing-name request or marks one as observed.
        self.assertEqual(self.list(extra="&name=absent-synthetic.txt")[0], 400)
        self.assertEqual((self.state.missing, self.state.payload_bytes), (0, 0))

    def test_denied_read_and_synthetic_delete_guard_preserve_sources(self):
        self.list()
        self.state.mode = "read_denied"
        status, _, raw = self.request("GET", "/content/801")
        self.assertEqual((status, json.loads(raw)), (403, {"message": "synthetic read denied"}))
        self.state.mode = "normal"
        self.assertEqual(self.request("DELETE", "/content/801")[0], 405)
        self.assertEqual((self.state.read_denied, self.state.rejected_mutations, self.state.payload_bytes), (1, 1, 0))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_unknown_routes_and_native_mutations_are_outside_read_profile(self):
        for method, path in (("POST", "/api/v1/folders"), ("POST", "/api/v1/file-entries/delete"),
                             ("POST", "/api/v1/uploads"), ("PUT", "/api/v1/file-entries/801"),
                             ("HEAD", "/content/801"), ("GET", "/api/v1/user/space-usage"),
                             ("GET", "/content/foreign"), ("GET", "https://elsewhere.invalid/")):
            with self.subTest(method=method, path=path):
                self.assertEqual(self.request(method, path)[0], 400)
        self.assertEqual((self.state.payload_bytes, self.state.rejected_mutations), (0, 0))

    def test_query_contract_rejects_pagination_workspace_duplicates_and_wrong_types(self):
        for query in ("folderId=1&page=2&perPage=1000", "folderId=1&page=1&perPage=1",
                      "folderId=1&page=1&perPage=1000&type=file", "folderId=1&page=1&perPage=1000&workspaceId=1",
                      "folderId=1&page=1&perPage=1000&extra=1", "folderId=1&page=1&page=1&perPage=1000",
                      "page=1&perPage=1000", "folderId=1&page=1&perPage=1000&type=%ff",
                      "folderId=1&page=1&perPage=1000&type=%GG", "folderId=1&page=1&perPage=1000&type=%00",
                      "folderId=2&page=1&perPage=1000", "folderId=1&page=1&perPage=1000&type=",
                      "folderId=1&page=1&perPage=1000&a=1&b=2"):
            with self.subTest(query=query):
                self.assertEqual(self.request("GET", API + "?" + query)[0], 400)
        self.assertEqual(self.request("GET", "/api/v1/%64rive/file-entries?folderId=1&page=1&perPage=1000")[0], 400)
        self.assertEqual(self.state.links, set())

    def test_authority_duplicate_headers_framing_and_metadata_ranges_are_exact(self):
        target = API + "?folderId=1&page=1&perPage=1000"
        for host in ("127.0.0.1", NAME + ":443", NAME + ".", "APP.drime.cloud"):
            self.assertEqual(self.request("GET", target, host=host)[0], 400)
        for headers in ((("Host", NAME),), (("Authorization", "Bearer " + SECRET),),
                        (("Content-Length", "00"),), (("Content-Length", "4097"),),
                        (("Transfer-Encoding", "chunked"),), (("Range", "bytes=0-1"),)):
            self.assertEqual(self.request("GET", target, headers=headers)[0], 400)
        self.assertEqual(self.request("GET", target, raw_body=b"x")[0], 400)
        self.assertEqual(self.state.links, set())

    def test_content_ranges_are_bounded(self):
        self.list("10")
        status, headers, raw = self.request("GET", "/content/802", headers=(("Range", "bytes=256-511"),))
        self.assertEqual((status, headers["Content-Range"], raw), (206, "bytes 256-511/2048", bytes(range(256))))
        for value in ("bytes=0--1", "bytes=-1", "bytes=2048-", "bytes=2-1", "bytes=0-1,3-4"):
            self.assertEqual(self.request("GET", "/content/802", headers=(("Range", value),))[0], 416)
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
            with T.BoundedHttpsServer(certificates, C.DrimeHandler, state=C.DrimeState(SECRET),
                    limits=T.TlsLimits(request_seconds=0.15)) as transport:
                with socket.create_connection(("127.0.0.1", transport.port), timeout=2) as raw:
                    with certificates.client_context().wrap_socket(raw, server_hostname="127.0.0.1") as client:
                        client.sendall(("GET " + API + "?folderId=1&page=1&perPage=1000 HTTP/1.1\r\nHost: " + NAME).encode())
                        self.assertEqual(client.recv(1), b"")
            self.assertIn("tls_request_deadline", transport.snapshot()["failure_codes"])
            self.assertTrue(transport.cleanup_complete)
        self.assertTrue(certificates.cleanup_complete)

class DrimeAuthorityTests(unittest.TestCase):
    def test_reviewed_name_has_its_own_exact_sni_and_san(self):
        with tempfile.TemporaryDirectory() as directory:
            with T.FixtureCertificates.create(Path(directory).resolve(), server_name=NAME) as certificates:
                from cryptography import x509
                leaf = x509.load_pem_x509_certificate((certificates.directory / "leaf.pem").read_bytes())
                self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value), [x509.DNSName(NAME)])
        self.assertIsNone(T._drime_sni(None, NAME, None))
        for name in (None, "", "fixture.pcloud.com", "api.cloudinary.com", "127.0.0.1", NAME + ".", NAME + ":443"):
            self.assertEqual(T._drime_sni(None, name, None), ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)
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
