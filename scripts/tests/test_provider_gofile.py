"""Independent GoFile wire oracles; no vendor or native acceptance."""
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
    import fixture_gofile as C
    import fixture_tls as T
finally:
    sys.path.pop(0)

NAME = "api.gofile.io"
API = "/contents/"
KEY, SECRET = "synthetic-key", "synthetic-secret"
PAYLOADS = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
            "nested/bytes.bin": bytes(range(256)) * 8, "nested/space name.txt": b"Nested synthetic payload.\n"}

class GoFileWireTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.state = C.GoFileState(SECRET)
        # Wire tests use ephemeral IP TLS, so they also run on Windows without
        # DNS/privileged ports. The contained native probe owns fixed-host TLS.
        self.certificates = self.enterContext(T.FixtureCertificates.create(self.root))
        self.transport = self.enterContext(T.BoundedHttpsServer(self.certificates, C.GoFileHandler, state=self.state))

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



    def list(self, identity="synthetic-root", extra=""):
        return self.request("GET", API + identity + "?page=1&pageSize=1000" + extra)

    def test_exact_bearer_is_required_for_list_metadata_content_and_guard(self):
        for auth in (None, "", "Bearer wrong", "bearer " + SECRET, "Bearer " + SECRET + "x"):
            for method, path in (("GET", API + "synthetic-root?page=1&pageSize=1000"),
                                 ("GET", API + "701?page=1&pageSize=1"),
                                 ("GET", "/content/701"), ("DELETE", "/content/701")):
                with self.subTest(auth=auth, method=method):
                    status, headers, raw = self.request(method, path, auth=auth)
                    self.assertEqual((status, json.loads(raw)), (401, {"status": "error-notAllowed"}))
                    self.assertNotIn("WWW-Authenticate", headers)
        self.assertEqual((self.state.denied, self.state.payload_bytes, self.state.rejected_mutations), (20, 0, 0))
        self.assertEqual(self.state.links, set())

    def test_inventory_has_independent_ids_hashes_sizes_times_and_links(self):
        for folder, names in (("synthetic-root", ["README-synthetic.txt"]),
                              ("synthetic-nested", ["nested/bytes.bin", "nested/space name.txt"])):
            status, _, raw = self.list(folder)
            self.assertEqual(status, 200)
            result = json.loads(raw)
            self.assertEqual(set(result), {"status", "data", "metadata"})
            self.assertEqual(result["status"], "ok")
            items = result["data"]["children"]
            for name in names:
                identity = str(701 + list(PAYLOADS).index(name))
                self.assertEqual(items[identity], {
                    "id": identity, "parentFolder": folder, "type": "file", "name": name.rsplit("/", 1)[-1],
                    "size": len(PAYLOADS[name]), "createTime": 1704067200, "modTime": 1704067200,
                    "md5": hashlib.md5(PAYLOADS[name]).hexdigest(), "mimetype": "application/octet-stream",
                    "link": "https://api.gofile.io/content/" + identity})
            if folder == "synthetic-root":
                self.assertEqual(items["synthetic-nested"], {"id": "synthetic-nested",
                    "parentFolder": "synthetic-root", "type": "folder", "name": "nested",
                    "createTime": 1704067200, "modTime": 1704067200, "childrenCount": 2})
            self.assertEqual(result["metadata"], {"page": 1, "pageSize": 1000, "totalCount": 2,
                                                 "totalPages": 1, "hasNextPage": False})
        self.assertEqual(self.state.files, PAYLOADS)

    def test_recursive_listing_contains_both_nested_children(self):
        status, _, raw = self.list(extra="&maxdepth=4")
        result = json.loads(raw)
        self.assertEqual(status, 200)
        root = result["data"]["children"]
        self.assertEqual(set(root), {"701", "synthetic-nested"})
        self.assertEqual(set(root["synthetic-nested"]["children"]), {"702", "703"})
        self.assertEqual([root["synthetic-nested"]["children"][i]["name"] for i in ("702", "703")],
                         ["bytes.bin", "space name.txt"])
        self.assertEqual(self.state.events, [("recursive_listing", "")])
        self.assertEqual(self.state.links, {"701", "702", "703"})
        self.assertEqual(self.state.payload_bytes, 0)

    def test_lookup_metadata_and_download_require_issued_links(self):
        self.assertEqual(self.request("GET", "/content/701")[0], 400)
        for identity, (name, payload) in enumerate(PAYLOADS.items(), 701):
            folder, _, leaf = name.rpartition("/")
            status, _, raw = self.list("synthetic-nested" if folder else "synthetic-root",
                                      "&" + urllib.parse.urlencode({"contentname": leaf}))
            self.assertEqual((status, set(json.loads(raw)["data"]["children"])), (200, {str(identity)}))
            status, _, raw = self.request("GET", API + str(identity) + "?page=1&pageSize=1")
            self.assertEqual((status, json.loads(raw)["data"]["md5"]), (200, hashlib.md5(payload).hexdigest()))
            self.assertEqual(self.request("GET", "/content/" + str(identity))[::2], (200, payload))
        self.assertEqual(self.state.payload_bytes, sum(map(len, PAYLOADS.values())))

    def test_missing_name_returns_no_object_or_payload(self):
        status, _, raw = self.list(extra="&contentname=absent-synthetic.txt")
        result = json.loads(raw)
        self.assertEqual((status, result["data"]["children"], result["metadata"]["totalCount"]), (200, {}, 0))
        self.assertEqual((self.state.missing, self.state.payload_bytes), (1, 0))
        self.assertEqual(self.state.links, set())

    def test_denied_read_and_synthetic_delete_guard_preserve_sources(self):
        self.list()
        self.state.mode = "read_denied"
        status, _, raw = self.request("GET", "/content/701")
        self.assertEqual((status, json.loads(raw)), (403, {"status": "error-notAllowed"}))
        self.state.mode = "normal"
        self.assertEqual(self.request("DELETE", "/content/701")[0], 405)
        self.assertEqual((self.state.read_denied, self.state.rejected_mutations, self.state.payload_bytes), (1, 1, 0))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_unknown_routes_and_native_mutations_are_outside_read_profile(self):
        for method, path in (("POST", "/accounts"), ("DELETE", "/contents/"),
                             ("POST", "/contents/upload"), ("PUT", "/contents/701"),
                             ("HEAD", "/content/701"), ("GET", "/accounts/synthetic-account"),
                             ("GET", API + "foreign?page=1&pageSize=1000"),
                             ("GET", "https://elsewhere.invalid/")):
            with self.subTest(method=method, path=path):
                self.assertEqual(self.request(method, path)[0], 400)
        self.assertEqual((self.state.payload_bytes, self.state.rejected_mutations), (0, 0))

    def test_query_contract_rejects_pagination_depth_duplicates_and_invalid_names(self):
        for query in ("page=2&pageSize=1000", "page=1&pageSize=1", "page=1&pageSize=1000&maxdepth=5",
                      "page=1&pageSize=1000&maxdepth=4&contentname=x", "page=1&pageSize=1000&extra=1",
                      "page=1&page=1&pageSize=1000", "pageSize=1000", "page=1&pageSize=1000&contentname=%ff",
                      "page=1&pageSize=1000&contentname=%GG", "page=1&pageSize=1000&contentname=%00",
                      "page=1&pageSize=1000&contentname=..", "page=1&pageSize=1000&contentname=nested%2Fx",
                      "page=1&pageSize=1000&contentname=", "page=1&pageSize=1000&a=1&b=2&c=3"):
            with self.subTest(query=query):
                self.assertEqual(self.request("GET", API + "synthetic-root?" + query)[0], 400)
        self.assertEqual(self.request("GET", "/%63ontents/synthetic-root?page=1&pageSize=1000")[0], 400)
        self.assertEqual(self.state.links, set())

    def test_authority_duplicate_headers_framing_and_metadata_ranges_are_exact(self):
        target = API + "synthetic-root?page=1&pageSize=1000"
        for host in ("127.0.0.1", NAME + ":443", NAME + ".", "API.gofile.io"):
            self.assertEqual(self.request("GET", target, host=host)[0], 400)
        for headers in ((("Host", NAME),), (("Authorization", "Bearer " + SECRET),),
                        (("Content-Length", "00"),), (("Content-Length", "4097"),),
                        (("Transfer-Encoding", "chunked"),), (("Range", "bytes=0-1"),)):
            self.assertEqual(self.request("GET", target, headers=headers)[0], 400)
        self.assertEqual(self.request("GET", target, raw_body=b"x")[0], 400)
        self.assertEqual(self.state.links, set())

    def test_content_ranges_are_bounded(self):
        self.list(extra="&maxdepth=4")
        status, headers, raw = self.request("GET", "/content/702", headers=(("Range", "bytes=256-511"),))
        self.assertEqual((status, headers["Content-Range"], raw), (206, "bytes 256-511/2048", bytes(range(256))))
        for value in ("bytes=0--1", "bytes=-1", "bytes=2048-", "bytes=2-1", "bytes=0-1,3-4"):
            self.assertEqual(self.request("GET", "/content/702", headers=(("Range", value),))[0], 416)
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
            with T.BoundedHttpsServer(certificates, C.GoFileHandler, state=C.GoFileState(SECRET),
                    limits=T.TlsLimits(request_seconds=0.15)) as transport:
                with socket.create_connection(("127.0.0.1", transport.port), timeout=2) as raw:
                    with certificates.client_context().wrap_socket(raw, server_hostname="127.0.0.1") as client:
                        client.sendall(("GET " + API + "synthetic-root?page=1&pageSize=1000 HTTP/1.1\r\nHost: " + NAME).encode())
                        self.assertEqual(client.recv(1), b"")
            self.assertIn("tls_request_deadline", transport.snapshot()["failure_codes"])
            self.assertTrue(transport.cleanup_complete)
        self.assertTrue(certificates.cleanup_complete)

class GoFileAuthorityTests(unittest.TestCase):
    def test_reviewed_name_has_its_own_exact_sni_and_san(self):
        with tempfile.TemporaryDirectory() as directory:
            with T.FixtureCertificates.create(Path(directory).resolve(), server_name=NAME) as certificates:
                from cryptography import x509
                leaf = x509.load_pem_x509_certificate((certificates.directory / "leaf.pem").read_bytes())
                self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value), [x509.DNSName(NAME)])
        self.assertIsNone(T._gofile_sni(None, NAME, None))
        for name in (None, "", "fixture.pcloud.com", "api.cloudinary.com", "127.0.0.1", NAME + ".", NAME + ":443"):
            self.assertEqual(T._gofile_sni(None, name, None), ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)
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
