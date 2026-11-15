"""Independent Zoho folder-read wire contracts; no vendor acceptance."""
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
    import fixture_zoho as C
    import fixture_tls as T
finally:
    sys.path.pop(0)

NAME = "workdrive.zoho.eu"
CONTENT = "download.zoho.eu"
SECRET = "synthetic-zoho-token"
API = "/api/v1/files/"
READ = "/v1/workdrive/download/"
PAYLOADS = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
            "nested/bytes.bin": bytes(range(256)) * 8, "nested/space name.txt": b"Nested synthetic payload.\n"}
IDS = {"README-synthetic.txt": "file2301", "nested/bytes.bin": "file2302", "nested/space name.txt": "file2303"}

class ZohoWireTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.state = C.ZohoState(SECRET)
        self.certificates = self.enterContext(T.FixtureCertificates.create(self.root))
        self.transport = self.enterContext(T.BoundedHttpsServer(self.certificates, C.ZohoHandler, state=self.state))

    def request(self, method, path, auth="auto", host=NAME, accept=None, headers=(), body=b""):
        if auth == "auto":
            auth = "Zoho-oauthtoken " + SECRET
        client = http.client.HTTPSConnection("127.0.0.1", self.transport.port, timeout=3,
                                             context=self.certificates.client_context())
        try:
            client.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            client.putheader("Host", host)
            if auth is not None:
                client.putheader("Authorization", auth)
            if accept is not None:
                client.putheader("Accept", accept)
            if body:
                client.putheader("Content-Length", str(len(body)))
            for key, value in headers:
                client.putheader(key, value)
            client.endheaders(body)
            response = client.getresponse()
            return response.status, dict(response.getheaders()), response.read(65537)
        finally:
            client.close()

    def listing(self, folder="synthetic-root", query="page%5Blimit%5D=1000&page%5Bnext%5D=0", **kwargs):
        return self.request("GET", API + folder + "/files?" + query,
                            **({"accept": "application/vnd.api+json"} | kwargs))

    def content(self, name="README-synthetic.txt", observe=True, **kwargs):
        if observe:
            self.assertEqual(self.listing("synthetic-root" if "/" not in name else "synthetic-nested")[0], 200)
        return self.request("GET", READ + IDS[name], **({"host": CONTENT} | kwargs))

    def test_complete_inventories_have_independent_typed_metadata(self):
        def metadata(name):
            folder = name == "nested"
            return {"id": "synthetic-nested" if folder else IDS[name], "attributes": {
                "name": name.rsplit("/", 1)[-1], "type": "folder" if folder else "file", "is_folder": folder,
                "created_time_in_millisecond": 1704067200000, "modified_time_in_millisecond": 1704067200000,
                "uploaded_time_in_millisecond": 1704067200000,
                "storage_info": {"size_in_bytes": 2074 if folder else len(PAYLOADS[name]),
                                 "files_count": 2 if folder else 0, "folders_count": 0}}}
        for folder, names in (("synthetic-root", ["README-synthetic.txt", "nested"]),
                              ("synthetic-nested", ["nested/bytes.bin", "nested/space name.txt"])):
            status, _, raw = self.listing(folder)
            self.assertEqual((status, json.loads(raw)), (200, {"data": [metadata(name) for name in names],
                "links": {"cursor": {"has_next": False, "next": ""}}}))
        self.assertEqual(self.state.observed, set(PAYLOADS))
        self.assertEqual(self.state.payload_bytes, 0)

    def test_saved_token_scheme_is_required_on_both_authorities(self):
        for auth in (None, "", "Bearer " + SECRET, "Zoho-oauthtoken wrong", "zoho-oauthtoken " + SECRET):
            self.assertEqual(self.listing(auth=auth)[0], 401)
        self.assertEqual(self.listing()[0], 200)
        for auth in (None, "", "Bearer " + SECRET, "Zoho-oauthtoken wrong"):
            self.assertEqual(self.content(observe=False, auth=auth)[0], 401)
        self.assertEqual((self.state.denied, self.state.payload_bytes), (9, 0))

    def test_known_downloads_require_observed_file_ids(self):
        self.assertEqual(self.content(observe=False)[0], 400)
        for name, payload in PAYLOADS.items():
            self.assertEqual(self.content(name)[::2], (200, payload))
        self.assertEqual(self.state.files, PAYLOADS)
        self.assertEqual(self.state.payload_bytes, sum(map(len, PAYLOADS.values())))

    def test_absent_name_is_not_fabricated_in_complete_inventories(self):
        for folder in ("synthetic-root", "synthetic-nested"):
            status, _, raw = self.listing(folder)
            self.assertEqual(status, 200)
            self.assertFalse(json.loads(raw)["links"]["cursor"]["has_next"])
            self.assertNotIn("absent-synthetic.txt", [x["attributes"]["name"] for x in json.loads(raw)["data"]])
        self.assertEqual(self.request("GET", READ + "absent-synthetic.txt", host=CONTENT)[0], 400)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_ranges_return_exact_bounded_bytes_and_reject_invalid_forms(self):
        status, headers, raw = self.content("nested/bytes.bin", headers=(("Range", "bytes=256-511"),))
        self.assertEqual((status, headers["Content-Range"], raw), (206, "bytes 256-511/2048", bytes(range(256))))
        for value in ("bytes=0--1", "bytes=-1", "bytes=2048-", "bytes=2-1", "bytes=0-1,3-4"):
            self.assertEqual(self.content("nested/bytes.bin", headers=(("Range", value),))[0], 416)
        self.assertEqual(self.state.files, PAYLOADS)

    def test_denial_has_object_length_so_size_mismatch_cannot_mask_status_bug(self):
        self.assertEqual(self.listing()[0], 200)
        self.state.mode = "read_denied"
        status, headers, raw = self.content(observe=False)
        self.assertEqual((status, json.loads(raw)), (403, {"error": "denied"}))
        self.assertEqual((headers["Content-Length"], len(raw)), (str(len(PAYLOADS["README-synthetic.txt"])), len(PAYLOADS["README-synthetic.txt"])))
        self.assertEqual((self.state.read_denied, self.state.payload_bytes), (1, 0))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_direct_delete_guard_requires_identity_and_credentials(self):
        self.assertEqual(self.request("DELETE", READ + "file2301", host=CONTENT)[0], 400)
        self.assertEqual(self.listing()[0], 200)
        self.assertEqual(self.request("DELETE", READ + "file2301", host=CONTENT, auth=None)[0], 401)
        self.assertEqual(self.request("DELETE", READ + "file2301", host=CONTENT)[0], 405)
        self.assertEqual((self.state.rejected_mutations, self.state.payload_bytes), (1, 0))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_pagination_duplicate_fields_and_scope_changes_are_rejected(self):
        for query in ("page[limit]=1000&page[next]=1", "page[limit]=1&page[next]=0",
                      "page[limit]=1000", "page[limit]=1000&page[next]=0&page[next]=0",
                      "page[limit]=1000&page[next]=0&token=x", "page[limit]=1000&page[next]=%ff",
                      "page[limit]=1000&page[next]=%GG"):
            self.assertEqual(self.listing(query=query)[0], 400)
        for folder in ("root", "foreign", "synthetic-root/", "synthetic-root%2F", "SYNTHETIC-ROOT"):
            self.assertEqual(self.listing(folder)[0], 400)
        self.assertEqual(self.state.observed, set())

    def test_content_query_aliases_and_unknown_ids_are_outside_scope(self):
        self.assertEqual(self.listing()[0], 200)
        for path in (READ + "file2301?token=x", READ + "file2301?download=1", READ + "file2301/",
                     READ + "FILE2301", READ + "%66ile2301", READ + "foreign", READ + "../file2301"):
            self.assertEqual(self.request("GET", path, host=CONTENT)[0], 400)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_api_and_content_authorities_cannot_be_swapped_or_aliased(self):
        for host in (CONTENT, NAME + ":443", NAME + ".", NAME.upper(), "127.0.0.1"):
            self.assertEqual(self.listing(host=host)[0], 400)
        self.assertEqual(self.listing()[0], 200)
        for host in (NAME, CONTENT + ":443", CONTENT + ".", CONTENT.upper(), "127.0.0.2"):
            self.assertEqual(self.content(observe=False, host=host)[0], 400)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_route_host_cannot_cross_the_transport_certificate_binding(self):
        # Wire tests are normally unnamed. Force each reviewed named transport
        # after accepting TLS so the handler must bind the route as well.
        with patch.object(self.transport, "_server_name", CONTENT):
            self.assertEqual(self.listing()[0], 400)
        self.assertEqual(self.listing()[0], 200)
        with patch.object(self.transport, "_server_name", NAME):
            self.assertEqual(self.content(observe=False)[0], 400)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_accept_and_credential_overrides_are_exact(self):
        for accept in (None, "*/*", "application/json"):
            self.assertEqual(self.listing(accept=accept)[0], 400)
        for key,value in (("Cookie", "x=y"), ("Content-Type", "application/json"),
                          ("X-Zoho-Token", "x"), ("X-Zohowd-Team", "x"), ("X-WorkDrive-User", "x")):
            self.assertEqual(self.listing(headers=((key,value),))[0], 400)
        self.assertEqual(self.listing()[0], 200)
        self.assertEqual(self.content(observe=False, accept="application/vnd.api+json")[0], 400)

    def test_account_discovery_metadata_and_mutations_remain_outside_scope(self):
        for method,path in (("GET", "/api/v1/users/me"), ("GET", "/api/v1/teams"),
                            ("GET", "/api/v1/files/synthetic-root"), ("GET", "/api/v1/files/file2301"),
                            ("POST", API + "synthetic-root/files"), ("PUT", READ + "file2301"),
                            ("DELETE", API + "synthetic-root/files"), ("GET", "https://elsewhere.invalid/")):
            self.assertEqual(self.request(method,path)[0], 400)
        self.assertEqual((self.state.payload_bytes,self.state.rejected_mutations), (0,0))

    def test_duplicate_headers_framing_and_listing_ranges_are_rejected(self):
        for headers in ((("Host", NAME),), (("Authorization", "Zoho-oauthtoken x"),),
                        (("Content-Length", "00"),), (("Content-Length", "4097"),),
                        (("Transfer-Encoding", "chunked"),), (("Range", "bytes=0-1"),)):
            self.assertEqual(self.listing(headers=headers)[0], 400)
        self.assertEqual(self.listing(body=b"x")[0], 400)
        self.assertEqual(self.state.observed, set())

    def test_request_and_response_budgets_prevent_success(self):
        self.state.request_limit = 1
        self.assertEqual(self.listing()[0], 200)
        self.assertEqual(self.listing()[0], 429)
        self.assertTrue(self.state.budget_exceeded)
        self.state.request_limit = 10;self.state.byte_limit = 1
        self.assertEqual(self.listing()[0], 429)

    def test_tls_deadline_stops_partial_headers(self):
        timer = threading.Timer
        with T.FixtureCertificates.create(self.root) as certificates, patch.object(
                T.threading, "Timer", side_effect=lambda delay, callback: timer(delay + 0.3, callback)):
            with T.BoundedHttpsServer(certificates, C.ZohoHandler, state=C.ZohoState(SECRET),
                    limits=T.TlsLimits(request_seconds=0.15)) as transport:
                with socket.create_connection(("127.0.0.1", transport.port), timeout=2) as raw:
                    with certificates.client_context().wrap_socket(raw, server_hostname="127.0.0.1") as client:
                        client.sendall(("GET " + API + " HTTP/1.1\r\nHost: " + NAME).encode())
                        self.assertEqual(client.recv(1), b"")
            self.assertIn("tls_request_deadline", transport.snapshot()["failure_codes"])
            self.assertTrue(transport.cleanup_complete)
        self.assertTrue(certificates.cleanup_complete)

class ZohoAuthorityTests(unittest.TestCase):
    def test_each_authority_has_distinct_exact_sni_and_single_name_certificate(self):
        from cryptography import x509
        for name, callback in ((NAME, T._zoho_api_sni), (CONTENT, T._zoho_content_sni)):
            with tempfile.TemporaryDirectory() as directory:
                with T.FixtureCertificates.create(Path(directory).resolve(), server_name=name) as certificates:
                    leaf = x509.load_pem_x509_certificate((certificates.directory / "leaf.pem").read_bytes())
                    self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value), [x509.DNSName(name)])
            self.assertIsNone(callback(None, name, None))
            for wrong in (None, "", CONTENT if name == NAME else NAME, name + ".", name + ":443", "127.0.0.1"):
                self.assertEqual(callback(None, wrong, None), ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)
            self.assertEqual(T._drive_sni(None, name, None), ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)

    def test_only_reviewed_content_authority_selects_second_linux_loopback_listener(self):
        calls = []
        def init(server, address, handler):
            calls.append(address);server.server_address = address
        with patch.object(T.HTTPServer, "__init__", init), patch.object(T.sys, "platform", "linux"):
            for name in (NAME, CONTENT, T.DRIVE_API_NAME, None):
                T._HttpServer(SimpleNamespace(_server_name=name), object, None)
        self.assertEqual(calls, [("127.0.0.1", 443), ("127.0.0.2", 443), ("127.0.0.1", 443), ("127.0.0.1", 0)])
        with patch.object(T.HTTPServer, "__init__") as bind, patch.object(T.sys, "platform", "win32"):
            for name in (NAME, CONTENT):
                with self.assertRaisesRegex(T.TlsError, "requires_linux"):
                    T._HttpServer(SimpleNamespace(_server_name=name), object, None)
            bind.assert_not_called()

class ZohoPairCleanupTests(unittest.TestCase):
    def pair(self, fail_start=False, fail_close=False):
        certificates, transports, events = [], [], []
        class Certificate:
            cleanup_complete = False
            def __init__(self, name):
                self.server_name = name
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.cleanup_complete = True
                events.append(("certificate_closed", self.server_name))
        class Transport:
            cleanup_complete = False
            def __init__(self, certificate, handler, **kwargs):
                self.authority = certificate.server_name
                transports.append(self)
            def start(self):
                events.append(("started", self.authority))
                if fail_start and self.authority == CONTENT:
                    raise RuntimeError("synthetic_start_failed")
                return self
            def close(self):
                events.append(("closed", self.authority))
                self.cleanup_complete = not (fail_close and self.authority == CONTENT)
                return self.cleanup_complete
        def create(root, server_name):
            cert = Certificate(server_name);certificates.append(cert);return cert
        return create, Transport, certificates, transports, events

    def test_second_listener_start_failure_still_closes_both_transports_and_certificates(self):
        create, transport, certificates, transports, events = self.pair(fail_start=True)
        state = C.ZohoState(SECRET)
        with patch.object(C.FixtureCertificates, "create", side_effect=create), patch.object(C, "BoundedHttpsServer", transport), \
             patch.object(C, "listeners_closed", return_value=True):
            with self.assertRaisesRegex(RuntimeError, "synthetic_start_failed"):
                with C.serve_zoho(Path("/synthetic"), state):
                    self.fail("startup must fail")
        self.assertEqual([name for event, name in events if event == "closed"], [CONTENT, NAME])
        self.assertTrue(all(t.cleanup_complete for t in transports))
        self.assertTrue(all(c.cleanup_complete for c in certificates))
        self.assertTrue(state.cleanup_complete)

    def test_failed_content_cleanup_is_not_hidden_by_successful_api_cleanup(self):
        create, transport, certificates, transports, events = self.pair(fail_close=True)
        state = C.ZohoState(SECRET)
        with patch.object(C.FixtureCertificates, "create", side_effect=create), patch.object(C, "BoundedHttpsServer", transport), \
             patch.object(C, "listeners_closed", return_value=True):
            with self.assertRaisesRegex(RuntimeError, "zoho_cleanup_failed"):
                with C.serve_zoho(Path("/synthetic"), state):
                    pass
        self.assertEqual([name for event, name in events if event == "closed"], [CONTENT, NAME])
        self.assertTrue(all(c.cleanup_complete for c in certificates))
        self.assertFalse(state.cleanup_complete)

if __name__ == "__main__":
    unittest.main()
