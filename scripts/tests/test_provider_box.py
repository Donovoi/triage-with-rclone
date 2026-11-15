"""Independent Box wire oracles; no vendor or native acceptance."""
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
    import fixture_box as C
    import fixture_tls as T
finally:
    sys.path.pop(0)

NAME = "api.box.com"
API = "/2.0"
SECRET = "synthetic-secret"
PAYLOADS = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
            "nested/bytes.bin": bytes(range(256)) * 8, "nested/space name.txt": b"Nested synthetic payload.\n"}

BROWSER = "synthetic-agent"

class BoxWireTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.state = C.BoxState(SECRET)
        # Wire tests use ephemeral IP TLS, so they also run on Windows without
        # DNS/privileged ports. The contained native probe owns fixed-host TLS.
        self.certificates = self.enterContext(T.FixtureCertificates.create(self.root))
        self.transport = self.enterContext(T.BoundedHttpsServer(self.certificates, C.BoxHandler, state=self.state))

    def request(self, method, path, data=None, auth="Bearer " + SECRET, headers=(), raw_body=None, host=NAME, user_agent=BROWSER):
        body = raw_body if raw_body is not None else json.dumps(data).encode() if data is not None else b""
        client = http.client.HTTPSConnection("127.0.0.1", self.transport.port, timeout=3,
                                             context=self.certificates.client_context())
        try:
            client.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            client.putheader("Host", host)
            if user_agent is not None:
                client.putheader("User-Agent", user_agent)
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






    def list(self, folder="0", extra="", **kwargs):
        return self.request("GET", API + "/folders/" + folder + "/items?" +
                            urllib.parse.urlencode({"fields": C.FIELDS, "limit": "1000", "usemarker": "true"}) + extra, **kwargs)

    def preflight(self, name="README-synthetic.txt", parent="0", **kwargs):
        return self.request("OPTIONS", API + "/files/content/", {"name": name, "parent": {"id": parent}}, **kwargs)

    def meta(self, identity="1401", **kwargs):
        return self.request("GET", API + "/files/" + identity + "?" +
                            urllib.parse.urlencode({"fields": C.FIELDS}), **kwargs)

    def content(self, name="README-synthetic.txt"):
        result = json.loads(self.preflight(name.rsplit("/", 1)[-1], "10" if "/" in name else "0")[2])
        identity = result["context_info"]["conflicts"]["id"]
        self.assertEqual(self.meta(identity)[0], 200)
        return API + "/files/" + identity + "/content"

    def test_exact_bearer_required_without_jwt_impersonation_or_renewal(self):
        for auth in (None, "", "OAuth " + SECRET, "Bearer wrong", "bearer " + SECRET):
            with self.subTest(auth=auth):
                status, _, raw = self.list(auth=auth)
                self.assertEqual((status, json.loads(raw)["code"]), (401, "unauthorized"))
        self.assertEqual((self.state.denied, self.state.payload_bytes, self.state.authenticated), (5, 0, 0))
        self.assertEqual(self.state.observed, set())
        self.assertEqual(self.state.preflights, 0)

    def test_independent_inventory_and_metadata_fields_match_the_pinned_schema(self):
        self.assertEqual(C.FIELDS, "type,id,sequence_id,etag,sha1,name,size,created_at,modified_at,content_created_at,content_modified_at,item_status,shared_link,owned_by")
        sha1s = {"README-synthetic.txt": "1ec3b3f6066fc5a95bbdd77582db2aab6a3b5cd4",
                 "nested/bytes.bin": "f10ccfde60c17db26e7d85d35665c7661dbbeb2c",
                 "nested/space name.txt": "e5f3513d82c1077ee498c25b7ce3500d392bf801"}
        def expected(name):
            directory = name == "nested"
            stamp = "2024-01-01T00:00:00Z"
            return {"type": "folder" if directory else "file", "id": "10" if directory else str(1401 + list(PAYLOADS).index(name)),
                    "sequence_id": "0", "etag": "0", "sha1": "" if directory else sha1s[name],
                    "name": name.rsplit("/", 1)[-1], "size": 0 if directory else len(PAYLOADS[name]),
                    "created_at": stamp, "modified_at": stamp, "content_created_at": stamp, "content_modified_at": stamp,
                    "item_status": "active", "shared_link": {},
                    "owned_by": {"type": "user", "id": "synthetic-owner", "name": "Synthetic", "login": "synthetic@example.invalid"}}
        for folder, names in (("0", ["README-synthetic.txt", "nested"]), ("10", ["nested/bytes.bin", "nested/space name.txt"])):
            status, _, raw = self.list(folder)
            self.assertEqual((status, json.loads(raw)), (200, {"entries": [expected(n) for n in names], "total_count": 2, "limit": 1000, "offset": 0}))
        for i, name in enumerate(PAYLOADS):
            self.assertEqual(json.loads(self.meta(str(1401 + i))[2]), expected(name))
        self.assertEqual(self.state.observed, set(PAYLOADS))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_read_side_options_returns_the_existing_file_conflict_without_mutation(self):
        status, _, raw = self.preflight()
        data = json.loads(raw)
        self.assertEqual((status, data["type"], data["status"], data["code"]), (409, "error", 409, "item_name_in_use"))
        self.assertEqual(data["context_info"], {"conflicts": {"type": "file", "id": "1401", "sequence_id": "0", "etag": "0",
            "sha1": "1ec3b3f6066fc5a95bbdd77582db2aab6a3b5cd4", "name": "README-synthetic.txt"}})
        self.assertEqual((self.state.preflights, self.state.rejected_mutations, self.state.payload_bytes), (1, 0, 0))
        self.assertEqual(self.state.observed, {"README-synthetic.txt"})
        self.assertEqual(self.state.files, PAYLOADS)

    def test_missing_preflight_has_no_conflict_and_never_uploads_or_reads_bytes(self):
        status, _, raw = self.preflight("absent-synthetic.txt")
        self.assertEqual((status, json.loads(raw)), (200, {"upload_token": "synthetic-unused-upload-token", "upload_url": "https://api.box.com/unused-upload"}))
        self.assertEqual((self.state.missing, self.state.preflights, self.state.observed, self.state.payload_bytes), (1, 1, set(), 0))
        self.assertEqual(self.request("POST", "/unused-upload", raw_body=b"x")[0], 400)
        self.assertEqual(self.state.files, PAYLOADS)

    def test_metadata_and_content_require_an_observed_known_identity(self):
        self.assertEqual(self.meta()[0], 404)
        self.assertEqual(self.request("GET", API + "/files/1401/content")[0], 404)
        self.assertEqual(self.meta("9999")[0], 404)
        self.assertEqual(self.state.payload_bytes, 0)
        self.assertEqual(self.preflight()[0], 409)
        self.assertEqual(self.meta()[0], 200)

    def test_three_literal_downloads_preserve_known_bytes(self):
        for name, payload in PAYLOADS.items():
            self.assertEqual(self.request("GET", self.content(name))[::2], (200, payload))
        self.assertEqual(self.state.payload_bytes, sum(map(len, PAYLOADS.values())))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_content_requires_bearer_and_denied_reads_and_guard_preserve_sources(self):
        path = self.content()
        self.assertEqual(self.request("GET", path, auth=None)[0], 401)
        self.assertEqual(self.request("GET", path + "?access_token=synthetic")[0], 400)
        self.state.mode = "read_denied"
        status, _, raw = self.request("GET", path)
        self.assertEqual((status, json.loads(raw)["code"]), (403, "access_denied_insufficient_permissions"))
        self.state.mode = "normal"
        self.assertEqual(self.request("DELETE", path, auth=None)[0], 401)
        self.assertEqual(self.request("DELETE", path)[0], 405)
        self.assertEqual((self.state.read_denied, self.state.rejected_mutations, self.state.payload_bytes), (1, 1, 0))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_preflight_rejects_upload_size_wrong_parent_and_noncanonical_json(self):
        target = API + "/files/content/"
        bad = [{}, {"name": "README-synthetic.txt", "parent": {"id": 0}},
               {"name": "README-synthetic.txt", "parent": {"id": "10"}},
               {"name": "README-synthetic.txt", "parent": {"id": "0", "extra": True}},
               {"name": "README-synthetic.txt", "parent": {"id": "0"}, "size": -1},
               {"name": "README-synthetic.txt", "parent": {"id": "0"}, "size": 62},
               {"name": "../README-synthetic.txt", "parent": {"id": "0"}},
               {"name": True, "parent": {"id": "0"}}, []]
        for data in bad:
            self.assertEqual(self.request("OPTIONS", target, data)[0], 400)
        for raw in (b'{"name":"README-synthetic.txt","name":"x","parent":{"id":"0"}}',
                    b'{"name":"README-synthetic.txt","parent":{"id":"0","id":"0"}}',
                    b'{"name":NaN,"parent":{"id":"0"}}', b'{"', b'\xff'):
            self.assertEqual(self.request("OPTIONS", target, raw_body=raw)[0], 400)
        self.assertEqual(self.request("OPTIONS", target)[0], 400)
        self.assertEqual((self.state.preflights, self.state.observed, self.state.rejected_mutations), (0, set(), 0))

    def test_query_contract_rejects_markers_impersonation_and_alternate_fields(self):
        for extra in ("&marker=synthetic", "&fields=name", "&limit=1000", "&usemarker=true", "&extra=1"):
            self.assertEqual(self.list(extra=extra)[0], 400)
        for query in ("fields=name&limit=1000&usemarker=true", "fields=x&limit=1&usemarker=false", "fields=%ff", "fields=%GG"):
            self.assertEqual(self.request("GET", API + "/folders/0/items?" + query)[0], 400)
        self.assertEqual(self.list(headers=(("as-user", "synthetic-user"),))[0], 400)
        self.assertEqual(self.list(headers=(("Cookie", "synthetic"),))[0], 400)
        self.assertEqual(self.preflight(headers=(("Cookie", "synthetic"),))[0], 400)
        self.assertEqual(self.state.observed, set())

    def test_oauth_account_primary_token_setup_and_native_writes_are_outside_scope(self):
        for method, path in (("POST", "/oauth2/token"), ("GET", API + "/users/me"),
                             ("POST", API + "/files/content"), ("PUT", API + "/files/1401"),
                             ("DELETE", API + "/files/1401"), ("POST", API + "/folders"),
                             ("HEAD", API + "/folders/0/items"), ("GET", API + "/files/content/"),
                             ("GET", "https://elsewhere.invalid/")):
            self.assertEqual(self.request(method, path)[0], 400)
        self.assertEqual((self.state.payload_bytes, self.state.rejected_mutations), (0, 0))

    def test_authority_duplicate_headers_framing_and_metadata_ranges_are_exact(self):
        target = API + "/files/content/"
        data = {"name": "README-synthetic.txt", "parent": {"id": "0"}}
        for host in ("127.0.0.1", NAME + ":443", NAME + ".", "API.box.com"):
            self.assertEqual(self.request("OPTIONS", target, data, host=host)[0], 400)
        for headers in ((("Host", NAME),), (("Authorization", "Bearer " + SECRET),),
                        (("Content-Length", "00"),), (("Content-Length", "4097"),),
                        (("Transfer-Encoding", "chunked"),), (("Range", "bytes=0-1"),)):
            self.assertEqual(self.request("OPTIONS", target, data, headers=headers)[0], 400)
        self.assertEqual(self.request("GET", API + "/files/1401", raw_body=b"x")[0], 400)
        self.assertEqual(self.state.observed, set())

    def test_content_ranges_are_bounded(self):
        path = self.content("nested/bytes.bin")
        status, headers, raw = self.request("GET", path, headers=(("Range", "bytes=256-511"),))
        self.assertEqual((status, headers["Content-Range"], raw), (206, "bytes 256-511/2048", bytes(range(256))))
        for value in ("bytes=0--1", "bytes=-1", "bytes=2048-", "bytes=2-1", "bytes=0-1,3-4"):
            self.assertEqual(self.request("GET", path, headers=(("Range", value),))[0], 416)
        self.assertEqual(self.state.files, PAYLOADS)

    def test_request_and_response_budgets_prevent_success(self):
        self.state.request_limit = 1
        self.assertEqual(self.preflight()[0], 409)
        self.assertEqual(self.preflight()[0], 429)
        self.assertTrue(self.state.budget_exceeded)
        self.state.request_limit = 10;self.state.byte_limit = 1
        self.assertEqual(self.list()[0], 429)

    def test_tls_deadline_stops_partial_headers_and_options_body(self):
        timer = threading.Timer
        for body in (False, True):
            with self.subTest(body=body), T.FixtureCertificates.create(self.root) as certificates, patch.object(
                    T.threading, "Timer", side_effect=lambda delay, callback: timer(delay + 0.3, callback)):
                with T.BoundedHttpsServer(certificates, C.BoxHandler, state=C.BoxState(SECRET),
                        limits=T.TlsLimits(request_seconds=0.15)) as transport:
                    with socket.create_connection(("127.0.0.1", transport.port), timeout=2) as raw:
                        with certificates.client_context().wrap_socket(raw, server_hostname="127.0.0.1") as client:
                            request = "OPTIONS " + API + "/files/content/ HTTP/1.1\r\nHost: " + NAME
                            if body:
                                request += "\r\nContent-Type: application/json\r\nContent-Length: 64\r\n\r\n{"
                            client.sendall(request.encode())
                            self.assertEqual(client.recv(1), b"")
                self.assertIn("tls_request_deadline", transport.snapshot()["failure_codes"])
                self.assertTrue(transport.cleanup_complete)
            self.assertTrue(certificates.cleanup_complete)

class BoxAuthorityTests(unittest.TestCase):
    def test_reviewed_name_has_its_own_exact_sni_and_san(self):
        with tempfile.TemporaryDirectory() as directory:
            with T.FixtureCertificates.create(Path(directory).resolve(), server_name=NAME) as certificates:
                from cryptography import x509
                leaf = x509.load_pem_x509_certificate((certificates.directory / "leaf.pem").read_bytes())
                self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value), [x509.DNSName(NAME)])
        self.assertIsNone(T._box_sni(None, NAME, None))
        for name in (None, "", "fixture.pcloud.com", "api.cloudinary.com", "127.0.0.1", NAME + ".", NAME + ":443"):
            self.assertEqual(T._box_sni(None, name, None), ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)
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
