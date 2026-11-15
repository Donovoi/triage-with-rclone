"""Independent OneDrive wire oracles; no vendor or native acceptance."""
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
    import fixture_onedrive as C
    import fixture_tls as T
finally:
    sys.path.pop(0)

NAME = "graph.microsoft.com"
DRIVE = "synthetic-business-drive"
API = "/v1.0/drives/" + DRIVE
SECRET = "synthetic-secret"
PAYLOADS = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
            "nested/bytes.bin": bytes(range(256)) * 8, "nested/space name.txt": b"Nested synthetic payload.\n"}

BROWSER = "synthetic-agent"

class OneDriveWireTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.state = C.OneDriveState(SECRET)
        # Wire tests use ephemeral IP TLS, so they also run on Windows without
        # DNS/privileged ports. The contained native probe owns fixed-host TLS.
        self.certificates = self.enterContext(T.FixtureCertificates.create(self.root))
        self.transport = self.enterContext(T.BoundedHttpsServer(self.certificates, C.OneDriveHandler, state=self.state))

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





    def meta(self, name="", colon=False, **kwargs):
        if not name:
            path = API + "/root"
        else:
            folder, _, leaf = name.rpartition("/")
            parent = "nested-id" if folder == "nested" else "root-id"
            path = API + "/items/" + parent + ":/" + urllib.parse.quote(leaf, safe="")
            if colon:
                path += ":"
        return self.request("GET", path, **kwargs)

    def listing(self, folder=""):
        return self.request("GET", API + "/items/" + ("nested-id" if folder else "root-id") + "/children?$top=1000")

    def link(self, name="README-synthetic.txt", observe=True, **kwargs):
        if observe:
            self.assertEqual(self.meta(name)[0], 200)
        ident = {"README-synthetic.txt": "file-1601", "nested/bytes.bin": "file-1602",
                 "nested/space name.txt": "file-1603"}[name]
        return self.request("GET", API + "/items/" + ident + "/content", **kwargs)

    def content(self, name="README-synthetic.txt"):
        status, headers, raw = self.link(name)
        parsed = urllib.parse.urlsplit(headers["Location"])
        self.assertEqual((status, raw, headers["Content-Length"]), (302, b"", "0"))
        self.assertEqual((parsed.scheme, parsed.netloc, parsed.query, parsed.fragment), ("https", NAME, "", ""))
        self.assertRegex(parsed.path, r"^/content/[a-f0-9]{32}$")
        return parsed.path

    def test_exact_bearer_scheme_and_token_required_without_renewal_fallback(self):
        for auth in (None, "", "OAuth " + SECRET, "Bearer wrong", "bearer " + SECRET):
            with self.subTest(auth=auth):
                status, _, raw = self.meta(auth=auth)
                self.assertEqual((status, json.loads(raw)["error"]["code"]), (401, "unauthenticated"))
        self.assertEqual((self.state.denied, self.state.payload_bytes, self.state.authenticated), (5, 0, 0))
        self.assertEqual(self.state.observed, set())
        self.assertEqual(self.state.links, {})

    def test_independent_quickxor_metadata_and_complete_directory_inventories(self):
        hashes = {"README-synthetic.txt": "q+GwV5ocSpsIHjWVCFGoh/fhS/8=",
                  "nested/bytes.bin": "rxAOGe1RimTF/e+k/mYO5nnSZT8=",
                  "nested/space name.txt": "LyTjnKtI9PIGV4r4Zi1N0FAGOqQ="}
        ids = {"": "root-id", "nested": "nested-id", "README-synthetic.txt": "file-1601",
               "nested/bytes.bin": "file-1602", "nested/space name.txt": "file-1603"}
        stamp = "2024-01-01T00:00:00Z"
        def metadata(name):
            parent = "nested-id" if name.startswith("nested/") else "root-id"
            item = {"id": ids[name], "name": name.rsplit("/", 1)[-1] if name else "root",
                    "size": len(PAYLOADS[name]) if name in PAYLOADS else 0,
                    "parentReference": {"driveId": DRIVE, "driveType": "business", "id": parent},
                    "createdDateTime": stamp, "lastModifiedDateTime": stamp,
                    "fileSystemInfo": {"createdDateTime": stamp, "lastModifiedDateTime": stamp},
                    "eTag": "synthetic-etag", "cTag": "synthetic-ctag"}
            if name in PAYLOADS:
                item["file"] = {"mimeType": "application/octet-stream", "hashes": {"quickXorHash": hashes[name]}}
            else:
                item["folder"] = {"childCount": 2}
            return item
        for name in ("", "nested", *PAYLOADS):
            self.assertEqual(json.loads(self.meta(name)[2]), metadata(name))
        for folder, names in (("", ["README-synthetic.txt", "nested"]), ("nested", ["nested/bytes.bin", "nested/space name.txt"])):
            status, _, raw = self.listing(folder)
            self.assertEqual((status, json.loads(raw)), (200, {"value": [metadata(name) for name in names]}))
        self.assertEqual(self.state.observed, set(PAYLOADS))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_native_colon_metadata_forms_preserve_ids_and_parent_drive(self):
        for name in ("nested", *PAYLOADS):
            self.assertEqual(self.meta(name, colon=True)[::2], self.meta(name)[::2])
            path = API + "/root:/" + urllib.parse.quote(name, safe="/")
            self.assertEqual(self.request("GET", path)[::2], self.meta(name)[::2])
        self.assertEqual(self.state.observed, set(PAYLOADS))
        self.assertEqual(self.state.links, {})

    def test_download_redirects_require_prior_metadata_or_inventory(self):
        self.assertEqual(self.link(observe=False)[0], 400)
        self.assertEqual(self.request("GET", "/content/" + "0" * 32, auth=None)[0], 401)
        self.assertEqual((self.state.payload_bytes, self.state.links), (0, {}))
        self.assertEqual(self.listing()[0], 200)
        self.assertEqual(self.link(observe=False)[0], 302)

    def test_three_literal_downloads_use_issued_links_without_authentication(self):
        paths = []
        for name, payload in PAYLOADS.items():
            path = self.content(name);paths.append(path)
            self.assertEqual(self.request("GET", path, auth=None)[::2], (200, payload))
        self.assertEqual(len(set(paths)), 3)
        self.assertEqual(self.state.payload_bytes, sum(map(len, PAYLOADS.values())))
        self.assertEqual(self.state.files, PAYLOADS)
        self.assertEqual(sum(e[0] == "unauthenticated_content" for e in self.state.events), 3)

    def test_redirect_targets_reject_forwarded_credentials_and_extra_parameters(self):
        path = self.content()
        for auth in ("Bearer " + SECRET, "", "OAuth wrong"):
            self.assertEqual(self.request("GET", path, auth=auth)[0], 400)
        for query in ("?access_token=" + SECRET, "?AVOverride=1"):
            self.assertEqual(self.request("GET", path + query, auth=None)[0], 400)
        for key in ("Cookie", "Prefer"):
            self.assertEqual(self.request("GET", path, auth=None, headers=((key, "synthetic"),))[0], 400)
        self.assertEqual(self.state.payload_bytes, 0)
        self.assertEqual(self.request("GET", path, auth=None)[::2], (200, PAYLOADS["README-synthetic.txt"]))
        self.assertNotEqual(path, self.content())

    def test_missing_metadata_returns_item_not_found_without_issuing_a_redirect(self):
        for colon in (False, True):
            status, _, raw = self.meta("absent-synthetic.txt", colon=colon)
            self.assertEqual((status, json.loads(raw)["error"]["code"]), (404, "itemNotFound"))
        self.assertEqual((self.state.missing, self.state.observed, self.state.links, self.state.payload_bytes), (2, set(), {}, 0))
        self.assertEqual(self.meta("unreviewed-name")[0], 400)

    def test_native_nested_candidate_probe_returns_missing_without_aliasing_parent(self):
        for suffix in ("", ":"):
            status, _, raw = self.request("GET", API + "/items/nested-id:/nested" + suffix)
            self.assertEqual((status, json.loads(raw)["error"]["code"]), (404, "itemNotFound"))
        self.assertEqual((self.state.missing, self.state.unexpected), (2, 0))
        self.assertEqual(self.state.observed, set())
        self.assertEqual(self.state.links, {})

    def test_denied_reads_and_direct_issued_link_guard_preserve_sources(self):
        path = self.content();self.state.mode = "read_denied"
        status, _, raw = self.request("GET", path, auth=None)
        self.assertEqual((status, json.loads(raw)), (403, {"message": "synthetic read denied"}))
        self.state.mode = "normal"
        self.assertEqual(self.request("DELETE", path)[0], 400)
        self.assertEqual(self.request("DELETE", path, auth=None)[0], 405)
        self.assertEqual((self.state.read_denied, self.state.rejected_mutations, self.state.payload_bytes), (1, 1, 0))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_grants_refresh_personal_shared_delta_malware_and_native_writes_are_outside_scope(self):
        for method, path in (("POST", "/token"), ("GET", "/authorize"), ("GET", API),
                             ("GET", API + "/root/delta"), ("GET", "/v1.0/me/drive/root"),
                             ("GET", "/v1.0/shares/synthetic/driveItem"),
                             ("GET", "/beta/drives/" + DRIVE + "/items/file-1601/contentStream"),
                             ("POST", API + "/items/root-id/children"), ("DELETE", API + "/items/file-1601"),
                             ("HEAD", API + "/root"), ("GET", "https://elsewhere.invalid/"),
                             ("GET", "/content/foreign")):
            self.assertEqual(self.request(method, path)[0], 400)
        self.assertEqual((self.state.payload_bytes, self.state.rejected_mutations), (0, 0))

    def test_query_contract_rejects_pagination_duplicates_and_extra_fields(self):
        for query in ("$top=1", "$skiptoken=next", "$top=1000&$skip=0",
                      "$top=1000&$top=1000", "$select=name", "$orderby=name",
                      "access_token=synthetic", "$top=%ff", "$top=%GG", "$top=%00", ""):
            self.assertEqual(self.request("GET", API + "/items/root-id/children?" + query)[0], 400)
        for query in ("?AVOverride=1", "?$select=id", "?access_token=synthetic"):
            self.assertEqual(self.request("GET", API + "/root" + query)[0], 400)
        self.assertEqual(self.state.observed, set())
        self.assertEqual(self.state.links, {})

    def test_encoded_paths_cannot_escape_exact_drive_and_item_names(self):
        for path in (API + "/items/root-id:/../README-synthetic.txt",
                     API + "/items/root-id:/nested%2Fbytes.bin",
                     API + "/items/nested-id:/space%2520name.txt",
                     API + "/items/nested-id:/space+name.txt",
                     API + "/items/root-id:/README-synthetic.txt/",
                     API + "/items/nested-id:/space%20name.txt::",
                     API + "/items/foreign-id:/README-synthetic.txt",
                     "/v1.0/drives/foreign-drive/root"):
            self.assertEqual(self.request("GET", path)[0], 400)
        self.assertEqual(self.state.observed, set())

    def test_authority_duplicate_headers_framing_and_metadata_ranges_are_exact(self):
        target = API + "/root"
        for host in ("127.0.0.1", NAME + ":443", NAME + ".", "GRAPH.microsoft.com"):
            self.assertEqual(self.request("GET", target, host=host)[0], 400)
        for headers in ((("Host", NAME),), (("Authorization", "Bearer " + SECRET),),
                        (("Content-Length", "00"),), (("Content-Length", "4097"),),
                        (("Transfer-Encoding", "chunked"),), (("Range", "bytes=0-1"),)):
            self.assertEqual(self.request("GET", target, headers=headers)[0], 400)
        self.assertEqual(self.request("GET", target, raw_body=b"x")[0], 400)
        self.assertEqual(self.state.observed, set())

    def test_content_ranges_are_bounded(self):
        path = self.content("nested/bytes.bin")
        status, headers, raw = self.request("GET", path, auth=None, headers=(("Range", "bytes=256-511"),))
        self.assertEqual((status, headers["Content-Range"], raw), (206, "bytes 256-511/2048", bytes(range(256))))
        for value in ("bytes=0--1", "bytes=-1", "bytes=2048-", "bytes=2-1", "bytes=0-1,3-4"):
            self.assertEqual(self.request("GET", path, auth=None, headers=(("Range", value),))[0], 416)
        self.assertEqual(self.state.files, PAYLOADS)

    def test_request_and_response_budgets_prevent_success(self):
        self.state.request_limit = 1
        self.assertEqual(self.meta()[0], 200)
        self.assertEqual(self.meta()[0], 429)
        self.assertTrue(self.state.budget_exceeded)
        self.state.request_limit = 10;self.state.byte_limit = 1
        self.assertEqual(self.meta()[0], 429)

    def test_tls_deadline_stops_partial_headers(self):
        timer = threading.Timer
        with T.FixtureCertificates.create(self.root) as certificates, patch.object(
                T.threading, "Timer", side_effect=lambda delay, callback: timer(delay + 0.3, callback)):
            with T.BoundedHttpsServer(certificates, C.OneDriveHandler, state=C.OneDriveState(SECRET),
                    limits=T.TlsLimits(request_seconds=0.15)) as transport:
                with socket.create_connection(("127.0.0.1", transport.port), timeout=2) as raw:
                    with certificates.client_context().wrap_socket(raw, server_hostname="127.0.0.1") as client:
                        client.sendall(("GET " + API + "/root HTTP/1.1\r\nHost: " + NAME).encode())
                        self.assertEqual(client.recv(1), b"")
            self.assertIn("tls_request_deadline", transport.snapshot()["failure_codes"])
            self.assertTrue(transport.cleanup_complete)
        self.assertTrue(certificates.cleanup_complete)

class OneDriveAuthorityTests(unittest.TestCase):
    def test_reviewed_name_has_its_own_exact_sni_and_san(self):
        with tempfile.TemporaryDirectory() as directory:
            with T.FixtureCertificates.create(Path(directory).resolve(), server_name=NAME) as certificates:
                from cryptography import x509
                leaf = x509.load_pem_x509_certificate((certificates.directory / "leaf.pem").read_bytes())
                self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value), [x509.DNSName(NAME)])
        self.assertIsNone(T._onedrive_sni(None, NAME, None))
        for name in (None, "", "fixture.pcloud.com", "api.cloudinary.com", "127.0.0.1", NAME + ".", NAME + ":443"):
            self.assertEqual(T._onedrive_sni(None, name, None), ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)
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
