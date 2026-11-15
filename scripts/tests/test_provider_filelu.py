"""Independent FileLu wire oracles; no vendor or native acceptance."""
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
    import fixture_filelu as C
    import fixture_tls as T
finally:
    sys.path.pop(0)

NAME = "filelu.com"
API = "/rclone"
ROOT = "synthetic-root"
SECRET = "synthetic-secret"
PAYLOADS = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
            "nested/bytes.bin": bytes(range(256)) * 8, "nested/space name.txt": b"Nested synthetic payload.\n"}

BROWSER = "synthetic-agent"

class FileLuWireTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.state = C.FileLuState(SECRET)
        # Wire tests use ephemeral IP TLS, so they also run on Windows without
        # DNS/privileged ports. The contained native probe owns fixed-host TLS.
        self.certificates = self.enterContext(T.FixtureCertificates.create(self.root))
        self.transport = self.enterContext(T.BoundedHttpsServer(self.certificates, C.FileLuHandler, state=self.state))

    def request(self, method, path, data=None, auth=None, headers=(), raw_body=None, host=NAME, user_agent=BROWSER):
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





    def api(self, route, fields, key=SECRET, extra="", **kwargs):
        query = dict(fields)
        if key is not None:
            query["key"] = key
        return self.request("GET", API + route + "?" + urllib.parse.urlencode(query) + extra, **kwargs)

    def listing(self, folder="", **kwargs):
        return self.api("/folder/list", {"folder_path": "/" + ROOT + ("/" + folder if folder else "")}, **kwargs)

    def meta(self, name="README-synthetic.txt", observe=True, **kwargs):
        if observe:
            self.assertEqual(self.listing(name.rpartition("/")[0])[0], 200)
        code = {"README-synthetic.txt": "filelu000001", "nested/bytes.bin": "filelu000002",
                "nested/space name.txt": "filelu000003"}[name]
        return self.api("/file/info2", {"file_code": code}, **kwargs)

    def link(self, name="README-synthetic.txt", observe=True, **kwargs):
        if observe:
            self.assertEqual(self.listing(name.rpartition("/")[0])[0], 200)
        return self.api("/file/direct_link", {"file_path": ROOT + "/" + name}, **kwargs)

    def content(self, name="README-synthetic.txt"):
        status, _, raw = self.link(name)
        data = json.loads(raw)
        self.assertEqual((status, set(data), data["status"], data["msg"]), (200, {"status", "msg", "result"}, 200, "OK"))
        self.assertEqual(set(data["result"]), {"url", "size"})
        self.assertEqual(data["result"]["size"], len(PAYLOADS[name]))
        parsed = urllib.parse.urlsplit(data["result"]["url"])
        self.assertEqual((parsed.scheme, parsed.netloc, parsed.query, parsed.fragment), ("https", NAME, "", ""))
        self.assertRegex(parsed.path, r"^/content/[a-f0-9]{32}$")
        return parsed.path

    def test_exact_configured_query_key_is_required_without_fallback(self):
        for key in ("", "wrong", SECRET.upper(), "Bearer " + SECRET):
            status, _, raw = self.listing(key=key)
            self.assertEqual((status, json.loads(raw)), (401, {"status": 401, "msg": "Invalid key", "result": {}}))
        self.assertEqual(self.listing(key=None)[0], 400)
        self.assertEqual(self.listing(auth="Bearer " + SECRET)[0], 400)
        self.assertEqual((self.state.denied, self.state.payload_bytes, self.state.authenticated), (4, 0, 0))
        self.assertEqual(self.state.observed, set())
        self.assertEqual(self.state.links, {})

    def test_complete_root_and_nested_inventories_use_exact_provider_fields(self):
        ids = {"README-synthetic.txt": "filelu000001", "nested/bytes.bin": "filelu000002",
               "nested/space name.txt": "filelu000003"}
        for folder, names in (("", ["README-synthetic.txt"]), ("nested", ["nested/bytes.bin", "nested/space name.txt"])):
            status, _, raw = self.listing(folder)
            files = [{"name": name.rsplit("/", 1)[-1], "fld_id": 20 if folder else 10,
                      "path": ROOT + "/" + name, "file_code": ids[name], "size": len(PAYLOADS[name])} for name in names]
            folders = [] if folder else [{"name": "nested", "fld_id": 20, "path": ROOT + "/nested"}]
            self.assertEqual((status, json.loads(raw)), (200, {"status": 200, "msg": "OK", "result": {"files": files, "folders": folders}}))
        self.assertEqual(self.state.observed, set(PAYLOADS))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_independent_info2_schema_keeps_string_sizes_and_filecode_spelling(self):
        md5s = {"README-synthetic.txt": "f9ac90560b9929242009ee0c24c9e5d8",
                "nested/bytes.bin": "1576a94d6cb334dd126cb1c27f19e0f2",
                "nested/space name.txt": "371d24ba264bcaac3332a3ed564a93f8"}
        for i, name in enumerate(sorted(PAYLOADS)):
            status, _, raw = self.meta(name)
            self.assertEqual((status, json.loads(raw)), (200, {"status": 200, "msg": "OK", "result": [
                {"size": str(len(PAYLOADS[name])), "name": name.rsplit("/", 1)[-1], "filecode": "filelu" + str(i + 1).zfill(6),
                 "hash": md5s[name], "status": 200}]}))
        self.assertEqual(self.state.payload_bytes, 0)

    def test_identity_and_links_require_inventory_observation(self):
        self.assertEqual(self.meta(observe=False)[0], 400)
        self.assertEqual(self.link(observe=False)[0], 400)
        self.assertEqual(self.request("GET", "/content/" + "0" * 32)[0], 401)
        self.assertEqual((self.state.payload_bytes, self.state.links), (0, {}))
        self.assertEqual(self.listing()[0], 200)
        self.assertEqual(self.meta(observe=False)[0], 200)
        self.assertEqual(self.link(observe=False)[0], 200)

    def test_three_literal_downloads_use_private_links_without_query_keys(self):
        paths = []
        for name, payload in PAYLOADS.items():
            path = self.content(name);paths.append(path)
            self.assertEqual(self.request("GET", path)[::2], (200, payload))
        self.assertEqual(len(set(paths)), 3)
        self.assertEqual(self.state.payload_bytes, sum(map(len, PAYLOADS.values())))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_content_rejects_forwarded_headers_and_query_credentials(self):
        path = self.content()
        for auth in ("Bearer " + SECRET, "", "OAuth wrong"):
            self.assertEqual(self.request("GET", path, auth=auth)[0], 400)
        for query in ("?key=" + SECRET, "?access_token=" + SECRET):
            self.assertEqual(self.request("GET", path + query)[0], 400)
        self.assertEqual(self.request("GET", path, headers=(("Cookie", "key=synthetic"),))[0], 400)
        self.assertEqual(self.state.payload_bytes, 0)
        self.assertEqual(self.request("GET", path)[::2], (200, PAYLOADS["README-synthetic.txt"]))
        self.assertNotEqual(path, self.content())

    def test_file_and_missing_directory_probes_are_not_fabricated_as_folders(self):
        for name in (*PAYLOADS, "absent-synthetic.txt"):
            status, _, raw = self.listing(name)
            self.assertEqual((status, json.loads(raw)), (200, {"status": 404, "msg": "Folder not found", "result": {}}))
        self.assertEqual((self.state.missing, self.state.unexpected), (4, 0))
        self.assertEqual(self.state.observed, set())
        self.assertEqual(self.state.links, {})
        self.assertEqual(self.listing("unreviewed-name")[0], 400)

    def test_scope_is_explicit_and_never_expands_to_account_root(self):
        for path in ("", "/", ROOT, "/other", "/" + ROOT + "/", "/" + ROOT + "/../",
                     "/" + ROOT + "//nested", "/" + ROOT + "/nested/"):
            self.assertEqual(self.api("/folder/list", {"folder_path": path})[0], 400)
        for path in ("README-synthetic.txt", "/" + ROOT + "/README-synthetic.txt", ROOT + "/../README-synthetic.txt"):
            self.assertEqual(self.api("/file/direct_link", {"file_path": path})[0], 400)
        self.assertEqual(self.state.observed, set())

    def test_denied_reads_and_direct_private_link_guard_preserve_sources(self):
        path = self.content();self.state.mode = "read_denied"
        status, _, raw = self.request("GET", path)
        self.assertEqual((status, json.loads(raw)), (403, {"message": "synthetic read denied"}))
        self.state.mode = "normal"
        self.assertEqual(self.request("DELETE", path, auth="Bearer " + SECRET)[0], 400)
        self.assertEqual(self.request("DELETE", path)[0], 405)
        self.assertEqual((self.state.read_denied, self.state.rejected_mutations, self.state.payload_bytes), (1, 1, 0))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_login_account_legacy_info_and_native_mutations_are_outside_scope(self):
        for method, path in (("POST", "/login"), ("GET", API + "/account/info"),
                             ("GET", API + "/file/info"), ("GET", API + "/upload/server"),
                             ("GET", API + "/file/delete"), ("POST", API + "/folder/create"),
                             ("DELETE", API + "/file/info2"), ("HEAD", API + "/folder/list"),
                             ("GET", "https://elsewhere.invalid/"), ("GET", "/content/foreign")):
            self.assertEqual(self.request(method, path)[0], 400)
        self.assertEqual((self.state.payload_bytes, self.state.rejected_mutations), (0, 0))

    def test_query_contract_rejects_pagination_duplicates_and_unknown_fields(self):
        for query in ("folder_path=/" + ROOT + "&page=1", "folder_path=/" + ROOT + "&limit=1000",
                      "folder_path=/" + ROOT + "&folder_path=/" + ROOT, "fld_id=10",
                      "folder_path=%ff", "folder_path=%GG", "folder_path=%00", ""):
            self.assertEqual(self.request("GET", API + "/folder/list?key=" + SECRET + "&" + query)[0], 400)
        self.assertEqual(self.listing(extra="&key=" + SECRET)[0], 400)
        self.assertEqual(self.listing(extra="&token=synthetic")[0], 400)
        self.assertEqual(self.state.observed, set())
        self.assertEqual(self.state.links, {})

    def test_authority_duplicate_headers_and_framing_are_exact(self):
        target = API + "/folder/list?folder_path=/" + ROOT + "&key=" + SECRET
        for host in ("127.0.0.1", NAME + ":443", NAME + ".", "FILELU.com"):
            self.assertEqual(self.request("GET", target, host=host)[0], 400)
        for headers in ((("Host", NAME),), (("Content-Length", "00"),), (("Content-Length", "4097"),),
                        (("Transfer-Encoding", "chunked"),), (("Range", "bytes=0-1"),)):
            self.assertEqual(self.request("GET", target, headers=headers)[0], 400)
        self.assertEqual(self.request("GET", target, raw_body=b"x")[0], 400)
        self.assertEqual(self.state.observed, set())

    def test_fixture_content_ranges_are_bounded_without_claiming_native_range_use(self):
        path = self.content("nested/bytes.bin")
        status, headers, raw = self.request("GET", path, headers=(("Range", "bytes=256-511"),))
        self.assertEqual((status, headers["Content-Range"], raw), (206, "bytes 256-511/2048", bytes(range(256))))
        for value in ("bytes=0--1", "bytes=-1", "bytes=2048-", "bytes=2-1", "bytes=0-1,3-4"):
            self.assertEqual(self.request("GET", path, headers=(("Range", value),))[0], 416)
        self.assertEqual(self.state.files, PAYLOADS)

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
            with T.BoundedHttpsServer(certificates, C.FileLuHandler, state=C.FileLuState(SECRET),
                    limits=T.TlsLimits(request_seconds=0.15)) as transport:
                with socket.create_connection(("127.0.0.1", transport.port), timeout=2) as raw:
                    with certificates.client_context().wrap_socket(raw, server_hostname="127.0.0.1") as client:
                        client.sendall(("GET " + API + "/folder/list HTTP/1.1\r\nHost: " + NAME).encode())
                        self.assertEqual(client.recv(1), b"")
            self.assertIn("tls_request_deadline", transport.snapshot()["failure_codes"])
            self.assertTrue(transport.cleanup_complete)
        self.assertTrue(certificates.cleanup_complete)

class FileLuAuthorityTests(unittest.TestCase):
    def test_reviewed_name_has_its_own_exact_sni_and_san(self):
        with tempfile.TemporaryDirectory() as directory:
            with T.FixtureCertificates.create(Path(directory).resolve(), server_name=NAME) as certificates:
                from cryptography import x509
                leaf = x509.load_pem_x509_certificate((certificates.directory / "leaf.pem").read_bytes())
                self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value), [x509.DNSName(NAME)])
        self.assertIsNone(T._filelu_sni(None, NAME, None))
        for name in (None, "", "fixture.pcloud.com", "api.cloudinary.com", "127.0.0.1", NAME + ".", NAME + ":443"):
            self.assertEqual(T._filelu_sni(None, name, None), ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)
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
