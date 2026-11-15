"""Independent Linkbox wire oracles; no vendor or native acceptance."""
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
    import fixture_linkbox as C
    import fixture_tls as T
finally:
    sys.path.pop(0)

NAME = "www.linkbox.to"
API = "/api/file/my_file_list/web"
KEY, SECRET = "synthetic-key", "synthetic-secret"
PAYLOADS = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
            "nested/bytes.bin": bytes(range(256)) * 8, "nested/space name.txt": b"Nested synthetic payload.\n"}

BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

class LinkboxWireTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.state = C.LinkboxState(SECRET)
        # Wire tests use ephemeral IP TLS, so they also run on Windows without
        # DNS/privileged ports. The contained native probe owns fixed-host TLS.
        self.certificates = self.enterContext(T.FixtureCertificates.create(self.root))
        self.transport = self.enterContext(T.BoundedHttpsServer(self.certificates, C.LinkboxHandler, state=self.state))

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




    def list(self, identity="0", token=SECRET, extra="", **kwargs):
        query = {"pid": identity, "pageNo": "1", "pageSize": "1000"}
        if token is not None:
            query["token"] = token
        return self.request("GET", API + "?" + urllib.parse.urlencode(query) + extra, **kwargs)

    def content(self, name="README-synthetic.txt"):
        result = json.loads(self.list("10" if "/" in name else "0")[2])
        item = next(x for x in result["data"]["list"] if x["name"] == name.rsplit("/", 1)[-1])
        parsed = urllib.parse.urlsplit(item["url"])
        self.assertEqual((parsed.scheme, parsed.netloc, parsed.query, parsed.fragment), ("https", NAME, "", ""))
        self.assertRegex(parsed.path, r"^/content/[a-f0-9]{32}$")
        return parsed.path

    def test_only_exact_query_web_token_authorizes_inventory(self):
        for token in (None, "", "wrong", SECRET + "x"):
            with self.subTest(token=token):
                status, _, raw = self.list(token=token)
                self.assertEqual((status, json.loads(raw)), (401, {"status": 401, "msg": "synthetic invalid web token"}))
        self.assertEqual((self.state.denied, self.state.payload_bytes, self.state.authenticated), (4, 0, 0))
        self.assertEqual(self.state.issued, set())

    def test_independent_inventory_types_ids_times_sizes_and_private_links(self):
        for folder, names in (("0", ["README-synthetic.txt"]), ("10", ["nested/bytes.bin", "nested/space name.txt"])):
            status, _, raw = self.list(folder)
            result = json.loads(raw)
            self.assertEqual((status, result["status"], result["msg"], set(result["data"])), (200, 1, "success", {"list"}))
            items = result["data"]["list"]
            expected = []
            for i, name in enumerate(names):
                identity = 1201 + list(PAYLOADS).index(name)
                item = items[i]
                url = urllib.parse.urlsplit(item["url"])
                self.assertEqual((url.scheme, url.netloc, url.query, url.fragment), ("https", NAME, "", ""))
                self.assertRegex(url.path, r"^/content/[a-f0-9]{32}$")
                expected.append({"id": identity, "pid": int(folder), "type": "application/octet-stream",
                    "name": name.rsplit("/", 1)[-1], "size": len(PAYLOADS[name]), "ctime": 1704067200,
                    "item_id": "item" + str(identity), "url": item["url"]})
            if folder == "0":
                expected.append({"id": 10, "pid": 0, "type": "dir", "name": "nested", "size": 0,
                                 "ctime": 1704067200, "item_id": "", "url": ""})
            self.assertEqual(items, expected)
            self.assertEqual(json.loads(self.list(folder)[2]), result)
        self.assertEqual(self.state.files, PAYLOADS)

    def test_links_require_inventory_before_any_content_bytes(self):
        path = "/content/" + next(iter(self.state.links))
        self.assertEqual(self.request("GET", path)[0], 401)
        self.assertEqual(self.request("GET", "/content/" + "0" * 32)[0], 401)
        self.assertEqual(self.state.payload_bytes, 0)
        self.assertEqual(self.state.issued, set())

    def test_three_literal_downloads_use_browser_agent_and_no_credentials(self):
        paths = []
        for name, payload in PAYLOADS.items():
            path = self.content(name); paths.append(path)
            self.assertEqual(self.request("GET", path)[::2], (200, payload))
        self.assertEqual(len(set(paths)), 3)
        self.assertEqual(self.state.payload_bytes, sum(map(len, PAYLOADS.values())))
        self.assertEqual(self.state.content_authorizations, 0)

    def test_cdn_rejects_forwarded_credentials_cookies_and_wrong_user_agent(self):
        path = self.content()
        for kwargs in ({"auth": "Bearer " + SECRET}, {"headers": (("Cookie", "token=" + SECRET),)},
                       {"user_agent": None}, {"user_agent": "rclone"}, {"user_agent": BROWSER + "x"}):
            self.assertEqual(self.request("GET", path, **kwargs)[0], 400)
        self.assertEqual(self.request("GET", path + "?token=" + SECRET)[0], 400)
        self.assertEqual(self.state.payload_bytes, 0)
        self.assertEqual(self.state.content_authorizations, 2)
        self.assertEqual(self.request("GET", path)[::2], (200, PAYLOADS["README-synthetic.txt"]))

    def test_complete_inventory_has_no_invented_missing_name_endpoint(self):
        status, _, raw = self.list()
        self.assertEqual((status, {x["name"] for x in json.loads(raw)["data"]["list"]}),
                         (200, {"README-synthetic.txt", "nested"}))
        self.assertEqual(self.list(extra="&name=absent-synthetic.txt")[0], 400)
        self.assertEqual((self.state.missing, self.state.payload_bytes), (0, 0))

    def test_read_denial_and_direct_query_authenticated_guard_preserve_sources(self):
        path = self.content()
        self.state.mode = "read_denied"
        status, _, raw = self.request("GET", path)
        self.assertEqual((status, json.loads(raw)), (403, {"error": "synthetic content denied"}))
        self.state.mode = "normal"
        self.assertEqual(self.request("DELETE", path)[0], 401)
        self.assertEqual(self.request("DELETE", path + "?token=" + SECRET)[0], 405)
        self.assertEqual((self.state.read_denied, self.state.rejected_mutations, self.state.payload_bytes), (1, 1, 0))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_login_account_public_api_and_native_writes_are_outside_saved_token_scope(self):
        for method, path in (("GET", "/api/user/login_email?email=synthetic&pwd=synthetic"),
                             ("GET", "/api/user/info"), ("GET", "/api/open/file_list?token=synthetic"),
                             ("GET", "/api/open/folder_create"), ("GET", "/api/open/folder_del"),
                             ("POST", API), ("HEAD", API), ("GET", "/content/foreign"),
                             ("GET", "https://elsewhere.invalid/")):
            self.assertEqual(self.request(method, path)[0], 400)
        self.assertEqual((self.state.payload_bytes, self.state.rejected_mutations), (0, 0))

    def test_query_contract_rejects_pagination_wrong_types_duplicates_and_extra_fields(self):
        base = "?token=" + SECRET
        for query in ("&pid=0&pageNo=2&pageSize=1000", "&pid=0&pageNo=1&pageSize=1",
                      "&pid=1&pageNo=1&pageSize=1000", "&pid=0&pageNo=1&pageSize=1000&pid=0",
                      "&pid=0&pageNo=1&pageSize=1000&extra=1", "&pid=0&pageNo=1&pageSize=1000&token=" + SECRET,
                      "&pid=%ff&pageNo=1&pageSize=1000", "&pid=%GG&pageNo=1&pageSize=1000",
                      "&pid=%00&pageNo=1&pageSize=1000", "&pageNo=1&pageSize=1000"):
            with self.subTest(query=query):
                self.assertEqual(self.request("GET", API + base + query)[0], 400)
        self.assertEqual(self.list(auth="Bearer " + SECRET)[0], 400)
        self.assertEqual(self.list(headers=(("Cookie", "token=" + SECRET),))[0], 400)
        self.assertEqual(self.state.issued, set())

    def test_authority_duplicate_headers_framing_and_metadata_ranges_are_exact(self):
        target = API + "?token=" + SECRET + "&pid=0&pageNo=1&pageSize=1000"
        for host in ("127.0.0.1", NAME + ":443", NAME + ".", "WWW.linkbox.to"):
            self.assertEqual(self.request("GET", target, host=host)[0], 400)
        for headers in ((("Host", NAME),), (("User-Agent", BROWSER),),
                        (("Content-Length", "00"),), (("Content-Length", "4097"),),
                        (("Transfer-Encoding", "chunked"),), (("Range", "bytes=0-1"),)):
            self.assertEqual(self.request("GET", target, headers=headers)[0], 400)
        self.assertEqual(self.request("GET", target, raw_body=b"x")[0], 400)
        self.assertEqual(self.state.issued, set())

    def test_content_ranges_are_bounded(self):
        path = self.content("nested/bytes.bin")
        status, headers, raw = self.request("GET", path, headers=(("Range", "bytes=256-511"),))
        self.assertEqual((status, headers["Content-Range"], raw), (206, "bytes 256-511/2048", bytes(range(256))))
        for value in ("bytes=0--1", "bytes=-1", "bytes=2048-", "bytes=2-1", "bytes=0-1,3-4"):
            self.assertEqual(self.request("GET", path, headers=(("Range", value),))[0], 416)
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
            with T.BoundedHttpsServer(certificates, C.LinkboxHandler, state=C.LinkboxState(SECRET),
                    limits=T.TlsLimits(request_seconds=0.15)) as transport:
                with socket.create_connection(("127.0.0.1", transport.port), timeout=2) as raw:
                    with certificates.client_context().wrap_socket(raw, server_hostname="127.0.0.1") as client:
                        client.sendall(("GET " + API + "?token=synthetic&pid=0&pageNo=1&pageSize=1000 HTTP/1.1\r\nHost: " + NAME).encode())
                        self.assertEqual(client.recv(1), b"")
            self.assertIn("tls_request_deadline", transport.snapshot()["failure_codes"])
            self.assertTrue(transport.cleanup_complete)
        self.assertTrue(certificates.cleanup_complete)

class LinkboxAuthorityTests(unittest.TestCase):
    def test_reviewed_name_has_its_own_exact_sni_and_san(self):
        with tempfile.TemporaryDirectory() as directory:
            with T.FixtureCertificates.create(Path(directory).resolve(), server_name=NAME) as certificates:
                from cryptography import x509
                leaf = x509.load_pem_x509_certificate((certificates.directory / "leaf.pem").read_bytes())
                self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value), [x509.DNSName(NAME)])
        self.assertIsNone(T._linkbox_sni(None, NAME, None))
        for name in (None, "", "fixture.pcloud.com", "api.cloudinary.com", "127.0.0.1", NAME + ".", NAME + ":443"):
            self.assertEqual(T._linkbox_sni(None, name, None), ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)
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
