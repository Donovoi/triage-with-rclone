"""Independent OpenDrive wire oracles; no vendor or native acceptance."""
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
    import fixture_opendrive as C
    import fixture_tls as T
finally:
    sys.path.pop(0)

NAME = "dev.opendrive.com"
API = "/api/v1"
KEY, SECRET = "synthetic-key", "synthetic-secret"
PAYLOADS = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
            "nested/bytes.bin": bytes(range(256)) * 8, "nested/space name.txt": b"Nested synthetic payload.\n"}

class OpenDriveWireTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.state = C.OpenDriveState(KEY, SECRET)
        # Wire tests use ephemeral IP TLS, so they also run on Windows without
        # DNS/privileged ports. The contained native probe owns fixed-host TLS.
        self.certificates = self.enterContext(T.FixtureCertificates.create(self.root))
        self.transport = self.enterContext(T.BoundedHttpsServer(self.certificates, C.OpenDriveHandler, state=self.state))

    def request(self, method, path, data=None, auth=None, headers=(), raw_body=None, host=NAME):
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


    def login(self, username=KEY, password=SECRET):
        return self.request("POST", API + "/session/login.json", {"username": username, "passwd": password})

    def session(self):
        status, _, raw = self.login()
        self.assertEqual(status, 200)
        result = json.loads(raw)
        self.assertEqual(set(result), {"SessionID", "UserName"})
        self.assertEqual(result["UserName"], KEY)
        self.assertRegex(result["SessionID"], r"^[a-f0-9]{32}$")
        return result["SessionID"]

    def test_sessions_require_exact_credentials_and_are_unique(self):
        first, second = self.session(), self.session()
        self.assertNotEqual(first, second)
        for username, password in ((KEY, "wrong"), ("wrong", SECRET), ("", ""), (KEY, SECRET + "x")):
            status, headers, raw = self.login(username, password)
            self.assertEqual(status, 401)
            self.assertEqual(json.loads(raw)["error"]["code"], 401)
            self.assertNotIn("WWW-Authenticate", headers)
        self.assertEqual(self.state.sessions, {first, second})
        self.assertEqual((self.state.denied, self.state.payload_bytes), (4, 0))

    def test_inventory_has_exact_string_sizes_hashes_and_folder_ids(self):
        session = self.session()
        for folder, names in (("0", ["README-synthetic.txt"]), ("10", ["nested/bytes.bin", "nested/space name.txt"])):
            status, _, raw = self.request("GET", API + "/folder/list.json/" + session + "/" + folder)
            self.assertEqual(status, 200)
            result = json.loads(raw)
            expected = [{"FileId": str(601 + list(PAYLOADS).index(name)), "Name": name.rsplit("/", 1)[-1],
                         "Size": str(len(PAYLOADS[name])), "DateModified": "1704067200",
                         "FileHash": hashlib.md5(PAYLOADS[name]).hexdigest(), "Access": "0"} for name in names]
            self.assertEqual(result["Files"], expected)
            self.assertEqual(result["Folders"], [{"FolderID": "10", "Name": "nested", "DateModified": 1704067200,
                                                  "ChildFolders": 0}] if folder == "0" else [])
        self.assertEqual(self.state.files, PAYLOADS)

    def test_lookup_metadata_and_content_use_the_issued_session(self):
        session = self.session()
        for i, (name, body) in enumerate(PAYLOADS.items(), 601):
            folder, _, leaf = name.rpartition("/")
            query = urllib.parse.urlencode({"name": leaf})
            path = API + "/folder/itembyname.json/" + session + "/" + ("10" if folder else "0")
            status, _, raw = self.request("GET", path + "?" + query)
            self.assertEqual((status, json.loads(raw)["Files"][0]["FileId"]), (200, str(i)))
            status, _, raw = self.request("GET", API + "/file/info.json/" + str(i) + "?session_id=" + session)
            self.assertEqual((status, json.loads(raw)["FileHash"]), (200, hashlib.md5(body).hexdigest()))
            self.assertEqual(self.request("GET", API + "/download/file.json/" + str(i) + "?session_id=" + session)[::2], (200, body))
        self.assertEqual(self.state.payload_bytes, sum(map(len, PAYLOADS.values())))

    def test_unknown_session_cannot_list_read_or_delete(self):
        unknown = "f" * 32
        for method, path in (("GET", "/folder/list.json/" + unknown + "/0"),
                             ("GET", "/folder/itembyname.json/" + unknown + "/0?name=README-synthetic.txt"),
                             ("GET", "/file/info.json/601?session_id=" + unknown),
                             ("GET", "/download/file.json/601?session_id=" + unknown),
                             ("DELETE", "/file.json/" + unknown + "/601")):
            self.assertEqual(self.request(method, API + path)[0], 401)
        self.assertEqual((self.state.denied, self.state.payload_bytes, self.state.rejected_mutations), (5, 0, 0))
        self.assertEqual(self.state.sessions, set())

    def test_missing_name_returns_no_object_or_payload(self):
        session = self.session()
        status, _, raw = self.request("GET", API + "/folder/itembyname.json/" + session + "/0?name=absent-synthetic.txt")
        self.assertEqual((status, json.loads(raw)["Files"], json.loads(raw)["Folders"]), (200, [], []))
        self.assertEqual((self.state.missing, self.state.payload_bytes), (1, 0))

    def test_denied_read_and_fixture_delete_guard_preserve_sources(self):
        session = self.session()
        self.state.mode = "read_denied"
        status, _, raw = self.request("GET", API + "/download/file.json/601?session_id=" + session)
        self.assertEqual(status, 403)
        self.assertNotIn(PAYLOADS["README-synthetic.txt"], raw)
        self.state.mode = "normal"
        self.assertEqual(self.request("DELETE", API + "/file.json/" + session + "/601")[0], 405)
        self.assertEqual((self.state.read_denied, self.state.rejected_mutations, self.state.payload_bytes), (1, 1, 0))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_unknown_methods_routes_and_queries_fail_closed(self):
        session = self.session()
        for method, path, body in (("GET", "/session/login.json", None), ("POST", "/folder.json", {}),
                ("PUT", "/file.json/" + session + "/601", None),
                ("GET", "/folder/list.json/" + session + "/0?foreign=1", None),
                ("GET", "/folder/itembyname.json/" + session + "/0?name=x&name=x", None),
                ("GET", "/file/info.json/601?session_id=" + session + "&extra=1", None),
                ("GET", "/file/info.json/601", None),
                ("GET", "/folder/itembyname.json/" + session + "/0?name=%ff", None),
                ("GET", "/folder/itembyname.json/" + session + "/0?name=%GG", None),
                ("GET", "/folder/itembyname.json/" + session + "/0?name=%00", None), ("GET", "/%66ile/info.json/601?session_id=" + session, None)):
            with self.subTest(path=path):
                self.assertEqual(self.request(method, API + path, body)[0], 400)
        self.assertEqual(self.request("GET", "https://elsewhere.invalid/")[0], 400)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_duplicate_nonobject_and_wrong_typed_login_bodies_fail(self):
        for raw in (b"[]", b'{"username":"x","username":"x","passwd":"x"}', b'{"username":',
                    b'{"username":null,"passwd":"x"}', b'{"username":true,"passwd":"x"}',
                    b'{"username":"x","passwd":"x","extra":1}'):
            self.assertEqual(self.request("POST", API + "/session/login.json", raw_body=raw)[0], 400)
        self.assertEqual(self.state.sessions, set())

    def test_authority_headers_framing_and_metadata_ranges_are_exact(self):
        session = self.session()
        target = API + "/file/info.json/601?session_id=" + session
        for host in ("127.0.0.1", NAME + ":443", NAME + ".", "DEV.opendrive.com"):
            self.assertEqual(self.request("GET", target, host=host)[0], 400)
        for headers in ((("Host", NAME),), (("Authorization", "Bearer unexpected"),), (("Content-Length", "00"),),
                        (("Content-Length", "4097"),), (("Transfer-Encoding", "chunked"),), (("Range", "bytes=0-1"),)):
            self.assertEqual(self.request("GET", target, headers=headers)[0], 400)

    def test_content_ranges_are_bounded(self):
        session = self.session()
        path = API + "/download/file.json/602?session_id=" + session
        status, headers, raw = self.request("GET", path, headers=(("Range", "bytes=256-511"),))
        self.assertEqual((status, headers["Content-Range"], raw), (206, "bytes 256-511/2048", bytes(range(256))))
        for value in ("bytes=0--1", "bytes=-1", "bytes=2048-", "bytes=2-1", "bytes=0-1,3-4"):
            self.assertEqual(self.request("GET", path, headers=(("Range", value),))[0], 416)
        self.assertEqual(self.state.files, PAYLOADS)

    def test_request_and_response_budgets_prevent_success(self):
        self.state.request_limit = 1
        self.assertEqual(self.login()[0], 200)
        self.assertEqual(self.login()[0], 429)
        self.assertTrue(self.state.budget_exceeded)
        self.state.request_limit = 10
        self.state.byte_limit = 1
        self.assertEqual(self.login()[0], 429)

    def test_tls_deadline_stops_a_partial_json_body(self):
        timer = threading.Timer
        with T.FixtureCertificates.create(self.root) as certificates, patch.object(
                T.threading, "Timer", side_effect=lambda delay, callback: timer(delay + 0.3, callback)):
            with T.BoundedHttpsServer(certificates, C.OpenDriveHandler, state=C.OpenDriveState(KEY, SECRET),
                    limits=T.TlsLimits(request_seconds=0.15)) as transport:
                with socket.create_connection(("127.0.0.1", transport.port), timeout=2) as raw:
                    with certificates.client_context().wrap_socket(raw, server_hostname="127.0.0.1") as client:
                        client.sendall(("POST " + API + "/session/login.json HTTP/1.1\r\nHost: " + NAME
                            + "\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{").encode())
                        self.assertEqual(client.recv(1), b"")
            self.assertIn("tls_request_deadline", transport.snapshot()["failure_codes"])
            self.assertTrue(transport.cleanup_complete)
        self.assertTrue(certificates.cleanup_complete)

class OpenDriveAuthorityTests(unittest.TestCase):
    def test_reviewed_name_has_its_own_exact_sni_and_san(self):
        with tempfile.TemporaryDirectory() as directory:
            with T.FixtureCertificates.create(Path(directory).resolve(), server_name=NAME) as certificates:
                from cryptography import x509
                leaf = x509.load_pem_x509_certificate((certificates.directory / "leaf.pem").read_bytes())
                self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value), [x509.DNSName(NAME)])
        self.assertIsNone(T._opendrive_sni(None, NAME, None))
        for name in (None, "", "fixture.pcloud.com", "api.cloudinary.com", "127.0.0.1", NAME + ".", NAME + ":443"):
            self.assertEqual(T._opendrive_sni(None, name, None), ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)
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
