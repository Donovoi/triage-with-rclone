"""Independent Fichier wire oracles; no vendor or native acceptance."""
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
    import fixture_fichier as C
    import fixture_tls as T
finally:
    sys.path.pop(0)

NAME = "api.1fichier.com"
API = "/v1"
KEY, SECRET = "synthetic-key", "synthetic-secret"
PAYLOADS = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
            "nested/bytes.bin": bytes(range(256)) * 8, "nested/space name.txt": b"Nested synthetic payload.\n"}

CHECKSUMS = {'README-synthetic.txt': '561d86d9772f31565be9f3ba2e103538d808d59dd548e8b0f493d886a50e4b93da58e1d267196a493c1b0c34f92cf5928529d8e0e8ae66be86a59aa7368ee5f9', 'nested/bytes.bin': '6aeaa024635a881dc2d97e1c5d25f4158fef3172d239fe80dcef01536e576f25565bbf17f71737f6de6d128bf9d91cf88e6226e152373be1c4ccb6a3e30465fd', 'nested/space name.txt': '563f21e95574757d38075169f3a0164545d1a1f714819a689be532d81986d6bfe8a60f1777e64ff9e2c6255d3dfd76386ea107fb61ac59875635a8d06e5b6a55'}

class FichierWireTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.state = C.FichierState(SECRET)
        # Wire tests use ephemeral IP TLS, so they also run on Windows without
        # DNS/privileged ports. The contained native probe owns fixed-host TLS.
        self.certificates = self.enterContext(T.FixtureCertificates.create(self.root))
        self.transport = self.enterContext(T.BoundedHttpsServer(self.certificates, C.FichierHandler, state=self.state))

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




    def list(self, folder=0):
        return self.request("POST", API + "/file/ls.cgi", {"folder_id": folder})

    def reference(self, name="README-synthetic.txt"):
        return "https://1fichier.com/?synthetic" + str(901 + list(PAYLOADS).index(name))

    def token(self, name="README-synthetic.txt"):
        self.assertEqual(self.list(10 if "/" in name else 0)[0], 200)
        status, _, raw = self.request("POST", API + "/download/get_token.cgi",
                                      {"url": self.reference(name), "single": 1})
        result = json.loads(raw)
        self.assertEqual((status, set(result), result["Status"]), (200, {"Status", "url"}, "OK"))
        target = urllib.parse.urlsplit(result["url"])
        self.assertEqual((target.scheme, target.netloc, target.query, target.fragment), ("https", NAME, "", ""))
        self.assertRegex(target.path, r"^/download/[a-f0-9]{32}$")
        return target.path

    def test_exact_bearer_is_required_for_every_route(self):
        for auth in (None, "", "Bearer wrong", "bearer " + SECRET, "Bearer " + SECRET + "x"):
            for method, path, data in (("POST", "/file/ls.cgi", {"folder_id": 0}),
                    ("POST", "/folder/ls.cgi", {"folder_id": 0}),
                    ("POST", "/file/info.cgi", {"url": self.reference()}),
                    ("POST", "/download/get_token.cgi", {"url": self.reference(), "single": 1}),
                    ("POST", "/file/rm.cgi", {"files": [{"url": self.reference()}]})):
                status, headers, raw = self.request(method, API + path, data, auth=auth)
                self.assertEqual((status, json.loads(raw)), (401, {"status": "KO", "message": "synthetic invalid key"}))
                self.assertNotIn("WWW-Authenticate", headers)
            self.assertEqual(self.request("GET", "/download/" + "a" * 32, auth=auth)[0], 401)
        self.assertEqual((self.state.denied, self.state.payload_bytes, self.state.rejected_mutations), (30, 0, 0))
        self.assertEqual(self.state.tokens, {})

    def test_file_inventory_and_info_have_independent_whirlpool_and_metadata(self):
        for folder, names in ((0, ["README-synthetic.txt"]), (10, ["nested/bytes.bin", "nested/space name.txt"])):
            status, _, raw = self.list(folder)
            expected = [{"cdn": 0, "pass": 0, "checksum": CHECKSUMS[name],
                "content-type": "application/octet-stream", "date": "2024-01-01 00:00:00",
                "filename": name.rsplit("/", 1)[-1], "size": len(PAYLOADS[name]), "url": self.reference(name)}
                for name in names]
            self.assertEqual((status, json.loads(raw)), (200, {"Status": "OK", "items": expected}))
            for name, metadata in zip(names, expected):
                status, _, raw = self.request("POST", API + "/file/info.cgi", {"url": self.reference(name)})
                self.assertEqual((status, json.loads(raw)), (200, metadata))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_folder_inventory_has_exact_ids_names_and_dates(self):
        for folder, names in ((0, [{"id": 10, "name": "nested", "create_date": "2024-01-01 00:00:00", "pass": 0}]), (10, [])):
            status, _, raw = self.request("POST", API + "/folder/ls.cgi", {"folder_id": folder})
            self.assertEqual((status, json.loads(raw)), (200, {"Status": "OK", "folder_id": folder,
                "name": "synthetic" if folder == 0 else "nested", "sub_folders": names}))
        self.assertEqual(self.state.listed, set())
        self.assertEqual(self.state.tokens, {})

    def test_issued_links_are_unique_single_use_and_do_not_consume_on_wrong_auth(self):
        first, second = self.token(), self.token()
        self.assertNotEqual(first, second)
        self.assertEqual(self.request("GET", first, auth="Bearer wrong")[0], 401)
        self.assertEqual(self.request("GET", first)[::2], (200, PAYLOADS["README-synthetic.txt"]))
        self.assertEqual(self.request("GET", first)[0], 401)
        self.assertEqual(self.request("GET", second)[::2], (200, PAYLOADS["README-synthetic.txt"]))
        self.assertEqual((self.state.replayed, self.state.payload_bytes), (1, 2 * len(PAYLOADS["README-synthetic.txt"])))
        self.assertTrue(all(used for _, used in self.state.tokens.values()))

    def test_unknown_links_and_unlisted_references_fail_without_payload(self):
        self.assertEqual(self.request("GET", "/download/" + "a" * 32)[0], 401)
        for url in (self.reference(), "https://elsewhere.invalid/file", "https://1fichier.com/?unknown", "", None, True):
            for path, data in (("/file/info.cgi", {"url": url}), ("/download/get_token.cgi", {"url": url, "single": 1}),
                               ("/file/rm.cgi", {"files": [{"url": url}]})):
                self.assertEqual(self.request("POST", API + path, data)[0], 400)
        self.assertEqual((self.state.payload_bytes, self.state.rejected_mutations), (0, 0))
        self.assertEqual(self.state.tokens, {})

    def test_three_downloads_match_literal_bytes(self):
        for name, payload in PAYLOADS.items():
            target = self.token(name)
            self.assertEqual(self.request("GET", target)[::2], (200, payload))
        self.assertEqual(self.state.payload_bytes, sum(map(len, PAYLOADS.values())))
        self.assertEqual(len(self.state.tokens), 3)

    def test_complete_inventory_has_no_missing_object_or_invented_filter(self):
        status, _, raw = self.list()
        self.assertEqual((status, {x["filename"] for x in json.loads(raw)["items"]}), (200, {"README-synthetic.txt"}))
        self.assertEqual(self.request("POST", API + "/file/ls.cgi", {"folder_id": 0, "name": "absent-synthetic.txt"})[0], 400)
        self.assertEqual((self.state.missing, self.state.payload_bytes), (0, 0))

    def test_denied_read_consumes_link_and_fixture_mutation_guard_preserves_source(self):
        target = self.token()
        self.state.mode = "read_denied"
        status, _, raw = self.request("GET", target)
        self.assertEqual((status, json.loads(raw)), (403, {"status": "KO", "message": "synthetic read denied"}))
        self.state.mode = "normal"
        self.assertEqual(self.request("GET", target)[0], 401)
        self.assertEqual(self.request("POST", API + "/file/rm.cgi", {"files": [{"url": self.reference()}]})[0], 405)
        self.assertEqual((self.state.read_denied, self.state.replayed, self.state.rejected_mutations, self.state.payload_bytes), (1, 1, 1, 0))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_unknown_routes_methods_queries_and_shared_folder_access_fail_closed(self):
        for method, path, data in (("GET", API + "/file/ls.cgi", None),
                ("DELETE", API + "/file/rm.cgi", None), ("POST", API + "/upload.cgi", {}),
                ("POST", "/dir/shared?json=1", {}), ("HEAD", "/download/" + "a" * 32, None),
                ("PUT", API + "/folder/ls.cgi", {}), ("POST", API + "/file/ls.cgi?extra=1", {"folder_id": 0}),
                ("POST", "/v1/%66ile/ls.cgi", {"folder_id": 0}), ("GET", "https://elsewhere.invalid/", None)):
            with self.subTest(method=method, path=path):
                self.assertEqual(self.request(method, path, data)[0], 400)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_json_fields_types_and_duplicate_keys_are_exact(self):
        for raw in (b"[]", b'{"folder_id":0,"folder_id":0}', b'{"folder_id":', b'{"folder_id":true}',
                    b'{"folder_id":0.0}', b'{"folder_id":"0"}', b'{"folder_id":null}',
                    b'{"folder_id":NaN}', b'{"folder_id":0,"extra":1}'):
            self.assertEqual(self.request("POST", API + "/file/ls.cgi", raw_body=raw)[0], 400)
        self.list()
        for data in ({"url": self.reference()}, {"url": self.reference(), "single": True},
                     {"url": self.reference(), "single": 0}, {"url": self.reference(), "single": 1.0},
                     {"url": self.reference(), "single": 1, "cdn": 1},
                     {"url": self.reference(), "single": 1, "pass": "x"}):
            self.assertEqual(self.request("POST", API + "/download/get_token.cgi", data)[0], 400)
        for data in ({"files": []}, {"files": {}}, {"files": [None]}, {"files": [{"url": self.reference(), "extra": 1}]},
                     {"files": [{"url": self.reference()}, {"url": self.reference()}]}):
            self.assertEqual(self.request("POST", API + "/file/rm.cgi", data)[0], 400)
        self.assertEqual(self.state.tokens, {})
        self.assertEqual(self.state.rejected_mutations, 0)

    def test_authority_duplicate_headers_framing_and_metadata_ranges_are_exact(self):
        target = API + "/file/ls.cgi"
        for host in ("127.0.0.1", NAME + ":443", NAME + ".", "API.1fichier.com"):
            self.assertEqual(self.request("POST", target, {"folder_id": 0}, host=host)[0], 400)
        for headers in ((("Host", NAME),), (("Authorization", "Bearer " + SECRET),),
                        (("Content-Length", "00"),), (("Content-Length", "4097"),),
                        (("Content-Type", "text/plain"),), (("Transfer-Encoding", "chunked"),),
                        (("Range", "bytes=0-1"),)):
            self.assertEqual(self.request("POST", target, {"folder_id": 0}, headers=headers)[0], 400)
        self.assertEqual(self.request("GET", "/download/" + "a" * 32, raw_body=b"x")[0], 400)
        self.assertEqual(self.state.listed, set())

    def test_content_ranges_are_bounded_and_each_link_is_consumed(self):
        path = self.token("nested/bytes.bin")
        status, headers, raw = self.request("GET", path, headers=(("Range", "bytes=256-511"),))
        self.assertEqual((status, headers["Content-Range"], raw), (206, "bytes 256-511/2048", bytes(range(256))))
        for value in ("bytes=0--1", "bytes=-1", "bytes=2048-", "bytes=2-1", "bytes=0-1,3-4"):
            path = self.token("nested/bytes.bin")
            self.assertEqual(self.request("GET", path, headers=(("Range", value),))[0], 416)
            self.assertEqual(self.request("GET", path)[0], 401)
        self.assertTrue(all(used for _, used in self.state.tokens.values()))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_request_and_response_budgets_prevent_success(self):
        self.state.request_limit = 1
        self.assertEqual(self.list()[0], 200)
        self.assertEqual(self.list()[0], 429)
        self.assertTrue(self.state.budget_exceeded)
        self.state.request_limit = 10
        self.state.byte_limit = 1
        self.assertEqual(self.list()[0], 429)

    def test_tls_deadline_stops_partial_json_without_an_http_reply(self):
        timer = threading.Timer
        with T.FixtureCertificates.create(self.root) as certificates, patch.object(
                T.threading, "Timer", side_effect=lambda delay, callback: timer(delay + 0.3, callback)):
            with T.BoundedHttpsServer(certificates, C.FichierHandler, state=C.FichierState(SECRET),
                    limits=T.TlsLimits(request_seconds=0.15)) as transport:
                with socket.create_connection(("127.0.0.1", transport.port), timeout=2) as raw:
                    with certificates.client_context().wrap_socket(raw, server_hostname="127.0.0.1") as client:
                        client.sendall(("POST " + API + "/file/ls.cgi HTTP/1.1\r\nHost: " + NAME
                            + "\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{").encode())
                        self.assertEqual(client.recv(1), b"")
            self.assertIn("tls_request_deadline", transport.snapshot()["failure_codes"])
            self.assertTrue(transport.cleanup_complete)
        self.assertTrue(certificates.cleanup_complete)

class FichierAuthorityTests(unittest.TestCase):
    def test_reviewed_name_has_its_own_exact_sni_and_san(self):
        with tempfile.TemporaryDirectory() as directory:
            with T.FixtureCertificates.create(Path(directory).resolve(), server_name=NAME) as certificates:
                from cryptography import x509
                leaf = x509.load_pem_x509_certificate((certificates.directory / "leaf.pem").read_bytes())
                self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value), [x509.DNSName(NAME)])
        self.assertIsNone(T._fichier_sni(None, NAME, None))
        for name in (None, "", "fixture.pcloud.com", "api.cloudinary.com", "127.0.0.1", NAME + ".", NAME + ":443"):
            self.assertEqual(T._fichier_sni(None, name, None), ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)
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
