"""Independent QingStor wire oracles; no vendor or native acceptance."""
import urllib.parse
import base64
import email.utils
import hmac
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
    import fixture_qingstor as C
    import fixture_tls as T
finally:
    sys.path.pop(0)

NAME = "pek3a.qingstor.com"
BUCKET = "synthetic-bucket"
API = "/" + BUCKET
KEY = "synthetic-qs-key"
STAMP = "Mon, 01 Jan 2024 00:00:00 GMT"
SECRET = "synthetic-qs-secret"
PAYLOADS = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
            "nested/bytes.bin": bytes(range(256)) * 8, "nested/space name.txt": b"Nested synthetic payload.\n"}

BROWSER = "synthetic-agent"

class QingStorWireTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.state = C.QingStorState(KEY, SECRET)
        self.certificates = self.enterContext(T.FixtureCertificates.create(self.root))
        self.transport = self.enterContext(T.BoundedHttpsServer(self.certificates, C.QingStorHandler, state=self.state))

    def request(self, method, path, auth="auto", date="now", key=KEY, secret=SECRET,
                headers=(), raw_body=b"", host=NAME + ":443", signature_path=None):
        if date == "now":
            date = email.utils.formatdate(usegmt=True)
        if auth == "auto":
            canonical = urllib.parse.urlsplit(path).path if signature_path is None else signature_path
            message = (method + "\n\n\n" + (date or "") + "\n" + canonical).encode()
            auth = "QS " + key + ":" + base64.b64encode(hmac.new(secret.encode(), message, hashlib.sha256).digest()).decode()
        client = http.client.HTTPSConnection("127.0.0.1", self.transport.port, timeout=3,
                                             context=self.certificates.client_context())
        try:
            client.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            client.putheader("Host", host)
            if date is not None:
                client.putheader("Date", date)
            if auth is not None:
                client.putheader("Authorization", auth)
            if raw_body:
                client.putheader("Content-Length", str(len(raw_body)))
            for k, v in headers:
                client.putheader(k, v)
            client.endheaders(raw_body)
            response = client.getresponse()
            return response.status, dict(response.getheaders()), response.read(65537)
        finally:
            client.close()

    def listing(self, folder="", recursive=False, extra="", **kwargs):
        query = {"delimiter": "" if recursive else "/", "limit": "1000",
                 "prefix": folder + "/" if folder else ""}
        return self.request("GET", API + "?" + urllib.parse.urlencode(query) + extra, **kwargs)

    def meta(self, name="README-synthetic.txt", **kwargs):
        return self.request("HEAD", API + "/" + urllib.parse.quote(name, safe="/"), **kwargs)

    def content(self, name="README-synthetic.txt", observe=True, **kwargs):
        if observe:
            self.assertEqual(self.meta(name)[0], 200)
        return self.request("GET", API + "/" + urllib.parse.quote(name, safe="/"), **kwargs)

    def test_independent_openssl_hmac_sha256_vectors(self):
        vectors = (("GET", API, "S3SChQo2PE86T4wFFsl5w0JgM7A0k4AI19Lg/nb3Epg="),
                   ("HEAD", API + "/README-synthetic.txt", "lJyy0ffBFf6R4ASLPUdfxnDBamrx0XFNFf/c83vkaUM="),
                   ("GET", API + "/nested/space%20name.txt", "ubsE48RuvWaKv0c6TzoxrUilW3D8VFTIqKsoc1AGB2c="),
                   ("DELETE", API + "/README-synthetic.txt", "PJnoubiQzgqmwc/FSsL1aWQIAASPz7S6V3O2Cvc0RG4="))
        for method, path, literal in vectors:
            self.assertEqual(C.authorization(method, path, STAMP, KEY, SECRET), "QS " + KEY + ":" + literal)
        with patch.object(C.time, "time", return_value=1704067200):
            self.assertEqual(self.listing(date=STAMP, auth="QS " + KEY + ":" + vectors[0][2])[0], 200)

    def test_wrong_keys_missing_auth_and_signature_tampering_are_rejected(self):
        for kwargs in ({"auth": None}, {"auth": ""}, {"key": "wrong"}, {"secret": "wrong"},
                       {"auth": "Bearer " + SECRET}, {"signature_path": "/foreign-bucket"}):
            status, _, raw = self.listing(**kwargs)
            self.assertEqual((status, json.loads(raw)["code"]), (403, "signature_not_match"))
        self.assertEqual((self.state.denied, self.state.payload_bytes, self.state.authenticated), (6, 0, 0))
        self.assertEqual(self.state.observed, set())

    def test_date_is_fresh_canonical_utc_and_required(self):
        for date in (None, "", "not-a-date", "\xff", "Mon, 01 Jan 2024 00:00:00 UTC",
                     "Mon, 01 Jan 2024 00:00:00 +0000"):
            self.assertEqual(self.listing(date=date)[0], 403)
        with patch.object(C.time, "time", return_value=1704067200 + 301):
            self.assertEqual(self.listing(date=STAMP)[0], 403)
        with patch.object(C.time, "time", return_value=1704067200 - 301):
            self.assertEqual(self.listing(date=STAMP)[0], 403)
        with patch.object(C.time, "time", return_value=1704067200 + 300):
            self.assertEqual(self.listing(date=STAMP)[0], 200)

    def test_method_and_escaped_path_are_bound_by_signature(self):
        date = email.utils.formatdate(usegmt=True)
        message = ("GET\n\n\n" + date + "\n" + API + "/README-synthetic.txt").encode()
        auth = "QS " + KEY + ":" + base64.b64encode(hmac.new(SECRET.encode(), message, hashlib.sha256).digest()).decode()
        self.assertEqual(self.meta(date=date, auth=auth)[0], 403)
        self.assertEqual(self.meta("nested/space name.txt", signature_path=API + "/nested/space name.txt")[0], 403)
        self.assertEqual(self.meta("nested/space name.txt")[0], 200)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_listing_query_scope_is_checked_separately_from_unsigned_controls(self):
        for extra in ("&marker=next", "&limit=1000", "&prefix=", "&access_key_id=synthetic", "&signature=x"):
            self.assertEqual(self.listing(extra=extra)[0], 400)
        for query in ("delimiter=/&limit=1&prefix=", "delimiter=x&limit=1000&prefix=",
                      "delimiter=/&limit=1000&prefix=foreign/", "delimiter=/&limit=1000",
                      "delimiter=/&limit=1000&prefix=%ff", "delimiter=/&limit=1000&prefix=%GG"):
            self.assertEqual(self.request("GET", API + "?" + query)[0], 400)
        self.assertEqual(self.state.observed, set())

    def test_independent_metadata_and_both_complete_listing_forms(self):
        md5s = {"README-synthetic.txt": "f9ac90560b9929242009ee0c24c9e5d8",
                "nested/bytes.bin": "1576a94d6cb334dd126cb1c27f19e0f2",
                "nested/space name.txt": "371d24ba264bcaac3332a3ed564a93f8"}
        def metadata(name):
            return {"key": name, "size": len(PAYLOADS[name]), "etag": md5s[name],
                    "mime_type": "application/octet-stream", "modified": 1704067200,
                    "created": "2024-01-01T00:00:00Z", "encrypted": False, "storage_class": "STANDARD"}
        for folder, names, prefixes in (("", ["README-synthetic.txt"], ["nested/"]),
                                        ("nested", ["nested/bytes.bin", "nested/space name.txt"], [])):
            status, _, raw = self.listing(folder)
            self.assertEqual((status, json.loads(raw)), (200, {"name": BUCKET, "prefix": folder + "/" if folder else "",
                "delimiter": "/", "limit": 1000, "has_more": False, "keys": [metadata(n) for n in names], "common_prefixes": prefixes}))
        status, _, raw = self.listing(recursive=True)
        self.assertEqual((status, json.loads(raw)), (200, {"name": BUCKET, "prefix": "", "delimiter": "", "limit": 1000,
            "has_more": False, "keys": [metadata(n) for n in sorted(PAYLOADS)], "common_prefixes": []}))
        self.assertEqual(self.state.observed, set(PAYLOADS))
        for name in PAYLOADS:
            status, headers, raw = self.meta(name)
            self.assertEqual((status, headers["Content-Length"], headers["ETag"], headers["Last-Modified"], raw),
                             (200, str(len(PAYLOADS[name])), '"' + md5s[name] + '"', STAMP, b""))
        self.assertEqual(self.state.payload_bytes, 0)

    def test_three_known_byte_reads_require_observed_identity_and_signatures(self):
        self.assertEqual(self.content(observe=False)[0], 400)
        for name, payload in PAYLOADS.items():
            self.assertEqual(self.content(name)[::2], (200, payload))
        self.assertEqual(self.state.payload_bytes, sum(map(len, PAYLOADS.values())))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_native_range_headers_return_bounded_content(self):
        status, headers, raw = self.content("nested/bytes.bin", headers=(("Range", "bytes=256-511"),))
        self.assertEqual((status, headers["Content-Range"], raw), (206, "bytes 256-511/2048", bytes(range(256))))
        for value in ("bytes=0--1", "bytes=-1", "bytes=2048-", "bytes=2-1", "bytes=0-1,3-4"):
            self.assertEqual(self.content("nested/bytes.bin", headers=(("Range", value),))[0], 416)
        self.assertEqual(self.state.files, PAYLOADS)

    def test_missing_objects_and_directory_candidates_return_real_404(self):
        for name in ("nested", "nested/", "absent-synthetic.txt"):
            status, _, raw = self.meta(name)
            self.assertEqual((status, raw), (404, b""))
        status, _, raw = self.content("absent-synthetic.txt", observe=False)
        self.assertEqual((status, json.loads(raw)["code"]), (404, "key_not_exist"))
        status, _, raw = self.listing("absent-synthetic.txt")
        self.assertEqual((status, json.loads(raw)["keys"], json.loads(raw)["has_more"]), (200, [], False))
        self.assertEqual((self.state.missing, self.state.payload_bytes), (5, 0))
        self.assertEqual(self.state.observed, set())

    def test_read_denial_and_direct_signed_guard_preserve_source(self):
        self.assertEqual(self.meta()[0], 200)
        self.state.mode = "read_denied"
        status, _, raw = self.content(observe=False)
        self.assertEqual((status, json.loads(raw)["code"]), (403, "permission_denied"))
        self.state.mode = "normal"
        self.assertEqual(self.request("DELETE", API + "/README-synthetic.txt", secret="wrong")[0], 403)
        self.assertEqual(self.request("DELETE", API + "/README-synthetic.txt")[0], 405)
        self.assertEqual((self.state.read_denied, self.state.rejected_mutations, self.state.payload_bytes), (1, 1, 0))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_host_must_keep_sdk_explicit_port_and_cannot_alias_authority(self):
        for host in (NAME, "127.0.0.1:443", NAME + ".", NAME + ":444", "PEK3A.qingstor.com:443"):
            self.assertEqual(self.listing(host=host)[0], 400)
        self.assertEqual(self.listing()[0], 200)

    def test_date_override_encryption_cookies_and_unsupported_content_headers_are_rejected(self):
        for key, value in (("X-QS-Date", STAMP), ("X-QS-Security-Token", "synthetic"),
                           ("X-QS-Encryption-Customer-Key", "synthetic"), ("Cookie", "token=x"),
                           ("Content-MD5", ""), ("Content-Type", "application/json")):
            self.assertEqual(self.listing(headers=((key, value),))[0], 400)
        self.assertEqual(self.state.authenticated, 0)

    def test_account_mutations_subresources_and_unknown_paths_are_outside_scope(self):
        for method, path in (("GET", "/"), ("GET", "/foreign-bucket"), ("PUT", API),
                             ("POST", API + "?delete"), ("GET", API + "?stats"),
                             ("GET", API + "?uploads"), ("DELETE", API),
                             ("GET", API + "/nested%2Fbytes.bin"), ("GET", API + "/../README-synthetic.txt"),
                             ("GET", "https://elsewhere.invalid/")):
            self.assertEqual(self.request(method, path)[0], 400)
        self.assertEqual((self.state.payload_bytes, self.state.rejected_mutations), (0, 0))

    def test_duplicate_headers_framing_and_metadata_ranges_are_exact(self):
        for headers in ((("Host", NAME + ":443"),), (("Date", STAMP),),
                        (("Authorization", "QS synthetic"),), (("Content-Length", "00"),),
                        (("Content-Length", "4097"),), (("Transfer-Encoding", "chunked"),),
                        (("Range", "bytes=0-1"),)):
            self.assertEqual(self.listing(headers=headers)[0], 400)
        self.assertEqual(self.meta(headers=(("Range", "bytes=0-1"),))[0], 400)
        self.assertEqual(self.listing(raw_body=b"x")[0], 400)
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
            with T.BoundedHttpsServer(certificates, C.QingStorHandler, state=C.QingStorState(KEY, SECRET),
                    limits=T.TlsLimits(request_seconds=0.15)) as transport:
                with socket.create_connection(("127.0.0.1", transport.port), timeout=2) as raw:
                    with certificates.client_context().wrap_socket(raw, server_hostname="127.0.0.1") as client:
                        client.sendall(("GET " + API + " HTTP/1.1\r\nHost: " + NAME + ":443").encode())
                        self.assertEqual(client.recv(1), b"")
            self.assertIn("tls_request_deadline", transport.snapshot()["failure_codes"])
            self.assertTrue(transport.cleanup_complete)
        self.assertTrue(certificates.cleanup_complete)

class QingStorAuthorityTests(unittest.TestCase):
    def test_reviewed_name_has_its_own_exact_sni_and_san(self):
        with tempfile.TemporaryDirectory() as directory:
            with T.FixtureCertificates.create(Path(directory).resolve(), server_name=NAME) as certificates:
                from cryptography import x509
                leaf = x509.load_pem_x509_certificate((certificates.directory / "leaf.pem").read_bytes())
                self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value), [x509.DNSName(NAME)])
        self.assertIsNone(T._qingstor_sni(None, NAME, None))
        for name in (None, "", "fixture.pcloud.com", "api.cloudinary.com", "127.0.0.1", NAME + ".", NAME + ":443"):
            self.assertEqual(T._qingstor_sni(None, name, None), ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)
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
