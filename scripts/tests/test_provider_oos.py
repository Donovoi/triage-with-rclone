"""Independent OCI RSA/signature and bounded bucket-read wire oracles."""
import urllib.parse
import base64
import email.utils
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
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

LAB = Path(__file__).resolve().parents[1] / "provider-lab"
sys.path.insert(0, str(LAB))
try:
    import fixture_oos as C
    import fixture_tls as T
finally:
    sys.path.pop(0)

NAME = "objectstorage.us-ashburn-1.oraclecloud.com"
API = "/n/synthetic-namespace/b/synthetic-bucket/o"
FIELDS = "name,size,etag,timeCreated,md5,timeModified,storageTier,archivalState"
KEY_ID = "ocid1.tenancy.oc1..synthetic/ocid1.user.oc1..synthetic/test-fingerprint"
STAMP = "Mon, 01 Jan 2024 00:00:00 GMT"
PAYLOADS = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
            "nested/bytes.bin": bytes(range(256)) * 8, "nested/space name.txt": b"Nested synthetic payload.\n"}
ORACLES = {'provenance': 'Independent openssl dgst -sha256 -sign on literal messages; generated disposable synthetic RSA-2048 test key; no provider credentials', 'key_id': 'ocid1.tenancy.oc1..synthetic/ocid1.user.oc1..synthetic/test-fingerprint', 'date': 'Mon, 01 Jan 2024 00:00:00 GMT', 'public_key': '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA+uN8jVHn7/s2XT5gnNWl\n7Gfy/hbZj/Sx0wUPgaNmVFLoFIZQW1Z2t35AolBzvS17/KKlhaVJtjWsTx02dk2F\nkbO+4fytgfkL/HEy3o/mwcy4Sc+1/KMnxd0/sckSWIh2Fj6bBR77qy6SLWmagta4\nknijJzaV+P4qr39HYLetOviSgAg5E26GQ3buw7zxfsSDNa4d/gFYsX4Wd9TD6iyQ\nlZqUVnuYZ+8DKXhSaUoF+cOV5m7W1jh8P1SI7A0uDDIUxvObVMd62CDCJ3EndzbZ\n0mF7VKINmJcrr2Zyzb+EjJrXkRhmFuOi4txoIbs1jq/javXqqoirTBbcN5CNGN3P\nyQIDAQAB\n-----END PUBLIC KEY-----\n', 'vectors': [{'method': 'GET', 'target': '/n/synthetic-namespace/b/synthetic-bucket/o?delimiter=%2F&fields=name%2Csize%2Cetag%2CtimeCreated%2Cmd5%2CtimeModified%2CstorageTier%2CarchivalState&limit=1000&prefix=', 'message': 'date: Mon, 01 Jan 2024 00:00:00 GMT\n(request-target): get /n/synthetic-namespace/b/synthetic-bucket/o?delimiter=%2F&fields=name%2Csize%2Cetag%2CtimeCreated%2Cmd5%2CtimeModified%2CstorageTier%2CarchivalState&limit=1000&prefix=\nhost: objectstorage.us-ashburn-1.oraclecloud.com', 'signature': 'owyFupqQfSZPK11tepFJpC8OMPYE/j8DXBG6viVmJ4k1Mu708a/wRva7fZe6d/Yzg4gAgV7qXjpDaKd6QqVmC07xSoQlrS0cJi/zr2jy6xdc+HNIPrazDmYuw2SmIf3YlIA0JMK9lJH/VG/W9Vm9l9J0iTlM4XK7Lvtg4gm5k+Q/mmOp4RiaO6yOwctACmCQtQKOJ1MOZaGDPQrA8JqEokbQGXKvYxtEwIam2UCUcIILgPRh58zc6kIo9arCfLn8kHu18A0n6AlDaAKLNloL4JRXfbGAChr7jTLoWywzvCOgx0ufjzSCJ1QHSq9cUx8E0XFe1/UJaOLEHg5uFVbcIQ=='}, {'method': 'HEAD', 'target': '/n/synthetic-namespace/b/synthetic-bucket/o/README-synthetic.txt', 'message': 'date: Mon, 01 Jan 2024 00:00:00 GMT\n(request-target): head /n/synthetic-namespace/b/synthetic-bucket/o/README-synthetic.txt\nhost: objectstorage.us-ashburn-1.oraclecloud.com', 'signature': 'tOMtlGPU5fFtaZQSgMaDKXNDmlsPKmsv04cMu/BaDAE2c3BzgOD34zhOXQR06+TBoWjU3fSKPmFSrYACnuTEP8Zyq2jwtte9MctjXCmRnHVi4NvqXxbWDRHuA7bKuw9+ZeWBvBxEJLhjULfVFYdK7SfdooYSClvBhmSA2R1iBGN1rhHFNtnRmHKPY9mslKPys3yqjFSJyWP4LaMrGzmvMHRB0L70HSyppCQFoLjDdqpO/5asqLBcK9CKHgR3aHs9Zi4ZLVeiOXDe08MDN2/Rh5UEzGK6AKGuhpaWt9rwsLWvcMEnYIVwo+PnD8Zns6c9KJVzi8K7xTmA3CfXnoMBzA=='}, {'method': 'GET', 'target': '/n/synthetic-namespace/b/synthetic-bucket/o/nested/space%20name.txt', 'message': 'date: Mon, 01 Jan 2024 00:00:00 GMT\n(request-target): get /n/synthetic-namespace/b/synthetic-bucket/o/nested/space%20name.txt\nhost: objectstorage.us-ashburn-1.oraclecloud.com', 'signature': '07D7S9UMboApqIpYEa0bPmc2bM1rq/cqtU9+YMpqFtmaoh/3Ats2M+n7mUW9+dCBpkmZMkeCdtF34qu3zrSV3vlo96k08Udsgh9NAv2QWkf4+bnvq5hJddQtcdgNIiBPCoEjiogUPCJ6/xfzmE8KVvH9GN2UnDqX+hgDEXERX5YbBPCWNE16X1riEn5r15cRB/7F9gVW5GGk7jAK5/VK5ngCbALGRzVuvkgU7ztzpSJ++ArNfR6GVWmVbmP+LqoslaeduU90o5ybeVbvZ/cqg0/7vordHzp5G0givelfkvq0NJ5WcqxmazOYbXg2rSTXWDLZoHMr8ZzrEUbZnma2Ig=='}, {'method': 'DELETE', 'target': '/n/synthetic-namespace/b/synthetic-bucket/o/README-synthetic.txt', 'message': 'date: Mon, 01 Jan 2024 00:00:00 GMT\n(request-target): delete /n/synthetic-namespace/b/synthetic-bucket/o/README-synthetic.txt\nhost: objectstorage.us-ashburn-1.oraclecloud.com', 'signature': 'ToNczNInVIH+BznzgmLkh/z2rpGUoodg6UdjHzmZduRCLRX1QCWdKHLpZcc8PBO52Z0fLHhsRAazn60tdd6kNPwsUinw2grbN1BeM9RhgO6IbW9t/eoNuVi9LwqO2dQ0T97mjtp5hzMJtYDIeETHXJ42kVSyfod5uD2I9oHpPrnT89x6DAmoLLB5CiKFJiRSX0+bfT2IwKwkoYrT99jrKFHS3JOcLktmJ0eUF/XByX9HtJngefPR8auenHtZAYYEBXmj/komHXHcbctGenH8otq3cbNnaVsDZi1R73IIcAEcUav03dT3pXsL9CQplb7SDXERpf71UwuMe43gbS/9RQ=='}]}

class OosWireTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.state = C.OosState(KEY_ID, self.key.public_key())
        self.certificates = self.enterContext(T.FixtureCertificates.create(self.root))
        self.transport = self.enterContext(T.BoundedHttpsServer(self.certificates, C.OosHandler, state=self.state))

    def request(self, method, path, auth="auto", date="now", key_id=KEY_ID, signing_key=None,
                headers=(), raw_body=b"", host=NAME, signature_target=None, signature_host=NAME,
                signature_method=None):
        if date == "now":
            date = email.utils.formatdate(usegmt=True)
        if auth == "auto":
            # Independent message construction; never call the fixture signer.
            message = ("date: " + (date or "") + "\n(request-target): " +
                       (signature_method or method).lower() + " " +
                       (signature_target if signature_target is not None else path) +
                       "\nhost: " + signature_host).encode("utf-8")
            signature = (signing_key or self.key).sign(message, padding.PKCS1v15(), hashes.SHA256())
            auth = ('Signature version="1",headers="date (request-target) host",keyId="' + key_id +
                    '",algorithm="rsa-sha256",signature="' + base64.b64encode(signature).decode() + '"')
        client = http.client.HTTPSConnection("127.0.0.1", self.transport.port, timeout=3,
                                             context=self.certificates.client_context())
        try:
            client.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            client.putheader("Host", host)
            if not any(k.lower() == "content-type" for k,v in headers):
                client.putheader("Content-Type", "application/json")
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
        query = {"fields": FIELDS, "limit": "1000", "prefix": folder + "/" if folder else ""}
        if not recursive:
            query["delimiter"] = "/"
        return self.request("GET", API + "?" + urllib.parse.urlencode(query) + extra, **kwargs)

    def meta(self, name="README-synthetic.txt", **kwargs):
        return self.request("HEAD", API + "/" + urllib.parse.quote(name, safe="/"), **kwargs)

    def content(self, name="README-synthetic.txt", observe=True, **kwargs):
        if observe:
            self.assertEqual(self.meta(name)[0], 200)
        return self.request("GET", API + "/" + urllib.parse.quote(name, safe="/"), **kwargs)

    def test_independent_openssl_rsa_sha256_vectors(self):
        self.state.public_key = serialization.load_pem_public_key(ORACLES["public_key"].encode())
        with patch.object(C.time, "time", return_value=1704067200):
            for vector, status in zip(ORACLES["vectors"], (200, 200, 200, 405), strict=True):
                self.assertEqual(C.signing_string(vector["method"], vector["target"], STAMP).decode(), vector["message"])
                auth = ('Signature version="1",headers="date (request-target) host",keyId="' + KEY_ID +
                        '",algorithm="rsa-sha256",signature="' + vector["signature"] + '"')
                # Root listing observes README; observe nested bytes for the signed GET.
                self.state.observed.add("nested/space name.txt")
                self.assertEqual(self.request(vector["method"], vector["target"], date=STAMP, auth=auth)[0], status)
            self.assertEqual(self.request("HEAD", ORACLES["vectors"][0]["target"], date=STAMP, auth=auth)[0], 400)

    def test_wrong_key_identity_missing_auth_and_signatures_rejected(self):
        wrong = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        for kwargs in ({"auth": None}, {"auth": ""}, {"key_id": "wrong"}, {"signing_key": wrong},
                       {"auth": "Bearer synthetic"}, {"signature_target": "/foreign-bucket"},
                       {"signature_host": NAME + ":443"}):
            status, _, raw = self.listing(**kwargs)
            self.assertEqual((status, json.loads(raw)["code"]), (401, "NotAuthenticated"))
        self.assertEqual((self.state.denied, self.state.payload_bytes, self.state.authenticated), (7, 0, 0))
        self.assertEqual(self.state.observed, set())

    def test_version_algorithm_headers_and_base64_canonicality_are_checked(self):
        date = email.utils.formatdate(usegmt=True)
        path = API + "/README-synthetic.txt"
        auth = C.authorization("HEAD", path, date, KEY_ID, self.key)
        for bad in (auth.replace('version="1"', 'version="2"'),
                    auth.replace('rsa-sha256', 'rsa-sha512'),
                    auth.replace('date (request-target) host', 'date host (request-target)'),
                    auth.replace('Signature ', 'signature '),
                    auth.replace('==', '='),
                    auth + ',keyId="duplicate"'):
            self.assertEqual(self.meta(auth=bad, date=date)[0], 401)
        self.assertEqual(self.meta(auth=auth, date=date)[0], 200)

    def test_date_is_fresh_canonical_utc_and_required(self):
        for date in (None, "", "not-a-date", "\xff", "Mon, 01 Jan 2024 00:00:00 UTC",
                     "Mon, 01 Jan 2024 00:00:00 +0000"):
            self.assertEqual(self.listing(date=date)[0], 401)
        for delta, status in ((301, 401), (-301, 401), (300, 200), (-300, 200)):
            with patch.object(C.time, "time", return_value=1704067200 + delta):
                self.assertEqual(self.listing(date=STAMP)[0], status)

    def test_method_escaped_path_and_raw_query_order_are_signed(self):
        self.assertEqual(self.meta(signature_method="GET")[0], 401)
        self.assertEqual(self.meta("nested/space name.txt", signature_target=API + "/nested/space name.txt")[0], 401)
        self.assertEqual(self.meta("nested/space name.txt")[0], 200)
        query = urllib.parse.urlencode({"fields": FIELDS, "limit": "1000", "prefix": "", "delimiter": "/"})
        target = API + "?" + query
        reordered = API + "?" + "&".join(reversed(query.split("&")))
        self.assertEqual(self.request("GET", reordered, signature_target=target)[0], 401)
        self.assertEqual(self.request("GET", reordered)[0], 200)
        self.assertEqual(self.listing(signature_target=API)[0], 401)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_listing_fields_scope_pagination_and_duplicate_controls(self):
        for extra in ("&start=next", "&limit=1000", "&prefix=", "&namespaceName=foreign", "&versionId=x"):
            self.assertEqual(self.listing(extra=extra)[0], 400)
        base = {"fields": FIELDS, "limit": "1000", "prefix": "", "delimiter": "/"}
        for replacement in ({"limit": "1"}, {"delimiter": ""}, {"delimiter": "x"}, {"prefix": "foreign/"},
                            {"fields": "name,size"}, {"prefix": "\ufffd"}):
            self.assertEqual(self.request("GET", API + "?" + urllib.parse.urlencode(base | replacement))[0], 400)
        for query in ("fields=name&limit=1000", "fields=%ff&limit=1000&prefix=", "fields=%GG&limit=1000&prefix="):
            self.assertEqual(self.request("GET", API + "?" + query)[0], 400)
        self.assertEqual(self.state.observed, set())

    def test_independent_metadata_and_complete_recursive_and_delimited_lists(self):
        md5s = {"README-synthetic.txt": "f9ac90560b9929242009ee0c24c9e5d8",
                "nested/bytes.bin": "1576a94d6cb334dd126cb1c27f19e0f2",
                "nested/space name.txt": "371d24ba264bcaac3332a3ed564a93f8"}
        def metadata(name):
            return {"name": name, "size": len(PAYLOADS[name]), "etag": "synthetic-etag-" + str(sorted(PAYLOADS).index(name) + 1),
                    "md5": base64.b64encode(bytes.fromhex(md5s[name])).decode(),
                    "timeCreated": "2024-01-01T00:00:00Z", "timeModified": "2024-01-01T00:00:00Z", "storageTier": "Standard"}
        for folder, names, prefixes in (("", ["README-synthetic.txt"], ["nested/"]),
                                        ("nested", ["nested/bytes.bin", "nested/space name.txt"], [])):
            status, _, raw = self.listing(folder)
            self.assertEqual((status, json.loads(raw)), (200, {"objects": [metadata(n) for n in names], "prefixes": prefixes}))
        status, _, raw = self.listing(recursive=True)
        self.assertEqual((status, json.loads(raw)), (200, {"objects": [metadata(n) for n in sorted(PAYLOADS)], "prefixes": []}))
        self.assertEqual(self.state.observed, set(PAYLOADS))
        for name in PAYLOADS:
            status, headers, raw = self.meta(name)
            self.assertEqual((status, headers["Content-Length"], headers["ETag"], headers["Last-Modified"],
                              headers["Content-MD5"], headers["storage-tier"], raw),
                             (200, str(len(PAYLOADS[name])), '"' + metadata(name)["etag"] + '"', STAMP,
                              metadata(name)["md5"], "Standard", b""))
        self.assertEqual(self.state.payload_bytes, 0)

    def test_three_known_byte_reads_require_observed_identity(self):
        self.assertEqual(self.content(observe=False)[0], 400)
        for name, payload in PAYLOADS.items():
            self.assertEqual(self.content(name)[::2], (200, payload))
        self.assertEqual(self.state.payload_bytes, sum(map(len, PAYLOADS.values())))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_range_headers_return_bounded_content(self):
        status, headers, raw = self.content("nested/bytes.bin", headers=(("Range", "bytes=256-511"),))
        self.assertEqual((status, headers["Content-Range"], raw), (206, "bytes 256-511/2048", bytes(range(256))))
        for value in ("bytes=0--1", "bytes=-1", "bytes=2048-", "bytes=2-1", "bytes=0-1,3-4"):
            self.assertEqual(self.content("nested/bytes.bin", headers=(("Range", value),))[0], 416)
        self.assertEqual(self.state.files, PAYLOADS)

    def test_missing_object_and_directory_candidates_return_real_404(self):
        for name in ("nested", "nested/", "absent-synthetic.txt"):
            self.assertEqual(self.meta(name)[::2], (404, b""))
        status, _, raw = self.content("absent-synthetic.txt", observe=False)
        self.assertEqual((status, json.loads(raw)["code"]), (404, "ObjectNotFound"))
        status, _, raw = self.listing("absent-synthetic.txt")
        self.assertEqual((status, json.loads(raw)), (200, {"objects": [], "prefixes": []}))
        self.assertEqual((self.state.missing, self.state.payload_bytes), (5, 0))
        self.assertEqual(self.state.observed, set())

    def test_read_denial_and_direct_signed_write_guard_preserve_source(self):
        self.assertEqual(self.meta()[0], 200)
        self.state.mode = "read_denied"
        status, _, raw = self.content(observe=False)
        self.assertEqual((status, json.loads(raw)["code"]), (403, "NotAuthorized"))
        self.state.mode = "normal"
        self.assertEqual(self.request("DELETE", API + "/README-synthetic.txt", key_id="wrong")[0], 401)
        self.assertEqual(self.request("DELETE", API + "/README-synthetic.txt")[0], 405)
        self.assertEqual((self.state.read_denied, self.state.rejected_mutations, self.state.payload_bytes), (1, 1, 0))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_default_authority_has_no_port_or_alternate_region_alias(self):
        for host in (NAME + ":443", "127.0.0.1:443", NAME + ".", NAME + ":444", NAME.upper(),
                     "objectstorage.us-phoenix-1.oraclecloud.com"):
            self.assertEqual(self.listing(host=host)[0], 400)
        self.assertEqual(self.listing()[0], 200)

    def test_override_encryption_impersonation_cookies_and_content_headers_are_rejected(self):
        for key, value in (("X-Date", STAMP), ("opc-obo-token", "synthetic"),
                           ("opc-sse-customer-key", "synthetic"), ("Cookie", "token=x"),
                           ("Content-MD5", ""), ("Content-Type", "application/octet-stream"), ("If-Match", "x"),
                           ("X-Content-SHA256", "x")):
            self.assertEqual(self.listing(headers=((key, value),))[0], 400)
        self.assertEqual(self.state.authenticated, 0)

    def test_account_mutations_foreign_namespace_bucket_and_unknown_paths_are_outside_scope(self):
        for method, path in (("GET", "/"), ("GET", "/n/synthetic-namespace/b"), ("PUT", API),
                             ("POST", API + "?delete"), ("GET", API + "?stats"), ("DELETE", API),
                             ("GET", API + "/nested%2Fbytes.bin"), ("GET", API + "/../README-synthetic.txt"),
                             ("GET", API + "/"), ("GET", API.replace("synthetic-namespace", "foreign")),
                             ("GET", API.replace("synthetic-bucket", "foreign")), ("GET", "https://elsewhere.invalid/")):
            self.assertEqual(self.request(method, path)[0], 400)
        self.assertEqual((self.state.payload_bytes, self.state.rejected_mutations), (0, 0))

    def test_duplicate_headers_framing_and_metadata_ranges_are_exact(self):
        for headers in ((("Host", NAME),), (("Date", STAMP),), (("Authorization", "Signature synthetic"),),
                        (("Content-Length", "00"),), (("Content-Length", "4097"),),
                        (("Transfer-Encoding", "chunked"),), (("Range", "bytes=0-1"),)):
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
            with T.BoundedHttpsServer(certificates, C.OosHandler, state=C.OosState(KEY_ID, self.key.public_key()),
                    limits=T.TlsLimits(request_seconds=0.15)) as transport:
                with socket.create_connection(("127.0.0.1", transport.port), timeout=2) as raw:
                    with certificates.client_context().wrap_socket(raw, server_hostname="127.0.0.1") as client:
                        client.sendall(("GET " + API + " HTTP/1.1\r\nHost: " + NAME).encode())
                        self.assertEqual(client.recv(1), b"")
            self.assertIn("tls_request_deadline", transport.snapshot()["failure_codes"])
            self.assertTrue(transport.cleanup_complete)
        self.assertTrue(certificates.cleanup_complete)

class OosAuthorityTests(unittest.TestCase):
    def test_reviewed_name_has_its_own_exact_sni_and_san(self):
        with tempfile.TemporaryDirectory() as directory:
            with T.FixtureCertificates.create(Path(directory).resolve(), server_name=NAME) as certificates:
                from cryptography import x509
                leaf = x509.load_pem_x509_certificate((certificates.directory / "leaf.pem").read_bytes())
                self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value), [x509.DNSName(NAME)])
        self.assertIsNone(T._oos_sni(None, NAME, None))
        for name in (None, "", "fixture.pcloud.com", "api.cloudinary.com", "127.0.0.1", NAME + ".", NAME + ":443"):
            self.assertEqual(T._oos_sni(None, name, None), ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)
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
