"""Independent SharedKey/XML subset tests. Never execute rclone or the app."""

import base64
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import hashlib
import hmac
import http.client
from pathlib import Path
import socket
import sys
import threading
import time
import unittest
import urllib.parse
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).parents[1] / "provider-lab"))
try:
    import fixture_servers as FIXTURES
finally:
    sys.path.pop(0)

KEY = bytes(range(32))
KEY64 = base64.b64encode(KEY).decode()
NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
BASE = "/syntheticaccount/synthetic-container"
README = BASE + "/README-synthetic.txt"
LIST = BASE + "?restype=container&comp=list&include=metadata"
EXPECTED = {
    "README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
    "nested/space name.txt": b"Nested synthetic payload.\n",
    "nested/bytes.bin": bytes(range(256)) * 8,
}


# Independently written literal canonical fields and precomputed HMACs.
# https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key
SIGNING_VECTORS = [{'name': 'encoded_nested_space',
  'method': 'GET',
  'target': '/syntheticaccount/synthetic-container/nested%2Fspace%20name.txt',
  'headers': [['X-Ms-Version', '2026-06-06'], ['x-ms-date', 'Mon, 01 Jan 2024 00:00:00 GMT']],
  'canonical': 'GET\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               'x-ms-date:Mon, 01 Jan 2024 00:00:00 GMT\n'
               'x-ms-version:2026-06-06\n'
               '/syntheticaccount/syntheticaccount/synthetic-container/nested%2Fspace%20name.txt',
  'signature': 'A7hKf/0pneCLJJYtcr1d6QgMF+1P/XjKmq/cUokNkUk='},
 {'name': 'sorted_query_and_headers',
  'method': 'GET',
  'target': '/syntheticaccount/synthetic-container?restype=container&prefix=nested%2Fspace%20&maxresults=5&include=metadata&delimiter=%2F&comp=list',
  'headers': [['x-ms-version', '2026-06-06'],
              ['X-Ms-Date', 'Mon, 01 Jan 2024 00:00:00 GMT'],
              ['x-ms-client-request-id', 'fixed-synthetic-id']],
  'canonical': 'GET\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               'x-ms-client-request-id:fixed-synthetic-id\n'
               'x-ms-date:Mon, 01 Jan 2024 00:00:00 GMT\n'
               'x-ms-version:2026-06-06\n'
               '/syntheticaccount/syntheticaccount/synthetic-container\n'
               'comp:list\n'
               'delimiter:/\n'
               'include:metadata\n'
               'maxresults:5\n'
               'prefix:nested/space \n'
               'restype:container',
  'signature': 'uL/Ff/x4X1cKKVUOV12fBLMrvq66M2lAvfgkRwGUIXM='},
 {'name': 'zero_content_length_head',
  'method': 'HEAD',
  'target': '/syntheticaccount/synthetic-container/README-synthetic.txt',
  'headers': [['Content-Length', '0'],
              ['x-ms-date', 'Mon, 01 Jan 2024 00:00:00 GMT'],
              ['x-ms-version', '2026-06-06']],
  'canonical': 'HEAD\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               'x-ms-date:Mon, 01 Jan 2024 00:00:00 GMT\n'
               'x-ms-version:2026-06-06\n'
               '/syntheticaccount/syntheticaccount/synthetic-container/README-synthetic.txt',
  'signature': 'kb49A1OJ8InGaGG8VJSK++CIz1RYf8iB4uidY0byl/8='},
 {'name': 'sdk_range_and_if_match',
  'method': 'GET',
  'target': '/syntheticaccount/synthetic-container/nested%2Fbytes.bin',
  'headers': [['x-ms-range', 'bytes=3-7'],
              ['If-Match', '*'],
              ['x-ms-version', '2026-06-06'],
              ['x-ms-date', 'Mon, 01 Jan 2024 00:00:00 GMT']],
  'canonical': 'GET\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '*\n'
               '\n'
               '\n'
               '\n'
               'x-ms-date:Mon, 01 Jan 2024 00:00:00 GMT\n'
               'x-ms-range:bytes=3-7\n'
               'x-ms-version:2026-06-06\n'
               '/syntheticaccount/syntheticaccount/synthetic-container/nested%2Fbytes.bin',
  'signature': '6/PjdIiKRS/JiObNM6pPqGR0TaeFV0wMj4SyLebsOG0='},
 {'name': 'signed_901_second_old',
  'method': 'GET',
  'target': '/syntheticaccount/synthetic-container/README-synthetic.txt',
  'headers': [['x-ms-date', 'Sun, 31 Dec 2023 23:44:59 GMT'], ['x-ms-version', '2026-06-06']],
  'canonical': 'GET\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               'x-ms-date:Sun, 31 Dec 2023 23:44:59 GMT\n'
               'x-ms-version:2026-06-06\n'
               '/syntheticaccount/syntheticaccount/synthetic-container/README-synthetic.txt',
  'signature': 'POIF5Vaw18noaeWfk619asvsIxQq/+MIpY9TyPjb94w='},
 {'name': 'signed_900_second_boundary',
  'method': 'GET',
  'target': '/syntheticaccount/synthetic-container/README-synthetic.txt',
  'headers': [['x-ms-date', 'Sun, 31 Dec 2023 23:45:00 GMT'], ['x-ms-version', '2026-06-06']],
  'canonical': 'GET\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               '\n'
               'x-ms-date:Sun, 31 Dec 2023 23:45:00 GMT\n'
               'x-ms-version:2026-06-06\n'
               '/syntheticaccount/syntheticaccount/synthetic-container/README-synthetic.txt',
  'signature': '0ACy/n8c/t+ZtF2IySqsN0inm7aUjxAb7zvzfLVi+Ss='}]

def independent_sign(method, target, headers, key=KEY):
    # Deliberately does not call the fixture's canonicalizer. Literal external
    # vectors below additionally pin canonical text and known HMAC outputs.
    values = {name.lower(): value for name, value in headers.items()}
    url = urllib.parse.urlparse(target)
    query = urllib.parse.parse_qs(url.query, keep_blank_values=True)
    length = values.get("content-length", "")
    standard = [method, values.get("content-encoding", ""), values.get("content-language", ""),
                "" if length == "0" else length, values.get("content-md5", ""), values.get("content-type", ""), "",
                values.get("if-modified-since", ""), values.get("if-match", ""), values.get("if-none-match", ""),
                values.get("if-unmodified-since", ""), values.get("range", "")]
    ms = "\n".join(name + ":" + values[name] for name in sorted(values) if name.startswith("x-ms-"))
    resource = "/syntheticaccount" + url.path
    for name in sorted(query):
        resource += "\n" + name.lower() + ":" + ",".join(sorted(query[name]))
    canonical = "\n".join(standard + [ms, resource])
    return "SharedKey syntheticaccount:" + base64.b64encode(hmac.new(key, canonical.encode(), hashlib.sha256).digest()).decode()


class AzureBlobServerTests(unittest.TestCase):
    def test_independent_fixed_canonical_and_hmac_vectors(self):
        for vector in SIGNING_VECTORS:
            with self.subTest(vector=vector["name"]):
                actual = FIXTURES.azure_string_to_sign("syntheticaccount", vector["method"], vector["target"], vector["headers"])
                self.assertEqual(actual, vector["canonical"])
                signature = base64.b64encode(hmac.new(KEY, actual.encode(), hashlib.sha256).digest()).decode()
                self.assertEqual(signature, vector["signature"])
                self.assertEqual(independent_sign(vector["method"], vector["target"], dict(vector["headers"])),
                                 "SharedKey syntheticaccount:" + vector["signature"])

    def test_fixed_stale_and_boundary_signatures_are_valid_but_only_fresh_is_served(self):
        state = FIXTURES.AzureBlobState(KEY64, utc_now=lambda: datetime(2024, 1, 1, tzinfo=timezone.utc))
        with FIXTURES.serve("azureblob", state) as self.port:
            self.state = state
            for vector in SIGNING_VECTORS[-2:]:
                headers = dict(vector["headers"])
                headers["Authorization"] = "SharedKey syntheticaccount:" + vector["signature"]
                response = self.request(vector["method"], vector["target"], headers)
                if vector["name"] == "signed_901_second_old":
                    self.assert_error(response, 403, "AuthenticationFailed")
                    self.assertEqual(state.payload_bytes, 0)
                else:
                    self.assertEqual(response[0], 200)
                    self.assertEqual(response[2], EXPECTED["README-synthetic.txt"])
        self.assertEqual(state.stale_denied, 1)
        self.assertTrue(state.cleanup_complete)

    def start(self):
        self.state = FIXTURES.AzureBlobState(KEY64, utc_now=lambda: NOW)
        self.port = self.enterContext(FIXTURES.serve("azureblob", self.state))

    def signed_headers(self, method, target, date=NOW, key=KEY, extra=None):
        headers = {"x-ms-date": format_datetime(date, usegmt=True), "x-ms-version": "2026-06-06"}
        headers.update(extra or {})
        headers["Authorization"] = independent_sign(method, target, headers, key)
        return headers

    def request(self, method, target, headers=None, body=None, extra=(), host=True):
        client = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            client.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
            if host:
                client.putheader("Host", f"127.0.0.1:{self.port}")
            for name, value in (headers or self.signed_headers(method, target)).items():
                client.putheader(name, value)
            for name, value in extra:
                client.putheader(name, value)
            client.endheaders(body)
            response = client.getresponse()
            return response.status, dict(response.getheaders()), response.read(16385)
        finally:
            client.close()

    def assert_error(self, response, status, error_code=None):
        code, headers, body = response
        self.assertEqual(code, status)
        self.assertLess(len(body), 512)
        self.assertNotIn("Location", headers)
        if error_code:
            self.assertEqual(headers["x-ms-error-code"], error_code)
        if body:
            self.assertEqual(ET.fromstring(body).tag, "Error")
        for payload in EXPECTED.values():
            self.assertNotIn(payload, body)
        self.assertNotIn(KEY64.encode(), body)

    def test_valid_signature_reads_exact_file_while_wrong_valid_key_is_denied(self):
        self.start()
        wrong = bytes(value ^ 1 for value in KEY)
        self.assertEqual(len(base64.b64decode(base64.b64encode(wrong), validate=True)), 32)
        self.assert_error(self.request("GET", README, self.signed_headers("GET", README, key=wrong)), 403, "AuthenticationFailed")
        self.assertEqual((self.state.auth_denied, self.state.authenticated, self.state.payload_bytes), (1, 0, 0))
        code, _, body = self.request("GET", README)
        self.assertEqual((code, body), (200, EXPECTED["README-synthetic.txt"]))

    def test_correct_signatures_observe_freshness_boundary_and_future_constraint(self):
        self.start()
        for seconds, status in ((0, 200), (900, 200), (901, 403), (-1, 403)):
            with self.subTest(age=seconds):
                headers = self.signed_headers("GET", README, date=NOW - timedelta(seconds=seconds))
                response = self.request("GET", README, headers)
                self.assertEqual(response[0], status)
                if status == 403:
                    self.assert_error(response, status, "AuthenticationFailed")
        self.assertEqual((self.state.auth_denied, self.state.stale_denied), (2, 2))
        self.assertEqual(self.state.payload_bytes, 2 * len(EXPECTED["README-synthetic.txt"]))

    def test_missing_malformed_nonutc_and_duplicate_dates_fail_closed(self):
        self.start()
        for date in (None, "not a date", "Fri, 02 Jan 2026 03:04:05 +0000", "Fri, 02 Jan 2026 03:04:05 UTC",
                     "Fri, 02 Jan 2026 04:04:05 +0100"):
            headers = {"x-ms-version": "2026-06-06"}
            if date:
                headers["x-ms-date"] = date
            headers["Authorization"] = independent_sign("GET", README, headers)
            self.assert_error(self.request("GET", README, headers), 403, "AuthenticationFailed")
        self.assert_error(self.request("GET", README, extra=(("X-Ms-Date", format_datetime(NOW, usegmt=True)),)), 400)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_missing_version_and_invalid_signature_or_duplicate_auth_are_denied(self):
        self.start()
        headers = self.signed_headers("GET", README)
        headers.pop("x-ms-version")
        headers["Authorization"] = independent_sign("GET", README, headers)
        self.assert_error(self.request("GET", README, headers), 403)
        headers = self.signed_headers("GET", README)
        headers["Authorization"] += "changed"
        self.assert_error(self.request("GET", README, headers), 403)
        self.assert_error(self.request("GET", README, extra=(("Authorization", "synthetic duplicate"),)), 400)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_escaped_nested_names_sign_raw_path_and_decode_once_for_lookup(self):
        self.start()
        target = BASE + "/nested%2Fspace%20name.txt"
        response = self.request("GET", target)
        self.assertEqual((response[0], response[2]), (200, EXPECTED["nested/space name.txt"]))
        headers = self.signed_headers("GET", target)
        headers["Authorization"] = independent_sign("GET", urllib.parse.unquote(target), headers)
        self.assert_error(self.request("GET", target, headers), 403)
        self.assert_error(self.request("GET", BASE + "/nested%252Fspace%20name.txt"), 400)

    def test_xml_inventory_and_head_metadata_match_independent_md5_size_and_sha256(self):
        self.start()
        code, _, body = self.request("GET", LIST)
        self.assertEqual(code, 200)
        root = ET.fromstring(body)
        rows = root.findall("Blobs/Blob")
        self.assertEqual({row.findtext("Name") for row in rows}, set(EXPECTED))
        self.assertIsNone(root.findtext("NextMarker") or None)
        for row in rows:
            name = row.findtext("Name")
            expected = EXPECTED[name]
            self.assertEqual(int(row.findtext("Properties/Content-Length")), len(expected))
            self.assertEqual(base64.b64decode(row.findtext("Properties/Content-MD5")), hashlib.md5(expected).digest())
            self.assertEqual(row.findtext("Properties/BlobType"), "BlockBlob")
            target = BASE + "/" + urllib.parse.quote(name, safe="")
            code, headers, body = self.request("HEAD", target)
            self.assertEqual((code, body), (200, b""))
            self.assertEqual(int(headers["Content-Length"]), len(expected))
            self.assertEqual(base64.b64decode(headers["Content-MD5"]), hashlib.md5(expected).digest())
            code, _, body = self.request("GET", target)
            self.assertEqual(code, 200)
            self.assertEqual(hashlib.sha256(body).digest(), hashlib.sha256(expected).digest())

    def test_paging_is_complete_or_explicitly_unsupported_never_truncated(self):
        self.start()
        for query, status, names in (
                ("maxresults=2", 400, set()),
                ("maxresults=3", 200, set(EXPECTED)),
                ("delimiter=%2F&maxresults=1", 400, set()),
                ("delimiter=%2F&maxresults=2", 200, {"README-synthetic.txt", "nested/"}),
                ("prefix=nested%2F&maxresults=2", 200, {"nested/bytes.bin", "nested/space name.txt"}),
                ("prefix=nested%2Fspace&maxresults=1", 200, {"nested/space name.txt"}),
                ("marker=next&maxresults=5000", 400, set()),
                ("marker=&maxresults=3", 200, set(EXPECTED))):
            with self.subTest(query=query):
                response = self.request("GET", LIST + "&" + query)
                self.assertEqual(response[0], status)
                root = ET.fromstring(response[2])
                actual = {entry.findtext("Name") for entry in root.findall("Blobs/*")}
                self.assertEqual(actual, names)
                if status == 200:
                    self.assertFalse(root.findtext("NextMarker"))
                else:
                    self.assertEqual(root.tag, "Error")

    def test_listing_rejects_duplicate_unknown_and_out_of_range_options(self):
        self.start()
        for query in ("maxresults=0", "maxresults=5001", "maxresults=x", "maxresults=2&maxresults=3",
                      "delimiter=x", "snapshot=other", "marker=next", "prefix=..%2F", "include=tags"):
            self.assert_error(self.request("GET", LIST + "&" + query), 400)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_missing_member_and_directory_have_no_file_bytes(self):
        self.start()
        for name in ("absent", "nested"):
            for method in ("HEAD", "GET"):
                self.assert_error(self.request(method, BASE + "/" + name), 404, "BlobNotFound")
        self.assertEqual(self.state.missing, 4)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_authenticated_mutations_are_rejected_and_source_remains_exact(self):
        self.start()
        before = dict(self.state.files)
        for method in ("PUT", "DELETE", "POST"):
            target = BASE + "/must-not-be-created.txt"
            headers = self.signed_headers(method, target, extra={"Content-Length": "0"})
            self.assert_error(self.request(method, target, headers, body=b""), 403, "AuthorizationPermissionMismatch")
        self.assertEqual(self.state.rejected_mutations, 3)
        self.assertEqual(self.state.files, before)
        self.assertEqual(self.state.auth_denied, 0)

    def test_signed_azure_range_returns_exact_partial_md5_and_full_blob_md5(self):
        self.start()
        headers = self.signed_headers("GET", README, extra={"x-ms-range": "bytes=2-5"})
        code, response_headers, body = self.request("GET", README, headers)
        expected = EXPECTED["README-synthetic.txt"]
        self.assertEqual((code, body), (206, expected[2:6]))
        self.assertEqual(response_headers["Content-Range"], f"bytes 2-5/{len(expected)}")
        self.assertEqual(base64.b64decode(response_headers["Content-MD5"]), hashlib.md5(expected[2:6]).digest())
        self.assertEqual(base64.b64decode(response_headers["x-ms-blob-content-md5"]), hashlib.md5(expected).digest())
        headers["x-ms-range"] = "bytes=2-6"
        self.assert_error(self.request("GET", README, headers), 403, "AuthenticationFailed")

    def test_invalid_duplicate_conflicting_or_head_ranges_are_rejected(self):
        self.start()
        for value in ("bytes=0-9999", "bytes=-2", "bytes=4-1", "bytes=0-1,3-4"):
            headers = self.signed_headers("GET", README, extra={"x-ms-range": value})
            self.assert_error(self.request("GET", README, headers), 400)
        headers = self.signed_headers("GET", README, extra={"x-ms-range": "bytes=0-1", "Range": "bytes=0-1"})
        self.assert_error(self.request("GET", README, headers), 400)
        headers = self.signed_headers("HEAD", README, extra={"x-ms-range": "bytes=0-1"})
        self.assert_error(self.request("HEAD", README, headers), 400)
        self.assert_error(self.request("GET", README, extra=(("x-ms-range", "bytes=0-1"), ("X-Ms-Range", "bytes=0-1"))), 400)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_owned_route_host_and_request_framing_are_enforced(self):
        self.start()
        for path in ("/syntheticaccount?comp=list", "/other/synthetic-container/README-synthetic.txt",
                     "/syntheticaccount/other/README-synthetic.txt", BASE + "/%2e%2e/README-synthetic.txt",
                     BASE + "/", BASE + "/nested//bytes.bin", BASE + "/nested%5cbytes.bin"):
            self.assert_error(self.request("GET", path), 400)
        self.assert_error(self.request("GET", README, host=False), 400)
        for extra in ((("Host", "example.invalid"),), (("Transfer-Encoding", "chunked"),),
                      (("Content-Length", "0"), ("Content-Length", "0"))):
            self.assert_error(self.request("GET", README, extra=extra), 400)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_signature_does_not_normalize_malformed_raw_targets(self):
        headers = self.signed_headers("GET", README)
        for target in ("\x01" + README, " " + README, README + "\t", README + "\r\n", README + "%XX", "//foreign/path"):
            with self.subTest(target=repr(target)):
                with self.assertRaises(ValueError):
                    FIXTURES.azure_string_to_sign("syntheticaccount", "GET", target, headers.items())

    def test_budget_and_deadline_reject_before_authorized_payload(self):
        self.start()
        self.state.request_limit = 0
        self.assert_error(self.request("GET", README), 429)
        self.assertTrue(self.state.budget_exceeded)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_slow_request_headers_are_absolutely_bounded_and_threads_close(self):
        state = FIXTURES.AzureBlobState(KEY64, utc_now=lambda: NOW)
        state.request_timeout = 0.2
        with FIXTURES.serve("azureblob", state) as port:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
                client.sendall(b"GET / HTTP/1.1\r\nX-Slow: ")
                stop = threading.Event()

                def feed():
                    for _ in range(40):
                        if stop.wait(0.025):
                            return
                        try:
                            client.sendall(b"x")
                        except OSError:
                            return

                thread = threading.Thread(target=feed)
                thread.start()
                began = time.monotonic()
                try:
                    try:
                        self.assertEqual(client.recv(1024), b"")
                    except (ConnectionResetError, ConnectionAbortedError):
                        pass
                    self.assertLess(time.monotonic() - began, 1.5)
                finally:
                    stop.set()
                    thread.join(2)
                self.assertFalse(thread.is_alive())
        self.assertTrue(state.budget_exceeded)
        self.assertTrue(state.cleanup_complete)
        self.assertFalse(state.sockets)
        self.assertEqual(state.payload_bytes, 0)
        with socket.socket() as probe:
            self.assertNotEqual(probe.connect_ex(("127.0.0.1", port)), 0)


if __name__ == "__main__":
    unittest.main()
