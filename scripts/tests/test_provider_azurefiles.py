"""Independent FileREST SharedKey tests; no native executable or cloud account."""

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
NOW = datetime(2024, 1, 1, tzinfo=timezone.utc)
BASE = "/syntheticaccount/synthetic-share"
ROOT = BASE + "/"
README = ROOT + "README-synthetic.txt"
LIST = ROOT + "?comp=list&include=Timestamps&restype=directory"
EXPECTED = {
    "README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
    "nested/space name.txt": b"Nested synthetic payload.\n",
    "nested/bytes.bin": bytes(range(256)) * 8,
}


# Separate literal FileREST signing oracle; no fixture or SDK import generated it.
# https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key
SIGNING_VECTORS = [{'name': 'root_directory_get_properties',
  'method': 'GET',
  'target': '/syntheticaccount/synthetic-share/?restype=directory',
  'headers': [['x-ms-version', '2026-06-06'],
              ['x-ms-file-request-intent', 'backup'],
              ['x-ms-date', 'Mon, 01 Jan 2024 00:00:00 GMT']],
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
               'x-ms-file-request-intent:backup\n'
               'x-ms-version:2026-06-06\n'
               '/syntheticaccount/syntheticaccount/synthetic-share/\n'
               'restype:directory',
  'signature': 'ywrFzbs2YMC+h0OG8Zz+c+6vU5YgKI6a3hLLRXdR20U='},
 {'name': 'directory_listing_sorted_query',
  'method': 'GET',
  'target': '/syntheticaccount/synthetic-share/nested?restype=directory&prefix=space%20&maxresults=5&include=Timestamps&comp=list',
  'headers': [['x-ms-client-request-id', 'fixed-synthetic-id'],
              ['x-ms-version', '2026-06-06'],
              ['x-ms-file-request-intent', 'backup'],
              ['x-ms-date', 'Mon, 01 Jan 2024 00:00:00 GMT']],
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
               'x-ms-file-request-intent:backup\n'
               'x-ms-version:2026-06-06\n'
               '/syntheticaccount/syntheticaccount/synthetic-share/nested\n'
               'comp:list\n'
               'include:Timestamps\n'
               'maxresults:5\n'
               'prefix:space \n'
               'restype:directory',
  'signature': '7vIDw5fDU48YJYRcJR3hSMmXrHPO2wvCELILX7stpsg='},
 {'name': 'file_head_zero_length_encoded_name',
  'method': 'HEAD',
  'target': '/syntheticaccount/synthetic-share/nested%2Fspace%20name.txt',
  'headers': [['Content-Length', '0'],
              ['x-ms-version', '2026-06-06'],
              ['x-ms-file-request-intent', 'backup'],
              ['x-ms-date', 'Mon, 01 Jan 2024 00:00:00 GMT']],
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
               'x-ms-file-request-intent:backup\n'
               'x-ms-version:2026-06-06\n'
               '/syntheticaccount/syntheticaccount/synthetic-share/nested%2Fspace%20name.txt',
  'signature': 'IWTRZHJnUA3BuWqIl3mw9RjexsH9SQT+7X0ReVjPTCs='},
 {'name': 'file_get_signed_range',
  'method': 'GET',
  'target': '/syntheticaccount/synthetic-share/nested%2Fbytes.bin',
  'headers': [['x-ms-range', 'bytes=3-7'],
              ['x-ms-version', '2026-06-06'],
              ['x-ms-file-request-intent', 'backup'],
              ['x-ms-date', 'Mon, 01 Jan 2024 00:00:00 GMT']],
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
               'x-ms-file-request-intent:backup\n'
               'x-ms-range:bytes=3-7\n'
               'x-ms-version:2026-06-06\n'
               '/syntheticaccount/syntheticaccount/synthetic-share/nested%2Fbytes.bin',
  'signature': 'K8NPKG3uvPjWTrJx9+mH6pF120q8jgRHPLRKD+09Ys4='},
 {'name': 'signed_901_second_old',
  'method': 'GET',
  'target': '/syntheticaccount/synthetic-share/README-synthetic.txt',
  'headers': [['x-ms-date', 'Sun, 31 Dec 2023 23:44:59 GMT'],
              ['x-ms-file-request-intent', 'backup'],
              ['x-ms-version', '2026-06-06']],
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
               'x-ms-file-request-intent:backup\n'
               'x-ms-version:2026-06-06\n'
               '/syntheticaccount/syntheticaccount/synthetic-share/README-synthetic.txt',
  'signature': 'kFsCi06dh4LsqJJs/hdaozDUieJyOrNL+Su1UKJQwAE='},
 {'name': 'signed_900_second_boundary',
  'method': 'GET',
  'target': '/syntheticaccount/synthetic-share/README-synthetic.txt',
  'headers': [['x-ms-date', 'Sun, 31 Dec 2023 23:45:00 GMT'],
              ['x-ms-file-request-intent', 'backup'],
              ['x-ms-version', '2026-06-06']],
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
               'x-ms-file-request-intent:backup\n'
               'x-ms-version:2026-06-06\n'
               '/syntheticaccount/syntheticaccount/synthetic-share/README-synthetic.txt',
  'signature': 'JDTs71cMqFfX1QuKG+bGG+fdwM7su8oyGhGZlRdPfJk='}]

def independent_sign(method, target, headers, key=KEY):
    # No call to the fixture signer: literal external vectors below independently
    # pin this test-side construction and the production canonicalizer.
    values = {name.lower(): value for name, value in headers.items()}
    url = urllib.parse.urlparse(target)
    query = urllib.parse.parse_qs(url.query, keep_blank_values=True)
    length = values.get("content-length", "")
    fields = [method, values.get("content-encoding", ""), values.get("content-language", ""),
              "" if length == "0" else length, values.get("content-md5", ""), values.get("content-type", ""), "",
              values.get("if-modified-since", ""), values.get("if-match", ""), values.get("if-none-match", ""),
              values.get("if-unmodified-since", ""), values.get("range", "")]
    fields.append("\n".join(name + ":" + values[name] for name in sorted(values) if name.startswith("x-ms-")))
    resource = "/syntheticaccount" + url.path
    for name in sorted(query):
        resource += "\n" + name.lower() + ":" + ",".join(sorted(query[name]))
    fields.append(resource)
    signature = base64.b64encode(hmac.new(key, "\n".join(fields).encode(), hashlib.sha256).digest()).decode()
    return "SharedKey syntheticaccount:" + signature


class AzureFilesServerTests(unittest.TestCase):
    def start(self):
        self.state = FIXTURES.AzureFilesState(KEY64, utc_now=lambda: NOW)
        self.port = self.enterContext(FIXTURES.serve("azurefiles", self.state))

    def signed(self, method, target, date=NOW, key=KEY, extra=None):
        headers = {"x-ms-date": format_datetime(date, usegmt=True), "x-ms-version": "2026-06-06",
                   "x-ms-file-request-intent": "backup"}
        headers.update(extra or {})
        headers["Authorization"] = independent_sign(method, target, headers, key)
        return headers

    def request(self, method, target, headers=None, extra=(), body=None, host=True):
        client = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            client.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
            if host:
                client.putheader("Host", f"127.0.0.1:{self.port}")
            for name, value in (headers or self.signed(method, target)).items():
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
        self.assertNotIn(KEY64.encode(), body)
        for payload in EXPECTED.values():
            self.assertNotIn(payload, body)

    def test_literal_files_canonicalization_and_hmac_vectors(self):
        for vector in SIGNING_VECTORS:
            with self.subTest(name=vector["name"]):
                canonical = FIXTURES.azure_string_to_sign("syntheticaccount", vector["method"], vector["target"], vector["headers"])
                self.assertEqual(canonical, vector["canonical"])
                signature = base64.b64encode(hmac.new(KEY, canonical.encode(), hashlib.sha256).digest()).decode()
                self.assertEqual(signature, vector["signature"])
                self.assertEqual(independent_sign(vector["method"], vector["target"], dict(vector["headers"])),
                                 "SharedKey syntheticaccount:" + vector["signature"])

    def test_literal_stale_and_boundary_signatures_are_checked_for_freshness(self):
        self.start()
        for vector in SIGNING_VECTORS[-2:]:
            headers = dict(vector["headers"])
            headers["Authorization"] = "SharedKey syntheticaccount:" + vector["signature"]
            response = self.request(vector["method"], vector["target"], headers)
            if "901" in vector["name"]:
                self.assert_error(response, 403, "AuthenticationFailed")
                self.assertEqual(self.state.payload_bytes, 0)
            else:
                self.assertEqual((response[0], response[2]), (200, EXPECTED["README-synthetic.txt"]))
        self.assertEqual(self.state.stale_denied, 1)

    def test_ignored_root_file_probe_is_distinct_from_directory_properties(self):
        self.start()
        self.assert_error(self.request("HEAD", ROOT), 404, "ResourceNotFound")
        code, headers, body = self.request("GET", ROOT + "?restype=directory")
        self.assertEqual((code, body), (200, b""))
        self.assertEqual(headers["x-ms-file-attributes"], "Directory")
        self.assertEqual(headers["x-ms-file-last-write-time"], "2024-01-01T00:00:00.0000000Z")
        self.assertEqual((self.state.root_file_probes, self.state.directory_properties, self.state.missing), (1, 1, 0))
        self.assert_error(self.request("HEAD", ROOT + "?restype=directory"), 400)

    def test_wrong_valid_key_requires_observed_known_member_denial(self):
        self.start()
        wrong = bytes(value ^ 1 for value in KEY)
        self.assertEqual(len(base64.b64decode(base64.b64encode(wrong), validate=True)), 32)
        self.assert_error(self.request("HEAD", ROOT, self.signed("HEAD", ROOT, key=wrong)), 403)
        self.assertEqual((self.state.root_probe_denied, self.state.read_auth_denied), (1, 0))
        self.assert_error(self.request("HEAD", README, self.signed("HEAD", README, key=wrong)), 403)
        self.assertEqual((self.state.read_auth_denied, self.state.authenticated, self.state.payload_bytes), (1, 0, 0))
        self.assertEqual(self.request("GET", README)[2], EXPECTED["README-synthetic.txt"])

    def test_intent_is_required_exact_and_signed(self):
        self.start()
        for value in (None, "primary", "Backup"):
            headers = self.signed("HEAD", README)
            if value is None:
                headers.pop("x-ms-file-request-intent")
            else:
                headers["x-ms-file-request-intent"] = value
            headers["Authorization"] = independent_sign("HEAD", README, headers)
            self.assert_error(self.request("HEAD", README, headers), 400)
        headers = self.signed("HEAD", README)
        altered = dict(headers)
        altered.pop("x-ms-file-request-intent")
        headers["Authorization"] = independent_sign("HEAD", README, altered)
        self.assert_error(self.request("HEAD", README, headers), 403, "AuthenticationFailed")
        self.assertEqual(self.state.payload_bytes, 0)

    def test_files_xml_has_leaf_names_distinct_directories_lengths_and_timestamps(self):
        self.start()
        for target, directory, names in ((LIST, "", {"README-synthetic.txt": "File", "nested": "Directory"}),
                                        (BASE + "/nested?restype=directory&comp=list&include=Timestamps", "nested",
                                         {"bytes.bin": "File", "space name.txt": "File"})):
            code, _, body = self.request("GET", target)
            self.assertEqual(code, 200)
            root = ET.fromstring(body)
            self.assertEqual(root.attrib["ShareName"], "synthetic-share")
            self.assertEqual(root.attrib["DirectoryPath"], directory)
            self.assertEqual({row.findtext("Name"): row.tag for row in root.findall("Entries/*")}, names)
            self.assertFalse(root.findtext("NextMarker"))
            for entry in root.findall("Entries/*"):
                relative = (directory + "/" if directory else "") + entry.findtext("Name")
                self.assertEqual(entry.findtext("Properties/LastWriteTime"), "2024-01-01T00:00:00.0000000Z")
                self.assertEqual(entry.findtext("Properties/Last-Modified"), "Tue, 02 Jan 2024 00:00:00 GMT")
                expected_size = len(EXPECTED[relative]) if entry.tag == "File" else 0
                self.assertEqual(int(entry.findtext("Properties/Content-Length")), expected_size)

    def test_exact_encoded_file_metadata_and_download_hashes(self):
        self.start()
        for name, payload in EXPECTED.items():
            target = ROOT + urllib.parse.quote(name, safe="")
            code, headers, body = self.request("HEAD", target)
            self.assertEqual((code, body), (200, b""))
            self.assertEqual(int(headers["Content-Length"]), len(payload))
            self.assertEqual(base64.b64decode(headers["Content-MD5"]), hashlib.md5(payload).digest())
            self.assertEqual(headers["x-ms-file-last-write-time"], "2024-01-01T00:00:00.0000000Z")
            self.assertEqual(headers["Last-Modified"], "Tue, 02 Jan 2024 00:00:00 GMT")
            code, _, body = self.request("GET", target)
            self.assertEqual(code, 200)
            self.assertEqual(hashlib.sha256(body).digest(), hashlib.sha256(payload).digest())
        target = ROOT + "nested%2Fspace%20name.txt"
        headers = self.signed("GET", target)
        headers["Authorization"] = independent_sign("GET", urllib.parse.unquote(target), headers)
        self.assert_error(self.request("GET", target, headers), 403)

    def test_page_limit_counts_files_and_directories_and_never_truncates(self):
        self.start()
        for suffix, status, names in (("maxresults=1", 400, set()),
                                      ("maxresults=2", 200, {"README-synthetic.txt", "nested"}),
                                      ("prefix=README&maxresults=1", 200, {"README-synthetic.txt"}),
                                      ("prefix=nest&maxresults=1", 200, {"nested"}),
                                      ("marker=next", 400, set()), ("marker=", 200, {"README-synthetic.txt", "nested"})):
            response = self.request("GET", LIST + "&" + suffix)
            self.assertEqual(response[0], status)
            root = ET.fromstring(response[2])
            self.assertEqual({row.findtext("Name") for row in root.findall("Entries/*")}, names)
            if status == 200:
                self.assertFalse(root.findtext("NextMarker"))
            else:
                self.assertEqual(root.tag, "Error")

    def test_missing_file_or_directory_uses_files_resource_error(self):
        self.start()
        for method, target in (("HEAD", ROOT + "absent"), ("GET", ROOT + "absent"),
                               ("HEAD", ROOT + "nested"), ("GET", ROOT + "absent?restype=directory"),
                               ("GET", ROOT + "absent?restype=directory&comp=list")):
            self.assert_error(self.request(method, target), 404, "ResourceNotFound")
        self.assertEqual(self.state.missing, 5)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_signed_file_range_has_file_specific_whole_content_md5(self):
        self.start()
        headers = self.signed("GET", README, extra={"x-ms-range": "bytes=2-5"})
        code, response_headers, body = self.request("GET", README, headers)
        expected = EXPECTED["README-synthetic.txt"]
        self.assertEqual((code, body), (206, expected[2:6]))
        self.assertEqual(response_headers["Content-Range"], f"bytes 2-5/{len(expected)}")
        self.assertEqual(base64.b64decode(response_headers["x-ms-content-md5"]), hashlib.md5(expected).digest())
        self.assertNotIn("Content-MD5", response_headers)
        self.assertNotIn("x-ms-blob-content-md5", response_headers)
        headers["x-ms-range"] = "bytes=2-6"
        self.assert_error(self.request("GET", README, headers), 403)

    def test_invalid_duplicate_conflicting_or_directory_ranges_fail_closed(self):
        self.start()
        for value in ("bytes=-2", "bytes=0-9999", "bytes=4-1", "bytes=0-1,3-4"):
            self.assert_error(self.request("GET", README, self.signed("GET", README, extra={"x-ms-range": value})), 400)
        for method, target, extra in (("GET", README, {"x-ms-range": "bytes=0-1", "Range": "bytes=0-1"}),
                ("HEAD", README, {"x-ms-range": "bytes=0-1"}),
                ("GET", LIST, {"x-ms-range": "bytes=0-1"}),
                ("GET", README, {"x-ms-range-get-content-md5": "true"})):
            self.assert_error(self.request(method, target, self.signed(method, target, extra=extra)), 400)
        self.assert_error(self.request("GET", README, extra=(("x-ms-range", "bytes=0-1"), ("X-Ms-Range", "bytes=0-1"))), 400)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_authentication_dates_require_exact_utc_and_bounded_age(self):
        self.start()
        for age, expected_status in ((0, 200), (900, 200), (901, 403), (-1, 403)):
            response = self.request("HEAD", README, self.signed("HEAD", README, date=NOW - timedelta(seconds=age)))
            self.assertEqual(response[0], expected_status)
        for value in (None, "not a date", "Mon, 01 Jan 2024 00:00:00 +0000", "Mon, 01 Jan 2024 00:00:00 UTC"):
            headers = self.signed("HEAD", README)
            if value is None:
                headers.pop("x-ms-date")
            else:
                headers["x-ms-date"] = value
            headers["Authorization"] = independent_sign("HEAD", README, headers)
            self.assert_error(self.request("HEAD", README, headers), 403)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_authenticated_write_guard_preserves_original_served_source(self):
        self.start()
        before = dict(self.state.files)
        for method in ("PUT", "DELETE", "POST"):
            target = ROOT + "must-not-be-created.txt"
            headers = self.signed(method, target, extra={"Content-Length": "0"})
            self.assert_error(self.request(method, target, headers, body=b""), 403, "AuthorizationPermissionMismatch")
        self.assertEqual(self.state.rejected_mutations, 3)
        self.assertEqual(self.state.files, before)
        self.assertEqual(self.state.auth_denied, 0)

    def test_ambiguous_headers_routes_query_and_signed_target_are_rejected(self):
        self.start()
        for target in ("/syntheticaccount?comp=list", "/other/synthetic-share/file", BASE, ROOT + ".", ROOT + "../file",
                       ROOT + "%2e%2e/file", ROOT + "nested%252Fbytes.bin", ROOT + "nested%5cbytes.bin"):
            self.assert_error(self.request("GET", target), 400)
        for suffix in ("maxresults=0", "maxresults=5001", "maxresults=2&maxresults=2", "include=timestamps",
                       "prefix=..%2F", "sharesnapshot=other", "timeout=2"):
            self.assert_error(self.request("GET", LIST + "&" + suffix), 400)
        for extra in ((("Host", "example.invalid"),), (("Content-Length", "0"), ("Content-Length", "0")),
                      (("X-Ms-Date", format_datetime(NOW, usegmt=True)),), (("Transfer-Encoding", "chunked"),),
                      (("Authorization", "duplicate"),), (("x-ms-file-request-intent", "backup"),)):
            self.assert_error(self.request("GET", README, extra=extra), 400)
        self.assert_error(self.request("GET", README, host=False), 400)
        for raw in ("\x01" + README, " " + README, README + "\t", README + "%XX"):
            with self.assertRaises(ValueError):
                FIXTURES.azure_string_to_sign("syntheticaccount", "GET", raw, self.signed("GET", README).items())
        self.assertEqual(self.state.payload_bytes, 0)

    def test_budget_rejects_before_serving_any_file_bytes(self):
        self.start()
        self.state.request_limit = 0
        self.assert_error(self.request("GET", README), 429)
        self.assertTrue(self.state.budget_exceeded)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_slow_header_deadline_joins_threads_and_closes_socket(self):
        state = FIXTURES.AzureFilesState(KEY64, utc_now=lambda: NOW)
        state.request_timeout = 0.2
        with FIXTURES.serve("azurefiles", state) as port:
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
        self.assertTrue(state.cleanup_complete)
        self.assertTrue(state.budget_exceeded)
        self.assertFalse(state.sockets)
        self.assertEqual(state.payload_bytes, 0)
        with socket.socket() as probe:
            self.assertNotEqual(probe.connect_ex(("127.0.0.1", port)), 0)


if __name__ == "__main__":
    unittest.main()
