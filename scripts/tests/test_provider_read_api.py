"""Independent wire oracles for HiDrive and all three DOI read formats."""
import hashlib
import http.client
import json
from pathlib import Path
import socket
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parents[1] / "provider-lab"))
try:
    import fixture_hidrive as H
    import fixture_doi as D
    import run_lab as LAB
finally:
    sys.path.pop(0)

PAYLOADS = {
    "README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
    "nested/bytes.bin": bytes(range(256)) * 8,
    "nested/space name.txt": b"Nested synthetic payload.\n",
}
EXPECTED = [{"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            for name, data in sorted(PAYLOADS.items())]
TOKEN = "synthetic-independent-token"
FIELDS = "members.name,members.type,members.id,members.size,members.mtime,members.chash,members.nmembers,nmembers"


class WireCase(unittest.TestCase):
    def request(self, method, path, *, headers=(), authorization=None):
        client = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            client.putrequest(method, path, skip_accept_encoding=True)
            if authorization is not None:
                client.putheader("Authorization", authorization)
            for key, value in headers:
                client.putheader(key, value)
            client.endheaders()
            response = client.getresponse()
            return response.status, dict(response.getheaders()), response.read(16385)
        finally:
            client.close()


class HiDriveWireTests(WireCase):
    def setUp(self):
        self.state = H.HiDriveState(TOKEN)
        self.port = self.enterContext(H.serve_hidrive(self.state))

    def get(self, path, **kw):
        return self.request("GET", path, authorization="Bearer " + TOKEN, **kw)

    def test_root_and_nested_inventory_match_independent_names(self):
        for path, names in (("%2F", ["README-synthetic.txt", "nested"]),
                            ("%2Fnested", ["bytes.bin", "space%20name.txt"])):
            status, _, body = self.get("/dir?path=" + path + "&members=all&sort=none&limit=0,5000&fields=" + FIELDS)
            self.assertEqual(status, 200)
            value = json.loads(body)
            self.assertEqual(value["nmembers"], 2)
            self.assertEqual([entry["name"] for entry in value["members"]], names)
            self.assertEqual([entry["type"] for entry in value["members"]], ["file", "dir"] if path == "%2F" else ["file", "file"])
        self.assertEqual(self.state.events, [("listing", ""), ("listing", "nested")])

    def test_metadata_and_content_match_literal_corpus(self):
        for name, data in PAYLOADS.items():
            path = "%2F" + name.replace("/", "%2F").replace(" ", "%20")
            status, _, body = self.get("/meta?path=" + path + "&fields=name,type,id,size,mtime,chash")
            self.assertEqual(status, 200)
            value = json.loads(body)
            self.assertEqual((value["type"], value["size"], value["mtime"]), ("file", len(data), 1704067200))
            status, _, body = self.get("/file?path=" + path)
            self.assertEqual((status, body), (200, data))
        self.assertEqual(self.state.payload_bytes, sum(map(len, PAYLOADS.values())))

    def test_saved_token_and_content_denials_never_return_source_bytes(self):
        status, headers, body = self.request("GET", "/meta?path=%2F&fields=name,type", authorization="Bearer wrong")
        self.assertEqual((status, json.loads(body)), (401, {"code": 401, "msg": "synthetic token denied"}))
        self.assertNotIn("WWW-Authenticate", headers)
        self.state.mode = "read_denied"
        status, _, body = self.get("/file?path=%2FREADME-synthetic.txt")
        self.assertEqual(status, 403)
        self.assertNotIn(PAYLOADS["README-synthetic.txt"], body)
        self.assertEqual((self.state.denied, self.state.read_denied, self.state.payload_bytes), (1, 1, 0))

    def test_missing_object_and_delete_are_distinct_denials(self):
        self.assertEqual(self.get("/meta?path=%2Fabsent-synthetic.txt&fields=name,type")[0], 404)
        self.assertEqual(self.request("DELETE", "/file?path=%2FREADME-synthetic.txt", authorization="Bearer " + TOKEN)[0], 405)
        self.assertEqual((self.state.missing, self.state.rejected_mutations), (1, 1))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_unreviewed_queries_paths_and_renewal_requests_fail(self):
        for path in ("/meta?path=%2F&fields=name,type&extra=1", "/meta?path=%2F&path=%2Fnested&fields=name,type",
                     "/meta?path=%2F..%2Foutside&fields=name,type", "/meta?path=%2F%252e%252e&fields=name,type",
                     "/dir?path=%2F&members=all&sort=none&limit=5000,5000&fields=" + FIELDS,
                     "/unreviewed-token", "/file?path=%2Fnested%2F%2Fbytes.bin"):
            with self.subTest(path=path):
                self.assertEqual(self.get(path)[0], 400)
        self.assertEqual(self.state.unexpected, 7)
        self.assertEqual(self.state.payload_bytes, 0)


class DoiWireTests(WireCase):
    def start(self, provider):
        self.state = D.DoiState(provider)
        self.port = self.enterContext(D.serve_doi(self.state))

    def test_resolver_answers_are_owned_loopback_urls_for_each_format(self):
        for provider in ("dataverse", "invenio", "zenodo"):
            self.start(provider)
            status, _, body = self.request("GET", "/resolver/handles/10.0000/zenodo.123?index=1")
            self.assertEqual(status, 200)
            target = f"http://127.0.0.1:{self.port}" + ("/dataset.xhtml?persistentId=doi:10.0000/zenodo.123" if provider == "dataverse" else "/records/123")
            self.assertEqual(json.loads(body), {"responseCode": 1, "handle": "10.0000/zenodo.123", "values": [
                {"index": 1, "type": "URL", "data": {"format": "string", "value": target}}]})
            self.assertEqual(self.state.payload_bytes, 0)

    def test_dataverse_schema_and_file_ids_match_independent_corpus(self):
        self.start("dataverse")
        status, _, body = self.request("GET", "/api/datasets/:persistentId/?persistentId=doi:10.0000/zenodo.123")
        self.assertEqual(status, 200)
        expected = [{"directoryLabel": name.rpartition("/")[0], "dataFile": {
            "id": 101 + i, "filename": name.rpartition("/")[2], "filesize": len(data),
            "contentType": "application/octet-stream", "md5": hashlib.md5(data).hexdigest()}}
            for i, (name, data) in enumerate(sorted(PAYLOADS.items()))]
        self.assertEqual(json.loads(body), {"status": "OK", "data": {"latestVersion": {
            "lastUpdateTime": "2024-01-01T00:00:00Z", "files": expected}}})
        for i, data in enumerate(PAYLOADS.values()):
            self.assertEqual(self.request("GET", f"/api/access/datafile/{101+i}?format=original")[::2], (200, data))

    def test_invenio_and_zenodo_schemas_resolve_exact_content_links(self):
        for provider in ("invenio", "zenodo"):
            self.start(provider)
            origin = f"http://127.0.0.1:{self.port}"
            self.assertEqual(json.loads(self.request("GET", "/api/records/123")[2]), {"links": {"self": origin + "/api/records/123"}})
            status, _, body = self.request("GET", "/api/records/123/files")
            self.assertEqual(status, 200)
            expected = [{"key": name, "checksum": "md5:" + hashlib.md5(data).hexdigest(), "size": len(data),
                         "updated": "2024-01-01T00:00:00Z", "mimetype": "application/octet-stream",
                         "links": {"content": origin + f"/content/{101+i}"}}
                        for i, (name, data) in enumerate(sorted(PAYLOADS.items()))]
            self.assertEqual(json.loads(body), {"entries": expected})
            for i, data in enumerate(PAYLOADS.values()):
                self.assertEqual(self.request("GET", f"/content/{101+i}")[::2], (200, data))

    def test_resolution_content_and_write_denials_are_observed_per_format(self):
        for provider in ("dataverse", "invenio", "zenodo"):
            self.start(provider)
            prefix, query = ("/api/access/datafile/", "?format=original") if provider == "dataverse" else ("/content/", "")
            response = self.request("GET", "/resolver/handles/10.0000/missing-synthetic?index=1")
            self.assertEqual((response[0], json.loads(response[2])), (200, {"responseCode": 100, "values": []}))
            self.assertEqual(self.request("GET", prefix + "999" + query)[0], 404)
            self.state.mode = "read_denied"
            self.assertEqual(self.request("GET", prefix + "101" + query)[0], 403)
            self.assertEqual(self.request("DELETE", prefix + "101" + query)[0], 405)
            self.assertEqual((self.state.resolver_denied, self.state.missing, self.state.read_denied, self.state.rejected_mutations), (1, 1, 1, 1))
            self.assertEqual(self.state.payload_bytes, 0)
            self.assertEqual(self.state.files, PAYLOADS)

    def test_cross_format_and_authenticated_requests_are_not_accepted(self):
        self.start("dataverse")
        for path in ("/api/records/123/files", "/api/access/datafile/101?format=converted",
                     "/resolver/handles/10.0000/zenodo.123?index=1&index=2", "/content/101"):
            self.assertEqual(self.request("GET", path)[0], 400)
        self.assertEqual(self.request("GET", "/resolver/handles/10.0000/zenodo.123?index=1", authorization="Bearer private")[0], 400)
        self.assertEqual(self.state.unexpected, 5)


class BoundedReadTransportTests(WireCase):
    def setUp(self):
        self.state = D.DoiState("invenio")
        self.port = self.enterContext(D.serve_doi(self.state))

    def test_ambiguous_headers_bodies_and_paths_fail_without_payload(self):
        for path, headers in (("/content/101", (("Host", "outside.invalid"),)),
                              ("/content/101", (("Content-Length", "1"),)),
                              ("/content/101", (("Transfer-Encoding", "chunked"),)),
                              ("/content/%XX", ()), ("/content/../101", ()), ("/content/%252e%252e/101", ())):
            with self.subTest(path=path, headers=headers):
                self.assertEqual(self.request("GET", path, headers=headers)[0], 400)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_ranges_are_bounded_and_do_not_change_source(self):
        status, headers, body = self.request("GET", "/content/102", headers=(("Range", "bytes=256-511"),))
        self.assertEqual((status, body), (206, bytes(range(256))))
        self.assertEqual(headers["Content-Range"], "bytes 256-511/2048")
        for value in ("bytes=-1", "bytes=9-2", "bytes=99999-", "bytes=0-1,3-4", "bytes=" + "9"*100 + "-"):
            self.assertEqual(self.request("GET", "/content/102", headers=(("Range", value),))[0], 416)
        self.assertEqual(self.state.files, PAYLOADS)
        self.assertEqual(self.state.payload_bytes, 256)

    def test_request_and_response_budgets_prevent_a_success_trace(self):
        self.state.request_limit = 1
        self.assertEqual(self.request("GET", "/content/101")[0], 200)
        self.assertEqual(self.request("GET", "/content/101")[0], 429)
        self.assertTrue(self.state.budget_exceeded)
        self.state.request_limit = 10
        self.state.byte_limit = 1
        self.assertEqual(self.request("GET", "/content/101")[0], 429)

    def test_slow_headers_are_bounded_and_listener_closes(self):
        state = D.DoiState("zenodo")
        state.request_timeout = 0.1
        with D.serve_doi(state) as port:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
                client.sendall(b"GET /records/123 HTTP/1.1\r\nHost:")
                self.assertEqual(client.recv(1), b"")
        self.assertTrue(state.budget_exceeded)
        self.assertTrue(state.cleanup_complete)
        self.assertFalse(state.sockets)
        with socket.socket() as client:
            self.assertNotEqual(client.connect_ex(("127.0.0.1", port)), 0)

    def test_missing_or_extra_content_and_denial_observations_fail(self):
        def observed():
            state = D.DoiState("invenio")
            state.events = [("content", name) for name in PAYLOADS]
            state.events += [("read_denied", "README-synthetic.txt"), ("write_denied", "README-synthetic.txt")]
            state.payload_bytes = sum(map(len, PAYLOADS.values()))
            state.read_denied = state.rejected_mutations = 1
            return state
        self.assertTrue(LAB.read_api_flow_matches(observed(), EXPECTED))
        for key, value in (("unexpected", 1), ("budget_exceeded", True), ("rejected_payload_bytes", 1),
                           ("read_denied", 0), ("rejected_mutations", 0), ("payload_bytes", 1)):
            state = observed()
            setattr(state, key, value)
            self.assertFalse(LAB.read_api_flow_matches(state, EXPECTED), key)
        for index in range(5):
            state = observed()
            del state.events[index]
            self.assertFalse(LAB.read_api_flow_matches(state, EXPECTED))
        state = observed()
        state.events.append(("content", "README-synthetic.txt"))
        self.assertFalse(LAB.read_api_flow_matches(state, EXPECTED))


if __name__ == "__main__":
    unittest.main()
