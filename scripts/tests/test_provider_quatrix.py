"""Quatrix wire oracles independent of native success receipts."""
import http.client
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

LAB = Path(__file__).resolve().parents[1] / "provider-lab"
sys.path.insert(0, str(LAB))
try:
    import fixture_quatrix as Q
    from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits
finally:
    sys.path.pop(0)

TOKEN, WRONG = "synthetic-static-key", "wrong-synthetic-key"
PAYLOADS = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
            "nested/bytes.bin": bytes(range(256)) * 8,
            "nested/space name.txt": b"Nested synthetic payload.\n"}
API = "/api/1.0/"


class QuatrixWireTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.state = Q.QuatrixState(TOKEN, WRONG)
        self.certificates, self.transport = self.enterContext(Q.serve_quatrix(self.root, self.state))

    def request(self, method, path, data=None, token=TOKEN, headers=(), raw_body=None):
        client = http.client.HTTPSConnection("127.0.0.1", self.transport.port, timeout=4,
                                            context=self.certificates.client_context())
        body = raw_body if raw_body is not None else json.dumps(data).encode() if data is not None else b""
        try:
            client.putrequest(method, path, skip_accept_encoding=True)
            if token is not None:
                client.putheader("Authorization", "Bearer " + token)
            if body:
                client.putheader("Content-Type", "application/json")
                client.putheader("Content-Length", str(len(body)))
            for key, value in headers:
                client.putheader(key, value)
            client.endheaders(body)
            response = client.getresponse()
            return response.status, dict(response.getheaders()), response.read(65537)
        finally:
            client.close()

    def post(self, route, value):
        return self.request("POST", API + route, value)

    def test_root_nested_and_file_id_lookup_matches_literal_inventory(self):
        for value, identity, kind in (({"path": ""}, "100", "D"),
                                      ({"parent_id": "100", "path": "nested"}, "200", "D"),
                                      ({"parent_id": "100", "path": "README-synthetic.txt"}, "301", "F"),
                                      ({"parent_id": "200", "path": "bytes.bin"}, "302", "F"),
                                      ({"path": "nested/space name.txt"}, "303", "F")):
            status, _, raw = self.post("file/id", value)
            result = json.loads(raw)
            self.assertEqual((status, result["file_id"], result["type"]), (200, identity, kind))
        self.assertEqual(self.state.payload_bytes, 0)

    def test_metadata_names_sizes_types_and_timestamps_are_exact(self):
        status, _, raw = self.request("GET", API + "file/metadata/100")
        self.assertEqual(status, 200)
        root = json.loads(raw)
        self.assertEqual((root["id"], root["type"], root["size"]), ("100", "D", 2))
        self.assertEqual([(v["name"], v["id"], v["type"]) for v in root["content"]],
                         [("README-synthetic.txt", "301", "F"), ("nested", "200", "D")])
        nested = json.loads(self.request("GET", API + "file/metadata/200")[2])
        self.assertEqual([(v["name"], v["id"], v["size"]) for v in nested["content"]],
                         [("bytes.bin", "302", 2048), ("space name.txt", "303", 26)])
        for i, (name, body) in enumerate(PAYLOADS.items(), 301):
            value = json.loads(self.request("GET", API + f"file/metadata/{i}?content=0")[2])
            self.assertEqual(value, {"id": str(i), "created": 1704067200, "modified": 1704067200,
                                    "modified_ms": 1704067200, "name": name.rsplit("/", 1)[-1],
                                    "parent_id": "200" if "/" in name else "100",
                                    "size": len(body), "type": "F", "operations": 0, "sub_type": ""})

    def test_download_requires_issued_link_and_preserves_literal_bytes(self):
        self.assertEqual(self.request("GET", API + "/file/download/link-301")[0], 400)
        for i, body in enumerate(PAYLOADS.values(), 301):
            status, _, raw = self.post("file/download-link", {"ids": [str(i)]})
            self.assertEqual((status, json.loads(raw)), (200, {"id": "link-" + str(i)}))
            self.assertEqual(self.request("GET", API + f"/file/download/link-{i}")[::2], (200, body))
        self.assertEqual(self.state.payload_bytes, sum(map(len, PAYLOADS.values())))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_configured_key_denial_never_issues_a_link_or_returns_content(self):
        for token in (WRONG, None):
            self.assertEqual(self.request("POST", API + "file/id", {"path": ""}, token=token)[0], 401)
            self.assertEqual(self.request("POST", API + "file/download-link", {"ids": ["301"]}, token=token)[0], 401)
        self.assertEqual((self.state.denied, self.state.payload_bytes, self.state.links), (4, 0, set()))
        self.assertEqual(self.request("POST", API + "file/id", {"path": ""}, token="unreviewed")[0], 400)

    def test_missing_member_and_known_member_read_denial_are_distinct(self):
        self.assertEqual(self.post("file/id", {"parent_id": "100", "path": "absent-synthetic.txt"})[::2], (404, b"{}"))
        self.assertEqual(self.post("file/download-link", {"ids": ["301"]})[0], 200)
        self.state.mode = "read_denied"
        status, _, raw = self.request("GET", API + "/file/download/link-301")
        self.assertEqual(status, 403)
        self.assertNotIn(PAYLOADS["README-synthetic.txt"], raw)
        self.assertEqual((self.state.missing, self.state.read_denied, self.state.payload_bytes), (1, 1, 0))

    def test_exact_delete_probe_is_rejected_without_changing_metadata_or_bytes(self):
        before = {key: self.state.metadata(key) for key in self.state.ids}
        status, _, raw = self.post("file/delete", {"ids": ["301"], "delete_permanently": False})
        self.assertEqual((status, json.loads(raw)), (405, {"error": "synthetic fixture is read-only"}))
        self.assertEqual(self.state.rejected_mutations, 1)
        self.assertEqual(self.state.files, PAYLOADS)
        self.assertEqual({key: self.state.metadata(key) for key in self.state.ids}, before)

    def test_unreviewed_methods_routes_and_upload_operations_fail(self):
        for method, path, body in (("GET", API + "file/id", None), ("POST", API + "file/upload-link", {"name": "x"}),
                                    ("POST", API + "file/delete", {"ids": ["301"], "delete_permanently": True}),
                                    ("GET", API + "file/download/link-301", None),
                                    ("GET", API + "/file/metadata/100", None),
                                    ("DELETE", API + "file/metadata/301", None),
                                    ("GET", API + "file/metadata/100?content=1", None)):
            self.assertEqual(self.request(method, path, body)[0], 400)
        self.assertEqual((self.state.unexpected, self.state.payload_bytes, self.state.rejected_mutations), (7, 0, 0))

    def test_ambiguous_json_and_path_shapes_fail(self):
        for raw in (b'{"path":"","path":"nested"}', b'[]', b'{"path":', b'{"path":null}',
                    b'{"path":"","extra":true}', b'{"path":"../outside"}', b'{"path":"nested//bytes.bin"}',
                    b'{"path":"nested/%2e%2e"}', b'{"path":"","parent_id":999}'):
            with self.subTest(raw=raw):
                self.assertEqual(self.request("POST", API + "file/id", raw_body=raw)[0], 400)
        for value in ({"ids": ["301", "302"]}, {"ids": [301]}, {"ids": ["100"]}, {"ids": "301"}):
            self.assertEqual(self.post("file/download-link", value)[0], 400)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_ambiguous_headers_and_body_lengths_fail(self):
        for headers in ((("Host", "elsewhere.invalid"),), (("Authorization", "Bearer " + WRONG),),
                        (("Transfer-Encoding", "chunked"),), (("Content-Length", "4097"),),
                        (("Content-Length", "00"),), (("Range", "bytes=0-1"),)):
            self.assertEqual(self.request("GET", API + "file/metadata/100", headers=headers)[0], 400)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_ranges_are_bounded_and_sources_remain_unchanged(self):
        self.post("file/download-link", {"ids": ["302"]})
        status, headers, raw = self.request("GET", API + "/file/download/link-302", headers=(("Range", "bytes=256-511"),))
        self.assertEqual((status, raw, headers["Content-Range"]), (206, bytes(range(256)), "bytes 256-511/2048"))
        for value in ("bytes=-1", "bytes=8-2", "bytes=2048-", "bytes=0-1,3-4"):
            self.assertEqual(self.request("GET", API + "/file/download/link-302", headers=(("Range", value),))[0], 416)
        self.assertEqual(self.state.files, PAYLOADS)

    def test_request_and_response_budgets_cannot_create_a_success_trace(self):
        self.state.request_limit = 1
        self.assertEqual(self.post("file/id", {"path": ""})[0], 200)
        self.assertEqual(self.post("file/id", {"path": ""})[0], 429)
        self.assertTrue(self.state.budget_exceeded)
        self.state.request_limit = 10
        self.state.byte_limit = 1
        self.assertEqual(self.request("GET", API + "file/metadata/100")[0], 429)

    def test_tls_cleanup_removes_certificates_workers_and_listener(self):
        state = Q.QuatrixState(TOKEN, WRONG)
        with Q.serve_quatrix(self.root, state) as (certificates, transport):
            folder, port = certificates.directory, transport.port
            self.assertTrue(folder.is_dir())
        self.assertTrue(state.cleanup_complete)
        self.assertFalse(folder.exists())
        snapshot = transport.snapshot()
        self.assertTrue(snapshot["cleanup_complete"])
        self.assertEqual((snapshot["active_connections"], snapshot["active_workers"], snapshot["active_timers"]), (0, 0, 0))
        with socket.socket() as client:
            self.assertNotEqual(client.connect_ex(("127.0.0.1", port)), 0)

    def test_slow_json_body_has_an_absolute_tls_deadline(self):
        state = Q.QuatrixState(TOKEN, WRONG)
        timer = threading.Timer
        # Force the socket deadline to win over the timer thread, as on a busy
        # Windows runner. A stalled request must still close without an HTTP reply.
        with FixtureCertificates.create(self.root) as certificates, patch(
                "fixture_tls.threading.Timer", side_effect=lambda delay, callback: timer(delay + 0.3, callback)):
            with BoundedHttpsServer(certificates, Q.QuatrixHandler, state=state,
                                    limits=TlsLimits(request_seconds=0.15)) as transport:
                with socket.create_connection(("127.0.0.1", transport.port), timeout=2) as raw:
                    with certificates.client_context().wrap_socket(raw, server_hostname="127.0.0.1") as client:
                        client.sendall((f"POST /api/1.0/file/id HTTP/1.1\r\nHost: 127.0.0.1:{transport.port}\r\n"
                                        "Content-Type: application/json\r\nContent-Length: 100\r\n\r\n{").encode())
                        self.assertEqual(client.recv(1), b"")
            snapshot = transport.snapshot()
            self.assertIn("tls_request_deadline", snapshot["failure_codes"])
            self.assertTrue(snapshot["cleanup_complete"])
        self.assertEqual(state.payload_bytes, 0)


if __name__ == "__main__":
    unittest.main()
