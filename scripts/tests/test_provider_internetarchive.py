"""Anonymous Internet Archive wire checks; synthetic HTTP only, no native runtime."""
import copy
import hashlib
import http.client
import json
from pathlib import Path
import socket
import sys
import time
import unittest
import zlib

sys.path.insert(0, str(Path(__file__).parents[1] / "provider-lab"))
try:
    import fixture_servers as F
finally:
    sys.path.pop(0)

PAYLOADS = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
            "nested/bytes.bin": bytes(range(256)) * 8, "nested/space name.txt": b"Nested synthetic payload.\n"}
META = "/front/metadata/synthetic-item"
CONTENT = "/front/download/synthetic-item/"
WRITE = "/ias3/synthetic-item%2FREADME-synthetic.txt"


def metadata(mode="normal"):
    entries = []
    for name, body in sorted(PAYLOADS.items()):
        item = {"name": name, "size": str(len(body)), "mtime": "1704153600.999",
                "rclone-mtime": ["invalid-synthetic-time", "2024-01-01T00:00:00.123456789Z"] if name.startswith("nested/")
                else "2024-01-01T00:00:00.123456789Z", "md5": hashlib.md5(body).hexdigest(),
                "sha1": hashlib.sha1(body).hexdigest(), "crc32": f"{zlib.crc32(body) & 0xffffffff:08x}"}
        if mode == "summation" and name == "README-synthetic.txt":
            item.update(summation="md5", md5="0" * 32, sha1="0" * 40, crc32="00000000")
        entries.append(item)
    return {"item_size": sum(map(len, PAYLOADS.values())), "files": entries}


class InternetArchiveServerTests(unittest.TestCase):
    def start(self, mode="normal"):
        self.state = F.InternetArchiveState(mode)
        self.port = self.enterContext(F.serve("internetarchive", self.state))

    def request(self, target=META, *, method="GET", extra=(), omitted=(), body=b""):
        client = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            client.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
            for name, value in (("Host", f"127.0.0.1:{self.port}"), ("Content-Length", str(len(body)))):
                if name not in omitted:
                    client.putheader(name, value)
            for name, value in extra:
                client.putheader(name, value)
            client.endheaders(body)
            response = client.getresponse()
            return response.status, dict(response.getheaders()), response.read(65537)
        finally:
            client.close()

    def setup_metadata(self):
        for _ in range(2):
            code, headers, body = self.request()
            self.assertEqual(code, 200)
            self.assertNotIn("Location", headers)
            self.assertEqual(json.loads(body), metadata(self.state.mode))

    def test_full_metadata_literal_wire_types_and_scalar_array_mtime_precedence(self):
        self.start()
        self.setup_metadata()
        self.assertEqual(self.state.metadata, metadata())
        self.assertEqual(self.state.events, [("metadata", "1"), ("metadata", "2")])
        self.assertEqual((self.state.requests, self.state.anonymous, self.state.payload_bytes), (2, 2, 0))
        self.assertNotIn("missing-synthetic-object.bin", [row["name"] for row in self.state.metadata["files"]])

    def test_all_three_content_paths_have_independent_bytes_and_sha256(self):
        for name, payload in PAYLOADS.items():
            with self.subTest(name=name), F.serve("internetarchive", state := F.InternetArchiveState()) as port:
                self.state, self.port = state, port
                self.setup_metadata()
                status, headers, body = self.request(CONTENT + name.replace(" ", "%20"))
                self.assertEqual((status, body), (200, payload))
                self.assertEqual(hashlib.sha256(body).hexdigest(), hashlib.sha256(payload).hexdigest())
                self.assertNotIn("Location", headers)
                self.assertEqual(state.events[-1], ("content", name))
                self.assertEqual((state.requests, state.anonymous, state.payload_bytes), (3, 3, len(payload)))
            self.assertTrue(state.cleanup_complete)
            self.assertFalse(state.sockets)

    def test_known_member_denial_follows_positive_setup_and_metadata(self):
        self.start("member_denied")
        self.setup_metadata()
        status, headers, body = self.request(CONTENT + "README-synthetic.txt")
        self.assertEqual((status, body), (403, b"Synthetic member denied"))
        self.assertNotIn("Location", headers)
        self.assertEqual(self.state.events, [("metadata", "1"), ("metadata", "2"), ("content_denied", "README-synthetic.txt")])
        self.assertEqual((self.state.member_denied, self.state.payload_bytes, self.state.rejected_payload_bytes), (1, 0, 0))

    def test_summation_deliberately_wrong_aggregate_hashes_do_not_change_bytes(self):
        self.start("summation")
        self.setup_metadata()
        status, _, body = self.request(CONTENT + "README-synthetic.txt")
        self.assertEqual((status, body), (200, PAYLOADS["README-synthetic.txt"]))
        self.assertEqual(self.state.metadata, metadata("summation"))

    def test_direct_ias3_write_guard_does_not_mutate_source_or_metadata(self):
        self.start()
        original = copy.deepcopy(self.state.metadata)
        self.setup_metadata()
        status, _, body = self.request(WRITE, method="DELETE")
        self.assertEqual((status, json.loads(body)), (405, {"status": "fixture_read_only"}))
        self.assertEqual(self.state.rejected_mutations, 1)
        self.assertEqual(self.state.metadata, original)
        self.assertEqual(self.state.files, PAYLOADS)
        self.assertEqual(self.state.unexpected, 0)

    def test_all_credential_headers_duplicate_host_encodings_and_bodies_fail_closed(self):
        cases = [("Authorization", "LOW synthetic:synthetic"), ("Proxy-Authorization", "Basic synthetic"),
                 ("Cookie", "synthetic=1"), ("Content-Encoding", "gzip"), ("Transfer-Encoding", "chunked"),
                 ("Range", "bytes=0-1"), ("Host", "external.invalid"), ("Content-Length", "0")]
        self.start()
        self.state.request_limit = 64
        self.state.connection_limit = 64
        for header in cases:
            with self.subTest(header=header[0]):
                status, _, _ = self.request(extra=[header])
                self.assertEqual(status, 400)
        self.assertEqual(self.request(omitted=["Host"])[0], 400)
        self.assertEqual(self.request(body=b"x")[0], 400)
        self.assertEqual((self.state.metadata_reads, self.state.anonymous, self.state.payload_bytes), (0, 0, 0))

    def test_queries_aliases_traversals_wrong_client_and_unsupported_methods_rejected(self):
        self.start()
        self.state.request_limit = self.state.connection_limit = 64
        targets = [META + "?", META + "?x=1", META + "/", META + "#x", "/metadata/synthetic-item",
                   "/ias3/metadata/synthetic-item", "/front/metadata/other-item", "http://127.0.0.1/" + META,
                   CONTENT + "nested%2Fbytes.bin", CONTENT + "nested/space%20name%2Etxt", CONTENT + "nested//bytes.bin",
                   CONTENT + "nested/%2e%2e/README-synthetic.txt", CONTENT + "missing-synthetic-object.bin",
                   CONTENT + "nested/space+name.txt", CONTENT + "nested/space%2520name.txt"]
        for target in targets:
            with self.subTest(target=target):
                self.assertEqual(self.request(target)[0], 400)
        for method in ("HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "PROPFIND"):
            with self.subTest(method=method):
                self.assertEqual(self.request(method=method)[0], 400)
        self.assertEqual((self.state.metadata_reads, self.state.anonymous), (0, 0))

    def test_content_requires_exactly_two_metadata_reads_and_no_replay(self):
        self.start()
        self.assertEqual(self.request(CONTENT + "README-synthetic.txt")[0], 400)
        self.assertEqual(self.request()[0], 200)
        self.assertEqual(self.request(CONTENT + "README-synthetic.txt")[0], 400)
        self.assertEqual(self.request()[0], 200)
        self.assertEqual(self.request()[0], 400)
        self.assertEqual(self.request(CONTENT + "README-synthetic.txt")[0], 200)
        self.assertEqual(self.request(CONTENT + "README-synthetic.txt")[0], 400)

    def test_budget_admission_deadline_and_body_limit_are_sticky(self):
        for key, value in (("request_limit", 0), ("deadline", time.monotonic() - 1), ("byte_limit", 1)):
            with self.subTest(key=key), F.serve("internetarchive", state := F.InternetArchiveState()) as port:
                self.state, self.port = state, port
                setattr(state, key, value)
                try:
                    self.assertEqual(self.request()[0], 429)
                except (OSError, http.client.HTTPException):
                    # An already-expired absolute deadline may close the socket
                    # before the HTTP rejection is written; both are fail-closed.
                    self.assertEqual(key, "deadline")
            self.assertTrue(state.budget_exceeded)
            self.assertTrue(state.cleanup_complete)
        with F.serve("internetarchive", state := F.InternetArchiveState()) as port:
            state.connection_limit = 0
            self.state, self.port = state, port
            with self.assertRaises((OSError, http.client.HTTPException)):
                self.request()
        self.assertTrue(state.budget_exceeded)
        self.assertGreater(state.admission_denied, 0)
        self.assertFalse(state.sockets)

    def test_idle_connection_has_absolute_deadline_and_owned_cleanup(self):
        state = F.InternetArchiveState()
        state.request_timeout = 0.05
        with F.serve("internetarchive", state) as port:
            conn = socket.create_connection(("127.0.0.1", port), timeout=2)
            try:
                self.assertEqual(conn.recv(1), b"")
            finally:
                conn.close()
        self.assertTrue(state.budget_exceeded)
        self.assertTrue(state.cleanup_complete)
        self.assertFalse(state.sockets)
        with socket.socket() as probe:
            self.assertNotEqual(probe.connect_ex(("127.0.0.1", port)), 0)

    def test_unknown_mode_is_rejected(self):
        for value in ("auth_denied", "", None, "http://external.invalid"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                F.InternetArchiveState(value)


if __name__ == "__main__":
    unittest.main()
