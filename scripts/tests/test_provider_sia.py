"""Legacy siad protocol oracles, without a daemon, wallet or cloud account."""
import base64
import hashlib
import http.client
import json
from pathlib import Path
import socket
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parents[1] / "provider-lab"))
try:
    import fixture_sia as S
    import run_lab as LAB
finally:
    sys.path.pop(0)

PASSWORD = "synthetic-test-password"
PAYLOADS = {
    "README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
    "nested/bytes.bin": bytes(range(256)) * 8,
    "nested/space name.txt": b"Nested synthetic payload.\n",
}
EXPECTED = [{"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            for name, data in sorted(PAYLOADS.items())]


class SiaServerTests(unittest.TestCase):
    def start(self, mode="normal"):
        self.state = S.SiaState(PASSWORD, mode)
        self.port = self.enterContext(S.serve_sia(self.state))

    def request(self, method, path, *, password=PASSWORD, extra=(), agent="Sia-Agent"):
        client = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            client.putrequest(method, path, skip_accept_encoding=True)
            client.putheader("Authorization", "Basic " + base64.b64encode((":" + password).encode()).decode())
            client.putheader("User-Agent", agent)
            for key, value in extra:
                client.putheader(key, value)
            client.endheaders()
            response = client.getresponse()
            return response.status, dict(response.getheaders()), response.read(16385)
        finally:
            client.close()

    def test_inventory_metadata_and_bytes_are_independent_literals(self):
        self.start()
        for route, directories, files in (
            ("", ["", "nested"], ["README-synthetic.txt"]),
            ("nested/", ["nested"], ["nested/bytes.bin", "nested/space name.txt"]),
        ):
            status, _, body = self.request("GET", "/renter/dir/" + route)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body), {
                "directories": [{"siapath": p, "mostrecentmodtime": "2024-01-01T00:00:00Z"} for p in directories],
                "files": [{"siapath": p, "filesize": len(PAYLOADS[p]), "modtime": "2024-01-01T00:00:00Z"} for p in files],
            })
        for name, data in PAYLOADS.items():
            encoded = name.replace(" ", "%20")
            status, _, body = self.request("GET", "/renter/file/" + encoded)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body), {"file": {"siapath": name, "filesize": len(data), "modtime": "2024-01-01T00:00:00Z"}})
            status, _, body = self.request("GET", "/renter/stream/" + encoded)
            self.assertEqual((status, body), (200, data))
        self.assertEqual(self.state.payload_bytes, sum(map(len, PAYLOADS.values())))
        self.assertEqual(self.state.unexpected, 0)

    def test_wrong_password_missing_and_content_denial_return_no_source_bytes(self):
        self.start("read_denied")
        for route, password, expected in (
            ("/renter/file/README-synthetic.txt", "wrong", 401),
            ("/renter/file/absent-synthetic.txt", PASSWORD, 400),
            ("/renter/stream/README-synthetic.txt", PASSWORD, 403),
        ):
            status, headers, body = self.request("GET", route, password=password)
            self.assertEqual(status, expected)
            self.assertEqual(set(json.loads(body)), {"message"})
            self.assertNotIn("Location", headers)
            for secret in (PASSWORD.encode(), *PAYLOADS.values()):
                self.assertNotIn(secret, body)
        self.assertEqual((self.state.denied, self.state.missing, self.state.read_denied), (1, 1, 1))
        self.assertEqual(self.state.payload_bytes, 0)
        self.assertEqual(self.state.files, PAYLOADS)

    def test_ranges_are_bounded_and_preserve_original_bytes(self):
        self.start()
        status, headers, body = self.request("GET", "/renter/stream/nested/bytes.bin", extra=(("Range", "bytes=256-511"),))
        self.assertEqual((status, body), (206, bytes(range(256))))
        self.assertEqual(headers["Content-Range"], "bytes 256-511/2048")
        for value in ("bytes=-3", "bytes=9-2", "bytes=999999-", "bytes=0-1,3-4", "bytes=" + "9" * 100 + "-"):
            self.assertEqual(self.request("GET", "/renter/stream/nested/bytes.bin", extra=(("Range", value),))[0], 416)
        self.assertEqual(self.state.payload_bytes, 256)
        self.assertEqual(self.state.files, PAYLOADS)

    def test_only_reviewed_requests_are_accepted(self):
        self.start()
        for method, path, extra, agent in (
            ("GET", "/renter/file/../secret", (), "Sia-Agent"),
            ("GET", "/renter/file/%2e%2e/secret", (), "Sia-Agent"),
            ("GET", "/renter/file/%252e%252e/secret", (), "Sia-Agent"),
            ("GET", "/renter/file/README-synthetic.txt?x=1", (), "Sia-Agent"),
            ("GET", "/renter/file/%XX", (), "Sia-Agent"),
            ("GET", "/renter/file/README-synthetic.txt", (("Host", "example.invalid"),), "Sia-Agent"),
            ("GET", "/renter/file/README-synthetic.txt", (("Content-Length", "1"),), "Sia-Agent"),
            ("GET", "/renter/file/README-synthetic.txt", (("Transfer-Encoding", "chunked"),), "Sia-Agent"),
            ("GET", "/renter/file/README-synthetic.txt", (), "other-agent"),
            ("PUT", "/renter/file/README-synthetic.txt", (), "Sia-Agent"),
        ):
            with self.subTest(path=path, extra=extra):
                self.assertEqual(self.request(method, path, extra=extra, agent=agent)[0], 400)
        self.assertEqual(self.state.payload_bytes, 0)
        self.assertEqual(self.state.unexpected, 10)

    def test_delete_and_upload_are_denied_and_counted(self):
        self.start()
        for route in ("delete", "uploadstream"):
            self.assertEqual(self.request("POST", f"/renter/{route}/README-synthetic.txt")[0], 405)
        self.assertEqual(self.state.rejected_mutations, 2)
        self.assertEqual(self.state.files, PAYLOADS)
        self.assertEqual(self.state.unexpected, 0)

    def test_budget_and_owned_socket_cleanup(self):
        state = S.SiaState(PASSWORD)
        state.request_limit = 1
        with S.serve_sia(state) as port:
            self.state, self.port = state, port
            self.assertEqual(self.request("GET", "/renter/dir/")[0], 200)
            self.assertEqual(self.request("GET", "/renter/dir/")[0], 429)
        self.assertTrue(state.budget_exceeded)
        self.assertTrue(state.cleanup_complete)
        self.assertFalse(state.sockets)
        with socket.socket() as client:
            self.assertNotEqual(client.connect_ex(("127.0.0.1", port)), 0)

    def test_slow_headers_hit_whole_request_deadline(self):
        state = S.SiaState(PASSWORD)
        state.request_timeout = 0.1
        with S.serve_sia(state) as port:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
                client.sendall(b"GET /renter/dir/ HTTP/1.1\r\nHost:")
                self.assertEqual(client.recv(1), b"")
        self.assertTrue(state.budget_exceeded)
        self.assertTrue(state.cleanup_complete)


class SiaFlowTests(unittest.TestCase):
    def observed(self):
        state = S.SiaState(PASSWORD)
        state.events = [("listing", ""), ("listing", "nested")] * 2
        state.events += [("content", name) for name in sorted(PAYLOADS)]
        state.events += [("file_missing", "absent-synthetic.txt"), ("read_denied", "README-synthetic.txt"),
                         ("write_denied", "README-synthetic.txt")]
        state.payload_bytes = sum(map(len, PAYLOADS.values()))
        state.denied = state.missing = state.read_denied = state.rejected_mutations = 1
        return state

    def test_missing_observations_or_unexpected_io_fail(self):
        self.assertTrue(LAB.sia_flow_matches(self.observed(), EXPECTED))
        for name, value in (("denied", 0), ("missing", 0), ("read_denied", 0), ("rejected_mutations", 0),
                            ("unexpected", 1), ("budget_exceeded", True), ("rejected_payload_bytes", 1), ("payload_bytes", 1)):
            state = self.observed()
            setattr(state, name, value)
            with self.subTest(field=name):
                self.assertFalse(LAB.sia_flow_matches(state, EXPECTED))
        for index in range(len(self.observed().events)):
            state = self.observed()
            del state.events[index]
            self.assertFalse(LAB.sia_flow_matches(state, EXPECTED))
        state = self.observed()
        state.events.append(("content", "README-synthetic.txt"))
        self.assertFalse(LAB.sia_flow_matches(state, EXPECTED))


if __name__ == "__main__":
    unittest.main()
