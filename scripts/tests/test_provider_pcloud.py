"""Owned Python HTTPS pCloud protocol checks, not native or vendor evidence."""
from contextlib import contextmanager, redirect_stderr
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import http.client
import io
import json
from pathlib import Path
import secrets
import socket
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "provider-lab"))
import fixture_pcloud as pcloud
from fixture_servers import FILES


class PCloudTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pcloud-unit-")
        self.root = Path(self.temp.name).resolve()
        self.token = "synthetic-" + secrets.token_hex(16)
        self.wrong = "wrong-synthetic-" + secrets.token_hex(16)
        self.fixtures = []

    def tearDown(self):
        failures = []
        try:
            for fixture in reversed(self.fixtures):
                try:
                    if not fixture.close():
                        failures.append("fixture cleanup failed")
                    snapshot = fixture.snapshot()
                    if not snapshot["certificate_cleanup"] or not snapshot["cleanup_complete"]:
                        failures.append("owned resource remains")
                except BaseException as exc:
                    failures.append("fixture cleanup raised " + type(exc).__name__)
        finally:
            try:
                self.temp.cleanup()
            except BaseException as exc:
                failures.append("temporary root cleanup raised " + type(exc).__name__)
        self.assertEqual(failures, [])

    def state(self, deny=None):
        return pcloud.PCloudState(FILES, self.token, self.wrong, deny)

    @contextmanager
    def fixture(self, state=None):
        state = state or self.state()
        with pcloud.serve_pcloud(self.root, state) as fixture:
            self.fixtures.append(fixture)
            yield fixture, state

    def request(self, fixture, path, method="GET", headers=None, body=None, token=None):
        auth = {"Authorization": "Bearer " + (token if token is not None else self.token)}
        auth.update(headers or {})
        connection = http.client.HTTPSConnection("127.0.0.1", fixture.port, timeout=2, context=fixture.client_context())
        try:
            connection.request(method, path, body=body, headers=auth)
            response = connection.getresponse()
            data = response.read(pcloud.MAX_RESPONSE_BYTES + 1)
            self.assertLessEqual(len(data), pcloud.MAX_RESPONSE_BYTES)
            self.assertNotIn("Location", dict(response.getheaders()))
            return response.status, data, dict(response.getheaders())
        finally:
            connection.close()

    def value(self, fixture, path, **kwargs):
        status, body, _ = self.request(fixture, path, **kwargs)
        self.assertEqual(status, 200)
        return json.loads(body)

    def raw(self, fixture, raw):
        output = bytearray()
        with socket.create_connection(("127.0.0.1", fixture.port), timeout=2) as sock:
            with fixture.client_context().wrap_socket(sock, server_hostname="127.0.0.1") as client:
                try:
                    client.sendall(raw)
                    while len(output) < 4096:
                        chunk = client.recv(4096 - len(output))
                        if not chunk:
                            break
                        output.extend(chunk)
                except OSError:
                    pass
        return bytes(output)

    def packet(self, fixture, path="/listfolder?folderid=100", extras=b"", method="GET"):
        return (f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{fixture.port}\r\n"
                f"Authorization: Bearer {self.token}\r\n").encode("ascii") + extras + b"\r\n"

    def wait_for(self, condition):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if condition():
                return
            time.sleep(0.005)
        self.fail("bounded protocol condition not observed")

    def locate(self, fixture, member):
        self.value(fixture, "/listfolder?folderid=100")
        if member.startswith("nested/"):
            self.value(fixture, "/listfolder?folderid=200")

    def test_only_fixed_source_and_distinct_bounded_tokens_are_accepted(self):
        bad_files = dict(FILES)
        bad_files[pcloud.MEMBERS[0]] += b"modified"
        variants = [(bad_files, self.token, self.wrong, None), ({}, self.token, self.wrong, None),
                    (dict(FILES), self.token, self.token, None), (dict(FILES), "short", self.wrong, None),
                    (dict(FILES), self.token + "\r\n", self.wrong, None),
                    (dict(FILES), self.token, self.wrong, "nested/bytes.bin"),
                    (dict(FILES), self.token, self.wrong, False)]
        for args in variants:
            with self.subTest(variant=variants.index(args)), self.assertRaises(pcloud.PCloudError):
                pcloud.PCloudState(*args)

    def test_metadata_and_time_fallback_oracle_are_exact(self):
        state = self.state()
        self.assertEqual(list(state.files), list(pcloud.MEMBERS))
        root = state.directory("100", True)
        self.assertEqual([item["name"] for item in root["contents"]], ["README-synthetic.txt", "nested"])
        self.assertEqual([item["id"] for item in root["contents"][1]["contents"]], ["f302", "f303"])
        for index, name in enumerate(pcloud.MEMBERS, 301):
            metadata = state.metadata[name]
            self.assertEqual(metadata["id"], "f" + str(index))
            self.assertEqual(metadata["fileid"], index)
            self.assertIs(metadata["isfolder"], False)
            self.assertEqual(metadata["size"], len(FILES[name]))
            self.assertEqual(metadata.get("modified", metadata["created"]), pcloud.MODIFIED)
        self.assertNotIn("modified", state.metadata[pcloud.MEMBERS[1]])
        self.assertNotEqual(state.metadata[pcloud.MEMBERS[0]]["created"], pcloud.MODIFIED)
        self.assertGreater((parsedate_to_datetime(state.link_expires) - datetime.now(timezone.utc)).total_seconds(), 550)
        root["contents"].clear()
        self.assertTrue(state.source_preserved())

    def test_recursive_listing_and_three_hashes_have_exact_events(self):
        with self.fixture() as (fixture, state):
            result = self.value(fixture, "/listfolder?folderid=100&recursive=1")
            self.assertEqual(result, {"result": 0, "metadata": state.directory("100", True)})
            for name in pcloud.MEMBERS:
                result = self.value(fixture, "/checksumfile?fileid=" + pcloud.FILE_IDS[name])
                self.assertEqual(result, {"result": 0, "metadata": state.metadata[name],
                                          "md5": hashlib.md5(FILES[name]).hexdigest(), "sha1": hashlib.sha1(FILES[name]).hexdigest()})
            self.assertEqual(state.events, [("list_recursive", "")] + [("checksum", name) for name in pcloud.MEMBERS])
            self.assertEqual((state.requests, state.authenticated, state.payload_bytes), (4, 4, 0))
            self.assertEqual(fixture.snapshot()["transport"]["failure_codes"], [])

    def test_all_samples_download_only_from_issued_owned_link(self):
        for name in pcloud.MEMBERS:
            with self.subTest(member=name), self.fixture() as (fixture, state):
                self.locate(fixture, name)
                number = pcloud.FILE_IDS[name]
                link = self.value(fixture, "/getfilelink?fileid=" + number)
                self.assertEqual(link, {"result": 0, "hosts": [f"127.0.0.1:{fixture.port}"],
                                       "path": "/download/" + number, "expires": state.link_expires})
                status, body, headers = self.request(fixture, link["path"])
                self.assertEqual(status, 200)
                self.assertEqual(body, FILES[name])
                self.assertEqual(hashlib.sha256(body).hexdigest(), pcloud.SOURCE_DIGESTS[name][1])
                self.assertEqual(headers["Content-Length"], str(len(FILES[name])))
                self.assertEqual(headers["Connection"], "close")
                self.value(fixture, "/checksumfile?fileid=" + number)
                expected = [("root_list", "")]
                if name.startswith("nested/"):
                    expected.append(("nested_list", "nested"))
                expected += [("link", name), ("content", name), ("checksum", name)]
                self.assertEqual(state.events, expected)
                self.assertEqual(state.requests, len(expected))
                self.assertEqual(state.payload_bytes, len(body))
                self.assertTrue(state.source_preserved())

    def test_missing_name_is_omitted_from_valid_metadata(self):
        with self.fixture() as (fixture, state):
            result = self.value(fixture, "/listfolder?folderid=100")
            self.assertEqual([item["name"] for item in result["metadata"]["contents"]], ["README-synthetic.txt", "nested"])
            self.assertNotIn("missing-synthetic.txt", json.dumps(result))
            self.assertEqual(state.events, [("root_list", "")])

    def test_wrong_saved_token_is_one_observed_401_without_refresh_hint(self):
        with self.fixture() as (fixture, state):
            status, body, headers = self.request(fixture, "/listfolder?folderid=100", token=self.wrong)
            self.assertEqual(status, 401)
            self.assertEqual(json.loads(body), {"result": 2000, "error": "synthetic token rejected"})
            self.assertNotIn("WWW-Authenticate", headers)
            self.assertEqual((state.requests, state.authenticated, state.auth_denied, state.unexpected), (1, 0, 1, 0))
            self.assertEqual(state.events, [("auth_denied", "")])
            self.assertNotIn(self.wrong.encode(), body)

    def test_member_denial_requires_positive_metadata_and_link(self):
        with self.fixture(self.state(pcloud.MEMBERS[0])) as (fixture, state):
            self.locate(fixture, pcloud.MEMBERS[0])
            self.value(fixture, "/getfilelink?fileid=301")
            status, body, _ = self.request(fixture, "/download/301")
            self.assertEqual(status, 403)
            self.assertEqual(json.loads(body), {"result": 2003, "error": "synthetic member denied"})
            self.assertEqual(state.events, [("root_list", ""), ("link", pcloud.MEMBERS[0]), ("content_denied", pcloud.MEMBERS[0])])
            self.assertEqual((state.member_denied, state.payload_bytes, state.unexpected), (1, 0, 0))

    def test_out_of_order_reads_cannot_fake_success_or_denial(self):
        for path in ("/download/301", "/getfilelink?fileid=301", "/checksumfile?fileid=301", "/listfolder?folderid=200"):
            with self.subTest(path=path), self.fixture(self.state(pcloud.MEMBERS[0])) as (fixture, state):
                self.assertEqual(self.request(fixture, path)[0], 400)
                self.assertEqual(state.events, [])
                self.assertEqual((state.unexpected, state.member_denied, state.payload_bytes), (1, 0, 0))
        with self.fixture() as (fixture, state):
            self.locate(fixture, pcloud.MEMBERS[0])
            self.assertEqual(self.request(fixture, "/download/301")[0], 400)
            self.assertEqual(state.payload_bytes, 0)

    def test_direct_write_guard_requires_stat_and_never_mutates(self):
        with self.fixture() as (fixture, state):
            original = state.source_snapshot()
            self.locate(fixture, pcloud.MEMBERS[0])
            self.value(fixture, "/checksumfile?fileid=301")
            status, body, _ = self.request(fixture, "/deletefile?fileid=301", method="POST")
            self.assertEqual((status, json.loads(body)), (405, {"status": "fixture_read_only"}))
            self.assertEqual(state.events[-1], ("write_denied", pcloud.MEMBERS[0]))
            self.assertEqual((state.rejected_mutations, state.unexpected, state.payload_bytes), (1, 0, 0))
            self.assertEqual(state.source_snapshot(), original)
        with self.fixture() as (fixture, state):
            self.assertEqual(self.request(fixture, "/deletefile?fileid=301", method="POST")[0], 400)
            self.assertEqual(state.rejected_mutations, 0)

    def test_oauth_routes_fail_closed_and_are_counted(self):
        for path, method in (("/oauth2_token", "POST"), ("/oauth2/authorize", "GET")):
            with self.subTest(path=path), self.fixture() as (fixture, state):
                status, body, _ = self.request(fixture, path, method=method)
                self.assertEqual(status, 400)
                self.assertEqual((state.oauth_requests, state.unexpected), (1, 1))
                self.assertEqual(state.events, [])
                self.assertNotIn(self.token.encode(), body)

    def test_queries_methods_and_path_aliases_are_closed(self):
        paths = ("/listfolder?recursive=1&folderid=100", "/listfolder?folderid=100&folderid=100",
                 "/listfolder?folderid=100&unexpected=1", "/listfolder?folderid=0100", "/listfolder?folderid=%31%30%30",
                 "/%6cistfolder?folderid=100", "//listfolder?folderid=100", "/./listfolder?folderid=100",
                 "https://127.0.0.1/listfolder?folderid=100", "/listfolder?folderid=0", "/download/301?x=1")
        for path in paths:
            with self.subTest(path=path), self.fixture() as (fixture, state):
                self.assertEqual(self.request(fixture, path)[0], 400)
                self.assertEqual(state.unexpected, 1)
                self.assertEqual(state.events, [])
        for method in ("PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT", "FROB"):
            with self.subTest(method=method), self.fixture() as (fixture, state):
                self.assertEqual(self.request(fixture, "/listfolder?folderid=100", method=method)[0], 400)
                self.assertEqual(state.unexpected, 1)

    def test_hosts_tokens_and_headers_are_strict(self):
        headers = ({"Host": "localhost"}, {"Host": "127.0.0.1:1"}, {"Authorization": "Basic synthetic"},
                   {"Authorization": "Bearer unapproved-synthetic-token"}, {"Cookie": "synthetic=value"},
                   {"Proxy-Authorization": "synthetic"}, {"Range": "bytes=0-1"}, {"Content-Encoding": "gzip"},
                   {"Transfer-Encoding": "chunked"}, {"X-Unexpected": "synthetic"}, {"Connection": "keep-alive"},
                   {"Accept-Encoding": "br"})
        for values in headers:
            with self.subTest(header=next(iter(values))), self.fixture() as (fixture, state):
                self.assertEqual(self.request(fixture, "/listfolder?folderid=100", headers=values)[0], 400)
                self.assertEqual(state.unexpected, 1)
                self.assertEqual(state.auth_denied, 0)

    def test_duplicate_and_folded_headers_are_rejected(self):
        for extra in (b"Host: 127.0.0.1\r\n", b"Authorization: Bearer synthetic-duplicate\r\n",
                      b"User-Agent: synthetic\r\n folded\r\n"):
            with self.subTest(extra_kind=extra.split(b":")[0]), self.fixture() as (fixture, state):
                result = self.raw(fixture, self.packet(fixture, extras=extra))
                self.assertTrue(result.startswith(b"HTTP/1.1 400"))
                self.assertEqual(state.unexpected, 1)
                self.assertEqual(state.events, [])

    def test_request_bodies_and_noncanonical_lengths_are_refused(self):
        for length, body in (("1", b"x"), ("00", b""), ("-1", b""), ("9999999999999999999", b"")):
            with self.subTest(length=length), self.fixture() as (fixture, state):
                packet = self.packet(fixture, extras=("Content-Length: " + length + "\r\n").encode()) + body
                self.raw(fixture, packet)
                self.assertEqual(state.unexpected, 1)
                # Noncanonical zero is refused but declares no payload bytes.
                if length == "00":
                    self.assertEqual(state.rejected_payload_bytes, 0)
                else:
                    self.assertGreater(state.rejected_payload_bytes, 0)
                self.assertLessEqual(state.rejected_payload_bytes, 4097)
                self.assertEqual(state.events, [])

    def test_truncated_headers_never_dispatch_or_expose_metadata(self):
        with self.fixture() as (fixture, state):
            with socket.create_connection(("127.0.0.1", fixture.port), timeout=2) as sock:
                with fixture.client_context().wrap_socket(sock, server_hostname="127.0.0.1") as client:
                    client.sendall(self.packet(fixture)[:-2])
                    client.shutdown(socket.SHUT_WR)
                    self.wait_for(lambda: fixture.snapshot()["transport"]["active_connections"] == 0)
            self.assertEqual(state.requests, 0)
            self.assertEqual(state.events, [])
            self.assertEqual(state.payload_bytes, 0)
            self.assertIn("tls_incomplete_http_headers", fixture.snapshot()["transport"]["failure_codes"])

    def test_header_and_request_line_budgets_stop_before_dispatch(self):
        for kind in ("line", "headers", "count"):
            with self.subTest(kind=kind), self.fixture() as (fixture, state):
                if kind == "line":
                    packet = self.packet(fixture, path="/" + "a" * 2200)
                elif kind == "headers":
                    packet = self.packet(fixture, extras=(b"User-Agent: " + b"x" * 1700 + b"\r\n") * 5)
                else:
                    packet = self.packet(fixture, extras=b"X-Foo: a\r\n" * 33)
                self.raw(fixture, packet)
                self.wait_for(lambda: fixture.snapshot()["transport"]["active_connections"] == 0)
                self.assertTrue(state.budget_exceeded)
                self.assertEqual(state.unexpected, 1)
                self.assertEqual(state.events, [])
                self.assertTrue(fixture.snapshot()["transport"]["failure_codes"])

    def test_request_and_response_budgets_are_sticky(self):
        with self.fixture() as (fixture, state):
            for _ in range(pcloud.MAX_REQUESTS):
                self.value(fixture, "/listfolder?folderid=100")
            self.assertEqual(self.request(fixture, "/listfolder?folderid=100")[0], 429)
            self.assertTrue(state.budget_exceeded)
            self.assertEqual(state.requests, pcloud.MAX_REQUESTS + 1)
        with self.fixture() as (fixture, state):
            state.response_bytes = pcloud.MAX_RESPONSE_BYTES
            with self.assertRaises(http.client.RemoteDisconnected):
                self.request(fixture, "/listfolder?folderid=100")
            self.wait_for(lambda: fixture.snapshot()["transport"]["active_connections"] == 0)
            self.assertTrue(state.budget_exceeded)
            self.assertTrue(fixture.snapshot()["transport"]["failure_codes"])

    def test_source_changes_are_refused_and_credentials_never_appear_in_snapshot(self):
        for change in ("file", "metadata", "token", "wrong", "mode"):
            with self.subTest(change=change), self.fixture() as (fixture, state):
                if change == "file": state.files[pcloud.MEMBERS[0]] += b"changed"
                if change == "metadata": state.metadata[pcloud.MEMBERS[0]]["size"] += 1
                if change == "token": state.token += "changed"
                if change == "wrong": state.wrong_token += "changed"
                if change == "mode": state.deny_member = pcloud.MEMBERS[0]
                self.assertEqual(self.request(fixture, "/listfolder?folderid=100")[0], 400)
                self.assertFalse(state.source_preserved())
                serialized = json.dumps(fixture.snapshot())
                self.assertNotIn(self.token, serialized)
                self.assertNotIn(self.wrong, serialized)

    def test_fixture_reuse_and_closed_access_are_refused(self):
        state = self.state()
        with self.fixture(state) as (fixture, _):
            path = Path(fixture.rclone_ca_args()[1])
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), fixture.ca_sha256)
        self.assertFalse(path.exists())
        self.assertTrue(state.cleanup_complete)
        with self.assertRaises(pcloud.PCloudError):
            fixture.client_context()
        with self.assertRaises(pcloud.PCloudError):
            with pcloud.serve_pcloud(self.root, state):
                pass
        self.assertEqual(list(self.root.iterdir()), [])

    def test_failed_start_removes_certificate_files_and_bound_listener(self):
        state = self.state()
        with patch.object(pcloud.BoundedHttpsServer, "start", side_effect=RuntimeError("synthetic startup")):
            with self.assertRaises(RuntimeError):
                pcloud.PCloudFixture(self.root, state)
        self.assertTrue(state.cleanup_complete)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_context_failure_closes_every_owned_resource(self):
        state = self.state()
        with self.assertRaisesRegex(ValueError, "synthetic body"):
            with self.fixture(state) as (fixture, _):
                raise ValueError("synthetic body")
        snapshot = fixture.snapshot()
        self.assertTrue(snapshot["cleanup_complete"])
        self.assertTrue(snapshot["certificate_cleanup"])
        self.assertEqual((snapshot["transport"]["active_connections"], snapshot["transport"]["active_workers"],
                          snapshot["transport"]["active_timers"]), (0, 0, 0))

    def test_cleanup_failure_propagates_and_can_be_reaped(self):
        state = self.state()
        manager = pcloud.serve_pcloud(self.root, state)
        fixture = manager.__enter__()
        self.fixtures.append(fixture)
        with patch.object(fixture._certificates, "close", return_value=False):
            with self.assertRaisesRegex(pcloud.PCloudError, "pcloud_cleanup_failed"):
                manager.__exit__(None, None, None)
        self.assertFalse(state.cleanup_complete)
        self.assertTrue(fixture.close())
        self.assertTrue(state.cleanup_complete)

    def test_parser_errors_are_sanitized_and_not_logged(self):
        with self.fixture() as (fixture, state):
            output = io.StringIO()
            with redirect_stderr(output):
                raw = self.raw(fixture, b"invalid synthetic-secret-request-line\r\n\r\n")
            self.assertNotIn(b"synthetic-secret", raw)
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(state.unexpected, 1)


if __name__ == "__main__":
    unittest.main()
