"""Synthetic Python HTTPS tests only; no rclone, callback, container or cloud."""
import base64
from contextlib import contextmanager, redirect_stderr
from email.message import Message
import hashlib
import http.client
import io
import json
from pathlib import Path
import secrets
import socket
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qsl, urlencode, urlsplit


LAB = Path(__file__).resolve().parents[1] / "provider-lab"
sys.path.insert(0, str(LAB))
sys.path.insert(0, str(LAB / "pcloud-oauth"))
import fixture_oauth as oauth


FILES = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
         "nested/space name.txt": b"Nested synthetic payload.\n", "nested/bytes.bin": bytes(range(256)) * 8}
BOUND_STATE = "AAECAwQFBgcICQoLDA0ODw"


class OAuthFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="oauth-fixture-unit-")
        self.root = Path(self.temp.name).resolve()
        self.credentials = tuple("synthetic-" + secrets.token_hex(16) for _ in range(5))
        self.fixtures = []

    def tearDown(self):
        failures = []
        try:
            for fixture in reversed(self.fixtures):
                try:
                    if not fixture.close():
                        failures.append("cleanup failed")
                    snapshot = fixture.snapshot()
                    if not snapshot["cleanup_complete"] or not snapshot["certificate_cleanup"]:
                        failures.append("owned material remains")
                    if snapshot["transport"] and any(snapshot["transport"][key] for key in
                            ("active_connections", "active_workers", "active_timers")):
                        failures.append("owned transport remains")
                except BaseException as exc:
                    failures.append("cleanup raised " + type(exc).__name__)
        finally:
            try:
                self.temp.cleanup()
            except BaseException as exc:
                failures.append("temporary cleanup raised " + type(exc).__name__)
        self.assertEqual(failures, [])

    def state(self):
        return oauth.OAuthState(FILES, *self.credentials)

    @contextmanager
    def fixture(self, state=None, *, bind=True):
        state = state or self.state()
        with oauth.serve_oauth(self.root, state) as fixture:
            self.fixtures.append(fixture)
            if bind:
                state.bind_state(BOUND_STATE)
            yield fixture, state

    def request(self, fixture, path, *, method="GET", headers=None, body=None):
        conn = http.client.HTTPSConnection("127.0.0.1", fixture.port, timeout=4, context=fixture.client_context())
        try:
            conn.request(method, path, headers=headers or {}, body=body)
            response = conn.getresponse()
            data = response.read(oauth.MAX_RESPONSE_BYTES + 1)
            self.assertLessEqual(len(data), oauth.MAX_RESPONSE_BYTES)
            return response.status, data, dict(response.getheaders())
        finally:
            conn.close()

    def authorize_path(self, fixture_state, **changes):
        values = dict(access_type="offline", client_id=fixture_state.client_id, redirect_uri=oauth.CALLBACK,
                      response_type="code", state=BOUND_STATE)
        values.update(changes)
        return "/oauth2/authorize?" + urlencode(sorted(values.items()))

    def authorize(self, fixture, state):
        status, body, headers = self.request(fixture, self.authorize_path(state))
        self.assertEqual(status, 302)
        self.assertEqual(json.loads(body), {"status": "synthetic_code_issued"})
        location = urlsplit(headers["Location"])
        self.assertEqual((location.scheme, location.netloc, location.path, location.fragment),
                         ("http", "localhost:53682", "/", ""))
        self.assertEqual(parse_qsl(location.query), sorted({"code": state.code, "hostname": fixture.host,
                                                         "locationid": "1", "state": BOUND_STATE}.items()))

    def token_body(self, state, **changes):
        values = dict(code=state.code, grant_type="authorization_code", redirect_uri=oauth.CALLBACK)
        values.update(changes)
        return urlencode(sorted(values.items())).encode("ascii")

    def basic(self, state):
        return "Basic " + base64.b64encode((state.client_id + ":" + state.client_secret).encode()).decode()

    def exchange(self, fixture, state, *, body=None, auth=None, headers=None):
        values = {"Content-Type": "application/x-www-form-urlencoded", "Authorization": self.basic(state) if auth is None else auth}
        values.update(headers or {})
        return self.request(fixture, "/oauth2_token", method="POST", headers=values,
                            body=self.token_body(state) if body is None else body)

    def issued(self, fixture, state):
        self.authorize(fixture, state)
        status, body, headers = self.exchange(fixture, state)
        self.assertEqual(status, 200)
        self.assertNotIn("Location", headers)
        self.assertEqual(json.loads(body), {"result": 0, "access_token": state.token, "token_type": "bearer", "uid": 10001})

    def read(self, fixture, state, path, **kwargs):
        return self.request(fixture, path, headers={"Authorization": "Bearer " + state.token}, **kwargs)

    def raw(self, fixture, packet):
        result = bytearray()
        with socket.create_connection(("127.0.0.1", fixture.port), timeout=4) as sock:
            with fixture.client_context().wrap_socket(sock, server_hostname="127.0.0.1") as client:
                try:
                    client.sendall(packet)
                    while len(result) < 8192:
                        block = client.recv(8192 - len(result))
                        if not block:
                            break
                        result.extend(block)
                except OSError:
                    pass
        return bytes(result)

    def packet(self, fixture, path, *, method="GET", extra=b"", body=b""):
        return (f"{method} {path} HTTP/1.1\r\nHost: {fixture.host}\r\n").encode() + extra + b"\r\n" + body

    def wait_for(self, condition):
        end = time.monotonic() + 4
        while time.monotonic() < end:
            if condition():
                return
            time.sleep(0.005)
        self.fail("bounded condition not observed")

    def test_positive_exact_six_request_chain_and_independent_bytes(self):
        with self.fixture() as (fixture, state):
            before = state.source_snapshot()
            self.issued(fixture, state)
            root = json.loads(self.read(fixture, state, "/listfolder?folderid=100")[1])
            self.assertEqual(root["metadata"]["contents"][0]["fileid"], 301)
            checksum = json.loads(self.read(fixture, state, "/checksumfile?fileid=301")[1])
            self.assertEqual(checksum["md5"], hashlib.md5(FILES[oauth.MEMBERS[0]]).hexdigest())
            link = json.loads(self.read(fixture, state, "/getfilelink?fileid=301")[1])
            self.assertEqual(link["hosts"], [fixture.host])
            self.assertEqual(link["path"], "/download/301")
            status, body, headers = self.read(fixture, state, link["path"])
            self.assertEqual((status, body), (200, FILES[oauth.MEMBERS[0]]))
            self.assertEqual(hashlib.sha256(body).hexdigest(), "1e901527b93ae84dc9d95a8aa76bbc12d7d77dbf8ab449333c172cfc909c639e")
            self.assertNotIn("Location", headers)
            self.assertEqual(state.events, [("authorize", ""), ("token", ""), *oauth.READ_STEPS])
            self.assertEqual((state.requests, state.oauth_requests, state.authorize_requests, state.token_requests,
                              state.authenticated, state.payload_bytes), (6, 2, 1, 1, 4, 62))
            self.assertEqual(state.phase, "complete")
            self.assertEqual(state.source_snapshot(), before)
            self.assertTrue(state.source_preserved())
            self.assertFalse(state.failed)
            self.assertEqual(fixture.snapshot()["transport"]["failure_codes"], [])
        self.assertTrue(state.cleanup_complete)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_credential_types_shape_distinctness_and_source_are_closed(self):
        for bad in ("short", True, 123, "x" * 129, "x" * 16 + "\r\n", "x" * 16 + ":"):
            with self.subTest(kind=type(bad).__name__):
                with self.assertRaisesRegex(oauth.OAuthError, "oauth_invalid_fixture_credentials"):
                    oauth.OAuthState(FILES, bad, *self.credentials[1:])
        with self.assertRaises(oauth.OAuthError):
            oauth.OAuthState(FILES, self.credentials[1], *self.credentials[1:])
        altered = dict(FILES)
        altered[oauth.MEMBERS[0]] += b"changed"
        with self.assertRaises(oauth.PCloudError):
            oauth.OAuthState(altered, *self.credentials)

    def test_binding_requires_started_fixture_exact_state_and_is_one_use(self):
        with self.assertRaisesRegex(oauth.OAuthError, "oauth_state_binding_refused"):
            self.state().bind_state(BOUND_STATE)
        for value in (None, "", True, BOUND_STATE + "=", BOUND_STATE[:-1] + "x", "A" * 21):
            with self.subTest(kind=type(value).__name__), self.fixture(bind=False) as (_, state):
                with self.assertRaises(oauth.OAuthError):
                    state.bind_state(value)
                self.assertTrue(state.failed)
        with self.fixture() as (_, state):
            with self.assertRaises(oauth.OAuthError):
                state.bind_state(BOUND_STATE)
            self.assertTrue(state.failed)

    def test_authorize_requires_binding_and_exact_five_fields(self):
        with self.fixture(bind=False) as (fixture, state):
            self.assertEqual(self.request(fixture, self.authorize_path(state))[0], 400)
            self.assertEqual(state.events, [])
        variants = [dict(state=""), dict(state="wrong"), dict(client_id="wrong"), dict(access_type="online"),
                    dict(redirect_uri="http://127.0.0.1:53682/"), dict(response_type="token"), dict(scope="read")]
        for changes in variants:
            with self.subTest(field=next(iter(changes))), self.fixture() as (fixture, state):
                self.assertEqual(self.request(fixture, self.authorize_path(state, **changes))[0], 400)
                self.assertTrue(state.failed)
                self.assertFalse(state.token_issued)
                self.assertEqual(state.events, [])

    def test_authorize_duplicate_missing_and_noncanonical_query_are_rejected(self):
        for mutation in ("duplicate", "missing", "order", "escape", "fragment"):
            with self.subTest(mutation=mutation), self.fixture() as (fixture, state):
                path = self.authorize_path(state)
                if mutation == "duplicate": path += "&state=" + BOUND_STATE
                if mutation == "missing": path = path.split("&state=")[0]
                if mutation == "order": path = "/oauth2/authorize?" + "&".join(reversed(path.split("?", 1)[1].split("&")))
                if mutation == "escape": path = path.replace("%3A", "%3a")
                if mutation == "fragment": path += "#fragment"
                self.assertEqual(self.request(fixture, path)[0], 400)
                self.assertFalse(state.token_issued)

    def test_authorize_replay_poisoning_prevents_later_token_issuance(self):
        with self.fixture() as (fixture, state):
            self.authorize(fixture, state)
            self.assertEqual(self.request(fixture, self.authorize_path(state))[0], 400)
            self.assertEqual(self.exchange(fixture, state)[0], 400)
            self.assertEqual(state.events, [("authorize", "")])
            self.assertFalse(state.token_issued)

    def test_exchange_requires_authorize_before_any_token(self):
        with self.fixture() as (fixture, state):
            self.assertEqual(self.exchange(fixture, state)[0], 400)
            self.assertEqual(state.events, [])
            self.assertFalse(state.token_issued)

    def test_exchange_wrong_client_or_mixed_auth_is_rejected(self):
        for auth in ("", "Bearer synthetic-token", "Basic " + base64.b64encode(b"wrong:wrong").decode(), "Basic !!!"):
            with self.subTest(style=auth.split(" ")[0]), self.fixture() as (fixture, state):
                self.authorize(fixture, state)
                self.assertEqual(self.exchange(fixture, state, auth=auth)[0], 400)
                self.assertEqual(state.auth_denied, 1)
                self.assertFalse(state.token_issued)
        with self.fixture() as (fixture, state):
            self.authorize(fixture, state)
            body = self.token_body(state, client_id=state.client_id, client_secret=state.client_secret)
            self.assertEqual(self.exchange(fixture, state, body=body)[0], 400)
            self.assertFalse(state.token_issued)

    def test_exchange_code_grant_redirect_duplicates_and_order_are_exact(self):
        for mutation in ("code", "grant", "redirect", "duplicate", "order", "extra"):
            with self.subTest(mutation=mutation), self.fixture() as (fixture, state):
                self.authorize(fixture, state)
                body = self.token_body(state)
                if mutation == "code": body = self.token_body(state, code="x" * len(state.code))
                if mutation == "grant": body = self.token_body(state, grant_type="client_credentials")
                if mutation == "redirect": body = self.token_body(state, redirect_uri="http://127.0.0.1:53682/")
                if mutation == "duplicate": body += b"&code=" + state.code.encode()
                if mutation == "order": body = b"&".join(reversed(body.split(b"&")))
                if mutation == "extra": body += b"&unknown=1"
                self.assertEqual(self.exchange(fixture, state, body=body)[0], 400)
                self.assertEqual(state.events, [("authorize", "")])
                self.assertFalse(state.token_issued)

    def test_bounded_token_form_is_consumed_before_semantic_rejection(self):
        # A response followed by TLS close with an unread form races the client's
        # body write. Prove body consumption independently of OS socket timing.
        for failure in ("duplicate", "unknown_field", "wrong_secret", "wrong_type", "wrong_order", "already_failed"):
            with self.subTest(failure=failure):
                state = self.state()
                state.phase = "bound" if failure == "wrong_order" else "authorized"
                state.failed = failure == "already_failed"
                state.deadline = time.monotonic() + 3
                body = self.token_body(state)
                if failure == "duplicate": body += b"&code=" + state.code.encode()
                if failure == "unknown_field": body += b"&extra=1"
                handler = object.__new__(oauth._OAuthHandler)
                handler.server = SimpleNamespace(state=state, server_address=("127.0.0.1", 12345))
                handler.command, handler.path, handler._counted = "POST", "/oauth2_token", False
                handler.raw_requestline = b"POST /oauth2_token HTTP/1.1\r\n"
                handler.headers = Message()
                for key, value in {"Authorization": "Basic wrong" if failure == "wrong_secret" else self.basic(state),
                                   "Content-Type": "application/json" if failure == "wrong_type" else "application/x-www-form-urlencoded",
                                   "Host": "127.0.0.1:12345", "Content-Length": str(len(body))}.items():
                    handler.headers[key] = value
                handler.rfile = io.BytesIO(body)
                handler._json = Mock()
                handler.dispatch()
                self.assertEqual(handler.rfile.tell(), len(body))
                handler._json.assert_called_once_with(400, {"status": "fixture_invalid_request"})
                self.assertTrue(state.failed)
                self.assertFalse(state.token_issued)
                self.assertEqual(state.events, [])

    def test_invalid_form_in_separate_tls_record_receives_complete_denial(self):
        for failure in ("duplicate", "wrong_secret"):
            with self.subTest(failure=failure), self.fixture() as (fixture, state):
                self.authorize(fixture, state)
                body = self.token_body(state)
                if failure == "duplicate": body += b"&code=" + state.code.encode()
                ready = threading.Event()
                original = oauth._OAuthHandler._read_form

                def announce_read(handler):
                    ready.set()
                    return original(handler)

                conn = http.client.HTTPSConnection("127.0.0.1", fixture.port, timeout=4, context=fixture.client_context())
                try:
                    with patch.object(oauth._OAuthHandler, "_read_form", announce_read):
                        conn.putrequest("POST", "/oauth2_token")
                        conn.putheader("Content-Type", "application/x-www-form-urlencoded")
                        conn.putheader("Content-Length", str(len(body)))
                        conn.putheader("Authorization", "Basic wrong" if failure == "wrong_secret" else self.basic(state))
                        conn.endheaders()
                        self.assertTrue(ready.wait(1), "server did not reach bounded body read")
                        conn.send(body)
                        response = conn.getresponse()
                        self.assertEqual(response.status, 400)
                        self.assertEqual(json.loads(response.read()), {"status": "fixture_invalid_request"})
                finally:
                    conn.close()
                self.assertFalse(state.token_issued)
                self.assertEqual(state.events, [("authorize", "")])
                self.assertTrue(state.failed)

    def test_ambiguous_or_oversized_token_framing_is_not_consumed(self):
        for length, extra in (("0", None), ("01", None), ("4097", None), ("124", ("Content-Length", "124")),
                              ("124", ("Transfer-Encoding", "chunked"))):
            with self.subTest(length=length, extra=extra):
                state = self.state()
                state.phase, state.deadline = "authorized", time.monotonic() + 3
                handler = object.__new__(oauth._OAuthHandler)
                handler.server = SimpleNamespace(state=state, server_address=("127.0.0.1", 12345))
                handler.command, handler.path, handler._counted = "POST", "/oauth2_token", False
                handler.raw_requestline = b"POST /oauth2_token HTTP/1.1\r\n"
                handler.headers = Message()
                for key, value in {"Host": "127.0.0.1:12345", "Content-Length": length,
                                   "Content-Type": "application/x-www-form-urlencoded", "Authorization": self.basic(state)}.items():
                    handler.headers[key] = value
                if extra: handler.headers[extra[0]] = extra[1]
                handler.rfile = io.BytesIO(b"untrusted body must not be consumed")
                handler._json = Mock()
                handler.dispatch()
                self.assertEqual(handler.rfile.tell(), 0)
                self.assertTrue(state.failed)
                self.assertFalse(state.token_issued)
                self.assertEqual(state.events, [])

    def test_token_exchange_replay_cannot_reissue_or_unlock_reads(self):
        with self.fixture() as (fixture, state):
            self.issued(fixture, state)
            self.assertEqual(self.exchange(fixture, state)[0], 400)
            self.assertEqual(self.read(fixture, state, "/listfolder?folderid=100")[0], 400)
            self.assertEqual(state.events, [("authorize", ""), ("token", "")])
            self.assertEqual(state.payload_bytes, 0)

    def test_preexchange_and_out_of_order_api_reads_never_dispatch(self):
        for phase, path in (("before", "/listfolder?folderid=100"), ("authorized", "/listfolder?folderid=100"),
                            ("exchanged", "/checksumfile?fileid=301"), ("exchanged", "/listfolder?folderid=100&recursive=1"),
                            ("root", "/getfilelink?fileid=301"), ("root", "/checksumfile?fileid=302")):
            with self.subTest(phase=phase, path=path), self.fixture() as (fixture, state):
                if phase == "authorized": self.authorize(fixture, state)
                if phase in ("exchanged", "root"): self.issued(fixture, state)
                if phase == "root": self.assertEqual(self.read(fixture, state, "/listfolder?folderid=100")[0], 200)
                before = list(state.events)
                self.assertEqual(self.read(fixture, state, path)[0], 400)
                self.assertEqual(state.events, before)
                self.assertEqual(state.payload_bytes, 0)

    def test_wrong_issued_bearer_token_does_not_read_metadata(self):
        with self.fixture() as (fixture, state):
            self.issued(fixture, state)
            self.assertEqual(self.request(fixture, "/listfolder?folderid=100", headers={"Authorization": "Bearer " + state.wrong_token})[0], 400)
            self.assertEqual(state.auth_denied, 1)
            self.assertEqual(state.events, [("authorize", ""), ("token", "")])

    def test_method_aliases_unknown_routes_and_mutations_are_closed(self):
        for method, path in (("POST", "/deletefile?fileid=301"), ("DELETE", "/download/301"), ("HEAD", "/oauth2/authorize"),
                             ("OPTIONS", "/oauth2_token"), ("GET", "/oauth2_token"), ("GET", "/oauth2/authorize"),
                             ("GET", "/oauth2/authorize/"), ("GET", "https://example.invalid/oauth2/authorize")):
            with self.subTest(method=method, path=path), self.fixture() as (fixture, state):
                status = self.request(fixture, path, method=method)[0]
                self.assertIn(status, (400, 405))
                self.assertTrue(state.failed)
                self.assertEqual(state.events, [])

    def test_host_cookie_proxy_range_encoding_and_unknown_headers_are_rejected(self):
        for headers in ({"Host": "localhost:1234"}, {"Cookie": "synthetic=1"}, {"Proxy-Authorization": "synthetic"},
                        {"Range": "bytes=0-1"}, {"Content-Encoding": "gzip"}, {"Transfer-Encoding": "chunked"},
                        {"Authorization": "Bearer synthetic"}, {"Accept": "*/*"}, {"X-Unknown": "1"}):
            with self.subTest(field=next(iter(headers))), self.fixture() as (fixture, state):
                self.assertEqual(self.request(fixture, self.authorize_path(state), headers=headers)[0], 400)
                self.assertEqual(state.events, [])
                self.assertTrue(state.failed)

    def test_duplicate_headers_and_raw_malformed_names_cannot_be_dropped(self):
        for extra in (b"Host: 127.0.0.1:1\r\n", b"User-Agent: a\r\nUser-Agent: b\r\n",
                      b"Authorization : Basic synthetic\r\n", b": Basic synthetic\r\n",
                      b"User-Agent: a\r\n folded\r\n", b"Cookie\t: a\r\n"):
            with self.subTest(field=extra.split(b":")[0]), self.fixture() as (fixture, state):
                self.raw(fixture, self.packet(fixture, self.authorize_path(state), extra=extra))
                self.wait_for(lambda: fixture.snapshot()["transport"]["active_connections"] == 0)
                self.assertTrue(state.failed)
                self.assertEqual(state.events, [])
                self.assertFalse(state.token_issued)

    def test_bare_lf_and_incomplete_headers_do_not_dispatch(self):
        for mutation in ("bare_lf", "incomplete"):
            with self.subTest(mutation=mutation), self.fixture() as (fixture, state):
                packet = self.packet(fixture, self.authorize_path(state))
                if mutation == "bare_lf": packet = packet.replace(b"\r\n", b"\n")
                else: packet = packet[:-2]
                with socket.create_connection(("127.0.0.1", fixture.port), timeout=2) as sock:
                    with fixture.client_context().wrap_socket(sock, server_hostname="127.0.0.1") as client:
                        client.sendall(packet)
                        client.shutdown(socket.SHUT_WR)
                        self.wait_for(lambda: fixture.snapshot()["transport"]["active_connections"] == 0)
                self.assertEqual(state.events, [])
                self.assertFalse(state.token_issued)
                self.assertTrue(fixture.snapshot()["transport"]["failure_codes"])

    def test_body_shape_type_length_and_payload_ceiling_are_closed(self):
        for headers in ({"Content-Type": "application/json"}, {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}):
            with self.subTest(field=next(iter(headers))), self.fixture() as (fixture, state):
                self.authorize(fixture, state)
                self.assertEqual(self.exchange(fixture, state, headers=headers)[0], 400)
                self.assertFalse(state.token_issued)
        # Send only the invalid framing. The fixture must reject immediately,
        # without waiting for (or consuming) an absent/oversized declared body.
        for length in ("0", "01", "4097"):
            with self.subTest(length=length), self.fixture() as (fixture, state):
                self.authorize(fixture, state)
                self.assertEqual(self.exchange(fixture, state, body=b"", headers={"Content-Length": length})[0], 400)
                self.assertFalse(state.token_issued)
        with self.fixture() as (fixture, state):
            self.assertEqual(self.request(fixture, self.authorize_path(state), body=b"x")[0], 400)
            self.assertEqual(state.rejected_payload_bytes, 1)

    def test_truncated_token_body_deadline_cannot_issue_token(self):
        with self.fixture() as (fixture, state):
            self.authorize(fixture, state)
            body = self.token_body(state)
            extra = (f"Authorization: {self.basic(state)}\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                     f"Content-Length: {len(body)}\r\n").encode()
            packet = self.packet(fixture, "/oauth2_token", method="POST", extra=extra, body=body[:-1])
            self.raw(fixture, packet)
            self.wait_for(lambda: fixture.snapshot()["transport"]["active_connections"] == 0)
            self.assertFalse(state.token_issued)
            self.assertEqual(state.events, [("authorize", "")])
            self.assertTrue(fixture.snapshot()["transport"]["failure_codes"])

    def test_header_limits_mark_failure_before_oauth(self):
        for extra in (b"User-Agent: " + b"x" * 2200 + b"\r\n", b"X-Foo: a\r\n" * 33):
            with self.fixture() as (fixture, state):
                self.raw(fixture, self.packet(fixture, self.authorize_path(state), extra=extra))
                self.wait_for(lambda: fixture.snapshot()["transport"]["active_connections"] == 0)
                self.assertTrue(state.budget_exceeded)
                self.assertTrue(state.failed)
                self.assertEqual(state.events, [])

    def test_request_response_and_lifetime_limits_remain_sticky(self):
        with self.fixture() as (fixture, state):
            state.requests = oauth.MAX_REQUESTS
            self.assertEqual(self.request(fixture, self.authorize_path(state))[0], 429)
            self.assertTrue(state.budget_exceeded)
            self.assertTrue(state.failed)
        with self.fixture() as (fixture, state):
            state.response_bytes = oauth.MAX_RESPONSE_BYTES
            with self.assertRaises(http.client.RemoteDisconnected):
                self.request(fixture, self.authorize_path(state))
            self.assertTrue(state.budget_exceeded)
            self.assertFalse(state.token_issued)
        with self.fixture() as (fixture, state):
            state.deadline = time.monotonic() - 1
            self.assertEqual(self.request(fixture, self.authorize_path(state))[0], 429)
            self.assertTrue(state.budget_exceeded)

    def test_admission_and_close_during_handshake_reap_all_workers(self):
        with self.fixture() as (fixture, state):
            clients = []
            try:
                for _ in range(3):
                    clients.append(socket.create_connection(("127.0.0.1", fixture.port), timeout=2))
                self.wait_for(lambda: fixture.snapshot()["transport"]["admission_denied"] == 1)
                self.assertTrue(fixture.close())
                self.assertEqual(state.events, [])
                self.assertTrue(fixture.snapshot()["transport"]["failure_codes"])
            finally:
                for client in clients:
                    client.close()

    def test_source_credentials_and_bound_state_changes_are_detected_after_cleanup(self):
        for change in ("file", "metadata", "client_id", "client_secret", "code", "token", "wrong_token", "bound", "deny_member"):
            with self.subTest(change=change):
                with self.assertRaisesRegex(oauth.OAuthError, "oauth_source_changed"):
                    with self.fixture() as (fixture, state):
                        if change == "file": state.files[oauth.MEMBERS[0]] += b"changed"
                        elif change == "metadata": state.metadata[oauth.MEMBERS[0]]["size"] += 1
                        elif change == "bound": state._bound_state = "A" * 22
                        elif change == "deny_member": state.deny_member = oauth.MEMBERS[0]
                        else: setattr(state, change, getattr(state, change) + "changed")
                        self.assertFalse(state.source_preserved())
                        self.assertEqual(self.request(fixture, self.authorize_path(state))[0], 400)
                        self.assertFalse(state.token_issued)
                self.assertTrue(fixture.cleanup_complete)

    def test_snapshots_never_include_credentials_code_callback_state_or_body(self):
        with self.fixture() as (fixture, state):
            self.issued(fixture, state)
            serialized = json.dumps(fixture.snapshot())
            for value in (*self.credentials, BOUND_STATE, *[body.decode("latin1") for body in FILES.values()]):
                self.assertNotIn(value, serialized)

    def test_reuse_closed_ca_and_start_failure_leave_no_owned_material(self):
        state = self.state()
        with self.fixture(state) as (fixture, _):
            path = Path(fixture.rclone_ca_args()[1])
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), fixture.ca_sha256)
        self.assertFalse(path.exists())
        with self.assertRaises(oauth.OAuthError):
            fixture.client_context()
        with self.assertRaises(oauth.OAuthError):
            fixture.rclone_ca_args()
        with self.assertRaises(oauth.OAuthError):
            oauth.OAuthFixture(self.root, state)
        failed = self.state()
        with patch.object(oauth.BoundedHttpsServer, "start", side_effect=RuntimeError("synthetic startup")):
            with self.assertRaises(RuntimeError):
                oauth.OAuthFixture(self.root, failed)
        self.assertTrue(failed.cleanup_complete)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_body_exception_and_cleanup_failure_propagate_but_reap_resources(self):
        with self.assertRaisesRegex(ValueError, "synthetic body"):
            with self.fixture() as (fixture, state):
                raise ValueError("synthetic body")
        self.assertTrue(state.cleanup_complete)
        manager = oauth.serve_oauth(self.root, self.state())
        fixture = manager.__enter__()
        self.fixtures.append(fixture)
        with patch.object(fixture._certificates, "close", return_value=False):
            with self.assertRaisesRegex(oauth.OAuthError, "oauth_cleanup_failed"):
                manager.__exit__(None, None, None)
        self.assertFalse(fixture.cleanup_complete)
        self.assertTrue(fixture.state.failed)
        self.assertTrue(fixture.close())
        self.assertTrue(fixture.state.failed)

    def test_cleanup_exception_still_attempts_every_resource_and_stays_failed(self):
        with self.fixture() as (fixture, state):
            original_material_close = fixture._certificates.close
            with patch.object(fixture._transport, "close", side_effect=RuntimeError("synthetic cleanup")), \
                    patch.object(fixture._certificates, "close", wraps=original_material_close) as material_close:
                with self.assertRaisesRegex(oauth.OAuthError, "oauth_cleanup_failed"):
                    fixture.close()
                material_close.assert_called_once_with()
            self.assertFalse(state.cleanup_complete)
            self.assertTrue(state.failed)
            self.assertTrue(fixture.close())
            self.assertTrue(state.failed)

    def test_parser_errors_do_not_log_or_echo_input(self):
        with self.fixture() as (fixture, state):
            output = io.StringIO()
            with redirect_stderr(output):
                result = self.raw(fixture, b"invalid synthetic-secret-request-line\r\n\r\n")
            self.assertNotIn(b"synthetic-secret", result)
            self.assertEqual(output.getvalue(), "")
            self.assertTrue(state.failed)
            self.assertEqual(state.events, [])


if __name__ == "__main__":
    unittest.main()
