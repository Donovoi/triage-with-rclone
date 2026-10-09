"""Hosted-only synthetic HTTPS component checks; no rclone or provider runs.

Do not spoof the hosted guard to run this module on a workstation. These tests
prove fixture wire behavior only, not OAuth client compatibility or acceptance.
"""
import base64
from contextlib import contextmanager
import errno
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import sys
import tempfile
import time
import types
import unittest
from urllib.parse import parse_qs, urlencode, urlsplit


LAB = Path(__file__).resolve().parents[1] / "provider-lab"
FILES = {
    "README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
    "nested/space name.txt": b"Nested synthetic payload.\n",
    "nested/bytes.bin": bytes(range(256)) * 8,
}
METADATA = "/storage/v1/b/synthetic-bucket/o/README-synthetic.txt?alt=json&prettyPrint=false"
MEDIA = "/media/README-synthetic.txt"
CALLBACK = "http://localhost:53682/"
SCOPE = "https://www.googleapis.com/auth/devstorage.read_write"
README_SHA256 = "1e901527b93ae84dc9d95a8aa76bbc12d7d77dbf8ab449333c172cfc909c639e"
MAX_REPLY = 16384


def _listener_outcome(port):
    # A bounded observation, not a Windows root-cause assumption. Timeout is
    # still a failure: only an explicit refusal proves this probe's condition.
    try:
        connection = socket.create_connection(("127.0.0.1", port), timeout=5)
    except ConnectionRefusedError:
        return "refused"
    except TimeoutError:
        return "timeout"
    except OSError as error:
        return "refused" if error.errno in (errno.ECONNREFUSED, 10061) else "other_os_error"
    except Exception:
        return "probe_error"
    try:
        connection.close()
    except Exception:
        return "connection_close_failed"
    return "accepted"


def _cleanup_observation(fixture, root):
    checks = dict.fromkeys(("fixture_closed", "fixture_complete", "source_preserved",
        "transport_complete", "connections_closed", "workers_joined", "timers_joined", "material_removed"), False)
    try:
        checks["fixture_closed"] = fixture.close() is True
    except Exception:
        pass
    try:
        snapshot = fixture.snapshot()
    except Exception:
        snapshot = None
    if type(snapshot) is dict:
        checks["fixture_complete"] = snapshot.get("cleanup_complete") is True
        transport = snapshot.get("transport")
        if type(transport) is dict:
            checks["transport_complete"] = transport.get("cleanup_complete") is True
            for check_name, field in (("connections_closed", "active_connections"),
                    ("workers_joined", "active_workers"), ("timers_joined", "active_timers")):
                checks[check_name] = type(transport.get(field)) is int and transport[field] == 0
    try:
        checks["source_preserved"] = fixture.state.source_preserved() is True
    except Exception:
        pass
    try:
        checks["material_removed"] = not any(root.iterdir())
    except Exception:
        pass
    try:
        outcome = _listener_outcome(fixture.port)
    except Exception:
        outcome = "probe_error"
    return checks, outcome


def _finish_cleanup(fixtures, root, uncertain):
    # Each predicate is observed even after another one fails. Export only
    # these fixed labels, never exception text, paths, socket addresses or keys.
    failures = {"constructor_unproved"} if uncertain else set()
    for fixture, material_root in reversed(fixtures):
        checks, outcome = _cleanup_observation(fixture, material_root)
        failures.update(name for name, passed in checks.items() if not passed)
        if outcome != "refused":
            failures.add("listener_" + outcome)
    if not failures:
        try:
            shutil.rmtree(root)
            if root.exists():
                failures.add("temporary_remove_failed")
        except Exception:
            failures.add("temporary_remove_failed")
    return sorted(failures)


class GcsOAuthWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Guard before importing certificate dependencies or creating any path,
        # socket, TLS material or worker. No test patches these environment keys.
        if (os.environ.get("GITHUB_ACTIONS") != "true"
                or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
            raise unittest.SkipTest("GCS wire tests require the actual GitHub-hosted runner")
        path = LAB / "gcs-oauth" / "fixture_oauth.py"
        module = types.ModuleType("gcs_oauth_hosted_wire_fixture")
        module.__file__ = str(path)
        sys.path.insert(0, str(LAB))
        try:
            exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
        finally:
            sys.path.remove(str(LAB))
        cls.fixture_module = module

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="gcs-oauth-hosted-wire-")).resolve()
        self.fixtures = []
        self.uncertain = False

    def tearDown(self):
        # No TemporaryDirectory finalizer: never remove material under a worker
        # whose shutdown is unproved, even when a test failed earlier.
        failures = _finish_cleanup(self.fixtures, self.root, self.uncertain)
        self.assertFalse(failures, "owned fixture cleanup unproved; private root retained: " + ",".join(failures))

    @contextmanager
    def fixture(self, mode="positive"):
        values = tuple(secrets.token_hex(24) for _ in range(9))
        self.assertEqual(len(set(values)), 9, "generated credential collision")
        bound, alternate = secrets.token_urlsafe(16), secrets.token_urlsafe(16)
        self.assertTrue(bound != alternate, "generated state collision")
        state = self.fixture_module.OAuthState(
            FILES, *values[:7], mode=mode, alternate_state=alternate,
            alternate_code=values[7], alternate_secret=values[8])
        state.bind_state(bound)
        root = self.root / ("case-" + str(len(self.fixtures)))
        root.mkdir(mode=0o700)
        try:
            fixture = self.fixture_module.OAuthFixture(root, state)
        except BaseException:
            self.uncertain = True
            raise
        self.fixtures.append((fixture, root))
        try:
            yield fixture, state, bound
        finally:
            self.assertTrue(fixture.close(), "owned TLS fixture did not close")
            self.assertTrue(state.source_preserved(), "synthetic source or credentials changed")

    def synchronized(self, state):
        self.assertTrue(state.lock.acquire(timeout=4), "fixture dispatch exceeded its bound")
        state.lock.release()

    def request(self, fixture, target, *, method="GET", body=None, headers=None):
        context = fixture.client_context()
        self.assertTrue(context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED)
        connection = http.client.HTTPSConnection("127.0.0.1", fixture.port, timeout=4, context=context)
        try:
            connection.request(method, target, body=body, headers=headers or {})
            response = connection.getresponse()
            content = response.read(MAX_REPLY + 1)
            self.assertLessEqual(len(content), MAX_REPLY)
            lengths = [value for key, value in response.getheaders() if key.lower() == "content-length"]
            self.assertEqual(lengths, [str(len(content))])
            self.synchronized(fixture.state)
            return response.status, content, dict(response.getheaders())
        finally:
            connection.close()

    def authorize_target(self, state, bound):
        return "/oauth/authorize?" + urlencode(sorted({
            "access_type": "offline", "client_id": state.client_id,
            "redirect_uri": CALLBACK, "response_type": "code", "scope": SCOPE,
            "state": bound}.items()))

    def authorize(self, fixture, state, bound):
        status, body, headers = self.request(fixture, self.authorize_target(state, bound))
        self.assertEqual(status, 302)
        self.assertEqual(json.loads(body), {"status": "synthetic_authorization"})
        redirect = urlsplit(headers["Location"])
        self.assertTrue((redirect.scheme, redirect.netloc, redirect.path, redirect.fragment)
                        == ("http", "localhost:53682", "/", ""), "redirect authority changed")
        return parse_qs(redirect.query, keep_blank_values=True, strict_parsing=True)

    def form(self, state, *, basic=False, refresh=False):
        secret = state.alternate_secret if state.mode == "wrong_client_secret" else state.client_secret
        code = state.alternate_code if state.mode == "invalid_code" else state.code
        values = ({"grant_type": "refresh_token", "refresh_token": state.refresh_token} if refresh else
                  {"code": code, "grant_type": "authorization_code", "redirect_uri": CALLBACK})
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if basic:
            headers["Authorization"] = "Basic " + base64.b64encode(
                (state.client_id + ":" + secret).encode("ascii")).decode("ascii")
        else:
            values.update(client_id=state.client_id, client_secret=secret)
        return urlencode(sorted(values.items())).encode("ascii"), headers

    def token(self, fixture, state, *, basic=False, refresh=False):
        body, headers = self.form(state, basic=basic, refresh=refresh)
        status, content, _ = self.request(fixture, "/oauth/token", method="POST", body=body, headers=headers)
        return status, json.loads(content)

    def grant(self, fixture, state, bound):
        query = self.authorize(fixture, state, bound)
        self.assertTrue(query == {"code": [state.code], "state": [bound]}, "grant redirect changed")
        status, body = self.token(fixture, state, basic=True)
        self.assertEqual((status, body.get("error")), (400, "invalid_client"))
        status, body = self.token(fixture, state)
        self.assertEqual(status, 200)
        expected = {"access_token": state.token, "refresh_token": state.refresh_token,
                    "token_type": "Bearer", "expires_in": 300 if state.mode == "positive" else 1}
        self.assertTrue(body == expected, "grant token fields differ")

    def read_member(self, fixture, token):
        headers = {"Authorization": "Bearer " + token}
        status, body, _ = self.request(fixture, METADATA, headers=headers)
        metadata = json.loads(body)
        self.assertEqual(status, 200)
        self.assertTrue(metadata == {
            "kind": "storage#object", "bucket": "synthetic-bucket", "name": "README-synthetic.txt",
            "size": "62", "md5Hash": base64.b64encode(hashlib.md5(FILES["README-synthetic.txt"]).digest()).decode(),
            "contentType": "application/octet-stream", "updated": "2024-01-01T00:00:00.123Z",
            "mediaLink": "https://127.0.0.1:" + str(fixture.port) + MEDIA}, "metadata or owned media authority differs")
        status, body, _ = self.request(fixture, MEDIA, headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual((len(body), hashlib.sha256(body).hexdigest()), (62, README_SHA256))

    def assert_no_grant_or_read(self, state):
        self.synchronized(state)
        self.assertFalse(state.token_issued)
        self.assertFalse(state.refresh_issued)
        self.assertEqual((state.authenticated, state.payload_bytes, state.grant_denials), (0, 0, 0))

    def raw(self, fixture, wire):
        # Deliberately malformed framing may close/reset TLS before an HTTP
        # response. Only finite state/counter evidence establishes rejection.
        with socket.create_connection(("127.0.0.1", fixture.port), timeout=4) as raw:
            with fixture.client_context().wrap_socket(raw, server_hostname="127.0.0.1") as client:
                client.settimeout(4)
                received = b""
                try:
                    client.sendall(wire)
                    while b"\r\n\r\n" not in received:
                        part = client.recv(min(1024, 8193 - len(received)))
                        if not part:
                            break
                        received += part
                        self.assertLessEqual(len(received), 8192)
                except (ssl.SSLEOFError, ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                    pass
        self.synchronized(fixture.state)
        return received

    def test_verified_ca_grant_metadata_and_independent_content_hash(self):
        with self.fixture() as (fixture, state, bound):
            self.grant(fixture, state, bound)
            self.read_member(fixture, state.token)
            self.assertEqual(state.events, [("authorize", ""), ("code_basic", ""),
                ("code_grant", ""), ("metadata", "README-synthetic.txt"), ("content", "README-synthetic.txt")])
            self.assertEqual((state.requests, state.authenticated, state.payload_bytes), (5, 2, 62))
            self.assertFalse(state.failed)
            self.assertEqual(fixture.snapshot()["transport"]["failure_codes"], [])

    def test_wrong_hostname_and_untrusted_ca_never_reach_http(self):
        for wrong_host in (True, False):
            with self.subTest(wrong_host=wrong_host), self.fixture() as (fixture, state, _bound):
                context = fixture.client_context() if wrong_host else ssl.create_default_context()
                self.assertTrue(context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED)
                with socket.create_connection(("127.0.0.1", fixture.port), timeout=4) as raw:
                    with self.assertRaises(ssl.SSLCertVerificationError):
                        with context.wrap_socket(raw, server_hostname="wrong.synthetic.invalid" if wrong_host else "127.0.0.1"):
                            self.fail("unverified TLS unexpectedly connected")
                self.assertEqual((state.requests, state.events), (0, []))
                self.assert_no_grant_or_read(state)

    def test_callback_redirect_negatives_are_exact_without_token_exchange(self):
        for mode in ("wrong_state", "blank_state", "consent_denied"):
            with self.subTest(mode=mode), self.fixture(mode) as (fixture, state, bound):
                query = self.authorize(fixture, state, bound)
                expected = ({"error": ["access_denied"], "error_description": ["synthetic consent denied"], "state": [bound]}
                            if mode == "consent_denied" else {"code": [state.code], "state": [state.alternate_state if mode == "wrong_state" else ""]})
                self.assertTrue(query == expected, "negative redirect fields differ")
                self.assertEqual((state.requests, state.token_requests), (1, 0))
                self.assert_no_grant_or_read(state)

    def test_invalid_code_and_client_secret_denials_require_exact_forms(self):
        for mode, error in (("invalid_code", "invalid_grant"), ("wrong_client_secret", "invalid_client")):
            with self.subTest(mode=mode), self.fixture(mode) as (fixture, state, bound):
                self.authorize(fixture, state, bound)
                first, _ = self.token(fixture, state, basic=True)
                status, body = self.token(fixture, state)
                self.assertEqual((first, status, body.get("error")), (400, 400, error))
                self.assertEqual((state.requests, state.auth_style_probes, state.grant_denials), (3, 1, 1))
                self.assertFalse(state.token_issued or state.refresh_issued or state.failed)
                self.assertEqual((state.authenticated, state.payload_bytes), (0, 0))

    def test_refresh_replacement_is_the_only_accepted_read_credential(self):
        for stale_token in (False, True):
            with self.subTest(stale_token=stale_token), self.fixture("refresh") as (fixture, state, bound):
                self.grant(fixture, state, bound)
                self.assertEqual(self.token(fixture, state, basic=True, refresh=True)[0], 400)
                status, body = self.token(fixture, state, refresh=True)
                self.assertEqual(status, 200)
                self.assertTrue(body == {"access_token": state.replacement, "refresh_token": state.replacement_refresh,
                                        "token_type": "Bearer", "expires_in": 300}, "replacement grant differs")
                if stale_token:
                    status, _, _ = self.request(fixture, METADATA, headers={"Authorization": "Bearer " + state.token})
                    self.assertEqual(status, 400)
                    self.assertTrue(state.failed)
                    self.assertEqual((state.authenticated, state.payload_bytes), (0, 0))
                else:
                    self.read_member(fixture, state.replacement)
                    self.assertEqual((state.requests, state.refresh_requests, state.payload_bytes), (7, 2, 62))
                    self.assertFalse(state.failed)

    def test_refresh_denial_never_issues_replacement_or_storage_payload(self):
        with self.fixture("refresh_denied") as (fixture, state, bound):
            self.grant(fixture, state, bound)
            self.assertEqual(self.token(fixture, state, basic=True, refresh=True)[0], 400)
            status, body = self.token(fixture, state, refresh=True)
            self.assertEqual((status, body.get("error")), (400, "invalid_grant"))
            self.assertEqual((state.requests, state.refresh_requests, state.grant_denials), (5, 2, 1))
            self.assertFalse(state.refresh_issued or state.failed)
            self.assertEqual((state.authenticated, state.payload_bytes), (0, 0))

    def test_held_refresh_disconnect_has_no_response_or_replacement(self):
        with self.fixture("refresh_cancel") as (fixture, state, bound):
            self.grant(fixture, state, bound)
            self.assertEqual(self.token(fixture, state, basic=True, refresh=True)[0], 400)
            body, _ = self.form(state, refresh=True)
            wire = ("POST /oauth/token HTTP/1.1\r\nHost: " + fixture.host +
                    "\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " + str(len(body)) +
                    "\r\nConnection: close\r\n\r\n").encode("ascii") + body
            try:
                with socket.create_connection(("127.0.0.1", fixture.port), timeout=4) as raw:
                    with fixture.client_context().wrap_socket(raw, server_hostname="127.0.0.1") as client:
                        client.sendall(wire)
                        self.assertTrue(state.refresh_received.wait(1), "held refresh was not observed")
                        client.settimeout(0.1)
                        with self.assertRaises(socket.timeout):
                            client.recv(1)
                # Component-level disconnect only: no child-cancellation claim.
            finally:
                state.release_hold.set()
            end = time.monotonic() + 1
            while not state.hold_completed and time.monotonic() < end:
                time.sleep(0.01)
            self.assertTrue(state.hold_completed, "held handler did not finish")
            self.assertEqual((state.requests, state.refresh_requests, state.payload_bytes), (5, 2, 0))
            self.assertFalse(state.refresh_issued or state.failed)

    def test_wrong_authority_duplicate_headers_and_aliases_never_grant(self):
        for mutation in ("host", "duplicate_host", "authorization", "absolute_target", "query_duplicate"):
            with self.subTest(mutation=mutation), self.fixture() as (fixture, state, bound):
                target = self.authorize_target(state, bound)
                host = "other.synthetic.invalid" if mutation == "host" else fixture.host
                if mutation == "absolute_target":
                    target = "https://" + fixture.host + target
                if mutation == "query_duplicate":
                    target += "&state=" + bound
                extra = ("Host: " + fixture.host + "\r\n" if mutation == "duplicate_host" else
                         "Authorization: Bearer " + state.token + "\r\n" if mutation == "authorization" else "")
                self.raw(fixture, ("GET " + target + " HTTP/1.1\r\nHost: " + host + "\r\n" + extra + "\r\n").encode("ascii"))
                self.assertTrue(state.failed)
                self.assertEqual((state.events, state.authorize_requests, state.token_requests), ([], 0, 0))
                self.assert_no_grant_or_read(state)

    def test_non_crlf_and_discarded_header_fields_never_dispatch(self):
        for mutation in ("lf", "crcrlf", "space_before_colon", "missing_colon"):
            with self.subTest(mutation=mutation), self.fixture() as (fixture, state, bound):
                line = ("GET " + self.authorize_target(state, bound) + " HTTP/1.1").encode("ascii")
                ending = b"\n" if mutation == "lf" else b"\r\r\n" if mutation == "crcrlf" else b"\r\n"
                header = b"Authorization : invalid\r\n" if mutation == "space_before_colon" else b"InvalidHeader\r\n" if mutation == "missing_colon" else b""
                self.raw(fixture, line + ending + ("Host: " + fixture.host + "\r\n").encode("ascii") + header + b"\r\n")
                self.assertTrue(state.failed)
                self.assertEqual((state.events, state.authorize_requests, state.token_requests), ([], 0, 0))
                self.assert_no_grant_or_read(state)

    def test_token_duplicate_form_and_ambiguous_framing_never_count_as_denial(self):
        for mutation in ("duplicate_form", "duplicate_length", "transfer_encoding", "wrong_content_type", "too_large"):
            with self.subTest(mutation=mutation), self.fixture("invalid_code") as (fixture, state, bound):
                self.authorize(fixture, state, bound)
                body, headers = self.form(state, basic=True)
                if mutation == "duplicate_form":
                    body += b"&grant_type=authorization_code"
                count = 4097 if mutation == "too_large" else len(body)
                content_type = "text/plain" if mutation == "wrong_content_type" else "application/x-www-form-urlencoded"
                extra = "Content-Length: " + str(count) + "\r\n" if mutation == "duplicate_length" else "Transfer-Encoding: chunked\r\n" if mutation == "transfer_encoding" else ""
                wire = ("POST /oauth/token HTTP/1.1\r\nHost: " + fixture.host + "\r\nContent-Type: " + content_type +
                        "\r\nContent-Length: " + str(count) + "\r\nAuthorization: " + headers["Authorization"] + "\r\n" + extra + "\r\n").encode("ascii") + body
                self.raw(fixture, wire)
                self.assertTrue(state.failed)
                self.assertEqual((state.token_requests, state.auth_style_probes, state.grant_denials), (0, 0, 0))
                self.assertEqual(state.events, [("authorize", "")])
                self.assert_no_grant_or_read(state)

    def test_storage_order_unknown_member_and_write_are_refused(self):
        for mutation in ("before_grant", "media_first", "unknown_member", "write"):
            with self.subTest(mutation=mutation), self.fixture() as (fixture, state, bound):
                if mutation != "before_grant":
                    self.grant(fixture, state, bound)
                target = MEDIA if mutation == "media_first" else METADATA.replace("README-synthetic.txt", "unknown.txt") if mutation == "unknown_member" else METADATA
                status, _, _ = self.request(fixture, target, method="DELETE" if mutation == "write" else "GET",
                                            headers={"Authorization": "Bearer " + state.token})
                self.assertEqual(status, 405 if mutation == "write" else 400)
                self.assertTrue(state.failed)
                self.assertEqual((state.authenticated, state.payload_bytes), (0, 0))

    def test_incomplete_token_body_hits_absolute_deadline_without_denial_credit(self):
        with self.fixture("invalid_code") as (fixture, state, bound):
            self.authorize(fixture, state, bound)
            body, headers = self.form(state, basic=True)
            wire = ("POST /oauth/token HTTP/1.1\r\nHost: " + fixture.host +
                    "\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " + str(len(body)) +
                    "\r\nAuthorization: " + headers["Authorization"] + "\r\n\r\n").encode("ascii") + body[:1]
            # The client leaves the connection open. Its four-second bound is
            # longer than the fixture's existing three-second request deadline.
            self.raw(fixture, wire)
            self.assertTrue(state.failed)
            self.assertEqual((state.token_requests, state.auth_style_probes, state.grant_denials), (0, 0, 0))
            self.assertEqual(state.events, [("authorize", "")])
            self.assert_no_grant_or_read(state)
            self.assertIn("tls_request_deadline", fixture.snapshot()["transport"]["failure_codes"])


if __name__ == "__main__":
    unittest.main()
