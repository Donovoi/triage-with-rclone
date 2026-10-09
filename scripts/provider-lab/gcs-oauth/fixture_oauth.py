"""Synthetic GCS OAuth protocol only; importing starts no service.

The static-token GCS fixture remains immutable. This separate state machine
binds every grant and storage request to generated credentials and one member.
"""
import base64
from contextlib import contextmanager
import hashlib
import hmac
from pathlib import Path
import re
import threading
import time
from urllib.parse import urlencode

from fixture_pcloud import PCloudState, PCloudError, _PCloudHandler
from fixture_tls import BoundedHttpsServer, FixtureCertificates, TlsLimits

# GCS storageConfig in rclone v1.75.1 uses oauthutil.RedirectURL, not its
# distinct RedirectLocalhostURL; authorize and both code forms must agree.
CALLBACK = "http://127.0.0.1:53682/"
SCOPE = "https://www.googleapis.com/auth/devstorage.read_write"
MEMBER = "README-synthetic.txt"
BUCKET = "synthetic-bucket"
METADATA = "/storage/v1/b/" + BUCKET + "/o/" + MEMBER + "?alt=json&prettyPrint=false"
MEDIA = "/media/" + MEMBER
MODES = ("positive", "wrong_state", "blank_state", "consent_denied", "invalid_code",
         "wrong_client_secret", "callback_cancel", "refresh", "refresh_denied", "refresh_cancel")
REFRESH_MODES = frozenset(("refresh", "refresh_denied", "refresh_cancel"))
MAX_FORM_BYTES = 4096
MAX_REQUESTS = 7
LIFETIME_SECONDS = 60


class OAuthError(PCloudError):
    """Only static diagnostics escape the fixture."""


def state_value(value):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{22}", value):
        return False
    raw = base64.urlsafe_b64decode(value + "==")
    return len(raw) == 16 and base64.urlsafe_b64encode(raw).decode().rstrip("=") == value


class OAuthState(PCloudState):
    def __init__(self, files, client_id, client_secret, code, token, refresh_token,
                 replacement, replacement_refresh, *, mode, alternate_state,
                 alternate_code, alternate_secret):
        values = (client_id, client_secret, code, token, refresh_token, replacement,
                  replacement_refresh, alternate_code, alternate_secret)
        if (mode not in MODES or any(type(v) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{24,96}", v) for v in values)
                or len(set(values)) != len(values) or not state_value(alternate_state)):
            raise OAuthError("gcs_oauth_invalid_state")
        super().__init__(files, token, replacement)
        self.client_id, self.client_secret, self.code = client_id, client_secret, code
        self.refresh_token, self.replacement = refresh_token, replacement
        self.replacement_refresh = replacement_refresh
        self.mode, self.alternate_state = mode, alternate_state
        self.alternate_code, self.alternate_secret = alternate_code, alternate_secret
        self._credentials = values
        self._mode = mode, alternate_state
        self._bound_state = self._original_bound_state = None
        self.phase = "unbound"
        self.failed = self.token_issued = self.refresh_issued = False
        self.authorize_requests = self.token_requests = self.refresh_requests = 0
        self.auth_style_probes = self.grant_denials = 0
        self.grant_wall = self.refresh_wall = None
        self.refresh_received, self.release_hold = threading.Event(), threading.Event()
        self.hold_completed = False

    def source_preserved(self):
        with self.lock:
            try:
                return (super().source_preserved() and self._credentials == (
                    self.client_id, self.client_secret, self.code, self.token, self.refresh_token,
                    self.replacement, self.replacement_refresh, self.alternate_code, self.alternate_secret)
                    and self._mode == (self.mode, self.alternate_state)
                    and self._bound_state == self._original_bound_state)
            except (AttributeError, ValueError, TypeError):
                return False

    def bind_state(self, value):
        with self.lock:
            if not state_value(value) or value == self.alternate_state or self.phase != "unbound" or self.requests:
                raise OAuthError("gcs_oauth_state_binding")
            self._bound_state = self._original_bound_state = value
            self.phase = "bound"

    def snapshot(self):
        with self.lock:
            value = super().snapshot()
            value.update(mode=self.mode, phase=self.phase, failed=self.failed,
                         authorize_requests=self.authorize_requests, token_requests=self.token_requests,
                         refresh_requests=self.refresh_requests, auth_style_probes=self.auth_style_probes,
                         grant_denials=self.grant_denials, token_issued=self.token_issued,
                         refresh_issued=self.refresh_issued, hold_completed=self.hold_completed)
            return value


class StrictReader:
    def __init__(self, stream, reject):
        self.stream, self.reject, self.first, self.complete = stream, reject, True, False

    def readline(self, size=-1):
        line = self.stream.readline(size)
        first, self.first = self.first, False
        if (not line.endswith(b"\r\n") or (not first and not self.complete and line != b"\r\n"
                and not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+:[\x20-\x7e]*\r\n", line))):
            self.reject()
            raise OAuthError("gcs_oauth_header_framing")
        if not first and line == b"\r\n":
            self.complete = True
        return line

    def __getattr__(self, name):
        return getattr(self.stream, name)


class OAuthHandler(_PCloudHandler):
    def setup(self):
        super().setup()
        self.rfile = StrictReader(self.rfile, self._framing_failure)

    def _framing_failure(self):
        with self.server.state.lock:
            self._count_request()
            self.server.state.unexpected += 1
            self.server.state.failed = True

    def _invalid(self, status=400):
        self.server.state.failed = True
        super()._invalid(status)

    def parse_request(self):
        okay = super().parse_request()
        if okay and self.headers.defects:
            self._framing_failure()
            self.close_connection = True
            return False
        return okay

    def headers_checked(self, *, token=False, storage=False):
        pairs = list(self.headers.items())
        names = [key.lower() for key, _ in pairs]
        allowed = {"host", "user-agent", "accept-encoding", "connection", "content-length"}
        if token:
            allowed |= {"authorization", "content-type"}
        if storage:
            allowed |= {"authorization", "x-goog-api-client"}
        raw = self.raw_requestline[:-2].split(b" ") if self.raw_requestline.endswith(b"\r\n") else []
        if (len(raw) != 3 or raw != [self.command.encode("ascii"), self.path.encode("ascii"), b"HTTP/1.1"]
                or not self.path.startswith("/") or self.path.startswith("//") or "#" in self.path
                or len(names) != len(set(names)) or not set(names) <= allowed
                or self.headers.get_all("Host") != [f"127.0.0.1:{self.server.server_address[1]}"]
                or any(any(ord(c) < 32 or ord(c) > 126 for c in value) for _, value in pairs)
                or self.headers.get("Accept-Encoding") not in (None, "identity", "gzip")
                or self.headers.get("Connection") not in (None, "close")):
            raise OAuthError("gcs_oauth_headers")
        length = self.headers.get("Content-Length")
        if token:
            if (not re.fullmatch(r"[1-9][0-9]{0,3}", length or "") or int(length) > MAX_FORM_BYTES
                    or self.headers.get("Content-Type") != "application/x-www-form-urlencoded"):
                raise OAuthError("gcs_oauth_form_framing")
            return int(length)
        if length not in (None, "0"):
            raise OAuthError("gcs_oauth_body_refused")
        return 0

    def authorize(self):
        state = self.server.state
        self.headers_checked()
        expected = "/oauth/authorize?" + urlencode(sorted({
            "access_type": "offline", "client_id": state.client_id, "redirect_uri": CALLBACK,
            "response_type": "code", "scope": SCOPE, "state": state._bound_state}.items()))
        if state.phase != "bound" or not hmac.compare_digest(self.path, expected):
            raise OAuthError("gcs_oauth_authorize")
        values = {"state": state.alternate_state if state.mode == "wrong_state" else
                  "" if state.mode == "blank_state" else state._bound_state}
        if state.mode == "consent_denied":
            values.update(error="access_denied", error_description="synthetic consent denied")
        else:
            values["code"] = state.alternate_code if state.mode == "invalid_code" else state.code
        body = b'{"status":"synthetic_authorization"}'
        self.close_connection = True
        self.send_response(302)
        self.send_header("Location", CALLBACK + "?" + urlencode(sorted(values.items())))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        state.response_bytes += len(body)
        state.events.append(("authorize", ""))
        state.authorize_requests += 1
        state.phase = "authorized"

    def exchange(self, body):
        """Return True only for a validated refresh whose response is held."""
        state = self.server.state
        refresh = state.phase in ("exchanged", "refresh_basic_denied")
        basic = state.phase in ("authorized", "exchanged")
        if state.phase not in ("authorized", "code_basic_denied", "exchanged", "refresh_basic_denied"):
            raise OAuthError("gcs_oauth_exchange_order")
        if refresh and state.mode not in REFRESH_MODES:
            raise OAuthError("gcs_oauth_unexpected_refresh")
        if not refresh and state.mode in ("wrong_state", "blank_state", "consent_denied", "callback_cancel"):
            raise OAuthError("gcs_oauth_unexpected_exchange")
        secret = state.alternate_secret if state.mode == "wrong_client_secret" else state.client_secret
        values = ({"grant_type": "refresh_token", "refresh_token": state.refresh_token} if refresh else
                  {"grant_type": "authorization_code", "code": state.alternate_code if state.mode == "invalid_code" else state.code,
                   "redirect_uri": CALLBACK})
        if basic:
            auth = "Basic " + base64.b64encode((state.client_id + ":" + secret).encode("ascii")).decode("ascii")
            valid_auth = hmac.compare_digest(self.headers.get("Authorization", ""), auth)
        else:
            valid_auth = self.headers.get_all("Authorization") is None
            values.update(client_id=state.client_id, client_secret=secret)
        if not valid_auth or not hmac.compare_digest(body, urlencode(sorted(values.items())).encode("ascii")):
            raise OAuthError("gcs_oauth_expected_form")
        if refresh:
            state.refresh_requests += 1
        else:
            state.token_requests += 1
        if basic:
            # v0.36.0 probes Basic then retries client credentials in the form.
            self._json(400, {"error": "invalid_client", "error_description": "synthetic form authentication required"})
            state.auth_style_probes += 1
            state.events.append(("refresh_basic" if refresh else "code_basic", ""))
            state.phase = "refresh_basic_denied" if refresh else "code_basic_denied"
        elif state.mode in ("invalid_code", "wrong_client_secret") or refresh and state.mode == "refresh_denied":
            error = "invalid_client" if state.mode == "wrong_client_secret" else "invalid_grant"
            self._json(400, {"error": error, "error_description": "synthetic grant rejected"})
            state.grant_denials += 1
            state.events.append(("refresh_denied" if refresh else "code_denied", ""))
            state.phase = "denied"
        elif refresh and state.mode == "refresh_cancel":
            state.events.append(("refresh_held", ""))
            state.phase = "held"
            state.refresh_received.set()
            return True
        else:
            seconds = 1 if not refresh and state.mode in REFRESH_MODES else 300
            self._json(200, {"access_token": state.replacement if refresh else state.token,
                            "refresh_token": state.replacement_refresh if refresh else state.refresh_token,
                            "token_type": "Bearer", "expires_in": seconds})
            state.events.append(("refresh_grant" if refresh else "code_grant", ""))
            if refresh:
                state.refresh_issued, state.refresh_wall, state.phase = True, time.time(), "refreshed"
            else:
                state.token_issued, state.grant_wall, state.phase = True, time.time(), "exchanged"
        return False

    def storage(self):
        state = self.server.state
        self.headers_checked(storage=True)
        expected_token = state.replacement if state.mode == "refresh" else state.token
        start_phase = "refreshed" if state.mode == "refresh" else "exchanged"
        if (state.mode not in ("positive", "refresh") or
                not hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + expected_token)):
            raise OAuthError("gcs_oauth_storage_token")
        if self.path == METADATA and state.phase == start_phase:
            body = state.files[MEMBER]
            self._json(200, {"kind": "storage#object", "bucket": BUCKET, "name": MEMBER, "size": str(len(body)),
                            "md5Hash": base64.b64encode(hashlib.md5(body).digest()).decode("ascii"),
                            "contentType": "application/octet-stream", "updated": "2024-01-01T00:00:00.123Z",
                            "mediaLink": f"https://127.0.0.1:{self.server.server_address[1]}" + MEDIA})
            state.events.append(("metadata", MEMBER))
            state.phase = "metadata"
        elif self.path == MEDIA and state.phase == "metadata":
            self._reply(200, state.files[MEMBER], payload=True)
            state.events.append(("content", MEMBER))
            state.phase = "complete"
        else:
            raise OAuthError("gcs_oauth_storage_order")
        state.authenticated += 1

    def dispatch(self):
        held = False
        with self.server.state.lock:
            state = self.server.state
            self._count_request()
            try:
                if state.requests > MAX_REQUESTS or time.monotonic() >= state.deadline:
                    state.budget_exceeded = True
                    raise OAuthError("gcs_oauth_request_budget")
                if state.failed or not state.source_preserved():
                    raise OAuthError("gcs_oauth_source_changed")
                if self.command == "GET" and self.path.startswith("/oauth/authorize?"):
                    self.authorize()
                elif self.command == "POST" and self.path == "/oauth/token":
                    count = self.headers_checked(token=True)
                    body = self.rfile.read(count)  # transport enforces an absolute deadline
                    if len(body) != count:
                        raise OAuthError("gcs_oauth_incomplete_form")
                    held = self.exchange(body)
                elif self.command == "GET":
                    self.storage()
                else:
                    state.rejected_mutations += 1
                    self._invalid(405)
            except (PCloudError, UnicodeError, ValueError, OSError):
                self._invalid()
        if held:
            # Never wait while owning the state lock; cancellation can close us.
            # The driver releases only after the exact child has been reaped.
            released = state.release_hold.wait(2)
            with state.lock:
                state.hold_completed = released
                if not released:
                    state.failed = True
            self.close_connection = True

    do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_TRACE = do_CONNECT = dispatch


class OAuthFixture:
    def __init__(self, root, state):
        if type(state) is not OAuthState:
            raise OAuthError("gcs_oauth_invalid_fixture")
        with state.lock:
            if state._started or not state.source_preserved():
                raise OAuthError("gcs_oauth_state_reuse")
            state._started = True
            state.deadline = time.monotonic() + LIFETIME_SECONDS
        self.state, self._certificates, self._transport = state, None, None
        self.cleanup_complete = self._closed = False
        try:
            self._certificates = FixtureCertificates.create(Path(root))
            self._transport = BoundedHttpsServer(self._certificates, OAuthHandler, state=state,
                limits=TlsLimits(connection_limit=10, active_limit=2, request_seconds=3,
                                 lifetime_seconds=LIFETIME_SECONDS))
            self.port = self._transport.port
            self.host = f"127.0.0.1:{self.port}"
            self._transport.start()
        except BaseException:
            self.close()
            raise

    def rclone_ca_args(self):
        if self._closed:
            raise OAuthError("gcs_oauth_fixture_closed")
        return self._certificates.rclone_ca_args()

    def client_context(self):
        if self._closed:
            raise OAuthError("gcs_oauth_fixture_closed")
        return self._certificates.client_context()

    def snapshot(self):
        return {"protocol": self.state.snapshot(),
                "transport": self._transport.snapshot() if self._transport else None,
                "cleanup_complete": self.cleanup_complete}

    def close(self):
        if self._closed:
            return self.cleanup_complete
        self.state.release_hold.set()
        transport, material = self._transport is None, self._certificates is None
        try:
            if self._transport:
                transport = self._transport.close()
        finally:
            # Certificate material can still be owned by a TLS worker if close
            # failed or could not prove it joined. Preserve it on uncertainty.
            if transport and self._certificates:
                material = self._certificates.close()
            self.cleanup_complete = bool(transport and material)
            self.state.cleanup_complete = self.cleanup_complete
            self._closed = self.cleanup_complete
        return self.cleanup_complete


@contextmanager
def serve_oauth(root, state):
    fixture = OAuthFixture(root, state)
    try:
        yield fixture
    finally:
        if not fixture.close() or not state.source_preserved():
            raise OAuthError("gcs_oauth_cleanup_failed")
