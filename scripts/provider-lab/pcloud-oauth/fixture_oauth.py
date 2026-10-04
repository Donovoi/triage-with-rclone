"""Owned pCloud OAuth positive-feasibility service; no acceptance/ledger claim.

The caller validates and owns rclone's separate callback listener before binding
its state. This service cannot prove callback receipt or native persistence; the
driver must observe both. No listener, credentials or certificate is created on
import. Existing saved-token fixtures and their rejection rules stay unchanged.
"""
import base64
from contextlib import contextmanager
import hmac
from pathlib import Path
import re
import time
from urllib.parse import urlencode

from fixture_pcloud import MEMBERS, PCloudError, PCloudState, _PCloudHandler
from fixture_tls import BoundedHttpsServer, FixtureCertificates, TlsLimits


CALLBACK = "http://localhost:53682/"
MAX_REQUESTS = 6
MAX_FORM_BYTES = 4096
MAX_RESPONSE_BYTES = 32768
LIFETIME_SECONDS = 60
READ_STEPS = (("root_list", ""), ("checksum", MEMBERS[0]),
              ("link", MEMBERS[0]), ("content", MEMBERS[0]))


class OAuthError(PCloudError):
    """Only static codes may escape this service."""


def _state_value(value):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{22}", value):
        return False
    decoded = base64.urlsafe_b64decode(value + "==")
    return len(decoded) == 16 and base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") == value


class OAuthState(PCloudState):
    def __init__(self, files, client_id, client_secret, code, token, wrong_token):
        credentials = (client_id, client_secret, code, token, wrong_token)
        if (any(type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", value)
                for value in credentials) or len(set(credentials)) != len(credentials)):
            raise OAuthError("oauth_invalid_fixture_credentials")
        super().__init__(files, token, wrong_token)
        self.client_id, self.client_secret, self.code = client_id, client_secret, code
        self._original_credentials = credentials
        self._bound_state = self._original_bound_state = None
        self.authorize_requests = self.token_requests = 0
        self.token_issued = self.failed = False
        self.phase = "unbound"

    def bind_state(self, value):
        with self.lock:
            if (not _state_value(value) or self._bound_state is not None or not self._started
                    or self.requests or self.failed or self.phase != "unbound" or not self.source_preserved()):
                self.failed = True
                raise OAuthError("oauth_state_binding_refused")
            self._bound_state = self._original_bound_state = value
            self.phase = "bound"

    def source_preserved(self):
        with self.lock:
            try:
                return (super().source_preserved()
                        and (self.client_id, self.client_secret, self.code, self.token, self.wrong_token)
                        == self._original_credentials
                        and self._bound_state == self._original_bound_state)
            except (AttributeError, TypeError, ValueError):
                return False

    def snapshot(self):
        with self.lock:
            result = super().snapshot()
            result.update(authorize_requests=self.authorize_requests, token_requests=self.token_requests,
                          token_issued=self.token_issued, bound_state=self._bound_state is not None,
                          phase=self.phase, failed=self.failed)
            return result


class _StrictReader:
    """Validate every raw header before the email parser can discard it."""
    def __init__(self, stream, reject):
        self.stream, self.reject = stream, reject
        self.first = True
        self.complete = False

    def readline(self, size=-1):
        line = self.stream.readline(size)
        first, self.first = self.first, False
        if (not line.endswith(b"\r\n") or (not first and not self.complete and line != b"\r\n"
                and not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+:[\x20-\x7e]*\r\n", line))):
            self.reject()
            raise OAuthError("oauth_invalid_header_framing")
        if not first and line == b"\r\n":
            self.complete = True
        return line

    def __getattr__(self, name):
        return getattr(self.stream, name)


class _OAuthHandler(_PCloudHandler):
    def setup(self):
        super().setup()
        self.rfile = _StrictReader(self.rfile, self._framing_failure)

    def _framing_failure(self):
        with self.server.state.lock:
            self._count_request()
            self.server.state.unexpected += 1
            self.server.state.failed = True

    def _input_limit(self):
        super()._input_limit()
        with self.server.state.lock:
            self.server.state.failed = True

    def parse_request(self):
        okay = super().parse_request()
        if okay and self.headers.defects:
            self._framing_failure()
            self.close_connection = True
            return False
        return okay

    def _invalid(self, status=400):
        self.server.state.failed = True
        super()._invalid(status)

    def _headers(self, *, token=False):
        state = self.server.state
        headers = list(self.headers.items())
        names = [name.lower() for name, _ in headers]
        allowed = {"host", "user-agent", "accept-encoding", "connection", "content-length"}
        if token:
            allowed.update(("authorization", "content-type"))
        parts = self.raw_requestline[:-2].split(b" ") if self.raw_requestline.endswith(b"\r\n") else []
        length = self.headers.get("Content-Length")
        if (len(parts) != 3 or parts[0] != self.command.encode("ascii") or parts[1] != self.path.encode("ascii")
                or parts[2] != b"HTTP/1.1" or len(names) != len(set(names)) or not set(names) <= allowed
                or self.headers.get_all("Host") != [f"127.0.0.1:{self.server.server_address[1]}"]
                or any(any(ord(char) < 32 or ord(char) > 126 for char in value) for _, value in headers)
                or self.headers.get("Accept-Encoding") not in (None, "gzip", "identity")
                or self.headers.get("Connection") not in (None, "close")):
            raise OAuthError("oauth_headers_refused")
        if token:
            if not re.fullmatch(r"[1-9][0-9]{0,3}", length or "") or int(length) > MAX_FORM_BYTES:
                state.rejected_payload_bytes += min(int(length), MAX_FORM_BYTES + 1) if (length or "").isdigit() and len(length) < 20 else 1
                raise OAuthError("oauth_form_length_refused")
            return int(length)
        if length not in (None, "0"):
            state.rejected_payload_bytes += min(int(length), MAX_FORM_BYTES + 1) if (length or "").isdigit() and len(length) < 20 else 1
            raise OAuthError("oauth_body_refused")
        return 0

    def _authorize(self):
        state = self.server.state
        self._headers()
        expected = "/oauth2/authorize?" + urlencode(sorted({"access_type": "offline", "client_id": state.client_id,
                    "redirect_uri": CALLBACK, "response_type": "code", "state": state._bound_state}.items()))
        if state.phase != "bound" or not hmac.compare_digest(self.path, expected):
            raise OAuthError("oauth_authorize_refused")
        location = CALLBACK + "?" + urlencode(sorted({"code": state.code, "hostname": f"127.0.0.1:{self.server.server_address[1]}",
                                                   "locationid": "1", "state": state._bound_state}.items()))
        body = b'{"status":"synthetic_code_issued"}'
        if state.response_bytes + len(body) > MAX_RESPONSE_BYTES:
            state.budget_exceeded = True
            raise OAuthError("oauth_response_limit")
        self.close_connection = True
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        state.response_bytes += len(body)
        state.events.append(("authorize", ""))
        state.phase = "authorized"

    def _read_form(self):
        state = self.server.state
        size = self._headers(token=True)
        # Consume only unambiguous, bounded framing before any semantic denial.
        # Closing TLS with an unread form can reset the connection before the
        # client receives the error response. The transport's absolute deadline
        # still interrupts incomplete bodies; oversized/ambiguous framing is not
        # drained, and no credentials or grant are accepted by this read.
        body = self.rfile.read(size)
        if len(body) != size:
            state.rejected_payload_bytes += len(body)
            raise OAuthError("oauth_form_refused")
        return body

    def _exchange(self, body):
        state = self.server.state
        if self.headers.get("Content-Type") != "application/x-www-form-urlencoded":
            state.rejected_payload_bytes += len(body)
            raise OAuthError("oauth_form_type_refused")
        if state.phase != "authorized":
            raise OAuthError("oauth_exchange_order_refused")
        # oauth2 v0.36.0 AuthStyleAutoDetect first tries escaped client credentials
        # in Basic. This positive service deliberately supports only that first try.
        basic = "Basic " + base64.b64encode((state.client_id + ":" + state.client_secret).encode("ascii")).decode("ascii")
        if not hmac.compare_digest(self.headers.get("Authorization", ""), basic):
            state.auth_denied += 1
            raise OAuthError("oauth_client_refused")
        expected = urlencode(sorted({"code": state.code, "grant_type": "authorization_code", "redirect_uri": CALLBACK}.items())).encode("ascii")
        if not hmac.compare_digest(body, expected):
            state.rejected_payload_bytes += len(body)
            raise OAuthError("oauth_form_refused")
        self._json(200, {"result": 0, "access_token": state.token, "token_type": "bearer", "uid": 10001})
        state.events.append(("token", ""))
        state.token_issued = True
        state.phase = "exchanged"

    def dispatch(self):
        with self.server.state.lock:
            state = self.server.state
            self._count_request()
            if self.path.startswith("/oauth"):
                state.oauth_requests += 1
            if state.requests > MAX_REQUESTS or time.monotonic() >= state.deadline:
                state.budget_exceeded = True
                self._invalid(429)
                return
            try:
                token_request = self.command == "POST" and self.path == "/oauth2_token"
                body = self._read_form() if token_request else None
                if state.failed or not state.source_preserved():
                    self._invalid()
                    return
                if self.command == "GET" and self.path.startswith("/oauth2/authorize?"):
                    state.authorize_requests += 1
                    self._authorize()
                    return
                if token_request:
                    state.token_requests += 1
                    self._exchange(body)
                    return
                if self.command != "GET":
                    state.rejected_mutations += 1
                    self._invalid(405)
                    return
                (kind, member), authenticated = self._route()
                index = {"exchanged": 0, "root_list": 1, "checksum": 2, "link": 3}.get(state.phase)
                if not authenticated:
                    state.auth_denied += 1
                    raise OAuthError("oauth_saved_token_refused")
                if not state.token_issued or index is None or (kind, member) != READ_STEPS[index]:
                    raise OAuthError("oauth_read_order_refused")
                # Base dispatch rechecks the fixed saved-token route and retains
                # its independent metadata/hash/content and authority oracle.
                super().dispatch()
                if not state.failed and not state.unexpected:
                    state.phase = "complete" if kind == "content" else kind
            except (PCloudError, UnicodeError, ValueError):
                self._invalid()

    # Base aliases bind its original function rather than virtual dispatch.
    do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_TRACE = do_CONNECT = dispatch


class OAuthFixture:
    def __init__(self, root, state):
        if type(state) is not OAuthState:
            raise OAuthError("oauth_invalid_state")
        with state.lock:
            if state._started or not state.source_preserved():
                raise OAuthError("oauth_state_reuse_or_change")
            state._started = True
            state.deadline = time.monotonic() + LIFETIME_SECONDS
        self.state, self._certificates, self._transport = state, None, None
        self.cleanup_complete = self._closed = False
        try:
            self._certificates = FixtureCertificates.create(Path(root))
            self._transport = BoundedHttpsServer(self._certificates, _OAuthHandler, state=state,
                                                limits=TlsLimits(connection_limit=8, active_limit=2,
                                                                 request_seconds=3, lifetime_seconds=LIFETIME_SECONDS))
            self.port = self._transport.port
            self.host = f"127.0.0.1:{self.port}"
            self._transport.start()
        except BaseException:
            if not self.close():
                raise OAuthError("oauth_cleanup_failed") from None
            raise

    @property
    def ca_sha256(self):
        return self._certificates.ca_sha256

    def rclone_ca_args(self):
        if self._closed:
            raise OAuthError("oauth_fixture_closed")
        return self._certificates.rclone_ca_args()

    def client_context(self):
        if self._closed:
            raise OAuthError("oauth_fixture_closed")
        return self._certificates.client_context()

    def snapshot(self):
        return {"protocol": self.state.snapshot(),
                "transport": self._transport.snapshot() if self._transport is not None else None,
                "certificate_cleanup": self._certificates.cleanup_complete if self._certificates is not None else True,
                "cleanup_complete": self.cleanup_complete}

    def close(self):
        if self._closed:
            return self.cleanup_complete
        transport_okay = self._transport is None
        material_okay = self._certificates is None
        raised = False
        try:
            if self._transport is not None:
                transport_okay = self._transport.close()
        except BaseException:
            raised = True
        finally:
            try:
                if self._certificates is not None:
                    material_okay = self._certificates.close()
            except BaseException:
                raised = True
            self.cleanup_complete = bool(transport_okay and material_okay)
            with self.state.lock:
                self.state.cleanup_complete = self.cleanup_complete
                if not self.cleanup_complete:
                    self.state.failed = True
            self._closed = self.cleanup_complete
        if raised:
            raise OAuthError("oauth_cleanup_failed") from None
        return self.cleanup_complete


@contextmanager
def serve_oauth(root, state):
    fixture = OAuthFixture(root, state)
    try:
        yield fixture
    finally:
        if not fixture.close():
            raise OAuthError("oauth_cleanup_failed")
        if not state.source_preserved():
            raise OAuthError("oauth_source_changed")
