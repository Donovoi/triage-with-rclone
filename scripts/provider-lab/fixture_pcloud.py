"""Closed pCloud saved-token read fixture; no vendor/OAuth/lifecycle acceptance.

The only content is the three immutable synthetic lab samples. The caller owns
native children/configs and must reap them before leaving serve_pcloud. This
module creates no listener, certificate or dependency import on module import.
"""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler
import json
from pathlib import Path
import re
import threading
import time

from fixture_tls import BoundedHttpsServer, FixtureCertificates, TlsLimits


MEMBERS = ("README-synthetic.txt", "nested/space name.txt", "nested/bytes.bin")
FILE_IDS = dict(zip(MEMBERS, ("301", "302", "303")))
SOURCE_DIGESTS = {
    MEMBERS[0]: (62, "1e901527b93ae84dc9d95a8aa76bbc12d7d77dbf8ab449333c172cfc909c639e"),
    MEMBERS[1]: (26, "e019c52fe70badce27affda5e408659399ff764985f07104029a42ade38125bd"),
    MEMBERS[2]: (2048, "10fc3c51a152e90e5b90319b601d92ccf37290ef53c35ff92507687d8a911a08"),
}
MODIFIED = "Mon, 01 Jan 2024 00:00:00 +0000"
EARLIER = "Sun, 31 Dec 2023 00:00:00 +0000"
MAX_REQUESTS, MAX_RESPONSE_BYTES = 8, 32768
MAX_INPUT_BYTES, MAX_LINE_BYTES, MAX_LINES = 8192, 2048, 32
LIFETIME_SECONDS = 60


class PCloudError(RuntimeError):
    """A fixed failure code, never caller headers, paths or token values."""


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class PCloudState:
    def __init__(self, files, token, wrong_token, deny_member=None):
        if (type(files) is not dict or set(files) != set(MEMBERS)
                or any(type(files[name]) is not bytes or len(files[name]) != SOURCE_DIGESTS[name][0]
                       or hashlib.sha256(files[name]).hexdigest() != SOURCE_DIGESTS[name][1] for name in MEMBERS)
                or any(type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", value)
                       for value in (token, wrong_token)) or token == wrong_token
                or deny_member not in (None, MEMBERS[0])):
            raise PCloudError("pcloud_invalid_fixture_state")
        self.files = {name: files[name] for name in MEMBERS}
        self.token, self.wrong_token, self.deny_member = token, wrong_token, deny_member
        self.metadata = {}
        for name in MEMBERS:
            number = FILE_IDS[name]
            self.metadata[name] = {"id": "f" + number, "fileid": int(number), "name": name.rsplit("/", 1)[-1],
                                   "path": "/synthetic/" + name, "isfolder": False,
                                   "parentfolderid": 200 if name.startswith("nested/") else 100,
                                   "size": len(files[name]), "created": MODIFIED if name == MEMBERS[1] else EARLIER}
            if name != MEMBERS[1]:
                self.metadata[name]["modified"] = MODIFIED
        self.link_expires = format_datetime(datetime.now(timezone.utc) + timedelta(minutes=10))
        self.lock = threading.RLock()
        self.events, self.details, self.links, self.checksummed = [], set(), set(), set()
        self.directories = {"100"}
        self.requests = self.authenticated = self.auth_denied = self.member_denied = 0
        self.rejected_mutations = self.payload_bytes = self.response_bytes = self.unexpected = 0
        self.rejected_payload_bytes = self.oauth_requests = 0
        self.budget_exceeded = self.cleanup_complete = self._started = False
        self.deadline = None
        self._original = self.source_snapshot()
        self._original_auth = token, wrong_token, deny_member

    def source_snapshot(self):
        return _canonical({"files": {name: {"size": len(body), "sha256": hashlib.sha256(body).hexdigest()}
                                     for name, body in self.files.items()},
                           "metadata": self.metadata, "link_expires": self.link_expires})

    def source_preserved(self):
        with self.lock:
            try:
                return (self.source_snapshot() == self._original
                        and (self.token, self.wrong_token, self.deny_member) == self._original_auth)
            except (TypeError, ValueError, AttributeError):
                return False

    def snapshot(self):
        with self.lock:
            result = {name: getattr(self, name) for name in
                      ("requests", "authenticated", "auth_denied", "member_denied", "rejected_mutations", "payload_bytes",
                       "response_bytes", "unexpected", "rejected_payload_bytes", "oauth_requests", "budget_exceeded", "cleanup_complete")}
            result["events"] = list(self.events)
            result["source_preserved"] = self.source_preserved()
            return result

    def directory(self, number, recursive=False):
        # Return copies so response construction cannot mutate the oracle.
        if number not in ("100", "200") or (recursive and number != "100"):
            raise PCloudError("pcloud_invalid_directory")
        nested = {"id": "d200", "folderid": 200, "parentfolderid": 100, "name": "nested", "path": "/synthetic/nested",
                  "isfolder": True, "created": EARLIER, "modified": MODIFIED,
                  "contents": [self.metadata[name] for name in MEMBERS[1:]] if recursive or number == "200" else []}
        root = {"id": "d100", "folderid": 100, "parentfolderid": 0, "name": "synthetic", "path": "/synthetic",
                "isfolder": True, "created": EARLIER, "modified": MODIFIED,
                "contents": [self.metadata[MEMBERS[0]], nested]}
        return json.loads(_canonical(root if number == "100" else nested))


class _BoundedReader:
    def __init__(self, stream, reject):
        self.stream, self.reject = stream, reject
        self.total = self.lines = 0

    def readline(self, size=-1):
        limit = min(MAX_LINE_BYTES + 1, MAX_INPUT_BYTES + 1 - self.total)
        if size >= 0:
            limit = min(limit, size)
        data = self.stream.readline(limit)
        self.total += len(data)
        self.lines += 1
        if len(data) > MAX_LINE_BYTES or self.total > MAX_INPUT_BYTES or self.lines > MAX_LINES:
            self.reject()
            raise PCloudError("pcloud_request_input_limit")
        return data

    def __getattr__(self, name):
        return getattr(self.stream, name)


class _PCloudHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self._counted = False
        self.rfile = _BoundedReader(self.rfile, self._input_limit)

    def _count_request(self):
        if not self._counted:
            self.server.state.requests += 1
            self._counted = True

    def _input_limit(self):
        with self.server.state.lock:
            self._count_request()
            self.server.state.unexpected += 1
            self.server.state.budget_exceeded = True

    def _reply(self, status, body, *, payload=False):
        state = self.server.state
        self.close_connection = True
        if type(body) is not bytes or len(body) > MAX_RESPONSE_BYTES or state.response_bytes + len(body) > MAX_RESPONSE_BYTES:
            state.budget_exceeded = True
            raise PCloudError("pcloud_response_limit")
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream" if payload else "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        state.response_bytes += len(body)
        if payload:
            state.payload_bytes += len(body)

    def _json(self, status, value):
        self._reply(status, _canonical(value).encode("ascii"))

    def _invalid(self, status=400):
        self.server.state.unexpected += 1
        self._json(status, {"status": "fixture_invalid_request"})

    def send_error(self, code, message=None, explain=None):
        # BaseHTTPRequestHandler error strings can contain request input.
        with self.server.state.lock:
            self._count_request()
            self._invalid(400)

    def _route(self):
        state = self.server.state
        headers = list(self.headers.items())
        names = [name.lower() for name, _ in headers]
        allowed = {"host", "authorization", "accept-encoding", "user-agent", "content-length", "connection"}
        raw = self.raw_requestline
        parts = raw[:-2].split(b" ") if raw.endswith(b"\r\n") else []
        length = self.headers.get("Content-Length")
        if length not in (None, "0"):
            # Count rejected declared input, capped; no request body is read.
            state.rejected_payload_bytes += min(int(length), 4097) if re.fullmatch(r"[0-9]{1,19}", length or "") else 1
            raise PCloudError("pcloud_body_refused")
        if (len(parts) != 3 or parts[0] != self.command.encode("ascii") or parts[1] != self.path.encode("ascii")
                or parts[2] != b"HTTP/1.1" or self.headers.get_all("Host") != [f"127.0.0.1:{self.server.server_address[1]}"]
                or len(names) != len(set(names)) or not set(names) <= allowed
                or any(any(ord(char) < 32 or ord(char) > 126 for char in value) for _, value in headers)
                or self.headers.get("Accept-Encoding") not in (None, "gzip", "identity")
                or self.headers.get("Connection") not in (None, "close")):
            raise PCloudError("pcloud_headers_refused")
        routes = {("GET", "/listfolder?folderid=100&recursive=1"): ("list_recursive", ""),
                  ("GET", "/listfolder?folderid=100"): ("root_list", ""),
                  ("GET", "/listfolder?folderid=200"): ("nested_list", "nested"),
                  ("POST", "/deletefile?fileid=301"): ("write_denied", MEMBERS[0])}
        for member, number in FILE_IDS.items():
            routes[("GET", "/checksumfile?fileid=" + number)] = ("checksum", member)
            routes[("GET", "/getfilelink?fileid=" + number)] = ("link", member)
            routes[("GET", "/download/" + number)] = ("content", member)
        route = routes.get((self.command, self.path))
        if route is None:
            raise PCloudError("pcloud_route_refused")
        auth = self.headers.get("Authorization", "")
        if hmac.compare_digest(auth, "Bearer " + state.token):
            return route, True
        if route == ("root_list", "") and hmac.compare_digest(auth, "Bearer " + state.wrong_token):
            return route, False
        raise PCloudError("pcloud_token_refused")

    def dispatch(self):
        with self.server.state.lock:
            state = self.server.state
            self._count_request()
            if self.path.startswith("/oauth"):
                state.oauth_requests += 1
            if state.requests > MAX_REQUESTS or time.monotonic() >= state.deadline:
                state.budget_exceeded = True
                self._json(429, {"status": "fixture_request_limit"})
                return
            if not state.source_preserved():
                self._invalid()
                return
            try:
                (kind, member), authenticated = self._route()
            except (PCloudError, UnicodeError, ValueError):
                self._invalid()
                return
            if not authenticated:
                state.auth_denied += 1
                state.events.append(("auth_denied", ""))
                self._json(401, {"result": 2000, "error": "synthetic token rejected"})
                return
            state.authenticated += 1
            if kind == "nested_list" and "200" not in state.directories:
                self._invalid()
                return
            if kind in ("checksum", "link", "content", "write_denied") and member not in state.details:
                self._invalid()
                return
            if kind == "content" and member not in state.links:
                self._invalid()
                return
            if kind == "write_denied" and member not in state.checksummed:
                self._invalid()
                return
            if kind in ("list_recursive", "root_list", "nested_list"):
                recursive, number = kind == "list_recursive", "200" if kind == "nested_list" else "100"
                state.events.append((kind, member))
                state.directories.add("200")
                state.details.update(MEMBERS if recursive else MEMBERS[1:] if number == "200" else MEMBERS[:1])
                self._json(200, {"result": 0, "metadata": state.directory(number, recursive)})
            elif kind == "checksum":
                state.events.append((kind, member))
                state.checksummed.add(member)
                body = state.files[member]
                self._json(200, {"result": 0, "md5": hashlib.md5(body).hexdigest(), "sha1": hashlib.sha1(body).hexdigest(),
                                 "metadata": state.metadata[member]})
            elif kind == "link":
                state.events.append((kind, member))
                state.links.add(member)
                self._json(200, {"result": 0, "hosts": [f"127.0.0.1:{self.server.server_address[1]}"],
                                 "path": "/download/" + FILE_IDS[member], "expires": state.link_expires})
            elif kind == "write_denied":
                state.events.append((kind, member))
                state.rejected_mutations += 1
                self._json(405, {"status": "fixture_read_only"})
            elif member == state.deny_member:
                state.events.append(("content_denied", member))
                state.member_denied += 1
                self._json(403, {"result": 2003, "error": "synthetic member denied"})
            else:
                state.events.append(("content", member))
                self._reply(200, state.files[member], payload=True)

    do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_TRACE = do_CONNECT = dispatch


class PCloudFixture:
    def __init__(self, root, state):
        if not isinstance(state, PCloudState):
            raise PCloudError("pcloud_invalid_state")
        with state.lock:
            if state._started or not state.source_preserved():
                raise PCloudError("pcloud_state_reuse_or_change")
            state._started = True
            state.deadline = time.monotonic() + LIFETIME_SECONDS
        self.state, self._certificates, self._transport = state, None, None
        self.cleanup_complete = False
        self._closed = False
        try:
            self._certificates = FixtureCertificates.create(Path(root))
            self._transport = BoundedHttpsServer(self._certificates, _PCloudHandler, state=state,
                                                limits=TlsLimits(connection_limit=16, active_limit=4,
                                                                 request_seconds=3, lifetime_seconds=LIFETIME_SECONDS))
            self.port = self._transport.port
            self._transport.start()
        except BaseException:
            if not self.close():
                raise PCloudError("pcloud_cleanup_failed") from None
            raise

    @property
    def ca_sha256(self):
        return self._certificates.ca_sha256

    def rclone_ca_args(self):
        if self._closed:
            raise PCloudError("pcloud_fixture_closed")
        return self._certificates.rclone_ca_args()

    def client_context(self):
        if self._closed:
            raise PCloudError("pcloud_fixture_closed")
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
        try:
            if self._transport is not None:
                transport_okay = self._transport.close()
        finally:
            if self._certificates is not None:
                material_okay = self._certificates.close()
            self.cleanup_complete = bool(transport_okay and material_okay)
            self.state.cleanup_complete = self.cleanup_complete
            self._closed = self.cleanup_complete
        return self.cleanup_complete


@contextmanager
def serve_pcloud(root, state):
    fixture = PCloudFixture(root, state)
    try:
        yield fixture
    finally:
        if not fixture.close():
            raise PCloudError("pcloud_cleanup_failed")
