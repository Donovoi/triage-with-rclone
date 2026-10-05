"""Closed GCS static-token reads on owned loopback HTTP; no OAuth/vendor claim.

The caller owns native children and must reap them before leaving serve_gcs.
Importing this module creates no listener, files, credentials or native process.
"""
from contextlib import contextmanager
import base64
import hashlib
import hmac
from http.server import HTTPServer
import json
import re
import socket
import threading
import time
from urllib.parse import quote

from fixture_servers import InternetArchiveLowHandler, SeafileFixture, State


MEMBERS = ("README-synthetic.txt", "nested/space name.txt", "nested/bytes.bin")
SOURCE_DIGESTS = {
    MEMBERS[0]: (62, "1e901527b93ae84dc9d95a8aa76bbc12d7d77dbf8ab449333c172cfc909c639e"),
    MEMBERS[1]: (26, "e019c52fe70badce27affda5e408659399ff764985f07104029a42ade38125bd"),
    MEMBERS[2]: (2048, "10fc3c51a152e90e5b90319b601d92ccf37290ef53c35ff92507687d8a911a08"),
}
BUCKET = "synthetic-bucket"
MISSING = "missing-synthetic-object.bin"
MODIFIED = "2024-01-01T00:00:00Z"
API_ROOT = "/storage/v1/"
LIST_PATH = API_ROOT + "b/" + BUCKET + "/o?alt=json&maxResults=1000&prefix=&prettyPrint=false"
LIFETIME_SECONDS = 60


class GcsError(RuntimeError):
    """Only fixed codes; never caller input or authentication material."""


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def metadata_path(member):
    if member not in (*MEMBERS, MISSING):
        raise GcsError("gcs_invalid_member")
    return API_ROOT + "b/" + BUCKET + "/o/" + quote(member, safe="") + "?alt=json&prettyPrint=false"


def media_path(member):
    if member not in MEMBERS:
        raise GcsError("gcs_invalid_member")
    return "/media/" + quote(member, safe="")


class GcsState(State):
    def __init__(self, files, token, wrong_token, deny_member=None):
        if (type(files) is not dict or set(files) != set(MEMBERS)
                or any(type(files[name]) is not bytes or len(files[name]) != SOURCE_DIGESTS[name][0]
                       or hashlib.sha256(files[name]).hexdigest() != SOURCE_DIGESTS[name][1] for name in MEMBERS)
                or any(type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", value)
                       for value in (token, wrong_token)) or token == wrong_token
                or deny_member not in (None, MEMBERS[0])):
            raise GcsError("gcs_invalid_fixture_state")
        super().__init__("", "")
        self.lock = threading.RLock()
        self.files = {name: files[name] for name in MEMBERS}
        self.token, self.wrong_token, self.deny_member = token, wrong_token, deny_member
        self.metadata = {name: {"kind": "storage#object", "bucket": BUCKET, "name": name,
                                "size": str(len(body)), "md5Hash": base64.b64encode(hashlib.md5(body).digest()).decode("ascii"),
                                "contentType": "application/octet-stream", "updated": MODIFIED}
                         for name, body in self.files.items()}
        self.authenticated = self.auth_denied = self.missing = self.member_denied = 0
        self.response_bytes = self.unexpected = self.rejected_payload_bytes = 0
        self.budget_exceeded = self._started = False
        self.events, self.failure_codes = [], set()
        self.accepted_connections = self.admission_denied = 0
        self.request_limit, self.connection_limit, self.active_connection_limit = 4, 8, 4
        self.request_timeout, self.byte_limit = 3, 32768
        self.deadline = 0.0
        self._original = self.source_snapshot()
        self._original_auth = token, wrong_token, deny_member

    def source_snapshot(self):
        return _canonical({"files": {name: {"size": len(body), "sha256": hashlib.sha256(body).hexdigest()}
                                     for name, body in self.files.items()}, "metadata": self.metadata})

    def source_preserved(self):
        with self.lock:
            try:
                return (self.source_snapshot() == self._original
                        and (self.token, self.wrong_token, self.deny_member) == self._original_auth)
            except (TypeError, ValueError, AttributeError):
                return False

    def snapshot(self):
        with self.lock:
            result = {key: getattr(self, key) for key in (
                "requests", "authenticated", "auth_denied", "missing", "member_denied", "rejected_mutations",
                "payload_bytes", "response_bytes", "unexpected", "rejected_payload_bytes", "budget_exceeded",
                "accepted_connections", "admission_denied", "cleanup_complete")}
            result["events"] = list(self.events)
            result["source_preserved"] = self.source_preserved()
            return result

    def object(self, member, port):
        if member not in MEMBERS or type(port) is not int or not 0 < port < 65536:
            raise GcsError("gcs_invalid_object")
        result = dict(self.metadata[member])
        result["mediaLink"] = f"http://127.0.0.1:{port}" + media_path(member)
        return result


class _GcsHandler(InternetArchiveLowHandler):
    # Reuse the strict CRLF/header/deadline parser and whole-request timer, not
    # the LOW wire protocol. Every inherited HTTP method alias is rebound below.
    protocol_version = "HTTP/1.1"

    def send_error(self, code, message=None, explain=None):
        with self.server.state.lock:
            self.server.state.unexpected += 1
            self._error(400, "invalid")

    def _reply(self, status, body, *, payload=False):
        state = self.server.state
        self.close_connection = True
        if state.response_bytes + len(body) > state.byte_limit:
            state.budget_exceeded = True
            state.unexpected += 1
            return
        # Reserve budgets before writing: a failed write cannot reset the bound.
        state.response_bytes += len(body)
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream" if payload else "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        if payload:
            state.payload_bytes += len(body)

    def _json(self, status, value):
        self._reply(status, _canonical(value).encode("ascii"))

    def _error(self, status, reason):
        self._json(status, {"error": {"code": status, "message": "Synthetic fixture " + reason,
                                     "errors": [{"domain": "global", "reason": reason,
                                                 "message": "Synthetic fixture " + reason}]}})

    def _route(self):
        state = self.server.state
        headers = list(self.headers.items())
        names = [name.lower() for name, _ in headers]
        raw = self.raw_requestline[:-2].split(b" ")
        allowed = {"host", "authorization", "user-agent", "accept-encoding", "connection", "content-length",
                   "x-goog-api-client"}
        length = self.headers.get("Content-Length")
        if length not in (None, "0"):
            state.rejected_payload_bytes += min(int(length), 8193) if re.fullmatch(r"[0-9]{1,19}", length or "") else 1
            raise GcsError("gcs_body_refused")
        if (len(raw) != 3 or raw[0] != self.command.encode("ascii") or raw[1] != self.path.encode("ascii")
                or raw[2] != b"HTTP/1.1" or self.headers.get_all("Host") != [f"127.0.0.1:{self.server.server_address[1]}"]
                or len(names) != len(set(names)) or not set(names) <= allowed
                or any(any(ord(char) < 32 or ord(char) > 126 for char in value) for _, value in headers)
                or self.headers.get("Accept-Encoding") not in (None, "identity", "gzip")
                or self.headers.get("Connection") not in (None, "close")):
            raise GcsError("gcs_headers_refused")
        routes = {LIST_PATH: ("list", ""), metadata_path(MISSING): ("missing", MISSING)}
        routes.update({metadata_path(name): ("metadata", name) for name in MEMBERS})
        routes.update({media_path(name): ("content", name) for name in MEMBERS})
        route = routes.get(self.path)
        if route is None:
            raise GcsError("gcs_route_refused")
        return route

    def dispatch(self):
        state = self.server.state
        with state.lock:
            state.requests += 1
            if (state.requests > state.request_limit or time.monotonic() >= self._request_deadline
                    or state.stopping.is_set()):
                state.budget_exceeded = True
                state.unexpected += 1
                self._error(429, "fixtureLimit")
                return
            try:
                if not state.source_preserved():
                    raise GcsError("gcs_source_changed")
                route, member = self._route()
                if self.command != "GET":
                    state.rejected_mutations += 1
                    state.unexpected += 1
                    self._error(405, "methodNotAllowed")
                    return
                auth = self.headers.get("Authorization", "")
                if (not state.events and route == "metadata" and member == MEMBERS[0]
                        and hmac.compare_digest(auth, "Bearer " + state.wrong_token)):
                    state.auth_denied += 1
                    state.events.append(("auth_denied", member))
                    self._error(401, "authError")
                    return
                if not hmac.compare_digest(auth, "Bearer " + state.token):
                    raise GcsError("gcs_token_refused")
                expected = [("metadata", member)] if route == "content" else []
                if state.events != expected:
                    raise GcsError("gcs_order_refused")
                state.authenticated += 1
                if route == "list":
                    state.events.append((route, member))
                    self._json(200, {"kind": "storage#objects", "items": [state.object(name, self.server.server_address[1]) for name in MEMBERS]})
                elif route == "metadata":
                    state.events.append((route, member))
                    self._json(200, state.object(member, self.server.server_address[1]))
                elif route == "missing":
                    state.missing += 1
                    state.events.append((route, member))
                    self._error(404, "notFound")
                elif member == state.deny_member:
                    state.member_denied += 1
                    state.events.append(("content_denied", member))
                    self._error(403, "forbidden")
                else:
                    state.events.append((route, member))
                    self._reply(200, state.files[member], payload=True)
            except (GcsError, UnicodeError):
                state.unexpected += 1
                self._error(400, "invalid")

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_PROPFIND = dispatch


class _GcsServer(SeafileFixture):
    def __init__(self, state):
        self.state = state
        HTTPServer.__init__(self, ("127.0.0.1", 0), _GcsHandler)

    def get_request(self):
        conn, address = super().get_request()
        with self.state.lock:
            if self.state.stopping.is_set() or time.monotonic() >= self.state.deadline:
                self.state.sockets.discard(conn)
                conn.close()
                self.state.budget_exceeded = True
                raise OSError("gcs_fixture_stopped")
        return conn, address

    def process_request(self, request, client_address):
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self.state.lock:
                self.state.failure_codes.add("gcs_worker_start_failed")
            self.shutdown_request(request)
            raise

    def handle_error(self, request, client_address):
        with self.state.lock:
            self.state.unexpected += 1
            self.state.failure_codes.add("gcs_handler_failed")

    def workers(self):
        value = getattr(self, "_threads", None)
        return list(value) if isinstance(value, list) else []


class GcsFixture:
    def __init__(self, state):
        if type(state) is not GcsState or state._started or not state.source_preserved():
            raise GcsError("gcs_invalid_fixture_state")
        state._started = True
        state.deadline = time.monotonic() + LIFETIME_SECONDS
        self.state = state
        self.server = self.thread = self.timer = None
        self.cleanup_complete = False
        try:
            self.server = _GcsServer(state)
            self.port = self.server.server_address[1]
            self.endpoint = f"http://127.0.0.1:{self.port}" + API_ROOT
            self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02})
            self.thread.start()
            self.timer = threading.Timer(LIFETIME_SECONDS, self._expire)
            self.timer.start()
        except BaseException:
            state.failure_codes.add("gcs_start_failed")
            self.close()
            raise GcsError("gcs_start_failed") from None

    def _expire(self):
        with self.state.lock:
            self.state.budget_exceeded = True
            self.state.failure_codes.add("gcs_lifetime_exceeded")
        self.state.stopping.set()
        self.server.shutdown()
        HTTPServer.server_close(self.server)

    def snapshot(self):
        with self.state.lock:
            workers = self.server.workers() if self.server is not None else []
            return {"protocol": self.state.snapshot(), "transport": {
                "failure_codes": sorted(self.state.failure_codes),
                "listener_closed": self.server is None or self.server.socket.fileno() == -1,
                "workers_alive": sum(worker.is_alive() for worker in workers),
                "timers_alive": int(self.timer is not None and self.timer.is_alive()),
                "sockets_open": len(self.state.sockets)}, "cleanup_complete": self.cleanup_complete}

    def close(self):
        if self.cleanup_complete:
            return True
        self.state.stopping.set()
        if self.timer is not None:
            self.timer.cancel()
            if self.timer.ident is not None:
                self.timer.join(5)
        if self.server is not None:
            if self.thread is not None and self.thread.ident is not None:
                self.server.shutdown()
            with self.state.lock:
                for conn in list(self.state.sockets):
                    try:
                        conn.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    conn.close()
            HTTPServer.server_close(self.server)
            # Bypass ThreadingMixIn's unlimited join, then join only owned workers.
            deadline = time.monotonic() + 5
            for worker in self.server.workers():
                if worker.ident is not None:
                    worker.join(max(0, deadline - time.monotonic()))
        if self.thread is not None and self.thread.ident is not None:
            self.thread.join(5)
        snap = self.snapshot()["transport"]
        self.cleanup_complete = (snap["listener_closed"] and not snap["workers_alive"]
                                 and not snap["timers_alive"] and not snap["sockets_open"]
                                 and (self.thread is None or not self.thread.is_alive()))
        self.state.cleanup_complete = self.cleanup_complete
        if not self.cleanup_complete:
            self.state.failure_codes.add("gcs_cleanup_failed")
        return self.cleanup_complete


@contextmanager
def serve_gcs(state):
    fixture = GcsFixture(state)
    try:
        yield fixture
    finally:
        if not fixture.close():
            raise GcsError("gcs_cleanup_failed")
        if not state.source_preserved():
            raise GcsError("gcs_source_changed")
