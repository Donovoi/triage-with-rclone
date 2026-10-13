"""Closed fixed-Bearer WebDAV control and injected copy-GET denial fixture.

No work starts on import. The existing HTTP transport supplies admission,
absolute request/fixture deadlines and owned socket/thread teardown.
"""
from contextlib import contextmanager
import hashlib
import hmac
from pathlib import Path
import re
import select
import socket
import threading
import time
import types
from urllib.parse import quote, unquote

_PATH = Path(__file__).absolute().with_name("fixture_http.py")
_BYTES = _PATH.read_bytes()
loaded_http_source_sha256 = hashlib.sha256(_BYTES).hexdigest()
_http = types.ModuleType("bearer_owned_http")
_http.__file__ = str(_PATH)
exec(compile(_BYTES, str(_PATH), "exec"), _http.__dict__)
del _BYTES
FixtureError = _http.FixtureError
CASES = ("accepted_token", "invalidated_token")
GATES = ("first_get",)
MEMBER = "README-synthetic.txt"
BODY = b"synthetic application fixture\n"
SHA256 = "64d5b40a5f4773b14940a6ce1dd57cf87b44ce5940c097088732ffc71be280cf"
PROPFIND_BODY = (b'<?xml version="1.0"?>\n<d:propfind xmlns:d="DAV:">\n <d:prop>\n'
                b'  <d:displayname/>\n  <d:getlastmodified/>\n  <d:getcontentlength/>\n'
                b'  <d:resourcetype/>\n </d:prop>\n</d:propfind>\n')
METADATA = (b'<?xml version="1.0" encoding="utf-8"?>'
    b'<d:multistatus xmlns:d="DAV:"><d:response><d:href>/README-synthetic.txt</d:href>'
    b'<d:propstat><d:prop><d:displayname>README-synthetic.txt</d:displayname>'
    b'<d:getlastmodified>Thu, 02 Jan 2025 03:04:05 GMT</d:getlastmodified>'
    b'<d:getcontentlength>30</d:getcontentlength><d:resourcetype/>'
    b'</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>')
ERROR_CODES = _http.ERROR_CODES | {"credentials_invalid", "sequence_invalid", "gate_invalid"}


class AppBearerState:
    def __init__(self, token):
        if type(token) is not str or re.fullmatch(r"[a-f0-9]{64}", token) is None:
            raise ValueError("input_invalid")
        self._token, self._body = token, BODY
        self.lock = threading.RLock()
        self.errors, self.history = [], []
        self.case = CASES[0]
        self._served = False
        self._transport = None
        self._reset()

    def _reset(self):
        self.events = []
        self.requests = self.metadata = self.payload_bytes = self.response_bytes = 0
        self.completed = False
        self._pending = self._reply = None
        self.gates = {"first_get": dict(entered=False, released=False)}
        self.wakes = {"first_get": threading.Event()}

    def source_preserved(self):
        return type(self._body) is bytes and self._body == BODY and len(self._body) == 30 and hashlib.sha256(self._body).hexdigest() == SHA256

    def _error(self, code):
        with self.lock:
            code = code if type(code) is str and code in ERROR_CODES else "worker_failed"
            if code not in self.errors:
                self.errors.append(code)

    def _event(self, kind, status=0, payload=0):
        if len(self.events) >= 512:
            raise FixtureError("event_limit")
        self.events.append((kind, status, payload))

    def gate_snapshot(self):
        with self.lock:
            return {name: dict(entered=1 if row["entered"] else None, released=row["released"])
                    for name, row in self.gates.items()}

    def release_gate(self, name):
        with self.lock:
            if (name != "first_get" or self.errors or not self.gates[name]["entered"] or
                    self.gates[name]["released"] or self._pending is None or self._pending[2] != name):
                raise FixtureError("gate_invalid")
            self.gates[name]["released"] = True
            self._event("gate_released")
            self.wakes[name].set()

    def release_observation(self):
        # Teardown wakes are not a qualifying release.
        self.wakes["first_get"].set()

    release_cancel = release_observation

    def begin(self, method, path, authorization):
        with self.lock:
            if self.errors or self._pending is not None or self.completed:
                raise FixtureError("sequence_invalid")
            if self.requests >= 3:
                raise FixtureError("request_limit")
            if not self.source_preserved():
                raise FixtureError("source_changed")
            if type(authorization) is not str or not hmac.compare_digest(authorization, "Bearer " + self._token):
                raise FixtureError("credentials_invalid")
            if path != MEMBER:
                raise FixtureError("route_invalid")
            gate = None
            if method == "PROPFIND" and self.metadata < 2:
                kind = "metadata"
            elif method == "GET" and self.metadata == 2:
                kind, gate = "get", "first_get"
            else:
                raise FixtureError("sequence_invalid")
            request = (kind, self.case, gate)
            self._pending = request
            self.requests += 1
            if gate is not None:
                self.gates[gate]["entered"] = True
                self._event("get_held")
            return request

    def response(self, request, endpoint):
        with self.lock:
            if request is not self._pending or self._reply is not None or not self.source_preserved():
                raise FixtureError("sequence_invalid")
            kind, case, gate = request
            if gate is not None and not self.gates[gate]["released"]:
                raise FixtureError("gate_invalid")
            if kind == "metadata":
                result = (207, METADATA, {"Content-Type": "application/xml; charset=utf-8"}, 0)
            elif case == "accepted_token":
                result = (200, self._body, {"Content-Type": "application/octet-stream"}, len(self._body))
            else:
                result = (401, b"", {"WWW-Authenticate": 'Bearer realm="synthetic"'}, 0)
            self._reply = result
            return result

    def commit(self, request, status, sent_bytes, payload):
        with self.lock:
            if (request is not self._pending or self._reply is None or type(status) is not int or
                    status != self._reply[0] or type(payload) is not int or payload != self._reply[3] or
                    type(sent_bytes) is not int or not 1 <= sent_bytes <= 4096):
                raise FixtureError("sequence_invalid")
            self.response_bytes += sent_bytes
            self.payload_bytes += payload
            if self.response_bytes > 524288:
                raise FixtureError("byte_limit")
            if request[0] == "metadata":
                self.metadata += 1
                self._event("metadata", 207)
            else:
                self.completed = True
                self._event("content" if self.case == "accepted_token" else "bearer_denied", status, payload)
            self._pending = self._reply = None

    def _snapshot(self):
        return dict(case=self.case, requests=self.requests, payload_bytes=self.payload_bytes,
            response_bytes=self.response_bytes, source_preserved=self.source_preserved(), errors=list(self.errors),
            events=[dict(ordinal=i + 1, kind=kind, status=status, object_bytes=payload)
                    for i, (kind, status, payload) in enumerate(self.events)])

    def snapshot_case(self, case):
        with self.lock:
            if case == self.case:
                return self._snapshot()
            if case == "accepted_token" and len(self.history) == 1:
                prior = self.history[0]
                return dict(prior, events=[dict(e) for e in prior["events"]], errors=list(self.errors),
                            source_preserved=self.source_preserved())
            raise FixtureError("sequence_invalid")

    def snapshot(self):
        with self.lock:
            value = self._snapshot()
            value["active_requests"] = int(self._pending is not None)
        value["transport"] = self._transport.transport_snapshot() if self._transport else None
        return value

    def advance(self, *, successful, reaped):
        with self.lock:
            if (successful is not True or reaped is not True or self.errors or self.case != CASES[0] or self.history or
                    not self.completed or self._pending is not None or self.requests != 3 or self.payload_bytes != 30):
                raise FixtureError("sequence_invalid")
            self.history.append(self._snapshot())
            self.case = CASES[1]
            self._reset()


class _Server(_http._Server):
    def __init__(self, state):
        super().__init__(state)
        self._close_attempted = False
        self._dispatch_lock = threading.Lock()

    def close(self):
        if self._close_attempted:
            if not self.cleanup_complete:
                raise FixtureError("cleanup_failed")
            return
        self._close_attempted = True
        super().close()

    def _parse(self, stream):
        line = stream.readline(4097)
        if len(line) > 4096 or not re.fullmatch(rb"[A-Z]+ /[^\x00-\x20\x7f-\xff]* HTTP/1\.[01]\r\n", line):
            raise FixtureError("request_invalid")
        method, target, _ = line.decode("ascii").split(" ")
        headers, total = {}, len(line)
        for _ in range(_http.MAX_HEADER_LINES):
            line = stream.readline(_http.MAX_HEADER_BYTES + 1)
            total += len(line)
            if total > _http.MAX_HEADER_BYTES or not line.endswith(b"\r\n"):
                raise FixtureError("headers_invalid")
            if line == b"\r\n":
                break
            name, colon, value = line[:-2].partition(b":")
            if not colon or not _http.HEADER.fullmatch(name) or any(c < 32 or c > 126 for c in value):
                raise FixtureError("headers_invalid")
            name = name.decode("ascii").lower()
            if name in headers:
                raise FixtureError("headers_invalid")
            headers[name] = value.decode("ascii").strip(" ")
        else:
            raise FixtureError("headers_invalid")
        allowed = {"host", "user-agent", "accept", "accept-encoding", "connection", "content-length",
                   "authorization", "referer", "depth", "range"}
        if (set(headers) - allowed or headers.get("host") != f"127.0.0.1:{self.port}" or
                headers.get("referer") != self.endpoint or
                headers.get("connection", "close").lower() not in {"close", "keep-alive"} or
                headers.get("accept-encoding", "identity") not in {"identity", "gzip"}):
            raise FixtureError("headers_invalid")
        if method not in {"PROPFIND", "GET"}:
            raise FixtureError("method_rejected")
        try:
            path = unquote(target[1:], encoding="utf-8", errors="strict")
        except UnicodeError:
            raise FixtureError("route_invalid") from None
        if target != "/" + quote(path, safe="/") or path != MEMBER:
            raise FixtureError("route_invalid")
        if method == "PROPFIND":
            if (headers.get("depth") != "0" or "range" in headers or
                    headers.get("content-length") != str(len(PROPFIND_BODY))):
                raise FixtureError("headers_invalid")
            # The watchdog closes the socket at its absolute request deadline even
            # if a slow body keeps the per-socket inactivity timeout from expiring.
            body = bytearray()
            while len(body) < len(PROPFIND_BODY):
                part = stream.read(len(PROPFIND_BODY) - len(body))
                if not part:
                    raise FixtureError("request_body_rejected")
                body.extend(part)
            if bytes(body) != PROPFIND_BODY:
                raise FixtureError("request_body_rejected")
        elif headers.get("depth") != "0" or headers.get("content-length", "0") != "0":
            raise FixtureError("headers_invalid")
        if "range" in headers and (method != "GET" or headers["range"] not in {"bytes=0-", "bytes=0-29"}):
            raise FixtureError("headers_invalid")
        return method, path, headers.get("authorization")

    def _wait_gate(self, sock, gate):
        with self.lock:
            if sock not in self.sockets:
                raise FixtureError("socket_unowned")
            # Observation must fit the accepted request's original deadline.
            # Holding the GET never extends it to the fixture lifetime.
        while not self.state.wakes[gate].is_set() and not self.stopping.is_set():
            self._live(sock)
            if select.select([sock], [], [], 0.05)[0]:
                raise FixtureError("client_aborted")
        if self.stopping.is_set() or not self.state.gates[gate]["released"]:
            raise FixtureError("gate_invalid")
        self._live(sock)

    def _acquire_dispatch(self, sock):
        while True:
            self._live(sock)
            with self.lock:
                remaining = min(self.deadline, self.sockets[sock]) - time.monotonic()
            if remaining <= 0:
                raise FixtureError("request_timeout")
            # Keep the original deadline and let stopped/closed waiters leave
            # promptly. No state or transport lock is held during this wait.
            if self._dispatch_lock.acquire(timeout=min(0.05, remaining)):
                return

    def _worker(self, sock):
        dispatch_owned = False
        try:
            sock.settimeout(_http.REQUEST_SECONDS)
            with sock.makefile("rb", buffering=0) as stream:
                fields = self._parse(stream)
                if select.select([sock], [], [], 0)[0] and sock.recv(1, socket.MSG_PEEK):
                    raise FixtureError("request_body_rejected")
                self._acquire_dispatch(sock)
                dispatch_owned = True
                self._live(sock)
                request = self.state.begin(*fields)
                if request[2] is not None:
                    self._wait_gate(sock, request[2])
                self._live(sock)
                status, body, headers, payload = self.state.response(request, self.endpoint.rstrip("/"))
                wire = (f"HTTP/1.1 {status} " + {200: "OK", 207: "Multi-Status", 401: "Unauthorized"}[status] +
                    f"\r\nContent-Length: {len(body)}\r\nConnection: close\r\n" +
                    "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n").encode("ascii")
                wire += body
                if len(wire) > 4096:
                    raise FixtureError("byte_limit")
                # The peer can see all bytes before sendall returns or this
                # worker resumes. Keep successors outside begin until commit,
                # without holding the state lock across network I/O.
                sock.sendall(wire)
                self.state.commit(request, status, len(wire), payload)
        except FixtureError as error:
            self.state._error(str(error))
        except (OSError, ValueError):
            self.state._error("connection_failed")
        except BaseException:
            self.state._error("worker_failed")
        finally:
            if dispatch_owned:
                self._dispatch_lock.release()
            with self.lock:
                try:
                    self._close_socket(sock)
                except OSError:
                    self.state._error("cleanup_failed")
                else:
                    self.sockets.pop(sock, None)


@contextmanager
def serve_bearer(state):
    if type(state) is not AppBearerState or state._served:
        raise ValueError("input_invalid")
    state._served = True
    server = _Server(state)
    state._transport = server
    try:
        server.start()
        yield server
    finally:
        server.close()
