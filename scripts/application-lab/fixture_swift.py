"""Synthetic Swift v1 token replacement/renewal-denial application fixture.

Import and model construction do not start listeners, threads or applications.
The unchanged HTTP sibling owns admission, deadlines and transport teardown.
"""
from contextlib import contextmanager
import hashlib
import hmac
from pathlib import Path
import re
import secrets
import select
import socket
import threading
import time
import types

_PATH = Path(__file__).absolute().with_name("fixture_http.py")
_BYTES = _PATH.read_bytes()
loaded_http_source_sha256 = hashlib.sha256(_BYTES).hexdigest()
_http = types.ModuleType("swift_owned_http")
_http.__file__ = str(_PATH)
exec(compile(_BYTES, str(_PATH), "exec"), _http.__dict__)
del _BYTES
FixtureError = _http.FixtureError
CASES = ("token_replacement", "renewal_denial")
GATES = ("first_get", "replacement_get", "renewal_auth")
BODY = b"Synthetic provider protocol fixture. No account or user data.\n"
SHA256 = "1e901527b93ae84dc9d95a8aa76bbc12d7d77dbf8ab449333c172cfc909c639e"
MD5 = "f9ac90560b9929242009ee0c24c9e5d8"
AUTH = "/auth/v1.0"
ACCOUNT = "/v1/AUTH_synthetic"
OBJECT = ACCOUNT + "/synthetic-bucket/README-synthetic.txt"
ERROR_CODES = _http.ERROR_CODES | {"credentials_invalid", "token_invalid", "sequence_invalid", "gate_invalid"}


class AppSwiftState:
    def __init__(self, case, user, key):
        if type(case) is not str or case not in CASES or any(
                type(v) is not str or not re.fullmatch(r"[a-f0-9]{64}", v) for v in (user, key)):
            raise ValueError("input_invalid")
        self.case, self._user, self._key = case, user, key
        self.lock = threading.RLock()
        self.errors, self.events = [], []
        self.tokens, self.heads = {}, dict.fromkeys(("stat", "copy_initial", "copy_replacement"), 0)
        self.requests = self.payload_bytes = self.response_bytes = 0
        self.injected = self.completed = self.denied = False
        self.gates = {g: dict(entered=False, released=False) for g in GATES}
        self.wakes = {g: threading.Event() for g in GATES}
        self._pending = self._reply = None
        self._served = False
        self._transport = None
        self._body = BODY

    def source_preserved(self):
        return type(self._body) is bytes and self._body == BODY and len(self._body) == 62 and hashlib.sha256(self._body).hexdigest() == SHA256

    def _error(self, code):
        with self.lock:
            code = code if type(code) is str and code in ERROR_CODES else "worker_failed"
            if code not in self.errors:
                self.errors.append(code)

    def _event(self, kind, role, status=0, payload=0):
        if len(self.events) >= 512:
            raise FixtureError("event_limit")
        self.events.append((kind, role, status, payload))

    def gate_snapshot(self):
        with self.lock:
            return {k: dict(entered=1 if v["entered"] else None, released=v["released"]) for k, v in self.gates.items()}

    def release_gate(self, name):
        with self.lock:
            if name not in GATES or self.errors or not self.gates[name]["entered"] or self.gates[name]["released"]:
                raise FixtureError("gate_invalid")
            if self._pending is None or self._pending[2] != name or name != "first_get" and not self.injected:
                raise FixtureError("gate_invalid")
            self.gates[name]["released"] = True
            self._event("gate_released", self._pending[1])
            self.wakes[name].set()

    def release_observation(self):
        # Teardown wakes cannot earn qualifying released flags.
        for wake in self.wakes.values():
            wake.set()

    release_cancel = release_observation

    def begin(self, method, path, user=None, key=None, token=None):
        """Reserve one request. No response is committed until its send returns."""
        with self.lock:
            if self.errors or self._pending is not None or self.completed or self.denied:
                raise FixtureError("sequence_invalid")
            if self.requests >= 128:
                self._error("request_limit")
                raise FixtureError("request_limit")
            self.requests += 1
            if not self.source_preserved():
                raise FixtureError("source_changed")
            gate = None
            if method == "GET" and path == AUTH:
                if (type(user) is not str or type(key) is not str or token is not None or
                        not hmac.compare_digest(user, self._user) or not hmac.compare_digest(key, self._key)):
                    raise FixtureError("credentials_invalid")
                if self.injected:
                    if len(self.tokens) != 2:
                        raise FixtureError("sequence_invalid")
                    if self.case == "renewal_denial":
                        kind, role, gate = "deny", "copy_initial", "renewal_auth"
                    else:
                        kind, role = "grant", "copy_replacement"
                elif not self.tokens:
                    kind, role = "grant", "stat"
                elif len(self.tokens) == 1 and self.heads["stat"] > 0:
                    kind, role = "grant", "copy_initial"
                else:
                    raise FixtureError("sequence_invalid")
                if kind == "grant":
                    token = "synthetic-" + secrets.token_hex(24)
                    if token in self.tokens:
                        raise FixtureError("token_invalid")
            else:
                if user is not None or key is not None or type(token) is not str or token not in self.tokens:
                    raise FixtureError("token_invalid")
                role = self.tokens[token]
                if (role == "stat" and len(self.tokens) != 1 or role == "copy_initial" and self.injected or
                        role == "copy_replacement" and not self.injected):
                    raise FixtureError("token_invalid")
                if path != OBJECT:
                    raise FixtureError("route_invalid")
                if method == "HEAD":
                    if self.heads[role] >= 4:
                        raise FixtureError("sequence_invalid")
                    kind = "head"
                elif method == "GET" and role in {"copy_initial", "copy_replacement"}:
                    if role == "copy_initial" and self.heads[role] == 0:
                        raise FixtureError("sequence_invalid")
                    kind, gate = "get", "first_get" if role == "copy_initial" else "replacement_get"
                else:
                    raise FixtureError("sequence_invalid")
            request = (kind, role, gate, token)
            self._pending = request
            if gate is not None:
                if self.gates[gate]["entered"]:
                    raise FixtureError("gate_invalid")
                self.gates[gate]["entered"] = True
                self._event("auth_held" if kind == "deny" else "get_held", role)
            return request

    def response(self, request, origin):
        with self.lock:
            if request is not self._pending or self.errors or self._reply is not None:
                raise FixtureError("sequence_invalid")
            kind, role, gate, token = request
            if gate is not None and not self.gates[gate]["released"]:
                raise FixtureError("gate_invalid")
            if kind == "grant":
                if type(origin) is not str or not re.fullmatch(r"http://127\.0\.0\.1:[1-9][0-9]{0,4}", origin):
                    raise FixtureError("route_invalid")
                result = (200, b"", {"X-Auth-Token": token, "X-Storage-Url": origin + ACCOUNT}, 0)
            elif kind == "deny":
                result = (403, b"", {}, 0)
            elif gate == "first_get":
                result = (401, b"", {}, 0)
            else:
                result = (200, self._body, {"Content-Type": "application/octet-stream", "Etag": MD5,
                    "Last-Modified": "Mon, 01 Jan 2024 00:00:00 GMT", "Accept-Ranges": "bytes"},
                    len(self._body) if kind == "get" else 0)
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
            kind, role, gate, token = request
            if kind == "grant":
                self.tokens[token] = role
                self._event("grant", role, 200)
            elif kind == "head":
                self.heads[role] += 1
                self._event("head", role, 200)
            elif kind == "deny":
                self.denied = True
                self._event("renewal_denied", role, 403)
            elif gate == "first_get":
                self.injected = True
                self._event("storage_401", role, 401)
            else:
                self.completed = True
                self._event("content", role, 200, payload)
            self._pending = self._reply = None

    def snapshot(self):
        with self.lock:
            return dict(case=self.case, requests=self.requests, payload_bytes=self.payload_bytes,
                response_bytes=self.response_bytes, source_preserved=self.source_preserved(), errors=list(self.errors),
                events=[dict(ordinal=i + 1, kind=k, role=r, status=s, object_bytes=b)
                        for i, (k, r, s, b) in enumerate(self.events)])


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
        if not re.fullmatch(rb"(?:GET|HEAD) /[^\x00-\x20\x7f-\xff]{1,2048} HTTP/1\.[01]\r\n", line):
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
        allowed = {"host", "user-agent", "accept", "accept-encoding", "connection", "content-length", "x-auth-user", "x-auth-key", "x-auth-token", "range"}
        if (set(headers) - allowed or headers.get("host") != f"127.0.0.1:{self.port}" or
                headers.get("content-length", "0") != "0" or target not in {AUTH, OBJECT} or
                headers.get("accept-encoding", "identity") not in {"identity", "gzip"} or
                headers.get("connection", "close").lower() not in {"close", "keep-alive"} or
                "range" in headers and (method != "GET" or target != OBJECT or headers["range"] != "bytes=0-")):
            raise FixtureError("headers_invalid")
        return method, target, headers.get("x-auth-user"), headers.get("x-auth-key"), headers.get("x-auth-token")

    def _wait_gate(self, sock, gate):
        with self.lock:
            if sock not in self.sockets:
                raise FixtureError("socket_unowned")
            self.sockets[sock] = self.deadline
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
                wire = (f"HTTP/1.1 {status} " + {200: "OK", 401: "Unauthorized", 403: "Forbidden"}[status] +
                    f"\r\nContent-Length: {len(body)}\r\nConnection: close\r\n" +
                    "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n").encode("ascii")
                wire += body if fields[0] == "GET" else b""
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
def serve_swift(state):
    if type(state) is not AppSwiftState or state._served:
        raise ValueError("input_invalid")
    state._served = True
    server = _Server(state)
    state._transport = server
    try:
        server.start()
        yield server
    finally:
        server.close()
