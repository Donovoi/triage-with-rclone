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


# Separate opt-in cancellation fixture. Renewal/v1 above remains unchanged.
CANCEL_BODY = bytes(range(256)) * 1024
CANCEL_SHA256 = "2312394bd99545d9de131c24efb781e765ac1aec243f2ed9347597a793a415e9"
CANCEL_MD5 = "d19215b1d714757e1fdb0060c52fd4c8"
CANCEL_OBJECT = ACCOUNT + "/synthetic-bucket/large/cancel.bin"


class AppSwiftCancellationState(AppSwiftState):
    def __init__(self, user, key):
        super().__init__("token_replacement", user, key)
        self.case, self._body = "cancellation", CANCEL_BODY
        self.chunks = 0
        self.headers_committed = False
        self.prefix_released = self.cancel_armed = self.disconnected = False

    def source_preserved(self):
        return (type(self._body) is bytes and self._body == CANCEL_BODY and len(self._body) == 262144 and
                hashlib.sha256(self._body).hexdigest() == CANCEL_SHA256)

    def begin(self, method, path, user=None, key=None, token=None):
        if path not in {AUTH, CANCEL_OBJECT}:
            raise FixtureError("route_invalid")
        return super().begin(method, OBJECT if path == CANCEL_OBJECT else path, user, key, token)

    def response(self, request, origin):
        with self.lock:
            if request[0] == "get":
                if request is not self._pending or self.errors or self._reply is not None or request[1] != "copy_initial":
                    raise FixtureError("sequence_invalid")
                result = (200, self._body, {"Content-Type": "application/octet-stream", "Etag": CANCEL_MD5,
                    "Last-Modified": "Mon, 01 Jan 2024 00:00:00 GMT", "Accept-Ranges": "bytes"}, 0)
                self._reply = result
                return result
            result = super().response(request, origin)
            if request[0] == "head":
                result[2]["Etag"] = CANCEL_MD5
            return result

    def commit_headers(self, request, sent):
        with self.lock:
            if (request is not self._pending or request[0] != "get" or self._reply is None or
                    self._reply[0] != 200 or self.headers_committed or type(sent) is not int or not 1 <= sent <= 4096 or self.response_bytes > 40960):
                raise FixtureError("sequence_invalid")
            self.headers_committed = True
            self.response_bytes += sent
            self._event("headers", "copy_initial", 200)

    def commit_chunk(self, request, body):
        with self.lock:
            if (request is not self._pending or request[0] != "get" or self.errors or not self.headers_committed or self.chunks not in {0, 1} or
                    self.chunks == 1 and not self.prefix_released or type(body) is not bytes or
                    body != self._body[self.chunks * 65536:(self.chunks + 1) * 65536]):
                raise FixtureError("sequence_invalid")
            self.chunks += 1
            self.payload_bytes += len(body)
            self.response_bytes += len(body)
            if self.response_bytes > 524288:
                raise FixtureError("byte_limit")
            self._event("chunk", "copy_initial", 200, len(body))

    def release_prefix(self):
        with self.lock:
            if self.errors or self.chunks != 1 or self.prefix_released:
                raise FixtureError("gate_invalid")
            self.prefix_released = True
            self._event("prefix_released", "copy_initial")

    def arm_cancel(self):
        with self.lock:
            if self.errors or self.chunks != 2 or not self.prefix_released or self.cancel_armed:
                raise FixtureError("gate_invalid")
            self.cancel_armed = True
            self._event("cancel_armed", "copy_initial")

    def peer_closed(self):
        with self.lock:
            if self.errors or self.chunks != 2 or not self.cancel_armed or self.disconnected:
                raise FixtureError("client_aborted")
            self.disconnected = True
            self._event("disconnected", "copy_initial")

    def held_teardown(self):
        with self.lock:
            if self.errors or self.chunks != 2 or not self.cancel_armed or self.disconnected:
                raise FixtureError("gate_invalid")
            self.disconnected = True
            self._event("held_teardown", "copy_initial")

    def cancel_snapshot(self):
        with self.lock:
            return dict(chunks=self.chunks, prefix_released=self.prefix_released,
                cancel_armed=self.cancel_armed, disconnected=self.disconnected)


class _CancellationServer(_Server):
    # Parser is the same closed grammar as renewal, with just the fixed object changed.
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
                headers.get("content-length", "0") != "0" or target not in {AUTH, CANCEL_OBJECT} or
                headers.get("accept-encoding", "identity") not in {"identity", "gzip"} or
                headers.get("connection", "close").lower() not in {"close", "keep-alive"} or
                "range" in headers and (method != "GET" or target != CANCEL_OBJECT or headers["range"] != "bytes=0-")):
            raise FixtureError("headers_invalid")
        return method, target, headers.get("x-auth-user"), headers.get("x-auth-key"), headers.get("x-auth-token")

    def _cancel_wait(self, sock, *, tail):
        while not self.stopping.is_set():
            try:
                self._live(sock)  # Original request/lifetime clocks; no deadline extension.
            except FixtureError:
                if self.stopping.is_set() and tail:
                    break
                raise
            snapshot = self.state.cancel_snapshot()
            if not tail and snapshot["prefix_released"]:
                return True
            try:
                readable = select.select([sock], [], [], 0.05)[0]
                if readable:
                    if not tail:
                        raise FixtureError("client_aborted")
                    try:
                        incoming = sock.recv(1, socket.MSG_PEEK)
                    except ConnectionResetError:
                        incoming = b""  # Same EOF treatment as the existing HTTP held-transfer path.
                    if incoming:
                        raise FixtureError("client_aborted")
                    self.state.peer_closed()
                    return False
            except (OSError, ValueError):
                if not self.stopping.is_set() or not tail:
                    raise
                break
        if tail:
            self.state.held_teardown()
        return False  # Teardown never releases the remaining content.

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
                status, body, headers, payload = self.state.response(request, self.endpoint.rstrip("/"))
                wire = (f"HTTP/1.1 {status} OK\r\nContent-Length: {len(body)}\r\nConnection: close\r\n" +
                    "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n").encode("ascii")
                if len(wire) > 4096:
                    raise FixtureError("byte_limit")
                sock.sendall(wire)
                if request[0] != "get":
                    self.state.commit(request, status, len(wire), payload)
                else:
                    self.state.commit_headers(request, len(wire))
                    chunk = body[:65536]
                    sock.sendall(chunk)
                    self.state.commit_chunk(request, chunk)
                    if self._cancel_wait(sock, tail=False):
                        self._live(sock)
                        chunk = body[65536:131072]
                        sock.sendall(chunk)
                        self.state.commit_chunk(request, chunk)
                        self._cancel_wait(sock, tail=True)
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
def serve_swift_cancellation(state):
    if type(state) is not AppSwiftCancellationState or state._served:
        raise ValueError("input_invalid")
    state._served = True
    server = _CancellationServer(state)
    state._transport = server
    try:
        server.start()
        yield server
    finally:
        server.close()

# Separate account-root listing mode; acquisition and cancellation stay unchanged.
LIST_CONTAINER = ACCOUNT + "/synthetic-bucket"
LIST_FILES = (("README-synthetic.txt", BODY), ("empty.txt", b""),
              ("space name.txt", b"Nested synthetic payload.\n"))
LIST_IDS = ("readme", "empty", "space")
LIST_TARGETS = {AUTH: ("grant", "listing"),
    ACCOUNT + "?format=json&limit=10000": ("account", "account"),
    LIST_CONTAINER + "?delimiter=%2F&format=json&limit=1000": ("container", "container"),
    **{LIST_CONTAINER + "/" + name.replace(" ", "%20"): ("head", role)
       for (name, _), role in zip(LIST_FILES, LIST_IDS)}}


class AppSwiftListingState(AppSwiftState):
    def __init__(self, user, key):
        super().__init__("token_replacement", user, key)
        self.case = "listing"
        self._files = dict(LIST_FILES)
        self.token = None
        self.account_done = self.container_done = False
        self.heads = set()
        self.gates = {"listing_auth": dict(entered=False, released=False)}
        self.wakes = {"listing_auth": threading.Event()}

    def source_preserved(self):
        return (type(self._files) is dict and set(self._files) == {n for n, _ in LIST_FILES} and
                all(type(self._files[n]) is bytes and self._files[n] == body for n, body in LIST_FILES))

    def begin(self, method, path, user=None, key=None, token=None):
        with self.lock:
            if self.errors or self._pending is not None or self.completed:
                raise FixtureError("sequence_invalid")
            if self.requests >= 128:
                raise FixtureError("request_limit")
            self.requests += 1
            if not self.source_preserved():
                raise FixtureError("source_changed")
            if type(path) is not str or path not in LIST_TARGETS:
                raise FixtureError("route_invalid")
            kind, role = LIST_TARGETS[path]
            if method != ("HEAD" if kind == "head" else "GET"):
                raise FixtureError("method_rejected")
            if kind == "grant":
                if (self.token is not None or self.gates["listing_auth"]["entered"] or token is not None or
                        type(user) is not str or type(key) is not str or
                        not hmac.compare_digest(user, self._user) or not hmac.compare_digest(key, self._key)):
                    raise FixtureError("credentials_invalid")
                token = "synthetic-" + secrets.token_hex(24)
                gate = "listing_auth"
                self.gates[gate]["entered"] = True
                self._event("auth_held", "listing")
            else:
                if (user is not None or key is not None or self.token is None or type(token) is not str or
                        not hmac.compare_digest(token, self.token)):
                    raise FixtureError("token_invalid")
                if (kind == "account" and self.account_done or
                        kind == "container" and (not self.account_done or self.container_done) or
                        kind == "head" and (not self.container_done or role in self.heads)):
                    raise FixtureError("sequence_invalid")
                gate = None
            self._pending = (kind, role, gate, token)
            return self._pending

    def release_gate(self, name):
        with self.lock:
            if (name != "listing_auth" or self.errors or self._pending is None or self._pending[2] != name or
                    not self.gates[name]["entered"] or self.gates[name]["released"]):
                raise FixtureError("gate_invalid")
            self.gates[name]["released"] = True
            self._event("gate_released", "listing")
            self.wakes[name].set()

    def response(self, request, origin):
        import json
        with self.lock:
            if request is not self._pending or self.errors or self._reply is not None or not self.source_preserved():
                raise FixtureError("sequence_invalid")
            kind, role, gate, token = request
            headers = {}
            if kind == "grant":
                if (not self.gates[gate]["released"] or type(origin) is not str or
                        not re.fullmatch(r"http://127\.0\.0\.1:[1-9][0-9]{0,4}", origin)):
                    raise FixtureError("gate_invalid")
                body = b""
                headers = {"X-Auth-Token": token, "X-Storage-Url": origin + ACCOUNT}
            elif kind == "head":
                name, body = LIST_FILES[LIST_IDS.index(role)]
                headers = {"Content-Type": "application/octet-stream", "Etag": hashlib.md5(body).hexdigest(),
                    "Last-Modified": "Mon, 01 Jan 2024 00:00:00 GMT", "Accept-Ranges": "bytes"}
            else:
                rows = ([dict(name="synthetic-bucket", count=3, bytes=88)] if kind == "account" else
                    [dict(name=name, bytes=len(body), hash=hashlib.md5(body).hexdigest(),
                          content_type="application/octet-stream", last_modified="2024-01-01T00:00:00.000000")
                     for name, body in LIST_FILES])
                body = json.dumps(rows, separators=(",", ":")).encode("ascii")
                headers = {"Content-Type": "application/json"}
            self._reply = (200, body, headers, 0)  # JSON metadata is not object content.
            return self._reply

    def commit(self, request, status, sent_bytes, payload):
        with self.lock:
            if (self.errors or not self.source_preserved() or request is not self._pending or self._reply is None or
                    type(status) is not int or status != 200 or type(payload) is not int or payload != 0 or
                    type(sent_bytes) is not int or not 1 <= sent_bytes <= 4096 or self.response_bytes + sent_bytes > 524288):
                raise FixtureError("sequence_invalid")
            kind, role, _, token = request
            if kind == "grant":
                self.token = token
            elif kind == "account":
                self.account_done = True
            elif kind == "container":
                self.container_done = True
            else:
                self.heads.add(role)
                self.completed = len(self.heads) == 3
            self._event(kind, role, 200)
            self.response_bytes += sent_bytes
            self._pending = self._reply = None


class _ListingServer(_Server):
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
                headers.get("content-length", "0") != "0" or target not in LIST_TARGETS or
                headers.get("accept-encoding", "identity") not in {"identity", "gzip"} or
                headers.get("connection", "close").lower() not in {"close", "keep-alive"} or
                "range" in headers):
            raise FixtureError("headers_invalid")
        return method, target, headers.get("x-auth-user"), headers.get("x-auth-key"), headers.get("x-auth-token")

    def _wait_gate(self, sock, gate):
        with self.lock:
            if sock not in self.sockets:
                raise FixtureError("socket_unowned")
        while not self.state.wakes[gate].is_set() and not self.stopping.is_set():
            self._live(sock)
            if select.select([sock], [], [], 0.05)[0]:
                raise FixtureError("client_aborted")
        if self.stopping.is_set() or not self.state.gates[gate]["released"]:
            raise FixtureError("gate_invalid")
        self._live(sock)

    def _worker(self, sock):
        dispatch_owned = False
        try:
            sock.settimeout(_http.REQUEST_SECONDS)
            with sock.makefile("rb", buffering=0) as stream:
                self._live(sock)
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
                self._live(sock)
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
def serve_swift_listing(state):
    if type(state) is not AppSwiftListingState or state._served:
        raise ValueError("input_invalid")
    state._served = True
    server = _ListingServer(state)
    state._transport = server
    try:
        server.start()
        yield server
    finally:
        server.close()
