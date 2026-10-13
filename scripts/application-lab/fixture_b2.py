"""Independent synthetic B2 HTTP fixture; no listener or process on import.

The HTTP sibling owns bounded socket/thread teardown. This module narrows its
absolute lifetime to 60 seconds, requests/events to 32 and per-request I/O to
3 seconds. Two private token objects are associated by metadata and retained
copy-process gates, never by assuming the first grant belongs to the copy.
"""
import base64
from contextlib import contextmanager
import hashlib
import hmac
import json
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
_http = types.ModuleType("b2_owned_http")
_http.__file__ = str(_PATH)
exec(compile(_BYTES, str(_PATH), "exec"), _http.__dict__)
del _BYTES
FixtureError = _http.FixtureError
CASES = ("token_replacement", "download_cap_denial")
GATES = ("first_get", "replacement_get")
BODY = b"synthetic application fixture\n"
BUCKET, MEMBER, FILE_ID = "synthetic-bucket", "README-synthetic.txt", "synthetic-file-0"
AUTH = "/b2api/v4/b2_authorize_account"
HEAD = "/file/" + BUCKET + "/" + MEMBER
GET = "/b2api/v1/b2_download_file_by_id?fileId=" + FILE_ID
ERROR_MESSAGE = "synthetic fixture response"
ERROR_CODES = _http.ERROR_CODES | {"credentials_invalid", "token_invalid", "sequence_invalid", "gate_invalid"}


class AppB2State:
    def __init__(self, case, user, key):
        if case not in CASES or any(type(v) is not str or not re.fullmatch(r"[a-f0-9]{64}", v) for v in (user, key)):
            raise ValueError("input_invalid")
        self.case, self._user, self._key = case, user, key
        self.lock = threading.RLock()
        self.errors, self.events = [], []
        self.tokens, self.heads = {}, set()
        self.initial = self.replacement = None
        self.requests = self.payload_bytes = self.response_bytes = 0
        self.injected = self.completed = self.denied = False
        self.gates = {g: dict(entered=False, released=False) for g in GATES}
        self.wakes = {g: threading.Event() for g in GATES}
        self._served = False
        self._transport = None
        self._body = BODY

    def source_preserved(self):
        return type(self._body) is bytes and self._body == BODY

    def _error(self, code):
        with self.lock:
            code = code if code in ERROR_CODES else "worker_failed"
            if code not in self.errors:
                self.errors.append(code)

    def _event(self, kind, token=None, status=0, payload=0):
        if len(self.events) >= 32:
            raise FixtureError("event_limit")
        self.events.append((kind, token, status, payload))

    def gate_snapshot(self):
        with self.lock:
            return {k: dict(entered=1 if v["entered"] else None, released=v["released"]) for k, v in self.gates.items()}

    def release_gate(self, name):
        with self.lock:
            if name not in GATES or self.errors or not self.gates[name]["entered"] or self.gates[name]["released"]:
                raise FixtureError("gate_invalid")
            if name == "replacement_get" and not self.injected:
                raise FixtureError("gate_invalid")
            self.gates[name]["released"] = True
            self._event("gate_released", self.initial if name == "first_get" else self.replacement)
            self.wakes[name].set()

    def release_observation(self):
        # Teardown wakeups never set the qualifying released flag.
        for wake in self.wakes.values():
            wake.set()

    release_cancel = release_observation

    def begin(self, method, path, authorization):
        """Pure request classification. Caller serializes reply+commit under lock."""
        with self.lock:
            # Count admitted classifications only, not connections after terminal
            # failure. Atomically latch overflow before any concurrent worker can
            # advance the counter beyond its finite receipt representation.
            if self.errors:
                raise FixtureError("sequence_invalid")
            if self.requests >= 32:
                self._error("request_limit")
                raise FixtureError("request_limit")
            self.requests += 1
            if not self.source_preserved():
                raise FixtureError("sequence_invalid")
            if method == "GET" and path == AUTH:
                expected = "Basic " + base64.b64encode((self._user + ":" + self._key).encode("ascii")).decode("ascii")
                if not hmac.compare_digest(authorization, expected):
                    raise FixtureError("credentials_invalid")
                if self.completed or self.denied or self.initial is not None and not self.injected:
                    raise FixtureError("sequence_invalid")
                if len(self.tokens) >= (3 if self.case == "token_replacement" else 2):
                    raise FixtureError("sequence_invalid")
                if self.injected and self.replacement is not None:
                    raise FixtureError("sequence_invalid")
                token = "synthetic-" + secrets.token_hex(24)
                if token in self.tokens:
                    raise FixtureError("token_invalid")
                self.tokens[token] = True
                if self.injected:
                    self.replacement = token
                return "grant", token, None
            token = authorization
            if token not in self.tokens or token == self.initial and self.injected:
                raise FixtureError("token_invalid")
            if method == "HEAD" and path == HEAD:
                if self.initial is not None or token in self.heads:
                    raise FixtureError("sequence_invalid")
                return "head", token, None
            if method != "GET" or path != GET or self.completed or self.denied:
                raise FixtureError("route_invalid")
            if self.initial is None:
                # Independent prior stat token/HEAD is retained, not relabelled.
                if token not in self.heads or len(self.heads - {token}) != 1 or len(self.tokens) != 2:
                    raise FixtureError("sequence_invalid")
                self.initial = token
                gate = "first_get"
            else:
                if self.case != "token_replacement" or not self.injected or token != self.replacement:
                    raise FixtureError("sequence_invalid")
                gate = "replacement_get"
            if self.gates[gate]["entered"]:
                raise FixtureError("gate_invalid")
            self.gates[gate]["entered"] = True
            self._event("get_held", token)
            return "get", token, gate

    def response(self, request, origin):
        kind, token, gate = request
        if kind == "grant":
            body = {"accountId": "synthetic-account", "authorizationToken": token,
                "apiInfo": {"storageApi": {"apiUrl": origin, "downloadUrl": origin,
                "absoluteMinimumPartSize": 5000000, "recommendedPartSize": 100000000,
                "allowed": {"buckets": [{"id": "synthetic-bucket-id", "name": BUCKET}],
                "capabilities": ["listFiles", "readFiles"], "namePrefix": None}}}}
            return 200, json.dumps(body, separators=(",", ":")).encode("ascii"), {"Content-Type": "application/json"}, 0
        headers = {"Content-Type": "application/octet-stream", "X-Bz-File-Id": FILE_ID,
            "X-Bz-File-Name": MEMBER, "X-Bz-Content-Sha1": hashlib.sha1(BODY).hexdigest(),
            "X-Bz-Upload-Timestamp": "1704067200000", "X-Bz-Info-src_last_modified_millis": "1704067200000"}
        if kind == "head":
            return 200, BODY, headers, 0
        if not self.gates[gate]["released"] or self.errors:
            raise FixtureError("gate_invalid")
        if gate == "replacement_get":
            return 200, BODY, headers, len(BODY)
        status, code = (401, "expired_auth_token") if self.case == "token_replacement" else (403, "download_cap_exceeded")
        body = json.dumps(dict(status=status, code=code, message=ERROR_MESSAGE), separators=(",", ":")).encode("ascii")
        return status, body, {"Content-Type": "application/json"}, 0

    def commit(self, request, status, sent_bytes, payload):
        kind, token, gate = request
        self.response_bytes += sent_bytes
        self.payload_bytes += payload
        if self.response_bytes > 16384:
            raise FixtureError("byte_limit")
        if kind == "head":
            self.heads.add(token)
            self._event("head", token, 200)
        elif kind == "grant":
            self._event("grant", token, 200)
        elif gate == "replacement_get":
            self.completed = True
            self._event("content", token, 200, payload)
        elif status == 401:
            self.injected = True
            self._event("expired_token", token, 401)
        else:
            self.denied = True
            self._event("download_cap", token, 403)

    def snapshot(self):
        with self.lock:
            def role(token):
                return "copy_initial" if token == self.initial else "copy_replacement" if token == self.replacement else "pre_copy"
            return dict(case=self.case, requests=self.requests, payload_bytes=self.payload_bytes,
                response_bytes=self.response_bytes, source_preserved=self.source_preserved(), errors=list(self.errors),
                events=[dict(ordinal=i + 1, kind=k, role=role(t), status=s, object_bytes=b)
                        for i, (k, t, s, b) in enumerate(self.events)])


class _Server(_http._Server):
    def __init__(self, state):
        super().__init__(state)
        self.deadline = time.monotonic() + 60
        self._close_attempted = False

    def close(self):
        # start() may already have attempted teardown after a thread failure.
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
        for _ in range(32):
            line = stream.readline(8193)
            total += len(line)
            if total > 8192 or not line.endswith(b"\r\n"):
                raise FixtureError("headers_invalid")
            if line == b"\r\n":
                break
            key, colon, value = line[:-2].partition(b":")
            if not colon or not _http.HEADER.fullmatch(key) or any(c < 32 or c > 126 for c in value):
                raise FixtureError("headers_invalid")
            key = key.decode("ascii").lower()
            if key in headers:
                raise FixtureError("headers_invalid")
            headers[key] = value.decode("ascii").strip(" ")
        else:
            raise FixtureError("headers_invalid")
        if (set(headers) - {"host", "user-agent", "accept", "accept-encoding", "connection", "content-length", "authorization", "range"}
                or headers.get("host") != f"127.0.0.1:{self.port}" or headers.get("content-length", "0") != "0"
                or headers.get("accept-encoding", "identity") not in {"identity", "gzip"}
                or headers.get("connection", "close").lower() not in {"close", "keep-alive"}
                or "authorization" not in headers or target not in {AUTH, HEAD, GET}
                or "range" in headers and (target != GET or headers["range"] != "bytes=0-")):
            raise FixtureError("headers_invalid")
        return method, target, headers["authorization"]

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

    def _worker(self, sock):
        try:
            with self.lock:
                self.sockets[sock] = min(self.deadline, time.monotonic() + 3)
            sock.settimeout(3)
            with sock.makefile("rb", buffering=0) as stream:
                method, path, authorization = self._parse(stream)
                if select.select([sock], [], [], 0)[0] and sock.recv(1, socket.MSG_PEEK):
                    raise FixtureError("request_body_rejected")
                request = self.state.begin(method, path, authorization)
                if request[2] is not None:
                    self._wait_gate(sock, request[2])
                self._live(sock)
                # Do not acquire transport lock inside state lock. A completed
                # write and commit are atomic against the next request's begin.
                with self.state.lock:
                    status, body, headers, payload = self.state.response(request, self.endpoint.rstrip("/"))
                    wire = (f"HTTP/1.1 {status} " + {200: "OK", 401: "Unauthorized", 403: "Forbidden"}[status] +
                        f"\r\nContent-Length: {len(body)}\r\nConnection: close\r\n" +
                        "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n").encode("ascii")
                    wire += body if method == "GET" else b""
                    if len(wire) > 4096:
                        raise FixtureError("byte_limit")
                    sock.sendall(wire)
                    self.state.commit(request, status, len(wire), payload)
        except FixtureError as error:
            self.state._error(str(error))
        except (OSError, ValueError):
            self.state._error("connection_failed")
        except BaseException:
            self.state._error("worker_failed")
        finally:
            with self.lock:
                try:
                    self._close_socket(sock)
                except OSError:
                    self.state._error("cleanup_failed")
                else:
                    self.sockets.pop(sock, None)


@contextmanager
def serve_b2(state):
    if type(state) is not AppB2State or state._served:
        raise ValueError("input_invalid")
    state._served = True
    server = _Server(state)
    state._transport = server
    try:
        server.start()
        yield server
    finally:
        server.close()
