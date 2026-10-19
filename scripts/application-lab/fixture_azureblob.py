"""Closed SharedKey Blob acquisition fixture. No listener or process on import."""
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
from email.utils import format_datetime, parsedate_to_datetime
import hashlib
import hmac
from pathlib import Path
import re
import select
import socket
import threading
import time
import types

_PATH = Path(__file__).absolute().with_name("fixture_http.py")
_SIGNER_PATH = _PATH.parent.parent / "provider-lab/fixture_servers.py"


def _load(name, path):
    raw = path.read_bytes()
    if not 0 < len(raw) <= 512 * 1024:
        raise ValueError("input_invalid")
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module, hashlib.sha256(raw).hexdigest()


_http, loaded_http_source_sha256 = _load("azureblob_owned_http", _PATH)
_signer, loaded_signer_source_sha256 = _load("azureblob_protocol_signer", _SIGNER_PATH)
FixtureError = _http.FixtureError
CASES = ("acquisition", "denial", "download_denial")
BODY = b"Nested synthetic payload.\n"
ACCOUNT, CONTAINER = "syntheticaccount", "synthetic-container"
MEMBER = "nested/space name.txt"
TARGET = "/syntheticaccount/synthetic-container/nested%2Fspace%20name.txt"
STAMP = "Mon, 01 Jan 2024 00:00:00 GMT"
ERROR_CODES = _http.ERROR_CODES | {"credentials_invalid", "sequence_invalid"}


class AppAzureBlobState:
    def __init__(self, case, key, wrong_key, utc_now=None):
        if type(case) is not str or case not in CASES:
            raise ValueError("input_invalid")
        values = []
        for value in (key, wrong_key):
            if type(value) is not str:
                raise ValueError("input_invalid")
            try:
                decoded = base64.b64decode(value, validate=True)
            except (ValueError, UnicodeError):
                raise ValueError("input_invalid") from None
            if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
                raise ValueError("input_invalid")
            values.append(decoded)
        if values[0] == values[1]:
            raise ValueError("input_invalid")
        self.case, self._key, self._wrong_key = case, *values
        self._original = (case, *values)
        self._body = BODY
        self.lock = threading.RLock()
        self.utc_now = utc_now or (lambda: datetime.now(timezone.utc))
        self.deadline = time.monotonic() + 60
        self.requests = self.payload_bytes = self.response_bytes = 0
        self.errors, self.events = [], []
        self._pending = self._reply = None
        self._served, self._transport = False, None

    def source_preserved(self):
        return (type(self._body) is bytes and self._body == BODY and
                (self.case, self._key, self._wrong_key) == self._original)

    def _error(self, code):
        with self.lock:
            code = code if code in ERROR_CODES else "worker_failed"
            if code not in self.errors:
                self.errors.append(code)

    def release_observation(self):
        pass  # No held request or qualifying release in this mode.

    def release_cancel(self):
        pass

    def begin(self, method, target, headers):
        with self.lock:
            if self.errors or not self.source_preserved():
                raise FixtureError("source_changed")
            if self._pending is not None:
                raise FixtureError("sequence_invalid")
            self.requests += 1
            if self.requests > 128:
                raise FixtureError("request_limit")
            if target != TARGET or method not in ("HEAD", "GET"):
                raise FixtureError("route_invalid")
            try:
                signed = _signer.azure_string_to_sign(ACCOUNT, method, target, headers.items())
                date = headers.get("x-ms-date", "")
                instant = parsedate_to_datetime(date)
                version = headers.get("x-ms-version", "")
                datetime.strptime(version, "%Y-%m-%d")
                age = (self.utc_now() - instant).total_seconds()
                if (instant.tzinfo is None or instant.utcoffset().total_seconds() != 0 or
                        format_datetime(instant, usegmt=True) != date or not 0 <= age <= 900 or
                        not re.fullmatch(r"\d{4}-\d{2}-\d{2}", version)):
                    raise ValueError("date_invalid")
                signatures = ["SharedKey " + ACCOUNT + ":" + base64.b64encode(
                    hmac.new(key, signed.encode("utf-8"), hashlib.sha256).digest()).decode("ascii")
                    for key in (self._key, self._wrong_key)]
                authorization = headers.get("authorization", "")
                expected = signatures[1 if self.case == "denial" else 0]
                if not hmac.compare_digest(authorization, expected):
                    raise ValueError("signature_invalid")
                if self.case == "denial" and hmac.compare_digest(authorization, signatures[0]):
                    raise ValueError("correct_key_not_denial")
            except (ValueError, TypeError, OverflowError):
                raise FixtureError("credentials_invalid") from None
            index = len(self.events)
            expected_methods = ("HEAD",) if self.case == "denial" else ("HEAD", "HEAD", "GET")
            if index >= len(expected_methods) or method != expected_methods[index]:
                raise FixtureError("sequence_invalid")
            ranged = headers.get("x-ms-range")
            if ranged is not None and (method != "GET" or ranged not in ("bytes=0-", "bytes=0-25")):
                raise FixtureError("headers_invalid")
            etag = '"synthetic-' + hashlib.md5(BODY).hexdigest() + '"'
            if headers.get("if-match") not in (None, etag, "*"):
                raise FixtureError("headers_invalid")
            status = 403 if self.case == "denial" or self.case == "download_denial" and method == "GET" else 206 if ranged else 200
            kind = ("wrong_key_denied" if self.case == "denial" else "download_denied" if status == 403 else
                    "head_authenticated" if method == "HEAD" else "content_authenticated")
            request = (method, kind, "stat" if index == 0 else "copy", status)
            self._pending = request
            return request

    def response(self, request):
        with self.lock:
            if self.errors or not self.source_preserved() or self._pending is not request or self._reply is not None:
                raise FixtureError("sequence_invalid")
            method, _, _, status = request
            headers = {"x-ms-request-id": "synthetic-request"}
            if status == 403:
                body = b""
                size = 0
                headers["x-ms-error-code"] = "AuthorizationFailure" if self.case == "download_denial" else "AuthenticationFailed"
            else:
                body = BODY if method == "GET" else b""
                size = len(BODY)
                headers.update({"Content-Type": "application/octet-stream", "Last-Modified": STAMP,
                    "ETag": '"synthetic-' + hashlib.md5(BODY).hexdigest() + '"',
                    "Content-MD5": base64.b64encode(hashlib.md5(BODY).digest()).decode("ascii"),
                    "x-ms-blob-type": "BlockBlob", "x-ms-meta-mtime": "2024-01-01T00:00:00Z"})
                if status == 206:
                    headers.update({"Content-Range": "bytes 0-25/26", "x-ms-blob-content-md5": headers["Content-MD5"]})
            wire = (f"HTTP/1.1 {status} " + {200: "OK", 206: "Partial Content", 403: "Forbidden"}[status] +
                    f"\r\nContent-Length: {size}\r\nConnection: close\r\n" +
                    "".join(f"{key}: {value}\r\n" for key, value in headers.items()) + "\r\n").encode("ascii") + body
            if len(wire) > 4096 or self.response_bytes + len(wire) > 524288:
                raise FixtureError("byte_limit")
            self._reply = (len(wire), len(body))
            return wire

    def commit(self, request, sent):
        with self.lock:
            if (self.errors or not self.source_preserved() or self._pending is not request or self._reply is None or
                    type(sent) is not int or sent != self._reply[0]):
                raise FixtureError("sequence_invalid")
            if len(self.events) >= 512:
                raise FixtureError("event_limit")
            _, kind, role, status = request
            self.events.append((kind, role, status, self._reply[1]))
            self.response_bytes += sent
            self.payload_bytes += self._reply[1]
            self._pending = self._reply = None

    def snapshot(self):
        with self.lock:
            return dict(case=self.case, requests=self.requests, payload_bytes=self.payload_bytes,
                response_bytes=self.response_bytes, source_preserved=self.source_preserved(), errors=list(self.errors),
                events=[dict(ordinal=i+1, kind=k, role=r, status=s, object_bytes=b)
                        for i, (k, r, s, b) in enumerate(self.events)])


class _Server(_http._Server):
    def __init__(self, state):
        self._dispatch_lock = threading.Lock()
        self._close_attempted = False
        super().__init__(state)
        self.deadline = state.deadline

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
        allowed = {"host", "user-agent", "accept", "accept-encoding", "connection", "content-length", "authorization",
                   "x-ms-date", "x-ms-version", "x-ms-client-request-id", "x-ms-range", "if-match"}
        if (set(headers) - allowed or headers.get("host") != f"127.0.0.1:{self.port}" or target != TARGET or
                headers.get("content-length", "0") != "0" or "authorization" not in headers or
                headers.get("accept-encoding", "identity") not in {"identity", "gzip"} or
                headers.get("connection", "close").lower() not in {"close", "keep-alive"}):
            raise FixtureError("headers_invalid")
        return method, target, headers

    def _accept(self):
        # Inherited admission/ownership order; Azure's 3-second deadline starts
        # here, before worker scheduling, rather than at the worker's first run.
        while not self.stopping.is_set():
            try:
                sock, address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if not self.stopping.is_set():
                    self.state._error("accept_failed")
                return
            with self.lock:
                self.accepted += 1
                if (self.stopping.is_set() or address[0] != "127.0.0.1" or
                        self.accepted > _http.MAX_CONNECTIONS or len(self.sockets) >= _http.MAX_ACTIVE):
                    self.state._error("admission_limit")
                    self._close_socket(sock)
                    if self.accepted >= _http.MAX_CONNECTIONS:
                        self._close_socket(self.listener)
                        return
                    continue
                self.sockets[sock] = min(self.deadline, time.monotonic() + 3)
                try:
                    thread = threading.Thread(target=self._worker, args=(sock,), name="app-http-request", daemon=True)
                    thread.start()
                except BaseException:
                    self.state._error("thread_start_failed")
                    self.sockets.pop(sock, None)
                    self._close_socket(sock)
                    if self.accepted >= _http.MAX_CONNECTIONS:
                        self._close_socket(self.listener)
                        return
                    continue
                self.workers.append(thread)
                if self.accepted >= _http.MAX_CONNECTIONS:
                    self._close_socket(self.listener)
                    return

    def _acquire_dispatch(self, sock):
        while True:
            self._live(sock)
            with self.lock:
                remaining = min(self.deadline, self.sockets[sock]) - time.monotonic()
            if remaining <= 0:
                raise FixtureError("request_timeout")
            if self._dispatch_lock.acquire(timeout=min(0.05, remaining)):
                return

    def _worker(self, sock):
        owned = False
        try:
            with self.lock:
                if sock not in self.sockets:
                    raise FixtureError("socket_unowned")
                self.sockets[sock] = min(self.sockets[sock], self.deadline, time.monotonic() + 3)
            sock.settimeout(3)
            self._live(sock)
            with sock.makefile("rb", buffering=0) as stream:
                fields = self._parse(stream)
                if select.select([sock], [], [], 0)[0] and sock.recv(1, socket.MSG_PEEK):
                    raise FixtureError("request_body_rejected")
                self._acquire_dispatch(sock)
                owned = True
                self._live(sock)
                request = self.state.begin(*fields)
                wire = self.state.response(request)
                self._live(sock)
                # Hold dispatch ownership, not the state lock, through send/commit.
                sock.sendall(wire)
                self._live(sock)
                self.state.commit(request, len(wire))
        except FixtureError as error:
            self.state._error(str(error))
        except (OSError, ValueError):
            self.state._error("connection_failed")
        except BaseException:
            self.state._error("worker_failed")
        finally:
            if owned:
                self._dispatch_lock.release()
            with self.lock:
                try:
                    self._close_socket(sock)
                except OSError:
                    self.state._error("cleanup_failed")
                else:
                    self.sockets.pop(sock, None)


@contextmanager
def serve_azureblob(state):
    if type(state) is not AppAzureBlobState or state._served:
        raise ValueError("input_invalid")
    state._served = True
    server = _Server(state)
    state._transport = server
    try:
        server.start()
        yield server
    finally:
        server.close()
