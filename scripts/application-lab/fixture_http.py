"""Bounded synthetic HTTP source for the separately supervised application lab."""
from __future__ import annotations

from contextlib import contextmanager
import html
import re
import select
import socket
import threading
import time
from types import MappingProxyType
from urllib.parse import quote, unquote

MODES = frozenset({"listing", "baseline", "mismatch", "missing", "denial", "cancellation"})
MISSING_MEMBER = "missing-synthetic.txt"
MODIFIED = "Thu, 02 Jan 2025 03:04:05 GMT"
MAX_LIFETIME = 180.0
REQUEST_SECONDS = 15.0
MAX_CONNECTIONS = 128
MAX_ACTIVE = 8
MAX_REQUESTS = 128
MAX_BODY_BYTES = 32 * 1024 * 1024
MAX_HEADER_BYTES = 16384
MAX_HEADER_LINES = 64
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,95}\Z")
HEADER = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
ERROR_CODES = frozenset({"input_invalid", "event_limit", "thread_start_failed", "accept_failed",
    "admission_limit", "lifetime_limit", "request_timeout", "socket_unowned", "unexpected_input",
    "client_aborted", "request_invalid", "headers_invalid", "method_rejected", "route_invalid",
    "byte_limit", "source_changed", "request_limit", "cancel_replayed", "request_body_rejected",
    "connection_failed", "worker_failed", "cleanup_failed"})


class FixtureError(RuntimeError):
    pass


def _member(value):
    return (type(value) is str and 0 < len(value) <= 256 and
            1 <= len(value.split("/")) <= 4 and
            all(NAME.fullmatch(part) and part not in {".", ".."} and
                not part.endswith((" ", ".")) for part in value.split("/")))


class AppHttpState:
    def __init__(self, files, mode, denied_member="README-synthetic.txt", cancel_member="large/cancel.bin"):
        if (type(files) is not dict or not 1 <= len(files) <= 32 or type(mode) is not str or mode not in MODES or
                any(not _member(k) or type(v) is not bytes or len(v) > 8 * 1024 * 1024
                    for k, v in files.items()) or sum(map(len, files.values())) > 16 * 1024 * 1024 or
                MISSING_MEMBER in files or not _member(denied_member) or not _member(cancel_member)):
            raise ValueError("input_invalid")
        if mode == "denial" and denied_member not in files:
            raise ValueError("input_invalid")
        if mode == "cancellation" and (cancel_member not in files or len(files[cancel_member]) < 2):
            raise ValueError("input_invalid")
        dirs = {""}
        for member in files:
            parts = member.split("/")
            dirs.update("/".join(parts[:i]) + "/" for i in range(1, len(parts)))
        if any(directory[:-1] in files for directory in dirs if directory):
            raise ValueError("input_invalid")
        self.files = MappingProxyType(dict(files))
        self.mode, self.denied_member, self.cancel_member = mode, denied_member, cancel_member
        self._original = (tuple(files.items()), mode, denied_member, cancel_member)
        self._dirs = frozenset(dirs)
        self.lock = threading.RLock()
        self.observation_started = threading.Event()
        self.cancel_started = threading.Event()
        self._observation_release = threading.Event()
        self._cancel_release = threading.Event()
        self._observation_claimed = False
        self._cancel_claimed = False
        self._served = False
        self._allocated_bytes = 0
        self._transport = None
        self.events, self.errors = [], []
        self.counters = {name: 0 for name in ("requests", "heads", "gets", "directory_reads",
            "content_reads", "missing", "denied", "rejected", "payload_bytes", "completed_payload_bytes")}
        self.cancel_disconnected = False

    def release_observation(self):
        self._observation_release.set()

    def release_cancel(self):
        """Teardown escape only: never sends the held remainder."""
        self._cancel_release.set()

    def source_preserved(self):
        return (tuple(self.files.items()), self.mode, self.denied_member, self.cancel_member) == self._original

    def _error(self, code):
        if code not in ERROR_CODES:
            code = "worker_failed"
        with self.lock:
            if code not in self.errors:
                self.errors.append(code)

    def _event(self, label, path=""):
        with self.lock:
            if len(self.events) >= MAX_REQUESTS * 3:
                self._error("event_limit")
                raise FixtureError("event_limit")
            self.events.append([label, path])

    def snapshot(self):
        with self.lock:
            result = dict(mode=self.mode, **self.counters,
                events=[list(event) for event in self.events], errors=list(self.errors),
                source_preserved=self.source_preserved(),
                observation_started=self.observation_started.is_set(),
                observation_released=self._observation_release.is_set(),
                cancel_started=self.cancel_started.is_set(), cancel_released=self._cancel_release.is_set(),
                cancel_disconnected=self.cancel_disconnected)
        result["transport"] = self._transport.transport_snapshot() if self._transport else None
        return result


class _Server:
    def __init__(self, state):
        self.state = state
        self.lock = threading.RLock()
        self.stopping = threading.Event()
        self.sockets, self.workers = {}, []
        self.accepted = 0
        self.cleanup_complete = False
        self.deadline = time.monotonic() + MAX_LIFETIME
        self.acceptor = self.watchdog = None
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.listener.bind(("127.0.0.1", 0))
            self.listener.listen(MAX_ACTIVE)
            self.listener.settimeout(0.1)
            self.port = self.listener.getsockname()[1]
            self.endpoint = f"http://127.0.0.1:{self.port}/"
        except BaseException:
            self.listener.close()
            raise

    @staticmethod
    def _close_socket(sock):
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()

    def start(self):
        try:
            self.watchdog = threading.Thread(target=self._watch, name="app-http-watch", daemon=True)
            self.acceptor = threading.Thread(target=self._accept, name="app-http-accept", daemon=True)
            self.watchdog.start()
            self.acceptor.start()
        except BaseException:
            self.state._error("thread_start_failed")
            self.close()
            raise

    def _accept(self):
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
                        self.accepted > MAX_CONNECTIONS or len(self.sockets) >= MAX_ACTIVE):
                    self.state._error("admission_limit")
                    self._close_socket(sock)
                    if self.accepted >= MAX_CONNECTIONS:
                        self._close_socket(self.listener)
                        return
                    continue
                self.sockets[sock] = min(self.deadline, time.monotonic() + REQUEST_SECONDS)
                try:
                    thread = threading.Thread(target=self._worker, args=(sock,), name="app-http-request", daemon=True)
                    thread.start()
                except BaseException:
                    self.state._error("thread_start_failed")
                    self.sockets.pop(sock, None)
                    self._close_socket(sock)
                    if self.accepted >= MAX_CONNECTIONS:
                        self._close_socket(self.listener)
                        return
                    continue
                self.workers.append(thread)
                if self.accepted >= MAX_CONNECTIONS:
                    self._close_socket(self.listener)
                    return

    def _watch(self):
        while not self.stopping.wait(0.05):
            now = time.monotonic()
            with self.lock:
                if now >= self.deadline:
                    self.state._error("lifetime_limit")
                    self.stopping.set()
                    self._close_socket(self.listener)
                expired = [sock for sock, deadline in self.sockets.items() if now >= deadline]
                for sock in expired:
                    self.state._error("request_timeout")
                    self._close_socket(sock)

    def _wait(self, sock, cancel=False):
        release = self.state._cancel_release if cancel else self.state._observation_release
        with self.lock:
            if sock not in self.sockets:
                raise FixtureError("socket_unowned")
            self.sockets[sock] = self.deadline
        while not release.is_set() and not self.stopping.is_set():
            if time.monotonic() >= self.deadline:
                raise FixtureError("lifetime_limit")
            ready, _, _ = select.select([sock], [], [], 0.05)
            if ready:
                try:
                    incoming = sock.recv(1, socket.MSG_PEEK)
                except ConnectionResetError:
                    incoming = b""
                if self.stopping.is_set():
                    return
                if incoming:
                    raise FixtureError("unexpected_input")
                if cancel:
                    with self.state.lock:
                        self.state.cancel_disconnected = True
                    self.state._event("cancel_disconnected", self.state.cancel_member)
                    return
                raise FixtureError("client_aborted")
        with self.lock:
            if sock in self.sockets:
                self.sockets[sock] = min(self.deadline, time.monotonic() + REQUEST_SECONDS)

    def _live(self, sock):
        with self.lock:
            if (self.stopping.is_set() or sock not in self.sockets or sock.fileno() < 0 or
                    time.monotonic() >= self.sockets[sock]):
                raise FixtureError("request_timeout")

    def _parse(self, stream):
        line = stream.readline(4097)
        if len(line) > 4096 or not re.fullmatch(rb"[A-Z]+ /[^\x00-\x20\x7f]* HTTP/1\.[01]\r\n", line):
            raise FixtureError("request_invalid")
        method, target, _ = line.decode("ascii").split(" ")
        headers, total = {}, len(line)
        for _ in range(MAX_HEADER_LINES):
            line = stream.readline(MAX_HEADER_BYTES + 1)
            total += len(line)
            if total > MAX_HEADER_BYTES or not line.endswith(b"\r\n"):
                raise FixtureError("headers_invalid")
            if line == b"\r\n":
                break
            name, colon, value = line[:-2].partition(b":")
            if not colon or not HEADER.fullmatch(name) or any(c < 32 or c > 126 for c in value):
                raise FixtureError("headers_invalid")
            name = name.decode("ascii").lower()
            if name in headers:
                raise FixtureError("headers_invalid")
            headers[name] = value.decode("ascii").strip(" ")
        else:
            raise FixtureError("headers_invalid")
        allowed = {"host", "user-agent", "accept", "accept-encoding", "connection", "content-length"}
        if (set(headers) - allowed or headers.get("host") != f"127.0.0.1:{self.port}" or
                headers.get("content-length", "0") != "0" or
                headers.get("connection", "close").lower() not in {"close", "keep-alive"} or
                headers.get("accept-encoding", "identity") not in {"identity", "gzip"}):
            raise FixtureError("headers_invalid")
        if method not in {"HEAD", "GET"}:
            raise FixtureError("method_rejected")
        try:
            path = unquote(target[1:], encoding="utf-8", errors="strict")
        except UnicodeError:
            raise FixtureError("route_invalid") from None
        if target != "/" + quote(path, safe="/"):
            raise FixtureError("route_invalid")
        if path not in self.state.files and path not in self.state._dirs and path != MISSING_MEMBER:
            raise FixtureError("route_invalid")
        return method, path

    def _reply(self, sock, status, body, method, content_type="application/octet-stream", path=""):
        self._live(sock)
        state = self.state
        payload = body if method == "GET" else b""
        with state.lock:
            if state._allocated_bytes + len(payload) > MAX_BODY_BYTES:
                raise FixtureError("byte_limit")
            state._allocated_bytes += len(payload)
        reason = {200: "OK", 400: "Bad Request", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed"}[status]
        header = (f"HTTP/1.1 {status} {reason}\r\nContent-Length: {len(body)}\r\n"
                  f"Content-Type: {content_type}\r\nLast-Modified: {MODIFIED}\r\n"
                  "Connection: close\r\n\r\n").encode("ascii")
        sock.sendall(header)
        cancellation = status == 200 and method == "GET" and state.mode == "cancellation" and path == state.cancel_member
        limit = min(65536, len(payload) - 1) if cancellation else len(payload)
        for offset in range(0, limit, 65536):
            part = payload[offset:min(limit, offset + 65536)]
            sock.sendall(part)
            with state.lock:
                state.counters["payload_bytes"] += len(part)
        if cancellation:
            state._event("cancel_prefix", path)
            state.cancel_started.set()
            self._wait(sock, cancel=True)
            return
        with state.lock:
            state.counters["completed_payload_bytes"] += len(payload)

    def _dispatch(self, sock, method, path):
        self._live(sock)
        state = self.state
        with state.lock:
            if not state.source_preserved():
                raise FixtureError("source_changed")
            state.counters["requests"] += 1
            state.counters["heads" if method == "HEAD" else "gets"] += 1
            if state.counters["requests"] > MAX_REQUESTS:
                raise FixtureError("request_limit")
            first = not state._observation_claimed
            state._observation_claimed = True
        if first:
            state._event("observation", path)
            state.observation_started.set()
        if not state._observation_release.is_set():
            self._wait(sock)
        if self.stopping.is_set():
            return
        self._live(sock)
        if path == MISSING_MEMBER:
            with state.lock:
                state.counters["missing"] += 1
            state._event("missing", path)
            return self._reply(sock, 404, b"synthetic missing\n", method)
        if state.mode == "denial" and path == state.denied_member:
            with state.lock:
                state.counters["denied"] += 1
            state._event("denied", path)
            return self._reply(sock, 403, b"synthetic denied\n", method)
        if path in state._dirs:
            children = {p[len(path):].split("/", 1)[0] + ("/" if "/" in p[len(path):] else "")
                        for p in state.files if p.startswith(path)}
            body = ("<!doctype html><html><body>\n" + "".join(
                '<a href="' + html.escape(quote(child, safe="/"), quote=True) + '">' +
                html.escape(child) + "</a>\n" for child in sorted(children)) + "</body></html>\n").encode("utf-8")
            with state.lock:
                state.counters["directory_reads"] += 1
            state._event("directory_head" if method == "HEAD" else "directory", path)
            return self._reply(sock, 200, body, method, "text/html; charset=utf-8")
        with state.lock:
            if state.mode == "cancellation" and path == state.cancel_member and method == "GET":
                if state._cancel_claimed:
                    raise FixtureError("cancel_replayed")
                state._cancel_claimed = True
            state.counters["content_reads"] += method == "GET"
        state._event("head" if method == "HEAD" else "content", path)
        self._reply(sock, 200, state.files[path], method, path=path)

    def _worker(self, sock):
        try:
            sock.settimeout(REQUEST_SECONDS)
            with sock.makefile("rb", buffering=0) as stream:
                method, path = self._parse(stream)
                if select.select([sock], [], [], 0)[0] and sock.recv(1, socket.MSG_PEEK):
                    raise FixtureError("request_body_rejected")
                self._dispatch(sock, method, path)
        except FixtureError as error:
            code = str(error)
            self.state._error(code)
            with self.state.lock:
                self.state.counters["rejected"] += 1
            try:
                if not self.stopping.is_set() and code not in {"lifetime_limit", "client_aborted", "socket_unowned"}:
                    self._reply(sock, 405 if code == "method_rejected" else 400, b"synthetic rejected\n", "GET")
            except (OSError, FixtureError):
                pass
        except (OSError, ValueError):
            if not self.stopping.is_set():
                self.state._error("connection_failed")
        except BaseException:
            self.state._error("worker_failed")
        finally:
            with self.lock:
                self.sockets.pop(sock, None)
                self._close_socket(sock)

    def transport_snapshot(self):
        with self.lock:
            return dict(accepted=self.accepted, active=len(self.sockets),
                workers_alive=sum(t.is_alive() for t in self.workers),
                watchdog_alive=bool(self.watchdog and self.watchdog.is_alive()),
                acceptor_alive=bool(self.acceptor and self.acceptor.is_alive()),
                cleanup_complete=self.cleanup_complete)

    def snapshot(self):
        return self.state.snapshot()

    def close(self):
        self.stopping.set()
        self.state.release_observation()
        self.state.release_cancel()
        with self.lock:
            self._close_socket(self.listener)
            for sock in list(self.sockets):
                self._close_socket(sock)
        deadline = time.monotonic() + 5
        for thread in [self.acceptor, self.watchdog, *self.workers]:
            if thread is not None and thread.ident is not None:
                thread.join(max(0, deadline - time.monotonic()))
        status = self.transport_snapshot()
        self.cleanup_complete = not any(status[k] for k in ("active", "workers_alive", "watchdog_alive", "acceptor_alive"))
        if not self.state.source_preserved():
            self.state._error("source_changed")
        if not self.cleanup_complete:
            self.state._error("cleanup_failed")
            raise FixtureError("cleanup_failed")


@contextmanager
def serve_http(state):
    if not isinstance(state, AppHttpState):
        raise ValueError("input_invalid")
    with state.lock:
        if state._served:
            raise ValueError("state_reused")
        state._served = True
    server = _Server(state)
    state._transport = server
    try:
        server.start()
        yield server
    finally:
        server.close()
