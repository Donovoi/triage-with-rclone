"""Finite read-API transport shared by the HiDrive and DOI fixtures.

Only admission, timers and response bounds come from the older Seafile transport;
provider handlers own all routes, query fields, credentials and wire schemas.
"""
from contextlib import contextmanager
from http.server import HTTPServer
import re
import socket
import threading
import time
import urllib.parse

from fixture_servers import State, SeafileFixture, SeafileHandler


class ReadState(State):
    def __init__(self, password=""):
        super().__init__("", password)
        self.deadline = time.monotonic() + 180
        self.request_timeout, self.request_limit = 3, 128
        self.byte_limit, self.response_bytes = 128 * 1024, 0
        self.connection_limit, self.active_connection_limit = 128, 4
        self.accepted_connections = self.admission_denied = 0
        self.unexpected = self.rejected_payload_bytes = self.authenticated = 0
        self.read_denied = self.missing = 0
        self.budget_exceeded = False
        self.events = []


class ReadFixture(SeafileFixture):
    def __init__(self, state, handler):
        self.state = state
        HTTPServer.__init__(self, ("127.0.0.1", 0), handler)


class ReadHandler(SeafileHandler):
    def wire(self):
        state = self.server.state
        state.requests += 1
        if state.requests > state.request_limit or time.monotonic() > state.deadline:
            state.budget_exceeded = True
            self.json_reply(429, {"error": "synthetic request limit"})
            return None
        headers = list(self.headers.items())
        names = [k.lower() for k, _ in headers]
        try:
            raw = self.raw_requestline.rstrip(b"\r\n").split(b" ")
            if (len(raw) != 3 or raw[1].decode("ascii") != self.path
                    or not self.path.startswith("/") or len(self.path) > 2048
                    or any(ord(c) <= 32 or ord(c) >= 127 for c in self.path)
                    or self.headers.get_all("Host") != [f"127.0.0.1:{self.server.server_address[1]}"]
                    or len(names) != len(set(names))
                    or sum(len(k) + len(v) for k, v in headers) > 16384
                    or any("\r" in v or "\n" in v for _, v in headers)
                    or self.headers.get("Transfer-Encoding") is not None
                    or self.headers.get("Content-Length", "0") != "0"
                    or re.search(r"%(?![0-9a-fA-F]{2})", self.path)):
                raise ValueError("invalid_request")
            url = urllib.parse.urlsplit(self.path)
            if url.scheme or url.netloc or url.fragment or "//" in url.path:
                raise ValueError("invalid_target")
            pairs = urllib.parse.parse_qsl(url.query, keep_blank_values=True, strict_parsing=True,
                                          max_num_fields=8, encoding="utf-8", errors="strict")
            query = dict(pairs)
            if len(query) != len(pairs):
                raise ValueError("duplicate_query")
            path = urllib.parse.unquote(url.path, encoding="utf-8", errors="strict")
            if ("%" in path or "\\" in path or any(ord(c) < 32 or ord(c) == 127 for c in path)
                    or any(part in (".", "..") for part in path.split("/"))):
                raise ValueError("invalid_path")
            return path, query
        except (UnicodeError, ValueError):
            self.reject()
            return None

    def payload(self, name):
        state = self.server.state
        if state.mode == "read_denied":
            state.read_denied += 1
            state.events.append(("read_denied", name))
            self.json_reply(403, {"error": "synthetic content denied"})
            return
        body, status = state.files[name], 200
        headers = {"Content-Type": "application/octet-stream"}
        requested = self.headers.get("Range")
        if requested is not None:
            match = re.fullmatch(r"bytes=([0-9]{1,19})-([0-9]{0,19})", requested)
            if not match:
                self.reject(416)
                return
            start = int(match[1])
            end = int(match[2]) if match[2] else len(body) - 1
            if start >= len(body) or start > end:
                self.reject(416)
                return
            end = min(end, len(body) - 1)
            headers["Content-Range"] = f"bytes {start}-{end}/{len(body)}"
            body, status = body[start:end + 1], 206
        state.events.append(("content", name))
        self.reply(status, body, headers, object_payload=True)

    def write_denial(self, name):
        state = self.server.state
        state.rejected_mutations += 1
        state.events.append(("write_denied", name))
        self.json_reply(405, {"error": "synthetic fixture is read-only"})


@contextmanager
def serve_read_api(state, handler):
    server = ReadFixture(state, handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        state.stopping.set()
        server.shutdown()
        with state.lock:
            for conn in list(state.sockets):
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                conn.close()
        server.server_close()
        thread.join(5)
        if thread.is_alive():
            raise RuntimeError("read_api_cleanup_failed")
        state.cleanup_complete = True
