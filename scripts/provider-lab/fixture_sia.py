"""Bounded legacy siad read fixture; no wallet, contracts or hosted storage.

Wire fields and errors follow rclone v1.75.2 backend/sia and backend/sia/api.
Only shared transport admission/deadline helpers are reused from Seafile.
"""
import base64
from contextlib import contextmanager
import hmac
from http.server import HTTPServer
import re
import socket
import threading
import time
import urllib.parse

from fixture_servers import State, SeafileFixture, SeafileHandler, children, is_directory

STAMP = "2024-01-01T00:00:00Z"
MISSING = "absent-synthetic.txt"
MEMBER = "README-synthetic.txt"


class SiaState(State):
    def __init__(self, password, mode="normal"):
        super().__init__("", password)
        if mode not in ("normal", "read_denied") or not password:
            raise ValueError("invalid_sia_fixture")
        self.mode = mode
        self.deadline = time.monotonic() + 180
        self.request_timeout, self.request_limit = 3, 128
        self.byte_limit, self.response_bytes = 128 * 1024, 0
        self.connection_limit, self.active_connection_limit = 128, 4
        self.accepted_connections = self.admission_denied = 0
        self.unexpected = self.rejected_payload_bytes = self.authenticated = 0
        self.missing = self.read_denied = 0
        self.budget_exceeded = False
        self.events = []


class SiaFixture(SeafileFixture):
    def __init__(self, state):
        self.state = state
        HTTPServer.__init__(self, ("127.0.0.1", 0), SiaHandler)


class SiaHandler(SeafileHandler):
    def error(self, status, message):
        self.json_reply(status, {"message": message})

    def reject(self, status=400):
        self.server.state.unexpected += 1
        self.error(status, "synthetic request rejected")

    def file_info(self, name):
        return {"siapath": name, "filesize": len(self.server.state.files[name]), "modtime": STAMP}

    def dispatch(self):
        with self.server.state.lock:
            state = self.server.state
            state.requests += 1
            if state.requests > state.request_limit or time.monotonic() > state.deadline:
                state.budget_exceeded = True
                self.error(429, "synthetic request limit")
                return
            headers = list(self.headers.items())
            names = [name.lower() for name, _ in headers]
            try:
                wire = self.raw_requestline.rstrip(b"\r\n").split(b" ")
                if (len(wire) != 3 or wire[1].decode("ascii") != self.path
                        or not self.path.startswith("/") or len(self.path) > 2048
                        or any(ord(c) <= 32 or ord(c) >= 127 for c in self.path)
                        or self.headers.get_all("Host") != [f"127.0.0.1:{self.server.server_address[1]}"]
                        or len(names) != len(set(names))
                        or sum(len(k) + len(v) for k, v in headers) > 16384
                        or any("\r" in v or "\n" in v for _, v in headers)
                        or self.headers.get("Transfer-Encoding") is not None
                        or self.headers.get("Content-Length", "0") != "0"
                        or self.headers.get("User-Agent") != "Sia-Agent"
                        or re.search(r"%(?![0-9a-fA-F]{2})", self.path)):
                    raise ValueError("invalid_request")
                url = urllib.parse.urlsplit(self.path)
                if url.query or url.fragment or url.scheme or url.netloc:
                    raise ValueError("invalid_target")
                decoded = urllib.parse.unquote(url.path, encoding="utf-8", errors="strict")
                match = re.fullmatch(r"/renter/(dir|file|stream|delete|uploadstream)/(.*)", decoded)
                if not match:
                    raise ValueError("invalid_route")
                route, name = match.groups()
                if route == "dir":
                    if not name.endswith("/") and name:
                        raise ValueError("directory_slash_required")
                    name = name.rstrip("/")
                if ("\\" in name or "%" in name or any(ord(c) < 32 or ord(c) == 127 for c in name)
                        or name and any(part in ("", ".", "..") for part in name.split("/"))
                        or self.command != ("POST" if route in ("delete", "uploadstream") else "GET")
                        or self.headers.get("Range") is not None and route != "stream"):
                    raise ValueError("invalid_member_or_method")
            except (ValueError, UnicodeError):
                self.reject()
                return
            wanted = "Basic " + base64.b64encode((":" + state.password).encode()).decode()
            if not hmac.compare_digest(self.headers.get("Authorization", "").encode(), wanted.encode()):
                state.denied += 1
                state.events.append(("auth_denied", name))
                self.error(401, "synthetic credentials denied")
                return
            state.authenticated += 1
            if route in ("delete", "uploadstream"):
                state.rejected_mutations += 1
                state.events.append(("write_denied", name))
                self.error(405, "synthetic fixture is read-only")
                return
            if route == "dir":
                if not is_directory(name, state.files):
                    state.missing += 1
                    state.events.append(("directory_missing", name))
                    self.error(500, "failed to get directory contents: path does not exist")
                    return
                paths = children(name, state.files)
                directories = [name] + [p for p in paths if is_directory(p, state.files)]
                state.events.append(("listing", name))
                self.json_reply(200, {
                    "directories": [{"siapath": p, "mostrecentmodtime": STAMP} for p in directories],
                    "files": [self.file_info(p) for p in paths if p in state.files],
                })
                return
            if name not in state.files:
                state.missing += 1
                state.events.append(("file_missing", name))
                self.error(400, "no file known with that path")
                return
            if route == "file":
                state.events.append(("metadata", name))
                self.json_reply(200, {"file": self.file_info(name)})
                return
            if state.mode == "read_denied":
                state.read_denied += 1
                state.events.append(("read_denied", name))
                self.error(403, "synthetic content denied")
                return
            payload, status, response_headers = state.files[name], 200, {"Content-Type": "application/octet-stream"}
            requested = self.headers.get("Range")
            if requested is not None:
                match = re.fullmatch(r"bytes=([0-9]{1,19})-([0-9]{0,19})", requested)
                if not match:
                    self.reject(416)
                    return
                start = int(match[1])
                end = int(match[2]) if match[2] else len(payload) - 1
                if start >= len(payload) or start > end:
                    self.reject(416)
                    return
                end = min(end, len(payload) - 1)
                response_headers["Content-Range"] = f"bytes {start}-{end}/{len(payload)}"
                payload, status = payload[start:end + 1], 206
            state.events.append(("content", name))
            self.reply(status, payload, response_headers, object_payload=True)

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch


@contextmanager
def serve_sia(state):
    server = SiaFixture(state)
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
            raise RuntimeError("sia_fixture_cleanup_failed")
        state.cleanup_complete = True
