"""Unqualified independent ImageKit fixed-authority read experiment."""
from contextlib import contextmanager, ExitStack
import base64
import hashlib
import hmac
import json
import posixpath
import re
import socket
import time
import urllib.parse

from fixture_read_api import ReadState, ReadHandler
from fixture_servers import children, is_directory
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits

API = "api.imagekit.io"
CONTENT = "synthetic-content.imagekit.invalid"
ADDRESSES = {API: "127.0.0.1", CONTENT: "127.0.0.2"}
STAMP = "2024-01-01T00:00:00Z"
UPDATED = "2024-01-01 00:00:00 +0000 UTC"


class ImageKitState(ReadState):
    def __init__(self, secret):
        super().__init__(secret)
        self.ids = {name: "synthetic-file-" + str(i) for i, name in enumerate(sorted(self.files))}
        self.observed = set()
        self.signed_reads = 0

    def metadata(self, name):
        directory = is_directory(name, self.files)
        result = {
            "fileId": "synthetic-folder-" + (name or "root") if directory else self.ids[name],
            "name": posixpath.basename(name), "filePath": "/" + name,
            "type": "folder" if directory else "file",
            "size": 0 if directory else len(self.files[name]),
            "createdAt": STAMP, "updatedAt": STAMP,
            "isPrivateFile": not directory, "mime": "application/octet-stream",
        }
        if directory:
            result["folderPath"] = "/" + name
        else:
            result["url"] = "https://" + CONTENT + "/" + urllib.parse.quote(name, safe="/")
        return result


class ImageKitHandler(ReadHandler):
    def wire(self):
        state = self.server.state
        state.requests += 1
        if state.requests > state.request_limit or time.monotonic() > state.deadline:
            state.budget_exceeded = True
            self.json_reply(429, {"error": "budget"})
            return None
        headers = list(self.headers.items())
        names = [k.lower() for k, _ in headers]
        try:
            raw = self.raw_requestline.rstrip(b"\r\n").split(b" ")
            authority = self.server.transport._server_name
            if (len(raw) != 3 or raw[1].decode("ascii") != self.path or len(self.path) > 2048
                    or not self.path.startswith("/") or any(ord(c) <= 32 or ord(c) >= 127 for c in self.path)
                    or self.headers.get_all("Host") != [authority] or authority not in ADDRESSES
                    or len(names) != len(set(names)) or sum(len(k) + len(v) for k, v in headers) > 16384
                    or any("\r" in v or "\n" in v for _, v in headers)
                    or self.headers.get("Transfer-Encoding") is not None
                    or self.headers.get("Content-Length", "0") != "0"
                    or self.command not in ("GET", "DELETE")
                    or re.search(r"%(?![0-9a-fA-F]{2})", self.path)):
                raise ValueError()
            url = urllib.parse.urlsplit(self.path)
            if url.scheme or url.netloc or url.fragment or "//" in url.path or "\\" in url.path:
                raise ValueError()
            pairs = urllib.parse.parse_qsl(url.query, keep_blank_values=True, strict_parsing=True, max_num_fields=4)
            query = dict(pairs)
            if len(query) != len(pairs) or any(p in (".", "..") for p in url.path.split("/")):
                raise ValueError()
            decoded = urllib.parse.unquote(url.path, encoding="utf-8", errors="strict")
            if (urllib.parse.quote(decoded, safe="/") != url.path or "%" in decoded or "\\" in decoded
                    or any(ord(c) < 32 or ord(c) == 127 for c in decoded)
                    or any(p in (".", "..") for p in decoded.split("/"))):
                raise ValueError()
            return decoded, query
        except (ValueError, UnicodeError):
            self.reject()
            return None

    def reject(self, status=400):
        state=self.server.state
        if not hasattr(state,"reject_diagnostics"):state.reject_diagnostics=[]
        parsed=urllib.parse.urlsplit(self.path)
        state.reject_diagnostics.append({"method":self.command,"path":parsed.path,"query_names":sorted(urllib.parse.parse_qs(parsed.query)),"range":self.headers.get("Range"),"authority":self.headers.get("Host")})
        super().reject(status)

    def dispatch(self):
        with self.server.state.lock:
            request = self.wire()
            if request is None:
                return
            path, query = request
            state = self.server.state
            if any(self.headers.get(k) is not None for k in ("Cookie", "X-API-Key", "Proxy-Authorization")):
                self.reject()
                return
            if self.headers["Host"] == API:
                expected = "Basic " + base64.b64encode((state.password + ":").encode()).decode()
                if not hmac.compare_digest(self.headers.get("Authorization", ""), expected):
                    state.denied += 1
                    state.events.append(("key_denied", ""))
                    self.json_reply(403, {"error": "synthetic key rejected"})
                    return
                state.authenticated += 1
                if self.headers.get("Range") is not None:
                    self.reject()
                    return
                if self.command == "DELETE" and not query and path.startswith("/v2/files/"):
                    names = [n for n, identifier in state.ids.items() if path == "/v2/files/" + identifier]
                    if len(names) == 1:
                        self.write_denial(names[0])
                    else:
                        self.reject()
                    return
                if self.command != "GET" or path != "/v2/files" or set(query) != {"path", "skip", "limit", "searchQuery"}:
                    self.reject()
                    return
                match = re.fullmatch(r'type = "(file|folder)"(?: AND name = ("[^"\\]+"))?', query["searchQuery"])
                if not match or query["skip"] != "0" or query["limit"] != ("1" if match[2] else "100"):
                    self.reject()
                    return
                parent = query["path"].strip("/")
                if query["path"] not in ("/" + parent, "/" + parent + "/"):
                    self.reject()
                    return
                entries = children(parent, state.files) if is_directory(parent, state.files) else []
                requested_name = json.loads(match[2]) if match[2] else None
                entries = [n for n in entries if is_directory(n, state.files) == (match[1] == "folder")
                           and (requested_name is None or posixpath.basename(n) == requested_name)]
                if requested_name and not entries and match[1] == "file":
                    state.missing += 1
                    state.events.append(("missing", requested_name))
                if requested_name is None:
                    state.events.append(("listing", parent))
                state.observed.update(n for n in entries if n in state.files)
                self.json_reply(200, [state.metadata(n) for n in entries])
                return
            name = path[1:]
            if (self.command != "GET" or name not in state.files or self.headers.get("Authorization") is not None
                    or set(query) != {"tr", "updatedAt", "ik-t", "ik-s"}
                    or query["tr"] != "orig-true" or query["updatedAt"] != UPDATED
                    or not re.fullmatch(r"[0-9]{10}", query["ik-t"])
                    or abs(int(query["ik-t"]) - time.time()) > 5):
                self.reject()
                return
            unsigned = urllib.parse.quote(name, safe="/") + "?" + urllib.parse.urlencode(sorted({"tr": "orig-true", "updatedAt": UPDATED}.items()))
            signature = hmac.new(state.password.encode(), (unsigned + query["ik-t"]).encode(), hashlib.sha1).hexdigest()
            if not hmac.compare_digest(signature, query["ik-s"]):
                self.reject()
                return
            state.signed_reads += 1
            if state.mode == "read_denied":
                state.read_denied += 1
                state.events.append(("read_denied", name))
                self.reply(403, state.files[name], {"Content-Type": "application/octet-stream"}, object_payload=True)
            elif state.mode == "ignored_range":
                state.events.append(("ignored_range", name))
                self.reply(200, state.files[name], {"Content-Type": "application/octet-stream"}, object_payload=True)
            else:
                self.payload(name)

    do_GET = dispatch
    do_DELETE = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_HEAD = dispatch


def listeners_closed(transports):
    for transport in transports:
        with socket.socket() as probe:
            probe.settimeout(1)
            if probe.connect_ex((ADDRESSES[transport.authority], transport.port)) == 0:
                return False
    return True


@contextmanager
def serve_imagekit(root, state):
    certificates, transports = [], []
    try:
        with ExitStack() as stack:
            for authority in ADDRESSES:
                cert = stack.enter_context(FixtureCertificates.create(root, server_name=authority))
                certificates.append(cert)
                transport = BoundedHttpsServer(cert, ImageKitHandler, state=state,
                    limits=TlsLimits(connection_limit=128, active_limit=4, request_seconds=3, lifetime_seconds=120))
                transports.append(transport)
                stack.callback(transport.close)
                transport.start()
            yield certificates, transports
    finally:
        state.stopping.set()
        state.cleanup_complete = (all(t.cleanup_complete for t in transports)
                                  and all(c.cleanup_complete for c in certificates) and listeners_closed(transports))
        if not state.cleanup_complete:
            raise RuntimeError("imagekit_cleanup_failed")
