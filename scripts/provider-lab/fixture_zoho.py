"""Independent Zoho saved-token scoped folder reads on two exact authorities."""
from contextlib import contextmanager, ExitStack
import hmac
import re
import socket
import time
import urllib.parse
from fixture_read_api import ReadState, ReadHandler
from fixture_servers import children
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits, ZOHO_API_NAME, ZOHO_CONTENT_NAME

ROOT = "synthetic-root"
ADDRESSES = {ZOHO_API_NAME: "127.0.0.1", ZOHO_CONTENT_NAME: "127.0.0.2"}
FOLDERS = {"": ROOT, "nested": "synthetic-nested"}
FILES = {"README-synthetic.txt": "file2301", "nested/bytes.bin": "file2302", "nested/space name.txt": "file2303"}

class ZohoState(ReadState):
    def __init__(self, token):
        if not token:
            raise ValueError("missing_zoho_token")
        super().__init__(token)
        self.observed = set()

    def metadata(self, name):
        folder = name in FOLDERS
        contents = [data for path,data in self.files.items() if path.startswith(name + "/")] if folder and name else list(self.files.values()) if folder else []
        return {"id": FOLDERS[name] if folder else FILES[name], "attributes": {
                "name": name.rsplit("/", 1)[-1] if name else "synthetic-root",
                "type": "folder" if folder else "file", "is_folder": folder,
                "created_time_in_millisecond": 1704067200000, "modified_time_in_millisecond": 1704067200000,
                "uploaded_time_in_millisecond": 1704067200000,
                "storage_info": {"size_in_bytes": sum(map(len, contents)) if folder else len(self.files[name]),
                                 "files_count": len(contents) if folder else 0,
                                 "folders_count": 1 if name == "" else 0}}}

    def listing(self, directory):
        names = children(directory, self.files)
        self.observed.update(name for name in names if name in self.files)
        self.events.append(("listing", directory))
        return {"data": [self.metadata(name) for name in names], "links": {"cursor": {"has_next": False, "next": ""}}}

class ZohoHandler(ReadHandler):
    def wire(self):
        state = self.server.state
        state.requests += 1
        if state.requests > state.request_limit or time.monotonic() > state.deadline:
            state.budget_exceeded = True
            self.json_reply(429, {"errors": [{"id": "synthetic", "title": "synthetic request limit"}]})
            return None
        headers = list(self.headers.items())
        names = [key.lower() for key, _ in headers]
        try:
            raw = self.raw_requestline.rstrip(b"\r\n").split(b" ")
            if (len(raw) != 3 or raw[1].decode("ascii") != self.path or len(self.path) > 2048
                    or not self.path.startswith("/") or any(ord(c) <= 32 or ord(c) >= 127 for c in self.path)
                    or len(names) != len(set(names)) or sum(len(k) + len(v) for k,v in headers) > 16384
                    or any("\r" in v or "\n" in v for _,v in headers)
                    or self.headers.get("Transfer-Encoding") is not None
                    or self.headers.get("Content-Length", "0") != "0"
                    or re.search(r"%(?![0-9a-fA-F]{2})", self.path)
                    or self.command not in ("GET", "DELETE")):
                raise ValueError("invalid_request")
            url = urllib.parse.urlsplit(self.path)
            if url.scheme or url.netloc or url.fragment or "//" in url.path:
                raise ValueError("invalid_target")
            pairs = urllib.parse.parse_qsl(url.query, keep_blank_values=True, strict_parsing=True,
                                          max_num_fields=3, encoding="utf-8", errors="strict")
            query = dict(pairs)
            if len(query) != len(pairs):
                raise ValueError("duplicate_query")
            path = urllib.parse.unquote(url.path, encoding="utf-8", errors="strict")
            if urllib.parse.quote(path, safe="/") != url.path:
                raise ValueError("noncanonical_path")
            authority = ZOHO_API_NAME if path.startswith("/api/v1/") else ZOHO_CONTENT_NAME if path.startswith("/v1/workdrive/") else None
            # Ephemeral wire tests use an unnamed transport; native named transports
            # must match both the route authority and the exact Host.
            if (authority is None or self.headers.get_all("Host") != [authority]
                    or self.server.transport._server_name not in (None, authority)):
                raise ValueError("wrong_authority")
            return path, query, authority
        except (ValueError, UnicodeError):
            self.reject()
            return None

    def payload(self, name):
        state = self.server.state
        if state.mode == "read_denied":
            state.read_denied += 1
            state.events.append(("read_denied", name))
            # Same length as the advertised object: rejection must depend on
            # HTTP status, not an incidental transfer-size mismatch.
            body = b'{"error":"denied"}'.ljust(len(state.files[name]), b" ")
            self.reply(403, body, {"Content-Type": "application/json"})
            return
        super().payload(name)

    def dispatch(self):
        with self.server.state.lock:
            request = self.wire()
            if request is None:
                return
            path, query, authority = request
            state = self.server.state
            if (self.headers.get("Cookie") is not None or self.headers.get("Content-Type") is not None
                    or any(k.lower().startswith(("x-zoho-", "x-zohowd-", "x-workdrive-")) for k in self.headers)):
                self.reject()
                return
            if not hmac.compare_digest(self.headers.get("Authorization", "").encode(),
                                       ("Zoho-oauthtoken " + state.password).encode()):
                state.denied += 1
                state.events.append(("credentials_denied", ""))
                self.json_reply(401, {"errors": [{"id": "synthetic", "title": "INVALID_TOKEN"}]})
                return
            state.authenticated += 1
            if authority == ZOHO_API_NAME:
                match = re.fullmatch(r"/api/v1/files/(synthetic-root|synthetic-nested)/files", path)
                if (self.command != "GET" or match is None or query != {"page[limit]": "1000", "page[next]": "0"}
                        or self.headers.get("Accept") != "application/vnd.api+json" or self.headers.get("Range") is not None):
                    self.reject()
                    return
                directory = next(name for name, ident in FOLDERS.items() if ident == match[1])
                self.json_reply(200, state.listing(directory))
                return
            if query or self.headers.get("Accept") is not None:
                self.reject()
                return
            match = re.fullmatch(r"/v1/workdrive/download/(file230[1-3])", path)
            if match is None:
                self.reject()
                return
            name = next(name for name, ident in FILES.items() if ident == match[1])
            if name not in state.observed or self.command == "DELETE" and self.headers.get("Range") is not None:
                self.reject()
            elif self.command == "DELETE":
                self.write_denial(name)
            else:
                self.payload(name)

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch

def listeners_closed(transports):
    for transport in transports:
        with socket.socket() as probe:
            probe.settimeout(1)
            if probe.connect_ex((ADDRESSES[transport.authority], transport.port)) == 0:
                return False
    return True

@contextmanager
def serve_zoho(root, state):
    certificates, transports = [], []
    try:
        with ExitStack() as stack:
            for authority in (ZOHO_API_NAME, ZOHO_CONTENT_NAME):
                cert = stack.enter_context(FixtureCertificates.create(root, server_name=authority))
                certificates.append(cert)
                transport = BoundedHttpsServer(cert, ZohoHandler, state=state,
                            limits=TlsLimits(connection_limit=128, active_limit=4, request_seconds=3, lifetime_seconds=120))
                transports.append(transport)
                stack.callback(transport.close)
                transport.start()
            yield certificates, transports
    finally:
        state.cleanup_complete = (all(t.cleanup_complete for t in transports)
                                  and all(c.cleanup_complete for c in certificates)
                                  and listeners_closed(transports))
        if not state.cleanup_complete:
            raise RuntimeError("zoho_cleanup_failed")
