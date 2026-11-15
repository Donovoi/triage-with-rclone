"""Independent Premiumize saved OAuth-token read fixture."""
from contextlib import contextmanager
import hmac
import posixpath
import re
import time
import urllib.parse
from fixture_read_api import ReadState, ReadHandler
from fixture_servers import children
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits, PREMIUMIZEME_API_NAME

STAMP = 1704067200

class PremiumizemeState(ReadState):
    def __init__(self, token):
        if not token:
            raise ValueError("missing_premiumizeme_token")
        super().__init__(token)
        self.ids = {name: "file" + str(1001 + i) for i, name in enumerate(sorted(self.files))}
        self.names = {value: key for key, value in self.ids.items()}
        self.links = set()

    def metadata(self, name):
        return {"id": self.ids[name], "type": "file", "name": posixpath.basename(name),
                "size": len(self.files[name]), "created_at": STAMP,
                "mime_type": "application/octet-stream",
                "link": "https://" + PREMIUMIZEME_API_NAME + "/content/" + self.ids[name]}

    def folder(self, name):
        items = []
        for path in children(name, self.files):
            if path in self.files:
                item = self.metadata(path)
                self.links.add(self.ids[path])
            else:
                item = {"id": "folder10", "type": "folder", "name": "nested", "created_at": STAMP}
            items.append(item)
        return items

class PremiumizemeHandler(ReadHandler):
    def wire(self):
        state = self.server.state
        state.requests += 1
        if state.requests > state.request_limit or time.monotonic() > state.deadline:
            state.budget_exceeded = True
            self.json_reply(429, {"error": {"message": "synthetic request limit"}})
            return None
        headers = list(self.headers.items())
        names = [key.lower() for key, _ in headers]
        try:
            raw = self.raw_requestline.rstrip(b"\r\n").split(b" ")
            length = self.headers.get("Content-Length", "0")
            if (len(raw) != 3 or raw[1].decode("ascii") != self.path or len(self.path) > 2048
                    or not self.path.startswith("/") or any(ord(c) <= 32 or ord(c) >= 127 for c in self.path)
                    or self.headers.get_all("Host") != [PREMIUMIZEME_API_NAME]
                    or len(names) != len(set(names))
                    or sum(len(k) + len(v) for k, v in headers) > 16384
                    or any("\r" in v or "\n" in v for _, v in headers)
                    or self.headers.get("Transfer-Encoding") is not None
                    or re.search(r"%(?![0-9a-fA-F]{2})", self.path)
                    or not re.fullmatch(r"0|[1-9][0-9]{0,3}", length) or int(length) > 4096
                    or self.command not in ("GET", "DELETE")
                    or length != "0"):
                raise ValueError("invalid_request")
            url = urllib.parse.urlsplit(self.path)
            if url.scheme or url.netloc or url.fragment or "%" in url.path or "//" in url.path or "\\" in url.path:
                raise ValueError("invalid_target")
            pairs = urllib.parse.parse_qsl(url.query, keep_blank_values=True, strict_parsing=True, max_num_fields=4, encoding="utf-8", errors="strict")
            query = dict(pairs)
            if len(query) != len(pairs):
                raise ValueError("duplicate_query")
            return url.path, query
        except OSError:
            # A timed-out/broken body is no longer an HTTP exchange we can
            # answer. The TLS transport records the deadline and owns cleanup.
            self.close_connection = True
            return None
        except (ValueError, UnicodeError):
            self.reject()
            return None


    def payload(self, name):
        state = self.server.state
        if state.mode == "read_denied":
            state.read_denied += 1
            state.events.append(("read_denied", name))
            self.json_reply(403, {"message": "synthetic read denied"})
            return
        super().payload(name)

    def dispatch(self):
        with self.server.state.lock:
            request = self.wire()
            if request is None:
                return
            path, query = request
            state = self.server.state
            content = re.fullmatch(r"/content/(file100[123])", path)
            listing = path == "/api/folder/list"
            if (not content and not listing or self.command == "DELETE" and not content
                    or self.headers.get("Range") is not None and (not content or self.command != "GET")):
                self.reject()
                return
            if not hmac.compare_digest(self.headers.get("Authorization", "").encode(), ("Bearer " + state.password).encode()):
                state.denied += 1
                state.events.append(("credentials_denied", ""))
                self.json_reply(401, {"status": "error", "message": "synthetic invalid token"})
                return
            state.authenticated += 1
            if content:
                if query or content[1] not in state.links:
                    self.reject()
                    return
                if self.command == "DELETE":
                    self.write_denial(state.names[content[1]])
                else:
                    self.payload(state.names[content[1]])
                return
            if (set(query) not in ({"includebreadcrumbs"}, {"includebreadcrumbs", "id"})
                    or query.get("includebreadcrumbs") != "false" or query.get("id", "folder10") != "folder10"):
                self.reject()
                return
            name = "nested" if "id" in query else ""
            items = state.folder(name)
            state.events.append(("listing", name))
            self.json_reply(200, {"status": "success", "content": items,
                                 "folder_id": "folder10" if name else "0", "name": name or "synthetic",
                                 "parent_id": "0"})

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch


@contextmanager
def serve_premiumizeme(root, state):
    certificates, transport = None, None
    try:
        certificates = FixtureCertificates.create(root, server_name=PREMIUMIZEME_API_NAME)
        transport = BoundedHttpsServer(certificates, PremiumizemeHandler, state=state,
                                       limits=TlsLimits(connection_limit=128, active_limit=4,
                                                        request_seconds=3, lifetime_seconds=120))
        transport.start()
        yield certificates, transport
    finally:
        transport_ok = transport is None or transport.close()
        material_ok = certificates is None or certificates.close()
        state.cleanup_complete = transport_ok and material_ok
        if not state.cleanup_complete:
            raise RuntimeError("premiumizeme_cleanup_failed")
