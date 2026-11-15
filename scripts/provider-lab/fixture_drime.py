"""Independent configured Drime token and read fixture."""
from contextlib import contextmanager
import hashlib
import hmac
import posixpath
import re
import time
import urllib.parse
from fixture_read_api import ReadState, ReadHandler
from fixture_servers import children
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits, DRIME_API_NAME

STAMP = "2024-01-01T00:00:00Z"

class DrimeState(ReadState):
    def __init__(self, token):
        if not token:
            raise ValueError("missing_drime_token")
        super().__init__(token)
        self.ids = {name: 801 + i for i, name in enumerate(sorted(self.files))}
        self.names = {str(value): key for key, value in self.ids.items()}
        self.links = set()

    def metadata(self, name):
        return {"id": self.ids[name], "parent_id": 10 if "/" in name else 1,
                "type": "file", "name": posixpath.basename(name), "file_name": posixpath.basename(name),
                "file_size": len(self.files[name]), "created_at": STAMP, "updated_at": STAMP,
                "mime": "application/octet-stream", "hash": hashlib.md5(self.files[name]).hexdigest(),
                "url": "content/" + str(self.ids[name])}

    def folder(self, name, directories_only=False):
        items = []
        for path in children(name, self.files):
            if path in self.files:
                if directories_only:
                    continue
                item = self.metadata(path)
                self.links.add(str(self.ids[path]))
            else:
                item = {"id": 10, "parent_id": 1, "type": "folder", "name": "nested",
                        "file_size": 0, "created_at": STAMP, "updated_at": STAMP}
            items.append(item)
        return items

class DrimeHandler(ReadHandler):
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
                    or self.headers.get_all("Host") != [DRIME_API_NAME]
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
            content = re.fullmatch(r"/content/(80[123])", path)
            listing = path == "/api/v1/drive/file-entries"
            if (not content and not listing or self.command == "DELETE" and not content
                    or self.headers.get("Range") is not None and (not content or self.command != "GET")):
                self.reject()
                return
            if not hmac.compare_digest(self.headers.get("Authorization", "").encode(), ("Bearer " + state.password).encode()):
                state.denied += 1
                state.events.append(("credentials_denied", ""))
                self.json_reply(401, {"message": "synthetic invalid token"})
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
            if (not {"folderId", "page", "perPage"} <= set(query)
                    or set(query) - {"folderId", "page", "perPage", "type"}
                    or query["folderId"] not in ("1", "10") or query["page"] != "1"
                    or query["perPage"] != "1000" or query.get("type", "folder") != "folder"):
                self.reject()
                return
            name = "" if query["folderId"] == "1" else "nested"
            only_folders = "type" in query
            items = state.folder(name, only_folders)
            state.events.append(("folder_lookup" if only_folders else "listing", name))
            self.json_reply(200, {"current_page": 1, "last_page": 1, "per_page": 1000, "data": items,
                                 "from": 1 if items else 0, "to": len(items), "total": len(items),
                                 "next_page_url": "", "prev_page_url": ""})

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch


@contextmanager
def serve_drime(root, state):
    certificates, transport = None, None
    try:
        certificates = FixtureCertificates.create(root, server_name=DRIME_API_NAME)
        transport = BoundedHttpsServer(certificates, DrimeHandler, state=state,
                                       limits=TlsLimits(connection_limit=128, active_limit=4,
                                                        request_seconds=3, lifetime_seconds=120))
        transport.start()
        yield certificates, transport
    finally:
        transport_ok = transport is None or transport.close()
        material_ok = certificates is None or certificates.close()
        state.cleanup_complete = transport_ok and material_ok
        if not state.cleanup_complete:
            raise RuntimeError("drime_cleanup_failed")
