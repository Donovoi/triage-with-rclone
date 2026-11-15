"""Independent dosya.dev API-key inventory and presigned read experiment."""
from contextlib import contextmanager
import hashlib
import hmac
import re
import time
import urllib.parse
import uuid
from fixture_read_api import ReadState, ReadHandler
from fixture_servers import children
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits, DOSYA_API_NAME

ORIGIN = "https://api.dosya.dev"
WORKSPACE = "synthetic-workspace"
STAMP = 1704067200
FOLDERS = {"": "root", "nested": "folder2800"}
FILES = {"README-synthetic.txt": "file2801", "nested/bytes.bin": "file2802", "nested/space name.txt": "file2803"}

class DosyaState(ReadState):
    def __init__(self, key):
        if not key:
            raise ValueError("missing_dosya_key")
        super().__init__(key)
        self.observed = set()
        self.issued = set()
        self.tokens = {name: uuid.uuid4().hex for name in self.files}
        self.content_authorizations = 0

    def metadata(self, name):
        return {"id": FILES[name], "name": name.rsplit("/", 1)[-1], "size_bytes": len(self.files[name]),
                "mime_type": "application/octet-stream", "extension": name.rsplit(".", 1)[-1],
                "region": "synthetic", "created_at": STAMP, "updated_at": STAMP,
                "folder_id": FOLDERS["nested"] if "/" in name else None,
                "is_synced": 1, "content_hash": hashlib.sha256(self.files[name]).hexdigest()}

    def listing(self, directory):
        files, folders = [], []
        for name in children(directory, self.files):
            if name in self.files:
                files.append(self.metadata(name))
                self.observed.add(name)
            else:
                folders.append({"id": FOLDERS[name], "name": "nested", "parent_id": None,
                                "created_at": STAMP, "file_count": 2, "is_synced": 1})
        self.events.append(("listing", directory))
        return {"ok": True, "files": files, "folders": folders,
                "pagination": {"page": 1, "per_page": 500, "total_files": len(files), "total_pages": 1}}

class DosyaHandler(ReadHandler):
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
                    or self.headers.get_all("Host") != [DOSYA_API_NAME]
                    or self.server.transport._server_name not in (None, DOSYA_API_NAME)
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
            pairs = urllib.parse.parse_qsl(url.query, keep_blank_values=True, strict_parsing=True, max_num_fields=6, encoding="utf-8", errors="strict")
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
            self.reply(403, state.files[name], {"Content-Type": "application/octet-stream"})
            return
        super().payload(name)

    def dispatch(self):
        with self.server.state.lock:
            request = self.wire()
            if request is None:
                return
            path, query = request
            state = self.server.state
            content = re.fullmatch(r"/synthetic-content/(file280[1-3])", path)
            download = re.fullmatch(r"/api/files/(file280[1-3])/download", path)
            listing = path == "/api/files"
            if (not content and not download and not listing
                    or self.command == "DELETE" and not content
                    or self.headers.get("Range") is not None and (not content or self.command != "GET")
                    or self.headers.get("Cookie") is not None):
                self.reject()
                return
            if content:
                name = next(name for name, ident in FILES.items() if ident == content[1])
                if self.headers.get("Authorization") is not None:
                    state.content_authorizations += 1
                    self.reject()
                elif (self.headers.get("X-Dosya-Workspace") is not None or name not in state.issued
                      or query != {"signature": state.tokens[name]}):
                    self.reject()
                elif self.command == "DELETE":
                    self.write_denial(name)
                else:
                    self.payload(name)
                return
            if not hmac.compare_digest(self.headers.get("Authorization", "").encode(),
                                       ("Bearer " + state.password).encode()):
                state.denied += 1
                state.events.append(("credentials_denied", ""))
                self.json_reply(401, {"ok": False, "error": "synthetic invalid API key"})
                return
            state.authenticated += 1
            if download:
                name = next(name for name, ident in FILES.items() if ident == download[1])
                if query or name not in state.observed or self.headers.get("X-Dosya-Workspace") != WORKSPACE:
                    self.reject()
                else:
                    state.issued.add(name)
                    state.events.append(("download_link", name))
                    location = ORIGIN + "/synthetic-content/" + FILES[name] + "?signature=" + state.tokens[name]
                    self.reply(302, b"", {"Location": location})
                return
            expected = {"workspace_id": WORKSPACE, "per_page": "500", "page": "1", "sort": "name", "dir": "asc"}
            directory = ""
            if "folder_id" in query:
                directory = "nested"
                expected["folder_id"] = FOLDERS[directory]
            if query != expected or self.headers.get("X-Dosya-Workspace") is not None:
                self.reject()
            else:
                self.json_reply(200, state.listing(directory))

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch

@contextmanager
def serve_dosya(root, state):
    certificates, transport = None, None
    try:
        certificates = FixtureCertificates.create(root, server_name=DOSYA_API_NAME)
        transport = BoundedHttpsServer(certificates, DosyaHandler, state=state,
                                       limits=TlsLimits(connection_limit=128, active_limit=4,
                                                        request_seconds=3, lifetime_seconds=120))
        transport.start()
        yield certificates, transport
    finally:
        transport_ok = transport is None or transport.close()
        material_ok = certificates is None or certificates.close()
        state.cleanup_complete = transport_ok and material_ok
        if not state.cleanup_complete:
            raise RuntimeError("dosya_cleanup_failed")
