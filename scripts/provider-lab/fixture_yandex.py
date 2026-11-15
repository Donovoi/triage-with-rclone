"""Independent Yandex saved OAuth-token metadata and issued-link read fixture."""
from contextlib import contextmanager
import hashlib
import hmac
import posixpath
import re
import time
import urllib.parse
import uuid
from fixture_read_api import ReadState, ReadHandler
from fixture_servers import children
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits, YANDEX_API_NAME

STAMP = "2024-01-01T00:00:00Z"
API = "/v1/disk"

class YandexState(ReadState):
    def __init__(self, token):
        if not token:
            raise ValueError("missing_yandex_token")
        super().__init__(token)
        self.observed, self.links = set(), {}

    def metadata(self, name):
        if name in self.files:
            return {"name": posixpath.basename(name), "path": "disk:/" + name, "type": "file",
                    "size": len(self.files[name]), "md5": hashlib.md5(self.files[name]).hexdigest(),
                    "created": STAMP, "modified": STAMP, "mime_type": "application/octet-stream"}
        if name not in ("", "nested"):
            raise ValueError("unknown_yandex_directory")
        return {"name": posixpath.basename(name), "path": "disk:/" + name, "type": "dir",
                "size": 0, "created": STAMP, "modified": STAMP}

    def folder(self, name):
        items = []
        for path in children(name, self.files):
            items.append(self.metadata(path))
            if path in self.files:
                self.observed.add(path)
        return items

class YandexHandler(ReadHandler):
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
                    or self.headers.get_all("Host") != [YANDEX_API_NAME]
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

    def api_error(self, status, reason):
        self.json_reply(status, {"error": reason, "message": "synthetic Yandex fixture rejection",
                                 "description": "synthetic request rejected"})

    def dispatch(self):
        with self.server.state.lock:
            request = self.wire()
            if request is None:
                return
            path, query = request
            state = self.server.state
            content = re.fullmatch(r"/content/([a-f0-9]{32})", path)
            metadata = path == API + "/resources"
            download = path == API + "/resources/download"
            if (not content and not metadata and not download
                    or self.command == "DELETE" and not content
                    or self.headers.get("Range") is not None and (not content or self.command != "GET")
                    or self.headers.get("Cookie") is not None):
                self.reject()
                return
            if not hmac.compare_digest(self.headers.get("Authorization", "").encode(),
                                       ("OAuth " + state.password).encode()):
                state.denied += 1
                state.events.append(("credentials_denied", ""))
                self.api_error(401, "UnauthorizedError")
                return
            state.authenticated += 1
            if content:
                if query:
                    self.reject()
                elif content[1] not in state.links:
                    self.api_error(401, "UnauthorizedError")
                elif self.command == "DELETE":
                    self.write_denial(state.links[content[1]])
                else:
                    self.payload(state.links[content[1]])
                return
            remote = query.get("path", "")
            allowed = {"path", "limit"} if metadata else {"path"}
            if (set(query) - allowed or "path" not in query
                    or "limit" in query and query["limit"] != "1000"
                    or not remote.startswith("disk:/")):
                self.reject()
                return
            if remote in ("disk:/", "disk:/nested", "disk:/nested/"):
                name = "nested" if "nested" in remote else ""
                if download:
                    self.reject()
                    return
                info = state.metadata(name)
                if "limit" in query:
                    items = state.folder(name)
                    info["_embedded"] = {"items": items, "path": remote, "limit": 1000, "offset": 0, "total": len(items)}
                    state.events.append(("listing", name))
                else:
                    state.events.append(("directory_metadata", name))
                self.json_reply(200, info)
                return
            name = remote.removeprefix("disk:/")
            # NewFs probes a candidate file as disk:/name/ before returning ErrorIsFile.
            if metadata and "limit" not in query and name.endswith("/") and name[:-1] in state.files:
                name = name[:-1]
            if name in ("absent-synthetic.txt", "absent-synthetic.txt/"):
                state.missing += 1
                state.events.append(("missing", "absent-synthetic.txt"))
                self.api_error(404, "DiskNotFoundError")
            elif "limit" in query:
                self.reject()
            elif name not in state.files:
                self.reject()
            elif download:
                if name not in state.observed:
                    self.reject()
                    return
                token = uuid.uuid4().hex
                state.links[token] = name
                state.events.append(("download_link", name))
                self.json_reply(200, {"href": "https://" + YANDEX_API_NAME + "/content/" + token,
                                     "method": "GET", "templated": False})
            else:
                state.observed.add(name)
                state.events.append(("metadata", name))
                self.json_reply(200, state.metadata(name))

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch


@contextmanager
def serve_yandex(root, state):
    certificates, transport = None, None
    try:
        certificates = FixtureCertificates.create(root, server_name=YANDEX_API_NAME)
        transport = BoundedHttpsServer(certificates, YandexHandler, state=state,
                                       limits=TlsLimits(connection_limit=128, active_limit=4,
                                                        request_seconds=3, lifetime_seconds=120))
        transport.start()
        yield certificates, transport
    finally:
        transport_ok = transport is None or transport.close()
        material_ok = certificates is None or certificates.close()
        state.cleanup_complete = transport_ok and material_ok
        if not state.cleanup_complete:
            raise RuntimeError("yandex_cleanup_failed")
