"""Independent Box saved OAuth-token read and non-mutating preflight fixture."""
from contextlib import contextmanager
import hashlib
import hmac
import json
import posixpath
import re
import time
import urllib.parse
from fixture_read_api import ReadState, ReadHandler
from fixture_servers import children
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits, BOX_API_NAME

STAMP = "2024-01-01T00:00:00Z"
FIELDS = "type,id,sequence_id,etag,sha1,name,size,created_at,modified_at,content_created_at,content_modified_at,item_status,shared_link,owned_by"

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result

class BoxState(ReadState):
    def __init__(self, token):
        if not token:
            raise ValueError("missing_box_token")
        super().__init__(token)
        self.ids = {name: str(1401 + i) for i, name in enumerate(sorted(self.files))}
        self.names = {identity: name for name, identity in self.ids.items()}
        self.observed = set()
        self.preflights = 0

    def metadata(self, name):
        directory = name == "nested"
        return {"type": "folder" if directory else "file", "id": "10" if directory else self.ids[name],
                "sequence_id": "0", "etag": "0", "sha1": "" if directory else hashlib.sha1(self.files[name]).hexdigest(),
                "name": posixpath.basename(name), "size": 0 if directory else len(self.files[name]),
                "created_at": STAMP, "modified_at": STAMP, "content_created_at": STAMP,
                "content_modified_at": STAMP, "item_status": "active", "shared_link": {},
                "owned_by": {"type": "user", "id": "synthetic-owner", "name": "Synthetic", "login": "synthetic@example.invalid"}}

    def folder(self, name):
        items = []
        for path in children(name, self.files):
            items.append(self.metadata(path))
            if path in self.files:
                self.observed.add(path)
        return items

class BoxHandler(ReadHandler):
    def wire(self):
        state = self.server.state
        state.requests += 1
        limited = state.requests > state.request_limit or time.monotonic() > state.deadline
        if limited:
            state.budget_exceeded = True
        # Validate and consume a bounded JSON body before sending a budget
        # rejection. Closing TLS with an unread OPTIONS body can discard the
        # response when the peer is still sending that body.
        headers = list(self.headers.items())
        names = [key.lower() for key, _ in headers]
        try:
            raw = self.raw_requestline.rstrip(b"\r\n").split(b" ")
            length = self.headers.get("Content-Length", "0")
            if (len(raw) != 3 or raw[1].decode("ascii") != self.path or len(self.path) > 2048
                    or not self.path.startswith("/") or any(ord(c) <= 32 or ord(c) >= 127 for c in self.path)
                    or self.headers.get_all("Host") != [BOX_API_NAME]
                    or len(names) != len(set(names))
                    or sum(len(k) + len(v) for k, v in headers) > 16384
                    or any("\r" in v or "\n" in v for _, v in headers)
                    or self.headers.get("Transfer-Encoding") is not None
                    or re.search(r"%(?![0-9a-fA-F]{2})", self.path)
                    or not re.fullmatch(r"0|[1-9][0-9]{0,3}", length) or int(length) > 4096
                    or self.command not in ("GET", "OPTIONS", "DELETE")
                    or self.command != "OPTIONS" and length != "0"
                    or self.command == "OPTIONS" and (length == "0" or self.headers.get("Content-Type") != "application/json")):
                raise ValueError("invalid_request")
            url = urllib.parse.urlsplit(self.path)
            if url.scheme or url.netloc or url.fragment or "%" in url.path or "//" in url.path or "\\" in url.path:
                raise ValueError("invalid_target")
            pairs = urllib.parse.parse_qsl(url.query, keep_blank_values=True, strict_parsing=True, max_num_fields=4, encoding="utf-8", errors="strict")
            query = dict(pairs)
            if len(query) != len(pairs):
                raise ValueError("duplicate_query")
            data = None
            if self.command == "OPTIONS":
                raw = self.rfile.read(int(length))
                if len(raw) != int(length):
                    raise ValueError("short_json")
                data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
                if type(data) is not dict:
                    raise ValueError("invalid_json")
            if limited:
                self.json_reply(429, {"error": {"message": "synthetic request limit"}})
                return None
            return url.path, query, data
        except OSError:
            # A timed-out/broken body is no longer an HTTP exchange we can
            # answer. The TLS transport records the deadline and owns cleanup.
            self.close_connection = True
            return None
        except (ValueError, UnicodeError):
            self.reject()
            return None


    def api_error(self, status, code, context=None):
        value = {"type": "error", "status": status, "code": code, "message": "synthetic Box fixture rejection"}
        if context is not None:
            value["context_info"] = context
        self.json_reply(status, value)

    def payload(self, name):
        if self.server.state.mode == "read_denied":
            self.server.state.read_denied += 1
            self.server.state.events.append(("read_denied", name))
            self.api_error(403, "access_denied_insufficient_permissions")
            return
        super().payload(name)

    def dispatch(self):
        with self.server.state.lock:
            request = self.wire()
            if request is None:
                return
            path, query, data = request
            state = self.server.state
            folder = re.fullmatch(r"/2.0/folders/(0|10)/items", path)
            file = re.fullmatch(r"/2.0/files/([0-9]+)", path)
            content = re.fullmatch(r"/2.0/files/([0-9]+)/content", path)
            preflight = path == "/2.0/files/content/" and self.command == "OPTIONS"
            if (not folder and not file and not content and not preflight
                    or self.command == "OPTIONS" and not preflight
                    or self.command == "DELETE" and not content
                    or self.headers.get("Range") is not None and (not content or self.command != "GET")
                    or self.headers.get("Cookie") is not None or self.headers.get("as-user") is not None):
                self.reject()
                return
            if not hmac.compare_digest(self.headers.get("Authorization", "").encode(),
                                       ("Bearer " + state.password).encode()):
                state.denied += 1
                state.events.append(("credentials_denied", ""))
                self.api_error(401, "unauthorized")
                return
            state.authenticated += 1
            if preflight:
                if (query or set(data) != {"name", "parent"} or type(data["name"]) is not str
                        or type(data["parent"]) is not dict or set(data["parent"]) != {"id"}
                        or type(data["parent"]["id"]) is not str or data["parent"]["id"] not in ("0", "10")):
                    self.reject()
                    return
                name = ("" if data["parent"]["id"] == "0" else "nested/") + data["name"]
                if name == "absent-synthetic.txt":
                    state.preflights += 1
                    state.missing += 1
                    state.events.append(("missing", name))
                    self.json_reply(200, {"upload_token": "synthetic-unused-upload-token",
                                          "upload_url": "https://" + BOX_API_NAME + "/unused-upload"})
                elif name in state.files:
                    state.preflights += 1
                    state.observed.add(name)
                    state.events.append(("preflight", name))
                    item = state.metadata(name)
                    mini = {key: item[key] for key in ("type", "id", "sequence_id", "etag", "sha1", "name")}
                    self.api_error(409, "item_name_in_use", {"conflicts": mini})
                else:
                    self.reject()
                return
            if folder:
                if query != {"fields": FIELDS, "limit": "1000", "usemarker": "true"}:
                    self.reject()
                    return
                name = "" if folder[1] == "0" else "nested"
                items = state.folder(name)
                state.events.append(("listing", name))
                self.json_reply(200, {"entries": items, "total_count": len(items), "limit": 1000, "offset": 0})
                return
            match = content or file
            name = state.names.get(match[1])
            if name is None or name not in state.observed:
                self.api_error(404, "not_found")
            elif content:
                if query:
                    self.reject()
                elif self.command == "DELETE":
                    self.write_denial(name)
                else:
                    self.payload(name)
            elif query != {"fields": FIELDS}:
                self.reject()
            else:
                state.events.append(("metadata", name))
                self.json_reply(200, state.metadata(name))

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch
    do_OPTIONS = dispatch


@contextmanager
def serve_box(root, state):
    certificates, transport = None, None
    try:
        certificates = FixtureCertificates.create(root, server_name=BOX_API_NAME)
        transport = BoundedHttpsServer(certificates, BoxHandler, state=state,
                                       limits=TlsLimits(connection_limit=128, active_limit=4,
                                                        request_seconds=3, lifetime_seconds=120))
        transport.start()
        yield certificates, transport
    finally:
        transport_ok = transport is None or transport.close()
        material_ok = certificates is None or certificates.close()
        state.cleanup_complete = transport_ok and material_ok
        if not state.cleanup_complete:
            raise RuntimeError("box_cleanup_failed")
