"""Independent Put.io OAuth API, cursor inventory and unsigned content fixture."""
from contextlib import contextmanager
import binascii
import hmac
import json
import posixpath
import re
import time
import urllib.parse
import uuid
from fixture_read_api import ReadState, ReadHandler
from fixture_servers import children
from fixture_quatrix import unique_object
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits, PUTIO_API_NAME

STAMP = "2024-01-01T00:00:00"

class PutioState(ReadState):
    def __init__(self, token):
        if not token:
            raise ValueError("missing_putio_token")
        super().__init__(token)
        self.ids = {name: 1101 + i for i, name in enumerate(sorted(self.files))}
        self.names = {str(value): key for key, value in self.ids.items()}
        self.listed, self.links, self.cursors = set(), {}, {}
        self.continuations = self.content_authorizations = 0

    def metadata(self, name):
        return {"id": self.ids[name], "parent_id": 10 if "/" in name else 0,
                "name": posixpath.basename(name), "size": len(self.files[name]),
                "content_type": "application/octet-stream",
                "created_at": STAMP, "updated_at": STAMP,
                "crc32": format(binascii.crc32(self.files[name]) & 0xffffffff, "08x")}

    def folder_metadata(self, name):
        return {"id": 10 if name else 0, "parent_id": 0,
                "name": "nested" if name else "synthetic", "size": 0,
                "content_type": "application/x-directory",
                "created_at": STAMP, "updated_at": STAMP}

    def inventory(self, name):
        return [self.metadata(path) if path in self.files else self.folder_metadata(path)
                for path in children(name, self.files)]

    def observe(self, items):
        for item in items:
            if item["content_type"] != "application/x-directory":
                self.listed.add(str(item["id"]))

class PutioHandler(ReadHandler):
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
                    or self.headers.get_all("Host") != [PUTIO_API_NAME]
                    or len(names) != len(set(names))
                    or sum(len(k) + len(v) for k, v in headers) > 16384
                    or any("\r" in v or "\n" in v for _, v in headers)
                    or self.headers.get("Transfer-Encoding") is not None
                    or re.search(r"%(?![0-9a-fA-F]{2})", self.path)
                    or not re.fullmatch(r"0|[1-9][0-9]{0,3}", length) or int(length) > 4096
                    or self.command not in ("GET", "POST", "DELETE")
                    or self.command != "POST" and length != "0"
                    or self.command == "POST" and (length == "0" or self.headers.get("Content-Type") != "application/json")):
                raise ValueError("invalid_request")
            url = urllib.parse.urlsplit(self.path)
            if url.scheme or url.netloc or url.fragment or "%" in url.path or "//" in url.path or "\\" in url.path:
                raise ValueError("invalid_target")
            pairs = urllib.parse.parse_qsl(url.query, keep_blank_values=True, strict_parsing=True, max_num_fields=2, encoding="utf-8", errors="strict")
            query = dict(pairs)
            if len(query) != len(pairs):
                raise ValueError("duplicate_query")
            data = None
            if self.command == "POST":
                raw = self.rfile.read(int(length))
                if len(raw) != int(length):
                    raise ValueError("short_json")
                data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
                if type(data) is not dict:
                    raise ValueError("invalid_json")
            return url.path, query, data
        except OSError:
            # A timed-out/broken body is no longer an HTTP exchange we can
            # answer. The TLS transport records the deadline and owns cleanup.
            self.close_connection = True
            return None
        except (ValueError, UnicodeError):
            self.reject()
            return None


    def api_error(self, status, message):
        self.json_reply(status, {"error_type": "SyntheticError", "error_message": message})

    def dispatch(self):
        with self.server.state.lock:
            request = self.wire()
            if request is None:
                return
            path, query, data = request
            state = self.server.state
            content = re.fullmatch(r"/content/([a-f0-9]{32})", path)
            child = re.fullmatch(r"/v2/files/(0|10)/child", path)
            link = re.fullmatch(r"/v2/files/(110[123])/url", path)
            listing = path == "/v2/files/list"
            continuation = path == "/v2/files/list/continue"
            if (not any((content, child, link, listing, continuation))
                    or continuation and self.command != "POST"
                    or not continuation and self.command != "GET" and not (content and self.command == "DELETE")
                    or self.headers.get("Range") is not None and (not content or self.command != "GET")):
                self.reject()
                return
            if content and self.command == "GET":
                if self.headers.get("Authorization") is not None:
                    state.content_authorizations += 1
                    self.reject()
                elif query or content[1] not in state.links:
                    self.api_error(401, "synthetic invalid content link")
                else:
                    self.payload(state.links[content[1]])
                return
            if not hmac.compare_digest(self.headers.get("Authorization", "").encode(), ("Bearer " + state.password).encode()):
                state.denied += 1
                state.events.append(("credentials_denied", ""))
                self.api_error(401, "synthetic invalid token")
                return
            state.authenticated += 1
            if content:
                if query or content[1] not in state.links:
                    self.reject()
                else:
                    self.write_denial(state.links[content[1]])
                return
            if listing:
                if set(query) != {"parent_id", "per_page"} or query["parent_id"] not in ("0", "10") or query["per_page"] != "1000":
                    self.reject()
                    return
                name = "" if query["parent_id"] == "0" else "nested"
                items = state.inventory(name)
                cursor = uuid.uuid4().hex
                state.cursors[cursor] = (name, items[1:])
                state.observe(items[:1])
                state.events.append(("listing", name))
                self.json_reply(200, {"files": items[:1], "parent": state.folder_metadata(name), "cursor": cursor})
                return
            if continuation:
                if query or set(data) != {"cursor"} or type(data["cursor"]) is not str or data["cursor"] not in state.cursors:
                    self.reject()
                    return
                name, items = state.cursors.pop(data["cursor"])
                state.observe(items)
                state.continuations += 1
                state.events.append(("continuation", name))
                self.json_reply(200, {"files": items, "cursor": ""})
                return
            if child:
                if set(query) != {"name"} or not query["name"] or len(query["name"]) > 200 or query["name"] in (".", "..") or any(c in query["name"] for c in ("/", "\\")) or any(ord(c) < 32 or ord(c) == 127 for c in query["name"]):
                    self.reject()
                    return
                parent = "" if child[1] == "0" else "nested"
                name = posixpath.join(parent, query["name"])
                if name == "nested":
                    self.json_reply(200, {"file": state.folder_metadata(name)})
                elif name in state.files:
                    state.listed.add(str(state.ids[name]))
                    state.events.append(("metadata", name))
                    self.json_reply(200, {"file": state.metadata(name)})
                else:
                    state.missing += 1
                    state.events.append(("missing", name))
                    self.api_error(404, "synthetic child not found")
                return
            if query != {"notunnel": "0"} or link[1] not in state.listed:
                self.reject()
                return
            token = uuid.uuid4().hex
            state.links[token] = state.names[link[1]]
            state.events.append(("download_link", state.names[link[1]]))
            self.json_reply(200, {"url": "https://" + PUTIO_API_NAME + "/content/" + token})

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch


@contextmanager
def serve_putio(root, state):
    certificates, transport = None, None
    try:
        certificates = FixtureCertificates.create(root, server_name=PUTIO_API_NAME)
        transport = BoundedHttpsServer(certificates, PutioHandler, state=state,
                                       limits=TlsLimits(connection_limit=128, active_limit=4,
                                                        request_seconds=3, lifetime_seconds=120))
        transport.start()
        yield certificates, transport
    finally:
        transport_ok = transport is None or transport.close()
        material_ok = certificates is None or certificates.close()
        state.cleanup_complete = transport_ok and material_ok
        if not state.cleanup_complete:
            raise RuntimeError("putio_cleanup_failed")
