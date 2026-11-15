"""Independent Linkbox saved web-token inventory and CDN read fixture."""
from contextlib import contextmanager
import hmac
import posixpath
import re
import time
import urllib.parse
import uuid
from fixture_read_api import ReadState, ReadHandler
from fixture_servers import children
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits, LINKBOX_API_NAME

STAMP = 1704067200
CDN_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

class LinkboxState(ReadState):
    def __init__(self, token):
        if not token:
            raise ValueError("missing_linkbox_web_token")
        super().__init__(token)
        self.ids = {name: 1201 + i for i, name in enumerate(sorted(self.files))}
        self.links = {uuid.uuid4().hex: name for name in self.files}
        self.tokens = {name: token for token, name in self.links.items()}
        self.issued = set()
        self.content_authorizations = 0

    def metadata(self, name):
        return {"id": self.ids[name], "pid": 10 if "/" in name else 0,
                "type": "application/octet-stream", "name": posixpath.basename(name),
                "size": len(self.files[name]), "ctime": STAMP, "item_id": "item" + str(self.ids[name]),
                "url": "https://" + LINKBOX_API_NAME + "/content/" + self.tokens[name]}

    def folder(self, name):
        items = []
        for path in children(name, self.files):
            if path in self.files:
                item = self.metadata(path)
                self.issued.add(self.tokens[path])
            else:
                item = {"id": 10, "pid": 0, "type": "dir", "name": "nested", "size": 0,
                        "ctime": STAMP, "item_id": "", "url": ""}
            items.append(item)
        return items

class LinkboxHandler(ReadHandler):
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
                    or self.headers.get_all("Host") != [LINKBOX_API_NAME]
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


    def dispatch(self):
        with self.server.state.lock:
            request = self.wire()
            if request is None:
                return
            path, query = request
            state = self.server.state
            content = re.fullmatch(r"/content/([a-f0-9]{32})", path)
            listing = path == "/api/file/my_file_list/web"
            if (not content and not listing or self.command == "DELETE" and not content
                    or self.headers.get("Range") is not None and (not content or self.command != "GET")):
                self.reject()
                return
            if self.headers.get("Authorization") is not None or self.headers.get("Cookie") is not None:
                if content and self.command == "GET":
                    state.content_authorizations += 1
                self.reject()
                return
            if content and self.command == "GET":
                if query or self.headers.get("User-Agent") != CDN_USER_AGENT:
                    self.reject()
                elif content[1] not in state.issued:
                    self.json_reply(401, {"status": 401, "msg": "synthetic unissued content link"})
                else:
                    self.payload(state.links[content[1]])
                return
            if not hmac.compare_digest(query.get("token", "").encode(), state.password.encode()):
                state.denied += 1
                state.events.append(("credentials_denied", ""))
                self.json_reply(401, {"status": 401, "msg": "synthetic invalid web token"})
                return
            state.authenticated += 1
            if content:
                if set(query) != {"token"} or content[1] not in state.issued:
                    self.reject()
                else:
                    self.write_denial(state.links[content[1]])
                return
            if (set(query) != {"token", "pid", "pageNo", "pageSize"} or query["pid"] not in ("0", "10")
                    or query["pageNo"] != "1" or query["pageSize"] != "1000"):
                self.reject()
                return
            name = "" if query["pid"] == "0" else "nested"
            state.events.append(("listing", name))
            self.json_reply(200, {"status": 1, "msg": "success", "data": {"list": state.folder(name)}})

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch


@contextmanager
def serve_linkbox(root, state):
    certificates, transport = None, None
    try:
        certificates = FixtureCertificates.create(root, server_name=LINKBOX_API_NAME)
        transport = BoundedHttpsServer(certificates, LinkboxHandler, state=state,
                                       limits=TlsLimits(connection_limit=128, active_limit=4,
                                                        request_seconds=3, lifetime_seconds=120))
        transport.start()
        yield certificates, transport
    finally:
        transport_ok = transport is None or transport.close()
        material_ok = certificates is None or certificates.close()
        state.cleanup_complete = transport_ok and material_ok
        if not state.cleanup_complete:
            raise RuntimeError("linkbox_cleanup_failed")
