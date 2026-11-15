"""Independent Cloudinary Admin API and public raw-asset read fixture."""
from contextlib import contextmanager
import base64
import hashlib
import hmac
import json
import posixpath
import re
import time
import urllib.parse

from fixture_read_api import ReadState, ReadHandler
from fixture_servers import children, is_directory
from fixture_quatrix import unique_object
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits, CLOUDINARY_API_NAME


API = "/v1_1/synthetic-cloud/"
STAMP = "2024-01-01T00:00:00Z"


class CloudinaryState(ReadState):
    def __init__(self, key, secret):
        if not key or not secret:
            raise ValueError("missing_cloudinary_credentials")
        super().__init__(secret)
        self.user = key
        self.ids = {name: str(301 + i) for i, name in enumerate(sorted(self.files))}
        self.names = {value: key for key, value in self.ids.items()}
        self.links = set()

    def metadata(self, name, origin):
        identity = self.ids[name]
        return {"public_id": "synthetic-" + identity, "asset_id": identity,
                "display_name": posixpath.basename(name), "asset_folder": posixpath.dirname(name),
                "resource_type": "raw", "type": "upload", "bytes": len(self.files[name]),
                "created_at": STAMP, "uploaded_at": STAMP,
                "etag": hashlib.md5(self.files[name]).hexdigest(),
                "secure_url": origin + "/content/" + identity}


class CloudinaryHandler(ReadHandler):
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
                    or self.headers.get_all("Host") != [CLOUDINARY_API_NAME]
                    or len(names) != len(set(names))
                    or sum(len(k) + len(v) for k, v in headers) > 16384
                    or any("\r" in v or "\n" in v for _, v in headers)
                    or self.headers.get("Transfer-Encoding") is not None
                    or not re.fullmatch(r"0|[1-9][0-9]{0,3}", length) or int(length) > 4096
                    or self.command not in ("GET", "POST", "DELETE")
                    or self.command != "POST" and length != "0"
                    or self.command == "POST" and (length == "0" or self.headers.get("Content-Type") != "application/json; charset=utf-8")):
                raise ValueError("invalid_request")
            url = urllib.parse.urlsplit(self.path)
            if url.scheme or url.netloc or url.fragment or "%" in url.path or "//" in url.path or "\\" in url.path:
                raise ValueError("invalid_target")
            pairs = urllib.parse.parse_qsl(url.query, keep_blank_values=True, strict_parsing=True, max_num_fields=2)
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
        except (ValueError, UnicodeError, OSError):
            self.reject()
            return None

    def dispatch(self):
        with self.server.state.lock:
            request = self.wire()
            if request is None:
                return
            path, query, data = request
            state = self.server.state
            origin = "https://" + CLOUDINARY_API_NAME
            content = re.fullmatch(r"/content/(30[123])", path)
            folders = re.fullmatch(re.escape(API) + r"folders(?:/(nested|absent-synthetic.txt))?/?", path)
            assets = path == API + "resources/by_asset_folder"
            search = path == API + "resources/search"
            if (not content and not folders and not assets and not search
                    or self.command == "POST" and not search
                    or self.command == "DELETE" and not content
                    or self.command == "GET" and search
                    or self.headers.get("Range") is not None and (not content or self.command != "GET")):
                self.reject()
                return
            expected = "Basic " + base64.b64encode((state.user + ":" + state.password).encode()).decode()
            if content and self.command == "GET":
                if query or self.headers.get("Authorization") is not None or content[1] not in state.links:
                    self.reject()
                    return
                self.payload(state.names[content[1]])
                return
            if not hmac.compare_digest(self.headers.get("Authorization", "").encode(), expected.encode()):
                state.denied += 1
                state.events.append(("credentials_denied", path))
                self.json_reply(401, {"error": {"message": "synthetic credential denied"}})
                return
            state.authenticated += 1
            if content:
                if query:
                    self.reject()
                    return
                self.write_denial(state.names[content[1]])
            elif folders:
                if query != {"max_results": "500"}:
                    self.reject()
                    return
                name = folders[1] or ""
                if not is_directory(name, state.files):
                    state.missing += 1
                    state.events.append(("missing", name))
                    self.json_reply(404, {"error": {"message": "Can't find folder with path synthetic-missing"}})
                    return
                state.events.append(("folders", name))
                values = [{"name": posixpath.basename(p), "path": p} for p in children(name, state.files)
                          if is_directory(p, state.files)]
                self.json_reply(200, {"folders": values})
            elif assets:
                if set(query) != {"max_results", "asset_folder"} or query["max_results"] != "500" or query["asset_folder"] not in ("", "nested/", "absent-synthetic.txt/"):
                    self.reject()
                    return
                name = query["asset_folder"].rstrip("/")
                state.events.append(("listing", name))
                values = [state.metadata(p, origin) for p in children(name, state.files) if p in state.files]
                state.links.update(state.ids[p] for p in children(name, state.files) if p in state.files)
                self.json_reply(200, {"resources": values})
            elif search:
                if (query or set(data) != {"expression", "sort_by", "max_results"}
                        or data["sort_by"] != [{"uploaded_at": "desc"}] or type(data["max_results"]) is not int
                        or data["max_results"] != 2 or type(data["expression"]) is not str):
                    self.reject()
                    return
                match = re.fullmatch(r'asset_folder:"(|nested)" AND display_name:"([^"\\/]{1,100})"', data["expression"])
                if not match or match[2] in (".", ".."):
                    self.reject()
                    return
                name = posixpath.join(match[1], match[2])
                if name not in state.files:
                    state.missing += 1
                    state.events.append(("missing", name))
                    self.json_reply(200, {"total_count": 0, "resources": []})
                    return
                state.events.append(("metadata", name))
                state.links.add(state.ids[name])
                self.json_reply(200, {"total_count": 1, "resources": [state.metadata(name, origin)]})

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch


@contextmanager
def serve_cloudinary(root, state):
    certificates, transport = None, None
    try:
        certificates = FixtureCertificates.create(root, server_name=CLOUDINARY_API_NAME)
        transport = BoundedHttpsServer(certificates, CloudinaryHandler, state=state,
                                       limits=TlsLimits(connection_limit=128, active_limit=4,
                                                        request_seconds=3, lifetime_seconds=120))
        transport.start()
        yield certificates, transport
    finally:
        transport_ok = transport is None or transport.close()
        material_ok = certificates is None or certificates.close()
        state.cleanup_complete = transport_ok and material_ok
        if not state.cleanup_complete:
            raise RuntimeError("cloudinary_cleanup_failed")
