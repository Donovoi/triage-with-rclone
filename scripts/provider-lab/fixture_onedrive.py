"""Independent OneDrive business-drive saved OAuth and redirect read fixture."""
from contextlib import contextmanager
import hmac
import posixpath
import re
import time
import urllib.parse
import uuid
from fixture_read_api import ReadState, ReadHandler
from fixture_servers import children
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits, ONEDRIVE_API_NAME

STAMP = "2024-01-01T00:00:00Z"
DRIVE = "synthetic-business-drive"
API = "/v1.0/drives/" + DRIVE
# Independent bit-by-bit Microsoft QuickXor oracles, checked against 70
# pinned reference vectors and native hashsum; preserve the default hash mode.
QUICKXOR = {
    "README-synthetic.txt": "q+GwV5ocSpsIHjWVCFGoh/fhS/8=",
    "nested/bytes.bin": "rxAOGe1RimTF/e+k/mYO5nnSZT8=",
    "nested/space name.txt": "LyTjnKtI9PIGV4r4Zi1N0FAGOqQ=",
}

class OneDriveState(ReadState):
    def __init__(self, token):
        if not token:
            raise ValueError("missing_onedrive_token")
        super().__init__(token)
        self.observed, self.links = set(), {}
        self.ids = {"": "root-id", "nested": "nested-id"}
        self.ids.update({name: "file-" + str(i + 1601) for i, name in enumerate(sorted(self.files))})
        self.names = {value: key for key, value in self.ids.items()}

    def metadata(self, name):
        if name not in self.ids:
            raise ValueError("unknown_onedrive_item")
        item = {"id": self.ids[name], "name": posixpath.basename(name) if name else "root",
                "size": len(self.files[name]) if name in self.files else 0,
                "parentReference": {"driveId": DRIVE, "driveType": "business",
                                    "id": self.ids[posixpath.dirname(name)]},
                "createdDateTime": STAMP, "lastModifiedDateTime": STAMP,
                "fileSystemInfo": {"createdDateTime": STAMP, "lastModifiedDateTime": STAMP},
                "eTag": "synthetic-etag", "cTag": "synthetic-ctag"}
        if name in self.files:
            item["file"] = {"mimeType": "application/octet-stream",
                            "hashes": {"quickXorHash": QUICKXOR[name]}}
        else:
            item["folder"] = {"childCount": len(children(name, self.files))}
        return item

    def folder(self, name):
        items = []
        for path in children(name, self.files):
            items.append(self.metadata(path))
            if path in self.files:
                self.observed.add(path)
        return items

class OneDriveHandler(ReadHandler):
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
                    or self.headers.get_all("Host") != [ONEDRIVE_API_NAME]
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
            if url.scheme or url.netloc or url.fragment or "//" in url.path or "\\" in url.path:
                raise ValueError("invalid_target")
            pairs = urllib.parse.parse_qsl(url.query, keep_blank_values=True, strict_parsing=True, max_num_fields=4, encoding="utf-8", errors="strict")
            query = dict(pairs)
            if len(query) != len(pairs):
                raise ValueError("duplicate_query")
            path = urllib.parse.unquote(url.path, encoding="utf-8", errors="strict")
            if urllib.parse.quote(path, safe="/:") != url.path:
                raise ValueError("noncanonical_path")
            return path, query
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

    def api_error(self, status, code):
        self.json_reply(status, {"error": {"code": code, "message": "synthetic OneDrive fixture rejection"}})

    def dispatch(self):
        with self.server.state.lock:
            request = self.wire()
            if request is None:
                return
            path, query = request
            state = self.server.state
            content = re.fullmatch(r"/content/([a-f0-9]{32})", path)
            if (self.headers.get("Cookie") is not None or self.headers.get("Prefer") is not None
                    or self.command == "DELETE" and not content):
                self.reject()
                return
            if content:
                if query != {"tempauth": content[1]} or self.headers.get("Authorization") is not None:
                    self.reject()
                elif content[1] not in state.links:
                    self.api_error(401, "unauthenticated")
                elif self.command == "DELETE":
                    self.write_denial(state.links[content[1]])
                else:
                    state.events.append(("unauthenticated_content", state.links[content[1]]))
                    self.payload(state.links[content[1]])
                return
            if not path.startswith(API + "/"):
                self.reject()
                return
            if not hmac.compare_digest(self.headers.get("Authorization", "").encode(),
                                       ("Bearer " + state.password).encode()):
                state.denied += 1
                state.events.append(("credentials_denied", ""))
                self.api_error(401, "unauthenticated")
                return
            state.authenticated += 1
            route = path.removeprefix(API)
            listing = re.fullmatch(r"/items/(root-id|nested-id)/children", route)
            download = re.fullmatch(r"/items/(file-160[123])/content", route)
            if self.headers.get("Range") is not None and not download:
                self.reject()
                return
            if listing:
                if query != {"$top": "1000"}:
                    self.reject()
                    return
                name = state.names[listing[1]]
                state.events.append(("listing", name))
                self.json_reply(200, {"value": state.folder(name)})
                return
            if query:
                self.reject()
                return
            if download:
                name = state.names[download[1]]
                if name not in state.observed:
                    self.reject()
                    return
                token = uuid.uuid4().hex
                state.links[token] = name
                state.events.append(("download_redirect", name))
                self.send_response(302)
                # Explicit preauthorization keeps Graph OAuth off the download hop.
                self.send_header("Location", "https://" + ONEDRIVE_API_NAME + "/content/" + token + "?tempauth=" + token)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if route == "/root":
                name = ""
                state.events.append(("root_discovery", name))
            else:
                relative = re.fullmatch(r"/items/(root-id|nested-id):/([^:]+):?", route)
                absolute = re.fullmatch(r"/root:/([^:]+)", route)
                if relative:
                    name = posixpath.join(state.names[relative[1]], relative[2])
                elif absolute:
                    name = absolute[1]
                else:
                    self.reject()
                    return
                if name in ("absent-synthetic.txt", "nested/nested"):
                    state.missing += 1
                    state.events.append(("missing", name))
                    self.api_error(404, "itemNotFound")
                    return
                if name not in state.ids:
                    self.reject()
                    return
            if name in state.files:
                state.observed.add(name)
            state.events.append(("metadata", name))
            self.json_reply(200, state.metadata(name))

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch


@contextmanager
def serve_onedrive(root, state):
    certificates, transport = None, None
    try:
        certificates = FixtureCertificates.create(root, server_name=ONEDRIVE_API_NAME)
        transport = BoundedHttpsServer(certificates, OneDriveHandler, state=state,
                                       limits=TlsLimits(connection_limit=128, active_limit=4,
                                                        request_seconds=3, lifetime_seconds=120))
        transport.start()
        yield certificates, transport
    finally:
        transport_ok = transport is None or transport.close()
        material_ok = certificates is None or certificates.close()
        state.cleanup_complete = transport_ok and material_ok
        if not state.cleanup_complete:
            raise RuntimeError("onedrive_cleanup_failed")
