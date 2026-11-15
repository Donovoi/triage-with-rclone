"""Independent FileLu configured-key reads in an explicit synthetic root."""
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
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits, FILELU_API_NAME

API = "/rclone"
ROOT = "synthetic-root"

class FileLuState(ReadState):
    def __init__(self, key):
        if not key:
            raise ValueError("missing_filelu_key")
        super().__init__(key)
        self.observed, self.links = set(), {}
        self.codes = {name: "filelu" + str(i + 1).zfill(6) for i, name in enumerate(sorted(self.files))}
        self.names = {code: name for name, code in self.codes.items()}

    def metadata(self, name):
        return {"size": str(len(self.files[name])), "name": posixpath.basename(name),
                "filecode": self.codes[name], "hash": hashlib.md5(self.files[name]).hexdigest(), "status": 200}

    def folder(self, name):
        files, folders = [], []
        for path in children(name, self.files):
            if path in self.files:
                self.observed.add(path)
                files.append({"name": posixpath.basename(path), "fld_id": 20 if name else 10,
                              "path": ROOT + "/" + path, "file_code": self.codes[path],
                              "size": len(self.files[path])})
            else:
                folders.append({"name": "nested", "fld_id": 20, "path": ROOT + "/nested"})
        return {"files": files, "folders": folders}

class FileLuHandler(ReadHandler):
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
                    or self.headers.get_all("Host") != [FILELU_API_NAME]
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

    def api_reply(self, status, result, msg="OK"):
        self.json_reply(200, {"status": status, "msg": msg, "result": result})

    def dispatch(self):
        with self.server.state.lock:
            request = self.wire()
            if request is None:
                return
            path, query = request
            state = self.server.state
            content = re.fullmatch(r"/content/([a-f0-9]{32})", path)
            if self.headers.get("Authorization") is not None or self.headers.get("Cookie") is not None:
                self.reject()
                return
            if content:
                if query:
                    self.reject()
                elif content[1] not in state.links:
                    self.json_reply(401, {"error": "unknown private link"})
                elif self.command == "DELETE":
                    self.write_denial(state.links[content[1]])
                else:
                    state.events.append(("uncredentialed_content", state.links[content[1]]))
                    self.payload(state.links[content[1]])
                return
            fields = {API + "/folder/list": "folder_path", API + "/file/info2": "file_code",
                      API + "/file/direct_link": "file_path"}
            field = fields.get(path)
            if (field is None or self.command != "GET" or set(query) != {"key", field}
                    or self.headers.get("Range") is not None):
                self.reject()
                return
            if not hmac.compare_digest(query["key"].encode(), state.password.encode()):
                state.denied += 1
                state.events.append(("credentials_denied", ""))
                self.json_reply(401, {"status": 401, "msg": "Invalid key", "result": {}})
                return
            state.authenticated += 1
            value = query[field]
            if field == "folder_path":
                if value in ("/" + ROOT, "/" + ROOT + "/nested"):
                    name = "" if value == "/" + ROOT else "nested"
                    state.events.append(("listing", name))
                    self.api_reply(200, state.folder(name))
                elif value == "/" + ROOT + "/absent-synthetic.txt" or value in {"/" + ROOT + "/" + name for name in state.files}:
                    state.missing += 1
                    state.events.append(("missing_folder", ""))
                    self.api_reply(404, {}, "Folder not found")
                else:
                    self.reject()
                return
            if field == "file_code":
                if value not in state.names or state.names[value] not in state.observed:
                    self.reject()
                    return
                name = state.names[value]
                state.events.append(("metadata", name))
                self.api_reply(200, [state.metadata(name)])
                return
            prefix = ROOT + "/"
            if not value.startswith(prefix) or value.removeprefix(prefix) not in state.observed:
                self.reject()
                return
            name = value.removeprefix(prefix)
            token = uuid.uuid4().hex
            state.links[token] = name
            state.events.append(("download_link", name))
            self.api_reply(200, {"url": "https://" + FILELU_API_NAME + "/content/" + token,
                                 "size": len(state.files[name])})

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch


@contextmanager
def serve_filelu(root, state):
    certificates, transport = None, None
    try:
        certificates = FixtureCertificates.create(root, server_name=FILELU_API_NAME)
        transport = BoundedHttpsServer(certificates, FileLuHandler, state=state,
                                       limits=TlsLimits(connection_limit=128, active_limit=4,
                                                        request_seconds=3, lifetime_seconds=120))
        transport.start()
        yield certificates, transport
    finally:
        transport_ok = transport is None or transport.close()
        material_ok = certificates is None or certificates.close()
        state.cleanup_complete = transport_ok and material_ok
        if not state.cleanup_complete:
            raise RuntimeError("filelu_cleanup_failed")
