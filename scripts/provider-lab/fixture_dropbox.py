"""Independent Dropbox saved-token reads across separate API/content TLS hosts."""
from contextlib import contextmanager, ExitStack
import hashlib
import hmac
import json
import posixpath
import re
import socket
import time
import urllib.parse
from fixture_read_api import ReadState, ReadHandler
from fixture_servers import children
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits, DROPBOX_API_NAME, DROPBOX_CONTENT_NAME

ROOT = "synthetic-root"
API = "/2/files/"
STAMP = "2024-01-01T00:00:00Z"
ADDRESSES = {DROPBOX_API_NAME: "127.0.0.1", DROPBOX_CONTENT_NAME: "127.0.0.2"}

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result

def content_hash(body):
    # Hash binary SHA-256 block digests, including no blocks for empty input.
    blocks = b"".join(hashlib.sha256(body[i:i + 4194304]).digest()
                      for i in range(0, len(body), 4194304))
    return hashlib.sha256(blocks).hexdigest()

class DropboxState(ReadState):
    def __init__(self, token):
        if not token:
            raise ValueError("missing_dropbox_token")
        super().__init__(token)
        self.observed = set()
        self.ids = {"": "id:synthetic-root", "nested": "id:synthetic-nested"}
        self.ids.update({name: "id:file" + str(i + 2001) for i, name in enumerate(sorted(self.files))})
        self.names = {value: key for key, value in self.ids.items()}

    def metadata(self, name):
        if name not in self.ids:
            raise ValueError("unknown_dropbox_item")
        path = "/" + ROOT + ("/" + name if name else "")
        item = {".tag": "file" if name in self.files else "folder", "id": self.ids[name],
                "name": posixpath.basename(name) if name else ROOT,
                "path_lower": path.lower(), "path_display": path}
        if name in self.files:
            item.update(size=len(self.files[name]), client_modified=STAMP, server_modified=STAMP,
                        rev="synthetic-revision", is_downloadable=True, content_hash=content_hash(self.files[name]))
        return item

class DropboxHandler(ReadHandler):
    def wire(self):
        state = self.server.state
        state.requests += 1
        limited = state.requests > state.request_limit or time.monotonic() > state.deadline
        if limited:
            state.budget_exceeded = True
        headers = list(self.headers.items())
        names = [key.lower() for key, _ in headers]
        try:
            raw = self.raw_requestline.rstrip(b"\r\n").split(b" ")
            length = self.headers.get("Content-Length", "0")
            host = self.headers.get("Host", "")
            content = self.path == API + "download"
            expected_host = DROPBOX_CONTENT_NAME if content else DROPBOX_API_NAME
            expected_type = "application/octet-stream" if content else "application/json"
            if (len(raw) != 3 or raw[1].decode("ascii") != self.path or len(self.path) > 2048
                    or self.path not in (API + "list_folder", API + "get_metadata", API + "download")
                    or self.headers.get_all("Host") != [expected_host]
                    or self.server.transport._server_name not in (None, expected_host)
                    or len(names) != len(set(names)) or sum(len(k) + len(v) for k, v in headers) > 16384
                    or any("\r" in v or "\n" in v for _, v in headers)
                    or self.headers.get("Transfer-Encoding") is not None
                    or self.headers.get("Cookie") is not None
                    or any(k.lower().startswith("dropbox-api-") and k.lower() != "dropbox-api-arg" for k in self.headers)
                    or not re.fullmatch(r"0|[1-9][0-9]{0,3}", length) or int(length) > 4096
                    or self.command not in ("POST", "DELETE")
                    or self.command == "DELETE" and not content
                    or self.headers.get("Content-Type") != expected_type
                    or content and length != "0"
                    or not content and (length == "0" or self.headers.get("Dropbox-API-Arg") is not None)
                    or not content and self.headers.get("Range") is not None):
                raise ValueError("invalid_request")
            if content:
                value = self.headers.get("Dropbox-API-Arg", "")
                if not 1 <= len(value) <= 4096:
                    raise ValueError("invalid_download_argument")
                data = json.loads(value, object_pairs_hook=unique_object)
            else:
                raw = self.rfile.read(int(length))
                if len(raw) != int(length):
                    raise ValueError("short_json")
                data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
            if type(data) is not dict:
                raise ValueError("invalid_json")
            # Drain only admitted bounded RPC bodies before a budget reply.
            if limited:
                self.json_reply(429, {"error_summary": "synthetic request limit"})
                return None
            return self.path, data
        except OSError:
            self.close_connection = True
            return None
        except (ValueError, UnicodeError):
            self.reject()
            return None

    def api_error(self, status, reason):
        error = {".tag": "path", "path": {".tag": reason}} if status == 409 else {".tag": reason}
        self.json_reply(status, {"error_summary": ("path/" if status == 409 else "") + reason + "/",
                                "error": error})

    def payload(self, name):
        state = self.server.state
        if state.mode == "read_denied":
            state.read_denied += 1
            state.events.append(("read_denied", name))
            self.api_error(409, "restricted_content")
            return
        body, status = state.files[name], 200
        headers = {"Content-Type": "application/octet-stream",
                   "Dropbox-API-Result": json.dumps(state.metadata(name), separators=(",", ":"))}
        requested = self.headers.get("Range")
        if requested is not None:
            match = re.fullmatch(r"bytes=([0-9]{1,19})-([0-9]{0,19})", requested)
            if not match:
                self.reject(416)
                return
            start = int(match[1]);end = int(match[2]) if match[2] else len(body) - 1
            if start >= len(body) or start > end:
                self.reject(416)
                return
            end = min(end, len(body) - 1)
            headers["Content-Range"] = f"bytes {start}-{end}/{len(body)}"
            body, status = body[start:end + 1], 206
        state.events.append(("content", name))
        self.reply(status, body, headers, object_payload=True)

    def dispatch(self):
        with self.server.state.lock:
            request = self.wire()
            if request is None:
                return
            path, data = request
            state = self.server.state
            if not hmac.compare_digest(self.headers.get("Authorization", "").encode(),
                                       ("Bearer " + state.password).encode()):
                state.denied += 1
                state.events.append(("credentials_denied", ""))
                self.api_error(401, "invalid_access_token")
                return
            state.authenticated += 1
            if path == API + "download":
                ident = data.get("path")
                if set(data) != {"path"} or type(ident) is not str or ident not in state.names:
                    self.reject()
                    return
                name = state.names[ident]
                if name not in state.files or name not in state.observed:
                    self.reject()
                elif self.command == "DELETE":
                    self.write_denial(name)
                else:
                    self.payload(name)
                return
            if path == API + "get_metadata":
                controls = {"include_media_info": False, "include_deleted": False, "include_has_explicit_shared_members": False}
            else:
                controls = {"recursive": False, "include_media_info": False, "include_deleted": False,
                            "include_has_explicit_shared_members": False, "include_mounted_folders": True,
                            "limit": 1000, "include_non_downloadable_files": True, "include_restorable_info": False}
            if (set(data) != set(controls) | {"path"} or type(data["path"]) is not str
                    or any(type(data[key]) is not type(value) or data[key] != value for key, value in controls.items())):
                self.reject()
                return
            value = data["path"]
            name = "" if value == "/" + ROOT else value.removeprefix("/" + ROOT + "/") if value.startswith("/" + ROOT + "/") else None
            if name == "absent-synthetic.txt":
                state.missing += 1
                state.events.append(("missing", name))
                self.api_error(409, "not_found")
                return
            if name not in state.ids or name == "" and value != "/" + ROOT:
                self.reject()
                return
            if path == API + "get_metadata":
                if name in state.files:
                    state.observed.add(name)
                state.events.append(("metadata", name))
                self.json_reply(200, state.metadata(name))
            elif name not in ("", "nested"):
                self.reject()
            else:
                names = children(name, state.files)
                state.observed.update(item for item in names if item in state.files)
                state.events.append(("listing", name))
                self.json_reply(200, {"entries": [state.metadata(item) for item in names],
                                      "cursor": "synthetic-complete-cursor", "has_more": False})

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch

def listeners_closed(transports):
    for transport in transports:
        with socket.socket() as probe:
            probe.settimeout(1)
            if probe.connect_ex((ADDRESSES[transport.authority], transport.port)) == 0:
                return False
    return True

@contextmanager
def serve_dropbox(root, state):
    certificates, transports = [], []
    try:
        with ExitStack() as stack:
            for authority in (DROPBOX_API_NAME, DROPBOX_CONTENT_NAME):
                cert = stack.enter_context(FixtureCertificates.create(root, server_name=authority))
                certificates.append(cert)
                transport = BoundedHttpsServer(cert, DropboxHandler, state=state,
                            limits=TlsLimits(connection_limit=128, active_limit=4, request_seconds=3, lifetime_seconds=120))
                transports.append(transport)
                stack.callback(transport.close)
                transport.start()
            yield certificates, transports
    finally:
        state.cleanup_complete = (all(t.cleanup_complete for t in transports)
                                  and all(c.cleanup_complete for c in certificates)
                                  and listeners_closed(transports))
        if not state.cleanup_complete:
            raise RuntimeError("dropbox_cleanup_failed")
