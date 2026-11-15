"""Independent Quatrix static-key reads over owned loopback TLS.

The API has POST-based lookup and download-link operations. These are reads;
only the exact deletion guard is admitted as a rejected mutation.
"""
from contextlib import contextmanager
import hmac
from http.server import BaseHTTPRequestHandler
import json
import posixpath
import re
import time
import urllib.parse

from fixture_read_api import ReadState, ReadHandler
from fixture_servers import children, is_directory, SeafileHandler
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits


class QuatrixState(ReadState):
    def __init__(self, token, wrong_token):
        if not token or not wrong_token or token == wrong_token:
            raise ValueError("invalid_quatrix_tokens")
        super().__init__(token)
        self.wrong_token = wrong_token
        self.ids = {"": "100", "nested": "200"}
        self.ids.update({name: str(301 + i) for i, name in enumerate(sorted(self.files))})
        self.names = {value: key for key, value in self.ids.items()}
        self.links = set()

    def metadata(self, name, content=False):
        directory = is_directory(name, self.files)
        value = {"id": self.ids[name], "created": 1704067200, "modified": 1704067200,
                 "modified_ms": 1704067200, "name": posixpath.basename(name),
                 "parent_id": self.ids.get(posixpath.dirname(name), ""), "type": "D" if directory else "F",
                 "size": len(children(name, self.files)) if directory else len(self.files[name]),
                 "operations": 0, "sub_type": ""}
        if content:
            value["content"] = [self.metadata(child) for child in children(name, self.files)]
        return value


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_json_key")
        value[key] = item
    return value


class QuatrixHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # Transport-independent bounded response and immutable-payload helpers.
    reply = SeafileHandler.reply
    json_reply = SeafileHandler.json_reply
    reject = SeafileHandler.reject
    send_error = SeafileHandler.send_error
    payload = ReadHandler.payload
    write_denial = ReadHandler.write_denial

    def log_message(self, *args):
        pass

    def wire(self):
        state = self.server.state
        state.requests += 1
        limited = state.requests > state.request_limit or time.monotonic() > state.deadline
        if limited:
            state.budget_exceeded = True
        # Validate and consume a bounded JSON body before sending a budget
        # rejection. Closing TLS with an unread POST body can discard the
        # response when the peer is still sending that body.
        headers = list(self.headers.items())
        names = [key.lower() for key, _ in headers]
        try:
            raw = self.raw_requestline.rstrip(b"\r\n").split(b" ")
            length = self.headers.get("Content-Length", "0")
            if (len(raw) != 3 or raw[1].decode("ascii") != self.path or len(self.path) > 2048
                    or not self.path.startswith("/") or any(ord(c) <= 32 or ord(c) >= 127 for c in self.path)
                    or self.headers.get_all("Host") != [self.server.authority]
                    or len(names) != len(set(names))
                    or sum(len(k) + len(v) for k, v in headers) > 16384
                    or any("\r" in v or "\n" in v for _, v in headers)
                    or self.headers.get("Transfer-Encoding") is not None
                    or not re.fullmatch(r"0|[1-9][0-9]{0,3}", length) or int(length) > 4096
                    or self.command not in ("GET", "POST")
                    or self.command == "GET" and length != "0"
                    or self.command == "POST" and (length == "0" or self.headers.get("Content-Type") != "application/json")):
                raise ValueError("invalid_request")
            url = urllib.parse.urlsplit(self.path)
            if url.scheme or url.netloc or url.fragment or "%" in url.path or "\\" in url.path:
                raise ValueError("invalid_target")
            pairs = urllib.parse.parse_qsl(url.query, keep_blank_values=True, strict_parsing=True, max_num_fields=1)
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
            if limited:
                self.json_reply(429, {"error": "synthetic request limit"})
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

    def dispatch(self):
        with self.server.state.lock:
            request = self.wire()
            if request is None:
                return
            path, query, data = request
            state = self.server.state
            base = "/api/1.0/"
            # The pinned rest client concatenates API root and download Path.
            # Only that exact double-slash download route is admitted.
            metadata = re.fullmatch(re.escape(base) + r"file/metadata/(100|200|30[123])", path)
            download = re.fullmatch(re.escape(base) + r"/file/download/link-(30[123])", path)
            if not (self.command == "POST" and path in (base + "file/id", base + "file/download-link", base + "file/delete") and not query
                    or self.command == "GET" and metadata and query in ({}, {"content": "0"})
                    or self.command == "GET" and download and not query):
                self.reject()
                return
            if self.headers.get("Range") is not None and not download:
                self.reject()
                return
            authorization = self.headers.get("Authorization", "")
            if not hmac.compare_digest(authorization.encode(), ("Bearer " + state.password).encode()):
                if authorization not in ("", "Bearer " + state.wrong_token):
                    self.reject()
                    return
                state.denied += 1
                state.events.append(("auth_denied", path))
                self.json_reply(401, {"error": "synthetic credential denied"})
                return
            state.authenticated += 1
            if path == base + "file/id":
                if (set(data) not in ({"path"}, {"path", "parent_id"}) or type(data.get("path")) is not str
                        or data.get("parent_id", "") not in ("", "100", "200")
                        or "\\" in data["path"] or "%" in data["path"]
                        or any(ord(c) < 32 or ord(c) == 127 for c in data["path"])
                        or data["path"] and any(part in ("", ".", "..") for part in data["path"].split("/"))):
                    self.reject()
                    return
                parent = state.names.get(data.get("parent_id", "100"), "")
                name = posixpath.join(parent, data["path"])
                if name not in state.ids:
                    state.missing += 1
                    state.events.append(("missing", name))
                    self.json_reply(404, {})
                    return
                state.events.append(("lookup", name))
                self.json_reply(200, {"file_id": state.ids[name], "parent_id": state.ids.get(posixpath.dirname(name), ""),
                                      "src": name, "type": "F" if name in state.files else "D"})
            elif metadata:
                name = state.names[metadata[1]]
                content = not query
                if content and not is_directory(name, state.files):
                    self.reject()
                    return
                state.events.append(("listing" if content else "metadata", name))
                self.json_reply(200, state.metadata(name, content))
            elif path in (base + "file/download-link", base + "file/delete"):
                expected_keys = {"ids"} if path.endswith("download-link") else {"ids", "delete_permanently"}
                if (set(data) != expected_keys or type(data.get("ids")) is not list or len(data["ids"]) != 1
                        or type(data["ids"][0]) is not str or data["ids"][0] not in ("301", "302", "303")
                        or path.endswith("delete") and data["delete_permanently"] is not False):
                    self.reject()
                    return
                identity = data["ids"][0]
                name = state.names[identity]
                if path.endswith("delete"):
                    self.write_denial(name)
                else:
                    state.links.add(identity)
                    state.events.append(("download_link", name))
                    self.json_reply(200, {"id": "link-" + identity})
            elif download:
                if download[1] not in state.links:
                    self.reject()
                    return
                self.payload(state.names[download[1]])

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch


@contextmanager
def serve_quatrix(root, state):
    certificates, transport = None, None
    try:
        certificates = FixtureCertificates.create(root)
        transport = BoundedHttpsServer(certificates, QuatrixHandler, state=state,
                                       limits=TlsLimits(connection_limit=128, active_limit=4,
                                                        request_seconds=3, lifetime_seconds=120))
        transport.start()
        yield certificates, transport
    finally:
        transport_ok = transport is None or transport.close()
        material_ok = certificates is None or certificates.close()
        state.cleanup_complete = transport_ok and material_ok
        if not state.cleanup_complete:
            raise RuntimeError("quatrix_cleanup_failed")
