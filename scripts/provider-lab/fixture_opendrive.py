"""Independent OpenDrive session and configured read fixture."""
from contextlib import contextmanager
import hashlib
import hmac
import json
import posixpath
import re
import secrets
import time
import urllib.parse
from fixture_read_api import ReadState, ReadHandler
from fixture_servers import children, is_directory
from fixture_quatrix import unique_object
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits, OPENDRIVE_API_NAME

API = "/api/v1"
STAMP = 1704067200

class OpenDriveState(ReadState):
    def __init__(self, username, password):
        if not username or not password:
            raise ValueError("missing_opendrive_credentials")
        super().__init__(password)
        self.user = username
        self.ids = {name: str(601 + i) for i, name in enumerate(sorted(self.files))}
        self.names = {value: key for key, value in self.ids.items()}
        self.sessions = set()

    def metadata(self, name):
        return {"FileId": self.ids[name], "Name": posixpath.basename(name),
                "Size": str(len(self.files[name])), "DateModified": str(STAMP),
                "FileHash": hashlib.md5(self.files[name]).hexdigest(), "Access": "0"}

    def listing(self, name, selected=None):
        paths = children(name, self.files)
        return {"Name": posixpath.basename(name), "ParentFolderID": "0", "ResponseType": 1,
                "Folders": [{"FolderID": "10", "Name": "nested", "DateModified": STAMP,
                             "ChildFolders": 0} for p in paths if is_directory(p, self.files) and selected is None],
                "Files": [self.metadata(p) for p in paths if p in self.files
                          and (selected is None or posixpath.basename(p) == selected)]}

class OpenDriveHandler(ReadHandler):
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
                    or self.headers.get_all("Host") != [OPENDRIVE_API_NAME]
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

    def dispatch(self):
        with self.server.state.lock:
            request = self.wire()
            if request is None:
                return
            path, query, data = request
            state = self.server.state
            login = path == API + "/session/login.json"
            listing = re.fullmatch(re.escape(API) + r"/folder/(list|itembyname)\.json/([a-f0-9]{32})/(0|10)", path)
            file = re.fullmatch(re.escape(API) + r"/(file/info|download/file)\.json/(60[123])", path)
            delete = re.fullmatch(re.escape(API) + r"/file\.json/([a-f0-9]{32})/(60[123])", path)
            if (self.headers.get("Authorization") is not None
                    or not any((login, listing, file, delete))
                    or self.command == "POST" and not login or login and self.command != "POST"
                    or self.command == "DELETE" and not delete or delete and self.command != "DELETE"
                    or self.headers.get("Range") is not None and (not file or file[1] != "download/file")):
                self.reject()
                return
            if login:
                if query or set(data) != {"username", "passwd"} or any(type(v) is not str for v in data.values()):
                    self.reject()
                    return
                if (not hmac.compare_digest(data["username"].encode(), state.user.encode())
                        or not hmac.compare_digest(data["passwd"].encode(), state.password.encode())):
                    state.denied += 1
                    state.events.append(("credentials_denied", ""))
                    self.json_reply(401, {"error": {"code": 401, "message": "synthetic credentials denied"}})
                    return
                session = secrets.token_hex(16)
                state.sessions.add(session)
                state.events.append(("session_created", ""))
                self.json_reply(200, {"SessionID": session, "UserName": state.user})
                return
            if file:
                if set(query) != {"session_id"}:
                    self.reject()
                    return
                session = query["session_id"]
            elif listing:
                session = listing[2]
                if (listing[1] == "list" and query or listing[1] == "itembyname"
                        and (set(query) != {"name"} or not re.fullmatch(r"[^/\\]{1,100}", query["name"])
                             or query["name"] in (".", "..") or any(ord(c) < 32 or ord(c) == 127 for c in query["name"]))):
                    self.reject()
                    return
            else:
                session = delete[1]
                if query:
                    self.reject()
                    return
            if session not in state.sessions:
                state.denied += 1
                state.events.append(("session_denied", ""))
                self.json_reply(401, {"error": {"code": 401, "message": "synthetic session denied"}})
                return
            state.authenticated += 1
            if listing:
                folder = "" if listing[3] == "0" else "nested"
                selected = query.get("name")
                result = state.listing(folder, selected)
                if selected is None:
                    state.events.append(("listing", folder))
                elif not result["Files"]:
                    state.missing += 1
                    state.events.append(("missing", posixpath.join(folder, selected)))
                else:
                    state.events.append(("lookup", posixpath.join(folder, selected)))
                self.json_reply(200, result)
            elif file:
                name = state.names[file[2]]
                if file[1] == "file/info":
                    state.events.append(("metadata", name))
                    self.json_reply(200, state.metadata(name))
                else:
                    self.payload(name)
            else:
                self.write_denial(state.names[delete[2]])

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch


@contextmanager
def serve_opendrive(root, state):
    certificates, transport = None, None
    try:
        certificates = FixtureCertificates.create(root, server_name=OPENDRIVE_API_NAME)
        transport = BoundedHttpsServer(certificates, OpenDriveHandler, state=state,
                                       limits=TlsLimits(connection_limit=128, active_limit=4,
                                                        request_seconds=3, lifetime_seconds=120))
        transport.start()
        yield certificates, transport
    finally:
        transport_ok = transport is None or transport.close()
        material_ok = certificates is None or certificates.close()
        state.cleanup_complete = transport_ok and material_ok
        if not state.cleanup_complete:
            raise RuntimeError("opendrive_cleanup_failed")
