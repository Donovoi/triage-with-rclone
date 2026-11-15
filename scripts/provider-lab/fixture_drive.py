"""Independent Google Drive saved-token reads for one explicit synthetic folder."""
from contextlib import contextmanager
import hashlib
import hmac
import posixpath
import re
import time
import urllib.parse
from fixture_read_api import ReadState, ReadHandler
from fixture_servers import children
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits, DRIVE_API_NAME

API = "/drive/v3/files"
ROOT = "synthetic-root"
STAMP = "2024-01-01T00:00:00Z"
FOLDER = "application/vnd.google-apps.folder"
SHORTCUT = "application/vnd.google-apps.shortcut"
FIELDS = "id,name,size,md5Checksum,sha1Checksum,sha256Checksum,trashed,explicitlyTrashed,modifiedTime,createdTime,mimeType,parents,webViewLink,shortcutDetails,exportLinks,resourceKey"
LIST_FIELDS = "files(" + FIELDS + "),nextPageToken,incompleteSearch"

class DriveState(ReadState):
    def __init__(self, token):
        if not token:
            raise ValueError("missing_drive_token")
        super().__init__(token)
        self.observed = set()
        self.ids = {"": ROOT, "nested": "synthetic-nested"}
        self.ids.update({name: "file-" + str(i + 1801) for i, name in enumerate(sorted(self.files))})
        self.names = {value: key for key, value in self.ids.items()}

    def metadata(self, name):
        if name not in self.ids:
            raise ValueError("unknown_drive_item")
        item = {"id": self.ids[name], "name": posixpath.basename(name) if name else "synthetic-root",
                "mimeType": "application/octet-stream" if name in self.files else FOLDER,
                "parents": [self.ids[posixpath.dirname(name)]] if name else [],
                "trashed": False, "explicitlyTrashed": False,
                "modifiedTime": STAMP, "createdTime": STAMP}
        if name in self.files:
            body = self.files[name]
            item.update(size=str(len(body)), md5Checksum=hashlib.md5(body).hexdigest(),
                        sha1Checksum=hashlib.sha1(body).hexdigest(), sha256Checksum=hashlib.sha256(body).hexdigest())
        return item

    def selection(self, expression):
        # Enumerate the finite reviewed predicates. Do not interpret arbitrary
        # Drive search syntax or silently drop scope, trash or type predicates.
        for directory in ("", "nested"):
            parent = self.ids[directory]
            for title in ("", "nested", "README-synthetic.txt", "bytes.bin", "space name.txt", "absent-synthetic.txt"):
                for kind in ("all", "directories", "files"):
                    query = "trashed=false and ('" + parent + "' in parents)"
                    if title:
                        query += " and (name='" + title + "')"
                    if kind == "directories":
                        query += " and (mimeType='" + FOLDER + "' or mimeType='" + SHORTCUT + "')"
                    elif kind == "files":
                        query += " and mimeType!='" + FOLDER + "'"
                    if expression == query:
                        paths = [name for name in children(directory, self.files)
                                 if (not title or posixpath.basename(name) == title)
                                 and (kind != "directories" or name not in self.files)
                                 and (kind != "files" or name in self.files)]
                        return directory, title, kind, paths
        return None

class DriveHandler(ReadHandler):
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
                    or self.headers.get_all("Host") != [DRIVE_API_NAME]
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
            pairs = urllib.parse.parse_qsl(url.query, keep_blank_values=True, strict_parsing=True, max_num_fields=8, encoding="utf-8", errors="strict")
            query = dict(pairs)
            if len(query) != len(pairs):
                raise ValueError("duplicate_query")
            path = urllib.parse.unquote(url.path, encoding="utf-8", errors="strict")
            if urllib.parse.quote(path, safe="/") != url.path:
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


    def api_error(self, status, reason):
        self.json_reply(status, {"error": {"code": status, "message": "synthetic Drive rejection",
                        "errors": [{"domain": "global", "reason": reason, "message": "synthetic Drive rejection"}]}})

    def payload(self, name):
        state = self.server.state
        if state.mode == "read_denied":
            state.read_denied += 1
            state.events.append(("read_denied", name))
            self.api_error(403, "forbidden")
            return
        super().payload(name)

    def dispatch(self):
        with self.server.state.lock:
            request = self.wire()
            if request is None:
                return
            path, query = request
            state = self.server.state
            match = re.fullmatch(re.escape(API) + r"/(synthetic-root|synthetic-nested|file-180[123])", path)
            media = match is not None and match[1].startswith("file-") and query == {"alt": "media"}
            if (path != API and match is None or self.headers.get("Cookie") is not None
                    or self.headers.get("X-Goog-Drive-Resource-Keys") is not None
                    or self.headers.get("Range") is not None and not media
                    or self.command == "DELETE" and not media):
                self.reject()
                return
            if not hmac.compare_digest(self.headers.get("Authorization", "").encode(),
                                       ("Bearer " + state.password).encode()):
                state.denied += 1
                state.events.append(("credentials_denied", ""))
                self.api_error(401, "authError")
                return
            state.authenticated += 1
            if path == API:
                controls = {"alt": "json", "prettyPrint": "false", "pageSize": "1000",
                            "supportsAllDrives": "true", "includeItemsFromAllDrives": "true",
                            "fields": LIST_FIELDS}
                if set(query) != set(controls) | {"q"} or any(query[key] != value for key, value in controls.items()):
                    self.reject()
                    return
                selection = state.selection(query["q"])
                if selection is None:
                    self.reject()
                    return
                directory, title, kind, paths = selection
                state.events.append(("listing" if not title and kind == "all" else "selection", directory))
                if title and not paths:
                    state.missing += 1
                    state.events.append(("missing", posixpath.join(directory, title)))
                for name in paths:
                    if name in state.files:
                        state.observed.add(name)
                self.json_reply(200, {"kind": "drive#fileList", "incompleteSearch": False,
                                     "files": [state.metadata(name) for name in paths]})
                return
            name = state.names[match[1]]
            if media:
                if name not in state.observed:
                    self.reject()
                elif self.command == "DELETE":
                    self.write_denial(name)
                else:
                    self.payload(name)
                return
            if query != {"alt": "json", "prettyPrint": "false", "supportsAllDrives": "true", "fields": FIELDS}:
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
def serve_drive(root, state):
    certificates, transport = None, None
    try:
        certificates = FixtureCertificates.create(root, server_name=DRIVE_API_NAME)
        transport = BoundedHttpsServer(certificates, DriveHandler, state=state,
                                       limits=TlsLimits(connection_limit=128, active_limit=4,
                                                        request_seconds=3, lifetime_seconds=120))
        transport.start()
        yield certificates, transport
    finally:
        transport_ok = transport is None or transport.close()
        material_ok = certificates is None or certificates.close()
        state.cleanup_complete = transport_ok and material_ok
        if not state.cleanup_complete:
            raise RuntimeError("drive_cleanup_failed")
