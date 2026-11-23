"""Files.com configured API-key reads over an independent loopback API."""
import hashlib
import hmac
import posixpath
import re

from fixture_read_api import ReadState, ReadHandler, serve_read_api
from fixture_servers import children, is_directory


API = "/api/rest/v1"
STAMP = "2024-01-01T00:00:00Z"


class FilesComState(ReadState):
    def __init__(self, token):
        if not token:
            raise ValueError("missing_filescom_key")
        super().__init__(token)
        self.ids = {name: str(301 + i) for i, name in enumerate(sorted(self.files))}
        self.names = {value: key for key, value in self.ids.items()}
        self.links = set()

    def metadata(self, name):
        directory = is_directory(name, self.files)
        return {"path": name, "display_name": posixpath.basename(name),
                "type": "directory" if directory else "file",
                "size": 0 if directory else len(self.files[name]), "mtime": STAMP, "created_at": STAMP,
                "md5": "" if directory else hashlib.md5(self.files[name]).hexdigest(),
                "mime_type": "application/octet-stream"}


class FilesComHandler(ReadHandler):
    def payload(self, name):
        state = self.server.state
        if state.mode == "read_denied":
            state.read_denied += 1
            state.events.append(("read_denied", name))
            self.reply(403, state.files[name], {"Content-Type": "application/octet-stream"}, object_payload=True)
            return
        super().payload(name)

    def error(self, status, kind):
        self.json_reply(status, {"type": kind + "/synthetic", "http-code": status,
                                 "error": "synthetic fixture rejection"})

    def dispatch(self):
        with self.server.state.lock:
            request = self.wire()
            if request is None:
                return
            path, query = request
            state = self.server.state
            content = re.fullmatch(r"/content/(30[123])", path)
            route, name = None, None
            for prefix, kind in ((API + "/folders/", "listing"), (API + "/file_actions/metadata/", "metadata"),
                                 (API + "/files/", "download_link")):
                if path.startswith(prefix):
                    route, name = kind, path[len(prefix):]
                    break
            if path == API + "/folders":
                route, name = "listing", ""
            if (not route and not content or self.command not in ("GET", "DELETE")
                    or self.command == "DELETE" and route != "download_link"
                    or self.headers.get("Range") is not None and not content
                    or self.headers.get("Authorization") is not None
                    or self.headers.get("X-FilesAPI-Auth") is not None
                    or self.headers.get("X-Files-Reauthentication") is not None
                    or self.headers.get("X-Files-Workspace-Id") is not None):
                self.reject()
                return
            expected_query = {"with_direct_connection_info": "true"} if route == "download_link" and self.command == "GET" else {}
            if query != expected_query or name is not None and name and any(p in ("", ".", "..") for p in name.split("/")):
                self.reject()
                return
            if not hmac.compare_digest(self.headers.get("X-FilesAPI-Key", "").encode(), state.password.encode()):
                state.denied += 1
                state.events.append(("key_denied", name or path))
                self.error(401, "not-authenticated")
                return
            state.authenticated += 1
            if content:
                if content[1] not in state.links:
                    self.reject()
                    return
                self.payload(state.names[content[1]])
            elif name not in state.files and not is_directory(name, state.files):
                state.missing += 1
                state.events.append(("missing", name))
                self.error(404, "not-found")
            elif self.command == "DELETE":
                self.write_denial(name)
            elif route == "listing" and is_directory(name, state.files):
                state.events.append(("listing", name))
                self.json_reply(200, [state.metadata(p) for p in children(name, state.files)])
            elif route == "metadata":
                state.events.append(("metadata", name))
                self.json_reply(200, state.metadata(name))
            elif route == "download_link" and name in state.files:
                state.links.add(state.ids[name])
                state.events.append(("download_link", name))
                value = state.metadata(name)
                value["download_uri"] = f"http://127.0.0.1:{self.server.server_address[1]}/content/" + state.ids[name]
                self.json_reply(200, value)
            else:
                self.reject()

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch


def serve_filescom(state):
    return serve_read_api(state, FilesComHandler)
