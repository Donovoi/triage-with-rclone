"""HiDrive 2.1 saved-bearer reads, independent of OAuth consent or refresh."""
import hmac
import posixpath
import urllib.parse

from fixture_read_api import ReadState, ReadHandler, serve_read_api
from fixture_servers import children, is_directory

METADATA_FIELDS = ("name,type,id,size,mtime,chash", "name,type,id,size,mtime,chash,nmembers")
DIRECTORY_FIELDS = tuple(",".join("members." + field for field in value.split(",")) + ",nmembers"
                         for value in METADATA_FIELDS)


class HiDriveState(ReadState):
    def __init__(self, token):
        if not token:
            raise ValueError("missing_hidrive_token")
        super().__init__(token)


class HiDriveHandler(ReadHandler):
    def metadata(self, name):
        state = self.server.state
        directory = is_directory(name, state.files)
        return {"name": urllib.parse.quote(posixpath.basename(name), safe=""),
                "type": "dir" if directory else "file", "id": "synthetic-" + (name or "root"),
                "size": 0 if directory else len(state.files[name]), "mtime": 1704067200,
                "nmembers": len(children(name, state.files)) if directory else 0, "chash": ""}

    def dispatch(self):
        with self.server.state.lock:
            request = self.wire()
            if request is None:
                return
            path, query = request
            state = self.server.state
            absolute = query.get("path", "")
            name = absolute[1:]
            if (path not in ("/meta", "/dir", "/file") or not absolute.startswith("/")
                    or "\\" in absolute or "%" in absolute or any(ord(c) < 32 or ord(c) == 127 for c in absolute)
                    or name and any(p in ("", ".", "..") for p in name.split("/"))
                    or self.command not in ("GET", "DELETE")
                    or self.command == "DELETE" and (path != "/file" or set(query) != {"path"})
                    or self.headers.get("Range") is not None and (path != "/file" or self.command != "GET")):
                self.reject()
                return
            if self.command == "GET":
                valid = ((path == "/meta" and set(query) == {"path", "fields"}
                          and query["fields"] in ("name,type", *METADATA_FIELDS))
                         or (path == "/dir" and set(query) == {"path", "fields", "members", "sort", "limit"}
                             and query["fields"] in DIRECTORY_FIELDS and query["members"] == "all"
                             and query["sort"] == "none" and query["limit"] == "0,5000")
                         or (path == "/file" and set(query) == {"path"}))
                if not valid:
                    self.reject()
                    return
            expected = ("Bearer " + state.password).encode()
            if not hmac.compare_digest(self.headers.get("Authorization", "").encode(), expected):
                state.denied += 1
                state.events.append(("token_denied", name))
                # No challenge: the saved-token rejection does not claim renewal.
                self.json_reply(401, {"code": 401, "msg": "synthetic token denied"})
                return
            state.authenticated += 1
            if self.command == "DELETE":
                self.write_denial(name)
            elif name not in state.files and not is_directory(name, state.files):
                state.missing += 1
                state.events.append(("missing", name))
                self.json_reply(404, {"code": 404, "msg": "synthetic path missing"})
            elif path == "/meta":
                state.events.append(("metadata", name))
                self.json_reply(200, self.metadata(name))
            elif path == "/dir" and is_directory(name, state.files):
                state.events.append(("listing", name))
                members = [self.metadata(p) for p in children(name, state.files)]
                self.json_reply(200, {"members": members, "nmembers": len(members)})
            elif path == "/file" and name in state.files:
                self.payload(name)
            else:
                self.reject()

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch


def serve_hidrive(state):
    return serve_read_api(state, HiDriveHandler)
