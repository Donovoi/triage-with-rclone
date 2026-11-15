"""ShareFile configured-token API reads; consent and renewal are separate."""
import hashlib
import hmac
import posixpath
import re

from fixture_read_api import ReadState, ReadHandler, serve_read_api
from fixture_servers import children, is_directory


SELECT = "odata.count,FileCount,Name,FileName,CreationDate,IsHidden,FileSizeBytes,odata.type,Id,Hash,ClientModifiedDate"
STAMP = "2024-01-01T00:00:00Z"


class ShareFileState(ReadState):
    def __init__(self, token):
        if not token:
            raise ValueError("missing_sharefile_token")
        super().__init__(token)
        self.ids = {"": "100", "nested": "200"}
        self.ids.update({name: str(301 + i) for i, name in enumerate(sorted(self.files))})
        self.names = {value: key for key, value in self.ids.items()}
        self.links = set()

    def metadata(self, name):
        directory = is_directory(name, self.files)
        return {"FileCount": len(children(name, self.files)) if directory else 0,
                "Name": posixpath.basename(name), "FileName": posixpath.basename(name),
                "CreationDate": STAMP, "ClientModifiedDate": STAMP, "IsHidden": False,
                "FileSizeBytes": 0 if directory else len(self.files[name]),
                "odata.type": "ShareFile.Api.Models." + ("Folder" if directory else "File"),
                "Id": self.ids[name], "Hash": "" if directory else hashlib.md5(self.files[name]).hexdigest()}


class ShareFileHandler(ReadHandler):
    def error(self, status, message):
        self.json_reply(status, {"code": str(status), "reason": "synthetic fixture",
                                 "message": {"lang": "en", "value": message}})

    def dispatch(self):
        with self.server.state.lock:
            request = self.wire()
            if request is None:
                return
            path, query = request
            state = self.server.state
            item = re.fullmatch(r"/sf/v3/Items\((100|200|30[123])\)(/ByPath|/Children|/Download)?", path)
            content = re.fullmatch(r"/content/(30[123])", path)
            if (self.command not in ("GET", "DELETE") or not item and not content
                    or self.command == "DELETE" and (not item or item[2] or query != {"singleversion": "false", "forceSync": "true"})
                    or self.headers.get("Range") is not None and not content):
                self.reject()
                return
            if content:
                valid = self.command == "GET" and not query
            elif self.command == "DELETE":
                valid = item[1] in ("301", "302", "303")
            elif item[2] == "/ByPath":
                valid = set(query) == {"$select", "path"} and query["$select"] == SELECT
            elif item[2] == "/Download":
                valid = query == {"redirect": "false"} and item[1] in ("301", "302", "303")
            else:
                valid = query == {"$select": SELECT}
            if not valid:
                self.reject()
                return
            if not hmac.compare_digest(self.headers.get("Authorization", "").encode(), ("Bearer " + state.password).encode()):
                state.denied += 1
                state.events.append(("token_denied", path))
                self.error(401, "synthetic token denied")
                return
            state.authenticated += 1
            if content:
                if content[1] not in state.links:
                    self.reject()
                    return
                self.payload(state.names[content[1]])
                return
            name = state.names[item[1]]
            if self.command == "DELETE":
                self.write_denial(name)
            elif item[2] == "/ByPath":
                absolute = query["path"]
                relative = absolute[1:]
                if (not absolute.startswith("/") or not relative
                        or any(p in ("", ".", "..") for p in relative.split("/"))
                        or "\\" in relative or "%" in relative or any(ord(c) < 32 or ord(c) == 127 for c in relative)):
                    self.reject()
                    return
                name = posixpath.join(name, relative)
                if name not in state.ids:
                    state.missing += 1
                    state.events.append(("missing", name))
                    self.error(404, "synthetic path missing")
                else:
                    state.events.append(("metadata", name))
                    self.json_reply(200, state.metadata(name))
            elif item[2] == "/Children":
                if not is_directory(name, state.files):
                    self.reject()
                    return
                state.events.append(("listing", name))
                values = [state.metadata(p) for p in children(name, state.files)]
                self.json_reply(200, {"odata.count": len(values), "value": values})
            elif item[2] == "/Download":
                state.links.add(item[1])
                state.events.append(("download_link", name))
                self.json_reply(200, {"DownloadToken": "synthetic-link", "DownloadUrl":
                                     f"http://127.0.0.1:{self.server.server_address[1]}/content/" + item[1]})
            else:
                state.events.append(("metadata", name))
                self.json_reply(200, state.metadata(name))

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch


def serve_sharefile(state):
    return serve_read_api(state, ShareFileHandler)
