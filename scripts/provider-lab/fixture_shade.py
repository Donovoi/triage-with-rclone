"""Shade FS cached-token direct reads; no account token exchange or renewal."""
import hashlib
import hmac

from fixture_read_api import ReadState, ReadHandler, serve_read_api
from fixture_servers import children, is_directory


DRIVE = "synthetic-drive"


class ShadeState(ReadState):
    def __init__(self, token):
        if not token:
            raise ValueError("missing_shade_token")
        super().__init__(token)

    def metadata(self, name):
        directory = is_directory(name, self.files)
        return {"type": "tree" if directory else "file", "path": "/" + name,
                "ino": 100 if not name else 200 if directory else 301 + sorted(self.files).index(name),
                "mtime": 1704067200000, "ctime": 1704067200000,
                "size": 0 if directory else len(self.files[name]), "draft": False,
                "hash": "" if directory else hashlib.md5(self.files[name]).hexdigest()}


class ShadeHandler(ReadHandler):
    def dispatch(self):
        with self.server.state.lock:
            request = self.wire()
            if request is None:
                return
            path, query = request
            state = self.server.state
            prefix = "/" + DRIVE + "/fs/"
            name = query.get("path", "")
            if (set(query) != {"path"} or path not in tuple(prefix + p for p in ("attr", "listdir", "download", "delete"))
                    or name and any(p in ("", ".", "..") for p in name.split("/"))
                    or "\\" in name or "%" in name or any(ord(c) < 32 or ord(c) == 127 for c in name)
                    or self.command != ("POST" if path == prefix + "delete" else "GET")
                    or self.headers.get("Range") is not None):
                self.reject()
                return
            if not hmac.compare_digest(self.headers.get("Authorization", "").encode(), ("Bearer " + state.password).encode()):
                state.denied += 1
                state.events.append(("token_denied", name))
                self.json_reply(401, {"error": "synthetic token denied"})
                return
            state.authenticated += 1
            if path == prefix + "delete":
                self.write_denial(name)
            elif name not in state.files and not is_directory(name, state.files):
                state.missing += 1
                state.events.append(("missing", name))
                self.json_reply(404, {"error": "synthetic path missing"})
            elif path == prefix + "attr":
                state.events.append(("metadata", name))
                self.json_reply(200, state.metadata(name))
            elif path == prefix + "listdir" and is_directory(name, state.files):
                state.events.append(("listing", name))
                self.json_reply(200, [state.metadata(p) for p in children(name, state.files)])
            elif path == prefix + "download" and name in state.files:
                self.payload(name)
            else:
                self.reject()

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch


def serve_shade(state):
    return serve_read_api(state, ShadeHandler)
