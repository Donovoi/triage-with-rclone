"""Independent configured GoFile token and read fixture."""
from contextlib import contextmanager
import hashlib
import hmac
import posixpath
import re
import time
import urllib.parse
from fixture_read_api import ReadState, ReadHandler
from fixture_servers import children
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits, GOFILE_API_NAME

STAMP = 1704067200
ROOT_ID, NESTED_ID = "synthetic-root", "synthetic-nested"

class GoFileState(ReadState):
    def __init__(self, token):
        if not token:
            raise ValueError("missing_gofile_token")
        super().__init__(token)
        self.ids = {name: str(701 + i) for i, name in enumerate(sorted(self.files))}
        self.names = {value: key for key, value in self.ids.items()}
        self.links = set()

    def metadata(self, name):
        return {"id": self.ids[name], "parentFolder": NESTED_ID if "/" in name else ROOT_ID,
                "type": "file", "name": posixpath.basename(name), "size": len(self.files[name]),
                "createTime": STAMP, "modTime": STAMP, "md5": hashlib.md5(self.files[name]).hexdigest(),
                "mimetype": "application/octet-stream", "link": "https://" + GOFILE_API_NAME + "/content/" + self.ids[name]}

    def folder(self, name, selected=None, recursive=False):
        items = {}
        for path in children(name, self.files):
            if selected is not None and posixpath.basename(path) != selected:
                continue
            if path in self.files:
                item = self.metadata(path)
                self.links.add(self.ids[path])
            elif recursive:
                item = self.folder(path)
            else:
                item = {"id": NESTED_ID, "parentFolder": ROOT_ID, "type": "folder", "name": "nested",
                        "createTime": STAMP, "modTime": STAMP, "childrenCount": 2}
            items[item["id"]] = item
        return {"id": ROOT_ID if not name else NESTED_ID, "parentFolder": "" if not name else ROOT_ID,
                "type": "folder", "name": name or "synthetic", "createTime": STAMP, "modTime": STAMP,
                "childrenCount": len(items), "children": items}

class GoFileHandler(ReadHandler):
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
                    or self.headers.get_all("Host") != [GOFILE_API_NAME]
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
            self.json_reply(403, {"status": "error-notAllowed"})
            return
        super().payload(name)

    def dispatch(self):
        with self.server.state.lock:
            request = self.wire()
            if request is None:
                return
            path, query = request
            state = self.server.state
            content = re.fullmatch(r"/content/(70[123])", path)
            item = re.fullmatch(r"/contents/(synthetic-root|synthetic-nested|70[123])", path)
            if (not content and not item or self.command == "DELETE" and not content
                    or self.headers.get("Range") is not None and (not content or self.command != "GET")):
                self.reject()
                return
            if not hmac.compare_digest(self.headers.get("Authorization", "").encode(), ("Bearer " + state.password).encode()):
                state.denied += 1
                state.events.append(("credentials_denied", ""))
                self.json_reply(401, {"status": "error-notAllowed"})
                return
            state.authenticated += 1
            if content:
                if query or content[1] not in state.links:
                    self.reject()
                    return
                if self.command == "DELETE":
                    self.write_denial(state.names[content[1]])
                else:
                    self.payload(state.names[content[1]])
                return
            if (query.get("page") != "1" or not {"page", "pageSize"} <= set(query)
                    or set(query) - {"page", "pageSize", "contentname", "maxdepth"}
                    or "contentname" in query and "maxdepth" in query):
                self.reject()
                return
            identity = item[1]
            if identity in state.names:
                if query != {"page": "1", "pageSize": "1"}:
                    self.reject()
                    return
                name = state.names[identity]
                state.events.append(("metadata", name)); state.links.add(identity)
                result = state.metadata(name)
            else:
                if query["pageSize"] != "1000" or query.get("maxdepth", "4") != "4":
                    self.reject()
                    return
                selected = query.get("contentname")
                if selected is not None and (not re.fullmatch(r"[^/\\]{1,100}", selected) or selected in (".", "..")
                        or any(ord(c) < 32 or ord(c) == 127 for c in selected)):
                    self.reject()
                    return
                name = "" if identity == ROOT_ID else "nested"
                result = state.folder(name, selected, "maxdepth" in query)
                if selected is None:
                    state.events.append(("recursive_listing" if "maxdepth" in query else "listing", name))
                elif not result["children"]:
                    state.missing += 1
                    state.events.append(("missing", posixpath.join(name, selected)))
                else:
                    state.events.append(("lookup", posixpath.join(name, selected)))
            count = len(result.get("children", {}))
            self.json_reply(200, {"status": "ok", "data": result,
                "metadata": {"page": 1, "pageSize": int(query["pageSize"]), "totalCount": count,
                             "totalPages": 1, "hasNextPage": False}})

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch


@contextmanager
def serve_gofile(root, state):
    certificates, transport = None, None
    try:
        certificates = FixtureCertificates.create(root, server_name=GOFILE_API_NAME)
        transport = BoundedHttpsServer(certificates, GoFileHandler, state=state,
                                       limits=TlsLimits(connection_limit=128, active_limit=4,
                                                        request_seconds=3, lifetime_seconds=120))
        transport.start()
        yield certificates, transport
    finally:
        transport_ok = transport is None or transport.close()
        material_ok = certificates is None or certificates.close()
        state.cleanup_complete = transport_ok and material_ok
        if not state.cleanup_complete:
            raise RuntimeError("gofile_cleanup_failed")
