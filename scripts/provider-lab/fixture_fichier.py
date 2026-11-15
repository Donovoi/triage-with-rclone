"""Independent configured 1Fichier key and single-use download fixture."""
from contextlib import contextmanager
import hmac
import json
import posixpath
import re
import time
import urllib.parse
import uuid
from fixture_read_api import ReadState, ReadHandler
from fixture_servers import children
from fixture_quatrix import unique_object
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits, FICHIER_API_NAME

STAMP = "2024-01-01 00:00:00"
WHIRLPOOL = {'README-synthetic.txt': '561d86d9772f31565be9f3ba2e103538d808d59dd548e8b0f493d886a50e4b93da58e1d267196a493c1b0c34f92cf5928529d8e0e8ae66be86a59aa7368ee5f9', 'nested/bytes.bin': '6aeaa024635a881dc2d97e1c5d25f4158fef3172d239fe80dcef01536e576f25565bbf17f71737f6de6d128bf9d91cf88e6226e152373be1c4ccb6a3e30465fd', 'nested/space name.txt': '563f21e95574757d38075169f3a0164545d1a1f714819a689be532d81986d6bfe8a60f1777e64ff9e2c6255d3dfd76386ea107fb61ac59875635a8d06e5b6a55'}

class FichierState(ReadState):
    def __init__(self, token):
        if not token:
            raise ValueError("missing_fichier_key")
        super().__init__(token)
        self.ids = {name: 901 + i for i, name in enumerate(sorted(self.files))}
        self.references = {"https://1fichier.com/?synthetic" + str(identity): name for name, identity in self.ids.items()}
        self.listed = set()
        self.tokens = {}
        self.replayed = 0

    def metadata(self, name):
        return {"cdn": 0, "pass": 0, "checksum": WHIRLPOOL[name],
                "content-type": "application/octet-stream", "date": STAMP,
                "filename": posixpath.basename(name), "size": len(self.files[name]),
                "url": "https://1fichier.com/?synthetic" + str(self.ids[name])}

    def files_in(self, name):
        items = []
        for path in children(name, self.files):
            if path in self.files:
                items.append(self.metadata(path))
                self.listed.add(path)
        return items

class FichierHandler(ReadHandler):
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
                    or self.headers.get_all("Host") != [FICHIER_API_NAME]
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


    def payload(self, name):
        state = self.server.state
        if state.mode == "read_denied":
            state.read_denied += 1
            state.events.append(("read_denied", name))
            self.json_reply(403, {"status": "KO", "message": "synthetic read denied"})
            return
        super().payload(name)

    def dispatch(self):
        with self.server.state.lock:
            request = self.wire()
            if request is None:
                return
            path, query, data = request
            state = self.server.state
            content = re.fullmatch(r"/download/([a-f0-9]{32})", path)
            api = path in ("/v1/file/ls.cgi", "/v1/folder/ls.cgi", "/v1/file/info.cgi",
                           "/v1/download/get_token.cgi", "/v1/file/rm.cgi")
            if (query or not content and not api or content and self.command != "GET"
                    or api and self.command != "POST" or self.headers.get("Range") is not None and not content):
                self.reject()
                return
            if not hmac.compare_digest(self.headers.get("Authorization", "").encode(), ("Bearer " + state.password).encode()):
                state.denied += 1
                state.events.append(("credentials_denied", ""))
                self.json_reply(401, {"status": "KO", "message": "synthetic invalid key"})
                return
            state.authenticated += 1
            if content:
                token = content[1]
                if token not in state.tokens or state.tokens[token][1]:
                    state.replayed += 1
                    state.events.append(("link_denied", ""))
                    self.json_reply(401, {"status": "KO", "message": "synthetic invalid download link"})
                    return
                name, _ = state.tokens[token]
                state.tokens[token] = (name, True)
                self.payload(name)
                return
            if path in ("/v1/file/ls.cgi", "/v1/folder/ls.cgi"):
                if set(data) != {"folder_id"} or type(data["folder_id"]) is not int or data["folder_id"] not in (0, 10):
                    self.reject()
                    return
                name = "" if data["folder_id"] == 0 else "nested"
                if path == "/v1/file/ls.cgi":
                    state.events.append(("listing", name))
                    self.json_reply(200, {"Status": "OK", "items": state.files_in(name)})
                else:
                    state.events.append(("folder_listing", name))
                    folders = [{"id": 10, "name": "nested", "create_date": STAMP, "pass": 0}] if not name else []
                    self.json_reply(200, {"Status": "OK", "folder_id": data["folder_id"],
                                         "name": name or "synthetic", "sub_folders": folders})
                return
            if path == "/v1/file/rm.cgi":
                if (set(data) != {"files"} or type(data["files"]) is not list or len(data["files"]) != 1
                        or type(data["files"][0]) is not dict or set(data["files"][0]) != {"url"}):
                    self.reject()
                    return
                url = data["files"][0]["url"]
            else:
                wanted = {"url", "single"} if path == "/v1/download/get_token.cgi" else {"url"}
                if set(data) != wanted or "single" in data and (type(data["single"]) is not int or data["single"] != 1):
                    self.reject()
                    return
                url = data["url"]
            if type(url) is not str or url not in state.references or state.references[url] not in state.listed:
                self.reject()
                return
            name = state.references[url]
            if path == "/v1/file/rm.cgi":
                self.write_denial(name)
            elif path == "/v1/file/info.cgi":
                state.events.append(("metadata", name))
                self.json_reply(200, state.metadata(name))
            else:
                token = uuid.uuid4().hex
                state.tokens[token] = (name, False)
                state.events.append(("download_token", name))
                self.json_reply(200, {"Status": "OK", "url": "https://" + FICHIER_API_NAME + "/download/" + token})

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch


@contextmanager
def serve_fichier(root, state):
    certificates, transport = None, None
    try:
        certificates = FixtureCertificates.create(root, server_name=FICHIER_API_NAME)
        transport = BoundedHttpsServer(certificates, FichierHandler, state=state,
                                       limits=TlsLimits(connection_limit=128, active_limit=4,
                                                        request_seconds=3, lifetime_seconds=120))
        transport.start()
        yield certificates, transport
    finally:
        transport_ok = transport is None or transport.close()
        material_ok = certificates is None or certificates.close()
        state.cleanup_complete = transport_ok and material_ok
        if not state.cleanup_complete:
            raise RuntimeError("fichier_cleanup_failed")
