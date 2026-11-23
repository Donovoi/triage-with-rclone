"""Independent Google Photos app-created album and opaque-content read experiment."""
from contextlib import contextmanager, ExitStack
import hmac
import json
import re
import socket
import time
import urllib.parse
import uuid
from fixture_read_api import ReadState, ReadHandler
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits, GPHOTOS_API_NAME, GPHOTOS_CONTENT_NAME
ADDRESSES = {GPHOTOS_API_NAME: "127.0.0.1", GPHOTOS_CONTENT_NAME: "127.0.0.2"}

def listeners_closed(transports):
    for transport in transports:
        with socket.socket() as probe:
            probe.settimeout(1)
            if probe.connect_ex((ADDRESSES[transport.authority], transport.port)) == 0:
                return False
    return True

ROOT = "album/Synthetic"
ALBUMS = {"": "synthetic-album-root", "nested": "synthetic-album-nested"}
FILES = {"README-synthetic.txt": "synthetic-media-1", "nested/bytes.bin": "synthetic-media-2", "nested/space name.txt": "synthetic-media-3"}
STAMP = "2024-01-01T00:00:00Z"

def unique_pairs(pairs):
    result = {}
    for key,value in pairs:
        if key in result:
            raise ValueError("duplicate_json")
        result[key] = value
    return result

class GphotosState(ReadState):
    def __init__(self, token):
        if not token:
            raise ValueError("missing_gphotos_token")
        super().__init__(token)
        self.observed = set()
        self.album_observed = set()
        self.tokens = {name: uuid.uuid4().hex for name in self.files}
        self.heads = 0
        self.album_lists = 0

    def metadata(self, name):
        return {"id": FILES[name], "filename": name.rsplit("/",1)[-1],
                "productUrl": "https://photos.google.com/photo/"+FILES[name],
                "baseUrl": "https://"+GPHOTOS_CONTENT_NAME+"/synthetic-content/"+FILES[name]+"/"+self.tokens[name],
                "mimeType": "image/jpeg",
                "mediaMetadata": {"creationTime": STAMP, "width":"1", "height":"1", "photo":{}}}

    def albums(self):
        self.album_lists += 1
        self.album_observed.update(ALBUMS.values())
        return {"albums":[{"id":number,"title":"Synthetic"+("/"+name if name else ""),
                           "mediaItemsCount":"2" if name else "1","isWriteable":False}
                          for name,number in ALBUMS.items()], "nextPageToken":""}

    def listing(self, directory):
        names=sorted(name for name in self.files if name.rsplit("/",1)[0]==directory) if directory else ["README-synthetic.txt"]
        self.observed.update(names)
        self.events.append(("listing",directory))
        return {"mediaItems":[self.metadata(name) for name in names],"nextPageToken":""}

class GphotosHandler(ReadHandler):
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
                    or self.headers.get_all("Host") not in ([GPHOTOS_API_NAME], [GPHOTOS_CONTENT_NAME])
                    or self.server.transport._server_name not in (None, self.headers.get("Host"))
                    or len(names) != len(set(names))
                    or sum(len(k) + len(v) for k, v in headers) > 16384
                    or any("\r" in v or "\n" in v for _, v in headers)
                    or self.headers.get("Transfer-Encoding") is not None
                    or re.search(r"%(?![0-9a-fA-F]{2})", self.path)
                    or not re.fullmatch(r"0|[1-9][0-9]{0,3}", length) or int(length) > 4096
                    or self.command not in ("GET", "HEAD", "POST", "DELETE")
                    or self.command != "POST" and length != "0"):
                raise ValueError("invalid_request")
            url = urllib.parse.urlsplit(self.path)
            if url.scheme or url.netloc or url.fragment or "%" in url.path or "//" in url.path or "\\" in url.path:
                raise ValueError("invalid_target")
            pairs = urllib.parse.parse_qsl(url.query, keep_blank_values=True, strict_parsing=True, max_num_fields=6, encoding="utf-8", errors="strict")
            query = dict(pairs)
            if len(query) != len(pairs):
                raise ValueError("duplicate_query")
            body = None
            if self.command == "POST":
                if self.headers.get("Content-Type") != "application/json" or not int(length):
                    raise ValueError("json_body_required")
                raw_body = self.rfile.read(int(length))
                if len(raw_body) != int(length):
                    raise ValueError("incomplete_body")
                body = json.loads(raw_body.decode("utf-8"), object_pairs_hook=unique_pairs,
                                  parse_constant=lambda value: (_ for _ in ()).throw(ValueError("invalid_constant")))
                if not isinstance(body, dict):
                    raise ValueError("object_body_required")
            elif self.headers.get("Content-Type") is not None:
                raise ValueError("unexpected_content_type")
            return url.path, query, body
        except OSError:
            # A timed-out/broken body is no longer an HTTP exchange we can
            # answer. The TLS transport records the deadline and owns cleanup.
            self.close_connection = True
            return None
        except (ValueError, UnicodeError):
            self.reject()
            return None



    def payload(self, name):
        state=self.server.state
        if self.command=="HEAD":
            state.heads+=1
            self.reply(200,state.files[name],{"Content-Type":"image/jpeg"})
            return
        if state.mode=="read_denied":
            state.read_denied+=1;state.events.append(("read_denied",name))
            self.reply(403,state.files[name],{"Content-Type":"application/octet-stream"})
            return
        super().payload(name)

    def dispatch(self):
        with self.server.state.lock:
            request=self.wire()
            if request is None:return
            path,query,body=request;state=self.server.state
            if self.headers.get("Cookie") is not None:self.reject();return
            authority=self.headers.get("Host")
            api=authority==GPHOTOS_API_NAME
            if api:
                if self.headers.get("Range") is not None:self.reject();return
                valid=(self.command=="GET" and path=="/v1/albums" and query=={"pageSize":"50"}
                       or self.command=="POST" and path=="/v1/mediaItems:search" and not query)
                if not valid:self.reject();return
            else:
                match=re.fullmatch(r"/synthetic-content/(synthetic-media-[1-3])/([a-f0-9]{32})=d",path)
                if query or not match or self.command not in ("GET","HEAD","DELETE"):
                    self.reject();return
                if self.headers.get("Range") is not None and self.command!="GET":self.reject();return
                name=next(name for name,number in FILES.items() if number==match[1])
                if name not in state.observed or not hmac.compare_digest(match[2],state.tokens[name]):
                    self.reject();return
            if not hmac.compare_digest(self.headers.get("Authorization","").encode(),("Bearer "+state.password).encode()):
                state.denied+=1;state.events.append(("credentials_denied",""))
                self.json_reply(401,{"error":{"code":401,"status":"UNAUTHENTICATED","message":"synthetic invalid token"}})
                return
            state.authenticated+=1
            if not api:
                if self.command=="DELETE":self.write_denial(name)
                else:self.payload(name)
                return
            if path=="/v1/albums":
                self.json_reply(200,state.albums());return
            if (set(body)!={"albumId","pageSize"} or type(body["pageSize"]) is not int or body["pageSize"]!=100
                    or type(body["albumId"]) is not str or body["albumId"] not in state.album_observed):
                self.reject();return
            directory=next(name for name,number in ALBUMS.items() if number==body["albumId"])
            self.json_reply(200,state.listing(directory))

    do_GET=dispatch
    do_HEAD=dispatch
    do_POST=dispatch
    do_PUT=dispatch
    do_DELETE=dispatch

@contextmanager
def serve_gphotos(root, state):
    certificates, transports = [], []
    try:
        with ExitStack() as stack:
            for authority in (GPHOTOS_API_NAME, GPHOTOS_CONTENT_NAME):
                cert=stack.enter_context(FixtureCertificates.create(root,server_name=authority))
                certificates.append(cert)
                transport=BoundedHttpsServer(cert,GphotosHandler,state=state,
                    limits=TlsLimits(connection_limit=128,active_limit=4,request_seconds=3,lifetime_seconds=120))
                transports.append(transport);stack.callback(transport.close);transport.start()
            yield certificates,transports
    finally:
        state.cleanup_complete=(all(t.cleanup_complete for t in transports) and
                                all(c.cleanup_complete for c in certificates) and listeners_closed(transports))
        if not state.cleanup_complete:raise RuntimeError("gphotos_cleanup_failed")
