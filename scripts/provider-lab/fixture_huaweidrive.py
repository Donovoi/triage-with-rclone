"""Independent Huawei Drive saved-token global-domain folder read experiment."""
from contextlib import contextmanager
import hashlib
import hmac
import re
import time
import urllib.parse
from fixture_read_api import ReadState, ReadHandler
from fixture_servers import children
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits, HUAWEIDRIVE_API_NAME

ROOT="synthetic-folder-3200"
FOLDERS={"":ROOT,"nested":"synthetic-folder-3210"}
FILES={"README-synthetic.txt":"synthetic-file-3201","nested/bytes.bin":"synthetic-file-3202","nested/space name.txt":"synthetic-file-3203"}
STAMP="2024-01-01T00:00:00Z"
FOLDER_MIME="application/vnd.huawei-apps.folder"

class HuaweidriveState(ReadState):
    def __init__(self, token):
        if not token:raise ValueError("missing_huaweidrive_token")
        super().__init__(token)
        self.observed=set()
        self.about_reads=0

    def metadata(self,name):
        folder=name in FOLDERS
        return {"id":FOLDERS[name] if folder else FILES[name],"fileName":name.rsplit("/",1)[-1],
                "mimeType":FOLDER_MIME if folder else "application/octet-stream","category":"drive#file",
                "size":0 if folder else len(self.files[name]),
                "sha256":"" if folder else hashlib.sha256(self.files[name]).hexdigest(),
                "createdTime":STAMP,"editedTime":STAMP,"editedByMeTime":STAMP,
                "parentFolder":[FOLDERS["nested"] if "/" in name else ROOT],
                "recycled":False,"directlyRecycled":False,"containers":["drive"]}

    def listing(self,directory):
        names=children(directory,self.files)
        self.observed.update(name for name in names if name in self.files)
        self.events.append(("listing",directory))
        return {"category":"drive#fileList","files":[self.metadata(name) for name in names],"nextPageToken":""}

class HuaweidriveHandler(ReadHandler):
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
                    or self.headers.get_all("Host") != [HUAWEIDRIVE_API_NAME]
                    or self.server.transport._server_name not in (None, HUAWEIDRIVE_API_NAME)
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
            pairs = urllib.parse.parse_qsl(url.query, keep_blank_values=True, strict_parsing=True, max_num_fields=6, encoding="utf-8", errors="strict")
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



    def payload(self,name):
        state=self.server.state
        if state.mode=="read_denied":
            state.read_denied+=1;state.events.append(("read_denied",name))
            self.reply(403,state.files[name],{"Content-Type":"application/octet-stream"})
            return
        super().payload(name)

    def dispatch(self):
        with self.server.state.lock:
            request=self.wire()
            if request is None:return
            path,query=request;state=self.server.state
            if self.headers.get("Cookie") is not None:self.reject();return
            download=path.startswith("/drive/v1/files/") and path.removeprefix("/drive/v1/files/") in FILES.values()
            if (not download and path not in ("/drive/v1/about","/drive/v1/files")
                    or self.command=="DELETE" and not download
                    or self.headers.get("Range") is not None and (not download or self.command!="GET")):
                self.reject();return
            if not hmac.compare_digest(self.headers.get("Authorization","").encode(),("Bearer "+state.password).encode()):
                state.denied+=1;state.events.append(("credentials_denied",""))
                self.json_reply(401,{"error":{"code":401,"message":"synthetic invalid bearer"}});return
            state.authenticated+=1
            if download:
                name=next(name for name,ident in FILES.items() if ident==path.removeprefix("/drive/v1/files/"))
                if query!={"form":"content"} or name not in state.observed:self.reject()
                elif self.command=="DELETE":self.write_denial(name)
                else:self.payload(name)
                return
            if path=="/drive/v1/about":
                if query!={"fields":"domain"}:self.reject();return
                state.about_reads+=1
                self.json_reply(200,{"domain":HUAWEIDRIVE_API_NAME});return
            directory=next((name for name,ident in FOLDERS.items()
                            if query.get("queryParam")==("'"+ident+"' in parentFolder")),None)
            if directory is None or query!={"fields":"*","containers":"drive","pageSize":"1000",
                                           "queryParam":"'"+FOLDERS[directory]+"' in parentFolder"}:
                self.reject();return
            self.json_reply(200,state.listing(directory))

    do_GET=dispatch
    do_HEAD=dispatch
    do_POST=dispatch
    do_PUT=dispatch
    do_DELETE=dispatch

@contextmanager
def serve_huaweidrive(root,state):
    certificates,transport=None,None
    try:
        certificates=FixtureCertificates.create(root,server_name=HUAWEIDRIVE_API_NAME)
        transport=BoundedHttpsServer(certificates,HuaweidriveHandler,state=state,
             limits=TlsLimits(connection_limit=128,active_limit=4,request_seconds=3,lifetime_seconds=120))
        transport.start()
        yield certificates,transport
    finally:
        transport_ok=transport is None or transport.close()
        material_ok=certificates is None or certificates.close()
        state.cleanup_complete=transport_ok and material_ok
        if not state.cleanup_complete:raise RuntimeError("huaweidrive_cleanup_failed")
