"""Unqualified PikPak saved-token experiment, including strict HTTP status rejection."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import re
import time
import urllib.parse
from fixture_read_api import ReadState, ReadHandler
from fixture_servers import children
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits, PIKPAK_API_NAME

ORIGIN = "https://api-drive.mypikpak.com"
ROOT = "synthetic-root"
DEVICE = "1" * 32
CAPTCHA = "synthetic-unused-captcha"
STAMP = "2024-01-01T00:00:00Z"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0"
FOLDERS = {"":ROOT,"nested":"synthetic-nested"}
FILES = {"README-synthetic.txt":"file2701","nested/bytes.bin":"file2702","nested/space name.txt":"file2703"}
API_HEADERS = {"Referer":"https://mypikpak.com/","X-Client-Id":"YUMx5nI8ZU8Ap8pm",
               "X-Client-Version":"2.0.0","X-Device-Id":DEVICE,"X-Captcha-Token":CAPTCHA}

def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError("duplicate_json")
        result[key]=value
    return result

class PikpakState(ReadState):
    def __init__(self, token):
        if not token:raise ValueError("missing_pikpak_token")
        super().__init__(token)
        self.observed=set();self.links=set()
        self.expiry=(datetime.now(timezone.utc)+timedelta(hours=2)).isoformat().replace("+00:00","Z")

    def metadata(self, name, link=False):
        folder=name in FOLDERS
        parent=FOLDERS[name.rpartition("/")[0]] if name else ""
        result={"kind":"drive#folder" if folder else "drive#file","id":FOLDERS[name] if folder else FILES[name],
                "parent_id":parent,"name":name.rsplit("/",1)[-1] if name else ROOT,
                "size":"0" if folder else str(len(self.files[name])),"created_time":STAMP,"modified_time":STAMP,
                "phase":"PHASE_TYPE_COMPLETE","trashed":False,"links":{}}
        if not folder:
            result.update(md5_checksum=hashlib.md5(self.files[name]).hexdigest(),mime_type="application/octet-stream")
            if link:
                result["links"]={"application/octet-stream":{"url":ORIGIN+"/synthetic-content/"+FILES[name],
                    "token":"synthetic-download-token","expire":self.expiry}}
        return result

    def listing(self, directory, kind):
        names=[name for name in children(directory,self.files) if not kind or
               ("drive#folder" if name in FOLDERS else "drive#file")==kind]
        self.observed.update(name for name in names if name in self.files)
        self.events.append(("listing",directory))
        return {"kind":"drive#fileList","files":[self.metadata(name) for name in names],
                "next_page_token":"","sync_time":STAMP}

class PikpakHandler(ReadHandler):
    def wire(self):
        state = self.server.state
        state.requests += 1
        if state.requests > state.request_limit or time.monotonic() > state.deadline:
            state.budget_exceeded = True
            self.json_reply(429, {"errors": [{"id": "synthetic", "title": "synthetic request limit"}]})
            return None
        headers = list(self.headers.items())
        names = [key.lower() for key, _ in headers]
        try:
            raw = self.raw_requestline.rstrip(b"\r\n").split(b" ")
            if (len(raw) != 3 or raw[1].decode("ascii") != self.path or len(self.path) > 2048
                    or not self.path.startswith("/") or any(ord(c) <= 32 or ord(c) >= 127 for c in self.path)
                    or len(names) != len(set(names)) or sum(len(k) + len(v) for k,v in headers) > 16384
                    or any("\r" in v or "\n" in v for _,v in headers)
                    or self.headers.get("Transfer-Encoding") is not None
                    or self.headers.get("Content-Length", "0") != "0"
                    or re.search(r"%(?![0-9a-fA-F]{2})", self.path)
                    or self.command not in ("GET", "DELETE")):
                raise ValueError("invalid_request")
            url = urllib.parse.urlsplit(self.path)
            if url.scheme or url.netloc or url.fragment or "//" in url.path:
                raise ValueError("invalid_target")
            pairs = urllib.parse.parse_qsl(url.query, keep_blank_values=True, strict_parsing=True,
                                          max_num_fields=8, encoding="utf-8", errors="strict")
            query = dict(pairs)
            if len(query) != len(pairs):
                raise ValueError("duplicate_query")
            path = urllib.parse.unquote(url.path, encoding="utf-8", errors="strict")
            if urllib.parse.quote(path, safe="/") != url.path:
                raise ValueError("noncanonical_path")
            authority = PIKPAK_API_NAME
            # Ephemeral wire tests use an unnamed transport; native named transports
            # must match both the route authority and the exact Host.
            if (authority is None or self.headers.get_all("Host") != [authority]
                    or self.server.transport._server_name not in (None, authority)):
                raise ValueError("wrong_authority")
            return path, query, authority
        except (ValueError, UnicodeError):
            self.reject()
            return None

    def payload(self, name):
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
            path,query,_=request;state=self.server.state
            if (any(self.headers.get(k) is not None for k in ("Cookie","Content-Type","Accept"))
                    or self.headers.get("User-Agent") != UA):
                self.reject();return
            if not hmac.compare_digest(self.headers.get("Authorization","").encode(),("Bearer "+state.password).encode()):
                state.denied+=1;state.events.append(("credentials_denied",""))
                self.json_reply(401,{"error":"unauthenticated","error_code":16});return
            state.authenticated+=1
            if path.startswith("/drive/v1/"):
                if self.command!="GET" or self.headers.get("Range") is not None or any(self.headers.get(k)!=v for k,v in API_HEADERS.items()):
                    self.reject();return
                allowed={k.lower() for k in API_HEADERS}
                if any(k.lower().startswith("x-") and k.lower() not in allowed for k in self.headers):
                    self.reject();return
                if path=="/drive/v1/files":
                    if (set(query)!={"thumbnail_size","limit","with_audit","parent_id","page_token","filters"}
                            or query["thumbnail_size"]!="SIZE_MEDIUM" or query["limit"]!="500"
                            or query["with_audit"]!="true" or query["page_token"]!=""
                            or query["parent_id"] not in FOLDERS.values()):
                        self.reject();return
                    try:
                        filters=json.loads(query["filters"],object_pairs_hook=unique)
                        kind=filters.get("kind",{}).get("eq","")
                        expected={"phase":{"eq":"PHASE_TYPE_COMPLETE"},"trashed":{"eq":False}}
                        if kind:
                            if kind not in ("drive#file","drive#folder"):raise ValueError("bad_kind")
                            expected["kind"]={"eq":kind}
                        if json.dumps(filters,sort_keys=True)!=json.dumps(expected,sort_keys=True):raise ValueError("bad_filters")
                    except (ValueError,TypeError,AttributeError):
                        self.reject();return
                    directory=next(name for name,ident in FOLDERS.items() if ident==query["parent_id"])
                    self.json_reply(200,state.listing(directory,kind));return
                match=re.fullmatch(r"/drive/v1/files/(file270[1-3])",path)
                if match is None or query:self.reject();return
                name=next(name for name,ident in FILES.items() if ident==match[1])
                if name not in state.observed:self.reject();return
                state.links.add(name);state.events.append(("metadata",name))
                self.json_reply(200,state.metadata(name,link=True));return
            if any(self.headers.get(k) is not None for k in API_HEADERS):
                self.reject();return
            match=re.fullmatch(r"/synthetic-content/(file270[1-3])",path)
            if match is None or query:self.reject();return
            name=next(name for name,ident in FILES.items() if ident==match[1])
            if name not in state.links or self.command=="DELETE" and self.headers.get("Range") is not None:self.reject()
            elif self.command=="DELETE":self.write_denial(name)
            else:self.payload(name)

    do_GET=dispatch
    do_HEAD=dispatch
    do_POST=dispatch
    do_PUT=dispatch
    do_DELETE=dispatch

@contextmanager
def serve_pikpak(root, state):
    certificates, transport = None, None
    try:
        certificates = FixtureCertificates.create(root, server_name=PIKPAK_API_NAME)
        transport = BoundedHttpsServer(certificates, PikpakHandler, state=state,
                                       limits=TlsLimits(connection_limit=128, active_limit=4,
                                                        request_seconds=3, lifetime_seconds=120))
        transport.start()
        yield certificates, transport
    finally:
        transport_ok = transport is None or transport.close()
        material_ok = certificates is None or certificates.close()
        state.cleanup_complete = transport_ok and material_ok
        if not state.cleanup_complete:
            raise RuntimeError("pikpak_cleanup_failed")
