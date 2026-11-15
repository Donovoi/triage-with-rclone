"""Independent SugarSync saved-authorization reads for a configured folder URI."""
from contextlib import contextmanager
import hmac
import re
import time
import urllib.parse
import xml.etree.ElementTree as ET
from fixture_read_api import ReadState, ReadHandler
from fixture_servers import children
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits, SUGARSYNC_API_NAME

ORIGIN = "https://api.sugarsync.com"
ROOT = ORIGIN + "/folder/synthetic-root"
AUTHORIZATION = ORIGIN + "/authorization/"
STAMP = "2024-01-01T00:00:00Z"
FOLDERS = {"":"synthetic-root","nested":"synthetic-nested"}
FILES = {"README-synthetic.txt":"file2601","nested/bytes.bin":"file2602","nested/space name.txt":"file2603"}

def element(parent, name, text):
    ET.SubElement(parent,name).text = str(text)

class SugarsyncState(ReadState):
    def __init__(self, token):
        if not token: raise ValueError("missing_sugarsync_authorization")
        super().__init__(token)
        self.observed = set()

    def metadata(self, name):
        folder = name in FOLDERS
        entry = ET.Element("collection",type="folder") if folder else ET.Element("file")
        ref = ORIGIN + ("/folder/" + FOLDERS[name] if folder else "/file/" + FILES[name])
        for key,value in (("displayName",name.rsplit("/",1)[-1] if name else "synthetic-root"),
                          ("ref",ref),("timeCreated",STAMP)):
            element(entry,key,value)
        if folder:
            element(entry,"contents",ref+"/contents")
        else:
            for key,value in (("dsid",FILES[name]),("parent",ORIGIN+"/folder/"+FOLDERS[name.rpartition("/")[0]]),
                              ("size",len(self.files[name])),("lastModified",STAMP),
                              ("mediaType","application/octet-stream"),("presentOnServer","true"),
                              ("fileData",ref+"/data"),("versions",ref+"/versions")):
                element(entry,key,value)
        return ET.tostring(entry)

    def listing(self, directory):
        names = children(directory,self.files)
        self.observed.update(name for name in names if name in self.files)
        self.events.append(("listing",directory))
        root = ET.Element("collectionContents",start="0",end=str(len(names)-1),hasMore="false")
        for name in names:root.append(ET.fromstring(self.metadata(name)))
        return ET.tostring(root)

class SugarsyncHandler(ReadHandler):
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
                                          max_num_fields=3, encoding="utf-8", errors="strict")
            query = dict(pairs)
            if len(query) != len(pairs):
                raise ValueError("duplicate_query")
            path = urllib.parse.unquote(url.path, encoding="utf-8", errors="strict")
            if urllib.parse.quote(path, safe="/") != url.path:
                raise ValueError("noncanonical_path")
            authority = SUGARSYNC_API_NAME
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
        state = self.server.state
        if state.mode == "read_denied":
            state.read_denied += 1;state.events.append(("read_denied",name))
            # Matching bytes and length cannot mask a missing native status check.
            self.reply(403,state.files[name],{"Content-Type":"application/octet-stream"})
            return
        super().payload(name)

    def dispatch(self):
        with self.server.state.lock:
            request = self.wire()
            if request is None:return
            path,query,_ = request
            state = self.server.state
            if (any(self.headers.get(key) is not None for key in ("Cookie","Content-Type","Accept"))
                    or any(k.lower().startswith("x-sugarsync-") for k in self.headers)):
                self.reject();return
            if not hmac.compare_digest(self.headers.get("Authorization","").encode(),
                                       (AUTHORIZATION+state.password).encode()):
                state.denied += 1;state.events.append(("credentials_denied",""))
                self.reply(401,b"<error>synthetic authorization rejected</error>",{"Content-Type":"application/xml"})
                return
            state.authenticated += 1
            match = re.fullmatch(r"/folder/(synthetic-root|synthetic-nested)/contents",path)
            if match:
                if self.command != "GET" or query != {"max":"500","start":"0"} or self.headers.get("Range") is not None:
                    self.reject();return
                directory=next(name for name,ident in FOLDERS.items() if ident==match[1])
                self.reply(200,state.listing(directory),{"Content-Type":"application/xml"})
                return
            match = re.fullmatch(r"/file/(file260[1-3])/data",path)
            if match is None or query:
                self.reject();return
            name=next(name for name,ident in FILES.items() if ident==match[1])
            if name not in state.observed or self.command=="DELETE" and self.headers.get("Range") is not None:
                self.reject()
            elif self.command=="DELETE":self.write_denial(name)
            else:self.payload(name)

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch

@contextmanager
def serve_sugarsync(root, state):
    certificates, transport = None, None
    try:
        certificates = FixtureCertificates.create(root, server_name=SUGARSYNC_API_NAME)
        transport = BoundedHttpsServer(certificates, SugarsyncHandler, state=state,
                                       limits=TlsLimits(connection_limit=128, active_limit=4,
                                                        request_seconds=3, lifetime_seconds=120))
        transport.start()
        yield certificates, transport
    finally:
        transport_ok = transport is None or transport.close()
        material_ok = certificates is None or certificates.close()
        state.cleanup_complete = transport_ok and material_ok
        if not state.cleanup_complete:
            raise RuntimeError("sugarsync_cleanup_failed")
