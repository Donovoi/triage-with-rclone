"""Independent iCloud Drive saved-cookie synthetic read experiment."""
from contextlib import contextmanager, ExitStack
import json
import re
import socket
import time
import urllib.parse
import uuid
from fixture_read_api import ReadState, ReadHandler
from fixture_servers import children
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits
SETUP="setup.icloud.com"
DRIVE="synthetic-drive.icloud.invalid"
DOCS="synthetic-docs.icloud.invalid"
CONTENT="synthetic-content.icloud.invalid"
ADDRESSES={SETUP:"127.0.0.1",DRIVE:"127.0.0.2",DOCS:"127.0.0.3",CONTENT:"127.0.0.4"}
ZONE="com.apple.CloudDocs"
ROOT="FOLDER::"+ZONE+"::root"
FOLDERS={"":ROOT,"nested":"FOLDER::"+ZONE+"::synthetic-3510"}
FILES={"README-synthetic.txt":"synthetic-3501","nested/bytes.bin":"synthetic-3502","nested/space name.txt":"synthetic-3503"}
STAMP="2024-01-01T00:00:00Z"

def unique_pairs(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError("duplicate_json")
        result[key]=value
    return result

def listeners_closed(transports):
    for transport in transports:
        with socket.socket() as probe:
            probe.settimeout(1)
            if probe.connect_ex((ADDRESSES[transport.authority],transport.port))==0:return False
    return True

class IclouddriveState(ReadState):
    def __init__(self,cookie):
        super().__init__(cookie)
        self.validations=0
        self.observed=set()
        self.links={}

    def metadata(self,name):
        folder=name in FOLDERS
        basename=name.rsplit("/",1)[-1] if name else "Synthetic"
        stem,sep,extension=basename.rpartition(".") if not folder else (basename,"","")
        return {"drivewsid":FOLDERS[name] if folder else "FILE::"+ZONE+"::"+FILES[name],
                "docwsid":"" if folder else FILES[name],"item_id":FOLDERS[name] if folder else FILES[name],
                "zone":ZONE,"name":stem if sep else basename,"extension":extension if sep else "",
                "type":"FOLDER" if folder else "FILE","status":"OK","etag":"synthetic-etag-3500",
                "dateCreated":STAMP,"dateModified":STAMP,"dateChanged":STAMP,
                "size":0 if folder else len(self.files[name]),
                "parentId":FOLDERS["nested"] if "/" in name else ROOT}

    def listing(self,directory):
        names=children(directory,self.files)
        self.observed.update(n for n in names if n in self.files)
        self.events.append(("listing",directory))
        item=self.metadata(directory)
        item.update(items=[self.metadata(n) for n in names],numberOfItems=len(names),
                    directChildrenCount=len(names),fileCount=sum(n in self.files for n in names))
        return [item]

class IclouddriveHandler(ReadHandler):
    def wire(self):
        state=self.server.state
        state.requests+=1
        if state.requests>state.request_limit or time.monotonic()>state.deadline:
            state.budget_exceeded=True
            self.json_reply(429,{"error":"synthetic request limit"})
            return None
        try:
            headers=list(self.headers.items());names=[k.lower() for k,v in headers]
            raw=self.raw_requestline.rstrip(b"\r\n").split(b" ")
            length=self.headers.get("Content-Length","0")
            if (len(raw)!=3 or raw[1].decode("ascii")!=self.path or len(self.path)>2048
                    or not self.path.startswith("/") or any(ord(c)<=32 or ord(c)>=127 for c in self.path)
                    or self.headers.get_all("Host") not in ([x] for x in ADDRESSES)
                    or self.server.transport._server_name not in (None,self.headers.get("Host"))
                    or len(names)!=len(set(names)) or sum(len(k)+len(v) for k,v in headers)>16384
                    or any("\r" in v or "\n" in v for _,v in headers)
                    or self.headers.get("Transfer-Encoding") is not None
                    or not re.fullmatch(r"0|[1-9][0-9]{0,3}",length) or int(length)>4096
                    or self.command not in ("GET","POST","DELETE")
                    or self.headers.get("Content-Type")!="application/json"
                    or self.headers.get("Origin")!="https://www.icloud.com"
                    or self.headers.get("Referer")!="https://www.icloud.com/"):
                raise ValueError("invalid_request")
            url=urllib.parse.urlsplit(self.path)
            if url.scheme or url.netloc or url.fragment or "%" in url.path or "//" in url.path or "\\" in url.path:
                raise ValueError("invalid_target")
            pairs=urllib.parse.parse_qsl(url.query,keep_blank_values=True,strict_parsing=True,max_num_fields=4,encoding="utf-8",errors="strict")
            query=dict(pairs)
            if len(query)!=len(pairs):raise ValueError("duplicate_query")
            raw_body=self.rfile.read(int(length))
            if len(raw_body)!=int(length):raise ValueError("incomplete_body")
            body=None
            if raw_body:
                body=json.loads(raw_body.decode("utf-8"),object_pairs_hook=unique_pairs,
                                parse_constant=lambda value:(_ for _ in ()).throw(ValueError("invalid_constant")))
            return url.path,query,body,raw_body
        except OSError:
            self.close_connection=True
            return None
        except (ValueError,UnicodeError):
            self.reject()
            return None

    def payload(self,name):
        state=self.server.state
        if state.mode=="read_denied":
            state.read_denied+=1;state.events.append(("read_denied",name))
            self.reply(403,state.files[name],{"Content-Type":"application/octet-stream"});return
        super().payload(name)

    def dispatch(self):
        with self.server.state.lock:
            request=self.wire()
            if request is None:return
            path,query,body,raw=request;state=self.server.state;host=self.headers["Host"]
            if self.headers.get("Authorization") is not None:self.reject();return
            if self.headers.get("Cookie")!=state.password:
                state.denied+=1;state.events.append(("cookie_denied",host))
                self.json_reply(403,{"error":"synthetic invalid cookie"});return
            state.authenticated+=1
            if host==SETUP and path=="/setup/ws/1/validate" and self.command=="POST":
                if query or raw or self.headers.get("Range") is not None:self.reject();return
                state.validations+=1
                self.json_reply(200,{"dsInfo":{"hsaVersion":2},"hsaChallengeRequired":False,
                    "webservices":{"drivews":{"url":"https://"+DRIVE,"status":"active","pcsRequired":False},
                                   "docws":{"url":"https://"+DOCS,"status":"active","pcsRequired":False}}});return
            if not state.validations:self.reject();return
            if host==DRIVE and path=="/retrieveItemDetailsInFolders" and self.command=="POST":
                if query or self.headers.get("Range") is not None or type(body) is not list or len(body)!=1 or type(body[0]) is not dict:
                    self.reject();return
                item=body[0]
                if (set(item)!={"drivewsid","partialData","includeHierarchy"} or item["partialData"] is not False
                        or item["includeHierarchy"] is not False or item["drivewsid"] not in FOLDERS.values()):
                    self.reject();return
                directory=next(n for n,id in FOLDERS.items() if id==item["drivewsid"])
                self.json_reply(200,state.listing(directory));return
            if host==DOCS and path=="/ws/"+ZONE+"/download/by_id" and self.command=="GET":
                if set(query)!={"document_id"} or raw!=b"null" or self.headers.get("Range") is not None:self.reject();return
                name=next((n for n,id in FILES.items() if id==query["document_id"]),None)
                if name not in state.observed:self.reject();return
                nonce=uuid.uuid4().hex;state.links[nonce]=name
                self.json_reply(200,{"document_id":FILES[name],"item_id":FILES[name],
                    "data_token":{"url":"https://"+CONTENT+"/synthetic-content/"+FILES[name]+"/"+nonce}});return
            match=re.fullmatch(r"/synthetic-content/(synthetic-350[1-3])/([a-f0-9]{32})",path)
            if host==CONTENT and match and self.command in ("GET","DELETE"):
                name=state.links.get(match[2])
                if name is None or FILES[name]!=match[1] or query or raw:self.reject();return
                if self.command=="DELETE":
                    if self.headers.get("Range") is not None:self.reject();return
                    self.write_denial(name);return
                self.payload(name);return
            self.reject()

    do_GET=dispatch
    do_HEAD=dispatch
    do_POST=dispatch
    do_PUT=dispatch
    do_DELETE=dispatch

@contextmanager
def serve_iclouddrive(root,state):
    certificates,transports=[],[]
    try:
        with ExitStack() as stack:
            for authority in ADDRESSES:
                cert=stack.enter_context(FixtureCertificates.create(root,server_name=authority));certificates.append(cert)
                transport=BoundedHttpsServer(cert,IclouddriveHandler,state=state,
                    limits=TlsLimits(connection_limit=128,active_limit=4,request_seconds=3,lifetime_seconds=120))
                transports.append(transport);stack.callback(transport.close);transport.start()
            yield certificates,transports
    finally:
        state.cleanup_complete=all(t.cleanup_complete for t in transports) and all(c.cleanup_complete for c in certificates) and listeners_closed(transports)
        if not state.cleanup_complete:raise RuntimeError("iclouddrive_cleanup_failed")
