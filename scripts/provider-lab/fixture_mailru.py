"""Independent Mail.ru saved-token M1 listing and dispatched content experiment."""
from contextlib import contextmanager, ExitStack
import hashlib
import hmac
import re
import socket
import time
import urllib.parse
import uuid
from fixture_read_api import ReadState, ReadHandler
from fixture_servers import children
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits, MAILRU_API_NAME, MAILRU_DISPATCH_NAME, MAILRU_CONTENT_NAME
ADDRESSES={MAILRU_API_NAME:"127.0.0.1",MAILRU_DISPATCH_NAME:"127.0.0.2",MAILRU_CONTENT_NAME:"127.0.0.3"}
ROOT="Synthetic"
STAMP=1704067200

def mailru_hash(payload):
    return payload.ljust(20,b"\0").hex() if len(payload)<=20 else hashlib.sha1(b"mrCloud"+payload+str(len(payload)).encode("ascii")).hexdigest()

def listeners_closed(transports):
    for transport in transports:
        with socket.socket() as probe:
            probe.settimeout(1)
            if probe.connect_ex((ADDRESSES[transport.authority],transport.port))==0:return False
    return True

class MailruState(ReadState):
    def __init__(self,token):
        if not token:raise ValueError("missing_mailru_token")
        super().__init__(token)
        self.observed=set()
        self.dispatches=0
        self.dispatch_token=uuid.uuid4().hex

    def metadata(self,name):
        folder=name in ("","nested")
        names=children(name,self.files) if folder else []
        return {"kind":"folder" if folder else "file","type":"folder" if folder else "file",
                "name":name.rsplit("/",1)[-1] if name else ROOT,
                "home":"/"+ROOT+("/"+name if name else ""),
                "size":0 if folder else len(self.files[name]),"mtime":STAMP,
                "hash":"" if folder else mailru_hash(self.files[name]),
                "count":{"files":sum(n in self.files for n in names),"folders":sum(n not in self.files for n in names)}}

    def listing(self,directory):
        names=children(directory,self.files)
        self.observed.update(n for n in names if n in self.files)
        self.events.append(("listing",directory))
        return {"status":200,"time":STAMP,"body":dict(self.metadata(directory),list=[self.metadata(n) for n in names])}

class MailruHandler(ReadHandler):
    def wire(self):
        state=self.server.state;state.requests+=1
        if state.requests>state.request_limit or time.monotonic()>state.deadline:
            state.budget_exceeded=True;self.json_reply(429,{"status":429});return None
        headers=list(self.headers.items());names=[k.lower() for k,v in headers]
        try:
            raw=self.raw_requestline.rstrip(b"\r\n").split(b" ")
            length=self.headers.get("Content-Length","0")
            if (len(raw)!=3 or raw[1].decode("ascii")!=self.path or len(self.path)>2048
                    or not self.path.startswith("/") or any(ord(c)<=32 or ord(c)>=127 for c in self.path)
                    or self.headers.get_all("Host") not in ([n] for n in ADDRESSES)
                    or self.server.transport._server_name not in (None,self.headers.get("Host"))
                    or len(names)!=len(set(names)) or sum(len(k)+len(v) for k,v in headers)>16384
                    or any("\r" in v or "\n" in v for k,v in headers)
                    or self.headers.get("Transfer-Encoding") is not None
                    or re.search(r"%(?![0-9a-fA-F]{2})",self.path)
                    or not re.fullmatch(r"0|[1-9][0-9]{0,3}",length) or int(length)>4096
                    or self.command not in ("GET","POST","DELETE")
                    or self.command!="POST" and length!="0"):
                raise ValueError("invalid_request")
            url=urllib.parse.urlsplit(self.path)
            if url.scheme or url.netloc or url.fragment or "//" in url.path or "\\" in url.path:raise ValueError("invalid_target")
            pairs=urllib.parse.parse_qsl(url.query,keep_blank_values=True,strict_parsing=True,max_num_fields=6,encoding="utf-8",errors="strict")
            query=dict(pairs)
            if len(query)!=len(pairs):raise ValueError("duplicate_query")
            body=None
            if self.command=="POST":
                if self.headers.get("Content-Type")!="application/x-www-form-urlencoded" or not int(length):raise ValueError("form_required")
                data=self.rfile.read(int(length))
                if len(data)!=int(length) or re.search(rb"%(?![0-9a-fA-F]{2})",data):raise ValueError("invalid_body")
                pairs=urllib.parse.parse_qsl(data.decode("ascii"),keep_blank_values=True,strict_parsing=True,max_num_fields=2,encoding="utf-8",errors="strict")
                body=dict(pairs)
                if len(body)!=len(pairs):raise ValueError("duplicate_form")
            return url.path,query,body
        except OSError:
            self.close_connection=True;return None
        except (ValueError,UnicodeError):
            self.reject();return None

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
            path,query,body=request;state=self.server.state
            authority=self.headers.get("Host")
            if self.headers.get("Authorization") is not None or self.headers.get("Cookie") is not None:self.reject();return
            if authority==MAILRU_DISPATCH_NAME:
                if self.command!="GET" or path!="/d" or query or self.headers.get("Range") is not None:
                    self.reject();return
                state.dispatches+=1
                self.reply(200,("https://"+MAILRU_CONTENT_NAME+"/"+state.dispatch_token+"/\n").encode(),{"Content-Type":"text/plain"});return
            token_key="access_token" if authority==MAILRU_API_NAME else "token"
            if not hmac.compare_digest(query.get(token_key,"").encode(),state.password.encode()):
                state.denied+=1;state.events.append(("credentials_denied",""))
                self.json_reply(401,{"status":401,"body":{"home":{"error":"synthetic invalid token"}}});return
            state.authenticated+=1
            if authority==MAILRU_CONTENT_NAME:
                name=next((n for n in state.files if path=="/"+state.dispatch_token+"/"+urllib.parse.quote(ROOT+"/"+n,safe="")),None)
                if (name is None or name not in state.observed or not state.dispatches
                        or query!={"client_id":"cloud-win","token":state.password}
                        or self.command not in ("GET","DELETE")
                        or self.headers.get("Range") is not None and self.command!="GET"):
                    self.reject();return
                if self.command=="DELETE":self.write_denial(name)
                else:self.payload(name)
                return
            if self.headers.get("Range") is not None:self.reject();return
            fixed={"access_token":state.password,"offset":"0","limit":"2147483647"}
            if self.command=="POST" and path=="/api/m1/folder" and query==fixed and body is not None and set(body)=={"home"}:
                directory=next((n for n in ("","nested") if body["home"]=="/"+ROOT+("/"+n if n else "")),None)
                if directory is None:self.json_reply(404,{"status":404,"body":{"home":{"error":"not exists"}}})
                else:self.json_reply(200,state.listing(directory))
                return
            if self.command=="GET" and path=="/api/m1/file" and set(query)==set(fixed)|{"home"} and all(query[k]==v for k,v in fixed.items()):
                name=next((n for n in ("","nested",*state.files) if query["home"] in (ROOT+("/"+n if n else ""), "/"+ROOT+("/"+n if n else ""))),None)
                if name is None:self.json_reply(404,{"status":404,"body":{"home":{"error":"not exists"}}})
                else:
                    if name in state.files:state.observed.add(name)
                    self.json_reply(200,{"status":200,"time":STAMP,"body":state.metadata(name)})
                return
            self.reject()

    do_GET=dispatch
    do_HEAD=dispatch
    do_POST=dispatch
    do_PUT=dispatch
    do_DELETE=dispatch

@contextmanager
def serve_mailru(root,state):
    certificates,transports=[],[]
    try:
        with ExitStack() as stack:
            for authority in ADDRESSES:
                cert=stack.enter_context(FixtureCertificates.create(root,server_name=authority));certificates.append(cert)
                transport=BoundedHttpsServer(cert,MailruHandler,state=state,
                    limits=TlsLimits(connection_limit=128,active_limit=4,request_seconds=3,lifetime_seconds=120))
                transports.append(transport);stack.callback(transport.close);transport.start()
            yield certificates,transports
    finally:
        state.cleanup_complete=all(t.cleanup_complete for t in transports) and all(c.cleanup_complete for c in certificates) and listeners_closed(transports)
        if not state.cleanup_complete:raise RuntimeError("mailru_cleanup_failed")
