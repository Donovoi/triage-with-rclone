"""Independent Uloz.to synthetic password/session and folder read experiment."""
from contextlib import contextmanager, ExitStack
import hmac
import json
import re
import socket
import time
import urllib.parse
import uuid
from fixture_read_api import ReadState, ReadHandler
from fixture_servers import children
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits, ULOZTO_API_NAME, ULOZTO_CONTENT_NAME
ADDRESSES={ULOZTO_API_NAME:"127.0.0.1",ULOZTO_CONTENT_NAME:"127.0.0.2"}
USER="synthetic-user"
ROOT="synthetic-root-3400"
FOLDERS={"":ROOT,"nested":"synthetic-folder-3410"}
FILES={"README-synthetic.txt":"synthetic-file-3401","nested/bytes.bin":"synthetic-file-3402","nested/space name.txt":"synthetic-file-3403"}
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

class UloztoState(ReadState):
    def __init__(self,app_token,password):
        if not app_token or not password:raise ValueError("missing_ulozto_credentials")
        super().__init__(app_token)
        self.login_password=password
        self.sessions=set()
        self.observed=set()
        self.links={}
        self.redirected=set()
        self.logins=0

    def metadata(self,name):
        folder=name in FOLDERS
        parent=FOLDERS["nested"] if "/" in name else ROOT
        value={"name":name.rsplit("/",1)[-1] if name else "Synthetic",
               "slug":FOLDERS[name] if folder else FILES[name],
               "last_user_modified":STAMP,"privacy":"private"}
        if folder:value.update(status="ok",parent_folder_slug=parent,created=STAMP)
        else:value.update(filesize=len(self.files[name]),folder_slug=parent,
                          upload_time=STAMP,description="",realm="ulozto",is_in_trash=False,is_incomplete=False)
        return value

    def listing(self,directory,kind,search):
        names=[n for n in children(directory,self.files) if (n in FOLDERS)==(kind=="folder")]
        if search:names=[n for n in names if n.rsplit("/",1)[-1]==search]
        self.observed.update(n for n in names if n in self.files)
        self.events.append(("listing_"+kind,directory,search))
        result={"metadata":{"RunAt":STAMP,"offset":0,"limit":500,"items_count":len(names)}}
        result["subfolders" if kind=="folder" else "items"]=[self.metadata(n) for n in names]
        if kind=="folder":result["folder"]=self.metadata(directory)
        return result

class UloztoHandler(ReadHandler):
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
                    or self.headers.get_all("Host") not in ([ULOZTO_API_NAME], [ULOZTO_CONTENT_NAME])
                    or self.server.transport._server_name not in (None, self.headers.get("Host"))
                    or len(names) != len(set(names))
                    or sum(len(k) + len(v) for k, v in headers) > 16384
                    or any("\r" in v or "\n" in v for _, v in headers)
                    or self.headers.get("Transfer-Encoding") is not None
                    or re.search(r"%(?![0-9a-fA-F]{2})", self.path)
                    or not re.fullmatch(r"0|[1-9][0-9]{0,3}", length) or int(length) > 4096
                    or self.command not in ("GET", "PUT", "POST", "DELETE")
                    or self.command not in ("POST","PUT") and length != "0"):
                raise ValueError("invalid_request")
            url = urllib.parse.urlsplit(self.path)
            if url.scheme or url.netloc or url.fragment or "%" in url.path or "//" in url.path or "\\" in url.path:
                raise ValueError("invalid_target")
            pairs = urllib.parse.parse_qsl(url.query, keep_blank_values=True, strict_parsing=True, max_num_fields=6, encoding="utf-8", errors="strict")
            query = dict(pairs)
            if len(query) != len(pairs):
                raise ValueError("duplicate_query")
            body = None
            if self.command in ("POST","PUT"):
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



    def payload(self,name):
        state=self.server.state
        if state.mode=="read_denied":
            state.read_denied+=1;state.events.append(("read_denied",name))
            self.reply(403,state.files[name],{"Content-Type":"application/octet-stream"});return
        super().payload(name)

    def reject_credentials(self):
        state=self.server.state;state.denied+=1;state.events.append(("credentials_denied",""))
        # This is invalid supplied credentials, not the expired-session code 70001.
        self.json_reply(401,{"error":70002,"code":401,"message":"synthetic invalid credentials"})

    def dispatch(self):
        with self.server.state.lock:
            request=self.wire()
            if request is None:return
            path,query,body=request;state=self.server.state
            if self.headers.get("Authorization") is not None or self.headers.get("Cookie") is not None:self.reject();return
            api=self.headers.get("Host")==ULOZTO_API_NAME
            content=re.fullmatch(r"/synthetic-content/(synthetic-file-340[1-3])/([a-f0-9]{32})",path)
            if content:
                if self.command not in ("GET","DELETE") or self.headers.get("Range") is not None and self.command!="GET":
                    self.reject();return
                record=state.links.get(content[2])
                if record is None or FILES[record[0]]!=content[1] or query!={"hash":record[2]}:
                    self.reject();return
                name,session,signature=record
                if api:
                    if self.headers.get("X-Auth-Token")!=state.password or self.headers.get("X-User-Token")!=session:
                        self.reject_credentials();return
                    state.authenticated+=1
                    if self.command=="DELETE":self.write_denial(name);return
                    state.redirected.add(content[2])
                    self.reply(302,b"",{"Location":"https://"+ULOZTO_CONTENT_NAME+path+"?"+urllib.parse.urlencode(query)});return
                if (self.headers.get("X-Auth-Token") is not None or self.headers.get("X-User-Token") is not None
                        or content[2] not in state.redirected or self.command!="GET"):
                    self.reject();return
                self.payload(name);return
            if not api or self.headers.get("Range") is not None:self.reject();return
            if self.command=="PUT" and path=="/v6/session":
                if query or self.headers.get("X-User-Token") is not None or set(body)!={"login","password"}:
                    self.reject();return
                if (self.headers.get("X-Auth-Token")!=state.password or body["login"]!=USER
                        or type(body["password"]) is not str or not hmac.compare_digest(body["password"].encode(),state.login_password.encode())):
                    self.reject_credentials();return
                session="synthetic-session-"+uuid.uuid4().hex;state.sessions.add(session);state.logins+=1;state.authenticated+=1
                self.json_reply(200,{"token_id":session,"token_validity_interval":3600,
                    "session":{"country":"CZ","is_limited_country":False,
                               "user":{"login":USER,"user_id":3400,"root_folder_slug":ROOT,"has_cloud":True}}});return
            if self.headers.get("X-Auth-Token")!=state.password or self.headers.get("X-User-Token") not in state.sessions:
                self.reject_credentials();return
            state.authenticated+=1
            match=re.fullmatch(r"/v([89])/user/"+USER+r"/folder/(synthetic-(?:root-3400|folder-3410))/(folder|file)-list",path)
            if self.command=="GET" and match:
                kind=match[3]
                if (match[1]!=("9" if kind=="folder" else "8") or query.get("status")!="ok" or query.get("limit")!="500"
                        or set(query) not in ({"status","limit"},{"status","limit","search_query"})
                        or "search_query" in query and (not query["search_query"] or len(query["search_query"])>128 or "/" in query["search_query"])):
                    self.reject();return
                directory=next(n for n,slug in FOLDERS.items() if slug==match[2])
                self.json_reply(200,state.listing(directory,kind,query.get("search_query","")));return
            if self.command=="POST" and path=="/v5/file/download-link/vipdata":
                if (query or set(body)!={"file_slug","user_login","device_id"} or body["user_login"]!=USER
                        or type(body["device_id"]) is not str or not re.fullmatch(r"[1-9][0-9]{18}",body["device_id"])
                        or type(body["file_slug"]) is not str):
                    self.reject();return
                name=next((n for n,slug in FILES.items() if slug==body["file_slug"]),None)
                if name not in state.observed:self.reject();return
                nonce,signature=uuid.uuid4().hex,uuid.uuid4().hex
                state.links[nonce]=(name,self.headers.get("X-User-Token"),signature)
                self.json_reply(200,{"link":"https://"+ULOZTO_API_NAME+"/synthetic-content/"+FILES[name]+"/"+nonce,
                                    "hash":signature,"download_url_valid_until":"2099-01-01T00:00:00Z",
                                    "download_url_validity_interval":3600});return
            self.reject()

    do_GET=dispatch
    do_HEAD=dispatch
    do_POST=dispatch
    do_PUT=dispatch
    do_DELETE=dispatch

@contextmanager
def serve_ulozto(root,state):
    certificates,transports=[],[]
    try:
        with ExitStack() as stack:
            for authority in ADDRESSES:
                cert=stack.enter_context(FixtureCertificates.create(root,server_name=authority));certificates.append(cert)
                transport=BoundedHttpsServer(cert,UloztoHandler,state=state,
                    limits=TlsLimits(connection_limit=128,active_limit=4,request_seconds=3,lifetime_seconds=120))
                transports.append(transport);stack.callback(transport.close);transport.start()
            yield certificates,transports
    finally:
        state.cleanup_complete=all(t.cleanup_complete for t in transports) and all(c.cleanup_complete for c in certificates) and listeners_closed(transports)
        if not state.cleanup_complete:raise RuntimeError("ulozto_cleanup_failed")
