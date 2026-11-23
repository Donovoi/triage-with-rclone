"""Unqualified Proton Drive saved-session encrypted read experiment."""
from contextlib import contextmanager, ExitStack
import base64
import copy
import hashlib
import hmac
import json
import re
import socket
import subprocess
import time
import urllib.parse
from pathlib import Path
from fixture_read_api import ReadState, ReadHandler
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits

API = "drive-api.proton.me"
CONTENT = "synthetic-content.proton.invalid"
ADDRESSES = {API: "127.0.0.1", CONTENT: "127.0.0.2"}
ROOT = "link-root"
NESTED = "link-nested"
SHARE = "share-synthetic"
UID = "uid-synthetic"

class ProtonState(ReadState):
    def __init__(self, secret):
        super().__init__(secret)
        self.request_limit = 512
        self.byte_limit = 4 * 1024 * 1024
        self.connection_limit = 512
        self.observed = set()
        self.reject_diagnostics = []
        self.tampered_reads = {}
        result = subprocess.run([str(Path(__file__).parent / "generate")],
             input=json.dumps({name:base64.b64encode(value).decode() for name,value in self.files.items()}),
             capture_output=True,text=True,timeout=30,check=True)
        if len(result.stdout)>256*1024: raise ValueError("generator_output_limit")
        self.data=json.loads(result.stdout)
        self.ids=self.data["ids"]
        self.names={v:k for k,v in self.ids.items()}
        self.ciphertext={k:base64.b64decode(v,validate=True) for k,v in self.data["blocks"].items()}
    def children(self, identifier):
        return [link for link in self.data["links"].values() if link["ParentLinkID"]==identifier]

class ProtonHandler(ReadHandler):
    def reject(self,status=400):
        state=self.server.state
        state.reject_diagnostics.append({"path":urllib.parse.urlsplit(self.path).path,"method":self.command,
          "query":urllib.parse.urlsplit(self.path).query,"content_type":self.headers.get("Content-Type"),
          "length":self.headers.get("Content-Length"),"range":self.headers.get("Range")})
        super().reject(status)
    def wire(self):
        state=self.server.state;state.requests+=1
        if state.requests>state.request_limit or time.monotonic()>state.deadline:
            state.budget_exceeded=True;self.json_reply(429,{"Code":2000,"Error":"synthetic budget"});return None
        headers=list(self.headers.items());names=[k.lower() for k,v in headers]
        try:
            raw=self.raw_requestline.rstrip(b"\r\n").split(b" ")
            authority=self.server.transport._server_name
            length=self.headers.get("Content-Length","0")
            if (len(raw)!=3 or raw[1].decode("ascii")!=self.path or len(self.path)>2048
                or not self.path.startswith("/") or any(ord(c)<=32 or ord(c)>=127 for c in self.path)
                or self.headers.get_all("Host")!=[authority] or authority not in ADDRESSES
                or len(names)!=len(set(names)) or sum(len(k)+len(v) for k,v in headers)>16384
                or any("\r" in v or "\n" in v for k,v in headers)
                or self.headers.get("Transfer-Encoding") is not None or self.headers.get("Range") is not None
                or not re.fullmatch(r"0|[1-9][0-9]{0,3}",length) or int(length)>4096
                or self.command not in ("GET","POST") or self.command=="GET" and length!="0"):
                raise ValueError()
            url=urllib.parse.urlsplit(self.path)
            if url.scheme or url.netloc or url.fragment or "//" in url.path or "%" in url.path or "\\" in url.path or any(p in (".","..") for p in url.path.split("/")):
                raise ValueError()
            pairs=urllib.parse.parse_qsl(url.query,keep_blank_values=True,strict_parsing=True,max_num_fields=4)
            query=dict(pairs)
            if len(query)!=len(pairs):raise ValueError()
            body=None
            if self.command=="POST":
                if self.headers.get("Content-Type")!="application/json":raise ValueError()
                def unique(pairs):
                    obj=dict(pairs)
                    if len(obj)!=len(pairs):raise ValueError()
                    return obj
                raw=self.rfile.read(int(length))
                if len(raw)!=int(length):raise ValueError()
                body=json.loads(raw,object_pairs_hook=unique)
                if type(body) is not dict:raise ValueError()
            return url.path,query,body
        except (ValueError,UnicodeError):
            self.reject();return None
    def ok(self, **values):
        self.json_reply(200,dict(Code=1000,**values))
    def dispatch(self):
        with self.server.state.lock:
            request=self.wire()
            if request is None:return
            path,query,body=request;state=self.server.state
            if any(self.headers.get(k) is not None for k in ("Cookie","X-API-Key","Proxy-Authorization")):
                self.reject();return
            if (not hmac.compare_digest(self.headers.get("Authorization",""),"Bearer "+state.password)
                or self.headers.get("X-Pm-Uid")!=UID):
                state.denied+=1;state.events.append(("credential_denied",""))
                self.json_reply(403,{"Code":2000,"Error":"synthetic credential rejected"});return
            state.authenticated+=1
            if self.headers["Host"]==CONTENT:
                match=re.fullmatch(r"/blocks/(link-file-[0-9])",path)
                if (self.command!="GET" or query or not match or match[1] not in state.names
                    or self.headers.get("Pm-Storage-Token")!="block-token-"+match[1]
                    or state.names[match[1]] not in state.observed):
                    self.reject();return
                identifier=match[1];name=state.names[identifier]
                status=403 if state.mode=="read_denied" else 200
                if status==403:state.read_denied+=1
                state.events.append(("read_denied" if status==403 else "content",name))
                payload=state.ciphertext[identifier]
                if state.mode in ("tampered_ciphertext","wrong_block_hash","wrong_block_signature"):
                    state.tampered_reads[state.mode]=state.tampered_reads.get(state.mode,0)+1
                if state.mode=="tampered_ciphertext":
                    payload=payload[:-1]+bytes([payload[-1]^1])
                self.reply(status,payload,{"Content-Type":"application/octet-stream"},object_payload=True);return
            if self.headers.get("Pm-Storage-Token") is not None:
                self.reject();return
            if self.command=="POST":
                check_match=re.fullmatch("/drive/shares/"+SHARE+r"/links/(link-(?:root|nested))/checkAvailableHashes",path)
                if check_match and not query and type(body) is dict and set(body)=={"Hashes"} and type(body["Hashes"]) is list and len(body["Hashes"])==1 and type(body["Hashes"][0]) is str and re.fullmatch(r"[0-9a-f]{64}",body["Hashes"][0]):
                    requested=body["Hashes"][0]
                    existing={link["Hash"] for link in state.children(check_match[1])}
                    available=[] if requested in existing else [requested]
                    if available:state.missing+=1
                    self.ok(AvailableHashes=available,PendingHashesData=[]);return
                prefix="/drive/shares/"+SHARE+"/folders/"
                if (path==prefix+ROOT+"/trash_multiple" and not query
                    and body=={"LinkIDs":[state.ids["README-synthetic.txt"]]}):
                    state.rejected_mutations+=1
                    self.json_reply(405,{"Code":2000,"Error":"synthetic fixture is read-only"});return
                self.reject();return
            if self.command!="GET":self.reject();return
            if path=="/core/v4/users" and not query:self.ok(User=state.data["user"]);return
            if path=="/core/v4/addresses" and not query:self.ok(Addresses=state.data["addresses"]);return
            if path=="/drive/volumes" and not query:self.ok(Volumes=state.data["volumes"]);return
            if path=="/drive/shares" and query in ({},{"ShowAll":"1"}):
                self.ok(Shares=[state.data["share_metadata"]]);return
            prefix="/drive/shares/"+SHARE
            if path==prefix and not query:self.ok(**state.data["share"]);return
            match=re.fullmatch(re.escape(prefix)+r"/links/(link-(?:root|nested|file-[0-9]))",path)
            if match and not query and match[1] in state.data["links"]:
                self.ok(Link=state.data["links"][match[1]]);return
            match=re.fullmatch(re.escape(prefix)+r"/folders/(link-(?:root|nested))/children",path)
            if match and query.get("Page") in ("0","1") and query.get("PageSize")=="150" and query.get("ShowAll") in ("0","1") and set(query)=={"Page","PageSize","ShowAll"}:
                links=state.children(match[1]) if query["Page"]=="0" else []
                state.observed.update(state.names[l["LinkID"]] for l in links if l["LinkID"] in state.names)
                state.events.append(("listing",match[1]));self.ok(Links=links);return
            match=re.fullmatch(re.escape(prefix)+r"/files/(link-file-[0-9])/revisions(?:/(revision-link-file-[0-9]))?",path)
            if match and not query and match[1] in state.data["revisions"]:
                revision=state.data["revisions"][match[1]]
                if match[2] is None:
                    self.ok(Revisions=[{k:v for k,v in revision.items() if k!="Blocks"}]);return
                if match[2]==revision["ID"]:
                    revision=copy.deepcopy(revision)
                    if state.mode=="wrong_block_hash":
                        revision["Blocks"][0]["Hash"]=base64.b64encode(bytes(32)).decode()
                    elif state.mode=="wrong_block_signature":
                        revision["Blocks"][0]["EncSignature"]=state.data["wrong_signatures"][match[1]]
                    self.ok(Revision=revision);return
            self.reject()
    do_GET=dispatch
    do_POST=dispatch
    do_DELETE=dispatch
    do_PUT=dispatch
    do_HEAD=dispatch

def listeners_closed(transports):
    for transport in transports:
        with socket.socket() as probe:
            probe.settimeout(1)
            if probe.connect_ex((ADDRESSES[transport.authority],transport.port))==0:return False
    return True

@contextmanager
def serve_proton(root,state):
    certificates,transports=[],[]
    try:
        with ExitStack() as stack:
            for authority in ADDRESSES:
                cert=stack.enter_context(FixtureCertificates.create(root,server_name=authority))
                certificates.append(cert)
                transport=BoundedHttpsServer(cert,ProtonHandler,state=state,
                   limits=TlsLimits(connection_limit=512,active_limit=4,request_seconds=3,lifetime_seconds=120))
                transports.append(transport);stack.callback(transport.close);transport.start()
            yield certificates,transports
    finally:
        state.stopping.set()
        state.cleanup_complete=all(t.cleanup_complete for t in transports) and all(c.cleanup_complete for c in certificates) and listeners_closed(transports)
        if not state.cleanup_complete:raise RuntimeError("proton_cleanup_failed")
