"""Independent Internxt saved-JWT rotation and encrypted single-shard read experiment."""
from contextlib import contextmanager, ExitStack
import base64
import hashlib
import hmac
import json
import re
import socket
import time
import urllib.parse
import uuid
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fixture_read_api import ReadState, ReadHandler
from fixture_servers import children
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits, INTERNXT_API_NAME, INTERNXT_CONTENT_NAME

ADDRESSES={INTERNXT_API_NAME:"127.0.0.1",INTERNXT_CONTENT_NAME:"127.0.0.2"}
MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
BUCKET="00112233445566778899aabb"
ROOT="11111111-1111-4111-8111-111111111111"
NESTED="22222222-2222-4222-8222-222222222222"
USER="synthetic-user";BRIDGE="synthetic-bridge"
BASIC="Basic "+base64.b64encode((BRIDGE+":"+hashlib.sha256(USER.encode()).hexdigest()).encode()).decode()
STAMP="2024-01-01T00:00:00Z"

def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")

def listeners_closed(transports):
    for transport in transports:
        with socket.socket() as probe:
            probe.settimeout(1)
            if probe.connect_ex((ADDRESSES[transport.authority],transport.port))==0:return False
    return True

class InternxtState(ReadState):
    def __init__(self,secret):
        super().__init__(secret)
        self.expiry=int(time.time())+86400
        self.sequence=0;self.rotations=[];self.current=self.token(0)
        self.observed=set();self.links={};self.ciphertext={};self.indices={}
        self.ids={name:str(uuid.UUID(int=3601+i)) for i,name in enumerate(sorted(self.files))}
        # Independent BIP39/PBKDF2 and SHA512 derivation; no provider SDK.
        seed=hashlib.pbkdf2_hmac("sha512",MNEMONIC.encode(),b"mnemonic",2048)
        bucket_key=hashlib.sha512(seed+bytes.fromhex(BUCKET)).digest()
        for name,payload in self.files.items():
            index=hashlib.sha256(("synthetic-index:"+name).encode()).digest()
            key=hashlib.sha512(bucket_key[:32]+index).digest()[:32]
            encryptor=Cipher(algorithms.AES(key),modes.CTR(index[:16])).encryptor()
            self.indices[name]=index.hex()
            self.ciphertext[name]=encryptor.update(payload)+encryptor.finalize()

    def token(self,sequence):
        header=b64(b'{"alg":"HS256","typ":"JWT"}')
        payload=b64(json.dumps({"exp":self.expiry,"sub":USER,"jti":str(sequence)},separators=(",",":")).encode())
        signed=header+"."+payload
        return signed+"."+b64(hmac.new(self.password.encode(),signed.encode(),hashlib.sha256).digest())

    def rotate(self):
        old=self.current;self.sequence+=1;self.current=self.token(self.sequence)
        self.rotations.append((old,self.current))
        return {"newToken":self.current,"user":{"rootFolderId":ROOT,"bucket":BUCKET,"bridgeUser":BRIDGE,"userId":USER}}

    def metadata(self,name):
        folder=name in ("","nested")
        leaf=name.rsplit("/",1)[-1]
        stem,_,extension=leaf.rpartition(".")
        return {"id":3600 if folder else 3601+list(sorted(self.files)).index(name),
                "uuid":ROOT if name=="" else NESTED if folder else self.ids[name],
                "fileId":"" if folder else "synthetic-"+self.ids[name],
                "plainName":leaf if folder or not stem else stem,"type":"" if folder or not stem else extension,
                "folderUuid":ROOT if "/" not in name else NESTED,"parentUuid":ROOT,
                "bucket":BUCKET,"size":0 if folder else len(self.files[name]),
                "encryptVersion":"03-aes","status":"EXISTS",
                "createdAt":STAMP,"updatedAt":STAMP,"creationTime":STAMP,"modificationTime":STAMP}

    def listing(self,directory,kind):
        names=children(directory,self.files)
        selected=[n for n in names if (n in self.files)==(kind=="files")]
        self.observed.update(n for n in selected if n in self.files)
        self.events.append(("listing_"+kind,directory))
        return {kind:[self.metadata(n) for n in selected],"nextCursor":""}

    def info(self,name):
        nonce=uuid.uuid4().hex;self.links[nonce]=name
        ciphertext=self.ciphertext[name]
        return {"bucket":BUCKET,"index":self.indices[name],"size":len(ciphertext),"version":1,
                "created":STAMP,"renewal":STAMP,"filename":name,"id":"synthetic-"+self.ids[name],
                "shards":[{"index":0,"hash":hashlib.new("ripemd160",hashlib.sha256(ciphertext).digest()).hexdigest(),
                           "url":"https://"+INTERNXT_CONTENT_NAME+"/shard/"+self.ids[name]+"/"+nonce}]}

class InternxtHandler(ReadHandler):
    def wire(self):
        state=self.server.state;state.requests+=1
        if state.requests>state.request_limit or time.monotonic()>state.deadline:
            state.budget_exceeded=True;self.json_reply(429,{"error":"budget"});return None
        try:
            raw=self.raw_requestline.rstrip(b"\r\n").split(b" ")
            headers=list(self.headers.items());names=[k.lower() for k,v in headers]
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
            pairs=urllib.parse.parse_qsl(url.query,keep_blank_values=True,strict_parsing=True,max_num_fields=4,encoding="utf-8",errors="strict")
            query=dict(pairs)
            if len(query)!=len(pairs):raise ValueError("duplicate_query")
            body=None
            if self.command=="POST":
                if self.headers.get("Content-Type")!="application/json" or not int(length):raise ValueError("json_required")
                data=self.rfile.read(int(length))
                if len(data)!=int(length):raise ValueError("body_length")
                def unique(pairs):
                    result=dict(pairs)
                    if len(result)!=len(pairs):raise ValueError("duplicate_json")
                    return result
                body=json.loads(data,object_pairs_hook=unique)
            return url.path,query,body
        except OSError:
            self.close_connection=True;return None
        except (ValueError,UnicodeError):
            self.reject();return None

    def shard(self,name):
        state=self.server.state;data=state.ciphertext[name]
        if state.mode=="read_denied":
            state.read_denied+=1;state.events.append(("read_denied",name))
            self.reply(403,data,{"Content-Type":"application/octet-stream"});return
        range_value=self.headers.get("Range")
        headers={"Content-Type":"application/octet-stream","Accept-Ranges":"bytes"}
        status=200
        if range_value is not None:
            match=re.fullmatch(r"bytes=(0|[1-9][0-9]*)-([0-9]*)",range_value)
            if match is None:self.reject();return
            first=int(match[1]);last=int(match[2]) if match[2] else len(data)-1
            if not 0<=first<=last<len(data):
                self.reply(416,b"",{"Content-Range":"bytes */"+str(len(data))});return
            headers["Content-Range"]=f"bytes {first}-{last}/{len(data)}";data=data[first:last+1];status=206
            state.events.append(("range",name))
        state.payload_bytes+=len(data);state.events.append(("download",name))
        self.reply(status,data,headers)

    def dispatch(self):
        with self.server.state.lock:
            request=self.wire()
            if request is None:return
            path,query,body=request;state=self.server.state;authority=self.headers.get("Host")
            if self.headers.get("Cookie") is not None:self.reject();return
            if authority==INTERNXT_CONTENT_NAME:
                match=re.fullmatch(r"/shard/([0-9a-f-]{36})/([0-9a-f]{32})",path)
                if (match is None or query or self.headers.get("Authorization") is not None
                        or self.headers.get("internxt-client") is not None or self.headers.get("internxt-version") is not None):
                    self.reject();return
                name=state.links.get(match[2])
                if name is None or state.ids[name]!=match[1] or name not in state.observed:self.reject();return
                if self.command!="GET" and self.headers.get("Range") is not None:self.reject();return
                if self.command=="DELETE":self.write_denial(name)
                elif self.command=="GET":self.shard(name)
                else:self.reject()
                return
            if self.headers.get("Range") is not None:self.reject();return
            if path.startswith("/network/"):
                if self.headers.get("Authorization")!=BASIC:
                    state.denied+=1;self.json_reply(403,{"error":"credentials"});return
                name=next((n for n in state.files if path=="/network/buckets/"+BUCKET+"/files/synthetic-"+state.ids[n]+"/info"),None)
                if (name is None or name not in state.observed or query or self.command!="GET"
                        or self.headers.get("internxt-version")!="1.0"):
                    self.reject();return
                self.json_reply(200,state.info(name));return
            if not hmac.compare_digest(self.headers.get("Authorization","").encode(),("Bearer "+state.current).encode()):
                state.denied+=1;state.events.append(("credentials_denied",""))
                self.json_reply(403,{"error":"synthetic invalid token"});return
            state.authenticated+=1
            if self.command=="GET" and path=="/drive/users/cli/refresh" and not query:
                if self.headers.get("internxt-client")!="rclone-adapter":self.reject();return
                self.json_reply(200,state.rotate());return
            if not state.sequence or self.headers.get("internxt-client") is not None:self.reject();return
            match=re.fullmatch(r"/drive/folders/v2/content/([0-9a-f-]{36})/(files|folders)",path)
            if self.command=="GET" and match and query=={"limit":"1000","order":"ASC"}:
                directory={ROOT:"",NESTED:"nested"}.get(match[1])
                if directory is None:self.json_reply(404,{"error":"missing"})
                else:self.json_reply(200,state.listing(directory,match[2]))
                return
            match=re.fullmatch(r"/drive/folders/content/([0-9a-f-]{36})/files/existence",path)
            if self.command=="POST" and match and not query:
                directory={ROOT:"",NESTED:"nested"}.get(match[1])
                if (directory is None or type(body) is not dict or set(body)!={"files"}
                        or type(body["files"]) is not list or not 1<=len(body["files"])<=3):
                    self.reject();return
                found=[]
                for entry in body["files"]:
                    if (type(entry) is not dict or set(entry)!={"plainName","type","originalFile"}
                            or entry["originalFile"]!={} or not all(type(entry[k]) is str for k in ("plainName","type"))
                            or any("/" in entry[k] or "\\" in entry[k] for k in ("plainName","type"))):
                        self.reject();return
                    leaf=entry["plainName"]+("."+entry["type"] if entry["type"] else "")
                    name=(directory+"/" if directory else "")+leaf
                    exists=name in state.files
                    found.append({"exists":exists,"status":"EXISTS" if exists else "MISSING",
                                  "uuid":state.ids.get(name,""),"plainName":entry["plainName"],"type":entry["type"]})
                    if exists:state.observed.add(name)
                self.json_reply(200,{"existentFiles":found});return
            name=next((n for n in state.files if path=="/drive/files/"+state.ids[n]+"/meta"),None)
            if self.command=="GET" and name is not None and not query and name in state.observed:
                self.json_reply(200,state.metadata(name));return
            self.reject()

    do_GET=dispatch
    do_HEAD=dispatch
    do_POST=dispatch
    do_PUT=dispatch
    do_DELETE=dispatch

@contextmanager
def serve_internxt(root,state):
    certificates,transports=[],[]
    try:
        with ExitStack() as stack:
            for authority in ADDRESSES:
                cert=stack.enter_context(FixtureCertificates.create(root,server_name=authority));certificates.append(cert)
                transport=BoundedHttpsServer(cert,InternxtHandler,state=state,
                    limits=TlsLimits(connection_limit=128,active_limit=4,request_seconds=3,lifetime_seconds=120))
                transports.append(transport);stack.callback(transport.close);transport.start()
            yield certificates,transports
    finally:
        state.cleanup_complete=all(t.cleanup_complete for t in transports) and all(c.cleanup_complete for c in certificates) and listeners_closed(transports)
        if not state.cleanup_complete:raise RuntimeError("internxt_cleanup_failed")
