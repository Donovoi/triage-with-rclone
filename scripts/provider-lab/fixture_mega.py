"""Independent Mega saved-session encrypted node and content fixture."""
from contextlib import contextmanager, ExitStack
import base64
import hashlib
import hmac
import json
import re
import socket
import struct
import time
import urllib.parse
import uuid
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fixture_read_api import ReadState, ReadHandler
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits, MEGA_API_NAME, MEGA_CONTENT_NAME

ADDRESSES={MEGA_API_NAME:"127.0.0.1",MEGA_CONTENT_NAME:"127.0.0.2"}
MASTER_KEY=bytes.fromhex("00112233445566778899aabbccddeeff")
ROOT="AAAAAAAB";NESTED="AAAAAAAC";USER="c3ludGh1c2U";SEQUENCE="synthetic-sequence"

def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")

def encrypt(key,mode,value):
    cipher=Cipher(algorithms.AES(key),mode).encryptor()
    return cipher.update(value)+cipher.finalize()

def padded(value):
    return value+b"\0"*((-len(value))%16)

def attr(key,name):
    return b64(encrypt(key,modes.CBC(bytes(16)),padded(b"MEGA"+json.dumps({"n":name},separators=(",",":")).encode())))

def listeners_closed(transports):
    for transport in transports:
        with socket.socket() as probe:
            probe.settimeout(1)
            if probe.connect_ex((ADDRESSES[transport.authority],transport.port))==0:return False
    return True

class MegaState(ReadState):
    def __init__(self,secret):
        super().__init__(secret)
        self.observed=set();self.links={};self.waits=set();self.ciphertext={};self.attributes={}
        self.ids={name:b64((10+i).to_bytes(6,"big")) for i,name in enumerate(sorted(self.files))}
        folder_key=hashlib.sha256(b"synthetic-folder-key").digest()[:16]
        self.nodes=[{"h":ROOT,"p":"","u":USER,"t":2,"ts":1704067200},
                    {"h":NESTED,"p":ROOT,"u":USER,"t":1,"ts":1704067200,
                     "a":attr(folder_key,"nested"),"k":USER+":"+b64(encrypt(MASTER_KEY,modes.ECB(),folder_key))}]
        for name,payload in self.files.items():
            # Independent single-chunk AES CTR encryption and folded CBC MAC.
            key=hashlib.sha256(("synthetic-file-key:"+name).encode()).digest()[:16]
            nonce=hashlib.sha256(("synthetic-nonce:"+name).encode()).digest()[:8]
            self.ciphertext[name]=encrypt(key,modes.CTR(nonce+bytes(8)),payload)
            chunk_mac=encrypt(key,modes.CBC(nonce*2),padded(payload))[-16:]
            mac=struct.unpack(">4I",encrypt(key,modes.CBC(bytes(16)),chunk_mac))
            k=struct.unpack(">4I",key);n=struct.unpack(">2I",nonce);m=(mac[0]^mac[1],mac[2]^mac[3])
            compkey=struct.pack(">8I",k[0]^n[0],k[1]^n[1],k[2]^m[0],k[3]^m[1],*n,*m)
            attributes=attr(key,name.rsplit("/",1)[-1]);self.attributes[name]=attributes
            self.nodes.append({"h":self.ids[name],"p":NESTED if "/" in name else ROOT,"u":USER,
                               "t":0,"ts":1704067200,"s":len(payload),"a":attributes,
                               "k":USER+":"+b64(encrypt(MASTER_KEY,modes.ECB(),compkey))})

    def listing(self):
        self.observed.update(self.files);self.events.append(("listing",""))
        return {"f":self.nodes,"ok":[],"s":[],"u":[],"sn":SEQUENCE}

    def download(self,name):
        nonce=uuid.uuid4().hex;self.links[nonce]=name;self.events.append(("link",name))
        return {"g":"https://"+MEGA_CONTENT_NAME+"/file/"+self.ids[name]+"/"+nonce,
                "s":len(self.files[name]),"at":self.attributes[name],"e":0}

class MegaHandler(ReadHandler):
    protocol_version="HTTP/1.1"

    def reply(self,status,body=b"",headers=None,object_payload=False):
        super().reply(status,body,headers,object_payload)
        # Reuse the authenticated API TLS connection for the discovered event
        # wait. The SDK releases startup before issuing that GET; reuse avoids
        # a new handshake racing the end of short-lived native commands.
        if self.headers.get("Host")==MEGA_API_NAME:
            self.close_connection=False

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
            if url.scheme or url.netloc or url.fragment or "//" in url.path or "\\" in url.path or "%" in url.path:
                raise ValueError("invalid_target")
            pairs=urllib.parse.parse_qsl(url.query,keep_blank_values=True,strict_parsing=True,max_num_fields=2,encoding="utf-8",errors="strict")
            query=dict(pairs)
            if len(query)!=len(pairs):raise ValueError("duplicate_query")
            body=None
            if self.command=="POST":
                if self.headers.get("Content-Type")!=("application/json" if url.path=="/cs" else "application/xml"):raise ValueError("content_type")
                data=self.rfile.read(int(length))
                if len(data)!=int(length):raise ValueError("body_length")
                if data:
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

    def dispatch(self):
        waiting=False
        with self.server.state.lock:
            request=self.wire()
            if request is None:return
            path,query,body=request;state=self.server.state;authority=self.headers.get("Host")
            if any(self.headers.get(k) is not None for k in ("Cookie","Authorization","Range")):
                self.reject();return
            if authority==MEGA_CONTENT_NAME:
                match=re.fullmatch(r"/file/([A-Za-z0-9_-]{8})/([0-9a-f]{32})/0-([0-9]{1,4})",path)
                if match is None or query or body is not None:self.reject();return
                name=state.links.get(match[2])
                if (name is None or state.ids[name]!=match[1] or name not in state.observed
                        or str(len(state.files[name])-1)!=match[3]):self.reject();return
                if self.command=="DELETE":self.write_denial(name);return
                if self.command!="GET":self.reject();return
                data=state.ciphertext[name]
                if state.mode=="read_denied":
                    state.read_denied+=1;state.events.append(("read_denied",name))
                    self.reply(403,data,{"Content-Type":"application/octet-stream"});return
                state.payload_bytes+=len(data);state.events.append(("download",name))
                self.reply(200,data,{"Content-Type":"application/octet-stream"});return
            if authority==MEGA_API_NAME and path.startswith("/wait/"):
                match=re.fullmatch(r"/wait/([0-9a-f]{32})",path)
                if match is None or match[1] not in state.waits or query or body is not None or self.command!="GET":
                    self.reject();return
                state.waits.remove(match[1]);state.events.append(("wait",""));waiting=True
            else:
                if self.command!="POST" or path not in ("/cs","/sc"):
                    self.reject();return
                required={"id","sid"} if path=="/cs" else {"sn","sid"}
                if (set(query)!=required or path=="/cs" and not re.fullmatch(r"[0-9]{1,20}",query["id"])
                        or path=="/sc" and query["sn"]!=SEQUENCE):self.reject();return
                if not hmac.compare_digest(query["sid"].encode(),state.password.encode()):
                    state.denied+=1;state.events.append(("credentials_denied",""));self.json_reply(200,[-15]);return
                state.authenticated+=1
                if path=="/sc":
                    if body is not None:self.reject();return
                    nonce=uuid.uuid4().hex;state.waits.add(nonce);state.events.append(("poll",""))
                    self.json_reply(200,{"w":"https://"+MEGA_API_NAME+"/wait/"+nonce,"a":[]});return
                if type(body) is not list or len(body)!=1 or type(body[0]) is not dict:self.reject();return
                message=body[0]
                if message=={"a":"f","c":1} and type(message["c"]) is int:
                    self.json_reply(200,[state.listing()]);return
                if set(message)=={"a","g","n","ssl"} and message["a"]=="g" and message["g"]==1 and message["ssl"]==2 and type(message["g"]) is int and type(message["ssl"]) is int and type(message["n"]) is str:
                    name=next((n for n in state.files if state.ids[n]==message["n"]),None)
                    if name is None or name not in state.observed:self.reject();return
                    self.json_reply(200,[state.download(name)]);return
                self.reject();return
        if waiting:
            # Do not hold the shared state lock while the SDK waits for events.
            self.connection.settimeout(1)
            try:
                extra=self.connection.recv(1)
                if not extra:
                    self.close_connection=True
                    return
                self.reject()
                return
            except socket.timeout:
                self.reply(200,b"",{"Content-Type":"application/octet-stream"})

    do_GET=dispatch
    do_HEAD=dispatch
    do_POST=dispatch
    do_PUT=dispatch
    do_DELETE=dispatch

@contextmanager
def serve_mega(root,state):
    certificates,transports=[],[]
    try:
        with ExitStack() as stack:
            for authority in ADDRESSES:
                cert=stack.enter_context(FixtureCertificates.create(root,server_name=authority));certificates.append(cert)
                transport=BoundedHttpsServer(cert,MegaHandler,state=state,
                    limits=TlsLimits(connection_limit=128,active_limit=4,request_seconds=3,lifetime_seconds=120))
                transports.append(transport);stack.callback(transport.close);transport.start()
            yield certificates,transports
    finally:
        state.stopping.set()
        state.cleanup_complete=all(t.cleanup_complete for t in transports) and all(c.cleanup_complete for c in certificates) and listeners_closed(transports)
        if not state.cleanup_complete:raise RuntimeError("mega_cleanup_failed")
