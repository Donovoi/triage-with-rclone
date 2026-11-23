"""Unqualified Filen saved-account v2 encrypted read experiment."""
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

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from fixture_read_api import ReadState, ReadHandler
from fixture_servers import children, is_directory
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits

API = "gateway.filen.io"
CONTENT = "egest.filen.io"
ADDRESSES = {API: "127.0.0.1", CONTENT: "127.0.0.2"}
ROOT = "00000000-0000-4000-8000-000000000001"
NESTED = "00000000-0000-4000-8000-000000000002"
MASTER = "0123456789abcdef" * 4
REGION = "synthetic-region"
BUCKET = "synthetic-bucket"
STAMP = 1704067200000


class FilenState(ReadState):
    def __init__(self, secret):
        super().__init__(secret)
        self.ids = {name: str(uuid.UUID(int=100+i)) for i, name in enumerate(sorted(self.files))}
        self.names = {identifier: name for name, identifier in self.ids.items()}
        self.observed = set()
        self.tampered_reads = 0
        self.ciphertext = {}
        self.file_metadata = {}
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.private_key = base64.b64encode(key.private_bytes(serialization.Encoding.DER,
                            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())).decode()
        self.public_key = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.PKCS1)).decode()
        derived = hashlib.pbkdf2_hmac("sha512", MASTER.encode(), MASTER.encode(), 1, 32)

        def metadata(label, value):
            nonce = hashlib.sha256(("metadata:" + label).encode()).hexdigest()[:12].encode()
            data = json.dumps(value, separators=(",", ":")).encode()
            return "002" + nonce.decode() + base64.b64encode(AESGCM(derived).encrypt(nonce, data, None)).decode()

        for name, payload in self.files.items():
            file_key = hashlib.sha256(("key:" + name).encode()).hexdigest()[:32]
            nonce = hashlib.sha256(("nonce:" + name).encode()).digest()[:12]
            self.ciphertext[name] = nonce + AESGCM(file_key.encode()).encrypt(nonce, payload, None)
            self.file_metadata[name] = metadata(name, {
                "name": name.rsplit("/", 1)[-1], "size": len(payload), "mime": "application/octet-stream",
                "key": file_key, "lastModified": STAMP, "creation": STAMP, "blake3": "",
            })
        self.folder_metadata = metadata("nested", {"name": "nested", "creation": STAMP // 1000})
        self.root_metadata = metadata("root", {"name": "", "creation": STAMP // 1000})

    def inventory(self, identifier):
        parent = "" if identifier == ROOT else "nested"
        uploads, folders = [], []
        for name in children(parent, self.files):
            if is_directory(name, self.files):
                folders.append({"uuid": NESTED, "name": self.folder_metadata, "parent": ROOT,
                                "color": "", "timestamp": STAMP // 1000, "favorited": 0,
                                "is_sync": 0, "is_default": 0})
            else:
                uploads.append({"uuid": self.ids[name], "metadata": self.file_metadata[name], "rm": "",
                                "timestamp": STAMP // 1000, "chunks": 1, "size": len(self.files[name]),
                                "bucket": BUCKET, "region": REGION, "parent": identifier,
                                "version": 2, "favorited": 0})
        return {"uploads": uploads, "folders": folders}


    def recursive_inventory(self, identifier):
        inventories = [self.inventory(identifier)]
        if identifier == ROOT:
            inventories.append(self.inventory(NESTED))
        files = [dict(item, size=str(item["size"]), favorited=False)
                 for inventory in inventories for item in inventory["uploads"]]
        folders = [dict(item, favorited=False) for inventory in inventories for item in inventory["folders"]]
        folders.insert(0, {"uuid":identifier,"name":self.root_metadata if identifier==ROOT else self.folder_metadata,
                           "parent":"base","timestamp":STAMP//1000,"favorited":False})
        return {"files": files, "folders": folders}


class FilenHandler(ReadHandler):
    def wire(self):
        state = self.server.state
        state.requests += 1
        if state.requests > state.request_limit or time.monotonic() > state.deadline:
            state.budget_exceeded = True
            self.json_reply(429, {"status": False, "code": "budget"})
            return None
        headers = list(self.headers.items())
        names = [k.lower() for k, _ in headers]
        try:
            raw = self.raw_requestline.rstrip(b"\r\n").split(b" ")
            authority = self.server.transport._server_name
            length = self.headers.get("Content-Length", "0")
            if (len(raw) != 3 or raw[1].decode("ascii") != self.path or len(self.path) > 2048
                    or not self.path.startswith("/") or any(ord(c) <= 32 or ord(c) >= 127 for c in self.path)
                    or self.headers.get_all("Host") != [authority] or authority not in ADDRESSES
                    or len(names) != len(set(names)) or sum(len(k) + len(v) for k, v in headers) > 16384
                    or any("\r" in v or "\n" in v for _, v in headers)
                    or self.headers.get("Transfer-Encoding") is not None
                    or self.headers.get("Range") is not None
                    or self.headers.get("Content-Type") != "application/json"
                    or not re.fullmatch(r"0|[1-9][0-9]{0,3}", length) or int(length) > 4096
                    or self.command not in ("GET", "POST") or self.command == "GET" and length != "0"):
                raise ValueError()
            url = urllib.parse.urlsplit(self.path)
            if (url.scheme or url.netloc or url.fragment or url.query or "//" in url.path
                    or "%" in url.path or "\\" in url.path or any(p in (".", "..") for p in url.path.split("/"))):
                raise ValueError()
            body = None
            if self.command == "POST":
                def unique(pairs):
                    result = dict(pairs)
                    if len(result) != len(pairs):
                        raise ValueError()
                    return result
                data = self.rfile.read(int(length))
                if len(data) != int(length):
                    raise ValueError()
                body = json.loads(data, object_pairs_hook=unique)
                if type(body) is not dict:
                    raise ValueError()
            return url.path, body
        except (ValueError, UnicodeError):
            self.reject()
            return None

    def reject(self, status=400):
        state=self.server.state
        if not hasattr(state,"reject_diagnostics"):state.reject_diagnostics=[]
        state.reject_diagnostics.append({"path":urllib.parse.urlsplit(self.path).path,"method":self.command,"content_type":self.headers.get("Content-Type"),"length":self.headers.get("Content-Length"),"range":self.headers.get("Range")})
        super().reject(status)

    def dispatch(self):
        with self.server.state.lock:
            request = self.wire()
            if request is None:
                return
            path, body = request
            state = self.server.state
            if any(self.headers.get(k) is not None for k in ("Cookie", "X-API-Key", "Proxy-Authorization")):
                self.reject()
                return
            if not hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + state.password):
                state.denied += 1
                state.events.append(("key_denied", ""))
                self.json_reply(403, {"status": False, "message": "synthetic key rejected", "code": "synthetic_credential_rejected"})
                return
            state.authenticated += 1
            if self.headers["Host"] == API:
                if (self.command != "POST" or type(body) is not dict
                        or set(body) != ({"uuid", "skipCache"} if path == "/v3/dir/download" else {"uuid"})
                        or path == "/v3/dir/download" and body.get("skipCache") != ""):
                    self.reject()
                    return
                identifier = body["uuid"]
                if path == "/v3/dir/content" and identifier in (ROOT, NESTED):
                    parent = "" if identifier == ROOT else "nested"
                    state.events.append(("listing", parent))
                    state.observed.update(n for n in children(parent, state.files) if n in state.files)
                    self.json_reply(200, {"status": True, "data": state.inventory(identifier)})
                elif path == "/v3/dir/download" and identifier in (ROOT, NESTED):
                    parent = "" if identifier == ROOT else "nested"
                    state.events.append(("recursive_listing", parent))
                    state.observed.update(n for n in state.files if not parent or n.startswith(parent + "/"))
                    self.json_reply(200, {"status": True, "data": state.recursive_inventory(identifier)})
                elif path == "/v3/file/trash" and identifier in state.names:
                    state.rejected_mutations += 1
                    state.events.append(("write_denied", state.names[identifier]))
                    self.json_reply(405, {"status": False, "code": "synthetic_read_only", "message": "synthetic fixture is read-only"})
                else:
                    self.reject()
                return
            match = re.fullmatch("/" + REGION + "/" + BUCKET + r"/([0-9a-f-]{36})/0", path)
            if (self.command != "GET" or not match or match[1] not in state.names
                    or state.names[match[1]] not in state.observed):
                self.reject()
                return
            name = state.names[match[1]]
            payload = state.ciphertext[name]
            status = 200
            if state.mode == "tampered_ciphertext":
                state.tampered_reads += 1
                payload = payload[:-1] + bytes([payload[-1] ^ 1])
            if state.mode == "read_denied":
                state.read_denied += 1
                state.events.append(("read_denied", name))
                status = 403
            else:
                state.events.append(("content", name))
            self.reply(status, payload, {"Content-Type": "application/octet-stream"}, object_payload=True)

    do_GET = dispatch
    do_POST = dispatch
    do_DELETE = dispatch
    do_PUT = dispatch
    do_HEAD = dispatch


def listeners_closed(transports):
    for transport in transports:
        with socket.socket() as probe:
            probe.settimeout(1)
            if probe.connect_ex((ADDRESSES[transport.authority], transport.port)) == 0:
                return False
    return True


@contextmanager
def serve_filen(root, state):
    certificates, transports = [], []
    try:
        with ExitStack() as stack:
            for authority in ADDRESSES:
                cert = stack.enter_context(FixtureCertificates.create(root, server_name=authority))
                certificates.append(cert)
                transport = BoundedHttpsServer(cert, FilenHandler, state=state,
                    limits=TlsLimits(connection_limit=128, active_limit=4, request_seconds=3, lifetime_seconds=120))
                transports.append(transport)
                stack.callback(transport.close)
                transport.start()
            yield certificates, transports
    finally:
        state.stopping.set()
        state.cleanup_complete = (all(t.cleanup_complete for t in transports)
                                  and all(c.cleanup_complete for c in certificates) and listeners_closed(transports))
        if not state.cleanup_complete:
            raise RuntimeError("filen_cleanup_failed")
