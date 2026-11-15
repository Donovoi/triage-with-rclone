"""Independent Jottacloud saved-token Archive reads on exact JSON/XML authorities."""
from contextlib import contextmanager, ExitStack
import hashlib
import hmac
import re
import socket
import time
import urllib.parse
import xml.etree.ElementTree as ET
from fixture_read_api import ReadState, ReadHandler
from fixture_servers import children
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits, JOTTACLOUD_API_NAME, JOTTACLOUD_CONTENT_NAME

ROOT = "synthetic-root"
PREFIX = "/jfs/synthetic-user/Jotta/Archive/" + ROOT
ADDRESSES = {JOTTACLOUD_API_NAME: "127.0.0.1", JOTTACLOUD_CONTENT_NAME: "127.0.0.2"}
FOLDERS = ("", "nested")
JOTTA_TIME = "2024-01-01-T00:00:00Z"
ISO_TIME = "2024-01-01T00:00:00Z"

def element(parent, name, text):
    ET.SubElement(parent, name).text = str(text)

class JottacloudState(ReadState):
    def __init__(self, token):
        if not token:
            raise ValueError("missing_jottacloud_token")
        super().__init__(token)
        self.observed = set()
        self.customers = self.plain_lists = self.stream_lists = 0

    def metadata(self, name):
        entry = ET.Element("file", name=name.rsplit("/", 1)[-1])
        revision = ET.SubElement(entry, "currentRevision")
        for key,value in (("number",1),("state","COMPLETED"),("created",JOTTA_TIME),
                          ("modified",JOTTA_TIME),("updated",JOTTA_TIME),("mime","application/octet-stream"),
                          ("size",len(self.files[name])),("md5",hashlib.md5(self.files[name]).hexdigest())):
            element(revision,key,value)
        return ET.tostring(entry)

    def listing(self, directory):
        self.plain_lists += 1
        self.events.append(("listing", directory))
        names = children(directory, self.files)
        self.observed.update(name for name in names if name in self.files)
        root = ET.Element("folder", name=directory.rsplit("/",1)[-1] if directory else ROOT)
        element(root,"path","/Archive/" + ROOT + ("/" + directory if directory else ""))
        for key in ("created","modified","updated"): element(root,key,JOTTA_TIME)
        folders, files = ET.SubElement(root,"folders"), ET.SubElement(root,"files")
        for name in names:
            if name in self.files:
                files.append(ET.fromstring(self.metadata(name)))
            else:
                folder = ET.SubElement(folders,"folder", name=name.rsplit("/",1)[-1])
                for key in ("created","modified","updated"): element(folder,key,JOTTA_TIME)
        return ET.tostring(root)

    def stream(self, directory):
        self.stream_lists += 1
        self.events.append(("stream_listing", directory))
        names = sorted(name for name in self.files if not directory or name.startswith(directory + "/"))
        self.observed.update(names)
        folders = [name for name in FOLDERS if name == directory or not directory]
        root = ET.Element("list")
        for name in folders:
            folder = ET.SubElement(root,"folder")
            element(folder,"path","/Archive/" + ROOT + ("/" + name if name else ""))
        for name in names:
            folder,_,leaf = name.rpartition("/")
            entry = ET.SubElement(root,"file")
            for key,value in (("path","/Archive/" + ROOT + ("/" + folder if folder else "")),
                              ("filename",leaf),("md5",hashlib.md5(self.files[name]).hexdigest()),
                              ("size",len(self.files[name])),("modified",ISO_TIME),("created",ISO_TIME)):
                element(entry,key,value)
        stats = ET.SubElement(root,"stats")
        element(stats,"folders",len(folders)); element(stats,"files",len(names))
        return ET.tostring(root)

class JottacloudHandler(ReadHandler):
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
            authority = JOTTACLOUD_API_NAME if path == "/account/v1/customer" else JOTTACLOUD_CONTENT_NAME if path.startswith("/jfs/") else None
            # Ephemeral wire tests use an unnamed transport; native named transports
            # must match both the route authority and the exact Host.
            if (authority is None or self.headers.get_all("Host") != [authority]
                    or self.server.transport._server_name not in (None, authority)):
                raise ValueError("wrong_authority")
            return path, query, authority
        except (ValueError, UnicodeError):
            self.reject()
            return None

    def xml_error(self, status):
        root = ET.Element("error")
        element(root,"code",status); element(root,"message","synthetic refusal")
        self.reply(status,ET.tostring(root),{"Content-Type":"application/xml"})

    def payload(self, name):
        state = self.server.state
        if state.mode == "read_denied":
            state.read_denied += 1
            state.events.append(("read_denied",name))
            # Identical size and bytes to the expected object. The native
            # client must reject HTTP 403 even when data and hashes would match.
            self.reply(403,state.files[name],{"Content-Type":"application/octet-stream"})
            return
        super().payload(name)

    def dispatch(self):
        with self.server.state.lock:
            request = self.wire()
            if request is None: return
            path, query, authority = request
            state = self.server.state
            if (any(self.headers.get(key) is not None for key in ("Cookie","Content-Type","Accept"))
                    or any(k.lower().startswith(("x-jotta-","x-jottacloud-")) for k in self.headers)):
                self.reject(); return
            if not hmac.compare_digest(self.headers.get("Authorization","").encode(),
                                       ("Bearer " + state.password).encode()):
                state.denied += 1
                state.events.append(("credentials_denied",""))
                if authority == JOTTACLOUD_API_NAME: self.json_reply(401,{"error":"unauthorized"})
                else: self.xml_error(401)
                return
            state.authenticated += 1
            if authority == JOTTACLOUD_API_NAME:
                if self.command != "GET" or query or self.headers.get("Range") is not None:
                    self.reject(); return
                state.customers += 1
                self.json_reply(200,{"username":"synthetic-user"})
                return
            if path == PREFIX: name = ""
            elif path.startswith(PREFIX + "/"): name = path[len(PREFIX)+1:]
            else: self.reject(); return
            if path.endswith("/") or name not in (*FOLDERS,*state.files,"absent-synthetic.txt"):
                self.reject(); return
            if self.command == "DELETE":
                if query or self.headers.get("Range") is not None or name not in state.observed:
                    self.reject()
                else: self.write_denial(name)
                return
            if query not in ({},{"mode":"bin"},{"mode":"liststream"}):
                self.reject(); return
            if name == "absent-synthetic.txt":
                if query: self.reject(); return
                state.missing += 1; state.events.append(("missing",name)); self.xml_error(404); return
            if name in FOLDERS:
                if self.headers.get("Range") is not None or query == {"mode":"bin"}:
                    self.reject(); return
                body = state.stream(name) if query else state.listing(name)
                self.reply(200,body,{"Content-Type":"application/xml"}); return
            if query == {"mode":"bin"}:
                if name not in state.observed: self.reject()
                else: self.payload(name)
            elif query or self.headers.get("Range") is not None:
                self.reject()
            else:
                state.observed.add(name)
                state.events.append(("metadata",name))
                self.reply(200,state.metadata(name),{"Content-Type":"application/xml"})

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch

def listeners_closed(transports):
    for transport in transports:
        with socket.socket() as probe:
            probe.settimeout(1)
            if probe.connect_ex((ADDRESSES[transport.authority], transport.port)) == 0:
                return False
    return True

@contextmanager
def serve_jottacloud(root, state):
    certificates, transports = [], []
    try:
        with ExitStack() as stack:
            for authority in (JOTTACLOUD_API_NAME, JOTTACLOUD_CONTENT_NAME):
                cert = stack.enter_context(FixtureCertificates.create(root, server_name=authority))
                certificates.append(cert)
                transport = BoundedHttpsServer(cert, JottacloudHandler, state=state,
                            limits=TlsLimits(connection_limit=128, active_limit=4, request_seconds=3, lifetime_seconds=120))
                transports.append(transport)
                stack.callback(transport.close)
                transport.start()
            yield certificates, transports
    finally:
        state.cleanup_complete = (all(t.cleanup_complete for t in transports)
                                  and all(c.cleanup_complete for c in certificates)
                                  and listeners_closed(transports))
        if not state.cleanup_complete:
            raise RuntimeError("jottacloud_cleanup_failed")
