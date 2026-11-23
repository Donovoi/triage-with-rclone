"""Independent kDrive saved-token inventory and authenticated download experiment."""
from contextlib import contextmanager
import hmac
import re
import time
import urllib.parse
from fixture_read_api import ReadState, ReadHandler
from fixture_servers import children
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits, KDRIVE_API_NAME

ORIGIN = "https://api.infomaniak.com"
DRIVE = "290"
ROOT = "2900"
STAMP = 1704067200
FOLDERS = {"": 2900, "nested": 2910}
FILES = {"README-synthetic.txt": 2901, "nested/bytes.bin": 2902, "nested/space name.txt": 2903}
# Independently computed with libxxhash 0.8.3 XXH3_64bits, over the known literal fixture bytes.
XXH3 = {'README-synthetic.txt': '2ec4e7a4e5accf6b', 'nested/bytes.bin': 'dd420471ff96bd00', 'nested/space name.txt': '2dbd70e0cc9cbf57'}

class KdriveState(ReadState):
    def __init__(self, token):
        if not token:
            raise ValueError("missing_kdrive_token")
        super().__init__(token)
        self.observed = set()

    def metadata(self, name):
        folder = name in FOLDERS
        return {"id": FOLDERS[name] if folder else FILES[name], "name": name.rsplit("/",1)[-1] if name else "Synthetic",
                "type": "dir" if folder else "file", "path": "/Synthetic"+("/"+name if name else ""),
                "status": "active", "hash": "" if folder else "xxh3:"+XXH3[name],
                "size": 0 if folder else len(self.files[name]), "visibility": "private", "drive_id": 290,
                "depth": name.count("/")+1 if name else 0, "created_by": 1001, "created_at": STAMP,
                "added_at": STAMP, "last_modified_at": STAMP, "last_modified_by": 1001,
                "revised_at": STAMP, "updated_at": STAMP, "mime_type": "" if folder else "application/octet-stream",
                "parent_id": 1 if not name else (2910 if "/" in name else 2900), "color": ""}

    def listing(self, directory, recursive):
        names=sorted([name for name in (*self.files,"nested") if name!=directory
                      and (not directory or name.startswith(directory+"/"))]) if recursive else children(directory,self.files)
        self.observed.update(name for name in names if name in self.files)
        self.events.append(("listing",directory))
        return {"result":"success","data":[self.metadata(name) for name in names],"cursor":"","has_more":False}

class KdriveHandler(ReadHandler):
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
                    or self.headers.get_all("Host") != [KDRIVE_API_NAME]
                    or self.server.transport._server_name not in (None, KDRIVE_API_NAME)
                    or len(names) != len(set(names))
                    or sum(len(k) + len(v) for k, v in headers) > 16384
                    or any("\r" in v or "\n" in v for _, v in headers)
                    or self.headers.get("Transfer-Encoding") is not None
                    or re.search(r"%(?![0-9a-fA-F]{2})", self.path)
                    or not re.fullmatch(r"0|[1-9][0-9]{0,3}", length) or int(length) > 4096
                    or self.command not in ("GET", "DELETE")
                    or length != "0"):
                raise ValueError("invalid_request")
            url = urllib.parse.urlsplit(self.path)
            if url.scheme or url.netloc or url.fragment or "%" in url.path or "//" in url.path or "\\" in url.path:
                raise ValueError("invalid_target")
            pairs = urllib.parse.parse_qsl(url.query, keep_blank_values=True, strict_parsing=True, max_num_fields=6, encoding="utf-8", errors="strict")
            query = dict(pairs)
            if len(query) != len(pairs):
                raise ValueError("duplicate_query")
            return url.path, query
        except OSError:
            # A timed-out/broken body is no longer an HTTP exchange we can
            # answer. The TLS transport records the deadline and owns cleanup.
            self.close_connection = True
            return None
        except (ValueError, UnicodeError):
            self.reject()
            return None


    def payload(self, name):
        state = self.server.state
        if state.mode == "read_denied":
            state.read_denied += 1
            state.events.append(("read_denied", name))
            self.reply(403, state.files[name], {"Content-Type": "application/octet-stream"})
            return
        super().payload(name)

    def dispatch(self):
        with self.server.state.lock:
            request=self.wire()
            if request is None:return
            path,query=request;state=self.server.state
            if self.headers.get("Cookie") is not None:self.reject();return
            route=re.fullmatch(r"/(2|3)/drive/290/files/([0-9]+)(?:/(files|name|download))?",path)
            if route is None:self.reject();return
            version,ident,action=route.groups()
            download=version=="2" and action=="download" and int(ident) in FILES.values()
            api=version=="3" and action in (None,"files","name")
            if (not download and not api or self.command=="DELETE" and not download
                    or self.headers.get("Range") is not None and (not download or self.command!="GET")):
                self.reject();return
            if not hmac.compare_digest(self.headers.get("Authorization","").encode(),("Bearer "+state.password).encode()):
                state.denied+=1;state.events.append(("credentials_denied",""))
                self.json_reply(401,{"result":"error","error":{"code":"unauthorized","description":"synthetic invalid bearer"}})
                return
            state.authenticated+=1
            if download:
                name=next(name for name,number in FILES.items() if number==int(ident))
                if query or name not in state.observed:self.reject()
                elif self.command=="DELETE":self.write_denial(name)
                else:self.payload(name)
                return
            if action is None:
                known={**FOLDERS,**FILES}
                names=[name for name,number in known.items() if number==int(ident)]
                if query!={"with":"path"} or not names or (names[0] in FILES and names[0] not in state.observed):
                    self.reject();return
                self.json_reply(200,{"result":"success","data":state.metadata(names[0])});return
            if int(ident) not in FOLDERS.values():self.reject();return
            directory=next(name for name,number in FOLDERS.items() if number==int(ident))
            if action=="files":
                recursive="depth" in query
                expected={"limit":"1000","with":"path,hash"}
                if recursive:expected["depth"]="unlimited"
                if query!=expected:self.reject();return
                self.json_reply(200,state.listing(directory,recursive));return
            name=query.get("name","")
            if (set(query)!={"name","with"} or query["with"]!="path,hash" or not name or len(name)>160
                    or "/" in name or "\\" in name or name in (".","..")
                    or any(ord(c)<32 for c in name)):
                self.reject();return
            member=(directory+"/" if directory else "")+name
            if member not in children(directory,state.files):
                state.missing+=1;state.events.append(("missing",directory))
                self.json_reply(404,{"result":"error","error":{"code":"object_not_found","description":"synthetic missing member"}})
                return
            if member in FILES:state.observed.add(member)
            state.events.append(("lookup",member))
            self.json_reply(200,{"result":"success","data":state.metadata(member)})

    do_GET=dispatch
    do_HEAD=dispatch
    do_POST=dispatch
    do_PUT=dispatch
    do_DELETE=dispatch

@contextmanager
def serve_kdrive(root, state):
    certificates, transport = None, None
    try:
        certificates = FixtureCertificates.create(root, server_name=KDRIVE_API_NAME)
        transport = BoundedHttpsServer(certificates, KdriveHandler, state=state,
                                       limits=TlsLimits(connection_limit=128, active_limit=4,
                                                        request_seconds=3, lifetime_seconds=120))
        transport.start()
        yield certificates, transport
    finally:
        transport_ok = transport is None or transport.close()
        material_ok = certificates is None or certificates.close()
        state.cleanup_complete = transport_ok and material_ok
        if not state.cleanup_complete:
            raise RuntimeError("kdrive_cleanup_failed")
