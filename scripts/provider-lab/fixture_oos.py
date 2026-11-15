"""Independent Oos configured-key signing and synthetic-bucket reads."""
from contextlib import contextmanager
import base64
import email.utils
import hashlib
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import re
import time
import urllib.parse
from fixture_read_api import ReadState, ReadHandler
from fixture_servers import children
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits, OOS_API_NAME

BUCKET = "synthetic-bucket"
NAMESPACE = "synthetic-namespace"
API = "/n/" + NAMESPACE + "/b/" + BUCKET + "/o"
FIELDS = "name,size,etag,timeCreated,md5,timeModified,storageTier,archivalState"
STAMP = "Mon, 01 Jan 2024 00:00:00 GMT"

def signing_string(method, target, date, host=OOS_API_NAME):
    # The request-target includes the exact escaped path AND raw query order.
    return ("date: " + date + "\n(request-target): " + method.lower() + " " +
            target + "\nhost: " + host).encode("ascii")

def authorization(method, target, date, key_id, private_key, host=OOS_API_NAME):
    signature = private_key.sign(signing_string(method, target, date, host), padding.PKCS1v15(), hashes.SHA256())
    return ('Signature version="1",headers="date (request-target) host",keyId="' + key_id +
            '",algorithm="rsa-sha256",signature="' + base64.b64encode(signature).decode("ascii") + '"')

class OosState(ReadState):
    def __init__(self, key_id, public_key):
        if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size != 2048 or not key_id:
            raise ValueError("invalid_oos_key")
        super().__init__("synthetic-oos-configured-key")
        self.key_id, self.public_key, self.observed = key_id, public_key, set()

    def metadata(self, name):
        return {"name": name, "size": len(self.files[name]),
                "etag": "synthetic-etag-" + str(sorted(self.files).index(name) + 1),
                "md5": base64.b64encode(hashlib.md5(self.files[name]).digest()).decode("ascii"),
                "timeCreated": "2024-01-01T00:00:00Z", "timeModified": "2024-01-01T00:00:00Z",
                "storageTier": "Standard"}

    def folder(self, name):
        keys, prefixes = [], []
        for path in children(name, self.files):
            if path in self.files:
                self.observed.add(path)
                keys.append(self.metadata(path))
            else:
                prefixes.append(path + "/")
        return keys, prefixes

class OosHandler(ReadHandler):
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
                    or self.headers.get_all("Host") != [OOS_API_NAME]
                    or len(names) != len(set(names))
                    or sum(len(k) + len(v) for k, v in headers) > 16384
                    or any("\r" in v or "\n" in v for _, v in headers)
                    or self.headers.get("Transfer-Encoding") is not None
                    or re.search(r"%(?![0-9a-fA-F]{2})", self.path)
                    or not re.fullmatch(r"0|[1-9][0-9]{0,3}", length) or int(length) > 4096
                    or self.command not in ("GET", "HEAD", "DELETE")
                    or length != "0"):
                raise ValueError("invalid_request")
            url = urllib.parse.urlsplit(self.path)
            if url.scheme or url.netloc or url.fragment or "//" in url.path or "\\" in url.path:
                raise ValueError("invalid_target")
            pairs = urllib.parse.parse_qsl(url.query, keep_blank_values=True, strict_parsing=True, max_num_fields=5, encoding="utf-8", errors="strict")
            query = dict(pairs)
            if len(query) != len(pairs):
                raise ValueError("duplicate_query")
            path = urllib.parse.unquote(url.path, encoding="utf-8", errors="strict")
            if urllib.parse.quote(path, safe="/=") != url.path:
                raise ValueError("noncanonical_path")
            return path, query
        except OSError:
            # A timed-out/broken body is no longer an HTTP exchange we can
            # answer. The TLS transport records the deadline and owns cleanup.
            self.close_connection = True
            return None
        except (ValueError, UnicodeError):
            self.reject()
            return None


    def api_error(self, status, code):
        self.json_reply(status, {"code": code, "message": "synthetic OOS rejection"})

    def payload(self, name):
        state = self.server.state
        if state.mode == "read_denied":
            state.read_denied += 1
            state.events.append(("read_denied", name))
            self.api_error(403, "NotAuthorized")
            return
        body, status = state.files[name], 200
        headers = {"Content-Type": "application/octet-stream", "ETag": '"' + state.metadata(name)["etag"] + '"',
                   "Last-Modified": STAMP, "opc-request-id": "synthetic-request",
                   "Content-MD5": state.metadata(name)["md5"], "storage-tier": "Standard"}
        requested = self.headers.get("Range")
        if requested is not None:
            match = re.fullmatch(r"bytes=([0-9]{1,19})-([0-9]{0,19})", requested)
            if not match:
                self.reject(416)
                return
            start = int(match[1]);end = int(match[2]) if match[2] else len(body) - 1
            if start >= len(body) or start > end:
                self.reject(416)
                return
            end = min(end, len(body) - 1)
            headers["Content-Range"] = f"bytes {start}-{end}/{len(body)}"
            body, status = body[start:end + 1], 206
        state.events.append(("content", name))
        self.reply(status, body, headers, object_payload=True)

    def dispatch(self):
        with self.server.state.lock:
            request = self.wire()
            if request is None:
                return
            path, query = request
            state = self.server.state
            listing = path == API
            name = path[len(API) + 1:] if path.startswith(API + "/") else None
            if (not listing and name is None or self.headers.get("Cookie") is not None
                    or self.headers.get("Content-MD5") is not None or self.headers.get("Content-Type") != "application/json"
                    or any(key.lower().startswith(("x-date", "x-content-", "opc-sse-", "opc-obo-", "if-")) for key in self.headers)
                    or listing and self.command != "GET"
                    or self.headers.get("Range") is not None and (listing or self.command != "GET")):
                self.reject()
                return
            date = self.headers.get("Date", "")
            try:
                parsed = email.utils.parsedate_to_datetime(date)
                fresh = (parsed.utcoffset().total_seconds() == 0 and
                         email.utils.format_datetime(parsed, usegmt=True) == date and
                         abs(time.time() - parsed.timestamp()) <= 300)
            except (TypeError, ValueError, OverflowError, AttributeError):
                fresh = False
            authenticated = False
            auth = self.headers.get("Authorization", "")
            match = re.fullmatch(r'Signature version="1",headers="date \(request-target\) host",keyId="([^"\\\r\n]{1,512})",algorithm="rsa-sha256",signature="([A-Za-z0-9+/]{342}==)"', auth)
            if fresh and match and match[1] == state.key_id:
                try:
                    signature = base64.b64decode(match[2], validate=True)
                    if base64.b64encode(signature).decode("ascii") != match[2]:
                        raise ValueError("noncanonical_signature")
                    state.public_key.verify(signature, signing_string(self.command, self.path, date),
                                            padding.PKCS1v15(), hashes.SHA256())
                    authenticated = True
                except (InvalidSignature, ValueError, UnicodeError):
                    pass
            if not authenticated:
                state.denied += 1
                state.events.append(("credentials_denied", ""))
                self.api_error(401, "NotAuthenticated")
                return
            state.authenticated += 1
            if listing:
                if (set(query) not in ({"fields", "limit", "prefix"}, {"fields", "limit", "prefix", "delimiter"})
                        or query.get("delimiter", "/") != "/" or query["fields"] != FIELDS
                        or query["limit"] != "1000" or query["prefix"] not in ("", "nested/", "absent-synthetic.txt/")):
                    self.reject()
                    return
                prefix = query["prefix"]
                if prefix == "absent-synthetic.txt/":
                    state.missing += 1
                    state.events.append(("missing_prefix", ""))
                    keys, prefixes = [], []
                elif "delimiter" not in query:
                    directory = prefix.rstrip("/")
                    names = [name for name in sorted(state.files) if name.startswith(prefix)]
                    state.observed.update(names)
                    state.events.append(("listing_recursive", directory))
                    keys, prefixes = [state.metadata(name) for name in names], []
                else:
                    directory = prefix.rstrip("/")
                    state.events.append(("listing", directory))
                    keys, prefixes = state.folder(directory)
                self.json_reply(200, {"objects": keys, "prefixes": prefixes})
                return
            if query:
                self.reject()
                return
            if name in ("nested", "nested/", "absent-synthetic.txt"):
                state.missing += 1
                state.events.append(("missing", name))
                self.api_error(404, "ObjectNotFound")
                return
            if name not in state.files:
                self.reject()
                return
            if self.command == "HEAD":
                state.observed.add(name)
                state.events.append(("metadata", name))
                self.reply(200, state.files[name], {"Content-Type": "application/octet-stream",
                           "ETag": '"' + state.metadata(name)["etag"] + '"', "Last-Modified": STAMP,
                           "opc-request-id": "synthetic-request",
                   "Content-MD5": state.metadata(name)["md5"], "storage-tier": "Standard"})
            elif name not in state.observed:
                self.reject()
            elif self.command == "DELETE":
                self.write_denial(name)
            else:
                self.payload(name)

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch


@contextmanager
def serve_oos(root, state):
    certificates, transport = None, None
    try:
        certificates = FixtureCertificates.create(root, server_name=OOS_API_NAME)
        transport = BoundedHttpsServer(certificates, OosHandler, state=state,
                                       limits=TlsLimits(connection_limit=128, active_limit=4,
                                                        request_seconds=3, lifetime_seconds=120))
        transport.start()
        yield certificates, transport
    finally:
        transport_ok = transport is None or transport.close()
        material_ok = certificates is None or certificates.close()
        state.cleanup_complete = transport_ok and material_ok
        if not state.cleanup_complete:
            raise RuntimeError("oos_cleanup_failed")
