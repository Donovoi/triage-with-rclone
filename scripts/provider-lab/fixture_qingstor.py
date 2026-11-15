"""Independent QingStor configured-key signing and synthetic-bucket reads."""
from contextlib import contextmanager
import base64
import email.utils
import hashlib
import hmac
import re
import time
import urllib.parse
from fixture_read_api import ReadState, ReadHandler
from fixture_servers import children
from fixture_tls import FixtureCertificates, BoundedHttpsServer, TlsLimits, QINGSTOR_API_NAME

BUCKET = "synthetic-bucket"
STAMP = "Mon, 01 Jan 2024 00:00:00 GMT"

def authorization(method, canonical_path, date, key, secret):
    # This profile admits no Content-MD5/Type, X-QS headers or signed subresources.
    # Listing controls are not signed by the SDK and are separately scoped.
    message = (method + "\n\n\n" + date + "\n" + canonical_path).encode("ascii")
    signature = base64.b64encode(hmac.new(secret.encode(), message, hashlib.sha256).digest()).decode("ascii")
    return "QS " + key + ":" + signature

class QingStorState(ReadState):
    def __init__(self, key, secret):
        if not key or not secret:
            raise ValueError("missing_qingstor_key")
        super().__init__(secret)
        self.key, self.observed = key, set()

    def metadata(self, name):
        return {"key": name, "size": len(self.files[name]),
                "etag": hashlib.md5(self.files[name]).hexdigest(),
                "mime_type": "application/octet-stream", "modified": 1704067200,
                "created": "2024-01-01T00:00:00Z", "encrypted": False, "storage_class": "STANDARD"}

    def folder(self, name):
        keys, prefixes = [], []
        for path in children(name, self.files):
            if path in self.files:
                self.observed.add(path)
                keys.append(self.metadata(path))
            else:
                prefixes.append(path + "/")
        return keys, prefixes

class QingStorHandler(ReadHandler):
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
                    or self.headers.get_all("Host") != [QINGSTOR_API_NAME + ":443"]
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
            pairs = urllib.parse.parse_qsl(url.query, keep_blank_values=True, strict_parsing=True, max_num_fields=4, encoding="utf-8", errors="strict")
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
        self.json_reply(status, {"code": code, "message": "synthetic QingStor rejection",
                                 "request_id": "synthetic-request", "url": ""})

    def payload(self, name):
        state = self.server.state
        if state.mode == "read_denied":
            state.read_denied += 1
            state.events.append(("read_denied", name))
            self.api_error(403, "permission_denied")
            return
        body, status = state.files[name], 200
        headers = {"Content-Type": "application/octet-stream", "ETag": '"' + state.metadata(name)["etag"] + '"',
                   "Last-Modified": STAMP, "X-QS-Request-ID": "synthetic-request"}
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
            listing = path == "/" + BUCKET
            name = path.removeprefix("/" + BUCKET + "/") if path.startswith("/" + BUCKET + "/") else None
            if (not listing and name is None or self.headers.get("Cookie") is not None
                    or self.headers.get("Content-MD5") is not None or self.headers.get("Content-Type") is not None
                    or any(key.lower().startswith("x-qs-") for key in self.headers)
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
            expected = authorization(self.command, urllib.parse.quote(path, safe="/="), date, state.key, state.password) if fresh else ""
            if not fresh or not hmac.compare_digest(self.headers.get("Authorization", "").encode(), expected.encode()):
                state.denied += 1
                state.events.append(("credentials_denied", ""))
                self.api_error(403, "signature_not_match")
                return
            state.authenticated += 1
            if listing:
                if (set(query) != {"delimiter", "limit", "prefix"} or query["delimiter"] not in ("", "/")
                        or query["limit"] != "1000" or query["prefix"] not in ("", "nested/", "absent-synthetic.txt/")):
                    self.reject()
                    return
                prefix = query["prefix"]
                if prefix == "absent-synthetic.txt/":
                    state.missing += 1
                    state.events.append(("missing_prefix", ""))
                    keys, prefixes = [], []
                elif query["delimiter"] == "":
                    directory = prefix.rstrip("/")
                    names = [name for name in sorted(state.files) if name.startswith(prefix)]
                    state.observed.update(names)
                    state.events.append(("listing_recursive", directory))
                    keys, prefixes = [state.metadata(name) for name in names], []
                else:
                    directory = prefix.rstrip("/")
                    state.events.append(("listing", directory))
                    keys, prefixes = state.folder(directory)
                self.json_reply(200, {"name": BUCKET, "prefix": prefix, "delimiter": query["delimiter"], "limit": 1000,
                                      "has_more": False, "keys": keys, "common_prefixes": prefixes})
                return
            if query:
                self.reject()
                return
            if name in ("nested", "nested/", "absent-synthetic.txt"):
                state.missing += 1
                state.events.append(("missing", name))
                self.api_error(404, "key_not_exist")
                return
            if name not in state.files:
                self.reject()
                return
            if self.command == "HEAD":
                state.observed.add(name)
                state.events.append(("metadata", name))
                self.reply(200, state.files[name], {"Content-Type": "application/octet-stream",
                           "ETag": '"' + state.metadata(name)["etag"] + '"', "Last-Modified": STAMP,
                           "X-QS-Request-ID": "synthetic-request"})
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
def serve_qingstor(root, state):
    certificates, transport = None, None
    try:
        certificates = FixtureCertificates.create(root, server_name=QINGSTOR_API_NAME)
        transport = BoundedHttpsServer(certificates, QingStorHandler, state=state,
                                       limits=TlsLimits(connection_limit=128, active_limit=4,
                                                        request_seconds=3, lifetime_seconds=120))
        transport.start()
        yield certificates, transport
    finally:
        transport_ok = transport is None or transport.close()
        material_ok = certificates is None or certificates.close()
        state.cleanup_complete = transport_ok and material_ok
        if not state.cleanup_complete:
            raise RuntimeError("qingstor_cleanup_failed")
