"""Small independent read-only protocol fixtures, never general-purpose servers."""

import base64
from contextlib import contextmanager
from datetime import datetime, timezone
from email.utils import format_datetime, parsedate_to_datetime
import ftplib
import hashlib
import hmac
import html
import http.client
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import posixpath
import re
import secrets
import socket
import socketserver
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape


FILES = {
    "README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
    "nested/space name.txt": b"Nested synthetic payload.\n",
    "nested/bytes.bin": bytes(range(256)) * 8,
}
STAMP = "Mon, 01 Jan 2024 00:00:00 GMT"


def safe_path(raw):
    """Resolve protocol paths only into our in-memory fixture namespace."""
    path = urllib.parse.unquote(urllib.parse.urlsplit(raw).path)
    if "\\" in path or "\x00" in path or any(p == ".." for p in path.split("/")):
        raise ValueError("unsafe_path")
    return path.strip("/")


def is_directory(path, files=FILES):
    return not path or any(name.startswith(path + "/") for name in files)


def children(path, files=FILES):
    prefix = path + "/" if path else ""
    return sorted({prefix + name[len(prefix):].split("/")[0]
                   for name in files if name.startswith(prefix)})


class State:
    def __init__(self, user, password):
        self.user, self.password = user, password
        self.files = dict(FILES)
        self.denied = 0
        self.rejected_mutations = 0
        self.payload_bytes = 0
        self.requests = 0
        self.mode = "normal"
        self.stalled = threading.Event()
        self.stopping = threading.Event()
        self.sockets = set()
        self.lock = threading.Lock()
        self.cleanup_complete = False


class LoopbackThreads(socketserver.ThreadingMixIn):
    daemon_threads = False
    block_on_close = True
    allow_reuse_address = False

    def get_request(self):
        conn, address = super().get_request()
        conn.settimeout(5)
        with self.state.lock:
            self.state.sockets.add(conn)
        return conn, address

    def shutdown_request(self, request):
        with self.state.lock:
            self.state.sockets.discard(request)
        super().shutdown_request(request)

    def handle_error(self, request, client_address):
        # Expected reset/EOF from rejection, truncation and cancellation.
        pass


class HttpFixture(LoopbackThreads, HTTPServer):
    def __init__(self, state):
        self.state = state
        super().__init__(("127.0.0.1", 0), HttpHandler)


class HttpHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):
        pass

    def authorize(self):
        state = self.server.state
        state.requests += 1
        expected = "Basic " + base64.b64encode(
            f"{state.user}:{state.password}".encode()).decode()
        if state.requests > 256:
            self.send_error(429)
            return False
        if self.headers.get("Authorization") != expected:
            state.denied += 1
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="synthetic-fixture"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return False
        return True

    def reply(self, code, body=b"", content_type="application/octet-stream", size=None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body) if size is None else size))
        self.send_header("Last-Modified", STAMP)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if not self.authorize():
            return
        try:
            path = safe_path(self.path)
        except ValueError:
            self.reply(400)
            return
        files = self.server.state.files
        if is_directory(path, files):
            body = "<html><body>" + "".join(
                '<a href="' + urllib.parse.quote(child.split("/")[-1])
                + ("/" if is_directory(child, files) else "") + '">'
                + html.escape(child.split("/")[-1]) + "</a>"
                for child in children(path, files)) + "</body></html>"
            self.reply(200, body.encode(), "text/html")
        elif path in files:
            payload = files[path]
            state = self.server.state
            if self.command == "GET" and state.mode == "stall":
                state.stalled.set()
                state.stopping.wait(10)
                return
            if self.command == "GET" and state.mode == "truncate":
                payload = payload[:3]
            if self.command == "GET":
                state.payload_bytes += len(payload)
            self.reply(200, payload, size=len(files[path]))
        else:
            self.reply(404)

    def do_PROPFIND(self):
        if not self.authorize():
            return
        try:
            path = safe_path(self.path)
        except ValueError:
            self.reply(400)
            return
        files = self.server.state.files
        if path not in files and not is_directory(path, files):
            self.reply(404)
            return
        depth = self.headers.get("Depth", "1")
        if depth not in ("0", "1"):
            self.reply(403)
            return
        paths = [path] + (children(path, files) if depth == "1" and is_directory(path, files) else [])
        body = '<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">'
        for item in paths:
            directory = is_directory(item, files)
            href = "/" + urllib.parse.quote(item) + ("/" if directory and item else "")
            body += ("<d:response><d:href>" + escape(href)
                     + "</d:href><d:propstat><d:prop><d:resourcetype>"
                     + ("<d:collection/>" if directory else "")
                     + "</d:resourcetype><d:getcontentlength>"
                     + str(0 if directory else len(files[item]))
                     + "</d:getcontentlength><d:getlastmodified>" + STAMP
                     + "</d:getlastmodified></d:prop><d:status>HTTP/1.1 200 OK"
                     + "</d:status></d:propstat></d:response>")
        self.reply(207, (body + "</d:multistatus>").encode(), "application/xml")

    def do_PUT(self):
        if self.authorize():
            self.server.state.rejected_mutations += 1
            self.reply(405)

    do_DELETE = do_PUT
    do_MKCOL = do_PUT
    do_MOVE = do_PUT
    do_COPY = do_PUT


def azure_string_to_sign(account, method, target, headers):
    """Documented SharedKey subset: preserve escaped URI, reject duplicates."""
    if not target.startswith("/") or any(ord(char) <= 32 or ord(char) >= 127 for char in target):
        raise ValueError("invalid_raw_signed_target")
    values = {}
    for name, value in headers:
        name = name.lower()
        if name in values or not re.fullmatch(r"[a-z0-9-]+", name) or "\r" in value or "\n" in value:
            raise ValueError("ambiguous_signed_header")
        values[name] = value.strip()
    url = urllib.parse.urlsplit(target)
    if url.scheme or url.netloc or url.fragment or re.search(r"%(?![0-9A-Fa-f]{2})", target):
        raise ValueError("invalid_signed_target")
    pairs = urllib.parse.parse_qsl(url.query, keep_blank_values=True, strict_parsing=True, max_num_fields=8)
    query = {}
    for name, value in pairs:
        name = name.lower()
        if name in query or not re.fullmatch(r"[a-z0-9-]+", name) or "\r" in value or "\n" in value:
            raise ValueError("ambiguous_signed_query")
        query[name] = value
    length = values.get("content-length", "")
    fields = [method, values.get("content-encoding", ""), values.get("content-language", ""),
              "" if length == "0" else length, values.get("content-md5", ""), values.get("content-type", ""), "",
              *(values.get(name, "") for name in ("if-modified-since", "if-match", "if-none-match", "if-unmodified-since", "range"))]
    fields.append("\n".join(name + ":" + values[name] for name in sorted(values) if name.startswith("x-ms-")))
    resource = "/" + account + (url.path or "/")
    resource += "".join("\n" + name + ":" + query[name] for name in sorted(query))
    fields.append(resource)
    return "\n".join(fields)


class AzureBlobState(State):
    account = "syntheticaccount"
    container = "synthetic-container"

    def __init__(self, key, utc_now=None):
        super().__init__(self.account, key)
        self.key_bytes = base64.b64decode(key, validate=True)
        if len(self.key_bytes) != 32:
            raise ValueError("invalid_synthetic_azure_key")
        self.utc_now = utc_now or (lambda: datetime.now(timezone.utc))
        self.deadline = time.monotonic() + 60
        self.request_limit = 128
        self.request_timeout = 3
        self.auth_denied = self.stale_denied = self.authenticated = 0
        self.missing = self.unexpected = self.rejected_payload_bytes = 0
        self.budget_exceeded = False


class AzureBlobFixture(LoopbackThreads, HTTPServer):
    def __init__(self, state):
        self.state = state
        super().__init__(("127.0.0.1", 0), AzureBlobHandler)


class AzureBlobHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):
        pass

    def handle(self):
        # Bound the whole request, including slow request-line/header/body
        # feeds. The timer owns only this accepted socket and is always joined.
        state = self.server.state
        expired = threading.Event()

        def close_expired():
            expired.set()
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        timer = threading.Timer(max(0.001, min(state.request_timeout, state.deadline - time.monotonic())), close_expired)
        timer.start()
        try:
            super().handle()
        finally:
            timer.cancel()
            timer.join()
            if expired.is_set():
                with state.lock:
                    state.budget_exceeded = True
                    state.unexpected += 1

    def reply(self, status, body=b"", headers=None, size=None, object_payload=False):
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Length", str(len(body) if size is None else size))
        self.send_header("x-ms-request-id", "synthetic-request")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            if object_payload:
                if status >= 400:
                    self.server.state.rejected_payload_bytes += len(body)
                else:
                    self.server.state.payload_bytes += len(body)
            self.wfile.write(body)

    def error(self, status, code):
        body = (f'<Error><Code>{code}</Code><Message>Synthetic fixture response.</Message></Error>').encode()
        self.reply(status, body, {"Content-Type": "application/xml", "x-ms-error-code": code})

    def reject(self, code="InvalidQueryParameterValue"):
        self.server.state.unexpected += 1
        self.error(400, code)

    def dispatch(self):
        with self.server.state.lock:
            state = self.server.state
            state.requests += 1
            if state.requests > state.request_limit or time.monotonic() > state.deadline:
                state.budget_exceeded = True
                self.error(429, "ServerBusy")
                return
            host = f"127.0.0.1:{self.server.server_address[1]}"
            if (self.headers.get_all("Host") != [host] or len(self.path) > 2048
                    or sum(len(name) + len(value) for name, value in self.headers.items()) > 8192
                    or self.headers.get("Transfer-Encoding") is not None):
                self.reject()
                return
            try:
                # BaseHTTPRequestHandler normalizes a leading // to /. Signed
                # paths must retain the exact target bytes received on the wire.
                wire_parts = self.raw_requestline.rstrip(b"\r\n").split(b" ")
                if len(wire_parts) != 3 or wire_parts[1].decode("ascii") != self.path:
                    raise ValueError("normalized_signed_target")
                signed = azure_string_to_sign(state.account, self.command, self.path, self.headers.items())
                length = self.headers.get("Content-Length", "0")
                if not length.isdigit() or int(length) > 4096 or (self.command in ("GET", "HEAD") and int(length)):
                    raise ValueError("invalid_body_length")
                url = urllib.parse.urlsplit(self.path)
                query = dict(urllib.parse.parse_qsl(url.query, keep_blank_values=True, strict_parsing=True, max_num_fields=8))
                base = "/" + state.account + "/" + state.container
                # The SDK escapes nested separators in blob names. Preserve
                # those bytes when signing, then decode exactly once for lookup.
                if url.path != base and not url.path.startswith(base + "/"):
                    raise ValueError("unowned_path")
                name = urllib.parse.unquote(url.path[len(base) + 1:], errors="strict") if url.path != base else ""
                if url.path != base and not name:
                    raise ValueError("empty_member")
                if name and ("\\" in name or "\x00" in name or "%" in name
                             or any(part in ("", ".", "..") for part in name.split("/"))):
                    raise ValueError("invalid_member")
                if self.headers.get("Date") is not None:
                    raise ValueError("ambiguous_date")
                allowed_xms = {"x-ms-date", "x-ms-version", "x-ms-client-request-id", "x-ms-range"}
                if any(key.lower().startswith("x-ms-") and key.lower() not in allowed_xms for key in self.headers):
                    raise ValueError("unsupported_header")
                if any(self.headers.get(key) is not None for key in ("If-Modified-Since", "If-None-Match", "If-Unmodified-Since")):
                    raise ValueError("unsupported_condition")
            except (ValueError, UnicodeError):
                self.reject()
                return
            signature = base64.b64encode(hmac.new(state.key_bytes, signed.encode(), hashlib.sha256).digest()).decode()
            expected = f"SharedKey {state.account}:{signature}"
            try:
                date = self.headers.get("x-ms-date", "")
                instant = parsedate_to_datetime(date)
                datetime.strptime(self.headers.get("x-ms-version", ""), "%Y-%m-%d")
                if (instant.tzinfo is None or instant.utcoffset().total_seconds() != 0
                        or format_datetime(instant, usegmt=True) != date
                        or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", self.headers.get("x-ms-version", ""))):
                    raise ValueError("invalid_date_version")
                age = (state.utc_now() - instant).total_seconds()
                valid_signature = hmac.compare_digest(self.headers.get("Authorization", ""), expected)
                valid_date = 0 <= age <= 900
            except (ValueError, TypeError, OverflowError):
                valid_signature = valid_date = False
            if not valid_signature or not valid_date:
                state.auth_denied += 1
                if valid_signature and not valid_date:
                    state.stale_denied += 1
                self.error(403, "AuthenticationFailed")
                return
            state.authenticated += 1
            if self.command in ("PUT", "DELETE", "POST"):
                if not name or query:
                    self.reject()
                    return
                state.rejected_mutations += 1
                self.error(403, "AuthorizationPermissionMismatch")
                return
            if self.command not in ("HEAD", "GET"):
                self.reject()
                return
            if not name:
                if self.command != "GET" or self.headers.get("Range") is not None or self.headers.get("x-ms-range") is not None:
                    self.reject()
                    return
                self.list_blobs(query)
                return
            if query:
                self.reject()
                return
            if name not in state.files:
                state.missing += 1
                self.error(404, "BlobNotFound")
                return
            payload = state.files[name]
            etag = '"synthetic-' + hashlib.md5(payload).hexdigest() + '"'
            if self.headers.get("If-Match") not in (None, etag, "*"):
                self.error(412, "ConditionNotMet")
                return
            headers = {"Content-Type": "application/octet-stream", "ETag": etag, "Last-Modified": STAMP,
                       "Content-MD5": base64.b64encode(hashlib.md5(payload).digest()).decode(),
                       "x-ms-blob-type": "BlockBlob", "x-ms-meta-mtime": "2024-01-01T00:00:00Z"}
            standard_range, azure_range = self.headers.get("Range"), self.headers.get("x-ms-range")
            if standard_range is not None or (azure_range is not None and self.command != "GET"):
                self.reject()
                return
            if self.command == "HEAD":
                self.reply(200, headers=headers, size=len(payload))
                return
            code = 200
            if azure_range is not None:
                match = re.fullmatch(r"bytes=(\d+)-(\d*)", azure_range)
                if not match:
                    self.reject("InvalidRange")
                    return
                start, end = int(match[1]), int(match[2]) if match[2] else len(payload) - 1
                if start > end or end >= len(payload):
                    self.reject("InvalidRange")
                    return
                headers["Content-Range"] = f"bytes {start}-{end}/{len(payload)}"
                headers["x-ms-blob-content-md5"] = headers["Content-MD5"]
                payload, code = payload[start:end + 1], 206
                headers["Content-MD5"] = base64.b64encode(hashlib.md5(payload).digest()).decode()
            self.reply(code, payload, headers, object_payload=True)

    def list_blobs(self, query):
        state = self.server.state
        if (set(query) - {"restype", "comp", "delimiter", "prefix", "marker", "maxresults", "include"}
                or query.get("restype") != "container" or query.get("comp") != "list"
                or query.get("include") not in (None, "metadata") or query.get("delimiter", "") not in ("", "/")
                or query.get("marker", "") != "" or not re.fullmatch(r"[0-9]+", query.get("maxresults", "5000"))
                or not 1 <= int(query.get("maxresults", "5000")) <= 5000):
            self.reject()
            return
        prefix, delimiter = query.get("prefix", ""), query.get("delimiter", "")
        if "\\" in prefix or "\x00" in prefix or any(part in (".", "..") for part in prefix.split("/")):
            self.reject()
            return
        rows = {}
        for name in sorted(state.files):
            if name.startswith(prefix):
                if delimiter and "/" in name[len(prefix):]:
                    rows[prefix + name[len(prefix):].split("/", 1)[0] + "/"] = False
                else:
                    rows[name] = True
        if len(rows) > int(query.get("maxresults", "5000")):
            self.reject("UnsupportedPagination")
            return
        root = ET.Element("EnumerationResults", {"ServiceEndpoint": f"http://127.0.0.1:{self.server.server_address[1]}/{state.account}",
                                                 "ContainerName": state.container})
        blobs = ET.SubElement(root, "Blobs")
        for name, is_file in sorted(rows.items()):
            entry = ET.SubElement(blobs, "Blob" if is_file else "BlobPrefix")
            ET.SubElement(entry, "Name").text = name
            if is_file:
                payload = state.files[name]
                props = ET.SubElement(entry, "Properties")
                for key, value in {"Content-Length": str(len(payload)), "Content-Type": "application/octet-stream",
                                   "Content-MD5": base64.b64encode(hashlib.md5(payload).digest()).decode(),
                                   "Last-Modified": STAMP, "Etag": '"synthetic-' + hashlib.md5(payload).hexdigest() + '"',
                                   "BlobType": "BlockBlob"}.items():
                    ET.SubElement(props, key).text = value
                ET.SubElement(ET.SubElement(entry, "Metadata"), "mtime").text = "2024-01-01T00:00:00Z"
        ET.SubElement(root, "NextMarker")
        self.reply(200, ET.tostring(root, encoding="utf-8", xml_declaration=True), {"Content-Type": "application/xml"})

    do_GET = dispatch
    do_HEAD = dispatch
    do_PUT = dispatch
    do_POST = dispatch
    do_DELETE = dispatch


class AzureFilesState(AzureBlobState):
    """Native FileREST SharedKey fixture; no Blob/emulator route semantics."""
    share = "synthetic-share"
    file_time = "2024-01-01T00:00:00.0000000Z"
    # Deliberately different from LastWriteTime: the native listing must use
    # the Files timestamp, not silently fall back to the HTTP modified time.
    last_modified = "Tue, 02 Jan 2024 00:00:00 GMT"

    def __init__(self, key, utc_now=None):
        super().__init__(key, utc_now)
        self.read_auth_denied = self.root_probe_denied = 0
        self.root_file_probes = self.directory_properties = self.directory_lists = 0


class AzureFilesFixture(LoopbackThreads, HTTPServer):
    def __init__(self, state):
        self.state = state
        super().__init__(("127.0.0.1", 0), AzureFilesHandler)


class AzureFilesHandler(AzureBlobHandler):
    # Reuse only the reviewed transport deadline/reply and signing primitives;
    # directory/file routes, response types and timestamps are Files-specific.
    def dispatch(self):
        with self.server.state.lock:
            state = self.server.state
            state.requests += 1
            if state.requests > state.request_limit or time.monotonic() > state.deadline:
                state.budget_exceeded = True
                self.error(429, "ServerBusy")
                return
            host = f"127.0.0.1:{self.server.server_address[1]}"
            if (self.headers.get_all("Host") != [host] or len(self.path) > 2048
                    or sum(len(name) + len(value) for name, value in self.headers.items()) > 8192
                    or self.headers.get("Transfer-Encoding") is not None):
                self.reject()
                return
            try:
                # FileREST signs the original escaped path, never the HTTP
                # parser's normalized spelling of that path.
                wire_parts = self.raw_requestline.rstrip(b"\r\n").split(b" ")
                if len(wire_parts) != 3 or wire_parts[1].decode("ascii") != self.path:
                    raise ValueError("normalized_signed_target")
                signed = azure_string_to_sign(state.account, self.command, self.path, self.headers.items())
                length = self.headers.get("Content-Length", "0")
                if not length.isdigit() or int(length) > 4096 or (self.command in ("GET", "HEAD") and int(length)):
                    raise ValueError("invalid_body_length")
                url = urllib.parse.urlsplit(self.path)
                query = dict(urllib.parse.parse_qsl(url.query, keep_blank_values=True, strict_parsing=True, max_num_fields=8))
                base = "/" + state.account + "/" + state.share
                if not url.path.startswith(base + "/"):
                    raise ValueError("unowned_path")
                name = urllib.parse.unquote(url.path[len(base) + 1:], errors="strict")
                if name and ("\\" in name or "\x00" in name or "%" in name
                             or any(part in ("", ".", "..") for part in name.split("/"))):
                    raise ValueError("invalid_member")
                if self.headers.get("Date") is not None:
                    raise ValueError("ambiguous_date")
                allowed_xms = {"x-ms-date", "x-ms-version", "x-ms-client-request-id", "x-ms-range", "x-ms-file-request-intent"}
                if any(key.lower().startswith("x-ms-") and key.lower() not in allowed_xms for key in self.headers):
                    raise ValueError("unsupported_header")
                if self.headers.get("x-ms-file-request-intent") != "backup":
                    raise ValueError("unsupported_request_intent")
                if any(self.headers.get(key) is not None for key in ("If-Modified-Since", "If-Match", "If-None-Match", "If-Unmodified-Since")):
                    raise ValueError("unsupported_condition")
            except (ValueError, UnicodeError):
                self.reject()
                return
            signature = base64.b64encode(hmac.new(state.key_bytes, signed.encode(), hashlib.sha256).digest()).decode()
            expected = f"SharedKey {state.account}:{signature}"
            try:
                date = self.headers.get("x-ms-date", "")
                instant = parsedate_to_datetime(date)
                datetime.strptime(self.headers.get("x-ms-version", ""), "%Y-%m-%d")
                if (instant.tzinfo is None or instant.utcoffset().total_seconds() != 0
                        or format_datetime(instant, usegmt=True) != date
                        or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", self.headers.get("x-ms-version", ""))):
                    raise ValueError("invalid_date_version")
                age = (state.utc_now() - instant).total_seconds()
                valid_signature = hmac.compare_digest(self.headers.get("Authorization", ""), expected)
                valid_date = 0 <= age <= 900
            except (ValueError, TypeError, OverflowError):
                valid_signature = valid_date = False
            if not valid_signature or not valid_date:
                state.auth_denied += 1
                if valid_signature and not valid_date:
                    state.stale_denied += 1
                if self.command in ("GET", "HEAD") and name in state.files and not query:
                    state.read_auth_denied += 1
                if self.command == "HEAD" and not name and not query:
                    state.root_probe_denied += 1
                self.error(403, "AuthenticationFailed")
                return
            state.authenticated += 1
            if self.command in ("PUT", "DELETE", "POST"):
                if not name or query:
                    self.reject()
                    return
                state.rejected_mutations += 1
                self.error(403, "AuthorizationPermissionMismatch")
                return
            if self.command not in ("HEAD", "GET"):
                self.reject()
                return
            azure_range = self.headers.get("x-ms-range")
            if self.headers.get("Range") is not None or (azure_range is not None and (self.command != "GET" or query)):
                self.reject()
                return
            if query:
                if self.command != "GET" or query.get("restype") != "directory":
                    self.reject()
                    return
                if query == {"restype": "directory"}:
                    if not is_directory(name, state.files):
                        state.missing += 1
                        self.error(404, "ResourceNotFound")
                        return
                    state.directory_properties += 1
                    self.reply(200, headers=self.metadata(name, directory=True))
                elif query.get("comp") == "list":
                    self.list_directory(name, query)
                else:
                    self.reject()
                return
            if not name:
                if self.command != "HEAD":
                    self.reject()
                    return
                # The backend deliberately probes a file at the share root
                # during construction and ignores failure. It is not a file.
                state.root_file_probes += 1
                self.error(404, "ResourceNotFound")
                return
            if name not in state.files:
                state.missing += 1
                self.error(404, "ResourceNotFound")
                return
            payload = state.files[name]
            headers = self.metadata(name)
            if self.command == "HEAD":
                self.reply(200, headers=headers, size=len(payload))
                return
            code = 200
            if azure_range is not None:
                match = re.fullmatch(r"bytes=(\d+)-(\d*)", azure_range)
                if not match:
                    self.reject("InvalidRange")
                    return
                start, end = int(match[1]), int(match[2]) if match[2] else len(payload) - 1
                if start > end or end >= len(payload):
                    self.reject("InvalidRange")
                    return
                headers["Content-Range"] = f"bytes {start}-{end}/{len(payload)}"
                headers["x-ms-content-md5"] = headers.pop("Content-MD5")
                payload, code = payload[start:end + 1], 206
            self.reply(code, payload, headers, object_payload=True)

    def metadata(self, name, directory=False):
        state = self.server.state
        identity = hashlib.sha256(name.encode()).hexdigest()[:16]
        headers = {"ETag": '"synthetic-' + identity + '"', "Last-Modified": state.last_modified,
                   "x-ms-file-last-write-time": state.file_time, "x-ms-file-creation-time": state.file_time,
                   "x-ms-file-change-time": state.file_time,
                   "x-ms-file-attributes": "Directory" if directory else "Archive", "x-ms-file-id": identity}
        if not directory:
            headers.update({"Content-Type": "application/octet-stream",
                            "Content-MD5": base64.b64encode(hashlib.md5(state.files[name]).digest()).decode()})
        return headers

    def list_directory(self, name, query):
        state = self.server.state
        if (set(query) - {"restype", "comp", "prefix", "marker", "maxresults", "include"}
                or query.get("include") not in (None, "Timestamps") or query.get("marker", "") != ""
                or not re.fullmatch(r"[0-9]+", query.get("maxresults", "5000"))
                or not 1 <= int(query.get("maxresults", "5000")) <= 5000):
            self.reject()
            return
        prefix = query.get("prefix", "")
        if "\\" in prefix or "\x00" in prefix or any(part in (".", "..") for part in prefix.split("/")):
            self.reject()
            return
        if not is_directory(name, state.files):
            state.missing += 1
            self.error(404, "ResourceNotFound")
            return
        directory_prefix = name + "/" if name else ""
        names = [item for item in children(name, state.files) if item[len(directory_prefix):].startswith(prefix)]
        if len(names) > int(query.get("maxresults", "5000")):
            self.reject("UnsupportedPagination")
            return
        state.directory_lists += 1
        root = ET.Element("EnumerationResults", {"ServiceEndpoint": f"http://127.0.0.1:{self.server.server_address[1]}/{state.account}",
                                                 "ShareName": state.share, "DirectoryPath": name})
        ET.SubElement(root, "Prefix").text = prefix
        ET.SubElement(root, "Marker")
        ET.SubElement(root, "MaxResults").text = query.get("maxresults", "5000")
        entries = ET.SubElement(root, "Entries")
        for path in names:
            is_file = path in state.files
            entry = ET.SubElement(entries, "File" if is_file else "Directory")
            ET.SubElement(entry, "Name").text = path[len(directory_prefix):]
            ET.SubElement(entry, "FileId").text = hashlib.sha256(path.encode()).hexdigest()[:16]
            props = ET.SubElement(entry, "Properties")
            for key, value in {"Content-Length": str(len(state.files[path])) if is_file else "0",
                               "CreationTime": state.file_time, "LastWriteTime": state.file_time,
                               "ChangeTime": state.file_time, "Last-Modified": state.last_modified,
                               "Etag": self.metadata(path, not is_file)["ETag"]}.items():
                ET.SubElement(props, key).text = value
        ET.SubElement(root, "NextMarker")
        self.reply(200, ET.tostring(root, encoding="utf-8", xml_declaration=True), {"Content-Type": "application/xml"})

    do_GET = dispatch
    do_HEAD = dispatch
    do_PUT = dispatch
    do_POST = dispatch
    do_DELETE = dispatch


class SeafileState(State):
    library_id = "11111111-2222-4333-8444-555555555555"
    library_name = "Synthetic Library"
    invalid_cached_token = "invalid-synthetic-cached-token"

    def __init__(self, user, password):
        super().__init__(user, password)
        self.deadline = time.monotonic() + 60
        self.request_timeout = 3
        self.request_limit = 64
        self.byte_limit = 128 * 1024
        self.response_bytes = 0
        self.token = None
        self.login_attempts = self.grants = self.auth_uses = 0
        self.auth_denied = self.cached_denied = self.missing = 0
        self.unexpected = self.rejected_payload_bytes = 0
        self.budget_exceeded = False
        self.events = []
        self.details = set()
        self.links = {}
        self.accepted_connections = self.admission_denied = 0
        self.connection_limit = 64
        self.active_connection_limit = 4


class SeafileFixture(LoopbackThreads, HTTPServer):
    def __init__(self, state):
        self.state = state
        super().__init__(("127.0.0.1", 0), SeafileHandler)

    def get_request(self):
        conn, address = super().get_request()
        state = self.state
        with state.lock:
            state.accepted_connections += 1
            if state.accepted_connections > state.connection_limit or len(state.sockets) > state.active_connection_limit:
                state.budget_exceeded = True
                state.unexpected += 1
                state.admission_denied += 1
                state.sockets.discard(conn)
                conn.close()
                raise OSError("synthetic_connection_limit")
        return conn, address

    def handle_error(self, request, client_address):
        # An unhandled handler failure must never be mistaken for a clean trace.
        with self.state.lock:
            self.state.unexpected += 1


class SeafileHandler(AzureBlobHandler):
    # The inherited whole-request timer closes only this accepted socket and
    # joins its timer on every exit; all HTTP/API semantics below are Seafile.
    def reply(self, status, body=b"", headers=None, object_payload=False):
        state = self.server.state
        if state.response_bytes + len(body) > state.byte_limit:
            state.budget_exceeded = True
            status, body, object_payload = 429, b'{"detail":"fixture byte limit"}', False
        state.response_bytes += len(body)
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            if object_payload:
                if status >= 400:
                    state.rejected_payload_bytes += len(body)
                else:
                    state.payload_bytes += len(body)
            self.wfile.write(body)

    def json_reply(self, status, value):
        self.reply(status, json.dumps(value, separators=(",", ":")).encode(), {"Content-Type": "application/json"})

    def reject(self, status=400):
        self.server.state.unexpected += 1
        self.json_reply(status, {"detail": "synthetic request rejected"})

    def send_error(self, code, message=None, explain=None):
        # BaseHTTPRequestHandler handles unknown methods and parse errors here.
        # They must not disappear from evidence or reflect attacker input.
        with self.server.state.lock:
            self.server.state.unexpected += 1
            self.json_reply(code, {"detail": "synthetic malformed request"})

    def dispatch(self):
        with self.server.state.lock:
            state = self.server.state
            state.requests += 1
            if state.requests > state.request_limit or time.monotonic() > state.deadline:
                state.budget_exceeded = True
                self.json_reply(429, {"detail": "synthetic request limit"})
                return
            host = f"127.0.0.1:{self.server.server_address[1]}"
            headers = list(self.headers.items())
            lowered = [name.lower() for name, _ in headers]
            try:
                wire_parts = self.raw_requestline.rstrip(b"\r\n").split(b" ")
                if (len(wire_parts) != 3 or wire_parts[1].decode("ascii") != self.path
                        or self.headers.get_all("Host") != [host] or len(self.path) > 2048
                        or len(set(lowered)) != len(lowered) or sum(len(k) + len(v) for k, v in headers) > 8192
                        or any("\r" in value or "\n" in value for _, value in headers)
                        or self.headers.get("Transfer-Encoding") is not None or self.headers.get("X-SEAFILE-OTP") is not None
                        or not self.path.startswith("/") or any(ord(char) <= 32 or ord(char) >= 127 for char in self.path)
                        or re.search(r"%(?![0-9A-Fa-f]{2})", self.path)):
                    raise ValueError("invalid_request")
                length = self.headers.get("Content-Length", "0")
                if not length.isdigit() or int(length) > 4096 or (self.command in ("GET", "HEAD") and int(length)):
                    raise ValueError("invalid_length")
                url = urllib.parse.urlsplit(self.path)
                if url.scheme or url.netloc or url.fragment or "%" in url.path or "//" in url.path:
                    raise ValueError("invalid_route")
                pairs = urllib.parse.parse_qsl(url.query, keep_blank_values=True, strict_parsing=True,
                                              max_num_fields=4, encoding="utf-8", errors="strict")
                query = dict(pairs)
                if len(query) != len(pairs):
                    raise ValueError("duplicate_query")
            except (ValueError, UnicodeError):
                self.reject()
                return
            path = url.path
            api = "/api2/repos/" + state.library_id
            directory = "/api/v2.1/repos/" + state.library_id + "/dir/"
            payload_route = bool(re.fullmatch(r"/fixture-download/[0-9a-f]{32}", path))
            if self.headers.get("Range") is not None and not payload_route:
                self.reject()
                return
            if path == "/api2/server-info/":
                if self.command != "GET" or query or self.headers.get("Authorization") is not None or state.events:
                    self.reject()
                    return
                state.events.append(("server_info", ""))
                self.json_reply(200, {"version": "7.0.0"})
                return
            if path == "/api2/auth-token/":
                if (self.command != "POST" or query or self.headers.get("Authorization") is not None
                        or self.headers.get("Content-Type") != "application/json" or not self.headers.get("Content-Length")
                        or state.events != [("server_info", "")] or state.login_attempts):
                    self.reject()
                    return
                try:
                    raw = self.rfile.read(int(length))  # The owned whole-request timer bounds slow feeds.
                    if len(raw) != int(length):
                        raise ValueError("incomplete_body")
                    body = json.loads(raw.decode("utf-8"), object_pairs_hook=B2Handler.unique_object)
                    if (not isinstance(body, dict) or set(body) != {"username", "password"}
                            or any(not isinstance(value, str) for value in body.values())):
                        raise ValueError("invalid_auth_body")
                    given_user, given_password = body["username"].encode("utf-8"), body["password"].encode("utf-8")
                except (ValueError, UnicodeError, OSError):
                    self.reject()
                    return
                state.login_attempts += 1
                if not hmac.compare_digest(given_user, state.user.encode()) or not hmac.compare_digest(given_password, state.password.encode()):
                    state.auth_denied += 1
                    state.events.append(("auth_denied", ""))
                    self.json_reply(400, {"non_field_errors": ["fixture authentication denied"]})
                    return
                state.token = "synthetic-" + secrets.token_hex(24)
                state.grants += 1
                state.events.append(("auth_granted", ""))
                self.json_reply(200, {"token": state.token})
                return
            if path not in ("/api2/repos/", directory, api + "/file/detail/", api + "/file/") and not payload_route:
                self.reject()
                return
            if not state.events or state.events[0] != ("server_info", ""):
                self.reject()
                return
            authorization = self.headers.get("Authorization", "")
            if state.token is None or not hmac.compare_digest(authorization.encode(), ("Token " + state.token).encode()):
                if (path == "/api2/repos/" and self.command == "GET" and not query
                        and hmac.compare_digest(authorization.encode(), ("Token " + state.invalid_cached_token).encode())):
                    state.cached_denied += 1
                    state.events.append(("cached_denied", ""))
                else:
                    state.unexpected += 1
                    state.events.append(("token_denied", ""))
                self.json_reply(403, {"detail": "fixture token denied"})
                return
            state.auth_uses += 1
            if path == "/api2/repos/":
                if self.command != "GET" or query or state.events != [("server_info", ""), ("auth_granted", "")]:
                    self.reject()
                    return
                state.events.append(("libraries", ""))
                self.json_reply(200, [{"encrypted": False, "id": state.library_id, "name": state.library_name,
                                      "size": sum(map(len, state.files.values())), "mtime": 1704067200}])
                return
            if ("libraries", "") not in state.events:
                self.reject()
                return
            if payload_route:
                if self.command != "GET" or query or path[1:] not in state.links:
                    self.reject()
                    return
                name, issuing_token = state.links[path[1:]]
                if not hmac.compare_digest(issuing_token, state.token):
                    self.reject()
                    return
                payload = state.files[name]
                response_headers = {"Content-Type": "application/octet-stream"}
                code = 200
                requested_range = self.headers.get("Range")
                if requested_range is not None:
                    match = re.fullmatch(r"bytes=(\d+)-(\d*)", requested_range)
                    if not match:
                        self.reject(416)
                        return
                    start, end = int(match[1]), int(match[2]) if match[2] else len(payload) - 1
                    if start > end or end >= len(payload):
                        self.reject(416)
                        return
                    response_headers["Content-Range"] = f"bytes {start}-{end}/{len(payload)}"
                    payload, code = payload[start:end + 1], 206
                state.events.append(("payload", name))
                self.reply(code, payload, response_headers, object_payload=True)
                return
            allowed_query = {"p", "recursive"} if path == directory else {"p"}
            absolute = query.get("p", "")
            if (set(query) != allowed_query or not absolute.startswith("/") or "\\" in absolute or "%" in absolute
                    or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in absolute)
                    or (absolute != "/" and any(part in ("", ".", "..") for part in absolute[1:].split("/")))):
                self.reject()
                return
            name = absolute[1:]
            if self.command in ("DELETE", "PUT", "POST"):
                if path != api + "/file/" or name not in state.files:
                    self.reject()
                    return
                state.rejected_mutations += 1
                state.events.append(("write_denied", name))
                self.json_reply(403, {"detail": "fixture is read-only"})
                return
            if self.command != "GET":
                self.reject()
                return
            if path == directory:
                if query["recursive"] not in ("0", "1"):
                    self.reject()
                    return
                if not is_directory(name, state.files):
                    state.missing += 1
                    state.events.append(("directory_missing", name))
                    self.json_reply(404, {"detail": "fixture directory missing"})
                    return
                prefix = name + "/" if name else ""
                names = set(state.files)
                for member in state.files:
                    parent = posixpath.dirname(member)
                    while parent:
                        names.add(parent)
                        parent = posixpath.dirname(parent)
                selected = sorted(item for item in names if item.startswith(prefix) and item != name
                                  and (query["recursive"] == "1" or "/" not in item[len(prefix):]))
                state.events.append(("directory_list", name))
                self.json_reply(200, {"dirent_list": [self.entry(item) for item in selected]})
                return
            if name not in state.files:
                state.missing += 1
                state.events.append(("file_missing" if path.endswith("/file/detail/") else "link_missing", name))
                self.json_reply(404, {"detail": "fixture file missing"})
                return
            if path.endswith("/file/detail/"):
                state.details.add(name)
                state.events.append(("file_detail", name))
                result = self.entry(name)
                result.pop("mtime")
                result["last_modified"] = "2024-01-01T00:00:00Z"
                self.json_reply(200, result)
                return
            if name not in state.details:
                self.reject()
                return
            link = "fixture-download/" + secrets.token_hex(16)
            state.links[link] = (name, state.token)
            state.events.append(("link_issued", name))
            self.json_reply(200, link)

    def entry(self, name):
        state = self.server.state
        return {"id": hashlib.sha256(name.encode()).hexdigest()[:32], "type": "file" if name in state.files else "dir",
                "name": posixpath.basename(name), "parent_dir": posixpath.dirname("/" + name),
                "size": len(state.files[name]) if name in state.files else 0, "mtime": 1704067200}

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch


class KoofrState(State):
    """One synthetic non-primary mount; Basic reads, never account login."""
    mount_id = "synthetic-mount"
    modified_ms = 1704067200123
    missing_path = "/missing-synthetic-object.bin"
    denied_path = "/README-synthetic.txt"

    def __init__(self, user, password, mode="normal", *, wrong_password="wrong-synthetic-password"):
        super().__init__(user, password)
        if mode not in ("normal", "member_denied") or wrong_password == password:
            raise ValueError("invalid_koofr_fixture_mode")
        self.mode, self.wrong_password = mode, wrong_password
        self.deadline = time.monotonic() + 60
        self.request_timeout, self.request_limit = 3, 128
        self.byte_limit, self.response_bytes = 128 * 1024, 0
        self.authenticated = self.auth_denied = self.member_denied = self.missing = 0
        self.unexpected = self.rejected_payload_bytes = 0
        self.budget_exceeded = False
        self.events, self.details, self.listed = [], set(), set()
        self.mounted = self.root_checked = False
        self.accepted_connections = self.admission_denied = 0
        self.connection_limit, self.active_connection_limit = 64, 4


class KoofrFixture(SeafileFixture):
    # Reuse only connection admission and exception accounting, not its API.
    def __init__(self, state):
        self.state = state
        HTTPServer.__init__(self, ("127.0.0.1", 0), KoofrHandler)


class KoofrHandler(SeafileHandler):
    # Reuse bounded transport/static JSON/error accounting only. The Koofr
    # routes and authentication below are independent of Seafile's token API.
    def dispatch(self):
        with self.server.state.lock:
            state = self.server.state
            state.requests += 1
            if state.requests > state.request_limit or time.monotonic() > state.deadline:
                state.budget_exceeded = True
                self.json_reply(429, {"detail": "synthetic request limit"})
                return
            headers = list(self.headers.items())
            lowered = [name.lower() for name, _ in headers]
            host = f"127.0.0.1:{self.server.server_address[1]}"
            base = "/api/v2/mounts/" + state.mount_id
            routes = {"/api/v2/mounts": "mounts", base + "/files/info": "info", base + "/files/list": "list",
                      "/content/api/v2/mounts/" + state.mount_id + "/files/get": "content", base + "/files/remove": "remove"}
            try:
                wire = self.raw_requestline.rstrip(b"\r\n").split(b" ")
                if (len(wire) != 3 or wire[1].decode("ascii") != self.path or len(self.path) > 2048
                        or not self.path.startswith("/") or any(ord(char) <= 32 or ord(char) >= 127 for char in self.path)
                        or self.headers.get_all("Host") != [host] or len(lowered) != len(set(lowered))
                        or sum(len(name) + len(value) for name, value in headers) > 16384
                        or any("\r" in value or "\n" in value for _, value in headers)
                        or self.headers.get("Transfer-Encoding") is not None
                        or self.headers.get("Content-Length", "0") != "0"
                        or re.search(r"%(?![0-9a-fA-F]{2})", self.path)):
                    raise ValueError("invalid_request")
                url = urllib.parse.urlsplit(self.path)
                if url.scheme or url.netloc or url.fragment or url.path not in routes:
                    raise ValueError("invalid_route")
                pairs = urllib.parse.parse_qsl(url.query, keep_blank_values=True, strict_parsing=True,
                                              max_num_fields=2, encoding="utf-8", errors="strict")
                query = dict(pairs)
                route = routes[url.path]
                if len(pairs) != len(query) or set(query) != (set() if route == "mounts" else {"path"}):
                    raise ValueError("invalid_query")
                absolute = query.get("path", "")
                if route != "mounts" and (not absolute.startswith("/") or "\\" in absolute or "%" in absolute
                        or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in absolute)
                        or (absolute != "/" and any(part in ("", ".", "..") for part in absolute[1:].split("/")))):
                    raise ValueError("invalid_member")
                if (self.command != ("DELETE" if route == "remove" else "GET")
                        or self.headers.get("Range") is not None and route != "content"):
                    raise ValueError("unsupported_method_or_range")
            except (ValueError, UnicodeError):
                self.reject()
                return
            wanted = "Basic " + base64.b64encode((state.user + ":" + state.password).encode()).decode()
            authorization = self.headers.get("Authorization", "")
            if not hmac.compare_digest(authorization.encode(), wanted.encode()):
                wrong = "Basic " + base64.b64encode((state.user + ":" + state.wrong_password).encode()).decode()
                if route == "mounts" and hmac.compare_digest(authorization.encode(), wrong.encode()):
                    state.auth_denied += 1
                    state.events.append(("auth_denied", ""))
                else:
                    state.unexpected += 1
                self.json_reply(401, {"detail": "synthetic credentials denied"})
                return
            state.authenticated += 1
            if route == "mounts":
                if state.mounted:
                    self.reject()
                    return
                state.mounted = True
                state.events.append(("mounts", ""))
                self.json_reply(200, {"mounts": [{"id": state.mount_id, "name": "Synthetic fixture", "type": "device", "isPrimary": False}]})
                return
            if not state.mounted:
                self.reject()
                return
            if route == "info" and absolute == "/":
                if state.root_checked:
                    self.reject()
                    return
                state.root_checked = True
                state.events.append(("root_info", "/"))
                self.json_reply(200, self.entry("/"))
                return
            if not state.root_checked:
                self.reject()
                return
            name = absolute[1:]
            if route == "remove":
                if absolute != state.denied_path:
                    self.reject()
                    return
                state.rejected_mutations += 1
                state.events.append(("write_denied", absolute))
                self.json_reply(405, {"detail": "synthetic fixture is read-only"})
                return
            if route == "info" and state.mode == "member_denied" and absolute == state.denied_path:
                state.member_denied += 1
                state.events.append(("member_denied", absolute))
                self.json_reply(401, {"detail": "synthetic member access denied"})
                return
            if absolute == state.missing_path and route in ("info", "content"):
                state.missing += 1
                state.events.append(("file_missing" if route == "info" else "content_missing", absolute))
                self.json_reply(404, {"detail": "synthetic object missing"})
                return
            if route == "list":
                if not is_directory(name, state.files) or absolute != "/" and "/" not in state.listed:
                    self.reject()
                    return
                state.listed.add(absolute)
                state.events.append(("list", absolute))
                self.json_reply(200, {"files": [self.entry("/" + child) for child in children(name, state.files)]})
                return
            if route == "info" and (name in state.files or is_directory(name, state.files)):
                state.details.add(absolute)
                state.events.append(("member_info", absolute))
                self.json_reply(200, self.entry(absolute))
                return
            if route != "content" or name not in state.files or absolute not in state.details:
                self.reject()
                return
            payload = state.files[name]
            result_headers, code = {"Content-Type": "application/octet-stream"}, 200
            requested = self.headers.get("Range")
            if requested is not None:
                # Reject oversized numbers before integer conversion; malformed
                # ranges remain a bounded, observable 416 response.
                match = re.fullmatch(r"bytes=([0-9]{1,19})-([0-9]{0,19})", requested)
                if not match:
                    self.reject(416)
                    return
                start = int(match[1])
                end = int(match[2]) if match[2] else len(payload) - 1
                if start >= len(payload) or start > end:
                    self.reject(416)
                    return
                end = min(end, len(payload) - 1)
                result_headers["Content-Range"] = f"bytes {start}-{end}/{len(payload)}"
                payload, code = payload[start:end + 1], 206
            state.events.append(("content", absolute))
            self.reply(code, payload, result_headers, object_payload=True)

    def entry(self, absolute):
        state = self.server.state
        name = absolute[1:]
        payload = state.files.get(name)
        return {"name": posixpath.basename(name) if name else "/", "type": "file" if payload is not None else "dir",
                "modified": state.modified_ms, "size": len(payload) if payload is not None else 0,
                "contentType": "application/octet-stream" if payload is not None else "",
                "path": absolute, "hash": hashlib.md5(payload).hexdigest() if payload is not None else ""}

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch


class PixeldrainState(State):
    """One synthetic filesystem; configured-key Basic auth, no token grant."""
    root = "me"
    modified = "2024-01-01T00:00:00.123Z"
    created = "2023-12-31T00:00:00Z"
    missing_path = "missing-synthetic-object.bin"
    denied_path = "README-synthetic.txt"

    def __init__(self, api_key, mode="normal", *, wrong_key="wrong-synthetic-key"):
        if (mode not in ("normal", "member_denied") or not isinstance(api_key, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", api_key)
                or not isinstance(wrong_key, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", wrong_key)
                or wrong_key == api_key):
            raise ValueError("invalid_pixeldrain_fixture")
        super().__init__("", api_key)
        self.api_key, self.wrong_key, self.mode = api_key, wrong_key, mode
        self.deadline = time.monotonic() + 60
        self.request_timeout, self.request_limit = 3, 128
        self.byte_limit, self.response_bytes = 128 * 1024, 0
        self.authenticated = self.auth_denied = self.member_denied = self.missing = 0
        self.unexpected = self.rejected_payload_bytes = 0
        self.budget_exceeded = self.user_checked = False
        self.root_stats = 0
        self.events, self.details = [], set()
        self.accepted_connections = self.admission_denied = 0
        self.connection_limit, self.active_connection_limit = 64, 4

    def node(self, member):
        if member not in self.files and not is_directory(member, self.files):
            raise ValueError("invalid_pixeldrain_member")
        payload = self.files.get(member)
        return {"type": "file" if payload is not None else "dir", "path": "/me/" + member,
                "name": member.rsplit("/", 1)[-1] if member else "me", "created": self.created,
                "modified": self.modified, "mode_octal": "0644" if payload is not None else "0755",
                "file_size": len(payload) if payload is not None else 0,
                "file_type": "application/octet-stream" if payload is not None else "inode/directory",
                "sha256_sum": hashlib.sha256(payload).hexdigest() if payload is not None else ""}

    def envelope(self, member):
        lineage = [""] + (["/".join(member.split("/")[:i + 1]) for i in range(len(member.split("/")))] if member else [])
        result = {"path": [self.node(name) for name in lineage], "base_index": len(lineage) - 1,
                  "children": [self.node(name) for name in children(member, self.files)] if is_directory(member, self.files) else []}
        if not pixeldrain_envelope_valid(result, member, self.files, self.modified, self.created):
            raise ValueError("invalid_pixeldrain_envelope")
        return result


def pixeldrain_envelope_valid(value, member, files, modified, created):
    """Guard the fixture's unchecked upstream BaseIndex and prefix contract."""
    if (not isinstance(member, str) or member not in files and not is_directory(member, files)
            or not isinstance(value, dict) or set(value) != {"path", "base_index", "children"}
            or not isinstance(value["path"], list) or not isinstance(value["children"], list)
            or type(value["base_index"]) is not int or not 0 <= value["base_index"] < len(value["path"])):
        return False
    lineage = [""] + (["/".join(member.split("/")[:i + 1]) for i in range(len(member.split("/")))] if member else [])
    descendants = children(member, files) if is_directory(member, files) else []
    if value["base_index"] != len(lineage) - 1:
        return False
    fields = {"type", "path", "name", "created", "modified", "mode_octal", "file_size", "file_type", "sha256_sum"}
    for nodes, names in ((value["path"], lineage), (value["children"], descendants)):
        if len(nodes) != len(names):
            return False
        for node, name in zip(nodes, names):
            data = files.get(name)
            is_file = data is not None
            if (not isinstance(node, dict) or set(node) != fields or node["path"] != "/me/" + name
                    or node["name"] != (name.rsplit("/", 1)[-1] if name else "me")
                    or node["type"] != ("file" if is_file else "dir") or node["modified"] != modified
                    or node["created"] != created or node["mode_octal"] != ("0644" if is_file else "0755")
                    or type(node["file_size"]) is not int or node["file_size"] != (len(data) if is_file else 0)
                    or node["file_type"] != ("application/octet-stream" if is_file else "inode/directory")
                    or node["sha256_sum"] != (hashlib.sha256(data).hexdigest() if is_file else "")):
                return False
    return True


class PixeldrainFixture(SeafileFixture):
    def __init__(self, state):
        self.state = state
        HTTPServer.__init__(self, ("127.0.0.1", 0), PixeldrainHandler)


class PixeldrainHandler(SeafileHandler):
    # Only reuse bounded transport/admission/error accounting, not another API.
    def error(self, status, value):
        messages = {"authentication_failed": "Synthetic authentication failed", "permission_denied": "Synthetic permission denied",
                    "path_not_found": "Synthetic path not found", "fixture_read_only": "Synthetic fixture is read only"}
        self.json_reply(status, {"value": value, "message": messages.get(value, "Synthetic request rejected")})

    def reject(self, status=400):
        self.server.state.unexpected += 1
        self.error(status, "fixture_request_rejected")

    def send_error(self, code, message=None, explain=None):
        with self.server.state.lock:
            self.reject(code)

    def dispatch(self):
        with self.server.state.lock:
            state = self.server.state
            state.requests += 1
            if state.requests > state.request_limit or time.monotonic() > state.deadline:
                state.budget_exceeded = True
                self.error(429, "fixture_request_limit")
                return
            headers = list(self.headers.items())
            lowered = [name.lower() for name, _ in headers]
            try:
                wire = self.raw_requestline.rstrip(b"\r\n").split(b" ")
                if (len(wire) != 3 or wire[1].decode("ascii") != self.path or len(self.path) > 2048
                        or not self.path.startswith("/") or any(ord(c) <= 32 or ord(c) >= 127 for c in self.path)
                        or self.headers.get_all("Host") != [f"127.0.0.1:{self.server.server_address[1]}"]
                        or len(lowered) != len(set(lowered)) or sum(len(k) + len(v) for k, v in headers) > 16384
                        or any("\r" in v or "\n" in v for _, v in headers)
                        or self.headers.get("Transfer-Encoding") is not None or self.headers.get("Content-Length", "0") != "0"):
                    raise ValueError("invalid_request")
                url = urllib.parse.urlsplit(self.path)
                if url.scheme or url.netloc or "#" in self.path:
                    raise ValueError("invalid_target")
                if self.path == "/api/user":
                    route, member = "user", ""
                else:
                    prefix = "/api/filesystem/me/"
                    if not url.path.startswith(prefix) or url.query not in ("", "stat=") or "?" in self.path and url.query == "":
                        raise ValueError("invalid_route")
                    encoded = url.path[len(prefix):]
                    parts = [urllib.parse.unquote(p, encoding="utf-8", errors="strict") for p in encoded.split("/")]
                    if any("/" in p or "\\" in p or "%" in p or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in p) for p in parts):
                        raise ValueError("invalid_member")
                    member = "/".join(parts)
                    if (member and any(p in ("", ".", "..") for p in parts)
                            or "/".join(urllib.parse.quote(p, safe="-._~") for p in parts) != encoded):
                        raise ValueError("noncanonical_member")
                    route = "stat" if url.query == "stat=" else "delete" if self.command == "DELETE" else "content"
                if (self.command != ("DELETE" if route == "delete" else "GET")
                        or self.headers.get("Range") is not None and route != "content"):
                    raise ValueError("invalid_method_or_range")
            except (ValueError, UnicodeError):
                self.reject()
                return
            wanted = "Basic " + base64.b64encode((":" + state.api_key).encode()).decode()
            actual = self.headers.get("Authorization", "").encode()
            if not hmac.compare_digest(actual, wanted.encode()):
                wrong = "Basic " + base64.b64encode((":" + state.wrong_key).encode()).decode()
                if route == "user" and hmac.compare_digest(actual, wrong.encode()):
                    state.auth_denied += 1
                    state.events.append(("auth_denied", ""))
                else:
                    state.unexpected += 1
                self.error(401, "authentication_failed")
                return
            state.authenticated += 1
            if route == "user":
                if state.user_checked:
                    self.reject()
                    return
                state.user_checked = True
                state.events.append(("user_info", ""))
                self.json_reply(200, {"username": "synthetic-user", "subscription": {"name": "synthetic-plan", "storage_space": 1048576},
                                      "storage_space_used": 0})
                return
            if not state.user_checked:
                self.reject()
                return
            if route == "stat" and member == "":
                if state.root_stats >= 2 or state.details:
                    self.reject()
                    return
                state.root_stats += 1
                state.events.append(("root_stat", "/"))
                self.json_reply(200, state.envelope(""))
                return
            if not state.root_stats:
                self.reject()
                return
            if route == "delete":
                if member != state.denied_path or member not in state.details:
                    self.reject()
                    return
                state.rejected_mutations += 1
                state.events.append(("write_denied", member))
                self.error(405, "fixture_read_only")
                return
            if route == "stat" and member == state.denied_path and state.mode == "member_denied":
                state.member_denied += 1
                state.events.append(("member_denied", member))
                self.error(403, "permission_denied")
                return
            if member == state.missing_path and route in ("stat", "content"):
                state.missing += 1
                state.events.append(("file_missing" if route == "stat" else "content_missing", member))
                self.error(404, "path_not_found")
                return
            if route == "stat" and member in state.files:
                state.details.add(member)
                state.events.append(("member_stat", member))
                self.json_reply(200, state.envelope(member))
                return
            if route == "stat" and member and is_directory(member, state.files) and state.root_stats == 2:
                state.events.append(("directory_stat", member))
                self.json_reply(200, state.envelope(member))
                return
            if route != "content" or member not in state.files or member not in state.details:
                self.reject()
                return
            payload, code = state.files[member], 200
            response_headers = {"Content-Type": "application/octet-stream"}
            requested = self.headers.get("Range")
            if requested is not None:
                match = re.fullmatch(r"bytes=([0-9]{1,19})-([0-9]{0,19})", requested)
                if not match:
                    self.reject(416)
                    return
                start, end = int(match[1]), int(match[2]) if match[2] else len(payload) - 1
                if start >= len(payload) or start > end:
                    self.reject(416)
                    return
                end = min(end, len(payload) - 1)
                response_headers["Content-Range"] = f"bytes {start}-{end}/{len(payload)}"
                payload, code = payload[start:end + 1], 206
            state.events.append(("content", member))
            self.reply(code, payload, response_headers, object_payload=True)

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch


class B2State(State):
    """Synthetic native B2 v4 authorization/v1 reads, restricted to one bucket."""
    bucket = "synthetic-bucket"
    bucket_id = "synthetic-bucket-id"

    def __init__(self, user, password, mode="normal"):
        super().__init__(user, password)
        if mode not in ("normal", "renew", "deny"):
            raise ValueError("invalid_b2_fixture_mode")
        self.mode = mode
        self.deadline = time.monotonic() + 60
        self.request_limit = 128
        self.generation = 0
        self.token = None
        self.tokens, self.revoked = set(), set()
        self.events = []
        self.forced_401 = self.expired_gets = 0
        self.auth_denied = self.renewal_denied = self.storage_denied = 0
        self.missing = self.unexpected = self.rejected_payload_bytes = 0
        self.budget_exceeded = False
        self.ids = {name: "synthetic-file-" + str(index) for index, name in enumerate(sorted(self.files))}


class B2Fixture(LoopbackThreads, HTTPServer):
    def __init__(self, state):
        self.state = state
        super().__init__(("127.0.0.1", 0), B2Handler)


class B2Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):
        pass

    def reply(self, status, body=b"", headers=None, size=None, object_payload=False):
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Length", str(len(body) if size is None else size))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            if object_payload:
                if status >= 400:
                    self.server.state.rejected_payload_bytes += len(body)
                else:
                    self.server.state.payload_bytes += len(body)
            self.wfile.write(body)

    def json_reply(self, status, value):
        self.reply(status, json.dumps(value, separators=(",", ":")).encode(), {"Content-Type": "application/json"})

    def error(self, status, code):
        # Protocol error JSON is not object payload; neither credentials nor
        # request values are reflected into responses or durable receipts.
        self.json_reply(status, {"status": status, "code": code, "message": "synthetic fixture response"})

    def reject(self, status=400):
        self.server.state.unexpected += 1
        self.error(status, "bad_request")

    @staticmethod
    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate_json_key")
            value[key] = item
        return value

    def read_body(self, length):
        # Socket timeouts alone only bound inactivity; slow drip feeds must not
        # hold the shared state/cleanup lock indefinitely. read1 performs at
        # most one underlying read before the absolute deadline is checked.
        state = self.server.state
        deadline = min(state.deadline, time.monotonic() + 3)
        body = bytearray()
        while len(body) < length:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("body_deadline")
            self.connection.settimeout(remaining)
            chunk = self.rfile.read1(length - len(body))
            if not chunk:
                raise ValueError("short_body")
            body.extend(chunk)
        self.connection.settimeout(5)
        return bytes(body)

    def dispatch(self):
        with self.server.state.lock:
            state = self.server.state
            state.requests += 1
            if state.requests > state.request_limit or time.monotonic() > state.deadline:
                state.budget_exceeded = True
                self.error(429, "request_limit")
                return
            host = f"127.0.0.1:{self.server.server_address[1]}"
            lengths = self.headers.get_all("Content-Length", [])
            if (self.headers.get_all("Host") != [host] or len(self.path) > 2048
                    or sum(len(key) + len(value) for key, value in self.headers.items()) > 8192
                    or self.headers.get("Transfer-Encoding") is not None or len(lengths) > 1
                    or (lengths and (not lengths[0].isdigit() or int(lengths[0]) > 4096))):
                self.reject()
                return
            length = int(lengths[0]) if lengths else 0
            if (self.command in ("GET", "HEAD") and length) or (self.command == "POST" and not lengths):
                self.reject()
                return
            try:
                url = urllib.parse.urlsplit(self.path)
                path = "/" + safe_path(self.path)
                query = urllib.parse.parse_qs(url.query, keep_blank_values=True, max_num_fields=4)
            except ValueError:
                self.reject()
                return
            if (url.scheme or url.netloc or url.fragment or url.path.endswith("/")
                    or url.path != urllib.parse.quote(path, safe="/._-~!$'()*;=:@")
                    or any(part in (".", "..", "") for part in path[1:].split("/"))
                    or (self.headers.get("Range") is not None
                        and (self.command != "GET" or path != "/b2api/v1/b2_download_file_by_id"))):
                self.reject()
                return
            if path == "/b2api/v4/b2_authorize_account":
                if self.command != "GET" or query:
                    self.reject()
                    return
                expected = "Basic " + base64.b64encode(f"{state.user}:{state.password}".encode()).decode()
                if (len(self.headers.get_all("Authorization", [])) != 1
                        or not hmac.compare_digest(self.headers.get("Authorization", ""), expected)):
                    state.auth_denied += 1
                    state.events.append(("auth_denied", state.generation))
                    self.error(401, "unauthorized")
                    return
                if state.mode == "deny" and state.forced_401:
                    state.renewal_denied += 1
                    state.events.append(("renewal_denied", state.generation))
                    self.error(401, "unauthorized")
                    return
                state.generation += 1
                state.token = "synthetic-" + secrets.token_hex(24)
                state.tokens.add(state.token)
                state.events.append(("grant", state.generation))
                self.json_reply(200, {"accountId": "synthetic-account", "authorizationToken": state.token,
                    "apiInfo": {"storageApi": {"apiUrl": f"http://{host}", "downloadUrl": f"http://{host}",
                        "absoluteMinimumPartSize": 5000000, "recommendedPartSize": 100000000,
                        "allowed": {"buckets": [{"id": state.bucket_id, "name": state.bucket}],
                                    "capabilities": ["listFiles", "readFiles"], "namePrefix": None}}}})
                return
            token = self.headers.get("Authorization", "")
            authorized = (len(self.headers.get_all("Authorization", [])) == 1 and state.token is not None
                          and hmac.compare_digest(token, state.token))
            download = path == "/b2api/v1/b2_download_file_by_id" and self.command == "GET"
            if authorized and token in state.revoked and download and state.mode == "deny":
                if query != {"fileId": [state.ids["README-synthetic.txt"]]}:
                    self.reject()
                    return
                state.expired_gets += 1
                state.events.append(("expired_retry", 1))
                self.error(401, "expired_auth_token")
                return
            if not authorized or token in state.revoked:
                state.storage_denied += 1
                state.events.append(("storage_denied", state.generation))
                self.error(401, "unauthorized")
                return
            if self.command == "POST":
                if query or self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
                    self.reject()
                    return
                try:
                    raw = self.read_body(length)
                    body = json.loads(raw, object_pairs_hook=self.unique_object)
                    if not isinstance(body, dict):
                        raise ValueError("non_object")
                except (ValueError, UnicodeError):
                    self.reject()
                    return
                except (TimeoutError, OSError):
                    state.unexpected += 1
                    state.budget_exceeded = True
                    self.close_connection = True
                    return
                if path == "/b2api/v1/b2_list_file_names":
                    self.list_files(body)
                elif path == "/b2api/v1/b2_get_upload_url" and body == {"bucketId": state.bucket_id}:
                    state.rejected_mutations += 1
                    self.error(403, "unauthorized")
                else:
                    self.reject()
                return
            if self.command == "HEAD" and path.startswith("/file/" + state.bucket + "/") and not query:
                name = path[len("/file/" + state.bucket + "/"):]
            elif download and set(query) == {"fileId"} and len(query["fileId"]) == 1:
                name = next((name for name, value in state.ids.items() if value == query["fileId"][0]), None)
            else:
                self.reject()
                return
            if name not in state.files:
                state.missing += 1
                self.error(404, "file_not_present")
                return
            payload = state.files[name]
            headers = {"Content-Type": "application/octet-stream", "X-Bz-File-Id": state.ids[name],
                "X-Bz-File-Name": urllib.parse.quote(name, safe=""), "X-Bz-Content-Sha1": hashlib.sha1(payload).hexdigest(),
                "X-Bz-Upload-Timestamp": "1704067200000", "X-Bz-Info-src_last_modified_millis": "1704067200000"}
            if self.command == "HEAD":
                if state.mode in ("renew", "deny") and name != "README-synthetic.txt":
                    self.reject()
                    return
                state.events.append(("head", state.generation))
                self.reply(200, headers=headers, size=len(payload))
                return
            if state.mode in ("renew", "deny"):
                if name != "README-synthetic.txt" or ("head", 1) not in state.events:
                    self.reject()
                    return
                if not state.forced_401:
                    state.revoked.add(token)
                    state.forced_401 = state.expired_gets = 1
                    state.events.append(("get_401", 1))
                    self.error(401, "expired_auth_token")
                    return
            code = 200
            ranges = self.headers.get_all("Range", [])
            if ranges:
                match = re.fullmatch(r"bytes=(\d+)-(\d*)", ranges[0]) if len(ranges) == 1 else None
                if not match:
                    self.reject(416)
                    return
                start, end = int(match[1]), int(match[2]) if match[2] else len(payload) - 1
                if start > end or end >= len(payload):
                    self.reject(416)
                    return
                headers["Content-Range"] = f"bytes {start}-{end}/{len(payload)}"
                payload, code = payload[start:end + 1], 206
            state.events.append(("get", state.generation))
            self.reply(code, payload, headers, object_payload=True)

    def list_files(self, body):
        state = self.server.state
        if (state.mode != "normal" or set(body) - {"bucketId", "maxFileCount", "prefix", "startFileName", "delimiter"}
                or body.get("bucketId") != state.bucket_id or type(body.get("maxFileCount", 100)) is not int
                or not 1 <= body.get("maxFileCount", 100) <= 1000
                or body.get("delimiter", "") not in ("", "/")):
            self.reject()
            return
        prefix, marker, delimiter = body.get("prefix", ""), body.get("startFileName", ""), body.get("delimiter", "")
        if any(not isinstance(value, str) or "\\" in value or "\x00" in value or ".." in value.split("/")
               for value in (prefix, marker)):
            self.reject()
            return
        rows = {}
        for name, payload in sorted(state.files.items()):
            if not name.startswith(prefix):
                continue
            if delimiter and "/" in name[len(prefix):]:
                folder = prefix + name[len(prefix):].split("/", 1)[0] + "/"
                rows[folder] = {"fileName": folder, "action": "folder"}
            else:
                rows[name] = {"fileId": state.ids[name], "fileName": name, "action": "upload", "size": len(payload),
                    "uploadTimestamp": 1704067200000, "contentSha1": hashlib.sha1(payload).hexdigest(),
                    "contentType": "application/octet-stream", "fileInfo": {"src_last_modified_millis": "1704067200000"}}
        names = [name for name in sorted(rows) if name >= marker]
        limit = body.get("maxFileCount", 100)
        self.json_reply(200, {"files": [rows[name] for name in names[:limit]],
                              "nextFileName": names[limit] if len(names) > limit else None})

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch


class SwiftState(State):
    """Only synthetic Swift v1 keys/tokens; never serialized into receipts."""
    account = "/v1/AUTH_synthetic"
    container = "synthetic-bucket"

    def __init__(self, user, password, mode="normal"):
        super().__init__(user, password)
        if mode not in ("normal", "renew", "deny"):
            raise ValueError("invalid_swift_fixture_mode")
        self.mode = mode
        self.deadline = time.monotonic() + 60
        self.request_limit = 128
        self.generation = 0
        self.token = None
        self.tokens = set()
        self.revoked = set()
        self.events = []
        self.forced_401 = 0
        self.auth_denied = 0
        self.renewal_denied = 0
        self.storage_denied = 0
        self.missing = 0
        self.unexpected = 0
        self.budget_exceeded = False
        self.rejected_payload_bytes = 0


class SwiftFixture(LoopbackThreads, HTTPServer):
    def __init__(self, state):
        self.state = state
        super().__init__(("127.0.0.1", 0), SwiftHandler)


class SwiftHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):
        pass

    def reply(self, status, body=b"", headers=None, size=None):
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Length", str(len(body) if size is None else size))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            if status >= 400:
                self.server.state.rejected_payload_bytes += len(body)
            self.wfile.write(body)

    def reject(self, status=400):
        self.server.state.unexpected += 1
        self.reply(status)

    def dispatch(self):
        # State transitions and the bounded response are serialized. Sockets
        # have a five-second timeout; fixture shutdown also closes owned sockets.
        with self.server.state.lock:
            state = self.server.state
            state.requests += 1
            if state.requests > state.request_limit or time.monotonic() > state.deadline:
                state.budget_exceeded = True
                self.reply(429)
                return
            host = f"127.0.0.1:{self.server.server_address[1]}"
            if (self.headers.get_all("Host") != [host] or len(self.path) > 2048
                    or sum(len(key) + len(value) for key, value in self.headers.items()) > 8192
                    or self.headers.get("Transfer-Encoding") is not None):
                self.reject()
                return
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) > 1 or (lengths and (not lengths[0].isdigit() or int(lengths[0]) > 4096)):
                self.reject()
                return
            if self.command in ("GET", "HEAD") and lengths and int(lengths[0]) != 0:
                self.reject()
                return
            url = urllib.parse.urlsplit(self.path)
            if url.scheme or url.netloc or url.fragment:
                self.reject()
                return
            try:
                path = "/" + safe_path(self.path)
                query = urllib.parse.parse_qs(url.query, keep_blank_values=True, max_num_fields=8)
            except ValueError:
                self.reject()
                return
            if path == "/auth/v1.0":
                if self.command != "GET" or query:
                    self.reject()
                    return
                if (self.headers.get_all("X-Auth-User") != [state.user]
                        or len(self.headers.get_all("X-Auth-Key", [])) != 1
                        or not hmac.compare_digest(self.headers.get("X-Auth-Key", ""), state.password)):
                    state.denied += 1
                    state.auth_denied += 1
                    state.events.append(("auth_denied", state.generation))
                    self.reply(401)
                    return
                if state.mode == "deny" and state.forced_401:
                    state.renewal_denied += 1
                    state.events.append(("renewal_denied", state.generation))
                    self.reply(403)
                    return
                state.generation += 1
                state.token = "synthetic-" + secrets.token_hex(24)
                state.tokens.add(state.token)
                state.events.append(("grant", state.generation))
                self.reply(200, headers={"X-Auth-Token": state.token,
                    "X-Storage-Url": f"http://{host}{state.account}"})
                return
            base = state.account + "/" + state.container
            if path != base and not path.startswith(base + "/"):
                self.reject(404)
                return
            token = self.headers.get("X-Auth-Token", "")
            if (len(self.headers.get_all("X-Auth-Token", [])) != 1 or state.token is None
                    or token in state.revoked or not hmac.compare_digest(token, state.token)):
                state.storage_denied += 1
                state.events.append(("storage_denied", state.generation))
                self.reply(401)
                return
            if self.command not in ("GET", "HEAD"):
                if self.command not in ("PUT", "POST", "DELETE", "COPY") or query:
                    self.reject(405)
                    return
                state.rejected_mutations += 1
                self.reply(405)
                return
            if path == base:
                if self.command == "HEAD":
                    if query:
                        self.reject()
                        return
                    self.reply(204, headers={"X-Container-Object-Count": str(len(state.files)),
                        "X-Container-Bytes-Used": str(sum(map(len, state.files.values()))), "X-Storage-Policy": "synthetic"})
                else:
                    self.list_objects(query)
                return
            if query:
                self.reject()
                return
            name = path[len(base) + 1:]
            if name not in state.files:
                state.missing += 1
                self.reply(404)
                return
            body = state.files[name]
            headers = {"Content-Type": "application/octet-stream", "Last-Modified": STAMP,
                       "Etag": hashlib.md5(body).hexdigest(), "Accept-Ranges": "bytes"}
            if self.command == "HEAD":
                state.events.append(("head", state.generation))
                self.reply(200, headers=headers, size=len(body))
                return
            if state.mode in ("renew", "deny") and state.generation == 1 and not state.forced_401:
                if ("head", 1) not in state.events or name != "README-synthetic.txt":
                    self.reject()
                    return
                state.revoked.add(token)
                state.forced_401 += 1
                state.events.append(("get_401", 1))
                self.reply(401)
                return
            code = 200
            ranges = self.headers.get_all("Range", [])
            if ranges:
                match = re.fullmatch(r"bytes=(\d+)-(\d*)", ranges[0]) if len(ranges) == 1 else None
                if not match:
                    self.reject(416)
                    return
                start = int(match[1])
                end = int(match[2]) if match[2] else len(body) - 1
                if start > end or end >= len(body):
                    self.reject(416)
                    return
                headers["Content-Range"] = f"bytes {start}-{end}/{len(body)}"
                body = body[start:end + 1]
                code = 206
            state.events.append(("get", state.generation))
            state.payload_bytes += len(body)
            self.reply(code, body, headers)

    def list_objects(self, query):
        state = self.server.state
        allowed = {"format", "prefix", "delimiter", "marker", "end_marker", "limit"}
        if set(query) - allowed or any(len(values) != 1 for values in query.values()) or query.get("format") != ["json"]:
            self.reject()
            return
        values = {key: value[0] for key, value in query.items()}
        prefix, delimiter = values.get("prefix", ""), values.get("delimiter", "")
        limit = values.get("limit", "1000")
        if delimiter not in ("", "/") or not limit.isdigit() or not 1 <= int(limit) <= 1000:
            self.reject()
            return
        for key in ("prefix", "marker", "end_marker"):
            value = values.get(key, "")
            if "\\" in value or "\x00" in value or ".." in value.split("/"):
                self.reject()
                return
        rows = {}
        for name, body in sorted(state.files.items()):
            if not name.startswith(prefix):
                continue
            tail = name[len(prefix):]
            if delimiter and delimiter in tail:
                child = prefix + tail.split(delimiter, 1)[0] + delimiter
                rows[child] = {"subdir": child}
            else:
                rows[name] = {"name": name, "bytes": len(body), "hash": hashlib.md5(body).hexdigest(),
                              "content_type": "application/octet-stream", "last_modified": "2024-01-01T00:00:00.000000"}
        selected = [row for name, row in sorted(rows.items()) if name > values.get("marker", "")
                    and (not values.get("end_marker") or name < values["end_marker"])][:int(limit)]
        self.reply(200, json.dumps(selected, separators=(",", ":")).encode(), {"Content-Type": "application/json"})

    do_GET = dispatch
    do_HEAD = dispatch
    do_PUT = dispatch
    do_POST = dispatch
    do_DELETE = dispatch
    do_COPY = dispatch


class FtpFixture(LoopbackThreads, socketserver.TCPServer):
    def __init__(self, state):
        self.state = state
        super().__init__(("127.0.0.1", 0), FtpHandler)


class FtpHandler(socketserver.StreamRequestHandler):
    def reply(self, code, text="synthetic"):
        self.wfile.write(f"{code} {text}\r\n".encode())

    def passive(self, extended):
        if self.data_socket:
            self.data_socket.close()
        self.data_socket = socket.socket()
        self.data_socket.settimeout(5)
        self.data_socket.bind(("127.0.0.1", 0))
        self.data_socket.listen(1)
        with self.server.state.lock:
            self.server.state.sockets.add(self.data_socket)
        port = self.data_socket.getsockname()[1]
        if extended:
            self.reply(229, f"Entering Extended Passive Mode (|||{port}|)")
        else:
            self.reply(227, f"Entering Passive Mode (127,0,0,1,{port // 256},{port % 256})")

    def transfer(self, body, payload=False):
        if not self.data_socket:
            self.reply(425)
            return
        self.reply(150)
        conn, peer = self.data_socket.accept()
        with conn:
            conn.settimeout(5)
            if peer[0] != "127.0.0.1":
                raise ValueError("non_loopback_peer")
            conn.sendall(body)
        self.data_socket.close()
        with self.server.state.lock:
            self.server.state.sockets.discard(self.data_socket)
        self.data_socket = None
        if payload:
            self.server.state.payload_bytes += len(body)
        self.reply(226)

    def handle(self):
        self.data_socket = None
        files = self.server.state.files
        logged_in, user, cwd = False, "", ""
        self.reply(220)
        try:
            for _ in range(128):
                raw = self.rfile.readline(4097)
                if not raw or len(raw) > 4096:
                    break
                command, _, argument = raw.decode("utf-8").strip().partition(" ")
                command = command.upper()
                if command == "USER":
                    user = argument
                    self.reply(331)
                elif command == "PASS":
                    logged_in = user == self.server.state.user and argument == self.server.state.password
                    if not logged_in:
                        self.server.state.denied += 1
                    self.reply(230 if logged_in else 530)
                elif command == "QUIT":
                    self.reply(221)
                    break
                elif not logged_in:
                    self.reply(530)
                elif command in ("PORT", "EPRT"):
                    self.reply(502, "Active connections disabled")
                elif command in ("STOR", "APPE", "DELE", "RMD", "MKD", "RNFR", "RNTO"):
                    self.server.state.rejected_mutations += 1
                    self.reply(550, "Read only")
                elif command == "FEAT":
                    self.wfile.write(b"211-Features\r\n UTF8\r\n MLST type*;size*;modify*;\r\n EPSV\r\n211 End\r\n")
                elif command in ("TYPE", "OPTS", "NOOP"):
                    self.reply(200)
                elif command == "SYST":
                    self.reply(215, "UNIX Type: L8")
                elif command == "PWD":
                    self.reply(257, '"/' + cwd + '"')
                elif command in ("PASV", "EPSV"):
                    self.passive(command == "EPSV")
                else:
                    try:
                        path = safe_path(argument if argument.startswith("/") else "/" + posixpath.join(cwd, argument))
                    except ValueError:
                        self.reply(550)
                        continue
                    if command == "CWD" and is_directory(path, files):
                        cwd = path
                        self.reply(250)
                    elif command == "SIZE" and path in files:
                        self.reply(213, str(len(files[path])))
                    elif command == "MDTM" and path in files:
                        self.reply(213, "20240101000000")
                    elif command == "MLST" and (is_directory(path, files) or path in files):
                        directory = is_directory(path, files)
                        size = 0 if directory else len(files[path])
                        self.wfile.write(("250-Listing\r\n "
                            + f"type={'dir' if directory else 'file'};size={size};modify=20240101000000; {path}\r\n"
                            + "250 End\r\n").encode())
                    elif command in ("LIST", "MLSD") and (is_directory(path, files) or command == "LIST" and path in files):
                        lines = []
                        for child in ([path] if path in files else children(path, files)):
                            directory = is_directory(child, files)
                            size = 0 if directory else len(files[child])
                            name = child.split("/")[-1]
                            if command == "MLSD":
                                lines.append(f"type={'dir' if directory else 'file'};size={size};modify=20240101000000; {name}\r\n")
                            else:
                                lines.append(f"{'d' if directory else '-'}r--r--r-- 1 fixture fixture {size} Jan 01 2024 {name}\r\n")
                        self.transfer("".join(lines).encode())
                    elif command == "RETR" and path in files:
                        self.transfer(files[path], payload=True)
                    else:
                        self.reply(550)
        finally:
            if self.data_socket:
                self.data_socket.close()
                with self.server.state.lock:
                    self.server.state.sockets.discard(self.data_socket)


@contextmanager
def serve(kind, state):
    server = (FtpFixture(state) if kind == "ftp" else SwiftFixture(state) if kind == "swift"
              else B2Fixture(state) if kind == "b2" else AzureBlobFixture(state) if kind == "azureblob"
              else AzureFilesFixture(state) if kind == "azurefiles" else SeafileFixture(state) if kind == "seafile"
              else KoofrFixture(state) if kind == "koofr" else PixeldrainFixture(state) if kind == "pixeldrain" else HttpFixture(state))
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        state.stopping.set()
        server.shutdown()
        with state.lock:
            for conn in list(state.sockets):
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                conn.close()
        server.server_close()
        thread.join(5)
        if thread.is_alive():
            raise RuntimeError("fixture_cleanup_failed")
        state.cleanup_complete = True


def probe_write_rejection(kind, port, state):
    """Test the fixture's write guard, not a vendor or application write path."""
    before = state.rejected_mutations
    if kind == "ftp":
        client = ftplib.FTP()
        try:
            client.connect("127.0.0.1", port, timeout=3)
            client.login(state.user, state.password)
            try:
                client.sendcmd("STOR must-not-be-written.txt")
            except ftplib.error_perm as error:
                if not str(error).startswith("550"):
                    raise ValueError("unexpected_mutation_response") from None
            else:
                raise ValueError("mutation_not_rejected")
        finally:
            client.close()
    else:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        try:
            authorization = base64.b64encode(f"{state.user}:{state.password}".encode()).decode()
            connection.request("PUT", "/must-not-be-written.txt", body=b"synthetic write must fail",
                               headers={"Authorization": "Basic " + authorization})
            response = connection.getresponse()
            if response.status != 405:
                raise ValueError("mutation_not_rejected")
            response.read(4096)
        finally:
            connection.close()
    if state.rejected_mutations != before + 1:
        raise ValueError("mutation_rejection_not_observed")
