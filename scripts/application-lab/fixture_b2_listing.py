"""Bounded metadata-only B2 ListR fixture. Import performs no native work.

The direct account case discovers its restricted bucket, then consumes two
pages. The alias-root case probes its root with HEAD and consumes two pages
with a nonempty prefix. No payload route is implemented.
"""
import base64
from contextlib import contextmanager
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
import select
import socket
import threading
import time
import types

_PATH = Path(__file__).absolute().with_name("fixture_http.py")
_BYTES = _PATH.read_bytes()
loaded_http_source_sha256 = hashlib.sha256(_BYTES).hexdigest()
_http = types.ModuleType("b2_listing_owned_http")
_http.__file__ = str(_PATH)
exec(compile(_BYTES, str(_PATH), "exec"), _http.__dict__)
del _BYTES
FixtureError = _http.FixtureError
CASES = ("account_listing", "alias_nested_listing")
CAPABILITIES = ("listBuckets", "listFiles", "readFiles")
BUCKET, BUCKET_ID = "synthetic-bucket", "synthetic-bucket-id"
AUTH = "/b2api/v4/b2_authorize_account"
BUCKETS = "/b2api/v1/b2_list_buckets"
FILES = "/b2api/v1/b2_list_file_names"
PROBE = "/file/synthetic-bucket/nested"
MARKER = "nested/space name.txt"
MEMBERS = (("README-synthetic.txt", 20), ("nested/", 0), ("nested/empty.txt", 0), (MARKER, 26), ("unmarked/leaf.txt", 17))
ERROR_CODES = _http.ERROR_CODES | {"credentials_invalid", "token_invalid", "sequence_invalid", "capability_denied"}


def parse_body(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= 1024:
        raise FixtureError("request_body_rejected")
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError()
            value[key] = item
        return value
    def constant(_):
        raise ValueError()
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
        if type(value) is not dict:
            raise ValueError()
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise FixtureError("request_body_rejected") from None


def response_wire(status, body):
    if type(status) is not int or status not in {200, 404} or type(body) is not bytes:
        raise FixtureError("sequence_invalid")
    wire = (f"HTTP/1.1 {status} " + {200: "OK", 404: "Not Found"}[status] +
        f"\r\nContent-Length: {len(body)}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n").encode("ascii") + body
    if len(wire) > 4096:
        raise FixtureError("byte_limit")
    return wire


class AppB2ListingState:
    def __init__(self, case, user, key, *, capabilities=CAPABILITIES):
        if type(case) is not str or case not in CASES or any(
                type(v) is not str or not re.fullmatch(r"[a-f0-9]{64}", v) for v in (user, key)):
            raise ValueError("input_invalid")
        # A finite subset is injectable only for pure negative controls; the
        # hosted producer always uses the complete default synthetic grant.
        if (type(capabilities) is not tuple or any(type(c) is not str or c not in CAPABILITIES for c in capabilities) or
                tuple(c for c in CAPABILITIES if c in capabilities) != capabilities):
            raise ValueError("input_invalid")
        self._capabilities = capabilities
        self.case, self._user, self._key = case, user, key
        self._original = (case, user, key, MEMBERS, capabilities)
        self._members = MEMBERS
        self.lock = threading.RLock()
        self.errors, self.events = [], []
        self.requests = self.payload_bytes = self.response_bytes = 0
        self._token, self._pending, self._prepared = None, None, None
        self._served, self._transport = False, None

    def source_preserved(self):
        return (self.case, self._user, self._key, self._members, self._capabilities) == self._original

    def release_observation(self):
        pass

    def release_cancel(self):
        pass

    def _error(self, code):
        with self.lock:
            code = code if code in ERROR_CODES else "unexpected_input"
            if code not in self.errors:
                self.errors.append(code)

    def begin(self, method, target, authorization, body=b""):
        with self.lock:
            try:
                return self._begin(method, target, authorization, body)
            except FixtureError as error:
                self._error(str(error))
                raise

    def _begin(self, method, target, authorization, body=b""):
        with self.lock:
            if not self.source_preserved():
                raise FixtureError("source_changed")
            if self.errors:
                raise FixtureError("sequence_invalid")
            if self.requests >= 32:
                raise FixtureError("request_limit")
            self.requests += 1
            if self._pending is not None or len(self.events) >= 4:
                raise FixtureError("sequence_invalid")
            stage = len(self.events)
            if type(authorization) is not str or type(body) is not bytes:
                raise FixtureError("credentials_invalid")
            if stage == 0:
                expected = "Basic " + base64.b64encode((self._user + ":" + self._key).encode("ascii")).decode("ascii")
                if not hmac.compare_digest(authorization, expected):
                    raise FixtureError("credentials_invalid")
                if (method, target, body) != ("GET", AUTH, b""):
                    raise FixtureError("sequence_invalid")
                self._token = "synthetic-" + secrets.token_hex(24)
                request = ("grant", "account", 200)
            else:
                if not hmac.compare_digest(authorization, self._token):
                    raise FixtureError("token_invalid")
                if stage == 1 and self.case == "alias_nested_listing":
                    if (method, target, body) != ("HEAD", PROBE, b""):
                        raise FixtureError("sequence_invalid")
                    if "readFiles" not in self._capabilities:
                        raise FixtureError("capability_denied")
                    request = ("root_probe", "nested_absent_object", 404)
                else:
                    expected_target = BUCKETS if stage == 1 else FILES
                    if method != "POST" or target != expected_target:
                        raise FixtureError("sequence_invalid")
                    required = "listBuckets" if stage == 1 else "listFiles"
                    if required not in self._capabilities:
                        raise FixtureError("capability_denied")
                    value = parse_body(body)
                    expected = {"accountId": "synthetic-account", "bucketId": BUCKET_ID} if stage == 1 else {
                        "bucketId": BUCKET_ID, "maxFileCount": 1000}
                    if stage >= 2:
                        if self.case == "alias_nested_listing":
                            expected.update(prefix="nested/", startFileName="nested/" if stage == 2 else MARKER)
                        elif stage == 3:
                            expected["startFileName"] = MARKER
                    if set(value) != set(expected) or any(type(value[k]) is not type(v) or value[k] != v for k, v in expected.items()):
                        raise FixtureError("sequence_invalid")
                    request = ("bucket_discovery", "restricted_bucket", 200) if stage == 1 else (
                        "file_names", "first_page" if stage == 2 else "continuation_page", 200)
            self._pending = request
            return request

    def response(self, request, origin):
        if request != self._pending or not re.fullmatch(r"http://127\.0\.0\.1:[1-9][0-9]{0,4}", origin) or not 1 <= int(origin.rsplit(":", 1)[1]) <= 65535:
            raise FixtureError("sequence_invalid")
        kind, role, status = request
        if kind == "grant":
            value = dict(accountId="synthetic-account", authorizationToken=self._token, apiInfo=dict(storageApi=dict(
                apiUrl=origin, downloadUrl=origin, absoluteMinimumPartSize=5000000, recommendedPartSize=100000000,
                allowed=dict(buckets=[dict(id=BUCKET_ID, name=BUCKET)], capabilities=list(self._capabilities), namePrefix=None))))
        elif kind == "bucket_discovery":
            value = dict(buckets=[dict(accountId="synthetic-account", bucketId=BUCKET_ID, bucketName=BUCKET,
                bucketType="allPrivate", bucketInfo={}, revision=1)])
        elif kind == "root_probe":
            self._prepared = (request, len(response_wire(status, b"")))
            return status, b""
        else:
            members = self._members[:3] if role == "first_page" else self._members[3:]
            if self.case == "alias_nested_listing":
                members = self._members[2:3] if role == "first_page" else self._members[3:4]
            value = dict(files=[dict(fileId="synthetic-file-" + str(self._members.index((name, size))), fileName=name,
                action="upload", size=size, uploadTimestamp=1704067200000, contentSha1="none",
                contentType="application/octet-stream", fileInfo={}) for name, size in members],
                nextFileName=MARKER if role == "first_page" else None)
        body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
        self._prepared = (request, len(response_wire(status, body)))
        return status, body

    def commit(self, request, status, wire_bytes):
        with self.lock:
            if (request != self._pending or type(status) is not int or status != request[2] or type(wire_bytes) is not int or
                    self._prepared != (request, wire_bytes) or not 0 < wire_bytes <= 4096 or self.response_bytes + wire_bytes > 16384):
                raise FixtureError("sequence_invalid")
            self.response_bytes += wire_bytes
            self.events.append(request)
            self._pending = self._prepared = None

    def snapshot(self):
        with self.lock:
            return dict(case=self.case, requests=self.requests, payload_bytes=self.payload_bytes, response_bytes=self.response_bytes,
                source_preserved=self.source_preserved(), granted_capabilities=list(self._capabilities) if self.events else None,
                errors=list(self.errors), events=[
                    dict(ordinal=i + 1, kind=k, role=r, status=s, object_bytes=0) for i, (k, r, s) in enumerate(self.events)])


class _Server(_http._Server):
    def __init__(self, state):
        super().__init__(state)
        self.deadline = time.monotonic() + 60
        self._close_attempted = False

    def close(self):
        if self._close_attempted:
            if not self.cleanup_complete:
                raise FixtureError("cleanup_failed")
            return
        self._close_attempted = True
        super().close()

    def _parse(self, stream):
        line = stream.readline(4097)
        if not re.fullmatch(rb"(?:GET|HEAD|POST) /[^\x00-\x20\x7f-\xff]{1,2048} HTTP/1\.[01]\r\n", line):
            raise FixtureError("request_invalid")
        method, target, _ = line.decode("ascii").split(" ")
        headers, total = {}, len(line)
        for _ in range(32):
            line = stream.readline(8193)
            total += len(line)
            if total > 8192 or not line.endswith(b"\r\n"):
                raise FixtureError("headers_invalid")
            if line == b"\r\n":
                break
            key, colon, value = line[:-2].partition(b":")
            if not colon or not _http.HEADER.fullmatch(key) or any(c < 32 or c > 126 for c in value):
                raise FixtureError("headers_invalid")
            key = key.decode("ascii").lower()
            if key in headers:
                raise FixtureError("headers_invalid")
            headers[key] = value.decode("ascii").strip(" ")
        else:
            raise FixtureError("headers_invalid")
        if (set(headers) - {"host", "user-agent", "accept", "accept-encoding", "connection", "content-length", "content-type", "authorization"}
                or headers.get("host") != f"127.0.0.1:{self.port}"
                or headers.get("accept-encoding", "identity") not in {"identity", "gzip"}
                or headers.get("connection", "close").lower() not in {"close", "keep-alive"}
                or "authorization" not in headers
                or (method, target) not in {("GET", AUTH), ("HEAD", PROBE), ("POST", BUCKETS), ("POST", FILES)}):
            raise FixtureError("headers_invalid")
        length = headers.get("content-length", "0")
        if method == "POST":
            if not re.fullmatch(r"[1-9][0-9]{0,3}", length) or int(length) > 1024 or headers.get("content-type") != "application/json":
                raise FixtureError("request_body_rejected")
        elif length != "0" or "content-type" in headers:
            raise FixtureError("request_body_rejected")
        # SocketIO may return a partial read: never treat one read as complete.
        body = bytearray()
        while len(body) < int(length):
            chunk = stream.read(int(length) - len(body))
            if not chunk:
                raise FixtureError("request_body_rejected")
            body.extend(chunk)
        return method, target, headers["authorization"], bytes(body)

    def _worker(self, sock):
        try:
            with self.lock:
                self.sockets[sock] = min(self.deadline, time.monotonic() + 3)
            sock.settimeout(3)
            with sock.makefile("rb", buffering=0) as stream:
                method, target, authorization, body = self._parse(stream)
                if select.select([sock], [], [], 0)[0] and sock.recv(1, socket.MSG_PEEK):
                    raise FixtureError("request_body_rejected")
                request = self.state.begin(method, target, authorization, body)
                self._live(sock)
                with self.state.lock:
                    status, payload = self.state.response(request, self.endpoint.rstrip("/"))
                    wire = response_wire(status, payload)
                    sock.sendall(wire)
                    self.state.commit(request, status, len(wire))
        except FixtureError as error:
            self.state._error(str(error))
        except (OSError, ValueError):
            self.state._error("connection_failed")
        except BaseException:
            self.state._error("worker_failed")
        finally:
            with self.lock:
                try:
                    self._close_socket(sock)
                except OSError:
                    self.state._error("cleanup_failed")
                else:
                    self.sockets.pop(sock, None)


@contextmanager
def serve_b2_listing(state):
    if type(state) is not AppB2ListingState or state._served:
        raise ValueError("input_invalid")
    state._served = True
    server = _Server(state)
    state._transport = server
    try:
        server.start()
        yield server
    finally:
        server.close()
