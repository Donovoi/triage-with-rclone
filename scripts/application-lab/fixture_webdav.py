"""Closed synthetic WebDAV transport; fixture observations are not app acceptance.

The HTTP sibling owns sockets, admission, absolute deadlines and thread cleanup.
Both source files must be included in the supervisor's loaded-source closure.
No server starts on import. Credentials and endpoint never enter snapshots.
"""
from __future__ import annotations

import base64
import binascii
from contextlib import contextmanager
import hashlib
import hmac
from pathlib import Path
import re
import select
import socket
import threading
import time
from types import MappingProxyType, ModuleType
from urllib.parse import quote, unquote
import xml.etree.ElementTree as ET

_HTTP_PATH = Path(__file__).resolve().with_name("fixture_http.py")
_HTTP_BYTES = _HTTP_PATH.read_bytes()
loaded_http_source_sha256 = hashlib.sha256(_HTTP_BYTES).hexdigest()
_http = ModuleType("_application_webdav_owned_http")
_http.__file__ = str(_HTTP_PATH)
exec(compile(_HTTP_BYTES, str(_HTTP_PATH), "exec"), _http.__dict__)
del _HTTP_BYTES
FixtureError = _http.FixtureError

INVOCATIONS = ("listing", "acquisition", "mismatch", "missing", "wrong_credentials",
               "accepted_a", "revoked_a", "replacement_b", "permission_denied",
               "truncated_transfer", "cancellation")
EPOCHS = ("accepted_a", "revoked_a", "replacement_b")
MISSING_MEMBER = "missing-synthetic.txt"
MODIFIED = "Thu, 02 Jan 2025 03:04:05 GMT"
MEMBERS = ("", "README-synthetic.txt", "large/cancel.bin", "nested/binary.bin",
           "nested/spaced name.txt", "large/", "nested/", MISSING_MEMBER)
MANIFEST = {
    "README-synthetic.txt": (30, "64d5b40a5f4773b14940a6ce1dd57cf87b44ce5940c097088732ffc71be280cf"),
    "large/cancel.bin": (2097152, "91d3beb88a9b2f778a6c44a1c53b63d3c79931845a9aef84b3fb414610bd1938"),
    "nested/binary.bin": (256, "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880"),
    "nested/spaced name.txt": (20, "0c6308d568f8ec30fbf044baac7827edac83a2465a60439ff653e277a5d9619e"),
}
# rclone v1.75.2 backend/webdav/webdav.go: standardProps, readMetaDataForPath,
# listAll and Object.Open. Generic vendor sends this exact body and no MIME type.
PROPFIND_BODY = (b'<?xml version="1.0"?>\n<d:propfind xmlns:d="DAV:">\n <d:prop>\n'
                b'  <d:displayname/>\n  <d:getlastmodified/>\n  <d:getcontentlength/>\n'
                b'  <d:resourcetype/>\n </d:prop>\n</d:propfind>\n')
COUNTERS = ("requests", "credential_attempts", "authenticated", "auth_denied",
            "propfinds", "metadata_reads", "directory_reads", "gets", "content_reads",
            "missing", "permission_denied", "truncated", "ranges", "rejected",
            "payload_bytes", "completed_payload_bytes", "response_bytes")
EVENTS = frozenset({"observation", "basic_accepted", "basic_denied", "metadata",
                    "directory", "content", "missing", "permission_denied", "truncated",
                    "cancel_prefix", "cancel_disconnected"})
ERROR_CODES = _http.ERROR_CODES | {"credentials_invalid", "epoch_invalid", "epoch_failed",
                                 "metadata_required", "range_invalid", "invocation_invalid"}


def _credential(value, *, user=False):
    return (type(value) is str and 1 <= len(value) <= 128 and
            all(33 <= ord(c) <= 126 for c in value) and (not user or ":" not in value))


class AppWebDavState:
    def __init__(self, files, invocation, user, password_a, *, wrong_password, password_b):
        if (type(files) is not dict or set(files) != set(MANIFEST) or
                any(type(v) is not bytes or (len(v), hashlib.sha256(v).hexdigest()) != MANIFEST[k]
                    for k, v in files.items()) or type(invocation) is not str or
                invocation not in INVOCATIONS or invocation in EPOCHS[1:] or
                not _credential(user, user=True) or
                any(not _credential(v) for v in (password_a, wrong_password, password_b)) or
                len({password_a, wrong_password, password_b}) != 3):
            raise ValueError("input_invalid")
        self.files = MappingProxyType(dict(files))
        self._original = tuple(sorted(files.items()))
        self._dirs = frozenset({"", "large/", "nested/"})
        self._user = user.encode("ascii")
        self._passwords = tuple(p.encode("ascii") for p in (password_a, wrong_password, password_b))
        self.invocation = invocation
        self.epoch = 1
        self.cancel_member = "large/cancel.bin"
        self.lock = threading.RLock()
        self._served = False
        self._transport_attempted = False
        self._transport = None
        self._allocated_bytes = 0
        self._total_requests = 0
        self._active_requests = 0
        self._transition_failed = False
        self.events, self.errors, self.history = [], [], []
        self._reset_epoch()

    def _reset_epoch(self):
        self.counters = dict.fromkeys(COUNTERS, 0)
        self.observation_started = threading.Event()
        self.cancel_started = threading.Event()
        self._observation_release = threading.Event()
        self._cancel_release = threading.Event()
        self._observation_claimed = self._cancel_claimed = False
        self.cancel_disconnected = False
        self._metadata = set()
        self._completed = set()

    def source_preserved(self):
        return tuple(sorted(self.files.items())) == self._original

    def release_observation(self):
        self._observation_release.set()

    def release_cancel(self):
        """Teardown escape, never evidence of a client disconnect."""
        self._cancel_release.set()

    def _error(self, code):
        with self.lock:
            code = code if code in ERROR_CODES else "worker_failed"
            if code not in self.errors:
                self.errors.append(code)

    def _event(self, label, path=""):
        with self.lock:
            if label not in EVENTS or path not in MEMBERS:
                raise FixtureError("input_invalid")
            if len(self.events) >= _http.MAX_REQUESTS * 4:
                raise FixtureError("event_limit")
            self.events.append([self.epoch, label, MEMBERS.index(path)])

    def _epoch_snapshot(self):
        return dict(invocation=self.invocation, epoch=self.epoch, **self.counters,
                    observation_started=self.observation_started.is_set(),
                    observation_released=self._observation_release.is_set(),
                    cancel_started=self.cancel_started.is_set(),
                    cancel_released=self._cancel_release.is_set(),
                    cancel_disconnected=self.cancel_disconnected)

    def snapshot(self):
        with self.lock:
            result = dict(self._epoch_snapshot(), events=[list(e) for e in self.events],
                          errors=list(self.errors), history=[dict(h) for h in self.history],
                          total_requests=self._total_requests, active_requests=self._active_requests,
                          transition_failed=self._transition_failed,
                          transport_attempted=self._transport_attempted,
                          source_preserved=self.source_preserved())
        result["transport"] = self._transport.transport_snapshot() if self._transport else None
        return result

    def advance_epoch(self, next_invocation, *, successful, reaped):
        """Caller proves its expected result AND reap, including the expected A denial.

        This does not prove caller config/artifact preservation. Lock ordering matches
        the inherited accept/watch ownership: transport first, then state. A
        request releases its socket and active count only after its final state
        mutation; a thread returning after that point is idle. Final cleanup
        separately requires all those threads to join.
        """
        transport = self._transport
        if transport is None:
            self._error("epoch_invalid")
            self._transition_failed = True
            raise FixtureError("epoch_invalid")
        with transport.lock, self.lock:
            positive = (self.invocation == "accepted_a" and self._completed == {"README-synthetic.txt"}
                        and self.counters["auth_denied"] == 0 and self.counters["authenticated"] > 0)
            denial = (self.invocation == "revoked_a" and self.counters["auth_denied"] > 0 and
                      self.counters["authenticated"] == self.counters["payload_bytes"] == 0)
            expected = {"accepted_a": "revoked_a", "revoked_a": "replacement_b"}.get(self.invocation)
            if (type(next_invocation) is not str or next_invocation != expected or
                    successful is not True or reaped is not True or self.errors or self._transition_failed or
                    self._active_requests or transport.sockets or transport.stopping.is_set() or
                    time.monotonic() >= transport.deadline or not self.source_preserved() or
                    not self.observation_started.is_set() or not self._observation_release.is_set() or
                    not (positive or denial)):
                self._transition_failed = True
                self._error("epoch_failed")
                raise FixtureError("epoch_failed")
            self.history.append(self._epoch_snapshot())
            self.invocation, self.epoch = next_invocation, self.epoch + 1
            self._reset_epoch()


class _Server(_http._Server):
    def _parse(self, stream):
        line = stream.readline(4097)
        if len(line) > 4096 or not re.fullmatch(rb"[A-Z]+ /[^\x00-\x20\x7f-\xff]* HTTP/1\.[01]\r\n", line):
            raise FixtureError("request_invalid")
        method, target, _ = line.decode("ascii").split(" ")
        headers, total = {}, len(line)
        for _ in range(_http.MAX_HEADER_LINES):
            line = stream.readline(_http.MAX_HEADER_BYTES + 1)
            total += len(line)
            if total > _http.MAX_HEADER_BYTES or not line.endswith(b"\r\n"):
                raise FixtureError("headers_invalid")
            if line == b"\r\n":
                break
            name, colon, value = line[:-2].partition(b":")
            if not colon or not _http.HEADER.fullmatch(name) or any(c < 32 or c > 126 for c in value):
                raise FixtureError("headers_invalid")
            name = name.decode("ascii").lower()
            if name in headers:
                raise FixtureError("headers_invalid")
            headers[name] = value.decode("ascii").strip(" ")
        else:
            raise FixtureError("headers_invalid")
        allowed = {"host", "user-agent", "accept", "accept-encoding", "connection", "content-length",
                   "authorization", "referer", "depth", "range"}
        if (set(headers) - allowed or headers.get("host") != f"127.0.0.1:{self.port}" or
                headers.get("referer") != self.endpoint or
                headers.get("connection", "close").lower() not in {"close", "keep-alive"} or
                headers.get("accept-encoding", "identity") not in {"identity", "gzip"}):
            raise FixtureError("headers_invalid")
        if method not in {"PROPFIND", "GET"}:
            raise FixtureError("method_rejected")
        try:
            path = unquote(target[1:], encoding="utf-8", errors="strict")
        except UnicodeError:
            raise FixtureError("route_invalid") from None
        if target != "/" + quote(path, safe="/") or path not in MEMBERS:
            raise FixtureError("route_invalid")
        if method == "PROPFIND":
            if (headers.get("depth") not in {"0", "1"} or "range" in headers or
                    headers.get("content-length") != str(len(PROPFIND_BODY))):
                raise FixtureError("headers_invalid")
            # The watchdog closes the socket at its absolute request deadline even
            # if a slow body keeps the per-socket inactivity timeout from expiring.
            body = bytearray()
            while len(body) < len(PROPFIND_BODY):
                part = stream.read(len(PROPFIND_BODY) - len(body))
                if not part:
                    raise FixtureError("request_body_rejected")
                body.extend(part)
            if bytes(body) != PROPFIND_BODY:
                raise FixtureError("request_body_rejected")
            if headers["depth"] == "1" and path not in self.state._dirs:
                raise FixtureError("route_invalid")
        elif headers.get("depth") != "0" or headers.get("content-length", "0") != "0":
            raise FixtureError("headers_invalid")
        return method, path, headers

    def _credentials(self, value):
        if type(value) is not str or not value.startswith("Basic ") or len(value) > 360:
            raise FixtureError("credentials_invalid")
        try:
            token = value[6:].encode("ascii")
            decoded = base64.b64decode(token, validate=True)
        except (ValueError, UnicodeError, binascii.Error):
            raise FixtureError("credentials_invalid") from None
        if base64.b64encode(decoded) != token:
            raise FixtureError("credentials_invalid")
        user, colon, password = decoded.partition(b":")
        state = self.state
        index = 1 if state.invocation == "wrong_credentials" else 2 if state.invocation == "replacement_b" else 0
        if not colon or not hmac.compare_digest(user, state._user) or not hmac.compare_digest(password, state._passwords[index]):
            raise FixtureError("credentials_invalid")
        return state.invocation not in {"wrong_credentials", "revoked_a"}

    @staticmethod
    def _range(value, length):
        if value is None:
            return 0, length - 1, False
        match = re.fullmatch(r"bytes=([1-9][0-9]{0,9})-([1-9][0-9]{0,9})", value)
        if not match:
            raise FixtureError("range_invalid")
        start = int(match[1])
        end = int(match[2])
        if start > end or end != length - 1:
            raise FixtureError("range_invalid")
        return start, end, True

    def _xml(self, path, depth):
        names = [path]
        if depth == "1":
            names += sorted(p for p in MEMBERS[:7] if p != path and p.startswith(path)
                            and "/" not in p[len(path):].rstrip("/"))
        root = ET.Element("{DAV:}multistatus")
        for name in names:
            response = ET.SubElement(root, "{DAV:}response")
            ET.SubElement(response, "{DAV:}href").text = "/" + quote(name, safe="/")
            propstat = ET.SubElement(response, "{DAV:}propstat")
            prop = ET.SubElement(propstat, "{DAV:}prop")
            ET.SubElement(prop, "{DAV:}displayname").text = name.rstrip("/").rsplit("/", 1)[-1]
            ET.SubElement(prop, "{DAV:}getlastmodified").text = MODIFIED
            ET.SubElement(prop, "{DAV:}getcontentlength").text = str(len(self.state.files[name])) if name in self.state.files else "0"
            resource = ET.SubElement(prop, "{DAV:}resourcetype")
            if name in self.state._dirs:
                ET.SubElement(resource, "{DAV:}collection")
            ET.SubElement(propstat, "{DAV:}status").text = "HTTP/1.1 200 OK"
        return ET.tostring(root, encoding="utf-8", xml_declaration=True)

    def _reply(self, sock, status, body=b"", *, object_path=None, declared=None, content_range=None):
        self._live(sock)
        with self.state.lock:
            if self.state._allocated_bytes + len(body) > _http.MAX_BODY_BYTES:
                raise FixtureError("byte_limit")
            self.state._allocated_bytes += len(body)
        reasons = {200: "OK", 206: "Partial Content", 207: "Multi-Status", 400: "Bad Request",
                   401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed"}
        length = len(body) if declared is None else declared
        content_type = "application/xml; charset=utf-8" if status == 207 else "application/octet-stream"
        header = (f"HTTP/1.1 {status} {reasons[status]}\r\nContent-Length: {length}\r\n"
                  f"Content-Type: {content_type}\r\nLast-Modified: {MODIFIED}\r\nConnection: close\r\n")
        if status == 401:
            header += 'WWW-Authenticate: Basic realm="synthetic"\r\n'
        if content_range is not None:
            header += "Content-Range: " + content_range + "\r\n"
        sock.sendall((header + "\r\n").encode("ascii"))
        for offset in range(0, len(body), 65536):
            self._live(sock)
            part = body[offset:offset + 65536]
            sock.sendall(part)
            with self.state.lock:
                self.state.counters["response_bytes"] += len(part)
                if object_path is not None:
                    self.state.counters["payload_bytes"] += len(part)
        if object_path is not None and length == len(body):
            with self.state.lock:
                self.state.counters["completed_payload_bytes"] += len(body)

    def _dispatch(self, sock, method, path, headers):
        self._live(sock)
        state = self.state
        if ((state.invocation == "listing" and path not in state._dirs) or
                (state.invocation == "missing" and path != MISSING_MEMBER) or
                (state.invocation == "cancellation" and path != state.cancel_member) or
                (state.invocation not in {"listing", "acquisition", "missing", "cancellation"} and
                 path != "README-synthetic.txt")):
            raise FixtureError("invocation_invalid")
        accepted = self._credentials(headers.get("authorization"))
        with state.lock:
            if not state.source_preserved():
                raise FixtureError("source_changed")
            state._total_requests += 1
            state.counters["requests"] += 1
            state.counters["credential_attempts"] += 1
            if state._total_requests > _http.MAX_REQUESTS:
                raise FixtureError("request_limit")
            first = not state._observation_claimed
            if first and method != "PROPFIND":
                raise FixtureError("metadata_required")
            state._observation_claimed = True
        if first:
            state._event("observation", path)
            state.observation_started.set()
        if not state._observation_release.is_set():
            self._wait(sock)
        if self.stopping.is_set():
            return
        self._live(sock)
        with state.lock:
            state.counters["authenticated" if accepted else "auth_denied"] += 1
        state._event("basic_accepted" if accepted else "basic_denied", path)
        if not accepted:
            return self._reply(sock, 401)
        if path == MISSING_MEMBER:
            if state.invocation != "missing" or method != "PROPFIND":
                raise FixtureError("invocation_invalid")
            with state.lock:
                state.counters["missing"] += 1
            state._event("missing", path)
            return self._reply(sock, 404)
        if state.invocation == "permission_denied" and path == "README-synthetic.txt":
            if method != "PROPFIND":
                raise FixtureError("metadata_required")
            with state.lock:
                state.counters["permission_denied"] += 1
            state._event("permission_denied", path)
            return self._reply(sock, 403)
        if method == "PROPFIND":
            with state.lock:
                state.counters["propfinds"] += 1
                is_list = headers["depth"] == "1"
                state.counters["directory_reads" if is_list else "metadata_reads"] += 1
                if not is_list and path in state.files:
                    state._metadata.add(path)
            state._event("directory" if is_list else "metadata", path)
            return self._reply(sock, 207, self._xml(path, headers["depth"]))
        if path not in state.files or state.invocation in {"listing", "missing", "permission_denied"}:
            raise FixtureError("invocation_invalid")
        with state.lock:
            if path not in state._metadata:
                raise FixtureError("metadata_required")
            if state.invocation in EPOCHS and path != "README-synthetic.txt":
                raise FixtureError("invocation_invalid")
            start, end, ranged = self._range(headers.get("range"), len(state.files[path]))
            state.counters["gets"] += 1
            state.counters["content_reads"] += 1
            state.counters["ranges"] += ranged
        body = state.files[path][start:end + 1]
        status = 206 if ranged else 200
        content_range = f"bytes {start}-{end}/{len(state.files[path])}" if ranged else None
        state._event("content", path)
        if state.invocation == "truncated_transfer":
            if path != "README-synthetic.txt":
                raise FixtureError("invocation_invalid")
            # Every initial/resumed GET is shorter than its advertised range. Never
            # repair the suffix: pinned ReOpen may otherwise turn truncation into success.
            with state.lock:
                state.counters["truncated"] += 1
            state._event("truncated", path)
            return self._reply(sock, status, body[:max(0, len(body) // 2)], object_path=path,
                               declared=len(body), content_range=content_range)
        if state.invocation == "cancellation":
            with state.lock:
                if path != state.cancel_member or ranged or state._cancel_claimed:
                    raise FixtureError("cancel_replayed")
                state._cancel_claimed = True
            self._reply(sock, 200, body[:65536], object_path=path, declared=len(body))
            state._event("cancel_prefix", path)
            state.cancel_started.set()
            self._wait(sock, cancel=True)
            return
        self._reply(sock, status, body, object_path=path, content_range=content_range)
        if not ranged:
            with state.lock:
                state._completed.add(path)

    def _worker(self, sock):
        with self.state.lock:
            self.state._active_requests += 1
        try:
            sock.settimeout(_http.REQUEST_SECONDS)
            with sock.makefile("rb", buffering=0) as stream:
                method, path, headers = self._parse(stream)
                if select.select([sock], [], [], 0)[0] and sock.recv(1, socket.MSG_PEEK):
                    raise FixtureError("request_body_rejected")
                self._dispatch(sock, method, path, headers)
        except FixtureError as error:
            code = str(error)
            self.state._error(code)
            with self.state.lock:
                self.state.counters["rejected"] += 1
            try:
                if not self.stopping.is_set() and code not in {"lifetime_limit", "client_aborted", "socket_unowned"}:
                    self._reply(sock, 405 if code == "method_rejected" else 400)
            except (OSError, FixtureError):
                pass
        except (OSError, ValueError):
            if not self.stopping.is_set():
                self.state._error("connection_failed")
        except BaseException:
            self.state._error("worker_failed")
        finally:
            with self.lock, self.state.lock:
                try:
                    self._close_socket(sock)
                except OSError:
                    self.state._error("cleanup_failed")
                    # Keep the uncertain socket in the owned inventory. Neither
                    # an epoch transition nor final cleanup may claim it gone.
                else:
                    self.state._active_requests -= 1
                    self.sockets.pop(sock, None)


@contextmanager
def serve_webdav(state):
    if type(state) is not AppWebDavState:
        raise ValueError("input_invalid")
    with state.lock:
        if state._served:
            raise ValueError("state_reused")
        state._served = True
        state._transport_attempted = True
    server = _Server(state)
    state._transport = server
    try:
        server.start()
        yield server
    finally:
        server.close()
