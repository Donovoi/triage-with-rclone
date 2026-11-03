"""Single-listener loopback fixture. Import and Model perform no I/O."""
import re
import socket
import threading
import time
import command_contract as C

PROPFIND = (b'<?xml version="1.0"?>\n<d:propfind xmlns:d="DAV:">\n <d:prop>\n'
            b'  <d:displayname/>\n  <d:getlastmodified/>\n  <d:getcontentlength/>\n'
            b'  <d:resourcetype/>\n </d:prop>\n</d:propfind>\n')


def metadata(size):
    return (b'<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>/payload.bin</d:href>'
            b'<d:propstat><d:prop><d:displayname>payload.bin</d:displayname><d:getlastmodified>Thu, 02 Jan 2025 03:04:05 GMT</d:getlastmodified>'
            b'<d:getcontentlength>' + str(size).encode("ascii") + b'</d:getcontentlength><d:resourcetype/></d:prop>'
            b'<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>')


def parse_request(header, body, port, size=30):
    C.require(type(header) is bytes and len(header) <= 8192 and header.endswith(b"\r\n\r\n"), "fixture")
    lines = header[:-4].split(b"\r\n")
    C.require(len(lines) <= 33 and lines[0] in (b"GET /payload.bin HTTP/1.1", b"PROPFIND /payload.bin HTTP/1.1"), "fixture")
    values = {}
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        C.require(colon and re.fullmatch(rb"[A-Za-z-]+", name) and all(32 <= b < 127 for b in value), "fixture")
        name = name.lower()
        C.require(name not in values, "fixture"); values[name] = value.strip(b" ")
    allowed = {b"host",b"authorization",b"user-agent",b"accept",b"accept-encoding",b"connection",b"content-length",b"depth",b"referer",b"range"}
    C.require(not set(values)-allowed and values.get(b"host") == f"127.0.0.1:{port}".encode(), "fixture")
    C.require(values.get(b"referer") == f"http://127.0.0.1:{port}/".encode(), "fixture")
    C.require(values.get(b"connection",b"close").lower() in (b"close",b"keep-alive") and values.get(b"accept-encoding",b"identity") in (b"identity",b"gzip"), "fixture")
    auth = values.get(b"authorization")
    credential = "A" if auth == b"Bearer "+C.TOKENS[0] else "B" if auth == b"Bearer "+C.TOKENS[1] else "empty" if auth == b"Bearer" else None
    C.require(credential is not None, "fixture")
    method = lines[0].split(b" ")[0].decode("ascii")
    if method == "PROPFIND":
        C.require(values.get(b"depth") == b"0" and b"range" not in values and body == PROPFIND and values.get(b"content-length") == str(len(body)).encode(), "fixture")
    else:
        C.require(not body and values.get(b"content-length", b"0") == b"0" and values.get(b"depth") == b"0", "fixture")
        C.require(values.get(b"range") in (None,b"bytes=0-",f"bytes=0-{size-1}".encode()), "fixture")
    return method, credential


class Model:
    def __init__(self, case):
        C.require(case in C.CASES, "fixture")
        self.case, self.events, self.failed = case, [], False

    def request(self, method, credential):
        expected = C.expected_events(self.case)
        C.require(len(self.events) < len(expected), "fixture")
        row = dict(expected[len(self.events)])
        C.require((method, credential) == (row["method"], row["credential"]), "fixture")
        row["payload_bytes"] = 0; self.events.append(row)
        return row["status"]

    def payload(self, count):
        C.require(self.events and C.integer(count, 0, C.EXTENTS[-1] if self.case == "cancellation" else len(C.BODY)), "fixture")
        C.require(self.events[-1]["method"] == "GET" and self.events[-1]["status"] == 200 and count >= self.events[-1]["payload_bytes"], "fixture")
        self.events[-1]["payload_bytes"] = count


class Server:
    def __init__(self, case, deadline, clock=time.monotonic):
        self.model, self.deadline, self.clock = Model(case), deadline, clock
        self.lock = threading.Lock(); self.stop = threading.Event()
        self.first_observed = threading.Event(); self.second_observed = threading.Event()
        self.listener = self.active = self.thread = None
        self.closed = False

    def start(self):
        C.require(self.listener is None and self.clock() < self.deadline, "fixture")
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.listener.bind(("127.0.0.1", 0)); self.listener.listen(1)
            self.port = self.listener.getsockname()[1]
            self.thread = threading.Thread(target=self._serve, name="owned-webdav-command", daemon=False)
            self.thread.start()
        except BaseException:
            self.listener.close(); raise
        return f"http://127.0.0.1:{self.port}/"

    def _remaining(self, request_deadline):
        remaining = min(self.deadline, request_deadline)-self.clock()
        C.require(not self.stop.is_set() and remaining > 0, "fixture")
        return remaining

    def _read(self, conn, until, deadline):
        data = b""
        while not until(data):
            conn.settimeout(self._remaining(deadline))
            chunk = conn.recv(1)  # Header cannot overread body/pipelined input.
            C.require(chunk and len(data) < 8192, "fixture"); data += chunk
        return data

    def _send(self, conn, data, deadline):
        conn.settimeout(self._remaining(deadline)); conn.sendall(data)

    def _wait(self, event, deadline):
        C.require(event.wait(self._remaining(deadline)) and not self.stop.is_set(), "fixture")

    def _serve(self):
        try:
            while not self.stop.is_set():
                C.require(self.clock() < self.deadline, "fixture")
                self.listener.settimeout(min(0.2, self.deadline-self.clock()))
                try:
                    conn, peer = self.listener.accept()
                except socket.timeout:
                    continue
                self.active = conn
                try:
                    C.require(peer[0] == "127.0.0.1", "fixture")
                    deadline = min(self.deadline, self.clock()+15)
                    header = self._read(conn, lambda b: b.endswith(b"\r\n\r\n"), deadline)
                    matches = re.findall(rb"(?im)^content-length: *([0-9]+) *\r$", header)
                    C.require(len(matches) <= 1, "fixture")
                    size = int(matches[0]) if matches else 0
                    C.require(size <= 4096, "fixture")
                    body = b""
                    while len(body) < size:
                        conn.settimeout(self._remaining(deadline)); chunk = conn.recv(size-len(body))
                        C.require(chunk, "fixture"); body += chunk
                    method, credential = parse_request(header, body, self.port, C.CANCEL_SIZE if self.model.case=="cancellation" else 30)
                    with self.lock:
                        status = self.model.request(method, credential)
                    cancel = self.model.case == "cancellation"
                    data = metadata(C.CANCEL_SIZE if cancel else 30) if status == 207 else C.BODY if status == 200 else b""
                    length = C.CANCEL_SIZE if status == 200 and cancel else len(data)
                    extra = b'WWW-Authenticate: Bearer realm="synthetic"\r\n' if status == 401 else b"Content-Type: application/xml; charset=utf-8\r\n" if status==207 else b"Content-Type: application/octet-stream\r\n"
                    self._send(conn, f"HTTP/1.1 {status} synthetic\r\nContent-Length: {length}\r\nConnection: close\r\n".encode()+extra+b"\r\n", deadline)
                    if status == 200 and cancel:
                        block = C.BLOCK*(C.EXTENTS[0]//256)
                        self._send(conn, block, deadline)
                        with self.lock: self.model.payload(C.EXTENTS[0])
                        self._wait(self.first_observed, deadline)
                        self._send(conn, block, deadline)
                        with self.lock: self.model.payload(C.EXTENTS[1])
                        self._wait(self.second_observed, deadline)
                        # Signal happens after the second witness. Never finish the body.
                        self.stop.wait(self._remaining(deadline))
                        C.require(self.stop.is_set(), "fixture")
                    else:
                        self._send(conn, data, deadline)
                        if status == 200:
                            with self.lock: self.model.payload(len(data))
                finally:
                    conn.close(); self.active = None
        except (OSError, C.Rejected):
            if not self.stop.is_set():
                with self.lock: self.model.failed = True

    def snapshot(self):
        with self.lock:
            return [dict(row) for row in self.model.events], self.model.failed

    def close(self, deadline):
        self.stop.set(); self.first_observed.set(); self.second_observed.set()
        active = self.active
        if active is not None:
            try: active.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            active.close()
        if self.listener is not None: self.listener.close()
        if self.thread is not None: self.thread.join(max(0, deadline-self.clock()))
        self.closed = (self.thread is None or not self.thread.is_alive()) and (self.listener is None or self.listener.fileno() == -1) and self.active is None
        return self.closed
