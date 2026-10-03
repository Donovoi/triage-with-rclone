"""Small independent read-only protocol fixtures, never general-purpose servers."""

import base64
from contextlib import contextmanager
import ftplib
import html
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import posixpath
import socket
import socketserver
import threading
import urllib.parse
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
    server = FtpFixture(state) if kind == "ftp" else HttpFixture(state)
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
