"""Owned loopback TLS for synthetic protocol fixtures, never host trust setup.

Certificate generation is lazy and requires the reviewed test dependency.
Nothing binds, generates keys, changes trust or starts threads on import.
"""
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import os
from pathlib import Path
import secrets
import socket
import ssl
import stat
import sys
import tempfile
import threading
import time


CRYPTOGRAPHY_VERSION = "50.0.2"
MAX_MATERIAL_BYTES = 65536
PCLOUD_OAUTH_NAME = "fixture.pcloud.com"


def _server_name(value):
    if value is not None and (type(value) is not str or value != PCLOUD_OAUTH_NAME):
        raise TlsError("tls_unreviewed_authority")
    return value


def _pcloud_sni(_socket, name, _context):
    # Never render an untrusted SNI value; failure remains a TLS failure.
    if name != PCLOUD_OAUTH_NAME:
        return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
    return None


class TlsError(RuntimeError):
    """Sanitized fixture failure; never include keys, request bytes or paths."""


def _plain_path(path):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise TlsError("tls_absolute_path_required")
    for member in (path, *path.parents):
        info = member.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise TlsError("tls_reparse_refused")
    return path


def _identity(info):
    return info.st_dev, info.st_ino


@dataclass(frozen=True)
class _Owner:
    path: Path
    identity: tuple


@dataclass(frozen=True)
class _Binding:
    owner: _Owner
    sha256: str
    size: int


def _read_regular(path, owner=None):
    path = _plain_path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_MATERIAL_BYTES:
        raise TlsError("tls_regular_owned_file_required")
    if owner is not None and (path != owner.path or _identity(before) != owner.identity):
        raise TlsError("tls_material_replaced")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if _identity(opened) != _identity(before) or opened.st_nlink != 1:
            raise TlsError("tls_material_replaced")
        pieces, length = [], 0
        while True:
            piece = os.read(fd, min(8192, MAX_MATERIAL_BYTES + 1 - length))
            if not piece:
                break
            pieces.append(piece)
            length += len(piece)
            if length > MAX_MATERIAL_BYTES:
                raise TlsError("tls_material_size_limit")
        data = b"".join(pieces)
        after = os.fstat(fd)
        current = _plain_path(path).lstat()
        if (_identity(current) != _identity(opened) or current.st_nlink != 1
                or after.st_size != len(data) or current.st_size != len(data)
                or (after.st_mtime_ns, after.st_ctime_ns) != (opened.st_mtime_ns, opened.st_ctime_ns)):
            raise TlsError("tls_material_changed")
        return data, _Owner(path, _identity(opened))
    finally:
        os.close(fd)


def _validated(binding):
    data, _ = _read_regular(binding.owner.path, binding.owner)
    if len(data) != binding.size or hashlib.sha256(data).hexdigest() != binding.sha256:
        raise TlsError("tls_material_hash_mismatch")
    return data


def _crypto():
    # Do not use an older ambient installation accidentally. Import only when
    # generating material, so unrelated stdlib fixtures remain importable.
    from importlib.metadata import version
    if version("cryptography") != CRYPTOGRAPHY_VERSION:
        raise TlsError("tls_dependency_version_mismatch")
    import cryptography
    if cryptography.__version__ != CRYPTOGRAPHY_VERSION:
        raise TlsError("tls_loaded_dependency_version_mismatch")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    return x509, hashes, serialization, ec, ExtendedKeyUsageOID, NameOID


class FixtureCertificates(AbstractContextManager):
    """Fresh CA/leaf material inside a caller-owned temporary root.

    ``rclone_ca_args`` validates the owned CA immediately before child launch.
    The caller must keep this context alive until all such children are reaped.
    Validation does not remove the filesystem race against the same OS user;
    this is a private synthetic fixture, not a hostile-user sandbox.
    """
    def __init__(self):
        raise TypeError("use_FixtureCertificates_create")

    @classmethod
    def create(cls, owned_root, *, server_name=None):
        server_name = _server_name(server_name)
        root = _plain_path(owned_root)
        if not root.is_dir():
            raise TlsError("tls_root_directory_required")
        x509, hashes, serialization, ec, eku, name_oid = _crypto()
        instance = object.__new__(cls)
        instance._lock = threading.RLock()
        instance._closed = False
        instance.cleanup_complete = False
        instance._owners = []
        instance._bindings = []
        instance._context = None
        instance._leases = 0
        instance._server_name = server_name
        instance.directory = Path(tempfile.mkdtemp(prefix="fixture-tls-", dir=root))
        instance._directory_owner = _Owner(instance.directory, _identity(instance.directory.lstat()))
        try:
            instance.directory.chmod(0o700)
            now = datetime.now(timezone.utc)
            ca_key, leaf_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
            ca_name = x509.Name([x509.NameAttribute(name_oid.COMMON_NAME, "Synthetic fixture CA " + secrets.token_hex(8))])
            leaf_name = x509.Name([x509.NameAttribute(name_oid.COMMON_NAME, "Synthetic loopback fixture")])
            ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
                  .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
                  .not_valid_after(now + timedelta(hours=1))
                  .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                  .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                               data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                               crl_sign=True, encipher_only=None, decipher_only=None), critical=True)
                  .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
                  .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                  .sign(ca_key, hashes.SHA256()))
            leaf = (x509.CertificateBuilder().subject_name(leaf_name).issuer_name(ca_name).public_key(leaf_key.public_key())
                    .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
                    .not_valid_after(now + timedelta(hours=1))
                    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                    .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                                 data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                                 crl_sign=False, encipher_only=None, decipher_only=None), critical=True)
                    .add_extension(x509.ExtendedKeyUsage([eku.SERVER_AUTH]), critical=False)
                    .add_extension(x509.SubjectAlternativeName([x509.DNSName(server_name) if server_name is not None
                        else x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
                    .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
                    .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                    .sign(ca_key, hashes.SHA256()))
            ca_binding = instance._write("ca.pem", ca.public_bytes(serialization.Encoding.PEM))
            leaf_binding = instance._write("leaf.pem", leaf.public_bytes(serialization.Encoding.PEM))
            password = secrets.token_bytes(32)
            private = leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.BestAvailableEncryption(password))
            key_binding = instance._write("leaf-key.pem", private)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.set_alpn_protocols(["http/1.1"])
            if server_name is not None:
                context.set_servername_callback(_pcloud_sni)
            if hasattr(context, "num_tickets"):
                context.num_tickets = 0
            _validated(leaf_binding)
            _validated(key_binding)
            context.load_cert_chain(str(leaf_binding.owner.path), str(key_binding.owner.path), password=password)
            instance._remove_owned(key_binding.owner)
            instance._bindings.remove(key_binding)
            instance._ca, instance._leaf, instance._context = ca_binding, leaf_binding, context
            return instance
        except BaseException:
            if not instance.close():
                raise TlsError("tls_material_cleanup_failed") from None
            raise

    def _owned_directory(self):
        directory = _plain_path(self.directory)
        info = directory.lstat()
        if _identity(info) != self._directory_owner.identity or not stat.S_ISDIR(info.st_mode):
            raise TlsError("tls_directory_replaced")
        return directory

    def _write(self, name, data):
        path = self.directory / name
        self._owned_directory()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        owner = _Owner(path, _identity(os.fstat(fd)))
        self._owners.append(owner)
        try:
            handle = os.fdopen(fd, "wb")
        except BaseException:
            os.close(fd)
            raise
        with handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        path.chmod(0o600)
        actual, observed = _read_regular(path, owner)
        if actual != data or observed != owner:
            raise TlsError("tls_material_write_mismatch")
        binding = _Binding(owner, hashlib.sha256(data).hexdigest(), len(data))
        self._bindings.append(binding)
        return binding

    def _remove_owned(self, owner):
        self._owned_directory()
        path = _plain_path(owner.path)
        info = path.lstat()
        if _identity(info) != owner.identity or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise TlsError("tls_cleanup_ownership_mismatch")
        path.unlink()
        if path.exists() or path.is_symlink():
            raise TlsError("tls_cleanup_file_remains")
        self._owners.remove(owner)

    def _active(self):
        if self._closed or self._context is None:
            raise TlsError("tls_material_closed")
        self._owned_directory()

    @property
    def server_name(self):
        return _server_name(self._server_name)

    @property
    def ca_path(self):
        return self._ca.owner.path

    @property
    def ca_sha256(self):
        return self._ca.sha256

    def rclone_ca_args(self):
        with self._lock:
            self._active()
            _validated(self._ca)
            return ["--ca-cert", str(self.ca_path)]

    def server_context(self):
        with self._lock:
            self._active()
            _validated(self._ca)
            _validated(self._leaf)
            return self._context

    def _acquire_server(self):
        with self._lock:
            context = self.server_context()
            self._leases += 1
            return context

    def _release_server(self):
        with self._lock:
            self._leases -= 1

    def client_context(self):
        with self._lock:
            self._active()
            ca = _validated(self._ca)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_verify_locations(cadata=ca.decode("ascii"))
            context.set_alpn_protocols(["http/1.1"])
            return context

    def close(self):
        with self._lock:
            if self._closed:
                return self.cleanup_complete
            if self._leases:
                return False
            self._closed = True
            self._context = None
            okay = True
            for owner in list(reversed(self._owners)):
                try:
                    self._remove_owned(owner)
                except (OSError, TlsError):
                    okay = False
            try:
                directory = self._owned_directory()
                directory.rmdir()  # Never recurse into unexpected or replaced contents.
                okay = okay and not directory.exists() and not directory.is_symlink()
            except (OSError, TlsError):
                okay = False
            self.cleanup_complete = okay and not self._owners
            return self.cleanup_complete

    def __enter__(self):
        self._active()
        return self

    def __exit__(self, *exc):
        if not self.close():
            raise TlsError("tls_material_cleanup_failed")
        return False


@dataclass(frozen=True)
class TlsLimits:
    connection_limit: int = 64
    active_limit: int = 4
    request_seconds: float = 3.0
    lifetime_seconds: float = 60.0
    cleanup_seconds: float = 5.0

    def validate(self):
        if (type(self.connection_limit) is not int or not 1 <= self.connection_limit <= 128
                or type(self.active_limit) is not int or not 1 <= self.active_limit <= 8
                or self.active_limit > self.connection_limit):
            raise TlsError("tls_invalid_limits")
        for value, upper in ((self.request_seconds, 10), (self.lifetime_seconds, 120), (self.cleanup_seconds, 10)):
            if type(value) not in (int, float) or not 0.01 <= value <= upper:
                raise TlsError("tls_invalid_limits")


class _HttpServer(HTTPServer):
    allow_reuse_address = False
    allow_reuse_port = False

    def __init__(self, transport, handler, state):
        self.transport, self.state = transport, state
        if transport._server_name is not None:
            if sys.platform != "linux":
                raise TlsError("tls_dns_profile_requires_linux")
            # Linux REUSEADDR permits sequential TIME_WAIT reuse, not a second
            # live listener. REUSEPORT stays off; prior cleanup is still required.
            self.allow_reuse_address = True
        super().__init__(("127.0.0.1", 443 if transport._server_name is not None else 0), handler)
        self.authority = transport._server_name or f"127.0.0.1:{self.server_address[1]}"

    def get_request(self):
        raw, address = super().get_request()
        owner = self.transport
        with owner._lock:
            owner._counts["accepted_connections"] += 1
            if (owner._stopping or time.monotonic() >= owner._deadline
                    or owner._counts["accepted_connections"] > owner.limits.connection_limit
                    or len(owner._sockets) >= owner.limits.active_limit):
                owner._counts["admission_denied"] += 1
                owner._failures.add("tls_admission_rejected")
                if owner._counts["accepted_connections"] > owner.limits.connection_limit:
                    owner._stopping = True
                raw.close()
                raise OSError("tls_admission_rejected")
            deadline = min(time.monotonic() + owner.limits.request_seconds, owner._deadline)
            raw.settimeout(max(0.001, deadline - time.monotonic()))
            owner._sockets.add(raw)
            try:
                wrapped = owner._context.wrap_socket(raw, server_side=True, do_handshake_on_connect=False)
            except BaseException:
                owner._sockets.discard(raw)
                raw.close()
                owner._counts["handshake_failures"] += 1
                owner._failures.add("tls_wrap_failed")
                raise OSError("tls_wrap_failed") from None
            owner._sockets.remove(raw)
            owner._sockets.add(wrapped)
            owner._socket_deadlines[wrapped] = deadline
            return wrapped, address

    def process_request(self, request, address):
        owner = self.transport
        with owner._lock:
            if owner._stopping:
                owner._release(request)
                return
            worker = threading.Thread(target=owner._worker, args=(request, address), name="synthetic-tls-worker")
            owner._workers.append(worker)
            try:
                worker.start()
            except BaseException:
                owner._workers.remove(worker)
                owner._release(request)
                owner._failures.add("tls_worker_start_failed")
                raise

    def handle_error(self, request, address):
        with self.transport._lock:
            self.transport._failures.add("tls_server_handler_failed")


class BoundedHttpsServer(AbstractContextManager):
    """Owned IPv4 listener; handshake and HTTP share one absolute deadline.

    ``state`` is passed to the supplied handler as ``self.server.state``.
    Transport failures remain sticky in ``snapshot()``; successful cleanup does
    not turn a TLS rejection or timeout into successful protocol evidence.
    The supplied fixed-route handler must enforce method, path, headers, body,
    response-byte and per-request budgets. This foundation bounds connections
    and time only. Handlers must cooperate with socket closure; arbitrary code
    cannot be forcibly stopped by a Python thread. Cleanup failure propagates.
    """
    def __init__(self, certificates, handler_class, *, state=None, limits=None):
        if not isinstance(certificates, FixtureCertificates) or not isinstance(handler_class, type) or not issubclass(handler_class, BaseHTTPRequestHandler):
            raise TlsError("tls_invalid_server_arguments")
        self.limits = limits if limits is not None else TlsLimits()
        if not isinstance(self.limits, TlsLimits):
            raise TlsError("tls_invalid_limits")
        self.limits.validate()
        self._certificates = certificates
        self._server_name = certificates.server_name
        self._context = certificates._acquire_server()
        self._lock, self._close_lock = threading.RLock(), threading.Lock()
        self._stopping = self._closed = self._started = False
        self.cleanup_complete = False
        self._deadline = time.monotonic() + self.limits.lifetime_seconds
        self._sockets, self._socket_deadlines, self._expired_sockets = set(), {}, set()
        self._workers, self._timers = [], []
        self._failures = set()
        self._counts = dict.fromkeys(("accepted_connections", "admission_denied", "handshake_successes", "handshake_failures",
                                     "request_timeouts", "handler_failures", "aborted_connections", "closed_connections"), 0)

        class QuietHandler(handler_class):
            def log_message(self, *args):
                pass

            def parse_request(self):
                # http.client.parse_headers accepts EOF as a header terminator.
                # Closing a timed-out TLS socket can therefore wake the parser
                # with success. Check framing and ownership after that read,
                # immediately before BaseHTTPRequestHandler dispatches do_*.
                original = self.rfile

                class HeaderReader:
                    complete = False

                    def readline(self, *args):
                        line = original.readline(*args)
                        if line in (b"\r\n", b"\n"):
                            self.complete = True
                        return line

                    def __getattr__(self, name):
                        return getattr(original, name)

                reader = HeaderReader()
                self.rfile = reader
                try:
                    parsed = super().parse_request()
                finally:
                    self.rfile = original
                transport = self.server.transport
                with transport._lock:
                    deadline = transport._socket_deadlines.get(self.connection)
                    timed_out = deadline is not None and time.monotonic() >= deadline
                    if timed_out:
                        transport._mark_expired(self.connection)
                    allowed = (deadline is not None and self.connection in transport._sockets
                               and self.connection not in transport._expired_sockets
                               and not transport._stopping and not timed_out)
                    if not allowed:
                        transport._failures.add("tls_http_dispatch_rejected")
                    if parsed and not reader.complete:
                        transport._failures.add("tls_incomplete_http_headers")
                if not parsed or not reader.complete or not allowed:
                    self.close_connection = True
                    return False
                return True

        try:
            self._server = _HttpServer(self, QuietHandler, state)
            self._server.timeout = 0.02
            self.port = self._server.server_address[1]
            self.authority = self._server.authority
            self._thread = threading.Thread(target=self._serve, name="synthetic-tls-listener")
        except BaseException:
            if hasattr(self, "_server"):
                self._server.server_close()
            self._context = None
            certificates._release_server()
            raise

    def _interrupt_sockets(self):
        with self._lock:
            sockets = list(self._sockets)
        for request in sockets:
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            request.close()

    def _serve(self):
        try:
            while True:
                with self._lock:
                    if self._stopping:
                        break
                    if time.monotonic() >= self._deadline:
                        self._failures.add("tls_lifetime_deadline")
                        break
                self._server.handle_request()
        except BaseException:
            with self._lock:
                if not self._stopping:
                    self._failures.add("tls_listener_failed")
        finally:
            with self._lock:
                self._stopping = True
            self._server.server_close()
            self._interrupt_sockets()

    def _release(self, request):
        with self._lock:
            tracked = request in self._sockets
            self._sockets.discard(request)
            self._socket_deadlines.pop(request, None)
            self._expired_sockets.discard(request)
            if tracked:
                self._counts["closed_connections"] += 1
        request.close()

    def _mark_expired(self, request):
        with self._lock:
            if request in self._sockets and request not in self._expired_sockets:
                self._expired_sockets.add(request)
                self._counts["request_timeouts"] += 1
                self._failures.add("tls_request_deadline")

    def _worker(self, request, address):
        phase, timer, timer_started = "setup", None, False

        def expire():
            self._mark_expired(request)
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            request.close()

        try:
            with self._lock:
                deadline = self._socket_deadlines[request]
            timer = threading.Timer(max(0.001, deadline - time.monotonic()), expire)
            timer.name = "synthetic-tls-deadline"
            with self._lock:
                self._timers.append(timer)
            timer.start()
            timer_started = True
            phase = "handshake"
            request.settimeout(max(0.001, deadline - time.monotonic()))
            request.do_handshake()
            with self._lock:
                self._counts["handshake_successes"] += 1
            phase = "http"
            self._server.finish_request(request, address)
            if time.monotonic() >= deadline:
                self._mark_expired(request)
        except BaseException:
            with self._lock:
                if self._stopping:
                    self._counts["aborted_connections"] += 1
                elif phase == "setup":
                    self._failures.add("tls_worker_setup_failed")
                elif phase == "handshake":
                    self._counts["handshake_failures"] += 1
                    self._failures.add("tls_handshake_failed")
                else:
                    self._counts["handler_failures"] += 1
                    self._failures.add("tls_http_handler_failed")
        finally:
            if timer is not None:
                timer.cancel()
                if timer_started:
                    timer.join()
                else:
                    with self._lock:
                        self._timers.remove(timer)
            self._release(request)

    def start(self):
        with self._lock:
            if self._closed or self._started:
                raise TlsError("tls_server_not_startable")
            try:
                self._certificates.server_context()
                self._started = True
                self._thread.start()
            except BaseException:
                self._started = False
                self._server.server_close()
                self._stopping = self._closed = self.cleanup_complete = True
                self._context = None
                self._certificates._release_server()
                self._failures.add("tls_listener_start_failed")
                raise
        return self

    def snapshot(self):
        with self._lock:
            return dict(self._counts, active_connections=len(self._sockets),
                        active_workers=sum(worker.is_alive() for worker in self._workers),
                        active_timers=sum(timer.is_alive() for timer in self._timers),
                        failure_codes=sorted(self._failures), cleanup_complete=self.cleanup_complete,
                        stopping=self._stopping)

    def close(self):
        if threading.current_thread() is self._thread or threading.current_thread() in self._workers:
            raise TlsError("tls_worker_cannot_close_server")
        with self._close_lock:
            if self._closed:
                return self.cleanup_complete
            end = time.monotonic() + self.limits.cleanup_seconds
            with self._lock:
                self._stopping = True
            self._server.server_close()
            self._interrupt_sockets()
            if self._started:
                self._thread.join(max(0, end - time.monotonic()))
            for worker in self._workers:
                worker.join(max(0, end - time.monotonic()))
            for timer in self._timers:
                timer.cancel()
                if timer.ident is not None:
                    timer.join(max(0, end - time.monotonic()))
            with self._lock:
                self.cleanup_complete = (not self._thread.is_alive() and not self._sockets and not self._socket_deadlines
                                         and not self._expired_sockets
                                         and all(not worker.is_alive() for worker in self._workers)
                                         and all(not timer.is_alive() for timer in self._timers)
                                         and self._server.socket.fileno() == -1)
                # A bounded failure stays sticky, but an explicit later close
                # may reap a cooperative worker that has since exited.
                self._closed = self.cleanup_complete
                if not self.cleanup_complete:
                    self._failures.add("tls_cleanup_failed")
                else:
                    self._context = None
                    self._certificates._release_server()
                return self.cleanup_complete

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        if not self.close():
            raise TlsError("tls_cleanup_failed")
        return False
