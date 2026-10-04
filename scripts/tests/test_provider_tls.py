"""Local synthetic TLS tests; never provider/native-rclone acceptance."""
from contextlib import redirect_stderr
from datetime import datetime, timezone
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler
import importlib.util
import io
import ipaddress
import os
from pathlib import Path
import socket
import ssl
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch


MODULE = Path(__file__).resolve().parents[1] / "provider-lab" / "fixture_tls.py"
spec = importlib.util.spec_from_file_location("tested_fixture_tls", MODULE)
tls = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = tls
spec.loader.exec_module(tls)


class FixedHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.state.append(self.path)
        if self.path != "/synthetic":
            self.send_error(404)
            return
        body = b"synthetic TLS sample\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


class TlsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tls-unit-")
        self.root = Path(self.temp.name).resolve()
        self.certificates, self.servers = [], []

    def tearDown(self):
        failures = []
        try:
            for server in reversed(self.servers):
                try:
                    if not server.close():
                        failures.append("server cleanup failed")
                    snapshot = server.snapshot()
                    if (snapshot["active_connections"], snapshot["active_workers"], snapshot["active_timers"]) != (0, 0, 0):
                        failures.append("server resources remained")
                except BaseException as exc:
                    failures.append("server cleanup raised " + type(exc).__name__)
            for certificates in reversed(self.certificates):
                try:
                    if not certificates._closed and not certificates.close():
                        failures.append("certificate cleanup failed")
                except BaseException as exc:
                    failures.append("certificate cleanup raised " + type(exc).__name__)
        finally:
            try:
                self.temp.cleanup()
            except BaseException as exc:
                failures.append("temporary root cleanup raised " + type(exc).__name__)
        self.assertEqual(failures, [])

    def material(self):
        result = tls.FixtureCertificates.create(self.root)
        self.certificates.append(result)
        return result

    def server(self, certificates=None, handler=FixedHandler, **limits):
        state = []
        server = tls.BoundedHttpsServer(certificates or self.material(), handler, state=state, limits=tls.TlsLimits(**limits))
        self.servers.append(server)
        server.start()
        return server, state

    def wait_for(self, predicate, seconds=2):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if predicate():
                return
            time.sleep(0.005)
        self.fail("bounded synthetic condition not observed")

    def request(self, server, certificates):
        connection = http.client.HTTPSConnection("127.0.0.1", server.port, timeout=2, context=certificates.client_context())
        try:
            connection.request("GET", "/synthetic")
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_material_is_fresh_and_private_key_is_not_retained(self):
        from cryptography import x509
        from cryptography.x509.oid import ExtendedKeyUsageOID
        first, second = self.material(), self.material()
        self.assertNotEqual(first.ca_sha256, second.ca_sha256)
        self.assertNotEqual(first.directory, second.directory)
        self.assertEqual({p.name for p in first.directory.iterdir()}, {"ca.pem", "leaf.pem"})
        ca = x509.load_pem_x509_certificate(first.ca_path.read_bytes())
        leaf = x509.load_pem_x509_certificate((first.directory / "leaf.pem").read_bytes())
        self.assertTrue(ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertEqual(ca.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length, 0)
        self.assertFalse(leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value),
                         [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])
        self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value), [ExtendedKeyUsageOID.SERVER_AUTH])
        self.assertNotEqual(ca.public_key().public_numbers(), leaf.public_key().public_numbers())
        now = datetime.now(timezone.utc)
        self.assertLess(leaf.not_valid_before_utc, now)
        self.assertGreater(leaf.not_valid_after_utc, now)
        self.assertLess((leaf.not_valid_after_utc - now).total_seconds(), 3601)
        for path in first.directory.iterdir():
            self.assertNotIn(b"PRIVATE KEY", path.read_bytes())
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(first.directory.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(first.ca_path.stat().st_mode), 0o600)

    def test_child_trust_args_and_explicit_client_trust(self):
        certificates = self.material()
        self.assertEqual(certificates.rclone_ca_args(), ["--ca-cert", str(certificates.ca_path)])
        self.assertEqual(certificates.ca_sha256, hashlib.sha256(certificates.ca_path.read_bytes()).hexdigest())
        keylog = self.root / "must-not-exist.log"
        with patch.dict(os.environ, {"SSLKEYLOGFILE": str(keylog), "SSL_CERT_FILE": str(self.root / "invalid.pem")}):
            context = certificates.client_context()
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertEqual(context.cert_store_stats()["x509_ca"], 1)
        self.assertFalse(keylog.exists())

    def test_dependency_pin_rejected_before_import_or_material_creation(self):
        with patch("importlib.metadata.version", return_value="46.0.5"), patch("builtins.__import__", wraps=__import__) as imports:
            with self.assertRaisesRegex(tls.TlsError, "dependency_version_mismatch"):
                tls.FixtureCertificates.create(self.root)
        self.assertFalse(any(call.args[0].startswith("cryptography") for call in imports.call_args_list))
        self.assertEqual(list(self.root.iterdir()), [])

    def test_loaded_dependency_must_also_match(self):
        import cryptography
        with patch.object(cryptography, "__version__", "0.0.0"):
            with self.assertRaisesRegex(tls.TlsError, "loaded_dependency_version_mismatch"):
                self.material()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_trusted_request_and_all_resources_close(self):
        certificates = self.material()
        server, state = self.server(certificates)
        self.assertEqual(self.request(server, certificates), (200, b"synthetic TLS sample\n"))
        self.wait_for(lambda: server.snapshot()["active_connections"] == 0)
        self.assertEqual(state, ["/synthetic"])
        self.assertEqual(server.snapshot()["failure_codes"], [])
        self.assertEqual(server._server.server_address[0], "127.0.0.1")
        self.assertTrue(server.close())
        self.assertTrue(certificates.close())
        self.assertFalse(certificates.directory.exists())
        self.assertEqual(server._server.socket.fileno(), -1)

    def test_wrong_ca_and_wrong_san_do_not_reach_handler(self):
        certificates, other = self.material(), self.material()
        server, state = self.server(certificates)
        for context, name in ((other.client_context(), "127.0.0.1"), (certificates.client_context(), "localhost")):
            with socket.create_connection(("127.0.0.1", server.port), timeout=1) as raw:
                with self.assertRaises(ssl.SSLCertVerificationError):
                    context.wrap_socket(raw, server_hostname=name)
        self.wait_for(lambda: server.snapshot()["handshake_failures"] == 2)
        self.assertEqual(state, [])

    def test_default_trust_does_not_include_fresh_ca(self):
        server, state = self.server()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_default_certs()
        with socket.create_connection(("127.0.0.1", server.port), timeout=1) as raw:
            with self.assertRaises(ssl.SSLCertVerificationError):
                context.wrap_socket(raw, server_hostname="127.0.0.1")
        self.wait_for(lambda: server.snapshot()["handshake_failures"] == 1)
        self.assertEqual(state, [])

    def test_plaintext_and_truncated_handshake_are_rejected(self):
        server, state = self.server()
        for body in (b"GET /synthetic HTTP/1.1\r\n\r\n", b"\x16\x03\x01\x00"):
            with socket.create_connection(("127.0.0.1", server.port), timeout=1) as raw:
                raw.sendall(body)
                raw.shutdown(socket.SHUT_WR)
        self.wait_for(lambda: server.snapshot()["handshake_failures"] == 2)
        self.assertEqual(state, [])

    def test_idle_handshake_does_not_block_a_trusted_connection(self):
        certificates = self.material()
        server, state = self.server(certificates, request_seconds=0.4)
        with socket.create_connection(("127.0.0.1", server.port), timeout=1):
            self.wait_for(lambda: server.snapshot()["active_connections"] == 1)
            self.assertEqual(self.request(server, certificates)[0], 200)
            self.wait_for(lambda: server.snapshot()["active_connections"] == 0)
        self.assertEqual(state, ["/synthetic"])
        self.assertIn("tls_handshake_failed", server.snapshot()["failure_codes"])

    def test_slow_handshake_has_absolute_deadline(self):
        server, state = self.server(request_seconds=0.15)
        began = time.monotonic()
        with socket.create_connection(("127.0.0.1", server.port), timeout=1) as raw:
            for byte in b"\x16\x03\x01\x00\x80\x01":
                try:
                    raw.sendall(bytes([byte]))
                except OSError:
                    break
                time.sleep(0.04)
            self.wait_for(lambda: server.snapshot()["active_connections"] == 0)
        self.assertLess(time.monotonic() - began, 0.9)
        self.assertEqual(state, [])
        self.assertTrue(server.snapshot()["failure_codes"])

    def test_http_headers_share_the_handshake_deadline(self):
        certificates = self.material()
        server, state = self.server(certificates, request_seconds=0.2)
        with socket.create_connection(("127.0.0.1", server.port), timeout=1) as raw:
            with certificates.client_context().wrap_socket(raw, server_hostname="127.0.0.1") as client:
                client.sendall(b"GET /synthetic HTTP/1.1\r\n")
                self.wait_for(lambda: server.snapshot()["request_timeouts"] == 1)
        self.wait_for(lambda: server.snapshot()["active_connections"] == 0)
        self.assertEqual(state, [])

    def test_dispatch_guard_rejects_successful_eof_parse_after_deadline(self):
        self._check_dispatch_guard(headers=b"Host: 127.0.0.1\r\n", deadline=10, now=10,
                                   failures={"tls_http_dispatch_rejected", "tls_request_deadline", "tls_incomplete_http_headers"})

    def test_dispatch_guard_rejects_complete_headers_after_deadline(self):
        self._check_dispatch_guard(headers=b"Host: 127.0.0.1\r\n\r\n", deadline=10, now=11,
                                   failures={"tls_http_dispatch_rejected", "tls_request_deadline"})

    def test_dispatch_guard_rejects_stopping_and_untracked_connections(self):
        for deadline, stopping in ((None, False), (20, True)):
            with self.subTest(deadline=deadline, stopping=stopping):
                self._check_dispatch_guard(headers=b"Host: 127.0.0.1\r\n\r\n", deadline=deadline, now=10,
                                           failures={"tls_http_dispatch_rejected"}, stopping=stopping)

    def test_eof_without_header_terminator_is_rejected_before_deadline(self):
        self._check_dispatch_guard(headers=b"Host: 127.0.0.1\r\n", deadline=20, now=10,
                                   failures={"tls_incomplete_http_headers"})

    def _check_dispatch_guard(self, *, headers, deadline, now, failures, stopping=False):
        # Exercise the real stdlib parser with deterministic EOF and clock.
        # It returns true for these incomplete headers; no socket scheduling
        # or platform-specific TLS EOF behavior is needed to reproduce that.
        state, parsed_results = [], []
        server = tls.BoundedHttpsServer(self.material(), FixedHandler, state=state)
        self.servers.append(server)
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server._sockets.add(connection)
        if deadline is not None:
            server._socket_deadlines[connection] = deadline
        server._stopping = stopping
        handler = object.__new__(server._server.RequestHandlerClass)
        handler.connection = handler.request = connection
        handler.server = server._server
        handler.client_address = ("127.0.0.1", 1)
        handler.rfile = io.BytesIO(b"GET /synthetic HTTP/1.1\r\n" + headers)
        handler.wfile = io.BytesIO()
        handler.close_connection = True
        original = BaseHTTPRequestHandler.parse_request
        def observe_parser(instance):
            result = original(instance)
            parsed_results.append(result)
            return result
        try:
            with patch.object(BaseHTTPRequestHandler, "parse_request", observe_parser), patch.object(tls.time, "monotonic", return_value=now):
                handler.handle_one_request()
                if deadline is not None and now >= deadline:
                    # The real timer and worker also report the same event.
                    server._mark_expired(connection)
                    server._mark_expired(connection)
            self.assertEqual(parsed_results, [True])
            self.assertEqual(state, [])
            self.assertTrue(handler.close_connection)
            self.assertEqual(set(server.snapshot()["failure_codes"]), failures)
            self.assertEqual(server.snapshot()["request_timeouts"], int(deadline is not None and now >= deadline))
        finally:
            handler.rfile.close()
            handler.wfile.close()
            server._release(connection)

    def test_active_limit_rejection_is_sticky(self):
        server, _ = self.server(active_limit=1)
        with socket.create_connection(("127.0.0.1", server.port), timeout=1):
            self.wait_for(lambda: server.snapshot()["active_connections"] == 1)
            with socket.create_connection(("127.0.0.1", server.port), timeout=1):
                self.wait_for(lambda: server.snapshot()["admission_denied"] == 1)
        self.assertTrue(server.close())
        self.assertIn("tls_admission_rejected", server.snapshot()["failure_codes"])

    def test_total_connection_limit_stops_listener(self):
        certificates = self.material()
        server, _ = self.server(certificates, connection_limit=1, active_limit=1)
        self.assertEqual(self.request(server, certificates)[0], 200)
        self.wait_for(lambda: server.snapshot()["active_connections"] == 0)
        with socket.create_connection(("127.0.0.1", server.port), timeout=1):
            self.wait_for(lambda: server.snapshot()["admission_denied"] == 1)
        self.wait_for(lambda: not server._thread.is_alive())
        self.assertEqual(server.snapshot()["accepted_connections"], 2)
        self.assertEqual(server._server.socket.fileno(), -1)

    def test_lifetime_stops_idle_listener(self):
        server, _ = self.server(lifetime_seconds=0.12)
        self.wait_for(lambda: not server._thread.is_alive())
        self.assertIn("tls_lifetime_deadline", server.snapshot()["failure_codes"])
        self.assertEqual(server._server.socket.fileno(), -1)

    def test_shutdown_mid_handshake_is_bounded(self):
        server, _ = self.server(request_seconds=3)
        with socket.create_connection(("127.0.0.1", server.port), timeout=1):
            self.wait_for(lambda: server.snapshot()["active_workers"] == 1)
            began = time.monotonic()
            self.assertTrue(server.close())
            self.assertLess(time.monotonic() - began, 1)
        self.assertEqual(server.snapshot()["active_timers"], 0)

    def test_timer_start_failure_releases_socket(self):
        server, state = self.server()
        with patch.object(threading.Timer, "start", side_effect=RuntimeError("synthetic timer failure")):
            with socket.create_connection(("127.0.0.1", server.port), timeout=1):
                self.wait_for(lambda: "tls_worker_setup_failed" in server.snapshot()["failure_codes"])
        self.wait_for(lambda: server.snapshot()["active_connections"] == 0)
        self.assertEqual(server.snapshot()["active_timers"], 0)
        self.assertEqual(state, [])

    def test_worker_start_failure_releases_socket_without_logging(self):
        server, state = self.server()
        real_start = threading.Thread.start
        def fail_worker(thread):
            if thread.name == "synthetic-tls-worker":
                raise RuntimeError("synthetic private diagnostic")
            return real_start(thread)
        output = io.StringIO()
        with redirect_stderr(output), patch.object(threading.Thread, "start", fail_worker):
            with socket.create_connection(("127.0.0.1", server.port), timeout=1):
                self.wait_for(lambda: "tls_worker_start_failed" in server.snapshot()["failure_codes"])
        self.assertEqual(server.snapshot()["active_connections"], 0)
        self.assertEqual(state, [])
        self.assertEqual(output.getvalue(), "")

    def test_listener_start_failure_is_sticky_and_cleanup_is_verified(self):
        certificates = self.material()
        server = tls.BoundedHttpsServer(certificates, FixedHandler, state=[])
        self.servers.append(server)
        with patch.object(server._thread, "start", side_effect=RuntimeError("synthetic")):
            with self.assertRaises(RuntimeError):
                server.start()
        self.assertTrue(server.cleanup_complete)
        self.assertIn("tls_listener_start_failed", server.snapshot()["failure_codes"])
        self.assertEqual(certificates._leases, 0)

    def test_changed_ca_before_enter_closes_listener_and_releases_lease(self):
        certificates = self.material()
        server = tls.BoundedHttpsServer(certificates, FixedHandler, state=[])
        self.servers.append(server)
        certificates.ca_path.write_bytes(b"synthetic replaced CA contents")
        with self.assertRaises(tls.TlsError):
            with server:
                self.fail("changed certificate accepted")
        self.assertTrue(server.cleanup_complete)
        self.assertEqual(server._server.socket.fileno(), -1)
        self.assertEqual(certificates._leases, 0)
        self.assertIn("tls_listener_start_failed", server.snapshot()["failure_codes"])

    def test_listener_thread_construction_failure_releases_lease(self):
        certificates = self.material()
        captured = []
        original = tls._HttpServer
        def capture(*args, **kwargs):
            server = original(*args, **kwargs)
            captured.append(server)
            return server
        with patch.object(tls, "_HttpServer", capture), patch.object(threading, "Thread", side_effect=RuntimeError("synthetic")):
            with self.assertRaises(RuntimeError):
                tls.BoundedHttpsServer(certificates, FixedHandler, state=[])
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0].socket.fileno(), -1)
        self.assertEqual(certificates._leases, 0)

    def test_handler_exception_is_sanitized_and_socket_is_closed(self):
        class BrokenHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                raise RuntimeError("never log synthetic secret content")
        certificates = self.material()
        server, _ = self.server(certificates, BrokenHandler)
        output = io.StringIO()
        with redirect_stderr(output):
            with self.assertRaises(http.client.RemoteDisconnected):
                self.request(server, certificates)
            self.wait_for(lambda: server.snapshot()["active_connections"] == 0)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("tls_http_handler_failed", server.snapshot()["failure_codes"])

    def test_invalid_limits_arguments_and_reuse_are_rejected(self):
        for fields in ({"connection_limit": True}, {"active_limit": 0}, {"active_limit": 9},
                       {"connection_limit": 1, "active_limit": 2}, {"request_seconds": float("nan")},
                       {"lifetime_seconds": float("inf")}, {"cleanup_seconds": False}, {"request_seconds": 11}):
            with self.subTest(fields=fields), self.assertRaises(tls.TlsError):
                tls.TlsLimits(**fields).validate()
        with self.assertRaises(tls.TlsError):
            tls.BoundedHttpsServer(object(), FixedHandler)
        certificates = self.material()
        server, _ = self.server(certificates)
        with self.assertRaises(tls.TlsError):
            server.start()
        self.assertTrue(server.close())
        with self.assertRaises(tls.TlsError):
            server.start()

    def test_material_cannot_close_while_server_owns_context(self):
        certificates = self.material()
        server, _ = self.server(certificates)
        self.assertFalse(certificates.close())
        self.assertTrue(certificates.ca_path.exists())
        self.assertTrue(server.close())
        self.assertTrue(certificates.close())
        with self.assertRaises(tls.TlsError):
            certificates.rclone_ca_args()

    def test_changed_ca_hash_is_rejected(self):
        certificates = self.material()
        original = certificates.ca_path.read_bytes()
        certificates.ca_path.write_bytes(original.replace(b"CERTIFICATE", b"CERTIFICATF", 1))
        for operation in (certificates.rclone_ca_args, certificates.client_context, certificates.server_context):
            with self.assertRaisesRegex(tls.TlsError, "hash_mismatch"):
                operation()

    def test_replaced_ca_even_with_identical_bytes_is_rejected(self):
        certificates = self.material()
        original = certificates.ca_path.read_bytes()
        held = certificates.directory / "original-ca.pem"
        certificates.ca_path.rename(held)
        certificates.ca_path.write_bytes(original)
        with self.assertRaisesRegex(tls.TlsError, "material_replaced"):
            certificates.rclone_ca_args()
        self.assertFalse(certificates.close())
        self.assertEqual(certificates.ca_path.read_bytes(), original)
        self.assertTrue(held.exists())

    def test_hardlink_ca_is_rejected(self):
        certificates = self.material()
        link = self.root / "extra-ca.pem"
        os.link(certificates.ca_path, link)
        try:
            with self.assertRaisesRegex(tls.TlsError, "regular_owned_file"):
                certificates.rclone_ca_args()
        finally:
            link.unlink()

    def test_every_ancestor_reparse_marker_is_rejected(self):
        certificates = self.material()
        original = Path.lstat
        marked = certificates.directory.parent
        def replaced_lstat(path):
            info = original(path)
            if path == marked:
                class ReparseInfo:
                    st_mode = info.st_mode
                    st_file_attributes = 0x400
                return ReparseInfo()
            return info
        with patch.object(Path, "lstat", replaced_lstat):
            for operation in (certificates.rclone_ca_args, certificates.client_context, certificates.server_context):
                with self.assertRaisesRegex(tls.TlsError, "reparse_refused"):
                    operation()

    def test_symlink_ancestor_is_rejected_without_reading_material(self):
        certificates = self.material()
        link = self.root / "linked"
        try:
            link.symlink_to(certificates.directory, target_is_directory=True)
        except OSError:
            # Windows can forbid real links; the independent reparse-bit test
            # still exercises every ancestor without requiring privileges.
            self.skipTest("OS does not grant synthetic symlink creation")
        try:
            with self.assertRaisesRegex(tls.TlsError, "reparse_refused"):
                tls._read_regular(link / "ca.pem")
        finally:
            link.unlink()

    def test_replaced_directory_never_deletes_foreign_contents(self):
        certificates = self.material()
        old = self.root / "held-original-material"
        certificates.directory.rename(old)
        certificates.directory.mkdir()
        foreign = certificates.directory / "ca.pem"
        foreign.write_bytes(b"synthetic foreign sentinel")
        with self.assertRaisesRegex(tls.TlsError, "directory_replaced"):
            certificates.rclone_ca_args()
        self.assertFalse(certificates.close())
        self.assertEqual(foreign.read_bytes(), b"synthetic foreign sentinel")
        self.assertEqual({p.name for p in old.iterdir()}, {"ca.pem", "leaf.pem"})

    def test_unexpected_file_causes_cleanup_failure_and_is_preserved(self):
        certificates = self.material()
        foreign = certificates.directory / "unexpected.txt"
        foreign.write_bytes(b"synthetic retained data")
        with self.assertRaisesRegex(tls.TlsError, "material_cleanup_failed"):
            with certificates:
                pass
        self.assertEqual(foreign.read_bytes(), b"synthetic retained data")
        self.assertFalse(certificates.ca_path.exists())
        self.assertFalse(certificates.cleanup_complete)

    def test_failed_certificate_load_cleans_all_partial_material(self):
        with patch.object(ssl.SSLContext, "load_cert_chain", side_effect=ssl.SSLError("synthetic")):
            with self.assertRaises(ssl.SSLError):
                self.material()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_failed_material_chmod_cleans_created_directory(self):
        with patch.object(Path, "chmod", side_effect=OSError("synthetic")):
            with self.assertRaises(OSError):
                self.material()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_context_body_exception_propagates_after_cleanup(self):
        certificates = self.material()
        server = tls.BoundedHttpsServer(certificates, FixedHandler, state=[])
        self.servers.append(server)
        with self.assertRaisesRegex(ValueError, "synthetic body"):
            with server:
                raise ValueError("synthetic body")
        self.assertTrue(server.cleanup_complete)

    def test_partial_material_write_failure_closes_descriptor_and_removes_files(self):
        with patch.object(os, "fsync", side_effect=OSError("synthetic write failure")):
            with self.assertRaises(OSError):
                self.material()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_cleanup_failure_propagates_then_can_be_reaped_without_clearing_failure(self):
        entered, release = threading.Event(), threading.Event()
        class ControlledHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                entered.set()
                release.wait(1)
        certificates = self.material()
        server, _ = self.server(certificates, ControlledHandler, cleanup_seconds=0.02)
        try:
            with socket.create_connection(("127.0.0.1", server.port), timeout=1) as raw:
                with certificates.client_context().wrap_socket(raw, server_hostname="127.0.0.1") as client:
                    client.sendall(b"GET /synthetic HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                    self.assertTrue(entered.wait(1))
                    with self.assertRaisesRegex(tls.TlsError, "tls_cleanup_failed"):
                        server.__exit__(None, None, None)
                    self.assertFalse(server.cleanup_complete)
                    self.assertFalse(certificates.close())
        finally:
            release.set()
        self.wait_for(lambda: server.snapshot()["active_workers"] == 0)
        self.assertTrue(server.close())
        self.assertEqual(certificates._leases, 0)
        self.assertIn("tls_cleanup_failed", server.snapshot()["failure_codes"])

    def test_never_started_listener_is_closed(self):
        certificates = self.material()
        server = tls.BoundedHttpsServer(certificates, FixedHandler, state=[])
        self.servers.append(server)
        self.assertTrue(server.close())
        self.assertEqual(certificates._leases, 0)


if __name__ == "__main__":
    unittest.main()
