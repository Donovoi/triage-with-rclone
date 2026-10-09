"""Pure authority/denial contracts; no sockets, TLS keys or native children."""
import copy
from email.message import Message
import hashlib
import io
from pathlib import Path
import socket
import ssl
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlencode, urlsplit

import test_provider_pcloud_oauth_probe as driver
import test_provider_pcloud_oauth_auth_probe as negative
import test_provider_pcloud_oauth_container as container
import test_provider_pcloud_authentication_container as authentication

LAB = Path(__file__).resolve().parents[1] / "provider-lab"
sys.path.insert(0, str(LAB))
sys.path.insert(0, str(LAB / "pcloud-oauth"))
import fixture_oauth as oauth
import fixture_tls as tls

P, S = driver.probe, container.S
NAME = "fixture.pcloud.com"


class AuthorityContracts(unittest.TestCase):
    def test_only_exact_reviewed_profile_is_accepted_before_any_material_creation(self):
        with patch.object(tls, "_crypto") as crypto:
            for name in (True, 443, "", "127.0.0.1", "fixture.pcloud.com:443", "Fixture.pcloud.com",
                         "fixture.pcloud.com.", "other.pcloud.com", "fixture.invalid", "*.pcloud.com"):
                with self.subTest(name=name), self.assertRaises(tls.TlsError):
                    tls.FixtureCertificates.create(Path("inert"), server_name=name)
            crypto.assert_not_called()
        self.assertIsNone(tls._server_name(None))
        self.assertEqual(tls._server_name(NAME), NAME)

    def test_sni_is_required_and_exact_with_no_rendered_value(self):
        self.assertIsNone(tls._pcloud_sni(None, NAME, None))
        for name in (None, "", "127.0.0.1", "Fixture.pcloud.com", NAME + ".", NAME + ":443", "private.invalid"):
            self.assertEqual(tls._pcloud_sni(None, name, None), ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)

    def test_server_profile_pairs_dns_with_443_and_default_with_ephemeral_ipv4(self):
        calls = []
        def init(server, address, _handler):
            calls.append((address, server.allow_reuse_address, server.allow_reuse_port))
            server.server_address = (address[0], address[1] or 23456)
        with patch.object(tls.HTTPServer, "__init__", init), patch.object(tls.sys, "platform", "linux"):
            for name, expected in ((None, "127.0.0.1:23456"), (NAME, NAME)):
                server = tls._HttpServer(SimpleNamespace(_server_name=name), object, None)
                self.assertEqual(server.authority, expected)
        self.assertEqual(calls, [(("127.0.0.1", 0), False, False), (("127.0.0.1", 443), True, False)])
        with patch.object(tls.HTTPServer, "__init__") as bind, patch.object(tls.sys, "platform", "win32"):
            with self.assertRaisesRegex(tls.TlsError, "tls_dns_profile_requires_linux"):
                tls._HttpServer(SimpleNamespace(_server_name=NAME), object, None)
            bind.assert_not_called()

    def test_failed_fixed_port_bind_releases_material_lease_without_fallback(self):
        cert = object.__new__(tls.FixtureCertificates)
        cert._server_name = NAME
        cert._acquire_server = Mock(return_value=object())
        cert._release_server = Mock()
        with patch.object(tls, "_HttpServer", side_effect=PermissionError("synthetic")) as server:
            with self.assertRaises(PermissionError):
                tls.BoundedHttpsServer(cert, tls.BaseHTTPRequestHandler)
        server.assert_called_once()
        cert._acquire_server.assert_called_once()
        cert._release_server.assert_called_once()
        cert._release_server.reset_mock()
        with patch.object(tls, "_HttpServer", side_effect=OSError(98, "synthetic occupied listener")) as server:
            with self.assertRaises(OSError):
                tls.BoundedHttpsServer(cert, tls.BaseHTTPRequestHandler)
        server.assert_called_once()
        cert._release_server.assert_called_once()

    def environment(self, hosts=b"127.0.0.1 localhost\n127.0.0.1 fixture.pcloud.com\n", start=b"0\n", answers=None):
        if answers is None:
            answers = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443))]
        def opened(path, mode):
            self.assertEqual(mode, "rb")
            self.assertIn(path.as_posix(), ("/etc/hosts", "/proc/sys/net/ipv4/ip_unprivileged_port_start"))
            return io.BytesIO(hosts if path.as_posix() == "/etc/hosts" else start)
        with patch.object(P.Path, "open", opened), patch.object(P.socket, "getaddrinfo", return_value=answers) as resolve:
            result = P.authority_environment()
            resolve.assert_called_once_with(NAME, 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
            return result

    def test_only_single_canonical_loopback_mapping_resolves(self):
        hosts = b"127.0.0.1 localhost\n127.0.0.1 fixture.pcloud.com\n"
        self.assertEqual(self.environment(hosts, b"443\n"), (hashlib.sha256(hosts).hexdigest(), b"443\n"))
        for body in (b"", hosts * 2, b"127.0.0.1 fixture.pcloud.com alias\n", b"::1 fixture.pcloud.com\n",
                     b"127.0.0.2 fixture.pcloud.com\n", b"127.0.0.1 Fixture.pcloud.com\n",
                     b"127.0.0.1 fixture.pcloud.com.\n", b"\xff", b"x" * 16385):
            with self.subTest(body=body[:40]), self.assertRaises(P.ProbeError):
                self.environment(body)

    def test_privileged_port_requirement_fails_without_mutation(self):
        for start in (b"444\n", b"1024\n", b"-1\n", b"00\n", b"443", b"1\n0\n", b"x" * 40):
            with self.subTest(start=start), self.assertRaises(P.ProbeError):
                self.environment(start=start)

    def test_resolver_unknown_or_nonloopback_answers_fail(self):
        good = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443))
        for answers in ([], [good] * 9,
                        [good, (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.1", 443))],
                        [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("::1", 443, 0, 0))],
                        [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 444))]):
            with self.subTest(answers=answers), self.assertRaises(P.ProbeError):
                self.environment(answers=answers)

    def test_https_driver_uses_dns_identity_and_never_disables_verification(self):
        connection = Mock()
        response = connection.getresponse.return_value
        response.status = 200
        response.getheaders.return_value = [("Content-Length", "2")]
        response.read.return_value = b"{}"
        context = SimpleNamespace(check_hostname=True, verify_mode=ssl.CERT_REQUIRED)
        with patch.object(P.http.client, "HTTPSConnection", return_value=connection) as connect:
            self.assertEqual(P.request(443, "/oauth2/authorize", NAME, context), (200, None, b"{}"))
            connect.assert_called_once_with(NAME, 443, timeout=3, context=context)
        connection.close.assert_called_once()
        for port, host, checked, required in ((444, NAME, True, 2), (443, NAME + ":443", True, 2),
                                             (443, "127.0.0.1", True, 2), (443, NAME, False, 2), (443, NAME, True, 0)):
            with patch.object(P.http.client, "HTTPSConnection") as connect, self.assertRaises(P.ProbeError):
                P.request(port, "/oauth2/authorize", host, SimpleNamespace(check_hostname=checked, verify_mode=required))
            connect.assert_not_called()

    def test_actual_listener_is_fixed_ipv4_owned_and_authority_binding_is_stable(self):
        fixture = SimpleNamespace(host=NAME, port=443, _certificates=SimpleNamespace(server_name=NAME),
            _transport=SimpleNamespace(authority=NAME,
                _server=SimpleNamespace(authority=NAME, server_address=('127.0.0.1', 443))))
        fd = Mock(); fd.is_symlink.return_value = True
        binding = ("fixed", b"0\n")
        with patch.object(P, "authority_environment", return_value=binding), \
                patch.object(P.Path, "iterdir", return_value=iter([fd])), \
                patch.object(P.os, "readlink", return_value="socket:[123]"), \
                patch.object(P, "listeners", return_value=([("0100007F:01BB", "123")], [])):
            P.fixture_authority(fixture, binding)
        for four, six, owner, current in (([], [], "socket:[123]", binding),
                 ([("00000000:01BB", "123")], [], "socket:[123]", binding),
                 ([("0100007F:01BB", "123")] * 2, [], "socket:[123]", binding),
                 ([("0100007F:01BB", "123"), ("0100007F:01BC", "124")], [], "socket:[123]", binding),
                 ([("0100007F:01BB", "123")], [("ipv6", "124")], "socket:[123]", binding),
                 ([("0100007F:01BB", "123")], [], "socket:[999]", binding),
                 ([("0100007F:01BB", "123")], [], "socket:[123]", ("changed", b"0\n"))):
            with patch.object(P, "authority_environment", return_value=current), \
                    patch.object(P.Path, "iterdir", return_value=iter([fd])), \
                    patch.object(P.os, "readlink", return_value=owner), \
                    patch.object(P, "listeners", return_value=(four, six)), self.assertRaises(P.ProbeError):
                P.fixture_authority(fixture, binding)
        for host, port, cert in ((NAME + ":443", 443, NAME), (NAME, 8443, NAME), (NAME, 443, None)):
            with self.assertRaises(P.ProbeError):
                P.fixture_authority(SimpleNamespace(host=host, port=port,
                    _certificates=SimpleNamespace(server_name=cert)), binding)
        for target, field, value in ((fixture._transport, 'authority', '127.0.0.1:443'),
                (fixture._transport._server, 'authority', 'other.pcloud.com'),
                (fixture._transport._server, 'server_address', ('0.0.0.0', 443))):
            with patch.object(target, field, value), self.assertRaises(P.ProbeError):
                P.fixture_authority(fixture, binding)

    def test_http_authority_has_no_default_port_or_ip_alias(self):
        handler = object.__new__(oauth._OAuthHandler)
        handler.server = SimpleNamespace(state=SimpleNamespace(), authority=NAME)
        handler.command, handler.path = "GET", "/oauth2/authorize"
        handler.raw_requestline = b"GET /oauth2/authorize HTTP/1.1\r\n"
        for host in (NAME, NAME + ":443", "127.0.0.1", "127.0.0.1:443", NAME + ".", "Fixture.pcloud.com"):
            handler.headers = Message(); handler.headers["Host"] = host
            if host == NAME:
                self.assertEqual(handler._headers(), 0)
            else:
                with self.assertRaises(oauth.OAuthError):
                    handler._headers()
        handler.headers = Message(); handler.headers["Host"] = NAME; handler.headers["Host"] = NAME
        with self.assertRaises(oauth.OAuthError):
            handler._headers()

    def test_container_mapping_is_singleton_and_never_grants_cap_sysctl_or_network(self):
        for authentication_mode in (False, True):
            argv = S.create_args(container.NAME, container.IMAGE, container.RUN, authentication_mode)
            self.assertEqual(argv.count("--add-host"), 1)
            self.assertEqual(argv[argv.index("--add-host") + 1], NAME + ":127.0.0.1")
            for forbidden in ("--sysctl", "--cap-add", "--privileged", "--publish", "--dns"):
                self.assertNotIn(forbidden, argv)
        for values in (None, [], [NAME + ":127.0.0.1"] * 2, [NAME + ":host-gateway"],
                       [NAME + ":127.0.0.2"], [NAME + ":443:127.0.0.1"], [NAME + ":127.0.0.1", "extra:127.0.0.1"],
                       [NAME + ":0:0:0:0:0:0:0:1"], ["Fixture.pcloud.com:127.0.0.1"]):
            item = container.container(); item["HostConfig"]["ExtraHosts"] = values
            with self.assertRaises(S.SupervisorError):
                S.validate_container(item, container.IMAGE, container.RUN, container.ENV)
        for key, value in (("Sysctls", {"net.ipv4.ip_unprivileged_port_start": "0"}), ("Dns", ["127.0.0.1"]),
                           ("DnsSearch", ["pcloud.com"]), ("DnsOptions", ["ndots:0"])):
            item = container.container(); item["HostConfig"][key] = value
            with self.assertRaises(S.SupervisorError):
                S.validate_container(item, container.IMAGE, container.RUN, container.ENV)

    def test_old_six_case_or_missing_authority_receipts_never_qualify(self):
        for mutate in (lambda suite: suite.update(cases=[row for row in suite["cases"]
                              if row["name"] not in ("blank_state", "invalid_hostname")]),
                       lambda suite: suite["cases"][0]["report"]["checks"].pop("tls_authority_bound"),
                       lambda suite: suite["cases"][-1]["report"]["checks"].pop("authority_preserved")):
            item = authentication.evidence(); mutate(item["native_evidence"]["probe"])
            with self.assertRaises(S.SupervisorError):
                S.validate_authentication_evidence(item, dict(container.IDENTITY, platform="linux"),
                                                   authentication.BINDINGS, authentication.NOW)

    def test_blank_state_and_invalid_hostname_are_exact_unconsumed_callback_values(self):
        for mode, expected_state, expected_host in (("blank_state", "", NAME), ("invalid_hostname", negative.STATE, "fixture.invalid")):
            state = oauth.OAuthState(dict(P.FILES), *["synthetic-value-%02d" % n for n in range(5)], mode=mode,
                alternate_state=negative.ALTERNATE, alternate_code="synthetic-other-code", alternate_secret="synthetic-other-secret")
            state._started = True
            state.bind_state(negative.STATE)
            handler = object.__new__(oauth._OAuthHandler)
            handler.server = SimpleNamespace(state=state, authority=NAME)
            handler.command = "GET"
            handler.path = "/oauth2/authorize?" + urlencode(sorted({"access_type": "offline", "client_id": state.client_id,
                "redirect_uri": "http://localhost:53682/", "response_type": "code", "state": negative.STATE}.items()))
            handler.raw_requestline = ("GET " + handler.path + " HTTP/1.1\r\n").encode()
            handler.headers = Message(); handler.headers["Host"] = NAME
            handler.wfile = io.BytesIO()
            handler.send_response = Mock(); handler.send_header = Mock(); handler.end_headers = Mock()
            handler._authorize()
            location = next(call.args[1] for call in handler.send_header.call_args_list if call.args[0] == "Location")
            fields = parse_qs(urlsplit(location).query, keep_blank_values=True)
            self.assertEqual(fields, {"state": [expected_state], "hostname": [expected_host], "locationid": ["1"], "code": [state.code]})
            self.assertEqual(state.events, [("authorize", "")])
            self.assertEqual((state.token_requests, state.authenticated, state.payload_bytes), (0, 0, 0))
            self.assertFalse(state.token_issued)
            self.assertTrue(state.source_preserved())


class CleanupContracts(unittest.TestCase):
    def finish(self, mutation=None, *, child=True, absent=True, returned=True):
        snapshot = {'certificate_cleanup': True, 'transport': {'cleanup_complete': True,
            'active_connections': 0, 'active_workers': 0, 'active_timers': 0, 'failure_codes': []}}
        fixture = SimpleNamespace(cleanup_complete=True, snapshot=lambda: snapshot)
        state = SimpleNamespace(requests=0, cleanup_complete=True, source_preserved=lambda: True)
        native = SimpleNamespace(records=[], close=lambda: child)
        if mutation is not None:
            mutation(fixture, state, snapshot)
        report = P.new_report('pcloud_oauth_callback_feasibility', P.CHECKS)
        report['errors'].append('original_failure')
        with patch.object(P.sys, 'platform', 'linux'), patch.object(P, 'listeners', return_value=([], []) if absent else ([('owned', '1')], [])), \
                patch.object(P, 'remove_owned', return_value=True) as remove:
            P.finish_report(report, native, fixture if returned else None, state, Path('inert'), (1, 2), fixture_attempted=True)
        self.assertFalse(report['success'])
        self.assertIn('original_failure', report['errors'])
        return report, remove

    def test_confirmed_cleanup_preserves_original_failure_but_can_remove_root(self):
        report, remove = self.finish()
        remove.assert_called_once()
        self.assertTrue(all(report['cleanup'].values()))

    def test_every_unproved_owner_or_material_retains_root(self):
        mutations = [lambda f, s, snap: setattr(f, 'cleanup_complete', False),
                     lambda f, s, snap: setattr(s, 'cleanup_complete', False),
                     lambda f, s, snap: setattr(s, 'source_preserved', lambda: False),
                     lambda f, s, snap: snap.update(certificate_cleanup=False),
                     lambda f, s, snap: snap['transport'].update(cleanup_complete=False),
                     lambda f, s, snap: snap['transport'].update(failure_codes=['sticky_failure'])]
        for key in ('active_connections', 'active_workers', 'active_timers'):
            for value in (1, False, None):
                mutations.append(lambda f, s, snap, key=key, value=value: snap['transport'].update({key: value}))
        for mutation in mutations:
            report, remove = self.finish(mutation)
            remove.assert_not_called()
            self.assertFalse(report['cleanup']['temporary_removed'])
        for values in ({'child': False}, {'absent': False}, {'returned': False}):
            report, remove = self.finish(**values)
            remove.assert_not_called()
            self.assertFalse(report['cleanup']['temporary_removed'])


if __name__ == "__main__":
    unittest.main()
