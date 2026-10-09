"""GCS OAuth state/driver tests. No socket, rclone, container or account runs."""
import base64
import copy
from datetime import datetime, timezone
from email.message import Message
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch, Mock

LAB = Path(__file__).resolve().parents[1] / "provider-lab"
ROOT = LAB / "gcs-oauth"
sys.path.insert(0, str(LAB))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


F = load("gcs_oauth_fixture_test", ROOT / "fixture_oauth.py")
P = load("gcs_oauth_probe_test", ROOT / "probe.py")
S = load("gcs_oauth_supervisor_test", ROOT / "run_container.py")
STATE = "AAAAAAAAAAAAAAAAAAAAAA"
ALTERNATE = "AQEBAQEBAQEBAQEBAQEBAQ"
FILES = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
         "nested/space name.txt": b"Nested synthetic payload.\n", "nested/bytes.bin": bytes(range(256)) * 8}


def state(mode="positive"):
    result = F.OAuthState(FILES, *[letter * 32 for letter in "abcdefg"],
                         mode=mode, alternate_state=ALTERNATE, alternate_code="h" * 32, alternate_secret="i" * 32)
    result.deadline = 10**12
    result.bind_state(STATE)
    return result


def request(value, method, target, body=b"", auth=None, extra=()):
    handler = object.__new__(F.OAuthHandler)
    handler.server = types.SimpleNamespace(state=value, server_address=("127.0.0.1", 12345))
    handler._counted = False
    handler.command, handler.path = method, target
    handler.raw_requestline = (method + " " + target + " HTTP/1.1\r\n").encode("ascii")
    handler.headers = Message()
    handler.headers["Host"] = "127.0.0.1:12345"
    if auth:
        handler.headers["Authorization"] = auth
    if method == "POST":
        handler.headers["Content-Type"] = "application/x-www-form-urlencoded"
        handler.headers["Content-Length"] = str(len(body))
    for key, val in extra:
        handler.headers[key] = val
    handler.rfile, handler.wfile = io.BytesIO(body), io.BytesIO()
    handler.response_headers, handler.status = [], None
    handler.send_response = lambda code: setattr(handler, "status", code)
    handler.send_header = lambda key, val: handler.response_headers.append((key, val))
    handler.end_headers = lambda: None
    handler.dispatch()
    return handler


def authorize(value):
    # Literal request oracle, independent of the service URL builder.
    return request(value, "GET", "/oauth/authorize?access_type=offline&client_id=" + "a" * 32 +
        "&redirect_uri=http%3A%2F%2F127.0.0.1%3A53682%2F&response_type=code&scope=" +
        "https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fdevstorage.read_write&state=" + STATE)


def exchange(value, *, refresh=False, basic=False):
    code = "h" * 32 if value.mode == "invalid_code" else "c" * 32
    secret = "i" * 32 if value.mode == "wrong_client_secret" else "b" * 32
    values = ("grant_type=refresh_token&refresh_token=" + "e" * 32 if refresh else
              "code=" + code + "&grant_type=authorization_code&redirect_uri=http%3A%2F%2F127.0.0.1%3A53682%2F")
    if not basic:
        values = "client_id=" + "a" * 32 + "&client_secret=" + secret + "&" + values
    auth = "Basic " + base64.b64encode(("a" * 32 + ":" + secret).encode()).decode() if basic else None
    return request(value, "POST", "/oauth/token", values.encode(), auth)


def granted(mode="positive"):
    value = state(mode)
    authorize(value)
    exchange(value, basic=True)
    response = exchange(value)
    return value, response


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.socket_guard = patch("socket.socket", side_effect=AssertionError("network forbidden"))
        self.socket_guard.start()
        self.addCleanup(self.socket_guard.stop)

    def test_fresh_code_grant_and_exact_read(self):
        value, grant = granted()
        self.assertEqual(grant.status, 200)
        self.assertEqual(json.loads(grant.wfile.getvalue()), {
            "access_token": "d" * 32, "refresh_token": "e" * 32, "token_type": "Bearer", "expires_in": 300})
        metadata = request(value, "GET", "/storage/v1/b/synthetic-bucket/o/README-synthetic.txt?alt=json&prettyPrint=false",
                           auth="Bearer " + "d" * 32)
        self.assertEqual(json.loads(metadata.wfile.getvalue())["mediaLink"], "https://127.0.0.1:12345/media/README-synthetic.txt")
        content = request(value, "GET", "/media/README-synthetic.txt", auth="Bearer " + "d" * 32)
        self.assertEqual(content.wfile.getvalue(), FILES["README-synthetic.txt"])
        self.assertTrue(P.flow_matches(value, "positive"))

    def test_gcs_numeric_callback_is_exact_for_authorize_and_redirect(self):
        # Independent pinned GCS/original oauthutil.RedirectURL oracle. A hostname
        # alias is not interchangeable with the callback configured by the client.
        target = ("/oauth/authorize?access_type=offline&client_id=" + "a" * 32 +
                  "&redirect_uri=http%3A%2F%2F127.0.0.1%3A53682%2F&response_type=code&scope=" +
                  "https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fdevstorage.read_write&state=" + STATE)
        value = state()
        reply = request(value, "GET", target)
        self.assertEqual(reply.status, 302)
        self.assertEqual(dict(reply.response_headers)["Location"],
                         "http://127.0.0.1:53682/?code=" + "c" * 32 + "&state=" + STATE)
        for index, changed in enumerate((target.replace("127.0.0.1", "localhost"),
                        target.replace("127.0.0.1", "localhost.rclone.org"),
                        target.replace("127.0.0.1", "outside.invalid"),
                        target.replace("53682", "53683"),
                        target.replace("access_type=offline&", ""),
                        target + "&state=" + STATE, target + "&extra=1")):
            with self.subTest(target_index=index):
                value = state()
                reply = request(value, "GET", changed)
                self.assertEqual(reply.status, 400)
                self.assertEqual(value.events, [])
                self.assertEqual(value.token_requests, 0)
                self.assertTrue(value.failed)

    def test_code_exchange_refuses_callback_hostname_alias_in_both_auth_styles(self):
        for basic in (True, False):
            with self.subTest(basic=basic):
                value = state()
                self.assertEqual(authorize(value).status, 302)
                if not basic:
                    self.assertEqual(exchange(value, basic=True).status, 400)
                prior_events, prior_requests = list(value.events), value.token_requests
                body = ("code=" + "c" * 32 +
                        "&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A53682%2F")
                auth = "Basic " + base64.b64encode(("a" * 32 + ":" + "b" * 32).encode()).decode() if basic else None
                if not basic:
                    body = "client_id=" + "a" * 32 + "&client_secret=" + "b" * 32 + "&" + body
                reply = request(value, "POST", "/oauth/token", body.encode(), auth)
                self.assertEqual(reply.status, 400)
                self.assertTrue(value.failed)
                self.assertEqual(value.events, prior_events)
                self.assertEqual(value.token_requests, prior_requests)
                self.assertFalse(value.token_issued)

    def test_replacement_is_required_and_old_token_rejected(self):
        value, grant = granted("refresh")
        self.assertEqual(json.loads(grant.wfile.getvalue())["expires_in"], 1)
        exchange(value, refresh=True, basic=True)
        self.assertEqual(json.loads(exchange(value, refresh=True).wfile.getvalue())["access_token"], "f" * 32)
        response = request(value, "GET", "/storage/v1/b/synthetic-bucket/o/README-synthetic.txt?alt=json&prettyPrint=false",
                           auth="Bearer " + "d" * 32)
        self.assertEqual(response.status, 400)
        self.assertFalse(P.flow_matches(value, "refresh"))
        self.assertEqual(value.payload_bytes, 0)

    def test_refresh_replacement_read_and_rotation(self):
        value, _ = granted("refresh")
        exchange(value, refresh=True, basic=True)
        grant = json.loads(exchange(value, refresh=True).wfile.getvalue())
        self.assertEqual(grant["refresh_token"], "g" * 32)
        request(value, "GET", "/storage/v1/b/synthetic-bucket/o/README-synthetic.txt?alt=json&prettyPrint=false",
                auth="Bearer " + "f" * 32)
        request(value, "GET", "/media/README-synthetic.txt", auth="Bearer " + "f" * 32)
        self.assertTrue(P.flow_matches(value, "refresh"))
        self.assertEqual(value.requests, 7)
        value.requests += 1
        self.assertFalse(P.flow_matches(value, "refresh"))

    def test_refresh_denial_is_exact_and_has_no_payload(self):
        value, _ = granted("refresh_denied")
        exchange(value, refresh=True, basic=True)
        reply = exchange(value, refresh=True)
        self.assertEqual(reply.status, 400)
        self.assertEqual(json.loads(reply.wfile.getvalue())["error"], "invalid_grant")
        self.assertTrue(P.flow_matches(value, "refresh_denied"))
        self.assertEqual((value.payload_bytes, value.authenticated, value.refresh_issued), (0, 0, False))

    def test_bad_code_and_bad_secret_are_not_malformed_request_credit(self):
        for mode, error in (("invalid_code", "invalid_grant"), ("wrong_client_secret", "invalid_client")):
            with self.subTest(mode=mode):
                value, reply = granted(mode)
                self.assertEqual(json.loads(reply.wfile.getvalue())["error"], error)
                self.assertTrue(P.flow_matches(value, mode))
                self.assertFalse(value.token_issued)
        value = state("invalid_code")
        authorize(value)
        reply = request(value, "POST", "/oauth/token", b"grant_type=authorization_code")
        self.assertEqual(reply.status, 400)
        self.assertFalse(P.flow_matches(value, "invalid_code"))

    def test_callback_cases_keep_distinct_exact_parameters(self):
        for mode in ("wrong_state", "blank_state", "consent_denied"):
            with self.subTest(mode=mode):
                value = state(mode)
                reply = authorize(value)
                location = dict(reply.response_headers)["Location"]
                if mode == "wrong_state":
                    self.assertIn("state=" + ALTERNATE, location)
                elif mode == "blank_state":
                    self.assertTrue(location.endswith("state="))
                else:
                    self.assertIn("error=access_denied", location)
                    self.assertNotIn("code=", location)
                self.assertTrue(P.flow_matches(value, mode))
                self.assertEqual(exchange(value, basic=True).status, 400)
                self.assertFalse(value.token_issued)

    def test_held_refresh_release_and_no_token(self):
        value, _ = granted("refresh_cancel")
        exchange(value, refresh=True, basic=True)
        value.release_hold.set()
        reply = exchange(value, refresh=True)
        self.assertIsNone(reply.status)
        self.assertTrue(value.refresh_received.is_set())
        self.assertTrue(P.flow_matches(value, "refresh_cancel"))
        self.assertFalse(value.refresh_issued)
        self.assertEqual(reply.wfile.getvalue(), b"")

    def test_held_refresh_timeout_fails_verdict(self):
        value, _ = granted("refresh_cancel")
        exchange(value, refresh=True, basic=True)
        with patch.object(value.release_hold, "wait", return_value=False):
            exchange(value, refresh=True)
        self.assertFalse(P.flow_matches(value, "refresh_cancel"))

    def test_raw_alias_and_duplicate_headers_rejected(self):
        for target, extra in (("//oauth/authorize", ()), ("/oauth/authorize?x=#", ()),
                              ("/oauth/authorize", (("Host", "127.0.0.1:12345"),))):
            value = state()
            reply = request(value, "GET", target, extra=extra)
            self.assertEqual(reply.status, 400)
            self.assertEqual(value.payload_bytes, 0)
            self.assertTrue(value.failed)

    def test_no_storage_before_grant_or_unlisted_members(self):
        for target in ("/media/README-synthetic.txt", "/storage/v1/b/other/o/README-synthetic.txt?alt=json&prettyPrint=false"):
            value = state()
            reply = request(value, "GET", target, auth="Bearer " + "d" * 32)
            self.assertEqual(reply.status, 400)
            self.assertEqual(value.payload_bytes, 0)

    def test_changed_source_or_credential_fails(self):
        value = state()
        value.files["README-synthetic.txt"] += b"tamper"
        self.assertFalse(value.source_preserved())
        self.assertEqual(authorize(value).status, 400)
        value = state()
        value.replacement = "x" * 32
        self.assertFalse(value.source_preserved())

    def test_unknown_method_and_budget_are_fail_closed(self):
        value = state()
        self.assertEqual(request(value, "DELETE", "/media/README-synthetic.txt").status, 405)
        self.assertEqual(value.rejected_mutations, 1)
        value = state()
        value.requests = 7
        self.assertEqual(authorize(value).status, 400)
        self.assertTrue(value.budget_exceeded)


class DriverTests(unittest.TestCase):
    @staticmethod
    def cleanup_report():
        return {"observations": {"callback_requests": 0}, "cleanup": dict.fromkeys(P.CLEANUP, False),
                "errors": [], "checks": {"source_preserved": True}}

    def test_fixture_constructor_uncertainty_retains_private_root(self):
        report = self.cleanup_report()
        native = types.SimpleNamespace(records=[], close=lambda: True)
        with patch.object(P.sys, "platform", "linux"), patch.object(P, "listeners", return_value=([], [])), patch.object(P, "remove_owned") as remove:
            P.finish_report(report, native, None, None, Path("mock"), (1, 2), fixture_attempted=True)
        remove.assert_not_called()
        self.assertIn("fixture_cleanup_failed", report["errors"])
        self.assertFalse(report["success"])

    def test_transport_or_listener_uncertainty_prevents_temporary_removal(self):
        for transport_closed, listener_closed, transport_errors in ((False, True, []), (True, False, []), (True, True, ["worker_failed"])):
            report = self.cleanup_report()
            value = types.SimpleNamespace(requests=0, cleanup_complete=transport_closed, source_preserved=lambda: True)
            fixture = types.SimpleNamespace(cleanup_complete=transport_closed,
                snapshot=lambda: {"transport": {"failure_codes": transport_errors}})
            with self.subTest(transport=transport_closed, listener=listener_closed, errors=transport_errors), patch.object(P.sys, "platform", "linux"), patch.object(P, "listeners", return_value=([], []) if listener_closed else ([("owned", "socket")], [])), patch.object(P, "remove_owned") as remove:
                P.finish_report(report, None, fixture, value, Path("mock"), (1, 2), fixture_attempted=True)
            remove.assert_not_called()
            self.assertFalse(report["success"])

    def test_completed_fixture_and_children_allow_cleanup(self):
        report = self.cleanup_report()
        value = types.SimpleNamespace(requests=0, cleanup_complete=True, source_preserved=lambda: True)
        fixture = types.SimpleNamespace(cleanup_complete=True, snapshot=lambda: {"transport": {"failure_codes": []}})
        with patch.object(P.sys, "platform", "linux"), patch.object(P, "listeners", return_value=([], [])), patch.object(P, "remove_owned", return_value=True) as remove:
            P.finish_report(report, None, fixture, value, Path("mock"), (1, 2), fixture_attempted=True)
        remove.assert_called_once()
        self.assertTrue(report["success"])

    def test_fixture_retains_certificate_material_until_tls_workers_join(self):
        for failure in (False, OSError("synthetic transport failure")):
            fixture = object.__new__(F.OAuthFixture)
            fixture.state = state()
            fixture._closed = fixture.cleanup_complete = False
            fixture._transport, fixture._certificates = Mock(), Mock()
            if isinstance(failure, Exception):
                fixture._transport.close.side_effect = failure
                with self.assertRaises(OSError):
                    fixture.close()
            else:
                fixture._transport.close.return_value = failure
                self.assertFalse(fixture.close())
            fixture._certificates.close.assert_not_called()
            self.assertFalse(fixture.state.cleanup_complete)
        fixture._transport.close.side_effect = None
        fixture._transport.close.return_value = True
        fixture._certificates.close.return_value = True
        self.assertTrue(fixture.close())
        fixture._certificates.close.assert_called_once()

    def test_persisted_token_must_match_response_and_options(self):
        issued = 1704067200.0
        token = {"access_token": "first", "refresh_token": "refresh", "token_type": "Bearer",
                 "expires_in": 1, "expiry": "2024-01-01T00:00:01.123456789Z"}
        opts = {"type": "google cloud storage", "endpoint": "https://127.0.0.1:12345/storage/v1/"}
        with patch.object(P, "config_values", return_value={**opts, "token": json.dumps(token)}):
            self.assertGreater(P.saved_token(Path("mock"), opts, "first", "refresh", 1, issued), issued)
        for key, value in (("access_token", "stale"), ("refresh_token", "stale"), ("expires_in", True),
                           ("expiry", "2024-01-01T00:01:01Z")):
            changed = {**token, key: value}
            with self.subTest(key=key), patch.object(P, "config_values", return_value={**opts, "token": json.dumps(changed)}):
                with self.assertRaises(P.ProbeError):
                    P.saved_token(Path("mock"), opts, "first", "refresh", 1, issued)
        with patch.object(P, "config_values", return_value={**opts, "access_token": "bypass", "token": json.dumps(token)}):
            with self.assertRaises(P.ProbeError):
                P.saved_token(Path("mock"), opts, "first", "refresh", 1, issued)

    def test_expiry_wait_observes_actual_clock_not_early_window(self):
        native = types.SimpleNamespace(deadline=200)
        with patch.object(P.time, "monotonic", return_value=100), patch.object(P.time, "time", side_effect=[9, 10, 10.1]), patch.object(P.time, "sleep") as sleep:
            P.await_expiry(native, 10)
        self.assertEqual(sleep.call_count, 2)
        with patch.object(P.time, "monotonic", side_effect=[100, 106]), patch.object(P.time, "time", return_value=9):
            with self.assertRaisesRegex(P.ProbeError, "token_expiry_deadline"):
                P.await_expiry(native, 10)

    def test_denied_refresh_requires_typed_error_not_generic_exit(self):
        response = {"error": 'loopback: call failed: invalid_grant: maybe token expired? - reconnect',
                    "path": "operations/copyfile", "status": 500}
        P.refresh_denial_output(1, json.dumps(response).encode())
        for field, value in (("status", True), ("status", 400), ("path", "operations/list"),
                             ("error", "network failed"), ("input", {}), ("extra", "canary"),
                             ("error", "invalid_grant: maybe token expired?")):
            with self.subTest(field=field), self.assertRaises(P.ProbeError):
                P.refresh_denial_output(1, json.dumps({**response, field: value}).encode())
        for code in (0, True, None):
            with self.subTest(code=code), self.assertRaisesRegex(P.ProbeError, 'refresh_denial_exit'):
                P.refresh_denial_output(code, json.dumps(response).encode())

    def test_copy_request_requires_exact_launched_operation_and_all_four_inputs(self):
        destination = Path('/synthetic-owned/output')
        arguments = ('rc', '--loopback', 'operations/copyfile', 'srcFs=Synthetic:synthetic-bucket',
                     'srcRemote=README-synthetic.txt', 'dstFs=' + str(destination),
                     'dstRemote=README-synthetic.txt')
        P.copy_request_matches(arguments, destination)
        bad_values = [arguments[:-1], arguments + ('extra=canary',), list(arguments)]
        bad_values += [arguments[:i] + ('canary',) + arguments[i+1:] for i in range(len(arguments))]
        for value in bad_values:
            with self.subTest(value_type=type(value).__name__), self.assertRaisesRegex(P.ProbeError, '^copy_request_mismatch$'):
                P.copy_request_matches(value, destination)

    def test_cancellation_requires_exact_owned_live_process(self):
        process = Mock(pid=123)
        process.poll.return_value = None
        process.wait.return_value = -15
        native = Mock()
        record = {"process": process, "identity": (7, 10001, 123)}
        with patch.object(P, "proc_identity", return_value=(8, 10001, 123)), patch.object(P.os, "killpg", create=True) as kill:
            with self.assertRaises(P.ProbeError):
                P.cancel_owned(native, record)
            kill.assert_not_called()
        with patch.object(P, "proc_identity", return_value=record["identity"]), patch.object(P.os, "killpg", create=True) as kill:
            self.assertEqual(P.cancel_owned(native, record), -15)
            kill.assert_called_once_with(123, P.signal.SIGTERM)

    def test_suite_stops_at_first_failure_and_never_grants_ledger_credit(self):
        def report(*args):
            mode = args[-1]
            return {"runtime": {}, "success": mode == "positive"}
        with patch.object(P, "run_case", side_effect=report) as case:
            result = P.run(Path("mock"), Path("mock"))
        self.assertEqual(case.call_count, 2)
        self.assertFalse(result["success"])
        self.assertFalse(result["ledger_eligible"])
        self.assertEqual([row["name"] for row in result["cases"]], ["positive", "wrong_state"])

    def test_cleanup_failure_stays_failed_and_prevents_removal_with_live_child(self):
        report = {"observations": {"callback_requests": 0}, "cleanup": dict.fromkeys(P.CLEANUP, False),
                  "errors": [], "checks": {"source_preserved": True}}
        native = types.SimpleNamespace(records=[], close=lambda: False)
        with patch.object(P, "listeners", return_value=([], [])), patch.object(P, "remove_owned") as remove:
            P.finish_report(report, native, None, None, Path("mock"), (1, 2))
        remove.assert_not_called()
        self.assertFalse(report["success"])


class SupervisorTests(unittest.TestCase):
    @staticmethod
    def pending_docker():
        docker = object.__new__(S.Docker)
        child = Mock(pid=234)
        child.poll.return_value = None
        docker.pending = {"child": child, "identity": (7, 1000, 234)}
        docker.commands_stopped = False
        return docker, child

    def test_unreaped_docker_command_blocks_following_commands_and_mutations(self):
        docker, child = self.pending_docker()
        child.wait.side_effect = S.subprocess.TimeoutExpired("synthetic", 3)
        with patch.object(S, "command_identity", return_value=(7, 1000, 234)), patch.object(S.signal, "SIGKILL", 9, create=True), patch.object(S.os, "killpg", create=True) as kill:
            with self.assertRaisesRegex(S.SupervisorError, "docker_command_reap_unproved"):
                docker.stop_command()
        self.assertEqual(kill.call_count, 2)
        self.assertFalse(docker.commands_stopped)
        self.assertIs(docker.pending["child"], child)
        with patch.object(S.subprocess, "Popen") as start:
            with self.assertRaises(S.SupervisorError):
                docker.run(["info"])
            with self.assertRaises(S.SupervisorError):
                S.cleanup_owned(docker, "owned", "owned", None, "owned")
        start.assert_not_called()

    def test_changed_command_identity_is_never_signalled(self):
        docker, child = self.pending_docker()
        with patch.object(S, "command_identity", return_value=(8, 1000, 234)), patch.object(S.os, "killpg", create=True) as kill:
            with self.assertRaises(S.SupervisorError):
                docker.stop_command()
        kill.assert_not_called()
        child.wait.assert_not_called()
        self.assertFalse(docker.commands_stopped)

    def test_reaped_command_clears_pending_state(self):
        docker, child = self.pending_docker()
        child.poll.side_effect = [None, -15]
        child.wait.return_value = -15
        with patch.object(S, "command_identity", return_value=(7, 1000, 234)), patch.object(S.os, "killpg", create=True) as kill:
            docker.stop_command()
        kill.assert_called_once_with(234, S.signal.SIGTERM)
        self.assertTrue(docker.commands_stopped)
        self.assertIsNone(docker.pending)

    def test_run_retains_exact_child_when_timeout_cleanup_cannot_reap(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(S.shutil, "which", return_value="mock-docker"):
                docker = S.Docker(Path(directory))
            child = Mock(pid=234)
            child.poll.return_value = None
            child.wait.side_effect = S.subprocess.TimeoutExpired("synthetic", 3)
            with patch.object(S.subprocess, "Popen", return_value=child), patch.object(S, "command_identity", return_value=(7, 1000, 234)), patch.object(S.os, "getuid", return_value=1000, create=True), patch.object(S.os, "killpg", create=True), patch.object(S.signal, "SIGKILL", 9, create=True), patch.object(S.time, "monotonic", return_value=100):
                with self.assertRaisesRegex(S.SupervisorError, "docker_command_reap_unproved"):
                    docker.run(["info"], timeout=0)
            self.assertIs(docker.pending["child"], child)
            self.assertEqual(docker.pending["identity"], (7, 1000, 234))
            self.assertFalse(docker.commands_stopped)

    def test_exited_command_is_reaped_without_signalling_reused_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(S.shutil, "which", return_value="mock-docker"):
                docker = S.Docker(Path(directory))
            child = Mock(pid=234, returncode=0)
            child.poll.return_value = 0
            with patch.object(S.subprocess, "Popen", return_value=child), patch.object(S, "command_identity") as identity, patch.object(S.os, "killpg", create=True) as kill:
                self.assertEqual(docker.run(["info"]), (0, b""))
            identity.assert_not_called()
            kill.assert_not_called()
            self.assertIsNone(docker.pending)
            self.assertTrue(docker.commands_stopped)

    def test_supervisor_preserves_root_after_unreaped_command(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "triage-gcs-oauth-synthetic"
            root.mkdir()
            docker, _ = self.pending_docker()
            docker.build_phase = None
            docker.run = Mock(side_effect=S.SupervisorError("docker_command_reap_unproved"))
            lock = {"requirements": {"sha256": "a" * 64, "distributions": {}}, "python_version": "3.12.15",
                    "base_image": "synthetic", "base_config_digest": "b" * 64}
            with patch.dict(S.os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}), patch.object(S.sys, "platform", "linux"), patch.object(S, "runtime_identity", return_value={"version": "1.75.1", "sha256": "a" * 64}), patch.object(S, "source_hashes", return_value={}), patch.object(S, "read_lock", return_value=lock), patch.object(S.tempfile, "mkdtemp", return_value=str(root)), patch.object(S, "Docker", return_value=docker), patch.object(S, "cleanup_owned") as cleanup, patch.object(S, "cleanup_temporary") as remove:
                result = S.run(base / "synthetic-runtime", base / "report.json")
            cleanup.assert_not_called()
            remove.assert_not_called()
            self.assertFalse(result["success"])
            self.assertFalse(result["cleanup"]["commands_stopped"])
            self.assertFalse(result["cleanup"]["temporary_removed"])
            self.assertTrue(root.exists())
            self.assertFalse(json.loads((base / "report.json").read_text())["ledger_eligible"])

    def test_cleanup_command_reap_failure_replaces_earlier_stopped_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "triage-gcs-oauth-synthetic"
            root.mkdir()
            docker = types.SimpleNamespace(commands_stopped=True, pending=None, build_phase=None)
            docker.run = Mock(side_effect=[(0, b'{"OSType":"linux","Architecture":"amd64"}'),
                                           (0, b""), S.SupervisorError("synthetic_build_failure")])
            docker.inspect = Mock(return_value={"Id": "b" * 64, "Architecture": "amd64", "Os": "linux"})
            lock = {"requirements": {"sha256": "a" * 64, "distributions": {}}, "python_version": "3.12.15",
                    "base_image": "synthetic", "base_config_digest": "b" * 64}

            def failed_cleanup(*_args):
                docker.commands_stopped = False
                docker.pending = {"child": Mock(), "identity": (7, 1000, 234)}
                raise S.SupervisorError("docker_command_reap_unproved")

            with patch.dict(S.os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}), patch.object(S.sys, "platform", "linux"), patch.object(S, "runtime_identity", return_value={"version": "1.75.1", "sha256": "a" * 64}), patch.object(S, "source_hashes", return_value={}), patch.object(S, "read_lock", return_value=lock), patch.object(S.tempfile, "mkdtemp", return_value=str(root)), patch.object(S, "Docker", return_value=docker), patch.object(S, "stage_context"), patch.object(S, "cleanup_owned", side_effect=failed_cleanup) as cleanup, patch.object(S, "cleanup_temporary") as remove:
                result = S.run(base / "synthetic-runtime", base / "report.json")
            cleanup.assert_called_once()
            remove.assert_not_called()
            self.assertFalse(result["cleanup"]["commands_stopped"])
            self.assertFalse(result["cleanup"]["temporary_removed"])
            self.assertTrue(root.exists())

    def suite(self):
        stamp = "2026-10-09T00:00:00Z"
        identity = {"version": "1.75.1", "sha256": "a" * 64}
        sources = {S.PREFIX + "probe.py": "b" * 64}
        lock = {"python_version": "3.12.15", "requirements": {"distributions": {"cryptography": "50.0.2"}}}
        runtime = {"platform": "linux", "architecture": "amd64", "uid": 10001, "gid": 10001,
                   "python_version": "3.12.15", "cryptography_version": "50.0.2", "rclone_version": "1.75.1",
                   "rclone_sha256": "a" * 64, "probe_sha256": "b" * 64, "fixture_manifest_sha256": S.FIXTURE_SHA256}
        rows = [{"name": name, "report": {"schema_version": 1, "scope": "gcs_oauth_lifecycle_case",
                 "ledger_eligible": False, "started_utc": stamp, "finished_utc": stamp, "runtime": runtime.copy(),
                 "checks": dict.fromkeys(S.CASE_CHECKS[name], True), "observations": S.CASE_OBSERVATIONS[name].copy(),
                 "cleanup": dict.fromkeys(S.PROBE_CLEANUP, True), "success": True, "errors": []}} for name in S.AUTH_CASES]
        return {"schema_version": 1, "scope": "gcs_oauth_lifecycle_suite", "ledger_eligible": False,
                "started_utc": stamp, "finished_utc": stamp, "runtime": runtime, "cases": rows,
                "success": True, "errors": []}, identity, sources, lock, stamp

    def test_complete_closed_suite_validates_but_remains_experimental(self):
        suite, identity, sources, lock, stamp = self.suite()
        self.assertIs(S.validate_suite(suite, identity, sources, lock, stamp, stamp), suite)
        self.assertFalse(suite["ledger_eligible"])

    def test_missing_reordered_or_forged_lifecycle_cases_rejected(self):
        for mutation in ("omit", "reorder", "cleanup", "token_read", "eligibility", "extra"):
            suite, identity, sources, lock, stamp = self.suite()
            if mutation == "omit":
                suite["cases"].pop()
            elif mutation == "reorder":
                suite["cases"][0], suite["cases"][1] = suite["cases"][1], suite["cases"][0]
            elif mutation == "cleanup":
                suite["cases"][-1]["report"]["cleanup"]["children_stopped"] = False
            elif mutation == "token_read":
                suite["cases"][7]["report"]["checks"]["replacement_read"] = False
            elif mutation == "eligibility":
                suite["ledger_eligible"] = True
            else:
                suite["cases"][0]["report"]["token"] = "never permitted"
            with self.subTest(mutation=mutation), self.assertRaises(S.SupervisorError):
                S.validate_suite(suite, identity, sources, lock, stamp, stamp)

    def test_container_command_is_network_none_without_mounts_or_capabilities(self):
        args = S.create_args("triage-gcs-oauth-" + "a" * 32, "sha256:" + "b" * 64, "a" * 32)
        self.assertEqual(args[args.index("--network") + 1], "none")
        self.assertEqual(args[args.index("--user") + 1], "10001:10001")
        self.assertEqual(args[args.index("--cap-drop") + 1], "ALL")
        self.assertIn("--read-only", args)
        self.assertNotIn("--mount", args)
        self.assertNotIn("--publish", args)
        self.assertTrue(S.COMMAND[0].endswith("/gcs-oauth/probe.py"))

    def test_checked_recipe_and_source_closure_are_self_consistent(self):
        bindings = S.compute_bindings()
        self.assertEqual(set(bindings["source_sha256"]), set(S.SOURCE_FILES))
        self.assertNotIn("scripts/provider-lab/fixture_gcs.py", bindings["source_sha256"])
        self.assertEqual(bindings["fixture_manifest_sha256"], P.MANIFEST_SHA)


if __name__ == "__main__":
    unittest.main()
