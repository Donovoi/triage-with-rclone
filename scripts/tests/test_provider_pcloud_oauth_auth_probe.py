"""Offline authentication-driver checks; processes, TLS and HTTP are all fakes."""
from contextlib import contextmanager, ExitStack
import hashlib
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlencode


SOURCE = Path(__file__).resolve().parents[1] / "provider-lab/pcloud-oauth/probe.py"
probe = types.ModuleType("pcloud_oauth_auth_probe_under_test")
probe.__file__ = str(SOURCE)
exec(compile(SOURCE.read_bytes(), str(SOURCE), "exec"), probe.__dict__)
NAMES = ("positive", "wrong_state", "consent_denied", "invalid_code", "wrong_client_secret", "cancelled")
COMMON = {"environment", "version_binding", "initial_config_question", "callback_ownership",
          "no_token_persisted", "config_preserved", "no_read", "source_preserved", "request_sequence"}
STATE = "AAECAwQFBgcICQoLDA0ODw"
ALTERNATE = "EBESExQVFhcYGRobHB0eHw"
QUESTION = {"State": "*oauth-islocal,,,", "Option": {"Name": "config_is_local", "Default": True, "Type": "bool"},
            "Error": "", "Result": ""}


def denial(mode, expected=STATE, alternate=ALTERNATE):
    # Literal source-derived causes, independent of deny_native_output's branches.
    causes = {
        "wrong_state": ('Error: Auth state doesn\'t match\nCode: ""\nDescription: Expecting "'
                        + expected + '" got "' + alternate + '"\nHelp: '),
        "consent_denied": ('Error: Auth Error\nCode: ""\nDescription: No code returned by remote server: '
                           'access_denied: synthetic consent denied\nHelp: '),
        "invalid_code": 'failed to get token: oauth2: "invalid_grant" "synthetic authorization code rejected"',
        "wrong_client_secret": 'failed to get token: oauth2: "invalid_client" "synthetic client secret rejected"',
    }
    return ("2026/01/01 00:00:00 Failed to update remote: " + causes[mode] + "\n").encode("ascii")


def write_config(path, values):
    path.write_text("[Synthetic]\n" + "".join(key + " = " + value + "\n" for key, value in values.items()), encoding="utf-8")


class DenialOracleTests(unittest.TestCase):
    def test_exact_source_causes_qualify_for_their_own_mode_only(self):
        for mode in NAMES[1:-1]:
            with self.subTest(mode=mode):
                probe.deny_native_output(mode, 1, b"", denial(mode), STATE, ALTERNATE)
                for other in NAMES[1:-1]:
                    if mode == other:
                        continue
                    with self.assertRaisesRegex(probe.ProbeError, "native_denial_reason_mismatch"):
                        probe.deny_native_output(mode, 1, b"", denial(other), STATE, ALTERNATE)

    def test_nonzero_arbitrary_error_success_signal_or_stdout_does_not_qualify(self):
        for mode in NAMES[1:-1]:
            for code, output, error in ((0, b"", denial(mode)), (-15, b"", denial(mode)),
                                       (True, b"", denial(mode)), ("1", b"", denial(mode)),
                                       (1, b"{}", denial(mode)), (1, b"", b"permission denied"),
                                       (1, b"", b"connection refused"), (1, b"", b""),
                                       (1, b"", denial(mode).decode())):
                with self.subTest(mode=mode, kind=type(error).__name__, code=code), self.assertRaises(probe.ProbeError):
                    probe.deny_native_output(mode, code, output, error, STATE, ALTERNATE)

    def test_wrong_state_requires_both_exact_states_and_nonempty_expected_cause(self):
        for expected, alternate in ((ALTERNATE, STATE), (STATE, STATE), ("", ALTERNATE), (STATE, "")):
            with self.assertRaisesRegex(probe.ProbeError, "native_denial_reason_mismatch"):
                probe.deny_native_output("wrong_state", 1, b"", denial("wrong_state"), expected, alternate)
        for mode, changed in (("wrong_state", denial("wrong_state").replace(b'Code: ""', b'Code: "unexpected"')),
                              ("consent_denied", denial("consent_denied").replace(b"access_denied", b"server_error")),
                              ("invalid_code", denial("invalid_code").replace(b"invalid_grant", b"invalid_client")),
                              ("wrong_client_secret", denial("wrong_client_secret").replace(b"synthetic client secret rejected", b"unauthorized"))):
            with self.assertRaises(probe.ProbeError):
                probe.deny_native_output(mode, 1, b"", changed, STATE, ALTERNATE)

    def test_unknown_or_cancellation_mode_cannot_be_a_denial_marker(self):
        for mode in ("positive", "cancelled", "other", ""):
            with self.assertRaisesRegex(probe.ProbeError, "unknown_denial_mode"):
                probe.deny_native_output(mode, 1, b"", denial("invalid_code"), STATE, ALTERNATE)


class CancellationTests(unittest.TestCase):
    def record(self):
        process = Mock(pid=4321)
        process.poll.return_value = None
        return {"process": process, "identity": (123, 10001, 4321)}

    def test_owned_waiting_child_gets_one_group_term_and_bounded_reap(self):
        record, native = self.record(), Mock()
        native.finish.return_value = (-signal.SIGTERM, b"", b"private")
        with patch.object(probe, "proc_identity", return_value=(123, 10001, 4321)), \
                patch.object(probe.os, "killpg", create=True) as kill:
            probe.cancel_waiting(native, record)
        native.check.assert_called_once_with(record)
        kill.assert_called_once_with(4321, signal.SIGTERM)
        record["process"].wait.assert_called_once_with(3)
        native.finish.assert_called_once_with(record)

    def test_unowned_reused_group_wrong_uid_or_finished_child_is_never_signalled(self):
        for identity, finished in (((124, 10001, 4321), None), ((123, 0, 4321), None),
                                   ((123, 10001, 8), None), ((123, 10001, 4321), 0)):
            record, native = self.record(), Mock()
            record["process"].poll.return_value = finished
            with patch.object(probe, "proc_identity", return_value=identity), \
                    patch.object(probe.os, "killpg", create=True) as kill, \
                    self.assertRaisesRegex(probe.ProbeError, "cancellation_owner_mismatch"):
                probe.cancel_waiting(native, record)
            kill.assert_not_called()
            native.finish.assert_not_called()

    def test_expired_native_deadline_prevents_signal(self):
        record, native = self.record(), Mock()
        native.check.side_effect = probe.ProbeError("child_deadline")
        with patch.object(probe.os, "killpg", create=True) as kill, self.assertRaisesRegex(probe.ProbeError, "child_deadline"):
            probe.cancel_waiting(native, record)
        kill.assert_not_called()

    def test_nonterminating_process_hits_exact_three_second_deadline(self):
        record, native = self.record(), Mock()
        record["process"].wait.side_effect = subprocess.TimeoutExpired("synthetic", 3)
        with patch.object(probe, "proc_identity", return_value=record["identity"]), \
                patch.object(probe.os, "killpg", create=True), \
                self.assertRaisesRegex(probe.ProbeError, "cancellation_deadline"):
            probe.cancel_waiting(native, record)
        native.finish.assert_not_called()
        record["process"].wait.assert_called_once_with(3)

    def test_cancel_cannot_count_normal_exit_bool_code_or_stdout(self):
        for result in ((0, b"", b""), (True, b"", b""), (-15, b"unexpected", b"")):
            record, native = self.record(), Mock()
            native.finish.return_value = result
            with patch.object(probe, "proc_identity", return_value=record["identity"]), \
                    patch.object(probe.os, "killpg", create=True), \
                    self.assertRaisesRegex(probe.ProbeError, "cancellation_result_mismatch"):
                probe.cancel_waiting(native, record)


class FakeState:
    def __init__(self, files, client_id, client_secret, code, token, wrong_token, *, mode,
                 alternate_state, alternate_code, alternate_secret):
        self.files, self.client_id, self.client_secret = files, client_id, client_secret
        self.code, self.token, self.wrong_token = code, token, wrong_token
        self.mode, self.alternate_state, self.alternate_code, self.alternate_secret = mode, alternate_state, alternate_code, alternate_secret
        self.events, self.requests, self.payload_bytes, self.authenticated = [], 0, 0, 0
        self.authorize_requests = self.token_requests = self.token_denials = self.basic_denials = self.form_denials = 0
        self.token_issued = self.cleanup_complete = self.failed = False
        self.unexpected = self.auth_denied = self.member_denied = self.rejected_mutations = self.rejected_payload_bytes = 0
        self.budget_exceeded = False
        self.bound, self.phase, self.preserved = None, "unbound", True

    def bind_state(self, value):
        if self.mode == "cancelled" or self.bound is not None:
            raise AssertionError("state binding out of order")
        self.bound, self.phase = value, "ready"

    def source_preserved(self):
        return self.preserved


class FakeFixture:
    host, port = "127.0.0.1:12345", 12345

    def __init__(self, owner):
        self.owner, self.cleanup_complete = owner, False

    def rclone_ca_args(self):
        return ["--ca-cert", "synthetic-owned-ca"]

    def client_context(self):
        return self

    def snapshot(self):
        return {"transport": {"failure_codes": ["synthetic_failure"] if self.owner.failure == "transport" else []}}


class FakeNative:
    def __init__(self, owner, binary, root):
        self.owner, self.binary, self.root, self.records = owner, binary, root, []
        self.config = root / "synthetic.conf"
        self.config.write_bytes(b"")
        self.options = None

    def run(self, args, ca_args=()):
        self.records.append(list(args))
        if args == ["version"]:
            return 0, b"rclone v9.8.7\n", b""
        self.owner.assertEqual(args[:5], ["config", "create", "Synthetic", "pcloud", "--non-interactive"])
        self.owner.assertEqual(ca_args, ["--ca-cert", "synthetic-owned-ca"])
        self.options = {"type": "pcloud"}
        self.options.update(arg.split("=", 1) for arg in args[5:] if "=" in arg and not arg.startswith("config_"))
        state = self.owner.state
        expected_secret = state.alternate_secret if state.mode == "wrong_client_secret" else state.client_secret
        self.owner.assertEqual(self.options, {
            "type": "pcloud", "client_id": state.client_id, "client_secret": expected_secret,
            "client_credentials": "false", "root_folder_id": "d100", "hostname": "127.0.0.1:12345",
            "auth_url": "https://127.0.0.1:12345/oauth2/authorize", "token_url": "https://127.0.0.1:12345/oauth2_token"})
        write_config(self.config, self.options)
        self.initial_bytes = self.config.read_bytes()
        return 0, json.dumps(QUESTION).encode(), b""

    def start(self, args, ca_args=(), notice=False):
        self.owner.assertEqual(args, ["config", "update", "Synthetic", "--continue", "--state", "*oauth-islocal,,,",
                                     "--result", "true", "config_auth_no_browser=true"])
        self.owner.assertEqual(ca_args, ["--ca-cert", "synthetic-owned-ca"])
        self.owner.assertTrue(notice)
        self.records.append(list(args))
        process = Mock(pid=4321)
        process.poll.return_value = None
        return {"process": process, "identity": (123, self.owner.root.stat().st_uid, 4321)}

    def check(self, record):
        if self.owner.failure == "cancel_deadline":
            raise probe.ProbeError("child_deadline")

    def finish(self, record):
        state, failure = self.owner.state, self.owner.failure
        if failure == "saved_token": write_config(self.config, dict(self.options, token="unexpected"))
        if failure == "token_issued": state.token_issued = True
        if failure == "config_bytes": self.config.write_bytes(self.initial_bytes + b"# changed\n")
        if failure == "config_scope": write_config(self.config, dict(self.options, hostname="external.invalid"))
        if failure == "backup": (self.root / "synthetic.conf.bak").write_bytes(self.initial_bytes)
        if failure == "read_counter": state.authenticated = 1
        if failure == "payload_counter": state.payload_bytes = 1
        if failure == "output": (self.root / "output").mkdir()
        if failure == "source": state.preserved = False
        if failure == "failed": state.failed = True
        if failure == "unexpected": state.unexpected = 1
        if failure == "events": state.events.reverse()
        if failure == "basic_counter": state.basic_denials = 0
        if failure == "extra_child": self.records.append(["unexpected"])
        if state.mode == "cancelled":
            return -signal.SIGTERM, b"", b""
        code = 0 if failure == "exit_zero" else 1
        output = b"{}" if failure == "stdout" else b""
        error = b"connection refused" if failure == "untyped_error" else denial(state.mode, STATE, state.alternate_state)
        return code, output, error

    def close(self):
        self.owner.closed += 1
        if self.owner.failure == "close_raises":
            raise OSError("synthetic private failure")
        return self.owner.failure != "children"


class NegativeOrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="oauth-auth-probe-unit-")
        self.root = Path(self.temp.name).resolve()
        self.base, self.work = self.root / "image", self.root / "work"
        self.base.mkdir()
        self.work.mkdir()
        self.binary, self.manifest = self.base / "rclone", self.base / "rclone-version.env"
        self.binary.write_bytes(b"synthetic inert binary never executed")
        self.manifest.write_text("RCLONE_VERSION=9.8.7\nRCLONE_EXE_SHA256=" + "1" * 64
                                 + "\nRCLONE_WINDOWS_ZIP_SHA256=" + "2" * 64 + "\nRCLONE_LINUX_ZIP_SHA256=" + "3" * 64
                                 + "\nRCLONE_LINUX_EXE_SHA256=" + hashlib.sha256(self.binary.read_bytes()).hexdigest() + "\n")
        self.old_regular = probe.regular

    def tearDown(self):
        self.temp.cleanup()

    @contextmanager
    def service(self, root, state):
        self.state, self.fixture = state, FakeFixture(self)
        try:
            yield self.fixture
        finally:
            self.fixture.cleanup_complete = state.cleanup_complete = self.failure != "fixture_cleanup"
            if self.failure == "source_at_close": state.preserved = False

    def make_native(self, binary, root):
        self.native = FakeNative(self, binary, root)
        return self.native

    def request(self, port, path, host, context=None):
        self.requests += 1
        state = self.state
        self.assertNotEqual(state.mode, "cancelled", "cancelled must issue no HTTP")
        if self.requests == 1:
            self.assertIsNone(state.bound)
            self.assertEqual((port, path, host, context), (53682, "/auth?state=" + STATE, "127.0.0.1:53682", None))
            fields = {"access_type": "offline", "client_id": state.client_id, "redirect_uri": "http://localhost:53682/",
                      "response_type": "code", "state": STATE}
            authority = "external.invalid" if self.failure == "authority" else "127.0.0.1:12345"
            return 307, "https://" + authority + "/oauth2/authorize?" + urlencode(sorted(fields.items())), b"redirect"
        if self.requests == 2:
            self.assertEqual(state.bound, STATE)
            self.assertEqual((port, host, context), (12345, "127.0.0.1:12345", self.fixture))
            state.events, state.requests, state.authorize_requests, state.phase = [("authorize", "")], 1, 1, "authorized"
            fields = {"state": state.alternate_state if state.mode == "wrong_state" else STATE,
                      "locationid": "1", "hostname": "127.0.0.1:12345"}
            if state.mode == "consent_denied":
                fields.update(error="access_denied", error_description="synthetic consent denied")
            else:
                fields["code"] = state.alternate_code if state.mode == "invalid_code" else state.code
            if self.failure == "callback_fields": fields["extra"] = "unexpected"
            return 302, "http://localhost:53682/?" + urlencode(sorted(fields.items())), b"redirect"
        self.assertEqual(self.requests, 3)
        self.assertEqual((port, host, context), (53682, "localhost:53682", None))
        callback_denied = state.mode in ("wrong_state", "consent_denied")
        if not callback_denied:
            error = "invalid_grant" if state.mode == "invalid_code" else "invalid_client"
            state.events.extend([("token_denied_basic", error), ("token_denied_form", error)])
            state.requests = 3
            state.token_requests = state.token_denials = state.auth_denied = 2
            state.basic_denials = state.form_denials = 1
            state.phase = "denied"
        status = 400 if callback_denied else 200
        if self.failure == "callback_status": status = 200 if callback_denied else 400
        return status, None, b"" if self.failure == "callback_empty" else b"<html>synthetic callback</html>"

    def execute(self, mode, failure=None):
        self.failure, self.requests, self.closed = failure, 0, 0
        self.state = self.fixture = self.native = None
        old_path = list(sys.path)
        with ExitStack() as stack:
            for name, value in (("BASE", self.base), ("WORK", self.work), ("UID", self.root.stat().st_uid)):
                stack.enter_context(patch.object(probe, name, value))
            stack.enter_context(patch.object(probe, "environment_checks"))
            stack.enter_context(patch.object(probe, "Native", side_effect=self.make_native))
            stack.enter_context(patch.object(probe, "regular", side_effect=lambda path, private=False: self.old_regular(path)))
            stack.enter_context(patch.object(probe, "wait_callback", return_value=STATE))
            stack.enter_context(patch.object(probe, "request", side_effect=self.request))
            stack.enter_context(patch.object(probe, "proc_identity", return_value=(123, self.root.stat().st_uid, 4321)))
            self.kill = stack.enter_context(patch.object(probe.os, "killpg", create=True))
            stack.enter_context(patch.object(probe, "listeners", return_value=([("synthetic", "1")], []) if failure == "listeners" else ([], [])))
            stack.enter_context(patch.object(probe.sys, "platform", "linux"))
            stack.enter_context(patch.object(probe.platform, "machine", return_value="x86_64"))
            stack.enter_context(patch.object(probe.os, "getuid", return_value=10001, create=True))
            stack.enter_context(patch.object(probe.os, "getgid", return_value=10001, create=True))
            stack.enter_context(patch.dict(sys.modules, {"fixture_oauth": types.SimpleNamespace(OAuthState=FakeState, serve_oauth=self.service),
                                                        "cryptography": types.SimpleNamespace(__version__="50.0.2")}))
            stack.enter_context(patch("subprocess.Popen", side_effect=AssertionError("native forbidden")))
            stack.enter_context(patch("socket.socket", side_effect=AssertionError("listeners forbidden")))
            try:
                return probe.run_negative(self.binary, self.manifest, mode)
            finally:
                sys.path[:] = old_path

    def test_five_full_mock_flows_have_exact_observations_and_no_secret_report(self):
        for mode in NAMES[1:]:
            with self.subTest(mode=mode):
                report = self.execute(mode)
                self.assertTrue(report["success"], report["errors"])
                self.assertEqual(report["scope"], "pcloud_oauth_authentication_case")
                self.assertIs(report["ledger_eligible"], False)
                extras = {"owned_process_cancel"} if mode == "cancelled" else {"authorize", "callback_denial" if mode in NAMES[1:3] else "token_denial"}
                self.assertEqual(set(report["checks"]), COMMON | extras)
                self.assertTrue(all(report["checks"].values()))
                self.assertTrue(all(report["cleanup"].values()))
                https, callback = (0, 0) if mode == "cancelled" else (1, 2) if mode in NAMES[1:3] else (3, 2)
                self.assertEqual(report["observations"], {"native_commands": 3, "http_transactions": https + callback,
                                                         "https_requests": https, "callback_requests": callback})
                self.assertEqual(self.closed, 1)
                self.assertEqual(list(self.work.iterdir()), [])
                self.assertEqual(self.native.records[0], ["version"])
                public = json.dumps(report)
                for secret in (self.state.client_id, self.state.client_secret, self.state.code, self.state.token,
                               self.state.wrong_token, self.state.alternate_state, self.state.alternate_code,
                               self.state.alternate_secret, STATE):
                    self.assertNotIn(secret, public)
                if mode == "cancelled":
                    self.assertIsNone(self.state.bound)
                    self.assertEqual(self.requests, 0)
                    self.kill.assert_called_once_with(4321, signal.SIGTERM)
                else:
                    self.kill.assert_not_called()

    def test_wrong_secret_changes_only_configured_client_secret(self):
        self.assertTrue(self.execute("wrong_client_secret")["success"])
        self.assertEqual(self.native.options["client_secret"], self.state.alternate_secret)
        self.assertNotEqual(self.native.options["client_secret"], self.state.client_secret)
        self.assertEqual(self.state.token_denials, 2)

    def test_untyped_native_error_exit_zero_or_stdout_never_promote(self):
        for mode in NAMES[1:-1]:
            for failure in ("untyped_error", "exit_zero", "stdout"):
                with self.subTest(mode=mode, failure=failure):
                    report = self.execute(mode, failure)
                    self.assertFalse(report["success"])
                    self.assertFalse(report["checks"]["callback_denial" if mode in NAMES[1:3] else "token_denial"])
                    self.assertTrue(all(report["cleanup"].values()))

    def test_callback_response_and_owned_url_are_required_before_credit(self):
        for failure in ("authority", "callback_fields", "callback_status", "callback_empty"):
            with self.subTest(failure=failure):
                report = self.execute("wrong_state", failure)
                self.assertFalse(report["success"])
                self.assertFalse(report["checks"]["callback_denial"])
                self.assertEqual(self.state.token_requests, 0)
                self.assertTrue(all(report["cleanup"].values()))
                if failure == "authority": self.assertIsNone(self.state.bound)

    def test_saved_token_scope_bytes_backup_or_source_mutation_fails(self):
        for failure in ("saved_token", "token_issued", "config_bytes", "config_scope", "backup", "source"):
            with self.subTest(failure=failure):
                report = self.execute("invalid_code", failure)
                self.assertFalse(report["success"])
                self.assertTrue(report["errors"])
                self.assertTrue(report["cleanup"]["children_stopped"])
                self.assertTrue(report["cleanup"]["temporary_removed"])

    def test_any_read_artifact_payload_or_request_sequence_drift_fails(self):
        for failure in ("read_counter", "payload_counter", "output", "failed", "unexpected", "events", "basic_counter", "extra_child"):
            with self.subTest(failure=failure):
                report = self.execute("invalid_code", failure)
                self.assertFalse(report["success"])
                self.assertTrue(report["errors"])
                self.assertTrue(all(report["cleanup"].values()))

    def test_late_transport_source_or_listener_failures_are_sticky_and_cleanup_independent(self):
        for failure in ("transport", "fixture_cleanup", "source_at_close", "listeners"):
            with self.subTest(failure=failure):
                report = self.execute("wrong_state", failure)
                self.assertFalse(report["success"])
                self.assertTrue(report["checks"]["request_sequence"])
                self.assertTrue(report["cleanup"]["children_stopped"])
                self.assertTrue(report["cleanup"]["temporary_removed"])
                self.assertEqual(list(self.work.iterdir()), [])

    def test_child_cleanup_failure_preserves_owned_temp_and_cannot_pass(self):
        for failure in ("children", "close_raises"):
            with self.subTest(failure=failure):
                report = self.execute("consent_denied", failure)
                self.assertFalse(report["success"])
                self.assertFalse(report["cleanup"]["children_stopped"])
                self.assertFalse(report["cleanup"]["temporary_removed"])
                self.assertTrue(report["cleanup"]["listeners_closed"])
                self.assertTrue(list(self.work.iterdir()))

    def test_expired_cancellation_does_not_signal_or_issue_http(self):
        report = self.execute("cancelled", "cancel_deadline")
        self.assertFalse(report["success"])
        self.assertIn("child_deadline", report["errors"])
        self.assertEqual(self.requests, 0)
        self.kill.assert_not_called()
        self.assertTrue(all(report["cleanup"].values()))


class SuiteTests(unittest.TestCase):
    def report(self, passed=True):
        return {"runtime": {"platform": "linux", "rclone_version": "9.8.7"}, "success": passed,
                "cleanup": {"children_stopped": passed, "listeners_closed": True, "temporary_removed": passed},
                "errors": [] if passed else ["temporary_cleanup_failed"]}

    def test_all_six_cases_execute_once_in_fixed_order_and_remain_ineligible(self):
        calls = []
        def positive(binary, manifest):
            calls.append("positive")
            return self.report()
        def negative(binary, manifest, mode):
            calls.append(mode)
            return self.report()
        with patch.object(probe, "run", side_effect=positive), patch.object(probe, "run_negative", side_effect=negative):
            report = probe.run_authentication(Path("inert"), Path("manifest"))
        self.assertTrue(report["success"])
        self.assertEqual(calls, list(NAMES))
        self.assertEqual([case["name"] for case in report["cases"]], list(NAMES))
        self.assertEqual(set(report), {"schema_version", "scope", "ledger_eligible", "started_utc", "finished_utc",
                                      "runtime", "cases", "success", "errors"})
        self.assertEqual(report["scope"], "pcloud_oauth_authentication_suite")
        self.assertIs(report["ledger_eligible"], False)

    def test_every_failed_cleanup_position_stops_exact_prefix_without_invented_cases(self):
        for stop in range(6):
            calls = []
            def result(name):
                calls.append(name)
                return self.report(len(calls) - 1 != stop)
            with self.subTest(stop=stop), patch.object(probe, "run", side_effect=lambda *_: result("positive")), \
                    patch.object(probe, "run_negative", side_effect=lambda _b, _m, name: result(name)):
                report = probe.run_authentication(Path("inert"), Path("manifest"))
            self.assertFalse(report["success"])
            self.assertEqual(calls, list(NAMES[:stop + 1]))
            self.assertEqual([case["name"] for case in report["cases"]], calls)
            self.assertEqual(report["errors"], ["authentication_case_failed"])
            self.assertFalse(report["cases"][-1]["report"]["cleanup"]["children_stopped"])

    def test_cli_defaults_to_positive_and_authentication_is_explicit(self):
        for explicit in (False, True):
            argv = ["probe", "--rclone", "inert", "--manifest", "manifest"]
            if explicit: argv.append("--authentication-suite")
            with patch.object(probe.sys, "argv", argv), patch.object(probe.signal, "signal"), \
                    patch.object(probe, "run", return_value={"success": True}) as positive, \
                    patch.object(probe, "run_authentication", return_value={"success": True}) as suite, patch("builtins.print"):
                self.assertEqual(probe.main(), 0)
            self.assertEqual(positive.call_count, int(not explicit))
            self.assertEqual(suite.call_count, int(explicit))


if __name__ == "__main__":
    unittest.main()
