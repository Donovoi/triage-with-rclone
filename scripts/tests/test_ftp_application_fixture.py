"""Pure real-parser/dispatcher tests. Every native boundary is forbidden/faked.

These do not establish TCP FIN behavior, rclone retry, acquisition, or acceptance.
"""
import hashlib
import io
import json
from pathlib import Path
import socket
from types import ModuleType
import unittest
from unittest import mock

PATH = Path(__file__).resolve().parents[1] / "application-lab" / "fixture_ftp.py"
F = ModuleType("ftp_fixture_under_test")
F.__file__ = str(PATH)
with mock.patch("socket.socket", side_effect=AssertionError("socket_forbidden")), \
        mock.patch("subprocess.Popen", side_effect=AssertionError("process_forbidden")), \
        mock.patch("threading.Thread.start", side_effect=AssertionError("thread_forbidden")):
    exec(compile(PATH.read_bytes(), str(PATH), "exec"), F.__dict__)

USER, A, B = "private-user-canary", "private-A-canary", "private-B-canary"
LOGIN = b"USER private-user-canary\r\nPASS private-A-canary\r\n"
LARGE = bytes(range(256)) * 8192


class FakeSocket:
    def __init__(self, incoming=b"", *, close_error=False, fin_error=False, send_error=False):
        self.input = io.BytesIO(incoming)
        self.output = bytearray()
        self.close_error, self.fin_error, self.send_error = close_error, fin_error, send_error
        self.shutdowns, self.timeouts = [], []
        self.closed = False
        self.close_calls = 0

    def recv(self, size):
        return self.input.read(size)

    def sendall(self, data):
        if self.send_error:
            raise OSError("PRIVATE-send-error")
        self.output.extend(data)

    def settimeout(self, timeout):
        if not 0 < timeout <= 15:
            raise AssertionError("timeout_bound")
        self.timeouts.append(timeout)

    def shutdown(self, how):
        self.shutdowns.append(how)
        if self.fin_error and how == socket.SHUT_WR:
            raise OSError("PRIVATE-fin-error")

    def close(self):
        self.close_calls += 1
        if self.close_error:
            raise OSError("PRIVATE-close-error")
        self.closed = True


class FakeListener(FakeSocket):
    def __init__(self, data=None, peer=("127.0.0.1", 49100), *, bind_error=False, close_error=False):
        super().__init__(close_error=close_error)
        self.data = data or FakeSocket()
        self.peer = peer
        self.bound = self.backlog = None
        self.bind_error = bind_error

    def bind(self, address):
        self.bound = address
        if self.bind_error:
            raise OSError("PRIVATE-bind-error")

    def listen(self, backlog):
        self.backlog = backlog

    def getsockname(self):
        return ("127.0.0.1", 49200)

    def accept(self):
        return self.data, self.peer


class FakeThread:
    def __init__(self, *, alive=False, on_join=None):
        self.ident = 1
        self.alive, self.on_join = alive, on_join
        self.joins = []

    def is_alive(self):
        return self.alive

    def join(self, timeout):
        self.joins.append(timeout)
        if self.on_join:
            self.on_join()
            self.on_join = None
        self.alive = False


class FixtureTests(unittest.TestCase):
    def setUp(self):
        for target in ("socket.socket", "socket.create_connection", "subprocess.Popen",
                       "threading.Thread.start"):
            patch = mock.patch(target, side_effect=AssertionError("native_boundary_forbidden"))
            patch.start()
            self.addCleanup(patch.stop)
        clock = mock.patch.object(F.time, "monotonic", return_value=100.0)
        self.clock = clock.start()
        self.addCleanup(clock.stop)

    def server(self):
        state = F.AppFtpState(USER, A, password_b=B)
        server = F._Server(state)
        state._transport, state._transport_attempted = server, True
        return state, server

    def session(self, server, commands=b""):
        control = FakeSocket(commands)
        return server._admit(control, ("127.0.0.1", 49101)), control

    def run_session(self, server, commands, data=None, listener=None):
        session, control = self.session(server, commands)
        listener = listener or FakeListener(data)
        with mock.patch.object(F.socket, "socket", return_value=listener):
            server._worker(session)
        return session, control, listener.data, listener

    def reconnect(self, server):
        first = self.run_session(server, LOGIN + b"EPSV\r\nRETR large/cancel.bin\r\n")
        second = self.run_session(server, LOGIN + b"EPSV\r\nRETR large/cancel.bin\r\nQUIT\r\n")
        return first, second

    def test_fixed_corpus_and_literal_mlsd_inventory(self):
        state, server = self.server()
        expected = {
            "README-synthetic.txt": (30, "64d5b40a5f4773b14940a6ce1dd57cf87b44ce5940c097088732ffc71be280cf"),
            "large/cancel.bin": (2097152, "91d3beb88a9b2f778a6c44a1c53b63d3c79931845a9aef84b3fb414610bd1938"),
            "nested/binary.bin": (256, "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880"),
            "nested/spaced name.txt": (20, "0c6308d568f8ec30fbf044baac7827edac83a2465a60439ff653e277a5d9619e"),
        }
        self.assertEqual({k: (len(v), hashlib.sha256(v).hexdigest()) for k, v in state.files.items()}, expected)
        _, control, data, listener = self.run_session(server, LOGIN + b"EPSV\r\nMLSD /\r\nQUIT\r\n")
        self.assertEqual(data.output, b"type=file;size=30;modify=20250102030405; README-synthetic.txt\r\n"
                         b"type=dir;modify=20250102030405; large\r\n"
                         b"type=dir;modify=20250102030405; nested\r\n")
        self.assertEqual(listener.bound, ("127.0.0.1", 0))
        self.assertIn(b"226 Transfer complete\r\n", control.output)
        _, _, nested, _ = self.run_session(server, LOGIN + b"PASV\r\nMLSD nested\r\nQUIT\r\n")
        self.assertEqual(nested.output, b"type=file;size=256;modify=20250102030405; binary.bin\r\n"
                         b"type=file;size=20;modify=20250102030405; spaced name.txt\r\n")
        self.assertFalse(state.snapshot()["drop_attempted"])

    def test_pinned_login_negotiation_and_metadata(self):
        state, server = self.server()
        _, control, _, _ = self.run_session(server, LOGIN + b"FEAT\r\nTYPE I\r\nOPTS UTF8 ON\r\n"
                                           b"PWD\r\nMLST /nested/spaced name.txt\r\nNOOP\r\nQUIT\r\n")
        self.assertIn(b"211-Features\r\n MLST type*;size*;modify*;\r\n UTF8\r\n EPSV\r\n211 End\r\n", control.output)
        self.assertIn(b"250-Entry\r\n type=file;size=20;modify=20250102030405; nested/spaced name.txt\r\n250 End\r\n", control.output)
        self.assertNotIn(b"REST", control.output)
        self.assertNotIn(b"TLS", control.output)
        self.assertEqual(state.errors, [])

    def test_exact_one_fin_no_226_then_fresh_authenticated_zero_restart(self):
        state, server = self.server()
        first, second = self.reconnect(server)
        self.assertEqual(first[2].output, LARGE[:65536])
        self.assertEqual(first[2].shutdowns, [socket.SHUT_WR])
        self.assertEqual(first[1].shutdowns, [socket.SHUT_WR])
        self.assertNotIn(b"226", first[1].output)
        self.assertEqual(second[2].output, LARGE)
        self.assertEqual(hashlib.sha256(second[2].output).hexdigest(),
                         "91d3beb88a9b2f778a6c44a1c53b63d3c79931845a9aef84b3fb414610bd1938")
        events = state.snapshot()["events"]
        drop = [e for e in events if e["kind"] == "drop_fin"]
        restart = [e for e in events if e["kind"] == "restart_served"]
        self.assertEqual(len(drop), 1)
        self.assertEqual(len(restart), 1)
        self.assertNotEqual(drop[0]["session"], restart[0]["session"])
        self.assertNotEqual(drop[0]["transfer"], restart[0]["transfer"])
        self.assertGreater(next(e["ordinal"] for e in events if e["kind"] == "login_a"
                                and e["session"] == restart[0]["session"]), drop[0]["ordinal"])
        self.assertTrue(state.snapshot()["reauthenticated_restart_served"])
        self.assertFalse(state.snapshot()["same_invocation_verified"])
        self.assertFalse(state.snapshot()["acquired_hash_verified"])
        server.close()
        self.assertTrue(server.snapshot()["cleanup_complete"])
        self.assertTrue(all(r.raw.close_calls == 1 for r in server.resources))

    def test_preexisting_session_cannot_prove_new_connection_reauthentication(self):
        for authenticated in (False, True):
            with self.subTest(authenticated=authenticated):
                state, server = self.server()
                old, _ = self.session(server)
                if authenticated:
                    server._dispatch(old, "USER", USER.encode())
                    server._dispatch(old, "PASS", A.encode())
                self.run_session(server, LOGIN + b"EPSV\r\nRETR large/cancel.bin\r\n")
                if not authenticated:
                    server._dispatch(old, "USER", USER.encode())
                    server._dispatch(old, "PASS", A.encode())
                with mock.patch.object(F.socket, "socket", return_value=FakeListener()):
                    server._dispatch(old, "EPSV", b"")
                    server._dispatch(old, "RETR", b"large/cancel.bin")
                self.assertFalse(state.snapshot()["reauthenticated_restart_served"])
                server.close()

    def test_user_resets_auth_and_passive_and_wrong_pass_never_serves(self):
        state, server = self.server()
        listener = FakeListener()
        _, control, data, _ = self.run_session(server, LOGIN + b"EPSV\r\nUSER other\r\n"
                                              b"MLST README-synthetic.txt\r\nPASS wrong\r\n"
                                              b"RETR README-synthetic.txt\r\nQUIT\r\n", listener=listener)
        self.assertEqual(control.output.count(b"530"), 3)
        self.assertTrue(listener.closed)
        self.assertEqual(data.output, b"")
        self.assertFalse(any(e["kind"] == "metadata" for e in state.events))
        self.assertEqual(state.errors, [])

    def test_pass_without_user_and_repeated_pass_revoke_session_auth(self):
        _, server = self.server()
        _, control, _, _ = self.run_session(server, b"PASS private-A-canary\r\n" + LOGIN +
                                           b"PASS private-A-canary\r\nMLST README-synthetic.txt\r\nQUIT\r\n")
        self.assertEqual(control.output.count(b"230"), 1)
        self.assertEqual(control.output.count(b"530"), 3)

    def test_epoch_revocation_replacement_preserves_deadline_counters_and_fault(self):
        state, server = self.server()
        self.reconnect(server)
        before = state.snapshot()
        deadline = server.deadline
        state.advance_epoch("revoked_a", invocation_succeeded=True, processes_reaped=True)
        _, denied, _, _ = self.run_session(server, LOGIN + b"MLST README-synthetic.txt\r\nQUIT\r\n")
        self.assertNotIn(b"230", denied.output)
        state.advance_epoch("replacement_b", invocation_succeeded=True, processes_reaped=True)
        login_b = b"USER private-user-canary\r\nPASS private-B-canary\r\n"
        _, accepted, data, _ = self.run_session(server, login_b + b"EPSV\r\nRETR large/cancel.bin\r\nQUIT\r\n")
        self.assertIn(b"230", accepted.output)
        self.assertEqual(data.output, LARGE)
        self.assertEqual(sum(e["kind"] == "drop_fin" for e in state.events), 1)
        self.assertGreater(state.snapshot()["commands"], before["commands"])
        self.assertEqual(server.deadline, deadline)
        self.assertEqual(state.epoch, 3)
        server.close()

    def test_epoch_without_reap_observation_or_with_live_resources_is_sticky(self):
        for kind in ("reap", "observation", "control", "worker", "uncertain"):
            with self.subTest(kind=kind):
                state, server = self.server()
                if kind != "observation":
                    self.reconnect(server)
                if kind == "control":
                    self.session(server)
                elif kind == "worker":
                    server.workers.append(FakeThread(alive=True))
                elif kind == "uncertain":
                    server.resources[0].uncertain = True
                with self.assertRaises(F.FixtureError):
                    state.advance_epoch("revoked_a", invocation_succeeded=True, processes_reaped=kind != "reap")
                errors = list(state.errors)
                self.assertEqual(state.epoch, 1)
                self.assertTrue(errors)
                with self.assertRaises(F.FixtureError):
                    state.advance_epoch("revoked_a", invocation_succeeded=True, processes_reaped=True)
                self.assertTrue(set(errors).issubset(state.errors))

    def test_revocation_evidence_requires_exact_username_and_password_pair(self):
        for prefix in (b"", b"USER other-private-canary\r\n"):
            state, server = self.server()
            self.reconnect(server)
            state.advance_epoch("revoked_a", invocation_succeeded=True, processes_reaped=True)
            self.run_session(server, prefix + b"PASS private-A-canary\r\nQUIT\r\n")
            self.assertFalse(any(e["epoch"] == 2 and e["kind"] == "denied_a" for e in state.events))
            self.assertTrue(any(e["epoch"] == 2 and e["kind"] == "denied_other" for e in state.events))
            with self.assertRaisesRegex(F.FixtureError, "epoch_unproved"):
                state.advance_epoch("replacement_b", invocation_succeeded=True, processes_reaped=True)
            self.assertEqual(state.epoch, 2)

    def test_unknown_mutation_tls_active_and_rest_commands_fail_closed(self):
        for command in (b"REST 65536", b"REST 0", b"PORT 127,0,0,1,1,1", b"EPRT |1|127.0.0.1|21|",
                        b"AUTH TLS", b"STOR README-synthetic.txt", b"DELE README-synthetic.txt", b"LIST"):
            with self.subTest(command=command):
                state, server = self.server()
                self.run_session(server, LOGIN + command + b"\r\n")
                self.assertIn("command_unsupported", state.errors)
                self.assertFalse(state.snapshot()["reauthenticated_restart_served"])

    def test_path_traversal_aliases_and_malformed_lines_rejected(self):
        for command in (b"MLST ../README-synthetic.txt\r\n", b"MLST //nested/binary.bin\r\n",
                        b"MLST nested/../README-synthetic.txt\r\n", b"MLST nested%2fbinary.bin\r\n",
                        b"NOOP\n", b"NOOP\x00\r\n", b"noop\r\n", b"MLST \xff\r\n",
                        b"X" * 513, b"NOOP\r"):
            with self.subTest(command=command[:32]):
                state, server = self.server()
                self.run_session(server, LOGIN + command)
                self.assertTrue(set(state.errors) & {"path_invalid", "line_invalid"})

    def test_missing_directory_as_file_and_unnegotiated_data_have_distinct_results(self):
        state, server = self.server()
        _, control, _, listener = self.run_session(server, LOGIN + b"EPSV\r\nRETR missing-synthetic.txt\r\n"
                                                   b"RETR nested\r\nQUIT\r\n")
        self.assertEqual(control.output.count(b"550"), 2)
        self.assertTrue(listener.closed)
        self.assertEqual(state.errors, [])
        self.run_session(server, LOGIN + b"RETR README-synthetic.txt\r\n")
        self.assertIn("passive_required", state.errors)

    def test_wrong_data_peer_and_duplicate_passive_fail_closed_and_close(self):
        for wrong_peer in (False, True):
            state, server = self.server()
            listener = FakeListener(peer=("192.0.2.1", 55)) if wrong_peer else FakeListener()
            command = b"RETR README-synthetic.txt" if wrong_peer else b"EPSV"
            self.run_session(server, LOGIN + b"EPSV\r\n" + command + b"\r\n", listener=listener)
            self.assertIn("peer_invalid" if wrong_peer else "passive_busy", state.errors)
            server.close()
            self.assertTrue(server.cleanup_complete)
            self.assertTrue(listener.closed)

    def test_admission_and_every_aggregate_budget_is_bounded(self):
        for field, limit, commands in (("_commands", 512, LOGIN), ("_transfers", 64, LOGIN + b"EPSV\r\nRETR README-synthetic.txt\r\n"),
                                       ("_wire_bytes", 33554432, LOGIN)):
            with self.subTest(field=field):
                state, server = self.server()
                setattr(state, field, limit)
                self.run_session(server, commands)
                self.assertIn("limit_exceeded", state.errors)
        state, server = self.server()
        state._sessions = 32
        with self.assertRaisesRegex(F.FixtureError, "limit_exceeded"):
            self.session(server)
        server.close()
        state, server = self.server()
        for _ in range(8):
            self.session(server)
        with self.assertRaisesRegex(F.FixtureError, "limit_exceeded"):
            self.session(server)
        server.close()
        state, server = self.server()
        state.events = [dict(ordinal=i) for i in range(2048)]
        with self.assertRaisesRegex(F.FixtureError, "limit_exceeded"):
            self.session(server)
        server.close()

    def test_deadline_expiry_is_not_reset_by_epoch_or_a_new_session(self):
        state, server = self.server()
        self.reconnect(server)
        original = server.deadline
        self.clock.return_value = original
        with self.assertRaisesRegex(F.FixtureError, "deadline"):
            state.advance_epoch("revoked_a", invocation_succeeded=True, processes_reaped=True)
        with self.assertRaisesRegex(F.FixtureError, "deadline"):
            self.session(server)
        self.assertEqual(server.deadline, original)
        self.assertEqual(state.epoch, 1)

    def test_failed_fin_or_prefix_send_never_proves_drop_or_restart(self):
        for error in ("fin", "send", "close"):
            with self.subTest(error=error):
                state, server = self.server()
                data = FakeSocket(fin_error=error == "fin", send_error=error == "send", close_error=error == "close")
                self.run_session(server, LOGIN + b"EPSV\r\nRETR large/cancel.bin\r\n", data=data)
                self.assertTrue(state.snapshot()["drop_attempted"])
                self.assertFalse(state.snapshot()["drop_confirmed"])
                self.run_session(server, LOGIN + b"EPSV\r\nRETR large/cancel.bin\r\nQUIT\r\n")
                self.assertFalse(state.snapshot()["reauthenticated_restart_served"])
                self.assertEqual(data.close_calls, 1)
                if error != "send":
                    with self.assertRaisesRegex(F.FixtureError, "cleanup_failed"):
                        server.close()
                    self.assertFalse(server.cleanup_complete)

    def test_uncertain_close_retains_each_socket_role_and_is_never_retried(self):
        for kind in ("control_listener", "control", "data_listener", "data"):
            with self.subTest(kind=kind):
                state, server = self.server()
                raw = FakeSocket(close_error=True)
                server._own(raw, kind)
                with self.assertRaisesRegex(F.FixtureError, "cleanup_failed"):
                    server.close()
                with self.assertRaisesRegex(F.FixtureError, "cleanup_failed"):
                    server.close()
                self.assertEqual(raw.close_calls, 1)
                self.assertEqual(server.snapshot()[kind], 1)
                self.assertIn("cleanup_failed", state.errors)

    def test_close_joins_late_worker_and_closes_late_resource_after_acceptor(self):
        _, server = self.server()
        late = FakeThread(alive=True)
        raw = FakeSocket()
        def finish_accept():
            server.workers.append(late)
            server._own(raw, "control")
        server.acceptor = FakeThread(alive=True, on_join=finish_accept)
        server.close()
        self.assertEqual(len(late.joins), 1)
        self.assertTrue(raw.closed)
        self.assertTrue(server.cleanup_complete)

    def test_close_checks_passive_accept_registered_during_worker_join(self):
        _, server = self.server()
        raw = FakeSocket(close_error=True)
        worker = FakeThread(alive=True, on_join=lambda: server._own(raw, "data", 1))
        server.workers.append(worker)
        with self.assertRaisesRegex(F.FixtureError, "cleanup_failed"):
            server.close()
        self.assertEqual(raw.close_calls, 1)
        self.assertFalse(server.cleanup_complete)
        self.assertEqual(server.snapshot()["data"], 1)

    def test_failed_close_records_state_only_after_releasing_resource_lock(self):
        state, server = self.server()
        resource = server._own(FakeSocket(close_error=True), "data", 1)
        original = state.fail
        def checked_fail(code):
            self.assertTrue(resource.lock.acquire(blocking=False))
            resource.lock.release()
            return original(code)
        with mock.patch.object(state, "fail", side_effect=checked_fail):
            self.assertFalse(resource.close())
        self.assertIn("cleanup_failed", state.errors)

    def test_bounded_actual_accept_and_registration_share_drop_boundary_lock(self):
        state, server = self.server()
        listener = FakeListener()
        server.listener = server._own(listener, "control_listener")
        accepted = []
        original_admit = server._admit
        def accept():
            self.assertTrue(state.lock._is_owned())
            return FakeSocket(), ("127.0.0.1", 49100)
        def admit(raw, peer):
            self.assertTrue(state.lock._is_owned())
            result = original_admit(raw, peer)
            accepted.append(result)
            return result
        def spawned(*_args):
            server.stopping.set()
            return FakeThread()
        with mock.patch.object(listener, "accept", side_effect=accept), \
                mock.patch.object(server, "_admit", side_effect=admit), \
                mock.patch.object(server, "_spawn", side_effect=spawned):
            server._accept()
        self.assertEqual(len(accepted), 1)
        server.close()
        self.assertTrue(server.cleanup_complete)

    def test_two_sessions_cannot_consume_each_others_passive_channel(self):
        state, server = self.server()
        a, _ = self.session(server)
        b, _ = self.session(server)
        for session in (a, b):
            server._dispatch(session, "USER", USER.encode())
            server._dispatch(session, "PASS", A.encode())
        listener = FakeListener()
        with mock.patch.object(F.socket, "socket", return_value=listener):
            server._dispatch(a, "EPSV", b"")
        with self.assertRaisesRegex(F.FixtureError, "passive_required"):
            server._dispatch(b, "RETR", b"README-synthetic.txt")
        self.assertIs(a.passive.raw, listener)
        self.assertEqual(listener.data.output, b"")
        server.close()
        self.assertTrue(server.cleanup_complete)

    def test_context_failed_bind_is_recorded_and_owned_before_failure(self):
        state = F.AppFtpState(USER, A, password_b=B)
        raw = FakeListener(bind_error=True)
        with mock.patch.object(F.socket, "socket", return_value=raw):
            with self.assertRaisesRegex(F.FixtureError, "io_failed"):
                with F.serve_ftp(state):
                    self.fail("yield_forbidden")
        self.assertTrue(state.snapshot()["transport_attempted"])
        self.assertTrue(state.snapshot()["transport"]["cleanup_complete"])
        self.assertEqual(raw.close_calls, 1)
        with self.assertRaisesRegex(F.FixtureError, "state_reused"):
            with F.serve_ftp(state):
                self.fail("yield_forbidden")

    def test_thread_start_failure_is_not_invented_cleanup(self):
        state = F.AppFtpState(USER, A, password_b=B)
        raw = FakeListener()
        with mock.patch.object(F.socket, "socket", return_value=raw):
            with self.assertRaisesRegex(F.FixtureError, "cleanup_failed"):
                with F.serve_ftp(state):
                    self.fail("yield_forbidden")
        self.assertIn("thread_start_failed", state.errors)
        self.assertIn("cleanup_failed", state.errors)
        self.assertFalse(state.snapshot()["transport"]["cleanup_complete"])
        self.assertEqual(raw.bound, ("127.0.0.1", 0))
        self.assertTrue(raw.closed)

    def test_context_preserves_producer_operation_exception_and_still_closes(self):
        state = F.AppFtpState(USER, A, password_b=B)
        primary = ValueError("PRIVATE-caller-failure")
        with mock.patch.object(F._Server, "start"):
            with self.assertRaises(ValueError) as raised:
                with F.serve_ftp(state):
                    raise primary
        self.assertIs(raised.exception, primary)
        self.assertEqual(state.errors, [])
        self.assertTrue(state.snapshot()["transport"]["cleanup_complete"])

    def test_snapshot_and_fixed_errors_do_not_disclose_private_canaries(self):
        state, server = self.server()
        self.run_session(server, LOGIN + b"EPSV\r\nRETR README-synthetic.txt\r\n", data=FakeSocket(send_error=True))
        state.fail("PRIVATE-unknown-error")
        encoded = json.dumps(state.snapshot())
        for canary in (USER, A, B, "PRIVATE", "127.0.0.1", "README", "synthetic application"):
            self.assertNotIn(canary, encoded)
        self.assertEqual(state.errors, ["io_failed"])
        self.assertFalse(state.snapshot()["can_complete_application"])

    def test_invalid_credential_types_and_control_bytes_refused(self):
        for user, a, b in ((None, A, B), (USER, True, B), (USER, A, A), (USER, "x\n", B),
                           (USER, "x " , B), (USER, "x" * 129, B), (USER, "", B)):
            with self.subTest(user=user, a=a):
                with self.assertRaisesRegex(F.FixtureError, "input_invalid"):
                    F.AppFtpState(user, a, password_b=b)

    def test_source_mutation_cannot_qualify_cleanup(self):
        state, server = self.server()
        state.files = dict(state.files)
        state.files["README-synthetic.txt"] = b"changed"
        with self.assertRaisesRegex(F.FixtureError, "cleanup_failed"):
            server.close()
        self.assertIn("source_changed", state.errors)
        self.assertFalse(state.snapshot()["source_preserved"])


if __name__ == "__main__":
    unittest.main()
