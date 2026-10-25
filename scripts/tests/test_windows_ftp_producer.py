"""Fake boundaries only. These tests cannot qualify FTP or a native observer."""
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import types
import unittest
from unittest.mock import Mock, patch

PATH = Path(__file__).resolve().parents[1] / "application-lab/run_windows_ftp.py"
P = types.ModuleType("ftp_producer_test")
P.__file__ = str(PATH)
with patch.object(subprocess, "Popen", side_effect=AssertionError("process_forbidden")), patch.object(socket, "socket", side_effect=AssertionError("socket_forbidden")):
    exec(compile(PATH.read_bytes(), str(PATH), "exec"), P.__dict__)
RUNTIME = dict(version="1.75.2", sha256="1" * 64, platform="windows")


def proof(phase):
    return dict(phase=phase, runtime_ordinal=2, runtime_sha256=RUNTIME["sha256"], application_live=True,
                runtime_live=True, same_process=phase == "verify", reference_closed=phase == "verify")


def snapshot(name, action="finish", finished=True):
    n = P.E.EXPECTED_LAUNCHES[name]
    value = dict(schema_version=3, action=action, ok=True, state="finished" if finished else "running",
        app_exit_code=(1 if name == "revoked_a" else 0) if finished else None,
        runtime_image_observed=False, runtime_sha256=None, runtime_process_count=None, ctrl_c_sent=False,
        output_bytes=0, output_limit_exceeded=False, forced_termination=False, errors=[], observation_kind="launch_image",
        launch_image_observed=True, launch_sha256=RUNTIME["sha256"], runtime_launch_count=n, peak_runtime_processes=1,
        system_helper_image_observed=True, system_helper_sha256="2" * 64, system_helper_launch_count=n,
        peak_system_helper_processes=1, debug_event_count=100)
    value.update(dict.fromkeys((*P.H.SESSION_CLEANUP, *P.C.OBSERVED_CLEANUP), finished))
    return value


class FakeBridge:
    def __init__(self, case):
        self.name = case.name.removeprefix("ftp-").replace("-", "_")
        self.last = None
        self.commands = []
        self.close_calls = 0

    def command(self, action, **fields):
        self.commands.append((action, fields))
        if action == "ready":
            self.last = dict(schema_version=1, action="ready", ok=True, state="ready")
        elif action == "observe_continuity":
            self.last = dict(snapshot(self.name, action, False), continuity=proof(fields["phase"]))
        else:
            self.last = snapshot(self.name, action, action in {"poll", "finish"})
        return deepcopy(self.last)

    def close(self):
        self.close_calls += 1
        if self.last is None or self.last["state"] != "finished":
            self.last = snapshot(self.name)
        return True


class ProducerTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        for obj, name in ((subprocess, "Popen"), (socket, "socket"), (socket, "create_connection"), (threading.Thread, "start")):
            self.stack.enter_context(patch.object(obj, name, side_effect=AssertionError("native_forbidden")))

    def test_hosted_guard_precedes_any_binding_or_path_creation(self):
        with patch.object(P.H, "hosted_guard", side_effect=P.ProducerError("binding_failed")), \
             patch.object(P.E, "compute_bindings") as bindings:
            with self.assertRaises(P.ProducerError):
                P.run("not-read", "0" * 64, "1" * 40, "not-read")
            bindings.assert_not_called()

    def test_config_queue_and_names_are_fixed_no_proxy_or_retry_override(self):
        config = P.config_bytes(("127.0.0.1", 2121), "a" * 64, "b" * 107)
        self.assertEqual(config, ("[Synthetic]\ntype = ftp\nhost = 127.0.0.1\nport = 2121\nuser = " + "a" * 64 +
                         "\npass = " + "b" * 107 + "\ntls = false\nexplicit_tls = false\n").encode())
        self.assertIn(b'large/cancel.bin,2097152,2025-01-02T03:04:05+00:00,false,91d3beb8', P.queue_bytes())
        for endpoint in (("localhost", 2121), ("127.0.0.1", True), ("127.0.0.1", 0), ("127.0.0.1", 65536)):
            with self.assertRaises(P.ProducerError): P.config_bytes(endpoint, "a" * 64, "b" * 107)
        valid = ("ftp-accepted-a", "ftp-revoked-a", "ftp-replacement-b", "ftp-credentials", "ftp-credential-setup", "app-ftp-" + "a" * 32)
        for name in valid:
            self.assertIn(P.H.setup_scope(name), P.H.SETUP_SCOPES)
            for bad in (name + "\0", name.upper(), name + "/child", "../" + name, name + "\n"):
                with self.assertRaises(P.ProducerError): P.H.setup_scope(bad)

    def test_continuity_requires_two_live_proofs_before_each_release(self):
        bridge = FakeBridge(Path("ftp-accepted-a"))
        state = Mock()
        state.errors = []
        state.gate_snapshot.return_value = {g: dict(entered=dict(session=i+1, transfer=i+1, member=2), released=False) for i, g in enumerate(P.F.GATES)}
        proofs = P.continuity(bridge, state, None, P.time.monotonic() + 10, RUNTIME)
        self.assertEqual(proofs, {p: proof(p) for p in ("arm", "verify")})
        self.assertEqual([c.args[0] for c in state.release_gate.call_args_list], list(P.F.GATES))
        self.assertEqual([fields["phase"] for action, fields in bridge.commands], ["arm", "verify"])
        for damaged in (None, dict(proof("arm"), runtime_live=False), dict(proof("arm"), runtime_ordinal=1)):
            state.release_gate.reset_mock()
            bridge.command = Mock(return_value=dict(snapshot("accepted_a", "observe_continuity", False), continuity=damaged))
            with self.assertRaises((P.ProducerError, P.C.H.ProducerError, P.E.A.ApplicationEvidenceError)):
                P.continuity(bridge, state, None, P.time.monotonic() + 10, RUNTIME)
            state.release_gate.assert_not_called()

    def test_deadline_after_native_proof_never_releases_gate(self):
        state = Mock(errors=[])
        state.gate_snapshot.return_value = {g: dict(entered={}, released=False) for g in P.F.GATES}
        bridge = FakeBridge(Path("ftp-accepted-a"))
        with patch.object(P.time, "monotonic", side_effect=[0, 11]):
            with self.assertRaises(P.ProducerError): P.continuity(bridge, state, None, 10, RUNTIME)
        state.release_gate.assert_not_called()

    def test_transport_close_alone_and_uncertainty_cannot_authorize_cleanup(self):
        bridge = FakeBridge(Path("ftp-accepted-a")); bridge.last = snapshot("accepted_a")
        self.assertTrue(P.cleanup_proved(bridge, True, "accepted_a", RUNTIME))
        for field in (*P.H.SESSION_CLEANUP, *P.C.OBSERVED_CLEANUP):
            bridge.last = snapshot("accepted_a"); bridge.last[field] = False
            try: result = P.cleanup_proved(bridge, True, "accepted_a", RUNTIME)
            except (P.ProducerError, P.C.H.ProducerError): result = False
            self.assertFalse(result, field)
        for code in P.CLEANUP_UNCERTAIN:
            bridge.last = dict(snapshot("accepted_a"), ok=False, errors=[code])
            self.assertFalse(P.cleanup_proved(bridge, True, "accepted_a", RUNTIME))
        bridge.last = dict(snapshot("accepted_a"), ok=False, forced_termination=True, errors=["forced_termination"])
        self.assertTrue(P.cleanup_proved(bridge, True, "accepted_a", RUNTIME))
        for bad in (None, dict(schema_version=1, action="close_ready", state="closed", ok=True), dict(snapshot("accepted_a"), private="canary")):
            bridge.last = bad
            try: result = P.cleanup_proved(bridge, True, "accepted_a", RUNTIME)
            except (P.ProducerError, P.C.H.ProducerError): result = False
            self.assertFalse(result)

    def test_three_execute_paths_issue_one_start_no_ctrlc_no_relaunch(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = Path(directory)
            app = owner / "input.bin"; app.write_bytes(b"inert-no-execution")
            app_sha = hashlib.sha256(app.read_bytes()).hexdigest()
            for name in P.E.CASES:
                bridges = []
                def bridge(case):
                    result = FakeBridge(case); bridges.append(result); return result
                def prepare(parent, name): (parent / name).mkdir()
                def source(case): (case / "source").mkdir(); return P.H.identity(case / "source")
                extra = ("manifest_exact", "no_download_outputs") if name == "revoked_a" else ("manifest_exact", "outputs_exact", "output_hash_exact")
                with ExitStack() as mocks:
                    for obj, key, value in ((P.H, "prepare", prepare), (P.H, "create_private_roots", lambda case: {}),
                            (P.H, "private_directory", lambda case, child: (case / child).mkdir()),
                            (P.H, "private_write", lambda case, child, body: (case / child).write_bytes(body)),
                            (P.H, "environment", lambda case: {"SYNTHETIC": "1"}), (P, "create_source", source),
                            (P.C, "ObservedSourceBridge", bridge), (P.H, "application_roots_empty", lambda *args: None),
                            (P.H, "helper_baseline", lambda *args: {}), (P.H, "configuration_preserved", lambda case, cfg: case / "working.conf"),
                            (P, "manifest", lambda *args: dict.fromkeys(extra, True)), (P.W, "fingerprint", lambda case: "a" * 64),
                            (P, "continuity", lambda *args: {p: proof(p) for p in ("arm", "verify")})):
                        mocks.enter_context(patch.object(obj, key, value))
                    errors = []
                    item = P.execute(name, owner, app, app_sha, RUNTIME,
                        types.SimpleNamespace(deadline=P.time.monotonic()+120, endpoint=("127.0.0.1", 2121)), Mock(), b"synthetic", errors)
                self.assertEqual(errors, [])
                self.assertIsNone(item["record"]["failure_code"])
                self.assertTrue(item["record"]["checks"]["process_cleanup"])
                self.assertEqual(bridges[0].close_calls, 1)
                starts = [(a, f) for a, f in bridges[0].commands if a == "start_source_observed"]
                self.assertEqual(len(starts), 1)
                self.assertEqual(starts[0][1]["max_runtime_launches"], P.E.EXPECTED_LAUNCHES[name])
                self.assertEqual(starts[0][1]["environment"], {"SYNTHETIC": "1"})
                self.assertFalse(any(a in {"ctrl_c", "observe_runtime", "start"} for a, _ in bridges[0].commands))

    def test_actual_manifest_bytes_not_verified_label_earns_hash(self):
        f = P.E.fixture_manifest()
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory); base = case / "output" / P.H.CASE_NAME
            for name in ("config", "logs", "listings", "downloads/Synthetic/large"):
                (base / name).mkdir(parents=True, exist_ok=True)
            (base / "config/working.conf").write_bytes(b"synthetic")
            (base / "config/working.source.json").write_bytes(b"{}")
            destination = base / "downloads/Synthetic/large/cancel.bin"
            destination.write_bytes(bytes(range(256)) * 8192)
            request = dict(source="Synthetic:large/cancel.bin", destination=str(destination), mode="CopyTo",
                           expected_hash=f["sha256"], expected_hash_type="sha256", expected_size=f["size"])
            result = dict(local_sha256=f["sha256"], integrity="Verified", source=request["source"], destination=str(destination), success=True,
                          error=None, size=f["size"], hash=f["sha256"], hash_type="sha256", hash_verified=True, hash_error=None)
            value = dict(schema_version=1, written_at="2026-10-12T12:00:00Z", rclone_version="1.75.2", config_path=str(base / "config/working.conf"),
                         plan=dict(files=[dict(remote_name="Synthetic", path=f["member"], request=request)], skipped_directories=0), results=[result], complete=True)
            stem = "acquisition-20261012T120000"
            manifest = base / (stem + ".json")
            manifest.write_text(json.dumps(value))
            for path in (base / (stem + ".txt"), base / "logs" / (stem + ".log"), base / "logs" / (stem + ".checkpoint.json")):
                path.write_bytes(b"synthetic")
            self.assertTrue(P.manifest("accepted_a", case, base / "config/working.conf", RUNTIME, ("127.0.0.1", 2121))["output_hash_exact"])
            destination.write_bytes(b"x" * f["size"])
            with self.assertRaisesRegex(P.ProducerError, "outputs_invalid"):
                P.manifest("accepted_a", case, base / "config/working.conf", RUNTIME, ("127.0.0.1", 2121))
            destination.write_bytes(bytes(range(256)) * 8192)
            (base / "downloads/unexpected").write_bytes(b"canary")
            with self.assertRaisesRegex(P.ProducerError, "outputs_invalid"):
                P.manifest("accepted_a", case, base / "config/working.conf", RUNTIME, ("127.0.0.1", 2121))

    def test_fixture_events_require_fresh_accept_and_login_after_committed_drop(self):
        events = []
        def event(kind, session, transfer=0, count=0):
            events.append(dict(ordinal=len(events)+1, kind=kind, epoch=1, session=session,
                               transfer=transfer, member=2 if transfer else 0, bytes=count))
        event("session_open", 1); event("login_a", 1); event("transfer_start", 1, 1)
        event("gate_pre_drop", 1, 1); event("gate_released", 1, 1); event("drop_prefix_sent", 1, 1, 65536)
        event("drop_fin", 1, 1, 65536); event("session_open", 2); event("login_a", 2)
        event("transfer_start", 2, 2); event("gate_restart", 2, 2); event("gate_released", 2, 2)
        event("content_sent", 2, 2, 2097152); event("restart_served", 2, 2, 2097152)
        state = Mock(); snap = dict(errors=[], source_preserved=True, events=events)
        state.snapshot.return_value = snap
        self.assertTrue(P.fixture_checks("accepted_a", state)["fresh_login_after_drop"])
        for index, changes in ((7, dict(ordinal=1)), (8, dict(ordinal=2)), (10, dict(session=1)),
                               (12, dict(bytes=65536)), (5, dict(bytes=1))):
            altered = deepcopy(snap); altered["events"][index].update(changes); state.snapshot.return_value = altered
            with self.assertRaises(P.ProducerError): P.fixture_checks("accepted_a", state)
        state.snapshot.return_value = dict(errors=[], source_preserved=True, events=[
            dict(ordinal=1, kind="denied_other", epoch=2, session=1, transfer=0, member=0, bytes=0)])
        with self.assertRaises(P.ProducerError): P.fixture_checks("revoked_a", state)

    def test_epoch_group_stops_after_failure_and_never_deletes_with_uncertain_fixture(self):
        for fail_name, closed in ((None, True), ("accepted_a", True), ("revoked_a", True), (None, False)):
            server = Mock(deadline=P.time.monotonic()+180, endpoint=("127.0.0.1", 2121))
            server.quiescent.return_value = True
            state = Mock(files={"large/cancel.bin": bytes(range(256)) * 8192})
            state.unchanged.return_value = True
            context = Mock(); context.__enter__ = Mock(return_value=server); context.__exit__ = Mock()
            calls = []
            def execute(name, owner, application, app_sha, runtime, actual_server, actual_state, config, errors):
                calls.append(name)
                row = dict(status="failed", failure_code=None, checks=dict.fromkeys(P.E.CHECKS[name], True))
                row["checks"].update(group_finalized=False, fixture_cleanup=False, temp_cleanup=False)
                if name == fail_name: P.mark(row, "session_failed", errors)
                return dict(name=name, case=owner/name, record=row, lease=(1,2), config=config, artifact="a"*64, roots={}, baseline={})
            with ExitStack() as m:
                for obj, key, value in ((P.H, "prepare", Mock()), (P.H, "identity", lambda p: (1,2)),
                    (P.F, "AppFtpState", Mock(return_value=state)), (P.F, "serve_ftp", Mock(return_value=context)),
                    (P, "execute", execute), (P, "fixture_checks", lambda *a: {}), (P, "preserved", Mock()),
                    (P, "fixture_closed", lambda s: closed), (P.H, "application_roots_empty", Mock()),
                    (P.H, "helper_baseline", lambda *a: {}), (P.H, "helper_cleanup_preserved", Mock()),
                    (P.H, "inventory", lambda p: {})):
                    m.enter_context(patch.object(obj, key, value))
                remove = m.enter_context(patch.object(P.H, "remove_owned"))
                output = m.enter_context(patch("builtins.print"))
                errors = []
                items, group, actual_closed = P.exercise(Path("synthetic-suite"), Path("app"), "0"*64, RUNTIME,
                    ("a"*64, "b"*64, "c"*64, "d"*107, "e"*107), errors)
            expected = list(P.E.CASES) if fail_name is None else list(P.E.CASES[:P.E.CASES.index(fail_name)+1])
            self.assertEqual(calls, expected)
            output.assert_not_called()
            self.assertEqual(actual_closed, closed)
            self.assertEqual(group["status"], "passed" if fail_name is None and closed else "failed")
            self.assertEqual(state.advance_epoch.call_count, 2 if fail_name is None else P.E.CASES.index(fail_name))
            for call in state.advance_epoch.call_args_list:
                self.assertEqual(call.kwargs, dict(invocation_succeeded=True, processes_reaped=True))
            if fail_name is not None or not closed:
                self.assertTrue(all(item["record"]["status"] == "failed" for item in items))
            if not closed:
                remove.assert_not_called()


class DenialDiagnosticTests(unittest.TestCase):
    def setUp(self):
        ProducerTests.setUp(self)
        self.cause = 'NewFs: failed to make FTP connection to "127.0.0.1:2121": 530 Login incorrect'
        self.notice = "2026/10/12 10:55:00 NOTICE: Failed to rc: loopback: call failed: "
        self.value = "Cannot stat source: " + self.notice + self.cause + "\n"

    def projected(self, function, *args):
        with patch("builtins.print") as output:
            function(*args)
        output.assert_called_once()
        line = output.call_args.args[0]
        self.assertLessEqual(len(line.encode("ascii")) + 1, 1024)
        self.assertEqual(output.call_args.kwargs, {"flush": True})
        self.assertNotIn("PRIVATE_CANARY", line)
        self.assertNotIn("127.0.0.1", line)
        return json.loads(line.split("=", 1)[1])

    def test_error_projection_distinguishes_exact_cause_notices_and_shape(self):
        good = self.projected(P.denial_error_diagnostic, self.value, self.cause)
        self.assertEqual(good, dict(schema_version=1, case="revoked_a", stage="manifest_denial",
            error_is_string=True, error_within_bound=True, error_text_valid=True, cannot_stat_prefix=True,
            line_limit_ok=True, notice_count=1, final_notice_grammar=True, expected_cause_equal=True,
            expected_connection_prefix_equal=True, terminal_category="login_incorrect",
            terminal_reply_prefix=True, terminal_contains_reply=True, terminal_length_relation="equal",
            terminal_detail="login_incorrect", terminal_shape=None))
        for value, changed in (
            (self.value.replace(":2121", ":2122"), {"expected_cause_equal": False,
                                                   "expected_connection_prefix_equal": False, "terminal_category": None}),
            (self.value.replace("530 Login", "531 Login"), {"expected_cause_equal": False, "terminal_category": "other",
                "terminal_reply_prefix": False, "terminal_contains_reply": False,
                "terminal_length_relation": "equal", "terminal_detail": "other"}),
            ("Cannot stat source: " + self.notice + "PRIVATE_CANARY\n" + self.notice + self.cause,
             {"notice_count": 2}),
            (self.value.replace("2026/10/12", "PRIVATE_CANARY"),
             {"final_notice_grammar": False, "expected_cause_equal": None,
              "expected_connection_prefix_equal": None, "terminal_category": None}),
            ("Cannot stat source: PRIVATE_CANARY", {"notice_count": 0, "final_notice_grammar": False, "expected_cause_equal": None,
                                                   "expected_connection_prefix_equal": None, "terminal_category": None}),
            (self.notice + self.cause, {"cannot_stat_prefix": False, "notice_count": None,
                                      "line_limit_ok": None, "final_notice_grammar": None, "expected_cause_equal": None,
                                      "expected_connection_prefix_equal": None, "terminal_category": None}),
            ("Cannot stat source: " + "PRIVATE_CANARY\n" * 128 + self.notice + self.cause,
             {"line_limit_ok": False, "notice_count": None, "final_notice_grammar": None, "expected_cause_equal": None,
              "expected_connection_prefix_equal": None, "terminal_category": None}),
        ):
            with self.subTest(changed=changed):
                expected = dict(good, terminal_reply_prefix=None, terminal_contains_reply=None,
                                terminal_length_relation=None, terminal_detail=None)
                expected.update(changed)
                self.assertEqual(self.projected(P.denial_error_diagnostic, value, self.cause), expected)

    def test_error_type_bounds_and_private_objects_are_not_stringified(self):
        class Private:
            def __str__(self):
                raise AssertionError("PRIVATE_CANARY")
        for value in (None, False, 3, [], {"PRIVATE_CANARY": "secret"}, Private(), "", "x" * 65537,
                      self.value + "\x00PRIVATE_CANARY", self.value + "\rPRIVATE_CANARY"):
            with self.subTest(kind=type(value).__name__):
                record = self.projected(P.denial_error_diagnostic, value, self.cause)
                self.assertEqual(record["error_is_string"], type(value) is str)
                self.assertEqual(record["error_within_bound"], type(value) is str and 0 < len(value) <= 65536)
                self.assertFalse(record["error_text_valid"])
                self.assertIsNone(record["cannot_stat_prefix"])
                self.assertIsNone(record["notice_count"])
                self.assertIsNone(record["expected_cause_equal"])
                self.assertIsNone(record["expected_connection_prefix_equal"])
                self.assertIsNone(record["terminal_category"])

    def test_exact_prefix_and_whole_terminal_categories_do_not_relax_denial(self):
        for terminal, category in (("530 Login incorrect", "login_incorrect"), ("530 Login required", "login_required"),
                                   ("530 Login incorrect ", "other"), ("530 Login incorrect PRIVATE_CANARY", "other"),
                                   ("530 login incorrect", "other"), ("PRIVATE_CANARY", "other"),
                                   ("530 Login incorrect\t", "other")):
            value = self.value.replace("530 Login incorrect", terminal)
            record = self.projected(P.denial_error_diagnostic, value, self.cause)
            self.assertIs(record["expected_connection_prefix_equal"], True)
            self.assertEqual(record["terminal_category"], category)
            if terminal != "530 Login incorrect":
                self.assertFalse(P.W.exact_rc_error(value, self.cause, stat=True))
        for old, new in (("127.0.0.1", "127.0.0.2"), (":2121", ":2122"), ("NewFs", "newfs"),
                         ('"127.0.0.1:2121"', '"PRIVATE_CANARY"')):
            record = self.projected(P.denial_error_diagnostic, self.value.replace(old, new), self.cause)
            self.assertIs(record["expected_connection_prefix_equal"], False)
            self.assertIsNone(record["terminal_category"])
        for cause in (None, {}, "PRIVATE_CANARY", self.cause.replace(":2121", ":0"),
                      self.cause.replace(":2121", ":65536"), self.cause.replace(":2121", ":02121"),
                      self.cause + "\n", self.cause + "\x00"):
            record = self.projected(P.denial_error_diagnostic, self.value, cause)
            self.assertIsNone(record["expected_connection_prefix_equal"])
            self.assertIsNone(record["terminal_category"])

    def negative_manifest(self, case, error):
        f = P.E.fixture_manifest()
        base = case / "output" / P.H.CASE_NAME
        for name in ("config", "logs", "listings", "downloads"):
            (base / name).mkdir(parents=True, exist_ok=True)
        working = base / "config/working.conf"
        working.write_bytes(b"synthetic")
        (base / "config/working.source.json").write_bytes(b"{}")
        destination = base / "downloads/Synthetic/large/cancel.bin"
        request = dict(source="Synthetic:large/cancel.bin", destination=str(destination), mode="CopyTo",
                       expected_hash=f["sha256"], expected_hash_type="sha256", expected_size=f["size"])
        result = dict(local_sha256=None, integrity="Failed", source=request["source"], destination=str(destination),
                      success=False, error=error, size=None, hash=None, hash_type=None, hash_verified=None, hash_error=None)
        value = dict(schema_version=1, written_at="2026-10-12T10:55:00Z", rclone_version="1.75.2", config_path=str(working),
            plan=dict(files=[dict(remote_name="Synthetic", path=f["member"], request=request)], skipped_directories=0),
            results=[result], complete=False)
        stem = "acquisition-20261012T105500"
        (base / (stem + ".json")).write_text(json.dumps(value), encoding="utf-8")
        for path in (base / (stem + ".txt"), base / "logs" / (stem + ".log"), base / "logs" / (stem + ".checkpoint.json")):
            path.write_bytes(b"synthetic")
        return working

    def test_real_manifest_matcher_is_called_once_and_success_is_silent(self):
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            working = self.negative_manifest(case, self.value)
            with patch.object(P.W, "exact_rc_error", wraps=P.W.exact_rc_error) as matcher, patch("builtins.print") as output:
                self.assertEqual(P.manifest("revoked_a", case, working, RUNTIME, ("127.0.0.1", 2121)),
                                 {"manifest_exact": True, "no_download_outputs": True})
            matcher.assert_called_once_with(self.value, self.cause, stat=True)
            output.assert_not_called()
            for error in (self.value.replace(":2121", ":2122"), self.value.replace("530", "531"),
                          "Cannot stat source: " + self.notice + "PRIVATE_CANARY\n" + self.notice + self.cause,
                          self.value.replace("NOTICE", "PRIVATE_CANARY"), self.value + "\r", None):
                self.negative_manifest(case, error)
                with patch.object(P.W, "exact_rc_error", wraps=P.W.exact_rc_error) as matcher, patch("builtins.print") as output:
                    with self.assertRaisesRegex(P.ProducerError, "^denial_failed$"):
                        P.manifest("revoked_a", case, working, RUNTIME, ("127.0.0.1", 2121))
                matcher.assert_called_once_with(error, self.cause, stat=True)
                output.assert_called_once()
                self.assertNotIn("PRIVATE_CANARY", output.call_args.args[0])

    def test_formatter_or_printer_failure_preserves_original_exception(self):
        original = P.ProducerError("denial_failed")
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            working = self.negative_manifest(case, self.value)
            for target in ("printer", "formatter"):
                with ExitStack() as mocks:
                    mocks.enter_context(patch.object(P.W, "exact_rc_error", side_effect=original))
                    if target == "printer":
                        mocks.enter_context(patch("builtins.print", side_effect=OSError("PRIVATE_CANARY")))
                    else:
                        mocks.enter_context(patch.object(P.E, "compact", side_effect=RuntimeError("PRIVATE_CANARY")))
                    with self.assertRaises(P.ProducerError) as caught:
                        P.manifest("revoked_a", case, working, RUNTIME, ("127.0.0.1", 2121))
                    self.assertIs(caught.exception, original)

    def state(self):
        state = P.F.AppFtpState("PRIVATE_CANARY_USER", "PRIVATE_CANARY_A", password_b="PRIVATE_CANARY_B")
        for kind, session, transfer, count in (("session_open", 1, 0, 0), ("user", 1, 0, 0), ("login_a", 1, 0, 0),
                ("transfer_start", 1, 1, 0), ("gate_pre_drop", 1, 1, 0), ("gate_released", 1, 1, 0),
                ("drop_prefix_sent", 1, 1, 65536), ("drop_fin", 1, 1, 65536), ("session_open", 2, 0, 0),
                ("user", 2, 0, 0), ("login_a", 2, 0, 0), ("transfer_start", 2, 2, 0),
                ("gate_restart", 2, 2, 0), ("gate_released", 2, 2, 0), ("content_sent", 2, 2, 2097152),
                ("restart_served", 2, 2, 2097152)):
            state._event(kind, session, transfer, 2 if transfer else 0, count)
        state.epoch = 2
        state._event("epoch")
        state._event("session_open", 3)
        state._event("user", 3)
        state._event("denied_a", 3)
        return state

    def test_fixture_projection_has_only_epoch_two_counts_and_allowlisted_errors(self):
        state = self.state()
        state.errors = sorted(P.F.ERROR_CODES)
        with patch.object(state, "snapshot", side_effect=AssertionError("snapshot_forbidden")), \
             patch.object(state, "unchanged", side_effect=AssertionError("rehash_forbidden")):
            record = self.projected(P.denial_fixture_diagnostic, state, True)
        self.assertTrue(record["snapshot_available"])
        self.assertEqual(record["availability_reason"], "available")
        self.assertEqual(record["timing"], "after_fixture_teardown_attempt")
        self.assertIs(record["fixture_cleanup_complete"], True)
        self.assertEqual(record["epoch"], 2)
        self.assertEqual(record["errors"], sorted(P.F.ERROR_CODES))
        self.assertEqual(record["counts"], dict(session_open=1, user=1, login_a=0, login_b=0,
            denied_a=1, denied_b=0, denied_other=0, transfer_start=0, content_sent=0))

    def test_fixture_busy_or_malformed_state_has_no_invented_counters(self):
        unavailable = dict(schema_version=1, case="revoked_a", stage="manifest_denial", epoch=2,
                           timing="after_fixture_teardown_attempt", fixture_cleanup_complete=False,
                           snapshot_available=False, availability_reason=None, counts=None, errors=None,
                           denial_send_availability="snapshot_unavailable", denial_sendall_attempted=None,
                           denial_sendall_returned=None)
        for reason, mutate in (
                ("epoch_invalid", lambda s: setattr(s, "epoch", True)), ("epoch_invalid", lambda s: setattr(s, "epoch", 3)),
                ("events_shape", lambda s: setattr(s, "events", ())),
                ("events_shape", lambda s: setattr(s, "events", [{}] * (P.F.MAX_EVENTS + 1))),
                ("errors_shape", lambda s: setattr(s, "errors", ())),
                ("errors_shape", lambda s: setattr(s, "errors", ["PRIVATE_CANARY"])),
                ("errors_shape", lambda s: setattr(s, "errors", ["deadline", "deadline"])),
                ("errors_shape", lambda s: setattr(s, "errors", ["deadline"] * (len(P.F.ERROR_CODES) + 1))),
                ("event_invalid", lambda s: s.events[0].update(private="PRIVATE_CANARY")),
                ("event_invalid", lambda s: s.events[0].update(ordinal=True)),
                ("event_invalid", lambda s: s.events[0].update(epoch=True)),
                ("event_invalid", lambda s: s.events[0].update(bytes=-1)),
                ("event_invalid", lambda s: s.events[0].update(kind="PRIVATE_CANARY"))):
            state = self.state(); mutate(state)
            self.assertEqual(self.projected(P.denial_fixture_diagnostic, state, False), dict(unavailable, availability_reason=reason))
        self.assertEqual(self.projected(P.denial_fixture_diagnostic, None, False), dict(unavailable, availability_reason="state_type"))
        state = self.state(); state.lock = Mock()
        state.lock.acquire.return_value = False
        self.assertEqual(self.projected(P.denial_fixture_diagnostic, state, False), dict(unavailable, availability_reason="lock_busy"))
        state.lock.acquire.assert_called_once_with(blocking=False)
        state.lock.release.assert_not_called()

    def test_unavailable_reason_order_and_cleanup_boolean_are_closed(self):
        state = self.state(); state.epoch = 3; state.events = None; state.errors = None
        self.assertEqual(self.projected(P.denial_fixture_diagnostic, state, True)["availability_reason"], "epoch_invalid")
        state.epoch = 2
        self.assertEqual(self.projected(P.denial_fixture_diagnostic, state, True)["availability_reason"], "events_shape")
        state.events = [{}]
        self.assertEqual(self.projected(P.denial_fixture_diagnostic, state, True)["availability_reason"], "errors_shape")
        state.errors = []
        self.assertEqual(self.projected(P.denial_fixture_diagnostic, state, True)["availability_reason"], "event_invalid")
        for closed in (None, 0, 1, "PRIVATE_CANARY", [], {}):
            with patch("builtins.print") as output:
                P.denial_fixture_diagnostic(self.state(), closed)
            output.assert_not_called()

    def test_fixture_diagnostic_failures_release_lock_and_do_not_escape(self):
        state = self.state(); state.lock = Mock()
        state.lock.acquire.return_value = True
        with patch("builtins.print", side_effect=OSError("PRIVATE_CANARY")):
            P.denial_fixture_diagnostic(state, True)
        state.lock.release.assert_called_once_with()
        with patch.object(P.E, "compact", side_effect=RuntimeError("PRIVATE_CANARY")):
            P.denial_fixture_diagnostic(state, True)
        self.assertEqual(state.lock.release.call_count, 2)

    def test_execute_defers_fixture_snapshot_and_keeps_same_single_bridge_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = Path(directory); app = owner / "input.bin"; app.write_bytes(b"inert-no-execution")
            app_sha = hashlib.sha256(app.read_bytes()).hexdigest()
            order, bridges = [], []
            def bridge(case):
                item = FakeBridge(case); bridges.append(item)
                close = item.close
                def traced_close(): order.append("close"); return close()
                item.close = traced_close
                return item
            def source(case): (case / "source").mkdir(); return P.H.identity(case / "source")
            def diagnostic(*args): order.append("diagnostic")
            with ExitStack() as mocks:
                for obj, key, value in ((P.H, "prepare", lambda parent, name: (parent / name).mkdir()),
                    (P.H, "create_private_roots", lambda case: {}), (P.H, "private_directory", lambda case, child: (case / child).mkdir()),
                    (P.H, "private_write", lambda case, child, body: (case / child).write_bytes(body)),
                    (P.H, "environment", lambda case: {"SYNTHETIC": "1"}), (P, "create_source", source),
                    (P.C, "ObservedSourceBridge", bridge), (P.H, "application_roots_empty", lambda *args: None),
                    (P.H, "helper_baseline", lambda *args: {}), (P.H, "configuration_preserved", lambda case, cfg: case / "working.conf"),
                    (P, "manifest", Mock(side_effect=P.ProducerError("denial_failed"))), (P, "denial_fixture_diagnostic", diagnostic)):
                    mocks.enter_context(patch.object(obj, key, value))
                errors = []
                item = P.execute("revoked_a", owner, app, app_sha, RUNTIME,
                    types.SimpleNamespace(deadline=P.time.monotonic()+120, endpoint=("127.0.0.1", 2121)), self.state(), b"synthetic", errors)
            self.assertEqual(order, ["close"])
            self.assertEqual(errors, ["denial_failed"])
            self.assertEqual(item["record"]["failure_code"], "denial_failed")
            self.assertTrue(item["record"]["checks"]["process_cleanup"])
            self.assertFalse(item["record"]["checks"]["manifest_exact"])
            self.assertEqual(bridges[0].close_calls, 1)
            self.assertEqual([a for a, _ in bridges[0].commands].count("start_source_observed"), 1)

    def test_group_projects_once_after_existing_teardown_and_preserves_failure(self):
        diagnostic = P.denial_fixture_diagnostic
        for closed, fault in ((True, None), (False, None), (True, "exit"),
                              (True, "closed"), (True, "printer"), (True, "formatter")):
            with self.subTest(closed=closed, fault=fault):
                order, calls = [], []
                server = Mock(deadline=P.time.monotonic()+180, endpoint=("127.0.0.1", 2121))
                server.quiescent.return_value = True
                context = Mock(); context.__enter__ = Mock(return_value=server)
                def exit_context(*args):
                    order.append("teardown")
                    if fault == "exit": raise OSError("PRIVATE_CANARY")
                context.__exit__ = Mock(side_effect=exit_context)
                def fixture_closed(actual):
                    self.assertIs(actual, server); order.append("closed")
                    if fault == "closed": raise OSError("PRIVATE_CANARY")
                    return closed
                def advance(state, *args, **kwargs):
                    state.epoch = 2; state._event("epoch")
                def execute(name, owner, app, app_sha, runtime, actual_server, state, config, errors):
                    calls.append(name)
                    if name == "accepted_a":
                        state.events = self.state().events[:-4]
                    else:
                        state._event("session_open", 3); state._event("user", 3); state._event("denied_a", 3)
                    row = dict(status="failed", failure_code=None, checks=dict.fromkeys(P.E.CHECKS[name], True))
                    row["checks"].update(group_finalized=False, fixture_cleanup=False, temp_cleanup=False)
                    if name == "revoked_a": P.mark(row, "denial_failed", errors)
                    return dict(name=name, case=owner/name, record=row, lease=(1,2), config=config,
                                artifact="a"*64, roots={}, baseline={})
                def projected(state, actual_closed):
                    order.append("diagnostic")
                    diagnostic(state, actual_closed)
                with ExitStack() as mocks:
                    for obj, key, value in ((P.H, "prepare", Mock()), (P.H, "identity", lambda p: (1,2)),
                        (P.F.AppFtpState, "advance_epoch", advance), (P.F, "serve_ftp", Mock(return_value=context)),
                        (P, "execute", execute), (P, "fixture_checks", lambda *a: {}), (P, "preserved", Mock()),
                        (P, "fixture_closed", fixture_closed), (P.H, "application_roots_empty", Mock()),
                        (P.H, "helper_baseline", lambda *a: {}), (P.H, "helper_cleanup_preserved", Mock()),
                        (P.H, "inventory", lambda p: {})):
                        mocks.enter_context(patch.object(obj, key, value))
                    remove = mocks.enter_context(patch.object(P.H, "remove_owned"))
                    projected_call = mocks.enter_context(patch.object(P, "denial_fixture_diagnostic", side_effect=projected))
                    output = mocks.enter_context(patch("builtins.print", side_effect=OSError("PRIVATE_CANARY") if fault == "printer" else None))
                    if fault == "formatter":
                        mocks.enter_context(patch.object(P.E, "compact", side_effect=RuntimeError("PRIVATE_CANARY")))
                    errors = []
                    items, group, actual_closed = P.exercise(Path("synthetic-suite"), Path("app"), "0"*64, RUNTIME,
                        ("a"*64, "b"*64, "c"*64, "d"*107, "e"*107), errors)
                self.assertEqual(calls, ["accepted_a", "revoked_a"])
                self.assertEqual(order, ["teardown", "diagnostic"] if fault == "exit" else ["teardown", "closed", "diagnostic"])
                context.__exit__.assert_called_once_with(None, None, None)
                projected_call.assert_called_once()
                expected_closed = closed and fault not in {"exit", "closed"}
                self.assertIs(actual_closed, expected_closed)
                self.assertIs(projected_call.call_args.args[1], expected_closed)
                self.assertEqual(group["status"], "failed")
                self.assertEqual(group["failure_code"], "denial_failed")
                self.assertEqual(items[1]["record"]["failure_code"], "denial_failed")
                self.assertTrue(all(item["record"]["status"] == "failed" for item in items))
                self.assertEqual(errors, ["denial_failed", "group_failed"] if expected_closed else
                                 ["denial_failed", "cleanup_failed", "cleanup_failed"])
                if not expected_closed: remove.assert_not_called()
                if fault not in {"formatter", "printer"}:
                    output.assert_called_once()
                    line = output.call_args.args[0]
                    self.assertLessEqual(len(line.encode("ascii")) + 1, 1024)
                    self.assertNotIn("PRIVATE_CANARY", line)
                    record = json.loads(line.split("=", 1)[1])
                    self.assertEqual(record["timing"], "after_fixture_teardown_attempt")
                    self.assertIs(record["fixture_cleanup_complete"], expected_closed)
                    self.assertEqual(record["availability_reason"], "available")
                    self.assertEqual(record["counts"]["denied_a"], 1)



    def test_shape_projection_distinguishes_formatting_without_accepting_it(self):
        variants = (
            ("530 login incorrect", "casefold_equal"),
            ("530  Login incorrect", "spacefold_equal"),
            ("530 \tLogin   incorrect ", "spacefold_equal"),
            ("530  login INCORRECT", "case_spacefold_equal"),
            ('530 "Login incorrect"', "quoted_message_equal"),
            ("530 'Login incorrect'", "quoted_message_equal"),
        )
        for terminal, marker in variants:
            with self.subTest(marker=marker, terminal=terminal):
                value = self.value.replace("530 Login incorrect", terminal)
                projected = self.projected(P.denial_error_diagnostic, value, self.cause)
                self.assertTrue(projected["terminal_shape"][marker])
                self.assertFalse(projected["expected_cause_equal"])
                self.assertFalse(P.W.exact_rc_error(value, self.cause, stat=True))
                with tempfile.TemporaryDirectory() as directory:
                    case = Path(directory)
                    working = self.negative_manifest(case, value)
                    with patch("builtins.print"), self.assertRaisesRegex(P.ProducerError, "^denial_failed$"):
                        P.manifest("revoked_a", case, working, RUNTIME, ("127.0.0.1", 2121))

    def test_shape_projection_is_closed_bounded_and_never_returns_private_text(self):
        keys = {"ascii_printable", "casefold_equal", "spacefold_equal", "case_spacefold_equal",
                "quoted_message_equal", "expected_message_present", "prefix_equal_chars", "suffix_equal_chars"}
        for terminal in ("530 PRIVATE_CANARY", "530 " + "p" * 508, "530 \u2603PRIVATE_CANARY", "530 \x1bPRIVATE_CANARY"):
            result = P.denial_reply_shape(terminal)
            self.assertEqual(set(result), keys)
            self.assertNotIn("PRIVATE_CANARY", json.dumps(result))
            self.assertEqual(result["prefix_equal_chars"], 4)
            self.assertTrue(all(type(v) is bool for k, v in result.items() if not k.endswith("_chars")))
            self.assertTrue(all(type(result[k]) is int and 0 <= result[k] <= 19 for k in keys if k.endswith("_chars")))
            self.projected(P.denial_error_diagnostic, self.value.replace("530 Login incorrect", terminal), self.cause)
        class Private:
            def __str__(self):
                raise AssertionError("PRIVATE_CANARY")
        for terminal in (None, True, [], {"PRIVATE_CANARY": 1}, Private(), "", "530 " + "p" * 509):
            self.assertIsNone(P.denial_reply_shape(terminal))

    def test_shape_requires_unique_bound_notice_and_mismatching530_terminal(self):
        for value in (self.value, self.value.replace("530", "531"), self.value.replace(":2121", ":2122"),
                      self.notice + self.cause, self.value + self.notice + self.cause,
                      self.value.replace("NOTICE", "PRIVATE_CANARY")):
            self.assertIsNone(self.projected(P.denial_error_diagnostic, value, self.cause)["terminal_shape"])
        value = self.value.replace("530 Login incorrect", "530 " + "p" * 509)
        self.assertIsNone(self.projected(P.denial_error_diagnostic, value, self.cause)["terminal_shape"])

    def test_shape_failure_cannot_change_original_denial_or_run_on_success(self):
        value = self.value.replace("530 Login incorrect", "530 PRIVATE_CANARY")
        with tempfile.TemporaryDirectory() as directory:
            case = Path(directory)
            working = self.negative_manifest(case, value)
            original = P.ProducerError("denial_failed")
            with patch.object(P.W, "exact_rc_error", side_effect=original), \
                    patch.object(P, "denial_reply_shape", side_effect=RuntimeError("PRIVATE_CANARY")), \
                    patch("builtins.print"):
                with self.assertRaises(P.ProducerError) as caught:
                    P.manifest("revoked_a", case, working, RUNTIME, ("127.0.0.1", 2121))
            self.assertIs(caught.exception, original)
            working = self.negative_manifest(case, self.value)
            with patch.object(P, "denial_reply_shape", side_effect=AssertionError("must stay silent")):
                P.manifest("revoked_a", case, working, RUNTIME, ("127.0.0.1", 2121))

    def test_source_pinned_terminal_details_are_observations_never_accepted_causes(self):
        cases = {
            "530 Login incorrect": "login_incorrect", "530 Login required": "login_required",
            "Login incorrect": "login_message_only", "EOF": "eof_text", "unexpected EOF": "unexpected_eof_text",
            "i/o timeout": "io_timeout_text", "use of closed network connection": "closed_connection_text",
            "context canceled": "context_canceled_text", "context deadline exceeded": "context_deadline_text",
            "short response: PRIVATE_CANARY": "textproto_short_response",
            "invalid response code: PRIVATE_CANARY": "textproto_invalid_code",
            "PRIVATE_CANARY": "other", "531 Login incorrect": "other", "530 Login incorrect ": "other",
            "context canceled PRIVATE_CANARY": "other", "x: context canceled": "other",
            "PRIVATE_CANARY EOF": "other", "x: EOF PRIVATE_CANARY": "other", "x: i/o timeout ": "other",
            "short response PRIVATE_CANARY": "other", "x short response: PRIVATE_CANARY": "other",
        }
        for text, detail in (("EOF", "eof_text"), ("unexpected EOF", "unexpected_eof_text"),
                             ("i/o timeout", "io_timeout_text"), ("use of closed network connection", "closed_connection_text")):
            cases["read tcp PRIVATE_CANARY: " + text] = detail
        for terminal, detail in cases.items():
            with self.subTest(detail=detail):
                value = self.value.replace("530 Login incorrect", terminal)
                record = self.projected(P.denial_error_diagnostic, value, self.cause)
                self.assertEqual(record["terminal_detail"], detail)
                self.assertIs(record["terminal_reply_prefix"], terminal.startswith("530 "))
                self.assertIs(record["terminal_contains_reply"], "530 Login incorrect" in terminal)
                self.assertEqual(record["terminal_length_relation"], "shorter" if len(terminal) < 19 else
                                 "equal" if len(terminal) == 19 else "longer")
                self.assertIs(P.W.exact_rc_error(value, self.cause, stat=True), terminal == "530 Login incorrect")

    def test_new_terminal_fields_stay_unknown_without_unique_bound_notice(self):
        for value in (self.notice + self.cause, self.value.replace(":2121", ":2122"),
                      self.value + self.notice + self.cause, None, 3, True, float("nan"), float("inf"),
                      self.value + "\r", self.value + "\0", self.value.replace("NOTICE", "PRIVATE_CANARY")):
            record = self.projected(P.denial_error_diagnostic, value, self.cause)
            for key in ("terminal_reply_prefix", "terminal_contains_reply", "terminal_length_relation", "terminal_detail"):
                self.assertIsNone(record[key])

    def test_send_cache_binding_unknown_failure_success_and_ambiguity(self):
        state = self.state()
        self.assertEqual(self.projected(P.denial_fixture_diagnostic, state, True)["denial_send_availability"], "cache_unavailable")
        decision = state.events[-1]
        for attempted, returned in ((None, None), (True, None), (True, False), (True, True)):
            state._denial_send = (2, decision["ordinal"], decision["session"], attempted, returned)
            record = self.projected(P.denial_fixture_diagnostic, state, True)
            self.assertEqual(record["denial_send_availability"], "available")
            self.assertIs(record["denial_sendall_attempted"], attempted)
            self.assertIs(record["denial_sendall_returned"], returned)
        for cache in (None, {}, [2, 20, 3, True, True], (True, 20, 3, True, True),
                      (2, True, 3, True, True), (2, 20, True, True, True), (3, 20, 3, True, True),
                      (2, 19, 3, True, True), (2, 20, 4, True, True), (2, 20, 3, False, False),
                      (2, 20, 3, None, True), (2, 20, 3, 1, True), (2, 20, 3, True, 1),
                      (2, 20, 3, True, "PRIVATE_CANARY"), (2, 20, 3, True, float("nan")),
                      (2, 20, 3, True, float("inf")), (2, 20, 3, True, True, "PRIVATE_CANARY")):
            state._denial_send = cache
            record = self.projected(P.denial_fixture_diagnostic, state, True)
            self.assertEqual(record["denial_send_availability"], "cache_unavailable")
            self.assertIsNone(record["denial_sendall_attempted"])
            self.assertIsNone(record["denial_sendall_returned"])
        state._denial_send = (2, decision["ordinal"], decision["session"], True, True)
        state._event("denied_a", 4)
        record = self.projected(P.denial_fixture_diagnostic, state, True)
        self.assertEqual(record["denial_send_availability"], "ambiguous")
        self.assertIsNone(record["denial_sendall_returned"])
        empty = P.F.AppFtpState("PRIVATE_CANARY", "A", password_b="B"); empty.epoch = 2
        empty._denial_send = state._denial_send
        self.assertEqual(self.projected(P.denial_fixture_diagnostic, empty, True)["denial_send_availability"], "not_observed")

    def test_maximal_closed_records_and_baseexception_diagnostics_remain_bounded(self):
        state = self.state(); state.errors = sorted(P.F.ERROR_CODES)
        decision = state.events[-1]
        state._denial_send = (2, decision["ordinal"], decision["session"], True, False)
        self.projected(P.denial_fixture_diagnostic, state, False)
        self.projected(P.denial_error_diagnostic, self.value.replace("530 Login incorrect", "invalid response code: PRIVATE_CANARY"), self.cause)
        class BrokenState(P.F.AppFtpState):
            pass
        # Exact type checking rejects foreign state; invalid private cache never stringifies.
        self.assertEqual(self.projected(P.denial_fixture_diagnostic, BrokenState("u", "a", password_b="b"), True)["availability_reason"], "state_type")
        for function, args in ((P.denial_error_diagnostic, (self.value, self.cause)), (P.denial_fixture_diagnostic, (state, True))):
            with patch("builtins.print", side_effect=KeyboardInterrupt("PRIVATE_CANARY")):
                function(*args)
            with patch.object(P.E, "compact", side_effect=SystemExit("PRIVATE_CANARY")):
                function(*args)


if __name__ == "__main__":
    unittest.main()
