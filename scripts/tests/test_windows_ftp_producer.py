"""Fake boundaries only. These tests cannot qualify FTP or a native observer."""
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import tempfile
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
        for obj, name in ((subprocess, "Popen"), (socket, "socket"), (socket, "create_connection")):
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
                errors = []
                items, group, actual_closed = P.exercise(Path("synthetic-suite"), Path("app"), "0"*64, RUNTIME,
                    ("a"*64, "b"*64, "c"*64, "d"*107, "e"*107), errors)
            expected = list(P.E.CASES) if fail_name is None else list(P.E.CASES[:P.E.CASES.index(fail_name)+1])
            self.assertEqual(calls, expected)
            self.assertEqual(actual_closed, closed)
            self.assertEqual(group["status"], "passed" if fail_name is None and closed else "failed")
            self.assertEqual(state.advance_epoch.call_count, 2 if fail_name is None else P.E.CASES.index(fail_name))
            for call in state.advance_epoch.call_args_list:
                self.assertEqual(call.kwargs, dict(invocation_succeeded=True, processes_reaped=True))
            if fail_name is not None or not closed:
                self.assertTrue(all(item["record"]["status"] == "failed" for item in items))
            if not closed:
                remove.assert_not_called()


if __name__ == "__main__":
    unittest.main()
