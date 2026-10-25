"""Fake supervisor/filesystem boundaries only; no helper or socket execution."""
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

PATH = Path(__file__).resolve().parents[1] / "application-lab/run_windows_webdav_bearer.py"
P = types.ModuleType("webdav_bearer_producer_test"); P.__file__ = str(PATH)
with patch.object(subprocess, "Popen", side_effect=AssertionError("forbidden")), patch.object(socket, "socket", side_effect=AssertionError("forbidden")):
    exec(compile(PATH.read_bytes(), str(PATH), "exec"), P.__dict__)
TEST = types.ModuleType("webdav_bearer_synthetic_receipts"); TEST.__file__ = str(Path(__file__).with_name("test_webdav_bearer_application_evidence.py"))
exec(compile(Path(TEST.__file__).read_bytes(), TEST.__file__, "exec"), TEST.__dict__)
RUNTIME = TEST.RUNTIME


def snapshot(name, action="finish", finished=True):
    result = dict(schema_version=3, action=action, ok=True, state="finished" if finished else "running",
        app_exit_code=(0 if name == "accepted_token" else 1) if finished else None,
        runtime_image_observed=False, runtime_sha256=None, runtime_process_count=None, ctrl_c_sent=False,
        output_bytes=0, output_limit_exceeded=False, forced_termination=False, errors=[], observation_kind="launch_image",
        launch_image_observed=True, launch_sha256=RUNTIME["sha256"], runtime_launch_count=2, peak_runtime_processes=1,
        system_helper_image_observed=True, system_helper_sha256="2" * 64, system_helper_launch_count=2,
        peak_system_helper_processes=1, debug_event_count=100)
    result.update(dict.fromkeys((*P.H.SESSION_CLEANUP, *P.C.OBSERVED_CLEANUP), finished))
    return result


class FakeBridge:
    def __init__(self, case):
        self.name = next(n for n, d in P.CASE_DIRECTORIES.items() if case.name == d)
        self.commands, self.last = [], None

    def command(self, action, **fields):
        self.commands.append((action, fields))
        if action == "ready": self.last = dict(schema_version=1, action="ready", ok=True, state="ready")
        elif action == "observe_continuity": self.last = dict(snapshot(self.name, action, False), continuity=TEST.proof(fields["phase"]))
        else: self.last = snapshot(self.name, action, action != "start_source_observed")
        return self.last

    def close(self): return True


def owned_ready_bridge():
    """Real command/preflight/close methods, only process/pipes/readers are fake."""
    bridge = P.C.ObservedSourceBridge.__new__(P.C.ObservedSourceBridge)
    bridge.observer_started = False
    bridge.ready = bridge.closed_ready = bridge.forced = False
    bridge.calls = bridge.responses = 0
    bridge.last = None
    bridge.failed = threading.Event(); bridge.done = threading.Event()
    bridge.response_lock = threading.RLock(); bridge.deadline = P.time.monotonic()+165
    bridge._diagnostic = Mock()
    bridge.process = Mock(returncode=0); bridge.process.poll.return_value = None
    # The owner now supplies an explicit closed-handle/reservation result.
    bridge.process.finalize.return_value = True
    bridge.process.finalized = False
    bridge.watchdog = Mock(); bridge.watchdog.is_alive.return_value = False
    bridge.threads = [Mock(), Mock()]
    for reader in bridge.threads:
        reader.is_alive.return_value = False
    bridge.messages = Mock(); bridge.messages.empty.return_value = True
    bridge.packets = []
    bridge.process.stdin.write.side_effect = lambda wire: bridge.packets.append(json.loads(wire))
    def receive(**kwargs):
        action = bridge.packets[-1]["action"]
        assert action in {"ready", "close_ready"}
        bridge.responses = bridge.calls
        return json.dumps(dict(schema_version=1, action=action, ok=True, state="ready" if action == "ready" else "closed")).encode()
    bridge.messages.get.side_effect = receive
    return bridge


class ProducerTests(unittest.TestCase):
    def setUp(self):
        for obj, name in ((subprocess, "Popen"), (socket, "socket"), (socket, "create_connection"), (threading.Thread, "start")):
            p = patch.object(obj, name, side_effect=AssertionError("forbidden")); p.start(); self.addCleanup(p.stop)
        self.session_observer = Mock()
        self.session_observer.observe.side_effect = lambda process, deadline: ProducerTests.session_quiescence(self, process, deadline)
        p = patch.object(P.C.H.O, "_SessionQuiescence", return_value=self.session_observer)
        self.session_observer_factory = p.start(); self.addCleanup(p.stop)


    def session_quiescence(self, process, deadline):
        # Keep the real Bridge.close ordering; only native Job observation is fake.
        process.stdin.close.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=10)
        process.stdout.close.assert_called_once_with()
        process.stderr.close.assert_called_once_with()
        self.assertIs(type(deadline), float)

    def test_host_guard_precedes_any_input_read_or_fixture(self):
        with patch.object(P.H, "hosted_guard", side_effect=P.ProducerError("binding_failed")), patch.object(P.E, "compute_bindings") as binding:
            with self.assertRaises(P.ProducerError): P.run("not-read", "0" * 64, "1" * 40)
            binding.assert_not_called()


    def test_printer_baseexception_cannot_replace_failure_or_publish_private_text(self):
        with patch.object(P.H, "hosted_guard", side_effect=P.ProducerError("private canary")), \
                patch("builtins.print", side_effect=KeyboardInterrupt("printer canary")) as printer:
            self.assertEqual(P.main(["--application", "unused", "--application-sha256", "1"*64,
                "--build-commit", "2"*40, "--report", "unused"]), 1)
            self.assertEqual(printer.call_args.args, ("application_probe_failed",))


    def test_fixture_cleanup_requires_typed_closed_snapshot_and_retains_uncertainty(self):
        value = dict(accepted=6, active=0, workers_alive=0, watchdog_alive=False, acceptor_alive=False, cleanup_complete=True)
        server = Mock(); server.transport_snapshot.return_value = value
        self.assertTrue(P.fixture_closed(server))
        for changes in (dict(active=False), dict(workers_alive=True), dict(accepted=129),
                dict(cleanup_complete=1), dict(watchdog_alive=0), dict(extra="private canary")):
            server.transport_snapshot.return_value = dict(value, **changes)
            self.assertFalse(P.fixture_closed(server))
        server.transport_snapshot.side_effect = KeyboardInterrupt("private canary")
        self.assertFalse(P.fixture_closed(server))


    def test_retained_proofs_precede_each_release_including_denial(self):
        for name in P.E.CASES:
            state = Mock(case=name, errors=[])
            state.gate_snapshot.return_value = {g: dict(entered=1, released=False) for g in P.F.GATES}
            bridge = FakeBridge(Path(P.CASE_DIRECTORIES[name]))
            order = []
            original = bridge.command
            def command(action, **kw):
                order.append(kw["phase"]); return original(action, **kw)
            bridge.command = command
            state.release_gate.side_effect = lambda gate: order.append(gate)
            result = P.continuity(bridge, state, None, P.time.monotonic()+10, RUNTIME)
            self.assertEqual(set(result), {"arm", "verify"})
            self.assertEqual(order, ["arm", "verify", "first_get"])


    def test_bad_identity_or_elapsed_proof_never_releases(self):
        for changed in (None, dict(TEST.proof("arm"), runtime_live=False), dict(TEST.proof("arm"), runtime_ordinal=1)):
            state = Mock(case="accepted_token", errors=[])
            state.gate_snapshot.return_value = {g: dict(entered=1, released=False) for g in P.F.GATES}
            bridge = Mock(); bridge.command.return_value = dict(snapshot("accepted_token", "observe_continuity", False), continuity=changed)
            with self.assertRaises((P.ProducerError, P.C.H.ProducerError)):
                P.continuity(bridge, state, None, P.time.monotonic()+10, RUNTIME)
            state.release_gate.assert_not_called()
        state = Mock(case="accepted_token", errors=[])
        state.gate_snapshot.return_value = {g: dict(entered=1, released=False) for g in P.F.GATES}
        bridge = FakeBridge(Path("acquisition"))
        with patch.object(P.time, "monotonic", side_effect=[0, 11]):
            with self.assertRaises(P.ProducerError): P.continuity(bridge, state, None, 10, RUNTIME)
        state.release_gate.assert_not_called()


    def test_every_native_cleanup_flag_required(self):
        bridge = FakeBridge(Path("acquisition")); bridge.last = snapshot("accepted_token")
        self.assertTrue(P.cleanup_proved(bridge, True, "accepted_token", RUNTIME))
        for key in (*P.H.SESSION_CLEANUP, *P.C.OBSERVED_CLEANUP):
            bridge.last = snapshot("accepted_token"); bridge.last[key] = False
            try: okay = P.cleanup_proved(bridge, True, "accepted_token", RUNTIME)
            except (P.ProducerError, P.C.H.ProducerError): okay = False
            self.assertFalse(okay, key)
        for code in P.CLEANUP_UNCERTAIN:
            bridge.last = dict(snapshot("accepted_token"), ok=False, errors=[code])
            self.assertFalse(P.cleanup_proved(bridge, True, "accepted_token", RUNTIME))


    def test_real_ready_protocol_closes_without_finish_force_or_app_credit(self):
        original = owned_ready_bridge(); original.command("ready")
        self.assertFalse(original.close())  # Demonstrates the inherited failure.
        self.assertTrue(original.forced and original.failed.is_set())
        fixed = owned_ready_bridge(); fixed.command("ready")
        original_deadline = fixed.deadline
        self.assertTrue(P.close_session(fixed, True, False, "accepted_token", RUNTIME))
        self.assertEqual([p["action"] for p in fixed.packets], ["ready", "close_ready"])
        self.assertFalse(fixed.forced or fixed.failed.is_set() or fixed.observer_started)
        fixed.process.stdin.close.assert_called_once(); fixed.process.wait.assert_called_once_with(timeout=10)
        fixed.watchdog.join.assert_called_once_with(1)
        for reader in fixed.threads:
            reader.join.assert_called_once_with(2)
        self.session_observer.observe.assert_called_once_with(fixed.process, original_deadline)
        self.assertEqual(fixed.deadline, original_deadline)
        fixed.process.finalize.assert_called_once_with()
        fixed.process.mark_uncertain.assert_not_called()


    def test_ready_close_requires_exact_owner_proof_after_original_teardown(self):
        for outcome in (True, False, None, 1, Mock(), KeyboardInterrupt("private canary")):
            with self.subTest(outcome_type=type(outcome).__name__):
                bridge = owned_ready_bridge(); bridge.command("ready")
                def finalize():
                    bridge.process.stdin.close.assert_called_once_with()
                    bridge.process.wait.assert_called_once_with(timeout=10)
                    bridge.watchdog.join.assert_called_once_with(1)
                    for reader in bridge.threads:
                        reader.join.assert_called_once_with(2)
                    bridge.process.stdout.close.assert_called_once_with()
                    bridge.process.stderr.close.assert_called_once_with()
                    self.session_observer.observe.assert_called_with(bridge.process, bridge.deadline)
                    if bridge.process.finalize.call_count == 1:
                        bridge.process.mark_uncertain.assert_not_called()
                    else:
                        # None is outside the owner's bool contract; the existing
                        # close finally makes one defensive, non-crediting call.
                        self.assertIsNone(outcome)
                        bridge.process.mark_uncertain.assert_called_once_with()
                    if isinstance(outcome, BaseException):
                        raise outcome
                    return outcome
                bridge.process.finalize.side_effect = finalize
                self.assertIs(P.close_session(bridge, True, False, 'accepted_token', RUNTIME), outcome is True)
                self.assertEqual(bridge.process.finalize.call_count, 2 if outcome is None else 1)
                self.assertTrue(all(not c.args and not c.kwargs for c in bridge.process.finalize.call_args_list))
                self.assertEqual([p["action"] for p in bridge.packets], ["ready", "close_ready"])
                self.assertFalse(bridge.observer_started)

        # Even a positive owner return cannot override an original cleanup failure.
        for failure in ("forced", "failed", "exit", "messages", "watchdog", "reader"):
            with self.subTest(failure=failure):
                bridge = owned_ready_bridge(); bridge.command("ready")
                bridge.command("close_ready")
                if failure == "forced": bridge.forced = True
                elif failure == "failed": bridge.failed.set()
                elif failure == "exit": bridge.process.returncode = 1
                elif failure == "messages": bridge.messages.empty.return_value = False
                elif failure == "watchdog": bridge.watchdog.is_alive.return_value = True
                else: bridge.threads[0].is_alive.return_value = True
                def finalize_uncertain():
                    bridge.process.mark_uncertain.assert_called_once_with()
                    return True
                bridge.process.finalize.side_effect = finalize_uncertain
                self.assertFalse(bridge.close())
                bridge.process.finalize.assert_called_once_with()
                if failure == "reader":
                    bridge.process.stdout.close.assert_not_called()

    def test_ready_close_rejects_failed_session_observation_even_if_finalizer_succeeds(self):
        bridge = owned_ready_bridge(); bridge.command("ready")
        original_deadline = bridge.deadline
        self.session_observer.observe.side_effect = OSError("private canary")
        self.assertFalse(P.close_session(bridge, True, False, "accepted_token", RUNTIME))
        self.session_observer_factory.assert_called_once_with()
        self.session_observer.observe.assert_called_once_with(bridge.process, original_deadline)
        self.assertEqual(bridge.deadline, original_deadline)
        bridge.process.finalize.assert_called_once_with()
        self.assertFalse(bridge.observer_started)

    def test_ready_proof_never_covers_possible_start_or_bad_close_reply(self):
        bridge = owned_ready_bridge(); bridge.command("ready")
        self.assertFalse(P.close_session(bridge, True, True, "accepted_token", RUNTIME))
        self.assertNotIn("close_ready", [p["action"] for p in bridge.packets])
        bridge = owned_ready_bridge(); bridge.command("ready")
        bridge.messages.get.return_value = b'{}'; bridge.messages.get.side_effect = None
        with self.assertRaises(P.C.H.ProducerError):
            P.close_session(bridge, True, False, "accepted_token", RUNTIME)
        bridge.process.stdin.close.assert_called_once()
        self.assertTrue(bridge.failed.is_set())


    def test_terminal_cause_is_exact_and_never_generic_exit(self):
        cause = "failed to open source object: 401 Unauthorized"
        good = "2026/10/12 12:00:00 NOTICE: Failed to rc: loopback: call failed: " + cause
        self.assertTrue(P.W.exact_rc_error(good, cause))
        for bad in ("exit 1", good.replace("401 Unauthorized", "Authorization Failed"), good.replace("401 Unauthorized", "forbidden"), good + "\nunknown", good.replace("failed to open source object: ", "")):
            self.assertFalse(P.W.exact_rc_error(bad, cause))


    def test_manifest_independent_hash_exact_failure_and_residue_rejection(self):
        for name in P.E.CASES:
            positive = name == "accepted_token"
            case = Path("C:/synthetic-private"); base = case/"output"/P.H.CASE_NAME
            f = P.E.fixture_manifest(); destination = base/"downloads/Synthetic"/f["member"]
            working = base/"config/working.conf"; stem = "acquisition-20261012T120000.000"
            request = dict(source="Synthetic:"+f["member"], destination=str(destination), mode="CopyTo",
                expected_hash=f["sha256"], expected_hash_type="sha256", expected_size=f["size"])
            result = dict(local_sha256=f["sha256"] if positive else None, integrity="Verified" if positive else "Failed",
                source=request["source"], destination=str(destination), success=positive,
                error=None if positive else "2026/10/12 12:00:00 NOTICE: Failed to rc: loopback: call failed: failed to open source object: 401 Unauthorized",
                size=f["size"] if positive else None, hash=f["sha256"] if positive else None,
                hash_type="sha256" if positive else None, hash_verified=True if positive else None, hash_error=None)
            manifest = dict(schema_version=1, written_at="2026-10-12T12:00:00Z", rclone_version=RUNTIME["version"],
                config_path=str(working), plan=dict(files=[dict(remote_name="Synthetic", path=f["member"], request=request)], skipped_directories=0),
                results=[result], complete=positive)
            inventory = {d: (True,) for d in ("logs", "downloads", "listings", "config")}
            inventory.update({p: (False,) for p in (stem+".json", stem+".txt", "logs/"+stem+".log", "logs/"+stem+".checkpoint.json", "config/working.conf", "config/source.conf")})
            wanted = {"Synthetic/"+f["member"]: ()} if positive else {}
            if positive:
                inventory.update({"downloads/Synthetic": (True,), "downloads/Synthetic/"+f["member"]: (False,)})
            for mutation in (None, "hash", "body", "residue", "cause", "generic_exit", "wrong_source", "missing_get_wrapper"):
                if mutation in {"body", "hash"} and not positive: continue
                if mutation in {"cause", "generic_exit", "missing_get_wrapper"} and positive: continue
                value = deepcopy(manifest); inv = dict(inventory); data = P.F.BODY
                if mutation == "hash": value["results"][0]["local_sha256"] = "f"*64
                if mutation == "body": data = b"x"*len(data)
                if mutation == "residue": inv["downloads/.triage-transfer/partial"] = (False,)
                if mutation == "cause": value["results"][0]["error"] = value["results"][0]["error"].replace("401 Unauthorized", "Authorization Failed")
                if mutation == "generic_exit": value["results"][0]["error"] = "exit 1"
                if mutation == "missing_get_wrapper": value["results"][0]["error"] = value["results"][0]["error"].replace("failed to open source object: ", "")
                if mutation == "wrong_source": value["plan"]["files"][0]["request"]["source"] += "-other"
                outer = {P.H.CASE_NAME: (True,), **{P.H.CASE_NAME+"/"+p: v for p,v in inv.items()}}
                with patch.object(P.H, "inventory", side_effect=lambda path: inv if path == base else outer), \
                        patch.object(P.H, "read", side_effect=lambda path, *a: json.dumps(value).encode() if path.suffix == ".json" else data), \
                        patch.object(P.H, "same_path", side_effect=lambda a,b: str(a) == str(b)), \
                        patch.object(P.H, "output_files", return_value=wanted):
                    if mutation is None:
                        self.assertTrue(all(P.manifest(name, case, working, RUNTIME, "unused").values()))
                    else:
                        with self.assertRaises(P.ProducerError): P.manifest(name, case, working, RUNTIME, "unused")


    def test_config_queue_app_and_saved_artifact_preservation_are_independent(self):
        case = Path("C:/synthetic-private"); config = b"synthetic config"
        item = dict(case=case, lease=(1,2), source=(2,3), config=config, artifact="a"*64,
            record=dict(checks=dict(configuration_preserved=True)))
        for broken in (None, "config", "queue", "app", "artifact", "source", "identity"):
            def read(path, *a):
                if path.name == "application.exe": return b"changed" if broken == "app" else b"app"
                if path.name == "source.conf": return b"changed" if broken == "config" else config
                return b"changed" if broken == "queue" else P.queue_bytes()
            with patch.object(P.H, "identity", side_effect=lambda path: (0,0) if broken == "identity" else (item["lease"] if path == case else item["source"])), \
                    patch.object(P.H, "inventory", return_value={"extra": ()} if broken == "source" else {}), \
                    patch.object(P.H, "read", side_effect=read), patch.object(P.H, "configuration_preserved") as working, \
                    patch.object(P.W, "fingerprint", return_value="b"*64 if broken == "artifact" else "a"*64):
                if broken is None:
                    P.preserved(item, P.H.sha(b"app")); working.assert_called_once()
                else:
                    with self.assertRaises(P.ProducerError): P.preserved(item, P.H.sha(b"app"))

    def test_configuration_and_queue_are_closed_fixed_token_inputs(self):
        config = P.config_bytes("http://127.0.0.1:12345/", "a"*64).decode()
        self.assertEqual(set(line.split(" = ")[0] for line in config.splitlines()[1:]),
                         {"type", "url", "vendor", "auth_redirect", "bearer_token"})
        self.assertIn("bearer_token = " + "a"*64, config)
        for endpoint, token in (("http://localhost:12345/", "a"*64), ("http://127.0.0.1:65536/", "a"*64),
                ("https://127.0.0.1:12345/", "a"*64), ("http://127.0.0.1:12345/", "a"*63+"\n")):
            with self.assertRaises(P.ProducerError): P.config_bytes(endpoint, token)
        rows = list(P.csv.reader(P.io.StringIO(P.queue_bytes().decode("utf-8-sig"))))
        self.assertEqual(rows[1][1:4], ["Synthetic", "README-synthetic.txt", "30"])
        self.assertEqual(rows[1][-2:], ["64d5b40a5f4773b14940a6ce1dd57cf87b44ce5940c097088732ffc71be280cf", "sha256"])

    def test_execute_reaps_and_retains_case_until_group_finalization(self):
        for name in P.E.CASES:
            with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
                suite = Path(temp); app = suite/"inert.bin"; app.write_bytes(b"inert")
                bridge = FakeBridge(Path(P.CASE_DIRECTORIES[name])); server = Mock(endpoint="http://127.0.0.1:12345/", deadline=P.time.monotonic()+60)
                def prepare(owner, child, *args): (owner/child).mkdir()
                def private(owner, child): (owner/child).mkdir()
                def source(case): (case/"source").mkdir(); return (1, 2)
                mocks = [(P.H, "prepare", dict(side_effect=prepare)), (P.H, "identity", dict(return_value=(1,2))),
                    (P.H, "create_private_roots", dict(return_value={})), (P.H, "private_directory", dict(side_effect=private)),
                    (P.H, "private_write", dict(side_effect=lambda owner, child, data: (owner/child).write_bytes(data))),
                    (P, "create_source", dict(side_effect=source)), (P.C, "ObservedSourceBridge", dict(return_value=bridge)),
                    (P.H, "application_roots_empty", {}), (P.H, "helper_baseline", dict(return_value={})),
                    (P.H, "environment", dict(return_value={})), (P.H, "configuration_preserved", dict(return_value="working")),
                    (P, "continuity", dict(return_value={phase: TEST.proof(phase) for phase in ("arm", "verify")})),
                    (P, "manifest", dict(return_value=dict.fromkeys(("manifest_exact", "output_hash_exact", "outputs_exact") if name == "accepted_token" else ("manifest_exact", "no_download_outputs"), True))),
                    (P.W, "fingerprint", dict(return_value="a"*64))]
                for obj, attr, kwargs in mocks: stack.enter_context(patch.object(obj, attr, **kwargs))
                remove = stack.enter_context(patch.object(P.H, "remove_owned"))
                errors = []; item = P.execute(name, suite, app, P.H.sha(b"inert"), RUNTIME, server, Mock(), b"fixed", errors)
                self.assertEqual(errors, [])
                self.assertTrue(item["case"].is_dir()); remove.assert_not_called()
                checks = item["record"]["checks"]
                self.assertTrue(all(checks[k] for k in ("runtime_observed", "configuration_preserved", "process_cleanup", "same_copy_process", "manifest_exact")))
                self.assertTrue(all(checks[k] is False for k in ("fixture_cleanup", "temp_cleanup", "group_finalized")))
                starts = [fields for action, fields in bridge.commands if action == "start_source_observed"]
                self.assertEqual(len(starts), 1)
                self.assertEqual((starts[0]["max_runtime_launches"], starts[0]["max_runtime_processes"]), (2, 1))
                self.assertLessEqual(starts[0]["deadline_ms"], 60000)

    def test_group_order_preserves_both_before_removal_and_failures_stay_unqualified(self):
        for fault in (None, "control_failure", "artifact_changed", "close_uncertain", "late_source_changed"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
                order, configs = [], []
                def execute(name, suite, app, app_sha, runtime, server, state, config, errors):
                    configs.append(config); order.append("execute:"+name)
                    for method in ("PROPFIND", "PROPFIND", "GET"):
                        request = state.begin(method, P.F.MEMBER, "Bearer " + state._token)
                        if method == "GET": state.release_gate("first_get")
                        status, body, _, payload = state.response(request, server.endpoint)
                        state.commit(request, status, 256+len(body), payload)
                    record = TEST.receipt()["cases"][name]; record["status"] = "failed"
                    for key in ("fixture_valid", "source_preserved", "fixture_cleanup", "temp_cleanup", "group_finalized"):
                        record["checks"][key] = False
                    if fault == "control_failure": P.mark(record, "manifest_invalid", errors)
                    return dict(name=name, record=record, case=suite/P.CASE_DIRECTORIES[name], lease=(1,2), source=(1,3),
                        roots={}, baseline={}, artifact="a"*64, config=config, config_written=True, start_attempted=True)
                def context(state):
                    class Context:
                        def __enter__(self):
                            self.server = Mock(endpoint="http://127.0.0.1:12345/", deadline=P.time.monotonic()+60)
                            self.server.snapshot.side_effect = state.snapshot
                            self.server.transport_snapshot.return_value = dict(accepted=6, active=0, workers_alive=0,
                                watchdog_alive=False, acceptor_alive=False, cleanup_complete=fault != "close_uncertain")
                            state._transport = self.server
                            return self.server
                        def __exit__(self, *args): order.append("closed")
                    return Context()
                def preserved(item, *args, **kwargs):
                    order.append("preserved:"+item["name"])
                    if fault == "artifact_changed" and item["name"] == "accepted_token": raise P.ProducerError("preservation_failed")
                binding_calls = []
                def bound(*args):
                    binding_calls.append(1)
                    if fault == "late_source_changed" and len(binding_calls) == 2: raise P.ProducerError("preservation_failed")
                    return TEST.BINDINGS
                for obj, attr, kwargs in [(P.H, "hosted_guard", {}), (P.E, "runtime_binding", dict(return_value=RUNTIME)),
                    (P.E, "compute_bindings", dict(return_value=TEST.BINDINGS)), (P, "bindings", dict(side_effect=bound)),
                    (P.H, "prepare", {}), (P.H, "identity", dict(return_value=(1,2))), (P, "execute", dict(side_effect=execute)),
                    (P.F, "serve_bearer", dict(side_effect=context)), (P, "preserved", dict(side_effect=preserved)),
                    (P.H, "application_roots_empty", {}), (P.H, "helper_baseline", dict(return_value={})),
                    (P.H, "helper_cleanup_preserved", {}), (P.H, "inventory", dict(return_value={})),
                    (P.H, "remove_owned", dict(side_effect=lambda path, lease: order.append("removed:"+path.name)))]:
                    stack.enter_context(patch.object(obj, attr, **kwargs))
                stack.enter_context(patch.dict(P.os.environ, RUNNER_TEMP=temp, GITHUB_SHA=TEST.BINDINGS["build_commit"]))
                receipt = P.run("inert.bin", TEST.BINDINGS["application_sha256"], TEST.BINDINGS["build_commit"])
                self.assertEqual(receipt["result"], "passed" if fault is None else "failed")
                if fault == "control_failure":
                    self.assertEqual(receipt["cases"]["invalidated_token"]["status"], "not_run")
                    self.assertEqual(len(configs), 1)
                else:
                    self.assertEqual(len(configs), 2); self.assertEqual(configs[0], configs[1])
                    self.assertLess(order.index("closed"), order.index("preserved:accepted_token"))
                    removes = [i for i, entry in enumerate(order) if entry.startswith("removed:")]
                    if fault == "close_uncertain": self.assertEqual(removes, [])
                    else: self.assertLess(order.index("preserved:invalidated_token"), min(removes))
                if fault:
                    self.assertEqual(set(receipt["capabilities"].values()), {"not_verified"})
                    self.assertTrue(receipt["errors"])
