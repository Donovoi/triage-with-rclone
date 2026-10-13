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

PATH = Path(__file__).resolve().parents[1] / "application-lab/run_windows_b2.py"
P = types.ModuleType("b2_producer_test"); P.__file__ = str(PATH)
with patch.object(subprocess, "Popen", side_effect=AssertionError("forbidden")), patch.object(socket, "socket", side_effect=AssertionError("forbidden")):
    exec(compile(PATH.read_bytes(), str(PATH), "exec"), P.__dict__)
TEST = types.ModuleType("b2_synthetic_receipts"); TEST.__file__ = str(Path(__file__).with_name("test_b2_application_evidence.py"))
exec(compile(Path(TEST.__file__).read_bytes(), TEST.__file__, "exec"), TEST.__dict__)
RUNTIME = TEST.RUNTIME


def snapshot(name, action="finish", finished=True):
    result = dict(schema_version=3, action=action, ok=True, state="finished" if finished else "running",
        app_exit_code=(0 if name == "token_replacement" else 1) if finished else None,
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
    bridge.watchdog = Mock(); bridge.watchdog.is_alive.return_value = False
    bridge.threads = []
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
        for obj, name in ((subprocess, "Popen"), (socket, "socket"), (socket, "create_connection")):
            p = patch.object(obj, name, side_effect=AssertionError("forbidden")); p.start(); self.addCleanup(p.stop)

    def test_host_guard_precedes_any_input_read_or_fixture(self):
        with patch.object(P.H, "hosted_guard", side_effect=P.ProducerError("binding_failed")), patch.object(P.E, "compute_bindings") as binding:
            with self.assertRaises(P.ProducerError): P.run("not-read", "0" * 64, "1" * 40)
            binding.assert_not_called()

    def test_config_queue_and_generic_private_names_no_retry_override(self):
        config = P.config_bytes("http://127.0.0.1:1234/", "a" * 64, "b" * 64)
        self.assertEqual(config, ("[Synthetic]\ntype = b2\naccount = " + "a"*64 + "\nkey = " + "b"*64 + "\nendpoint = http://127.0.0.1:1234\n").encode())
        self.assertIn(b"synthetic-bucket/README-synthetic.txt,30,", P.queue_bytes())
        for value in ("http://localhost:1234/", "http://127.0.0.1:0/", "http://127.0.0.1:65536/", "http://127.0.0.1:1234/x\n"):
            with self.assertRaises(P.ProducerError): P.config_bytes(value, "a"*64, "b"*64)
        for name in (*P.CASE_DIRECTORIES.values(), "app-http-" + "a"*32):
            self.assertIn(P.H.setup_scope(name), P.H.SETUP_SCOPES)
        self.assertNotIn(b"retries", config)

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
            self.assertEqual(order, ["arm", "first_get", "verify", "replacement_get"] if name == "token_replacement" else ["arm", "verify", "first_get"])

    def test_bad_identity_or_elapsed_proof_never_releases(self):
        for changed in (None, dict(TEST.proof("arm"), runtime_live=False), dict(TEST.proof("arm"), runtime_ordinal=1)):
            state = Mock(case="token_replacement", errors=[])
            state.gate_snapshot.return_value = {g: dict(entered=1, released=False) for g in P.F.GATES}
            bridge = Mock(); bridge.command.return_value = dict(snapshot("token_replacement", "observe_continuity", False), continuity=changed)
            with self.assertRaises((P.ProducerError, P.C.H.ProducerError)):
                P.continuity(bridge, state, None, P.time.monotonic()+10, RUNTIME)
            state.release_gate.assert_not_called()
        state = Mock(case="token_replacement", errors=[])
        state.gate_snapshot.return_value = {g: dict(entered=1, released=False) for g in P.F.GATES}
        bridge = FakeBridge(Path("acquisition"))
        with patch.object(P.time, "monotonic", side_effect=[0, 11]):
            with self.assertRaises(P.ProducerError): P.continuity(bridge, state, None, 10, RUNTIME)
        state.release_gate.assert_not_called()

    def test_every_native_cleanup_flag_required(self):
        bridge = FakeBridge(Path("acquisition")); bridge.last = snapshot("token_replacement")
        self.assertTrue(P.cleanup_proved(bridge, True, "token_replacement", RUNTIME))
        for key in (*P.H.SESSION_CLEANUP, *P.C.OBSERVED_CLEANUP):
            bridge.last = snapshot("token_replacement"); bridge.last[key] = False
            try: okay = P.cleanup_proved(bridge, True, "token_replacement", RUNTIME)
            except (P.ProducerError, P.C.H.ProducerError): okay = False
            self.assertFalse(okay, key)
        for code in P.CLEANUP_UNCERTAIN:
            bridge.last = dict(snapshot("token_replacement"), ok=False, errors=[code])
            self.assertFalse(P.cleanup_proved(bridge, True, "token_replacement", RUNTIME))

    def test_real_ready_protocol_closes_without_finish_force_or_app_credit(self):
        original = owned_ready_bridge(); original.command("ready")
        self.assertFalse(original.close())  # Demonstrates the inherited failure.
        self.assertTrue(original.forced and original.failed.is_set())
        fixed = owned_ready_bridge(); fixed.command("ready")
        self.assertTrue(P.close_session(fixed, True, False, "token_replacement", RUNTIME))
        self.assertEqual([p["action"] for p in fixed.packets], ["ready", "close_ready"])
        self.assertFalse(fixed.forced or fixed.failed.is_set() or fixed.observer_started)
        fixed.process.stdin.close.assert_called_once(); fixed.process.wait.assert_called_once_with(timeout=10)
        fixed.watchdog.join.assert_called_once_with(1)

    def test_ready_proof_never_covers_possible_start_or_bad_close_reply(self):
        bridge = owned_ready_bridge(); bridge.command("ready")
        self.assertFalse(P.close_session(bridge, True, True, "token_replacement", RUNTIME))
        self.assertNotIn("close_ready", [p["action"] for p in bridge.packets])
        bridge = owned_ready_bridge(); bridge.command("ready")
        bridge.messages.get.return_value = b'{}'; bridge.messages.get.side_effect = None
        with self.assertRaises(P.C.H.ProducerError):
            P.close_session(bridge, True, False, "token_replacement", RUNTIME)
        bridge.process.stdin.close.assert_called_once()
        self.assertTrue(bridge.failed.is_set())

    def test_prestart_failures_write_failed_receipt_and_prove_owned_cleanup(self):
        import shutil
        for phase in ("before_fixture", "fixture_start", "config", "budget"):
            with tempfile.TemporaryDirectory() as directory, ExitStack() as mocks:
                parent = Path(directory); app = parent/"inert.bin"; app.write_bytes(b"inert")
                app_sha = P.H.sha(b"inert"); bound = dict(TEST.BINDINGS, application_sha256=app_sha)
                bridge = owned_ready_bridge(); removed = []
                state = P.F.AppB2State("token_replacement", "a"*64, "b"*64)
                server = Mock(endpoint="invalid" if phase == "config" else "http://127.0.0.1:1234/",
                    deadline=P.time.monotonic()+(-1 if phase == "budget" else 60))
                server.transport_snapshot.return_value = dict(cleanup_complete=True, active=0, workers_alive=0,
                    watchdog_alive=False, acceptor_alive=False)
                state._transport = server
                context = Mock(); context.__enter__ = Mock(return_value=server); context.__exit__ = Mock()
                if phase == "fixture_start": context.__enter__.side_effect = P.ProducerError("case_setup_failed")
                def prepare(p,n,action="Create"):
                    if action == "Create": (p/n).mkdir()
                def source(case): (case/"source").mkdir(); return P.H.identity(case/"source")
                def remove(path, identity):
                    path.relative_to(parent)  # Ordinary scratch tree only, never live evidence.
                    self.assertEqual(P.H.identity(path), identity)
                    removed.append(path.name); shutil.rmtree(path)
                for obj,key,value in ((P.H,"hosted_guard",Mock()),(P.E,"runtime_binding",lambda r:RUNTIME),
                        (P.E,"compute_bindings",lambda *a:bound),(P,"bindings",lambda *a:bound),
                        (P.H,"prepare",prepare),(P.H,"create_private_roots",lambda c:{}),
                        (P.H,"private_directory",lambda c,n:(c/n).mkdir()),(P.H,"private_write",lambda c,n,b:(c/n).write_bytes(b)),
                        (P,"create_source",source),(P.C,"ObservedSourceBridge",lambda c:bridge),
                        (P.H,"application_roots_empty",Mock()),(P.H,"helper_baseline",lambda *a:{}),
                        (P.H,"helper_cleanup_preserved",Mock()),(P.H,"remove_owned",remove),
                        (P.F,"AppB2State",lambda *a:state),(P.F,"serve_b2",lambda s:context)):
                    mocks.enter_context(patch.object(obj,key,value))
                if phase == "before_fixture": mocks.enter_context(patch.object(P.secrets,"token_hex",side_effect=P.ProducerError("case_setup_failed")))
                mocks.enter_context(patch.dict(P.os.environ, {"RUNNER_TEMP":str(parent),"GITHUB_SHA":bound["build_commit"]}))
                path=parent/"closed-failed.json"
                code=P.main(["--application",str(app),"--application-sha256",app_sha,"--build-commit",bound["build_commit"],"--report",str(path)])
                self.assertEqual(code,1)
                r=json.loads(path.read_bytes()); P.E.validate_receipt(r,RUNTIME,bound)
                self.assertEqual(r["result"],"failed"); self.assertTrue(r["cleanup_complete"])
                row=r["cases"]["token_replacement"]
                self.assertTrue(all(row["checks"][k] for k in ("process_cleanup","fixture_cleanup","temp_cleanup")))
                self.assertIsNone(row["exit_code"]); self.assertIsNone(row["observation"])
                self.assertEqual(r["cases"]["download_cap_denial"]["status"],"not_run")
                self.assertEqual([p["action"] for p in bridge.packets],["ready","close_ready"])
                self.assertEqual(len(removed),2); self.assertIn("acquisition",removed)
                self.assertNotIn("passed",r["capabilities"].values())

    def test_rejection_storm_writes_valid_failed_receipt_instead_of_empty_file(self):
        state=P.F.AppB2State("token_replacement","a"*64,"b"*64)
        for _ in range(128):
            try: state.begin("GET",P.F.AUTH,"invalid authorization")
            except P.F.FixtureError as error: state._error(str(error))
        row=P.E.empty_cases()["token_replacement"]
        row.update(status="failed",failure_code="fixture_failed",fixture=state.snapshot(),checks=dict.fromkeys(P.E.CHECKS["token_replacement"],False))
        for key in ("process_cleanup","fixture_cleanup","temp_cleanup"): row["checks"][key]=True
        def execute(name,*args):
            args[-1].append("fixture_failed")
            return dict(name=name,record=deepcopy(row),artifact=None)
        with tempfile.TemporaryDirectory() as directory, ExitStack() as mocks:
            for obj,key,value in ((P.H,"hosted_guard",Mock()),(P.E,"runtime_binding",lambda r:RUNTIME),
                    (P.E,"compute_bindings",lambda *a:TEST.BINDINGS),(P,"bindings",lambda *a:TEST.BINDINGS),
                    (P.H,"prepare",Mock()),(P.H,"identity",lambda p:(1,2)),(P.H,"inventory",lambda p:{}),
                    (P.H,"remove_owned",Mock()),(P,"execute",execute)):
                mocks.enter_context(patch.object(obj,key,value))
            mocks.enter_context(patch.dict(P.os.environ,{"RUNNER_TEMP":directory,"GITHUB_SHA":TEST.BINDINGS["build_commit"]}))
            path=Path(directory)/"storm-failed.json"
            code=P.main(["--application","not-read","--application-sha256",TEST.BINDINGS["application_sha256"],
                "--build-commit",TEST.BINDINGS["build_commit"],"--report",str(path)])
            self.assertEqual(code,1)
            r=json.loads(path.read_bytes()); P.E.validate_receipt(r,RUNTIME,TEST.BINDINGS)
            self.assertEqual(r["result"],"failed"); self.assertTrue(r["cleanup_complete"])
            self.assertEqual(r["cases"]["token_replacement"]["fixture"]["requests"],1)
            self.assertEqual(r["errors"],["fixture_failed","group_failed"])
            self.assertNotIn("passed",r["capabilities"].values())

    def test_execute_once_observed_start_no_hidden_runtime_and_fresh_fixture_after_ready(self):
        for name in P.E.CASES:
            with tempfile.TemporaryDirectory() as directory, ExitStack() as mocks:
                suite = Path(directory); app = suite / "input.bin"; app.write_bytes(b"inert")
                sha = hashlib.sha256(b"inert").hexdigest(); order = []
                bridge = FakeBridge(suite / P.CASE_DIRECTORIES[name])
                original = bridge.command
                def command(action, **kw): order.append(action); return original(action, **kw)
                bridge.command = command
                state = Mock(case=name); state.snapshot.return_value = TEST.fixture(name)
                server = Mock(endpoint="http://127.0.0.1:1234/", deadline=P.time.monotonic()+60)
                context = Mock(); context.__enter__ = Mock(side_effect=lambda: (order.append("fixture_start"), server)[1]); context.__exit__ = Mock()
                extra = ("manifest_exact", "output_hash_exact", "outputs_exact") if name == "token_replacement" else ("manifest_exact", "no_download_outputs")
                def prepare(parent, child, action="Create"):
                    if action == "Create": (parent / child).mkdir()
                def source(case): (case / "source").mkdir(); return P.H.identity(case / "source")
                for obj, key, value in ((P.H, "prepare", prepare), (P.H, "create_private_roots", lambda c: {}),
                        (P.H, "private_directory", lambda c, n: (c/n).mkdir()), (P.H, "private_write", lambda c,n,b: (c/n).write_bytes(b)),
                        (P.H, "environment", lambda c: {}), (P, "create_source", source), (P.C, "ObservedSourceBridge", lambda c: bridge),
                        (P.H, "application_roots_empty", Mock()), (P.H, "helper_baseline", lambda *a: {}),
                        (P.H, "helper_cleanup_preserved", Mock()), (P.H, "configuration_preserved", lambda c,v: c/"working.conf"),
                        (P, "manifest", lambda *a: dict.fromkeys(extra, True)), (P.W, "fingerprint", lambda c: "a"*64),
                        (P, "continuity", lambda *a: {p: TEST.proof(p) for p in ("arm", "verify")}),
                        (P, "preserved", Mock()), (P.H, "remove_owned", Mock()), (P, "fixture_closed", lambda s: True),
                        (P.F, "AppB2State", lambda *a: state), (P.F, "serve_b2", lambda s: context)):
                    mocks.enter_context(patch.object(obj, key, value))
                errors = []; item = P.execute(name, suite, app, sha, RUNTIME, errors)
                self.assertEqual(errors, [])
                self.assertTrue(all(v for k,v in item["record"]["checks"].items() if k != "group_finalized"))
                self.assertLess(order.index("ready"), order.index("fixture_start"))
                starts = [f for a,f in bridge.commands if a == "start_source_observed"]
                self.assertEqual(len(starts), 1)
                self.assertEqual(starts[0]["max_runtime_launches"], 2)
                self.assertLessEqual(starts[0]["deadline_ms"], 60000)
                self.assertFalse(any("retries" in arg for arg in starts[0]["args"]))
                context.__exit__.assert_called_once()

    def test_run_stops_after_failure_and_late_binding_failure_removes_credit(self):
        for initial_fail, late_failure in ((False, False), (True, False), (False, True)):
            calls = []
            def execute(name, *args):
                calls.append(name); row = deepcopy(TEST.receipt()["cases"][name]); row["status"] = "failed"; row["checks"]["group_finalized"] = False
                if initial_fail: P.mark(row, "session_failed", args[-1])
                return dict(name=name, record=row, artifact="a"*64)
            with ExitStack() as mocks:
                for obj, key, value in ((P.H, "hosted_guard", Mock()), (P.E, "runtime_binding", lambda root: RUNTIME),
                        (P.E, "compute_bindings", lambda *a: TEST.BINDINGS), (P.H, "prepare", Mock()),
                        (P.H, "identity", lambda p: (1,2)), (P.H, "inventory", lambda p: {}), (P.H, "remove_owned", Mock()),
                        (P, "execute", execute)):
                    mocks.enter_context(patch.object(obj, key, value))
                mocks.enter_context(patch.dict(P.os.environ, {"RUNNER_TEMP": str(Path.cwd()), "GITHUB_SHA": TEST.BINDINGS["build_commit"]}))
                values = [TEST.BINDINGS, P.ProducerError("preservation_failed") if late_failure else TEST.BINDINGS]
                mocks.enter_context(patch.object(P, "bindings", side_effect=values))
                r = P.run("not-read", TEST.BINDINGS["application_sha256"], TEST.BINDINGS["build_commit"])
                self.assertEqual(calls, list(P.E.CASES[:1] if initial_fail else P.E.CASES))
                self.assertEqual(r["result"], "failed" if initial_fail or late_failure else "passed")
                if initial_fail or late_failure: self.assertNotIn("passed", r["capabilities"].values())

    def test_terminal_cause_is_exact_and_never_generic_exit(self):
        cause = "failed to open source object: failed to GET for download: synthetic fixture response (403 download_cap_exceeded)"
        good = "2026/10/12 12:00:00 NOTICE: Failed to rc: loopback: call failed: " + cause
        self.assertTrue(P.W.exact_rc_error(good, cause))
        for bad in ("exit 1", good.replace("403", "401"), good.replace("download_cap_exceeded", "unauthorized"), good + "\nunknown", good.replace("failed to GET for download: ", "")):
            self.assertFalse(P.W.exact_rc_error(bad, cause))

    def test_manifest_independent_hash_exact_failure_and_residue_rejection(self):
        for name in P.E.CASES:
            positive = name == "token_replacement"
            case = Path("C:/synthetic-private"); base = case/"output"/P.H.CASE_NAME
            f = P.E.fixture_manifest(); destination = base/"downloads/Synthetic"/f["member"]
            working = base/"config/working.conf"; stem = "acquisition-20261012T120000.000"
            request = dict(source="Synthetic:"+f["member"], destination=str(destination), mode="CopyTo",
                expected_hash=f["sha256"], expected_hash_type="sha256", expected_size=f["size"])
            result = dict(local_sha256=f["sha256"] if positive else None, integrity="Verified" if positive else "Failed",
                source=request["source"], destination=str(destination), success=positive,
                error=None if positive else "2026/10/12 12:00:00 NOTICE: Failed to rc: loopback: call failed: failed to open source object: failed to GET for download: synthetic fixture response (403 download_cap_exceeded)",
                size=f["size"] if positive else None, hash=f["sha256"] if positive else None,
                hash_type="sha256" if positive else None, hash_verified=True if positive else None, hash_error=None)
            manifest = dict(schema_version=1, written_at="2026-10-12T12:00:00Z", rclone_version=RUNTIME["version"],
                config_path=str(working), plan=dict(files=[dict(remote_name="Synthetic", path=f["member"], request=request)], skipped_directories=0),
                results=[result], complete=positive)
            inventory = {d: (True,) for d in ("logs", "downloads", "listings", "config")}
            inventory.update({p: (False,) for p in (stem+".json", stem+".txt", "logs/"+stem+".log", "logs/"+stem+".checkpoint.json", "config/working.conf", "config/source.conf")})
            wanted = {"Synthetic/"+f["member"]: ()} if positive else {}
            if positive:
                inventory.update({"downloads/Synthetic": (True,), "downloads/Synthetic/synthetic-bucket": (True,), "downloads/Synthetic/"+f["member"]: (False,)})
            for mutation in (None, "hash", "body", "residue", "cause", "generic_exit", "wrong_source", "missing_get_wrapper"):
                if mutation in {"body", "hash"} and not positive: continue
                if mutation in {"cause", "generic_exit", "missing_get_wrapper"} and positive: continue
                value = deepcopy(manifest); inv = dict(inventory); data = P.F.BODY
                if mutation == "hash": value["results"][0]["local_sha256"] = "f"*64
                if mutation == "body": data = b"x"*len(data)
                if mutation == "residue": inv["downloads/.triage-transfer/partial"] = (False,)
                if mutation == "cause": value["results"][0]["error"] = value["results"][0]["error"].replace("download_cap_exceeded", "unauthorized")
                if mutation == "generic_exit": value["results"][0]["error"] = "exit 1"
                if mutation == "missing_get_wrapper": value["results"][0]["error"] = value["results"][0]["error"].replace("failed to GET for download: ", "")
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


if __name__ == "__main__": unittest.main()
