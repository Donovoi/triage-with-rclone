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

PATH = Path(__file__).resolve().parents[1] / "application-lab/run_windows_swift.py"
P = types.ModuleType("swift_producer_test"); P.__file__ = str(PATH)
with patch.object(subprocess, "Popen", side_effect=AssertionError("forbidden")), patch.object(socket, "socket", side_effect=AssertionError("forbidden")):
    exec(compile(PATH.read_bytes(), str(PATH), "exec"), P.__dict__)
TEST = types.ModuleType("swift_synthetic_receipts"); TEST.__file__ = str(Path(__file__).with_name("test_swift_application_evidence.py"))
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
        for obj, name in ((subprocess, "Popen"), (socket, "socket"), (socket, "create_connection"), (threading.Thread, "start")):
            p = patch.object(obj, name, side_effect=AssertionError("forbidden")); p.start(); self.addCleanup(p.stop)

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

    def test_config_queue_and_generic_private_names_no_retry_override(self):
        config = P.config_bytes("http://127.0.0.1:1234/", "a" * 64, "b" * 64)
        self.assertEqual(config, ("[Synthetic]\ntype = swift\nenv_auth = false\nuser = " + "a"*64 + "\nkey = " + "b"*64 + "\nauth = http://127.0.0.1:1234/auth/v1.0\nauth_version = 1\nendpoint_type = public\nno_large_objects = true\n").encode())
        self.assertIn(b"synthetic-bucket/README-synthetic.txt,62,", P.queue_bytes())
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
            self.assertEqual(order, ["arm", "first_get", "verify", "replacement_get"] if name == "token_replacement" else ["arm", "first_get", "verify", "renewal_auth"])

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
                state = P.F.AppSwiftState("token_replacement", "a"*64, "b"*64)
                server = Mock(endpoint="invalid" if phase == "config" else "http://127.0.0.1:1234/",
                    deadline=P.time.monotonic()+(-1 if phase == "budget" else 60))
                server.transport_snapshot.return_value = dict(accepted=0, cleanup_complete=True, active=0, workers_alive=0,
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
                        (P.F,"AppSwiftState",lambda *a:state),(P.F,"serve_swift",lambda s:context)):
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
                self.assertEqual(r["cases"]["renewal_denial"]["status"],"not_run")
                self.assertEqual([p["action"] for p in bridge.packets],["ready","close_ready"])
                self.assertEqual(len(removed),2); self.assertIn("acquisition",removed)
                self.assertNotIn("passed",r["capabilities"].values())

    def test_rejection_storm_writes_valid_failed_receipt_instead_of_empty_file(self):
        state=P.F.AppSwiftState("token_replacement","a"*64,"b"*64)
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
                        (P.F, "AppSwiftState", lambda *a: state), (P.F, "serve_swift", lambda s: context)):
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
        cause = "failed to open source object: Operation forbidden"
        good = "2026/10/12 12:00:00 NOTICE: Failed to rc: loopback: call failed: " + cause
        self.assertTrue(P.W.exact_rc_error(good, cause))
        for bad in ("exit 1", good.replace("Operation forbidden", "Authorization Failed"), good.replace("Operation forbidden", "forbidden"), good + "\nunknown", good.replace("failed to open source object: ", "")):
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
                error=None if positive else "2026/10/12 12:00:00 NOTICE: Failed to rc: loopback: call failed: failed to open source object: Operation forbidden",
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
                if mutation == "cause": value["results"][0]["error"] = value["results"][0]["error"].replace("Operation forbidden", "Authorization Failed")
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



def cancel_snapshot(action="poll", finished=False):
    value=dict(schema_version=1,action=action,ok=True,state="finished" if finished else "running",
        app_exit_code=1 if finished else None,runtime_image_observed=True,runtime_sha256=RUNTIME["sha256"],
        runtime_process_count=1,ctrl_c_sent=action=="ctrl_c" or finished,output_bytes=0,output_limit_exceeded=False,
        forced_termination=False,errors=[])
    value.update(dict.fromkeys(P.H.SESSION_CLEANUP,finished))
    return value


class CancellationProducerTests(unittest.TestCase):
    def setUp(self):
        for obj,name in ((subprocess,"Popen"),(socket,"socket"),(socket,"create_connection"),(threading.Thread,"start")):
            guard=patch.object(obj,name,side_effect=AssertionError("forbidden"));guard.start();self.addCleanup(guard.stop)

    def test_queue_literal_and_no_retry_rate_or_buffer_options(self):
        import csv,io
        rows=list(csv.reader(io.StringIO(P.cancellation_queue_bytes().decode("utf-8-sig"))))
        self.assertEqual(rows[1],["excel-safe-v1","Synthetic","synthetic-bucket/large/cancel.bin","262144",
            "2024-01-01T00:00:00+00:00","false","2312394bd99545d9de131c24efb781e765ac1aec243f2ed9347597a793a415e9","sha256"])
        self.assertEqual(len(rows),2)
        args=P.H.app_args("acquisition",Path("synthetic"))
        self.assertFalse(any(any(word in a for word in ("retry","buffer","bytes-per-second")) for a in args))

    def test_partial_inventory_rejects_unknown_extra_staging_and_missing_ancestor(self):
        case=Path("synthetic");stage="Synthetic/synthetic-bucket/large/.triage-transfer-"+"a"*32
        dirs=["Synthetic","Synthetic/synthetic-bucket","Synthetic/synthetic-bucket/large",stage]
        leaf=stage+"/payload.1234abcd.partial"
        inv={n:(True,0,1,2) for n in dirs};inv[leaf]=(False,65536,3,4)
        with patch.object(P.H,"identity",return_value=(1,2)),patch.object(Path,"exists",return_value=True):
            for broken in (None,"extra_stage","missing","unknown","wrong_leaf","file_dir"):
                value=dict(inv)
                if broken=="extra_stage":value[stage[:-1]+"b"]=(True,0,1,2)
                if broken=="missing":del value[dirs[1]]
                if broken=="unknown":value["unknown"]=(True,0,1,2)
                if broken=="wrong_leaf":value[leaf+"x"]=value.pop(leaf)
                if broken=="file_dir":value[dirs[0]]=(False,0,1,2)
                with patch.object(P.H,"inventory",return_value=value):
                    if broken is None:self.assertEqual(P.cancellation_partial(case,(1,2)),(leaf,(3,4)))
                    else:
                        with self.assertRaises(P.ProducerError):P.cancellation_partial(case,(1,2))
            for count in range(5):
                with patch.object(P.H,"inventory",return_value={n:inv[n] for n in dirs[:count]}):self.assertIsNone(P.cancellation_partial(case,(1,2)))
            no_leaf={n:inv[n] for n in dirs};no_leaf[stage[:-1]+"b"]=(True,0,1,2)
            with patch.object(P.H,"inventory",return_value=no_leaf):
                with self.assertRaises(P.ProducerError):P.cancellation_partial(case,(1,2))

    def test_content_not_length_and_short_growth_pending(self):
        import io
        block=bytes(range(256))*256
        for data,before,after,want in ((b"\0"*262144,262144,262144,0),(block,65536,65536,65536),
                (block*2,131072,131072,131072),(block*2+b"\0"*65536,262144,262144,131072),
                (block[:300],65536,65536,None),(block,65536,131072,None)):
            w=P.CancellationWitness.__new__(P.CancellationWitness);w.stream=io.BytesIO(data);w.verify=Mock(side_effect=[before,after])
            self.assertEqual(w.sample(),want)
        w=P.CancellationWitness.__new__(P.CancellationWitness);w.stream=io.BytesIO(block*4);w.verify=Mock(return_value=262144)
        with self.assertRaises(P.ProducerError):w.sample()

    def test_retained_identity_parent_leaf_hardlink_and_sticky_close(self):
        from types import SimpleNamespace
        w=P.CancellationWitness.__new__(P.CancellationWitness);w.case=Path("case");w.lease=(1,2);w.parents=[Path("parent")]
        w.identities=[(1,2)];w.selected=("leaf",(3,4));w.path=Path("leaf");w.stream=Mock()
        for broken in (None,"parent","leaf","handle","links","reparse","size"):
            info=SimpleNamespace(st_mode=0o100600,st_nlink=2 if broken=="links" else 1,
                st_file_attributes=0x400 if broken=="reparse" else 0,st_dev=3,st_ino=5 if broken=="handle" else 4,
                st_size=262145 if broken=="size" else 65536)
            named=SimpleNamespace(st_dev=3,st_ino=5 if broken=="leaf" else 4,st_size=65536)
            with patch.object(P.H,"identity",return_value=(9,9) if broken=="parent" else (1,2)), \
                    patch.object(P,"cancellation_partial",return_value=w.selected),patch.object(P.H,"plain",return_value=named),patch.object(P.os,"fstat",return_value=info):
                if broken is None:self.assertEqual(w.verify(),65536)
                else:
                    with self.assertRaises(P.ProducerError):w.verify()
        w.close_attempted=False;w.cleanup=dict(closed=False,failed=False);w.stream.close.side_effect=OSError("private canary")
        for _ in range(2):
            with self.assertRaises(P.ProducerError):w.close()
        self.assertEqual(w.stream.close.call_count,1);self.assertEqual(w.cleanup,dict(closed=False,failed=True))

    def transfer(self, *, broken=None):
        order=[];clock=[0.0];cleanup=dict(closed=False,failed=False);state=Mock();state.snapshot.return_value={"errors":[]}
        state.cancel_snapshot.side_effect=[dict(chunks=0),dict(chunks=1),dict(chunks=2)]
        state.release_prefix.side_effect=lambda:order.append("release_prefix")
        state.arm_cancel.side_effect=lambda:order.append("arm_cancel")
        witness=Mock();witness.sample.side_effect=[65536,65536,131072]
        def sample():
            order.append("sample")
            if broken=="late_sample":clock[0]=101
            return next(samples)
        samples=iter([65536,65536,131072]);witness.sample.side_effect=sample
        def close():
            order.append("close")
            if broken=="close":cleanup["failed"]=True;raise P.ProducerError("cleanup_failed")
            cleanup["closed"]=True
            if broken=="late_close":clock[0]=101
        witness.close.side_effect=close
        calls=[]
        def command(action,**fields):
            order.append(action);calls.append(action);value=cancel_snapshot(action)
            if broken=="app_exit" and action=="poll":value.update(app_exited=True,app_exit_code=0)
            if broken=="late_poll" and action=="poll":clock[0]=101
            if broken=="late_live" and action=="observe_runtime":clock[0]=101
            if broken=="wrong_live" and action=="observe_runtime":value["runtime_sha256"]="f"*64
            if action=="ctrl_c":
                if broken=="late_ctrl_c":clock[0]=101
                if broken=="no_signal":value["ctrl_c_sent"]=False
                if broken=="force":value["forced_termination"]=True
            return value
        bridge=Mock();bridge.command.side_effect=command
        with patch.object(P,"cancellation_partial",return_value=("leaf",(3,4))),patch.object(P,"CancellationWitness",return_value=witness), \
                patch.object(P.time,"monotonic",side_effect=lambda:clock[0]),patch.object(P.time,"sleep",side_effect=lambda _:None):
            if broken:
                with self.assertRaises(P.ProducerError):P.cancellation_transfer(bridge,Path("case"),(1,2),RUNTIME,state,100,cleanup)
            else:
                observation,_=P.cancellation_transfer(bridge,Path("case"),(1,2),RUNTIME,state,100,cleanup)
                P.E.cancellation_observation(observation)
                self.assertEqual(witness.sample.call_count,3) # Send-return commit lag did not reset or earn content credit.
                self.assertLess(order.index("close"),order.index("arm_cancel"));self.assertLess(order.index("arm_cancel"),order.index("ctrl_c"))
                self.assertEqual(calls.count("observe_runtime"),2);self.assertEqual(calls.count("ctrl_c"),1)
            self.assertLessEqual(calls.count("ctrl_c"),1)
            if broken in {"app_exit","late_poll","late_live","wrong_live","late_sample","close","late_close"}:self.assertNotIn("ctrl_c",calls)

    def test_transfer_commit_race_content_and_signal_order(self):self.transfer()

    def test_late_steps_wrong_image_exit_close_and_failed_signal_cannot_pass(self):
        for broken in ("app_exit","late_poll","late_live","wrong_live","late_sample","close","late_close","late_ctrl_c","no_signal","force"):
            with self.subTest(broken=broken):self.transfer(broken=broken)

    def test_final_session_and_cleanup_require_actual_closed_proof(self):
        good=cancel_snapshot("finish",True)
        P.cancellation_final(good,RUNTIME)
        for key in (*P.H.SESSION_CLEANUP,"ctrl_c_sent","runtime_image_observed"):
            value=dict(good);value[key]=False
            with self.assertRaises(P.ProducerError):P.cancellation_final(value,RUNTIME)
        for value in (dict(good,forced_termination=True),dict(good,runtime_process_count=2),dict(good,output_limit_exceeded=True)):
            with self.assertRaises(P.ProducerError):P.cancellation_final(value,RUNTIME)
        for broken in (None,"close","reader","force_cleanup"):
            b=Mock();b.close.return_value=broken!="close";b.last=dict(good)
            if broken=="reader":b.last["reader_joined"]=False
            if broken=="force_cleanup":b.last.update(ok=False,errors=["termination_failed"])
            self.assertEqual(P.close_cancellation_session(b,True,True),broken is None)
            b.close.assert_called_once()
        b=Mock();b.command.return_value=dict(schema_version=1,action="close_ready",ok=True,state="closed");b.close.return_value=True
        self.assertTrue(P.close_cancellation_session(b,True,False));b.command.assert_called_once_with("close_ready")

    def test_manifest_requires_cancelled_null_fields_and_no_partial_or_final_output(self):
        case=Path("synthetic");base=case/"output"/P.H.CASE_NAME;working=base/"config/working.conf";f=P.E.cancellation_manifest()
        destination=base/"downloads/Synthetic"/f["member"];stem="acquisition-20261012T120000.000"
        request=dict(source="Synthetic:"+f["member"],destination=str(destination),mode="CopyTo",expected_size=262144,expected_hash=f["sha256"],expected_hash_type="sha256")
        result=dict(source=request["source"],destination=str(destination),success=False,integrity="Cancelled",error="Cancelled",
            **dict.fromkeys(("local_sha256","size","hash","hash_type","hash_verified","hash_error")))
        good=dict(schema_version=1,written_at="2026-10-12T12:00:00Z",rclone_version=RUNTIME["version"],config_path=str(working),complete=False,
            plan=dict(files=[dict(remote_name="Synthetic",path=f["member"],request=request)],skipped_directories=0),results=[result])
        inv={d:(True,) for d in ("logs","downloads","listings","config")}
        inv.update({n:(False,) for n in (stem+".json",stem+".txt","logs/"+stem+".log","logs/"+stem+".checkpoint.json","config/working.conf","config/source.conf")})
        for broken in (None,"success","integrity","hash","size","complete","partial","payload","source"):
            value=deepcopy(good);entries=dict(inv);outputs={}
            if broken=="success":value["results"][0]["success"]=True
            if broken=="integrity":value["results"][0]["integrity"]="Failed"
            if broken in {"hash","size"}:value["results"][0][broken]=1
            if broken=="complete":value["complete"]=True
            if broken=="partial":entries["downloads/Synthetic/.triage-transfer-x/payload.partial"]=(False,)
            if broken=="payload":outputs={"Synthetic/"+f["member"]:()}
            if broken=="source":value["plan"]["files"][0]["request"]["source"]="other"
            outer={P.H.CASE_NAME:(True,),**{P.H.CASE_NAME+"/"+n:r for n,r in entries.items()}}
            with patch.object(P.H,"inventory",side_effect=lambda path:entries if path==base else outer),patch.object(P.H,"read",return_value=json.dumps(value).encode()), \
                    patch.object(P.H,"same_path",side_effect=lambda a,b:str(a)==str(b)),patch.object(P.H,"output_files",return_value=outputs):
                if broken is None:self.assertTrue(all(P.cancellation_manifest(case,working,RUNTIME).values()))
                else:
                    with self.assertRaises(P.ProducerError):P.cancellation_manifest(case,working,RUNTIME)

    def test_actual_execute_orchestration_ordinary_bridge_and_cleanup_failures(self):
        for broken in (None, "helper_cleanup", "fixture_cleanup", "verify"):
            with tempfile.TemporaryDirectory() as directory, ExitStack() as mocks:
                suite=Path(directory);app=suite/"input.bin";app.write_bytes(b"inert")
                sha=P.H.sha(b"inert");order=[];bridge=Mock();bridge.last=None;bridge.close.return_value=True
                def command(action, **fields):
                    order.append((action,fields))
                    bridge.last=(dict(schema_version=1,action="ready",state="ready",ok=True) if action=="ready" else
                        cancel_snapshot(action,action=="poll"))
                    return bridge.last
                bridge.command.side_effect=command
                state=Mock();state.snapshot.return_value=TEST.cancellation_receipt()["cases"]["cancellation"]["fixture"]
                server=Mock(endpoint="http://127.0.0.1:1234/",deadline=P.time.monotonic()+60)
                context=Mock();context.__enter__=Mock(side_effect=lambda:(order.append(("fixture",{})),server)[1]);context.__exit__=Mock()
                if broken=="fixture_cleanup":context.__exit__.side_effect=P.ProducerError("cleanup_failed")
                def prepare(parent,child,action="Create"):
                    if action=="Create":(parent/child).mkdir()
                    elif broken=="verify":raise P.ProducerError("cleanup_failed")
                def source(case):(case/"source").mkdir();return P.H.identity(case/"source")
                def transfer(b,*args):return (dict(kind="live_image",runtime_process_count=1,first_verified_bytes=65536,last_verified_bytes=131072),b.command("ctrl_c"))
                for obj,key,value in ((P.H,"prepare",prepare),(P.H,"create_private_roots",lambda c:{}),
                        (P.H,"private_directory",lambda c,n:(c/n).mkdir()),(P.H,"private_write",lambda c,n,b:(c/n).write_bytes(b)),
                        (P.H,"environment",lambda c:{}),(P,"create_source",source),(P.C,"SourceBridge",lambda c:bridge),
                        (P.H,"application_roots_empty",Mock()),(P.H,"helper_baseline",lambda *a:{}),
                        (P.H,"helper_cleanup_preserved",Mock(side_effect=P.ProducerError("cleanup_failed") if broken=="helper_cleanup" else None)),
                        (P.H,"configuration_preserved",lambda c,v:c/"working.conf"),(P,"cancellation_transfer",transfer),
                        (P,"cancellation_manifest",lambda *a:dict.fromkeys(("manifest_exact","cancelled_result_exact","manifest_incomplete","no_partial_outputs","no_download_outputs"),True)),
                        (P.W,"fingerprint",lambda c:"a"*64),(P,"cancellation_preserved",Mock()),(P.H,"remove_owned",Mock()),
                        (P,"fixture_closed",lambda s:broken!="fixture_cleanup"),(P.F,"AppSwiftCancellationState",lambda *a:state),
                        (P.F,"serve_swift_cancellation",lambda s:context)):
                    mocks.enter_context(patch.object(obj,key,value))
                with patch.object(P.C,"ObservedSourceBridge",side_effect=AssertionError("wrong mode")):
                    errors=[];item=P.execute_cancellation("cancellation",suite,app,sha,RUNTIME,errors)
                self.assertEqual(item["record"]["exit_code"],1)
                self.assertEqual(errors,[] if broken is None else ["cleanup_failed"])
                self.assertEqual(item["record"]["checks"]["temp_cleanup"],broken is None)
                starts=[fields for action,fields in order if action=="start_source"]
                self.assertEqual(len(starts),1);self.assertNotIn("max_runtime_launches",starts[0]);self.assertNotIn("expected_runtime_sha256",starts[0])
                self.assertLessEqual(starts[0]["deadline_ms"],60000)
                self.assertLess([a for a,_ in order].index("ready"),[a for a,_ in order].index("fixture"))
                context.__exit__.assert_called_once();bridge.close.assert_called_once()

    def test_cancellation_input_and_saved_artifact_preservation(self):
        case=Path("synthetic");config=b"inert config"
        item=dict(case=case,lease=(1,2),source=(2,3),config=config,artifact="a"*64,record=dict(checks=dict(configuration_preserved=True)))
        for broken in (None,"config","queue","app","artifact","source","identity"):
            def read(path,*args):
                if path.name=="application.exe":return b"changed" if broken=="app" else b"app"
                if path.name=="source.conf":return b"changed" if broken=="config" else config
                return b"changed" if broken=="queue" else P.cancellation_queue_bytes()
            with patch.object(P.H,"identity",side_effect=lambda path:(0,0) if broken=="identity" else item["lease"] if path==case else item["source"]), \
                    patch.object(P.H,"inventory",return_value={"extra":()} if broken=="source" else {}),patch.object(P.H,"read",side_effect=read), \
                    patch.object(P.H,"configuration_preserved"),patch.object(P.W,"fingerprint",return_value="b"*64 if broken=="artifact" else "a"*64):
                if broken is None:P.cancellation_preserved(item,P.H.sha(b"app"))
                else:
                    with self.assertRaises(P.ProducerError):P.cancellation_preserved(item,P.H.sha(b"app"))

    def test_one_case_group_late_binding_failure_and_cleanup_cannot_grant_pass(self):
        for broken in (None,"binding","fixture","process","temp"):
            calls=[]
            def execute(name,*args):
                calls.append(name);row=deepcopy(TEST.cancellation_receipt()["cases"][name]);row["status"]="failed";row["checks"]["group_finalized"]=False
                if broken in {"fixture","process","temp"}:
                    row["checks"][broken+"_cleanup"]=False
                    row["checks"]["temp_cleanup"]=False  # Actual execute never removes a tree without the other cleanup proofs.
                    P.mark(row,"cleanup_failed",args[-1])
                return dict(name=name,record=row,artifact="a"*64)
            with ExitStack() as mocks:
                for obj,key,value in ((P.H,"hosted_guard",Mock()),(P.E,"runtime_binding",lambda r:RUNTIME),
                        (P.E,"compute_cancellation_bindings",lambda *a:TEST.BINDINGS),(P.H,"prepare",Mock()),(P.H,"identity",lambda p:(1,2)),
                        (P.H,"inventory",lambda p:{}),(P.H,"remove_owned",Mock()),(P,"execute_cancellation",execute)):
                    mocks.enter_context(patch.object(obj,key,value))
                mocks.enter_context(patch.dict(P.os.environ,{"RUNNER_TEMP":str(Path.cwd()),"GITHUB_SHA":TEST.BINDINGS["build_commit"]}))
                mocks.enter_context(patch.object(P,"cancellation_bindings",side_effect=[TEST.BINDINGS,P.ProducerError("preservation_failed") if broken=="binding" else TEST.BINDINGS]))
                r=P.run_cancellation("not-read",TEST.BINDINGS["application_sha256"],TEST.BINDINGS["build_commit"])
                self.assertEqual(calls,["cancellation"]);self.assertEqual(r["result"],"passed" if broken is None else "failed")
                if broken:self.assertNotIn("passed",r["capabilities"].values())



def listing_snapshot(action="finish", running=False):
    value = dict(schema_version=1, action=action, ok=True, state="running" if running else "finished",
        app_exit_code=None if running else 0, runtime_image_observed=True, runtime_sha256=RUNTIME["sha256"],
        runtime_process_count=1, ctrl_c_sent=False, output_bytes=0, output_limit_exceeded=False, forced_termination=False, errors=[])
    value.update(dict.fromkeys(P.H.SESSION_CLEANUP, not running))
    return value


class ListingProducerTests(unittest.TestCase):
    setUp = ProducerTests.setUp

    def test_final_visible_head_waits_for_returned_send_commit(self):
        for returned_before_wait in (False, True):
            state = P.F.AppSwiftListingState("a" * 64, "b" * 64)
            token = None
            targets = [P.F.AUTH, P.F.ACCOUNT + "?format=json&limit=10000",
                P.F.LIST_CONTAINER + "?delimiter=%2F&format=json&limit=1000"]
            targets += [P.F.LIST_CONTAINER + "/" + name.replace(" ", "%20") for name, _ in P.F.LIST_FILES]
            for index, target in enumerate(targets):
                request = state.begin("HEAD" if index >= 3 else "GET", target,
                    "a" * 64 if index == 0 else None, "b" * 64 if index == 0 else None, token)
                if index == 0: state.release_gate("listing_auth")
                reply = state.response(request, "http://127.0.0.1:1234")
                if index < 5:
                    state.commit(request, reply[0], 256, reply[3])
                    if index == 0: token = request[3]
            # Schedule: the peer has received the final HEAD and exited. Its
            # worker resumes either in sendall or immediately after its return.
            schedule = dict(peer_exited=True, send_returned=returned_before_wait, committed=False)
            def resume_worker(seconds):
                self.assertLessEqual(seconds, 0.02)
                self.assertTrue(schedule["peer_exited"])
                self.assertFalse(state.completed)
                schedule["send_returned"] = True
                state.commit(request, reply[0], 256, reply[3])
                schedule["committed"] = True
            with patch.object(P.time, "monotonic", return_value=1), patch.object(P.time, "sleep", side_effect=resume_worker) as sleep:
                P.listing_committed(state, 10)
            sleep.assert_called_once(); self.assertTrue(schedule["committed"])
            self.assertTrue(state.completed); P.E.listing_fixture(state.snapshot(), successful=True)

    def test_commit_wait_failed_send_source_error_and_expiry_never_succeed(self):
        complete = TEST.listing_receipt()["cases"]["listing"]["fixture"]
        partial = deepcopy(complete); partial["events"].pop()
        for broken in ("send", "source", "malformed"):
            value = deepcopy(partial)
            if broken == "send": value["errors"] = ["connection_failed"]
            elif broken == "source": value["source_preserved"] = False
            else: value["events"][0]["kind"] = "private canary"
            with patch.object(P.time, "monotonic", return_value=1), patch.object(P.time, "sleep") as sleep:
                with self.assertRaises(Exception): P.listing_committed(Mock(snapshot=Mock(return_value=value)), 10)
                sleep.assert_not_called()
        now = [1.0]
        def expire(seconds):
            self.assertLessEqual(seconds, 0.02); now[0] = 10
        state = Mock(snapshot=Mock(return_value=partial))
        with patch.object(P.time, "monotonic", side_effect=lambda: now[0]), patch.object(P.time, "sleep", side_effect=expire):
            with self.assertRaisesRegex(P.ProducerError, "deadline_exceeded"): P.listing_committed(state, 10)
        state.snapshot.assert_called_once()
        with patch.object(P.time, "monotonic", side_effect=[1, 10]), patch.object(P.time, "sleep") as sleep:
            with self.assertRaisesRegex(P.ProducerError, "deadline_exceeded"):
                P.listing_committed(Mock(snapshot=Mock(return_value=complete)), 10)
            sleep.assert_not_called()

    def test_export_parser_requires_exact_inventory_and_canonical_names(self):
        import csv, io
        def wire(rows):
            stream=io.StringIO(newline=""); csv.writer(stream,lineterminator="\r\n").writerows(rows)
            return b"\xef\xbb\xbf"+stream.getvalue().encode()
        rows=[P.H.HEADERS]+P.E.listing_rows(); body=wire(rows)
        self.assertTrue(P.listing_csv(body)); self.assertTrue(P.listing_csv(wire([rows[0]]+list(reversed(rows[1:])))))
        mutations=[rows[:-1],rows+[rows[-1]],rows[1:],rows[:1]+rows[2:]]
        for column,bad in ((0,"plain"),(1,"Other"),(2,"'synthetic-bucket/empty.txt"),(2,"synthetic-bucket/./empty.txt"),
                           (3,"00"),(4,"2025-01-01T00:00:00+00:00"),(5,"true"),(6,"d41d8cd98f00b204e9800998ecf8427e"),(7,"MD5")):
            changed=deepcopy(rows); changed[3][column]=bad; mutations.append(changed)
        for changed in mutations:
            with self.assertRaises(P.ProducerError): P.listing_csv(wire(changed))
        for bad in (body[3:],b"\xef\xbb\xbf\xff",b"x"*16385):
            with self.assertRaises(P.ProducerError): P.listing_csv(bad)

    def test_live_runtime_observation_precedes_gate_release_and_expiry_rejects(self):
        state=Mock(errors=[]); state.gate_snapshot.return_value={"listing_auth":dict(entered=1,released=False)}
        bridge=Mock(); bridge.command.return_value=listing_snapshot("observe_runtime",True)
        with patch.object(P.time,"monotonic",return_value=1):
            self.assertEqual(P.listing_live(bridge,Path("case"),state,RUNTIME,10),dict(kind="live_image",runtime_process_count=1))
        state.release_gate.assert_called_once_with("listing_auth")
        changes=[dict(app_exited=True,app_exit_code=0),dict(runtime_sha256="f"*64),dict(runtime_process_count=2),
                 dict(runtime_image_observed=False),dict(forced_termination=True),dict(output_limit_exceeded=True)]
        for change in changes:
            state.release_gate.reset_mock(); bridge.command.return_value=dict(listing_snapshot("observe_runtime",True),**change)
            with patch.object(P.time,"monotonic",return_value=1),self.assertRaises(P.ProducerError):
                P.listing_live(bridge,Path("case"),state,RUNTIME,10)
            state.release_gate.assert_not_called()
        state.release_gate.reset_mock(); bridge.command.return_value=listing_snapshot("observe_runtime",True)
        with patch.object(P.time,"monotonic",side_effect=[1,11]),self.assertRaises(P.ProducerError):
            P.listing_live(bridge,Path("case"),state,RUNTIME,10)
        state.release_gate.assert_not_called()

    def test_all_session_cleanup_flags_and_ready_start_ownership(self):
        bridge=Mock(last=listing_snapshot()); bridge.close.return_value=True
        self.assertTrue(P.listing_close_session(bridge,True,True)); bridge.close.assert_called_once()
        for key in P.H.SESSION_CLEANUP:
            bridge=Mock(last=dict(listing_snapshot(),**{key:False})); bridge.close.return_value=True
            self.assertFalse(P.listing_close_session(bridge,True,True)); bridge.close.assert_called_once()
        bridge=Mock(last=listing_snapshot()); bridge.close.return_value=False
        self.assertFalse(P.listing_close_session(bridge,True,True))
        bridge=Mock(); bridge.close.return_value=True
        bridge.command.return_value=dict(schema_version=1,action="close_ready",ok=True,state="closed")
        self.assertTrue(P.listing_close_session(bridge,True,False)); bridge.command.assert_called_once_with("close_ready")
        bridge.command.side_effect=KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt): P.listing_close_session(bridge,True,False)
        self.assertEqual(bridge.close.call_count,2)

    def execute_fake(self, fault=None):
        calls=[]; case=Path("synthetic-suite/listing"); state=Mock(errors=[])
        state.snapshot.return_value=TEST.listing_receipt()["cases"]["listing"]["fixture"]
        server=Mock(endpoint="http://127.0.0.1:1234/",deadline=170)
        server.transport_snapshot.return_value=dict(accepted=6,active=0,workers_alive=0,watchdog_alive=False,acceptor_alive=False,cleanup_complete=True)
        state._transport=server
        context=Mock(); context.__enter__=Mock(return_value=server); context.__exit__=Mock()
        if fault=="commit_delayed":
            complete=deepcopy(state.snapshot.return_value); pending=deepcopy(complete); pending["events"].pop()
            state.snapshot.return_value=pending
            def resumed(seconds):
                calls.append(("commit", "listing")); state.snapshot.return_value=complete
            def close_fixture(*args):
                self.assertIn(("commit", "listing"),calls); calls.append(("fixture_close", "listing"))
            context.__exit__.side_effect=close_fixture
        bridge=Mock(last=listing_snapshot())
        def command(action,**fields):
            calls.append((action,fields))
            if action=="ready": return dict(schema_version=1,action="ready",ok=True,state="ready")
            bridge.last=listing_snapshot(action, action=="start")
            if fault=="exit" and action=="poll": bridge.last["app_exit_code"]=1
            return bridge.last
        bridge.command.side_effect=command; bridge.close.return_value=True
        def prepare(parent,name,action="Create"):
            calls.append((action,name))
            if fault=="verify" and action=="Verify": raise P.ProducerError("cleanup_failed")
        patches=[(P.time,"monotonic",lambda:1),(P.H,"prepare",prepare),(P.H,"identity",lambda p:(1,2)),
            (P.H,"create_private_roots",lambda p:{}),(P.H,"private_directory",Mock()),(P,"create_source",lambda p:(1,3)),
            (P.H,"read",lambda *a,**k:b"inert"),(P.H,"private_write",lambda p,n,b:calls.append(("write",n))),
            (P.H,"Bridge",lambda c:bridge),(P.H,"application_roots_empty",Mock()),(P.H,"helper_baseline",lambda *a:{}),
            (P.F,"AppSwiftListingState",lambda *a:state),(P.F,"serve_swift_listing",lambda s:context),
            (P,"listing_live",Mock(return_value=dict(kind="live_image",runtime_process_count=1))),
            (P.H,"configuration_preserved",Mock(return_value="working")),
            (P,"listing_output",Mock(return_value=dict.fromkeys(("inventory_exact","listing_complete","outputs_exact","no_download_outputs"),True))),
            (P.W,"fingerprint",Mock(return_value={"artifact":"inert"})),(P,"listing_preserved",Mock()),
            (P.H,"helper_cleanup_preserved",Mock()),(P.H,"remove_owned",lambda *a:calls.append(("remove","listing")))]
        if fault=="fixture_close": context.__exit__.side_effect=OSError("private canary")
        if fault=="fixture_active": server.transport_snapshot.return_value["active"]=1
        if fault=="session_close": bridge.close.return_value=False
        if fault=="fixture_error": state.snapshot.return_value["errors"]=["request_timeout"]
        with ExitStack() as mocks:
            for obj,key,value in patches: mocks.enter_context(patch.object(obj,key,value))
            if fault=="commit_delayed": mocks.enter_context(patch.object(P.time,"sleep",side_effect=resumed))
            if fault in {"output","preservation","live"}:
                name={"output":"listing_output","preservation":"listing_preserved","live":"listing_live"}[fault]
                mocks.enter_context(patch.object(P,name,side_effect=P.ProducerError("listing_invalid" if fault=="output" else "preservation_failed")))
            errors=[]; item=P.execute_listing("listing",case.parent,Path("inert.bin"),P.H.sha(b"inert"),RUNTIME,errors)
        return item,errors,calls

    def test_full_fake_listing_control_flow_and_no_queue_or_content_action(self):
        item,errors,calls=self.execute_fake()
        self.assertFalse(errors); checks=item["record"]["checks"]
        self.assertTrue(all(v for k,v in checks.items() if k!="group_finalized"))
        start=[v for k,v in calls if k=="start"]
        self.assertEqual(len(start),1); self.assertIn("--list-remote",start[0]["args"])
        self.assertNotIn("--download",start[0]["args"]); self.assertNotIn(("write","queue.csv"),calls)
        self.assertIn(("Verify","listing"),calls); self.assertIn(("remove","listing"),calls)

    def test_final_commit_precedes_fixture_teardown_after_successful_exit(self):
        item,errors,calls=self.execute_fake("commit_delayed")
        self.assertFalse(errors)
        self.assertTrue(all(v for k,v in item["record"]["checks"].items() if k!="group_finalized"))
        poll=next(i for i,(action,_) in enumerate(calls) if action=="poll")
        self.assertLess(poll,calls.index(("commit","listing")))
        self.assertLess(calls.index(("commit","listing")),calls.index(("fixture_close","listing")))

    def test_late_failures_remain_failed_and_uncertain_ownership_blocks_removal(self):
        for fault in ("exit","live","output","preservation","fixture_close","fixture_active","fixture_error","session_close","verify"):
            item,errors,calls=self.execute_fake(fault)
            self.assertTrue(errors,fault); self.assertEqual(item["record"]["status"],"failed")
            self.assertFalse(item["record"]["checks"]["group_finalized"])
            if fault in {"preservation","fixture_active","session_close","verify"}: self.assertNotIn(("remove","listing"),calls)
            self.assertNotIn("private canary",json.dumps(item["record"]))

    def test_group_requires_complete_case_and_post_suite_cleanup(self):
        for broken in (None,"temp_cleanup","configuration_preserved","suite_verify"):
            row=deepcopy(TEST.listing_receipt()["cases"]["listing"]); row.update(status="failed",failure_code=None)
            row["checks"]["group_finalized"]=False
            if broken in row["checks"]: row["checks"][broken]=False
            item=dict(record=row,artifact={"fixed":True})
            def prepare(*args):
                if broken=="suite_verify" and args[-1]=="Verify": raise P.ProducerError("cleanup_failed")
            with ExitStack() as stack:
                for obj,key,value in ((P.H,"hosted_guard",Mock()),(P.E,"runtime_binding",lambda *a:RUNTIME),
                    (P.E,"compute_listing_bindings",lambda *a:TEST.BINDINGS),(P,"listing_bindings",lambda *a:TEST.BINDINGS),
                    (P.H,"prepare",prepare),(P.H,"identity",lambda *a:(1,2)),(P.H,"inventory",lambda *a:{}),
                    (P.H,"remove_owned",Mock()),(P,"execute_listing",lambda *a:item)):
                    stack.enter_context(patch.object(obj,key,value))
                stack.enter_context(patch.dict(P.os.environ,{"GITHUB_SHA":TEST.BINDINGS["build_commit"],"RUNNER_TEMP":"synthetic-parent"}))
                result=P.run_listing("inert",TEST.BINDINGS["application_sha256"],TEST.BINDINGS["build_commit"])
            self.assertEqual(result["result"],"passed" if broken is None else "failed")
            self.assertFalse(any(result["claims"].values()))

    def test_host_guard_and_cli_exclusivity_before_work(self):
        with patch.object(P.H,"hosted_guard",side_effect=P.ProducerError("binding_failed")),patch.object(P.E,"compute_listing_bindings") as bind:
            with self.assertRaises(P.ProducerError): P.run_listing("unused","0"*64,"1"*40)
            bind.assert_not_called()
        with patch.object(P.H,"hosted_guard") as guard:
            with self.assertRaises(SystemExit) as error:
                P.main(["--application","unused","--application-sha256","unused","--build-commit","unused","--report","unused","--listing-only","--cancellation-only"])
            self.assertEqual(error.exception.code,2); guard.assert_not_called()


if __name__ == "__main__": unittest.main()
