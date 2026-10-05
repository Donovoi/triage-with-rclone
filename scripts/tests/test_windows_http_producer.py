"""Offline producer tests. No application, helper, runtime or listener executes."""
import copy
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "scripts/application-lab/run_windows_http.py"
SPEC = importlib.util.spec_from_file_location("application_producer_test", SOURCE)
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
RUNTIME = {"version": "1.75.1", "sha256": "a" * 64, "platform": "windows"}
BODIES = {"README-synthetic.txt": b"synthetic application fixture\n",
          "large/cancel.bin": bytes(range(256)) * 8192,
          "nested/binary.bin": bytes(range(256)), "nested/spaced name.txt": b"spaces remain exact\n"}
HEADER = ["path_encoding", "remote", "path", "size", "modified", "is_dir", "hash", "hash_type"]


def dump(path, value):
    path.write_bytes(json.dumps(value, separators=(",", ":")).encode())


def session(action, *, final=False, observed=True, cancelled=False, exit_code=0):
    return {"schema_version": 1, "action": action, "ok": True,
        "state": "finished" if final else "running", "app_exit_code": exit_code if final else None,
        "runtime_image_observed": observed, "runtime_sha256": RUNTIME["sha256"] if observed else None,
        "ctrl_c_sent": cancelled, "output_bytes": 500, "output_limit_exceeded": False,
        "forced_termination": False, "app_exited": final, "observed_children_exited": final,
        "job_zero_confirmed": final, "reader_joined": final, "conpty_closed": final, "errors": []}


def fake_prepare(parent, name, action="Create"):
    path = Path(parent) / name
    if action == "Create":
        path.mkdir()
    else:
        assert path.is_dir()
    return path


def materialize(case, name):
    """Independent literal application artifact shapes, not producer builders."""
    base = case / "output/synthetic-case"
    for part in ("logs", "downloads", "listings", "config"):
        (base / part).mkdir(parents=True, exist_ok=True)
    config = base / "config/working-SYNTHETIC.conf"
    original = (case / "source.conf").read_bytes()
    config.write_bytes(original)
    dump(config.with_suffix(".provenance.json"), {
        "schema_version": 1, "source_path": str(case / "source.conf"),
        "source_sha256": hashlib.sha256(original).hexdigest(), "working_path": str(config),
        "snapshotted_at": "2026-01-01T00:00:00Z"})
    if name == "listing":
        out = io.StringIO(newline="")
        writer = csv.writer(out)
        writer.writerow(HEADER)
        for path, body in sorted(BODIES.items()):
            writer.writerow(["excel-safe-v1", "Synthetic", path, len(body), "2025-01-02T03:04:05+00:00", "false", "", ""])
        for path in ("large", "nested"):
            writer.writerow(["excel-safe-v1", "Synthetic", path, "", "0001-01-01T00:00:00+00:00", "true", "", ""])
        (base / "listings/inventory.csv").write_bytes(b"\xef\xbb\xbf" + out.getvalue().encode())
        return config
    names = sorted(BODIES) if name == "acquisition" else ["missing-synthetic.txt" if name == "missing" else
        "large/cancel.bin" if name == "cancellation" else "README-synthetic.txt"]
    plan, results = [], []
    for path in names:
        destination = base / "downloads/Synthetic" / path
        body = BODIES.get(path, b"x")
        digest = hashlib.sha256(body).hexdigest()
        expected = "0" * 64 if name in {"mismatch", "missing"} else digest
        plan.append({"remote_name": "Synthetic", "path": path, "request": {
            "source": "Synthetic:" + path, "destination": str(destination), "mode": "CopyTo",
            "expected_hash": expected, "expected_hash_type": "sha256", "expected_size": len(body)}})
        success = name == "acquisition"
        has_bytes = name in {"acquisition", "mismatch"}
        error = {"acquisition": None, "mismatch": "Downloaded bytes do not match the expected source hash",
            "missing": "Source was not found or is not an individual file: Synthetic:missing-synthetic.txt",
            "denial": "Cannot stat source: synthetic HTTP 403 Forbidden",
            "cancellation": "Operation cancelled"}[name]
        results.append({"local_sha256": digest if has_bytes else None,
            "integrity": {"acquisition": "Verified", "mismatch": "Mismatch", "cancellation": "Cancelled"}.get(name, "Failed"),
            "source": "Synthetic:" + path, "destination": str(destination), "success": success,
            "error": error, "size": len(body) if has_bytes else None, "hash": digest if has_bytes else None,
            "hash_type": "sha256" if has_bytes else None, "hash_verified": success if has_bytes else None, "hash_error": None})
        if has_bytes:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(body)
    stem = "acquisition-20260101T000000.123456789"
    dump(base / (stem + ".json"), {"schema_version": 1, "written_at": "2026-01-01T00:00:00Z",
        "rclone_version": "1.75.1", "config_path": str(config), "plan": {"files": plan, "skipped_directories": 0},
        "results": results, "complete": name == "acquisition"})
    for path in (stem + ".txt", "logs/" + stem + ".log", "logs/" + stem + ".checkpoint.json"):
        (base / path).write_bytes(b"private synthetic support")
    return config


class Flow:
    def __init__(self, name, *, late_error=None, enter_error=False, close_ok=True, grow=True, forced=False):
        self.name, self.late_error, self.enter_error, self.close_ok, self.grow = name, late_error, enter_error, close_ok, grow
        self.forced = forced
        self.events, self.server = [], None

    def serve(self, state):
        flow = self
        self.state = state
        class Context:
            def __enter__(self):
                if flow.enter_error:
                    raise P.ProducerError("fixture_failed")
                flow.server = types.SimpleNamespace(endpoint="http://127.0.0.1:54321/", cleanup_complete=False,
                    snapshot=state.snapshot)
                return flow.server
            def __exit__(self, *args):
                flow.events.append("fixture_closed")
                flow.server.cleanup_complete = True
                if flow.late_error:
                    state.errors.append(flow.late_error)
        return Context()

    def factory(self, case):
        flow = self
        class Session:
            last = None
            def command(self, action, **fields):
                flow.events.append(action)
                if action == "start":
                    assert Path(fields["app_path"]) == case / "application.exe"
                    assert Path(fields["app_path"]).read_bytes() == b"inert application bytes"
                    assert "--rclone-config-path" in fields["args"] and "--rclone-config" not in fields["args"]
                    flow.state._event("observation", "")
                    flow.state.observation_started.set()
                    self.last = session(action, observed=False)
                elif action == "observe_runtime":
                    assert not flow.state._observation_release.is_set()
                    self.last = session(action)
                    if flow.name == "cancellation":
                        flow.state.cancel_started.set()
                        if flow.grow:
                            partial = case / "output/synthetic-case/downloads/Synthetic/large/.triage-transfer-synthetic/payload"
                            partial.parent.mkdir(parents=True)
                            partial.write_bytes(b"synthetic prefix")
                else:
                    assert flow.state._observation_release.is_set()
                    if flow.name == "cancellation":
                        assert action == "ctrl_c"
                        partial = case / "output/synthetic-case/downloads/Synthetic/large/.triage-transfer-synthetic/payload"
                        assert partial.stat().st_size > 0
                        partial.unlink()
                        partial.parent.rmdir()
                        flow.state.cancel_disconnected = True
                        flow.state._event("cancel_prefix", "large/cancel.bin")
                        flow.state._event("cancel_disconnected", "large/cancel.bin")
                    materialize(case, flow.name)
                    contents = sorted(BODIES) if flow.name == "acquisition" else ["README-synthetic.txt"] if flow.name == "mismatch" else ["large/cancel.bin"] if flow.name == "cancellation" else []
                    for path in contents:
                        flow.state._event("content", path)
                    if flow.name in {"missing", "denial"}:
                        flow.state.counters["missing" if flow.name == "missing" else "denied"] = 1
                    # HTML bodies are completed even when a content GET is cancelled.
                    flow.state.counters["completed_payload_bytes"] = 300
                    self.last = session(action, final=True, cancelled=flow.name == "cancellation",
                        exit_code=0 if flow.name in {"listing", "acquisition"} else 1)
                    self.last["forced_termination"] = flow.forced
                return self.last
            def close(self):
                flow.events.append("helper_closed")
                return flow.close_ok
        return Session()


class ProducerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.app = self.root / "built.exe"
        self.app.write_bytes(b"inert application bytes")
        self.digest = hashlib.sha256(self.app.read_bytes()).hexdigest()
        self.no_native = mock.patch.object(P.subprocess, "Popen", side_effect=AssertionError("native forbidden"))
        self.no_native.start()
        self.env = mock.patch.dict(os.environ, {"SYSTEMROOT": str(self.root), "GITHUB_SHA": "b" * 40,
            "RUNNER_TEMP": str(self.root)})
        self.env.start()
    def tearDown(self):
        self.env.stop()
        self.no_native.stop()
        self.temp.cleanup()

    def execute_case(self, name, **kwargs):
        flow = Flow(name, **kwargs)
        suite = self.root / name
        suite.mkdir()
        with mock.patch.object(P, "prepare", side_effect=fake_prepare), mock.patch.object(P.F, "serve_http", side_effect=flow.serve), mock.patch.object(P.time, "sleep"):
            result = P.run_case(name, suite, self.app, self.digest, RUNTIME, session_factory=flow.factory)
        return result, flow, suite

    def test_six_complete_flows_with_real_disk_oracles(self):
        for name in ("listing", "acquisition", "mismatch", "missing", "denial", "cancellation"):
            with self.subTest(name=name):
                result, flow, suite = self.execute_case(name)
                self.assertEqual(result["status"], "passed", result)
                self.assertTrue(all(result["checks"].values()))
                self.assertEqual(result["runtime_sha256"], "a" * 64)
                self.assertLess(flow.events.index("observe_runtime"), flow.events.index("poll" if name != "cancellation" else "ctrl_c"))
                self.assertLess(flow.events.index("helper_closed"), flow.events.index("fixture_closed"))
                self.assertEqual(list(suite.iterdir()), [])

    def test_late_fixture_failure_cannot_promote(self):
        result, _, suite = self.execute_case("acquisition", late_error="worker_failed")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failure_code"], "fixture_failed")
        self.assertTrue(result["checks"]["output_hashes_exact"])
        self.assertFalse(result["checks"]["fixture_valid"])
        self.assertEqual(list(suite.iterdir()), [])

    def test_unjoined_helper_retains_case(self):
        result, _, suite = self.execute_case("acquisition", close_ok=False)
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["checks"]["process_cleanup"])
        self.assertFalse(result["checks"]["temp_cleanup"])
        self.assertTrue((suite / "acquisition/source.conf").exists())

    def test_fixture_enter_uncertainty_retains_case(self):
        result, flow, suite = self.execute_case("listing", enter_error=True)
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["checks"]["fixture_cleanup"])
        self.assertFalse(result["checks"]["temp_cleanup"])
        self.assertNotIn("start", flow.events)
        self.assertTrue((suite / "listing").exists())

    def test_cancellation_requires_actual_partial_file_growth(self):
        with mock.patch.object(P.time, "monotonic", side_effect=[0, 121]):
            result, flow, _ = self.execute_case("cancellation", grow=False)
        self.assertFalse(result["checks"]["transfer_active"])
        self.assertFalse(result["checks"]["ctrl_c_sent"])
        self.assertNotIn("ctrl_c", flow.events)
        self.assertEqual(result["status"], "failed")

    def test_literal_manifest_queue_and_payload_are_independent(self):
        expected = [{"path": path, "size": len(body), "sha256": hashlib.sha256(body).hexdigest()} for path, body in sorted(BODIES.items())]
        self.assertEqual(P.fixture_manifest(), expected)
        for name in ("acquisition", "mismatch", "missing", "denial", "cancellation"):
            data = P.queue_bytes(name)
            self.assertTrue(data.startswith(b"\xef\xbb\xbf"))
            rows = list(csv.reader(io.StringIO(data.decode("utf-8-sig"))))
            self.assertEqual(rows[0], HEADER)
            self.assertTrue(all(len(row) == 8 and row[0] == "excel-safe-v1" for row in rows[1:]))
        self.assertEqual(P.payloads(), BODIES)

    def prepared_oracle(self, name):
        case = self.root / "oracle"
        case.mkdir()
        (case / "source.conf").write_bytes(b"[Synthetic]\ntype = http\nurl = http://127.0.0.1:54321/\n")
        config = materialize(case, name)
        return case, config

    def test_manifest_rejects_corrupt_bytes_extra_file_and_wrong_result(self):
        case, config = self.prepared_oracle("acquisition")
        base = case / "output/synthetic-case"
        manifest = next(base.glob("acquisition-*.json"))
        original = manifest.read_bytes()
        mutations = [lambda: (base / "downloads/Synthetic/README-synthetic.txt").write_bytes(b"wrong"),
            lambda: (base / "extra.private").write_bytes(b"canary"),
            lambda: dump(manifest, dict(json.loads(original), complete=False))]
        for mutate in mutations:
            with self.subTest(mutation=mutations.index(mutate)):
                mutate()
                with self.assertRaises(P.ProducerError):
                    P.check_manifest("acquisition", case, config, RUNTIME)
                (base / "downloads/Synthetic/README-synthetic.txt").write_bytes(BODIES["README-synthetic.txt"])
                (base / "extra.private").unlink(missing_ok=True)
                manifest.write_bytes(original)

    def test_wrong_hash_must_retain_exact_original_bytes(self):
        case, config = self.prepared_oracle("mismatch")
        self.assertTrue(P.check_manifest("mismatch", case, config, RUNTIME)["retained_bytes_exact"])
        (case / "output/synthetic-case/downloads/Synthetic/README-synthetic.txt").unlink()
        with self.assertRaises(P.ProducerError):
            P.check_manifest("mismatch", case, config, RUNTIME)

    def test_config_snapshot_and_original_are_both_required(self):
        case, config = self.prepared_oracle("listing")
        original = (case / "source.conf").read_bytes()
        self.assertEqual(P.configuration_preserved(case, original), config)
        for path in (case / "source.conf", config):
            path.write_bytes(b"mutated")
            with self.assertRaises(P.ProducerError):
                P.configuration_preserved(case, original)
            path.write_bytes(original)

    def test_strict_json_and_session_privacy(self):
        for value in (b'{"x":1,"x":2}', b'{"x":NaN}'):
            with self.assertRaises(P.ProducerError):
                P.strict_json(value)
        good = session("finish", final=True)
        self.assertEqual(P.validate_session(good, "finish"), good)
        mutations = [dict(good, unknown="private canary"), dict(good, app_exit_code=True),
            dict(good, runtime_sha256=None), dict(good, errors=["private canary"], ok=False),
            dict(good, schema_version=True), dict(good, action="poll")]
        for value in mutations:
            with self.assertRaisesRegex(P.ProducerError, "^session_failed$"):
                P.validate_session(value, "finish")

    def test_fixed_pins_are_closed(self):
        path = self.root / "pins"
        content = ("RCLONE_VERSION=9.8.7\n" + "".join(key + "=" + "a" * 64 + "\n" for key in (
            "RCLONE_EXE_SHA256", "RCLONE_WINDOWS_ZIP_SHA256", "RCLONE_LINUX_ZIP_SHA256", "RCLONE_LINUX_EXE_SHA256"))).encode()
        path.write_bytes(content)
        self.assertEqual(P.runtime_pins(path)["version"], "9.8.7")
        for bad in (content + b"RCLONE_VERSION=9.9.9\n", content.replace(b"9.8.7", b"latest"), content + b"UNKNOWN=x\n"):
            path.write_bytes(bad)
            with self.assertRaises(P.ProducerError):
                P.runtime_pins(path)

    def test_private_file_reader_rejects_links_but_release_source_can_be_copied(self):
        alias = self.root / "alias.exe"
        os.link(self.app, alias)
        with self.assertRaises(P.ProducerError):
            P.read(self.app)
        self.assertEqual(P.read(self.app, allow_hardlinks=True), b"inert application bytes")
        result, _, _ = self.execute_case("listing")
        self.assertEqual(result["status"], "passed")

    def test_prepare_unknown_outcome_never_claims_case_process_cleanup(self):
        with mock.patch.object(P, "prepare", side_effect=P.ProducerError("case_setup_failed")):
            result = P.run_case("listing", self.root, self.app, self.digest, RUNTIME)
        self.assertFalse(result["checks"]["process_cleanup"])
        self.assertEqual(result["failure_code"], "case_setup_failed")

    def test_case_verify_timeout_keeps_cleanup_false_and_directory(self):
        flow = Flow("listing")
        def prepare(parent, name, action="Create"):
            if action == "Verify":
                raise P.ProducerError("case_setup_failed")
            return fake_prepare(parent, name, action)
        with mock.patch.object(P, "prepare", side_effect=prepare), mock.patch.object(P.F, "serve_http", side_effect=flow.serve), mock.patch.object(P.time, "sleep"):
            result = P.run_case("listing", self.root, self.app, self.digest, RUNTIME, session_factory=flow.factory)
        self.assertFalse(result["checks"]["process_cleanup"])
        self.assertFalse(result["checks"]["temp_cleanup"])
        self.assertTrue((self.root / "listing/source.conf").exists())
        self.assertEqual(result["status"], "failed")

    def test_forced_app_exit_cannot_pass(self):
        result, _, _ = self.execute_case("acquisition", forced=True)
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["checks"]["orderly_exit"])
        self.assertEqual(result["failure_code"], "session_failed")

    def test_suite_creation_verification_failure_retains_uncertain_directory(self):
        def failed(parent, name, action="Create"):
            (parent / name).mkdir()
            raise P.ProducerError("case_setup_failed")
        with mock.patch.object(P, "hosted_guard"), mock.patch.object(P, "prepare", side_effect=failed):
            result = P.run(self.app, self.digest, "b" * 40)
        self.assertFalse(result["cleanup_complete"])
        self.assertEqual(result["capabilities"]["cleanup"], "failed")
        self.assertEqual(result["result"], "failed")
        self.assertIn("cleanup_failed", result["errors"])
        self.assertEqual(len(list(self.root.glob("app-http-*"))), 1)

    def test_suite_late_source_binding_failure_remains_failed(self):
        bindings = P.E.compute_bindings(ROOT, self.app, "b" * 40, P.fixture_manifest())
        drift = dict(bindings, application_source_sha256="0" * 64)
        def passed(name, *_):
            return {"status": "passed", "exit_code": 0 if name in {"listing", "acquisition"} else 1,
                "runtime_sha256": P.runtime_pins(ROOT / "rclone-version.env")["sha256"], "failure_code": None,
                "checks": {key: True for key in P.E.CASE_CHECKS[name]}}
        with mock.patch.object(P, "hosted_guard"), mock.patch.object(P, "prepare", side_effect=fake_prepare), \
             mock.patch.object(P, "run_case", side_effect=passed), mock.patch.object(P.E, "compute_bindings", side_effect=[bindings, drift]):
            result = P.run(self.app, self.digest, "b" * 40)
        self.assertTrue(result["cleanup_complete"])
        self.assertEqual(result["result"], "failed")
        self.assertEqual(result["errors"], ["preservation_failed"])

    def test_bridge_close_does_not_close_pipe_locked_by_live_reader(self):
        bridge = P.Bridge.__new__(P.Bridge)
        bridge.last = session("finish", final=True)
        bridge.forced = False
        bridge.done, bridge.failed = threading.Event(), threading.Event()
        bridge.watchdog = mock.Mock()
        bridge.watchdog.is_alive.return_value = False
        alive, dead = mock.Mock(), mock.Mock()
        alive.is_alive.return_value, dead.is_alive.return_value = True, False
        bridge.threads = [alive, dead]
        bridge.process = mock.Mock(returncode=0)
        bridge.process.poll.return_value = 0
        self.assertFalse(bridge.close())
        bridge.process.stdout.close.assert_not_called()
        bridge.process.stderr.close.assert_called_once()

    def test_hosted_guard_rejects_self_hosted_before_setup(self):
        with mock.patch.object(P.os, "name", "nt"), mock.patch.dict(os.environ, {
                "GITHUB_ACTIONS": "true", "RUNNER_OS": "Windows", "RUNNER_ENVIRONMENT": "self-hosted"}):
            with self.assertRaisesRegex(P.ProducerError, "binding_failed"):
                P.hosted_guard()

    def test_fallback_cancel_release_is_not_a_disconnect(self):
        state = P.F.AppHttpState(P.payloads(), "cancellation")
        state.observation_started.set()
        state.release_observation()
        state.cancel_started.set()
        state.release_cancel()
        state.events = [["observation", ""], ["content", "large/cancel.bin"], ["cancel_prefix", "large/cancel.bin"]]
        with self.assertRaisesRegex(P.ProducerError, "cancellation_failed"):
            P.fixture_valid("cancellation", state.snapshot())


if __name__ == "__main__":
    unittest.main()
