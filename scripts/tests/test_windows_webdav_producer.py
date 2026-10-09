"""Pure orchestration/artifact tests. Every native and socket boundary is inert."""
from contextlib import ExitStack
import base64
import copy
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("tested_webdav_supervisor", ROOT / "scripts/application-lab/run_windows_webdav.py")
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
REAL_CREDENTIALS = P.credentials
BODY = {"README-synthetic.txt": b"synthetic application fixture\n", "nested/binary.bin": bytes(range(256)),
        "nested/spaced name.txt": b"spaces remain exact\n", "large/cancel.bin": bytes(range(256)) * 8192}
RUNTIME = dict(version="1.75.2", sha256="a" * 64, platform="windows")
SECRET = ("1" * 64, "2" * 64, "3" * 64, "4" * 64, "a" * 107, "b" * 107, "c" * 107)
NAMES = ("listing", "acquisition", "mismatch", "missing", "wrong_credentials", "accepted_a", "revoked_a", "replacement_b",
         "permission_denied", "truncated_transfer", "cancellation")
HEADER = ["path_encoding", "remote", "path", "size", "modified", "is_dir", "hash", "hash_type"]


def write_json(path, value):
    path.write_bytes(json.dumps(value, separators=(",", ":")).encode("utf-8"))


def materialize(case, name):
    """Literal app shapes; no producer artifact-oracle/builder generates these."""
    base = case / "output/synthetic-case"
    for part in ("logs", "downloads", "listings", "config"):
        (base / part).mkdir(parents=True, exist_ok=True)
    original = (case / "source.conf").read_bytes()
    config = base / "config/working-SYNTHETIC.conf"
    config.write_bytes(original)
    write_json(config.with_suffix(".provenance.json"), dict(schema_version=1, source_path=str(case / "source.conf"),
        source_sha256=hashlib.sha256(original).hexdigest(), working_path=str(config), snapshotted_at="2026-10-10T00:00:00Z"))
    if name == "listing":
        stream = io.StringIO(newline="")
        writer = csv.writer(stream)
        writer.writerow(HEADER)
        for path, body in sorted(BODY.items()):
            writer.writerow(["excel-safe-v1", "Synthetic", path, len(body), "2025-01-02T03:04:05+00:00", "false", "", ""])
        for path in ("large", "nested"):
            writer.writerow(["excel-safe-v1", "Synthetic", path, "", "2025-01-02T03:04:05+00:00", "true", "", ""])
        (base / "listings/inventory.csv").write_bytes(b"\xef\xbb\xbf" + stream.getvalue().encode())
        return
    selected = sorted(BODY) if name == "acquisition" else ["missing-synthetic.txt" if name == "missing" else
        "large/cancel.bin" if name == "cancellation" else "README-synthetic.txt"]
    good = name in {"acquisition", "accepted_a", "replacement_b"}
    plan, results = [], []
    for path in selected:
        body = BODY.get(path, b"x")
        digest = hashlib.sha256(body).hexdigest()
        destination = base / "downloads/Synthetic" / path
        plan.append(dict(remote_name="Synthetic", path=path, request=dict(source="Synthetic:" + path, destination=str(destination),
            mode="CopyTo", expected_hash="0" * 64 if name in {"mismatch", "missing"} else digest,
            expected_hash_type="sha256", expected_size=len(body))))
        if good or name == "mismatch":
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(body)
            result = dict(local_sha256=digest, integrity="Verified" if good else "Mismatch", source="Synthetic:" + path,
                destination=str(destination), success=good, error=None if good else "Downloaded bytes do not match the expected source hash",
                size=len(body), hash=digest, hash_type="sha256", hash_verified=good, hash_error=None)
        else:
            if name == "missing":
                error = "Source was not found or is not an individual file: Synthetic:missing-synthetic.txt"
            elif name == "cancellation":
                error = "Operation cancelled"
            else:
                cause = "read metadata failed: 401 Unauthorized" if name in {"wrong_credentials", "revoked_a"} else (
                    "read metadata failed: 403 Forbidden" if name == "permission_denied" else "failed to reopen: too many retries")
                error = ("Cannot stat source: " if name != "truncated_transfer" else "") + "2026/10/10 00:00:00 NOTICE: Failed to rc: loopback: call failed: " + cause + "\n"
            result = dict(local_sha256=None, integrity="Cancelled" if name == "cancellation" else "Failed", source="Synthetic:" + path,
                destination=str(destination), success=False, error=error, size=None, hash=None, hash_type=None, hash_verified=None, hash_error=None)
        results.append(result)
    stem = "acquisition-20261010T000000.000"
    write_json(base / (stem + ".json"), dict(schema_version=1, written_at="2026-10-10T00:00:00Z", rclone_version="1.75.2",
        config_path=str(config), plan=dict(files=plan, skipped_directories=0), results=results, complete=good))
    (base / (stem + ".txt")).write_bytes(b"synthetic summary")
    (base / "logs" / (stem + ".log")).write_bytes(b"synthetic log")
    write_json(base / "logs" / (stem + ".checkpoint.json"), {})


class FakeServer:
    def __init__(self, harness, state):
        self.harness, self.state = harness, state
        self.deadline, self.endpoint = time.monotonic() + 180, "http://127.0.0.1:23456/"
        self.lock, self.stopping, self.sockets = threading.RLock(), threading.Event(), {}
        self.cleanup_complete = False
        state._transport_attempted = True
        state._transport = self
    def __enter__(self):
        if self.harness.fault == (self.state.invocation, "constructor"):
            raise ValueError("PRIVATE-CANARY")
        self.harness.current = self
        self.harness.servers.append(self)
        return self
    def __exit__(self, *_):
        self.stopping.set()
        self.state.release_observation()
        self.state.release_cancel()
        self.cleanup_complete = self.harness.fault != (self.state.invocation, "fixture_close")
        if self.harness.fault == (self.state.invocation, "late_a_mutation"):
            target = self.harness.paths["accepted_a"] / "output/synthetic-case/downloads/Synthetic/README-synthetic.txt"
            target.write_bytes(b"CHANGED")
    def transport_snapshot(self):
        return dict(accepted=self.state._total_requests, active=0, workers_alive=0,
            watchdog_alive=not self.stopping.is_set(), acceptor_alive=not self.stopping.is_set(), cleanup_complete=self.cleanup_complete)
    def snapshot(self):
        return self.state.snapshot()


def traffic(state, *, cancelled=False):
    """Scripted transport, exercising real state snapshots and epoch transitions."""
    name = state.invocation
    paths = sorted(BODY) if name == "acquisition" else ["large/cancel.bin" if name == "cancellation" else
        "missing-synthetic.txt" if name == "missing" else "README-synthetic.txt"]
    if name == "listing":
        paths = ["", "large/", "nested/"]
    for path in paths:
        state.counters["requests"] += 1
        state.counters["credential_attempts"] += 1
        state._total_requests += 1
        denied = name in {"wrong_credentials", "revoked_a"}
        state.counters["auth_denied" if denied else "authenticated"] += 1
        state._event("basic_denied" if denied else "basic_accepted", path)
        if denied:
            continue
        if name in {"missing", "permission_denied"}:
            label = "missing" if name == "missing" else "permission_denied"
            state.counters[label] += 1
            state._event(label, path)
            continue
        state.counters["propfinds"] += 1
        state.counters["directory_reads" if name == "listing" else "metadata_reads"] += 1
        state._event("directory" if name == "listing" else "metadata", path)
        if name == "listing":
            continue
        state.counters["requests"] += 1
        state.counters["credential_attempts"] += 1
        state.counters["authenticated"] += 1
        state._total_requests += 1
        state._event("basic_accepted", path)
        state.counters["gets"] += 1
        state.counters["content_reads"] += 1
        state._event("content", path)
        if name == "truncated_transfer":
            state.counters["truncated"] += 1
            state.counters["payload_bytes"] += 15
            state._event("truncated", path)
        elif name == "cancellation":
            state.counters["payload_bytes"] += 65536
            state.cancel_started.set()
            state._event("cancel_prefix", path)
            if cancelled:
                state.cancel_disconnected = True
                state._event("cancel_disconnected", path)
        else:
            state.counters["payload_bytes"] += len(BODY[path])
            state.counters["completed_payload_bytes"] += len(BODY[path])
            state._completed.add(path)


class FakeBridge:
    def __init__(self, harness, case):
        self.harness, self.case = harness, case
        self.state = harness.current.state
        self.name = self.state.invocation
        harness.paths[self.name] = case
        harness.launched.append(self.name)
        self.last = None
        self.sent = False
        self.observed = False
        self.cancelled = False
        if harness.fault == (self.name, "bridge_constructor"):
            raise ValueError("PRIVATE-CANARY")
    def response(self, action, final=False):
        return dict(schema_version=1, action=action, ok=True, state="finished" if final else "running",
            app_exit_code=(0 if self.name in {"listing", "acquisition", "accepted_a", "replacement_b"} else 1) if final else None,
            runtime_image_observed=self.observed, runtime_sha256=RUNTIME["sha256"] if self.observed else None,
            runtime_process_count=1 if self.observed else None, ctrl_c_sent=self.cancelled, output_bytes=100,
            output_limit_exceeded=False, forced_termination=False, errors=[], **dict.fromkeys(P.H.SESSION_CLEANUP, final))
    def command(self, action, **kwargs):
        if action == "ready":
            return dict(schema_version=1, action="ready", ok=True, state="ready")
        if action == "start":
            self.harness.test.assertEqual(kwargs["args"], ["--name", "synthetic-case", "--output-dir", str(self.case / "output"),
                "--rclone-config-path", str(self.case / "source.conf"), *( ["--list-remote", "Synthetic"] if self.name == "listing" else
                ["--download", str(self.case / "queue.csv"), "--remote", "Synthetic"])])
            self.harness.test.assertLessEqual(kwargs["deadline_ms"], 120000)
            self.harness.test.assertLessEqual(kwargs["max_runtime_processes"], 4)
            member = "" if self.name == "listing" else "large/cancel.bin" if self.name == "cancellation" else "missing-synthetic.txt" if self.name == "missing" else "README-synthetic.txt"
            self.state._event("observation", member)
            self.state.observation_started.set()
        elif action == "observe_runtime":
            self.observed = self.harness.fault != (self.name, "runtime")
        elif action == "ctrl_c":
            self.cancelled = True
            self.state.cancel_disconnected = True
            self.state._event("cancel_disconnected", "large/cancel.bin")
            stage = self.case / ("output/synthetic-case/downloads/Synthetic/large/.triage-transfer-" + "1" * 32)
            shutil.rmtree(stage)
        if action in {"poll", "ctrl_c"}:
            self.harness.test.assertTrue(self.state._observation_release.is_set())
            if not self.sent:
                traffic(self.state)
                self.sent = True
            if self.name == "cancellation" and not self.cancelled:
                stage = self.case / ("output/synthetic-case/downloads/Synthetic/large/.triage-transfer-" + "1" * 32)
                stage.mkdir(parents=True, exist_ok=True)
                (stage / "payload.1234abcd.partial").write_bytes(bytes(65536))
                self.last = self.response(action)
                return self.last
            materialize(self.case, self.name)
            self.harness.mutate(self.case, self.name)
            self.last = self.response(action, final=True)
            return self.last
        self.last = self.response(action)
        return self.last
    def close(self):
        if self.last is None or self.last["state"] != "finished":
            self.last = self.response("finish", final=True)
        return self.harness.fault != (self.name, "process_close")


class Harness:
    def __init__(self, test, fault=None):
        self.test, self.fault = test, fault
        self.paths, self.launched, self.servers, self.removed = {}, [], [], []
        self.current = None
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.app = self.root / "synthetic-app.exe"
        self.app.write_bytes(b"never executed synthetic application")
        self.app_sha = hashlib.sha256(self.app.read_bytes()).hexdigest()
        self.bound = {k: "d" * 64 for k in P.E.BINDING_KEYS}
        self.bound.update(application_sha256=self.app_sha, build_commit="e" * 40,
            build_target="x86_64-pc-windows-msvc", build_profile="release")
        self.stack = ExitStack()
    def __enter__(self):
        def prepare(parent, name, action="Create"):
            path = Path(parent) / name
            if self.fault == (name, "verify") and action == "Verify":
                raise P.ProducerError("case_setup_failed")
            if action == "Create":
                path.mkdir()
            else:
                self.test.assertTrue(path.is_dir())
            return path
        def remove(path, lease):
            self.test.assertEqual(P.H.identity(path), lease)
            self.removed.append(path.name)
            shutil.rmtree(path)
        def private_write(parent, name, data):
            with (parent / name).open("xb") as stream:
                stream.write(data)
        patches = [mock.patch.object(P.H, "hosted_guard"), mock.patch.object(P.H, "prepare", side_effect=prepare),
            mock.patch.object(P.H, "private_directory", side_effect=lambda p, n: (p / n).mkdir()),
            mock.patch.object(P.H, "private_write", side_effect=private_write),
            mock.patch.object(P.H, "remove_owned", side_effect=remove), mock.patch.object(P.H, "environment", return_value={"PRIVATE": "yes"}),
            mock.patch.object(P.H, "Bridge", side_effect=lambda case: FakeBridge(self, case)),
            mock.patch.object(P.F, "serve_webdav", side_effect=lambda state: FakeServer(self, state)),
            mock.patch.object(P, "credentials", return_value=(SECRET, True)),
            mock.patch.object(P, "bindings", return_value=self.bound), mock.patch.object(P.E, "runtime_binding", return_value=RUNTIME),
            mock.patch.object(P.E, "compute_bindings", return_value=self.bound),
            mock.patch.dict(os.environ, {"RUNNER_TEMP": str(self.root), "GITHUB_SHA": "e" * 40}),
            mock.patch.object(P.subprocess, "Popen", side_effect=AssertionError("NATIVE BLOCKED")),
            mock.patch.object(P.subprocess, "run", side_effect=AssertionError("NATIVE BLOCKED")),
            mock.patch.object(P.F._http.socket, "socket", side_effect=AssertionError("SOCKET BLOCKED"))]
        for patcher in patches:
            self.stack.enter_context(patcher)
        return self
    def __exit__(self, *args):
        self.stack.close()
        self.tmp.cleanup()
    def mutate(self, case, name):
        if not self.fault or self.fault[0] != name:
            return
        kind = self.fault[1]
        base = case / "output/synthetic-case"
        if kind == "body":
            (base / "downloads/Synthetic/README-synthetic.txt").write_bytes(b"wrong bytes")
        elif kind == "listing_time":
            path = base / "listings/inventory.csv"
            path.write_bytes(path.read_bytes().replace(b"2025-01-02", b"2000-01-01"))
        elif kind in {"cause", "cleanup_error", "wrong_remote", "complete"}:
            path = next(base.glob("acquisition-*.json"))
            data = json.loads(path.read_bytes())
            if kind == "cause":
                data["results"][0]["error"] = "unrelated error 401 Unauthorized"
            elif kind == "cleanup_error":
                data["results"][0]["error"] += "; transfer staging cleanup failed: PRIVATE-CANARY"
            elif kind == "wrong_remote":
                data["plan"]["files"][0]["remote_name"] = "OTHER"
            else:
                data["complete"] = not data["complete"]
            write_json(path, data)
        elif kind == "extra_output":
            (base / "unexpected").write_bytes(b"x")
        elif kind == "config":
            (case / "source.conf").write_bytes(b"poisoned")
    def run(self):
        return P.run(self.app, self.app_sha, "e" * 40, self.root / "unused-runtime.exe")


class ProducerTests(unittest.TestCase):
    def test_full_ten_scenarios_eleven_invocations_use_real_oracles(self):
        with Harness(self) as h:
            receipt = h.run()
            self.assertEqual(receipt["errors"], [])
            self.assertEqual(receipt["result"], "passed")
            self.assertTrue(receipt["cleanup_complete"])
            self.assertEqual(h.launched, list(NAMES))
            self.assertEqual(len(h.servers), 9)
            self.assertEqual(sum(len(r["checks"]) for c in receipt["cases"].values() for r in c["invocations"].values()), 186)
            self.assertEqual(len(receipt["credential_group"]["checks"]), 12)
            self.assertTrue(all(v is False for v in receipt["claims"].values()))
            shared = h.servers[5]
            self.assertEqual([r["invocation"] for r in shared.state.history], ["accepted_a", "revoked_a"])
            self.assertEqual(shared.state.epoch, 3)
            self.assertEqual(sorted(p.name for p in h.root.iterdir()), [h.app.name])
    def test_artifact_and_error_mutations_stop_at_first_failure(self):
        for name, kind, code in (("listing", "listing_time", "listing_invalid"), ("acquisition", "body", "outputs_invalid"),
            ("acquisition", "wrong_remote", "manifest_invalid"), ("mismatch", "complete", "manifest_invalid"),
            ("wrong_credentials", "cause", "denial_failed"), ("permission_denied", "cause", "denial_failed"),
            ("truncated_transfer", "cause", "truncation_failed"), ("cancellation", "cleanup_error", "cleanup_failed"),
            ("acquisition", "extra_output", "outputs_invalid"), ("acquisition", "config", "preservation_failed")):
            with self.subTest(name=name, kind=kind), Harness(self, (name, kind)) as h:
                report = h.run()
                self.assertEqual(report["result"], "failed")
                self.assertIn(code, report["errors"])
                self.assertEqual(h.launched, list(NAMES[:NAMES.index(name) + 1]))
                self.assertNotIn("PRIVATE-CANARY", json.dumps(report))
    def test_runtime_observation_is_required_before_releasing_request(self):
        with Harness(self, ("wrong_credentials", "runtime")) as h:
            report = h.run()
            row = report["cases"]["wrong_credentials"]["invocations"]["wrong_credentials"]
            self.assertFalse(row["checks"]["runtime_observed"])
            self.assertIsNone(row["runtime_sha256"])
            self.assertEqual(h.servers[-1].state.counters["requests"], 0)
            self.assertIn("runtime_unobserved", report["errors"])
    def test_uncertain_bridge_or_fixture_retains_owned_case_and_suite(self):
        for fault in ("bridge_constructor", "process_close", "fixture_close", "constructor"):
            with self.subTest(fault=fault), Harness(self, ("listing", fault)) as h:
                report = h.run()
                self.assertFalse(report["cleanup_complete"])
                self.assertEqual(report["result"], "failed")
                self.assertTrue(any(p.name.startswith("app-webdav-") for p in h.root.iterdir()))
                self.assertFalse(any(n.startswith("app-webdav-") for n in h.removed))
    def test_group_early_failure_keeps_successor_unattempted_and_projects_failure(self):
        with Harness(self, ("revoked_a", "cause")) as h:
            report = h.run()
            self.assertEqual(report["credential_group"]["status"], "failed")
            self.assertEqual(report["cases"]["replacement_credentials"]["status"], "not_run")
            for row in report["cases"]["revoked_credentials"]["invocations"].values():
                self.assertEqual(row["status"], "failed")
                self.assertFalse(row["checks"]["group_finalized"])
            accepted = report["cases"]["revoked_credentials"]["invocations"]["accepted_a"]
            self.assertTrue(accepted["checks"]["output_hashes_exact"])
            self.assertNotIn("replacement_b", h.launched)
    def test_late_accepted_artifact_change_retains_whole_group_and_stops_later_cases(self):
        with Harness(self, ("replacement_b", "late_a_mutation")) as h:
            report = h.run()
            self.assertIn("preservation_failed", report["errors"])
            self.assertFalse(report["cleanup_complete"])
            self.assertTrue(h.paths["accepted_a"].exists())
            self.assertTrue(h.paths["replacement_b"].exists())
            self.assertNotIn("permission_denied", h.launched)
            self.assertFalse(report["credential_group"]["checks"]["accepted_a_preserved"])
    def test_group_late_fixture_failure_projects_all_cleanup_without_erasing_observations(self):
        with Harness(self, ("replacement_b", "fixture_close")) as h:
            report = h.run()
            self.assertFalse(report["credential_group"]["checks"]["fixture_cleanup"])
            for case in ("revoked_credentials", "replacement_credentials"):
                for row in report["cases"][case]["invocations"].values():
                    self.assertEqual(row["status"], "failed")
                    self.assertFalse(row["checks"]["fixture_cleanup"])
                    self.assertFalse(row["checks"]["temp_cleanup"])
                    self.assertTrue(row["checks"]["fixture_valid"])
    def test_source_change_after_all_cases_is_failed_with_observations_preserved(self):
        with Harness(self) as h, mock.patch.object(P, "bindings", side_effect=[h.bound, P.ProducerError("preservation_failed")]):
            report = h.run()
            self.assertEqual(report["result"], "failed")
            self.assertIn("preservation_failed", report["errors"])
            self.assertTrue(all(c["status"] == "passed" for c in report["cases"].values()))
    def test_setup_cleanup_failure_prevents_every_application_and_suite_removal(self):
        with Harness(self) as h, mock.patch.object(P, "credentials", return_value=(SECRET, False)):
            report = h.run()
            self.assertFalse(report["cleanup_complete"])
            self.assertEqual(h.launched, [])
            self.assertTrue(all(c["status"] == "not_run" for c in report["cases"].values()))
    def test_initial_loaded_source_drift_emits_unrun_failed_receipt_without_setup(self):
        with Harness(self) as h, mock.patch.object(P, "bindings", side_effect=P.ProducerError("preservation_failed")), \
                mock.patch.object(P.H, "prepare", side_effect=AssertionError("setup forbidden")):
            report = h.run()
            self.assertEqual(report["result"], "failed")
            self.assertEqual(report["errors"], ["preservation_failed"])
            self.assertTrue(report["cleanup_complete"])
            self.assertEqual(h.launched, [])
            self.assertTrue(all(c["status"] == "not_run" for c in report["cases"].values()))
    def test_failed_final_case_and_group_helper_verification_retains_uncertainty(self):
        for name in ("webdav-listing", "webdav-accepted-a", "webdav-credentials"):
            with self.subTest(name=name), Harness(self, (name, "verify")) as h:
                report = h.run()
                self.assertEqual(report["result"], "failed")
                self.assertFalse(report["cleanup_complete"])
                self.assertIn("cleanup_failed", report["errors"])
                if name == "webdav-listing":
                    self.assertFalse(report["cases"]["listing"]["invocations"]["listing"]["checks"]["process_cleanup"])
                else:
                    self.assertFalse(report["credential_group"]["checks"]["all_processes_reaped"])
                    self.assertNotIn("permission_denied", h.launched)
                    if name == "webdav-accepted-a":
                        for leaf in ("accepted_a", "revoked_a", "replacement_b"):
                            self.assertTrue(h.paths[leaf].exists())
                        # The three earlier application reaps remain factual;
                        # uncertainty belongs to the later group-finalizer helper.
                        row = report["cases"]["revoked_credentials"]["invocations"]["accepted_a"]
                        self.assertTrue(row["checks"]["process_cleanup"])
                        self.assertFalse(row["checks"]["group_finalized"])
    def test_auxiliary_setup_uses_distinct_owner_and_preserves_runtime(self):
        with Harness(self) as h:
            suite = h.root / "setup-suite"
            suite.mkdir()
            runtime_path = h.root / "inert-runtime.exe"
            runtime_path.write_bytes(b"inert runtime")
            runtime = dict(RUNTIME, sha256=hashlib.sha256(b"inert runtime").hexdigest())
            errors = []
            with mock.patch.object(P.secrets, "token_hex", side_effect=list(SECRET[:4])), \
                    mock.patch.object(P, "obscure_once", side_effect=list(SECRET[4:])) as obscurer:
                values, clean = REAL_CREDENTIALS(suite, runtime_path, runtime, errors)
            self.assertTrue(clean)
            self.assertEqual(values, SECRET)
            self.assertEqual(errors, [])
            self.assertEqual(obscurer.call_count, 3)
            self.assertEqual([c.args[2] for c in obscurer.call_args_list], list(SECRET[1:4]))
            self.assertTrue(all(c.args[0] == suite / "webdav-credential-setup/application.exe" for c in obscurer.call_args_list))
            self.assertEqual(list(suite.iterdir()), [])
            self.assertEqual(runtime_path.read_bytes(), b"inert runtime")
    def test_auxiliary_uncertain_child_retains_private_credentials_and_source(self):
        with Harness(self) as h:
            suite = h.root / "setup-suite"
            suite.mkdir()
            runtime_path = h.root / "inert-runtime.exe"
            runtime_path.write_bytes(b"inert runtime")
            runtime = dict(RUNTIME, sha256=hashlib.sha256(b"inert runtime").hexdigest())
            errors = []
            with mock.patch.object(P, "obscure_once", side_effect=P.ProducerError("cleanup_failed")):
                values, clean = REAL_CREDENTIALS(suite, runtime_path, runtime, errors)
            self.assertIsNone(values)
            self.assertFalse(clean)
            self.assertTrue((suite / "webdav-credential-setup/application.exe").is_file())
            self.assertTrue((suite / "webdav-credential-setup/source.conf").is_file())
            self.assertIn("cleanup_failed", errors)
    def test_closed_config_and_source_declarations(self):
        config = P.config_bytes("http://127.0.0.1:23456/", SECRET[0], SECRET[4])
        self.assertIn(b"auth_redirect = false\n", config)
        for endpoint in ("https://127.0.0.1:23456/", "http://localhost:23456/", "http://127.0.0.1:65536/", "http://127.0.0.1:80/path"):
            with self.subTest(endpoint=endpoint), self.assertRaises(P.ProducerError):
                P.config_bytes(endpoint, SECRET[0], SECRET[4])
        self.assertEqual(len(P.E.HARNESS_FILES), 9)
        self.assertIn("scripts/application-lab/run_windows_http.py", P.E.HARNESS_FILES)
    def test_denial_truncation_error_is_specific_loopback_final_record(self):
        cause = "read metadata failed: 401 Unauthorized"
        good = "Cannot stat source: 2026/10/10 00:00:00 NOTICE: Failed to rc: loopback: call failed: " + cause + "\n"
        self.assertTrue(P.exact_rc_error(good, cause, stat=True))
        for value in (good.replace("loopback: ", ""), good + "another line", good + good, good.replace("401", "403"),
                      good.replace("NOTICE", "ERROR"), good.replace("rc:", "cat:"), "401 Unauthorized", good.replace("\n", "\r\n")):
            with self.subTest(value=value):
                self.assertFalse(P.exact_rc_error(value, cause, stat=True))
    def test_fixture_observations_require_exact_epochs_events_and_completed_payload(self):
        with Harness(self) as h:
            state = P.F.AppWebDavState(dict(BODY), "accepted_a", SECRET[0], SECRET[1], wrong_password=SECRET[2], password_b=SECRET[3])
            FakeServer(h, state)
            state._event("observation", "README-synthetic.txt")
            state.observation_started.set()
            state.release_observation()
            traffic(state)
            good = state.snapshot()
            self.assertTrue(P.fixture_checks("accepted_a", good, 1)["fixture_valid"])
            mutations = [lambda x: x.update(total_requests=129), lambda x: x.update(source_preserved=False),
                lambda x: x.update(completed_payload_bytes=29), lambda x: x.update(active_requests=1),
                lambda x: x.update(invocation="replacement_b"), lambda x: x["events"].append([1, "UNKNOWN", 1]),
                lambda x: x.update(authenticated=True), lambda x: x.update(observation_released=False)]
            for change in mutations:
                bad = copy.deepcopy(good)
                change(bad)
                with self.subTest(change=change), self.assertRaises(P.ProducerError):
                    P.fixture_checks("accepted_a", bad, 1)
    def test_truncation_conservative_nested_retry_bound_keeps_total_budgets(self):
        with Harness(self) as h:
            state = P.F.AppWebDavState(dict(BODY), "truncated_transfer", SECRET[0], SECRET[1], wrong_password=SECRET[2], password_b=SECRET[3])
            FakeServer(h, state)
            state._event("observation", "README-synthetic.txt")
            state.observation_started.set()
            state.release_observation()
            traffic(state)
            snap = state.snapshot()
            snap.update(requests=101, credential_attempts=101, authenticated=101, gets=100, content_reads=100,
                        truncated=100, payload_bytes=1500, total_requests=101)
            snap["events"] = [[1, "observation", 1], [1, "basic_accepted", 1], [1, "metadata", 1]] + [
                row for _ in range(100) for row in ([1, "basic_accepted", 1], [1, "content", 1], [1, "truncated", 1])]
            self.assertTrue(P.fixture_checks("truncated_transfer", snap, 1)["truncation_observed"])
            snap["gets"] = snap["truncated"] = 101
            snap["requests"] = snap["credential_attempts"] = snap["authenticated"] = snap["total_requests"] = 102
            snap["events"].extend([[1, "basic_accepted", 1], [1, "content", 1], [1, "truncated", 1]])
            with self.assertRaises(P.ProducerError):
                P.fixture_checks("truncated_transfer", snap, 1)
    def test_only_source_backed_final_truncation_literals_pass_the_artifact_oracle(self):
        with Harness(self) as h:
            case = h.root / "oracle"
            case.mkdir()
            (case / "source.conf").write_bytes(b"synthetic config")
            materialize(case, "truncated_transfer")
            path = next((case / "output/synthetic-case").glob("acquisition-*.json"))
            original = json.loads(path.read_bytes())
            config = case / "output/synthetic-case/config/working-SYNTHETIC.conf"
            for cause, accepted in (("unexpected EOF", True), ("failed to reopen: too many retries", True), ("EOF", False),
                                    ("connection reset by peer", False), ("401 Unauthorized", False)):
                value = copy.deepcopy(original)
                value["results"][0]["error"] = "2026/10/10 00:00:00 NOTICE: Failed to rc: loopback: call failed: " + cause + "\n"
                write_json(path, value)
                if accepted:
                    self.assertTrue(P.manifest("truncated_transfer", case, config, RUNTIME)["failed_result_exact"])
                else:
                    with self.assertRaisesRegex(P.ProducerError, "truncation_failed"):
                        P.manifest("truncated_transfer", case, config, RUNTIME)


class ObscureTests(unittest.TestCase):
    def test_private_stdin_argv_caps_and_exact_obscured_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            case = Path(tmp)
            exe = case / "application.exe"
            exe.write_bytes(b"inert")
            digest = hashlib.sha256(b"inert").hexdigest()
            token = base64.urlsafe_b64encode(bytes(80)).rstrip(b"=").decode("ascii")
            class Input(io.BytesIO):
                saved = None
                def close(self):
                    if not self.closed:
                        self.saved = self.getvalue()
                    super().close()
            process = mock.Mock()
            process.stdin, process.stdout, process.stderr = Input(), io.BytesIO((token + "\n").encode()), io.BytesIO()
            process.poll.return_value = 0
            process.returncode = 0
            with mock.patch.object(P.H, "hidden", return_value={}), mock.patch.object(P.H, "environment", return_value={"PRIVATE": "yes"}), \
                    mock.patch.object(P.subprocess, "Popen", return_value=process) as launch:
                self.assertEqual(P.obscure_once(exe, case, "2" * 64, digest), token)
            argv = launch.call_args.args[0]
            self.assertEqual(argv, [str(exe), "obscure", "-", "--config", str(case / "source.conf")])
            self.assertNotIn("2" * 64, repr(launch.call_args))
            self.assertEqual(process.stdin.saved, b"2" * 64 + b"\n")
            process.wait.assert_called_once_with(timeout=5)
            process.kill.assert_not_called()
    def test_unreaped_setup_and_partial_launch_are_cleanup_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            exe = Path(tmp) / "application.exe"
            exe.write_bytes(b"inert")
            digest = hashlib.sha256(b"inert").hexdigest()
            with mock.patch.object(P.H, "hidden", return_value={}), mock.patch.object(P.H, "environment", return_value={}), \
                    mock.patch.object(P.subprocess, "Popen", side_effect=OSError("PRIVATE-CANARY")):
                with self.assertRaisesRegex(P.ProducerError, "^cleanup_failed$"):
                    P.obscure_once(exe, Path(tmp), "2" * 64, digest)
            process = mock.Mock(stdin=io.BytesIO(), stdout=io.BytesIO(), stderr=io.BytesIO())
            process.poll.return_value = None
            process.wait.side_effect = TimeoutError()
            with mock.patch.object(P.H, "hidden", return_value={}), mock.patch.object(P.H, "environment", return_value={}), \
                    mock.patch.object(P.subprocess, "Popen", return_value=process), mock.patch.object(P, "SETUP_SECONDS", 0):
                with self.assertRaisesRegex(P.ProducerError, "^cleanup_failed$"):
                    P.obscure_once(exe, Path(tmp), "2" * 64, digest)
            process.kill.assert_called_once()
    def test_obscure_rejects_stderr_overflow_wrong_encoding_and_thread_start_failure(self):
        good = base64.urlsafe_b64encode(bytes(80)).rstrip(b"=") + b"\n"
        with tempfile.TemporaryDirectory() as tmp:
            exe = Path(tmp) / "application.exe"
            exe.write_bytes(b"inert")
            digest = hashlib.sha256(b"inert").hexdigest()
            for stdout, stderr in ((good, b"PRIVATE-CANARY"), (b"x" * 5000, b""), (b"a" * 107 + b"\n", b""),
                                   (good + b"extra", b"")):
                process = mock.Mock(stdin=io.BytesIO(), stdout=io.BytesIO(stdout), stderr=io.BytesIO(stderr), returncode=0)
                process.poll.return_value = 0
                with self.subTest(stdout=len(stdout), stderr=len(stderr)), mock.patch.object(P.H, "hidden", return_value={}), \
                        mock.patch.object(P.H, "environment", return_value={}), mock.patch.object(P.subprocess, "Popen", return_value=process):
                    with self.assertRaises(P.ProducerError) as caught:
                        P.obscure_once(exe, Path(tmp), "2" * 64, digest)
                    self.assertNotIn("PRIVATE-CANARY", str(caught.exception))
                process.wait.assert_called_once_with(timeout=5)
            process = mock.Mock(stdin=io.BytesIO(), stdout=io.BytesIO(), stderr=io.BytesIO(), returncode=0)
            process.poll.return_value = 0
            with mock.patch.object(P.H, "hidden", return_value={}), mock.patch.object(P.H, "environment", return_value={}), \
                    mock.patch.object(P.subprocess, "Popen", return_value=process), \
                    mock.patch.object(P.threading.Thread, "start", side_effect=RuntimeError("PRIVATE-CANARY")):
                with self.assertRaisesRegex(P.ProducerError, "^unexpected_failure$"):
                    P.obscure_once(exe, Path(tmp), "2" * 64, digest)
            self.assertTrue(process.stdout.closed and process.stderr.closed and process.stdin.closed)


if __name__ == "__main__":
    unittest.main()
