"""Offline producer tests. No application, helper, runtime or listener executes."""
import copy
from contextlib import redirect_stderr, redirect_stdout
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
            writer.writerow(["excel-safe-v1", "Synthetic", path, "", "2000-01-01T00:00:00+00:00", "true", "", ""])
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
    def __init__(self, name, *, late_error=None, enter_error=False, close_ok=True, grow=True, forced=False,
                 before_app=None, after_app=None, ready_result=None):
        self.name, self.late_error, self.enter_error, self.close_ok, self.grow = name, late_error, enter_error, close_ok, grow
        self.forced = forced
        self.before_app, self.after_app, self.ready_result = before_app, after_app, ready_result
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
                if action == "ready":
                    if flow.before_app:
                        flow.before_app(case)
                    self.last = ({"schema_version": 1, "action": "ready", "ok": True, "state": "ready"}
                                 if flow.ready_result is None else flow.ready_result)
                elif action == "start":
                    assert flow.events == ["ready", "start"]
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
                    if flow.after_app:
                        flow.after_app(case)
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
        (self.root / "System32").mkdir()
        self.profile = self.root / "ci-profile"
        (self.profile / "AppData/Roaming").mkdir(parents=True)
        (self.profile / "AppData/Local").mkdir()
        self.digest = hashlib.sha256(self.app.read_bytes()).hexdigest()
        self.no_native = mock.patch.object(P.subprocess, "Popen", side_effect=AssertionError("native forbidden"))
        self.no_native.start()
        self.env = mock.patch.dict(os.environ, {"SYSTEMROOT": str(self.root), "GITHUB_SHA": "b" * 40,
            "RUNNER_TEMP": str(self.root), "USERPROFILE": str(self.profile),
            "APPDATA": str(self.profile / "AppData/Roaming"), "LOCALAPPDATA": str(self.profile / "AppData/Local"),
            "TEMP": str(self.root), "TMP": str(self.root)})
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

    def test_helper_profile_baseline_predates_start_and_full_owned_case_is_removed(self):
        def before_app(case):
            (case / "profile/pre-existing-canary/child").mkdir(parents=True)
        with redirect_stdout(io.StringIO()) as output:
            result, flow, suite = self.execute_case("listing", before_app=before_app)
        self.assertEqual(flow.events[:2], ["ready", "start"])
        self.assertEqual(result["status"], "passed")
        self.assertTrue(result["checks"]["temp_cleanup"])
        self.assertEqual(list(suite.iterdir()), [])
        self.assertNotIn("pre-existing-canary", output.getvalue() + json.dumps(result))

    def execute_profile_flow(self, index, *, before_app=None, after_app=None, ready_result=None, output=None):
        suite = self.root / ("profile-case-" + str(index))
        suite.mkdir()
        flow = Flow("listing", before_app=before_app, after_app=after_app, ready_result=ready_result)
        output = io.StringIO() if output is None else output
        with mock.patch.object(P, "prepare", side_effect=fake_prepare), mock.patch.object(P.F, "serve_http", side_effect=flow.serve), \
             mock.patch.object(P.time, "sleep"), redirect_stdout(output):
            result = P.run_case("listing", suite, self.app, self.digest, RUNTIME, session_factory=flow.factory)
        self.assertNotIn("private-canary", output.getvalue() + json.dumps(result))
        return result, flow, suite

    def prestart_observation(self, output):
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("application_prestart_diagnostic="))
        value = json.loads(lines[0].split("=", 1)[1])
        self.assertEqual(set(value), {"scope", "stage", "location", "entries", "directories", "files", "total_bytes"})
        self.assertNotIn(str(self.root), output.getvalue())
        self.assertNotIn("canary", output.getvalue())
        return value

    def test_prestart_profile_failures_report_precise_counts_without_start_or_delete(self):
        def replace(case):
            (case / "profile").rename(case / "private-canary-old")
            (case / "profile").mkdir()
        def large(case):
            for index in range(33):
                (case / "profile" / ("private-canary-" + str(index))).mkdir()
        mutations = [(lambda c: (c / "profile/private-canary").write_bytes(b"xyz"),
                      "profile_directories", (1, 0, 1, 3)),
                     (large, "profile_limit", (33, 33, 0, 0)),
                     (replace, "profile_identity", (None, None, None, None))]
        for index, (mutate, stage, counts) in enumerate(mutations):
            with self.subTest(stage=stage), mock.patch.object(P, "remove_owned") as remove:
                output = io.StringIO()
                result, flow, suite = self.execute_profile_flow(index, before_app=mutate, output=output)
                self.assertEqual(self.prestart_observation(output), dict(scope="listing", stage=stage, location="profile",
                    **dict(zip(("entries", "directories", "files", "total_bytes"), counts))))
                self.assertEqual(result["failure_code"], "cleanup_failed")
                self.assertEqual(result["status"], "failed")
                self.assertNotIn("start", flow.events)
                self.assertFalse(result["checks"]["temp_cleanup"])
                self.assertFalse(result["checks"]["runtime_observed"])
                self.assertTrue((suite / "listing").is_dir())
                remove.assert_not_called()

    def test_prestart_other_roots_still_require_empty_and_report_fixed_location(self):
        for location in ("temp", "home", "appdata", "localappdata"):
            def residue(case):
                (case / location / "private-canary-dir").mkdir()
                (case / location / "private-canary-content").write_bytes(b"xyz")
            with self.subTest(location=location), mock.patch.object(P, "remove_owned") as remove:
                output = io.StringIO()
                result, flow, suite = self.execute_profile_flow(location, before_app=residue, output=output)
                self.assertEqual(self.prestart_observation(output), dict(scope="listing", stage="private_empty", location=location,
                    entries=2, directories=1, files=1, total_bytes=3))
                self.assertEqual(result["failure_code"], "cleanup_failed")
                self.assertNotIn("start", flow.events)
                self.assertFalse(result["checks"]["temp_cleanup"])
                self.assertTrue((suite / "listing").is_dir())
                remove.assert_not_called()

    def test_prestart_unreadable_or_link_inventory_reports_unknown_counts(self):
        original = P.inventory
        for location in ("profile", "home"):
            for error in (OSError("private-canary-path"), P.ProducerError("preservation_failed")):
                def failed(path):
                    if Path(path).name == location:
                        raise error
                    return original(path)
                with self.subTest(location=location, failure=type(error).__name__), \
                     mock.patch.object(P, "inventory", side_effect=failed), mock.patch.object(P, "remove_owned") as remove:
                    output = io.StringIO()
                    result, flow, suite = self.execute_profile_flow(location + type(error).__name__, output=output)
                    stage = "profile_inventory" if location == "profile" else "private_inventory"
                    self.assertEqual(self.prestart_observation(output), dict(scope="listing", stage=stage, location=location,
                        entries=None, directories=None, files=None, total_bytes=None))
                    self.assertEqual(result["failure_code"], "unexpected_failure" if isinstance(error, OSError) else "preservation_failed")
                    self.assertNotIn("start", flow.events)
                    self.assertFalse(result["checks"]["temp_cleanup"])
                    self.assertTrue((suite / "listing").is_dir())
                    remove.assert_not_called()

    def test_prestart_original_exception_survives_even_failed_diagnostic(self):
        case = self.root / "prestart-direct"
        case.mkdir()
        (case / "profile").mkdir()
        error = OSError("private-canary")
        with mock.patch.object(P, "inventory", side_effect=error), \
             mock.patch.object(P, "prestart_diagnostic", side_effect=RuntimeError("private-canary-output")):
            with self.assertRaises(OSError) as caught:
                P.prestart_baseline("listing", case, P.identity(case / "profile"))
        self.assertIs(caught.exception, error)

    def test_prestart_diagnostic_rejects_unbounded_untyped_or_foreign_fields(self):
        counts = dict(entries=1, directories=0, files=1, total_bytes=3)
        for fields in (("private-canary", "profile_directories", "profile", counts),
                       ("listing", "private-canary", "profile", counts),
                       ("listing", "private_empty", "private-canary", counts),
                       ("listing", "profile_limit", "temp", counts),
                       ("listing", "private_empty", "profile", counts),
                       ("listing", "profile_inventory", "profile", counts),
                       ("listing", "profile_directories", "profile", dict(counts, entries=True)),
                       ("listing", "profile_directories", "profile", dict(counts, entries=1025)),
                       ("listing", "profile_directories", "profile", dict(counts, files=0)),
                       ("listing", "profile_directories", "profile", dict(counts, total_bytes=512 * 1024 * 1024 + 1)),
                       ("listing", "profile_directories", "profile", dict(counts, extra="private-canary"))):
            with self.subTest(stage=fields[1]), redirect_stdout(io.StringIO()) as output:
                with self.assertRaisesRegex(P.ProducerError, "^cleanup_failed$"):
                    P.prestart_diagnostic(*fields)
                self.assertEqual(output.getvalue(), "")

    def test_bad_ready_or_prestart_profile_never_starts_or_deletes(self):
        def replace_root(case):
            (case / "profile").rename(case / "old-profile")
            (case / "profile").mkdir()
        def too_many(case):
            for index in range(33):
                (case / "profile" / str(index)).mkdir()
        def missing_ready(case):
            raise P.ProducerError("session_failed")
        mutations = [lambda c: (c / "profile/private-canary").write_bytes(b"x"), replace_root, too_many,
            lambda c: (c / "temp/private-canary").mkdir(), missing_ready]
        with mock.patch.object(P, "remove_owned") as remove:
            for index, mutate in enumerate(mutations):
                with self.subTest(mutation=index):
                    result, flow, suite = self.execute_profile_flow(index, before_app=mutate)
                    self.assertEqual(result["status"], "failed")
                    self.assertNotIn("start", flow.events)
                    self.assertFalse(result["checks"]["temp_cleanup"])
                    self.assertTrue((suite / "listing").exists())
            for index, response in enumerate(({}, {"schema_version": True, "action": "ready", "ok": True, "state": "ready"},
                    {"schema_version": 1, "action": "ready", "ok": True, "state": "ready", "extra": "private-canary"}), 10):
                with self.subTest(response=index):
                    result, flow, suite = self.execute_profile_flow(index, ready_result=response)
                    self.assertEqual(result["failure_code"], "session_failed")
                    self.assertNotIn("start", flow.events)
                    self.assertFalse(result["checks"]["temp_cleanup"])
                    self.assertTrue((suite / "listing").exists())
            remove.assert_not_called()

    def test_profile_baseline_rejects_link_before_start(self):
        original_plain = P.plain
        def guarded(path, directory=False, **kwargs):
            if Path(path).name == "private-canary":
                raise P.ProducerError("preservation_failed")
            return original_plain(path, directory, **kwargs)
        with mock.patch.object(P, "plain", side_effect=guarded), mock.patch.object(P, "remove_owned") as remove:
            result, flow, _ = self.execute_profile_flow("link", before_app=lambda c: (c / "profile/private-canary").mkdir())
        self.assertNotIn("start", flow.events)
        self.assertFalse(result["checks"]["temp_cleanup"])
        remove.assert_not_called()

    def test_profile_baseline_add_remove_replace_and_late_file_are_sticky_failures(self):
        def baseline(case):
            (case / "profile/owned-child").mkdir()
        def replace_child(case):
            (case / "profile/owned-child").rename(case / "old-child")
            (case / "profile/owned-child").mkdir()
        def replace_root(case):
            (case / "profile").rename(case / "old-profile")
            (case / "profile/owned-child").mkdir(parents=True)
        mutations = [lambda c: (c / "profile/new-child").mkdir(),
            lambda c: (c / "profile/owned-child").rmdir(), replace_child, replace_root,
            lambda c: (c / "profile/private-canary").write_bytes(b"x")]
        with mock.patch.object(P, "remove_owned") as remove:
            for index, mutate in enumerate(mutations):
                with self.subTest(mutation=index):
                    result, flow, suite = self.execute_profile_flow(index, before_app=baseline, after_app=mutate)
                    self.assertEqual(result["status"], "failed")
                    self.assertEqual(result["failure_code"], "cleanup_failed")
                    self.assertIn("start", flow.events)
                    self.assertTrue(result["checks"]["inventory_exact"])
                    self.assertTrue(result["checks"]["process_cleanup"])
                    self.assertFalse(result["checks"]["temp_cleanup"])
                    self.assertTrue((suite / "listing").exists())
            remove.assert_not_called()

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

    def test_listing_uses_exact_default_directory_time_and_keeps_full_row_oracle(self):
        case, _ = self.prepared_oracle("listing")
        path = case / "output/synthetic-case/listings/inventory.csv"
        original = list(csv.reader(io.StringIO(path.read_bytes().decode("utf-8-sig"), newline="")))
        self.assertEqual(P.check_listing(case), {"inventory_exact": True, "listing_complete": True})
        self.assertEqual(len(original), 7)
        self.assertEqual([row[4] for row in original[1:] if row[5] == "true"],
                         ["2000-01-01T00:00:00+00:00"] * 2)
        mutations = []
        for index in (5, 6):
            for timestamp in ("0001-01-01T00:00:00+00:00", "2001-01-01T00:00:00+00:00", "2000-01-01T00:00:00Z", ""):
                rows = copy.deepcopy(original)
                rows[index][4] = timestamp
                mutations.append(rows)
        for column in range(8):
            rows = copy.deepcopy(original)
            rows[1][column] = "invalid-synthetic-cell"
            mutations.append(rows)
        mutations.extend([original[:-1], original + [original[1]], [original[0]] + original[2:]])
        for index, rows in enumerate(mutations):
            with self.subTest(mutation=index):
                text = io.StringIO(newline="")
                csv.writer(text).writerows(rows)
                path.write_bytes(b"\xef\xbb\xbf" + text.getvalue().encode("utf-8"))
                with self.assertRaisesRegex(P.ProducerError, "^listing_invalid$"):
                    P.check_listing(case)

    def cleanup_observation(self, output):
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("application_cleanup_diagnostic="))
        value = json.loads(lines[0].split("=", 1)[1])
        self.assertEqual(set(value), {"scope", "stage", "location", "entries", "directories", "files", "total_bytes"})
        return value

    def test_cleanup_residue_reports_only_counts_and_preserves_primary_listing_failure(self):
        original_materialize = materialize
        def with_residue(case, name):
            config = original_materialize(case, name)
            path = case / "output/synthetic-case/listings/inventory.csv"
            path.write_bytes(path.read_bytes().replace(b"2000-01-01", b"0001-01-01"))
            private = case / "profile/private-name-canary"
            private.mkdir()
            (private / "private-content-canary").write_bytes(b"xyz")
            return config
        output = io.StringIO()
        with mock.patch(__name__ + ".materialize", side_effect=with_residue), \
             mock.patch.object(P, "remove_owned") as remove, redirect_stdout(output):
            result, _, suite = self.execute_case("listing")
        self.assertEqual(result["failure_code"], "listing_invalid")
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["checks"]["process_cleanup"])
        self.assertFalse(result["checks"]["temp_cleanup"])
        remove.assert_not_called()
        self.assertEqual((suite / "listing/profile/private-name-canary/private-content-canary").read_bytes(), b"xyz")
        self.assertEqual(self.cleanup_observation(output), dict(scope="listing", stage="private_inventory", location="profile",
            entries=2, directories=1, files=1, total_bytes=3))
        self.assertNotIn("canary", output.getvalue())
        self.assertNotIn(str(self.root), output.getvalue())

    def test_cleanup_unreadable_inventory_has_unknown_counts_and_no_delete(self):
        original_inventory = P.inventory
        def failed(path):
            if Path(path).name == "appdata" and (Path(path).parent / "output/synthetic-case/listings/inventory.csv").exists():
                raise OSError("private-path-canary")
            return original_inventory(path)
        output = io.StringIO()
        with mock.patch.object(P, "inventory", side_effect=failed), mock.patch.object(P, "remove_owned") as remove, redirect_stdout(output):
            result, _, suite = self.execute_case("listing")
        self.assertEqual(result["failure_code"], "cleanup_failed")
        self.assertTrue(result["checks"]["inventory_exact"])
        self.assertFalse(result["checks"]["temp_cleanup"])
        self.assertTrue((suite / "listing").is_dir())
        remove.assert_not_called()
        self.assertEqual(self.cleanup_observation(output), dict(scope="listing", stage="private_inventory", location="appdata",
            entries=None, directories=None, files=None, total_bytes=None))
        self.assertNotIn("canary", output.getvalue())

    def test_cleanup_removal_failure_is_distinct_from_successful_acl_verification(self):
        output = io.StringIO()
        with mock.patch.object(P, "remove_owned", side_effect=OSError("private-removal-canary")), redirect_stdout(output):
            result, _, suite = self.execute_case("listing")
        self.assertEqual(result["failure_code"], "cleanup_failed")
        self.assertTrue(result["checks"]["process_cleanup"])
        self.assertFalse(result["checks"]["temp_cleanup"])
        self.assertTrue((suite / "listing").is_dir())
        self.assertEqual(self.cleanup_observation(output), dict(scope="listing", stage="owned_removal", location=None,
            entries=None, directories=None, files=None, total_bytes=None))
        self.assertNotIn("canary", output.getvalue())

    def test_cleanup_diagnostic_rejects_unbounded_or_nonfinite_fields(self):
        counts = dict(entries=2, directories=1, files=1, total_bytes=3)
        for fields in (("private-case", "private_inventory", "profile", counts),
                       ("listing", "private-stage", "profile", counts),
                       ("listing", "private_inventory", "private-path", counts),
                       ("listing", "private_inventory", "profile", dict(counts, entries=True)),
                       ("listing", "private_inventory", "profile", dict(counts, entries=1025)),
                       ("listing", "private_inventory", "profile", dict(counts, files=0)),
                       ("listing", "private_inventory", "profile", dict(counts, total_bytes=512 * 1024 * 1024 + 1)),
                       ("listing", "private_inventory", "profile", dict(counts, extra="private-canary")),
                       ("listing", "owned_removal", None, counts)):
            with self.subTest(fields=fields[:3]), redirect_stdout(io.StringIO()) as output:
                with self.assertRaisesRegex(P.ProducerError, "^cleanup_failed$"):
                    P.cleanup_diagnostic(*fields)
                self.assertEqual(output.getvalue(), "")

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
        bridge.messages = P.queue.Queue()
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

    def bare_bridge(self, name):
        bridge = P.Bridge.__new__(P.Bridge)
        bridge.case = self.root / name
        bridge.case.mkdir()
        bridge.last, bridge.forced, bridge.ready = None, False, False
        bridge.closed_ready = False
        bridge.stage_bytes, bridge.stage_invalid = bytearray(), False
        bridge.failed, bridge.done = threading.Event(), threading.Event()
        bridge.response_lock = threading.Lock()
        bridge.responses = bridge.calls = 0
        bridge.messages = P.queue.Queue()
        bridge.deadline = P.time.monotonic() + 60
        bridge.process = mock.Mock(returncode=0)
        bridge.process.poll.return_value = None
        bridge.threads = []
        bridge.watchdog = mock.Mock()
        bridge.watchdog.is_alive.return_value = False
        return bridge

    def reply_on_write(self, bridge, raw=b'{"schema_version":1,"action":"ready","ok":true,"state":"ready"}'):
        def write(_):
            bridge.responses += 1
            bridge.messages.put(raw)
        bridge.process.stdin.write.side_effect = write

    def test_bridge_ready_preflight_errors_are_sticky_and_prevent_start(self):
        for scenario in ("missing", "repeat", "queued_duplicate"):
            with self.subTest(scenario=scenario):
                bridge = self.bare_bridge(scenario)
                self.reply_on_write(bridge)
                if scenario != "missing":
                    self.assertEqual(bridge.command("ready"), {"schema_version": 1, "action": "ready", "ok": True, "state": "ready"})
                if scenario == "queued_duplicate":
                    bridge.messages.put(b'{"schema_version":1,"action":"ready","ok":true,"state":"ready"}')
                before = bridge.process.stdin.write.call_count
                with self.assertRaisesRegex(P.ProducerError, "^session_failed$"):
                    bridge.command("ready" if scenario == "repeat" else "start")
                self.assertTrue(bridge.failed.is_set())
                with self.assertRaisesRegex(P.ProducerError, "^session_failed$"):
                    bridge.command("start")
                self.assertEqual(bridge.process.stdin.write.call_count, before)

    def test_bridge_bad_or_missing_ready_response_poisons_session(self):
        for index, raw in enumerate((b'{}', b'{"schema_version":true,"action":"ready","ok":true,"state":"ready"}',
                b'{"schema_version":1,"action":"ready","ok":true,"state":"ready","private-canary":1}',
                b'{"schema_version":1,"action":"ready","ok":false,"state":"ready"}', None)):
            with self.subTest(response=index):
                bridge = self.bare_bridge("bad-ready-" + str(index))
                if raw is None:
                    bridge.messages.get = mock.Mock(side_effect=P.queue.Empty)
                else:
                    self.reply_on_write(bridge, raw)
                with self.assertRaisesRegex(P.ProducerError, "^session_failed$"):
                    bridge.command("ready")
                self.assertTrue(bridge.failed.is_set())
                self.assertFalse(bridge.ready)
                self.assertEqual(bridge.process.stdin.write.call_count, 1)
                with self.assertRaisesRegex(P.ProducerError, "^session_failed$"):
                    bridge.command("start")
                self.assertEqual(bridge.process.stdin.write.call_count, 1)

    def test_reader_duplicate_ready_and_late_unsolicited_reply_are_sticky(self):
        line = b'{"schema_version":1,"action":"ready","ok":true,"state":"ready"}\n'
        bridge = self.bare_bridge("duplicate-wire")
        bridge.process.stdin.write.side_effect = lambda _: bridge._reader(io.BytesIO(line + line), "stdout")
        with self.assertRaisesRegex(P.ProducerError, "^session_failed$"):
            bridge.command("ready")
        self.assertTrue(bridge.failed.is_set())
        with self.assertRaisesRegex(P.ProducerError, "^session_failed$"):
            bridge.command("start")
        self.assertEqual(bridge.process.stdin.write.call_count, 1)

        # A duplicate arriving after Start cannot be excluded in advance. It
        # must still poison final cleanup, even with an orderly final response.
        late = self.bare_bridge("late-wire")
        late.ready = True
        late.calls = late.responses = 2
        late.last = session("finish", final=True)
        late.process.poll.return_value = 0
        late._reader(io.BytesIO(line), "stdout")
        self.assertTrue(late.failed.is_set())
        self.assertFalse(late.close())

    def test_close_ready_is_exact_terminal_and_never_native_completion(self):
        bridge = self.bare_bridge("close-ready")
        self.reply_on_write(bridge)
        bridge.command("ready")
        raw = b'{"schema_version":1,"action":"close_ready","ok":true,"state":"closed"}'
        self.reply_on_write(bridge, raw)
        self.assertEqual(bridge.command("close_ready"), json.loads(raw))
        self.assertTrue(bridge.closed_ready)
        self.assertNotIn("app_exit_code", bridge.last)
        for action in ("start", "ready", "close_ready", "poll"):
            with self.subTest(action=action), redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(P.ProducerError, "^session_failed$"):
                    bridge.command(action)
        self.assertEqual(bridge.process.stdin.write.call_count, 2)
        self.assertTrue(bridge.failed.is_set())
        for value in ({}, dict(json.loads(raw), schema_version=True), dict(json.loads(raw), extra="private-canary"),
                      dict(json.loads(raw), ok=False), dict(json.loads(raw), state="finished")):
            with self.assertRaises(P.ProducerError):
                P.validate_close_ready(value)

    def test_close_ready_before_ready_after_start_and_extra_reply_are_rejected(self):
        for scenario in ("before", "after", "extra"):
            with self.subTest(scenario=scenario), redirect_stdout(io.StringIO()):
                bridge = self.bare_bridge("close-order-" + scenario)
                if scenario != "before":
                    self.reply_on_write(bridge)
                    bridge.command("ready")
                if scenario == "after":
                    self.reply_on_write(bridge, json.dumps(session("start")).encode())
                    bridge.command("start")
                if scenario == "extra":
                    raw = b'{"schema_version":1,"action":"close_ready","ok":true,"state":"closed"}\n'
                    bridge.process.stdin.write.side_effect = lambda _: bridge._reader(io.BytesIO(raw + raw), "stdout")
                before = bridge.process.stdin.write.call_count
                with self.assertRaisesRegex(P.ProducerError, "^session_failed$"):
                    bridge.command("close_ready")
                self.assertTrue(bridge.failed.is_set())
                self.assertEqual(bridge.process.stdin.write.call_count, before + (scenario == "extra"))

    def test_bridge_compile_markers_require_exact_complete_ordered_prefix(self):
        first = b"application_bridge_stage=compile\n"
        second = b"application_bridge_stage=compiled\n"
        self.assertEqual(P.bridge_stage(first), "compile")
        self.assertEqual(P.bridge_stage((first + second).replace(b"\n", b"\r\n")), "compiled")
        for raw in (b"", first[:-1], first + second[:-1], second, first + first, first + b"\n",
                    first + second + b"private-canary\n", b"private-canary\n" + first,
                    first.replace(b"=", b"=\r"), first + b"x" * 4097):
            with self.subTest(length=len(raw)):
                self.assertIsNone(P.bridge_stage(raw))
        bridge = self.bare_bridge("marker-reader")
        bridge._reader(io.BytesIO(first + second + b"private-canary\n"), "stderr")
        with redirect_stdout(io.StringIO()) as output:
            bridge._diagnostic("ready", "wait", "timeout")
        self.assertEqual(json.loads(output.getvalue().split("=", 1)[1]),
            dict(action="ready", phase="wait", outcome="timeout", last_stage=None))
        self.assertNotIn("canary", output.getvalue())

    def test_session_timeout_protocol_and_io_diagnostics_preserve_failure(self):
        for failure in ("timeout", "protocol", "write"):
            bridge = self.bare_bridge("session-diagnostic-" + failure)
            bridge.stage_bytes.extend(b"application_bridge_stage=compile\n")
            if failure == "timeout":
                bridge.messages.get = mock.Mock(side_effect=P.queue.Empty)
            elif failure == "protocol":
                self.reply_on_write(bridge, b'{"private-canary":"private-path"}')
            else:
                bridge.process.stdin.write.side_effect = OSError("private-canary")
            with self.subTest(failure=failure), redirect_stdout(io.StringIO()) as output:
                with self.assertRaisesRegex(P.ProducerError, "^session_failed$"):
                    bridge.command("ready")
            value = json.loads(output.getvalue().split("=", 1)[1])
            expected = {"timeout": ("wait", "timeout"), "protocol": ("reply", "protocol_failed"), "write": ("write", "io_failed")}[failure]
            self.assertEqual(value, dict(action="ready", phase=expected[0], outcome=expected[1], last_stage="compile"))
            self.assertTrue(bridge.failed.is_set())
            self.assertNotIn("canary", output.getvalue())
            if failure == "timeout":
                self.assertLessEqual(bridge.messages.get.call_args.kwargs["timeout"], 35)
        for fields in (("private-canary", "wait", "timeout", None), ("ready", "private-canary", "timeout", None),
                       ("ready", "wait", "private-canary", None), ("ready", "wait", "timeout", "private-canary")):
            with redirect_stdout(io.StringIO()) as output, self.assertRaises(P.ProducerError):
                P.session_diagnostic(*fields)
            self.assertEqual(output.getvalue(), "")

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

    @staticmethod
    def setup_stream(action="Create", stages=None, final=True):
        # Literal sequence is independent of the parser's constants.
        if stages is None:
            stages = ["input", "parent", "identity", "acl", "compile", "create", "verify", "complete"] if action == "Create" else ["input", "parent", "identity", "verify", "complete"]
        records = [{"schema_version": 1, "stage": stage} for stage in stages]
        if final is not None:
            records.append({"schema_version": 1, "ok": final})
        return b"".join(json.dumps(value, separators=(",", ":")).encode() + b"\r\n" for value in records)

    def prepare_result(self, result=None, error=None, identity_effect=None, action="Create"):
        output = io.StringIO()
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_OS": "Windows", "RUNNER_ENVIRONMENT": "github-hosted"}), \
             mock.patch.object(P, "hosted_guard"), mock.patch.object(P, "powershell", return_value="fixed-system-powershell"), \
             mock.patch.object(P, "hidden", return_value={}), mock.patch.object(P.subprocess, "run", return_value=result, side_effect=error) as child:
            if identity_effect is not None:
                with mock.patch.object(P, "identity", side_effect=identity_effect), redirect_stdout(output):
                    with self.assertRaisesRegex(P.ProducerError, "^case_setup_failed$"):
                        P.prepare(self.root, "app-http-" + "c" * 32, action)
            else:
                with redirect_stdout(output):
                    with self.assertRaisesRegex(P.ProducerError, "^case_setup_failed$"):
                        P.prepare(self.root, "app-http-" + "c" * 32, action)
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("application_setup_diagnostic="))
        value = json.loads(lines[0].split("=", 1)[1])
        self.assertEqual(set(value), {"outcome", "action", "scope", "exit_code", "last_stage"})
        self.assertEqual(value["scope"], "suite")
        self.assertEqual(value["action"], action)
        self.assertNotIn("private-canary", output.getvalue())
        self.assertNotIn(str(self.root), output.getvalue())
        self.assertNotIn("c" * 32, output.getvalue())
        self.assertEqual(child.call_args.kwargs["timeout"], 20)
        self.assertEqual(child.call_args.kwargs["env"]["RUNNER_ENVIRONMENT"], "github-hosted")
        return value

    def test_prepare_accepts_only_complete_exact_success_protocol(self):
        for action in ("Create", "Verify"):
            with self.subTest(action=action):
                result = types.SimpleNamespace(returncode=0, stdout=self.setup_stream(action))
                with mock.patch.object(P, "hosted_guard"), mock.patch.object(P, "powershell", return_value="fixed-system-powershell"), \
                     mock.patch.object(P, "hidden", return_value={}), mock.patch.object(P.subprocess, "run", return_value=result), redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(P.prepare(self.root, "listing", action), self.root / "listing")
                self.assertEqual(output.getvalue(), "")
        missing = self.setup_stream(stages=["input", "parent", "identity", "compile", "create", "verify", "complete"])
        value = self.prepare_result(types.SimpleNamespace(returncode=0, stdout=missing))
        self.assertEqual(value, {"outcome": "protocol_failed", "action": "Create", "scope": "suite", "exit_code": 0, "last_stage": None})

    def test_prepare_timeout_retains_only_validated_finite_prefix(self):
        prefix = self.setup_stream(stages=["input", "parent", "identity", "acl", "compile"], final=None)
        for raw, expected in ((prefix, "compile"), (prefix + b'private-canary', None),
                              (prefix + b'{"schema_version":1,"stage":"create"', None), (None, None)):
            with self.subTest(expected=expected, raw_present=raw is not None):
                error = P.subprocess.TimeoutExpired(["private-canary"], 20, output=raw, stderr=b"private-canary")
                value = self.prepare_result(error=error)
                self.assertEqual(value["outcome"], "timeout")
                self.assertIsNone(value["exit_code"])
                self.assertEqual(value["last_stage"], expected)

    def test_prepare_exit_launch_protocol_and_parent_drift_are_distinct(self):
        failed = self.setup_stream(stages=["input", "parent", "identity", "acl", "compile", "create"], final=False)
        value = self.prepare_result(types.SimpleNamespace(returncode=1, stdout=failed))
        self.assertEqual((value["outcome"], value["exit_code"], value["last_stage"]), ("exit_failed", 1, "create"))
        value = self.prepare_result(error=OSError("private-canary"))
        self.assertEqual((value["outcome"], value["exit_code"], value["last_stage"]), ("launch_failed", None, None))
        value = self.prepare_result(types.SimpleNamespace(returncode=0, stdout=b"private-canary\n"))
        self.assertEqual((value["outcome"], value["last_stage"]), ("protocol_failed", None))
        value = self.prepare_result(types.SimpleNamespace(returncode=0, stdout=self.setup_stream()), identity_effect=[(1, 2), (1, 3)])
        self.assertEqual((value["outcome"], value["last_stage"]), ("parent_changed", "complete"))

    def test_setup_parser_rejects_forged_unknown_oversize_or_partial_data(self):
        valid = self.setup_stream()
        mutations = [valid.replace(b'"input"', b'"private-canary"'), valid.replace(b'"schema_version":1', b'"schema_version":true', 1),
            valid.replace(b'"stage":"input"', b'"stage":"input","extra":"private-canary"'),
            valid.replace(b'"stage":"input"', b'"stage":"input","stage":"input"'),
            valid + b"\n", valid[:-1], b"x" * 4097, valid.replace(b'"input"', b'NaN')]
        for raw in mutations:
            with self.assertRaises(P.ProducerError):
                P.setup_progress(raw, "Create")
        value = self.prepare_result(types.SimpleNamespace(returncode=True, stdout=valid))
        self.assertEqual((value["outcome"], value["exit_code"]), ("protocol_failed", None))

    def probe_patches(self):
        # App, fixture and session entry points must remain unreachable.
        stack = __import__("contextlib").ExitStack()
        stack.enter_context(mock.patch.object(P, "hosted_guard"))
        stack.enter_context(mock.patch.object(P, "run", side_effect=AssertionError("application forbidden")))
        stack.enter_context(mock.patch.object(P, "run_case", side_effect=AssertionError("case forbidden")))
        stack.enter_context(mock.patch.object(P.F, "serve_http", side_effect=AssertionError("listener forbidden")))
        return stack

    def test_setup_probe_cli_only_verifies_and_removes_exact_empty_suite(self):
        with self.probe_patches(), mock.patch.object(P, "prepare", side_effect=fake_prepare) as prep, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(P.main(["--setup-probe"]), 0)
        self.assertEqual(output.getvalue(), "application_setup_probe_passed\n")
        self.assertEqual(prep.call_count, 2)
        self.assertEqual(prep.call_args_list[0].args[:2], prep.call_args_list[1].args[:2])
        self.assertEqual(prep.call_args_list[1].args[2], "Verify")
        self.assertEqual(list(self.root.glob("app-http-*")), [])
        self.assertEqual(list(self.root.glob("*.json")), [])

    def probe_bridge_factory(self, *, ready=None, close_ok=True, before_ready=None, after_close=None, events=None):
        events = [] if events is None else events
        def factory(case):
            (case / "bridge-stdout.private").write_bytes(b"private-canary")
            (case / "bridge-stderr.private").write_bytes(b"private-canary")
            class Session:
                def command(self, action):
                    events.append(action)
                    if action == "ready":
                        if before_ready:
                            before_ready(case)
                        if isinstance(ready, BaseException):
                            raise ready
                        return ready if ready is not None else {"schema_version": 1, "action": "ready", "ok": True, "state": "ready"}
                    if action != "close_ready":
                        raise AssertionError("app action forbidden")
                    return {"schema_version": 1, "action": "close_ready", "ok": True, "state": "closed"}
                def close(self):
                    events.append("close")
                    if after_close:
                        after_close(case)
                    return close_ok
            return Session()
        return factory

    def test_bridge_probe_cli_has_no_application_or_receipt_and_removes_owned_tree(self):
        events = []
        def baseline(case):
            (case / "profile/private-canary-dir/child").mkdir(parents=True)
        with self.probe_patches(), mock.patch.object(P, "prepare", side_effect=fake_prepare) as prep, \
             mock.patch.object(P, "Bridge", side_effect=self.probe_bridge_factory(before_ready=baseline, events=events)), \
             redirect_stdout(io.StringIO()) as output:
            self.assertEqual(P.main(["--bridge-probe"]), 0)
        self.assertEqual(output.getvalue(), "application_bridge_probe_passed\n")
        self.assertEqual(events, ["ready", "close_ready", "close"])
        self.assertEqual([c.args[2] if len(c.args) == 3 else "Create" for c in prep.call_args_list], ["Create", "Create", "Verify", "Verify"])
        self.assertEqual(list(self.root.glob("app-http-*")), [])
        self.assertEqual(list(self.root.glob("*.json")), [])

    def test_bridge_probe_cli_rejects_mixed_preflight_and_application_flags(self):
        for extra in (["--setup-probe"], *[[flag, "synthetic"] for flag in
                ("--application", "--application-sha256", "--build-commit", "--report")]):
            with self.subTest(flags=extra), mock.patch.object(P, "bridge_probe") as probe, \
                 redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                P.main(["--bridge-probe", *extra])
            self.assertEqual(error.exception.code, 2)
            probe.assert_not_called()

    def test_bridge_probe_ready_cleanup_and_directory_uncertainty_retain_root(self):
        def replace(case):
            (case / "home").rename(case / "old-home")
            (case / "home").mkdir()
        variants = [dict(ready={}), dict(ready=P.ProducerError("session_failed")), dict(close_ok=False),
                    dict(before_ready=lambda c: (c / "temp/private-canary").write_bytes(b"x")),
                    dict(before_ready=replace), dict(after_close=replace),
                    dict(after_close=lambda c: (c / "profile/private-canary").mkdir())]
        phases = ("ready", "ready", "helper_cleanup", "prestart", "prestart", "identity", "private_inventory")
        for index, options in enumerate(variants):
            events = []
            with self.subTest(variant=index), self.probe_patches(), mock.patch.object(P, "prepare", side_effect=fake_prepare), \
                 mock.patch.object(P, "remove_owned") as remove, redirect_stdout(io.StringIO()) as output:
                self.assertEqual(P.bridge_probe(self.probe_bridge_factory(events=events, **options)), 1)
            self.assertNotIn("start", events)
            self.assertEqual(events.count("close"), 1)
            self.assertTrue(output.getvalue().endswith("application_bridge_probe_failed\n"))
            self.assertNotIn("canary", output.getvalue())
            self.assertNotIn(str(self.root), output.getvalue())
            line = next(line for line in output.getvalue().splitlines() if line.startswith("application_bridge_probe_diagnostic="))
            value = json.loads(line.split("=", 1)[1])
            self.assertEqual(set(value), {"stage", "failure_code"})
            self.assertEqual(value["stage"], phases[index])
            self.assertIn(value["failure_code"], P.E.FAILURE_CODES)
            remove.assert_not_called()
        self.assertEqual(len(list(self.root.glob("app-http-*"))), len(variants))

    def test_bridge_probe_setup_acl_and_removal_failure_never_promote(self):
        for phase in ("Create", "Verify", "remove"):
            events = []
            def prepare(parent, name, action="Create"):
                result = fake_prepare(parent, name, action)
                if action == phase:
                    raise P.ProducerError("case_setup_failed")
                return result
            with self.subTest(phase=phase), self.probe_patches(), mock.patch.object(P, "prepare", side_effect=prepare), \
                 mock.patch.object(P, "remove_owned", side_effect=P.ProducerError("cleanup_failed")) as remove, \
                 redirect_stdout(io.StringIO()) as output:
                self.assertEqual(P.bridge_probe(self.probe_bridge_factory(events=events)), 1)
            self.assertNotIn("start", events)
            self.assertNotIn("passed", output.getvalue())
            if phase != "remove":
                remove.assert_not_called()
        self.assertEqual(len(list(self.root.glob("app-http-*"))), 3)

    def test_bridge_probe_source_unknown_and_reparse_failure_diagnostics_are_finite(self):
        for variant in ("source", "unknown", "reparse"):
            original_plain = P.plain
            def plain(path, directory=False, **kwargs):
                if variant == "reparse" and Path(path).name == "profile" and (Path(path).parent / "bridge-stdout.private").exists():
                    raise P.ProducerError("preservation_failed")
                return original_plain(path, directory, **kwargs)
            factory = self.probe_bridge_factory(ready=ValueError("private-canary") if variant == "unknown" else None)
            source_checks = [None, P.ProducerError("binding_failed")] if variant == "source" else [None, None, None]
            with self.subTest(variant=variant), self.probe_patches(), mock.patch.object(P, "prepare", side_effect=fake_prepare), \
                 mock.patch.object(P, "plain", side_effect=plain), mock.patch.object(P, "loaded_sources_preserved", side_effect=source_checks), \
                 mock.patch.object(P, "remove_owned") as remove, redirect_stdout(io.StringIO()) as output:
                self.assertEqual(P.bridge_probe(factory), 1)
            value = json.loads(next(line.split("=", 1)[1] for line in output.getvalue().splitlines()
                if line.startswith("application_bridge_probe_diagnostic=")))
            stage, code = {"source": ("source", "binding_failed"), "unknown": ("ready", "unexpected_failure"),
                           "reparse": ("prestart", "preservation_failed")}[variant]
            self.assertEqual(value, dict(stage=stage, failure_code=code))
            self.assertNotIn("canary", output.getvalue())
            self.assertNotIn(str(self.root), output.getvalue())
            remove.assert_not_called()
        for stage, code in (("private-canary", "cleanup_failed"), ("source", "private-canary")):
            with redirect_stdout(io.StringIO()) as output, self.assertRaises(P.ProducerError):
                P.bridge_probe_diagnostic(stage, code)
            self.assertEqual(output.getvalue(), "")

    def test_setup_probe_rejects_all_application_receipt_arguments(self):
        for flag in ("--application", "--application-sha256", "--build-commit", "--report"):
            with mock.patch.object(P, "setup_probe") as run_probe, redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                P.main(["--setup-probe", flag, "synthetic"])
            self.assertEqual(error.exception.code, 2)
            run_probe.assert_not_called()

    def test_setup_probe_timeout_or_verification_failure_never_deletes(self):
        for failing_action in ("Create", "Verify"):
            with self.subTest(action=failing_action):
                def prepare(parent, name, action="Create"):
                    if action == "Create":
                        (parent / name).mkdir()
                    if action == failing_action:
                        raise P.ProducerError("case_setup_failed")
                    return parent / name
                with self.probe_patches(), mock.patch.object(P, "prepare", side_effect=prepare), \
                     mock.patch.object(P, "remove_owned") as remove, redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(P.setup_probe(), 1)
                self.assertEqual(output.getvalue(), "application_setup_probe_failed\n")
                remove.assert_not_called()
        self.assertEqual(len(list(self.root.glob("app-http-*"))), 2)

    def test_setup_probe_cleanup_failure_and_unexpected_content_fail_closed(self):
        with self.probe_patches(), mock.patch.object(P, "prepare", side_effect=fake_prepare), \
             mock.patch.object(P, "remove_owned", side_effect=P.ProducerError("cleanup_failed")), redirect_stdout(io.StringIO()):
            self.assertEqual(P.setup_probe(), 1)
        self.assertEqual(len(list(self.root.glob("app-http-*"))), 1)
        def extra(parent, name, action="Create"):
            root = fake_prepare(parent, name, action)
            if action == "Verify":
                (root / "unexpected").write_bytes(b"private-canary")
            return root
        with self.probe_patches(), mock.patch.object(P, "prepare", side_effect=extra), \
             mock.patch.object(P, "remove_owned") as remove, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(P.setup_probe(), 1)
        self.assertNotIn("private-canary", output.getvalue())
        remove.assert_not_called()

    def synthetic_setup_environment(self, **extras):
        return {"SYSTEMROOT": str(self.root), "USERPROFILE": str(self.profile),
            "APPDATA": str(self.profile / "AppData/Roaming"), "LOCALAPPDATA": str(self.profile / "AppData/Local"),
            "TEMP": str(self.root), "TMP": str(self.root), "GITHUB_ACTIONS": "true",
            "RUNNER_OS": "Windows", "RUNNER_ENVIRONMENT": "github-hosted", **extras}

    def test_only_trusted_setup_inherits_a_snapshot_of_the_hosted_environment(self):
        extras = {"PATH": "private-canary", "AWS_SECRET_ACCESS_KEY": "private-canary",
                  "RCLONE_CONFIG": "private-canary", "HTTP_PROXY": "private-canary",
                  "HTTPS_PROXY": "private-canary", "GITHUB_TOKEN": "private-canary",
                  "APPLICATION_LAB_SENTINEL": "private-canary"}
        before = sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*"))
        with mock.patch.dict(os.environ, self.synthetic_setup_environment(**extras), clear=True):
            value = P.setup_environment()
            self.assertEqual(value, dict(os.environ))
            os.environ["APPLICATION_LAB_SENTINEL"] = "changed-after-snapshot"
            self.assertEqual(value["APPLICATION_LAB_SENTINEL"], "private-canary")
            self.assertNotIn("private-canary", repr(P.environment(self.root)))
            self.assertNotIn("changed-after-snapshot", repr(P.environment(self.root)))
        self.assertEqual(before, sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*")))

    def test_bridge_and_app_maps_stay_scrubbed_and_private_values_never_enter_evidence(self):
        extras = {"APPLICATION_LAB_SENTINEL": "private-canary", "AWS_SECRET_ACCESS_KEY": "private-canary",
                  "RCLONE_CONFIG": "private-canary", "HTTPS_PROXY": "private-canary", "PATH": "private-canary"}
        with mock.patch.dict(os.environ, self.synthetic_setup_environment(**extras), clear=True):
            with mock.patch.object(P, "powershell", return_value="fixed-system-powershell"), \
                 mock.patch.object(P, "hidden", return_value={}), \
                 mock.patch.object(P.subprocess, "Popen", return_value=mock.Mock()) as child, \
                 mock.patch.object(P.threading, "Thread"):
                P.Bridge(self.root)
            application_env = P.environment(self.root)
            self.assertEqual(set(application_env), {"SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "COMSPEC", "PATH",
                "TEMP", "TMP", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA"})
            self.assertEqual(child.call_args.kwargs["env"], dict(application_env,
                GITHUB_ACTIONS="true", RUNNER_OS="Windows", RUNNER_ENVIRONMENT="github-hosted"))
            self.assertNotIn("private-canary", repr(child.call_args))
            result, _, _ = self.execute_case("listing")
            self.assertNotIn("private-canary", json.dumps(result))
            prefix = self.setup_stream(stages=["input", "parent", "identity", "acl", "compile"], final=None)
            diagnostic = self.prepare_result(error=P.subprocess.TimeoutExpired("private-canary", 20, output=prefix))
            self.assertNotIn("private-canary", json.dumps(diagnostic))

    def test_setup_environment_rejects_missing_relative_unc_nonexistent_and_wrong_profile_dirs(self):
        mutations = [("USERPROFILE", ""), ("APPDATA", "relative"), ("TMP", r"\\synthetic.invalid\share"),
            ("TEMP", str(self.root / "absent")), ("LOCALAPPDATA", str(self.root)),
            ("APPDATA", str(self.profile / "AppData/Local")), ("SYSTEMROOT", str(self.app))]
        for name, value in mutations:
            with self.subTest(name=name, value_kind=mutations.index((name, value))), mock.patch.dict(os.environ, {name: value}):
                with self.assertRaises(P.ProducerError):
                    P.setup_environment()
        saved = os.environ.pop("APPDATA")
        try:
            with self.assertRaises(P.ProducerError):
                P.setup_environment()
        finally:
            os.environ["APPDATA"] = saved

    def test_setup_environment_reparse_guard_failure_blocks_launch_with_static_diagnostic(self):
        actual_plain = P.plain
        def linked(path, directory=False, **kwargs):
            if Path(path) == self.profile:
                raise P.ProducerError("preservation_failed")
            return actual_plain(path, directory, **kwargs)
        with mock.patch.object(P, "hosted_guard"), mock.patch.object(P, "plain", side_effect=linked), \
             mock.patch.object(P.subprocess, "run") as child, redirect_stdout(io.StringIO()) as output:
            with self.assertRaisesRegex(P.ProducerError, "^case_setup_failed$"):
                P.prepare(self.root, "listing")
        child.assert_not_called()
        self.assertEqual(output.getvalue(), 'application_setup_diagnostic={"action":"Create","exit_code":null,"last_stage":null,"outcome":"environment_invalid","scope":"listing"}\n')

    def test_setup_mixed_separator_unc_is_rejected_before_filesystem_lookup(self):
        for value in (r"\/synthetic.invalid/share/path", r"/\synthetic.invalid/share/path", r"\\?\C:\synthetic"):
            with self.subTest(grammar=value[:4]), mock.patch.dict(os.environ, {"TEMP": value}), \
                 mock.patch.object(P, "plain", wraps=P.plain) as inspect:
                # Pure Windows grammar is checked even in the Linux test job.
                self.assertTrue(P.PureWindowsPath(value).drive.startswith("\\\\"))
                with self.assertRaises(P.ProducerError):
                    P.setup_environment()
                self.assertFalse(any(str(call.args[0]) == str(Path(value)) for call in inspect.call_args_list))

    def test_setup_child_gets_job_snapshot_with_existing_timeout_and_fixed_command(self):
        result = types.SimpleNamespace(returncode=0, stdout=self.setup_stream())
        with mock.patch.dict(os.environ, self.synthetic_setup_environment(APPLICATION_LAB_SENTINEL="private-canary"), clear=True), \
             mock.patch.object(P, "hosted_guard"), mock.patch.object(P, "powershell", return_value="fixed-system-powershell"), \
             mock.patch.object(P, "hidden", return_value={}), mock.patch.object(P.subprocess, "run", return_value=result) as child:
            with redirect_stdout(io.StringIO()) as output:
                P.prepare(self.root, "listing")
            self.assertEqual(child.call_args.kwargs["env"], dict(os.environ))
            self.assertEqual(child.call_args.kwargs["env"]["APPLICATION_LAB_SENTINEL"], "private-canary")
            self.assertEqual(output.getvalue(), "")
        self.assertEqual(child.call_args.kwargs["timeout"], 20)
        self.assertEqual(child.call_args.kwargs["stderr"], P.subprocess.DEVNULL)
        self.assertEqual(child.call_args.args[0][1:5], ["-NoProfile", "-NonInteractive", "-File", str(P.HERE / "prepare_case.ps1")])


if __name__ == "__main__":
    unittest.main()
