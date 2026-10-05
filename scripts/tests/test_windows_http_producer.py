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
            if Path(path).name == "appdata":
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
