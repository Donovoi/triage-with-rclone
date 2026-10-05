"""GCS orchestration with fake processes/transport and disposable synthetic files."""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

LAB_ROOT = Path(__file__).parents[1] / "provider-lab"
sys.path.insert(0, str(LAB_ROOT))
try:
    import run_lab as LAB
finally:
    sys.path.pop(0)

PAYLOADS = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
            "nested/bytes.bin": bytes(range(256)) * 8,
            "nested/space name.txt": b"Nested synthetic payload.\n"}
SHA256 = {"README-synthetic.txt": "1e901527b93ae84dc9d95a8aa76bbc12d7d77dbf8ab449333c172cfc909c639e",
          "nested/bytes.bin": "10fc3c51a152e90e5b90319b601d92ccf37290ef53c35ff92507687d8a911a08",
          "nested/space name.txt": "e019c52fe70badce27affda5e408659399ff764985f07104029a42ade38125bd"}
NAMES = sorted(PAYLOADS)
CAPS = {"listing", "download_hash", "missing_object_rejection", "authentication_rejection",
        "read_denial", "source_preservation", "config_preservation", "cleanup"}
LABELS = ["listing", "download-0", "download-1", "download-2", "missing", "wrong_token", "member_denied"]


class FakeState:
    def __init__(self, files, token, wrong_token, deny_member):
        assert files == PAYLOADS
        self.files = dict(PAYLOADS)
        self.token, self.wrong_token, self.deny_member = token, wrong_token, deny_member
        self.events = []
        self.requests = self.authenticated = self.auth_denied = self.missing = self.member_denied = 0
        self.rejected_mutations = self.payload_bytes = self.unexpected = self.rejected_payload_bytes = 0
        self.budget_exceeded = self.cleanup_complete = False
        self.metadata_preserved = True

    def source_preserved(self): return self.files == PAYLOADS and self.metadata_preserved


class Scenario:
    def __init__(self, root, late_fault=None, result_fault=None):
        self.root, self.late_fault, self.result_fault = root, late_fault, result_fault
        self.children, self.calls, self.states, self.fixtures = [], [], [], []
        self.closed_ports = True
        self.label = self.active = None

    @contextmanager
    def serve(self, state):
        self.states.append(state); self.active = state
        fixture = SimpleNamespace(port=19000 + len(self.states), cleanup_complete=False, failures=[])
        fixture.snapshot = lambda: {"transport": {"failure_codes": list(fixture.failures)}}
        self.fixtures.append(fixture)
        try: yield fixture
        finally:
            state.cleanup_complete = fixture.cleanup_complete = True
            if self.label == "member_denied" and self.late_fault: self.late_fault(self)

    def run(self, args, config):
        self.label = config.stem.removeprefix("gcs-")
        assert self.label == LABELS[len(self.calls)]
        self.calls.append((list(args), config))
        assert args[:2] == ["rc", "--loopback"]
        state = self.active
        result = dict(code=0, output=b"{}", stderr=b"")
        if self.label == "listing":
            assert args[2:4] == ["operations/list", "--json"]
            assert json.loads(args[4]) == {"fs": "Synthetic:synthetic-bucket", "remote": "",
                "opt": {"filesOnly": True, "showHash": True, "noModTime": False, "noMimeType": True, "recurse": True}}
            state.events = [("list", "")]
            result["output"] = json.dumps({"list": [{"Path": name, "Name": name.rsplit("/", 1)[-1],
                "Size": len(PAYLOADS[name]), "IsDir": False, "ModTime": "2024-01-01T00:00:00Z",
                "Hashes": {"md5": hashlib.md5(PAYLOADS[name]).hexdigest()}} for name in NAMES]}).encode()
        else:
            positive = self.label.startswith("download-")
            name = NAMES[int(self.label.rsplit("-", 1)[1])] if positive else (
                "missing-synthetic-object.bin" if self.label == "missing" else "README-synthetic.txt")
            directory = self.root / ("downloads" if positive else "negative-" + self.label)
            assert args[2:] == ["operations/copyfile", "srcFs=Synthetic:synthetic-bucket", "srcRemote=" + name,
                               "dstFs=" + str(directory), "dstRemote=" + name]
            if positive:
                state.events = [("metadata", name), ("content", name)]
                state.payload_bytes = len(PAYLOADS[name])
                target = directory / name; target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(PAYLOADS[name])
            else:
                causes = {"missing": "object not found",
                    "wrong_token": "googleapi: Error 401: Synthetic fixture authError, authError",
                    "member_denied": "failed to open source object: googleapi: Error 403: Synthetic fixture forbidden, forbidden"}
                result.update(code=1, output=json.dumps({"error": "loopback: call failed: " + causes[self.label],
                    "path": "operations/copyfile", "status": 500}).encode())
                if self.label == "missing": state.events, state.missing = [("missing", name)], 1
                elif self.label == "wrong_token": state.events, state.auth_denied = [("auth_denied", name)], 1
                else: state.events, state.member_denied = [("metadata", name), ("content_denied", name)], 1
        state.requests = len(state.events); state.authenticated = state.requests - state.auth_denied
        if self.result_fault: self.result_fault(self, result)
        process = SimpleNamespace(returncode=result["code"])
        process.poll = lambda: process.returncode
        self.children.append((process, self.root / "private.out", self.root / "private.err"))
        return result["code"], result["output"], result["stderr"]

    def execute(self):
        module = SimpleNamespace(GcsState=FakeState, serve_gcs=self.serve)
        with mock.patch.dict(sys.modules, {"fixture_gcs": module}), \
                mock.patch.object(LAB, "listener_closed", side_effect=lambda _: self.closed_ports), \
                mock.patch.object(LAB.subprocess, "Popen", side_effect=AssertionError("native_process_forbidden")), \
                mock.patch.object(LAB.socket, "create_connection", side_effect=AssertionError("network_forbidden")):
            return LAB.run_backend(self, "gcs", self.root)


class GcsFinalizationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.sequence = 0

    def scenario(self, **kwargs):
        self.sequence += 1
        return Scenario(self.root / ("case-" + str(self.sequence)), **kwargs)

    def assert_failed(self, row, code):
        self.assertIn(code, row["errors"])
        self.assertEqual(set(row["capabilities"]), CAPS)
        self.assertTrue(all(row["capabilities"][name] != "passed" for name in CAPS - {"cleanup"}))

    def test_exact_seven_children_eleven_events_and_three_independent_hashes(self):
        scenario = self.scenario(); row = scenario.execute()
        self.assertEqual(row["errors"], [])
        self.assertEqual((row["backend"], row["fixture_kind"]), ("gcs", "independent_loopback"))
        self.assertEqual(row["capabilities"], dict.fromkeys(CAPS, "passed"))
        self.assertEqual([config.stem.removeprefix("gcs-") for _, config in scenario.calls], LABELS)
        self.assertEqual(len(scenario.children), 7); self.assertEqual(len(scenario.states), 7)
        self.assertEqual(sum(state.requests for state in scenario.states), 11)
        self.assertEqual({p.relative_to(scenario.root / "downloads").as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in (scenario.root / "downloads").rglob("*") if p.is_file()}, SHA256)
        self.assertTrue(all(s.cleanup_complete for s in scenario.states))
        good = (scenario.root / "gcs-wrong_token-valid.conf").read_text()
        wrong = (scenario.root / "gcs-wrong_token.conf").read_text()
        state = scenario.states[5]
        self.assertNotEqual(good, wrong)
        self.assertEqual(good.replace(state.token, state.wrong_token), wrong)
        for state in scenario.states:
            self.assertNotIn(state.token, json.dumps(row)); self.assertNotIn(state.wrong_token, json.dumps(row))

    def test_success_exit_and_trace_cannot_hide_corrupted_download_bytes(self):
        def corrupt(scenario, result):
            if scenario.label == "download-1":
                (scenario.root / "downloads/nested/bytes.bin").write_bytes(b"x" * 2048)
        scenario = self.scenario(result_fault=corrupt)
        self.assert_failed(scenario.execute(), "gcs_download_mismatch")
        self.assertEqual(len(scenario.calls), 3)

    def test_negative_requires_nonzero_exact_cause_trace_and_no_artifact(self):
        for label in ("missing", "wrong_token", "member_denied"):
            for fault in ("zero", "generic", "wrong_cause", "empty_trace", "artifact", "payload"):
                def mutate(scenario, result):
                    if scenario.label != label: return
                    if fault == "zero": result["code"] = 0
                    elif fault in ("generic", "wrong_cause"):
                        value = json.loads(result["output"])
                        value["error"] = "private-canary" if fault == "generic" else "loopback: call failed: connection refused"
                        result["output"] = json.dumps(value).encode()
                    elif fault == "empty_trace":
                        scenario.active.events = []; scenario.active.requests = scenario.active.authenticated = 0
                    elif fault == "artifact": (scenario.root / ("negative-" + label) / "partial.bin").write_bytes(b"x")
                    else: scenario.active.rejected_payload_bytes = 1
                with self.subTest(label=label, fault=fault):
                    row = self.scenario(result_fault=mutate).execute()
                    self.assertTrue(row["errors"])
                    self.assertTrue(all(row["capabilities"][name] != "passed" for name in CAPS - {"cleanup"}))
                    self.assertNotIn("private-canary", json.dumps(row))

    def test_late_source_config_and_transport_failures_prevent_promotion(self):
        for fault, code in (("source", "gcs_source_changed"), ("metadata", "gcs_source_changed"),
                            ("config", "gcs_config_changed"), ("transport", "gcs_transport_failure")):
            def mutate(scenario):
                if fault == "source": scenario.states[0].files["README-synthetic.txt"] = b"changed"
                elif fault == "metadata": scenario.states[0].metadata_preserved = False
                elif fault == "config":
                    config = scenario.calls[0][1]; config.write_bytes(config.read_bytes() + b"changed = synthetic\n")
                else: scenario.fixtures[0].failures.append("request_deadline")
            with self.subTest(fault=fault):
                scenario = self.scenario(late_fault=mutate)
                self.assert_failed(scenario.execute(), code); self.assertEqual(len(scenario.calls), 7)

    def test_cleanup_failure_is_sticky_at_outer_dispatch(self):
        for fault in ("state", "fixture", "listener", "child"):
            def mutate(scenario):
                if fault == "state": scenario.states[0].cleanup_complete = False
                elif fault == "fixture": scenario.fixtures[0].cleanup_complete = False
                elif fault == "listener": scenario.closed_ports = False
                else: scenario.children[0][0].returncode = None
            with self.subTest(fault=fault):
                row = self.scenario(late_fault=mutate).execute()
                self.assert_failed(row, "gcs_cleanup_failed"); self.assertEqual(row["capabilities"]["cleanup"], "failed")

    def test_late_extra_child_or_output_tree_cannot_borrow_success(self):
        for fault, code in (("child", "gcs_total_process_or_request_mismatch"), ("tree", "gcs_final_inventory_changed")):
            def mutate(scenario):
                if fault == "child": scenario.children.append(scenario.children[0])
                else: (scenario.root / "downloads/extra.bin").write_bytes(b"x")
            self.assert_failed(self.scenario(late_fault=mutate).execute(), code)

    def test_post_flow_budget_or_unexpected_request_remains_failure(self):
        for field, value in (("budget_exceeded", True), ("unexpected", 1), ("rejected_payload_bytes", 1)):
            self.assert_failed(self.scenario(late_fault=lambda s: setattr(s.states[0], field, value)).execute(),
                               "gcs_unexpected_request_or_budget")

    def test_nonzero_positive_prevents_completion(self):
        def fail(scenario, result):
            if scenario.label == "download-0": result["code"] = 1
        scenario = self.scenario(result_fault=fail)
        self.assert_failed(scenario.execute(), "gcs_download_mismatch"); self.assertEqual(len(scenario.calls), 2)


if __name__ == "__main__": unittest.main()
