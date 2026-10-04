"""Independent LOW runner observations; no native process or socket is started."""
import configparser
import copy
from contextlib import contextmanager
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parents[1] / "provider-lab"))
try:
    import run_lab as L
finally:
    sys.path.pop(0)

MEMBER = "README-synthetic.txt"
PAYLOADS = {MEMBER: b"Synthetic provider protocol fixture. No account or user data.\n",
            "nested/space name.txt": b"Nested synthetic payload.\n", "nested/bytes.bin": bytes(range(256)) * 8}
EXPECTED = [{"path": k, "size": len(v), "sha256": hashlib.sha256(v).hexdigest()} for k, v in sorted(PAYLOADS.items())]
CAPS = {"authentication_rejection", "source_preservation", "config_preservation", "cleanup"}
LABELS = ("valid-before", "wrong-secret", "valid-after", "both-empty", "key-only", "secret-only", "content-denied")


def denial(content=False):
    cause = ('failed to open source object: HTTP error 403 (403 Forbidden) returned body: "Synthetic member denied"'
             if content else 'HTTP error 403 (403 Forbidden) returned body: "Synthetic credentials denied"')
    return json.dumps({"error": "loopback: call failed: " + cause, "path": "operations/copyfile", "status": 500}).encode()


def observations(label):
    denied = label in ("wrong-secret", "both-empty", "key-only", "secret-only")
    content_denied = label == "content-denied"
    events = ([("auth_denied", "1"), ("auth_denied", "2")] if denied else
              [("metadata", "1"), ("metadata", "2"), ("content_denied" if content_denied else "content", MEMBER)])
    return dict(events=events, requests=2 if denied else 3, authenticated=0 if denied else 3,
                auth_denied=2 if denied else 0, anonymous=0, metadata_reads=0 if denied else 2,
                member_denied=int(content_denied), rejected_mutations=0,
                payload_bytes=0 if denied or content_denied else len(PAYLOADS[MEMBER]),
                response_bytes=1000, unexpected=0, rejected_payload_bytes=0, accepted_connections=2 if denied else 3,
                admission_denied=0, budget_exceeded=False)


class Scenario:
    def __init__(self, root, mutate=None, after=None):
        self.root, self.mutate, self.after = root, mutate, after
        self.children, self.calls, self.states = [], [], []
        self.active = self.label = None
        self.pending = self.extra_child = False

    @contextmanager
    def serve(self, kind, state):
        assert kind == "internetarchive-low-auth"
        self.active = state
        self.states.append(state)
        try:
            yield 21000 + len(self.states)
        finally:
            state.cleanup_complete = True
            if self.after:
                self.after(self)

    def run(self, args, config=None):
        assert args[:3] == ["rc", "--loopback", "operations/copyfile"]
        params = dict(value.split("=", 1) for value in args[3:])
        assert set(params) == {"srcFs", "srcRemote", "dstFs", "dstRemote"}
        assert params["srcFs"] == "Synthetic:synthetic-item" and params["srcRemote"] == params["dstRemote"] == MEMBER
        label = self.label = config.stem.removeprefix("internetarchive-low-")
        destination = Path(params["dstFs"])
        assert destination == self.root / label
        self.calls.append(label)
        parsed = configparser.ConfigParser(interpolation=None)
        parsed.read_string(config.read_text())
        assert parsed.sections() == ["Synthetic"]
        options = dict(parsed["Synthetic"])
        assert set(options) == {"type", "endpoint", "front_endpoint", "access_key_id", "secret_access_key", "wait_archive", "item_derive"}
        port = 21000 + len(self.states)
        assert options["endpoint"] == f"http://127.0.0.1:{port}/ias3" and options["front_endpoint"] == f"http://127.0.0.1:{port}/front"
        assert options["type"] == "internetarchive" and options["wait_archive"] == "1ns" and options["item_derive"] == "false"
        assert options["access_key_id"] == ("" if label in ("both-empty", "secret-only") else self.active.key)
        secret = ("" if label in ("both-empty", "key-only") else self.active.wrong_secret if label == "wrong-secret" else self.active.secret)
        assert options["secret_access_key"] == secret
        for name, value in observations(label).items():
            setattr(self.active, name, copy.deepcopy(value))
        positive = label in ("valid-before", "valid-after")
        result = {"code": 0 if positive else 1, "output": b"{}" if positive else denial(label == "content-denied"), "error": b""}
        if positive:
            (destination / MEMBER).write_bytes(PAYLOADS[MEMBER])
        if self.mutate:
            self.mutate(self, result)
        process = mock.Mock()
        process.poll.return_value = None if self.pending else result["code"]
        record = (process, self.root / "private.out", self.root / "private.err")
        self.children.append(record)
        if self.extra_child:
            self.children.append(record)
        return result["code"], result["output"], result["error"]


class RunnerTests(unittest.TestCase):
    def exercise(self, mutate=None, after=None, closed=True):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            scenario = Scenario(root, mutate, after)
            row = {"capabilities": dict.fromkeys(CAPS, "not_run")}
            with mock.patch.object(L, "serve", scenario.serve), mock.patch.object(L, "listener_closed", return_value=closed):
                L.internetarchive_low_checks(scenario, root, row, EXPECTED)
            self.assertEqual(row["capabilities"], dict.fromkeys(CAPS, "passed"))
            return scenario

    def test_exact_seven_cases_are_required_with_no_extra_claims(self):
        scenario = self.exercise()
        self.assertEqual(scenario.calls, list(LABELS))
        self.assertEqual(len(scenario.children), 7)
        self.assertEqual(sum(state.requests for state in scenario.states), 17)

    def test_wrong_hash_and_extra_output_cannot_qualify_success(self):
        for body, extra in ((b"X" * len(PAYLOADS[MEMBER]), False), (PAYLOADS[MEMBER], True)):
            def mutate(scenario, result):
                if scenario.label == "valid-before":
                    path = scenario.root / scenario.label / ("extra.bin" if extra else MEMBER)
                    path.write_bytes(body)
            with self.subTest(extra=extra), self.assertRaises(L.LabError):
                self.exercise(mutate)

    def test_denial_requires_known_cause_and_empty_destination(self):
        for field, value in (("code", 0), ("output", b"{}"), ("output", denial(True)), ("output", b'{"error":"startup failed"}')):
            def mutate(scenario, result):
                if scenario.label == "wrong-secret":
                    result[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(L.LabError):
                self.exercise(mutate)
        def accepted_bytes(scenario, result):
            if scenario.label == "both-empty":
                (scenario.root / scenario.label / "partial.bin").write_bytes(b"unexpected")
        with self.assertRaises(L.LabError):
            self.exercise(accepted_bytes)

    def test_ignored_constructor_denial_and_content_denial_are_not_authentication(self):
        for kind in ("one_request", "content_error", "retry", "anonymous_success"):
            def mutate(scenario, result):
                if scenario.label != "wrong-secret":
                    return
                if kind == "one_request":
                    scenario.active.requests = scenario.active.auth_denied = 1
                    scenario.active.events.pop()
                elif kind == "content_error":
                    result["output"] = denial(True)
                elif kind == "retry":
                    scenario.active.requests += 1
                else:
                    scenario.active.anonymous = 1
            with self.subTest(kind=kind), self.assertRaises(L.LabError):
                self.exercise(mutate)

    def test_config_source_metadata_and_credential_changes_are_detected(self):
        for kind in ("config", "source", "metadata", "secret", "scope", "earlier_output"):
            def after(scenario):
                if scenario.label != "content-denied":
                    return
                if kind == "config":
                    next(scenario.root.glob("*.conf")).write_text("changed")
                elif kind == "source":
                    scenario.states[0].files[MEMBER] = b"changed"
                elif kind == "metadata":
                    scenario.states[0].metadata["item_size"] = 0
                elif kind == "secret":
                    scenario.states[0].secret += "changed"
                elif kind == "scope":
                    scenario.states[0].item = "different-item"
                else:
                    (scenario.root / "valid-before" / MEMBER).write_bytes(b"changed")
            with self.subTest(kind=kind), self.assertRaises(L.LabError):
                self.exercise(after=after)

    def test_unreaped_duplicate_children_listener_and_transport_cleanup_fail(self):
        for pending in (True, False):
            def mutate(scenario, result):
                scenario.pending, scenario.extra_child = pending, not pending
            with self.subTest(pending=pending), self.assertRaises(L.LabError):
                self.exercise(mutate)
        with self.assertRaisesRegex(L.LabError, "cleanup_failed"):
            self.exercise(closed=False)
        def after(scenario):
            scenario.active.cleanup_complete = False
        with self.assertRaisesRegex(L.LabError, "cleanup_failed"):
            self.exercise(after=after)

    def test_all_wrong_error_shapes_and_cross_scope_errors_fail_closed(self):
        for content in (False, True):
            self.assertTrue(L.internetarchive_low_error_matches(denial(content), content))
            self.assertFalse(L.internetarchive_low_error_matches(denial(not content), content))
            for key, value in (("status", True), ("status", "500"), ("path", "operations/list"), ("extra", "private"), ("error", "not found")):
                data = json.loads(denial(content)); data[key] = value
                self.assertFalse(L.internetarchive_low_error_matches(json.dumps(data).encode(), content))
        for raw in (b"null", b"[]", b'{"status":500,"status":500}', b'{"error":NaN}'):
            self.assertFalse(L.internetarchive_low_error_matches(raw))

    def test_counter_types_event_order_and_budgets_are_strict(self):
        for label, auth, mode in (("valid-before", "valid", "normal"), ("wrong-secret", "wrong_secret", "normal"),
                                   ("both-empty", "absent", "normal"), ("content-denied", "valid", "member_denied")):
            state = SimpleNamespace(**observations(label), byte_limit=65536, connection_limit=3)
            self.assertTrue(L.internetarchive_low_flow_matches(state, auth, mode, len(PAYLOADS[MEMBER])))
            for name in observations(label):
                for value in (None, True):
                    changed = copy.deepcopy(state); setattr(changed, name, value)
                    with self.subTest(label=label, name=name, value=value):
                        self.assertFalse(L.internetarchive_low_flow_matches(changed, auth, mode, len(PAYLOADS[MEMBER])))
            changed = copy.deepcopy(state); changed.events.reverse()
            self.assertFalse(L.internetarchive_low_flow_matches(changed, auth, mode, len(PAYLOADS[MEMBER])))


class ReceiptTests(unittest.TestCase):
    def execute(self, root, closed=True, fail=False):
        runtime = mock.Mock()
        runtime.run.return_value = (0, b"rclone v1.75.1\n", b"")
        runtime.close.return_value = closed
        def observations(runtime, case_root, row, manifest):
            self.assertEqual(manifest, EXPECTED)
            self.assertTrue(case_root.is_dir())
            self.assertEqual(set(row["capabilities"]), CAPS)
            if fail:
                raise L.LabError("internetarchive_low_denial_mismatch")
            row["capabilities"] = dict.fromkeys(CAPS, "passed")
        report_path = root / "evidence.json"
        with mock.patch.object(L, "verified_runtime", return_value=(Path("synthetic"), {"version": "1.75.1", "sha256": "a" * 64}, "linux")), \
                mock.patch.object(L, "Runtime", return_value=runtime), mock.patch.object(L, "internetarchive_low_checks", observations):
            report = L.run_internetarchive_low_auth(Path("synthetic"), report_path)
        self.assertEqual(json.loads(report_path.read_text()), report)
        self.assertEqual(report["schema_version"], 4)
        self.assertEqual(report["backends"][0]["fixture_mode"], "internetarchive_low_read_auth_v1")
        runtime.close.assert_called_once()
        return report

    def test_fresh_receipt_and_failed_observation_and_late_cleanup(self):
        for closed, fail in ((True, False), (True, True), (False, False)):
            with self.subTest(closed=closed, fail=fail), tempfile.TemporaryDirectory() as name:
                report = self.execute(Path(name), closed=closed, fail=fail)
                self.assertEqual(report["success"], closed and not fail)
                self.assertEqual(report["cleanup_passed"], closed)
                if not closed:
                    self.assertEqual(report["backends"][0]["capabilities"]["cleanup"], "failed")

    def test_cli_flag_is_explicit_and_mutually_exclusive(self):
        with mock.patch.object(sys, "argv", ["lab", "--rclone", "x", "--report", "y", "--internetarchive-low-auth"]), \
                mock.patch.object(L, "run_internetarchive_low_auth", return_value={"success": True, "cleanup_passed": True, "backends": [{}]}) as low, \
                mock.patch.object(L, "run_lab", side_effect=AssertionError("baseline must not run")), mock.patch.object(sys, "stdout", io.StringIO()):
            self.assertEqual(L.main(), 0)
            low.assert_called_once_with(Path("x"), Path("y"))
        for other in ("--filefabric-renewal", "--backends=internetarchive"):
            with mock.patch.object(sys, "argv", ["lab", "--rclone", "x", "--report", "y", "--internetarchive-low-auth", other]), \
                    mock.patch.object(sys, "stderr", io.StringIO()), self.assertRaises(SystemExit):
                L.main()


if __name__ == "__main__":
    unittest.main()
