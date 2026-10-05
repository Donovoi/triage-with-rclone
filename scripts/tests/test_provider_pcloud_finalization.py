"""pCloud orchestration faults with synthetic files and mocked I/O only.

No fixture TLS imports, certificate creation, listeners or native children run.
The literal transcript and payloads are independent of the runner predicates.
"""

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


PAYLOADS = {
    "README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
    "nested/bytes.bin": bytes(range(256)) * 8,
    "nested/space name.txt": b"Nested synthetic payload.\n",
}
NAMES = sorted(PAYLOADS)
IDS = {"README-synthetic.txt": "f301", "nested/space name.txt": "f302", "nested/bytes.bin": "f303"}
CAPS = {"listing", "download_hash", "missing_object_rejection", "saved_token_read", "saved_token_rejection",
        "read_denial", "source_preservation", "config_preservation", "fixture_write_rejection", "cleanup"}
EXPECTED_LABELS = ["listing-initial", "stat-0", "download-0", "stat-1", "download-1", "stat-2", "download-2",
                   "missing-stat", "missing", "wrong_token", "member_denied", "write-guard", "listing-final"]


def metadata(name):
    body = PAYLOADS[name]
    return {"Path": name, "Name": name.rsplit("/", 1)[-1], "Size": len(body), "IsDir": False,
            "ID": IDS[name], "ModTime": "2024-01-01T00:00:00Z",
            "Hashes": {"md5": hashlib.md5(body).hexdigest(), "sha1": hashlib.sha1(body).hexdigest()}}


class FakeState:
    def __init__(self, files, token, wrong_token, deny_member):
        assert files == PAYLOADS
        self.files = dict(PAYLOADS)
        self.token, self.wrong_token, self.deny_member = token, wrong_token, deny_member
        self.events = []
        self.requests = self.authenticated = self.auth_denied = self.member_denied = 0
        self.rejected_mutations = self.payload_bytes = self.unexpected = self.rejected_payload_bytes = self.oauth_requests = 0
        self.budget_exceeded = self.cleanup_complete = False
        self.metadata_preserved = True

    def source_preserved(self):
        return self.files == PAYLOADS and self.metadata_preserved


class Scenario:
    def __init__(self, root, late_fault=None, result_fault=None):
        self.root, self.late_fault, self.result_fault = root, late_fault, result_fault
        self.children, self.calls, self.states, self.fixtures, self.connections = [], [], [], [], []
        self.active = self.fixture = None
        self.label = None
        self.closed_ports = True

    @contextmanager
    def serve(self, root, state):
        assert root == self.root
        self.states.append(state)
        fixture = SimpleNamespace(port=19000 + len(self.states), cleanup_complete=False, failures=[], context=object())
        fixture.rclone_ca_args = lambda: ["--ca-cert", str(root / "synthetic-ca.pem")]
        fixture.client_context = lambda: fixture.context
        fixture.snapshot = lambda: {"transport": {"failure_codes": list(fixture.failures)}}
        self.fixtures.append(fixture)
        self.active, self.fixture = state, fixture
        try:
            yield fixture
        finally:
            state.cleanup_complete = fixture.cleanup_complete = True
            if self.label == "listing-final" and self.late_fault:
                self.late_fault(self)

    def run(self, args, config):
        label = config.stem.removeprefix("pcloud-")
        assert label == EXPECTED_LABELS[len(self.calls)]
        self.label = label
        self.calls.append((list(args), config))
        assert args[:2] == ["--ca-cert", str(self.root / "synthetic-ca.pem")]
        assert args[2:4] == ["rc", "--loopback"]
        result = {"code": 0, "output": b"{}", "stderr": b""}
        state = self.active
        state.events = [("root_list", "")]
        if label.startswith("listing-"):
            assert args[4] == "operations/list"
            state.events = [("list_recursive", ""), ("checksum", "nested/space name.txt"),
                            ("checksum", "README-synthetic.txt"), ("checksum", "nested/bytes.bin")]
            result["output"] = json.dumps({"list": [metadata(name) for name in NAMES]}).encode()
        elif label.startswith(("stat-", "download-")) or label == "write-guard":
            name = "README-synthetic.txt" if label == "write-guard" else NAMES[int(label.rsplit("-", 1)[1])]
            if name.startswith("nested/"):
                state.events.append(("nested_list", "nested"))
            state.events.append(("checksum", name))
            if label.startswith("download-"):
                assert args[4:] == ["operations/copyfile", "srcFs=Synthetic:", "srcRemote=" + name,
                                    "dstFs=" + str(self.root / "downloads"), "dstRemote=" + name]
                state.events += [("link", name), ("content", name)]
                state.payload_bytes = len(PAYLOADS[name])
                destination = self.root / "downloads" / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(PAYLOADS[name])
            else:
                assert args[4] == "operations/stat"
                result["output"] = json.dumps({"item": metadata(name)}).encode()
        elif label == "missing-stat":
            assert args[4] == "operations/stat"
            result["output"] = b'{"item":null}'
        else:
            assert args[4] == "operations/copyfile"
            causes = {"missing": "object not found",
                      "wrong_token": "couldn't list files: pcloud error: synthetic token rejected (2000)",
                      "member_denied": "failed to open source object: pcloud error: synthetic member denied (2003)"}
            result.update(code=1, output=json.dumps({"error": "loopback: call failed: " + causes[label],
                                                    "path": "operations/copyfile", "status": 500}).encode())
            if label == "wrong_token":
                state.events = [("auth_denied", "")]
                state.auth_denied = 1
            elif label == "member_denied":
                state.events += [("checksum", "README-synthetic.txt"), ("link", "README-synthetic.txt"),
                                 ("content_denied", "README-synthetic.txt")]
                state.member_denied = 1
        state.requests = len(state.events)
        state.authenticated = state.requests - state.auth_denied
        if self.result_fault:
            self.result_fault(self, result)
        process = SimpleNamespace(returncode=result["code"])
        process.poll = lambda: process.returncode
        self.children.append((process, self.root / "private.out", self.root / "private.err"))
        return result["code"], result["output"], result["stderr"]

    def connection(self, host, port, timeout, context):
        assert (host, port, timeout) == ("127.0.0.1", self.fixture.port, 3)
        assert context is self.fixture.context
        scenario = self

        class Connection:
            closed = False

            def request(self, method, target, headers):
                assert (method, target) == ("POST", "/deletefile?fileid=301")
                assert headers == {"Authorization": "Bearer " + scenario.active.token}
                assert scenario.active.events == [("root_list", ""), ("checksum", "README-synthetic.txt")]
                scenario.active.events.append(("write_denied", "README-synthetic.txt"))
                scenario.active.requests += 1
                scenario.active.authenticated += 1
                scenario.active.rejected_mutations += 1

            def getresponse(self):
                return SimpleNamespace(status=405, read=lambda limit: b'{"status":"fixture_read_only"}')

            def close(self):
                self.closed = True

        connection = Connection()
        self.connections.append(connection)
        return connection

    def execute(self):
        module = SimpleNamespace(PCloudState=FakeState, serve_pcloud=self.serve)
        # Scope the lazy-import substitute and dependency mock to this execution.
        # Real installed-version predicates are tested separately by the runner tests.
        with mock.patch.dict(sys.modules, {"fixture_pcloud": module}), \
                mock.patch.object(LAB, "pcloud_dependencies") as dependencies, \
                mock.patch.object(LAB.http.client, "HTTPSConnection", self.connection), \
                mock.patch.object(LAB, "listener_closed", side_effect=lambda port: self.closed_ports):
            row = LAB.run_backend(self, "pcloud", self.root)
            self.dependency_checks = dependencies.call_count
            return row


class PCloudFinalizationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.sequence = 0

    def scenario(self, **kwargs):
        self.sequence += 1
        return Scenario(self.root / ("case-" + str(self.sequence)), **kwargs)

    def assert_failed(self, row, error):
        self.assertIn(error, row["errors"])
        self.assertEqual(set(row["capabilities"]), CAPS)
        self.assertTrue(all(row["capabilities"][name] != "passed" for name in CAPS - {"cleanup"}))

    def test_full_transcript_finishes_thirteen_children_and_forty_requests(self):
        scenario = self.scenario()
        row = scenario.execute()
        self.assertEqual(row["errors"], [])
        self.assertEqual(row["capabilities"], {name: "passed" for name in CAPS})
        self.assertEqual([config.stem.removeprefix("pcloud-") for _, config in scenario.calls], EXPECTED_LABELS)
        self.assertEqual(len(scenario.children), 13)
        self.assertEqual(sum(state.requests for state in scenario.states), 40)
        self.assertEqual(scenario.dependency_checks, 14)
        self.assertTrue(all(connection.closed for connection in scenario.connections))
        self.assertTrue(all(state.cleanup_complete for state in scenario.states))
        self.assertEqual({path.relative_to(scenario.root / "downloads").as_posix(): path.read_bytes()
                          for path in (scenario.root / "downloads").rglob("*") if path.is_file()}, PAYLOADS)

    def test_late_config_content_change_cannot_be_promoted_to_passed(self):
        def mutate(scenario):
            path = scenario.calls[0][1]
            path.write_bytes(path.read_bytes() + b"unexpected = synthetic\n")
        scenario = self.scenario(late_fault=mutate)
        self.assert_failed(scenario.execute(), "pcloud_config_changed")
        self.assertEqual(len(scenario.calls), 13)

    def test_late_source_bytes_or_metadata_change_cannot_pass(self):
        for field in ("bytes", "metadata"):
            def mutate(scenario):
                if field == "bytes":
                    scenario.states[0].files["README-synthetic.txt"] = b"changed"
                else:
                    scenario.states[0].metadata_preserved = False
            with self.subTest(field=field):
                scenario = self.scenario(late_fault=mutate)
                self.assert_failed(scenario.execute(), "pcloud_source_changed")
                self.assertEqual(len(scenario.calls), 13)

    def test_late_transport_failure_is_not_erased_by_successful_cleanup(self):
        scenario = self.scenario(late_fault=lambda value: value.fixtures[0].failures.append("tls_request_deadline"))
        row = scenario.execute()
        self.assert_failed(row, "pcloud_transport_failure")
        self.assertEqual(row["capabilities"]["cleanup"], "passed")
        self.assertEqual(len(scenario.calls), 13)

    def test_extra_finished_child_rejects_the_complete_transcript(self):
        scenario = self.scenario(late_fault=lambda value: value.children.append(value.children[0]))
        self.assert_failed(scenario.execute(), "pcloud_total_process_or_request_mismatch")
        self.assertEqual(len(scenario.calls), 13)

    def test_every_late_cleanup_boundary_remains_failed(self):
        for kind in ("state", "fixture", "listener", "child"):
            def mutate(scenario):
                if kind == "state":
                    scenario.states[0].cleanup_complete = False
                elif kind == "fixture":
                    scenario.fixtures[0].cleanup_complete = False
                elif kind == "listener":
                    scenario.closed_ports = False
                else:
                    scenario.children[0][0].returncode = None
            with self.subTest(kind=kind):
                scenario = self.scenario(late_fault=mutate)
                row = scenario.execute()
                self.assert_failed(row, "pcloud_cleanup_failed")
                self.assertEqual(row["capabilities"]["cleanup"], "failed")
                self.assertEqual(len(scenario.calls), 13)

    def test_late_output_mutation_or_negative_artifact_invalidates_final_inventory(self):
        for kind in ("changed", "extra", "negative"):
            def mutate(scenario):
                paths = {"changed": scenario.root / "downloads" / "README-synthetic.txt",
                         "extra": scenario.root / "downloads" / "extra.txt",
                         "negative": scenario.root / "negative-missing" / "partial"}
                paths[kind].write_bytes(b"unexpected")
            with self.subTest(kind=kind):
                scenario = self.scenario(late_fault=mutate)
                self.assert_failed(scenario.execute(), "pcloud_final_inventory_changed")

    def test_late_oauth_or_budget_failure_cannot_be_hidden_after_last_operation(self):
        for field in ("oauth_requests", "unexpected", "rejected_payload_bytes", "budget_exceeded"):
            scenario = self.scenario(late_fault=lambda value: setattr(value.states[0], field, 1))
            with self.subTest(field=field):
                self.assert_failed(scenario.execute(), "pcloud_unexpected_request_or_budget")

    def test_early_operation_error_never_reaches_completion_promotion(self):
        def fail(scenario, result):
            if scenario.label == "download-0":
                result["code"] = 1
        scenario = self.scenario(result_fault=fail)
        row = scenario.execute()
        self.assert_failed(row, "pcloud_download_mismatch")
        self.assertEqual(len(scenario.calls), 3)
        self.assertTrue(all(fixture.cleanup_complete for fixture in scenario.fixtures))

    def test_post_download_checksum_order_cannot_replace_observed_native_flow(self):
        def mutate(scenario, result):
            if scenario.label == "download-0":
                state = scenario.active
                state.events = [("root_list", ""), ("link", "README-synthetic.txt"),
                                ("content", "README-synthetic.txt"), ("checksum", "README-synthetic.txt")]
        scenario = self.scenario(result_fault=mutate)
        self.assert_failed(scenario.execute(), "pcloud_download_mismatch")


if __name__ == "__main__":
    unittest.main()
