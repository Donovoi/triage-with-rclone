"""Koofr verdict regressions: independent literals, mocked I/O, no listeners."""

import base64
import copy
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest import mock


LAB_ROOT = Path(__file__).parents[1] / "provider-lab"
sys.path.insert(0, str(LAB_ROOT))
try:
    import run_lab as LAB
finally:
    sys.path.pop(0)


# Independent literal bytes, not values loaded from the fixture implementation.
PAYLOADS = {
    "README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
    "nested/bytes.bin": bytes(range(256)) * 8,
    "nested/space name.txt": b"Nested synthetic payload.\n",
}
NAMES = sorted(PAYLOADS)
EXPECTED = [{"path": name, "size": len(body), "sha256": hashlib.sha256(body).hexdigest(),
             "md5": hashlib.md5(body).hexdigest()} for name, body in sorted(PAYLOADS.items())]
ABSENT_MOUNT_OUTPUT = (b'{\n\t"error": "loopback: call failed: failed to find mount absent-synthetic-mount",\n'
                       b'\t"path": "operations/copyfile",\n\t"status": 500\n}\n')


def item(name):
    return {"Path": name, "Name": name.rsplit("/", 1)[-1], "IsDir": False, "Size": len(PAYLOADS[name]),
            "Hashes": {"md5": hashlib.md5(PAYLOADS[name]).hexdigest()}, "ModTime": "2024-01-01T00:00:00.123Z"}


class FakeState:
    mount_id = "synthetic-mount"
    modified_ms = 1704067200123

    def __init__(self, user, password, mode="normal", *, wrong_password="wrong-synthetic-password"):
        self.user, self.password, self.mode, self.wrong_password = user, password, mode, wrong_password
        self.files = dict(PAYLOADS)
        self.events = []
        self.requests = self.authenticated = self.auth_denied = self.member_denied = 0
        self.missing = self.rejected_mutations = self.payload_bytes = self.unexpected = self.rejected_payload_bytes = 0
        self.budget_exceeded = self.cleanup_complete = False


def observed(kind, name="README-synthetic.txt"):
    """Literal expected traces; deliberately not derived from runner helpers."""
    state = FakeState("synthetic-user", "synthetic-password")
    if kind == "wrong_password":
        state.events = [("auth_denied", "")]
        state.auth_denied = 1
    elif kind == "absent_mount":
        state.events = [("mounts", "")]
    else:
        state.events = [("mounts", ""), ("root_info", "/")]
        if kind == "listing":
            state.events += [("list", "/"), ("list", "/nested")]
        elif kind in ("stat", "download", "write"):
            state.events += [("member_info", "/" + name)]
            if kind == "download":
                state.events += [("content", "/" + name)]
                state.payload_bytes = len(PAYLOADS[name])
            elif kind == "write":
                state.events += [("write_denied", "/README-synthetic.txt")]
                state.rejected_mutations = 1
        elif kind == "missing":
            state.events += [("file_missing", "/missing-synthetic-object.bin")]
            state.missing = 1
        elif kind == "member_denied":
            state.events += [("member_denied", "/README-synthetic.txt")]
            state.member_denied = 1
        else:
            raise AssertionError("unknown synthetic case")
    state.requests = len(state.events)
    state.authenticated = state.requests - state.auth_denied
    return state


class Scenario:
    """Run the real verdict code against independent mock process/HTTP results."""
    def __init__(self, root, *, mutate=None, after_case=None):
        self.root, self.mutate, self.after_case = root, mutate, after_case
        self.children, self.calls, self.states, self.connections = [], [], [], []
        self.active = None
        self.label = None
        self.pending = False
        self.extra_child = False

    @contextmanager
    def serve(self, backend, state):
        assert backend == "koofr"
        self.active = state
        self.states.append(state)
        try:
            yield 19000 + len(self.states)
        finally:
            if self.after_case:
                self.after_case(self)
            state.cleanup_complete = True

    def run(self, args, config=None, **kwargs):
        self.calls.append((args, config, kwargs))
        result = {"code": 0, "output": b"{}", "error": b""}
        if args[0] == "obscure":
            result["output"] = (b"synthetic_obscured_wrong_00001\n" if args[1] == "wrong-synthetic-password"
                                else b"synthetic_obscured_good_00001\n")
        else:
            self.label = config.stem.removeprefix("koofr-")
            label, name = self.label, "README-synthetic.txt"
            if label.startswith("listing-"):
                kind = "listing"
                result["output"] = json.dumps({"list": [item(n) for n in NAMES]}).encode()
            elif label.startswith("stat-") or label == "write-guard":
                kind = "stat"
                name = NAMES[int(label.removeprefix("stat-"))] if label.startswith("stat-") else name
                result["output"] = json.dumps({"item": item(name)}).encode()
            elif label.startswith("download-"):
                kind = "download"
                name = NAMES[int(label.removeprefix("download-"))]
                destination = self.root / "downloads" / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(PAYLOADS[name])
            elif label in ("missing-stat", "missing-copy"):
                kind, name = "missing", "missing-synthetic-object.bin"
                result["output"] = b'{"item":null}' if label == "missing-stat" else b""
                if label == "missing-copy":
                    result.update(code=1, error=b"object not found")
            else:
                kind = label
                if label == "absent_mount":
                    result.update(code=1, output=ABSENT_MOUNT_OUTPUT)
                else:
                    result.update(code=1, error=b"synthetic HTTP401 denial")
            oracle = observed(kind, name)
            for field in ("events", "requests", "authenticated", "auth_denied", "member_denied", "missing",
                          "rejected_mutations", "payload_bytes", "unexpected", "rejected_payload_bytes", "budget_exceeded"):
                setattr(self.active, field, copy.deepcopy(getattr(oracle, field)))
            if self.mutate:
                self.mutate(self, result)
        process = mock.Mock(pid=4200 + len(self.children))
        process.poll.return_value = None if self.pending else result["code"]
        record = (process, self.root / "private.out", self.root / "private.err")
        self.children.append(record)
        if self.extra_child:
            self.children.append(record)
        return result["code"], result["output"], result["error"]

    def connection(self, host, port, timeout):
        assert host == "127.0.0.1" and port == 19000 + len(self.states) and timeout == 3
        scenario = self

        class Connection:
            closed = False

            def request(self, method, target, headers):
                assert method == "DELETE"
                assert target == "/api/v2/mounts/synthetic-mount/files/remove?path=%2FREADME-synthetic.txt"
                decoded = base64.b64decode(headers["Authorization"].removeprefix("Basic ")).decode()
                assert decoded == scenario.active.user + ":" + scenario.active.password
                assert scenario.active.events == [("mounts", ""), ("root_info", "/"), ("member_info", "/README-synthetic.txt")]
                scenario.active.events.append(("write_denied", "/README-synthetic.txt"))
                scenario.active.requests += 1
                scenario.active.authenticated += 1
                scenario.active.rejected_mutations += 1

            def getresponse(self):
                return SimpleNamespace(status=405, read=lambda limit: b"synthetic fixture read only")

            def close(self):
                self.closed = True

        connection = Connection()
        self.connections.append(connection)
        return connection

    def execute(self, *, listener_closed=True):
        with mock.patch.object(LAB, "KoofrState", FakeState), mock.patch.object(LAB, "serve", self.serve), \
                mock.patch.object(LAB, "listener_closed", return_value=listener_closed), \
                mock.patch.object(LAB.http.client, "HTTPConnection", self.connection):
            return LAB.run_backend(self, "koofr", self.root)


class KoofrRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.sequence = 0

    def scenario(self, **kwargs):
        self.sequence += 1
        return Scenario(self.root / ("case-" + str(self.sequence)), **kwargs)

    def test_complete_mock_flow_has_exact_eight_capabilities_and_no_secret_receipt(self):
        scenario = self.scenario()
        row = scenario.execute()
        self.assertEqual(row["errors"], [])
        self.assertEqual(row["fixture_kind"], "independent_loopback")
        self.assertEqual(row["capabilities"], {name: "passed" for name in (
            "listing", "download_hash", "missing_object_rejection", "authentication_rejection", "source_preservation",
            "config_preservation", "fixture_write_rejection", "cleanup")})
        self.assertEqual(len(scenario.states), 14)
        self.assertEqual(len(scenario.calls), 16)  # Two obscure + fourteen bounded native reads.
        self.assertEqual(len(scenario.children), 16)
        self.assertTrue(all(connection.closed for connection in scenario.connections))
        encoded = json.dumps(row)
        for private in (str(self.root), scenario.states[0].user, scenario.states[0].password,
                        "synthetic_obscured_good_00001", "synthetic_obscured_wrong_00001", "127.0.0.1", "private.out"):
            self.assertNotIn(private, encoded)

    def test_generated_configs_and_native_methods_are_closed_to_owned_paths(self):
        scenario = self.scenario()
        self.assertEqual(scenario.execute()["errors"], [])
        for args, config, kwargs in scenario.calls:
            self.assertEqual(kwargs, {})
            if args[0] == "obscure":
                continue
            self.assertEqual(args[:2], ["rc", "--loopback"])
            text = config.read_text()
            self.assertIn("provider = other\n", text)
            self.assertIn("setmtime = true\n", text)
            self.assertRegex(text, r"endpoint = http://127\.0\.0\.1:190[0-9]{2}\n")
            expected_mount = "absent-synthetic-mount" if "absent_mount" in config.name else "synthetic-mount"
            self.assertIn("mountid = " + expected_mount + "\n", text)
            credential_kind = "wrong" if "wrong_password" in config.name else "good"
            self.assertIn("password = synthetic_obscured_" + credential_kind + "_00001\n", text)
            other_kind = "good" if credential_kind == "wrong" else "wrong"
            self.assertNotIn("synthetic_obscured_" + other_kind + "_00001", text)
            self.assertEqual(text.count("[Synthetic]"), 1)
            if args[2] in ("operations/stat", "operations/list"):
                self.assertEqual(args[3], "--json")
                request = json.loads(args[4])
                self.assertEqual(set(request), {"fs", "remote", "opt"})
                self.assertEqual(request["fs"], "Synthetic:")
                self.assertEqual(request["opt"]["hashTypes"], ["MD5"])
                self.assertIs(request["opt"]["noModTime"], False)
                self.assertIs(request["opt"]["filesOnly"], True)
                self.assertIn(request["remote"], ["", *NAMES, "missing-synthetic-object.bin"])
            else:
                self.assertEqual(args[2], "operations/copyfile")
                self.assertIn("srcFs=Synthetic:", args)
                self.assertTrue(any(arg.startswith("dstFs=" + str(scenario.root)) for arg in args))

    def test_environment_excludes_trace_proxy_config_and_real_credential_overrides(self):
        blocked = {"HTTPCLIENT_TRACE": "1", "RCLONE_CONFIG": "private", "RCLONE_KOOFR_ENDPOINT": "https://example.com",
                   "RCLONE_DUMP": "auth", "HTTP_PROXY": "private", "HTTPS_PROXY": "private", "ALL_PROXY": "private",
                   "AWS_SECRET_ACCESS_KEY": "private", "SSH_AUTH_SOCK": "private", "LISTEN_FDS": "3"}
        with mock.patch.dict(os.environ, blocked):
            isolated = LAB.isolated_environment(self.root)
        self.assertTrue(set(blocked).isdisjoint(isolated))

    def test_option_and_metadata_request_builders_reject_arbitrary_endpoints_members(self):
        state = FakeState("synthetic-user", "synthetic-password")
        for port in (True, 0, 65536, "443"):
            with self.assertRaises(LAB.LabError):
                LAB.koofr_options(state, port, "synthetic_obscured_password")
        for field, value in (("mount_id", "../other"), ("modified_ms", 1704067200000)):
            changed = copy.copy(state)
            setattr(changed, field, value)
            with self.assertRaises(LAB.LabError):
                LAB.koofr_options(changed, 19001, "synthetic_obscured_password")
        for kind, member in (("copyfile", ""), ("list", "nested"), ("stat", "../escape"), ("stat", "Other:member")):
            with self.assertRaises(LAB.LabError):
                LAB.koofr_metadata_args(kind, member)

    def test_literal_metadata_accepts_equivalent_zone_and_order(self):
        entries = [item(name) for name in reversed(NAMES)]
        for entry in entries:
            entry["ModTime"] = "2024-01-01T11:00:00.123000000+11:00"
        self.assertTrue(LAB.koofr_metadata_matches(json.dumps({"list": entries}).encode(), EXPECTED))
        self.assertTrue(LAB.koofr_metadata_matches(json.dumps({"item": item(NAMES[0])}).encode(), EXPECTED[:1], stat_result=True))

    def test_metadata_rejects_malformed_success_duplicate_and_every_wrong_field(self):
        for output in (b"{}", b"null", b'{"list":null}', b'{"list":[]}', b'{"list":[],"list":[]}', b'{"list":NaN}', b"\xff"):
            self.assertFalse(LAB.koofr_metadata_matches(output, EXPECTED))
        for changes in ({"Path": "wrong"}, {"Name": "wrong"}, {"Size": True}, {"Size": 0}, {"IsDir": 0},
                        {"Hashes": {}}, {"Hashes": {"MD5": "0" * 32}}, {"Hashes": {"md5": 1}}, {"extra": True}):
            entry = dict(item(NAMES[0]), **changes)
            self.assertFalse(LAB.koofr_metadata_matches(json.dumps({"item": entry}).encode(), EXPECTED[:1], stat_result=True))
        entries = [item(name) for name in NAMES]
        entries[1] = entries[0]
        self.assertFalse(LAB.koofr_metadata_matches(json.dumps({"list": entries}).encode(), EXPECTED))

    def test_timestamp_requires_exact_milliseconds_without_truncating_nanos_or_overflow(self):
        values = ("2024-01-01T00:00:00Z", "2024-01-01T00:00:00.123000001Z", "2024-01-01T00:00:00.1230001Z",
                  "2024-01-01T00:00:00.124Z", "2024-01-01T00:00:00.123-00:00", "2024-01-01T00:00:00.123+24:00",
                  "2024-01-01T00:00:00.123", "0001-01-01T00:00:00.123+23:59", "9999-12-31T23:59:59.123-23:59")
        for value in values:
            entry = dict(item(NAMES[0]), ModTime=value)
            with self.subTest(value=value):
                self.assertFalse(LAB.koofr_metadata_matches(json.dumps({"item": entry}).encode(), EXPECTED[:1], stat_result=True))

    def test_each_operation_requires_exact_member_setup_order_and_counters(self):
        for kind in ("listing", "stat", "download", "missing", "wrong_password", "member_denied", "absent_mount", "write"):
            name = "missing-synthetic-object.bin" if kind == "missing" else NAMES[0]
            size = len(PAYLOADS[NAMES[0]]) if kind == "download" else 0
            state = observed(kind)
            self.assertTrue(LAB.koofr_flow_matches(state, kind, name, size))
            for field in ("requests", "authenticated", "auth_denied", "member_denied", "missing", "rejected_mutations",
                          "payload_bytes", "unexpected", "rejected_payload_bytes"):
                changed = copy.deepcopy(state)
                setattr(changed, field, getattr(changed, field) + 1)
                self.assertFalse(LAB.koofr_flow_matches(changed, kind, name, size), (kind, field))
                setattr(changed, field, False)
                self.assertFalse(LAB.koofr_flow_matches(changed, kind, name, size), (kind, field))
            for events in (state.events[1:], list(reversed(state.events)), state.events + [("mounts", "")]):
                if events == state.events:
                    continue
                changed = copy.deepcopy(state)
                changed.events, changed.requests = events, len(events)
                changed.authenticated = changed.requests - changed.auth_denied
                self.assertFalse(LAB.koofr_flow_matches(changed, kind, name, size), kind)

    def test_root_denial_content_missing_and_wrong_member_do_not_qualify_negatives(self):
        for kind, changed_event in (("missing", ("content_missing", "/missing-synthetic-object.bin")),
                                    ("member_denied", ("member_denied", "/")),
                                    ("stat", ("member_info", "/nested/bytes.bin"))):
            state = observed(kind)
            state.events[-1] = changed_event
            member = "missing-synthetic-object.bin" if kind == "missing" else NAMES[0]
            self.assertFalse(LAB.koofr_flow_matches(state, kind, member))
        state = observed("wrong_password")
        state.events = [("auth_denied", "/README-synthetic.txt")]
        self.assertFalse(LAB.koofr_flow_matches(state, "wrong_password"))

    def test_download_requires_exact_trace_size_and_file_content(self):
        state = observed("download")
        self.assertFalse(LAB.koofr_flow_matches(state, "download", NAMES[0], True))
        self.assertFalse(LAB.koofr_flow_matches(state, "download", NAMES[0], 1))
        def corrupt(scenario, result):
            if scenario.label == "download-0":
                (scenario.root / "downloads" / NAMES[0]).write_bytes(b"corrupt")
        self.assertIn("koofr_download_mismatch", self.scenario(mutate=corrupt).execute()["errors"])

    def test_missing_copy_needs_exact_error_and_no_partial_artifact(self):
        for mutation in (lambda s, r: r.update(error=b"unrelated failure"),
                         lambda s, r: (s.root / "negative-missing/partial").write_bytes(b"bad"),
                         lambda s, r: r.update(code=0)):
            def inject(scenario, result):
                if scenario.label == "missing-copy":
                    mutation(scenario, result)
            self.assertIn("koofr_missing_copy_mismatch", self.scenario(mutate=inject).execute()["errors"])

    def test_absent_mount_error_cannot_be_an_unrelated_nonzero_failure(self):
        def change(scenario, result):
            if scenario.label == "absent_mount":
                result["output"] = b'{"error":"connection refused","path":"operations/copyfile","status":500}'
        self.assertIn("koofr_wrong_mount_error", self.scenario(mutate=change).execute()["errors"])

    def test_absent_mount_accepts_exact_structured_stdout_with_empty_stderr(self):
        self.assertEqual(len(ABSENT_MOUNT_OUTPUT), 131)
        self.assertTrue(LAB.koofr_absent_mount_error_matches(ABSENT_MOUNT_OUTPUT))
        observed_absent = []
        def inspect(scenario, result):
            if scenario.label == "absent_mount":
                observed_absent.append((result["output"], result["error"]))
        self.assertEqual(self.scenario(mutate=inspect).execute()["errors"], [])
        self.assertEqual(observed_absent, [(ABSENT_MOUNT_OUTPUT, b"")])

    def test_absent_mount_requires_exact_typed_error_contract(self):
        expected = json.loads(ABSENT_MOUNT_OUTPUT)
        variants = []
        for field, values in {
            "status": (404, 500.0, True, "500", None),
            "path": ("operations/stat", "operations/copyfile/", None),
            "error": ("failed to find mount absent-synthetic-mount",
                      "loopback: call failed: failed to find mount another-mount",
                      "loopback: call failed: unexpected: failed to find mount absent-synthetic-mount",
                      "loopback: call failed: failed to find mount absent-synthetic-mount\n", None),
        }.items():
            for value in values:
                variants.append({**expected, field: value})
        variants.append({**expected, "extra": None})
        variants.extend({key: value for key, value in expected.items() if key != missing} for missing in expected)
        for data in variants:
            with self.subTest(data=data):
                output = json.dumps(data).encode()
                self.assertFalse(LAB.koofr_absent_mount_error_matches(output))
                def change(scenario, result):
                    if scenario.label == "absent_mount":
                        result["output"] = output
                self.assertIn("koofr_wrong_mount_error", self.scenario(mutate=change).execute()["errors"])

    def test_absent_mount_rejects_malformed_duplicate_or_stderr_only_errors(self):
        for output in (b"", b"null", b"[]", ABSENT_MOUNT_OUTPUT[:-2], b"\xff",
                       ABSENT_MOUNT_OUTPUT.replace(b'"status": 500', b'"status": 500, "status": 500'),
                       ABSENT_MOUNT_OUTPUT.replace(b'"status": 500', b'"status": NaN'),
                       ABSENT_MOUNT_OUTPUT + b"{}"):
            with self.subTest(output=output):
                def change(scenario, result):
                    if scenario.label == "absent_mount":
                        result.update(output=output, error=ABSENT_MOUNT_OUTPUT)
                self.assertIn("koofr_wrong_mount_error", self.scenario(mutate=change).execute()["errors"])

    def test_absent_mount_structured_error_still_requires_observed_failure_and_empty_tree(self):
        for alteration in ("success", "unobserved", "artifact"):
            with self.subTest(alteration=alteration):
                def change(scenario, result):
                    if scenario.label != "absent_mount":
                        return
                    if alteration == "success":
                        result["code"] = 0
                    elif alteration == "unobserved":
                        scenario.active.events = []
                    else:
                        (scenario.root / "negative-absent_mount" / "partial").write_bytes(b"bad")
                row = self.scenario(mutate=change).execute()
                self.assertIn("koofr_absent_mount_not_observed", row["errors"])
                self.assertEqual(row["capabilities"]["authentication_rejection"], "not_run")

    def test_generic_auth_exit_and_success_after_denial_are_not_acceptance(self):
        for mode in ("wrong_password", "member_denied"):
            for alteration in ("success", "unobserved", "artifact"):
                def change(scenario, result):
                    if scenario.label != mode:
                        return
                    if alteration == "success":
                        result["code"] = 0
                    elif alteration == "unobserved":
                        scenario.active.events = []
                    else:
                        (scenario.root / ("negative-" + mode) / "partial").write_bytes(b"bad")
                row = self.scenario(mutate=change).execute()
                self.assertIn("koofr_" + mode + "_not_observed", row["errors"])
                self.assertEqual(row["capabilities"]["authentication_rejection"], "not_run")

    def test_final_inventory_detects_prior_file_change_extra_directory_and_negative_sibling(self):
        mutations = [lambda root: (root / "downloads" / NAMES[0]).write_bytes(b"changed later"),
                     lambda root: (root / "downloads/extra").mkdir(),
                     lambda root: (root / "negative-wrong_password/partial").write_bytes(b"late")]
        for mutation in mutations:
            def change(scenario, result):
                if scenario.label == "listing-final":
                    mutation(scenario.root)
            self.assertIn("koofr_final_inventory_changed", self.scenario(mutate=change).execute()["errors"])

    def test_source_bytes_metadata_mount_and_config_changes_cannot_pass_preservation(self):
        changes = [(lambda s: s.active.files.update({NAMES[0]: b"changed"}), "koofr_source_changed"),
                   (lambda s: setattr(s.active, "modified_ms", 1704067200000), "koofr_source_changed"),
                   (lambda s: setattr(s.active, "mount_id", "other"), "koofr_source_changed"),
                   (lambda s: (s.root / "koofr-listing-final.conf").write_text("changed"), "koofr_config_changed")]
        for change, error in changes:
            def mutate(scenario, result):
                if scenario.label == "listing-final":
                    change(scenario)
            self.assertIn(error, self.scenario(mutate=mutate).execute()["errors"])

    def test_extra_child_and_forced_exit_or_unreaped_process_fail(self):
        for failure in ("extra", "forced", "pending"):
            def change(scenario, result):
                if scenario.label != "listing-initial":
                    return
                if failure == "extra":
                    scenario.extra_child = True
                elif failure == "forced":
                    result["code"] = -15
                else:
                    scenario.pending = True
            row = self.scenario(mutate=change).execute()
            self.assertTrue(row["errors"])
            self.assertEqual(row["capabilities"]["listing"], "not_run")
            if failure == "pending":
                self.assertEqual(row["capabilities"]["cleanup"], "failed")

    def test_listener_or_handler_cleanup_failure_cannot_pass(self):
        row = self.scenario().execute(listener_closed=False)
        self.assertIn("koofr_cleanup_failed", row["errors"])
        self.assertEqual(row["capabilities"]["cleanup"], "failed")
        def fail(scenario):
            raise RuntimeError("synthetic handler failed to close")
        row = self.scenario(after_case=fail).execute()
        self.assertIn("koofr_cleanup_failed", row["errors"])

    def test_write_guard_requires_405_bounded_response_and_closes_client_on_failure(self):
        for status, body in ((200, b"accepted"), (401, b"wrong authentication"), (405, b"x" * 1025)):
            scenario = self.scenario()
            original = scenario.connection

            def connection(host, port, timeout):
                client = original(host, port, timeout)
                client.getresponse = lambda: SimpleNamespace(status=status, read=lambda limit: body)
                return client

            scenario.connection = connection
            row = scenario.execute()
            self.assertIn("koofr_write_guard_not_observed", row["errors"])
            self.assertEqual(row["capabilities"]["fixture_write_rejection"], "not_run")
            self.assertTrue(scenario.connections[0].closed)


if __name__ == "__main__":
    unittest.main()
