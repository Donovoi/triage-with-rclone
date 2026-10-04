"""FileFabric verdict checks against literal oracles; no process or listener."""

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


sys.path.insert(0, str(Path(__file__).parents[1] / "provider-lab"))
try:
    import run_lab as LAB
finally:
    sys.path.pop(0)


# Independent known bytes and identities, not imported from fixture state.
PAYLOADS = {
    "README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
    "nested/bytes.bin": bytes(range(256)) * 8,
    "nested/space name.txt": b"Nested synthetic payload.\n",
}
NAMES = sorted(PAYLOADS)
EXPECTED = [{"path": name, "size": len(body), "sha256": hashlib.sha256(body).hexdigest()}
            for name, body in sorted(PAYLOADS.items())]
ERRORS = {
    "missing": b'{"error":"loopback: call failed: object not found","path":"operations/copyfile","status":500}',
    "wrong_token": b'{"error":"loopback: call failed: failed to check path exists: Synthetic cached session denied (login_token_expired)",'
                 b'"path":"operations/copyfile","status":500}',
    "member_denied": b'{"error":"loopback: call failed: failed to check path exists: Synthetic member denied (fixture_member_denied)","path":"operations/copyfile","status":500}',
}
WRITE_BODY = b'{"status":"fixture_read_only"}'


def item(name):
    return {"Path": name, "Name": name.rsplit("/", 1)[-1], "Size": len(PAYLOADS[name]), "IsDir": False,
            "ID": {"README-synthetic.txt": "301", "nested/bytes.bin": "302", "nested/space name.txt": "303"}[name],
            "ModTime": "2024-01-01T00:00:00Z"}


class FakeState:
    root_id, nested_id = "100", "200"
    modified, localtime = "2024-01-02 00:00:00", "2024-01-01 00:00:00"
    ids = {"README-synthetic.txt": "301", "nested/bytes.bin": "302", "nested/space name.txt": "303"}

    def __init__(self, token, mode="normal", *, wrong_token="wrong-synthetic-session"):
        self.token, self.mode, self.wrong_token = token, mode, wrong_token
        self.files, self.events = dict(PAYLOADS), []
        self.requests = self.authenticated = self.auth_denied = self.member_denied = self.missing = 0
        self.rejected_mutations = self.payload_bytes = self.unexpected = self.rejected_payload_bytes = 0
        self.budget_exceeded = self.cleanup_complete = False


def observed(kind, member="README-synthetic.txt"):
    """Literal expected RPC sequence, independent from the verdict builder."""
    state = FakeState("synthetic-token")
    if kind == "listing":
        state.events = [("listing", "100"), ("listing", "200")]
    elif kind in ("stat", "download", "write"):
        state.events = [("member_stat", member)]
        if kind == "download":
            state.events += [("content", member)]
            state.payload_bytes = len(PAYLOADS[member])
        if kind == "write":
            state.events += [("write_denied", member)]
            state.rejected_mutations = 1
    elif kind == "missing":
        state.events = [("file_missing", "missing-synthetic-object.bin")]
        state.missing = 1
    elif kind == "wrong_token":
        state.events = [("auth_denied", "README-synthetic.txt")]
        state.auth_denied = 1
    elif kind == "member_denied":
        state.events = [("member_denied", "README-synthetic.txt")]
        state.member_denied = 1
    state.requests = len(state.events)
    state.authenticated = state.requests - state.auth_denied
    return state


class Scenario:
    def __init__(self, root, *, mutate=None, after_case=None):
        self.root, self.mutate, self.after_case = root, mutate, after_case
        self.calls, self.children, self.states, self.connections = [], [], [], []
        self.active = self.label = None
        self.pending = self.extra_child = False

    @contextmanager
    def serve(self, backend, state):
        assert backend == "filefabric"
        self.active = state
        self.states.append(state)
        try:
            yield 18000 + len(self.states)
        finally:
            state.cleanup_complete = True
            if self.after_case:
                self.after_case(self)

    def run(self, args, config=None, **kwargs):
        self.calls.append((args, config, kwargs))
        assert config is not None and args[:2] == ["rc", "--loopback"]
        label = self.label = config.stem.removeprefix("filefabric-")
        result = {"code": 0, "output": b"{}", "error": b""}
        member = "README-synthetic.txt"
        if label.startswith("listing-"):
            kind = "listing"
            result["output"] = json.dumps({"list": [item(name) for name in NAMES]}).encode()
        elif label.startswith("stat-") or label == "write-guard":
            kind = "stat"
            member = NAMES[int(label[5:])] if label.startswith("stat-") else member
            result["output"] = json.dumps({"item": item(member)}).encode()
        elif label.startswith("download-"):
            kind = "download"
            member = NAMES[int(label[9:])]
            target = self.root / "downloads" / member
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(PAYLOADS[member])
        elif label in ("missing-stat", "missing-copy"):
            kind, member = "missing", "missing-synthetic-object.bin"
            result["output"] = b'{"item":null}'
            if label == "missing-copy":
                result.update(code=1, output=ERRORS["missing"])
        else:
            kind = label
            result.update(code=1, output=ERRORS[kind])
        oracle = observed(kind, member)
        for name in ("events", "requests", "authenticated", "auth_denied", "member_denied", "missing", "rejected_mutations",
                     "payload_bytes", "unexpected", "rejected_payload_bytes", "budget_exceeded"):
            setattr(self.active, name, copy.deepcopy(getattr(oracle, name)))
        if self.mutate:
            self.mutate(self, result)
        process = mock.Mock(pid=4300 + len(self.children))
        process.poll.return_value = None if self.pending else result["code"]
        record = (process, self.root / "private.out", self.root / "private.err")
        self.children.append(record)
        if self.extra_child:
            self.children.append(record)
        return result["code"], result["output"], result["error"]

    def connection(self, host, port, timeout):
        assert host == "127.0.0.1" and port == 18000 + len(self.states) and timeout == 3
        scenario = self

        class Connection:
            closed = False

            def request(self, method, target, body, headers):
                assert method == "POST" and target == "/api/rpc.php"
                assert headers == {"Content-Type": "application/x-www-form-urlencoded"}
                assert dict(LAB.urllib.parse.parse_qsl(body)) == {"function": "doDeleteFile", "token": scenario.active.token,
                      "apiformat": "json", "fi_id": "301", "completedeletion": "n"}
                assert scenario.active.events == [("member_stat", "README-synthetic.txt")]
                scenario.active.events.append(("write_denied", "README-synthetic.txt"))
                scenario.active.requests += 1
                scenario.active.authenticated += 1
                scenario.active.rejected_mutations += 1

            def getresponse(self):
                return SimpleNamespace(status=405, read=lambda limit: WRITE_BODY)

            def close(self):
                self.closed = True

        connection = Connection()
        self.connections.append(connection)
        return connection

    def execute(self, *, listener_closed=True):
        with mock.patch.object(LAB, "FileFabricState", FakeState), mock.patch.object(LAB, "serve", self.serve), \
                mock.patch.object(LAB, "listener_closed", return_value=listener_closed), \
                mock.patch.object(LAB.http.client, "HTTPConnection", self.connection):
            return LAB.run_backend(self, "filefabric", self.root)


class FileFabricRunnerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root, self.sequence = Path(temporary.name), 0

    def scenario(self, **kwargs):
        self.sequence += 1
        return Scenario(self.root / ("case-" + str(self.sequence)), **kwargs)

    def test_expiry_guard_prevents_implicit_grant_before_child(self):
        from datetime import datetime, timedelta, timezone
        for expiry in ("2020-01-01T00:00:00Z", (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat(),
                       "2030-01-01T00:00:00"):
            path = self.root / "expiry.conf"
            path.write_text("token_expiry = " + expiry + "\n")
            with self.assertRaises((LAB.LabError, ValueError)):
                LAB.filefabric_cache_fresh(path)
        for port in (0, -1, 65536, True, "80"):
            with self.assertRaises(LAB.LabError):
                LAB.filefabric_options(FakeState("synthetic"), port)

    def test_wrong_session_config_changes_only_cached_token(self):
        scenario = self.scenario()
        self.assertEqual(scenario.execute()["errors"], [])
        valid = (scenario.root / "filefabric-wrong_token-valid.conf").read_text()
        invalid = (scenario.root / "filefabric-wrong_token.conf").read_text()
        self.assertEqual(invalid, valid.replace("token = " + scenario.states[0].token + "\n",
                                               "token = wrong-synthetic-session\n"))

    def test_required_exact_file_ids_and_no_unexpected_fields(self):
        original = {"item": item(NAMES[0])}
        self.assertTrue(LAB.filefabric_metadata_matches(json.dumps(original).encode(), EXPECTED[:1], stat_result=True))
        for value in (None, "", "302", "100", 301, True):
            changed = copy.deepcopy(original)
            changed["item"]["ID"] = value
            self.assertFalse(LAB.filefabric_metadata_matches(json.dumps(changed).encode(), EXPECTED[:1], stat_result=True))
        for alteration in ("missing", "extra"):
            changed = copy.deepcopy(original)
            if alteration == "missing":
                del changed["item"]["ID"]
            else:
                changed["item"]["OrigID"] = "301"
            self.assertFalse(LAB.filefabric_metadata_matches(json.dumps(changed).encode(), EXPECTED[:1], stat_result=True))

    def test_complete_independent_flow_and_receipt_scope(self):
        scenario = self.scenario()
        row = scenario.execute()
        self.assertEqual(row["errors"], [])
        self.assertEqual(row["fixture_kind"], "independent_loopback")
        self.assertEqual(row["capabilities"], {name: "passed" for name in (
            "listing", "download_hash", "missing_object_rejection", "authentication_rejection", "source_preservation",
            "config_preservation", "fixture_write_rejection", "cleanup")})
        self.assertEqual((len(scenario.states), len(scenario.calls), len(scenario.children)), (13, 13, 13))
        self.assertTrue(all(client.closed for client in scenario.connections))
        for secret in (str(self.root), scenario.states[0].token, "127.0.0.1", "private.out"):
            self.assertNotIn(secret, json.dumps(row))
        other = self.scenario()
        self.assertEqual(other.execute()["errors"], [])
        self.assertNotEqual(scenario.states[0].token, other.states[0].token)

    def test_literal_config_and_request_arguments_use_fixed_root_id(self):
        scenario = self.scenario()
        self.assertEqual(scenario.execute()["errors"], [])
        for index, (args, config, kwargs) in enumerate(scenario.calls, 1):
            self.assertEqual(kwargs, {})
            self.assertEqual(args[:2], ["rc", "--loopback"])
            options = dict(line.split(" = ", 1) for line in config.read_text().splitlines() if " = " in line)
            self.assertEqual(set(options), {"type", "url", "root_folder_id", "token", "token_expiry", "permanent_token", "version"})
            self.assertEqual({key: options[key] for key in ("type", "url", "root_folder_id", "token", "version")},
                             {"type": "filefabric", "url": f"http://127.0.0.1:{18000 + index}", "root_folder_id": "100",
                              "token": "wrong-synthetic-session" if "wrong_token" in config.name else scenario.states[0].token,
                              "version": "2006.02"})
            self.assertTrue(options["permanent_token"].startswith("unused-synthetic-"))
            LAB.filefabric_cache_fresh(config)
            if args[2] == "operations/copyfile":
                self.assertEqual(len(args), 7)
                data = dict(argument.split("=", 1) for argument in args[3:])
                self.assertEqual(set(data), {"srcFs", "srcRemote", "dstFs", "dstRemote"})
                self.assertEqual(data["srcFs"], "Synthetic:")
                self.assertIn(data["srcRemote"], (*NAMES, "missing-synthetic-object.bin"))
                self.assertEqual(data["srcRemote"], data["dstRemote"])
                self.assertTrue(Path(data["dstFs"]).is_relative_to(scenario.root))
            else:
                self.assertEqual(args[3], "--json")
                self.assertEqual(len(args), 5)
                data = json.loads(args[4])
                self.assertEqual(set(data), {"fs", "remote", "opt"})
                self.assertEqual(data["fs"], "Synthetic:")
                expected = {"filesOnly": True, "showHash": True, "noModTime": False, "noMimeType": True}
                if args[2] == "operations/list":
                    self.assertEqual(data["remote"], "")
                    expected["recurse"] = True
                else:
                    self.assertEqual(args[2], "operations/stat")
                    self.assertIn(data["remote"], (*NAMES, "missing-synthetic-object.bin"))
                self.assertEqual(data["opt"], expected)

    def test_environment_excludes_ambient_proxies_credentials_and_tracing(self):
        names = ("HTTPCLIENT_TRACE", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "NO_PROXY",
                 "RCLONE_CONFIG", "RCLONE_CONFIG_SYNTHETIC_API_KEY", "RCLONE_PIXELDRAIN_API_URL", "RCLONE_DUMP",
                 "PIXELDRAIN_API_KEY", "AWS_ACCESS_KEY_ID", "AZURE_STORAGE_KEY")
        with mock.patch.dict(os.environ, {name: "must-not-inherit" for name in names}):
            environment = LAB.isolated_environment(self.root)
        self.assertTrue(all(name not in environment for name in names if name != "NO_PROXY"))
        self.assertEqual(environment["NO_PROXY"], "*")

    def test_metadata_requires_exact_members_sizes_aware_seconds_and_no_backend_hash(self):
        output = {"list": [item(name) for name in NAMES]}
        self.assertTrue(LAB.filefabric_metadata_matches(json.dumps(output).encode(), EXPECTED))
        for field, values in {"Size": (True, "59", -1), "IsDir": (0, True), "Name": ("wrong",),
                              "Path": ("../escape",), "ModTime": ("2024-01-02T00:00:00Z", "2024-01-01T00:00:00", "2024-01-01T00:00:00.001Z"),
                              "Hashes": (None, [], {"sha256": "a" * 64})}.items():
            for value in values:
                changed = copy.deepcopy(output)
                changed["list"][0][field] = value
                self.assertFalse(LAB.filefabric_metadata_matches(json.dumps(changed).encode(), EXPECTED), (field,value))
        for value in ({}, {"list": []}, {"list": output["list"] + [output["list"][0]]}):
            self.assertFalse(LAB.filefabric_metadata_matches(json.dumps(value).encode(), EXPECTED))
        for node in output["list"]:
            node["Hashes"] = {}
        self.assertTrue(LAB.filefabric_metadata_matches(json.dumps(output).encode(), EXPECTED))

    def test_complete_metadata_allows_order_and_equivalent_precise_timezone(self):
        values = [item(name) for name in reversed(NAMES)]
        for value in values:
            value["ModTime"] = "2024-01-01T11:00:00+11:00"
        self.assertTrue(LAB.filefabric_metadata_matches(json.dumps({"list": values}).encode(), EXPECTED))
        self.assertTrue(LAB.filefabric_metadata_matches(json.dumps({"item": item(NAMES[0])}).encode(), EXPECTED[:1], stat_result=True))

    def test_metadata_rejects_malformed_empty_duplicate_and_nonfinite_success(self):
        values = [b"{}", b"null", b'{"list":null}', b'{"list":[]}', b'{"list":[],"list":[]}', b"\xff",
                  b'{"list":NaN}', json.dumps({"list": [item(NAMES[0])] * 3}).encode(),
                  json.dumps({"list": [item(name) for name in NAMES], "extra": None}).encode()]
        for output in values:
            self.assertFalse(LAB.filefabric_metadata_matches(output, EXPECTED))

    def test_wrong_prefix_type_size_name_hash_and_missing_fields_cannot_pass(self):
        mutations = {"ID": "302", "Path": "/me/README-synthetic.txt", "Name": "different", "Size": True, "IsDir": True,
                     "Hashes": {"sha256": "0" * 64}, "ModTime": None}
        for field, wrong in mutations.items():
            for remove in (False, True):
                entry = item(NAMES[0])
                if remove and field == "Hashes":
                    continue
                if remove:
                    del entry[field]
                else:
                    entry[field] = wrong
                self.assertFalse(LAB.filefabric_metadata_matches(json.dumps({"item": entry}).encode(), EXPECTED[:1], stat_result=True))
        for hashes in ({"SHA-256": EXPECTED[0]["sha256"]}, {"sha256": EXPECTED[0]["sha256"].upper()},
                       {"sha256": EXPECTED[0]["sha256"], "md5": "0" * 32}):
            entry = {**item(NAMES[0]), "Hashes": hashes}
            self.assertFalse(LAB.filefabric_metadata_matches(json.dumps({"item": entry}).encode(), EXPECTED[:1], stat_result=True))

    def test_timestamp_rejects_nanosecond_drift_truncation_naive_and_overflow(self):
        for stamp in ("2024-01-01T00:00:00.123000001Z", "2024-01-01T00:00:00.123001Z", "2024-01-01T00:00:01Z",
                      "2024-01-01T00:00:00.123", "2024-01-01T00:00:00.123-00:00", "2024-01-01T00:00:00.123+24:00",
                      "0001-01-01T00:00:00.123+23:59", "9999-12-31T23:59:59.123-23:59", "2024-02-30T00:00:00.123Z"):
            entry = {**item(NAMES[0]), "ModTime": stamp}
            self.assertFalse(LAB.filefabric_metadata_matches(json.dumps({"item": entry}).encode(), EXPECTED[:1], stat_result=True))

    def test_every_native_flow_binds_order_members_counts_and_successful_setup(self):
        for kind in ("listing", "stat", "download", "missing", "wrong_token", "member_denied", "write"):
            member = "missing-synthetic-object.bin" if kind == "missing" else NAMES[0]
            size = len(PAYLOADS[NAMES[0]]) if kind == "download" else 0
            state = observed(kind, member)
            self.assertTrue(LAB.filefabric_flow_matches(state, kind, member, size), kind)
            for field in ("requests", "authenticated", "auth_denied", "member_denied", "missing", "rejected_mutations",
                          "payload_bytes", "unexpected", "rejected_payload_bytes"):
                for wrong in (-1, True, getattr(state, field) + 1):
                    changed = copy.deepcopy(state)
                    setattr(changed, field, wrong)
                    self.assertFalse(LAB.filefabric_flow_matches(changed, kind, member, size), (kind, field, wrong))
            for events in ([], list(reversed(state.events)), state.events + [("content", NAMES[0])]):
                if events == state.events:
                    continue
                changed = copy.deepcopy(state)
                changed.events = events
                self.assertFalse(LAB.filefabric_flow_matches(changed, kind, member, size))

    def test_root_error_or_content_missing_cannot_substitute_designated_member_failure(self):
        for kind in ("wrong_token", "member_denied", "missing"):
            for event in (("root_stat", "/"), ("content_missing", "missing-synthetic-object.bin"),
                          ("member_denied", "nested/bytes.bin"), ("file_missing", "README-synthetic.txt")):
                state = observed(kind)
                state.events[-1] = event
                self.assertFalse(LAB.filefabric_flow_matches(state, kind, "missing-synthetic-object.bin"))

    def test_structured_errors_require_exact_kind_status_path_and_no_other_keys(self):
        for kind, output in ERRORS.items():
            self.assertTrue(LAB.filefabric_error_matches(output, kind))
            original = json.loads(output)
            for field, values in {"status": (404, True, 500.0, "500"), "path": ("operations/stat", None),
                                  "error": ("unrelated error", original["error"] + "\n", original["error"][10:])}.items():
                for value in values:
                    self.assertFalse(LAB.filefabric_error_matches(json.dumps({**original, field: value}).encode(), kind))
            self.assertFalse(LAB.filefabric_error_matches(json.dumps({**original, "extra": None}).encode(), kind))
            for missing in original:
                self.assertFalse(LAB.filefabric_error_matches(json.dumps({k: v for k, v in original.items() if k != missing}).encode(), kind))
            for wrong_kind in set(ERRORS) - {kind}:
                self.assertFalse(LAB.filefabric_error_matches(output, wrong_kind))
            for malformed in (b"", b"null", b"[]", b"\xff", output[:-1], output + b"{}",
                              output.replace(b'"status":500', b'"status":500,"status":500'),
                              output.replace(b'"status":500', b'"status":NaN')):
                self.assertFalse(LAB.filefabric_error_matches(malformed, kind))
        self.assertFalse(LAB.filefabric_error_matches(ERRORS["missing"], "unknown"))

    def test_missing_stat_requires_null_item_and_observed_semantic_absence(self):
        for wrong in (b"{}", b'{"item":{}}', b'{"item":null,"extra":true}'):
            def change(scenario, result):
                if scenario.label == "missing-stat":
                    result["output"] = wrong
            self.assertIn("filefabric_missing_stat_mismatch", self.scenario(mutate=change).execute()["errors"])

    def test_all_native_negatives_require_stdout_error_exit_trace_and_no_partial(self):
        for label, kind in (("missing-copy", "missing"), ("wrong_token", "wrong_token"), ("member_denied", "member_denied")):
            for alteration in ("success", "stderr_only", "other_error", "unobserved", "partial"):
                def change(scenario, result):
                    if scenario.label != label:
                        return
                    if alteration == "success":
                        result["code"] = 0
                    elif alteration == "stderr_only":
                        result.update(error=result["output"], output=b"")
                    elif alteration == "other_error":
                        result["output"] = ERRORS["missing" if kind != "missing" else "member_denied"]
                    elif alteration == "unobserved":
                        scenario.active.events = []
                    else:
                        (scenario.root / ("negative-" + kind) / "partial").write_bytes(b"bad")
                row = self.scenario(mutate=change).execute()
                self.assertIn("filefabric_" + kind + "_not_observed", row["errors"], (label, alteration))
                self.assertEqual(row["capabilities"]["authentication_rejection"], "not_run")

    def test_download_verifies_literal_bytes_not_just_success_or_server_counters(self):
        for alteration in ("content", "extra", "trace"):
            def change(scenario, result):
                if scenario.label == "download-0":
                    if alteration == "content":
                        (scenario.root / "downloads" / NAMES[0]).write_bytes(b"bad")
                    elif alteration == "extra":
                        (scenario.root / "downloads" / "extra").write_bytes(b"bad")
                    else:
                        scenario.active.events[-1] = ("content", NAMES[1])
            self.assertIn("filefabric_download_mismatch", self.scenario(mutate=change).execute()["errors"])

    def test_final_inventory_rechecks_old_downloads_empty_extra_dirs_and_negative_siblings(self):
        for alteration in ("bytes", "directory", "negative"):
            def change(scenario, result):
                if scenario.label == "listing-final":
                    if alteration == "bytes":
                        (scenario.root / "downloads" / NAMES[0]).write_bytes(b"changed")
                    elif alteration == "directory":
                        (scenario.root / "downloads" / "unexpected-dir").mkdir()
                    else:
                        (scenario.root / "negative-missing" / "late-partial").write_bytes(b"bad")
            self.assertIn("filefabric_final_inventory_changed", self.scenario(mutate=change).execute()["errors"])

    def test_source_bytes_root_timestamps_key_and_config_preservation(self):
        for field in ("files", "root_id", "nested_id", "modified", "localtime", "token", "wrong_token", "config", "ids"):
            def change(scenario, result):
                if scenario.label != "listing-final":
                    return
                state = scenario.states[0]
                if field == "files":
                    state.files[NAMES[0]] = b"changed"
                elif field == "config":
                    scenario.calls[0][1].write_text("changed")
                else:
                    setattr(state, field, "changed")
            row = self.scenario(mutate=change).execute()
            self.assertIn("filefabric_config_changed" if field == "config" else "filefabric_source_changed", row["errors"])
            self.assertEqual(row["capabilities"]["source_preservation"], "not_run")

    def test_hardlinked_or_reparse_destination_is_rejected_before_acceptance(self):
        def hardlink(scenario, result):
            if scenario.label == "download-0":
                os.link(scenario.root / "downloads" / NAMES[0], scenario.root / "same-bytes-hardlink")
        self.assertIn("filefabric_download_mismatch", self.scenario(mutate=hardlink).execute()["errors"])
        real_lstat = Path.lstat
        def reparse(path, *args, **kwargs):
            info = real_lstat(path, *args, **kwargs)
            if path.name == "nested":
                return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400)
            return info
        with mock.patch.object(Path, "lstat", reparse):
            self.assertIn("filefabric_download_mismatch", self.scenario().execute()["errors"])

    def test_extra_forced_or_unreaped_child_cannot_be_success(self):
        for alteration in ("extra", "forced", "pending", "bool"):
            def change(scenario, result):
                if scenario.label == "listing-initial":
                    if alteration == "extra":
                        scenario.extra_child = True
                    elif alteration == "pending":
                        scenario.pending = True
                    else:
                        result["code"] = -9 if alteration == "forced" else False
            row = self.scenario(mutate=change).execute()
            self.assertTrue(row["errors"])
            self.assertEqual(row["capabilities"]["listing"], "not_run")
            if alteration == "pending":
                self.assertEqual(row["capabilities"]["cleanup"], "failed")

    def test_listener_handler_budget_and_rejected_payload_failure_remain_sticky(self):
        self.assertEqual(self.scenario().execute(listener_closed=False)["capabilities"]["cleanup"], "failed")
        for field in ("cleanup_complete", "budget_exceeded", "unexpected", "rejected_payload_bytes"):
            def change(scenario):
                if scenario.label == "listing-final":
                    setattr(scenario.states[0], field, False if field == "cleanup_complete" else 1)
            row = self.scenario(after_case=change).execute()
            self.assertTrue(row["errors"])
            if field == "cleanup_complete":
                self.assertEqual(row["capabilities"]["cleanup"], "failed")

    def test_write_requires_setup_405_exact_bounded_body_and_closes_client(self):
        for status, body in ((200, WRITE_BODY), (401, WRITE_BODY), (405, b"x" * 1025), (405, b"{}"),
                             (405, WRITE_BODY.replace(b'"fixture_read_only"', b'"permission_denied"'))):
            scenario = self.scenario()
            original = scenario.connection
            def replacement(*args, **kwargs):
                client = original(*args, **kwargs)
                client.getresponse = lambda: SimpleNamespace(status=status, read=lambda limit: body)
                return client
            scenario.connection = replacement
            row = scenario.execute()
            self.assertIn("filefabric_write_guard_not_observed", row["errors"])
            self.assertTrue(scenario.connections[0].closed)
        def change(scenario, result):
            if scenario.label == "write-guard":
                scenario.active.events = []
        scenario = self.scenario(mutate=change)
        self.assertIn("filefabric_write_setup_failed", scenario.execute()["errors"])
        self.assertEqual(scenario.connections, [])


if __name__ == "__main__":
    unittest.main()
