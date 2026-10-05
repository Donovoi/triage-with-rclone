"""Independent signed-read verdict oracles; no native process or listener."""
import base64
import copy
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest import mock
import zlib

sys.path.insert(0, str(Path(__file__).parents[1] / "provider-lab"))
try:
    import run_lab as LAB
finally:
    sys.path.pop(0)

PAYLOADS = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
            "nested/bytes.bin": bytes(range(256)) * 8, "nested/space name.txt": b"Nested synthetic payload.\n"}
NAMES = sorted(PAYLOADS)
EXPECTED = [{"path": n, "size": len(b), "sha256": hashlib.sha256(b).hexdigest()} for n, b in sorted(PAYLOADS.items())]
CAPS = {"listing", "download_hash", "missing_object_rejection", "authentication_rejection", "source_preservation",
        "config_preservation", "fixture_write_rejection", "cleanup"}
ERRORS = {"missing": b'{"error":"loopback: call failed: object not found","path":"operations/copyfile","status":500}',
          "wrong_secret": json.dumps({"error": 'loopback: call failed: failed to call NetStorage API: HTTP error 403 (403 Forbidden) returned body: "Synthetic authentication denied"', "path": "operations/copyfile", "status": 500}).encode(),
          "member_denied": json.dumps({"error": 'loopback: call failed: failed to open source object: failed to call NetStorage API: HTTP error 403 (403 Forbidden) returned body: "Synthetic member denied"',
                                       "path": "operations/copyfile", "status": 500}).encode()}


def item(name):
    return {"Path": name, "Name": name.rsplit("/", 1)[-1], "Size": len(PAYLOADS[name]), "IsDir": False,
            "ModTime": "2024-01-01T00:00:00Z", "Hashes": {"md5": hashlib.md5(PAYLOADS[name]).hexdigest()}}


def observed(kind, member="README-synthetic.txt"):
    events = [("root_stat", "")]
    auth_denied = denied = writes = payload = missing = 0
    if kind == "listing":
        events.append(("listing", ""))
    elif kind == "missing":
        events.append(("file_missing", member))
        missing = 1
    elif kind == "wrong_secret":
        events = [("auth_denied", ""), ("auth_denied", member)]
        auth_denied = 2
    else:
        events.append(("member_stat", member))
        if kind == "download":
            events.append(("content", member))
            payload = len(PAYLOADS[member])
        elif kind == "member_denied":
            events.append(("content_denied", member))
            denied = 1
        elif kind == "write":
            events.append(("write_denied", member))
            writes = 1
    return SimpleNamespace(events=events, requests=len(events), authenticated=len(events)-auth_denied, auth_denied=auth_denied,
                           member_denied=denied, missing=missing, rejected_mutations=writes, payload_bytes=payload,
                           unexpected=0, rejected_payload_bytes=0, budget_exceeded=False)


class Scenario:
    def __init__(self, root, mutate=None, after_case=None):
        self.root, self.mutate, self.after_case = root, mutate, after_case
        self.calls, self.children, self.states, self.connections, self.keys = [], [], [], [], []
        self.active = self.label = None
        self.pending = self.extra_child = False

    @contextmanager
    def serve(self, backend, state):
        assert backend == "netstorage"
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
        if args[0] == "obscure":
            self.label = "obscure-" + str(len(self.keys))
            self.keys.append(args[1])
            result = {"code": 0, "output": ("a" * 32 if len(self.keys) == 1 else "b" * 32).encode(), "error": b""}
            if self.mutate:
                self.mutate(self, result)
            return self.finish(result)
        assert config is not None and args[:2] == ["rc", "--loopback"]
        label = self.label = config.stem.removeprefix("netstorage-")
        result = {"code": 0, "output": b"{}", "error": b""}
        member = "README-synthetic.txt"
        if label.startswith("listing-"):
            kind = "listing"
            result["output"] = json.dumps({"list": [item(n) for n in NAMES]}).encode()
        elif label.startswith("stat-") or label == "write-guard":
            kind = "stat"
            member = NAMES[int(label[5:])] if label.startswith("stat-") else member
            result["output"] = json.dumps({"item": item(member)}).encode()
        elif label.startswith("download-"):
            kind = "download"
            member = NAMES[int(label[9:])] if label.startswith("download-") else member
            target = self.root / "downloads" / member
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(PAYLOADS[member])
        elif label in ("missing-stat", "missing"):
            kind, member = "missing", "missing-synthetic-object.bin"
            result["output"] = b'{"item":null}'
            if label == "missing":
                result.update(code=1, output=ERRORS["missing"])
        else:
            kind = label
            result.update(code=1, output=ERRORS[kind])
        oracle = observed(kind, member)
        for name, value in vars(oracle).items():
            setattr(self.active, name, copy.deepcopy(value))
        if args[2] == "operations/copyfile":
            params = dict(arg.split("=", 1) for arg in args[3:])
            assert params["srcFs"] == "Synthetic:" and params["srcRemote"] == member
            assert params["dstRemote"] == member and Path(params["dstFs"]).parent == self.root
        else:
            params = json.loads(args[-1])
            assert params["fs"] == "Synthetic:"
            assert params["remote"] == ("" if kind == "listing" else member)
            assert params["opt"] == dict(filesOnly=True, showHash=True, noModTime=False, noMimeType=True,
                                          **({"recurse": True} if kind == "listing" else {}))
        if self.mutate:
            self.mutate(self, result)
        return self.finish(result)

    def finish(self, result):
        process = mock.Mock(pid=4600 + len(self.children))
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

            def request(self, method, target, headers):
                assert (method, target) == ("POST", "/123456/synthetic/README-synthetic.txt")
                assert set(headers) == {"X-Akamai-ACS-Action", "X-Akamai-ACS-Auth-Data", "X-Akamai-ACS-Auth-Sign"}
                assert headers["X-Akamai-ACS-Action"] == "version=1&action=delete"
                data = headers["X-Akamai-ACS-Auth-Data"]
                message = data + target + "\nx-akamai-acs-action:version=1&action=delete\n"
                expected = base64.b64encode(hmac.new(scenario.keys[0].encode(), message.encode(), hashlib.sha256).digest()).decode()
                assert headers["X-Akamai-ACS-Auth-Sign"] == expected
                assert scenario.active.events == [("root_stat", ""), ("member_stat", "README-synthetic.txt")]
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

    def execute(self, closed=True):
        with mock.patch.object(LAB, "serve", self.serve), mock.patch.object(LAB, "listener_closed", return_value=closed), \
                mock.patch.object(LAB.http.client, "HTTPConnection", self.connection):
            return LAB.run_backend(self, "netstorage", self.root)


class NetStorageRunnerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root, self.sequence = Path(temporary.name), 0

    def scenario(self, **kwargs):
        self.sequence += 1
        return Scenario(self.root / str(self.sequence), **kwargs)

    def test_complete_thirteen_protocol_plus_two_obscure_children_have_exact_eight_cap_contract(self):
        scenario = self.scenario()
        row = scenario.execute()
        self.assertEqual(row, {"backend": "netstorage", "fixture_kind": "independent_loopback",
                              "capabilities": dict.fromkeys(CAPS, "passed"), "errors": []})
        self.assertEqual(len(scenario.calls), 15)
        self.assertEqual(len(scenario.states), 13)
        self.assertTrue(all(c.closed for c in scenario.connections))
        self.assertEqual(LAB.fixture_manifest(), EXPECTED)
        self.assertEqual(len(LAB.BACKENDS), 20)
        self.assertNotEqual(*scenario.keys)
        for index, (_, config, kwargs) in enumerate(scenario.calls[2:], 1):
            self.assertEqual(kwargs, {})
            lines = dict(line.split(" = ", 1) for line in config.read_text().splitlines() if " = " in line)
            self.assertEqual(lines, {"type": "netstorage", "protocol": "http", "host": f"127.0.0.1:{18000+index}/123456/synthetic/",
                                    "account": "synthetic-account", "secret": "b" * 32 if "wrong_secret" in config.name else "a" * 32})
            if "wrong_secret" in config.name:
                valid = config.with_name(config.stem + "-valid.conf")
                original = dict(line.split(" = ", 1) for line in valid.read_text().splitlines() if " = " in line)
                self.assertEqual({k for k in original if original[k] != lines[k]}, {"secret"})
                self.assertEqual(original["secret"], "a" * 32)

    def test_metadata_complete_inventory_types_times_and_all_hashes(self):
        baseline = {"list": [item(n) for n in NAMES]}
        self.assertTrue(LAB.netstorage_metadata_matches(json.dumps(baseline).encode(), EXPECTED))
        for change in (lambda x: x["list"].pop(), lambda x: x["list"].append(item(NAMES[0])),
                       lambda x: x["list"][0].update(Size=True), lambda x: x["list"][0].update(Size=-1),
                       lambda x: x["list"][0].update(IsDir=0), lambda x: x["list"][0].update(ModTime="2024-01-02T00:00:00.999000000Z"),
                       lambda x: x["list"][0].update(ModTime="2024-01-01T00:00:00.000000000Z"),
                       lambda x: x["list"][0].update(ID="unrequested"), lambda x: x["list"][0].pop("Hashes"),
                       lambda x: x["list"][0]["Hashes"].update(md5="0" * 32),
                       lambda x: x["list"][0]["Hashes"].update(SHA256="0" * 64),
                       lambda x: x["list"][0].update(Path="../README-synthetic.txt"),
                       lambda x: x["list"][0].update(Name="wrong"), lambda x: x.update(extra=True)):
            mutated = copy.deepcopy(baseline)
            change(mutated)
            with self.subTest(mutated=mutated):
                self.assertFalse(LAB.netstorage_metadata_matches(json.dumps(mutated).encode(), EXPECTED))
        for raw in (b'{"list":[],"list":[]}', b'{}', b'{"list":null}', b'{"list":[NaN]}'):
            self.assertFalse(LAB.netstorage_metadata_matches(raw, EXPECTED))

    def test_seconds_require_an_aware_exact_instant_and_lowercase_md5_only(self):
        for timestamp in ("2024-01-01T00:00:00Z", "2024-01-01T11:00:00+11:00", "2023-12-31T19:00:00-05:00"):
            value = item(NAMES[0])
            value["ModTime"] = timestamp
            self.assertTrue(LAB.netstorage_metadata_matches(json.dumps({"item": value}).encode(), EXPECTED[:1], stat_result=True))
        for timestamp in ("2024-01-01T00:00:00", "2024-01-01T00:00:00-00:00", "2024-01-01T00:00:00.1Z", "2024-01-01T00:00:01Z"):
            value = item(NAMES[0])
            value["ModTime"] = timestamp
            self.assertFalse(LAB.netstorage_metadata_matches(json.dumps({"item": value}).encode(), EXPECTED[:1], stat_result=True))
        for key in ("MD5", "sha1", "crc32"):
            value = item(NAMES[0])
            value["Hashes"][key] = value["Hashes"].pop("md5")
            self.assertFalse(LAB.netstorage_metadata_matches(json.dumps({"item": value}).encode(), EXPECTED[:1], stat_result=True))

    def test_error_requires_exact_typed_cause_and_operation(self):
        for kind, raw in ERRORS.items():
            self.assertTrue(LAB.netstorage_error_matches(raw, kind))
            for key, value in (("error", "generic error"), ("status", "500"), ("status", True), ("path", "operations/list"),
                               ("extra", "secret")):
                data = json.loads(raw)
                data[key] = value
                self.assertFalse(LAB.netstorage_error_matches(json.dumps(data).encode(), kind))
        unwrapped = ERRORS["member_denied"].replace(b"failed to open source object: ", b"")
        self.assertFalse(LAB.netstorage_error_matches(unwrapped, "member_denied"))
        self.assertFalse(LAB.netstorage_error_matches(ERRORS["missing"], "member_denied"))
        self.assertFalse(LAB.netstorage_error_matches(b'{}', "unknown"))

    def test_all_counter_and_event_mutations_fail_closed(self):
        for kind, member in (("listing", ""), ("stat", NAMES[0]), ("download", NAMES[0]),
                             ("missing", "missing-synthetic-object.bin"), ("wrong_secret", NAMES[0]), ("member_denied", NAMES[0]), ("write", NAMES[0])):
            base = observed(kind, member)
            size = len(PAYLOADS[member]) if kind == "download" else 0
            self.assertTrue(LAB.netstorage_flow_matches(base, kind, member, size))
            for key in vars(base):
                data = copy.deepcopy(base)
                setattr(data, key, [] if key == "events" else True if key == "budget_exceeded" else getattr(data, key) + 1)
                self.assertFalse(LAB.netstorage_flow_matches(data, kind, member, size), (kind, key))
            base.requests = True
            self.assertFalse(LAB.netstorage_flow_matches(base, kind, member, size))
        for kind, member in (("listing", "other"), ("stat", "../other"), ("missing", NAMES[0]), ("unknown", "")):
            self.assertFalse(LAB.netstorage_flow_matches(observed("listing"), kind, member))

    def test_configuration_and_metadata_argument_builders_forbid_arbitrary_scope(self):
        state = LAB.NetStorageState("synthetic-secret-value", "wrong-synthetic-secret")
        for port in (True, "123", 0, 65536):
            with self.assertRaises(LAB.LabError):
                LAB.netstorage_options(state, port, "a" * 32)
        state.prefix = "other"
        with self.assertRaises(LAB.LabError):
            LAB.netstorage_options(state, 123, "a" * 32)
        for kind, member in (("list", "other"), ("stat", "../escape"), ("copy", NAMES[0]), ("stat", "http://external.invalid")):
            with self.assertRaises(LAB.LabError):
                LAB.netstorage_metadata_args(kind, member)

    def test_negative_success_generic_error_early_failure_and_output_artifact_never_pass(self):
        def mutate(kind):
            def action(scenario, result):
                if scenario.label != "member_denied":
                    return
                if kind == "success":
                    result["code"] = 0
                elif kind == "generic":
                    result["output"] = ERRORS["missing"]
                elif kind == "startup_only":
                    scenario.active.events = [("content_denied", NAMES[0])]
                    scenario.active.authenticated = 1
                    scenario.active.requests = 1
                else:
                    (scenario.root / "negative-member_denied" / "partial.bin").write_bytes(b"partial")
            return action
        for kind in ("success", "generic", "startup_only", "artifact"):
            with self.subTest(kind=kind):
                row = self.scenario(mutate=mutate(kind)).execute()
                self.assertIn("netstorage_member_denied_not_observed", row["errors"])
                self.assertEqual(row["capabilities"]["authentication_rejection"], "not_run")

    def test_wrong_secret_cannot_pass_from_root_failure_alone_generic_error_or_artifacts(self):
        for failure in ("root_only", "success", "wrong_cause", "unexpected", "artifact"):
            def mutate(scenario, result):
                if scenario.label != "wrong_secret":
                    return
                if failure == "root_only":
                    scenario.active.events = [("auth_denied", "")]
                    scenario.active.requests = scenario.active.auth_denied = 1
                elif failure == "success":
                    result["code"] = 0
                elif failure == "wrong_cause":
                    result["output"] = ERRORS["missing"]
                elif failure == "unexpected":
                    scenario.active.unexpected = 1
                else:
                    (scenario.root / "negative-wrong_secret" / "partial").write_bytes(b"partial")
            row = self.scenario(mutate=mutate).execute()
            self.assertTrue(row["errors"], failure)
            self.assertNotEqual(row["capabilities"]["authentication_rejection"], "passed")

    def test_obscure_setup_requires_two_distinct_valid_completed_results(self):
        for failure in ("error", "empty", "badchars", "identical", "pending", "extra"):
            def mutate(scenario, result):
                if scenario.label != "obscure-1":
                    return
                if failure == "error":
                    result["code"] = 1
                elif failure in ("empty", "badchars", "identical"):
                    result["output"] = {"empty": b"", "badchars": b"\x00" * 32, "identical": b"a" * 32}[failure]
                elif failure == "pending":
                    scenario.pending = True
                else:
                    scenario.extra_child = True
            row = self.scenario(mutate=mutate).execute()
            self.assertTrue(row["errors"], failure)
            self.assertNotEqual(row["capabilities"]["authentication_rejection"], "passed")

    def test_corrupt_extra_partial_and_hardlinked_downloads_are_rejected(self):
        for kind in ("corrupt", "extra", "missing", "hardlink"):
            def mutate(scenario, result):
                if scenario.label != "download-0":
                    return
                path = scenario.root / "downloads" / NAMES[0]
                if kind == "corrupt":
                    path.write_bytes(b"wrong")
                elif kind == "extra":
                    (path.parent / "extra.bin").write_bytes(b"extra")
                elif kind == "missing":
                    path.unlink()
                else:
                    os.link(path, scenario.root / "owned-hardlink")
            with self.subTest(kind=kind):
                row = self.scenario(mutate=mutate).execute()
                self.assertIn("netstorage_download_mismatch", row["errors"])

    def test_late_source_metadata_config_and_download_changes_are_sticky(self):
        for kind in ("source", "metadata", "config", "download", "credential"):
            def late(scenario):
                if scenario.label != "listing-final":
                    return
                if kind == "source":
                    scenario.states[0].files[NAMES[0]] = b"changed"
                elif kind == "metadata":
                    scenario.states[0].metadata[NAMES[0]]["mtime"] = "changed"
                elif kind == "config":
                    scenario.calls[2][1].write_text("changed")
                elif kind == "credential":
                    scenario.states[0].user = "unexpected"
                else:
                    target = "downloads"
                    (scenario.root / target / NAMES[0]).write_bytes(b"changed")
            with self.subTest(kind=kind):
                row = self.scenario(after_case=late).execute()
                self.assertTrue(row["errors"])
                self.assertNotEqual(row["capabilities"]["source_preservation"], "passed")

    def test_unreaped_extra_children_open_listener_and_false_cleanup_never_pass(self):
        for kind in ("pending", "extra", "listener", "state"):
            def mutate(scenario, result):
                scenario.pending = kind == "pending"
                scenario.extra_child = kind == "extra"
            def after(scenario):
                if kind == "state":
                    scenario.active.cleanup_complete = False
            row = self.scenario(mutate=mutate, after_case=after).execute(closed=kind != "listener")
            self.assertTrue(row["errors"], kind)
            self.assertNotEqual(row["capabilities"]["authentication_rejection"], "passed")
            if kind != "extra":
                self.assertEqual(row["capabilities"]["cleanup"], "failed")


if __name__ == "__main__":
    unittest.main()
