"""Independent anonymous-read verdict oracles; no native process or listener."""
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
CAPS = {"listing", "download_hash", "missing_object_rejection", "anonymous_read", "read_denial", "source_preservation",
        "config_preservation", "fixture_write_rejection", "cleanup"}
ERRORS = {"missing": b'{"error":"loopback: call failed: object not found","path":"operations/copyfile","status":500}',
          "member_denied": json.dumps({"error": 'loopback: call failed: failed to open source object: HTTP error 403 (403 Forbidden) returned body: "Synthetic member denied"',
                                       "path": "operations/copyfile", "status": 500}).encode()}


def item(name, summation=False):
    body = PAYLOADS[name]
    result = {"Path": name, "Name": name.rsplit("/", 1)[-1], "Size": len(body), "IsDir": False,
              "ModTime": "2024-01-01T00:00:00.123456789Z"}
    if not summation:
        result["Hashes"] = {"md5": hashlib.md5(body).hexdigest(), "sha1": hashlib.sha1(body).hexdigest(),
                            "crc32": f"{zlib.crc32(body) & 0xffffffff:08x}"}
    return result


def observed(kind, member="README-synthetic.txt"):
    events = [("metadata", "1"), ("metadata", "2")]
    denied = writes = payload = 0
    if kind == "download":
        events.append(("content", member))
        payload = len(PAYLOADS[member])
    elif kind == "member_denied":
        events.append(("content_denied", member))
        denied = 1
    elif kind == "write":
        events.append(("write_denied", member))
        writes = 1
    return SimpleNamespace(events=events, requests=len(events), anonymous=len(events), metadata_reads=2,
                           member_denied=denied, rejected_mutations=writes, payload_bytes=payload,
                           unexpected=0, rejected_payload_bytes=0, budget_exceeded=False)


class Scenario:
    def __init__(self, root, mutate=None, after_case=None):
        self.root, self.mutate, self.after_case = root, mutate, after_case
        self.calls, self.children, self.states, self.connections = [], [], [], []
        self.active = self.label = None
        self.pending = self.extra_child = False

    @contextmanager
    def serve(self, backend, state):
        assert backend == "internetarchive"
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
        label = self.label = config.stem.removeprefix("internetarchive-")
        result = {"code": 0, "output": b"{}", "error": b""}
        member = "README-synthetic.txt"
        if label.startswith("listing-"):
            kind = "listing"
            result["output"] = json.dumps({"list": [item(n) for n in NAMES]}).encode()
        elif label.startswith("stat-") or label in ("write-guard", "summation-stat"):
            kind = "stat"
            member = NAMES[int(label[5:])] if label.startswith("stat-") else member
            result["output"] = json.dumps({"item": item(member, label == "summation-stat")}).encode()
        elif label.startswith("download-") or label == "summation-copy":
            kind = "download"
            member = NAMES[int(label[9:])] if label.startswith("download-") else member
            target = self.root / ("summation-download" if label == "summation-copy" else "downloads") / member
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
            assert params["srcFs"] == "Synthetic:synthetic-item" and params["srcRemote"] == member
            assert params["dstRemote"] == member and Path(params["dstFs"]).parent == self.root
        else:
            params = json.loads(args[-1])
            assert params["fs"] == "Synthetic:synthetic-item"
            assert params["remote"] == ("" if kind == "listing" else member)
            assert params["opt"] == dict(filesOnly=True, showHash=True, noModTime=False, noMimeType=True,
                                          **({"recurse": True} if kind == "listing" else {}))
        if self.mutate:
            self.mutate(self, result)
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

            def request(self, method, target):
                assert (method, target) == ("DELETE", "/ias3/synthetic-item%2FREADME-synthetic.txt")
                assert scenario.active.events == [("metadata", "1"), ("metadata", "2")]
                scenario.active.events.append(("write_denied", "README-synthetic.txt"))
                scenario.active.requests += 1
                scenario.active.anonymous += 1
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
            return LAB.run_backend(self, "internetarchive", self.root)


class InternetArchiveRunnerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root, self.sequence = Path(temporary.name), 0

    def scenario(self, **kwargs):
        self.sequence += 1
        return Scenario(self.root / str(self.sequence), **kwargs)

    def test_complete_fourteen_owned_children_have_exact_anonymous_nine_cap_contract(self):
        scenario = self.scenario()
        row = scenario.execute()
        self.assertEqual(row, {"backend": "internetarchive", "fixture_kind": "independent_loopback",
                              "capabilities": dict.fromkeys(CAPS, "passed"), "errors": []})
        self.assertEqual(len(scenario.calls), 14)
        self.assertEqual(len(scenario.states), 14)
        self.assertTrue(all(c.closed for c in scenario.connections))
        self.assertEqual(LAB.fixture_manifest(), EXPECTED)
        self.assertEqual(len(LAB.BACKENDS), 20)
        for index, (_, config, kwargs) in enumerate(scenario.calls, 1):
            self.assertEqual(kwargs, {})
            lines = dict(line.split(" = ", 1) for line in config.read_text().splitlines() if " = " in line)
            self.assertEqual(lines, {"type": "internetarchive", "endpoint": f"http://127.0.0.1:{18000+index}/ias3",
                         "front_endpoint": f"http://127.0.0.1:{18000+index}/front", "access_key_id": "", "secret_access_key": "",
                         "wait_archive": "1ns", "item_derive": "false"})

    def test_metadata_complete_inventory_types_times_and_all_hashes(self):
        baseline = {"list": [item(n) for n in NAMES]}
        self.assertTrue(LAB.internetarchive_metadata_matches(json.dumps(baseline).encode(), EXPECTED))
        for change in (lambda x: x["list"].pop(), lambda x: x["list"].append(item(NAMES[0])),
                       lambda x: x["list"][0].update(Size=True), lambda x: x["list"][0].update(Size=-1),
                       lambda x: x["list"][0].update(IsDir=0), lambda x: x["list"][0].update(ModTime="2024-01-02T00:00:00.999000000Z"),
                       lambda x: x["list"][0].update(ModTime="2024-01-01T00:00:00Z"),
                       lambda x: x["list"][0].update(ID="unrequested"), lambda x: x["list"][0].pop("Hashes"),
                       lambda x: x["list"][0]["Hashes"].update(md5="0" * 32),
                       lambda x: x["list"][0]["Hashes"].update(SHA256="0" * 64),
                       lambda x: x["list"][0].update(Path="../README-synthetic.txt"),
                       lambda x: x["list"][0].update(Name="wrong"), lambda x: x.update(extra=True)):
            mutated = copy.deepcopy(baseline)
            change(mutated)
            with self.subTest(mutated=mutated):
                self.assertFalse(LAB.internetarchive_metadata_matches(json.dumps(mutated).encode(), EXPECTED))
        for raw in (b'{"list":[],"list":[]}', b'{}', b'{"list":null}', b'{"list":[NaN]}'):
            self.assertFalse(LAB.internetarchive_metadata_matches(raw, EXPECTED))

    def test_hash_keys_use_canonical_names_not_uppercase_aliases(self):
        for name, alias in (("md5", "MD5"), ("sha1", "SHA-1"), ("crc32", "CRC-32")):
            for replace in (True, False):
                value = item(NAMES[0])
                value["Hashes"][alias] = value["Hashes"][name]
                if replace:
                    del value["Hashes"][name]
                with self.subTest(name=name, replace=replace):
                    self.assertFalse(LAB.internetarchive_metadata_matches(json.dumps({"item": value}).encode(),
                                                                          EXPECTED[:1], stat_result=True))

    def test_summation_requires_no_hashes_and_does_not_relax_baseline(self):
        body = json.dumps({"item": item(NAMES[0], True)}).encode()
        self.assertTrue(LAB.internetarchive_metadata_matches(body, EXPECTED[:1], stat_result=True, summation=True))
        self.assertFalse(LAB.internetarchive_metadata_matches(body, EXPECTED[:1], stat_result=True))
        body = json.dumps({"item": item(NAMES[0])}).encode()
        self.assertFalse(LAB.internetarchive_metadata_matches(body, EXPECTED[:1], stat_result=True, summation=True))

    def test_error_requires_exact_typed_cause_and_operation(self):
        for kind, raw in ERRORS.items():
            self.assertTrue(LAB.internetarchive_error_matches(raw, kind))
            for key, value in (("error", "generic error"), ("status", "500"), ("status", True), ("path", "operations/list"),
                               ("extra", "secret")):
                data = json.loads(raw)
                data[key] = value
                self.assertFalse(LAB.internetarchive_error_matches(json.dumps(data).encode(), kind))
        unwrapped = ERRORS["member_denied"].replace(b"failed to open source object: ", b"")
        self.assertFalse(LAB.internetarchive_error_matches(unwrapped, "member_denied"))
        self.assertFalse(LAB.internetarchive_error_matches(ERRORS["missing"], "member_denied"))
        self.assertFalse(LAB.internetarchive_error_matches(b'{}', "unknown"))

    def test_all_counter_and_event_mutations_fail_closed(self):
        for kind, member in (("listing", ""), ("stat", NAMES[0]), ("download", NAMES[0]),
                             ("missing", "missing-synthetic-object.bin"), ("member_denied", NAMES[0]), ("write", NAMES[0])):
            base = observed(kind, member)
            size = len(PAYLOADS[member]) if kind == "download" else 0
            self.assertTrue(LAB.internetarchive_flow_matches(base, kind, member, size))
            for key in vars(base):
                data = copy.deepcopy(base)
                setattr(data, key, [] if key == "events" else True if key == "budget_exceeded" else getattr(data, key) + 1)
                self.assertFalse(LAB.internetarchive_flow_matches(data, kind, member, size), (kind, key))
            base.requests = True
            self.assertFalse(LAB.internetarchive_flow_matches(base, kind, member, size))
        for kind, member in (("listing", "other"), ("stat", "../other"), ("missing", NAMES[0]), ("unknown", "")):
            self.assertFalse(LAB.internetarchive_flow_matches(observed("listing"), kind, member))

    def test_configuration_and_metadata_argument_builders_forbid_arbitrary_scope(self):
        state = LAB.InternetArchiveState()
        for port in (True, "123", 0, 65536):
            with self.assertRaises(LAB.LabError):
                LAB.internetarchive_options(state, port)
        state.item = "other"
        with self.assertRaises(LAB.LabError):
            LAB.internetarchive_options(state, 123)
        for kind, member in (("list", "other"), ("stat", "../escape"), ("copy", NAMES[0]), ("stat", "http://external.invalid")):
            with self.assertRaises(LAB.LabError):
                LAB.internetarchive_metadata_args(kind, member)

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
                    scenario.active.metadata_reads = 0
                    scenario.active.requests = scenario.active.anonymous = 1
                else:
                    (scenario.root / "negative-member_denied" / "partial.bin").write_bytes(b"partial")
            return action
        for kind in ("success", "generic", "startup_only", "artifact"):
            with self.subTest(kind=kind):
                row = self.scenario(mutate=mutate(kind)).execute()
                self.assertIn("internetarchive_member_denied_not_observed", row["errors"])
                self.assertEqual(row["capabilities"]["read_denial"], "not_run")

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
                self.assertIn("internetarchive_download_mismatch", row["errors"])

    def test_late_source_metadata_config_and_download_changes_are_sticky(self):
        for kind in ("source", "metadata", "config", "download", "summation", "credential"):
            def late(scenario):
                if scenario.label != "listing-final":
                    return
                if kind == "source":
                    scenario.states[0].files[NAMES[0]] = b"changed"
                elif kind == "metadata":
                    scenario.states[0].metadata["files"][0]["rclone-mtime"] = "changed"
                elif kind == "config":
                    scenario.calls[0][1].write_text("changed")
                elif kind == "credential":
                    scenario.states[0].user = "unexpected"
                else:
                    target = "summation-download" if kind == "summation" else "downloads"
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
            self.assertNotEqual(row["capabilities"]["anonymous_read"], "passed")
            if kind != "extra":
                self.assertEqual(row["capabilities"]["cleanup"], "failed")


if __name__ == "__main__":
    unittest.main()
