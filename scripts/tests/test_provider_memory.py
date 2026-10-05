"""Memory batch evidence regressions. No executable or server is started."""

import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
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


# Separate literal truth: do not obtain payloads or response metadata from the
# producer's current FILES mapping or from the requested operations.
PAYLOADS = {
    "README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
    "nested/bytes.bin": bytes(range(256)) * 8,
    "nested/space name.txt": b"Nested synthetic payload.\n",
}
EXPECTED = [{"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            for name, data in sorted(PAYLOADS.items())]
PID = 4242
BUCKET = "synthetic-" + "a" * 32


def oracle_item(name):
    return {"Path": name, "Name": name.rsplit("/", 1)[-1], "Size": len(PAYLOADS[name]),
            "ModTime": "2024-01-01T00:00:00.000000000Z", "IsDir": False,
            "Hashes": {"md5": hashlib.md5(PAYLOADS[name]).hexdigest()}}


def oracle_results(root, bucket=BUCKET):
    remote = "Synthetic:" + bucket
    items = [oracle_item(name) for name in sorted(PAYLOADS)]
    pid = {"pid": PID}
    missing = {"status": 404, "error": "object not found", "path": "operations/copyfile",
               "input": {"srcFs": remote, "srcRemote": "missing-synthetic-object.bin",
                         "dstFs": str(root / "missing"), "dstRemote": "missing-synthetic-object.bin",
                         "_group": "job/1"}}
    return {"results": [dict(pid), {"list": []}, {}, {}, {}, dict(pid), {"list": copy.deepcopy(items)},
                        *({"item": copy.deepcopy(item)} for item in items), {}, {}, {}, {"item": None},
                        missing, dict(pid), {"list": copy.deepcopy(items)}, {}, {}, {},
                        {"list": [{"Path": bucket, "Name": bucket, "Size": -1, "ModTime": "",
                                   "IsDir": True, "IsBucket": True}]}, dict(pid)]}


class FakeRuntime:
    """Return an independent transcript, not an interpreter of batch requests."""
    def __init__(self, mutate=None):
        self.children = []
        self.calls = []
        self.mutate = mutate
        self.code = 0
        self.exit_code = 0

    def run(self, args, config):
        self.calls.append((args, config))
        root = config.parent
        batch = json.loads(args[-1])
        bucket = batch["inputs"][2]["dstFs"].removeprefix("Synthetic:")
        response = oracle_results(root, bucket)
        process = mock.Mock(pid=PID)
        process.poll.side_effect = lambda: self.exit_code
        self.children.append((process, root / "private.out", root / "private.err"))
        for directory in ("first", "audit"):
            for name, body in PAYLOADS.items():
                destination = root / directory / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(body)
        if self.mutate:
            self.mutate(root, response, self)
        return self.code, json.dumps(response).encode(), b"Private synthetic error; never receipt data"


class MemoryFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def run_case(self, mutate=None):
        runtime = FakeRuntime(mutate)
        row = LAB.run_backend(runtime, "memory", self.root / ("case-" + str(len(list(self.root.iterdir())))))
        return runtime, row

    def validate(self, response):
        batch = LAB.memory_batch(self.root, BUCKET, EXPECTED)
        metadata = [dict(item, md5=hashlib.md5(PAYLOADS[item["path"]]).hexdigest()) for item in EXPECTED]
        LAB.memory_results_match(json.dumps(response).encode(), batch, BUCKET, metadata, PID)

    def test_complete_independent_transcript_and_bytes_has_exact_seven_local_capabilities(self):
        runtime, row = self.run_case()
        self.assertEqual(row, {"backend": "memory", "fixture_kind": "local", "errors": [], "capabilities": {
            "listing": "passed", "download_hash": "passed", "missing_object_rejection": "passed",
            "source_preservation": "passed", "authentication_rejection": "not_applicable",
            "cleanup": "passed", "config_preservation": "passed"}})
        self.assertEqual(len(runtime.children), 1)
        self.assertEqual(len(runtime.calls), 1)
        self.assertNotIn("private", json.dumps(row).lower())
        self.assertNotIn(str(self.root), json.dumps(row))

    def test_generated_argv_has_one_literal_json_and_only_closed_synchronous_calls(self):
        runtime, _ = self.run_case()
        args, config = runtime.calls[0]
        self.assertEqual(args[:4], ["rc", "--loopback", "job/batch", "--json"])
        self.assertEqual(len(args), 5)
        self.assertLessEqual(len(args[-1].encode()), 16384)
        batch = json.loads(args[-1])
        self.assertEqual(set(batch), {"concurrency", "inputs"})
        self.assertIs(type(batch["concurrency"]), int)
        self.assertEqual(batch["concurrency"], 1)
        calls = batch["inputs"]
        self.assertEqual(len(calls), 22)
        self.assertEqual([call["_path"] for call in calls], [
            "core/pid", "operations/list", *(["operations/copyfile"] * 3), "core/pid", "operations/list",
            *(["operations/stat"] * 3), *(["operations/copyfile"] * 3), "operations/stat", "operations/copyfile",
            "core/pid", "operations/list", *(["operations/copyfile"] * 3), "operations/list", "core/pid"])
        remote = calls[2]["dstFs"]
        self.assertRegex(remote, r"^Synthetic:synthetic-[0-9a-f]{32}$")
        root = config.parent
        for call in calls:
            self.assertEqual({key for key in call if key.startswith("_")}, {"_path"})
            if call["_path"] == "core/pid":
                self.assertEqual(set(call), {"_path"})
            elif call["_path"] == "operations/copyfile":
                self.assertEqual(set(call), {"_path", "srcFs", "srcRemote", "dstFs", "dstRemote"})
            else:
                self.assertEqual(set(call), {"_path", "fs", "remote", "opt"})
                self.assertIs(call["opt"]["noMimeType"], True)
        for offset, name in enumerate(sorted(PAYLOADS)):
            self.assertEqual(calls[2 + offset], {"_path": "operations/copyfile", "srcFs": str(root / "seed"),
                             "srcRemote": name, "dstFs": remote, "dstRemote": name})
            for start, destination in ((10, "first"), (17, "audit")):
                self.assertEqual(calls[start + offset], {"_path": "operations/copyfile", "srcFs": remote,
                                 "srcRemote": name, "dstFs": str(root / destination), "dstRemote": name})
        self.assertEqual(config.read_text(), "[Synthetic]\ntype = memory\ndiscard = false\n")
        self.assertEqual((root / "batch-input.json").read_text(), args[-1])

    def test_input_is_closed_to_arbitrary_bucket_and_manifest_paths(self):
        for bucket in ("../other", "synthetic-a", "Other:", True, BUCKET + "/child"):
            with self.subTest(bucket=bucket), self.assertRaises(LAB.LabError):
                LAB.memory_batch(self.root, bucket, EXPECTED)
        for path in ("../escape", "/absolute", "Other:member", "nested\\alias"):
            changed = copy.deepcopy(EXPECTED)
            changed[0]["path"] = path
            with self.subTest(path=path), self.assertRaisesRegex(LAB.LabError, "invalid_manifest"):
                LAB.memory_batch(self.root, BUCKET, changed)

    def test_outer_success_missing_extra_reordered_or_async_members_cannot_pass(self):
        mutations = [lambda r: r.pop("results"), lambda r: r.update(jobid=1),
                     lambda r: r["results"].pop(), lambda r: r["results"].append({}),
                     lambda r: r["results"].__setitem__(slice(7, 9), list(reversed(r["results"][7:9]))),
                     lambda r: r["results"].__setitem__(10, {"jobid": 4, "executeId": "synthetic"}),
                     lambda r: r["results"].__setitem__(17, {"status": 500, "error": "failed"}),
                     lambda r: r["results"].__setitem__(1, {"list": [], "extra": True})]
        for mutation in mutations:
            response = oracle_results(self.root)
            mutation(response)
            with self.subTest(mutation=mutation), self.assertRaises(LAB.LabError):
                self.validate(response)

    def test_each_pid_sentinel_requires_exact_retained_positive_integer(self):
        for index in (0, 5, 15, 21):
            for value in (None, True, PID + 1, str(PID), float(PID)):
                response = oracle_results(self.root)
                response["results"][index]["pid"] = value
                with self.subTest(index=index, value=value), self.assertRaises(LAB.LabError):
                    self.validate(response)
        for value in (True, 0, -1, "4242"):
            with self.assertRaisesRegex(LAB.LabError, "invalid_child_pid"):
                LAB.memory_results_match(b"{}", {}, BUCKET, [], value)

    def test_missing_error_must_have_exact_origin_code_message_and_input(self):
        changes = [("status", True), ("status", 403), ("status", 404.0), ("error", "directory not found"),
                   ("error", "wrapped: object not found"), ("path", "operations/stat"), ("input", {}), ("extra", 1)]
        for key, value in changes:
            response = oracle_results(self.root)
            response["results"][14][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(LAB.LabError):
                self.validate(response)
        for key, value in (("srcFs", "Other:bucket"), ("srcRemote", "README-synthetic.txt"),
                           ("dstFs", str(self.root / "first")), ("dstRemote", "wrong.bin"),
                           ("_async", False), ("_path", "operations/copyfile"), ("extra", 0)):
            response = oracle_results(self.root)
            response["results"][14]["input"][key] = value
            with self.subTest(key=key), self.assertRaises(LAB.LabError):
                self.validate(response)

    def test_only_bounded_optional_internal_job_group_is_allowed(self):
        response = oracle_results(self.root)
        response["results"][14]["input"].pop("_group")
        self.validate(response)
        for group in (None, True, "", "job/0", "job/01", "job/-1", "job/" + "1" * 20,
                      "job/1\n", "private/path", "job/1/extra"):
            response = oracle_results(self.root)
            response["results"][14]["input"]["_group"] = group
            with self.subTest(group=group), self.assertRaises(LAB.LabError):
                self.validate(response)

    def test_every_list_and_stat_item_is_independently_bound_to_size_hash_name_and_time(self):
        changes = [("Path", "wrong"), ("Name", "wrong"), ("Size", True), ("Size", 1), ("IsDir", 0),
                   ("Hashes", {"MD5": "0" * 32}), ("Hashes", {}), ("ModTime", "2024-01-01T00:00:00.000000001Z"),
                   ("ModTime", "2024-01-01T00:00:00-00:00"), ("ModTime", "2024-01-01T00:00:00"),
                   ("ModTime", "0001-01-01T00:00:00+23:59"), ("ModTime", "9999-12-31T23:59:59-23:59"), ("extra", 1)]
        for index in (6, 7, 8, 9, 16):
            for key, value in changes:
                response = oracle_results(self.root)
                result = response["results"][index]
                item = result["list"][0] if "list" in result else result["item"]
                item[key] = value
                with self.subTest(index=index, key=key), self.assertRaises(LAB.LabError):
                    self.validate(response)

    def test_listing_order_and_equivalent_timezone_are_valid_but_duplicate_names_are_not(self):
        response = oracle_results(self.root)
        for index in (6, 16):
            response["results"][index]["list"].reverse()
            for item in response["results"][index]["list"]:
                item["ModTime"] = "2024-01-01T11:00:00.0000000+11:00"
        self.validate(response)
        response["results"][16]["list"][0] = response["results"][16]["list"][1]
        with self.assertRaises(LAB.LabError):
            self.validate(response)

    def test_root_and_missing_stat_require_exact_closed_shapes(self):
        for replacement in ({"item": {}}, {"item": None, "extra": True}, {"status": 404}):
            response = oracle_results(self.root)
            response["results"][13] = replacement
            with self.assertRaises(LAB.LabError):
                self.validate(response)
        for key, value in (("IsDir", 1), ("IsBucket", 1), ("Size", -1.0), ("Path", "wrong"), ("extra", 1)):
            response = oracle_results(self.root)
            response["results"][20]["list"][0][key] = value
            with self.assertRaises(LAB.LabError):
                self.validate(response)

    def test_duplicate_json_keys_nonfinite_invalid_utf8_truncation_and_oversize_fail(self):
        for data in (b'{"results":[],"results":[]}', b'{"x":{"pid":1,"pid":2}}', b'{"x":NaN}',
                     b'\xff', b'{"results":', b' ' * (LAB.MAX_OUTPUT + 1)):
            with self.subTest(data=data[:50]), self.assertRaises(LAB.LabError):
                LAB.memory_json(data)

    def test_all_readbacks_need_exact_bytes_and_no_extra_files_directories_or_partials(self):
        for directory in ("first", "audit"):
            mutations = [lambda root, d=directory: (root / d / "README-synthetic.txt").write_bytes(b"corrupt"),
                         lambda root, d=directory: (root / d / "nested/bytes.bin").unlink(),
                         lambda root, d=directory: (root / d / "README-synthetic.txt.partial").write_bytes(b"partial"),
                         lambda root, d=directory: (root / d / "unexpected").mkdir()]
            for mutation in mutations:
                _, row = self.run_case(lambda root, response, runtime: mutation(root))
                self.assertIn("memory_download_inventory_or_hash", row["errors"])
                self.assertEqual(row["capabilities"]["download_hash"], "not_run")

    def test_missing_destination_and_sibling_artifacts_cannot_pass(self):
        for name in ("missing-synthetic-object.bin", "missing-synthetic-object.bin.partial", "unrelated"):
            _, row = self.run_case(lambda root, response, runtime: (root / "missing" / name).write_bytes(b"bad"))
            self.assertIn("memory_missing_artifact", row["errors"])

    def test_seed_content_timestamp_inventory_config_and_plan_mutations_fail(self):
        cases = [
            (lambda root: (root / "seed/README-synthetic.txt").write_bytes(b"changed"), "memory_source_changed"),
            (lambda root: os.utime(root / "seed/README-synthetic.txt", ns=(1, 1)), "memory_source_changed"),
            (lambda root: (root / "seed/extra").mkdir(), "memory_source_changed"),
            (lambda root: (root / "memory.conf").write_text("changed"), "memory_config_changed"),
            (lambda root: (root / "batch-input.json").write_text("{}"), "memory_plan_changed"),
        ]
        for mutation, error in cases:
            _, row = self.run_case(lambda root, response, runtime: mutation(root))
            self.assertIn(error, row["errors"])
            self.assertEqual(row["capabilities"]["source_preservation"], "not_run")

    def test_exit_child_count_and_unreaped_child_fail_closed(self):
        def extra(root, response, runtime):
            runtime.children.append(runtime.children[0])

        mutations = [lambda root, response, runtime: setattr(runtime, "code", 1),
                     lambda root, response, runtime: setattr(runtime, "exit_code", None), extra]
        for mutation in mutations:
            _, row = self.run_case(mutation)
            self.assertTrue(row["errors"])
            self.assertEqual(row["capabilities"]["cleanup"], "failed")
            self.assertEqual(row["capabilities"]["download_hash"], "not_run")

    def test_timeout_and_output_failure_cannot_be_promoted_after_forced_stop(self):
        for error in (LAB.LabError("child_timeout"), LAB.LabError("child_output_limit"), subprocess.TimeoutExpired("synthetic", 20)):
            def fail(root, response, runtime):
                runtime.exit_code = -15
                raise error

            _, row = self.run_case(fail)
            self.assertTrue(row["errors"])
            self.assertEqual(row["capabilities"]["cleanup"], "failed")
            self.assertEqual(row["capabilities"]["listing"], "not_run")

    def test_symlink_and_reparse_ancestors_fail_before_scan(self):
        actual = self.root.lstat()
        for mode, attributes in ((stat.S_IFLNK | 0o777, 0), (actual.st_mode, 0x400)):
            fake = mock.Mock(st_mode=mode, st_file_attributes=attributes)
            with mock.patch.object(Path, "lstat", return_value=fake), mock.patch.object(LAB.os, "scandir") as scan:
                self.assertFalse(LAB.memory_tree_matches(self.root, []))
                scan.assert_not_called()

    def test_reparse_descendant_is_rejected_before_descending_or_hashing(self):
        child = mock.Mock()
        child.path = str(self.root / "junction")
        reparse = mock.Mock(st_mode=stat.S_IFDIR | 0o700, st_file_attributes=0x400)
        original = Path.lstat

        def metadata(path):
            return reparse if str(path) == child.path else original(path)

        manager = mock.MagicMock()
        manager.__enter__.return_value = iter([child])
        with mock.patch.object(Path, "lstat", metadata), mock.patch.object(LAB.os, "scandir", return_value=manager) as scan, mock.patch.object(LAB, "digest") as digest:
            self.assertFalse(LAB.memory_tree_matches(self.root, []))
        self.assertEqual(scan.call_count, 1)
        child.stat.assert_not_called()
        digest.assert_not_called()

    def test_hardlinked_payload_does_not_count_as_owned_independent_readback(self):
        LAB.prepare_files(self.root / "tree")
        os.link(self.root / "tree/README-synthetic.txt", self.root / "outside-link")
        self.assertFalse(LAB.memory_tree_matches(self.root / "tree", EXPECTED))

    def test_large_json_input_is_rejected_before_runtime(self):
        real_batch = LAB.memory_batch

        def too_big(root, bucket, expected):
            result = real_batch(root, bucket, expected)
            result["padding"] = "x" * 16384
            return result

        with mock.patch.object(LAB, "memory_batch", side_effect=too_big):
            runtime, row = self.run_case()
        self.assertEqual(runtime.calls, [])
        self.assertIn("memory_batch_input_limit", row["errors"])

    def test_windows_utf16_command_limit_is_checked_before_popen_or_output_creation(self):
        runtime = object.__new__(LAB.Runtime)
        runtime.root, runtime.binary = self.root, self.root / "not-executed.exe"
        runtime.config, runtime.cache = self.root / "synthetic.conf", self.root / "cache"
        runtime.sequence, runtime.children, runtime.env = 0, [], {}
        # Non-BMP characters count twice in CreateProcess' UTF-16 limit.
        with mock.patch.object(LAB.os, "name", "nt"), mock.patch.object(LAB.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(LAB.LabError, "child_command_line_limit"):
                runtime.start(["rc", "--loopback", "job/batch", "--json", "\U0001f680" * 16384])
        popen.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertEqual(runtime.children, [])

    def test_runtime_passes_json_as_one_argv_member_and_retains_exact_child(self):
        runtime = object.__new__(LAB.Runtime)
        runtime.root, runtime.binary = self.root, self.root / "not-executed"
        runtime.config, runtime.cache = self.root / "synthetic.conf", self.root / "cache"
        runtime.sequence, runtime.children, runtime.env = 0, [], {}
        payload = json.dumps(LAB.memory_batch(self.root, BUCKET, EXPECTED))
        process = mock.Mock(pid=PID)
        with mock.patch.object(LAB.subprocess, "Popen", return_value=process) as popen:
            record = runtime.start(["rc", "--loopback", "job/batch", "--json", payload])
        command = popen.call_args.args[0]
        self.assertEqual(command[-5:], ["rc", "--loopback", "job/batch", "--json", payload])
        self.assertNotIn("shell", popen.call_args.kwargs)
        self.assertIs(record[0], process)
        self.assertEqual(runtime.children, [record])


if __name__ == "__main__":
    unittest.main()
