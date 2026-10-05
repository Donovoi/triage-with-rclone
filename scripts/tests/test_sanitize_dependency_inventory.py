import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HELPER = Path(__file__).with_name("sanitize_dependency_inventory.py")
# Compatible with eventual scripts/tests/ placement without importing unrelated code.
if not HELPER.is_file():
    HELPER = Path(__file__).resolve().parents[1] / "sanitize_dependency_inventory.py"
SPEC = importlib.util.spec_from_file_location("sanitized_inventory_test_subject", HELPER)
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)

CANARY = "PRIVATE-person@example.invalid"
ROOT = "path+file:///C:/PRIVATE-person/work/project#sample-app@1.2.3"
DEP = "registry+https://PRIVATE-user:PRIVATE-secret@example.invalid#dep@2.0.0"
LOCK = b'version = 4\n# PRIVATE-person@example.invalid\n'


def metadata():
    def package(identity, name, version):
        return {"id": identity, "name": name, "version": version,
                "authors": [CANARY], "description": CANARY, "license": CANARY,
                "source": DEP, "manifest_path": "/private/" + CANARY,
                "metadata": {"private": CANARY}, "features": {CANARY: [CANARY]},
                "targets": [{"src_path": "/private/" + CANARY}],
                "repository": "https://" + CANARY, "license_file": CANARY}
    return {
        "version": 1,
        "packages": [package(ROOT, "sample-app", "1.2.3"), package(DEP, "dep", "2.0.0")],
        "workspace_root": "/private/" + CANARY, "metadata": {"private": CANARY},
        "workspace_members": [ROOT], "workspace_default_members": [ROOT],
        "resolve": {"root": ROOT, "nodes": [
            {"id": ROOT, "features": [CANARY], "dependencies": [DEP],
             "deps": [{"name": CANARY, "pkg": DEP,
                       "dep_kinds": [{"kind": None, "target": CANARY},
                                     {"kind": "build", "target": CANARY}]}]},
            {"id": DEP, "dependencies": [], "deps": [], "features": []},
        ]},
    }


def encode(value):
    return json.dumps(value).encode()


class BinaryStandardStream:
    def __init__(self, data=b""):
        self.buffer = io.BytesIO(data)


class InventoryTests(unittest.TestCase):
    def sanitize(self, value=None):
        return inventory.sanitize_metadata(encode(metadata() if value is None else value), LOCK)

    def rejected(self, value, code):
        with self.assertRaises(inventory.InventoryError) as caught:
            self.sanitize(value)
        self.assertEqual(str(caught.exception), code)
        self.assertNotIn(CANARY, str(caught.exception))

    def test_literal_public_schema_and_graph(self):
        self.assertEqual(self.sanitize(), {
            "schema_version": 1, "scope": "cargo_dependency_inventory", "cargo_metadata_version": 1,
            "lockfile_sha256": hashlib.sha256(LOCK).hexdigest(),
            "packages": [
                {"id": "pkg000001", "name": "dep", "version": "2.0.0", "dependencies": []},
                {"id": "pkg000002", "name": "sample-app", "version": "1.2.3", "dependencies": [
                    {"package_id": "pkg000001", "kinds": ["build", "normal"]}]},
            ],
            "resolve_root": "pkg000002", "workspace_members": ["pkg000002"],
            "workspace_default_members": ["pkg000002"],
            "limitations": {"source_identities_omitted": True, "target_conditions_omitted": True,
                            "features_omitted": True, "build_usage_verified": False,
                            "vulnerability_status_verified": False, "lockfile_consistency_verified": False},
        })

    def test_sensitive_fields_never_reach_serialization(self):
        data = inventory.serialize(self.sanitize())
        for forbidden in (CANARY, ROOT, DEP, "PRIVATE", "https://", "file://", "manifest_path", "authors"):
            self.assertNotIn(forbidden.encode(), data)

    def test_private_id_text_does_not_determine_public_ids(self):
        original = metadata()
        changed = json.loads(json.dumps(original).replace(ROOT, "opaque-private-root").replace(DEP, "opaque-private-dep"))
        self.assertEqual(self.sanitize(original), self.sanitize(changed))

    def test_same_name_version_nodes_are_not_merged(self):
        value = metadata()
        value["packages"][1]["name"] = "sample-app"
        value["packages"][1]["version"] = "1.2.3"
        result = self.sanitize(value)
        self.assertEqual(len(result["packages"]), 2)
        self.assertEqual(result["packages"][0]["dependencies"], [{"package_id": "pkg000002", "kinds": ["build", "normal"]}])

    def test_target_alias_collapse_preserves_all_kinds(self):
        value = metadata()
        value["resolve"]["nodes"][0]["deps"].append(
            {"pkg": DEP, "name": CANARY, "dep_kinds": [{"kind": "dev", "target": CANARY}, {"kind": None}]})
        result = self.sanitize(value)
        self.assertEqual(result["packages"][1]["dependencies"], [{"package_id": "pkg000001", "kinds": ["build", "dev", "normal"]}])

    def test_virtual_workspace_nullable_root(self):
        value = metadata()
        value["resolve"]["root"] = None
        self.assertIsNone(self.sanitize(value)["resolve_root"])

    def test_identity_version_type_and_token_guards(self):
        for field, invalid in [("name", CANARY), ("name", "../path"), ("name", True),
                               ("version", CANARY), ("version", True), ("version", "01.2.3"),
                               ("version", "1.2.3-01"), ("version", "1.2.3\n")]:
            with self.subTest(field=field, category=type(invalid).__name__):
                value = metadata()
                value["packages"][0][field] = invalid
                self.rejected(value, "package_invalid")
        for valid in ("0.0.0", "1.2.3-alpha.1+build.2", "1.2.3-rc-1", "1.2.3+01"):
            value = metadata()
            value["packages"][0]["version"] = valid
            self.assertEqual(self.sanitize(value)["packages"][1]["version"], valid)

    def test_package_and_graph_uniqueness_completeness(self):
        value = metadata()
        value["packages"].append(copy.deepcopy(value["packages"][0]))
        self.rejected(value, "package_duplicate")
        value = metadata()
        value["resolve"]["nodes"].pop()
        self.rejected(value, "graph_incomplete")
        value = metadata()
        value["resolve"]["nodes"][1] = copy.deepcopy(value["resolve"]["nodes"][0])
        self.rejected(value, "graph_incomplete")

    def test_unknown_references_and_flat_graph_mismatch(self):
        for location in ("root", "flat", "edge"):
            value = metadata()
            if location == "root":
                value["resolve"]["root"] = CANARY
            elif location == "flat":
                value["resolve"]["nodes"][0]["dependencies"] = []
            else:
                value["resolve"]["nodes"][0]["deps"][0]["pkg"] = CANARY
            self.rejected(value, "graph_reference")

    def test_workspace_membership_and_default_subset(self):
        for field, invalid in [("workspace_members", []), ("workspace_members", [ROOT, ROOT]),
                               ("workspace_members", [CANARY]), ("workspace_default_members", [DEP]),
                               ("workspace_default_members", None)]:
            value = metadata()
            value[field] = invalid
            self.rejected(value, "workspace_invalid")

    def test_unknown_boolean_or_empty_dependency_kinds_reject(self):
        for kinds in ([], [{"kind": True}], [{"kind": "normal"}], [{"kind": CANARY}], [{}]):
            value = metadata()
            value["resolve"]["nodes"][0]["deps"][0]["dep_kinds"] = kinds
            self.rejected(value, "graph_invalid")

    def test_json_duplicate_nonfinite_encoding_and_schema_reject(self):
        for raw, code in [(b'{"version":1,"version":1}', "metadata_duplicate_key"),
                          (b'{"ignored":{"x":1,"x":2}}', "metadata_duplicate_key"),
                          (b'{"ignored":NaN}', "metadata_json"), (b'\xff', "metadata_json"),
                          (b'{"version":true}', "metadata_schema"), (b'{"version":2}', "metadata_schema")]:
            with self.assertRaises(inventory.InventoryError) as caught:
                inventory.sanitize_metadata(raw, LOCK)
            self.assertEqual(str(caught.exception), code)

    def test_bounded_metadata_lock_packages_edges_and_output(self):
        for constant, limit, code in [("MAX_METADATA_BYTES", 2, "metadata_size"),
                                      ("MAX_LOCK_BYTES", 2, "lock_size"),
                                      ("MAX_PACKAGES", 1, "input_limit"),
                                      ("MAX_EDGES", 2, "input_limit"),
                                      ("MAX_OUTPUT_BYTES", 2, "output_limit")]:
            with mock.patch.object(inventory, constant, limit):
                with self.assertRaises(inventory.InventoryError) as caught:
                    self.sanitize()
                self.assertEqual(str(caught.exception), code)

    def test_main_streams_only_sanitized_output_after_full_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / "Cargo.lock"
            lock.write_bytes(LOCK)
            source, output, errors = BinaryStandardStream(encode(metadata())), BinaryStandardStream(), io.StringIO()
            with mock.patch.object(inventory.sys, "stdin", source), mock.patch.object(inventory.sys, "stdout", output), contextlib.redirect_stderr(errors):
                status = inventory.main(["--metadata", "-", "--lockfile", str(lock), "--output", "-"])
            self.assertEqual(status, 0)
            self.assertEqual(errors.getvalue(), "")
            self.assertEqual(json.loads(output.buffer.getvalue()), self.sanitize())
            self.assertNotIn(CANARY.encode(), output.buffer.getvalue())
            for raw in (b'{"version":true}', b'{"private":"' + CANARY.encode() + b'",'):
                source, output = BinaryStandardStream(raw), BinaryStandardStream()
                with mock.patch.object(inventory.sys, "stdin", source), mock.patch.object(inventory.sys, "stdout", output), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(inventory.main(["--metadata", "-", "--lockfile", str(lock), "--output", "-"]), 2)
                self.assertEqual(output.buffer.getvalue(), b"")

    def test_stdin_limit_and_output_limit_publish_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / "Cargo.lock"
            lock.write_bytes(LOCK)
            for constant in ("MAX_METADATA_BYTES", "MAX_OUTPUT_BYTES"):
                source, output = BinaryStandardStream(encode(metadata())), BinaryStandardStream()
                with mock.patch.object(inventory, constant, 2), mock.patch.object(inventory.sys, "stdin", source), mock.patch.object(inventory.sys, "stdout", output), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(inventory.main(["--metadata", "-", "--lockfile", str(lock), "--output", "-"]), 2)
                self.assertEqual(output.buffer.getvalue(), b"")

    def test_absolute_file_mode_is_create_new_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            source, lock, output = [Path(directory) / name for name in ("private.json", "Cargo.lock", "inventory.json")]
            source.write_bytes(encode(metadata()))
            lock.write_bytes(LOCK)
            args = ["--metadata", str(source), "--lockfile", str(lock), "--output", str(output)]
            self.assertEqual(inventory.main(args), 0)
            expected = output.read_bytes()
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(inventory.main(args), 2)
            self.assertEqual(output.read_bytes(), expected)

    def test_errors_never_echo_input_paths_or_cli_values(self):
        for args in (["--metadata", "/private/" + CANARY, "--lockfile", "/missing", "--output", "-"],
                     ["--unknown-argument", CANARY]):
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                self.assertEqual(inventory.main(args), 2)
            self.assertRegex(errors.getvalue(), r"\Adependency_inventory_failed:[a-z_]+\n\Z")
            self.assertNotIn(CANARY, errors.getvalue())

    def test_output_fsync_failure_removes_only_new_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "inventory.json"
            with mock.patch.object(inventory.os, "fsync", side_effect=OSError(CANARY)):
                with self.assertRaisesRegex(inventory.InventoryError, "^output_file$"):
                    inventory.write_output(str(output), b"{}\n")
            self.assertFalse(output.exists())

    def test_unknown_error_code_is_never_exposed(self):
        self.assertEqual(str(inventory.InventoryError(CANARY)), "inventory_internal")


if __name__ == "__main__":
    unittest.main()
