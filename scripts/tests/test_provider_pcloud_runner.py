"""Strict pCloud evidence predicates; native tests require the explicit lab CLI."""

import copy
import hashlib
import importlib
import importlib.metadata
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

LAB_ROOT = Path(__file__).parents[1] / "provider-lab"
sys.path.insert(0, str(LAB_ROOT))
try:
    import run_lab as LAB
finally:
    sys.path.pop(0)


class PCloudRunnerTests(unittest.TestCase):
    def metadata(self):
        return {"list": [{"Path": item["path"], "Name": item["path"].rsplit("/", 1)[-1],
                          "Size": item["size"], "ModTime": "2024-01-01T00:00:00Z", "IsDir": False,
                          "ID": {"README-synthetic.txt": "f301", "nested/space name.txt": "f302",
                                 "nested/bytes.bin": "f303"}[item["path"]],
                          "Hashes": {"md5": hashlib.md5(LAB.FILES[item["path"]]).hexdigest(),
                                     "sha1": hashlib.sha1(LAB.FILES[item["path"]]).hexdigest()}}
                         for item in LAB.fixture_manifest()]}

    def test_metadata_requires_complete_exact_identity_hash_size_and_timestamp(self):
        good = self.metadata()
        expected = LAB.fixture_manifest()
        self.assertTrue(LAB.pcloud_metadata_matches(json.dumps(good).encode(), expected))
        for field, value in (("ID", "f999"), ("Size", True), ("IsDir", 0), ("Name", "renamed"),
                             ("Path", "../README-synthetic.txt"), ("ModTime", "2024-01-01T00:00:00-00:00"),
                             ("ModTime", "2024-01-01T00:00:01Z"), ("ModTime", "2024-01-01T00:00:00.1Z"),
                             ("Hashes", {}), ("Hashes", {"sha1": "0" * 40, "md5": "0" * 32})):
            with self.subTest(field=field, value=value):
                bad = copy.deepcopy(good)
                bad["list"][0][field] = value
                self.assertFalse(LAB.pcloud_metadata_matches(json.dumps(bad).encode(), expected))
        for entries in (good["list"][:2], [good["list"][0]] * 3):
            self.assertFalse(LAB.pcloud_metadata_matches(json.dumps({"list": entries}).encode(), expected))

    def test_stat_has_its_own_envelope_and_exact_member(self):
        entry = self.metadata()["list"][0]
        payload = json.dumps({"item": entry}).encode()
        self.assertTrue(LAB.pcloud_metadata_matches(payload, LAB.fixture_manifest()[:1], stat_result=True))
        self.assertFalse(LAB.pcloud_metadata_matches(payload, LAB.fixture_manifest()[:1]))
        self.assertFalse(LAB.pcloud_metadata_matches(b'{"item":null}', LAB.fixture_manifest()[:1], stat_result=True))

    def test_options_constrain_api_oauth_and_token_without_ambient_credentials(self):
        state = SimpleNamespace(token="synthetic-" + "a" * 32, wrong_token="wrong-synthetic-" + "b" * 32)
        good = LAB.pcloud_options(state, 23456)
        self.assertEqual(set(good), {"type", "hostname", "root_folder_id", "client_id", "client_secret",
                                     "client_credentials", "auth_url", "token_url", "token"})
        self.assertEqual((good["hostname"], good["root_folder_id"], good["client_credentials"]),
                         ("127.0.0.1:23456", "d100", "false"))
        self.assertEqual(good["auth_url"], "https://127.0.0.1:23456/oauth2/authorize")
        self.assertEqual(good["token_url"], "https://127.0.0.1:23456/oauth2_token")
        self.assertEqual(json.loads(good["token"]), {"access_token": state.token, "token_type": "Bearer",
                                                     "expiry": "0001-01-01T00:00:00Z"})
        wrong = LAB.pcloud_options(state, 23456, wrong_token=True)
        self.assertEqual(json.loads(wrong.pop("token"))["access_token"], state.wrong_token)
        good.pop("token")
        self.assertEqual(wrong, good)
        for port in (True, 0, 65536, "23456"):
            with self.subTest(port=port), self.assertRaises(LAB.LabError):
                LAB.pcloud_options(state, port)

    def test_options_reject_non_synthetic_token_or_non_boolean_mode(self):
        for token in ("", "short", "synthetic\nheader", "https://example.invalid/value"):
            with self.subTest(token=token), self.assertRaises(LAB.LabError):
                LAB.pcloud_options(SimpleNamespace(token=token, wrong_token="b" * 32), 23456)
        with self.assertRaises(LAB.LabError):
            LAB.pcloud_options(SimpleNamespace(token="a" * 32, wrong_token="a" * 32), 23456)
        with self.assertRaises(LAB.LabError):
            LAB.pcloud_options(SimpleNamespace(token="a" * 32, wrong_token="b" * 32), 23456, wrong_token=1)

    def test_loaded_dependencies_match_the_reviewed_lock(self):
        LAB.pcloud_dependencies()

    def test_distribution_metadata_cannot_hide_a_different_loaded_module(self):
        versions = {"cffi": "2.1.1", "cryptography": "50.0.2", "pycparser": "3.0"}
        loaded_versions = dict(versions, pycparser="3.00")
        for changed in versions:
            with self.subTest(changed=changed), mock.patch.object(importlib.metadata, "version", side_effect=versions.get), \
                    mock.patch.object(importlib, "import_module", side_effect=lambda name: SimpleNamespace(
                        __version__="0.0.0" if name == changed else loaded_versions[name])), self.assertRaisesRegex(
                        LAB.LabError, "pcloud_loaded_dependency_version_mismatch"):
                LAB.pcloud_dependencies()

    def test_lock_drift_and_missing_distribution_fail_closed(self):
        with mock.patch.object(Path, "read_text", return_value="cryptography==0.0.0 \\\n"), \
                self.assertRaisesRegex(LAB.LabError, "pcloud_dependency_lock_mismatch"):
            LAB.pcloud_dependencies()
        with mock.patch.object(importlib.metadata, "version", side_effect=importlib.metadata.PackageNotFoundError), \
                self.assertRaisesRegex(LAB.LabError, "pcloud_dependencies_missing"):
            LAB.pcloud_dependencies()

    def test_negative_error_requires_correct_cause_typed_envelope_and_operation(self):
        good = {"error": "loopback: call failed: couldn't list files: pcloud error: synthetic token rejected (2000)",
                "path": "operations/copyfile", "status": 500}
        self.assertTrue(LAB.pcloud_error_matches(json.dumps(good).encode(), "wrong_token"))
        for key, value in (("status", "500"), ("status", True), ("path", "operations/list"),
                           ("error", "generic transport failure")):
            with self.subTest(key=key):
                self.assertFalse(LAB.pcloud_error_matches(json.dumps(dict(good, **{key: value})).encode(), "wrong_token"))
        self.assertFalse(LAB.pcloud_error_matches(json.dumps(good).encode(), "missing"))
        self.assertFalse(LAB.pcloud_error_matches(b'{"error":"one","error":"two"}', "missing"))

    def state(self, events, **overrides):
        values = {"requests": len(events), "authenticated": len(events), "auth_denied": 0,
                  "member_denied": 0, "rejected_mutations": 0, "payload_bytes": 0, "unexpected": 0,
                  "rejected_payload_bytes": 0, "oauth_requests": 0, "budget_exceeded": False, "events": events}
        return SimpleNamespace(**dict(values, **overrides))

    def test_listing_accepts_checksum_order_only_after_recursive_root(self):
        events = [("list_recursive", ""), *[("checksum", name) for name in reversed(LAB.FILES)]]
        self.assertTrue(LAB.pcloud_flow_matches(self.state(events), "listing"))
        for wrong in (events[1:] + events[:1], events + [events[1]], events[:1] + [events[1]] * 3):
            self.assertFalse(LAB.pcloud_flow_matches(self.state(wrong), "listing"))

    def test_payload_requires_positive_parent_checksum_link_then_content(self):
        member = "nested/bytes.bin"
        events = [("root_list", ""), ("nested_list", "nested"), ("checksum", member), ("link", member), ("content", member)]
        state = self.state(events, payload_bytes=2048)
        self.assertTrue(LAB.pcloud_flow_matches(state, "download", member, 2048))
        for field, value in (("payload_bytes", 2047), ("authenticated", 4), ("oauth_requests", 1), ("unexpected", 1),
                             ("rejected_payload_bytes", 1), ("budget_exceeded", True), ("requests", True)):
            with self.subTest(field=field):
                bad = copy.deepcopy(state)
                setattr(bad, field, value)
                self.assertFalse(LAB.pcloud_flow_matches(bad, "download", member, 2048))
        self.assertFalse(LAB.pcloud_flow_matches(self.state(events[:-1], payload_bytes=2048), "download", member, 2048))

    def test_wrong_token_and_read_denial_cannot_be_empty_or_generic_errors(self):
        wrong = self.state([("auth_denied", "")], authenticated=0, auth_denied=1)
        self.assertTrue(LAB.pcloud_flow_matches(wrong, "wrong_token", "README-synthetic.txt"))
        self.assertFalse(LAB.pcloud_flow_matches(self.state([]), "wrong_token", "README-synthetic.txt"))
        denied = self.state([("root_list", ""), ("checksum", "README-synthetic.txt"), ("link", "README-synthetic.txt"),
                             ("content_denied", "README-synthetic.txt")], member_denied=1)
        self.assertTrue(LAB.pcloud_flow_matches(denied, "member_denied", "README-synthetic.txt"))
        self.assertFalse(LAB.pcloud_flow_matches(wrong, "member_denied", "README-synthetic.txt"))
        self.assertFalse(LAB.pcloud_flow_matches(denied, "wrong_token", "README-synthetic.txt"))

    def test_metadata_commands_are_inprocess_exact_closed_member_requests(self):
        args = LAB.pcloud_metadata_args("stat", "nested/space name.txt")
        self.assertEqual(args[:4], ["rc", "--loopback", "operations/stat", "--json"])
        self.assertEqual(json.loads(args[4])["fs"], "Synthetic:")
        self.assertEqual(json.loads(args[4])["remote"], "nested/space name.txt")
        for kind, member in (("delete", "README-synthetic.txt"), ("list", "nested"), ("stat", "../unknown")):
            with self.subTest(kind=kind, member=member), self.assertRaises(LAB.LabError):
                LAB.pcloud_metadata_args(kind, member)


if __name__ == "__main__":
    unittest.main()
