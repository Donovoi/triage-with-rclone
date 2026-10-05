"""GCS evidence predicates only: no HTTP server or native runtime is used."""
import copy
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

LAB_ROOT = Path(__file__).parents[1] / "provider-lab"
sys.path.insert(0, str(LAB_ROOT))
try:
    import run_lab as LAB
finally:
    sys.path.pop(0)

PAYLOADS = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
            "nested/bytes.bin": bytes(range(256)) * 8,
            "nested/space name.txt": b"Nested synthetic payload.\n"}
CAUSES = {"missing": "object not found",
          "wrong_token": "googleapi: Error 401: Synthetic fixture authError, authError",
          "member_denied": "failed to open source object: googleapi: Error 403: Synthetic fixture forbidden, forbidden"}


class GcsRunnerTests(unittest.TestCase):
    def metadata(self):
        return {"list": [{"Path": name, "Name": name.rsplit("/", 1)[-1], "Size": len(body),
                          "IsDir": False, "ModTime": "2024-01-01T00:00:00Z",
                          "Hashes": {"md5": hashlib.md5(body).hexdigest()}}
                         for name, body in sorted(PAYLOADS.items())]}

    def test_metadata_matches_exact_three_independent_files(self):
        expected = [{"path": name, "size": len(body), "sha256": hashlib.sha256(body).hexdigest()}
                    for name, body in sorted(PAYLOADS.items())]
        good = self.metadata()
        self.assertTrue(LAB.gcs_metadata_matches(json.dumps(good).encode(), expected))
        for field, value in (("Path", "../README-synthetic.txt"), ("Path", []), ("Name", "wrong"),
                             ("Size", True), ("Size", 0), ("IsDir", 0), ("Hashes", {}),
                             ("Hashes", {"md5": "0" * 32}), ("ModTime", "2024-01-01T00:00:00.000000001Z"),
                             ("ModTime", "2024-01-01T00:00:00-00:00"), ("extra", "private-canary")):
            bad = copy.deepcopy(good); bad["list"][0][field] = value
            with self.subTest(field=field, value=value):
                self.assertFalse(LAB.gcs_metadata_matches(json.dumps(bad).encode(), expected))
        for rows in (good["list"][:2], good["list"] + [good["list"][0]], [good["list"][0]] * 3):
            self.assertFalse(LAB.gcs_metadata_matches(json.dumps({"list": rows}).encode(), expected))
        for output in (b'{"list":null}', b'{"list":[],"list":[]}', b'[]', b'null', b'{"list":[NaN]}'):
            self.assertFalse(LAB.gcs_metadata_matches(output, expected))

    def test_options_use_only_static_token_on_exact_loopback_endpoint(self):
        state = SimpleNamespace(token="synthetic-" + "a" * 32, wrong_token="wrong-synthetic-" + "b" * 32)
        good = LAB.gcs_options(state, 23456)
        self.assertEqual(good, dict(type="google cloud storage", access_token=state.token,
            endpoint="http://127.0.0.1:23456/storage/v1/", anonymous="false", env_auth="false",
            service_account_file="", service_account_credentials="", project_number=""))
        self.assertEqual(LAB.gcs_options(state, 23456, wrong_token=True), dict(good, access_token=state.wrong_token))
        for port in (True, 0, 65536, "23456"):
            with self.subTest(port=port), self.assertRaises(LAB.LabError): LAB.gcs_options(state, port)
        for token in ("", "short", "a" * 97, "x\n" * 16, "é" * 32, state.wrong_token):
            with self.subTest(token=token), self.assertRaises(LAB.LabError):
                LAB.gcs_options(SimpleNamespace(token=token, wrong_token=state.wrong_token), 23456)
        with self.assertRaises(LAB.LabError): LAB.gcs_options(state, 23456, wrong_token=1)

    def test_listing_is_inprocess_exact_bucket_with_hashes(self):
        args = LAB.gcs_metadata_args()
        self.assertEqual(args[:4], ["rc", "--loopback", "operations/list", "--json"])
        self.assertEqual(json.loads(args[4]), {"fs": "Synthetic:synthetic-bucket", "remote": "",
            "opt": {"filesOnly": True, "showHash": True, "noModTime": False, "noMimeType": True, "recurse": True}})

    def test_negative_causes_require_exact_typed_rc_envelope(self):
        for kind, cause in CAUSES.items():
            good = {"error": "loopback: call failed: " + cause, "path": "operations/copyfile", "status": 500}
            self.assertTrue(LAB.gcs_error_matches(json.dumps(good).encode(), kind))
            for field, value in (("error", "connection refused private-canary"), ("error", cause),
                                 ("path", "operations/list"), ("status", True), ("status", "500"),
                                 ("status", 401), ("extra", "private-canary")):
                self.assertFalse(LAB.gcs_error_matches(json.dumps(dict(good, **{field: value})).encode(), kind))
            for other in set(CAUSES) - {kind}: self.assertFalse(LAB.gcs_error_matches(json.dumps(good).encode(), other))
        for raw in (b'null', b'[]', b'{"error":"one","error":"two"}', b'{"status":NaN}', b'not json'):
            self.assertFalse(LAB.gcs_error_matches(raw, "missing"))

    @staticmethod
    def state(events, **overrides):
        values = dict(events=events, requests=len(events), authenticated=len(events), auth_denied=0,
                      missing=0, member_denied=0, rejected_mutations=0, payload_bytes=0, unexpected=0,
                      rejected_payload_bytes=0, budget_exceeded=False)
        return SimpleNamespace(**dict(values, **overrides))

    def test_download_requires_metadata_then_same_member_and_exact_payload_count(self):
        name = "nested/bytes.bin"
        events = [("metadata", name), ("content", name)]
        good = self.state(events, payload_bytes=2048)
        self.assertTrue(LAB.gcs_flow_matches(good, "download", name, 2048))
        for field, value in (("events", list(reversed(events))), ("events", events + events),
                             ("events", [("metadata", name), ("content", "README-synthetic.txt")]),
                             ("payload_bytes", 2047), ("payload_bytes", True), ("requests", True),
                             ("requests", 3), ("authenticated", 1), ("unexpected", 1),
                             ("rejected_payload_bytes", 1), ("budget_exceeded", True), ("budget_exceeded", 0)):
            bad = copy.deepcopy(good); setattr(bad, field, value)
            self.assertFalse(LAB.gcs_flow_matches(bad, "download", name, 2048))
        self.assertFalse(LAB.gcs_flow_matches(good, "download", name, True))

    def test_negative_events_are_distinct_and_cannot_borrow_payload_or_setup(self):
        name = "README-synthetic.txt"; missing = "missing-synthetic-object.bin"
        cases = (("missing", missing, self.state([("missing", missing)], missing=1)),
                 ("wrong_token", name, self.state([("auth_denied", name)], authenticated=0, auth_denied=1)),
                 ("member_denied", name, self.state([("metadata", name), ("content_denied", name)], member_denied=1)))
        for kind, member, state in cases:
            self.assertTrue(LAB.gcs_flow_matches(state, kind, member))
            self.assertFalse(LAB.gcs_flow_matches(self.state([]), kind, member))
            for field, value in (("payload_bytes", 1), ("rejected_payload_bytes", 1), ("missing", True),
                                 ("rejected_mutations", 1), ("events", state.events + [("list", "")])):
                bad = copy.deepcopy(state); setattr(bad, field, value)
                self.assertFalse(LAB.gcs_flow_matches(bad, kind, member))
            for other, other_member, _ in cases:
                if other != kind: self.assertFalse(LAB.gcs_flow_matches(state, other, other_member))
        self.assertTrue(LAB.gcs_flow_matches(self.state([("list", "")]), "listing"))
        self.assertFalse(LAB.gcs_flow_matches(self.state([("list", ""), ("list", "")]), "listing"))


if __name__ == "__main__": unittest.main()
