"""Closed setup names only; no native helper, process or socket execution."""
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import types
import unittest
from unittest import mock


PATH = Path(__file__).resolve().parents[1] / "application-lab/run_windows_http.py"
SPEC = importlib.util.spec_from_file_location("application_setup_alias_subject", PATH)
H = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(H)

HTTP = ("listing", "acquisition", "mismatch", "missing", "denial", "cancellation")
WEBDAV = ("webdav-listing", "webdav-acquisition", "webdav-mismatch", "webdav-missing",
          "webdav-wrong-credentials", "webdav-accepted-a", "webdav-revoked-a",
          "webdav-replacement-b", "webdav-permission-denied", "webdav-truncated-transfer",
          "webdav-cancellation")


class SetupAliasTests(unittest.TestCase):
    def setUp(self):
        for obj, name in ((subprocess, "Popen"), (subprocess, "run"), (socket, "socket")):
            patch = mock.patch.object(obj, name, side_effect=AssertionError("native_work_forbidden"))
            patch.start()
            self.addCleanup(patch.stop)

    def test_exact_legacy_and_namespaced_webdav_names(self):
        for name in HTTP + WEBDAV:
            self.assertEqual(H.setup_scope(name), name)
        self.assertEqual(H.setup_scope("webdav-credentials"), "webdav_credentials")
        self.assertEqual(H.setup_scope("webdav-credential-setup"), "webdav_credential_setup")
        self.assertEqual(H.setup_scope("app-http-" + "a" * 32), "suite")
        self.assertEqual(H.setup_scope("app-webdav-" + "b" * 32), "webdav_suite")

    def test_path_aliases_unknown_names_and_wrong_types_fail_before_setup(self):
        invalid = [None, False, 1, b"listing", [], {}, "", "accepted_a", "webdav-suite",
                   "webdav-unknown", "webdav_wrong_credentials", "app-webdav-",
                   "app-webdav-" + "a" * 31, "app-webdav-" + "a" * 33,
                   "app-webdav-" + "g" * 32]
        for name in HTTP + WEBDAV + ("webdav-credential-setup", "webdav-credentials", "app-webdav-" + "b" * 32):
            invalid.extend((name.upper(), name + "\n", name + "\x00", name + "/child",
                            name + "\\child", "../" + name, " " + name, name + " "))
        with mock.patch.object(H, "hosted_guard"), mock.patch.object(H, "identity") as identity:
            for name in invalid:
                with self.subTest(name_type=type(name).__name__), self.assertRaisesRegex(
                        H.ProducerError, "^case_setup_failed$"):
                    H.prepare(Path("synthetic-parent"), name)
            identity.assert_not_called()

    def test_allowed_names_reach_only_fixed_helper_and_unchanged_protocol(self):
        stages = ("input", "parent", "identity", "acl", "compile", "create", "verify", "complete")
        records = [dict(schema_version=1, stage=stage) for stage in stages]
        records.append(dict(schema_version=1, ok=True))
        output = b"".join(json.dumps(row).encode() + b"\n" for row in records)
        parent = Path("synthetic-parent").absolute()
        with mock.patch.object(H, "hosted_guard"), mock.patch.object(H, "identity", return_value=(1, 2)), \
             mock.patch.object(H, "setup_environment", return_value={"SYNTHETIC": "1"}), \
             mock.patch.object(H, "powershell", return_value="fixed-system-powershell"), \
             mock.patch.object(H, "hidden", return_value={}), \
             mock.patch.object(H.subprocess, "run", return_value=types.SimpleNamespace(
                 returncode=0, stdout=output)) as child:
            for name in HTTP + WEBDAV + ("webdav-credential-setup", "webdav-credentials", "app-webdav-" + "b" * 32):
                self.assertEqual(H.prepare(parent, name), parent / name)
                self.assertEqual(child.call_args.args[0], ["fixed-system-powershell", "-NoProfile",
                    "-NonInteractive", "-File", str(H.HERE / "prepare_case.ps1"),
                    "-Action", "Create", "-Parent", str(parent), "-Name", name])
                self.assertEqual(child.call_args.kwargs["timeout"], 20)
                self.assertEqual(child.call_args.kwargs["env"], {"SYNTHETIC": "1"})


if __name__ == "__main__":
    unittest.main()
