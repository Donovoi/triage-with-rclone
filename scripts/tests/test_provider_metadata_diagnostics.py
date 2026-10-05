"""Filesystem fault injection only: metadata children are always forbidden."""
import contextlib
import errno
import gc
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import weakref


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "provider_coverage_metadata_diagnostics", ROOT / "scripts" / "provider_coverage.py")
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)
CANARY = "PRIVATE_CANARY_path_token_and_child_output"
CATALOG_BYTES = b'[{"Name":"http","Prefix":"http","Options":[]}]'


class OwnedTemporary:
    def cleanup(self):
        self.cleanup_calls += 1
        if self.cleanup_error is not None:
            raise self.cleanup_error
        self.inner.cleanup()


class MetadataDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.binary = self.root / "original-runtime"
        self.binary.write_bytes(b"synthetic non-executable metadata fixture")
        self.digest = C.sha256_bytes(self.binary.read_bytes())
        self.manifest = self.root / "pins.env"
        self.manifest.write_text("RCLONE_VERSION=1.75.1\nRCLONE_LINUX_EXE_SHA256=" + self.digest)
        self.owned = []
        self.cleanup_error = None
        self.real_temporary = tempfile.TemporaryDirectory
        self.stack.enter_context(patch.object(C.platform_module, "system", return_value="Linux"))
        self.popen = self.stack.enter_context(patch.object(
            C.subprocess, "Popen", side_effect=AssertionError("native execution forbidden")))
        self.metadata = self.stack.enter_context(patch.object(C, "run_metadata", side_effect=self.output))

    def output(self, executable, arguments, config, environment):
        self.assertNotEqual(executable, self.binary)
        self.assertEqual(executable.read_bytes(), self.binary.read_bytes())
        self.assertEqual(config.read_bytes(), b"")
        self.assertEqual(executable.parent, config.parent)
        return b"rclone v1.75.1\n" if arguments == ["version"] else CATALOG_BYTES

    def own_temporary(self, **kwargs):
        self.assertEqual(kwargs, {"prefix": "triage-catalog-"})
        # C.tempfile and the test's tempfile share one module; use the saved
        # constructor for test storage without re-entering this patched factory.
        item = object.__new__(OwnedTemporary)
        item.inner = self.real_temporary(dir=self.root, prefix="owned-catalog-")
        item.name = item.inner.name
        item.cleanup_error = self.cleanup_error
        item.cleanup_calls = 0
        self.owned.append(item)
        self.addCleanup(item.inner.cleanup)
        return item

    def query(self):
        with patch.object(C.tempfile, "TemporaryDirectory", side_effect=self.own_temporary):
            return C.query_runtime(self.binary, self.manifest)

    def assert_failure(self, expected, operation=None):
        with self.assertRaises(C.CoverageError) as caught:
            (operation or self.query)()
        error = caught.exception
        codes = list(error.codes) if isinstance(error, C.MetadataDiagnosticError) else [str(error)]
        self.assertEqual(codes, expected)
        self.assertNotIn(CANARY, repr(error.__dict__) + str(error))
        self.assertIsNone(error.__context__)
        self.assertIsNone(error.__cause__)
        self.popen.assert_not_called()
        return error

    def main(self, *extra):
        report = self.root / ("report-" + str(len(list(self.root.glob("report-*")))) + ".json")
        captured = io.StringIO()
        with patch.object(C.tempfile, "TemporaryDirectory", side_effect=self.own_temporary), \
                contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
            status = C.main(["--rclone", str(self.binary), "--manifest", str(self.manifest),
                             "--report", str(report), *extra])
        text = report.read_text()
        self.assertNotIn(CANARY, text + captured.getvalue())
        self.assertNotIn(str(self.root), text + captured.getvalue())
        self.popen.assert_not_called()
        return status, json.loads(text)

    def test_preflight_failure_is_classified_without_temp_or_child(self):
        with patch.object(C, "plain_path", side_effect=PermissionError(errno.EACCES, CANARY)):
            self.assert_failure(["metadata_runtime_preflight_access_denied"])
        self.assertEqual(self.owned, [])
        self.metadata.assert_not_called()

    def test_existing_verification_failure_code_is_preserved(self):
        with patch.object(Path, "read_text", side_effect=OSError(CANARY)):
            self.assert_failure(["runtime_verification_failed"])
        self.assertEqual(self.owned, [])
        self.metadata.assert_not_called()

    def test_unclassified_verification_failure_has_finite_stage(self):
        with patch.object(Path, "read_text", side_effect=TypeError(CANARY)):
            self.assert_failure(["metadata_runtime_verification_type_error"])
        self.assertEqual(self.owned, [])

    def test_temporary_creation_failure_is_distinct(self):
        with patch.object(C.tempfile, "TemporaryDirectory", side_effect=PermissionError(CANARY)):
            self.assert_failure(["metadata_temporary_create_access_denied"],
                                lambda: C.query_runtime(self.binary, self.manifest))
        self.metadata.assert_not_called()

    def test_permissions_copy_rehash_and_config_failures_cleanup_exact_owned_root(self):
        real_chmod, real_open, real_os_open = Path.chmod, Path.open, C.os.open
        for target, expected in (
                ("root", "temporary_permissions"), ("copy", "runtime_copy"),
                ("executable", "runtime_permissions"), ("rehash", "runtime_rehash"),
                ("config", "config_create")):
            with self.subTest(stage=expected), contextlib.ExitStack() as patches:
                def chmod(path, *args, **kwargs):
                    if ((target == "root" and path.name.startswith("owned-catalog-"))
                            or (target == "executable" and path.name == "rclone")):
                        raise PermissionError(errno.EACCES, CANARY)
                    return real_chmod(path, *args, **kwargs)

                def opened(path, *args, **kwargs):
                    if target == "rehash" and path.name == "rclone":
                        raise PermissionError(errno.EACCES, CANARY)
                    return real_open(path, *args, **kwargs)

                def os_open(path, *args, **kwargs):
                    if target == "config" and Path(path).name == "empty.conf":
                        raise PermissionError(errno.EACCES, CANARY)
                    return real_os_open(path, *args, **kwargs)

                patches.enter_context(patch.object(Path, "chmod", chmod))
                patches.enter_context(patch.object(Path, "open", opened))
                patches.enter_context(patch.object(C.os, "open", os_open))
                if target == "copy":
                    patches.enter_context(patch.object(C.shutil, "copyfile", side_effect=PermissionError(CANARY)))
                self.assert_failure([f"metadata_{expected}_access_denied"])
                self.assertEqual(self.owned[-1].cleanup_calls, 1)
                self.assertFalse(Path(self.owned[-1].name).exists())
        self.metadata.assert_not_called()
        self.assertEqual(self.binary.read_bytes(), b"synthetic non-executable metadata fixture")

    def test_version_and_providers_boundaries_are_distinct(self):
        for arguments, expected in ((["version"], "version_probe"),
                                    (["config", "providers"], "providers_probe")):
            with self.subTest(stage=expected):
                def output(executable, selected, config, environment):
                    if selected == arguments:
                        raise subprocess.SubprocessError(CANARY)
                    return self.output(executable, selected, config, environment)
                self.metadata.side_effect = output
                self.assert_failure([f"metadata_{expected}_subprocess_error"])
                self.assertEqual(self.owned[-1].cleanup_calls, 1)
                self.assertFalse(Path(self.owned[-1].name).exists())

    def test_catalog_parse_unclassified_failure_is_distinct(self):
        with patch.object(C, "catalog_from_schemas", side_effect=TypeError(CANARY)):
            self.assert_failure(["metadata_catalog_parse_type_error"])
        self.assertEqual(self.owned[-1].cleanup_calls, 1)

    def test_existing_typed_probe_and_catalog_failures_remain_unchanged(self):
        for code in ("metadata_start_failed", "metadata_bound_exceeded", "metadata_command_failed"):
            with self.subTest(code=code):
                self.metadata.side_effect = C.CoverageError(code)
                error = self.assert_failure([code])
                self.assertIs(type(error), C.CoverageError)
                self.assertEqual(self.owned[-1].cleanup_calls, 1)
        self.metadata.side_effect = lambda executable, arguments, config, environment: (
            b"rclone v1.75.1\n" if arguments == ["version"] else CANARY.encode())
        self.assert_failure(["invalid_catalog"])

    def test_typed_primary_plus_cleanup_failure_both_reach_cli_report(self):
        self.metadata.side_effect = C.CoverageError("metadata_command_failed")
        self.cleanup_error = PermissionError(errno.EACCES, CANARY)
        status, report = self.main()
        self.assertEqual(status, 1)
        self.assertEqual(report["errors"], ["metadata_command_failed", "metadata_temporary_cleanup_access_denied"])
        self.assertEqual(report["gate_errors"], report["errors"])
        self.assertEqual(report["providers"], [])
        self.assertEqual(self.owned[-1].cleanup_calls, 1)
        self.assertTrue(Path(self.owned[-1].name).exists())

    def test_untyped_primary_plus_cleanup_failure_retains_order_and_no_exception_objects(self):
        self.metadata.side_effect = TypeError(CANARY)
        self.cleanup_error = OSError(CANARY)
        error = self.assert_failure(["metadata_version_probe_type_error", "metadata_temporary_cleanup_os_error"])
        self.assertEqual(set(error.__dict__), {"codes"})
        self.assertTrue(all(type(code) is str for code in error.codes))
        self.assertEqual(self.owned[-1].cleanup_calls, 1)

    def test_original_exception_is_released_before_cleanup(self):
        class PrivateFault(TypeError):
            pass

        references = []
        checked = []
        original_cleanup = OwnedTemporary.cleanup

        def fail_metadata(*args):
            error = PrivateFault(CANARY)
            references.append(weakref.ref(error))
            raise error

        def cleanup(owned):
            gc.collect()
            self.assertEqual(len(references), 1)
            self.assertIsNone(references[0]())
            checked.append(True)
            return original_cleanup(owned)

        self.metadata.side_effect = fail_metadata
        with patch.object(OwnedTemporary, "cleanup", cleanup):
            self.assert_failure(["metadata_version_probe_type_error"])
        self.assertEqual(checked, [True])

    def test_successful_query_cannot_hide_failed_cleanup(self):
        self.cleanup_error = PermissionError(CANARY)
        status, report = self.main()
        self.assertEqual(self.metadata.call_count, 2)
        self.assertEqual(status, 1)
        self.assertEqual(report["errors"], ["metadata_temporary_cleanup_access_denied"])
        self.assertFalse(report["all_complete"])
        self.assertFalse(report["all_plans_current"])
        self.assertEqual(self.owned[-1].cleanup_calls, 1)

    def test_success_returns_catalog_only_after_cleanup(self):
        runtime, catalog = self.query()
        self.assertEqual(runtime, {"version": "1.75.1", "sha256": self.digest, "platform": "linux"})
        self.assertEqual([entry["backend"] for entry in catalog], ["http"])
        self.assertEqual([call.args[1] for call in self.metadata.call_args_list],
                         [["version"], ["config", "providers"]])
        self.assertEqual(self.owned[-1].cleanup_calls, 1)
        self.assertFalse(Path(self.owned[-1].name).exists())
        self.popen.assert_not_called()

    def test_initial_summary_failure_is_classified_separately(self):
        with patch.object(C, "evaluate", side_effect=TypeError(CANARY)):
            status, report = self.main()
        self.assertEqual(status, 1)
        self.assertEqual(report["errors"], ["metadata_initial_catalog_summary_type_error"])
        self.assertEqual(self.metadata.call_count, 2)
        self.assertFalse(Path(self.owned[-1].name).exists())

    def test_later_input_failure_keeps_existing_generic_code_and_catalog(self):
        with patch.object(C, "read_json", side_effect=TypeError(CANARY)):
            status, report = self.main()
        self.assertEqual(status, 1)
        self.assertEqual(report["errors"], ["coverage_input_failed"])
        self.assertEqual([entry["backend"] for entry in report["providers"]], ["http"])

    def test_static_categories_never_include_exception_text_or_numeric_codes(self):
        sharing = OSError(CANARY)
        sharing.winerror = 32
        unknown_os = OSError(123456, CANARY)
        for error, category in (
                (sharing, "sharing_violation"), (PermissionError(CANARY), "access_denied"),
                (FileNotFoundError(CANARY), "not_found"), (unknown_os, "os_error"),
                (subprocess.TimeoutExpired(CANARY, 30), "timeout"),
                (subprocess.SubprocessError(CANARY), "subprocess_error"),
                (ValueError(CANARY), "value_error"), (TypeError(CANARY), "type_error"),
                (KeyError(CANARY), "key_error"), (RuntimeError(CANARY), "runtime_error")):
            with self.subTest(category=category):
                self.assertEqual(C.metadata_diagnostic("temporary_cleanup", error),
                                 "metadata_temporary_cleanup_" + category)
        with self.assertRaisesRegex(ValueError, "^invalid_metadata_stage$"):
            C.metadata_diagnostic(CANARY, sharing)
        with self.assertRaisesRegex(ValueError, "^invalid_metadata_diagnostic$"):
            C.MetadataDiagnosticError(None, [CANARY])
        with self.assertRaisesRegex(ValueError, "^invalid_metadata_diagnostic$"):
            C.MetadataDiagnosticError("/private/path", ["metadata_runtime_copy_os_error"])


if __name__ == "__main__":
    unittest.main()
