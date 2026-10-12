"""Filesystem fault injection only: metadata children are always forbidden."""
import contextlib
import errno
import gc
import importlib.util
import io
import json
from pathlib import Path
import socket
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
        self.stack.enter_context(patch.object(
            socket, "socket", side_effect=AssertionError("network execution forbidden")))
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
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            runtime, catalog = self.query()
        self.assertEqual(captured.getvalue(), "")
        self.assertEqual(runtime, {"version": "1.75.1", "sha256": self.digest, "platform": "linux"})
        self.assertEqual([entry["backend"] for entry in catalog], ["http"])
        self.assertEqual([call.args[1] for call in self.metadata.call_args_list],
                         [["version"], ["config", "providers"]])
        self.assertEqual(self.owned[-1].cleanup_calls, 1)
        self.assertFalse(Path(self.owned[-1].name).exists())
        self.popen.assert_not_called()

    def cleanup_record(self, operation=None):
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            result = (operation or self.query)()
        lines = captured.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith(C.METADATA_CLEANUP_PREFIX))
        self.assertLessEqual(len(captured.getvalue().encode("utf-8")), 768)
        self.assertNotIn(CANARY, captured.getvalue())
        self.assertNotIn(str(self.root), captured.getvalue())
        return result, json.loads(lines[0][len(C.METADATA_CLEANUP_PREFIX):])

    def test_cleanup_numbers_distinguish_sharing_errors_without_changing_failure(self):
        original_cleanup = OwnedTemporary.cleanup
        for number in (32, 33):
            with self.subTest(winerror=number):
                def cleanup(owned):
                    fault = OSError(errno.EACCES, CANARY, str(Path(owned.name) / "rclone"))
                    fault.winerror = number
                    owned.cleanup_error = fault
                    original_cleanup(owned)

                with patch.object(OwnedTemporary, "cleanup", cleanup), \
                        patch.object(C.time, "monotonic_ns", side_effect=[1_000_000, 8_999_999]):
                    error, record = self.cleanup_record(lambda: self.assert_failure(
                        ["metadata_temporary_cleanup_sharing_violation"]))
                self.assertEqual(record, {
                    "schema_version": 1, "stage": "temporary_cleanup", "attempt": 1,
                    "errno": errno.EACCES, "winerror": number, "target": "runtime_copy",
                    "suboperation": None, "elapsed_ms": 7, "version_probe_completed": True,
                    "providers_probe_completed": True, "catalog_parsed": True,
                })
                self.assertEqual(set(error.__dict__), {"codes"})
                self.assertEqual(self.owned[-1].cleanup_calls, 1)
                self.assertTrue(Path(self.owned[-1].name).exists())

    def test_cleanup_flags_describe_only_completed_boundaries_and_preserve_order(self):
        self.cleanup_error = OSError(CANARY)
        for phase, expected, flags in (
                ("version", "metadata_start_failed", (False, False, False)),
                ("version_mismatch", "runtime_version_mismatch", (False, False, False)),
                ("providers", "metadata_command_failed", (True, False, False)),
                ("parse", "invalid_catalog", (True, True, False))):
            with self.subTest(phase=phase):
                def output(executable, arguments, config, environment):
                    if phase == "version":
                        raise C.CoverageError("metadata_start_failed")
                    if phase == "version_mismatch":
                        return b"rclone v0.0.0\n"
                    if arguments == ["config", "providers"]:
                        if phase == "providers":
                            raise C.CoverageError("metadata_command_failed")
                        return b"invalid JSON"
                    return self.output(executable, arguments, config, environment)
                self.metadata.side_effect = output
                _, record = self.cleanup_record(lambda: self.assert_failure(
                    [expected, "metadata_temporary_cleanup_os_error"]))
                self.assertEqual(tuple(record[name] for name in (
                    "version_probe_completed", "providers_probe_completed", "catalog_parsed")), flags)
                self.assertEqual(self.owned[-1].cleanup_calls, 1)

    def test_cleanup_details_do_not_change_failed_cli_report(self):
        self.cleanup_error = OSError(errno.EACCES, CANARY)
        self.cleanup_error.winerror = 33
        status, report = self.main()
        self.assertEqual(status, 1)
        self.assertEqual(report["errors"], ["metadata_temporary_cleanup_sharing_violation"])
        self.assertEqual(report["providers"], [])
        self.assertFalse(report["all_complete"])
        self.assertFalse(report["all_plans_current"])
        self.assertEqual(self.owned[-1].cleanup_calls, 1)

    def test_diagnostic_faults_never_replace_cleanup_or_retry(self):
        self.cleanup_error = OSError(CANARY)
        for target in ("metadata_cleanup_record", "format_metadata_cleanup_diagnostic"):
            with self.subTest(target=target), patch.object(C, target, side_effect=RuntimeError(CANARY)):
                self.assert_failure(["metadata_temporary_cleanup_os_error"])
                self.assertEqual(self.owned[-1].cleanup_calls, 1)
                self.assertTrue(Path(self.owned[-1].name).exists())
        with patch("builtins.print", side_effect=OSError(CANARY)):
            self.assert_failure(["metadata_temporary_cleanup_os_error"])
        self.assertEqual(self.owned[-1].cleanup_calls, 1)
        original_format = C.format_metadata_cleanup_diagnostic
        for serialization in (UnicodeError(CANARY), "\ud800", "x" * 768):
            options = ({"side_effect": serialization} if isinstance(serialization, Exception)
                       else {"return_value": serialization})

            def broken_format(record):
                # The catalog also uses json.dumps: inject only at the new formatter.
                with patch.object(C.json, "dumps", **options):
                    return original_format(record)

            with patch.object(C, "format_metadata_cleanup_diagnostic", side_effect=broken_format), \
                    contextlib.redirect_stderr(io.StringIO()) as output:
                self.assert_failure(["metadata_temporary_cleanup_os_error"])
                self.assertEqual(output.getvalue(), "")
                self.assertEqual(self.owned[-1].cleanup_calls, 1)
        with patch.object(C.time, "monotonic_ns", side_effect=RuntimeError(CANARY)):
            _, record = self.cleanup_record(lambda: self.assert_failure(
                ["metadata_temporary_cleanup_os_error"]))
        self.assertIsNone(record["elapsed_ms"])
        self.assertEqual(self.owned[-1].cleanup_calls, 1)

    def test_cleanup_exception_is_not_retained_by_projection(self):
        class PrivateFault(OSError):
            pass

        references = []

        def cleanup(owned):
            owned.cleanup_calls += 1
            fault = PrivateFault(errno.EACCES, CANARY, CANARY)
            references.append(weakref.ref(fault))
            raise fault

        with patch.object(OwnedTemporary, "cleanup", cleanup):
            error, _ = self.cleanup_record(lambda: self.assert_failure(
                ["metadata_temporary_cleanup_access_denied"]))
        gc.collect()
        self.assertIsNone(references[0]())
        self.assertEqual(set(error.__dict__), {"codes"})

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


class MetadataCleanupProjectionTests(unittest.TestCase):
    TARGETS = {"runtime_copy": "C:\\owned\\rclone.exe", "empty_config": "C:\\owned\\empty.conf",
               "temporary_root": "C:\\owned"}

    def record(self, error=None, *, started=1_000_000, ended=2_000_000, targets=None):
        with patch.object(C.time, "monotonic_ns", return_value=ended):
            return C.metadata_cleanup_record(error if error is not None else OSError(CANARY),
                                             self.TARGETS if targets is None else targets,
                                             started, (True, True, True))

    def test_target_uses_only_exact_assigned_lexical_paths(self):
        for expected, path in self.TARGETS.items():
            with self.subTest(expected=expected):
                record = self.record(OSError(errno.EACCES, CANARY, path))
                self.assertEqual(record["target"], expected)
                line = C.format_metadata_cleanup_diagnostic(record)
                self.assertNotIn(path, line)
                self.assertNotIn(CANARY, line)
        for path in (None, "rclone.exe", "C:\\elsewhere\\rclone.exe", "c:\\owned\\rclone.exe",
                     "\\\\?\\C:\\owned\\rclone.exe", "C:/owned/rclone.exe", ".\\rclone.exe",
                     "C:\\owned\\other", "C:\\owned\\rclone.exe\0" + CANARY, CANARY, "x" * 4097):
            with self.subTest(path_type=type(path).__name__):
                fault = OSError(errno.EACCES, CANARY)
                fault.filename = path
                record = self.record(fault)
                self.assertEqual(record["target"], "unavailable")
                self.assertIsNone(record["suboperation"])
                self.assertNotIn(CANARY, C.format_metadata_cleanup_diagnostic(record))
        self.assertEqual(self.record(OSError(13, CANARY, self.TARGETS["runtime_copy"]),
                                     targets={})["target"], "unavailable")

    def test_attributes_are_optional_exact_bounded_integers_not_coerced(self):
        for name, maximum in (("errno", 2_147_483_647), ("winerror", 4_294_967_295)):
            for value in (None, True, False, "32", -1, maximum + 1, [32]):
                with self.subTest(name=name, value_type=type(value).__name__):
                    fault = OSError(CANARY)
                    setattr(fault, name, value)
                    self.assertIsNone(self.record(fault)[name])
            for value in (0, maximum):
                fault = OSError(CANARY)
                setattr(fault, name, value)
                self.assertEqual(self.record(fault)[name], value)
        not_os = RuntimeError(CANARY)
        not_os.errno, not_os.winerror, not_os.filename = 13, 32, self.TARGETS["runtime_copy"]
        record = self.record(not_os)
        self.assertIsNone(record["errno"])
        self.assertIsNone(record["winerror"])
        self.assertEqual(record["target"], "unavailable")

    def test_raising_attributes_and_private_string_conversion_are_never_leaked(self):
        seen = []

        class Fault(OSError):
            def __getattribute__(self, name):
                if name in ("errno", "winerror", "filename", "filename2"):
                    seen.append(name)
                    raise RuntimeError(CANARY)
                return super().__getattribute__(name)

            def __str__(self):
                raise AssertionError("exception text must not be read")

        record = self.record(Fault())
        self.assertEqual((record["errno"], record["winerror"], record["target"]),
                         (None, None, "unavailable"))
        self.assertEqual(seen, ["filename", "errno", "winerror"])
        self.assertNotIn(CANARY, C.format_metadata_cleanup_diagnostic(record))

    def test_clock_uncertainty_is_null_and_never_an_elapsed_claim(self):
        for start, end in ((None, 2), (True, 2), (-1, 2), (3, 2), (0, None),
                           (0, True), (0, 1.5), (0, -1), (0, 2_147_483_648_000_000)):
            with self.subTest(start=start, end=end):
                self.assertIsNone(self.record(started=start, ended=end)["elapsed_ms"])
        self.assertEqual(self.record(started=0, ended=2_147_483_647_999_999)["elapsed_ms"],
                         2_147_483_647)

    def test_formatter_closed_types_keys_enums_and_full_line_bound(self):
        record = self.record()
        line = C.format_metadata_cleanup_diagnostic(record)
        self.assertLessEqual(len((line + "\n").encode("utf-8")), 768)
        self.assertEqual(json.loads(line[len(C.METADATA_CLEANUP_PREFIX):]), record)
        self.assertEqual(set(record), {"schema_version", "stage", "attempt", "errno", "winerror",
                                     "target", "suboperation", "elapsed_ms", "version_probe_completed",
                                     "providers_probe_completed", "catalog_parsed"})
        changes = ({"extra": CANARY}, {"stage": "temporary_cleanup\0" + CANARY},
                   {"target": "runtime_copy\0"}, {"suboperation": "unlink"},
                   {"schema_version": True}, {"attempt": 2}, {"attempt": True},
                   {"errno": True}, {"winerror": "32"}, {"elapsed_ms": -1},
                   {"version_probe_completed": 1}, {"providers_probe_completed": None},
                   {"catalog_parsed": "true"})
        for change in changes:
            with self.subTest(field=next(iter(change))), self.assertRaisesRegex(
                    ValueError, "^invalid_metadata_cleanup_diagnostic$"):
                C.format_metadata_cleanup_diagnostic(record | change)
        for key in record:
            incomplete = dict(record)
            del incomplete[key]
            with self.assertRaisesRegex(ValueError, "^invalid_metadata_cleanup_diagnostic$"):
                C.format_metadata_cleanup_diagnostic(incomplete)


if __name__ == "__main__":
    unittest.main()
