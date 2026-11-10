"""Pure filesystem faults; all runtime children and network operations forbidden."""
import contextlib
import errno
import gc
import io
import json
from pathlib import Path
import types
import unittest
from unittest.mock import patch
import weakref

import test_provider_metadata_diagnostics as D

C = D.C


class MetadataCleanupRetryTests(unittest.TestCase):
    output = D.MetadataDiagnosticsTests.output
    own_temporary = D.MetadataDiagnosticsTests.own_temporary
    query = D.MetadataDiagnosticsTests.query
    assert_failure = D.MetadataDiagnosticsTests.assert_failure

    def setUp(self):
        D.MetadataDiagnosticsTests.setUp(self)
        self.stack.enter_context(patch.object(C.platform_module, "system", return_value="Windows"))
        self.manifest.write_text(self.manifest.read_text() + "\nRCLONE_EXE_SHA256=" + self.digest)
        self.sleep = self.stack.enter_context(patch.object(C.time, "sleep"))
        self.clock = self.stack.enter_context(patch.object(C.time, "monotonic_ns", return_value=1_000_000))
        self.failures = 1
        self.winerror = 32
        self.target = "rclone.exe"
        self.hook = lambda owned: None
        self.captured = io.StringIO()
        self.stack.enter_context(contextlib.redirect_stderr(self.captured))
        self.stack.enter_context(patch.object(D.OwnedTemporary, "cleanup", lambda owned: self.cleanup(owned)))

    def cleanup(self, owned):
        owned.cleanup_calls += 1
        if owned.cleanup_calls <= self.failures:
            self.hook(owned)
            error = OSError(errno.EACCES, D.CANARY, str(Path(owned.name) / self.target))
            error.winerror = self.winerror
            raise error
        owned.inner.cleanup()

    def receipts(self):
        text = self.captured.getvalue()
        self.assertNotIn(D.CANARY, text)
        self.assertNotIn(str(self.root), text)
        records = []
        for line in text.splitlines():
            self.assertLessEqual(len((line + "\n").encode()), 768)
            prefix, payload = line.split("=", 1)
            records.append((prefix, json.loads(payload)))
        return records

    def failure(self):
        return self.assert_failure(["metadata_temporary_cleanup_sharing_violation"])

    def test_normalized_owned_path_alias_retains_identity_and_cleans_up(self):
        # A valid lexical spelling may differ from resolve(), as Windows short
        # names do. Exercise the distinction with a portable dot-dot spelling.
        component = self.root / "alias-parent"
        component.mkdir()
        original_factory = self.own_temporary
        def aliased_temporary(**kwargs):
            item = original_factory(**kwargs)
            item.name = str(component / ".." / Path(item.name).name)
            self.assertNotEqual(Path(item.name), Path(item.name).resolve(strict=True))
            return item
        self.own_temporary = aliased_temporary
        self.query()
        self.assertEqual(self.owned[-1].cleanup_calls, 2)
        self.assertFalse(Path(self.owned[-1].name).exists())
        self.assertTrue(component.is_dir())
        self.assertEqual(self.receipts()[-1][1]["stop_reason"], "verified_absent")

    def test_canonical_resolution_to_different_object_is_rejected(self):
        replacement = self.root / "unrelated-file"
        replacement.write_text("preserve")
        original = Path.resolve
        def resolve(target, strict=False):
            return replacement if target.name == "rclone.exe" else original(target, strict=strict)
        with patch.object(Path, "resolve", resolve):
            self.assert_failure(["metadata_cleanup_resolution_mismatch",
                                 "metadata_temporary_cleanup_sharing_violation"])
        self.sleep.assert_not_called()
        self.metadata.assert_not_called()
        self.assertEqual(replacement.read_text(), "preserve")

    def test_changed_canonical_spelling_refuses_recursive_retry(self):
        original_identity = C._metadata_cleanup_identity
        def identity(target, directory=False):
            value = original_identity(target, directory)
            return (*value[:3], value[3] + "-changed") if self.sleep.called else value
        with patch.object(C, "_metadata_cleanup_identity", side_effect=identity):
            self.failure()
        self.assertEqual(self.owned[-1].cleanup_calls, 1)
        self.assertEqual(self.receipts()[-1][1]["stop_reason"], "ownership_rejected")

    def test_zero_inode_and_multiple_links_remain_fatal(self):
        original = Path.lstat
        for field, value, code in (("st_ino", 0, "metadata_cleanup_inode_unavailable"),
                                   ("st_nlink", 2, "metadata_cleanup_hardlink_rejected")):
            def changed(target):
                info = original(target)
                if target.name == "rclone.exe":
                    fields = {key: getattr(info, key) for key in dir(info) if key.startswith("st_")}
                    fields[field] = value
                    return types.SimpleNamespace(**fields)
                return info
            with self.subTest(field=field), patch.object(Path, "lstat", changed):
                self.assert_failure([code, "metadata_temporary_cleanup_sharing_violation"])
                self.assertEqual(self.owned[-1].cleanup_calls, 1)
        self.sleep.assert_not_called()
        self.metadata.assert_not_called()

    def test_transient_lock_retries_only_cleanup_and_verifies_absence(self):
        runtime, catalog = self.query()
        self.assertEqual(runtime["platform"], "windows")
        self.assertEqual(catalog[0]["backend"], "http")
        self.assertEqual(self.owned[-1].cleanup_calls, 2)
        self.sleep.assert_called_once_with(0.1)
        self.assertFalse(Path(self.owned[-1].name).exists())
        self.assertEqual([call.args[1] for call in self.metadata.call_args_list],
                         [["version"], ["config", "providers"]])
        self.assertEqual(self.binary.read_bytes(), b"synthetic non-executable metadata fixture")
        self.assertEqual(self.receipts()[-1][1], {"schema_version": 1, "attempts": 2,
                         "stop_reason": "verified_absent", "cleanup_verified": True})
        self.popen.assert_not_called()

    def test_persistent_lock_fails_after_five_explicit_attempts(self):
        self.failures = 9
        self.failure()
        self.assertEqual(self.owned[-1].cleanup_calls, 5)
        self.assertEqual([call.args[0] for call in self.sleep.call_args_list], [0.1, 0.2, 0.4, 0.8])
        records = self.receipts()
        self.assertEqual([r["attempt"] for p, r in records if p == C.METADATA_CLEANUP_PREFIX[:-1]],
                         [1, 2, 3, 4, 5])
        self.assertEqual(records[-1][1]["stop_reason"], "attempts_exhausted")
        self.assertFalse(records[-1][1]["cleanup_verified"])
        self.assertEqual(self.metadata.call_count, 2)

    def test_lock_clearing_on_last_allowed_attempt_succeeds(self):
        self.failures = 4
        self.query()
        self.assertEqual(self.owned[-1].cleanup_calls, 5)
        self.assertEqual(self.receipts()[-1][1]["stop_reason"], "verified_absent")

    def test_other_windows_errors_and_targets_are_not_retried(self):
        for number, target, category in ((33, "rclone.exe", "sharing_violation"),
                                        (5, "rclone.exe", "access_denied"),
                                        (32, "empty.conf", "sharing_violation"),
                                        (32, "unrecognized", "sharing_violation")):
            with self.subTest(number=number, target=target):
                self.winerror, self.target = number, target
                self.assert_failure(["metadata_temporary_cleanup_" + category])
                self.assertEqual(self.owned[-1].cleanup_calls, 1)
        self.sleep.assert_not_called()

    def test_linux_does_not_retry_a_synthetic_windows_error(self):
        self.target = "rclone"
        with patch.object(C.platform_module, "system", return_value="Linux"):
            self.failure()
        self.assertEqual(self.owned[-1].cleanup_calls, 1)
        self.sleep.assert_not_called()

    def test_failed_metadata_probe_never_retries_cleanup(self):
        self.metadata.side_effect = C.CoverageError("metadata_command_failed")
        self.assert_failure(["metadata_command_failed", "metadata_temporary_cleanup_sharing_violation"])
        self.sleep.assert_not_called()
        self.assertEqual(self.owned[-1].cleanup_calls, 1)

    def test_invalid_catalog_never_retries_cleanup(self):
        self.metadata.side_effect = [b"rclone v1.75.1\n", b"invalid"]
        self.assert_failure(["invalid_catalog", "metadata_temporary_cleanup_sharing_violation"])
        self.sleep.assert_not_called()

    def test_unavailable_clock_does_not_retry(self):
        self.clock.return_value = None
        self.failure()
        self.sleep.assert_not_called()
        self.assertEqual(self.receipts()[-1][1]["stop_reason"], "budget_exhausted")

    def test_budget_before_wait_prevents_retry(self):
        self.clock.side_effect = [0, 0, 1_900_000_000]
        self.failure()
        self.sleep.assert_not_called()
        self.assertEqual(self.owned[-1].cleanup_calls, 1)

    def test_budget_after_wait_prevents_retry(self):
        self.clock.side_effect = [0, 0, 0, 2_000_000_000]
        self.failure()
        self.sleep.assert_called_once_with(0.1)
        self.assertEqual(self.owned[-1].cleanup_calls, 1)

    def test_clock_regression_prevents_retry(self):
        self.clock.side_effect = [10, 10, 9]
        self.failure()
        self.sleep.assert_not_called()

    def test_added_entry_refuses_recursive_retry(self):
        self.hook = lambda owned: (Path(owned.name) / "foreign").write_text("preserve")
        self.failure()
        self.assertEqual((Path(self.owned[-1].name) / "foreign").read_text(), "preserve")
        self.assertEqual(self.owned[-1].cleanup_calls, 1)
        self.assertEqual(self.receipts()[-1][1]["stop_reason"], "ownership_rejected")

    def test_replaced_runtime_inode_refuses_recursive_retry(self):
        def replace(owned):
            original = Path(owned.name) / "rclone.exe"
            # Both paths are inside this test's independently owned temporary root.
            saved = self.root / "saved-copy"
            self.assertEqual(original.parent.parent, self.root)
            self.assertEqual(saved.parent, self.root)
            original.rename(saved)
            original.write_text("replacement")
        self.hook = replace
        self.failure()
        self.assertEqual((Path(self.owned[-1].name) / "rclone.exe").read_text(), "replacement")
        self.assertEqual(self.owned[-1].cleanup_calls, 1)

    def test_root_identity_change_refuses_recursive_retry(self):
        real_identity = C._metadata_cleanup_identity
        def identity(target, directory=False):
            value = real_identity(target, directory)
            return (value[0], value[1] + 1, value[2]) if directory and self.sleep.called else value
        with patch.object(C, "_metadata_cleanup_identity", side_effect=identity):
            self.failure()
        self.assertEqual(self.owned[-1].cleanup_calls, 1)

    def test_symlink_reparse_hardlink_and_directory_leaves_are_rejected(self):
        import stat
        original = Path.lstat
        for field, value in (("st_mode", stat.S_IFLNK), ("st_file_attributes", 0x400),
                             ("st_nlink", 2), ("st_mode", stat.S_IFDIR)):
            self.sleep.reset_mock()
            def changed(target):
                info = original(target)
                if target.name == "rclone.exe" and self.sleep.called:
                    fields = {key: getattr(info, key) for key in dir(info) if key.startswith("st_")}
                    fields[field] = value
                    return types.SimpleNamespace(**fields)
                return info
            with self.subTest(field=field, value=value), patch.object(Path, "lstat", changed):
                self.failure()
                self.assertEqual(self.owned[-1].cleanup_calls, 1)

    def test_partial_first_cleanup_allows_absent_owned_config(self):
        self.hook = lambda owned: (Path(owned.name) / "empty.conf").unlink()
        self.query()
        self.assertEqual(self.owned[-1].cleanup_calls, 2)
        self.assertFalse(Path(self.owned[-1].name).exists())

    def test_nominal_cleanup_success_without_root_removal_is_rejected(self):
        def incomplete(owned):
            if not owned.cleanup_calls:
                return self.cleanup(owned)
            owned.cleanup_calls += 1
        with patch.object(D.OwnedTemporary, "cleanup", incomplete):
            self.failure()
        self.assertEqual(self.receipts()[-1][1]["stop_reason"], "absence_unverified")
        self.assertTrue(Path(self.owned[-1].name).exists())

    def test_retry_does_not_retain_previous_exception(self):
        refs = []
        class WeakError(OSError):
            pass
        def cleanup(owned):
            owned.cleanup_calls += 1
            if owned.cleanup_calls == 1:
                error = WeakError(errno.EACCES, D.CANARY, str(Path(owned.name) / "rclone.exe"))
                error.winerror = 32
                refs.append(weakref.ref(error))
                raise error
            gc.collect()
            self.assertIsNone(refs[0]())
            owned.inner.cleanup()
        with patch.object(D.OwnedTemporary, "cleanup", cleanup):
            self.query()

    def test_diagnostic_failure_cannot_hide_persistent_cleanup_failure(self):
        self.failures = 9
        with patch.object(C, "format_metadata_cleanup_diagnostic", side_effect=RuntimeError(D.CANARY)), \
                patch.object(C.sys, "stderr", types.SimpleNamespace(write=lambda text: (_ for _ in ()).throw(OSError()))):
            self.failure()
        self.assertEqual(self.owned[-1].cleanup_calls, 5)

    def test_real_temporary_directory_cleanup_is_reusable_after_delete_failure(self):
        original_rmtree = self.real_temporary._rmtree
        calls = []
        def rmtree(name, *args, **kwargs):
            calls.append(name)
            if len(calls) == 1:
                error = OSError(errno.EACCES, D.CANARY, str(Path(name) / "rclone.exe"))
                error.winerror = 32
                raise error
            return original_rmtree(name, *args, **kwargs)
        def cleanup(owned):
            owned.cleanup_calls += 1
            owned.inner.cleanup()
        with patch.object(D.OwnedTemporary, "cleanup", cleanup), \
                patch.object(self.real_temporary, "_rmtree", side_effect=rmtree):
            self.query()
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0], calls[1])
        self.assertFalse(Path(calls[0]).exists())

    def test_changed_cleanup_error_stops_after_first_retry(self):
        self.failures = 9
        self.sleep.side_effect = lambda delay: setattr(self, "winerror", 5)
        self.assert_failure(["metadata_temporary_cleanup_access_denied"])
        self.assertEqual(self.owned[-1].cleanup_calls, 2)
        self.assertEqual(self.receipts()[-1][1]["stop_reason"], "cleanup_failed")

    def test_sleep_failure_preserves_original_closed_error(self):
        self.sleep.side_effect = OSError(D.CANARY)
        self.failure()
        self.assertEqual(self.owned[-1].cleanup_calls, 1)
        self.assertEqual(self.receipts()[-1][1]["stop_reason"], "cleanup_failed")


if __name__ == "__main__":
    unittest.main()
