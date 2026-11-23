"""Archive bytes and evidence gates must fail closed before distribution."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest import mock
import zipfile

spec = importlib.util.spec_from_file_location("distribution_package", Path(__file__).with_name("package.py"))
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_rebuild_ignores_input_order_permissions_and_mtime(self):
        binary = self.root / "binary"
        binary.write_bytes(b"executable bytes\x00")
        entries = [("rclone", binary, True), ("source/lock.json", b"{}\n", False)]
        first, second = self.root / "a.zip", self.root / "b.zip"
        package.archive(first, "runtime-test", entries)
        binary.chmod(0o600)
        os.utime(binary, (1700000000, 1700000000))
        package.archive(second, "runtime-test", list(reversed(entries)))
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with zipfile.ZipFile(first) as archive:
            self.assertEqual(archive.namelist(), ["runtime-test/rclone", "runtime-test/source/lock.json"])
            for item in archive.infolist():
                self.assertEqual(item.date_time, package.STAMP)
                self.assertEqual(item.create_system, 3)
                self.assertEqual(item.compress_type, zipfile.ZIP_STORED)
                self.assertEqual(item.extra, b"")
                self.assertEqual(item.comment, b"")
                mode = item.external_attr >> 16
                self.assertTrue(stat.S_ISREG(mode))
                self.assertEqual(stat.S_IMODE(mode), 0o755 if item.filename.endswith("/rclone") else 0o644)
            self.assertEqual(archive.read("runtime-test/rclone"), binary.read_bytes())

    def test_existing_archive_is_never_overwritten(self):
        target = self.root / "existing.zip"
        target.write_bytes(b"keep")
        with self.assertRaisesRegex(package.PackageError, "archive_already_exists"):
            package.archive(target, "test", [("rclone", b"new", True)])
        self.assertEqual(target.read_bytes(), b"keep")

    def test_prefix_traversal_and_unsafe_members_rejected(self):
        for index, prefix in enumerate(("../escape", "/absolute", ".", "..", "bad\\name")):
            with self.subTest(prefix=prefix), self.assertRaisesRegex(package.PackageError, "invalid_archive_prefix"):
                package.archive(self.root / f"prefix-{index}.zip", prefix, [("rclone", b"x", True)])
        for index, member in enumerate(("../escape", "/absolute", "a/../b", "a//b", "a/./b", "a\\b", "a/", "")):
            with self.subTest(member=member), self.assertRaisesRegex(package.PackageError, "invalid_archive_member"):
                package.archive(self.root / f"member-{index}.zip", "test", [(member, b"x", False)])

    def test_duplicate_members_rejected(self):
        with self.assertRaisesRegex(package.PackageError, "duplicate_archive_member"):
            package.archive(self.root / "duplicate.zip", "test", [("a", b"x", False), ("a", b"y", False)])

    def test_symlink_input_rejected(self):
        source = self.root / "source"
        source.write_bytes(b"data")
        link = self.root / "link"
        link.symlink_to(source)
        with self.assertRaisesRegex(package.PackageError, "plain_input_file_required"):
            package.archive(self.root / "symlink.zip", "test", [("data", link, False)])


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.work = self.root / "work"
        self.work.mkdir()
        self.native_dir = self.root / "provider-lab/readfix-experimental"
        self.native_dir.mkdir(parents=True)
        for name in ("run.py", "generate.go", "Dockerfile"):
            (self.native_dir / name).write_text("fixture")
        for name in ("fixture_tls.py", "requirements-fixture.txt"):
            (self.native_dir.parent / name).write_text("shared")
        patch = mock.patch.object(package, "NATIVE", self.native_dir)
        patch.start()
        self.addCleanup(patch.stop)
        self.lock = {"platforms": ["linux-amd64", "windows-amd64", "windows-386", "windows-arm64"],
                     "runtime_version": "v1.76.0-triage-readfix.2", "rclone_commit": "source",
                     "scope": "experimental", "toolchain": "go1.27.4"}
        self.identity = {"build.py": "current"}
        self.recipe = types.SimpleNamespace(
            verify_source=mock.Mock(), verify_prepared=mock.Mock(), verify_binary=mock.Mock(),
            recipe_identity=lambda: self.identity, EXPECTED_TESTS={("package", "regression")})
        self.native_gate = types.SimpleNamespace(PROVIDERS={"filen": 25}, validate_report=mock.Mock())
        self.checks = {"success": True, "recipe": self.identity, "scope": "experimental", "ledger_eligible": False}
        for field, outcome in (("baseline", "fail"), ("fixed", "pass"), ("race", "pass")):
            self.checks[field] = [{"package": "package", "test": "regression", "outcome": outcome}]
        self.write(self.work / "checks.json", self.checks)
        self.write(self.work / "prepared.json", {"source_tree_sha256": "tree"})
        self.builds = {}
        for platform in self.lock["platforms"]:
            directory = self.work / "artifacts" / platform
            directory.mkdir(parents=True)
            binary = directory / ("rclone.exe" if platform.startswith("windows-") else "rclone")
            binary.write_bytes(platform.encode())
            build = {"success": True, "recipe": self.identity, "different_root_rebuild_matched": True,
                     "runtime_version": self.lock["runtime_version"], "source_commit": "source",
                     "source_tree_sha256": "tree", "platform": platform, "sha256": package.digest(binary),
                     "bytes": binary.stat().st_size, "ledger_eligible": False, "scope": "experimental",
                     "toolchain": "go1.27.4", "execution_verified": platform == "linux-amd64"}
            self.builds[platform] = build
            self.write(directory / "build.json", build)
        self.native_path = self.root / "native.json"
        self.runtime = {key: self.builds["linux-amd64"][key] for key in ("runtime_version", "sha256", "source_commit")}
        self.native = {"success": True, "errors": [], "ledger_eligible": False,
                      "scope": "experimental_native_reads_not_provider_acceptance", "runtime": self.runtime,
                      "providers": {"filen": {"success": True, "container_removed": True, "native": {"proof": "native"}}},
                      "source_sha256": {p.relative_to(self.native_dir.parent).as_posix(): package.digest(p)
                                        for p in self.native_dir.parent.rglob("*") if p.is_file()}}
        self.write(self.native_path, self.native)

    @staticmethod
    def write(path, value):
        path.write_text(json.dumps(value))

    def verify(self):
        return package.verify_inputs(self.work, self.native_path, self.recipe, self.native_gate, self.lock)

    def test_complete_receipts_delegate_source_architecture_and_native_checks(self):
        self.assertEqual(self.verify(), self.builds)
        self.recipe.verify_source.assert_called_once_with(self.work / "rclone", self.lock, True)
        self.recipe.verify_prepared.assert_called_once_with(self.work, self.lock)
        self.assertEqual(self.recipe.verify_binary.call_count, 4)
        self.native_gate.validate_report.assert_called_once_with({"proof": "native"}, "filen", self.runtime)

    def test_missing_or_wrong_regression_results_rejected(self):
        for field, wrong in (("baseline", []), ("fixed", []), ("race", []),
                             ("baseline", [{"package": "package", "test": "regression", "outcome": "pass"}])):
            checks = copy.deepcopy(self.checks)
            checks[field] = wrong
            self.write(self.work / "checks.json", checks)
            with self.subTest(field=field, wrong=wrong), self.assertRaisesRegex(package.PackageError, "complete_regressions_required"):
                self.verify()

    def test_stale_or_wrong_scope_regression_receipt_rejected(self):
        for field, wrong in (("recipe", {}), ("success", False), ("scope", "live"), ("ledger_eligible", True)):
            checks = copy.deepcopy(self.checks)
            checks[field] = wrong
            self.write(self.work / "checks.json", checks)
            with self.subTest(field=field), self.assertRaisesRegex(package.PackageError, "current_regressions_required"):
                self.verify()

    def test_build_receipt_field_mismatch_rejected(self):
        target = self.work / "artifacts/linux-amd64/build.json"
        mutations = {"success": False, "recipe": {}, "different_root_rebuild_matched": False,
                     "runtime_version": "v1.76.0", "source_commit": "wrong", "source_tree_sha256": "wrong",
                     "platform": "windows-amd64", "sha256": "wrong", "bytes": 0, "ledger_eligible": True,
                     "scope": "live", "toolchain": "go1.26.0"}
        for field, wrong in mutations.items():
            build = copy.deepcopy(self.builds["linux-amd64"])
            build[field] = wrong
            self.write(target, build)
            with self.subTest(field=field), self.assertRaisesRegex(package.PackageError, "verified_build_required"):
                self.verify()

    def test_changed_binary_bytes_rejected(self):
        (self.work / "artifacts/windows-arm64/rclone.exe").write_bytes(b"tampered")
        with self.assertRaisesRegex(package.PackageError, "verified_build_required"):
            self.verify()

    def test_windows_execution_is_not_inferred_from_cross_build(self):
        build = dict(self.builds["windows-amd64"], execution_verified=True)
        self.write(self.work / "artifacts/windows-amd64/build.json", build)
        with self.assertRaisesRegex(package.PackageError, "execution_scope_mismatch"):
            self.verify()

    def test_incomplete_or_wrong_scope_native_receipt_rejected(self):
        for field, wrong in (("providers", {}), ("errors", ["failure"]), ("success", False),
                             ("ledger_eligible", True), ("scope", "live")):
            native = copy.deepcopy(self.native)
            native[field] = wrong
            self.write(self.native_path, native)
            with self.subTest(field=field), self.assertRaisesRegex(package.PackageError, "complete_native_report_required"):
                self.verify()

    def test_native_runtime_and_cleanup_required(self):
        native = copy.deepcopy(self.native)
        native["runtime"]["sha256"] = "wrong"
        self.write(self.native_path, native)
        with self.assertRaisesRegex(package.PackageError, "native_runtime_mismatch"):
            self.verify()
        native = copy.deepcopy(self.native)
        native["providers"]["filen"]["container_removed"] = False
        self.write(self.native_path, native)
        with self.assertRaisesRegex(package.PackageError, "native_cleanup_required"):
            self.verify()

    def test_native_gate_failure_propagates(self):
        self.native_gate.validate_report.side_effect = RuntimeError("native failure")
        with self.assertRaisesRegex(RuntimeError, "native failure"):
            self.verify()

    def test_missing_and_changed_native_sources_rejected(self):
        native = copy.deepcopy(self.native)
        native["source_sha256"].pop("readfix-experimental/Dockerfile")
        self.write(self.native_path, native)
        with self.assertRaisesRegex(package.PackageError, "native_source_inventory_mismatch"):
            self.verify()
        self.write(self.native_path, self.native)
        (self.native_dir / "generate.go").write_text("changed")
        with self.assertRaisesRegex(package.PackageError, "native_source_changed"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
