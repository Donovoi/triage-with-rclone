"""Tests for the regression proof and cross-architecture artifact gates."""
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("readfix_build", Path(__file__).with_name("build.py"))
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)


class RegressionProofTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.log = Path(self.temporary.name) / "tests.jsonl"

    def events(self, action):
        values = [{"Package": package, "Test": test, "Action": action}
                  for package, test in sorted(BUILD.EXPECTED_TESTS)]
        values += [{"Package": package, "Action": action}
                   for package in sorted({p for p, _ in BUILD.EXPECTED_TESTS})]
        return values

    def check(self, values, expected="fail"):
        self.log.write_text("\n".join(json.dumps(v) for v in values))
        return BUILD.test_result(self.log, expected)

    def test_all_named_baseline_failures_are_required(self):
        self.assertEqual(len(self.check(self.events("fail"))), 5)

    def test_patched_and_race_passes_are_required(self):
        self.assertEqual(len(self.check(self.events("pass"), "pass")), 5)

    def test_build_failure_does_not_prove_a_regression(self):
        with self.assertRaises(BUILD.BuildError):
            self.check([{"Package": p, "Action": "fail"} for p, _ in BUILD.EXPECTED_TESTS])

    def test_missing_or_wrong_named_test_fails(self):
        for event_index in range(5):
            values = self.events("fail")
            values[event_index]["Test"] = "TestUnrelated"
            with self.subTest(index=event_index), self.assertRaises(BUILD.BuildError):
                self.check(values)

    def test_unexpected_passing_baseline_fails(self):
        values = self.events("fail")
        values[0]["Action"] = "pass"
        with self.assertRaises(BUILD.BuildError):
            self.check(values)

    def test_skips_are_not_passing_regression_coverage(self):
        values = self.events("pass") + [{"Package": "anything", "Test": "TestSkipped", "Action": "skip"}]
        with self.assertRaises(BUILD.BuildError):
            self.check(values, "pass")

    def test_package_failure_after_test_passes_fails(self):
        values = self.events("pass")
        values[-1]["Action"] = "fail"
        with self.assertRaises(BUILD.BuildError):
            self.check(values, "pass")


class SourceTreeTests(unittest.TestCase):
    def test_full_tree_binding_detects_other_source_changes_and_new_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "backend.go").write_text("original")
            (root / "other.go").write_text("unpatched")
            baseline = BUILD.source_tree_digest(root)
            original = BUILD.digest(root / "backend.go")
            (root / "backend.go").write_text("patched")
            patches = [{"source": "backend.go", "before_sha256": original}]
            self.assertEqual(BUILD.source_tree_digest(root, patches), baseline)
            (root / "other.go").write_text("unexpected")
            self.assertNotEqual(BUILD.source_tree_digest(root, patches), baseline)
            (root / "other.go").write_text("unpatched")
            (root / "new.go").write_text("injected")
            self.assertNotEqual(BUILD.source_tree_digest(root, patches), baseline)

    def test_git_metadata_does_not_change_the_source_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "source.go").write_text("code")
            baseline = BUILD.source_tree_digest(root)
            (root / ".git").mkdir()
            (root / ".git/config").write_text("local path")
            self.assertEqual(BUILD.source_tree_digest(root), baseline)


class ModuleCopyTests(unittest.TestCase):
    def test_read_only_cache_copy_has_writable_root_and_children(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, target = root / "cache", root / "owned"
            source.mkdir()
            (source / "block.go").write_text("synthetic")
            (source / "block.go").chmod(0o444)
            source.chmod(0o555)
            try:
                BUILD.copy_module(source, target)
                self.assertTrue(target.stat().st_mode & 0o200)
                (target / "new_test.go").write_text("test")
                (target / "block.go").write_text("patched")
                self.assertEqual((source / "block.go").read_text(), "synthetic")
            finally:
                source.chmod(0o755)


class ArtifactArchitectureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.binary = Path(self.temporary.name) / "rclone"

    def pe(self, machine):
        data = bytearray(512)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 60, 128)
        data[128:132] = b"PE\0\0"
        struct.pack_into("<H", data, 132, machine)
        self.binary.write_bytes(data)

    def test_all_windows_machine_types(self):
        for platform, machine in (("windows-amd64", 0x8664), ("windows-386", 0x14c),
                                  ("windows-arm64", 0xaa64)):
            with self.subTest(platform=platform):
                self.pe(machine)
                BUILD.verify_binary(self.binary, platform)

    def test_wrong_machine_is_rejected(self):
        self.pe(0x8664)
        with self.assertRaises(BUILD.BuildError):
            BUILD.verify_binary(self.binary, "windows-arm64")

    def test_out_of_bounds_pe_header_is_rejected(self):
        self.pe(0x8664)
        data = bytearray(self.binary.read_bytes())
        struct.pack_into("<I", data, 60, 2**32 - 1)
        self.binary.write_bytes(data)
        with self.assertRaises(BUILD.BuildError):
            BUILD.verify_binary(self.binary, "windows-amd64")

    def test_linux_architecture(self):
        data = bytearray(64)
        data[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", data, 18, 62)
        self.binary.write_bytes(data)
        BUILD.verify_binary(self.binary, "linux-amd64")
        struct.pack_into("<H", data, 18, 183)
        self.binary.write_bytes(data)
        with self.assertRaises(BUILD.BuildError):
            BUILD.verify_binary(self.binary, "linux-amd64")

    def test_truncation_is_rejected(self):
        for platform in ("linux-amd64", "windows-amd64"):
            self.binary.write_bytes(b"")
            with self.subTest(platform=platform), self.assertRaises(BUILD.BuildError):
                BUILD.verify_binary(self.binary, platform)


if __name__ == "__main__":
    unittest.main()
