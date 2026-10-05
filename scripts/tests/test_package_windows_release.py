"""Release packaging checks use synthetic PE headers and no native execution."""

import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile


SPEC = importlib.util.spec_from_file_location(
    "package_windows_release", Path(__file__).parents[1] / "package_windows_release.py")
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.artifacts = self.root / "artifacts"
        self.output = self.root / "release"
        self.commit = "a" * 40
        self.manifest = self.root / "rclone-version.env"
        self.manifest.write_text("RCLONE_VERSION=1.75.1\n")
        self.builds = {}
        for arch, (target, machine) in PACKAGE.TARGETS.items():
            build = self.artifacts / arch / "rclone-triage" / "target" / target / "release"
            build.mkdir(parents=True)
            data = bytearray(256)
            data[:2] = b"MZ"
            struct.pack_into("<I", data, 60, 128)
            data[128:132] = b"PE\0\0"
            struct.pack_into("<H", data, 132, machine)
            (build / "rclone-triage.exe").write_bytes(data)
            (build / "dependencies.json").write_text('{"schema_version":1}\n')
            (self.artifacts / arch / "rclone-version.env").write_text('RCLONE_VERSION=1.75.1\n')
            self.builds[arch] = build

    def test_all_architectures_include_exact_inputs_and_verifiable_hashes(self):
        PACKAGE.package(self.artifacts, self.output, self.commit, "123", "1", self.manifest)
        self.assertEqual(len(list(self.output.iterdir())), 4)
        for line in (self.output / "SHA256SUMS").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((self.output / name).read_bytes()).hexdigest(), digest)
        for arch, build in self.builds.items():
            with zipfile.ZipFile(self.output / f"rclone-triage-windows-{arch}.zip") as archive:
                self.assertEqual(set(archive.namelist()), {
                    "rclone-triage.exe", "dependencies.json", "rclone-version.env", "BUILD.json", "SHA256SUMS"})
                self.assertEqual(archive.read("rclone-triage.exe"), (build / "rclone-triage.exe").read_bytes())
                self.assertEqual(json.loads(archive.read("BUILD.json")), {
                    "commit": self.commit, "architecture": arch,
                    "run_id": "123", "run_attempt": "1",
                    "channel": "nightly", "provider_acceptance_complete": False})
                for line in archive.read("SHA256SUMS").decode().splitlines():
                    digest, name = line.split("  ")
                    self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(), digest)

    def test_missing_architecture_prevents_any_publication(self):
        (self.builds["arm64"] / "rclone-triage.exe").unlink()
        with self.assertRaises(ValueError):
            PACKAGE.package(self.artifacts, self.output, self.commit, "123", "1", self.manifest)
        self.assertFalse(self.output.exists())

    def test_wrong_architecture_prevents_any_publication(self):
        (self.builds["x86"] / "rclone-triage.exe").write_bytes(
            (self.builds["x64"] / "rclone-triage.exe").read_bytes())
        with self.assertRaisesRegex(ValueError, "wrong architecture"):
            PACKAGE.package(self.artifacts, self.output, self.commit, "123", "1", self.manifest)
        self.assertFalse(self.output.exists())

    def test_mixed_runtime_manifests_are_rejected(self):
        (self.artifacts / "arm64" / "rclone-version.env").write_text('RCLONE_VERSION=1.75.0\n')
        with self.assertRaisesRegex(ValueError, "manifests disagree"):
            PACKAGE.package(self.artifacts, self.output, self.commit, "123", "1", self.manifest)
        self.assertFalse(self.output.exists())

    def test_all_stale_manifests_cannot_be_relabelled_as_current_commit(self):
        for arch in PACKAGE.TARGETS:
            (self.artifacts / arch / "rclone-version.env").write_text('RCLONE_VERSION=1.75.0\n')
        with self.assertRaisesRegex(ValueError, "manifests disagree"):
            PACKAGE.package(self.artifacts, self.output, self.commit, "123", "1", self.manifest)
        self.assertFalse(self.output.exists())

    def test_existing_output_is_preserved(self):
        self.output.mkdir()
        sentinel = self.output / "keep.txt"
        sentinel.write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            PACKAGE.package(self.artifacts, self.output, self.commit, "123", "1", self.manifest)
        self.assertEqual(list(self.output.iterdir()), [sentinel])

    def test_invalid_commit_and_pe_headers_are_rejected(self):
        for commit in ("main", "A" * 40, "a" * 39, "a" * 40 + "\n"):
            with self.subTest(commit=commit), self.assertRaises(ValueError):
                PACKAGE.package(self.artifacts, self.output, commit, "123", "1", self.manifest)
        for data in (b"", b"MZ", b"MZ" + bytes(254)):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                PACKAGE.machine(data)


if __name__ == "__main__":
    unittest.main()
