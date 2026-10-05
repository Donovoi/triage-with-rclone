"""Runtime architecture data/source contracts. No executable or network calls."""
import hashlib
import importlib.util
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
ARCH_KEYS = ("RCLONE_WINDOWS_X86_EXE_SHA256", "RCLONE_WINDOWS_X86_ZIP_SHA256",
             "RCLONE_WINDOWS_ARM64_EXE_SHA256", "RCLONE_WINDOWS_ARM64_ZIP_SHA256")


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    # All imports are source/data only; any attempted process is a test failure.
    with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("native execution forbidden")):
        spec.loader.exec_module(module)
    return module


class RuntimeArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        old_path = list(sys.path)
        try:
            cls.smb = load("architecture_smb", "scripts/provider-lab/smb/probe_samba.py")
            cls.oauth = load("architecture_oauth", "scripts/provider-lab/pcloud-oauth/probe.py")
            cls.container = load("architecture_container", "scripts/provider-lab/pcloud-oauth/run_container.py")
            cls.hdfs = load("architecture_hdfs", "scripts/provider-lab/hdfs-fixture/container_fixture.py")
        finally:
            sys.path[:] = old_path

    def parsers(self, root, binary):
        path = root / "rclone-version.env"
        return (
            (lambda: self.smb.read_runtime_pins(path), self.smb.ProbeError),
            (lambda: self.oauth.pins(path), self.oauth.ProbeError),
            (lambda: self.container.runtime_identity(binary), self.container.SupervisorError),
            (lambda: self.hdfs.runtime_pin(path), self.hdfs.FixtureError),
        )

    def test_all_closed_consumers_accept_legacy_or_complete_extended_pins_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "never-executed.bin"
            binary.write_bytes(b"synthetic bytes, not an executable")
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            legacy = {"RCLONE_VERSION": "1.75.1", "RCLONE_EXE_SHA256": "a" * 64,
                      "RCLONE_WINDOWS_ZIP_SHA256": "b" * 64, "RCLONE_LINUX_ZIP_SHA256": "c" * 64,
                      "RCLONE_LINUX_EXE_SHA256": digest}
            extra = {key: "d" * 64 for key in ARCH_KEYS}
            path = root / "rclone-version.env"
            with mock.patch.object(self.container, "REPOSITORY", root):
                for mask in range(16):
                    pins = dict(legacy, **{key: extra[key] for i, key in enumerate(ARCH_KEYS) if mask & (1 << i)})
                    path.write_text("".join(f"{key}={value}\n" for key, value in pins.items()), encoding="ascii")
                    for index, (parse, failure) in enumerate(self.parsers(root, binary)):
                        with self.subTest(mask=mask, parser=index):
                            if mask not in (0, 15):
                                with self.assertRaises(failure):
                                    parse()
                            else:
                                result = parse()
                                self.assertIn(result, (("1.75.1", digest), {"version": "1.75.1", "sha256": digest}))

    def test_extended_consumers_reject_invalid_extra_hashes_unknown_and_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "never-executed.bin"
            binary.write_bytes(b"synthetic bytes")
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            body = (ROOT / "rclone-version.env").read_text()
            body = re.sub(r"(?m)^RCLONE_LINUX_EXE_SHA256=.*$", "RCLONE_LINUX_EXE_SHA256=" + digest, body)
            mutations = [body + "UNEXPECTED_PIN=" + "a" * 64 + "\n",
                         body + ARCH_KEYS[0] + "=" + "a" * 64 + "\n"]
            for key in ARCH_KEYS:
                for invalid in ("a" * 63, "A" * 64, "g" * 64):
                    mutations.append(re.sub(r"(?m)^" + key + r"=.*$", key + "=" + invalid, body))
            with mock.patch.object(self.container, "REPOSITORY", root):
                for mutation in mutations:
                    (root / "rclone-version.env").write_text(mutation, encoding="ascii")
                    for parse, failure in self.parsers(root, binary):
                        with self.assertRaises(failure):
                            parse()

    def test_download_and_build_architecture_selection_source_contract(self):
        build = (ROOT / "rclone-triage/build.rs").read_text()
        # Literal independent architecture/machine oracle; hosted CI compiles Rust.
        choices = dict((arch, (key, int(machine, 16))) for arch, key, machine in re.findall(
            r'"(x86_64|i686|aarch64)" => \("([A-Z0-9_]+)", (0x[0-9a-f]+)\)', build))
        self.assertEqual(choices, {"x86_64": ("RCLONE_EXE_SHA256", 0x8664),
                                   "i686": ("RCLONE_WINDOWS_X86_EXE_SHA256", 0x014c),
                                   "aarch64": ("RCLONE_WINDOWS_ARM64_EXE_SHA256", 0xaa64)})
        self.assertIn('std::env::var("TARGET").expect(', build)
        self.assertIn('_ => panic!("Unsupported Windows runtime architecture")', build)
        self.assertIn('verify_pe_machine("assets/rclone.exe", machine)', build)
        self.assertRegex(build, r'u16::from_le_bytes\(\[pe\[4\], pe\[5\]\]\),\s+expected,')
        ps = (ROOT / "scripts/download-rclone.ps1").read_text()
        self.assertIn("[ValidateSet('x64', 'x86', 'arm64')][string]$Architecture = 'x64'", ps)
        expected = {"x64": ("amd64", "RCLONE_WINDOWS_ZIP_SHA256", "RCLONE_EXE_SHA256"),
                    "x86": ("386", "RCLONE_WINDOWS_X86_ZIP_SHA256", "RCLONE_WINDOWS_X86_EXE_SHA256"),
                    "arm64": ("arm64", "RCLONE_WINDOWS_ARM64_ZIP_SHA256", "RCLONE_WINDOWS_ARM64_EXE_SHA256")}
        actual = {arch: (platform, archive, binary) for arch, platform, archive, binary in re.findall(
            r"'(x64|x86|arm64)' \{ @\('([^']+)', '([^']+)', '([^']+)'\) \}", ps)}
        self.assertEqual(actual, expected)
        for relative in ("provider_matrix.rs", "provider_smoke.rs"):
            source = (ROOT / "rclone-triage/tests" / relative).read_text()
            self.assertIn('"x86" => "RCLONE_WINDOWS_X86_EXE_SHA256', source)
            self.assertIn('"aarch64" => "RCLONE_WINDOWS_ARM64_EXE_SHA256', source)


if __name__ == "__main__":
    unittest.main()
