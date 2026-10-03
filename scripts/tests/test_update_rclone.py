"""Offline updater tests: generated archives, no provider/network/process access."""

import hashlib
import importlib.util
import io
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile


SPEC = importlib.util.spec_from_file_location("update_rclone", Path(__file__).parents[1] / "update-rclone.py")
UPDATER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UPDATER)


def archive_bytes(version, platform, payload=None, duplicate=False, symlink=False):
    name = f"rclone-v{version}-{platform}-amd64"
    executable = "rclone.exe" if platform == "windows" else "rclone"
    payload = payload if payload is not None else (b"MZsynthetic" if platform == "windows" else b"\x7fELFsynthetic")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        entry = zipfile.ZipInfo(f"{name}/{executable}")
        if symlink:
            entry.create_system = 3
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(entry, payload)
        if duplicate:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                archive.writestr(entry.filename, payload)
        # This member must never be extracted, even though it is present.
        archive.writestr("../../must-not-extract.txt", b"synthetic traversal")
    return output.getvalue()


class UpdaterTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.manifest = self.root / "rclone-version.env"
        self.original = self.manifest_text("1.0.0")
        self.manifest.write_text(self.original, encoding="utf-8")
        self.urls = []
        self.release = self.make_release("1.0.1")

    @staticmethod
    def manifest_text(version):
        return "\n".join([f"RCLONE_VERSION={version}"] + [f"{key}={'0' * 64}" for key in UPDATER.KEYS[1:-1]]) + "\n"

    @staticmethod
    def make_release(version, **windows_options):
        data = {f"{UPDATER.ORIGIN}/version.txt": f"rclone v{version}\n".encode()}
        checksums = []
        for platform in ("windows", "linux"):
            filename = f"rclone-v{version}-{platform}-amd64.zip"
            payload = archive_bytes(version, platform, **(windows_options if platform == "windows" else {}))
            data[f"{UPDATER.ORIGIN}/v{version}/{filename}"] = payload
            checksums.append(f"{hashlib.sha256(payload).hexdigest()}  {filename}")
        data[f"{UPDATER.ORIGIN}/v{version}/SHA256SUMS"] = ("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA1\n\n" + "\n".join(checksums) + "\n-----BEGIN PGP SIGNATURE-----\nsynthetic armor\n").encode()
        return data

    def fetch(self, url, destination, limit):
        UPDATER.validate_url(url)
        self.urls.append(url)
        payload = self.release[url]
        self.assertLessEqual(len(payload), limit)
        destination.write_bytes(payload)

    def test_dry_run_verifies_both_archives_and_binaries_without_edit(self):
        result = UPDATER.update(self.manifest, fetch=self.fetch)
        self.assertTrue(result["verified"])
        self.assertTrue(result["changed"])
        self.assertFalse(result["written"])
        self.assertEqual(result["pins"]["RCLONE_EXE_SHA256"], hashlib.sha256(b"MZsynthetic").hexdigest())
        self.assertEqual(result["pins"]["RCLONE_LINUX_EXE_SHA256"], hashlib.sha256(b"\x7fELFsynthetic").hexdigest())
        self.assertEqual(self.manifest.read_text(), self.original)
        self.assertFalse((self.root / "must-not-extract.txt").exists())

    def test_write_is_deterministic_and_atomic(self):
        result = UPDATER.update(self.manifest, write=True, fetch=self.fetch)
        self.assertEqual(self.manifest.read_bytes(), UPDATER.render_manifest(result["pins"]).encode())
        self.assertTrue(result["written"])
        self.assertEqual(list(self.root.glob(".rclone-pin-*")), [])
        self.urls.clear()
        same = UPDATER.update(self.manifest, write=True, fetch=self.fetch)
        self.assertFalse(same["changed"])
        self.assertEqual(self.urls, [f"{UPDATER.ORIGIN}/version.txt"])

    def test_refresh_current_only_adds_missing_pin(self):
        verified = UPDATER.update(self.manifest, fetch=self.fetch)["pins"]
        legacy = UPDATER.render_manifest(verified).split("RCLONE_LINUX_EXE_SHA256=")[0]
        self.manifest.write_text(legacy, encoding="utf-8")
        result = UPDATER.update(self.manifest, write=True, refresh_current=True, fetch=self.fetch)
        self.assertTrue(result["changed"])
        self.assertEqual(UPDATER.parse_manifest(self.manifest.read_text()), verified)
        again = UPDATER.update(self.manifest, write=True, refresh_current=True, fetch=self.fetch)
        self.assertTrue(again["verified"])
        self.assertFalse(again["changed"])

    def test_existing_release_pin_mismatch_is_not_replaced(self):
        self.manifest.write_text(self.manifest_text("1.0.1"), encoding="utf-8")
        before = self.manifest.read_bytes()
        with self.assertRaisesRegex(UPDATER.UpdateError, "existing release pin"):
            UPDATER.update(self.manifest, write=True, refresh_current=True, fetch=self.fetch)
        self.assertEqual(self.manifest.read_bytes(), before)

    def test_semver_order_and_no_downgrade(self):
        self.assertGreater(UPDATER.version_tuple("1.10.0"), UPDATER.version_tuple("1.9.99"))
        self.manifest.write_text(self.manifest_text("1.9.0"), encoding="utf-8")
        with self.assertRaisesRegex(UPDATER.UpdateError, "downgrade"):
            UPDATER.update(self.manifest, write=True, fetch=self.fetch)
        self.assertEqual(len(self.urls), 1)

    def test_prerelease_or_injected_version_fails_closed(self):
        for value in ("rclone v1.0.1-beta\n", "rclone v1.0.1\nother", "rclone v01.0.1", "v1.0.1", "rclone v1.0.1/../../x"):
            with self.subTest(value=value):
                self.release[f"{UPDATER.ORIGIN}/version.txt"] = value.encode()
                with self.assertRaises(UPDATER.UpdateError):
                    UPDATER.update(self.manifest, write=True, fetch=self.fetch)
                self.assertEqual(self.manifest.read_text(), self.original)

    def test_untrusted_urls_and_redirects_rejected(self):
        for url in ("http://downloads.rclone.org/version.txt", "https://downloads.rclone.org.evil.test/version.txt", "https://downloads.rclone.org@evil.test/version.txt", "https://downloads.rclone.org:443/version.txt", "https://downloads.rclone.org/version.txt?x=1", "https://downloads.rclone.org/v1.0.1/../evil.zip", "https://downloads.rclone.org/v1.0.1/rclone-v1.0.2-linux-amd64.zip"):
            with self.subTest(url=url), self.assertRaises(UPDATER.UpdateError):
                UPDATER.validate_url(url)
        with self.assertRaises(UPDATER.UpdateError):
            UPDATER.NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://evil.test/")

    def test_download_rejects_truncated_oversized_or_wrong_origin_responses(self):
        url = f"{UPDATER.ORIGIN}/version.txt"
        for length, body, final_url in (("10", b"short", url), ("1", b"too long", url), ("1000", b"x", url), (None, b"x", "https://evil.test/version.txt")):
            with self.subTest(length=length, final_url=final_url):
                response = mock.MagicMock()
                response.__enter__.return_value = response
                response.status = 200
                response.headers = {} if length is None else {"Content-Length": length}
                response.geturl.return_value = final_url
                response.read1.side_effect = [body, b""]
                opener = mock.MagicMock()
                opener.open.return_value = response
                destination = self.root / "download.txt"
                with mock.patch.object(UPDATER.urllib.request, "build_opener", return_value=opener), self.assertRaises(UPDATER.UpdateError):
                    UPDATER.download(url, destination, 128)
                destination.unlink(missing_ok=True)

    def test_slow_stream_checks_deadline_after_one_underlying_read(self):
        url = f"{UPDATER.ORIGIN}/version.txt"
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.headers = {}
        response.geturl.return_value = url
        response.read1.side_effect = [b"r", b"c"]
        opener = mock.MagicMock()
        opener.open.return_value = response
        with mock.patch.object(UPDATER.urllib.request, "build_opener", return_value=opener), mock.patch.object(UPDATER.time, "monotonic", side_effect=[0, 301]):
            with self.assertRaisesRegex(UPDATER.UpdateError, "deadline"):
                UPDATER.download(url, self.root / "slow-download.txt", 128)
        response.read1.assert_called_once_with(1024 * 1024)
        response.read.assert_not_called()

    def test_archive_hash_mismatch_preserves_original(self):
        self.release[f"{UPDATER.ORIGIN}/v1.0.1/rclone-v1.0.1-windows-amd64.zip"] += b"tampered"
        with self.assertRaisesRegex(UPDATER.UpdateError, "archive SHA256"):
            UPDATER.update(self.manifest, write=True, fetch=self.fetch)
        self.assertEqual(self.manifest.read_text(), self.original)

    def test_missing_or_duplicate_checksum_rejected(self):
        name = "rclone-v1.0.1-windows-amd64.zip"
        checksum = "a" * 64 + "  " + name + "\n"
        for text in ("", checksum + checksum):
            with self.subTest(text=text), self.assertRaises(UPDATER.UpdateError):
                UPDATER.parse_checksums(text, [name])

    def test_wrong_duplicate_or_symlink_executable_rejected(self):
        for options in ({"payload": b"not executable"}, {"duplicate": True}, {"symlink": True}):
            self.release = self.make_release("1.0.1", **options)
            with self.subTest(options=options), self.assertRaises(UPDATER.UpdateError):
                UPDATER.update(self.manifest, write=True, fetch=self.fetch)
            self.assertEqual(self.manifest.read_text(), self.original)

    def test_extracted_readback_mismatch_preserves_manifest(self):
        original_hash = UPDATER.sha256_file
        with mock.patch.object(UPDATER, "sha256_file", side_effect=lambda p: "0" * 64 if p.name == "rclone.exe" else original_hash(p)):
            with self.assertRaisesRegex(UPDATER.UpdateError, "read-back"):
                UPDATER.update(self.manifest, write=True, fetch=self.fetch)
        self.assertEqual(self.manifest.read_text(), self.original)

    def test_invalid_manifest_rejected_before_network(self):
        for suffix in ("RCLONE_VERSION=1.2.3\n", "INJECTED=$(command)\n", "no-equals\n"):
            self.manifest.write_text(self.original + suffix, encoding="utf-8")
            with self.subTest(suffix=suffix), self.assertRaises(UPDATER.UpdateError):
                UPDATER.update(self.manifest, write=True, fetch=self.fetch)
        self.assertEqual(self.urls, [])

    def test_concurrent_manifest_edit_is_preserved(self):
        def changed_fetch(url, destination, limit):
            self.fetch(url, destination, limit)
            if url.endswith("linux-amd64.zip"):
                self.manifest.write_text("concurrent edit\n", encoding="utf-8")
        with self.assertRaisesRegex(UPDATER.UpdateError, "changed"):
            UPDATER.update(self.manifest, write=True, fetch=changed_fetch)
        self.assertEqual(self.manifest.read_text(), "concurrent edit\n")


if __name__ == "__main__":
    unittest.main()
