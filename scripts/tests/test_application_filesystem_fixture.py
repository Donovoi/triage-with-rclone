"""Pure byte tests with an independent ZIP encoder; no extraction or native work."""
import builtins
import hashlib
import importlib.util
import io
from pathlib import Path
import struct
import unittest
from unittest import mock
import zipfile
import zlib


PATH = Path(__file__).resolve().parents[1] / "application-lab" / "fixture_filesystem.py"
SPEC = importlib.util.spec_from_file_location("application_filesystem_fixture", PATH)
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
FILES = {
    "README-synthetic.txt": b"synthetic application fixture\n",
    "empty.bin": b"",
    "large/cancel.bin": bytes(range(256)) * 8192,
    "nested/binary.bin": bytes(range(256)),
    "nested/caf\u00e9-\u96ea.txt": b"\xc3\xa9 and \xe9\x9b\xaa: synthetic only\n",
    "nested/spaced name.txt": b"spaces remain exact\n",
}
ROWS = (
    ("README-synthetic.txt", 30, "64d5b40a5f4773b14940a6ce1dd57cf87b44ce5940c097088732ffc71be280cf", "4bdad4b7"),
    ("empty.bin", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "00000000"),
    ("large/cancel.bin", 2097152, "91d3beb88a9b2f778a6c44a1c53b63d3c79931845a9aef84b3fb414610bd1938", "f2a904a4"),
    ("nested/binary.bin", 256, "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880", "29058c73"),
    ("nested/caf\u00e9-\u96ea.txt", 27, "90bf78859b2ed84141735dae7df2ed9894593643772ca8a8a1a8d3b58c0af23f", "0fe1e113"),
    ("nested/spaced name.txt", 20, "0c6308d568f8ec30fbf044baac7827edac83a2465a60439ff653e277a5d9619e", "60fd99b6"),
)
ORDER = ("README-synthetic.txt", "empty-dir/", "empty.bin", "large/", "large/cancel.bin",
         "nested/", "nested/binary.bin", "nested/caf\u00e9-\u96ea.txt", "nested/spaced name.txt")
ARCHIVES = {
    "valid": (2098445, "31179825a73f043ba143688bb5c964a6b06e4251ad6da1527019ed4193d38e9f"),
    "corrupt_member": (2098445, "1bde22fa5fa4daa9184be79bac53650887378908d9a4fc7aff9adf21fa91cd36"),
    "truncated": (2098423, "aac91bf6b1447894835ca5016a2ce13ae8d04f1c10f6001a22045d4c723a4f50"),
}


def independent_zip():
    """Serialize fixed ZIP records directly; never call the fixture or ZipFile."""
    local, central, spans = bytearray(), bytearray(), {}
    dos_time, dos_date = (3 << 11) | (4 << 5) | 3, (45 << 9) | (1 << 5) | 2
    for name in ORDER:
        body = FILES.get(name, b"")
        encoded = name.encode("utf-8")
        flags = 0 if name.isascii() else 0x800
        crc, offset = zlib.crc32(body) & 0xffffffff, len(local)
        local += struct.pack("<I5H3I2H", 0x04034b50, 20, flags, 0, dos_time, dos_date,
                             crc, len(body), len(body), len(encoded), 0) + encoded
        spans[name] = (len(local), len(body))
        local += body
        attributes = ((0o40700 << 16) | 0x10) if name.endswith("/") else (0o100600 << 16)
        central += struct.pack("<I6H3I5H2I", 0x02014b50, 0x314, 20, flags, 0, dos_time, dos_date,
                               crc, len(body), len(body), len(encoded), 0, 0, 0, 0, attributes, offset) + encoded
    ending = struct.pack("<I4H2IH", 0x06054b50, 0, 0, 9, 9, len(central), len(local), 0)
    return bytes(local + central + ending), spans


class FilesystemFixtureTests(unittest.TestCase):
    def test_exact_payload_bytes_and_independent_literal_hashes(self):
        self.assertEqual(F.payloads(), FILES)
        expected = []
        for path, size, sha, crc in ROWS:
            body = FILES[path]
            self.assertEqual((len(body), hashlib.sha256(body).hexdigest(), f"{zlib.crc32(body) & 0xffffffff:08x}"),
                             (size, sha, crc))
            expected.append(dict(path=path, size=size, sha256=sha, crc32=crc))
        self.assertEqual(F.manifest(), expected)
        self.assertEqual(set(F.manifest()[0]), {"path", "size", "sha256", "crc32"})

    def test_archive_matches_independent_serialized_records_and_pinned_digest(self):
        expected, _ = independent_zip()
        actual = F.archive_bytes()
        self.assertEqual(actual, expected)
        self.assertEqual((len(expected), hashlib.sha256(expected).hexdigest()), ARCHIVES["valid"])
        self.assertEqual(F.archive_bytes(), actual)

    def test_closed_zip_structure_fixed_order_metadata_and_no_optional_records(self):
        raw = F.archive_bytes()
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            self.assertEqual(archive.namelist(), list(ORDER))
            self.assertEqual(len(archive.infolist()), 9)
            self.assertEqual(archive.comment, b"")
            self.assertIsNone(archive.testzip())
            for info in archive.infolist():
                with self.subTest(member=info.filename):
                    body = FILES.get(info.filename, b"")
                    self.assertEqual(info.date_time, (2025, 1, 2, 3, 4, 6))
                    self.assertEqual((info.create_system, info.create_version, info.extract_version), (3, 20, 20))
                    self.assertEqual(info.compress_type, zipfile.ZIP_STORED)
                    self.assertEqual(info.flag_bits, 0 if info.filename.isascii() else 0x800)
                    self.assertEqual((info.extra, info.comment, info.internal_attr), (b"", b"", 0))
                    self.assertEqual((info.file_size, info.compress_size, info.CRC),
                                     (len(body), len(body), zlib.crc32(body) & 0xffffffff))
                    expected_attrs = ((0o40700 << 16) | 0x10) if info.is_dir() else (0o100600 << 16)
                    self.assertEqual(info.external_attr, expected_attrs)
                    self.assertEqual(archive.read(info), body)
        self.assertEqual(raw[-22:-18], b"PK\x05\x06")
        self.assertEqual(struct.unpack("<I4H2IH", raw[-22:])[1:5], (0, 0, 9, 9))

    def test_explicit_empty_directory_and_empty_file_remain_distinct(self):
        with zipfile.ZipFile(io.BytesIO(F.archive_bytes())) as archive:
            directories = [info.filename for info in archive.infolist() if info.is_dir()]
            self.assertEqual(directories, ["empty-dir/", "large/", "nested/"])
            self.assertEqual(F.DIRECTORIES, tuple(directories))
            self.assertFalse(archive.getinfo("empty.bin").is_dir())
            self.assertEqual(archive.read("empty.bin"), b"")
            self.assertEqual(archive.read("empty-dir/"), b"")
            self.assertFalse(any(name.startswith("empty-dir/") and name != "empty-dir/" for name in archive.namelist()))

    def test_unicode_and_space_names_are_literal_utf8_not_path_transformations(self):
        raw = F.archive_bytes()
        self.assertEqual(raw.count(b"nested/caf\xc3\xa9-\xe9\x9b\xaa.txt"), 2)
        self.assertEqual(raw.count(b"nested/spaced name.txt"), 2)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            self.assertEqual(archive.read("nested/caf\u00e9-\u96ea.txt"), b"\xc3\xa9 and \xe9\x9b\xaa: synthetic only\n")
            for alias in ("nested/cafe\u0301-\u96ea.txt", "nested/spaced%20name.txt", "/nested/binary.bin"):
                with self.assertRaises(KeyError): archive.getinfo(alias)

    def test_corruption_is_one_known_body_byte_and_preserves_all_other_bytes(self):
        valid, spans = independent_zip()
        corrupt = F.archive_bytes("corrupt_member")
        start, size = spans["nested/binary.bin"]
        self.assertEqual(start + 128, 2097605)
        self.assertEqual(len(corrupt), len(valid))
        self.assertEqual(corrupt[:start+128], valid[:start+128])
        self.assertEqual((valid[start+128], corrupt[start+128]), (128, 0))
        self.assertEqual(corrupt[start+129:], valid[start+129:])
        self.assertEqual(hashlib.sha256(corrupt[start:start+size]).hexdigest(),
                         "6ef9398b60ea7f0b79047499a4191f7a4add5f95ec7fdf4a02be6ccaaf10deac")
        for name, (offset, length) in spans.items():
            if name != "nested/binary.bin":
                self.assertEqual(corrupt[offset:offset+length], valid[offset:offset+length])

    def test_corrupted_member_crc_fails_while_unaffected_members_still_read_exactly(self):
        with zipfile.ZipFile(io.BytesIO(F.archive_bytes("corrupt_member"))) as archive:
            self.assertEqual(archive.testzip(), "nested/binary.bin")
            self.assertEqual(archive.getinfo("nested/binary.bin").CRC, 0x29058c73)
            with self.assertRaisesRegex(zipfile.BadZipFile, "CRC"):
                archive.read("nested/binary.bin")
            for name in ORDER:
                if name != "nested/binary.bin": self.assertEqual(archive.read(name), FILES.get(name, b""))

    def test_truncation_removes_only_eocd_and_preserves_every_member_body(self):
        valid, spans = independent_zip()
        truncated = F.archive_bytes("truncated")
        self.assertEqual(truncated, valid[:-22])
        self.assertEqual(truncated + valid[-22:], valid)
        for name, (offset, size) in spans.items():
            self.assertEqual(truncated[offset:offset+size], FILES.get(name, b""))
        self.assertFalse(zipfile.is_zipfile(io.BytesIO(truncated)))
        with self.assertRaises(zipfile.BadZipFile): zipfile.ZipFile(io.BytesIO(truncated))

    def test_each_variant_has_an_independently_pinned_size_and_digest(self):
        self.assertEqual(F.archive_manifest(), [dict(variant=name, size=size, sha256=sha)
            for name, (size, sha) in ARCHIVES.items()])
        for name, expected in ARCHIVES.items():
            body = F.archive_bytes(name)
            self.assertEqual((len(body), hashlib.sha256(body).hexdigest()), expected)
            self.assertLess(len(body), 3 * 1024 * 1024)
        self.assertEqual(max(map(len, F.payloads().values())), 2 * 1024 * 1024)

    def test_callers_cannot_mutate_future_payloads_or_manifests(self):
        value = F.payloads(); value["README-synthetic.txt"] = b"changed"; value.clear()
        rows = F.manifest(); rows[0]["path"] = "../escape"; rows.clear()
        archives = F.archive_manifest(); archives[0]["sha256"] = "changed"; archives.clear()
        self.assertEqual(F.payloads(), FILES)
        self.assertEqual(F.manifest()[0]["path"], "README-synthetic.txt")
        self.assertEqual(hashlib.sha256(F.archive_bytes()).hexdigest(), ARCHIVES["valid"][1])

    def test_unknown_or_path_like_inputs_have_one_finite_error(self):
        class Text(str):
            pass
        for value in (None, True, 0, b"valid", [], {}, Text("valid"), "", "../private-name", Path("private-name")):
            with self.subTest(kind=type(value).__name__), self.assertRaisesRegex(ValueError, "^filesystem_fixture_variant$"):
                F.archive_bytes(value)

    def test_building_all_variants_does_not_open_files(self):
        with mock.patch.object(builtins, "open", side_effect=AssertionError("filesystem open prohibited")), \
             mock.patch.object(io, "open", side_effect=AssertionError("filesystem open prohibited")):
            self.assertEqual(F.payloads(), FILES)
            for variant in ARCHIVES:
                self.assertEqual(len(F.archive_bytes(variant)), ARCHIVES[variant][0])


if __name__ == "__main__":
    unittest.main()
