"""Pure, fixed synthetic bytes for future local/archive application fixtures.

No paths are accepted and no files, processes or listeners are created. The
large member is data only; its presence does not demonstrate cancellation.
"""
from io import BytesIO
import hashlib
import zipfile
import zlib


ZIP_TIMESTAMP = (2025, 1, 2, 3, 4, 6)  # DOS timestamps have two-second precision.
DIRECTORIES = ("empty-dir/", "large/", "nested/")
ZIP_ORDER = ("README-synthetic.txt", "empty-dir/", "empty.bin", "large/", "large/cancel.bin",
             "nested/", "nested/binary.bin", "nested/caf\u00e9-\u96ea.txt", "nested/spaced name.txt")
MAX_MEMBER_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_BYTES = 3 * 1024 * 1024
CORRUPT_MEMBER = "nested/binary.bin"
CORRUPT_MEMBER_OFFSET = 128
CORRUPT_ARCHIVE_OFFSET = 2097605
TRUNCATED_TAIL_BYTES = 22  # Remove only the complete end-of-central-directory record.
_FILE_ROWS = (
    ("README-synthetic.txt", 30, "64d5b40a5f4773b14940a6ce1dd57cf87b44ce5940c097088732ffc71be280cf", "4bdad4b7"),
    ("empty.bin", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "00000000"),
    ("large/cancel.bin", 2097152, "91d3beb88a9b2f778a6c44a1c53b63d3c79931845a9aef84b3fb414610bd1938", "f2a904a4"),
    ("nested/binary.bin", 256, "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880", "29058c73"),
    ("nested/caf\u00e9-\u96ea.txt", 27, "90bf78859b2ed84141735dae7df2ed9894593643772ca8a8a1a8d3b58c0af23f", "0fe1e113"),
    ("nested/spaced name.txt", 20, "0c6308d568f8ec30fbf044baac7827edac83a2465a60439ff653e277a5d9619e", "60fd99b6"),
)
_ARCHIVE_ROWS = (
    ("valid", 2098445, "31179825a73f043ba143688bb5c964a6b06e4251ad6da1527019ed4193d38e9f"),
    ("corrupt_member", 2098445, "1bde22fa5fa4daa9184be79bac53650887378908d9a4fc7aff9adf21fa91cd36"),
    ("truncated", 2098423, "aac91bf6b1447894835ca5016a2ce13ae8d04f1c10f6001a22045d4c723a4f50"),
)


def manifest():
    """Return fresh file-only records; explicit ZIP directories are separate."""
    return [dict(path=path, size=size, sha256=sha, crc32=crc) for path, size, sha, crc in _FILE_ROWS]


def archive_manifest():
    return [dict(variant=variant, size=size, sha256=sha) for variant, size, sha in _ARCHIVE_ROWS]


def payloads():
    # The four pre-existing HTTP application payload identities are unchanged.
    files = {"README-synthetic.txt": b"synthetic application fixture\n", "empty.bin": b"",
             "large/cancel.bin": bytes(range(256)) * 8192, "nested/binary.bin": bytes(range(256)),
             "nested/caf\u00e9-\u96ea.txt": "\u00e9 and \u96ea: synthetic only\n".encode("utf-8"),
             "nested/spaced name.txt": b"spaces remain exact\n"}
    actual = [dict(path=path, size=len(body), sha256=hashlib.sha256(body).hexdigest(),
                   crc32=f"{zlib.crc32(body) & 0xffffffff:08x}") for path, body in sorted(files.items())]
    if actual != manifest() or any(len(body) > MAX_MEMBER_BYTES for body in files.values()):
        raise ValueError("filesystem_fixture_changed")
    return files


def archive_bytes(variant="valid"):
    """Return one fixed ZIP variant; never accept a path or arbitrary member.

    Corruption flips bit 7 of byte 128 in binary.bin, retaining its old CRC and
    every other byte. Truncation preserves all local entries and the central
    directory, but removes the EOCD; it is not a truncated member payload.
    """
    if type(variant) is not str or variant not in {row[0] for row in _ARCHIVE_ROWS}:
        raise ValueError("filesystem_fixture_variant")
    files = payloads()
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        for name in ZIP_ORDER:
            info = zipfile.ZipInfo(name, date_time=ZIP_TIMESTAMP)
            info.create_system, info.create_version, info.extract_version = 3, 20, 20
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = ((0o40700 << 16) | 0x10) if name in DIRECTORIES else (0o100600 << 16)
            archive.writestr(info, b"" if name in DIRECTORIES else files[name])
    valid = stream.getvalue()
    if (len(valid), hashlib.sha256(valid).hexdigest()) != _ARCHIVE_ROWS[0][1:]:
        raise ValueError("filesystem_fixture_changed")
    if variant == "corrupt_member":
        changed = bytearray(valid)
        changed[CORRUPT_ARCHIVE_OFFSET] ^= 0x80
        body = bytes(changed)
    elif variant == "truncated":
        body = valid[:-TRUNCATED_TAIL_BYTES]
    else:
        body = valid
    expected = next(row[1:] for row in _ARCHIVE_ROWS if row[0] == variant)
    if len(body) > MAX_ARCHIVE_BYTES or (len(body), hashlib.sha256(body).hexdigest()) != expected:
        raise ValueError("filesystem_fixture_changed")
    return body
