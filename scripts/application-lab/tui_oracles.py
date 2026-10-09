"""Pure artifact checks for the bounded manual-HTTP Windows TUI experiment.

These checks neither start the application nor establish UI/process/HTTP/ACL
acceptance. Call only after the producer has stopped or quiesced owned writers.
The producer must independently bind the case, visible state, endpoint requests,
runtime, cancellation activity and cleanup. HTTP supplies no expected hash:
successful results must say Unavailable, with an independently checked SHA-256.
Logs/reports are checked for bounded presence only, not semantic correctness.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from datetime import datetime
import functools
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from types import MappingProxyType
import xml.etree.ElementTree as ET
import zipfile


# Independent, literal expected hashes; never derive expectations from downloads.
MEMBERS = MappingProxyType({
    "README-synthetic.txt": (30, "64d5b40a5f4773b14940a6ce1dd57cf87b44ce5940c097088732ffc71be280cf"),
    "large/cancel.bin": (2097152, "91d3beb88a9b2f778a6c44a1c53b63d3c79931845a9aef84b3fb414610bd1938"),
    "nested/binary.bin": (256, "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880"),
    "nested/spaced name.txt": (20, "0c6308d568f8ec30fbf044baac7827edac83a2465a60439ff653e277a5d9619e"),
})
MODIFIED = "2025-01-02T03:04:05+00:00"
DIR_MODIFIED = "2000-01-01T00:00:00+00:00"
CSV_HEADERS = ["path_encoding", "remote", "path", "size", "modified", "is_dir", "hash", "hash_type"]
XLSX_HEADERS = ["Remote", "Path", "Size", "Modified", "IsDir", "Hash", "HashType"]
UNAVAILABLE = "Source did not supply a hash; local SHA-256 recorded"
ERRORS = frozenset({"artifact_invalid", "path_invalid", "config_invalid", "config_changed",
                    "listing_invalid", "manifest_invalid", "outputs_invalid", "history_invalid"})
MAX_FILE = 16 * 1024 * 1024
XML_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
DOC_REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
CONTENT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"


class OracleError(ValueError):
    """A finite, content-free error safe for a private producer diagnostic."""

    def __init__(self, code):
        super().__init__(code if code in ERRORS else "artifact_invalid")


def need(condition, code):
    if not condition:
        raise OracleError(code)


def _public(function):
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except OracleError:
            raise
        except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError,
                csv.Error, ET.ParseError, zipfile.BadZipFile):
            raise OracleError("artifact_invalid") from None
    return wrapped


def _sha(data):
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class ConfigSnapshot:
    case_root: str = field(repr=False)
    remotes: tuple[tuple[str, str], ...] = field(repr=False)
    data: bytes = field(repr=False)

    @property
    def sha256(self):
        return _sha(self.data)


@dataclass(frozen=True)
class AcquisitionSnapshot:
    case_root: str = field(repr=False)
    manifest: bytes = field(repr=False)
    # Cumulative accepted files, relative to downloads; never inferred from disk.
    outputs: tuple[tuple[str, int, str], ...] = field(repr=False)
    selected_count: int
    cancelled: bool

    @property
    def manifest_sha256(self):
        return _sha(self.manifest)


def _plain(info, directory):
    need(not (getattr(info, "st_file_attributes", 0) & 0x400), "path_invalid")
    need((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)), "path_invalid")
    if not directory:
        need(info.st_nlink == 1, "path_invalid")


def _root(value):
    path = Path(value)
    need(path.is_absolute() and ".." not in path.parts, "path_invalid")
    _plain(path.lstat(), True)
    # Reject aliases through ancestors; do not require system ancestors private.
    need(os.path.normcase(str(path.resolve(strict=True))) == os.path.normcase(str(path)), "path_invalid")
    return path


def _relative(value):
    need(type(value) is str and 0 < len(value) <= 240, "path_invalid")
    need(not any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value), "path_invalid")
    need(not any(c in value for c in "\\:*?<>|\""), "path_invalid")
    parts = value.split("/")
    need(all(p and p not in (".", "..") and not p.endswith((" ", ".")) for p in parts), "path_invalid")
    need(all(not re.fullmatch(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", p, re.I) for p in parts), "path_invalid")
    return value


def _inventory(root):
    _plain(root.lstat(), True)
    found, folded, total = {}, set(), 0

    def visit(path, prefix, depth):
        nonlocal total
        need(depth <= 8, "path_invalid")
        with os.scandir(path) as entries:
            for entry in entries:
                name = _relative(prefix + entry.name)
                need(name.casefold() not in folded and len(found) < 128, "path_invalid")
                folded.add(name.casefold())
                # Path.lstat gives the actual hardlink count on Windows.
                info = Path(entry.path).lstat()
                directory = stat.S_ISDIR(info.st_mode)
                _plain(info, directory)
                found[name] = directory
                if directory:
                    visit(Path(entry.path), name + "/", depth + 1)
                else:
                    need(0 <= info.st_size <= MAX_FILE, "artifact_invalid")
                    total += info.st_size
                    need(total <= 32 * 1024 * 1024, "artifact_invalid")
    visit(root, "", 0)
    return found


def _read(root, relative, maximum):
    relative = _relative(relative)
    path = root
    for component in relative.split("/")[:-1]:
        path /= component
        _plain(path.lstat(), True)
    path /= relative.split("/")[-1]
    before = path.lstat()
    _plain(before, False)
    need(before.st_size <= maximum, "artifact_invalid")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as source:
        opened = os.fstat(source.fileno())
        _plain(opened, False)
        need((before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino), "path_invalid")
        data = source.read(maximum + 1)
        after = os.fstat(source.fileno())
    final = path.lstat()
    _plain(final, False)
    need(len(data) <= maximum and len(data) == before.st_size == after.st_size == final.st_size and
         (before.st_dev, before.st_ino, before.st_mtime_ns) ==
         (final.st_dev, final.st_ino, final.st_mtime_ns), "artifact_invalid")
    return data


def _remote(value):
    need(type(value) is str and re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{1,47}", value), "config_invalid")
    return value


def _endpoint(value):
    need(type(value) is str and re.fullmatch(r"http://127\.0\.0\.1:[1-9][0-9]{0,4}/", value), "config_invalid")
    need(1 <= int(value.rsplit(":", 1)[1][:-1]) <= 65535, "config_invalid")
    return value


def _config_bytes(data, remotes):
    # Only the exact nonsecret HTTP keys written by the selected manual flow.
    text = data.decode("utf-8")
    need(text.startswith("# rclone-triage config\n") and "\r" not in text and text.endswith("\n"), "config_invalid")
    sections, current = {}, None
    for line in text.splitlines()[1:]:
        if line == "":
            continue
        if line.startswith("[") and line.endswith("]"):
            current = _remote(line[1:-1])
            need(current not in sections, "config_invalid")
            sections[current] = {}
            continue
        need(current is not None and " = " in line, "config_invalid")
        key, value = line.split(" = ", 1)
        need(key in ("type", "url") and key not in sections[current], "config_invalid")
        sections[current][key] = value
    need(sections == {name: {"type": "http", "url": endpoint} for name, endpoint in remotes}, "config_invalid")


@_public
def validate_manual_config(case_root, expected_remotes, previous=None):
    """Validate exact manual sections; optional reset/add must preserve old bytes."""
    root = _root(case_root)
    need(type(expected_remotes) is dict and 1 <= len(expected_remotes) <= 4, "config_invalid")
    remotes = tuple(sorted((_remote(k), _endpoint(v)) for k, v in expected_remotes.items()))
    need(len({k.casefold() for k, _ in remotes}) == len(remotes), "config_invalid")
    need(len({v for _, v in remotes}) == len(remotes), "config_invalid")
    need(_inventory(root / "config") == {"rclone.conf": False}, "config_invalid")
    data = _read(root, "config/rclone.conf", 8192)
    _config_bytes(data, remotes)
    if previous is not None:
        need(type(previous) is ConfigSnapshot and previous.case_root == str(root), "config_changed")
        need(set(previous.remotes) <= set(remotes) and data.startswith(previous.data), "config_changed")
        if previous.remotes == remotes:
            need(data == previous.data, "config_changed")
    return ConfigSnapshot(str(root), remotes, data)


def _config_preserved(root, config, remote):
    need(type(config) is ConfigSnapshot and config.case_root == str(root), "config_changed")
    need(_remote(remote) in dict(config.remotes), "config_invalid")
    current = validate_manual_config(root, dict(config.remotes))
    need(current.data == config.data, "config_changed")


def _members(values):
    need(type(values) in (tuple, list) and 0 < len(values) <= len(MEMBERS), "artifact_invalid")
    need(all(type(v) is str and v in MEMBERS for v in values) and len(set(values)) == len(values), "artifact_invalid")
    return tuple(sorted(values))


def _parents(paths):
    parents = set()
    for path in paths:
        current = PurePosixPath(path).parent
        while str(current) != ".":
            parents.add(str(current))
            current = current.parent
    return parents


def _listing_rows(members):
    rows = [["", p, str(MEMBERS[p][0]), MODIFIED, False, "", ""] for p in members]
    rows += [["", p, "", DIR_MODIFIED, True, "", ""] for p in sorted(_parents(members))]
    return rows


def _xml(data):
    need(len(data) <= 512 * 1024 and b"<!" not in data, "listing_invalid")
    return ET.fromstring(data)


def _xlsx_relationships(tree, expected):
    need(tree.tag == "{" + REL_NS + "}Relationships" and not tree.attrib and
         len(tree) == len(expected), "listing_invalid")
    observed = {}
    for node in tree:
        need(node.tag == "{" + REL_NS + "}Relationship" and not len(node) and
             set(node.attrib) == {"Id", "Type", "Target"} and
             node.get("Id") not in observed, "listing_invalid")
        observed[node.get("Id")] = (node.get("Type"), node.get("Target"))
    need(observed == expected, "listing_invalid")


def _xlsx_content_types(tree):
    need(tree.tag == "{" + CONTENT_NS + "}Types" and not tree.attrib, "listing_invalid")
    defaults, overrides = {}, {}
    for node in tree:
        need(not len(node), "listing_invalid")
        if node.tag == "{" + CONTENT_NS + "}Default":
            need(set(node.attrib) == {"Extension", "ContentType"} and
                 node.get("Extension") not in defaults, "listing_invalid")
            defaults[node.get("Extension")] = node.get("ContentType")
        else:
            need(node.tag == "{" + CONTENT_NS + "}Override" and
                 set(node.attrib) == {"PartName", "ContentType"} and
                 node.get("PartName") not in overrides, "listing_invalid")
            overrides[node.get("PartName")] = node.get("ContentType")
    prefix = "application/vnd.openxmlformats-"
    need(defaults == {"rels": prefix + "package.relationships+xml", "xml": "application/xml"} and
         overrides == {"/docProps/app.xml": prefix + "officedocument.extended-properties+xml",
                       "/docProps/core.xml": prefix + "package.core-properties+xml",
                       "/xl/styles.xml": prefix + "officedocument.spreadsheetml.styles+xml",
                       "/xl/theme/theme1.xml": prefix + "officedocument.theme+xml",
                       "/xl/workbook.xml": prefix + "officedocument.spreadsheetml.sheet.main+xml",
                       "/xl/worksheets/sheet1.xml": prefix + "officedocument.spreadsheetml.worksheet+xml",
                       "/xl/sharedStrings.xml": prefix + "officedocument.spreadsheetml.sharedStrings+xml"},
         "listing_invalid")


def _xlsx_rows(data):
    allowed = {"[Content_Types].xml", "_rels/.rels", "docProps/app.xml", "docProps/core.xml",
               "xl/workbook.xml", "xl/_rels/workbook.xml.rels", "xl/styles.xml", "xl/theme/theme1.xml",
               "xl/worksheets/sheet1.xml", "xl/sharedStrings.xml"}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        names = [item.filename for item in entries]
        need(len(names) == len(set(names)) and set(names) == allowed, "listing_invalid")
        need(sum(i.file_size for i in entries) <= 2 * 1024 * 1024 and
             all(i.file_size <= 512 * 1024 and not (i.flag_bits & 1) and
                 i.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) for i in entries), "listing_invalid")
        trees = {name: _xml(archive.read(name)) for name in names}
    # The app uses one ordinary rust_xlsxwriter 0.69.0 sheet, without images,
    # macros or custom properties. Bind the named sheet to the inspected XML;
    # rows in an unreferenced part are not a completed workbook inventory.
    _xlsx_content_types(trees["[Content_Types].xml"])
    _xlsx_relationships(trees["_rels/.rels"], {
        "rId1": (DOC_REL_NS + "/officeDocument", "xl/workbook.xml"),
        "rId2": (REL_NS + "/metadata/core-properties", "docProps/core.xml"),
        "rId3": (DOC_REL_NS + "/extended-properties", "docProps/app.xml"),
    })
    _xlsx_relationships(trees["xl/_rels/workbook.xml.rels"], {
        "rId1": (DOC_REL_NS + "/worksheet", "worksheets/sheet1.xml"),
        "rId2": (DOC_REL_NS + "/theme", "theme/theme1.xml"),
        "rId3": (DOC_REL_NS + "/styles", "styles.xml"),
        "rId4": (DOC_REL_NS + "/sharedStrings", "sharedStrings.xml"),
    })
    book = trees["xl/workbook.xml"]
    sheets = book.findall(XML_NS + "sheets")
    need(book.tag == XML_NS + "workbook" and len(sheets) == 1 and len(sheets[0]) == 1 and
         sheets[0][0].tag == XML_NS + "sheet" and
         sheets[0][0].attrib == {"name": "Listing", "sheetId": "1", "{" + DOC_REL_NS + "}id": "rId1"},
         "listing_invalid")
    strings = []
    need(trees["xl/sharedStrings.xml"].tag == XML_NS + "sst", "listing_invalid")
    for item in trees["xl/sharedStrings.xml"]:
        need(item.tag == XML_NS + "si" and len(item) == 1 and item[0].tag == XML_NS + "t", "listing_invalid")
        value = item[0].text or ""
        need(len(value) <= 512 and len(strings) < 256, "listing_invalid")
        strings.append(value)
    sheet = trees["xl/worksheets/sheet1.xml"]
    need(sheet.tag == XML_NS + "worksheet" and not list(sheet.iter(XML_NS + "f")), "listing_invalid")
    sheet_tables = sheet.findall(XML_NS + "sheetData")
    need(len(sheet_tables) == 1 and 1 <= len(sheet_tables[0]) <= 16, "listing_invalid")
    sheet_data = sheet_tables[0]
    result = []
    for index, row in enumerate(sheet_data, 1):
        need(row.tag == XML_NS + "row" and row.get("r") == str(index), "listing_invalid")
        cells, seen = [""] * 7, set()
        for cell in row:
            address = cell.get("r", "")
            need(re.fullmatch(r"[A-G]" + str(index), address) and address not in seen and
                 cell.tag == XML_NS + "c" and len(cell) == 1 and cell[0].tag == XML_NS + "v", "listing_invalid")
            seen.add(address)
            raw = cell[0].text or ""
            if cell.get("t") == "s":
                need(re.fullmatch(r"0|[1-9][0-9]{0,2}", raw) and int(raw) < len(strings), "listing_invalid")
                value = strings[int(raw)]
            else:
                need(cell.get("t") == "b" and raw in ("0", "1"), "listing_invalid")
                value = raw == "1"
            cells[ord(address[0]) - ord("A")] = value
        result.append(cells)
    return result


@_public
def validate_listing(case_root, config, expected_remote, members=tuple(MEMBERS)):
    """Exact CSV/XLSX inventory. Remote attribution additionally needs UI/HTTP proof."""
    root = _root(case_root)
    _config_preserved(root, config, expected_remote)
    members = _members(members)
    need(_inventory(root / "listings") == {"http_files.csv": False, "http_files.xlsx": False}, "listing_invalid")
    data = _read(root, "listings/http_files.csv", 65536)
    need(data.startswith(b"\xef\xbb\xbf"), "listing_invalid")
    rows = list(csv.reader(io.StringIO(data.decode("utf-8-sig"), newline=""), strict=True))
    expected = _listing_rows(members)
    csv_expected = [["excel-safe-v1"] + row[:4] + [str(row[4]).lower()] + row[5:] for row in expected]
    need(rows and rows[0] == CSV_HEADERS and sorted(rows[1:]) == sorted(csv_expected), "listing_invalid")
    workbook = _read(root, "listings/http_files.xlsx", 2 * 1024 * 1024)
    xlsx = _xlsx_rows(workbook)
    need(xlsx[0] == XLSX_HEADERS and sorted(xlsx[1:], key=lambda row: row[1]) ==
         sorted(expected, key=lambda row: row[1]), "listing_invalid")
    return {"files": len(members), "directories": len(_parents(members)),
            "csv_sha256": _sha(data), "xlsx_sha256": _sha(workbook)}


def _json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "manifest_invalid")
            result[key] = value
        return result
    return json.loads(data.decode("utf-8"), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(OracleError("manifest_invalid")))


def _keys(value, keys):
    need(type(value) is dict and set(value) == set(keys.split()), "manifest_invalid")


def _time(value):
    need(type(value) is str and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|\+00:00)", value), "manifest_invalid")
    datetime.fromisoformat(value.replace("Z", "+00:00"))


def _path_matches(value, path):
    need(type(value) is str and "\x00" not in value and not any(ord(c) < 32 for c in value), "manifest_invalid")
    candidate = value.removeprefix("\\\\?\\")
    need(not {".", ".."}.intersection(candidate.replace("\\", "/").split("/")), "manifest_invalid")
    need(os.path.isabs(candidate) and os.path.normcase(os.path.abspath(candidate)) ==
         os.path.normcase(str(path)), "manifest_invalid")


def _case_layout(root, history):
    entries = _inventory(root)
    fixed = {"logs": True, "downloads": True, "listings": True, "config": True,
             "logs/rclone-triage.log": False, "config/rclone.conf": False,
             "listings/http_files.csv": False, "listings/http_files.xlsx": False,
             "acquisition-manifest.json": False, "forensic_report.txt": False,
             "forensic_report.xlsx": False, "log-checkpoint.json": False}
    outside_downloads = {k: v for k, v in entries.items() if not k.startswith("downloads/")}
    archives = {k: v for k, v in outside_downloads.items() if re.fullmatch(r"acquisition-prior-[A-Za-z0-9_-]{1,64}\.json", k)}
    need(all(not kind for kind in archives.values()), "history_invalid")
    need({k: v for k, v in outside_downloads.items() if k not in archives} == fixed, "outputs_invalid")
    need(sorted(_read(root, name, 65536) for name in archives) == sorted(history), "history_invalid")
    for path in ("logs/rclone-triage.log", "forensic_report.txt", "forensic_report.xlsx", "log-checkpoint.json"):
        need(bool(_read(root, path, MAX_FILE)), "outputs_invalid")


@_public
def validate_acquisition(case_root, config, expected_remote, selected_members, runtime_version,
                         *, outcome="success", prior=()):
    """Validate a selected success or one active-cancel artifact, including history.

    Cancellation activity/intent must separately be observed by the live producer.
    Prior snapshots bind preserved downloads and one exact archived manifest each.
    This returns evidence for subsequent checks, not an acceptance receipt.
    """
    root = _root(case_root)
    _config_preserved(root, config, expected_remote)
    members = _members(selected_members)
    need(type(runtime_version) is str and re.fullmatch(r"[1-9][0-9]*\.\d+\.\d+", runtime_version), "manifest_invalid")
    need(outcome in ("success", "cancelled") and (outcome != "cancelled" or members == ("large/cancel.bin",)), "manifest_invalid")
    need(type(prior) in (tuple, list) and len(prior) <= 4, "history_invalid")
    outputs, history = {}, []
    for snapshot in prior:
        need(type(snapshot) is AcquisitionSnapshot and snapshot.case_root == str(root), "history_invalid")
        history.append(snapshot.manifest)
        for name, size, digest in snapshot.outputs:
            need(name not in outputs or outputs[name] == (size, digest), "history_invalid")
            outputs[name] = (size, digest)
    data = _read(root, "acquisition-manifest.json", 65536)
    document = _json(data)
    _keys(document, "schema_version written_at rclone_version config_path plan results complete")
    need(type(document["schema_version"]) is int and document["schema_version"] == 1 and
         document["rclone_version"] == runtime_version and type(document["complete"]) is bool and
         document["complete"] == (outcome == "success"), "manifest_invalid")
    _time(document["written_at"])
    _path_matches(document["config_path"], root / "config/rclone.conf")
    plan = document["plan"]
    _keys(plan, "files skipped_directories")
    need(type(plan["skipped_directories"]) is int and plan["skipped_directories"] == 0 and
         type(plan["files"]) is list and len(plan["files"]) == len(members) and
         type(document["results"]) is list and len(document["results"]) == len(members), "manifest_invalid")
    expected_results = {}
    for member, item in zip(members, plan["files"]):
        _keys(item, "remote_name path request")
        need(item["remote_name"] == expected_remote and item["path"] == member, "manifest_invalid")
        request = item["request"]
        _keys(request, "source destination mode expected_hash expected_hash_type expected_size")
        source = expected_remote + ":" + member
        destination = root / "downloads" / expected_remote / member
        size, digest = MEMBERS[member]
        need(request["source"] == source and request["mode"] == "CopyTo" and
             request["expected_hash"] is None and request["expected_hash_type"] is None and
             type(request["expected_size"]) is int and request["expected_size"] == size, "manifest_invalid")
        _path_matches(request["destination"], destination)
        expected_results[source] = (member, destination, size, digest)
    seen = set()
    for result in document["results"]:
        _keys(result, "local_sha256 integrity source destination success error size hash hash_type hash_verified hash_error")
        source = result["source"]
        need(type(source) is str and source in expected_results and source not in seen, "manifest_invalid")
        seen.add(source)
        member, destination, size, digest = expected_results[source]
        _path_matches(result["destination"], destination)
        relative = expected_remote + "/" + member
        need(relative not in outputs, "history_invalid")
        need(result["hash"] is None and result["hash_type"] is None and result["hash_verified"] is None, "manifest_invalid")
        if outcome == "success":
            need(result["success"] is True and result["integrity"] == "Unavailable" and result["error"] is None and
                 type(result["size"]) is int and result["size"] == size and result["local_sha256"] == digest and
                 result["hash_error"] == UNAVAILABLE, "manifest_invalid")
            outputs[relative] = (size, digest)
        else:
            need(result["success"] is False and result["integrity"] == "Cancelled" and
                 all(result[key] is None for key in ("local_sha256", "size", "hash_error")) and
                 type(result["error"]) is str and 0 < len(result["error"]) <= 4096, "manifest_invalid")
            # download.rs preserves Cancelled when staging.close() fails, but
            # appends this fixed failure marker. Absence of residue must not
            # override that explicit failure. Ordinary cancellation can contain
            # collected child stderr, so it is not one deterministic literal.
            need(not result["error"].startswith("Transfer staging cleanup failed:") and
                 "; transfer staging cleanup failed:" not in result["error"], "manifest_invalid")
    expected_dirs = _parents(list(outputs) + [expected_remote + "/" + member for member in members])
    need(_inventory(root / "downloads") == ({p: False for p in outputs} | {p: True for p in expected_dirs}), "outputs_invalid")
    for relative, (size, digest) in outputs.items():
        payload = _read(root / "downloads", relative, size)
        need(len(payload) == size and _sha(payload) == digest, "outputs_invalid")
    _case_layout(root, history)
    return AcquisitionSnapshot(str(root), data, tuple((p, *outputs[p]) for p in sorted(outputs)), len(members), outcome == "cancelled")
