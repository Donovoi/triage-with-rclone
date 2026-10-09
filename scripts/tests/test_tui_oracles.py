"""Synthetic artifact tests only; no application, native runtime or HTTP server."""

import copy
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET
import zipfile


SOURCE = Path(__file__).resolve().parents[1] / "application-lab/tui_oracles.py"
SPEC = importlib.util.spec_from_file_location("tui_artifact_oracles_tested", SOURCE)
O = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = O
with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("no processes")), \
        mock.patch.object(socket, "socket", side_effect=AssertionError("no sockets")):
    SPEC.loader.exec_module(O)

# Independent fixture definitions. No expected rows/hashes are built by the oracle.
PAYLOADS = {
    "README-synthetic.txt": b"synthetic application fixture\n",
    "large/cancel.bin": bytes(range(256)) * 8192,
    "nested/binary.bin": bytes(range(256)),
    "nested/spaced name.txt": b"spaces remain exact\n",
}
STAMP = "2025-01-02T03:04:05+00:00"
DIR_STAMP = "2000-01-01T00:00:00+00:00"
NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
REL = "http://schemas.openxmlformats.org/package/2006/relationships"
DOC_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
CSV_HEADER = ["path_encoding", "remote", "path", "size", "modified", "is_dir", "hash", "hash_type"]
XLSX_HEADER = ["Remote", "Path", "Size", "Modified", "IsDir", "Hash", "HashType"]


def config_bytes(remotes):
    return ("# rclone-triage config\n" + "".join(
        f"\n[{remote}]\ntype = http\nurl = {url}\n" for remote, url in remotes.items())).encode()


def workbook_bytes(rows):
    # Independent relationship-complete package for one ordinary Listing sheet.
    # Content/relationship literals follow the locked writer's public package
    # format, not the oracle's tables; negative tests mutate this valid graph.
    strings = []
    sheet = ET.Element("worksheet", xmlns=NS)
    sheet_data = ET.SubElement(sheet, "sheetData")
    for number, values in enumerate(rows, 1):
        row = ET.SubElement(sheet_data, "row", r=str(number))
        for column, value in enumerate(values):
            if value == "":
                continue
            cell = ET.SubElement(row, "c", r=chr(65 + column) + str(number))
            if type(value) is bool:
                cell.set("t", "b")
                encoded = "1" if value else "0"
            else:
                cell.set("t", "s")
                if value not in strings:
                    strings.append(value)
                encoded = str(strings.index(value))
            ET.SubElement(cell, "v").text = encoded
    table = ET.Element("sst", xmlns=NS)
    for value in strings:
        ET.SubElement(ET.SubElement(table, "si"), "t").text = value
    book = ET.Element("workbook", xmlns=NS)
    ET.SubElement(ET.SubElement(book, "sheets"), "sheet", {
        "name": "Listing", "sheetId": "1", "{" + DOC_REL + "}id": "rId1"})
    root_rels = ET.Element("Relationships", xmlns=REL)
    for number, relation, target in (
        (1, DOC_REL + "/officeDocument", "xl/workbook.xml"),
        (2, REL + "/metadata/core-properties", "docProps/core.xml"),
        (3, DOC_REL + "/extended-properties", "docProps/app.xml"),
    ):
        ET.SubElement(root_rels, "Relationship", Id=f"rId{number}", Type=relation, Target=target)
    book_rels = ET.Element("Relationships", xmlns=REL)
    for number, relation, target in (
        (1, "worksheet", "worksheets/sheet1.xml"), (2, "theme", "theme/theme1.xml"),
        (3, "styles", "styles.xml"), (4, "sharedStrings", "sharedStrings.xml"),
    ):
        ET.SubElement(book_rels, "Relationship", Id=f"rId{number}", Type=DOC_REL + "/" + relation, Target=target)
    content = ET.Element("Types", xmlns="http://schemas.openxmlformats.org/package/2006/content-types")
    ET.SubElement(content, "Default", Extension="rels", ContentType="application/vnd.openxmlformats-package.relationships+xml")
    ET.SubElement(content, "Default", Extension="xml", ContentType="application/xml")
    for part, kind in (
        ("/xl/workbook.xml", "officedocument.spreadsheetml.sheet.main"),
        ("/xl/worksheets/sheet1.xml", "officedocument.spreadsheetml.worksheet"),
        ("/xl/sharedStrings.xml", "officedocument.spreadsheetml.sharedStrings"),
        ("/xl/styles.xml", "officedocument.spreadsheetml.styles"),
        ("/xl/theme/theme1.xml", "officedocument.theme"),
        ("/docProps/core.xml", "package.core-properties"),
        ("/docProps/app.xml", "officedocument.extended-properties"),
    ):
        ET.SubElement(content, "Override", PartName=part, ContentType="application/vnd.openxmlformats-" + kind + "+xml")
    # No style index is used by the sparse cells. Supporting parts are ordinary
    # non-executable synthetic XML; they earn no rendering/formatting credit.
    styles = f'<styleSheet xmlns="{NS}"><fonts count="1"><font/></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border/></borders><cellStyleXfs count="1"><xf/></cellStyleXfs><cellXfs count="1"><xf xfId="0"/></cellXfs></styleSheet>'.encode()
    theme = b'<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="Synthetic"><a:themeElements><a:clrScheme name="Synthetic"/><a:fontScheme name="Synthetic"/><a:fmtScheme name="Synthetic"/></a:themeElements></a:theme>'
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", ET.tostring(content))
        archive.writestr("_rels/.rels", ET.tostring(root_rels))
        archive.writestr("xl/_rels/workbook.xml.rels", ET.tostring(book_rels))
        archive.writestr("xl/workbook.xml", ET.tostring(book))
        archive.writestr("xl/worksheets/sheet1.xml", ET.tostring(sheet))
        archive.writestr("xl/sharedStrings.xml", ET.tostring(table))
        archive.writestr("xl/styles.xml", styles)
        archive.writestr("xl/theme/theme1.xml", theme)
        archive.writestr("docProps/app.xml", b'<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"/>')
        archive.writestr("docProps/core.xml", b'<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"/>')
    return output.getvalue()


def listing_files(root):
    rows = [["", member, str(len(payload)), STAMP, False, "", ""] for member, payload in PAYLOADS.items()]
    rows.extend([["", "large", "", DIR_STAMP, True, "", ""], ["", "nested", "", DIR_STAMP, True, "", ""]])
    text = io.StringIO(newline="")
    writer = csv.writer(text)
    writer.writerow(CSV_HEADER)
    writer.writerows([["excel-safe-v1"] + r[:4] + [str(r[4]).lower()] + r[5:] for r in rows])
    (root / "listings/http_files.csv").write_bytes(b"\xef\xbb\xbf" + text.getvalue().encode())
    (root / "listings/http_files.xlsx").write_bytes(workbook_bytes([XLSX_HEADER] + rows))
    return rows


def manifest(root, remote, members, cancel=False):
    plans, results = [], []
    for member in sorted(members):
        destination = root / "downloads" / remote / member
        destination.parent.mkdir(parents=True, exist_ok=True)
        payload = PAYLOADS[member]
        if not cancel:
            destination.write_bytes(payload)
        request = {"source": remote + ":" + member, "destination": str(destination), "mode": "CopyTo",
                   "expected_hash": None, "expected_hash_type": None, "expected_size": len(payload)}
        plans.append({"remote_name": remote, "path": member, "request": request})
        results.append({"local_sha256": None if cancel else hashlib.sha256(payload).hexdigest(),
                        "integrity": "Cancelled" if cancel else "Unavailable", "source": request["source"],
                        "destination": str(destination), "success": not cancel,
                        "error": "Operation cancelled" if cancel else None,
                        "size": None if cancel else len(payload), "hash": None, "hash_type": None,
                        "hash_verified": None, "hash_error": None if cancel else
                        "Source did not supply a hash; local SHA-256 recorded"})
    return {"schema_version": 1, "written_at": "2026-10-10T01:02:03.1234567Z", "rclone_version": "1.75.2",
            "config_path": str(root / "config/rclone.conf"),
            "plan": {"files": plans, "skipped_directories": 0}, "results": results, "complete": not cancel}


class TuiArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tui-oracle-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / "SyntheticCase"
        for directory in ("config", "downloads", "listings", "logs"):
            (self.root / directory).mkdir(parents=True)
        self.remotes = {"TuiHttpA": "http://127.0.0.1:12345/"}
        (self.root / "config/rclone.conf").write_bytes(config_bytes(self.remotes))
        self.config = O.validate_manual_config(self.root, self.remotes)
        self.rows = listing_files(self.root)
        # Only bounded presence is claimed for these supporting report files.
        for name in ("logs/rclone-triage.log", "forensic_report.txt", "forensic_report.xlsx", "log-checkpoint.json"):
            (self.root / name).write_bytes(b"synthetic supporting artifact\n")
        self.no_process = mock.patch.object(subprocess, "Popen", side_effect=AssertionError("no processes"))
        self.no_socket = mock.patch.object(socket, "socket", side_effect=AssertionError("no sockets"))
        self.no_process.start()
        self.no_socket.start()
        self.addCleanup(self.no_process.stop)
        self.addCleanup(self.no_socket.stop)

    def save(self, document):
        (self.root / "acquisition-manifest.json").write_text(json.dumps(document), encoding="utf-8")

    def acquire(self, members=("README-synthetic.txt",), remote="TuiHttpA", cancel=False, prior=()):
        return O.validate_acquisition(self.root, self.config, remote, members, "1.75.2",
                                      outcome="cancelled" if cancel else "success", prior=prior)

    def reject(self, action, expected=None):
        with self.assertRaises(O.OracleError) as caught:
            action()
        self.assertIn(str(caught.exception), O.ERRORS)
        if expected:
            self.assertEqual(str(caught.exception), expected)

    def test_literal_fixture_hashes_and_exact_listing(self):
        for member, payload in PAYLOADS.items():
            self.assertEqual((len(payload), hashlib.sha256(payload).hexdigest()), O.MEMBERS[member])
        evidence = O.validate_listing(self.root, self.config, "TuiHttpA")
        self.assertEqual((evidence["files"], evidence["directories"]), (4, 2))
        self.assertEqual(set(evidence), {"files", "directories", "csv_sha256", "xlsx_sha256"})

    def test_manual_config_rejects_unknown_duplicate_and_changed_keys(self):
        original = self.config.data
        variants = [original + b"token = sensitive-canary\n", original + b"url = http://127.0.0.1:12345/\n",
                    original.replace(b"type = http", b"type = webdav"),
                    original.replace(b"url = ", b"url= "), original + b"\n[Unexpected]\ntype = http\n"]
        for data in variants:
            with self.subTest(data_length=len(data)):
                (self.root / "config/rclone.conf").write_bytes(data)
                self.reject(lambda: O.validate_manual_config(self.root, self.remotes))

    def test_config_rejects_nonloopback_ambiguous_and_credential_endpoints(self):
        for url in ("https://127.0.0.1:12345/", "http://localhost:12345/", "http://127.0.0.1:65536/",
                    "http://user:secret@127.0.0.1:12345/", "http://127.0.0.1:12345/?x=1"):
            self.reject(lambda: O.validate_manual_config(self.root, {"TuiHttpA": url}), "config_invalid")
        self.reject(lambda: O.validate_manual_config(self.root, {"TuiHttpA": self.remotes["TuiHttpA"],
                                                               "tuihttpa": "http://127.0.0.1:12346/"}))

    def test_reset_adds_only_new_remote_and_preserves_original_bytes(self):
        both = self.remotes | {"TuiHttpB": "http://127.0.0.1:12346/"}
        (self.root / "config/rclone.conf").write_bytes(config_bytes(both))
        second = O.validate_manual_config(self.root, both, previous=self.config)
        self.assertEqual(len(second.remotes), 2)
        self.assertTrue(second.data.startswith(self.config.data))
        changed = config_bytes(both).replace(b"[TuiHttpA]", b"\n[TuiHttpA]")
        (self.root / "config/rclone.conf").write_bytes(changed)
        self.reject(lambda: O.validate_manual_config(self.root, both, previous=self.config), "config_changed")

    def test_config_snapshot_binds_case_and_rejects_working_copy(self):
        (self.root / "config/working-extra.conf").write_bytes(self.config.data)
        self.reject(lambda: O.validate_listing(self.root, self.config, "TuiHttpA"), "config_invalid")
        (self.root / "config/working-extra.conf").unlink()
        stale = O.ConfigSnapshot(str(self.root.parent), self.config.remotes, self.config.data)
        self.reject(lambda: O.validate_listing(self.root, stale, "TuiHttpA"), "config_changed")

    def test_csv_rejects_missing_duplicate_remote_hash_and_wrong_time(self):
        path = self.root / "listings/http_files.csv"
        original = path.read_bytes()
        lines = original.splitlines(keepends=True)
        mutations = [b"".join(lines[:-1]), original + lines[1], original.replace(b"excel-safe-v1,,", b"excel-safe-v1,TuiHttpA,"),
                     original.replace(b",false,,", b",false,deadbeef,sha256"), original.replace(b"03:04:05", b"03:04:06")]
        for value in mutations:
            path.write_bytes(value)
            self.reject(lambda: O.validate_listing(self.root, self.config, "TuiHttpA"), "listing_invalid")
        path.write_bytes(original.removeprefix(b"\xef\xbb\xbf"))
        self.reject(lambda: O.validate_listing(self.root, self.config, "TuiHttpA"), "listing_invalid")

    def test_xlsx_semantic_rows_must_match_independently(self):
        path = self.root / "listings/http_files.xlsx"
        for mutation in ("missing", "size", "time", "directory", "duplicate"):
            rows = copy.deepcopy(self.rows)
            if mutation == "missing":
                rows.pop()
            elif mutation == "size":
                rows[0][2] = "31"
            elif mutation == "time":
                rows[0][3] = "2025-01-02T03:04:06+00:00"
            elif mutation == "directory":
                rows[0][4] = True
            else:
                rows.append(rows[0])
            path.write_bytes(workbook_bytes([XLSX_HEADER] + rows))
            self.reject(lambda: O.validate_listing(self.root, self.config, "TuiHttpA"), "listing_invalid")

    def rewrite_workbook(self, files):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            for name, data in files.items():
                archive.writestr(name, data)
        (self.root / "listings/http_files.xlsx").write_bytes(output.getvalue())

    def workbook_parts(self):
        with zipfile.ZipFile(self.root / "listings/http_files.xlsx") as archive:
            return {name: archive.read(name) for name in archive.namelist()}

    def test_xlsx_requires_every_package_part_even_with_correct_rows(self):
        original = self.workbook_parts()
        self.assertEqual(len(original), 10)
        for missing in original:
            with self.subTest(missing=missing):
                self.rewrite_workbook({name: data for name, data in original.items() if name != missing})
                self.reject(lambda: O.validate_listing(self.root, self.config, "TuiHttpA"), "listing_invalid")
        self.rewrite_workbook(original)
        self.assertEqual(O.validate_listing(self.root, self.config, "TuiHttpA")["files"], 4)

    def test_xlsx_rejects_disconnected_or_redirected_relationships(self):
        original = self.workbook_parts()
        for part in ("_rels/.rels", "xl/_rels/workbook.xml.rels"):
            for mutation in ("missing", "id", "target", "type", "external", "duplicate", "namespace"):
                with self.subTest(part=part, mutation=mutation):
                    tree = ET.fromstring(original[part])
                    if mutation == "missing":
                        tree.remove(tree[0])
                    elif mutation == "id":
                        tree[0].set("Id", "rId99")
                    elif mutation == "target":
                        # Another allowed part must not replace the workbook or
                        # worksheet target, even while expected sheet1 is intact.
                        tree[0].set("Target", "docProps/app.xml" if part == "_rels/.rels" else "theme/theme1.xml")
                    elif mutation == "type":
                        tree[0].set("Type", DOC_REL + "/theme")
                    elif mutation == "external":
                        tree[0].set("TargetMode", "External")
                    elif mutation == "duplicate":
                        tree.append(copy.deepcopy(tree[0]))
                    else:
                        tree.tag = "Relationships"
                    self.rewrite_workbook(original | {part: ET.tostring(tree)})
                    self.reject(lambda: O.validate_listing(self.root, self.config, "TuiHttpA"), "listing_invalid")

    def test_xlsx_binds_sheet_identity_and_declared_content_types(self):
        original = self.workbook_parts()
        for mutation in ("missing_id", "wrong_id", "hidden", "duplicate_sheets", "wrong_sheet_root",
                         "missing_content_type", "wrong_content_type", "duplicate_content_type"):
            with self.subTest(mutation=mutation):
                files = dict(original)
                if "content_type" in mutation:
                    part = "[Content_Types].xml"
                    tree = ET.fromstring(files[part])
                    if mutation == "missing_content_type":
                        tree.remove(tree[2])
                    elif mutation == "wrong_content_type":
                        tree[2].set("ContentType", "application/xml")
                    else:
                        tree.append(copy.deepcopy(tree[2]))
                elif mutation == "wrong_sheet_root":
                    part = "xl/worksheets/sheet1.xml"
                    tree = ET.fromstring(files[part])
                    tree.tag = "{" + NS + "}unrelated"
                else:
                    part = "xl/workbook.xml"
                    tree = ET.fromstring(files[part])
                    sheets = tree.find("{" + NS + "}sheets")
                    if mutation == "missing_id":
                        del sheets[0].attrib["{" + DOC_REL + "}id"]
                    elif mutation == "wrong_id":
                        sheets[0].set("{" + DOC_REL + "}id", "rId2")
                    elif mutation == "hidden":
                        sheets[0].set("state", "hidden")
                    else:
                        tree.append(copy.deepcopy(sheets))
                self.rewrite_workbook(files | {part: ET.tostring(tree)})
                self.reject(lambda: O.validate_listing(self.root, self.config, "TuiHttpA"), "listing_invalid")

    def test_xlsx_rejects_external_formula_traversal_and_xml_entities(self):
        original = (self.root / "listings/http_files.xlsx").read_bytes()
        for variant in ("external", "formula", "traversal", "entity"):
            with zipfile.ZipFile(io.BytesIO(original)) as z:
                files = {name: z.read(name) for name in z.namelist()}
            if variant == "external":
                files["xl/_rels/workbook.xml.rels"] = b'<Relationships><Relationship TargetMode="External" Target="https://example.invalid"/></Relationships>'
            elif variant == "formula":
                files["xl/worksheets/sheet1.xml"] = files["xl/worksheets/sheet1.xml"].replace(b"<v>", b"<f>SECRET()</f><v>", 1)
            elif variant == "traversal":
                files["../outside.xml"] = b"<x/>"
            else:
                files["xl/sharedStrings.xml"] = b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///secret">]><sst/>'
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w") as z:
                for name, data in files.items():
                    z.writestr(name, data)
            (self.root / "listings/http_files.xlsx").write_bytes(output.getvalue())
            self.reject(lambda: O.validate_listing(self.root, self.config, "TuiHttpA"), "listing_invalid")

    def test_selected_acquisition_requires_real_bytes_not_verified_label(self):
        self.save(manifest(self.root, "TuiHttpA", ("README-synthetic.txt",)))
        result = self.acquire()
        self.assertEqual(result.selected_count, 1)
        self.assertFalse(result.cancelled)
        self.assertEqual(len(result.outputs), 1)
        self.assertNotIn("synthetic", repr(result).lower())
        self.assertEqual((self.root / "downloads/TuiHttpA/README-synthetic.txt").read_bytes(), b"synthetic application fixture\n")
        (self.root / "downloads/TuiHttpA/README-synthetic.txt").write_bytes(b"X" * 30)
        self.reject(self.acquire, "outputs_invalid")

    def test_manifest_rejects_remote_source_destination_mode_or_expected_hash_drift(self):
        original = manifest(self.root, "TuiHttpA", ("README-synthetic.txt",))
        mutations = [("remote_name", "TuiHttpB"), ("path", "nested/binary.bin")]
        for key, value in mutations:
            changed = copy.deepcopy(original)
            changed["plan"]["files"][0][key] = value
            self.save(changed)
            self.reject(self.acquire, "manifest_invalid")
        for key, value in (("source", "TuiHttpB:README-synthetic.txt"), ("destination", str(self.root / "escaped")),
                           ("mode", "Copy"), ("expected_hash", "abc"), ("expected_hash_type", "sha256"), ("expected_size", True)):
            changed = copy.deepcopy(original)
            changed["plan"]["files"][0]["request"][key] = value
            self.save(changed)
            self.reject(self.acquire, "manifest_invalid")

    def test_manifest_rejects_verified_dryrun_mismatch_partial_and_wrong_runtime(self):
        original = manifest(self.root, "TuiHttpA", ("README-synthetic.txt",))
        for integrity in ("Verified", "DryRun", "Mismatch", "Failed", "Cancelled"):
            changed = copy.deepcopy(original)
            changed["results"][0]["integrity"] = integrity
            self.save(changed)
            self.reject(self.acquire, "manifest_invalid")
        for key, value in (("complete", False), ("schema_version", True), ("rclone_version", "1.75.1"),
                           ("results", []), ("written_at", "2026-10-10T01:02:03")):
            changed = copy.deepcopy(original)
            changed[key] = value
            self.save(changed)
            self.reject(self.acquire, "manifest_invalid")

    def test_manifest_exact_closed_schema_and_duplicate_json_keys(self):
        original = manifest(self.root, "TuiHttpA", ("README-synthetic.txt",))
        for location in ("top", "plan", "item", "request", "result"):
            changed = copy.deepcopy(original)
            target = {"top": changed, "plan": changed["plan"], "item": changed["plan"]["files"][0],
                      "request": changed["plan"]["files"][0]["request"], "result": changed["results"][0]}[location]
            target["unexpected"] = "sensitive-canary"
            self.save(changed)
            self.reject(self.acquire, "manifest_invalid")
        data = json.dumps(original).replace('"complete": true', '"complete": false, "complete": true')
        (self.root / "acquisition-manifest.json").write_text(data, encoding="utf-8")
        self.reject(self.acquire, "manifest_invalid")

    def test_multiple_selected_files_exact_plan_and_unordered_results(self):
        chosen = ("nested/spaced name.txt", "README-synthetic.txt")
        value = manifest(self.root, "TuiHttpA", chosen)
        value["results"].reverse()
        self.save(value)
        self.assertEqual(self.acquire(chosen).selected_count, 2)
        value["results"][1] = copy.deepcopy(value["results"][0])
        self.save(value)
        self.reject(lambda: self.acquire(chosen), "manifest_invalid")

    def test_unselected_outputs_and_partial_staging_are_rejected(self):
        self.save(manifest(self.root, "TuiHttpA", ("README-synthetic.txt",)))
        rogue = self.root / "downloads/TuiHttpA/unselected.txt"
        rogue.write_bytes(b"extra")
        self.reject(self.acquire, "outputs_invalid")
        rogue.unlink()
        stage = self.root / "downloads/TuiHttpA/.triage-transfer-" / "payload.12345678.partial"
        stage.parent.mkdir()
        stage.write_bytes(b"partial")
        self.reject(self.acquire, "outputs_invalid")

    def test_known_supporting_artifacts_only_and_config_unchanged(self):
        self.save(manifest(self.root, "TuiHttpA", ("README-synthetic.txt",)))
        (self.root / "unexpected.txt").write_bytes(b"extra")
        self.reject(self.acquire, "outputs_invalid")
        (self.root / "unexpected.txt").unlink()
        (self.root / "forensic_report.txt").unlink()
        self.reject(self.acquire, "outputs_invalid")
        (self.root / "forensic_report.txt").write_bytes(b"report")
        (self.root / "config/rclone.conf").write_bytes(self.config.data + b"\n")
        self.reject(self.acquire, "config_changed")

    def test_success_reset_second_remote_preserves_prior_download_and_manifest(self):
        self.save(manifest(self.root, "TuiHttpA", ("README-synthetic.txt",)))
        first = self.acquire()
        remotes = self.remotes | {"TuiHttpB": "http://127.0.0.1:12346/"}
        (self.root / "config/rclone.conf").write_bytes(config_bytes(remotes))
        self.config = O.validate_manual_config(self.root, remotes, previous=self.config)
        (self.root / "acquisition-prior-ABC123.json").write_bytes(first.manifest)
        self.save(manifest(self.root, "TuiHttpB", ("README-synthetic.txt",)))
        second = self.acquire(remote="TuiHttpB", prior=(first,))
        self.assertEqual(len(second.outputs), 2)
        (self.root / "downloads/TuiHttpA/README-synthetic.txt").write_bytes(b"X" * 30)
        self.reject(lambda: self.acquire(remote="TuiHttpB", prior=(first,)), "outputs_invalid")

    def test_history_requires_exact_prior_bytes_no_unrequested_archives(self):
        self.save(manifest(self.root, "TuiHttpA", ("README-synthetic.txt",)))
        (self.root / "acquisition-prior-ABC123.json").write_bytes(b"{}")
        self.reject(self.acquire, "history_invalid")
        (self.root / "acquisition-prior-ABC123.json").unlink()
        first = self.acquire()
        self.save(manifest(self.root, "TuiHttpA", ("nested/binary.bin",)))
        (self.root / "acquisition-prior-ABC123.json").write_bytes(first.manifest.replace(b'"Unavailable"', b'"Verified"'))
        self.reject(lambda: self.acquire(("nested/binary.bin",), prior=(first,)), "history_invalid")

    def test_cancelled_manifest_requires_no_output_and_exact_cancelled_state(self):
        chosen = ("large/cancel.bin",)
        original = manifest(self.root, "TuiHttpA", chosen, cancel=True)
        self.save(original)
        cancelled = self.acquire(chosen, cancel=True)
        self.assertTrue(cancelled.cancelled)
        self.assertEqual(cancelled.outputs, ())
        for key, value in (("success", True), ("integrity", "Failed"), ("size", 0), ("local_sha256", "0" * 64), ("error", "")):
            changed = copy.deepcopy(original)
            changed["results"][0][key] = value
            self.save(changed)
            self.reject(lambda: self.acquire(chosen, cancel=True), "manifest_invalid")
        self.save(original)
        (self.root / "downloads/TuiHttpA/large/cancel.bin").write_bytes(b"partial")
        self.reject(lambda: self.acquire(chosen, cancel=True), "outputs_invalid")

    def test_cancelled_cleanup_failure_is_sticky_without_any_residue(self):
        chosen = ("large/cancel.bin",)
        document = manifest(self.root, "TuiHttpA", chosen, cancel=True)
        # The app preserves Cancelled on staging.close failure, even though an
        # independent subsequent directory walk might find no remaining file.
        for error in ("Operation cancelled; transfer staging cleanup failed: PRIVATE-CANARY",
                      "bounded child error\nOperation cancelled; transfer staging cleanup failed: PRIVATE-CANARY",
                      "Transfer staging cleanup failed: PRIVATE-CANARY"):
            with self.subTest(error_form=error.split(":", 1)[0]):
                document["results"][0]["error"] = error
                self.save(document)
                self.assertFalse(any(path.is_file() for path in (self.root / "downloads").rglob("*")))
                with self.assertRaises(O.OracleError) as raised:
                    self.acquire(chosen, cancel=True)
                self.assertEqual(str(raised.exception), "manifest_invalid")
                self.assertNotIn("PRIVATE-CANARY", str(raised.exception))
        # Managed cancellation may append its fixed message to child stderr;
        # exact single-message matching would reject this legitimate shape.
        document["results"][0]["error"] = "bounded child error\nOperation cancelled"
        self.save(document)
        self.assertTrue(self.acquire(chosen, cancel=True).cancelled)

    def test_paths_cannot_escape_or_use_parent_aliases(self):
        original = manifest(self.root, "TuiHttpA", ("README-synthetic.txt",))
        for value in (str(self.root / "config/../config/rclone.conf"), "relative/config/rclone.conf", str(self.root / "config/rclone.conf") + ":stream"):
            changed = copy.deepcopy(original)
            changed["config_path"] = value
            self.save(changed)
            self.reject(self.acquire, "manifest_invalid")
        self.reject(lambda: O.validate_manual_config(self.root / ".." / self.root.name, self.remotes), "path_invalid")

    def test_hardlink_input_and_reparse_metadata_rejected(self):
        config_path = self.root / "config/rclone.conf"
        extra = self.root.parent / "linked-config.conf"
        os.link(config_path, extra)
        self.reject(lambda: O.validate_manual_config(self.root, self.remotes), "path_invalid")
        extra.unlink()
        real = Path.lstat

        def reparse(path, *args, **kwargs):
            info = real(path, *args, **kwargs)
            if path == config_path:
                fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
                fields["st_file_attributes"] = 0x400
                return type("ReparseMetadata", (), fields)()
            return info
        with mock.patch.object(Path, "lstat", reparse):
            self.reject(lambda: O.validate_manual_config(self.root, self.remotes), "path_invalid")

    def test_size_budget_and_errors_never_echo_artifact_content(self):
        (self.root / "config/rclone.conf").write_bytes(b"sensitive-canary" * 600)
        self.reject(lambda: O.validate_manual_config(self.root, self.remotes), "artifact_invalid")
        (self.root / "config/rclone.conf").write_bytes(self.config.data)
        (self.root / "acquisition-manifest.json").write_bytes(b'{"secret":"sensitive-canary"')
        self.reject(self.acquire, "artifact_invalid")
        self.assertNotIn("12345", repr(self.config))

    def test_wrong_case_remote_unknown_selection_and_bool_type_refused(self):
        self.save(manifest(self.root, "TuiHttpA", ("README-synthetic.txt",)))
        self.reject(lambda: self.acquire(remote="tuihttpa"), "config_invalid")
        self.reject(lambda: self.acquire(("README-synthetic.txt", "README-synthetic.txt")))
        self.reject(lambda: self.acquire(("../README-synthetic.txt",)))
        self.reject(lambda: self.acquire(()))
        document = json.loads((self.root / "acquisition-manifest.json").read_text())
        document["results"][0]["success"] = 1
        self.save(document)
        self.reject(self.acquire, "manifest_invalid")


if __name__ == "__main__":
    unittest.main()
