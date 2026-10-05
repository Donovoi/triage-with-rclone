"""Independent synthetic tar and mocked lifetime tests; no external execution."""
import contextlib
import copy
import datetime as dt
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import urllib.request

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("bootstrap_material_under_test", HERE / "bootstrap_material.py")
b = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = b
SPEC.loader.exec_module(b)
ROOT_NAME = "apache-maven-3.9.16"
SCRIPT = b"#!/bin/sh\n# inert fixture, never executed\n"


def archive(entries=None):
    entries = entries if entries is not None else [
        (ROOT_NAME + "/", tarfile.DIRTYPE, b"", 0o755),
        (ROOT_NAME + "/bin/", tarfile.DIRTYPE, b"", 0o755),
        (ROOT_NAME + "/bin/mvn", tarfile.REGTYPE, SCRIPT, 0o755)]
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as target:
        for name, kind, payload, mode in entries:
            item = tarfile.TarInfo(name)
            item.type, item.size, item.mode = kind, len(payload), mode
            item.linkname = "/unrelated/target" if kind in {tarfile.SYMTYPE, tarfile.LNKTYPE} else ""
            target.addfile(item, io.BytesIO(payload))
    return gzip.compress(stream.getvalue(), mtime=0)


def patch_header(data, index, fields):
    """Independent raw USTAR oracle: writer APIs otherwise mask Unix type bits."""
    raw = bytearray(gzip.decompress(data))
    start = 0
    for _ in range(1, index):
        size = int(raw[start + 124:start + 136].rstrip(b"\0 "), 8)
        start += 512 + ((size + 511) // 512) * 512
    header = bytearray(raw[start:start + 512])
    assert len(header) == 512 and any(header)
    for offset, value in fields.items():
        assert 0 <= offset < 512 and offset + len(value) <= 512
        header[offset:offset + len(value)] = value
    header[148:156] = b" " * 8
    header[148:156] = f"{sum(header):06o}\0 ".encode("ascii")
    raw[start:start + 512] = header
    return gzip.compress(raw, mtime=0)


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.stack = contextlib.ExitStack()
        self.stack.enter_context(mock.patch.object(subprocess, "Popen", side_effect=AssertionError("native_forbidden")))
        self.stack.enter_context(mock.patch.object(urllib.request, "urlopen", side_effect=AssertionError("network_forbidden")))
        self.stack.enter_context(mock.patch.object(os, "system", side_effect=AssertionError("shell_forbidden")))

    def tearDown(self):
        self.stack.close()
        self.temp.cleanup()

    def error(self, code, fn, *args):
        with self.assertRaises(b.MaterialError) as caught:
            fn(*args)
        self.assertEqual(caught.exception.code, code)

    def layout(self, data):
        path = self.root / "layout.gz"
        path.write_bytes(data)
        return b.inspect_layout(path)

    def test_data_only_layout_has_independent_counts_and_script_hash(self):
        result = self.layout(archive())
        self.assertEqual((result["members"], result["files"], result["directories"]), (3, 1, 2))
        self.assertEqual(result["payload_bytes"], len(SCRIPT))
        self.assertEqual(result["mvn"], {"size": len(SCRIPT), "sha256": hashlib.sha256(SCRIPT).hexdigest(), "executable": True})
        self.assertFalse(result["extracted"])
        self.assertFalse(result["executed"])
        self.assertEqual(sorted(path.name for path in self.root.iterdir()), ["layout.gz"])

    def test_absent_archive_and_absent_mvn_reject(self):
        self.error("source_invalid", b.inspect_layout, self.root / "absent.gz")
        self.error("layout_mvn_invalid", self.layout, archive([]))

    def test_symlink_and_hardlink_members_reject_before_extraction(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            with self.subTest(kind=kind):
                self.error("layout_link_unsupported", self.layout, archive([(ROOT_NAME + "/link", kind, b"", 0o777)]))

    def test_aliases_absolute_traversal_backslash_and_controls_reject(self):
        for name in ("/" + ROOT_NAME + "/bin/mvn", ROOT_NAME + "/../bin/mvn", ROOT_NAME + "//bin/mvn",
                     ROOT_NAME + "/./bin/mvn", ROOT_NAME + "\\bin\\mvn", ROOT_NAME + "/bin/mvn\n",
                     "other/bin/mvn", ROOT_NAME + "/bin/mvn/"):
            with self.subTest(name=name):
                self.error("layout_alias", self.layout, archive([(name, tarfile.REGTYPE, SCRIPT, 0o755)]))

    def test_duplicate_canonical_names_reject(self):
        entries = [(ROOT_NAME + "/", tarfile.DIRTYPE, b"", 0o755),
                   (ROOT_NAME, tarfile.DIRTYPE, b"", 0o755)]
        # TarInfo writes a trailing slash for both names; remove it in the actual header.
        data = patch_header(archive(entries), 2, {0: ROOT_NAME.encode().ljust(100, b"\0")})
        self.error("layout_duplicate", self.layout, data)

    def duplicate_diagnostic(self, entries, updates=()):
        data = archive(entries)
        for index, fields in updates:
            data = patch_header(data, index, fields)
        with self.assertRaises(b.MaterialError) as caught:
            self.layout(data)
        self.assertEqual(str(caught.exception), "layout_duplicate")
        return caught.exception.diagnostic

    def test_duplicate_directories_report_only_canonical_hash_and_closed_metadata(self):
        name = ROOT_NAME + "/PRIVATE_NAME_CANARY"
        result = self.duplicate_diagnostic([(name + "/", tarfile.DIRTYPE, b"", 0o755),
                                            (name, tarfile.DIRTYPE, b"", 0o755)],
                                           updates=((2, {0: name.encode().ljust(100, b"\0")}),))
        self.assertEqual(result, {
            "schema_version": 1, "code": "layout_duplicate",
            "canonical_path_sha256": hashlib.sha256(name.encode()).hexdigest(),
            "existing": {"index": 1, "type": "directory", "size": 0, "mode": 0o755, "payload_sha256": None},
            "new": {"index": 2, "type": "directory", "size": 0, "mode": 0o755, "payload_sha256": None},
            "same_type": True, "same_size": True, "same_mode": True, "same_content": True})
        self.assertNotIn("PRIVATE_NAME_CANARY", json.dumps(result))
        self.assertNotIn(ROOT_NAME, json.dumps(result))

    def test_duplicate_files_independently_compare_full_payload_size_and_modes(self):
        name, payload = ROOT_NAME + "/PRIVATE_NAME_CANARY", b"PRIVATE_PAYLOAD_CANARY"
        for other, mode, same_size, same_mode, same_content in (
                (payload, 0o644, True, True, True),
                (payload.lower(), 0o644, True, True, False),
                (payload + b"x", 0o644, False, True, False),
                (payload, 0o600, True, False, True)):
            with self.subTest(mode=mode, same_content=same_content, same_size=same_size):
                result = self.duplicate_diagnostic([(name, tarfile.REGTYPE, payload, 0o644),
                                                    (name, tarfile.REGTYPE, other, mode)])
                self.assertEqual(result["existing"], {"index": 1, "type": "file", "size": len(payload),
                    "mode": 0o644, "payload_sha256": hashlib.sha256(payload).hexdigest()})
                self.assertEqual(result["new"], {"index": 2, "type": "file", "size": len(other),
                    "mode": mode, "payload_sha256": hashlib.sha256(other).hexdigest()})
                self.assertEqual((result["same_type"], result["same_size"], result["same_mode"], result["same_content"]),
                                 (True, same_size, same_mode, same_content))
                self.assertNotIn("PRIVATE", json.dumps(result))

    def test_duplicate_cross_types_and_directory_mode_conflict_still_reject(self):
        name = ROOT_NAME + "/duplicate"
        for first, second in ((tarfile.DIRTYPE, tarfile.REGTYPE), (tarfile.REGTYPE, tarfile.DIRTYPE)):
            with self.subTest(first=first):
                result = self.duplicate_diagnostic([(name, first, b"", 0o755), (name, second, b"", 0o755)])
                self.assertFalse(result["same_type"])
                self.assertFalse(result["same_content"])
                self.assertTrue(result["same_size"])
                self.assertEqual({result["existing"]["payload_sha256"], result["new"]["payload_sha256"]},
                                 {None, hashlib.sha256(b"").hexdigest()})
        result = self.duplicate_diagnostic([(name, tarfile.DIRTYPE, b"", 0o755),
                                            (name, tarfile.DIRTYPE, b"", 0o700)])
        self.assertFalse(result["same_mode"])
        self.assertTrue(result["same_content"])

    def test_duplicate_payload_must_obey_bounds_and_be_complete(self):
        entries = [(ROOT_NAME + "/", tarfile.DIRTYPE, b"", 0o755),
                   (ROOT_NAME + "/duplicate", tarfile.REGTYPE, b"abcd", 0o644),
                   (ROOT_NAME + "/duplicate", tarfile.REGTYPE, b"abcd", 0o644)]
        data = archive(entries)
        with mock.patch.object(b, "MAX_PAYLOAD", 7):
            self.error("layout_bounds", self.layout, data)
        self.error("layout_truncated", self.layout, gzip.compress(gzip.decompress(data)[:2050], mtime=0))

    def test_diagnostic_schema_types_bounds_and_consistency_are_closed(self):
        good = self.duplicate_diagnostic([(ROOT_NAME, tarfile.DIRTYPE, b"", 0o755),
                                          (ROOT_NAME, tarfile.DIRTYPE, b"", 0o755)],
                                         updates=((2, {136: b"00000000001\0"}),))
        changes = [("schema_version", True), ("code", "PRIVATE_CODE"), ("extra", "PRIVATE_PATH"),
                   ("canonical_path_sha256", "PRIVATE_PATH"), ("canonical_path_sha256", "A" * 64),
                   ("same_type", 1), ("same_mode", False), ("same_content", False),
                   ("existing.index", True), ("existing.index", 0), ("existing.index", 2),
                   ("new.index", b.MAX_MEMBERS + 1), ("existing.size", True), ("existing.size", -1),
                   ("existing.size", b.MAX_PAYLOAD + 1), ("existing.size", 1),
                   ("existing.mode", True), ("existing.mode", -1), ("existing.mode", 0o4755),
                   ("existing.mode", 0o100755), ("existing.mode", 0o240755),
                   ("existing.payload_sha256", "a" * 64), ("existing.type", "symlink"),
                   ("existing.type", "file"), ("existing.path", "PRIVATE_PATH")]
        for field, value in changes:
            with self.subTest(field=field, value=value):
                changed = copy.deepcopy(good)
                if "." in field:
                    group, key = field.split(".")
                    changed[group][key] = value
                else:
                    changed[field] = value
                with self.assertRaisesRegex(ValueError, "^invalid_layout_diagnostic$"):
                    b.MaterialError("layout_duplicate", changed)
        with self.assertRaisesRegex(ValueError, "^invalid_layout_diagnostic$"):
            b.MaterialError("layout_invalid", good)
        error = b.MaterialError("layout_duplicate", good)
        good["existing"]["size"] = 1
        self.assertEqual(error.diagnostic["existing"]["size"], 0)

    def test_full_unix_modes_preserved_from_raw_headers(self):
        data = archive()
        for index, mode in ((1, 0o40755), (2, 0o40755), (3, 0o100755)):
            data = patch_header(data, index, {100: f"{mode:07o}\0".encode("ascii")})
        result = self.layout(data)
        expected_rows = [
            {"path": ROOT_NAME, "type": "directory", "size": 0, "mode": 0o40755, "sha256": None},
            {"path": ROOT_NAME + "/bin", "type": "directory", "size": 0, "mode": 0o40755, "sha256": None},
            {"path": ROOT_NAME + "/bin/mvn", "type": "file", "size": len(SCRIPT), "mode": 0o100755,
             "sha256": hashlib.sha256(SCRIPT).hexdigest()}]
        framing = (json.dumps(expected_rows, sort_keys=True, separators=(",", ":")) + "\n").encode()
        self.assertEqual(result["members_sha256"], hashlib.sha256(framing).hexdigest())
        self.assertEqual((result["members"], result["repeated_directories"]), (3, 0))
        self.assertTrue(result["mvn"]["executable"])
        # Nonexecutable data files accept 0100644 too; bin/mvn must stay executable.
        entries = [(ROOT_NAME + "/data", tarfile.REGTYPE, b"data", 0o644),
                   (ROOT_NAME + "/bin/mvn", tarfile.REGTYPE, SCRIPT, 0o755)]
        self.assertEqual(self.layout(patch_header(archive(entries), 1, {100: b"0100644\0"}))["files"], 2)

    def test_raw_conflicting_unknown_and_special_mode_bits_reject(self):
        for index, mode in ((1, 0o100755), (3, 0o40755), (1, 0o20755), (3, 0o140755),
                            (1, 0o240755), (3, 0o200755), (1, 0o44755), (3, 0o102755),
                            (3, 0o101755), (1, 0o1755), (3, 0o6755)):
            with self.subTest(index=index, mode=oct(mode)):
                self.error("layout_invalid", self.layout,
                           patch_header(archive(), index, {100: f"{mode:07o}\0".encode("ascii")}))

    def test_exact_repeated_directory_headers_retain_every_physical_row(self):
        entries = [(ROOT_NAME + "/", tarfile.DIRTYPE, b"", 0o755),
                   (ROOT_NAME + "/bin/", tarfile.DIRTYPE, b"", 0o755),
                   (ROOT_NAME + "/bin/mvn", tarfile.REGTYPE, SCRIPT, 0o755),
                   (ROOT_NAME + "/bin/", tarfile.DIRTYPE, b"", 0o755)]
        for full in (False, True):
            with self.subTest(full=full):
                data = archive(entries)
                modes = [0o40755, 0o40755, 0o100755, 0o40755] if full else [0o755] * 4
                for index, mode in enumerate(modes, 1):
                    data = patch_header(data, index, {100: f"{mode:07o}\0".encode("ascii")})
                result = self.layout(data)
                rows = [
                    {"path": ROOT_NAME, "type": "directory", "size": 0, "mode": modes[0], "sha256": None},
                    {"path": ROOT_NAME + "/bin", "type": "directory", "size": 0, "mode": modes[1], "sha256": None},
                    {"path": ROOT_NAME + "/bin/mvn", "type": "file", "size": len(SCRIPT), "mode": modes[2],
                     "sha256": hashlib.sha256(SCRIPT).hexdigest()},
                    {"path": ROOT_NAME + "/bin", "type": "directory", "size": 0, "mode": modes[3], "sha256": None}]
                framing = (json.dumps(rows, sort_keys=True, separators=(",", ":")) + "\n").encode()
                self.assertEqual(result["members_sha256"], hashlib.sha256(framing).hexdigest())
                self.assertEqual((result["members"], result["files"], result["directories"],
                                  result["repeated_directories"]), (4, 1, 3, 1))
                self.assertEqual(result["payload_bytes"], len(SCRIPT))
                self.assertFalse(result["extracted"])
                self.assertFalse(result["executed"])

    def test_directory_header_metadata_or_raw_spelling_changes_reject(self):
        entries = [(ROOT_NAME + "/", tarfile.DIRTYPE, b"", 0o755)] * 2
        for fields in ({108: b"0000001\0"}, {116: b"0000001\0"}, {136: b"00000000001\0"},
                       {265: b"PRIVATE_OWNER_CANARY"}, {297: b"PRIVATE_GROUP_CANARY"}, {500: b"x"},
                       {100: b"0040755\0"}, {0: ROOT_NAME.encode().ljust(100, b"\0")}):
            with self.subTest(offset=next(iter(fields))):
                result = self.duplicate_diagnostic(entries, updates=((2, fields),))
                self.assertEqual((result["existing"]["index"], result["new"]["index"]), (1, 2))
                self.assertNotIn("PRIVATE", json.dumps(result))
        for alias in (ROOT_NAME + "//", ROOT_NAME + "/./"):
            with self.subTest(alias=alias):
                self.error("layout_alias", self.layout,
                           patch_header(archive(entries), 2, {0: alias.encode().ljust(100, b"\0")}))

    def test_repeats_count_against_member_bound_and_preserve_first_index(self):
        entries = [(ROOT_NAME + "/", tarfile.DIRTYPE, b"", 0o755)] * 3
        entries += [(ROOT_NAME, tarfile.REGTYPE, b"", 0o755)]
        result = self.duplicate_diagnostic(entries)
        self.assertEqual((result["existing"]["index"], result["new"]["index"]), (1, 4))
        with mock.patch.object(b, "MAX_MEMBERS", 2):
            self.error("layout_bounds", self.layout, archive(entries))

    def test_repeated_file_still_rejects_with_full_modes(self):
        entries = [(ROOT_NAME + "/file", tarfile.REGTYPE, b"same", 0o644)] * 2
        result = self.duplicate_diagnostic(entries, updates=((1, {100: b"0100644\0"}), (2, {100: b"0100644\0"})))
        self.assertTrue(result["same_content"])
        self.assertEqual(result["existing"]["mode"], 0o100644)
        self.assertEqual(b.validate_layout_diagnostic(result), result)

    def test_pax_physical_headers_reject_before_large_payload_parse(self):
        for kind in (tarfile.XHDTYPE, tarfile.XGLTYPE):
            item = tarfile.TarInfo(ROOT_NAME + "/pax")
            item.type, item.size = kind, 1024 * 1024 * 1024
            data = gzip.compress(item.tobuf(format=tarfile.USTAR_FORMAT) + b"\0" * 1024, mtime=0)
            with self.subTest(kind=kind):
                self.error("layout_pax_unsupported", self.layout, data)

    def test_member_payload_and_decompressed_bounds_reject(self):
        for key, value in (("MAX_MEMBERS", 2), ("MAX_PAYLOAD", 8), ("MAX_TAR", 1024)):
            with self.subTest(key=key), mock.patch.object(b, key, value):
                self.error("layout_bounds", self.layout, archive())

    def test_mvn_directory_empty_or_nonexecutable_reject(self):
        cases = [(tarfile.DIRTYPE, b"", 0o755), (tarfile.REGTYPE, b"", 0o755), (tarfile.REGTYPE, SCRIPT, 0o644)]
        for kind, data, mode in cases:
            with self.subTest(kind=kind, mode=mode):
                self.error("layout_mvn_invalid", self.layout, archive([(ROOT_NAME + "/bin/mvn", kind, data, mode)]))

    def test_file_parent_conflict_and_special_modes_reject(self):
        self.error("layout_invalid", self.layout, archive([
            (ROOT_NAME + "/bin", tarfile.REGTYPE, b"file", 0o644),
            (ROOT_NAME + "/bin/mvn", tarfile.REGTYPE, SCRIPT, 0o755)]))
        self.error("layout_invalid", self.layout, archive([(ROOT_NAME + "/bin/mvn", tarfile.REGTYPE, SCRIPT, 0o4755)]))

    def test_truncated_tar_gzip_and_trailing_data_reject(self):
        raw = gzip.decompress(archive())
        self.error("layout_truncated", self.layout, gzip.compress(raw[:1700], mtime=0))
        self.error("layout_trailing_data", self.layout, gzip.compress(raw + b"UNEXPECTED", mtime=0))
        self.error("layout_invalid", self.layout, archive()[:-6])

    def test_source_loader_rejects_unreviewed_bytes_without_execution(self):
        path = self.root / "verifier.py"
        path.write_text('raise RuntimeError("MUST_NOT_EXECUTE")\n', encoding="ascii")
        self.error("source_changed", b.load_verifier, path)

    @contextlib.contextmanager
    def scenario(self, *, download_error=None, signature_error=None, cleanup_error=False, unreaped=False,
                 archive_data=None):
        inputs = self.root / "inputs"
        inputs.mkdir()
        source = b"# synthetic reviewed source; module loader is mocked\n"
        recipe = b"FROM synthetic\nENV JAVA_VERSION=jdk-17.0.20.1+1\n"
        config = b.canonical({"os": "linux", "architecture": "amd64", "config": {"Env": ["JAVA_VERSION=jdk-17.0.20.1+1"]}})
        config_hash = hashlib.sha256(config).hexdigest()
        manifest = b.canonical({"schemaVersion": 2, "config": {"digest": "sha256:" + config_hash, "size": len(config)},
                                "annotations": {"org.opencontainers.image.source": b.JDK_RECIPE}})
        names = ("source.py", "manifest.json", "config.json", "Dockerfile")
        for name, data in zip(names, (source, manifest, config, recipe)):
            (inputs / name).write_bytes(data)
        payloads = {"maven.tar.gz": archive() if archive_data is None else archive_data,
                    "maven.tar.gz.asc": b"synthetic detached signature\n",
                    "maven-KEYS.txt": b"synthetic public-key bundle\n"}
        calls = []
        def download(root, activity):
            calls.append("download")
            if download_error:
                raise download_error
            for name, data in payloads.items():
                b.write_new(root / name, data)
        def signature(root, activity):
            calls.append("signature")
            if signature_error:
                raise signature_error
            if unreaped:
                activity["children_stopped"] = False
                raise b.MaterialError("children_cleanup_failed")
        def remove(root, expected):
            calls.append("cleanup")
            if cleanup_error:
                raise OSError("PRIVATE_CLEANUP_CANARY")
            info = root.lstat()
            self.assertEqual((info.st_dev, info.st_ino), expected)
            shutil.rmtree(root)
        verifier = SimpleNamespace(hosted_guard=mock.Mock(), download_inputs=download,
                                   verify_hashes=mock.Mock(), signature_check=signature, remove_owned=remove)
        saved_mkdtemp = tempfile.mkdtemp
        with contextlib.ExitStack() as patches:
            for key, value in {
                "VERIFIER_SHA256": hashlib.sha256(source).hexdigest(),
                "ARCHIVE_SHA256": hashlib.sha256(payloads["maven.tar.gz"]).hexdigest(),
                "ARCHIVE_SHA512": hashlib.sha512(payloads["maven.tar.gz"]).hexdigest(),
                "ARCHIVE_BYTES": len(payloads["maven.tar.gz"]),
                "SIGNATURE_SHA256": hashlib.sha256(payloads["maven.tar.gz.asc"]).hexdigest(),
                "KEYS_SHA256": hashlib.sha256(payloads["maven-KEYS.txt"]).hexdigest(),
                "JDK_MANIFEST_SHA256": hashlib.sha256(manifest).hexdigest(),
                "JDK_CONFIG_SHA256": config_hash,
                "JDK_SOURCE_SHA256": hashlib.sha256(recipe).hexdigest(),
            }.items():
                patches.enter_context(mock.patch.object(b, key, value))
            patches.enter_context(mock.patch.object(b, "load_verifier", return_value=verifier))
            patches.enter_context(mock.patch.object(b.os, "getuid", return_value=self.root.lstat().st_uid, create=True))
            patches.enter_context(mock.patch.object(b.stat, "S_IMODE", return_value=0o700))
            patches.enter_context(mock.patch.object(b.tempfile, "mkdtemp",
                                                    side_effect=lambda prefix, dir: saved_mkdtemp(prefix=prefix, dir=self.root)))
            lease = b.BootstrapLease(*(inputs / name for name in names))
            yield lease, calls, verifier

    def test_success_lease_exposes_current_bytes_only_until_exit(self):
        with self.scenario() as (lease, calls, verifier):
            with lease as current:
                self.assertIs(current, lease)
                root = lease.root
                self.assertFalse(lease.report["success"])
                for field in ("material", "verification", "layout"):
                    self.assertIsNone(lease.report[field])
                self.assertTrue((root / "maven.tar.gz").is_file())
                value = lease.material
                self.assertEqual(set(value), b.MATERIAL_KEYS)
                self.assertEqual(value["schema_version"], 2)
                self.assertIn("publisher_keys_sha256", value)
                self.assertNotIn("publisher_key_sha256", value)
                self.assertTrue(value["jdk_image"].startswith("docker.io/library/eclipse-temurin@sha256:"))
                self.assertEqual(value["publisher_fingerprint"], "84789D24DF77A32433CE1F079EB80E92EB2135B1")
                self.assertEqual(b.validate_material(value, root), value)
                value["signature_verified"] = False
                self.assertTrue(lease.material["signature_verified"])
            self.assertEqual(calls, ["download", "signature", "cleanup"])
            self.assertTrue(lease.report["success"])
            self.assertEqual(lease.report["checks"], {"checksums_verified": True, "signature_verified": True,
                                                     "layout_inspected": True})
            self.assertIsNone(lease.report["layout_diagnostic"])
            self.assertEqual(lease.report["adapter_source_sha256"], hashlib.sha256(Path(b.__file__).read_bytes()).hexdigest())
            self.assertFalse(root.exists())
            self.assertFalse(lease.report["ledger_eligible"])
            self.error("material_invalid", lambda: lease.material)
            self.error("lease_reused", lease.__enter__)

    def test_full_mode_repeated_directory_layout_revalidates_through_lease(self):
        entries = [(ROOT_NAME + "/", tarfile.DIRTYPE, b"", 0o755),
                   (ROOT_NAME + "/bin/", tarfile.DIRTYPE, b"", 0o755),
                   (ROOT_NAME + "/bin/mvn", tarfile.REGTYPE, SCRIPT, 0o755),
                   (ROOT_NAME + "/bin/", tarfile.DIRTYPE, b"", 0o755)]
        data = archive(entries)
        for index, mode in ((1, 0o40755), (2, 0o40755), (3, 0o100755), (4, 0o40755)):
            data = patch_header(data, index, {100: f"{mode:07o}\0".encode("ascii")})
        with self.scenario(archive_data=data) as (lease, _, _):
            with lease:
                self.assertEqual(b.validate_material(lease.material, lease.root), lease.material)
                self.assertIsNone(lease.report["layout"])
            self.assertTrue(lease.report["success"])
            self.assertEqual((lease.report["layout"]["members"], lease.report["layout"]["repeated_directories"]), (4, 1))
            self.assertIsNone(lease.report["layout_diagnostic"])
            self.assertEqual(lease.report["cleanup"], {"children_stopped": True, "temporary_removed": True})
            self.assertFalse(lease.root.exists())

    def test_pure_revalidation_does_not_call_verifier_or_network(self):
        with self.scenario() as (lease, calls, verifier), lease:
            before = list(calls)
            verifier.hosted_guard.reset_mock()
            result = b.validate_material(lease.material, lease.root)
            result["scope"] = "mutated"
            self.assertEqual(calls, before)
            verifier.hosted_guard.assert_not_called()
            self.assertEqual(lease.material["scope"], "hdfs_verified_bootstrap_material")

    def test_old_extra_typed_boolean_and_identity_substitution_reject(self):
        with self.scenario() as (lease, _, _), lease:
            original = lease.material
            mutations = [{**original, "publisher_key_sha256": "a" * 64},
                         {**original, "schema_version": 1}, {**original, "schema_version": True},
                         {**original, "jdk_major": True}, {**original, "signature_verified": 1},
                         {**original, "publisher_fingerprint": "A" * 40},
                         {**original, "jdk_image": original["jdk_image"].replace("docker.io/library/", "")},
                         {**original, "adapter_source_sha256": "a" * 64},
                         {**original, "verification_receipt_sha256": "a" * 64}]
            for index, value in enumerate(mutations):
                with self.subTest(index=index):
                    self.error("material_invalid", b.validate_material, value, lease.root)

    def test_wrong_key_bytes_and_deleted_material_cannot_revalidate(self):
        with self.scenario() as (lease, _, _):
            with self.assertRaises(b.MaterialError):
                with lease:
                    key = lease.root / "maven-KEYS.txt"
                    key.write_bytes(b"selected key substituted for bundle")
                    self.error("checksum_mismatch", b.validate_material, lease.material, lease.root)
                    key.unlink()
                    self.error("material_invalid", b.validate_material, lease.material, lease.root)
            self.assertFalse(lease.report["success"])
            self.assertFalse(lease.root.exists())

    def test_layout_semantic_substitution_rejects_even_with_new_byte_hash(self):
        with self.scenario() as (lease, _, _):
            with self.assertRaises(b.MaterialError):
                with lease:
                    path = lease.root / "maven-layout.json"
                    data = json.loads(path.read_bytes())
                    data["executed"] = True
                    path.write_bytes(b.canonical(data))
                    value = lease.material
                    value["layout_sha256"] = b.sha(path)
                    self.error("layout_invalid", b.validate_material, value, lease.root)

    def test_false_or_extra_receipt_checks_fail_despite_matching_receipt_hash(self):
        with self.scenario() as (lease, _, _):
            with self.assertRaises(b.MaterialError):
                with lease:
                    path = lease.root / "verification-receipt.json"
                    original = json.loads(path.read_bytes())
                    for field, value in (("signature_verified", False), ("signature_verified", 1), ("extra", True)):
                        changed = copy.deepcopy(original)
                        changed["checks"][field] = value
                        path.write_bytes(b.canonical(changed))
                        material = lease.material
                        material["verification_receipt_sha256"] = b.sha(path)
                        self.error("receipt_invalid", b.validate_material, material, lease.root)

    def test_stale_future_and_reversed_verification_times_fail(self):
        with self.scenario() as (lease, _, _):
            with self.assertRaises(b.MaterialError):
                with lease:
                    path = lease.root / "verification-receipt.json"
                    original = json.loads(path.read_bytes())
                    for hours in (-3, 1):
                        stamp = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=hours)).isoformat(timespec="microseconds").replace("+00:00", "Z")
                        changed = {**original, "started_utc": stamp, "finished_utc": stamp}
                        path.write_bytes(b.canonical(changed))
                        material = lease.material
                        material["verification_receipt_sha256"] = b.sha(path)
                        self.error("receipt_invalid", b.validate_material, material, lease.root)

    def test_jdk_metadata_mutation_rejects_before_any_download(self):
        with self.scenario() as (lease, calls, _):
            lease.paths[2].write_text('{"os":"windows"}', encoding="ascii")
            self.error("jdk_metadata_invalid", lease.__enter__)
            self.assertEqual(calls, ["cleanup"])
            self.assertFalse(lease.root.exists())

    def test_enter_failure_cleans_private_bytes_and_uses_static_code(self):
        with self.scenario(signature_error=RuntimeError("PRIVATE_GPG_NAME_PATH_CANARY")) as (lease, calls, _):
            self.error("lease_failed", lease.__enter__)
            self.assertEqual(calls, ["download", "signature", "cleanup"])
            self.assertFalse(lease.root.exists())
            self.assertNotIn("CANARY", json.dumps(lease.report))
            self.assertEqual(lease.report["checks"], {"checksums_verified": True, "signature_verified": False,
                                                     "layout_inspected": False})

    def test_duplicate_failure_retains_verified_stages_but_no_material_and_cli_stays_private(self):
        name, payload = ROOT_NAME + "/PRIVATE_NAME_CANARY", b"PRIVATE_PAYLOAD_CANARY"
        data = archive([(name, tarfile.REGTYPE, payload, 0o644), (name, tarfile.REGTYPE, payload, 0o600)])
        with self.scenario(archive_data=data) as (lease, calls, _), mock.patch.object(b, "BootstrapLease", return_value=lease):
            report_path = self.root / "public.json"
            args = ["--verifier", str(lease.paths[0]), "--jdk-manifest", str(lease.paths[1]),
                    "--jdk-config", str(lease.paths[2]), "--jdk-source", str(lease.paths[3]), "--report", str(report_path)]
            self.assertEqual(b.main(args), 1)
            result = json.loads(report_path.read_bytes())
            self.assertEqual(set(result), {"schema_version", "scope", "ledger_eligible", "started_utc", "finished_utc",
                "duration_seconds", "material", "verification", "layout", "adapter_source_sha256", "layout_diagnostic",
                "checks", "success", "errors", "cleanup"})
            self.assertEqual(calls, ["download", "signature", "cleanup"])
            self.assertFalse(lease.root.exists())
            self.assertEqual(result["errors"], ["layout_duplicate"])
            self.assertFalse(result["success"])
            self.assertFalse(result["ledger_eligible"])
            self.assertEqual(result["cleanup"], {"children_stopped": True, "temporary_removed": True})
            self.assertEqual(result["checks"], {"checksums_verified": True, "signature_verified": True,
                                              "layout_inspected": False})
            self.assertEqual(result["adapter_source_sha256"], hashlib.sha256(Path(b.__file__).read_bytes()).hexdigest())
            for field in ("material", "verification", "layout"):
                self.assertIsNone(result[field])
            self.assertTrue(result["layout_diagnostic"]["same_content"])
            self.assertFalse(result["layout_diagnostic"]["same_mode"])
            for canary in ("PRIVATE", ROOT_NAME, str(self.root)):
                self.assertNotIn(canary, report_path.read_text())
            changed = lease.report
            changed["layout_diagnostic"]["new"]["size"] = 99
            self.assertEqual(lease.report["layout_diagnostic"]["new"]["size"], len(payload))
            self.error("material_invalid", lambda: lease.material)

    def test_invalid_diagnostic_cannot_escape_record_allowlist(self):
        lease = b.BootstrapLease(*(self.root / name for name in ("a", "b", "c", "d")))
        lease._record(SimpleNamespace(code="layout_duplicate", diagnostic={"path": "PRIVATE_CANARY"}))
        self.assertEqual(lease.report["errors"], ["layout_duplicate"])
        self.assertIsNone(lease.report["layout_diagnostic"])
        self.assertNotIn("PRIVATE_CANARY", json.dumps(lease.report))

    def test_early_failure_binds_adapter_but_claims_no_completed_stage(self):
        with self.scenario(download_error=b.MaterialError("download_timeout")) as (lease, _, _):
            self.error("download_timeout", lease.__enter__)
            self.assertEqual(lease.report["checks"], {"checksums_verified": False, "signature_verified": False,
                                                     "layout_inspected": False})
            self.assertEqual(lease.report["adapter_source_sha256"], hashlib.sha256(Path(b.__file__).read_bytes()).hexdigest())

    def test_unreaped_child_prevents_directory_deletion_and_success(self):
        with self.scenario(unreaped=True) as (lease, calls, _):
            self.error("children_cleanup_failed", lease.__enter__)
            self.assertNotIn("cleanup", calls)
            self.assertTrue(lease.root.exists())
            self.assertFalse(lease.report["success"])
            self.assertFalse(lease.report["cleanup"]["temporary_removed"])

    def test_primary_and_cleanup_failures_both_survive(self):
        with self.scenario(download_error=b.MaterialError("download_timeout"), cleanup_error=True) as (lease, _, _):
            self.error("download_timeout", lease.__enter__)
            self.assertEqual(lease.report["errors"], ["download_timeout", "temporary_cleanup_failed"])
            self.assertFalse(lease.report["success"])

    def test_successful_body_cannot_hide_cleanup_failure(self):
        with self.scenario(cleanup_error=True) as (lease, _, _):
            with self.assertRaisesRegex(b.MaterialError, "temporary_cleanup_failed"):
                with lease:
                    pass
            self.assertFalse(lease.report["success"])
            self.assertTrue(all(lease.report["checks"].values()))
            for field in ("material", "verification", "layout"):
                self.assertIsNone(lease.report[field])

    def test_consumer_exception_is_not_published_and_still_cleans(self):
        with self.scenario() as (lease, _, _):
            with self.assertRaisesRegex(RuntimeError, "PRIVATE_CONSUMER_CANARY"):
                with lease:
                    raise RuntimeError("PRIVATE_CONSUMER_CANARY")
            self.assertEqual(lease.report["errors"], ["consumer_failed"])
            self.assertFalse(lease.report["success"])
            self.assertFalse(lease.root.exists())
            self.assertNotIn("CANARY", json.dumps(lease.report))

    def test_cli_reports_only_after_cleanup_and_refuses_overwrite(self):
        with self.scenario() as (lease, _, _), mock.patch.object(b, "BootstrapLease", return_value=lease):
            report = self.root / "inspection.json"
            args = ["--verifier", str(lease.paths[0]), "--jdk-manifest", str(lease.paths[1]),
                    "--jdk-config", str(lease.paths[2]), "--jdk-source", str(lease.paths[3]), "--report", str(report)]
            self.assertEqual(b.main(args), 0)
            self.assertTrue(json.loads(report.read_bytes())["success"])
            self.assertFalse(lease.root.exists())
            before = report.read_bytes()
            with mock.patch.object(sys, "stderr", io.StringIO()) as errors:
                self.assertEqual(b.main(args), 1)
                self.assertEqual(errors.getvalue(), "report_create_failed\n")
            self.assertEqual(report.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
