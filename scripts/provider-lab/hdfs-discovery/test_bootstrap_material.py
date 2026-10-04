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
        self.error("layout_duplicate", self.layout, archive(entries))

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
    def scenario(self, *, download_error=None, signature_error=None, cleanup_error=False, unreaped=False):
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
        payloads = {"maven.tar.gz": archive(), "maven.tar.gz.asc": b"synthetic detached signature\n",
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
            self.assertFalse(root.exists())
            self.assertFalse(lease.report["ledger_eligible"])
            self.error("material_invalid", lambda: lease.material)
            self.error("lease_reused", lease.__enter__)

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
