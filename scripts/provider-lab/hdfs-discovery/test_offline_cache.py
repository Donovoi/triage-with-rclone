"""Synthetic tar/data tests only; no network or artifact execution."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).with_name("offline_cache.py")
m = types.ModuleType("offline_cache_tested")
m.__file__ = str(SOURCE)
sys.modules[m.__name__] = m
exec(compile(SOURCE.read_bytes(), str(SOURCE), "exec"), m.__dict__)
CANARY = b"private-person@example.invalid /private/cache?secret=do-not-export"


def sample():
    rows, payloads = [], {}
    for artifact, kind, data in (("alpha", "pom", b"synthetic POM A"),
                                 ("alpha", "jar", b"synthetic JAR A"),
                                 ("beta", "pom", b"synthetic POM B")):
        row = {"group": "org.example", "artifact": artifact, "version": "1.2.3",
               "classifier": "", "type": kind, "size": len(data), "sha256": m.sha(data),
               "selected_runtime": kind == "jar", "origin": "unverified_private_cache"}
        rows.append(row)
        payloads[m._artifact_path(row)] = data
    return rows, payloads


def write_tar(path, entries, *, fmt=tarfile.USTAR_FORMAT):
    with tarfile.open(path, "w:", format=fmt) as stream:
        for item in entries:
            name, data = item[:2]
            overrides = item[2] if len(item) > 2 else {}
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o600
            for key, value in overrides.items():
                setattr(info, key, value)
            stream.addfile(info, io.BytesIO(data) if info.isreg() else None)


def manifest(rows):
    entries = [{k: r[k] for k in ("group", "artifact", "version", "type", "classifier", "size", "sha256")}
               for r in rows if r["selected_runtime"]]
    return {"artifacts": copy.deepcopy(rows),
            "runtime_classpath": {"schema_version": 1, "entries": entries,
                                  "normalized_sha256": m.sha(m.encoded(entries))},
            "graph_outputs": {name: {"sha256": m.sha(name.encode()), "size": 100} for name in m.GRAPH_NAMES},
            "dependency_semantics": {"complete": False, "nodes": [{"id": 1}], "omissions": []},
            "archive_inventory": {"unrelated_count": 123}, "private_archive_sha256": "a" * 64}


class OfflineCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.rows, self.payloads = sample()
        self.pinned = patch.object(m, "_load_lock", return_value=copy.deepcopy(self.rows))
        self.pinned.start(); self.addCleanup(self.pinned.stop)
        self.online = self.root / "online.tar"
        self.seed = self.root / "seed.tar"

    def assert_code(self, code, fn, *args, **kwargs):
        with self.assertRaises(m.CacheError) as found:
            fn(*args, **kwargs)
        self.assertEqual(found.exception.code, code)
        self.assertNotIn("private-person", str(found.exception))
        self.assertIn(found.exception.code, m.CODES)

    def make_source(self, extras=(), entries=None, fmt=tarfile.USTAR_FORMAT):
        write_tar(self.online, (list(self.payloads.items()) if entries is None else entries) + list(extras), fmt=fmt)

    def seed_entries(self):
        with tarfile.open(self.seed, "r:") as stream:
            return [(x.name, stream.extractfile(x).read()) for x in stream]

    def test_real_lock_exact_hash_and_all_roles(self):
        self.pinned.stop()
        rows = m._load_lock()
        self.assertEqual(m._counts(rows), {"artifacts": 605, "poms": 421,
            "selected_runtime_jars": 128, "other_jars": 56, "artifact_bytes": 95465519})
        self.assertEqual(len(m._tracking({m._artifact_path(r): r for r in rows})), 421)
        self.assertEqual(len({m._artifact_path(r) for r in rows}), 605)

    def test_lock_drift_rejected_without_echoing_bytes(self):
        self.pinned.stop()
        with patch.object(m, "_bound_bytes", return_value=(CANARY, None)):
            self.assert_code("lock_invalid", m._load_lock)

    def test_exact_seed_reconstructs_metadata_and_does_not_copy_private_auxiliary(self):
        artifact = next(iter(self.payloads))
        tracking = next(iter(m._tracking(self.payloads)))
        self.make_source([(artifact + ".sha1", CANARY), (tracking, CANARY),
                          ("output/status", CANARY), ("output/runtime-tree.json", CANARY)])
        receipt = m.prepare_cache(self.online, self.seed)
        self.assertEqual(receipt, m.verify_cache(self.seed))
        self.assertTrue(receipt["success"])
        self.assertEqual(receipt["sha256"], m.sha(self.seed.read_bytes()))
        self.assertEqual(receipt["seed_regular_files"], 8)
        self.assertEqual(receipt["sha1_files"], 3)
        self.assertEqual(receipt["repository_tracking_files"], 2)
        self.assertTrue(receipt["metadata_reconstructed"])
        self.assertFalse(receipt["original_auxiliary_copied"])
        self.assertTrue(all(receipt[key] is False for key in m.FALSE_CLAIMS))
        self.assertTrue(receipt["advisory_work_pending"])
        entries = dict(self.seed_entries())
        self.assertEqual(entries["m2/org/example/alpha/1.2.3/_remote.repositories"],
                         b"alpha-1.2.3.jar>owned-central=\nalpha-1.2.3.pom>owned-central=\n")
        for name, data in self.payloads.items():
            self.assertEqual(entries[name], data)
            self.assertEqual(entries[name + ".sha1"], hashlib.sha1(data).hexdigest().encode() + b"\n")
        self.assertNotIn(CANARY, self.seed.read_bytes())
        self.assertNotIn(str(self.root), json.dumps(receipt))

    def test_seed_is_deterministic_across_source_order_times_and_private_logs(self):
        self.make_source([( "output/status", b"one")])
        first = m.prepare_cache(self.online, self.seed)
        reversed_entries = [(name, value, {"mtime": 1234567, "uid": 10001, "uname": "synthetic"})
                            for name, value in reversed(list(self.payloads.items()))]
        self.make_source(entries=reversed_entries + [("output/status", b"different")])
        second_path = self.root / "second.tar"
        second = m.prepare_cache(self.online, second_path)
        self.assertEqual(first, second)
        self.assertEqual(self.seed.read_bytes(), second_path.read_bytes())

    def test_gnu_long_names_and_explicit_source_directories_are_supported(self):
        rows = copy.deepcopy(self.rows)
        rows[0]["group"] = "org." + "longsyntheticcomponent." * 4 + "example"
        payloads = {m._artifact_path(r): next(v for k, v in self.payloads.items() if k.endswith(r["artifact"] + "-1.2.3." + r["type"])) for r in rows}
        self.assertGreater(max(map(len, payloads)), 100)
        with patch.object(m, "_load_lock", return_value=rows):
            write_tar(self.online, [("m2", b"", {"type": tarfile.DIRTYPE})] + list(payloads.items()), fmt=tarfile.GNU_FORMAT)
            self.assertTrue(m.prepare_cache(self.online, self.seed)["success"])

    def test_missing_wrong_size_and_wrong_hash_never_create_seed(self):
        entries = list(self.payloads.items())
        variants = [("artifact_missing", entries[1:]),
                    ("artifact_mismatch", [(entries[0][0], b"x")] + entries[1:]),
                    ("artifact_mismatch", [(entries[0][0], b"x" * len(entries[0][1]))] + entries[1:])]
        for code, changed in variants:
            with self.subTest(code=code):
                self.make_source(entries=changed)
                self.assert_code(code, m.prepare_cache, self.online, self.seed)
                self.assertFalse(self.seed.exists())

    def test_duplicate_artifact_and_metadata_rejected(self):
        name = next(iter(self.payloads))
        for extras in ([(name, self.payloads[name])], [(name + ".sha1", b"a"), (name + ".sha1", b"b")]):
            self.make_source(extras)
            self.assert_code("duplicate_member", m.prepare_cache, self.online, self.seed)

    def test_alias_traversal_absolute_backslash_and_unknown_paths_rejected(self):
        for name in ("m2/../outside", "/outside", "m2//unexpected", "m2/./unexpected", "m2\\bad", "m2/a space", "m2/unknown.jar", "output/unknown.log"):
            self.make_source([(name, CANARY)])
            with self.assertRaises(m.CacheError): m.prepare_cache(self.online, self.seed)
            self.assertFalse(self.seed.exists())

    def test_links_sparse_and_pax_refused(self):
        name = next(iter(self.payloads))
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            self.make_source(entries=[(name, b"", {"type": kind, "linkname": "/private"})])
            self.assert_code("archive_invalid", m.prepare_cache, self.online, self.seed)
        self.make_source(entries=[(name, self.payloads[name], {"pax_headers": {"comment": CANARY.decode()}})], fmt=tarfile.PAX_FORMAT)
        self.assert_code("archive_invalid", m.prepare_cache, self.online, self.seed)
        sparse = tarfile.TarInfo(name); sparse.type = tarfile.GNUTYPE_SPARSE
        self.online.write_bytes(sparse.tobuf(format=tarfile.GNU_FORMAT) + b"\0" * 1024)
        self.assert_code("archive_invalid", m.prepare_cache, self.online, self.seed)

    def test_archive_limits_are_independent(self):
        self.make_source()
        for constant, value in (("MAX_MEMBERS", 2), ("MAX_FILE", 2), ("MAX_PAYLOAD", 2)):
            with patch.object(m, constant, value):
                self.assert_code("archive_limit", m.prepare_cache, self.online, self.seed)

    def test_truncated_nonzero_tail_and_invalid_header_fail(self):
        self.make_source(); original = self.online.read_bytes()
        for changed in (original[:-1], original + b"x" * 512, b"x" * 512 + original[512:], original[:512]):
            self.online.write_bytes(changed)
            with self.assertRaises(m.CacheError): m.prepare_cache(self.online, self.seed)
            self.assertFalse(self.seed.exists())

    def test_maximum_record_padding_accepted_but_excess_nonzero_and_short_tail_rejected(self):
        self.make_source([("output/status", b"x" * 6144)])
        original = self.online.read_bytes()
        with tarfile.open(self.online, "r:") as archive:
            last = archive.getmembers()[-1]
            end = last.offset_data + ((last.size + 511) // 512) * 512
        self.assertEqual(end % 10240, 9728)
        self.assertEqual(len(original) - end, 10752)
        self.assertEqual(original[end:], b"\0" * 10752)
        self.assertTrue(m.prepare_cache(self.online, self.seed)["success"])
        for tail in (b"\0" * 11264, b"\0" * 10751 + b"x", b"\0" * 512):
            self.online.write_bytes(original[:end] + tail)
            with self.subTest(tail_bytes=len(tail)):
                self.assert_code("archive_invalid", m.prepare_cache, self.online, self.root / "refused.tar")
                self.assertFalse((self.root / "refused.tar").exists())

    def test_seed_verifier_accepts_actual_maximum_padding(self):
        rows = copy.deepcopy(self.rows)
        first = rows[0]
        data = b"a" * 1537  # Adds three payload blocks to the 8,192-byte seed.
        first["size"], first["sha256"] = len(data), m.sha(data)
        payloads = dict(self.payloads); payloads[m._artifact_path(first)] = data
        self.make_source(entries=list(payloads.items()))
        with patch.object(m, "_load_lock", return_value=rows):
            prepared = m.prepare_cache(self.online, self.seed)
            with tarfile.open(self.seed, "r:") as archive:
                last = archive.getmembers()[-1]
                end = last.offset_data + ((last.size + 511) // 512) * 512
            self.assertEqual(self.seed.stat().st_size - end, 10752)
            self.assertEqual(prepared, m.verify_cache(self.seed))

    def test_existing_destination_and_same_source_destination_are_preserved(self):
        self.make_source(); self.seed.write_bytes(b"original")
        self.assert_code("destination_exists", m.prepare_cache, self.online, self.seed)
        self.assertEqual(self.seed.read_bytes(), b"original")
        before = self.online.read_bytes()
        self.assert_code("destination_exists", m.prepare_cache, self.online, self.online)
        self.assertEqual(before, self.online.read_bytes())

    def test_seed_exact_set_rejects_missing_extra_directories_and_order(self):
        self.make_source(); m.prepare_cache(self.online, self.seed); entries = self.seed_entries()
        for modified in (entries[1:], entries + [("output/status", b"raw")],
                         [("m2", b"", {"type": tarfile.DIRTYPE})] + entries, list(reversed(entries))):
            write_tar(self.seed, modified)
            with self.assertRaises(m.CacheError): m.verify_cache(self.seed)

    def test_seed_derived_metadata_and_header_fields_are_exact(self):
        self.make_source(); m.prepare_cache(self.online, self.seed); entries = self.seed_entries()
        for suffix in (".sha1", "_remote.repositories"):
            changed = [(name, b"x" * len(data) if name.endswith(suffix) else data) for name, data in entries]
            write_tar(self.seed, changed)
            self.assert_code("metadata_mismatch", m.verify_cache, self.seed)
        for field, value in (("mode", 0o644), ("mtime", 1), ("uid", 10001), ("uname", "synthetic")):
            write_tar(self.seed, [(name, data, {field: value}) for name, data in entries])
            self.assert_code("seed_mismatch", m.verify_cache, self.seed)

    def test_corrupted_artifact_in_seed_rejected(self):
        self.make_source(); m.prepare_cache(self.online, self.seed); entries = self.seed_entries()
        name = next(iter(self.payloads))
        write_tar(self.seed, [(path, b"x" * len(data) if path == name else data) for path, data in entries])
        self.assert_code("artifact_mismatch", m.verify_cache, self.seed)

    def test_source_changed_during_copy_fails_and_removes_owned_seed(self):
        self.make_source(); original = m._file_hash; calls = 0
        def altered(path):
            nonlocal calls
            if path == self.online:
                calls += 1
                if calls == 3: return "a" * 64
            return original(path)
        with patch.object(m, "_file_hash", side_effect=altered):
            self.assert_code("source_changed", m.prepare_cache, self.online, self.seed)
        self.assertFalse(self.seed.exists())

    def test_late_verification_failure_cleans_up_without_raw_error(self):
        self.make_source()
        with patch.object(m, "verify_cache", side_effect=m.CacheError("seed_mismatch")):
            self.assert_code("seed_mismatch", m.prepare_cache, self.online, self.seed)
        self.assertFalse(self.seed.exists())

    def test_fdopen_failure_cleans_empty_owned_file(self):
        self.make_source()
        with patch.object(m.os, "fdopen", side_effect=OSError(CANARY.decode())):
            self.assert_code("cache_io_failed", m.prepare_cache, self.online, self.seed)
        self.assertFalse(self.seed.exists())

    def test_cleanup_failure_retains_primary_static_code(self):
        self.make_source()
        with patch.object(m, "verify_cache", side_effect=m.CacheError("seed_mismatch")), patch.object(Path, "unlink", side_effect=OSError(CANARY.decode())):
            with self.assertRaises(m.CacheError) as found: m.prepare_cache(self.online, self.seed)
        self.assertEqual(found.exception.code, "seed_mismatch")
        self.assertTrue(found.exception.cleanup_failed)
        self.assertNotIn(CANARY.decode(), str(found.exception))

    def test_replaced_destination_is_never_accepted_or_removed(self):
        self.make_source()
        displaced = self.root / "owned-displaced.tar"
        def replace(path, *, profile="hdfs"):
            path.rename(displaced)
            path.write_bytes(b"foreign original bytes")
            return {"success": True}
        with patch.object(m, "verify_cache", side_effect=replace):
            with self.assertRaises(m.CacheError) as found: m.prepare_cache(self.online, self.seed)
        self.assertEqual(found.exception.code, "source_changed")
        self.assertTrue(found.exception.cleanup_failed)
        self.assertEqual(self.seed.read_bytes(), b"foreign original bytes")
        self.assertTrue(displaced.is_file())

    def test_hardlink_source_rejected(self):
        self.make_source(); os.link(self.online, self.root / "alias.tar")
        self.assert_code("path_invalid", m.prepare_cache, self.online, self.seed)

    def test_reparse_file_and_ancestor_refused(self):
        fake = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_file_attributes=0x400, st_nlink=1, st_size=100)
        with patch.object(Path, "lstat", return_value=fake):
            self.assert_code("path_invalid", m._regular, self.online)
            self.assert_code("path_invalid", m._path, self.online)

    def test_comparison_accepts_only_required_stable_evidence(self):
        first = manifest(self.rows); second = copy.deepcopy(first)
        second["private_archive_sha256"] = "b" * 64
        second["archive_inventory"] = {"unrelated_count": 9999}
        actual = m.compare_manifests(first, second)
        self.assertTrue(actual["success"])
        self.assertTrue(actual["artifact_runtime_graph_match"])
        self.assertFalse(actual["auxiliary_cache_identity_claimed"])
        self.assertTrue(all(actual[key] is False for key in m.FALSE_CLAIMS))
        self.assertNotIn("private_archive", json.dumps(actual))

    def test_comparison_rejects_missing_changed_typed_and_duplicate_artifacts(self):
        first = manifest(self.rows)
        for edit in (lambda x:x["artifacts"].pop(), lambda x:x["artifacts"][0].update(size=True),
                     lambda x:x["artifacts"][0].update(sha256="a" * 64),
                     lambda x:x["artifacts"].append(copy.deepcopy(x["artifacts"][0]))):
            second = copy.deepcopy(first); edit(second)
            self.assert_code("manifest_mismatch", m.compare_manifests, first, second)

    def test_comparison_rejects_runtime_order_changes_even_with_correct_hash(self):
        extra = copy.deepcopy(self.rows[1]); extra["artifact"] = "gamma"
        rows = self.rows + [extra]
        first = manifest(rows); second = copy.deepcopy(first)
        second["runtime_classpath"]["entries"].reverse()
        second["runtime_classpath"]["normalized_sha256"] = m.sha(m.encoded(second["runtime_classpath"]["entries"]))
        with patch.object(m, "_load_lock", return_value=rows):
            self.assert_code("manifest_mismatch", m.compare_manifests, first, second)

    def test_comparison_graph_topology_and_outputs_are_bound(self):
        first = manifest(self.rows)
        for edit in (lambda x:x["dependency_semantics"].update(nodes=[{"id": 2}]),
                     lambda x:x["graph_outputs"]["runtime-tree.json"].update(sha256="b" * 64),
                     lambda x:x["runtime_classpath"].update(normalized_sha256="a" * 64)):
            second = copy.deepcopy(first); edit(second)
            self.assert_code("manifest_mismatch", m.compare_manifests, first, second)
        for edit in (lambda x:x["graph_outputs"]["runtime-tree.json"].update(size=True),
                     lambda x:x["graph_outputs"].update(extra={}),
                     lambda x:x["runtime_classpath"].update(schema_version=True),
                     lambda x:x.update(dependency_semantics={})):
            second = copy.deepcopy(first); edit(second)
            self.assert_code("manifest_invalid", m.compare_manifests, first, second)

    def test_kerberos_lock_exact_hash_count_roles_and_paths(self):
        self.pinned.stop()
        rows = m._load_lock("kerberos")
        self.assertEqual(m.lock_path().name, "artifact-lock.json")
        self.assertEqual(m.lock_path("kerberos").name, "artifact-lock-kerberos.json")
        self.assertEqual(m.sha(m.lock_path("kerberos").read_bytes()),
                         "a62e2a60bbb3f6c8b95b849760ff597e4e05e1c93bf61987c175502c3fe2ac74")
        self.assertEqual(m.sha(m.encoded(rows)),
                         "a2152c3451b85c3f5e2093a4086c6b28db64e394e355401f8e4b5b93de5ad638")
        self.assertEqual(m._counts(rows), {"artifacts": 645, "poms": 447,
            "selected_runtime_jars": 142, "other_jars": 56, "artifact_bytes": 98990688})
        self.assertEqual(len(m._tracking({m._artifact_path(r): r for r in rows})), 447)
        self.assertEqual(len({m._artifact_path(r) for r in rows}), 645)
        rows[0]["size"] = 1
        self.assertNotEqual(m._load_lock("kerberos")[0]["size"], 1)

    def test_closed_profiles_reject_before_any_file_io(self):
        self.pinned.stop()
        with patch.object(m, "_bound_bytes", side_effect=AssertionError("unexpected read")), \
             patch.object(m.os, "open", side_effect=AssertionError("unexpected write")):
            for invalid in (None, True, 1, {}, [], "", "Kerberos", "hdfs/../kerberos", "other"):
                self.assert_code("profile_invalid", m.lock_path, invalid)
                self.assert_code("profile_invalid", m._load_lock, invalid)
                self.assert_code("profile_invalid", m.prepare_cache, self.online, self.seed, profile=invalid)
                self.assert_code("profile_invalid", m.verify_cache, self.seed, profile=invalid)
                self.assert_code("profile_invalid", m.compare_manifests, {}, {}, profile=invalid)

    def test_swapped_real_locks_rejected_in_both_directions(self):
        self.pinned.stop()
        for expected, wrong in (("hdfs", "kerberos"), ("kerberos", "hdfs")):
            wrong_bytes = m.lock_path(wrong).read_bytes()
            with patch.object(m, "_bound_bytes", return_value=(wrong_bytes, None)):
                self.assert_code("lock_invalid", m._load_lock, expected)

    def test_kerberos_seed_is_explicit_and_no_auth_or_execution_credit(self):
        self.make_source()
        receipt = m.prepare_cache(self.online, self.seed, profile="kerberos")
        self.assertEqual(receipt, m.verify_cache(self.seed, profile="kerberos"))
        self.assertEqual(receipt["candidate_profile"], "kerberos")
        self.assertEqual(receipt["lock_sha256"],
                         "a62e2a60bbb3f6c8b95b849760ff597e4e05e1c93bf61987c175502c3fe2ac74")
        for claim in set(m.FALSE_CLAIMS) | {"authentication_verified", "application_accepted", "vendor_accepted"}:
            self.assertIs(receipt[claim], False)
        self.assertEqual(receipt["seed_regular_files"], 8)
        self.assertEqual(dict(self.seed_entries())[next(iter(self.payloads))], next(iter(self.payloads.values())))
        self.assertNotIn("private-person", json.dumps(receipt))

    def test_default_hdfs_receipt_and_seed_remain_equivalent_to_explicit_hdfs(self):
        self.make_source()
        default = m.prepare_cache(self.online, self.seed)
        other = self.root / "explicit.tar"
        explicit = m.prepare_cache(self.online, other, profile="hdfs")
        self.assertEqual(default, explicit)
        self.assertEqual(self.seed.read_bytes(), other.read_bytes())
        self.assertEqual(default["lock_sha256"],
                         "e0c4a34dc8999bc0b53ec5d8fc5d4d5fd2b72400424b4e110d45e70f8ab780e6")
        self.assertNotIn("candidate_profile", default)
        self.assertNotIn("authentication_verified", default)

    def test_profile_seed_mismatch_rejects_before_destination_creation(self):
        original_rows = copy.deepcopy(self.rows)
        kerberos_rows = copy.deepcopy(self.rows)
        kerberos_rows[0]["version"] = "2.1.2"
        def selected(profile="hdfs"):
            return copy.deepcopy(original_rows if profile == "hdfs" else kerberos_rows)
        with patch.object(m, "_load_lock", side_effect=selected):
            self.make_source()
            m.prepare_cache(self.online, self.seed)
            wrong = self.root / "wrong.tar"
            for source in (self.online, self.seed):
                with self.assertRaises(m.CacheError):
                    m.prepare_cache(source, wrong, profile="kerberos")
                self.assertFalse(wrong.exists())
            with self.assertRaises(m.CacheError): m.verify_cache(self.seed, profile="kerberos")

    def test_real_manifest_both_wrong_profile_is_not_a_match(self):
        self.pinned.stop()
        hdfs = manifest(m._load_lock())
        kerberos = manifest(m._load_lock("kerberos"))
        for chosen, wrong in (("hdfs", kerberos), ("kerberos", hdfs)):
            self.assert_code("manifest_mismatch", m.compare_manifests, wrong, copy.deepcopy(wrong), profile=chosen)
        self.assert_code("manifest_mismatch", m.compare_manifests, hdfs, kerberos, profile="kerberos")
        match = m.compare_manifests(kerberos, copy.deepcopy(kerberos), profile="kerberos")
        self.assertEqual(match["candidate_profile"], "kerberos")
        self.assertEqual(match["counts"]["selected_runtime_jars"], 142)
        self.assertFalse(match["authentication_verified"])

    def test_explicit_manifest_profile_must_be_exact(self):
        original = manifest(self.rows)
        for value in ("hdfs", "other", None, True, 1, {}, []):
            changed = copy.deepcopy(original); changed["candidate_profile"] = value
            self.assert_code("manifest_mismatch", m.compare_manifests, changed, changed, profile="kerberos")
        original["candidate_profile"] = "kerberos"
        self.assertTrue(m.compare_manifests(original, copy.deepcopy(original), profile="kerberos")["success"])

    def test_source_and_lock_drift_before_seed_write_reject(self):
        self.make_source()
        original = m._binding("kerberos")
        for index in (0, 1, 2, 3):
            changed = list(original); changed[index] = "changed"
            with patch.object(m, "_binding", side_effect=[original, tuple(changed)]):
                self.assert_code("source_changed", m.prepare_cache, self.online, self.seed, profile="kerberos")
            self.assertFalse(self.seed.exists())

    def test_late_source_lock_drift_removes_only_owned_seed(self):
        self.make_source()
        original = m._binding("kerberos")
        changed = ("a" * 64, *original[1:])
        # prepare start/pre-write; verify start/end; prepare final recheck.
        with patch.object(m, "_binding", side_effect=[original] * 4 + [changed]):
            self.assert_code("source_changed", m.prepare_cache, self.online, self.seed, profile="kerberos")
        self.assertFalse(self.seed.exists())

    def test_verifier_and_comparator_recheck_source_and_selected_lock(self):
        self.make_source(); m.prepare_cache(self.online, self.seed, profile="kerberos")
        initial = m._binding("kerberos")
        changed = (*initial[:2], "b" * 64, initial[3])
        for fn, args in ((m.verify_cache, (self.seed,)),
                         (m.compare_manifests, (manifest(self.rows), manifest(self.rows)))):
            with patch.object(m, "_binding", side_effect=[initial, changed]):
                self.assert_code("source_changed", fn, *args, profile="kerberos")

    def test_bound_source_read_rejects_hardlinks_and_oversize(self):
        path = self.root / "source.py"; path.write_bytes(b"synthetic")
        self.assert_code("path_invalid", m._bound_bytes, path, 3)
        os.link(path, self.root / "alias.py")
        self.assert_code("path_invalid", m._bound_bytes, path, 1024)

    def test_binding_io_failure_is_finite_in_comparator_too(self):
        with patch.object(m, "_bound_bytes", side_effect=OSError(CANARY.decode())):
            self.assert_code("source_changed", m.compare_manifests,
                             manifest(self.rows), manifest(self.rows), profile="kerberos")

    def test_bound_read_compares_ctime_within_each_metadata_api(self):
        path = self.root / "source.py"; path.write_bytes(b"synthetic")
        current = path.stat()
        fields = {key: getattr(current, key) for key in
                  ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink")}
        # Windows path/fd ctime may differ while describing the same stable file.
        fd_fields = dict(fields, st_ctime_ns=fields["st_ctime_ns"] + 10000)
        with patch.object(m.os, "fstat", return_value=types.SimpleNamespace(**fd_fields)):
            self.assertEqual(m._bound_bytes(path, 1024)[0], b"synthetic")
        changed = dict(fd_fields, st_ctime_ns=fd_fields["st_ctime_ns"] + 1)
        with patch.object(m.os, "fstat", side_effect=[types.SimpleNamespace(**fd_fields),
                                                      types.SimpleNamespace(**changed)]):
            self.assert_code("source_changed", m._bound_bytes, path, 1024)


if __name__ == "__main__":
    unittest.main()
