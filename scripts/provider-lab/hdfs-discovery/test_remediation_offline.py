"""Inert cache archives and fake hosted replay; no artifacts are executed."""
import copy
import itertools
import json
from unittest.mock import patch
import unittest

import hosted_kerberos_discovery as H
import resolver_discovery as D
import test_hosted_kerberos_discovery as T
import test_offline_cache as C
import test_remediation_discovery as P
import test_resolver_discovery as F

PROFILE = "kerberos-remediation"
PROFILES = ("hdfs", "kerberos", PROFILE)


class RemediationCacheTests(unittest.TestCase):
    setUp = C.OfflineCacheTests.setUp
    assert_code = C.OfflineCacheTests.assert_code
    make_source = C.OfflineCacheTests.make_source

    def test_exact_new_lock_rows_counts_and_false_claims(self):
        self.pinned.stop()
        m = C.m
        rows = m._load_lock(PROFILE)
        self.assertEqual(m.sha(m.lock_path(PROFILE).read_bytes()),
                         "a0fc4edc8ea5fa9df5c26cac0be9f638650c7a657260b9da5eaad16195746e95")
        self.assertEqual(m.sha(m.encoded(rows)),
                         "d411690d9c923494ebbc85eace1ff890d62d9e2c39b62e25749a361f122ffa46")
        self.assertEqual(m._counts(rows), dict(artifacts=641, poms=444, selected_runtime_jars=142,
                                             other_jars=55, artifact_bytes=97419881))
        self.assertEqual(len({m._artifact_path(row) for row in rows}), 641)
        lock = json.loads(m.lock_path(PROFILE).read_bytes())
        self.assertTrue(lock["advisory_work_pending"])
        self.assertTrue(lock["claims"] and all(value is False for value in lock["claims"].values()))

    def test_all_cross_profile_lock_and_real_manifest_substitutions_fail(self):
        self.pinned.stop()
        m = C.m
        for chosen, wrong in itertools.permutations(PROFILES, 2):
            with self.subTest(chosen=chosen, wrong=wrong):
                wrong_bytes = m.lock_path(wrong).read_bytes()
                with patch.object(m, "_bound_bytes", return_value=(wrong_bytes, None)):
                    self.assert_code("lock_invalid", m._load_lock, chosen)
                value = C.manifest(m._load_lock(wrong))
                self.assert_code("manifest_mismatch", m.compare_manifests, value, value, profile=chosen)
        value = C.manifest(m._load_lock(PROFILE))
        receipt = m.compare_manifests(value, copy.deepcopy(value), profile=PROFILE)
        self.assertEqual(receipt["candidate_profile"], PROFILE)
        self.assertIs(receipt["offline_reproduced"], False)

    def test_inert_seed_uses_new_profile_and_preserves_claim_boundaries(self):
        self.make_source(extras=[("output/java-version.log", C.CANARY)])
        m = C.m
        receipt = m.prepare_cache(self.online, self.seed, profile=PROFILE)
        self.assertEqual(receipt, m.verify_cache(self.seed, profile=PROFILE))
        self.assertEqual(receipt["candidate_profile"], PROFILE)
        self.assertEqual(receipt["lock_sha256"], m.REMEDIATION_LOCK_SHA256)
        self.assertNotIn(C.CANARY, self.seed.read_bytes())
        for claim in (*m.FALSE_CLAIMS, "authentication_verified", "application_accepted", "vendor_accepted"):
            self.assertIs(receipt[claim], False)

    def test_old_seed_cannot_satisfy_new_profile_or_create_destination(self):
        m = C.m
        old = copy.deepcopy(self.rows)
        new = copy.deepcopy(old)
        new[0]["version"] = "2.0.0"
        with patch.object(m, "_load_lock", side_effect=lambda profile: new if profile == PROFILE else old):
            self.make_source()
            m.prepare_cache(self.online, self.seed, profile="kerberos")
            with self.assertRaises(m.CacheError): m.verify_cache(self.seed, profile=PROFILE)
            wrong = self.root / "new-seed.tar"
            with self.assertRaises(m.CacheError): m.prepare_cache(self.online, wrong, profile=PROFILE)
            self.assertFalse(wrong.exists())

    def test_new_lock_drift_during_seed_creation_removes_owned_output(self):
        self.make_source()
        m = C.m
        before = m._binding(PROFILE)
        after = (*before[:-1], "changed_identity")
        with patch.object(m, "_binding", side_effect=[before, after]):
            self.assert_code("source_changed", m.prepare_cache, self.online, self.seed, profile=PROFILE)
        self.assertFalse(self.seed.exists())


class RemediationResolverTests(unittest.TestCase):
    setUp = F.ResolverTests.setUp

    def execute(self, *args, **kwargs):
        original = F.make_tar
        def make_tar(out, mutate=None, suffix=b"", **options):
            def updated(entries):
                if mutate: mutate(entries)
                P.add_updated_graph(entries)
            return original(out, updated, suffix, **options)
        with patch.object(F, "make_tar", side_effect=make_tar):
            return F.ResolverTests.execute(self, *args, candidate_profile=PROFILE, **kwargs)

    def test_online_seed_and_fresh_offline_context_use_only_new_profile(self):
        online, first = self.execute(prepare=True)
        self.assertTrue(online["success"], online["errors"])
        self.assertTrue(all(call.kwargs == {"profile": PROFILE} for call in self.last_cache_calls))
        with patch.object(F, "RUN", "b" * 32):
            offline, second = self.execute(offline=True)
        self.assertTrue(offline["success"], offline["errors"])
        self.assertNotEqual(first.root, second.root)
        self.assertTrue(all(call.kwargs == {"profile": PROFILE} for call in self.last_cache_calls))
        self.assertFalse(any(args[:2] == ["image", "pull"] for args, _ in second.calls))
        create = next(args for args, _ in second.calls if args[0] == "create")
        build = next(args for args, _ in second.calls if args[0] == "build")
        self.assertEqual(create[create.index("--network") + 1], "none")
        self.assertEqual(build[build.index("--network") + 1], "none")
        self.assertIn("--no-cache", build)
        self.assertNotIn("--volume", create)
        self.assertEqual(D.driver_script(offline=True).count("/bin/mvn -o -B"), 4)
        self.assertTrue(all(online["cleanup"].values()) and all(offline["cleanup"].values()))
        self.assertFalse((first.root / "context").exists() or (second.root / "context").exists())

    def test_wrong_seed_is_rejected_before_owned_native_resources(self):
        with self.assertRaisesRegex(D.DiscoveryError, "offline_cache_invalid"):
            self.execute(offline=True, verify_effect=D.offline_cache.CacheError("seed_mismatch"))
        self.assertEqual(self.last_instances, [])

    def test_context_and_late_seed_drift_fail_with_strict_cleanup(self):
        good, changed = {"sha256": "1" * 64}, {"sha256": "2" * 64}
        for index, receipts in enumerate(([good, changed, good], [good, good, changed])):
            with self.subTest(index=index), patch.object(F, "RUN", str(index + 1) * 32):
                report, docker = self.execute(offline=True, verify_effect=receipts)
                self.assertFalse(report["success"] or report["offline_reproduced"])
                self.assertTrue(all(report["cleanup"].values()))
                if index == 0: self.assertEqual(docker.calls, [])
                else: self.assertIn("source_changed", report["errors"])

    def test_offline_failure_is_never_retried_online(self):
        report, docker = self.execute("maven", offline=True)
        self.assertFalse(report["success"])
        self.assertEqual(sum(args[0] == "start" for args, _ in docker.calls), 1)
        self.assertFalse(any(args[:2] == ["image", "pull"] for args, _ in docker.calls))
        self.assertTrue(all(report["cleanup"].values()))


class RemediationHostedReplayTests(unittest.TestCase):
    setUp = T.HostedKerberosTests.setUp

    def invoke(self, **kwargs):
        return T.HostedKerberosTests.invoke(self, mode="repeat", profile=PROFILE, **kwargs)

    def test_complete_fake_replay_awards_only_reproducibility(self):
        report, root, events = self.invoke()
        self.assertTrue(report["success"] and report["offline_reproduced"])
        self.assertEqual(events.count("discover"), 1)
        self.assertEqual(events.count("offline_discover"), 1)
        self.assertEqual(events.count("compare"), 1)
        self.assertFalse(root.exists())
        for claim in H.FALSE_CLAIMS:
            if claim != "offline_reproduced": self.assertIs(report[claim], False)

    def test_same_wrong_profile_lock_or_source_in_both_stages_fails(self):
        for field, wrong in (("candidate_profile", "kerberos"),
                              ("cache_lock_sha256", D.offline_cache.KERBEROS_LOCK_SHA256),
                              ("cache_source_sha256", "0" * 64)):
            online, offline = T.discovery(prepare=True, profile=PROFILE), T.discovery(offline=True, profile=PROFILE)
            online["inputs"][field] = offline["inputs"][field] = wrong
            report, _, events = self.invoke(result=online, offline_result=offline)
            self.assertFalse(report["success"] or report["offline_reproduced"])
            self.assertNotIn("offline_discover", events)

    def test_foreign_or_malformed_cache_receipts_prevent_offline_start(self):
        changes = [lambda x: x.update(candidate_profile="kerberos"),
                   lambda x: x.update(lock_sha256=D.offline_cache.KERBEROS_LOCK_SHA256),
                   lambda x: x.update(counts=T.COUNTS), lambda x: x["counts"].update(artifacts=True),
                   lambda x: x.update(authentication_verified=True),
                   lambda x: x.update(metadata_reconstructed=False),
                   lambda x: x.update(original_auxiliary_copied=True)]
        for index, mutate in enumerate(changes):
            with self.subTest(index=index):
                online = T.discovery(prepare=True, profile=PROFILE)
                mutate(online["cache_preparation"])
                report, _, events = self.invoke(result=online)
                self.assertFalse(report["success"] or report["offline_reproduced"])
                self.assertNotIn("offline_discover", events)

    def test_wrong_comparison_or_swapped_classpath_never_qualifies(self):
        changes = [lambda x: x.update(candidate_profile="kerberos"),
                   lambda x: x.update(lock_sha256=D.offline_cache.KERBEROS_LOCK_SHA256),
                   lambda x: x.update(counts=T.COUNTS),
                   lambda x: x.update(runtime_classpath_sha256="0" * 64),
                   lambda x: x.update(dependency_semantics_sha256="0" * 64),
                   lambda x: x.update(graph_outputs_sha256="0" * 64)]
        for mutate in changes:
            receipt = T.comparison_receipt(PROFILE); mutate(receipt)
            report, _, _ = self.invoke(comparison=receipt)
            self.assertFalse(report["success"] or report["offline_reproduced"])
            self.assertIn("offline_comparison_failed", report["errors"])

    def test_each_owned_cleanup_failure_retains_raw_and_blocks_reproducibility(self):
        for key in ("container_removed", "image_removed", "context_removed"):
            offline = T.discovery(offline=True, profile=PROFILE)
            offline["cleanup"][key] = False
            report, root, _ = self.invoke(offline_result=offline)
            self.assertFalse(report["success"] or report["offline_reproduced"])
            self.assertTrue(root.exists())
            self.assertFalse(report["cleanup"]["raw_evidence_removed"])
        for kind in ("metadata", "bootstrap"):
            for failure in ("children", "temporary", "raised_exit"):
                report, root, _ = self.invoke(**{kind + "_failure": failure})
                self.assertFalse(report["success"] or report["offline_reproduced"])
                self.assertTrue(root.exists())

    def test_final_source_drift_and_private_cleanup_failure_block_reproducibility(self):
        for change in ({"sources_after": {}}, {"remove_failure": True},
                       {"candidate_after": {"pom.xml": "0" * 64}}):
            report, _, _ = self.invoke(**change)
            self.assertFalse(report["success"] or report["offline_reproduced"])


class HostedReviewedLockCountTests(unittest.TestCase):
    """Bridge actual pinned rows to wrapper predicates, independently of fake counts."""
    setUp = T.HostedKerberosTests.setUp
    invoke = T.HostedKerberosTests.invoke

    def reviewed_counts(self):
        raw = D.offline_cache.lock_path(PROFILE).read_bytes()
        self.assertEqual(D.offline_cache.sha(raw), D.offline_cache.REMEDIATION_LOCK_SHA256)
        lock = json.loads(raw); rows = lock["artifacts"]
        counts = dict(artifacts=len(rows), poms=sum(r["type"] == "pom" for r in rows),
                      selected_runtime_jars=sum(r["type"] == "jar" and r["selected_runtime"] is True for r in rows),
                      other_jars=sum(r["type"] == "jar" and r["selected_runtime"] is False for r in rows),
                      artifact_bytes=sum(r["size"] for r in rows))
        self.assertEqual(lock["counts"]["bytes"], counts["artifact_bytes"])
        self.assertEqual({k: v for k, v in counts.items() if k != "artifact_bytes"},
                         {k: v for k, v in lock["counts"].items() if k != "bytes"})
        return counts

    def test_wrapper_and_fake_seed_match_independently_counted_reviewed_rows(self):
        counts = self.reviewed_counts()
        self.assertEqual(H.REMEDIATION_COUNTS, counts)
        seed = T.seed_receipt(PROFILE)
        self.assertEqual(seed["counts"], counts)
        self.assertEqual(seed["sha1_files"], counts["artifacts"])
        self.assertEqual(seed["repository_tracking_files"], counts["poms"])
        self.assertEqual(seed["seed_regular_files"], 2 * counts["artifacts"] + counts["poms"])
        self.assertEqual(H.COUNTS, T.COUNTS)

    def test_reviewed_counts_pass_both_cache_and_comparison_predicates(self):
        counts = self.reviewed_counts()
        seed = T.seed_receipt(PROFILE); seed["counts"] = counts
        comparison = T.comparison_receipt(PROFILE); comparison["counts"] = counts
        self.assertTrue(H.cache_matches(seed, PROFILE))
        self.assertTrue(H.comparison_matches(comparison, T.manifest(), PROFILE))
        self.assertFalse(H.cache_matches(seed, "kerberos"))
        self.assertFalse(H.comparison_matches(comparison, T.manifest(), "kerberos"))

    def test_stale_full_or_individual_count_rejected_by_both_predicates(self):
        counts = self.reviewed_counts()
        stale = dict(artifacts=643, poms=445, selected_runtime_jars=142, other_jars=56,
                     artifact_bytes=97948330)
        cases = [stale, T.COUNTS]
        cases += [dict(counts, **{key: value}) for key, value in stale.items() if value != counts[key]]
        for value in cases:
            with self.subTest(counts=value):
                seed = T.seed_receipt(PROFILE); seed["counts"] = value
                comparison = T.comparison_receipt(PROFILE); comparison["counts"] = value
                self.assertFalse(H.cache_matches(seed, PROFILE))
                self.assertFalse(H.comparison_matches(comparison, T.manifest(), PROFILE))

    def test_missing_extra_and_wrong_typed_counts_are_rejected(self):
        counts = self.reviewed_counts()
        for key in counts:
            cases = [{k: v for k, v in counts.items() if k != key}, dict(counts, unexpected=0)]
            cases += [dict(counts, **{key: value}) for value in (True, float(counts[key]), str(counts[key]), None)]
            for value in cases:
                with self.subTest(key=key, counts=value):
                    seed = T.seed_receipt(PROFILE); seed["counts"] = value
                    comparison = T.comparison_receipt(PROFILE); comparison["counts"] = value
                    self.assertFalse(H.cache_matches(seed, PROFILE))
                    self.assertFalse(H.comparison_matches(comparison, T.manifest(), PROFILE))

    def test_fake_repeat_uses_actual_lock_counts_in_both_stages_and_comparison(self):
        counts = self.reviewed_counts()
        online = T.discovery(prepare=True, profile=PROFILE)
        offline = T.discovery(offline=True, profile=PROFILE)
        online["cache_preparation"]["counts"] = counts
        offline["inputs"]["seed_cache"]["counts"] = counts
        comparison = T.comparison_receipt(PROFILE); comparison["counts"] = counts
        report, root, events = self.invoke(mode="repeat", profile=PROFILE, result=online,
                                         offline_result=offline, comparison=comparison)
        self.assertTrue(report["success"] and report["offline_reproduced"])
        self.assertLess(events.index("discover"), events.index("offline_discover"))
        self.assertEqual(events.count("offline_discover"), 1)
        self.assertFalse(root.exists())
        for claim in H.FALSE_CLAIMS:
            if claim != "offline_reproduced": self.assertIs(report[claim], False)

    def test_stale_wrapper_never_starts_offline_with_actual_lock_seed(self):
        online = T.discovery(prepare=True, profile=PROFILE)
        online["cache_preparation"]["counts"] = self.reviewed_counts()
        stale = dict(artifacts=643, poms=445, selected_runtime_jars=142, other_jars=56,
                     artifact_bytes=97948330)
        with patch.object(H, "REMEDIATION_COUNTS", stale):
            report, root, events = self.invoke(mode="repeat", profile=PROFILE, result=online)
        self.assertFalse(report["success"] or report["offline_reproduced"])
        self.assertNotIn("offline_discover", events)
        self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
