"""Online-only dependency refresh contracts; no native tools or network."""
import copy
import hashlib
from pathlib import Path
import tempfile
import types
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch

import resolver_discovery as D
import hosted_kerberos_discovery as H
import test_resolver_discovery as F
import test_remediation_discovery as R
import test_hosted_kerberos_discovery as T

HERE = Path(__file__).resolve().parent
PROFILE = "kerberos-refresh"
UPDATES = (("com.google.guava", "guava", "33.7.2-jre"),
           ("org.xerial.snappy", "snappy-java", "1.1.10.9"))


def rows():
    return [dict(group=g, artifact=a, version=v, type="jar", classifier="", selected_runtime=True)
            for g, a, v in (*R.FAMILIES, *UPDATES)]


class RefreshTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def test_exact_pom_has_both_updates_and_preserves_existing_candidate(self):
        raw = D.candidate_inputs(HERE / "candidate-kerberos-refresh", PROFILE)
        self.assertEqual({k: hashlib.sha256(v).hexdigest() for k, v in raw.items()}, D.REFRESH_INPUT_HASHES)
        root = ET.fromstring(raw["pom.xml"]); ns = {"m": "http://maven.apache.org/POM/4.0.0"}
        for property_name, version in (("guava.version", "33.7.2-jre"), ("snappy.version", "1.1.10.9")):
            self.assertEqual(root.findtext("m:properties/m:" + property_name, namespaces=ns), version)
        managed = root.findall("m:dependencyManagement/m:dependencies/m:dependency", ns)
        for group, artifact, property_name in (("com.google.guava", "guava", "guava.version"),
                                               ("org.xerial.snappy", "snappy-java", "snappy.version")):
            matching = [x for x in managed if x.findtext("m:groupId", namespaces=ns) == group
                        and x.findtext("m:artifactId", namespaces=ns) == artifact]
            self.assertEqual(len(matching), 1)
            self.assertEqual(matching[0].findtext("m:version", namespaces=ns), "$" + "{" + property_name + "}")
        old = D.candidate_inputs(HERE / "candidate-kerberos-remediation", D.REMEDIATION_PROFILE)
        self.assertEqual(hashlib.sha256(old["pom.xml"]).hexdigest(),
                         "834df5c2b94de5b7d99ed70807c7d31c6fdbd6272a9f75672f59865da049c0e0")
        self.assertEqual(D.offline_cache.REMEDIATION_LOCK_SHA256,
                         "a0fc4edc8ea5fa9df5c26cac0be9f638650c7a657260b9da5eaad16195746e95")

    def test_candidate_bytes_and_profiles_cannot_be_crossed(self):
        candidate = HERE / "candidate-kerberos-refresh"
        for other, directory in (("hdfs", "candidate"), ("kerberos", "candidate-kerberos"),
                                  (D.REMEDIATION_PROFILE, "candidate-kerberos-remediation")):
            with self.subTest(profile=other):
                with self.assertRaises(D.DiscoveryError): D.candidate_inputs(candidate, other)
                with self.assertRaises(D.DiscoveryError): D.candidate_inputs(HERE / directory, PROFILE)
        changed = self.root / "candidate"; changed.mkdir()
        for name, raw in D.candidate_inputs(candidate, PROFILE).items(): (changed / name).write_bytes(raw)
        with (changed / "pom.xml").open("ab") as stream: stream.write(b"\n")
        with self.assertRaises(D.DiscoveryError): D.candidate_inputs(changed, PROFILE)

    def test_wrong_missing_duplicate_classifier_and_unselected_updates_fail(self):
        D.validate_refresh_versions({"artifacts": rows()})
        for group, artifact, version in UPDATES:
            values = rows(); selected = next(x for x in values if (x["group"], x["artifact"]) == (group, artifact))
            remaining = [x for x in values if x is not selected]
            invalid = [remaining, [*values, dict(selected)]]
            for key, wrong in (("version", "1.0.0"), ("group", "wrong.group"), ("artifact", "wrong-artifact"),
                               ("type", "pom"), ("classifier", "unreviewed"), ("selected_runtime", False)):
                invalid.append([*remaining, dict(selected, **{key: wrong})])
            for value in invalid:
                with self.subTest(package=artifact), self.assertRaisesRegex(D.DiscoveryError, "classpath_invalid"):
                    D.validate_refresh_versions({"artifacts": value})
            D.validate_refresh_versions({"artifacts": [*values, dict(selected, version="1.0.0", selected_runtime=False)]})
        with self.assertRaises(D.DiscoveryError):
            D.validate_refresh_versions({"artifacts": rows()[-2:]})

    def test_cache_prepare_or_replay_fails_before_inputs_or_bootstrap(self):
        for kwargs in ({"cache_destination": self.root / "offline-seed.tar"},
                       {"seed_cache": self.root / "offline-seed.tar"}):
            with self.subTest(kwargs=kwargs), patch.object(D, "hosted_guard"), \
                    patch.object(D, "file_hash") as files, patch.object(D, "candidate_inputs") as inputs, \
                    patch.object(D, "validate_bootstrap") as bootstrap, \
                    patch.object(D.offline_cache, "lock_path") as lock:
                with self.assertRaisesRegex(D.DiscoveryError, "offline_cache_invalid"):
                    D.discover(None, None, None, None, candidate_profile=PROFILE, **kwargs)
                for value in (files, inputs, bootstrap, lock): value.assert_not_called()
        with self.assertRaises(D.offline_cache.CacheError): D.offline_cache.lock_path(PROFILE)

    def test_repeat_is_rejected_before_any_hosted_or_filesystem_access(self):
        with patch.object(D, "hosted_guard") as guard, patch.object(H, "candidate_binding") as binding:
            with self.assertRaisesRegex(ValueError, "mode_invalid"):
                H.run(None, None, "repeat", profile=PROFILE)
            guard.assert_not_called(); binding.assert_not_called()
        self.assertFalse(H.cache_matches(T.seed_receipt(), PROFILE))
        self.assertFalse(H.comparison_matches(T.comparison_receipt(), T.manifest(), PROFILE))

    def test_source_binding_has_no_cache_lock_and_binds_real_helpers(self):
        verifier = self.root / "verify_bootstrap.py"; verifier.write_bytes(b"synthetic verifier")
        with patch.object(H.B, "VERIFIER_SHA256", hashlib.sha256(verifier.read_bytes()).hexdigest()), \
                patch.object(D.offline_cache, "lock_path", side_effect=AssertionError("cache lock forbidden")):
            sources = H.source_bindings(verifier, PROFILE)
        self.assertFalse(any(name.startswith("artifact-lock") for name in sources))
        for name in ("resolver_discovery.py", "offline_cache.py", "hosted_kerberos_discovery.py", "graph_export.py"):
            self.assertEqual(sources[name], hashlib.sha256((HERE / name).read_bytes()).hexdigest())

    def test_fake_resolution_uses_no_cache_and_preserves_all_cleanup(self):
        archive = self.root / "inert-bootstrap.tar.gz"; archive.write_bytes(b"not executed")
        bootstrap = dict(jdk_image=F.BASE, jdk_image_id=F.BASE_ID,
                         maven_archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
                         maven_version="3.9.16", maven_archive_sha512=D.MAVEN_SHA512)
        original = F.make_tar
        def make_tar(out, mutate=None, suffix=b"", **kwargs):
            def mutate_all(entries):
                if mutate: mutate(entries)
                R.add_updated_graph(entries)
            return original(out, mutate_all, suffix, **kwargs)
        instances = []
        def factory(root):
            obj = F.FakeDocker(root, kerberos=True); instances.append(obj); return obj
        with patch.object(D, "hosted_guard"), patch.object(D, "validate_bootstrap", return_value=bootstrap), \
                patch.object(D.uuid, "uuid4", return_value=types.SimpleNamespace(hex=F.RUN)), \
                patch.object(D.stat, "S_IMODE", return_value=0o700), patch.object(F, "make_tar", side_effect=make_tar), \
                patch.object(R, "FAMILIES", (*R.FAMILIES, *UPDATES)), \
                patch.object(D.offline_cache, "lock_path", side_effect=AssertionError("cache forbidden")), \
                patch.object(D.offline_cache, "prepare_cache", side_effect=AssertionError("cache forbidden")), \
                patch.object(D.subprocess, "Popen", side_effect=AssertionError("native forbidden")):
            result = D.discover(HERE / "candidate-kerberos-refresh", bootstrap, archive, self.root,
                                runner_factory=factory, candidate_profile=PROFILE)
        self.assertTrue(result["success"], result["errors"])
        self.assertTrue(all(result["cleanup"].values()))
        self.assertIsNone(result["inputs"]["cache_lock_sha256"])
        self.assertIsNone(result["inputs"]["seed_cache"])
        self.assertIsNone(result["cache_preparation"])
        self.assertEqual(result["inputs"]["candidate_sha256"], D.REFRESH_INPUT_HASHES)
        self.assertTrue(instances and not instances[0].offline)
        for key in ("offline_reproduced", "ledger_eligible", "daemon_accepted"):
            self.assertIs(result[key], False)

    def test_workflow_is_pinned_online_only_and_existing_replay_remains(self):
        workflow_root = HERE.parents[2] / ".github/workflows"
        refresh = (workflow_root / "hdfs-refresh-discovery.yml").read_text()
        replay = (workflow_root / "hdfs-remediation-discovery.yml").read_text()
        self.assertEqual(refresh.count("--mode online"), 1)
        self.assertNotIn("--mode repeat", refresh)
        self.assertIn("--mode repeat", replay)
        for required in ("contents: read", "persist-credentials: false",
                         "ref: $" + "{{ github.event.pull_request.head.sha || github.sha }}",
                         "--candidate scripts/provider-lab/hdfs-discovery/candidate-kerberos-refresh",
                         "--profile kerberos-refresh", "if: always()", "timeout-minutes: 60"):
            self.assertIn(required, refresh)


class RefreshHostedTests(unittest.TestCase):
    setUp = T.HostedKerberosTests.setUp
    invoke = T.HostedKerberosTests.invoke

    def test_success_binds_online_sources_and_keeps_all_acceptance_false(self):
        report, root, events = self.invoke(profile=PROFILE)
        self.assertTrue(report["success"], report["errors"])
        self.assertEqual(events.count("discover"), 1)
        self.assertNotIn("offline_discover", events)
        self.assertNotIn("compare", events)
        self.assertFalse(root.exists())
        for key in H.FALSE_CLAIMS: self.assertIs(report[key], False)

    def test_old_lock_missing_lock_field_and_source_spoof_are_rejected(self):
        for key, wrong in (("cache_lock_sha256", T.LOCK_SHA), ("supervisor_sha256", "0" * 64),
                           ("cache_source_sha256", "0" * 64), ("candidate_profile", D.REMEDIATION_PROFILE)):
            value = T.discovery(profile=PROFILE); value["inputs"][key] = wrong
            with self.subTest(key=key):
                report, _, _ = self.invoke(profile=PROFILE, result=value)
                self.assertFalse(report["success"])
                self.assertIn("discovery_failed", report["errors"])
        value = T.discovery(profile=PROFILE); del value["inputs"]["cache_lock_sha256"]
        report, _, _ = self.invoke(profile=PROFILE, result=value)
        self.assertFalse(report["success"])

    def test_offline_claim_seed_or_uncertain_cleanup_cannot_pass(self):
        for mutate in (lambda x: x.update(mode="offline"), lambda x: x.update(offline_reproduced=True),
                       lambda x: x["inputs"].update(seed_cache=T.seed_receipt()),
                       lambda x: x.update(cache_preparation=T.seed_receipt()),
                       lambda x: x["cleanup"].update(container_removed=False)):
            value = T.discovery(profile=PROFILE); mutate(value)
            report, _, _ = self.invoke(profile=PROFILE, result=value)
            self.assertFalse(report["success"] or report["offline_reproduced"])

    def test_changed_candidate_and_source_stay_failed_after_cleanup(self):
        for kwargs in ({"candidate_after": {"pom.xml": "0" * 64}},
                       {"sources_after": {"resolver_discovery.py": "0" * 64}}):
            report, _, _ = self.invoke(profile=PROFILE, **kwargs)
            self.assertFalse(report["success"] or report["offline_reproduced"])


if __name__ == "__main__":
    unittest.main()
