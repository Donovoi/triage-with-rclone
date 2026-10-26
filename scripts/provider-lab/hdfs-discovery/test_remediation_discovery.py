"""Prospective graph contracts using inert archives and fake owned resources."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

import resolver_discovery as D
import hosted_kerberos_discovery as H
import test_resolver_discovery as F
import test_hosted_kerberos_discovery as T

HERE = Path(__file__).resolve().parent
PROFILE = "kerberos-remediation"
FAMILIES = (
    ("com.fasterxml.jackson.core", "jackson-core", "2.18.12"),
    ("com.fasterxml.jackson.core", "jackson-databind", "2.18.12"),
    ("io.netty", "netty-handler", "4.1.139.Final"),
    ("io.netty", "netty-buffer", "4.1.139.Final"),
    ("org.apache.commons", "commons-configuration2", "2.15.1"),
    ("commons-io", "commons-io", "2.22.0"),
    ("org.bouncycastle", "bcprov-jdk18on", "1.86"),
)


def selected_rows():
    return [dict(group=g, artifact=a, version=v, type="jar", classifier="", selected_runtime=True)
            for g, a, v in FAMILIES]


def add_updated_graph(entries):
    tree = json.loads(entries["output/runtime-tree.json"])
    text = entries["output/runtime-tree.txt"].decode().splitlines()
    text[-3] = text[-3].replace("\\- ", "+- ", 1)
    for i, (group, artifact, version) in enumerate(FAMILIES):
        base = "m2/" + group.replace(".", "/") + "/" + artifact + "/" + version + "/" + artifact + "-" + version
        entries[base + ".jar"] = b"inert synthetic dependency; not executable"
        entries[base + ".pom"] = (
            "<project><modelVersion>4.0.0</modelVersion><groupId>" + group + "</groupId><artifactId>" + artifact +
            "</artifactId><version>" + version + "</version></project>").encode()
        entries["output/runtime-classpath.txt"] += (":/work/" + base + ".jar").encode()
        tree["children"].append(dict(groupId=group, artifactId=artifact, version=version,
                                     type="jar", scope="compile", classifier="", optional="false"))
        text.append(("\\- " if i == len(FAMILIES) - 1 else "+- ") + group + ":" + artifact + ":jar:" + version + ":compile")
    entries["output/runtime-tree.json"] = json.dumps(tree).encode()
    entries["output/runtime-tree.txt"] = ("\n".join(text) + "\n").encode()


class RemediationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def test_candidate_is_exact_and_cannot_replace_either_existing_profile(self):
        candidate = HERE / "candidate-kerberos-remediation"
        actual = D.candidate_inputs(candidate, PROFILE)
        self.assertEqual({k: hashlib.sha256(v).hexdigest() for k, v in actual.items()}, D.REMEDIATION_INPUT_HASHES)
        self.assertEqual(D.KERBEROS_INPUT_HASHES["pom.xml"], "f2b4397a3e096770be70663bcb801ff942ee4d84f294b75826a4934b13e7bb28")
        self.assertEqual(D.offline_cache.KERBEROS_LOCK_SHA256, "a62e2a60bbb3f6c8b95b849760ff597e4e05e1c93bf61987c175502c3fe2ac74")
        for old_profile, old_dir in (("hdfs", "candidate"), ("kerberos", "candidate-kerberos")):
            with self.subTest(profile=old_profile):
                D.candidate_inputs(HERE / old_dir, old_profile)
                with self.assertRaises(D.DiscoveryError): D.candidate_inputs(candidate, old_profile)
                with self.assertRaises(D.DiscoveryError): D.candidate_inputs(HERE / old_dir, PROFILE)
        original = candidate / "pom.xml"
        altered = self.root / "candidate"; altered.mkdir()
        for name, data in actual.items(): (altered / name).write_bytes(data)
        (altered / original.name).write_bytes(original.read_bytes() + b"\n")
        with self.assertRaises(D.DiscoveryError): D.candidate_inputs(altered, PROFILE)

    def test_wrong_lock_fails_before_any_resource_or_bootstrap_access(self):
        for kwargs in ({"cache_destination": self.root / "offline-seed.tar"},
                       {"seed_cache": self.root / "offline-seed.tar"}):
            with self.subTest(kwargs=kwargs), patch.object(D, "hosted_guard"), \
                    patch.object(D, "file_hash", return_value=D.offline_cache.KERBEROS_LOCK_SHA256), \
                    patch.object(D, "validate_bootstrap") as bootstrap, \
                    patch.object(D, "candidate_inputs") as inputs:
                with self.assertRaisesRegex(D.DiscoveryError, "offline_cache_invalid"):
                    D.discover(None, None, None, None, candidate_profile=PROFILE, **kwargs)
                bootstrap.assert_not_called(); inputs.assert_not_called()

    def test_every_updated_family_must_be_present_and_no_old_selected_member_survives(self):
        rows = selected_rows()
        D.validate_remediation_versions({"artifacts": rows})
        for group, _, _ in FAMILIES:
            with self.subTest(missing=group), self.assertRaises(D.DiscoveryError):
                D.validate_remediation_versions({"artifacts": [r for r in rows if r["group"] != group]})
        for i in range(len(rows)):
            changed = copy.deepcopy(rows); changed[i]["version"] = "1.0.0"
            with self.subTest(stale=i), self.assertRaises(D.DiscoveryError):
                D.validate_remediation_versions({"artifacts": changed})
            stale = dict(changed[i], selected_runtime=False)
            D.validate_remediation_versions({"artifacts": [*rows, stale]})

    def test_source_binding_selects_new_lock_and_keeps_verified_tools(self):
        verifier = self.root / "verify_bootstrap.py"; verifier.write_bytes(b"synthetic verifier")
        with patch.object(H.B, "VERIFIER_SHA256", hashlib.sha256(verifier.read_bytes()).hexdigest()):
            sources = H.source_bindings(verifier, PROFILE)
            self.assertNotIn("artifact-lock-kerberos.json", sources)
            self.assertEqual(sources["artifact-lock-kerberos-remediation.json"], D.offline_cache.REMEDIATION_LOCK_SHA256)
            self.assertIn("offline_cache.py", sources)
            self.assertIn("resolver_discovery.py", sources)

    def test_mock_online_resolution_binds_new_lock_and_preserves_cleanup(self):
        archive = self.root / "inert-bootstrap.tar.gz"; archive.write_bytes(b"not executed")
        bootstrap = dict(jdk_image=F.BASE, jdk_image_id=F.BASE_ID,
                         maven_archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
                         maven_version="3.9.16", maven_archive_sha512=D.MAVEN_SHA512)
        original = F.make_tar
        def make_tar(out, mutate=None, suffix=b"", **kwargs):
            def mutate_all(entries):
                if mutate: mutate(entries)
                add_updated_graph(entries)
            return original(out, mutate_all, suffix, **kwargs)
        instances = []
        def factory(root):
            obj = F.FakeDocker(root, kerberos=True); instances.append(obj); return obj
        with patch.object(D, "hosted_guard"), patch.object(D, "validate_bootstrap", return_value=bootstrap), \
                patch.object(D.uuid, "uuid4", return_value=types.SimpleNamespace(hex=F.RUN)), \
                patch.object(D.stat, "S_IMODE", return_value=0o700), patch.object(F, "make_tar", side_effect=make_tar), \
                patch.object(D.offline_cache, "prepare_cache", side_effect=AssertionError("cache forbidden")), \
                patch.object(D.subprocess, "Popen", side_effect=AssertionError("native forbidden")):
            result = D.discover(HERE / "candidate-kerberos-remediation", bootstrap, archive, self.root,
                                runner_factory=factory, candidate_profile=PROFILE)
        self.assertTrue(result["success"], result["errors"])
        self.assertTrue(all(result["cleanup"].values()))
        self.assertEqual(result["inputs"]["cache_lock_sha256"], D.offline_cache.REMEDIATION_LOCK_SHA256)
        self.assertIsNone(result["inputs"]["seed_cache"])
        self.assertIsNone(result["cache_preparation"])
        for key in ("offline_reproduced", "ledger_eligible", "daemon_accepted"):
            self.assertIs(result[key], False)
        self.assertTrue(instances and not instances[0].offline)


class HostedRemediationTests(unittest.TestCase):
    setUp = T.HostedKerberosTests.setUp
    invoke = T.HostedKerberosTests.invoke

    def test_mock_online_flow_binds_sources_and_awards_no_acceptance(self):
        report, root, events = self.invoke(profile=PROFILE)
        self.assertTrue(report["success"], report["errors"])
        self.assertEqual(events.count("discover"), 1)
        self.assertNotIn("offline_discover", events)
        self.assertFalse(root.exists())
        self.assertEqual(report["candidate_profile"], PROFILE)
        for key in H.FALSE_CLAIMS: self.assertIs(report[key], False)

    def test_stale_graph_lock_and_same_wrong_source_binding_are_rejected(self):
        for key, value in (("cache_lock_sha256", D.offline_cache.KERBEROS_LOCK_SHA256),
                           ("supervisor_sha256", "9" * 64), ("candidate_profile", "kerberos")):
            result = T.discovery(profile=PROFILE)
            result["inputs"][key] = value
            with self.subTest(key=key):
                report, _, _ = self.invoke(profile=PROFILE, result=result)
                self.assertFalse(report["success"])
                self.assertIn("discovery_failed", report["errors"])

    def test_uncertain_cleanup_and_changed_inputs_never_pass(self):
        report, root, _ = self.invoke(profile=PROFILE, failure=RuntimeError("PRIVATE_SYNTHETIC_CANARY"))
        self.assertFalse(report["success"]); self.assertTrue(root.exists())
        report, _, _ = self.invoke(profile=PROFILE, candidate_after={"pom.xml": "9" * 64})
        self.assertFalse(report["success"]); self.assertIn("candidate_changed", report["errors"])


class CommonsIoLinkageCorrectionTests(unittest.TestCase):
    def test_exact_declared_io_override_and_candidate_hash(self):
        import xml.etree.ElementTree as ET
        candidate = HERE / "candidate-kerberos-remediation"
        raw = (candidate / "pom.xml").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), D.REMEDIATION_INPUT_HASHES["pom.xml"])
        root = ET.fromstring(raw); ns = {"m": "http://maven.apache.org/POM/4.0.0"}
        self.assertEqual(root.findtext("m:properties/m:commons.io.version", namespaces=ns), "2.22.0")
        deps = [node for node in root.findall("m:dependencyManagement/m:dependencies/m:dependency", ns)
                if node.findtext("m:groupId", namespaces=ns) == "commons-io"
                and node.findtext("m:artifactId", namespaces=ns) == "commons-io"]
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0].findtext("m:version", namespaces=ns), "${commons.io.version}")

    def test_missing_old_mixed_and_spoofed_selected_io_are_rejected(self):
        rows = selected_rows(); good = next(r for r in rows if r["group"] == "commons-io")
        without = [r for r in rows if r is not good]
        cases = [without, [*without, dict(good, version="2.16.1")],
                 [*rows, dict(good, version="2.16.1")],
                 [*without, dict(good, group="org.apache.commons")],
                 [*without, dict(good, artifact="commons-io-private")],
                 [*without, dict(good, selected_runtime=False)]]
        for changed in cases:
            with self.subTest(rows=changed), self.assertRaisesRegex(D.DiscoveryError, "classpath_invalid"):
                D.validate_remediation_versions({"artifacts": changed})
        D.validate_remediation_versions({"artifacts": [*rows, dict(good, version="2.16.1", selected_runtime=False)]})

    def test_corrected_lock_rejects_a_stale_selected_io_row(self):
        lock = json.loads(D.offline_cache.lock_path(PROFILE).read_bytes())
        selected = [row for row in lock["artifacts"] if row["selected_runtime"] is True
                    and (row["group"], row["artifact"]) == ("commons-io", "commons-io")]
        self.assertEqual([row["version"] for row in selected], ["2.22.0"])
        D.validate_remediation_versions(lock)
        stale = copy.deepcopy(lock)
        row = next(row for row in stale["artifacts"] if row["selected_runtime"] is True
                   and (row["group"], row["artifact"]) == ("commons-io", "commons-io"))
        row["version"] = "2.16.1"
        with self.assertRaisesRegex(D.DiscoveryError, "classpath_invalid"):
            D.validate_remediation_versions(stale)
        self.assertTrue(lock["claims"] and all(value is False for value in lock["claims"].values()))

    def test_repeat_workflow_requires_new_lock_and_exact_source(self):
        workflow = (HERE.parents[2] / ".github/workflows/hdfs-remediation-discovery.yml").read_text()
        self.assertEqual(workflow.count("--mode repeat"), 1)
        self.assertNotIn("--mode online", workflow)
        for required in ("workflow_dispatch:", "pull_request:", "contents: read", "persist-credentials: false",
                         "ref: ${{ github.event.pull_request.head.sha || github.sha }}", "--profile kerberos-remediation",
                         "--candidate scripts/provider-lab/hdfs-discovery/candidate-kerberos-remediation",
                         "reviewed Commons IO correction", "fresh", "if: always()"):
            self.assertIn(required, workflow)


if __name__ == "__main__":
    unittest.main()
