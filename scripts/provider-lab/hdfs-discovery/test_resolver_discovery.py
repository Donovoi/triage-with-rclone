"""Pure construction and synthetic-file/mocked Docker tests; no native tools."""
from contextlib import ExitStack
import copy
from datetime import datetime
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch

import resolver_discovery as D


HERE = Path(__file__).resolve().parent
CANDIDATE = HERE / "candidate"
RUN = "1" * 32
BASE = "docker.io/library/eclipse-temurin@sha256:" + "2" * 64
BASE_ID = "sha256:" + "3" * 64
IMAGE = "sha256:" + "4" * 64
CONTAINER = "5" * 64
ROOTS = ("hadoop-common", "hadoop-hdfs-client", "hadoop-hdfs")


def graph_bytes():
    tree = {"groupId": "org.example.synthetic", "artifactId": "hdfs-normal-runtime-resolution",
            "version": "1.0.0", "type": "pom", "scope": "", "classifier": "", "optional": "false",
            "children": [{"groupId": "org.apache.hadoop", "artifactId": name, "version": "3.5.0",
                          "type": "jar", "scope": "compile", "classifier": "", "optional": "false"}
                         for name in ROOTS]}
    text = "org.example.synthetic:hdfs-normal-runtime-resolution:pom:1.0.0\n"
    text += "".join(("\\- " if index == 2 else "+- ") + "org.apache.hadoop:" + name + ":jar:3.5.0:compile\n"
                    for index, name in enumerate(ROOTS))
    return json.dumps(tree, separators=(",", ":")).encode(), text.encode()


def pom_bytes(name):
    return ('<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>'
            '<groupId>org.apache.hadoop</groupId><artifactId>' + name + '</artifactId><version>3.5.0</version>'
            '<developers><developer><name>PRIVATE_SYNTHETIC_CANARY</name></developer></developers></project>').encode()


def make_tar(path, mutate=None, suffix=b""):
    entries = {"m2/org/apache/hadoop/" + name + "/3.5.0/" + name + "-3.5.0.jar": (name + " synthetic bytes").encode() for name in ROOTS}
    classpath = ":".join("/work/" + name for name in entries).encode()
    entries.update({"m2/org/apache/hadoop/" + name + "/3.5.0/" + name + "-3.5.0.pom": pom_bytes(name) for name in ROOTS})
    tree_json, tree_text = graph_bytes()
    entries.update({"output/status": b"resolved\ncomplete\n", "output/runtime-tree.json": tree_json,
                    "output/runtime-tree.txt": tree_text, "output/runtime-classpath.txt": classpath})
    if mutate: mutate(entries)
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as stream:
        for name, data in entries.items():
            item = tarfile.TarInfo(name); item.size = len(data)
            stream.addfile(item, io.BytesIO(data))
    if suffix:
        with path.open("ab") as stream: stream.write(suffix)
    return path


def container_record(name, image, run_id, started=False):
    return {"Id": CONTAINER, "Name": "/" + name, "Image": image,
            "State": {"Status": "exited" if started else "created", "Running": False, "ExitCode": 0, "OOMKilled": False},
            "Config": {"Labels": {D.LABEL: run_id}, "User": "10001:10001", "Entrypoint": ["/usr/bin/env"],
                       "Cmd": ["-i", "HOME=/work/home", "PATH=/opt/java/openjdk/bin:/usr/bin:/bin",
                               "JAVA_HOME=/opt/java/openjdk", "MAVEN_OPTS=-Duser.home=/work/home -Djava.io.tmpdir=/work/tmp -XX:MaxRAMPercentage=50.0",
                               "LANG=C", "LC_ALL=C", "/bin/sh", "/opt/resolver/driver.sh"]},
            "Mounts": [], "HostConfig": {"NetworkMode": "bridge", "ReadonlyRootfs": True,
              "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges"], "Memory": 4294967296,
              "NanoCpus": 2000000000, "PidsLimit": 128, "Init": True, "IpcMode": "private", "CgroupnsMode": "private",
              "Tmpfs": {"/work": "rw,nosuid,nodev,noexec,size=2g,mode=0700,uid=10001,gid=10001"}}}


class FakeDocker:
    def __init__(self, root, failure=None):
        self.root, self.failure = root, failure
        self.calls, self.built, self.created, self.started = [], False, False, False
        self.exit_code = 0

    def call(self, args, **kwargs):
        self.calls.append((args, kwargs))
        out, err = self.root / ("fake-%s.out" % len(self.calls)), self.root / ("fake-%s.err" % len(self.calls))
        out.write_bytes(b""); err.write_bytes(b"")
        if args[0] == "info": out.write_bytes(b'{"OSType":"linux","Architecture":"amd64"}')
        elif args[0] == "build":
            self.built = True
            Path(args[args.index("--iidfile") + 1]).write_text(IMAGE)
            if self.failure == "build": raise D.DiscoveryError("command_failed")
        elif args[0] == "create":
            self.created = True
            if self.failure == "create": raise D.DiscoveryError("command_failed")
        elif args[0] == "start":
            self.started = True
            if self.failure == "timeout": raise D.DiscoveryError("command_timeout")
            if self.failure == "unreaped_command": raise D.DiscoveryError("command_cleanup_failed")
            if self.failure == "interrupt": raise KeyboardInterrupt
            self.exit_code = 1 if self.failure in ("maven", "maven_unknown", "maven_partial", "maven_resolved") else 0
            failed_status = b"failed\nprivate-canary-stage\n" if self.failure == "maven_unknown" else b"failed\nenforce\n"
            make_tar(out, (lambda entries: entries.update({"output/status": failed_status}))
                     if self.failure in ("maven", "maven_unknown", "maven_partial") else None)
            if self.failure == "maven_partial": out.write_bytes(out.read_bytes()[:-1])
        elif args[:2] == ["container", "rm"]:
            if self.failure == "container_cleanup": raise D.DiscoveryError("command_failed")
            self.created = False
        elif args[:2] == ["image", "rm"]:
            if self.failure == "image_cleanup": raise D.DiscoveryError("command_failed")
            self.built = False
        return D.Result(self.exit_code if args[0] == "start" else 0, out, err)

    def inspect(self, kind, identity, allow_missing=False):
        if kind == "image":
            if identity == BASE: return {"Id": BASE_ID, "Os": "linux", "Architecture": "amd64"}
            if not self.built: return None
            tags = ["hdfs-discovery:" + RUN]
            if self.failure == "foreign_tag" and self.started: tags.append("unrelated:keep")
            return {"Id": IMAGE, "RepoTags": tags, "Config": {"Labels": {D.LABEL: RUN}}}
        if not self.created: return None
        value = container_record("hdfs-discovery-" + RUN, IMAGE, RUN, self.started)
        value["State"]["ExitCode"] = self.exit_code
        if self.failure == "foreign_container" and self.started: value["Config"]["Labels"][D.LABEL] = "2" * 32
        if self.failure == "mount": value["Mounts"] = [{"Type": "bind", "Destination": "/host"}]
        return value


class ResolverTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.popen = self.stack.enter_context(patch.object(D.subprocess, "Popen", side_effect=AssertionError("native forbidden")))

    def test_candidate_is_exact_hash_bound_and_unchanged(self):
        result = D.candidate_inputs(CANDIDATE)
        self.assertEqual(set(result), {"pom.xml", "settings.xml", "global-settings.xml"})
        self.assertEqual(hashlib.sha256(result["pom.xml"]).hexdigest(), "c1234134333255ae53df8714471011c490c0cf60e66109743703fcd0abceece2")
        copied = self.root / "candidate"; copied.mkdir()
        for name, body in result.items(): (copied/name).write_bytes(body)
        (copied/"pom.xml").write_bytes(result["pom.xml"] + b" ")
        with self.assertRaisesRegex(D.DiscoveryError, "candidate_invalid"): D.candidate_inputs(copied)

    def test_old_flat_bootstrap_fails_before_any_native_access(self):
        pending = json.loads((HERE / "bootstrap.pending.json").read_text())
        with self.assertRaisesRegex(D.DiscoveryError, "bootstrap_invalid"):
            D.validate_bootstrap(pending, self.root / "absent.tar.gz")
        for field in ("schema_version", "extra"):
            changed = dict(pending); changed[field] = True
            with self.assertRaises(D.DiscoveryError): D.validate_bootstrap(changed, self.root / "absent")
        self.popen.assert_not_called()

    def test_default_platform_and_environment_guard_prevent_native(self):
        with patch.object(D.sys, "platform", "win32"), patch.dict(D.os.environ, {}, clear=True):
            with self.assertRaisesRegex(D.DiscoveryError, "hosted_linux_required"): D.hosted_guard()

    def test_declared_bootstrap_verification_cannot_override_wrong_actual_bytes(self):
        value=json.loads((HERE/"bootstrap.pending.json").read_text())
        archive=self.root/"maven.tar.gz"; archive.write_bytes(b"synthetic invalid archive")
        value.update(maven_archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
                     signature_sha256="1"*64,publisher_key_sha256="2"*64,publisher_fingerprint="A"*40,
                     signature_verified=True,jdk_image=BASE,jdk_image_id=BASE_ID,jdk_publisher_reviewed=True)
        with self.assertRaisesRegex(D.DiscoveryError,"bootstrap_invalid"):
            D.validate_bootstrap(value,archive)
        value["signature_verified"]=1
        with self.assertRaisesRegex(D.DiscoveryError,"bootstrap_invalid"):
            D.validate_bootstrap(value,archive)
        with patch.object(D.sys, "platform", "linux"), patch.dict(D.os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted", "RUNNER_OS": "Linux"}, clear=True):
            with self.assertRaisesRegex(D.DiscoveryError, "hosted_linux_required"): D.hosted_guard()

    def test_fixed_goals_do_not_compile_test_or_start_daemons(self):
        script = D.driver_script()
        self.assertEqual(script.count("timeout --signal=TERM --kill-after=3s 150s"), 4)
        self.assertIn("set -eu", script)
        self.assertIn("-B -ntp -C -nsu", script)
        self.assertIn("/bin/mvn -B -version >", script)
        self.assertNotIn("go-offline", script)
        self.assertNotIn("NameNode", script)
        self.assertNotIn("--fail-never", script)
        self.assertLess(script.index("enforcer-plugin"), script.index("dependency-plugin"))

    def test_container_has_concrete_bounds_no_mounts_or_credential_environment(self):
        args = D.container_args("hdfs-discovery-" + RUN, IMAGE, RUN)
        for flag, value in (("--network", "bridge"), ("--memory", "4g"), ("--cpus", "2"),
                            ("--pids-limit", "128"), ("--user", "10001:10001"), ("--cap-drop", "ALL")):
            self.assertEqual(args[args.index(flag)+1], value)
        for forbidden in ("--privileged", "--volume", "-v", "--mount", "--publish", "-p", "--env-file"):
            self.assertNotIn(forbidden, args)
        self.assertEqual(args[args.index(IMAGE)+1], "-i")
        for changed in ("host", "foreign", "hdfs-discovery-" + "2"*32):
            with self.assertRaises(D.DiscoveryError): D.container_args(changed, IMAGE, RUN)

    def test_effective_docker_inspection_rejects_mount_port_network_and_privilege_changes(self):
        good = container_record("hdfs-discovery-" + RUN, IMAGE, RUN)
        D.inspect_container(good, "hdfs-discovery-" + RUN, IMAGE, RUN)
        for key, value in (("NetworkMode", "host"), ("Privileged", True), ("Binds", ["/host:/host"]),
                           ("PortBindings", {"1/tcp": []}), ("PidsLimit", 999), ("Memory", 0),
                           ("CapAdd", ["SYS_ADMIN"]), ("SecurityOpt", []), ("ReadonlyRootfs", False)):
            bad=copy.deepcopy(good); bad["HostConfig"][key]=value
            with self.subTest(field=key), self.assertRaises(D.DiscoveryError): D.inspect_container(bad, "hdfs-discovery-" + RUN, IMAGE, RUN)

    def test_independent_artifact_bytes_hash_and_runtime_roots_are_quarantined(self):
        result = D.artifact_manifest(make_tar(self.root / "cache.tar"))
        self.assertEqual(len(result["artifacts"]), 6)
        for row in result["artifacts"]:
            body = (row["artifact"] + " synthetic bytes").encode() if row["type"] == "jar" else pom_bytes(row["artifact"])
            self.assertEqual(row["sha256"], hashlib.sha256(body).hexdigest())
            self.assertEqual(row["selected_runtime"], row["type"] == "jar")
        for key in ("ledger_eligible", "offline_reproduced", "daemon_accepted", "graph_semantics_reviewed", "publisher_audit_completed", "repository_policy_is_os_egress_confinement"):
            self.assertIs(result[key], False)
        self.assertEqual(result["review_status"], "quarantined")
        tree_json, tree_text = graph_bytes()
        expected_graphs = {"runtime-tree.json": tree_json, "runtime-tree.txt": tree_text,
                           "runtime-classpath.txt": ":".join("/work/m2/org/apache/hadoop/"+name+"/3.5.0/"+name+"-3.5.0.jar" for name in ROOTS).encode()}
        self.assertEqual(result["graph_outputs"], {name:{"size":len(body),"sha256":hashlib.sha256(body).hexdigest()} for name,body in expected_graphs.items()})
        self.assertIn("dependency_semantics", result)
        self.assertNotIn("PRIVATE_SYNTHETIC_CANARY", json.dumps(result))

    def test_finite_failed_stage_reader_is_diagnostic_only(self):
        for stage in ("bootstrap", "versions", "enforce", "tree_json", "tree_text", "classpath", "complete"):
            path=make_tar(self.root/"status.tar",lambda e:e.update({"output/status":("failed\n"+stage+"\n").encode()}))
            self.assertEqual(D.discovery_status(path), "maven_status_failed_"+stage)
            with self.assertRaises(D.DiscoveryError): D.artifact_manifest(path)
        self.assertEqual(D.discovery_status(make_tar(self.root/"resolved.tar")), "maven_status_resolved_complete")

    def test_unknown_forged_duplicate_or_partial_status_never_reaches_public_diagnostic(self):
        for status in (b"failed\nPRIVATE_CANARY\n", b"passed\nenforce\n", b"resolved\nenforce\n",
                       b"failed\nenforce\nprivate prose\n", b"failed\nenforce", b"failed\nenforce\r\n"):
            path=make_tar(self.root/"status.tar",lambda e:e.update({"output/status":status}))
            self.assertIsNone(D.discovery_status(path))
        path=make_tar(self.root/"duplicate-status.tar")
        with tarfile.open(path,"a") as stream:
            item=tarfile.TarInfo("output/status"); item.size=15; stream.addfile(item,io.BytesIO(b"failed\nenforce\n"))
        self.assertIsNone(D.discovery_status(path))
        for removed in (1, 512):
            path=make_tar(self.root/"partial.tar"); path.write_bytes(path.read_bytes()[:-removed])
            # Removing only optional all-zero padding may retain a complete tar.
            if removed != 512: self.assertIsNone(D.discovery_status(path))
        path = make_tar(self.root / "missing-end-record.tar")
        with tarfile.open(path, "r:") as source:
            last = max(m.offset_data + ((m.size + 511) // 512) * 512 for m in source)
        path.write_bytes(path.read_bytes()[:last + 512])
        self.assertIsNone(D.discovery_status(path))
        path=make_tar(self.root/"tail-status.tar",suffix=b"PRIVATE_CANARY")
        self.assertIsNone(D.discovery_status(path))

    def test_arbitrary_output_path_partial_status_wrong_classpath_or_tail_fails(self):
        changes = [lambda e:e.update({"../outside": b"x"}), lambda e:e.update({"output/private-token": b"secret"}),
                   lambda e:e.update({"output/status": b"failed\nenforce\n"}),
                   lambda e:e.update({"output/runtime-classpath.txt": b"/host/cache.jar"}),
                   lambda e:e.update({"output/runtime-classpath.txt": b"/work/m2/absent.jar"}),
                   lambda e:e.update({"output/runtime-tree.json": b'{"x":1,"x":2}'})]
        for index, change in enumerate(changes):
            with self.subTest(index=index), self.assertRaises(D.DiscoveryError): D.artifact_manifest(make_tar(self.root/f"bad-{index}.tar",change))
        with self.assertRaises(D.DiscoveryError): D.artifact_manifest(make_tar(self.root/"tail.tar",suffix=b"unexpected stdout"))

    def test_graph_disagreement_is_a_finite_error(self):
        path = make_tar(self.root / "disagree.tar", lambda entries: entries.update({
            "output/runtime-tree.txt": graph_bytes()[1].replace(b"hadoop-common", b"other-library", 1)}))
        with self.assertRaisesRegex(D.DiscoveryError, "artifact_semantics_tree_mismatch"):
            D.artifact_manifest(path)

    def pom_error(self):
        raw = b"<project>PRIVATE_SYNTHETIC_CANARY"
        path = make_tar(self.root / "rejected-pom.tar", lambda entries: entries.update({
            "m2/org/apache/hadoop/hadoop-common/3.5.0/hadoop-common-3.5.0.pom": raw}))
        with self.assertRaisesRegex(D.DiscoveryError, "artifact_semantics_pom_invalid") as caught:
            D.artifact_manifest(path)
        return caught.exception, raw

    def test_pom_failure_binds_only_validated_coordinate_bytes_and_finite_reason(self):
        error, raw = self.pom_error()
        self.assertEqual(error.pom_diagnostic, {
            "schema_version": 1, "scope": "hdfs_pom_rejection", "code": "pom_invalid", "reason": "xml_parse",
            "coordinate": {"group": "org.apache.hadoop", "artifact": "hadoop-common", "version": "3.5.0",
                           "classifier": "", "type": "pom"}, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        self.assertNotIn("PRIVATE_SYNTHETIC_CANARY", json.dumps(error.pom_diagnostic))
        with self.assertRaisesRegex(ValueError, "invalid_diagnostic_code"):
            D.DiscoveryError("container_failed", error.pom_diagnostic)

    def test_directory_alias_and_duplicate_are_rejected(self):
        for names in (("m2//extra",), ("m2/extra", "m2/extra/")):
            with self.subTest(names=names):
                path = make_tar(self.root / "directory-alias.tar")
                with tarfile.open(path, "a") as stream:
                    for name in names:
                        member = tarfile.TarInfo(name)
                        member.type = tarfile.DIRTYPE
                        stream.addfile(member)
                with self.assertRaises(D.DiscoveryError):
                    D.artifact_manifest(path)

    def test_link_duplicate_snapshot_test_classifier_and_unknown_cache_file_fail(self):
        for filename in ("m2/g/a/1-SNAPSHOT/a-1-SNAPSHOT.jar", "m2/g/a/1/a-1-tests.jar", "m2/g/a/1/arbitrary.json"):
            with self.subTest(filename=filename), self.assertRaises(D.DiscoveryError):
                D.artifact_manifest(make_tar(self.root/"bad.tar",lambda e:e.update({filename:b"x"})))
        path=make_tar(self.root/"link.tar")
        with tarfile.open(path,"a") as stream:
            member=tarfile.TarInfo("m2/link"); member.type=tarfile.SYMTYPE; member.linkname="/host"
            stream.addfile(member)
        with self.assertRaises(D.DiscoveryError): D.artifact_manifest(path)
        path=make_tar(self.root/"duplicate.tar")
        with tarfile.open(path,"a") as stream:
            member=tarfile.TarInfo("output/status"); member.size=2; stream.addfile(member,io.BytesIO(b"xx"))
        with self.assertRaises(D.DiscoveryError): D.artifact_manifest(path)

    def execute(self, failure=None):
        archive=self.root/"inert-bootstrap.tar.gz"; archive.write_bytes(b"not executed")
        bootstrap={"jdk_image":BASE,"jdk_image_id":BASE_ID,"maven_archive_sha256":hashlib.sha256(archive.read_bytes()).hexdigest(),
                   "maven_version":"3.9.16","maven_archive_sha512":D.MAVEN_SHA512}
        instances=[]
        def factory(root):
            obj=FakeDocker(root,failure); instances.append(obj); return obj
        with patch.object(D,"hosted_guard"), patch.object(D,"validate_bootstrap",return_value=bootstrap), \
             patch.object(D.uuid,"uuid4",return_value=types.SimpleNamespace(hex=RUN)), patch.object(D.stat,"S_IMODE",return_value=0o700):
            result=D.discover(CANDIDATE,bootstrap,archive,self.root,runner_factory=factory)
        self.popen.assert_not_called()
        return result,instances[0]

    def test_full_mock_discovery_verifies_bounds_cleans_resources_and_retains_only_private_evidence(self):
        result,docker=self.execute()
        self.assertTrue(result["success"],result["errors"])
        self.assertTrue(all(result["cleanup"].values()))
        self.assertFalse((docker.root/"context").exists())
        self.assertTrue((docker.root/"sanitized-discovery.json").is_file())
        start=next(kw for args,kw in docker.calls if args[0]=="start")
        self.assertEqual(start,{"timeout":630,"limit":1073741824,"allow_failure":True})
        build=next(args for args,kw in docker.calls if args[0]=="build")
        self.assertEqual(build[build.index("--network")+1],"none")
        self.assertFalse(result["ledger_eligible"])
        self.assertEqual(result["image_id"],IMAGE)
        self.assertEqual(set(result["inputs"]),{"supervisor_sha256","graph_export_sha256","candidate_sha256","maven","jdk","bootstrap_material"})
        self.assertEqual(result["inputs"]["graph_export_sha256"], hashlib.sha256(Path(D.graph_export.__file__).read_bytes()).hexdigest())
        self.assertEqual(result["inputs"]["supervisor_sha256"],hashlib.sha256((HERE/"resolver_discovery.py").read_bytes()).hexdigest())
        self.assertEqual(result["inputs"]["candidate_sha256"],D.INPUT_HASHES)
        self.assertEqual(result["inputs"]["jdk"],{"manifest":BASE,"config_id":BASE_ID})
        self.assertEqual(result["inputs"]["maven"],{"version":"3.9.16","archive_sha256":hashlib.sha256(b"not executed").hexdigest(),"archive_sha512":D.MAVEN_SHA512})
        self.assertLessEqual(datetime.fromisoformat(result["started_utc"]),datetime.fromisoformat(result["finished_utc"]))
        self.assertGreaterEqual(result["duration_seconds"],0)

    def test_pom_diagnostic_survives_failed_discovery_without_promoting_manifest(self):
        error, raw = self.pom_error()
        with patch.object(D, "artifact_manifest", side_effect=error):
            result, _docker = self.execute()
        self.assertFalse(result["success"])
        self.assertIsNone(result["manifest"])
        self.assertEqual(result["pom_diagnostic"], error.pom_diagnostic)
        self.assertIsNot(result["pom_diagnostic"], error.pom_diagnostic)
        self.assertEqual(result["errors"], ["artifact_semantics_pom_invalid"])
        self.assertTrue(all(result["cleanup"].values()))
        self.assertNotIn("PRIVATE_SYNTHETIC_CANARY", json.dumps(result))

    def test_malformed_pom_diagnostic_is_dropped_and_cleanup_still_runs(self):
        error, _raw = self.pom_error()
        error.pom_diagnostic["raw"] = "PRIVATE_SYNTHETIC_CANARY"
        with patch.object(D, "artifact_manifest", side_effect=error):
            result, _docker = self.execute()
        self.assertFalse(result["success"])
        self.assertIsNone(result["manifest"])
        self.assertIsNone(result["pom_diagnostic"])
        self.assertEqual(result["errors"], ["artifact_semantics_pom_invalid", "artifact_semantics_invalid"])
        self.assertTrue(all(result["cleanup"].values()))
        self.assertNotIn("PRIVATE_SYNTHETIC_CANARY", json.dumps(result))

    def test_nonzero_exit_status_diagnostic_never_promotes_inventory(self):
        for failure,extra in (("maven",["maven_status_failed_enforce"]),("maven_unknown",[]),
                              ("maven_partial",[]),("maven_resolved",["maven_status_resolved_complete"])):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                old=self.root; self.root=Path(temporary).resolve()
                try: result,docker=self.execute(failure)
                finally: self.root=old
                self.assertEqual(result["errors"],["container_failed",*extra])
                self.assertFalse(result["success"])
                self.assertIsNone(result["manifest"])
                self.assertTrue(all(result["cleanup"].values()))
                self.assertNotIn("private-canary",json.dumps(result).lower())

    def test_unreaped_command_preserves_build_context(self):
        result, docker = self.execute("unreaped_command")
        self.assertFalse(result["success"])
        self.assertFalse(result["cleanup"]["context_removed"])
        self.assertTrue((docker.root / "context").is_dir())
        self.assertIn("command_cleanup_failed", result["errors"])
        self.assertIn("context_cleanup_failed", result["errors"])

    def test_changed_exporter_source_cannot_produce_a_success(self):
        original = D.file_hash
        exporter = Path(D.graph_export.__file__).absolute()
        reads = 0
        def changed(path, *args, **kwargs):
            nonlocal reads
            if Path(path) == exporter:
                reads += 1
                if reads > 1:
                    return "0" * 64
            return original(path, *args, **kwargs)
        with patch.object(D, "file_hash", side_effect=changed):
            result, _docker = self.execute()
        self.assertFalse(result["success"])
        self.assertIn("source_changed", result["errors"])
        self.assertEqual(reads, 2)

    def test_late_cleanup_and_foreign_ownership_fail_without_removing_foreign_objects(self):
        for failure in ("container_cleanup","image_cleanup","foreign_container","foreign_tag"):
            # Fresh per-case private root; no shared image/container objects.
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                old=self.root; self.root=Path(temporary).resolve()
                try: result,docker=self.execute(failure)
                finally: self.root=old
                self.assertFalse(result["success"])
                self.assertTrue(result["errors"])
                self.assertTrue(result["cleanup"]["context_removed"])
                if failure=="foreign_container": self.assertFalse(any(args[:2]==["container","rm"] for args,_ in docker.calls))
                if failure=="foreign_tag": self.assertFalse(any(args[:2]==["image","rm"] for args,_ in docker.calls))

    def test_build_create_runtime_timeout_and_maven_failure_still_attempt_cleanup(self):
        for failure in ("build","create","timeout","maven","mount","interrupt"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                old=self.root; self.root=Path(temporary).resolve()
                try: result,docker=self.execute(failure)
                finally: self.root=old
                self.assertFalse(result["success"])
                self.assertTrue(all(result["cleanup"].values()),result["errors"])
                self.assertTrue(result["errors"])

    def test_docker_ambient_environment_is_removed_and_inspect_error_is_not_absence(self):
        with patch.dict(D.os.environ,{"AWS_SECRET_ACCESS_KEY":"private-canary","DOCKER_HOST":"tcp://unrelated","MAVEN_OPTS":"-agentlib:unexpected"}):
            docker=D.Docker(self.root)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY",docker.environment)
        self.assertNotIn("DOCKER_HOST",docker.environment)
        self.assertNotIn("MAVEN_OPTS",docker.environment)
        out=self.root/"out"; err=self.root/"err"; out.write_bytes(b"owned-id\n"); err.write_bytes(b"private")
        with patch.object(docker,"call",side_effect=[D.Result(1,out,err),D.Result(0,out,err)]) as call:
            with self.assertRaises(D.DiscoveryError): docker.inspect("container",CONTAINER,allow_missing=True)
            self.assertEqual(call.call_args_list[-1].args[0],["container","ls","--all","--no-trunc","--quiet","--filter","id="+CONTAINER])


if __name__=="__main__":
    unittest.main()
