"""Pure/fake container, loader, report and workflow gates; no native boundary."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import re
import shlex
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import test_webdav_command_protocol as T

ROOT=Path(__file__).resolve().parents[1]/"provider-lab/webdav-command"
REPO=ROOT.parents[2]
def load(name,path):
    module=types.ModuleType(name);module.__file__=str(path)
    exec(compile(path.read_bytes(),str(path),"exec"),module.__dict__);return module
S=load("supervision_under_test",ROOT/"run_container.py")
E=load("entrypoint_under_test",ROOT/"entrypoint.py")
C=T.C
REV="a"*40
IMAGE="sha256:"+"b"*64
CONTAINER="c"*64
RID="d"*32


def sources():return S.source_hashes()
def build(src=None):
    src=sources() if src is None else src
    return dict(schema_version=1,revision=REV,source_sha256={**{n:src[S.PREFIX+n] for n in S.NAMES},"rclone-version.env":src["rclone-version.env"]},runtime_sha256=C.RUNTIME_SHA,runtime_manifest_sha256=src["rclone-version.env"],python_version="3.12.15",python_sha256="f"*64)
def protocol(manifest):
    return dict(schema_version=1,scope="linux_network_none_protocol",mode="webdav_command_rc_v1",runtime=dict(version="1.75.2",platform="linux_amd64",sha256=C.RUNTIME_SHA),bindings=S.bindings_for(manifest,C),cases=[T.passed(c) for c in C.CASES],result="passed",claims=dict(C.CLAIMS))
def image(run_id=RID,source_digest=None):
    return dict(Id=IMAGE,Architecture="amd64",Os="linux",Config=dict(Labels={S.LABEL:run_id,S.KIND:"webdav-command-protocol",S.SOURCE_LABEL:source_digest or S.canonical_hash(sources())},User="10001:10001",Entrypoint=S.ENTRYPOINT,Cmd=S.COMMAND,WorkingDir="/work",Env=["LANG=C.UTF-8"]))
def container(run_id=RID,status="created"):
    h=dict(NetworkMode="none",ReadonlyRootfs=True,Privileged=False,CapDrop=["ALL"],SecurityOpt=["no-new-privileges"],CgroupnsMode="private",IpcMode="private",Init=True,Memory=536870912,NanoCpus=1000000000,PidsLimit=64,Tmpfs={"/work":S.TMPFS})
    return dict(Id=CONTAINER,Image=IMAGE,Config=image(run_id)["Config"],HostConfig=h,Mounts=[],NetworkSettings=dict(Networks={"none":{}}),State=dict(Running=False,Status=status,ExitCode=0,OOMKilled=False,Error=""))
def passed_report():
    src=sources();b=build(src)
    return dict(schema_version=1,scope="webdav_command_protocol_supervision",ledger_eligible=False,source_revision=REV,source_sha256=src,runtime=dict(version="1.75.2",sha256=C.RUNTIME_SHA),started_utc="2026-10-15T00:00:00.000000Z",finished_utc="2026-10-15T00:00:01.000000Z",stage="complete",success=True,errors=[],build=b,image_id=IMAGE,isolation_before=True,isolation_after=True,attach_exit=0,container_exit=0,container_stdout_bytes=123,container_stderr_bytes=0,oom_killed=False,start_error_present=False,protocol=protocol(b),cleanup={k:True for k in S.CLEANUP},source_runtime_preserved=True,interpreter_hash_evidence="image_build_manifest_and_in_container_file_check",build_cache_scope="shared_daemon_cache_not_pruned")


class LoaderTests(unittest.TestCase):
    def test_verified_source_load_restores_unrelated_modules(self):
        original={n:types.ModuleType("poison_"+n) for n in ("command_contract","token_helper","fixture","probe")}
        with patch.dict(sys.modules,original),patch.object(E,"PROFILE",ROOT):
            got=E.load_modules(build())
            self.assertEqual(set(got),set(original))
            for name in original:self.assertIs(sys.modules[name],original[name]);self.assertIsNot(got[name],original[name])
    def test_hash_mismatch_does_not_execute_or_leak_module(self):
        b=build();b["source_sha256"]["fixture.py"]="0"*64
        sentinel=types.ModuleType("poison_fixture")
        with patch.dict(sys.modules,{"fixture":sentinel}),patch.object(E,"PROFILE",ROOT):
            with self.assertRaises(E.Invalid):E.load_modules(b)
            self.assertIs(sys.modules["fixture"],sentinel)
    def test_build_exact_types_fields_and_binding(self):
        self.assertEqual(S.build_binding(build(),sources(),REV,E),build())
        for key,value in (("schema_version",True),("python_version","3.12.14"),("revision","x"*40),("runtime_sha256","0"*64),("python_sha256","canary")):
            b=build();b[key]=value
            with self.subTest(key=key),self.assertRaises((E.Invalid,S.SupervisorError)):S.build_binding(b,sources(),REV,E)
        b=build();b["private"]="canary"
        with self.assertRaises(E.Invalid):E.validate_build(b)
    def test_entrypoint_nonpass_and_overflow_exit_nonzero(self):
        class Output:
            def __init__(self):self.buffer=self;self.raw=b""
            def write(self,raw):self.raw+=raw
            def flush(self):pass
        output=Output()
        with patch.object(E,"verify_image",side_effect=E.Invalid),patch.object(E.sys,"stdout",output):
            self.assertEqual(E.main(),1)
        self.assertEqual(json.loads(output.raw)["error"],"entrypoint_failed")
        # No operational core call: the overflow result comes only from a fake.
        b=build();fakeP=types.SimpleNamespace(SOURCE_FILES=tuple(n+".py" for n in ("command_contract","token_helper","fixture","probe")),run_suite=lambda *_:{"result":"passed","canary":"x"*70000})
        output=Output()
        with patch.object(E,"verify_image",return_value=b),patch.object(E,"load_modules",return_value={"command_contract":C,"probe":fakeP}),patch.object(E.sys,"stdout",output):
            self.assertEqual(E.main(),1)
        self.assertEqual(json.loads(output.raw)["error"],"output_bound");self.assertNotIn(b"canary",output.raw)


class IsolationTests(unittest.TestCase):
    def test_exact_create_args_and_closed_names(self):
        args=S.create_args("triage-webdav-command-"+RID,IMAGE,RID)
        self.assertIn("none",args);self.assertNotIn("--volume",args);self.assertEqual(args[-4:],S.COMMAND)
        for name,img,rid in (("other",IMAGE,RID),("triage-webdav-command-"+RID,"latest",RID),("triage-webdav-command-"+RID,IMAGE,"x")):
            with self.assertRaises(S.SupervisorError):S.create_args(name,img,rid)
    def test_image_source_and_environment(self):
        src=S.canonical_hash(sources());self.assertEqual(S.validate_image(image(),IMAGE,RID,src),["LANG=C.UTF-8"])
        for key,val in (("User","0:0"),("Cmd",["sh"]),("Volumes",{"/other":{}}),("Env",["RCLONE_RETRIES=1"]),("Env",["A=1","A=2"])):
            value=image();value["Config"][key]=val
            with self.subTest(key=key),self.assertRaises(S.SupervisorError):S.validate_image(value,IMAGE,RID,src)
    def test_container_rejects_every_extra_resource_and_budget(self):
        S.validate_container(container(),IMAGE,RID,["LANG=C.UTF-8"])
        for key,val in (("NetworkMode","bridge"),("ReadonlyRootfs",False),("UsernsMode","host"),("PidMode","host"),("CapAdd",["SYS_ADMIN"]),("Binds",["/tmp:/work"]),("PortBindings",{"80/tcp":[]}),("Memory",True),("PidsLimit",65),("Tmpfs",{"/work":"rw"}),("Init",False)):
            value=container();value["HostConfig"][key]=val
            with self.subTest(key=key),self.assertRaises(S.SupervisorError):S.validate_container(value,IMAGE,RID,["LANG=C.UTF-8"])
    def test_fixed_cp_from_created_owned_container_and_bound(self):
        with tempfile.TemporaryDirectory(prefix="command-supervision-pure-") as tmp:
            root=Path(tmp);calls=[]
            class D:
                commands_stopped=True;pending=None
                def run(self,args,**kwargs):
                    calls.append((args,kwargs));(root/"build-manifest.json").write_bytes(C.compact(build()))
            value=S.copy_build_manifest(D(),CONTAINER,root,sources(),REV,E)
            self.assertEqual(value,build());self.assertEqual(calls[0][0],["cp",CONTAINER+":/opt/fixture/build-manifest.json",str(root/"build-manifest.json")])
            self.assertEqual(calls[0][1],dict(timeout=30,output_limit=16384))
            with self.assertRaises(S.SupervisorError):S.copy_build_manifest(D(),CONTAINER,root,sources(),REV,E)
        with tempfile.TemporaryDirectory(prefix="command-supervision-pure-") as tmp:
            class D:
                commands_stopped=False;pending={}
                def run(self,*_a,**_k):raise AssertionError("must_not_copy")
            with self.assertRaises(S.SupervisorError):S.copy_build_manifest(D(),CONTAINER,Path(tmp),sources(),REV,E)
    def test_cp_oversized_manifest_rejected(self):
        with tempfile.TemporaryDirectory(prefix="command-supervision-pure-") as tmp:
            root=Path(tmp)
            class D:
                commands_stopped=True;pending=None
                def run(self,*a,**k):(root/"build-manifest.json").write_bytes(b"x"*16385)
            with self.assertRaises(S.SupervisorError):S.copy_build_manifest(D(),CONTAINER,root,sources(),REV,E)


class ReportTests(unittest.TestCase):
    def test_pass_and_failed_native_evidence(self):
        r=passed_report();S.validate_report(r,sources(),REV,C,E)
        r.update(success=False,errors=["operation_failed"],attach_exit=1,container_exit=1)
        self.assertEqual(S.validate_report(r,sources(),REV,C,E)["container_exit"],1)
    def test_success_rejects_unknown_cleanup_exit_and_claims(self):
        for key,val in (("image_id",None),("attach_exit",None),("container_exit",1),("container_exit",True),("container_stderr_bytes",1),("oom_killed",True),("isolation_after",False),("source_runtime_preserved",False),("ledger_eligible",True),("interpreter_hash_evidence","host_independently_hashed")):
            r=passed_report();r[key]=val
            with self.subTest(key=key),self.assertRaises((S.SupervisorError,C.Rejected)):S.validate_report(r,sources(),REV,C,E)
        for key in S.CLEANUP:
            r=passed_report();r["cleanup"][key]=False
            with self.assertRaises(S.SupervisorError):S.validate_report(r,sources(),REV,C,E)
    def test_source_revision_time_unknown_keys_and_raw_rejected(self):
        for change in (lambda r:r.update(source_revision="b"*40),lambda r:r.update(raw="canary"),lambda r:r.update(errors=["canary"]),lambda r:r.update(finished_utc="2025-01-01T00:00:00.000000Z"),lambda r:r["source_sha256"].update({"unrelated":"f"*64})):
            r=passed_report();change(r)
            with self.assertRaises((S.SupervisorError,C.Rejected)):S.validate_report(r,sources(),REV,C,E)
    def test_exact_protocol_not_changed_into_outer_pass(self):
        for mutate in (lambda p:p["cases"][1]["events"].pop(),lambda p:p["cases"][1]["helpers"].pop(),lambda p:p["cases"][4]["cancellation"].update(signal_attempts=0),lambda p:p["claims"].update(vendor=True)):
            r=passed_report();mutate(r["protocol"])
            with self.assertRaises((S.SupervisorError,C.Rejected)):S.validate_report(r,sources(),REV,C,E)
    def test_entry_duplicate_truncated_wrong_build_and_failure(self):
        b=build();entry=dict(schema_version=1,stage="complete",error=None,build=b,protocol=protocol(b))
        self.assertEqual(S.validate_entry(C.compact(entry),b,C)["result"],"passed")
        for raw in (b'{"stage":1,"stage":2}',b'{',b'x'*65537,C.compact(dict(entry,error="entrypoint_failed")),C.compact(dict(entry,build=None))):
            with self.assertRaises((S.SupervisorError,C.Rejected)):S.validate_entry(raw,b,C)


class FakeDocker:
    instances=[];failure=None
    def __init__(self,root):
        self.root=root;self.pending=None;self.commands_stopped=True;self.last_stderr=b"";self.build_phase=None
        self.calls=[];self.rid=None;self.created=False;self.built=False;self.started=False;self.instances.append(self)
    def run(self,args,**kwargs):
        self.calls.append((args,kwargs))
        if args[0]=="info":return 0,C.compact(dict(OSType="linux",Architecture="amd64"))
        if args[0]=="build":
            self.rid=next(x.split("=",1)[1] for x in args if x.startswith(S.LABEL+"="));self.built=True
            Path(args[args.index("--iidfile")+1]).write_text(IMAGE);return 0,b""
        if args[0]=="create":self.created=True;return 0,CONTAINER.encode()
        if args[0]=="cp":Path(args[-1]).write_bytes(C.compact(build()));return 0,b""
        if args[0]=="start":
            self.started=True
            if self.failure=="lifetime":self.pending={};self.commands_stopped=False;raise S.SupervisorError("unverified")
            self.last_stderr=b"synthetic-private-canary" if self.failure=="stderr" else b""
            entry=dict(schema_version=1,stage="complete",error=None,build=build(),protocol=protocol(build()))
            return (1 if self.failure=="exit" else 0),C.compact(entry)
        if args[0]=="rm":self.created=False;return 0,b""
        if args[:2]==["image","rm"]:self.built=False;return 0,b""
        return 0,b""
    def inspect(self,kind,target):
        if kind=="image" and target==S.read_lock()["base_image"]:return dict(Id=S.read_lock()["base_config_digest"],Architecture="amd64",Os="linux")
        if kind=="image":return image(self.rid) if self.built else None
        return container(self.rid,"exited" if self.started else "created") if self.created else None


class TrackedSourceTests(unittest.TestCase):
    def tree(self):
        rows=[]
        for name in S.SOURCE_FILES:
            raw=(REPO/name).read_bytes()
            digest=hashlib.sha1(b"blob "+str(len(raw)).encode("ascii")+b"\0"+raw).hexdigest()
            rows.append(b"100644 blob "+digest.encode()+b"\t"+name.encode()+b"\0")
        return b"".join(rows)
    def exercise(self,tree=None,src=None,head=None,error=b""):
        calls=[]
        def fake(args,**kwargs):
            calls.append((args,kwargs))
            if "rev-parse" in args:return types.SimpleNamespace(stdout=REV.encode()+b"\n" if head is None else head,stderr=b"")
            return types.SimpleNamespace(stdout=self.tree() if tree is None else tree,stderr=error)
        with patch.object(S.subprocess,"run",fake):S.verify_tracked_sources(REV,sources() if src is None else src)
        return calls
    def test_fixed_paths_and_exact_current_blob_binding(self):
        calls=self.exercise()
        self.assertEqual(calls[1],(["git","-C",str(REPO),"ls-tree","-z","--full-tree",REV,"--",*S.SOURCE_FILES],dict(capture_output=True,timeout=10,check=True)))
        self.assertEqual(len(calls),2)
    def test_dirty_bytes_even_when_current_sha_is_supplied_are_rejected(self):
        tree=self.tree()
        match=re.search(rb" blob ([a-f0-9]{40})\t",tree)
        tree=tree[:match.start(1)]+b"0"*40+tree[match.end(1):]
        with self.assertRaises(S.SupervisorError):self.exercise(tree)
        src=sources();src[next(iter(src))]="0"*64
        with self.assertRaises(S.SupervisorError):self.exercise(src=src)
    def test_untracked_missing_foreign_duplicate_and_alias_records_rejected(self):
        rows=self.tree().split(b"\0")[:-1]
        for tree in (b"\0".join(rows[:-1])+b"\0",b"\0".join([rows[0],*rows[:-1]])+b"\0",self.tree().replace(b"100644 blob ",b"120000 blob ",1),self.tree().replace(S.SOURCE_FILES[0].encode(),b"unrelated.py",1),self.tree().replace(S.SOURCE_FILES[0].encode(),b"../escape",1),self.tree()[:-1],b"x"*4097):
            with self.subTest(tree_size=len(tree)),self.assertRaises(S.SupervisorError):self.exercise(tree)
    def test_foreign_head_stderr_and_wrong_source_set_rejected(self):
        for kwargs in (dict(head=b"b"*40+b"\n"),dict(error=b"private-canary"),dict(src={}),dict(src={**sources(),"untracked":"0"*64})):
            with self.subTest(keys=list(kwargs)),self.assertRaises(S.SupervisorError):self.exercise(**kwargs)


class OrchestrationTests(unittest.TestCase):
    def exercise(self,failure):
        FakeDocker.instances=[]
        with tempfile.TemporaryDirectory(prefix="command-integration-pure-") as tmp:
            root=Path(tmp);binary=root/"fake-rclone";binary.write_bytes(b"inert test data")
            real_digest=S.digest;real_mkdtemp=S.tempfile.mkdtemp
            def fake_digest(path):return C.RUNTIME_SHA if Path(path).name in ("fake-rclone","rclone") else real_digest(path)
            def new_owned(*,prefix):return real_mkdtemp(prefix=prefix,dir=root)
            bindings=[]
            def verify(_revision,_sources):
                bindings.append((_revision,_sources))
                if failure=="source_after" and len(bindings)==2:raise S.SupervisorError("tracked_blob_mismatch")
            with patch.object(S.sys,"platform","linux"),patch.dict(S.os.environ,{"GITHUB_ACTIONS":"true","RUNNER_ENVIRONMENT":"github-hosted"}),patch.object(S,"verify_tracked_sources",verify),patch.object(S,"runtime_identity",lambda _:dict(version="1.75.2",sha256=C.RUNTIME_SHA)),patch.object(S,"digest",fake_digest),patch.object(S,"Docker",FakeDocker),patch.object(FakeDocker,"failure",failure),patch.object(S.tempfile,"mkdtemp",new_owned):
                result=S.run(binary,root/"report.json",REV)
            self.assertEqual(len(bindings),2);self.assertEqual(bindings[0],bindings[1])
            serialized=(root/"report.json").read_bytes();self.assertNotIn(b"canary",serialized)
            self.assertEqual(json.loads(serialized),result)
            return result,FakeDocker.instances[0]
    def test_single_complete_supervision_and_independent_report(self):
        result,docker=self.exercise(None);self.assertTrue(result["success"])
        self.assertEqual(sum(a[0]=="start" for a,_ in docker.calls),1)
        self.assertEqual(next(k for a,k in docker.calls if a[0]=="start"),dict(timeout=780,allow_failure=True,output_limit=262144))
        self.assertLess(next(i for i,(a,_) in enumerate(docker.calls) if a[0]=="cp"),next(i for i,(a,_) in enumerate(docker.calls) if a[0]=="start"))
    def test_nonzero_and_stderr_cannot_pass(self):
        for failure in ("exit","stderr"):
            with self.subTest(failure=failure):
                result,_=self.exercise(failure);self.assertFalse(result["success"]);self.assertTrue(all(result["cleanup"].values()))
                self.assertEqual(result["attach_exit"],1 if failure=="exit" else 0)
    def test_unknown_docker_lifetime_blocks_every_later_docker_and_cleanup(self):
        result,docker=self.exercise("lifetime")
        self.assertFalse(result["success"]);self.assertFalse(result["cleanup"]["commands_stopped"]);self.assertFalse(result["cleanup"]["temporary_removed"])
        self.assertEqual(docker.calls[-1][0][0],"start");self.assertIsNone(result["attach_exit"])
    def test_after_cleanup_commit_source_mismatch_cannot_pass(self):
        result,_=self.exercise("source_after")
        self.assertFalse(result["success"]);self.assertFalse(result["source_runtime_preserved"])
        self.assertEqual(result["errors"],["source_or_runtime_changed"])
        self.assertTrue(all(result["cleanup"].values()))


def workflow_contract(text):
    jobs={m[1]:m[2] for m in re.finditer(r"^  ([a-z0-9-]+):\n((?:(?!^  [a-z0-9-]+:)[\s\S])*)",text.split("\njobs:\n",1)[1],re.MULTILINE)}
    job=jobs["webdav-command-experiment"]
    def need(ok):
        if not ok:raise ValueError("workflow_contract")
    need("      webdav_command_experiment:\n        description: Run one unqualified WebDAV command protocol experiment\n        required: false\n        type: boolean\n        default: false\n" in text)
    need("WEBDAV_COMMAND_EXPERIMENT: ${{ inputs.webdav_command_experiment }}" in jobs["revision"] and 'if [[ "$WEBDAV_COMMAND_EXPERIMENT" == \'true\' && -z "$EXPECTED_SHA" ]]; then' in jobs["revision"] and '"$EXPECTED_SHA" != "$ACTUAL_SHA"' in jobs["revision"])
    for line in ("    if: ${{ github.event_name == 'workflow_dispatch' && inputs.webdav_command_experiment }}","    needs: [revision, test, python-audit]","    runs-on: ubuntu-latest","    timeout-minutes: 25","          persist-credentials: false","        if: ${{ always() && steps.prepare.outcome == 'success' }}","        if: always()","          name: webdav-command-experiment","          path: ${{ runner.temp }}/webdav-command-experiment.json","          if-no-files-found: error","          retention-days: 14"):
        need(line in job)
    actions=re.findall(r"(?:uses: )([^\s]+)",job)
    need(actions==["actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1","actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97","actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"])
    commands=[]
    for m in re.finditer(r"^        run: (.*)\n((?:          .*\n)*)",job,re.MULTILINE):
        commands.append(shlex.split((m[2] if m[1]=="|" else m[1]).replace("\\\n"," ")))
    expected=["python","-B","scripts/provider-lab/webdav-command/run_container.py","--rclone","$RUNNER_TEMP/rclone-webdav-command","--report","$RUNNER_TEMP/webdav-command-experiment.json","--revision","$GITHUB_SHA"]
    need(commands==[["bash","scripts/download-rclone.sh","--linux","$RUNNER_TEMP/rclone-webdav-command"],expected,expected+["--validate-only"]])
    need(len(re.findall(r"^          path:",job,re.MULTILINE))==1 and "continue-on-error" not in job and "${{ inputs." not in job.split("    steps:\n",1)[1])
    for name,value in jobs.items():
        if name!="webdav-command-experiment":need(not re.search(r"^    needs:.*webdav-command-experiment",value,re.MULTILINE) and "webdav-command-experiment.json" not in value)


class WorkflowTests(unittest.TestCase):
    def test_default_off_exact_source_and_normalized_only(self):workflow_contract((REPO/".github/workflows/ci.yml").read_text())
    def test_bypass_foreign_artifact_raw_upload_and_retry_mutations(self):
        text=(REPO/".github/workflows/ci.yml").read_text()
        start=text.index("  webdav-command-experiment:\n");end=text.index("  gcs-oauth-lifecycle:\n",start);job=text[start:end]
        for old,new in (("inputs.webdav_command_experiment }}","true }}"),("needs: [revision, test, python-audit]","needs: revision"),("persist-credentials: false","persist-credentials: true"),("always() && steps.prepare.outcome == 'success'","success()"),("webdav-command-experiment.json","private/*.out"),("--revision \"$GITHUB_SHA\"","--revision other"),("--validate-only","--retries 1"),("timeout-minutes: 25","timeout-minutes: 90")):
            with self.subTest(old=old),self.assertRaises(ValueError):workflow_contract(text[:start]+job.replace(old,new)+text[end:])
    def test_image_has_no_install_or_extra_entrypoint(self):
        recipe=(ROOT/"Dockerfile").read_text();S.read_lock()
        self.assertNotIn(" pip ",recipe);self.assertNotIn("curl ",recipe)
        self.assertIn('ENTRYPOINT ["/usr/local/bin/python3.12"]',recipe)
        self.assertIn('CMD ["-I", "-S", "-B", "/opt/fixture/webdav-command/entrypoint.py"]',recipe)
        python=recipe.split("<<'PY'\n",1)[1].split("\nPY\n",1)[0];ast.parse(python)
