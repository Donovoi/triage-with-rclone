"""Pure tests for source bindings, container admission and exact cleanup ownership."""
import copy
from pathlib import Path
import types
import unittest
from unittest.mock import patch
import context_container as U

RUN="a"*32
IMAGE="sha256:"+"b"*64
CID="c"*64

def inspected(kind="case",variant="patched",case="renewable"):
    if kind=="identity": variant=case=None
    suffix="identity" if kind=="identity" else variant+"-"+case
    name="hdfs-context-retained-"+RUN+"-"+suffix
    args=U.command_args(name,IMAGE,RUN,kind,variant,case)
    value=dict(Name="/"+name,Image=IMAGE,Id=CID,
        Config=dict(Labels={U.LABEL:RUN},User="10001:10001",Entrypoint=["/usr/bin/env"],Cmd=args[args.index(IMAGE)+1:],
                    Volumes=None,ExposedPorts=None,Healthcheck=None),
        HostConfig=dict(NetworkMode="none",ReadonlyRootfs=True,Privileged=False,CapDrop=["ALL"],CapAdd=None,
            Binds=None,PortBindings=None,SecurityOpt=["no-new-privileges"],Memory=2147483648,NanoCpus=2000000000,
            PidsLimit=128,Init=True,IpcMode="private",CgroupnsMode="private",Tmpfs={"/work":U.TMPFS},
            LogConfig={"Type":"none"},Devices=None,DeviceRequests=None,ExtraHosts=None,PidMode=""),
        Mounts=[],State=dict(Status="created",Running=False,OOMKilled=False,ExitCode=0))
    return name,value


class SupervisorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.R,cls.F,cls.data,cls.hashes=U.load_inputs();cls.C=cls.R.load_support()

    def test_all_frozen_source_identities_loaded(self):
        self.assertEqual(len(self.data),21);self.assertEqual(len(self.hashes),22)
        self.assertIn("hdfs-kerberos-context-cancellation/HdfsContextCancellationProbe.java",self.data)
        self.assertEqual(self.C.BASE,self.F.C.BASE)

    def test_changed_frozen_dependency_rejected(self):
        original=U.frozen_read
        def changed(path,maximum=262144):
            raw=original(path,maximum)
            return raw+b" " if path.name=="HdfsContextHeldResponse.java" else raw
        with patch.object(U,"frozen_read",changed),self.assertRaises(U.ProbeError):U.load_inputs()

    def test_package_root_reaches_the_frozen_worker_identity_guard(self):
        class ReachedIdentity(Exception): pass
        def identity(*args): raise ReachedIdentity()
        reader=types.SimpleNamespace(hosted_guard=lambda:None,directory=identity)
        valid=Path(__file__).resolve().parent/(U.PACKAGE_PREFIX+"-"+RUN+"-owned")/"context"
        with patch.object(self.R.sys,"version_info",(3,14)),self.assertRaises(ReachedIdentity):
            self.R.package_worker(reader,None,valid,(1,2),"0"*64)
        invalid=valid.parent.parent/("hdfs-context-"+RUN+"-owned")/"context"
        with patch.object(self.R.sys,"version_info",(3,14)),self.assertRaises(self.R.ProbeError) as caught:
            self.R.package_worker(reader,None,invalid,(1,2),"0"*64)
        self.assertEqual(caught.exception.code,"unsafe_path")

    def test_local_native_execution_rejected(self):
        with patch.dict(U.os.environ,{},clear=True),self.assertRaises(Exception):self.C.hosted_guard()

    def test_exact_five_container_commands(self):
        self.assertEqual(U.CASES,self.F.CASES)
        self.assertEqual(len(U.CASES),4)
        for kind,variant,case in [("identity",None,None),*(("case",v,c) for v,c in U.CASES)]:
            name,record=inspected(kind,variant,case)
            U.inspect_container(record,name,IMAGE,RUN,kind,variant,case)
            args=U.command_args(name,IMAGE,RUN,kind,variant,case)
            self.assertNotIn("--volume",args);self.assertNotIn("--publish",args)
            if kind=="case":self.assertEqual(args[-2:],[case,variant])

    def test_unknown_or_relabelled_case_rejected(self):
        name,_=inspected()
        for kind,variant,case in (("case","other","renewable"),("case","patched","other"),
                ("identity","patched","renewable"),("case","original","renewable"),
                ("other",None,None),("case","patched","nonrenewable")):
            with self.assertRaises(U.ProbeError):U.command_args(name,IMAGE,RUN,kind,variant,case)

    def test_container_isolation_mutations_rejected(self):
        name,record=inspected()
        for key,bad in (("NetworkMode","host"),("ReadonlyRootfs",False),("Privileged",True),("CapDrop",[]),
                        ("CapAdd",["SYS_ADMIN"]),("Binds",["/:/host"]),("PortBindings",{"88/tcp":[]}),("SecurityOpt",[]),
                        ("Memory",True),("NanoCpus",0),("PidsLimit",True),("Init",False),("IpcMode","host"),
                        ("CgroupnsMode","host"),("Tmpfs",{"/work":"rw,size=1g"}),("LogConfig",{"Type":"json-file"}),
                        ("Devices",[{}]),("DeviceRequests",[{}]),("ExtraHosts",["a:b"]),("PidMode","host")):
            with self.subTest(key=key):
                v=copy.deepcopy(record);v["HostConfig"][key]=bad
                with self.assertRaises(U.ProbeError):U.inspect_container(v,name,IMAGE,RUN,"case","patched","renewable")

    def test_command_and_identity_mutations_rejected(self):
        name,record=inspected()
        for area,key,bad in ((None,"Id","bad"),(None,"Image","sha256:"+"d"*64),(None,"Name","/different"),
                             ("Config","Labels",{}),("Config","User","0"),("Config","Entrypoint",["/bin/sh"]),
                             ("Config","Cmd",["evil"]),("Config","Volumes",{"/x":{}}),("Config","Healthcheck",{"Test":["CMD","x"]}),
                             (None,"Mounts",[{"Type":"bind","Destination":"/work"}])):
            with self.subTest(area=area,key=key):
                v=copy.deepcopy(record);(v if area is None else v[area])[key]=bad
                with self.assertRaises(U.ProbeError):U.inspect_container(v,name,IMAGE,RUN,"case","patched","renewable")

    def test_cleanup_rejects_unowned_container(self):
        name,record=inspected()
        for area,key,bad in ((None,"Id","d"*64),(None,"Name","/other"),(None,"Image","sha256:"+"e"*64),("Config","Labels",{})):
            v=copy.deepcopy(record);(v if area is None else v[area])[key]=bad;calls=[]
            docker=types.SimpleNamespace(inspect=lambda *a,**kw:v,call=lambda args:calls.append(args))
            with self.assertRaises(U.ProbeError):U.remove_container(docker,dict(name=name,id=CID,removed=False),IMAGE,RUN)
            self.assertEqual(calls,[])

    def test_cleanup_removes_exact_id_and_verifies_absence(self):
        name,record=inspected();values=iter([record,None]);calls=[]
        docker=types.SimpleNamespace(inspect=lambda *a,**kw:next(values),call=lambda args:calls.append(args))
        entry=dict(name=name,id=CID,removed=False);U.remove_container(docker,entry,IMAGE,RUN)
        self.assertTrue(entry["removed"]);self.assertEqual(calls,[["container","rm","--force",CID]])

    def test_cleanup_absent_container_does_not_delete(self):
        calls=[];docker=types.SimpleNamespace(inspect=lambda *a,**kw:None,call=lambda args:calls.append(args))
        entry=dict(name="owned",id=CID,removed=False);U.remove_container(docker,entry,IMAGE,RUN)
        self.assertTrue(entry["removed"]);self.assertEqual(calls,[])

    def test_closed_build_diagnostics(self):
        raw=b"/opt/rpc/HdfsContextCancellationProbe.java:123: error: cannot find symbol SECRET\n/opt/rpc/unknown.java:44: error: secret\n"
        out=U.build_diagnostics(self.R,raw)
        self.assertEqual(out["java_errors"],[dict(file="HdfsContextCancellationProbe.java",line=123,category="symbol")])
        self.assertNotIn("SECRET",str(out));self.assertNotIn("unknown",str(out))

    def test_closed_exception_diagnostics(self):
        try:raise OSError("secret-token-value")
        except OSError as error:out=U.failure_diagnostics(error)
        self.assertEqual(out["category"],"filesystem");self.assertNotIn("secret",str(out))

    def test_java_diagnostics_keep_only_finite_states(self):
        raw=b'{"stage":"cancellation_discard","error":"wire_invalid","secret":"do-not-publish","checks":{"cancellation_disposition":false,"secret":false},"kdc_trace":{"failure_stage":"response_decode"}}'
        out=U.java_diagnostics(self.F,raw)
        self.assertEqual(out["stage"],"cancellation_discard");self.assertEqual(out["error"],"wire_invalid")
        self.assertEqual(out["failed_checks"],["cancellation_disposition"])
        self.assertEqual(out["kdc_stage"],"response_decode");self.assertNotIn("secret",str(out));self.assertNotIn("do-not-publish",str(out))
        self.assertFalse(U.java_diagnostics(self.F,b"not json")["report_parseable"])

    def test_combined_build_preserves_native_boundaries(self):
        pins=self.C.profile_settings("kerberos-remediation")
        rows=self.C.runtime_rows(self.C.read(pins["runtime"],524288),self.C.read(pins["lock"],524288),profile="kerberos-remediation")
        sources={Path(n).name:b for n,b in self.data.items() if n.endswith(".java")}
        go={name:self.C.read(source,131072) for name,source in self.R.SOURCES.items()}
        files=U.build_files(self.C,self.R,self.F,rows,sources,go,b"module synthetic\n",b"")
        docker=files["Dockerfile"].decode();driver=files["rpc/driver.sh"].decode()
        self.assertIn("-proc:none -implicit:none",docker);self.assertIn("USER 10001:10001",docker)
        self.assertIn("180s",driver);self.assertIn('HdfsContextCancellationProbe "$1" "$2"',driver)
        self.assertIn("GOPROXY=off GOSUMDB=off",files["build.sh"].decode())
        self.assertEqual(len(rows),142)
        for n in U.JAVA_NAMES:self.assertIn("/opt/rpc/"+n,docker)
        self.assertIn(b"for variant in original patched",files["driver.sh"])
        self.assertIn(b"/opt/rpc/resources/webapps",files["rpc/runtime-checksums"])

    def test_execute_observes_exit_and_removes_container(self):
        name,record=inspected();ended=copy.deepcopy(record);ended["State"]["Status"]="exited"
        snapshots=iter([None,record,ended,ended,None]);calls=[]
        result=types.SimpleNamespace(stdout=b"{}",stderr=b"",code=0)
        docker=types.SimpleNamespace(inspect=lambda *a,**kw:next(snapshots),call=lambda args,**kw:(calls.append((args,kw)) or result))
        owned=[];reader=types.SimpleNamespace(read=lambda raw,maximum:raw)
        out=U.execute(reader,docker,IMAGE,RUN,"case",owned,"patched","renewable")
        self.assertEqual(out,(b"{}",0,CID));self.assertTrue(owned[0]["removed"])
        self.assertEqual(calls[1][1]["timeout"],195)

    def test_execute_rejects_oom_before_admission(self):
        name,record=inspected();ended=copy.deepcopy(record);ended["State"].update(Status="exited",OOMKilled=True)
        snapshots=iter([None,record,ended]);calls=[]
        result=types.SimpleNamespace(stdout=b"{}",stderr=b"",code=0)
        docker=types.SimpleNamespace(inspect=lambda *a,**kw:next(snapshots),call=lambda args,**kw:(calls.append(args) or result))
        owned=[];reader=types.SimpleNamespace(read=lambda raw,maximum:raw)
        with self.assertRaises(U.ProbeError):U.execute(reader,docker,IMAGE,RUN,"case",owned,"patched","renewable")
        self.assertFalse(owned[0]["removed"]);self.assertEqual(len(calls),2)

    def test_identity_runtime_has_bounded_native_control_time(self):
        name,record=inspected("identity");ended=copy.deepcopy(record);ended["State"]["Status"]="exited"
        snapshots=iter([None,record,ended,ended,None]);calls=[]
        result=types.SimpleNamespace(stdout=b"{}",stderr=b"",code=0)
        docker=types.SimpleNamespace(inspect=lambda *a,**kw:next(snapshots),call=lambda args,**kw:(calls.append((args,kw)) or result))
        owned=[];reader=types.SimpleNamespace(read=lambda raw,maximum:raw)
        U.execute(reader,docker,IMAGE,RUN,"identity",owned)
        self.assertEqual(calls[1][1]["timeout"],90);self.assertTrue(owned[0]["removed"])

    def test_binary_identity_requires_each_exact_qualified_digest(self):
        value=dict(binaries=[dict(variant="original",bytes=119830724,sha256="37ef48307cbaae684126fe8e2f5d6ca3717fce679fd36c34fc4ba584295ea0d3"),
            dict(variant="patched",bytes=119848207,sha256="8c72cfd7f7a8f0a7e62c7f527155e0e55bb391cf8bffdb1ada6009416d74e27b")],
            context_tests=dict(binary_bytes=12025580,binary_sha256="4b9cc4d5f84c1467e92828961e8e521251dd1b93032bc911489dc83d7cebb645"))
        self.assertTrue(U.qualified_identity(value))
        for index,key,bad in ((0,"sha256","0"*64),(1,"sha256","0"*64),(0,"bytes",True),(1,"bytes",119848208),
                              (1,"variant","original"),(0,"variant",[])):
            v=copy.deepcopy(value);v["binaries"][index][key]=bad
            with self.assertRaises(U.ProbeError):U.qualified_identity(v)
        for key,bad in (("binary_bytes",12025579),("binary_sha256","0"*64)):
            v=copy.deepcopy(value);v["context_tests"][key]=bad
            with self.assertRaises(U.ProbeError):U.qualified_identity(v)

if __name__=="__main__":unittest.main()
