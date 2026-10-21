"""Repository-discoverable pure/fake coverage; no operational boundary is run."""
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
def load_source(name, path):
    value = types.ModuleType(name)
    value.__file__ = str(path)
    sys.modules[name] = value
    exec(compile(path.read_bytes(), str(path), "exec"), value.__dict__)
    return value


# This hyphenated directory is not a Python package. Read the repository's exact
# source bytes without cached bytecode or persistent generic module aliases.
SOURCE = Path(__file__).resolve().parents[1] / "provider-lab" / "webdav-command"
# Real temporary files retain the host user's ownership. Windows reports UID 0.
HOST_UID = getattr(os, "getuid", lambda: 0)()
with patch.dict(sys.modules):
    C = load_source("command_contract", SOURCE / "command_contract.py")
    H = load_source("token_helper", SOURCE / "token_helper.py")
    F = load_source("fixture", SOURCE / "fixture.py")
    P = load_source("probe", SOURCE / "probe.py")


class Memory:
    def __init__(self,case):
        self.case=case; self.files={}; self.outputs=[]; self.locked=False
    def control(self): return C.compact(dict(schema_version=1,case=self.case))
    def case_matches(self,case): return self.case==case
    @contextlib.contextmanager
    def lock(self):
        if self.locked: raise BlockingIOError()
        self.locked=True
        try: yield
        finally: self.locked=False
    def names(self): return set(self.files)
    def read(self,name): return self.files[name]
    def create(self,name,body):
        if name in self.files: raise FileExistsError()
        self.files[name]=body
    def write(self,fd,body): self.outputs.append((fd,body))


def passed(case):
    row=C.empty_case(case)
    row.update(status="passed",error=None,elapsed_ms=1000,helpers=[C.expected_helper(case,i+1) for i in range(C.MAX_HELPERS[case])],events=C.expected_events(case),checks={k:True for k in C.CHECKS})
    row["children"]=[dict(role="stat",exit_code=1 if case.startswith("initial_") else 0,identity_checked=True,reaped=True,group_empty=True,forced=False)]
    if not case.startswith("initial_"): row["children"].append(dict(role="copy",exit_code=0 if case=="renewal" else 1,identity_checked=True,reaped=True,group_empty=True,forced=False))
    row["output"]=dict(kind="exact_content",bytes=30,sha256=C.BODY_SHA) if case=="renewal" else dict(kind="empty",bytes=0,sha256=None)
    if case=="cancellation": row["cancellation"]=dict(signal_attempts=1,group_identity_checked=True,reader_closed=True,extents=[dict(bytes=n,sha256=s,identity_verified=True) for n,s in zip(C.EXTENTS,C.EXTENT_SHAS)])
    return row


class HelperTests(unittest.TestCase):
    def test_all_five_sequences_and_finite_output(self):
        for case in C.CASES:
            memory=Memory(case)
            for n in range(1,C.MAX_HELPERS[case]+1):
                code=H.run(memory); expected=C.expected_helper(case,n)
                self.assertEqual(code,expected["intended_exit"])
                self.assertEqual(C.parse(memory.files[f"{n:03}-done.json"]),expected)
                self.assertLessEqual(len(memory.files[f"{n:03}-done.json"]),256)
            self.assertEqual(H.run(memory),71)
            self.assertTrue(all(len(body)<=32 for _,body in memory.outputs))
    def test_contention_does_not_wait_or_write(self):
        memory=Memory("renewal");memory.locked=True
        self.assertEqual(H.run(memory),72);self.assertEqual(memory.files,{})
    def test_orphan_start_rejected(self):
        memory=Memory("renewal");memory.files["001-start.json"]=b"{}"
        self.assertEqual(H.run(memory),71);self.assertEqual(memory.outputs,[])
    def test_duplicate_unknown_oversized_control(self):
        for raw in (b'{"schema_version":1,"case":"renewal","case":"initial_empty"}',b'{"schema_version":true,"case":"renewal"}',b'{"schema_version":1,"case":"renewal","token":"secret"}',b"x"*1025):
            memory=Memory("renewal");memory.control=lambda:raw
            self.assertEqual(H.run(memory),71);self.assertEqual(memory.outputs,[])
    def test_previous_record_tamper(self):
        memory=Memory("renewal");self.assertEqual(H.run(memory),0)
        memory.files["001-done.json"]=b"{}"
        self.assertEqual(H.run(memory),71)
    def test_output_failure_has_no_completed_claim(self):
        memory=Memory("renewal")
        def fail(*_): raise OSError()
        memory.write=fail
        self.assertEqual(H.run(memory),72);self.assertNotIn("001-done.json",memory.files)
    def test_no_console_or_private_error_printing(self):
        memory=Memory("initial_nonzero");self.assertEqual(H.run(memory),70)
        self.assertEqual(memory.outputs,[(1,b""),(2,b"synthetic-command-denied\n")])


class ContractTests(unittest.TestCase):
    def test_all_cases_and_full_suite(self):
        bindings={k:"1"*(40 if k=="source_revision" else 64) for k in C.BINDINGS};bindings["runtime_sha256"]=C.RUNTIME_SHA
        value=dict(schema_version=1,scope="linux_network_none_protocol",mode="webdav_command_rc_v1",runtime=dict(version="1.75.2",platform="linux_amd64",sha256=C.RUNTIME_SHA),bindings=bindings,cases=[passed(c) for c in C.CASES],result="passed",claims=dict(C.CLAIMS))
        self.assertIs(C.validate(value,bindings),value)
        self.assertLess(len(C.compact(value)),65536)
        for key in C.CLAIMS:
            bad=copy.deepcopy(value);bad["claims"][key]=True
            with self.assertRaises(C.Rejected):C.validate(bad,bindings)
    def test_denial_counts_cannot_be_prefix_or_extra(self):
        for field,count in (("helpers",101),("helpers",103),("events",101),("events",103)):
            row=passed("refresh_denied");row[field]=row[field][:count] if count<len(row[field]) else row[field]+[row[field][-1]]
            with self.assertRaises(C.Rejected):C.validate_case(row)
    def test_wrong_order_and_empty_output_meaning(self):
        for case in ("renewal","initial_empty"):
            row=passed(case);row["helpers"][0]["action"]="deny"
            with self.assertRaises(C.Rejected):C.validate_case(row)
        self.assertEqual(len(C.expected_events("initial_empty")),10)
        self.assertEqual(C.MAX_HELPERS["initial_empty"],11)
    def test_cleanup_and_exit_are_not_intent(self):
        for field,value in (("forced",True),("reaped",False),("group_empty",None),("exit_code",None),("identity_checked",False),("exit_code",True)):
            row=passed("refresh_denied");row["children"][-1][field]=value
            with self.assertRaises(C.Rejected):C.validate_case(row)
    def test_cancel_requires_two_hashes_closed_reader_and_one_signal(self):
        for key,value in (("signal_attempts",0),("signal_attempts",2),("reader_closed",False),("group_identity_checked",None),("extents",[])):
            row=passed("cancellation");row["cancellation"][key]=value
            with self.assertRaises(C.Rejected):C.validate_case(row)
        row=passed("cancellation");row["cancellation"]["extents"][1]["sha256"]="0"*64
        with self.assertRaises(C.Rejected):C.validate_case(row)
    def test_unknown_raw_fields_boolean_counts_and_deadline(self):
        for update in ({"raw_error":"private-canary"},{"elapsed_ms":True},{"elapsed_ms":420001}):
            row=passed("refresh_denied");row.update(update)
            with self.assertRaises(C.Rejected):C.validate_case(row)
        row=passed("initial_nonzero");row["output"]["bytes"]=False
        with self.assertRaises(C.Rejected):C.validate_case(row)
    def test_failure_is_finite_and_does_not_need_success_facts(self):
        row=C.empty_case("renewal");self.assertIs(C.validate_case(row),row)
        row["error"]="path-secret"
        with self.assertRaises(C.Rejected):C.validate_case(row)
    def test_json_duplicate_and_oversize(self):
        for raw in (b'{"a":1,"a":2}',b'NaN',b" "*65537):
            with self.assertRaises(C.Rejected):C.parse(raw)


class FixtureTests(unittest.TestCase):
    def test_model_exact_routes_and_limits(self):
        for case in C.CASES:
            model=F.Model(case)
            for row in C.expected_events(case):
                self.assertEqual(model.request(row["method"],row["credential"]),row["status"])
                if row["payload_bytes"]:model.payload(row["payload_bytes"])
            self.assertEqual(model.events,C.expected_events(case))
            with self.assertRaises(C.Rejected):model.request("GET","A")
    def test_no_denial_status_or_credential_substitution(self):
        model=F.Model("refresh_denied")
        for _ in range(2):model.request("PROPFIND","A")
        with self.assertRaises(C.Rejected):model.request("GET","B")
        self.assertEqual(len(model.events),2)
    def header(self,method="PROPFIND",auth=b"Bearer synthetic-tokenA"):
        body=F.PROPFIND if method=="PROPFIND" else b""
        headers=f"{method} /payload.bin HTTP/1.1\r\nHost: 127.0.0.1:1234\r\nReferer: http://127.0.0.1:1234/\r\n".encode()+b"Authorization: "+auth+b"\r\n"
        headers+=b"Depth: 0\r\n"
        if method=="PROPFIND":headers+=b"Content-Length: "+str(len(body)).encode()+b"\r\n"
        return headers+b"\r\n",body
    def test_bounded_parser_standard_body_and_trimmed_empty(self):
        header,body=self.header();self.assertEqual(F.parse_request(header,body,1234),("PROPFIND","A"))
        for auth in (b"Bearer",b"Bearer "):
            header,body=self.header(auth=auth);self.assertEqual(F.parse_request(header,body,1234),("PROPFIND","empty"))
    def test_unknown_route_header_range_duplicate_body_rejected(self):
        header,body=self.header()
        for wrong in (header.replace(b"/payload.bin ",b"/other "),header.replace(b"Depth: 0",b"Depth: 1"),header[:-2]+b"Range: bytes=0-1\r\n\r\n",header[:-2]+b"Authorization: private\r\n\r\n",header+b" "*8192):
            with self.assertRaises(C.Rejected):F.parse_request(wrong,body,1234)
        with self.assertRaises(C.Rejected):F.parse_request(header,b"",1234)
    def test_source_defined_get_depth_and_initial_full_range(self):
        header,body=self.header("GET")
        for value in (b"bytes=0-",b"bytes=0-29"):
            self.assertEqual(F.parse_request(header[:-2]+b"Range: "+value+b"\r\n\r\n",body,1234),("GET","A"))
        for wrong in (header.replace(b"Depth: 0\r\n",b""),header[:-2]+b"Range: bytes=1-\r\n\r\n",header[:-2]+b"Content-Type: anything\r\n\r\n"):
            with self.assertRaises(C.Rejected):F.parse_request(wrong,body,1234)


class BoundaryTests(unittest.TestCase):
    def test_exact_rc_args_have_no_retry_or_transport_overrides(self):
        for role in ("stat","copy"):
            args=P.arguments(role,Path("/opt/rclone"),Path("/work/config"),Path("/work/output"))
            self.assertEqual(args[7:9],["rc","--loopback"])
            self.assertFalse(any(a in args for a in ("--retries","--low-level-retries","--timeout","--contimeout","--async","copyto","lsjson")))
        self.assertIn('opt={"noModTime":true,"noMimeType":true,"filesOnly":true}',P.arguments("stat","r","c","o"))
    def test_fixed_config_has_no_static_token_or_shell(self):
        value=P.command_config("http://127.0.0.1:1234/","/usr/local/bin/python3")
        self.assertIn(b" -I -S -B /opt/fixture/webdav-command/token_helper.py\n",value)
        self.assertNotIn(b"bearer_token =",value)
        for endpoint,python in (("http://example.org/","/usr/local/bin/python3"),("http://127.0.0.1:1234/","/bin/sh")):
            with self.assertRaises(C.Rejected):P.command_config(endpoint,python)
    def test_literal_hashes_match_independent_pattern(self):
        self.assertEqual(hashlib.sha256(bytes(range(256))*1024).hexdigest(),C.EXTENT_SHAS[0])
        self.assertEqual(hashlib.sha256(bytes(range(256))*2048).hexdigest(),C.EXTENT_SHAS[1])
    def test_stat_rejects_directory_wrong_size_and_parent_fallback(self):
        value={"item":{"Path":"payload.bin","Name":"payload.bin","Size":30,"IsDir":False}}
        P.stat_exact(C.compact(value),30)
        for change in ({"Size":31},{"IsDir":True},{"Path":"parent/payload.bin"},{"Size":True}):
            wrong=copy.deepcopy(value);wrong["item"].update(change)
            with self.assertRaises(C.Rejected):P.stat_exact(C.compact(wrong),30)


class ChildTests(unittest.TestCase):
    def child(self, process, now=0):
        obj=P.Child.__new__(P.Child);obj.process=process;obj.bound=(9,0,42,42);obj.deadline=100
        obj.observed=dict(role="copy",exit_code=None,identity_checked=True,reaped=None,group_empty=None,forced=False)
        obj.uncertain=False;self.signals=[]
        obj.h=dict(clock=lambda:now,identity=lambda _:obj.bound,killpg=lambda pid,sig:self.signals.append((pid,sig)),group_empty=lambda _:True)
        return obj
    def test_single_signal_after_witness_close(self):
        process=types.SimpleNamespace(pid=42,poll=lambda:None)
        child=self.child(process);evidence=passed("cancellation")["cancellation"];evidence["signal_attempts"]=0
        child.cancel_once(evidence)
        self.assertEqual(self.signals,[(42,signal.SIGINT)])
        with self.assertRaises(C.Rejected):child.cancel_once(evidence)
    def test_identity_failure_or_open_reader_never_signals(self):
        for failure in ("identity","reader"):
            child=self.child(types.SimpleNamespace(pid=42,poll=lambda:None));e=passed("cancellation")["cancellation"];e["signal_attempts"]=0
            if failure=="identity":child.h["identity"]=lambda _:None
            else:e["reader_closed"]=False
            with self.assertRaises(C.Rejected):child.cancel_once(e)
            self.assertEqual(self.signals,[])
    def test_actual_wait_code_preserved_and_unknown_group_rejected(self):
        for empty in (True,False):
            process=types.SimpleNamespace(pid=42,returncode=70,poll=lambda:70,wait=lambda **_:70)
            child=self.child(process);child.h["group_empty"]=lambda _:empty
            self.assertEqual(child.close(30),empty)
            self.assertEqual(child.observed["exit_code"],70);self.assertTrue(child.observed["reaped"])
    def test_unknown_start_is_not_reaped(self):
        child=self.child(None);child.uncertain=True
        self.assertFalse(child.close(30));self.assertIsNone(child.observed["exit_code"])
    def test_forced_cleanup_never_credits_natural_exit(self):
        state={"running":True}
        def wait(**_):state["running"]=False;return 143
        process=types.SimpleNamespace(pid=42,returncode=143,poll=lambda:None if state["running"] else 143,wait=wait)
        child=self.child(process)
        self.assertTrue(child.close(30));self.assertTrue(child.observed["forced"])
        self.assertEqual(self.signals,[(42,signal.SIGTERM)])


class OwnershipTests(unittest.TestCase):
    def test_regular_requires_matching_owner_including_nonzero_uid(self):
        for uid in (0, 10001):
            with self.subTest(uid=uid), patch.object(P.os, "getuid", lambda: uid, create=True):
                info = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_uid=uid, st_size=1)
                path = types.SimpleNamespace(lstat=lambda: info)
                self.assertIs(P.regular(path, 1), info)
                info.st_uid = uid + 1
                with self.assertRaises(C.Rejected):
                    P.regular(path, 1)


class WitnessTests(unittest.TestCase):
    def exercise(self, body, mutate=False, extra=False):
        position=[0];changed=[False];closed=[]
        def info(directory=False):
            return types.SimpleNamespace(st_mode=stat.S_IFDIR|0o700 if directory else stat.S_IFREG|0o600,st_dev=1,st_ino=1 if directory else (3 if changed[0] else 2),st_nlink=1,st_uid=0,st_size=C.CANCEL_SIZE)
        leaf=types.SimpleNamespace(name="payload.bin.1234abcd.partial",lstat=lambda:info())
        root=types.SimpleNamespace(lstat=lambda:info(True),is_symlink=lambda:False,iterdir=lambda:iter([leaf,leaf] if extra else [leaf]))
        def read(fd,size):
            value=body[position[0]:position[0]+size];position[0]+=len(value)
            if mutate:changed[0]=True
            return value
        with patch.object(P.os,"getuid",lambda:0,create=True),patch.object(P.os,"O_NOFOLLOW",0,create=True),patch.object(P.os,"open",lambda *_:7),patch.object(P.os,"fstat",lambda _:info()),patch.object(P.os,"lseek",lambda *_:position.__setitem__(0,0)),patch.object(P.os,"read",read),patch.object(P.os,"close",lambda fd:closed.append(fd)):
            witness=P.Witness(root)
            try:return witness.sample(0)
            finally:witness.close()
    def test_preallocation_zeros_and_short_read_do_not_qualify(self):
        self.assertIsNone(self.exercise(b"\0"*C.EXTENTS[0]))
        self.assertIsNone(self.exercise(C.BLOCK*10))
    def test_correct_content_is_required(self):
        self.assertEqual(self.exercise(C.BLOCK*1024),dict(bytes=262144,sha256=C.EXTENT_SHAS[0],identity_verified=True))
    def test_identity_change_and_extra_leaf_fail_closed(self):
        for change in (dict(mutate=True),dict(extra=True)):
            with self.assertRaises(C.Rejected):self.exercise(C.BLOCK*1024,**change)


class FakeEvent:
    def __init__(self):self.called=0
    def set(self):self.called+=1


class FakeServer:
    def __init__(self,case,deadline,clock):
        self.case=case;self.first_observed=FakeEvent();self.second_observed=FakeEvent()
    def start(self):return "http://127.0.0.1:1234/"
    def snapshot(self):return C.expected_events(self.case),False
    def close(self,deadline):return True


class FakeChild:
    starts=[]; signals=[]; forced=False
    def __init__(self,role,root,deadline,env):
        self.role,self.root,self.deadline=role,root,deadline
        self.case=json.loads((root/"control.json").read_bytes())["case"]
        self.observed=dict(role=role,exit_code=None,identity_checked=None,reaped=None,group_empty=None,forced=False)
    def start(self):
        self.starts.append((self.case,self.role))
        size=C.CANCEL_SIZE if self.case=="cancellation" else 30
        (self.root/(self.role+".out")).write_bytes(C.compact(dict(item=dict(Path="payload.bin",Name="payload.bin",Size=size,IsDir=False))) if self.role=="stat" else b"{}")
        (self.root/(self.role+".err")).write_bytes(b"")
        self.observed["identity_checked"]=True
        count=C.MAX_HELPERS[self.case] if self.role=="copy" or self.case.startswith("initial_") else 1
        for i in range(1,count+1):
            expected=C.expected_helper(self.case,i)
            for kind,value in (("start",dict(sequence=i,action=expected["action"])),("done",expected)):
                path=self.root/"journal"/f"{i:03}-{kind}.json"
                if not path.exists():path.write_bytes(C.compact(value)+b"\n")
        if self.role=="copy" and self.case=="renewal":(self.root/"output"/"payload.bin").write_bytes(C.BODY)
        if self.role=="copy" and self.case=="cancellation":(self.root/"output"/"payload.bin.1234abcd.partial").write_bytes(C.BLOCK*2048)
    def check(self):pass
    def live(self):pass
    def wait(self):
        code=1 if self.case.startswith("initial_") or self.role=="copy" and self.case!="renewal" else 0
        self.observed.update(exit_code=code,reaped=True,group_empty=True)
        if self.case=="cancellation" and self.role=="copy":(self.root/"output"/"payload.bin.1234abcd.partial").unlink()
        return (self.root/(self.role+".out")).read_bytes(),b""
    def cancel_once(self,evidence):
        C.require(evidence["reader_closed"] is True and len(evidence["extents"])==2 and evidence["signal_attempts"]==0,"signal")
        evidence["signal_attempts"]=1;evidence["group_identity_checked"]=True;self.signals.append(self.case)
    def close(self,deadline):
        if self.forced:self.observed["forced"]=True
        return True


class OrchestrationTests(unittest.TestCase):
    def test_all_five_real_orchestrations_with_fake_boundaries(self):
        FakeChild.starts=[];FakeChild.signals=[]
        real_digest=P.digest
        real_open=P.os.open
        def binary_open(path,flags,*args):return real_open(path,flags|getattr(P.os,"O_BINARY",0),*args)
        polls=[]
        def bounded_fake_sleep(_):
            polls.append(1)
            if len(polls)>10:raise AssertionError("fake_witness_did_not_progress")
        def digest(path):return "1"*64 if path==P.HELPER else C.RUNTIME_SHA if path==P.BINARY else real_digest(path)
        with tempfile.TemporaryDirectory(prefix="command-pure-") as tmp,patch.object(P,"WORK",Path(tmp)),patch.object(P.os,"getuid",lambda:HOST_UID,create=True),patch.object(P.os,"O_NOFOLLOW",0,create=True),patch.object(P.os,"open",binary_open),patch.object(P,"digest",digest):
            for case in C.CASES:
                row=P.case_run(case,"/usr/local/bin/python3",dict(runtime_sha256=C.RUNTIME_SHA,helper_sha256="1"*64),lambda:True,720,factory=FakeChild,fixture_factory=FakeServer,clock=lambda:0,sleep=bounded_fake_sleep)
                self.assertEqual(row["status"],"passed",row)
                self.assertEqual(row["helpers"],passed(case)["helpers"])
                self.assertEqual(list(Path(tmp).iterdir()),[])
        self.assertEqual(len(FakeChild.starts),8)
        self.assertEqual(FakeChild.signals,["cancellation"])
    def test_forced_cleanup_is_failed_even_when_empty(self):
        real_digest=P.digest
        def digest(path):return "1"*64 if path==P.HELPER else C.RUNTIME_SHA if path==P.BINARY else real_digest(path)
        with tempfile.TemporaryDirectory(prefix="command-pure-") as tmp,patch.object(P,"WORK",Path(tmp)),patch.object(P.os,"getuid",lambda:HOST_UID,create=True),patch.object(P.os,"O_NOFOLLOW",0,create=True),patch.object(P,"digest",digest),patch.object(FakeChild,"forced",True):
            row=P.case_run("renewal","/usr/local/bin/python3",dict(runtime_sha256=C.RUNTIME_SHA,helper_sha256="1"*64),lambda:True,720,factory=FakeChild,fixture_factory=FakeServer,clock=lambda:0)
            self.assertEqual(row["status"],"failed");self.assertEqual(row["error"],"cleanup")
            self.assertTrue(row["checks"]["temporary_removed"])


class DeferredFixture(FakeServer):
    mode = "complete"
    instances = []
    def __init__(self, case, deadline, clock):
        super().__init__(case, deadline, clock)
        self.closed = False
        self.closes = 0
        self.snapshots = []
        self.instances.append(self)
    def snapshot(self):
        self.snapshots.append(self.closed)
        events = copy.deepcopy(C.expected_events(self.case))
        if not self.closed or self.mode == "incomplete_payload":
            events[-1]["payload_bytes"] = 0
        return events, self.closed and self.mode == "fixture_failed"
    def close(self, deadline):
        self.closes += 1
        self.closed = True
        return self.mode != "join_failed"


class CompletionOrderTests(unittest.TestCase):
    def run_case(self, module, mode="complete", child_type=FakeChild):
        DeferredFixture.instances = []
        real_digest = module.digest
        def digest(path):
            return "1"*64 if path == module.HELPER else C.RUNTIME_SHA if path == module.BINARY else real_digest(path)
        with tempfile.TemporaryDirectory(prefix="command-order-pure-") as tmp, patch.object(module, "WORK", Path(tmp)), patch.object(module.os, "getuid", lambda: HOST_UID, create=True), patch.object(module.os, "O_NOFOLLOW", 0, create=True), patch.object(module, "digest", digest), patch.object(DeferredFixture, "mode", mode):
            row = module.case_run("renewal", "/usr/local/bin/python3", dict(runtime_sha256=C.RUNTIME_SHA, helper_sha256="1"*64), lambda: True, 720, factory=child_type, fixture_factory=DeferredFixture, clock=lambda: 0)
            if mode != "join_failed": self.assertEqual(list(Path(tmp).iterdir()), [])
        fixture = DeferredFixture.instances[0]
        self.assertEqual(fixture.closes, 1)
        return row, fixture

    def test_delayed_payload_commits_before_exact_comparison(self):
        row, fixture = self.run_case(P)
        self.assertEqual(row["status"], "passed")
        self.assertIsNone(row["error"])
        self.assertEqual(fixture.snapshots, [True])
        self.assertEqual(row["events"], C.expected_events("renewal"))

    def test_postjoin_fixture_failure_or_incomplete_event_still_rejects(self):
        for mode in ("fixture_failed", "incomplete_payload", "join_failed"):
            with self.subTest(mode=mode):
                row, fixture = self.run_case(P, mode)
                self.assertEqual(row["status"], "failed")
                self.assertEqual(row["error"], "cleanup" if mode == "join_failed" else "fixture")
                self.assertEqual(fixture.snapshots, [True])
                self.assertEqual(row["checks"]["fixture_closed"], mode != "join_failed")

    def test_existing_copy_failure_survives_final_fixture_failure(self):
        class BadCopy(FakeChild):
            def wait(self):
                result = super().wait()
                if self.role == "copy": self.observed["exit_code"] = 1
                return result
        row, _ = self.run_case(P, "fixture_failed", BadCopy)
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["error"], "copy")
        self.assertEqual(row["children"][-1]["exit_code"], 1)
