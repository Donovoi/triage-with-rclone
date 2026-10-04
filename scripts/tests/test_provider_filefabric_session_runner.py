"""FileFabric session verdict mutation tests; fake runtime, no native process/listener."""
import copy
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).parents[1]/"provider-lab"))
try:
    import run_lab as L
finally:sys.path.pop(0)

NAME="README-synthetic.txt"
DATA=b"Synthetic provider protocol fixture. No account or user data.\n"
EXPECTED=[{"path":NAME,"size":len(DATA),"sha256":hashlib.sha256(DATA).hexdigest()}]
CAPS={"session_token_reacquisition","renewal_denial","config_scope_preservation","saved_token_reuse","source_preservation","cleanup"}
STAT={"_path":"operations/stat","fs":"Synthetic:","remote":NAME,
      "opt":{"filesOnly":True,"showHash":True,"noModTime":False,"noMimeType":True}}


def item():return {"item":{"Path":NAME,"Name":NAME,"Size":len(DATA),"IsDir":False,"ID":"301","ModTime":"2024-01-01T00:00:00Z"}}


def error(kind):
    cause={"expired":"failed to check path exists: Synthetic cached session expired (login_token_expired)",
           "grant_denied":"failed to check path exists: failed to get session token: Synthetic grant denied (fixture_grant_denied)"}[kind]
    return {"error":cause,"input":{k:copy.deepcopy(v) for k,v in STAT.items() if k!="_path"},"path":"operations/stat","status":500}


def flow(state,mode):
    if mode=="success":
        events=[("initial_stat",NAME),("expired",NAME),("grant",""),("appliance",""),("renewed_stat",NAME),("copy_stat",NAME),("content",NAME)]
        counts=(7,4,1,1,1,0,1,len(DATA));state.phase="complete"
    elif mode=="deny":
        events=[("initial_stat",NAME),("expired",NAME),("grant_denied","")]
        counts=(3,1,1,1,0,1,0,0);state.phase="denied"
    else:
        events=[("reuse_stat",NAME),("reuse_copy_stat",NAME),("reuse_content",NAME)]
        counts=(3,3,0,0,0,0,0,len(DATA));state.phase="reuse_complete"
    state.events=events
    for key,value in zip(("requests","authenticated","expirations","grant_attempts","grants","grant_denials","appliance_calls","payload_bytes"),counts):
        setattr(state,key,value)
    state.lifetime_requests+=counts[0]


class Scenario:
    def __init__(self,root,mutate=None,after=None):
        self.root=root;root.mkdir(mode=0o700)
        self.mutate,self.after=mutate,after
        self.children=[];self.states=[];self.calls=[];self.active=None
        self.code=0;self.pending=False;self.extra_child=False

    @contextmanager
    def serve(self,kind,state):
        assert kind=="filefabric-renewal"
        self.active=state;self.states.append(state)
        try:yield 18000+len(self.states)
        finally:
            state.cleanup_complete=True
            if self.after:self.after(self,state)

    def run(self,args,config=None,**kwargs):
        assert args[:4]==["rc","--loopback","job/batch","--json"] and len(args)==5
        assert kwargs=={"timeout":20}
        batch=json.loads(args[4]);assert set(batch)=={"concurrency","inputs"} and type(batch["concurrency"]) is int and batch["concurrency"]==1
        mode="reuse" if len(batch["inputs"])==4 else "deny" if self.active.deny else "success"
        self.mode=mode;self.calls.append((mode,args,config))
        pid=9100+len(self.children)
        values=[{"pid":pid},item(),{}, {"pid":pid}] if mode=="reuse" else [{"pid":pid},item(),error("expired"),{"pid":pid},error("grant_denied") if mode=="deny" else item()]
        if mode=="success":values+=[{}]
        if mode!="reuse":values+=[{"pid":pid}]
        flow(self.active,mode)
        if mode=="success":
            self.active.issued_token="synthetic-issued-B"
            self.active.expiry_lower=datetime(2026,10,4,1,2,3,100000,tzinfo=timezone.utc)
            self.active.grant_upper=self.active.expiry_lower+timedelta(milliseconds=100)
            self.active.expiry_lower_monotonic=10.;self.active.grant_upper_monotonic=10.1
            old=config.read_text()
            expiry=(self.active.expiry_lower+timedelta(minutes=55)).replace(microsecond=0).astimezone(timezone(timedelta(hours=11))).isoformat()
            lines=[]
            for line in old.splitlines():
                if line.startswith("token = "):line="token = synthetic-issued-B"
                elif line.startswith("token_expiry = "):line="token_expiry = "+expiry
                elif line.startswith("version = "):line="version = 2006.02"
                lines.append(line)
            config.write_text("\n".join(lines)+"\n",encoding="utf-8")
        for request in batch["inputs"]:
            if request["_path"]=="operations/copyfile":
                assert request["srcFs"]=="Synthetic:" and request["srcRemote"]==NAME and request["dstRemote"]==NAME
                target=Path(request["dstFs"])/NAME
                assert target.is_relative_to(self.root)
                target.write_bytes(DATA)
        result={"results":values}
        if self.mutate:self.mutate(self,result,batch,config)
        process=mock.Mock(pid=pid)
        process.poll.return_value=None if self.pending else self.code
        record=(process,self.root/"private.out",self.root/"private.err")
        self.children.append(record)
        if self.extra_child:self.children.append(record)
        return self.code,json.dumps(result).encode(),b""

    def execute(self,closed=True):
        row={"backend":"filefabric","fixture_kind":"independent_loopback","fixture_mode":"filefabric_later_call_renewal_v1",
             "capabilities":{name:"not_run" for name in CAPS},"errors":[]}
        with mock.patch.object(L,"serve",self.serve),mock.patch.object(L,"listener_closed",return_value=closed):
            try:L.filefabric_session_checks(self,self.root,row,L.fixture_manifest())
            except L.LabError as exc:row["errors"].append(str(exc))
        return row


class FileFabricSessionRunnerTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.serial=0

    def scenario(self,**kwargs):
        self.serial+=1
        return Scenario(self.root/str(self.serial),**kwargs)

    def test_full_success_denial_saved_reuse_scope(self):
        scenario=self.scenario();row=scenario.execute()
        self.assertEqual(row["errors"],[])
        self.assertEqual(row["capabilities"],{name:"passed" for name in CAPS})
        self.assertEqual([mode for mode,*_ in scenario.calls],["success","reuse","deny"])
        self.assertEqual(len(scenario.children),3)
        self.assertEqual([state.lifetime_requests for state in scenario.states],[10,3])
        for canary in (str(self.root),scenario.states[0].token,scenario.states[0].permanent_token,"synthetic-issued-B","18001"):
            self.assertNotIn(canary,json.dumps(row))

    def test_batches_have_fixed_typed_inputs_no_async_overrides_and_only_one_member(self):
        scenario=self.scenario();self.assertEqual(scenario.execute()["errors"],[])
        for mode,args,config in scenario.calls:
            batch=json.loads(args[4]);calls=batch["inputs"]
            self.assertEqual(len(calls),{"success":7,"deny":6,"reuse":4}[mode])
            self.assertEqual(type(batch["concurrency"]),int)
            self.assertEqual(batch["concurrency"],1)
            self.assertEqual(calls[0],{"_path":"core/pid"});self.assertEqual(calls[-1],{"_path":"core/pid"})
            for call in calls:
                self.assertFalse(set(call)&{"_async","_config","_filter","_group"})
                if call["_path"]=="operations/stat":self.assertEqual(call,STAT)
                if call["_path"]=="operations/copyfile":self.assertEqual(call["srcRemote"],NAME)
        for mode in ("unknown",True,1):
            with self.assertRaises(L.LabError):L.filefabric_session_batch(self.root,mode)

    def test_batch_error_exact_keys_direct_cause_typed_nested_input(self):
        for kind in ("expired","grant_denied"):
            valid=error(kind);self.assertTrue(L.filefabric_session_error_matches(valid,STAT,kind))
            valid["input"]["_group"]="job/12";self.assertTrue(L.filefabric_session_error_matches(valid,STAT,kind))
            for field,values in {"status":(True,500.,"500",404),"path":("operations/copyfile",),
                                 "error":("loopback: call failed: "+valid["error"],"wrong")}.items():
                for value in values:
                    changed=copy.deepcopy(valid);changed[field]=value
                    self.assertFalse(L.filefabric_session_error_matches(changed,STAT,kind))
            for key,value in (("filesOnly",1),("showHash",None),("noModTime",0),("noMimeType",1)):
                changed=copy.deepcopy(valid);changed["input"]["opt"][key]=value
                self.assertFalse(L.filefabric_session_error_matches(changed,STAT,kind))
            for group in (None,12,"job/0","job/-1","job/1234567890123","job/12\n","other/12"):
                changed=copy.deepcopy(valid);changed["input"]["_group"]=group
                self.assertFalse(L.filefabric_session_error_matches(changed,STAT,kind))
            for key in ("_async","_filter","_config","extra"):
                changed=copy.deepcopy(valid);changed["input"][key]=False
                self.assertFalse(L.filefabric_session_error_matches(changed,STAT,kind))
            for key in valid:
                changed=copy.deepcopy(valid);del changed[key]
                self.assertFalse(L.filefabric_session_error_matches(changed,STAT,kind))

    def test_failed_middle_result_cannot_be_success_or_stderr_only_in_a_successful_batch(self):
        for mode,index in (("success",2),("deny",2),("deny",4)):
            for wrong in (item(),{},None,{"error":"unrelated"}):
                def mutate(s,r,b,c):
                    if s.mode==mode:r["results"][index]=wrong
                row=self.scenario(mutate=mutate).execute()
                self.assertIn("filefabric_session_batch_results",row["errors"])
                self.assertEqual(row["capabilities"]["session_token_reacquisition"],"not_run")

    def test_pid_count_order_and_metadata_identity_are_exact(self):
        for alteration in ("pid","boolpid","remove","extra","reorder","id","bytesize"):
            def mutate(s,r,b,c):
                if s.mode!="success":return
                if alteration=="pid":r["results"][3]["pid"]+=1
                elif alteration=="boolpid":r["results"][0]["pid"]=True
                elif alteration=="remove":r["results"].pop()
                elif alteration=="extra":r["results"].append({})
                elif alteration=="reorder":r["results"][1:3]=reversed(r["results"][1:3])
                elif alteration=="id":r["results"][1]["item"]["ID"]="302"
                else:r["results"][1]["item"]["Size"]=False
            self.assertIn("filefabric_session_batch_results",self.scenario(mutate=mutate).execute()["errors"])

    def test_exact_event_graph_counters_and_no_early_recovery(self):
        for mode in ("success","deny","reuse"):
            for alteration in ("event","count","member","bytes","budget","token"):
                def mutate(s,r,b,c):
                    if s.mode!=mode:return
                    state=s.active
                    if alteration=="event":state.events=state.events[1:]
                    elif alteration=="count":state.grant_attempts+=1
                    elif alteration=="member":state.events[-1]=(state.events[-1][0],"nested/bytes.bin")
                    elif alteration=="bytes":state.payload_bytes+=1
                    elif alteration=="budget":state.budget_exceeded=True
                    elif mode=="deny":state.issued_token="unexpected-B"
                    else:state.phase="wrong"
                row=self.scenario(mutate=mutate).execute()
                self.assertTrue(row["errors"],(mode,alteration))

    def test_saved_config_requires_real_disk_changes_and_only_allowed_scope(self):
        for alteration in ("token","expiry","version","root","url","permanent","extra","backup","malformed","duplicate"):
            def mutate(s,r,b,c):
                if s.mode!="success":return
                text=c.read_text()
                if alteration=="token":text=text.replace("token = synthetic-issued-B","token = "+s.active.token)
                elif alteration=="expiry":text=text.replace("2026-10-04T12:57:03+11:00","2026-10-04T12:57:04+11:00")
                elif alteration=="version":text=text.replace("version = 2006.02","version = 2006.01")
                elif alteration=="root":text=text.replace("root_folder_id = 100","root_folder_id = 0")
                elif alteration=="url":text=text.replace("127.0.0.1","example.invalid")
                elif alteration=="permanent":text=text.replace(s.active.permanent_token,"changed")
                elif alteration=="extra":text+="[Other]\ntype = local\n"
                elif alteration=="backup":(c.parent/"session.conf.old123").write_text("synthetic leftover")
                elif alteration=="malformed":text="not ini"
                else:text+="token = duplicate\n"
                c.write_text(text)
            row=self.scenario(mutate=mutate).execute()
            self.assertTrue(row["errors"],alteration)
            self.assertEqual(row["capabilities"]["saved_token_reuse"],"not_run")

    def test_expiry_normalizes_offset_and_rejects_naive_unknown_offset_and_clock_anomalies(self):
        state=SimpleNamespace(issued_token="B",expiry_lower=datetime(2026,1,1,0,0,0,100000,tzinfo=timezone.utc),
                              grant_upper=datetime(2026,1,1,0,0,0,900000,tzinfo=timezone.utc),expiry_lower_monotonic=1.,grant_upper_monotonic=1.8)
        original={"token":"A","token_expiry":"old","version":"2006.01","url":"http://127.0.0.1:1234"}
        saved={**original,"token":"B","token_expiry":"2026-01-01T00:55:00Z","version":"2006.02"}
        for valid in ("2026-01-01T00:55:00Z","2026-01-01T11:55:00+11:00","2025-12-31T19:55:00-05:00"):
            self.assertTrue(L.filefabric_session_saved_config(state,original,{**saved,"token_expiry":valid}))
        for wrong in ("2026-01-01T00:55:00","2026-01-01T00:55:00-00:00","2026-01-01T00:55:00+24:00","2026-01-01T00:55:00.1Z",
                      "2026-01-01T00:54:59Z","2026-01-01T00:55:01Z","invalid"):
            self.assertFalse(L.filefabric_session_saved_config(state,original,{**saved,"token_expiry":wrong}))
        for field,value in (("grant_upper",state.expiry_lower-timedelta(seconds=1)),("grant_upper_monotonic",-1.),
                            ("grant_upper_monotonic",10.),("grant_upper_monotonic",float("nan"))):
            changed=copy.copy(state);setattr(changed,field,value)
            self.assertFalse(L.filefabric_session_saved_config(changed,original,saved))

    def test_reuse_disk_and_denial_disk_changes_fail_after_successful_operations(self):
        for mode in ("reuse","deny"):
            def mutate(s,r,b,c):
                if s.mode==mode:c.write_text(c.read_text()+"\n# unexpected rewrite\n")
            self.assertTrue(self.scenario(mutate=mutate).execute()["errors"])

    def test_downloads_need_independent_bytes_and_complete_inventory(self):
        for mode in ("success","reuse","deny"):
            for alteration in ("badbytes","extra","directory"):
                def mutate(s,r,b,c):
                    if s.mode!=mode:return
                    folder=s.root/("deny" if mode=="deny" else "success")/{"success":"downloads","reuse":"reuse-downloads","deny":"denied-downloads"}[mode]
                    if alteration=="directory":(folder/"unexpected-dir").mkdir()
                    else:(folder/(NAME if alteration=="badbytes" else "extra")).write_bytes(b"bad")
                self.assertTrue(self.scenario(mutate=mutate).execute()["errors"],(mode,alteration))

    def test_final_checks_detect_late_prior_source_config_or_download_changes(self):
        for alteration in ("source","config","download","permanent","lifetime"):
            def after(s,state):
                if not state.deny:return
                if alteration=="source":s.states[0].files["nested/bytes.bin"]=b"changed"
                elif alteration=="permanent":s.states[0].permanent_token="changed"
                elif alteration=="lifetime":s.states[0].lifetime_requests=129
                elif alteration=="config":(s.root/"success"/"config"/"session.conf").write_text("changed")
                else:(s.root/"success"/"downloads"/NAME).write_bytes(b"changed")
            self.assertTrue(self.scenario(after=after).execute()["errors"],alteration)

    def test_owned_child_listener_and_handler_cleanup_failure_stays_failed(self):
        self.assertEqual(self.scenario().execute(closed=False)["capabilities"]["cleanup"],"failed")
        for alteration in ("extra","pending","forced","bool"):
            def mutate(s,r,b,c):
                if s.mode!="success":return
                if alteration=="extra":s.extra_child=True
                elif alteration=="pending":s.pending=True
                else:s.code=-9 if alteration=="forced" else False
            row=self.scenario(mutate=mutate).execute()
            self.assertTrue(row["errors"])
            if alteration=="pending":self.assertEqual(row["capabilities"]["cleanup"],"failed")
        def after(s,state):state.cleanup_complete=False
        self.assertEqual(self.scenario(after=after).execute()["capabilities"]["cleanup"],"failed")

    def test_private_config_extra_files_duplicate_sections_and_hardlinks_rejected(self):
        folder=self.root/"config";folder.mkdir()
        path=folder/"session.conf"
        valid="[Synthetic]\ntype = filefabric\nurl = http://127.0.0.1:1\nroot_folder_id = 100\npermanent_token = P\ntoken = A\ntoken_expiry = 2030-01-01T00:00:00Z\nversion = 2006.01\n"
        for wrong in (valid+"[Synthetic]\n",valid+"token = duplicate\n",valid+"[DEFAULT]\nx = value\n",valid+"extra = value\n"):
            path.write_text(wrong);path.chmod(0o600)
            with self.assertRaises(L.LabError):L.filefabric_session_config(path)
        path.write_text(valid);path.chmod(0o600)
        os.link(path,self.root/"hardlink")
        with self.assertRaises(L.LabError):L.filefabric_session_config(path)

    def test_schema2_producer_has_only_exact_session_capabilities_and_sticky_failures(self):
        identity={"version":"1.75.1","sha256":"a"*64}
        for failure in (None,"scenario","cleanup"):
            runtime=mock.Mock()
            runtime.run.return_value=(0,b"rclone v1.75.1\n",b"")
            runtime.close.return_value=failure!="cleanup"
            def execute(actual_runtime,root,row,expected):
                self.assertIs(actual_runtime,runtime)
                self.assertEqual(row["fixture_mode"],"filefabric_later_call_renewal_v1")
                self.assertEqual(set(row["capabilities"]),CAPS)
                self.assertEqual(expected,L.fixture_manifest())
                if failure=="scenario":
                    row["capabilities"]["cleanup"]="failed"
                    raise L.LabError("synthetic_session_failure")
                for name in CAPS:row["capabilities"][name]="passed"
            report_path=self.root/(str(failure)+"-report.json")
            with mock.patch.object(L,"verified_runtime",return_value=(self.root/"not-executed",identity,"windows")), \
                 mock.patch.object(L,"Runtime",return_value=runtime),mock.patch.object(L,"filefabric_session_checks",execute):
                report=L.run_filefabric_renewal(self.root/"not-executed",report_path)
            self.assertEqual(report["schema_version"],2)
            self.assertEqual(set(report),{"schema_version","scope","runtime","harness_sha256","fixture_manifest_sha256",
                                        "started_utc","finished_utc","platform","success","cleanup_passed","backends","errors"})
            self.assertEqual(len(report["backends"]),1)
            self.assertEqual(set(report["backends"][0]),{"backend","fixture_kind","fixture_mode","capabilities","errors"})
            self.assertEqual(report["success"],failure is None)
            self.assertEqual(json.loads(report_path.read_text()),report)
            if failure=="scenario":
                self.assertEqual(report["backends"][0]["capabilities"]["cleanup"],"failed")
                self.assertEqual(report["backends"][0]["capabilities"]["saved_token_reuse"],"not_run")
            runtime.close.assert_called_once()

    def test_cli_new_mode_is_explicit_mutually_exclusive_and_baseline_default_unchanged(self):
        result={"success":True,"cleanup_passed":True,"backends":[{}]}
        with mock.patch.object(L,"run_lab",return_value=result) as baseline,mock.patch.object(L,"run_filefabric_renewal",return_value=result) as renewal, mock.patch("builtins.print"):
            with mock.patch.object(sys,"argv",["lab","--rclone","pinned","--report","fresh"]):self.assertEqual(L.main(),0)
            baseline.assert_called_once();renewal.assert_not_called()
            with mock.patch.object(sys,"argv",["lab","--rclone","pinned","--report","fresh","--backends",""]),mock.patch("sys.stderr"):
                with self.assertRaises(SystemExit):L.main()
            baseline.assert_called_once()
            with mock.patch.object(sys,"argv",["lab","--rclone","pinned","--report","fresh","--filefabric-renewal"]):self.assertEqual(L.main(),0)
            renewal.assert_called_once()
            with mock.patch.object(sys,"argv",["lab","--rclone","pinned","--report","fresh","--filefabric-renewal","--backends","filefabric"]),mock.patch("sys.stderr"):
                with self.assertRaises(SystemExit):L.main()


if __name__=="__main__":unittest.main()
