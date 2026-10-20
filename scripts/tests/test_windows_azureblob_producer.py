"""Pure manifest/error checks and fake owned process/fixture boundaries only."""
from contextlib import ExitStack
from copy import deepcopy
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

PATH = Path(__file__).resolve().parents[1] / "application-lab/run_windows_azureblob.py"
P = types.ModuleType("azureblob_producer_test"); P.__file__ = str(PATH)
exec(compile(PATH.read_bytes(), str(PATH), "exec"), P.__dict__)
TEST = types.ModuleType("azureblob_synthetic_receipts")
TEST.__file__ = str(Path(__file__).with_name("test_azureblob_application_evidence.py"))
exec(compile(Path(TEST.__file__).read_bytes(), TEST.__file__, "exec"), TEST.__dict__)
RUNTIME = TEST.RUNTIME
ENDPOINT = "http://127.0.0.1:1234/"


def denial():
    return ("Cannot stat source: 2026/10/15 12:00:00 NOTICE: Failed to rc: loopback: call failed: HEAD "
        + ENDPOINT + "syntheticaccount/synthetic-container/nested%2Fspace%20name.txt\n" + "-"*80
        + "\nRESPONSE 403: 403 Forbidden\nERROR CODE: AuthenticationFailed\n" + "-"*80
        + "\nResponse contained no body\n" + "-"*80 + "\n")


def download_denial(endpoint=ENDPOINT,stamp="2026/10/15 12:00:00"):
    return (stamp + " NOTICE: Failed to rc: loopback: call failed: failed to open source object: "
        "failed to open for download: GET " + endpoint + "syntheticaccount/synthetic-container/nested%2Fspace%20name.txt\n" + "-"*80
        + "\nRESPONSE 403: 403 Forbidden\nERROR CODE: AuthorizationFailure\n" + "-"*80
        + "\nResponse contained no body\n" + "-"*80)


def snapshot(name, action="finish", finished=True):
    n = 1 if name == "denial" else 2
    value = dict(schema_version=3, action=action, ok=True, state="finished" if finished else "running",
        app_exit_code=(0 if name == "acquisition" else 1) if finished else None,
        runtime_image_observed=False, runtime_sha256=None, runtime_process_count=None, ctrl_c_sent=False,
        output_bytes=0, output_limit_exceeded=False, forced_termination=False, errors=[], observation_kind="launch_image",
        launch_image_observed=True, launch_sha256=RUNTIME["sha256"], runtime_launch_count=n, peak_runtime_processes=1,
        system_helper_image_observed=False, system_helper_sha256=None, system_helper_launch_count=0,
        peak_system_helper_processes=0, debug_event_count=100)
    value.update(dict.fromkeys((*P.H.SESSION_CLEANUP, *P.C.OBSERVED_CLEANUP), finished))
    return value


class FakeBridge:
    def __init__(self, name):
        self.name, self.commands, self.last = name, [], None
        self.observer_started = False
        self.close = Mock(return_value=True)

    def command(self, action, **fields):
        self.commands.append((action, fields))
        if action in {"ready", "close_ready"}:
            self.last = dict(schema_version=1, action=action, ok=True, state="ready" if action == "ready" else "closed")
        else:
            self.observer_started = True
            self.last = snapshot(self.name, action, action != "start_source_observed")
        return self.last


class ProducerTests(unittest.TestCase):
    def test_host_guard_precedes_input_and_fixture(self):
        with patch.object(P.H,"hosted_guard",side_effect=P.ProducerError("binding_failed")), patch.object(P.E,"compute_bindings") as bind:
            with self.assertRaises(P.ProducerError): P.run("not-read","0"*64,"1"*40)
            bind.assert_not_called()

    def test_config_and_queue_fixed_scope_without_retry_override(self):
        key=base64.b64encode(bytes(range(32))).decode()
        config=P.config_bytes(ENDPOINT,key)
        for line in (b"env_auth = false\n", b"use_emulator = true\n", b"use_arrow_list = false\n",
                     b"account = syntheticaccount\n", b"endpoint = http://127.0.0.1:1234/syntheticaccount\n"):
            self.assertIn(line,config)
        for token in (b"retries",b"buffer_size",b"bwlimit",b"sas_url",b"client_secret"):
            self.assertNotIn(token,config)
        self.assertIn(b"synthetic-container/nested/space name.txt,26,",P.queue_bytes())
        self.assertIn(b"e019c52fe70badce27affda5e408659399ff764985f07104029a42ade38125bd",P.queue_bytes())
        for endpoint in ("http://localhost:1234/","http://127.0.0.1:0/","http://127.0.0.1:65536/",ENDPOINT+"x\n"):
            with self.assertRaises(P.ProducerError): P.config_bytes(endpoint,key)
        for bad in ("private canary",key+"\n",base64.b64encode(b"short").decode(),None):
            with self.assertRaises(P.ProducerError): P.config_bytes(ENDPOINT,bad)
        for name in (*P.CASE_DIRECTORIES.values(),"app-http-"+"a"*32):
            self.assertIn(P.H.setup_scope(name),P.H.SETUP_SCOPES)

    def test_multiline_denial_is_exact_and_bound_to_owned_head_url(self):
        good=denial();self.assertTrue(P.exact_stat_denial(good,ENDPOINT))
        for old,new in (("Cannot stat source: ",""),("HEAD ","GET "),("1234/","1235/"),("%2F","/"),
                        ("403 Forbidden","401 Unauthorized"),("AuthenticationFailed","AuthorizationFailure"),
                        ("Response contained no body","PRIVATE-CANARY"),("-"*80,"-"*79)):
            self.assertFalse(P.exact_stat_denial(good.replace(old,new),ENDPOINT),(old,new))
        for value in (None,"exit 1",good+"private canary",good+good,good.replace("\n","\r\n"),good+"\x00","x"*65537):
            self.assertFalse(P.exact_stat_denial(value,ENDPOINT))

    def test_download_denial_exact_single_stderr_block_and_calendar(self):
        good=download_denial();self.assertTrue(P.exact_download_denial(good,ENDPOINT))
        for stamp in ("2000/02/29 00:00:00","2026/12/31 23:59:59"):
            self.assertTrue(P.exact_download_denial(download_denial(stamp=stamp),ENDPOINT))
        for stamp in ("2026/02/29 12:00:00","2026/13/01 12:00:00","2026/01/01 24:00:00","0000/01/01 12:00:00"):
            self.assertFalse(P.exact_download_denial(download_denial(stamp=stamp),ENDPOINT))
        for old,new in (("failed to open source object: ",""),("failed to open for download: ",""),
                ("GET ","HEAD "),("1234/","1235/"),("%2F","/"),("%20"," "),("403 Forbidden","401 Unauthorized"),
                ("AuthorizationFailure","AuthenticationFailed"),("Response contained no body","PRIVATE-CANARY"),
                ("-"*80,"-"*79),("NOTICE: Failed to rc:","ERROR : Failed to copy:"),
                ("loopback: call failed:","loopback: 2 errors:")):
            self.assertFalse(P.exact_download_denial(good.replace(old,new),ENDPOINT),(old,new))
        for value in (None,"exit 1",denial(),"Cannot stat source: "+good,good+"\n",good+good,
                      good+"\ncleanup failed",good.replace("\n","\r\n"),good+"\x00",good+"\x1b[0m","x"*65537,
                      "\n".join(good.split("\n")[:-1]),"ERROR : Failed to copy: private\n"+good):
            self.assertFalse(P.exact_download_denial(value,ENDPOINT))
        for endpoint in ("http://localhost:1234/","http://127.0.0.1:0/","http://127.0.0.1:65536/","http://127.0.0.1:01234/",ENDPOINT+"x"):
            self.assertFalse(P.exact_download_denial(download_denial(endpoint),endpoint))

    def test_observation_counts_and_every_cleanup_flag_are_required(self):
        for name in ("acquisition","denial","download_denial"):
            bridge=FakeBridge(name);bridge.last=snapshot(name)
            self.assertTrue(P.cleanup_proved(bridge,True,name,RUNTIME))
            self.assertEqual(P.observed_final(bridge.last,name,RUNTIME)["runtime_launch_count"],1 if name=="denial" else 2)
            for key in (*P.H.SESSION_CLEANUP,*P.C.OBSERVED_CLEANUP):
                bridge.last=snapshot(name);bridge.last[key]=False
                try: okay=P.cleanup_proved(bridge,True,name,RUNTIME)
                except (P.ProducerError,P.C.H.ProducerError): okay=False
                self.assertFalse(okay,key)
            for changed in (dict(snapshot(name),runtime_launch_count=3),dict(snapshot(name),launch_sha256="f"*64),
                            dict(snapshot(name),forced_termination=True)):
                with self.assertRaises((P.ProducerError,P.C.H.ProducerError)): P.observed_final(changed,name,RUNTIME)
            for code in P.CLEANUP_UNCERTAIN:
                bridge.last=dict(snapshot(name),ok=False,errors=[code])
                self.assertFalse(P.cleanup_proved(bridge,True,name,RUNTIME))

    def test_ready_only_and_start_attempted_cleanup_are_not_interchangeable(self):
        ready=FakeBridge("acquisition");ready.command("ready")
        self.assertTrue(P.close_session(ready,True,False,"acquisition",RUNTIME))
        self.assertEqual([a for a,_ in ready.commands],["ready","close_ready"]);ready.close.assert_called_once()
        uncertain=FakeBridge("acquisition");uncertain.command("ready")
        with self.assertRaises((P.ProducerError,P.C.H.ProducerError)):
            P.close_session(uncertain,True,True,"acquisition",RUNTIME)
        uncertain.close.assert_called_once();self.assertEqual(len(uncertain.commands),1)
        malformed=FakeBridge("acquisition");malformed.command=Mock(side_effect=KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt): P.close_session(malformed,True,False,"acquisition",RUNTIME)
        malformed.close.assert_called_once()

    def test_manifest_independent_bytes_and_denial_null_fields(self):
        for name in ("acquisition","denial","download_denial"):
            positive=name=="acquisition";f=P.E.fixture_manifest()
            case=Path("C:/synthetic-private");base=case/"output"/P.H.CASE_NAME
            destination=base/"downloads/Synthetic"/f["member"];working=base/"config/working.conf"
            stem="acquisition-20261015T120000.000"
            request=dict(source="Synthetic:"+f["member"],destination=str(destination),mode="CopyTo",
                expected_hash=f["sha256"],expected_hash_type="sha256",expected_size=26)
            result=dict(local_sha256=f["sha256"] if positive else None,integrity="Verified" if positive else "Failed",
                source=request["source"],destination=str(destination),success=positive,error=None if positive else download_denial() if name=="download_denial" else denial(),
                size=26 if positive else None,hash=f["sha256"] if positive else None,hash_type="sha256" if positive else None,
                hash_verified=True if positive else None,hash_error=None)
            original=dict(schema_version=1,written_at="2026-10-15T12:00:00Z",rclone_version=RUNTIME["version"],
                config_path=str(working),plan=dict(files=[dict(remote_name="Synthetic",path=f["member"],request=request)],
                skipped_directories=0),results=[result],complete=positive)
            inventory={p:(True,) for p in ("logs","downloads","listings","config")}
            inventory.update({p:(False,) for p in (stem+".json",stem+".txt","logs/"+stem+".log",
                "logs/"+stem+".checkpoint.json","config/working.conf","config/source.conf")})
            wanted={"Synthetic/"+f["member"]:()} if positive else {}
            if positive:
                inventory.update({p:(True,) for p in ("downloads/Synthetic","downloads/Synthetic/synthetic-container",
                    "downloads/Synthetic/synthetic-container/nested")})
                inventory["downloads/Synthetic/"+f["member"]]=(False,)
            mutations=(None,"hash","bytes","residue","source") if positive else (None,"null_size","null_hash","null_local_sha256","null_hash_value","null_hash_type","null_hash_error","cause","generic_exit","stat_error","residue","source","complete","success","integrity","payload")
            for mutation in mutations:
                value=deepcopy(original);inv=dict(inventory);body=b"Nested synthetic payload.\n"
                if mutation=="hash":value["results"][0]["local_sha256"]="f"*64
                if mutation=="bytes":body=b"x"*26
                if mutation=="null_size":value["results"][0]["size"]=0
                if mutation=="null_hash":value["results"][0]["hash_verified"]=False
                for tag,field in (("null_local_sha256","local_sha256"),("null_hash_value","hash"),("null_hash_type","hash_type"),("null_hash_error","hash_error")):
                    if mutation==tag:value["results"][0][field]="unexpected"
                if mutation=="cause":value["results"][0]["error"]=original["results"][0]["error"].replace("Failed","Other").replace("AuthorizationFailure","Other")
                if mutation=="stat_error":value["results"][0]["error"]=denial() if name=="download_denial" else download_denial()
                if mutation=="complete":value["complete"]=True
                if mutation=="success":value["results"][0]["success"]=True
                if mutation=="integrity":value["results"][0]["integrity"]="Verified"
                if mutation=="generic_exit":value["results"][0]["error"]="exit 1"
                if mutation=="residue":inv["downloads/.triage-transfer/partial"]=(False,)
                if mutation=="source":value["plan"]["files"][0]["request"]["source"]+="-other"
                outer={P.H.CASE_NAME:(True,),**{P.H.CASE_NAME+"/"+p:v for p,v in inv.items()}}
                with patch.object(P.H,"inventory",side_effect=lambda p:inv if p==base else outer), \
                     patch.object(P.H,"read",side_effect=lambda p,*a:json.dumps(value).encode() if p.suffix==".json" else body), \
                     patch.object(P.H,"same_path",side_effect=lambda a,b:str(a)==str(b)),patch.object(P.H,"output_files",return_value={"Synthetic/"+f["member"]:()} if mutation=="payload" else wanted):
                    if mutation is None:self.assertTrue(all(P.manifest(name,case,working,RUNTIME,ENDPOINT).values()))
                    else:
                        with self.assertRaises(P.ProducerError):P.manifest(name,case,working,RUNTIME,ENDPOINT)

    def test_execute_ordered_single_start_and_cleanup_failures(self):
        for name,broken in (("acquisition",None),("denial",None),("download_denial",None),("download_denial","fixture_close"),("download_denial","session_close"),("acquisition","fixture_close"),("denial","session_close"),("acquisition","setup")):
            with tempfile.TemporaryDirectory() as directory,ExitStack() as mocks:
                suite=Path(directory);app=suite/"input.bin";app.write_bytes(b"inert");sha=hashlib.sha256(b"inert").hexdigest()
                bridge=FakeBridge(name);order=[];original=bridge.command
                def command(action,**kw):order.append(action);return original(action,**kw)
                bridge.command=command
                if broken=="session_close":bridge.close.return_value=False
                state=Mock(case=name);state.snapshot.return_value=TEST.fixture(name)
                state_factory=Mock(return_value=state)
                server=Mock(endpoint=ENDPOINT,deadline=P.time.monotonic()+60)
                context=Mock();context.__enter__=Mock(side_effect=lambda:(order.append("fixture_start"),server)[1])
                context.__exit__=Mock(side_effect=P.F.FixtureError("cleanup_failed") if broken=="fixture_close" else None)
                extra=("manifest_exact","output_hash_exact","outputs_exact") if name=="acquisition" else ("manifest_exact","no_download_outputs")
                def prepare(parent,child,action="Create"):
                    if action=="Create":(parent/child).mkdir()
                def source(case):(case/"source").mkdir();return P.H.identity(case/"source")
                removed=Mock()
                for obj,key,value in ((P.H,"prepare",prepare),(P.H,"create_private_roots",lambda c:{}),
                        (P.H,"private_directory",lambda c,n:(c/n).mkdir()),(P.H,"private_write",lambda c,n,b:(c/n).write_bytes(b)),
                        (P.H,"environment",lambda c:{}),(P,"create_source",source),(P.C,"ObservedSourceBridge",lambda c:bridge),
                        (P.H,"application_roots_empty",Mock()),(P.H,"helper_baseline",lambda *a:{}),(P.H,"helper_cleanup_preserved",Mock()),
                        (P.H,"configuration_preserved",lambda c,v:c/"working.conf"),(P,"manifest",lambda *a:dict.fromkeys(extra,True)),
                        (P.W,"fingerprint",lambda c:"a"*64),(P,"preserved",Mock()),(P.H,"remove_owned",removed),
                        (P,"fixture_closed",lambda s:broken!="fixture_close"),(P.F,"AppAzureBlobState",state_factory),(P.F,"serve_azureblob",lambda s:context)):
                    mocks.enter_context(patch.object(obj,key,value))
                if broken=="setup":mocks.enter_context(patch.object(P.secrets,"token_bytes",side_effect=KeyboardInterrupt()))
                errors=[];item=P.execute(name,suite,app,sha,RUNTIME,errors);row=item["record"]
                bridge.close.assert_called_once()
                if broken is None:
                    self.assertEqual(errors,[]);self.assertTrue(all(v for k,v in row["checks"].items() if k!="group_finalized"))
                    self.assertLess(order.index("ready"),order.index("fixture_start"))
                    starts=[f for a,f in bridge.commands if a=="start_source_observed"]
                    self.assertEqual(len(starts),1);self.assertEqual(starts[0]["max_runtime_launches"],1 if name=="denial" else 2)
                    self.assertLessEqual(starts[0]["deadline_ms"],60000);context.__exit__.assert_called_once();removed.assert_called_once()
                    self.assertFalse(any("retries" in arg for arg in starts[0]["args"]))
                    _,correct,wrong=state_factory.call_args.args
                    saved=(suite/P.CASE_DIRECTORIES[name]/"source.conf").read_bytes()
                    self.assertIn(("key = "+(wrong if name=="denial" else correct)+"\n").encode("ascii"),saved)
                else:
                    self.assertTrue(errors);self.assertFalse(row["checks"]["group_finalized"])
                    if broken=="setup":
                        self.assertEqual(order,["ready","close_ready"]);self.assertTrue(row["checks"]["temp_cleanup"])
                    else:removed.assert_not_called();self.assertFalse(row["checks"]["temp_cleanup"])

    def test_run_stops_on_failure_and_late_binding_removes_credit(self):
        for early,late in ((False,False),(True,False),(False,True)):
            calls=[]
            def execute(name,*args):
                calls.append(name);row=deepcopy(TEST.receipt()["cases"][name]);row["status"]="failed";row["checks"]["group_finalized"]=False
                if early:P.mark(row,"session_failed",args[-1])
                return dict(name=name,record=row,artifact="a"*64)
            with ExitStack() as mocks:
                for obj,key,value in ((P.H,"hosted_guard",Mock()),(P.E,"runtime_binding",lambda r:RUNTIME),
                        (P.E,"compute_bindings",lambda *a:TEST.BINDINGS),(P.H,"prepare",Mock()),(P.H,"identity",lambda p:(1,2)),
                        (P.H,"inventory",lambda p:{}),(P.H,"remove_owned",Mock()),(P,"execute",execute)):
                    mocks.enter_context(patch.object(obj,key,value))
                mocks.enter_context(patch.dict(P.os.environ,{"RUNNER_TEMP":str(Path.cwd()),"GITHUB_SHA":TEST.BINDINGS["build_commit"]}))
                mocks.enter_context(patch.object(P,"bindings",side_effect=[TEST.BINDINGS,P.ProducerError("preservation_failed") if late else TEST.BINDINGS]))
                receipt=P.run("not-read",TEST.BINDINGS["application_sha256"],TEST.BINDINGS["build_commit"])
                self.assertEqual(calls,list(P.E.CASES[:1] if early else P.E.CASES))
                self.assertEqual(receipt["result"],"failed" if early or late else "passed")
                if early or late:self.assertNotIn("passed",receipt["capabilities"].values())

    def test_download_mode_stops_unfinalized_control_before_denial_and_retains_late_failure(self):
        mode=P.E.DOWNLOAD_DENIAL_MODE
        for broken in (None,"output_hash_exact","configuration_preserved","source_preserved","process_cleanup",
                       "fixture_cleanup","temp_cleanup","artifact","late_binding"):
            calls=[]
            def execute(name,*args):
                calls.append(name);row=deepcopy(TEST.receipt(mode)["cases"][name])
                row["status"]="failed";row["checks"]["group_finalized"]=False
                if name=="acquisition" and broken in row["checks"]:row["checks"][broken]=False
                if name=="acquisition" and broken in {"process_cleanup","fixture_cleanup"}:row["checks"]["temp_cleanup"]=False
                return dict(name=name,record=row,artifact=None if broken=="artifact" else "a"*64)
            with ExitStack() as mocks:
                for obj,key,value in ((P.H,"hosted_guard",Mock()),(P.E,"runtime_binding",lambda r:RUNTIME),
                        (P.E,"compute_bindings",lambda *a:TEST.BINDINGS),(P.H,"prepare",Mock()),(P.H,"identity",lambda p:(1,2)),
                        (P.H,"inventory",lambda p:{}),(P.H,"remove_owned",Mock()),(P,"execute",execute)):
                    mocks.enter_context(patch.object(obj,key,value))
                mocks.enter_context(patch.dict(P.os.environ,{"RUNNER_TEMP":str(Path.cwd()),"GITHUB_SHA":TEST.BINDINGS["build_commit"]}))
                mocks.enter_context(patch.object(P,"bindings",side_effect=[TEST.BINDINGS,P.ProducerError("preservation_failed") if broken=="late_binding" else TEST.BINDINGS]))
                value=P.run("not-read",TEST.BINDINGS["application_sha256"],TEST.BINDINGS["build_commit"],mode)
            self.assertEqual(calls,["acquisition","download_denial"] if broken in (None,"late_binding") else ["acquisition"])
            self.assertEqual(value["result"],"passed" if broken is None else "failed")
            if broken is not None:self.assertNotIn("passed",value["capabilities"].values())

    def test_config_queue_source_and_artifact_preservation_are_independent(self):
        case=Path("C:/synthetic-private");config=b"synthetic config"
        item=dict(case=case,lease=(1,2),source=(2,3),config=config,artifact="a"*64,record=dict(checks=dict(configuration_preserved=True)))
        for broken in (None,"config","queue","app","artifact","source","identity"):
            def read(path,*a):
                if path.name=="application.exe":return b"changed" if broken=="app" else b"app"
                if path.name=="source.conf":return b"changed" if broken=="config" else config
                return b"changed" if broken=="queue" else P.queue_bytes()
            with patch.object(P.H,"identity",side_effect=lambda path:(0,0) if broken=="identity" else item["lease"] if path==case else item["source"]), \
                 patch.object(P.H,"inventory",return_value={"extra":()} if broken=="source" else {}),patch.object(P.H,"read",side_effect=read), \
                 patch.object(P.H,"configuration_preserved"),patch.object(P.W,"fingerprint",return_value="b"*64 if broken=="artifact" else "a"*64):
                if broken is None:P.preserved(item,P.H.sha(b"app"))
                else:
                    with self.assertRaises(P.ProducerError):P.preserved(item,P.H.sha(b"app"))


if __name__=="__main__":unittest.main()
