"""Pure listing contracts and fake owned lifecycle; no live transport."""
from contextlib import ExitStack
from copy import deepcopy
import base64
import csv
import hashlib
import hmac
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qsl, urlsplit
import xml.etree.ElementTree as ET
import test_azureblob_application_evidence as old_e
import test_azureblob_application_fixture as old_f
import test_windows_azureblob_producer as old_p
import test_azureblob_application_workflow as workflow
E,F,P=old_e.E,old_f.F,old_p.P
ACCOUNT="/syntheticaccount?comp=list&include=deleted%2Cmetadata&maxresults=5000"
FLAT="/syntheticaccount/synthetic-container?comp=list&delimiter=&include=metadata&maxresults=5000&prefix=&restype=container"


def state():
    return F.AppAzureBlobListingState(base64.b64encode(old_f.KEY).decode(),base64.b64encode(old_f.WRONG).decode(),lambda:old_f.NOW)


def signed(target,key=old_f.KEY,date=None):
    # Independent canonical string; never call the fixture signer.
    h={"host":"127.0.0.1:1234","x-ms-date":date or old_f.format_datetime(old_f.NOW,usegmt=True),"x-ms-version":"2026-06-06"}
    url=urlsplit(target);query={}
    for k,v in parse_qsl(url.query,keep_blank_values=True):query.setdefault(k.lower(),[]).append(v)
    fields=["GET"]+[""]*11+["\n".join(k+":"+h[k] for k in sorted(h) if k.startswith("x-ms-")),
        "/syntheticaccount"+url.path+"".join("\n"+k+":"+",".join(sorted(v)) for k,v in sorted(query.items()))]
    h["authorization"]="SharedKey syntheticaccount:"+base64.b64encode(hmac.new(key,"\n".join(fields).encode(),hashlib.sha256).digest()).decode()
    return h


def exchange(s,target):
    r=s.begin("GET",target,signed(target));wire=s.response(r);s.commit(r,len(wire));return wire


def fixture():
    return dict(case="listing",requests=2,payload_bytes=0,response_bytes=2000,source_preserved=True,errors=[],events=[
        dict(ordinal=i+1,kind=k,role=r,status=200,object_bytes=0) for i,(k,r) in enumerate(
        (("account_authenticated","account"),("listing_authenticated","flat")))])


def receipt():
    v=old_e.receipt();row=v["cases"]["acquisition"]
    row.update(checks=dict.fromkeys(E.CHECKS["listing"],True),fixture=fixture());row["observation"]["runtime_launch_count"]=1
    v.update(fixture_mode=E.LIST_MODE,cases={"listing":row},claims=dict.fromkeys(E.false_claims(E.LIST_MODE),False))
    v["capabilities"]=E.derive_capabilities(v["cases"],True,E.LIST_MODE);return v


def csv_bytes(rows=None):
    stream=io.StringIO(newline="");w=csv.writer(stream,lineterminator="\r\n");w.writerow(P.H.HEADERS)
    w.writerows(E.listing_rows() if rows is None else rows);return b"\xef\xbb\xbf"+stream.getvalue().encode()


class ListingTests(unittest.TestCase):
    def validate(self,v):return E.validate_receipt(v,old_e.RUNTIME,old_e.BINDINGS,now=old_e.NOW,mode=E.LIST_MODE)
    def reject(self,v):
        with self.assertRaises((ValueError,TypeError,E.A.ApplicationEvidenceError)):self.validate(v)

    def test_distinct_mode_oracle_and_unchanged_old_claims(self):
        v=receipt();self.assertIs(self.validate(v),v);self.assertEqual(E.mode_cases(E.LIST_MODE),("listing",))
        self.assertEqual([r[2] for r in E.listing_rows()],["synthetic-container","synthetic-container/nested","synthetic-container/README-synthetic.txt","synthetic-container/empty.txt","synthetic-container/nested/space name.txt"])
        self.assertEqual([r[3] for r in E.listing_rows()],["","","20","0","26"])
        for mode in (E.MODE,E.DOWNLOAD_DENIAL_MODE):
            old=old_e.receipt(mode);E.validate_receipt(old,old_e.RUNTIME,old_e.BINDINGS,now=old_e.NOW,mode=mode)
            self.assertIs(old["claims"]["listing_verified"],False);self.reject(old)
        for claim in ("listing_verified","provider_accepted","vendor_accepted","ledger_eligible"):
            bad=deepcopy(v);bad["claims"][claim]=True;self.reject(bad)

    def test_all_checks_cleanup_and_typed_launches_required(self):
        for key in E.CHECKS["listing"]:
            for bad in (False,None,1):
                v=receipt();v["cases"]["listing"]["checks"][key]=bad;self.reject(v)
        for key in E.GROUP_CHECKS:
            v=receipt();v["experiment"]["checks"][key]=False;self.reject(v)
        for field,bad in (("exit_code",1),("exit_code",False),("runtime_sha256","f"*64),("continuity",{})):
            v=receipt();v["cases"]["listing"][field]=bad;self.reject(v)
        for field,bad in (("runtime_launch_count",2),("runtime_launch_count",True),("peak_runtime_processes",2)):
            v=receipt();v["cases"]["listing"]["observation"][field]=bad;self.reject(v)

    def test_exact_metadata_sequence_not_exit_or_counter_only(self):
        for field,bad in (("requests",True),("requests",1),("payload_bytes",1),("source_preserved",False),("errors",["worker_failed"]),("events",[])):
            v=receipt();v["cases"]["listing"]["fixture"][field]=bad;self.reject(v)
        for field,bad in (("ordinal",True),("kind","head_authenticated"),("role","container"),("status",201),("object_bytes",False)):
            v=receipt();v["cases"]["listing"]["fixture"]["events"][0][field]=bad;self.reject(v)
        v=receipt();v["cases"]["listing"]["fixture"]["events"].reverse();self.reject(v)
        v=receipt();v["cases"]["listing"]["fixture"]["private"]="PRIVATE-CANARY";self.reject(v)

    def test_exact_csv_mutations_and_partial_exports_rejected(self):
        self.assertTrue(P.listing_csv(csv_bytes()));self.assertTrue(P.listing_csv(csv_bytes(list(reversed(E.listing_rows())))))
        variants=[E.listing_rows()[:-1],E.listing_rows()+E.listing_rows()[:1]]
        for row in range(5):
            for col in range(8):
                rows=deepcopy(E.listing_rows());rows[row][col]="changed";variants.append(rows)
        for rows in variants:
            with self.assertRaises(P.ProducerError):P.listing_csv(csv_bytes(rows))
        for data in (csv_bytes()[3:],b"",b"\xef\xbb\xbf\xff",csv_bytes()+b"extra"):
            with self.assertRaises(P.ProducerError):P.listing_csv(data)

    def test_complete_signed_xml_and_marker_no_object_payload(self):
        s=state();wires=[exchange(s,ACCOUNT),exchange(s,FLAT)]
        for wire in wires:
            head,body=wire.split(b"\r\n\r\n",1);self.assertIn(("Content-Length: "+str(len(body))).encode(),head)
            self.assertIsNone(ET.fromstring(body).find("NextMarker").text)
        self.assertEqual(ET.fromstring(wires[0].split(b"\r\n\r\n",1)[1]).findtext("Containers/Container/Name"),F.CONTAINER)
        blobs=ET.fromstring(wires[1].split(b"\r\n\r\n",1)[1]).findall("Blobs/Blob")
        self.assertEqual([(b.findtext("Name"),int(b.findtext("Properties/Content-Length"))) for b in blobs],[("README-synthetic.txt",20),("empty.txt",0),("nested/space name.txt",26),("nested/",0)])
        E.listing_fixture(s.snapshot(),successful=True);self.assertEqual(s.payload_bytes,0)

    def test_continuation_incomplete_page_aliases_and_malformed_queries_rejected(self):
        variants=[FLAT+"&marker=next",FLAT.replace("maxresults=5000","maxresults=3"),FLAT+"&maxresults=5000",
            FLAT.replace("comp=list","comp=list&comp=list"),FLAT.replace("maxresults=5000","maxresults=True"),
            FLAT.replace("maxresults=5000","maxresults=5001"),FLAT.replace("delimiter=","delimiter=%2F"),
            FLAT.replace("prefix=","prefix=nested%2F"),FLAT.replace("include=metadata","include=snapshots"),FLAT+"&unknown=x",FLAT+"#fragment",
            FLAT.replace("/syntheticaccount/","//syntheticaccount/",1),FLAT.replace("synthetic-container","other"),ACCOUNT.replace("deleted%2Cmetadata","metadata")]
        for target in variants:
            with self.subTest(target=target),self.assertRaises(F.FixtureError):F.listing_route(target)
        self.assertEqual(F.listing_route(FLAT.replace("maxresults=5000","maxresults=4")),"flat")

    def test_authentication_staleness_and_content_routes_fail_closed(self):
        for h in (signed(ACCOUNT,old_f.WRONG),signed(ACCOUNT,date="Mon, 01 Jan 2024 00:00:00 GMT"),dict(signed(ACCOUNT),authorization="invalid"),dict(signed(ACCOUNT),**{"x-ms-range":"bytes=0-1"})):
            s=state()
            with self.assertRaises(F.FixtureError):s.begin("GET",ACCOUNT,h)
            self.assertEqual(s.events,[]);self.assertEqual(s.payload_bytes,0)
        for method,target in (("HEAD",ACCOUNT),("PUT",ACCOUNT),("GET",F.TARGET)):
            with self.assertRaises(F.FixtureError):state().begin(method,target,signed(ACCOUNT))

    def test_mutation_order_and_response_commit_are_strict(self):
        with self.assertRaises(F.FixtureError):state().begin("GET",FLAT,signed(FLAT))
        for mutation in ("body","marker","credential"):
            s=state()
            if mutation=="body":s._files["README-synthetic.txt"]=b"changed"
            elif mutation=="marker":del s._files["nested/"]
            else:s._key=old_f.WRONG
            with self.assertRaises(F.FixtureError):s.begin("GET",ACCOUNT,signed(ACCOUNT))
        s=state();r=s.begin("GET",ACCOUNT,signed(ACCOUNT));wire=s.response(r)
        with self.assertRaises(F.FixtureError):s.commit(r,len(wire)-1)
        self.assertEqual(s.events,[]);s.commit(r,len(wire))
        with self.assertRaises(F.FixtureError):s.commit(r,len(wire))
        with self.assertRaises(F.FixtureError):s.begin("GET",ACCOUNT,signed(ACCOUNT))

    def test_parser_keeps_strict_headers_host_body_and_wire_target(self):
        obj,_=old_f.server(state());obj.__class__=F._ListingServer
        wire=("GET "+ACCOUNT+" HTTP/1.1\r\n"+"".join(k+": "+v+"\r\n" for k,v in signed(ACCOUNT).items())+"\r\n").encode()
        self.assertEqual(obj._parse(io.BytesIO(wire))[1],ACCOUNT)
        for raw in (wire.replace(b"127.0.0.1:1234",b"other"),wire.replace(b"\r\n\r\n",b"\r\nHost: other\r\n\r\n"),wire.replace(b"\r\n\r\n",b"\r\nContent-Length: 1\r\n\r\n"),wire.replace(b"/syntheticaccount?",b"//syntheticaccount?")):
            with self.assertRaises(F.FixtureError):obj._parse(io.BytesIO(raw))

    def test_final_metadata_commit_wait_keeps_original_deadline(self):
        pending=fixture();pending["events"]=pending["events"][:1];pending["requests"]=1
        s=Mock();s.snapshot.side_effect=[pending,fixture()]
        with patch.object(P.time,"monotonic",return_value=1),patch.object(P.time,"sleep") as sleep:P.listing_committed(s,2);sleep.assert_called_once()
        with patch.object(P.time,"monotonic",return_value=3),self.assertRaises(P.ProducerError):P.listing_committed(Mock(),2)

    def test_workflow_requires_new_mode_and_normalized_artifact(self):
        text=workflow.WORKFLOW.read_text();workflow.validate(text)
        for old,new in (("--fixture-mode azureblob_sharedkey_listing_cli_v1","--fixture-mode azureblob_sharedkey_acquisition_cli_v1"),("name: azureblob-listing-experiment-Windows","name: azureblob-experiment-Windows"),("path: ${{ runner.temp }}/azureblob-listing-validation.json","path: ${{ runner.temp }}/azureblob-listing.private.json")):
            with self.assertRaises((ValueError,KeyError,IndexError)):workflow.validate(text.replace(old,new,1))

    def test_fake_listing_launch_count_no_queue_and_cleanup_faults(self):
        for broken in (None,"setup","session_close","fixture_close","preservation"):
            with tempfile.TemporaryDirectory() as directory,ExitStack() as mocks:
                suite=Path(directory);app=suite/"input.data";app.write_bytes(b"inert");app_sha=hashlib.sha256(b"inert").hexdigest()
                bridge=old_p.FakeBridge("listing");original_snapshot=old_p.snapshot;order=[];original_command=bridge.command
                def snapshot(name,action="finish",finished=True):
                    value=original_snapshot("acquisition",action,finished);value["runtime_launch_count"]=1;return value
                mocks.enter_context(patch.object(old_p,"snapshot",snapshot))
                def command(action,**fields):order.append(action);return original_command(action,**fields)
                bridge.command=command
                if broken=="session_close":bridge.close.return_value=False
                state_fake=Mock();state_fake.snapshot.return_value=fixture()
                server=Mock(endpoint=old_p.ENDPOINT,deadline=P.time.monotonic()+60)
                context=Mock();context.__enter__=Mock(side_effect=lambda:(order.append("fixture_start"),server)[1])
                context.__exit__=Mock(side_effect=P.F.FixtureError("cleanup_failed") if broken=="fixture_close" else None)
                def prepare(parent,child,action="Create"):
                    if action=="Create":(parent/child).mkdir()
                def source(case):(case/"source").mkdir();return P.H.identity(case/"source")
                removed=Mock();preserved=Mock(side_effect=P.ProducerError("preservation_failed") if broken=="preservation" else None)
                for obj,key,value in ((P.H,"prepare",prepare),(P.H,"create_private_roots",lambda c:{}),
                    (P.H,"private_directory",lambda c,n:(c/n).mkdir()),(P.H,"private_write",lambda c,n,b:(c/n).write_bytes(b)),
                    (P.H,"environment",lambda c:{}),(P,"create_source",source),(P.C,"ObservedSourceBridge",lambda c:bridge),
                    (P.H,"application_roots_empty",Mock()),(P.H,"helper_baseline",lambda *a:{}),(P.H,"helper_cleanup_preserved",Mock()),
                    (P.H,"configuration_preserved",lambda c,v:c/"working.conf"),(P,"listing_output",lambda c:dict.fromkeys(("inventory_exact","listing_complete","outputs_exact","no_download_outputs"),True)),
                    (P.W,"fingerprint",lambda c:"a"*64),(P,"preserved",preserved),(P.H,"remove_owned",removed),
                    (P,"fixture_closed",lambda s:broken!="fixture_close"),(P.F,"AppAzureBlobListingState",lambda *a:state_fake),(P.F,"serve_azureblob_listing",lambda s:context)):
                    mocks.enter_context(patch.object(obj,key,value))
                if broken=="setup":mocks.enter_context(patch.object(P.secrets,"token_bytes",side_effect=KeyboardInterrupt()))
                errors=[];item=P.execute("listing",suite,app,app_sha,old_e.RUNTIME,errors);row=item["record"]
                bridge.close.assert_called_once();self.assertFalse((suite/"listing/queue.csv").exists())
                starts=[f for a,f in bridge.commands if a=="start_source_observed"]
                if broken is None:
                    self.assertEqual(errors,[]);self.assertTrue(all(v for k,v in row["checks"].items() if k!="group_finalized"))
                    self.assertEqual(len(starts),1);self.assertEqual(starts[0]["max_runtime_launches"],1)
                    self.assertIn("--list-remote",starts[0]["args"]);self.assertNotIn("--download-from",starts[0]["args"])
                    self.assertLess(order.index("ready"),order.index("fixture_start"));removed.assert_called_once();context.__exit__.assert_called_once()
                else:
                    self.assertTrue(errors);self.assertFalse(row["checks"]["group_finalized"])
                    if broken=="setup":self.assertEqual(order,["ready","close_ready"]);self.assertTrue(row["checks"]["temp_cleanup"])
                    else:removed.assert_not_called();self.assertFalse(row["checks"]["temp_cleanup"])

    def test_one_case_group_late_failure_cannot_earn_listing_credit(self):
        for late in (False,True):
            calls=[]
            def execute(name,*args):
                calls.append(name);row=deepcopy(receipt()["cases"][name]);row["status"]="failed";row["checks"]["group_finalized"]=False
                return dict(name=name,record=row,artifact="a"*64)
            with ExitStack() as mocks:
                for obj,key,value in ((P.H,"hosted_guard",Mock()),(P.E,"runtime_binding",lambda r:old_e.RUNTIME),
                    (P.E,"compute_bindings",lambda *a:old_e.BINDINGS),(P.H,"prepare",Mock()),(P.H,"identity",lambda p:(1,2)),
                    (P.H,"inventory",lambda p:{}),(P.H,"remove_owned",Mock()),(P,"execute",execute)):
                    mocks.enter_context(patch.object(obj,key,value))
                mocks.enter_context(patch.dict(P.os.environ,{"RUNNER_TEMP":str(Path.cwd()),"GITHUB_SHA":old_e.BINDINGS["build_commit"]}))
                mocks.enter_context(patch.object(P,"bindings",side_effect=[old_e.BINDINGS,P.ProducerError("preservation_failed") if late else old_e.BINDINGS]))
                value=P.run("not-read",old_e.BINDINGS["application_sha256"],old_e.BINDINGS["build_commit"],E.LIST_MODE)
                self.assertEqual(calls,["listing"]);self.assertEqual(value["result"],"failed" if late else "passed")
                if late:self.assertNotIn("passed",value["capabilities"].values())

    def test_listing_preservation_rejects_queue_app_config_or_artifact_change(self):
        case=Path("C:/synthetic-private");config=b"synthetic config"
        item=dict(name="listing",case=case,lease=(1,2),source=(2,3),config=config,artifact="a"*64,record=dict(checks=dict(configuration_preserved=True)))
        for broken in (None,"config","queue","app","artifact","source","identity"):
            def read(p,*a):return (b"changed" if broken=="app" else b"app") if p.name=="application.exe" else (b"changed" if broken=="config" else config)
            def inventory(p):return {"queue.csv":()} if p==case and broken=="queue" else {"extra":()} if p==case/"source" and broken=="source" else {}
            with patch.object(P.H,"identity",side_effect=lambda p:(0,0) if broken=="identity" else item["lease"] if p==case else item["source"]),patch.object(P.H,"inventory",side_effect=inventory),patch.object(P.H,"read",side_effect=read),patch.object(P.H,"configuration_preserved"),patch.object(P.W,"fingerprint",return_value="b"*64 if broken=="artifact" else "a"*64):
                if broken is None:P.preserved(item,P.H.sha(b"app"))
                else:
                    with self.assertRaises(P.ProducerError):P.preserved(item,P.H.sha(b"app"))
