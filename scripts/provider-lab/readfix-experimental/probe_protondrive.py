from pathlib import Path
import base64,configparser,hashlib,json,sys,shutil,tempfile,uuid,os,http.client
directory=Path("/opt/prototype")
sys.path[:0]=[str(directory),str(directory/"foundation")]
import run_lab as lab
from fixture_protondrive import ProtonState,serve_proton,listeners_closed,CONTENT,ROOT,NESTED,SHARE,UID

report={"scope":"experimental_patched_runtime_native_protondrive_reads","ledger_eligible":False,
 "backend":"protondrive","success":False,"errors":[],
 "capabilities":dict.fromkeys(lab.QUATRIX_CAPABILITIES,"not_run"),"cleanup":{}}
build=Path("/opt/runtime");metadata=json.loads((build/"build.json").read_text());binary=build/"rclone"
assert hashlib.sha256(binary.read_bytes()).hexdigest()==metadata["sha256"] and metadata["different_root_rebuild_matched"] is True
report["runtime"]={k:metadata[k] for k in ("runtime_version","sha256","source_commit")}
assert os.getuid()==10001 and {line.split(":")[0].strip() for line in Path("/proc/net/dev").read_text().splitlines() if ":" in line}=={"lo"}
root=Path(tempfile.mkdtemp(prefix="proton-readfix-",dir="/work"));native=None
state=ProtonState("synthetic-"+uuid.uuid4().hex);certificates=[];transports=[]
def config_data(p):
    parser=configparser.ConfigParser(interpolation=None);parser.read(p)
    return {section:dict(parser[section]) for section in parser.sections()}
try:
    native=lab.Runtime(binary,{"sha256":metadata["sha256"],"version":metadata["runtime_version"].removeprefix("v")},root)
    native.binary.unlink();native.binary=binary
    code,data,_=native.run(["version"])
    lab.check(code==0 and data.decode().splitlines()[0]=="rclone "+metadata["runtime_version"],"experimental_version_mismatch")
    work=root/"protondrive";work.mkdir(mode=0o700)
    expected=lab.fixture_manifest();caps=report["capabilities"]
    before=json.dumps(state.data,sort_keys=True)
    ciphertext_before={name:hashlib.sha256(payload).hexdigest() for name,payload in state.ciphertext.items()}
    with serve_proton(root,state) as (certificates,transports):
        options={"type":"protondrive","username":"synthetic@example.invalid","client_uid":UID,
          "client_access_token":state.password,"client_refresh_token":"synthetic-refresh-unused",
          "client_salted_key_pass":state.data["salted_key_pass"]}
        good=lab.config_file(work,"good.conf",options)
        bad=lab.config_file(work,"wrong.conf",dict(options,client_access_token="synthetic-invalid"))
        wrong_key=lab.config_file(work,"wrong-key.conf",dict(options,client_salted_key_pass=base64.b64encode(b"synthetic-wrong-key").decode()))
        saved={p:p.read_bytes() for p in (good,bad,wrong_key)}
        parsed={p:config_data(p) for p in saved}
        invalid_used=set()
        class TrustedRuntime:
            def run(self,args,config=None,**kwargs):
                for p,v in saved.items():
                    if p not in invalid_used:lab.check(p.read_bytes()==v,"proton_config_changed_before")
                result=native.run([*[part for cert in certificates for part in cert.rclone_ca_args()],*args],config,**kwargs)
                lab.check(good.read_bytes()==saved[good],"proton_good_config_changed")
                if config in (bad,wrong_key):
                    wanted={section:dict(values) for section,values in parsed[config].items()}
                    for key in ("client_uid","client_access_token","client_refresh_token","client_salted_key_pass"):
                        wanted["Synthetic"][key]=""
                    lab.check(config_data(config)==wanted,"proton_invalid_config_clear_mismatch")
                    invalid_used.add(config)
                if result[0]!=0 and config==good:
                    report.setdefault("failed_native_diagnostics",[]).append({"operation":args[0],"exit":result[0]})
                return result
        runner=TrustedRuntime()
        lab.common_checks(runner,work,good,bad,"Synthetic:",report,state,expected=expected)
        lab.read_api_listing(runner,good,expected)
        nested=[dict(item,path=item["path"][7:]) for item in expected if item["path"].startswith("nested/")]
        lab.read_api_listing(runner,good,nested,"Synthetic:nested/")
        for item in expected:
            code,data,error=runner.run(["cat","Synthetic:"+item["path"]],good)
            lab.check(code==0 and len(data)==item["size"] and hashlib.sha256(data).hexdigest()==item["sha256"],"proton_cat_mismatch")
        name="README-synthetic.txt"
        code,data,_=runner.run(["cat","--offset","3","--count","11","Synthetic:"+name],good)
        lab.check(code==0 and data==state.files[name][3:14],"proton_range_mismatch")
        state.mode="read_denied";denied=work/"denied";denied.mkdir(mode=0o700)
        cat_code,cat_data,_=runner.run(["cat","Synthetic:"+name],good)
        code,data,error=lab.exact_copy(runner,good,"Synthetic:",name,str(denied),"denied.bin")
        lab.check(cat_code!=0 and not cat_data and code!=0 and b"403" in data+error
                  and not list(denied.iterdir()) and state.read_denied==2,"proton_read_denial_missing")
        state.mode="normal";caps["read_denial"]="passed"
        for mode in ("tampered_ciphertext","wrong_block_hash","wrong_block_signature"):
            state.mode=mode;tampered=work/mode;tampered.mkdir(mode=0o700)
            cat_code,cat_data,_=runner.run(["cat","Synthetic:"+name],good)
            code,data,error=lab.exact_copy(runner,good,"Synthetic:",name,str(tampered),"must-not-exist")
            marker={"tampered_ciphertext":b"MDC hash mismatch","wrong_block_hash":b"hash of the downloaded block","wrong_block_signature":b"invalid signature"}[mode]
            lab.check(cat_code!=0 and not cat_data and code!=0 and not list(tampered.iterdir())
                      and state.tampered_reads.get(mode)==2 and marker in data+error,"proton_"+mode+"_accepted")
        report["tampered_reads_rejected"]=dict(state.tampered_reads);state.mode="normal"
        wrong=work/"wrong-key";wrong.mkdir(mode=0o700)
        before_payload=state.payload_bytes
        code,data,error=lab.exact_copy(runner,wrong_key,"Synthetic:",name,str(wrong),"must-not-exist")
        lab.check(code!=0 and not list(wrong.iterdir()) and state.payload_bytes==before_payload
                  and b"initialize" in data+error,"proton_wrong_key_accepted")
        connection=http.client.HTTPSConnection(transports[0].authority,443,timeout=3,context=certificates[0].client_context())
        try:
            connection.request("POST","/drive/shares/"+SHARE+"/folders/"+ROOT+"/trash_multiple",
               json.dumps({"LinkIDs":[state.ids[name]]}),
               {"Authorization":"Bearer "+state.password,"X-Pm-Uid":UID,"Content-Type":"application/json"})
            response=connection.getresponse()
            lab.check(response.status==405 and len(response.read(4097))<=4096 and state.rejected_mutations==1,"proton_write_guard_missing")
        finally:connection.close()
        lab.check(not state.unexpected and not state.budget_exceeded and state.denied>0 and state.observed==set(state.files),"proton_protocol_flow_mismatch")
        lab.check(lab.served_source_unchanged(state,expected) and json.dumps(state.data,sort_keys=True)==before
          and {n:hashlib.sha256(p).hexdigest() for n,p in state.ciphertext.items()}==ciphertext_before,"proton_source_changed")
    for transport in transports:
        snapshot=transport.snapshot()
        lab.check(not snapshot["failure_codes"] and snapshot["handshake_successes"]>0,"proton_tls_failed")
    for cap in caps:caps[cap]="passed"
    report["success"]=True
except lab.LabError as error:report["errors"].append(str(error))
except Exception as error:report["errors"].append(type(error).__name__)
finally:
    report["native_commands"]=0 if native is None else len(native.children)
    report["observations"]={key:getattr(state,key) for key in ("requests","unexpected","denied","read_denied","missing","rejected_mutations")}
    report["tls"]=[t.snapshot() for t in transports]
    report["reject_diagnostics"]=state.reject_diagnostics
    report["cleanup"]["children_stopped"]=native is None or native.close()
    report["cleanup"]["listeners_closed"]=state.cleanup_complete and listeners_closed(transports)
    report["cleanup"]["certificates_removed"]=all(c.cleanup_complete for c in certificates)
    shutil.rmtree(root);report["cleanup"]["temporary_removed"]=not root.exists()
    report["success"]=report["success"] and all(report["cleanup"].values()) and not report["errors"]
    report["capabilities"]["cleanup"]="passed" if all(report["cleanup"].values()) else "failed"
if report["success"]:report.pop("failed_native_diagnostics",None)
print(json.dumps(report))
raise SystemExit(0 if report["success"] else 1)
