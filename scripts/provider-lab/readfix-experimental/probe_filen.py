from pathlib import Path
import hashlib,json,sys,shutil,tempfile,uuid,os,http.client
directory=Path("/opt/prototype")
sys.path[:0]=[str(directory),str(directory/"foundation")]
import run_lab as lab
from fixture_filen import FilenState,serve_filen,listeners_closed,CONTENT,ROOT,NESTED,MASTER

report={"scope":"experimental_patched_runtime_native_filen_reads","ledger_eligible":False,
        "backend":"filen","success":False,"errors":[],
        "capabilities":dict.fromkeys(lab.QUATRIX_CAPABILITIES,"not_run"),"cleanup":{}}
build=Path("/opt/runtime");metadata=json.loads((build/"build.json").read_text());binary=build/"rclone"
assert hashlib.sha256(binary.read_bytes()).hexdigest()==metadata["sha256"]
assert metadata["different_root_rebuild_matched"] is True
report["runtime"]={k:metadata[k] for k in ("runtime_version","sha256","source_commit")}
assert os.getuid()==10001 and {line.split(":")[0].strip() for line in Path("/proc/net/dev").read_text().splitlines() if ":" in line}=={"lo"}
root=Path(tempfile.mkdtemp(prefix="filen-readfix-",dir="/work"));native=None
state=FilenState("synthetic-"+uuid.uuid4().hex);certificates=[];transports=[]
try:
    native=lab.Runtime(binary,{"sha256":metadata["sha256"],"version":metadata["runtime_version"].removeprefix("v")},root)
    native.binary.unlink()
    native.binary=binary
    code,data,_=native.run(["version"])
    lab.check(code==0 and data.decode().splitlines()[0]=="rclone "+metadata["runtime_version"],"experimental_version_mismatch")
    work=root/"filen";work.mkdir(mode=0o700)
    expected=lab.fixture_manifest();caps=report["capabilities"]
    before=json.dumps([state.inventory(ROOT),state.inventory(NESTED)],sort_keys=True)
    ciphertext_before={name:hashlib.sha256(payload).hexdigest() for name,payload in state.ciphertext.items()}
    with serve_filen(root,state) as (certificates,transports):
        def obscure(value):
            code,data,_=native.run(["obscure",value])
            lab.check(code==0 and len(data)<512,"filen_obscure_failed")
            return data.decode().strip()
        options={"type":"filen","email":"synthetic@example.invalid","password":obscure("INTERNAL"),
                 "api_key":obscure(state.password),"auth_version":"2","base_folder_uuid":ROOT,
                 "master_keys":MASTER,"private_key":state.private_key,"public_key":state.public_key}
        good=lab.config_file(work,"good.conf",options)
        bad=lab.config_file(work,"wrong.conf",dict(options,api_key=obscure("synthetic-invalid")))
        wrong_master=lab.config_file(work,"wrong-master.conf",dict(options,master_keys="abcdef0123456789"*4))
        saved={p:p.read_bytes() for p in (good,bad,wrong_master)}
        class TrustedRuntime:
            def run(self,args,config=None,**kwargs):
                lab.check(all(p.read_bytes()==v for p,v in saved.items()),"filen_config_changed")
                result=native.run([*[part for cert in certificates for part in cert.rclone_ca_args()],*args],config,**kwargs)
                lab.check(all(p.read_bytes()==v for p,v in saved.items()),"filen_config_changed")
                return result
        runner=TrustedRuntime()
        lab.common_checks(runner,work,good,bad,"Synthetic:",report,state,expected=expected)
        lab.read_api_listing(runner,good,expected)
        nested=[dict(item,path=item["path"][7:]) for item in expected if item["path"].startswith("nested/")]
        lab.read_api_listing(runner,good,nested,"Synthetic:nested/")
        for item in expected:
            code,data,error=runner.run(["cat","Synthetic:"+item["path"]],good)
            if code!=0 or len(data)!=item["size"] or hashlib.sha256(data).hexdigest()!=item["sha256"]:
                report["cat_diagnostic"]={"path":item["path"],"exit":code,"bytes":len(data),"expected_bytes":item["size"]}
            lab.check(code==0 and len(data)==item["size"] and hashlib.sha256(data).hexdigest()==item["sha256"],"filen_cat_mismatch")
        name="README-synthetic.txt"
        for mode in ("normal",):
            state.mode=mode
            code,data,_=runner.run(["cat","--offset","3","--count","11","Synthetic:"+name],good)
            lab.check(code==0 and data==state.files[name][3:14],"filen_range_mismatch")
        state.mode="read_denied";denied=work/"denied";denied.mkdir(mode=0o700)
        cat_code,cat_data,_=runner.run(["cat","Synthetic:"+name],good)
        code,data,error=lab.exact_copy(runner,good,"Synthetic:",name,str(denied),"denied.bin")
        lab.check(cat_code!=0 and not cat_data and code!=0 and b"403" in data+error
                  and not list(denied.iterdir()) and state.read_denied==2,"filen_read_denial_missing")
        state.mode="normal";caps["read_denial"]="passed"
        state.mode="tampered_ciphertext";tampered=work/"tampered";tampered.mkdir(mode=0o700)
        cat_code,cat_data,_=runner.run(["cat","Synthetic:"+name],good)
        code,data,error=lab.exact_copy(runner,good,"Synthetic:",name,str(tampered),"tampered.bin")
        lab.check(cat_code!=0 and not cat_data and code!=0 and not list(tampered.iterdir()) and state.tampered_reads==2
                  and b"message authentication failed" in data+error,
                  "filen_tampered_ciphertext_accepted")
        report["tampered_ciphertext_rejected"]=True;state.mode="normal"
        wrong_key=work/"wrong-key";wrong_key.mkdir(mode=0o700)
        code,data,error=lab.exact_copy(runner,wrong_master,"Synthetic:",name,str(wrong_key),"must-not-exist")
        lab.check(code!=0 and not list(wrong_key.iterdir()) and b"decrypting metadata" in data+error,
                  "filen_wrong_master_key_accepted")
        connection=http.client.HTTPSConnection(transports[0].authority,443,timeout=3,context=certificates[0].client_context())
        try:
            connection.request("POST","/v3/file/trash",json.dumps({"uuid":state.ids[name]}),
                               {"Authorization":"Bearer "+state.password,"Content-Type":"application/json"})
            response=connection.getresponse()
            lab.check(response.status==405 and len(response.read(4097))<=4096 and state.rejected_mutations==1,
                      "filen_write_guard_missing")
        finally:connection.close()
        lab.check(not state.unexpected and not state.budget_exceeded and state.denied>0
                  and state.observed==set(state.files),
                  "filen_protocol_flow_mismatch")
        lab.check(lab.served_source_unchanged(state,expected)
                  and json.dumps([state.inventory(ROOT),state.inventory(NESTED)],sort_keys=True)==before
                  and {n:hashlib.sha256(p).hexdigest() for n,p in state.ciphertext.items()}==ciphertext_before,"filen_source_changed")
    for transport in transports:
        snapshot=transport.snapshot()
        lab.check(not snapshot["failure_codes"] and snapshot["handshake_successes"]>0,"filen_tls_failed")
    for cap in caps:caps[cap]="passed"
    report["success"]=True
except lab.LabError as error:
    report["errors"].append(str(error))
except Exception as error:
    report["errors"].append(type(error).__name__)
finally:
    report["native_commands"]=0 if native is None else len(native.children)
    report["observations"]={key:getattr(state,key) for key in ("requests","unexpected","denied","read_denied","missing","rejected_mutations")}
    report["tls"]=[t.snapshot() for t in transports]
    report["reject_diagnostics"]=getattr(state,"reject_diagnostics",[])
    report["cleanup"]["children_stopped"]=native is None or native.close()
    report["cleanup"]["listeners_closed"]=state.cleanup_complete and listeners_closed(transports)
    report["cleanup"]["certificates_removed"]=all(c.cleanup_complete for c in certificates)
    shutil.rmtree(root)
    report["cleanup"]["temporary_removed"]=not root.exists()
    report["success"]=report["success"] and all(report["cleanup"].values()) and not report["errors"]
    report["capabilities"]["cleanup"]="passed" if all(report["cleanup"].values()) else "failed"
if report["success"]:report.pop("failed_native_diagnostics",None)
print(json.dumps(report))
raise SystemExit(0 if report["success"] else 1)
