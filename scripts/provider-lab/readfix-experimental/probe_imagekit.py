from pathlib import Path
import hashlib,json,sys,shutil,tempfile,uuid,os
directory=Path("/opt/prototype")
sys.path[:0]=[str(directory),str(directory/"foundation")]
import run_lab as lab
from fixture_imagekit import ImageKitState,serve_imagekit,listeners_closed,CONTENT

report={"scope":"experimental_patched_runtime_native_imagekit_reads","ledger_eligible":False,
        "backend":"imagekit","success":False,"errors":[],
        "capabilities":dict.fromkeys(lab.QUATRIX_CAPABILITIES,"not_run"),"cleanup":{}}
build=Path("/opt/runtime");metadata=json.loads((build/"build.json").read_text());binary=build/"rclone"
assert hashlib.sha256(binary.read_bytes()).hexdigest()==metadata["sha256"]
assert metadata["different_root_rebuild_matched"] is True
report["runtime"]={k:metadata[k] for k in ("runtime_version","sha256","source_commit")}
assert os.getuid()==10001 and {line.split(":")[0].strip() for line in Path("/proc/net/dev").read_text().splitlines() if ":" in line}=={"lo"}
root=Path(tempfile.mkdtemp(prefix="imagekit-readfix-",dir="/work"));native=None
state=ImageKitState("synthetic-"+uuid.uuid4().hex);certificates=[];transports=[]
try:
    native=lab.Runtime(binary,{"sha256":metadata["sha256"],"version":metadata["runtime_version"].removeprefix("v")},root)
    native.binary.unlink()
    native.binary=binary
    code,data,_=native.run(["version"])
    lab.check(code==0 and data.decode().splitlines()[0]=="rclone "+metadata["runtime_version"],"experimental_version_mismatch")
    work=root/"imagekit";work.mkdir(mode=0o700)
    expected=lab.fixture_manifest();caps=report["capabilities"]
    before={name:state.metadata(name) for name in ("","nested",*state.files)}
    with serve_imagekit(root,state) as (certificates,transports):
        options={"type":"imagekit","endpoint":"https://"+CONTENT,"public_key":"synthetic-public","private_key":state.password}
        good=lab.config_file(work,"good.conf",options)
        bad=lab.config_file(work,"wrong.conf",dict(options,private_key="synthetic-invalid"))
        saved={p:p.read_bytes() for p in (good,bad)}
        class TrustedRuntime:
            def run(self,args,config=None,**kwargs):
                lab.check(all(p.read_bytes()==v for p,v in saved.items()),"imagekit_config_changed")
                result=native.run([*[part for cert in certificates for part in cert.rclone_ca_args()],*args],config,**kwargs)
                lab.check(all(p.read_bytes()==v for p,v in saved.items()),"imagekit_config_changed")
                return result
        runner=TrustedRuntime()
        lab.common_checks(runner,work,good,bad,"Synthetic:",report,state,expected=expected)
        lab.read_api_listing(runner,good,expected)
        nested=[dict(item,path=item["path"][7:]) for item in expected if item["path"].startswith("nested/")]
        lab.read_api_listing(runner,good,nested,"Synthetic:nested/")
        for item in expected:
            code,data,_=runner.run(["cat","Synthetic:"+item["path"]],good)
            lab.check(code==0 and len(data)==item["size"] and hashlib.sha256(data).hexdigest()==item["sha256"],"imagekit_cat_mismatch")
        name="README-synthetic.txt"
        for mode in ("normal","ignored_range"):
            state.mode=mode
            code,data,_=runner.run(["cat","--offset","3","--count","11","Synthetic:"+name],good)
            lab.check(code==0 and data==state.files[name][3:14],"imagekit_range_mismatch")
        state.mode="read_denied";denied=work/"denied";denied.mkdir(mode=0o700)
        cat_code,cat_data,_=runner.run(["cat","Synthetic:"+name],good)
        code,data,error=lab.exact_copy(runner,good,"Synthetic:",name,str(denied),"denied.bin")
        lab.check(cat_code!=0 and not cat_data and code!=0 and b"403" in data+error
                  and not list(denied.iterdir()) and state.read_denied==2,"imagekit_read_denial_missing")
        state.mode="normal";caps["read_denial"]="passed"
        code,data,error=runner.run(["deletefile","Synthetic:"+name],good)
        lab.check(code!=0 and b"405" in data+error and state.rejected_mutations==1,"imagekit_write_denial_missing")
        lab.check(not state.unexpected and not state.budget_exceeded and state.denied>0 and state.missing>0
                  and state.observed==set(state.files) and state.signed_reads>=len(state.files),
                  "imagekit_protocol_flow_mismatch")
        lab.check(lab.served_source_unchanged(state,expected)
                  and {n:state.metadata(n) for n in before}==before,"imagekit_source_changed")
    for transport in transports:
        snapshot=transport.snapshot()
        lab.check(not snapshot["failure_codes"] and snapshot["handshake_successes"]>0,"imagekit_tls_failed")
    for cap in caps:caps[cap]="passed"
    report["success"]=True
except lab.LabError as error:
    report["errors"].append(str(error))
except Exception as error:
    report["errors"].append(type(error).__name__)
finally:
    report["native_commands"]=0 if native is None else len(native.children)
    report["observations"]={key:getattr(state,key) for key in ("requests","unexpected","denied","read_denied","missing","rejected_mutations","signed_reads")}
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
