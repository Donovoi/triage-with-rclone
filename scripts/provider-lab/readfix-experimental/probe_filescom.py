from pathlib import Path
import hashlib,json,sys,tempfile,shutil,uuid,os
directory=Path("/opt/prototype")
sys.path[:0]=[str(directory),str(directory/"foundation")]
import run_lab as lab
from fixture_filescom import FilesComState,FilesComHandler
from fixture_read_api import serve_read_api
assert os.getuid()==10001 and {line.split(":")[0].strip() for line in Path("/proc/net/dev").read_text().splitlines() if ":" in line}=={"lo"}

report={"scope":"experimental_patched_runtime_native_filescom_reads","ledger_eligible":False,"backend":"filescom",
        "success":False,"errors":[],"capabilities":dict.fromkeys(lab.QUATRIX_CAPABILITIES,"not_run"),
        "cleanup":{},"native_commands":0}
build=Path("/opt/runtime")
metadata=json.loads((build/"build.json").read_text());binary=build/"rclone"
assert hashlib.sha256(binary.read_bytes()).hexdigest()==metadata["sha256"]
report["runtime"]={k:metadata[k] for k in ("runtime_version","sha256","source_commit")}
root=Path(tempfile.mkdtemp(prefix="filescom-readfix-",dir="/work"));native=None
state=FilesComState("synthetic-"+uuid.uuid4().hex);port=None
try:
    identity={"sha256":metadata["sha256"],"version":metadata["runtime_version"].removeprefix("v")}
    native=lab.Runtime(binary,identity,root)
    native.binary.unlink();native.binary=binary
    code,data,_=native.run(["version"])
    lab.check(code==0 and data.decode().splitlines()[0]=="rclone "+metadata["runtime_version"],"experimental_version_mismatch")
    work=root/"filescom";work.mkdir(mode=0o700)
    expected=lab.fixture_manifest();caps=report["capabilities"]
    before={name:state.metadata(name) for name in ("","nested",*state.files)}
    with serve_read_api(state,FilesComHandler) as port:
        options={"type":"filescom","site":f"http://127.0.0.1:{port}","api_key":state.password}
        good=lab.config_file(work,"good.conf",options)
        bad=lab.config_file(work,"wrong.conf",dict(options,api_key="synthetic-invalid"))
        saved={p:p.read_bytes() for p in (good,bad)}
        class PreservingRuntime:
            def run(self,args,config=None,**kwargs):
                lab.check(all(p.read_bytes()==v for p,v in saved.items()),"filescom_config_changed")
                result=native.run(args,config,**kwargs)
                lab.check(all(p.read_bytes()==v for p,v in saved.items()),"filescom_config_changed")
                return result
        runner=PreservingRuntime()
        lab.common_checks(runner,work,good,bad,"Synthetic:",report,state,expected=expected)
        lab.read_api_listing(runner,good,expected)
        for item in expected:
            code,data,_=runner.run(["cat","Synthetic:"+item["path"]],good)
            lab.check(code==0 and len(data)==item["size"] and hashlib.sha256(data).hexdigest()==item["sha256"],"filescom_cat_mismatch")
        name="README-synthetic.txt"
        code,data,_=runner.run(["cat","--offset","3","--count","11","Synthetic:"+name],good)
        lab.check(code==0 and data==state.files[name][3:14],"filescom_range_mismatch")
        state.mode="read_denied";denied=work/"denied";denied.mkdir(mode=0o700)
        cat_code,cat_data,_=runner.run(["cat","Synthetic:"+name],good)
        code,data,error=lab.exact_copy(runner,good,"Synthetic:",name,str(denied),"denied.bin")
        lab.check(cat_code!=0 and not cat_data and code!=0 and b"403" in data+error
                  and not list(denied.iterdir()) and state.read_denied==2,"filescom_read_denial_missing")
        state.mode="normal";caps["read_denial"]="passed"
        code,data,error=runner.run(["deletefile","Synthetic:"+name],good)
        lab.check(code!=0 and b"synthetic fixture is read-only" in data+error and state.rejected_mutations==1,"filescom_write_denial_missing")
        lab.check(not state.unexpected and not state.budget_exceeded and state.denied>0 and state.missing>0,
                  "filescom_protocol_flow_mismatch")
        lab.check(lab.served_source_unchanged(state,expected)
                  and {n:state.metadata(n) for n in before}==before,"filescom_source_changed")
        for cap in caps:caps[cap]="passed"
    report["success"]=True
except lab.LabError as error:
    report["errors"].append(str(error))
except Exception as error:
    report["errors"].append(type(error).__name__)
finally:
    report["observations"]={key:getattr(state,key) for key in ("requests","unexpected","denied","read_denied","missing","rejected_mutations")}
    report["native_commands"]=0 if native is None else len(native.children)
    report["cleanup"]["children_stopped"]=native is None or native.close()
    report["cleanup"]["listeners_closed"]=state.cleanup_complete and (port is None or lab.listener_closed(port))
    shutil.rmtree(root)
    report["cleanup"]["temporary_removed"]=not root.exists()
    report["success"]=report["success"] and all(report["cleanup"].values()) and not report["errors"]
    report["capabilities"]["cleanup"]="passed" if all(report["cleanup"].values()) else "failed"

print(json.dumps(report))
raise SystemExit(0 if report["success"] else 1)
