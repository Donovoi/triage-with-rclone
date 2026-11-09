"""Hosted-only retained HDFS context-cancellation matrix; no provider acceptance.

Imports are inert. Public dependency preparation uses retained bounded workers;
all native compilation and execution occurs in an admitted offline container.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import sys
import tempfile
import time
import types
import uuid

HERE=Path(__file__).resolve().parent
PINS_SHA="723e67806b330f6271b609ff004724d7add946d61ed703c3cc16c5d04514259e"
LABEL="org.openai.triage.hdfs-retained-context"
TMPFS="rw,nosuid,nodev,noexec,size=128m,mode=0700,uid=10001,gid=10001"
PROFILE="kerberos-remediation"
CASES=(("original","renewable"),("patched","renewable"),("original","nonrenewable"),("patched","nonrenewable"))
JAVA_NAMES=("HdfsContextCancellationProbe.java","HdfsContextHeldResponse.java","HdfsContextHeldResponseVectors.java",
            "HdfsCancellationRpcGate.java","HdfsCancellationRpcGateVectors.java")
QUALIFIED_BINARIES={
    "original":(119830724,"37ef48307cbaae684126fe8e2f5d6ca3717fce679fd36c34fc4ba584295ea0d3"),
    "patched":(119848207,"8c72cfd7f7a8f0a7e62c7f527155e0e55bb391cf8bffdb1ada6009416d74e27b")}
QUALIFIED_TEST=(12025580,"4b9cc4d5f84c1467e92828961e8e521251dd1b93032bc911489dc83d7cebb645")

FALSE_CLAIMS=("cancellation_verified","renewal_verified","rclone_verified","provider_accepted","application_accepted",
              "vendor_accepted","vulnerability_audited")
CODES=frozenset(("input_invalid","input_changed","unsafe_path","hosted_linux_required","python_version",
    "package_download_failed","package_worker_failed","package_cleanup_failed","bundle_invalid","platform_invalid",
    "image_invalid","container_invalid","java_report_invalid","java_probe_failed","container_cleanup_failed",
    "image_cleanup_failed","raw_cleanup_failed","command_cleanup_failed","download_cleanup_failed","download_failed",
    "build_failed","interrupted","probe_failed","report_failed"))

class ProbeError(Exception):
    def __init__(self, code):
        self.code=code if code in CODES else "probe_failed"; super().__init__(self.code)

def need(value,code):
    if not value: raise ProbeError(code)

def sha(raw): return hashlib.sha256(raw).hexdigest()
def canonical(value): return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("ascii")

def frozen_read(path, maximum=262144):
    need(path.is_absolute(),"unsafe_path")
    for item in (path,*path.parents):
        s=item.lstat(); need(not stat.S_ISLNK(s.st_mode) and not getattr(s,"st_file_attributes",0)&0x400,"unsafe_path")
    before=path.stat(); need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=maximum,"input_invalid")
    with path.open("rb") as stream:
        opened=os.fstat(stream.fileno()); raw=stream.read(maximum+1); after=os.fstat(stream.fileno())
    stamp=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)
    need(len(raw)<=maximum and stamp(before)==stamp(opened)==stamp(after)==stamp(path.stat()),"input_changed")
    return raw

def load_inputs():
    raw=frozen_read(HERE/"source-pins.json",16384); need(sha(raw)==PINS_SHA,"input_changed")
    pins=json.loads(raw); need(type(pins) is dict and set(pins)=={"schema_version","files"}
        and type(pins["schema_version"]) is int and pins["schema_version"]==1,"input_invalid")
    data={}; hashes={HERE/"source-pins.json":PINS_SHA}
    for name,pin in pins["files"].items():
        need(type(name) is str and re.fullmatch(r"(?:[A-Za-z0-9_-]+/)+[A-Za-z0-9_.-]+",name)
             and type(pin) is dict and set(pin)=={"bytes","sha256"} and type(pin["bytes"]) is int
             and 0<pin["bytes"]<=262144 and re.fullmatch("[a-f0-9]{64}",pin["sha256"]),"input_invalid")
        source=HERE.parent/name; blob=frozen_read(source,pin["bytes"])
        need(len(blob)==pin["bytes"] and sha(blob)==pin["sha256"],"input_changed")
        data[name]=blob; hashes[source]=pin["sha256"]
    def module(name):
        source=HERE.parent/name; obj=types.ModuleType("retained_"+source.stem); obj.__file__=str(source)
        exec(compile(data[name],str(source),"exec"),obj.__dict__); return obj
    R=module("hdfs-cancellation-context-build/hdfs_context_build.py")
    F=module("hdfs-kerberos-context-cancellation/context_contract.py")
    return R,F,data,hashes


def command_args(name,image,run_id,kind,variant=None,service_case=None):
    need(type(run_id) is str and re.fullmatch("[a-f0-9]{32}",run_id)
         and type(image) is str and re.fullmatch("sha256:[a-f0-9]{64}",image),"container_invalid")
    need(kind in ("identity","case") and (kind=="identity" and variant is None and service_case is None
         or kind=="case" and (variant,service_case) in CASES),"container_invalid")
    suffix="identity" if kind=="identity" else variant+"-"+service_case
    need(name=="hdfs-context-retained-"+run_id+"-"+suffix,"container_invalid")
    command=["/bin/sh","/opt/input/driver.sh"] if kind=="identity" else ["/bin/sh","/opt/rpc/driver.sh",service_case,variant]
    return ["create","--name",name,"--label",LABEL+"="+run_id,"--network","none","--read-only",
        "--user","10001:10001","--cap-drop","ALL","--security-opt","no-new-privileges","--pids-limit","128",
        "--memory","2g","--cpus","2","--init","--cgroupns","private","--ipc","private","--log-driver","none",
        "--stop-timeout","5","--tmpfs","/work:"+TMPFS,"--entrypoint","/usr/bin/env",image,
        "-i","HOME=/work/home","PATH=/opt/java/openjdk/bin:/usr/bin:/bin","JAVA_HOME=/opt/java/openjdk",
        "GOMAXPROCS=2","LANG=C","LC_ALL=C",*command]


def inspect_container(value,name,image,run_id,kind,variant=None,service_case=None):
    need(type(value) is dict and value.get("Name")=="/"+name and value.get("Image")==image
         and re.fullmatch("[a-f0-9]{64}",value.get("Id","")),"container_invalid")
    config,host=value.get("Config",{}),value.get("HostConfig",{})
    args=command_args(name,image,run_id,kind,variant,service_case)
    need(config.get("Labels",{}).get(LABEL)==run_id and config.get("User")=="10001:10001"
         and config.get("Entrypoint")==["/usr/bin/env"] and config.get("Cmd")==args[args.index(image)+1:]
         and not config.get("Volumes") and not config.get("ExposedPorts") and not config.get("Healthcheck"),"container_invalid")
    need(host.get("NetworkMode")=="none" and host.get("ReadonlyRootfs") is True and host.get("Privileged") is False
         and host.get("CapDrop")==["ALL"] and not host.get("CapAdd") and not host.get("Binds") and not host.get("PortBindings")
         and host.get("SecurityOpt") in (["no-new-privileges"],["no-new-privileges=true"])
         and type(host.get("Memory")) is int and host["Memory"]==2*1024**3
         and type(host.get("NanoCpus")) is int and host["NanoCpus"]==2*10**9
         and type(host.get("PidsLimit")) is int and host["PidsLimit"]==128 and host.get("Init") is True
         and host.get("IpcMode")=="private" and host.get("CgroupnsMode")=="private"
         and host.get("Tmpfs")=={"/work":TMPFS} and host.get("LogConfig",{}).get("Type")=="none"
         and not host.get("Devices") and not host.get("DeviceRequests") and not host.get("ExtraHosts") and not host.get("PidMode"),"container_invalid")
    mounts=value.get("Mounts")
    need(type(mounts) is list and len(mounts)<=1 and all(type(m) is dict and m.get("Type")=="tmpfs"
         and m.get("Destination")=="/work" for m in mounts),"container_invalid")


def build_files(C,R,F,rows,sources,go_sources,original_mod,original_sum):
    need(set(sources)==set(JAVA_NAMES),"input_invalid")
    result=R.build_files(C,go_sources,original_mod,original_sum)
    cp=":".join("/opt/rpc/jars/%03d.jar"%i for i in range(len(rows)))
    driver=("#!/bin/sh\nset -eu\numask 077\nmkdir /work/home /work/tmp\n"
        "exec /usr/bin/timeout --signal=TERM --kill-after=5s 180s /opt/java/openjdk/bin/java "
        "-Xmx512m -Djava.net.preferIPv4Stack=true -Djava.io.tmpdir=/work/tmp -Duser.home=/work/home "
        "-cp \"$(cat /opt/rpc/classpath)\" HdfsContextCancellationProbe \"$1\" \"$2\"\n").encode()
    runtime={**sources,"driver.sh":driver,"classpath":("/opt/rpc/classes:"+cp+"\n").encode()}
    resources=F.C.webapp_resources()
    checks="".join(row["sha256"]+"  /opt/rpc/jars/%03d.jar\n"%i for i,row in enumerate(rows))
    checks+="".join(sha(blob)+"  /opt/rpc/"+name+"\n" for name,blob in sorted(runtime.items()))
    checks+="".join(sha(blob)+"  /opt/rpc/resources/"+name+"\n" for name,blob in sorted(resources.items()))
    result.update({"rpc/"+name:blob for name,blob in runtime.items()})
    result.update({"resources/"+name:blob for name,blob in resources.items()})
    result["rpc/runtime-checksums"]=checks.encode()
    result["Dockerfile"]=("FROM "+C.BASE+"\nUSER 0\nCOPY . /opt/input/\n"
        "RUN cd /opt/input && sha256sum -c checksums && /bin/sh /opt/input/build.sh\n"
        "COPY jars /opt/rpc/jars/\nCOPY rpc /opt/rpc/\nCOPY resources /opt/rpc/resources/\n"
        "RUN sha256sum -c /opt/rpc/runtime-checksums && mkdir /opt/rpc/classes && "
        "/opt/java/openjdk/bin/javac -J-Xmx512m -proc:none -implicit:none -encoding UTF-8 -cp '"+cp+
        "' -d /opt/rpc/classes "+" ".join("/opt/rpc/"+n for n in JAVA_NAMES)+
        " && cp -R /opt/rpc/resources/webapps /opt/rpc/classes/ && chmod -R a=rX /opt/rpc\n"
        "USER 10001:10001\nWORKDIR /work\n").encode()
    return result


def build_diagnostics(R,raw):
    need(type(raw) is bytes and len(raw)<=8388608,"input_invalid")
    names="|".join(re.escape(n[:-5]) for n in JAVA_NAMES)
    pattern=r"/opt/rpc/("+names+r")[.]java:([0-9]{1,5}): error: ([^\r\n]*)"
    errors=[]
    for match in re.finditer(pattern,raw.decode("utf-8",errors="replace")):
        line=int(match[2]); need(1<=line<=10000 and len(errors)<32,"input_invalid"); message=match[3]
        category="symbol" if "cannot find symbol" in message else "type" if "incompatible types" in message else "package" if "package " in message and "does not exist" in message else "syntax" if any(s in message for s in ("expected","illegal start","reached end")) else "other"
        row=dict(file=match[1]+".java",line=line,category=category)
        if row not in errors: errors.append(row)
    return dict(java_errors=errors,go=R.build_diagnostics(raw))


def failure_diagnostics(error):
    category="filesystem" if isinstance(error,OSError) else "validation" if hasattr(error,"code") else "unexpected"
    frames=[]; tb=error.__traceback__
    while tb:
        name=Path(tb.tb_frame.f_code.co_filename).name
        if name in {"context_container.py","context_contract.py","hdfs_context_build.py","cancellation_container.py","policy_denial_container.py"}:
            frames.append(dict(file=name,line=max(1,min(10000,tb.tb_lineno))))
        tb=tb.tb_next
    return dict(category=category,frames=frames[-8:])


def remove_container(docker,entry,image,run_id):
    current=docker.inspect("container",entry.get("id") or entry["name"],allow_missing=True)
    if current is not None:
        owned=current.get("Id")
        need(current.get("Config",{}).get("Labels",{}).get(LABEL)==run_id
             and re.fullmatch("[a-f0-9]{64}",owned or "") and current.get("Name")=="/"+entry["name"]
             and current.get("Image")==image and (entry.get("id") is None or owned==entry["id"]),"container_cleanup_failed")
        docker.call(["container","rm","--force",owned])
        need(docker.inspect("container",owned,allow_missing=True) is None,"container_cleanup_failed")
    entry["removed"]=True


def execute(C,docker,image,run_id,kind,owned,variant=None,service_case=None):
    suffix="identity" if kind=="identity" else variant+"-"+service_case
    name="hdfs-context-retained-"+run_id+"-"+suffix
    need(docker.inspect("container",name,allow_missing=True) is None,"container_invalid")
    entry=dict(name=name,id=None,removed=False); owned.append(entry)
    docker.call(command_args(name,image,run_id,kind,variant,service_case))
    initial=docker.inspect("container",name); inspect_container(initial,name,image,run_id,kind,variant,service_case)
    need(initial.get("State",{}).get("Status")=="created" and initial["State"].get("Running") is False,"container_invalid")
    entry["id"]=initial["Id"]
    result=docker.call(["start","--attach",entry["id"]],timeout=90 if kind=="identity" else 195,limit=262144,allow_failure=True)
    ended=docker.inspect("container",entry["id"]); inspect_container(ended,name,image,run_id,kind,variant,service_case)
    state=ended.get("State",{})
    need(ended["Id"]==entry["id"] and state.get("Running") is False and state.get("Status")=="exited"
         and state.get("OOMKilled") is False and type(state.get("ExitCode")) is int and state["ExitCode"]==result.code,"container_invalid")
    stdout=C.read(result.stdout,262144); stderr=C.read(result.stderr,8388608)
    if kind=="identity": need(stderr==b"","probe_failed")
    remove_container(docker,entry,image,run_id)
    return stdout,result.code,entry["id"]


def java_diagnostics(F,raw):
    result=dict(report_parseable=False,stage="unavailable",error="unavailable",failed_checks=[],failed_cleanup=[],kdc_stage="unavailable")
    try:
        value=F.parse(raw,32768)
        if type(value) is not dict: return result
        result["report_parseable"]=True
        for key,allowed in (("stage",F.STAGES),("error",F.JAVA_CODES)):
            observed=value.get(key)
            if observed is None and key=="error": result[key]="none"
            elif type(observed) is str and observed in allowed: result[key]=observed
        for section,allowed,target in (("checks",F.JAVA_CHECKS,"failed_checks"),("cleanup",F.JAVA_CLEANUP,"failed_cleanup")):
            obj=value.get(section)
            if type(obj) is dict: result[target]=sorted(k for k in allowed if obj.get(k) is False)
        obj=value.get("kdc_trace"); observed=obj.get("failure_stage") if type(obj) is dict else None
        if type(observed) is str and observed in F.C.TRACE_STAGES: result["kdc_stage"]=observed
    except BaseException: pass
    return result


def qualified_identity(value):
    need(type(value) is dict and type(value.get("binaries")) is list and len(value["binaries"])==2,"input_changed")
    for entry in value["binaries"]:
        need(type(entry) is dict and type(entry.get("variant")) is str and entry["variant"] in QUALIFIED_BINARIES
             and type(entry.get("bytes")) is int
             and (entry["bytes"],entry.get("sha256"))==QUALIFIED_BINARIES[entry["variant"]],"input_changed")
    need({entry["variant"] for entry in value["binaries"]}==set(QUALIFIED_BINARIES),"input_changed")
    test=value.get("context_tests",{})
    need(type(test) is dict and type(test.get("binary_bytes")) is int
         and (test["binary_bytes"],test.get("binary_sha256"))==QUALIFIED_TEST,"input_changed")
    return True


def run():
    began=time.monotonic()
    report=dict(schema_version=1,scope="hdfs_retained_context_cancellation_matrix",success=False,
        started_utc=datetime.now(timezone.utc).isoformat(),finished_utc=None,duration_seconds=None,
        stage="preflight",inputs=None,binary_identity=None,cases=[],case_diagnostics=[],build_diagnostics=None,
        worker_diagnostics=None,failure_diagnostics=None,test_diagnostics=None,errors=[],
        cleanup=dict(containers_removed=False,image_removed=False,contexts_removed=False,raw_evidence_removed=False),
        cleanup_excludes=["shared_base_image","shared_build_cache"],**dict.fromkeys(FALSE_CLAIMS,False))
    C=R=F=B=D=docker=context=image=None
    roots=[]; owned=[]; source_hashes={}; built_attempted=False
    run_id=uuid.uuid4().hex; tag="hdfs-context-retained-"+run_id; old_umask=os.umask(0o077)
    def stage(value): report["stage"]=value
    def new_root(prefix):
        p=Path(tempfile.mkdtemp(prefix=prefix+"-"+run_id+"-",dir="/tmp"))
        item=dict(root=p,root_id=C.directory(p),context=None,context_id=None); roots.append(item)
        c=p/"context"; c.mkdir(mode=0o700); item.update(context=c,context_id=C.directory(c)); return c
    try:
        R,F,source_data,source_hashes=load_inputs(); C=R.load_support(); C.hosted_guard()
        need(sys.version_info[:2]==(3,14),"python_version")
        need(C.BASE==F.C.BASE and C.BASE_ID==F.C.BASE_ID,"input_invalid")
        B=R.load_bundle(C); D,helpers=C.load_helpers(); source_hashes.update(helpers)
        source_hashes.update({R.SUPPORT:R.SUPPORT_SHA,
            R.ASSETS_HOME/"rclone_build_bundle.py":R.BUNDLE_SHA,
            Path(__file__):C.file_hash(Path(__file__),262144)})
        lock_raw=C.read(R.ASSETS_HOME/"assets-lock.json",1048576); lock=B.load_lock(lock_raw)
        pins=C.profile_settings(PROFILE); runtime_raw=C.read(pins["runtime"],524288); jar_lock=C.read(pins["lock"],524288)
        rows=C.runtime_rows(runtime_raw,jar_lock,profile=PROFILE)
        source_hashes.update({R.ASSETS_HOME/"assets-lock.json":sha(lock_raw),
                             pins["runtime"]:sha(runtime_raw),pins["lock"]:sha(jar_lock)})
        go_sources={name:C.read(source,131072) for name,source in R.SOURCES.items()}
        source_hashes.update({R.SOURCES[name]:sha(raw) for name,raw in go_sources.items()})
        java_sources={Path(name).name:raw for name,raw in source_data.items()
                      if name.endswith(".java")}
        report["inputs"]=dict(source_sha256={p.relative_to(HERE.parent).as_posix():h for p,h in source_hashes.items()},
            base_manifest=C.BASE,base_config_id=C.BASE_ID,assets=1137,asset_bytes=sum(r["bytes"] for r in lock["assets"]),
            toolchain="go1.26.10",module="github.com/rclone/rclone",module_version="v1.75.2",
            runtime_jars=len(rows),runtime_bytes=sum(r["size"] for r in rows),runtime_file_sha256=pins["runtime_sha256"],
            runtime_classpath_sha256=pins["order_sha256"],lock_sha256=pins["lock_sha256"],
            context_sha256=None,image_id=None,containers=[])
        need(shutil.disk_usage("/tmp").free>=12*1024**3,"unsafe_path")
        context=new_root("hdfs-context")
        stage("download_assets"); R.prepare_packages(C,B,context,progress=stage)
        report["worker_diagnostics"]=R.read_worker_status(C,context)
        need(report["worker_diagnostics"]["phase"]=="complete" and report["worker_diagnostics"]["error"]=="none","package_worker_failed")
        stage("stage_hdfs"); report["inputs"]["hdfs_overlay"]=R.stage_hdfs(C,B,context,lock,go_sources)
        (context/"runtime-classpath.json").write_bytes(runtime_raw); (context/pins["lock"].name).write_bytes(jar_lock)
        stage("download_jars"); C.download(context,rows,profile=PROFILE); C.verify_jars(context,rows)
        stage("stage_context")
        staged={**go_sources,**build_files(C,R,F,rows,java_sources,go_sources,
            C.read(context/"original/go.mod",131072),C.read(context/"original/go.sum",131072))}
        for filename,raw in staged.items():
            target=context/filename; target.parent.mkdir(parents=True,exist_ok=True)
            with target.open("xb") as stream: stream.write(raw)
        stage("hash_context"); before=R.tree_hashes(C,context)
        (context/"checksums").write_bytes(R.checksum_manifest(before))
        context_hashes=R.tree_hashes(C,context); report["inputs"]["context_sha256"]=sha(canonical(context_hashes))
        docker=D.Docker(roots[0]["root"],max_calls=100)
        host=C.parse(C.read(docker.call(["info","--format","{{json .}}"]).stdout,1048576))
        need(host.get("OSType")=="linux" and host.get("Architecture") in ("amd64","x86_64"),"platform_invalid")
        stage("base"); docker.call(["image","pull","--quiet","--platform","linux/amd64",C.BASE],timeout=120)
        base=docker.inspect("image",C.BASE); report["base_observation"]=C.base_observation(base,C.BASE,C.BASE_ID)
        C.validate_base(base,C.BASE,C.BASE_ID)
        need(docker.inspect("image",tag,allow_missing=True) is None,"image_invalid")
        stage("build"); built_attempted=True
        compiled=docker.call(["build","--network","none","--pull=false","--label",LABEL+"="+run_id,"--tag",tag,str(context)],
                             timeout=600,limit=4194304,allow_failure=True)
        report["build_diagnostics"]=build_diagnostics(R,C.read(compiled.stdout,4194304)+C.read(compiled.stderr,4194304))
        need(compiled.code==0,"build_failed")
        built=docker.inspect("image",tag); image=built.get("Id")
        need(type(image) is str and re.fullmatch("sha256:[a-f0-9]{64}",image)
             and built.get("Config",{}).get("Labels",{}).get(LABEL)==run_id
             and built.get("Config",{}).get("User")=="10001:10001","image_invalid")
        need(R.tree_hashes(C,context)==context_hashes,"input_changed"); report["inputs"]["image_id"]=image
        stage("binary_identity"); raw,code,container=execute(C,docker,image,run_id,"identity",owned)
        report["inputs"]["containers"].append(dict(kind="identity",id=container))
        report["test_diagnostics"]=R.native_test_diagnostics(C,raw)
        report["binary_identity"]=R.validate_native(C,raw,code,lock)
        need(qualified_identity(report["binary_identity"]),"input_changed")
        need(CASES==F.CASES,"input_invalid")
        for variant,service_case in CASES:
            stage(variant+"_"+service_case)
            raw,code,container=execute(C,docker,image,run_id,"case",owned,variant,service_case)
            report["inputs"]["containers"].append(dict(kind="case",variant=variant,case=service_case,id=container))
            report["case_diagnostics"].append(dict(variant=variant,case=service_case,diagnostics=java_diagnostics(F,raw)))
            result=F.validate_java(raw,code,service_case,variant)
            report["cases"].append(dict(variant=variant,case=service_case,result=result))
            if not result["success"]: report["errors"].append("java_probe_failed")
        report["success"]=len(report["cases"])==4 and all(x["result"]["success"] for x in report["cases"])
        stage("completed")
    except KeyboardInterrupt: report["errors"].append("interrupted")
    except BaseException as error:
        report["failure_diagnostics"]=failure_diagnostics(error)
        report["errors"].append(getattr(error,"code",None) if getattr(error,"code",None) in CODES else "probe_failed")
        if context is not None and R is not None and C is not None and report["worker_diagnostics"] is None:
            try: report["worker_diagnostics"]=R.read_worker_status(C,context)
            except BaseException: report["worker_diagnostics"]=dict(schema_version=1,phase="startup",asset_index=-1,processed_assets=0,error="status_unavailable",http_status=0)
    finally:
        try:
            for entry in reversed(owned):
                if not entry["removed"]: remove_container(docker,entry,image,run_id)
            report["cleanup"]["containers_removed"]=True
        except BaseException as error:
            if getattr(error,"code",None)=="command_cleanup_failed": report["errors"].append("command_cleanup_failed")
            report["errors"].append("container_cleanup_failed")
        try:
            if built_attempted:
                current=docker.inspect("image",image or tag,allow_missing=True)
                if current is not None:
                    need(report["cleanup"]["containers_removed"] and current.get("Config",{}).get("Labels",{}).get(LABEL)==run_id
                         and (image is None or current.get("Id")==image) and current.get("RepoTags")==[tag+":latest"],"image_cleanup_failed")
                    actual=current.get("Id"); need(re.fullmatch("sha256:[a-f0-9]{64}",actual or ""),"image_cleanup_failed")
                    docker.call(["image","rm",actual]); need(docker.inspect("image",actual,allow_missing=True) is None,"image_cleanup_failed")
            report["cleanup"]["image_removed"]=True
        except BaseException as error:
            if getattr(error,"code",None)=="command_cleanup_failed": report["errors"].append("command_cleanup_failed")
            report["errors"].append("image_cleanup_failed")
        try:
            for p,expected in source_hashes.items(): need(sha(frozen_read(p,1048576))==expected,"input_changed")
        except BaseException: report["errors"].append("input_changed")
        safe=report["cleanup"]["containers_removed"] and report["cleanup"]["image_removed"]
        safe=safe and not {"command_cleanup_failed","download_cleanup_failed","package_cleanup_failed"}.intersection(report["errors"])
        try:
            for item in reversed(roots):
                need(safe,"raw_cleanup_failed"); C.directory(item["root"],item["root_id"])
                if item["context"] is not None:
                    C.directory(item["context"],item["context_id"]); R.tree_hashes(C,item["context"])
                    shutil.rmtree(item["context"]); need(not item["context"].exists(),"raw_cleanup_failed")
            report["cleanup"]["contexts_removed"]=True
            for item in reversed(roots):
                need(safe,"raw_cleanup_failed"); C.directory(item["root"],item["root_id"])
                for count,p in enumerate(item["root"].rglob("*"),1):
                    need(count<=1000 and not p.is_symlink(),"unsafe_path")
                    if p.is_dir(): C.directory(p)
                    else: C.regular(p,8388608)
                shutil.rmtree(item["root"]); need(not item["root"].exists(),"raw_cleanup_failed")
            report["cleanup"]["raw_evidence_removed"]=True
        except BaseException: report["errors"].append("raw_cleanup_failed")
        os.umask(old_umask)
    report["success"]=report["success"] and not report["errors"] and all(report["cleanup"].values())
    report["finished_utc"]=datetime.now(timezone.utc).isoformat(); report["duration_seconds"]=round(time.monotonic()-began,3)
    return report


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument("--report",type=Path,required=True)
    args=parser.parse_args(argv)
    previous=signal.getsignal(signal.SIGTERM); signal.signal(signal.SIGTERM,lambda *_:(_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        R,_,_,_=load_inputs(); C=R.load_support(); C.hosted_guard(); need(args.report.is_absolute(),"unsafe_path")
        for parent in args.report.parents: C.directory(parent)
        fd=os.open(args.report,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
        with os.fdopen(fd,"wb") as stream:
            result=run(); data=canonical(result)+b"\n"; need(len(data)<=1048576,"report_failed")
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        return 0 if result["success"] else 1
    except BaseException: sys.stderr.write("retained_context_cancellation_failed\n"); return 1
    finally: signal.signal(signal.SIGTERM,previous)


if __name__=="__main__": raise SystemExit(main())
