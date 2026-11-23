"""Run native Storj/Tardigrade reads in an isolated disposable test network."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import uuid

import build_fixture as build_tools
import protocol_evidence as contract

ROOT = Path(__file__).absolute().parent
LABEL = "org.triage.storj-native"

def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def resource_inventory(root):
    root = Path(root)
    result = {}
    for path in sorted(root.rglob("*")):
        contract.require(not path.is_symlink(), "resource_link_refused")
        if path.is_file():
            build_tools.regular(path, 1024*1024)
            result[str(path.relative_to(root))] = build_tools.digest(path)
    return result

def verified_build(path, bindings):
    path = Path(path).absolute()
    build = json.loads(build_tools.regular(path/"build.json",1024*1024).read_text())
    contract.validate_build(build,bindings)
    binary = build_tools.regular(path/"planet.test",192*1024*1024)
    contract.require(build_tools.digest(binary)==build["binary_sha256"]
                     and binary.stat().st_size==build["binary_bytes"],"compiled_binary_changed")
    contract.require(resource_inventory(path/"resources")==build["resources_sha256"],"resources_changed")
    return build

def verify_isolation(value, image_id, runid):
    host=value["HostConfig"];config=value["Config"]
    contract.require(value["Image"]==image_id and config["Labels"].get(LABEL)==runid
        and config["User"]=="999:999" and host["NetworkMode"]=="none" and host["ReadonlyRootfs"] is True
        and host["CapDrop"]==["ALL"] and "no-new-privileges" in host["SecurityOpt"]
        and host["NanoCpus"]==1500000000 and host["Memory"]==1536*1024*1024
        and host["MemorySwap"]==1536*1024*1024 and host["PidsLimit"]==384
        and host["CgroupnsMode"]=="private" and host["IpcMode"]=="private" and host["Init"] is True
        and not host.get("Binds") and not host.get("PortBindings")
        and set(host["Tmpfs"])=={"/work","/var/lib/postgresql"}
        and all(x["Type"]=="tmpfs" for x in value["Mounts"]),"container_isolation_invalid")
    for target,size in (("/work","512m"),("/var/lib/postgresql","16m")):
        flags=set(host["Tmpfs"][target].split(","))
        contract.require(flags=={"rw","nosuid","nodev","noexec","size="+size,"mode=0700","uid=999","gid=999"},
                         "container_tmpfs_invalid")

def parse_probe(stdout):
    lines=stdout.splitlines()
    markers=[x.removeprefix("TRIAGE_STORJ_NATIVE_RESULT ") for x in lines
             if x.startswith("TRIAGE_STORJ_NATIVE_RESULT ")]
    contract.require(len(markers)==1 and "--- PASS: TestSyntheticNetwork/Postgres" in stdout
        and "--- PASS: TestSyntheticNetwork (" in stdout
        and "--- FAIL" not in stdout and "--- SKIP" not in stdout,"probe_failed")
    probe=json.loads(markers[0])
    contract.validate_probe(probe)
    return probe

def execute(build_root,rclone):
    bindings=contract.compute_bindings(ROOT);pins=bindings["pins"]
    built=verified_build(build_root,bindings)
    rclone=build_tools.regular(rclone,256*1024*1024)
    contract.require(build_tools.digest(rclone)==pins["rclone_sha256"],"rclone_binary_mismatch")
    runtime={"version":pins["rclone_version"],"sha256":pins["rclone_sha256"]}
    runid=uuid.uuid4().hex;name="triage-storj-native-"+runid;tag=name+":fixture"
    context=Path(tempfile.mkdtemp(prefix=name+"-")).absolute();parent=context.parent
    expected_files={"planet.test","rclone","Dockerfile","entrypoint.sh"}
    image_id=cid=None;probe=None;failure=None
    native={"source_sha256":bindings["source_sha256"],"build":built,"base_image":pins["runtime_image"],
            "image_id":None,"isolation_verified":False,"probe":None,"exit_code":None,
            "oom_killed":None,"stdout_bytes":0,"stderr_bytes":0,
            "cleanup":{k:False for k in contract.CLEANUP_KEYS}}
    started=utc_now()
    try:
        shutil.copyfile(Path(build_root)/"planet.test",context/"planet.test")
        shutil.copyfile(rclone,context/"rclone")
        for source in ("Dockerfile","entrypoint.sh"):
            (context/source).write_bytes(contract.file_bytes(ROOT/source))
        contract.require((context/"Dockerfile").read_text().splitlines()[0]=="FROM "+pins["runtime_image"],
                         "runtime_image_pin_mismatch")
        shutil.copytree(Path(build_root)/"resources",context/"resources")
        expected_files|={"resources/"+x for x in built["resources_sha256"]}
        contract.require(build_tools.digest(context/"planet.test")==built["binary_sha256"]
                         and build_tools.digest(context/"rclone")==runtime["sha256"]
                         and resource_inventory(context/"resources")==built["resources_sha256"],
                         "staged_input_changed")
        build_tools.call(["docker","pull",pins["runtime_image"]],300)
        base=build_tools.inspect(["image"],pins["runtime_image"])
        contract.require(base["Architecture"]=="amd64" and base["Os"]=="linux"
            and set(base["Config"].get("Volumes",{}))=={"/var/lib/postgresql"},"base_image_invalid")
        build_tools.call(["docker","build","--network","none","--label",LABEL+"="+runid,"-t",tag,str(context)],180)
        image=build_tools.inspect(["image"],tag);image_id=image["Id"]
        contract.require(image["Config"]["Labels"][LABEL]==runid and image["RepoTags"]==[tag],
                         "image_ownership_invalid")
        native["image_id"]=image_id;started=utc_now()
        args=["docker","create","--name",name,"--label",LABEL+"="+runid,"--network","none",
              "--read-only","--user","999:999","--cap-drop","ALL","--security-opt","no-new-privileges",
              "--cpus","1.5","--memory","1536m","--memory-swap","1536m","--pids-limit","384",
              "--cgroupns","private","--ipc","private","--init",
              "--tmpfs","/work:rw,nosuid,nodev,noexec,size=512m,mode=0700,uid=999,gid=999",
              "--tmpfs","/var/lib/postgresql:rw,nosuid,nodev,noexec,size=16m,mode=0700,uid=999,gid=999",image_id]
        cid=build_tools.call(args).stdout.strip()
        verify_isolation(build_tools.inspect([],cid),image_id,runid);native["isolation_verified"]=True
        expected_files|={"stdout.private","stderr.private"}
        with (context/"stdout.private").open("w") as out,(context/"stderr.private").open("w") as err:
            result=subprocess.run(["docker","start","--attach",cid],stdout=out,stderr=err,timeout=180)
        state=build_tools.inspect([],cid)["State"]
        native.update(exit_code=result.returncode,oom_killed=state["OOMKilled"],
                      stdout_bytes=(context/"stdout.private").stat().st_size,
                      stderr_bytes=(context/"stderr.private").stat().st_size)
        contract.require(result.returncode==0 and state["ExitCode"]==0 and state["OOMKilled"] is False,
                         "native_execution_failed")
        contract.require(0<native["stdout_bytes"]<=4*1024*1024 and native["stderr_bytes"]<=4*1024*1024,
                         "native_output_invalid")
        probe=parse_probe((context/"stdout.private").read_text())
        native["probe"]=probe
        contract.require(contract.compute_bindings(ROOT)==bindings,"source_changed")
        contract.require(verified_build(build_root,bindings)==built and build_tools.digest(rclone)==runtime["sha256"],
                         "runtime_input_changed")
    except (OSError,ValueError,KeyError,subprocess.SubprocessError) as error:
        code=str(error)
        failure=code if type(error) is ValueError and re.fullmatch(r"storj_[a-z0-9_]{1,64}",code) else "storj_native_run_failed"
    finally:
        if cid:
            owned=build_tools.inspect([],cid)
            contract.require(owned["Config"]["Labels"][LABEL]==runid and owned["Image"]==image_id,
                             "container_cleanup_ownership_invalid")
            build_tools.call(["docker","rm","--force","--volumes",cid])
            native["cleanup"]["container_removed"]=True
        if image_id:
            owned=build_tools.inspect(["image"],image_id)
            contract.require(owned["Config"]["Labels"][LABEL]==runid and owned["RepoTags"]==[tag],
                             "image_cleanup_ownership_invalid")
            build_tools.call(["docker","image","rm",image_id])
            native["cleanup"]["image_removed"]=True
        contract.require(context.parent==parent and context.resolve().parent==parent.resolve()
            and not context.is_symlink() and not any(x.is_symlink() for x in context.rglob("*"))
            and {str(x.relative_to(context)) for x in context.rglob("*") if x.is_file()}<=expected_files,
            "temporary_cleanup_ownership_invalid")
        shutil.rmtree(context)
        native["cleanup"]["temporary_removed"]=not context.exists()
    success=failure is None and probe is not None and all(native["cleanup"].values())
    errors=[] if success else [failure or "storj_native_run_failed"]
    receipt={"schema_version":36,"scope":"rclone_backend_protocol_fixture","runtime":runtime,
             "platform":"linux","architecture":"amd64","harness_sha256":bindings["harness_sha256"],
             "fixture_manifest_sha256":bindings["fixture_manifest_sha256"],"started_utc":started,
             "finished_utc":utc_now(),"success":success,"cleanup_passed":all(native["cleanup"].values()),
             "backends":[{"backend":backend,"fixture_kind":"independent_storj_test_network",
                          "fixture_mode":contract.MODE,"capabilities":{k:"passed" if success else "failed"
                          for k in contract.CAPABILITIES},"errors":errors} for backend in contract.BACKENDS],
             "errors":errors,"native_evidence":native}
    if success:
        contract.validate_evidence(receipt,runtime,bindings,datetime.now(timezone.utc))
    return receipt

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build",required=True,help="Fresh output from build_fixture.py")
    parser.add_argument("--rclone",required=True)
    parser.add_argument("--report",required=True)
    args=parser.parse_args()
    report=Path(args.report).absolute()
    contract.require(not report.exists() and report.parent.is_dir()
        and not any(x.is_symlink() for x in (report.parent,*report.parent.parents)),"new_report_path_required")
    def interrupted(signum,frame):
        raise ValueError("storj_interrupted")
    for sig in (signal.SIGTERM,signal.SIGINT):
        signal.signal(sig,interrupted)
    try:
        receipt=execute(args.build,args.rclone)
    except (OSError,ValueError,KeyError,subprocess.SubprocessError):
        print(json.dumps({"success":False,"error":"storj_fixture_failed"}))
        return 1
    with report.open("x") as stream:
        json.dump(receipt,stream,indent=2);stream.write("\n")
    print(json.dumps({"success":receipt["success"],"backends":list(contract.BACKENDS),
                      "native_commands":len(receipt["native_evidence"]["probe"]["native_checks"])
                      if receipt["native_evidence"]["probe"] else 0,
                      "cleanup_passed":receipt["cleanup_passed"]}))
    return 0 if receipt["success"] else 1

if __name__=="__main__":
    raise SystemExit(main())
