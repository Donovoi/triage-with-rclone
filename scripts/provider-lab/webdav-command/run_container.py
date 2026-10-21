"""One opt-in hosted Linux protocol experiment; all operational work is explicit."""
import argparse
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import types
import uuid

ROOT=Path(__file__).absolute().parent
REPOSITORY=ROOT.parents[2]
PREFIX="scripts/provider-lab/webdav-command/"
NAMES=("command_contract.py","token_helper.py","fixture.py","probe.py","entrypoint.py","run_container.py","Dockerfile","build-lock.json")
SOURCE_FILES=tuple(PREFIX+name for name in NAMES)+("rclone-version.env",)
HASH=re.compile(r"[a-f0-9]{64}")
LABEL="org.openai.triage.fixture-id"
KIND="org.openai.triage.fixture-kind"
SOURCE_LABEL="org.openai.triage.fixture-source-sha256"
TMPFS="rw,nosuid,nodev,noexec,size=32m,mode=0700,uid=10001,gid=10001"
ENTRYPOINT=["/usr/local/bin/python3.12"]
COMMAND=["-I","-S","-B","/opt/fixture/webdav-command/entrypoint.py"]
BUILD_PHASE=re.compile(rb"^(?:#[0-9]+ +[0-9.]+ +)?WEBDAV_COMMAND_BUILD_PHASE=(verify|manifest)\r?$",re.MULTILINE)
STAGES=("preflight","pull","build","create","manifest","protocol","complete")
ERRORS=("operation_failed","supervisor_interrupted","supervisor_cleanup_failed","temporary_cleanup_failed","source_or_runtime_changed")
CLEANUP=("commands_stopped","container_removed","image_removed","temporary_removed")
RUNTIME_SHA="ed7ab1f17876bb006c3df3949a3044959671afd9112362dacaa5dd1647735bc1"


class SupervisorError(ValueError):pass


def check(ok,code):
    if not ok:raise SupervisorError(code)


def plain(path):
    path = Path(path)
    try:
        return path.is_absolute() and all(not stat.S_ISLNK(p.lstat().st_mode)
            and not getattr(p.lstat(), "st_file_attributes", 0) & 0x400 for p in (path, *path.parents))
    except OSError:
        return False

def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        check(key not in result, "duplicate_json_key")
        result[key] = value
    return result

def bad_constant(value):
    raise SupervisorError("nonfinite_json")

def parse_json(data):
    check(len(data) <= 262144, "json_size_limit")
    try:
        return json.loads(data, object_pairs_hook=unique_object, parse_constant=bad_constant)
    except (ValueError, UnicodeError):
        raise SupervisorError("invalid_json") from None

def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()

def regular(path, limit=None):
    check(plain(path) and path.is_file() and path.stat().st_nlink == 1, "regular_owned_input_required")
    check(limit is None or path.stat().st_size <= limit, "input_size_limit")

def source_hashes(repository=None):
    repository = REPOSITORY if repository is None else repository
    result = {}
    for name in SOURCE_FILES:
        path = repository / name
        regular(path, 1024 * 1024)
        result[name] = digest(path)
    return result

def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")

def command_identity(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return int(fields[19]), Path(f"/proc/{pid}").stat().st_uid, int(fields[2])

class Docker:
    def __init__(self, root):
        self.root, self.sequence = root, 0
        self.last_stderr = b""
        self.build_phase = None
        self.pending = None
        self.commands_stopped = True
        self.config = root / "docker-config"
        self.config.mkdir(mode=0o700)
        binary = shutil.which("docker")
        check(binary is not None, "docker_missing")
        self.command = [binary, "--config", str(self.config), "--host", "unix:///var/run/docker.sock"]
        self.env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(root), "LANG": "C.UTF-8"}

    def run(self, args, *, timeout=30, allow_failure=False, output_limit=4 * 1024 * 1024):
        check(self.pending is None and self.commands_stopped, "docker_command_reap_unproved")
        self.sequence += 1
        output, error = self.root / f"docker-{self.sequence}.out", self.root / f"docker-{self.sequence}.err"
        with output.open("xb") as out, error.open("xb") as err:
            child = subprocess.Popen([*self.command, *args], cwd=self.root, env=self.env, stdin=subprocess.DEVNULL,
                                     stdout=out, stderr=err, start_new_session=True)
            self.pending = {"child": child, "identity": None}
            self.commands_stopped = False
        deadline = time.monotonic() + timeout
        try:
            if child.poll() is None:
                identity = command_identity(child.pid)
                check(identity[1:] == (os.getuid(), child.pid), "docker_command_ownership_mismatch")
                self.pending["identity"] = identity
            while child.poll() is None:
                check(output.stat().st_size + error.stat().st_size <= output_limit, "docker_output_limit")
                check(time.monotonic() < deadline, "docker_command_timeout")
                time.sleep(0.1)
            check(output.stat().st_size + error.stat().st_size <= output_limit, "docker_output_limit")
            self.last_stderr = error.read_bytes()
            check(allow_failure or child.returncode == 0, "docker_command_failed")
            return child.returncode, output.read_bytes()
        finally:
            self.stop_command()
            if args and args[0] == "build":
                # Fixed markers only. Neither the transcript nor arbitrary error
                # text may enter the public report, even when the build fails.
                with error.open("rb") as stream:
                    transcript = stream.read(4 * 1024 * 1024)
                phases = BUILD_PHASE.findall(transcript)
                if phases:
                    self.build_phase = phases[-1].decode("ascii")

    def stop_command(self):
        if self.pending is None:
            check(self.commands_stopped, "docker_command_reap_unproved")
            return
        record, child = self.pending, self.pending["child"]
        try:
            if child.poll() is None:
                check(record["identity"] is not None and command_identity(child.pid) == record["identity"],
                      "docker_command_ownership_mismatch")
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(3)
                except subprocess.TimeoutExpired:
                    check(command_identity(child.pid) == record["identity"], "docker_command_ownership_mismatch")
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(3)
            check(child.poll() is not None, "docker_command_reap_unproved")
        except (OSError, ValueError, IndexError, subprocess.SubprocessError, SupervisorError):
            # Keep the retained child and false state. No later Docker command
            # or filesystem cleanup may race this command or its output files.
            raise SupervisorError("docker_command_reap_unproved") from None
        self.pending = None
        self.commands_stopped = True

    def inspect(self, kind, target):
        code, data = self.run([kind, "inspect", target], allow_failure=True)
        if code:
            # An unavailable daemon/permission error is not proof of absence.
            expected = re.escape(target)
            missing = re.fullmatch(r"(?:Error response from daemon: |Error: )No such " + kind + r": " + expected,
                                   self.last_stderr.decode("utf-8", errors="replace").strip())
            check(code == 1 and missing is not None, "docker_inspection_failed")
            return None
        parsed = parse_json(data)
        check(isinstance(parsed, list) and len(parsed) == 1 and isinstance(parsed[0], dict), "docker_inspect_invalid")
        return parsed[0]

def cleanup_owned(docker, name, tag, image, run_id):
    check(docker.commands_stopped and docker.pending is None, "docker_command_reap_unproved")
    container_removed = image_removed = False
    container = docker.inspect("container", name)
    if container is not None:
        config = container.get("Config")
        check(isinstance(config, dict) and isinstance(config.get("Labels"), dict)
              and config["Labels"].get(LABEL) == run_id
              and config["Labels"].get(KIND) == "webdav-command-protocol", "cleanup_container_ownership_mismatch")
        container_id = container.get("Id", "")
        check(HASH.fullmatch(container_id), "cleanup_container_id_invalid")
        check(isinstance(container.get("State"), dict), "cleanup_container_state_invalid")
        if container["State"].get("Running"):
            docker.run(["stop", "--time", "5", container_id], timeout=15, allow_failure=True)
        docker.run(["rm", "--force", container_id], timeout=15)
    container_removed = docker.inspect("container", name) is None
    info = docker.inspect("image", image or tag)
    if info is not None:
        config = info.get("Config")
        check(isinstance(config, dict) and isinstance(config.get("Labels"), dict)
              and config["Labels"].get(LABEL) == run_id
              and config["Labels"].get(KIND) == "webdav-command-protocol", "cleanup_image_ownership_mismatch")
        image_id = info.get("Id", "")
        check(re.fullmatch(r"sha256:[a-f0-9]{64}", image_id), "cleanup_image_id_invalid")
        tagged = docker.inspect("image", tag)
        check(isinstance(tagged, dict) and tagged.get("Id") == image_id
              and tagged.get("Config") == info.get("Config"), "cleanup_image_tag_changed")
        # Exact immutable ID, no force/prune. Docker refuses multiple references;
        # a concurrently retargeted tag cannot redirect deletion to another image.
        docker.run(["image", "rm", image_id], timeout=30)
        image_removed = docker.inspect("image", image_id) is None and docker.inspect("image", tag) is None
    else:
        image_removed = True
    return {"container_removed": container_removed, "image_removed": image_removed}

def cleanup_temporary(root, identity):
    check(plain(root) and root.name.startswith("triage-webdav-command-")
          and (root.stat().st_dev, root.stat().st_ino) == identity, "temporary_ownership_mismatch")
    shutil.rmtree(root)
    return not root.exists()


def runtime_identity(binary):
    regular(binary,268435456);regular(REPOSITORY/"rclone-version.env",4096)
    pins={}
    for line in (REPOSITORY/"rclone-version.env").read_text("ascii").splitlines():
        if not line or line.startswith("#"):continue
        key,sep,value=line.partition("=");check(sep and key not in pins,"runtime_manifest_invalid");pins[key]=value
    check(pins.get("RCLONE_VERSION")=="1.75.2" and pins.get("RCLONE_LINUX_EXE_SHA256")==RUNTIME_SHA and digest(binary)==RUNTIME_SHA,"runtime_binding")
    return dict(version="1.75.2",sha256=RUNTIME_SHA)


def read_lock():
    regular(ROOT/"build-lock.json",16384)
    lock=parse_json((ROOT/"build-lock.json").read_bytes())
    expected=dict(schema_version=1,platform="linux/amd64",base_image="docker.io/library/python@sha256:9901e0a8d75037d8242ed43155cbcb2d1f61be1356383d8054afb59fd50e39c4",base_config_digest="sha256:3abf66fa95bf9285d35eac802319797d29d01fbcfef9c0cd560f73d97f4289e8",python_version="3.12.15",python_path=ENTRYPOINT[0],runtime_version="1.75.2",runtime_sha256=RUNTIME_SHA)
    check(type(lock) is dict and lock==expected and type(lock["schema_version"]) is int,"lock_invalid")
    recipe=(ROOT/"Dockerfile").read_text("utf-8")
    check(re.findall(r"^FROM (.+)$",recipe,re.MULTILINE)==[lock["base_image"]] and digest(ROOT/"build-lock.json") in recipe,"recipe_lock_invalid")
    return lock


def load_components(sources):
    loaded={}
    for name in ("command_contract","entrypoint"):
        path=ROOT/(name+".py");raw=path.read_bytes()
        check(hashlib.sha256(raw).hexdigest()==sources[PREFIX+name+".py"],"validator_source_changed")
        module=types.ModuleType("webdav_command_"+name);module.__file__=str(path)
        exec(compile(raw,str(path),"exec"),module.__dict__);loaded[name]=module
    return loaded["command_contract"],loaded["entrypoint"]


def create_args(name,image,run_id):
    check(re.fullmatch(r"triage-webdav-command-[a-f0-9]{32}",name) and re.fullmatch(r"sha256:[a-f0-9]{64}",image) and re.fullmatch(r"[a-f0-9]{32}",run_id),"owned_identity_invalid")
    return ["create","--name",name,"--label",LABEL+"="+run_id,"--label",KIND+"=webdav-command-protocol","--network","none","--read-only","--user","10001:10001","--cap-drop","ALL","--security-opt","no-new-privileges","--pids-limit","64","--memory","512m","--cpus","1","--cgroupns","private","--ipc","private","--init","--hostname","synthetic-command","--tmpfs","/work:"+TMPFS,"--entrypoint",ENTRYPOINT[0],image,*COMMAND]


def validate_image(info,image,run_id,source_digest):
    check(type(info) is dict and info.get("Id")==image and info.get("Architecture")=="amd64" and info.get("Os")=="linux","image_identity")
    c=info.get("Config",{})
    check(type(c) is dict and type(c.get("Labels")) is dict and c["Labels"].get(LABEL)==run_id and c["Labels"].get(KIND)=="webdav-command-protocol" and c["Labels"].get(SOURCE_LABEL)==source_digest,"image_source")
    check(c.get("User")=="10001:10001" and c.get("Entrypoint")==ENTRYPOINT and c.get("Cmd")==COMMAND and c.get("WorkingDir")=="/work" and not c.get("Volumes") and not c.get("ExposedPorts") and not c.get("Healthcheck"),"image_config")
    env=c.get("Env")
    check(type(env) is list and len(env)<=32 and all(type(x) is str and len(x)<=1024 and "=" in x and not x.startswith("RCLONE_") for x in env) and len({x.split("=",1)[0] for x in env})==len(env),"image_environment")
    return env


def validate_container(info,image,run_id,expected_env):
    check(type(info) is dict,"container_shape")
    c,h=info.get("Config"),info.get("HostConfig")
    check(type(c) is dict and type(h) is dict and type(c.get("Labels")) is dict and info.get("Image")==image and c["Labels"].get(LABEL)==run_id and c["Labels"].get(KIND)=="webdav-command-protocol","container_identity")
    check(c.get("User")=="10001:10001" and h.get("NetworkMode")=="none" and h.get("ReadonlyRootfs") is True and h.get("Privileged") is False and h.get("CapDrop")==["ALL"] and not h.get("CapAdd") and h.get("SecurityOpt")==["no-new-privileges"] and h.get("CgroupnsMode")=="private" and h.get("IpcMode")=="private" and not h.get("PidMode") and not h.get("UTSMode") and not h.get("UsernsMode") and h.get("Init") is True,"container_isolation")
    check(type(h.get("Memory")) is int and h["Memory"]==536870912 and type(h.get("NanoCpus")) is int and h["NanoCpus"]==1000000000 and type(h.get("PidsLimit")) is int and h["PidsLimit"]==64 and h.get("Tmpfs")=={"/work":TMPFS},"container_budget")
    check(not any(h.get(k) for k in ("Binds","Mounts","VolumesFrom","Devices","DeviceRequests","PortBindings","ExtraHosts","Links")) and not c.get("Volumes") and not c.get("ExposedPorts") and not c.get("Healthcheck"),"container_resource")
    mounts=info.get("Mounts",[])
    check(type(mounts) is list and len(mounts)<=1 and all(type(m) is dict and m.get("Type")=="tmpfs" and m.get("Destination")=="/work" and not m.get("Source") for m in mounts),"container_mounts")
    check(c.get("Entrypoint")==ENTRYPOINT and c.get("Cmd")==COMMAND and c.get("WorkingDir")=="/work" and c.get("Env")==expected_env,"container_command")
    network=info.get("NetworkSettings")
    check(type(network) is dict and type(network.get("Networks")) is dict and set(network["Networks"])<={"none"},"container_network")


def build_binding(build,sources,revision,E):
    E.validate_build(build)
    expected={name:sources[PREFIX+name] for name in NAMES};expected["rclone-version.env"]=sources["rclone-version.env"]
    check(build["source_sha256"]==expected and build["revision"]==revision,"build_source_binding")
    return build


def bindings_for(build,C):
    names=("command_contract.py","token_helper.py","fixture.py","probe.py")
    return dict(source_revision=build["revision"],source_sha256=hashlib.sha256(C.compact([[n,build["source_sha256"][n]] for n in names])).hexdigest(),runtime_manifest_sha256=build["runtime_manifest_sha256"],runtime_sha256=build["runtime_sha256"],helper_sha256=build["source_sha256"]["token_helper.py"],python_sha256=build["python_sha256"])


def copy_build_manifest(docker,container_id,root,sources,revision,E):
    check(HASH.fullmatch(container_id) and docker.commands_stopped and docker.pending is None,"manifest_ownership")
    target=root/"build-manifest.json"
    check(plain(root) and not target.exists() and not target.is_symlink(),"manifest_destination")
    docker.run(["cp",container_id+":/opt/fixture/build-manifest.json",str(target)],timeout=30,output_limit=16384)
    regular(target,16384)
    return build_binding(parse_json(target.read_bytes()),sources,revision,E)


def validate_entry(raw,build,C):
    check(type(raw) is bytes and len(raw)<=65536,"entry_bound")
    value=parse_json(raw)
    check(type(value) is dict and set(value)=={"schema_version","stage","error","build","protocol"} and type(value["schema_version"]) is int and value["schema_version"]==1,"entry_shape")
    check(value["stage"] in ("preflight","binding","protocol","complete") and (value["error"] is None or value["error"] in ("entrypoint_failed","output_bound")),"entry_enum")
    check(value["build"]==build and value["protocol"] is not None and value["stage"]=="complete" and value["error"] is None,"entry_incomplete")
    return C.validate(value["protocol"],bindings_for(build,C))


def validate_report(value,sources,revision,C,E):
    keys={"schema_version","scope","ledger_eligible","source_revision","source_sha256","runtime","started_utc","finished_utc","stage","success","errors","build","image_id","isolation_before","isolation_after","attach_exit","container_exit","container_stdout_bytes","container_stderr_bytes","oom_killed","start_error_present","protocol","cleanup","source_runtime_preserved","interpreter_hash_evidence","build_cache_scope"}
    check(type(value) is dict and set(value)==keys and type(value["schema_version"]) is int and value["schema_version"]==1,"report_shape")
    check(value["scope"]=="webdav_command_protocol_supervision" and value["ledger_eligible"] is False and value["source_revision"]==revision and value["source_sha256"]==sources and value["runtime"]==dict(version="1.75.2",sha256=RUNTIME_SHA),"report_binding")
    check(value["interpreter_hash_evidence"]=="image_build_manifest_and_in_container_file_check" and value["build_cache_scope"]=="shared_daemon_cache_not_pruned","report_claim")
    check(type(value["stage"]) is str and value["stage"] in STAGES and type(value["success"]) is bool and type(value["errors"]) is list and len(value["errors"])<=5 and all(type(e) is str and e in ERRORS for e in value["errors"]),"report_status")
    for k in ("isolation_before","isolation_after","source_runtime_preserved"):check(type(value[k]) is bool,"report_bool")
    for k in ("oom_killed","start_error_present"):check(value[k] is None or type(value[k]) is bool,"report_nullable_bool")
    for k in ("attach_exit","container_exit"):check(value[k] is None or type(value[k]) is int and -255<=value[k]<=255,"report_exit")
    for k in ("container_stdout_bytes","container_stderr_bytes"):check(value[k] is None or type(value[k]) is int and 0<=value[k]<=262144,"report_bytes")
    check(value["image_id"] is None or type(value["image_id"]) is str and re.fullmatch("sha256:[a-f0-9]{64}",value["image_id"]),"report_image")
    check(type(value["cleanup"]) is dict and set(value["cleanup"])==set(CLEANUP) and all(type(v) is bool for v in value["cleanup"].values()),"report_cleanup")
    times=[]
    for key in ("started_utc","finished_utc"):
        v=value[key];check(type(v) is str and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z",v),"report_time")
        times.append(datetime.fromisoformat(v.replace("Z","+00:00")))
    check(times[1]>=times[0],"report_time_order")
    if value["build"] is not None:build_binding(value["build"],sources,revision,E)
    if value["protocol"] is not None:
        check(value["build"] is not None,"protocol_build");C.validate(value["protocol"],bindings_for(value["build"],C))
    if value["success"]:
        check(value["stage"]=="complete" and not value["errors"] and value["image_id"] is not None and value["isolation_before"] and value["isolation_after"] and value["source_runtime_preserved"] and all(value["cleanup"].values()),"success_cleanup")
        check(value["attach_exit"]==value["container_exit"]==0 and value["oom_killed"] is False and value["start_error_present"] is False and value["container_stderr_bytes"]==0 and value["container_stdout_bytes"] is not None and value["container_stdout_bytes"]>0 and value["protocol"] is not None and value["protocol"]["result"]=="passed","success_native")
    else:check(bool(value["errors"]),"failure_reason")
    check(len(C.compact(value))+1<=65536,"normalized_bound")
    return value


def stage_context(context,binary,sources,revision):
    context.mkdir(mode=0o700);profile=context/"webdav-command";profile.mkdir(mode=0o700)
    for name in NAMES:
        shutil.copyfile(ROOT/name,profile/name);check(digest(profile/name)==sources[PREFIX+name],"staged_source_changed")
    for src,dst,expected in ((REPOSITORY/"rclone-version.env",context/"rclone-version.env",sources["rclone-version.env"]),(binary,context/"rclone",RUNTIME_SHA)):
        shutil.copyfile(src,dst);check(digest(dst)==expected,"staged_binding_changed")
    shutil.copyfile(profile/"Dockerfile",context/"Dockerfile")
    manifest={name:sources[PREFIX+name] for name in NAMES};manifest["rclone-version.env"]=sources["rclone-version.env"]
    with (context/"source-manifest.json").open("x",encoding="ascii") as f:json.dump(manifest,f,sort_keys=True,separators=(",",":"))
    with (context/"source-revision").open("x",encoding="ascii") as f:f.write(revision)


def verify_revision(revision):
    check(type(revision) is str and re.fullmatch("[a-f0-9]{40}",revision),"revision_invalid")
    got=subprocess.run(["git","-C",str(REPOSITORY),"rev-parse","HEAD"],capture_output=True,timeout=10,check=True)
    check(got.stdout==revision.encode("ascii")+b"\n" and not got.stderr,"revision_mismatch")


def verify_tracked_sources(revision,sources):
    verify_revision(revision)
    check(type(sources) is dict and set(sources)==set(SOURCE_FILES),"tracked_source_set")
    got=subprocess.run(["git","-C",str(REPOSITORY),"ls-tree","-z","--full-tree",revision,"--",*SOURCE_FILES],capture_output=True,timeout=10,check=True)
    check(type(got.stdout) is bytes and len(got.stdout)<=4096 and not got.stderr and got.stdout.endswith(b"\0"),"tracked_tree_bound")
    records=got.stdout[:-1].split(b"\0");check(len(records)==len(SOURCE_FILES),"tracked_tree_count")
    tracked={}
    for record in records:
        match=re.fullmatch(rb"(100644|100755) blob ([a-f0-9]{40})\t([a-zA-Z0-9_./-]+)",record)
        check(match is not None,"tracked_tree_record")
        name=match[3].decode("ascii")
        check(name in sources and name not in tracked,"tracked_tree_path")
        tracked[name]=match[2].decode("ascii")
    check(set(tracked)==set(sources),"tracked_tree_set")
    for name in SOURCE_FILES:
        path=REPOSITORY/name;regular(path,1048576)
        with path.open("rb") as stream:raw=stream.read(1048577)
        check(len(raw)<=1048576 and hashlib.sha256(raw).hexdigest()==sources[name],"tracked_source_changed")
        blob=hashlib.sha1(b"blob "+str(len(raw)).encode("ascii")+b"\0"+raw).hexdigest()
        check(blob==tracked[name],"tracked_blob_mismatch")


def run(binary,report_path,revision):
    check(sys.platform=="linux" and os.environ.get("GITHUB_ACTIONS")=="true" and os.environ.get("RUNNER_ENVIRONMENT")=="github-hosted","hosted_linux_required")
    check(report_path.is_absolute() and plain(report_path.parent) and report_path.parent.is_dir() and not report_path.exists() and not report_path.is_symlink(),"new_report_required")
    identity=runtime_identity(binary);sources=source_hashes();verify_tracked_sources(revision,sources);lock=read_lock();C,E=load_components(sources)
    source_digest=canonical_hash(sources);run_id=uuid.uuid4().hex
    name="triage-webdav-command-"+run_id;tag="triage-webdav-command-fixture:"+run_id
    report=dict(schema_version=1,scope="webdav_command_protocol_supervision",ledger_eligible=False,source_revision=revision,source_sha256=sources,runtime=identity,started_utc=utc_now(),finished_utc=None,stage="preflight",success=False,errors=[],build=None,image_id=None,isolation_before=False,isolation_after=False,attach_exit=None,container_exit=None,container_stdout_bytes=None,container_stderr_bytes=None,oom_killed=None,start_error_present=None,protocol=None,cleanup={k:False for k in CLEANUP},source_runtime_preserved=False,interpreter_hash_evidence="image_build_manifest_and_in_container_file_check",build_cache_scope="shared_daemon_cache_not_pruned")
    root=Path(tempfile.mkdtemp(prefix="triage-webdav-command-"));owned=(root.stat().st_dev,root.stat().st_ino)
    docker=image=None;attempted_build=False
    try:
        check(plain(root),"temporary_root");docker=Docker(root)
        _,raw=docker.run(["info","--format","{{json .}}"]);info=parse_json(raw)
        check(type(info) is dict and info.get("OSType")=="linux" and info.get("Architecture") in ("x86_64","amd64"),"docker_platform")
        context=root/"context";stage_context(context,binary,sources,revision)
        report["stage"]="pull"
        docker.run(["image","pull","--quiet","--platform","linux/amd64",lock["base_image"]],timeout=120)
        base=docker.inspect("image",lock["base_image"])
        check(type(base) is dict and base.get("Id")==lock["base_config_digest"] and base.get("Architecture")=="amd64" and base.get("Os")=="linux","base_image")
        report["stage"]="build";attempted_build=True;iid=root/"image-id"
        docker.run(["build","--no-cache","--force-rm","--platform","linux/amd64","--label",LABEL+"="+run_id,"--label",SOURCE_LABEL+"="+source_digest,"--tag",tag,"--iidfile",str(iid),str(context)],timeout=300)
        regular(iid,80);image=iid.read_text("ascii").strip();check(re.fullmatch("sha256:[a-f0-9]{64}",image),"built_image_id")
        built=docker.inspect("image",image);env=validate_image(built,image,run_id,source_digest);report["image_id"]=image
        report["stage"]="create";docker.run(create_args(name,image,run_id))
        initial=docker.inspect("container",name) or {};validate_container(initial,image,run_id,env)
        state=initial.get("State")
        check(type(state) is dict and state.get("Running") is False and state.get("Status")=="created" and type(initial.get("Id")) is str and HASH.fullmatch(initial["Id"]),"container_created")
        container_id=initial["Id"];report["isolation_before"]=True
        report["stage"]="manifest";report["build"]=copy_build_manifest(docker,container_id,root,sources,revision,E)
        # Copy reads one fixed regular file from this exact created container.
        after_copy=docker.inspect("container",container_id) or {};validate_container(after_copy,image,run_id,env)
        check(after_copy.get("Id")==container_id and after_copy.get("State")==state,"created_state_changed")
        report["stage"]="protocol"
        code,raw=docker.run(["start","--attach",container_id],timeout=780,allow_failure=True,output_limit=262144)
        stderr=docker.last_stderr
        report.update(attach_exit=code,container_stdout_bytes=len(raw),container_stderr_bytes=len(stderr))
        final=docker.inspect("container",container_id) or {};validate_container(final,image,run_id,env)
        state=final.get("State")
        check(final.get("Id")==container_id and type(state) is dict and state.get("Running") is False and state.get("Status")=="exited","container_final")
        check(type(state.get("ExitCode")) is int and -255<=state["ExitCode"]<=255 and type(state.get("OOMKilled")) is bool and type(state.get("Error")) is str,"container_state")
        report.update(isolation_after=True,container_exit=state["ExitCode"],oom_killed=state["OOMKilled"],start_error_present=bool(state["Error"]))
        report["protocol"]=validate_entry(raw,report["build"],C)
        check(code==0 and state["ExitCode"]==0 and not state["OOMKilled"] and not state["Error"] and not stderr and report["protocol"]["result"]=="passed","protocol_failed")
        report["success"]=True;report["stage"]="complete"
    except KeyboardInterrupt:report["errors"].append("supervisor_interrupted")
    except (SupervisorError,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):report["errors"].append("operation_failed")
    finally:
        try:
            check(docker is None or docker.commands_stopped and docker.pending is None,"command_lifetime")
            if docker is not None and attempted_build:report["cleanup"].update(cleanup_owned(docker,name,tag,image,run_id))
            else:report["cleanup"].update(container_removed=True,image_removed=True)
        except (SupervisorError,OSError,ValueError,TypeError,subprocess.SubprocessError):report["errors"].append("supervisor_cleanup_failed")
        finally:report["cleanup"]["commands_stopped"]=docker is None or docker.commands_stopped and docker.pending is None
        try:
            check(all(report["cleanup"][k] for k in ("commands_stopped","container_removed","image_removed")),"cleanup_unproved")
            report["cleanup"]["temporary_removed"]=cleanup_temporary(root,owned)
        except (SupervisorError,OSError):report["errors"].append("temporary_cleanup_failed")
        try:
            check(source_hashes()==sources and runtime_identity(binary)==identity,"source_or_runtime_changed")
            verify_tracked_sources(revision,sources)
            report["source_runtime_preserved"]=True
        except (SupervisorError,OSError,ValueError,TypeError,subprocess.SubprocessError):report["errors"].append("source_or_runtime_changed")
        report["success"]=report["success"] and not report["errors"] and all(report["cleanup"].values())
        report["finished_utc"]=utc_now();validate_report(report,sources,revision,C,E)
        with report_path.open("xb") as f:f.write(C.compact(report)+b"\n")
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rclone",required=True,type=Path);parser.add_argument("--report",required=True,type=Path)
    parser.add_argument("--revision",required=True);parser.add_argument("--validate-only",action="store_true")
    args=parser.parse_args()
    def interrupted(_signum,_frame):raise KeyboardInterrupt
    signal.signal(signal.SIGTERM,interrupted)
    try:
        if args.validate_only:
            runtime_identity(args.rclone);sources=source_hashes();verify_tracked_sources(args.revision,sources);read_lock();C,E=load_components(sources)
            regular(args.report,65536);result=validate_report(parse_json(args.report.read_bytes()),sources,args.revision,C,E)
        else:result=run(args.rclone,args.report,args.revision)
        print(json.dumps(dict(success=result["success"],stage=result["stage"],errors=result["errors"],ledger_eligible=False)))
        return 0 if result["success"] else 1
    except (Exception,KeyboardInterrupt):
        print("WebDAV command protocol evidence unavailable",file=sys.stderr);return 1


if __name__=="__main__":raise SystemExit(main())
