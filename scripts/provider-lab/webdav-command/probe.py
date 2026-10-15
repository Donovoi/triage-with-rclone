"""Opt-in Linux protocol core. No entrypoint or operational work on import.

The separate future supervisor must materialize/load only the verified source
closure and establish its reviewed immutable image and container isolation.
"""
import hashlib
import itertools
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
import command_contract as C
import fixture as F

SOURCE_FILES = ("command_contract.py", "token_helper.py", "fixture.py", "probe.py")
WORK = Path("/work")
HELPER = Path("/opt/fixture/webdav-command/token_helper.py")
BINARY = Path("/opt/fixture/rclone")
MAX_OUTPUT = 262144


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def regular(path, limit):
    info = path.lstat()
    C.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid() and info.st_size <= limit, "output")
    return info


def bounded_read(path, limit):
    before = regular(path, limit)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        held = os.fstat(fd)
        C.require((held.st_dev,held.st_ino) == (before.st_dev,before.st_ino), "output")
        with os.fdopen(fd, "rb", closefd=False) as stream: body = stream.read(limit+1)
        after = regular(path, limit)
        C.require((after.st_dev,after.st_ino,after.st_size) == (held.st_dev,held.st_ino,len(body)) and len(body) <= limit, "output")
        return body
    finally:
        os.close(fd)


def private_write(path, body):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        C.require(stream.write(body) == len(body), "setup")


def identity(pid):
    text = Path(f"/proc/{pid}/stat").read_text()
    fields = text.rsplit(")",1)[1].split()
    return (int(fields[19]), Path(f"/proc/{pid}").stat().st_uid, int(fields[2]), int(fields[3]))


def group_empty(pgid):
    entries = list(itertools.islice(Path("/proc").iterdir(), 4097))
    C.require(len(entries) <= 4096, "cleanup")
    for path in entries:
        if path.name.isdecimal():
            try: found = identity(int(path.name))
            except FileNotFoundError: continue
            if found[2] == pgid or found[3] == pgid:
                return False
    return True


def arguments(role, binary, config, output):
    common = [str(binary), "--config", str(config), "--log-level", "ERROR", "--stats", "0", "rc", "--loopback"]
    if role == "stat":
        return common + ["operations/stat", "fs=Synthetic:", "remote=payload.bin", 'opt={"noModTime":true,"noMimeType":true,"filesOnly":true}']
    C.require(role == "copy", "runtime")
    return common + ["operations/copyfile", "srcFs=Synthetic:", "srcRemote=payload.bin", "dstFs="+str(output), "dstRemote=payload.bin"]


def command_config(endpoint, python):
    C.require(re.fullmatch(r"http://127\.0\.0\.1:[1-9][0-9]{0,4}/", endpoint) and 1 <= int(endpoint.split(":")[-1][:-1]) <= 65535, "setup")
    C.require(re.fullmatch(r"/usr/local/bin/python3(?:\.[0-9]+)?", str(python)), "binding")
    # Both fixed POSIX paths contain no CSV separators or quotes; no shell.
    return ("[Synthetic]\ntype = webdav\nurl = "+endpoint+"\nvendor = other\nbearer_token_command = "+str(python)+" -I -S -B "+HELPER.as_posix()+"\n").encode("ascii")


class Child:
    def __init__(self, role, root, deadline, env, hooks=None):
        self.role, self.root, self.deadline = role, root, deadline
        self.h = hooks or dict(Popen=subprocess.Popen, clock=time.monotonic, sleep=time.sleep, identity=identity, killpg=os.killpg, group_empty=group_empty)
        self.process = self.bound = None
        self.uncertain = False
        self.observed = dict(role=role, exit_code=None, identity_checked=None, reaped=None, group_empty=None, forced=False)
        self.out, self.err = root/(role+".out"), root/(role+".err")
        self.env = env

    def start(self):
        C.require(self.process is None and self.h["clock"]() < self.deadline, "deadline")
        self.uncertain = True
        with self.out.open("xb") as out, self.err.open("xb") as err:
            self.process = self.h["Popen"](arguments(self.role,BINARY,self.root/"synthetic.conf",self.root/"output"), cwd=self.root, env=self.env,
                stdin=subprocess.DEVNULL, stdout=out, stderr=err, start_new_session=True)
        self.uncertain = False
        self.bound = self.h["identity"](self.process.pid)
        C.require(self.bound[1:] == (os.getuid(),self.process.pid,self.process.pid), "runtime")
        self.observed["identity_checked"] = True

    def live(self):
        C.require(self.process is not None and self.process.poll() is None and self.h["identity"](self.process.pid) == self.bound, "runtime")

    def check(self):
        C.require(self.h["clock"]() < self.deadline, "deadline")
        regular(self.out,MAX_OUTPUT); regular(self.err,MAX_OUTPUT)

    def wait(self):
        C.require(self.process is not None, "runtime")
        while self.process.poll() is None:
            self.check(); self.h["sleep"](0.02)
        self.process.wait()
        self.observed["exit_code"] = self.process.returncode
        self.observed["reaped"] = True
        self.check()
        self.observed["group_empty"] = self.h["group_empty"](self.process.pid)
        C.require(self.observed["group_empty"], "cleanup")
        return bounded_read(self.out,MAX_OUTPUT), bounded_read(self.err,MAX_OUTPUT)

    def cancel_once(self, evidence):
        C.require(evidence["signal_attempts"] == 0 and evidence["reader_closed"] is True and len(evidence["extents"]) == 2, "signal")
        self.live(); evidence["group_identity_checked"] = True
        evidence["signal_attempts"] = 1
        self.h["killpg"](self.process.pid,signal.SIGINT)

    def close(self, cleanup_deadline):
        if self.process is None:
            return not self.uncertain
        try:
            if self.process.poll() is None:
                self.live(); self.observed["forced"] = True
                self.h["killpg"](self.process.pid,signal.SIGTERM)
                try: self.process.wait(timeout=min(3,max(0,cleanup_deadline-self.h["clock"]())))
                except subprocess.TimeoutExpired:
                    self.live(); self.h["killpg"](self.process.pid,signal.SIGKILL)
                    self.process.wait(timeout=min(3,max(0,cleanup_deadline-self.h["clock"]())))
            self.process.wait(timeout=max(0,cleanup_deadline-self.h["clock"]()))
            self.observed["exit_code"] = self.process.returncode
            self.observed["reaped"] = True
            self.observed["group_empty"] = self.h["group_empty"](self.process.pid)
            return self.observed["group_empty"] is True
        except (OSError, C.Rejected, subprocess.TimeoutExpired):
            return False


class Witness:
    def __init__(self, root):
        self.root = root
        info = root.lstat(); C.require(stat.S_ISDIR(info.st_mode) and not root.is_symlink(), "witness")
        self.parent = (info.st_dev,info.st_ino)
        self.fd = self.path = self.key = None

    def sample(self, index):
        C.require(index in (0,1), "witness")
        names = list(itertools.islice(self.root.iterdir(),3))
        C.require(len(names) <= 1, "witness")
        if not names: return None
        path = names[0]
        C.require(re.fullmatch(r"payload\.bin\.[0-9a-f]{8}\.partial",path.name), "witness")
        info = regular(path,C.CANCEL_SIZE)
        if self.fd is None:
            self.fd = os.open(path,os.O_RDONLY | os.O_NOFOLLOW)
            self.path, self.key = path,(info.st_dev,info.st_ino)
        self.verify()
        size = C.EXTENTS[index]
        if os.fstat(self.fd).st_size < size: return None
        os.lseek(self.fd,0,os.SEEK_SET)
        chunks=[]; remaining=size
        while remaining:
            chunk=os.read(self.fd,min(65536,remaining))
            if not chunk: return None
            chunks.append(chunk); remaining-=len(chunk)
        self.verify(); result=hashlib.sha256(b"".join(chunks)).hexdigest()
        # Preallocated zeroes or a short/growing prefix never qualify.
        if result != C.EXTENT_SHAS[index]: return None
        return dict(bytes=size,sha256=result,identity_verified=True)

    def verify(self):
        parent=self.root.lstat(); named=regular(self.path,C.CANCEL_SIZE); held=os.fstat(self.fd)
        C.require((parent.st_dev,parent.st_ino)==self.parent and stat.S_ISDIR(parent.st_mode), "witness")
        C.require((named.st_dev,named.st_ino)==self.key==(held.st_dev,held.st_ino) and held.st_nlink==1 and stat.S_ISREG(held.st_mode), "witness")

    def close(self):
        if self.fd is not None:
            os.close(self.fd); self.fd=None


def helper_records(root, case):
    files=list(itertools.islice((root/"journal").iterdir(),205))
    C.require(len(files)<=204 and len(files)%2==0, "helper")
    count=len(files)//2
    C.require(count<=C.MAX_HELPERS[case] and {p.name for p in files}=={f"{i:03}-{k}.json" for i in range(1,count+1) for k in ("start","done")}, "helper")
    result=[]
    for i in range(1,count+1):
        expected=C.expected_helper(case,i)
        C.require(C.parse(bounded_read(root/"journal"/f"{i:03}-start.json",256),256)==dict(sequence=i,action=expected["action"]), "helper")
        C.require(C.parse(bounded_read(root/"journal"/f"{i:03}-done.json",256),256)==expected, "helper")
        result.append(expected)
    return result


def stat_exact(raw, size):
    value=C.parse(raw,MAX_OUTPUT)
    C.require(type(value) is dict and set(value)=={"item"} and type(value["item"]) is dict, "stat")
    item=value["item"]
    C.require(item.get("Path")=="payload.bin" and item.get("Name")=="payload.bin" and type(item.get("Size")) is int and item["Size"]==size and item.get("IsDir") is False, "stat")


def remove_owned(root, identity_key):
    info=root.lstat()
    C.require(stat.S_ISDIR(info.st_mode) and (info.st_dev,info.st_ino)==identity_key, "cleanup")
    allowed_dirs={root/name for name in ("journal","output","home","cache","tmp")}
    rows=list(itertools.islice(root.iterdir(),17)); C.require(len(rows)<=16,"cleanup")
    files=[]; dirs=[]
    for path in rows:
        info=path.lstat()
        if stat.S_ISDIR(info.st_mode):
            C.require(path in allowed_dirs,"cleanup"); dirs.append(path)
            children=list(itertools.islice(path.iterdir(),205)); C.require(len(children)<=204,"cleanup")
            for child in children:
                regular(child,MAX_OUTPUT if path.name!="output" else C.CANCEL_SIZE); files.append(child)
        else:
            C.require(path.name in {"control.json","helper.lock","synthetic.conf","stat.out","stat.err","copy.out","copy.err"},"cleanup")
            regular(path,MAX_OUTPUT); files.append(path)
    for path in files: path.unlink()
    for path in dirs: path.rmdir()
    root.rmdir()
    return not root.exists()


def case_run(case, python, bindings, source_check, batch_deadline, factory=Child, fixture_factory=F.Server, clock=time.monotonic, sleep=time.sleep):
    row=C.empty_case(case); started=clock(); deadline=min(batch_deadline,started+C.BUDGETS[case])
    root=WORK/("case-"+case); children=[]; server=witness=None; owned=None; config_hash=control_hash=None; failure="setup"
    try:
        root.mkdir(mode=0o700); info=root.lstat(); owned=(info.st_dev,info.st_ino)
        for name in ("journal","output","home","cache","tmp"): (root/name).mkdir(mode=0o700)
        private_write(root/"control.json",C.compact(dict(schema_version=1,case=case))+b"\n")
        control_hash=digest(root/"control.json")
        private_write(root/"helper.lock",b"")
        server=fixture_factory(case,deadline,clock); endpoint=server.start()
        private_write(root/"synthetic.conf",command_config(endpoint,python)); config_hash=digest(root/"synthetic.conf")
        env={"PATH":"/usr/local/bin:/usr/bin:/bin","HOME":str(root/"home"),"XDG_CONFIG_HOME":str(root/"home"),"XDG_CACHE_HOME":str(root/"cache"),"TMPDIR":str(root/"tmp"),"LANG":"C.UTF-8","LC_ALL":"C.UTF-8","PYTHONDONTWRITEBYTECODE":"1","PYTHONNOUSERSITE":"1"}
        failure="runtime"; child=factory("stat",root,deadline,env); children.append(child); child.start()
        raw,_=child.wait(); failure="stat"
        if case.startswith("initial_"):
            C.require(child.observed["exit_code"]!=0,"stat")
        else:
            C.require(child.observed["exit_code"]==0,"stat"); stat_exact(raw,C.CANCEL_SIZE if case=="cancellation" else 30)
            failure="runtime"; child=factory("copy",root,deadline,env); children.append(child); child.start()
            if case=="cancellation":
                failure="witness"; witness=Witness(root/"output")
                for index in range(2):
                    while True:
                        child.check(); child.live()
                        events,failed=server.snapshot(); C.require(not failed,"fixture")
                        sample=witness.sample(index)
                        if sample is not None:
                            row["cancellation"]["extents"].append(sample)
                            (server.first_observed if index==0 else server.second_observed).set(); break
                        sleep(0.02)
                witness.close(); row["cancellation"]["reader_closed"]=True; witness=None
                failure="helper"; C.require(len(helper_records(root,case))==3,"helper")
                failure="signal"; child.cancel_once(row["cancellation"])
            failure="copy"; child.wait()
            C.require((child.observed["exit_code"]==0)==(case=="renewal"),"copy")
        failure="helper"; row["helpers"]=helper_records(root,case)
        C.require(len(row["helpers"])==C.MAX_HELPERS[case],"helper")
        failure="output"; items=list(itertools.islice((root/"output").iterdir(),3))
        if case=="renewal":
            C.require(items==[root/"output"/"payload.bin"],"output")
            body=bounded_read(items[0],30); C.require(len(body)==30 and hashlib.sha256(body).hexdigest()==C.BODY_SHA,"output")
            row["output"]=dict(kind="exact_content",bytes=30,sha256=C.BODY_SHA)
        else:
            C.require(not items,"output"); row["output"]=dict(kind="empty",bytes=0,sha256=None)
        row["error"]=None
    except (OSError,C.Rejected,ValueError,subprocess.SubprocessError):
        row["error"]=failure
    finally:
        cleanup_deadline=min(batch_deadline+30,clock()+30)
        if witness is not None:
            try: witness.close(); row["cancellation"]["reader_closed"]=True
            except OSError: row["cancellation"]["reader_closed"]=False
        all_closed=True
        for child in children: all_closed=child.close(cleanup_deadline) and all_closed
        row["children"]=[dict(child.observed) for child in children]
        row["checks"]["children_reaped"]=all_closed and all(c["reaped"] is True for c in row["children"])
        row["checks"]["groups_empty"]=all_closed and all(c["group_empty"] is True for c in row["children"])
        try:
            row["checks"]["fixture_closed"]=server.close(cleanup_deadline) if server else True
            if server:
                events,failed=server.snapshot()
                # Preserve only a structurally valid observed prefix; unknown events never echo.
                trial=dict(row,events=events,status="failed",error=row["error"] or "fixture"); C.validate_case(trial); row["events"]=events
                # Exact sequence is stable only after the owned fixture close/join.
                if (failed or events != C.expected_events(case)) and row["error"] is None: row["error"]="fixture"
        except (OSError,C.Rejected): row["checks"]["fixture_closed"]=False
        if all_closed and owned is not None:
            try: row["helpers"]=helper_records(root,case)
            except (OSError,C.Rejected): pass
        try:
            row["checks"]["runtime_preserved"] = digest(BINARY)==bindings["runtime_sha256"]
            row["checks"]["helper_preserved"] = digest(HELPER)==bindings["helper_sha256"]
            row["checks"]["source_preserved"] = source_check()
            row["checks"]["config_preserved"] = config_hash is not None and digest(root/"synthetic.conf")==config_hash
            row["checks"]["control_preserved"] = control_hash is not None and digest(root/"control.json")==control_hash and bounded_read(root/"helper.lock",0)==b""
            safe=all_closed and row["checks"]["fixture_closed"] is True
            row["checks"]["temporary_removed"] = remove_owned(root,owned) if safe and owned is not None else False
        except (OSError,C.Rejected): row["checks"]["temporary_removed"]=False
    row["elapsed_ms"]=max(0,int((clock()-started)*1000))
    if row["error"] is None and all(v is True for v in row["checks"].values()) and not any(c["forced"] for c in row["children"]):
        row["status"]="passed"
        try: C.validate_case(row)
        except C.Rejected: row["status"]="failed"; row["error"]="preservation"
    elif row["error"] is None: row["error"]="cleanup"
    return C.validate_case(row)


def run_suite(python, bindings, source_sha256):
    """Called only by the future separately reviewed verified-image entrypoint."""
    C.validate_bindings(bindings)
    C.require(sys.platform=="linux" and os.getuid()==os.getgid()==10001,"setup")
    C.require({line.split(":",1)[0].strip() for line in Path("/proc/net/dev").read_text().splitlines() if ":" in line}=={"lo"},"setup")
    C.require(str(HELPER.parent)==str(Path(__file__).resolve().parent),"binding")
    info=WORK.lstat(); C.require(stat.S_ISDIR(info.st_mode) and not WORK.is_symlink() and info.st_uid==10001 and stat.S_IMODE(info.st_mode)==0o700 and not any(WORK.iterdir()),"setup")
    def source_check():
        rows=[[name,digest(HELPER.parent/name)] for name in SOURCE_FILES]
        return hashlib.sha256(C.compact(rows)).hexdigest()==source_sha256==bindings["source_sha256"]
    C.require(source_check() and digest(BINARY)==bindings["runtime_sha256"]==C.RUNTIME_SHA and digest(HELPER)==bindings["helper_sha256"] and digest(python)==bindings["python_sha256"] and digest(Path("/opt/fixture/rclone-version.env"))==bindings["runtime_manifest_sha256"],"binding")
    old_umask=os.umask(0o077)
    try:
        deadline=time.monotonic()+720; rows=[]
        for case in C.CASES:
            row=case_run(case,python,bindings,source_check,deadline); rows.append(row)
            if row["status"]!="passed": break
        result=dict(schema_version=1,scope="linux_network_none_protocol",mode="webdav_command_rc_v1",runtime=dict(version="1.75.2",platform="linux_amd64",sha256=C.RUNTIME_SHA),bindings=bindings,cases=rows,result="passed" if len(rows)==5 and rows[-1]["status"]=="passed" else "failed",claims=dict(C.CLAIMS))
        return C.validate(result,bindings)
    finally:
        os.umask(old_umask)
