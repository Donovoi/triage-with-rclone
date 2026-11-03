"""Fixed verified-image entrypoint. Import performs no filesystem or native work."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import types

ROOT=Path("/opt/fixture")
PROFILE=ROOT/"webdav-command"
NAMES=("command_contract.py","token_helper.py","fixture.py","probe.py","entrypoint.py","run_container.py","Dockerfile","build-lock.json")
PYTHON="/usr/local/bin/python3.12"
RUNTIME="ed7ab1f17876bb006c3df3949a3044959671afd9112362dacaa5dd1647735bc1"


class Invalid(ValueError): pass


def require(ok):
    if not ok: raise Invalid()


def compact(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")


def parse(raw,limit=16384):
    require(type(raw) is bytes and len(raw)<=limit)
    def pairs(values):
        out={}
        for k,v in values:
            require(k not in out);out[k]=v
        return out
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(Invalid()))


def plain_file(path,limit):
    info=path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==0 and not path.is_symlink() and info.st_size<=limit)
    require(all(not p.is_symlink() and stat.S_ISDIR(p.lstat().st_mode) for p in path.parents))
    return info


def file_hash(path,limit):
    before=plain_file(path,limit)
    with path.open("rb") as stream:
        held=os.fstat(stream.fileno());value=hashlib.file_digest(stream,"sha256").hexdigest()
    after=plain_file(path,limit)
    require((before.st_dev,before.st_ino,before.st_size)==(held.st_dev,held.st_ino,held.st_size)==(after.st_dev,after.st_ino,after.st_size))
    return value


def validate_build(value):
    require(type(value) is dict and set(value)=={"schema_version","revision","source_sha256","runtime_sha256","runtime_manifest_sha256","python_version","python_sha256"})
    require(type(value["schema_version"]) is int and value["schema_version"]==1)
    require(type(value["revision"]) is str and re.fullmatch("[a-f0-9]{40}",value["revision"]))
    require(value["runtime_sha256"]==RUNTIME and value["python_version"]=="3.12.15")
    require(type(value["source_sha256"]) is dict and set(value["source_sha256"])==set(NAMES)|{"rclone-version.env"})
    for digest in [*value["source_sha256"].values(),value["runtime_manifest_sha256"],value["python_sha256"]]:
        require(type(digest) is str and re.fullmatch("[a-f0-9]{64}",digest))
    require(value["runtime_manifest_sha256"]==value["source_sha256"]["rclone-version.env"])
    return value


def verify_image():
    require(sys.platform=="linux" and os.getuid()==os.getgid()==10001 and len(sys.argv)==1)
    require(sys.executable==PYTHON and platform.python_version()=="3.12.15")
    plain_file(ROOT/"build-manifest.json",16384)
    build=validate_build(parse((ROOT/"build-manifest.json").read_bytes()))
    require(set(p.name for p in ROOT.iterdir())=={"webdav-command","rclone","rclone-version.env","source-manifest.json","source-revision","build-manifest.json"})
    require(set(p.name for p in PROFILE.iterdir())==set(NAMES))
    for name,expected in build["source_sha256"].items():
        require(file_hash(ROOT/name if name=="rclone-version.env" else PROFILE/name,1048576)==expected)
    require(file_hash(ROOT/"rclone",268435456)==build["runtime_sha256"])
    require(file_hash(Path(PYTHON),268435456)==build["python_sha256"])
    plain_file(ROOT/"source-manifest.json",16384);plain_file(ROOT/"source-revision",40)
    require(parse((ROOT/"source-manifest.json").read_bytes())==build["source_sha256"])
    require((ROOT/"source-revision").read_bytes()==build["revision"].encode("ascii"))
    return build


def load_modules(build):
    names=("command_contract","token_helper","fixture","probe")
    missing=object();displaced={name:sys.modules.get(name,missing) for name in names};loaded={}
    try:
        for name in names:
            path=PROFILE/(name+".py");raw=path.read_bytes()
            require(hashlib.sha256(raw).hexdigest()==build["source_sha256"][name+".py"])
            module=types.ModuleType(name);module.__file__=str(path);sys.modules[name]=module
            exec(compile(raw,str(path),"exec"),module.__dict__);loaded[name]=module
        return loaded
    finally:
        for name,value in displaced.items():
            if value is missing:sys.modules.pop(name,None)
            else:sys.modules[name]=value


def main():
    result=dict(schema_version=1,stage="preflight",error="entrypoint_failed",build=None,protocol=None)
    try:
        build=verify_image();result["build"]=build;result["stage"]="binding"
        modules=load_modules(build);C=modules["command_contract"];P=modules["probe"]
        source_digest=hashlib.sha256(C.compact([[name,build["source_sha256"][name]] for name in P.SOURCE_FILES])).hexdigest()
        bindings=dict(source_revision=build["revision"],source_sha256=source_digest,runtime_manifest_sha256=build["runtime_manifest_sha256"],runtime_sha256=build["runtime_sha256"],helper_sha256=build["source_sha256"]["token_helper.py"],python_sha256=build["python_sha256"])
        result["stage"]="protocol";result["protocol"]=P.run_suite(PYTHON,bindings,source_digest)
        result["stage"]="complete";result["error"]=None
    except (Exception,KeyboardInterrupt):
        pass
    raw=compact(result)+b"\n"
    if len(raw)>65536:
        result=dict(schema_version=1,stage=result["stage"],error="output_bound",build=None,protocol=None)
        raw=compact(result)+b"\n"
    sys.stdout.buffer.write(raw);sys.stdout.buffer.flush()
    return 0 if result["error"] is None and result["protocol"]["result"]=="passed" and len(raw)<=65536 else 1


if __name__=="__main__":raise SystemExit(main())
