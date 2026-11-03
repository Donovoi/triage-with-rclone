# New opt-in stdlib-only protocol image; no dependency installer or runtime network.
FROM docker.io/library/python@sha256:9901e0a8d75037d8242ed43155cbcb2d1f61be1356383d8054afb59fd50e39c4
LABEL org.openai.triage.fixture-kind="webdav-command-protocol"
ENV LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONNOUSERSITE=1 HOME=/work TMPDIR=/work
COPY webdav-command/ /opt/fixture/webdav-command/
COPY rclone rclone-version.env source-manifest.json source-revision /opt/fixture/
RUN <<'BUILD'
set -eu
printf '%s\n' 'WEBDAV_COMMAND_BUILD_PHASE=verify'
/usr/local/bin/python3.12 -I -S -B - <<'PY'
import hashlib,json,os,pathlib,platform,re,stat,sys
root=pathlib.Path('/opt/fixture');profile=root/'webdav-command'
names={'command_contract.py','token_helper.py','fixture.py','probe.py','entrypoint.py','run_container.py','Dockerfile','build-lock.json'}
assert set(p.name for p in root.iterdir())=={'webdav-command','rclone','rclone-version.env','source-manifest.json','source-revision'}
assert set(p.name for p in profile.iterdir())==names
for path in root.rglob('*'):
    assert not path.is_symlink()
    if path.is_file():assert path.stat().st_nlink==1
lockraw=(profile/'build-lock.json').read_bytes()
assert hashlib.sha256(lockraw).hexdigest()=='fa87c3fc9ee17fd2ab3161d01b1bb7f987dfe110f2a9e3a3a4c32476b4af8bb9'
lock=json.loads(lockraw)
assert platform.python_version()==lock['python_version'] and platform.machine()=='x86_64' and sys.executable==lock['python_path']
sources=json.loads((root/'source-manifest.json').read_bytes())
assert set(sources)==names|{'rclone-version.env'}
for name,value in sources.items():
    assert type(value) is str and re.fullmatch('[a-f0-9]{64}',value)
    path=root/name if name=='rclone-version.env' else profile/name
    assert hashlib.sha256(path.read_bytes()).hexdigest()==value
revision=(root/'source-revision').read_bytes().decode('ascii')
assert re.fullmatch('[a-f0-9]{40}',revision)
pins={}
for line in (root/'rclone-version.env').read_text('ascii').splitlines():
    if not line or line.startswith('#'):continue
    key,sep,value=line.partition('=');assert sep and key not in pins;pins[key]=value
assert pins['RCLONE_VERSION']==lock['runtime_version'] and pins['RCLONE_LINUX_EXE_SHA256']==lock['runtime_sha256']
runtime=hashlib.sha256((root/'rclone').read_bytes()).hexdigest()
assert runtime==lock['runtime_sha256']
manifest=dict(schema_version=1,revision=revision,source_sha256=sources,runtime_sha256=runtime,runtime_manifest_sha256=sources['rclone-version.env'],python_version=platform.python_version(),python_sha256=hashlib.sha256(pathlib.Path(sys.executable).read_bytes()).hexdigest())
with (root/'build-manifest.json').open('x',encoding='ascii') as f:json.dump(manifest,f,sort_keys=True,separators=(',',':'))
assert all(line.split(':')[2]!='10001' for line in pathlib.Path('/etc/passwd').read_text().splitlines())
assert all(line.split(':')[2]!='10001' for line in pathlib.Path('/etc/group').read_text().splitlines())
with open('/etc/passwd','a') as f:f.write('synthetic-command:x:10001:10001:Synthetic fixture:/work:/usr/sbin/nologin\n')
with open('/etc/group','a') as f:f.write('synthetic-command:x:10001:\n')
for path in (pathlib.Path('/opt'),root,*root.rglob('*')):
    path.chmod(0o755 if path.is_dir() else 0o555 if path.name=='rclone' else 0o444)
work=pathlib.Path('/work');work.mkdir(exist_ok=True);work.chmod(0o700);os.chown(work,10001,10001)
PY
printf '%s\n' 'WEBDAV_COMMAND_BUILD_PHASE=manifest'
BUILD
USER 10001:10001
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/python3.12"]
CMD ["-I", "-S", "-B", "/opt/fixture/webdav-command/entrypoint.py"]
