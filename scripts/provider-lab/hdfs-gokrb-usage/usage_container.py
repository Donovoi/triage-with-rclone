"""Hosted-only constructor regression; no real service or provider acceptance."""
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
import subprocess
import sys
import tempfile
import time
import types
import uuid

HERE=Path(__file__).resolve().parent
SUPPORT=HERE.parent/'hdfs-kerberos-policy-denial/policy_denial_container.py'
SUPPORT_SHA='99304f8183f6068140e9e6f364bb96e1cc5c7c28408f1437b6a85b85fdfec2bd'
BUNDLE_SHA='9ec9ce6d2032c8aaa22f8ad87511f7a2e70b8327ee795d5e09e1e5eed1570d2b'
LABEL='org.openai.triage.gokrb-usage'
TMPFS='rw,nosuid,nodev,noexec,size=32m,mode=0700,uid=10001,gid=10001'
SOURCES=('main.go','patches/APReq.go','patches/KDCReq.go','LICENSE-gokrb5')
VARIANTS=('original','context-fix','global-control')
CASES=('tgt_tgs_aes128','service_renew_aes128','service_renew_aes256','hdfs_ap_aes128','http_ap_aes128')
EXPECTED=((7,11,11,11,11),(7,7,7,11,11),(7,7,7,7,7))
FALSE_CLAIMS=('renewal_verified','rclone_verified','provider_accepted','application_accepted','vendor_accepted','vulnerability_audited')
CODES=frozenset(('input_invalid','input_changed','unsafe_path','hosted_linux_required','python_version',
 'package_worker_failed','package_cleanup_failed','platform_invalid','image_invalid','container_invalid',
 'report_invalid','probe_failed','container_cleanup_failed','image_cleanup_failed','raw_cleanup_failed',
 'command_cleanup_failed','build_failed','interrupted','report_failed'))

class ProbeError(Exception):
    def __init__(self,code):
        self.code=code if code in CODES else 'probe_failed';super().__init__(self.code)

def need(value,code):
    if not value:raise ProbeError(code)

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
def sha(raw):return hashlib.sha256(raw).hexdigest()

def load_support():
    # Reject links and changed bytes before compiling the already reviewed helper.
    for path in (SUPPORT,*SUPPORT.parents):
        info=path.lstat()
        need(not path.is_symlink() and not getattr(info,'st_file_attributes',0)&0x400,'unsafe_path')
    before=SUPPORT.stat();need(before.st_nlink==1 and before.st_size<=131072,'input_invalid')
    with SUPPORT.open('rb') as stream:
        opened=os.fstat(stream.fileno());raw=stream.read(131073);after=os.fstat(stream.fileno())
    stamp=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)
    need(stamp(before)==stamp(opened)==stamp(after)==stamp(SUPPORT.stat()) and sha(raw)==SUPPORT_SHA,'input_changed')
    module=types.ModuleType('reviewed_gokrb_container_support');module.__file__=str(SUPPORT)
    exec(compile(raw,str(SUPPORT),'exec'),module.__dict__)
    return module

def load_bundle(C):
    path=HERE/'go_bundle.py';raw=C.read(path,131072)
    need(sha(raw)==BUNDLE_SHA,'input_changed')
    module=types.ModuleType('reviewed_gokrb_bundle');module.__file__=str(path)
    exec(compile(raw,str(path),'exec'),module.__dict__)
    return module


def tree_hashes(C,root):
    hashes={};total=0
    for count,p in enumerate(root.rglob('*'),1):
        need(count<=10000 and not p.is_symlink(),'unsafe_path')
        if p.is_dir():C.directory(p)
        else:
            s=C.regular(p,128*1024*1024);total+=s.st_size
            need(total<=256*1024*1024,'input_invalid')
            hashes[p.relative_to(root).as_posix()]=C.file_hash(p)
    return hashes

def package_worker(C,B,context,identity,source_hash):
    C.hosted_guard();need(sys.version_info[:2]==(3,14),'python_version')
    need(context.is_absolute() and context.name=='context'
         and re.fullmatch('gokrb-usage-[a-f0-9]{32}-[a-z0-9_]+',context.parent.name),'unsafe_path')
    C.directory(context,identity);need(C.file_hash(Path(__file__),524288)==source_hash,'input_changed')
    lock=B.load_lock(C.read(HERE/'assets-lock.json',131072))
    B.download(context,lock);B.prepare(context,lock,C.read)

def prepare_packages(C,B,context):
    process=None;identity=C.directory(context);source=Path(__file__).resolve();source_hash=C.file_hash(source,524288)
    env={key:os.environ[key] for key in ('PATH','LANG','LC_ALL','GITHUB_ACTIONS','RUNNER_ENVIRONMENT','RUNNER_OS') if key in os.environ}
    try:
        process=subprocess.Popen([sys.executable,'-I','-S','-B',str(source),'--package-worker',str(context),str(identity[0]),str(identity[1]),source_hash],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,cwd=context,env=env,start_new_session=True)
        try:code=process.wait(timeout=300)
        except subprocess.TimeoutExpired:raise ProbeError('package_worker_failed') from None
        need(code==0,'package_worker_failed')
    finally:
        if process is not None:
            try:
                if process.poll() is None:
                    need(os.getpgid(process.pid)==process.pid,'package_cleanup_failed');os.killpg(process.pid,signal.SIGKILL)
                process.wait(timeout=3)
            except (OSError,subprocess.TimeoutExpired):raise ProbeError('package_cleanup_failed') from None
    C.directory(context,identity);need(C.file_hash(source,524288)==source_hash,'input_changed')
    # Recompute all original, cache and asset content in the parent without execution.
    lock=B.load_lock(C.read(HERE/'assets-lock.json',131072))
    for row in lock['assets']:
        raw=C.read(context/'assets'/row['file'],row['bytes']);B.verify_asset(raw,row)
        if row['kind']=='toolchain':continue
        cached=context/'module-cache/cache/download'/row['module']/'@v'/(row['version']+'.'+row['kind'])
        need(C.read(cached,row['bytes'])==raw,'input_changed')
        if row['kind']=='zip':
            need(C.read(cached.with_suffix('.ziphash'),128)==row['h1'].encode(),'input_changed')
            files=B.module_files(raw,row)
            if row['module']==B.MODULE:
                need(tree_hashes(C,context/'original')=={p:sha(b) for p,b in files.items()},'input_changed')
    return lock

def build_files(C,sources):
    need(set(sources)==set(SOURCES),'input_invalid')
    anchor=b'func newAPReq(tkt Ticket, sessionKey types.EncryptionKey, auth types.Authenticator, usage int) (APReq, error) {\n'
    need(sources['patches/APReq.go'].count(anchor)==1,'input_invalid')
    global_ap=sources['patches/APReq.go'].replace(anchor,anchor+b'\tusage = keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR // Deliberately overbroad negative control.\n')
    driver=('#!/bin/sh\nset -eu\numask 077\nmkdir /work/home\n'
        'for variant in original context-fix global-control; do\n'
        ' /usr/bin/timeout --signal=TERM --kill-after=2s 10s /opt/probes/"$variant"\n'
        'done\n').encode()
    build=('#!/bin/sh\nset -eu\numask 077\n'
        'tar -xzf /opt/input/assets/go-toolchain.tar.gz -C /opt\n'
        'mkdir /opt/probes /opt/cache /opt/tmp /opt/home\n'
        'mkdir -p /opt/input/original/cmd/usage-regression\n'
        'cp /opt/input/main.go /opt/input/original/cmd/usage-regression/main.go\n'
        'cd /opt/input/original\n'
        'for variant in original context-fix global-control; do\n'
        ' if [ "$variant" != original ]; then\n'
        '  cp /opt/input/patches/APReq.go messages/APReq.go\n'
        '  cp /opt/input/patches/KDCReq.go messages/KDCReq.go\n'
        ' fi\n'
        ' if [ "$variant" = global-control ]; then cp /opt/input/global-APReq.go messages/APReq.go; fi\n'
        ' env -i HOME=/opt/home PATH=/opt/go/bin:/usr/bin:/bin GOROOT=/opt/go '
        'GOMODCACHE=/opt/input/module-cache GOCACHE=/opt/cache GOTMPDIR=/opt/tmp '
        'GOENV=off GOTOOLCHAIN=local GOWORK=off GOTELEMETRY=off GOPROXY=off GOSUMDB=off '
        'CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOMAXPROCS=2 GOMEMLIMIT=512MiB '
        '/opt/go/bin/go build -mod=readonly -trimpath -buildvcs=false -p 2 '
        '-ldflags "-X main.variant=$variant" -o /opt/probes/"$variant" ./cmd/usage-regression\n'
        'done\n'
        'chmod -R a=rX /opt/probes\nchmod 0555 /opt/probes/* /opt/input /opt/input/driver.sh\n').encode()
    dockerfile=('FROM '+C.BASE+'\nUSER 0\nCOPY . /opt/input/\n'
        'RUN cd /opt/input && sha256sum -c checksums && /bin/sh /opt/input/build.sh\n'
        'USER 10001:10001\nWORKDIR /work\n').encode()
    return {'Dockerfile':dockerfile,'build.sh':build,'driver.sh':driver,'global-APReq.go':global_ap}

def command_args(name,image,run_id):
    need(type(run_id) is str and re.fullmatch('[a-f0-9]{32}',run_id) and name=='gokrb-usage-'+run_id
        and type(image) is str and re.fullmatch('sha256:[a-f0-9]{64}',image),'container_invalid')
    return ['create','--name',name,'--label',LABEL+'='+run_id,'--network','none','--read-only',
        '--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','128',
        '--memory','2g','--cpus','2','--init','--cgroupns','private','--ipc','private','--log-driver','none',
        '--stop-timeout','5','--tmpfs','/work:'+TMPFS,'--entrypoint','/usr/bin/env',image,
        '-i','HOME=/work/home','PATH=/usr/bin:/bin','GOMAXPROCS=2','LANG=C','LC_ALL=C',
        '/bin/sh','/opt/input/driver.sh']

def build_diagnostics(raw):
    need(type(raw) is bytes and len(raw)<=8388608,'input_invalid')
    errors=[]
    for m in re.finditer(r'(cmd/usage-regression/main[.]go|messages/(?:APReq|KDCReq)[.]go):([0-9]{1,5}):[^\r\n]*',raw.decode('utf8','replace')):
        row={'file':m[1],'line':int(m[2])}
        need(1<=row['line']<=10000 and len(errors)<32,'input_invalid')
        if row not in errors:errors.append(row)
    return {'source_errors':errors,'module_resolution_failed':b'module lookup disabled by GOPROXY=off' in raw,
            'module_update_required':b'updates to go.mod needed' in raw}

def validate_native(C,raw,exit_code,lock):
    need(type(raw) is bytes and len(raw)<=32768 and type(exit_code) is int,'report_invalid')
    lines=raw.splitlines();need(len(lines)==3,'report_invalid')
    rows=[C.parse(line,16384) for line in lines]
    pins={(r['module'],r['version']):r['h1'] for r in lock['assets'] if r['kind']=='zip'}
    common=None
    for index,v in enumerate(rows):
        need(type(v) is dict and set(v)=={'schema_version','variant','success','error','go_version','dependencies','cases',
             'rclone_verified','renewal_verified','provider_accepted'},'report_invalid')
        need(type(v['schema_version']) is int and v['schema_version']==1 and v['variant']==VARIANTS[index]
             and v['success'] is True and v['error']=='none' and v['go_version']=='go1.26.10'
             and all(v[k] is False for k in ('rclone_verified','renewal_verified','provider_accepted')),'report_invalid')
        deps=v['dependencies'];need(type(deps) is list and 0<len(deps)<=16,'report_invalid')
        seen=set()
        for d in deps:
            need(type(d) is dict and set(d)=={'path','version','sum'}
                 and type(d['path']) is str and d['path'] not in seen
                 and pins.get((d['path'],d['version']))==d['sum'],'report_invalid');seen.add(d['path'])
        need(common is None or deps==common,'report_invalid');common=deps
        cases=v['cases'];need(type(cases) is list and len(cases)==5,'report_invalid')
        for i,c in enumerate(cases):
            need(type(c) is dict and set(c)=={'case','usage','checks','negative_controls','required_usage'},'report_invalid')
            need(c['case']==CASES[i] and type(c['usage']) is int and c['usage']==EXPECTED[index][i]
                 and type(c['checks']) is int and c['checks']==(15 if i<3 else 8)
                 and type(c['negative_controls']) is int and c['negative_controls']==(4 if i<3 else 3)
                 and c['required_usage'] is (c['usage']==(7 if i<3 else 11)),'report_invalid')
    need(exit_code==0,'probe_failed')
    return {'success':True,'variants':rows,'cases':15,'binding_checks':183,'negative_controls':54,
            'context_fix_only_passes_all_cases':True}
def inspect_container(value,name,image,run_id):
    need(type(value) is dict and value.get('Name')=='/'+name and value.get('Image')==image
        and re.fullmatch('[a-f0-9]{64}',value.get('Id','')),'container_invalid')
    config,host=value.get('Config',{}),value.get('HostConfig',{});args=command_args(name,image,run_id)
    need(config.get('Labels',{}).get(LABEL)==run_id and config.get('User')=='10001:10001'
        and config.get('Entrypoint')==['/usr/bin/env'] and config.get('Cmd')==args[args.index(image)+1:]
        and not config.get('Volumes') and not config.get('ExposedPorts') and not config.get('Healthcheck'),'container_invalid')
    need(host.get('NetworkMode')=='none' and host.get('ReadonlyRootfs') is True and host.get('Privileged') is False
        and host.get('CapDrop')==['ALL'] and not host.get('CapAdd') and not host.get('Binds') and not host.get('PortBindings')
        and host.get('SecurityOpt') in (['no-new-privileges'],['no-new-privileges=true'])
        and type(host.get('Memory')) is int and host['Memory']==2*1024**3
        and type(host.get('NanoCpus')) is int and host['NanoCpus']==2*10**9
        and type(host.get('PidsLimit')) is int and host['PidsLimit']==128 and host.get('Init') is True
        and host.get('IpcMode')=='private' and host.get('CgroupnsMode')=='private'
        and host.get('Tmpfs')=={'/work':TMPFS} and host.get('LogConfig',{}).get('Type')=='none'
        and not host.get('Devices') and not host.get('DeviceRequests') and not host.get('ExtraHosts') and not host.get('PidMode'),'container_invalid')
    mounts=value.get('Mounts')
    need(type(mounts) is list and len(mounts)<=1 and all(type(m) is dict and m.get('Type')=='tmpfs' and m.get('Destination')=='/work' for m in mounts),'container_invalid')


def run():
    began=time.monotonic();report=dict(schema_version=1,scope='gokrb5_constructor_regression',success=False,
        started_utc=datetime.now(timezone.utc).isoformat(),finished_utc=None,duration_seconds=None,
        stage='preflight',inputs=None,result=None,build_diagnostics=None,errors=[],
        cleanup=dict(container_removed=False,image_removed=False,context_removed=False,raw_evidence_removed=False),
        cleanup_excludes=['shared_base_image','shared_build_cache'],**dict.fromkeys(FALSE_CLAIMS,False))
    C=B=D=docker=root=context=root_id=context_id=image=container=None
    source_hashes={};built_attempted=created_attempted=False
    run_id=uuid.uuid4().hex;name=tag='gokrb-usage-'+run_id;old_umask=os.umask(0o077)
    try:
        C=load_support();C.hosted_guard();need(sys.version_info[:2]==(3,14),'python_version');B=load_bundle(C)
        D,source_hashes=C.load_helpers();lock_raw=C.read(HERE/'assets-lock.json',131072);lock=B.load_lock(lock_raw)
        sources={name:C.read(HERE/name,131072) for name in SOURCES}
        source_hashes.update({SUPPORT:SUPPORT_SHA,Path(__file__):C.file_hash(Path(__file__),524288),
            HERE/'go_bundle.py':BUNDLE_SHA,HERE/'assets-lock.json':sha(lock_raw)})
        source_hashes.update({HERE/name:sha(raw) for name,raw in sources.items()})
        report['inputs']=dict(source_sha256={p.relative_to(HERE.parent).as_posix():h for p,h in source_hashes.items()},
            base_manifest=C.BASE,base_config_id=C.BASE_ID,assets=87,asset_bytes=sum(r['bytes'] for r in lock['assets']),
            toolchain='go1.26.10',module='github.com/jcmturner/gokrb5/v8',module_version='v8.4.4',
            context_sha256=None,image_id=None,container_id=None)
        need(shutil.disk_usage('/tmp').free>=1024*1024**2,'unsafe_path')
        root=Path(tempfile.mkdtemp(prefix=name+'-',dir='/tmp'));root_id=C.directory(root)
        context=root/'context';context.mkdir(mode=0o700);context_id=C.directory(context)
        report['stage']='download_assets';prepare_packages(C,B,context)
        for filename,raw in {**sources,**build_files(C,sources)}.items():
            target=context/filename;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
        before=tree_hashes(C,context)
        (context/'checksums').write_text(''.join(h+'  '+p+'\n' for p,h in sorted(before.items())),encoding='ascii')
        context_hashes=tree_hashes(C,context);report['inputs']['context_sha256']=sha(canonical(context_hashes))
        docker=D.Docker(root,max_calls=40);host=C.parse(C.read(docker.call(['info','--format','{{json .}}']).stdout,1048576))
        need(host.get('OSType')=='linux' and host.get('Architecture') in ('amd64','x86_64'),'platform_invalid')
        report['stage']='base';docker.call(['image','pull','--quiet','--platform','linux/amd64',C.BASE],timeout=120)
        base=docker.inspect('image',C.BASE);report['base_observation']=C.base_observation(base,C.BASE,C.BASE_ID);C.validate_base(base,C.BASE,C.BASE_ID)
        need(docker.inspect('image',tag,allow_missing=True) is None,'image_invalid')
        report['stage']='build';built_attempted=True
        compiled=docker.call(['build','--network','none','--pull=false','--label',LABEL+'='+run_id,'--tag',tag,str(context)],timeout=300,limit=4194304,allow_failure=True)
        report['build_diagnostics']=build_diagnostics(C.read(compiled.stdout,4194304)+C.read(compiled.stderr,4194304))
        need(compiled.code==0,'build_failed')
        built=docker.inspect('image',tag);image=built.get('Id')
        need(type(image) is str and re.fullmatch('sha256:[a-f0-9]{64}',image)
             and built.get('Config',{}).get('Labels',{}).get(LABEL)==run_id
             and built.get('Config',{}).get('User')=='10001:10001','image_invalid')
        need(tree_hashes(C,context)==context_hashes,'input_changed');report['inputs']['image_id']=image
        need(docker.inspect('container',name,allow_missing=True) is None,'container_invalid')
        report['stage']='create';created_attempted=True;docker.call(command_args(name,image,run_id))
        initial=docker.inspect('container',name);inspect_container(initial,name,image,run_id)
        need(initial.get('State',{}).get('Status')=='created' and initial['State'].get('Running') is False,'container_invalid')
        container=initial['Id'];report['inputs']['container_id']=container;report['stage']='constructors'
        result=docker.call(['start','--attach',container],timeout=45,limit=32768,allow_failure=True)
        ended=docker.inspect('container',container);inspect_container(ended,name,image,run_id);state=ended.get('State',{})
        need(ended['Id']==container and state.get('Running') is False and state.get('Status')=='exited'
             and state.get('OOMKilled') is False and type(state.get('ExitCode')) is int
             and state['ExitCode']==result.code,'container_invalid')
        need(C.read(result.stderr,8388608)==b'','probe_failed')
        report['result']=validate_native(C,C.read(result.stdout,32768),result.code,lock)
        report['success']=True;report['stage']='completed'
    except KeyboardInterrupt:report['errors'].append('interrupted')
    except BaseException as error:report['errors'].append(getattr(error,'code',None) if getattr(error,'code',None) in CODES else 'probe_failed')
    finally:
        for kind,attempted,reference,exact in (('container',created_attempted,container or name,container),('image',built_attempted,image or tag,image)):
            try:
                if attempted:
                    current=docker.inspect(kind,reference,allow_missing=True)
                    if current is not None:
                        need(current.get('Config',{}).get('Labels',{}).get(LABEL)==run_id and (exact is None or current.get('Id')==exact),kind+'_cleanup_failed')
                        owned=current.get('Id')
                        if kind=='container':need(re.fullmatch('[a-f0-9]{64}',owned or '') and current.get('Name')=='/'+name and current.get('Image')==image,'container_cleanup_failed')
                        else:need(re.fullmatch('sha256:[a-f0-9]{64}',owned or '') and current.get('RepoTags')==[tag+':latest'],'image_cleanup_failed')
                        docker.call([kind,'rm',*(['--force'] if kind=='container' else []),owned]);need(docker.inspect(kind,owned,allow_missing=True) is None,kind+'_cleanup_failed')
                report['cleanup'][kind+'_removed']=True
            except BaseException as error:
                if getattr(error,'code',None)=='command_cleanup_failed':report['errors'].append('command_cleanup_failed')
                report['errors'].append(kind+'_cleanup_failed')
        try:
            for path,expected in source_hashes.items():need(C.file_hash(path,524288)==expected,'input_changed')
        except BaseException:report['errors'].append('input_changed')
        safe=all(report['cleanup'][key] for key in ('container_removed','image_removed'))
        safe=safe and not {'command_cleanup_failed','download_cleanup_failed','package_cleanup_failed'}.intersection(report['errors'])
        try:
            if context is not None:
                need(safe,'raw_cleanup_failed');C.directory(root,root_id);C.directory(context,context_id);tree_hashes(C,context)
                shutil.rmtree(context);need(not context.exists(),'raw_cleanup_failed')
            report['cleanup']['context_removed']=True
            if root is not None:
                need(safe,'raw_cleanup_failed');C.directory(root,root_id)
                for path in root.rglob('*'):
                    need(not path.is_symlink(),'unsafe_path')
                    if path.is_file():C.regular(path,8388608)
                shutil.rmtree(root);need(not root.exists(),'raw_cleanup_failed')
            report['cleanup']['raw_evidence_removed']=True
        except BaseException:report['errors'].append('raw_cleanup_failed')
        os.umask(old_umask)
    report['success']=report['success'] and not report['errors'] and all(report['cleanup'].values())
    report['finished_utc']=datetime.now(timezone.utc).isoformat();report['duration_seconds']=round(time.monotonic()-began,3)
    return report

def main(argv=None):
    args=sys.argv[1:] if argv is None else argv
    if args and args[0]=='--package-worker':
        try:
            need(len(args)==5,'input_invalid');C=load_support();B=load_bundle(C)
            package_worker(C,B,Path(args[1]),(int(args[2]),int(args[3])),args[4]);return 0
        except BaseException:return 1
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--report',type=Path,required=True);args=parser.parse_args(args)
    previous=signal.getsignal(signal.SIGTERM);signal.signal(signal.SIGTERM,lambda *_:(_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        C=load_support();C.hosted_guard();need(args.report.is_absolute(),'unsafe_path')
        for parent in args.report.parents:C.directory(parent)
        fd=os.open(args.report,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
        with os.fdopen(fd,'wb') as stream:
            result=run();data=canonical(result)+b'\n';need(len(data)<=65536,'report_failed');stream.write(data);stream.flush();os.fsync(stream.fileno())
        return 0 if result['success'] else 1
    except BaseException:sys.stderr.write('gokrb_constructor_failed\n');return 1
    finally:signal.signal(signal.SIGTERM,previous)

if __name__=='__main__':raise SystemExit(main())
