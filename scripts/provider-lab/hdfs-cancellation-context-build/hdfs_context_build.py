"""Hosted-only original/patched full rclone builds; no renewal acceptance."""
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
ASSETS_HOME=HERE.parent/'hdfs-rclone-usage-build'
SUPPORT=HERE.parent/'hdfs-kerberos-policy-denial/policy_denial_container.py'
SUPPORT_SHA='99304f8183f6068140e9e6f364bb96e1cc5c7c28408f1437b6a85b85fdfec2bd'
BUNDLE_SHA='5fe229670dfc48755df3f296359d9d09359c18b7861d1cc867de0f5567c1400d'
LABEL='org.openai.triage.hdfs-context-build'
TMPFS='rw,nosuid,nodev,noexec,size=32m,mode=0700,uid=10001,gid=10001'
SOURCE_NAMES=("inspect_context_build.go","COPYING-rclone","COPYING-hdfs","patch-pins.json","patches/hdfs/internal/rpc/namenode.go","patches/hdfs/stat.go","patches/hdfs/file_reader.go","patches/hdfs/readdir.go","patches/rclone/backend/hdfs/fs.go","patches/hdfs/internal/rpc/namenode_context.go","patches/hdfs/internal/rpc/namenode_context_test.go")
SOURCES={name:HERE/name for name in SOURCE_NAMES}
PATCH_PATHS=("hdfs/internal/rpc/namenode.go","hdfs/stat.go","hdfs/file_reader.go","hdfs/readdir.go","rclone/backend/hdfs/fs.go","hdfs/internal/rpc/namenode_context.go","hdfs/internal/rpc/namenode_context_test.go")
TEST_NAMES=("TestContextAdmissionCancellationPreservesOwner","TestContextPrecancelledRequestHasNoEffects","TestContextExpiredDeadlineHasNoEffects","TestContextHeldResponseFinishesBeforeRelease","TestContextBlockedWriteFinishes","TestContextDialReceivesCancellation","TestContextHandshakeReceivesCancellation","TestContextCompletedRequestCannotCloseNextOperation","TestContextStartedCallbackIsJoinedBeforeReturn","TestContextNonCancellationErrorIsPreserved","TestContextCancelledStreamRequiresFreshDial")
FALSE_CLAIMS=('cancellation_verified','renewal_verified','rclone_verified','provider_accepted','application_accepted','vendor_accepted','vulnerability_audited')
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

def checksum_manifest(hashes):
    # Upstream test data includes Unicode filenames. Preserve their UTF-8 bytes.
    return ''.join(h+'  '+p+'\n' for p,h in sorted(hashes.items())).encode('utf-8')

def failure_diagnostics(error):
    # Source locations are from bound fixture files; never retain exception text.
    category='unexpected'
    for kind,label in ((ProbeError,'probe_error'),(ValueError,'value_error'),(KeyError,'key_error'),
                       (AttributeError,'attribute_error'),(TypeError,'type_error'),(OSError,'io_error')):
        if isinstance(error,kind):category=label;break
    allowed={str(Path(__file__)):'hdfs_context_build.py',str(ASSETS_HOME/'rclone_build_bundle.py'):'rclone_build_bundle.py',
             str(SUPPORT):'policy_denial_container.py'}
    frames=[];trace=error.__traceback__;depth=0
    while trace is not None and depth<64:
        name=allowed.get(trace.tb_frame.f_code.co_filename)
        if name is not None and 1<=trace.tb_lineno<=10000:frames.append(dict(file=name,line=trace.tb_lineno))
        trace=trace.tb_next;depth+=1
    number=getattr(error,'errno',None)
    return dict(category=category,errno=number if type(number) is int and 1<=number<=255 else None,frames=frames[-8:])

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
    path=ASSETS_HOME/'rclone_build_bundle.py';raw=C.read(path,131072)
    need(sha(raw)==BUNDLE_SHA,'input_changed')
    module=types.ModuleType('reviewed_gokrb_bundle');module.__file__=str(path)
    exec(compile(raw,str(path),'exec'),module.__dict__)
    return module


def tree_hashes(C,root):
    hashes={};total=0
    for count,p in enumerate(root.rglob('*'),1):
        need(count<=20000 and not p.is_symlink(),'unsafe_path')
        if p.is_dir():C.directory(p)
        else:
            s=C.regular(p,128*1024*1024);total+=s.st_size
            need(total<=2*1024**3,'input_invalid')
            hashes[p.relative_to(root).as_posix()]=C.file_hash(p)
    return hashes

WORKER_PHASES=frozenset(('startup','download','prepare','verify_sources','complete'))
WORKER_ERRORS=frozenset(('none','http_error','network_io','timeout','asset_validation','archive_invalid','filesystem_error','unexpected','status_unavailable'))

def worker_error(B,error):
    import urllib.error
    if isinstance(error,urllib.error.HTTPError):
        return 'http_error',error.code if type(error.code) is int and 100<=error.code<=599 else 0
    if isinstance(error,urllib.error.URLError):
        return ('timeout' if isinstance(error.reason,TimeoutError) else 'network_io'),0
    if isinstance(error,TimeoutError):return 'timeout',0
    if isinstance(error,(B.zipfile.BadZipFile,B.tarfile.TarError,EOFError)):return 'archive_invalid',0
    if isinstance(error,ValueError):return 'asset_validation',0
    if isinstance(error,OSError):return 'filesystem_error',0
    return 'unexpected',0

def validate_worker_status(value):
    need(type(value) is dict and set(value)=={'schema_version','phase','asset_index','processed_assets','error','http_status'},'report_invalid')
    need(type(value['schema_version']) is int and value['schema_version']==1 and type(value['phase']) is str and value['phase'] in WORKER_PHASES
         and type(value['asset_index']) is int and -1<=value['asset_index']<1137
         and type(value['processed_assets']) is int and 0<=value['processed_assets']<=1137
         and type(value['error']) is str and value['error'] in WORKER_ERRORS and type(value['http_status']) is int
         and (value['http_status']==0 or 100<=value['http_status']<=599),'report_invalid')
    need((value['error']=='http_error')==(value['http_status']!=0),'report_invalid')
    if value['phase'] in ('download','prepare'):
        need(value['asset_index']>=0 and value['processed_assets'] in (value['asset_index'],value['asset_index']+1),'report_invalid')
    else:need(value['asset_index']==-1,'report_invalid')
    if value['phase']=='complete':
        need(value['asset_index']==-1 and value['processed_assets']==1137 and value['error']=='none','report_invalid')
    return value

def read_worker_status(C,context):
    return validate_worker_status(C.parse(C.read(context/'worker-status.json',2048),2048))

def package_worker(C,B,context,identity,source_hash):
    C.hosted_guard();need(sys.version_info[:2]==(3,14),'python_version')
    need(context.is_absolute() and context.name=='context'
         and re.fullmatch('rclone-usage-[a-f0-9]{32}-[a-z0-9_]+',context.parent.name),'unsafe_path')
    C.directory(context,identity);need(C.file_hash(Path(__file__),524288)==source_hash,'input_changed')
    state=dict(schema_version=1,phase='startup',asset_index=-1,processed_assets=0,error='none',http_status=0)
    def record(phase,index,processed):
        state.update(phase=phase,asset_index=index,processed_assets=processed)
        validate_worker_status(state);C.directory(context,identity)
        target=context/'worker-status.json';temporary=context/'worker-status.next'
        if target.exists() or target.is_symlink():C.regular(target,2048)
        raw=canonical(state)+b'\n';need(len(raw)<=2048,'report_invalid')
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,target);C.directory(context,identity)
    try:
        record('startup',-1,0)
        lock=B.load_lock(C.read(ASSETS_HOME/'assets-lock.json',1048576))
        B.download(context,lock,observer=record)
        B.prepare(context,lock,C.read,observer=record)
        record('complete',-1,1137)
    except BaseException as error:
        state['error'],state['http_status']=worker_error(B,error)
        try:record(state['phase'],state['asset_index'],state['processed_assets'])
        except BaseException:pass
        raise

def prepare_packages(C,B,context,progress=None):
    process=None;identity=C.directory(context);source=Path(__file__).resolve();source_hash=C.file_hash(source,524288)
    env={key:os.environ[key] for key in ('PATH','LANG','LC_ALL','GITHUB_ACTIONS','RUNNER_ENVIRONMENT','RUNNER_OS') if key in os.environ}
    try:
        process=subprocess.Popen([sys.executable,'-I','-S','-B',str(source),'--package-worker',str(context),str(identity[0]),str(identity[1]),source_hash],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,cwd=context,env=env,start_new_session=True)
        try:code=process.wait(timeout=600)
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
    if progress is not None:progress('verify_packages')
    lock=B.load_lock(C.read(ASSETS_HOME/'assets-lock.json',1048576))
    escape=lambda s:''.join('!'+c.lower() if 'A'<=c<='Z' else c for c in s)
    for row in lock['assets']:
        raw=C.read(context/'assets'/row['file'],row['bytes']);B.verify_asset(raw,row)
        if row['kind']=='toolchain':continue
        cached=context/'module-cache/cache/download'/escape(row['module'])/'@v'/(escape(row['version'])+'.'+row['kind'])
        need(C.read(cached,row['bytes'])==raw,'input_changed')
        if row['kind']=='zip':
            need(C.read(cached.with_suffix('.ziphash'),128)==row['h1'].encode(),'input_changed')
            if row['module'] in (B.MODULE,lock['patch_module']['module']):
                files,_=B.module_files(raw,row,retain=True)
                selected=context/('original' if row['module']==B.MODULE else 'patched-gokrb')
                need(tree_hashes(C,selected)=={p:sha(b) for p,b in files.items()},'input_changed')
    return lock


def load_patch_pins(C,sources):
    need(set(sources)==set(SOURCES),'input_invalid')
    value=C.parse(sources['patch-pins.json'],16384)
    need(type(value) is dict and set(value)=={'schema_version','files'}
         and type(value['schema_version']) is int and value['schema_version']==1
         and type(value['files']) is list and len(value['files'])==7,'input_invalid')
    pins={}
    for row in value['files']:
        need(type(row) is dict and set(row)=={'path','beforeBytes','beforeSha256','afterBytes','afterSha256'}
             and type(row['path']) is str and row['path'] in PATCH_PATHS and row['path'] not in pins
             and type(row['beforeBytes']) is int and 0<=row['beforeBytes']<=131072
             and type(row['afterBytes']) is int and 0<row['afterBytes']<=131072
             and type(row['afterSha256']) is str and re.fullmatch('[a-f0-9]{64}',row['afterSha256']),'input_invalid')
        added=row['path'] in ('hdfs/internal/rpc/namenode_context.go','hdfs/internal/rpc/namenode_context_test.go')
        need((row['beforeBytes']==0 and row['beforeSha256'] is None) if added else
             (row['beforeBytes']>0 and type(row['beforeSha256']) is str and re.fullmatch('[a-f0-9]{64}',row['beforeSha256'])),'input_invalid')
        raw=sources['patches/'+row['path']]
        need(len(raw)==row['afterBytes'] and sha(raw)==row['afterSha256'],'input_changed')
        pins[row['path']]=row
    need(set(pins)==set(PATCH_PATHS),'input_invalid')
    return pins

def stage_hdfs(C,B,context,lock,sources):
    pins=load_patch_pins(C,sources)
    selected=[r for r in lock['assets'] if r['kind']=='zip' and r['module']=='github.com/colinmarc/hdfs/v2' and r['version']=='v2.4.0']
    need(len(selected)==1 and selected[0]['sha256']=='b996584b71a7e8f337bb528cce3a28740687251d0dde7624b5487c447a7439f9','input_invalid')
    row=selected[0];files,stats=B.module_files(C.read(context/'assets'/row['file'],row['bytes']),row,retain=True)
    target=context/'patched-hdfs';target.mkdir(mode=0o700);identity=C.directory(target)
    for relative,raw in files.items():
        C.directory(target,identity);path=target/relative;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as stream:stream.write(raw)
    C.directory(target,identity);need(tree_hashes(C,target)=={p:sha(b) for p,b in files.items()},'input_changed')
    for name,pin in pins.items():
        relative=name.split('/',1)[1]
        original=files.get(relative) if name.startswith('hdfs/') else C.read(context/'original'/relative,131072)
        if pin['beforeSha256'] is None:need(original is None,'input_changed')
        else:need(type(original) is bytes and len(original)==pin['beforeBytes'] and sha(original)==pin['beforeSha256'],'input_changed')
    need('LICENSE.txt' in files and sources['COPYING-hdfs']==files['LICENSE.txt'],'input_changed')
    return dict(module='github.com/colinmarc/hdfs/v2',version='v2.4.0',archive_sha256=row['sha256'],
                members=stats['members'],expanded_bytes=stats['expanded_bytes'],patches=len(pins),original_sources_verified=True)

def overlay_commands(pins,kind):
    result=[]
    for name,pin in pins.items():
        if not name.startswith(kind+'/'):continue
        relative=name.split('/',1)[1]
        target=('/opt/input/patched-hdfs/' if kind=='hdfs' else '/opt/input/original/')+relative
        if pin['beforeSha256'] is not None:
            result.append("printf '%s\\n' '"+pin['beforeSha256']+"  "+target+"' | sha256sum -c -")
        else:result.append('test ! -e '+target)
        result.append('cp /opt/input/patches/'+name+' '+target)
        result.append("printf '%s\\n' '"+pin['afterSha256']+"  "+target+"' | sha256sum -c -")
    return result

def build_files(C,sources,original_mod,original_sum):
    pins=load_patch_pins(C,sources)
    need(b'\nreplace ' not in original_mod,'input_invalid')
    patched_mod=original_mod+b'\nreplace github.com/colinmarc/hdfs/v2 => /opt/input/patched-hdfs\n'
    driver='\n'.join(["#!/bin/sh","set -eu","umask 077","mkdir /work/home","ulimit -f 16","set +e","/usr/bin/timeout --signal=TERM --kill-after=2s 40s /opt/probes/context-tests -test.v -test.timeout=30s -test.run '^(TestContextAdmissionCancellationPreservesOwner|TestContextPrecancelledRequestHasNoEffects|TestContextExpiredDeadlineHasNoEffects|TestContextHeldResponseFinishesBeforeRelease|TestContextBlockedWriteFinishes|TestContextDialReceivesCancellation|TestContextHandshakeReceivesCancellation|TestContextCompletedRequestCannotCloseNextOperation|TestContextStartedCallbackIsJoinedBeforeReturn|TestContextNonCancellationErrorIsPreserved|TestContextCancelledStreamRequiresFreshDial)$' > /work/context-tests-stdout 2> /work/context-tests-stderr","unit_status=$?","set -e","printf '%s\\n' \"$unit_status\" > /work/context-tests-status","for variant in original patched; do"," /usr/bin/timeout --signal=TERM --kill-after=2s 10s /opt/probes/rclone-\"$variant\" version > /work/\"$variant\"-version","done","exec /usr/bin/timeout --signal=TERM --kill-after=2s 10s /opt/probes/inspect-context-build",""]).encode()
    commands=["#!/bin/sh","set -eu","umask 077","tar -xzf /opt/input/assets/go-toolchain.tar.gz -C /opt","mkdir /opt/probes /opt/cache /opt/tmp /opt/home"]
    commands+=overlay_commands(pins,'hdfs')
    commands+=["cd /opt/input/original","env -i HOME=/opt/home PATH=/opt/go/bin:/usr/bin:/bin GOROOT=/opt/go GOMODCACHE=/opt/input/module-cache GOCACHE=/opt/cache GOTMPDIR=/opt/tmp GOENV=off GOTOOLCHAIN=local GOWORK=off GOTELEMETRY=off GOPROXY=off GOSUMDB=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOMAXPROCS=2 GOMEMLIMIT=1GiB /opt/go/bin/go build -mod=readonly -modfile=/opt/input/original/go.mod -trimpath -buildvcs=false -p 2 -ldflags \"-X github.com/rclone/rclone/fs.Version=v1.75.2-kerberos-original\" -o /opt/probes/rclone-original ."]
    commands+=overlay_commands(pins,'rclone')
    commands+=["env -i HOME=/opt/home PATH=/opt/go/bin:/usr/bin:/bin GOROOT=/opt/go GOMODCACHE=/opt/input/module-cache GOCACHE=/opt/cache GOTMPDIR=/opt/tmp GOENV=off GOTOOLCHAIN=local GOWORK=off GOTELEMETRY=off GOPROXY=off GOSUMDB=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOMAXPROCS=2 GOMEMLIMIT=1GiB /opt/go/bin/go build -mod=readonly -modfile=/opt/input/patched-rclone.mod -trimpath -buildvcs=false -p 2 -ldflags \"-X github.com/rclone/rclone/fs.Version=v1.75.2-hdfs-context-patched\" -o /opt/probes/rclone-patched .","env -i HOME=/opt/home PATH=/opt/go/bin:/usr/bin:/bin GOROOT=/opt/go GOMODCACHE=/opt/input/module-cache GOCACHE=/opt/cache GOTMPDIR=/opt/tmp GOENV=off GOTOOLCHAIN=local GOWORK=off GOTELEMETRY=off GOPROXY=off GOSUMDB=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOMAXPROCS=2 GOMEMLIMIT=1GiB /opt/go/bin/go test -c -mod=readonly -modfile=/opt/input/patched-rclone.mod -trimpath -buildvcs=false -p 2 -o /opt/probes/context-tests github.com/colinmarc/hdfs/v2/internal/rpc","env -i HOME=/opt/home PATH=/opt/go/bin:/usr/bin:/bin GOROOT=/opt/go GOMODCACHE=/opt/input/module-cache GOCACHE=/opt/cache GOTMPDIR=/opt/tmp GOENV=off GOTOOLCHAIN=local GOWORK=off GOTELEMETRY=off GOPROXY=off GOSUMDB=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOMAXPROCS=2 GOMEMLIMIT=1GiB /opt/go/bin/go build -mod=readonly -trimpath -buildvcs=false -p 2 -o /opt/probes/inspect-context-build /opt/input/inspect_context_build.go","chmod -R a=rX /opt/probes","chmod 0555 /opt/probes/* /opt/input /opt/input/driver.sh",""]
    build='\n'.join(commands).encode()
    dockerfile=('FROM '+C.BASE+'\nUSER 0\nCOPY . /opt/input/\n'
        'RUN cd /opt/input && sha256sum -c checksums && /bin/sh /opt/input/build.sh\n'
        'USER 10001:10001\nWORKDIR /work\n').encode()
    return {'Dockerfile':dockerfile,'build.sh':build,'driver.sh':driver,'patched-rclone.mod':patched_mod,'patched-rclone.sum':original_sum}

def command_args(name,image,run_id):
    need(type(run_id) is str and re.fullmatch('[a-f0-9]{32}',run_id) and name=='rclone-usage-'+run_id
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
    for m in re.finditer(r'(inspect_context_build[.]go|internal/rpc/(?:namenode|namenode_context|namenode_context_test)[.]go|(?:stat|file_reader|readdir)[.]go|backend/hdfs/fs[.]go):([0-9]{1,5}):[^\r\n]*',raw.decode('utf8','replace')):
        row={'file':m[1],'line':int(m[2])}
        need(1<=row['line']<=10000 and len(errors)<32,'input_invalid')
        if row not in errors:errors.append(row)
    return {'source_errors':errors,'module_resolution_failed':b'module lookup disabled by GOPROXY=off' in raw,
            'module_update_required':b'updates to go.mod needed' in raw or b'updates to ' in raw and b'.mod needed' in raw,
            'build_constraints':b'build constraints exclude all Go files' in raw,
            'toolchain_requirement':b'requires go >=' in raw}

def validate_context_tests(value,complete=False):
    keys={'stage','parser_vectors','binary_sha256','binary_bytes','exit_code','stderr_empty','protocol_valid','runs','passed','failed','all_passed'}
    need(type(value) is dict and set(value)==keys,'report_invalid')
    need(type(value['parser_vectors']) is int and 0<=value['parser_vectors']<=14,'report_invalid')
    need(type(value['stage']) is str and value['stage'] in ('start','binary','status','stderr','parse','failed','complete')
         and type(value['binary_sha256']) is str and (value['binary_sha256']=='' or re.fullmatch('[a-f0-9]{64}',value['binary_sha256']))
         and type(value['binary_bytes']) is int and (value['binary_bytes']==0 or 1024*1024<value['binary_bytes']<=128*1024*1024)
         and (value['binary_sha256']=='') is (value['binary_bytes']==0)
         and type(value['exit_code']) is int and -1<=value['exit_code']<=255,'report_invalid')
    need(all(type(value[k]) is bool for k in ('stderr_empty','protocol_valid','all_passed')),'report_invalid')
    for key in ('runs','passed','failed'):
        rows=value[key]
        need(type(rows) is list and len(rows)<=11 and all(type(x) is str and x in TEST_NAMES for x in rows)
             and len(set(rows))==len(rows),'report_invalid')
    need(set(value['passed']).isdisjoint(value['failed'])
         and set(value['passed'])|set(value['failed'])<=set(value['runs'])
         and (value['stage']=='complete') is value['all_passed'],'report_invalid')
    if value['protocol_valid']:need(value['stage'] in ('failed','complete'),'report_invalid')
    if value['all_passed'] or complete:
        need(value['all_passed'] is True and value['stage']=='complete' and value['exit_code']==0
             and value['stderr_empty'] is True and value['protocol_valid'] is True
             and value['runs']==value['passed']==list(TEST_NAMES) and value['failed']==[]
             and value['binary_bytes']>1024*1024 and len(value['binary_sha256'])==64 and value['parser_vectors']==14,'report_invalid')
    return value

def native_test_diagnostics(C,raw):
    need(type(raw) is bytes and len(raw)<=262144,'report_invalid')
    value=C.parse(raw,262144);need(type(value) is dict and 'context_tests' in value,'report_invalid')
    return validate_context_tests(value['context_tests'])

def validate_native(C,raw,exit_code,lock):
    need(type(raw) is bytes and len(raw)<=262144 and type(exit_code) is int,'report_invalid')
    v=C.parse(raw,262144)
    need(type(v) is dict and set(v)=={'schema_version','success','error','go_version','binaries','rclone_renewal_verified','provider_accepted','cancellation_verified','context_tests'},'report_invalid')
    need(type(v['schema_version']) is int and v['schema_version']==1 and v['success'] is True
         and v['error']=='none' and v['go_version']=='go1.26.10'
         and v['rclone_renewal_verified'] is False and v['provider_accepted'] is False and v['cancellation_verified'] is False,'report_invalid')
    validate_context_tests(v['context_tests'],True)
    need(type(v['binaries']) is list and len(v['binaries'])==2,'report_invalid')
    pins={(r['module'],r['version']):r['h1'] for r in lock['assets'] if r['kind']=='zip'}
    graphs=[]
    for index,b in enumerate(v['binaries']):
        need(type(b) is dict and set(b)=={'variant','sha256','bytes','checks','version_verified','modules'},'report_invalid')
        need(b['variant']==('original','patched')[index] and re.fullmatch('[a-f0-9]{64}',b['sha256'])
             and type(b['bytes']) is int and 1024*1024<b['bytes']<=512*1024*1024
             and type(b['checks']) is int and b['checks']==13 and b['version_verified'] is True,'report_invalid')
        modules=b['modules'];need(type(modules) is list and 0<len(modules)<=334,'report_invalid');graph={}
        for d in modules:
            need(type(d) is dict and set(d)=={'path','version','sum','replacement'} and type(d['path']) is str
                 and type(d['version']) is str and type(d['sum']) is str and type(d['replacement']) is str
                 and d['path'] not in graph,'report_invalid')
            if index==1 and d['path']=='github.com/colinmarc/hdfs/v2':
                need(d['version']=='v2.4.0' and d['sum']=='' and d['replacement']=='context-cancellation','report_invalid')
            else:need(d['replacement']=='' and pins.get((d['path'],d['version']))==d['sum'],'report_invalid')
            graph[d['path']]=d
        need([d['path'] for d in modules]==sorted(graph) and 'github.com/jcmturner/gokrb5/v8' in graph,'report_invalid')
        need(graph.get('golang.org/x/crypto',{}).get('version')=='v0.57.0'
             and graph.get('golang.org/x/net',{}).get('version')=='v0.60.0'
             and graph.get('github.com/colinmarc/hdfs/v2',{}).get('version')=='v2.4.0','report_invalid')
        graphs.append(graph)
    need(set(graphs[0])==set(graphs[1]),'report_invalid')
    for p,d in graphs[0].items():
        other=graphs[1][p];need(d['version']==other['version'] and (p=='github.com/colinmarc/hdfs/v2' or d==other),'report_invalid')
    need(v['binaries'][0]['sha256']!=v['binaries'][1]['sha256'] and exit_code==0,'probe_failed')
    return v

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


CLEANUP_ERROR_CODES=frozenset(('command_timeout','command_failed','command_output_limit','command_start_failed',
    'command_cleanup_failed','container_binding_invalid','docker_json_invalid','container_cleanup_failed',
    'image_cleanup_failed','input_invalid'))

def cleanup_error(error):
    code=getattr(error,'code',None)
    if type(code) is str and code in CLEANUP_ERROR_CODES:return code
    if isinstance(error,KeyboardInterrupt):return 'interrupted'
    if isinstance(error,OSError):return 'filesystem'
    return 'unexpected'

def cleanup_owned(docker,kind,reference,exact,run_id,name,tag,image,diagnostic):
    # Preserve the existing ownership and removal bounds. Diagnostics contain
    # only the operation phase and a closed error category, never raw output.
    try:
        diagnostic['stage']='preflight'
        need(kind in ('container','image'),'input_invalid')
        diagnostic['stage']='inspect'
        current=docker.inspect(kind,reference,allow_missing=True)
        if current is not None:
            diagnostic['stage']='bind_label'
            need(current.get('Config',{}).get('Labels',{}).get(LABEL)==run_id,kind+'_cleanup_failed')
            owned=current.get('Id')
            diagnostic['stage']='bind_identity'
            need(type(owned) is str and (exact is None or owned==exact)
                 and re.fullmatch('[a-f0-9]{64}' if kind=='container' else 'sha256:[a-f0-9]{64}',owned),kind+'_cleanup_failed')
            if kind=='container':
                diagnostic['stage']='bind_container_name'
                need(current.get('Name')=='/'+name,'container_cleanup_failed')
                diagnostic['stage']='bind_container_image'
                need(current.get('Image')==image,'container_cleanup_failed')
            else:
                diagnostic['stage']='bind_image_tags'
                need(current.get('RepoTags')==[tag+':latest'],'image_cleanup_failed')
            diagnostic['stage']='remove'
            docker.call([kind,'rm',*(['--force'] if kind=='container' else []),owned])
            diagnostic['stage']='confirm_absence'
            need(docker.inspect(kind,owned,allow_missing=True) is None,kind+'_cleanup_failed')
        diagnostic['stage']='complete'
    except BaseException as error:
        diagnostic['error']=cleanup_error(error)
        raise

def run():
    began=time.monotonic();report=dict(schema_version=1,scope='hdfs_context_candidate_build',success=False,
        started_utc=datetime.now(timezone.utc).isoformat(),finished_utc=None,duration_seconds=None,
        stage='preflight',inputs=None,result=None,test_diagnostics=None,build_diagnostics=None,worker_diagnostics=None,failure_diagnostics=None,errors=[],
        cleanup=dict(container_removed=False,image_removed=False,context_removed=False,raw_evidence_removed=False),
        cleanup_diagnostics={kind:dict(stage='not_attempted',error='none') for kind in ('container','image')},
        cleanup_excludes=['shared_base_image','shared_build_cache'],**dict.fromkeys(FALSE_CLAIMS,False))
    C=B=D=docker=root=context=root_id=context_id=image=container=None
    source_hashes={};built_attempted=created_attempted=False
    run_id=uuid.uuid4().hex;name=tag='rclone-usage-'+run_id;old_umask=os.umask(0o077)
    try:
        C=load_support();C.hosted_guard();need(sys.version_info[:2]==(3,14),'python_version');B=load_bundle(C)
        D,source_hashes=C.load_helpers();lock_raw=C.read(ASSETS_HOME/'assets-lock.json',1048576);lock=B.load_lock(lock_raw)
        sources={name:C.read(source,131072) for name,source in SOURCES.items()}
        source_hashes.update({SUPPORT:SUPPORT_SHA,Path(__file__):C.file_hash(Path(__file__),524288),
            ASSETS_HOME/'rclone_build_bundle.py':BUNDLE_SHA,ASSETS_HOME/'assets-lock.json':sha(lock_raw)})
        source_hashes.update({SOURCES[name]:sha(raw) for name,raw in sources.items()})
        report['inputs']=dict(source_sha256={p.relative_to(HERE.parent).as_posix():h for p,h in source_hashes.items()},
            base_manifest=C.BASE,base_config_id=C.BASE_ID,assets=1137,asset_bytes=sum(r['bytes'] for r in lock['assets']),
            toolchain='go1.26.10',module='github.com/rclone/rclone',module_version='v1.75.2',
            context_sha256=None,image_id=None,container_id=None)
        need(shutil.disk_usage('/tmp').free>=12*1024**3,'unsafe_path')
        root=Path(tempfile.mkdtemp(prefix=name+'-',dir='/tmp'));root_id=C.directory(root)
        context=root/'context';context.mkdir(mode=0o700);context_id=C.directory(context)
        report['stage']='download_assets';prepare_packages(C,B,context,progress=lambda stage:report.update(stage=stage))
        report['worker_diagnostics']=read_worker_status(C,context)
        need(report['worker_diagnostics']['phase']=='complete' and report['worker_diagnostics']['error']=='none','package_worker_failed')
        report['stage']='stage_context'
        report['inputs']['hdfs_source']=stage_hdfs(C,B,context,lock,sources)
        for filename,raw in {**sources,**build_files(C,sources,C.read(context/'original/go.mod',131072),C.read(context/'original/go.sum',131072))}.items():
            target=context/filename;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
        report['stage']='hash_context';before=tree_hashes(C,context)
        (context/'checksums').write_bytes(checksum_manifest(before))
        context_hashes=tree_hashes(C,context);report['inputs']['context_sha256']=sha(canonical(context_hashes))
        docker=D.Docker(root,max_calls=40);host=C.parse(C.read(docker.call(['info','--format','{{json .}}']).stdout,1048576))
        need(host.get('OSType')=='linux' and host.get('Architecture') in ('amd64','x86_64'),'platform_invalid')
        report['stage']='base';docker.call(['image','pull','--quiet','--platform','linux/amd64',C.BASE],timeout=120)
        base=docker.inspect('image',C.BASE);report['base_observation']=C.base_observation(base,C.BASE,C.BASE_ID);C.validate_base(base,C.BASE,C.BASE_ID)
        need(docker.inspect('image',tag,allow_missing=True) is None,'image_invalid')
        report['stage']='build';built_attempted=True
        compiled=docker.call(['build','--network','none','--pull=false','--label',LABEL+'='+run_id,'--tag',tag,str(context)],timeout=600,limit=4194304,allow_failure=True)
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
        container=initial['Id'];report['inputs']['container_id']=container;report['stage']='context_tests_and_identity'
        result=docker.call(['start','--attach',container],timeout=90,limit=262144,allow_failure=True)
        ended=docker.inspect('container',container);inspect_container(ended,name,image,run_id);state=ended.get('State',{})
        need(ended['Id']==container and state.get('Running') is False and state.get('Status')=='exited'
             and state.get('OOMKilled') is False and type(state.get('ExitCode')) is int
             and state['ExitCode']==result.code,'container_invalid')
        need(C.read(result.stderr,8388608)==b'','probe_failed')
        native_raw=C.read(result.stdout,262144)
        report['test_diagnostics']=native_test_diagnostics(C,native_raw)
        report['result']=validate_native(C,native_raw,result.code,lock)
        report['success']=True;report['stage']='completed'
    except KeyboardInterrupt:report['errors'].append('interrupted')
    except BaseException as error:
        report['failure_diagnostics']=failure_diagnostics(error)
        report['errors'].append(getattr(error,'code',None) if getattr(error,'code',None) in CODES else 'probe_failed')
        if context is not None and C is not None and report['worker_diagnostics'] is None:
            try:report['worker_diagnostics']=read_worker_status(C,context)
            except BaseException:report['worker_diagnostics']=dict(schema_version=1,phase='startup',asset_index=-1,processed_assets=0,error='status_unavailable',http_status=0)
    finally:
        for kind,attempted,reference,exact in (('container',created_attempted,container or name,container),('image',built_attempted,image or tag,image)):
            try:
                if attempted:cleanup_owned(docker,kind,reference,exact,run_id,name,tag,image,report['cleanup_diagnostics'][kind])
                report['cleanup'][kind+'_removed']=True
            except BaseException as error:
                if getattr(error,'code',None)=='command_cleanup_failed':report['errors'].append('command_cleanup_failed')
                report['errors'].append(kind+'_cleanup_failed')
        try:
            for path,expected in source_hashes.items():need(C.file_hash(path,1048576)==expected,'input_changed')
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
            result=run();data=canonical(result)+b'\n';need(len(data)<=393216,'report_failed');stream.write(data);stream.flush();os.fsync(stream.fileno())
        return 0 if result['success'] else 1
    except BaseException:sys.stderr.write('rclone_candidate_build_failed\n');return 1
    finally:signal.signal(signal.SIGTERM,previous)

if __name__=='__main__':raise SystemExit(main())
