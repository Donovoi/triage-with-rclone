"""Hosted-only MIT KDC bootstrap prerequisite; no rclone renewal credit.

Importing this module does not download or execute anything. Native work is
confined to the pinned, network-disabled image after container admission.
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
import subprocess
import sys
import tempfile
import time
import types
import urllib.request
import uuid

HERE=Path(__file__).resolve().parent
SUPPORT=HERE.parent/'hdfs-kerberos-policy-denial/policy_denial_container.py'
SUPPORT_SHA='67edb0c6324e995ff592fb4d7ea332b8ba14c09a425db56ca8f22cc0545c4f19'
BUNDLE_SHA='732376a8580b5f7da8605714026ef57358bd5233e4621cc112aa50dd8db867d7'
PROFILE='kerberos-remediation'
LABEL='org.openai.triage.mit-kdc-renewal'
TMPFS='rw,nosuid,nodev,noexec,size=128m,mode=0700,uid=10001,gid=10001'
SOURCES=('MitKdcOwner.java','MitKdcOwnerContracts.java','MitKdcOwnerLifecycle.java','MitKdcLifecycleChild.java','MitKdcBootstrapProbe.java','mit-kdc-plan-template.json')
LIFECYCLE_CHECKS=frozenset(('graceful_termination','forced_termination_rejected','output_overflow_rejected','descendant_rejected'))
CHECKS=frozenset(('managed_contracts','lifecycle_controls','runtime_started','positive_tgt','short_renewable_service','wrong_password_rejected',
    'unknown_principal_rejected','healthy_after_rejection','tasks_reaped','new_threads_reaped','processes_reaped'))
OWNER_KEYS=frozenset(('stage','setup_completed','children','children_reaped','streams_reaped','modules_verified',
    'listener_verified','forced','descendants_seen','stream_failure','private_material_removed','native_qualified','renewal_verified'))
FALSE_CLAIMS=frozenset(('renewal_verified','rclone_verified','provider_accepted','application_accepted',
    'vendor_accepted','vulnerability_audited'))
JAVA_STAGES=frozenset(('managed_contracts','owner_construct','owner_prepare','owner_start','lifecycle_controls','client_init','positive_tgt','service_ticket',
    'wrong_password','unknown_principal','healthy_after_rejection','completed'))
JAVA_ERRORS=frozenset(('none','plan_invalid','environment_invalid','path_invalid','file_changed','file_bound',
    'setup_nonzero','child_failed','output_bound','child_descendant','deadline','listener_mismatch',
    'module_mismatch','interrupted','cleanup_failed','request_timeout','krb_failure','bootstrap_failed'))
CODES=frozenset(('input_invalid','input_changed','unsafe_path','hosted_linux_required','python_version',
    'package_download_failed','package_worker_failed','package_cleanup_failed','bundle_invalid','platform_invalid',
    'image_invalid','container_invalid','java_report_invalid','java_probe_failed','container_cleanup_failed',
    'image_cleanup_failed','raw_cleanup_failed','command_cleanup_failed','download_cleanup_failed',
    'build_failed','interrupted','probe_failed','report_failed'))

class ProbeError(Exception):
    def __init__(self,code):
        self.code=code if code in CODES else 'probe_failed'
        super().__init__(self.code)

def need(value,code):
    if not value:raise ProbeError(code)

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')

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
    module=types.ModuleType('reviewed_mit_container_support');module.__file__=str(SUPPORT)
    exec(compile(raw,str(SUPPORT),'exec'),module.__dict__)
    return module

def load_bundle(C):
    path=HERE/'mit_runtime_bundle.py';raw=C.read(path,131072)
    need(sha(raw)==BUNDLE_SHA,'input_changed')
    module=types.ModuleType('reviewed_mit_bundle');module.__file__=str(path)
    exec(compile(raw,str(path),'exec'),module.__dict__)
    return module

def download_package_bytes(lock,*,opener=None,clock=time.monotonic):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):raise ProbeError('package_download_failed')
    opener=opener or urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    until=clock()+120;result={}
    for row in lock['packages']:
        need(clock()<until,'package_download_failed')
        request=urllib.request.Request(row['url'],headers={'User-Agent':'triage-synthetic-mit-kdc','Accept-Encoding':'identity'})
        with opener.open(request,timeout=min(20,max(1,int(until-clock())))) as response:
            need(response.status==200 and response.url==row['url'],'package_download_failed')
            need(response.headers.get_all('Content-Length',[])==[str(row['bytes'])]
                and not response.headers.get_all('Transfer-Encoding',[]) and not response.headers.get_all('Content-Encoding',[]),'package_download_failed')
            chunks=[];count=0
            while True:
                need(clock()<until,'package_download_failed')
                chunk=response.read(min(65536,row['bytes']-count+1))
                need(clock()<until,'package_download_failed')
                if not chunk:break
                count+=len(chunk);need(count<=row['bytes'],'package_download_failed');chunks.append(chunk)
        raw=b''.join(chunks)
        need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'package_download_failed')
        result[row['filename']]=raw
    need(clock()<until,'package_download_failed');return result

def write_bundle(C,context,members):
    identity=C.directory(context)
    for name,raw in sorted(members.items()):
        C.directory(context,identity)
        need(type(name) is str and name.startswith('mit/') and '\\' not in name
             and all(p not in ('','.','..') for p in name.split('/')),'unsafe_path')
        target=context/name;parent=context
        for part in name.split('/')[:-1]:
            parent_id=C.directory(parent);child=parent/part
            if not child.exists():
                C.directory(parent,parent_id);child.mkdir(mode=0o700)
            C.directory(child);parent=child
        with target.open('xb') as output:output.write(raw)
        need(C.read(target,len(raw))==raw,'input_changed')

def verify_bundle(C,B,context,lock_raw):
    lock=B.load_lock(lock_raw);expected={m['destination']:m for p in lock['packages'] for m in p['members']}
    observed=set()
    for count,path in enumerate((context/'mit').rglob('*'),1):
        need(count<=100 and not path.is_symlink(),'bundle_invalid')
        if path.is_dir():C.directory(path)
        else:observed.add(path.relative_to(context).as_posix())
    need(observed==set(expected),'bundle_invalid')
    for name,pin in expected.items():
        raw=C.read(context/name,pin['bytes']);need(len(raw)==pin['bytes'] and sha(raw)==pin['sha256'],'bundle_invalid')
    return expected

def package_worker(C,B,context,identity,source_hash):
    C.hosted_guard();need(sys.version_info[:2]==(3,14),'python_version')
    need(context.is_absolute() and context.name=='context' and re.fullmatch('mit-kdc-[a-f0-9]{32}-[a-z0-9_]+',context.parent.name),'unsafe_path')
    C.directory(context,identity);need(C.file_hash(Path(__file__),524288)==source_hash,'input_changed')
    lock_raw=C.read(HERE/'mit-runtime-lock.json',131072);lock=B.load_lock(lock_raw)
    members=B.extract_bundle(lock_raw,download_package_bytes(lock))
    write_bundle(C,context,members);verify_bundle(C,B,context,lock_raw)

def prepare_packages(C,B,context):
    process=None;identity=C.directory(context);source=Path(__file__).resolve();source_hash=C.file_hash(source,524288)
    env={key:os.environ[key] for key in ('PATH','LANG','LC_ALL','GITHUB_ACTIONS','RUNNER_ENVIRONMENT','RUNNER_OS') if key in os.environ}
    try:
        process=subprocess.Popen([sys.executable,'-I','-S','-B',str(source),'--package-worker',str(context),str(identity[0]),str(identity[1]),source_hash],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,cwd=context,env=env,start_new_session=True)
        try:code=process.wait(timeout=180)
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
    return verify_bundle(C,B,context,C.read(HERE/'mit-runtime-lock.json',131072))

def build_files(C,rows,members,sources):
    need(set(sources)==set(SOURCES),'input_invalid')
    cp=':'.join('/opt/rpc/jars/%03d.jar'%i for i in range(len(rows)))
    driver=('#!/bin/sh\nset -eu\numask 077\nmkdir /work/home /work/tmp\n'
        'exec /usr/bin/timeout --signal=TERM --kill-after=5s 180s /opt/java/openjdk/bin/java '
        '-Xmx512m -Djava.net.preferIPv4Stack=true -Djava.io.tmpdir=/work/tmp -Duser.home=/work/home '
        '-cp "$(cat /opt/rpc/classpath)" MitKdcBootstrapProbe\n').encode()
    classpath=('/opt/rpc/classes:'+cp+'\n').encode()
    checks=''.join(row['sha256']+'  /opt/rpc/jars/%03d.jar\n'%i for i,row in enumerate(rows))
    checks+=''.join(pin['sha256']+'  /opt/'+name+'\n' for name,pin in sorted(members.items()))
    checks+=''.join(sha(raw)+'  /opt/rpc/'+name+'\n' for name,raw in sorted({**sources,'driver.sh':driver,'classpath':classpath}.items()))
    dockerfile=('FROM '+C.BASE+'\nUSER 0\nCOPY jars /opt/rpc/jars/\nCOPY mit /opt/mit/\n'
        'COPY MitKdcOwner.java MitKdcOwnerContracts.java MitKdcOwnerLifecycle.java MitKdcLifecycleChild.java MitKdcBootstrapProbe.java mit-kdc-plan-template.json checksums driver.sh classpath /opt/rpc/\n'
        'RUN sha256sum -c /opt/rpc/checksums && mkdir /opt/rpc/classes && '
        "/opt/java/openjdk/bin/javac -J-Xmx512m -proc:none -implicit:none -encoding UTF-8 -cp '"+cp+
        "' -d /opt/rpc/classes /opt/rpc/MitKdcOwner.java /opt/rpc/MitKdcOwnerContracts.java /opt/rpc/MitKdcOwnerLifecycle.java /opt/rpc/MitKdcLifecycleChild.java /opt/rpc/MitKdcBootstrapProbe.java && "
        'chmod -R a=rX /opt/rpc /opt/mit && chmod 0555 /opt/mit/bin/krb5kdc /opt/mit/bin/kdb5_util /opt/mit/bin/kadmin.local\n'
        'USER 10001:10001\nWORKDIR /work\n').encode()
    return dict(Dockerfile=dockerfile,checksums=checks.encode(),**{'driver.sh':driver,'classpath':classpath})

def command_args(name,image,run_id):
    need(type(run_id) is str and re.fullmatch('[a-f0-9]{32}',run_id) and name=='mit-kdc-'+run_id
        and type(image) is str and re.fullmatch('sha256:[a-f0-9]{64}',image),'container_invalid')
    return ['create','--name',name,'--label',LABEL+'='+run_id,'--network','none','--read-only',
        '--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','128',
        '--memory','2g','--cpus','2','--init','--cgroupns','private','--ipc','private','--log-driver','none',
        '--stop-timeout','5','--tmpfs','/work:'+TMPFS,'--entrypoint','/usr/bin/env',image,
        '-i','HOME=/work/home','PATH=/opt/java/openjdk/bin:/usr/bin:/bin','JAVA_HOME=/opt/java/openjdk',
        'LANG=C','LC_ALL=C','/bin/sh','/opt/rpc/driver.sh']

def build_diagnostics(raw):
    """Project only fixed source names, bounded line numbers and finite categories."""
    need(type(raw) is bytes and len(raw)<=8388608,'input_invalid')
    text=raw.decode('utf-8',errors='replace');errors=[]
    pattern=r'/opt/rpc/(MitKdcOwner|MitKdcOwnerContracts|MitKdcOwnerLifecycle|MitKdcLifecycleChild|MitKdcBootstrapProbe)[.]java:([0-9]{1,5}): error: ([^\r\n]*)'
    for match in re.finditer(pattern,text):
        line=int(match[2]);need(1<=line<=10000 and len(errors)<32,'input_invalid')
        message=match[3]
        kind='symbol' if 'cannot find symbol' in message else 'type' if 'incompatible types' in message else 'package' if 'package ' in message and 'does not exist' in message else 'syntax' if any(word in message for word in ('expected','illegal start','reached end')) else 'other'
        row=dict(file=match[1]+'.java',line=line,category=kind)
        if row not in errors:errors.append(row)
    return dict(java_errors=errors)

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

def validate_java(C,raw,exit_code):
    need(type(raw) is bytes and len(raw)<=32768,'java_report_invalid');value=C.parse(raw)
    keys={'schema_version','scope','success','stage','error','checks','owner','tasks','managed_assertions','lifecycle_checks','lifecycle_children',
        'initial_new_threads','remaining_new_threads','thread_wait_ms','thread_quiet_observations','tgt_lifetime_seconds','service_lifetime_seconds','duration_ms','cleanup_complete'}|FALSE_CLAIMS
    need(type(value) is dict and set(value)==keys and type(value['schema_version']) is int and value['schema_version']==1
        and value['scope']=='mit_kdc_bootstrap_only' and type(value['success']) is bool and type(value['cleanup_complete']) is bool,'java_report_invalid')
    need(type(value['stage']) is str and value['stage'] in JAVA_STAGES and type(value['error']) is str
        and value['error'] in JAVA_ERRORS and all(value[k] is False for k in FALSE_CLAIMS),'java_report_invalid')
    checks=value['checks'];need(type(checks) is dict and set(checks)==CHECKS and all(type(v) is bool for v in checks.values()),'java_report_invalid')
    lifecycle=value['lifecycle_checks'];need(type(lifecycle) is dict and set(lifecycle)==LIFECYCLE_CHECKS and all(type(v) is bool for v in lifecycle.values()),'java_report_invalid')
    for key in ('initial_new_threads','remaining_new_threads'):
        counts=value[key];need(type(counts) is dict and set(counts)=={'process_reaper','owned_mit','other'}
            and all(type(n) is int and 0<=n<=128 for n in counts.values()) and sum(counts.values())<=128,'java_report_invalid')
    for name,maximum in [('tasks',5),('managed_assertions',1000),('lifecycle_children',5),('thread_wait_ms',71000),('thread_quiet_observations',3),('tgt_lifetime_seconds',120),('service_lifetime_seconds',10),('duration_ms',190000)]:
        need(type(value[name]) is int and 0<=value[name]<=maximum,'java_report_invalid')
    owner=value['owner'];need(type(owner) is dict and (not owner or set(owner)==OWNER_KEYS),'java_report_invalid')
    if owner:
        need(type(owner['stage']) is str and owner['stage'] in {'constructed','environment','prepared','kdc_start','running','closed',*LABELS_FOR_OWNER}
            and type(owner['setup_completed']) is int and 0<=owner['setup_completed']<=6
            and type(owner['children']) is int and 0<=owner['children']<=7,'java_report_invalid')
        need(all(type(v) is bool for k,v in owner.items() if k not in {'stage','setup_completed','children'})
            and owner['native_qualified'] is False and owner['renewal_verified'] is False,'java_report_invalid')
    if value['success']:
        need(exit_code==0 and value['stage']=='completed' and value['error']=='none' and value['cleanup_complete']
            and all(checks.values()) and all(lifecycle.values()) and value['lifecycle_children']==5
            and value['thread_quiet_observations']==3 and all(n==0 for n in value['remaining_new_threads'].values())
            and value['tasks']==5 and value['managed_assertions']==83 and 118<=value['tgt_lifetime_seconds']<=120
            and 8<=value['service_lifetime_seconds']<=10 and owner and owner['stage']=='closed'
            and owner['setup_completed']==6 and owner['children']==7,'java_report_invalid')
        need(all(owner[k] for k in ('children_reaped','streams_reaped','modules_verified','listener_verified','private_material_removed'))
            and not any(owner[k] for k in ('forced','descendants_seen','stream_failure')),'java_report_invalid')
    else:need(exit_code!=0,'java_report_invalid')
    return value

LABELS_FOR_OWNER=frozenset(('database_create','reader_create','hdfs_create','hdfs_export','http_create','http_export'))

def run():
    began=time.monotonic();report=dict(schema_version=1,scope='mit_kdc_bootstrap_container_prerequisite',success=False,
        started_utc=datetime.now(timezone.utc).isoformat(),finished_utc=None,duration_seconds=None,stage='preflight',inputs=None,result=None,build_diagnostics=None,errors=[],
        cleanup=dict(container_removed=False,image_removed=False,context_removed=False,raw_evidence_removed=False),
        cleanup_excludes=['shared_base_image','shared_build_cache'],**dict.fromkeys(FALSE_CLAIMS,False))
    C=B=D=docker=root=context=root_id=context_id=image=container=None
    source_hashes={};built_attempted=created_attempted=False
    run_id=uuid.uuid4().hex;name=tag='mit-kdc-'+run_id;old_umask=os.umask(0o077)
    try:
        C=load_support();C.hosted_guard();need(sys.version_info[:2]==(3,14),'python_version');B=load_bundle(C)
        D,source_hashes=C.load_helpers();pins=C.profile_settings(PROFILE)
        runtime_raw=C.read(pins['runtime'],524288);jar_lock=C.read(pins['lock'],524288)
        rows=C.runtime_rows(runtime_raw,jar_lock,profile=PROFILE);lock_raw=C.read(HERE/'mit-runtime-lock.json',131072);lock=B.load_lock(lock_raw)
        sources={name:C.read(HERE/name,131072) for name in SOURCES}
        source_hashes.update({SUPPORT:SUPPORT_SHA,Path(__file__):C.file_hash(Path(__file__),524288),HERE/'mit_runtime_bundle.py':BUNDLE_SHA,
            HERE/'mit-runtime-lock.json':sha(lock_raw),pins['runtime']:sha(runtime_raw),pins['lock']:sha(jar_lock)})
        source_hashes.update({HERE/name:sha(raw) for name,raw in sources.items()})
        report['inputs']=dict(source_sha256={p.name:h for p,h in source_hashes.items()},jdk_manifest=C.BASE,jdk_config_id=C.BASE_ID,
            runtime_jars=len(rows),runtime_bytes=sum(row['size'] for row in rows),runtime_file_sha256=pins['runtime_sha256'],
            runtime_classpath_sha256=pins['order_sha256'],lock_sha256=pins['lock_sha256'],mit_lock_sha256=B.LOCK_SHA256,
            mit_packages=len(lock['packages']),mit_members=sum(len(p['members']) for p in lock['packages']),context_sha256=None,image_id=None,container_id=None)
        need(shutil.disk_usage('/tmp').free>=512*1024**2,'unsafe_path')
        root=Path(tempfile.mkdtemp(prefix=name+'-',dir='/tmp'));root_id=C.directory(root)
        context=root/'context';context.mkdir(mode=0o700);context_id=C.directory(context)
        (context/'runtime-classpath.json').write_bytes(runtime_raw);(context/pins['lock'].name).write_bytes(jar_lock)
        report['stage']='download_jars';C.download(context,rows,profile=PROFILE);C.verify_jars(context,rows)
        report['stage']='download_mit';members=prepare_packages(C,B,context)
        for filename,raw in {**sources,**build_files(C,rows,members,sources)}.items():(context/filename).write_bytes(raw)
        context_hashes=C.tree_hashes(context);report['inputs']['context_sha256']=sha(canonical(context_hashes))
        docker=D.Docker(root,max_calls=40);host=C.parse(C.read(docker.call(['info','--format','{{json .}}']).stdout,1048576))
        need(host.get('OSType')=='linux' and host.get('Architecture') in ('amd64','x86_64'),'platform_invalid')
        report['stage']='base';docker.call(['image','pull','--quiet','--platform','linux/amd64',C.BASE],timeout=120)
        base=docker.inspect('image',C.BASE);report['base_observation']=C.base_observation(base,C.BASE,C.BASE_ID);C.validate_base(base,C.BASE,C.BASE_ID)
        need(docker.inspect('image',tag,allow_missing=True) is None,'image_invalid')
        report['stage']='build';built_attempted=True
        compiled=docker.call(['build','--network','none','--pull=false','--label',LABEL+'='+run_id,'--tag',tag,str(context)],timeout=180,limit=4194304,allow_failure=True)
        report['build_diagnostics']=build_diagnostics(C.read(compiled.stdout,4194304)+C.read(compiled.stderr,4194304))
        need(compiled.code==0,'build_failed')
        built=docker.inspect('image',tag);image=built.get('Id')
        need(type(image) is str and re.fullmatch('sha256:[a-f0-9]{64}',image) and built.get('Config',{}).get('Labels',{}).get(LABEL)==run_id
            and built.get('Config',{}).get('User')=='10001:10001','image_invalid')
        need(C.tree_hashes(context)==context_hashes,'input_changed');report['inputs']['image_id']=image
        need(docker.inspect('container',name,allow_missing=True) is None,'container_invalid')
        report['stage']='create';created_attempted=True;docker.call(command_args(name,image,run_id))
        initial=docker.inspect('container',name);inspect_container(initial,name,image,run_id)
        need(initial.get('State',{}).get('Status')=='created' and initial['State'].get('Running') is False,'container_invalid')
        container=initial['Id'];report['inputs']['container_id']=container;report['stage']='bootstrap'
        result=docker.call(['start','--attach',container],timeout=195,limit=32768,allow_failure=True)
        ended=docker.inspect('container',container);inspect_container(ended,name,image,run_id);state=ended.get('State',{})
        need(ended['Id']==container and state.get('Running') is False and state.get('Status')=='exited' and state.get('OOMKilled') is False
            and type(state.get('ExitCode')) is int and state['ExitCode']==result.code,'container_invalid')
        report['result']=validate_java(C,C.read(result.stdout,32768),result.code)
        need(report['result']['success'],'java_probe_failed');report['success']=True;report['stage']='completed'
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
                need(safe,'raw_cleanup_failed');C.directory(root,root_id);C.directory(context,context_id);C.tree_hashes(context)
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
    except BaseException:sys.stderr.write('mit_bootstrap_failed\n');return 1
    finally:signal.signal(signal.SIGTERM,previous)

if __name__=='__main__':raise SystemExit(main())
