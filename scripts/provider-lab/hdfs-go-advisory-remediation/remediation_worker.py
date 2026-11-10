"""Owned Python worker for pinned remediation assets; native execution is elsewhere."""
from __future__ import annotations
import os,re,signal,subprocess,sys
from pathlib import Path
from audit_contract import ContractError,need
from remediation_bundle import load_lock,prepare,verify_prepared,validate_prepared

PHASES=frozenset(('startup','download','prepare','complete'))
ERRORS=frozenset(('none','http_error','network_io','timeout','asset_validation','archive_invalid',
                 'filesystem_error','unexpected','status_unavailable'))
def validate_status(value):
    need(type(value) is dict and set(value)=={'schema_version','phase','asset_index','processed_assets','error','http_status'},
         'remediation_worker_status')
    need(type(value['schema_version']) is int and value['schema_version']==1
         and type(value['phase']) is str and value['phase'] in PHASES
         and type(value['asset_index']) is int and -1<=value['asset_index']<36
         and type(value['processed_assets']) is int and 0<=value['processed_assets']<=36
         and type(value['error']) is str and value['error'] in ERRORS
         and type(value['http_status']) is int
         and (value['http_status']==0 or 100<=value['http_status']<=599),'remediation_worker_status')
    need((value['error']=='http_error')==(value['http_status']!=0),'remediation_worker_status')
    if value['phase']=='download':
        need(value['asset_index']>=0 and value['processed_assets'] in (value['asset_index'],value['asset_index']+1),
             'remediation_worker_status')
    else:
        need(value['asset_index']==-1 and value['processed_assets']==(0 if value['phase']=='startup' else 36),
             'remediation_worker_status')
    if value['phase']=='complete':need(value['error']=='none','remediation_worker_status')
    return value

def worker(C,R,B,context,identity,source,source_hash,lock_raw):
    C.hosted_guard();need(sys.version_info[:2]==(3,14),'python_version')
    need(context.is_absolute() and context.name=='remediation' and context.parent.name=='context'
         and re.fullmatch('rclone-usage-[a-f0-9]{32}-[a-z0-9_]+',context.parent.parent.name),'unsafe_path')
    C.directory(context,identity);need(C.file_hash(source,524288)==source_hash,'input_changed')
    state=dict(schema_version=1,phase='startup',asset_index=-1,processed_assets=0,error='none',http_status=0)
    def record(phase,index,processed):
        state.update(phase=phase,asset_index=index,processed_assets=processed)
        validate_status(state);C.directory(context,identity)
        destination=context/'worker-status.json';temporary=context/'worker-status.next'
        if destination.exists() or destination.is_symlink():C.regular(destination,2048)
        raw=R.canonical(state)+b'\n';need(len(raw)<=2048,'remediation_worker_status')
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,destination);C.directory(context,identity)
    try:
        record('startup',-1,0)
        lock=load_lock(lock_raw);B.download(context,lock,observer=record)
        record('prepare',-1,36)
        result=prepare(B,context,lock,C.read)
        raw=R.canonical(result)+b'\n';need(len(raw)<=4096,'remediation_worker_report')
        with (context/'prepared.json').open('xb') as stream:stream.write(raw)
        record('complete',-1,36)
    except BaseException as error:
        state['error'],state['http_status']=('asset_validation',0) if isinstance(error,ContractError) else R.worker_error(B,error)
        try:record(state['phase'],state['asset_index'],state['processed_assets'])
        except BaseException:pass
        raise

def prepare_owned(C,R,B,context,source,lock_raw):
    C.hosted_guard();need(sys.version_info[:2]==(3,14),'python_version')
    process=None;identity=C.directory(context);source=source.resolve();source_hash=C.file_hash(source,524288)
    env={key:os.environ[key] for key in ('PATH','LANG','LC_ALL','GITHUB_ACTIONS','RUNNER_ENVIRONMENT','RUNNER_OS') if key in os.environ}
    try:
        process=subprocess.Popen([sys.executable,'-I','-S','-B',str(source),'--remediation-worker',str(context),
                                  str(identity[0]),str(identity[1]),source_hash],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
            cwd=context,env=env,start_new_session=True)
        try:code=process.wait(timeout=270)
        except subprocess.TimeoutExpired:raise R.ProbeError('package_worker_failed') from None
        need(code==0,'remediation_worker_failed')
    finally:
        if process is not None:
            try:
                if process.poll() is None:
                    need(os.getpgid(process.pid)==process.pid,'package_cleanup_failed');os.killpg(process.pid,signal.SIGKILL)
                process.wait(timeout=3)
            except (OSError,subprocess.TimeoutExpired):raise R.ProbeError('package_cleanup_failed') from None
    C.directory(context,identity);need(C.file_hash(source,524288)==source_hash,'input_changed')
    status_raw=C.read(context/'worker-status.json',2048)
    status=validate_status(C.parse(status_raw,2048));need(status['phase']=='complete','remediation_worker_failed')
    lock=load_lock(lock_raw);hashes=verify_prepared(B,context,lock,C.read)
    prepared_raw=C.read(context/'prepared.json',4096);prepared=C.parse(prepared_raw,4096)
    validate_prepared(prepared)
    hashes.update({'worker-status.json':R.sha(status_raw),'prepared.json':R.sha(prepared_raw)})
    need(R.tree_hashes(C,context)==hashes,'remediation_worker_tree')
    return lock,prepared,status,hashes
