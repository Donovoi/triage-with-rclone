"""Hosted-only, offline native Go advisory observations for qualified rclone builds."""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import hashlib,json,os,re,shutil,signal,stat,sys,tempfile,time,types,uuid
from pathlib import Path

HERE=Path(__file__).resolve().parent
PINS_SHA='11c48152a533d9a19c7f72a193c94292d004ef785b185230d569bb263ed5cfca'
LABEL='org.openai.triage.hdfs-context-build'
TMPFS='rw,nosuid,nodev,noexec,size=128m,mode=0700,uid=10001,gid=10001'
MODULES=('audit_contract','advisory_contract','scan_contract','snapshot_contract','tool_bundle',
         'tool_worker','wrapper_contract','native_controls','audit_build','remediation_bundle',
         'remediation_worker','remediation_merge','remediation_contract','remediation_build','remediation_regression')
CASES=(('scan','positive'),('scan','negative'),('scan','fallback'),('extract','stripped'),
       ('extract','original'),('scan','original'),('extract','patched'),('scan','patched'),
       ('extract','upgraded'),('scan','upgraded'),('regression','upgraded'))
IDENTITY_LIMIT=262144+2*1024*1024

def variant_cases(variant):
    need(variant in ('original','patched'),'input_invalid')
    return CASES[:4]+(('extract',variant),('scan',variant),('extract','upgraded'),('scan','upgraded'))
FALSE_CLAIMS=('provider_accepted','application_accepted','vendor_accepted','vulnerability_audited',
              'reachability_verified','exploitability_verified')
REQUIRED_FINDINGS={('GO-2026-5932','golang.org/x/crypto'),('GO-2026-6860','golang.org/x/net'),
    ('GO-2026-6865','github.com/klauspost/compress'),('GO-2026-6866','golang.org/x/net'),
    ('GO-2026-6888','github.com/andybalholm/brotli')}
WRAPPER_ERRORS=frozenset(('none','unexpected','file_invalid','file_changed','build_info','build_settings','tool_lock',
    'tool_identity','tool_dependencies','capture_control','arguments','runtime','target_identity','control_identity',
    'work_directory','scanner_deadline','scanner_output','scanner_process','stripped_elf'))
CODES=frozenset(('input_invalid','input_changed','unsafe_path','hosted_linux_required','python_version',
    'package_worker_failed','package_cleanup_failed','tool_worker_failed','platform_invalid','image_invalid','container_invalid',
    'remediation_worker_failed','report_invalid','probe_failed','admission_failed','container_cleanup_failed','image_cleanup_failed','raw_cleanup_failed',
    'command_cleanup_failed','build_failed','interrupted','report_failed','tool_worker_report','tool_worker_tree',
    'tool_worker_status','build_anchor','build_files','build_flags','build_diagnostics'))
class ProbeError(Exception):
    def __init__(self,code):self.code=code if code in CODES else 'probe_failed';super().__init__(self.code)
def need(value,code):
    if not value:raise ProbeError(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
def frozen_read(p,maximum=2*1024*1024):
    need(p.is_absolute(),'unsafe_path')
    for item in (p,*p.parents):
        info=item.lstat();need(not stat.S_ISLNK(info.st_mode) and not getattr(info,'st_file_attributes',0)&0x400,'unsafe_path')
    before=p.stat();need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=maximum,'input_invalid')
    with p.open('rb') as stream:
        opened=os.fstat(stream.fileno());raw=stream.read(maximum+1);after=os.fstat(stream.fileno())
    stamp=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)
    need(len(raw)<=maximum and stamp(before)==stamp(opened)==stamp(after)==stamp(p.stat()),'input_changed')
    return raw

def load_inputs():
    raw=frozen_read(HERE/'source-pins.json',32768);need(sha(raw)==PINS_SHA,'input_changed')
    pins=json.loads(raw)
    need(type(pins) is dict and set(pins)=={'schema_version','files'} and type(pins['schema_version']) is int
         and pins['schema_version']==1 and type(pins['files']) is dict and 30<=len(pins['files'])<=70,'input_invalid')
    data={};hashes={HERE/'source-pins.json':PINS_SHA,Path(__file__):sha(frozen_read(Path(__file__),524288))}
    for name,pin in pins['files'].items():
        need(type(name) is str and re.fullmatch(r'(?:[A-Za-z0-9_-]+/)+[A-Za-z0-9_.-]+',name)
             and type(pin) is dict and set(pin)=={'bytes','sha256'} and type(pin['bytes']) is int
             and 0<pin['bytes']<=2*1024*1024 and type(pin['sha256']) is str
             and re.fullmatch('[a-f0-9]{64}',pin['sha256']),'input_invalid')
        source=HERE.parent/name;blob=frozen_read(source,pin['bytes'])
        need(len(blob)==pin['bytes'] and sha(blob)==pin['sha256'],'input_changed')
        data[name]=blob;hashes[source]=pin['sha256']
    saved={};loaded={}
    try:
        for name in MODULES:
            source=HERE/(name+'.py');key='hdfs-go-advisory-remediation/'+name+'.py'
            need(key in data,'input_invalid');saved[name]=sys.modules.get(name)
            obj=types.ModuleType(name);obj.__file__=str(source);sys.modules[name]=obj
            exec(compile(data[key],str(source),'exec'),obj.__dict__);loaded[name]=obj
        key='hdfs-cancellation-context-build/hdfs_context_build.py';need(key in data,'input_invalid')
        source=HERE.parent/key;R=types.ModuleType('audit_bound_hdfs_foundation');R.__file__=str(source)
        exec(compile(data[key],str(source),'exec'),R.__dict__)
        need(R.LABEL==LABEL,'input_changed')
        return R,loaded,data,hashes
    finally:
        for name,previous in saved.items():
            if previous is None:sys.modules.pop(name,None)
            else:sys.modules[name]=previous

def command_args(name,image,run_id,mode=None,target=None):
    identity=mode is None and target is None
    need(type(run_id) is str and re.fullmatch('[a-f0-9]{32}',run_id)
         and type(image) is str and re.fullmatch('sha256:[a-f0-9]{64}',image)
         and (identity or (mode,target) in CASES),'container_invalid')
    suffix='identity' if identity else mode+'-'+target
    need(name=='go-binary-audit-'+run_id+'-'+suffix,'container_invalid')
    command=['/bin/sh','/opt/input/driver.sh'] if identity else (['/opt/probes/remediation-regression']
        if mode=='regression' else ['/opt/probes/audit-driver',mode,target])
    return ['create','--name',name,'--label',LABEL+'='+run_id,'--network','none','--read-only',
        '--user','10001:10001','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','128',
        '--memory','2g','--cpus','2','--init','--cgroupns','private','--ipc','private','--log-driver','none',
        '--stop-timeout','5','--tmpfs','/work:'+TMPFS,'--entrypoint','/usr/bin/env',image,
        '-i','HOME=/work/home','PATH=/opt/go/bin:/usr/bin:/bin','GOMAXPROCS=2','GOMEMLIMIT=512MiB','LANG=C','LC_ALL=C',*command]

def inspect_container(value,name,image,run_id,mode=None,target=None):
    need(type(value) is dict and value.get('Name')=='/'+name and value.get('Image')==image
         and re.fullmatch('[a-f0-9]{64}',value.get('Id','')),'container_invalid')
    config,host=value.get('Config',{}),value.get('HostConfig',{})
    args=command_args(name,image,run_id,mode,target)
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
         and not host.get('Devices') and not host.get('DeviceRequests') and not host.get('ExtraHosts')
         and not host.get('PidMode'),'container_invalid')
    mounts=value.get('Mounts')
    need(type(mounts) is list and len(mounts)<=1 and all(type(m) is dict and m.get('Type')=='tmpfs'
         and m.get('Destination')=='/work' for m in mounts),'container_invalid')

def remove_owned_container(R,docker,entry,image,run_id,tag):
    R.cleanup_owned(docker,'container',entry['id'] or entry['name'],entry['id'],run_id,entry['name'],tag,image,
                    entry['cleanup_diagnostics'])
    entry['removed']=True

def execute(C,R,docker,image,run_id,tag,owned,mode=None,target=None):
    suffix='identity' if mode is None else mode+'-'+target
    name='go-binary-audit-'+run_id+'-'+suffix
    need(docker.inspect('container',name,allow_missing=True) is None,'container_invalid')
    entry=dict(name=name,id=None,removed=False,cleanup_diagnostics=dict(stage='not_attempted',error='none'))
    owned.append(entry)
    docker.call(command_args(name,image,run_id,mode,target))
    initial=docker.inspect('container',name);inspect_container(initial,name,image,run_id,mode,target)
    need(initial.get('State',{}).get('Status')=='created' and initial['State'].get('Running') is False,'container_invalid')
    entry['id']=initial['Id']
    limit=IDENTITY_LIMIT if mode is None else 65536 if mode=='regression' else 90*1024*1024
    result=docker.call(['start','--attach',entry['id']],timeout=90 if mode is None or mode=='regression' else 110,limit=limit,allow_failure=True)
    ended=docker.inspect('container',entry['id']);inspect_container(ended,name,image,run_id,mode,target)
    state=ended.get('State',{})
    need(ended['Id']==entry['id'] and state.get('Running') is False and state.get('Status')=='exited'
         and state.get('OOMKilled') is False and type(state.get('ExitCode')) is int
         and state['ExitCode']==result.code,'container_invalid')
    raw=C.read(result.stdout,limit);need(C.read(result.stderr,8388608)==b'','probe_failed')
    remove_owned_container(R,docker,entry,image,run_id,tag)
    return raw,result.code,entry['id']

def qualified_foundation(value,W):
    need(type(value) is dict and type(value.get('binaries')) is list and len(value['binaries'])==2,'report_invalid')
    need({b.get('variant') for b in value['binaries']}==set(W.TARGETS),'report_invalid')
    for b in value['binaries']:
        need((b.get('sha256'),b.get('bytes'))==W.TARGETS[b['variant']] and len(b['modules'])==242,'input_changed')
    tests=value.get('context_tests',{})
    need((tests.get('binary_sha256'),tests.get('binary_bytes'))==
        ('4b9cc4d5f84c1467e92828961e8e521251dd1b93032bc911489dc83d7cebb645',12025580),'input_changed')

def wrapper_diagnostics(C,raw):
    result=dict(parseable=False,error='unavailable',capture_controls=None,duration_ms=None)
    try:
        value=C.parse(raw,90*1024*1024)
        if type(value) is not dict:return result
        result['parseable']=True
        if type(value.get('error')) is str and value['error'] in WRAPPER_ERRORS:result['error']=value['error']
        for key,maximum in [('capture_controls',9),('duration_ms',120000)]:
            if type(value.get(key)) is int and 0<=value[key]<=maximum:result[key]=value[key]
    except BaseException:pass
    return result

def failure_diagnostics(error,modules):
    code=getattr(error,'code',None);admission=None
    contract=modules.get('audit_contract') if modules else None
    if contract is not None and isinstance(error,contract.ContractError):
        if type(code) is str and re.fullmatch('[a-z0-9_]{1,80}',code):admission=code
    category='unexpected'
    for kind,label in ((ProbeError,'probe_error'),(ValueError,'value_error'),(KeyError,'key_error'),
                       (TypeError,'type_error'),(AttributeError,'attribute_error'),(OSError,'io_error')):
        if isinstance(error,kind):category=label;break
    frames=[];trace=error.__traceback__;depth=0
    while trace is not None and depth<64:
        source=Path(trace.tb_frame.f_code.co_filename)
        if source.parent==HERE and 1<=trace.tb_lineno<=10000:frames.append(dict(file=source.name,line=trace.tb_lineno))
        trace=trace.tb_next;depth+=1
    number=getattr(error,'errno',None)
    return dict(category=category,admission_code=admission,
                errno=number if type(number) is int and 1<=number<=255 else None,frames=frames[-8:])

def run(variant):
    began=time.monotonic()
    report=dict(schema_version=1,scope='isolated_go_dependency_remediation_comparison',variant=variant,success=False,
        started_utc=datetime.now(timezone.utc).isoformat(),finished_utc=None,duration_seconds=None,stage='preflight',
        inputs=None,snapshot=None,binary_identity=None,tool_preparation=None,tool_worker_diagnostics=None,
        foundation_worker_diagnostics=None,test_diagnostics=None,build_diagnostics=None,failure_diagnostics=None,
        remediation_preparation=None,remediation_worker_diagnostics=None,remediation_cache_merge=None,upgraded_identity=None,benign_regressions=None,advisory_comparison=None,
        native_diagnostics=[],wrappers=[],controls=[],stripped_control=None,extractions=[],scans=[],errors=[],
        cleanup=dict(containers_removed=False,image_removed=False,context_removed=False,raw_evidence_removed=False),
        cleanup_diagnostics=dict(containers=[],image=dict(stage='not_attempted',error='none')),
        cleanup_excludes=['shared_base_image','shared_build_cache'],
        coverage_limits=['local_main_version_requires_upstream_release_review',
            'local_hdfs_replacement_requires_conservative_upstream_proxy','binary_symbols_do_not_prove_reachability',
            'chi_publisher_advisory_absent_from_curated_snapshot'],
        **dict.fromkeys(FALSE_CLAIMS,False))
    C=R=B=D=docker=root=context=root_id=context_id=image=None
    modules={};source_hashes={};owned=[];built_attempted=False
    run_id=uuid.uuid4().hex;tag='go-binary-audit-'+run_id;old_umask=os.umask(0o077)
    try:
        need(variant in ('original','patched'),'input_invalid')
        R,modules,data,source_hashes=load_inputs();C=R.load_support();C.hosted_guard()
        need(sys.version_info[:2]==(3,14),'python_version')
        B=R.load_bundle(C);D,helper_hashes=C.load_helpers()
        need(all(source_hashes.get(p)==h for p,h in helper_hashes.items()),'input_changed')
        need(source_hashes.get(R.SUPPORT)==R.SUPPORT_SHA
             and source_hashes.get(R.ASSETS_HOME/'rclone_build_bundle.py')==R.BUNDLE_SHA,'input_changed')
        A=modules['audit_contract'];T=modules['tool_bundle'];TW=modules['tool_worker'];W=modules['wrapper_contract']
        N=modules['native_controls'];S=modules['snapshot_contract'];SC=modules['scan_contract'];AB=modules['audit_build']
        RB=modules['remediation_bundle'];RW=modules['remediation_worker'];RM=modules['remediation_merge']
        RC=modules['remediation_contract'];RBUILD=modules['remediation_build'];REG=modules['remediation_regression']
        get=lambda name:data['hdfs-go-advisory-remediation/'+name]
        lock_raw=C.read(R.ASSETS_HOME/'assets-lock.json',1048576);lock=B.load_lock(lock_raw)
        tool_lock_raw=get('tool-assets-lock.json');tool_lock=T.load_lock(tool_lock_raw)
        pin=S.parse_json(get('advisory-snapshot-pin.json'))
        snapshot,db_files,records,index=S.decode_snapshot(get('advisory-snapshot.json.gz'),pin)
        report['snapshot']=snapshot
        need({x[0] for x in REQUIRED_FINDINGS}==set(pin['known_ids']),'input_invalid')
        go_sources={name:C.read(p,131072) for name,p in R.SOURCES.items()}
        need(all(source_hashes.get(R.SOURCES[name])==sha(raw) for name,raw in go_sources.items()),'input_changed')
        report['inputs']=dict(source_sha256={p.relative_to(HERE.parent).as_posix():h for p,h in source_hashes.items()},
            base_manifest=C.BASE,base_config_id=C.BASE_ID,foundation_assets=len(lock['assets']),
            foundation_asset_bytes=sum(r['bytes'] for r in lock['assets']),tool_assets=34,
            toolchain='go1.26.10',rclone_source_version='v1.75.2',analyzer_source_version=T.VERSION,
            analyzer_origin=T.ORIGIN,context_sha256=None,image_id=None,containers=[],docker_calls=None)
        need(shutil.disk_usage('/tmp').free>=12*1024**3,'unsafe_path')
        root=Path(tempfile.mkdtemp(prefix='rclone-usage-'+run_id+'-',dir='/tmp'));root_id=C.directory(root)
        context=root/'context';context.mkdir(mode=0o700);context_id=C.directory(context)
        report['stage']='foundation_assets'
        R.prepare_packages(C,B,context);report['foundation_worker_diagnostics']=R.read_worker_status(C,context)
        need(report['foundation_worker_diagnostics']['phase']=='complete','package_worker_failed')
        report['stage']='analyzer_assets';tool_root=context/'audit-tool';tool_root.mkdir(mode=0o700)
        tool_lock,prepared,status=TW.prepare_owned(C,R,B,tool_root,Path(__file__),tool_lock_raw)
        report['tool_preparation']=prepared;report['tool_worker_diagnostics']=status
        (tool_root/'tool-assets-lock.json').write_bytes(tool_lock_raw)
        report['stage']='remediation_assets';remediation_root=context/'remediation';remediation_root.mkdir(mode=0o700)
        remediation_lock,prepared,status,prepared_tree=RW.prepare_owned(C,R,B,remediation_root,Path(__file__),get('remediation-assets-lock.json'))
        report['remediation_preparation']=prepared;report['remediation_worker_diagnostics']=status
        report['remediation_cache_merge']=RM.merge_prepared(C,R,B,context,remediation_root,remediation_lock,prepared_tree)
        report['stage']='stage_context'
        report['inputs']['hdfs_source']=R.stage_hdfs(C,B,context,lock,go_sources)
        original_mod=C.read(context/'original/go.mod',131072);original_sum=C.read(context/'original/go.sum',131072)
        overlay=RB.overlay_files(remediation_lock,original_mod,original_sum,get('upgraded-rclone.mod'),get('upgraded-rclone.sum'),variant)
        catalog=RB.source_catalog(lock,remediation_lock)
        metadata=[original_mod,overlay['upgraded-rclone.mod']]
        for asset_lock,asset_root in ((lock,context),(remediation_lock,remediation_root)):
            for row in asset_lock['assets']:
                if row['kind']=='mod':
                    raw=C.read(asset_root/'assets'/row['file'],2*1024*1024);B.verify_asset(raw,row);metadata.append(raw)
        known={(row['module'],row['version']) for asset_lock in (lock,remediation_lock)
               for row in asset_lock['assets'] if row['kind'] in ('mod','zip','info')}
        diagnostic_coordinates=RBUILD.diagnostic_coordinates(metadata,known)
        build=RBUILD.extend_build(AB.extend_build(R.build_files(C,go_sources,original_mod,original_sum)),variant)
        control_files,blobs,_,_=N.fixture()
        additions={**go_sources,**build,**overlay,'audit_driver.go':get('audit_driver.go'),
                   'remediation_driver.go':get('remediation_driver.go'),'remediation_regression.go':get('remediation_regression.go'),
                   'resolver_diagnostics.go':get('resolver_diagnostics.go'),
                   'remediation-coordinate-pins.json':canonical([dict(module=m,version=v) for m,v in sorted(diagnostic_coordinates)]),**control_files,
                   **{'advisories/'+p:raw for p,raw in db_files.items()}}
        for filename,raw in additions.items():
            target=context/filename;target.parent.mkdir(parents=True,exist_ok=True)
            with target.open('xb') as stream:stream.write(raw)
        report['stage']='hash_context';before=R.tree_hashes(C,context)
        (context/'checksums').write_bytes(R.checksum_manifest(before))
        context_hashes=R.tree_hashes(C,context);report['inputs']['context_sha256']=sha(canonical(context_hashes))
        report['inputs']['context_files']=len(context_hashes)
        docker=D.Docker(root,max_calls=120)
        host=C.parse(C.read(docker.call(['info','--format','{{json .}}']).stdout,1048576))
        need(host.get('OSType')=='linux' and host.get('Architecture') in ('amd64','x86_64'),'platform_invalid')
        report['stage']='base';docker.call(['image','pull','--quiet','--platform','linux/amd64',C.BASE],timeout=120)
        base=docker.inspect('image',C.BASE);report['base_observation']=C.base_observation(base,C.BASE,C.BASE_ID);C.validate_base(base,C.BASE,C.BASE_ID)
        need(docker.inspect('image',tag,allow_missing=True) is None,'image_invalid')
        report['stage']='build';built_attempted=True
        compiled=docker.call(['build','--network','none','--pull=false','--label',LABEL+'='+run_id,'--tag',tag,str(context)],
                            timeout=630,limit=4194304,allow_failure=True)
        report['build_diagnostics']=RBUILD.diagnostics(R,C.read(compiled.stdout,4194304)+C.read(compiled.stderr,4194304),diagnostic_coordinates)
        need(compiled.code==0,'build_failed')
        built=docker.inspect('image',tag);image=built.get('Id')
        need(type(image) is str and re.fullmatch('sha256:[a-f0-9]{64}',image)
             and built.get('Config',{}).get('Labels',{}).get(LABEL)==run_id
             and built.get('Config',{}).get('User')=='10001:10001','image_invalid')
        need(R.tree_hashes(C,context)==context_hashes,'input_changed');report['inputs']['image_id']=image
        report['stage']='foundation_identity'
        raw,code,container=execute(C,R,docker,image,run_id,tag,owned)
        report['inputs']['containers'].append(dict(kind='foundation',id=container))
        foundation_raw,upgraded_raw=RC.identity_stream(raw)
        report['test_diagnostics']=R.native_test_diagnostics(C,foundation_raw)
        native=R.validate_native(C,foundation_raw,code,lock);qualified_foundation(native,W);report['binary_identity']=native
        binaries={b['variant']:b for b in native['binaries']};tool=None;extracted={}
        upgraded=RC.admit_identity(upgraded_raw,variant,catalog,overlay,binaries[variant]);report['upgraded_identity']=upgraded
        identities={variant:W.extraction_identity(binaries[variant]),'upgraded':RC.extraction_identity(upgraded)}
        for mode,target in variant_cases(variant):
            report['stage']=mode+'_'+target
            raw,code,container=execute(C,R,docker,image,run_id,tag,owned,mode,target)
            report['inputs']['containers'].append(dict(kind='analyzer',mode=mode,target=target,id=container))
            report['native_diagnostics'].append(dict(mode=mode,target=target,diagnostics=wrapper_diagnostics(C,raw)))
            if target in ('positive','negative','fallback'):
                expected=dict(file=dict(sha256=sha(blobs[target]),bytes=len(blobs[target])))
            elif target=='stripped':
                peek=C.parse(raw,90*1024*1024)
                need(type(peek) is dict and 'target_before' in peek,'report_invalid')
                expected=dict(file=W.stamp(peek['target_before']),modules=W.runtime_modules(binaries['original']))
            elif target=='upgraded':expected=RC.wrapper_target(upgraded)
            else:
                expected=W.expected_target(binaries[target])
            wrapper,stdout,stderr=W.admit_wrapper(raw,mode,target,expected,tool_lock,code,tool)
            if tool is None:tool=wrapper['tool']
            report['wrappers'].append(wrapper)
            if target in ('positive','negative','fallback'):
                report['controls'].append(N.validate_native(target,stdout,wrapper['exit_code'],stderr))
            elif target=='stripped':
                report['stripped_control']=N.validate_stripped(stdout,W.extraction_identity(binaries['original']))
            elif mode=='extract':
                summary,_=A.admit_extraction(stdout,identities[target])
                report['extractions'].append(dict(variant=target,result=summary));extracted[target]=stdout
            else:
                required={('GO-2026-5932','golang.org/x/crypto')} if target=='upgraded' else REQUIRED_FINDINGS
                summary=SC.admit_scan(stdout,extracted[target],identities[target],
                    N.config('file:///opt/input/advisories',snapshot['database_modified']),
                    records,index,required,wrapper['exit_code'],stderr)
                if target!='upgraded':need(summary['osv_messages']==361 and summary['unique_osv_ids']==334,'report_invalid')
                report['scans'].append(dict(variant=target,result=summary))
        need(len(report['controls'])==3 and report['stripped_control']['success'] is True
             and len(report['extractions'])==2 and len(report['scans'])==2 and len(report['wrappers'])==8,'report_invalid')
        scan_map={row['variant']:row['result'] for row in report['scans']}
        report['advisory_comparison']=RC.compare_scans(scan_map[variant],scan_map['upgraded'])
        report['stage']='benign_regressions'
        raw,code,container=execute(C,R,docker,image,run_id,tag,owned,'regression','upgraded')
        report['inputs']['containers'].append(dict(kind='regression',id=container))
        report['benign_regressions']=REG.admit(raw,variant,upgraded,code)
        need(R.tree_hashes(C,context)==context_hashes,'input_changed')
        report['success']=True;report['stage']='completed'
    except KeyboardInterrupt:report['errors'].append('interrupted')
    except BaseException as error:
        report['failure_diagnostics']=failure_diagnostics(error,modules)
        code=getattr(error,'code',None)
        report['errors'].append(code if code in CODES else 'admission_failed' if report['failure_diagnostics']['admission_code'] else 'probe_failed')
        if context is not None and C is not None:
            if report['foundation_worker_diagnostics'] is None and R is not None:
                try:report['foundation_worker_diagnostics']=R.read_worker_status(C,context)
                except BaseException:pass
            if report['tool_worker_diagnostics'] is None and 'tool_worker' in modules:
                try:report['tool_worker_diagnostics']=modules['tool_worker'].validate_status(C.parse(C.read(context/'audit-tool/worker-status.json',2048),2048))
                except BaseException:pass
    finally:
        try:
            for entry in reversed(owned):
                if not entry['removed']:remove_owned_container(R,docker,entry,image,run_id,tag)
            report['cleanup']['containers_removed']=True
        except BaseException as error:
            if getattr(error,'code',None)=='command_cleanup_failed':report['errors'].append('command_cleanup_failed')
            report['errors'].append('container_cleanup_failed')
        report['cleanup_diagnostics']['containers']=[dict(name=e['name'],removed=e['removed'],**e['cleanup_diagnostics']) for e in owned]
        try:
            if built_attempted:
                need(report['cleanup']['containers_removed'],'image_cleanup_failed')
                R.cleanup_owned(docker,'image',image or tag,image,run_id,None,tag,image,report['cleanup_diagnostics']['image'])
            report['cleanup']['image_removed']=True
        except BaseException as error:
            if getattr(error,'code',None)=='command_cleanup_failed':report['errors'].append('command_cleanup_failed')
            report['errors'].append('image_cleanup_failed')
        try:
            for p,expected in source_hashes.items():need(sha(frozen_read(p))==expected,'input_changed')
        except BaseException:report['errors'].append('input_changed')
        safe=report['cleanup']['containers_removed'] and report['cleanup']['image_removed']
        safe=safe and not {'command_cleanup_failed','package_cleanup_failed'}.intersection(report['errors'])
        try:
            if root is not None:
                need(safe,'raw_cleanup_failed');C.directory(root,root_id)
                if context is not None:
                    C.directory(context,context_id);R.tree_hashes(C,context)
                    shutil.rmtree(context);need(not context.exists(),'raw_cleanup_failed')
            report['cleanup']['context_removed']=True
            if root is not None:
                total=0
                for count,p in enumerate(root.rglob('*'),1):
                    need(count<=1000 and not p.is_symlink(),'unsafe_path')
                    if p.is_dir():C.directory(p)
                    else:
                        total+=C.regular(p,90*1024*1024).st_size
                        need(total<=2*1024**3,'raw_cleanup_failed')
                shutil.rmtree(root);need(not root.exists(),'raw_cleanup_failed')
            report['cleanup']['raw_evidence_removed']=True
        except BaseException:report['errors'].append('raw_cleanup_failed')
        if docker is not None and report['inputs'] is not None:report['inputs']['docker_calls']=docker.calls
        os.umask(old_umask)
    report['success']=report['success'] and not report['errors'] and all(report['cleanup'].values())
    report['finished_utc']=datetime.now(timezone.utc).isoformat();report['duration_seconds']=round(time.monotonic()-began,3)
    return report

def main(argv=None):
    args=sys.argv[1:] if argv is None else argv
    if args and args[0] in ('--tool-worker','--remediation-worker'):
        try:
            need(len(args)==5,'input_invalid')
            R,modules,data,_=load_inputs();C=R.load_support();C.hosted_guard();B=R.load_bundle(C)
            worker,lock_name=('tool_worker','tool-assets-lock.json') if args[0]=='--tool-worker' else ('remediation_worker','remediation-assets-lock.json')
            modules[worker].worker(C,R,B,Path(args[1]),(int(args[2]),int(args[3])),Path(__file__),args[4],
                                  data['hdfs-go-advisory-remediation/'+lock_name])
            return 0
        except BaseException:return 1
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--report',type=Path,required=True)
    parser.add_argument('--variant',choices=('original','patched'),required=True)
    args=parser.parse_args(args)
    previous=signal.getsignal(signal.SIGTERM);signal.signal(signal.SIGTERM,lambda *_:(_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        R,_,_,_=load_inputs();C=R.load_support();C.hosted_guard();need(args.report.is_absolute(),'unsafe_path')
        for parent in args.report.parents:C.directory(parent)
        fd=os.open(args.report,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
        with os.fdopen(fd,'wb') as stream:
            result=run(args.variant);raw=canonical(result)+b'\n';need(len(raw)<=4*1024*1024,'report_failed')
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
        return 0 if result['success'] else 1
    except BaseException:sys.stderr.write('isolated_go_binary_audit_failed\n');return 1
    finally:signal.signal(signal.SIGTERM,previous)

if __name__=='__main__':raise SystemExit(main())
