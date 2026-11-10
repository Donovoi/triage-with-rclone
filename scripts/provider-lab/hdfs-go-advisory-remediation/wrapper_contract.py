"""Admit bounded native wrapper evidence before reading scanner streams."""
from __future__ import annotations
import base64,binascii,hashlib,json,re
from audit_contract import ContractError,need,unique,nonfinite,text_value
from tool_bundle import validate_lock,LOCK_SHA,TOOL,VERSION,ORIGIN

MAX_WRAPPER_BYTES=90*1024*1024
MAX_STDOUT_BYTES=64*1024*1024
TARGETS={'original':('37ef48307cbaae684126fe8e2f5d6ca3717fce679fd36c34fc4ba584295ea0d3',119830724),
         'patched':('8c72cfd7f7a8f0a7e62c7f527155e0e55bb391cf8bffdb1ada6009416d74e27b',119848207)}
FIELDS={'schema_version','success','error','mode','target','tool','target_before','target_after','target_identity','stripped_evidence',
        'tool_unchanged','target_unchanged','exit_code','timed_out','wait_delay_exceeded','stdout_overflow','stderr_overflow',
        'stdout_base64','stderr_base64','stdout_sha256','stderr_sha256','capture_controls','duration_ms',
        'vulnerability_audit_completed','provider_accepted'}

def stamp(value):
    need(type(value) is dict and set(value)=={'sha256','bytes'}
        and type(value['sha256']) is str and re.fullmatch('[a-f0-9]{64}',value['sha256'])
        and type(value['bytes']) is int and 0<value['bytes']<=256*1024*1024,'wrapper_stamp')
    return value

def binary(value,path,main):
    need(type(value) is dict and set(value)=={'file','go_version','path','main','settings','modules'},'wrapper_binary')
    stamp(value['file'])
    need(value['go_version']=='go1.26.10' and value['path']==path,'wrapper_binary_identity')
    need(type(value['main']) is dict and set(value['main'])=={'path','version','sum','replacement'}
         and value['main']['path']==main and value['main']['version'] in ('','(devel)')
         and value['main']['sum']==value['main']['replacement']=='','wrapper_main')
    settings=value['settings'];need(type(settings) is dict and len(settings)<=64
        and all(text_value(k,256) and text_value(v,4096,True) for k,v in settings.items()),'wrapper_settings')
    need(all(settings.get(k)==v for k,v in dict(GOOS='linux',GOARCH='amd64',CGO_ENABLED='0').items())
         and settings.get('-buildmode')=='exe' and settings.get('-trimpath')=='true'
         and not any(k=='vcs' or k.startswith('vcs.') for k in settings),'wrapper_settings')
    rows=value['modules'];need(type(rows) is list and 0<len(rows)<=4096,'wrapper_modules')
    names=[]
    for row in rows:
        need(type(row) is dict and set(row)=={'path','version','sum','replacement'}
             and all(text_value(v,4096,True) for v in row.values()) and row['path'],'wrapper_module')
        names.append(row['path'])
    need(names==sorted(set(names)),'wrapper_modules')
    return value

def decode(value,maximum):
    need(type(value) is str and len(value)<=4*((maximum+2)//3),'wrapper_base64')
    try:raw=base64.b64decode(value,validate=True)
    except (ValueError,binascii.Error):raise ContractError('wrapper_base64') from None
    need(len(raw)<=maximum and base64.b64encode(raw).decode('ascii')==value,'wrapper_base64')
    return raw

def admit_wrapper(raw,mode,target,expected_target,lock,exit_code,expected_tool=None):
    validate_lock(lock)
    need(type(raw) is bytes and 0<len(raw)<=MAX_WRAPPER_BYTES,'wrapper_size')
    try:value=json.loads(raw,object_pairs_hook=unique,parse_constant=nonfinite)
    except (ValueError,UnicodeError,RecursionError):raise ContractError('wrapper_json') from None
    need(type(value) is dict and set(value)==FIELDS,'wrapper_shape')
    need(type(value['schema_version']) is int and value['schema_version']==1
         and value['success'] is True and value['error']=='none','wrapper_success')
    need(mode in ('extract','scan') and target in ('original','patched','upgraded','stripped','positive','negative','fallback')
         and not(mode=='extract' and target in ('positive','negative','fallback'))
         and not(mode=='scan' and target=='stripped')
         and value['mode']==mode and value['target']==target,'wrapper_case')
    need(type(exit_code) is int and exit_code==0 and type(value['exit_code']) is int and value['exit_code']==0
         and all(value[k] is False for k in ('timed_out','wait_delay_exceeded','stdout_overflow','stderr_overflow',
                                           'vulnerability_audit_completed','provider_accepted'))
         and value['tool_unchanged'] is True and value['target_unchanged'] is True,'wrapper_process')
    need(type(value['capture_controls']) is int and value['capture_controls']==9
         and type(value['duration_ms']) is int and 0<=value['duration_ms']<=95000,'wrapper_controls')
    before=stamp(value['target_before']);after=stamp(value['target_after'])
    need(before==after==expected_target['file'],'wrapper_target_binding')
    if target in TARGETS:
        need((before['sha256'],before['bytes'])==TARGETS[target],'wrapper_target_identity')
    if target in ('original','patched','upgraded','stripped'):
        identity=binary(value['target_identity'],'github.com/rclone/rclone','github.com/rclone/rclone')
        need(identity['file']==before and identity['modules']==expected_target['modules'],'wrapper_target_graph')
        if target=='upgraded':need(1024*1024<=before['bytes']<=256*1024*1024,'wrapper_target_identity')
        if target=='stripped':
            evidence=value['stripped_evidence']
            need(1024*1024<=before['bytes']<TARGETS['original'][1]
                 and '-ldflags' not in identity['settings']
                 and type(evidence) is dict and set(evidence)=={'format','sha256','bytes','symbol_table_absent',
                     'string_table_absent','dwarf_sections_absent','pcln_present'}
                 and evidence['format']=='ELF64-little-x86_64' and evidence['sha256']==before['sha256']
                 and type(evidence['bytes']) is int and evidence['bytes']==before['bytes']
                 and all(evidence[k] is True for k in ('symbol_table_absent','string_table_absent',
                                                      'dwarf_sections_absent','pcln_present')),
                 'wrapper_stripped_identity')
    else:need(value['target_identity'] is None and before['bytes']<16384,'wrapper_synthetic_identity')
    if target!='stripped':need(value['stripped_evidence'] is None,'wrapper_unexpected_stripping')
    tool=value['tool']
    need(type(tool) is dict and set(tool)=={'binary','source_version','source_origin','lock_sha256'}
         and tool['source_version']==VERSION and tool['source_origin']==ORIGIN and tool['lock_sha256']==LOCK_SHA,'wrapper_tool')
    identity=binary(tool['binary'],TOOL+'/cmd/govulncheck',TOOL)
    need(1024*1024<=identity['file']['bytes']<=64*1024*1024,'wrapper_tool')
    allowed={r['module']:dict(path=r['module'],version=r['version'],sum=r['h1'],replacement='')
             for r in lock['assets'] if r['kind']=='zip' and r['module']!=TOOL}
    need(all(allowed.get(r['path'])==r for r in identity['modules'])
         and {'golang.org/x/mod','golang.org/x/tools'}<=set(r['path'] for r in identity['modules']),'wrapper_tool_graph')
    if expected_tool is not None:need(tool==expected_tool,'wrapper_tool_changed')
    stdout=decode(value['stdout_base64'],MAX_STDOUT_BYTES);stderr=decode(value['stderr_base64'],16384)
    need(stdout and not stderr and hashlib.sha256(stdout).hexdigest()==value['stdout_sha256']
         and hashlib.sha256(stderr).hexdigest()==value['stderr_sha256'],'wrapper_stream_binding')
    summary={k:v for k,v in value.items() if k not in ('stdout_base64','stderr_base64')}
    summary.update(scope='contained_go_scanner_invocation',stdout_bytes=len(stdout),stderr_bytes=len(stderr))
    return summary,stdout,stderr

def runtime_modules(native_binary):
    """Translate only the foundation's closed HDFS marker to its checked path."""
    need(type(native_binary) is dict and native_binary.get('variant') in TARGETS,'expected_binary')
    variant=native_binary['variant']
    need((native_binary.get('sha256'),native_binary.get('bytes'))==TARGETS[variant],'expected_binary')
    rows=native_binary.get('modules')
    need(type(rows) is list and 0<len(rows)<=4096,'expected_binary_modules')
    output=[];replacements=0
    for row in rows:
        need(type(row) is dict and set(row)=={'path','version','sum','replacement'},'expected_binary_module')
        mapped=dict(row)
        if row['replacement']:
            need(variant=='patched' and row['path']=='github.com/colinmarc/hdfs/v2'
                 and row['version']=='v2.4.0' and row['sum']=='' and row['replacement']=='context-cancellation',
                 'expected_binary_replacement')
            mapped['replacement']='/opt/input/patched-hdfs';replacements+=1
        output.append(mapped)
    need(replacements==(1 if variant=='patched' else 0),'expected_binary_replacement')
    need([r['path'] for r in output]==sorted({r['path'] for r in output}),'expected_binary_modules')
    return output

def expected_target(native_binary):
    rows=runtime_modules(native_binary)
    return dict(file=dict(sha256=native_binary['sha256'],bytes=native_binary['bytes']),modules=rows)

def extraction_identity(native_binary):
    rows=runtime_modules(native_binary)
    return dict(path='github.com/rclone/rclone',go_version='go1.26.10',goos='linux',goarch='amd64',
        main_versions=['','(devel)'],
        modules=[dict(path=r['path'],version=r['version'],
                      replacement=None if not r['replacement'] else dict(path=r['replacement'],versions=['','(devel)'])) for r in rows])
