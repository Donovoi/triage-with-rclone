"""Admission for complete, snapshot-bound binary scanner JSON streams."""
from __future__ import annotations
from collections import Counter
import hashlib,json,re
from audit_contract import ContractError,need,unique,nonfinite,text_value,admit_extraction,MAX_EXTRACT_BYTES
from advisory_contract import project_osv

def scan_messages(raw):
    need(type(raw) is bytes and 0<len(raw)<=MAX_EXTRACT_BYTES,'scan_size')
    try:text=raw.decode('utf-8','strict')
    except UnicodeError:raise ContractError('scan_encoding') from None
    decoder=json.JSONDecoder(object_pairs_hook=unique,parse_constant=nonfinite)
    values=[];offset=0
    while offset<len(text):
        while offset<len(text) and text[offset] in ' \t\r\n':offset+=1
        if offset==len(text):break
        need(len(values)<100000,'scan_message_limit')
        try:value,offset=decoder.raw_decode(text,offset)
        except (ValueError,RecursionError):raise ContractError('scan_json') from None
        need(type(value) is dict and len(value)==1,'scan_message_shape')
        values.append(value)
    need(len(values)>=2,'scan_message_count')
    return values

def effective(module):
    return module['Replace'] if module['Replace'] is not None else module

def sbom_module(module):
    out={'path':module['Path']}
    if module['Version']:out['version']=module['Version']
    return out

def expected_sbom(body):
    return {'go_version':body['goVersion'],'roots':[body['main']['Path']],
        'modules':[sbom_module(body['main']),*[sbom_module(effective(x)) for x in body['modules']],
                   {'path':'stdlib','version':body['goVersion']}]}

def admit_scan(raw,extraction_raw,identity,config,snapshot,index,required_module_findings,exit_code,stderr):
    need(type(exit_code) is int and exit_code==0 and stderr==b'','scan_process')
    extraction,body=admit_extraction(extraction_raw,identity)
    need(type(config) is dict and config.get('protocol_version')=='v1.0.0'
         and config.get('scan_mode')=='binary' and config.get('scan_level')=='symbol','scan_expected_config')
    need(type(snapshot) is dict and type(index) is dict,'snapshot_shape')
    messages=scan_messages(raw)
    need(messages[0]=={'config':config},'scan_config')
    expected_book=expected_sbom(body)
    actual_modules=[body['main'],*[effective(x) for x in body['modules']]]
    lookup_paths=[m['Path'] for m in actual_modules]+['stdlib']
    need(len(lookup_paths)==len(set(lookup_paths)),'scan_module_collision')
    expected_counts=Counter(ident for name in lookup_paths for ident in index.get(name,[]))
    need(all(ident in snapshot for ident in expected_counts),'snapshot_missing_record')
    need(re.fullmatch(r'go\d+\.\d+\.\d+',body['goVersion']) is not None,'scan_stdlib_version')
    versions={m['Path']:m['Version'] for m in actual_modules}
    versions['stdlib']='v'+body['goVersion'][2:]
    symbol_set={(body['path'] if s.get('pkg')=='main' else s.get('pkg',''),s['name']) for s in body['pkgSymbols']}
    package_set={p for p,_ in symbol_set if p}
    counts=Counter();seen_sbom=0;findings=[];omissions=[];progress=0
    for message in messages[1:]:
        key=next(iter(message));value=message[key]
        if key=='SBOM':
            need(value==expected_book and seen_sbom==0,'scan_sbom')
            seen_sbom+=1
        elif key=='progress':
            need(type(value) is dict and set(value)<={'time','message'}
                 and ('message' not in value or text_value(value['message'],16384,True))
                 and ('time' not in value or text_value(value['time'],128)),'scan_progress')
            progress+=1
        elif key=='osv':
            need(type(value) is dict and value.get('id') in expected_counts,'scan_osv_id')
            ident=value['id'];expected=project_osv(snapshot[ident],omissions)
            need(project_osv(value)==value and value==expected,'scan_osv_content')
            counts[ident]+=1
            need(counts[ident]<=expected_counts[ident],'scan_osv_multiplicity')
        elif key=='finding':
            findings.append(value)
            need(len(findings)<=50000,'scan_finding_limit')
        else:need(False,'scan_unknown_message')
    need(seen_sbom==1,'scan_sbom_missing')
    need(counts==expected_counts,'scan_osv_completeness')
    output=[];module_findings=set()
    for finding in findings:
        need(type(finding) is dict and set(finding)<={'osv','fixed_version','trace'}
             and set(finding)>={'osv','trace'},'finding_shape')
        ident=finding['osv'];need(type(ident) is str and ident in expected_counts,'finding_osv')
        fixed=finding.get('fixed_version','');need(text_value(fixed,256,True),'finding_fixed_version')
        trace=finding['trace'];need(type(trace) is list and len(trace)==1,'finding_trace')
        frame=trace[0]
        need(type(frame) is dict and set(frame)<={'module','version','package','function','receiver'}
             and 'module' in frame,'finding_frame')
        need(all(text_value(v,4096,True) for v in frame.values()),'finding_text')
        module=frame['module'];version=frame.get('version','')
        need(module in versions and version==versions[module],'finding_module')
        affected=[a for a in snapshot[ident]['affected'] if a['package']['name']==module]
        need(bool(affected),'finding_module_advisory')
        package=frame.get('package','');function=frame.get('function','');receiver=frame.get('receiver','')
        need(not receiver or function,'finding_receiver')
        need(not function or package,'finding_function')
        level='module'
        if package:
            level='package';need(package in package_set,'finding_package_absent')
            if '.' not in package.split('/')[0]:owner='stdlib'
            else:
                candidates=[m for m in [body['main'],*body['modules']] if package==m['Path'] or package.startswith(m['Path']+'/')]
                need(bool(candidates),'finding_package_owner')
                owner=effective(max(candidates,key=lambda m:len(m['Path'])))['Path']
            need(owner==module,'finding_package_owner')
            if function:
                level='symbol';symbol=(receiver+'.' if receiver else '')+function
                need((package,symbol) in symbol_set,'finding_symbol_absent')
        else:module_findings.add((ident,module))
        output.append({'id':ident,'level':level,'module':module,'version':version,'package':package,
                       'function':function,'receiver':receiver,'fixed_version':fixed})
    need(set(required_module_findings)<=module_findings,'scan_positive_controls_missing')
    # Every higher-precision finding must retain its module-level evidence.
    need(all((x['id'],x['module']) in module_findings for x in output),'scan_finding_hierarchy')
    canonical=lambda x:json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
    unique_findings={canonical(x):x for x in output}
    ordered=[unique_findings[k] for k in sorted(unique_findings)]
    custom={canonical(x):x for x in omissions}
    return {'schema_version':1,'scope':'go_binary_advisory_observations','success':True,
        'raw_sha256':hashlib.sha256(raw).hexdigest(),'raw_bytes':len(raw),'scanner_config':config,
        'extraction':extraction,'sbom_sha256':hashlib.sha256(canonical(expected_book)).hexdigest(),
        'osv_messages':sum(counts.values()),'unique_osv_ids':len(counts),
        'osv_multiplicities':dict(sorted(counts.items())),'progress_messages':progress,
        'finding_messages':len(findings),'unique_findings':len(ordered),
        'findings_by_level':{level:sum(x['level']==level for x in ordered) for level in ('module','package','symbol')},
        'findings':ordered,'custom_ranges_omitted_by_scanner':[custom[k] for k in sorted(custom)],
        'required_module_controls':len(set(required_module_findings)),
        'reachability_verified':False,'exploitability_verified':False,
        'vulnerability_audit_completed':False,'provider_accepted':False}
