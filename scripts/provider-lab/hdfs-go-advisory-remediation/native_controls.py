"""Synthetic native scanner controls, kept separate from the frozen advisory DB."""
from __future__ import annotations
import hashlib,json
from audit_contract import ContractError,admit_extraction,admit_metadata,need
from scan_contract import admit_scan

ID='GO-2099-0001'
DATE='2099-01-01T00:00:00Z'
MODULE='example.test/audit-control'
MAIN='example.test/audit-main'
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n'
def module(name,version):
    return dict(Path=name,Version=version,Replace=None,Time=None,Main=False,Indirect=False,Dir='',GoMod='',GoVersion='',Error=None)
def fixture():
    record={'schema_version':'1.7.0','id':ID,'modified':DATE,'published':DATE,
        'summary':'Synthetic scanner control; not a published vulnerability.',
        'details':'Only tests the pinned scanner against a separate artificial database.',
        'affected':[{'package':{'name':MODULE,'ecosystem':'Go'},
            'ranges':[{'type':'SEMVER','events':[{'introduced':'1.0.0'},{'fixed':'1.0.1'}]}],
            'ecosystem_specific':{'imports':[{'path':MODULE,'goos':['linux'],'goarch':['amd64'],'symbols':['Problem']}]}}]}
    expected=dict(path=MAIN,go_version='go1.26.10',goos='linux',goarch='amd64',
        main_versions=['v1.0.0'],modules=[dict(path=MODULE,version='v1.0.0',replacement=None)])
    metadata=dict(path=MAIN,main=module(MAIN,'v1.0.0'),modules=[module(MODULE,'v1.0.0')],
        goVersion='go1.26.10',goos='linux',goarch='amd64')
    blobs={}
    for case,symbols in [('positive',['Problem']),('negative',['Safe']),('fallback',[])]:
        body=dict(metadata,pkgSymbols=[dict(pkg=MODULE,name=s) for s in symbols])
        blobs[case]=canonical(dict(name='govulncheck-extract',version='0.1.0'))+canonical(body)
    files={'control-db/index/db.json':canonical(dict(modified=DATE)),
        'control-db/index/modules.json':canonical([dict(path=MODULE,vulns=[dict(id=ID,modified=DATE,fixed='1.0.1')])]),
        'control-db/ID/'+ID+'.json':canonical(record)}
    files.update({'control-blobs/'+case+'.blob':raw for case,raw in blobs.items()})
    return files,blobs,expected,record

def config(database,modified):
    return dict(protocol_version='v1.0.0',scanner_name='govulncheck',scanner_version='v0.0.0',
        db=database,db_last_modified=modified,scan_mode='binary',scan_level='symbol')

def validate_native(case,raw,exit_code,stderr):
    files,blobs,expected,record=fixture()
    need(case in blobs,'control_case')
    body,_=admit_metadata(blobs[case],expected)
    raw_for_validation=blobs[case]
    rejection=None
    if case=='fallback':
        need(body['pkgSymbols']==[],'control_fallback')
        try:admit_extraction(blobs[case],expected)
        except ContractError as error:rejection=error.code
        need(rejection=='symbol_count','control_fallback')
        # This deliberately synthetic reference describes the scanner fallback.
        # It is never substituted for a real binary's extracted symbol evidence.
        raw_for_validation=blobs['positive']
    observation=admit_scan(raw,raw_for_validation,expected,
        config('file:///opt/input/control-db',DATE),{ID:record},{MODULE:[ID]},
        {(ID,MODULE)},exit_code,stderr)
    wanted={'module':1,'package':1,'symbol':0 if case=='negative' else 1}
    need(observation['findings_by_level']==wanted,'control_findings')
    need(observation['finding_messages']==sum(wanted.values()) and observation['osv_messages']==1,'control_multiplicity')
    need(all(x['fixed_version']=='v1.0.1' for x in observation['findings']),'control_fixed_version')
    if case!='negative':
        need([x['function'] for x in observation['findings'] if x['level']=='symbol']==['Problem'],'control_symbol')
    return dict(schema_version=1,scope='synthetic_native_scanner_control',case=case,success=True,
        raw_sha256=hashlib.sha256(raw).hexdigest(),raw_bytes=len(raw),findings_by_level=wanted,
        empty_symbol_rejection=rejection,real_binary_symbol_evidence=False,
        vulnerability_audit_completed=False,provider_accepted=False)

def validate_stripped(raw,expected):
    body,_=admit_metadata(raw,expected)
    need('pkgSymbols' not in body,'stripped_symbols_present')
    rejection=None
    try:admit_extraction(raw,expected)
    except ContractError as error:rejection=error.code
    need(rejection=='extract_body','stripped_admission')
    return dict(schema_version=1,scope='stripped_real_binary_negative_control',success=True,
        metadata_verified=True,omitted_symbols=True,admission_rejection=rejection,
        raw_sha256=hashlib.sha256(raw).hexdigest(),raw_bytes=len(raw),
        vulnerability_audit_completed=False,provider_accepted=False)
