"""Bound admission for the pinned govulncheck binary-extraction protocol.

This validates symbol availability and metadata only. It does not establish
vulnerability reachability, exploitability, or a clean vulnerability scan.
"""
from __future__ import annotations
import hashlib
import json

MAX_EXTRACT_BYTES=64*1024*1024
MAX_SYMBOLS=500000
MODULE_FIELDS=frozenset(('Path','Version','Replace','Time','Main','Indirect','Dir','GoMod','GoVersion','Error'))
BODY_FIELDS=frozenset(('path','main','modules','pkgSymbols','goVersion','goos','goarch'))

class ContractError(Exception):
    def __init__(self,code):
        self.code=code
        super().__init__(code)

def need(ok,code):
    if not ok:raise ContractError(code)

def unique(rows):
    result={}
    for key,value in rows:
        need(key not in result,'duplicate_key')
        result[key]=value
    return result

def nonfinite(_):
    raise ContractError('nonfinite')

def bounded_stream(raw,count):
    need(type(raw) is bytes and 0<len(raw)<=MAX_EXTRACT_BYTES,'input_size')
    try:text=raw.decode('utf-8','strict')
    except UnicodeError:raise ContractError('encoding') from None
    decoder=json.JSONDecoder(object_pairs_hook=unique,parse_constant=nonfinite)
    values=[];offset=0
    while offset<len(text):
        while offset<len(text) and text[offset] in ' \t\r\n':offset+=1
        if offset==len(text):break
        need(len(values)<count,'message_count')
        try:value,offset=decoder.raw_decode(text,offset)
        except (ValueError,RecursionError):raise ContractError('json') from None
        values.append(value)
    need(len(values)==count,'message_count')
    return values

def text_value(value,limit=4096,empty=False):
    if not (type(value) is str and (empty or len(value)>0) and len(value)<=limit and not any(ord(c)<32 for c in value)):return False
    try:value.encode('utf-8','strict')
    except UnicodeError:return False
    return True

def module_shape(value,allow_replace=True):
    need(type(value) is dict and set(value)==MODULE_FIELDS,'module_shape')
    need(text_value(value['Path']) and text_value(value['Version'],256,True),'module_identity')
    need(value['Time'] is None and value['Main'] is False and value['Indirect'] is False
         and value['Dir']=='' and value['GoMod']=='' and value['GoVersion']=='' and value['Error'] is None,'module_metadata')
    replacement=value['Replace']
    if replacement is not None:
        need(allow_replace,'nested_replacement')
        module_shape(replacement,False)
    return value

def admit_metadata(raw,expected):
    """Bind metadata even when the scanner omits symbols; no precision credit."""
    need(type(expected) is dict and set(expected)=={'path','go_version','goos','goarch','main_versions','modules'},'expected_shape')
    header,body=bounded_stream(raw,2)
    need(header=={'name':'govulncheck-extract','version':'0.1.0'},'extract_header')
    need(type(body) is dict and set(body) in (BODY_FIELDS,BODY_FIELDS-{'pkgSymbols'}),'extract_body')
    for key,expected_key in [('path','path'),('goVersion','go_version'),('goos','goos'),('goarch','goarch')]:
        need(body[key]==expected[expected_key],'binary_metadata')
    main=module_shape(body['main'])
    need(main['Path']==expected['path'] and main['Replace'] is None
         and main['Version'] in expected['main_versions'],'main_metadata')
    modules=body['modules'];wanted=expected['modules']
    need(type(modules) is list and type(wanted) is list and 0<len(modules)==len(wanted)<=4096,'module_count')
    wanted_map={}
    for item in wanted:
        need(type(item) is dict and set(item)=={'path','version','replacement'},'expected_module')
        need(item['path'] not in wanted_map,'expected_duplicate_module')
        wanted_map[item['path']]=item
    seen=set();replacement_rows=[]
    for item in modules:
        module=module_shape(item);name=module['Path']
        need(name not in seen and name in wanted_map,'module_set')
        seen.add(name);target=wanted_map[name]
        need(module['Version']==target['version'],'module_version')
        replacement=module['Replace'];wanted_replacement=target['replacement']
        if wanted_replacement is None:
            need(replacement is None,'unexpected_replacement')
        else:
            need(type(wanted_replacement) is dict and set(wanted_replacement)=={'path','versions'},'expected_replacement')
            need(replacement is not None and replacement['Path']==wanted_replacement['path']
                 and replacement['Version'] in wanted_replacement['versions'],'replacement_identity')
            replacement_rows.append({'path':name,'version':module['Version'],
                'replacement_path':replacement['Path'],'replacement_version':replacement['Version'],
                'upstream_advisory_coverage':'requires_separate_conservative_proxy'})
    return body,replacement_rows

def admit_extraction(raw,expected):
    """Require independently bound metadata and nonempty extracted symbols."""
    body,replacement_rows=admit_metadata(raw,expected)
    need(set(body)==BODY_FIELDS,'extract_body')
    main=body['main']
    symbols=body['pkgSymbols']
    need(type(symbols) is list and 0<len(symbols)<=MAX_SYMBOLS,'symbol_count')
    symbol_set=set();packages=set();last=None
    for item in symbols:
        need(type(item) is dict and set(item)<= {'pkg','name'} and 'name' in item,'symbol_shape')
        pkg,name=item.get('pkg',''),item['name']
        need(text_value(pkg,4096,True) and text_value(name),'symbol_text')
        pair=(pkg,name);sort_key=pkg+'.'+name
        need(pair not in symbol_set,'duplicate_symbol')
        need(last is None or last<=sort_key,'symbol_order')
        last=sort_key;symbol_set.add(pair)
        if pkg:packages.add(pkg)
    need(len(packages)>0,'qualified_symbols_absent')
    canonical=json.dumps(symbols,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
    metadata={k:v for k,v in body.items() if k!='pkgSymbols'}
    summary={'schema_version':1,'scope':'go_binary_extraction_admission',
        'raw_sha256':hashlib.sha256(raw).hexdigest(),'raw_bytes':len(raw),
        'symbols':len(symbols),'packages':len(packages),'symbols_sha256':hashlib.sha256(canonical).hexdigest(),
        'metadata_sha256':hashlib.sha256(json.dumps(metadata,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        'main_module_version':main['Version'],'main_version_is_upstream_release':main['Version'] not in ('','(devel)'),
        'local_replacements':sorted(replacement_rows,key=lambda x:x['path']),
        'symbol_fallback_absent':True,'reachability_verified':False,'exploitability_verified':False,
        'vulnerability_audit_completed':False,'provider_accepted':False}
    return summary,body
