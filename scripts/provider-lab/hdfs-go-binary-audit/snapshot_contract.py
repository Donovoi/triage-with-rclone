"""Decode an immutable advisory bundle without extracting filesystem paths."""
from __future__ import annotations
from collections import Counter
import hashlib,json,re,zlib
from audit_contract import ContractError,need,unique,nonfinite,text_value
from advisory_contract import project_osv,timestamp

def parse_json(raw):
    try:return json.loads(raw,object_pairs_hook=unique,parse_constant=nonfinite)
    except (ValueError,UnicodeError,RecursionError):raise ContractError('snapshot_json') from None

def decode_snapshot(raw,pin):
    required={'compressed_bytes','compressed_sha256','payload_bytes','payload_sha256','source_archive_sha256',
              'files','records','original_file_bytes','database_modified','module_index_entries','module_references','known_ids'}
    need(type(pin) is dict and set(pin)==required,'snapshot_pin')
    for key,maximum in [('compressed_bytes',2*1024*1024),('payload_bytes',16*1024*1024),('files',10000),
                        ('records',10000),('original_file_bytes',16*1024*1024),('module_index_entries',10000),('module_references',100000)]:
        need(type(pin[key]) is int and 0<pin[key]<=maximum,'snapshot_pin_bound')
    for key in ('compressed_sha256','payload_sha256','source_archive_sha256'):
        need(type(pin[key]) is str and re.fullmatch('[a-f0-9]{64}',pin[key]),'snapshot_pin_digest')
    need(type(raw) is bytes and len(raw)==pin['compressed_bytes']
         and hashlib.sha256(raw).hexdigest()==pin['compressed_sha256'],'snapshot_archive_binding')
    try:
        decoder=zlib.decompressobj(31);payload=decoder.decompress(raw,pin['payload_bytes']+1)
    except zlib.error:raise ContractError('snapshot_compression') from None
    need(len(payload)==pin['payload_bytes'] and decoder.eof and not decoder.unused_data
         and not decoder.unconsumed_tail,'snapshot_expansion')
    need(hashlib.sha256(payload).hexdigest()==pin['payload_sha256'],'snapshot_payload_binding')
    bundle=parse_json(payload)
    need(type(bundle) is dict and set(bundle)=={'schema_version','source_archive_sha256','files'}
         and type(bundle['schema_version']) is int and bundle['schema_version']==1
         and bundle['source_archive_sha256']==pin['source_archive_sha256'],'snapshot_header')
    files=bundle['files'];need(type(files) is dict and len(files)==pin['files'],'snapshot_file_count')
    decoded={};file_bytes={};total=0
    for name,content in files.items():
        need(type(name) is str and (name in {'index/db.json','index/modules.json','index/vulns.json'}
             or re.fullmatch(r'ID/GO-[0-9]{4}-[0-9]{4,}[.]json',name)),'snapshot_path')
        need(type(content) is str,'snapshot_file_type')
        try:encoded=content.encode('utf-8','strict')
        except UnicodeError:raise ContractError('snapshot_file_encoding') from None
        need(0<len(encoded)<=1048576,'snapshot_file_size')
        total+=len(encoded);need(total<=pin['original_file_bytes'],'snapshot_total_size')
        decoded[name]=parse_json(encoded);file_bytes[name]=encoded
    need(total==pin['original_file_bytes'],'snapshot_total_size')
    need({'index/db.json','index/modules.json','index/vulns.json'}<=set(decoded),'snapshot_indexes_missing')
    database=decoded['index/db.json']
    need(type(database) is dict and set(database)=={'modified'}
         and timestamp(database['modified'])==timestamp(pin['database_modified']),'snapshot_database_time')
    records={};custom=[];affected_counts=Counter()
    for name,value in decoded.items():
        if not name.startswith('ID/'):continue
        projected=project_osv(value,custom)
        need(projected['id']==name[3:-5],'snapshot_record_name')
        records[value['id']]=value
        for affected in value['affected']:affected_counts[(affected['package']['name'],value['id'])]+=1
    need(len(records)==pin['records'],'snapshot_record_count')
    vulns=decoded['index/vulns.json']
    need(type(vulns) is list and len(vulns)==len(records),'snapshot_vuln_index')
    seen=set()
    for item in vulns:
        need(type(item) is dict and set(item)<={'id','modified','aliases'} and set(item)>={'id','modified'},'snapshot_vuln_row')
        ident=item['id'];need(type(ident) is str and ident in records and ident not in seen,'snapshot_vuln_identity');seen.add(ident)
        need(item['modified']==records[ident]['modified'] and item.get('aliases',[])==records[ident].get('aliases',[]),'snapshot_vuln_binding')
    modules=decoded['index/modules.json']
    need(type(modules) is list and len(modules)==pin['module_index_entries'],'snapshot_module_index')
    index={};indexed_counts=Counter();references=0
    for item in modules:
        need(type(item) is dict and set(item)=={'path','vulns'} and text_value(item['path']) and type(item['vulns']) is list,'snapshot_module_row')
        module=item['path'];need(module not in index,'snapshot_duplicate_module');ids=[]
        for entry in item['vulns']:
            need(type(entry) is dict and set(entry)<={'id','modified','fixed'} and set(entry)>={'id','modified'},'snapshot_module_advisory')
            ident=entry['id'];need(type(ident) is str and ident in records,'snapshot_module_advisory_id')
            record=records[ident]
            need(entry['modified']==record['modified'],'snapshot_module_modified')
            if 'fixed' in entry:
                fixed=[e['fixed'] for a in record['affected'] if a['package']['name']==module for r in a.get('ranges',[]) for e in r.get('events',[]) if 'fixed' in e]
                need(entry['fixed'] in fixed,'snapshot_fixed_membership')
            indexed_counts[(module,ident)]+=1;ids.append(ident);references+=1
        index[module]=ids
    need(indexed_counts==affected_counts and references==pin['module_references'],'snapshot_module_bindings')
    need(type(pin['known_ids']) is list and all(type(x) is str and x in records for x in pin['known_ids']),'snapshot_known_controls')
    summary={'schema_version':1,'scope':'offline_go_advisory_snapshot','compressed_sha256':pin['compressed_sha256'],
        'payload_sha256':pin['payload_sha256'],'source_archive_sha256':pin['source_archive_sha256'],
        'files':len(files),'records':len(records),'file_bytes':total,'modules':len(index),'module_references':references,
        'database_modified':database['modified'],'custom_range_records':len({x['id'] for x in custom}),
        'custom_range_affected_blocks':len(custom),'version_semantics_verified':False,'vulnerability_audit_completed':False}
    return summary,file_bytes,records,index
