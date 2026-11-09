"""Pinned public Go analyzer assets; preparation does not execute native code."""
from __future__ import annotations
import hashlib,json,re
from pathlib import Path
from audit_contract import ContractError,need,unique,nonfinite

LOCK_SHA='d9cb60f32fe2c837a5ed6109403e401033b143824e4fb4a1a33e8c5c8e472917'
TOOL='golang.org/x/vuln'
VERSION='v1.9.0'
ORIGIN='e672cbe8fbc8c76e28fcb6db0efd9ce354e0dac5'
TOTAL_BYTES=7340965

def escape(value):
    return ''.join('!'+c.lower() if 'A'<=c<='Z' else c for c in value)

def validate_lock(value):
    need(type(value) is dict and set(value)=={'schema_version','tool','assets'}
         and type(value['schema_version']) is int and value['schema_version']==1,'tool_lock')
    need(value['tool']==dict(module=TOOL,version=VERSION,originCommit=ORIGIN),'tool_identity')
    rows=value['assets'];need(type(rows) is list and len(rows)==34,'tool_asset_count')
    names=set();identities=set();numbers=set();counts={};total=0
    for row in rows:
        need(type(row) is dict and row.get('kind') in ('zip','mod','info'),'tool_asset_shape')
        kind=row['kind'];fields={'file','module','version','kind','url','bytes','sha256'}
        if kind!='info':fields.add('h1')
        need(set(row)==fields,'tool_asset_shape')
        need(type(row['file']) is str and re.fullmatch(r'asset-[0-9]{3}[.]'+kind,row['file'])
             and row['file'] not in names,'tool_asset_name')
        number=int(row['file'][6:9]);need(number not in numbers,'tool_asset_name');numbers.add(number)
        module,version=row['module'],row['version']
        need(type(module) is str and re.fullmatch('[A-Za-z0-9./_~-]+',module)
             and '..' not in module and not module.startswith('/') and not module.endswith('/'),'tool_module')
        need(type(version) is str and re.fullmatch('v[0-9][A-Za-z0-9.+-]*',version),'tool_version')
        need(type(row['bytes']) is int and 0<row['bytes']<=(16*1024*1024 if kind=='zip' else 1048576 if kind=='mod' else 16384),'tool_asset_bound')
        need(type(row['sha256']) is str and re.fullmatch('[a-f0-9]{64}',row['sha256']),'tool_asset_digest')
        if kind!='info':need(type(row['h1']) is str and re.fullmatch('h1:[A-Za-z0-9+/]{43}=',row['h1']),'tool_hash1')
        need(row['url']=='https://proxy.golang.org/'+escape(module)+'/@v/'+escape(version)+'.'+kind,'tool_asset_url')
        identity=(module,version,kind);need(identity not in identities,'tool_duplicate_identity')
        identities.add(identity);names.add(row['file']);counts[kind]=counts.get(kind,0)+1;total+=row['bytes']
    need(counts==dict(zip=11,mod=12,info=11) and numbers==set(range(34)) and total==TOTAL_BYTES,'tool_asset_inventory')
    zips={(m,v) for m,v,k in identities if k=='zip'};mods={(m,v) for m,v,k in identities if k=='mod'}
    infos={(m,v) for m,v,k in identities if k=='info'}
    need(zips==infos and zips<=mods and (TOOL,VERSION) in zips,'tool_asset_closure')
    return value

def load_lock(raw):
    need(type(raw) is bytes and len(raw)<=65536 and hashlib.sha256(raw).hexdigest()==LOCK_SHA,'tool_lock_binding')
    try:value=json.loads(raw,object_pairs_hook=unique,parse_constant=nonfinite)
    except (ValueError,UnicodeError,RecursionError):raise ContractError('tool_lock_json') from None
    return validate_lock(value)

def prepare(B,root,lock,read):
    validate_lock(lock)
    need(root.is_dir() and not root.is_symlink(),'tool_root')
    rows=lock['assets'];raws={};members=expanded=0;main_files=None;archives=0
    for row in rows:
        raw=read(root/'assets'/row['file'],row['bytes'])
        try:B.verify_asset(raw,row)
        except (ValueError,KeyError,TypeError):raise ContractError('tool_asset_invalid') from None
        raws[(row['module'],row['version'],row['kind'])]=raw
    cache=root/'module-cache/cache/download';cache.mkdir(parents=True,mode=0o700)
    source=root/'source';source.mkdir(mode=0o700)
    for row in rows:
        key=(row['module'],row['version'],row['kind']);raw=raws[key]
        target=cache/escape(row['module'])/'@v'/(escape(row['version'])+'.'+row['kind'])
        target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb') as stream:stream.write(raw)
        if row['kind']=='zip':
            try:files,stats=B.module_files(raw,row,retain=True)
            except (ValueError,KeyError,TypeError):raise ContractError('tool_archive_invalid') from None
            need(files.get('go.mod')==raws[(row['module'],row['version'],'mod')],'tool_module_file_binding')
            archives+=1;members+=stats['members'];expanded+=stats['expanded_bytes']
            need(members<=5000 and expanded<=64*1024*1024,'tool_expansion')
            with target.with_suffix('.ziphash').open('xb') as stream:stream.write(row['h1'].encode('ascii'))
            if row['module']==TOOL:
                need(main_files is None and row['version']==VERSION,'tool_main_duplicate')
                main_files=files
                for relative,content in files.items():
                    destination=source/relative;destination.parent.mkdir(parents=True,exist_ok=True)
                    with destination.open('xb') as stream:stream.write(content)
    need(archives==11 and members==2923 and expanded==24260680 and main_files is not None and len(main_files)==308,'tool_expansion_inventory')
    sums={}
    for line in main_files['go.sum'].decode('utf-8').splitlines():
        fields=line.split();need(len(fields)==3 and tuple(fields[:2]) not in sums,'tool_go_sum')
        sums[tuple(fields[:2])]=fields[2]
    wanted={(r['module'],r['version']+('/go.mod' if r['kind']=='mod' else '')):r['h1']
            for r in rows if r['module']!=TOOL and r['kind'] in ('zip','mod')}
    need(sums==wanted,'tool_dependency_sums')
    need(b'\nreplace ' not in main_files['go.mod'] and b'\ngo 1.26.0\n' in main_files['go.mod'],'tool_go_mod')
    return {'schema_version':1,'scope':'go_analyzer_source_preparation','module':TOOL,'version':VERSION,'origin':ORIGIN,
        'assets':len(rows),'asset_bytes':sum(r['bytes'] for r in rows),'archives':archives,'members':members,
        'expanded_bytes':expanded,'source_files':len(main_files),
        'source_sha256':{n:hashlib.sha256(main_files[n]).hexdigest() for n in ('go.mod','go.sum','LICENSE')},
        'native_build_verified':False,'vulnerability_audit_completed':False}

def verify_prepared(B,root,lock,read):
    """Rebind every output of the completed download worker without executing Go."""
    validate_lock(lock)
    expected_files={};members=expanded=0
    for row in lock['assets']:
        asset=root/'assets'/row['file'];raw=read(asset,row['bytes'])
        try:B.verify_asset(raw,row)
        except (ValueError,KeyError,TypeError):raise ContractError('tool_asset_invalid') from None
        expected_files[asset.relative_to(root).as_posix()]=hashlib.sha256(raw).hexdigest()
        target=root/'module-cache/cache/download'/escape(row['module'])/'@v'/(escape(row['version'])+'.'+row['kind'])
        need(read(target,row['bytes'])==raw,'tool_cache_binding')
        expected_files[target.relative_to(root).as_posix()]=hashlib.sha256(raw).hexdigest()
        if row['kind']=='zip':
            checksum=target.with_suffix('.ziphash')
            need(read(checksum,128)==row['h1'].encode('ascii'),'tool_cache_binding')
            expected_files[checksum.relative_to(root).as_posix()]=hashlib.sha256(row['h1'].encode('ascii')).hexdigest()
            try:files,stats=B.module_files(raw,row,retain=row['module']==TOOL)
            except (ValueError,KeyError,TypeError):raise ContractError('tool_archive_invalid') from None
            members+=stats['members'];expanded+=stats['expanded_bytes']
            if row['module']==TOOL:
                for relative,content in files.items():
                    destination=root/'source'/relative
                    need(read(destination,len(content))==content,'tool_source_binding')
                    expected_files[destination.relative_to(root).as_posix()]=hashlib.sha256(content).hexdigest()
    need(members==2923 and expanded==24260680 and len(expected_files)==387,'tool_prepared_inventory')
    return expected_files
