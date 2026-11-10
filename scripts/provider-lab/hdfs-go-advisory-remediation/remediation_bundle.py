"""Pinned public source inputs for the contained dependency-upgrade comparison."""
from __future__ import annotations
import hashlib,json,re
from pathlib import Path
from audit_contract import ContractError,need,unique,nonfinite

LOCK_SHA='cd5a454cec149568c8acf5dd125277a76c9e9a743990120d3f4ab385421103fa'
MODULE='github.com/rclone/rclone'
VERSION='v1.75.2'
GO_VERSION='go1.26.10'
ASSETS=36
ASSET_BYTES=60113133
ARCHIVES=11
MEMBERS=4776
EXPANDED=116715130
UPDATES=(('github.com/andybalholm/brotli','v1.2.2','v1.2.7'),
 ('github.com/klauspost/compress','v1.19.2','v1.20.2'),
 ('golang.org/x/net','v0.60.0','v0.62.0'),('golang.org/x/crypto','v0.57.0','v0.58.0'),
 ('golang.org/x/sys','v0.48.0','v0.49.0'),('golang.org/x/term','v0.46.0','v0.47.0'),
 ('golang.org/x/text','v0.42.0','v0.43.0'),('golang.org/x/tools','v0.49.0','v0.51.0'),
 ('golang.org/x/sync','v0.23.0','v0.24.0'))
ADDITIONS=(('golang.org/x/mod','v0.41.0'),('golang.org/x/telemetry','v0.0.0-20260924152758-ed294f943157'))
COORDINATES=(('github.com/andybalholm/brotli','v1.2.7'),('github.com/klauspost/compress','v1.20.2'),
 ('golang.org/x/net','v0.62.0'),('golang.org/x/crypto','v0.58.0'),('golang.org/x/sys','v0.49.0'),
 ('golang.org/x/term','v0.47.0'),('golang.org/x/text','v0.43.0'),('golang.org/x/tools','v0.51.0'),
 ('golang.org/x/mod','v0.41.0'),('golang.org/x/sync','v0.24.0'),
 ('golang.org/x/telemetry','v0.0.0-20260924152758-ed294f943157'),
 ('github.com/google/go-cmp','v0.6.0'),('golang.org/x/net','v0.59.0'),('github.com/pelletier/go-toml','v1.9.5'))

def sha(raw):return hashlib.sha256(raw).hexdigest()
def escape(value):return ''.join('!'+c.lower() if 'A'<=c<='Z' else c for c in value)
def pin(value):
 need(type(value) is dict and set(value)=={'bytes','sha256'} and type(value['bytes']) is int
      and 0<value['bytes']<=131072 and type(value['sha256']) is str
      and re.fullmatch('[a-f0-9]{64}',value['sha256']),'remediation_pin')
 return value

def validate_lock(value):
 need(type(value) is dict and set(value)=={'schema_version','scope','source_module','source_version','go_version',
  'assets','original_sources','overlay_sources','version_updates','new_indirect_requirements','metadata_only_inputs'},'remediation_lock')
 need(type(value['schema_version']) is int and value['schema_version']==1
  and value['scope']=='isolated_go_advisory_remediation_sources' and value['source_module']==MODULE
  and value['source_version']==VERSION and value['go_version']==GO_VERSION,'remediation_lock')
 need(value['version_updates']==[dict(module=m,original=o,candidate=n) for m,o,n in UPDATES]
  and value['new_indirect_requirements']==[dict(module=m,version=v) for m,v in ADDITIONS]
  and value['metadata_only_inputs']==[dict(module=m,version=v) for m,v in COORDINATES[-3:]],'remediation_versions')
 need(type(value['original_sources']) is dict and set(value['original_sources'])=={'go.mod','go.sum'}
  and all(type(v) is str and re.fullmatch('[a-f0-9]{64}',v) for v in value['original_sources'].values()),'remediation_original_sources')
 need(type(value['overlay_sources']) is dict and set(value['overlay_sources'])=={'upgraded-rclone.mod','upgraded-rclone.sum'},'remediation_overlay')
 for item in value['overlay_sources'].values():pin(item)
 rows=value['assets'];need(type(rows) is list and len(rows)==ASSETS,'remediation_assets')
 seen=set();files=set();counts={};total=0
 for row in rows:
  need(type(row) is dict and set(row)=={'module','version','kind','file','url','bytes','sha256','h1'},'remediation_asset')
  need(type(row['module']) is str and type(row['version']) is str and (row['module'],row['version']) in COORDINATES,'remediation_coordinate')
  index=COORDINATES.index((row['module'],row['version']));kind=row['kind']
  need(kind in ('zip','mod','info') and (index<11 or kind=='mod'),'remediation_asset_kind')
  need(row['file']==f'upgrade-{index:03d}.{kind}' and row['file'] not in files
   and row['url']=='https://proxy.golang.org/'+escape(row['module'])+'/@v/'+escape(row['version'])+'.'+kind,'remediation_asset_path')
  need(type(row['bytes']) is int and 0<row['bytes']<=(64*1024*1024 if kind=='zip' else 131072)
   and type(row['sha256']) is str and re.fullmatch('[a-f0-9]{64}',row['sha256'])
   and type(row['h1']) is str and re.fullmatch('h1:[A-Za-z0-9+/]{43}=',row['h1']),'remediation_asset_pin')
  identity=(row['module'],row['version'],kind);need(identity not in seen,'remediation_asset_duplicate')
  seen.add(identity);files.add(row['file']);counts[kind]=counts.get(kind,0)+1;total+=row['bytes']
 need(counts==dict(zip=11,mod=14,info=11) and total==ASSET_BYTES,'remediation_asset_inventory')
 for module,version in COORDINATES[:11]:
  items={r['kind']:r for r in rows if (r['module'],r['version'])==(module,version)}
  need(set(items)=={'zip','mod','info'} and items['zip']['h1']==items['info']['h1'],'remediation_module_assets')
 return value

def load_lock(raw):
 need(type(raw) is bytes and len(raw)<=131072 and sha(raw)==LOCK_SHA,'remediation_lock_binding')
 try:value=json.loads(raw,object_pairs_hook=unique,parse_constant=nonfinite)
 except (ValueError,UnicodeError,RecursionError):raise ContractError('remediation_lock_json') from None
 return validate_lock(value)

def cache_relative(row):
 return 'module-cache/cache/download/'+escape(row['module'])+'/@v/'+escape(row['version'])+'.'+row['kind']

def prepare(B,root,lock,read):
 validate_lock(lock);need(root.is_dir() and not root.is_symlink(),'remediation_root')
 raws={};members=expanded=archives=0
 for row in lock['assets']:
  raw=read(root/'assets'/row['file'],row['bytes'])
  try:B.verify_asset(raw,row)
  except (ValueError,KeyError,TypeError):raise ContractError('remediation_asset_invalid') from None
  raws[(row['module'],row['version'],row['kind'])]=raw
 for row in lock['assets']:
  raw=raws[(row['module'],row['version'],row['kind'])]
  target=root/cache_relative(row);target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
  with target.open('xb') as stream:stream.write(raw)
  if row['kind']=='zip':
   try:files,stats=B.module_files(raw,row,retain=True)
   except (ValueError,KeyError,TypeError):raise ContractError('remediation_archive_invalid') from None
   need(files.get('go.mod')==raws[(row['module'],row['version'],'mod')],'remediation_module_binding')
   members+=stats['members'];expanded+=stats['expanded_bytes'];archives+=1
   need(members<=5000 and expanded<=128*1024*1024,'remediation_expansion')
   with target.with_suffix('.ziphash').open('xb') as stream:stream.write(row['h1'].encode('ascii'))
 need((archives,members,expanded)==(ARCHIVES,MEMBERS,EXPANDED),'remediation_expansion_inventory')
 return dict(schema_version=1,scope='go_remediation_source_preparation',module=MODULE,version=VERSION,
  assets=ASSETS,asset_bytes=ASSET_BYTES,archives=archives,members=members,expanded_bytes=expanded,
  native_build_verified=False,module_resolution_verified=False,vulnerability_audit_completed=False)

def validate_prepared(value):
 expected=dict(schema_version=1,scope='go_remediation_source_preparation',module=MODULE,version=VERSION,
  assets=ASSETS,asset_bytes=ASSET_BYTES,archives=ARCHIVES,members=MEMBERS,expanded_bytes=EXPANDED,
  native_build_verified=False,module_resolution_verified=False,vulnerability_audit_completed=False)
 need(type(value) is dict and set(value)==set(expected)
  and all(type(value[k]) is type(v) and value[k]==v for k,v in expected.items()),'remediation_prepared_report')
 return value

def verify_prepared(B,root,lock,read):
 validate_lock(lock);need(root.is_dir() and not root.is_symlink(),'remediation_root')
 expected={};members=expanded=archives=0
 for row in lock['assets']:
  for rel in ('assets/'+row['file'],cache_relative(row)):
   raw=read(root/rel,row['bytes'])
   try:B.verify_asset(raw,row)
   except (ValueError,KeyError,TypeError):raise ContractError('remediation_asset_invalid') from None
   expected[rel]=row['sha256']
  if row['kind']=='zip':
   try:_,stats=B.module_files(raw,row,retain=False)
   except (ValueError,KeyError,TypeError):raise ContractError('remediation_archive_invalid') from None
   members+=stats['members'];expanded+=stats['expanded_bytes'];archives+=1
   rel=cache_relative(row)[:-4]+'.ziphash';value=read(root/rel,64)
   need(value==row['h1'].encode('ascii'),'remediation_ziphash');expected[rel]=sha(value)
 need((archives,members,expanded)==(ARCHIVES,MEMBERS,EXPANDED),'remediation_expansion_inventory')
 return expected

def overlay_files(lock,original_mod,original_sum,mod,sum_bytes,variant):
 validate_lock(lock);need(variant in ('original','patched'),'remediation_variant')
 need(type(original_mod) is bytes and type(original_sum) is bytes
  and sha(original_mod)==lock['original_sources']['go.mod'] and sha(original_sum)==lock['original_sources']['go.sum'],
  'remediation_original_binding')
 for name,raw in (('upgraded-rclone.mod',mod),('upgraded-rclone.sum',sum_bytes)):
  expected=lock['overlay_sources'][name]
  need(type(raw) is bytes and len(raw)==expected['bytes'] and sha(raw)==expected['sha256'],'remediation_overlay_binding')
 need(b'\nreplace ' not in original_mod and b'\nreplace ' not in mod,'remediation_replacement')
 if variant=='patched':mod+=b'\nreplace github.com/colinmarc/hdfs/v2 => /opt/input/patched-hdfs\n'
 return {'upgraded-rclone.mod':mod,'upgraded-rclone.sum':sum_bytes,'remediation-variant.txt':(variant+'\n').encode('ascii')}

def source_catalog(baseline,lock):
 """Allow known source coordinates; this does not resolve Go minimal-version selection."""
 validate_lock(lock);need(type(baseline) is dict and type(baseline.get('assets')) is list,'remediation_baseline')
 old={r['module']:r for r in baseline['assets'] if r['kind']=='zip'}
 need(len(old)==334 and MODULE in old,'remediation_baseline')
 for module,version,_ in UPDATES:need(module in old and old[module]['version']==version,'remediation_baseline_version')
 for module,_ in ADDITIONS:need(module not in old,'remediation_baseline_version')
 selected=dict(old)
 for row in lock['assets']:
  if row['kind']=='zip':selected[row['module']]=row
 modpins={(r['module'],r['version']):r['h1'] for r in baseline['assets'] if r['kind']=='mod'}
 modpins.update({(r['module'],r['version']):r['h1'] for r in lock['assets'] if r['kind']=='mod'})
 need(len(selected)==336,'remediation_catalog')
 need(all((module,r['version']) in modpins for module,r in selected.items()),'remediation_catalog_modpin')
 return {module:dict(path=module,version=r['version'],sum=r['h1'],go_mod_sum=modpins[(module,r['version'])])
         for module,r in selected.items()}
