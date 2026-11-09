"""Exact public version metadata for selected graph nodes without source archives."""
from __future__ import annotations
import base64,hashlib,json,os,re
from datetime import datetime
from audit_contract import ContractError,need,unique,nonfinite
import remediation_bundle as B

SNAPSHOT_SHA='0e47c28ecb34e99a5d9f0c389492b25ef95ee980f3d962bac14d3c4ebea3945e'
SNAPSHOT_BYTES=241246
SELECTED=653
METADATA=318
METADATA_BYTES=53641
GRAPH_NODES=654
SOURCE_NODES=336


def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
def coordinate(module,version):
 need(type(module) is str and 0<len(module)<=256 and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9./_~+-]*',module)
  and all(p not in ('','.','..') for p in module.split('/')) and module!=B.MODULE
  and type(version) is str and len(version)<=256 and re.fullmatch(r'v[0-9][A-Za-z0-9.+-]*',version),'graph_metadata_coordinate')
def parse(raw):
 try:return json.loads(raw,object_pairs_hook=unique,parse_constant=nonfinite)
 except (ValueError,UnicodeError,RecursionError):raise ContractError('graph_metadata_json') from None

def validate_snapshot(value):
 need(type(value) is dict and set(value)=={'schema_version','scope','origin_head','origin_run','go_version','selected','metadata'}
  and type(value['schema_version']) is int and value['schema_version']==1
  and value['scope']=='selected_graph_version_metadata_only'
  and value['origin_head']=='749e27f48f4eb4496e9ec4032509cec58a4a1283'
  and type(value['origin_run']) is int and value['origin_run']==42717840460 and value['go_version']==B.GO_VERSION,'graph_metadata_snapshot')
 selected=value['selected'];need(type(selected) is list and len(selected)==SELECTED,'graph_metadata_selected')
 versions={};names=[]
 for row in selected:
  need(type(row) is dict and set(row)=={'module','version'},'graph_metadata_selected')
  coordinate(row['module'],row['version']);need(row['module'] not in versions,'graph_metadata_duplicate')
  names.append(row['module']);versions[row['module']]=row['version']
 need(names==sorted(names),'graph_metadata_order')
 rows=value['metadata'];need(type(rows) is list and len(rows)==METADATA,'graph_metadata_inventory')
 metadata={};total=0;names=[]
 for row in rows:
  need(type(row) is dict and set(row)=={'module','version','url','bytes','sha256','content_base64','go_mod_sum'},'graph_metadata_row')
  module,version=row['module'],row['version'];coordinate(module,version)
  need(versions.get(module)==version and module not in metadata,'graph_metadata_selected')
  need(row['url']=='https://proxy.golang.org/'+B.escape(module)+'/@v/'+B.escape(version)+'.info','graph_metadata_url')
  need(type(row['bytes']) is int and 0<row['bytes']<=4096 and type(row['sha256']) is str
   and re.fullmatch('[a-f0-9]{64}',row['sha256']) and type(row['content_base64']) is str
   and len(row['content_base64'])<=5464,'graph_metadata_pin')
  try:raw=base64.b64decode(row['content_base64'],validate=True)
  except ValueError:raise ContractError('graph_metadata_base64') from None
  need(base64.b64encode(raw).decode('ascii')==row['content_base64'] and len(raw)==row['bytes']
   and sha(raw)==row['sha256'],'graph_metadata_binding')
  info=parse(raw)
  need(type(info) is dict and {'Version','Time'}<=set(info)<={'Version','Time','Origin'}
   and info['Version']==version and type(info['Time']) is str and len(info['Time'])<=40
   and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.][0-9]{1,9})?Z',info['Time'])
   and ('Origin' not in info or type(info['Origin']) is dict),'graph_metadata_info')
  try:datetime.fromisoformat(info['Time'].removesuffix('Z')+'+00:00')
  except ValueError:raise ContractError('graph_metadata_time') from None
  need(type(row['go_mod_sum']) is str and (row['go_mod_sum']=='' or re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=',row['go_mod_sum'])),
   'graph_metadata_modsum')
  metadata[module]=dict(version=version,raw=raw,sha256=row['sha256'],go_mod_sum=row['go_mod_sum'])
  names.append(module);total+=len(raw)
 need(names==sorted(names) and total==METADATA_BYTES,'graph_metadata_inventory')
 return versions,metadata

def load_snapshot(raw):
 need(type(raw) is bytes and len(raw)==SNAPSHOT_BYTES and sha(raw)==SNAPSHOT_SHA,'graph_metadata_snapshot_binding')
 return validate_snapshot(parse(raw))

def extend_catalog(source,raw,sum_raw,mod_sums,allowed):
 versions,metadata=load_snapshot(raw)
 need(type(source) is dict and len(source)==SOURCE_NODES and B.MODULE in source
  and type(mod_sums) is dict and type(allowed) is set and type(sum_raw) is bytes and len(sum_raw)<=131072,'graph_metadata_sources')
 recorded={}
 try:
  for line in sum_raw.decode('ascii').splitlines():
   module,version,digest=line.split(' ')
   need((module,version) not in recorded and re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=',digest),'graph_metadata_sums')
   recorded[(module,version)]=digest
 except (ValueError,UnicodeError):raise ContractError('graph_metadata_sums') from None
 result={}
 for module,row in source.items():
  need(type(row) is dict and set(row)=={'path','version','sum','go_mod_sum'} and row['path']==module
   and all(type(row[k]) is str and re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=',row[k]) for k in ('sum','go_mod_sum')),'graph_metadata_source_row')
  if module!=B.MODULE:need(versions.get(module)==row['version'],'graph_metadata_source_version')
  result[module]=dict(row,source_available=True)
 for module,row in metadata.items():
  version=row['version'];expected=row['go_mod_sum']
  need(module not in source and (module,version) in allowed,'graph_metadata_overlap')
  need((module,version) not in recorded and recorded.get((module,version+'/go.mod'),'')==expected
   and (not expected or mod_sums.get((module,version))==expected),'graph_metadata_recorded_sum')
  result[module]=dict(path=module,version=version,sum='',go_mod_sum=expected,source_available=False)
 need(len(result)==GRAPH_NODES and set(result)==set(versions)|{B.MODULE},'graph_metadata_graph_inventory')
 return result

def stage_owned(C,context,raw):
 _,metadata=load_snapshot(raw)
 need(context.is_absolute(),'graph_metadata_context')
 context_id=C.directory(context);cache=context/'module-cache/cache/download';cache_id=C.directory(cache)
 plan=[]
 for module,row in metadata.items():
  relative=B.cache_relative(dict(module=module,version=row['version'],kind='info'));target=context/relative
  need(not target.exists() and not target.is_symlink(),'graph_metadata_cache_collision')
  for parent in target.parents:
   if parent==context:break
   need(context in parent.parents,'graph_metadata_cache_path')
   if parent.exists() or parent.is_symlink():C.directory(parent)
  else:need(False,'graph_metadata_cache_path')
  plan.append((relative,target,row))
 for relative,target,row in plan:
  C.directory(context,context_id);C.directory(cache,cache_id)
  target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
  for parent in target.parents:
   if parent==context:break
   C.directory(parent)
  fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  with os.fdopen(fd,'wb') as stream:stream.write(row['raw'])
  need(sha(C.read(target,4096))==row['sha256'],'graph_metadata_cache_changed')
 for _,target,row in plan:need(sha(C.read(target,4096))==row['sha256'],'graph_metadata_cache_changed')
 C.directory(context,context_id);C.directory(cache,cache_id)
 return dict(schema_version=1,scope='owned_selected_graph_metadata',snapshot_sha256=SNAPSHOT_SHA,
  cache_files=len(plan),cache_bytes=METADATA_BYTES,cache_sha256={rel:row['sha256'] for rel,_,row in plan},
  source_archives_added=0,module_resolution_verified=False,native_build_verified=False)
