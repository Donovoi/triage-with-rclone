"""Admit hosted resolver and compiled metadata against the pinned source catalogue."""
from __future__ import annotations
import hashlib,json,re
from audit_contract import ContractError,need,unique,nonfinite
import wrapper_contract as W
from remediation_bundle import MODULE,GO_VERSION

HDFS='github.com/colinmarc/hdfs/v2'
LOCAL_HDFS='/opt/input/patched-hdfs'
GRAPH_FIELDS={'path','version','sum','go_mod_sum','main','indirect','go_version','replacement'}
IDENTITY_FIELDS={'schema_version','success','error','variant','target','binary','graph','source_files','graph_file',
 'version_stdout','version_stderr','version_exit_code','version_timed_out','version_wait_delay_exceeded',
 'version_stdout_overflow','version_stderr_overflow','target_unchanged','sources_unchanged','graph_unchanged',
 'capture_controls','duration_ms','vulnerability_audit_completed','provider_accepted'}
CRITICAL={'github.com/andybalholm/brotli','github.com/klauspost/compress','golang.org/x/net',HDFS}

def root_requirements(raw,variant):
 need(type(raw) is bytes and len(raw)<=131072 and variant in ('original','patched'),'remediation_root_mod')
 try:text=raw.decode('utf-8')
 except UnicodeError:raise ContractError('remediation_root_mod') from None
 required={};go=None;module=None;inside=False;replacements=0;godebug=0
 for original in text.splitlines():
  line=original.split('//',1)[0].strip()
  if not line:continue
  if line=='require (':need(not inside,'remediation_root_mod');inside=True;continue
  if line==')':need(inside,'remediation_root_mod');inside=False;continue
  if inside or line.startswith('require '):
   if not inside:line=line[8:].strip()
   match=re.fullmatch(r'([A-Za-z0-9./_~!+-]+) (v[0-9][A-Za-z0-9.+-]*)',line)
   need(match is not None and match[1] not in required,'remediation_root_requirement')
   required[match[1]]=match[2];continue
  if line.startswith('module '):
   need(module is None and line=='module '+MODULE,'remediation_root_mod');module=MODULE
  elif line.startswith('go '):
   need(go is None and line=='go 1.26.0','remediation_root_mod');go='1.26.0'
  elif line=='godebug x509negativeserial=1':
   godebug+=1
  elif line=='replace '+HDFS+' => '+LOCAL_HDFS:
   replacements+=1
  else:raise ContractError('remediation_root_mod')
 need(not inside and module==MODULE and go=='1.26.0' and godebug==1 and len(required)==275
  and replacements==(1 if variant=='patched' else 0),'remediation_root_mod')
 return required,go

def admit_graph(rows,catalog,mod,variant):
 required,go=root_requirements(mod,variant)
 need(all(m in catalog and catalog[m]['version']==v for m,v in required.items()),'remediation_required_versions')
 need(type(catalog) is dict and len(catalog)==654 and all(type(c) is dict
  and set(c)=={'path','version','sum','go_mod_sum','source_available'} and type(c['source_available']) is bool
  for c in catalog.values()) and sum(c['source_available'] for c in catalog.values())==336,'remediation_graph_catalog')
 need(type(rows) is list and len(rows)==len(catalog),'remediation_graph_size')
 names=[];mapped={};main_count=replacements=0
 for row in rows:
  need(type(row) is dict and set(row)==GRAPH_FIELDS,'remediation_graph_row')
  need(all(type(row[k]) is str and len(row[k])<=4096 for k in GRAPH_FIELDS-{'main','indirect'})
   and type(row['main']) is bool and type(row['indirect']) is bool,'remediation_graph_row')
  module=row['path'];need(module in catalog and module not in mapped,'remediation_graph_module')
  need(not row['go_version'] or re.fullmatch(r'[0-9]+\.[0-9]+(?:\.[0-9]+)?',row['go_version']),'remediation_graph_go_version')
  if module==MODULE:
   main_count+=1
   need(row['main'] is True and row['indirect'] is False and row['version']==row['sum']==row['go_mod_sum']==row['replacement']==''
    and row['go_version']==go,'remediation_graph_main')
  else:
   expected=catalog[module]
   need(row['main'] is False and row['version']==expected['version'],'remediation_graph_version')
   if variant=='patched' and module==HDFS:
    need(row['replacement']==LOCAL_HDFS and row['sum']==row['go_mod_sum']=='','remediation_graph_replacement');replacements+=1
   else:
    need(row['replacement']=='' and row['sum']==expected['sum'] and row['go_mod_sum']==expected['go_mod_sum'],
     'remediation_graph_source_binding')
  names.append(module);mapped[module]=dict(row,source_available=catalog[module]['source_available'])
 need(main_count==1 and names==sorted(names) and set(names)==set(catalog) and set(required)<=set(names)
  and replacements==(1 if variant=='patched' else 0),'remediation_graph_inventory')
 return mapped

def admit_compiled(identity,graph,baseline,variant):
 W.binary(identity,MODULE,MODULE)
 need(baseline.get('variant')==variant,'remediation_baseline_variant')
 before=W.expected_target(baseline)
 need(identity['file']!=before['file'] and 1024*1024<=identity['file']['bytes']<=256*1024*1024,'remediation_upgrade_identity')
 names=set()
 for row in identity['modules']:
  module=row['path'];need(module in graph and module!=MODULE,'remediation_compiled_module')
  target=graph[module]
  need(target.get('source_available') is True,'remediation_compiled_metadata_only')
  need(row=={k:target[k] for k in ('path','version','sum','replacement')},'remediation_compiled_binding')
  names.add(module)
 need(CRITICAL<=names,'remediation_compiled_critical')
 old={x['path']:x for x in before['modules']};new={x['path']:x for x in identity['modules']}
 return dict(added=sorted(set(new)-set(old)),removed=sorted(set(old)-set(new)),
  changed=[dict(path=m,before=old[m],after=new[m]) for m in sorted(set(old)&set(new)) if old[m]!=new[m]])

def admit_identity(raw,variant,catalog,expected_files,baseline):
 need(type(raw) is bytes and 0<len(raw)<=2*1024*1024,'remediation_identity_size')
 try:value=json.loads(raw,object_pairs_hook=unique,parse_constant=nonfinite)
 except (ValueError,UnicodeError,RecursionError):raise ContractError('remediation_identity_json') from None
 need(type(value) is dict and set(value)==IDENTITY_FIELDS and type(value['schema_version']) is int
  and value['schema_version']==1 and value['success'] is True and value['error']=='none'
  and variant in ('original','patched') and value['variant']==variant and value['target']=='upgraded','remediation_identity_shape')
 need(value['capture_controls']==9 and type(value['capture_controls']) is int and type(value['duration_ms']) is int
  and 0<=value['duration_ms']<=95000 and type(value['version_exit_code']) is int and value['version_exit_code']==0,
  'remediation_identity_process')
 need(all(value[k] is False for k in ('version_timed_out','version_wait_delay_exceeded','version_stdout_overflow',
  'version_stderr_overflow','vulnerability_audit_completed','provider_accepted'))
  and all(value[k] is True for k in ('target_unchanged','sources_unchanged','graph_unchanged')),'remediation_identity_process')
 need(type(expected_files) is dict and set(expected_files)=={'upgraded-rclone.mod','upgraded-rclone.sum','remediation-variant.txt'}
  and all(type(v) is bytes for v in expected_files.values()) and expected_files['remediation-variant.txt']==(variant+'\n').encode(),
  'remediation_expected_sources')
 sources=value['source_files'];need(type(sources) is dict and set(sources)==set(expected_files),'remediation_source_files')
 for name,expected in expected_files.items():
  need(W.stamp(sources[name])==dict(bytes=len(expected),sha256=hashlib.sha256(expected).hexdigest()),'remediation_source_binding')
 need(W.stamp(value['graph_file'])['bytes']<=4*1024*1024,'remediation_graph_file')
 stdout=value['version_stdout']
 need(type(stdout) is str and len(stdout)<=4096 and all(c=='\n' or 32<=ord(c)<127 for c in stdout)
  and stdout.startswith('rclone v1.75.2-advisory-upgraded-'+variant+'\n')
  and all(x in stdout.splitlines() for x in ('- os/type: linux','- os/arch: amd64','- go/version: '+GO_VERSION))
  and value['version_stderr']=='','remediation_version')
 graph=admit_graph(value['graph'],catalog,expected_files['upgraded-rclone.mod'],variant)
 delta=admit_compiled(value['binary'],graph,baseline,variant)
 result=dict(value)
 result.update(scope='contained_upgraded_module_and_binary_identity',graph_modules=len(graph),
  compiled_modules=len(value['binary']['modules']),compiled_delta=delta,native_module_resolution_verified=True,
  native_build_identity_verified=True,native_compatibility_verified=False,exploitability_verified=False)
 return result

def wrapper_target(admitted):
 need(admitted.get('native_module_resolution_verified') is True and admitted.get('native_build_identity_verified') is True,
  'remediation_identity_unqualified')
 value=admitted['binary'];return dict(file=value['file'],modules=value['modules'])

def extraction_identity(admitted):
 value=wrapper_target(admitted)
 return dict(path=MODULE,go_version=GO_VERSION,goos='linux',goarch='amd64',main_versions=['','(devel)'],
  modules=[dict(path=r['path'],version=r['version'],replacement=None if not r['replacement']
   else dict(path=r['replacement'],versions=['','(devel)'])) for r in value['modules']])

def identity_stream(raw):
 """Keep the foundation and upgrade JSON reports separate and reject extra output."""
 need(type(raw) is bytes and 0<len(raw)<=262144+2*1024*1024,'remediation_identity_stream')
 try:
  text=raw.decode('utf-8');decoder=json.JSONDecoder(object_pairs_hook=unique,parse_constant=nonfinite)
  offset=0;reports=[]
  for maximum in (262144,2*1024*1024):
   while offset<len(text) and text[offset] in ' \t\r\n':offset+=1
   start=offset;value,offset=decoder.raw_decode(text,offset)
   fragment=text[start:offset].encode('utf-8')
   need(type(value) is dict and 0<len(fragment)<=maximum,'remediation_identity_stream')
   reports.append(fragment)
  need(all(c in ' \t\r\n' for c in text[offset:]),'remediation_identity_stream')
 except (ValueError,UnicodeError,RecursionError):raise ContractError('remediation_identity_stream') from None
 return tuple(reports)

FIXED_CONTROLS={('GO-2026-6860','golang.org/x/net'),('GO-2026-6866','golang.org/x/net'),
 ('GO-2026-6865','github.com/klauspost/compress'),('GO-2026-6888','github.com/andybalholm/brotli')}
RETAINED_CONTROL=('GO-2026-5932','golang.org/x/crypto')

def compare_scans(baseline,upgraded):
 """Compare already-admitted observations without discarding new findings."""
 for scan in (baseline,upgraded):
  need(type(scan) is dict and scan.get('scope')=='go_binary_advisory_observations' and scan.get('success') is True
   and type(scan.get('findings')) is list and all(scan.get(k) is False for k in ('reachability_verified',
    'exploitability_verified','vulnerability_audit_completed','provider_accepted')),'remediation_comparison_input')
 before={(r['id'],r['module']) for r in baseline['findings'] if r['level']=='module'}
 after={(r['id'],r['module']) for r in upgraded['findings'] if r['level']=='module'}
 need(FIXED_CONTROLS|{RETAINED_CONTROL}<=before and RETAINED_CONTROL in after,'remediation_comparison_controls')
 need(not FIXED_CONTROLS&after,'remediation_fixed_controls_remain')
 rows=lambda values:[dict(id=i,module=m) for i,m in sorted(values)]
 return dict(schema_version=1,scope='frozen_snapshot_version_filter_comparison',success=True,
  known_fixed_advisory_filters_verified=True,known_fixed_controls=rows(FIXED_CONTROLS),
  removed_module_findings=rows(before-after),retained_module_findings=rows(before&after),
  added_module_findings=rows(after-before),upgraded_findings=upgraded['findings'],
  upgraded_findings_by_level=upgraded['findings_by_level'],reachability_verified=False,exploitability_verified=False,
  vulnerability_audit_completed=False,provider_accepted=False)
