import copy,hashlib,json,unittest
from pathlib import Path
from audit_contract import ContractError
import remediation_bundle as B
import remediation_contract as R
import graph_metadata as G

HERE=Path(__file__).resolve().parent
def fingerprint(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
class RemediationIdentityTests(unittest.TestCase):
 def setUp(self):
  self.lock=B.load_lock((HERE/'remediation-assets-lock.json').read_bytes())
  baseline=json.loads((HERE.parent/'hdfs-rclone-usage-build/assets-lock.json').read_bytes())
  source=B.source_catalog(baseline,self.lock);raw=(HERE/'graph-metadata-snapshot.json').read_bytes()
  versions,_=G.load_snapshot(raw)
  mod_sums={(r['module'],r['version']):r['h1'] for lock in (baseline,self.lock) for r in lock['assets'] if r['kind']=='mod'}
  self.catalog=G.extend_catalog(source,raw,(HERE/'upgraded-rclone.sum').read_bytes(),mod_sums,set(versions.items()))
  self.baselines={x['variant']:x for x in json.loads((HERE/'fixtures/qualified-foundation-binaries.json').read_bytes())}
 def fixture(self,variant='original'):
  files=B.overlay_files(self.lock,(HERE/'fixtures/original-rclone.mod').read_bytes(),(HERE/'fixtures/original-rclone.sum').read_bytes(),
   (HERE/'upgraded-rclone.mod').read_bytes(),(HERE/'upgraded-rclone.sum').read_bytes(),variant)
  graph=[]
  for module,c in sorted(self.catalog.items()):
   row=dict({k:v for k,v in c.items() if k!='source_available'},main=False,indirect=True,go_version='',replacement='')
   if module==B.MODULE:row.update(version='',sum='',go_mod_sum='',main=True,indirect=False,go_version='1.26.0')
   elif variant=='patched' and module==R.HDFS:row.update(sum='',go_mod_sum='',replacement=R.LOCAL_HDFS)
   graph.append(row)
  mapped={x['path']:x for x in graph};baseline=self.baselines[variant]
  modules=[{k:mapped[x['path']][k] for k in ('path','version','sum','replacement')} for x in baseline['modules']]
  binary=dict(file=dict(bytes=120000000,sha256='a'*64),go_version='go1.26.10',path=B.MODULE,
   main=dict(path=B.MODULE,version='(devel)',sum='',replacement=''),
   settings={'GOOS':'linux','GOARCH':'amd64','CGO_ENABLED':'0','-buildmode':'exe','-trimpath':'true'},modules=modules)
  value=dict(schema_version=1,success=True,error='none',variant=variant,target='upgraded',binary=binary,graph=graph,
   source_files={k:fingerprint(v) for k,v in files.items()},graph_file=dict(bytes=123456,sha256='b'*64),
   version_stdout='rclone v1.75.2-advisory-upgraded-'+variant+'\n- os/type: linux\n- os/arch: amd64\n- go/version: go1.26.10\n',
   version_stderr='',version_exit_code=0,version_timed_out=False,version_wait_delay_exceeded=False,
   version_stdout_overflow=False,version_stderr_overflow=False,target_unchanged=True,sources_unchanged=True,graph_unchanged=True,
   capture_controls=9,duration_ms=1000,vulnerability_audit_completed=False,provider_accepted=False)
  return value,files,baseline
 def admit(self,value,files,baseline):
  return R.admit_identity(json.dumps(value).encode(),value['variant'],self.catalog,files,baseline)
 def reject(self,mutator,variant='original'):
  value,files,baseline=self.fixture(variant);mutator(value)
  with self.assertRaises(ContractError):self.admit(value,files,baseline)
 def row(self,value,module='golang.org/x/net'):return next(x for x in value['graph'] if x['path']==module)
 def test_both_variants_bind_graph_and_binary_without_acceptance(self):
  for variant in ('original','patched'):
   value,files,baseline=self.fixture(variant);result=self.admit(value,files,baseline)
   self.assertTrue(result['native_module_resolution_verified']);self.assertTrue(result['native_build_identity_verified'])
   self.assertFalse(result['native_compatibility_verified']);self.assertFalse(result['exploitability_verified'])
   self.assertFalse(result['vulnerability_audit_completed']);self.assertFalse(result['provider_accepted'])
   self.assertEqual(result['graph_modules'],654)
   self.assertEqual(len(R.wrapper_target(result)['modules']),242)
   self.assertEqual(R.extraction_identity(result)['path'],B.MODULE)
 def test_full_selected_source_inventory_is_required(self):
  value,files,baseline=self.fixture();module='github.com/pelletier/go-toml'
  self.assertNotIn(module,{x['path'] for x in value['binary']['modules']})
  value['graph']=[x for x in value['graph'] if x['path']!=module]
  with self.assertRaises(ContractError):self.admit(value,files,baseline)
 def test_metadata_only_graph_nodes_are_retained_with_recorded_sums(self):
  value,files,baseline=self.fixture();result=self.admit(value,files,baseline)
  metadata=[x for x in result['graph'] if not self.catalog[x['path']]['source_available']]
  self.assertEqual(len(metadata),318);self.assertTrue(all(x['sum']=='' for x in metadata))
  self.assertEqual(sum(bool(x['go_mod_sum']) for x in metadata),9)
 def test_missing_metadata_only_node_is_rejected(self):
  module=next(m for m,c in self.catalog.items() if not c['source_available'])
  self.reject(lambda v:v.update(graph=[x for x in v['graph'] if x['path']!=module]))
 def test_metadata_only_compiled_module_is_explicitly_rejected(self):
  value,files,baseline=self.fixture();graph=R.admit_graph(value['graph'],self.catalog,files['upgraded-rclone.mod'],'original')
  module=next(m for m,c in self.catalog.items() if not c['source_available'])
  graph[module]['sum']='h1:'+'A'*43+'='
  row={k:graph[module][k] for k in ('path','version','sum','replacement')}
  value['binary']['modules'].append(row);value['binary']['modules'].sort(key=lambda x:x['path'])
  with self.assertRaisesRegex(ContractError,'remediation_compiled_metadata_only'):
   R.admit_compiled(value['binary'],graph,baseline,'original')
 def test_old_dependency_version_rejected(self):
  self.reject(lambda v:self.row(v).update(version='v0.60.0'))
 def test_wrong_archive_hash_rejected(self):
  self.reject(lambda v:self.row(v).update(sum='h1:'+'A'*43+'='))
 def test_wrong_module_file_hash_rejected(self):
  self.reject(lambda v:self.row(v).update(go_mod_sum='h1:'+'A'*43+'='))
 def test_unknown_module_rejected(self):
  self.reject(lambda v:self.row(v).update(path='example.invalid/unpinned'))
 def test_duplicate_module_rejected(self):
  self.reject(lambda v:v['graph'].__setitem__(1,copy.deepcopy(v['graph'][0])))
 def test_unsorted_graph_rejected(self):
  self.reject(lambda v:v['graph'].reverse())
 def test_missing_required_module_rejected(self):
  self.reject(lambda v:v.update(graph=[x for x in v['graph'] if x['path']!='golang.org/x/net']))
 def test_missing_main_module_rejected(self):
  self.reject(lambda v:v.update(graph=[x for x in v['graph'] if x['path']!=B.MODULE]))
 def test_wrong_root_go_version_rejected(self):
  self.reject(lambda v:self.row(v,B.MODULE).update(go_version='1.25.0'))
 def test_integer_main_flag_rejected(self):
  self.reject(lambda v:self.row(v).update(main=0))
 def test_remote_replacement_rejected(self):
  self.reject(lambda v:self.row(v).update(replacement='example.invalid/module'))
 def test_original_cannot_claim_local_hdfs_replacement(self):
  self.reject(lambda v:self.row(v,R.HDFS).update(replacement=R.LOCAL_HDFS,sum='',go_mod_sum=''))
 def test_patched_requires_closed_hdfs_replacement(self):
  self.reject(lambda v:self.row(v,R.HDFS).update(replacement=''),'patched')
 def test_patched_cannot_use_another_local_path(self):
  self.reject(lambda v:self.row(v,R.HDFS).update(replacement='/tmp/other'),'patched')
 def test_baseline_binary_cannot_masquerade_as_upgrade(self):
  value,files,baseline=self.fixture();value['binary']['file']=dict(bytes=baseline['bytes'],sha256=baseline['sha256'])
  with self.assertRaises(ContractError):self.admit(value,files,baseline)
 def test_compiled_metadata_must_match_resolved_graph(self):
  self.reject(lambda v:next(x for x in v['binary']['modules'] if x['path']=='golang.org/x/net').update(version='v0.60.0'))
 def test_compiled_critical_module_cannot_be_omitted(self):
  self.reject(lambda v:v['binary'].update(modules=[x for x in v['binary']['modules'] if x['path']!='github.com/andybalholm/brotli']))
 def test_alternate_compiler_identity_rejected(self):
  self.reject(lambda v:v['binary'].update(go_version='go1.26.9'))
 def test_versioned_main_binary_rejected(self):
  self.reject(lambda v:v['binary']['main'].update(version='v1.75.2'))
 def test_changed_staged_module_file_rejected(self):
  self.reject(lambda v:v['source_files']['upgraded-rclone.mod'].update(sha256='c'*64))
 def test_changed_staged_checksums_rejected(self):
  self.reject(lambda v:v['source_files']['upgraded-rclone.sum'].update(bytes=1))
 def test_source_change_flag_rejected(self):
  self.reject(lambda v:v.update(sources_unchanged=False))
 def test_graph_change_flag_rejected(self):
  self.reject(lambda v:v.update(graph_unchanged=False))
 def test_target_change_flag_rejected(self):
  self.reject(lambda v:v.update(target_unchanged=False))
 def test_timeout_rejected(self):
  self.reject(lambda v:v.update(version_timed_out=True))
 def test_output_overflow_rejected(self):
  self.reject(lambda v:v.update(version_stdout_overflow=True))
 def test_nonzero_version_exit_rejected(self):
  self.reject(lambda v:v.update(version_exit_code=1))
 def test_version_stderr_rejected(self):
  self.reject(lambda v:v.update(version_stderr='unexpected'))
 def test_wrong_platform_version_output_rejected(self):
  self.reject(lambda v:v.update(version_stdout=v['version_stdout'].replace('- os/arch: amd64','- os/arch: arm64')))
 def test_boolean_duration_rejected(self):
  self.reject(lambda v:v.update(duration_ms=True))
 def test_broad_acceptance_claim_rejected(self):
  self.reject(lambda v:v.update(vulnerability_audit_completed=True))
 def test_unknown_report_field_rejected(self):
  self.reject(lambda v:v.update(extra=True))
 def test_unqualified_identity_cannot_supply_wrapper_target(self):
  with self.assertRaises(ContractError):R.wrapper_target(dict(native_module_resolution_verified=False,native_build_identity_verified=True))
 def test_duplicate_json_keys_rejected(self):
  value,files,baseline=self.fixture();raw=json.dumps(value).encode();raw=b'{"schema_version":1,'+raw[1:]
  with self.assertRaises(ContractError):R.admit_identity(raw,'original',self.catalog,files,baseline)
 def test_nonfinite_json_rejected(self):
  value,files,baseline=self.fixture();value['duration_ms']=float('nan')
  with self.assertRaises(ContractError):self.admit(value,files,baseline)
 def test_extra_root_requirement_rejected(self):
  value,files,baseline=self.fixture();mod=files['upgraded-rclone.mod']+b'\nrequire example.invalid/unpinned v1.0.0\n'
  with self.assertRaises(ContractError):R.admit_graph(value['graph'],self.catalog,mod,'original')
 def test_changed_root_requirement_version_rejected(self):
  value,files,baseline=self.fixture();mod=files['upgraded-rclone.mod'].replace(b'golang.org/x/net v0.62.0',b'golang.org/x/net v0.63.0')
  with self.assertRaises(ContractError):R.admit_graph(value['graph'],self.catalog,mod,'original')
 def test_wrong_variant_baseline_rejected(self):
  value,files,_=self.fixture()
  with self.assertRaises(ContractError):self.admit(value,files,self.baselines['patched'])
 def test_changed_debug_directive_rejected(self):
  value,files,baseline=self.fixture();mod=files['upgraded-rclone.mod'].replace(b'godebug x509negativeserial=1',b'godebug x509negativeserial=0')
  with self.assertRaises(ContractError):R.admit_graph(value['graph'],self.catalog,mod,'original')
 def test_duplicate_debug_directive_rejected(self):
  value,files,baseline=self.fixture();mod=files['upgraded-rclone.mod']+b'\ngodebug x509negativeserial=1\n'
  with self.assertRaises(ContractError):R.admit_graph(value['graph'],self.catalog,mod,'original')
if __name__=='__main__':unittest.main()

class RemediationComparisonTests(unittest.TestCase):
 def scan(self,controls):
  return dict(scope='go_binary_advisory_observations',success=True,
   findings=[dict(id=i,module=m,level='module') for i,m in sorted(controls)],findings_by_level={'module':len(controls),'package':0,'symbol':0},
   reachability_verified=False,exploitability_verified=False,vulnerability_audit_completed=False,provider_accepted=False)
 def test_fixed_filters_removed_and_crypto_retained(self):
  out=R.compare_scans(self.scan(R.FIXED_CONTROLS|{R.RETAINED_CONTROL}),self.scan({R.RETAINED_CONTROL}))
  self.assertTrue(out['known_fixed_advisory_filters_verified']);self.assertEqual(len(out['removed_module_findings']),4)
  self.assertEqual(len(out['retained_module_findings']),1);self.assertFalse(out['vulnerability_audit_completed'])
 def test_unexpected_new_finding_is_preserved(self):
  extra=('GO-2026-9999','example.org/another')
  out=R.compare_scans(self.scan(R.FIXED_CONTROLS|{R.RETAINED_CONTROL}),self.scan({R.RETAINED_CONTROL,extra}))
  self.assertEqual(out['added_module_findings'],[dict(id=extra[0],module=extra[1])]);self.assertEqual(len(out['upgraded_findings']),2)
 def test_missing_positive_control_rejected(self):
  for before,after in ((R.FIXED_CONTROLS,{R.RETAINED_CONTROL}),(R.FIXED_CONTROLS|{R.RETAINED_CONTROL},set())):
   with self.assertRaises(ContractError):R.compare_scans(self.scan(before),self.scan(after))
 def test_remaining_known_fixed_finding_rejected(self):
  with self.assertRaises(ContractError):
   R.compare_scans(self.scan(R.FIXED_CONTROLS|{R.RETAINED_CONTROL}),self.scan({R.RETAINED_CONTROL,next(iter(R.FIXED_CONTROLS))}))
 def test_unadmitted_scan_rejected(self):
  before=self.scan(R.FIXED_CONTROLS|{R.RETAINED_CONTROL});before['success']=False
  with self.assertRaises(ContractError):R.compare_scans(before,self.scan({R.RETAINED_CONTROL}))
