import unittest
from audit_contract import ContractError
import audit_build as AB
import remediation_build as M

class RemediationBuild(unittest.TestCase):
 def setUp(self):
  self.original=AB.GO_ENV+' /opt/go/bin/go build '+AB.BUILD_FLAGS+' -modfile=/opt/input/original/go.mod -ldflags "-X github.com/rclone/rclone/fs.Version=v1.75.2-kerberos-original" -o /opt/probes/rclone-original .'
  self.patched=AB.GO_ENV+' /opt/go/bin/go build '+AB.BUILD_FLAGS+' -modfile=/opt/input/patched-rclone.mod -ldflags "-X github.com/rclone/rclone/fs.Version=v1.75.2-hdfs-context-patched" -o /opt/probes/rclone-patched .'
  self.input={'Dockerfile':b'FROM pinned\n','build.sh':('\n'.join(['#!/bin/sh',self.original,'cp frozen-rclone-patch target',self.patched,AB.PERMISSIONS])+'\n').encode(),
   'driver.sh':('#!/bin/sh\nset -eu\n'+M.IDENTITY+'\n').encode(),'patched-rclone.mod':b'original','patched-rclone.sum':b'sums'}
  self.files=AB.extend_build(self.input)
 def test_original_upgrade_precedes_source_mutation(self):
  lines=[l for l in M.extend_build(self.files,'original')['build.sh'].decode().splitlines() if 'GO_REMEDIATION_BUILD_PHASE=' not in l]
  i=next(i for i,l in enumerate(lines) if l.endswith(' -o /opt/probes/rclone-upgraded .'))
  self.assertTrue(lines[i-1].endswith(' -o /opt/probes/rclone-stripped .'))
  mutation=lines.index('cp frozen-rclone-patch target')
  self.assertLess(i,mutation)
  graph=next(j for j,l in enumerate(lines) if ' /opt/go/bin/go list ' in l)
  self.assertLess(graph,mutation)
  self.assertIn('/usr/bin/timeout --signal=TERM --kill-after=2s 10s /opt/probes/resolver-diagnostics',lines[graph+1])
 def test_patched_upgrade_follows_source_mutation(self):
  lines=[l for l in M.extend_build(self.files,'patched')['build.sh'].decode().splitlines() if 'GO_REMEDIATION_BUILD_PHASE=' not in l]
  i=lines.index(self.patched)
  self.assertTrue(lines[i+1].endswith(' -o /opt/probes/rclone-upgraded .'))
 def test_baseline_commands_are_preserved(self):
  for variant in ('original','patched'):
   lines=M.extend_build(self.files,variant)['build.sh'].decode().splitlines()
   self.assertIn(self.original,lines);self.assertIn(self.patched,lines)
   stripped=[l for l in self.files['build.sh'].decode().splitlines() if ' -o /opt/probes/rclone-stripped .' in l]
   self.assertTrue(set(stripped)<=set(lines))
 def test_resolver_is_offline_readonly_and_uses_overlay(self):
  lines=[l for l in M.extend_build(self.files,'original')['build.sh'].decode().splitlines() if 'GO_REMEDIATION_BUILD_PHASE=' not in l]
  resolver=next(l for l in lines if ' go list ' in l or '/go list ' in l)
  self.assertTrue(resolver.startswith(M.ENV));self.assertIn('GOPROXY=off GOSUMDB=off',resolver)
  self.assertIn('-m -e -json -mod=readonly -modfile=/opt/input/upgraded-rclone.mod all',resolver)
 def test_upgrade_build_uses_closed_variant_version(self):
  for variant in ('original','patched'):
   line=next(l for l in M.extend_build(self.files,variant)['build.sh'].decode().splitlines() if l.endswith(' -o /opt/probes/rclone-upgraded .'))
   self.assertTrue(line.startswith(M.ENV));self.assertIn(AB.BUILD_FLAGS,line);self.assertIn(M.MOD,line)
   self.assertIn('v1.75.2-advisory-upgraded-'+variant,line)
 def test_identity_reports_follow_foundation_success(self):
  driver=M.extend_build(self.files,'original')['driver.sh'].decode().splitlines()
  self.assertEqual(driver[-2],M.IDENTITY.removeprefix('exec '))
  self.assertEqual(driver[-1],'exec /usr/bin/timeout --signal=TERM --kill-after=2s 15s /opt/probes/audit-driver identity')
  self.assertIn('set -eu',driver)
 def test_native_reporter_sources_and_read_permissions(self):
  lines=[l for l in M.extend_build(self.files,'original')['build.sh'].decode().splitlines() if 'GO_REMEDIATION_BUILD_PHASE=' not in l]
  self.assertTrue(any(l.endswith('/opt/input/audit_driver.go /opt/input/remediation_driver.go') for l in lines))
  self.assertIn('chmod 0444 /opt/input/upgraded-rclone.mod /opt/input/upgraded-rclone.sum /opt/input/remediation-variant.txt',lines)
 def test_other_files_and_input_unchanged(self):
  before=dict(self.files);out=M.extend_build(self.files,'original')
  self.assertEqual(before,self.files)
  for name in ('Dockerfile','patched-rclone.mod','patched-rclone.sum'):self.assertEqual(out[name],before[name])
 def test_invalid_variant(self):
  for v in ('',None,True,'original;command'):
   with self.assertRaises(ContractError):M.extend_build(self.files,v)
 def test_missing_and_duplicate_anchors(self):
  for anchor in (self.original,self.patched,AB.PERMISSIONS):
   for replacement in ('',anchor+'\n'+anchor):
    files=dict(self.files);files['build.sh']=files['build.sh'].replace(anchor.encode(),replacement.encode())
    with self.assertRaises(ContractError):M.extend_build(files,'original')
 def test_reordered_baseline_builds(self):
  files=dict(self.files);lines=files['build.sh'].decode().splitlines();lines.remove(self.patched);lines.insert(0,self.patched)
  files['build.sh']='\n'.join(lines).encode()
  with self.assertRaises(ContractError):M.extend_build(files,'patched')
 def test_missing_or_trailed_identity_anchor(self):
  for raw in (b'changed',self.files['driver.sh']+b'echo unbound\n'):
   files=dict(self.files);files['driver.sh']=raw
   with self.assertRaises(ContractError):M.extend_build(files,'original')
 def test_extra_input_file_rejected(self):
  files=dict(self.files);files['unbound']=b'input'
  with self.assertRaises(ContractError):M.extend_build(files,'original')

class RemediationBuildDiagnostics(unittest.TestCase):
 def diagnostics(self,raw,allowed=None):
  import types
  foundation=types.SimpleNamespace(build_diagnostics=lambda data:dict(module_resolution_failed=b'module lookup disabled by GOPROXY=off' in data))
  return M.diagnostics(foundation,raw,allowed if allowed is not None else {('example.org/known','v1.2.3')})
 def test_coordinates_come_only_from_bound_inputs(self):
  raw=b'module example.org/root\ngo 1.26.0\nrequire (\n example.org/known v1.2.3 // indirect\n)\nrequire example.org/other v2.3.4\n'
  self.assertEqual(M.diagnostic_coordinates([raw],{('example.org/pinned','v0.1.0')}),
   {('example.org/known','v1.2.3'),('example.org/other','v2.3.4'),('example.org/pinned','v0.1.0')})
 def test_unknown_module_is_redacted(self):
  value=self.diagnostics(b'go: private.example/secret@v1.0.0: module lookup disabled by GOPROXY=off\n')
  self.assertEqual(value['module_errors'],[]);self.assertTrue(value['unbound_module_error_present'])
  self.assertNotIn('private',str(value))
 def test_known_missing_coordinate_is_retained(self):
  value=self.diagnostics(b'go: example.org/known@v1.2.3: module lookup disabled by GOPROXY=off\n')
  self.assertEqual(value['module_errors'],[dict(module='example.org/known',version='v1.2.3',kind='lookup_disabled')])
  self.assertFalse(value['unbound_module_error_present'])
 def test_missing_sum_is_distinguished(self):
  value=self.diagnostics(b'example.org/known@v1.2.3: missing go.sum entry for go.mod file\n')
  self.assertEqual(value['module_errors'][0]['kind'],'sum_missing')
 def test_versions_are_allowlisted_independently(self):
  value=self.diagnostics(b'example.org/known@v1.2.4: module lookup disabled by GOPROXY=off\n')
  self.assertEqual(value['module_errors'],[]);self.assertTrue(value['unbound_module_error_present'])
 def test_closed_phase_marker(self):
  value=self.diagnostics(b'#8 0.2 GO_REMEDIATION_BUILD_PHASE=upgraded_binary\nGO_REMEDIATION_BUILD_PHASE=private\n')
  self.assertEqual(value['remediation_phase'],'upgraded_binary')
 def test_source_errors_return_only_file_and_line(self):
  value=self.diagnostics(b'/opt/input/remediation_driver.go:99: private exception details\n')
  self.assertEqual(value['remediation_source_errors'],[dict(file='remediation_driver.go',line=99)])
  self.assertNotIn('private',str(value))
 def test_build_phase_precedes_every_go_command(self):
  base=RemediationBuild();base.setUp()
  for variant in ('original','patched'):
   lines=M.extend_build(base.files,variant)['build.sh'].decode().splitlines()
   for i,line in enumerate(lines):
    if ' /opt/go/bin/go ' in line:self.assertIn('GO_REMEDIATION_BUILD_PHASE=',lines[i-1])

class StructuredResolverDiagnostics(unittest.TestCase):
 def admit(self,raw,allowed=None):
  import types
  foundation=types.SimpleNamespace(build_diagnostics=lambda data:dict(module_resolution_failed=False))
  return M.diagnostics(foundation,raw,allowed if allowed is not None else {('example.org/known','v1.2.3')})
 def test_structured_error_coordinate_is_admitted(self):
  raw=b'#8 0.200 GO_REMEDIATION_MODULE_ERROR=example.org/known@v1.2.3:lookup_disabled\nGO_REMEDIATION_GRAPH_STATUS=errors\n'
  value=self.admit(raw)
  self.assertEqual(value['module_errors'],[dict(module='example.org/known',version='v1.2.3',kind='lookup_disabled')])
  self.assertEqual(value['resolver_graph_status'],'errors')
 def test_unbound_coordinate_is_never_exported(self):
  value=self.admit(b'GO_REMEDIATION_MODULE_ERROR=private.example/secret@v1.0.0:lookup_disabled\n')
  self.assertEqual(value['module_errors'],[]);self.assertTrue(value['unbound_module_error_present']);self.assertNotIn('private',str(value))
 def test_explicit_unbound_marker(self):
  value=self.admit(b'GO_REMEDIATION_MODULE_ERROR=unbound\n')
  self.assertTrue(value['unbound_module_error_present']);self.assertEqual(value['module_errors'],[])
 def test_arbitrary_error_kind_rejected(self):
  with self.assertRaises(ContractError):self.admit(b'GO_REMEDIATION_MODULE_ERROR=example.org/known@v1.2.3:private_details\n')
 def test_evidence_flag_does_not_bypass_native_failure_gate(self):
  base=RemediationBuild();base.setUp()
  lines=M.extend_build(base.files,'original')['build.sh'].decode().splitlines()
  graph=next(i for i,l in enumerate(lines) if '/go list ' in l)
  self.assertIn(' -e -json ',lines[graph])
  self.assertIn('/usr/bin/timeout --signal=TERM --kill-after=2s 10s /opt/probes/resolver-diagnostics',lines[graph+1])
  self.assertTrue(any(l.endswith(' -o /opt/probes/resolver-diagnostics /opt/input/resolver_diagnostics.go') for l in lines[:graph]))

class ResolverDiagnosticBounds(unittest.TestCase):
 def inspect(self,raw):
  import types
  foundation=types.SimpleNamespace(build_diagnostics=lambda value:dict(module_resolution_failed=False))
  return M.diagnostics(foundation,raw,{('example.org/known','v1.2.3')})
 def test_closed_invalid_stage_and_counts_survive(self):
  value=self.inspect(b'GO_REMEDIATION_GRAPH_STATUS=invalid\nGO_REMEDIATION_DIAGNOSTIC_STAGE=graph_read\nGO_REMEDIATION_GRAPH_BYTES=0\nGO_REMEDIATION_GRAPH_MODULES=0\nGO_REMEDIATION_ERROR_MODULES=0\nGO_REMEDIATION_COORDINATES=1426\n')
  self.assertEqual(value['resolver_graph_status'],'invalid');self.assertEqual(value['resolver_diagnostic_stage'],'graph_read')
  self.assertEqual(value['resolver_diagnostic_counts'],dict(graph_bytes=0,graph_modules=0,error_modules=0,coordinates=1426))
 def test_truncated_errors_remain_explicit(self):
  value=self.inspect(b'GO_REMEDIATION_MODULE_ERROR=example.org/known@v1.2.3:lookup_disabled\nGO_REMEDIATION_GRAPH_STATUS=errors_truncated\nGO_REMEDIATION_ERROR_MODULES=64\n')
  self.assertEqual(value['resolver_graph_status'],'errors_truncated');self.assertEqual(value['resolver_diagnostic_counts']['error_modules'],64)
  self.assertEqual(len(value['module_errors']),1)
 def test_unrecognized_stage_never_escapes(self):
  value=self.inspect(b'GO_REMEDIATION_DIAGNOSTIC_STAGE=private_details\n')
  self.assertIsNone(value['resolver_diagnostic_stage']);self.assertNotIn('private',str(value))
 def test_counts_cannot_exceed_bounds(self):
  for key,value in ((b'GRAPH_BYTES',4194305),(b'GRAPH_MODULES',2049),(b'ERROR_MODULES',2049),(b'COORDINATES',20001)):
   with self.assertRaises(ContractError):self.inspect(b'GO_REMEDIATION_'+key+b'='+str(value).encode()+b'\n')
 def test_only_last_closed_state_is_reported(self):
  value=self.inspect(b'GO_REMEDIATION_DIAGNOSTIC_STAGE=graph_read\nGO_REMEDIATION_DIAGNOSTIC_STAGE=graph_summary\nGO_REMEDIATION_GRAPH_MODULES=1\nGO_REMEDIATION_GRAPH_MODULES=300\n')
  self.assertEqual(value['resolver_diagnostic_stage'],'graph_summary');self.assertEqual(value['resolver_diagnostic_counts']['graph_modules'],300)

class ResolverInventoryDiagnostics(unittest.TestCase):
 def inspect(self,rows,trailer=b''):
  import json,types
  raw=b''.join(b'GO_REMEDIATION_GRAPH_ROW='+json.dumps(row).encode()+b'\n' for row in rows)+trailer
  return M.diagnostics(types.SimpleNamespace(build_diagnostics=lambda value:dict(module_resolution_failed=False)),raw,{('example.org/known','v1.2.3')})
 def row(self,**changes):
  return dict(dict(module='example.org/known',version='v1.2.3',kind='lookup_disabled',has_sum=False,has_go_mod_sum=True),**changes)
 def test_complete_error_inventory_has_explicit_bounds(self):
  row=self.row();value=self.inspect([row],b'GO_REMEDIATION_GRAPH_STATUS=errors\nGO_REMEDIATION_GRAPH_MODULES=2\nGO_REMEDIATION_ERROR_MODULES=1\n')
  self.assertEqual(value['resolver_inventory'],[row]);self.assertTrue(value['resolver_inventory_complete'])
 def test_unknown_coordinates_are_redacted(self):
  value=self.inspect([self.row(module='private.example/secret')]);self.assertEqual(value['resolver_inventory'],[])
  self.assertTrue(value['unbound_module_error_present']);self.assertNotIn('private',str(value))
 def test_identical_repeated_log_rows_are_deduplicated(self):
  row=self.row();self.assertEqual(self.inspect([row,row])['resolver_inventory'],[row])
 def test_conflicting_rows_are_rejected(self):
  with self.assertRaises(ContractError):self.inspect([self.row(),self.row(kind='none')])
 def test_inventory_type_and_field_checks(self):
  for row in (self.row(kind='private_details'),self.row(has_sum=1),self.row(extra='private'),self.row(version=[])):
   with self.assertRaises(ContractError):self.inspect([row])
 def test_missing_counts_cannot_establish_completeness(self):
  self.assertFalse(self.inspect([self.row()])['resolver_inventory_complete'])
 def test_error_count_mismatch_cannot_establish_completeness(self):
  trailer=b'GO_REMEDIATION_GRAPH_STATUS=complete\nGO_REMEDIATION_GRAPH_MODULES=2\nGO_REMEDIATION_ERROR_MODULES=0\n'
  self.assertFalse(self.inspect([self.row()],trailer)['resolver_inventory_complete'])
 def test_marker_count_is_bounded(self):
  with self.assertRaises(ContractError):self.inspect([self.row()]*2049)
 def test_duplicate_json_fields_are_rejected(self):
  raw=b'GO_REMEDIATION_GRAPH_ROW={"module":"example.org/known","module":"private"}\n'
  with self.assertRaises(ContractError):self.inspect([],raw)
