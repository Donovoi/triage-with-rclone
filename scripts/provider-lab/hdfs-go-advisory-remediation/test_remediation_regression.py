import copy,hashlib,json,unittest
from audit_contract import ContractError
import remediation_regression as R
from audit_container import command_args
import remediation_build as BUILD
import test_remediation_build as TEST_BUILD

def stamp(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def fixture(variant='original'):
 target=dict(bytes=120000000,sha256='a'*64)
 upgraded=dict(native_module_resolution_verified=True,native_build_identity_verified=True,binary=dict(file=target,modules=[]))
 cases=R.CASES+(['upgraded_hdfs_context'] if variant=='patched' else [])
 outputs=[b'fixture.txt\n',b'',b'',R.PAYLOAD]+([b'controlled context output'] if variant=='patched' else [])
 value=dict(schema_version=1,success=True,error='none',variant=variant,target_before=target,target_after=target,
  target_unchanged=True,payload=stamp(R.PAYLOAD),brotli_archive=stamp(b'archive'),zstd_object=stamp(b'compressed'),
  context_binary=dict(bytes=12000000,sha256='b'*64) if variant=='patched' else None,context_tests=11 if variant=='patched' else 0,
  http_requests=1,server_joined=True,controls=R.CONTROLS+(['upgraded_hdfs_context'] if variant=='patched' else []),children=[],
  duration_ms=1000,vulnerability_audit_completed=False,provider_accepted=False)
 for case,out in zip(cases,outputs):
  value['children'].append(dict(case=case,exit_code=0,timed_out=False,wait_delay_exceeded=False,stdout_overflow=False,
   stderr_overflow=False,stdout=stamp(out),stderr=stamp(b''),duration_ms=10))
 return value,upgraded
class RemediationRegression(unittest.TestCase):
 def admit(self,value,upgraded,code=0):return R.admit(json.dumps(value).encode(),value['variant'],upgraded,code)
 def reject(self,change,variant='original'):
  value,upgraded=fixture(variant);change(value)
  with self.assertRaises(ContractError):self.admit(value,upgraded)
 def test_both_variants_admitted_with_limited_claims(self):
  for variant in ('original','patched'):
   value,upgraded=fixture(variant);out=self.admit(value,upgraded)
   self.assertTrue(out['native_compatibility_controls_verified']);self.assertFalse(out['malformed_input_tested'])
   self.assertFalse(out['exploitability_verified']);self.assertFalse(out['provider_acceptance_verified'])
 def test_failed_or_extra_report(self):
  for key,value in [('success',False),('error','unexpected'),('extra',True),('schema_version',True)]:
   self.reject(lambda v,k=key,x=value:v.__setitem__(k,x))
 def test_native_claims_rejected(self):
  for key in ('provider_accepted','vulnerability_audit_completed'):
   self.reject(lambda v,k=key:v.__setitem__(k,True))
 def test_unadmitted_binary_rejected(self):
  value,upgraded=fixture();upgraded['native_build_identity_verified']=False
  with self.assertRaises(ContractError):self.admit(value,upgraded)
 def test_changed_binary_rejected(self):
  self.reject(lambda v:v.__setitem__('target_after',dict(bytes=120000000,sha256='c'*64)))
 def test_report_false_guarantees_rejected(self):
  for key in ('target_unchanged','server_joined'):self.reject(lambda v,k=key:v.__setitem__(k,False))
 def test_payload_mismatch_rejected(self):self.reject(lambda v:v.__setitem__('payload',stamp(b'wrong')))
 def test_missing_reordered_or_extra_controls(self):
  for controls in ([],list(reversed(R.CONTROLS)),R.CONTROLS+['invented']):
   self.reject(lambda v,x=controls:v.__setitem__('controls',x))
 def test_http_request_bound(self):
  for number in (0,17,True):self.reject(lambda v,x=number:v.__setitem__('http_requests',x))
 def test_context_only_allowed_for_patched(self):self.reject(lambda v:v.__setitem__('context_binary',dict(bytes=12000000,sha256='b'*64)))
 def test_patched_requires_eleven_tests(self):self.reject(lambda v:v.__setitem__('context_tests',10),'patched')
 def test_patched_requires_native_test_binary(self):self.reject(lambda v:v.__setitem__('context_binary',None),'patched')
 def test_child_timeout_overflow_and_exit_rejected(self):
  for key,value in [('timed_out',True),('wait_delay_exceeded',True),('stdout_overflow',True),('stderr_overflow',True),('exit_code',1),('duration_ms',13001)]:
   self.reject(lambda v,k=key,x=value:v['children'][0].__setitem__(k,x))
 def test_child_stderr_rejected(self):self.reject(lambda v:v['children'][0].__setitem__('stderr',stamp(b'error')))
 def test_wrong_roundtrip_rejected(self):self.reject(lambda v:v['children'][3].__setitem__('stdout',stamp(b'wrong')))
 def test_missing_child_rejected(self):self.reject(lambda v:v['children'].pop())
 def test_child_output_binding_rejected(self):self.reject(lambda v:v['children'][0].__setitem__('stdout',dict(bytes=0,sha256='d'*64)))
 def test_total_deadline(self):self.reject(lambda v:v.__setitem__('duration_ms',85001))
 def test_nonzero_container_exit(self):
  value,upgraded=fixture()
  with self.assertRaises(ContractError):self.admit(value,upgraded,1)
 def test_regression_container_command(self):
  run='a'*32;image='sha256:'+'b'*64
  args=command_args('go-binary-audit-'+run+'-regression-upgraded',image,run,'regression','upgraded')
  self.assertEqual(args[-1],'/opt/probes/remediation-regression');self.assertEqual(args[args.index('--network')+1],'none')
 def test_regression_build_uses_upgraded_modules(self):
  base=TEST_BUILD.RemediationBuild();base.setUp()
  for variant in ('original','patched'):
   lines=BUILD.extend_build(base.files,variant)['build.sh'].decode().splitlines()
   line=next(l for l in lines if ' -o /opt/probes/remediation-regression ' in l)
   self.assertTrue(line.startswith(BUILD.ENV));self.assertIn(BUILD.MOD,line)
   context=[l for l in lines if ' -o /opt/probes/upgraded-context-tests ' in l]
   self.assertEqual(len(context),1 if variant=='patched' else 0)
   if context:self.assertIn(BUILD.MOD,context[0])
