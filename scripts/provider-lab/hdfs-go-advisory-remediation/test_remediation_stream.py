import json,unittest
from audit_contract import ContractError
from remediation_contract import identity_stream
from audit_container import variant_cases,command_args,IDENTITY_LIMIT

class RemediationStream(unittest.TestCase):
 def test_two_reports_are_preserved(self):
  first=b'{"foundation": true}';second=b'{"upgrade": [1,2]}'
  self.assertEqual(identity_stream(b' \n'+first+b'\n\t'+second+b'\n'),(first,second))
 def test_empty_missing_extra_or_nonobject_reports_rejected(self):
  for raw in (b'',b'{}',b'{}{}{}',b'[]{}',b'{}null',b'{}{}noise',b'{}\x0b{}'):
   with self.subTest(raw=raw),self.assertRaises(ContractError):identity_stream(raw)
 def test_duplicate_keys_nonfinite_and_invalid_encoding_rejected(self):
  for raw in (b'{"x":1,"x":2}{}',b'{}{"x":NaN}',b'{}{"x":Infinity}',b'{}{"x":"\xff"}'):
   with self.assertRaises(ContractError):identity_stream(raw)
 def test_each_report_has_its_own_bound(self):
  for raw in (json.dumps({'x':'a'*262144}).encode()+b'{}',b'{}'+json.dumps({'x':'a'*(2*1024*1024)}).encode()):
   with self.assertRaises(ContractError):identity_stream(raw)
 def test_total_identity_budget_is_explicit(self):
  self.assertEqual(IDENTITY_LIMIT,262144+2*1024*1024)
 def test_each_variant_uses_eight_wrappers(self):
  for variant in ('original','patched'):
   cases=variant_cases(variant);self.assertEqual(len(cases),8);self.assertEqual(len(set(cases)),8)
   self.assertEqual(cases[-4:],(('extract',variant),('scan',variant),('extract','upgraded'),('scan','upgraded')))
 def test_invalid_variant_rejected(self):
  for v in ('upgraded','',None,True):
   with self.assertRaises(Exception):variant_cases(v)
 def test_upgrade_container_retains_isolation(self):
  run='a'*32;image='sha256:'+'b'*64
  args=command_args('go-binary-audit-'+run+'-scan-upgraded',image,run,'scan','upgraded')
  for key,val in (('--network','none'),('--user','10001:10001'),('--memory','2g'),('--cpus','2'),('--pids-limit','128')):
   self.assertEqual(args[args.index(key)+1],val)
  self.assertIn('--read-only',args);self.assertIn('--cap-drop',args)
  self.assertEqual(args[-3:],['/opt/probes/audit-driver','scan','upgraded'])
