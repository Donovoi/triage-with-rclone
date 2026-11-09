import copy,json,unittest
from pathlib import Path
from audit_contract import ContractError
import remediation_bundle as R

HERE=Path(__file__).resolve().parent
class RemediationBundleTests(unittest.TestCase):
 def setUp(self):
  self.raw=(HERE/'remediation-assets-lock.json').read_bytes();self.lock=R.load_lock(self.raw)
  self.original_mod=(HERE/'fixtures/original-rclone.mod').read_bytes()
  self.original_sum=(HERE/'fixtures/original-rclone.sum').read_bytes()
  self.mod=(HERE/'upgraded-rclone.mod').read_bytes();self.sum=(HERE/'upgraded-rclone.sum').read_bytes()
  self.baseline=json.loads((HERE.parent/'hdfs-rclone-usage-build/assets-lock.json').read_bytes())
 def reject(self,mutator):
  value=copy.deepcopy(self.lock);mutator(value)
  with self.assertRaises(ContractError):R.validate_lock(value)
 def overlay(self,variant='original',**overrides):
  values=dict(original_mod=self.original_mod,original_sum=self.original_sum,mod=self.mod,sum_bytes=self.sum,variant=variant)
  values.update(overrides);return R.overlay_files(self.lock,**values)
 def test_exact_lock_and_asset_inventory(self):
  self.assertEqual(len(self.lock['assets']),36)
  self.assertEqual(sum(x['bytes'] for x in self.lock['assets']),60113133)
 def test_changed_lock_bytes_rejected(self):
  with self.assertRaises(ContractError):R.load_lock(self.raw+b' ')
 def test_non_bytes_lock_rejected(self):
  with self.assertRaises(ContractError):R.load_lock(self.raw.decode())
 def test_unknown_top_level_field_rejected(self):
  self.reject(lambda v:v.update(extra=True))
 def test_path_traversal_rejected(self):
  self.reject(lambda v:v['assets'][0].update(file='../outside.info'))
 def test_alternate_download_host_rejected(self):
  self.reject(lambda v:v['assets'][0].update(url='https://example.invalid/source'))
 def test_unknown_module_version_rejected(self):
  self.reject(lambda v:v['assets'][0].update(version='v1.2.8'))
 def test_boolean_asset_size_rejected(self):
  self.reject(lambda v:v['assets'][0].update(bytes=True))
 def test_oversized_archive_rejected(self):
  self.reject(lambda v:next(x for x in v['assets'] if x['kind']=='zip').update(bytes=64*1024*1024+1))
 def test_duplicate_asset_rejected(self):
  self.reject(lambda v:v['assets'].__setitem__(1,copy.deepcopy(v['assets'][0])))
 def test_missing_asset_rejected(self):
  self.reject(lambda v:v['assets'].pop())
 def test_metadata_only_input_cannot_become_source(self):
  self.reject(lambda v:next(x for x in v['assets'] if x['file']=='upgrade-011.mod').update(kind='zip',file='upgrade-011.zip'))
 def test_info_and_archive_hash_identity_must_match(self):
  self.reject(lambda v:next(x for x in v['assets'] if x['file']=='upgrade-000.info').update(h1='h1:'+'A'*43+'='))
 def test_nonstrict_sha_rejected(self):
  self.reject(lambda v:v['assets'][0].update(sha256='A'*64))
 def test_unplanned_crypto_boundary_rejected(self):
  self.reject(lambda v:next(x for x in v['version_updates'] if x['module']=='golang.org/x/crypto').update(candidate='v0.58.1-0.20261009181718-2f1f834330b2'))
 def test_original_overlay_keeps_exact_staged_bytes(self):
  value=self.overlay();self.assertEqual(value['upgraded-rclone.mod'],self.mod)
  self.assertEqual(value['upgraded-rclone.sum'],self.sum)
  self.assertEqual(value['remediation-variant.txt'],b'original\n')
 def test_patched_overlay_has_only_closed_hdfs_replacement(self):
  value=self.overlay('patched')
  self.assertEqual(value['upgraded-rclone.mod'],self.mod+b'\nreplace github.com/colinmarc/hdfs/v2 => /opt/input/patched-hdfs\n')
  self.assertEqual(value['upgraded-rclone.sum'],self.sum)
  self.assertEqual(value['remediation-variant.txt'],b'patched\n')
 def test_unknown_variant_rejected(self):
  with self.assertRaises(ContractError):self.overlay('other')
 def test_changed_baseline_mod_rejected(self):
  with self.assertRaises(ContractError):self.overlay(original_mod=self.original_mod+b'\n')
 def test_changed_baseline_sum_rejected(self):
  with self.assertRaises(ContractError):self.overlay(original_sum=self.original_sum+b'\n')
 def test_changed_candidate_mod_rejected(self):
  with self.assertRaises(ContractError):self.overlay(mod=self.mod+b'\n')
 def test_changed_candidate_sum_rejected(self):
  with self.assertRaises(ContractError):self.overlay(sum_bytes=self.sum+b'\n')
 def test_catalog_overrides_only_prepared_source_versions(self):
  catalog=R.source_catalog(self.baseline,self.lock);self.assertEqual(len(catalog),336)
  for module,_,version in R.UPDATES:self.assertEqual(catalog[module]['version'],version)
  for module,version in R.ADDITIONS:self.assertEqual(catalog[module]['version'],version)
  self.assertEqual(catalog['github.com/go-chi/chi/v5']['version'],'v5.3.1')
  self.assertEqual(catalog['github.com/google/go-cmp']['version'],'v0.7.0')
  self.assertEqual(catalog['golang.org/x/net']['version'],'v0.62.0')
 def test_changed_baseline_version_cannot_silently_rebase(self):
  next(x for x in self.baseline['assets'] if x['kind']=='zip' and x['module']=='golang.org/x/net')['version']='v0.61.0'
  with self.assertRaises(ContractError):R.source_catalog(self.baseline,self.lock)
 def test_missing_baseline_source_cannot_pass_catalog(self):
  self.baseline['assets']=[x for x in self.baseline['assets'] if not(x['kind']=='zip' and x['module']=='github.com/google/go-cmp')]
  with self.assertRaises(ContractError):R.source_catalog(self.baseline,self.lock)
 def test_missing_module_file_pin_rejected(self):
  self.baseline['assets']=[x for x in self.baseline['assets'] if not(x['kind']=='mod' and x['module']=='github.com/go-chi/chi/v5' and x['version']=='v5.3.1')]
  with self.assertRaises(ContractError):R.source_catalog(self.baseline,self.lock)
 def test_overlay_keeps_open_advisory_gaps_explicit(self):
  self.assertIn(b'golang.org/x/crypto v0.58.0',self.mod)
  self.assertIn(b'github.com/go-chi/chi/v5 v5.3.1',self.mod)
  self.assertNotIn(b'2f1f834330b2',self.mod)
if __name__=='__main__':unittest.main()
