"""Filesystem ownership tests with a fake already-verified asset backend."""
import hashlib,json,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
from audit_contract import ContractError,need
import remediation_bundle as B
import remediation_merge as M

HERE=Path(__file__).resolve().parent
class RemediationMergeTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(dir=HERE);self.addCleanup(self.temp.cleanup)
  self.context=Path(self.temp.name)/'context';self.root=self.context/'remediation';self.root.mkdir(parents=True)
  (self.context/'module-cache/cache/download').mkdir(parents=True)
  self.sentinel=self.context/'module-cache/cache/download/baseline.txt';self.sentinel.write_bytes(b'preserve existing cache')
  self.lock=B.load_lock((HERE/'remediation-assets-lock.json').read_bytes());self.verified={}
  for row in self.lock['assets']:
   rels=['assets/'+row['file'],B.cache_relative(row)]
   if row['kind']=='zip':rels.append(B.cache_relative(row)[:-4]+'.ziphash')
   for rel in rels:
    p=self.root/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'inert cache fixture\n')
    self.verified[rel]=self.sha(p.read_bytes())
  prepared=dict(schema_version=1,scope='go_remediation_source_preparation',module=B.MODULE,version=B.VERSION,
   assets=B.ASSETS,asset_bytes=B.ASSET_BYTES,archives=B.ARCHIVES,members=B.MEMBERS,expanded_bytes=B.EXPANDED,
   native_build_verified=False,module_resolution_verified=False,vulnerability_audit_completed=False)
  status=dict(schema_version=1,phase='complete',asset_index=-1,processed_assets=36,error='none',http_status=0)
  self.expected=dict(self.verified)
  for name,value in [('prepared.json',prepared),('worker-status.json',status)]:self.bind_report(name,value)
  def directory(p,identity=None):
   need(p.is_dir() and not p.is_symlink(),'test_directory');st=p.stat();actual=(st.st_dev,st.st_ino)
   need(identity is None or identity==actual,'test_identity');return actual
  def regular(p,maximum):
   need(p.is_file() and not p.is_symlink() and p.stat().st_size<=maximum,'test_regular');return p.stat()
  def read(p,maximum):regular(p,maximum);return p.read_bytes()
  self.C=types.SimpleNamespace(directory=directory,regular=regular,read=read,parse=lambda b,n:json.loads(b))
  self.R=types.SimpleNamespace(tree_hashes=lambda C,p:self.tree(p))
  self.backend=patch.object(M.BUNDLE,'verify_prepared',return_value=self.verified);self.backend.start();self.addCleanup(self.backend.stop)
 def sha(self,raw):return hashlib.sha256(raw).hexdigest()
 def tree(self,root):
  result={}
  for p in root.rglob('*'):
   need(not p.is_symlink(),'test_symlink')
   if p.is_file():result[p.relative_to(root).as_posix()]=self.sha(p.read_bytes())
  return result
 def bind_report(self,name,value):
  raw=json.dumps(value).encode();(self.root/name).write_bytes(raw);self.expected[name]=self.sha(raw)
 def merge(self,**changes):
  values=dict(C=self.C,R=self.R,B=None,context=self.context,root=self.root,lock=self.lock,expected_tree=self.expected)
  values.update(changes);return M.merge_prepared(**values)
 def test_transfers_only_verified_cache_files_and_preserves_baseline(self):
  result=self.merge();self.assertEqual(result['cache_files'],47);self.assertEqual(result['source_files_before'],85)
  self.assertEqual(result['source_files_after'],38);self.assertFalse(result['native_build_verified'])
  self.assertEqual(self.sentinel.read_bytes(),b'preserve existing cache')
  for rel,h in self.verified.items():
   p=self.context/rel if rel.startswith(M.PREFIX) else self.root/rel
   self.assertEqual(self.sha(p.read_bytes()),h)
  self.assertEqual(len(self.tree(self.root)),38)
 def test_collision_is_rejected_before_any_cache_copy(self):
  relative=sorted(k for k in self.verified if k.startswith(M.PREFIX))[-1];dest=self.context/relative
  dest.parent.mkdir(parents=True);dest.write_bytes(b'existing destination')
  before=self.tree(self.root)
  with self.assertRaises(ContractError):self.merge()
  self.assertEqual(self.tree(self.root),before);self.assertEqual(dest.read_bytes(),b'existing destination')
  self.assertEqual(len(self.tree(self.context/'module-cache')),2)
 def test_unknown_worker_file_is_rejected(self):
  (self.root/'unexpected').write_bytes(b'x')
  with self.assertRaises(ContractError):self.merge()
  self.assertEqual(len(self.tree(self.context/'module-cache')),1)
 def test_changed_worker_source_is_rejected(self):
  (self.root/'assets/upgrade-000.info').write_bytes(b'tampered')
  with self.assertRaises(ContractError):self.merge()
 def test_missing_expected_cache_binding_rejected(self):
  self.expected.pop(next(k for k in self.verified if k.startswith(M.PREFIX)))
  with self.assertRaises(ContractError):self.merge()
 def test_extra_expected_tree_binding_rejected(self):
  self.expected['unexpected']='0'*64
  with self.assertRaises(ContractError):self.merge()
 def test_worker_must_be_complete(self):
  self.bind_report('worker-status.json',dict(schema_version=1,phase='prepare',asset_index=-1,processed_assets=36,error='none',http_status=0))
  with self.assertRaises(ContractError):self.merge()
 def test_preparation_cannot_claim_native_build(self):
  value=json.loads((self.root/'prepared.json').read_bytes());value['native_build_verified']=True;self.bind_report('prepared.json',value)
  with self.assertRaises(ContractError):self.merge()
 def test_extra_preparation_diagnostics_rejected(self):
  value=json.loads((self.root/'prepared.json').read_bytes());value['raw']='not admissible';self.bind_report('prepared.json',value)
  with self.assertRaises(ContractError):self.merge()
 def test_unbound_worker_report_rejected(self):
  (self.root/'worker-status.json').write_bytes(b'{}')
  with self.assertRaises(ContractError):self.merge()
 def test_unrelated_root_rejected(self):
  with self.assertRaises(ContractError):self.merge(root=self.context/'another')
 def test_non_directory_destination_parent_is_rejected(self):
  blocked=self.context/'module-cache/cache/download/github.com';blocked.write_bytes(b'existing file')
  with self.assertRaises(ContractError):self.merge()
  self.assertEqual(blocked.read_bytes(),b'existing file');self.assertEqual(self.tree(self.root),self.expected)
 def test_write_failure_does_not_delete_verified_sources(self):
  before=self.tree(self.root)
  with patch.object(M.os,'open',side_effect=OSError('controlled write failure')):
   with self.assertRaises(OSError):self.merge()
  self.assertEqual(self.tree(self.root),before)
if __name__=='__main__':unittest.main()
