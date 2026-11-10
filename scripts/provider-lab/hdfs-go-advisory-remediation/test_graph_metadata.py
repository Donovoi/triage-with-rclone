import base64,copy,hashlib,json,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
from audit_contract import ContractError,need
import graph_metadata as G
import remediation_bundle as B

HERE=Path(__file__).resolve().parent
class GraphMetadataTests(unittest.TestCase):
 def setUp(self):
  self.raw=(HERE/'graph-metadata-snapshot.json').read_bytes();self.value=json.loads(self.raw)
  self.baseline=json.loads((HERE.parent/'hdfs-rclone-usage-build/assets-lock.json').read_bytes())
  self.lock=B.load_lock((HERE/'remediation-assets-lock.json').read_bytes())
  self.source=B.source_catalog(self.baseline,self.lock)
  self.sums=(HERE/'upgraded-rclone.sum').read_bytes()
  self.mod_sums={(r['module'],r['version']):r['h1'] for lock in (self.baseline,self.lock) for r in lock['assets'] if r['kind']=='mod'}
  versions,_=G.load_snapshot(self.raw);self.allowed=set(versions.items())
 def extend(self,**changes):
  args=dict(source=self.source,raw=self.raw,sum_raw=self.sums,mod_sums=self.mod_sums,allowed=self.allowed);args.update(changes)
  return G.extend_catalog(**args)
 def reject(self,change):
  value=copy.deepcopy(self.value);change(value)
  with self.assertRaises(ContractError):G.validate_snapshot(value)
 def test_exact_snapshot_binds_all_public_info_bytes(self):
  versions,metadata=G.load_snapshot(self.raw)
  self.assertEqual(len(versions),653);self.assertEqual(len(metadata),318)
  self.assertEqual(sum(len(x['raw']) for x in metadata.values()),53641)
  self.assertTrue(all(json.loads(x['raw'])['Version']==x['version'] for x in metadata.values()))
 def test_extension_preserves_all_archive_bindings(self):
  result=self.extend();self.assertEqual(len(result),654)
  self.assertEqual(sum(x['source_available'] for x in result.values()),336)
  for name,row in self.source.items():self.assertEqual(result[name],dict(row,source_available=True))
  meta=[r for r in result.values() if not r['source_available']]
  self.assertTrue(all(r['sum']=='' for r in meta));self.assertEqual(sum(bool(r['go_mod_sum']) for r in meta),9)
 def test_changed_snapshot_bytes_rejected(self):
  for raw in (self.raw+b' ',self.raw[:-1],b'{}',self.raw.decode()):
   with self.assertRaises(ContractError):G.load_snapshot(raw)
 def test_duplicate_json_key_rejected(self):
  with self.assertRaises(ContractError):G.parse(b'{"a":1,"a":2}')
 def test_nonfinite_json_rejected(self):
  with self.assertRaises(ContractError):G.parse(b'{"a":NaN}')
 def test_unrecognized_snapshot_field_rejected(self):self.reject(lambda v:v.update(accepted=True))
 def test_wrong_origin_rejected(self):self.reject(lambda v:v.update(origin_head='0'*40))
 def test_bool_origin_run_rejected(self):self.reject(lambda v:v.update(origin_run=True))
 def test_selected_coordinate_order_required(self):self.reject(lambda v:v['selected'].reverse())
 def test_duplicate_selected_module_rejected(self):self.reject(lambda v:v['selected'].__setitem__(1,v['selected'][0]))
 def test_missing_selected_node_rejected(self):self.reject(lambda v:v['selected'].pop())
 def test_path_traversal_rejected(self):self.reject(lambda v:v['selected'][0].update(module='example.org/../escape'))
 def test_wrong_metadata_version_rejected(self):self.reject(lambda v:v['metadata'][0].update(version='v9.9.9'))
 def test_unexpected_download_host_rejected(self):self.reject(lambda v:v['metadata'][0].update(url='https://example.org/other.info'))
 def test_hash_mismatch_rejected(self):self.reject(lambda v:v['metadata'][0].update(sha256='0'*64))
 def test_noncanonical_base64_rejected(self):self.reject(lambda v:v['metadata'][0].update(content_base64=v['metadata'][0]['content_base64']+'\n'))
 def test_extra_metadata_field_rejected(self):self.reject(lambda v:v['metadata'][0].update(source_available=True))
 def test_metadata_byte_bound_rejected(self):self.reject(lambda v:v['metadata'][0].update(bytes=4097))
 def test_metadata_order_required(self):self.reject(lambda v:v['metadata'].reverse())
 def test_duplicate_metadata_rejected(self):self.reject(lambda v:v['metadata'].__setitem__(1,v['metadata'][0]))
 def test_info_version_is_independently_bound(self):
  def change(v):
   row=v['metadata'][0];info=json.loads(base64.b64decode(row['content_base64']));info['Version']='v9.9.9'
   raw=json.dumps(info).encode();row.update(content_base64=base64.b64encode(raw).decode(),bytes=len(raw),sha256=G.sha(raw))
  self.reject(change)
 def test_invalid_info_date_rejected(self):
  def change(v):
   row=v['metadata'][0];info=json.loads(base64.b64decode(row['content_base64']));info['Time']='2026-99-99T00:00:00Z'
   raw=json.dumps(info).encode();row.update(content_base64=base64.b64encode(raw).decode(),bytes=len(raw),sha256=G.sha(raw))
  self.reject(change)
 def test_metadata_coordinates_need_bound_public_allowlist(self):
  allowed=set(self.allowed);row=self.value['metadata'][0];allowed.remove((row['module'],row['version']))
  with self.assertRaises(ContractError):self.extend(allowed=allowed)
 def test_archive_catalog_version_cannot_change(self):
  source=copy.deepcopy(self.source);source['golang.org/x/net']['version']='v0.60.0'
  with self.assertRaises(ContractError):self.extend(source=source)
 def test_metadata_source_checksum_cannot_be_invented(self):
  row=self.value['metadata'][0];extra=(row['module']+' '+row['version']+' h1:'+'A'*43+'=\n').encode()
  with self.assertRaises(ContractError):self.extend(sum_raw=self.sums+extra)
 def test_recorded_mod_checksum_must_match_pinned_mod(self):
  row=next(r for r in self.value['metadata'] if r['go_mod_sum']);pins=dict(self.mod_sums);pins.pop((row['module'],row['version']))
  with self.assertRaises(ContractError):self.extend(mod_sums=pins)
 def test_recorded_mod_checksum_cannot_disappear(self):
  row=next(r for r in self.value['metadata'] if r['go_mod_sum']);line=(row['module']+' '+row['version']+'/go.mod '+row['go_mod_sum']+'\n').encode()
  self.assertIn(line,self.sums)
  with self.assertRaises(ContractError):self.extend(sum_raw=self.sums.replace(line,b''))

class GraphMetadataOwnershipTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(dir=HERE);self.addCleanup(self.temp.cleanup)
  self.context=Path(self.temp.name)/'context';self.cache=self.context/'module-cache/cache/download';self.cache.mkdir(parents=True)
  self.raw=(HERE/'graph-metadata-snapshot.json').read_bytes();_,self.metadata=G.load_snapshot(self.raw)
  self.sentinel=self.cache/'preserved';self.sentinel.write_bytes(b'existing cache')
  def directory(p,identity=None):
   need(p.is_dir() and not p.is_symlink(),'test_directory');st=p.stat();actual=(st.st_dev,st.st_ino)
   need(identity is None or identity==actual,'test_identity');return actual
  def read(p,maximum):
   need(p.is_file() and not p.is_symlink() and p.stat().st_nlink==1 and p.stat().st_size<=maximum,'test_regular');return p.read_bytes()
  self.C=types.SimpleNamespace(directory=directory,read=read)
 def target(self,module,row):return self.context/B.cache_relative(dict(module=module,version=row['version'],kind='info'))
 def count(self):return sum(p.is_file() for p in self.context.rglob('*'))
 def test_exact_metadata_staging_preserves_existing_cache(self):
  result=G.stage_owned(self.C,self.context,self.raw)
  self.assertEqual(result['cache_files'],318);self.assertEqual(result['cache_bytes'],53641)
  self.assertEqual(result['source_archives_added'],0);self.assertFalse(result['native_build_verified'])
  self.assertEqual(self.sentinel.read_bytes(),b'existing cache');self.assertEqual(self.count(),319)
  for module,row in self.metadata.items():self.assertEqual(self.target(module,row).read_bytes(),row['raw'])
 def test_last_destination_collision_is_found_before_writes(self):
  module,row=list(self.metadata.items())[-1];target=self.target(module,row);target.parent.mkdir(parents=True);target.write_bytes(b'existing')
  with self.assertRaisesRegex(ContractError,'graph_metadata_cache_collision'):G.stage_owned(self.C,self.context,self.raw)
  self.assertEqual(target.read_bytes(),b'existing');self.assertEqual(self.count(),2)
 def test_nondirectory_parent_is_rejected_before_writes(self):
  blocked=self.cache/'github.com';blocked.write_bytes(b'existing file')
  with self.assertRaises(ContractError):G.stage_owned(self.C,self.context,self.raw)
  self.assertEqual(blocked.read_bytes(),b'existing file');self.assertEqual(self.count(),2)
 def test_bad_snapshot_is_rejected_before_writes(self):
  with self.assertRaises(ContractError):G.stage_owned(self.C,self.context,self.raw+b'x')
  self.assertEqual(self.count(),1)
 def test_exclusive_write_failure_preserves_existing_cache(self):
  with patch.object(G.os,'open',side_effect=OSError('controlled exclusive-open failure')):
   with self.assertRaises(OSError):G.stage_owned(self.C,self.context,self.raw)
  self.assertEqual(self.sentinel.read_bytes(),b'existing cache');self.assertEqual(self.count(),1)
 def test_postwrite_byte_change_is_rejected(self):
  with patch.object(self.C,'read',return_value=b'changed'):
   with self.assertRaisesRegex(ContractError,'graph_metadata_cache_changed'):G.stage_owned(self.C,self.context,self.raw)
  self.assertEqual(self.sentinel.read_bytes(),b'existing cache')
 def test_relative_context_is_rejected(self):
  with self.assertRaisesRegex(ContractError,'graph_metadata_context'):G.stage_owned(self.C,Path('relative'),self.raw)
 def test_cache_identity_change_is_rejected_before_writes(self):
  original=self.C.directory
  def changed(p,identity=None):
   if p==self.cache and identity is not None:raise ContractError('changed cache identity')
   return original(p,identity)
  with patch.object(self.C,'directory',side_effect=changed):
   with self.assertRaisesRegex(ContractError,'changed cache identity'):G.stage_owned(self.C,self.context,self.raw)
  self.assertEqual(self.count(),1)
