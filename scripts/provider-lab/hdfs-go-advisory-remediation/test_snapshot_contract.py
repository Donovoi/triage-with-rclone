import copy,gzip,hashlib,json,unittest
from pathlib import Path
from audit_contract import ContractError
from snapshot_contract import decode_snapshot
import test_advisory_contract as advisory_cases

class SnapshotAdmission(unittest.TestCase):
    def setUp(self):
        case=advisory_cases.AdvisoryProjection();case.setUp();record=case.value
        encode=lambda x:json.dumps(x,separators=(',',':'))
        self.bundle={'schema_version':1,'source_archive_sha256':'1'*64,'files':{
            'ID/'+record['id']+'.json':encode(record),
            'index/db.json':encode({'modified':record['modified']}),
            'index/vulns.json':encode([{'id':record['id'],'modified':record['modified']}]),
            'index/modules.json':encode([{'path':'example.test/lib','vulns':[{'id':record['id'],'modified':record['modified'],'fixed':'1.2.4'}]}])}}
        self.pin={'source_archive_sha256':'1'*64,'files':4,'records':1,'database_modified':record['modified'],
            'module_index_entries':1,'module_references':1,'known_ids':[record['id']]}
    def encoded(self):
        payload=json.dumps(self.bundle,separators=(',',':')).encode();raw=gzip.compress(payload,mtime=0)
        pin={**self.pin,'compressed_bytes':len(raw),'compressed_sha256':hashlib.sha256(raw).hexdigest(),
            'payload_bytes':len(payload),'payload_sha256':hashlib.sha256(payload).hexdigest(),
            'original_file_bytes':sum(len(x.encode()) for x in self.bundle['files'].values())}
        return raw,pin
    def reject(self,code,raw=None,pin=None):
        current,current_pin=self.encoded()
        with self.assertRaises(ContractError) as caught:decode_snapshot(current if raw is None else raw,current_pin if pin is None else pin)
        self.assertEqual(caught.exception.code,code)
    def test_complete_snapshot_preserves_original_bytes(self):
        summary,files,records,index=decode_snapshot(*self.encoded())
        self.assertEqual(summary['records'],1);self.assertEqual(index['example.test/lib'],['GO-2026-9999'])
        self.assertEqual(files['index/db.json'],self.bundle['files']['index/db.json'].encode())
    def test_wrong_archive_digest_and_size_fail(self):
        raw,pin=self.encoded();self.reject('snapshot_archive_binding',raw=raw+b'x',pin=pin)
        pin['compressed_sha256']='0'*64;self.reject('snapshot_archive_binding',pin=pin)
    def test_payload_digest_and_expansion_bound_fail(self):
        raw,pin=self.encoded();pin['payload_sha256']='0'*64;self.reject('snapshot_payload_binding',raw=raw,pin=pin)
        raw,pin=self.encoded();pin['payload_bytes']-=1;self.reject('snapshot_expansion',raw=raw,pin=pin)
    def test_trailing_gzip_members_fail(self):
        raw,pin=self.encoded();raw+=gzip.compress(b'{}',mtime=0)
        pin.update(compressed_bytes=len(raw),compressed_sha256=hashlib.sha256(raw).hexdigest())
        self.reject('snapshot_expansion',raw=raw,pin=pin)
    def test_unsafe_paths_fail(self):
        self.bundle['files']['../bad.json']=self.bundle['files'].pop('index/db.json');self.reject('snapshot_path')
    def test_record_filename_binding(self):
        self.bundle['files']['ID/GO-2026-8888.json']=self.bundle['files'].pop('ID/GO-2026-9999.json')
        self.reject('snapshot_record_name')
    def test_module_index_multiplicity_and_fixed_versions_bound(self):
        self.bundle['files']['index/modules.json']=json.dumps([{'path':'example.test/lib','vulns':[]}])
        self.reject('snapshot_module_bindings')
    def test_unknown_control_and_boolean_version_rejected(self):
        self.pin['known_ids']=['GO-2026-8888'];self.reject('snapshot_known_controls')
        self.pin['known_ids']=['GO-2026-9999'];self.bundle['schema_version']=True;self.reject('snapshot_header')
    def test_full_frozen_snapshot(self):
        here=Path(__file__).parent
        raw=(here/'advisory-snapshot.json.gz').read_bytes()
        pin=json.loads((here/'advisory-snapshot-pin.json').read_bytes())
        summary,files,records,index=decode_snapshot(raw,pin)
        self.assertEqual(summary['records'],4789);self.assertEqual(summary['custom_range_records'],609)
        self.assertEqual(summary['custom_range_affected_blocks'],657)

if __name__=='__main__':unittest.main()
