import copy,json,unittest
from pathlib import Path
from audit_contract import ContractError
import tool_bundle as T

class ToolAssetAdmission(unittest.TestCase):
    def setUp(self):
        self.raw=(Path(__file__).parent/'tool-assets-lock.json').read_bytes()
        self.lock=T.load_lock(self.raw)
    def reject(self,code):
        with self.assertRaises(ContractError) as caught:T.validate_lock(self.lock)
        self.assertEqual(caught.exception.code,code)
    def test_pinned_lock_and_case_escape(self):
        self.assertEqual(len(self.lock['assets']),34)
        self.assertEqual(T.escape('example.test/SomeModule'),'example.test/!some!module')
    def test_lock_bytes_are_pinned(self):
        with self.assertRaises(ContractError) as caught:T.load_lock(self.raw+b' ')
        self.assertEqual(caught.exception.code,'tool_lock_binding')
    def test_wrong_tool_or_origin_rejected(self):
        self.lock['tool']['version']='v9.0.0';self.reject('tool_identity')
    def test_arbitrary_url_and_embedded_credentials_rejected(self):
        self.lock['assets'][0]['url']='https://user:secret@proxy.golang.org/x';self.reject('tool_asset_url')
    def test_path_traversal_and_absolute_module_rejected(self):
        self.lock['assets'][0]['module']='../outside';self.reject('tool_module')
        self.lock['assets'][0]['module']='/absolute';self.reject('tool_module')
    def test_filename_escape_rejected(self):
        self.lock['assets'][0]['file']='../asset-000.zip';self.reject('tool_asset_name')
    def test_duplicate_asset_identity_rejected(self):
        other=copy.deepcopy(self.lock['assets'][0]);other['file']=self.lock['assets'][3]['file'].split('.')[0]+'.zip'
        self.lock['assets'][3]=other;self.reject('tool_duplicate_identity')
    def test_output_size_and_boolean_count_rejected(self):
        self.lock['assets'][0]['bytes']=True;self.reject('tool_asset_bound')
        self.lock['assets'][0]['bytes']=100*1024*1024;self.reject('tool_asset_bound')
    def test_malformed_digest_and_hash1_rejected(self):
        self.lock['assets'][0]['sha256']='not a digest';self.reject('tool_asset_digest')
        self.lock['assets'][0]['sha256']='0'*64;self.lock['assets'][0]['h1']='h1:bad';self.reject('tool_hash1')
    def test_missing_asset_and_extraneous_fields_rejected(self):
        self.lock['assets'].pop();self.reject('tool_asset_count')
        self.lock=T.load_lock(self.raw);self.lock['assets'][0]['command']='unexpected';self.reject('tool_asset_shape')
    def test_noncontiguous_asset_numbers_rejected(self):
        self.lock['assets'][0]['file']='asset-999.zip';self.reject('tool_asset_inventory')

if __name__=='__main__':unittest.main()
