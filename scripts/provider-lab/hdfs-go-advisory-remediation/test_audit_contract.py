"""Pure negative controls for extraction evidence admission."""
import copy,json,unittest
from audit_contract import ContractError,admit_extraction,bounded_stream,MAX_EXTRACT_BYTES

def mod(path,version):
    return dict(Path=path,Version=version,Replace=None,Time=None,Main=False,Indirect=False,Dir='',GoMod='',GoVersion='',Error=None)

class ExtractionAdmission(unittest.TestCase):
    def setUp(self):
        self.expected=dict(path='example.test/main',go_version='go1.26.10',goos='linux',goarch='amd64',
            main_versions=['','(devel)','v1.0.0'],modules=[dict(path='example.test/lib',version='v1.2.3',replacement=None)])
        self.header=dict(name='govulncheck-extract',version='0.1.0')
        self.body=dict(path='example.test/main',main=mod('example.test/main','(devel)'),modules=[mod('example.test/lib','v1.2.3')],
            pkgSymbols=[dict(name='Encoding'),dict(pkg='example.test/lib',name='Thing.Method')],goVersion='go1.26.10',goos='linux',goarch='amd64')
    def raw(self):
        return (json.dumps(self.header)+'\n'+json.dumps(self.body)+'\n').encode()
    def reject(self,code,raw=None):
        with self.assertRaises(ContractError) as caught:admit_extraction(self.raw() if raw is None else raw,self.expected)
        self.assertEqual(caught.exception.code,code)
    def test_complete_metadata_and_symbols(self):
        summary,body=admit_extraction(self.raw(),self.expected)
        self.assertEqual(summary['symbols'],2);self.assertEqual(summary['packages'],1)
        self.assertFalse(summary['main_version_is_upstream_release'])
        self.assertFalse(summary['reachability_verified']);self.assertFalse(summary['vulnerability_audit_completed'])
    def test_missing_and_empty_symbols_reject_fallback(self):
        self.body['pkgSymbols']=[];self.reject('symbol_count')
        del self.body['pkgSymbols'];self.reject('extract_body')
    def test_only_unqualified_names_are_not_symbol_evidence(self):
        self.body['pkgSymbols']=[dict(name='Encoding')];self.reject('qualified_symbols_absent')
    def test_exact_replacement_preserved_as_coverage_gap(self):
        self.body['modules'][0]['Replace']=mod('/opt/input/patched-hdfs','')
        self.expected['modules'][0]['replacement']=dict(path='/opt/input/patched-hdfs',versions=['','(devel)'])
        summary,_=admit_extraction(self.raw(),self.expected)
        self.assertEqual(summary['local_replacements'][0]['upstream_advisory_coverage'],'requires_separate_conservative_proxy')
    def test_replacement_rewrite_or_missing_rejected(self):
        self.expected['modules'][0]['replacement']=dict(path='/opt/input/patched-hdfs',versions=['','(devel)'])
        self.reject('replacement_identity')
        self.body['modules'][0]['Replace']=mod('example.test/lib','v1.2.3');self.reject('replacement_identity')
    def test_unexpected_and_nested_replacements_rejected(self):
        self.body['modules'][0]['Replace']=mod('/tmp/unexpected','');self.reject('unexpected_replacement')
        self.body['modules'][0]['Replace']['Replace']=mod('nested','');self.reject('nested_replacement')
    def test_binary_platform_version_and_path_bound(self):
        for key in ('path','goVersion','goos','goarch'):
            with self.subTest(key=key):
                old=self.body[key];self.body[key]='wrong';self.reject('binary_metadata');self.body[key]=old
    def test_main_identity_and_version_bound(self):
        self.body['main']['Version']='v99.0.0';self.reject('main_metadata')
        self.body['main']['Version']='(devel)';self.body['main']['Path']='wrong';self.reject('main_metadata')
    def test_module_count_set_and_version_bound(self):
        self.body['modules'][0]['Version']='v99.0.0';self.reject('module_version')
        self.body['modules'][0]['Version']='v1.2.3';self.body['modules'][0]['Path']='wrong';self.reject('module_set')
        self.body['modules']=[];self.reject('module_count')
    def test_default_metadata_cannot_hide_source_errors(self):
        for key,value in [('Main',True),('Indirect',True),('Error',{'Err':'secret'}),('Dir','/tmp/secret'),('Time','2026-01-01')]:
            with self.subTest(key=key):
                old=self.body['modules'][0][key];self.body['modules'][0][key]=value;self.reject('module_metadata');self.body['modules'][0][key]=old
    def test_duplicate_module_is_rejected(self):
        self.body['modules']*=2;self.expected['modules'].append(dict(path='example.test/other',version='v1.0.0',replacement=None))
        self.reject('module_set')
    def test_duplicate_and_unordered_symbols_rejected(self):
        self.body['pkgSymbols'].append(self.body['pkgSymbols'][-1]);self.reject('duplicate_symbol')
        self.body['pkgSymbols']=self.body['pkgSymbols'][:2][::-1];self.reject('symbol_order')
    def test_symbol_shape_and_control_characters_rejected(self):
        self.body['pkgSymbols'][0]['position']={};self.reject('symbol_shape')
        del self.body['pkgSymbols'][0]['position'];self.body['pkgSymbols'][0]['name']='bad\nname';self.reject('symbol_text')
    def test_unpaired_surrogate_rejected_with_closed_error(self):
        self.body['pkgSymbols'][0]['name']='bad'+chr(0xd800);self.reject('symbol_text')
    def test_unknown_protocol_and_fields_rejected(self):
        self.header['version']='0.2.0';self.reject('extract_header')
        self.header['version']='0.1.0';self.body['extra']=True;self.reject('extract_body')
    def test_truncated_and_trailing_messages_rejected(self):
        self.reject('json',self.raw()[:-3])
        self.reject('message_count',self.raw()+b'{}')
    def test_duplicate_json_keys_rejected(self):
        self.reject('duplicate_key',self.raw().replace(b'"name": "govulncheck-extract"',b'"name": "govulncheck-extract", "name":"x"',1))
    def test_nonfinite_and_invalid_utf8_rejected(self):
        self.reject('nonfinite',b'NaN\n{}')
        self.reject('encoding',b'\xff')
    def test_input_bound_and_two_messages_required(self):
        self.reject('input_size',b'')
        self.reject('message_count',b'{}')
        with self.assertRaises(ContractError) as caught:bounded_stream(b' '*(MAX_EXTRACT_BYTES+1),2)
        self.assertEqual(caught.exception.code,'input_size')
    def test_upstream_extraction_fixture_is_admitted(self):
        from pathlib import Path
        raw=(Path(__file__).parent/'fixtures/extract-example.blob').read_bytes()
        _,body=bounded_stream(raw,2)
        expected=dict(path=body['path'],go_version=body['goVersion'],goos=body['goos'],goarch=body['goarch'],
            main_versions=[body['main']['Version']],modules=[dict(path=x['Path'],version=x['Version'],replacement=None) for x in body['modules']])
        summary,_=admit_extraction(raw,expected)
        self.assertEqual(summary['symbols'],2754)

if __name__=='__main__':unittest.main()
