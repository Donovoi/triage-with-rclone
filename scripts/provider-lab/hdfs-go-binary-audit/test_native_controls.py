import copy,hashlib,json,unittest
from audit_contract import ContractError,admit_metadata,admit_extraction
from native_controls import fixture,validate_native,validate_stripped,config,ID,DATE,MODULE
from scan_contract import expected_sbom
class NativeControls(unittest.TestCase):
    def setUp(self):self.files,self.blobs,self.expected,self.record=fixture()
    def stream(self,case):
        body,_=admit_metadata(self.blobs[case],self.expected)
        frame=dict(module=MODULE,version='v1.0.0')
        finding=lambda f:dict(finding=dict(osv=ID,fixed_version='v1.0.1',trace=[f]))
        rows=[dict(config=config('file:///opt/input/control-db',DATE)),
              dict(SBOM=expected_sbom(body)),dict(osv=self.record),
              finding(frame),finding(dict(frame,package=MODULE))]
        if case!='negative':rows.append(finding(dict(frame,package=MODULE,function='Problem')))
        return b'\n'.join(json.dumps(r).encode() for r in rows)
    def test_synthetic_cases_require_exact_native_findings(self):
        for case in self.blobs:
            result=validate_native(case,self.stream(case),0,b'')
            self.assertTrue(result['success']);self.assertFalse(result['real_binary_symbol_evidence'])
            self.assertFalse(result['vulnerability_audit_completed'])
    def test_missing_positive_findings_rejected(self):
        raw=self.stream('negative')
        with self.assertRaisesRegex(ContractError,'control_findings'):validate_native('positive',raw,0,b'')
    def test_negative_cannot_report_positive_symbol(self):
        with self.assertRaisesRegex(ContractError,'finding_symbol_absent'):
            validate_native('negative',self.stream('positive'),0,b'')
    def test_duplicate_control_findings_rejected(self):
        raw=self.stream('positive');raw+=b'\n'+raw.splitlines()[-1]
        with self.assertRaisesRegex(ContractError,'control_multiplicity'):validate_native('positive',raw,0,b'')
    def test_control_fixed_version_bound(self):
        raw=self.stream('positive').replace(b'"fixed_version": "v1.0.1"',b'"fixed_version": "v1.0.2"')
        with self.assertRaisesRegex(ContractError,'control_fixed_version'):validate_native('positive',raw,0,b'')
    def stripped(self,**updates):
        body,_=admit_metadata(self.blobs['fallback'],self.expected);del body['pkgSymbols'];body.update(updates)
        return json.dumps(dict(name='govulncheck-extract',version='0.1.0')).encode()+b'\n'+json.dumps(body).encode()
    def test_stripped_metadata_verified_before_symbol_rejection(self):
        result=validate_stripped(self.stripped(),self.expected)
        self.assertEqual(result['admission_rejection'],'extract_body');self.assertTrue(result['metadata_verified'])
    def test_stripped_wrong_metadata_cannot_count_as_negative_control(self):
        with self.assertRaisesRegex(ContractError,'binary_metadata'):validate_stripped(self.stripped(goarch='arm64'),self.expected)
    def test_stripped_with_symbols_or_empty_list_rejected(self):
        for symbols in ([],[dict(pkg=MODULE,name='Problem')]):
            with self.assertRaisesRegex(ContractError,'stripped_symbols_present'):
                validate_stripped(self.stripped(pkgSymbols=symbols),self.expected)
    def test_metadata_only_never_grants_symbol_admission(self):
        admit_metadata(self.blobs['fallback'],self.expected)
        with self.assertRaisesRegex(ContractError,'symbol_count'):admit_extraction(self.blobs['fallback'],self.expected)
    def test_control_database_is_separate_and_deterministic(self):
        self.assertEqual(self.files,fixture()[0]);self.assertEqual(len(self.files),6)
        self.assertTrue(all(p.startswith(('control-db/','control-blobs/')) for p in self.files))
        self.assertEqual(json.loads(self.files['control-db/index/modules.json'])[0]['vulns'][0]['id'],ID)
