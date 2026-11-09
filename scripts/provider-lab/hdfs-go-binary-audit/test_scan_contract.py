import copy,json,unittest
from audit_contract import ContractError
from scan_contract import admit_scan,expected_sbom
import test_audit_contract as extraction_cases
import test_advisory_contract as advisory_cases

class ScannerAdmission(unittest.TestCase):
    def setUp(self):
        extraction=extraction_cases.ExtractionAdmission();extraction.setUp()
        self.body=extraction.body;self.identity=extraction.expected;self.extraction=extraction.raw()
        projection=advisory_cases.AdvisoryProjection();projection.setUp()
        self.record=projection.value
        self.config={'protocol_version':'v1.0.0','scanner_name':'govulncheck','scanner_version':'v0.0.0',
            'db':'file:///opt/advisories','db_last_modified':'2026-11-01T00:00:00Z','scan_mode':'binary','scan_level':'symbol'}
        self.snapshot={self.record['id']:self.record}
        self.index={'example.test/lib':[self.record['id']]}
        self.required={(self.record['id'],'example.test/lib')}
        frame={'module':'example.test/lib','version':'v1.2.3'}
        finding=lambda f:{'finding':{'osv':self.record['id'],'fixed_version':'v1.2.4','trace':[f]}}
        self.messages=[{'config':self.config},{'SBOM':expected_sbom(self.body)},{'osv':copy.deepcopy(self.record)},
            finding(frame),finding({**frame,'package':'example.test/lib'}),
            finding({**frame,'package':'example.test/lib','receiver':'Thing','function':'Method'})]
    def raw(self):return ('\n'.join(json.dumps(x) for x in self.messages)+'\n').encode()
    def run_admit(self,**kwargs):
        args=dict(raw=self.raw(),extraction_raw=self.extraction,identity=self.identity,config=self.config,
            snapshot=self.snapshot,index=self.index,required_module_findings=self.required,exit_code=0,stderr=b'')
        args.update(kwargs);return admit_scan(**args)
    def reject(self,code,**kwargs):
        with self.assertRaises(ContractError) as caught:self.run_admit(**kwargs)
        self.assertEqual(caught.exception.code,code)
    def test_complete_three_level_evidence(self):
        out=self.run_admit()
        self.assertEqual(out['findings_by_level'],{'module':1,'package':1,'symbol':1})
        self.assertFalse(out['reachability_verified']);self.assertFalse(out['vulnerability_audit_completed'])
    def test_expected_advisory_duplicates_are_counted(self):
        self.index['example.test/lib']*=2;self.messages.insert(3,{'osv':copy.deepcopy(self.record)})
        self.assertEqual(self.run_admit()['osv_messages'],2)
    def test_missing_or_extra_advisory_messages_fail(self):
        self.messages.pop(2);self.reject('scan_osv_completeness')
        self.messages.insert(2,{'osv':copy.deepcopy(self.record)});self.messages.insert(2,{'osv':copy.deepcopy(self.record)})
        self.reject('scan_osv_multiplicity')
    def test_advisory_content_is_snapshot_bound(self):
        self.messages[2]['osv']['affected'][0]['ranges'][0]['events'][1]['fixed']='99.0.0'
        self.reject('scan_osv_content')
    def test_unknown_advisory_and_message_fail(self):
        self.messages[2]['osv']['id']='GO-2026-8888';self.reject('scan_osv_id')
        self.messages[2]={'unknown':{}};self.reject('scan_unknown_message')
    def test_config_and_sbom_are_exact(self):
        self.messages[0]={'config':{**self.config,'scan_level':'module'}};self.reject('scan_config')
        self.messages[0]={'config':self.config};self.messages[1]['SBOM']['modules'][1]['version']='v9.0.0';self.reject('scan_sbom')
    def test_missing_and_duplicate_sbom_fail(self):
        sbom=self.messages.pop(1);self.reject('scan_sbom_missing')
        self.messages.insert(1,sbom);self.messages.insert(1,copy.deepcopy(sbom));self.reject('scan_sbom')
    def test_missing_symbols_cannot_be_hidden_by_scanner_config(self):
        self.body['pkgSymbols']=[]
        raw=(json.dumps({'name':'govulncheck-extract','version':'0.1.0'})+'\n'+json.dumps(self.body)).encode()
        self.reject('symbol_count',extraction_raw=raw)
    def test_nonzero_or_stderr_is_not_qualified(self):
        self.reject('scan_process',exit_code=1);self.reject('scan_process',stderr=b'warning')
        self.reject('scan_process',exit_code=False)
    def test_unknown_module_and_wrong_version_fail(self):
        self.messages[-1]['finding']['trace'][0]['version']='v9.0.0';self.reject('finding_module')
    def test_unextracted_symbol_or_package_fail(self):
        frame=self.messages[-1]['finding']['trace'][0];frame['function']='Missing';self.reject('finding_symbol_absent')
        frame['function']='Method';frame['package']='example.test/missing';self.reject('finding_package_absent')
    def test_source_callstack_is_not_binary_symbol_evidence(self):
        self.messages[-1]['finding']['trace'].append(self.messages[-1]['finding']['trace'][0]);self.reject('finding_trace')
    def test_positions_are_not_accepted_in_binary_frames(self):
        self.messages[-1]['finding']['trace'][0]['position']={'line':1};self.reject('finding_frame')
    def test_zero_findings_cannot_replace_positive_controls(self):
        self.messages=self.messages[:3];self.reject('scan_positive_controls_missing')
    def test_higher_precision_requires_module_finding(self):
        self.messages.pop(3)
        self.reject('scan_finding_hierarchy',required_module_findings=set())
    def test_pinned_custom_ranges_are_retained_separately(self):
        custom=[{'type':'ECOSYSTEM','events':[{'introduced':'1.0.0'}]}]
        self.record['affected'][0]['ecosystem_specific']['custom_ranges']=custom
        out=self.run_admit()
        self.assertEqual(out['custom_ranges_omitted_by_scanner'][0]['ranges'],custom)
    def test_trailing_partial_and_duplicate_json_fail(self):
        self.reject('scan_json',raw=self.raw()+b'{')
        raw=self.raw().replace(b'"scan_level": "symbol"',b'"scan_level":"symbol","scan_level":"module"',1)
        self.reject('duplicate_key',raw=raw)
    def test_repeated_findings_are_preserved_as_counts(self):
        self.messages.append(copy.deepcopy(self.messages[-1]))
        out=self.run_admit();self.assertEqual(out['finding_messages'],4);self.assertEqual(out['unique_findings'],3)

if __name__=='__main__':unittest.main()
