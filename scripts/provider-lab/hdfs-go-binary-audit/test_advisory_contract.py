import copy,json,unittest
from audit_contract import ContractError
from advisory_contract import project_osv,timestamp

class AdvisoryProjection(unittest.TestCase):
    def setUp(self):
        self.value={'id':'GO-2026-9999','modified':'2026-11-01T00:00:00Z','published':'2026-10-01T00:00:00Z',
            'details':'Synthetic advisory','affected':[{'package':{'name':'example.test/lib','ecosystem':'Go'},
            'ranges':[{'type':'SEMVER','events':[{'introduced':'0'},{'fixed':'1.2.4'}]}],
            'ecosystem_specific':{'imports':[{'path':'example.test/lib','symbols':['Thing.Method'],'goos':['linux'],'goarch':['amd64']}]}}]}
    def reject(self,code):
        with self.assertRaises(ContractError) as caught:project_osv(self.value)
        self.assertEqual(caught.exception.code,code)
    def test_complete_projection_preserves_applicability(self):
        self.assertEqual(project_osv(self.value),self.value)
    def test_go_omission_of_non_analysis_metadata(self):
        self.value.update(credits=[{'name':'Researcher','contact':['https://example.test']}],database_specific={'url':'https://example.test','review_status':'REVIEWED','extra':'metadata'})
        result=project_osv(self.value)
        self.assertEqual(result['credits'],[{'name':'Researcher'}])
        self.assertEqual(result['database_specific'],{'url':'https://example.test','review_status':'REVIEWED'})
    def test_unknown_range_types_and_events_fail(self):
        self.value['affected'][0]['ranges'][0]['type']='GIT';self.reject('osv_unsupported_range')
        self.value['affected'][0]['ranges'][0]['type']='SEMVER'
        self.value['affected'][0]['ranges'][0]['events'][1]={'last_affected':'1.2.4'};self.reject('osv_unsupported_event')
    def test_explicit_versions_cannot_be_silently_ignored(self):
        self.value['affected'][0]['versions']=['1.2.3'];self.reject('osv_unsupported_affected')
    def test_unknown_platform_and_package_fields_fail(self):
        imports=self.value['affected'][0]['ecosystem_specific']['imports']
        imports[0]['platform']='windows';self.reject('osv_unsupported_import')
        del imports[0]['platform'];self.value['affected'][0]['ecosystem_specific']['packages']=[];self.reject('osv_unsupported_ecosystem')
    def test_custom_ranges_require_and_preserve_explicit_ledger(self):
        custom=[{'type':'ECOSYSTEM','events':[{'introduced':'1.45.0'}]}]
        self.value['affected'][0]['ecosystem_specific']['custom_ranges']=custom
        self.reject('osv_custom_ranges_unacknowledged')
        ledger=[];out=project_osv(self.value,ledger)
        self.assertNotIn('custom_ranges',out['affected'][0]['ecosystem_specific'])
        self.assertEqual(ledger,[{'id':self.value['id'],'module':'example.test/lib','ranges':custom,'scanner_interprets_ranges':False}])
    def test_custom_range_unknown_semantics_rejected(self):
        self.value['affected'][0]['ecosystem_specific']['custom_ranges']=[{'type':'GIT','events':[{'introduced':'0'}]}]
        with self.assertRaises(ContractError) as caught:project_osv(self.value,[])
        self.assertEqual(caught.exception.code,'osv_custom_ranges')
    def test_missing_identity_and_invalid_ecosystem_fail(self):
        self.value['id']='GHSA-xxxx-yyyy-zzzz';self.reject('osv_id')
        self.value['id']='GO-2026-9999';self.value['affected'][0]['package']['ecosystem']='npm';self.reject('osv_ecosystem')
    def test_invalid_and_noncanonical_times(self):
        self.assertEqual(timestamp('2026-11-01T00:00:00.120000000+00:00'),'2026-11-01T00:00:00.12Z')
        self.value['modified']='2026-02-30T00:00:00Z';self.reject('osv_time')
    def test_empty_imports_preserve_package_wildcard(self):
        self.value['affected'][0]['ecosystem_specific']={'imports':[]}
        result=project_osv(self.value)
        self.assertEqual(result['affected'][0]['ecosystem_specific'],{})
    def test_multiline_summary_preserved(self):
        self.value['summary']='First line\nSecond line'
        self.assertEqual(project_osv(self.value)['summary'],self.value['summary'])
    def test_multiline_details_preserved(self):
        self.value['details']='First line\nSecond line\twith detail'
        self.assertEqual(project_osv(self.value)['details'],self.value['details'])
    def test_missing_or_empty_details_serializes_as_go_default(self):
        del self.value['details']
        self.assertEqual(project_osv(self.value)['details'],'')
    def test_unsupported_review_status_fails(self):
        self.value['database_specific']={'review_status':'APPROVED'};self.reject('osv_review_status')

if __name__=='__main__':unittest.main()
