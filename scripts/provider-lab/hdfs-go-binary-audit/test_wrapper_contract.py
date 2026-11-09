import base64,copy,hashlib,json,unittest
from pathlib import Path
from audit_contract import ContractError
from tool_bundle import load_lock,TOOL,VERSION,ORIGIN,LOCK_SHA
from wrapper_contract import admit_wrapper,TARGETS
class WrapperAdmission(unittest.TestCase):
    def setUp(self):
        self.lock=load_lock((Path(__file__).parent/'tool-assets-lock.json').read_bytes())
        self.target=dict(file=dict(sha256=TARGETS['original'][0],bytes=TARGETS['original'][1]),
                         modules=[dict(path='example.test/lib',version='v1.0.0',sum='h1:reference',replacement='')])
        toolrows=[dict(path=r['module'],version=r['version'],sum=r['h1'],replacement='')
                  for r in self.lock['assets'] if r['kind']=='zip' and r['module'] in ('golang.org/x/mod','golang.org/x/tools')]
        toolrows.sort(key=lambda r:r['path'])
        def identity(path,main,file,rows):
            return dict(file=file,go_version='go1.26.10',path=path,
                        main=dict(path=main,version='(devel)',sum='',replacement=''),
                        settings={'GOOS':'linux','GOARCH':'amd64','CGO_ENABLED':'0','-buildmode':'exe','-trimpath':'true'},
                        modules=rows)
        self.tool=dict(binary=identity(TOOL+'/cmd/govulncheck',TOOL,dict(sha256='a'*64,bytes=5*1024*1024),toolrows),
                       source_version=VERSION,source_origin=ORIGIN,lock_sha256=LOCK_SHA)
        out=b'{"example":"raw scanner stream"}\n'
        self.value=dict(schema_version=1,success=True,error='none',mode='extract',target='original',tool=self.tool,
            target_before=self.target['file'],target_after=copy.deepcopy(self.target['file']),
            target_identity=identity('github.com/rclone/rclone','github.com/rclone/rclone',
                                     copy.deepcopy(self.target['file']),copy.deepcopy(self.target['modules'])),
            tool_unchanged=True,target_unchanged=True,exit_code=0,timed_out=False,wait_delay_exceeded=False,
            stdout_overflow=False,stderr_overflow=False,stdout_base64=base64.b64encode(out).decode(),stderr_base64='',
            stdout_sha256=hashlib.sha256(out).hexdigest(),stderr_sha256=hashlib.sha256(b'').hexdigest(),
            capture_controls=9,duration_ms=100,vulnerability_audit_completed=False,provider_accepted=False)
    def run_admit(self,**kwargs):
        args=dict(raw=json.dumps(self.value).encode(),mode='extract',target='original',
                  expected_target=self.target,lock=self.lock,exit_code=0,expected_tool=None)
        args.update(kwargs);return admit_wrapper(**args)
    def reject(self,code,**kwargs):
        with self.assertRaises(ContractError) as caught:self.run_admit(**kwargs)
        self.assertEqual(caught.exception.code,code)
    def test_complete_binding_returns_stream_separately(self):
        summary,out,err=self.run_admit();self.assertTrue(summary['success'])
        self.assertNotIn('stdout_base64',summary);self.assertTrue(out);self.assertEqual(err,b'')
    def test_tool_reuse_is_bound_to_first_observed_identity(self):
        other=copy.deepcopy(self.tool);other['binary']['file']['sha256']='b'*64
        self.reject('wrapper_tool_changed',expected_tool=other)
    def test_qualified_rclone_identity_cannot_be_replaced(self):
        self.target['file']['sha256']='b'*64;self.value['target_after']['sha256']='b'*64
        self.value['target_identity']['file']['sha256']='b'*64
        self.reject('wrapper_target_identity')
    def test_target_mutation_rejected(self):
        self.value['target_after']['sha256']='c'*64;self.reject('wrapper_target_binding')
    def test_compiled_target_graph_cannot_drift(self):
        self.value['target_identity']['modules'][0]['version']='v2.0.0';self.reject('wrapper_target_graph')
    def test_tool_dependency_replacement_or_wrong_sum_rejected(self):
        self.value['tool']['binary']['modules'][0]['replacement']='/changed';self.reject('wrapper_tool_graph')
        self.value['tool']['binary']['modules'][0]['replacement']=''
        self.value['tool']['binary']['modules'][0]['sum']='h1:changed';self.reject('wrapper_tool_graph')
    def test_missing_tool_source_pin_rejected(self):
        self.value['tool']['source_version']='v0.0.0';self.reject('wrapper_tool')
    def test_different_compiler_or_platform_rejected(self):
        self.value['tool']['binary']['go_version']='go1.27.0';self.reject('wrapper_binary_identity')
        self.value['tool']['binary']['go_version']='go1.26.10'
        self.value['tool']['binary']['settings']['GOARCH']='arm64';self.reject('wrapper_settings')
    def test_runtime_failure_flags_and_false_acceptance_claims_rejected(self):
        for key in ('timed_out','wait_delay_exceeded','stdout_overflow','stderr_overflow','provider_accepted','vulnerability_audit_completed'):
            with self.subTest(key=key):
                self.value[key]=True;self.reject('wrapper_process');self.value[key]=False
    def test_native_and_outer_process_failure_rejected(self):
        self.reject('wrapper_process',exit_code=1)
        self.value['exit_code']=False;self.reject('wrapper_process')
    def test_capture_controls_and_duration_bound(self):
        self.value['capture_controls']=8;self.reject('wrapper_controls')
        self.value['capture_controls']=9;self.value['duration_ms']=95001;self.reject('wrapper_controls')
    def test_stream_hash_and_stderr_binding(self):
        self.value['stdout_sha256']='d'*64;self.reject('wrapper_stream_binding')
        self.value['stdout_sha256']=hashlib.sha256(base64.b64decode(self.value['stdout_base64'])).hexdigest()
        self.value['stderr_base64']=base64.b64encode(b'warning').decode();self.reject('wrapper_stream_binding')
    def test_noncanonical_or_invalid_base64_rejected(self):
        self.value['stdout_base64']='@@@@';self.reject('wrapper_base64')
    def test_unknown_fields_duplicate_keys_and_case_confusion_rejected(self):
        raw=json.dumps(self.value).encode()
        self.reject('duplicate_key',raw=b'{"success":true,'+raw[1:])
        self.value['extra']=True;self.reject('wrapper_shape');del self.value['extra']
        self.value['mode']='scan';self.reject('wrapper_case')
    def test_stripped_control_must_bind_original_graph_and_flags(self):
        self.value['target']='stripped'
        self.target['file']['sha256']='e'*64;self.target['file']['bytes']=80*1024*1024
        self.value['target_after']=copy.deepcopy(self.target['file'])
        self.value['target_identity']['file']=copy.deepcopy(self.target['file'])
        self.reject('wrapper_stripped_identity',target='stripped')
        self.value['target_identity']['settings']['-ldflags']='-s -w -X github.com/rclone/rclone/fs.Version=v1.75.2-kerberos-original'
        self.run_admit(target='stripped')
    def test_synthetic_blob_cannot_claim_binary_identity(self):
        self.value['mode']='scan';self.value['target']='positive'
        file=dict(sha256='f'*64,bytes=1000)
        self.value['target_before']=file;self.value['target_after']=copy.deepcopy(file)
        self.reject('wrapper_synthetic_identity',mode='scan',target='positive',expected_target=dict(file=file))
        self.value['target_identity']=None
        self.run_admit(mode='scan',target='positive',expected_target=dict(file=file))
