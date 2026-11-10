import copy,unittest
from audit_contract import ContractError
from tool_worker import validate_status
class ToolWorkerStatus(unittest.TestCase):
    def status(self,phase='startup',index=-1,processed=0,error='none',http=0):
        return dict(schema_version=1,phase=phase,asset_index=index,processed_assets=processed,error=error,http_status=http)
    def test_bounded_success_phases(self):
        for value in (self.status(),self.status('download',0,0),self.status('download',0,1),
                      self.status('download',33,34),self.status('prepare',-1,34),self.status('complete',-1,34)):
            self.assertEqual(validate_status(value),value)
    def test_incomplete_count_cannot_claim_complete(self):
        for count in (0,33,35,True):
            with self.assertRaises(ContractError):validate_status(self.status('complete',-1,count))
    def test_download_progress_must_match_owned_asset(self):
        for index,count in ((-1,0),(34,34),(4,3),(4,6)):
            with self.assertRaises(ContractError):validate_status(self.status('download',index,count))
    def test_http_error_requires_bounded_status(self):
        validate_status(self.status('download',2,2,'http_error',503))
        for error,http in (('none',503),('http_error',0),('http_error',600)):
            with self.assertRaises(ContractError):validate_status(self.status('download',2,2,error,http))
    def test_complete_cannot_contain_failure(self):
        with self.assertRaises(ContractError):validate_status(self.status('complete',-1,34,'timeout'))
    def test_unknown_diagnostics_and_extra_fields_rejected(self):
        for change in (dict(phase='native_build'),dict(error='arbitrary message'),dict(detail='raw stderr')):
            with self.assertRaises(ContractError):validate_status(dict(self.status(),**change))
    def test_prepare_phase_cannot_hide_unprocessed_assets(self):
        with self.assertRaises(ContractError):validate_status(self.status('prepare',-1,33))

class ToolWorkerOwnership(unittest.TestCase):
    def setup_case(self):
        import tempfile,types
        from pathlib import Path
        import tool_worker as W
        temporary=tempfile.TemporaryDirectory()
        root=Path(temporary.name);source=root/'driver.py';source.write_text('# inert source\n')
        calls=[]
        C=types.SimpleNamespace(hosted_guard=lambda:calls.append('hosted_guard'),
            directory=lambda *args:(1,2),file_hash=lambda *args:'a'*64)
        class Failure(Exception):
            def __init__(self,code):self.code=code;super().__init__(code)
        R=types.SimpleNamespace(ProbeError=Failure)
        return W,temporary,root,source,C,R,calls
    def test_timeout_kills_only_owned_group_and_joins(self):
        from unittest.mock import patch
        import types
        W,tmp,root,source,C,R,calls=self.setup_case()
        class Process:
            pid=77
            def wait(self,timeout):
                calls.append(('wait',timeout))
                if timeout==270:raise W.subprocess.TimeoutExpired('owned-worker',timeout)
                return 0
            def poll(self):return None
        try:
            with patch.object(W.signal,'SIGKILL',9,create=True),patch.object(W.sys,'version_info',(3,14)),patch.object(W.subprocess,'Popen',return_value=Process()) as launch,\
                 patch.object(W.os,'getpgid',return_value=77,create=True),patch.object(W.os,'killpg',create=True) as kill:
                with self.assertRaisesRegex(R.ProbeError,'package_worker_failed'):
                    W.prepare_owned(C,R,None,root,source,b'')
                kill.assert_called_once_with(77,W.signal.SIGKILL)
                self.assertEqual(calls,['hosted_guard',('wait',270),('wait',3)])
                self.assertTrue(launch.call_args.kwargs['start_new_session'])
                self.assertEqual(launch.call_args.args[0][1:4],['-I','-S','-B'])
        finally:tmp.cleanup()
    def test_unbound_process_group_is_never_signalled(self):
        from unittest.mock import patch
        import types
        W,tmp,root,source,C,R,calls=self.setup_case()
        process=types.SimpleNamespace(pid=77,poll=lambda:None,wait=lambda **kw:(_ for _ in ()).throw(W.subprocess.TimeoutExpired('owned-worker',270)))
        try:
            with patch.object(W.signal,'SIGKILL',9,create=True),patch.object(W.sys,'version_info',(3,14)),patch.object(W.subprocess,'Popen',return_value=process),\
                 patch.object(W.os,'getpgid',return_value=88,create=True),patch.object(W.os,'killpg',create=True) as kill:
                with self.assertRaisesRegex(ContractError,'package_cleanup_failed'):W.prepare_owned(C,R,None,root,source,b'')
                kill.assert_not_called()
        finally:tmp.cleanup()
    def test_failure_to_join_is_a_cleanup_failure(self):
        from unittest.mock import patch
        import types
        W,tmp,root,source,C,R,calls=self.setup_case()
        process=types.SimpleNamespace(pid=77,poll=lambda:None,wait=lambda **kw:(_ for _ in ()).throw(W.subprocess.TimeoutExpired('owned-worker',kw['timeout'])))
        try:
            with patch.object(W.signal,'SIGKILL',9,create=True),patch.object(W.sys,'version_info',(3,14)),patch.object(W.subprocess,'Popen',return_value=process),\
                 patch.object(W.os,'getpgid',return_value=77,create=True),patch.object(W.os,'killpg',create=True):
                with self.assertRaisesRegex(R.ProbeError,'package_cleanup_failed'):W.prepare_owned(C,R,None,root,source,b'')
        finally:tmp.cleanup()
