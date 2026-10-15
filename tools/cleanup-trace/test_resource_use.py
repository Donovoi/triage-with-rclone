"""Pure synthetic validation and source-order tests; never load native code."""
import copy
import contextlib
import io
import json
import sys
import unittest
from pathlib import Path
from unittest import mock
import validate_resource_use as V

SHA = 'a'*64
CANARY = 'PRIVATE-CANARY/path/PID/secret'

def trace():
    value = {key:True for key in V.primary.BOOLS}
    value.update(schema=4,capture_contract=V.primary.CAPTURE_CONTRACT,scope='original_runtime_remove_tree',
                 status='unavailable',reason='correlation_end_multiple',original_ok=False,os_code=32,
                 operation_us=1200,runtime_sha256=SHA,counts=None,schema_rejection=None,
                 ownership={'availability':'unavailable','reason':'unsupported_opcode','pattern':None,
                            'starts':None,'ends':None,'complete_pairs':None,'nonselected_create_pairs':None,
                            'other_operation_pairs':None,'rejection':{'opcode':84,'version':3,'header_flags':832}})
    return value

def record():
    return dict(schema=1,scope='post_failure_resource_use',phase='after_trace_before_residue',original_os_code=32,
                original_result_preserved=True,causal_owner=False,hard_deadline=False,runtime_sha256=SHA,
                availability='available',reason='none',trace_closed=True,prior_probe_closed=True,
                pre_identity=True,pre_closed=True,post_identity=True,post_closed=True,
                start_status=0,register_status=0,list_status=0,end_status=0,caller_listed=False,
                counts={'total':0,'other_processes':0,'types':[0]*7})

def raw(value): return json.dumps(value,separators=(',',':')).encode()
def unavailable(reason):
    value=record(); value.update(reason=reason,availability='unavailable',counts=None,caller_listed=None)
    return value
def stdout():
    return f'running 1 test\ntest {V.TEST} ... FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 457 filtered out; finished in 0.12s\n'.encode()
def log(value=None, original=None):
    return b'private unrelated '+CANARY.encode()+b'\nruntime_cleanup_trace='+raw(original or trace())+b'\n'+V.PREFIX+raw(value or record())+b'\n'
def replay(data): return V.replay(data,stdout(),101,SHA,'b'*64,'c'*64,'d'*40,'e'*40,'f'*64,'1'*64,'1')

class Validation(unittest.TestCase):
    def check(self,value,original=None): return V.validate(raw(value),original or trace())
    def test_unavailable_etw_does_not_suppress_separate_observation(self):
        result=replay(log())
        self.assertEqual(result['original_trace']['status'],'unavailable')
        self.assertEqual(result['resource_use']['availability'],'available')
        self.assertFalse(result['original_cleanup_passed']); self.assertFalse(result['causal_owner_proved'])
        self.assertFalse(result['provider_credit']); self.assertNotIn(CANARY,json.dumps(result))
    def test_empty_and_caller_counts_are_not_causation(self):
        self.check(record())
        value=record(); value.update(caller_listed=True,counts={'total':2,'other_processes':1,'types':[0,0,0,1,0,1,0]})
        self.check(value)
        value['counts']['other_processes']=2
        with self.assertRaises(ValueError): self.check(value)
    def test_each_transport_flag_blocks_query_even_with_semantic_validity(self):
        for key in V.TRACE_CLOSED:
            with self.subTest(key=key):
                original=trace(); original[key]=False
                value=record()
                with self.assertRaises(ValueError): self.check(value,original)
                value=unavailable('trace_unclosed'); value['trace_closed']=False
                for k in ('pre_identity','pre_closed','post_identity','post_closed','start_status','register_status','list_status','end_status'): value[k]=None
                self.check(value,original)
    def test_initial_unavailable_gates_have_no_api_or_probe_facts(self):
        for reason in ('trace_unclosed','prior_probe_unclosed'):
            value=unavailable(reason)
            for k in ('pre_identity','pre_closed','post_identity','post_closed','start_status','register_status','list_status','end_status'): value[k]=None
            with self.assertRaises(ValueError): self.check(value)
        for reason in ('registration_unavailable','primary_unwritten','prior_probe_unclosed'):
            value=unavailable(reason); original=trace()
            for k in ('pre_identity','pre_closed','post_identity','post_closed','start_status','register_status','list_status','end_status'): value[k]=None
            if reason=='prior_probe_unclosed':
                value['prior_probe_closed']=False; original['target_identity_verified']=False
            self.check(value,original)
            value['start_status']=0
            with self.assertRaises(ValueError): self.check(value,original)
    def test_pre_probe_close_and_identity_stop_before_start(self):
        for matched,closed,reason in ((False,True,'pre_identity'),(True,False,'pre_close'),(False,False,'pre_close')):
            value=unavailable(reason); value.update(pre_identity=matched,pre_closed=closed)
            for k in ('post_identity','post_closed','start_status','register_status','list_status','end_status'): value[k]=None
            self.check(value); value['end_status']=0
            with self.assertRaises(ValueError): self.check(value)
    def test_api_edges_have_exact_one_end_after_started(self):
        cases=[('start',5,None,None,None),('register',0,5,None,0),('capacity',0,0,234,0),('list',0,0,5,0),('shape',0,0,0,0),('end',0,0,0,5)]
        for reason,start,register,listing,end in cases:
            with self.subTest(reason=reason):
                value=unavailable(reason); value.update(start_status=start,register_status=register,list_status=listing,end_status=end)
                if reason=='start': value.update(post_identity=None,post_closed=None)
                self.check(value)
                value['counts']=record()['counts']
                with self.assertRaises(ValueError): self.check(value)
    def test_end_and_probe_uncertainty_override_other_results(self):
        for reason,postidentity,postclosed,end in (('post_identity',False,True,0),('post_close',False,False,0),('end',False,False,6)):
            value=unavailable(reason); value.update(post_identity=postidentity,post_closed=postclosed,end_status=end)
            self.check(value); value['reason']='none'; value['availability']='available'
            with self.assertRaises(ValueError): self.check(value)
    def test_shape_types_counts_and_closed_enums(self):
        changes=[('schema',True),('causal_owner',True),('hard_deadline',True),('runtime_sha256','b'*64),
                 ('reason','none\0'),('reason',CANARY),('scope',CANARY),('original_os_code',5),
                 ('pre_closed',1),('start_status',True),('end_status',-1),('list_status',2**32),
                 ('caller_listed',1),('availability','available ')]
        for key,value in changes:
            with self.subTest(key=key,value=value):
                x=record(); x[key]=value
                with self.assertRaises(ValueError): self.check(x)
        for c in ({'total':65,'other_processes':65,'types':[65,0,0,0,0,0,0]},
                  {'total':1,'other_processes':1,'types':[0]*7},
                  {'total':0,'other_processes':0,'types':[False]*7},
                  {'total':0,'other_processes':0,'types':[0]*8}):
            x=record(); x['counts']=c
            with self.assertRaises(ValueError): self.check(x)
    def test_duplicate_unknown_and_bound(self):
        data=raw(record())
        for malformed in (data[:-1]+b',"schema":1}',data[:-1]+b',"\\u0073chema":1}',data[:-1]+b',"private":"'+CANARY.encode()+b'"}',data+b' '*1024):
            with self.assertRaises(ValueError): V.validate(malformed,trace())
        for key in record():
            x=record(); del x[key]
            with self.assertRaises(ValueError): self.check(x)
    def test_duplicate_missing_reordered_windows_are_invalid(self):
        value=log()
        for data in (b'none',value+V.PREFIX+raw(record()),value+b'runtime_cleanup_trace='+raw(trace()),
                     V.PREFIX+raw(record())+b'\nruntime_cleanup_trace='+raw(trace())):
            with self.assertRaises(ValueError): replay(data)
    def test_success_non32_and_wrong_unit_cannot_admit_resource_use(self):
        for change in ({'original_ok':True,'os_code':None},{'os_code':5}):
            original=trace(); original.update(change)
            with self.assertRaises(ValueError): self.check(record(),original)
        for data in (stdout().replace(V.TEST.encode(),V.primary.LIBRARY_TEST.encode()),stdout().replace(b'running 1 test',b'running 2 tests'),stdout().replace(b'1 failed',b'0 failed')):
            with self.assertRaises(ValueError): V.execution(data,101,SHA,SHA,'1')
        for exitcode in (0,1,True):
            with self.assertRaises(ValueError): V.execution(stdout(),exitcode,SHA,SHA,'1')
        with self.assertRaises(ValueError): V.execution(stdout(),101,SHA,SHA,None)
    def test_prefix_inclusive_bound_with_maximum_statuses(self):
        value=unavailable('end'); value.update(register_status=0xffffffff,list_status=None,end_status=0xffffffff)
        self.assertLessEqual(len(raw(value))+len(V.PREFIX)+1,1024); self.check(value)
    def cli(self,output_error=None,missing=False):
        argv=['validate_resource_use.py']
        for key,value in (('log','log'),('test-stdout','stdout'),('test-exit','101'),('runtime-sha256',SHA),
                          ('test-harness-sha256','b'*64),('cargo-json-sha256','c'*64),('commit','d'*40),
                          ('source-tree','e'*40),('application-source-sha256','f'*64),('test-source-sha256','1'*64),('dynamic-providers','1')):
            argv.extend(('--'+key,value))
        original_only=b'runtime_cleanup_trace='+raw(trace())+b'\n'
        with mock.patch.object(sys,'argv',argv), mock.patch.object(V,'read_bounded',side_effect=lambda p: stdout() if p=='stdout' else original_only if missing else log()):
            if output_error:
                with mock.patch('builtins.print',side_effect=output_error) as printer:
                    self.assertEqual(V.main(),1); self.assertEqual(printer.call_count,1)
            else:
                output=io.StringIO()
                with contextlib.redirect_stdout(output): self.assertEqual(V.main(),1)
                return [json.loads(line) for line in output.getvalue().splitlines()]
    def test_missing_supplement_does_not_hide_valid_original(self):
        values=self.cli(missing=True)
        self.assertEqual(values[0]['original_trace'],trace())
        self.assertEqual(values[1]['result'],'invalid_resource_use')
        self.assertNotIn(CANARY,json.dumps(values))
    def test_failed_printer_stops_without_retry_or_raw_error(self):
        self.cli(output_error=OSError(CANARY))
        self.cli(output_error=RuntimeError(CANARY))

class SourceBoundaries(unittest.TestCase):
    def test_hook_original_finish_and_result_order(self):
        text=Path(__file__).with_name('src').joinpath('native.rs').read_text()
        measure=text[text.index('    pub fn measure'):text.index('    unsafe fn verify_survivor')]
        self.assertEqual(measure.count('model::original_then(remove,'),1)
        self.assertLess(measure.index('self.finish('),measure.index('self.observe_resource_use()'))
        self.assertIn('if code == Some(32)',measure)
        observer=text[text.index('    fn observe_resource_use'):text.index('    fn shutdown')]
        self.assertLess(observer.index('!self.primary_written'),observer.index('resource_use::observe(probe)'))
        self.assertIn('let _ = io::stderr().lock().write_all',observer)
        self.assertNotIn('self.reason',observer)
        self.assertNotIn('?',observer)
        self.assertIn('TRIAGE_RUNTIME_RESOURCE_USE',text)
    def test_windows_adapter_no_shutdown_retry_or_extra_registration(self):
        text=Path(__file__).with_name('src').joinpath('resource_use_windows.rs').read_text()
        for name in ('RmStartSession(','RmRegisterResources(','RmGetList(','RmEndSession('):
            self.assertEqual(text.count(name),1)
        for forbidden in ('RmShutdown(','RmRestart(','RmCancelCurrentTask(','OpenProcess(','thread::','sleep(','impl Drop'):
            self.assertNotIn(forbidden,text)
        self.assertIn('self.session, 1, &file, 0, ptr::null(), 0, ptr::null()',text)
        self.assertIn('FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE',text)
        self.assertIn('let closed = CloseHandle(handle) != 0',text)
        self.assertIn('time(a.ProcessStartTime) == time(b.ProcessStartTime)',text)
    def test_model_no_end_on_start_failure_and_no_panic_or_retry_in_observe(self):
        text=Path(__file__).with_name('src').joinpath('resource_use.rs').read_text()
        observe=text[text.index('pub fn observe'):text.index('#[cfg(test)]')]
        self.assertEqual(observe.count('api.start()'),1); self.assertEqual(observe.count('api.end()'),1)
        for value in ('unwrap(', 'expect(', 'panic!', 'loop {', 'while ', 'sleep(', 'thread::'):
            self.assertNotIn(value,observe)
        self.assertLess(observe.index('api.probe()'),observe.index('api.start()'))
        self.assertLess(observe.index('api.end()'),observe.rindex('api.probe()'))

if __name__=='__main__': unittest.main()
