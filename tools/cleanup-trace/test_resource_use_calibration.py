"""Pure calibration schema/selection and source boundary tests; no native calls."""
import copy
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import resource_use_calibration as C

D = Path(__file__).resolve().parent
PROJECT = r'C:\source\tools\cleanup-trace'


def bindings():
    return {key: 'a' * (40 if key in {'commit', 'source_tree'} else 64) for key in C.BINDINGS}


def observation():
    def phase(total, caller):
        return dict(available=True, api=[0]*4, identity=[True]*4, total=total, caller=caller)
    return dict(schema=1, scope='synthetic_rm_calibration', causal_owner=False, runtime_executed=False,
                hard_deadline=False, setup=True, creator_closed=True, held=phase(1, True), released=phase(0, False),
                handle_closed=True, identity_closed=True, file_removed=True, directory_closed=True,
                directory_removed=True, cleanup_complete=True, reason='none', passed=True)


def logs(value):
    label = 'ok' if value['passed'] else 'FAILED'
    counts = '1 passed; 0 failed' if value['passed'] else '0 passed; 1 failed'
    out = f'\nrunning 1 test\ntest {C.TEST} ... {label}\n\ntest result: {label}. {counts}; 0 ignored; 0 measured; 4 filtered out; finished in 0.03s\n'.encode()
    err = C.PREFIX + json.dumps(value, separators=(',', ':')).encode() + b'\n'
    return err, out, 0 if value['passed'] else 101


def cargo():
    exe = PROJECT + r'\target\aarch64-pc-windows-msvc\release\deps\triage_cleanup_trace-0123456789abcdef.exe'
    artifact = dict(reason='compiler-artifact', manifest_path=PROJECT+r'\Cargo.toml',
        target=dict(name='triage_cleanup_trace', kind=['lib'], crate_types=['lib'], src_path=PROJECT+r'\src\lib.rs'),
        profile=dict(test=True, opt_level='3', debug_assertions=False, overflow_checks=False), features=[],
        executable=exe, filenames=[exe])
    return [artifact, dict(reason='build-finished', success=True)]


class CalibrationTests(unittest.TestCase):
    def test_real_libtest_artifact_only_and_completion(self):
        rows = cargo(); encode = lambda r: b'\n'.join(json.dumps(x).encode() for x in r)
        selected = C.select(encode(rows), PROJECT)
        self.assertEqual(selected['artifact_kind'], 'resource_use_calibration')
        self.assertNotIn('application', selected)
        for changed in (
            [{**rows[0], 'features':['default']}, rows[1]],
            [{**rows[0], 'profile':{**rows[0]['profile'], 'test':False}}, rows[1]],
            [{**rows[0], 'target':{**rows[0]['target'], 'name':'rclone_triage'}}, rows[1]],
            [{**rows[0], 'target':{**rows[0]['target'], 'kind':['bin']}}, rows[1]],
            [{**rows[0], 'executable':rows[0]['executable'].replace('aarch64', 'x86_64')}, rows[1]],
            [rows[0], rows[0], rows[1]], rows[:1], [rows[1], rows[0]],
            [rows[0], {**rows[1], 'success':False}],
        ):
            with self.subTest(rows=changed), self.assertRaises(ValueError): C.select(encode(changed), PROJECT)

    def test_complete_pair_is_only_synthetic_calibration(self):
        result = C.validate(*logs(observation()), bindings())
        self.assertEqual(result['status'], 'calibrated')
        self.assertFalse(result['causal_pr115_owner']); self.assertFalse(result['runtime_observed'])
        self.assertLessEqual(len(logs(observation())[0]), 1024)

    def test_unsupported_caller_and_nonempty_control_are_unavailable(self):
        for part, total, caller, reason in [('held',0,False,'caller_not_observed'), ('held',2,True,'caller_not_observed'),
                                          ('released',1,True,'control_not_empty'), ('released',1,False,'control_not_empty')]:
            value=observation();value[part].update(total=total,caller=caller);value.update(reason=reason,passed=False)
            self.assertEqual(C.validate(*logs(value),bindings())['status'],'unavailable')

    def test_uncertain_probe_session_or_handle_has_no_credit(self):
        for failure in ('pre_close','end','hold_close','after_end'):
            value=observation();value.update(reason='cleanup_unverified',passed=False,cleanup_complete=False,
                                            identity_closed=False,file_removed=False,directory_removed=False)
            if failure=='hold_close': value.update(handle_closed=False,released=None)
            else:
                target=value['released'] if failure=='after_end' else value['held']
                target.update(available=False,total=None,caller=None)
                if failure=='pre_close':target.update(api=[None]*4,identity=[True,False,None,None])
                else:target['api'][3]=5
                if failure!='after_end':value['released']=None
            self.assertEqual(C.validate(*logs(value),bindings())['status'],'unavailable')
            value['passed']=True
            with self.assertRaises(ValueError):C.validate(*logs(value),bindings())

    def test_api_error_edges_preserve_query_and_end_order(self):
        for api,identity in [([5,None,None,None],[True,True,None,None]),([0,5,None,0],[True]*4),
                             ([0,0,234,0],[True]*4),([0,0,5,0],[True]*4),([0,0,0,0],[True]*4)]:
            value=observation();value['held'].update(available=False,api=api,identity=identity,total=None,caller=None)
            value.update(released=None,reason='held_query_unavailable',passed=False)
            self.assertEqual(C.validate(*logs(value),bindings())['status'],'unavailable')
        for api,identity in [([0,0,0,None],[True]*4),([5,0,0,0],[True]*4),([0,5,0,0],[True]*4),([None]*4,[True]*4)]:
            value=observation();value['held'].update(api=api,identity=identity)
            with self.assertRaises(ValueError):C.validate(*logs(value),bindings())

    def test_no_setup_or_environment_claims_fake_observation(self):
        value=observation();value.update(setup=False,held=None,released=None,reason='environment',passed=False)
        for key in ('creator_closed','handle_closed','identity_closed','file_removed','directory_closed','directory_removed','cleanup_complete'):value[key]=False
        self.assertEqual(C.validate(*logs(value),bindings())['status'],'unavailable')
        value['directory_closed']=True
        with self.assertRaises(ValueError):C.validate(*logs(value),bindings())

    def test_closed_types_keys_bounds_and_private_canary(self):
        for key,bad in [('schema',True),('passed',1),('cleanup_complete',1),('causal_owner',True),
                        ('runtime_executed',True),('hard_deadline',True),('reason','none\0private-canary')]:
            value=observation();value[key]=bad
            with self.subTest(key=key),self.assertRaises(ValueError):C.validate(*logs(value),bindings())
        for bad in (-1,65,True,'private-canary'):
            value=observation();value['held']['total']=bad
            with self.assertRaises(ValueError):C.validate(*logs(value),bindings())
        err,out,code=logs(observation())
        for bad in (err+err,err.replace(b'"schema":1',b'"schema":1,"schema":1'),
                    err.replace(b'"schema":1',b'"schema":1,"\\u0073chema":1'),
                    err.replace(b'"schema":1',b'"schema":1,"private":"private-canary"'),
                    err+b'runtime_cleanup_trace={}\n',C.PREFIX+b'x'*1024):
            with self.assertRaises(ValueError):C.validate(bad,out,code,bindings())

    def test_exact_ignored_test_exit_identity_and_source_bindings(self):
        err,out,code=logs(observation())
        for bad in (out.replace(b'running 1 test',b'running 0 tests'),out.replace(C.TEST.encode(),b'other'),
                    out.replace(b'0 ignored',b'1 ignored'),out+out):
            with self.assertRaises(ValueError):C.validate(err,bad,code,bindings())
        for code in (True,1,101):
            with self.assertRaises(ValueError):C.validate(err,out,code,bindings())
        for key in C.BINDINGS:
            b=bindings();b[key]='A'*64
            with self.assertRaises(ValueError):C.validate(err,out,0,b)

    def test_native_calibration_is_ignored_and_does_not_call_original_trace(self):
        source=(D/'src/resource_use_calibration.rs').read_text()
        self.assertIn('#[ignore = "explicit hosted ARM64 calibration only"]',source)
        self.assertIn('cfg!(target_arch = "aarch64")',source)
        for forbidden in ('Trace::','remove_dir_all','RmShutdown','RmRestart','OpenProcess','thread::spawn','sleep('):
            self.assertNotIn(forbidden,source)
        self.assertEqual(source.count('resource_use::observe(api)'),2)
        self.assertEqual(source.count('fs::remove_file('),1);self.assertEqual(source.count('fs::remove_dir('),1)
        self.assertIn('FILE_SHARE_READ | FILE_SHARE_WRITE',source)
        self.assertIn('CloseHandle(handle)',source)
        self.assertIn('line.len() <= 1024',source)

    def test_cli_failure_is_finite_even_when_printer_fails(self):
        args=['calibration','validate','--stderr','missing','--stdout','missing','--report','unused','--test-exit','0']
        for key,value in bindings().items():args+=['--'+key.replace('_','-'),value]
        with patch('sys.argv',args),patch.object(C,'read',side_effect=OSError('private-canary')),patch('builtins.print',side_effect=RuntimeError('private-canary')):
            self.assertEqual(C.main(),2)


if __name__=='__main__':unittest.main()
