"""Pure report validation only; never calls the native trace or application."""
import json
import contextlib
import io
import tempfile
from unittest import mock
from pathlib import Path
import types
import unittest
V = types.ModuleType("validate_result")
exec(compile(Path(__file__).with_name("validate_result.py").read_bytes(), "validate_result.py", "exec"), V.__dict__)

A = types.ModuleType("select_artifacts")
exec(compile(Path(__file__).with_name("select_artifacts.py").read_bytes(), "select_artifacts.py", "exec"), A.__dict__)

SHA="a"*64

def record():
    x={key:True for key in V.BOOLS}
    x.update(schema=1,scope="original_runtime_remove_tree",status="observed",reason="none",original_ok=False,os_code=32,operation_us=51000,runtime_sha256=SHA,counts=dict(attempts=2,successful=1,sharing=1,other=0),schema_rejection=None)
    return x

class Tests(unittest.TestCase):
    def check(self,x,code=101):return V.validate(json.dumps(x).encode(),code,SHA)
    def test_genuine_trace_and_not_reproduced_are_distinct(self):
        self.assertEqual(self.check(record())["status"],"observed")
        x=record();x.update(status="not_reproduced",original_ok=True,os_code=None,target_identity_verified=False)
        self.assertEqual(self.check(x,0)["status"],"not_reproduced")
        with self.assertRaises(ValueError):self.check(x)
    def test_every_independent_proof_is_required(self):
        for key in V.BOOLS:
            with self.subTest(key=key):
                x=record();x[key]=False
                with self.assertRaises(ValueError):self.check(x)
    def test_no_false_pass_from_loss_or_wrong_status_or_shape(self):
        for key,value in (("schema",True),("os_code",5),("operation_us",180000001),("runtime_sha256","b"*64),("original_ok",True),("reason","event_loss"),("reason",[]),("consumer_closed",1)):
            x=record();x[key]=value
            with self.assertRaises(ValueError):self.check(x)
        with self.assertRaises(ValueError):self.check(record(),True)
        for counts in (dict(attempts=1,successful=1,sharing=1,other=0),dict(attempts=1,successful=1,sharing=0,other=0),dict(attempts=129,successful=0,sharing=129,other=0)):
            x=record();x["counts"]=counts
            with self.assertRaises(ValueError):self.check(x)
    def test_unavailable_preserves_failure_without_qualification(self):
        x=record();x.update(status="unavailable",reason="cleanup_uncertain",consumer_closed=False)
        self.assertEqual(self.check(x)["status"],"unavailable")
    def test_closed_correlation_reasons_cannot_qualify(self):
        expected = {
            "correlation_no_selected_start", "correlation_start_order", "correlation_start_end_overlap",
            "correlation_end_missing", "correlation_end_multiple", "correlation_end_order",
            "correlation_end_before_start", "correlation_end_unowned", "correlation_cross_thread_reuse",
        }
        self.assertEqual(V.CORRELATION_REASONS, expected)
        for reason in expected:
            with self.subTest(reason=reason):
                x=record();x.update(status="unavailable",reason=reason,counts=None)
                self.assertEqual(self.check(x)["reason"],reason)
                x.update(original_ok=True,os_code=None,target_identity_verified=False)
                self.assertEqual(self.check(x,0)["status"],"unavailable")
                for status in ("observed","not_reproduced"):
                    x["status"]=status
                    with self.assertRaises(ValueError):self.check(x,0)
                x.update(status="unavailable",counts=record()["counts"])
                with self.assertRaises(ValueError):self.check(x,0)
                x.update(counts=None,schema_rejection=dict(attribution="unattributed_fileio",stage="version",property=None,opcode=64,version=1,header_flags=64,tdh_status=None,size=None))
                with self.assertRaises(ValueError):self.check(x,0)
        x=record();x.update(status="unavailable",reason="correlation_missing_or_ambiguous",counts=None)
        self.assertEqual(self.check(x)["reason"],"correlation_missing_or_ambiguous")
        for reason in ("correlation_unknown", "CORRELATION_END_MISSING", "correlation_end_missing\0", "correlation_end_missing ", "private-canary/path/id", None, 1, []):
            x=record();x.update(status="unavailable",reason=reason,counts=None)
            with self.assertRaises(ValueError):self.check(x)
    def test_duplicate_extra_canary_and_records_refused(self):
        raw=json.dumps(record()).encode()
        with self.assertRaises(ValueError):V.validate(raw[:-1]+b',"schema":1}',101,SHA)
        x=record();x['private_canary']='secret'
        with self.assertRaises(ValueError):self.check(x)
        self.assertEqual(V.select(b'private unrelated text\nruntime_cleanup_trace='+raw),raw)
        for log in (b'no record',b'runtime_cleanup_trace='+raw+b'\nruntime_cleanup_trace='+raw):
            with self.assertRaises(ValueError):V.select(log)


ROOT = r"D:\a\triage\triage\rclone-triage"


def artifacts():
    rows=[]
    for test,name,source in ((False,"rclone-triage",r"src\main.rs"),(True,"cli_acquisition",r"tests\cli_acquisition.rs")):
        exe=ROOT+"\\target\\"+A.TARGET+"\\release\\"+(r"deps\cli_acquisition-0123456789abcdef.exe" if test else "rclone-triage.exe")
        rows.append(dict(reason="compiler-artifact", manifest_path=ROOT+r"\Cargo.toml",
            target=dict(name=name,kind=["test" if test else "bin"],crate_types=["bin"],src_path=ROOT+"\\"+source),
            profile=dict(test=test),features=["default","runtime-cleanup-trace"],executable=exe,filenames=[exe]))
    return rows+[dict(reason="build-finished",success=True)]


def cargo_bytes(rows):
    return b"\n".join(json.dumps(row).encode() for row in rows)


def harness_stdout(code=0):
    outcome,passed,failed=("ok",1,0) if code==0 else ("FAILED",0,1)
    return (f"\nrunning 1 test\ntest {V.EMPTY_TEST} ... {outcome}\n\n"
            f"test result: {outcome}. {passed} passed; {failed} failed; 0 ignored; 0 measured; 16 filtered out; finished in 0.12s\n").encode()


class ArtifactTests(unittest.TestCase):
    def test_exact_pair_selected_with_mixed_cargo_separators(self):
        rows=artifacts();rows[0]['manifest_path']=rows[0]['manifest_path'].replace('\\','/')
        found=A.select(cargo_bytes(rows),ROOT)
        self.assertEqual(found['application'],rows[0]['executable'])
        self.assertEqual(found['test_harness'],rows[1]['executable'])
        self.assertEqual(set(found),{'schema','application','test_harness','cargo_json_sha256'})

    def test_missing_duplicate_failed_or_extra_finish(self):
        rows=artifacts()
        for bad in (rows[:1]+rows[2:], rows+[rows[0]], rows[:-1], rows+[rows[-1]], rows[:-1]+[dict(reason='build-finished',success=False)]):
            with self.subTest(bad=bad),self.assertRaises(ValueError):A.select(cargo_bytes(bad),ROOT)

    def test_wrong_manifest_source_kind_profile_feature_location(self):
        changes=[('manifest_path',ROOT+r'\other\Cargo.toml'),('executable',ROOT+r'\target\debug\cli_acquisition-0123456789abcdef.exe'),
                 ('features',['default']),('features',['default','runtime-cleanup-trace','other']),('profile',{'test':False}),
                 ('target',dict(name='cli_acquisition',kind=['bin'],crate_types=['bin'],src_path=ROOT+r'\tests\cli_acquisition.rs')),
                 ('target',dict(name='cli_acquisition',kind=['test'],crate_types=['bin'],src_path=ROOT+r'\tests\other.rs')),
                 ('filenames',[])]
        for key,value in changes:
            rows=artifacts();rows[1][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):A.select(cargo_bytes(rows),ROOT)

    def test_paths_cannot_alias_or_escape(self):
        for path in (r'relative\x',r'\\server\share\x',r'\\?\D:\x',r'D:\x\..\y',r'D:\x\.\y',r'D:\x\\y',r'D:\x:stream',r'D:\x.\y',r'D:\x \y','D:\\x\0y'):
            with self.subTest(path=path),self.assertRaises(ValueError):A.windows_path(path)
        rows=artifacts();rows[1]['executable']=rows[1]['executable'].replace('deps','DEPS')
        with self.assertRaises(ValueError):A.select(cargo_bytes(rows),ROOT)

    def test_bounds_malformed_and_duplicate_json_keys(self):
        for raw in (b'',b'x',b'[]',b'{}\n'*10001,b'x'*(A.MAX_JSON+1),b'{"reason":"build-finished","success":true,"success":true}'):
            with self.assertRaises((ValueError,KeyError)):A.select(raw,ROOT)


class HarnessTests(unittest.TestCase):
    def test_both_real_exit_shapes_and_closed_projection(self):
        for code in (0,101):
            value=V.validate_harness(harness_stdout(code).replace(b'\n',b'\r\n'),code,SHA,'b'*64)
            self.assertEqual(value['selected_tests'],1);self.assertEqual(value['test_exit'],code)
            self.assertEqual(value['test'],V.EMPTY_TEST)
            self.assertNotIn('private-canary',json.dumps(value))

    def test_zero_wrong_duplicate_ignored_or_missing_test_is_rejected(self):
        good=harness_stdout()
        for bad in (good.replace(b'running 1 test',b'running 0 tests'),good.replace(V.EMPTY_TEST.encode(),b'wrong_test'),
                    good+good,good.replace(b' ... ok',b' ... ignored'),good.replace(b'0 ignored',b'1 ignored'),
                    good.replace(b'1 passed',b'0 passed'),good.split(b'test result:')[0],good.replace(b'0 failed',b'1 failed')):
            with self.assertRaises(ValueError):V.validate_harness(bad,0,SHA,SHA)

    def test_exit_hash_and_stream_bounds(self):
        for code in (True,1,-1,102):
            with self.assertRaises(ValueError):V.validate_harness(harness_stdout(),code,SHA,SHA)
        with self.assertRaises(ValueError):V.validate_harness(harness_stdout(),101,SHA,SHA)
        for raw in (b'',b'\xff',b'x'*(4*1024*1024+1)):
            with self.assertRaises(ValueError):V.validate_harness(raw,0,SHA,SHA)
        for digest in (None,1,'A'*64,'a'*63,'private-canary'):
            with self.assertRaises(ValueError):V.validate_harness(harness_stdout(),0,digest,SHA)

    def test_cli_historical_mode_unchanged_and_new_mode_all_or_none(self):
        with tempfile.TemporaryDirectory() as directory:
            trace=Path(directory)/'stderr';stdout=Path(directory)/'stdout'
            x=record();x.update(status='not_reproduced',original_ok=True,os_code=None,target_identity_verified=False)
            trace.write_bytes(b'runtime_cleanup_trace='+json.dumps(x).encode());stdout.write_bytes(harness_stdout())
            base=['validator','--log',str(trace),'--test-exit','0','--runtime-sha256',SHA,'--application-sha256',SHA,'--commit','b'*40]
            extra=['--test-stdout',str(stdout),'--test-harness-sha256',SHA,'--cargo-json-sha256',SHA]
            for tail,code in (([],0),(extra,0),(extra[:2],2)):
                out=io.StringIO()
                with mock.patch('sys.argv',base+tail),contextlib.redirect_stdout(out):self.assertEqual(V.main(),code)
                result=json.loads(out.getvalue())
                if code==0:self.assertEqual('execution' in result,bool(tail))
                else:self.assertEqual(result['reason'],'validation_failed')

    def test_workflow_fixed_single_call_and_matching_forwarding(self):
        root=Path(__file__).resolve().parents[2]
        workflow=(root/'.github/workflows/original-cleanup-trace.yml').read_text()
        invocation=f'& $harness {V.EMPTY_TEST} --exact --nocapture --test-threads=1 > $privateOut 2> $privateErr'
        self.assertEqual(workflow.count(invocation),1)
        self.assertEqual(workflow.count('cargo test --locked --release'),1)
        self.assertIn('--no-run --message-format=json',workflow)
        self.assertNotIn('--list',workflow)
        self.assertIn('--test-stdout $privateOut --test-harness-sha256 $harnessHash --cargo-json-sha256 $cargoJsonHash',workflow)
        self.assertIn('if ($originalExit -ne 0) { exit $originalExit }',workflow)
        self.assertEqual(workflow.count('Get-FileHash -LiteralPath $harness'),2)
        source=(root/'rclone-triage/tests/cli_acquisition.rs').read_text()
        old=source[source.index('fn cli_imported_listing_is_complete_recursive'):]
        new=source[source.index('fn '+V.EMPTY_TEST):]
        def block(text):return text[text.index('    #[cfg(feature = "runtime-cleanup-trace")]'):text.index('    assert!(')]
        self.assertEqual(block(old),block(new))
        new=new[:new.index('\n#[test]')]
        self.assertEqual(new.count('.output().unwrap()'),1)

if __name__=="__main__":unittest.main()
