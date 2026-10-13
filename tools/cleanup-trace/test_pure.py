"""Pure report validation only; never calls the native trace or application."""
import json
from pathlib import Path
import types
import unittest
V = types.ModuleType("validate_result")
exec(compile(Path(__file__).with_name("validate_result.py").read_bytes(), "validate_result.py", "exec"), V.__dict__)

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

if __name__=="__main__":unittest.main()
