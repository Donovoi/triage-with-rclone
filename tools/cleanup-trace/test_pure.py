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
        invocation=f'& $harness {V.LIBRARY_TEST} --exact --nocapture --test-threads=1 > $privateOut 2> $privateErr'
        self.assertEqual(workflow.count(invocation),1)
        self.assertEqual(workflow.count('cargo test --locked --release'),1)
        self.assertIn('--no-run --message-format=json',workflow)
        self.assertNotIn('--list',workflow)
        self.assertIn('--test-stdout $privateOut --test-harness-sha256 $harnessHash --cargo-json-sha256 $cargoJsonHash',workflow)
        self.assertIn('if ($originalExit -ne 0) { exit $originalExit }',workflow)
        self.assertEqual(workflow.count('Get-FileHash -LiteralPath $harness'),2)
        self.assertIn('--lib --no-run --message-format=json',workflow)
        self.assertIn("RCLONE_TRIAGE_DYNAMIC_PROVIDERS: '1'",workflow)
        self.assertIn('--library-unit --dynamic-providers $env:RCLONE_TRIAGE_DYNAMIC_PROVIDERS',workflow)
        self.assertNotIn('$selected.application',workflow)
        source=(root/'rclone-triage/src/ui/runner.rs').read_text()
        unit=source[source.index('    fn test_main_menu_enter_download_sets_status()'):]
        unit=unit[:unit.index('    #[test]')]
        self.assertEqual(unit.count('handle_main_menu_enter(&mut app)'),1)
        self.assertIn('handle_main_menu_enter(&mut app).unwrap()',unit)

class OwnershipTests(unittest.TestCase):
    def trace(self, ownership=None):
        value = record()
        value.update(schema=2, status="unavailable", reason="correlation_end_multiple", counts=None,
                     ownership=ownership or self.observed())
        return value

    def observed(self):
        return dict(availability="available", reason="none", pattern="sequential_reuse",
                    starts=2, ends=2, complete_pairs=2, nonselected_create_pairs=0, other_operation_pairs=1)

    def unknown(self, reason="schema"):
        return dict(availability="unavailable", reason=reason, pattern=None,
                    **dict.fromkeys(V.OWNERSHIP_COUNTS))

    def check(self, value):
        return V.validate(json.dumps(value).encode(), 101, SHA)

    def test_schema1_remains_readable_and_schema2_has_exact_keys(self):
        self.assertEqual(V.validate(json.dumps(record()).encode(), 101, SHA), record())
        for field in ("ownership", "PRIVATE"):
            old = record(); old[field] = None
            with self.assertRaises(ValueError): self.check(old)
        for schema in (True, False, 0, 3, "2", 2.0, None):
            value = self.trace(); value["schema"] = schema
            with self.assertRaises(ValueError): self.check(value)
        value = self.trace(); del value["ownership"]
        with self.assertRaises(ValueError): self.check(value)
        value = self.trace(); value["PRIVATE"] = None
        with self.assertRaises(ValueError): self.check(value)

    def test_ownership_cannot_qualify_or_fill_main_counts(self):
        value = self.trace()
        self.assertEqual(self.check(value)["status"], "unavailable")
        for status in ("observed", "not_reproduced"):
            value = self.trace(); value["status"] = status
            with self.assertRaises(ValueError): self.check(value)
        value = self.trace(); value["counts"] = record()["counts"]
        with self.assertRaises(ValueError): self.check(value)
        for reason in V.REASONS - {"correlation_end_multiple"}:
            value = self.trace(); value["reason"] = reason
            with self.assertRaises(ValueError): self.check(value)

    def test_schema2_null_ownership_preserves_other_original_results(self):
        for reason in V.REASONS - {"none", "correlation_end_multiple"}:
            value = self.trace(); value.update(reason=reason, ownership=None)
            self.assertEqual(self.check(value)["reason"], reason)
        value = record(); value.update(schema=2, ownership=None)
        self.assertEqual(self.check(value)["status"], "observed")
        value.update(status="not_reproduced", original_ok=True, os_code=None)
        self.assertEqual(V.validate(json.dumps(value).encode(), 0, SHA)["status"], "not_reproduced")
        value = self.trace(); value["ownership"] = None
        with self.assertRaises(ValueError): self.check(value)

    def test_unavailable_witness_is_null_without_invented_counts(self):
        for reason in V.OWNERSHIP_REASONS:
            value = self.trace(self.unknown(reason)); self.check(value)
            for key in V.OWNERSHIP_COUNTS | {"pattern"}:
                broken = self.trace(self.unknown(reason)); broken["ownership"][key] = 0
                with self.assertRaises(ValueError): self.check(broken)
        for reason in ("none", "PRIVATE", None, True, [], {}):
            with self.assertRaises(ValueError): self.check(self.trace(self.unknown(reason)))

    def test_available_witness_requires_all_existing_collection_gates(self):
        for field in V.BOOLS - {"target_identity_verified"}:
            value = self.trace(); value[field] = False
            with self.assertRaises(ValueError): self.check(value)
            value["ownership"] = self.unknown("teardown")
            self.check(value)
        value = self.trace(); value["operation_us"] = None
        with self.assertRaises(ValueError): self.check(value)
        value = self.trace(); value["target_identity_verified"] = False
        self.check(value)  # No new file identity or holder claim.

    def test_numeric_privacy_shape_and_finite_enum_negatives(self):
        for field in V.OWNERSHIP_COUNTS:
            for bad in (True, False, -1, 8193, 1.0, float("nan"), float("inf"), "PRIVATE", None, [], {}):
                value = self.trace(); value["ownership"][field] = bad
                with self.assertRaises(ValueError): self.check(value)
        for field in ("availability", "pattern", "reason"):
            for bad in ("PRIVATE", True, None, [], {}):
                value = self.trace(); value["ownership"][field] = bad
                with self.assertRaises(ValueError): self.check(value)
        for field in V.OWNERSHIP_KEYS:
            value = self.trace(); del value["ownership"][field]
            with self.assertRaises(ValueError): self.check(value)
        value = self.trace(); value["ownership"]["PRIVATE"] = 1
        with self.assertRaises(ValueError): self.check(value)

    def test_anomalies_keep_pair_attribution_null(self):
        for pattern, starts, ends in (("extra_end_without_observed_begin", 1, 2),
                                     ("overlapping_begins", 2, 2), ("incomplete", 3, 2)):
            witness = self.observed(); witness.update(pattern=pattern, starts=starts, ends=ends,
                complete_pairs=None, nonselected_create_pairs=None, other_operation_pairs=None)
            self.check(self.trace(witness))
            for key in ("complete_pairs", "nonselected_create_pairs", "other_operation_pairs"):
                broken = dict(witness); broken[key] = 0
                with self.assertRaises(ValueError): self.check(self.trace(broken))
        for change in (dict(starts=1, ends=1, complete_pairs=1, other_operation_pairs=0),
                       dict(complete_pairs=1), dict(nonselected_create_pairs=2),
                       dict(other_operation_pairs=0), dict(starts=4097, ends=4097, complete_pairs=4097)):
            witness = self.observed(); witness.update(change)
            with self.assertRaises(ValueError): self.check(self.trace(witness))

    def test_maximal_record_fits_existing_line_and_printer_failure_is_not_success(self):
        value = self.trace(); value["ownership"].update(starts=4096, ends=4096,
            complete_pairs=4096, nonselected_create_pairs=4094, other_operation_pairs=1)
        data = json.dumps(value, separators=(",", ":")).encode()
        self.assertLessEqual(len(data), 4096)
        self.check(value)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private-log"
            path.write_bytes(b"runtime_cleanup_trace=" + data)
            argv = ['validator', '--log', str(path), '--test-exit', '101', '--runtime-sha256', SHA,
                    '--application-sha256', SHA, '--commit', 'b'*40]
            out = io.StringIO()
            with mock.patch('sys.argv', argv), contextlib.redirect_stdout(out):
                self.assertEqual(V.main(), 1)
            self.assertEqual(json.loads(out.getvalue())["trace"]["status"], "unavailable")
            self.assertNotIn("PRIVATE", out.getvalue())
            with mock.patch('sys.argv', argv), mock.patch('builtins.print', side_effect=OSError('PRIVATE')):
                with self.assertRaises(OSError): V.main()


class OwnershipRejectionTests(unittest.TestCase):
    def trace(self):
        old = OwnershipTests()
        value = old.trace(old.unknown("unsupported_opcode"))
        value["schema"] = 3
        value["ownership"]["rejection"] = dict(opcode=255, version=3, header_flags=64)
        return value

    def check(self, value):
        return V.validate(json.dumps(value).encode(), 101, SHA)

    def test_exact_header_table_roundtrips_without_qualification(self):
        for version in (2, 3):
            for opcode in range(256):
                value = self.trace()
                value["ownership"]["rejection"].update(opcode=opcode, version=version)
                if opcode in (0, 32, 35, 36) or 64 <= opcode <= 77:
                    with self.assertRaises(ValueError): self.check(value)
                else:
                    checked = self.check(value)
                    self.assertEqual(checked, value)
                    self.assertEqual(checked["status"], "unavailable")
                    self.assertIsNone(checked["counts"])
                    for key in V.OWNERSHIP_COUNTS | {"pattern"}:
                        self.assertIsNone(checked["ownership"][key])
        for flags in (64, 0x8040, 0xFFDF):
            value = self.trace(); value["ownership"]["rejection"]["header_flags"] = flags
            self.check(value)

    def test_header_types_bounds_and_private_fields_are_rejected(self):
        for field, maximum in (("opcode", 255), ("version", 255), ("header_flags", 65535)):
            for bad in (None, True, False, -1, maximum + 1, 1.0, "PRIVATE_CANARY", [], {}):
                value = self.trace(); value["ownership"]["rejection"][field] = bad
                with self.assertRaises(ValueError) as error: self.check(value)
                self.assertNotIn("PRIVATE_CANARY", str(error.exception))
        for field, values in (("version", (0, 1, 4, 255)), ("header_flags", (0, 32, 96, 65535))):
            for bad in values:
                value = self.trace(); value["ownership"]["rejection"][field] = bad
                with self.assertRaises(ValueError): self.check(value)
        for missing in ("opcode", "version", "header_flags"):
            value = self.trace(); del value["ownership"]["rejection"][missing]
            with self.assertRaises(ValueError): self.check(value)
        for bad in (None, [], True, "PRIVATE_CANARY", dict(opcode=255, version=3, header_flags=64, PRIVATE_CANARY=7)):
            value = self.trace(); value["ownership"]["rejection"] = bad
            with self.assertRaises(ValueError) as error: self.check(value)
            self.assertNotIn("PRIVATE_CANARY", str(error.exception))
        raw = json.dumps(self.trace()).replace('"opcode": 255', '"opcode": 255, "opcode": 254').encode()
        with self.assertRaises(ValueError): V.validate(raw, 101, SHA)

    def test_first_failure_overrides_keep_header_suppressed(self):
        for field in V.BOOLS - {"target_identity_verified"}:
            value = self.trace(); value[field] = False
            with self.assertRaises(ValueError): self.check(value)
            value["ownership"].update(reason="teardown", rejection=None)
            self.check(value)
        value = self.trace(); value["operation_us"] = None
        with self.assertRaises(ValueError): self.check(value)
        value["ownership"].update(reason="window", rejection=None)
        self.check(value)
        for reason in V.OWNERSHIP_REASONS - {"unsupported_opcode"}:
            value = self.trace(); value["ownership"]["reason"] = reason
            with self.assertRaises(ValueError): self.check(value)
            value["ownership"]["rejection"] = None
            self.check(value)
        for field in V.OWNERSHIP_COUNTS | {"pattern"}:
            value = self.trace(); value["ownership"][field] = 0
            with self.assertRaises(ValueError): self.check(value)

    def test_historical_shapes_and_new_nonrejection_results_remain_distinct(self):
        old = OwnershipTests()
        for value in (old.trace(old.unknown("unsupported_opcode")), old.trace(), record()):
            self.assertEqual(self.check(value), value)
        value = old.trace(); value["schema"] = 3
        with self.assertRaises(ValueError): self.check(value)
        value["ownership"]["rejection"] = None
        self.check(value)
        value["ownership"]["rejection"] = self.trace()["ownership"]["rejection"]
        with self.assertRaises(ValueError): self.check(value)
        for schema in (1, 2, 4):
            value = self.trace(); value["schema"] = schema
            with self.assertRaises(ValueError): self.check(value)
        value = record(); value.update(schema=3, ownership=None)
        self.check(value)
        for change in (dict(status="observed"), dict(status="not_reproduced"),
                       dict(counts=record()["counts"]), dict(reason="none")):
            value = self.trace(); value.update(change)
            with self.assertRaises(ValueError): self.check(value)

    def test_schema3_cli_stays_nonzero_and_record_bound_is_unchanged(self):
        value = self.trace()
        data = json.dumps(value, separators=(",", ":")).encode()
        self.assertLess(len(data), 4096)
        with self.assertRaisesRegex(ValueError, "record_bound"):
            V.validate(data + b" " * 4096, 101, SHA)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private-log"
            path.write_bytes(b"runtime_cleanup_trace=" + data)
            argv = ['validator', '--log', str(path), '--test-exit', '101', '--runtime-sha256', SHA,
                    '--application-sha256', SHA, '--commit', 'b'*40]
            out = io.StringIO()
            with mock.patch('sys.argv', argv), contextlib.redirect_stdout(out):
                self.assertEqual(V.main(), 1)
            self.assertEqual(json.loads(out.getvalue())["trace"], value)
            with mock.patch('sys.argv', argv), mock.patch('builtins.print', side_effect=OSError('PRIVATE')):
                with self.assertRaises(OSError): V.main()


def library_artifacts():
    executable=ROOT+r'\target\aarch64-pc-windows-msvc\release\deps\rclone_triage-0123456789abcdef.exe'
    return [dict(reason='compiler-artifact',manifest_path=ROOT+r'\Cargo.toml',
                 target=dict(name='rclone_triage',kind=['lib'],crate_types=['lib'],src_path=ROOT+r'\src\lib.rs'),
                 profile=dict(test=True,opt_level='3',debug_assertions=False,overflow_checks=False),
                 features=['default','runtime-cleanup-trace'],executable=executable,filenames=[executable]),
            dict(reason='build-finished',success=True)]


def schema_observation():
    return dict(schema=1,scope='unsupported_fileio_schema',availability='available',reason='none',
                runtime_sha256=SHA,call_count=1,
                header=dict(id=0,version=3,channel=0,level=0,opcode=84,task=0,keyword=0,header_flags=832),
                tdh_status=0,buffer_bytes=512,provider_matched=True,descriptor_matched=True,decoding_source=1,
                properties=[dict(name='IrpPtr',flags=0,in_type=16,out_type=0,count=1,length=0)])


class LibrarySelectionTests(unittest.TestCase):
    def test_only_library_executable_is_selected(self):
        rows=library_artifacts();value=A.select(cargo_bytes(rows),ROOT,True)
        self.assertEqual(value['artifact_kind'],'library_test');self.assertNotIn('application',value)
        self.assertEqual(value['test_harness'],rows[0]['executable'])
        with self.assertRaises(ValueError):A.select(cargo_bytes(artifacts()),ROOT,True)
        with self.assertRaises(ValueError):A.select(cargo_bytes(rows),ROOT)

    def test_stale_wrong_profile_feature_and_ambiguous_selection_fail(self):
        for field,value in [('features',['default']),('features',['default','runtime-cleanup-trace','other']),
                            ('manifest_path',ROOT+r'\other\Cargo.toml'),('filenames',[]),
                            ('executable',ROOT+r'\target\x86_64-pc-windows-msvc\release\deps\rclone_triage-0123456789abcdef.exe')]:
            rows=library_artifacts();rows[0][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):A.select(cargo_bytes(rows),ROOT,True)
        for field,value in [('test',False),('test',1),('opt_level','0'),('debug_assertions',True),('overflow_checks',True)]:
            rows=library_artifacts();rows[0]['profile'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):A.select(cargo_bytes(rows),ROOT,True)
        rows=library_artifacts()
        for bad in [rows[:1],rows[1:],rows[:1]+rows,rows+[rows[-1]],rows[::-1]]:
            with self.assertRaises(ValueError):A.select(cargo_bytes(bad),ROOT,True)

    def test_exact_unit_dynamic_refresh_actual_exit_required(self):
        for code in (0,101):
            raw=harness_stdout(code).replace(V.EMPTY_TEST.encode(),V.LIBRARY_TEST.encode())
            result=V.validate_harness(raw,code,SHA,SHA,True,'1')
            self.assertEqual(result['test'],V.LIBRARY_TEST);self.assertEqual(result['test_exit'],code)
            self.assertEqual(result['dynamic_providers'],'1')
            for flag in (None,'0','true',1):
                with self.assertRaises(ValueError):V.validate_harness(raw,code,SHA,SHA,True,flag)
            for bad in (raw.replace(b'running 1 test',b'running 0 tests'),harness_stdout(code),raw+raw):
                with self.assertRaises(ValueError):V.validate_harness(bad,code,SHA,SHA,True,'1')


class SchemaMetadataTests(unittest.TestCase):
    def check(self,value,trace=None):
        return V.validate_schema(json.dumps(value).encode(),trace or record())

    def test_hosted_schema_checks_use_only_fixed_pure_filter(self):
        source=(Path(__file__).resolve().parents[2]/'.github/workflows/original-cleanup-trace.yml').read_text()
        command='          cargo test --manifest-path tools/cleanup-trace/Cargo.toml --locked --lib schema_metadata::tests'
        check="          if ($LASTEXITCODE -ne 0) { throw 'Pure schema tests failed' }"
        self.assertEqual(source.count(command),1)
        self.assertIn(command+'\n'+check+'\n',source)
        before=source.split('      - name: Prepare matching verified runtime')[0]
        self.assertIn('      - name: Pure correlation and output checks',before)
        self.assertIn(command,before)

    def test_available_schema_does_not_change_original_result(self):
        x=schema_observation();trace=record();trace.update(status='unavailable',reason='correlation_end_missing',counts=None)
        self.assertEqual(self.check(x,trace),x)
        self.assertEqual(trace['status'],'unavailable');self.assertIsNone(trace['counts'])
        for n in (0,65536,2**32-1):
            bad=schema_observation();bad.update(availability='unavailable',reason='tdh_failed',tdh_status=122,buffer_bytes=n,
                                              provider_matched=None,descriptor_matched=None,decoding_source=None,properties=None)
            self.assertEqual(self.check(bad),bad)

    def test_no_call_and_native_failure_are_distinct(self):
        for reason in ('not_observed','buffer_unavailable','collection_unavailable'):
            x=schema_observation();x.update(availability='unavailable',reason=reason,call_count=0,
                                          tdh_status=None,buffer_bytes=None,provider_matched=None,
                                          descriptor_matched=None,decoding_source=None,properties=None)
            t=record()
            if reason!='buffer_unavailable':x['header']=None
            if reason=='collection_unavailable':t['consumer_closed']=False;x['call_count']=None
            self.assertEqual(self.check(x,t),x)
            x['tdh_status']=0
            with self.assertRaises(ValueError):self.check(x,t)

    def test_each_original_collection_gate_overrides_schema(self):
        for key in V.BOOLS-{'target_identity_verified'}:
            t=record();t[key]=False
            with self.subTest(key=key),self.assertRaises(ValueError):self.check(schema_observation(),t)
        t=record();t['operation_us']=None
        with self.assertRaises(ValueError):self.check(schema_observation(),t)

    def test_not_observed_cannot_contradict_original_unsupported_header(self):
        x=schema_observation()
        for key in ('header','tdh_status','buffer_bytes','provider_matched','descriptor_matched','decoding_source','properties'):
            x[key]=None
        x.update(availability='unavailable',reason='not_observed',call_count=0)
        self.assertEqual(self.check(x),x)
        with self.assertRaisesRegex(ValueError,'schema_unobserved'):
            self.check(x,OwnershipRejectionTests().trace())

    def test_identity_status_shape_and_no_partial_descriptor_fail_closed(self):
        mutations=[('provider_matched',False),('descriptor_matched',1),('call_count',2),('call_count',True),
                   ('tdh_status',5),('buffer_bytes',65537),('buffer_bytes',0),('decoding_source',2),
                   ('runtime_sha256','b'*64),('reason','private-canary'),('availability','private-canary'),
                   ('properties',[]),('properties',schema_observation()['properties']*17)]
        for key,value in mutations:
            x=schema_observation();x[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.check(x)
        for key in ('filename','pid','raw_schema','message'):
            x=schema_observation();x[key]='private-canary'
            with self.assertRaises(ValueError):self.check(x)
        for reason in ('identity_mismatch','metadata_bounds','metadata_flags','property_shape','property_name','property_bound','decoding_source'):
            x=schema_observation();x.update(availability='unavailable',reason=reason)
            with self.assertRaises(ValueError):self.check(x)

    def test_names_flags_indices_and_duplicate_properties_are_closed(self):
        for key,value in [('name','private/path'),('name','private-canary'),('name','1bad'),('name','x'*65),
                          ('name','x\0'),('name','x"'),('flags',1),('flags',8),('flags',64),('flags',128),
                          ('flags',18),('flags',36),('in_type',True),('out_type',65536),('count',-1)]:
            x=schema_observation();x['properties'][0][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):self.check(x)
        for flags,key in ((2,'length'),(4,'count')):
            x=schema_observation();x['properties'][0].update(flags=flags);x['properties'][0][key]=1
            with self.assertRaises(ValueError):self.check(x)
        x=schema_observation();x['properties']*=2
        with self.assertRaises(ValueError):self.check(x)

    def test_header_binding_duplicates_and_sizes(self):
        for key,value in [('opcode',64),('version',4),('header_flags',32),('keyword',2**64),('id',True)]:
            x=schema_observation();x['header'][key]=value
            with self.assertRaises(ValueError):self.check(x)
        t=OwnershipRejectionTests().trace()
        with self.assertRaises(ValueError):self.check(schema_observation(),t)
        for raw in (b'',b'{}',b'x'*8193,b'{"schema":1,"schema":1}'):
            with self.assertRaises(ValueError):V.validate_schema(raw,record())

    def test_separate_bounded_create_only_result_and_original_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            trace=Path(directory)/'stderr';stdout=Path(directory)/'stdout';schema=Path(directory)/'schema'
            x=record();x.update(status='not_reproduced',original_ok=True,os_code=None,target_identity_verified=False)
            trace.write_bytes(b'runtime_cleanup_trace='+json.dumps(x).encode()+b'\n'+
                              b'runtime_cleanup_schema='+json.dumps(schema_observation()).encode()+b'\n')
            stdout.write_bytes(harness_stdout().replace(V.EMPTY_TEST.encode(),V.LIBRARY_TEST.encode()))
            argv=['validator','--log',str(trace),'--test-exit','0','--runtime-sha256',SHA,'--application-sha256',SHA,
                  '--commit','b'*40,'--test-stdout',str(stdout),'--test-harness-sha256',SHA,'--cargo-json-sha256',SHA,
                  '--library-unit','--dynamic-providers','1','--schema-result',str(schema)]
            out=io.StringIO()
            with mock.patch('sys.argv',argv),contextlib.redirect_stdout(out):self.assertEqual(V.main(),0)
            lines=out.getvalue().splitlines();primary=json.loads(lines[0])
            self.assertNotIn('application_sha256',primary)
            self.assertEqual(primary['scope'],'original_cleanup_library_diagnostic_only')
            self.assertEqual(primary['trace'],x);self.assertLessEqual(len(schema.read_bytes()),8192)
            diagnostic=json.loads(schema.read_bytes());self.assertFalse(diagnostic['ownership_attributed'])
            self.assertEqual(lines[1],'runtime_cleanup_schema_result='+schema.read_text().strip())
            with mock.patch('sys.argv',argv),contextlib.redirect_stdout(io.StringIO()):self.assertEqual(V.main(),2)
            for content in (trace.read_bytes().split(b'runtime_cleanup_schema=')[0],trace.read_bytes()+trace.read_bytes()):
                with self.assertRaises(ValueError):V.schema_result(content,x,'b'*40,SHA,SHA,b'original')

    def test_invalid_separate_schema_preserves_valid_original_and_stays_nonzero(self):
        with tempfile.TemporaryDirectory() as directory:
            trace=Path(directory)/'stderr';stdout=Path(directory)/'stdout';schema=Path(directory)/'schema'
            x=record();x.update(status='not_reproduced',original_ok=True,os_code=None,target_identity_verified=False)
            primary=b'runtime_cleanup_trace='+json.dumps(x).encode()+b'\n'
            stdout.write_bytes(harness_stdout().replace(V.EMPTY_TEST.encode(),V.LIBRARY_TEST.encode()))
            argv=['validator','--log',str(trace),'--test-exit','0','--runtime-sha256',SHA,'--application-sha256',SHA,
                  '--commit','b'*40,'--test-stdout',str(stdout),'--test-harness-sha256',SHA,'--cargo-json-sha256',SHA,
                  '--library-unit','--dynamic-providers','1','--schema-result',str(schema)]
            for suffix in (b'',b'runtime_cleanup_schema=PRIVATE_CANARY\n',
                           b'runtime_cleanup_schema={}\nruntime_cleanup_schema={}\n'):
                trace.write_bytes(primary+suffix);out=io.StringIO()
                with self.subTest(suffix=suffix),mock.patch('sys.argv',argv),contextlib.redirect_stdout(out):
                    self.assertEqual(V.main(),2)
                lines=out.getvalue().splitlines();self.assertEqual(len(lines),2)
                self.assertEqual(json.loads(lines[0])['trace'],x)
                failure=json.loads(lines[1].removeprefix('runtime_cleanup_schema_result='))
                self.assertEqual(failure,dict(schema=1,scope='original_cleanup_schema_diagnostic_only',status='invalid',
                    reason='schema_validation_failed',ownership_attributed=False,cleanup_fixed=False,provider_accepted=False))
                self.assertNotIn('PRIVATE_CANARY',out.getvalue());self.assertFalse(schema.exists())


if __name__=="__main__":unittest.main()
