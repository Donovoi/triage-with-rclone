"""Synthetic schema mutations plus rejection of the retained older hosted proof.

The added control values are test inputs, never new native qualification.
"""
from copy import deepcopy
from contextlib import redirect_stdout
from datetime import timedelta
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import protocol_evidence as E


class ProtocolEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.recorded_native = E.parse((Path(__file__).parent/'test-data/protocol-native-success.json').read_bytes())
        cls.bindings = E.compute_bindings()
        cls.native = deepcopy(cls.recorded_native)
        synthetic = E.parse((Path(__file__).parent/'test-data/security-control-contract.json').read_bytes())
        assert synthetic['scope'] == 'synthetic_contract_values_only_not_native_evidence'
        cls.native['result']['datanode_security'] = synthetic['proof']
        cls.native['result']['checks']['block_token_controls'] = True
        cls.native['result']['cleanup']['data_security_closed'] = True
        qop = E.parse((Path(__file__).parent/'test-data/rclone-qop-contract.json').read_bytes())
        assert qop['scope'] == 'synthetic_contract_values_only_not_native_evidence'
        cls.native['result']['rclone_qop'] = qop['proof']
        cls.native['result']['checks']['rclone_qop'] = True
        cls.native['result']['cleanup']['qop_observer_closed'] = True
        for key in ('source_sha256', 'context_sha256'):
            cls.native['inputs'][key] = deepcopy(cls.bindings[key])
        cls.now = E.utc(cls.native['finished_utc']) + timedelta(seconds=1)
        cls.receipt = E.make_receipt(cls.native, cls.bindings, cls.now)
        cls.runtime = cls.receipt['runtime']

    def validate(self, value, **kwargs):
        E.validate_evidence(value, self.runtime, self.bindings, kwargs.pop('now', self.now), **kwargs)

    def reject(self, value, **kwargs):
        with self.assertRaises(ValueError):
            self.validate(value, **kwargs)

    def test_synthetic_contract_validates_and_false_claims_stay_false(self):
        self.validate(self.receipt)
        self.assertEqual(set(self.receipt['backends'][0]['capabilities']), set(E.CAPABILITIES))
        self.assertEqual(self.receipt['native_evidence'], self.native)
        self.assertEqual(self.bindings['context_sha256'], self.native['inputs']['context_sha256'])
        for obj in (self.native, self.native['result']):
            for key in ('provider_accepted','application_accepted','vendor_accepted','ledger_eligible','vulnerability_audited'):
                self.assertIs(obj[key], False)

    def test_prior_native_proof_cannot_qualify_new_control_sources(self):
        with self.assertRaises(ValueError):
            E.make_receipt(self.recorded_native, self.bindings, self.now)

    def test_control_is_required_without_promoting_rclone_qop(self):
        for field, bad in (('qop', 'auth'), ('qop_observations', 2), ('valid_before', False),
                           ('invalid_operation_token', False), ('valid_after', False),
                           ('closed', 2), ('disposed', 2), ('rclone_qop_verified', True),
                           ('wire_bytes_read', 0), ('parser_checked', False)):
            value = deepcopy(self.receipt)
            value['native_evidence']['result']['datanode_security'][field] = bad
            with self.subTest(field=field):
                self.reject(value)

    def test_every_proof_check_and_cleanup_predicate_is_required(self):
        for route in (('native_evidence','cleanup'), ('native_evidence','result','checks'),
                      ('native_evidence','result','cleanup')):
            original=self.receipt
            for key in route: original=original[key]
            for name in original:
                for bad in (False, 1, None, 'true'):
                    value=deepcopy(self.receipt); row=value
                    for key in route: row=row[key]
                    row[name]=bad
                    with self.subTest(route=route,name=name,bad=bad): self.reject(value)

    def test_source_runtime_and_context_bindings_cannot_drift(self):
        for name in self.native['inputs']['source_sha256']:
            value=deepcopy(self.receipt)
            value['native_evidence']['inputs']['source_sha256'][name]='0'*64
            with self.subTest(source=name): self.reject(value)
        for key in ('context_sha256','jdk_manifest','jdk_config_id','rclone_sha256','rclone_version',
                    'runtime_file_sha256','runtime_classpath_sha256','lock_sha256','runtime_jars','runtime_bytes'):
            for bad in (None,True,{},'0'*64):
                value=deepcopy(self.receipt);value['native_evidence']['inputs'][key]=bad
                with self.subTest(key=key,bad=bad): self.reject(value)
        for key in ('harness_sha256','fixture_manifest_sha256'):
            value=deepcopy(self.receipt);value[key]='0'*64;self.reject(value)

    def test_stale_future_duration_and_invalid_policy_are_rejected(self):
        self.reject(self.receipt, now=self.now+timedelta(hours=25))
        self.reject(self.receipt, now=self.now-timedelta(seconds=2))
        for age in (0,True,169,1.5,None): self.reject(self.receipt,max_age_hours=age)
        for bad in (True,0,-1,float('inf'),float('nan'),10**1000,1201,[],None):
            value=deepcopy(self.receipt);value['native_evidence']['duration_seconds']=bad
            with self.subTest(duration=repr(bad)[:20]): self.reject(value)
        value=deepcopy(self.receipt);value['finished_utc']=value['started_utc'];self.reject(value)

    def test_wrong_missing_category_or_unpaired_hash_cannot_pass(self):
        for key,bad in (('missing_object_category','directory_not_found'),('missing_object_category','permission_denied'),
                        ('missing_category','object_not_found'),('rc_hash_sha256','0'*64),('child_count',10),('child_count',13)):
            value=deepcopy(self.receipt);value['native_evidence']['result'][key]=bad;self.reject(value)
        for phase in self.native['result']['relay']['phase_connections']:
            for bad in (0,2,True):
                value=deepcopy(self.receipt);value['native_evidence']['result']['relay']['phase_connections'][phase]=bad
                with self.subTest(phase=phase,bad=bad): self.reject(value)

    def test_finite_oracles_and_zero_residuals_are_required(self):
        for key in ('wire_oracle','rclone_wire_oracle'):
            for field in E.ORACLE:
                value=deepcopy(self.receipt);value['native_evidence']['result'][key][field]=None;self.reject(value)
            value=deepcopy(self.receipt);value['native_evidence']['result'][key]['bounded_single_response']=1;self.reject(value)
            value=deepcopy(self.receipt);value['native_evidence']['result'][key]['rpc_version']=9.0;self.reject(value)
        for category in self.native['result']['remaining_threads']:
            value=deepcopy(self.receipt);value['native_evidence']['result']['remaining_threads'][category]=1;self.reject(value)
        for phase in self.native['result']['acquisitions']:
            value=deepcopy(self.receipt);value['native_evidence']['result']['acquisitions'][phase]['sha256']='0'*64;self.reject(value)

    def test_closed_schemas_cannot_gain_acceptance_or_other_capabilities(self):
        for route in ((), ('native_evidence',), ('native_evidence','inputs'), ('native_evidence','result'),
                      ('backends',0), ('backends',0,'capabilities')):
            value=deepcopy(self.receipt);row=value
            for key in route: row=row[key]
            row['application_accepted']=True
            with self.subTest(route=route): self.reject(value)
        for obj in ('native_evidence','result'):
            value=deepcopy(self.receipt);row=value['native_evidence']
            if obj=='result': row=row['result']
            for name in E.contract().JAVA_FALSE:
                altered=deepcopy(value);target=altered['native_evidence']
                if obj=='result': target=target['result']
                target[name]=True
                with self.subTest(obj=obj,name=name): self.reject(altered)
        for schema in (1,3,5,6,True,7.0):
            value=deepcopy(self.receipt);value['schema_version']=schema;self.reject(value)

    def test_duplicate_trailing_nonfinite_and_excessive_json_are_rejected(self):
        for raw in (b'{"x":1,"x":2}',b'{}{}',b'{"x":NaN}',b'{"x":Infinity}',b'\xff',b' '* (E.MAX_RECEIPT+1),b'{"x":'+b'9'*5000+b'}'):
            with self.subTest(raw=raw[:20]),self.assertRaises(ValueError): E.parse(raw)
        self.assertEqual(E.parse(E.canonical(self.receipt)),self.receipt)

    def test_cli_writes_only_validated_proof_and_preserves_existing_file(self):
        with tempfile.TemporaryDirectory() as temp, redirect_stdout(io.StringIO()):
            root=Path(temp); source=root/'native.json'; output=root/'protocol.json'
            source.write_bytes(E.canonical(self.native))
            args=['--native-report',str(source),'--report',str(output)]
            self.assertEqual(E.main(args,now=self.now),0)
            raw=output.read_bytes();self.validate(E.parse(raw))
            self.assertEqual(E.main(args,now=self.now),1)
            self.assertEqual(output.read_bytes(),raw)

    def test_cli_failure_or_source_drift_emits_no_receipt(self):
        with tempfile.TemporaryDirectory() as temp, redirect_stdout(io.StringIO()):
            root=Path(temp); source=root/'native.json'; output=root/'protocol.json'
            bad=deepcopy(self.native);bad['cleanup']['container_removed']=False
            source.write_bytes(E.canonical(bad))
            args=['--native-report',str(source),'--report',str(output)]
            self.assertEqual(E.main(args,now=self.now),1);self.assertFalse(output.exists())
            source.write_bytes(E.canonical(self.native))
            changed=deepcopy(self.bindings);changed['harness_sha256']='0'*64
            with patch.object(E,'compute_bindings',side_effect=[self.bindings,changed]):
                self.assertEqual(E.main(args,now=self.now),1)
            self.assertFalse(output.exists())


if __name__=='__main__':
    unittest.main()
