"""HDFS protocol coverage stays separate from application/lifecycle acceptance."""
from copy import deepcopy
from datetime import timedelta
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('hdfs_coverage_subject',ROOT/'scripts/provider_coverage.py')
C=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


class HdfsCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper=C.hdfs_evidence_module()
        cls.bindings=C.compute_hdfs_bindings(ROOT/'scripts/provider-lab/hdfs-kerberos-transfer')
        cls.native=cls.helper.parse((ROOT/'scripts/provider-lab/hdfs-kerberos-transfer/test-data/protocol-native-success.json').read_bytes())
        # The recorded prior receipt is unchanged. Added values are explicit
        # synthetic contract inputs and grant no native qualification.
        synthetic=cls.helper.parse((ROOT/'scripts/provider-lab/hdfs-kerberos-transfer/test-data/security-control-contract.json').read_bytes())
        assert synthetic['scope']=='synthetic_contract_values_only_not_native_evidence'
        cls.native['result']['datanode_security']=synthetic['proof']
        cls.native['result']['checks']['block_token_controls']=True
        cls.native['result']['cleanup']['data_security_closed']=True
        qop=cls.helper.parse((ROOT/'scripts/provider-lab/hdfs-kerberos-transfer/test-data/rclone-qop-contract.json').read_bytes())
        assert qop['scope']=='synthetic_contract_values_only_not_native_evidence'
        cls.native['result']['rclone_qop']=qop['proof']
        cls.native['result']['checks']['rclone_qop']=True
        cls.native['result']['cleanup']['qop_observer_closed']=True
        for key in ('source_sha256','context_sha256'):
            cls.native['inputs'][key]=deepcopy(cls.bindings[key])
        cls.now=cls.helper.utc(cls.native['finished_utc'])+timedelta(seconds=1)
        cls.receipt=cls.helper.make_receipt(cls.native,cls.bindings,cls.now)
        cls.runtime=dict(cls.receipt['runtime'],platform='linux')
        original=json.loads((ROOT/'provider-coverage-policy.json').read_text())
        entry=deepcopy(original['providers']['hdfs'])
        cls.catalog=C.catalog_from_schemas([{'Name':'hdfs','Prefix':'hdfs','Options':[]}])
        entry.pop('schema_sha256_by_platform',None)
        entry['schema_sha256']=cls.catalog[0]['schema_sha256']
        cls.policy={'schema_version':2,'reviewed_runtime_version':cls.runtime['version'],
                    'providers':{'hdfs':entry},'profiles':{entry['profile']:deepcopy(original['profiles'][entry['profile']])}}

    def evaluate(self,receipts,**kwargs):
        args=dict(now=self.now,fixture_manifest_sha256='a'*64,hdfs_bindings=self.bindings)
        args.update(kwargs)
        return C.evaluate(self.catalog,self.policy,self.runtime,receipts,'b'*64,**args)

    def test_scoped_success_satisfies_six_protocol_obligations_only(self):
        self.assertTrue(self.receipt['started_utc'].endswith('Z'))
        self.assertTrue(self.receipt['finished_utc'].endswith('Z'))
        self.assertEqual(self.receipt['native_evidence'],self.native)
        report=self.evaluate([self.receipt]);self.assertEqual(report['errors'],[])
        row=report['providers'][0];evidence=row['evidence']
        self.assertEqual(evidence['local_protocol']['status'],'passed')
        self.assertEqual(evidence['application']['status'],'not_verified')
        self.assertNotEqual(evidence['vendor']['status'],'passed')
        self.assertFalse(report['all_complete'])
        self.assertEqual(C.gate_errors(report,require_plans=True,require_fixtures=['hdfs']),[])
        self.assertTrue(C.gate_errors(report,require_complete=True))
        self.assertTrue(C.gate_errors(report,require_application=['hdfs']))
        mode=evidence['local_protocol']['modes']['hdfs_kerberos_transfer_read_v1']
        self.assertEqual(mode['capabilities'],dict.fromkeys(self.helper.CAPABILITIES,'passed'))
        run=mode['runs'][0]
        self.assertEqual(run['source_sha256'],self.native['inputs']['source_sha256'])
        self.assertEqual(run['context_sha256'],self.bindings['context_sha256'])
        self.assertEqual(run['fixture_manifest_sha256'],self.bindings['fixture_manifest_sha256'])
        self.assertNotEqual(run['fixture_manifest_sha256'],'a'*64)
        self.assertEqual(row['lifecycle_applicability'],{
            'credential_renewal':'required','connection_session_reauthentication':'required'})
        for capability in ('refresh','reauthentication','revocation','cancellation'):
            self.assertEqual(evidence['application']['capabilities'][capability],'not_verified')

    def test_missing_bindings_and_raw_feasibility_cannot_be_imported(self):
        for receipts,options in (([self.receipt],{'hdfs_bindings':None}),([self.native],{}),([self.native['result']],{}),([],{})):
            report=self.evaluate(receipts,**options)
            self.assertEqual(report['providers'][0]['evidence']['local_protocol']['status'],'not_verified')
            self.assertTrue(C.gate_errors(report,require_fixtures=['hdfs']))
        with self.assertRaisesRegex(C.CoverageError,'unknown_receipt_schema'):
            C.validate_receipt(self.receipt,self.runtime,'b'*64,self.now,fixture_manifest_sha256='a'*64)

    def test_malformed_or_stale_input_blocks_gate_even_beside_success(self):
        for mutate in (lambda r:r.update(schema_version=3),lambda r:r['backends'][0].update(backend='smb'),
                       lambda r:r.update(fixture_manifest_sha256='a'*64),
                       lambda r:r['native_evidence']['cleanup'].update(container_removed=False),
                       lambda r:r['backends'][0]['capabilities'].update(renewal='passed')):
            bad=deepcopy(self.receipt);mutate(bad)
            report=self.evaluate([self.receipt,bad])
            self.assertTrue(report['errors']);self.assertTrue(C.gate_errors(report,require_fixtures=['hdfs']))
        report=self.evaluate([self.receipt],now=self.now+timedelta(hours=25))
        self.assertTrue(report['errors']);self.assertTrue(C.gate_errors(report,require_fixtures=['hdfs']))

    def test_wrong_platform_runtime_and_source_are_rejected(self):
        for key,bad_value in (('sha256','0'*64),('version','0.0.0'),('platform','windows')):
            runtime=dict(self.runtime,**{key:bad_value})
            with self.assertRaises(C.CoverageError):
                C.validate_receipt(self.receipt,runtime,'b'*64,self.now,hdfs_bindings=self.bindings)
        bad=deepcopy(self.receipt)
        bad['native_evidence']['inputs']['source_sha256']['HdfsTransferJson.java']='0'*64
        report=self.evaluate([bad]);self.assertTrue(C.gate_errors(report,require_fixtures=['hdfs']))


if __name__=='__main__':
    unittest.main()
