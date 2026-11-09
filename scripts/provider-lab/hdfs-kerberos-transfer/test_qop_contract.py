"""Pure adversarial receipt contracts, never native QOP evidence."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location('qop_contract_subject', HERE/'transfer_container.py')
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)


class QopContractTests(unittest.TestCase):
    def setUp(self):
        fixture = json.loads((HERE/'test-data/rclone-qop-contract.json').read_text())
        self.assertEqual(fixture['scope'], 'synthetic_contract_values_only_not_native_evidence')
        self.proof = fixture['proof']

    def reject(self, value, checked=True, cleaned=True):
        with self.assertRaises(F.ProbeError): F.validate_rclone_qop(value, checked, cleaned)

    def test_closed_complete_contract(self):
        F.validate_rclone_qop(self.proof, True, True)
        for key in self.proof:
            value = deepcopy(self.proof); del value[key]; self.reject(value)
        value = deepcopy(self.proof); value['raw_message'] = 'not allowed'; self.reject(value)

    def test_strict_scalar_types(self):
        for key, old in self.proof.items():
            for bad in [None, {}, 1 if type(old) is bool else True]:
                with self.subTest(key=key, bad=bad):
                    value = deepcopy(self.proof); value[key] = bad; self.reject(value)
        self.reject(self.proof, 1, True)
        self.reject(self.proof, True, 1)

    def test_requested_or_downgraded_qop_cannot_pass(self):
        for bad in ('privacy', 'requested: auth-conf', 'auth', 'auth-int', 'not_observed', ''):
            value = deepcopy(self.proof); value['qop'] = bad; self.reject(value)

    def test_missing_foreign_duplicate_or_future_phase_observation_rejected(self):
        for i in range(10):
            for delta in (-1, 1):
                value = deepcopy(self.proof); value['phase_connections'][i] += delta
                value['connections'] += delta
                with self.subTest(i=i, delta=delta): self.reject(value)
        for wrong in ([], [0]*9, [0]*11, [False]*10, [0.0]*10):
            value = deepcopy(self.proof); value['phase_connections'] = wrong; self.reject(value)
        value = deepcopy(self.proof); value.update(verified=False, phases_completed=2)
        self.reject(value, False, True)

    def test_false_success_and_missing_cleanup_rejected(self):
        for key in ('attempted', 'parser_checked', 'verified', 'logger_restored', 'quiescent'):
            value = deepcopy(self.proof); value[key] = False; self.reject(value)
        for key in ('failed', 'attached'):
            value = deepcopy(self.proof); value[key] = True; self.reject(value)
        for key, wrong in [('phases_completed', 9), ('phases_completed', 11), ('connections', 5), ('connections', 7)]:
            value = deepcopy(self.proof); value[key] = wrong; self.reject(value)
        self.reject(self.proof, True, False)

    def test_unattempted_and_partial_failure_are_honest(self):
        value = deepcopy(self.proof)
        value.update(attempted=False, parser_checked=False, verified=False, phases_completed=0,
                     connections=0, qop='not_observed', phase_connections=[0]*10)
        F.validate_rclone_qop(value, False, True)
        self.reject(value)
        value.update(attempted=True, parser_checked=True, failed=True, phases_completed=2,
                     connections=1, qop='auth-conf', phase_connections=[0,0,1,0,0,0,0,0,0,0])
        F.validate_rclone_qop(value, False, True)
        self.reject(value)
        value.update(quiescent=False)
        F.validate_rclone_qop(value, False, False)
        self.reject(value, False, True)
        value.update(quiescent=True, attached=True, logger_restored=False)
        F.validate_rclone_qop(value, False, False)
        value.update(logger_restored=True)
        self.reject(value, False, False)

    def test_source_pin_matches_helper_and_probe_stays_bounded(self):
        self.assertEqual(F.sha((HERE/'HdfsRcloneQop.java').read_bytes()), F.QOP_SHA)
        self.assertEqual(F.sha((HERE/'HdfsKerberosTransferProbe.java').read_bytes()), F.JAVA_SHA)
        self.assertLessEqual((HERE/'HdfsKerberosTransferProbe.java').stat().st_size, 128*1024)


if __name__ == '__main__': unittest.main()
