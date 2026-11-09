"""Adversarial pure control contracts; no network, JVM, or synthetic admission."""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import unittest

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location('security_contract_under_test', HERE/'transfer_container.py')
F = importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)


class SecurityContractTests(unittest.TestCase):
    def setUp(self):
        fixture = json.loads((HERE/'test-data/security-control-contract.json').read_text())
        self.assertEqual(fixture['scope'], 'synthetic_contract_values_only_not_native_evidence')
        self.proof = fixture['proof']

    def test_complete_contract(self):
        F.validate_data_security(self.proof, True, True)

    def test_boolean_and_counter_types_are_strict(self):
        for key, old in self.proof.items():
            bad_values = [None, [], {}, 1 if type(old) is bool else True]
            for bad in bad_values:
                value = deepcopy(self.proof); value[key] = bad
                with self.subTest(key=key, bad=bad), self.assertRaises(F.ProbeError):
                    F.validate_data_security(value, True, True)

    def test_missing_or_extra_field_is_rejected(self):
        for key in self.proof:
            value = deepcopy(self.proof); del value[key]
            with self.subTest(key=key), self.assertRaises(F.ProbeError):
                F.validate_data_security(value, True, True)
        value = deepcopy(self.proof); value['accepted'] = True
        with self.assertRaises(F.ProbeError): F.validate_data_security(value, True, True)

    def test_partial_or_broadened_proof_never_passes(self):
        mutations = [('closed', 2), ('disposed', 2), ('qop_observations', 2), ('connections', 4),
                     ('participants', 0), ('protected_frames', 49), ('wire_bytes_read', 98305),
                     ('wire_bytes_written', -1), ('wire_bytes_read', 0), ('qop', 'auth-int'),
                     ('qop', 'not_observed'), ('rclone_qop_verified', True), ('parser_checked', False)]
        mutations += [(key, False) for key in ('attempted', 'valid_before', 'invalid_operation_token', 'valid_after')]
        for key, bad in mutations:
            value = deepcopy(self.proof); value[key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(F.ProbeError):
                F.validate_data_security(value, True, True)

    def test_unattempted_cleanup_is_honest_but_not_success(self):
        value = {key: (False if type(old) is bool else 0 if type(old) is int else 'not_observed')
                 for key, old in self.proof.items()}
        value['quiescent'] = True
        F.validate_data_security(value, False, True)
        with self.assertRaises(F.ProbeError): F.validate_data_security(value, True, True)
        with self.assertRaises(F.ProbeError): F.validate_data_security(value, False, False)

    def test_partial_failure_cannot_launder_cleanup_or_phase_order(self):
        value = deepcopy(self.proof)
        value.update(connections=2, closed=1, participants=2, disposed=1, qop_observations=2,
                     protected_frames=2, valid_after=False)
        F.validate_data_security(value, False, False)
        with self.assertRaises(F.ProbeError): F.validate_data_security(value, False, True)
        value.update(valid_before=False, valid_after=True)
        with self.assertRaises(F.ProbeError): F.validate_data_security(value, False, False)

    def test_equal_resource_counts_do_not_hide_active_control(self):
        value = deepcopy(self.proof); value['quiescent'] = False
        F.validate_data_security(value, False, False)
        with self.assertRaises(F.ProbeError): F.validate_data_security(value, False, True)
        with self.assertRaises(F.ProbeError): F.validate_data_security(value, True, False)

    def test_known_byte_checksum_is_independently_reconstructed(self):
        chunks = []
        for start in range(0, 4096, 512):
            crc = 0xffffffff
            for index in range(start, start + 512):
                crc ^= index % 256
                for _ in range(8): crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
            chunks.append(struct.pack('>I', crc ^ 0xffffffff))
        digest = hashlib.md5(b''.join(chunks)).hexdigest()
        self.assertEqual(digest, '1a89363878a82c5c7beffed1d407834a')
        source = (HERE/'HdfsDataNodeSecurity.java').read_text()
        self.assertIn('private static final String CHECKSUM = "' + digest + '";', source)


if __name__ == '__main__': unittest.main()
