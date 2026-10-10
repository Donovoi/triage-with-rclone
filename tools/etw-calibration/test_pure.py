"""No helper execution, subprocess, sockets, or Windows API calls."""
import json
import socket
import subprocess
import unittest
from unittest.mock import patch
from validate_result import BOOLS, REQUESTED_SESSION_SETTINGS, validate


def forbidden(*args, **kwargs):
    raise AssertionError("native/network execution forbidden in pure validation")


def fixture():
    return dict(schema=3, scope="synthetic_open_only", status="observed", reason="none",
                api="CreateFileW_DELETE_OPEN_EXISTING", holder_access="READ_DATA|DELETE_without_delete_share",
                queried_session_settings=dict(REQUESTED_SESSION_SETTINGS), **dict.fromkeys(BOOLS, True))


def mismatch_fixture():
    value = fixture()
    value.update(status="unavailable", reason="session_configuration_mismatch",
                 consumer_completed=False, create_opend_pair=False, win32_sharing_violation=False)
    value["queried_session_settings"]["clock_selector"] = 0
    return value


def raw(obj):
    return json.dumps(obj).encode("utf-8")


class BoundaryTests(unittest.TestCase):
    def test_exact_success(self):
        self.assertEqual(validate(raw(fixture()), 0), fixture())

    def test_each_missing_proof(self):
        for key in BOOLS:
            with self.subTest(key=key):
                value = fixture(); value[key] = False
                with self.assertRaises(ValueError): validate(raw(value), 0)

    def test_no_raw_identity_or_extra_fields(self):
        for key in ("path", "pid", "irp", "stderr", "provider_complete"):
            value = fixture(); value[key] = "private"
            with self.assertRaises(ValueError): validate(raw(value), 0)

    def test_types_and_exit_status(self):
        for key in BOOLS | {"schema"}:
            value = fixture(); value[key] = 1 if key in BOOLS else True
            with self.assertRaises(ValueError): validate(raw(value), 0)
        with self.assertRaises(ValueError): validate(raw(fixture()), 2)
        with self.assertRaises(ValueError): validate(raw(fixture()), False)

    def test_duplicate_and_budget(self):
        data = raw(fixture())
        with self.assertRaises(ValueError): validate(b'{"schema":1,' + data[1:], 0)
        with self.assertRaises(ValueError): validate(data + b" " * 2049, 0)
        with self.assertRaises(ValueError): validate(data + b"\n{}", 0)

    def test_unavailable_loss_and_teardown(self):
        value = fixture(); value.update(status="unavailable", reason="event_loss", zero_loss=False, create_opend_pair=False)
        self.assertEqual(validate(raw(value), 2), value)
        value.update(session_stop_verified=False)
        with self.assertRaises(ValueError): validate(raw(value), 2)
        value.update(reason="cleanup_uncertain")
        self.assertEqual(validate(raw(value), 2), value)

    def test_preflight_unavailable(self):
        value = fixture(); value.update(dict.fromkeys(BOOLS, False)); value.update(status="unavailable", reason="unsupported_environment", queried_session_settings=None)
        self.assertEqual(validate(raw(value), 2), value)

    def test_cleanup_requires_both_original_identities(self):
        for field in ("same_owned_file", "same_owned_directory"):
            value = fixture(); value.update(status="unavailable", reason="cleanup_uncertain")
            value[field] = False
            with self.assertRaises(ValueError): validate(raw(value), 2)
            value["owned_file_cleaned"] = False
            self.assertEqual(validate(raw(value), 2), value)

    def test_holder_contract_and_old_schema_rejected(self):
        for field, wrong in (("holder_access", "READ_DATA"), ("schema", 1), ("schema", 2)):
            value = fixture(); value[field] = wrong
            with self.assertRaises(ValueError): validate(raw(value), 0)

    def test_each_setting_mismatch_and_u32_endpoints(self):
        for field in REQUESTED_SESSION_SETTINGS:
            for number in (0, 0xFFFFFFFF):
                with self.subTest(field=field, number=number):
                    value = mismatch_fixture()
                    value["queried_session_settings"] = dict(REQUESTED_SESSION_SETTINGS)
                    value["queried_session_settings"][field] = number
                    self.assertEqual(validate(raw(value), 2), value)
                    value.update(status="observed", reason="none", **dict.fromkeys(BOOLS, True))
                    with self.assertRaises(ValueError): validate(raw(value), 0)

    def test_session_settings_shape_and_missing_field(self):
        for malformed in (False, 0, "settings", [], {}, {**REQUESTED_SESSION_SETTINGS, "path": "PRIVATE"}):
            value = mismatch_fixture(); value["queried_session_settings"] = malformed
            with self.assertRaises(ValueError): validate(raw(value), 2)
        for field in REQUESTED_SESSION_SETTINGS:
            value = mismatch_fixture(); del value["queried_session_settings"][field]
            with self.assertRaises(ValueError): validate(raw(value), 2)
        value = fixture(); del value["queried_session_settings"]
        with self.assertRaises(ValueError): validate(raw(value), 0)

    def test_session_settings_strict_u32_types(self):
        for field in REQUESTED_SESSION_SETTINGS:
            for malformed in (True, False, -1, 0x100000000, 1.0, "1", None, [], {}):
                with self.subTest(field=field, malformed=malformed):
                    value = mismatch_fixture(); value["queried_session_settings"][field] = malformed
                    with self.assertRaises(ValueError): validate(raw(value), 2)

    def test_null_settings_mean_no_successful_query(self):
        value = mismatch_fixture()
        value.update(reason="session_unavailable", queried_session_settings=None, effective_buffers_within_budget=False)
        self.assertEqual(validate(raw(value), 2), value)
        value.update(reason="session_configuration_mismatch")
        with self.assertRaises(ValueError): validate(raw(value), 2)
        value = fixture(); value["queried_session_settings"] = None
        with self.assertRaises(ValueError): validate(raw(value), 0)
        value = mismatch_fixture(); value.update(session_started=False, session_stop_verified=False)
        with self.assertRaises(ValueError): validate(raw(value), 2)

    def test_mismatch_does_not_claim_consumer_or_probe(self):
        for field in ("consumer_completed", "create_opend_pair", "win32_sharing_violation"):
            value = mismatch_fixture(); value[field] = True
            with self.assertRaises(ValueError): validate(raw(value), 2)
        value = mismatch_fixture(); value["queried_session_settings"] = dict(REQUESTED_SESSION_SETTINGS)
        with self.assertRaises(ValueError): validate(raw(value), 2)
        value = mismatch_fixture(); value["reason"] = "session_unavailable"
        with self.assertRaises(ValueError): validate(raw(value), 2)
        value = mismatch_fixture(); value.update(reason="cleanup_uncertain", session_stop_verified=False)
        self.assertEqual(validate(raw(value), 2), value)

    def test_nested_duplicate_session_field_rejected(self):
        data = raw(mismatch_fixture()).replace(b'"clock_selector": 0', b'"clock_selector": 0, "clock_selector": 0')
        with self.assertRaises(ValueError): validate(data, 2)


if __name__ == "__main__":
    with patch.object(subprocess, "Popen", forbidden), patch.object(socket, "socket", forbidden), patch.object(socket, "create_connection", forbidden):
        unittest.main()
