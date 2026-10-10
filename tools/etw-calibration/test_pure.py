"""No helper execution, subprocess, sockets, or Windows API calls."""
import json
import socket
import subprocess
import unittest
from unittest.mock import patch
from validate_result import BOOLS, validate


def forbidden(*args, **kwargs):
    raise AssertionError("native/network execution forbidden in pure validation")


def fixture():
    return dict(schema=2, scope="synthetic_open_only", status="observed", reason="none",
                api="CreateFileW_DELETE_OPEN_EXISTING", holder_access="READ_DATA|DELETE_without_delete_share", **dict.fromkeys(BOOLS, True))


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
        value = fixture(); value.update(dict.fromkeys(BOOLS, False)); value.update(status="unavailable", reason="unsupported_environment")
        self.assertEqual(validate(raw(value), 2), value)

    def test_cleanup_requires_both_original_identities(self):
        for field in ("same_owned_file", "same_owned_directory"):
            value = fixture(); value.update(status="unavailable", reason="cleanup_uncertain")
            value[field] = False
            with self.assertRaises(ValueError): validate(raw(value), 2)
            value["owned_file_cleaned"] = False
            self.assertEqual(validate(raw(value), 2), value)

    def test_holder_contract_and_old_schema_rejected(self):
        for field, wrong in (("holder_access", "READ_DATA"), ("schema", 1)):
            value = fixture(); value[field] = wrong
            with self.assertRaises(ValueError): validate(raw(value), 0)


if __name__ == "__main__":
    with patch.object(subprocess, "Popen", forbidden), patch.object(socket, "socket", forbidden), patch.object(socket, "create_connection", forbidden):
        unittest.main()
