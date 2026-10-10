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
    return dict(schema=4, scope="synthetic_open_only", status="observed", reason="none",
                api="CreateFileW_DELETE_OPEN_EXISTING", holder_access="READ_DATA|DELETE_without_delete_share",
                queried_session_settings=dict(REQUESTED_SESSION_SETTINGS), schema_rejection=None, **dict.fromkeys(BOOLS, True))


def rejection_fixture(**fields):
    value = fixture()
    value.update(status="unavailable", reason="schema_unavailable", create_opend_pair=False)
    value["schema_rejection"] = dict(
        attribution="unattributed_fileio", stage="version", property=None,
        opcode=64, version=3, header_flags=0x40, tdh_status=None, size=None,
    )
    value["schema_rejection"].update(fields)
    return value


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
        for field, wrong in (("holder_access", "READ_DATA"), ("schema", 1), ("schema", 2), ("schema", 3)):
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

    def test_shutdown_mode_is_explicit_and_other_modes_cannot_pass(self):
        for mode in (0x12000100, 0x12800100, 0x12C00100, 0x12400101):
            value = fixture(); value["queried_session_settings"]["log_mode"] = mode
            with self.assertRaises(ValueError): validate(raw(value), 0)
            value.update(status="unavailable", reason="session_configuration_mismatch",
                         consumer_completed=False, create_opend_pair=False, win32_sharing_violation=False)
            self.assertEqual(validate(raw(value), 2), value)

    def test_each_schema_rejection_stage_and_valid_endpoints(self):
        examples = [
            dict(version=0, header_flags=0), dict(version=255, header_flags=65535, opcode=76),
            dict(stage="header_flags", version=2, header_flags=0),
            dict(stage="header_flags", version=2, header_flags=0x60),
        ]
        for opcode, prop in ((64, "TTID"), (64, "IrpPtr"), (64, "ShareAccess"),
                             (64, "OpenPath"), (76, "IrpPtr"), (76, "NtStatus")):
            base = dict(opcode=opcode, property=prop, version=2)
            capacity = 2048 if prop == "OpenPath" else 8
            examples.extend([
                dict(base, stage="tdh_size", tdh_status=1),
                dict(base, stage="tdh_size", tdh_status=0xFFFFFFFF),
                dict(base, stage="property_bound", tdh_status=0, size=0),
                dict(base, stage="property_bound", tdh_status=0, size=0xFFFFFFFF),
                dict(base, stage="tdh_read", tdh_status=1, size=1),
                dict(base, stage="tdh_read", tdh_status=0xFFFFFFFF, size=capacity),
                dict(base, stage="path_encoding" if prop == "OpenPath" else "numeric_width", tdh_status=0, size=1),
            ])
        examples.extend(dict(stage="correlation_shape", version=2, property=prop) for prop in ("IrpPtr", "ShareAccess"))
        for fields in examples:
            with self.subTest(fields=fields):
                value = rejection_fixture(**fields)
                self.assertEqual(validate(raw(value), 2), value)
                self.assertLessEqual(len(raw(value)), 2048)

    def test_rejection_exact_shape_and_duplicate_fields(self):
        for malformed in (False, 0, "schema", [], {}):
            value = rejection_fixture(); value["schema_rejection"] = malformed
            with self.assertRaises(ValueError): validate(raw(value), 2)
        for field in rejection_fixture()["schema_rejection"]:
            value = rejection_fixture(); del value["schema_rejection"][field]
            with self.assertRaises(ValueError): validate(raw(value), 2)
            data = raw(rejection_fixture())
            encoded = json.dumps(field).encode() + b":"
            data = data.replace(encoded, encoded + b"null," + encoded)
            with self.assertRaises(ValueError): validate(data, 2)
        for field in ("path", "pid", "irp", "payload", "unknown_property"):
            value = rejection_fixture(); value["schema_rejection"][field] = "private"
            with self.assertRaises(ValueError): validate(raw(value), 2)
        value = fixture(); del value["schema_rejection"]
        with self.assertRaises(ValueError): validate(raw(value), 0)
        data = raw(fixture()).replace(b'"schema_rejection": null', b'"schema_rejection": null, "schema_rejection": null')
        with self.assertRaises(ValueError): validate(data, 0)

    def test_rejection_integer_bounds_and_types(self):
        for field, maximum in (("opcode", 255), ("version", 255), ("header_flags", 65535),
                               ("tdh_status", 0xFFFFFFFF), ("size", 0xFFFFFFFF)):
            for malformed in (True, False, -1, maximum + 1, 1.0, "1", [], {}):
                with self.subTest(field=field, malformed=malformed):
                    value = rejection_fixture(); value["schema_rejection"][field] = malformed
                    with self.assertRaises(ValueError): validate(raw(value), 2)
        for field in ("opcode", "version", "header_flags"):
            value = rejection_fixture(); value["schema_rejection"][field] = None
            with self.assertRaises(ValueError): validate(raw(value), 2)

    def test_rejection_stage_selector_and_gate_relationships(self):
        malformed = [
            dict(attribution="owned_file"), dict(attribution=None), dict(stage="unknown"), dict(stage=[]),
            dict(opcode=0), dict(opcode=65), dict(version=2), dict(property="TTID"), dict(tdh_status=0), dict(size=0),
            dict(stage="header_flags", version=3, header_flags=0),
            dict(stage="header_flags", version=2, header_flags=0x40),
            dict(stage="tdh_size", version=2, property="unknown", tdh_status=1),
            dict(stage="tdh_size", version=2, property=[], tdh_status=1),
            dict(stage="tdh_size", version=2, property="TTID", opcode=76, tdh_status=1),
            dict(stage="tdh_size", version=2, property="NtStatus", tdh_status=1),
            dict(stage="tdh_size", version=2, property="TTID", header_flags=0, tdh_status=1),
            dict(stage="tdh_size", version=2, property="TTID", tdh_status=0),
            dict(stage="tdh_size", version=2, property="TTID", tdh_status=1, size=4),
            dict(stage="property_bound", version=2, property="TTID", tdh_status=1, size=0),
            dict(stage="property_bound", version=2, property="OpenPath", tdh_status=0, size=2048),
            dict(stage="tdh_read", version=2, property="TTID", tdh_status=0, size=4),
            dict(stage="tdh_read", version=2, property="TTID", tdh_status=1, size=0),
            dict(stage="tdh_read", version=2, property="TTID", tdh_status=1, size=9),
            dict(stage="numeric_width", version=2, property="TTID", tdh_status=0, size=8),
            dict(stage="numeric_width", version=2, property="ShareAccess", tdh_status=0, size=4),
            dict(stage="numeric_width", version=2, property="OpenPath", tdh_status=0, size=4),
            dict(stage="path_encoding", version=2, property="IrpPtr", tdh_status=0, size=4),
            dict(stage="path_encoding", version=2, property="OpenPath", tdh_status=1, size=4),
            dict(stage="correlation_shape", version=2, property="TTID"),
            dict(stage="correlation_shape", version=2, property="IrpPtr", opcode=76),
            dict(stage="correlation_shape", version=2, property="IrpPtr", tdh_status=0),
        ]
        for fields in malformed:
            with self.subTest(fields=fields):
                with self.assertRaises(ValueError): validate(raw(rejection_fixture(**fields)), 2)
        for stage in ("tdh_size", "property_bound", "tdh_read", "numeric_width", "path_encoding"):
            value = rejection_fixture(stage=stage, version=2, property="OpenPath")
            with self.assertRaises(ValueError): validate(raw(value), 2)

    def test_rejection_cannot_claim_success_or_pair(self):
        value = rejection_fixture(); value.update(status="observed", reason="none", create_opend_pair=True)
        with self.assertRaises(ValueError): validate(raw(value), 0)
        value = rejection_fixture(); value["create_opend_pair"] = True
        with self.assertRaises(ValueError): validate(raw(value), 2)
        value = rejection_fixture(); value["schema_rejection"] = None
        with self.assertRaises(ValueError): validate(raw(value), 2)
        value = rejection_fixture(); value["queried_session_settings"]["clock_selector"] = 0
        with self.assertRaises(ValueError): validate(raw(value), 2)
        for field in ("win32_sharing_violation", "consumer_completed", "session_stop_verified", "zero_loss", "effective_buffers_within_budget"):
            value = rejection_fixture(); value[field] = False
            with self.assertRaises(ValueError): validate(raw(value), 2)
        for reason in ("session_configuration_mismatch", "session_unavailable", "correlation_missing_or_ambiguous"):
            value = rejection_fixture(); value["reason"] = reason
            with self.assertRaises(ValueError): validate(raw(value), 2)

    def test_latched_rejection_survives_existing_outcome_precedence(self):
        for reason in ("event_loss", "budget_exceeded", "cleanup_uncertain", "clock_unavailable", "consumer_unavailable", "unexpected_status"):
            value = rejection_fixture()
            value.update(reason=reason, win32_sharing_violation=False)
            if reason == "cleanup_uncertain":
                value.update(session_stop_verified=False, consumer_completed=False, owned_file_cleaned=False)
            elif reason == "event_loss":
                value["zero_loss"] = False
            elif reason == "budget_exceeded":
                value["effective_buffers_within_budget"] = False
            self.assertEqual(validate(raw(value), 2), value)
        value = rejection_fixture(stage="correlation_shape", version=2, property="IrpPtr")
        value.update(reason="cleanup_uncertain", owned_file_cleaned=False)
        self.assertEqual(validate(raw(value), 2), value)
        for reason in ("event_loss", "budget_exceeded", "clock_unavailable", "consumer_unavailable", "unexpected_status"):
            value["reason"] = reason
            with self.assertRaises(ValueError): validate(raw(value), 2)
        value["reason"] = "cleanup_uncertain"
        value["consumer_completed"] = False
        with self.assertRaises(ValueError): validate(raw(value), 2)


if __name__ == "__main__":
    with patch.object(subprocess, "Popen", forbidden), patch.object(socket, "socket", forbidden), patch.object(socket, "create_connection", forbidden):
        unittest.main()
