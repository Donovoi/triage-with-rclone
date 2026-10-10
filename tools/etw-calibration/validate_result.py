"""Pure, strict release boundary for the sole sanitized calibration record."""
import json
import sys
from pathlib import Path

REASONS = frozenset((
    "none", "unsupported_environment", "owned_file_unavailable", "identity_unavailable",
    "budget_exceeded", "schema_unavailable", "clock_unavailable",
    "correlation_missing_or_ambiguous", "unexpected_status", "event_loss",
    "session_collision", "access_denied", "session_unavailable", "consumer_unavailable",
    "cleanup_uncertain", "session_configuration_mismatch",
))
BOOLS = frozenset((
    "win32_sharing_violation", "create_opend_pair", "same_owned_file", "same_owned_directory", "session_started",
    "session_stop_verified", "consumer_completed", "zero_loss",
    "effective_buffers_within_budget", "owned_file_cleaned",
))
KEYS = BOOLS | {"schema", "scope", "status", "reason", "api", "holder_access", "queried_session_settings", "schema_rejection"}
REQUESTED_SESSION_SETTINGS = {
    "enable_flags": 0x16000000,  # FILE_IO_INIT | FILE_IO | NO_SYSCONFIG
    "log_mode": 0x12400100,  # REAL_TIME | SYSTEM_LOGGER | NO_PER_PROCESSOR_BUFFERING | STOP_ON_HYBRID_SHUTDOWN
    "clock_selector": 1,  # QPC
}
REJECTION_KEYS = frozenset((
    "attribution", "stage", "property", "opcode", "version", "header_flags", "tdh_status", "size",
))
STAGES = frozenset((
    "version", "header_flags", "tdh_size", "property_bound", "tdh_read", "numeric_width",
    "path_encoding", "correlation_shape",
))
PROPERTIES = {64: frozenset(("TTID", "IrpPtr", "OpenPath", "ShareAccess")),
              76: frozenset(("IrpPtr", "NtStatus"))}


def uint(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def validate_rejection(value):
    if type(value) is not dict or value.keys() != REJECTION_KEYS:
        raise ValueError("schema rejection shape")
    stage, prop, status, size = (value[key] for key in ("stage", "property", "tdh_status", "size"))
    if value["attribution"] != "unattributed_fileio" or type(stage) is not str or stage not in STAGES:
        raise ValueError("schema rejection enum")
    if not uint(value["opcode"], 0xFF) or value["opcode"] not in PROPERTIES:
        raise ValueError("schema opcode")
    if not uint(value["version"], 0xFF) or not uint(value["header_flags"], 0xFFFF):
        raise ValueError("schema header bounds")
    if any(item is not None and not uint(item, 0xFFFFFFFF) for item in (status, size)):
        raise ValueError("schema TDH bounds")
    header_ok = value["header_flags"] & 0x40 != 0 and value["header_flags"] & 0x20 == 0
    if stage in ("version", "header_flags"):
        if any(item is not None for item in (prop, status, size)):
            raise ValueError("header rejection has no property query")
        if (stage == "version" and value["version"] in (2, 3)) or (
            stage == "header_flags" and (value["version"] not in (2, 3) or header_ok)
        ):
            raise ValueError("header rejection gate")
        return
    if value["version"] not in (2, 3) or not header_ok or type(prop) is not str or prop not in PROPERTIES[value["opcode"]]:
        raise ValueError("property before header gate or unknown selector")
    if stage == "correlation_shape":
        if value["opcode"] != 64 or prop not in ("IrpPtr", "ShareAccess") or status is not None or size is not None:
            raise ValueError("correlation rejection shape")
        return
    if stage == "tdh_size":
        if status is None or status == 0 or size is not None:
            raise ValueError("failed size query cannot report a size")
        return
    capacity = 2048 if prop == "OpenPath" else 8
    if size is None or status is None:
        raise ValueError("successful size query required")
    if stage == "property_bound":
        if status != 0 or 0 < size <= capacity:
            raise ValueError("property buffer gate")
        return
    if not 0 < size <= capacity:
        raise ValueError("property read size")
    if stage == "tdh_read":
        if status == 0:
            raise ValueError("failed read status required")
        return
    if status != 0:
        raise ValueError("successful property read required")
    if stage == "numeric_width":
        expected = 8 if prop == "IrpPtr" or (prop == "TTID" and value["version"] == 2) else 4
        if prop == "OpenPath" or size == expected:
            raise ValueError("numeric width gate")
    elif stage == "path_encoding" and prop != "OpenPath":
        raise ValueError("path encoding selector")


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def validate(raw, exit_code):
    if type(raw) is not bytes or not 0 < len(raw) <= 2048:
        raise ValueError("bounded input required")
    obj = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs)
    if type(obj) is not dict or obj.keys() != KEYS:
        raise ValueError("exact keys required")
    if type(obj["schema"]) is not int or obj["schema"] != 5:
        raise ValueError("schema")
    if obj["scope"] != "synthetic_open_only" or obj["api"] != "CreateFileW_DELETE_OPEN_EXISTING":
        raise ValueError("scope")
    if obj["holder_access"] != "READ_DATA|DELETE_without_delete_share":
        raise ValueError("holder contract")
    if any(type(obj[key]) is not bool for key in BOOLS):
        raise ValueError("boolean facts required")
    if type(obj["reason"]) is not str or obj["reason"] not in REASONS or obj["status"] not in ("observed", "unavailable"):
        raise ValueError("closed enum")
    settings = obj["queried_session_settings"]
    if settings is not None:
        if type(settings) is not dict or settings.keys() != REQUESTED_SESSION_SETTINGS.keys():
            raise ValueError("session settings shape")
        if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in settings.values()):
            raise ValueError("session settings u32 values")
        if not obj["session_started"]:
            raise ValueError("query without owned session")
    settings_match = settings == REQUESTED_SESSION_SETTINGS
    rejection = obj["schema_rejection"]
    if rejection is not None:
        validate_rejection(rejection)
        if not settings_match or not obj["session_started"] or obj["create_opend_pair"] or obj["status"] != "unavailable":
            raise ValueError("schema rejection cannot certify a pair")
        if obj["reason"] not in ("schema_unavailable", "event_loss", "budget_exceeded", "cleanup_uncertain",
                                 "clock_unavailable", "consumer_unavailable", "unexpected_status"):
            raise ValueError("schema rejection outcome")
        if rejection["stage"] == "correlation_shape" and obj["reason"] not in ("schema_unavailable", "cleanup_uncertain"):
            raise ValueError("correlation rejection outcome")
    if obj["reason"] == "schema_unavailable" or (rejection is not None and rejection["stage"] == "correlation_shape"):
        if rejection is None or not all(obj[key] for key in (
            "win32_sharing_violation", "consumer_completed", "session_stop_verified", "zero_loss", "effective_buffers_within_budget",
        )):
            raise ValueError("schema outcome requires completed observation and rejection")
    if not settings_match and any(obj[key] for key in (
        "consumer_completed", "create_opend_pair", "win32_sharing_violation",
    )):
        raise ValueError("operation before session configuration gate")
    if obj["reason"] == "session_configuration_mismatch" and (settings is None or settings_match):
        raise ValueError("configuration mismatch requires differing queried settings")
    if settings is not None and not settings_match and obj["reason"] not in (
        "session_configuration_mismatch", "budget_exceeded", "event_loss", "cleanup_uncertain",
    ):
        raise ValueError("configuration mismatch outcome")
    if obj["session_stop_verified"] and not obj["session_started"]:
        raise ValueError("stop ownership")
    if obj["owned_file_cleaned"] and not (obj["same_owned_file"] and obj["same_owned_directory"]):
        raise ValueError("cleanup identity")
    if obj["create_opend_pair"] and not all(obj[key] for key in (
        "win32_sharing_violation", "session_started", "session_stop_verified",
        "consumer_completed", "zero_loss", "effective_buffers_within_budget",
    )):
        raise ValueError("incomplete correlation")
    if obj["status"] == "observed":
        if type(exit_code) is not int or exit_code != 0 or obj["reason"] != "none" or not all(obj[key] for key in BOOLS) or not settings_match:
            raise ValueError("incomplete success")
    elif type(exit_code) is not int or exit_code != 2 or obj["reason"] == "none":
        raise ValueError("unavailable contract")
    if obj["session_started"] and not obj["session_stop_verified"] and obj["reason"] != "cleanup_uncertain":
        raise ValueError("uncertain teardown")
    return obj


if __name__ == "__main__":
    # Do not disclose parser exceptions, private filenames, or invalid input.
    try:
        if len(sys.argv) != 3:
            raise ValueError("arguments")
        with Path(sys.argv[1]).open("rb") as stream:
            result = validate(stream.read(2049), int(sys.argv[2]))
    except Exception:
        print('{"scope":"synthetic_open_only","status":"unavailable","reason":"invalid_or_missing_result_cleanup_uncertain"}')
        sys.exit(2)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    sys.exit(0 if result["status"] == "observed" else 2)
