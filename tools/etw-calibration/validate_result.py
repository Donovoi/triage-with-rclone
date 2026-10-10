"""Pure, strict release boundary for the sole sanitized calibration record."""
import json
import sys
from pathlib import Path

REASONS = frozenset((
    "none", "unsupported_environment", "owned_file_unavailable", "identity_unavailable",
    "budget_exceeded", "schema_unavailable", "clock_unavailable",
    "correlation_missing_or_ambiguous", "unexpected_status", "event_loss",
    "session_collision", "access_denied", "session_unavailable", "consumer_unavailable",
    "cleanup_uncertain",
))
BOOLS = frozenset((
    "win32_sharing_violation", "create_opend_pair", "same_owned_file", "same_owned_directory", "session_started",
    "session_stop_verified", "consumer_completed", "zero_loss",
    "effective_buffers_within_budget", "owned_file_cleaned",
))
KEYS = BOOLS | {"schema", "scope", "status", "reason", "api", "holder_access"}


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
    if type(obj["schema"]) is not int or obj["schema"] != 2:
        raise ValueError("schema")
    if obj["scope"] != "synthetic_open_only" or obj["api"] != "CreateFileW_DELETE_OPEN_EXISTING":
        raise ValueError("scope")
    if obj["holder_access"] != "READ_DATA|DELETE_without_delete_share":
        raise ValueError("holder contract")
    if any(type(obj[key]) is not bool for key in BOOLS):
        raise ValueError("boolean facts required")
    if obj["reason"] not in REASONS or obj["status"] not in ("observed", "unavailable"):
        raise ValueError("closed enum")
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
        if type(exit_code) is not int or exit_code != 0 or obj["reason"] != "none" or not all(obj[key] for key in BOOLS):
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
