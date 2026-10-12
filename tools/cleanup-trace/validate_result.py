"""Closed original-removal trace boundary. No executable or native code is loaded."""
import argparse
import hashlib
import json
import re
from pathlib import Path

CORRELATION_REASONS = frozenset((
    "correlation_no_selected_start", "correlation_start_order", "correlation_start_end_overlap",
    "correlation_end_missing", "correlation_end_multiple", "correlation_end_order",
    "correlation_end_before_start", "correlation_end_unowned", "correlation_cross_thread_reuse",
))
# Keep the old common reason readable for preserved historical records.
REASONS = CORRELATION_REASONS | frozenset(("none", "unsupported_environment", "identity_unavailable", "budget_exceeded", "schema_unavailable", "clock_unavailable", "correlation_missing_or_ambiguous", "event_loss", "session_collision", "access_denied", "session_unavailable", "consumer_unavailable", "cleanup_uncertain", "session_configuration_mismatch", "operation_not_observed", "status_not_attributed"))
BOOLS = frozenset(("target_identity_verified", "session_started", "settings_verified", "bounded", "zero_loss", "stop_succeeded", "session_absent", "consumer_completed", "consumer_closed", "worker_joined"))
KEYS = BOOLS | {"schema", "scope", "status", "reason", "original_ok", "os_code", "operation_us", "runtime_sha256", "counts", "schema_rejection"}
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




def validate(raw, test_exit, expected_runtime):
    if type(raw) is not bytes or not 0 < len(raw) <= 4096:
        raise ValueError("record_bound")
    if type(test_exit) is not int or not 0 <= test_exit <= 0xffffffff:
        raise ValueError("test_exit")
    if type(expected_runtime) is not str or not re.fullmatch("[a-f0-9]{64}", expected_runtime):
        raise ValueError("runtime_binding")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs)
    if type(value) is not dict or value.keys() != KEYS:
        raise ValueError("record_shape")
    if type(value["schema"]) is not int or value["schema"] != 1 or value["scope"] != "original_runtime_remove_tree":
        raise ValueError("scope")
    if any(type(value[key]) is not bool for key in BOOLS):
        raise ValueError("boolean_type")
    if type(value["runtime_sha256"]) is not str or not re.fullmatch("[a-f0-9]{64}", expected_runtime) or value["runtime_sha256"] != expected_runtime:
        raise ValueError("runtime_binding")
    if type(value["status"]) is not str or type(value["reason"]) is not str or value["status"] not in ("observed", "not_reproduced", "unavailable") or value["reason"] not in REASONS:
        raise ValueError("enum")
    if value["original_ok"] is not None and type(value["original_ok"]) is not bool:
        raise ValueError("original_result")
    if value["os_code"] is not None and not uint(value["os_code"], 0xffffffff):
        raise ValueError("os_code")
    if value["operation_us"] is not None and not uint(value["operation_us"], 180000000):
        raise ValueError("duration")
    counts = value["counts"]
    if counts is not None:
        if type(counts) is not dict or counts.keys() != {"attempts", "successful", "sharing", "other"}:
            raise ValueError("count_shape")
        if any(not uint(v,128) for v in counts.values()) or not 1 <= counts["attempts"] <= 128 or counts["attempts"] != sum(counts[k] for k in ("successful", "sharing", "other")):
            raise ValueError("count_consistency")
    if value["schema_rejection"] is not None:
        validate_rejection(value["schema_rejection"])
        if value["status"] != "unavailable":
            raise ValueError("rejection_cannot_qualify")
    if value["reason"] in CORRELATION_REASONS and (counts is not None or value["schema_rejection"] is not None):
        raise ValueError("correlation rejection has no completed counts or decoder rejection")
    if value["status"] == "unavailable":
        if value["reason"] == "none":
            raise ValueError("unavailable_reason")
        return value
    if value["reason"] != "none" or value["schema_rejection"] is not None or counts is None or value["operation_us"] is None:
        raise ValueError("qualification")
    if not all(value[key] for key in BOOLS - {"target_identity_verified"}):
        raise ValueError("trace_cleanup")
    if value["status"] == "observed":
        if value["original_ok"] is not False or value["os_code"] != 32 or counts["sharing"] == 0 or not value["target_identity_verified"] or test_exit != 101:
            raise ValueError("observed_binding")
    elif value["original_ok"] is not True or value["os_code"] is not None or test_exit != 0:
        raise ValueError("not_reproduced_binding")
    return value


def select(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= 4*1024*1024:
        raise ValueError("log_bound")
    prefix=b"runtime_cleanup_trace="
    found=[line[len(prefix):] for line in raw.splitlines() if line.startswith(prefix)]
    if len(found)!=1:
        raise ValueError("record_count")
    return found[0]


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--test-exit", required=True, type=int)
    parser.add_argument("--runtime-sha256", required=True)
    parser.add_argument("--application-sha256", required=True)
    parser.add_argument("--commit", required=True)
    args=parser.parse_args()
    try:
        if not re.fullmatch("[a-f0-9]{64}",args.application_sha256) or not re.fullmatch("[a-f0-9]{40}",args.commit):
            raise ValueError("binding")
        with args.log.open("rb") as stream: raw=stream.read(4*1024*1024+1)
        record=validate(select(raw),args.test_exit,args.runtime_sha256)
        print(json.dumps({"schema":1,"scope":"original_cleanup_diagnostic_only","commit":args.commit,"application_sha256":args.application_sha256,"private_log_sha256":hashlib.sha256(raw).hexdigest(),"trace":record,"provider_accepted":False,"cleanup_fixed":False},sort_keys=True,separators=(",",":")))
        return 1 if record["status"]=="unavailable" else 0
    except (OSError,ValueError,TypeError,KeyError,UnicodeError):
        print('{"schema":1,"scope":"original_cleanup_diagnostic_only","status":"invalid","reason":"validation_failed","provider_accepted":false,"cleanup_fixed":false}')
        return 2

if __name__=="__main__":
    raise SystemExit(main())
