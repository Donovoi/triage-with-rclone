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
BUDGET_BRANCH_REASONS = frozenset((
    "start_reservation_failed",
    "end_reservation_failed",
    "end_capacity_reached",
    "target_start_capacity_reached",
    "callback_limit_exceeded",
    "initial_session_bounds_unverified",
    "final_bounds_proof_unverified",
))
REASONS = CORRELATION_REASONS | BUDGET_BRANCH_REASONS | frozenset(("none", "unsupported_environment", "identity_unavailable", "budget_exceeded", "schema_unavailable", "clock_unavailable", "correlation_missing_or_ambiguous", "event_loss", "session_collision", "access_denied", "session_unavailable", "consumer_unavailable", "cleanup_uncertain", "session_configuration_mismatch", "operation_not_observed", "status_not_attributed"))
CAPTURE_CONTRACT = "window_end_admission_v1"
ADMISSION_REASONS = frozenset((
    "end_bounds_invalid", "end_bounds_regressed", "end_bounds_changed",
    "end_bounds_unpublished", "end_bounds_mismatch", "end_timestamp_invalid",
    "end_omission_summary_unavailable", "end_omission_accounting_unavailable",
    "end_unpublished_omission_unproved", "end_pre_omission_unproved", "end_post_omission_unproved",
))
FINISH_ONLY_ADMISSION_REASONS = frozenset((
    "end_bounds_unpublished", "end_bounds_mismatch", "end_omission_summary_unavailable",
    "end_unpublished_omission_unproved", "end_pre_omission_unproved", "end_post_omission_unproved",
))
BOOLS = frozenset(("target_identity_verified", "session_started", "settings_verified", "bounded", "zero_loss", "stop_succeeded", "session_absent", "consumer_completed", "consumer_closed", "worker_joined"))
KEYS = BOOLS | {"schema", "scope", "status", "reason", "original_ok", "os_code", "operation_us", "runtime_sha256", "counts", "schema_rejection"}
OWNERSHIP_COUNTS = frozenset(("starts", "ends", "complete_pairs", "nonselected_create_pairs", "other_operation_pairs"))
OWNERSHIP_KEYS = OWNERSHIP_COUNTS | {"availability", "reason", "pattern"}
OWNERSHIP_REASONS = frozenset(("schema", "unsupported_opcode", "event_loss", "budget", "order", "teardown", "window"))
OWNERSHIP_PATTERNS = frozenset(("sequential_reuse", "extra_end_without_observed_begin", "overlapping_begins", "incomplete"))
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


def validate_ownership(value, trace):
    """Supplemental observations cannot fill main counts or qualify any result."""
    if trace["reason"] != "correlation_end_multiple":
        if value is not None:
            raise ValueError("ownership outside multiple-end failure")
        return
    if trace["status"] != "unavailable" or trace["counts"] is not None:
        raise ValueError("ownership cannot qualify")
    keys = OWNERSHIP_KEYS | {"rejection"} if trace["schema"] in (3, 4) else OWNERSHIP_KEYS
    if type(value) is not dict or value.keys() != keys:
        raise ValueError("ownership shape")
    availability, reason, pattern = (value[key] for key in ("availability", "reason", "pattern"))
    if type(availability) is not str or type(reason) is not str:
        raise ValueError("ownership enum type")
    if trace["schema"] in (3, 4):
        rejection = value["rejection"]
        if availability == "unavailable" and reason == "unsupported_opcode":
            if type(rejection) is not dict or rejection.keys() != {"opcode", "version", "header_flags"}:
                raise ValueError("ownership rejection shape")
            opcode, version, flags = (rejection[k] for k in ("opcode", "version", "header_flags"))
            if (not uint(opcode, 0xFF) or opcode in {0, 32, 35, 36} or 64 <= opcode <= 77
                    or not uint(version, 0xFF) or version not in (2, 3)
                    or not uint(flags, 0xFFFF) or flags & 0x40 == 0 or flags & 0x20 != 0):
                raise ValueError("ownership unsupported header")
            if not all(trace[key] for key in BOOLS - {"target_identity_verified"}) or trace["operation_us"] is None:
                raise ValueError("ownership rejection collection gates")
        elif rejection is not None:
            raise ValueError("ownership rejection outside unsupported opcode")
    if availability == "unavailable":
        if reason not in OWNERSHIP_REASONS or pattern is not None or any(value[k] is not None for k in OWNERSHIP_COUNTS):
            raise ValueError("ownership uncertainty")
        return
    if (availability != "available" or reason != "none" or type(pattern) is not str
            or pattern not in OWNERSHIP_PATTERNS):
        raise ValueError("ownership observation enum")
    if not all(trace[key] for key in BOOLS - {"target_identity_verified"}) or trace["operation_us"] is None:
        raise ValueError("ownership collection gates")
    if (not all(uint(value[k], 8192) for k in ("starts", "ends")) or value["starts"] < 1
            or value["ends"] < 2 or value["starts"] + value["ends"] > 8192):
        raise ValueError("ownership observed counts")
    pairs = ("complete_pairs", "nonselected_create_pairs", "other_operation_pairs")
    if pattern == "sequential_reuse":
        if (not all(uint(value[k], 8192) for k in pairs)
                or value["complete_pairs"] != value["starts"] or value["starts"] != value["ends"]
                or not 1 <= value["nonselected_create_pairs"] + value["other_operation_pairs"] < value["complete_pairs"]):
            raise ValueError("ownership complete chain")
    elif any(value[k] is not None for k in pairs):
        raise ValueError("ownership anomaly has no paired attribution")
    elif (pattern == "overlapping_begins" and value["starts"] < 2) or (
            pattern == "incomplete" and value["starts"] != value["ends"] + 1):
        raise ValueError("ownership anomaly counts")


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
    if type(value) is not dict:
        raise ValueError("record_shape")
    schema = value.get("schema")
    if type(schema) is not int or schema not in (1, 2, 3, 4):
        raise ValueError("scope")
    expected_keys = KEYS if schema == 1 else KEYS | {"ownership"}
    if schema == 4:
        expected_keys = expected_keys | {"capture_contract"}
    if value.keys() != expected_keys:
        raise ValueError("record_shape")
    if schema == 4 and (type(value["capture_contract"]) is not str or value["capture_contract"] != CAPTURE_CONTRACT):
        raise ValueError("capture_contract")
    if value["scope"] != "original_runtime_remove_tree":
        raise ValueError("scope")
    if any(type(value[key]) is not bool for key in BOOLS):
        raise ValueError("boolean_type")
    if type(value["runtime_sha256"]) is not str or not re.fullmatch("[a-f0-9]{64}", expected_runtime) or value["runtime_sha256"] != expected_runtime:
        raise ValueError("runtime_binding")
    reasons = REASONS | ADMISSION_REASONS if schema == 4 else REASONS
    if type(value["status"]) is not str or type(value["reason"]) is not str or value["status"] not in ("observed", "not_reproduced", "unavailable") or value["reason"] not in reasons:
        raise ValueError("enum")
    if value["reason"] in ADMISSION_REASONS and (
            value["status"] != "unavailable" or value["counts"] is not None
            or value["ownership"] is not None or value["schema_rejection"] is not None):
        raise ValueError("admission_uncertainty")
    if value["reason"] in FINISH_ONLY_ADMISSION_REASONS and not all(value[key] for key in BOOLS - {"target_identity_verified"}):
        raise ValueError("admission_finish_gate")
    if value["reason"] in {"initial_session_bounds_unverified", "final_bounds_proof_unverified"} and value["bounded"]:
        raise ValueError("budget_bounds_contradiction")
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
    if schema >= 2:
        validate_ownership(value["ownership"], value)
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


EMPTY_TEST = "cli_imported_listing_empty_remote_publishes_explicit_empty_csv_schema"
LIBRARY_TEST = "ui::runner::tests::test_main_menu_enter_download_sets_status"
ACQUISITION_TEST = "cli_preserves_remote_identity_and_original_config"


def validate_cli_binding(value):
    keys = {"application_sha256", "application_source_sha256", "test_source_sha256", "source_tree"}
    if type(value) is not dict or value.keys() != keys:
        raise ValueError("acquisition_source_binding")
    for key in keys:
        width = 40 if key == "source_tree" else 64
        if type(value[key]) is not str or re.fullmatch("[a-f0-9]{" + str(width) + "}", value[key]) is None:
            raise ValueError("acquisition_source_binding")
    return dict(value)


def validate_schema(raw, trace):
    """Separate schema metadata; cannot contribute correlation or cleanup credit."""
    if type(raw) is not bytes or not 0 < len(raw) <= 8192:
        raise ValueError("schema_bound")
    x = json.loads(raw, object_pairs_hook=unique_pairs)
    fields = {"schema", "scope", "availability", "reason", "runtime_sha256", "call_count", "header",
              "tdh_status", "buffer_bytes", "provider_matched", "descriptor_matched", "decoding_source", "properties"}
    if (type(x) is not dict or x.keys() != fields or type(x["schema"]) is not int or x["schema"] != 1
            or x["scope"] != "unsupported_fileio_schema" or x["runtime_sha256"] != trace["runtime_sha256"]
            or type(x["availability"]) is not str or type(x["reason"]) is not str):
        raise ValueError("schema_shape")
    gates = all(trace[k] for k in BOOLS - {"target_identity_verified"}) and trace["operation_us"] is not None
    payload = fields - {"schema", "scope", "availability", "reason", "runtime_sha256"}
    if not gates:
        if (x["availability"] != "unavailable" or x["reason"] != "collection_unavailable"
                or any(x[k] is not None for k in payload)):
            raise ValueError("schema_collection_gates")
        return x
    if x["reason"] == "not_observed":
        if (x["availability"] != "unavailable" or type(x["call_count"]) is not int or x["call_count"] != 0
                or any(x[k] is not None for k in payload - {"call_count"})
                or (trace.get("ownership") or {}).get("rejection") is not None):
            raise ValueError("schema_unobserved")
        return x
    h = x["header"]
    maxima = {"id":65535, "version":255, "channel":255, "level":255, "opcode":255,
              "task":65535, "keyword":2**64-1, "header_flags":65535}
    if (type(h) is not dict or h.keys() != maxima.keys() or any(not uint(h[k], n) for k,n in maxima.items())
            or h["opcode"] in {0,32,35,36} or 64 <= h["opcode"] <= 77 or h["version"] not in (2,3)
            or h["header_flags"] & 0x40 == 0 or h["header_flags"] & 0x20 != 0):
        raise ValueError("schema_header")
    rejection = (trace.get("ownership") or {}).get("rejection")
    if rejection is not None and any(h[k] != rejection[k] for k in rejection):
        raise ValueError("schema_first_header_binding")
    if type(x["call_count"]) is not int or x["call_count"] not in (0,1):
        raise ValueError("schema_call_bound")
    if x["call_count"] == 0:
        if (x["reason"] != "buffer_unavailable" or x["availability"] != "unavailable"
                or any(x[k] is not None for k in payload - {"header", "call_count"})):
            raise ValueError("schema_allocation")
        return x
    if not uint(x["tdh_status"], 2**32-1) or not uint(x["buffer_bytes"], 2**32-1):
        raise ValueError("schema_native_status")
    reasons = {"none", "tdh_failed", "metadata_bounds", "identity_mismatch", "decoding_source",
               "property_bound", "metadata_flags", "property_shape", "property_name"}
    if x["reason"] not in reasons or (x["availability"] == "available") != (x["reason"] == "none"):
        raise ValueError("schema_reason")
    if x["availability"] not in ("available", "unavailable"):
        raise ValueError("schema_availability")
    if x["tdh_status"] != 0:
        if x["reason"] != "tdh_failed" or any(x[k] is not None for k in ("provider_matched", "descriptor_matched", "decoding_source", "properties")):
            raise ValueError("schema_failed_lookup")
        return x
    if x["reason"] == "tdh_failed":
        raise ValueError("schema_success_status")
    matches = (x["provider_matched"], x["descriptor_matched"])
    if x["reason"] == "metadata_bounds" and matches == (None,None):
        pass
    elif any(type(v) is not bool for v in matches):
        raise ValueError("schema_identity_types")
    elif x["reason"] == "identity_mismatch":
        if all(matches): raise ValueError("schema_identity_failure")
    elif not all(matches):
        raise ValueError("schema_identity_required")
    if x["reason"] != "metadata_bounds" and not 1 <= x["buffer_bytes"] <= 65536:
        raise ValueError("schema_used_bound")
    if x["reason"] != "none":
        if x["decoding_source"] is not None or x["properties"] is not None:
            raise ValueError("schema_no_partial_descriptors")
        return x
    if type(x["decoding_source"]) is not int or x["decoding_source"] not in (0,1):
        raise ValueError("schema_decoding_source")
    properties=x["properties"]
    if type(properties) is not list or not 1 <= len(properties) <= 16:
        raise ValueError("schema_property_count")
    names=set()
    for p in properties:
        if (type(p) is not dict or p.keys() != {"name","flags","in_type","out_type","count","length"}
                or type(p["name"]) is not str or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}",p["name"]) is None
                or p["name"] in names or any(not uint(p[k],65535) for k in ("in_type","out_type","count","length"))
                or not uint(p["flags"],54) or p["flags"] & ~54 != 0
                or p["flags"] & 2 != 0 and p["flags"] & 16 != 0
                or p["flags"] & 4 != 0 and p["flags"] & 32 != 0
                or p["flags"] & 4 != 0 and p["count"] >= len(properties)
                or p["flags"] & 2 != 0 and p["length"] >= len(properties)):
            raise ValueError("schema_property")
        names.add(p["name"])
    return x


def schema_result(raw, trace, commit, harness_hash, cargo_hash, original_raw, cli_binding=None):
    prefix = b"runtime_cleanup_schema="
    values = [line[len(prefix):] for line in raw.splitlines() if line.startswith(prefix)]
    if len(values) != 1:
        raise ValueError("schema_record_count")
    observation = validate_schema(values[0], trace)
    result = dict(schema=1, scope="original_cleanup_schema_diagnostic_only", commit=commit,
                  test=LIBRARY_TEST, test_harness_sha256=harness_hash, cargo_json_sha256=cargo_hash,
                  original_trace_sha256=hashlib.sha256(original_raw).hexdigest(),
                  private_log_sha256=hashlib.sha256(raw).hexdigest(), observation=observation,
                  ownership_attributed=False, cleanup_fixed=False, provider_accepted=False)
    if cli_binding is not None:
        cli_binding = validate_cli_binding(cli_binding)
        if cli_binding["application_sha256"] == harness_hash:
            raise ValueError("distinct_cli_artifacts")
        result.update(cli_binding, test=ACQUISITION_TEST)
    encoded=json.dumps(result,sort_keys=True,separators=(",",":")).encode("ascii")+b"\n"
    if len(encoded) + len(b"runtime_cleanup_schema_result=") > 8192: raise ValueError("schema_result_bound")
    return encoded


def validate_harness(raw, test_exit, harness_sha256, cargo_json_sha256, library_unit=False, dynamic_providers=None, cli_acquisition=False):
    """Bind one completed, non-ignored exact test; never publish libtest text."""
    if type(raw) is not bytes or not 0 < len(raw) <= 4*1024*1024:
        raise ValueError("stdout_bound")
    if type(test_exit) is not int or test_exit not in (0, 101):
        raise ValueError("harness_exit")
    if any(type(value) is not str or not re.fullmatch("[a-f0-9]{64}", value)
           for value in (harness_sha256, cargo_json_sha256)):
        raise ValueError("harness_binding")
    if library_unit and cli_acquisition or cli_acquisition and dynamic_providers is not None:
        raise ValueError("exclusive_harness_mode")
    if library_unit and dynamic_providers != "1":
        raise ValueError("dynamic_catalogue_required")
    test = ACQUISITION_TEST if cli_acquisition else LIBRARY_TEST if library_unit else EMPTY_TEST
    lines = raw.decode("utf-8", errors="strict").splitlines()
    running = [line for line in lines if line.startswith("running ")]
    cases = [line for line in lines if line.startswith("test ") and not line.startswith("test result:")]
    summaries = [line for line in lines if line.startswith("test result:")]
    outcome, passed, failed = ("ok", 1, 0) if test_exit == 0 else ("FAILED", 0, 1)
    summary = (rf"test result: {outcome}\. {passed} passed; {failed} failed; 0 ignored; "
               r"0 measured; ([0-9]{1,6}) filtered out; finished in [0-9]+(?:\.[0-9]+)?s")
    if (running != ["running 1 test"] or cases != [f"test {test} ... {outcome}"]
            or len(summaries) != 1 or re.fullmatch(summary, summaries[0]) is None):
        raise ValueError("exact_test_execution")
    result = {"test": test, "selected_tests": 1, "test_exit": test_exit,
            "test_harness_sha256": harness_sha256, "cargo_json_sha256": cargo_json_sha256,
            "private_stdout_sha256": hashlib.sha256(raw).hexdigest(),
            "target": "aarch64-pc-windows-msvc", "profile": "release",
            "feature": "runtime-cleanup-trace"}
    if library_unit:
        result.update(artifact_kind="library_test", dynamic_providers="1")
    if cli_acquisition:
        result.update(artifact_kind="cli_acquisition")
    return result


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--test-exit", required=True, type=int)
    parser.add_argument("--runtime-sha256", required=True)
    parser.add_argument("--application-sha256", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--test-stdout", type=Path)
    parser.add_argument("--test-harness-sha256")
    parser.add_argument("--cargo-json-sha256")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--library-unit", action="store_true")
    mode.add_argument("--cli-acquisition", action="store_true")
    parser.add_argument("--dynamic-providers")
    parser.add_argument("--schema-result", type=Path)
    parser.add_argument("--application-source-sha256")
    parser.add_argument("--test-source-sha256")
    parser.add_argument("--source-tree")
    args=parser.parse_args()
    try:
        if not re.fullmatch("[a-f0-9]{64}",args.application_sha256) or not re.fullmatch("[a-f0-9]{40}",args.commit):
            raise ValueError("binding")
        with args.log.open("rb") as stream: raw=stream.read(4*1024*1024+1)
        record=validate(select(raw),args.test_exit,args.runtime_sha256)
        result={"schema":1,"scope":"original_cleanup_diagnostic_only","commit":args.commit,"application_sha256":args.application_sha256,"private_log_sha256":hashlib.sha256(raw).hexdigest(),"trace":record,"provider_accepted":False,"cleanup_fixed":False}
        binding=(args.test_stdout,args.test_harness_sha256,args.cargo_json_sha256)
        cli_binding = None
        source_binding = (args.application_source_sha256, args.test_source_sha256, args.source_tree)
        if args.cli_acquisition:
            if any(v is None for v in binding) or args.schema_result is None or args.dynamic_providers is not None:
                raise ValueError("acquisition_binding_required")
            if args.application_sha256 == args.test_harness_sha256:
                raise ValueError("distinct_cli_artifacts")
            cli_binding = validate_cli_binding(dict(application_sha256=args.application_sha256,
                application_source_sha256=args.application_source_sha256,
                test_source_sha256=args.test_source_sha256, source_tree=args.source_tree))
        elif any(v is not None for v in source_binding):
            raise ValueError("acquisition_only_binding")
        if args.library_unit and (any(v is None for v in binding) or args.schema_result is None
                                  or args.application_sha256 != args.test_harness_sha256):
            raise ValueError("library_binding_required")
        if not args.library_unit and not args.cli_acquisition and (args.dynamic_providers is not None or args.schema_result is not None):
            raise ValueError("library_only_binding")
        if any(value is not None for value in binding):
            if any(value is None for value in binding): raise ValueError("partial_harness_binding")
            with args.test_stdout.open("rb") as stream: stdout=stream.read(4*1024*1024+1)
            result["execution"]=validate_harness(stdout,args.test_exit,args.test_harness_sha256,args.cargo_json_sha256,args.library_unit,args.dynamic_providers,args.cli_acquisition)
            if cli_binding is not None:
                result["execution"].update(cli_binding)
                result["scope"] = "original_cleanup_cli_acquisition_diagnostic_only"
        if args.library_unit:
            result["scope"]="original_cleanup_library_diagnostic_only"
            result.pop("application_sha256")  # The tested executable is libtest, not the CLI.
        print(json.dumps(result,sort_keys=True,separators=(",",":")))
        if args.library_unit or args.cli_acquisition:
            try:
                encoded=schema_result(raw,record,args.commit,args.test_harness_sha256,args.cargo_json_sha256,select(raw),cli_binding)
                with args.schema_result.open("xb") as stream: stream.write(encoded)
            except (OSError,ValueError,TypeError,KeyError,UnicodeError):
                # Supplemental failure cannot erase a separately validated original trace.
                print('runtime_cleanup_schema_result={"schema":1,"scope":"original_cleanup_schema_diagnostic_only","status":"invalid","reason":"schema_validation_failed","ownership_attributed":false,"cleanup_fixed":false,"provider_accepted":false}')
                return 2
            print("runtime_cleanup_schema_result=" + encoded.decode("ascii").rstrip("\n"))
        return 1 if record["status"]=="unavailable" else 0
    except (OSError,ValueError,TypeError,KeyError,UnicodeError):
        print('{"schema":1,"scope":"original_cleanup_diagnostic_only","status":"invalid","reason":"validation_failed","provider_accepted":false,"cleanup_fixed":false}')
        return 2

if __name__=="__main__":
    raise SystemExit(main())
