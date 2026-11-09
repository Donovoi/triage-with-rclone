"""Closed evidence contract for isolated retained HDFS context cancellation.

Imports are inert. Parsing a synthetic receipt is never native qualification.
"""
from pathlib import Path
import hashlib
import importlib.util
import re

HERE = Path(__file__).resolve().parent
BASE_PATH = HERE.parent / "hdfs-kerberos-cancellation" / "cancellation_container.py"
BASE_SHA = "39a7c0caf66f72beab39ab4b856796169f768db4ecce4218e47efa672796b51c"
base_source = BASE_PATH.read_bytes()
if hashlib.sha256(base_source).hexdigest() != BASE_SHA:
    raise RuntimeError("contract_dependency_changed")
spec = importlib.util.spec_from_file_location("context_cancellation_common", BASE_PATH)
C = importlib.util.module_from_spec(spec)
exec(compile(base_source, str(BASE_PATH), "exec"), C.__dict__)
ProbeError, need, parse = C.ProbeError, C.need, C.parse
JAVA_FALSE, JAVA_CLEANUP, JAVA_CODES = C.JAVA_FALSE, C.JAVA_CLEANUP, C.JAVA_CODES
JAVA_CHECKS = (C.JAVA_CHECKS - {"cancellation_release"}) | {
    "cancellation_disposition", "cancellation_state_parser", "queued_cancellation_observation",
    "queued_owner_preserved", "cancellation_recovery"}
STAGES = C.STAGES | {"cancellation_vectors", "queued_before_stop", "queued_stop",
                    "queued_observation", "cancellation_discard", "cancellation_recovery"}
SERVICE_CASES, VARIANTS = C.SERVICE_CASES, ("original", "patched")
CASES = tuple((variant, case) for case in SERVICE_CASES for variant in VARIANTS)
parse_wire = C.parse_wire
validate_service_cache, validate_kdc_trace = C.validate_service_cache, C.validate_kdc_trace
validate_diagnostics, validate_rpc_diagnostics = C.validate_diagnostics, C.validate_rpc_diagnostics
validate_owned_cleanup = C.validate_owned_cleanup


def integer(value, low, high):
    need(type(value) is int and low <= value <= high, "java_report_invalid")


def validate_relay(value, complete, variant):
    keys = {"before_connections", "negative_connections", "expired_connections", "expired_kerberos_headers", "after_connections", "none_headers", "fatal_responses",
            "unexpected_connections", "forced_disconnects", "bytes_forwarded_unchanged", "recovery_kerberos_headers"}
    need(type(complete) is bool, "java_report_invalid")
    if value is None:
        need(not complete, "java_report_invalid"); return
    need(type(value) is dict and set(value) == keys and type(value["bytes_forwarded_unchanged"]) is bool,
         "java_report_invalid")
    for key in keys - {"bytes_forwarded_unchanged"}:
        need(type(value[key]) is int and 0 <= value[key] <= (1 if key in {"unexpected_connections", "forced_disconnects"} else 4),
             "java_report_invalid")
    need(value["fatal_responses"] <= value["none_headers"] <= value["negative_connections"] and value["expired_kerberos_headers"] <= value["expired_connections"], "java_report_invalid")
    need(value["recovery_kerberos_headers"] <= value["after_connections"], "java_report_invalid")
    if complete:
        need(all(value[key] == 1 for key in ("before_connections", "negative_connections", "expired_connections", "forced_disconnects"))
             and value["after_connections"] == value["recovery_kerberos_headers"] == (1 if variant == "patched" else 0)
             and value["none_headers"] == value["negative_connections"] == value["fatal_responses"]
             and value["expired_kerberos_headers"] == value["expired_connections"]
             and value["unexpected_connections"] == 0 and value["bytes_forwarded_unchanged"] is True,
             "java_report_invalid")


def validate_reconnect(value, complete, cleanup):
    flags = {"daemon_started", "daemon_identity_verified", "daemon_reaped", "rc_json_parser_checked",
             "rc_authentication_verified", "fresh_cache_load_rejected", "cache_permissions_restored",
             "retained_listing_after_expiry", "background_lease_activity_possible",
             "transparent_same_call_recovery_verified"}
    keys = flags | {"backend_cache_counts", "rc_requests", "rc_connections", "forced_disconnects",
                    "recovery_outcomes", "recovery_mode"}
    need(type(value) is dict and set(value) == keys
         and all(type(value[k]) is bool for k in flags), "java_report_invalid")
    need(value["background_lease_activity_possible"] is True
         and value["transparent_same_call_recovery_verified"] is False, "java_report_invalid")
    counts = value["backend_cache_counts"]
    need(type(counts) is list and len(counts) == 3
         and all(type(x) is int and -1 <= x <= 1 for x in counts), "java_report_invalid")
    need(type(value["rc_requests"]) is int and type(value["rc_connections"]) is int
         and 0 <= value["rc_requests"] <= 96
         and value["rc_requests"] <= value["rc_connections"] <= 128, "java_report_invalid")
    need(type(value["forced_disconnects"]) is int and 0 <= value["forced_disconnects"] <= 1,
         "java_report_invalid")
    outcomes = value["recovery_outcomes"]
    allowed = {"success", "namenode_backoff", "transport_eof", "transport_reset", "transport_broken_pipe"}
    need(type(outcomes) is list and len(outcomes) <= 3
         and all(type(x) is str and x in allowed for x in outcomes)
         and "success" not in outcomes[:-1], "java_report_invalid")
    mode = value["recovery_mode"]
    need(type(mode) is str and mode in {"not_observed", "first_listing_success", "after_listing_failure"},
         "java_report_invalid")
    expected = ("first_listing_success" if len(outcomes) == 1 else "after_listing_failure") \
        if outcomes and outcomes[-1] == "success" else "not_observed"
    need(mode == expected, "java_report_invalid")
    if value["daemon_started"]:
        need(value["daemon_reaped"] is cleanup["daemon_reaped"], "java_report_invalid")
    need(value["cache_permissions_restored"] is cleanup["cache_permissions_restored"], "java_report_invalid")
    if complete:
        need(all(value[k] is True for k in flags - {"transparent_same_call_recovery_verified"})
             and counts == [0, 1, 1] and 8 <= value["rc_requests"] <= 96
             and value["forced_disconnects"] == 1 and bool(outcomes) and outcomes[-1] == "success"
             and mode != "not_observed", "java_report_invalid")



def validate_cancellation(value, complete, checks, cleanup, variant):
    flags = {"baseline_release_success", "queued_stop_acknowledged", "queued_terminal_while_owner_held",
             "queued_owner_preserved", "stop_acknowledged", "terminal_while_held", "response_disposed",
             "terminal_before_disposition", "client_eof_before_discard", "cancelled_stream_retired",
             "fresh_recovery_verified", "recovery_listing_verified", "recovery_repeat_verified", "cancellation_verified"}
    counts = {"rpc_parser_vectors", "job_parser_vectors", "state_parser_vectors", "baseline_unfinished_polls",
              "queued_before_stop_polls", "queued_held_observations", "queued_unfinished_observations",
              "held_observations", "unfinished_observations", "held_window_minimum_milliseconds"}
    strings = {"queued_terminal_result", "outcome", "terminal_result", "response_disposition"}
    need(type(value) is dict and set(value) == flags | counts | strings
         and all(type(value[k]) is bool for k in flags)
         and all(type(value[k]) is int for k in counts)
         and all(type(value[k]) is str for k in strings), "java_report_invalid")
    v = value
    need(v["cancellation_verified"] is False and variant in VARIANTS
         and v["held_window_minimum_milliseconds"] == 500, "java_report_invalid")
    vectors = (v["rpc_parser_vectors"], v["job_parser_vectors"], v["state_parser_vectors"])
    need(vectors in {(0, 0, 0), (85, 0, 0), (85, 42, 0), (85, 42, 44)}, "java_report_invalid")
    need(checks["cancellation_rpc_parser"] is (vectors == (85, 42, 44))
         and checks["cancellation_state_parser"] is (vectors == (85, 42, 44)), "java_report_invalid")
    for key in ("baseline_unfinished_polls", "queued_before_stop_polls", "queued_held_observations", "held_observations"):
        integer(v[key], 0, 3)
    integer(v["queued_unfinished_observations"], 0, v["queued_held_observations"])
    integer(v["unfinished_observations"], 0, v["held_observations"])
    need(v["queued_terminal_while_owner_held"] is (v["queued_unfinished_observations"] < v["queued_held_observations"])
         and v["terminal_while_held"] is (v["unfinished_observations"] < v["held_observations"]), "java_report_invalid")
    for key in ("terminal_result", "queued_terminal_result"):
        need(v[key] in {"not_observed", "context_cancelled"}, "java_report_invalid")
    need(v["outcome"] in {"not_observed", "job_cancelled_while_response_held", "job_unfinished_during_held_window"}
         and v["response_disposition"] in {"not_observed", "discarded_after_terminal_cancellation",
             "forwarded_before_terminal_cancellation"}, "java_report_invalid")
    need(checks["cancellation_baseline"] is v["baseline_release_success"]
         and checks["queued_owner_preserved"] is v["queued_owner_preserved"]
         and checks["cancellation_stop_ack"] is v["stop_acknowledged"]
         and checks["cancellation_disposition"] is v["response_disposed"], "java_report_invalid")
    if v["queued_before_stop_polls"]:
        need(v["baseline_unfinished_polls"] == 3 and vectors == (85, 42, 44), "java_report_invalid")
    if v["queued_stop_acknowledged"]:
        need(v["queued_before_stop_polls"] == 3, "java_report_invalid")
    if v["queued_held_observations"]:
        need(v["queued_stop_acknowledged"], "java_report_invalid")
    patched = variant == "patched"
    if checks["queued_cancellation_observation"]:
        need(v["queued_held_observations"] == 3 and v["queued_terminal_while_owner_held"] is patched,
             "java_report_invalid")
    if v["queued_owner_preserved"] or v["baseline_release_success"]:
        need(v["queued_owner_preserved"] and v["baseline_release_success"]
             and checks["queued_cancellation_observation"] and v["queued_terminal_result"] == "context_cancelled",
             "java_report_invalid")
    if v["queued_terminal_result"] != "not_observed":
        need(checks["queued_cancellation_observation"], "java_report_invalid")
    if v["stop_acknowledged"]:
        need(v["queued_owner_preserved"], "java_report_invalid")
    if v["held_observations"]:
        need(v["stop_acknowledged"], "java_report_invalid")
    observed = v["outcome"] != "not_observed"
    need(checks["cancellation_observation"] is observed, "java_report_invalid")
    if observed:
        need(v["held_observations"] == 3 and v["terminal_while_held"] is patched
             and v["outcome"] == ("job_cancelled_while_response_held" if patched else "job_unfinished_during_held_window"),
             "java_report_invalid")
    if v["terminal_result"] != "not_observed":
        need(observed, "java_report_invalid")
    if v["terminal_before_disposition"]:
        need(patched and v["terminal_while_held"] and v["terminal_result"] == "context_cancelled", "java_report_invalid")
    if v["client_eof_before_discard"]:
        need(v["terminal_before_disposition"], "java_report_invalid")
    if v["cancelled_stream_retired"]:
        need(v["client_eof_before_discard"] and v["response_disposition"] == "discarded_after_terminal_cancellation",
             "java_report_invalid")
    if v["response_disposition"] != "not_observed":
        need(v["terminal_result"] == "context_cancelled" and observed
             and v["response_disposition"] == ("discarded_after_terminal_cancellation" if patched
                 else "forwarded_before_terminal_cancellation"), "java_report_invalid")
        if patched:
            need(v["cancelled_stream_retired"] and v["client_eof_before_discard"] and v["terminal_before_disposition"],
                 "java_report_invalid")
    if not patched:
        need(not any(v[k] for k in ("terminal_before_disposition", "client_eof_before_discard",
             "cancelled_stream_retired", "fresh_recovery_verified")), "java_report_invalid")
    if v["response_disposed"]:
        need(v["response_disposition"] != "not_observed", "java_report_invalid")
    if v["recovery_listing_verified"]:
        need(v["response_disposed"], "java_report_invalid")
    if v["recovery_repeat_verified"]:
        need(v["recovery_listing_verified"], "java_report_invalid")
    if v["fresh_recovery_verified"]:
        need(patched and v["recovery_repeat_verified"] and v["cancelled_stream_retired"], "java_report_invalid")
    if checks["cancellation_recovery"]:
        need(v["recovery_repeat_verified"] and v["fresh_recovery_verified"] is patched, "java_report_invalid")
    if complete:
        need(all(checks[k] for k in ("cancellation_rpc_parser", "cancellation_state_parser", "cancellation_baseline",
             "queued_cancellation_observation", "queued_owner_preserved", "cancellation_stop_ack",
             "cancellation_observation", "cancellation_disposition", "cancellation_recovery"))
             and cleanup["cancellation_gate_closed"], "java_report_invalid")


def validate_java(raw, exit_code, service_case="renewable", variant="original"):
    try:
        need(type(service_case) is str and service_case in SERVICE_CASES
             and type(variant) is str and variant in VARIANTS, "java_report_invalid")
        value = parse(raw, 32768)
        keys = {"schema_version", "scope", "success", "expected_kerby_version", "runtime_binding_required", "checks",
                "cleanup", "cache_bytes", "observed_lifetime_seconds", "child_count", "service_cache_lifecycle", "stage", "wire_hex", "rclone_wire_hex", "relay", "error", "diagnostic", "remaining_threads", "remaining_thread_intervals", "remaining_thread_matrix", "remaining_timer_kinds", "remaining_rpc_kinds", "cleanup_entry_rpc_kinds", "thread_observation_complete", "owned_thread_cleanup", "kdc_trace", "reconnect_lifecycle", "cancellation_lifecycle", "binary_variant"} | JAVA_FALSE
        need(type(value) is dict and set(value) == keys and type(value["schema_version"]) is int
             and value["schema_version"] == 1 and value["scope"] == "hdfs_retained_context_cancellation"
             and value["binary_variant"] == variant
             and value["expected_kerby_version"] == "2.1.2" and value["runtime_binding_required"] is True
             and type(value["success"]) is bool and all(value[key] is False for key in JAVA_FALSE), "java_report_invalid")
        for key, expected in (("checks", JAVA_CHECKS), ("cleanup", JAVA_CLEANUP)):
            need(type(value[key]) is dict and set(value[key]) == expected
                 and all(type(x) is bool for x in value[key].values()), "java_report_invalid")
        need(type(value["cache_bytes"]) is int and 0 <= value["cache_bytes"] <= 65536
             and type(value["observed_lifetime_seconds"]) is int and 0 <= value["observed_lifetime_seconds"] <= 120
             and (value["error"] is None or type(value["error"]) is str and value["error"] in JAVA_CODES), "java_report_invalid")
        need(type(value["stage"]) is str and value["stage"] in STAGES, "java_report_invalid")
        oracles = {}
        for key, check in (("wire_hex", "wire_auth_boundary_rejection"), ("rclone_wire_hex", "rclone_auth_boundary_rejection")):
            need(type(value[key]) is str and re.fullmatch(r"(?:[0-9a-f]{2}){0,4100}", value[key]), "java_report_invalid")
            need(not value["checks"][check] or bool(value[key]), "java_report_invalid")
            oracles[key] = parse_wire(bytes.fromhex(value[key])) if value[key] else None
        passed = all(value["checks"].values()) and all(value["cleanup"].values()) and value["error"] is None
        need(type(exit_code) is int and exit_code in (0, 1) and value["success"] is passed
             and exit_code == (0 if passed else 1), "java_report_invalid")
        if passed: need(100 < value["cache_bytes"] <= 65536 and 118 <= value["observed_lifetime_seconds"] <= 120, "java_report_invalid")
        validate_relay(value["relay"], passed, variant)
        validate_service_cache(value["service_cache_lifecycle"], passed, value["child_count"], service_case)
        validate_kdc_trace(value["kdc_trace"], passed, service_case)
        validate_reconnect(value["reconnect_lifecycle"], passed, value["cleanup"])
        validate_cancellation(value["cancellation_lifecycle"], passed, value["checks"], value["cleanup"], variant)
        if passed: need(value["reconnect_lifecycle"]["rc_requests"] >= 38, "java_report_invalid")
        need(value["reconnect_lifecycle"]["forced_disconnects"] == (0 if value["relay"] is None else value["relay"]["forced_disconnects"]), "java_report_invalid")
        validate_diagnostics(value["diagnostic"], value["remaining_threads"], value["remaining_thread_intervals"],
                             value["remaining_thread_matrix"], value["remaining_timer_kinds"], value["thread_observation_complete"], value["error"], value["cleanup"], passed)
        validate_rpc_diagnostics(value["remaining_threads"], value["remaining_rpc_kinds"], value["cleanup_entry_rpc_kinds"], passed)
        validate_owned_cleanup(value["owned_thread_cleanup"], value["cleanup"])
        if passed:
            need(value["stage"] == "completed" and value["wire_hex"] == value["rclone_wire_hex"], "java_report_invalid")
        del value["wire_hex"]  # Raw RPC bytes stay private; publish only finite categories.
        del value["rclone_wire_hex"]
        value["wire_oracle"] = oracles["wire_hex"]
        value["rclone_wire_oracle"] = oracles["rclone_wire_hex"]
        return value
    except ProbeError:
        raise ProbeError("java_report_invalid") from None


