"""Closed evidence contract for the retained MIT/HDFS renewal experiment.

All helpers are inert on import. Successful local parsing is not native evidence.
"""
from pathlib import Path
import hashlib
import importlib.util
import re

HERE = Path(__file__).resolve().parent
BASE_PATH = HERE.parent / "hdfs-kerberos-reconnect" / "reconnect_container.py"
BASE_SHA = "fd0e805383ee7be022c702874f0c4d29fb5a0ca1c44f928a99dac02f793c1caa"
base_source = BASE_PATH.read_bytes()
if hashlib.sha256(base_source).hexdigest() != BASE_SHA:
    raise RuntimeError("contract_dependency_changed")
spec = importlib.util.spec_from_file_location("retained_renewal_common", BASE_PATH)
C = importlib.util.module_from_spec(spec)
exec(compile(base_source, str(BASE_PATH), "exec"), C.__dict__)
ProbeError, need, parse = C.ProbeError, C.need, C.parse
JAVA_FALSE, JAVA_CLEANUP, JAVA_CODES = C.JAVA_FALSE, C.JAVA_CLEANUP, C.JAVA_CODES
JAVA_CHECKS = (C.JAVA_CHECKS - {"nonrenewable_tgt"}) | {"renewable_tgt"}
STAGES = C.STAGES | {"mit_construct", "mit_prepare", "mit_start"}
TRACE_STAGES = C.TRACE_STAGES | {"request_authenticator"}
SERVICE_CASES = C.SERVICE_CASES
VARIANTS = ("original", "patched")
SASL_STAGES = frozenset(("start", "negotiate_sent", "negotiate_received", "initiate_sent", "challenge_received", "response_sent", "authenticated"))
parse_wire, validate_relay = C.parse_wire, C.validate_relay
validate_reconnect, validate_diagnostics = C.validate_reconnect, C.validate_diagnostics
validate_rpc_diagnostics, validate_owned_cleanup = C.validate_rpc_diagnostics, C.validate_owned_cleanup
RENEWAL_FIELDS = frozenset(("fields_present", "nonce", "server", "auth_time", "start_time",
                            "validity", "renewal_horizon", "flags", "key"))
OWNER_TRUE = frozenset(("children_reaped", "streams_reaped", "modules_verified", "listener_verified", "private_material_removed"))
OWNER_FALSE = frozenset(("forced", "descendants_seen", "stream_failure", "native_qualified", "renewal_verified"))
OWNER_STAGES = frozenset(("constructed", "environment", "prepared", "kdc_start", "running", "closed",
    "database_create", "reader_create", "hdfs_create", "hdfs_export", "http_create", "http_export"))


def integer(value, low, high):
    need(type(value) is int and low <= value <= high, "java_report_invalid")


def expected_events(service_case, variant):
    ordinary = dict(phase=2, renew=False, ticket_kind="issued_tgt", response="tgs_rep",
                    error_code=0, fresh_service_ticket=True, authenticator_usage=7)
    if service_case == "nonrenewable": return [ordinary]
    if variant == "patched":
        return [dict(phase=2, renew=True, ticket_kind="issued_service", response="tgs_rep",
                     error_code=0, fresh_service_ticket=True, authenticator_usage=7)]
    return [dict(phase=2, renew=True, ticket_kind="issued_service", response="krb_error",
                 error_code=31, fresh_service_ticket=False, authenticator_usage=11), ordinary]


def validate_kdc_trace(value, complete, service_case, variant):
    if value is None:
        need(not complete, "java_report_invalid"); return
    need(type(value) is dict and set(value) == {"connections", "events", "forwarded_bytes",
         "bytes_forwarded_unchanged", "all_phases_observed", "parser_checked", "failure_stage"}, "java_report_invalid")
    need(type(value["failure_stage"]) is str and value["failure_stage"] in TRACE_STAGES
         and (value["failure_stage"] == "none") is value["bytes_forwarded_unchanged"], "java_report_invalid")
    counts, events = value["connections"], value["events"]
    need(type(counts) is list and len(counts) == 4 and all(type(x) is int and 0 <= x <= 4 for x in counts)
         and type(events) is list and len(events) <= sum(counts) <= 16, "java_report_invalid")
    integer(value["forwarded_bytes"], 0, 1048576)
    need(all(type(value[k]) is bool for k in ("bytes_forwarded_unchanged", "all_phases_observed", "parser_checked")), "java_report_invalid")
    phase_counts = [0, 0, 0, 0]
    for event in events:
        need(type(event) is dict and set(event) == {"phase", "renew", "ticket_kind", "response", "error_code",
             "fresh_service_ticket", "authenticator_usage"}, "java_report_invalid")
        integer(event["phase"], 0, 3); integer(event["error_code"], 0, 255)
        integer(event["authenticator_usage"], 7, 11)
        need(event["authenticator_usage"] in (7, 11) and type(event["renew"]) is bool
             and type(event["fresh_service_ticket"]) is bool
             and type(event["ticket_kind"]) is str and event["ticket_kind"] in {"issued_tgt", "issued_service"}
             and type(event["response"]) is str and event["response"] in {"tgs_rep", "krb_error"}, "java_report_invalid")
        need(event["renew"] is (event["ticket_kind"] == "issued_service")
             and (event["response"] == "tgs_rep") is (event["error_code"] == 0)
             and (event["response"] != "krb_error" or event["fresh_service_ticket"] is False), "java_report_invalid")
        phase_counts[event["phase"]] += 1
    need(all(phase_counts[i] <= counts[i] for i in range(4)), "java_report_invalid")
    if complete:
        expected = expected_events(service_case, variant)
        need(counts == [0, 0, len(expected), 0] and events == expected
             and value["forwarded_bytes"] > 0
             and all(value[k] is True for k in ("bytes_forwarded_unchanged", "all_phases_observed", "parser_checked")), "java_report_invalid")


def validate_owner(owner, complete):
    if owner is None:
        need(not complete, "java_report_invalid"); return
    need(type(owner) is dict and set(owner) == {"stage", "setup_completed", "children"} | OWNER_TRUE | OWNER_FALSE, "java_report_invalid")
    need(type(owner["stage"]) is str and owner["stage"] in OWNER_STAGES, "java_report_invalid")
    integer(owner["setup_completed"], 0, 6); integer(owner["children"], 0, 7)
    need(all(type(owner[k]) is bool for k in OWNER_TRUE | OWNER_FALSE)
         and owner["native_qualified"] is False and owner["renewal_verified"] is False, "java_report_invalid")
    if complete:
        need(owner["stage"] == "closed" and owner["setup_completed"] == 6 and owner["children"] == 7
             and all(owner[k] is True for k in OWNER_TRUE) and all(owner[k] is False for k in OWNER_FALSE), "java_report_invalid")


def validate_sasl(value, complete, fresh):
    if value is None:
        need(not complete, "java_report_invalid"); return
    flags = {"fresh_connection", "ap_ticket_bound", "sasl_success", "complete_before_close", "closed"}
    limits = dict(client_frames=64, server_frames=64, context_frames=1,
                  listing_requests=32, matching_listing_replies=32, pending_requests=32, pending_at_close=32)
    need(type(value) is dict and set(value) == flags | set(limits) | {"stage"}, "java_report_invalid")
    need(type(value["stage"]) is str and value["stage"] in SASL_STAGES, "java_report_invalid")
    need(all(type(value[k]) is bool for k in flags) and value["fresh_connection"] is fresh, "java_report_invalid")
    for key, limit in limits.items(): integer(value[key], 0, limit)
    need(value["matching_listing_replies"] <= value["listing_requests"], "java_report_invalid")
    if complete:
        need(value["stage"] == "authenticated" and all(value[k] is True for k in flags - {"fresh_connection"})
             and value["client_frames"] >= 5 and value["server_frames"] >= 4 and value["context_frames"] == 1
             and value["listing_requests"] >= 1 and value["listing_requests"] == value["matching_listing_replies"]
             and value["pending_requests"] == value["pending_at_close"] == 0, "java_report_invalid")


def validate_new_evidence(value, complete, service_case, variant):
    need(type(service_case) is str and service_case in SERVICE_CASES and type(variant) is str and variant in VARIANTS
         and type(value["binary_variant"]) is str and value["binary_variant"] == variant, "java_report_invalid")
    observations=value["ticket_flag_observations"]
    need(type(observations) is list and len(observations)<=2, "java_report_invalid")
    for index, observed in enumerate(observations):
        need(type(observed) is dict and set(observed)=={"kind","cache_flags","issued_flags","renewable_expected"}
             and observed["kind"]==("issued_tgt" if index==0 else "issued_service")
             and type(observed["renewable_expected"]) is bool
             and observed["renewable_expected"] is (index==0 or service_case=="renewable"), "java_report_invalid")
        integer(observed["cache_flags"],0,4294967295); integer(observed["issued_flags"],0,4294967295)
        if complete:
            flags=observed["cache_flags"]
            need(flags==observed["issued_flags"] and flags & ~0x00e00000 == 0
                 and bool(flags & 0x00800000) is observed["renewable_expected"], "java_report_invalid")
    if complete: need(len(observations)==2, "java_report_invalid")
    integer(value["rpc_gate_vectors"], 0, 85)
    validate_owner(value["mit_owner"], complete)
    validate_sasl(value["initial_sasl_binding"], complete, False)
    validate_sasl(value["fresh_sasl_binding"], complete, True)
    evidence = value["renewal_evidence"]
    if evidence is None:
        need(not complete, "java_report_invalid"); return
    counters = dict(requests=4, authenticator_controls=32, renewal_replies=1, ordinary_replies=1,
                    reply_controls=4, initial_ap_bindings=1, fresh_ap_bindings=1, ap_controls=8)
    need(type(evidence) is dict and set(evidence) == set(counters) | {"renewal_fields", "closed", "renewal_verified"}, "java_report_invalid")
    for key, limit in counters.items(): integer(evidence[key], 0, limit)
    fields = evidence["renewal_fields"]
    need(type(fields) is dict and (not fields or set(fields) == RENEWAL_FIELDS)
         and all(type(x) is bool for x in fields.values()) and type(evidence["closed"]) is bool
         and evidence["renewal_verified"] is False, "java_report_invalid")
    if complete:
        positive = service_case == "renewable" and variant == "patched"
        requests = len(expected_events(service_case, variant))
        need(value["rpc_gate_vectors"] == 85 and evidence["requests"] == requests
             and evidence["authenticator_controls"] == requests * 8 and evidence["closed"] is True
             and evidence["initial_ap_bindings"] == evidence["fresh_ap_bindings"] == 1
             and evidence["ap_controls"] == 8 and evidence["renewal_replies"] == int(positive)
             and evidence["ordinary_replies"] == int(not positive) and evidence["reply_controls"] == (4 if positive else 2)
             and (set(fields) == RENEWAL_FIELDS and all(fields.values()) if positive else fields == {}), "java_report_invalid")


def validate_service_cache(value, complete, child_count, service_case, variant):
    keys = {"case", "issued_cache_bindings", "service_lifetime_seconds", "service_renewable",
            "expired_by_seconds", "actual_service_expiry", "remaining_tgt_seconds", "cache_ticket_bound",
            "original_cache_preserved", "new_tgs_acquisition_verified", "successful_renewal_verified"}
    need(type(service_case) is str and service_case in SERVICE_CASES, "java_report_invalid")
    need(type(value) is dict and set(value) == keys and type(value["case"]) is str
         and value["case"] in (*SERVICE_CASES, "not_selected"), "java_report_invalid")
    need(value["case"] == service_case or not complete and value["case"] == "not_selected", "java_report_invalid")
    for key, limit in (("issued_cache_bindings", 2), ("service_lifetime_seconds", 10),
                       ("expired_by_seconds", 15), ("remaining_tgt_seconds", 120)):
        need(type(value[key]) is int and 0 <= value[key] <= limit, "java_report_invalid")
    flags = ("service_renewable", "actual_service_expiry", "cache_ticket_bound", "original_cache_preserved",
             "new_tgs_acquisition_verified", "successful_renewal_verified")
    need(all(type(value[k]) is bool for k in flags)
         and value["service_renewable"] is (value["case"] == "renewable")
         and value["successful_renewal_verified"] is False, "java_report_invalid")
    need(type(child_count) is int and 0 <= child_count <= 4, "java_report_invalid")
    if complete:
        need(child_count == 4 and value["issued_cache_bindings"] == 2
             and 8 <= value["service_lifetime_seconds"] <= 10 and 1 <= value["expired_by_seconds"] <= 15
             and 1 <= value["remaining_tgt_seconds"] <= 120
             and all(value[k] is True for k in ("actual_service_expiry", "cache_ticket_bound",
                                               "original_cache_preserved"))
             and value["new_tgs_acquisition_verified"] is not (service_case == "renewable" and variant == "patched"), "java_report_invalid")


def validate_java(raw, exit_code, service_case="renewable", variant="patched"):
    try:
        value = parse(raw, 32768)
        keys = {"schema_version", "scope", "success", "expected_kerby_version", "runtime_binding_required", "checks",
                "cleanup", "cache_bytes", "observed_lifetime_seconds", "child_count", "service_cache_lifecycle", "stage", "wire_hex", "rclone_wire_hex", "relay", "error", "diagnostic", "remaining_threads", "remaining_thread_intervals", "remaining_thread_matrix", "remaining_timer_kinds", "remaining_rpc_kinds", "cleanup_entry_rpc_kinds", "thread_observation_complete", "owned_thread_cleanup", "kdc_trace", "reconnect_lifecycle", "renewal_evidence", "mit_owner", "binary_variant", "rpc_gate_vectors", "initial_sasl_binding", "fresh_sasl_binding", "ticket_flag_observations"} | JAVA_FALSE
        need(type(value) is dict and set(value) == keys and type(value["schema_version"]) is int
             and value["schema_version"] == 1 and value["scope"] == "hdfs_mit_retained_renewal"
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
        validate_relay(value["relay"], passed)
        validate_service_cache(value["service_cache_lifecycle"], passed, value["child_count"], service_case, variant)
        validate_kdc_trace(value["kdc_trace"], passed, service_case, variant)
        validate_new_evidence(value, passed, service_case, variant)
        validate_reconnect(value["reconnect_lifecycle"], passed, value["cleanup"])
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

