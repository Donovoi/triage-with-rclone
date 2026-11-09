"""Synthetic evidence controls only; no process, socket, native code or credentials."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("context_contract_under_test", HERE / "context_contract.py")
F = importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)


def varint(value):
    result = bytearray()
    while value > 127: result.append((value & 127) | 128); value >>= 7
    result.append(value); return bytes(result)


def wire_fields(overrides=None):
    # Independent literal expected wire values, not supervisor constants.
    fields = {1: 0xffffffff, 2: 2, 3: 9,
        4: b"org.apache.hadoop.security.AccessControlException",
        5: b"SIMPLE authentication is not enabled.  Available:[TOKEN, KERBEROS]",
        6: 15, 7: b"", 8: 1}
    fields.update(overrides or {})
    return fields


def wire(fields=None, suffix=b""):
    fields = wire_fields() if fields is None else fields
    header = b""
    for key, value in fields.items():
        if type(value) is bytes: header += varint(key * 8 + 2) + varint(len(value)) + value
        else: header += varint(key * 8) + varint(value)
    body = varint(len(header)) + header + suffix
    return len(body).to_bytes(4, "big") + body


def empty_thread_matrix():
    return {category: dict(kdc=0, owner_login=0, format=0, namenode=0, filesystem=0,
                          reader=0, controls=0, shutdown=0, unattributed=0)
            for category in ('probe_task', 'jdk_process_reaper', 'jdk_timer', 'jdk_executor', 'jdk_cleaner',
                             'hadoop_metrics', 'hadoop_rpc', 'hadoop_fs', 'hadoop_namenode',
                             'hadoop_blockmanagement', 'hadoop_util', 'jetty', 'kerby', 'other')}


def legacy_fixture():
    # Independent literal wire record, including deliberately narrow evidence label.
    return dict(schema_version=1, scope="hdfs_kerberos_cancellation_feasibility", success=True,
        expected_kerby_version="2.1.2", runtime_binding_required=True,
        checks=dict(environment=True, endpoint_settings=True, positive_tgt=True, file_cache_v3=True,
            nonrenewable_tgt=True, issued_service_ticket=True, secure_namenode=True, listing_before=True,
            rclone_auth_boundary_rejection=True, wire_auth_boundary_rejection=True, listing_after=True, listing_repeat=True,
            source_preserved=True, cache_preserved=True, cache_ticket_bound=True, actual_service_expiry=True,
            kdc_exchange_classified=True, owner_filesystem_lifecycle=True, rc_json_parser=True, rc_authentication=True,
            cache_read_barrier=True, retained_backend=True, retained_session_after_expiry=True,
            forced_connection_loss=True, bounded_reconnect=True, cancellation_rpc_parser=True,
            cancellation_baseline=True, cancellation_stop_ack=True, cancellation_observation=True, cancellation_release=True),
        cleanup=dict(cancellation_gate_closed=True, daemon_reaped=True, rc_sockets_closed=True, cache_permissions_restored=True, children_reaped=True, relay_closed=True, kdc_relay_closed=True, filesystem_closed=True, namenode_stop_returned=True, owner_logged_out=True, kdc_stop_returned=True, threads_terminated=True, listeners_absent=True,
            private_material_removed=True, process_property_restored=True, cleanup_completed=True,
            gc_monitor_reaped=True, fs_statistics_cleaner_reaped=True, format_ssl_timer_reaped=True),
        owned_thread_cleanup=dict(gc_monitor='terminated', fs_statistics_cleaner='terminated', format_ssl_timer='terminated'),
        cache_bytes=400, observed_lifetime_seconds=120, child_count=4,
        cancellation_lifecycle=dict(rpc_parser_vectors=85, job_parser_vectors=33, baseline_unfinished_polls=3, baseline_release_success=True,
            stop_acknowledged=True, held_observations=3, unfinished_observations=3, terminal_while_held=False,
            gates_released=True, held_window_minimum_milliseconds=500, outcome="job_unfinished_during_held_window",
            terminal_result="context_cancelled", cancellation_verified=False),
        reconnect_lifecycle=dict(daemon_started=True, daemon_identity_verified=True, daemon_reaped=True,
            rc_json_parser_checked=True, rc_authentication_verified=True, fresh_cache_load_rejected=True,
            cache_permissions_restored=True, retained_listing_after_expiry=True, backend_cache_counts=[0,1,1],
            rc_requests=22, rc_connections=22, forced_disconnects=1,
            recovery_outcomes=["namenode_backoff","success"], recovery_mode="after_listing_failure",
            background_lease_activity_possible=True, transparent_same_call_recovery_verified=False),
        service_cache_lifecycle=dict(case="renewable", issued_cache_bindings=2, service_lifetime_seconds=10,
            service_renewable=True, expired_by_seconds=1, actual_service_expiry=True, remaining_tgt_seconds=100,
            cache_ticket_bound=True, original_cache_preserved=True, new_tgs_acquisition_verified=True,
            successful_renewal_verified=False), stage="completed", wire_hex=wire().hex(), rclone_wire_hex=wire().hex(),
        kdc_trace=dict(connections=[0,0,2,0], events=[
            dict(phase=2, renew=True, ticket_kind="issued_service", response="krb_error", error_code=31, fresh_service_ticket=False),
            dict(phase=2, renew=False, ticket_kind="issued_tgt", response="tgs_rep", error_code=0, fresh_service_ticket=True)],
            forwarded_bytes=4096, bytes_forwarded_unchanged=True, all_phases_observed=True, parser_checked=True, failure_stage="none"),
        relay=dict(before_connections=1, negative_connections=1, expired_connections=1, expired_kerberos_headers=1, after_connections=0, forced_disconnects=1, none_headers=1,
                   fatal_responses=1, unexpected_connections=0, bytes_forwarded_unchanged=True), error=None, ledger_eligible=False,
        diagnostic=dict(category="none", origin="none"),
        remaining_threads=dict(probe_task=0, jdk_process_reaper=0, jdk_timer=0, jdk_executor=0,
            jdk_cleaner=0, hadoop_metrics=0, hadoop_rpc=0, hadoop_fs=0, hadoop_namenode=0,
            hadoop_blockmanagement=0, hadoop_util=0, jetty=0, kerby=0, other=0),
        thread_observation_complete=True,
        remaining_thread_intervals=dict(kdc=0, owner_login=0, format=0, namenode=0,
            filesystem=0, reader=0, controls=0, shutdown=0, unattributed=0),
        remaining_thread_matrix=empty_thread_matrix(),
        remaining_timer_kinds=dict(namenode_metrics=0, rpc_idle=0, snapshot_gc=0, shell_timeout=0, ssl_store=0, unknown=0),
        remaining_rpc_kinds=dict(client_request_sender=0, client_connection=0, other=0),
        cleanup_entry_rpc_kinds=dict(client_request_sender=0, client_connection=0, other=0),
        authentication_verified=False, hdfs_authenticated=False, renewal_verified=False,
        daemon_accepted=False, provider_accepted=False, application_accepted=False,
        vendor_accepted=False, vulnerability_audited=False)



def positive(variant="patched", service_case="renewable"):
    value = legacy_fixture()
    value.update(scope="hdfs_retained_context_cancellation", binary_variant=variant)
    del value["checks"]["cancellation_release"]
    value["checks"].update(cancellation_disposition=True, cancellation_state_parser=True,
        queued_cancellation_observation=True, queued_owner_preserved=True, cancellation_recovery=True)
    patched = variant == "patched"
    value["cancellation_lifecycle"] = dict(rpc_parser_vectors=85, job_parser_vectors=42, state_parser_vectors=44,
        baseline_unfinished_polls=3, baseline_release_success=True, queued_before_stop_polls=3,
        queued_stop_acknowledged=True, queued_held_observations=3, queued_unfinished_observations=1 if patched else 3,
        queued_terminal_while_owner_held=patched, queued_owner_preserved=True, queued_terminal_result="context_cancelled",
        stop_acknowledged=True, held_observations=3, unfinished_observations=1 if patched else 3, terminal_while_held=patched,
        response_disposed=True, terminal_before_disposition=patched, client_eof_before_discard=patched,
        cancelled_stream_retired=patched, fresh_recovery_verified=patched, recovery_listing_verified=True,
        recovery_repeat_verified=True, response_disposition="discarded_after_terminal_cancellation" if patched
            else "forwarded_before_terminal_cancellation", held_window_minimum_milliseconds=500,
        outcome="job_cancelled_while_response_held" if patched else "job_unfinished_during_held_window",
        terminal_result="context_cancelled", cancellation_verified=False)
    value["reconnect_lifecycle"].update(rc_requests=48, rc_connections=50)
    value["relay"].update(after_connections=1 if patched else 0, recovery_kerberos_headers=1 if patched else 0)
    if service_case == "nonrenewable":
        value["service_cache_lifecycle"].update(case="nonrenewable", service_renewable=False)
        value["kdc_trace"].update(connections=[0, 0, 1, 0], events=value["kdc_trace"]["events"][-1:])
    return value


def raw(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def validate(value, exit_code=0, variant=None, service_case=None):
    return F.validate_java(raw(value), exit_code, service_case or value["service_cache_lifecycle"]["case"],
                           variant or value["binary_variant"])


class ContextReceiptTests(unittest.TestCase):
    def rejected(self, value, **kwargs):
        with self.assertRaisesRegex(F.ProbeError, "^java_report_invalid$"):
            validate(value, **kwargs)

    def test_four_complete_cases_and_private_wire_projection(self):
        for variant, case in F.CASES:
            with self.subTest(variant=variant, case=case):
                result = validate(positive(variant, case))
                self.assertNotIn("wire_hex", result)
                self.assertNotIn("rclone_wire_hex", result)
                self.assertEqual(result["wire_oracle"]["category"], "simple_disabled_kerberos_offered")
                self.assertFalse(result["application_accepted"])
                self.assertFalse(result["cancellation_lifecycle"]["cancellation_verified"])

    def test_variant_binding_rejects_cross_credit(self):
        for variant, case in F.CASES:
            self.rejected(positive(variant, case), variant="original" if variant == "patched" else "patched")

    def test_service_case_binding_rejects_cross_credit(self):
        for variant, case in F.CASES:
            self.rejected(positive(variant, case), service_case="nonrenewable" if case == "renewable" else "renewable")

    def test_patched_must_terminate_both_jobs_while_owner_response_held(self):
        for key, replacement in (("queued_terminal_while_owner_held", False), ("terminal_while_held", False),
                                 ("queued_unfinished_observations", 3), ("unfinished_observations", 3),
                                 ("queued_terminal_result", "success"), ("terminal_result", "success")):
            with self.subTest(key=key):
                value = positive(); value["cancellation_lifecycle"][key] = replacement; self.rejected(value)

    def test_original_must_remain_unfinished_until_release(self):
        value = positive("original")
        for key, replacement in (("queued_terminal_while_owner_held", True), ("terminal_while_held", True),
                                 ("queued_unfinished_observations", 2), ("unfinished_observations", 2),
                                 ("terminal_before_disposition", True), ("fresh_recovery_verified", True)):
            with self.subTest(key=key):
                changed = copy.deepcopy(value); changed["cancellation_lifecycle"][key] = replacement; self.rejected(changed)

    def test_discard_requires_terminal_eof_retirement_and_recovery(self):
        for key in ("terminal_before_disposition", "client_eof_before_discard", "cancelled_stream_retired",
                    "response_disposed", "fresh_recovery_verified", "recovery_listing_verified", "recovery_repeat_verified"):
            with self.subTest(key=key):
                value = positive(); value["cancellation_lifecycle"][key] = False; self.rejected(value)

    def test_queued_cancellation_requires_intact_owner_and_baseline(self):
        for key, replacement in (("baseline_release_success", False), ("queued_owner_preserved", False),
                                 ("queued_stop_acknowledged", False), ("queued_before_stop_polls", 2),
                                 ("baseline_unfinished_polls", 2), ("queued_held_observations", 2)):
            with self.subTest(key=key):
                value = positive(); value["cancellation_lifecycle"][key] = replacement; self.rejected(value)

    def test_response_disposition_is_bound_to_binary(self):
        for variant in ("original", "patched"):
            for disposition in ("not_observed", "wrong", "forwarded_before_terminal_cancellation" if variant == "patched"
                                else "discarded_after_terminal_cancellation"):
                value = positive(variant); value["cancellation_lifecycle"]["response_disposition"] = disposition
                self.rejected(value)

    def test_parser_vector_counts_and_check_bindings(self):
        for key, expected in (("rpc_parser_vectors", 85), ("job_parser_vectors", 42), ("state_parser_vectors", 44)):
            for count in (0, True, expected-1, expected+1):
                value = positive(); value["cancellation_lifecycle"][key] = count; self.rejected(value)
        for key in ("cancellation_rpc_parser", "cancellation_state_parser", "cancellation_baseline",
                    "queued_owner_preserved", "cancellation_stop_ack", "cancellation_observation", "cancellation_disposition"):
            value = positive(); value["checks"][key] = False
            value["success"] = False; value["error"] = "relay_invalid"
            self.rejected(value, exit_code=1)

    def test_exact_recovery_stream_requires_header_and_connection(self):
        for key in ("after_connections", "recovery_kerberos_headers"):
            for replacement in (0, 2, True):
                value = positive(); value["relay"][key] = replacement; self.rejected(value)
        value = positive("original"); value["relay"].update(after_connections=1, recovery_kerberos_headers=1)
        self.rejected(value)

    def test_poll_bounds_and_minimum_window(self):
        for key in ("baseline_unfinished_polls", "queued_before_stop_polls", "queued_held_observations",
                    "queued_unfinished_observations", "held_observations", "unfinished_observations"):
            for count in (-1, 4, True, 1.5):
                value = positive(); value["cancellation_lifecycle"][key] = count; self.rejected(value)
        for count in (0, 499, 501, True):
            value = positive(); value["cancellation_lifecycle"]["held_window_minimum_milliseconds"] = count; self.rejected(value)

    def test_rc_budget_and_cache_ownership(self):
        for key, replacement in (("rc_requests", 97), ("rc_connections", 129), ("rc_connections", 47),
                                 ("backend_cache_counts", [0, 1, 2]), ("forced_disconnects", 2),
                                 ("daemon_identity_verified", False), ("fresh_cache_load_rejected", False)):
            value = positive(); value["reconnect_lifecycle"][key] = replacement; self.rejected(value)
        value = positive(); value["reconnect_lifecycle"].update(rc_requests=96, rc_connections=128)
        validate(value)

    def test_request_minimum_admits_the_no_retry_path(self):
        value = positive(); value["reconnect_lifecycle"].update(rc_requests=38, rc_connections=38)
        validate(value)
        value["reconnect_lifecycle"].update(rc_requests=37, rc_connections=37)
        self.rejected(value)

    def test_claims_and_cleanup_cannot_be_promoted(self):
        for key in ("application_accepted", "provider_accepted", "vendor_accepted", "authentication_verified",
                    "renewal_verified", "vulnerability_audited", "ledger_eligible"):
            value = positive(); value[key] = True; self.rejected(value)
        value = positive(); value["cancellation_lifecycle"]["cancellation_verified"] = True; self.rejected(value)
        for key in ("cancellation_gate_closed", "daemon_reaped", "rc_sockets_closed", "private_material_removed"):
            value = positive(); value["cleanup"][key] = False; self.rejected(value)

    def test_closed_shapes_types_and_untrusted_strings(self):
        for area in (None, "cancellation_lifecycle", "relay", "reconnect_lifecycle"):
            value = positive(); target = value if area is None else value[area]; target["extra"] = "CANARY"
            self.rejected(value)
        for key, replacement in (("outcome", "CANARY"), ("terminal_result", "context canceled CANARY"),
                                 ("queued_terminal_result", "CANARY"), ("client_eof_before_discard", 1)):
            value = positive(); value["cancellation_lifecycle"][key] = replacement; self.rejected(value)
        value = positive(); value["stage"] = "CANARY"; self.rejected(value)
        with self.assertRaises(F.ProbeError): F.validate_java(b'{"success":true,"success":false}', 0)

    def test_partial_state_before_vectors_is_reportable_without_credit(self):
        value = positive()
        value.update(success=False, stage="cancellation_vectors", error="relay_invalid")
        value["diagnostic"]["category"] = "assertion"
        v = value["cancellation_lifecycle"]
        for key, item in list(v.items()):
            if type(item) is bool: v[key] = False
            elif type(item) is int: v[key] = 500 if key == "held_window_minimum_milliseconds" else 0
            else: v[key] = "not_observed"
        for key in ("cancellation_rpc_parser", "cancellation_state_parser", "cancellation_baseline",
                    "queued_cancellation_observation", "queued_owner_preserved", "cancellation_stop_ack",
                    "cancellation_observation", "cancellation_disposition", "cancellation_recovery"):
            value["checks"][key] = False
        value["relay"].update(after_connections=0, recovery_kerberos_headers=0)
        result = validate(value, exit_code=1)
        self.assertFalse(result["success"])
        self.assertFalse(result["cancellation_lifecycle"]["cancellation_verified"])


if __name__ == "__main__":
    unittest.main()
