"""Pure report rejection tests; no JVM, build, network, or container execution."""
import copy
import json
import unittest
import positive_contract as F

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
    return dict(schema_version=1, scope="hdfs_kerberos_reconnect_feasibility", success=True,
        expected_kerby_version="2.1.2", runtime_binding_required=True,
        checks=dict(environment=True, endpoint_settings=True, positive_tgt=True, file_cache_v3=True,
            nonrenewable_tgt=True, issued_service_ticket=True, secure_namenode=True, listing_before=True,
            rclone_auth_boundary_rejection=True, wire_auth_boundary_rejection=True, listing_after=True, listing_repeat=True,
            source_preserved=True, cache_preserved=True, cache_ticket_bound=True, actual_service_expiry=True,
            kdc_exchange_classified=True, owner_filesystem_lifecycle=True, rc_json_parser=True, rc_authentication=True,
            cache_read_barrier=True, retained_backend=True, retained_session_after_expiry=True,
            forced_connection_loss=True, bounded_reconnect=True),
        cleanup=dict(daemon_reaped=True, rc_sockets_closed=True, cache_permissions_restored=True, children_reaped=True, relay_closed=True, kdc_relay_closed=True, filesystem_closed=True, namenode_stop_returned=True, owner_logged_out=True, kdc_stop_returned=True, threads_terminated=True, listeners_absent=True,
            private_material_removed=True, process_property_restored=True, cleanup_completed=True,
            gc_monitor_reaped=True, fs_statistics_cleaner_reaped=True, format_ssl_timer_reaped=True),
        owned_thread_cleanup=dict(gc_monitor='terminated', fs_statistics_cleaner='terminated', format_ssl_timer='terminated'),
        cache_bytes=400, observed_lifetime_seconds=120, child_count=4,
        reconnect_lifecycle=dict(daemon_started=True, daemon_identity_verified=True, daemon_reaped=True,
            rc_json_parser_checked=True, rc_authentication_verified=True, fresh_cache_load_rejected=True,
            cache_permissions_restored=True, retained_listing_after_expiry=True, backend_cache_counts=[0,1,1],
            rc_requests=10, rc_connections=10, forced_disconnects=1,
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



def fixture(case="renewable", variant="patched", policy=None):
    policy=policy or ("default300" if case=="renewable" else "strict5")
    value = legacy_fixture()
    value["scope"] = "hdfs_mit_retained_renewal"
    value["checks"]["renewable_tgt"] = value["checks"].pop("nonrenewable_tgt")
    value["binary_variant"] = variant
    value["kdc_policy"]=dict(name=policy,clock_skew_seconds=5 if policy=="strict5" else 300,configuration_verified=True,vectors=9)
    value["rpc_gate_vectors"] = 85
    value["ticket_flag_observations"] = [dict(kind="issued_tgt",cache_flags=0x00e10000,issued_flags=0x00e10000,renewable_expected=True),
        dict(kind="issued_service",cache_flags=0x00a90000 if case=="renewable" else 0x00290000,
             issued_flags=0x00a90000 if case=="renewable" else 0x00290000,renewable_expected=case=="renewable")]
    positive = case == "renewable" and variant == "patched" and policy == "default300"
    cache = value["service_cache_lifecycle"]
    cache.update(case=case, service_renewable=case == "renewable", new_tgs_acquisition_verified=not positive)
    ordinary = dict(phase=2, renew=False, ticket_kind="issued_tgt", response="tgs_rep", error_code=0,
                    fresh_service_ticket=True, authenticator_usage=7)
    renewal = dict(phase=2, renew=True, ticket_kind="issued_service", response="tgs_rep", error_code=0,
                   fresh_service_ticket=True, authenticator_usage=7)
    rejected = dict(phase=2, renew=True, ticket_kind="issued_service", response="krb_error", error_code=31 if variant=="original" else 32,
                    fresh_service_ticket=False, authenticator_usage=11 if variant=="original" else 7)
    events = [renewal] if positive else [rejected, ordinary] if case == "renewable" else [ordinary]
    value["kdc_trace"].update(connections=[0, 0, len(events), 0], events=events)
    value["renewal_evidence"] = dict(requests=len(events), authenticator_controls=8 * len(events),
        renewal_replies=1 if positive else 0, ordinary_replies=0 if positive else 1,
        reply_controls=4 if positive else 2, initial_ap_bindings=1, fresh_ap_bindings=1, ap_controls=8,
        renewal_fields=dict(fields_present=True, nonce=True, server=True, auth_time=True, start_time=True,
                            validity=True, renewal_horizon=True, flags=True, key=True) if positive else {},
        response_observations=[dict(renew=e["renew"],authenticator_usage=e["authenticator_usage"],
            response=e["response"],error_code=e["error_code"],stage="complete",
             service_expired_seconds=12 if policy=="strict5" else 7,
             renewable_remaining_seconds=(38 if policy=="strict5" else 43) if case=="renewable" else 0) for e in events],
        closed=True, renewal_verified=False)
    value["mit_owner"] = dict(stage="closed", setup_completed=6, children=7, children_reaped=True,
        streams_reaped=True, modules_verified=True, listener_verified=True, private_material_removed=True,
        forced=False, descendants_seen=False, stream_failure=False, native_qualified=False, renewal_verified=False)
    binding = dict(stage="authenticated", fresh_connection=False, client_frames=9, server_frames=8, context_frames=1,
                   ap_ticket_bound=True, sasl_success=True, listing_requests=2, matching_listing_replies=2,
                   pending_requests=0, pending_at_close=0, complete_before_close=True, closed=True)
    value["initial_sasl_binding"] = binding.copy()
    value["fresh_sasl_binding"] = dict(binding, fresh_connection=True)
    return value


def encode(value): return json.dumps(value, separators=(",", ":")).encode("ascii")


class ContractTests(unittest.TestCase):
    def accept(self, value, case="renewable", variant="patched", exit_code=0, policy=None):
        policy=policy or ("default300" if case=="renewable" else "strict5")
        return F.validate_java(encode(value), exit_code, case, variant, policy)

    def reject(self, value, case="renewable", variant="patched", exit_code=0, policy=None):
        with self.assertRaises(F.ProbeError) as caught:
            self.accept(value, case, variant, exit_code, policy)
        self.assertEqual(caught.exception.code, "java_report_invalid")

    def test_six_distinct_case_contracts(self):
        self.assertEqual(len(F.CASES),6)
        for variant,case,policy in F.CASES:
            with self.subTest(case=case,variant=variant,policy=policy):
                out=self.accept(fixture(case,variant,policy),case,variant,policy=policy)
                self.assertTrue(out["success"])
                self.assertFalse(out["renewal_verified"])
                self.assertNotIn("wire_hex",out)
                self.assertEqual(out["wire_oracle"],out["rclone_wire_oracle"])

    def test_policy_cannot_be_relabelled(self):
        self.reject(fixture(policy="strict5"))
        self.reject(fixture(),policy="strict5")
        self.reject(fixture(),policy="unknown")
        self.reject(fixture("nonrenewable",policy="default300"),case="nonrenewable",policy="default300")
        for field,bad in (("name","default301"),("clock_skew_seconds",True),("clock_skew_seconds",5),
                          ("configuration_verified",False),("configuration_verified",1),("vectors",8),("vectors",True)):
            v=fixture();v["kdc_policy"][field]=bad;self.reject(v)

    def test_strict_expiry_denial_cannot_count_as_renewal(self):
        v=fixture(policy="strict5")
        self.assertEqual(v["kdc_trace"]["events"][0]["error_code"],32)
        self.assertEqual(v["kdc_trace"]["events"][0]["authenticator_usage"],7)
        self.accept(v,policy="strict5")
        for key in ("kdc_trace","renewal_evidence","service_cache_lifecycle"):
            forged=fixture();forged[key]=v[key];self.reject(forged)
        for field,bad in (("error_code",31),("authenticator_usage",11),("response","tgs_rep")):
            forged=fixture(policy="strict5");forged["kdc_trace"]["events"][0][field]=bad
            self.reject(forged,policy="strict5")

    def test_request_timing_bound_to_policy_and_horizon(self):
        for variant,case,policy in F.CASES:
            low,high=(6,20) if policy=="strict5" else (1,15)
            for age in (low,high):
                v=fixture(case,variant,policy)
                for response in v["renewal_evidence"]["response_observations"]:response["service_expired_seconds"]=age
                self.accept(v,case,variant,policy=policy)
            for bad in (True,low-1,high+1,1.5):
                v=fixture(case,variant,policy);v["renewal_evidence"]["response_observations"][0]["service_expired_seconds"]=bad
                self.reject(v,case,variant,policy=policy)
            for bad in ((True,-1,24,60,1.5) if case=="renewable" else (True,-1,1,1.5)):
                v=fixture(case,variant,policy);v["renewal_evidence"]["response_observations"][0]["renewable_remaining_seconds"]=bad
                self.reject(v,case,variant,policy=policy)

    def test_variant_cannot_be_relabelled(self):
        self.reject(fixture(variant="original"))
        self.reject(fixture(), variant="original")
        self.reject(fixture(), variant="unrecognized")

    def test_case_cannot_be_relabelled(self):
        self.reject(fixture(case="nonrenewable"))
        self.reject(fixture(), case="nonrenewable")

    def test_ordinary_acquisition_cannot_count_as_renewal(self):
        v = fixture(); fallback = fixture(variant="original")
        for key in ("kdc_trace", "renewal_evidence", "service_cache_lifecycle"):
            v[key] = fallback[key]
        self.reject(v)

    def test_listing_without_fresh_ticket_binding_rejected(self):
        for key in ("initial_sasl_binding", "fresh_sasl_binding"):
            for field in ("ap_ticket_bound", "sasl_success", "complete_before_close", "closed"):
                with self.subTest(key=key, field=field):
                    v=fixture(); v[key][field]=False; self.reject(v)

    def test_listing_response_and_pending_work_bound(self):
        for key in ("initial_sasl_binding", "fresh_sasl_binding"):
            for field, bad in (("matching_listing_replies", 1), ("pending_requests", 1),
                               ("pending_at_close", 1), ("context_frames", 0), ("listing_requests", 0)):
                with self.subTest(key=key, field=field):
                    v=fixture(); v[key][field]=bad; self.reject(v)

    def test_initial_fresh_connection_labels_bound(self):
        for key in ("initial_sasl_binding", "fresh_sasl_binding"):
            v=fixture(); v[key]["fresh_connection"]=not v[key]["fresh_connection"]; self.reject(v)

    def test_each_authenticated_renewal_field_required(self):
        for field in fixture()["renewal_evidence"]["renewal_fields"]:
            for bad in (False, 1, None):
                with self.subTest(field=field, bad=bad):
                    v=fixture(); v["renewal_evidence"]["renewal_fields"][field]=bad; self.reject(v)

    def test_renewal_fields_not_credited_to_controls(self):
        for case, variant in (("renewable", "original"), ("nonrenewable", "original"), ("nonrenewable", "patched")):
            v=fixture(case, variant); v["renewal_evidence"]["renewal_fields"]=fixture()["renewal_evidence"]["renewal_fields"]
            self.reject(v, case, variant)

    def test_authenticator_usage_and_exact_error_bound(self):
        for case, variant in (("renewable", "original"), ("renewable", "patched"), ("nonrenewable", "patched")):
            for field, bad in (("authenticator_usage", 9), ("authenticator_usage", True), ("error_code", 1),
                               ("phase", 0), ("ticket_kind", "issued_service" if case == "nonrenewable" else "issued_tgt")):
                with self.subTest(case=case, variant=variant, field=field, bad=bad):
                    v=fixture(case, variant); v["kdc_trace"]["events"][0][field]=bad; self.reject(v, case, variant)

    def test_every_evidence_counter_bound(self):
        for field in ("requests", "authenticator_controls", "renewal_replies", "ordinary_replies", "reply_controls",
                      "initial_ap_bindings", "fresh_ap_bindings", "ap_controls"):
            for bad in (True, -1, 999):
                with self.subTest(field=field, bad=bad):
                    v=fixture(); v["renewal_evidence"][field]=bad; self.reject(v)
            v=fixture(); v["renewal_evidence"][field] += 1; self.reject(v)

    def test_cleanup_required_for_positive_result(self):
        for field in ("children_reaped", "streams_reaped", "modules_verified", "listener_verified", "private_material_removed"):
            v=fixture(); v["mit_owner"][field]=False; self.reject(v)
        for field in ("forced", "descendants_seen", "stream_failure"):
            v=fixture(); v["mit_owner"][field]=True; self.reject(v)
        for key in ("children", "setup_completed"):
            v=fixture(); v["mit_owner"][key]-=1; self.reject(v)
        v=fixture(); v["renewal_evidence"]["closed"]=False; self.reject(v)

    def test_no_acceptance_promotion(self):
        for key in ("ledger_eligible", "authentication_verified", "hdfs_authenticated", "renewal_verified",
                    "daemon_accepted", "provider_accepted", "application_accepted", "vendor_accepted", "vulnerability_audited"):
            v=fixture(); v[key]=True; self.reject(v)
        for section, key in (("mit_owner", "native_qualified"), ("mit_owner", "renewal_verified"), ("renewal_evidence", "renewal_verified")):
            v=fixture(); v[section][key]=True; self.reject(v)

    def test_gate_vectors_exact(self):
        for bad in (0, 84, 86, True):
            v=fixture(); v["rpc_gate_vectors"]=bad; self.reject(v)

    def test_closed_schemas(self):
        for section in (None, "kdc_policy", "mit_owner", "renewal_evidence", "initial_sasl_binding", "fresh_sasl_binding", "kdc_trace"):
            v=fixture(); obj=v if section is None else v[section]; obj["unexpected"]="secret"; self.reject(v)
        for key in ("kdc_policy", "mit_owner", "renewal_evidence", "initial_sasl_binding", "fresh_sasl_binding"):
            v=fixture(); del v[key]; self.reject(v)
            v=fixture(); v[key]=None; self.reject(v)

    def test_exit_status_and_boolean_types(self):
        for bad in (1, True, -1): self.reject(fixture(), exit_code=bad)
        for key in ("success", "schema_version", "child_count", "observed_lifetime_seconds"):
            v=fixture(); v[key]=True if key != "success" else 1; self.reject(v)

    def test_duplicate_keys_and_nonfinite_json(self):
        for raw in (encode(fixture()).replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1'),
                    encode(fixture()).replace(b'"rpc_gate_vectors":85', b'"rpc_gate_vectors":NaN')):
            with self.assertRaises(F.ProbeError): F.validate_java(raw, 0)

    def test_partial_failure_preserves_evidence_without_admission(self):
        v=fixture(); v.update(success=False, error="wire_invalid", stage="bounded_reconnect")
        v["checks"]["listing_after"]=False; v["diagnostic"]["category"]="assertion"
        v["fresh_sasl_binding"]=None; v["renewal_evidence"]=None
        out=self.accept(v, exit_code=1); self.assertFalse(out["success"])
        self.reject(v, exit_code=0)

    def test_partial_failure_cannot_carry_unbounded_diagnostics(self):
        v=fixture(); v.update(success=False, error="wire_invalid", stage="bounded_reconnect")
        v["checks"]["listing_after"]=False; v["diagnostic"]["category"]="assertion"
        v["mit_owner"]["children"]=100; self.reject(v, exit_code=1)

    def test_ticket_flags_cannot_weaken_acceptance(self):
        for bad in (True,-1,4294967296,0x00e90000):
            v=fixture();v["ticket_flag_observations"][0]["cache_flags"]=bad;v["ticket_flag_observations"][0]["issued_flags"]=bad;self.reject(v)
        v=fixture();v["ticket_flag_observations"]=[];self.reject(v)
        v=fixture();v["ticket_flag_observations"][1]["kind"]="issued_tgt";self.reject(v)

    def test_mit_flags_reject_privilege_or_semantic_drift(self):
        forbidden=(0x40000000,0x20000000,0x10000000,0x08000000,0x04000000,0x02000000,0x01000000,0x00040000,0x00008000,0x00000001)
        for index in (0,1):
            for bit in forbidden:
                with self.subTest(index=index,bit=bit):
                    v=fixture();obs=v["ticket_flag_observations"][index]
                    obs["cache_flags"] |= bit;obs["issued_flags"] |= bit;self.reject(v)
            for bit in (0x00200000,0x00010000,0x00800000):
                v=fixture();obs=v["ticket_flag_observations"][index]
                obs["cache_flags"] &= ~bit;obs["issued_flags"] &= ~bit;self.reject(v)
        v=fixture();v["ticket_flag_observations"][0]["cache_flags"] ^= 0x00010000;self.reject(v)
        for index,bit in ((0,0x00400000),(1,0x00080000)):
            v=fixture();obs=v["ticket_flag_observations"][index]
            obs["cache_flags"] &= ~bit;obs["issued_flags"] &= ~bit;self.reject(v)

    def test_partial_flag_failure_preserves_bounded_observation(self):
        v=fixture();v.update(success=False,error="ticket_flags_mismatch",stage="service_ticket")
        v["checks"]["listing_after"]=False;v["diagnostic"]["category"]="assertion"
        v["ticket_flag_observations"]=[dict(kind="issued_tgt",cache_flags=0x00e10000,issued_flags=0x00e10000,renewable_expected=True)]
        out=self.accept(v,exit_code=1);self.assertEqual(out["ticket_flag_observations"][0]["cache_flags"],0x00e10000)
        self.assertFalse(out["success"])
        v["ticket_flag_observations"][0]["secret"]="not allowed";self.reject(v,exit_code=1)

    def test_response_observations_are_closed_and_bounded(self):
        for field,bad in (("renew",1),("authenticator_usage",True),("authenticator_usage",8),
                          ("response","raw_ticket"),("error_code",True),("error_code",-1),("error_code",256),
                          ("stage","arbitrary_exception")):
            with self.subTest(field=field,bad=bad):
                v=fixture();v["renewal_evidence"]["response_observations"][0][field]=bad;self.reject(v)
        v=fixture();v["renewal_evidence"]["response_observations"][0]["secret"]="forbidden";self.reject(v)
        for bad in (None,{},[],fixture()["renewal_evidence"]["response_observations"]*5):
            v=fixture();v["renewal_evidence"]["response_observations"]=bad;self.reject(v)

    def test_response_progress_does_not_promote_failure(self):
        v=fixture();v.update(success=False,error="relay_invalid",stage="bounded_reconnect")
        v["checks"]["bounded_reconnect"]=False;v["diagnostic"]["category"]="assertion"
        response=v["renewal_evidence"]["response_observations"][0]
        response.update(response="krb_error",error_code=13,stage="expected_error")
        out=self.accept(v,exit_code=1)
        self.assertEqual(out["renewal_evidence"]["response_observations"][0]["error_code"],13)
        self.assertFalse(out["renewal_verified"])
        response["secret"]="forbidden";self.reject(v,exit_code=1)

    def test_success_requires_exact_completed_response_sequence(self):
        for case,variant in (("renewable","original"),("renewable","patched"),("nonrenewable","original"),("nonrenewable","patched")):
            for field,bad in (("renew",False if case=="renewable" else True),("authenticator_usage",11),
                              ("response","unclassified"),("error_code",12),("stage","reply_decrypt")):
                v=fixture(case,variant);response=v["renewal_evidence"]["response_observations"][-1]
                if response[field]==bad:continue
                response[field]=bad;self.reject(v,case,variant)
            if variant=="original" and case=="renewable":
                v=fixture(case,variant);v["renewal_evidence"]["response_observations"].reverse();self.reject(v,case,variant)

    def test_legacy_fixture_cannot_pass(self):
        self.reject(legacy_fixture())


if __name__ == "__main__": unittest.main()
