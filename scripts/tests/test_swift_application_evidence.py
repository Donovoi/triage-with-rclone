"""Adversarial replay of synthetic receipts; no native application credit."""
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import socket
import subprocess
import threading
import types
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / "swift_application_evidence.py"
E = types.ModuleType("swift_evidence_test"); E.__file__ = str(PATH)
with patch.object(subprocess, "Popen", side_effect=AssertionError("forbidden")), patch.object(socket, "socket", side_effect=AssertionError("forbidden")):
    exec(compile(PATH.read_bytes(), str(PATH), "exec"), E.__dict__)
RUNTIME = dict(version="1.75.2", sha256="1" * 64, platform="windows")
BINDINGS = {key: "2" * 64 for key in E.A.BINDING_KEYS}
BINDINGS.update(build_commit="3" * 40, build_target="x86_64-pc-windows-msvc", build_profile="release")
NOW = datetime(2026, 10, 12, 12, tzinfo=timezone.utc)


def proof(phase):
    return dict(phase=phase, runtime_ordinal=2, runtime_sha256=RUNTIME["sha256"], application_live=True,
        runtime_live=True, same_process=phase == "verify", reference_closed=phase == "verify")


def fixture(name):
    rows = [("grant", "stat"), ("head", "stat"), ("grant", "copy_initial"), ("head", "copy_initial"),
        ("get_held", "copy_initial"), ("gate_released", "copy_initial"), ("storage_401", "copy_initial")]
    positive = name == "token_replacement"
    rows += ([("grant", "copy_replacement"), ("get_held", "copy_replacement"),
        ("gate_released", "copy_replacement"), ("content", "copy_replacement")] if positive else [("auth_held", "copy_initial"), ("gate_released", "copy_initial"), ("renewal_denied", "copy_initial")])
    events = [dict(ordinal=i + 1, kind=k, role=r, status={"grant": 200, "head": 200, "content": 200, "storage_401": 401,
        "renewal_denied": 403}.get(k, 0), object_bytes=62 if k == "content" else 0) for i, (k, r) in enumerate(rows)]
    return dict(case=name, requests=7 if positive else 6, payload_bytes=62 if positive else 0, response_bytes=2000,
        source_preserved=True, errors=[], events=events)


def receipt():
    cases = E.empty_cases()
    for name, r in cases.items():
        r.update(status="passed", exit_code=0 if name == "token_replacement" else 1, runtime_sha256=RUNTIME["sha256"],
            checks=dict.fromkeys(E.CHECKS[name], True), observation=dict(runtime_launch_count=2, peak_runtime_processes=1,
                system_helper_sha256="4" * 64, system_helper_launch_count=2, peak_system_helper_processes=1, debug_event_count=100),
            continuity={p: proof(p) for p in ("arm", "verify")}, fixture=fixture(name))
    return dict(schema_version=1, scope=E.SCOPE, fixture_mode=E.MODE, backend="swift", platform="windows", created_at="2026-10-12T12:00:00Z",
        runtime=deepcopy(RUNTIME), bindings=deepcopy(BINDINGS), cases=cases, experiment=dict(status="passed", failure_code=None,
        checks=dict.fromkeys(E.GROUP_CHECKS, True)), lifecycle_scope="injected_storage_401_reauthentication", claims=dict.fromkeys(E.FALSE_CLAIMS, False),
        cleanup_complete=True, errors=[], result="passed", capabilities=E.derive_capabilities(cases, True))


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        for obj, key in ((subprocess, "Popen"), (socket, "socket"), (socket, "create_connection"), (threading.Thread, "start")):
            p = patch.object(obj, key, side_effect=AssertionError("forbidden")); p.start(); self.addCleanup(p.stop)

    def validate(self, r): return E.validate_receipt(r, RUNTIME, BINDINGS, now=NOW)

    def reject(self, r):
        with self.assertRaises((E.A.ApplicationEvidenceError, TypeError, ValueError)): self.validate(r)

    def test_synthetic_positive_has_scoped_renewal_denial_no_provider_credit(self):
        r = receipt(); self.assertIs(self.validate(r), r)
        self.assertEqual(r["lifecycle_scope"], "injected_storage_401_reauthentication")
        self.assertTrue(all(v is False for v in r["claims"].values()))
        self.assertEqual(E.fixture_manifest()["size"], 62)

    def test_all_shapes_and_boolean_types_closed(self):
        r = receipt()
        for key in E.RECEIPT_KEYS:
            candidate = deepcopy(r); del candidate[key]; self.reject(candidate)
        for candidate in (dict(r, extra="canary"), dict(r, schema_version=True), dict(r, cleanup_complete=1), dict(r, lifecycle_scope="passed")):
            self.reject(candidate)
        for name in E.CASES:
            for key in E.RECORD_KEYS:
                candidate = deepcopy(r); del candidate["cases"][name][key]; self.reject(candidate)
            for key in E.CHECKS[name]:
                for value in (False, None, 1):
                    candidate = deepcopy(r); candidate["cases"][name]["checks"][key] = value; self.reject(candidate)

    def test_external_source_build_runtime_and_freshness(self):
        for key in BINDINGS:
            r = receipt(); r["bindings"][key] = "f" * 64; self.reject(r)
        for key, value in (("version", "1.75.1"), ("sha256", "e" * 64), ("platform", "linux")):
            r = receipt(); r["runtime"][key] = value; self.reject(r)
        for stamp in ("2020-01-01T00:00:00Z", "2026-10-12T12:06:00Z", "2026-99-99T00:00:00Z"):
            r = receipt(); r["created_at"] = stamp; self.reject(r)

    def test_every_retained_proof_field_is_necessary(self):
        for name in E.CASES:
            for phase in ("arm", "verify"):
                for key in E.PROOF_KEYS:
                    r = receipt(); del r["cases"][name]["continuity"][phase][key]; self.reject(r)
                for change in (dict(runtime_ordinal=1), dict(runtime_ordinal=True), dict(runtime_sha256="f"*64),
                        dict(runtime_live=False), dict(application_live=1), dict(reference_closed=phase != "verify"),
                        dict(same_process=phase != "verify"), dict(extra="canary")):
                    r = receipt(); r["cases"][name]["continuity"][phase].update(change); self.reject(r)
            r = receipt(); r["cases"][name]["continuity"] = None; self.reject(r)

    def test_events_replay_not_just_counts(self):
        for name in E.CASES:
            for key in ("requests", "payload_bytes", "response_bytes"):
                for value in (True, -1, 10**6):
                    r = receipt(); r["cases"][name]["fixture"][key] = value; self.reject(r)
            for changes in (dict(extra="token"), dict(ordinal=True), dict(ordinal=99), dict(role="copy_replacement"),
                    dict(status=True), dict(status=401), dict(object_bytes=1), dict(kind="unknown")):
                r = receipt(); r["cases"][name]["fixture"]["events"][0].update(changes); self.reject(r)
            r = receipt(); r["cases"][name]["fixture"]["events"].reverse(); self.reject(r)
            r = receipt(); r["cases"][name]["fixture"]["events"].pop(); self.reject(r)
            r = receipt(); r["cases"][name]["fixture"]["errors"] = ["cleanup_failed"]; self.reject(r)
            r = receipt(); r["cases"][name]["fixture"]["source_preserved"] = False; self.reject(r)
            r = receipt(); r["cases"][name]["fixture"]["events"] *= 4; self.reject(r)

    def test_native_exit_and_launch_observations_must_be_exact(self):
        for name in E.CASES:
            for value in (None, True, 2, 0 if name == "renewal_denial" else 1):
                r = receipt(); r["cases"][name]["exit_code"] = value; self.reject(r)
            for changes in (dict(runtime_launch_count=3), dict(runtime_launch_count=True), dict(peak_runtime_processes=2),
                    dict(system_helper_sha256=None), dict(debug_event_count=1), dict(extra=1)):
                r = receipt(); r["cases"][name]["observation"].update(changes); self.reject(r)

    def test_failure_downgrades_all_credit(self):
        r = receipt(); r["errors"] = ["preservation_failed"]; self.reject(r)
        r = receipt(); r["cleanup_complete"] = False; self.reject(r)
        for key in E.FALSE_CLAIMS:
            r = receipt(); r["claims"][key] = True; self.reject(r)
        r = receipt(); r["experiment"]["status"] = "failed"; r["experiment"]["failure_code"] = "group_failed"
        r["errors"] = ["group_failed"]; self.reject(r)
        for row in r["cases"].values():
            row.update(status="failed", failure_code="group_failed"); row["checks"]["group_finalized"] = False
        r["result"] = "failed"; r["capabilities"] = E.derive_capabilities(r["cases"], True)
        self.validate(r)

    def test_duplicate_json_and_private_error_values_rejected(self):
        with self.assertRaises(E.A.ApplicationEvidenceError): E.parse_receipt(b'{"x":1,"x":2}')
        r = receipt(); r["errors"] = ["private token canary"]; self.reject(r)
        r = receipt(); r["cases"]["token_replacement"]["fixture"]["errors"] = ["private token canary"]; self.reject(r)



def cancellation_receipt():
    rows=[("grant","stat"),("head","stat"),("grant","copy_initial"),("head","copy_initial")]
    rows += [(k,"copy_initial") for k in ("get_held","headers","chunk","prefix_released","chunk","cancel_armed","disconnected")]
    events=[dict(ordinal=i+1,kind=k,role=role,status=200 if k in {"grant","head","headers","chunk"} else 0,
        object_bytes=65536 if k=="chunk" else 0) for i,(k,role) in enumerate(rows)]
    case=dict(status="passed",exit_code=1,runtime_sha256=RUNTIME["sha256"],continuity=None,failure_code=None,
        observation=dict(kind="live_image",runtime_process_count=1,first_verified_bytes=65536,last_verified_bytes=131072),
        fixture=dict(case="cancellation",requests=5,payload_bytes=131072,response_bytes=132352,source_preserved=True,errors=[],events=events),
        checks=dict.fromkeys(E.CANCEL_CHECKS["cancellation"],True))
    return dict(schema_version=2,scope=E.SCOPE,fixture_mode=E.CANCEL_MODE,backend="swift",platform="windows",created_at="2026-10-12T12:00:00Z",
        runtime=deepcopy(RUNTIME),bindings=deepcopy(BINDINGS),cases={"cancellation":case},experiment=dict(status="passed",failure_code=None,
        checks=dict.fromkeys(E.GROUP_CHECKS,True)),lifecycle_scope="content_verified_incomplete_transfer",claims=dict.fromkeys(E.CANCEL_FALSE_CLAIMS,False),
        cleanup_complete=True,errors=[],result="passed",capabilities={"content_verified_cancellation":"passed","cleanup":"passed"})


class CancellationEvidenceTests(unittest.TestCase):
    def validate(self,r): return E.validate_cancellation_receipt(r,RUNTIME,BINDINGS,now=NOW)
    def reject(self,r):
        with self.assertRaises(E.A.ApplicationEvidenceError): self.validate(r)

    def test_independent_literal_mode_oracle_and_legacy_is_not_relabelled(self):
        self.assertIs(self.validate(cancellation_receipt())["cleanup_complete"],True)
        self.assertEqual(E.cancellation_manifest()["sha256"],"2312394bd99545d9de131c24efb781e765ac1aec243f2ed9347597a793a415e9")
        self.assertEqual(E.cancellation_manifest()["verified_prefixes"],[65536,131072])
        self.reject(receipt())
        with self.assertRaises(E.A.ApplicationEvidenceError): E.validate_receipt(cancellation_receipt(),RUNTIME,BINDINGS,now=NOW)
        self.assertFalse(receipt()["claims"]["cancellation_verified"])

    def test_all_required_flags_numbers_progress_and_no_retained_process_claim(self):
        for key in E.CANCEL_CHECKS["cancellation"]:
            for v in (False,None,1):
                r=cancellation_receipt();r["cases"]["cancellation"]["checks"][key]=v;self.reject(r)
        for key in ("runtime_process_count","first_verified_bytes","last_verified_bytes"):
            for v in (True,0,262144,"private canary"):
                r=cancellation_receipt();r["cases"]["cancellation"]["observation"][key]=v;self.reject(r)
        for key,v in (("exit_code",0),("exit_code",True),("continuity",{"arm":proof("arm")}), ("runtime_sha256","f"*64)):
            r=cancellation_receipt();r["cases"]["cancellation"][key]=v;self.reject(r)

    def test_fixture_events_exact_counts_no_tail_or_renewal_credit(self):
        for key,v in (("requests",6),("payload_bytes",262144),("source_preserved",False),("errors",["client_aborted"]),("response_bytes",True)):
            r=cancellation_receipt();r["cases"]["cancellation"]["fixture"][key]=v;self.reject(r)
        for mutation in ("reorder","extra","missing","wrong_role","wrong_kind","wrong_size"):
            r=cancellation_receipt();ev=r["cases"]["cancellation"]["fixture"]["events"]
            if mutation=="reorder":ev[6],ev[7]=ev[7],ev[6]
            elif mutation=="extra":ev.append(dict(ev[-1]))
            elif mutation=="missing":ev.pop()
            elif mutation=="wrong_role":ev[-1]["role"]="stat"
            elif mutation=="wrong_kind":ev[-1]["kind"]="private canary"
            else:ev[6]["object_bytes"]=True
            self.reject(r)
        r=cancellation_receipt();r["cases"]["cancellation"]["fixture"]["events"][-1]["kind"]="held_teardown";self.validate(r)

    def test_binding_age_group_cleanup_and_private_claims_fail_closed(self):
        for key in BINDINGS:
            r=cancellation_receipt();r["bindings"][key]="e"*64;self.reject(r)
        for key,v in (("fixture_mode",E.MODE),("schema_version",True),("created_at","2020-01-01T00:00:00Z"),("cleanup_complete",False)):
            r=cancellation_receipt();r[key]=v;self.reject(r)
        for key in E.GROUP_CHECKS:
            r=cancellation_receipt();r["experiment"]["checks"][key]=False;self.reject(r)
        for key in E.CANCEL_FALSE_CLAIMS:
            r=cancellation_receipt();r["claims"][key]=True;self.reject(r)
        r=cancellation_receipt();r["cases"]["cancellation"]["observation"]["path"]="private canary";self.reject(r)

    def test_failed_receipt_retains_partial_evidence_without_credit(self):
        r=cancellation_receipt();c=r["cases"]["cancellation"]
        c.update(status="failed",failure_code="cancellation_failed",exit_code=None,observation=None,runtime_sha256=None)
        c["checks"]=dict.fromkeys(E.CANCEL_CHECKS["cancellation"],False)
        r.update(errors=["cancellation_failed","cleanup_failed"],result="failed",cleanup_complete=False,
            capabilities={"content_verified_cancellation":"not_verified","cleanup":"not_verified"})
        r["experiment"].update(status="failed",failure_code="cancellation_failed",checks=dict.fromkeys(E.GROUP_CHECKS,False))
        self.validate(r)



def listing_receipt():
    pairs = [("auth_held", "listing"), ("gate_released", "listing"), ("grant", "listing"),
             ("account", "account"), ("container", "container"), ("head", "space"), ("head", "readme"), ("head", "empty")]
    events = [dict(ordinal=i+1, kind=k, role=r, status=0 if i < 2 else 200, object_bytes=0) for i,(k,r) in enumerate(pairs)]
    row = dict(status="passed", exit_code=0, runtime_sha256=RUNTIME["sha256"], continuity=None, failure_code=None,
        observation=dict(kind="live_image", runtime_process_count=1), checks=dict.fromkeys(E.LIST_CHECKS["listing"], True),
        fixture=dict(case="listing", requests=6, payload_bytes=0, response_bytes=1700, source_preserved=True, errors=[], events=events))
    return dict(schema_version=3, scope=E.SCOPE, fixture_mode=E.LIST_MODE, backend="swift", platform="windows",
        created_at="2026-10-12T12:00:00Z", runtime=deepcopy(RUNTIME), bindings=deepcopy(BINDINGS), cases={"listing":row},
        experiment=dict(status="passed", failure_code=None, checks=dict.fromkeys(E.GROUP_CHECKS, True)),
        lifecycle_scope="configured_account_root_listing", claims=dict.fromkeys(E.LIST_FALSE_CLAIMS, False),
        cleanup_complete=True, errors=[], result="passed", capabilities=E.listing_capabilities({"listing":row}, True))


class ListingEvidenceTests(unittest.TestCase):
    setUp = EvidenceTests.setUp

    def validate(self, value): return E.validate_listing_receipt(value, RUNTIME, BINDINGS, now=NOW)

    def reject(self, value):
        with self.assertRaises((E.A.ApplicationEvidenceError, TypeError, ValueError)): self.validate(value)

    def test_literal_inventory_and_success_scope(self):
        value = listing_receipt(); self.assertIs(self.validate(value), value)
        self.assertEqual(E.listing_rows(), [
            ["excel-safe-v1","Synthetic","synthetic-bucket","88","2000-01-01T00:00:00+00:00","true","",""],
            ["excel-safe-v1","Synthetic","synthetic-bucket/README-synthetic.txt","62","2024-01-01T00:00:00+00:00","false","",""],
            ["excel-safe-v1","Synthetic","synthetic-bucket/empty.txt","0","2024-01-01T00:00:00+00:00","false","",""],
            ["excel-safe-v1","Synthetic","synthetic-bucket/space name.txt","26","2024-01-01T00:00:00+00:00","false","",""]])
        self.assertTrue(all(v is False for v in value["claims"].values()))
        self.assertNotIn("download_hash", value["capabilities"])

    def test_every_check_shape_and_primitive_is_required(self):
        for key in E.RECEIPT_KEYS:
            v=listing_receipt(); del v[key]; self.reject(v)
        for key in E.LIST_CHECKS["listing"]:
            for bad in (False, None, 1):
                v=listing_receipt(); v["cases"]["listing"]["checks"][key]=bad; self.reject(v)
        for key in E.GROUP_CHECKS:
            v=listing_receipt(); v["experiment"]["checks"][key]=False; self.reject(v)
        for change in (dict(extra="private canary"),dict(schema_version=True),dict(cleanup_complete=1),dict(lifecycle_scope="acquisition")):
            self.reject(dict(listing_receipt(), **change))

    def test_ordered_complete_route_and_metadata_not_counts_alone(self):
        for action in ("omit_root", "duplicate_head", "missing_empty", "grant_after_listing", "private_role", "payload", "requests"):
            v=listing_receipt(); f=v["cases"]["listing"]["fixture"]; events=f["events"]
            if action == "omit_root": del events[3]
            elif action == "duplicate_head": events[-1]["role"]="readme"
            elif action == "missing_empty": events.pop()
            elif action == "grant_after_listing": events[2],events[3]=events[3],events[2]
            elif action == "private_role": events[-1]["role"]="private canary"
            elif action == "payload": f["payload_bytes"]=1
            else: f["requests"]=True
            for i,row in enumerate(events,1): row["ordinal"]=i
            self.reject(v)
        v=listing_receipt(); v["cases"]["listing"]["fixture"]["events"][5:] = list(reversed(v["cases"]["listing"]["fixture"]["events"][5:]))
        for i,row in enumerate(v["cases"]["listing"]["fixture"]["events"],1): row["ordinal"]=i
        self.validate(v)

    def test_runtime_bindings_age_observation_and_mixed_modes_rejected(self):
        for key in BINDINGS:
            v=listing_receipt(); v["bindings"][key]="f"*64; self.reject(v)
        for key in RUNTIME:
            v=listing_receipt(); v["runtime"][key]="wrong"; self.reject(v)
        for stamp in ("2020-01-01T00:00:00Z", "2026-10-12T12:06:00Z"):
            v=listing_receipt(); v["created_at"]=stamp; self.reject(v)
        for change in (dict(kind="launch_image"), dict(runtime_process_count=True), dict(runtime_process_count=2), dict(path="private canary")):
            v=listing_receipt(); v["cases"]["listing"]["observation"].update(change); self.reject(v)
        for old in (receipt(), cancellation_receipt()): self.reject(old)
        for validate in (E.validate_receipt,E.validate_cancellation_receipt):
            with self.assertRaises(E.A.ApplicationEvidenceError): validate(listing_receipt(),RUNTIME,BINDINGS,now=NOW)

    def test_not_run_and_failed_cleanup_cannot_be_promoted(self):
        v=listing_receipt(); row=v["cases"]["listing"]
        row.update(status="failed", failure_code="cleanup_failed"); row["checks"]["group_finalized"]=False; row["checks"]["temp_cleanup"]=False
        v.update(result="failed", cleanup_complete=False, errors=["cleanup_failed"], capabilities=E.listing_capabilities(v["cases"],False))
        v["experiment"].update(status="failed",failure_code="cleanup_failed"); v["experiment"]["checks"]["temp_cleanup"]=False
        self.validate(v)
        v["result"]="passed"; self.reject(v)
        v=listing_receipt(); v["cases"]["listing"] = dict.fromkeys(E.RECORD_KEYS,None)
        v["cases"]["listing"].update(status="not_run",checks=dict.fromkeys(E.LIST_CHECKS["listing"],None))
        v["experiment"]=E.empty_group(); v.update(result="failed",errors=["binding_failed"],capabilities=E.listing_capabilities(v["cases"],True))
        self.validate(v)

    def test_explicit_validator_cli_modes_are_exclusive(self):
        with patch.object(E,"read_bounded") as read:
            with self.assertRaises(SystemExit) as error:
                E.main(["--receipt","unused","--application","unused","--build-commit","unused","--report","unused","--listing-only","--cancellation-only"])
            self.assertEqual(error.exception.code,2); read.assert_not_called()


if __name__ == "__main__": unittest.main()
