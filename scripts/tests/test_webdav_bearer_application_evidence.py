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

PATH = Path(__file__).resolve().parents[1] / "webdav_bearer_application_evidence.py"
E = types.ModuleType("webdav_bearer_evidence_test"); E.__file__ = str(PATH)
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
    positive = name == "accepted_token"
    kinds = ("metadata", "metadata", "get_held", "gate_released", "content" if positive else "bearer_denied")
    events = [dict(ordinal=i + 1, kind=k, status={"metadata": 207, "content": 200, "bearer_denied": 401}.get(k, 0),
                   object_bytes=30 if k == "content" else 0) for i, k in enumerate(kinds)]
    return dict(case=name, requests=3, payload_bytes=30 if positive else 0, response_bytes=1500,
                source_preserved=True, errors=[], events=events)


def receipt():
    cases = E.empty_cases()
    for name, r in cases.items():
        r.update(status="passed", exit_code=0 if name == "accepted_token" else 1, runtime_sha256=RUNTIME["sha256"],
            checks=dict.fromkeys(E.CHECKS[name], True), observation=dict(runtime_launch_count=2, peak_runtime_processes=1,
                system_helper_sha256="4" * 64, system_helper_launch_count=2, peak_system_helper_processes=1, debug_event_count=100),
            continuity={p: proof(p) for p in ("arm", "verify")}, fixture=fixture(name))
    return dict(schema_version=1, scope=E.SCOPE, fixture_mode=E.MODE, backend="webdav", platform="windows", created_at="2026-10-12T12:00:00Z",
        runtime=deepcopy(RUNTIME), bindings=deepcopy(BINDINGS), cases=cases, experiment=dict(status="passed", failure_code=None,
        checks=dict.fromkeys(E.GROUP_CHECKS, True)), lifecycle_scope="injected_fixed_bearer_401_no_renewal", claims=dict.fromkeys(E.FALSE_CLAIMS, False),
        cleanup_complete=True, errors=[], result="passed", capabilities=E.derive_capabilities(cases, True))


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        for obj, key in ((subprocess, "Popen"), (socket, "socket"), (socket, "create_connection"), (threading.Thread, "start")):
            p = patch.object(obj, key, side_effect=AssertionError("forbidden")); p.start(); self.addCleanup(p.stop)

    def validate(self, r): return E.validate_receipt(r, RUNTIME, BINDINGS, now=NOW)

    def reject(self, r):
        with self.assertRaises((E.A.ApplicationEvidenceError, TypeError, ValueError)): self.validate(r)

    def test_fixed_bearer_positive_is_partial_and_has_no_renewal_credit(self):
        r = receipt(); self.assertIs(self.validate(r), r)
        self.assertEqual(r["lifecycle_scope"], "injected_fixed_bearer_401_no_renewal")
        self.assertTrue(all(v is False for v in r["claims"].values()))
        self.assertEqual(E.fixture_manifest()["size"], 30)

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
            for value in (None, True, 2, 0 if name == "invalidated_token" else 1):
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
        r = receipt(); r["cases"]["accepted_token"]["fixture"]["errors"] = ["private token canary"]; self.reject(r)


if __name__ == "__main__": unittest.main()
