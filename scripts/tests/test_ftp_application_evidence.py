"""Synthetic receipt validation only; no application/provider acceptance."""
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import socket
import subprocess
import types
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / "ftp_application_evidence.py"
E = types.ModuleType("ftp_evidence_test")
E.__file__ = str(PATH)
with patch.object(subprocess, "Popen", side_effect=AssertionError("native_forbidden")), patch.object(socket, "socket", side_effect=AssertionError("socket_forbidden")):
    exec(compile(PATH.read_bytes(), str(PATH), "exec"), E.__dict__)
RUNTIME = dict(version="1.75.2", sha256="1" * 64, platform="windows")
BINDINGS = {key: "2" * 64 for key in E.A.BINDING_KEYS}
BINDINGS.update(build_commit="3" * 40, build_target="x86_64-pc-windows-msvc", build_profile="release")
NOW = datetime(2026, 10, 12, 12, tzinfo=timezone.utc)


def proof(phase):
    return dict(phase=phase, runtime_ordinal=2, runtime_sha256=RUNTIME["sha256"], application_live=True,
                runtime_live=True, same_process=phase == "verify", reference_closed=phase == "verify")


def receipt():
    cases = E.empty_cases()
    for name, row in cases.items():
        n = E.EXPECTED_LAUNCHES[name]
        row.update(status="passed", exit_code=1 if name == "revoked_a" else 0, runtime_sha256=RUNTIME["sha256"],
            checks=dict.fromkeys(E.CHECKS[name], True), observation=dict(runtime_launch_count=n, peak_runtime_processes=1,
            system_helper_sha256="4" * 64, system_helper_launch_count=n, peak_system_helper_processes=1, debug_event_count=100))
    cases["accepted_a"]["continuity"] = {p: proof(p) for p in ("arm", "verify")}
    return dict(schema_version=1, scope=E.SCOPE, fixture_mode=E.MODE, backend="ftp", platform="windows", created_at="2026-10-12T12:00:00Z",
        runtime=deepcopy(RUNTIME), bindings=deepcopy(BINDINGS), cases=cases,
        credential_group=dict(status="passed", failure_code=None, checks=dict.fromkeys(E.GROUP_CHECKS, True)),
        claims=dict.fromkeys(E.FALSE_CLAIMS, False), cleanup_complete=True, errors=[], result="passed",
        capabilities=E.derive_capabilities(cases, True))


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        for obj, name in ((subprocess, "Popen"), (socket, "socket"), (socket, "create_connection")):
            p = patch.object(obj, name, side_effect=AssertionError("native_forbidden")); p.start(); self.addCleanup(p.stop)

    def validate(self, value):
        return E.validate_receipt(value, RUNTIME, BINDINGS, now=NOW)

    def reject(self, value):
        with self.assertRaises((E.A.ApplicationEvidenceError, TypeError, ValueError)):
            self.validate(value)

    def test_exact_synthetic_pass_has_no_completion_claims(self):
        value = receipt()
        self.assertIs(self.validate(value), value)
        self.assertTrue(all(v is False for v in value["claims"].values()))
        self.assertEqual(E.fixture_manifest()["sha256"], "91d3beb88a9b2f778a6c44a1c53b63d3c79931845a9aef84b3fb414610bd1938")

    def test_direct_retained_identity_proof_cannot_be_replaced_by_counts(self):
        for candidate in (None, {}, {"arm": proof("arm")}, {"verify": proof("verify")},
                          {"arm": proof("arm"), "verify": dict(proof("verify"), same_process=False)}):
            r = receipt(); r["cases"]["accepted_a"]["continuity"] = candidate; self.reject(r)
        for name in ("revoked_a", "replacement_b"):
            r = receipt(); r["cases"][name]["continuity"] = deepcopy(r["cases"]["accepted_a"]["continuity"]); self.reject(r)

    def test_every_proof_field_closed_and_typed(self):
        for phase in ("arm", "verify"):
            for key in E.PROOF_KEYS:
                r = receipt(); del r["cases"]["accepted_a"]["continuity"][phase][key]; self.reject(r)
            for changes in (dict(runtime_ordinal=True), dict(runtime_ordinal=1), dict(runtime_sha256="f" * 64),
                            dict(application_live=1), dict(runtime_live=False), dict(reference_closed=phase != "verify"),
                            dict(extra="private-canary"), dict(phase=phase + "\0")):
                r = receipt(); r["cases"]["accepted_a"]["continuity"][phase].update(changes); self.reject(r)

    def test_source_runtime_build_and_freshness_are_external(self):
        for key in BINDINGS:
            r = receipt(); r["bindings"][key] = "f" * 64; self.reject(r)
        for changes in (dict(sha256="f" * 64), dict(version="1.75.1"), dict(platform="linux"), dict(extra="canary")):
            r = receipt(); r["runtime"].update(changes); self.reject(r)
        for time in ("2020-01-01T00:00:00Z", "2026-10-12T12:06:00Z", "2026-99-99T00:00:00Z", "2026-10-12T12:00:00+00:00"):
            r = receipt(); r["created_at"] = time; self.reject(r)

    def test_unknown_private_keys_and_all_claims_refused(self):
        for r in (dict(receipt(), private="canary"), dict(receipt(), schema_version=True), dict(receipt(), fixture_mode="future")):
            self.reject(r)
        for key in E.FALSE_CLAIMS:
            r = receipt(); r["claims"][key] = True; self.reject(r)
        for name in E.CASES:
            r = receipt(); r["cases"][name]["private"] = "canary"; self.reject(r)
            for key in E.CHECKS[name]:
                r = receipt(); r["cases"][name]["checks"][key] = False; self.reject(r)

    def test_exact_launch_limits_exit_and_cleanup_not_generic_success(self):
        for name in E.CASES:
            for changes in (dict(runtime_launch_count=True), dict(runtime_launch_count=3), dict(peak_runtime_processes=2),
                dict(system_helper_launch_count=3), dict(system_helper_sha256=None), dict(debug_event_count=1), dict(extra=0)):
                r = receipt(); r["cases"][name]["observation"].update(changes); self.reject(r)
            r = receipt(); r["cases"][name]["exit_code"] = 0 if name == "revoked_a" else 1; self.reject(r)
        r = receipt(); r["cleanup_complete"] = False; self.reject(r)
        for key in E.GROUP_CHECKS:
            r = receipt(); r["credential_group"]["checks"][key] = False; self.reject(r)

    def test_failed_group_retains_facts_but_no_case_credit(self):
        r = receipt(); r.update(result="failed", errors=["cleanup_failed"], cleanup_complete=False)
        r["credential_group"].update(status="failed", failure_code="cleanup_failed")
        r["credential_group"]["checks"]["temp_cleanup"] = False
        for row in r["cases"].values():
            row.update(status="failed", failure_code="cleanup_failed")
            row["checks"].update(group_finalized=False, temp_cleanup=False)
        r["capabilities"] = E.derive_capabilities(r["cases"], False)
        self.validate(r)
        r["cases"]["accepted_a"]["status"] = "passed"; self.reject(r)

    def test_global_failure_cannot_retain_passed_group_or_capabilities(self):
        r = receipt()
        r.update(errors=["preservation_failed"], result="failed")
        self.assertTrue(all(value == "passed" for value in r["capabilities"].values()))
        self.reject(r)

    def test_all_not_run_failure_is_honest_and_duplicate_json_rejected(self):
        r = receipt(); r.update(cases=E.empty_cases(), credential_group=E.empty_group(), errors=["binding_failed"], result="failed")
        r["capabilities"] = E.derive_capabilities(r["cases"], True)
        self.validate(r)
        with self.assertRaises(E.A.ApplicationEvidenceError):
            E.parse_receipt(b'{"schema_version":1,"schema_version":1}')


if __name__ == "__main__":
    unittest.main()
