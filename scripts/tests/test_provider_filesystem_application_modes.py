"""Pure receipt-to-ledger regressions; mocks establish no application acceptance."""
from copy import deepcopy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

with patch("subprocess.Popen", side_effect=AssertionError("native_forbidden")), \
        patch("socket.socket", side_effect=AssertionError("socket_forbidden")), \
        patch("socket.create_connection", side_effect=AssertionError("network_forbidden")):
    from test_filesystem_application_evidence import E, BINDINGS, NOW, RUNTIME, receipt as filesystem_receipt
    from test_provider_application_modes import HTTP, DAV, CAPS, FixedDatetime, receipt as legacy_receipt
    from test_provider_coverage import coverage as C, policy_for, schema


LOCAL = ("local", "local_filesystem_cli_v1", "windows")
ARCHIVE = ("archive", "archive_zip_local_cli_v1", "windows")
FILESYSTEM = (LOCAL, ARCHIVE)
ALL_MODES = (HTTP, DAV, LOCAL, ARCHIVE)
FILESYSTEM_BINDINGS = {**BINDINGS, "harness_sha256": "5" * 64, "fixture_manifest_sha256": "6" * 64}


def receipt(key, complete=True):
    if key in FILESYSTEM:
        value = filesystem_receipt(key[0], complete=complete)
        value["bindings"] = dict(FILESYSTEM_BINDINGS)
        return value
    return legacy_receipt(key)


class FilesystemApplicationModeTests(unittest.TestCase):
    def setUp(self):
        for target in ("subprocess.Popen", "socket.socket", "socket.create_connection"):
            boundary = patch(target, side_effect=AssertionError("native_boundary_forbidden"))
            boundary.start()
            self.addCleanup(boundary.stop)
        self.catalog = C.catalog_from_schemas([schema(key[0]) for key in ALL_MODES])
        self.policy = policy_for(self.catalog, application=False, vendor=False)
        self.policy["reviewed_runtime_version"] = RUNTIME["version"]
        self.policy["profiles"]["test"]["required"]["application"] = sorted(CAPS)
        # Both filesystem modes intentionally share one current source/build
        # closure. Their distinct case grammars, not invented hashes, bind mode.
        self.bindings = {key: deepcopy(receipt(key)["bindings"]) for key in ALL_MODES}

    def evaluate(self, values, **kwargs):
        options = dict(now=NOW, application_receipts=values, application_bindings=deepcopy(self.bindings))
        options.update(kwargs)
        return C.evaluate(self.catalog, self.policy, RUNTIME, [], None, **options)

    def row(self, report, key):
        return next(row for row in report["providers"] if row["backend"] == key[0])

    def app(self, report, key):
        return self.row(report, key)["evidence"]["application"]

    def assert_rejected(self, value, key, **kwargs):
        report = self.evaluate([value], **kwargs)
        self.assertTrue(report["errors"], report)
        self.assertNotIn("modes", self.app(report, key))
        self.assertIn("required_application_mode_not_verified",
                      C.gate_errors(report, require_application_modes=[key]))
        self.assertFalse(self.row(report, key)["complete"])
        return report

    def test_finite_filesystem_entries_have_no_completion_right(self):
        for key in FILESYSTEM:
            self.assertEqual(dict(C.APPLICATION_REGISTRY[key]), {
                "module": "filesystem_application_evidence.py",
                "producer": "application-lab/run_windows_filesystem.py", "can_complete_application": False})
            with self.assertRaises(TypeError):
                C.APPLICATION_REGISTRY[key]["can_complete_application"] = True
            helper = C.application_module(key=key)
            self.assertEqual(helper.MODE[key[0]], key[1])
            self.assertIs(helper.validate_receipt(receipt(key), RUNTIME, FILESYSTEM_BINDINGS, now=NOW)["claims"]["provider_accepted"], False)

    def test_complete_modes_mix_with_unchanged_http_and_webdav_in_all_rotations(self):
        orders = [ALL_MODES[offset:] + ALL_MODES[:offset] for offset in range(len(ALL_MODES))]
        orders.append(tuple(reversed(ALL_MODES)))
        for order in orders:
            with self.subTest(order=order):
                report = self.evaluate([receipt(key) for key in order])
                self.assertEqual(report["errors"], [])
                self.assertEqual(C.gate_errors(report, require_application_modes=ALL_MODES), [])
                for key in ALL_MODES:
                    app = self.app(report, key)
                    self.assertEqual(app["modes"][key[1]]["capabilities"], dict.fromkeys(CAPS, "passed"))
                    self.assertEqual(app["modes"][key[1]]["status"], "passed")
                    self.assertEqual(app["runs"][0]["bindings"], self.bindings[key])
                    self.assertEqual(app["status"], "passed" if key == HTTP else "not_verified")
                self.assertEqual(C.gate_errors(report, require_application=["http"]), [])
                for key in FILESYSTEM:
                    self.assertEqual(C.gate_errors(report, require_application=[key[0]]), ["required_application_not_verified"])
                    self.assertFalse(self.row(report, key)["complete"])
                self.assertFalse(report["all_complete"])

    def test_flat_http_binding_and_swapped_other_mode_bindings_cannot_qualify_filesystem(self):
        for key in FILESYSTEM:
            forged = receipt(key)
            forged["bindings"] = deepcopy(self.bindings[HTTP])
            self.assert_rejected(forged, key, application_bindings=self.bindings[HTTP])
            for other in (HTTP, DAV):
                swapped = deepcopy(self.bindings)
                swapped[key], swapped[other] = swapped[other], swapped[key]
                self.assert_rejected(receipt(key), key, application_bindings=swapped)
            missing = deepcopy(self.bindings)
            del missing[key]
            self.assert_rejected(receipt(key), key, application_bindings=missing)

    def test_same_source_bindings_do_not_permit_local_archive_receipt_relabeling(self):
        self.assertEqual(self.bindings[LOCAL], self.bindings[ARCHIVE])
        for source, target in ((LOCAL, ARCHIVE), (ARCHIVE, LOCAL)):
            candidate = receipt(source)
            candidate.update(backend=target[0], fixture_mode=target[1])
            report = self.assert_rejected(candidate, target)
            self.assertIn("filesystem_cases_invalid", report["errors"])

    def test_runtime_source_binary_commit_and_freshness_are_external_requirements(self):
        for key in FILESYSTEM:
            for field in BINDINGS:
                value = receipt(key)
                value["bindings"][field] = "0" * (40 if field == "build_commit" else 64) if field.endswith("sha256") or field == "build_commit" else "other"
                self.assert_rejected(value, key)
            for created in ("2026-10-08T23:59:59Z", "2026-10-10T00:05:01Z"):
                value = receipt(key)
                value["created_at"] = created
                self.assert_rejected(value, key)
            for field, changed in (("sha256", "0" * 64), ("version", "1.75.1"), ("platform", "linux")):
                value = receipt(key)
                value["runtime"][field] = changed
                self.assert_rejected(value, key)

    def test_old_schema_unknown_mode_platform_and_wrapper_are_not_upgraded(self):
        for key in FILESYSTEM:
            value = receipt(key)
            value["schema_version"] = 1
            self.assert_rejected(value, key)
            for field, changed in (("fixture_mode", "remote_archive_cli_v1"), ("platform", "linux"),
                                   ("backend", "../PRIVATE_CANARY"), ("fixture_mode", [key[1]])):
                value = receipt(key)
                value[field] = changed
                with patch.object(C, "application_module", side_effect=AssertionError("unknown_import")):
                    report = self.assert_rejected(value, key)
                self.assertNotIn("PRIVATE_CANARY", json.dumps(report))
            wrapped = dict(schema_version=1, validated=True, receipt_sha256="0" * 64, receipt=receipt(key))
            self.assert_rejected(wrapped, key)

    def test_partial_not_run_cancellation_is_failed_mode_and_cannot_be_forged_passed(self):
        for key in FILESYSTEM:
            value = receipt(key, complete=False)
            report = self.evaluate([value])
            self.assertEqual(report["errors"], [])
            app = self.app(report, key)
            self.assertEqual(app["status"], "failed")
            self.assertEqual(app["modes"][key[1]]["status"], "failed")
            self.assertEqual(app["modes"][key[1]]["capabilities"]["cancellation"], "unverified")
            self.assertTrue(C.gate_errors(report, require_application_modes=[key]))
            value["result"] = "passed"
            self.assert_rejected(value, key)

    def test_cleanup_failure_invalidates_every_mode_capability_and_cancel_claim(self):
        for key in FILESYSTEM:
            value = receipt(key)
            value.update(result="failed", cleanup_complete=False, errors=["cleanup_failed"])
            value["claims"]["cancellation_verified"] = False
            value["capabilities"] = E.derive_capabilities(key[0], value["cases"], False)
            report = self.evaluate([value])
            self.assertEqual(report["errors"], [])
            mode = self.app(report, key)["modes"][key[1]]
            self.assertEqual(mode["status"], "failed")
            self.assertEqual(mode["capabilities"], dict.fromkeys(CAPS, "unverified"))
            self.assertTrue(C.gate_errors(report, require_application_modes=[key]))
            value["claims"]["cancellation_verified"] = True
            self.assert_rejected(value, key)

    def test_failure_and_partial_stay_sticky_in_both_orders_without_poisoning_other_modes(self):
        for key in FILESYSTEM:
            failure = receipt(key)
            failure.update(result="failed", errors=["session_failed"])
            for failed in (failure, receipt(key, complete=False)):
                for pair in ([failed, receipt(key)], [receipt(key), failed]):
                    values = pair + [receipt(other) for other in ALL_MODES if other != key]
                    report = self.evaluate(values)
                    self.assertEqual(report["errors"], [])
                    app = self.app(report, key)
                    self.assertEqual(app["status"], "failed")
                    self.assertEqual(app["modes"][key[1]]["status"], "failed")
                    self.assertEqual(len(app["runs"]), 2)
                    self.assertTrue(C.gate_errors(report, require_application_modes=[key]))
                    for other in ALL_MODES:
                        if other != key:
                            self.assertEqual(C.gate_errors(report, require_application_modes=[other]), [])

    def test_weakened_policy_cannot_promote_application_provider_or_other_tiers(self):
        for required in (sorted(CAPS), ["cleanup"]):
            self.policy["profiles"]["test"]["required"]["application"] = required
            report = self.evaluate([receipt(key) for key in FILESYSTEM])
            for key in FILESYSTEM:
                row = self.row(report, key)
                self.assertEqual(C.gate_errors(report, require_application_modes=[key]), [])
                self.assertEqual(row["evidence"]["application"]["status"], "not_verified")
                self.assertEqual(row["evidence"]["local_protocol"]["status"], "not_verified")
                self.assertFalse(row["complete"])
            self.assertFalse(report["all_complete"])
        self.policy = policy_for(self.catalog, application=True, vendor=True)
        self.policy["reviewed_runtime_version"] = RUNTIME["version"]
        report = self.evaluate([receipt(key) for key in FILESYSTEM])
        for key in FILESYSTEM:
            self.assertEqual(self.app(report, key)["capabilities"]["authentication"], "not_verified")
            self.assertEqual(self.app(report, key)["capabilities"]["refresh"], "not_verified")
            self.assertEqual(self.row(report, key)["evidence"]["vendor"]["status"], "not_verified")

    def test_full_filesystem_contract_required_even_under_cleanup_only_policy(self):
        self.policy["profiles"]["test"]["required"]["application"] = ["cleanup"]
        for key in FILESYSTEM:
            for mutation in ("acquisition", "cancel", "progress", "cleanup", "overclaim"):
                candidate = receipt(key)
                if mutation == "acquisition":
                    del candidate["cases"]["acquisition_unicode"]
                elif mutation == "cancel":
                    del candidate["cases"]["cancellation"]
                elif mutation == "progress":
                    candidate["cases"]["cancellation"]["checks"]["content_progress_exact"] = False
                elif mutation == "cleanup":
                    candidate["cases"]["listing"]["checks"]["temp_cleanup"] = False
                else:
                    candidate["claims"]["full_application_accepted"] = True
                self.assert_rejected(candidate, key)
        for name, check in (("acquisition_empty", "archive_crc32"), ("corrupt_member", "corruption_failure_exact"),
                            ("truncated_archive", "archive_failure_exact")):
            candidate = receipt(ARCHIVE)
            candidate["cases"][name]["checks"][check] = False
            self.assert_rejected(candidate, ARCHIVE)

    def test_invalid_helper_receipt_is_caught_without_erasing_other_backend(self):
        for key in FILESYSTEM:
            candidate = receipt(key)
            candidate["PRIVATE_CANARY"] = "PRIVATE_CANARY"
            for values in ([candidate, receipt(HTTP)], [receipt(HTTP), candidate]):
                report = self.evaluate(values)
                self.assertIn("filesystem_receipt_fields", report["errors"])
                self.assertNotIn("PRIVATE_CANARY", json.dumps(report))
                self.assertEqual(C.gate_errors(report, require_application=["http"]), ["filesystem_receipt_fields"])
                self.assertEqual(self.app(report, HTTP)["status"], "passed")
                self.assertNotIn("modes", self.app(report, key))

    def test_mode_gate_requires_current_policy_and_exact_closed_triplet(self):
        self.assertEqual(C.parse_required_application_modes([":".join(key) for key in FILESYSTEM]), sorted(FILESYSTEM))
        for text in ("local", "local:local_filesystem_cli_v1:linux", "archive:remote_archive_cli_v1:windows",
                     ":".join(LOCAL) + ":extra", ":".join(ARCHIVE) + " "):
            with self.assertRaises(C.CoverageError):
                C.parse_required_application_modes([text])
        original = deepcopy(self.policy)
        for mutation in ("runtime", "schema", "review"):
            self.policy = deepcopy(original)
            if mutation == "runtime":
                self.policy["reviewed_runtime_version"] = "1.75.1"
            elif mutation == "schema":
                self.policy["providers"]["local"]["schema_sha256"] = "0" * 64
            else:
                self.policy["profiles"]["test"]["review_required"] = True
            report = self.evaluate([receipt(LOCAL)])
            self.assertTrue(C.gate_errors(report, require_application_modes=[LOCAL]))

    def test_binding_dispatch_uses_fixed_helper_without_importing_producer(self):
        for key in FILESYSTEM:
            helper = SimpleNamespace(compute_bindings=Mock(return_value=dict(BINDINGS)))
            with patch.object(C, "application_module", return_value=helper) as load:
                self.assertEqual(C.compute_application_bindings(Path("never-executed.exe"), "d" * 40, key=key), BINDINGS)
            load.assert_called_once_with(key=key)
            helper.compute_bindings.assert_called_once_with(C.ROOT, Path("never-executed.exe"), "d" * 40)

    def test_cli_revalidates_raw_receipts_and_refuses_full_application_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy, output = root / "policy.json", root / "report.json"
            policy.write_text(json.dumps(self.policy), encoding="utf-8")
            args = ["--rclone", str(root / "never-executed"), "--policy", str(policy), "--report", str(output),
                    "--application", str(root / "never-executed.exe"), "--application-build-commit", "d" * 40]
            for key in FILESYSTEM:
                path = root / (key[0] + ".json")
                path.write_text(json.dumps(receipt(key)), encoding="utf-8")
                args += ["--application-receipt", str(path), "--require-application-mode", ":".join(key)]
            def compute(application, commit, *, key):
                self.assertEqual((application, commit), (root / "never-executed.exe", "d" * 40))
                return deepcopy(self.bindings[key])
            with patch.object(C, "query_runtime", return_value=(RUNTIME, self.catalog)), \
                    patch.object(C, "compute_application_bindings", side_effect=compute) as binding, \
                    patch.object(C, "datetime", FixedDatetime), redirect_stdout(io.StringIO()):
                self.assertEqual(C.main(args), 0)
                self.assertEqual({call.kwargs["key"] for call in binding.call_args_list}, set(FILESYSTEM))
                result = json.loads(output.read_text())
                self.assertFalse(result["all_complete"])
                output.unlink()
                self.assertEqual(C.main(args + ["--require-application", "local", "--require-application", "archive"]), 1)
                self.assertEqual(json.loads(output.read_text())["gate_errors"], ["required_application_not_verified"])


if __name__ == "__main__":
    unittest.main()
