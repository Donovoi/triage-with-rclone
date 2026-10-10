"""Keep staged filesystem execution bound to checked artifacts and publication."""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]


class FilesystemWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        cls.job = cls.workflow.split("  windows-filesystem:\n", 1)[1].split("  windows-architectures:\n", 1)[0]

    def test_hosted_job_uses_only_same_run_checked_build(self):
        self.assertIn("    needs: test\n", self.job)
        self.assertIn("        backend: [local, archive]\n", self.job)
        self.assertIn("    runs-on: windows-latest\n", self.job)
        self.assertNotIn("continue-on-error", self.job)
        self.assertNotIn("run-id:", self.job)
        self.assertNotIn("repository:", self.job)
        self.assertIn("name: rclone-triage-windows\n", self.job)
        self.assertEqual(self.job.count("filesystem-build/rclone-triage/target/release/rclone-triage.exe"), 3)
        self.assertEqual(self.job.count("$env:GITHUB_SHA -cne $buildCommit"), 3)
        self.assertIn("$expectedPins -cne $artifactPins", self.job)

    def test_raw_receipt_never_enters_public_artifact(self):
        artifact = self.job.split("      - name: Retain only validated filesystem evidence\n", 1)[1]
        self.assertIn("path: ${{ runner.temp }}/filesystem-validation.json", artifact)
        self.assertNotIn("private.json", artifact)
        self.assertNotIn("*", artifact)
        self.assertIn("if-no-files-found: error", artifact)

    def test_independent_verifier_runs_after_either_native_outcome(self):
        verification = self.job.split("      - name: Independently validate staged filesystem evidence\n", 1)[1]
        for text in ("steps.filesystem_cases.outcome == 'success'", "steps.filesystem_cases.outcome == 'failure'",
                     "python -B scripts/filesystem_application_evidence.py", "--application $application",
                     "--build-commit $buildCommit", "--receipt", "--report"):
            self.assertIn(text, verification)
        self.assertNotRegex(self.job, r"--require-application(?:\s|$)")

    def test_ledger_requires_validated_receipt_and_verified_runtime_for_exact_mode(self):
        preparation = self.job.split("      - name: Prepare verified runtime for the filesystem coverage ledger\n", 1)[1]
        preparation = preparation.split("      - name: Require the same-build filesystem mode evidence\n", 1)[0]
        self.assertIn("steps.filesystem_validation.outcome == 'success'", preparation)
        self.assertIn("run: bash scripts/download-rclone.sh", preparation)
        ledger = self.job.split("      - name: Require the same-build filesystem mode evidence\n", 1)[1]
        ledger = ledger.split("      - name: Retain only validated filesystem evidence\n", 1)[0]
        for text in ("!cancelled()", "steps.filesystem_validation.outcome == 'success'",
                     "steps.filesystem_runtime.outcome == 'success'", "switch -CaseSensitive ($env:FILESYSTEM_BACKEND)",
                     "'local' { 'local:local_filesystem_cli_v1:windows' }",
                     "'archive' { 'archive:archive_zip_local_cli_v1:windows' }",
                     "default { throw 'filesystem_mode_unsupported' }", "--rclone $runtime",
                     "--application-receipt \"$env:RUNNER_TEMP/filesystem.private.json\"",
                     "--application $application --application-build-commit $buildCommit",
                     "--require-plans --require-application-mode $mode", "throw 'filesystem_coverage_failed'"):
            self.assertIn(text, ledger)
        self.assertNotIn("--require-complete", ledger)
        self.assertNotIn("continue-on-error", ledger)

    def test_ledger_artifact_is_separate_and_contains_only_the_sanitized_report(self):
        artifact = self.job.split("      - name: Retain sanitized filesystem coverage ledger\n", 1)[1]
        self.assertIn("steps.filesystem_coverage.outcome == 'success'", artifact)
        self.assertIn("steps.filesystem_coverage.outcome == 'failure'", artifact)
        self.assertIn("name: provider-evidence-Windows-filesystem-${{ matrix.backend }}", artifact)
        self.assertIn("path: ${{ runner.temp }}/provider-evidence-windows-filesystem.json", artifact)
        self.assertNotIn("private.json", artifact)
        self.assertNotIn("*", artifact)
        self.assertIn("if-no-files-found: error", artifact)

    def test_both_modes_gate_nightly_without_changing_architecture_builds(self):
        publication = self.workflow.split("    name: Publish Windows nightly\n", 1)[1]
        needs = re.search(r"^    needs: \[([^\]]+)\]$", publication, re.MULTILINE)
        self.assertIsNotNone(needs)
        names = [name.strip() for name in needs.group(1).split(",")]
        self.assertEqual(names.count("windows-filesystem"), 1)
        self.assertIn("windows-architectures", names)
        self.assertIn("test", names)


if __name__ == "__main__":
    unittest.main()
