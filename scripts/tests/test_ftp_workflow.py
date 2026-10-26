"""Pure source obligations for isolated FTP CI; no native acceptance credit."""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]


class FtpWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        cls.job = cls.workflow.split("  windows-ftp:\n", 1)[1].split("  windows-b2:\n", 1)[0]
        cls.steps = re.split(r"(?m)^      - ", cls.job)[1:]
        cls.producer = next(step for step in cls.steps if "        id: ftp_cases\n" in step)
        cls.validator = next(step for step in cls.steps if "        id: ftp_validation\n" in step)
        cls.upload = cls.steps[-1]

    def test_hosted_job_is_required_and_bounded_without_permission_expansion(self):
        self.assertIn("    needs: test\n", self.job)
        self.assertIn("    runs-on: windows-latest\n", self.job)
        self.assertIn("    timeout-minutes: 25\n", self.job)
        self.assertEqual(len(self.steps), 7)
        self.assertIn("persist-credentials: false", self.steps[0])
        self.assertIn("python-version: '3.12'", self.steps[1])
        for forbidden in ("continue-on-error", "secrets.", "permissions:", "strategy:", "matrix:",
                          "download-rclone", "pip install", "--require-application", "provider_coverage.py"):
            self.assertNotIn(forbidden, self.job)
        self.assertIn("timeout-minutes: 12", self.producer)
        self.assertIn("timeout-minutes: 3", self.validator)

    def test_downloads_use_only_same_run_fixed_artifacts_and_pinned_actions(self):
        downloads = [step for step in self.steps if step.startswith("uses: actions/download-artifact@")]
        self.assertEqual(len(downloads), 2)
        for step, name, folder in zip(downloads, ("rclone-triage-windows", "rclone-runtime-windows"), ("ftp-build", "ftp-runtime")):
            self.assertIn("actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c", step)
            self.assertIn(f"name: {name}\n", step)
            self.assertIn("path: ${{ runner.temp }}/" + folder + "\n", step)
            self.assertIn("timeout-minutes: 2", step)
            for forbidden in ("run-id:", "repository:", "github-token:", "pattern:", "merge-multiple:"):
                self.assertNotIn(forbidden, step)
        for step in self.steps:
            if step.startswith("uses:") or "        uses:" in step:
                self.assertRegex(step, r"uses: actions/[a-z-]+@[0-9a-f]{40}(?: |\n)")

    def test_runtime_upload_is_success_only_and_keeps_checked_app_shape(self):
        test_job = self.workflow.split("  test:\n", 1)[1].split("  windows-ftp:\n", 1)[0]
        upload = test_job.split("      - name: Upload checked Windows runtime for isolated application tests\n", 1)[1]
        self.assertIn("        if: runner.os == 'Windows'\n", upload)
        self.assertNotIn("always()", upload)
        self.assertEqual(re.findall(r"^            (.+)$", upload, re.MULTILINE),
                         ["rclone-triage/assets/rclone.exe", "rclone-version.env"])
        self.assertIn("name: rclone-runtime-windows\n", upload)
        self.assertIn("if-no-files-found: error", upload)
        self.assertIn("retention-days: 14", upload)
        app = test_job.split("      - name: Upload checked Windows build\n", 1)[1].split("      - name:", 1)[0]
        self.assertEqual(re.findall(r"^            (.+)$", app, re.MULTILINE),
                         ["rclone-triage/target/release/rclone-triage.exe", "rclone-triage/target/release/dependencies.json", "rclone-version.env"])

    def test_both_commands_independently_check_exact_build_manifest_and_images(self):
        for step in (self.producer, self.validator):
            with self.subTest(step=step.splitlines()[0]):
                self.assertIn("shell: pwsh", step)
                self.assertIn("$env:GITHUB_ACTIONS -cne 'true'", step)
                self.assertIn("$env:RUNNER_ENVIRONMENT -cne 'github-hosted'", step)
                self.assertEqual(step.count("$env:GITHUB_SHA -cne $buildCommit"), 1)
                self.assertIn("$buildCommit -cnotmatch '^[0-9a-f]{40}$'", step)
                self.assertIn("git rev-parse --verify HEAD", step)
                self.assertEqual(step.count("ftp-build/rclone-triage/target/release/rclone-triage.exe"), 1)
                self.assertEqual(step.count("ftp-runtime/rclone-triage/assets/rclone.exe"), 1)
                self.assertIn('@("$env:RUNNER_TEMP/ftp-build/rclone-version.env", "$env:RUNNER_TEMP/ftp-runtime/rclone-version.env")', step)
                self.assertIn(".Hash -cne $expectedPins", step)
                self.assertIn("$runtimePin.Count -ne 1", step)
                self.assertIn("^RCLONE_EXE_SHA256=[0-9a-f]{64}$", step)
                self.assertIn("Get-FileHash -LiteralPath $runtime -Algorithm SHA256", step)
                self.assertIn("-cne (($runtimePin[0] -csplit '=', 2)[1])", step)
                self.assertLess(step.index("ftp_hosted_required"), step.index("python -B"))
                self.assertLess(step.index("$runtimePin.Count -ne 1"), step.index("python -B"))

    def test_exact_native_and_independent_validator_arguments_and_exit_checks(self):
        expected = (
            (self.producer, "scripts/application-lab/run_windows_ftp.py",
             ["--application", "--application-sha256", "--build-commit", "--rclone", "--report"], "ftp_cases_failed"),
            (self.validator, "scripts/ftp_application_evidence.py",
             ["--receipt", "--application", "--build-commit", "--report"], "ftp_evidence_failed"),
        )
        for step, script, flags, error in expected:
            invocation = step.split("          python -B ", 1)[1].split("          if ($LASTEXITCODE", 1)[0]
            self.assertTrue(invocation.startswith(script + " `\n"))
            self.assertEqual(re.findall(r"--[a-z0-9-]+", invocation), flags)
            self.assertIn("--application $application", invocation)
            self.assertIn("--build-commit $buildCommit", invocation)
            self.assertIn("if ($LASTEXITCODE -ne 0) { throw '" + error + "' }", step)
        self.assertIn("Get-FileHash -LiteralPath $application -Algorithm SHA256", self.producer)
        self.assertIn('--rclone $runtime --report "$env:RUNNER_TEMP/ftp.private.json"', self.producer)
        self.assertIn('--receipt "$env:RUNNER_TEMP/ftp.private.json"', self.validator)
        self.assertIn('--report "$env:RUNNER_TEMP/ftp-validation.json"', self.validator)

    def test_failure_runs_validator_then_only_normalized_report_upload(self):
        for step, prior in ((self.validator, "ftp_cases"), (self.upload, "ftp_validation")):
            self.assertIn("if: ${{ !cancelled() && (steps." + prior + ".outcome == 'success' || steps." + prior + ".outcome == 'failure') }}", step)
        self.assertIn("name: ftp-experiment-Windows\n", self.upload)
        self.assertIn("path: ${{ runner.temp }}/ftp-validation.json\n", self.upload)
        self.assertIn("if-no-files-found: error", self.upload)
        self.assertIn("retention-days: 14", self.upload)
        self.assertIn("timeout-minutes: 2", self.upload)
        for forbidden in ("ftp.private.json", "*", "transcript", "source.conf", "if-no-files-found: warn"):
            self.assertNotIn(forbidden, self.upload)

    def test_nightly_keeps_all_existing_prerequisites_and_adds_ftp_once(self):
        publication = self.workflow.split("    name: Publish Windows nightly\n", 1)[1]
        needs = re.search(r"^    needs: \[([^\]]+)\]$", publication, re.MULTILINE)
        self.assertIsNotNone(needs)
        self.assertEqual([name.strip() for name in needs.group(1).split(",")],
                         ["test", "windows-filesystem", "windows-ftp", "windows-b2", "windows-swift",
                          "windows-azureblob", "windows-swift-cancellation", "windows-swift-listing",
                          "windows-architectures", "audit", "python-audit", "smb-protocol",
                          "linux-provider-evidence", "pcloud-oauth-feasibility", "pcloud-oauth-authentication",
                          "gcs-oauth-lifecycle", "windows-webdav-bearer"])


if __name__ == "__main__":
    unittest.main()
