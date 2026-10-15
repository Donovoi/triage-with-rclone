"""Pure hosted-wiring contracts; no shell, fixture or application is executed."""
from pathlib import Path
import re
import shlex
import unittest

from test_gcs_oauth_workflow_contract import jobs, require, scalar
from test_swift_application_workflow import action_refs, after_either_outcome, steps

WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml"
JOB = "windows-webdav-bearer"


def bound_command(step):
    require(scalar(step, "shell", 8) == "pwsh", "powershell_required")
    script = step.split("        run: |\n", 1)[1]
    joined = script.replace("`\n", "")
    commands = list(re.finditer(r"(?m)^\s*python -B ([^\n]+)", joined))
    require(len(commands) == 1, "one_python_invocation")
    before, after = joined[:commands[0].start()], joined[commands[0].end():]
    guards = re.findall(r"if \((.*)\) \{ throw '[^']+' \}", before)
    for terms in (("$env:GITHUB_ACTIONS -cne 'true'", "$env:RUNNER_ENVIRONMENT -cne 'github-hosted'", " -or "),
                  ("$LASTEXITCODE -ne 0", "$buildCommit -cnotmatch '^[0-9a-f]{40}$'", "$env:GITHUB_SHA -cne $buildCommit", " -or "),
                  ('Get-FileHash -LiteralPath "$env:RUNNER_TEMP/webdav-bearer-build/rclone-version.env"', "-Algorithm SHA256", ".Hash -cne $expectedPins")):
        require(any(all(term in guard for term in terms) for guard in guards), "independent_binding_guard_before_execution")
    for binding in ("$ErrorActionPreference = 'Stop'", "$buildCommit = (& git rev-parse --verify HEAD).Trim()",
                    '$application = (Resolve-Path "$env:RUNNER_TEMP/webdav-bearer-build/rclone-triage/target/release/rclone-triage.exe").Path',
                    "$expectedPins = (Get-FileHash -LiteralPath rclone-version.env -Algorithm SHA256).Hash"):
        require(binding in before, "bound_inputs_before_execution")
    require(re.fullmatch(r"\s*if \(\$LASTEXITCODE -ne 0\) \{ throw '[^']+' \}\s*", after), "actual_native_exit_required")
    return before, shlex.split(commands[0][1])


def validate(text):
    definitions = jobs(text); job = definitions[JOB]; chain = steps(job)
    fields = re.findall(r"^    ([a-z-]+):", job, re.MULTILINE)
    require(sorted(fields) == sorted(("name", "needs", "runs-on", "timeout-minutes", "steps")), "closed_job_surface")
    require(scalar(job, "needs", 4) == "test" and scalar(job, "runs-on", 4) == "windows-latest", "checked_hosted_build")
    require(scalar(job, "timeout-minutes", 4) == "20", "bounded_job")
    require(len(chain) == 6 and "continue-on-error" not in job and "secrets." not in job and
            not re.search(r"^        (?:env|working-directory):", job, re.MULTILINE), "mandatory_fixed_steps")
    require(action_refs(job) == action_refs(definitions["windows-swift"]) and len(action_refs(job)) == 4, "shared_pinned_actions")
    require(scalar(chain[0], "persist-credentials", 10) == "false", "no_persisted_credentials")
    require(re.findall(r"^          ([a-z-]+):", chain[0], re.MULTILINE) == ["persist-credentials"], "same_checkout_revision")
    require(scalar(chain[1], "python-version", 10) == "'3.12'", "fixed_python")
    download = chain[2]
    require("uses: actions/download-artifact@" in download and scalar(download, "timeout-minutes", 8) == "2", "bounded_artifact_download")
    require(re.findall(r"^          ([a-z-]+):", download, re.MULTILINE) == ["name", "path"] and
            scalar(download, "name", 10) == "rclone-triage-windows" and
            scalar(download, "path", 10) == "${{ runner.temp }}/webdav-bearer-build", "current_run_exact_artifact")
    checked = [part for part in steps(definitions["test"]) if "          name: rclone-triage-windows\n" in part]
    require(len(checked) == 1 and all(path in checked[0] for path in
            ("rclone-triage/target/release/rclone-triage.exe", "rclone-triage/target/release/dependencies.json", "rclone-version.env")), "checked_x64_artifact_layout")
    producer, validator = chain[3:5]
    require(scalar(producer, "id", 8) == "webdav_bearer_cases" and scalar(validator, "id", 8) == "webdav_bearer_validation", "distinct_ordered_steps")
    require(not re.search(r"^        if:", producer, re.MULTILINE), "producer_not_optional")
    require(scalar(producer, "timeout-minutes", 8) == "8" and scalar(validator, "timeout-minutes", 8) == "3", "existing_outer_bounds")
    before, p = bound_command(producer); _, v = bound_command(validator)
    require("$applicationHash = (Get-FileHash -LiteralPath $application -Algorithm SHA256).Hash.ToLowerInvariant()" in before, "actual_application_hash")
    require(p == ["scripts/application-lab/run_windows_webdav_bearer.py", "--application", "$application",
                  "--application-sha256", "$applicationHash", "--build-commit", "$buildCommit",
                  "--report", "$env:RUNNER_TEMP/webdav-bearer.private.json"], "fixed_producer_arguments")
    require(v == ["scripts/webdav_bearer_application_evidence.py", "--receipt", "$env:RUNNER_TEMP/webdav-bearer.private.json",
                  "--application", "$application", "--build-commit", "$buildCommit",
                  "--report", "$env:RUNNER_TEMP/webdav-bearer-validation.json"], "independent_fixed_validator_arguments")
    after_either_outcome(validator, "webdav_bearer_cases")
    upload = chain[5]
    require("uses: actions/upload-artifact@" in upload and scalar(upload, "timeout-minutes", 8) == "2", "one_bounded_upload")
    after_either_outcome(upload, "webdav_bearer_validation")
    require(re.findall(r"^          ([a-z-]+):", upload, re.MULTILINE) == ["name", "path", "if-no-files-found", "retention-days"], "closed_upload_surface")
    require(scalar(upload, "name", 10) == "webdav-bearer-experiment-Windows" and
            scalar(upload, "path", 10) == "${{ runner.temp }}/webdav-bearer-validation.json" and
            scalar(upload, "if-no-files-found", 10) == "error" and scalar(upload, "retention-days", 10) == "14", "normalized_only_upload")
    require(scalar(definitions["release"], "needs", 4).strip("[]").split(", ").count(JOB) == 1, "mandatory_nightly_dependency")


class WebdavBearerWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.text = WORKFLOW.read_text(encoding="utf-8")

    def reject(self, mutations, region=None):
        region = jobs(self.text)[JOB] if region is None else region
        for old, new in mutations:
            with self.subTest(mutation=old):
                self.assertIn(old, region)
                with self.assertRaises((ValueError, KeyError, IndexError)):
                    validate(self.text.replace(region, region.replace(old, new, 1), 1))

    def test_same_run_bound_experiment_contract(self): validate(self.text)

    def test_shared_pins_labels_and_release_order_are_not_coupled(self):
        changed = self.text
        for ref in action_refs(jobs(self.text)["windows-swift"]):
            changed = changed.replace(ref, ref.split("@")[0] + "@" + "1" * 40)
        release = jobs(changed)["release"]; needs = scalar(release, "needs", 4)
        reordered = "[" + ", ".join(reversed(needs.strip("[]").split(", "))) + "]"
        validate(changed.replace(release, release.replace(needs, reordered, 1), 1).replace(
            "Windows WebDAV fixed-token rejection experiment", "Controlled WebDAV rejection"))

    def test_foreign_artifact_or_unchecked_host_rejected(self):
        self.reject((("needs: test", "needs: revision"), ("windows-latest", "self-hosted"),
            ("path: ${{ runner.temp }}/webdav-bearer-build", "path: ${{ runner.temp }}/webdav-bearer-build\n          run-id: 123"),
            ("name: rclone-triage-windows", "pattern: rclone-triage-*"),
            ("persist-credentials: false", "persist-credentials: true"),
            ("persist-credentials: false", "persist-credentials: false\n          ref: foreign")))

    def test_both_steps_independently_enforce_binding_and_native_exit(self):
        for region in steps(jobs(self.text)[JOB])[3:5]:
            self.reject((("$env:RUNNER_ENVIRONMENT -cne 'github-hosted'", "$false"),
                ("$env:GITHUB_SHA -cne $buildCommit", "$false"), (".Hash -cne $expectedPins", ".Hash -eq $expectedPins"),
                ("git rev-parse --verify HEAD", "git rev-parse --verify other")), region)
            exit_guard = re.findall(r"if \(\$LASTEXITCODE -ne 0\) \{ throw '[^']+' \}", region)[-1]
            self.reject(((exit_guard, "Write-Output 'ignored'"),), region)

    def test_one_producer_distinct_validator_and_exact_arguments(self):
        self.reject((("python -B scripts/webdav_bearer_application_evidence.py", "python -B scripts/application-lab/run_windows_webdav_bearer.py"),
            ("--application-sha256 $applicationHash", "--application-sha256 omitted"),
            ("--application $application", "--application foreign.exe"),
            ("          python -B scripts/application-lab/run_windows_webdav_bearer.py", "          python -B extra.py\n          python -B scripts/application-lab/run_windows_webdav_bearer.py")))

    def test_failure_skip_and_bypass_cannot_earn_credit(self):
        self.reject((("steps.webdav_bearer_cases.outcome == 'failure'", "steps.webdav_bearer_cases.outcome == 'skipped'"),
            ("steps.webdav_bearer_validation.outcome == 'failure'", "steps.webdav_bearer_validation.outcome == 'skipped'"),
            ("!cancelled()", "true"), ("        id: webdav_bearer_cases", "        if: false\n        id: webdav_bearer_cases"),
            ("    steps:", "    continue-on-error: true\n    steps:"),
            ("        id: webdav_bearer_validation", "        continue-on-error: true\n        id: webdav_bearer_validation")))

    def test_only_normalized_report_upload_is_allowed(self):
        self.reject((("path: ${{ runner.temp }}/webdav-bearer-validation.json", "path: ${{ runner.temp }}/webdav-bearer.private.json"),
            ("path: ${{ runner.temp }}/webdav-bearer-validation.json", "path: ${{ runner.temp }}/**"),
            ("if-no-files-found: error", "if-no-files-found: warn"),
            ("retention-days: 14", "retention-days: 14\n          include-hidden-files: true")))

    def test_time_budgets_remain_fixed(self):
        self.reject((("    timeout-minutes: 20", "    timeout-minutes: 30"),
            ("        timeout-minutes: 8", "        timeout-minutes: 9"),
            ("        timeout-minutes: 3", "        timeout-minutes: 4")))

    def test_bearer_must_gate_nightly_without_adjacency_assumptions(self):
        release = jobs(self.text)["release"]; needs = scalar(release, "needs", 4)
        names = needs.strip("[]").split(", ")
        for changed in ([name for name in names if name != JOB], names + [JOB]):
            self.reject(((needs, "[" + ", ".join(changed) + "]"),), release)


if __name__ == "__main__": unittest.main()
