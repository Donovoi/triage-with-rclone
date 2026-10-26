"""Pure CI boundary checks; no workflow scripts or native programs are run."""
from pathlib import Path
import re
import shlex
import unittest

from test_gcs_oauth_workflow_contract import jobs, require, scalar

WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml"


def steps(job):
    return [part for part in re.split(r"(?=^      - )", job.split("    steps:\n", 1)[1], flags=re.MULTILINE) if part.strip()]


def action_refs(job):
    return re.findall(r"\buses: (actions/[\w-]+@[a-f0-9]{40})\b", job)


def after_either_outcome(step, predecessor):
    condition = scalar(step, "if", 8)
    match = re.fullmatch(r"\$\{\{\s*!cancelled\(\)\s*&&\s*\((.+)\)\s*\}\}", condition)
    require(match is not None, "uncancelled_outcome_gate")
    terms = [term.strip() for term in match[1].split("||")]
    require(len(terms) == 2 and set(terms) == {
        f"steps.{predecessor}.outcome == 'success'", f"steps.{predecessor}.outcome == 'failure'"}, "success_or_failure_only")


def bound_command(step):
    require(scalar(step, "shell", 8) == "pwsh", "powershell_required")
    script = step.split("        run: |\n", 1)[1]
    guards = re.findall(r"if \((.*)\) \{ throw '[^']+' \}", script)
    # Inspect the trust boundaries, not the complete PowerShell implementation.
    for terms in (("$env:GITHUB_ACTIONS -cne 'true'", "$env:RUNNER_ENVIRONMENT -cne 'github-hosted'", " -or "),
                  ("$LASTEXITCODE -ne 0", "$buildCommit -cnotmatch '^[0-9a-f]{40}$'", "$env:GITHUB_SHA -cne $buildCommit", " -or "),
                  ('Get-FileHash -LiteralPath "$env:RUNNER_TEMP/azureblob-build/rclone-version.env"', "-Algorithm SHA256", ".Hash -cne $expectedPins")):
        require(any(all(term in guard for term in terms) for guard in guards), "independent_binding_guard")
    for binding in ("$ErrorActionPreference = 'Stop'", "$buildCommit = (& git rev-parse --verify HEAD)",
                    '$application = (Resolve-Path "$env:RUNNER_TEMP/azureblob-build/rclone-triage/target/release/rclone-triage.exe")',
                    "$expectedPins = (Get-FileHash -LiteralPath rclone-version.env -Algorithm SHA256)"):
        require(binding in script, "bound_inputs")
    joined = script.replace("`\n", "")
    commands = list(re.finditer(r"(?m)^\s*python -B ([^\n]+)", joined))
    require(len(commands) == 1, "one_python_invocation")
    require(re.search(r"if \(\$LASTEXITCODE -ne 0\) \{ throw '[^']+' \}", joined[commands[0].end():]), "native_exit_required")
    args = shlex.split(commands[0][1])
    require(args.count("--application") == args.count("--build-commit") == 1 and
        args[args.index("--application") + 1] == "$application" and
        args[args.index("--build-commit") + 1] == "$buildCommit", "same_build_arguments")
    return script, args


def validate(text):
    definitions = jobs(text); job = definitions["windows-azureblob"]; chain = steps(job)
    require(scalar(job, "needs", 4) == "test" and scalar(job, "runs-on", 4) == "windows-latest", "checked_hosted_build")
    require(not re.search(r"^    (?:if|services|permissions):", job, re.MULTILINE) and
        "continue-on-error" not in job and "secrets." not in job, "mandatory_unprivileged_job")
    shared = action_refs(definitions["windows-b2"])
    require(len(shared) == 4 and action_refs(job) == shared + [shared[-1], shared[-1]], "shared_pinned_actions")
    require("persist-credentials: false" in chain[0], "no_persisted_credentials")
    downloads = [part for part in chain if "uses: actions/download-artifact@" in part]
    require(len(downloads) == 1, "one_checked_download")
    download = downloads[0]
    require(re.findall(r"^          ([a-z-]+):", download, re.MULTILINE) == ["name", "path"] and
        scalar(download, "name", 10) == "rclone-triage-windows" and
        scalar(download, "path", 10) == "${{ runner.temp }}/azureblob-build", "current_run_exact_artifact")
    checked = [part for part in steps(definitions["test"]) if "          name: rclone-triage-windows\n" in part]
    require(len(checked) == 1 and all(path in checked[0] for path in
        ("rclone-triage/target/release/rclone-triage.exe", "rclone-triage/target/release/dependencies.json", "rclone-version.env")), "checked_artifact_layout")
    runs = [part for part in chain if "        run:" in part]
    ids = ["azureblob_cases", "azureblob_validation", "azureblob_download_denial_cases", "azureblob_download_denial_validation", "azureblob_listing_cases", "azureblob_listing_validation"]
    require(len(runs) == 6 and [scalar(part, "id", 8) for part in runs] == ids, "distinct_ordered_steps")
    uploads = [part for part in chain if "uses: actions/upload-artifact@" in part]
    require(len(uploads) == 3, "three_distinct_normalized_uploads")
    for index, stem in enumerate(("azureblob", "azureblob-download-denial", "azureblob-listing")):
        first, second = runs[index * 2:index * 2 + 2]; upload = uploads[index]
        require(not re.search(r"^        if:", first, re.MULTILINE), "producer_not_optional")
        producer, p = bound_command(first); _, v = bound_command(second)
        require(p[0] == "scripts/application-lab/run_windows_azureblob.py" and v[0] == "scripts/azureblob_application_evidence.py", "producer_then_independent_validator")
        require("Get-FileHash -LiteralPath $application -Algorithm SHA256" in producer and
            p[p.index("--application-sha256") + 1] == "$applicationHash", "application_hash_required")
        if index == 0:
            require("--fixture-mode" not in p and "--fixture-mode" not in v, "original_default_mode_retained")
        else:
            for args in (p, v):
                require(args.count("--fixture-mode") == 1 and args[args.index("--fixture-mode") + 1] ==
                    ("azureblob_sharedkey_download_denial_cli_v1" if index == 1 else "azureblob_sharedkey_listing_cli_v1"), "explicit_experiment_mode")
        require(p[p.index("--report") + 1] == v[v.index("--receipt") + 1] == "$env:RUNNER_TEMP/" + stem + ".private.json" and
            v[v.index("--report") + 1] == "$env:RUNNER_TEMP/" + stem + "-validation.json", "private_input_normalized_output")
        after_either_outcome(second, ids[index * 2]); after_either_outcome(upload, ids[index * 2 + 1])
        require(chain.index(first) < chain.index(second) < chain.index(upload) and
            (index == 0 or chain.index(uploads[index - 1]) < chain.index(first)), "retained_evidence_before_next_mode")
        require(scalar(upload, "path", 10) == "${{ runner.temp }}/" + stem + "-validation.json" and
            scalar(upload, "if-no-files-found", 10) == "error", "normalized_only_upload")
        require(scalar(upload, "name", 10) == stem + "-experiment-Windows", "distinct_normalized_artifact")
        require(scalar(first, "timeout-minutes", 8) == "8" and scalar(second, "timeout-minutes", 8) == "3", "bounded_steps")
    require(scalar(job, "timeout-minutes", 4) == "20", "bounded_execution")
    require(scalar(definitions["release"], "needs", 4).strip("[]").split(", ").count("windows-azureblob") == 1, "mandatory_nightly_dependency")


class AzureBlobWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.text = WORKFLOW.read_text(encoding="utf-8")

    def reject(self, mutations, region=None):
        region = region or jobs(self.text)["windows-azureblob"]
        for old, new in mutations:
            with self.subTest(mutation=old):
                self.assertIn(old, region)
                with self.assertRaises((ValueError, KeyError, IndexError)):
                    validate(self.text.replace(region, region.replace(old, new, 1), 1))

    def test_same_run_bound_experiment_contract(self): validate(self.text)

    def test_shared_pin_and_nonsemantic_label_changes_need_no_test_update(self):
        changed = self.text
        for ref in action_refs(jobs(self.text)["windows-b2"]): changed = changed.replace(ref, ref.split("@")[0] + "@" + "1" * 40)
        validate(changed.replace("Windows AzureBlob SharedKey acquisition experiment", "AzureBlob renewal experiment"))

    def test_foreign_artifact_or_unchecked_host_rejected(self):
        self.reject((("needs: test", "needs: revision"), ("windows-latest", "self-hosted"),
            ("path: ${{ runner.temp }}/azureblob-build", "path: ${{ runner.temp }}/azureblob-build\n          run-id: 123"),
            ("name: rclone-triage-windows", "pattern: rclone-triage-*"),
            ("persist-credentials: false", "persist-credentials: true"),
            ("timeout-minutes: 20", "timeout-minutes: 60")))

    def test_both_steps_independently_enforce_bindings_and_native_exit(self):
        runs = [part for part in steps(jobs(self.text)["windows-azureblob"]) if "        run:" in part]
        for region in runs:
            self.reject((("$env:RUNNER_ENVIRONMENT -cne 'github-hosted'", "$false"),
                ("$env:GITHUB_SHA -cne $buildCommit", "$false"), (".Hash -cne $expectedPins", ".Hash -eq $expectedPins"),
                ("git rev-parse --verify HEAD", "git rev-parse --verify other")), region)
            exit_guard = re.findall(r"if \(\$LASTEXITCODE -ne 0\) \{ throw '[^']+' \}", region)[-1]
            self.reject(((exit_guard, "Write-Output 'ignored'"),), region)

    def test_exactly_one_producer_and_distinct_validator_required(self):
        self.reject((("python -B scripts/azureblob_application_evidence.py", "python -B scripts/application-lab/run_windows_azureblob.py"),
            ("--application-sha256 $applicationHash", "--application-sha256 omitted"),
            ("          python -B scripts/application-lab/run_windows_azureblob.py", "          python -B extra.py\n          python -B scripts/application-lab/run_windows_azureblob.py")))

    def test_failure_skip_and_cancellation_cannot_earn_credit(self):
        self.reject((("steps.azureblob_cases.outcome == 'failure'", "steps.azureblob_cases.outcome == 'skipped'"),
            ("steps.azureblob_validation.outcome == 'failure'", "steps.azureblob_validation.outcome == 'skipped'"),
            ("!cancelled()", "true"), ("        id: azureblob_cases", "        if: false\n        id: azureblob_cases"),
            ("    steps:", "    continue-on-error: true\n    steps:")))

    def test_private_or_wildcard_artifact_rejected(self):
        self.reject((("path: ${{ runner.temp }}/azureblob-validation.json", "path: ${{ runner.temp }}/azureblob.private.json"),
            ("path: ${{ runner.temp }}/azureblob-validation.json", "path: ${{ runner.temp }}/**"),
            ("if-no-files-found: error", "if-no-files-found: warn"),
            ("name: azureblob-experiment-Windows", "name: swift-experiment-Windows")))

    def test_azureblob_must_gate_nightly(self):
        with self.assertRaises(ValueError):
            validate(self.text.replace("windows-swift, windows-azureblob, ", "windows-swift, ", 1))

    def test_new_mode_and_evidence_cannot_replay_original_mode(self):
        chain = steps(jobs(self.text)["windows-azureblob"])
        for region in [part for part in chain if "        run:" in part][2:4]:
            self.reject((("--fixture-mode azureblob_sharedkey_download_denial_cli_v1", ""),
                ("--fixture-mode azureblob_sharedkey_download_denial_cli_v1", "--fixture-mode azureblob_sharedkey_acquisition_cli_v1"),
                ("azureblob-download-denial.private.json", "azureblob.private.json")), region)
        self.reject((("steps.azureblob_download_denial_cases.outcome == 'failure'", "steps.azureblob_download_denial_cases.outcome == 'skipped'"),
            ("steps.azureblob_download_denial_validation.outcome == 'failure'", "steps.azureblob_download_denial_validation.outcome == 'skipped'"),
            ("        id: azureblob_download_denial_cases", "        if: false\n        id: azureblob_download_denial_cases"),
            ("path: ${{ runner.temp }}/azureblob-download-denial-validation.json", "path: ${{ runner.temp }}/azureblob-download-denial.private.json"),
            ("name: azureblob-download-denial-experiment-Windows", "name: azureblob-experiment-Windows")))


if __name__ == "__main__": unittest.main()
