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
                  ('Get-FileHash -LiteralPath "$env:RUNNER_TEMP/swift-build/rclone-version.env"', "-Algorithm SHA256", ".Hash -cne $expectedPins")):
        require(any(all(term in guard for term in terms) for guard in guards), "independent_binding_guard")
    for binding in ("$ErrorActionPreference = 'Stop'", "$buildCommit = (& git rev-parse --verify HEAD)",
                    '$application = (Resolve-Path "$env:RUNNER_TEMP/swift-build/rclone-triage/target/release/rclone-triage.exe")',
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


def without_nightly_dependency(text, job_id):
    release = jobs(text)["release"]
    needs = scalar(release, "needs", 4)
    dependencies = needs.strip("[]").split(", ")
    require(dependencies.count(job_id) == 1, "mutation_requires_one_dependency")
    dependencies.remove(job_id)
    changed = release.replace(f"    needs: {needs}\n", f"    needs: [{', '.join(dependencies)}]\n", 1)
    require(changed != release, "mutation_must_change_release")
    return text.replace(release, changed, 1)


def validate(text, cancellation=False, listing=False):
    require(not (cancellation and listing), "one_mode")
    job_id = "windows-swift-listing" if listing else "windows-swift-cancellation" if cancellation else "windows-swift"
    producer_id = "swift_listing_cases" if listing else "swift_cancel_cases" if cancellation else "swift_cases"
    validator_id = "swift_listing_validation" if listing else "swift_cancel_validation" if cancellation else "swift_validation"
    stem = "swift-listing" if listing else "swift-cancellation" if cancellation else "swift"
    definitions = jobs(text); job = definitions[job_id]; chain = steps(job)
    require(scalar(job, "needs", 4) == "test" and scalar(job, "runs-on", 4) == "windows-latest", "checked_hosted_build")
    require(not re.search(r"^    (?:if|services|permissions):", job, re.MULTILINE) and
        "continue-on-error" not in job and "secrets." not in job, "mandatory_unprivileged_job")
    shared = action_refs(definitions["windows-b2"])
    require(len(shared) == 5 and shared[-1] == shared[-2] and
        action_refs(job) == shared[:4], "shared_pinned_actions")
    require("persist-credentials: false" in chain[0], "no_persisted_credentials")
    downloads = [part for part in chain if "uses: actions/download-artifact@" in part]
    require(len(downloads) == 1, "one_checked_download")
    download = downloads[0]
    require(re.findall(r"^          ([a-z-]+):", download, re.MULTILINE) == ["name", "path"] and
        scalar(download, "name", 10) == "rclone-triage-windows" and
        scalar(download, "path", 10) == "${{ runner.temp }}/swift-build", "current_run_exact_artifact")
    checked = [part for part in steps(definitions["test"]) if "          name: rclone-triage-windows\n" in part]
    require(len(checked) == 1 and all(path in checked[0] for path in
        ("rclone-triage/target/release/rclone-triage.exe", "rclone-triage/target/release/dependencies.json", "rclone-version.env")), "checked_artifact_layout")
    runs = [part for part in chain if "        run:" in part]
    require(len(runs) == 2 and scalar(runs[0], "id", 8) == producer_id and scalar(runs[1], "id", 8) == validator_id, "distinct_ordered_steps")
    require(not re.search(r"^        if:", runs[0], re.MULTILINE), "producer_not_optional")
    producer, p = bound_command(runs[0]); _, v = bound_command(runs[1])
    require(p.count("--cancellation-only") == v.count("--cancellation-only") == int(cancellation), "explicit_matching_mode")
    require(p.count("--listing-only") == v.count("--listing-only") == int(listing), "explicit_matching_mode")
    require(p[0] == "scripts/application-lab/run_windows_swift.py" and v[0] == "scripts/swift_application_evidence.py", "producer_then_independent_validator")
    require("Get-FileHash -LiteralPath $application -Algorithm SHA256" in producer and
        p[p.index("--application-sha256") + 1] == "$applicationHash", "application_hash_required")
    require(p[p.index("--report") + 1] == v[v.index("--receipt") + 1] == f"$env:RUNNER_TEMP/{stem}.private.json" and
        v[v.index("--report") + 1] == f"$env:RUNNER_TEMP/{stem}-validation.json", "private_input_normalized_output")
    after_either_outcome(runs[1], producer_id)
    uploads = [part for part in chain if "uses: actions/upload-artifact@" in part]
    require(len(uploads) == 1, "one_normalized_upload"); upload = uploads[0]
    after_either_outcome(upload, validator_id)
    require(scalar(upload, "path", 10) == "${{ runner.temp }}/" + stem + "-validation.json" and
        scalar(upload, "if-no-files-found", 10) == "error", "normalized_only_upload")
    require(scalar(upload, "name", 10) == stem + "-experiment-Windows", "distinct_normalized_artifact")
    require(scalar(job, "timeout-minutes", 4) == "20" and scalar(runs[0], "timeout-minutes", 8) == "8" and
        scalar(runs[1], "timeout-minutes", 8) == "3", "bounded_execution")
    require(scalar(definitions["release"], "needs", 4).strip("[]").split(", ").count(job_id) == 1, "mandatory_nightly_dependency")


class SwiftWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.text = WORKFLOW.read_text(encoding="utf-8")

    def reject(self, mutations, region=None):
        region = region or jobs(self.text)["windows-swift"]
        for old, new in mutations:
            with self.subTest(mutation=old):
                self.assertIn(old, region)
                with self.assertRaises((ValueError, KeyError, IndexError)):
                    validate(self.text.replace(region, region.replace(old, new, 1), 1))

    def test_same_run_bound_experiment_contract(self): validate(self.text)

    def test_shared_pin_and_nonsemantic_label_changes_need_no_test_update(self):
        changed = self.text
        for ref in action_refs(jobs(self.text)["windows-b2"]): changed = changed.replace(ref, ref.split("@")[0] + "@" + "1" * 40)
        validate(changed.replace("Windows Swift token replacement experiment", "Swift renewal experiment"))

    def test_foreign_artifact_or_unchecked_host_rejected(self):
        self.reject((("needs: test", "needs: revision"), ("windows-latest", "self-hosted"),
            ("path: ${{ runner.temp }}/swift-build", "path: ${{ runner.temp }}/swift-build\n          run-id: 123"),
            ("name: rclone-triage-windows", "pattern: rclone-triage-*"),
            ("persist-credentials: false", "persist-credentials: true")))

    def test_both_steps_independently_enforce_bindings_and_native_exit(self):
        runs = [part for part in steps(jobs(self.text)["windows-swift"]) if "        run:" in part]
        for region in runs:
            self.reject((("$env:RUNNER_ENVIRONMENT -cne 'github-hosted'", "$false"),
                ("$env:GITHUB_SHA -cne $buildCommit", "$false"), (".Hash -cne $expectedPins", ".Hash -eq $expectedPins"),
                ("git rev-parse --verify HEAD", "git rev-parse --verify other")), region)
            exit_guard = re.findall(r"if \(\$LASTEXITCODE -ne 0\) \{ throw '[^']+' \}", region)[-1]
            self.reject(((exit_guard, "Write-Output 'ignored'"),), region)

    def test_exactly_one_producer_and_distinct_validator_required(self):
        self.reject((("python -B scripts/swift_application_evidence.py", "python -B scripts/application-lab/run_windows_swift.py"),
            ("--application-sha256 $applicationHash", "--application-sha256 omitted"),
            ("          python -B scripts/application-lab/run_windows_swift.py", "          python -B extra.py\n          python -B scripts/application-lab/run_windows_swift.py")))

    def test_failure_skip_and_cancellation_cannot_earn_credit(self):
        self.reject((("steps.swift_cases.outcome == 'failure'", "steps.swift_cases.outcome == 'skipped'"),
            ("steps.swift_validation.outcome == 'failure'", "steps.swift_validation.outcome == 'skipped'"),
            ("!cancelled()", "true"), ("        id: swift_cases", "        if: false\n        id: swift_cases"),
            ("    steps:", "    continue-on-error: true\n    steps:")))

    def test_private_or_wildcard_artifact_rejected(self):
        self.reject((("path: ${{ runner.temp }}/swift-validation.json", "path: ${{ runner.temp }}/swift.private.json"),
            ("path: ${{ runner.temp }}/swift-validation.json", "path: ${{ runner.temp }}/**"),
            ("if-no-files-found: error", "if-no-files-found: warn")))

    def test_swift_must_gate_nightly(self):
        changed = without_nightly_dependency(self.text, "windows-swift")
        self.assertNotEqual(changed, self.text)
        with self.assertRaises(ValueError):
            validate(changed)




class SwiftCancellationWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.text = WORKFLOW.read_text(encoding="utf-8")

    def reject(self, mutations, region=None):
        region = region or jobs(self.text)["windows-swift-cancellation"]
        for old, new in mutations:
            with self.subTest(mutation=old):
                self.assertIn(old, region)
                changed = self.text.replace(region, region.replace(old, new, 1), 1)
                with self.assertRaises((ValueError, KeyError, IndexError)):
                    validate(changed, cancellation=True)

    def test_bound_cancellation_and_unchanged_renewal_modes(self):
        validate(self.text)
        validate(self.text, cancellation=True)

    def test_both_steps_require_one_explicit_cancellation_selection(self):
        runs = [s for s in steps(jobs(self.text)["windows-swift-cancellation"]) if "        run:" in s]
        for region in runs:
            self.reject(((" --cancellation-only", ""), (" --cancellation-only", " --cancellation-only --cancellation-only")), region)

    def test_renewal_cannot_silently_switch_modes(self):
        region = jobs(self.text)["windows-swift"]
        changed = region.replace("run_windows_swift.py `", "run_windows_swift.py --cancellation-only `", 1)
        with self.assertRaises(ValueError): validate(self.text.replace(region, changed, 1))

    def test_foreign_build_or_optional_job_rejected(self):
        self.reject((("needs: test", "needs: revision"), ("windows-latest", "self-hosted"),
            ("path: ${{ runner.temp }}/swift-build", "path: ${{ runner.temp }}/swift-build\n          run-id: 123"),
            ("persist-credentials: false", "persist-credentials: true"),
            ("    steps:", "    continue-on-error: true\n    steps:"), ("timeout-minutes: 20", "timeout-minutes: 60")))

    def test_both_steps_enforce_binding_and_exit(self):
        runs = [s for s in steps(jobs(self.text)["windows-swift-cancellation"]) if "        run:" in s]
        for region in runs:
            self.reject((("$env:GITHUB_SHA -cne $buildCommit", "$false"), (".Hash -cne $expectedPins", ".Hash -eq $expectedPins"),
                ("$env:RUNNER_ENVIRONMENT -cne 'github-hosted'", "$false")), region)
            guard = re.findall(r"if \(\$LASTEXITCODE -ne 0\) \{ throw '[^']+' \}", region)[-1]
            self.reject(((guard, "Write-Output 'ignored'"),), region)

    def test_failure_reports_are_required_and_private_inputs_stay_private(self):
        self.reject((("steps.swift_cancel_cases.outcome == 'failure'", "steps.swift_cancel_cases.outcome == 'skipped'"),
            ("steps.swift_cancel_validation.outcome == 'failure'", "steps.swift_cancel_validation.outcome == 'skipped'"),
            ("path: ${{ runner.temp }}/swift-cancellation-validation.json", "path: ${{ runner.temp }}/swift-cancellation.private.json"),
            ("name: swift-cancellation-experiment-Windows", "name: swift-experiment-Windows"),
            ("if-no-files-found: error", "if-no-files-found: warn")))

    def test_cancellation_must_gate_nightly(self):
        changed = without_nightly_dependency(self.text, "windows-swift-cancellation")
        self.assertNotEqual(changed, self.text)
        with self.assertRaises(ValueError):
            validate(changed, cancellation=True)


class SwiftListingWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.text = WORKFLOW.read_text(encoding="utf-8")

    def reject(self, old, new, region=None):
        region = region or jobs(self.text)["windows-swift-listing"]
        self.assertIn(old, region)
        changed = self.text.replace(region, region.replace(old, new, 1), 1)
        self.assertNotEqual(changed, self.text)
        with self.assertRaises((ValueError, KeyError, IndexError)):
            validate(changed, listing=True)

    def test_listing_and_existing_modes_remain_required(self):
        validate(self.text)
        validate(self.text, cancellation=True)
        validate(self.text, listing=True)

    def test_both_steps_enforce_the_exact_listing_mode_and_binding(self):
        for region in (s for s in steps(jobs(self.text)["windows-swift-listing"]) if "        run:" in s):
            for old, new in ((" --listing-only", ""), (" --listing-only", " --cancellation-only"),
                    (" --listing-only", " --listing-only --listing-only"),
                    ("$env:GITHUB_SHA -cne $buildCommit", "$false"),
                    (".Hash -cne $expectedPins", ".Hash -eq $expectedPins"),
                    ("$env:RUNNER_ENVIRONMENT -cne 'github-hosted'", "$false")):
                with self.subTest(old=old, new=new): self.reject(old, new, region)
            guard = re.findall(r"if \(\$LASTEXITCODE -ne 0\) \{ throw '[^']+' \}", region)[-1]
            self.reject(guard, "Write-Output 'ignored'", region)

    def test_listing_failure_cannot_skip_evidence_or_publish_private_input(self):
        for old, new in (("steps.swift_listing_cases.outcome == 'failure'", "steps.swift_listing_cases.outcome == 'skipped'"),
                ("steps.swift_listing_validation.outcome == 'failure'", "steps.swift_listing_validation.outcome == 'skipped'"),
                ("path: ${{ runner.temp }}/swift-listing-validation.json", "path: ${{ runner.temp }}/swift-listing.private.json"),
                ("name: swift-listing-experiment-Windows", "name: swift-experiment-Windows"),
                ("    steps:", "    continue-on-error: true\n    steps:")):
            with self.subTest(old=old): self.reject(old, new)

    def test_listing_cannot_be_removed_from_nightly_requirements(self):
        changed = without_nightly_dependency(self.text, "windows-swift-listing")
        with self.assertRaises(ValueError): validate(changed, listing=True)

    def test_existing_modes_cannot_silently_select_listing(self):
        for job_id, cancellation in (("windows-swift", False), ("windows-swift-cancellation", True)):
            region = jobs(self.text)[job_id]
            changed = region.replace("run_windows_swift.py", "run_windows_swift.py --listing-only", 1)
            with self.assertRaises(ValueError): validate(self.text.replace(region, changed, 1), cancellation=cancellation)


if __name__ == "__main__": unittest.main()
