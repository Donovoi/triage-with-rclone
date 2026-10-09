"""Pure gate/artifact contracts; no workflow, shell or runtime execution."""
from pathlib import Path
import re
import unittest

from test_gcs_oauth_workflow_contract import command, jobs, require, scalar

ROOT = Path(__file__).resolve().parents[2]
BASELINE = set("local,archive,http,webdav,ftp,sftp,s3,swift,b2,azureblob,azurefiles,seafile,memory,koofr,pixeldrain,filefabric,netstorage,internetarchive".split(","))
ALL = BASELINE | {"gcs", "smb", "pcloud"}


def steps(block):
    return [part for part in re.split(r"(?=^      - )", block.split("    steps:\n", 1)[1], flags=re.MULTILINE) if part.strip()]


def gate(step, baseline):
    args = command(step)
    require(args.count("--require-fixtures") == 1, "fixture_gate_required")
    names = args[args.index("--require-fixtures") + 1].split(",")
    require(len(names) == len(set(names)) and set(names) == (BASELINE if baseline else ALL), "complete_gate_required")
    require(args.count("--require-gcs-static-token") == (1 if baseline else 0), "static_mode_gate_required")
    receipts = [args[i + 1] for i, value in enumerate(args) if value == "--fixture-receipt"]
    expected = ("$RUNNER_TEMP/provider-gcs/gcs-oauth-lifecycle.json" if "provider-baseline" in " ".join(args)
                else "$RUNNER_TEMP/gcs-oauth-lifecycle.json")
    require((expected in receipts) is (not baseline), "qualified_receipt_required")
    require(not any("experiment" in value for value in receipts), "unqualified_import_refused")


def validate(ci, smoke):
    definitions = jobs(ci)
    job = definitions["gcs-oauth-lifecycle"]
    fields = re.findall(r"^    ([a-z-]+):", job, re.MULTILINE)
    require(set(fields) == {"name", "needs", "runs-on", "timeout-minutes", "steps"} and len(fields) == 5,
            "required_unconditional_job")
    require(scalar(job, "needs", 4) == "[revision, test, python-audit]", "prerequisites_required")
    require(scalar(job, "runs-on", 4) == "ubuntu-latest" and scalar(job, "timeout-minutes", 4) == "25", "hosted_bound")
    parts = steps(job); require(len(parts) == 5, "closed_steps")
    require("persist-credentials: false" in parts[0], "no_checkout_credentials")
    require("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" in parts[0]
            and "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97" in parts[1], "pinned_setup")
    require(command(parts[2]) == ["bash", "scripts/download-rclone.sh", "--linux", "$RUNNER_TEMP/rclone-gcs-lifecycle"], "pinned_runtime")
    require(command(parts[3]) == ["python", "-B", "scripts/provider-lab/gcs-oauth/run_container.py", "--rclone",
            "$RUNNER_TEMP/rclone-gcs-lifecycle", "--lifecycle-evidence", "--report", "$RUNNER_TEMP/gcs-oauth-lifecycle.json"], "fresh_qualification_required")
    require(scalar(parts[4], "if", 8) == "always()"
            and scalar(parts[4], "uses", 8).split(" #", 1)[0] == "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
            and scalar(parts[4], "name", 10) == "gcs-oauth-lifecycle"
            and scalar(parts[4], "path", 10) == "${{ runner.temp }}/gcs-oauth-lifecycle.json"
            and scalar(parts[4], "if-no-files-found", 10) == "error", "sanitized_failure_artifact")
    require("continue-on-error" not in job and "permissions:" not in job, "no_failure_or_privilege_override")
    baseline = [step for step in steps(definitions["test"]) if "--require-fixtures" in step]
    require(len(baseline) == 2, "matrix_and_windows_baseline_required")
    for item in baseline: gate(item, True)
    require("gcs-oauth-lifecycle.json" not in definitions["test"], "no_linux_borrowing")
    combined = definitions["linux-provider-evidence"]
    require(scalar(combined, "needs", 4) == "[test, smb-protocol, pcloud-oauth-authentication, gcs-oauth-lifecycle]", "same_run_dependency")
    downloaded = [part for part in steps(combined) if "name: gcs-oauth-lifecycle" in part]
    require(len(downloaded) == 1, "same_run_named_download")
    require("actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c" in downloaded[0]
            and scalar(downloaded[0], "path", 10) == "${{ runner.temp }}/provider-gcs"
            and re.findall(r"^          ([a-z-]+):", downloaded[0], re.MULTILINE) == ["name", "path"], "no_foreign_artifact_run")
    combined_gates = [part for part in steps(combined) if "--require-fixtures" in part]
    require(len(combined_gates) == 1, "combined_gate_required"); gate(combined_gates[0], False)
    require("gcs-oauth-lifecycle" in scalar(definitions["release"], "needs", 4).strip("[]").split(", "), "release_dependency_required")
    smoke_parts = [part for part in re.split(r"(?=^      - )", smoke, flags=re.MULTILINE) if part.strip()]
    qualified = [part for part in smoke_parts if "gcs-oauth/run_container.py" in part]
    require(len(qualified) == 1 and command(qualified[0]) == ["python", "-B", "../scripts/provider-lab/gcs-oauth/run_container.py",
            "--rclone", "$RUNNER_TEMP/rclone-smoke", "--lifecycle-evidence", "--report", "$RUNNER_TEMP/gcs-oauth-lifecycle.json"], "nightly_qualification_required")
    daily_gates = [part for part in smoke_parts if "--require-fixtures" in part]
    require(len(daily_gates) == 1, "nightly_gate_required"); gate(daily_gates[0], False)
    require("            ${{ runner.temp }}/gcs-oauth-lifecycle.json\n" in smoke, "nightly_receipt_retained")


class GcsLifecycleWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.ci = (ROOT / ".github/workflows/ci.yml").read_text()
        self.smoke = (ROOT / ".github/workflows/provider-smoke.yml").read_text()

    def test_current_required_qualification_and_preserved_baseline(self):
        validate(self.ci, self.smoke)

    def test_each_baseline_gate_cannot_drop_gcs_or_other_existing_obligation(self):
        for occurrence in (0, 1):
            matches = list(re.finditer(r"--require-fixtures ([a-z0-9_,]+) --require-gcs-static-token", self.ci))
            match = matches[occurrence]
            for replacement in (match[0].replace(" --require-gcs-static-token", ""),
                                match[0].replace("local,", ""), match[0].replace("internetarchive", "gcs")):
                changed = self.ci[:match.start()] + replacement + self.ci[match.end():]
                with self.assertRaises(ValueError): validate(changed, self.smoke)

    def test_optional_skipped_foreign_or_unqualified_evidence_cannot_pass(self):
        for before, after in (
                ("  gcs-oauth-lifecycle:\n", "  gcs-oauth-lifecycle:\n    if: false\n"),
                ("[test, smb-protocol, pcloud-oauth-authentication, gcs-oauth-lifecycle]", "[test, smb-protocol, pcloud-oauth-authentication]"),
                ('--lifecycle-evidence \\\n', '\\\n'),
                ('--fixture-receipt "$RUNNER_TEMP/provider-gcs/gcs-oauth-lifecycle.json"', '--fixture-receipt "$RUNNER_TEMP/provider-gcs/gcs-oauth-experiment.json"'),
                ('          path: ${{ runner.temp }}/provider-gcs', '          run-id: 123\n          path: ${{ runner.temp }}/provider-gcs'),
                ('          path: ${{ runner.temp }}/gcs-oauth-lifecycle.json', '          path: ${{ runner.temp }}/**')):
            with self.subTest(before=before), self.assertRaises(ValueError):
                validate(self.ci.replace(before, after, 1), self.smoke)

    def test_nightly_cannot_omit_fresh_run_import_or_retention(self):
        for before, after in (('--lifecycle-evidence', ''), ('--rclone "$RUNNER_TEMP/rclone-smoke" --lifecycle-evidence', '--rclone "$RUNNER_TEMP/other" --lifecycle-evidence'),
                              ('--fixture-receipt "$RUNNER_TEMP/gcs-oauth-lifecycle.json"', ''),
                              ('            ${{ runner.temp }}/gcs-oauth-lifecycle.json\n', '')):
            with self.subTest(before=before), self.assertRaises(ValueError):
                validate(self.ci, self.smoke.replace(before, after, 1))


if __name__ == "__main__":
    unittest.main()
