"""Pure source contracts for the opt-in job; no shell, runtime or Docker runs.

This inspects the workflow's fixed indentation and shell argv, not general YAML.
Workflow YAML parsing is a separate validation step; no parser dependency is
added to the repository's locked fixture environment.
"""
from pathlib import Path
import re
import shlex
import unittest


WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml"
JOB = "gcs-oauth-experiment"
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
PYTHON = "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97"
UPLOAD = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"


def require(value, code):
    if not value:
        raise ValueError(code)


def scalar(block, key, indent):
    values = re.findall(r"^" + " " * indent + re.escape(key) + r": ([^\n]+)$", block, re.MULTILINE)
    require(len(values) == 1, "missing_or_duplicate_" + key)
    return values[0]


def jobs(text):
    require(text.count("\njobs:\n") == 1, "jobs_mapping")
    body = text.split("\njobs:\n", 1)[1]
    matches = list(re.finditer(r"^  ([a-z][a-z0-9-]*):\n", body, re.MULTILINE))
    require(len({match[1] for match in matches}) == len(matches), "duplicate_job")
    return {match[1]: body[match.start():matches[index + 1].start() if index + 1 < len(matches) else len(body)]
            for index, match in enumerate(matches)}


def command(step):
    block = re.search(r"^        run: \|\n((?:          [^\n]*\n)+)", step, re.MULTILINE)
    if block:
        script = "\n".join(line[10:] for line in block[1].splitlines())
    else:
        script = scalar(step, "run", 8)
    return shlex.split(script.replace("\\\n", ""), posix=True)


def validate(text):
    definitions = jobs(text)
    header = text.split("\njobs:\n", 1)[0]
    input_match = re.search(r"^      gcs_oauth_experiment:\n((?:        [^\n]+\n)+)", header, re.MULTILINE)
    require(input_match is not None, "missing_manual_input")
    require(re.search(r"^  workflow_dispatch:\n    inputs:\n", header, re.MULTILINE), "manual_input_placement")
    require(scalar(input_match[1], "type", 8) == "boolean", "boolean_input_required")
    require(scalar(input_match[1], "default", 8) == "false", "default_false_required")
    require(scalar(input_match[1], "required", 8) == "false", "optional_opt_in_required")
    require(re.search(r"^permissions:\n  contents: read\n(?=\S)", header, re.MULTILINE), "read_only_global_permission")

    revision = definitions["revision"]
    require(scalar(revision, "EXPECTED_SHA", 10) == "${{ inputs.expected_sha }}", "requested_sha_binding")
    require(scalar(revision, "ACTUAL_SHA", 10) == "${{ github.sha }}", "actual_sha_binding")
    require(scalar(revision, "GCS_OAUTH_EXPERIMENT", 10) == "${{ inputs.gcs_oauth_experiment }}", "opt_in_binding")
    missing_guard = ("          if [[ \"$GCS_OAUTH_EXPERIMENT\" == 'true' && -z \"$EXPECTED_SHA\" ]]; then\n"
                     "            echo 'An exact expected_sha is required for the GCS experiment.' >&2\n"
                     "            exit 1\n          fi\n")
    existing_guard = ("          if [[ -n \"$EXPECTED_SHA\" ]] && { [[ ! \"$EXPECTED_SHA\" =~ ^[0-9a-f]{40}$ ]] || "
                      "[[ \"$EXPECTED_SHA\" != \"$ACTUAL_SHA\" ]]; }; then\n"
                      "            echo 'The requested commit does not match this workflow run.' >&2\n"
                      "            exit 1\n          fi\n")
    require(missing_guard in revision and existing_guard in revision, "explicit_nonempty_exact_sha_failure")

    job = definitions[JOB]
    fields = re.findall(r"^    ([a-z-]+):", job, re.MULTILINE)
    require(set(fields) == {"name", "if", "needs", "runs-on", "timeout-minutes", "steps"}
            and len(fields) == 6, "unexpected_job_surface")
    require(scalar(job, "if", 4) == "${{ github.event_name == 'workflow_dispatch' && inputs.gcs_oauth_experiment }}",
            "manual_boolean_gate_required")
    needs = scalar(job, "needs", 4)
    require(needs == "[revision, test, python-audit]", "wire_revision_audit_dependencies")
    require(scalar(job, "runs-on", 4) == "ubuntu-latest" and scalar(job, "timeout-minutes", 4) == "25",
            "hosted_time_bound")
    steps = re.split(r"(?=^      - )", job.split("    steps:\n", 1)[1], flags=re.MULTILINE)
    steps = [step for step in steps if step.strip()]
    require(len(steps) == 5, "exact_five_steps")
    for index, action in ((0, CHECKOUT), (1, PYTHON)):
        require(re.search(r"^      - uses: " + re.escape(action) + r"(?: #[^\n]*)?\n", steps[index]), "pinned_action_required")
    require(scalar(steps[0], "persist-credentials", 10) == "false", "checkout_credentials_refused")
    require(scalar(steps[1], "python-version", 10) == "'3.12'", "python_version")
    require(scalar(steps[2], "shell", 8) == scalar(steps[3], "shell", 8) == "bash", "explicit_bash")
    require(command(steps[2]) == ["bash", "scripts/download-rclone.sh", "--linux", "$RUNNER_TEMP/rclone-gcs-oauth"],
            "verified_runtime_preparation")
    require(command(steps[3]) == ["python", "-B", "scripts/provider-lab/gcs-oauth/run_container.py",
            "--rclone", "$RUNNER_TEMP/rclone-gcs-oauth", "--report", "$RUNNER_TEMP/gcs-oauth-experiment.json"],
            "one_exact_supervisor_invocation")
    require(scalar(steps[4], "if", 8) == "always()" and scalar(steps[4], "uses", 8).split(" #", 1)[0] == UPLOAD,
            "always_pinned_artifact")
    require(scalar(steps[4], "name", 10) == JOB
            and scalar(steps[4], "path", 10) == "${{ runner.temp }}/gcs-oauth-experiment.json"
            and scalar(steps[4], "if-no-files-found", 10) == "error"
            and scalar(steps[4], "retention-days", 10) == "14", "exact_sanitized_artifact")
    require(len(re.findall(r"^        run:", job, re.MULTILINE)) == 2
            and "${{ inputs." not in job.split("    steps:\n", 1)[1], "no_additional_execution_or_input_interpolation")
    for name, definition in definitions.items():
        if name != JOB:
            require(not re.search(r"^    needs:.*\bgcs-oauth-experiment\b", definition, re.MULTILINE), "no_release_or_ledger_dependency")
            require("gcs-oauth-experiment.json" not in definition and "gcs-oauth/run_container.py" not in definition,
                    "no_extra_experiment_or_import")


class GcsWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8")

    def test_reviewed_workflow_has_one_manual_bounded_unqualified_job(self):
        validate(self.text)

    def test_automatic_default_or_sha_skip_cannot_enable_native_execution(self):
        mutations = (
            ("        default: false", "        default: true"),
            ("        type: boolean", "        type: string"),
            ("github.event_name == 'workflow_dispatch' && inputs.gcs_oauth_experiment", "inputs.gcs_oauth_experiment"),
            ("github.event_name == 'workflow_dispatch' && inputs.gcs_oauth_experiment",
             "github.event_name == 'workflow_dispatch' && inputs.gcs_oauth_experiment && inputs.expected_sha != ''"),
            ("&& -z \"$EXPECTED_SHA\"", "&& -n \"$EXPECTED_SHA\""),
            ("[[ \"$EXPECTED_SHA\" != \"$ACTUAL_SHA\" ]]", "[[ \"$EXPECTED_SHA\" == \"$ACTUAL_SHA\" ]]"),
            ("            exit 1\n          fi\n          if", "            exit 0\n          fi\n          if"),
        )
        for before, after in mutations:
            with self.subTest(mutation=before):
                self.assertIn(before, self.text)
                with self.assertRaises(ValueError):
                    validate(self.text.replace(before, after, 1))

    def test_unverified_runtime_extra_execution_or_artifact_scope_are_rejected(self):
        mutations = (
            ("[revision, test, python-audit]", "[revision, python-audit]"),
            ("    timeout-minutes: 25", "    timeout-minutes: 90"),
            ("bash scripts/download-rclone.sh --linux \"$RUNNER_TEMP/rclone-gcs-oauth\"", "curl https://example.invalid/runtime"),
            ("--report \"$RUNNER_TEMP/gcs-oauth-experiment.json\"", "--authentication-evidence --report \"$RUNNER_TEMP/gcs-oauth-experiment.json\""),
            ("--report \"$RUNNER_TEMP/gcs-oauth-experiment.json\"", "--report \"$RUNNER_TEMP/gcs-oauth-experiment.json\"; docker run unrelated"),
            ("path: ${{ runner.temp }}/gcs-oauth-experiment.json", "path: ${{ runner.temp }}/**"),
        )
        for before, after in mutations:
            with self.subTest(mutation=before), self.assertRaises(ValueError):
                validate(self.text.replace(before, after, 1))

    def test_privilege_and_release_or_ledger_expansion_are_rejected(self):
        for changed in (
            self.text.replace("permissions:\n  contents: read", "permissions:\n  contents: write", 1),
            self.text.replace("  gcs-oauth-experiment:\n", "  gcs-oauth-experiment:\n    permissions: write-all\n", 1),
            self.text.replace("  release:\n", "  release:\n    needs: [gcs-oauth-experiment]\n", 1),
            self.text.replace("  linux-provider-evidence:\n", "  linux-provider-evidence:\n    needs: [gcs-oauth-experiment]\n", 1),
        ):
            with self.subTest(), self.assertRaises(ValueError):
                validate(changed)


if __name__ == "__main__":
    unittest.main()
