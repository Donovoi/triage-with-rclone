"""Pure source contracts for same-run HDFS qualification and ingestion."""
from pathlib import Path
import re
import shlex
import unittest

from test_gcs_oauth_workflow_contract import command, jobs, require, scalar
from test_provider_gcs_lifecycle_workflow import steps

ROOT = Path(__file__).resolve().parents[2]
DOWNLOAD = "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
UPLOAD = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"


def folded_command(step):
    match = re.search(r"^        run: >-\n((?:          [^\n]+\n)+)", step, re.MULTILINE)
    require(match is not None, "qualified_command_required")
    return shlex.split(" ".join(line[10:] for line in match[1].splitlines()))


def validate(ci, smoke, transfer):
    for text, prerequisite, consumer in ((ci, "revision", "linux-provider-evidence"),
                                          (smoke, "python-audit", "provider-smoke-linux")):
        definitions = jobs(text)
        caller = definitions.get("hdfs-protocol", "")
        require(scalar(caller, "uses", 4) == "./.github/workflows/hdfs-kerberos-transfer.yml",
                "reviewed_reusable_workflow_required")
        require(scalar(caller, "needs", 4) == prerequisite, "caller_prerequisite_required")
        require(re.findall(r"^    ([a-z-]+):", caller, re.MULTILINE) ==
                ["name", "needs", "uses", "permissions"], "closed_caller_surface")
        require(re.findall(r"^      ([a-z-]+): ([^\n]+)$", caller, re.MULTILINE) ==
                [("contents", "read")], "read_only_caller")
        block = definitions[consumer]
        require("hdfs-protocol" in scalar(block, "needs", 4).strip("[]").split(", "),
                "consumer_dependency_required")
        parts = steps(block)
        downloads = [part for part in parts if "          name: hdfs-protocol\n" in part]
        require(len(downloads) == 1, "one_named_download")
        download = downloads[0]
        require(DOWNLOAD in download and scalar(download, "path", 10) == "${{ runner.temp }}/provider-hdfs",
                "reviewed_download_required")
        require(re.findall(r"^          ([a-z-]+):", download, re.MULTILINE) == ["name", "path"],
                "foreign_artifact_refused")
        gates = [part for part in parts if "--require-fixtures" in part]
        require(len(gates) == 1, "one_full_protocol_gate")
        args = command(gates[0])
        receipts = [args[i + 1] for i, arg in enumerate(args) if arg == "--fixture-receipt"]
        require(receipts.count("$RUNNER_TEMP/provider-hdfs/hdfs-protocol.json") == 1,
                "qualified_receipt_required")
        require(not any("hdfs-kerberos-transfer-experiment" in item for item in receipts),
                "raw_feasibility_refused")
        require(args.count("--require-fixtures") == 1, "one_fixture_gate")
        names = args[args.index("--require-fixtures") + 1].split(",")
        require(len(names) == len(set(names)) == 22 and "hdfs" in names, "hdfs_gate_required")
        require(parts.index(download) < parts.index(gates[0]), "download_before_import")
    require(re.search(r"^  workflow_call:\n", transfer, re.MULTILINE), "reusable_trigger_required")
    require("${{ github.event.pull_request.head.sha || github.sha }}" in transfer,
            "exact_revision_checkout")
    require("hdfs-kerberos-transfer-${{ github.workflow }}-" in transfer, "separate_concurrency_groups")
    require("  cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}" in transfer,
            "main_run_preservation")
    parts = steps(jobs(transfer)["transfer"])
    native = [p for p in parts if "/transfer_container.py" in p]
    qualify = [p for p in parts if "/protocol_evidence.py" in p]
    artifacts = [p for p in parts if "          name: hdfs-protocol\n" in p]
    require(len(native) == len(qualify) == len(artifacts) == 1, "one_producer_qualifier_artifact")
    require(parts.index(native[0]) < parts.index(qualify[0]) < parts.index(artifacts[0]),
            "native_before_qualification_before_upload")
    require(folded_command(qualify[0]) == ["python", "-I", "-S", "-B",
            "scripts/provider-lab/hdfs-kerberos-transfer/protocol_evidence.py",
            "--native-report", "${{ runner.temp }}/hdfs-kerberos-transfer-experiment.json",
            "--report", "${{ runner.temp }}/hdfs-protocol.json"], "closed_qualifier_command")
    require(UPLOAD in artifacts[0] and scalar(artifacts[0], "if-no-files-found", 10) == "error"
            and scalar(artifacts[0], "path", 10) == "${{ runner.temp }}/hdfs-protocol.json",
            "validated_artifact_required")
    for part in (native[0], qualify[0], artifacts[0]):
        require("        if:" not in part and "continue-on-error" not in part,
                "success_only_qualification")


class HdfsProtocolWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.ci = (ROOT / ".github/workflows/ci.yml").read_text()
        self.smoke = (ROOT / ".github/workflows/provider-smoke.yml").read_text()
        self.transfer = (ROOT / ".github/workflows/hdfs-kerberos-transfer.yml").read_text()

    def test_current_same_run_qualification_and_both_gates(self):
        validate(self.ci, self.smoke, self.transfer)

    def test_caller_dependency_permissions_and_foreign_artifacts_are_closed(self):
        for before, after in (
                ("    needs: [python-audit, hdfs-protocol]", "    needs: python-audit"),
                ("    needs: python-audit\n    uses: ./.github/workflows/hdfs-kerberos-transfer.yml",
                 "    needs: python-audit\n    if: false\n    uses: ./.github/workflows/hdfs-kerberos-transfer.yml"),
                ("      contents: read", "      contents: write"),
                ("      contents: read", "      contents: read\n      id-token: write"),
                ("          path: ${{ runner.temp }}/provider-hdfs", "          run-id: 123\n          path: ${{ runner.temp }}/provider-hdfs"),
                ('--fixture-receipt "$RUNNER_TEMP/provider-hdfs/hdfs-protocol.json"',
                 '--fixture-receipt "$RUNNER_TEMP/provider-hdfs/hdfs-kerberos-transfer-experiment.json"'),
                ("internetarchive,gcs,smb,pcloud,hdfs", "internetarchive,gcs,smb,pcloud")):
            self.assertIn(before, self.smoke)
            with self.subTest(mutation=before), self.assertRaises(ValueError):
                validate(self.ci, self.smoke.replace(before, after, 1), self.transfer)

    def test_qualification_cannot_be_skipped_or_publish_failed_proof(self):
        for before, after in (
                ("  workflow_call:\n", ""),
                ("hdfs-kerberos-transfer-${{ github.workflow }}-", "hdfs-kerberos-transfer-"),
                ("      - name: Qualify only the six HDFS protocol capabilities\n",
                 "      - name: Qualify only the six HDFS protocol capabilities\n        if: always()\n"),
                ("      - name: Retain the validated HDFS protocol envelope\n",
                 "      - name: Retain the validated HDFS protocol envelope\n        if: always()\n"),
                ("          if-no-files-found: error", "          if-no-files-found: warn"),
                ("--native-report", "--unqualified-report")):
            self.assertIn(before, self.transfer)
            with self.subTest(mutation=before), self.assertRaises(ValueError):
                validate(self.ci, self.smoke, self.transfer.replace(before, after, 1))


if __name__ == "__main__":
    unittest.main()
