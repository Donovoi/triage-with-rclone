"""Keep future local test obligations in CI, or explicitly unresolved."""
import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]


class WorkflowObligationTests(unittest.TestCase):
    def test_application_gate_uses_workspace_absolute_binary_paths(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        steps = re.split(r"(?m)^      - ", text)
        gates = [step for step in steps if "--require-application http" in step]
        self.assertEqual(len(gates), 1)
        gate = gates[0]
        # The importer rejects relative runtime paths before reading a receipt.
        # Both build inputs must use the same checkout's absolute workspace.
        for flag, variable, suffix in (
            ("--rclone", "PROVIDER_BINARY", "rclone-triage/assets/rclone.exe"),
            ("--application", "APPLICATION_BINARY", "rclone-triage/target/release/rclone-triage.exe"),
        ):
            with self.subTest(flag=flag):
                match = re.search(re.escape(flag) + r'\s+("[^"\n]+"|\S+)', gate)
                self.assertIsNotNone(match)
                self.assertEqual(match.group(1), '"$' + variable + '"')
                self.assertIn(variable + ": ${{ format('{0}/" + suffix + "', github.workspace) }}", gate)

    def test_every_local_obligation_is_gated_or_explicitly_unresolved(self):
        policy = json.loads((ROOT / "provider-coverage-policy.json").read_text(encoding="utf-8"))
        required = {
            backend for backend, plan in policy["providers"].items()
            if policy["profiles"][plan["profile"]]["required"].get("local_protocol")
        }
        # These are missing coverage, not passing tests. Remove each exception
        # when its gate is enabled. A new obligation must receive an explicit
        # decision here; it must not silently escape the workflow's fixed list.
        unresolved = {
            "ci.yml": [
                {"hdfs", "smb", "pcloud"},  # Cross-platform matrix; latter two run in separate Linux jobs.
                {"hdfs", "smb", "pcloud"},  # Windows application ledger reuses that protocol evidence.
                {"hdfs"},                  # Combined Linux evidence; secure HDFS is still unverified.
            ],
            "provider-smoke.yml": [{"hdfs"}],
        }
        self.assertTrue(required)
        for filename, exceptions in unresolved.items():
            text = (ROOT / ".github" / "workflows" / filename).read_text(encoding="utf-8")
            values = re.findall(r"--require-fixtures\s+([a-z0-9_,]+)(?=\s|$)", text)
            self.assertEqual(len(values), text.count("--require-fixtures"), filename)
            self.assertEqual(len(values), len(exceptions), filename)
            for index, (value, missing) in enumerate(zip(values, exceptions)):
                with self.subTest(workflow=filename, gate=index):
                    names = value.split(",")
                    gated = set(names)
                    self.assertEqual(len(names), len(gated), "Duplicate fixture gate")
                    self.assertFalse(gated & missing, "Resolved exceptions must be removed")
                    self.assertEqual(gated | missing, required,
                                     "Every local obligation needs a gate or an explicit unresolved entry")


if __name__ == "__main__":
    unittest.main()
