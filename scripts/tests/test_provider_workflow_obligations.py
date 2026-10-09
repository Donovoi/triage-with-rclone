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

    def test_windows_target_inventory_uses_absolute_paths(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        job = workflow.split("  windows-architectures:\n", 1)[1].split("  linux-provider-evidence:\n", 1)[0]
        step = job.split("      - name: Record dependency inventory\n", 1)[1].split("      - name:", 1)[0]
        # The sanitizer deliberately rejects relative input/output paths. Both
        # flags must resolve from the same absolute checkout as the tested EXE.
        for flag, variable, binding in (
            ("--lockfile", "INVENTORY_LOCKFILE", "format('{0}/rclone-triage/Cargo.lock', github.workspace)"),
            ("--output", "INVENTORY_OUTPUT", "format('{0}/rclone-triage/target/{1}/release/dependencies.json', github.workspace, matrix.target)"),
        ):
            with self.subTest(flag=flag):
                argument = re.search(re.escape(flag) + r'\s+("[^"\n]+"|\S+)', step)
                self.assertIsNotNone(argument)
                self.assertEqual(argument.group(1), '"$env:' + variable + '"')
                self.assertIn(variable + ": ${{ " + binding + " }}", step)

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
                {"hdfs", "smb", "pcloud", "gcs"},  # GCS lifecycle is separate; static GCS is gated below.
                {"hdfs", "smb", "pcloud", "gcs"},  # Windows keeps static GCS; no borrowed lifecycle.
                {"hdfs"},                  # Combined Linux evidence; secure HDFS is still unverified.
            ],
            "provider-smoke.yml": [{"hdfs"}],
        }
        self.assertTrue(required)
        for filename, exceptions in unresolved.items():
            text = (ROOT / ".github" / "workflows" / filename).read_text(encoding="utf-8")
            gates = [step for step in re.split(r"(?m)^      - ", text) if "--require-fixtures" in step]
            self.assertEqual(text.count("--require-gcs-static-token"), 2 if filename == "ci.yml" else 0)
            values = re.findall(r"--require-fixtures\s+([a-z0-9_,]+)(?=\s|$)", text)
            self.assertEqual(len(values), text.count("--require-fixtures"), filename)
            self.assertEqual(len(values), len(exceptions), filename)
            for index, (value, missing) in enumerate(zip(values, exceptions)):
                with self.subTest(workflow=filename, gate=index):
                    names = value.split(",")
                    gated = set(names)
                    self.assertEqual(len(names), len(gated), "Duplicate fixture gate")
                    if filename == "ci.yml" and index < 2:
                        self.assertEqual(len(gated), 18)
                        self.assertEqual(gates[index].count("--require-gcs-static-token"), 1)
                        self.assertNotIn("gcs-oauth-lifecycle.json", gates[index])
                    else:
                        self.assertEqual(len(gated), 21)
                        self.assertNotIn("--require-gcs-static-token", gates[index])
                        self.assertIn("gcs-oauth-lifecycle.json", gates[index])
                    self.assertFalse(gated & missing, "Resolved exceptions must be removed")
                    self.assertEqual(gated | missing, required,
                                     "Every local obligation needs a gate or an explicit unresolved entry")


if __name__ == "__main__":
    unittest.main()
