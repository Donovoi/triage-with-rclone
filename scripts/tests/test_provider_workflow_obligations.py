"""Keep future local test obligations in CI, or explicitly unresolved."""
import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]


class WorkflowObligationTests(unittest.TestCase):
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
                {"hdfs", "smb", "pcloud"},  # Cross-platform matrix; latter two run in separate Linux jobs.
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
