"""Keep future local test obligations in CI, or explicitly unresolved."""
import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]


class WorkflowObligationTests(unittest.TestCase):
    def full_profile_gates(self, text, filename):
        gates = [step for step in re.split(r"(?m)^      - ", text) if "--require-fixtures" in step]
        scoped_count = 0
        if filename == "ci.yml":
            job = text.split("  windows-filesystem:\n", 1)[1].split("  windows-architectures:\n", 1)[0]
            scoped = [step for step in re.split(r"(?m)^      - ", job) if "--require-fixtures" in step]
            self.assertEqual(len(scoped), 1, "Exactly one filesystem matrix gate is required")
            self.assertEqual(scoped[0].splitlines()[0], "name: Require the same-build filesystem mode evidence")
            self.assertEqual(re.findall(r"^        backend: (.+)$", job, re.MULTILINE), ["[local, archive]"])
            self.assertEqual(re.findall(r"^          FILESYSTEM_BACKEND: (.+)$", scoped[0], re.MULTILINE),
                             ["${{ matrix.backend }}"])
            self.assertEqual(re.findall(r"--require-fixtures\s+(\S+)", scoped[0]), ["$env:FILESYSTEM_BACKEND"])
            gates = [step for step in gates if step != scoped[0]]
            scoped_count = 1
        # The scoped matrix is additional coverage. It cannot replace any full
        # profile list, and unrecognized variables or duplicate flags fail.
        full_text = "\n".join(gates)
        values = re.findall(r"--require-fixtures\s+([a-z0-9_,]+)(?=\s|$)", full_text)
        self.assertEqual(len(values), full_text.count("--require-fixtures"), filename)
        self.assertEqual(len(values) + scoped_count, text.count("--require-fixtures"), filename)
        return gates, values

    def test_unknown_or_changed_scoped_fixture_gates_are_rejected(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.full_profile_gates(text, "ci.yml")
        for original, changed in (
            ("backend: [local, archive]", "backend: [local, archive, http]"),
            ("FILESYSTEM_BACKEND: ${{ matrix.backend }}", "FILESYSTEM_BACKEND: local"),
            ("--require-fixtures $env:FILESYSTEM_BACKEND", "--require-fixtures $env:OTHER_BACKEND"),
            ("--require-fixtures $env:FILESYSTEM_BACKEND", ""),
            ("--require-fixtures $env:FILESYSTEM_BACKEND", "--require-fixtures local,archive"),
            ("--require-fixtures $env:FILESYSTEM_BACKEND", "--require-fixtures $env:FILESYSTEM_BACKEND --require-fixtures local"),
            ("name: Require the same-build filesystem mode evidence", "name: Unrecognized scoped gate"),
        ):
            with self.subTest(mutation=original), self.assertRaises(AssertionError):
                self.full_profile_gates(text.replace(original, changed), "ci.yml")
        with self.assertRaises(AssertionError):
            self.full_profile_gates(text + "\n      - run: importer --require-fixtures $env:UNREVIEWED\n", "ci.yml")

    def test_application_gate_uses_workspace_absolute_binary_paths(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        steps = re.split(r"(?m)^      - ", text)
        gates = [step for step in steps if "--require-application http" in step]
        expected = (
            ("name: Require the same-build HTTP application evidence",
             ["http-application.json"], None),
            ("name: Require the same-build configured WebDAV evidence",
             ["http-application.json", "webdav-application.json"],
             "webdav:webdav_basic_loopback_cli_v1:windows"),
        )
        self.assertEqual([gate.splitlines()[0] for gate in gates], [row[0] for row in expected])
        # The importer rejects relative runtime paths before reading a receipt.
        # Both build inputs must use the same checkout's absolute workspace.
        for gate, (name, receipts, mode) in zip(gates, expected):
            with self.subTest(gate=name):
                self.assertEqual(re.findall(r'--application-receipt\s+"\$RUNNER_TEMP/([^"\n]+)"', gate), receipts)
                self.assertEqual(len(re.findall(r"--application-receipt(?=[\s=])", gate)), len(receipts))
                self.assertEqual(re.findall(r"--require-application-mode\s+(\S+)", gate), [mode] if mode else [])
                self.assertEqual(len(re.findall(r"--require-application-mode(?=[\s=])", gate)), int(mode is not None))
                self.assertIn('--application-build-commit "$BUILD_COMMIT"', gate)
                self.assertEqual(len(re.findall(r"--application-build-commit(?=[\s=])", gate)), 1)
                for flag, variable, suffix in (
                    ("--rclone", "PROVIDER_BINARY", "rclone-triage/assets/rclone.exe"),
                    ("--application", "APPLICATION_BINARY", "rclone-triage/target/release/rclone-triage.exe"),
                ):
                    with self.subTest(flag=flag):
                        self.assertEqual(len(re.findall(re.escape(flag) + r"(?=[\s=])", gate)), 1)
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
            gates, values = self.full_profile_gates(text, filename)
            self.assertEqual(text.count("--require-gcs-static-token"), 2 if filename == "ci.yml" else 0)
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
