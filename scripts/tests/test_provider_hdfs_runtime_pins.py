"""Repository runtime pins must match every released-binary HDFS supervisor."""
import ast
import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class HdfsRuntimePinTests(unittest.TestCase):
    def test_released_runtime_and_java_sources_match_repository_pins(self):
        pins = dict(line.split("=", 1) for line in
                    (ROOT / "rclone-version.env").read_text().splitlines()
                    if line and not line.startswith("#"))
        controllers = []
        for path in sorted((ROOT / "scripts/provider-lab").glob("hdfs*/*container.py")):
            constants = {}
            for node in ast.parse(path.read_bytes()).body:
                if isinstance(node, ast.Assign) and len(node.targets) == 1:
                    target = node.targets[0]
                    if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
                        constants[target.id] = node.value.value
            if "RCLONE_VERSION" not in constants:
                continue  # Independently pinned source-build experiments have no release pin.
            controllers.append(path)
            with self.subTest(controller=path.parent.name):
                self.assertEqual(constants["RCLONE_VERSION"], pins["RCLONE_VERSION"])
                self.assertEqual(constants["RCLONE_SHA"], pins["RCLONE_LINUX_EXE_SHA256"])
                sources = list(path.parent.glob("HdfsKerberos*Probe.java"))
                self.assertEqual(len(sources), 1)
                source = sources[0].read_bytes()
                self.assertEqual(hashlib.sha256(source).hexdigest(), constants["JAVA_SHA"])
                self.assertIn(('startsWith("rclone v' + pins["RCLONE_VERSION"] + r'\n")').encode(), source)
        self.assertGreaterEqual(len(controllers), 7)


    def test_frozen_source_manifests_match_shared_helpers(self):
        base = ROOT / "scripts/provider-lab"
        for path in sorted(base.glob("hdfs*/source-pins.json")):
            with self.subTest(manifest=path.parent.name):
                raw = path.read_bytes()
                pins = json.loads(raw)
                for relative, expected in pins["files"].items():
                    with self.subTest(source=relative):
                        source = (base / relative).read_bytes()
                        self.assertEqual(expected, {"bytes": len(source),
                            "sha256": hashlib.sha256(source).hexdigest()})
                controllers = [p for p in path.parent.glob("*container.py")
                               if not p.name.startswith("test_")]
                self.assertEqual(len(controllers), 1)
                assignments = [node for node in ast.parse(controllers[0].read_bytes()).body
                               if isinstance(node, ast.Assign) and len(node.targets) == 1
                               and isinstance(node.targets[0], ast.Name)
                               and node.targets[0].id == "PINS_SHA"]
                self.assertEqual(len(assignments), 1)
                self.assertEqual(ast.literal_eval(assignments[0].value),
                                 hashlib.sha256(raw).hexdigest())

if __name__ == "__main__":
    unittest.main()
