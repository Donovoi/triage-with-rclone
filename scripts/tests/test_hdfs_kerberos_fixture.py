"""Run pure secure HDFS supervisor checks in both platform suites."""
from pathlib import Path
import unittest


def load_tests(loader, standard_tests, pattern):
    root = Path(__file__).resolve().parents[1] / "provider-lab" / "hdfs-kerberos-fixture"
    return unittest.TestLoader().discover(str(root), pattern="test_*.py", top_level_dir=str(root))
