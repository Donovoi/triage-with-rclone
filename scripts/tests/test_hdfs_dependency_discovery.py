"""Include the pure HDFS preparation regressions in both platform test suites."""
from pathlib import Path
import unittest


def load_tests(loader, standard_tests, pattern):
    root = Path(__file__).resolve().parents[1] / "provider-lab" / "hdfs-discovery"
    return unittest.TestLoader().discover(str(root), pattern="test_*.py", top_level_dir=str(root))
