"""Pure Python contracts with process/network denial before candidate imports."""
from pathlib import Path
import sys
import unittest

DENIED = []


def guard(event, args):
    if event.startswith(("socket.", "subprocess.", "os.exec", "os.spawn")) or event in {
        "os.system", "os.posix_spawn", "os.fork", "os.forkpty", "pty.spawn", "ctypes.dlopen"
    }:
        DENIED.append(event)
        raise RuntimeError("pure_contract_operation_denied")


sys.addaudithook(guard)
sys.dont_write_bytecode = True
suite = unittest.defaultTestLoader.discover(str(Path(__file__).resolve().parent), pattern="test_*.py")
result = unittest.TextTestRunner(verbosity=2).run(suite)
print("Denied operation attempts:", len(DENIED))
raise SystemExit(0 if result.wasSuccessful() and not DENIED else 1)
