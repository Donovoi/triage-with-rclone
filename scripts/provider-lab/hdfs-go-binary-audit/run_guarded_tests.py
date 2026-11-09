import sys
denied=[]
def guard(event,args):
 if event.startswith(('socket.','subprocess.','os.exec','os.spawn')) or event in {'os.system','os.posix_spawn','os.fork','os.forkpty','pty.spawn','ctypes.dlopen'}:
  denied.append(event);raise RuntimeError('denied')
sys.addaudithook(guard)
import unittest
from pathlib import Path
suite=unittest.defaultTestLoader.discover(str(Path(__file__).parent),pattern='test_*.py')
def identities(value):
 for item in value:
  if isinstance(item,unittest.TestSuite):yield from identities(item)
  else:yield item.id()
ids=list(identities(suite))
if len(ids)!=len(set(ids)):raise RuntimeError('duplicate test identities')
result=unittest.TextTestRunner(verbosity=1).run(suite)
print('Denied operation attempts:',len(denied))
raise SystemExit(0 if result.wasSuccessful() and not denied else 1)
