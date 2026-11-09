import sys,unittest
from pathlib import Path
denied=[]
def guard(e,a):
    if e.startswith(('socket.','subprocess.','os.exec','os.spawn')) or e in {'os.system','os.posix_spawn','os.fork','os.forkpty','pty.spawn','ctypes.dlopen'}:
        denied.append(e);raise RuntimeError('operation_denied')
sys.addaudithook(guard)
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
suite=unittest.defaultTestLoader.loadTestsFromNames(['test_mit_runtime_bundle','test_mit_kdc_plan','test_mit_kdc_container'])
result=unittest.TextTestRunner(verbosity=2).run(suite)
print('Denied operation attempts:',len(denied))
raise SystemExit(0 if result.wasSuccessful() and not denied else 1)
