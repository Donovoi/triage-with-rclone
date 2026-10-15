#!/usr/bin/env python3
"""Closed inert parent/child fixture. Definitions only on import; no provider or app."""
import ctypes as C
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

SYNC, QUERY, DUP = 0x100000, 0x1000, 0x40
AMD64, UNKNOWN, TIMEOUT = 0x8664, 0, 258
HERE = Path(__file__).resolve()
REQUEST_KEYS = frozenset({'schema_version', 'nonce', 'controller', 'python_sha256', 'fixture_sha256', 'release', 'ready'})
TRANSFER_KEYS = frozenset({'schema_version', 'nonce', 'controller', 'python_sha256', 'fixture_sha256', 'child', 'child_handle'})


class FixtureError(ValueError):
    pass


def need(value, reason='fixture_failed'):
    if not value:
        raise FixtureError(reason)


def integer(value, low=1, high=2**64-2):
    need(type(value) is int and low <= value <= high)
    return value


def plain(path, directory=False):
    path = Path(path).absolute()
    for item in (path, *path.parents):
        info = item.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400)
    info = path.stat()
    need(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
    return info


def read(path, limit):
    before = plain(path)
    need(0 <= before.st_size <= limit)
    key = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
    with Path(path).open('rb') as source:
        opened = os.fstat(source.fileno())
        need(key(opened) == key(before))
        raw = source.read(limit + 1)
        after = os.fstat(source.fileno())
        need(key(after) == key(opened) and after.st_ctime_ns == opened.st_ctime_ns)
    last = plain(path)
    need(key(last) == key(before) and last.st_ctime_ns == before.st_ctime_ns and len(raw) == before.st_size)
    return raw


def digest(path, limit):
    return hashlib.sha256(read(path, limit)).hexdigest()


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def record(path):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result)
            result[key] = value
        return result
    return json.loads(read(path, 4096).decode('ascii'), object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(FixtureError('fixture_failed')))


def publish(path, value):
    raw = compact(value)
    need(len(raw) <= 4096)
    plain(Path(path).parent, True)
    with Path(path).open('xb') as output:
        need(output.write(raw) == len(raw))
        output.flush()


def identity(value):
    need(type(value) is dict and set(value) == {'pid', 'created', 'image'})
    integer(value['pid'], high=2**32-1)
    integer(value['created'])
    path = value['image']
    need(type(path) is str and 0 < len(path) < 32768 and not any(ord(c) < 32 for c in path))
    need(Path(path).is_absolute() and str(Path(path)) == path)
    return value


def request(value):
    need(type(value) is dict and set(value) == REQUEST_KEYS)
    need(type(value['schema_version']) is int and value['schema_version'] == 1)
    need(type(value['nonce']) is str and re.fullmatch('[0-9a-f]{32}', value['nonce']))
    identity(value['controller'])
    for key in ('python_sha256', 'fixture_sha256'):
        need(type(value[key]) is str and re.fullmatch('[0-9a-f]{64}', value[key]))
    integer(value['release']); integer(value['ready'])
    need(value['release'] != value['ready'])
    return value


def transfer(value, expected):
    request(expected)
    need(type(value) is dict and set(value) == TRANSFER_KEYS)
    for key in ('schema_version', 'nonce', 'controller', 'python_sha256', 'fixture_sha256'):
        need(type(value[key]) is type(expected[key]) and value[key] == expected[key])
    identity(value['child'])
    integer(value['child_handle'])
    need(value['child']['pid'] != expected['controller']['pid'])
    need(value['child']['image'] == expected['controller']['image'])
    need(value['child_handle'] not in (expected['release'], expected['ready']))
    return value


class Native:
    """Only documented fixed-width handle/identity/creation calls; no child kill API."""
    def __init__(self):
        need(os.name == 'nt' and C.sizeof(C.c_void_p) == 8)
        P, U, I = C.c_void_p, C.c_uint32, C.c_int32
        class FT(C.Structure):
            _fields_ = [('low', U), ('high', U)]
        class SA(C.Structure):
            _fields_ = [('size', U), ('descriptor', P), ('inherit', I)]
        class SI(C.Structure):
            _fields_ = [('cb', U), ('reserved', C.c_wchar_p), ('desktop', C.c_wchar_p), ('title', C.c_wchar_p),
                ('x', U), ('y', U), ('cx', U), ('cy', U), ('charsx', U), ('charsy', U), ('fill', U), ('flags', U),
                ('show', C.c_uint16), ('size', C.c_uint16), ('data', P), ('stdin', P), ('stdout', P), ('stderr', P)]
        class SIX(C.Structure):
            _fields_ = [('startup', SI), ('attributes', P)]
        class PI(C.Structure):
            _fields_ = [('process', P), ('thread', P), ('pid', U), ('tid', U)]
        self.FT, self.SA, self.SIX, self.PI = FT, SA, SIX, PI
        self.k = C.WinDLL('kernel32', use_last_error=True)
        signatures = {
            'GetCurrentProcess': ([], P), 'GetProcessId': ([P], U),
            'GetProcessTimes': ([P, C.POINTER(FT), C.POINTER(FT), C.POINTER(FT), C.POINTER(FT)], I),
            'QueryFullProcessImageNameW': ([P, U, C.c_wchar_p, C.POINTER(U)], I),
            'IsWow64Process2': ([P, C.POINTER(C.c_uint16), C.POINTER(C.c_uint16)], I),
            'OpenProcess': ([U, I, U], P), 'CloseHandle': ([P], I),
            'CreateEventW': ([P, I, I, C.c_wchar_p], P), 'SetEvent': ([P], I),
            'WaitForSingleObject': ([P, U], U), 'GetExitCodeProcess': ([P, C.POINTER(U)], I),
            'GetHandleInformation': ([P, C.POINTER(U)], I),
            'DuplicateHandle': ([P, P, P, C.POINTER(P), U, I, U], I),
            'GetStdHandle': ([U], P), 'GetFileType': ([P], U),
            'CreateFileW': ([C.c_wchar_p, U, U, C.POINTER(SA), U, U, P], P),
            'InitializeProcThreadAttributeList': ([P, U, U, C.POINTER(C.c_size_t)], I),
            'UpdateProcThreadAttribute': ([P, U, C.c_size_t, P, C.c_size_t, P, P], I),
            'DeleteProcThreadAttributeList': ([P], None),
            'CreateProcessW': ([C.c_wchar_p, C.c_wchar_p, P, P, I, U, P, C.c_wchar_p, C.POINTER(SIX), C.POINTER(PI)], I),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.k, name)
            function.argtypes, function.restype = args, result

    def current(self):
        return self.k.GetCurrentProcess()

    def close(self, handle):
        need(self.k.CloseHandle(handle) != 0, 'handle_close_failed')

    def identify(self, handle):
        pid = self.k.GetProcessId(handle)
        values = [self.FT() for _ in range(4)]
        need(self.k.GetProcessTimes(handle, *(C.byref(v) for v in values)) != 0)
        length = C.c_uint32(32768)
        image = C.create_unicode_buffer(length.value)
        need(self.k.QueryFullProcessImageNameW(handle, 0, image, C.byref(length)) != 0 and 0 < length.value < 32768)
        return identity(dict(pid=pid, created=values[0].low | values[0].high << 32, image=image.value))

    def x64(self, handle):
        process, native = C.c_uint16(), C.c_uint16()
        need(self.k.IsWow64Process2(handle, C.byref(process), C.byref(native)) != 0)
        need(process.value == UNKNOWN and native.value == AMD64, 'architecture_failed')
        return True

    def flags(self, handle, expected):
        flags = C.c_uint32()
        need(self.k.GetHandleInformation(handle, C.byref(flags)) != 0 and flags.value == expected)

    def event(self):
        handle = self.k.CreateEventW(None, 1, 0, None)
        integer(handle)
        self.flags(handle, 0)
        return handle

    def signal(self, handle):
        need(self.k.SetEvent(handle) != 0, 'release_failed')

    def wait(self, handle, milliseconds):
        integer(milliseconds, 0, 45000)
        result = self.k.WaitForSingleObject(handle, milliseconds)
        need(result in (0, TIMEOUT), 'wait_failed')
        return result == 0

    def exit_code(self, handle):
        value = C.c_uint32()
        need(self.k.GetExitCodeProcess(handle, C.byref(value)) != 0)
        return value.value

    def open_controller(self, value):
        handle = self.k.OpenProcess(SYNC | QUERY | DUP, 0, value['pid'])
        integer(handle)
        return handle

    def duplicate(self, source_process, source, target_process, access, inherit=False, same_access=False):
        output = C.c_void_p()
        need(self.k.DuplicateHandle(source_process, source, target_process, C.byref(output), access,
                                   int(inherit), 2 if same_access else 0) != 0)
        return integer(output.value)

    def stdout(self):
        value = self.k.GetStdHandle((-11) & 0xffffffff)
        integer(value)
        need(self.k.GetFileType(value) == 3)
        return value

    def null(self, readable):
        security = self.SA(C.sizeof(self.SA), None, 1)
        value = self.k.CreateFileW('NUL', 0x80000000 if readable else 0x40000000, 3,
                                  C.byref(security), 3, 0x80, None)
        integer(value)
        need(value != C.c_void_p(-1).value)
        return value

    def create_child(self, args, handles, result):
        # result is retained by the caller even if CreateProcess returns ambiguously.
        need(len(handles) == 5 and len(set(handles)) == 5)
        for handle in handles:
            self.flags(handle, 1)
        size = C.c_size_t()
        self.k.InitializeProcThreadAttributeList(None, 1, 0, C.byref(size))
        need(0 < size.value <= 65536)
        storage = C.create_string_buffer(size.value)
        inherited = (C.c_void_p * 5)(*handles)
        startup = self.SIX()
        startup.startup.cb, startup.startup.flags, startup.startup.show = C.sizeof(startup), 0x101, 0
        startup.startup.stdin, startup.startup.stdout, startup.startup.stderr = handles[:3]
        startup.attributes = C.addressof(storage)
        initialized = False
        try:
            need(self.k.InitializeProcThreadAttributeList(storage, 1, 0, C.byref(size)) != 0)
            initialized = True
            need(self.k.UpdateProcThreadAttribute(storage, 0, 0x20002, inherited, C.sizeof(inherited), None, None) != 0)
            command = C.create_unicode_buffer(subprocess.list2cmdline(args))
            need(self.k.CreateProcessW(args[0], command, None, None, 1, 0x80000 | 0x08000000,
                                      None, None, C.byref(startup), C.byref(result)) != 0)
            need(result.process and result.thread)
        finally:
            if initialized:
                self.k.DeleteProcThreadAttributeList(storage)


def source_identity(api, expected, fixture=HERE):
    current = api.identify(api.current())
    need(current['image'] == expected['controller']['image'])
    api.x64(api.current())
    need(digest(current['image'], 32*1024*1024) == expected['python_sha256'])
    need(digest(fixture, 256*1024) == expected['fixture_sha256'])
    return current


def close_known(api, handles):
    failed = False
    for handle in handles:
        try:
            api.close(handle)
        except BaseException:
            failed = True
    need(not failed, 'handle_close_failed')


def parent(api, request_path):
    expected = request(record(request_path))
    source_identity(api, expected)
    owned, result, succeeded = [], api.PI(), False
    try:
        controller = api.open_controller(expected['controller']); owned.append(controller)
        need(api.identify(controller) == expected['controller'] and not api.wait(controller, 0))
        api.flags(controller, 0)
        local = api.current()
        release = api.duplicate(controller, expected['release'], local, SYNC, True); owned.append(release)
        ready = api.duplicate(controller, expected['ready'], local, 2, True); owned.append(ready)
        stdin = api.null(True); owned.append(stdin)
        stderr = api.null(False); owned.append(stderr)
        stdout = api.duplicate(local, api.stdout(), local, 0, True, True); owned.append(stdout)
        need(not api.wait(release, 0))
        args = [expected['controller']['image'], '-B', '-I', '-S', str(HERE), 'child', str(request_path), str(release), str(ready)]
        api.create_child(args, [stdin, stdout, stderr, release, ready], result)
        # Register only the actual returned handles; never reopen the child's PID.
        owned.extend([result.thread, result.process])
        child = api.identify(result.process)
        need(child['pid'] == result.pid and child['image'] == expected['controller']['image'])
        api.x64(result.process)
        transferred = api.duplicate(local, result.process, controller, SYNC | QUERY)
        value = {key: expected[key] for key in ('schema_version', 'nonce', 'controller', 'python_sha256', 'fixture_sha256')}
        value.update(child=child, child_handle=transferred)
        transfer(value, expected)
        publish(Path(request_path).with_name('transfer.json'), value)
        succeeded = True
    finally:
        # Any ambiguous creation/duplication fails. No child termination or inferred closure.
        try:
            close_known(api, list(reversed(owned)))
        except BaseException:
            succeeded = False
    need(succeeded)
    return 0


def child(api, request_path, release, ready):
    expected = request(record(request_path))
    source_identity(api, expected)
    integer(release); integer(ready); need(release != ready)
    api.stdout()
    need(not api.wait(release, 0))
    result = 32
    try:
        api.signal(ready)
        result = 0 if api.wait(release, 45000) else 33
    finally:
        close_known(api, [ready, release])
    return result


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        need(type(args) is list and all(type(v) is str for v in args))
        need(len(args) in (2, 4) and args[0] in ('parent', 'child'))
        need(len(args) == (2 if args[0] == 'parent' else 4))
        path = Path(args[1]); need(path.is_absolute() and path.name == 'request.json')
        plain(path.parent, True)
        api = Native()
        if args[0] == 'parent':
            return parent(api, path)
        need(all(re.fullmatch('[1-9][0-9]{0,19}', v) for v in args[2:]))
        return child(api, path, int(args[2]), int(args[3]))
    except BaseException:
        return 31


if __name__ == '__main__':
    raise SystemExit(main())
