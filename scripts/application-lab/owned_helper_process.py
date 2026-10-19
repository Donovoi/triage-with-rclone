"""Retained helper ownership. Import defines Python state; Win32 is lazy.

Only the registered HTTP loader may admit helpers. No waiting destructor, tree
termination, PID reopening, retry or public reset exists. Native uncertainty is
retained independently of a constructor's caller.
"""
from contextlib import contextmanager
import ctypes as C
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

API_VERSION = 1
SLOT = "_triage_acceptance_helper_owner"
_lock = threading.Lock()
_active = None
_poisoned = False


class OwnershipError(OSError):
    """Closed failure text; never contains a native message or source path."""


def need(value):
    if not value:
        raise OwnershipError("helper_ownership_failed")


def _registered():
    envelope = globals().get("_registration")
    need(type(envelope) is dict and getattr(sys, SLOT, None) is envelope and
         envelope.get("state") == "ready" and envelope.get("module") is globals().get("_module_identity") and
         envelope.get("token") is globals().get("_registration_token") and
         envelope.get("api") == API_VERSION)
    # The HTTP loader supplies the strict, source-bound preservation callback.
    envelope["preserved"]()
    return envelope


def _reserve(owner):
    global _active
    _registered()
    with _lock:
        need(not _poisoned and _active is None)
        _active = owner


def _poison(owner):
    global _poisoned
    with _lock:
        _poisoned = True
        # Never replace the first retained reservation with a later owner.
        if _active is not owner:
            owner.uncertain = True
    owner.uncertain = True


class _Handle:
    def __init__(self, owner):
        self.owner, self.value = owner, None
        self.lock = threading.Lock()
        self.users, self.attempted, self.closed = 0, False, None

    @contextmanager
    def borrow(self):
        with self.lock:
            need(self.value is not None and not self.attempted)
            self.users += 1
            value = self.value
        try:
            yield value
        finally:
            with self.lock:
                self.users -= 1

    def close(self):
        with self.lock:
            if self.value is None:
                return self.closed is not False
            if self.attempted:
                return self.closed is True
            if self.users:
                return False
            self.attempted = True
            value = self.value
        try:
            self.owner.api.close(value)
        except OwnershipError:
            self.closed = False
            _poison(self.owner)
            raise
        except BaseException:
            self.closed = None  # The call may have completed before interruption.
            _poison(self.owner)
            raise
        self.closed = True
        return True


class _Pipe:
    def __init__(self, owner, handle, readable):
        self.owner, self.handle, self.readable = owner, handle, readable
        self.requested = False

    @property
    def closed(self):
        return self.handle.closed is True

    def _finish_requested(self):
        if self.requested:
            try:
                if not self.handle.close():
                    _poison(self.owner)
            except BaseException:
                _poison(self.owner)

    def read1(self, size):
        need(self.readable and type(size) is int and 0 < size <= 4096)
        try:
            with self.handle.borrow() as handle:
                return self.owner.api.read(handle, size)
        finally:
            self._finish_requested()

    def write(self, data):
        need(not self.readable and type(data) is bytes and len(data) <= 65536)
        try:
            with self.handle.borrow() as handle:
                return self.owner.api.write(handle, data)
        finally:
            self._finish_requested()

    def flush(self):
        need(not self.closed)  # Raw WriteFile has no Python output buffer.

    def close(self):
        self.requested = True
        if not self.handle.close():
            # Never close a handle beneath an outstanding read/write. Returning
            # here is not closure: finalized() checks actual close facts.
            _poison(self.owner)


class _Win32:
    """Documented fixed-width ABI; constructed only after admission."""
    def __init__(self):
        need(os.name == "nt")
        U32, I32, PTR = C.c_uint32, C.c_int32, C.c_void_p
        class SA(C.Structure):
            _fields_ = [("length", U32), ("descriptor", PTR), ("inherit", I32)]
        class SI(C.Structure):
            _fields_ = [("cb", U32), ("reserved", C.c_wchar_p), ("desktop", C.c_wchar_p),
                ("title", C.c_wchar_p), ("x", U32), ("y", U32), ("xsize", U32), ("ysize", U32),
                ("xchars", U32), ("ychars", U32), ("fill", U32), ("flags", U32),
                ("show", C.c_uint16), ("reserved_size", C.c_uint16), ("reserved_data", PTR),
                ("stdin", PTR), ("stdout", PTR), ("stderr", PTR)]
        class SIX(C.Structure):
            _fields_ = [("startup", SI), ("attributes", PTR)]
        class PI(C.Structure):
            _fields_ = [("process", PTR), ("thread", PTR), ("pid", U32), ("tid", U32)]
        class TIMES(C.Structure):
            _fields_ = [("low", U32), ("high", U32)]
        class ACCOUNT(C.Structure):
            _fields_ = [("user", C.c_int64), ("kernel", C.c_int64),
                ("period_user", C.c_int64), ("period_kernel", C.c_int64),
                ("faults", U32), ("total", U32), ("active", U32), ("terminated", U32)]
        self.SA, self.SIX, self.PI, self.TIMES, self.ACCOUNT = SA, SIX, PI, TIMES, ACCOUNT
        self.k = C.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CreateJobObjectW": ([PTR, C.c_wchar_p], PTR),
            "CreatePipe": ([C.POINTER(PTR), C.POINTER(PTR), C.POINTER(SA), U32], I32),
            "SetHandleInformation": ([PTR, U32, U32], I32),
            "CreateFileW": ([C.c_wchar_p, U32, U32, C.POINTER(SA), U32, U32, PTR], PTR),
            "InitializeProcThreadAttributeList": ([PTR, U32, U32, C.POINTER(C.c_size_t)], I32),
            "UpdateProcThreadAttribute": ([PTR, U32, C.c_size_t, PTR, C.c_size_t, PTR, PTR], I32),
            "DeleteProcThreadAttributeList": ([PTR], None),
            "CreateProcessW": ([C.c_wchar_p, C.c_wchar_p, PTR, PTR, I32, U32, PTR, C.c_wchar_p,
                                 C.POINTER(SIX), C.POINTER(PI)], I32),
            "IsProcessInJob": ([PTR, PTR, C.POINTER(I32)], I32),
            "QueryFullProcessImageNameW": ([PTR, U32, C.c_wchar_p, C.POINTER(U32)], I32),
            "GetProcessTimes": ([PTR, C.POINTER(TIMES), C.POINTER(TIMES), C.POINTER(TIMES), C.POINTER(TIMES)], I32),
            "ResumeThread": ([PTR], U32), "CloseHandle": ([PTR], I32),
            "WaitForSingleObject": ([PTR, U32], U32),
            "GetExitCodeProcess": ([PTR, C.POINTER(U32)], I32),
            "TerminateProcess": ([PTR, U32], I32),
            "QueryInformationJobObject": ([PTR, I32, PTR, U32, C.POINTER(U32)], I32),
            "ReadFile": ([PTR, PTR, U32, C.POINTER(U32), PTR], I32),
            "WriteFile": ([PTR, PTR, U32, C.POINTER(U32), PTR], I32),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.k, name)
            function.argtypes, function.restype = arguments, result

    def close(self, handle):
        need(self.k.CloseHandle(handle) != 0)

    def job(self):
        handle = self.k.CreateJobObjectW(None, None)
        need(handle not in (None, 0, C.c_void_p(-1).value))
        return handle

    def pipe(self, read_cell, write_cell, parent):
        a, b = C.c_void_p(), C.c_void_p()
        security = self.SA(C.sizeof(self.SA), None, 1)
        need(self.k.CreatePipe(C.byref(a), C.byref(b), C.byref(security), 0) != 0)
        read_cell.value, write_cell.value = a.value, b.value
        need(self.k.SetHandleInformation(parent.value, 1, 0) != 0)

    def null(self, readable):
        security = self.SA(C.sizeof(self.SA), None, 1)
        handle = self.k.CreateFileW("NUL", 0x80000000 if readable else 0x40000000,
                                    3, C.byref(security), 3, 0x80, None)
        need(handle not in (None, 0, C.c_void_p(-1).value))
        return handle

    def create(self, owner, args, env, cwd, flags, startupinfo):
        size = C.c_size_t()
        self.k.InitializeProcThreadAttributeList(None, 2, 0, C.byref(size))
        need(0 < size.value <= 65536)
        storage = C.create_string_buffer(size.value)
        initialized = False
        jobs = (C.c_void_p * 1)(owner.job.value)
        inherited = (C.c_void_p * 3)(*(cell.value for cell in owner.child))
        startup = self.SIX()
        startup.startup.cb = C.sizeof(startup)
        startup.startup.flags = 0x100 | 1  # USESTDHANDLES | USESHOWWINDOW
        startup.startup.show = 0
        startup.startup.stdin, startup.startup.stdout, startup.startup.stderr = inherited
        startup.attributes = C.addressof(storage)
        command = C.create_unicode_buffer(subprocess.list2cmdline(args))
        environment = C.create_unicode_buffer("\0".join(f"{key}={env[key]}" for key in sorted(env, key=str.upper)) + "\0\0")
        owner.pi = self.PI()  # Kept even when creation's returned result is uncertain.
        try:
            need(self.k.InitializeProcThreadAttributeList(storage, 2, 0, C.byref(size)) != 0)
            initialized = True
            need(self.k.UpdateProcThreadAttribute(storage, 0, 0x20002, inherited, C.sizeof(inherited), None, None) != 0)
            need(self.k.UpdateProcThreadAttribute(storage, 0, 0x2000D, jobs, C.sizeof(jobs), None, None) != 0)
            owner.creation_attempted = True
            result = self.k.CreateProcessW(args[0], command, None, None, 1,
                flags | 0x80000 | 0x400 | 4, environment, str(cwd) if cwd is not None else None,
                C.byref(startup), C.byref(owner.pi))
            owner.creation_resolved = True
            if not result:
                need(not owner.pi.process and not owner.pi.thread)
                raise OwnershipError("helper_ownership_failed")
            owner.process.value, owner.primary_thread.value = owner.pi.process, owner.pi.thread
            owner.created = True
            need(bool(owner.process.value) and bool(owner.primary_thread.value))
        finally:
            if initialized:
                self.k.DeleteProcThreadAttributeList(storage)
            # Storage and both value arrays remain live through destruction.

    def identity(self, process, job, expected):
        member = C.c_int32()
        need(self.k.IsProcessInJob(process, job, C.byref(member)) != 0 and member.value == 1)
        count = C.c_uint32(32768)
        path = C.create_unicode_buffer(count.value)
        need(self.k.QueryFullProcessImageNameW(process, 0, path, C.byref(count)) != 0 and 0 < count.value < 32768)
        need(os.path.normcase(os.path.normpath(path.value)) == os.path.normcase(os.path.normpath(expected)))
        times = [self.TIMES() for _ in range(4)]
        need(self.k.GetProcessTimes(process, *(C.byref(value) for value in times)) != 0)
        created = times[0].low | (times[0].high << 32)
        need(created > 0)
        return created

    def resume(self, handle):
        need(self.k.ResumeThread(handle) == 1)

    def wait(self, handle, timeout):
        need(type(timeout) in (int, float) and math.isfinite(timeout) and 0 <= timeout <= 165)
        outcome = self.k.WaitForSingleObject(handle, int(timeout * 1000))
        need(outcome in (0, 258))
        if outcome == 258:
            return None
        code = C.c_uint32()
        need(self.k.GetExitCodeProcess(handle, C.byref(code)) != 0)
        return code.value

    def kill(self, handle):
        if not self.k.TerminateProcess(handle, 1):
            need(self.wait(handle, 0) is not None)  # Already-exited parent only.

    def accounting(self, handle):
        value, returned = self.ACCOUNT(), C.c_uint32()
        need(self.k.QueryInformationJobObject(handle, 1, C.byref(value), C.sizeof(value), C.byref(returned)) != 0)
        need(returned.value == C.sizeof(value))
        return value.active, value.total

    def read(self, handle, size):
        buffer, count = C.create_string_buffer(size), C.c_uint32()
        if not self.k.ReadFile(handle, buffer, size, C.byref(count), None):
            need(C.get_last_error() == 109)  # ERROR_BROKEN_PIPE is EOF.
            return b""
        need(count.value <= size)
        return buffer.raw[:count.value]

    def write(self, handle, data):
        if not data:
            return 0
        buffer, count = C.create_string_buffer(data, len(data)), C.c_uint32()
        need(self.k.WriteFile(handle, buffer, len(data), C.byref(count), None) != 0 and count.value <= len(data))
        return count.value


_native_factory = _Win32


class HelperProcess:
    def __init__(self, args, *, env, cwd=None, stdin=subprocess.PIPE,
                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, startupinfo=None,
                 creationflags=0x08000000):
        need(type(args) is list and args and all(type(v) is str and "\0" not in v for v in args))
        need(type(env) is dict and env and all(type(k) is str and type(v) is str and
             k and "=" not in k and "\0" not in k + v for k, v in env.items()))
        need(creationflags == 0x08000000 and stdout == subprocess.PIPE and
             (stdin, stderr) in ((subprocess.PIPE, subprocess.PIPE), (subprocess.DEVNULL, subprocess.DEVNULL)))
        if startupinfo is not None:
            need(startupinfo.dwFlags == 1 and startupinfo.wShowWindow == 0)
        self.args, self.api, self.pi = args, None, None
        self.uncertain = self.created = self.creation_attempted = self.creation_resolved = self.resumed = False
        self.resume_attempted = False
        self.returncode, self.creation_identity = None, None
        self.forced, self.finalized, self.final_result = False, False, None
        self.termination_lock = threading.Lock()
        self.termination_attempted = self.termination_returned = False
        self.active_count = self.total_count = None
        self.stage = "allocate"
        self.job, self.process, self.primary_thread = (_Handle(self) for _ in range(3))
        self.child = [_Handle(self) for _ in range(3)]
        self.parent = [_Handle(self) for _ in range(3)]
        self.stdin = self.stdout = self.stderr = None
        _reserve(self)
        try:
            self.api = _native_factory()
            self.stage = "job"
            self.job.value = self.api.job()
            self.stage = "pipes"
            if stdin == subprocess.PIPE:
                self.api.pipe(self.child[0], self.parent[0], self.parent[0])
                self.stdin = _Pipe(self, self.parent[0], False)
            else:
                self.child[0].value = self.api.null(True)
            self.api.pipe(self.parent[1], self.child[1], self.parent[1])
            self.stdout = _Pipe(self, self.parent[1], True)
            if stderr == subprocess.PIPE:
                self.api.pipe(self.parent[2], self.child[2], self.parent[2])
                self.stderr = _Pipe(self, self.parent[2], True)
            else:
                self.child[2].value = self.api.null(False)
            self.stage = "create"
            self.api.create(self, args, env, cwd, creationflags, startupinfo)
            need(self.creation_resolved and self.created)
            # Parent copies of inherited child ends cannot retain a pipe writer.
            for cell in self.child:
                need(cell.close())
            self.stage = "identity"
            with self.process.borrow() as process, self.job.borrow() as job:
                self.creation_identity = self.api.identity(process, job, args[0])
            self.stage = "resume"
            with self.primary_thread.borrow() as thread:
                self.resume_attempted = True
                self.api.resume(thread)
            self.resumed = True
            need(self.primary_thread.close())
            self.stage = "running"
        except BaseException:
            # A partially created owner is retained before any caller can lose it.
            if not (self.creation_resolved and self.created):
                _poison(self)
            try:
                self._failure_cleanup(time.monotonic() + 5)
            except BaseException:
                _poison(self)
            raise

    def mark_uncertain(self):
        _poison(self)

    def poll(self):
        if self.returncode is not None:
            return self.returncode
        with self.process.borrow() as handle:
            result = self.api.wait(handle, 0)
        if result is not None:
            need(type(result) is int and 0 <= result < 2**32)
            self.returncode = result
        return self.returncode

    def wait(self, timeout=None):
        need(type(timeout) in (int, float) and math.isfinite(timeout) and 0 <= timeout <= 165)
        if self.returncode is None:
            with self.process.borrow() as handle:
                result = self.api.wait(handle, timeout)
            if result is None:
                raise subprocess.TimeoutExpired(self.args, timeout)
            need(type(result) is int and 0 <= result < 2**32)
            self.returncode = result
        return self.returncode

    def kill(self):
        if self.returncode is not None:
            return  # No new termination after an already observed exit.
        if not self.termination_lock.acquire(blocking=False):
            _poison(self)
            raise OwnershipError()
        try:
            if self.termination_attempted:
                need(self.termination_returned)
                return
            self.termination_attempted = self.forced = True
            with self.process.borrow() as handle:
                self.api.kill(handle)
            self.termination_returned = True
        except BaseException:
            _poison(self)
            raise
        finally:
            self.termination_lock.release()

    def _failure_cleanup(self, deadline, *, kill=True):
        if self.created and self.creation_resolved:
            if kill:
                try:
                    self.kill()
                except BaseException:
                    _poison(self)
            try:
                self.wait(timeout=max(0, deadline - time.monotonic()))
            except BaseException:
                _poison(self)
        for stream in (self.stdin, self.stdout, self.stderr):
            if stream is not None:
                try:
                    stream.close()
                except BaseException:
                    _poison(self)
        # Factory failure has no readers. Release every known allocated pipe,
        # including one whose wrapper was not yet constructed. Unknown returned
        # creation handles remain in pi and are never guessed/closed here.
        for cell in self.parent:
            try:
                if not cell.close():
                    _poison(self)
            except BaseException:
                _poison(self)
        self.finalize()

    def finalize(self):
        """One nonwaiting terminal proof; never adds a process wait or kill."""
        global _active
        if self.finalized:
            return self.final_result is True
        self.finalized = True
        def close(cell):
            try:
                return self.api is not None and cell.close()
            except BaseException:
                return False
        # Independent known resources are still attempted when another close
        # fails; no retry of a failed/ambiguous close is made.
        child_closed = [close(cell) for cell in self.child]
        thread_closed = close(self.primary_thread)
        pipe_closed = all(cell.value is None or cell.closed is True for cell in self.parent)
        process_closed = job_closed = quiet = False
        if self.creation_resolved and self.created and self.returncode is not None:
            self.stage = "process_close"
            process_closed = close(self.process)
            if process_closed:
                try:
                    self.stage = "accounting"
                    with self.job.borrow() as handle:
                        active, total = self.api.accounting(handle)
                    need(type(active) is int and type(total) is int and 0 <= active <= total < 2**32)
                    self.active_count, self.total_count = active, total
                    quiet = active == 0
                except BaseException:
                    _poison(self)
                self.stage = "job_close"
                job_closed = close(self.job)
        elif not self.creation_attempted or self.creation_resolved and not self.created:
            close(self.job)  # Known allocation only; no launch/closure credit.
        result = bool(all(child_closed) and thread_closed and pipe_closed and process_closed and
                      job_closed and quiet and not self.uncertain)
        if result:
            self.stage = "closed"
        else:
            _poison(self)
        self.final_result = result
        if result:
            with _lock:
                if _active is self and not _poisoned:
                    _active = None
                else:
                    result = self.final_result = False
        if not result or self.forced:
            self.diagnostic()
        return result

    def diagnostic(self):
        try:
            stage = self.stage if self.stage in {"allocate", "job", "pipes", "create", "identity", "resume",
                                                "running", "process_close", "accounting", "job_close", "closed"} else None
            integer = lambda value: value if type(value) is int and 0 <= value < 2**32 else None
            boolean = lambda value: value if type(value) is bool else None
            record = dict(schema_version=1, stage=stage, creation_resolved=boolean(self.creation_resolved),
                created=None if self.creation_attempted and not self.creation_resolved else boolean(self.created),
                resumed=None if self.resume_attempted and not self.resumed else boolean(self.resumed), exit_code=integer(self.returncode),
                forced=boolean(self.forced), uncertain=boolean(self.uncertain),
                process_handle_closed=boolean(self.process.closed), job_handle_closed=boolean(self.job.closed),
                active=integer(self.active_count), total=integer(self.total_count), closed=boolean(self.final_result))
            line = "application_helper_owner=" + json.dumps(record, separators=(",", ":"))
            if len(line.encode("ascii")) <= 1024:
                print(line, flush=True)
        except BaseException:
            pass


def spawn(args, **kwargs):
    return HelperProcess(args, **kwargs)


def _retain_uncertainty(process):
    try:
        process.mark_uncertain()
    except BaseException:
        pass  # The original failure still owns propagation; reservation remains.


class _Capture:
    def __init__(self, process):
        self.process, self.pipe = process, process.stdout
        self.lock = threading.Lock()
        self.buffer = bytearray()
        self.overflow = self.eof = self.failed = self.claimed = self.revoked = self.stop = False
        self.returned = False
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        claimed = False
        try:
            with self.lock:
                if self.revoked:
                    return
                self.claimed = claimed = True
            while True:
                with self.lock:
                    if self.stop:
                        return
                data = self.pipe.read1(1024)
                need(type(data) is bytes and len(data) <= 1024)
                with self.lock:
                    if not data:
                        self.eof = True
                        return
                    room = 4096 - len(self.buffer)
                    self.buffer.extend(data[:room])
                    self.overflow |= len(data) > room
        except BaseException:
            self.failed = True
        finally:
            if claimed:
                try:
                    self.pipe.close()
                except BaseException:
                    self.failed = True

    def start(self):
        try:
            self.thread.start()
            self.returned = True
        except BaseException:
            _retain_uncertainty(self.process)
            raise

    def join(self, deadline):
        self.thread.join(max(0, deadline - time.monotonic()))
        return not self.thread.is_alive()

    def snapshot(self):
        with self.lock:
            return None if self.overflow or self.failed else bytes(self.buffer)

    def failure_close(self, deadline):
        # The lock covers only transfer of pipe ownership, never read/join/close.
        with self.lock:
            claimed = self.claimed
            if not self.returned and not claimed:
                self.revoked = True
            revoked = self.revoked
        if self.returned or claimed:
            joined = self.join(deadline)
            with self.lock:
                self.stop = True
            if not joined:
                self.process.mark_uncertain()
            return joined
        if revoked:
            self.pipe.close()
        # Interrupted start can still have an unclaimed late target. Revocation
        # protects the pipe, but is never a claim that its thread already ended.
        self.process.mark_uncertain()
        return False

    def failure_close_nowait(self):
        # A failed clock grants no join or reader-close authority. Revoke only
        # an unclaimed interrupted start; a claimed reader keeps its own pipe.
        with self.lock:
            if not self.returned and not self.claimed:
                self.revoked = True
            revoked = self.revoked
            self.stop = True
        if revoked:
            self.pipe.close()
        self.process.mark_uncertain()


class _SetupQuiescence:
    """Setup-success observation only; finalization remains an independent proof."""
    def __init__(self):
        self.status, self.queries = "admission_failed", 0
        self.active = self.total = self.last_clock = self.deadline_expired = None

    def clock(self, deadline, *, starting=False):
        try:
            need(type(deadline) in (int, float) and math.isfinite(deadline))
            now = time.monotonic()
            need(type(now) in (int, float) and math.isfinite(now) and now >= 0 and
                 (self.last_clock is None or now >= self.last_clock))
        except BaseException:
            self.status = "clock_failed"
            self.deadline_expired = None
            raise
        self.last_clock = now
        self.deadline_expired = now >= deadline if starting else now > deadline
        if self.deadline_expired:
            self.status = "deadline_exhausted"
            raise OwnershipError("helper_ownership_failed")
        return now

    def observe(self, process, capture, deadline):
        try:
            _registered()
            with _lock:
                need(_active is process and not _poisoned)
            need(not process.finalized and not process.forced and not process.uncertain and
                 process.creation_resolved and process.created and process.resumed and
                 type(process.returncode) is int and process.returncode == 0)
            need(capture.process is process and capture.pipe is process.stdout and
                 capture.returned and capture.claimed and not capture.revoked and not capture.stop and
                 capture.eof and not capture.failed and not capture.overflow and
                 not capture.thread.is_alive() and process.stdout.closed and
                 process.stdout.handle is process.parent[1] and process.stdin is None and process.stderr is None)
            for cell in (*process.child, process.primary_thread, *process.parent):
                with cell.lock:
                    need(cell.owner is process and cell.users == 0 and
                         (cell.value is None or cell.closed is True))
            for cell in (process.process, process.job):
                with cell.lock:
                    need(cell.owner is process and cell.value is not None and cell.users == 0 and
                         not cell.attempted and cell.closed is None)
            self.clock(deadline, starting=True)
            self.status = "parent_close_failed"
            need(process.process.close() and process.process.closed is True)
            self.clock(deadline)
            while self.queries < 401:
                self.clock(deadline, starting=True)
                self.status = "query_failed"
                self.queries += 1
                with process.job.borrow() as handle:
                    sample = process.api.accounting(handle)
                self.status = "invalid_accounting"
                need(type(sample) is tuple and len(sample) == 2)
                active, total = sample
                need(type(active) is int and type(total) is int and 0 <= active <= total < 2**32 and
                     total >= 1 and (self.total is None or total >= self.total))
                self.active, self.total = active, total
                now = self.clock(deadline)
                if active == 0:
                    self.status = "zero_observed"
                    return
                if self.queries == 401:
                    self.status = "observation_cap"
                    raise OwnershipError("helper_ownership_failed")
                now = self.clock(deadline, starting=True)
                self.status = "pace_failed"
                time.sleep(min(0.05, deadline - now))
                self.clock(deadline)
        except BaseException:
            _retain_uncertainty(process)
            raise

    def diagnostic(self):
        # This is emitted only while propagating failure, including a failed
        # final proof after zero_observed. Finalizer counts never overwrite it.
        try:
            statuses = {"admission_failed", "parent_close_failed", "query_failed", "invalid_accounting",
                        "clock_failed", "deadline_exhausted", "observation_cap", "pace_failed", "zero_observed"}
            need(self.status in statuses and type(self.queries) is int and 0 <= self.queries <= 401)
            need((self.active is None and self.total is None) or
                 (type(self.active) is int and type(self.total) is int and 0 <= self.active <= self.total < 2**32 and self.total >= 1))
            need(self.deadline_expired is None or type(self.deadline_expired) is bool)
            record = dict(schema_version=1, status=self.status, queries=self.queries,
                          active=self.active, total=self.total, deadline_expired=self.deadline_expired)
            print("application_helper_setup_quiescence=" + json.dumps(record, separators=(",", ":")), flush=True)
        except BaseException:
            pass


def run_setup(args, *, env, cwd=None, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
              stderr=subprocess.DEVNULL, timeout=20, check=False, failure_drain_seconds=5,
              capture_limit=4096, **hidden):
    need(timeout == 20 and failure_drain_seconds == 5 and capture_limit == 4096 and check is False and
         (stdin, stdout, stderr) == (subprocess.DEVNULL, subprocess.PIPE, subprocess.DEVNULL))
    process = spawn(args, env=env, cwd=cwd, stdin=stdin, stdout=stdout, stderr=stderr, **hidden)
    deadline = time.monotonic() + 20
    capture = observation = None
    try:
        capture = _Capture(process)
        capture.start()
        if not capture.join(deadline):
            raise subprocess.TimeoutExpired(args, timeout)
        process.wait(timeout=max(0, deadline - time.monotonic()))
        need(capture.eof and not capture.failed and not capture.overflow)
        data = capture.snapshot()
        need(type(data) is bytes)
        if process.returncode == 0:
            observation = _SetupQuiescence()
            observation.observe(process, capture, deadline)
        need(process.finalize())
        return subprocess.CompletedProcess(args, process.returncode, stdout=data, stderr=None)
    except BaseException as primary:
        try:
            failure_start = time.monotonic()
            need(type(failure_start) in (int, float) and math.isfinite(failure_start) and failure_start >= 0 and
                 (observation is None or observation.last_clock is None or failure_start >= observation.last_clock))
            failure_deadline = failure_start + 5
            need(math.isfinite(failure_deadline))
        except BaseException:
            failure_deadline = None
            _retain_uncertainty(process)
        try:
            process.kill()  # The original one parent kill, never a tree kill.
        except BaseException:
            _retain_uncertainty(process)
        try:
            process.wait(timeout=0 if failure_deadline is None else max(0, failure_deadline - time.monotonic()))
        except BaseException:
            _retain_uncertainty(process)
        try:
            if capture is not None:
                if failure_deadline is None:
                    capture.failure_close_nowait()
                else:
                    capture.failure_close(failure_deadline)
            else:
                process.stdout.close()  # No reader was constructed or started.
                process.mark_uncertain()
        except BaseException:
            _retain_uncertainty(process)
        try:
            if isinstance(primary, subprocess.TimeoutExpired):
                primary.timeout = timeout
                primary.output = capture.snapshot() if capture is not None else None
        except BaseException:
            pass
        try:
            process.finalize()
        except BaseException:
            _retain_uncertainty(process)
        if observation is not None:
            try:
                observation.diagnostic()
            except BaseException:
                pass
        raise
