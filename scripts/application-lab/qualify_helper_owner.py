#!/usr/bin/env python3
"""Hosted x64 inert retained-stdout calibration, separate from production success."""
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import time
import types
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SELF_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
# Final exact-source header is generated only from the held integration and this fixture.
SOURCE_PINS = {'.github/workflows/ci.yml': {'bytes': 65976, 'sha256': '47d16b52cd472914b46220e274dcfbbf922a1848d3f3de216c4b037eb2ad804a'}, 'scripts/application_evidence.py': {'bytes': 13266, 'sha256': 'a229fdecc8c5285920c0a56118fddf6cda020e89adddefb89d382ef4b866cf88'}, 'scripts/application-lab/fixture_http.py': {'bytes': 19465, 'sha256': 'ee98f60c2764f142d0a3c834c329fe6f82cfd87df8d126101b83a5e6f95ca8cb'}, 'scripts/application-lab/HostedConPtySession.cs': {'bytes': 104364, 'sha256': 'ecded11bd529a8da58e87a8f0b37c807e85778a2655368ea0f459a1d0ee506d1'}, 'scripts/application-lab/hosted_session.ps1': {'bytes': 10525, 'sha256': 'f333b67a0817838da543b448f547de6e65886bf46e994bb2e078431e91853d03'}, 'scripts/application-lab/prepare_case.ps1': {'bytes': 11317, 'sha256': '9f92c3a570a8dc94ebf9375789eeaf0b7f897e89af4028bc923ba3a6c963d1a5'}, 'scripts/application-lab/run_windows_http.py': {'bytes': 116983, 'sha256': 'a95f78b0c35a1538e0780cbac5bde238088b767363343c3dbc809403cc48510a'}, 'scripts/application-lab/owned_helper_process.py': {'bytes': 27931, 'sha256': '462f34e63cdb2adb9631110b4ef888f722ead24a27121b31e79f5ec88ef7050d'}, 'scripts/application-lab/helper_owner_fixture.py': {'bytes': 14693, 'sha256': 'fd1f6233a14b5cb0712730e35bfec72d240262260f44297a348e0e04cfafd46e'}}
REGISTRATION = """      - name: Check hosted x64 helper descendant ownership
        if: runner.os == 'Windows' && runner.arch == 'X64'
        timeout-minutes: 2
        run: python -B -I -S ../scripts/application-lab/qualify_helper_owner.py
"""
REASONS = frozenset({'host', 'sources', 'image', 'setup', 'expected_failure', 'transfer', 'admission',
    'release', 'child_exit', 'reader', 'handles', 'preservation', 'temp_cleanup', 'unexpected',
    'job_observation', 'job_quiescence'})
CONTRACT = 'known_child_membership_bounded_job_quiescence_v3'
QUIESCENCE_STATUSES = frozenset({'not_started', 'zero_observed', 'deadline_exhausted',
    'observation_cap', 'query_failed', 'invalid_accounting', 'clock_failed', 'pace_failed'})


class CalibrationError(ValueError):
    pass


def need(value):
    if not value:
        raise CalibrationError('calibration_failed')


def counts(value):
    need(type(value) is tuple and len(value) == 2)
    active, total = value
    need(type(active) is int and type(total) is int and 0 <= active <= total < 2**32)
    return value


class JobObservation:
    """Calibration-only exact-Job capability; never changes an owner verdict."""
    def __init__(self, owner, api):
        self.owner, self.api, self.cls = owner, api, owner._Win32
        self.original = self.cls.accounting
        self.job = self.native = self.before = self.after = None
        self.calls, self.failed = 0, False
        self.install_attempted = self.restore_attempted = self.restored = False
        self.query_attempted = self.close_attempted = False
        self.closed = self.member = None
        self.query_count, self.quiescence_status = 0, 'not_started'
        self.last_clock = self.within_cleanup_deadline = None

        def wrapper(native, handle):
            # Always call the original once, even on a repeated/foreign call.
            # No observation exception may replace its result or exception.
            try:
                result = self.original(native, handle)
            except BaseException:
                self.failed = True
                raise
            try:
                self.calls += 1
                need(not self.failed and self.calls == 1)
                process = self.owner._active
                need(type(process) is self.owner.HelperProcess and process.api is native)
                cell = process.job
                need(cell.owner is process and type(handle) is int and cell.value == handle and
                     cell.closed is None and cell.attempted is False and
                     type(cell.users) is int and cell.users > 0)
                self.before, self.native = counts(result), native
                # Unchanged fixture helper checks successful BOOL and valid output
                # before returning. Failed/ambiguous out storage is never owned.
                current = self.api.current()
                self.job = self.api.duplicate(current, handle, current, 0x0004)
                self.api.flags(self.job, 0)
            except BaseException:
                self.failed = True
            return result
        self.wrapper = wrapper

    def install(self):
        need(self.owner._native_factory is self.cls and self.cls.accounting is self.original)
        self.install_attempted = True
        setattr(self.cls, 'accounting', self.wrapper)
        need(self.cls.accounting is self.wrapper)

    def restore(self):
        if not self.install_attempted or self.restore_attempted:
            return
        self.restore_attempted = True
        try:
            need(self.cls.accounting is self.wrapper or self.cls.accounting is self.original)
            setattr(self.cls, 'accounting', self.original)
            need(self.cls.accounting is self.original)
            self.restored = True
        except BaseException:
            # In particular, preserve a pending TimeoutExpired object/traceback.
            self.failed = True

    def ready(self, process):
        need(not self.failed and self.restored and self.calls == 1 and self.job is not None and
             self.owner._active is process and process.api is self.native and
             self.before == (process.active_count, process.total_count) and
             self.cls.accounting is self.original and not self.close_attempted)

    def membership(self, child):
        try:
            need(not self.failed and self.job is not None and self.member is None)
            member = ctypes.c_int32()
            need(self.native.k.IsProcessInJob(child, self.job, ctypes.byref(member)) != 0 and member.value == 1)
            need(not self.api.wait(child, 0))
            self.member = True
        except BaseException:
            self.failed = True
            raise

    def quiescence(self, deadline, last_clock, clock=time.monotonic, pause=time.sleep):
        """Observe one retained Job within the existing cleanup window, without retrying errors."""
        def tick(before=False):
            try:
                self.last_clock = clock_value(self.last_clock, clock)
            except BaseException:
                self.within_cleanup_deadline = False
                self.quiescence_status = 'clock_failed'
                raise
            self.within_cleanup_deadline = self.last_clock <= deadline
            if self.last_clock > deadline or before and self.last_clock == deadline:
                self.quiescence_status = 'deadline_exhausted'
                raise CalibrationError('calibration_failed')
        try:
            need(not self.failed and self.restored and self.member is True and
                 self.job is not None and not self.query_attempted and not self.close_attempted)
            self.query_attempted = True
            try:
                need(type(deadline) in (int, float) and math.isfinite(deadline))
                need(type(last_clock) in (int, float) and math.isfinite(last_clock))
                self.last_clock = last_clock
            except BaseException:
                self.within_cleanup_deadline = False
                self.quiescence_status = 'clock_failed'
                raise
            total = counts(self.before)[1]
            for _ in range(201):
                tick(before=True)
                self.query_count += 1
                try:
                    sample = self.original(self.native, self.job)
                except BaseException:
                    self.quiescence_status = 'query_failed'
                    raise
                try:
                    self.after = counts(sample)  # Keep sane late or contradictory counts.
                except BaseException:
                    self.quiescence_status = 'invalid_accounting'
                    raise
                tick()
                if self.after[1] < total:
                    self.quiescence_status = 'invalid_accounting'
                    raise CalibrationError('calibration_failed')
                total = self.after[1]
                if self.after[0] == 0:
                    self.quiescence_status = 'zero_observed'
                    return
                if self.query_count == 201:
                    self.quiescence_status = 'observation_cap'
                    raise CalibrationError('calibration_failed')
                if self.last_clock == deadline:
                    self.quiescence_status = 'deadline_exhausted'
                    raise CalibrationError('calibration_failed')
                try:
                    pause(min(0.05, deadline - self.last_clock))
                except BaseException:
                    self.quiescence_status = 'pace_failed'
                    raise
                tick(before=True)
        except BaseException:
            self.failed = True
            raise

    def close(self):
        if self.job is None or self.close_attempted:
            return self.closed is True
        self.close_attempted = True
        try:
            self.api.close(self.job)
            self.closed = True
        except BaseException:
            self.failed = True  # Ambiguous close is never retried.
        return self.closed is True


def load(name, path, digest):
    raw = path.read_bytes()
    need(len(raw) <= 512*1024 and hashlib.sha256(raw).hexdigest() == digest)
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def pe_x64(raw):
    need(type(raw) is bytes and 64 <= len(raw) <= 32*1024*1024 and raw[:2] == b'MZ')
    offset = struct.unpack_from('<I', raw, 60)[0]
    need(64 <= offset <= len(raw)-26 and raw[offset:offset+4] == b'PE\0\0')
    need(struct.unpack_from('<H', raw, offset+4)[0] == 0x8664 and struct.unpack_from('<H', raw, offset+24)[0] == 0x20b)


def verify_sources(F):
    need(len(SOURCE_PINS) == 9)
    rows = []
    for name, pin in sorted(SOURCE_PINS.items()):
        raw = F.read(ROOT / name, 512*1024)
        need(len(raw) == pin['bytes'] and hashlib.sha256(raw).hexdigest() == pin['sha256'])
        rows.append([name, pin['sha256']])
    workflow = F.read(ROOT / '.github/workflows/ci.yml', 512*1024).decode('utf-8')
    old = "      - name: Check hosted Windows helper readiness and cleanup\n        if: runner.os == 'Windows'\n        run: python -B ../scripts/application-lab/run_windows_http.py --bridge-probe\n"
    need(workflow.count(old + REGISTRATION) == 1)
    need(workflow.count('run: python -B ../scripts/application-lab/run_windows_http.py --setup-probe') == 1)
    return hashlib.sha256(F.compact(rows)).hexdigest()


def recover(owner, error):
    need(type(error) is subprocess.TimeoutExpired and type(error.timeout) is int and error.timeout == 20)
    current, matches, count = error.__traceback__, [], 0
    while current is not None:
        count += 1
        need(count <= 4)
        if current.tb_frame.f_code is owner.run_setup.__code__:
            local = current.tb_frame.f_locals
            process, capture = local.get('process'), local.get('capture')
            need(type(process) is owner.HelperProcess and type(capture) is owner._Capture)
            need(capture.process is process and owner._active is process)
            matches.append((process, capture))
        current = current.tb_next
    need(len(matches) == 1)
    return matches[0]


def expected_failure(owner, process, capture, error):
    need(type(error) is subprocess.TimeoutExpired and type(error.timeout) is int and error.timeout == 20 and error.output == b'')
    need(owner._active is process and process.returncode == 0 and type(process.returncode) is int)
    need(process.process.closed is True and process.finalized is True and process.final_result is False)
    need(process.uncertain is True and type(process.forced) is bool)
    need(process.created is True and process.creation_resolved is True and process.resumed is True)
    for handle in [process.process, process.primary_thread, process.job, *process.child]:
        need(handle.closed is True and type(handle.users) is int and handle.users == 0)
    counts((process.active_count, process.total_count))
    need(capture.returned is True and capture.claimed is True and capture.revoked is False)
    need(capture.eof is False and capture.failed is False and capture.overflow is False)
    need(capture.snapshot() == b'' and capture.thread.is_alive() is True and capture.pipe.closed is False)
    need(capture.pipe is process.stdout)


def owner_handles_closed(process):
    for handle in [process.process, process.primary_thread, process.job, *process.child, *process.parent]:
        need(type(handle.users) is int and handle.users == 0 and (handle.value is None or handle.closed is True))


def accept_transfer(F, api, value, expected):
    F.transfer(value, expected)
    handle = value['child_handle']
    # Do not close or retain the incoming number as an owned capability before identity agrees.
    need(api.identify(handle) == value['child'])
    api.flags(handle, 0)
    api.x64(handle)
    need(not api.wait(handle, 0))
    return handle


def admission(owner, process, args, environment):
    try:
        owner.run_setup(args, env=environment, timeout=20, failure_drain_seconds=5,
                        capture_limit=4096, check=False)
    except owner.OwnershipError:
        need(owner._active is process)
    else:
        raise CalibrationError('calibration_failed')


def clock_value(last_clock, clock):
    now = clock()
    need(type(now) in (int, float) and math.isfinite(now))
    need(last_clock is None or type(last_clock) in (int, float) and math.isfinite(last_clock) and now >= last_clock)
    return now


def advance_cleanup(result, clock):
    """Carry one deadline and the latest valid clock through all cleanup operations."""
    try:
        need(result['deadline'] is not None and result['last_clock'] is not None)
        result['last_clock'] = clock_value(result['last_clock'], clock)
        result['within_deadline'] = result['within_deadline'] is True and result['last_clock'] <= result['deadline']
        return max(0, result['deadline'] - result['last_clock']) if result['within_deadline'] else 0
    except BaseException:
        result['within_deadline'] = False
        raise


def observe_cleanup(api, release, child, capture, clock=time.monotonic):
    """One signal, one child wait, one remaining-time existing reader join. No kill."""
    result = dict(released=False, child_exit=None, reader_closed=False, complete=False, error=None,
                  deadline=None, last_clock=None, within_deadline=None)
    def failed(reason):
        if result['error'] is None:
            result['error'] = reason
    try:
        start = clock_value(None, clock)
        deadline = start + 10
        need(math.isfinite(deadline) and deadline > start)
        result.update(deadline=deadline, last_clock=start, within_deadline=True)
    except BaseException:
        result['within_deadline'] = False
        failed('unexpected')
    try:
        api.signal(release)
        result['released'] = True
    except BaseException:
        failed('release')
    try:
        advance_cleanup(result, clock)
    except BaseException:
        failed('unexpected')
    if child is not None:
        try:
            seconds = advance_cleanup(result, clock)
            need(seconds > 0)
            try:
                exited = api.wait(child, int(seconds*1000))
                if exited:
                    code = api.exit_code(child)
                    need(type(code) is int and 0 <= code < 2**32)
                    result['child_exit'] = code
            finally:
                advance_cleanup(result, clock)
            need(exited and result['within_deadline'] is True and result['child_exit'] == 0)
        except BaseException:
            failed('child_exit')
    else:
        failed('child_exit')
    if capture is not None:
        try:
            seconds = advance_cleanup(result, clock)
            need(seconds > 0)
            try:
                capture.thread.join(seconds)
                need(capture.thread.is_alive() is False and capture.eof is True and capture.failed is False and capture.overflow is False)
                need(capture.snapshot() == b'' and capture.pipe.closed is True and capture.pipe.handle.users == 0)
                result['reader_closed'] = True
            finally:
                advance_cleanup(result, clock)
            need(result['within_deadline'] is True)
        except BaseException:
            failed('reader')
    else:
        failed('reader')
    result['complete'] = (result['released'] and result['child_exit'] == 0 and result['reader_closed'] and
                          result['within_deadline'] is True and result['error'] is None)
    return result


def remove_owned(F, directory, original_identity, hashes):
    info = F.plain(directory, True)
    need((info.st_dev, info.st_ino) == original_identity)
    need(set(p.name for p in directory.iterdir()) == {'request.json', 'transfer.json'} and set(hashes) == {'request.json', 'transfer.json'})
    for name in ('request.json', 'transfer.json'):
        need(F.digest(directory / name, 4096) == hashes[name])
    for name in ('transfer.json', 'request.json'):
        (directory / name).unlink()
    directory.rmdir()
    need(not directory.exists())


def emit(value):
    # No incoming native text, identity, handle, path, timestamp or transcript is copied.
    try:
        need(set(value) == {'schema_version', 'scope', 'result', 'reason', 'expected_failure', 'owner_sticky_failed',
            'cleanup_complete', 'parent_exit', 'child_exit', 'forced', 'architecture', 'sources_sha256',
            'controller_sha256', 'python_sha256', 'powershell_file_sha256', 'contract', 'child_in_job',
            'before_active', 'before_total', 'final_active', 'final_total', 'query_job_closed', 'observation_complete',
            'query_count', 'within_cleanup_deadline', 'quiescence_status'})
        need(value['reason'] is None or value['reason'] in REASONS)
        need(type(value['schema_version']) is int and value['schema_version'] == 3 and value['contract'] == CONTRACT)
        need(type(value['query_count']) is int and 0 <= value['query_count'] <= 201)
        need(type(value['quiescence_status']) is str and value['quiescence_status'] in QUIESCENCE_STATUSES)
        need(value['scope'] == 'hosted_windows_x64_inert_descendant' and value['result'] in {'passed', 'failed'})
        need(value['architecture'] in {None, 'native_x64'})
        for key in ('expected_failure', 'owner_sticky_failed', 'cleanup_complete', 'observation_complete'):
            need(type(value[key]) is bool)
        for key in ('forced', 'child_in_job', 'query_job_closed', 'within_cleanup_deadline'):
            need(value[key] is None or type(value[key]) is bool)
        for key in ('parent_exit', 'child_exit', 'before_active', 'before_total', 'final_active', 'final_total'):
            need(value[key] is None or type(value[key]) is int and 0 <= value[key] < 2**32)
        for prefix in ('before', 'final'):
            pair = (value[prefix + '_active'], value[prefix + '_total'])
            need(pair == (None, None) or all(v is not None for v in pair) and counts(pair) is pair)
        if value['observation_complete']:
            need(value['child_in_job'] is True and value['query_job_closed'] is True and value['final_active'] == 0)
            need(value['before_total'] is not None and value['final_total'] >= value['before_total'])
            need(value['query_count'] > 0 and value['quiescence_status'] == 'zero_observed' and value['within_cleanup_deadline'] is True)
        for key in ('sources_sha256', 'controller_sha256', 'python_sha256', 'powershell_file_sha256'):
            need(value[key] is None or type(value[key]) is str and re.fullmatch('[0-9a-f]{64}', value[key]))
        if value['result'] == 'passed':
            need(value['reason'] is None and value['expected_failure'] and value['owner_sticky_failed'] and value['cleanup_complete'])
            need(value['observation_complete'] and value['before_active'] is not None)
            need(value['parent_exit'] == value['child_exit'] == 0 and value['architecture'] == 'native_x64')
            need(all(value[k] is not None for k in ('forced', 'sources_sha256', 'controller_sha256', 'python_sha256', 'powershell_file_sha256')))
        raw = json.dumps(value, separators=(',', ':'), ensure_ascii=True).encode('ascii')
        need(len(raw) <= 2048)
        print('helper_owner_calibration=' + raw.decode('ascii'), flush=True)
        return True
    except BaseException:
        return False


def main():
    value = dict(schema_version=3, contract=CONTRACT, scope='hosted_windows_x64_inert_descendant', result='failed', reason=None,
        expected_failure=False, owner_sticky_failed=False, cleanup_complete=False, parent_exit=None, child_exit=None,
        forced=None, architecture=None, sources_sha256=None, controller_sha256=None, python_sha256=None,
        powershell_file_sha256=None, child_in_job=None, before_active=None, before_total=None,
        final_active=None, final_total=None, query_job_closed=None, observation_complete=False,
        query_count=0, within_cleanup_deadline=None, quiescence_status='not_started')
    phase, F, H, api, directory, directory_identity = 'host', None, None, None, None, None
    release, ready, child, capture, process, primary = None, None, None, None, None, None
    handles, hashes, normalized, observation = [], {}, None, None
    try:
        need(len(sys.argv) == 1 and os.name == 'nt' and ctypes.sizeof(ctypes.c_void_p) == 8)
        need(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'Windows'
             and os.environ.get('RUNNER_ARCH') == 'X64' and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted')
        phase = 'sources'
        name = 'scripts/application-lab/helper_owner_fixture.py'
        F = load('helper_owner_fixture', ROOT / name, SOURCE_PINS[name]['sha256'])
        value['sources_sha256'] = verify_sources(F)
        value['controller_sha256'] = F.digest(Path(__file__), 512*1024)
        need(value['controller_sha256'] == SELF_SHA256)
        H = load('calibration_http', HERE / 'run_windows_http.py', SOURCE_PINS['scripts/application-lab/run_windows_http.py']['sha256'])
        H.loaded_sources_preserved()
        phase = 'image'
        api = F.Native()
        current = api.identify(api.current())
        api.x64(api.current())
        image = F.read(current['image'], 32*1024*1024)
        pe_x64(image)
        value['python_sha256'] = hashlib.sha256(image).hexdigest()
        powershell = H.powershell()
        image = H.read(powershell, 32*1024*1024, allow_hardlinks=True)
        pe_x64(image)
        value['powershell_file_sha256'] = hashlib.sha256(image).hexdigest()
        value['architecture'] = 'native_x64'
        parent = Path(os.environ['RUNNER_TEMP']).absolute()
        F.plain(parent, True)
        directory = parent / ('helper-owner-' + uuid.uuid4().hex)
        directory.mkdir()
        info = F.plain(directory, True); directory_identity = (info.st_dev, info.st_ino)
        release = api.event(); handles.append(release)
        ready = api.event(); handles.append(ready)
        need(release != ready and not api.wait(release, 0) and not api.wait(ready, 0))
        expected = dict(schema_version=1, nonce=uuid.uuid4().hex, controller=current, python_sha256=value['python_sha256'],
                        fixture_sha256=SOURCE_PINS[name]['sha256'], release=release, ready=ready)
        F.request(expected)
        request_path = directory / 'request.json'
        F.publish(request_path, expected)
        hashes['request.json'] = F.digest(request_path, 4096)
        args = [current['image'], '-B', '-I', '-S', str(HERE / 'helper_owner_fixture.py'), 'parent', str(request_path)]
        environment = {key: os.environ[key] for key in ('SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP') if key in os.environ}
        need(environment.get('SYSTEMROOT'))
        phase = 'setup'
        observation = JobObservation(H.O, api)
        try:
            try:
                observation.install()
                H.O.run_setup(args, env=environment, timeout=20, failure_drain_seconds=5, capture_limit=4096, check=False)
            finally:
                observation.restore()
        except BaseException as error:
            primary = error
            phase = 'expected_failure'
            process, capture = recover(H.O, error)
            expected_failure(H.O, process, capture, error)
            value['expected_failure'] = True
            value['owner_sticky_failed'] = True
            value['parent_exit'], value['forced'] = process.returncode, process.forced
        else:
            raise CalibrationError('calibration_failed')
        phase = 'job_observation'
        observation.ready(process)
        phase = 'transfer'
        transfer_path = directory / 'transfer.json'
        transferred = F.record(transfer_path)
        child = accept_transfer(F, api, transferred, expected); handles.append(child)
        hashes['transfer.json'] = F.digest(transfer_path, 4096)
        phase = 'job_observation'
        observation.membership(child)
        need(api.wait(ready, 0))
        phase = 'admission'
        admission(H.O, process, args, environment)
    except BaseException:
        value['reason'] = phase if phase in REASONS else 'unexpected'
    finally:
        if release is not None:
            try:
                normalized = observe_cleanup(api, release, child, capture, clock=time.monotonic)
                value['child_exit'] = normalized['child_exit']
                if value['reason'] is None:
                    value['reason'] = normalized['error']
            except BaseException:
                if value['reason'] is None:
                    value['reason'] = 'unexpected'
        else:
            value['reason'] = value['reason'] or 'release'
        closed = True
        # No wait is outstanding here; only validated or directly created handles are closed.
        for handle in reversed(handles):
            try:
                api.close(handle)
            except BaseException:
                closed = False
                value['reason'] = value['reason'] or 'handles'
            try:
                need(normalized is not None)
                advance_cleanup(normalized, time.monotonic)
            except BaseException:
                value['reason'] = value['reason'] or 'handles'
        quiet = False
        try:
            phase = 'job_quiescence'
            need(normalized is not None and normalized['complete'] and normalized['within_deadline'] is True and closed)
            need(observation is not None)
            observation.quiescence(normalized['deadline'], normalized['last_clock'], clock=time.monotonic, pause=time.sleep)
            quiet = True
        except BaseException:
            value['reason'] = value['reason'] or (phase if phase in REASONS else 'unexpected')
        finally:
            if observation is not None:
                if observation.last_clock is not None:
                    normalized['last_clock'] = observation.last_clock
                if normalized is not None and observation.within_cleanup_deadline is False:
                    normalized['within_deadline'] = False
                observation.restore()  # No-op after the one protected restoration.
                observation.close()
                try:
                    need(normalized is not None)
                    advance_cleanup(normalized, time.monotonic)
                except BaseException:
                    value['reason'] = value['reason'] or 'job_quiescence'
                value['child_in_job'], value['query_job_closed'] = observation.member, observation.closed
                value['query_count'], value['quiescence_status'] = observation.query_count, observation.quiescence_status
                if observation.before is not None:
                    value['before_active'], value['before_total'] = observation.before
                if observation.after is not None:
                    value['final_active'], value['final_total'] = observation.after
                value['observation_complete'] = bool(quiet and not observation.failed and observation.closed is True and
                    normalized is not None and normalized['within_deadline'] is True)
            if normalized is not None:
                value['within_cleanup_deadline'] = normalized['within_deadline']
        try:
            need(value['observation_complete'])
            phase = 'preservation'
            need(verify_sources(F) == value['sources_sha256'])
            need(F.digest(Path(__file__), 512*1024) == value['controller_sha256'])
            need(H.O._active is process and process.final_result is False and process.uncertain is True)
            owner_handles_closed(process)
            phase = 'temp_cleanup'
            remove_owned(F, directory, directory_identity, hashes)
            value['cleanup_complete'] = True
        except BaseException:
            value['reason'] = value['reason'] or (phase if phase in REASONS else 'unexpected')
    try:
        if primary is not None:
            primary.__traceback__ = None
    except BaseException:
        pass
    value['result'] = 'passed' if value['reason'] is None and value['expected_failure'] and value['cleanup_complete'] else 'failed'
    printed = emit(value)
    return 0 if printed and value['result'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
