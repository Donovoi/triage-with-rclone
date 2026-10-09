#!/usr/bin/env python3
"""Owned network-none GCS OAuth lifecycle experiment; never ledger evidence.

The container supervisor binds the image and source closure. This probe checks
the namespace again, drives finite requests without browser/redirect following,
and publishes only fixed checks after its private children and data are gone.
"""
import argparse
import base64
import configparser
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import parse_qsl, urlsplit

BASE = Path('/opt/fixture')
WORK = Path('/work')
UID = 10001
CALLBACK_PORT = 53682
# rclone v1.75.1 GCS storageConfig uses oauthutil.RedirectURL (numeric loopback),
# not RedirectLocalhostURL. Keep this exact across authorize, callback and exchange.
CALLBACK_URI = 'http://127.0.0.1:53682/'
MEMBER = 'README-synthetic.txt'
FILES = {MEMBER: b'Synthetic provider protocol fixture. No account or user data.\n',
         'nested/space name.txt': b'Nested synthetic payload.\n',
         'nested/bytes.bin': bytes(range(256)) * 8}
MEMBER_SHA = '1e901527b93ae84dc9d95a8aa76bbc12d7d77dbf8ab449333c172cfc909c639e'
MANIFEST_SHA = 'c990bbd4909b227aae4c70d26f9da5534740a2eb10337ced47977f915fa617be'
AUTH_CASES = ('positive', 'wrong_state', 'blank_state', 'consent_denied', 'invalid_code',
              'wrong_client_secret', 'callback_cancel', 'refresh', 'refresh_denied', 'refresh_cancel')
COMMON_CHECKS = ('environment', 'version_binding', 'initial_config_question', 'callback_ownership',
                 'source_preserved', 'request_sequence')
CASE_CHECKS = {
    'positive': COMMON_CHECKS + ('authorize', 'token_exchange', 'config_persisted', 'fresh_child_read', 'config_preserved'),
    **{name: COMMON_CHECKS + ('authorize', 'callback_denial', 'no_token_persisted', 'config_preserved', 'no_read')
       for name in ('wrong_state', 'blank_state', 'consent_denied')},
    **{name: COMMON_CHECKS + ('authorize', 'token_denial', 'no_token_persisted', 'config_preserved', 'no_read')
       for name in ('invalid_code', 'wrong_client_secret')},
    'callback_cancel': COMMON_CHECKS + ('owned_process_cancel', 'no_token_persisted', 'config_preserved', 'no_read'),
    'refresh': COMMON_CHECKS + ('authorize', 'token_exchange', 'config_persisted', 'expired_before_read',
                              'replacement_read', 'replacement_persisted', 'non_token_config_preserved'),
    'refresh_denied': COMMON_CHECKS + ('authorize', 'token_exchange', 'config_persisted', 'expired_before_read',
                                     'refresh_denial', 'config_preserved', 'no_read'),
    'refresh_cancel': COMMON_CHECKS + ('authorize', 'token_exchange', 'config_persisted', 'expired_before_read',
                                     'owned_process_cancel', 'config_preserved', 'no_read'),
}
CLEANUP = ('children_stopped', 'listeners_closed', 'temporary_removed')

MAX_OUTPUT = 2 * 1024 * 1024
MAX_SECONDS = 60


class ProbeError(RuntimeError):
    """Static diagnostic codes only."""


def require(value, code):
    if not value:
        raise ProbeError(code)


def fixture_manifest_sha256():
    # Match the established fixture manifest's path/size/sha256 field order.
    manifest = [{'path': name, 'size': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
                for name, body in sorted(FILES.items())]
    return hashlib.sha256(json.dumps(manifest, separators=(',', ':')).encode('ascii')).hexdigest()


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            h.update(block)
    return h.hexdigest()


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate_json_key')
            result[key] = value
        return result

    def invalid(_):
        raise ProbeError('invalid_json_number')

    require(type(data) in (bytes, str) and len(data) <= MAX_OUTPUT, 'json_size_limit')
    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)
    except (ValueError, UnicodeError, TypeError):
        raise ProbeError('invalid_json') from None


def regular(path, private=False):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'absolute_path_required')
    for part in (path, *path.parents):
        require(not part.is_symlink(), 'symlink_refused')
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'regular_file_required')
    if private:
        require(info.st_uid == UID and stat.S_IMODE(info.st_mode) == 0o600, 'private_file_required')
    return info


def pins(path):
    require(regular(path).st_size <= 4096, 'manifest_size_limit')
    expected = {'RCLONE_VERSION', 'RCLONE_EXE_SHA256', 'RCLONE_WINDOWS_ZIP_SHA256',
                'RCLONE_LINUX_ZIP_SHA256', 'RCLONE_LINUX_EXE_SHA256'}
    extended = expected | {'RCLONE_WINDOWS_X86_EXE_SHA256', 'RCLONE_WINDOWS_X86_ZIP_SHA256',
                           'RCLONE_WINDOWS_ARM64_EXE_SHA256', 'RCLONE_WINDOWS_ARM64_ZIP_SHA256'}
    result = {}
    for line in path.read_text(encoding='ascii').splitlines():
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition('=')
        require(separator and key in extended and key not in result, 'invalid_runtime_manifest')
        result[key] = value
    require(set(result) in (expected, extended) and re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)',
            result['RCLONE_VERSION']), 'invalid_runtime_manifest')
    require(all(re.fullmatch(r'[a-f0-9]{64}', result[key]) for key in set(result) - {'RCLONE_VERSION'}),
            'invalid_runtime_manifest')
    return result['RCLONE_VERSION'], result['RCLONE_LINUX_EXE_SHA256']


def tcp_listeners(text):
    result = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        require(len(fields) >= 10, 'invalid_socket_table')
        if fields[3] == '0A':
            result.append((fields[1], fields[9]))
    return result


def listeners():
    return (tcp_listeners(Path('/proc/net/tcp').read_text()),
            tcp_listeners(Path('/proc/net/tcp6').read_text()))


def proc_identity(pid):
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    return (int(fields[19]), Path(f'/proc/{pid}').stat().st_uid, int(fields[2]))


def environment_checks():
    require(sys.platform == 'linux' and platform.machine() == 'x86_64', 'linux_amd64_required')
    require(os.getuid() == os.getgid() == UID, 'nonroot_identity_required')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    require(all(status.get(key, '').split() == [str(UID)] * 4 for key in ('Uid', 'Gid')),
            'identity_mismatch')
    require(status.get('Groups', '').split() in ([], [str(UID)]) and status.get('NoNewPrivs', '').strip() == '1'
            and status.get('Seccomp', '').strip() == '2',
            'privilege_boundary_required')
    require(all(status.get(key, '').strip() == '0' * 16 for key in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')),
            'capabilities_present')
    mounts = {}
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        left, right = line.split(' - ', 1)
        fields = left.split()
        mounts[fields[4]] = (set(fields[5].split(',')), right.split()[0])
    require('ro' in mounts['/'][0] and mounts.get('/work', (set(), ''))[1] == 'tmpfs'
            and {'rw', 'nosuid', 'nodev', 'noexec'} <= mounts['/work'][0], 'mount_boundary_required')
    interfaces = {line.split(':', 1)[0].strip() for line in Path('/proc/net/dev').read_text().splitlines() if ':' in line}
    require(interfaces == {'lo'} and listeners() == ([], []), 'empty_loopback_namespace_required')
    initial = {int(path.name) for path in Path('/proc').iterdir() if path.name.isdecimal()}
    require(initial == {1, os.getpid()}, 'unexpected_initial_process')
    require(Path('/proc/1/cmdline').read_bytes().split(b'\0')[0].rsplit(b'/', 1)[-1] in (b'docker-init', b'tini'),
            'container_init_required')
    require(WORK.is_dir() and not WORK.is_symlink() and WORK.stat().st_uid == UID
            and stat.S_IMODE(WORK.stat().st_mode) == 0o700 and not any(WORK.iterdir()), 'empty_private_tmpfs_required')
    require(fixture_manifest_sha256() == MANIFEST_SHA, 'literal_manifest_mismatch')


def private_write(path, body):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(body)


class Native:
    def __init__(self, binary, root):
        self.binary, self.root, self.records = binary, root, []
        self.deadline = time.monotonic() + MAX_SECONDS
        self.config = root / 'synthetic.conf'
        private_write(self.config, b'')
        for name in ('home', 'cache', 'tmp'):
            (root / name).mkdir(mode=0o700)
        self.env = {'PATH': '/opt/fixture/venv/bin:/usr/local/bin:/usr/bin:/bin', 'HOME': str(root / 'home'),
                    'XDG_CONFIG_HOME': str(root / 'home'), 'XDG_CACHE_HOME': str(root / 'cache'),
                    'TMPDIR': str(root / 'tmp'), 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}

    def start(self, arguments, ca_args=(), notice=False):
        require(len(self.records) < 4 and time.monotonic() < self.deadline, 'native_budget_exceeded')
        index = len(self.records) + 1
        out, err = self.root / f'child-{index}.out', self.root / f'child-{index}.err'
        command = [str(self.binary), '--config', str(self.config), '--cache-dir', str(self.root / 'cache'),
                   '--log-level', 'NOTICE' if notice else 'ERROR', '--stats', '0', '--retries', '1',
                   '--low-level-retries', '1', '--contimeout', '3s', '--timeout', '5s', *ca_args, *arguments]
        with out.open('xb') as stdout, err.open('xb') as stderr:
            process = subprocess.Popen(command, cwd=self.root, env=self.env, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, start_new_session=True)
        record = {'process': process, 'out': out, 'err': err, 'identity': None,
                  'deadline': min(self.deadline, time.monotonic() + 20)}
        self.records.append(record)
        try:
            record['identity'] = proc_identity(process.pid)
        except FileNotFoundError:
            require(process.poll() is not None, 'child_identity_missing')
        return record

    def check(self, record):
        require(record['out'].stat().st_size + record['err'].stat().st_size <= MAX_OUTPUT, 'child_output_limit')
        require(time.monotonic() < record['deadline'], 'child_deadline')

    def finish(self, record):
        while record['process'].poll() is None:
            self.check(record)
            time.sleep(0.02)
        self.check(record)
        record['process'].wait()
        return record['process'].returncode, record['out'].read_bytes(), record['err'].read_bytes()

    def run(self, arguments, ca_args=()):
        return self.finish(self.start(arguments, ca_args))

    def close(self):
        okay = True
        for record in self.records:
            process = record['process']
            try:
                if process.poll() is None:
                    identity = proc_identity(process.pid)
                    require(identity == record['identity'] and identity[1:] == (UID, process.pid), 'child_identity_changed')
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(3)
                    except subprocess.TimeoutExpired:
                        require(proc_identity(process.pid) == identity, 'child_identity_changed')
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(3)
                process.wait()
            except (OSError, ProbeError, subprocess.TimeoutExpired):
                okay = False
        return okay and all(record['process'].poll() is not None for record in self.records)


def config_values(path):
    require(regular(path, private=True).st_size <= 16384, 'config_size_limit')
    parser = configparser.ConfigParser(interpolation=None, strict=True, delimiters=('=',), empty_lines_in_values=False)
    parser.optionxform = str
    try:
        parser.read_string(path.read_text(encoding='utf-8'))
    except (configparser.Error, UnicodeError):
        raise ProbeError('config_parse_failed') from None
    require(parser.sections() == ['Synthetic'] and not parser.defaults(), 'config_scope_changed')
    values = dict(parser['Synthetic'])
    require(all('\n' not in value and '\r' not in value for value in values.values()), 'config_multiline_refused')
    return values


def question(output):
    value = strict_json(output)
    require(type(value) is dict and set(value) == {'State', 'Option', 'Error', 'Result'}
            and value['State'] == '*oauth-islocal,,,' and value['Error'] == value['Result'] == ''
            and type(value['Option']) is dict and value['Option'].get('Name') == 'config_is_local'
            and value['Option'].get('Default') is True and value['Option'].get('Type') == 'bool', 'initial_question_mismatch')
    return value['State']


def terminal(output):
    require(strict_json(output) == {'State': '', 'Option': None, 'Error': '', 'Result': ''}, 'terminal_config_mismatch')


def unique_query(value, expected):
    require(type(value) is str and len(value) <= 4096 and re.search(r'%(?![a-fA-F0-9]{2})', value) is None,
            'invalid_url_query')
    try:
        pairs = parse_qsl(value, keep_blank_values=True, strict_parsing=True, max_num_fields=10, errors='strict')
    except (ValueError, UnicodeError):
        raise ProbeError('invalid_url_query') from None
    require(len(pairs) == len(expected) and len({key for key, _ in pairs}) == len(pairs)
            and dict(pairs) == expected, 'url_query_mismatch')


def validate_location(value, scheme, authority, path, expected):
    require(type(value) is str and len(value) <= 4096 and all(32 < ord(char) < 127 for char in value),
            'invalid_location')
    parsed = urlsplit(value)
    require(parsed.scheme == scheme and parsed.netloc == authority and parsed.path == path
            and not parsed.fragment and not parsed.username and not parsed.password, 'location_authority_mismatch')
    unique_query(parsed.query, expected)
    return parsed.path + '?' + parsed.query


def request(port, path, host, context=None):
    require(type(port) is int and 0 < port < 65536 and path.startswith('/') and not path.startswith('//')
            and len(path) <= 4096, 'invalid_owned_request')
    conn = (http.client.HTTPSConnection('127.0.0.1', port, timeout=3, context=context) if context else
            http.client.HTTPConnection('127.0.0.1', port, timeout=3))
    try:
        conn.request('GET', path, headers={'Host': host, 'Connection': 'close'})
        response = conn.getresponse()
        headers = response.getheaders()
        require(sum(len(key) + len(value) for key, value in headers) <= 8192, 'response_header_limit')
        body = response.read(65537)
        require(len(body) <= 65536, 'response_body_limit')
        lengths = [value for key, value in headers if key.lower() == 'content-length']
        require(not lengths or (len(lengths) == 1 and lengths[0] == str(len(body))), 'incomplete_http_body')
        locations = [value for key, value in headers if key.lower() == 'location']
        require(len(locations) <= 1, 'duplicate_location')
        return response.status, locations[0] if locations else None, body
    finally:
        conn.close()


def callback_owner(pid):
    four, six = listeners()
    candidates = [inode for address, inode in four if address == f'0100007F:{CALLBACK_PORT:04X}']
    require(not any(address.endswith(f':{CALLBACK_PORT:04X}') for address, _ in six), 'callback_ipv6_refused')
    other = [address for address, _ in four if address.endswith(f':{CALLBACK_PORT:04X}')
             and address != f'0100007F:{CALLBACK_PORT:04X}']
    require(not other and len(candidates) <= 1, 'callback_bind_mismatch')
    if not candidates:
        return False
    sockets = {os.readlink(path) for path in Path(f'/proc/{pid}/fd').iterdir() if path.is_symlink()}
    require(f'socket:[{candidates[0]}]' in sockets, 'callback_owner_mismatch')
    return True


def wait_callback(native, record):
    process = record['process']
    while True:
        native.check(record)
        require(process.poll() is None, 'continuation_exited_before_callback')
        body = record['out'].read_bytes() + record['err'].read_bytes()
        urls = set(re.findall(rb'http://127\.0\.0\.1:53682/auth\?[^\r\n]*[\r\n]', body))
        states = set()
        for url in urls:
            match = re.fullmatch(rb'http://127\.0\.0\.1:53682/auth\?state=([A-Za-z0-9_-]{22})[\r\n]+', url)
            require(match is not None, 'callback_url_mismatch')
            states.add(match.group(1))
        require(len(states) <= 1, 'multiple_callback_states')
        if states and callback_owner(process.pid):
            value = next(iter(states)).decode('ascii')
            raw = base64.urlsafe_b64decode(value + '==')
            require(len(raw) == 16 and base64.urlsafe_b64encode(raw).decode().rstrip('=') == value,
                    'callback_state_not_canonical')
            return value
        time.sleep(0.02)


def output_matches(destination):
    entries = list(destination.iterdir())
    require(len(entries) == 1 and entries[0].name == MEMBER, 'acquisition_scope_changed')
    require(regular(entries[0]).st_size == 62 and digest(entries[0]) == MEMBER_SHA, 'acquisition_hash_mismatch')


def remove_owned(root, identity):
    require(root.parent == WORK and not root.is_symlink() and (root.stat().st_dev, root.stat().st_ino) == identity,
            'temporary_root_changed')
    for path in root.rglob('*'):
        info = path.lstat()
        require(not path.is_symlink() and info.st_uid == UID and (stat.S_ISDIR(info.st_mode)
                or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1)), 'cleanup_entry_refused')
    shutil.rmtree(root)
    return not root.exists() and not any(WORK.iterdir())


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def new_report(scope, checks):
    return {'schema_version': 1, 'scope': scope, 'ledger_eligible': False,
              'started_utc': utc_now(), 'finished_utc': None, 'runtime': {'platform': sys.platform,
              'architecture': 'amd64' if platform.machine() == 'x86_64' else platform.machine(),
              'uid': os.getuid() if hasattr(os, 'getuid') else -1, 'gid': os.getgid() if hasattr(os, 'getgid') else -1,
              'python_version': platform.python_version(), 'cryptography_version': '', 'rclone_version': '',
              'rclone_sha256': '', 'probe_sha256': digest(Path(__file__)), 'fixture_manifest_sha256': MANIFEST_SHA},
              'checks': dict.fromkeys(checks, False), 'observations': dict.fromkeys(
                  ('native_commands', 'http_transactions', 'callback_requests', 'https_requests'), 0),
              'cleanup': dict.fromkeys(CLEANUP, False), 'success': False, 'errors': []}


def finish_report(report, native, fixture, state, root, identity, *, fixture_attempted=False):
    report['observations']['native_commands'] = len(native.records) if native else 0
    report['observations']['https_requests'] = state.requests if state else 0
    report['observations']['http_transactions'] = (report['observations']['callback_requests']
                                                   + report['observations']['https_requests'])
    try:
        report['cleanup']['children_stopped'] = native.close() if native else True
    except Exception:
        report['errors'].append('child_cleanup_failed')
    fixture_stopped = not fixture_attempted and fixture is None
    try:
        if fixture_attempted or fixture is not None:
            require(fixture is not None and state is not None, 'fixture_cleanup_unproved')
            require(fixture.cleanup_complete and state.cleanup_complete and state.source_preserved(), 'fixture_cleanup_failed')
            snapshot = fixture.snapshot()
            require(not snapshot['transport']['failure_codes'], 'transport_cleanup_failed')
            fixture_stopped = True
    except Exception:
        report['errors'].append('fixture_cleanup_failed')
    try:
        report['cleanup']['listeners_closed'] = listeners() == ([], []) if sys.platform == 'linux' else False
    except Exception:
        report['errors'].append('listener_cleanup_failed')
    try:
        # A failed constructor can leave no returned fixture object. Retain the
        # private root unless every attempted worker/listener is proved stopped.
        require(report['cleanup']['children_stopped'] and report['cleanup']['listeners_closed']
                and fixture_stopped, 'worker_cleanup_unproved')
        report['cleanup']['temporary_removed'] = remove_owned(root, identity) if root else True
    except Exception:
        report['errors'].append('temporary_cleanup_failed')
    report['finished_utc'] = utc_now()
    report['success'] = (not report['errors'] and all(report['checks'].values()) and all(report['cleanup'].values()))


def saved_token(path, options, access, refresh, seconds, issued):
    values = config_values(path)
    require(set(values) == set(options) | {'token'} and
            {key: value for key, value in values.items() if key != 'token'} == options,
            'non_token_config_changed')
    token = strict_json(values['token'])
    require(type(token) is dict and set(token) == {'access_token', 'refresh_token', 'token_type', 'expiry', 'expires_in'}
            and token['access_token'] == access and token['refresh_token'] == refresh
            and token['token_type'] == 'Bearer' and type(token['expires_in']) is int
            and token['expires_in'] == seconds, 'persisted_token_mismatch')
    require(type(token['expiry']) is str and re.fullmatch(
        r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z', token['expiry']),
        'token_expiry_invalid')
    try:
        expiry = datetime.fromisoformat(token['expiry'].replace('Z', '+00:00')).timestamp()
    except (ValueError, OverflowError):
        raise ProbeError('token_expiry_invalid') from None
    require(type(issued) is float and issued - 1 <= expiry - seconds <= issued + 2,
            'token_expiry_unbound')
    return expiry


def await_expiry(native, expiry):
    # Wait for actual persisted wall-clock expiry, not oauth2's 10-second
    # early-expiry window, and never edit the saved credential.
    deadline = min(native.deadline, time.monotonic() + 5)
    while time.time() <= expiry + 0.05:
        require(time.monotonic() < deadline, 'token_expiry_deadline')
        time.sleep(0.02)


def cancel_owned(native, record):
    process = record['process']
    native.check(record)
    require(process.poll() is None and proc_identity(process.pid) == record['identity']
            and record['identity'][1:] == (UID, process.pid), 'cancellation_owner_mismatch')
    os.killpg(process.pid, signal.SIGTERM)
    try:
        code = process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        raise ProbeError('cancellation_deadline') from None
    native.check(record)
    require(type(code) is int and code != 0, 'cancellation_exit_mismatch')
    return code


def flow_matches(state, mode):
    if (state.failed or state.unexpected or state.budget_exceeded or state.rejected_payload_bytes
            or state.rejected_mutations or not state.source_preserved()):
        return False
    expected = [] if mode == 'callback_cancel' else [('authorize', '')]
    if mode in ('positive', 'refresh', 'refresh_denied', 'refresh_cancel', 'invalid_code', 'wrong_client_secret'):
        expected += [('code_basic', ''), ('code_denied' if mode in ('invalid_code', 'wrong_client_secret') else 'code_grant', '')]
    if mode in ('refresh', 'refresh_denied', 'refresh_cancel'):
        expected += [('refresh_basic', ''), ({'refresh': 'refresh_grant', 'refresh_denied': 'refresh_denied',
                                             'refresh_cancel': 'refresh_held'}[mode], '')]
    if mode in ('positive', 'refresh'):
        expected += [('metadata', MEMBER), ('content', MEMBER)]
    counts = {key: sum(event[0] == key for event in expected) for key in
              ('authorize', 'code_basic', 'code_grant', 'code_denied', 'refresh_basic',
               'refresh_grant', 'refresh_denied', 'refresh_held', 'metadata', 'content')}
    return (state.events == expected and state.requests == len(expected)
            and state.authorize_requests == counts['authorize']
            and state.token_requests == counts['code_basic'] + counts['code_grant'] + counts['code_denied']
            and state.refresh_requests == counts['refresh_basic'] + counts['refresh_grant'] + counts['refresh_denied'] + counts['refresh_held']
            and state.auth_style_probes == counts['code_basic'] + counts['refresh_basic']
            and state.grant_denials == counts['code_denied'] + counts['refresh_denied']
            and state.authenticated == counts['metadata'] + counts['content']
            and state.payload_bytes == counts['content'] * 62
            and state.token_issued == bool(counts['code_grant'])
            and state.refresh_issued == bool(counts['refresh_grant'])
            and (mode != 'refresh_cancel' or state.hold_completed))


def callback_denial(mode, code, output, error, original, alternate):
    require(type(code) is int and code > 0 and output == b'', 'denial_process_result')
    if mode in ('wrong_state', 'blank_state'):
        got = alternate if mode == 'wrong_state' else ''
        marker = ('Error: Auth state doesn\'t match\nCode: ""\nDescription: Expecting "' +
                  original + '" got "' + got + '"').encode('ascii')
    elif mode == 'consent_denied':
        marker = b'No code returned by remote server: access_denied: synthetic consent denied'
    else:
        marker = b'oauth2: "invalid_client" "synthetic grant rejected"' if mode == 'wrong_client_secret' else b'oauth2: "invalid_grant" "synthetic grant rejected"'
    require(marker in error, 'expected_auth_denial_absent')


def refresh_denial_output(code, output, expected_input):
    require(type(code) is int and code > 0, 'refresh_denial_exit')
    data = strict_json(output)
    require(type(data) is dict and set(data) == {'error', 'input', 'path', 'status'}
            and data['path'] == 'operations/copyfile' and type(data['status']) is int and data['status'] == 500
            and type(expected_input) is dict and type(data['input']) is dict and data['input'] == expected_input
            and type(data['error']) is str
            and 'invalid_grant: maybe token expired?' in data['error'], 'refresh_denial_result')


def run_case(binary, manifest, mode):
    require(mode in AUTH_CASES, 'unknown_case')
    report = new_report('gcs_oauth_lifecycle_case', CASE_CHECKS[mode])
    native = fixture = state = root = identity = None
    fixture_attempted = False
    try:
        environment_checks()
        report['checks']['environment'] = True
        version, expected_sha = pins(manifest)
        require(regular(binary).st_uid == 0 and digest(binary) == expected_sha, 'runtime_hash_mismatch')
        import cryptography
        report['runtime'].update(cryptography_version=cryptography.__version__, rclone_version=version, rclone_sha256=expected_sha)
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from fixture_oauth import OAuthState, serve_oauth, SCOPE, REFRESH_MODES
        root = Path(tempfile.mkdtemp(prefix='gcs-oauth-', dir=WORK))
        root.chmod(0o700)
        identity = root.stat().st_dev, root.stat().st_ino
        native = Native(binary, root)
        code, output, _ = native.run(['version'])
        require(code == 0 and output.splitlines()[0] == ('rclone v' + version).encode(), 'runtime_version_mismatch')
        report['checks']['version_binding'] = True
        credentials = [secrets.token_urlsafe(24) for _ in range(9)]
        alternate_state = secrets.token_urlsafe(16)
        state = OAuthState(dict(FILES), *credentials[:7], mode=mode, alternate_state=alternate_state,
                           alternate_code=credentials[7], alternate_secret=credentials[8])
        fixture_attempted = True
        with serve_oauth(root, state) as fixture:
            options = {'type': 'google cloud storage', 'client_id': state.client_id,
                       'client_secret': state.alternate_secret if mode == 'wrong_client_secret' else state.client_secret,
                       'client_credentials': 'false', 'anonymous': 'false', 'env_auth': 'false',
                       'service_account_file': '', 'service_account_credentials': '', 'project_number': '',
                       'auth_url': 'https://' + fixture.host + '/oauth/authorize',
                       'token_url': 'https://' + fixture.host + '/oauth/token',
                       'endpoint': 'https://' + fixture.host + '/storage/v1/'}
            create = ['config', 'create', 'Synthetic', 'google cloud storage', '--non-interactive',
                      *[key + '=' + value for key, value in options.items() if key != 'type'], 'config_auth_no_browser=true']
            code, output, _ = native.run(create, fixture.rclone_ca_args())
            require(code == 0, 'create_config_failed')
            continuation = question(output)
            require(config_values(native.config) == options and not state.requests, 'initial_config_or_network_changed')
            initial = native.config.read_bytes()
            report['checks']['initial_config_question'] = True
            record = native.start(['config', 'update', 'Synthetic', '--continue', '--state', continuation,
                                   '--result', 'true', 'config_auth_no_browser=true'], fixture.rclone_ca_args(), notice=True)
            callback_state = wait_callback(native, record)
            report['checks']['callback_ownership'] = True
            if mode == 'callback_cancel':
                cancel_owned(native, record)
                report['checks']['owned_process_cancel'] = True
            else:
                status, location, _ = request(CALLBACK_PORT, '/auth?state=' + callback_state, '127.0.0.1:53682')
                report['observations']['callback_requests'] += 1
                require(status == 307 and location, 'authorize_redirect')
                route = validate_location(location, 'https', fixture.host, '/oauth/authorize',
                    {'access_type': 'offline', 'client_id': state.client_id, 'redirect_uri': CALLBACK_URI,
                     'response_type': 'code', 'scope': SCOPE, 'state': callback_state})
                state.bind_state(callback_state)
                status, location, _ = request(fixture.port, route, fixture.host, fixture.client_context())
                require(status == 302 and location, 'callback_redirect')
                values = {'state': alternate_state if mode == 'wrong_state' else '' if mode == 'blank_state' else callback_state}
                if mode == 'consent_denied':
                    values.update(error='access_denied', error_description='synthetic consent denied')
                else:
                    values['code'] = state.alternate_code if mode == 'invalid_code' else state.code
                route = validate_location(location, 'http', '127.0.0.1:53682', '/', values)
                report['checks']['authorize'] = True
                status, location, body = request(CALLBACK_PORT, route, '127.0.0.1:53682')
                report['observations']['callback_requests'] += 1
                require(status == (400 if mode in ('wrong_state', 'blank_state', 'consent_denied') else 200)
                        and location is None and body, 'callback_response')
                code, output, error = native.finish(record)
                if mode in ('wrong_state', 'blank_state', 'consent_denied', 'invalid_code', 'wrong_client_secret'):
                    callback_denial(mode, code, output, error, callback_state, alternate_state)
                    report['checks']['callback_denial' if mode in ('wrong_state', 'blank_state', 'consent_denied') else 'token_denial'] = True
                else:
                    require(code == 0 and state.token_issued, 'code_exchange_failed')
                    terminal(output)
                    report['checks']['token_exchange'] = True
                    expiry = saved_token(native.config, options, state.token, state.refresh_token,
                                         1 if mode in REFRESH_MODES else 300, state.grant_wall)
                    saved = native.config.read_bytes()
                    report['checks']['config_persisted'] = True
                    if mode in REFRESH_MODES:
                        await_expiry(native, expiry)
                        require(native.config.read_bytes() == saved and time.time() > expiry, 'expiry_not_observed')
                        report['checks']['expired_before_read'] = True
                    destination = root / 'output'
                    destination.mkdir(mode=0o700)
                    args = ['rc', '--loopback', 'operations/copyfile', 'srcFs=Synthetic:synthetic-bucket',
                            'srcRemote=' + MEMBER, 'dstFs=' + str(destination), 'dstRemote=' + MEMBER]
                    record = native.start(args, fixture.rclone_ca_args())
                    if mode == 'refresh_cancel':
                        while not state.refresh_received.wait(0.01):
                            native.check(record)
                            require(record['process'].poll() is None, 'refresh_not_reached')
                        cancel_owned(native, record)
                        state.release_hold.set()
                        deadline = time.monotonic() + 1
                        while not state.hold_completed:
                            require(time.monotonic() < deadline, 'held_request_not_closed')
                            time.sleep(0.01)
                        report['checks']['owned_process_cancel'] = True
                    else:
                        code, output, _ = native.finish(record)
                        if mode == 'refresh_denied':
                            refresh_denial_output(code, output, {'srcFs': 'Synthetic:synthetic-bucket',
                                'srcRemote': MEMBER, 'dstFs': str(destination), 'dstRemote': MEMBER})
                            report['checks']['refresh_denial'] = True
                        else:
                            require(code == 0 and strict_json(output) == {}, 'synthetic_read_failed')
                            output_matches(destination)
                            if mode == 'refresh':
                                saved_token(native.config, options, state.replacement, state.replacement_refresh, 300, state.refresh_wall)
                                report['checks'].update(replacement_read=True, replacement_persisted=True, non_token_config_preserved=True)
                            else:
                                report['checks']['fresh_child_read'] = True
                    if mode in ('positive', 'refresh_denied', 'refresh_cancel'):
                        require(native.config.read_bytes() == saved, 'credential_changed_unexpectedly')
                        report['checks']['config_preserved'] = True
                    if mode in ('refresh_denied', 'refresh_cancel'):
                        require(not any(destination.iterdir()) and not state.payload_bytes and not state.authenticated,
                                'negative_read_or_output')
                        report['checks']['no_read'] = True
            if mode not in ('positive', *REFRESH_MODES):
                require(native.config.read_bytes() == initial and config_values(native.config) == options,
                        'failed_auth_config_changed')
                require(not state.token_issued and not state.authenticated and not state.payload_bytes, 'failed_auth_read_or_token')
                report['checks'].update(no_token_persisted=True, config_preserved=True, no_read=True)
            require(not list(root.glob('synthetic.conf.*')), 'config_backup_leftover')
            require(flow_matches(state, mode), 'request_sequence_mismatch')
            report['checks']['request_sequence'] = True
            require(state.source_preserved(), 'source_changed')
            report['checks']['source_preserved'] = True
    except Exception as error:
        report['errors'].append(str(error) if isinstance(error, ProbeError) and re.fullmatch(r'[a-z][a-z0-9_]{0,79}', str(error))
                                else 'case_operation_failed')
    finally:
        finish_report(report, native, fixture, state, root, identity, fixture_attempted=fixture_attempted)
    return report


def run(binary, manifest):
    started, cases = utc_now(), []
    for name in AUTH_CASES:
        report = run_case(binary, manifest, name)
        cases.append({'name': name, 'report': report})
        if not report['success']:
            break
    okay = len(cases) == len(AUTH_CASES) and all(row['report']['success'] for row in cases)
    return {'schema_version': 1, 'scope': 'gcs_oauth_lifecycle_suite', 'ledger_eligible': False,
            'started_utc': started, 'finished_utc': utc_now(), 'runtime': cases[0]['report']['runtime'],
            'cases': cases, 'success': okay, 'errors': [] if okay else ['lifecycle_case_failed']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rclone', required=True, type=Path)
    parser.add_argument('--manifest', required=True, type=Path)
    args = parser.parse_args()
    report = run(args.rclone, args.manifest)
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))
    return 0 if report['success'] else 1


if __name__ == '__main__':
    sys.exit(main())
