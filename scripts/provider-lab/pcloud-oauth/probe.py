#!/usr/bin/env python3
"""Owned network-none OAuth callback feasibility; never ledger evidence.

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
CALLBACK_URI = 'http://localhost:53682/'
MEMBER = 'README-synthetic.txt'
FILES = {MEMBER: b'Synthetic provider protocol fixture. No account or user data.\n',
         'nested/space name.txt': b'Nested synthetic payload.\n',
         'nested/bytes.bin': bytes(range(256)) * 8}
MEMBER_SHA = '1e901527b93ae84dc9d95a8aa76bbc12d7d77dbf8ab449333c172cfc909c639e'
MANIFEST_SHA = 'c990bbd4909b227aae4c70d26f9da5534740a2eb10337ced47977f915fa617be'
CHECKS = ('environment', 'version_binding', 'initial_config_question', 'callback_ownership',
          'authorize', 'token_exchange', 'config_persisted', 'fresh_child_read',
          'source_preserved', 'post_auth_config_preserved', 'request_sequence')
CLEANUP = ('children_stopped', 'listeners_closed', 'temporary_removed')
AUTH_CASES = ('positive', 'wrong_state', 'consent_denied', 'invalid_code', 'wrong_client_secret', 'cancelled')
NEGATIVE_COMMON_CHECKS = ('environment', 'version_binding', 'initial_config_question', 'callback_ownership',
                          'no_token_persisted', 'config_preserved', 'no_read', 'source_preserved', 'request_sequence')
NEGATIVE_CHECKS = {
    name: NEGATIVE_COMMON_CHECKS + (('owned_process_cancel',) if name == 'cancelled' else
                                  ('authorize', 'callback_denial' if name in ('wrong_state', 'consent_denied') else 'token_denial'))
    for name in AUTH_CASES[1:]
}
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
    result = {}
    for line in path.read_text(encoding='ascii').splitlines():
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition('=')
        require(separator and key in expected and key not in result, 'invalid_runtime_manifest')
        result[key] = value
    require(set(result) == expected and re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)',
            result['RCLONE_VERSION']), 'invalid_runtime_manifest')
    require(all(re.fullmatch(r'[a-f0-9]{64}', result[key]) for key in expected - {'RCLONE_VERSION'}),
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


def check_saved_config(path, options, token):
    values = config_values(path)
    require(set(values) == set(options) | {'token'} and all(values[key] == value for key, value in options.items()),
            'saved_config_options_changed')
    require(strict_json(values['token']) == {'access_token': token, 'token_type': 'bearer',
            'expiry': '0001-01-01T00:00:00Z'}, 'saved_token_mismatch')
    return path.read_bytes()


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


def finish_report(report, native, fixture, state, root, identity):
    report['observations']['native_commands'] = len(native.records) if native else 0
    report['observations']['https_requests'] = state.requests if state else 0
    report['observations']['http_transactions'] = (report['observations']['callback_requests']
                                                   + report['observations']['https_requests'])
    try:
        report['cleanup']['children_stopped'] = native.close() if native else True
    except Exception:
        report['errors'].append('child_cleanup_failed')
    try:
        if fixture is not None:
            require(fixture.cleanup_complete and state.cleanup_complete and state.source_preserved(), 'fixture_cleanup_failed')
            snapshot = fixture.snapshot()
            require(not snapshot['transport']['failure_codes'], 'transport_cleanup_failed')
    except Exception:
        report['errors'].append('fixture_cleanup_failed')
    try:
        report['cleanup']['listeners_closed'] = listeners() == ([], []) if sys.platform == 'linux' else False
    except Exception:
        report['errors'].append('listener_cleanup_failed')
    try:
        # Do not unlink output beneath a child which could still be writing.
        require(report['cleanup']['children_stopped'], 'live_child_prevents_removal')
        report['cleanup']['temporary_removed'] = remove_owned(root, identity) if root else True
    except Exception:
        report['errors'].append('temporary_cleanup_failed')
    report['finished_utc'] = utc_now()
    report['success'] = (not report['errors'] and all(report['checks'].values()) and all(report['cleanup'].values()))


def run(binary, manifest):
    report = new_report('pcloud_oauth_callback_feasibility', CHECKS)
    root = identity = native = fixture = state = None
    try:
        environment_checks()
        require(binary == BASE / 'rclone' and manifest == BASE / 'rclone-version.env', 'fixed_image_paths_required')
        report['checks']['environment'] = True
        version, binary_sha = pins(manifest)
        regular(binary)
        require(digest(binary) == binary_sha, 'rclone_hash_mismatch')
        import cryptography
        require(cryptography.__version__ == '50.0.2', 'certificate_dependency_mismatch')
        report['runtime'].update(cryptography_version=cryptography.__version__, rclone_version=version, rclone_sha256=binary_sha)
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from fixture_oauth import OAuthState, serve_oauth
        root = Path(tempfile.mkdtemp(prefix='oauth-', dir=WORK))
        identity = root.stat().st_dev, root.stat().st_ino
        native = Native(binary, root)
        code, output, _ = native.run(['version'])
        require(code == 0 and output.splitlines()[0] == ('rclone v' + version).encode(), 'runtime_version_mismatch')
        report['checks']['version_binding'] = True
        client_id, client_secret, auth_code, token, wrong_token = (secrets.token_urlsafe(24) for _ in range(5))
        require(len({client_id, client_secret, auth_code, token, wrong_token}) == 5, 'fixture_credential_collision')
        state = OAuthState(dict(FILES), client_id, client_secret, auth_code, token, wrong_token)
        with serve_oauth(root, state) as fixture:
            options = {'type': 'pcloud', 'client_id': client_id, 'client_secret': client_secret,
                       'client_credentials': 'false', 'root_folder_id': 'd100', 'hostname': fixture.host,
                       'auth_url': 'https://' + fixture.host + '/oauth2/authorize',
                       'token_url': 'https://' + fixture.host + '/oauth2_token'}
            create = ['config', 'create', 'Synthetic', 'pcloud', '--non-interactive']
            create += [key + '=' + value for key, value in options.items() if key != 'type']
            create += ['config_auth_no_browser=true']
            code, output, _ = native.run(create, fixture.rclone_ca_args())
            require(code == 0, 'create_config_failed')
            continuation = question(output)
            require(config_values(native.config) == options and state.requests == 0, 'initial_config_or_network_changed')
            report['checks']['initial_config_question'] = True
            record = native.start(['config', 'update', 'Synthetic', '--continue', '--state', continuation,
                                   '--result', 'true', 'config_auth_no_browser=true'], fixture.rclone_ca_args(), notice=True)
            callback_state = wait_callback(native, record)
            report['checks']['callback_ownership'] = True
            status, location, _ = request(CALLBACK_PORT, '/auth?state=' + callback_state, '127.0.0.1:53682')
            report['observations']['callback_requests'] += 1
            require(status == 307 and location is not None, 'auth_redirect_mismatch')
            authorize = validate_location(location, 'https', fixture.host, '/oauth2/authorize',
                                          {'access_type': 'offline', 'client_id': client_id, 'redirect_uri': CALLBACK_URI,
                                           'response_type': 'code', 'state': callback_state})
            state.bind_state(callback_state)
            status, location, _ = request(fixture.port, authorize, fixture.host, fixture.client_context())
            require(status == 302 and location is not None, 'authorize_redirect_mismatch')
            callback = validate_location(location, 'http', 'localhost:53682', '/',
                                         {'code': auth_code, 'state': callback_state, 'locationid': '1', 'hostname': fixture.host})
            report['checks']['authorize'] = True
            status, location, body = request(CALLBACK_PORT, callback, 'localhost:53682')
            report['observations']['callback_requests'] += 1
            require(status == 200 and location is None and bool(body), 'callback_response_mismatch')
            code, output, _ = native.finish(record)
            require(code == 0, 'continuation_failed')
            terminal(output)
            require(state.token_issued and state.token_requests == 1 and state.authorize_requests == 1,
                    'exchange_sequence_mismatch')
            report['checks']['token_exchange'] = True
            saved = check_saved_config(native.config, options, token)
            report['checks']['config_persisted'] = True
            require(not list(root.glob('synthetic.conf.*')), 'config_backup_leftover')
            destination = root / 'output'
            destination.mkdir(mode=0o700)
            code, output, _ = native.run(['rc', '--loopback', 'operations/copyfile', 'srcFs=Synthetic:',
                                         'srcRemote=' + MEMBER, 'dstFs=' + str(destination), 'dstRemote=' + MEMBER],
                                        fixture.rclone_ca_args())
            require(code == 0 and strict_json(output) == {}, 'fresh_child_read_failed')
            output_matches(destination)
            report['checks']['fresh_child_read'] = True
            require(check_saved_config(native.config, options, token) == saved, 'post_auth_config_changed')
            report['checks']['post_auth_config_preserved'] = True
            expected_events = [('authorize', ''), ('token', ''), ('root_list', ''), ('checksum', MEMBER),
                               ('link', MEMBER), ('content', MEMBER)]
            require(state.events == expected_events and state.requests == 6 and state.payload_bytes == 62
                    and state.authenticated == 4 and state.authorize_requests == state.token_requests == 1
                    and state.source_preserved(), 'protocol_sequence_mismatch')
            require(not any(getattr(state, field) for field in ('unexpected', 'auth_denied', 'member_denied',
                    'rejected_mutations', 'rejected_payload_bytes', 'budget_exceeded')), 'unexpected_protocol_observation')
            report['checks']['source_preserved'] = True
            require(len(native.records) == 4 and report['observations']['callback_requests'] == 2, 'case_count_mismatch')
            report['checks']['request_sequence'] = True
    except ProbeError as error:
        report['errors'].append(str(error))
    except KeyboardInterrupt:
        report['errors'].append('probe_interrupted')
    except Exception:
        report['errors'].append('probe_unexpected_failure')
    finally:
        finish_report(report, native, fixture, state, root, identity)
    return report


def deny_native_output(mode, code, output, error, callback_state, alternate_state):
    require(type(code) is int and code > 0 and output == b'', 'denial_process_result_mismatch')
    if mode == 'wrong_state':
        marker = ('Error: Auth state doesn\'t match\nCode: ""\nDescription: Expecting "'
                  + callback_state + '" got "' + alternate_state + '"').encode('ascii')
    elif mode == 'consent_denied':
        marker = (b'Error: Auth Error\nCode: ""\nDescription: No code returned by remote server: '
                  b'access_denied: synthetic consent denied')
    elif mode == 'invalid_code':
        marker = b'failed to get token: oauth2: "invalid_grant" "synthetic authorization code rejected"'
    elif mode == 'wrong_client_secret':
        marker = b'failed to get token: oauth2: "invalid_client" "synthetic client secret rejected"'
    else:
        raise ProbeError('unknown_denial_mode')
    require(type(error) is bytes and marker in error, 'native_denial_reason_mismatch')


def cancel_waiting(native, record):
    native.check(record)
    process = record['process']
    require(process.poll() is None and proc_identity(process.pid) == record['identity']
            and record['identity'][1:] == (UID, process.pid), 'cancellation_owner_mismatch')
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(3)
    except subprocess.TimeoutExpired:
        raise ProbeError('cancellation_deadline') from None
    code, output, _ = native.finish(record)
    require(type(code) is int and code != 0 and output == b'', 'cancellation_result_mismatch')


def run_negative(binary, manifest, mode):
    require(mode in NEGATIVE_CHECKS, 'unknown_denial_mode')
    report = new_report('pcloud_oauth_authentication_case', NEGATIVE_CHECKS[mode])
    root = identity = native = fixture = state = None
    try:
        environment_checks()
        require(binary == BASE / 'rclone' and manifest == BASE / 'rclone-version.env', 'fixed_image_paths_required')
        report['checks']['environment'] = True
        version, binary_sha = pins(manifest)
        regular(binary)
        require(digest(binary) == binary_sha, 'rclone_hash_mismatch')
        import cryptography
        require(cryptography.__version__ == '50.0.2', 'certificate_dependency_mismatch')
        report['runtime'].update(cryptography_version=cryptography.__version__, rclone_version=version, rclone_sha256=binary_sha)
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from fixture_oauth import OAuthState, serve_oauth
        root = Path(tempfile.mkdtemp(prefix='oauth-', dir=WORK))
        identity = root.stat().st_dev, root.stat().st_ino
        native = Native(binary, root)
        code, output, _ = native.run(['version'])
        require(code == 0 and output.splitlines()[0] == ('rclone v' + version).encode(), 'runtime_version_mismatch')
        report['checks']['version_binding'] = True
        client_id, client_secret, auth_code, token, wrong_token, alternate_code, alternate_secret = (
            secrets.token_urlsafe(24) for _ in range(7))
        alternate_state = secrets.token_urlsafe(16)
        require(len({client_id, client_secret, auth_code, token, wrong_token, alternate_code,
                     alternate_secret, alternate_state}) == 8, 'fixture_credential_collision')
        state = OAuthState(dict(FILES), client_id, client_secret, auth_code, token, wrong_token,
                           mode=mode, alternate_state=alternate_state, alternate_code=alternate_code,
                           alternate_secret=alternate_secret)
        with serve_oauth(root, state) as fixture:
            options = {'type': 'pcloud', 'client_id': client_id,
                       'client_secret': alternate_secret if mode == 'wrong_client_secret' else client_secret,
                       'client_credentials': 'false', 'root_folder_id': 'd100', 'hostname': fixture.host,
                       'auth_url': 'https://' + fixture.host + '/oauth2/authorize',
                       'token_url': 'https://' + fixture.host + '/oauth2_token'}
            create = ['config', 'create', 'Synthetic', 'pcloud', '--non-interactive']
            create += [key + '=' + value for key, value in options.items() if key != 'type']
            create += ['config_auth_no_browser=true']
            code, output, _ = native.run(create, fixture.rclone_ca_args())
            require(code == 0, 'create_config_failed')
            continuation = question(output)
            require(config_values(native.config) == options and state.requests == 0, 'initial_config_or_network_changed')
            pre_auth = native.config.read_bytes()
            report['checks']['initial_config_question'] = True
            record = native.start(['config', 'update', 'Synthetic', '--continue', '--state', continuation,
                                   '--result', 'true', 'config_auth_no_browser=true'], fixture.rclone_ca_args(), notice=True)
            callback_state = wait_callback(native, record)
            require(callback_state != alternate_state, 'fixture_state_collision')
            report['checks']['callback_ownership'] = True
            if mode == 'cancelled':
                cancel_waiting(native, record)
                report['checks']['owned_process_cancel'] = True
            else:
                status, location, _ = request(CALLBACK_PORT, '/auth?state=' + callback_state, '127.0.0.1:53682')
                report['observations']['callback_requests'] += 1
                require(status == 307 and location is not None, 'auth_redirect_mismatch')
                authorize = validate_location(location, 'https', fixture.host, '/oauth2/authorize',
                                              {'access_type': 'offline', 'client_id': client_id, 'redirect_uri': CALLBACK_URI,
                                               'response_type': 'code', 'state': callback_state})
                state.bind_state(callback_state)
                status, location, _ = request(fixture.port, authorize, fixture.host, fixture.client_context())
                require(status == 302 and location is not None, 'authorize_redirect_mismatch')
                expected = {'state': alternate_state if mode == 'wrong_state' else callback_state,
                            'locationid': '1', 'hostname': fixture.host}
                if mode == 'consent_denied':
                    expected.update(error='access_denied', error_description='synthetic consent denied')
                else:
                    expected['code'] = alternate_code if mode == 'invalid_code' else auth_code
                callback = validate_location(location, 'http', 'localhost:53682', '/', expected)
                report['checks']['authorize'] = True
                status, location, body = request(CALLBACK_PORT, callback, 'localhost:53682')
                report['observations']['callback_requests'] += 1
                callback_denial = mode in ('wrong_state', 'consent_denied')
                require(status == (400 if callback_denial else 200) and location is None and bool(body),
                        'denial_callback_response_mismatch')
                code, output, error = native.finish(record)
                deny_native_output(mode, code, output, error, callback_state, alternate_state)
                if callback_denial:
                    require(state.token_requests == state.token_denials == state.basic_denials == state.form_denials == 0,
                            'unexpected_denial_exchange')
                    report['checks']['callback_denial'] = True
                else:
                    require(state.token_requests == state.token_denials == state.auth_denied == 2
                            and state.basic_denials == state.form_denials == 1, 'token_denial_sequence_mismatch')
                    report['checks']['token_denial'] = True
            values = config_values(native.config)
            require(not state.token_issued and 'token' not in values, 'denial_saved_token')
            report['checks']['no_token_persisted'] = True
            require(values == options and native.config.read_bytes() == pre_auth
                    and not list(root.glob('synthetic.conf.*')), 'denial_config_changed')
            report['checks']['config_preserved'] = True
            require(state.authenticated == state.payload_bytes == 0 and not (root / 'output').exists(), 'denial_returned_data')
            report['checks']['no_read'] = True
            require(state.source_preserved(), 'denial_source_changed')
            report['checks']['source_preserved'] = True
            require(not state.failed and not any(getattr(state, field) for field in
                    ('unexpected', 'member_denied', 'rejected_mutations', 'rejected_payload_bytes', 'budget_exceeded')),
                    'unexpected_protocol_observation')
            expected_events = [] if mode == 'cancelled' else [('authorize', '')]
            if mode in ('invalid_code', 'wrong_client_secret'):
                error_code = 'invalid_grant' if mode == 'invalid_code' else 'invalid_client'
                expected_events += [('token_denied_basic', error_code), ('token_denied_form', error_code)]
            expected_phase = ('unbound' if mode == 'cancelled' else 'denied' if len(expected_events) == 3 else 'authorized')
            require(state.events == expected_events and state.phase == expected_phase and state.requests == len(expected_events)
                    and state.authorize_requests == (0 if mode == 'cancelled' else 1)
                    and state.auth_denied == (2 if len(expected_events) == 3 else 0)
                    and len(native.records) == 3 and report['observations']['callback_requests'] == (0 if mode == 'cancelled' else 2),
                    'case_count_mismatch')
            report['checks']['request_sequence'] = True
    except ProbeError as error:
        report['errors'].append(str(error))
    except KeyboardInterrupt:
        report['errors'].append('probe_interrupted')
    except Exception:
        report['errors'].append('probe_unexpected_failure')
    finally:
        finish_report(report, native, fixture, state, root, identity)
    return report


def run_authentication(binary, manifest):
    suite = {'schema_version': 1, 'scope': 'pcloud_oauth_authentication_suite', 'ledger_eligible': False,
             'started_utc': utc_now(), 'finished_utc': None, 'runtime': None, 'cases': [], 'success': False, 'errors': []}
    for name in AUTH_CASES:
        report = run(binary, manifest) if name == 'positive' else run_negative(binary, manifest, name)
        if suite['runtime'] is None:
            suite['runtime'] = dict(report['runtime'])
        suite['cases'].append({'name': name, 'report': report})
        if not report['success']:
            suite['errors'].append('authentication_case_failed')
            break
    suite['finished_utc'] = utc_now()
    suite['success'] = len(suite['cases']) == len(AUTH_CASES) and not suite['errors']
    return suite


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rclone', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--authentication-suite', action='store_true')
    args = parser.parse_args()
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    report = (run_authentication(args.rclone, args.manifest) if args.authentication_suite else run(args.rclone, args.manifest))
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))
    return 0 if report['success'] else 1


if __name__ == '__main__':
    sys.exit(main())
