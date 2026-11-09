"""Pure, source-bound HDFS protocol evidence. No native tools or credentials.

The producer's feasibility/acceptance flags stay false. This separate envelope
can credit only six protocol capabilities after validating the complete proof.
"""
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat

HERE = Path(__file__).resolve().parent
MODE = 'hdfs_kerberos_transfer_read_v1'
CAPABILITIES = ('listing', 'download_hash', 'missing_object_rejection',
                'authentication_rejection', 'source_preservation', 'cleanup')
MAX_RECEIPT = 128 * 1024
SOURCES = (
    'HdfsKerberosTransferProbe.java', 'HdfsTransferJson.java', 'transfer_container.py',
    '../hdfs-discovery/bootstrap_material.py', '../hdfs-discovery/graph_export.py',
    '../hdfs-discovery/offline_cache.py', '../hdfs-discovery/resolver_discovery.py',
    '../hdfs-discovery/artifact-lock-kerberos-remediation.json',
    '../hdfs-kerberos-rpc/runtime-classpath-remediation.json', '../../../rclone-version.env',
)
TOP_KEYS = set('schema_version scope runtime platform architecture harness_sha256 fixture_manifest_sha256 started_utc finished_utc success cleanup_passed backends errors native_evidence'.split())
NATIVE_KEYS = set('build_diagnostic candidate_profile cleanup cleanup_excludes duration_seconds errors finished_utc inputs java_validation_stage result schema_version scope stage started_utc success'.split())
INPUT_KEYS = set('base_observation candidate_profile container_id context_sha256 hadoop_version image_id jdk_config_id jdk_manifest kerby_version lock_sha256 rclone_sha256 rclone_version runtime_bytes runtime_classpath_sha256 runtime_file_sha256 runtime_jars source_sha256'.split())
RESULT_KEYS = set('acquired_bytes acquisitions cache_bytes checks child_count cleanup diagnostic error expected_kerby_version metrics_mode missing_category missing_object_category observed_lifetime_seconds owned_thread_cleanup pipeline_origin pipeline_server_diagnostic rc_hash_sha256 rclone_observation rclone_wire_oracle relay remaining_executor_kind remaining_thread_intervals remaining_thread_matrix remaining_threads remaining_timer_kinds runtime_binding_required schema_version scope seed_checkpoint ssl_capture stage success thread_observation_complete wire_oracle'.split())
OUTER_CLEANUP = {'container_removed', 'context_removed', 'image_removed', 'raw_evidence_removed'}
ORACLE = dict(bounded_single_response=True, category='simple_disabled_kerberos_offered',
              detail='FATAL_UNAUTHORIZED', endpoint='namenode_loopback', rpc_version=9, status='FATAL')
_CONTRACT = None


def require(condition, code):
    if not condition:
        raise ValueError(code)


def exact(value, keys, code='hdfs_receipt_shape_invalid'):
    require(type(value) is dict and set(value) == set(keys), code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def parse(raw):
    require(type(raw) is bytes and len(raw) <= MAX_RECEIPT, 'hdfs_receipt_size_invalid')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'hdfs_duplicate_key')
            result[key] = value
        return result
    def constant(_):
        raise ValueError('hdfs_nonfinite_json')
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)
    except ValueError as error:
        if str(error) in ('hdfs_duplicate_key', 'hdfs_nonfinite_json'):
            raise
        raise ValueError('hdfs_json_invalid') from None
    except (UnicodeError, RecursionError):
        raise ValueError('hdfs_json_invalid') from None


def file_bytes(path, limit=512 * 1024):
    path = Path(os.path.abspath(path))
    for item in (path, *path.parents):
        info = item.lstat()
        require(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400,
                'hdfs_source_link_refused')
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit,
            'hdfs_source_file_invalid')
    identity = lambda v: (v.st_dev, v.st_ino, v.st_mode, v.st_nlink, v.st_size, v.st_mtime_ns)
    with path.open('rb') as stream:
        require(identity(info) == identity(os.fstat(stream.fileno())), 'hdfs_source_changed')
        raw = stream.read(limit + 1)
        require(identity(info) == identity(os.fstat(stream.fileno())), 'hdfs_source_changed')
    require(identity(info) == identity(path.lstat()) and len(raw) <= limit, 'hdfs_source_changed')
    return raw


def contract():
    global _CONTRACT
    path = HERE / 'transfer_container.py'
    raw = file_bytes(path)
    digest = sha(raw)
    if _CONTRACT is None or _CONTRACT[0] != digest:
        spec = importlib.util.spec_from_file_location('hdfs_protocol_producer_contract', path)
        module = importlib.util.module_from_spec(spec)
        exec(compile(raw, str(path), 'exec'), module.__dict__)  # Inert definitions only.
        _CONTRACT = (digest, module)
    return _CONTRACT[1]


def fixture_manifest():
    # Independent bytes oracle; these are fixture data, not acquired outputs.
    pattern = bytes(range(256))
    return [dict(path=name, size=size, sha256=sha(pattern * (size // 256) + pattern[:size % 256]))
            for name, size in (('empty.bin', 0), ('nested/space name.bin', 4096), ('payload.bin', 1052673))]


def compute_bindings(root=HERE):
    require(Path(root).absolute() == HERE, 'hdfs_source_root_invalid')
    f = contract()
    sources = {Path(name).name: file_bytes(HERE / name, 131072 if name.endswith('.java') else 524288)
               for name in SOURCES}
    require(sha(sources['HdfsKerberosTransferProbe.java']) == f.JAVA_SHA
            and sha(sources['HdfsTransferJson.java']) == f.JSON_SHA, 'hdfs_java_pin_mismatch')
    pins = f.profile_settings('kerberos-remediation')
    runtime_raw = sources['runtime-classpath-remediation.json']
    lock_raw = sources['artifact-lock-kerberos-remediation.json']
    rows = f.runtime_rows(runtime_raw, lock_raw, profile='kerberos-remediation')
    require(len(rows) == 142, 'hdfs_runtime_count_invalid')
    pin_lines = sources['rclone-version.env'].decode('ascii').splitlines()
    require('RCLONE_VERSION=' + f.RCLONE_VERSION in pin_lines
            and 'RCLONE_LINUX_EXE_SHA256=' + f.RCLONE_SHA in pin_lines, 'hdfs_rclone_pin_mismatch')
    source_hashes = {name: sha(raw) for name, raw in sources.items()}
    source_hashes['rclone-hdfs-transfer'] = f.RCLONE_SHA
    context = {f'jars/{i:03d}.jar': row['sha256'] for i, row in enumerate(rows)}
    context.update({'runtime-classpath.json': sha(runtime_raw), pins['lock'].name: sha(lock_raw),
                    'HdfsKerberosTransferProbe.java': f.JAVA_SHA, 'HdfsTransferJson.java': f.JSON_SHA,
                    'rclone': f.RCLONE_SHA})
    context.update({'resources/' + name: sha(raw) for name, raw in f.webapp_resources().items()})
    context.update({name: sha(raw) for name, raw in f.build_files(rows).items()})
    harness = hashlib.sha256()
    for name in sorted((*SOURCES, 'protocol_evidence.py')):
        harness.update(name.encode() + b'\0' + file_bytes(HERE / name) + b'\0')
    return dict(harness_sha256=harness.hexdigest(), fixture_manifest_sha256=sha(canonical(fixture_manifest())),
                source_sha256=source_hashes, context_sha256=sha(canonical(context)),
                jdk_manifest=f.BASE, jdk_config_id=f.BASE_ID, rclone_version=f.RCLONE_VERSION,
                rclone_sha256=f.RCLONE_SHA, runtime_jars=len(rows), runtime_bytes=sum(x['size'] for x in rows),
                lock_sha256=pins['lock_sha256'], runtime_file_sha256=pins['runtime_sha256'],
                runtime_classpath_sha256=pins['order_sha256'])


def utc(value):
    require(type(value) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|\+00:00)', value),
            'hdfs_receipt_time_invalid')
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise ValueError('hdfs_receipt_time_invalid') from None


def utc_text(value):
    return utc(value).isoformat().replace('+00:00', 'Z')


def validate_native(native, bindings, now, max_age_hours=24):
    f = contract()
    exact(native, NATIVE_KEYS | set(f.FALSE_CLAIMS))
    require(all(native[key] is False for key in f.FALSE_CLAIMS), 'hdfs_acceptance_claim_refused')
    require(type(native['schema_version']) is int and native['schema_version'] == 1
            and native['scope'] == 'hdfs_kerberos_transfer_container_feasibility'
            and native['candidate_profile'] == 'kerberos-remediation', 'hdfs_native_scope_invalid')
    require(native['success'] is True and native['stage'] == 'completed' and native['errors'] == []
            and native['build_diagnostic'] is None and native['java_validation_stage'] == 'not_observed',
            'hdfs_native_failed')
    exact(native['cleanup'], OUTER_CLEANUP)
    require(all(x is True for x in native['cleanup'].values())
            and native['cleanup_excludes'] == ['shared_base_image', 'shared_build_cache'], 'hdfs_cleanup_invalid')
    start, finish = utc(native['started_utc']), utc(native['finished_utc'])
    require(isinstance(now, datetime) and now.tzinfo is not None and now.utcoffset() is not None
            and type(max_age_hours) is int and 1 <= max_age_hours <= 168, 'hdfs_freshness_policy_invalid')
    require(start <= finish <= now and finish >= now - timedelta(hours=max_age_hours)
            and finish - start <= timedelta(minutes=20), 'hdfs_receipt_stale_or_duration_invalid')
    duration = native['duration_seconds']
    require(type(duration) in (int, float) and 0 < duration <= 1200 and math.isfinite(duration)
            and abs((finish-start).total_seconds()-duration) < 1, 'hdfs_duration_invalid')
    inputs = native['inputs']; exact(inputs, INPUT_KEYS)
    for key in ('source_sha256', 'context_sha256', 'jdk_manifest', 'jdk_config_id', 'rclone_version',
                'rclone_sha256', 'runtime_jars', 'runtime_bytes', 'lock_sha256',
                'runtime_file_sha256', 'runtime_classpath_sha256'):
        require(type(inputs[key]) is type(bindings[key]) and inputs[key] == bindings[key], 'hdfs_native_binding_mismatch')
    require(inputs['candidate_profile'] == 'kerberos-remediation' and inputs['hadoop_version'] == '3.5.0'
            and inputs['kerby_version'] == '2.1.2', 'hdfs_dependency_version_invalid')
    for key, prefix in (('image_id', 'sha256:'), ('container_id', '')):
        require(type(inputs[key]) is str and re.fullmatch(prefix + '[a-f0-9]{64}', inputs[key]), 'hdfs_runtime_identity_invalid')
    observation = inputs['base_observation']
    exact(observation, {'id_kind', 'linux', 'amd64', 'config_present', 'java_options_absent'})
    require(observation['id_kind'] in ('manifest_digest', 'config_digest')
            and all(observation[key] is True for key in ('linux', 'amd64', 'config_present', 'java_options_absent')),
            'hdfs_base_observation_invalid')
    value = native['result']; exact(value, RESULT_KEYS | f.JAVA_FALSE)
    require(all(value[key] is False for key in f.JAVA_FALSE), 'hdfs_acceptance_claim_refused')
    require(type(value['schema_version']) is int and value['schema_version'] == 1
            and value['scope'] == 'hdfs_kerberos_transfer_feasibility'
            and value['runtime_binding_required'] is True and value['expected_kerby_version'] == '2.1.2',
            'hdfs_result_scope_invalid')
    require(value['success'] is True and value['stage'] == 'completed' and value['error'] is None, 'hdfs_result_failed')
    for key, keys in (('checks', f.JAVA_CHECKS), ('cleanup', f.JAVA_CLEANUP)):
        exact(value[key], keys)
        require(all(x is True for x in value[key].values()), 'hdfs_result_proof_incomplete')
    require(type(value['cache_bytes']) is int and 100 < value['cache_bytes'] <= 65536
            and type(value['observed_lifetime_seconds']) is int and 110 <= value['observed_lifetime_seconds'] <= 120,
            'hdfs_ticket_bound_invalid')
    for key in ('wire_oracle', 'rclone_wire_oracle'):
        exact(value[key], ORACLE)
        require(all(type(value[key][k]) is type(expected) and value[key][k] == expected for k, expected in ORACLE.items()),
                'hdfs_authentication_oracle_invalid')
    require(value['remaining_executor_kind'] == 'not_observed' and type(value['pipeline_origin']) is str
            and value['pipeline_origin'] in f.DIAGNOSTIC_ORIGINS | {'not_observed'}, 'hdfs_diagnostic_invalid')
    try:
        f.validate_metrics_mode(value['metrics_mode'], value['checks'], value['cleanup'])
        f.validate_ssl_capture(value['ssl_capture'], value['checks'], value['cleanup'], None)
        f.validate_seed_checkpoint(value['seed_checkpoint'], value['checks'])
        f.validate_pipeline_server(value['pipeline_server_diagnostic'])
        f.validate_rclone_observation(value['rclone_observation'], True)
        f.validate_relay(value['relay'], True)
        f.validate_acquisitions(value, True)
        f.validate_diagnostics(value['diagnostic'], value['remaining_threads'], value['remaining_thread_intervals'],
                               value['remaining_thread_matrix'], value['remaining_timer_kinds'],
                               value['thread_observation_complete'], None, value['cleanup'], True)
        f.validate_owned_cleanup(value['owned_thread_cleanup'], value['cleanup'])
    except (f.ProbeError, KeyError, TypeError, AttributeError, OverflowError):
        raise ValueError('hdfs_result_contract_invalid') from None
    manifest = {row['path']: row for row in fixture_manifest()}
    require(value['rc_hash_sha256'] == manifest['nested/space name.bin']['sha256'], 'hdfs_fixture_digest_mismatch')
    for phase, name in (('empty', 'empty.bin'), ('small', 'nested/space name.bin'),
                        ('missing', 'empty.bin'), ('negative', 'empty.bin'),
                        ('before', 'payload.bin'), ('after', 'payload.bin')):
        row = manifest[name]
        require(value['acquisitions'][phase] == {'bytes': row['size'], 'sha256': row['sha256']}, 'hdfs_fixture_digest_mismatch')


def make_receipt(native, bindings, now):
    validate_native(native, bindings, now)
    return dict(schema_version=7, scope='rclone_backend_protocol_fixture', platform='linux', architecture='amd64',
                runtime=dict(version=bindings['rclone_version'], sha256=bindings['rclone_sha256']),
                harness_sha256=bindings['harness_sha256'], fixture_manifest_sha256=bindings['fixture_manifest_sha256'],
                started_utc=utc_text(native['started_utc']), finished_utc=utc_text(native['finished_utc']), success=True, cleanup_passed=True,
                backends=[dict(backend='hdfs', fixture_kind='independent_hdfs_container', fixture_mode=MODE,
                               capabilities={name: 'passed' for name in CAPABILITIES}, errors=[])], errors=[], native_evidence=native)


def validate_evidence(receipt, runtime, bindings, now, max_age_hours=24):
    exact(receipt, TOP_KEYS)
    require(type(runtime) is dict, 'hdfs_runtime_mismatch')
    require(type(receipt['schema_version']) is int and receipt['schema_version'] == 7
            and receipt['scope'] == 'rclone_backend_protocol_fixture' and receipt['platform'] == 'linux'
            and receipt['architecture'] == 'amd64', 'hdfs_receipt_scope_invalid')
    expected_runtime = dict(version=bindings['rclone_version'], sha256=bindings['rclone_sha256'])
    exact(receipt['runtime'], {'version', 'sha256'})
    require(receipt['runtime'] == expected_runtime and expected_runtime == {k: runtime.get(k) for k in expected_runtime}
            and runtime.get('platform', 'linux') == 'linux', 'hdfs_runtime_mismatch')
    require(receipt['harness_sha256'] == bindings['harness_sha256']
            and receipt['fixture_manifest_sha256'] == bindings['fixture_manifest_sha256'], 'hdfs_source_binding_mismatch')
    require(receipt['success'] is True and receipt['cleanup_passed'] is True and receipt['errors'] == [], 'hdfs_receipt_failed')
    rows = receipt['backends']
    require(type(rows) is list and len(rows) == 1, 'hdfs_backend_count_invalid')
    row = rows[0]; exact(row, {'backend', 'fixture_kind', 'fixture_mode', 'capabilities', 'errors'})
    require(row['backend'] == 'hdfs' and row['fixture_kind'] == 'independent_hdfs_container'
            and row['fixture_mode'] == MODE and row['errors'] == [], 'hdfs_backend_scope_invalid')
    exact(row['capabilities'], CAPABILITIES)
    require(all(type(v) is str and v == 'passed' for v in row['capabilities'].values()), 'hdfs_capability_incomplete')
    native = receipt['native_evidence']
    validate_native(native, bindings, now, max_age_hours)
    require(receipt['started_utc'] == utc_text(native['started_utc']) and receipt['finished_utc'] == utc_text(native['finished_utc']),
            'hdfs_receipt_time_mismatch')


def main(argv=None, *, now=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-report', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        bindings = compute_bindings()
        native = parse(file_bytes(args.native_report, 65536))
        now = datetime.now(timezone.utc) if now is None else now
        receipt = make_receipt(native, bindings, now)
        validate_evidence(receipt, receipt['runtime'], bindings, now)
        require(compute_bindings() == bindings, 'hdfs_source_changed')
        raw = canonical(receipt) + b'\n'
        require(len(raw) <= MAX_RECEIPT, 'hdfs_receipt_size_invalid')
        destination = Path(os.path.abspath(args.report))
        for parent in destination.parents:
            info = parent.lstat()
            require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
                    and not getattr(info, 'st_file_attributes', 0) & 0x400, 'hdfs_output_parent_invalid')
        with destination.open('xb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except (OSError, ValueError, RuntimeError, TypeError, KeyError, AttributeError, OverflowError):
        print('{"success":false,"error":"hdfs_protocol_evidence_rejected"}')
        return 1
    print('{"success":true,"backend":"hdfs","protocol_capabilities":6,"provider_accepted":false}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
