"""Independent closed supplement validation. Never promotes original cleanup/trace."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import validate_result as primary

PREFIX = b'runtime_cleanup_resource_use='
TEST = 'ui::flows::download::tests::external_config_listing_selection_acquisition_preserves_source_and_checkpoint'
TRACE_CLOSED = ('session_started', 'stop_succeeded', 'session_absent', 'consumer_completed', 'consumer_closed', 'worker_joined')
KEYS = frozenset(('schema','scope','phase','original_os_code','original_result_preserved','causal_owner','hard_deadline','runtime_sha256','availability','reason','trace_closed','prior_probe_closed','pre_identity','pre_closed','post_identity','post_closed','start_status','register_status','list_status','end_status','caller_listed','counts'))
PRE_REASONS = frozenset(('trace_unclosed','prior_probe_unclosed','primary_unwritten','registration_unavailable'))

def digest(value, width=64):
    if type(value) is not str or re.fullmatch('[a-f0-9]{'+str(width)+'}',value) is None:
        raise ValueError('binding')
    return value

def select(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= 4*1024*1024:
        raise ValueError('log_bound')
    # A single selected test/primary/removal is required; never select first.
    lines = raw.splitlines()
    found = [(index,line[len(PREFIX):]) for index,line in enumerate(lines) if line.startswith(PREFIX)]
    originals = [index for index,line in enumerate(lines) if line.startswith(b'runtime_cleanup_trace=')]
    if len(found) != 1 or len(originals) != 1 or originals[0] >= found[0][0]:
        raise ValueError('record_order_count')
    return found[0][1]

def validate(raw, trace):
    if type(raw) is not bytes or not 0 < len(raw)+len(PREFIX)+1 <= 1024:
        raise ValueError('record_bound')
    value = json.loads(raw.decode('utf-8'),object_pairs_hook=primary.unique_pairs)
    if type(value) is not dict or value.keys() != KEYS:
        raise ValueError('shape')
    exact = {'schema':1,'scope':'post_failure_resource_use','phase':'after_trace_before_residue',
             'original_os_code':32,'original_result_preserved':True,'causal_owner':False,'hard_deadline':False}
    for key, expected in exact.items():
        if type(value[key]) is not type(expected) or value[key] != expected:
            raise ValueError('scope')
    if trace['original_ok'] is not False or trace['os_code'] != 32:
        raise ValueError('original_failure')
    if digest(value['runtime_sha256']) != trace['runtime_sha256']:
        raise ValueError('runtime_binding')
    for key in ('trace_closed','prior_probe_closed'):
        if type(value[key]) is not bool: raise ValueError('boolean')
    if value['trace_closed'] != all(trace[key] for key in TRACE_CLOSED):
        raise ValueError('trace_closure')
    if not value['prior_probe_closed'] and trace['target_identity_verified']:
        raise ValueError('prior_probe')
    for key in ('pre_identity','pre_closed','post_identity','post_closed','caller_listed'):
        if value[key] is not None and type(value[key]) is not bool: raise ValueError('nullable_boolean')
    for key in ('start_status','register_status','list_status','end_status'):
        if value[key] is not None and not primary.uint(value[key],0xffffffff): raise ValueError('api_status')
    if type(value['reason']) is not str or type(value['availability']) is not str:
        raise ValueError('enum')
    reason = value['reason']
    stages = ('pre_identity','pre_closed','post_identity','post_closed','start_status','register_status','list_status','end_status')
    if reason in PRE_REASONS:
        expected = ('trace_unclosed' if not value['trace_closed'] else
                    'prior_probe_unclosed' if not value['prior_probe_closed'] else reason)
        if (reason != expected or any(value[k] is not None for k in stages)
                or value['trace_closed'] and value['prior_probe_closed'] and reason not in {'primary_unwritten','registration_unavailable'}):
            raise ValueError('pre_gate')
    else:
        if not value['trace_closed'] or not value['prior_probe_closed'] or any(value[k] is None for k in ('pre_identity','pre_closed')):
            raise ValueError('query_before_gate')
        if not value['pre_closed'] or not value['pre_identity']:
            expected = 'pre_close' if not value['pre_closed'] else 'pre_identity'
            if any(value[k] is not None for k in stages[2:]): raise ValueError('pre_probe_order')
        elif value['start_status'] is None:
            raise ValueError('missing_start')
        elif value['start_status'] != 0:
            expected = 'start'
            if any(value[k] is not None for k in ('register_status','list_status','end_status','post_identity','post_closed')): raise ValueError('failed_start_order')
        else:
            if any(value[k] is None for k in ('register_status','end_status','post_identity','post_closed')):
                raise ValueError('end_obligation')
            if value['register_status'] != 0:
                if value['list_status'] is not None: raise ValueError('failed_register_order')
                expected = 'register'
            elif value['list_status'] is None:
                raise ValueError('missing_list')
            elif value['list_status'] != 0:
                expected = 'capacity' if value['list_status'] == 234 else 'list'
            else:
                expected = 'shape' if reason == 'shape' else 'none'
            if not value['post_identity']: expected = 'post_identity'
            if not value['post_closed']: expected = 'post_close'
            if value['end_status'] != 0: expected = 'end'
        if reason != expected: raise ValueError('reason_precedence')
    if reason == 'none':
        counts = value['counts']
        if value['availability'] != 'available' or type(value['caller_listed']) is not bool or type(counts) is not dict or counts.keys() != {'total','other_processes','types'}:
            raise ValueError('counts_shape')
        if (not primary.uint(counts['total'],64) or not primary.uint(counts['other_processes'],64)
                or counts['other_processes'] != counts['total']-int(value['caller_listed'])
                or type(counts['types']) is not list or len(counts['types']) != 7
                or any(not primary.uint(v,64) for v in counts['types']) or sum(counts['types']) != counts['total']):
            raise ValueError('counts')
    elif value['availability'] != 'unavailable' or value['caller_listed'] is not None or value['counts'] is not None:
        raise ValueError('unavailable_counts')
    return value

def execution(raw, test_exit, harness, cargo_json, dynamic_providers):
    # Deliberately separate from historical menu/CLI selectors; no reassignment.
    if type(raw) is not bytes or not 0 < len(raw) <= 4*1024*1024: raise ValueError('stdout_bound')
    if type(test_exit) is not int or test_exit != 101 or dynamic_providers != '1': raise ValueError('failed_unit_required')
    lines = raw.decode('utf-8').splitlines()
    running = [line for line in lines if line.startswith('running ')]
    tests = [line for line in lines if line.startswith('test ') and not line.startswith('test result:')]
    results = [line for line in lines if line.startswith('test result:')]
    if (running != ['running 1 test'] or tests != [f'test {TEST} ... FAILED'] or len(results) != 1
            or re.fullmatch(r'test result: FAILED\. 0 passed; 1 failed; 0 ignored; 0 measured; [0-9]{1,6} filtered out; finished in [0-9]+(?:\.[0-9]+)?s',results[0]) is None):
        raise ValueError('exact_unit')
    return {'test':TEST,'test_exit':101,'selected_tests':1,'artifact_kind':'library_test',
            'target':'aarch64-pc-windows-msvc','profile':'release','feature':'runtime-cleanup-trace',
            'dynamic_providers':'1','test_harness_sha256':digest(harness),'cargo_json_sha256':digest(cargo_json),
            'private_stdout_sha256':hashlib.sha256(raw).hexdigest()}

def replay(log, stdout, test_exit, runtime, harness, cargo_json, commit, source_tree, application_source, test_source, dynamic_providers):
    original = primary.select(log)
    trace = primary.validate(original,test_exit,runtime)
    observed = validate(select(log),trace)
    bound = execution(stdout,test_exit,harness,cargo_json,dynamic_providers)
    return {'schema':1,'result':'resource_use_observed' if observed['availability']=='available' else 'resource_use_unavailable',
            'original_trace':trace,'original_trace_sha256':hashlib.sha256(original).hexdigest(),
            'resource_use':observed,'execution':bound,'commit':digest(commit,40),'source_tree':digest(source_tree,40),
            'application_source_sha256':digest(application_source),'test_source_sha256':digest(test_source),
            'original_cleanup_passed':False,'causal_owner_proved':False,'provider_credit':False}

def read_bounded(path):
    with Path(path).open('rb') as stream:
        data = stream.read(4*1024*1024+1)
    if not 0 < len(data) <= 4*1024*1024: raise ValueError('input_bound')
    return data

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('log','test-stdout','runtime-sha256','test-harness-sha256','cargo-json-sha256','commit','source-tree','application-source-sha256','test-source-sha256','dynamic-providers'):
        parser.add_argument('--'+name,required=True)
    parser.add_argument('--test-exit',required=True,type=int)
    args = parser.parse_args()
    try:
        log = read_bounded(args.log)
        # Preserve a valid original observation even if the supplement is absent,
        # malformed or unavailable. Neither this projection nor the CLI can pass.
        original = primary.validate(primary.select(log),args.test_exit,args.runtime_sha256)
        if not emit({'schema':1,'result':'original_trace_preserved','original_trace':original,'provider_credit':False}):
            return 1
        value = replay(log,read_bounded(args.test_stdout),args.test_exit,args.runtime_sha256,args.test_harness_sha256,args.cargo_json_sha256,args.commit,args.source_tree,args.application_source_sha256,args.test_source_sha256,args.dynamic_providers)
        emit(value)
    except (ValueError,TypeError,KeyError,OSError,UnicodeError):
        emit({'schema':1,'result':'invalid_resource_use','provider_credit':False})
    # A valid resource-use observation is still an original failed cleanup/test.
    return 1

def emit(value):
    try:
        text = json.dumps(value,sort_keys=True,separators=(',',':'))
        if len(text.encode('ascii'))+1 > 8192: return False
        print(text)
        return True
    except Exception:
        return False

if __name__ == '__main__':
    raise SystemExit(main())
