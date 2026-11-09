"""Admit benign hosted CLI regressions against the independently admitted binary."""
from __future__ import annotations
import hashlib,json
from audit_contract import ContractError,need,unique,nonfinite
import wrapper_contract as W
from remediation_contract import wrapper_target
PAYLOAD=b'benign dependency compatibility fixture 0123456789\n'*1024
EMPTY=hashlib.sha256(b'').hexdigest()
FIELDS={'schema_version','success','error','variant','target_before','target_after','target_unchanged','payload',
 'brotli_archive','zstd_object','context_binary','context_tests','http_requests','server_joined','controls','children',
 'duration_ms','vulnerability_audit_completed','provider_accepted'}
CHILD_FIELDS={'case','exit_code','timed_out','wait_delay_exceeded','stdout_overflow','stderr_overflow','stdout','stderr','duration_ms'}
CONTROLS=['http_directory_parse','brotli_archive_extract','zstd_object_roundtrip']
CASES=['http_directory','brotli_archive','zstd_write','zstd_read']

def stream_stamp(value,maximum):
 need(type(value) is dict and set(value)=={'bytes','sha256'} and type(value['bytes']) is int
  and 0<=value['bytes']<=maximum,'remediation_regression_stream')
 if value['bytes']==0:need(value['sha256']==EMPTY,'remediation_regression_stream')
 else:W.stamp(value)
 return value

def admit(raw,variant,upgraded,exit_code):
 need(type(raw) is bytes and 0<len(raw)<=65536,'remediation_regression_size')
 try:value=json.loads(raw,object_pairs_hook=unique,parse_constant=nonfinite)
 except (ValueError,UnicodeError,RecursionError):raise ContractError('remediation_regression_json') from None
 need(type(value) is dict and set(value)==FIELDS and type(value['schema_version']) is int and value['schema_version']==1
  and value['success'] is True and value['error']=='none' and variant in ('original','patched') and value['variant']==variant,
  'remediation_regression_shape')
 need(type(exit_code) is int and exit_code==0 and value['target_unchanged'] is True and value['server_joined'] is True
  and value['vulnerability_audit_completed'] is False and value['provider_accepted'] is False
  and type(value['duration_ms']) is int and 0<=value['duration_ms']<=85000,'remediation_regression_process')
 target=wrapper_target(upgraded)['file']
 need(W.stamp(value['target_before'])==W.stamp(value['target_after'])==target,'remediation_regression_target')
 need(W.stamp(value['payload'])==dict(bytes=len(PAYLOAD),sha256=hashlib.sha256(PAYLOAD).hexdigest()),'remediation_regression_payload')
 need(W.stamp(value['brotli_archive'])['bytes']<=131072 and W.stamp(value['zstd_object'])['bytes']<len(PAYLOAD),
  'remediation_regression_fixtures')
 need(type(value['http_requests']) is int and 1<=value['http_requests']<=16,'remediation_regression_http')
 controls=CONTROLS+(['upgraded_hdfs_context'] if variant=='patched' else [])
 cases=CASES+(['upgraded_hdfs_context'] if variant=='patched' else [])
 need(value['controls']==controls and type(value['context_tests']) is int,'remediation_regression_controls')
 if variant=='patched':
  need(value['context_tests']==11 and 1024*1024<=W.stamp(value['context_binary'])['bytes']<=128*1024*1024,
   'remediation_regression_context')
 else:need(value['context_tests']==0 and value['context_binary'] is None,'remediation_regression_context')
 children=value['children'];need(type(children) is list and len(children)==len(cases),'remediation_regression_children')
 expected_output={'http_directory':b'fixture.txt\n','brotli_archive':b'','zstd_write':b'','zstd_read':PAYLOAD}
 for child,case in zip(children,cases):
  need(type(child) is dict and set(child)==CHILD_FIELDS and child['case']==case and type(child['exit_code']) is int
   and child['exit_code']==0 and type(child['duration_ms']) is int and 0<=child['duration_ms']<=13000
   and all(child[k] is False for k in ('timed_out','wait_delay_exceeded','stdout_overflow','stderr_overflow')),
   'remediation_regression_child')
  stdout=stream_stamp(child['stdout'],131072);stderr=stream_stamp(child['stderr'],16384)
  need(stderr==dict(bytes=0,sha256=EMPTY),'remediation_regression_stderr')
  if case in expected_output:
   expected=expected_output[case]
   need(stdout==dict(bytes=len(expected),sha256=hashlib.sha256(expected).hexdigest()),'remediation_regression_output')
  else:need(0<stdout['bytes']<=16384,'remediation_regression_output')
 return dict(value,scope='contained_benign_cli_regressions',native_compatibility_controls_verified=True,
  malformed_input_tested=False,exploitability_verified=False,provider_acceptance_verified=False)
