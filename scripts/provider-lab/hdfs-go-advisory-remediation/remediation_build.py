"""Deterministic offline upgrades; foundation build commands retain their order."""
from __future__ import annotations
import re
from audit_contract import need
import audit_build as AB

MOD='-modfile=/opt/input/upgraded-rclone.mod'
ENV=AB.GO_ENV.replace('/opt/input/audit-tool/module-cache','/opt/input/module-cache')
PERMISSIONS='chmod -R a=rX /opt/probes'
IDENTITY='exec /usr/bin/timeout --signal=TERM --kill-after=2s 10s /opt/probes/inspect-context-build'

def index_one(lines,ending):
 matches=[i for i,line in enumerate(lines) if line.endswith(ending)]
 need(len(matches)==1,'remediation_build_anchor')
 return matches[0]

def extend_build(files,variant):
 need(variant in ('original','patched'),'remediation_build_variant')
 need(type(files) is dict and set(files)=={'Dockerfile','build.sh','driver.sh','patched-rclone.mod','patched-rclone.sum'},
  'remediation_build_files')
 lines=files['build.sh'].decode('utf-8').splitlines()
 original=index_one(lines,' -o /opt/probes/rclone-original .')
 stripped=index_one(lines,' -o /opt/probes/rclone-stripped .')
 patched=index_one(lines,' -o /opt/probes/rclone-patched .')
 need(original+1==stripped and stripped<patched and lines.count(PERMISSIONS)==1,'remediation_build_order')
 anchor=stripped if variant=='original' else patched
 additions=[ENV+' /opt/go/bin/go build '+AB.BUILD_FLAGS+' '+MOD+
  ' -ldflags "-X github.com/rclone/rclone/fs.Version=v1.75.2-advisory-upgraded-'+variant+'" -o /opt/probes/rclone-upgraded .',
  ENV+' /opt/go/bin/go build '+AB.BUILD_FLAGS+' '+MOD+' -o /opt/probes/resolver-diagnostics /opt/input/resolver_diagnostics.go',
  ENV+' /opt/go/bin/go list -m -e -json -mod=readonly '+MOD+' all > /opt/probes/upgraded-module-graph.json',
  ENV+' /usr/bin/timeout --signal=TERM --kill-after=2s 10s /opt/probes/resolver-diagnostics']
 lines[anchor+1:anchor+1]=additions
 driver_index=index_one(lines,' -o /opt/probes/audit-driver /opt/input/audit_driver.go')
 lines[driver_index]+=' /opt/input/remediation_driver.go'
 position=lines.index(PERMISSIONS)
 regressions=['cd /opt/input/original',ENV+' /opt/go/bin/go build '+AB.BUILD_FLAGS+' '+MOD+
  ' -o /opt/probes/remediation-regression /opt/input/remediation_regression.go']
 if variant=='patched':
  regressions+=[ENV+' /opt/go/bin/go test -c '+AB.BUILD_FLAGS+' '+MOD+
   ' -o /opt/probes/upgraded-context-tests github.com/colinmarc/hdfs/v2/internal/rpc']
 lines[position:position]=regressions+['chmod 0444 /opt/input/upgraded-rclone.mod /opt/input/upgraded-rclone.sum /opt/input/remediation-variant.txt']
 driver=files['driver.sh'].decode('utf-8')
 need(driver.count(IDENTITY)==1 and driver.endswith(IDENTITY+'\n'),'remediation_build_driver')
 driver=driver[:-len(IDENTITY+'\n')]+IDENTITY.removeprefix('exec ')+'\n'+  'exec /usr/bin/timeout --signal=TERM --kill-after=2s 15s /opt/probes/audit-driver identity\n'
 marked=[]
 for line in lines:
  phase=None
  if ' /opt/go/bin/go ' in line:
   if ' /opt/go/bin/go list ' in line:phase='upgraded_graph'
   else:
    for name,label in BUILD_TARGETS.items():
     if ' -o /opt/probes/'+name+' ' in line:phase=label;break
   need(phase is not None,'remediation_build_phase')
   marked.append("printf '%s\\n' 'GO_REMEDIATION_BUILD_PHASE="+phase+"'")
  marked.append(line)
 result=dict(files);result['build.sh']=('\n'.join(marked)+'\n').encode();result['driver.sh']=driver.encode()
 return result

BUILD_TARGETS={'rclone-original':'baseline_original','rclone-stripped':'baseline_stripped','rclone-patched':'baseline_patched',
 'rclone-upgraded':'upgraded_binary','context-tests':'baseline_context_tests','inspect-context-build':'foundation_reporter',
 'govulncheck':'analyzer','audit-driver':'audit_wrapper','remediation-regression':'benign_regression',
 'upgraded-context-tests':'upgraded_context_tests','resolver-diagnostics':'resolver_diagnostics'}
PHASES=set(BUILD_TARGETS.values())|{'upgraded_graph'}
PHASE=re.compile(rb"^(?:#[0-9]+ +[0-9.]+ +)?GO_REMEDIATION_BUILD_PHASE=("+
 b'|'.join(x.encode('ascii') for x in sorted(PHASES))+rb")\r?$",re.MULTILINE)
COORD=re.compile(rb'([A-Za-z0-9][A-Za-z0-9./_~!+-]*)@(v[0-9][A-Za-z0-9.+-]*)')
REQUIRE=re.compile(rb'^\s*(?:require\s+)?([A-Za-z0-9][A-Za-z0-9./_~!+-]*)[ \t]+(v[0-9][A-Za-z0-9.+-]*)(?:[ \t]*(?://[^\r\n]*)?)\r?$',re.MULTILINE)

def diagnostic_coordinates(inputs,known):
 """Only coordinates present in already verified public module inputs may escape."""
 need(type(inputs) is list and len(inputs)<=512 and all(type(x) is bytes and len(x)<=2*1024*1024 for x in inputs)
  and sum(map(len,inputs))<=16*1024*1024,'remediation_diagnostic_inputs')
 result=set(known)
 for raw in inputs:
  for match in REQUIRE.finditer(raw):result.add((match[1].decode('ascii'),match[2].decode('ascii')))
 need(len(result)<=20000,'remediation_diagnostic_inputs')
 return result

def diagnostics(R,raw,allowed):
 need(type(raw) is bytes and len(raw)<=8*1024*1024 and type(allowed) is set,'remediation_diagnostic_inputs')
 result=AB.diagnostics(R,raw);phases=PHASE.findall(raw)
 result['remediation_phase']=phases[-1].decode('ascii') if phases else None
 found=set();unbound=False
 for line in raw.splitlines():
  kind='lookup_disabled' if b'module lookup disabled by GOPROXY=off' in line else 'sum_missing' if b'missing go.sum entry' in line else None
  if kind is None:continue
  for match in COORD.finditer(line):
   coordinate=(match[1].decode('ascii'),match[2].decode('ascii'))
   if coordinate in allowed:found.add((*coordinate,kind))
   else:unbound=True
 need(len(found)<=32,'remediation_diagnostic_limit')
 for match in re.finditer(rb'^(?:#[0-9]+ +[0-9.]+ +)?GO_REMEDIATION_MODULE_ERROR=([^\r\n]+)\r?$',raw,re.MULTILINE):
  payload=match[1]
  if payload==b'unbound':unbound=True;continue
  coordinate,sep,kind=payload.rpartition(b':')
  match_coord=COORD.fullmatch(coordinate)
  need(sep and match_coord is not None and kind in (b'lookup_disabled',b'sum_missing',b'unclassified'),'remediation_diagnostic_marker')
  pair=(match_coord[1].decode('ascii'),match_coord[2].decode('ascii'))
  if pair in allowed:found.add((*pair,kind.decode('ascii')))
  else:unbound=True
 need(len(found)<=32,'remediation_diagnostic_limit')
 result['module_errors']=[dict(module=m,version=v,kind=k) for m,v,k in sorted(found)]
 statuses=re.findall(rb'^(?:#[0-9]+ +[0-9.]+ +)?GO_REMEDIATION_GRAPH_STATUS=(errors|complete|invalid)\r?$',raw,re.MULTILINE)
 result['resolver_graph_status']=statuses[-1].decode('ascii') if statuses else None
 result['unbound_module_error_present']=unbound
 errors=set()
 for match in re.finditer(rb'(remediation_(?:driver|regression)[.]go|resolver_diagnostics[.]go):([0-9]{1,5}):[^\r\n]*',raw):
  line=int(match[2]);need(1<=line<=10000,'remediation_diagnostic_limit');errors.add((match[1].decode('ascii'),line))
 need(len(errors)<=32,'remediation_diagnostic_limit')
 result['remediation_source_errors']=[dict(file=f,line=n) for f,n in sorted(errors)]
 return result
