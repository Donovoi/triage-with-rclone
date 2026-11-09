"""Deterministic offline upgrades; foundation build commands retain their order."""
from __future__ import annotations
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
  ENV+' /opt/go/bin/go list -m -json -mod=readonly '+MOD+' all > /opt/probes/upgraded-module-graph.json']
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
 result=dict(files);result['build.sh']=('\n'.join(lines)+'\n').encode();result['driver.sh']=driver.encode()
 return result
