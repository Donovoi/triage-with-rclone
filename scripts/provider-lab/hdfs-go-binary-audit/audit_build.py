"""Deterministic offline build additions for the isolated Go binary audit."""
from __future__ import annotations
import re
from audit_contract import need

ORIGINAL_END=' -o /opt/probes/rclone-original .'
PERMISSIONS='chmod -R a=rX /opt/probes'
GO_ENV='env -i HOME=/opt/home PATH=/opt/go/bin:/usr/bin:/bin GOROOT=/opt/go GOMODCACHE=/opt/input/audit-tool/module-cache GOCACHE=/opt/cache GOTMPDIR=/opt/tmp GOENV=off GOTOOLCHAIN=local GOWORK=off GOTELEMETRY=off GOPROXY=off GOSUMDB=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOMAXPROCS=2 GOMEMLIMIT=1GiB'
BUILD_FLAGS='-mod=readonly -trimpath -buildvcs=false -p 2'

def extend_build(files):
    need(type(files) is dict and set(files)=={'Dockerfile','build.sh','driver.sh','patched-rclone.mod','patched-rclone.sum'},'build_files')
    lines=files['build.sh'].decode('utf-8').splitlines()
    original=[i for i,line in enumerate(lines) if line.endswith(ORIGINAL_END)]
    need(len(original)==1 and lines.count(PERMISSIONS)==1,'build_anchor')
    index=original[0];line=lines[index]
    flag='-ldflags "-X github.com/rclone/rclone/fs.Version=v1.75.2-kerberos-original"'
    need(line.count(flag)==1,'build_flags')
    stripped=line.replace(flag,'-ldflags "-s -w -X github.com/rclone/rclone/fs.Version=v1.75.2-kerberos-original"')
    stripped=stripped[:-len(ORIGINAL_END)]+' -o /opt/probes/rclone-stripped .'
    lines.insert(index+1,stripped)
    additions=['cd /opt/input/audit-tool/source',
        GO_ENV+' /opt/go/bin/go build '+BUILD_FLAGS+' -o /opt/probes/govulncheck ./cmd/govulncheck',
        GO_ENV+' /opt/go/bin/go build '+BUILD_FLAGS+' -o /opt/probes/audit-driver /opt/input/audit_driver.go',
        'chmod -R a=rX /opt/input/advisories /opt/input/control-db /opt/input/control-blobs',
        'chmod 0555 /opt/input/audit-tool',
        'chmod 0444 /opt/input/audit-tool/tool-assets-lock.json']
    position=lines.index(PERMISSIONS);lines[position:position]=additions
    result=dict(files);result['build.sh']=('\n'.join(lines)+'\n').encode()
    return result

def diagnostics(R,raw):
    result=R.build_diagnostics(raw)
    rows=[]
    for match in re.finditer(r'(audit_driver[.]go):([0-9]{1,5}):[^\r\n]*',raw.decode('utf-8','replace')):
        value=dict(file=match[1],line=int(match[2]))
        need(1<=value['line']<=10000 and len(rows)<32,'build_diagnostics')
        if value not in rows:rows.append(value)
    result['audit_source_errors']=rows
    result['tool_module_resolution_failed']=b'golang.org/x/vuln' in raw and result['module_resolution_failed']
    return result
