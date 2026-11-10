import unittest
from audit_contract import ContractError
from audit_build import extend_build,GO_ENV,BUILD_FLAGS,PERMISSIONS
class AuditBuild(unittest.TestCase):
    def setUp(self):
        original='env -i /opt/go/bin/go build -mod=readonly -modfile=/opt/input/original/go.mod -trimpath -buildvcs=false -p 2 -ldflags "-X github.com/rclone/rclone/fs.Version=v1.75.2-kerberos-original" -o /opt/probes/rclone-original .'
        self.original=original
        self.files={'Dockerfile':b'FROM pinned\n','build.sh':('\n'.join(['#!/bin/sh',original,'cp rclone-patch target',
            'build patched',PERMISSIONS,'chmod 0555 /opt/probes/* /opt/input /opt/input/driver.sh'])+'\n').encode(),
            'driver.sh':b'identity driver','patched-rclone.mod':b'module original','patched-rclone.sum':b'h1'}
    def test_stripped_original_built_before_rclone_overlay(self):
        lines=extend_build(self.files)['build.sh'].decode().splitlines()
        i=lines.index(self.original)
        self.assertIn('-s -w -X ',lines[i+1]);self.assertTrue(lines[i+1].endswith('-o /opt/probes/rclone-stripped .'))
        self.assertEqual(lines[i+2],'cp rclone-patch target')
    def test_tool_has_separate_offline_module_cache(self):
        build=extend_build(self.files)['build.sh'].decode()
        line=next(x for x in build.splitlines() if '-o /opt/probes/govulncheck' in x)
        self.assertTrue(line.startswith(GO_ENV));self.assertIn(BUILD_FLAGS,line)
        self.assertIn('GOPROXY=off GOSUMDB=off',line)
        self.assertIn('GOTOOLCHAIN=local GOWORK=off GOTELEMETRY=off',line)
    def test_wrapper_built_from_pinned_context_source(self):
        build=extend_build(self.files)['build.sh'].decode()
        self.assertIn(' -o /opt/probes/audit-driver /opt/input/audit_driver.go',build)
    def test_runtime_reads_have_explicit_permissions(self):
        lines=extend_build(self.files)['build.sh'].decode().splitlines()
        self.assertIn('chmod -R a=rX /opt/input/advisories /opt/input/control-db /opt/input/control-blobs',lines)
        self.assertIn('chmod 0444 /opt/input/audit-tool/tool-assets-lock.json',lines)
        self.assertLess(lines.index('chmod 0555 /opt/input/audit-tool'),lines.index(PERMISSIONS))
    def test_foundation_other_files_preserved(self):
        out=extend_build(self.files)
        for key in self.files:
            if key!='build.sh':self.assertEqual(out[key],self.files[key])
        self.assertNotIn(b'rclone-stripped',self.files['build.sh'])
    def test_missing_or_duplicate_original_anchor_fails(self):
        initial=self.files['build.sh']
        for raw in (initial.replace(self.original.encode(),b'changed'),initial+self.original.encode()+b'\n'):
            self.files['build.sh']=raw
            with self.assertRaisesRegex(ContractError,'build_anchor'):extend_build(self.files)
    def test_changed_original_flags_fail(self):
        self.files['build.sh']=self.files['build.sh'].replace(b'kerberos-original',b'unknown-original')
        with self.assertRaisesRegex(ContractError,'build_flags'):extend_build(self.files)
    def test_missing_permission_anchor_fails(self):
        self.files['build.sh']=self.files['build.sh'].replace(PERMISSIONS.encode(),b'')
        with self.assertRaisesRegex(ContractError,'build_anchor'):extend_build(self.files)
