import unittest
from audit_contract import ContractError
import audit_build as AB
import remediation_build as M

class RemediationBuild(unittest.TestCase):
 def setUp(self):
  self.original=AB.GO_ENV+' /opt/go/bin/go build '+AB.BUILD_FLAGS+' -modfile=/opt/input/original/go.mod -ldflags "-X github.com/rclone/rclone/fs.Version=v1.75.2-kerberos-original" -o /opt/probes/rclone-original .'
  self.patched=AB.GO_ENV+' /opt/go/bin/go build '+AB.BUILD_FLAGS+' -modfile=/opt/input/patched-rclone.mod -ldflags "-X github.com/rclone/rclone/fs.Version=v1.75.2-hdfs-context-patched" -o /opt/probes/rclone-patched .'
  self.input={'Dockerfile':b'FROM pinned\n','build.sh':('\n'.join(['#!/bin/sh',self.original,'cp frozen-rclone-patch target',self.patched,AB.PERMISSIONS])+'\n').encode(),
   'driver.sh':('#!/bin/sh\nset -eu\n'+M.IDENTITY+'\n').encode(),'patched-rclone.mod':b'original','patched-rclone.sum':b'sums'}
  self.files=AB.extend_build(self.input)
 def test_original_upgrade_precedes_source_mutation(self):
  lines=M.extend_build(self.files,'original')['build.sh'].decode().splitlines()
  i=next(i for i,l in enumerate(lines) if l.endswith(' -o /opt/probes/rclone-upgraded .'))
  self.assertTrue(lines[i-1].endswith(' -o /opt/probes/rclone-stripped .'))
  self.assertEqual(lines[i+2],'cp frozen-rclone-patch target')
 def test_patched_upgrade_follows_source_mutation(self):
  lines=M.extend_build(self.files,'patched')['build.sh'].decode().splitlines()
  i=lines.index(self.patched)
  self.assertTrue(lines[i+1].endswith(' -o /opt/probes/rclone-upgraded .'))
 def test_baseline_commands_are_preserved(self):
  for variant in ('original','patched'):
   lines=M.extend_build(self.files,variant)['build.sh'].decode().splitlines()
   self.assertIn(self.original,lines);self.assertIn(self.patched,lines)
   stripped=[l for l in self.files['build.sh'].decode().splitlines() if ' -o /opt/probes/rclone-stripped .' in l]
   self.assertTrue(set(stripped)<=set(lines))
 def test_resolver_is_offline_readonly_and_uses_overlay(self):
  lines=M.extend_build(self.files,'original')['build.sh'].decode().splitlines()
  resolver=next(l for l in lines if ' go list ' in l or '/go list ' in l)
  self.assertTrue(resolver.startswith(M.ENV));self.assertIn('GOPROXY=off GOSUMDB=off',resolver)
  self.assertIn('-m -json -mod=readonly -modfile=/opt/input/upgraded-rclone.mod all',resolver)
 def test_upgrade_build_uses_closed_variant_version(self):
  for variant in ('original','patched'):
   line=next(l for l in M.extend_build(self.files,variant)['build.sh'].decode().splitlines() if l.endswith(' -o /opt/probes/rclone-upgraded .'))
   self.assertTrue(line.startswith(M.ENV));self.assertIn(AB.BUILD_FLAGS,line);self.assertIn(M.MOD,line)
   self.assertIn('v1.75.2-advisory-upgraded-'+variant,line)
 def test_identity_reports_follow_foundation_success(self):
  driver=M.extend_build(self.files,'original')['driver.sh'].decode().splitlines()
  self.assertEqual(driver[-2],M.IDENTITY.removeprefix('exec '))
  self.assertEqual(driver[-1],'exec /usr/bin/timeout --signal=TERM --kill-after=2s 15s /opt/probes/audit-driver identity')
  self.assertIn('set -eu',driver)
 def test_native_reporter_sources_and_read_permissions(self):
  lines=M.extend_build(self.files,'original')['build.sh'].decode().splitlines()
  self.assertTrue(any(l.endswith('/opt/input/audit_driver.go /opt/input/remediation_driver.go') for l in lines))
  self.assertIn('chmod 0444 /opt/input/upgraded-rclone.mod /opt/input/upgraded-rclone.sum /opt/input/remediation-variant.txt',lines)
 def test_other_files_and_input_unchanged(self):
  before=dict(self.files);out=M.extend_build(self.files,'original')
  self.assertEqual(before,self.files)
  for name in ('Dockerfile','patched-rclone.mod','patched-rclone.sum'):self.assertEqual(out[name],before[name])
 def test_invalid_variant(self):
  for v in ('',None,True,'original;command'):
   with self.assertRaises(ContractError):M.extend_build(self.files,v)
 def test_missing_and_duplicate_anchors(self):
  for anchor in (self.original,self.patched,AB.PERMISSIONS):
   for replacement in ('',anchor+'\n'+anchor):
    files=dict(self.files);files['build.sh']=files['build.sh'].replace(anchor.encode(),replacement.encode())
    with self.assertRaises(ContractError):M.extend_build(files,'original')
 def test_reordered_baseline_builds(self):
  files=dict(self.files);lines=files['build.sh'].decode().splitlines();lines.remove(self.patched);lines.insert(0,self.patched)
  files['build.sh']='\n'.join(lines).encode()
  with self.assertRaises(ContractError):M.extend_build(files,'patched')
 def test_missing_or_trailed_identity_anchor(self):
  for raw in (b'changed',self.files['driver.sh']+b'echo unbound\n'):
   files=dict(self.files);files['driver.sh']=raw
   with self.assertRaises(ContractError):M.extend_build(files,'original')
 def test_extra_input_file_rejected(self):
  files=dict(self.files);files['unbound']=b'input'
  with self.assertRaises(ContractError):M.extend_build(files,'original')
