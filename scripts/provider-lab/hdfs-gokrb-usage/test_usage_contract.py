import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

import go_bundle as B
import usage_container as U

class Assets(unittest.TestCase):
    def setUp(self):
        self.raw=(U.HERE/'assets-lock.json').read_bytes();self.lock=B.load_lock(self.raw)
    def test_published_graph_and_toolchain_are_pinned(self):
        self.assertEqual(len(self.lock['assets']),87)
        self.assertEqual(sum(r['kind']=='zip' for r in self.lock['assets']),16)
    def test_changed_lock_rejected(self):
        with self.assertRaises(ValueError):B.load_lock(self.raw+b' ')
    def test_duplicate_json_key_rejected(self):
        with self.assertRaises(ValueError):B.parse(b'{"a":1,"a":2}')
    def test_nonfinite_json_rejected(self):
        with self.assertRaises(ValueError):B.parse(b'{"a":NaN}')
    def test_wrong_asset_digest_and_length_rejected(self):
        r={'kind':'zip','bytes':1,'sha256':hashlib.sha256(b'x').hexdigest()}
        for raw in (b'',b'xx',b'y'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):B.verify_asset(raw,r)
    def test_zip_path_and_mode_admission(self):
        for name,mode in [('m@v1.0.0/../evil',0),('/m@v1.0.0/file',0),
                          ('m@v1.0.0/link',0o120777),('m@v1.0.0/file',0o104755),
                          ('m@v1.0.0/a\\b',0),('m@v1.0.0/a\nb',0)]:
            with self.subTest(name=name,mode=mode):
                stream=io.BytesIO()
                with zipfile.ZipFile(stream,'w') as z:
                    item=zipfile.ZipInfo(name);item.external_attr=mode<<16;z.writestr(item,b'x')
                raw=stream.getvalue();r=dict(kind='zip',module='m',version='v1.0.0',bytes=len(raw),sha256=B.sha(raw),h1='unused')
                with self.assertRaises(ValueError):B.module_files(raw,r)
    def test_hash1_checked_and_valid_module_decoded(self):
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w') as z:z.writestr('m@v1.0.0/a.go',b'package m\n')
        raw=stream.getvalue();digest=hashlib.sha256((B.sha(b'package m\n')+'  m@v1.0.0/a.go\n').encode()).digest()
        r=dict(kind='zip',module='m',version='v1.0.0',bytes=len(raw),sha256=B.sha(raw),
               h1='h1:'+B.base64.b64encode(digest).decode())
        self.assertEqual(B.module_files(raw,r),{'a.go':b'package m\n'})
        r['h1']='wrong'
        with self.assertRaises(ValueError):B.module_files(raw,r)

class Admission(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.C=U.load_support();cls.B=U.load_bundle(cls.C)
        cls.lock=B.load_lock((U.HERE/'assets-lock.json').read_bytes())
    def native(self):
        dep=next(r for r in self.lock['assets'] if r['kind']=='zip' and r['module']=='github.com/jcmturner/gofork')
        return [dict(schema_version=1,variant=v,success=True,error='none',go_version='go1.26.10',
            dependencies=[dict(path=dep['module'],version=dep['version'],sum=dep['h1'])],
            cases=[dict(case=n,usage=U.EXPECTED[j][i],checks=15 if i<3 else 8,negative_controls=4 if i<3 else 3,
                        required_usage=U.EXPECTED[j][i]==(7 if i<3 else 11)) for i,n in enumerate(U.CASES)],
            rclone_verified=False,renewal_verified=False,provider_accepted=False) for j,v in enumerate(U.VARIANTS)]
    def validate(self,rows,code=0):
        return U.validate_native(self.C,b'\n'.join(U.canonical(r) for r in rows)+b'\n',code,self.lock)
    def test_all_three_variants_required(self):
        self.assertEqual(self.validate(self.native())['binding_checks'],183)
        for rows in (self.native()[:2],self.native()+self.native()[:1],list(reversed(self.native()))):
            with self.assertRaises(U.ProbeError):self.validate(rows)
    def test_false_claims_required(self):
        for key in ('rclone_verified','renewal_verified','provider_accepted'):
            rows=self.native();rows[0][key]=True
            with self.subTest(key=key),self.assertRaises(U.ProbeError):self.validate(rows)
    def test_changed_usage_or_missing_controls_rejected(self):
        for variant in range(3):
            for case in range(5):
                for key,value in [('usage',9),('checks',0),('negative_controls',0),('required_usage',None)]:
                    rows=self.native();rows[variant]['cases'][case][key]=value
                    with self.subTest(variant=variant,case=case,key=key),self.assertRaises(U.ProbeError):self.validate(rows)
    def test_mismatched_dependency_or_replacement_rejected(self):
        for key,value in [('sum','h1:wrong'),('version','v0.0.0'),('path','unapproved')]:
            rows=self.native();rows[1]['dependencies'][0][key]=value
            with self.subTest(key=key),self.assertRaises(U.ProbeError):self.validate(rows)
        rows=self.native();rows[0]['dependencies'][0]['replace']='other'
        with self.assertRaises(U.ProbeError):self.validate(rows)
    def test_numeric_booleans_and_unknown_fields_rejected(self):
        for target,key,value in [('root','schema_version',True),('root','success',1),('root','extra',1),
                                  ('case','usage',True),('case','checks',True),('case','negative_controls',True)]:
            rows=self.native();obj=rows[0] if target=='root' else rows[0]['cases'][0];obj[key]=value
            with self.subTest(key=key),self.assertRaises(U.ProbeError):self.validate(rows)
    def test_nonzero_and_extra_output_rejected(self):
        with self.assertRaises(U.ProbeError):self.validate(self.native(),1)
        with self.assertRaises(U.ProbeError):U.validate_native(self.C,b'x'*32769,0,self.lock)
    def container(self):
        run='a'*32;name='gokrb-usage-'+run;image='sha256:'+'b'*64
        args=U.command_args(name,image,run)
        value=dict(Name='/'+name,Image=image,Id='c'*64,Config=dict(Labels={U.LABEL:run},User='10001:10001',
            Entrypoint=['/usr/bin/env'],Cmd=args[args.index(image)+1:]),
            HostConfig=dict(NetworkMode='none',ReadonlyRootfs=True,Privileged=False,CapDrop=['ALL'],
                SecurityOpt=['no-new-privileges'],Memory=2*1024**3,NanoCpus=2*10**9,PidsLimit=128,
                Init=True,IpcMode='private',CgroupnsMode='private',Tmpfs={'/work':U.TMPFS},LogConfig={'Type':'none'}),
            Mounts=[])
        return value,name,image,run
    def test_container_accepted_only_with_limits(self):
        args=self.container();U.inspect_container(*args)
        for key,value in [('NetworkMode','host'),('ReadonlyRootfs',False),('Privileged',True),
                          ('CapDrop',[]),('Memory',0),('NanoCpus',0),('PidsLimit',0),('Init',False),
                          ('IpcMode','host'),('CgroupnsMode','host'),('Binds',['/tmp:/tmp']),
                          ('Devices',[{}]),('ExtraHosts',['host:1.2.3.4']),('PidMode','host')]:
            v,n,i,r=self.container();v['HostConfig'][key]=value
            with self.subTest(key=key),self.assertRaises(U.ProbeError):U.inspect_container(v,n,i,r)
    def test_wrong_image_user_command_or_mount_rejected(self):
        for key,value in [('User','0'),('Entrypoint',['sh']),('Cmd',[]),('Volumes',{'/x':{}}),('Healthcheck',{'Test':['x']})]:
            v,n,i,r=self.container();v['Config'][key]=value
            with self.subTest(key=key),self.assertRaises(U.ProbeError):U.inspect_container(v,n,i,r)
        v,n,i,r=self.container();v['Mounts']=[{'Type':'bind','Destination':'/work'}]
        with self.assertRaises(U.ProbeError):U.inspect_container(v,n,i,r)
    def test_build_has_no_network_and_keeps_three_variants(self):
        sources={p:(U.HERE/p).read_bytes() for p in U.SOURCES}
        built=U.build_files(self.C,sources)
        self.assertIn(b'GOPROXY=off GOSUMDB=off',built['build.sh'])
        self.assertIn(b'CGO_ENABLED=0',built['build.sh'])
        self.assertIn(b'GOTOOLCHAIN=local',built['build.sh'])
        self.assertIn(b'for variant in original context-fix global-control',built['build.sh'])
        self.assertIn(b'--kill-after=2s 10s',built['driver.sh'])
        self.assertNotEqual(built['global-APReq.go'],sources['patches/APReq.go'])
    def test_bounded_build_diagnostics(self):
        value=U.build_diagnostics(b'cmd/usage-regression/main.go:12: unknown symbol secret\n')
        self.assertEqual(value['source_errors'],[{'file':'cmd/usage-regression/main.go','line':12}])
        self.assertNotIn('secret',str(value))
    def test_support_bound_to_reviewed_bytes(self):
        self.assertEqual(self.C.sha(U.SUPPORT.read_bytes()),U.SUPPORT_SHA)
        self.assertEqual(self.B.sha((U.HERE/'go_bundle.py').read_bytes()),U.BUNDLE_SHA)

if __name__=='__main__':unittest.main()
