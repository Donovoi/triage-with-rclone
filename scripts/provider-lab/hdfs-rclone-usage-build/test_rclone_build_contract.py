import copy
import hashlib
import io
import json
import unittest
import zipfile

import rclone_build_bundle as B
import rclone_usage_build as U

class Bundle(unittest.TestCase):
    def setUp(self):self.raw=(U.HERE/'assets-lock.json').read_bytes();self.lock=B.load_lock(self.raw)
    def test_full_graph_is_pinned(self):
        self.assertEqual(len(self.lock['assets']),1137)
        self.assertEqual(sum(r['bytes'] for r in self.lock['assets']),507477878)
        self.assertEqual(self.lock['source_commit'],'be8d6044eacb843b74d335db0c5fbe09222031fe')
    def test_changed_lock_rejected(self):
        with self.assertRaises(ValueError):B.load_lock(self.raw+b' ')
    def test_duplicate_and_nonfinite_json_rejected(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}'):
            with self.assertRaises(ValueError):B.parse(raw)
    def test_changed_or_truncated_asset_rejected(self):
        r=dict(kind='zip',bytes=1,sha256=B.sha(b'x'))
        for raw in (b'',b'xx',b'y'):
            with self.assertRaises(ValueError):B.verify_asset(raw,r)
    def archive(self,name,data=b'package m\n',mode=0):
        b=io.BytesIO()
        with zipfile.ZipFile(b,'w') as z:
            i=zipfile.ZipInfo(name);i.external_attr=mode<<16;z.writestr(i,data)
        raw=b.getvalue();digest=hashlib.sha256((B.sha(data)+'  '+name+'\n').encode()).digest()
        return raw,dict(kind='zip',module='m',version='v1.0.0',bytes=len(raw),sha256=B.sha(raw),
                        h1='h1:'+B.base64.b64encode(digest).decode())
    def test_hash1_and_retention_modes(self):
        raw,row=self.archive('m@v1.0.0/m.go')
        files,stats=B.module_files(raw,row)
        self.assertEqual(files,{})
        self.assertEqual(stats,dict(members=1,expanded_bytes=10))
        files,stats=B.module_files(raw,row,retain=True)
        self.assertEqual(files,{'m.go':b'package m\n'})
        row['h1']='invalid'
        with self.assertRaises(ValueError):B.module_files(raw,row)
    def test_archive_path_and_special_file_rejections(self):
        for name,mode in [('m@v1.0.0/../x',0),('/m@v1.0.0/x',0),('m@v1.0.0/a\\b',0),
                          ('m@v1.0.0/a\nb',0),('m@v1.0.0/link',0o120777),('m@v1.0.0/x',0o104755)]:
            with self.subTest(name=name):
                raw,row=self.archive(name,mode=mode)
                with self.assertRaises(ValueError):B.module_files(raw,row)

class Admission(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.C=U.load_support();cls.B=U.load_bundle(cls.C)
        cls.lock=B.load_lock((U.HERE/'assets-lock.json').read_bytes())
        cls.pins={(r['module'],r['version']):r['h1'] for r in cls.lock['assets'] if r['kind']=='zip'}
    def report(self):
        modules=[dict(path=p,version=v,sum=self.pins[(p,v)],replacement='') for p,v in (
            ('github.com/colinmarc/hdfs/v2','v2.4.0'),('github.com/jcmturner/gokrb5/v8','v8.4.4'),
            ('golang.org/x/crypto','v0.57.0'),('golang.org/x/net','v0.60.0'))]
        original=dict(variant='original',sha256='a'*64,bytes=10*1024*1024,checks=13,version_verified=True,modules=modules)
        patched=copy.deepcopy(original);patched.update(variant='patched',sha256='b'*64)
        patched['modules'][1].update(sum='',replacement='context-fix')
        return dict(schema_version=1,success=True,error='none',go_version='go1.26.10',binaries=[original,patched],
                    rclone_renewal_verified=False,provider_accepted=False)
    def validate(self,v,code=0):return U.validate_native(self.C,U.canonical(v),code,self.lock)
    def test_original_and_explicit_local_replacement_accepted(self):
        self.assertTrue(self.validate(self.report())['success'])
    def test_false_claims_and_wrong_toolchain_rejected(self):
        for k,v in [('rclone_renewal_verified',True),('provider_accepted',True),('go_version','go1.27.3'),('success',1)]:
            r=self.report();r[k]=v
            with self.subTest(k=k),self.assertRaises(U.ProbeError):self.validate(r)
    def test_binary_identity_and_typed_bounds(self):
        for k,v in [('variant','other'),('sha256','x'*64),('bytes',True),('bytes',1024),('checks',True),
                    ('checks',12),('version_verified',1),('extra','ignored')]:
            r=self.report();r['binaries'][0][k]=v
            with self.subTest(k=k),self.assertRaises(U.ProbeError):self.validate(r)
    def test_variant_order_and_distinct_binaries_required(self):
        r=self.report();r['binaries'].reverse()
        with self.assertRaises(U.ProbeError):self.validate(r)
        r=self.report();r['binaries'][1]['sha256']=r['binaries'][0]['sha256']
        with self.assertRaises(U.ProbeError):self.validate(r)
    def test_actual_rclone_versions_required(self):
        for index in range(2):
            for module in range(4):
                r=self.report();r['binaries'][index]['modules'][module]['version']='v0.0.0'
                with self.subTest(index=index,module=module),self.assertRaises(U.ProbeError):self.validate(r)
    def test_checksum_and_replacement_binding(self):
        for index,module,key,value in [(0,0,'sum','h1:bad'),(0,1,'replacement','context-fix'),
                                      (1,1,'sum','h1:bad'),(1,1,'replacement',''),(1,2,'replacement','context-fix')]:
            r=self.report();r['binaries'][index]['modules'][module][key]=value
            with self.subTest(index=index,module=module,key=key),self.assertRaises(U.ProbeError):self.validate(r)
    def test_duplicate_missing_and_extra_dependency_fields_rejected(self):
        for change in ('duplicate','missing','extra'):
            r=self.report();modules=r['binaries'][0]['modules']
            if change=='duplicate':modules.append(copy.deepcopy(modules[0]))
            elif change=='missing':modules.pop()
            else:modules[0]['extra']=True
            with self.subTest(change=change),self.assertRaises(U.ProbeError):self.validate(r)
    def test_nonzero_and_output_bound_rejected(self):
        with self.assertRaises(U.ProbeError):self.validate(self.report(),1)
        with self.assertRaises(U.ProbeError):U.validate_native(self.C,b'x'*262145,0,self.lock)
    def container(self):
        run='a'*32;name='rclone-usage-'+run;image='sha256:'+'b'*64
        args=U.command_args(name,image,run)
        v=dict(Name='/'+name,Image=image,Id='c'*64,Config=dict(Labels={U.LABEL:run},User='10001:10001',
            Entrypoint=['/usr/bin/env'],Cmd=args[args.index(image)+1:]),
            HostConfig=dict(NetworkMode='none',ReadonlyRootfs=True,Privileged=False,CapDrop=['ALL'],
                SecurityOpt=['no-new-privileges'],Memory=2*1024**3,NanoCpus=2*10**9,PidsLimit=128,
                Init=True,IpcMode='private',CgroupnsMode='private',Tmpfs={'/work':U.TMPFS},LogConfig={'Type':'none'}),
            Mounts=[])
        return v,name,image,run
    def test_closed_container_admission(self):
        U.inspect_container(*self.container())
        for key,value in [('NetworkMode','host'),('ReadonlyRootfs',False),('Privileged',True),('CapDrop',[]),
                          ('Memory',0),('NanoCpus',0),('PidsLimit',0),('Init',False),('IpcMode','host'),
                          ('CgroupnsMode','host'),('Binds',['/tmp:/tmp']),('Devices',[{}]),('PidMode','host')]:
            v,n,i,r=self.container();v['HostConfig'][key]=value
            with self.subTest(key=key),self.assertRaises(U.ProbeError):U.inspect_container(v,n,i,r)
    def test_wrong_command_or_user_rejected(self):
        for key,value in [('User','0'),('Cmd',[]),('Entrypoint',['sh']),('Volumes',{'/x':{}})]:
            v,n,i,r=self.container();v['Config'][key]=value
            with self.subTest(key=key),self.assertRaises(U.ProbeError):U.inspect_container(v,n,i,r)
    def test_candidate_modfile_preserves_graph_and_adds_one_replacement(self):
        sources={name:path.read_bytes() for name,path in U.SOURCES.items()}
        mod=b'module github.com/rclone/rclone\n\ngo 1.26.0\n';sums=b'published sums\n'
        out=U.build_files(self.C,sources,mod,sums)
        self.assertEqual(out['patched-rclone.mod'],mod+b'\nreplace github.com/jcmturner/gokrb5/v8 => /opt/input/patched-gokrb\n')
        self.assertEqual(out['patched-rclone.sum'],sums)
        with self.assertRaises(U.ProbeError):U.build_files(self.C,sources,mod+b'\nreplace unapproved => ./x\n',sums)
    def test_diagnostics_project_no_raw_text(self):
        out=U.build_diagnostics(b'inspect_build.go:12: secret words\n')
        self.assertEqual(out['source_errors'],[dict(file='inspect_build.go',line=12)])
        self.assertNotIn('secret',str(out))
    def test_shared_helpers_are_bound(self):
        self.assertEqual(U.sha(U.SUPPORT.read_bytes()),U.SUPPORT_SHA)
        self.assertEqual(U.sha((U.HERE/'rclone_build_bundle.py').read_bytes()),U.BUNDLE_SHA)

if __name__=='__main__':unittest.main()
