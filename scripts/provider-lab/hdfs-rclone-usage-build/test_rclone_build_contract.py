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


class Downloads(unittest.TestCase):
    def row(self):
        return dict(file='module-000.mod',url='https://proxy.golang.org/m/@v/v1.0.0.mod',bytes=3,sha256=B.sha(b'abc'))
    def response(self,body=b'abc',partial_timeout=False):
        from email.message import Message
        class Response(io.BytesIO):
            status=200
            url='https://proxy.golang.org/m/@v/v1.0.0.mod'
            headers=Message()
            reads=0
            def read(self,size=-1):
                self.reads+=1
                if partial_timeout and self.reads>1:raise TimeoutError('read timeout')
                return super().read(1 if partial_timeout else size)
        return Response(body)
    def execute(self,results,*,clock=None,limit=None):
        import tempfile
        from pathlib import Path
        outer=self
        class Opener:
            calls=0
            def open(self,*args,**kwargs):
                value=results[self.calls];self.calls+=1
                if isinstance(value,BaseException):raise value
                return value
        opener=Opener();sleeps=[];events=[]
        with tempfile.TemporaryDirectory(dir=U.HERE) as tmp:
            context=Path(tmp)
            B.download(context,{'assets':[self.row()]},opener=opener,clock=clock or (lambda:0),
                       sleeper=sleeps.append,observer=lambda *e:events.append(e))
            outer.assertEqual((context/'assets/module-000.mod').read_bytes(),b'abc')
        return opener.calls,sleeps,events
    def test_transient_open_errors_retry_then_succeed(self):
        import urllib.error
        result=self.execute([TimeoutError(),urllib.error.HTTPError('https://invalid.invalid/',503,'unused',{},None),self.response()])
        self.assertEqual(result,(3,[1,2],[('download',0,0),('download',0,1)]))
    def test_partial_timeout_restarts_with_fresh_digest_and_file(self):
        self.assertEqual(self.execute([self.response(partial_timeout=True),self.response()])[:2],(2,[1]))
    def test_retry_attempts_have_fixed_limit(self):
        import tempfile
        from pathlib import Path
        class Opener:
            calls=0
            def open(self,*a,**k):self.calls+=1;raise TimeoutError()
        opener=Opener();sleeps=[]
        with tempfile.TemporaryDirectory(dir=U.HERE) as tmp,self.assertRaises(TimeoutError):
            B.download(Path(tmp),{'assets':[self.row()]},opener=opener,clock=lambda:0,sleeper=sleeps.append)
        self.assertEqual((opener.calls,sleeps),(3,[1,2]))
    def test_integrity_and_nontransient_errors_are_not_retried(self):
        import urllib.error
        cases=[self.response(b'bad'),self.response(b'ab'),self.response(b'abcd'),
               urllib.error.HTTPError('https://invalid.invalid/',403,'unused',{},None),urllib.error.URLError(ValueError('permanent'))]
        for first in cases:
            with self.subTest(first=type(first).__name__),self.assertRaises((ValueError,urllib.error.URLError)):
                self.execute([first])
    def test_backoff_cannot_extend_total_deadline(self):
        import tempfile
        from pathlib import Path
        now=[0];sleeps=[]
        class Opener:
            calls=0
            def open(self,*a,**k):self.calls+=1;now[0]=569;raise TimeoutError()
        opener=Opener()
        with tempfile.TemporaryDirectory(dir=U.HERE) as tmp,self.assertRaises(ValueError):
            B.download(Path(tmp),{'assets':[self.row()]},opener=opener,clock=lambda:now[0],sleeper=sleeps.append)
        self.assertEqual((opener.calls,sleeps),(1,[]))
    def test_partial_retry_bytes_count_toward_global_bound(self):
        old=B.MAX_TOTAL;B.MAX_TOTAL=3
        try:
            with self.assertRaises(ValueError):self.execute([self.response(partial_timeout=True),self.response()])
        finally:B.MAX_TOTAL=old
    def test_existing_file_is_preserved(self):
        import tempfile
        from pathlib import Path
        response=self.response()
        with tempfile.TemporaryDirectory(dir=U.HERE) as tmp:
            context=Path(tmp);destination=context/'assets/module-000.mod'
            class Opener:
                def open(self,*a,**k):destination.write_bytes(b'preserved');return response
            with self.assertRaises(FileExistsError):
                B.download(context,{'assets':[self.row()]},opener=Opener(),clock=lambda:0,sleeper=lambda _:None)
            self.assertEqual(destination.read_bytes(),b'preserved')

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
    def test_worker_error_projection_has_no_raw_message(self):
        import urllib.error
        cases=[(urllib.error.HTTPError('https://invalid.invalid/',503,'private text',{},None),('http_error',503)),
               (urllib.error.URLError(TimeoutError('private text')),('timeout',0)),
               (urllib.error.URLError('private text'),('network_io',0)),
               (ValueError('private text'),('asset_validation',0)),
               (zipfile.BadZipFile('private text'),('archive_invalid',0)),
               (OSError('private text'),('filesystem_error',0)),
               (RuntimeError('private text'),('unexpected',0))]
        for error,expected in cases:
            with self.subTest(error=type(error).__name__):
                self.assertEqual(U.worker_error(B,error),expected)
                self.assertNotIn('private',str(U.worker_error(B,error)))
    def test_parent_diagnostics_keep_bound_source_location_only(self):
        try:U.sha(None)
        except TypeError as error:result=U.failure_diagnostics(error)
        self.assertEqual(result['category'],'type_error')
        self.assertIsNone(result['errno'])
        self.assertEqual(len(result['frames']),1)
        self.assertEqual(result['frames'][0]['file'],'rclone_usage_build.py')
        self.assertTrue(1<=result['frames'][0]['line']<=10000)
        for error,category,number in [(ValueError('private text'),'value_error',None),
                                      (OSError(13,'private path'),'io_error',13),
                                      (RuntimeError('private text'),'unexpected',None)]:
            projected=U.failure_diagnostics(error)
            self.assertEqual(projected,dict(category=category,errno=number,frames=[]))
            self.assertNotIn('private',str(projected))
    def test_parent_diagnostics_bound_trace_depth_and_frames(self):
        import types
        code=types.SimpleNamespace(co_filename=str(U.HERE/'rclone_usage_build.py'))
        frame=types.SimpleNamespace(f_code=code)
        trace=None
        for _ in range(70):trace=types.SimpleNamespace(tb_frame=frame,tb_lineno=42,tb_next=trace)
        fake=types.SimpleNamespace(__traceback__=trace,errno=True)
        result=U.failure_diagnostics(fake)
        self.assertEqual(result['frames'],[dict(file='rclone_usage_build.py',line=42)]*8)
        self.assertIsNone(result['errno'])
    def test_worker_status_closed_and_typed(self):
        valid=dict(schema_version=1,phase='download',asset_index=17,processed_assets=17,error='http_error',http_status=503)
        self.assertEqual(U.validate_worker_status(valid),valid)
        for key,value in [('phase',[]),('phase','unknown'),('asset_index',True),('asset_index',1137),
                          ('processed_assets',True),('processed_assets',1140),('error','raw traceback'),
                          ('http_status',0),('extra','url')]:
            changed={**valid,key:value}
            with self.subTest(key=key,value=value),self.assertRaises(U.ProbeError):U.validate_worker_status(changed)
        self.assertEqual(U.validate_worker_status(dict(schema_version=1,phase='complete',asset_index=-1,
                         processed_assets=1137,error='none',http_status=0))['phase'],'complete')
    def test_download_failure_preserves_asset_ordinal(self):
        import tempfile,urllib.error
        from pathlib import Path
        class Opener:
            def open(self,*args,**kwargs):
                raise urllib.error.HTTPError('https://invalid.invalid/',503,'not emitted',{},None)
        events=[]
        row=dict(file='module-000.mod',url='https://proxy.golang.org/m/@v/v1.0.0.mod',bytes=1,sha256=B.sha(b'x'))
        with tempfile.TemporaryDirectory(dir=U.HERE) as tmp:
            with self.assertRaises(urllib.error.HTTPError):
                B.download(Path(tmp),{'assets':[row]},opener=Opener(),clock=lambda:0,observer=lambda *event:events.append(event),sleeper=lambda _:None)
        self.assertEqual(events,[('download',0,0)])

    def test_shared_helpers_are_bound(self):
        self.assertEqual(U.sha(U.SUPPORT.read_bytes()),U.SUPPORT_SHA)
        self.assertEqual(U.sha((U.HERE/'rclone_build_bundle.py').read_bytes()),U.BUNDLE_SHA)

if __name__=='__main__':unittest.main()
