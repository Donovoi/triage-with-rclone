import copy
import hashlib
import io
import json
import unittest
import types
import zipfile

import hdfs_context_build as U
B=U.load_bundle(U.load_support())

class Bundle(unittest.TestCase):
    def setUp(self):self.raw=(U.ASSETS_HOME/'assets-lock.json').read_bytes();self.lock=B.load_lock(self.raw)
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
        cls.lock=B.load_lock((U.ASSETS_HOME/'assets-lock.json').read_bytes())
        cls.pins={(r['module'],r['version']):r['h1'] for r in cls.lock['assets'] if r['kind']=='zip'}
    def report(self):
        modules=[dict(path=p,version=v,sum=self.pins[(p,v)],replacement='') for p,v in (
            ('github.com/colinmarc/hdfs/v2','v2.4.0'),('github.com/jcmturner/gokrb5/v8','v8.4.4'),
            ('golang.org/x/crypto','v0.57.0'),('golang.org/x/net','v0.60.0'))]
        original=dict(variant='original',sha256='a'*64,bytes=10*1024*1024,checks=13,version_verified=True,modules=modules)
        patched=copy.deepcopy(original);patched.update(variant='patched',sha256='b'*64)
        patched['modules'][0].update(sum='',replacement='context-cancellation')
        return dict(schema_version=1,success=True,error='none',go_version='go1.26.10',binaries=[original,patched],
                    rclone_renewal_verified=False,provider_accepted=False,cancellation_verified=False,context_tests=dict(
                        stage='complete',parser_vectors=14,binary_sha256='c'*64,binary_bytes=10*1024*1024,exit_code=0,stderr_empty=True,
                        protocol_valid=True,runs=list(U.TEST_NAMES),passed=list(U.TEST_NAMES),failed=[],all_passed=True))
    def validate(self,v,code=0):return U.validate_native(self.C,U.canonical(v),code,self.lock)
    def test_original_and_explicit_local_replacement_accepted(self):
        self.assertTrue(self.validate(self.report())['success'])
    def test_false_claims_and_wrong_toolchain_rejected(self):
        for k,v in [('cancellation_verified',True),('rclone_renewal_verified',True),('provider_accepted',True),('go_version','go1.27.3'),('success',1)]:
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
        for index,module,key,value in [(0,0,'sum','h1:bad'),(0,1,'replacement','context-cancellation'),
                                      (1,0,'sum','h1:bad'),(1,0,'replacement',''),(1,2,'replacement','context-cancellation')]:
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
        self.assertEqual(out['patched-rclone.mod'],mod+b'\nreplace github.com/colinmarc/hdfs/v2 => /opt/input/patched-hdfs\n')
        self.assertEqual(out['patched-rclone.sum'],sums)
        with self.assertRaises(U.ProbeError):U.build_files(self.C,sources,mod+b'\nreplace unapproved => ./x\n',sums)
    def test_diagnostics_project_no_raw_text(self):
        out=U.build_diagnostics(b'inspect_context_build.go:12: secret words\n')
        self.assertEqual(out['source_errors'],[dict(file='inspect_context_build.go',line=12)])
        self.assertNotIn('secret',str(out))
    def test_checksum_manifest_preserves_upstream_unicode_filenames(self):
        names=['original/cmd/bisync/testdata/test_normalization/modfiles/測試_filtersfile.txt',
               'original/cmd/bisync/testdata/test_extended_filenames/initial/Русский.txt']
        hashes={names[0]:'a'*64,names[1]:'b'*64}
        raw=U.checksum_manifest(hashes)
        self.assertFalse(raw.startswith(b'\xef\xbb\xbf'))
        self.assertNotIn(b'\r',raw)
        lines=raw.decode('utf-8').splitlines()
        self.assertEqual([line[66:] for line in lines],sorted(names))
        self.assertEqual({line[66:]:line[:64] for line in lines},hashes)
        with self.assertRaises(UnicodeEncodeError):raw.decode('utf-8').encode('ascii')
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
        self.assertEqual(result['frames'][0]['file'],'hdfs_context_build.py')
        self.assertTrue(1<=result['frames'][0]['line']<=10000)
        for error,category,number in [(ValueError('private text'),'value_error',None),
                                      (OSError(13,'private path'),'io_error',13),
                                      (RuntimeError('private text'),'unexpected',None)]:
            projected=U.failure_diagnostics(error)
            self.assertEqual(projected,dict(category=category,errno=number,frames=[]))
            self.assertNotIn('private',str(projected))
    def test_parent_diagnostics_bound_trace_depth_and_frames(self):
        import types
        code=types.SimpleNamespace(co_filename=str(U.HERE/'hdfs_context_build.py'))
        frame=types.SimpleNamespace(f_code=code)
        trace=None
        for _ in range(70):trace=types.SimpleNamespace(tb_frame=frame,tb_lineno=42,tb_next=trace)
        fake=types.SimpleNamespace(__traceback__=trace,errno=True)
        result=U.failure_diagnostics(fake)
        self.assertEqual(result['frames'],[dict(file='hdfs_context_build.py',line=42)]*8)
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
        self.assertEqual(U.sha((U.ASSETS_HOME/'rclone_build_bundle.py').read_bytes()),U.BUNDLE_SHA)


    def test_context_result_rejects_claim_inflation_and_bad_types(self):
        cases=[('stage','failed'),('stage',[]),('parser_vectors',True),('parser_vectors',13),('parser_vectors',15),
               ('binary_sha256','x'*64),('binary_bytes',True),('binary_bytes',1024),('exit_code',True),('exit_code',1),
               ('stderr_empty',1),('stderr_empty',False),('protocol_valid',False),('all_passed',False),
               ('runs',list(reversed(U.TEST_NAMES))),('passed',list(U.TEST_NAMES[:-1])),('failed',[U.TEST_NAMES[0]]),
               ('runs',[U.TEST_NAMES[0]]*11),('extra','private text')]
        for key,value in cases:
            report=self.report();report['context_tests'][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(U.ProbeError):self.validate(report)
    def test_finite_failed_context_result_survives_without_acceptance(self):
        report=self.report();report.update(success=False,error='probe_failed')
        unit=report['context_tests'];unit.update(stage='failed',exit_code=1,all_passed=False,
            passed=list(U.TEST_NAMES[:-1]),failed=[U.TEST_NAMES[-1]])
        self.assertEqual(U.native_test_diagnostics(self.C,U.canonical(report)),unit)
        with self.assertRaises(U.ProbeError):self.validate(report,1)
        report['context_tests']['private_raw']='not retained'
        with self.assertRaises((U.ProbeError,self.C.ProbeError)):U.native_test_diagnostics(self.C,U.canonical(report))
    def test_failed_diagnostics_are_closed_and_bounded(self):
        for raw in (b'',b'{}',b'x'*262145,b'{"context_tests":NaN}',b'{"context_tests":{},"context_tests":{}}'):
            with self.assertRaises((U.ProbeError,self.C.ProbeError)):U.native_test_diagnostics(self.C,raw)
    def test_patch_sources_are_bound_to_seven_closed_pins(self):
        sources={name:path.read_bytes() for name,path in U.SOURCES.items()}
        pins=U.load_patch_pins(self.C,sources)
        self.assertEqual(set(pins),set(U.PATCH_PATHS))
        for key in U.PATCH_PATHS:
            changed=dict(sources);changed['patches/'+key]+=b' '
            with self.subTest(key=key),self.assertRaises(U.ProbeError):U.load_patch_pins(self.C,changed)
        original=json.loads(sources['patch-pins.json'])
        for mutation in ('duplicate','missing','unknown','extra','bool_bytes','bad_hash','added_before'):
            value=copy.deepcopy(original)
            if mutation=='duplicate':value['files'][1]=value['files'][0]
            elif mutation=='missing':value['files'].pop()
            elif mutation=='unknown':value['files'][0]['path']='hdfs/../../escape'
            elif mutation=='extra':value['files'][0]['extra']='text'
            elif mutation=='bool_bytes':value['files'][0]['afterBytes']=True
            elif mutation=='bad_hash':value['files'][0]['afterSha256']='x'*64
            else:
                row=next(r for r in value['files'] if r['beforeSha256'] is None)
                row.update(beforeBytes=1,beforeSha256='a'*64)
            changed={**sources,'patch-pins.json':U.canonical(value)}
            with self.subTest(mutation=mutation),self.assertRaises(U.ProbeError):U.load_patch_pins(self.C,changed)
    def test_build_preserves_baseline_before_backend_overlay(self):
        sources={name:path.read_bytes() for name,path in U.SOURCES.items()}
        out=U.build_files(self.C,sources,b'module github.com/rclone/rclone\n',b'sums\n')
        build=out['build.sh'].decode();driver=out['driver.sh'].decode()
        self.assertLess(build.index('-o /opt/probes/rclone-original .'),build.index('cp /opt/input/patches/rclone/'))
        self.assertLess(build.index('cp /opt/input/patches/rclone/'),build.index('-o /opt/probes/rclone-patched .'))
        self.assertIn('-test.run '+chr(39)+'^('+'|'.join(U.TEST_NAMES)+')$'+chr(39),driver)
        self.assertIn('40s /opt/probes/context-tests -test.v -test.timeout=30s',driver)
        self.assertIn('printf '+chr(39)+'%s'+chr(92)+'n'+chr(39)+' "$unit_status"',driver)
        self.assertNotIn(chr(92)+'"',driver)
        self.assertNotIn(chr(92)+'"',build)
        self.assertNotIn(chr(92)+chr(92)+'n',build)
        self.assertIn('-mod=readonly',build)
        self.assertIn('GOPROXY=off GOSUMDB=off CGO_ENABLED=0',build)
        self.assertNotIn('go test -race',build)

class CleanupDiagnostics(unittest.TestCase):
    run_id='a'*32
    name='rclone-usage-'+'a'*32
    tag=name
    image='sha256:'+'b'*64
    container='c'*64

    class Error(Exception):
        def __init__(self,code):
            self.code=code
            super().__init__('SECRET raw command details')

    def record(self,kind):
        if kind=='container':
            return dict(Id=self.container,Name='/'+self.name,Image=self.image,Config=dict(Labels={U.LABEL:self.run_id}))
        return dict(Id=self.image,RepoTags=[self.tag+':latest'],Config=dict(Labels={U.LABEL:self.run_id}))

    def driver(self,snapshots,call_error=None):
        pending=iter(snapshots);calls=[]
        def inspect(*args,**kwargs):
            value=next(pending)
            if isinstance(value,BaseException):raise value
            return value
        def call(args):
            calls.append(args)
            if call_error is not None:raise call_error
        return types.SimpleNamespace(inspect=inspect,call=call),calls

    def invoke(self,docker,kind,diagnostic):
        identity=self.container if kind=='container' else self.image
        U.cleanup_owned(docker,kind,identity,identity,self.run_id,self.name,self.tag,self.image,diagnostic)

    def test_exact_container_and_image_removal_commands(self):
        for kind,identity,force in (('container',self.container,['--force']),('image',self.image,[])):
            docker,calls=self.driver([self.record(kind),None]);diagnostic=dict(stage='not_attempted',error='none')
            self.invoke(docker,kind,diagnostic)
            self.assertEqual(diagnostic,dict(stage='complete',error='none'))
            self.assertEqual(calls,[[kind,'rm',*force,identity]])

    def test_verified_absence_performs_no_removal(self):
        for kind in ('container','image'):
            docker,calls=self.driver([None]);diagnostic=dict(stage='not_attempted',error='none')
            self.invoke(docker,kind,diagnostic)
            self.assertEqual(calls,[]);self.assertEqual(diagnostic,dict(stage='complete',error='none'))

    def test_binding_failure_identifies_phase_and_never_removes(self):
        mutations=[('container','Config',{},'bind_label'),('image','Config',{},'bind_label'),
            ('container','Id','d'*64,'bind_identity'),('image','Id','sha256:'+'d'*64,'bind_identity'),
            ('container','Name','/unowned','bind_container_name'),('container','Image','sha256:'+'e'*64,'bind_container_image'),
            ('image','RepoTags',['unowned:latest'],'bind_image_tags')]
        for kind,key,bad,phase in mutations:
            record=self.record(kind);record[key]=bad;docker,calls=self.driver([record]);diagnostic=dict(stage='not_attempted',error='none')
            with self.assertRaises(U.ProbeError):self.invoke(docker,kind,diagnostic)
            self.assertEqual(calls,[]);self.assertEqual(diagnostic,dict(stage=phase,error=kind+'_cleanup_failed'))

    def test_initial_inspect_timeout_is_not_absence(self):
        for kind in ('container','image'):
            docker,calls=self.driver([self.Error('command_timeout')]);diagnostic=dict(stage='not_attempted',error='none')
            with self.assertRaises(self.Error):self.invoke(docker,kind,diagnostic)
            self.assertEqual(calls,[]);self.assertEqual(diagnostic,dict(stage='inspect',error='command_timeout'))

    def test_remove_timeout_preserves_failure_without_retry(self):
        docker,calls=self.driver([self.record('image')],self.Error('command_timeout'));diagnostic=dict(stage='not_attempted',error='none')
        with self.assertRaises(self.Error):self.invoke(docker,'image',diagnostic)
        self.assertEqual(calls,[['image','rm',self.image]])
        self.assertEqual(diagnostic,dict(stage='remove',error='command_timeout'))

    def test_post_removal_inspect_failure_remains_unqualified(self):
        docker,calls=self.driver([self.record('image'),self.Error('container_binding_invalid')]);diagnostic=dict(stage='not_attempted',error='none')
        with self.assertRaises(self.Error):self.invoke(docker,'image',diagnostic)
        self.assertEqual(diagnostic,dict(stage='confirm_absence',error='container_binding_invalid'))
        self.assertEqual(len(calls),1)

    def test_still_present_image_is_not_cleanup_success(self):
        docker,calls=self.driver([self.record('image'),self.record('image')]);diagnostic=dict(stage='not_attempted',error='none')
        with self.assertRaises(U.ProbeError):self.invoke(docker,'image',diagnostic)
        self.assertEqual(diagnostic,dict(stage='confirm_absence',error='image_cleanup_failed'))
        self.assertEqual(len(calls),1)

    def test_unknown_errors_never_export_raw_text(self):
        docker,calls=self.driver([self.Error('SECRET')]);diagnostic=dict(stage='not_attempted',error='none')
        with self.assertRaises(self.Error):self.invoke(docker,'image',diagnostic)
        self.assertEqual(diagnostic,dict(stage='inspect',error='unexpected'))
        self.assertNotIn('SECRET',str(diagnostic))
        self.assertEqual(U.cleanup_error(OSError('SECRET')),'filesystem')
        self.assertEqual(U.cleanup_error(KeyboardInterrupt()),'interrupted')

    def test_invalid_kind_cannot_invoke_docker(self):
        docker,calls=self.driver([]);diagnostic=dict(stage='not_attempted',error='none')
        with self.assertRaises(U.ProbeError):self.invoke(docker,'volume',diagnostic)
        self.assertEqual(calls,[]);self.assertEqual(diagnostic,dict(stage='preflight',error='input_invalid'))

if __name__=='__main__':unittest.main()
