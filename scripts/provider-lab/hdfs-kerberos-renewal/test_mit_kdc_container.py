"""Guarded contracts for acquisition, containment and native-report admission."""
import copy
from email.message import Message
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import mit_kdc_container as M

ROOT=Path(__file__).parent

class Response(io.BytesIO):
    def __init__(self,data,url,headers,status=200):
        super().__init__(data);self.url=url;self.status=status;self.headers=Message()
        for key,value in headers:self.headers.add_header(key,value)

class Opener:
    def __init__(self,data,url,headers=None,status=200):
        self.data=data;self.url=url;self.headers=headers or [('Content-Length',str(len(data)))];self.status=status;self.calls=0
    def open(self,request,timeout):
        self.calls+=1
        assert request.full_url=='https://archive.ubuntu.com/ubuntu/pool/main/f/fixture/fixture_1_amd64.deb'
        assert request.get_header('Accept-encoding')=='identity' and 0<timeout<=20
        return Response(self.data,self.url,self.headers,self.status)

def package_fixture():
    raw=b'passive bytes only';url='https://archive.ubuntu.com/ubuntu/pool/main/f/fixture/fixture_1_amd64.deb'
    return raw,dict(packages=[dict(filename='fixture_1_amd64.deb',url=url,bytes=len(raw),sha256=M.sha(raw))])

def native_success():
    owner=dict(stage='closed',setup_completed=6,children=7,children_reaped=True,streams_reaped=True,
        modules_verified=True,listener_verified=True,forced=False,descendants_seen=False,stream_failure=False,
        private_material_removed=True,native_qualified=False,renewal_verified=False)
    return dict(schema_version=1,scope='mit_kdc_bootstrap_only',success=True,stage='completed',error='none',
        checks=dict.fromkeys(M.CHECKS,True),owner=owner,tasks=5,managed_assertions=83,tgt_lifetime_seconds=120,service_lifetime_seconds=10,
        duration_ms=1000,cleanup_complete=True,**dict.fromkeys(M.FALSE_CLAIMS,False))

def container_fixture():
    run='a'*32;name='mit-kdc-'+run;image='sha256:'+'b'*64;args=M.command_args(name,image,run)
    return dict(Name='/'+name,Image=image,Id='c'*64,
        Config=dict(Labels={M.LABEL:run},User='10001:10001',Entrypoint=['/usr/bin/env'],Cmd=args[args.index(image)+1:],Volumes=None,ExposedPorts=None,Healthcheck=None),
        HostConfig=dict(NetworkMode='none',ReadonlyRootfs=True,Privileged=False,CapDrop=['ALL'],CapAdd=None,Binds=None,PortBindings=None,
            SecurityOpt=['no-new-privileges'],Memory=2*1024**3,NanoCpus=2*10**9,PidsLimit=128,Init=True,IpcMode='private',CgroupnsMode='private',
            Tmpfs={'/work':M.TMPFS},LogConfig={'Type':'none'},Devices=None,DeviceRequests=None,ExtraHosts=None,PidMode=''),Mounts=[]),name,image,run

class ContainerContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.C=M.load_support();cls.B=M.load_bundle(cls.C)

    def test_exact_support_bundle_and_lock_pins(self):
        self.assertEqual(self.C.file_hash(M.SUPPORT),M.SUPPORT_SHA)
        lock=self.B.load_lock((ROOT/'mit-runtime-lock.json').read_bytes())
        self.assertEqual(len(lock['packages']),15)
        self.assertEqual(sum(len(p['members']) for p in lock['packages']),32)
        self.assertEqual(self.C.BASE,self.B.BASE_IMAGE)

    def test_acquisition_accepts_only_exact_complete_bytes(self):
        raw,lock=package_fixture();url=lock['packages'][0]['url'];opener=Opener(raw,url)
        self.assertEqual(M.download_package_bytes(lock,opener=opener,clock=lambda:0),{lock['packages'][0]['filename']:raw})
        self.assertEqual(opener.calls,1)

    def test_acquisition_rejects_status_redirect_header_and_content_mutations(self):
        raw,lock=package_fixture();url=lock['packages'][0]['url']
        cases=[Opener(raw,url,status=404),Opener(raw,url+'/redirect'),Opener(raw[:-1],url),Opener(raw+b'x',url),
            Opener(b'x'*len(raw),url),Opener(raw,url,headers=[('Content-Length',str(len(raw))),('Content-Length',str(len(raw)))]),
            Opener(raw,url,headers=[('Content-Length',str(len(raw))),('Content-Encoding','gzip')]),
            Opener(raw,url,headers=[('Content-Length',str(len(raw))),('Transfer-Encoding','chunked')])]
        for opener in cases:
            with self.subTest(status=opener.status,url=opener.url,headers=opener.headers):
                with self.assertRaises(M.ProbeError):M.download_package_bytes(lock,opener=opener,clock=lambda:0)

    def test_acquisition_deadline_cannot_be_reset_per_package(self):
        raw,lock=package_fixture();clock=iter([0,0,0,121])
        with self.assertRaises(M.ProbeError):M.download_package_bytes(lock,opener=Opener(raw,lock['packages'][0]['url']),clock=lambda:next(clock))

    def test_bundle_writes_are_owned_regular_files_and_never_overwrite(self):
        with tempfile.TemporaryDirectory(dir=ROOT,prefix='pure-bundle-') as directory:
            root=Path(directory);self.assertEqual(root.resolve().parent,ROOT.resolve())
            members={'mit/lib/krb5/plugins/kdb/db2.so':b'not executed','mit/licenses/test.copyright':b'notice'}
            M.write_bundle(self.C,root,members)
            for name,raw in members.items():self.assertEqual((root/name).read_bytes(),raw)
            with self.assertRaises(FileExistsError):M.write_bundle(self.C,root,members)
            for bad in ['../outside','mit/../../outside','/absolute','mit\\outside','mit//outside']:
                with self.subTest(path=bad):
                    with self.assertRaises(M.ProbeError):M.write_bundle(self.C,root,{bad:b'untrusted'})

    @unittest.skipIf(os.name=='nt','Real symlink control runs on the isolated hosted Linux runner')
    def test_linked_parent_rejected_before_creating_descendants(self):
        with tempfile.TemporaryDirectory(dir=ROOT,prefix='pure-link-') as directory:
            root=Path(directory);self.assertEqual(root.resolve().parent,ROOT.resolve())
            context=root/'context';outside=root/'outside';context.mkdir();outside.mkdir();(context/'mit').symlink_to(outside,target_is_directory=True)
            with self.assertRaises(Exception):M.write_bundle(self.C,context,{'mit/lib/new/member':b'untrusted'})
            self.assertEqual(list(outside.iterdir()),[])

    def test_container_admission_rejects_privilege_network_mount_and_identity_mutations(self):
        value,name,image,run=container_fixture();M.inspect_container(value,name,image,run)
        mutations=[('NetworkMode','host'),('ReadonlyRootfs',False),('Privileged',True),('CapDrop',[]),('CapAdd',['SYS_ADMIN']),
            ('Binds',['/:/host']),('PortBindings',{'88/tcp':[{}]}),('SecurityOpt',[]),('Memory',True),('Memory',0),
            ('NanoCpus',0),('PidsLimit',0),('Init',False),('IpcMode','host'),('CgroupnsMode','host'),('Tmpfs',{}),
            ('LogConfig',{'Type':'json-file'}),('Devices',[{}]),('DeviceRequests',[{}]),('ExtraHosts',['host:1.2.3.4']),('PidMode','host')]
        for key,bad in mutations:
            changed=copy.deepcopy(value);changed['HostConfig'][key]=bad
            with self.subTest(field=key):
                with self.assertRaises(M.ProbeError):M.inspect_container(changed,name,image,run)
        for key,bad in [('User','0'),('Entrypoint',['/bin/sh']),('Cmd',['untrusted']),('Volumes',{'/host':{}}),('ExposedPorts',{'88/tcp':{}}),('Healthcheck',{'Test':['CMD','true']})]:
            changed=copy.deepcopy(value);changed['Config'][key]=bad
            with self.subTest(field=key):
                with self.assertRaises(M.ProbeError):M.inspect_container(changed,name,image,run)
        for key,bad in [('Id','other'),('Image','sha256:'+'d'*64),('Name','/other'),('Mounts',[{'Type':'bind','Destination':'/work'}])]:
            changed=copy.deepcopy(value);changed[key]=bad
            with self.assertRaises(M.ProbeError):M.inspect_container(changed,name,image,run)

    def test_native_success_requires_every_check_and_cleanup_predicate(self):
        value=native_success();self.assertEqual(M.validate_java(self.C,M.canonical(value),0),value)
        for key in M.CHECKS:
            changed=copy.deepcopy(value);changed['checks'][key]=False
            with self.subTest(check=key):
                with self.assertRaises(M.ProbeError):M.validate_java(self.C,M.canonical(changed),0)
        for key in ['children_reaped','streams_reaped','modules_verified','listener_verified','private_material_removed']:
            changed=copy.deepcopy(value);changed['owner'][key]=False
            with self.assertRaises(M.ProbeError):M.validate_java(self.C,M.canonical(changed),0)
        for key in ['forced','descendants_seen','stream_failure']:
            changed=copy.deepcopy(value);changed['owner'][key]=True
            with self.assertRaises(M.ProbeError):M.validate_java(self.C,M.canonical(changed),0)

    def test_native_report_rejects_scope_claim_type_and_bound_mutations(self):
        value=native_success()
        edits=[('scope','provider_accepted'),('schema_version',True),('stage',[]),('error','private raw error'),('tasks',True),
            ('tasks',6),('managed_assertions',82),('duration_ms',190001),('tgt_lifetime_seconds',121),('service_lifetime_seconds',0),('cleanup_complete',False)]
        edits += [(key,True) for key in M.FALSE_CLAIMS]
        for key,bad in edits:
            changed=copy.deepcopy(value);changed[key]=bad
            with self.subTest(field=key):
                with self.assertRaises(M.ProbeError):M.validate_java(self.C,M.canonical(changed),0)
        with self.assertRaises(M.ProbeError):M.validate_java(self.C,M.canonical(value),2)
        for change in [lambda v:v.update(unrecognized='value'),lambda v:v.pop('owner'),lambda v:v['owner'].update(native_qualified=True),lambda v:v['owner'].update(children=True)]:
            changed=copy.deepcopy(value);change(changed)
            with self.assertRaises(M.ProbeError):M.validate_java(self.C,M.canonical(changed),0)

    def test_native_failure_can_be_retained_without_success_credit(self):
        value=native_success();value.update(success=False,error='setup_nonzero',stage='owner_prepare',cleanup_complete=True,tasks=0,tgt_lifetime_seconds=0,service_lifetime_seconds=0)
        value['checks']=dict.fromkeys(M.CHECKS,False);value['owner'].update(setup_completed=0,children=1,modules_verified=False,listener_verified=False)
        self.assertFalse(M.validate_java(self.C,M.canonical(value),2)['success'])
        with self.assertRaises(M.ProbeError):M.validate_java(self.C,M.canonical(value),0)

    def test_image_context_binds_every_selected_input_without_installation(self):
        lock=self.B.load_lock((ROOT/'mit-runtime-lock.json').read_bytes())
        members={m['destination']:m for p in lock['packages'] for m in p['members']}
        sources={n:(ROOT/n).read_bytes() for n in M.SOURCES};rows=[dict(sha256='f'*64)]
        files=M.build_files(self.C,rows,members,sources);docker=files['Dockerfile'].decode();checks=files['checksums'].decode()
        self.assertTrue(docker.startswith('FROM '+self.B.BASE_IMAGE+'\n'))
        self.assertIn('sha256sum -c /opt/rpc/checksums',docker)
        self.assertIn('-proc:none -implicit:none',docker)
        self.assertIn('USER 10001:10001',docker)
        for forbidden in ('apt-get','dpkg','curl','wget','ADD '):self.assertNotIn(forbidden,docker)
        for name,pin in members.items():self.assertIn(pin['sha256']+'  /opt/'+name+'\n',checks)
        for name,raw in sources.items():self.assertIn(M.sha(raw)+'  /opt/rpc/'+name+'\n',checks)

    def test_local_execution_is_rejected_before_download_or_container_work(self):
        with patch.dict(os.environ,{},clear=True):result=M.run()
        self.assertFalse(result['success'])
        self.assertEqual(result['stage'],'preflight')
        self.assertEqual(result['errors'],['hosted_linux_required'])
        self.assertIsNone(result['inputs'])
        self.assertTrue(all(result['cleanup'].values()))

    def test_compiler_diagnostics_exclude_arbitrary_paths_and_messages(self):
        raw=b'/secret/token:9: error: private\n#4 /opt/rpc/MitKdcOwner.java:17: error: cannot find symbol secret-content\n/opt/rpc/Untrusted.java:1: error: private\n/opt/rpc/MitKdcBootstrapProbe.java:31: error: incompatible types: private\n'
        value=M.build_diagnostics(raw)
        self.assertEqual(value,{'java_errors':[dict(file='MitKdcOwner.java',line=17,category='symbol'),dict(file='MitKdcBootstrapProbe.java',line=31,category='type')]})
        self.assertNotIn('private',repr(value));self.assertNotIn('secret',repr(value))
        for invalid in (b'/opt/rpc/MitKdcOwner.java:0: error: other',b'/opt/rpc/MitKdcOwner.java:10001: error: other'):
            with self.assertRaises(M.ProbeError):M.build_diagnostics(invalid)

if __name__=='__main__':unittest.main()
