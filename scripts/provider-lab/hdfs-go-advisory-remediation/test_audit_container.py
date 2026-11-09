import copy,json,types,unittest
import audit_container as U

RUN='1'*32
IMAGE='sha256:'+'2'*64
CID='3'*64
class ContainerAdmission(unittest.TestCase):
    def name(self,mode=None,target=None):return 'go-binary-audit-'+RUN+'-'+('identity' if mode is None else mode+'-'+target)
    def spec(self,mode=None,target=None):
        name=self.name(mode,target);args=U.command_args(name,IMAGE,RUN,mode,target)
        return dict(Name='/'+name,Image=IMAGE,Id=CID,
            Config=dict(Labels={U.LABEL:RUN},User='10001:10001',Entrypoint=['/usr/bin/env'],
                Cmd=args[args.index(IMAGE)+1:],Volumes=None,ExposedPorts=None,Healthcheck=None),
            HostConfig=dict(NetworkMode='none',ReadonlyRootfs=True,Privileged=False,CapDrop=['ALL'],CapAdd=None,
                Binds=None,PortBindings=None,SecurityOpt=['no-new-privileges'],Memory=2*1024**3,NanoCpus=2*10**9,
                PidsLimit=128,Init=True,IpcMode='private',CgroupnsMode='private',Tmpfs={'/work':U.TMPFS},
                LogConfig={'Type':'none'},Devices=[],DeviceRequests=None,ExtraHosts=None,PidMode=''),
            Mounts=[],State=dict(Status='created',Running=False,OOMKilled=False,ExitCode=0))
    def check(self,value,mode=None,target=None):
        return U.inspect_container(value,self.name(mode,target),IMAGE,RUN,mode,target)
    def test_ten_owned_commands_per_variant_have_closed_execution(self):
        self.check(self.spec())
        for variant in ('original','patched'):
            commands=[]
            for mode,target in U.variant_cases(variant)+(('regression','upgraded'),):
                self.check(self.spec(mode,target),mode,target)
                args=U.command_args(self.name(mode,target),IMAGE,RUN,mode,target)
                expected=['/opt/probes/remediation-regression'] if mode=='regression' else ['/opt/probes/audit-driver',mode,target]
                self.assertEqual(args[-len(expected):],expected);commands.append(tuple(args))
                self.assertNotIn('--privileged',args);self.assertIn('none',args)
            self.assertEqual(len(commands),9);self.assertEqual(len(set(commands)),9)
    def test_unplanned_command_and_names_are_rejected(self):
        for mode,target in [('scan','stripped'),('extract','positive'),('shell','original'),(None,'original')]:
            with self.assertRaises(U.ProbeError):U.command_args(self.name(mode or 'x',target or 'x'),IMAGE,RUN,mode,target)
        with self.assertRaises(U.ProbeError):U.command_args('another-container',IMAGE,RUN)
    def test_container_identity_and_label_are_bound(self):
        for key,value in [('Name','/another'),('Image','sha256:'+'4'*64),('Id','invalid')]:
            spec=self.spec();spec[key]=value
            with self.assertRaises(U.ProbeError):self.check(spec)
        spec=self.spec();spec['Config']['Labels'][U.LABEL]='f'*32
        with self.assertRaises(U.ProbeError):self.check(spec)
    def test_privilege_mount_network_and_resource_changes_rejected(self):
        changes=dict(NetworkMode='host',ReadonlyRootfs=False,Privileged=True,CapDrop=[],CapAdd=['SYS_ADMIN'],
            Binds=['/:/host'],PortBindings={'22/tcp':[]},SecurityOpt=[],Memory=4*1024**3,
            NanoCpus=4*10**9,PidsLimit=0,Init=False,IpcMode='host',CgroupnsMode='host',
            Tmpfs={'/work':'rw,exec'},LogConfig={'Type':'json-file'},Devices=[{'PathOnHost':'/dev/sda'}],
            DeviceRequests=[{}],ExtraHosts=['private:1.2.3.4'],PidMode='host')
        for key,value in changes.items():
            with self.subTest(key=key):
                spec=self.spec();spec['HostConfig'][key]=value
                with self.assertRaises(U.ProbeError):self.check(spec)
    def test_entrypoint_command_user_and_exposed_surfaces_rejected(self):
        for key,value in [('User','0'),('Entrypoint',['/bin/sh']),('Cmd',['-c','unexpected']),
                          ('Volumes',{'/host':{}}),('ExposedPorts',{'80/tcp':{}}),('Healthcheck',{'Test':['CMD','x']})]:
            spec=self.spec();spec['Config'][key]=value
            with self.assertRaises(U.ProbeError):self.check(spec)
    def test_only_owned_work_tmpfs_may_be_mounted(self):
        spec=self.spec();spec['Mounts']=[dict(Type='tmpfs',Destination='/work')];self.check(spec)
        for mounts in ([dict(Type='bind',Destination='/work')],[dict(Type='tmpfs',Destination='/other')],
                       [dict(Type='tmpfs',Destination='/work')]*2):
            spec['Mounts']=mounts
            with self.assertRaises(U.ProbeError):self.check(spec)
    def test_boolean_resource_limits_are_rejected(self):
        for key in ('Memory','NanoCpus','PidsLimit'):
            spec=self.spec();spec['HostConfig'][key]=True
            with self.assertRaises(U.ProbeError):self.check(spec)

class NativeExecutionOwnership(unittest.TestCase):
    def setup_run(self,mode='scan',target='positive'):
        factory=ContainerAdmission();factory.setUp()
        spec=factory.spec(mode,target);calls=[]
        class Docker:
            current=None
            def inspect(self,kind,reference,allow_missing=False):
                calls.append(('inspect',kind,reference))
                return copy.deepcopy(self.current)
            def call(self,args,**kwargs):
                calls.append(('call',args,kwargs))
                if args[0]=='create':self.current=copy.deepcopy(spec)
                elif args[:2]==['start','--attach']:self.current['State']['Status']='exited'
                elif args[:2]==['container','rm']:self.current=None
                return types.SimpleNamespace(code=0,stdout='stdout',stderr='stderr')
        C=types.SimpleNamespace(read=lambda p,n:b'{}' if p=='stdout' else b'')
        R,_,_,_=U.load_inputs()
        return C,R,Docker(),calls
    def test_wrapper_run_is_removed_by_exact_id_before_return(self):
        C,R,docker,calls=self.setup_run();owned=[]
        raw,code,cid=U.execute(C,R,docker,IMAGE,RUN,'go-binary-audit-'+RUN,owned,'scan','positive')
        self.assertEqual((raw,code,cid),(b'{}',0,CID));self.assertTrue(owned[0]['removed'])
        start=next(row for row in calls if row[0]=='call' and row[1][0]=='start')
        self.assertEqual(start[2],dict(timeout=110,limit=90*1024*1024,allow_failure=True))
        remove=next(row for row in calls if row[0]=='call' and row[1][:2]==['container','rm'])
        self.assertEqual(remove[1],['container','rm','--force',CID])
        self.assertEqual(owned[0]['cleanup_diagnostics'],dict(stage='complete',error='none'))
    def test_ten_containers_fit_unchanged_docker_budget(self):
        # Each absent inspect adds the qualified helper's exact-empty listing.
        # Pre-build calls cost seven; owned image cleanup costs four.
        fixed_calls=7+4
        for variant in ('original','patched'):
            total=fixed_calls
            for mode,target in ((None,None),)+U.variant_cases(variant)+(('regression','upgraded'),):
                C,R,docker,calls=self.setup_run(mode,target)
                cost=[];original=docker.inspect
                def inspect(kind,reference,allow_missing=False):
                    result=original(kind,reference,allow_missing)
                    cost.append(2 if result is None else 1)
                    return result
                docker.inspect=inspect
                U.execute(C,R,docker,IMAGE,RUN,'go-binary-audit-'+RUN,[],mode,target)
                total+=sum(cost)+sum(row[0]=='call' for row in calls)
            self.assertEqual(total,111);self.assertLessEqual(total,120)
    def test_foreign_preexisting_container_is_preserved(self):
        C,R,docker,calls=self.setup_run();docker.current={'Id':'4'*64};owned=[]
        with self.assertRaises(U.ProbeError):U.execute(C,R,docker,IMAGE,RUN,'go-binary-audit-'+RUN,owned,'scan','positive')
        self.assertEqual(owned,[]);self.assertFalse(any(row[0]=='call' for row in calls))
    def test_failed_start_preserves_owned_entry_for_cleanup(self):
        C,R,docker,calls=self.setup_run();original=docker.call
        def fail(args,**kwargs):
            if args[0]=='start':raise U.ProbeError('probe_failed')
            return original(args,**kwargs)
        docker.call=fail;owned=[]
        with self.assertRaises(U.ProbeError):U.execute(C,R,docker,IMAGE,RUN,'go-binary-audit-'+RUN,owned,'scan','positive')
        self.assertEqual(owned[0]['id'],CID);self.assertFalse(owned[0]['removed'])
    def test_exited_state_must_match_process_code_without_oom(self):
        for change in [dict(OOMKilled=True),dict(Running=True),dict(Status='running'),dict(ExitCode=1)]:
            C,R,docker,calls=self.setup_run();original=docker.call
            def alter(args,**kwargs):
                result=original(args,**kwargs)
                if args[0]=='start':docker.current['State'].update(change)
                return result
            docker.call=alter
            with self.assertRaises(U.ProbeError):U.execute(C,R,docker,IMAGE,RUN,'go-binary-audit-'+RUN,[],'scan','positive')

class SourceAndDiagnostics(unittest.TestCase):
    def test_source_pins_bind_all_loaded_helpers_and_snapshot(self):
        R,modules,data,hashes=U.load_inputs()
        self.assertEqual(set(modules),set(U.MODULES));self.assertEqual(R.LABEL,U.LABEL)
        self.assertIn('hdfs-go-advisory-remediation/advisory-snapshot.json.gz',data)
        self.assertEqual(hashes[U.HERE/'source-pins.json'],U.PINS_SHA)
        self.assertEqual(hashes[R.SUPPORT],R.SUPPORT_SHA)
        self.assertEqual(hashes[R.ASSETS_HOME/'rclone_build_bundle.py'],R.BUNDLE_SHA)
    def test_wrapper_diagnostics_never_return_raw_output_or_arbitrary_errors(self):
        C=types.SimpleNamespace(parse=lambda raw,limit:json.loads(raw))
        out=U.wrapper_diagnostics(C,json.dumps(dict(error='private arbitrary string',stdout_base64='secret',duration_ms=9)).encode())
        self.assertEqual(out,dict(parseable=True,error='unavailable',capture_controls=None,duration_ms=9))
        out=U.wrapper_diagnostics(C,b'not JSON');self.assertFalse(out['parseable'])
    def test_native_error_category_remains_closed(self):
        C=types.SimpleNamespace(parse=lambda raw,limit:json.loads(raw))
        out=U.wrapper_diagnostics(C,b'{"error":"scanner_deadline","capture_controls":9,"duration_ms":90001}')
        self.assertEqual(out['error'],'scanner_deadline');self.assertEqual(out['capture_controls'],9)
    def test_failure_diagnostics_do_not_export_exception_text(self):
        try:raise ValueError('not permitted in report')
        except ValueError as error:out=U.failure_diagnostics(error,{})
        self.assertEqual(out['category'],'value_error');self.assertNotIn('not permitted',json.dumps(out))
