"""Adversarial pure planning tests. No process/config native execution."""
import hashlib
from pathlib import Path
import re
import unittest
import mit_kdc_plan as P

ARGS = ('012345abcdef','abcdef012345','0123456789abcdef'*2,'fedcba9876543210'*2)

class KdcPlanning(unittest.TestCase):
    def test_untrusted_token_inputs_rejected_before_planning(self):
        attacks = ['',None,True,12,b'012345abcdef','../etc/passwd','\n[realms]',
                   'a'*100000,'１２３４５６７８９０１２','012345abcde\x00','012345abcde\n',
                   '012345abcde;', '012345abcde"', '012345ABCDEf']
        for slot in range(4):
            for value in attacks:
                with self.subTest(slot=slot,value=repr(value)[:30]):
                    args=list(ARGS);args[slot]=value
                    with self.assertRaises(P.PlanError):P.plan(*args)

    def test_port_type_range_and_collision_rejection(self):
        for value in [True,False,None,0,88,1023,65536,18888.0,'18888',[],{}]:
            for key in ('kdc_port','relay_port'):
                with self.subTest(value=value,key=key):
                    with self.assertRaises(P.PlanError):P.plan(*ARGS,**{key:value})
        with self.assertRaisesRegex(P.PlanError,'distinct_ports'):P.plan(*ARGS,kdc_port=18888,relay_port=18888)
        self.assertEqual(P.plan(*ARGS,kdc_port=1024,relay_port=65535)['listeners'][0]['port'],1024)

    def test_separate_synthetic_master_and_reader_secrets(self):
        with self.assertRaisesRegex(P.PlanError,'distinct_secrets'):P.plan(*ARGS[:2],ARGS[2],ARGS[2])
        p=P.plan(*ARGS)
        self.assertTrue(p['realm'].endswith('.INVALID'))
        self.assertTrue(p['reader'].endswith('@'+p['realm']))
        self.assertNotEqual(p['reader'].split('@')[0],'fixtureadmin')

    def test_secrets_only_appear_in_bounded_stdin(self):
        p=P.plan(*ARGS)
        all_text=repr({k:v for k,v in p.items() if k not in ('setup','foreground')})
        for command in p['setup']+[p['foreground']]:
            all_text+=repr({k:v for k,v in command.items() if k!='stdin'})
        for secret in ARGS[2:]:self.assertNotIn(secret,all_text)
        self.assertEqual(p['setup'][0]['stdin'],(ARGS[2]+'\n'+ARGS[2]+'\n').encode())
        self.assertEqual(p['setup'][1]['stdin'],(ARGS[3]+'\n'+ARGS[3]+'\n').encode())
        self.assertTrue(all(not c['stdin'] for c in p['setup'][2:]+[p['foreground']]))

    def test_commands_are_direct_without_interactive_query_or_shell(self):
        p=P.plan(*ARGS)
        for command in p['setup']+[p['foreground']]:
            self.assertIsInstance(command['argv'],list)
            self.assertIn(command['argv'][0],(P.BIN+'/kdb5_util',P.BIN+'/kadmin.local',P.BIN+'/krb5kdc'))
            self.assertNotIn('-q',command['argv'])
            self.assertNotIn('-P',command['argv'])
            self.assertNotIn('-pw',command['argv'])
            self.assertEqual(command['maximum_output_bytes'],65536)
        self.assertEqual(len(p['setup']),6)
        self.assertEqual(len({c['label'] for c in p['setup']}),6)
        for c in p['setup']:self.assertEqual(c['timeout_seconds'],10)
        for c in p['setup'][1:]:
            self.assertIn('-p',c['argv'])
            self.assertEqual(c['argv'][c['argv'].index('-p')+1],'fixtureadmin@'+p['realm'])

    def test_foreground_has_no_fork_workers_or_clock_offset(self):
        fg=P.plan(*ARGS)['foreground']
        self.assertIn('-n',fg['argv'])
        self.assertNotIn('-w',fg['argv'])
        self.assertNotIn('-T',fg['argv'])
        self.assertEqual(fg['startup_timeout_seconds'],10)
        self.assertEqual(fg['lifetime_seconds'],180)

    def test_only_owned_loopback_tcp_listener(self):
        p=P.plan(*ARGS,kdc_port=20001,relay_port=20002)
        config=p['files'][P.ROOT+'/kdc.conf'].decode()
        self.assertEqual(p['listeners'],[dict(protocol='tcp',address='127.0.0.1',port=20001)])
        self.assertEqual(config.count('kdc_listen = ""'),2)
        self.assertEqual(config.count('kdc_tcp_listen = 127.0.0.1:20001'),2)
        self.assertIn('kadmind_listen = ""',config)
        self.assertIn('kpasswd_listen = ""',config)
        self.assertNotIn('20002',config)

    def test_client_routing_and_plugin_scope_are_explicit(self):
        p=P.plan(*ARGS)
        direct=p['files'][P.ROOT+'/krb5.conf'].decode()
        reader=p['files'][P.ROOT+'/reader-krb5.conf'].decode()
        self.assertEqual(direct.replace('18888','18889'),reader)
        for content in (direct,reader):
            self.assertIn('plugin_base_dir = /opt/mit/lib/krb5/plugins',content)
            self.assertEqual(content.count('enable_only = encrypted_timestamp'),2)
            for key in ('dns_lookup_kdc','dns_lookup_realm','dns_uri_lookup','dns_canonicalize_hostname','rdns'):
                self.assertIn(key+' = false',content)
            self.assertIn('clockskew = 5',content)
            self.assertNotIn('include ',content)
            self.assertNotIn('module ',content)
        server=p['files'][P.ROOT+'/kdc.conf'].decode()
        self.assertIn('db_module_dir = /opt/mit/lib/krb5/plugins/kdb',server)
        self.assertIn('db_library = db2',server)
        self.assertIn('database_name = /work/mit-kdc/principal',server)
        self.assertIn('key_stash_file = /work/mit-kdc/master.stash',server)

    def test_closed_environment_and_private_paths(self):
        p=P.plan(*ARGS)
        expected={'HOME','TMPDIR','PATH','LANG','LC_ALL','LD_LIBRARY_PATH','KRB5_CONFIG',
                  'KRB5_KDC_PROFILE','KRB5CCNAME','KRB5_KTNAME','KRB5_CLIENT_KTNAME','KRB5RCACHEDIR'}
        for c in p['setup']+[p['foreground']]:
            self.assertEqual(set(c['environment']),expected)
            self.assertEqual(c['environment']['LD_LIBRARY_PATH'],'/opt/mit/lib')
            self.assertEqual(c['environment']['KRB5_CONFIG'],'/work/mit-kdc/krb5.conf')
            self.assertNotIn('LD_PRELOAD',c['environment'])
        self.assertEqual(p['directory_mode'],0o700)
        self.assertEqual(p['file_mode'],0o600)
        self.assertTrue(all(n.startswith(P.ROOT+'/') for n in p['files']))
        self.assertEqual(p['files'][P.ROOT+'/kadm5.acl'],b'')

    def test_principals_use_distinct_random_keys_and_export_preserves_keys(self):
        p=P.plan(*ARGS)
        creates=[c for c in p['setup'] if c['label'].endswith('_create') and c['label']!='database_create']
        self.assertEqual(len(creates),3)
        for c in creates:
            self.assertIn('+requires_preauth',c['argv'])
            self.assertIn('180 seconds',c['argv'])
            self.assertIn('120 seconds',c['argv'])
        for c in creates[1:]:self.assertIn('-randkey',c['argv'])
        exports=[c for c in p['setup'] if c['label'].endswith('_export')]
        self.assertEqual(len(exports),2)
        self.assertNotEqual(exports[0]['argv'][-1],exports[1]['argv'][-1])
        for c in exports:
            self.assertIn('-norandkey',c['argv'])
            self.assertNotIn('-e',c['argv'])
            self.assertIn(P.ROOT+'/'+c['label'].split('_')[0]+'.keytab',c['argv'])

    def test_mutation_cannot_contaminate_another_command_or_plan(self):
        one=P.plan(*ARGS);two=P.plan(*ARGS)
        one['setup'][0]['environment']['LD_PRELOAD']='/untrusted'
        one['setup'][1]['argv'].append('untrusted')
        self.assertNotIn('LD_PRELOAD',one['setup'][1]['environment'])
        self.assertNotIn('LD_PRELOAD',two['setup'][0]['environment'])
        self.assertNotIn('untrusted',two['setup'][1]['argv'])

    def test_planning_never_grants_native_or_renewal_credit(self):
        p=P.plan(*ARGS)
        self.assertIs(p['native_qualified'],False)
        self.assertIs(p['renewal_verified'],False)

    def test_native_resource_round_trips_two_independent_synthetic_plans(self):
        for args in (ARGS,('987654fedcba','fedcba987654','a'*32,'b'*32)):
            raw=P.runtime_template()
            for marker,value in [('__REALM__','SYNTHETIC'+args[0].upper()+'.INVALID'),
                                  ('__READER__','reader'+args[1]),
                                  ('__MASTER_SECRET__',args[2]),('__READER_SECRET__',args[3])]:
                raw=raw.replace(marker.encode(),value.encode())
            self.assertEqual(raw,P.json_plan(P.plan(*args)))
            self.assertNotIn(b'__',raw)

    def test_native_template_contains_no_seed_secrets_or_ambient_inputs(self):
        raw=P.runtime_template()
        self.assertLessEqual(len(raw),16384)
        for value in ARGS:self.assertNotIn(value.encode(),raw)
        for marker in (b'__REALM__',b'__READER__',b'__MASTER_SECRET__',b'__READER_SECRET__'):
            self.assertIn(marker,raw)

    def test_native_resource_and_owner_hash_bind_the_current_plan(self):
        root=Path(__file__).parent
        raw=(root/'mit-kdc-plan-template.json').read_bytes()
        self.assertEqual(raw,P.runtime_template())
        source=(root/'MitKdcOwner.java').read_text()
        matches=re.findall(r'TEMPLATE_SHA = "([a-f0-9]{64})";',source)
        self.assertEqual(matches,[hashlib.sha256(raw).hexdigest()])

if __name__=='__main__':unittest.main()
