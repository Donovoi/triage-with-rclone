"""Pure contained-KDC configuration and argv planning; never executes a child.

The future native owner must create and verify every directory/file, launch
each command with a cleared environment, bound streams, and reap every child.
Inputs are synthetic tokens only; no host path or inherited environment enters.
"""
import json
import re

ROOT = '/work/mit-kdc'
LIB = '/opt/mit/lib'
BIN = '/opt/mit/bin'
ENCTYPE = 'aes128-cts-hmac-sha1-96'
MAX_LIFE_SECONDS = 120
MAX_RENEW_SECONDS = 180

class PlanError(ValueError):
    pass

def need(value, reason):
    if not value:
        raise PlanError(reason)

def token(value, length):
    need(type(value) is str and re.fullmatch('[0-9a-f]{'+str(length)+'}', value), 'synthetic_token')
    return value

def port(value):
    need(type(value) is int and 1024 <= value <= 65535, 'loopback_port')
    return value

def _client_config(realm, endpoint):
    return f'''[libdefaults]
 default_realm = {realm}
 dns_lookup_kdc = false
 dns_lookup_realm = false
 dns_uri_lookup = false
 dns_canonicalize_hostname = false
 rdns = false
 canonicalize = false
 udp_preference_limit = 1
 clockskew = 5
 ticket_lifetime = 120s
 renew_lifetime = 180s
 forwardable = false
 proxiable = false
 allow_weak_crypto = false
 default_tkt_enctypes = {ENCTYPE}
 default_tgs_enctypes = {ENCTYPE}
 permitted_enctypes = {ENCTYPE}
 default_ccache_name = FILE:{ROOT}/reader.ccache
 default_keytab_name = FILE:{ROOT}/hdfs.keytab
 default_client_keytab_name = FILE:{ROOT}/reader.keytab
 default_rcache_name = dfl:
 plugin_base_dir = {LIB}/krb5/plugins
[realms]
 {realm} = {{
  kdc = 127.0.0.1:{endpoint}
 }}
[domain_realm]
 127.0.0.1 = {realm}
[plugins]
 clpreauth = {{
  enable_only = encrypted_timestamp
 }}
 kdcpreauth = {{
  enable_only = encrypted_timestamp
 }}
 hostrealm = {{
  enable_only = profile
 }}
'''.encode('ascii')

def _server_config(realm, endpoint):
    return f'''[kdcdefaults]
 kdc_listen = ""
 kdc_tcp_listen = 127.0.0.1:{endpoint}
[realms]
 {realm} = {{
  kdc_listen = ""
  kdc_tcp_listen = 127.0.0.1:{endpoint}
  kadmind_listen = ""
  kpasswd_listen = ""
  database_module = synthetic_db
  key_stash_file = {ROOT}/master.stash
  acl_file = {ROOT}/kadm5.acl
  max_life = 120s
  max_renewable_life = 180s
  master_key_type = {ENCTYPE}
  supported_enctypes = {ENCTYPE}:normal
  no_host_referral = *
 }}
[dbmodules]
 db_module_dir = {LIB}/krb5/plugins/kdb
 synthetic_db = {{
  db_library = db2
  database_name = {ROOT}/principal
 }}
[logging]
 kdc = STDERR
 admin_server = STDERR
 default = STDERR
'''.encode('ascii')

def environment():
    """Return the entire child environment, not additions to the parent."""
    return dict(HOME=ROOT+'/home', TMPDIR=ROOT+'/tmp', PATH='/usr/bin:/bin',
        LANG='C', LC_ALL='C', LD_LIBRARY_PATH=LIB,
        KRB5_CONFIG=ROOT+'/krb5.conf', KRB5_KDC_PROFILE=ROOT+'/kdc.conf',
        KRB5CCNAME='FILE:'+ROOT+'/reader.ccache', KRB5_KTNAME='FILE:'+ROOT+'/hdfs.keytab',
        KRB5_CLIENT_KTNAME='FILE:'+ROOT+'/reader.keytab', KRB5RCACHEDIR=ROOT+'/rcache')

def plan(realm_token, reader_token, master_secret, reader_secret, kdc_port=18888, relay_port=18889):
    realm = 'SYNTHETIC'+token(realm_token,12).upper()+'.INVALID'
    reader = 'reader'+token(reader_token,12)+'@'+realm
    token(master_secret,32)
    token(reader_secret,32)
    need(master_secret != reader_secret, 'distinct_secrets')
    port(kdc_port); port(relay_port)
    need(kdc_port != relay_port, 'distinct_ports')
    env = environment()
    commands = []
    def command(label, argv, stdin=b'', timeout=10):
        commands.append(dict(label=label, argv=argv, stdin=stdin, environment=dict(env),
                             timeout_seconds=timeout, maximum_output_bytes=65536))
    command('database_create', [BIN+'/kdb5_util', '-r', realm, 'create', '-s'],
            (master_secret+'\n'+master_secret+'\n').encode('ascii'))
    admin = [BIN+'/kadmin.local', '-r', realm, '-p', 'fixtureadmin@'+realm]
    restrictions = ['-maxlife','120 seconds','-maxrenewlife','180 seconds',
                    '+requires_preauth','-allow_forwardable','-allow_proxiable','-allow_postdated']
    command('reader_create', admin+['addprinc']+restrictions+[reader],
            (reader_secret+'\n'+reader_secret+'\n').encode('ascii'))
    for service in ('hdfs','HTTP'):
        principal = service+'/127.0.0.1@'+realm
        command(service.lower()+'_create', admin+['addprinc','-randkey']+restrictions+[principal])
        command(service.lower()+'_export', admin+['ktadd','-norandkey','-k',ROOT+'/'+service.lower()+'.keytab',principal])
    foreground = dict(label='kdc_foreground', argv=[BIN+'/krb5kdc','-n','-r',realm],
                      stdin=b'', environment=dict(env), maximum_output_bytes=65536,
                      startup_timeout_seconds=10, lifetime_seconds=180)
    return dict(schema_version=1, scope='synthetic_mit_kdc_preparation', realm=realm, reader=reader,
        directories=[ROOT,ROOT+'/home',ROOT+'/tmp',ROOT+'/rcache'], directory_mode=0o700,
        files={ROOT+'/krb5.conf':_client_config(realm,kdc_port),
               ROOT+'/reader-krb5.conf':_client_config(realm,relay_port),
               ROOT+'/kdc.conf':_server_config(realm,kdc_port), ROOT+'/kadm5.acl':b''},
        file_mode=0o600, setup=commands, foreground=foreground,
        listeners=[dict(protocol='tcp',address='127.0.0.1',port=kdc_port)],
        renewal_verified=False, native_qualified=False)

def json_plan(value):
    """Serialize a plan for the contained Java owner without executable content."""
    def convert(item):
        if type(item) is bytes:
            return item.decode('ascii')
        if type(item) is dict:
            return {key:convert(val) for key,val in item.items()}
        if type(item) is list:
            return [convert(val) for val in item]
        return item
    return json.dumps(convert(value),sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')

def runtime_template():
    """Non-secret immutable resource; native owner supplies four closed tokens."""
    sample = plan('012345abcdef','abcdef012345','0123456789abcdef'*2,'fedcba9876543210'*2)
    raw = json_plan(sample)
    for before,after in [
        ('SYNTHETIC012345ABCDEF.INVALID','__REALM__'),
        ('readerabcdef012345','__READER__'),
        ('0123456789abcdef'*2,'__MASTER_SECRET__'),
        ('fedcba9876543210'*2,'__READER_SECRET__')]:
        need(before.encode() in raw,'template_marker')
        raw = raw.replace(before.encode(),after.encode())
    need(len(raw) <= 16384,'template_bound')
    return raw
