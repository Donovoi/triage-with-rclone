import copy,hashlib,importlib.util,io,json,struct,sys,tarfile,unittest
from pathlib import Path
from compression.zstd import compress
ROOT=Path(__file__).parent
spec=importlib.util.spec_from_file_location('mit_bundle',ROOT/'mit_runtime_bundle.py')
B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)

def elf():
    raw=bytearray(64);raw[:6]=b'\x7fELF\x02\x01';struct.pack_into('<HH',raw,16,3,62);return bytes(raw)
def tar(entries,format=tarfile.USTAR_FORMAT):
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w',format=format) as archive:
        for name,data,kind in entries:
            info=tarfile.TarInfo(name);info.mode=0o444
            if kind=='symlink':info.type=tarfile.SYMTYPE;info.linkname='/ignored/private-canary'
            elif kind=='fifo':info.type=tarfile.FIFOTYPE
            else:info.size=len(data)
            archive.addfile(info,io.BytesIO(data) if kind=='file' else None)
    return stream.getvalue()
def ar(rows):
    raw=bytearray(b'!<arch>\n')
    for name,data in rows:
        header=(name+'/').ljust(16)+'0'.ljust(12)+'0'.ljust(6)+'0'.ljust(6)+'100644'.ljust(8)+str(len(data)).ljust(10)+'`\n'
        assert len(header)==60
        raw.extend(header.encode());raw.extend(data)
        if len(data)%2:raw.extend(b'\n')
    return bytes(raw)
def deb(data):
    return ar([('debian-binary',b'2.0\n'),('control.tar.zst',compress(b'ignored-control')),('data.tar.zst',compress(data))])
def fixture(entries=None):
    payload=elf()
    if entries is None:entries=[('./usr/bin/fixture',payload,'file')]
    raw=deb(tar(entries))
    pkg=dict(name='fixture',version='1',filename='fixture_1_amd64.deb',url='https://archive.ubuntu.com/ubuntu/pool/main/f/fixture/fixture_1_amd64.deb',bytes=len(raw),sha256=B.digest(raw),members=[dict(source='./usr/bin/fixture',destination='mit/bin/fixture',bytes=len(payload),sha256=B.digest(payload),kind='executable')])
    return raw,pkg

def lock(pkg):
    return dict(schema_version=1,scope='mit_kdc_renewal_runtime',base_image=B.BASE_IMAGE,architecture='amd64',interpreter='python3.14',packages=[pkg])
def repin(raw,pkg):
    pkg=copy.deepcopy(pkg);pkg['bytes']=len(raw);pkg['sha256']=B.digest(raw);return pkg

class BundleContracts(unittest.TestCase):
    def rejects(self,reason,action):
        with self.assertRaisesRegex(B.BundleError,'^'+reason+'$'):action()
    def test_lock_exact_bytes_are_required(self):
        raw=(ROOT/'mit-runtime-lock.json').read_bytes()
        for changed in (raw+b' ',raw[:-1],b'{}',b'',None):
            with self.subTest(value=type(changed).__name__):self.rejects('lock_digest',lambda:B.load_lock(changed))
    def test_closed_lock_and_package_shapes(self):
        raw,p=fixture()
        for mutation in (lambda x:x.update(extra=True),lambda x:x.update(schema_version=True),lambda x:x.update(architecture='arm64'),lambda x:x.update(interpreter='python3.12'),lambda x:x.update(packages=[])):
            value=lock(copy.deepcopy(p));mutation(value)
            with self.assertRaises(B.BundleError):B._validate_lock(value)
        value=lock(copy.deepcopy(p));value['packages'][0]['extra']=True
        self.rejects('package_shape',lambda:B._validate_lock(value))
    def test_urls_and_filenames_are_closed(self):
        raw,p=fixture()
        for url in ('http://archive.ubuntu.com/ubuntu/pool/main/f/fixture/fixture_1_amd64.deb','https://archive.ubuntu.com.evil/ubuntu/pool/main/f/fixture/fixture_1_amd64.deb',p['url']+'?x=1','https://user@archive.ubuntu.com/ubuntu/pool/main/f/fixture/fixture_1_amd64.deb',p['url'].replace('/f/','/../')):
            q=copy.deepcopy(p);q['url']=url;self.rejects('package_url',lambda:B._validate_lock(lock(q)))
        q=copy.deepcopy(p);q['filename']='../fixture_1_amd64.deb';self.rejects('package_filename',lambda:B._validate_lock(lock(q)))
    def test_bad_paths_and_destination_prefixes(self):
        raw,p=fixture()
        for source in ('/usr/bin/fixture','./usr/../bin/fixture','./usr//bin/fixture','./usr/\\bin/fixture','./usr/bin/fixturé','./usr/bin/fixture\x00'):
            q=copy.deepcopy(p);q['members'][0]['source']=source
            with self.assertRaises(B.BundleError):B._validate_lock(lock(q))
        for destination in ('/mit/bin/fixture','mit/libevil/fixture','./mit/bin/fixture','mit/bin/../fixture'):
            q=copy.deepcopy(p);q['members'][0]['destination']=destination
            with self.assertRaises(B.BundleError):B._validate_lock(lock(q))
    def test_duplicate_manifest_members_and_packages(self):
        raw,p=fixture();q=copy.deepcopy(p);q['members'].append(copy.deepcopy(q['members'][0]))
        with self.assertRaises(B.BundleError):B._validate_lock(lock(q))
        value=lock(p);value['packages'].append(copy.deepcopy(p))
        with self.assertRaises(B.BundleError):B._validate_lock(value)
        self.rejects('duplicate_json_key',lambda:B._unique([('a',1),('a',2)]))
    def test_manifest_integer_and_size_bounds(self):
        raw,p=fixture()
        for value in (True,0,-1,B.MAX_PACKAGE_BYTES+1):
            q=copy.deepcopy(p);q['bytes']=value;self.rejects('package_pin',lambda:B._validate_lock(lock(q)))
        for value in (True,0,-1,B.MAX_MEMBER_BYTES+1):
            q=copy.deepcopy(p);q['members'][0]['bytes']=value;self.rejects('member_pin',lambda:B._validate_lock(lock(q)))
    def test_package_digest_precedes_decoding(self):
        raw,p=fixture()
        for changed in (raw+b'x',raw[:-1],b'bad',None):self.rejects('package_digest',lambda:B._package_members(changed,p))
    def test_complete_valid_synthetic_member(self):
        raw,p=fixture();self.assertEqual(B._package_members(raw,p),{'mit/bin/fixture':elf()})
    def test_ar_signature_truncation_and_extra_members(self):
        raw,p=fixture()
        for changed in (b'bad'+raw[3:],raw[:60],raw+b'x'):
            with self.assertRaises(B.BundleError):B._ar_members(changed)
        changed=ar([('debian-binary',b'2.0\n'),('control.tar.zst',b'a'),('data.tar.zst',b'b'),('extra',b'c')])
        self.rejects('ar_header',lambda:B._ar_members(changed))
    def test_ar_duplicate_missing_and_version(self):
        for rows in ([('debian-binary',b'2.0\n')],[('debian-binary',b'1.0\n'),('control.tar.zst',b'a'),('data.tar.zst',b'b')],[('debian-binary',b'2.0\n'),('control.tar.zst',b'a'),('control.tar.zst',b'b')]):
            with self.assertRaises(B.BundleError):B._ar_members(ar(rows))
    def test_ar_header_size_and_padding(self):
        raw=ar([('debian-binary',b'2.0\n'),('control.tar.zst',b'a'),('data.tar.zst',b'b')])
        bad=bytearray(raw);bad[8+48:8+58]=b'-1        ';self.rejects('ar_header',lambda:B._ar_members(bytes(bad)))
        bad=bytearray(raw);bad[-1]=0;self.rejects('ar_padding',lambda:B._ar_members(bytes(bad)))
    def test_compression_malformed_truncated_and_multiple_frames(self):
        encoded=compress(b'hello')
        for changed in (b'bad',encoded[:-1],encoded+encoded,encoded+b'x'):
            with self.assertRaises(B.BundleError):B._decompress(changed)
    def test_compressed_expansion_is_bounded(self):
        encoded=compress(bytes(B.MAX_TAR_BYTES+1))
        self.rejects('compressed_bound',lambda:B._decompress(encoded))
    def test_selected_symlink_and_fifo_rejected(self):
        for kind in ('symlink','fifo'):
            raw,p=fixture([('./usr/bin/fixture',b'',kind)])
            with self.assertRaises(B.BundleError):B._package_members(raw,p)
    def test_unselected_symlink_is_not_followed(self):
        raw,p=fixture([('./usr/bin/fixture',elf(),'file'),('./usr/bin/ignored',b'','symlink')])
        self.assertEqual(B._package_members(raw,p),{'mit/bin/fixture':elf()})
    def test_unsafe_tar_name_is_rejected_even_when_unselected(self):
        for name in ('/private-canary','../outside','./usr/../outside'):
            raw,p=fixture([('./usr/bin/fixture',elf(),'file'),(name,b'x','file')])
            self.rejects('member_name',lambda:B._package_members(raw,p))
    def test_duplicate_tar_member_is_rejected(self):
        raw,p=fixture([('./usr/bin/fixture',elf(),'file'),('./usr/bin/fixture',elf(),'file')])
        self.rejects('tar_member',lambda:B._package_members(raw,p))
    def test_missing_member_and_member_digest(self):
        raw,p=fixture([('./usr/bin/other',elf(),'file')]);self.rejects('missing_member',lambda:B._package_members(raw,p))
        raw,p=fixture();p['members'][0]['sha256']='0'*64;self.rejects('member_digest',lambda:B._package_members(raw,p))
    def test_selected_size_is_checked(self):
        raw,p=fixture([('./usr/bin/fixture',elf()+b'X','file')]);self.rejects('selected_member',lambda:B._package_members(raw,p))
    def test_pax_metadata_and_nonzero_tar_trailer_rejected(self):
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w',format=tarfile.PAX_FORMAT) as a:
            i=tarfile.TarInfo('./usr/bin/fixture');i.size=64;i.pax_headers={'comment':'untrusted'};a.addfile(i,io.BytesIO(elf()))
        original,p=fixture();raw=deb(stream.getvalue());self.rejects('tar_metadata',lambda:B._package_members(raw,repin(raw,p)))
        data=bytearray(tar([('./usr/bin/fixture',elf(),'file')]));data[-1]=1;raw=deb(bytes(data));self.rejects('tar_trailer',lambda:B._package_members(raw,repin(raw,p)))
    def test_non_amd64_or_non_elf_members_rejected(self):
        for offset,changed in ((0,0),(4,1),(5,2),(18,183)):
            payload=bytearray(elf());payload[offset]=changed;raw,p=fixture([('./usr/bin/fixture',bytes(payload),'file')]);p['members'][0]['sha256']=B.digest(payload)
            self.rejects('elf_platform',lambda:B._package_members(raw,p))
    def test_bundle_input_set_is_exact(self):
        raw=(ROOT/'mit-runtime-lock.json').read_bytes()
        for inputs in ({},{'unexpected.deb':b''},[]):self.rejects('bundle_inputs',lambda:B.extract_bundle(raw,inputs))

if __name__=='__main__':unittest.main(verbosity=2)
