"""Pure, bounded reader for the pinned contained MIT KDC runtime.
Requires Python3.14 for standard-library zstd. No filesystem writes, loading,
installation, network, subprocesses, or package maintainer scripts.
"""
import hashlib
import io
import json
from pathlib import PurePosixPath
import re
import struct
import tarfile
from compression.zstd import DecompressionParameter, ZstdDecompressor

LOCK_SHA256 = '4516caa8e17cb454adcc275839017fe8e57933bf256496d7ef6367d2c6e17e88'
BASE_IMAGE = 'docker.io/library/eclipse-temurin@sha256:e1c09a9ee23feb81f94016547826c1e694086cd927356fb57fccc312fcc32f85'
MAX_PACKAGE_BYTES = 4 * 1024 * 1024
MAX_TAR_BYTES = 16 * 1024 * 1024
MAX_BUNDLE_BYTES = 8 * 1024 * 1024
MAX_MEMBER_BYTES = 8 * 1024 * 1024
KINDS = frozenset(('executable','shared_library','database_module','event_module','notice'))

class BundleError(ValueError):
    pass

def need(value, reason):
    if not value:
        raise BundleError(reason)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def _integer(value, low, high):
    return type(value) is int and low <= value <= high

def _sha(value):
    return type(value) is str and re.fullmatch('[a-f0-9]{64}', value) is not None

def _name(value):
    need(type(value) is str and 0 < len(value) <= 512 and value.isascii(), 'member_name')
    need(all(32 <= ord(ch) < 127 for ch in value) and '\\' not in value and ':' not in value, 'member_name')
    if value.startswith('./'):
        value = value[2:]
    value = value.rstrip('/')
    need(value and not value.startswith('/') and all(p not in ('','.','..') for p in value.split('/')), 'member_name')
    need(PurePosixPath(value).as_posix() == value, 'member_name')
    return value

def _unique(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value, 'duplicate_json_key')
        value[key] = item
    return value

def _validate_lock(value):
    need(type(value) is dict and set(value) == {'schema_version','scope','base_image','architecture','interpreter','packages'}, 'lock_shape')
    need(type(value['schema_version']) is int and value['schema_version'] == 1 and value['scope'] == 'mit_kdc_renewal_runtime', 'lock_scope')
    need(value['base_image'] == BASE_IMAGE and value['architecture'] == 'amd64' and value['interpreter'] == 'python3.14', 'lock_platform')
    packages = value['packages']
    need(type(packages) is list and 1 <= len(packages) <= 20, 'package_count')
    names, filenames, destinations = set(), set(), set()
    total = 0
    for package in packages:
        need(type(package) is dict and set(package) == {'name','version','filename','url','bytes','sha256','members'}, 'package_shape')
        name, filename, version = package['name'], package['filename'], package['version']
        need(type(name) is str and re.fullmatch('[a-z0-9][a-z0-9+.-]{0,63}', name) and name not in names, 'package_name')
        need(type(version) is str and re.fullmatch('[A-Za-z0-9+~.-]{1,100}', version), 'package_version')
        need(type(filename) is str and filename == name+'_'+version+'_amd64.deb' and filename not in filenames, 'package_filename')
        url = package['url']
        need(type(url) is str and re.fullmatch(r'https://archive[.]ubuntu[.]com/ubuntu/pool/(main|universe)/[a-z0-9+.-]+/[a-z0-9+.-]+/'+re.escape(filename), url), 'package_url')
        need(all(part not in ('.','..') for part in url.split('/')[3:]), 'package_url')
        need(_integer(package['bytes'], 8, MAX_PACKAGE_BYTES) and _sha(package['sha256']), 'package_pin')
        members = package['members']
        need(type(members) is list and 1 <= len(members) <= 32, 'member_count')
        sources = set()
        for member in members:
            need(type(member) is dict and set(member) == {'source','destination','bytes','sha256','kind'}, 'member_shape')
            source, destination = _name(member['source']), _name(member['destination'])
            need(source.startswith('usr/') and source not in sources, 'member_source')
            need(member['destination'] == destination and destination not in destinations, 'member_destination')
            kind = member['kind']
            need(type(kind) is str and kind in KINDS, 'member_kind')
            prefix = 'mit/licenses/' if kind == 'notice' else 'mit/bin/' if kind == 'executable' else 'mit/lib/'
            need(destination.startswith(prefix) and _integer(member['bytes'], 1, 262144 if kind == 'notice' else MAX_MEMBER_BYTES) and _sha(member['sha256']), 'member_pin')
            sources.add(source); destinations.add(destination); total += member['bytes']
        names.add(name); filenames.add(filename)
    need(len(destinations) <= 128 and total <= MAX_BUNDLE_BYTES, 'bundle_bound')
    return value

def load_lock(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 131072 and digest(raw) == LOCK_SHA256, 'lock_digest')
    try:
        value = json.loads(raw, object_pairs_hook=_unique)
    except (UnicodeError, json.JSONDecodeError):
        raise BundleError('lock_json') from None
    return _validate_lock(value)

def _ar_members(raw):
    need(type(raw) is bytes and 8 <= len(raw) <= MAX_PACKAGE_BYTES and raw[:8] == b'!<arch>\n', 'ar_envelope')
    offset, members = 8, {}
    while offset < len(raw):
        need(len(members) < 3 and offset+60 <= len(raw), 'ar_header')
        header = raw[offset:offset+60]
        need(header[58:] == b'`\n', 'ar_header')
        try:
            name = header[:16].decode('ascii').strip().rstrip('/')
            size_text = header[48:58].decode('ascii').strip()
        except UnicodeError:
            raise BundleError('ar_header') from None
        need(name in {'debian-binary','control.tar.zst','data.tar.zst'} and name not in members and re.fullmatch('[0-9]{1,10}', size_text), 'ar_header')
        size = int(size_text); offset += 60
        need(0 < size <= MAX_PACKAGE_BYTES and offset+size <= len(raw), 'ar_size')
        members[name] = raw[offset:offset+size]; offset += size
        if size % 2:
            need(offset < len(raw) and raw[offset:offset+1] == b'\n', 'ar_padding')
            offset += 1
    need(offset == len(raw) and set(members) == {'debian-binary','control.tar.zst','data.tar.zst'} and members['debian-binary'] == b'2.0\n', 'deb_members')
    return members

def _decompress(raw):
    try:
        decoder = ZstdDecompressor(options={DecompressionParameter.window_log_max:25})
        data = decoder.decompress(raw, MAX_TAR_BYTES+1)
        need(len(data) <= MAX_TAR_BYTES and decoder.eof and not decoder.unused_data, 'compressed_bound')
        return data
    except BundleError:
        raise
    except Exception:
        raise BundleError('compressed_data') from None

def _package_members(raw, package):
    need(type(raw) is bytes and len(raw) == package['bytes'] and digest(raw) == package['sha256'], 'package_digest')
    data = _decompress(_ar_members(raw)['data.tar.zst'])
    selected = {_name(m['source']): m for m in package['members']}
    seen, found, total = set(), {}, 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
            for item in archive:
                need(len(seen) < 512 and not item.pax_headers and item.sparse is None, 'tar_metadata')
                if item.name in ('.','./') and item.isdir():
                    name = '.'
                else:
                    name = _name(item.name)
                need(name not in seen and item.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE, tarfile.SYMTYPE), 'tar_member')
                seen.add(name); total += item.size
                need(_integer(item.size, 0, MAX_MEMBER_BYTES) and total <= MAX_TAR_BYTES, 'tar_bound')
                if name not in selected:
                    continue
                pin = selected[name]
                need(item.type in (tarfile.REGTYPE,tarfile.AREGTYPE) and item.size == pin['bytes'], 'selected_member')
                stream = archive.extractfile(item)
                need(stream is not None, 'selected_member')
                raw_member = stream.read(pin['bytes']+1)
                need(len(raw_member) == pin['bytes'] and digest(raw_member) == pin['sha256'], 'member_digest')
                if pin['kind'] != 'notice':
                    need(len(raw_member) >= 64 and raw_member[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H',raw_member,16)[0] in (2,3) and struct.unpack_from('<H',raw_member,18)[0] == 62, 'elf_platform')
                found[pin['destination']] = raw_member
            need(not archive.pax_headers and len(data)-archive.offset >= 1024 and not any(data[archive.offset:]), 'tar_trailer')
    except BundleError:
        raise
    except Exception:
        raise BundleError('tar_data') from None
    need(set(found) == {m['destination'] for m in package['members']}, 'missing_member')
    return found

def extract_bundle(lock_raw, package_bytes):
    lock = load_lock(lock_raw)
    need(type(package_bytes) is dict and set(package_bytes) == {p['filename'] for p in lock['packages']}, 'bundle_inputs')
    output = {}
    for package in lock['packages']:
        members = _package_members(package_bytes[package['filename']], package)
        need(not set(output).intersection(members), 'bundle_overlap')
        output.update(members)
    need(sum(map(len,output.values())) <= MAX_BUNDLE_BYTES, 'bundle_bound')
    return output
