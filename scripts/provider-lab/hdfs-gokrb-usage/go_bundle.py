"""Pinned passive assets for the isolated gokrb5 constructor experiment."""
from __future__ import annotations
import base64
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import time
import urllib.parse
import urllib.request
import zipfile

LOCK_SHA = '9fbee50995e6e183d2d3eea5f183638a665ef072a4abe744ff83908f773a6ce4'
MODULE = 'github.com/jcmturner/gokrb5/v8'
VERSION = 'v8.4.4'
GO_VERSION = 'go1.26.10'
MAX_TOTAL = 80 * 1024 * 1024

def need(value):
    if not value: raise ValueError('asset_invalid')

def sha(raw): return hashlib.sha256(raw).hexdigest()

def unique(pairs):
    result={}
    for k,v in pairs:
        need(k not in result);result[k]=v
    return result

def parse(raw):
    need(type(raw) is bytes and len(raw)<=131072)
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('asset_invalid')))

def load_lock(raw):
    need(sha(raw)==LOCK_SHA)
    lock=parse(raw)
    need(set(lock)=={'schema_version','scope','go_version','module','version','assets','original_sources'})
    need(type(lock['schema_version']) is int and lock['schema_version']==1
         and lock['scope']=='gokrb5_constructor_regression' and lock['go_version']==GO_VERSION
         and lock['module']==MODULE and lock['version']==VERSION)
    rows=lock['assets'];need(type(rows) is list and len(rows)==87)
    files=set();identities=set();counts={};total=0
    for r in rows:
        need(type(r) is dict and r['kind'] in ('mod','zip','info','toolchain'))
        expected={'file','kind','url','bytes','sha256','version'}
        if r['kind']!='toolchain':expected|={'module','h1'}
        need(set(r)==expected)
        need(type(r['bytes']) is int and 0<r['bytes']<=66936659
             and re.fullmatch('[a-f0-9]{64}',r['sha256']) and r['file'] not in files)
        if r['kind']=='toolchain':
            need(r['file']=='go-toolchain.tar.gz' and r['version']==GO_VERSION
                 and r['url']=='https://dl.google.com/go/'+GO_VERSION+'.linux-amd64.tar.gz'
                 and r['bytes']==66936659)
        else:
            need(re.fullmatch('module-[0-9]{3}[.](mod|zip|info)',r['file'])
                 and r['file'].endswith('.'+r['kind'])
                 and re.fullmatch('[a-z0-9./_-]+',r['module'])
                 and '..' not in r['module'] and not r['module'].startswith('/')
                 and re.fullmatch('v[0-9][a-z0-9.+-]*',r['version'])
                 and re.fullmatch('h1:[A-Za-z0-9+/]{43}=',r['h1']))
            need(r['url']=='https://proxy.golang.org/'+r['module']+'/@v/'+r['version']+'.'+r['kind'])
            need(r['bytes']<=(16*1024*1024 if r['kind']=='zip' else 1048576 if r['kind']=='mod' else 8192))
            ident=(r['module'],r['version'],r['kind']);need(ident not in identities);identities.add(ident)
        files.add(r['file']);counts[r['kind']]=counts.get(r['kind'],0)+1;total+=r['bytes']
    need(counts=={'mod':54,'zip':16,'info':16,'toolchain':1} and total<=MAX_TOTAL)
    need(set(lock['original_sources'])=={'APReq.go','KDCReq.go'}
         and all(re.fullmatch('[a-f0-9]{64}',v) for v in lock['original_sources'].values()))
    return lock

def verify_asset(raw,row):
    need(type(raw) is bytes and len(raw)==row['bytes'] and sha(raw)==row['sha256'])
    if row['kind']=='mod':
        digest=hashlib.sha256((sha(raw)+'  go.mod\n').encode()).digest()
        need('h1:'+base64.b64encode(digest).decode()==row['h1'])
    if row['kind']=='info':
        value=parse(raw);need(value.get('Version')==row['version'] and type(value.get('Time')) is str)

def module_files(raw,row):
    """Bound decompression and verify Go's published Hash1 before returning bytes."""
    need(row['kind']=='zip');verify_asset(raw,row)
    prefix=row['module']+'@'+row['version']+'/'
    files={};total=0;digest=hashlib.sha256()
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        infos=z.infolist();need(0<len(infos)<=10000)
        need(len({i.filename for i in infos})==len(infos))
        for i in sorted(infos,key=lambda x:x.filename):
            p=PurePosixPath(i.filename);mode=i.external_attr>>16
            need(i.filename.startswith(prefix) and '\\' not in i.filename and '\n' not in i.filename
                 and '\r' not in i.filename and not p.is_absolute() and '..' not in p.parts
                 and '/'.join(p.parts)==i.filename and not i.is_dir() and not i.flag_bits&1
                 and i.compress_type in (0,8) and 0<=i.file_size<=16*1024*1024
                 and stat.S_IFMT(mode) in (0,stat.S_IFREG) and not mode&0o7000)
            total+=i.file_size;need(total<=64*1024*1024)
            with z.open(i) as stream:data=stream.read(i.file_size+1)
            need(len(data)==i.file_size)
            digest.update((sha(data)+'  '+i.filename+'\n').encode())
            files[i.filename[len(prefix):]]=data
    need('h1:'+base64.b64encode(digest.digest()).decode()==row['h1'])
    return files

def inspect_toolchain(raw,row):
    verify_asset(raw,row);names=set();total=0
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
        for i in archive:
            name=i.name.rstrip('/');p=PurePosixPath(name)
            need(len(names)<20000 and name not in names and (name.startswith('go/') or (name=='go' and i.isdir()))
                 and not p.is_absolute() and '..' not in p.parts and '\\' not in name
                 and '/'.join(p.parts)==name and (i.isfile() or i.isdir())
                 and not i.issparse() and not i.mode&0o7000 and 0<=i.size<=64*1024*1024)
            names.add(name);total+=i.size;need(total<=300*1024*1024)
            if i.name=='go/bin/go':
                with archive.extractfile(i) as stream:header=stream.read(20)
                need(header[:6]==b'\x7fELF\x02\x01' and header[18:20]==b'\x3e\x00')
    need(len(names)==16712 and total==232612406 and 'go/bin/go' in names)

class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        parsed=urllib.parse.urlsplit(newurl)
        need(parsed.scheme=='https' and parsed.hostname in ('proxy.golang.org','storage.googleapis.com','dl.google.com')
             and parsed.username is None and parsed.password is None and parsed.port in (None,443))
        return super().redirect_request(req,fp,code,msg,headers,newurl)

def download(context,lock,*,opener=None,clock=time.monotonic):
    opener=opener or urllib.request.build_opener(urllib.request.ProxyHandler({}),Redirect())
    target=context/'assets';target.mkdir(mode=0o700);deadline=clock()+270
    for row in lock['assets']:
        need(clock()<deadline)
        request=urllib.request.Request(row['url'],headers={'User-Agent':'triage-offline-gokrb','Accept-Encoding':'identity'})
        count=0;digest=hashlib.sha256()
        with opener.open(request,timeout=min(20,max(1,int(deadline-clock())))) as response:
            parsed=urllib.parse.urlsplit(response.url)
            need(response.status==200 and parsed.scheme=='https'
                 and parsed.hostname in ('proxy.golang.org','storage.googleapis.com','dl.google.com')
                 and not response.headers.get_all('Content-Encoding',[]))
            lengths=response.headers.get_all('Content-Length',[])
            need(not lengths or lengths==[str(row['bytes'])])
            with (target/row['file']).open('xb') as stream:
                while True:
                    need(clock()<deadline)
                    chunk=response.read(min(65536,row['bytes']-count+1))
                    need(clock()<deadline)
                    if not chunk:break
                    count+=len(chunk);need(count<=row['bytes']);stream.write(chunk);digest.update(chunk)
        need(count==row['bytes'] and digest.hexdigest()==row['sha256'])
    need(clock()<deadline)

def prepare(context,lock,read):
    cache=context/'module-cache/cache/download';cache.mkdir(parents=True,mode=0o700)
    original=context/'original';original.mkdir(mode=0o700)
    for row in lock['assets']:
        raw=read(context/'assets'/row['file'],row['bytes'])
        verify_asset(raw,row)
        if row['kind']=='toolchain':
            inspect_toolchain(raw,row)
            continue
        out=cache/row['module']/'@v'/(row['version']+'.'+row['kind']);out.parent.mkdir(parents=True,exist_ok=True)
        with out.open('xb') as stream:stream.write(raw)
        if row['kind']=='zip':
            files=module_files(raw,row)
            with out.with_suffix('.ziphash').open('xb') as stream:stream.write(row['h1'].encode())
            if row['module']==MODULE and row['version']==VERSION:
                for relative,data in files.items():
                    target=original/relative;target.parent.mkdir(parents=True,exist_ok=True)
                    with target.open('xb') as stream:stream.write(data)
    for name,digest in lock['original_sources'].items():
        need(sha(read(original/'messages'/name,131072))==digest)
    need((original/'go.mod').is_file() and (original/'go.sum').is_file())
