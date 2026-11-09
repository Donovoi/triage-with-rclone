"""Pinned passive assets for full rclone candidate builds."""
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
import urllib.error
import urllib.parse
import urllib.request
import zipfile

LOCK_SHA = 'c21b5c5aee74f44a12eb4607d53fd0857f2e1d8d3d78d5583737c2dc4dace6c0'
MODULE = 'github.com/rclone/rclone'
VERSION = 'v1.75.2'
GO_VERSION = 'go1.26.10'
MAX_TOTAL = 512 * 1024 * 1024

def need(value):
    if not value: raise ValueError('asset_invalid')

def sha(raw): return hashlib.sha256(raw).hexdigest()

def unique(pairs):
    result={}
    for k,v in pairs:
        need(k not in result);result[k]=v
    return result

def parse(raw):
    need(type(raw) is bytes and len(raw)<=1048576)
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('asset_invalid')))

def load_lock(raw):
    need(sha(raw)==LOCK_SHA)
    lock=parse(raw)
    need(set(lock)=={'schema_version','scope','go_version','module','version','assets','original_sources','patch_module','source_commit'})
    need(type(lock['schema_version']) is int and lock['schema_version']==1
         and lock['scope']=='rclone_usage_candidate_build' and lock['go_version']==GO_VERSION
         and lock['module']==MODULE and lock['version']==VERSION
         and lock['source_commit']=='be8d6044eacb843b74d335db0c5fbe09222031fe')
    rows=lock['assets'];need(type(rows) is list and len(rows)==1137)
    files=set();identities=set();counts={};total=0
    escape=lambda s:''.join('!'+c.lower() if 'A'<=c<='Z' else c for c in s)
    for r in rows:
        need(type(r) is dict and r['kind'] in ('mod','zip','info','toolchain'))
        expected={'file','kind','url','bytes','sha256','version'}
        if r['kind']!='toolchain':expected|={'module','h1'}
        need(set(r)==expected)
        need(type(r['bytes']) is int and 0<r['bytes']<=96*1024*1024
             and re.fullmatch('[a-f0-9]{64}',r['sha256']) and r['file'] not in files)
        if r['kind']=='toolchain':
            need(r['file']=='go-toolchain.tar.gz' and r['version']==GO_VERSION
                 and r['url']=='https://dl.google.com/go/'+GO_VERSION+'.linux-amd64.tar.gz'
                 and r['bytes']==66936659)
        else:
            need(re.fullmatch('(module-[0-9]{3}|rclone-source)[.](mod|zip|info)',r['file'])
                 and r['file'].endswith('.'+r['kind'])
                 and re.fullmatch('[A-Za-z0-9./_~-]+',r['module'])
                 and '..' not in r['module'] and not r['module'].startswith('/')
                 and re.fullmatch('v[0-9][A-Za-z0-9.+-]*',r['version'])
                 and re.fullmatch('h1:[A-Za-z0-9+/]{43}=',r['h1']))
            need(r['url']=='https://proxy.golang.org/'+escape(r['module'])+'/@v/'+escape(r['version'])+'.'+r['kind'])
            need(r['bytes']<=(96*1024*1024 if r['kind']=='zip' else 1048576 if r['kind']=='mod' else 16384))
            ident=(r['module'],r['version'],r['kind']);need(ident not in identities);identities.add(ident)
        files.add(r['file']);counts[r['kind']]=counts.get(r['kind'],0)+1;total+=r['bytes']
    need(counts=={'mod':468,'zip':334,'info':334,'toolchain':1} and total<=MAX_TOTAL)
    need(set(lock['original_sources'])=={'go.mod','go.sum','rclone.go','fs/version.go'}
         and all(re.fullmatch('[a-f0-9]{64}',v) for v in lock['original_sources'].values()))
    patch=lock['patch_module']
    need(set(patch)=={'module','version','original_sources'} and patch['module']=='github.com/jcmturner/gokrb5/v8'
         and patch['version']=='v8.4.4' and set(patch['original_sources'])=={'APReq.go','KDCReq.go'}
         and all(re.fullmatch('[a-f0-9]{64}',v) for v in patch['original_sources'].values()))
    return lock

def verify_asset(raw,row):
    need(type(raw) is bytes and len(raw)==row['bytes'] and sha(raw)==row['sha256'])
    if row['kind']=='mod':
        digest=hashlib.sha256((sha(raw)+'  go.mod\n').encode()).digest()
        need('h1:'+base64.b64encode(digest).decode()==row['h1'])
    if row['kind']=='info':
        value=parse(raw);need(value.get('Version')==row['version'] and type(value.get('Time')) is str)

def module_files(raw,row,*,retain=False):
    """Bound decompression and verify Go's published Hash1 before returning bytes."""
    need(row['kind']=='zip');verify_asset(raw,row)
    prefix=row['module']+'@'+row['version']+'/'
    files={};total=0;digest=hashlib.sha256()
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        infos=z.infolist();need(0<len(infos)<=32768)
        need(len({i.filename for i in infos})==len(infos))
        for i in sorted(infos,key=lambda x:x.filename):
            p=PurePosixPath(i.filename);mode=i.external_attr>>16
            need(i.filename.startswith(prefix) and '\\' not in i.filename and '\n' not in i.filename
                 and '\r' not in i.filename and not p.is_absolute() and '..' not in p.parts
                 and '/'.join(p.parts)==i.filename and not i.is_dir() and not i.flag_bits&1
                 and i.compress_type in (0,8) and 0<=i.file_size<=32*1024*1024
                 and stat.S_IFMT(mode) in (0,stat.S_IFREG) and not mode&0o7000)
            total+=i.file_size;need(total<=512*1024*1024)
            with z.open(i) as stream:data=stream.read(i.file_size+1)
            need(len(data)==i.file_size)
            digest.update((sha(data)+'  '+i.filename+'\n').encode())
            if retain:files[i.filename[len(prefix):]]=data
    need('h1:'+base64.b64encode(digest.digest()).decode()==row['h1'])
    return files,dict(members=len(infos),expanded_bytes=total)

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

def retryable_download_error(error):
    if isinstance(error,urllib.error.HTTPError):return error.code in (429,500,502,503,504)
    if isinstance(error,urllib.error.URLError):error=error.reason
    return isinstance(error,(TimeoutError,ConnectionError))

def download(context,lock,*,opener=None,clock=time.monotonic,observer=None,sleeper=time.sleep):
    opener=opener or urllib.request.build_opener(urllib.request.ProxyHandler({}),Redirect())
    target=context/'assets';target.mkdir(mode=0o700);deadline=clock()+570
    observer=observer or (lambda *_:None)
    transferred=0
    for index,row in enumerate(lock['assets']):
        observer('download',index,index)
        need(clock()<deadline)
        request=urllib.request.Request(row['url'],headers={'User-Agent':'triage-offline-gokrb','Accept-Encoding':'identity'})
        for attempt in range(3):
            need(clock()<deadline)
            count=0;digest=hashlib.sha256();created=False;destination=target/row['file']
            try:
                with opener.open(request,timeout=min(20,max(1,int(deadline-clock())))) as response:
                    parsed=urllib.parse.urlsplit(response.url)
                    need(response.status==200 and parsed.scheme=='https'
                         and parsed.hostname in ('proxy.golang.org','storage.googleapis.com','dl.google.com')
                         and not response.headers.get_all('Content-Encoding',[]))
                    lengths=response.headers.get_all('Content-Length',[])
                    need(not lengths or lengths==[str(row['bytes'])])
                    with destination.open('xb') as stream:
                        created=True
                        while True:
                            need(clock()<deadline)
                            chunk=response.read(min(65536,row['bytes']-count+1))
                            need(clock()<deadline)
                            if not chunk:break
                            count+=len(chunk);transferred+=len(chunk)
                            need(count<=row['bytes'] and transferred<=MAX_TOTAL)
                            stream.write(chunk);digest.update(chunk)
                need(count==row['bytes'] and digest.hexdigest()==row['sha256'])
                break
            except (urllib.error.URLError,TimeoutError,ConnectionError) as error:
                if isinstance(error,urllib.error.HTTPError):error.close()
                if not retryable_download_error(error) or attempt==2:raise
                if created:destination.unlink()
                delay=attempt+1
                need(clock()+delay<deadline);sleeper(delay);need(clock()<deadline)
    need(clock()<deadline)
    observer('download',len(lock['assets'])-1,len(lock['assets']))

def prepare(context,lock,read,*,observer=None):
    cache=context/'module-cache/cache/download';cache.mkdir(parents=True,mode=0o700)
    original=context/'original';original.mkdir(mode=0o700)
    patched=context/'patched-gokrb';patched.mkdir(mode=0o700)
    escape=lambda s:''.join('!'+c.lower() if 'A'<=c<='Z' else c for c in s)
    archives=members=expanded=0
    observer=observer or (lambda *_:None)
    for index,row in enumerate(lock['assets']):
        observer('prepare',index,index)
        raw=read(context/'assets'/row['file'],row['bytes'])
        verify_asset(raw,row)
        if row['kind']=='toolchain':
            inspect_toolchain(raw,row);continue
        out=cache/escape(row['module'])/'@v'/(escape(row['version'])+'.'+row['kind']);out.parent.mkdir(parents=True,exist_ok=True)
        with out.open('xb') as stream:stream.write(raw)
        if row['kind']=='zip':
            retain=row['module'] in (MODULE,lock['patch_module']['module'])
            files,stats=module_files(raw,row,retain=retain)
            archives+=1;members+=stats['members'];expanded+=stats['expanded_bytes']
            need(members<=100000 and expanded<=2*1024**3)
            with out.with_suffix('.ziphash').open('xb') as stream:stream.write(row['h1'].encode())
            if retain:
                target_root=original if row['module']==MODULE else patched
                for relative,data in files.items():
                    target=target_root/relative;target.parent.mkdir(parents=True,exist_ok=True)
                    with target.open('xb') as stream:stream.write(data)
    observer('verify_sources',-1,len(lock['assets']))
    for name,digest in lock['original_sources'].items():need(sha(read(original/name,131072))==digest)
    for name,digest in lock['patch_module']['original_sources'].items():need(sha(read(patched/'messages'/name,131072))==digest)
    need(archives==334 and members==71206 and expanded==1387141663)
    return dict(archives=archives,members=members,expanded_bytes=expanded)
