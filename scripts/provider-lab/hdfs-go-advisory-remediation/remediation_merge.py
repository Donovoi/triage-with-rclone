"""Transfer only verified new module-cache files inside one owned context."""
from __future__ import annotations
import hashlib,os
from audit_contract import need
import remediation_bundle as BUNDLE
from remediation_worker import validate_status

PREFIX='module-cache/cache/download/'
def sha(raw):return hashlib.sha256(raw).hexdigest()

def merge_prepared(C,R,B,context,root,lock,expected_tree):
 need(context.is_absolute() and root==context/'remediation','remediation_merge_path')
 context_id=C.directory(context);root_id=C.directory(root)
 C.directory(context/'module-cache');C.directory(context/'module-cache/cache/download')
 verified=BUNDLE.verify_prepared(B,root,lock,C.read)
 need(type(expected_tree) is dict and set(expected_tree)==set(verified)|{'prepared.json','worker-status.json'}
  and all(expected_tree.get(k)==v for k,v in verified.items()),'remediation_merge_tree')
 prepared_raw=C.read(root/'prepared.json',4096);status_raw=C.read(root/'worker-status.json',2048)
 need(sha(prepared_raw)==expected_tree['prepared.json'] and sha(status_raw)==expected_tree['worker-status.json'],
  'remediation_merge_reports')
 BUNDLE.validate_prepared(C.parse(prepared_raw,4096))
 status=validate_status(C.parse(status_raw,2048));need(status['phase']=='complete','remediation_merge_worker')
 need(R.tree_hashes(C,root)==expected_tree,'remediation_merge_tree')
 cache_keys=sorted(k for k in verified if k.startswith(PREFIX));need(len(cache_keys)==47,'remediation_merge_inventory')
 plan=[]
 for relative in cache_keys:
  source=root/relative;target=context/relative
  C.regular(source,64*1024*1024)
  need(not target.exists() and not target.is_symlink(),'remediation_cache_collision')
  for parent in target.parents:
   if parent==context:break
   need(context in parent.parents,'remediation_merge_path')
   if parent.exists() or parent.is_symlink():C.directory(parent)
  else:need(False,'remediation_merge_path')
  plan.append((relative,source,target))
 total=0
 for relative,source,target in plan:
  C.directory(context,context_id);C.directory(root,root_id)
  raw=C.read(source,64*1024*1024);need(sha(raw)==verified[relative],'remediation_cache_changed')
  total+=len(raw);need(total<=64*1024*1024,'remediation_cache_size')
  target.parent.mkdir(parents=True,exist_ok=True,mode=0o700);C.directory(target.parent)
  fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  with os.fdopen(fd,'wb') as stream:stream.write(raw)
  need(sha(C.read(target,64*1024*1024))==verified[relative],'remediation_cache_changed')
 need(R.tree_hashes(C,root)==expected_tree,'remediation_cache_changed')
 for relative,source,target in plan:
  C.regular(source,64*1024*1024)
  need(sha(C.read(source,64*1024*1024))==verified[relative]
   and sha(C.read(target,64*1024*1024))==verified[relative],'remediation_cache_changed')
  source.unlink()
 remaining={k:v for k,v in expected_tree.items() if not k.startswith(PREFIX)}
 C.directory(context,context_id);C.directory(root,root_id)
 need(R.tree_hashes(C,root)==remaining and len(remaining)==38,'remediation_merge_tree')
 return dict(schema_version=1,scope='owned_remediation_cache_transfer',cache_files=len(plan),cache_bytes=total,
  cache_sha256={k:verified[k] for k in cache_keys},source_files_before=len(expected_tree),source_files_after=len(remaining),
  source_assets_preserved=True,source_cache_removed=True,module_resolution_verified=False,native_build_verified=False)
