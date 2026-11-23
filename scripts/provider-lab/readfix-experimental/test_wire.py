"""Wire boundary tests; native probes separately verify backend decryption."""
from pathlib import Path
import base64
import hashlib
import http.client
import json
import sys
import threading
import unittest
from types import SimpleNamespace

HERE=Path(__file__).resolve().parent
sys.path[:0]=[str(HERE),str(HERE / "foundation" if (HERE / "foundation").is_dir() else HERE.parent)]
from fixture_read_api import ReadFixture,ReadState
from fixture_filen import FilenState,FilenHandler,API as FILEN_API,CONTENT as FILEN_CONTENT,ROOT,NESTED,REGION,BUCKET,MASTER
from fixture_protondrive import ProtonState,ProtonHandler,API as PROTON_API,CONTENT as PROTON_CONTENT,UID,SHARE
from fixture_filescom import FilesComState,FilesComHandler
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class WireCase(unittest.TestCase):
    def request(self, authority, target, *, headers=None, method="GET", body=None):
        server=ReadFixture(self.state,self.handler)
        if authority:server.transport=SimpleNamespace(_server_name=authority)
        thread=threading.Thread(target=server.handle_request);thread.start()
        connection=http.client.HTTPConnection("127.0.0.1",server.server_port,timeout=3)
        try:
            values={} if authority is None else {"Host":authority}
            values.update(headers or {})
            connection.request(method,target,body=body,headers=values)
            response=connection.getresponse()
            return response.status,response.read()
        finally:
            connection.close();thread.join(5);server.server_close()
            self.assertFalse(thread.is_alive())


class FilenWireTests(WireCase):
    def setUp(self):
        self.state=FilenState("synthetic-wire-key");self.handler=FilenHandler
    def api(self,path="/v3/dir/content",identifier=ROOT,raw=None,token=None):
        body=json.dumps({"uuid":identifier}) if raw is None else raw
        return self.request(FILEN_API,path,method="POST",body=body,headers={
            "Authorization":"Bearer "+(self.state.password if token is None else token),"Content-Type":"application/json"})
    def content(self,headers=None):
        name="README-synthetic.txt"
        return self.request(FILEN_CONTENT,"/"+REGION+"/"+BUCKET+"/"+self.state.ids[name]+"/0",
            headers={"Authorization":"Bearer "+self.state.password,"Content-Type":"application/json",**(headers or {})})
    def test_root_and_nested_metadata_is_encrypted_and_authentic(self):
        derived=hashlib.pbkdf2_hmac("sha512",MASTER.encode(),MASTER.encode(),1,32)
        for identifier in (ROOT,NESTED):
            code,data=self.api(identifier=identifier);self.assertEqual(code,200)
            for file in json.loads(data)["data"]["uploads"]:
                encrypted=file["metadata"];self.assertEqual(encrypted[:3],"002")
                plain=AESGCM(derived).decrypt(encrypted[3:15].encode(),base64.b64decode(encrypted[15:]),None)
                metadata=json.loads(plain)
                self.assertEqual(metadata["size"],file["size"])
                self.assertTrue(metadata["name"])
    def test_recursive_inventory_preserves_wire_types(self):
        code,data=self.api("/v3/dir/download",raw=json.dumps({"uuid":ROOT,"skipCache":""}))
        self.assertEqual(code,200);value=json.loads(data)["data"]
        self.assertEqual(len(value["files"]),3)
        self.assertTrue(all(type(f["size"]) is str and type(f["favorited"]) is bool for f in value["files"]))
    def test_wrong_token_rejected_before_listing(self):
        self.assertEqual(self.api(token="wrong")[0],403);self.assertEqual(self.state.denied,1)
        self.assertEqual(self.state.observed,set())
    def test_duplicate_json_and_extra_fields_rejected(self):
        self.assertEqual(self.api(raw='{"uuid":"'+ROOT+'","uuid":"'+ROOT+'"}')[0],400)
        self.assertEqual(self.api(raw=json.dumps({"uuid":ROOT,"extra":1}))[0],400)
        self.assertEqual(self.state.unexpected,2)
    def test_content_requires_prior_listing_and_rejects_range(self):
        self.assertEqual(self.content()[0],400)
        self.api()
        self.assertEqual(self.content(headers={"Range":"bytes=0-2"})[0],400)
    def test_status_denial_uses_the_valid_ciphertext(self):
        self.api();expected=self.state.ciphertext["README-synthetic.txt"]
        self.assertEqual(self.content(),(200,expected))
        self.state.mode="read_denied";self.assertEqual(self.content(),(403,expected))
        self.assertEqual(self.state.read_denied,1)
    def test_tamper_changes_only_the_ciphertext_tag(self):
        self.api();expected=self.state.ciphertext["README-synthetic.txt"]
        self.state.mode="tampered_ciphertext";code,data=self.content()
        self.assertEqual(code,200);self.assertEqual(data[:-1],expected[:-1])
        self.assertEqual(data[-1],expected[-1]^1);self.assertEqual(self.state.tampered_reads,1)
        self.assertEqual(self.state.ciphertext["README-synthetic.txt"],expected)
    def test_mutation_is_rejected_without_source_changes(self):
        before=dict(self.state.files)
        self.assertEqual(self.api("/v3/file/trash",self.state.ids["README-synthetic.txt"])[0],405)
        self.assertEqual(self.state.files,before);self.assertEqual(self.state.rejected_mutations,1)


class ProtonWireTests(WireCase):
    def setUp(self):
        self.handler=ProtonHandler
        self.state=ProtonState.__new__(ProtonState)
        ReadState.__init__(self.state,"synthetic-wire-key")
        self.state.observed=set();self.state.reject_diagnostics=[];self.state.tampered_reads={}
        self.state.ids={"README-synthetic.txt":"link-file-0"};self.state.names={"link-file-0":"README-synthetic.txt"}
        self.state.ciphertext={"link-file-0":b"synthetic-valid-ciphertext"}
        self.state.data={"user":{"ID":"synthetic-user"},"addresses":[],"volumes":[],
            "share":{"ShareID":SHARE},"share_metadata":{"ShareID":SHARE},
            "links":{"link-file-0":{"LinkID":"link-file-0","ParentLinkID":"link-root","Hash":"a"*64}},
            "revisions":{"link-file-0":{"ID":"revision-link-file-0","Blocks":[{"Hash":"valid-hash","EncSignature":"valid-signature"}]}},
            "wrong_signatures":{"link-file-0":"wrong-plaintext-signature"}}
    def api(self,path,query="",body=None,token=None):
        return self.request(PROTON_API,path+query,method="GET" if body is None else "POST",body=body,
            headers={"Authorization":"Bearer "+(self.state.password if token is None else token),
                     "X-Pm-Uid":UID,"Content-Type":"application/json"})
    def listing(self,page="0"):
        return self.api("/drive/shares/"+SHARE+"/folders/link-root/children",
                        "?Page="+page+"&PageSize=150&ShowAll=1")
    def content(self,token=None):
        return self.request(PROTON_CONTENT,"/blocks/link-file-0",headers={
            "Authorization":"Bearer "+self.state.password,"X-Pm-Uid":UID,
            "Pm-Storage-Token":"block-token-link-file-0" if token is None else token})
    def test_saved_session_user_and_wrong_token(self):
        self.assertEqual(self.api("/core/v4/users")[0],200)
        self.assertEqual(self.api("/core/v4/users",token="wrong")[0],403)
        self.assertEqual(self.state.denied,1)
    def test_listing_pagination_terminates_and_marks_content(self):
        code,data=self.listing();self.assertEqual(code,200)
        self.assertEqual(len(json.loads(data)["Links"]),1)
        self.assertEqual(json.loads(self.listing("1")[1])["Links"],[])
        self.assertEqual(self.state.observed,{"README-synthetic.txt"})
    def test_duplicate_query_rejected(self):
        self.assertEqual(self.api("/core/v4/users","?x=1&x=2")[0],400)
    def test_hash_lookup_distinguishes_present_and_missing(self):
        path="/drive/shares/"+SHARE+"/links/link-root/checkAvailableHashes"
        for value,present in (("a"*64,True),("b"*64,False)):
            code,data=self.api(path,body=json.dumps({"Hashes":[value]}))
            self.assertEqual(code,200);self.assertEqual(json.loads(data)["AvailableHashes"],[] if present else [value])
        self.assertEqual(self.state.missing,1)
    def test_content_requires_listing_and_matching_block_token(self):
        self.assertEqual(self.content()[0],400);self.listing()
        self.assertEqual(self.content(token="wrong")[0],400)
        self.assertEqual(self.state.payload_bytes,0)
    def test_read_denial_uses_the_valid_block(self):
        self.listing();expected=self.state.ciphertext["link-file-0"]
        self.assertEqual(self.content(),(200,expected))
        self.state.mode="read_denied";self.assertEqual(self.content(),(403,expected))
        self.assertEqual(self.state.read_denied,1)
    def test_revision_tamper_does_not_change_saved_metadata(self):
        saved=json.dumps(self.state.data,sort_keys=True)
        path="/drive/shares/"+SHARE+"/files/link-file-0/revisions/revision-link-file-0"
        for mode,field in (("wrong_block_hash","Hash"),("wrong_block_signature","EncSignature")):
            self.state.mode=mode;code,data=self.api(path);self.assertEqual(code,200)
            self.assertNotEqual(json.loads(data)["Revision"]["Blocks"][0][field],self.state.data["revisions"]["link-file-0"]["Blocks"][0][field])
            self.assertEqual(json.dumps(self.state.data,sort_keys=True),saved)
    def test_mutation_is_rejected_without_source_changes(self):
        before=dict(self.state.files)
        path="/drive/shares/"+SHARE+"/folders/link-root/trash_multiple"
        self.assertEqual(self.api(path,body=json.dumps({"LinkIDs":["link-file-0"]}))[0],405)
        self.assertEqual(self.state.files,before);self.assertEqual(self.state.rejected_mutations,1)


class FilesComWireTests(WireCase):
    def setUp(self):
        self.state=FilesComState("synthetic-key");self.handler=FilesComHandler
    def api(self,path,key=None,method="GET",extra=None):
        return self.request(None,path,method=method,headers={
            "X-FilesAPI-Key":self.state.password if key is None else key,**(extra or {})})
    def test_auth_listing_and_missing_object(self):
        self.assertEqual(self.api("/api/rest/v1/folders",key="wrong")[0],401)
        code,data=self.api("/api/rest/v1/folders");self.assertEqual(code,200);self.assertEqual(len(json.loads(data)),2)
        self.assertEqual(self.api("/api/rest/v1/file_actions/metadata/missing.txt")[0],404)
    def test_direct_link_required_before_content(self):
        identifier=self.state.ids["README-synthetic.txt"]
        self.assertEqual(self.api("/content/"+identifier)[0],400)
        code,data=self.api("/api/rest/v1/files/README-synthetic.txt?with_direct_connection_info=true")
        self.assertEqual(code,200);self.assertTrue(json.loads(data)["download_uri"].endswith("/"+identifier))
        self.assertEqual(self.api("/content/"+identifier,extra={"Range":"bytes=3-13"}),(206,self.state.files["README-synthetic.txt"][3:14]))
    def test_http_denial_keeps_the_same_valid_plaintext(self):
        identifier=self.state.ids["README-synthetic.txt"]
        self.api("/api/rest/v1/files/README-synthetic.txt?with_direct_connection_info=true")
        self.state.mode="read_denied"
        self.assertEqual(self.api("/content/"+identifier),(403,self.state.files["README-synthetic.txt"]))
        self.assertEqual(self.state.read_denied,1)
    def test_ambiguous_auth_and_query_rejected(self):
        self.assertEqual(self.api("/api/rest/v1/folders",extra={"Authorization":"Bearer extra"})[0],400)
        self.assertEqual(self.api("/api/rest/v1/folders?x=1&x=2")[0],400)
    def test_native_delete_route_cannot_mutate(self):
        before=dict(self.state.files)
        self.assertEqual(self.api("/api/rest/v1/files/README-synthetic.txt",method="DELETE")[0],405)
        self.assertEqual(self.state.files,before);self.assertEqual(self.state.rejected_mutations,1)


if __name__=="__main__":unittest.main()
