"""Independent Internxt JWT rotation, encrypted shard and authority contracts."""
import base64
import hashlib
import hmac
import http.client
import json
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.parse
LAB=Path(__file__).resolve().parents[1]/"provider-lab"
sys.path.insert(0,str(LAB))
try:
    import fixture_internxt as C
    import fixture_tls as T
finally:sys.path.pop(0)
API="gateway.internxt.com";CONTENT="synthetic-content.internxt.invalid"
ROOT="11111111-1111-4111-8111-111111111111";NESTED="22222222-2222-4222-8222-222222222222"
BUCKET="00112233445566778899aabb"
BASIC="Basic "+base64.b64encode(("synthetic-bridge:"+hashlib.sha256(b"synthetic-user").hexdigest()).encode()).decode()
PAYLOADS={"README-synthetic.txt":b"Synthetic provider protocol fixture. No account or user data.\n",
          "nested/bytes.bin":bytes(range(256))*8,"nested/space name.txt":b"Nested synthetic payload.\n"}
CIPHER_SHA={"README-synthetic.txt":"cf1c954ac72a464194f874cd1f264e9539f6badc96d87fc0c431da6ac1cdcbb5",
            "nested/bytes.bin":"f241b5c346e6f7eba96478f0b67ce8210eb021ce1cf753b1a893901cd828293d",
            "nested/space name.txt":"5190036ee3db40e540f0a807f86ecb7407f837eeb85d52c5dac012438a59ce90"}

class InternxtWireTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.state=C.InternxtState("synthetic-secret")
        self.certificates=self.enterContext(T.FixtureCertificates.create(self.root))
        self.transport=self.enterContext(T.BoundedHttpsServer(self.certificates,C.InternxtHandler,state=self.state))

    def request(self,method,path,host=API,auth=True,body=None,headers=(),raw=None):
        client=http.client.HTTPSConnection("127.0.0.1",self.transport.port,timeout=3,context=self.certificates.client_context())
        data=json.dumps(body,separators=(",",":")).encode() if body is not None else (raw or b"")
        try:
            client.putrequest(method,path,skip_host=True,skip_accept_encoding=True)
            client.putheader("Host",host)
            if auth is True:client.putheader("Authorization","Bearer "+self.state.current)
            elif isinstance(auth,str):client.putheader("Authorization",auth)
            if data:
                client.putheader("Content-Type","application/json")
                client.putheader("Content-Length",str(len(data)))
            for key,value in headers:client.putheader(key,value)
            client.endheaders(data);response=client.getresponse()
            return response.status,dict(response.getheaders()),response.read(65537)
        finally:client.close()

    def refresh(self):
        result=self.request("GET","/drive/users/cli/refresh",headers=(("internxt-client","rclone-adapter"),))
        self.assertEqual(result[0],200);return json.loads(result[2])

    def listing(self,directory="",kind="files"):
        if not self.state.sequence:self.refresh()
        parent=NESTED if directory else ROOT
        return self.request("GET","/drive/folders/v2/content/"+parent+"/"+kind+"?limit=1000&order=ASC")

    def issue(self,name="README-synthetic.txt"):
        self.assertEqual(self.listing("nested" if "/" in name else "")[0],200)
        meta=self.state.metadata(name)
        result=self.request("GET","/network/buckets/"+BUCKET+"/files/"+meta["fileId"]+"/info",
                            auth=BASIC,headers=(("internxt-version","1.0"),))
        self.assertEqual(result[0],200);info=json.loads(result[2])
        self.assertEqual((info["bucket"],info["size"],info["version"]),(BUCKET,len(PAYLOADS[name]),1))
        url=urllib.parse.urlsplit(info["shards"][0]["url"])
        self.assertEqual((url.scheme,url.netloc,url.query),("https",CONTENT,""))
        return url.path,info

    def test_refresh_requires_exact_token_and_returns_no_data_on_denial(self):
        for auth in (None,"Bearer wrong","Basic wrong","Bearer "+self.state.current+" "):
            self.assertEqual(self.request("GET","/drive/users/cli/refresh",auth=auth,
                headers=(("internxt-client","rclone-adapter"),))[0],403)
        self.assertEqual((self.state.sequence,self.state.payload_bytes,self.state.denied),(0,0,4))

    def test_rotation_is_fresh_and_predecessor_cannot_be_reused(self):
        old=self.state.current;first=self.refresh();second=self.refresh()
        self.assertNotEqual(first["newToken"],second["newToken"]);self.assertNotEqual(old,first["newToken"])
        self.assertEqual(self.state.rotations,[(old,first["newToken"]),(first["newToken"],second["newToken"])])
        self.assertEqual(second["user"],{"rootFolderId":ROOT,"bucket":BUCKET,"bridgeUser":"synthetic-bridge","userId":"synthetic-user"})
        self.assertEqual(self.request("GET","/drive/users/cli/refresh",auth="Bearer "+first["newToken"],
            headers=(("internxt-client","rclone-adapter"),))[0],403)

    def test_rotated_jwt_binds_future_expiry_subject_generation_and_signature(self):
        for sequence in (1,2):
            token=self.refresh()["newToken"];head,payload,signature=token.split(".")
            decode=lambda v:base64.urlsafe_b64decode(v+"="*((-len(v))%4))
            self.assertEqual(json.loads(decode(head)),{"alg":"HS256","typ":"JWT"})
            self.assertEqual(json.loads(decode(payload)),{"exp":self.state.expiry,"sub":"synthetic-user","jti":str(sequence)})
            self.assertEqual(decode(signature),hmac.new(b"synthetic-secret",(head+"."+payload).encode(),hashlib.sha256).digest())

    def test_refresh_requires_native_method_path_header_and_empty_body(self):
        for method,path,headers,raw in (
            ("GET","/drive/users/cli/refresh",(),None),
            ("GET","/drive/users/refresh",(("internxt-client","rclone-adapter"),),None),
            ("GET","/drive/users/cli/refresh?extra=1",(("internxt-client","rclone-adapter"),),None),
            ("POST","/drive/users/cli/refresh",(("internxt-client","rclone-adapter"),),b"{}"),
            ("GET","/drive/users/cli/refresh",(("internxt-client","wrong"),),None),
            ("GET","/drive/users/cli/refresh",(("internxt-client","rclone-adapter"),("Range","bytes=0-1")),None)):
            self.assertEqual(self.request(method,path,headers=headers,raw=raw)[0],400)
        self.assertEqual(self.state.sequence,0)

    def test_inventory_requires_observed_startup_rotation(self):
        self.assertEqual(self.request("GET","/drive/folders/v2/content/"+ROOT+"/files?limit=1000&order=ASC")[0],400)
        self.assertEqual(self.state.observed,set())

    def test_complete_inventory_preserves_names_extensions_sizes_and_ids(self):
        for directory,names in (("",["README-synthetic.txt"]),("nested",["nested/bytes.bin","nested/space name.txt"])):
            status,_,raw=self.listing(directory);self.assertEqual(status,200)
            rows=json.loads(raw);self.assertEqual(rows["nextCursor"],"");self.assertEqual(len(rows["files"]),len(names))
            for row,name in zip(rows["files"],names):
                leaf=name.rsplit("/",1)[-1];stem,_,ext=leaf.rpartition(".")
                self.assertEqual((row["plainName"],row["type"],row["size"],row["bucket"],row["folderUuid"],row["status"]),
                    (stem,ext,len(PAYLOADS[name]),BUCKET,NESTED if directory else ROOT,"EXISTS"))
                self.assertEqual(row["modificationTime"],"2024-01-01T00:00:00Z")
                self.assertRegex(row["uuid"],r"^[0-9a-f-]{36}$")
        status,_,raw=self.listing(kind="folders");self.assertEqual(status,200)
        self.assertEqual([(v["uuid"],v["plainName"],v["parentUuid"]) for v in json.loads(raw)["folders"]],[(NESTED,"nested",ROOT)])
        self.assertEqual(json.loads(self.listing("nested","folders")[2])["folders"],[])
        self.assertEqual(self.state.observed,set(PAYLOADS))

    def test_inventory_query_aliases_and_unknown_folders_rejected(self):
        self.refresh();path="/drive/folders/v2/content/"+ROOT+"/files"
        for query in ("","?limit=50&order=ASC","?limit=1000&order=DESC","?limit=1000&order=ASC&cursor=x","?limit=1000&limit=1000&order=ASC"):
            self.assertEqual(self.request("GET",path+query)[0],400)
        self.assertEqual(self.request("GET",path.replace(ROOT,NESTED.replace("2","3"))+"?limit=1000&order=ASC")[0],404)

    def test_existence_checks_distinguish_missing_and_observed_metadata(self):
        self.refresh();path="/drive/folders/content/"+ROOT+"/files/existence"
        rows=[{"plainName":"README-synthetic","type":"txt","originalFile":{}},{"plainName":"missing","type":"txt","originalFile":{}}]
        status,_,raw=self.request("POST",path,body={"files":rows});self.assertEqual(status,200)
        result=json.loads(raw)["existentFiles"]
        self.assertEqual([r["exists"] for r in result],[True,False]);self.assertEqual(result[1]["uuid"],"")
        status,_,raw=self.request("GET","/drive/files/"+result[0]["uuid"]+"/meta")
        self.assertEqual(status,200);self.assertEqual(json.loads(raw)["size"],62)
        self.assertEqual(self.state.observed,{"README-synthetic.txt"})

    def test_malformed_existence_bodies_do_not_grant_observation(self):
        self.refresh();path="/drive/folders/content/"+ROOT+"/files/existence"
        item={"plainName":"README-synthetic","type":"txt","originalFile":{}}
        for body in ({},[],{"files":[]},{"files":[item]*4},{"files":[dict(item,extra=1)]},{"files":[dict(item,plainName="../x")]},{"files":[dict(item,originalFile=None)]}):
            self.assertEqual(self.request("POST",path,body=body)[0],400)
        for raw in (b'{"files":[],"files":[]}',b'NaN',b'['):
            self.assertEqual(self.request("POST",path,raw=raw)[0],400)
        self.assertEqual(self.state.observed,set())

    def test_bucket_info_requires_observed_file_exact_basic_auth_and_version(self):
        self.refresh();fileid="synthetic-"+self.state.ids["README-synthetic.txt"]
        path="/network/buckets/"+BUCKET+"/files/"+fileid+"/info"
        self.assertEqual(self.request("GET",path,auth=BASIC,headers=(("internxt-version","1.0"),))[0],400)
        self.listing()
        for auth,headers in ((True,(("internxt-version","1.0"),)),(None,(("internxt-version","1.0"),)),(BASIC,())):
            self.assertIn(self.request("GET",path,auth=auth,headers=headers)[0],(400,403))
        self.assertEqual(self.state.links,{})

    def test_issued_shards_are_fresh_file_bound_and_reject_auth_leakage(self):
        first,_=self.issue();second,_=self.issue();self.assertNotEqual(first,second)
        for path in (first.replace(self.state.ids["README-synthetic.txt"],self.state.ids["nested/bytes.bin"]),first.rsplit("/",1)[0]+"/"+"f"*32,first+"?extra=1"):
            self.assertEqual(self.request("GET",path,host=CONTENT,auth=None)[0],400)
        for headers in ((("Authorization",BASIC),),(("Cookie","secret"),),(("internxt-client","rclone-adapter"),),(("internxt-version","1.0"),)):
            self.assertEqual(self.request("GET",first,host=CONTENT,auth=None,headers=headers)[0],400)
        self.assertEqual(self.state.payload_bytes,0)

    def test_ciphertext_matches_literal_vectors_and_preserves_plaintext(self):
        for name,data in PAYLOADS.items():
            target,info=self.issue(name);status,_,ciphertext=self.request("GET",target,host=CONTENT,auth=None)
            self.assertEqual(status,200);self.assertEqual(len(ciphertext),len(data));self.assertNotEqual(ciphertext,data)
            self.assertEqual(hashlib.sha256(ciphertext).hexdigest(),CIPHER_SHA[name])
            self.assertEqual(info["shards"][0]["hash"],hashlib.new("ripemd160",hashlib.sha256(ciphertext).digest()).hexdigest())
        self.assertEqual(self.state.files,PAYLOADS)

    def test_http_denial_contains_the_same_valid_ciphertext(self):
        target,_=self.issue();good=self.request("GET",target,host=CONTENT,auth=None)[2]
        before=self.state.payload_bytes;self.state.mode="read_denied"
        self.assertEqual(self.request("GET",target,host=CONTENT,auth=None)[::2],(403,good))
        self.assertEqual((self.state.read_denied,self.state.payload_bytes),(1,before))

    def test_ranges_return_exact_encrypted_offsets_and_reject_invalid_forms(self):
        target,_=self.issue("nested/bytes.bin")
        status,h,raw=self.request("GET",target,host=CONTENT,auth=None,headers=(("Range","bytes=16-31"),))
        self.assertEqual((status,h["Content-Range"],raw),(206,"bytes 16-31/2048",bytes.fromhex("aa47c3cfe1618452a96dafe2de1e6ddb")))
        for value,status in (("bytes=-2",400),("bytes=7-1",416),("bytes=2048-",416),("bytes=0-1,4-5",400)):
            self.assertEqual(self.request("GET",target,host=CONTENT,auth=None,headers=(("Range",value),))[0],status)

    def test_direct_delete_guard_preserves_source_and_requires_no_range(self):
        target,_=self.issue()
        self.assertEqual(self.request("DELETE",target,host=CONTENT,auth=None,headers=(("Range","bytes=0-1"),))[0],400)
        self.assertEqual(self.request("DELETE",target,host=CONTENT,auth=None)[0],405)
        self.assertEqual((self.state.rejected_mutations,self.state.payload_bytes),(1,0));self.assertEqual(self.state.files,PAYLOADS)

    def test_authority_route_and_sni_bindings_are_exact(self):
        for host in (API.upper(),API+":443",API+".","127.0.0.1",CONTENT):
            self.assertEqual(self.request("GET","/drive/users/cli/refresh",host=host,headers=(("internxt-client","rclone-adapter"),))[0],400)
        with patch.object(self.transport,"_server_name",CONTENT):
            self.assertEqual(self.request("GET","/drive/users/cli/refresh",headers=(("internxt-client","rclone-adapter"),))[0],400)

    def test_duplicate_headers_framing_and_target_aliases_rejected(self):
        for headers in ((("Host",API),),(("Authorization","Bearer x"),),(("Content-Length","00"),),(("Content-Length","4097"),),(("Transfer-Encoding","chunked"),),(("Cookie","x"),)):
            self.assertEqual(self.request("GET","/drive/users/cli/refresh",headers=headers+(("internxt-client","rclone-adapter"),))[0],400)
        for method,path in (("PUT","/drive/files"),("HEAD","/drive/users/cli/refresh"),("GET","https://elsewhere.invalid/"),("GET","//drive/users/cli/refresh"),("GET","/drive/users/cli/refre%73h"),("GET","/drive/users/cli/refresh#fragment")):
            self.assertEqual(self.request(method,path,headers=(("internxt-client","rclone-adapter"),))[0],400)

    def test_request_response_and_deadline_limits_cannot_pass(self):
        self.refresh();self.state.request_limit=self.state.requests+1
        self.assertEqual(self.listing()[0],200);self.assertEqual(self.listing()[0],429);self.assertTrue(self.state.budget_exceeded)
        self.state.request_limit=100;self.state.byte_limit=1;self.assertEqual(self.listing()[0],429)
        self.state.deadline=0;self.assertEqual(self.listing()[0],429)

    def test_tls_deadline_closes_partial_headers_and_cleans_up(self):
        timer=threading.Timer
        with T.FixtureCertificates.create(self.root) as certificates,patch.object(
                T.threading,"Timer",side_effect=lambda delay,callback:timer(delay+0.3,callback)):
            with T.BoundedHttpsServer(certificates,C.InternxtHandler,state=C.InternxtState("synthetic"),
                    limits=T.TlsLimits(request_seconds=0.15)) as transport:
                with socket.create_connection(("127.0.0.1",transport.port),timeout=2) as raw:
                    with certificates.client_context().wrap_socket(raw,server_hostname="127.0.0.1") as client:
                        client.sendall(("GET / HTTP/1.1\r\nHost: "+API).encode());self.assertEqual(client.recv(1),b"")
            self.assertIn("tls_request_deadline",transport.snapshot()["failure_codes"]);self.assertTrue(transport.cleanup_complete)
        self.assertTrue(certificates.cleanup_complete)

class InternxtAuthorityTests(unittest.TestCase):
    def test_two_reviewed_names_have_exact_sni_and_single_san(self):
        from cryptography import x509
        for name,callback in ((API,T._internxt_api_sni),(CONTENT,T._internxt_content_sni)):
            with tempfile.TemporaryDirectory() as directory:
                with T.FixtureCertificates.create(Path(directory).resolve(),server_name=name) as certificates:
                    leaf=x509.load_pem_x509_certificate((certificates.directory/"leaf.pem").read_bytes())
                    self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value),[x509.DNSName(name)])
            self.assertIsNone(callback(None,name,None))
            for other in {None,"","127.0.0.1",name+".",name+":443",API,CONTENT}-{name}:
                self.assertEqual(callback(None,other,None),ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)

    def test_two_private_addresses_are_linux_only_without_port_fallback(self):
        for name,address in ((API,"127.0.0.1"),(CONTENT,"127.0.0.2")):
            calls=[]
            def init(server,location,handler):calls.append(location);server.server_address=location
            with patch.object(T.HTTPServer,"__init__",init),patch.object(T.sys,"platform","linux"):
                server=T._HttpServer(SimpleNamespace(_server_name=name),object,None);self.assertEqual(server.authority,name)
            self.assertEqual(calls,[(address,443)])
            with patch.object(T.HTTPServer,"__init__") as bind,patch.object(T.sys,"platform","win32"):
                with self.assertRaisesRegex(T.TlsError,"requires_linux"):T._HttpServer(SimpleNamespace(_server_name=name),object,None)
                bind.assert_not_called()

if __name__=="__main__":unittest.main()
