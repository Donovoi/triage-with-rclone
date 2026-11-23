"""Independent kDrive wire contracts; no live-provider acceptance."""
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
    import fixture_kdrive as C
    import fixture_tls as T
finally:
    sys.path.pop(0)
NAME="api.infomaniak.com"
API="/3/drive/290/files/"
SECRET="synthetic-kdrive-token"
AUTH="Bearer "+SECRET
PAYLOADS={"README-synthetic.txt":b"Synthetic provider protocol fixture. No account or user data.\n",
          "nested/bytes.bin":bytes(range(256))*8,"nested/space name.txt":b"Nested synthetic payload.\n"}
IDS={"README-synthetic.txt":2901,"nested/bytes.bin":2902,"nested/space name.txt":2903}
# Independent libxxhash 0.8.3 XXH3_64bits values over the literal fixture bytes.
XXH3={"README-synthetic.txt":"2ec4e7a4e5accf6b","nested/bytes.bin":"dd420471ff96bd00",
      "nested/space name.txt":"2dbd70e0cc9cbf57"}

class KdriveWireTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.state=C.KdriveState(SECRET)
        self.certificates=self.enterContext(T.FixtureCertificates.create(self.root))
        self.transport=self.enterContext(T.BoundedHttpsServer(self.certificates,C.KdriveHandler,state=self.state))

    def request(self,method,path,auth=AUTH,host=NAME,headers=(),body=b""):
        client=http.client.HTTPSConnection("127.0.0.1",self.transport.port,timeout=3,context=self.certificates.client_context())
        try:
            client.putrequest(method,path,skip_host=True,skip_accept_encoding=True);client.putheader("Host",host)
            if auth is not None:client.putheader("Authorization",auth)
            if body:client.putheader("Content-Length",str(len(body)))
            for key,value in headers:client.putheader(key,value)
            client.endheaders(body);response=client.getresponse()
            return response.status,dict(response.getheaders()),response.read(65537)
        finally:client.close()

    def query(self,recursive=False,**changes):
        value={"limit":"1000","with":"path,hash"}
        if recursive:value["depth"]="unlimited"
        value.update(changes);return urllib.parse.urlencode(value)

    def listing(self,nested=False,recursive=False,query=None,**kwargs):
        return self.request("GET",API+("2910" if nested else "2900")+"/files?"+
                            (self.query(recursive) if query is None else query),**kwargs)

    def target(self,name="README-synthetic.txt"):
        self.assertEqual(self.listing("/" in name)[0],200)
        return "/2/drive/290/files/"+str(IDS[name])+"/download"

    def test_complete_root_inventory_has_typed_metadata_and_xxh3(self):
        status,_,raw=self.listing();self.assertEqual(status,200);value=json.loads(raw)
        self.assertEqual(set(value),{"result","data","cursor","has_more"})
        self.assertEqual((value["result"],value["cursor"],value["has_more"]),("success","",False))
        self.assertEqual([item["name"] for item in value["data"]],["README-synthetic.txt","nested"])
        for item in value["data"]:
            name=item["name"];folder=name=="nested"
            self.assertEqual(item,{"id":2910 if folder else 2901,"name":name,"type":"dir" if folder else "file",
                "path":"/Synthetic/"+name,"status":"active","hash":"" if folder else "xxh3:2ec4e7a4e5accf6b",
                "size":0 if folder else len(PAYLOADS[name]),"visibility":"private","drive_id":290,"depth":1,"created_by":1001,
                "created_at":1704067200,"added_at":1704067200,"last_modified_at":1704067200,"last_modified_by":1001,
                "revised_at":1704067200,"updated_at":1704067200,"mime_type":"" if folder else "application/octet-stream",
                "parent_id":2900,"color":""})

    def test_nested_inventory_preserves_scope_sizes_paths_and_literal_hashes(self):
        status,_,raw=self.listing(nested=True);self.assertEqual(status,200);value=json.loads(raw)
        self.assertEqual((value["cursor"],value["has_more"]),("",False))
        self.assertEqual([x["name"] for x in value["data"]],["bytes.bin","space name.txt"])
        for item,name in zip(value["data"],("nested/bytes.bin","nested/space name.txt")):
            self.assertEqual((item["id"],item["parent_id"],item["path"],item["size"],item["hash"]),
                             (IDS[name],2910,"/Synthetic/"+name,len(PAYLOADS[name]),"xxh3:"+XXH3[name]))
            self.assertIs(type(item["size"]),int)

    def test_recursive_listing_contains_each_descendant_once_and_respects_nested_root(self):
        for nested,expected in ((False,["/Synthetic/README-synthetic.txt","/Synthetic/nested",
                                       "/Synthetic/nested/bytes.bin","/Synthetic/nested/space name.txt"]),
                                (True,["/Synthetic/nested/bytes.bin","/Synthetic/nested/space name.txt"])):
            status,_,raw=self.listing(nested,True);self.assertEqual(status,200)
            self.assertEqual([x["path"] for x in json.loads(raw)["data"]],expected)

    def test_listing_rejects_other_drives_ids_pages_and_incomplete_fields(self):
        for key,value in (("limit","1"),("with","path"),("depth","1"),("cursor","next"),("extra","1")):
            self.assertEqual(self.listing(query=self.query(**{key:value}))[0],400)
        for query in ("",self.query()+"&limit=1000","limit=1000"):
            self.assertEqual(self.listing(query=query)[0],400)
        for path in (API.replace("/290/","/291/")+"2900/files",API+"999/files",API+"2901/files"):
            self.assertEqual(self.request("GET",path+"?"+self.query())[0],400)
        self.assertEqual(self.state.observed,set())

    def test_name_lookup_decodes_space_and_exposes_only_selected_folder(self):
        query=urllib.parse.urlencode({"name":"space name.txt","with":"path,hash"})
        status,_,raw=self.request("GET",API+"2910/name?"+query)
        self.assertEqual(status,200);item=json.loads(raw)["data"]
        self.assertEqual((item["id"],item["path"],item["hash"]),(2903,"/Synthetic/nested/space name.txt",
                                                             "xxh3:2dbd70e0cc9cbf57"))
        self.assertEqual(self.state.observed,{"nested/space name.txt"})
        status,_,raw=self.request("GET",API+"2900/name?"+query)
        self.assertEqual(status,404)
        self.assertEqual(json.loads(raw),{"result":"error","error":{"code":"object_not_found",
                                                                  "description":"synthetic missing member"}})
        self.assertEqual(self.state.missing,1)

    def test_name_lookup_rejects_traversal_ambiguous_query_and_wrong_fields(self):
        for name in ("","..",".","nested/bytes.bin","nested\\bytes.bin","x\x00","x"*161):
            path=API+"2900/name?"+urllib.parse.urlencode({"name":name,"with":"path,hash"})
            self.assertEqual(self.request("GET",path)[0],400)
        for query in ("name=README-synthetic.txt","name=README-synthetic.txt&with=path",
                      "name=a&name=b&with=path%2Chash","name=x&with=path%2Chash&cursor=1"):
            self.assertEqual(self.request("GET",API+"2900/name?"+query)[0],400)
        self.assertEqual(self.state.observed,set())

    def test_metadata_and_download_require_discovery_of_file_identity(self):
        self.assertEqual(self.request("GET",API+"2900?with=path")[0],200)
        self.assertEqual(self.request("GET",API+"2910?with=path")[0],200)
        self.assertEqual(self.request("GET",API+"2901?with=path")[0],400)
        self.assertEqual(self.request("GET","/2/drive/290/files/2901/download")[0],400)
        self.assertEqual(self.listing()[0],200)
        status,_,raw=self.request("GET",API+"2901?with=path");self.assertEqual(status,200)
        self.assertEqual(json.loads(raw)["data"]["id"],2901)
        for query in ("","with=path%2Chash","with=path&extra=1"):
            self.assertEqual(self.request("GET",API+"2901?"+query)[0],400)

    def test_credentials_are_required_for_both_api_and_download(self):
        for auth in (None,SECRET,"Bearer wrong",AUTH+"extra"):
            self.assertEqual(self.listing(auth=auth)[0],401)
        self.assertEqual((self.state.denied,self.state.authenticated,self.state.payload_bytes),(4,0,0))
        self.assertEqual(self.state.observed,set())
        target=self.target()
        self.assertEqual(self.request("GET",target,auth=None)[0],401)
        self.assertEqual(self.request("GET",target,auth="Bearer wrong")[0],401)
        self.assertEqual(self.state.payload_bytes,0)

    def test_all_known_files_download_exactly_with_saved_bearer(self):
        for name,body in PAYLOADS.items():
            self.assertEqual(self.request("GET",self.target(name))[::2],(200,body))
        self.assertEqual(self.state.payload_bytes,sum(map(len,PAYLOADS.values())))
        self.assertEqual(self.state.files,PAYLOADS)

    def test_http403_contains_identical_expected_bytes_without_success_payload(self):
        target=self.target();self.state.mode="read_denied"
        self.assertEqual(self.request("GET",target)[::2],(403,PAYLOADS["README-synthetic.txt"]))
        self.assertEqual((self.state.read_denied,self.state.payload_bytes),(1,0))
        self.assertEqual(self.state.files,PAYLOADS)

    def test_ranges_are_bounded_and_invalid_forms_rejected(self):
        target=self.target("nested/bytes.bin")
        status,h,raw=self.request("GET",target,headers=(("Range","bytes=1-7"),))
        self.assertEqual((status,h["Content-Range"],raw),(206,"bytes 1-7/2048",PAYLOADS["nested/bytes.bin"][1:8]))
        status,h,raw=self.request("GET",target,headers=(("Range","bytes=0-4096"),))
        self.assertEqual((status,h["Content-Range"],raw),(206,"bytes 0-2047/2048",PAYLOADS["nested/bytes.bin"]))
        for value in ("bytes=-2","bytes=7-1","bytes=2048-","bytes=0-1,4-5"):
            self.assertEqual(self.request("GET",target,headers=(("Range",value),))[0],416)

    def test_download_rejects_api_version_queries_and_unknown_id(self):
        target=self.target()
        for bad in (target+"?extra=1",target.replace("/2/","/3/"),target.replace("2901","999"),
                    target.replace("2901","%32%39%30%31"),target.replace("/290/","/291/")):
            self.assertEqual(self.request("GET",bad)[0],400)
        self.assertEqual(self.state.payload_bytes,0)

    def test_direct_delete_guard_requires_discovery_and_preserves_source(self):
        self.assertEqual(self.request("DELETE","/2/drive/290/files/2901/download")[0],400)
        self.assertEqual(self.request("DELETE",self.target())[0],405)
        self.assertEqual((self.state.rejected_mutations,self.state.payload_bytes),(1,0))
        self.assertEqual(self.state.files,PAYLOADS)

    def test_authority_is_exact_and_named_transport_must_match(self):
        for host in (NAME.upper(),NAME+":443",NAME+".","127.0.0.1","user@"+NAME):
            self.assertEqual(self.listing(host=host)[0],400)
        with patch.object(self.transport,"_server_name","api.sugarsync.com"):
            self.assertEqual(self.listing()[0],400)
        self.assertEqual(self.state.observed,set())

    def test_duplicate_headers_framing_cookies_and_metadata_ranges_fail_closed(self):
        for headers in ((("Host",NAME),),(("Authorization",AUTH),),(("Content-Length","00"),),
                        (("Content-Length","4097"),),(("Transfer-Encoding","chunked"),),(("Range","bytes=0-1"),),
                        (("Cookie","private=x"),)):
            self.assertEqual(self.listing(headers=headers)[0],400)
        self.assertEqual(self.listing(body=b"x")[0],400);self.assertEqual(self.state.observed,set())

    def test_account_discovery_oauth_uploads_and_unknown_routes_remain_unqualified(self):
        for method,path in (("GET","/3/drive"),("POST","/oauth2/token"),("POST",API+"2900/upload"),
                            ("PUT",API+"2901"),("HEAD",API+"2900"),("DELETE",API+"2901"),
                            ("GET","https://elsewhere.invalid/"),("GET","//3/drive/290/files/2900"),
                            ("GET",API+"2900/files?with=%zz")):
            self.assertEqual(self.request(method,path)[0],400)
        self.assertEqual((self.state.payload_bytes,self.state.rejected_mutations),(0,0))

    def test_request_response_and_deadline_budgets_cannot_pass(self):
        self.state.request_limit=1;self.assertEqual(self.listing()[0],200);self.assertEqual(self.listing()[0],429)
        self.assertTrue(self.state.budget_exceeded)
        self.state.request_limit=10;self.state.byte_limit=1;self.assertEqual(self.listing()[0],429)
        self.state.deadline=0;self.assertEqual(self.listing()[0],429)

    def test_tls_deadline_stops_partial_headers_and_cleans_up(self):
        timer=threading.Timer
        with T.FixtureCertificates.create(self.root) as certificates, patch.object(
                T.threading,"Timer",side_effect=lambda delay,callback:timer(delay+0.3,callback)):
            with T.BoundedHttpsServer(certificates,C.KdriveHandler,state=C.KdriveState(SECRET),
                    limits=T.TlsLimits(request_seconds=0.15)) as transport:
                with socket.create_connection(("127.0.0.1",transport.port),timeout=2) as raw:
                    with certificates.client_context().wrap_socket(raw,server_hostname="127.0.0.1") as client:
                        client.sendall(("GET "+API+"2900 HTTP/1.1\r\nHost: "+NAME).encode())
                        self.assertEqual(client.recv(1),b"")
            self.assertIn("tls_request_deadline",transport.snapshot()["failure_codes"])
            self.assertTrue(transport.cleanup_complete)
        self.assertTrue(certificates.cleanup_complete)

class KdriveAuthorityTests(unittest.TestCase):
    def test_reviewed_name_has_its_own_exact_sni_and_san(self):
        with tempfile.TemporaryDirectory() as directory:
            with T.FixtureCertificates.create(Path(directory).resolve(),server_name=NAME) as certificates:
                from cryptography import x509
                leaf=x509.load_pem_x509_certificate((certificates.directory/"leaf.pem").read_bytes())
                self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value),
                                 [x509.DNSName(NAME)])
        self.assertIsNone(T._kdrive_sni(None,NAME,None))
        for name in (None,"","fixture.pcloud.com","api.cloudinary.com","127.0.0.1",NAME+".",NAME+":443"):
            self.assertEqual(T._kdrive_sni(None,name,None),ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)
        self.assertEqual(T._pcloud_sni(None,NAME,None),ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)
        self.assertEqual(T._cloudinary_sni(None,NAME,None),ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)

    def test_fixed_port_is_linux_only_and_never_falls_back(self):
        calls=[]
        def init(server,address,handler):
            calls.append(address);server.server_address=address
        with patch.object(T.HTTPServer,"__init__",init),patch.object(T.sys,"platform","linux"):
            server=T._HttpServer(SimpleNamespace(_server_name=NAME),object,None)
            self.assertEqual(server.authority,NAME)
        self.assertEqual(calls,[("127.0.0.1",443)])
        with patch.object(T.HTTPServer,"__init__") as bind,patch.object(T.sys,"platform","win32"):
            with self.assertRaisesRegex(T.TlsError,"requires_linux"):
                T._HttpServer(SimpleNamespace(_server_name=NAME),object,None)
            bind.assert_not_called()

if __name__=="__main__":
    unittest.main()
