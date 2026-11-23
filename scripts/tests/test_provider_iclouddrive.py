"""Independent iCloud saved-cookie discovery, inventory and download contracts."""
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
    import fixture_iclouddrive as C
    import fixture_tls as T
finally:sys.path.pop(0)
SETUP="setup.icloud.com"
DRIVE="synthetic-drive.icloud.invalid"
DOCS="synthetic-docs.icloud.invalid"
CONTENT="synthetic-content.icloud.invalid"
COOKIE="X-APPLE-WEBAUTH-TOKEN=synthetic-cookie"
ZONE="com.apple.CloudDocs"
ROOT="FOLDER::"+ZONE+"::root"
FOLDERS={"":ROOT,"nested":"FOLDER::"+ZONE+"::synthetic-3510"}
FILES={"README-synthetic.txt":"synthetic-3501","nested/bytes.bin":"synthetic-3502","nested/space name.txt":"synthetic-3503"}
PAYLOADS={"README-synthetic.txt":b"Synthetic provider protocol fixture. No account or user data.\n",
          "nested/bytes.bin":bytes(range(256))*8,"nested/space name.txt":b"Nested synthetic payload.\n"}
STAMP="2024-01-01T00:00:00Z"

class IclouddriveWireTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.state=C.IclouddriveState(COOKIE)
        self.certificates=self.enterContext(T.FixtureCertificates.create(self.root))
        self.transport=self.enterContext(T.BoundedHttpsServer(self.certificates,C.IclouddriveHandler,state=self.state))

    def request(self,method,path,host=SETUP,cookie=COOKIE,body=None,headers=(),raw=None):
        client=http.client.HTTPSConnection("127.0.0.1",self.transport.port,timeout=3,context=self.certificates.client_context())
        data=json.dumps(body,separators=(",",":")).encode() if body is not None else (raw or b"")
        try:
            client.putrequest(method,path,skip_host=True,skip_accept_encoding=True)
            for key,value in (("Host",host),("Content-Type","application/json"),("Origin","https://www.icloud.com"),("Referer","https://www.icloud.com/")):
                client.putheader(key,value)
            if cookie is not None:client.putheader("Cookie",cookie)
            if data:client.putheader("Content-Length",str(len(data)))
            for key,value in headers:client.putheader(key,value)
            client.endheaders(data);response=client.getresponse()
            return response.status,dict(response.getheaders()),response.read(65537)
        finally:client.close()

    def validate(self):
        result=self.request("POST","/setup/ws/1/validate")
        self.assertEqual(result[0],200);return json.loads(result[2])

    def listing(self,directory=""):
        if not self.state.validations:self.validate()
        return self.request("POST","/retrieveItemDetailsInFolders",host=DRIVE,
            body=[{"drivewsid":FOLDERS[directory],"partialData":False,"includeHierarchy":False}])

    def issue(self,name="README-synthetic.txt"):
        self.assertEqual(self.listing("nested" if "/" in name else "")[0],200)
        status,_,raw=self.request("GET","/ws/"+ZONE+"/download/by_id?document_id="+FILES[name],host=DOCS,raw=b"null")
        self.assertEqual(status,200);value=json.loads(raw)
        self.assertEqual((value["document_id"],value["item_id"]),(FILES[name],FILES[name]))
        url=urllib.parse.urlsplit(value["data_token"]["url"])
        self.assertEqual((url.scheme,url.netloc,url.query),("https",CONTENT,""))
        return url.path

    def test_validation_requires_exact_saved_cookie(self):
        for cookie in (None,"wrong",COOKIE+"; extra=1"):
            self.assertEqual(self.request("POST","/setup/ws/1/validate",cookie=cookie)[0],403)
        self.assertEqual((self.state.validations,self.state.payload_bytes,self.state.denied),(0,0,3))

    def test_validation_requires_empty_body_and_no_query_or_range(self):
        for method,path,raw,headers in (
            ("POST","/setup/ws/1/validate",b"null",()),
            ("POST","/setup/ws/1/validate?extra=1",None,()),
            ("GET","/setup/ws/1/validate",None,()),
            ("POST","/setup/ws/1/validate",None,(("Range","bytes=0-1"),))):
            self.assertEqual(self.request(method,path,raw=raw,headers=headers)[0],400)
        self.assertEqual(self.state.validations,0)

    def test_discovery_returns_only_reviewed_non_adp_service_authorities(self):
        self.assertEqual(self.validate(),{"dsInfo":{"hsaVersion":2},"hsaChallengeRequired":False,
            "webservices":{"drivews":{"url":"https://"+DRIVE,"status":"active","pcsRequired":False},
                           "docws":{"url":"https://"+DOCS,"status":"active","pcsRequired":False}}})
        self.assertEqual(self.state.validations,1)

    def test_complete_inventories_preserve_literal_metadata_and_scope(self):
        for directory,names in (("",["README-synthetic.txt","nested"]),("nested",["nested/bytes.bin","nested/space name.txt"])):
            status,_,raw=self.listing(directory);self.assertEqual(status,200);rows=json.loads(raw)
            self.assertEqual(len(rows),1);parent=rows[0]
            self.assertEqual((parent["drivewsid"],parent["numberOfItems"],parent["directChildrenCount"]),(FOLDERS[directory],len(names),len(names)))
            self.assertEqual(parent["fileCount"],sum(n in PAYLOADS for n in names))
            expected=[]
            for name in names:
                folder=name in FOLDERS;basename=name.rsplit("/",1)[-1];stem,sep,ext=basename.rpartition(".")
                expected.append({"drivewsid":FOLDERS[name] if folder else "FILE::"+ZONE+"::"+FILES[name],
                    "docwsid":"" if folder else FILES[name],"item_id":FOLDERS[name] if folder else FILES[name],
                    "zone":ZONE,"name":stem if sep else basename,"extension":ext if sep else "",
                    "type":"FOLDER" if folder else "FILE","status":"OK","etag":"synthetic-etag-3500",
                    "dateCreated":STAMP,"dateModified":STAMP,"dateChanged":STAMP,
                    "size":0 if folder else len(PAYLOADS[name]),"parentId":FOLDERS["nested"] if "/" in name else ROOT})
            self.assertEqual(parent["items"],expected)
        self.assertEqual(self.state.observed,set(PAYLOADS))

    def test_service_reads_require_observed_discovery(self):
        self.assertEqual(self.request("POST","/retrieveItemDetailsInFolders",host=DRIVE,
            body=[{"drivewsid":ROOT,"partialData":False,"includeHierarchy":False}])[0],400)
        self.assertEqual(self.state.observed,set())

    def test_inventory_rejects_duplicate_keys_nonboolean_flags_and_other_shapes(self):
        self.validate();item={"drivewsid":ROOT,"partialData":False,"includeHierarchy":False}
        for body in ({},[],[item,item],[dict(item,partialData=0)],[dict(item,includeHierarchy=True)],[dict(item,extra=1)]):
            self.assertEqual(self.request("POST","/retrieveItemDetailsInFolders",host=DRIVE,body=body)[0],400)
        for raw in (b'[{"drivewsid":"x","drivewsid":"y"}]',b'NaN',b'['):
            self.assertEqual(self.request("POST","/retrieveItemDetailsInFolders",host=DRIVE,raw=raw)[0],400)
        self.assertEqual(self.state.observed,set())

    def test_only_exact_folder_ids_are_inventory_roots(self):
        self.validate()
        for id in ("root",ROOT.lower(),"FILE::"+ZONE+"::"+FILES["README-synthetic.txt"],"absent",None):
            self.assertEqual(self.request("POST","/retrieveItemDetailsInFolders",host=DRIVE,
                body=[{"drivewsid":id,"partialData":False,"includeHierarchy":False}])[0],400)

    def test_each_route_is_bound_to_its_issued_authority(self):
        self.validate()
        for host in (DRIVE,DOCS,CONTENT):
            self.assertEqual(self.request("POST","/setup/ws/1/validate",host=host)[0],400)
        for host in (SETUP,DOCS,CONTENT):
            self.assertEqual(self.request("POST","/retrieveItemDetailsInFolders",host=host,
                body=[{"drivewsid":ROOT,"partialData":False,"includeHierarchy":False}])[0],400)

    def test_download_link_requires_a_file_observed_in_its_folder(self):
        self.validate()
        path="/ws/"+ZONE+"/download/by_id?document_id="
        self.assertEqual(self.request("GET",path+FILES["README-synthetic.txt"],host=DOCS,raw=b"null")[0],400)
        self.listing()
        for id in (FILES["nested/bytes.bin"],"absent",ROOT):
            self.assertEqual(self.request("GET",path+id,host=DOCS,raw=b"null")[0],400)
        self.assertEqual(self.state.links,{})

    def test_download_metadata_requires_native_null_body_and_exact_query(self):
        self.listing();path="/ws/"+ZONE+"/download/by_id?document_id="+FILES["README-synthetic.txt"]
        for raw in (None,b"{}",b"[]",b"false"):
            self.assertEqual(self.request("GET",path,host=DOCS,raw=raw)[0],400)
        for target in (path+"&extra=1",path+"&document_id=x",path.replace("document_id=","id=")):
            self.assertEqual(self.request("GET",target,host=DOCS,raw=b"null")[0],400)
        self.assertEqual(self.state.links,{})

    def test_issued_content_urls_are_fresh_and_bound_to_the_observed_file(self):
        first=self.issue();second=self.issue();self.assertNotEqual(first,second)
        for path in (first.replace("synthetic-3501","synthetic-3502"),first.rsplit("/",1)[0]+"/"+"f"*32,first+"?extra=1"):
            self.assertEqual(self.request("GET",path,host=CONTENT)[0],400)
        self.assertEqual(self.request("GET",first,host=CONTENT,cookie="wrong")[0],403)
        self.assertEqual(self.state.payload_bytes,0)

    def test_three_downloads_match_independent_literal_bytes(self):
        for name,data in PAYLOADS.items():
            self.assertEqual(self.request("GET",self.issue(name),host=CONTENT)[::2],(200,data))
        self.assertEqual(self.state.payload_bytes,sum(map(len,PAYLOADS.values())))
        self.assertEqual(self.state.files,PAYLOADS)

    def test_denial_contains_identical_bytes_without_success_credit(self):
        target=self.issue();self.state.mode="read_denied"
        self.assertEqual(self.request("GET",target,host=CONTENT)[::2],(403,PAYLOADS["README-synthetic.txt"]))
        self.assertEqual((self.state.read_denied,self.state.payload_bytes),(1,0))

    def test_content_ranges_are_bounded_and_invalid_forms_rejected(self):
        target=self.issue("nested/bytes.bin")
        status,h,raw=self.request("GET",target,host=CONTENT,headers=(("Range","bytes=1-7"),))
        self.assertEqual((status,h["Content-Range"],raw),(206,"bytes 1-7/2048",PAYLOADS["nested/bytes.bin"][1:8]))
        for value in ("bytes=-2","bytes=7-1","bytes=2048-","bytes=0-1,4-5"):
            self.assertEqual(self.request("GET",target,host=CONTENT,headers=(("Range",value),))[0],416)

    def test_direct_delete_guard_preserves_source(self):
        self.assertEqual(self.request("DELETE",self.issue(),host=CONTENT)[0],405)
        self.assertEqual((self.state.rejected_mutations,self.state.payload_bytes),(1,0));self.assertEqual(self.state.files,PAYLOADS)

    def test_duplicate_headers_framing_auth_and_authority_aliases_rejected(self):
        for headers in ((("Host",SETUP),),(("Cookie",COOKIE),),(("Content-Length","00"),),
                        (("Content-Length","4097"),),(("Transfer-Encoding","chunked"),),
                        (("Authorization","Bearer x"),),(("Origin","https://elsewhere.invalid"),)):
            self.assertEqual(self.request("POST","/setup/ws/1/validate",headers=headers)[0],400)
        for host in (SETUP.upper(),SETUP+":443",SETUP+".","127.0.0.1"):
            self.assertEqual(self.request("POST","/setup/ws/1/validate",host=host)[0],400)
        with patch.object(self.transport,"_server_name",CONTENT):
            self.assertEqual(self.request("POST","/setup/ws/1/validate")[0],400)
        self.assertEqual(self.state.validations,0)

    def test_unreviewed_mutations_and_target_aliases_rejected(self):
        self.validate()
        for method,path in (("POST","/upload"),("DELETE","/deleteItems"),("PUT","/setup/ws/1/validate"),
                            ("HEAD","/setup/ws/1/validate"),("GET","https://elsewhere.invalid/"),
                            ("POST","//setup/ws/1/validate"),("POST","/setup/ws/%31/validate"),
                            ("POST","/setup/ws/1/validate#fragment")):
            self.assertEqual(self.request(method,path)[0],400)
        self.assertEqual((self.state.payload_bytes,self.state.rejected_mutations),(0,0))

    def test_request_response_and_deadline_limits_cannot_pass(self):
        self.validate();self.state.request_limit=self.state.requests+1
        self.assertEqual(self.listing()[0],200);self.assertEqual(self.listing()[0],429);self.assertTrue(self.state.budget_exceeded)
        self.state.request_limit=10;self.state.byte_limit=1;self.assertEqual(self.listing()[0],429)
        self.state.deadline=0;self.assertEqual(self.listing()[0],429)

    def test_tls_deadline_closes_partial_headers_and_cleans_up(self):
        timer=threading.Timer
        with T.FixtureCertificates.create(self.root) as certificates,patch.object(
                T.threading,"Timer",side_effect=lambda delay,callback:timer(delay+0.3,callback)):
            with T.BoundedHttpsServer(certificates,C.IclouddriveHandler,state=C.IclouddriveState(COOKIE),
                    limits=T.TlsLimits(request_seconds=0.15)) as transport:
                with socket.create_connection(("127.0.0.1",transport.port),timeout=2) as raw:
                    with certificates.client_context().wrap_socket(raw,server_hostname="127.0.0.1") as client:
                        client.sendall(("GET / HTTP/1.1\r\nHost: "+SETUP).encode());self.assertEqual(client.recv(1),b"")
            self.assertIn("tls_request_deadline",transport.snapshot()["failure_codes"]);self.assertTrue(transport.cleanup_complete)
        self.assertTrue(certificates.cleanup_complete)

class IclouddriveAuthorityTests(unittest.TestCase):
    def test_four_reviewed_names_have_exact_sni_and_single_san(self):
        from cryptography import x509
        for name,callback in ((SETUP,T._icloud_setup_sni),(DRIVE,T._icloud_drive_sni),(DOCS,T._icloud_docs_sni),(CONTENT,T._icloud_content_sni)):
            with tempfile.TemporaryDirectory() as directory:
                with T.FixtureCertificates.create(Path(directory).resolve(),server_name=name) as certificates:
                    leaf=x509.load_pem_x509_certificate((certificates.directory/"leaf.pem").read_bytes())
                    self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value),[x509.DNSName(name)])
            self.assertIsNone(callback(None,name,None))
            for other in {None,"","127.0.0.1",name+".",name+":443",SETUP,DRIVE,DOCS,CONTENT}-{name}:
                self.assertEqual(callback(None,other,None),ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)

    def test_four_private_addresses_are_linux_only_without_port_fallback(self):
        for name,address in ((SETUP,"127.0.0.1"),(DRIVE,"127.0.0.2"),(DOCS,"127.0.0.3"),(CONTENT,"127.0.0.4")):
            calls=[]
            def init(server,location,handler):calls.append(location);server.server_address=location
            with patch.object(T.HTTPServer,"__init__",init),patch.object(T.sys,"platform","linux"):
                server=T._HttpServer(SimpleNamespace(_server_name=name),object,None);self.assertEqual(server.authority,name)
            self.assertEqual(calls,[(address,443)])
            with patch.object(T.HTTPServer,"__init__") as bind,patch.object(T.sys,"platform","win32"):
                with self.assertRaisesRegex(T.TlsError,"requires_linux"):T._HttpServer(SimpleNamespace(_server_name=name),object,None)
                bind.assert_not_called()

if __name__=="__main__":unittest.main()
