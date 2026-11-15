"""Independent Huawei Drive saved-token global-domain wire contracts."""
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
    import fixture_huaweidrive as C
    import fixture_tls as T
finally:
    sys.path.pop(0)
NAME="driveapis.cloud.huawei.com.cn"
API="/drive/v1"
SECRET="synthetic-huawei-token"
AUTH="Bearer "+SECRET
PAYLOADS={"README-synthetic.txt":b"Synthetic provider protocol fixture. No account or user data.\n",
          "nested/bytes.bin":bytes(range(256))*8,"nested/space name.txt":b"Nested synthetic payload.\n"}
IDS={"README-synthetic.txt":"synthetic-file-3201","nested/bytes.bin":"synthetic-file-3202",
     "nested/space name.txt":"synthetic-file-3203"}
# Independent OpenSSL SHA-256 values over literal payloads.
SHA256={"README-synthetic.txt":"1e901527b93ae84dc9d95a8aa76bbc12d7d77dbf8ab449333c172cfc909c639e",
        "nested/bytes.bin":"10fc3c51a152e90e5b90319b601d92ccf37290ef53c35ff92507687d8a911a08",
        "nested/space name.txt":"e019c52fe70badce27affda5e408659399ff764985f07104029a42ade38125bd"}

class HuaweidriveWireTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.state=C.HuaweidriveState(SECRET)
        self.certificates=self.enterContext(T.FixtureCertificates.create(self.root))
        self.transport=self.enterContext(T.BoundedHttpsServer(self.certificates,C.HuaweidriveHandler,state=self.state))

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

    def query(self,nested=False,**changes):
        folder="synthetic-folder-3210" if nested else "synthetic-folder-3200"
        value={"fields":"*","containers":"drive","pageSize":"1000","queryParam":"'"+folder+"' in parentFolder"}
        value.update(changes);return urllib.parse.urlencode(value)

    def listing(self,nested=False,query=None,**kwargs):
        return self.request("GET",API+"/files?"+(self.query(nested) if query is None else query),**kwargs)

    def target(self,name="README-synthetic.txt"):
        self.assertEqual(self.listing("/" in name)[0],200)
        return API+"/files/"+IDS[name]+"?form=content"

    def test_about_returns_exact_global_domain_without_region_switch(self):
        status,_,raw=self.request("GET",API+"/about?fields=domain")
        self.assertEqual(status,200);self.assertEqual(json.loads(raw),{"domain":NAME})
        self.assertEqual((self.state.about_reads,self.state.payload_bytes),(1,0))
        for path in (API+"/about",API+"/about?fields=*",API+"/about?fields=domain&region=europe",
                     API+"/about?fields=domain&fields=domain"):
            self.assertEqual(self.request("GET",path)[0],400)

    def test_root_and_nested_inventory_have_literal_metadata_sha256_and_scope(self):
        for nested,names in ((False,["README-synthetic.txt","nested"]),(True,["nested/bytes.bin","nested/space name.txt"])):
            status,_,raw=self.listing(nested);self.assertEqual(status,200);value=json.loads(raw)
            self.assertEqual(set(value),{"category","files","nextPageToken"})
            self.assertEqual((value["category"],value["nextPageToken"]),("drive#fileList",""))
            expected=[]
            for name in names:
                folder=name=="nested"
                expected.append({"id":"synthetic-folder-3210" if folder else IDS[name],
                    "fileName":name.rsplit("/",1)[-1],
                    "mimeType":"application/vnd.huawei-apps.folder" if folder else "application/octet-stream",
                    "category":"drive#file","size":0 if folder else len(PAYLOADS[name]),
                    "sha256":"" if folder else SHA256[name],"createdTime":"2024-01-01T00:00:00Z",
                    "editedTime":"2024-01-01T00:00:00Z","editedByMeTime":"2024-01-01T00:00:00Z",
                    "parentFolder":["synthetic-folder-3210" if nested else "synthetic-folder-3200"],
                    "recycled":False,"directlyRecycled":False,"containers":["drive"]})
            self.assertEqual(value["files"],expected)
        self.assertEqual(self.state.observed,set(PAYLOADS))

    def test_listing_rejects_other_parents_filters_cursors_and_fields(self):
        for key,value in (("fields","id"),("containers","applicationData"),("pageSize","1"),("pageSize","1001"),
                          ("queryParam","'other' in parentFolder"),("queryParam","'synthetic-folder-3200' in parentFolder and recycled = false"),
                          ("pageToken",""),("extra","1")):
            self.assertEqual(self.listing(query=self.query(**{key:value}))[0],400)
        self.assertEqual(self.listing(query="")[0],400)
        self.assertEqual(self.listing(query=self.query()+"&pageSize=1000")[0],400)
        self.assertEqual(self.state.observed,set())

    def test_credentials_are_required_for_about_inventory_and_content(self):
        for auth in (None,SECRET,"Bearer wrong",AUTH+"extra"):
            self.assertEqual(self.listing(auth=auth)[0],401)
        self.assertEqual(self.request("GET",API+"/about?fields=domain",auth=None)[0],401)
        self.assertEqual((self.state.authenticated,self.state.payload_bytes,self.state.about_reads),(0,0,0))
        target=self.target()
        self.assertEqual(self.request("GET",target,auth=None)[0],401)
        self.assertEqual(self.request("GET",target,auth="Bearer wrong")[0],401)
        self.assertEqual(self.state.payload_bytes,0)

    def test_content_requires_observed_identity_and_exact_form(self):
        target=API+"/files/synthetic-file-3201?form=content"
        self.assertEqual(self.request("GET",target)[0],400)
        self.assertEqual(self.listing()[0],200)
        for bad in (target.split("?")[0],target.replace("form=content","form=json"),target+"&extra=1",
                    target+"&form=content",target.replace("synthetic-file-3201","synthetic-file-3202")):
            self.assertEqual(self.request("GET",bad)[0],400)
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

    def test_direct_delete_guard_requires_discovery_and_preserves_source(self):
        path=API+"/files/synthetic-file-3201?form=content"
        self.assertEqual(self.request("DELETE",path)[0],400)
        self.assertEqual(self.request("DELETE",self.target())[0],405)
        self.assertEqual((self.state.rejected_mutations,self.state.payload_bytes),(1,0))
        self.assertEqual(self.state.files,PAYLOADS)

    def test_authority_and_named_transport_are_exact(self):
        for host in (NAME.upper(),NAME+":443",NAME+".","127.0.0.1","user@"+NAME,
                     "drive-dre.cloud.dbankcloud.cn"):
            self.assertEqual(self.listing(host=host)[0],400)
        with patch.object(self.transport,"_server_name","api.infomaniak.com"):
            self.assertEqual(self.listing()[0],400)
        self.assertEqual(self.state.observed,set())

    def test_duplicate_headers_framing_cookies_and_metadata_ranges_rejected(self):
        for headers in ((("Host",NAME),),(("Authorization",AUTH),),(("Content-Length","00"),),
                        (("Content-Length","4097"),),(("Transfer-Encoding","chunked"),),
                        (("Cookie","private=x"),),(("Range","bytes=0-1"),)):
            self.assertEqual(self.listing(headers=headers)[0],400)
        self.assertEqual(self.listing(body=b"x")[0],400);self.assertEqual(self.state.observed,set())

    def test_root_autodiscovery_oauth_upload_and_change_api_remain_unqualified(self):
        for method,path in (("GET",API+"/files/root?fields=id"),("POST","/oauth2/v3/token"),
                            ("POST","/upload/drive/v1/files"),("GET",API+"/changes"),
                            ("HEAD",API+"/files/synthetic-file-3201?form=content"),
                            ("PUT",API+"/files/synthetic-file-3201"),
                            ("DELETE",API+"/files"),("GET","https://elsewhere.invalid/")):
            self.assertEqual(self.request(method,path)[0],400)
        self.assertEqual((self.state.payload_bytes,self.state.rejected_mutations),(0,0))

    def test_target_aliases_encoded_ids_and_ambiguous_queries_fail_closed(self):
        self.assertEqual(self.listing()[0],200)
        for path in (API+"/files/%73ynthetic-file-3201?form=content","//drive/v1/files",
                     API+"/../files",API+"/files?fields=%zz",API+"/files?fields=%FF",
                     API+"/files?fields=*#fragment"):
            self.assertEqual(self.request("GET",path)[0],400)
        self.assertEqual(self.state.payload_bytes,0)

    def test_complete_inventory_proves_absent_name_without_fabricated_metadata(self):
        self.assertEqual(self.listing()[0],200)
        status,_,raw=self.listing(nested=True);self.assertEqual(status,200)
        self.assertNotIn("missing-synthetic.txt",[x["fileName"] for x in json.loads(raw)["files"]])
        self.assertEqual(self.request("GET",API+"/files/unknown?form=content")[0],400)
        self.assertEqual(self.state.files,PAYLOADS)

    def test_request_response_and_deadline_budgets_cannot_pass(self):
        self.state.request_limit=1;self.assertEqual(self.listing()[0],200);self.assertEqual(self.listing()[0],429)
        self.assertTrue(self.state.budget_exceeded)
        self.state.request_limit=10;self.state.byte_limit=1;self.assertEqual(self.listing()[0],429)
        self.state.deadline=0;self.assertEqual(self.listing()[0],429)

    def test_tls_deadline_stops_partial_headers_and_cleans_up(self):
        timer=threading.Timer
        with T.FixtureCertificates.create(self.root) as certificates,patch.object(
                T.threading,"Timer",side_effect=lambda delay,callback:timer(delay+0.3,callback)):
            with T.BoundedHttpsServer(certificates,C.HuaweidriveHandler,state=C.HuaweidriveState(SECRET),
                    limits=T.TlsLimits(request_seconds=0.15)) as transport:
                with socket.create_connection(("127.0.0.1",transport.port),timeout=2) as raw:
                    with certificates.client_context().wrap_socket(raw,server_hostname="127.0.0.1") as client:
                        client.sendall(("GET "+API+"/files HTTP/1.1\r\nHost: "+NAME).encode())
                        self.assertEqual(client.recv(1),b"")
            self.assertIn("tls_request_deadline",transport.snapshot()["failure_codes"])
            self.assertTrue(transport.cleanup_complete)
        self.assertTrue(certificates.cleanup_complete)

class HuaweidriveAuthorityTests(unittest.TestCase):
    def test_reviewed_name_has_its_own_exact_sni_and_san(self):
        from cryptography import x509
        with tempfile.TemporaryDirectory() as directory:
            with T.FixtureCertificates.create(Path(directory).resolve(),server_name=NAME) as certificates:
                leaf=x509.load_pem_x509_certificate((certificates.directory/"leaf.pem").read_bytes())
                self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value),
                                 [x509.DNSName(NAME)])
        self.assertIsNone(T._huaweidrive_sni(None,NAME,None))
        for name in (None,"","fixture.pcloud.com","127.0.0.1",NAME+".",NAME+":443","drive-dre.cloud.dbankcloud.cn"):
            self.assertEqual(T._huaweidrive_sni(None,name,None),ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)
        self.assertEqual(T._pcloud_sni(None,NAME,None),ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)

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
