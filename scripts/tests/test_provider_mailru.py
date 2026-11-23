"""Mail.ru M1 wire contracts independent of the native client."""
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
    import fixture_mailru as C
    import fixture_tls as T
finally:sys.path.pop(0)
API="cloud.mail.ru"
DISPATCH="dispatcher.cloud.mail.ru"
CONTENT="synthetic-content.mailru.invalid"
SECRET="synthetic-mailru-token"
PAYLOADS={"README-synthetic.txt":b"Synthetic provider protocol fixture. No account or user data.\n",
          "nested/bytes.bin":bytes(range(256))*8,"nested/space name.txt":b"Nested synthetic payload.\n"}
HASHES={"README-synthetic.txt":"4ee38dc14a10d94c4a04d71c3a42812423782569",
        "nested/bytes.bin":"9e7db3d62e105f59d494b87b15eb0f273740241a",
        "nested/space name.txt":"57aa20186f9e2d69b05a5022e40d93da00bbe732"}

class MailruWireTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.state=C.MailruState(SECRET)
        self.certificates=self.enterContext(T.FixtureCertificates.create(self.root))
        self.transport=self.enterContext(T.BoundedHttpsServer(self.certificates,C.MailruHandler,state=self.state))

    def request(self,method,path,host=API,headers=(),body=b""):
        client=http.client.HTTPSConnection("127.0.0.1",self.transport.port,timeout=3,context=self.certificates.client_context())
        try:
            client.putrequest(method,path,skip_host=True,skip_accept_encoding=True);client.putheader("Host",host)
            if body:client.putheader("Content-Length",str(len(body)))
            for key,value in headers:client.putheader(key,value)
            client.endheaders(body);response=client.getresponse()
            return response.status,dict(response.getheaders()),response.read(65537)
        finally:client.close()

    def query(self,token=SECRET,**extra):
        values={"access_token":token,"offset":"0","limit":"2147483647"};values.update(extra)
        return urllib.parse.urlencode(values)

    def listing(self,nested=False,query=None,body=None,headers=(),host=API):
        data=urllib.parse.urlencode({"home":"/Synthetic"+("/nested" if nested else "")}).encode() if body is None else body
        return self.request("POST","/api/m1/folder?"+(self.query() if query is None else query),host=host,
                            headers=(("Content-Type","application/x-www-form-urlencoded"),*headers),body=data)

    def target(self,name="README-synthetic.txt"):
        self.assertEqual(self.listing("/" in name)[0],200)
        status,_,raw=self.request("GET","/d",host=DISPATCH);self.assertEqual(status,200)
        base=raw.decode().strip()
        return urllib.parse.urlsplit(base).path+urllib.parse.quote("Synthetic/"+name,safe="")+"?"+urllib.parse.urlencode({"client_id":"cloud-win","token":SECRET})

    def test_root_and_nested_inventory_scope_sizes_timestamps_and_mailru_hashes(self):
        for nested,names in ((False,["README-synthetic.txt","nested"]),(True,["nested/bytes.bin","nested/space name.txt"])):
            status,_,raw=self.listing(nested);self.assertEqual(status,200);value=json.loads(raw)
            self.assertEqual((value["status"],value["time"]),(200,1704067200))
            self.assertEqual(value["body"]["home"],"/Synthetic"+("/nested" if nested else ""))
            expected=[]
            for name in names:
                folder=name=="nested"
                expected.append({"kind":"folder" if folder else "file","type":"folder" if folder else "file",
                                 "name":name.rsplit("/",1)[-1],"home":"/Synthetic/"+name,
                                 "size":0 if folder else len(PAYLOADS[name]),"mtime":1704067200,
                                 "hash":"" if folder else HASHES[name],
                                 "count":{"files":2 if folder else 0,"folders":0}})
            self.assertEqual(value["body"]["list"],expected)
        self.assertEqual(self.state.observed,set(PAYLOADS))

    def test_metadata_and_missing_name_have_distinct_status_and_no_payload(self):
        for name in ("README-synthetic.txt","nested","absent-synthetic.txt"):
            status,_,raw=self.request("GET","/api/m1/file?"+self.query(home="/Synthetic/"+name))
            self.assertEqual(status,404 if name.startswith("absent") else 200)
            if status==404:self.assertEqual(json.loads(raw),{"status":404,"body":{"home":{"error":"not exists"}}})
        self.assertEqual(self.state.payload_bytes,0)

    def test_newfs_relative_and_newobject_absolute_metadata_paths_are_exact(self):
        for home in ("Synthetic/README-synthetic.txt","/Synthetic/README-synthetic.txt"):
            status,_,raw=self.request("GET","/api/m1/file?"+self.query(home=home))
            self.assertEqual(status,200);self.assertEqual(json.loads(raw)["body"]["home"],"/Synthetic/README-synthetic.txt")
        for home in ("//Synthetic/README-synthetic.txt","Synthetic//README-synthetic.txt","Synthetic/../README-synthetic.txt"):
            self.assertEqual(self.request("GET","/api/m1/file?"+self.query(home=home))[0],404)

    def test_hash_boundary_matches_literal_padding_and_independent_vectors(self):
        self.assertEqual(C.mailru_hash(b""),"0"*40)
        self.assertEqual(C.mailru_hash(b"abc"),"616263"+"00"*17)
        self.assertEqual(C.mailru_hash(bytes(range(20))),bytes(range(20)).hex())
        for name,data in PAYLOADS.items():self.assertEqual(C.mailru_hash(data),HASHES[name])

    def test_listing_requires_exact_query_form_and_no_duplicate_keys(self):
        for query in (self.query(offset="1"),self.query(limit="1000"),self.query(page="1"),self.query()+"&offset=0"):
            self.assertEqual(self.listing(query=query)[0],400)
        for data in (b"home=%2FSynthetic&home=%2FSynthetic",b"home=%2FSynthetic&extra=x",b"home=%FF",b"home=%zz",b"home"):
            self.assertEqual(self.listing(body=data)[0],400)
        self.assertEqual(self.state.observed,set())

    def test_unknown_directory_is_not_a_successful_empty_inventory(self):
        self.assertEqual(self.listing(body=b"home=%2FSynthetic%2Fmissing")[0],404)
        self.assertEqual(self.state.observed,set())

    def test_authentication_is_query_only_and_wrong_tokens_cannot_read(self):
        for query in (self.query(token="wrong"),self.query(token=""),"offset=0&limit=2147483647"):
            self.assertEqual(self.listing(query=query)[0],401)
        for headers in ((("Authorization","Bearer "+SECRET),),(("Cookie","private=x"),)):
            self.assertEqual(self.listing(headers=headers)[0],400)
        target=self.target()
        self.assertEqual(self.request("GET",target.replace("token="+SECRET,"token=wrong"),host=CONTENT)[0],401)
        self.assertEqual(self.state.payload_bytes,0)

    def test_dispatcher_is_public_but_exact_and_only_issues_private_content(self):
        status,_,raw=self.request("GET","/d",host=DISPATCH)
        self.assertEqual(status,200);url=urllib.parse.urlsplit(raw.decode().strip())
        self.assertEqual((url.scheme,url.netloc),("https",CONTENT));self.assertRegex(url.path,r"^/[a-f0-9]{32}/$")
        for path in ("/d?token="+SECRET,"/m","/d/"):
            self.assertEqual(self.request("GET",path,host=DISPATCH)[0],400)
        self.assertEqual(self.request("GET","/d",host=DISPATCH,headers=(("Authorization","Bearer "+SECRET),))[0],400)
        self.assertEqual((self.state.dispatches,self.state.payload_bytes),(1,0))

    def test_content_requires_observation_dispatch_and_exact_issued_prefix(self):
        path="/"+self.state.dispatch_token+"/Synthetic%2FREADME-synthetic.txt?client_id=cloud-win&token="+SECRET
        self.assertEqual(self.request("GET",path,host=CONTENT)[0],400)
        self.assertEqual(self.listing()[0],200)
        self.assertEqual(self.request("GET",path,host=CONTENT)[0],400)
        target=self.target()
        for bad in (target.replace(self.state.dispatch_token,"0"*32),target.replace("cloud-win","other"),target+"&extra=1",
                    target+"&token="+SECRET,target.replace("%2F","/"),target.replace("%2F","%2f")):
            self.assertEqual(self.request("GET",bad,host=CONTENT)[0],400)
        self.assertEqual(self.state.payload_bytes,0)

    def test_three_known_files_download_exactly_via_dispatched_authority(self):
        for name,payload in PAYLOADS.items():
            self.assertEqual(self.request("GET",self.target(name),host=CONTENT)[::2],(200,payload))
        self.assertEqual(self.state.payload_bytes,sum(map(len,PAYLOADS.values())))
        self.assertEqual(self.state.files,PAYLOADS)

    def test_http403_contains_identical_bytes_without_success_credit(self):
        target=self.target();self.state.mode="read_denied"
        self.assertEqual(self.request("GET",target,host=CONTENT)[::2],(403,PAYLOADS["README-synthetic.txt"]))
        self.assertEqual((self.state.read_denied,self.state.payload_bytes),(1,0))

    def test_ranges_are_bounded_and_invalid_forms_rejected(self):
        target=self.target("nested/bytes.bin")
        status,h,raw=self.request("GET",target,host=CONTENT,headers=(("Range","bytes=1-7"),))
        self.assertEqual((status,h["Content-Range"],raw),(206,"bytes 1-7/2048",PAYLOADS["nested/bytes.bin"][1:8]))
        for value in ("bytes=-2","bytes=7-1","bytes=2048-","bytes=0-1,4-5"):
            self.assertEqual(self.request("GET",target,host=CONTENT,headers=(("Range",value),))[0],416)

    def test_direct_delete_guard_preserves_source(self):
        self.assertEqual(self.request("DELETE",self.target(),host=CONTENT)[0],405)
        self.assertEqual((self.state.rejected_mutations,self.state.payload_bytes),(1,0));self.assertEqual(self.state.files,PAYLOADS)

    def test_authority_routing_and_sni_binding_cannot_be_substituted(self):
        for host in (API.upper(),API+":443",API+".","127.0.0.1",DISPATCH,CONTENT):
            self.assertEqual(self.listing(host=host)[0],400 if host!=CONTENT else 401)
        with patch.object(self.transport,"_server_name",DISPATCH):self.assertEqual(self.listing()[0],400)
        self.assertEqual(self.state.observed,set())

    def test_duplicate_headers_framing_and_metadata_ranges_are_rejected(self):
        for headers in ((("Host",API),),(("Content-Length","00"),),(("Content-Length","4097"),),
                        (("Transfer-Encoding","chunked"),),(("Range","bytes=0-1"),)):
            self.assertEqual(self.listing(headers=headers)[0],400)
        self.assertEqual(self.state.observed,set())

    def test_login_binary_protocol_uploads_and_unreviewed_methods_are_rejected(self):
        for method,path in (("POST","/token"),("POST","/api/m1/file/add"),("PUT","/api/m1/file"),
                            ("HEAD","/api/m1/file"),("DELETE","/api/m1/folder"),("GET","https://elsewhere.invalid/")):
            self.assertIn(self.request(method,path)[0],(400,401))
        self.assertEqual((self.state.payload_bytes,self.state.rejected_mutations),(0,0))

    def test_ambiguous_targets_fragments_and_queries_fail_closed(self):
        for path in ("//api/m1/file","/api/../m1/file","/api/m1/file?home=%zz","/api/m1/file?home=%FF",
                     "/api/m1/file?home=/Synthetic#fragment"):
            self.assertIn(self.request("GET",path)[0],(400,401))
        self.assertEqual(self.state.payload_bytes,0)

    def test_request_response_and_deadline_budgets_cannot_pass(self):
        self.state.request_limit=1;self.assertEqual(self.listing()[0],200);self.assertEqual(self.listing()[0],429)
        self.assertTrue(self.state.budget_exceeded)
        self.state.request_limit=10;self.state.byte_limit=1;self.assertEqual(self.listing()[0],429)
        self.state.deadline=0;self.assertEqual(self.listing()[0],429)

    def test_tls_deadline_stops_partial_headers_and_cleans_up(self):
        timer=threading.Timer
        with T.FixtureCertificates.create(self.root) as certificates,patch.object(
                T.threading,"Timer",side_effect=lambda delay,callback:timer(delay+0.3,callback)):
            with T.BoundedHttpsServer(certificates,C.MailruHandler,state=C.MailruState(SECRET),
                    limits=T.TlsLimits(request_seconds=0.15)) as transport:
                with socket.create_connection(("127.0.0.1",transport.port),timeout=2) as raw:
                    with certificates.client_context().wrap_socket(raw,server_hostname="127.0.0.1") as client:
                        client.sendall(("GET /api/m1/file HTTP/1.1\r\nHost: "+API).encode())
                        self.assertEqual(client.recv(1),b"")
            self.assertIn("tls_request_deadline",transport.snapshot()["failure_codes"]);self.assertTrue(transport.cleanup_complete)
        self.assertTrue(certificates.cleanup_complete)

class MailruAuthorityTests(unittest.TestCase):
    def test_each_reviewed_name_has_distinct_exact_sni_and_san(self):
        from cryptography import x509
        for name,callback in ((API,T._mailru_api_sni),(DISPATCH,T._mailru_dispatch_sni),(CONTENT,T._mailru_content_sni)):
            with tempfile.TemporaryDirectory() as directory:
                with T.FixtureCertificates.create(Path(directory).resolve(),server_name=name) as certificates:
                    leaf=x509.load_pem_x509_certificate((certificates.directory/"leaf.pem").read_bytes())
                    self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value),[x509.DNSName(name)])
            self.assertIsNone(callback(None,name,None))
            for other in {None,"","fixture.pcloud.com","127.0.0.1",name+".",name+":443",API,DISPATCH,CONTENT}-{name}:
                self.assertEqual(callback(None,other,None),ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)

    def test_three_private_addresses_are_linux_only_without_port_fallback(self):
        for name,address in ((API,"127.0.0.1"),(DISPATCH,"127.0.0.2"),(CONTENT,"127.0.0.3")):
            calls=[]
            def init(server,location,handler):calls.append(location);server.server_address=location
            with patch.object(T.HTTPServer,"__init__",init),patch.object(T.sys,"platform","linux"):
                server=T._HttpServer(SimpleNamespace(_server_name=name),object,None);self.assertEqual(server.authority,name)
            self.assertEqual(calls,[(address,443)])
            with patch.object(T.HTTPServer,"__init__") as bind,patch.object(T.sys,"platform","win32"):
                with self.assertRaisesRegex(T.TlsError,"requires_linux"):T._HttpServer(SimpleNamespace(_server_name=name),object,None)
                bind.assert_not_called()

if __name__=="__main__":unittest.main()
