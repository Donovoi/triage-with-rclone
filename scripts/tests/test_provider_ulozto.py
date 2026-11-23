"""Independent Uloz.to wire, synthetic session and redirect contracts."""
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
    import fixture_ulozto as C
    import fixture_tls as T
finally:sys.path.pop(0)
API="apis.uloz.to"
CONTENT="synthetic-content.ulozto.invalid"
APP="synthetic-app-token"
PASSWORD="synthetic-password"
USER="synthetic-user"
ROOT="synthetic-root-3400"
FOLDERS={"":ROOT,"nested":"synthetic-folder-3410"}
FILES={"README-synthetic.txt":"synthetic-file-3401","nested/bytes.bin":"synthetic-file-3402","nested/space name.txt":"synthetic-file-3403"}
PAYLOADS={"README-synthetic.txt":b"Synthetic provider protocol fixture. No account or user data.\n",
          "nested/bytes.bin":bytes(range(256))*8,"nested/space name.txt":b"Nested synthetic payload.\n"}
STAMP="2024-01-01T00:00:00Z"

class UloztoWireTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.state=C.UloztoState(APP,PASSWORD)
        self.certificates=self.enterContext(T.FixtureCertificates.create(self.root))
        self.transport=self.enterContext(T.BoundedHttpsServer(self.certificates,C.UloztoHandler,state=self.state))
        self.session=None

    def request(self,method,path,host=API,app=APP,session=None,body=None,headers=(),raw=None):
        client=http.client.HTTPSConnection("127.0.0.1",self.transport.port,timeout=3,context=self.certificates.client_context())
        data=json.dumps(body,separators=(",",":")).encode() if body is not None else (raw or b"")
        try:
            client.putrequest(method,path,skip_host=True,skip_accept_encoding=True);client.putheader("Host",host)
            if app is not None:client.putheader("X-Auth-Token",app)
            if session is not None:client.putheader("X-User-Token",session)
            if data:client.putheader("Content-Type","application/json");client.putheader("Content-Length",str(len(data)))
            for key,value in headers:client.putheader(key,value)
            client.endheaders(data);response=client.getresponse()
            return response.status,dict(response.getheaders()),response.read(65537)
        finally:client.close()

    def login(self):
        status,_,raw=self.request("PUT","/v6/session",body={"login":USER,"password":PASSWORD})
        self.assertEqual(status,200);self.session=json.loads(raw)["token_id"];return self.session

    def list_path(self,kind="file",nested=False,**query):
        q={"status":"ok","limit":"500"};q.update(query)
        return "/v"+("9" if kind=="folder" else "8")+"/user/"+USER+"/folder/"+FOLDERS["nested" if nested else ""]+"/"+kind+"-list?"+urllib.parse.urlencode(q)

    def listing(self,kind="file",nested=False,**query):
        if self.session is None:self.login()
        return self.request("GET",self.list_path(kind,nested,**query),session=self.session)

    def issue(self,name="README-synthetic.txt"):
        self.assertEqual(self.listing(nested="/" in name)[0],200)
        status,_,raw=self.request("POST","/v5/file/download-link/vipdata",session=self.session,
              body={"file_slug":FILES[name],"user_login":USER,"device_id":"1795400000000000000"})
        self.assertEqual(status,200);value=json.loads(raw)
        return urllib.parse.urlsplit(value["link"]).path+"?hash="+value["hash"]

    def redirected(self,name="README-synthetic.txt"):
        target=self.issue(name);status,headers,raw=self.request("GET",target,session=self.session)
        self.assertEqual((status,raw),(302,b""))
        url=urllib.parse.urlsplit(headers["Location"]);self.assertEqual((url.scheme,url.netloc),("https",CONTENT))
        return url.path+"?"+url.query

    def test_login_requires_app_and_password_and_issues_fresh_sessions(self):
        first=self.login();second=self.login();self.assertNotEqual(first,second)
        self.assertRegex(first,r"^synthetic-session-[a-f0-9]{32}$")
        for app,password in ((None,PASSWORD),("wrong",PASSWORD),(APP,"wrong"),(APP,"nonascii-\u00f6")):
            self.assertEqual(self.request("PUT","/v6/session",app=app,body={"login":USER,"password":password})[0],401)
        self.assertEqual((self.state.logins,self.state.denied,self.state.payload_bytes),(2,4,0))

    def test_login_rejects_duplicate_json_extra_keys_stale_session_and_query(self):
        for raw in (b'{"login":"synthetic-user","password":"synthetic-password","password":"synthetic-password"}',
                    b'{"login":"synthetic-user","password":NaN}',b'[]',b'{"login":',b'{"login":"synthetic-user","password":"synthetic-password","extra":1}'):
            self.assertEqual(self.request("PUT","/v6/session",raw=raw)[0],400)
        self.assertEqual(self.request("PUT","/v6/session",session="stale",body={"login":USER,"password":PASSWORD})[0],400)
        self.assertEqual(self.request("PUT","/v6/session?extra=1",body={"login":USER,"password":PASSWORD})[0],400)
        self.assertEqual(self.state.logins,0)

    def test_listing_requires_a_session_actually_issued_by_login(self):
        path=self.list_path()
        for session in (None,"synthetic-session-forged","wrong"):
            self.assertEqual(self.request("GET",path,session=session)[0],401)
        self.assertEqual((self.state.payload_bytes,len(self.state.observed)),(0,0))
        self.login();self.assertEqual(self.request("GET",path,session=self.session,app="wrong")[0],401)

    def test_complete_root_and_nested_files_preserve_literal_metadata(self):
        for nested,names in ((False,["README-synthetic.txt"]),(True,["nested/bytes.bin","nested/space name.txt"])):
            status,_,raw=self.listing(nested=nested);self.assertEqual(status,200);value=json.loads(raw)
            self.assertEqual(value["metadata"],{"RunAt":STAMP,"offset":0,"limit":500,"items_count":len(names)})
            expected=[{"name":n.rsplit("/",1)[-1],"slug":FILES[n],"last_user_modified":STAMP,"privacy":"private",
                       "filesize":len(PAYLOADS[n]),"folder_slug":FOLDERS["nested" if nested else ""],
                       "upload_time":STAMP,"description":"","realm":"ulozto","is_in_trash":False,"is_incomplete":False} for n in names]
            self.assertEqual(value["items"],expected)
        self.assertEqual(self.state.observed,set(PAYLOADS))

    def test_folder_and_file_routes_remain_distinct_with_exact_versions(self):
        status,_,raw=self.listing("folder");self.assertEqual(status,200);value=json.loads(raw)
        self.assertEqual([x["name"] for x in value["subfolders"]],["nested"])
        self.assertEqual(value["subfolders"][0]["slug"],FOLDERS["nested"])
        self.assertEqual(value["subfolders"][0]["parent_folder_slug"],ROOT)
        self.assertEqual(value["folder"]["slug"],ROOT)
        self.assertEqual(json.loads(self.listing("folder",True)[2])["subfolders"],[])
        for path in (self.list_path().replace("/v8/","/v9/"),self.list_path("folder").replace("/v9/","/v8/")):
            self.assertEqual(self.request("GET",path,session=self.session)[0],400)

    def test_search_preserves_folder_scope_and_absence_without_fabricated_metadata(self):
        self.assertEqual(json.loads(self.listing(nested=True,search_query="space name.txt")[2])["items"][0]["name"],"space name.txt")
        self.assertEqual(json.loads(self.listing(search_query="space name.txt")[2])["items"],[])
        self.assertEqual(json.loads(self.listing(search_query="absent-synthetic.txt")[2])["items"],[])
        self.assertEqual(json.loads(self.listing("folder",search_query="absent-synthetic.txt")[2])["subfolders"],[])

    def test_listing_rejects_other_limits_statuses_offsets_and_duplicate_queries(self):
        self.login()
        for query in ({"status":"trash"},{"limit":"1"},{"offset":"0"},{"search_query":""},{"search_query":"nested/bytes.bin"},{"extra":"x"}):
            self.assertEqual(self.request("GET",self.list_path(**query),session=self.session)[0],400)
        self.assertEqual(self.request("GET",self.list_path()+"&limit=500",session=self.session)[0],400)
        self.assertEqual(self.state.observed,set())

    def test_download_link_requires_observed_file_owner_and_numeric_device(self):
        self.login();body={"file_slug":FILES["README-synthetic.txt"],"user_login":USER,"device_id":"1795400000000000000"}
        self.assertEqual(self.request("POST","/v5/file/download-link/vipdata",session=self.session,body=body)[0],400)
        self.listing()
        for change in ({"user_login":"other"},{"device_id":"x"},{"device_id":1795400000000000000},{"file_slug":FILES["nested/bytes.bin"]},{"extra":"1"}):
            self.assertEqual(self.request("POST","/v5/file/download-link/vipdata",session=self.session,body=dict(body,**change))[0],400)
        self.assertEqual(self.state.links,{})

    def test_issued_links_have_fresh_prefix_and_signature_bound_to_session(self):
        first=self.issue();second=self.issue();self.assertNotEqual(first,second)
        old=self.session;self.login()
        self.assertEqual(self.request("GET",first,session=self.session)[0],401)
        self.assertEqual(self.request("GET",first,session=old)[0],302)
        for bad in (first.split("?")[0],first+"&extra=1",first+"&hash=x",first.replace("hash=","other=")):
            self.assertEqual(self.request("GET",bad,session=old)[0],400)

    def test_content_requires_observed_redirect_and_no_app_or_session_headers(self):
        target=self.issue()
        self.assertEqual(self.request("GET",target,host=CONTENT,app=None)[0],400)
        self.assertEqual(self.request("GET",target,session=self.session)[0],302)
        for app,session in ((APP,None),(None,self.session),(APP,self.session)):
            self.assertEqual(self.request("GET",target,host=CONTENT,app=app,session=session)[0],400)
        self.assertEqual(self.state.payload_bytes,0)

    def test_three_downloads_match_literal_bytes_after_cross_host_redirect(self):
        for name,data in PAYLOADS.items():
            self.assertEqual(self.request("GET",self.redirected(name),host=CONTENT,app=None)[::2],(200,data))
        self.assertEqual(self.state.payload_bytes,sum(map(len,PAYLOADS.values())))
        self.assertEqual(self.state.files,PAYLOADS)

    def test_http403_contains_identical_bytes_without_success_credit(self):
        target=self.redirected();self.state.mode="read_denied"
        self.assertEqual(self.request("GET",target,host=CONTENT,app=None)[::2],(403,PAYLOADS["README-synthetic.txt"]))
        self.assertEqual((self.state.read_denied,self.state.payload_bytes),(1,0))

    def test_content_ranges_are_bounded_and_invalid_forms_rejected(self):
        target=self.redirected("nested/bytes.bin")
        status,h,raw=self.request("GET",target,host=CONTENT,app=None,headers=(("Range","bytes=1-7"),))
        self.assertEqual((status,h["Content-Range"],raw),(206,"bytes 1-7/2048",PAYLOADS["nested/bytes.bin"][1:8]))
        for value in ("bytes=-2","bytes=7-1","bytes=2048-","bytes=0-1,4-5"):
            self.assertEqual(self.request("GET",target,host=CONTENT,app=None,headers=(("Range",value),))[0],416)

    def test_direct_delete_guard_preserves_source(self):
        self.assertEqual(self.request("DELETE",self.issue(),session=self.session)[0],405)
        self.assertEqual((self.state.rejected_mutations,self.state.payload_bytes),(1,0));self.assertEqual(self.state.files,PAYLOADS)

    def test_authority_and_named_transport_are_exact(self):
        for host in (API.upper(),API+":443",API+".","127.0.0.1","user@"+API):
            self.assertEqual(self.request("PUT","/v6/session",host=host,body={"login":USER,"password":PASSWORD})[0],400)
        with patch.object(self.transport,"_server_name",CONTENT):
            self.assertEqual(self.request("PUT","/v6/session",body={"login":USER,"password":PASSWORD})[0],400)

    def test_duplicate_headers_framing_cookies_and_metadata_ranges_rejected(self):
        self.login()
        for headers in ((("Host",API),),(("X-Auth-Token",APP),),(("Content-Length","00"),),
                        (("Content-Length","4097"),),(("Transfer-Encoding","chunked"),),
                        (("Cookie","private=x"),),(("Authorization","Bearer x"),),(("Range","bytes=0-1"),)):
            self.assertEqual(self.request("GET",self.list_path(),session=self.session,headers=headers)[0],400)
        self.assertEqual(self.state.observed,set())

    def test_unreviewed_upload_mutations_and_target_aliases_are_rejected(self):
        self.login()
        for method,path in (("POST","/v5/upload/link"),("DELETE","/v6/user/synthetic-user/folder"),
                            ("HEAD",self.list_path()),("GET","https://elsewhere.invalid/"),
                            ("GET","//v8/user/synthetic-user/folder/"+ROOT+"/file-list"),
                            ("GET","/v8/file/%zz"),("GET",self.list_path()+"#fragment")):
            self.assertEqual(self.request(method,path,session=self.session)[0],400)
        self.assertEqual((self.state.payload_bytes,self.state.rejected_mutations),(0,0))

    def test_request_response_and_deadline_budgets_cannot_pass(self):
        self.login();self.state.request_limit=self.state.requests+1
        self.assertEqual(self.listing()[0],200);self.assertEqual(self.listing()[0],429);self.assertTrue(self.state.budget_exceeded)
        self.state.request_limit=10;self.state.byte_limit=1;self.assertEqual(self.listing()[0],429)
        self.state.deadline=0;self.assertEqual(self.listing()[0],429)

    def test_tls_deadline_stops_partial_headers_and_cleans_up(self):
        timer=threading.Timer
        with T.FixtureCertificates.create(self.root) as certificates,patch.object(
                T.threading,"Timer",side_effect=lambda delay,callback:timer(delay+0.3,callback)):
            with T.BoundedHttpsServer(certificates,C.UloztoHandler,state=C.UloztoState(APP,PASSWORD),
                    limits=T.TlsLimits(request_seconds=0.15)) as transport:
                with socket.create_connection(("127.0.0.1",transport.port),timeout=2) as raw:
                    with certificates.client_context().wrap_socket(raw,server_hostname="127.0.0.1") as client:
                        client.sendall(("GET / HTTP/1.1\r\nHost: "+API).encode());self.assertEqual(client.recv(1),b"")
            self.assertIn("tls_request_deadline",transport.snapshot()["failure_codes"]);self.assertTrue(transport.cleanup_complete)
        self.assertTrue(certificates.cleanup_complete)

class UloztoAuthorityTests(unittest.TestCase):
    def test_each_reviewed_name_has_distinct_exact_sni_and_san(self):
        from cryptography import x509
        for name,callback in ((API,T._ulozto_api_sni),(CONTENT,T._ulozto_content_sni)):
            with tempfile.TemporaryDirectory() as directory:
                with T.FixtureCertificates.create(Path(directory).resolve(),server_name=name) as certificates:
                    leaf=x509.load_pem_x509_certificate((certificates.directory/"leaf.pem").read_bytes())
                    self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value),[x509.DNSName(name)])
            self.assertIsNone(callback(None,name,None))
            for other in {None,"","fixture.pcloud.com","127.0.0.1",name+".",name+":443",API,CONTENT}-{name}:
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
