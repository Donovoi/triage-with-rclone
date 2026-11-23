"""Independent dosya.dev wire contracts; no live-provider acceptance."""
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
    import fixture_dosya as C
    import fixture_tls as T
finally:
    sys.path.pop(0)
NAME="api.dosya.dev"
API="/api/files"
SECRET="synthetic-dosya-key"
AUTH="Bearer "+SECRET
WORKSPACE="synthetic-workspace"
PAYLOADS={"README-synthetic.txt":b"Synthetic provider protocol fixture. No account or user data.\n",
          "nested/bytes.bin":bytes(range(256))*8,"nested/space name.txt":b"Nested synthetic payload.\n"}
IDS={"README-synthetic.txt":"file2801","nested/bytes.bin":"file2802","nested/space name.txt":"file2803"}
# Independent OpenSSL SHA-256 values over the literal bytes.
SHA256={'README-synthetic.txt': '1e901527b93ae84dc9d95a8aa76bbc12d7d77dbf8ab449333c172cfc909c639e', 'nested/bytes.bin': '10fc3c51a152e90e5b90319b601d92ccf37290ef53c35ff92507687d8a911a08', 'nested/space name.txt': 'e019c52fe70badce27affda5e408659399ff764985f07104029a42ade38125bd'}

class DosyaWireTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.state=C.DosyaState(SECRET)
        self.certificates=self.enterContext(T.FixtureCertificates.create(self.root))
        self.transport=self.enterContext(T.BoundedHttpsServer(self.certificates,C.DosyaHandler,state=self.state))

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
        value={"workspace_id":WORKSPACE,"per_page":"500","page":"1","sort":"name","dir":"asc"}
        if nested:value["folder_id"]="folder2800"
        value.update(changes);return urllib.parse.urlencode(value)

    def listing(self,nested=False,query=None,**kwargs):
        return self.request("GET",API+"?"+(self.query(nested) if query is None else query),**kwargs)

    def issue(self,name="README-synthetic.txt"):
        self.assertEqual(self.listing("/" in name)[0],200)
        status,headers,body=self.request("GET",API+"/"+IDS[name]+"/download",headers=(("X-Dosya-Workspace",WORKSPACE),))
        self.assertEqual((status,body),(302,b""))
        url=urllib.parse.urlsplit(headers["Location"])
        self.assertEqual((url.scheme,url.netloc),("https",NAME))
        return url.path+"?"+url.query

    def test_complete_inventory_has_literal_metadata_sha256_and_pagination(self):
        for nested,names in ((False,["README-synthetic.txt"]),(True,["nested/bytes.bin","nested/space name.txt"])):
            status,_,raw=self.listing(nested);self.assertEqual(status,200);value=json.loads(raw)
            self.assertEqual(set(value),{"ok","files","folders","pagination"});self.assertIs(value["ok"],True)
            expected=[]
            for name in names:
                expected.append({"id":IDS[name],"name":name.rsplit("/",1)[-1],"size_bytes":len(PAYLOADS[name]),
                  "mime_type":"application/octet-stream","extension":name.rsplit(".",1)[-1],"region":"synthetic",
                  "created_at":1704067200,"updated_at":1704067200,"folder_id":"folder2800" if nested else None,
                  "is_synced":1,"content_hash":SHA256[name]})
            self.assertEqual(value["files"],expected)
            self.assertEqual(value["folders"],[] if nested else [{"id":"folder2800","name":"nested","parent_id":None,
                  "created_at":1704067200,"file_count":2,"is_synced":1}])
            self.assertEqual(value["pagination"],{"page":1,"per_page":500,"total_files":len(names),"total_pages":1})

    def test_listing_rejects_other_workspaces_folders_pages_and_sort_contracts(self):
        for key,value in (("workspace_id","other"),("per_page","1"),("page","2"),("sort","id"),("dir","desc"),
                          ("folder_id","root"),("folder_id","other"),("extra","1")):
            self.assertEqual(self.listing(query=self.query(**{key:value}))[0],400)
        self.assertEqual(self.listing(query=self.query()+"&page=1")[0],400)
        self.assertEqual(self.listing(query="")[0],400);self.assertEqual(self.state.observed,set())

    def test_download_link_requires_observed_id_and_exact_workspace_hint(self):
        path=API+"/file2801/download"
        self.assertEqual(self.request("GET",path,headers=(("X-Dosya-Workspace",WORKSPACE),))[0],400)
        self.assertEqual(self.listing()[0],200)
        for headers in ((),(("X-Dosya-Workspace","other"),)):
            self.assertEqual(self.request("GET",path,headers=headers)[0],400)
        self.assertEqual(self.state.issued,set())
        target=self.issue();self.assertTrue(target.startswith("/synthetic-content/file2801?signature="))

    def test_api_credentials_are_required_and_never_read_payload_on_denial(self):
        for auth in (None,SECRET,"Bearer wrong",AUTH+"extra"):
            self.assertEqual(self.listing(auth=auth)[0],401)
        self.assertEqual((self.state.denied,self.state.authenticated,self.state.payload_bytes),(4,0,0))
        self.assertEqual(self.state.observed,set())

    def test_content_requires_issued_signature_and_rejects_api_credentials(self):
        path="/synthetic-content/file2801?signature="+"0"*32
        self.assertEqual(self.request("GET",path,auth=None)[0],400)
        target=self.issue()
        self.assertEqual(self.request("GET",target)[0],400)
        self.assertEqual(self.request("GET",target,auth=None,headers=(("X-Dosya-Workspace",WORKSPACE),))[0],400)
        self.assertEqual((self.state.content_authorizations,self.state.payload_bytes),(1,0))
        self.assertEqual(self.request("GET",target,auth=None)[2],PAYLOADS["README-synthetic.txt"])

    def test_all_known_files_download_exactly_without_authorization(self):
        for name,body in PAYLOADS.items():
            target=self.issue(name)
            self.assertEqual(self.request("GET",target,auth=None)[::2],(200,body))
        self.assertEqual(self.state.payload_bytes,sum(map(len,PAYLOADS.values())))
        self.assertEqual(self.state.files,PAYLOADS)

    def test_http403_contains_identical_expected_bytes_without_success_payload(self):
        target=self.issue();self.state.mode="read_denied"
        status,_,body=self.request("GET",target,auth=None)
        self.assertEqual((status,body),(403,PAYLOADS["README-synthetic.txt"]))
        self.assertEqual((self.state.read_denied,self.state.payload_bytes),(1,0))
        self.assertEqual(self.state.files,PAYLOADS)

    def test_ranges_are_bounded_and_invalid_forms_are_rejected(self):
        target=self.issue("nested/bytes.bin")
        status,h,raw=self.request("GET",target,auth=None,headers=(("Range","bytes=1-7"),))
        self.assertEqual((status,h["Content-Range"],raw),(206,"bytes 1-7/2048",PAYLOADS["nested/bytes.bin"][1:8]))
        status,h,raw=self.request("GET",target,auth=None,headers=(("Range","bytes=0-4096"),))
        self.assertEqual((status,h["Content-Range"],raw),(206,"bytes 0-2047/2048",PAYLOADS["nested/bytes.bin"]))
        for value in ("bytes=-2","bytes=7-1","bytes=2048-","bytes=0-1,4-5"):
            self.assertEqual(self.request("GET",target,auth=None,headers=(("Range",value),))[0],416)

    def test_content_signature_changes_duplicates_and_extras_fail_closed(self):
        target=self.issue();path=target.split("?",1)[0]
        for bad in (path,path+"?signature=wrong",target+"&extra=1",target+"&signature=wrong",
                    target.replace("file2801","file2802"),target.replace("file2801","%66ile2801")):
            self.assertEqual(self.request("GET",bad,auth=None)[0],400)
        self.assertEqual(self.state.payload_bytes,0)

    def test_direct_delete_guard_requires_issued_link_and_preserves_source(self):
        self.assertEqual(self.request("DELETE","/synthetic-content/file2801",auth=None)[0],400)
        target=self.issue();self.assertEqual(self.request("DELETE",target,auth=None)[0],405)
        self.assertEqual((self.state.rejected_mutations,self.state.payload_bytes),(1,0))
        self.assertEqual(self.state.files,PAYLOADS)

    def test_authority_is_exact_and_named_transport_must_match(self):
        for host in (NAME.upper(),NAME+":443",NAME+".","127.0.0.1","user@"+NAME):
            self.assertEqual(self.listing(host=host)[0],400)
        with patch.object(self.transport,"_server_name","api.sugarsync.com"):
            self.assertEqual(self.listing()[0],400)
        self.assertEqual(self.state.observed,set())

    def test_duplicate_headers_framing_cookies_and_metadata_ranges_are_rejected(self):
        for headers in ((("Host",NAME),),(("Authorization",AUTH),),(("Content-Length","00"),),
                        (("Content-Length","4097"),),(("Transfer-Encoding","chunked"),),(("Range","bytes=0-1"),),
                        (("Cookie","private=x"),),(("X-Dosya-Workspace",WORKSPACE),)):
            self.assertEqual(self.listing(headers=headers)[0],400)
        self.assertEqual(self.listing(body=b"x")[0],400);self.assertEqual(self.state.observed,set())

    def test_account_discovery_uploads_and_unknown_routes_remain_unqualified(self):
        for method,path in (("GET","/api/workspaces"),("POST","/api/upload/init"),("PUT","/api/upload/id"),
                            ("GET",API+"/absent/download"),("HEAD",API),("DELETE",API),
                            ("GET","https://elsewhere.invalid/"),("GET","//api/files")):
            self.assertEqual(self.request(method,path)[0],400)
        self.assertEqual((self.state.payload_bytes,self.state.rejected_mutations),(0,0))

    def test_download_queries_and_listing_workspace_header_are_rejected(self):
        self.assertEqual(self.listing()[0],200)
        self.assertEqual(self.request("GET",API+"/file2801/download?x=1",
                         headers=(("X-Dosya-Workspace",WORKSPACE),))[0],400)
        self.assertEqual(self.listing(headers=(("X-Dosya-Workspace",WORKSPACE),))[0],400)
        self.assertEqual(self.state.issued,set())

    def test_request_and_response_budgets_cannot_pass(self):
        self.state.request_limit=1;self.assertEqual(self.listing()[0],200);self.assertEqual(self.listing()[0],429)
        self.assertTrue(self.state.budget_exceeded)
        self.state.request_limit=10;self.state.byte_limit=1;self.assertEqual(self.listing()[0],429)

    def test_tls_deadline_stops_partial_headers(self):
        timer = threading.Timer
        with T.FixtureCertificates.create(self.root) as certificates, patch.object(
                T.threading, "Timer", side_effect=lambda delay, callback: timer(delay + 0.3, callback)):
            with T.BoundedHttpsServer(certificates, C.DosyaHandler, state=C.DosyaState(SECRET),
                    limits=T.TlsLimits(request_seconds=0.15)) as transport:
                with socket.create_connection(("127.0.0.1", transport.port), timeout=2) as raw:
                    with certificates.client_context().wrap_socket(raw, server_hostname="127.0.0.1") as client:
                        client.sendall(("GET " + API + " HTTP/1.1\r\nHost: " + NAME).encode())
                        self.assertEqual(client.recv(1), b"")
            self.assertIn("tls_request_deadline", transport.snapshot()["failure_codes"])
            self.assertTrue(transport.cleanup_complete)
        self.assertTrue(certificates.cleanup_complete)

class DosyaAuthorityTests(unittest.TestCase):
    def test_reviewed_name_has_its_own_exact_sni_and_san(self):
        with tempfile.TemporaryDirectory() as directory:
            with T.FixtureCertificates.create(Path(directory).resolve(), server_name=NAME) as certificates:
                from cryptography import x509
                leaf = x509.load_pem_x509_certificate((certificates.directory / "leaf.pem").read_bytes())
                self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value), [x509.DNSName(NAME)])
        self.assertIsNone(T._dosya_sni(None, NAME, None))
        for name in (None, "", "fixture.pcloud.com", "api.cloudinary.com", "127.0.0.1", NAME + ".", NAME + ":443"):
            self.assertEqual(T._dosya_sni(None, name, None), ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)
        self.assertEqual(T._pcloud_sni(None, NAME, None), ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)
        self.assertEqual(T._cloudinary_sni(None, NAME, None), ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)

    def test_fixed_port_is_linux_only_and_never_falls_back(self):
        calls = []
        def init(server, address, handler):
            calls.append(address)
            server.server_address = address
        with patch.object(T.HTTPServer, "__init__", init), patch.object(T.sys, "platform", "linux"):
            server = T._HttpServer(SimpleNamespace(_server_name=NAME), object, None)
            self.assertEqual(server.authority, NAME)
        self.assertEqual(calls, [("127.0.0.1", 443)])
        with patch.object(T.HTTPServer, "__init__") as bind, patch.object(T.sys, "platform", "win32"):
            with self.assertRaisesRegex(T.TlsError, "requires_linux"):
                T._HttpServer(SimpleNamespace(_server_name=NAME), object, None)
            bind.assert_not_called()

if __name__ == "__main__":
    unittest.main()
