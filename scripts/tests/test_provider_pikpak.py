"""Independent PikPak wire contracts; no live-provider acceptance."""
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
    import fixture_pikpak as C
    import fixture_tls as T
finally:
    sys.path.pop(0)
NAME="api-drive.mypikpak.com"
ORIGIN="https://api-drive.mypikpak.com"
API="/drive/v1/files"
READ="/synthetic-content/"
SECRET="synthetic-pikpak-token"
AUTH="Bearer "+SECRET
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0"
HEADERS={"Referer":"https://mypikpak.com/","X-Client-Id":"YUMx5nI8ZU8Ap8pm","X-Client-Version":"2.0.0",
         "X-Device-Id":"1"*32,"X-Captcha-Token":"synthetic-unused-captcha"}
PAYLOADS={"README-synthetic.txt":b"Synthetic provider protocol fixture. No account or user data.\n",
          "nested/bytes.bin":bytes(range(256))*8,"nested/space name.txt":b"Nested synthetic payload.\n"}
IDS={"README-synthetic.txt":"file2701","nested/bytes.bin":"file2702","nested/space name.txt":"file2703"}
# Independent OpenSSL MD5 values over the literal fixture bytes.
MD5={"README-synthetic.txt":"f9ac90560b9929242009ee0c24c9e5d8","nested/bytes.bin":"1576a94d6cb334dd126cb1c27f19e0f2",
     "nested/space name.txt":"371d24ba264bcaac3332a3ed564a93f8"}

class PikpakWireTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.state=C.PikpakState(SECRET)
        self.certificates=self.enterContext(T.FixtureCertificates.create(self.root))
        self.transport=self.enterContext(T.BoundedHttpsServer(self.certificates,C.PikpakHandler,state=self.state))

    def request(self,method,path,auth=AUTH,host=NAME,headers=(),api_headers=None,ua=UA,body=b""):
        client=http.client.HTTPSConnection("127.0.0.1",self.transport.port,timeout=3,context=self.certificates.client_context())
        try:
            client.putrequest(method,path,skip_host=True,skip_accept_encoding=True);client.putheader("Host",host)
            if ua is not None:client.putheader("User-Agent",ua)
            if auth is not None:client.putheader("Authorization",auth)
            if path.startswith("/drive/"):
                for k,v in (HEADERS if api_headers is None else api_headers).items():client.putheader(k,v)
            if body:client.putheader("Content-Length",str(len(body)))
            for k,v in headers:client.putheader(k,v)
            client.endheaders(body);response=client.getresponse()
            return response.status,dict(response.getheaders()),response.read(65537)
        finally:client.close()

    def query(self,parent="synthetic-root",kind=None,**changes):
        filters={"phase":{"eq":"PHASE_TYPE_COMPLETE"},"trashed":{"eq":False}}
        if kind is not None:filters["kind"]={"eq":kind}
        q={"thumbnail_size":"SIZE_MEDIUM","limit":"500","with_audit":"true","parent_id":parent,"page_token":"",
           "filters":json.dumps(filters,separators=(",",":"))}
        q.update(changes);return urllib.parse.urlencode(q)

    def listing(self,parent="synthetic-root",kind=None,query=None,**kwargs):
        return self.request("GET",API+"?"+(self.query(parent,kind) if query is None else query),**kwargs)

    def issue(self,name="README-synthetic.txt"):
        self.assertEqual(self.listing("synthetic-nested" if "/" in name else "synthetic-root")[0],200)
        status,_,raw=self.request("GET",API+"/"+IDS[name]);self.assertEqual(status,200);return json.loads(raw)

    def content(self,name="README-synthetic.txt",observe=True,**kwargs):
        if observe:self.issue(name)
        return self.request("GET",READ+IDS[name],**kwargs)

    def test_complete_inventory_has_independent_typed_metadata_and_empty_continuation(self):
        for parent,names in (("synthetic-root",["README-synthetic.txt","nested"]),
                             ("synthetic-nested",["nested/bytes.bin","nested/space name.txt"])):
            status,_,raw=self.listing(parent);self.assertEqual(status,200);value=json.loads(raw)
            self.assertEqual(set(value),{"kind","files","next_page_token","sync_time"})
            self.assertEqual((value["kind"],value["next_page_token"],value["sync_time"]),
                             ("drive#fileList","","2024-01-01T00:00:00Z"))
            expected=[]
            for name in names:
                folder=name=="nested"
                item={"kind":"drive#folder" if folder else "drive#file","id":"synthetic-nested" if folder else IDS[name],
                      "parent_id":parent,"name":name.rsplit("/",1)[-1],"size":"0" if folder else str(len(PAYLOADS[name])),
                      "created_time":"2024-01-01T00:00:00Z","modified_time":"2024-01-01T00:00:00Z",
                      "phase":"PHASE_TYPE_COMPLETE","trashed":False,"links":{}}
                if not folder:item.update(md5_checksum=MD5[name],mime_type="application/octet-stream")
                expected.append(item)
            self.assertEqual(value["files"],expected)

    def test_kind_filter_selects_complete_subsets_and_missing_name_stays_absent(self):
        for kind,ids in (("drive#folder",["synthetic-nested"]),("drive#file",["file2701"])):
            status,_,raw=self.listing(kind=kind);self.assertEqual(status,200)
            self.assertEqual([r["id"] for r in json.loads(raw)["files"]],ids)
        self.assertEqual(self.state.observed,{"README-synthetic.txt"})
        self.assertEqual(self.request("GET",API+"/absent-synthetic.txt")[0],400)

    def test_metadata_requires_observed_object_and_content_requires_issued_link(self):
        for path in (API+"/file2701",READ+"file2701"):self.assertEqual(self.request("GET",path)[0],400)
        self.assertEqual(self.listing()[0],200);self.assertEqual(self.request("GET",READ+"file2701")[0],400)
        item=self.issue()
        self.assertEqual(item["links"],{"application/octet-stream":{"url":ORIGIN+READ+"file2701",
                         "token":"synthetic-download-token","expire":self.state.expiry}})
        self.assertEqual(self.content(observe=False)[2],PAYLOADS["README-synthetic.txt"])

    def test_all_known_files_download_with_exact_bytes(self):
        for name,body in PAYLOADS.items():
            status,_,raw=self.content(name);self.assertEqual((status,raw),(200,body))
        self.assertEqual(self.state.files,PAYLOADS)
        self.assertEqual(self.state.payload_bytes,sum(map(len,PAYLOADS.values())))

    def test_wrong_missing_or_nonbearer_credentials_are_denied_without_payload(self):
        for auth in (None,SECRET,"Bearer wrong","Bearer "+SECRET+"extra"):
            status,_,raw=self.listing(auth=auth);self.assertEqual(status,401)
            self.assertEqual(json.loads(raw),{"error":"unauthenticated","error_code":16})
        self.assertEqual((self.state.denied,self.state.authenticated,self.state.payload_bytes),(4,0,0))
        self.assertEqual(self.state.observed,set())

    def test_http403_contains_identical_expected_bytes_and_no_success_payload_count(self):
        self.issue();self.state.mode="read_denied"
        status,_,raw=self.content(observe=False);self.assertEqual((status,raw),(403,PAYLOADS["README-synthetic.txt"]))
        self.assertEqual((self.state.read_denied,self.state.payload_bytes),(1,0));self.assertEqual(self.state.files,PAYLOADS)

    def test_ranges_return_exact_bytes_and_reject_invalid_forms(self):
        self.issue("nested/bytes.bin")
        status,h,raw=self.content("nested/bytes.bin",observe=False,headers=(("Range","bytes=1-7"),))
        self.assertEqual((status,h["Content-Range"],raw),(206,"bytes 1-7/2048",PAYLOADS["nested/bytes.bin"][1:8]))
        status,h,raw=self.content("nested/bytes.bin",observe=False,headers=(("Range","bytes=0-4096"),))
        self.assertEqual((status,h["Content-Range"],raw),(206,"bytes 0-2047/2048",PAYLOADS["nested/bytes.bin"]))
        for value in ("bytes=-2","bytes=7-1","bytes=2048-","bytes=0-1,4-5"):
            self.assertEqual(self.content("nested/bytes.bin",observe=False,headers=(("Range",value),))[0],416)

    def test_direct_mutation_guard_requires_observed_link_and_correct_credentials(self):
        path=READ+"file2701";self.assertEqual(self.request("DELETE",path)[0],400);self.issue()
        self.assertEqual(self.request("DELETE",path,auth="Bearer wrong")[0],401)
        self.assertEqual(self.request("DELETE",path)[0],405)
        self.assertEqual((self.state.rejected_mutations,self.state.payload_bytes),(1,0));self.assertEqual(self.state.files,PAYLOADS)

    def test_query_scope_pagination_duplicates_and_filter_types_fail_closed(self):
        for key,value in (("thumbnail_size","x"),("limit","1"),("with_audit","false"),("parent_id","other"),
                          ("page_token","next"),("extra","1")):
            self.assertEqual(self.listing(query=self.query(**{key:value}))[0],400)
        for q in (self.query()+"&limit=500",""):self.assertEqual(self.listing(query=q)[0],400)
        for filters in ('null','[]','{"phase":{}}',
                        '{"phase":{"eq":"PHASE_TYPE_COMPLETE"},"trashed":{"eq":0}}',
                        '{"phase":{"eq":"PHASE_TYPE_COMPLETE"},"trashed":{"eq":"false"}}',
                        '{"phase":{"eq":"PHASE_TYPE_COMPLETE"},"trashed":{"eq":false},"trashed":{"eq":false}}',
                        '{"phase":{"eq":"PHASE_TYPE_COMPLETE"},"trashed":{"eq":false},"kind":{"eq":true}}'):
            self.assertEqual(self.listing(query=self.query(filters=filters))[0],400)
        self.assertEqual(self.state.observed,set())

    def test_api_client_device_captcha_and_referer_headers_are_exact(self):
        for key in HEADERS:
            for missing in (True,False):
                headers=dict(HEADERS)
                if missing:headers.pop(key)
                else:headers[key]="wrong"
                self.assertEqual(self.listing(api_headers=headers)[0],400)
        self.assertEqual(self.state.observed,set())

    def test_content_rejects_api_headers_and_changed_user_agent(self):
        self.issue()
        for key,value in HEADERS.items():self.assertEqual(self.content(observe=False,headers=((key,value),))[0],400)
        for ua in (None,"rclone/v1.76.0",UA+" changed"):self.assertEqual(self.listing(ua=ua)[0],400)
        self.assertEqual(self.state.payload_bytes,0)

    def test_authority_is_exact_and_matches_named_transport(self):
        for host in (NAME.upper(),NAME+":443",NAME+".","127.0.0.1","user@"+NAME):
            self.assertEqual(self.listing(host=host)[0],400)
        with patch.object(self.transport,"_server_name","api.sugarsync.com"):self.assertEqual(self.listing()[0],400)
        self.assertEqual(self.state.observed,set())

    def test_content_query_aliases_and_unissued_ids_are_rejected(self):
        self.issue()
        for path in (READ+"file2701?x=1",READ+"file2702",READ+"file9999",READ+"%66ile2701",
                     "//synthetic-content/file2701",READ+"../file2701"):
            self.assertEqual(self.request("GET",path)[0],400)
        self.assertEqual(self.state.payload_bytes,0)

    def test_duplicate_headers_body_framing_and_metadata_ranges_are_rejected(self):
        for headers in ((("Host",NAME),),(("Authorization",AUTH),),(("Content-Length","00"),),
                        (("Content-Length","4097"),),(("Transfer-Encoding","chunked"),),(("Range","bytes=0-1"),),
                        (("X-Client-Id",HEADERS["X-Client-Id"]),)):
            self.assertEqual(self.listing(headers=headers)[0],400)
        self.assertEqual(self.listing(body=b"x")[0],400);self.assertEqual(self.state.observed,set())

    def test_login_refresh_captcha_and_write_routes_remain_unqualified(self):
        for method,path in (("POST","/v1/auth/signin"),("POST","/v1/auth/token"),("POST","/v1/shield/captcha/init"),
                            ("POST",API),("PUT",READ+"file2701"),("HEAD",READ+"file2701"),("DELETE",API),
                            ("GET","https://elsewhere.invalid/")):
            self.assertEqual(self.request(method,path)[0],400)
        self.assertEqual((self.state.payload_bytes,self.state.rejected_mutations),(0,0))

    def test_extra_negotiation_cookie_and_unknown_api_headers_are_rejected(self):
        for headers in ((("Accept","application/json"),),(("Cookie","x=y"),),(("Content-Type","application/json"),),
                        (("X-Unknown","value"),)):
            self.assertEqual(self.listing(headers=headers)[0],400)
        self.assertEqual(self.state.observed,set())

    def test_request_and_response_budgets_prevent_success(self):
        self.state.request_limit=1;self.assertEqual(self.listing()[0],200);self.assertEqual(self.listing()[0],429)
        self.assertTrue(self.state.budget_exceeded)
        self.state.request_limit=10;self.state.byte_limit=1;self.assertEqual(self.listing()[0],429)

    def test_tls_deadline_stops_partial_headers(self):
        timer = threading.Timer
        with T.FixtureCertificates.create(self.root) as certificates, patch.object(
                T.threading, "Timer", side_effect=lambda delay, callback: timer(delay + 0.3, callback)):
            with T.BoundedHttpsServer(certificates, C.PikpakHandler, state=C.PikpakState(SECRET),
                    limits=T.TlsLimits(request_seconds=0.15)) as transport:
                with socket.create_connection(("127.0.0.1", transport.port), timeout=2) as raw:
                    with certificates.client_context().wrap_socket(raw, server_hostname="127.0.0.1") as client:
                        client.sendall(("GET " + API + " HTTP/1.1\r\nHost: " + NAME).encode())
                        self.assertEqual(client.recv(1), b"")
            self.assertIn("tls_request_deadline", transport.snapshot()["failure_codes"])
            self.assertTrue(transport.cleanup_complete)
        self.assertTrue(certificates.cleanup_complete)

class PikpakAuthorityTests(unittest.TestCase):
    def test_reviewed_name_has_its_own_exact_sni_and_san(self):
        with tempfile.TemporaryDirectory() as directory:
            with T.FixtureCertificates.create(Path(directory).resolve(), server_name=NAME) as certificates:
                from cryptography import x509
                leaf = x509.load_pem_x509_certificate((certificates.directory / "leaf.pem").read_bytes())
                self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value), [x509.DNSName(NAME)])
        self.assertIsNone(T._pikpak_sni(None, NAME, None))
        for name in (None, "", "fixture.pcloud.com", "api.cloudinary.com", "127.0.0.1", NAME + ".", NAME + ":443"):
            self.assertEqual(T._pikpak_sni(None, name, None), ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)
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
