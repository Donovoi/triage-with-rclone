"""Independent Google Photos app-created album wire contracts."""
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
    import fixture_gphotos as C
    import fixture_tls as T
finally:
    sys.path.pop(0)
API="photoslibrary.googleapis.com"
CONTENT="lh3.googleusercontent.com"
SECRET="synthetic-gphotos-token"
AUTH="Bearer "+SECRET
PAYLOADS={"README-synthetic.txt":b"Synthetic provider protocol fixture. No account or user data.\n",
          "nested/bytes.bin":bytes(range(256))*8,"nested/space name.txt":b"Nested synthetic payload.\n"}
IDS={"README-synthetic.txt":"synthetic-media-1","nested/bytes.bin":"synthetic-media-2",
     "nested/space name.txt":"synthetic-media-3"}

class GphotosWireTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.state=C.GphotosState(SECRET)
        self.certificates=self.enterContext(T.FixtureCertificates.create(self.root))
        self.transport=self.enterContext(T.BoundedHttpsServer(self.certificates,C.GphotosHandler,state=self.state))

    def request(self,method,path,auth=AUTH,host=API,headers=(),body=b""):
        client=http.client.HTTPSConnection("127.0.0.1",self.transport.port,timeout=3,context=self.certificates.client_context())
        try:
            client.putrequest(method,path,skip_host=True,skip_accept_encoding=True);client.putheader("Host",host)
            if auth is not None:client.putheader("Authorization",auth)
            if body:client.putheader("Content-Length",str(len(body)))
            for key,value in headers:client.putheader(key,value)
            client.endheaders(body);response=client.getresponse()
            return response.status,dict(response.getheaders()),response.read(65537)
        finally:client.close()

    def albums(self,**kwargs):
        return self.request("GET","/v1/albums?pageSize=50",**kwargs)

    def listing(self,nested=False,body=None,**kwargs):
        if body is None:body=json.dumps({"albumId":"synthetic-album-nested" if nested else "synthetic-album-root",
                                        "pageSize":100}).encode()
        return self.request("POST","/v1/mediaItems:search",body=body,headers=(("Content-Type","application/json"),),**kwargs)

    def target(self,name="README-synthetic.txt"):
        self.assertEqual(self.albums()[0],200)
        status,_,raw=self.listing("/" in name);self.assertEqual(status,200)
        item=next(x for x in json.loads(raw)["mediaItems"] if x["filename"]==name.rsplit("/",1)[-1])
        url=urllib.parse.urlsplit(item["baseUrl"])
        self.assertEqual((url.scheme,url.netloc,url.query,url.fragment),("https",CONTENT,"",""))
        self.assertRegex(url.path,"^/synthetic-content/"+IDS[name]+"/[a-f0-9]{32}$")
        return url.path+"=d"

    def test_album_inventory_is_complete_with_string_counts_and_nested_title(self):
        status,_,raw=self.albums();self.assertEqual(status,200)
        self.assertEqual(json.loads(raw),{"albums":[
            {"id":"synthetic-album-root","title":"Synthetic","mediaItemsCount":"1","isWriteable":False},
            {"id":"synthetic-album-nested","title":"Synthetic/nested","mediaItemsCount":"2","isWriteable":False}],
            "nextPageToken":""})

    def test_media_inventory_metadata_and_issued_url_match_literal_contract(self):
        self.assertEqual(self.albums()[0],200)
        for nested,names in ((False,["README-synthetic.txt"]),(True,["nested/bytes.bin","nested/space name.txt"])):
            status,_,raw=self.listing(nested);self.assertEqual(status,200);value=json.loads(raw)
            self.assertEqual(set(value),{"mediaItems","nextPageToken"});self.assertEqual(value["nextPageToken"],"")
            self.assertEqual([x["filename"] for x in value["mediaItems"]],[x.rsplit("/",1)[-1] for x in names])
            for item,name in zip(value["mediaItems"],names):
                url=item["baseUrl"];self.assertRegex(url,"^https://"+CONTENT.replace(".","\\.")+
                                                    "/synthetic-content/"+IDS[name]+"/[a-f0-9]{32}$")
                self.assertEqual(item,{"id":IDS[name],"filename":name.rsplit("/",1)[-1],
                    "productUrl":"https://photos.google.com/photo/"+IDS[name],"baseUrl":url,"mimeType":"image/jpeg",
                    "mediaMetadata":{"creationTime":"2024-01-01T00:00:00Z","width":"1","height":"1","photo":{}}})

    def test_search_requires_discovered_album_and_keeps_nested_scope(self):
        self.assertEqual(self.listing()[0],400);self.assertEqual(self.state.observed,set())
        self.assertEqual(self.albums()[0],200);self.assertEqual(self.listing(True)[0],200)
        self.assertEqual(self.state.observed,{"nested/bytes.bin","nested/space name.txt"})

    def test_album_listing_rejects_page_cursors_fields_and_alternate_api(self):
        for path in ("/v1/albums","/v1/albums?pageSize=1","/v1/albums?pageSize=50&pageToken=x",
                     "/v1/albums?pageSize=50&pageSize=50","/v1/albums?pageSize=50&extra=1","/v2/albums?pageSize=50"):
            self.assertEqual(self.request("GET",path)[0],400)
        self.assertEqual(self.state.album_observed,set())

    def test_search_rejects_wrong_scope_boolean_sizes_filters_and_pagination(self):
        self.assertEqual(self.albums()[0],200)
        base={"albumId":"synthetic-album-root","pageSize":100}
        for value in ({},[],dict(base,albumId="other"),dict(base,pageSize=True),dict(base,pageSize="100"),
                      dict(base,pageSize=100.0),dict(base,pageSize=1),dict(base,pageToken=""),
                      dict(base,filters={}),dict(base,extra=1)):
            self.assertEqual(self.listing(body=json.dumps(value).encode())[0],400)
        self.assertEqual(self.state.observed,set())

    def test_json_duplicates_invalid_constants_encoding_and_content_type_fail_closed(self):
        self.assertEqual(self.albums()[0],200)
        for body in (b'{"albumId":"synthetic-album-root","albumId":"other","pageSize":100}',
                     b'{"albumId":"synthetic-album-root","pageSize":NaN}',b'{',b'\xff',b'null'):
            self.assertEqual(self.listing(body=body)[0],400)
        body=b'{"albumId":"synthetic-album-root","pageSize":100}'
        for headers in ((),(("Content-Type","text/plain"),),(("Content-Type","application/json;charset=utf-8"),)):
            self.assertEqual(self.request("POST","/v1/mediaItems:search",body=body,headers=headers)[0],400)
        self.assertEqual(self.state.observed,set())

    def test_api_and_content_require_exact_saved_bearer(self):
        for auth in (None,SECRET,"Bearer wrong",AUTH+"extra"):
            self.assertEqual(self.albums(auth=auth)[0],401)
        self.assertEqual((self.state.denied,self.state.authenticated,self.state.payload_bytes),(4,0,0))
        target=self.target()
        for auth in (None,"Bearer wrong"):
            self.assertEqual(self.request("GET",target,host=CONTENT,auth=auth)[0],401)
        self.assertEqual(self.state.payload_bytes,0)

    def test_opaque_payloads_download_exactly_without_media_fidelity_claim(self):
        for name,body in PAYLOADS.items():
            self.assertEqual(self.request("GET",self.target(name),host=CONTENT)[::2],(200,body))
        self.assertEqual(self.state.payload_bytes,sum(map(len,PAYLOADS.values())))
        self.assertEqual(self.state.files,PAYLOADS)

    def test_head_provides_literal_size_without_payload_credit(self):
        for name,body in PAYLOADS.items():
            status,headers,raw=self.request("HEAD",self.target(name),host=CONTENT)
            self.assertEqual((status,int(headers["Content-Length"]),raw),(200,len(body),b""))
        self.assertEqual((self.state.heads,self.state.payload_bytes),(3,0))

    def test_download_requires_issued_url_identity_signature_and_image_suffix(self):
        path="/synthetic-content/synthetic-media-1/"+"0"*32+"=d"
        self.assertEqual(self.request("GET",path,host=CONTENT)[0],400)
        target=self.target()
        for bad in (target[:-2],target+"v",target+"?x=1",target.replace("synthetic-media-1","synthetic-media-2"),
                    target.replace("/"+target.rsplit("/",1)[1],"/"+"0"*32+"=d"),
                    target.replace("synthetic-media-1","%73ynthetic-media-1")):
            self.assertEqual(self.request("GET",bad,host=CONTENT)[0],400)
        self.assertEqual(self.state.payload_bytes,0)

    def test_issued_signature_is_bound_to_current_private_fixture_instance(self):
        target=self.target()
        with patch.dict(self.state.tokens,{"README-synthetic.txt":"0"*32}):
            self.assertEqual(self.request("GET",target,host=CONTENT)[0],400)
        self.assertEqual(self.state.payload_bytes,0)

    def test_http403_contains_identical_expected_bytes_and_head_still_reports_size(self):
        target=self.target();self.state.mode="read_denied"
        self.assertEqual(self.request("GET",target,host=CONTENT)[::2],(403,PAYLOADS["README-synthetic.txt"]))
        status,headers,raw=self.request("HEAD",target,host=CONTENT)
        self.assertEqual((status,int(headers["Content-Length"]),raw),(200,len(PAYLOADS["README-synthetic.txt"]),b""))
        self.assertEqual((self.state.read_denied,self.state.payload_bytes),(1,0))

    def test_ranges_are_bounded_and_rejected_on_head_or_metadata(self):
        target=self.target("nested/bytes.bin")
        status,h,raw=self.request("GET",target,host=CONTENT,headers=(("Range","bytes=1-7"),))
        self.assertEqual((status,h["Content-Range"],raw),(206,"bytes 1-7/2048",PAYLOADS["nested/bytes.bin"][1:8]))
        status,h,raw=self.request("GET",target,host=CONTENT,headers=(("Range","bytes=0-4096"),))
        self.assertEqual((status,h["Content-Range"],raw),(206,"bytes 0-2047/2048",PAYLOADS["nested/bytes.bin"]))
        for value in ("bytes=-2","bytes=7-1","bytes=2048-","bytes=0-1,4-5"):
            self.assertEqual(self.request("GET",target,host=CONTENT,headers=(("Range",value),))[0],416)
        self.assertEqual(self.request("HEAD",target,host=CONTENT,headers=(("Range","bytes=0-1"),))[0],400)
        self.assertEqual(self.albums(headers=(("Range","bytes=0-1"),))[0],400)

    def test_direct_delete_guard_preserves_source_and_does_not_claim_native_write(self):
        target=self.target();self.assertEqual(self.request("DELETE",target,host=CONTENT)[0],405)
        self.assertEqual((self.state.rejected_mutations,self.state.payload_bytes),(1,0))
        self.assertEqual(self.state.files,PAYLOADS)

    def test_authorities_are_exact_and_api_content_routes_cannot_cross(self):
        target=self.target()
        for host in (API.upper(),API+":443",API+".","127.0.0.1","user@"+API):
            self.assertEqual(self.albums(host=host)[0],400)
        self.assertEqual(self.albums(host=CONTENT)[0],400)
        self.assertEqual(self.request("GET",target,host=API)[0],400)
        with patch.object(self.transport,"_server_name",API):
            self.assertEqual(self.request("GET",target,host=CONTENT)[0],400)
        self.assertEqual(self.state.payload_bytes,0)

    def test_duplicate_headers_ambiguous_framing_and_cookies_fail_closed(self):
        for headers in ((("Host",API),),(("Authorization",AUTH),),(("Content-Length","00"),),
                        (("Content-Length","4097"),),(("Transfer-Encoding","chunked"),),
                        (("Cookie","private=x"),),(("Content-Type","application/json"),)):
            self.assertEqual(self.albums(headers=headers)[0],400)
        self.assertEqual(self.albums(body=b"x")[0],400);self.assertEqual(self.state.album_observed,set())

    def test_shared_album_discovery_oauth_uploads_and_direct_metadata_are_unqualified(self):
        for method,path in (("GET","/v1/sharedAlbums?pageSize=50"),("POST","/oauth2/token"),
                            ("POST","/v1/uploads"),("PUT","/v1/albums/id"),("HEAD","/v1/albums?pageSize=50"),
                            ("DELETE","/v1/albums/id"),("GET","/v1/mediaItems/synthetic-media-1"),
                            ("GET","https://elsewhere.invalid/"),("GET","//v1/albums"),("GET","/v1/%zz")):
            self.assertEqual(self.request(method,path)[0],400)
        self.assertEqual((self.state.payload_bytes,self.state.rejected_mutations),(0,0))

    def test_request_response_and_deadline_budgets_cannot_pass(self):
        self.state.request_limit=1;self.assertEqual(self.albums()[0],200);self.assertEqual(self.albums()[0],429)
        self.assertTrue(self.state.budget_exceeded)
        self.state.request_limit=10;self.state.byte_limit=1;self.assertEqual(self.albums()[0],429)
        self.state.deadline=0;self.assertEqual(self.albums()[0],429)

    def test_tls_deadline_stops_partial_json_body_and_cleans_up(self):
        timer=threading.Timer
        with T.FixtureCertificates.create(self.root) as certificates, patch.object(
                T.threading,"Timer",side_effect=lambda delay,callback:timer(delay+0.3,callback)):
            with T.BoundedHttpsServer(certificates,C.GphotosHandler,state=C.GphotosState(SECRET),
                    limits=T.TlsLimits(request_seconds=0.15)) as transport:
                with socket.create_connection(("127.0.0.1",transport.port),timeout=2) as raw:
                    with certificates.client_context().wrap_socket(raw,server_hostname="127.0.0.1") as client:
                        request=("POST /v1/mediaItems:search HTTP/1.1\r\nHost: "+API+
                                 "\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n{")
                        client.sendall(request.encode());self.assertEqual(client.recv(1),b"")
            self.assertIn("tls_request_deadline",transport.snapshot()["failure_codes"])
            self.assertTrue(transport.cleanup_complete)
        self.assertTrue(certificates.cleanup_complete)

class GphotosAuthorityTests(unittest.TestCase):
    def test_both_reviewed_names_have_exact_distinct_sni_and_san(self):
        from cryptography import x509
        for name,callback in ((API,T._gphotos_api_sni),(CONTENT,T._gphotos_content_sni)):
            with tempfile.TemporaryDirectory() as directory:
                with T.FixtureCertificates.create(Path(directory).resolve(),server_name=name) as certificates:
                    leaf=x509.load_pem_x509_certificate((certificates.directory/"leaf.pem").read_bytes())
                    self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value),
                                     [x509.DNSName(name)])
            self.assertIsNone(callback(None,name,None))
            for bad in (None,"","fixture.pcloud.com","127.0.0.1",name+".",name+":443",
                        CONTENT if name==API else API):
                self.assertEqual(callback(None,bad,None),ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)
            self.assertEqual(T._pcloud_sni(None,name,None),ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)

    def test_fixed_addresses_and_port_are_linux_only_without_fallback(self):
        for name,address in ((API,"127.0.0.1"),(CONTENT,"127.0.0.2")):
            calls=[]
            def init(server,bind,handler):
                calls.append(bind);server.server_address=bind
            with patch.object(T.HTTPServer,"__init__",init),patch.object(T.sys,"platform","linux"):
                server=T._HttpServer(SimpleNamespace(_server_name=name),object,None)
                self.assertEqual(server.authority,name)
            self.assertEqual(calls,[(address,443)])
            with patch.object(T.HTTPServer,"__init__") as bind,patch.object(T.sys,"platform","win32"):
                with self.assertRaisesRegex(T.TlsError,"requires_linux"):
                    T._HttpServer(SimpleNamespace(_server_name=name),object,None)
                bind.assert_not_called()

    def test_listener_cleanup_checks_both_owned_addresses(self):
        transports=[SimpleNamespace(authority=API,port=443),SimpleNamespace(authority=CONTENT,port=443)]
        with patch.object(C.socket,"socket") as factory:
            sock=factory.return_value.__enter__.return_value;sock.connect_ex.side_effect=[111,111]
            self.assertTrue(C.listeners_closed(transports))
            self.assertEqual([call.args[0] for call in sock.connect_ex.call_args_list],
                             [("127.0.0.1",443),("127.0.0.2",443)])
            sock.connect_ex.side_effect=[111,0]
            self.assertFalse(C.listeners_closed(transports))

if __name__=="__main__":
    unittest.main()
