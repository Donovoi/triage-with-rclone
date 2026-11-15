"""Independent Sugarsync folder-read wire contracts; no vendor acceptance."""
import http.client
import json
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

LAB = Path(__file__).resolve().parents[1] / "provider-lab"
sys.path.insert(0, str(LAB))
try:
    import fixture_sugarsync as C
    import fixture_tls as T
finally:
    sys.path.pop(0)

NAME = "api.sugarsync.com"
CONTENT = "api.sugarsync.com"
SECRET = "synthetic-sugarsync-token"
API = "/folder/"
READ = "/file/"
ORIGIN = "https://api.sugarsync.com"
AUTH = ORIGIN + "/authorization/" + SECRET
PAYLOADS = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
            "nested/bytes.bin": bytes(range(256)) * 8, "nested/space name.txt": b"Nested synthetic payload.\n"}
IDS = {"README-synthetic.txt":"file2601","nested/bytes.bin":"file2602","nested/space name.txt":"file2603"}

class SugarsyncWireTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.state = C.SugarsyncState(SECRET)
        self.certificates = self.enterContext(T.FixtureCertificates.create(self.root))
        self.transport = self.enterContext(T.BoundedHttpsServer(self.certificates, C.SugarsyncHandler, state=self.state))

    def request(self, method, path, auth="auto", host=NAME, accept=None, headers=(), body=b""):
        if auth == "auto":
            auth = AUTH
        client = http.client.HTTPSConnection("127.0.0.1", self.transport.port, timeout=3,
                                             context=self.certificates.client_context())
        try:
            client.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            client.putheader("Host", host)
            if auth is not None:
                client.putheader("Authorization", auth)
            if accept is not None:
                client.putheader("Accept", accept)
            if body:
                client.putheader("Content-Length", str(len(body)))
            for key, value in headers:
                client.putheader(key, value)
            client.endheaders(body)
            response = client.getresponse()
            return response.status, dict(response.getheaders()), response.read(65537)
        finally:
            client.close()

    def listing(self, folder="synthetic-root", query="max=500&start=0", **kwargs):
        return self.request("GET",API+folder+"/contents"+("?" + query if query else ""),**kwargs)

    def content(self, name="README-synthetic.txt", observe=True, **kwargs):
        if observe:self.assertEqual(self.listing("synthetic-nested" if "/" in name else "synthetic-root")[0],200)
        return self.request("GET",READ+IDS[name]+"/data",**kwargs)

    def test_complete_xml_inventories_have_independent_typed_metadata_and_uri_references(self):
        for folder,names in (("synthetic-root",["README-synthetic.txt","nested"]),
                             ("synthetic-nested",["nested/bytes.bin","nested/space name.txt"])):
            status,headers,raw=self.listing(folder)
            self.assertEqual((status,headers["Content-Type"]),(200,"application/xml"))
            root=ET.fromstring(raw)
            self.assertEqual((root.tag,root.attrib),("collectionContents",{"start":"0","end":"1","hasMore":"false"}))
            self.assertEqual(len(root),len(names))
            for node,name in zip(root,names):
                if name=="nested":
                    self.assertEqual((node.tag,node.attrib),("collection",{"type":"folder"}))
                    expected={"displayName":"nested","ref":ORIGIN+"/folder/synthetic-nested",
                        "timeCreated":"2024-01-01T00:00:00Z","contents":ORIGIN+"/folder/synthetic-nested/contents"}
                else:
                    self.assertEqual((node.tag,node.attrib),("file",{}))
                    ref=ORIGIN+"/file/"+IDS[name]
                    expected={"displayName":name.rsplit("/",1)[-1],"ref":ref,"timeCreated":"2024-01-01T00:00:00Z",
                        "dsid":IDS[name],"parent":ORIGIN+"/folder/"+folder,"size":str(len(PAYLOADS[name])),
                        "lastModified":"2024-01-01T00:00:00Z","mediaType":"application/octet-stream",
                        "presentOnServer":"true","fileData":ref+"/data","versions":ref+"/versions"}
                self.assertEqual({x.tag:x.text for x in node},expected)
        self.assertEqual(self.state.observed,set(PAYLOADS))
        self.assertEqual(self.state.payload_bytes,0)

    def test_saved_authorization_is_an_exact_uri_without_bearer_prefix(self):
        for auth in (None,"",SECRET,"Bearer "+AUTH,AUTH+"wrong",AUTH.replace("https:","http:")):
            self.assertEqual(self.listing(auth=auth)[0],401)
        self.assertEqual(self.listing()[0],200)
        for auth in (None,"",SECRET,"Bearer "+AUTH):
            self.assertEqual(self.content(observe=False,auth=auth)[0],401)
        self.assertEqual((self.state.denied,self.state.payload_bytes),(10,0))

    def test_observed_file_identity_is_required_for_known_byte_downloads(self):
        self.assertEqual(self.content(observe=False)[0],400)
        for name,payload in PAYLOADS.items():self.assertEqual(self.content(name)[::2],(200,payload))
        self.assertEqual(self.state.files,PAYLOADS)
        self.assertEqual(self.state.payload_bytes,sum(map(len,PAYLOADS.values())))

    def test_missing_name_is_absent_from_complete_inventories(self):
        for folder in ("synthetic-root","synthetic-nested"):
            status,_,raw=self.listing(folder);self.assertEqual(status,200)
            root=ET.fromstring(raw);self.assertEqual(root.attrib["hasMore"],"false")
            self.assertNotIn("absent-synthetic.txt",[x.findtext("displayName") for x in root])
        self.assertEqual(self.request("GET",READ+"absent-synthetic.txt/data")[0],400)
        self.assertEqual(self.state.payload_bytes,0)

    def test_ranges_return_exact_bytes_and_reject_ambiguous_or_unbounded_forms(self):
        status,headers,raw=self.content("nested/bytes.bin",headers=(("Range","bytes=256-511"),))
        self.assertEqual((status,headers["Content-Range"],raw),(206,"bytes 256-511/2048",bytes(range(256))))
        for value in ("bytes=0--1","bytes=-1","bytes=2048-","bytes=2-1","bytes=0-1,3-4"):
            self.assertEqual(self.content("nested/bytes.bin",headers=(("Range",value),))[0],416)
        self.assertEqual(self.state.files,PAYLOADS)

    def test_403_denial_contains_identical_expected_object_bytes(self):
        self.assertEqual(self.listing()[0],200);self.state.mode="read_denied"
        status,headers,raw=self.content(observe=False)
        self.assertEqual((status,raw),(403,PAYLOADS["README-synthetic.txt"]))
        self.assertEqual(headers["Content-Length"],str(len(raw)))
        self.assertEqual((self.state.read_denied,self.state.payload_bytes),(1,0))
        self.assertEqual(self.state.files,PAYLOADS)

    def test_direct_mutation_guard_requires_credentials_and_observed_identity(self):
        path=READ+"file2601/data"
        self.assertEqual(self.request("DELETE",path)[0],400)
        self.assertEqual(self.listing()[0],200)
        self.assertEqual(self.request("DELETE",path,auth=None)[0],401)
        self.assertEqual(self.request("DELETE",path)[0],405)
        self.assertEqual((self.state.rejected_mutations,self.state.payload_bytes),(1,0))
        self.assertEqual(self.state.files,PAYLOADS)

    def test_pagination_queries_and_folder_scope_are_exact(self):
        for query in ("","max=500&start=1","max=1&start=0","max=500","max=500&start=0&start=0",
                      "max=500&start=0&token=x","max=500&start=%ff","max=500&start=%GG"):
            self.assertEqual(self.listing(query=query)[0],400)
        for folder in ("foreign","root","synthetic-root/","SYNTHETIC-ROOT","synthetic%2Droot"):
            self.assertEqual(self.listing(folder)[0],400)
        self.assertEqual(self.state.observed,set())

    def test_content_queries_aliases_and_unknown_ids_cannot_expand_scope(self):
        self.assertEqual(self.listing()[0],200)
        for path in (READ+"file2601/data?token=x",READ+"file2601/data/",READ+"FILE2601/data",
                     READ+"%66ile2601/data",READ+"foreign/data",READ+"file2601/../data",READ+"file2601"):
            self.assertEqual(self.request("GET",path)[0],400)
        self.assertEqual(self.state.payload_bytes,0)

    def test_authority_spelling_and_port_are_exact(self):
        for host in ("127.0.0.1",NAME+":443",NAME+".",NAME.upper(),"content.sugarsync.com"):
            self.assertEqual(self.listing(host=host)[0],400)
        self.assertEqual(self.state.observed,set())

    def test_host_must_match_named_transport_binding(self):
        with patch.object(self.transport,"_server_name","api.jottacloud.com"):
            self.assertEqual(self.listing()[0],400)
        self.assertEqual(self.state.payload_bytes,0)

    def test_extra_accept_and_credential_headers_are_rejected(self):
        for key,value in (("Cookie","x=y"),("Content-Type","application/xml"),("Accept","application/xml"),
                          ("X-SugarSync-API-Version","1.5"),("X-SugarSync-User","x")):
            self.assertEqual(self.listing(headers=((key,value),))[0],400)
        self.assertEqual(self.state.observed,set())

    def test_account_discovery_refresh_and_native_writes_remain_outside_scope(self):
        for method,path in (("GET","/user"),("POST","/authorization"),("POST","/app-authorization"),
                            ("GET",API+"synthetic-root"),("POST",API+"synthetic-root/contents"),
                            ("PUT",READ+"file2601/data"),("HEAD",READ+"file2601/data"),
                            ("DELETE",API+"synthetic-root/contents"),("GET","https://elsewhere.invalid/")):
            self.assertEqual(self.request(method,path)[0],400)
        self.assertEqual((self.state.payload_bytes,self.state.rejected_mutations),(0,0))

    def test_duplicate_headers_framing_and_metadata_ranges_are_rejected(self):
        for headers in ((("Host",NAME),),(("Authorization",AUTH),),(("Content-Length","00"),),
                        (("Content-Length","4097"),),(("Transfer-Encoding","chunked"),),(("Range","bytes=0-1"),)):
            self.assertEqual(self.listing(headers=headers)[0],400)
        self.assertEqual(self.listing(body=b"x")[0],400)
        self.assertEqual(self.state.observed,set())

    def test_request_and_response_budgets_prevent_success(self):
        self.state.request_limit=1
        self.assertEqual(self.listing()[0],200);self.assertEqual(self.listing()[0],429)
        self.assertTrue(self.state.budget_exceeded)
        self.state.request_limit=10;self.state.byte_limit=1
        self.assertEqual(self.listing()[0],429)

    def test_tls_deadline_stops_partial_headers(self):
        timer = threading.Timer
        with T.FixtureCertificates.create(self.root) as certificates, patch.object(
                T.threading, "Timer", side_effect=lambda delay, callback: timer(delay + 0.3, callback)):
            with T.BoundedHttpsServer(certificates, C.SugarsyncHandler, state=C.SugarsyncState(SECRET),
                    limits=T.TlsLimits(request_seconds=0.15)) as transport:
                with socket.create_connection(("127.0.0.1", transport.port), timeout=2) as raw:
                    with certificates.client_context().wrap_socket(raw, server_hostname="127.0.0.1") as client:
                        client.sendall(("GET " + API + " HTTP/1.1\r\nHost: " + NAME).encode())
                        self.assertEqual(client.recv(1), b"")
            self.assertIn("tls_request_deadline", transport.snapshot()["failure_codes"])
            self.assertTrue(transport.cleanup_complete)
        self.assertTrue(certificates.cleanup_complete)

class SugarsyncAuthorityTests(unittest.TestCase):
    def test_reviewed_name_has_its_own_exact_sni_and_san(self):
        with tempfile.TemporaryDirectory() as directory:
            with T.FixtureCertificates.create(Path(directory).resolve(), server_name=NAME) as certificates:
                from cryptography import x509
                leaf = x509.load_pem_x509_certificate((certificates.directory / "leaf.pem").read_bytes())
                self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value), [x509.DNSName(NAME)])
        self.assertIsNone(T._sugarsync_sni(None, NAME, None))
        for name in (None, "", "fixture.pcloud.com", "api.cloudinary.com", "127.0.0.1", NAME + ".", NAME + ":443"):
            self.assertEqual(T._sugarsync_sni(None, name, None), ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)
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
