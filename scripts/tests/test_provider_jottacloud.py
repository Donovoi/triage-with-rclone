"""Independent Jottacloud folder-read wire contracts; no vendor acceptance."""
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
    import fixture_jottacloud as C
    import fixture_tls as T
finally:
    sys.path.pop(0)

NAME = "api.jottacloud.com"
CONTENT = "jfs.jottacloud.com"
SECRET = "synthetic-jottacloud-token"
API = "/account/v1/customer"
READ = "/jfs/synthetic-user/Jotta/Archive/synthetic-root"
PAYLOADS = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
            "nested/bytes.bin": bytes(range(256)) * 8, "nested/space name.txt": b"Nested synthetic payload.\n"}
MD5 = {"README-synthetic.txt":"f9ac90560b9929242009ee0c24c9e5d8",
       "nested/bytes.bin":"1576a94d6cb334dd126cb1c27f19e0f2",
       "nested/space name.txt":"371d24ba264bcaac3332a3ed564a93f8"}

class JottacloudWireTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.state = C.JottacloudState(SECRET)
        self.certificates = self.enterContext(T.FixtureCertificates.create(self.root))
        self.transport = self.enterContext(T.BoundedHttpsServer(self.certificates, C.JottacloudHandler, state=self.state))

    def request(self, method, path, auth="auto", host=NAME, accept=None, headers=(), body=b""):
        if auth == "auto":
            auth = "Bearer " + SECRET
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

    def customer(self, **kwargs):
        return self.request("GET", API, **kwargs)

    def listing(self, directory="", query="", **kwargs):
        return self.request("GET",READ + ("/" + urllib.parse.quote(directory,safe="/") if directory else "")
                            + ("?" + query if query else ""), **({"host":CONTENT} | kwargs))

    def content(self, name="README-synthetic.txt", observe=True, **kwargs):
        if observe:
            self.assertEqual(self.listing(name.rpartition("/")[0])[0],200)
        return self.request("GET",READ + "/" + urllib.parse.quote(name,safe="/") + "?mode=bin",
                            **({"host":CONTENT} | kwargs))

    def check_file(self, node, name):
        self.assertEqual(node.tag,"file")
        self.assertEqual(node.attrib,{"name":name.rsplit("/",1)[-1]})
        revision=node.find("currentRevision")
        self.assertEqual({x.tag:x.text for x in revision}, {"number":"1","state":"COMPLETED",
            "created":"2024-01-01-T00:00:00Z","modified":"2024-01-01-T00:00:00Z","updated":"2024-01-01-T00:00:00Z",
            "mime":"application/octet-stream","size":str(len(PAYLOADS[name])),"md5":MD5[name]})

    def test_customer_json_selects_the_exact_internal_username(self):
        status,headers,raw=self.customer()
        self.assertEqual((status,json.loads(raw)),(200,{"username":"synthetic-user"}))
        self.assertIn("application/json",headers["Content-Type"])
        self.assertEqual((self.state.customers,self.state.payload_bytes),(1,0))

    def test_directory_xml_has_complete_children_and_independent_revision_fields(self):
        for directory,names in (("",["README-synthetic.txt"]),("nested",["nested/bytes.bin","nested/space name.txt"])):
            status,headers,raw=self.listing(directory)
            self.assertEqual((status,headers["Content-Type"]),(200,"application/xml"))
            root=ET.fromstring(raw)
            self.assertEqual(root.tag,"folder")
            self.assertEqual(root.attrib,{"name":directory or "synthetic-root"})
            self.assertEqual(root.findtext("path"),"/Archive/synthetic-root"+("/"+directory if directory else ""))
            self.assertEqual([x.attrib["name"] for x in root.findall("folders/folder")],["nested"] if not directory else [])
            files=root.findall("files/file")
            self.assertEqual(len(files),len(names))
            for node,name in zip(files,names):self.check_file(node,name)
        self.assertEqual(self.state.observed,set(PAYLOADS))
        self.assertEqual(self.state.payload_bytes,0)

    def test_liststream_xml_has_exact_paths_counts_and_known_md5(self):
        for directory,names,folders in (("",sorted(PAYLOADS),["","nested"]),
                                      ("nested",["nested/bytes.bin","nested/space name.txt"],["nested"])):
            status,_,raw=self.listing(directory,query="mode=liststream")
            self.assertEqual(status,200);root=ET.fromstring(raw)
            self.assertEqual([x.findtext("path") for x in root.findall("folder")],
                ["/Archive/synthetic-root"+("/"+x if x else "") for x in folders])
            self.assertEqual({x.tag:x.text for x in root.find("stats")},{"folders":str(len(folders)),"files":str(len(names))})
            actual=[{x.tag:x.text for x in node} for node in root.findall("file")]
            expected=[{"path":"/Archive/synthetic-root"+("/nested" if "/" in n else ""),
                "filename":n.rsplit("/",1)[-1],"md5":MD5[n],"size":str(len(PAYLOADS[n])),
                "modified":"2024-01-01T00:00:00Z","created":"2024-01-01T00:00:00Z"} for n in names]
            self.assertEqual(actual,expected)
        self.assertEqual((self.state.stream_lists,self.state.payload_bytes),(2,0))

    def test_saved_bearer_is_required_on_both_authorities(self):
        for auth in (None,"","Basic "+SECRET,"Bearer wrong","bearer "+SECRET):
            self.assertEqual(self.customer(auth=auth)[0],401)
            self.assertEqual(self.listing(auth=auth)[0],401)
        self.assertEqual((self.state.denied,self.state.payload_bytes),(10,0))

    def test_object_metadata_observes_exact_path_and_content_requires_observation(self):
        self.assertEqual(self.content(observe=False)[0],400)
        for name,payload in PAYLOADS.items():
            status,_,raw=self.listing(name)
            self.assertEqual(status,200);self.check_file(ET.fromstring(raw),name)
            self.assertEqual(self.content(name,observe=False)[::2],(200,payload))
        self.assertEqual(self.state.payload_bytes,sum(map(len,PAYLOADS.values())))
        self.assertEqual(self.state.files,PAYLOADS)

    def test_missing_object_returns_explicit_xml_404(self):
        status,_,raw=self.listing("absent-synthetic.txt")
        root=ET.fromstring(raw)
        self.assertEqual((status,root.tag,root.findtext("code")),(404,"error","404"))
        self.assertEqual((self.state.missing,self.state.payload_bytes),(1,0))
        self.assertEqual(self.listing("unknown")[0],400)

    def test_content_ranges_are_bounded_and_malformed_ranges_fail(self):
        status,headers,raw=self.content("nested/bytes.bin",headers=(("Range","bytes=256-511"),))
        self.assertEqual((status,headers["Content-Range"],raw),(206,"bytes 256-511/2048",bytes(range(256))))
        for value in ("bytes=0--1","bytes=-1","bytes=2048-","bytes=2-1","bytes=0-1,3-4"):
            self.assertEqual(self.content("nested/bytes.bin",headers=(("Range",value),))[0],416)
        self.assertEqual(self.state.files,PAYLOADS)

    def test_denied_content_is_identical_to_expected_bytes_but_has_error_status(self):
        self.assertEqual(self.listing()[0],200);self.state.mode="read_denied"
        status,headers,raw=self.content(observe=False)
        self.assertEqual((status,raw),(403,PAYLOADS["README-synthetic.txt"]))
        self.assertEqual(headers["Content-Length"],str(len(raw)))
        self.assertEqual((self.state.read_denied,self.state.payload_bytes),(1,0))
        self.assertEqual(self.state.files,PAYLOADS)

    def test_direct_delete_requires_observation_and_saved_credentials(self):
        path=READ+"/README-synthetic.txt"
        self.assertEqual(self.request("DELETE",path,host=CONTENT)[0],400)
        self.assertEqual(self.listing()[0],200)
        self.assertEqual(self.request("DELETE",path,host=CONTENT,auth=None)[0],401)
        self.assertEqual(self.request("DELETE",path,host=CONTENT)[0],405)
        self.assertEqual((self.state.rejected_mutations,self.state.payload_bytes),(1,0))
        self.assertEqual(self.state.files,PAYLOADS)

    def test_modes_queries_and_canonical_paths_cannot_expand_scope(self):
        for query in ("mode=bin","mode=LISTSTREAM","mode=liststream&mode=liststream","mode=liststream&token=x",
                      "mode=","mode=%ff","mode=%GG","mkDir=true"):
            self.assertEqual(self.listing(query=query)[0],400)
        for path in (READ+"/",READ+"/nested/",READ.replace("Archive","Sync"),
                     READ.replace("synthetic-root","foreign"),READ+"/%6Eested",READ+"/nested%2Fbytes.bin",
                     READ+"/../README-synthetic.txt",READ+"/nested/bytes.bin?mode=liststream"):
            self.assertEqual(self.request("GET",path,host=CONTENT)[0],400)
        self.assertEqual(self.state.observed,set())

    def test_route_authorities_cannot_be_swapped_or_aliased(self):
        for host in (CONTENT,NAME+":443",NAME+".",NAME.upper(),"127.0.0.1"):
            self.assertEqual(self.customer(host=host)[0],400)
        for host in (NAME,CONTENT+":443",CONTENT+".",CONTENT.upper(),"127.0.0.2"):
            self.assertEqual(self.listing(host=host)[0],400)
        self.assertEqual(self.state.payload_bytes,0)

    def test_transport_certificate_binding_matches_route_host(self):
        with patch.object(self.transport,"_server_name",CONTENT):
            self.assertEqual(self.customer()[0],400)
        with patch.object(self.transport,"_server_name",NAME):
            self.assertEqual(self.listing()[0],400)
        self.assertEqual(self.state.payload_bytes,0)

    def test_discovery_beyond_customer_and_mutations_stay_outside_scope(self):
        for method,path,host in (("GET","/account/v1/customer?token=x",NAME),
                ("GET","/account/v1/customer/",NAME),("GET","/auth/realms/jottacloud",NAME),
                ("GET","/jfs/synthetic-user",CONTENT),("GET","/jfs/synthetic-user/Jotta/Archive",CONTENT),
                ("POST",READ,CONTENT),("PUT",READ+"/README-synthetic.txt",CONTENT),
                ("DELETE",API,NAME),("GET","https://elsewhere.invalid/",CONTENT)):
            self.assertEqual(self.request(method,path,host=host)[0],400)
        self.assertEqual((self.state.payload_bytes,self.state.rejected_mutations),(0,0))

    def test_headers_framing_and_metadata_ranges_fail_closed(self):
        for headers in ((("Host",CONTENT),),(("Authorization","Bearer x"),),(("Content-Length","00"),),
                (("Content-Length","4097"),),(("Transfer-Encoding","chunked"),),(("Range","bytes=0-1"),),
                (("Cookie","x=y"),),(("Content-Type","application/xml"),),(("Accept","application/xml"),),
                (("X-Jotta-User","x"),),(("X-Jottacloud-Token","x"),)):
            self.assertEqual(self.listing(headers=headers)[0],400)
        self.assertEqual(self.listing(body=b"x")[0],400)
        self.assertEqual(self.state.observed,set())

    def test_request_and_response_limits_prevent_success(self):
        self.state.request_limit=1
        self.assertEqual(self.listing()[0],200);self.assertEqual(self.listing()[0],429)
        self.assertTrue(self.state.budget_exceeded)
        self.state.request_limit=10;self.state.byte_limit=1
        self.assertEqual(self.listing()[0],429)

    def test_tls_deadline_stops_partial_headers(self):
        timer = threading.Timer
        with T.FixtureCertificates.create(self.root) as certificates, patch.object(
                T.threading, "Timer", side_effect=lambda delay, callback: timer(delay + 0.3, callback)):
            with T.BoundedHttpsServer(certificates, C.JottacloudHandler, state=C.JottacloudState(SECRET),
                    limits=T.TlsLimits(request_seconds=0.15)) as transport:
                with socket.create_connection(("127.0.0.1", transport.port), timeout=2) as raw:
                    with certificates.client_context().wrap_socket(raw, server_hostname="127.0.0.1") as client:
                        client.sendall(("GET " + API + " HTTP/1.1\r\nHost: " + NAME).encode())
                        self.assertEqual(client.recv(1), b"")
            self.assertIn("tls_request_deadline", transport.snapshot()["failure_codes"])
            self.assertTrue(transport.cleanup_complete)
        self.assertTrue(certificates.cleanup_complete)

class JottacloudAuthorityTests(unittest.TestCase):
    def test_each_authority_has_distinct_exact_sni_and_single_name_certificate(self):
        from cryptography import x509
        for name, callback in ((NAME, T._jottacloud_api_sni), (CONTENT, T._jottacloud_content_sni)):
            with tempfile.TemporaryDirectory() as directory:
                with T.FixtureCertificates.create(Path(directory).resolve(), server_name=name) as certificates:
                    leaf = x509.load_pem_x509_certificate((certificates.directory / "leaf.pem").read_bytes())
                    self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value), [x509.DNSName(name)])
            self.assertIsNone(callback(None, name, None))
            for wrong in (None, "", CONTENT if name == NAME else NAME, name + ".", name + ":443", "127.0.0.1"):
                self.assertEqual(callback(None, wrong, None), ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)
            self.assertEqual(T._drive_sni(None, name, None), ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)

    def test_only_reviewed_content_authority_selects_second_linux_loopback_listener(self):
        calls = []
        def init(server, address, handler):
            calls.append(address);server.server_address = address
        with patch.object(T.HTTPServer, "__init__", init), patch.object(T.sys, "platform", "linux"):
            for name in (NAME, CONTENT, T.DRIVE_API_NAME, None):
                T._HttpServer(SimpleNamespace(_server_name=name), object, None)
        self.assertEqual(calls, [("127.0.0.1", 443), ("127.0.0.2", 443), ("127.0.0.1", 443), ("127.0.0.1", 0)])
        with patch.object(T.HTTPServer, "__init__") as bind, patch.object(T.sys, "platform", "win32"):
            for name in (NAME, CONTENT):
                with self.assertRaisesRegex(T.TlsError, "requires_linux"):
                    T._HttpServer(SimpleNamespace(_server_name=name), object, None)
            bind.assert_not_called()

class JottacloudPairCleanupTests(unittest.TestCase):
    def pair(self, fail_start=False, fail_close=False):
        certificates, transports, events = [], [], []
        class Certificate:
            cleanup_complete = False
            def __init__(self, name):
                self.server_name = name
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.cleanup_complete = True
                events.append(("certificate_closed", self.server_name))
        class Transport:
            cleanup_complete = False
            def __init__(self, certificate, handler, **kwargs):
                self.authority = certificate.server_name
                transports.append(self)
            def start(self):
                events.append(("started", self.authority))
                if fail_start and self.authority == CONTENT:
                    raise RuntimeError("synthetic_start_failed")
                return self
            def close(self):
                events.append(("closed", self.authority))
                self.cleanup_complete = not (fail_close and self.authority == CONTENT)
                return self.cleanup_complete
        def create(root, server_name):
            cert = Certificate(server_name);certificates.append(cert);return cert
        return create, Transport, certificates, transports, events

    def test_second_listener_start_failure_still_closes_both_transports_and_certificates(self):
        create, transport, certificates, transports, events = self.pair(fail_start=True)
        state = C.JottacloudState(SECRET)
        with patch.object(C.FixtureCertificates, "create", side_effect=create), patch.object(C, "BoundedHttpsServer", transport), \
             patch.object(C, "listeners_closed", return_value=True):
            with self.assertRaisesRegex(RuntimeError, "synthetic_start_failed"):
                with C.serve_jottacloud(Path("/synthetic"), state):
                    self.fail("startup must fail")
        self.assertEqual([name for event, name in events if event == "closed"], [CONTENT, NAME])
        self.assertTrue(all(t.cleanup_complete for t in transports))
        self.assertTrue(all(c.cleanup_complete for c in certificates))
        self.assertTrue(state.cleanup_complete)

    def test_failed_content_cleanup_is_not_hidden_by_successful_api_cleanup(self):
        create, transport, certificates, transports, events = self.pair(fail_close=True)
        state = C.JottacloudState(SECRET)
        with patch.object(C.FixtureCertificates, "create", side_effect=create), patch.object(C, "BoundedHttpsServer", transport), \
             patch.object(C, "listeners_closed", return_value=True):
            with self.assertRaisesRegex(RuntimeError, "jottacloud_cleanup_failed"):
                with C.serve_jottacloud(Path("/synthetic"), state):
                    pass
        self.assertEqual([name for event, name in events if event == "closed"], [CONTENT, NAME])
        self.assertTrue(all(c.cleanup_complete for c in certificates))
        self.assertFalse(state.cleanup_complete)

if __name__ == "__main__":
    unittest.main()
