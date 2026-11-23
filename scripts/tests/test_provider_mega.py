"""Mega saved-session, encrypted content and bounded authority contracts."""
import base64
import hashlib
import http.client
import json
from pathlib import Path
import socket
import ssl
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.parse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
LAB=Path(__file__).resolve().parents[1]/"provider-lab"
sys.path.insert(0,str(LAB))
try:
    import fixture_mega as C
    import fixture_tls as T
finally:sys.path.pop(0)
API="g.api.mega.co.nz";CONTENT="synthetic-content.mega.invalid";EVENTS=API
PAYLOADS={"README-synthetic.txt":b"Synthetic provider protocol fixture. No account or user data.\n",
          "nested/bytes.bin":bytes(range(256))*8,"nested/space name.txt":b"Nested synthetic payload.\n"}
CIPHER_SHA={"README-synthetic.txt":"0b6286b517736a9f530b68af20d34faceab8b00e45730eb857107a79318ba17a",
            "nested/bytes.bin":"eab4be66bfdc37e1bc2e59f0c8bea9ffbc130e69acb472efdf2582cfdca07d96",
            "nested/space name.txt":"d40921da901193b69c2f848cb3821525928a7959195f4a4576d0e85638710915"}
def decode(v):return base64.urlsafe_b64decode(v+"="*((-len(v))%4))
def decrypt(key,mode,value):
    d=Cipher(algorithms.AES(key),mode).decryptor()
    return d.update(value)+d.finalize()

class MegaWireTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.state=C.MegaState("synthetic-secret")
        self.certificates=self.enterContext(T.FixtureCertificates.create(self.root))
        self.transport=self.enterContext(T.BoundedHttpsServer(self.certificates,C.MegaHandler,state=self.state))

    def request(self,method,path,host=API,body=None,headers=(),raw=None,content_type=None):
        client=http.client.HTTPSConnection("127.0.0.1",self.transport.port,timeout=3,context=self.certificates.client_context())
        data=json.dumps(body,separators=(",",":")).encode() if body is not None else (raw or b"")
        try:
            client.putrequest(method,path,skip_host=True,skip_accept_encoding=True)
            client.putheader("Host",host)
            if method=="POST":
                client.putheader("Content-Type",content_type or ("application/xml" if path.startswith("/sc?") else "application/json"))
                client.putheader("Content-Length",str(len(data)))
            for key,value in headers:client.putheader(key,value)
            client.endheaders(data);response=client.getresponse()
            return response.status,dict(response.getheaders()),response.read(65537)
        finally:client.close()

    def api(self,message,sid="synthetic-secret"):
        return self.request("POST","/cs?id=123&sid="+sid,body=[message])

    def listing(self):
        result=self.api({"a":"f","c":1});self.assertEqual(result[0],200)
        return json.loads(result[2])[0]

    def issue(self,name="README-synthetic.txt"):
        self.listing()
        result=self.api({"a":"g","g":1,"n":self.state.ids[name],"ssl":2})
        self.assertEqual(result[0],200);info=json.loads(result[2])[0]
        url=urllib.parse.urlsplit(info["g"])
        self.assertEqual((url.scheme,url.netloc,url.query),("https",CONTENT,""))
        self.assertEqual(info["s"],len(PAYLOADS[name]))
        return url.path+"/0-"+str(info["s"]-1),info

    def test_wrong_saved_sessions_do_not_disclose_nodes_or_payloads(self):
        for sid in ("wrong","","synthetic-secret%20"):
            status,_,raw=self.api({"a":"f","c":1},sid=sid)
            self.assertEqual((status,json.loads(raw)),(200,[-15]))
        self.assertEqual((self.state.denied,self.state.payload_bytes,self.state.observed),(3,0,set()))

    def test_inventory_has_exact_root_folder_and_independently_decryptable_nodes(self):
        listing=self.listing();nodes=listing["f"]
        self.assertEqual(set(listing),{"f","ok","s","u","sn"})
        self.assertEqual((listing["sn"],len(nodes)),("synthetic-sequence",5))
        self.assertEqual((nodes[0]["h"],nodes[0]["t"],nodes[1]["p"]),("AAAAAAAB",2,"AAAAAAAB"))
        names=set()
        for node in nodes[1:]:
            owner,wrapped=node["k"].split(":");self.assertEqual(owner,node["u"])
            compound=decrypt(bytes.fromhex("00112233445566778899aabbccddeeff"),modes.ECB(),decode(wrapped))
            if node["t"]==0:
                words=struct.unpack(">8I",compound)
                key=struct.pack(">4I",*(words[i]^words[i+4] for i in range(4)))
            else:key=compound
            plain=decrypt(key,modes.CBC(bytes(16)),decode(node["a"])).rstrip(b"\0")
            self.assertTrue(plain.startswith(b"MEGA"))
            name=json.loads(plain[4:])["n"];names.add(name)
            if node["t"]==0:
                path=("nested/" if node["p"]=="AAAAAAAC" else "")+name
                self.assertEqual(node["s"],len(PAYLOADS[path]))
                nonce=struct.pack(">2I",words[4],words[5])
                decoded=decrypt(key,modes.CTR(nonce+bytes(8)),self.state.ciphertext[path])
                self.assertEqual(decoded,PAYLOADS[path])
        self.assertEqual(names,{"nested","README-synthetic.txt","bytes.bin","space name.txt"})

    def test_unknown_or_unobserved_node_cannot_issue_url(self):
        self.assertEqual(self.api({"a":"g","g":1,"n":self.state.ids["README-synthetic.txt"],"ssl":2})[0],400)
        self.listing()
        self.assertEqual(self.api({"a":"g","g":1,"n":"AAAAAAAA","ssl":2})[0],400)
        self.assertEqual(self.state.links,{})

    def test_api_command_types_fields_and_duplicate_keys_are_strict(self):
        for body in ([],{},[{}],[{"a":"f","c":1,"extra":0}],[{"a":"f","c":True}],
                     [{"a":"f","c":1.0}],[{"a":"f","c":1}]*2,[{"a":"g","g":True,"n":"x","ssl":2}],
                     [{"a":"g","g":1,"n":[],"ssl":2}],[{"a":"f","c":1.5}]):
            self.assertEqual(self.request("POST","/cs?id=123&sid=synthetic-secret",body=body)[0],400)
        for raw in (b'[{"a":"f","a":"f","c":1}]',b'NaN',b'[',b'[{"a":"f","c":NaN}]'):
            self.assertEqual(self.request("POST","/cs?id=123&sid=synthetic-secret",raw=raw)[0],400)
        self.assertEqual(self.state.observed,set())

    def test_api_query_names_duplicates_and_methods_are_strict(self):
        for query in ("id=1","id=1&sid=synthetic-secret&extra=1","id=x&sid=synthetic-secret",
                      "id=1&id=1&sid=synthetic-secret","id=1&sid=synthetic-secret&sid=wrong"):
            self.assertEqual(self.request("POST","/cs?"+query,body=[{"a":"f","c":1}])[0],400)
        for method in ("GET","PUT","DELETE","HEAD"):
            self.assertEqual(self.request(method,"/cs?id=1&sid=synthetic-secret")[0],400)
        self.assertEqual(self.state.observed,set())

    def test_issued_urls_are_fresh_file_bound_and_exact_chunk_only(self):
        first,_=self.issue();second,_=self.issue();self.assertNotEqual(first,second)
        for target in (first.replace(self.state.ids["README-synthetic.txt"],self.state.ids["nested/bytes.bin"]),
                       first.replace("/0-61","/0-60"),first.replace("/0-61","/3-13"),
                       first.replace("/0-61","/0-061"),first+"?extra=1",first.replace("/file/","/file//")):
            self.assertEqual(self.request("GET",target,host=CONTENT)[0],400)
        self.assertEqual(self.state.payload_bytes,0)

    def test_ciphertext_matches_literal_vectors_and_plaintext_is_unchanged(self):
        for name,payload in PAYLOADS.items():
            target,_=self.issue(name);status,_,data=self.request("GET",target,host=CONTENT)
            self.assertEqual(status,200);self.assertEqual(len(data),len(payload));self.assertNotEqual(data,payload)
            self.assertEqual(hashlib.sha256(data).hexdigest(),CIPHER_SHA[name])
        self.assertEqual(self.state.files,PAYLOADS)

    def test_http_denial_returns_identical_valid_ciphertext(self):
        target,_=self.issue();good=self.request("GET",target,host=CONTENT)[2]
        before=self.state.payload_bytes;self.state.mode="read_denied"
        self.assertEqual(self.request("GET",target,host=CONTENT)[::2],(403,good))
        self.assertEqual((self.state.read_denied,self.state.payload_bytes),(1,before))

    def test_content_rejects_credentials_cookies_and_http_range(self):
        target,_=self.issue()
        for headers in ((("Authorization","Bearer synthetic-secret"),),(("Cookie","sid=synthetic-secret"),),(("Range","bytes=0-1"),)):
            self.assertEqual(self.request("GET",target,host=CONTENT,headers=headers)[0],400)
        self.assertEqual(self.state.payload_bytes,0)

    def test_direct_delete_guard_preserves_source(self):
        target,_=self.issue()
        self.assertEqual(self.request("DELETE",target,host=CONTENT)[0],405)
        self.assertEqual((self.state.rejected_mutations,self.state.payload_bytes),(1,0))
        self.assertEqual(self.state.files,PAYLOADS)

    def test_event_wait_requires_session_sequence_and_single_use_discovered_url(self):
        path="/sc?sn=synthetic-sequence&sid=synthetic-secret"
        for bad in (path.replace("synthetic-secret","wrong"),):
            self.assertEqual(json.loads(self.request("POST",bad)[2]),[-15])
        for bad in (path.replace("synthetic-sequence","wrong"),path+"&extra=1"):
            self.assertEqual(self.request("POST",bad)[0],400)
        self.assertEqual(self.request("POST",path,body={})[0],400)
        status,_,raw=self.request("POST",path);self.assertEqual(status,200)
        url=urllib.parse.urlsplit(json.loads(raw)["w"])
        self.assertEqual((url.scheme,url.netloc),("https",EVENTS))
        self.assertEqual(self.request("GET",url.path,host=EVENTS)[0],200)
        self.assertEqual(self.request("GET",url.path,host=EVENTS)[0],400)
        self.assertEqual(self.request("GET","/wait/"+"f"*32,host=EVENTS)[0],400)

    def test_event_wait_rejects_auth_leakage_and_wrong_authority(self):
        path="/sc?sn=synthetic-sequence&sid=synthetic-secret"
        url=urllib.parse.urlsplit(json.loads(self.request("POST",path)[2])["w"])
        for host,headers in ((CONTENT,()),(EVENTS,(("Cookie","secret"),)),(EVENTS,(("Authorization","secret"),))):
            self.assertEqual(self.request("GET",url.path,host=host,headers=headers)[0],400)
        self.assertEqual(len(self.state.waits),1)

    def test_authority_sni_and_route_bindings_are_exact(self):
        for host in (API.upper(),API+":443",API+".","127.0.0.1",CONTENT):
            self.assertEqual(self.request("POST","/cs?id=1&sid=synthetic-secret",host=host,body=[{"a":"f","c":1}])[0],400)
        with patch.object(self.transport,"_server_name",CONTENT):
            self.assertEqual(self.api({"a":"f","c":1})[0],400)

    def test_duplicate_headers_framing_and_target_aliases_are_rejected(self):
        for headers in ((("Host",API),),(("Content-Length","0"),),(("Transfer-Encoding","chunked"),),
                        (("Authorization","x"),),(("Cookie","x"),)):
            self.assertEqual(self.request("POST","/cs?id=1&sid=synthetic-secret",body=[{"a":"f","c":1}],headers=headers)[0],400)
        for path in ("https://elsewhere.invalid/cs","//cs","/c%73","/cs#fragment","/cs/../cs"):
            self.assertEqual(self.request("POST",path,body=[{"a":"f","c":1}])[0],400)
        self.assertEqual(self.request("POST","/cs?id=1&sid=synthetic-secret",body=[{"a":"f","c":1}],content_type="application/xml")[0],400)

    def test_request_response_and_deadline_budgets_fail_closed(self):
        self.state.request_limit=1
        self.listing();self.assertEqual(self.api({"a":"f","c":1})[0],429)
        self.assertTrue(self.state.budget_exceeded)
        self.state.request_limit=128;self.state.byte_limit=1
        self.assertEqual(self.api({"a":"f","c":1})[0],429)
        self.state.deadline=0;self.assertEqual(self.api({"a":"f","c":1})[0],429)

class MegaAuthorityTests(unittest.TestCase):
    def test_two_reviewed_names_have_exact_sni_and_single_san(self):
        from cryptography import x509
        for name,callback in ((API,T._mega_api_sni),(CONTENT,T._mega_content_sni)):
            with tempfile.TemporaryDirectory() as directory:
                with T.FixtureCertificates.create(Path(directory).resolve(),server_name=name) as certificates:
                    leaf=x509.load_pem_x509_certificate((certificates.directory/"leaf.pem").read_bytes())
                    self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value),[x509.DNSName(name)])
            self.assertIsNone(callback(None,name,None))
            for other in {None,"","127.0.0.1",name+".",name+":443",API,CONTENT,EVENTS}-{name}:
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
