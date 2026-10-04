"""Literal cached-session FileFabric RPC fixture tests; no native runtime/account."""
import copy
import hashlib
import http.client
import json
from pathlib import Path
import socket
import sys
import time
import unittest
import urllib.parse

sys.path.insert(0, str(Path(__file__).parents[1] / "provider-lab"))
try:
    import fixture_servers as F
finally:
    sys.path.pop(0)

TOKEN = "synthetic-cached-session"
WRONG = "wrong-synthetic-session"
PAYLOADS = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
            "nested/bytes.bin": bytes(range(256)) * 8, "nested/space name.txt": b"Nested synthetic payload.\n"}
IDS = {"README-synthetic.txt": "301", "nested/bytes.bin": "302", "nested/space name.txt": "303"}
OPTIONS = "filelist|fi_id|fi_pid|fi_name|fi_type|fi_size|fi_contenttype|fi_modified|fi_localtime|trash|subfolders"


def form(function="checkPathExists", token=TOKEN, **fields):
    return urllib.parse.urlencode({"function": function, "apiformat": "json", "token": token, **fields}).encode()


def node(member):
    directory = member == "nested"
    return {"fi_id": "200" if directory else IDS[member], "fi_pid": "100" if "/" not in member else "200",
            "fi_name": member.rsplit("/", 1)[-1], "fi_type": "1" if directory else "0",
            "fi_size": "0" if directory else str(len(PAYLOADS[member])),
            "fi_contenttype": "inode/directory" if directory else "application/octet-stream",
            "fi_modified": "2024-01-02 00:00:00", "fi_localtime": "2024-01-01 00:00:00", "trash": False, "subfolders": 0}


class FileFabricServerTests(unittest.TestCase):
    def start(self, mode="normal"):
        self.state = F.FileFabricState(TOKEN, mode)
        self.port = self.enterContext(F.serve("filefabric", self.state))

    def request(self, body, *, method="POST", target="/api/rpc.php", extra=(), omitted=()):
        client = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            client.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
            for name, value in (("Host", f"127.0.0.1:{self.port}"), ("Content-Length", str(len(body))),
                                ("Content-Type", "application/x-www-form-urlencoded")):
                if name not in omitted:
                    client.putheader(name, value)
            for name, value in extra:
                client.putheader(name, value)
            client.endheaders(body)
            response = client.getresponse()
            return response.status, dict(response.getheaders()), response.read(16385)
        finally:
            client.close()

    def metadata(self, member="README-synthetic.txt"):
        return self.request(form(pid="100", path=member))

    def test_complete_two_page_free_listings_have_literal_wire_types(self):
        self.start()
        for parent, members in (("100", ["README-synthetic.txt", "nested"]), ("200", ["nested/bytes.bin", "nested/space name.txt"])):
            status, _, body = self.request(form("getFolderContents", fi_pid=parent, count="1000", subfolders="y", options=OPTIONS))
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body), {"status": "ok", "total": "2", "from": 0, "pid": parent,
                                                "filelist": [node(member) for member in members]})
        self.assertEqual(self.state.events, [("listing", "100"), ("listing", "200")])
        self.assertEqual(self.state.payload_bytes, 0)

    def test_exact_metadata_then_content_independent_bytes_and_hashes(self):
        self.start()
        for member, payload in PAYLOADS.items():
            status, _, body = self.metadata(member)
            self.assertEqual((status, json.loads(body)), (200, {"status": "ok", "exists": "y", "file": node(member)}))
            status, headers, body = self.request(form("getFile", fi_id=IDS[member]))
            self.assertEqual(status, 200)
            self.assertEqual(int(headers["Content-Length"]), len(payload))
            self.assertEqual(body, payload)
            self.assertEqual(hashlib.sha256(body).digest(), hashlib.sha256(payload).digest())
        self.assertEqual(self.state.files, PAYLOADS)
        self.assertEqual(self.state.payload_bytes, sum(map(len, PAYLOADS.values())))
        self.assertEqual(self.state.unexpected, 0)

    def test_missing_is_exact_semantic_exists_n_without_data(self):
        self.start()
        status, _, body = self.metadata("missing-synthetic-object.bin")
        self.assertEqual((status,json.loads(body)), (200, {"status":"ok","exists":"n"}))
        self.assertEqual(self.state.events, [("file_missing", "missing-synthetic-object.bin")])
        self.assertEqual((self.state.missing,self.state.payload_bytes), (1,0))

    def test_wrong_cached_token_is_only_designated_metadata_status_and_never_granted(self):
        self.start()
        status, _, body = self.request(form(token=WRONG, pid="100", path="README-synthetic.txt"))
        self.assertEqual((status,json.loads(body)), (200, {"status":"login_token_expired","statusmessage":"Synthetic cached session denied"}))
        self.assertEqual(self.state.events, [("auth_denied","README-synthetic.txt")])
        self.assertEqual((self.state.auth_denied,self.state.authenticated,self.state.payload_bytes), (1,0,0))

    def test_known_member_denial_with_valid_token_is_distinct(self):
        self.start("member_denied")
        status, _, body = self.metadata()
        self.assertEqual((status,json.loads(body)), (200, {"status":"fixture_member_denied","statusmessage":"Synthetic member denied"}))
        self.assertEqual(self.state.events, [("member_denied","README-synthetic.txt")])
        self.assertEqual((self.state.member_denied,self.state.auth_denied,self.state.payload_bytes), (1,0,0))

    def test_direct_authenticated_delete_is_rejected_without_mutation(self):
        self.start()
        before = copy.deepcopy(self.state.files)
        status, _, body = self.request(form("doDeleteFile", fi_id="301", completedeletion="n"))
        self.assertEqual((status,json.loads(body)), (405, {"status":"fixture_read_only"}))
        self.assertEqual(self.state.files,before)
        self.assertEqual(self.state.events,[("write_denied","README-synthetic.txt")])
        self.assertEqual((self.state.rejected_mutations,self.state.payload_bytes), (1,0))

    def test_grant_appliance_info_unknown_function_and_extra_fields_fail_closed(self):
        self.start()
        for body in (form("getTokenByAuthToken", token="*", authtoken="synthetic-permanent"),
                     form("getApplianceInfo", token="*"), form("doCreateFolder", name="bad"),
                     form(pid="100", path="README-synthetic.txt", extra="bad")):
            with self.subTest(body_kind=body.split(b"&",1)[0]):
                self.assertEqual(self.request(body)[0],400)
        self.assertEqual(self.state.events,[])
        self.assertEqual(self.state.payload_bytes,0)
        self.assertEqual(self.state.unexpected,4)

    def test_known_id_path_and_parent_graph_only(self):
        self.start()
        for body in (form(pid="0",path="README-synthetic.txt"), form(pid="100",path="../README-synthetic.txt"),
                     form(pid="100",path="nested/../README-synthetic.txt"), form(pid="100",path="https://example.invalid/"),
                     form(pid="100",path="other"), form("getFile",fi_id="0"), form("getFile",fi_id="301"),
                     form("doDeleteFile",fi_id="302",completedeletion="n"), form("doDeleteFile",fi_id="301",completedeletion="y")):
            self.assertEqual(self.request(body)[0],400)
        self.assertEqual(self.state.payload_bytes,0)
        self.assertEqual(self.state.files,PAYLOADS)

    def test_listing_rejects_pagination_wrong_options_and_oversized_decimal(self):
        self.start()
        valid={"fi_pid":"100","count":"1000","subfolders":"y","options":OPTIONS}
        for key,value in (("fi_pid","0"),("count","1"),("count","9"*1000),("from","0"),("subfolders","n"),("options","filelist")):
            self.assertEqual(self.request(form("getFolderContents",**{**valid,key:value}))[0],400)
        self.assertEqual(self.state.events,[])

    def test_strict_form_duplicates_encoding_controls_blank_values_and_field_count(self):
        self.start()
        good=form(pid="100",path="README-synthetic.txt")
        bodies=[good+b"&token=other", good+b"&%74oken=other", good+b"&path=x",good+b"&token=%GG",
                good.replace(b"path=",b"path=%FF"),good.replace(b"path=",b"path=%00"),good+b"&extra=",
                good.replace(b"apiformat=json",b"apiformat=xml"), b"nodelimiter", b"=missingkey",
                good+b"&a=x&b=x&c=x&d=x"]
        for body in bodies:
            self.assertEqual(self.request(body)[0],400)
        self.assertEqual(self.state.events,[])

    def test_exact_route_and_method_reject_aliases_redirect_targets_and_unknowns(self):
        self.start()
        for target in ("/api/rpc.php?x=1","/api/rpc.php#fragment","//api/rpc.php","/api/%72pc.php","http://example.invalid/api/rpc.php","/other"):
            self.assertEqual(self.request(form(pid="100",path="README-synthetic.txt"),target=target)[0],400)
        for method in ("GET","PUT","DELETE","PATCH"):
            self.assertGreaterEqual(self.request(form(pid="100",path="README-synthetic.txt"),method=method)[0],400)
        self.assertEqual(self.state.events,[])

    def test_strict_header_framing_no_proxy_auth_cookie_or_duplicate_headers(self):
        self.start()
        body=form(pid="100",path="README-synthetic.txt")
        for header in (("Host","localhost"),("Content-Length",str(len(body))),("Content-Type","application/x-www-form-urlencoded"),
                       ("Transfer-Encoding","chunked"),("Content-Encoding","gzip"),("Authorization","Bearer synthetic"),("Proxy-Authorization","Basic x"),("Cookie","x=y"),
                       ("Range","bytes=0-1"),("X-Large","x"*17000)):
            self.assertEqual(self.request(body,extra=(header,))[0],400)
        for missing in ("Host","Content-Length","Content-Type"):
            self.assertEqual(self.request(body,omitted=(missing,))[0],400)
        for size in ("0","-1","4097","9"*500,"01"):
            self.assertEqual(self.request(body,omitted=("Content-Length",),extra=(("Content-Length",size),))[0],400)
        self.assertEqual(self.state.events,[])

    def test_unregistered_wrong_token_or_wrong_member_cannot_supply_expected_denial(self):
        self.start()
        for token,member in (("other","README-synthetic.txt"),(WRONG,"nested/bytes.bin")):
            self.assertEqual(self.request(form(token=token,pid="100",path=member))[0],200)
        self.assertEqual(self.state.auth_denied,0)
        self.assertEqual(self.state.unexpected,2)
        self.assertEqual(self.state.events,[])

    def test_range_unit_only_returns_exact_subbytes_and_rejects_invalid_bounds(self):
        self.start()
        self.metadata("nested/bytes.bin")
        for requested,expected in (("bytes=0-3",PAYLOADS["nested/bytes.bin"][:4]),("bytes=2044-",PAYLOADS["nested/bytes.bin"][-4:])):
            status,headers,body=self.request(form("getFile",fi_id="302"),extra=(("Range",requested),))
            self.assertEqual((status,body),(206,expected))
            self.assertIn("Content-Range",headers)
        for requested in ("bytes=-4","bytes=8-2","bytes=2048-","bytes=0-1,4-8","bytes="+"9"*20+"-"):
            self.assertEqual(self.request(form("getFile",fi_id="302"),extra=(("Range",requested),))[0],416)

    def test_slow_body_absolute_timeout_and_cleanup(self):
        self.start()
        self.state.request_timeout=0.15
        sock=socket.create_connection(("127.0.0.1",self.port),timeout=2)
        try:
            sock.sendall((f"POST /api/rpc.php HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\r\n\r\nx").encode())
            started=time.monotonic()
            try:
                while sock.recv(4096):
                    pass
            except (ConnectionResetError,socket.timeout):
                pass
            self.assertLess(time.monotonic()-started,1.5)
        finally:
            sock.close()
        self.doCleanups()
        self.assertTrue(self.state.cleanup_complete)
        self.assertTrue(self.state.budget_exceeded)
        self.assertGreater(self.state.unexpected,0)
        self.assertEqual(self.state.payload_bytes,0)

    def test_request_byte_connection_and_time_budgets_are_sticky(self):
        for kind in ("requests","bytes","deadline","connections"):
            with self.subTest(kind=kind):
                state=F.FileFabricState(TOKEN)
                with F.serve("filefabric",state) as port:
                    self.state,self.port=state,port
                    if kind=="requests":state.request_limit=0
                    elif kind=="bytes":state.byte_limit=1
                    elif kind=="deadline":state.deadline=time.monotonic()-1
                    else:state.connection_limit=0
                    try:
                        status,_,_=self.metadata()
                        self.assertGreaterEqual(status,400)
                    except (OSError,http.client.HTTPException):
                        pass
                self.assertTrue(state.budget_exceeded)
                self.assertTrue(state.cleanup_complete)
                self.assertEqual(state.files,PAYLOADS)
                self.assertEqual(state.payload_bytes,0)

    def test_normal_cleanup_closes_listener_sockets_and_threads(self):
        self.start()
        self.metadata()
        self.doCleanups()
        self.assertTrue(self.state.cleanup_complete)
        self.assertFalse(self.state.sockets)
        with socket.socket() as client:
            client.settimeout(0.3)
            self.assertNotEqual(client.connect_ex(("127.0.0.1",self.port)),0)

    def test_invalid_state_construction(self):
        for token,mode,wrong in (("","normal",WRONG),(TOKEN,"renew",WRONG),(TOKEN,"normal",TOKEN),(TOKEN+"\n","normal",WRONG)):
            with self.assertRaises(ValueError):F.FileFabricState(token,mode,wrong_token=wrong)


if __name__ == "__main__":
    unittest.main()
