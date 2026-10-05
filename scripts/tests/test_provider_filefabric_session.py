"""Generated-only later-call FileFabric HTTP tests; no rclone or accounts."""
import copy
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

A, P = "synthetic-cached-A", "synthetic-permanent-P"
MEMBER = "README-synthetic.txt"
BYTES = b"Synthetic provider protocol fixture. No account or user data.\n"


def form(function="checkPathExists", token=A, **params):
    return urllib.parse.urlencode({"function":function,"token":token,"apiformat":"json",**params}).encode()


class FileFabricSessionServerTests(unittest.TestCase):
    def start(self, deny=False):
        self.state=F.FileFabricSessionState(A,P,deny=deny)
        self.port=self.enterContext(F.serve("filefabric-renewal",self.state))

    def request(self, body, *, headers=(), target="/api/rpc.php", method="POST"):
        client=http.client.HTTPConnection("127.0.0.1",self.port,timeout=3)
        try:
            client.putrequest(method,target,skip_host=True,skip_accept_encoding=True)
            for key,value in (("Host",f"127.0.0.1:{self.port}"),("Content-Type","application/x-www-form-urlencoded"),("Content-Length",str(len(body))),*headers):
                client.putheader(key,value)
            client.endheaders(body)
            response=client.getresponse()
            return response.status,response.read(16385)
        finally:client.close()

    def stat(self, token=A, **params):
        return self.request(form(token=token,**{"pid":"100","path":MEMBER,**params}))

    def expired(self):
        self.assertEqual(self.stat()[0],200)
        status,body=self.stat()
        self.assertEqual((status,json.loads(body)),(200,{"status":"login_token_expired","statusmessage":"Synthetic cached session expired"}))
        self.assertEqual(self.state.phase,"grant")
        self.assertIsNone(self.state.issued_token)

    def granted(self):
        self.expired()
        status,body=self.request(form("getTokenByAuthToken",token="*",authtoken=P))
        result=json.loads(body)
        self.assertEqual((status,set(result),result["status"]),(200,{"status","token"},"ok"))
        self.assertNotEqual(result["token"],A)
        self.assertEqual(result["token"],self.state.issued_token)
        self.assertEqual(self.request(form("getApplianceInfo",token="*")),(200,b'{"status":"ok","softwareversionlabel":"2006.02"}'))
        return result["token"]

    def finish(self, token):
        self.assertEqual(self.stat(token)[0],200)
        self.assertEqual(self.stat(token)[0],200)
        self.assertEqual(self.request(form("getFile",token=token,fi_id="301")),(200,BYTES))

    def drain(self):
        deadline=time.monotonic()+2
        while time.monotonic()<deadline:
            with self.state.lock:
                if not self.state.active_handlers and not self.state.sockets:return
            time.sleep(.01)
        self.fail("owned handlers did not drain")

    def test_exact_later_call_success_then_fresh_phase_reuse(self):
        self.start()
        before=copy.deepcopy(self.state.files)
        token=self.granted()
        self.finish(token)
        self.drain()
        self.assertEqual(self.state.events,[("initial_stat",MEMBER),("expired",MEMBER),("grant",""),("appliance",""),
                                           ("renewed_stat",MEMBER),("copy_stat",MEMBER),("content",MEMBER)])
        self.assertEqual((self.state.requests,self.state.expirations,self.state.grant_attempts,self.state.grants,self.state.appliance_calls),(7,1,1,1,1))
        self.assertLessEqual(self.state.expiry_lower,self.state.grant_upper)
        self.state.begin_reuse()
        self.assertEqual(self.state.lifetime_requests,7)
        self.assertEqual(self.state.events,[])
        self.finish(token)
        self.drain()
        self.assertEqual(self.state.events,[("reuse_stat",MEMBER),("reuse_copy_stat",MEMBER),("reuse_content",MEMBER)])
        self.assertEqual((self.state.requests,self.state.lifetime_requests,self.state.grant_attempts,self.state.appliance_calls),(3,10,0,0))
        self.assertEqual(self.state.files,before)
        self.assertEqual(self.state.unexpected,0)
        self.doCleanups()
        self.assertTrue(self.state.cleanup_complete)
        self.assertFalse(self.state.sockets)

    def test_denied_grant_ends_without_token_appliance_or_content(self):
        self.start(True)
        before=copy.deepcopy(self.state.files)
        self.expired()
        status,body=self.request(form("getTokenByAuthToken",token="*",authtoken=P))
        self.assertEqual((status,json.loads(body)),(200,{"status":"fixture_grant_denied","statusmessage":"Synthetic grant denied"}))
        self.assertEqual(self.state.events,[("initial_stat",MEMBER),("expired",MEMBER),("grant_denied","")])
        self.assertEqual((self.state.phase,self.state.grants,self.state.grant_denials,self.state.appliance_calls,self.state.payload_bytes),("denied",0,1,0,0))
        self.assertIsNone(self.state.issued_token)
        self.assertEqual(self.state.files,before)
        with self.assertRaises(ValueError):self.state.begin_reuse()

    def test_early_grant_discovery_content_unknown_member_and_wrong_auth_rejected(self):
        self.start()
        for body in (form("getTokenByAuthToken",token="*",authtoken=P),form("getApplianceInfo",token="*"),form("getFile",fi_id="301"),
                     form(pid="100",path="nested/bytes.bin"),form(pid="0",path=MEMBER),form(token="wrong",pid="100",path=MEMBER),
                     form("getFolderContents",fi_pid="100",count="1000",subfolders="y",options="filelist")):
            self.assertEqual(self.request(body)[0],400)
        self.assertEqual(self.state.events,[])
        self.assertEqual(self.state.payload_bytes,0)
        self.assertEqual(self.state.grant_attempts,0)

    def test_expired_call_is_not_retried_with_old_token_and_wrong_permanent_never_grants(self):
        self.start()
        self.expired()
        for body in (form(pid="100",path=MEMBER),form("getTokenByAuthToken",token=A,authtoken=P),
                     form("getTokenByAuthToken",token="*",authtoken="wrong")):
            self.assertEqual(self.request(body)[0],400)
        self.assertEqual(self.state.grants,0)
        self.assertIsNone(self.state.issued_token)

    def test_no_old_token_or_extra_grant_after_issued_session(self):
        self.start()
        token=self.granted()
        self.assertEqual(self.stat()[0],400)
        self.assertEqual(self.request(form("getTokenByAuthToken",token="*",authtoken=P))[0],400)
        self.finish(token)
        self.assertEqual(self.request(form("getFile",token=token,fi_id="301"))[0],400)
        self.assertEqual(self.state.grants,1)

    def test_strict_shared_framing_unknown_encoding_duplicates_routes_range(self):
        self.start()
        body=form(pid="100",path=MEMBER)
        for header in (("Content-Encoding","gzip"),("Content-Length",str(len(body))),("Authorization","Bearer synthetic"),
                       ("Host","localhost"),("Transfer-Encoding","chunked"),("Range","bytes=0-3")):
            self.assertEqual(self.request(body,headers=(header,))[0],400)
        for raw in (body+b"&token=x",body+b"&%74oken=x",body+b"&extra=x",body.replace(b"path=",b"path=%FF")):
            self.assertEqual(self.request(raw)[0],400)
        for target in ("/api/rpc.php?extra=x","/api/rpc.php#fragment","//api/rpc.php","http://example.invalid/api/rpc.php"):
            self.assertEqual(self.request(body,target=target)[0],400)
        self.assertEqual(self.state.events,[])

    def test_phase_reset_requires_complete_quiescent_owned_state(self):
        self.start()
        with self.assertRaises(ValueError):self.state.begin_reuse()
        token=self.granted();self.finish(token);self.drain()
        for field,value in (("active_handlers",1),("sockets",{object()}),("unexpected",1),("budget_exceeded",True)):
            original=getattr(self.state,field)
            setattr(self.state,field,value)
            with self.assertRaises(ValueError):self.state.begin_reuse()
            setattr(self.state,field,original)
        self.state.begin_reuse()
        self.assertEqual(self.state.lifetime_requests,7)
        with self.assertRaises(ValueError):self.state.begin_reuse()

    def test_request_budget_remains_cumulative_after_reuse(self):
        self.start()
        token=self.granted();self.finish(token);self.drain();self.state.begin_reuse()
        self.state.request_limit=7
        self.assertEqual(self.stat(token)[0],429)
        self.assertTrue(self.state.budget_exceeded)
        self.assertEqual(self.state.lifetime_requests,8)

    def test_slow_incomplete_form_deadline_and_owned_cleanup(self):
        self.start();self.state.request_timeout=.15
        client=socket.create_connection(("127.0.0.1",self.port),timeout=2)
        try:
            client.sendall((f"POST /api/rpc.php HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\r\n\r\nx").encode())
            started=time.monotonic()
            try:
                while client.recv(4096):pass
            except OSError:pass
            self.assertLess(time.monotonic()-started,1.5)
        finally:client.close()
        self.doCleanups()
        self.assertTrue(self.state.cleanup_complete)
        self.assertTrue(self.state.budget_exceeded)
        self.assertEqual(self.state.active_handlers,0)
        self.assertEqual(self.state.grants,0)

    def test_invalid_generated_only_state(self):
        for token,permanent,deny in ((A,A,False),(A,"",False),(A,P,1),(A,P+"\n",False)):
            with self.assertRaises(ValueError):F.FileFabricSessionState(token,permanent,deny=deny)


if __name__ == "__main__":unittest.main()
