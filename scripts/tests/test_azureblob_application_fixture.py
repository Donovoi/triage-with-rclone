"""Pure states and fake transports. No real socket or thread may start."""
import base64
from datetime import datetime, timezone, timedelta
from email.utils import format_datetime
import hashlib
import hmac
import io
import json
from pathlib import Path
import threading
import types
import unittest
from unittest.mock import Mock, patch

PATH=Path(__file__).resolve().parents[1]/"application-lab/fixture_azureblob.py"
F=types.ModuleType("azureblob_fixture_test");F.__file__=str(PATH)
exec(compile(PATH.read_bytes(),str(PATH),"exec"),F.__dict__)
KEY=bytes(range(32));WRONG=bytes(v^1 for v in KEY)
NOW=datetime(2026,10,15,12,tzinfo=timezone.utc)


def state(case="acquisition"):
    return F.AppAzureBlobState(case,base64.b64encode(KEY).decode(),base64.b64encode(WRONG).decode(),lambda:NOW)


def headers(method="HEAD",key=KEY,date=None,extra=None,target=F.TARGET):
    # Independent string construction, not the production canonicalizer.
    h={"host":"127.0.0.1:1234","x-ms-date":date or format_datetime(NOW,usegmt=True),"x-ms-version":"2026-06-06"}
    h.update(extra or {})
    fields=[method,"","","","","","","",h.get("if-match",""),"","",""]
    fields += ["\n".join(name+":"+h[name] for name in sorted(h) if name.startswith("x-ms-")),"/syntheticaccount"+target]
    signature=base64.b64encode(hmac.new(key,"\n".join(fields).encode(),hashlib.sha256).digest()).decode()
    h["authorization"]="SharedKey syntheticaccount:"+signature
    return h


def complete(s,method="HEAD",key=KEY,extra=None):
    req=s.begin(method,F.TARGET,headers(method,key,extra=extra));wire=s.response(req);s.commit(req,len(wire));return wire


def server(s,sock=None):
    sock=sock or Mock();sock.fileno.return_value=1
    obj=F._Server.__new__(F._Server);obj.state=s;obj.lock=threading.RLock();obj.stopping=threading.Event()
    obj.deadline=F.time.monotonic()+60;obj.sockets={sock:F.time.monotonic()+3};obj._dispatch_lock=threading.Lock()
    obj.port=1234;obj._close_attempted=False;obj.cleanup_complete=False
    return obj,sock


class FixtureTests(unittest.TestCase):
    def test_known_content_correct_and_wrong_key_are_distinct_ordered_cases(self):
        s=state();complete(s);complete(s);wire=complete(s,"GET")
        self.assertTrue(wire.endswith(b"Nested synthetic payload.\n"))
        self.assertEqual((s.requests,s.payload_bytes,len(s.events)),(3,26,3))
        s=state("denial");wire=complete(s,key=WRONG)
        self.assertIn(b"403 Forbidden",wire);self.assertIn(b"x-ms-error-code: AuthenticationFailed",wire)
        self.assertEqual((s.requests,s.payload_bytes,len(s.events)),(1,0,1));self.assertTrue(wire.endswith(b"\r\n\r\n"))
        for token in (base64.b64encode(KEY).decode(),base64.b64encode(WRONG).decode(),"127.0.0.1","SharedKey"):
            self.assertNotIn(token,json.dumps(s.snapshot()))

    def test_canonical_encoded_path_not_raw_alias_and_full_ranges_only(self):
        for target in (F.TARGET.replace("%2F","/"),F.TARGET.replace("%20"," "),F.TARGET+"?x=y","/other"):
            with self.assertRaises(F.FixtureError):state().begin("HEAD",target,headers(target=target))
        for value in ("bytes=0-","bytes=0-25"):
            s=state();complete(s);complete(s);wire=complete(s,"GET",extra={"x-ms-range":value})
            self.assertIn(b"206 Partial Content",wire);self.assertIn(b"Content-Range: bytes 0-25/26",wire)
        for value in ("bytes=1-25","bytes=0-26","bytes=0-1,3-4"):
            s=state();complete(s);complete(s)
            with self.assertRaises(F.FixtureError):complete(s,"GET",extra={"x-ms-range":value})

    def test_authentication_freshness_and_malformed_key_fail_closed(self):
        for bad in ("not-base64",base64.b64encode(b"short").decode(),base64.b64encode(KEY).decode()+"\n"):
            with self.assertRaises(ValueError):F.AppAzureBlobState("acquisition",bad,base64.b64encode(WRONG).decode())
        for case,key in (("acquisition",WRONG),("denial",KEY),("denial",b"z"*32)):
            with self.assertRaisesRegex(F.FixtureError,"credentials_invalid"):complete(state(case),key=key)
        for seconds in (901,-1):
            h=headers(date=format_datetime(NOW-timedelta(seconds=seconds),usegmt=True))
            with self.assertRaisesRegex(F.FixtureError,"credentials_invalid"):state().begin("HEAD",F.TARGET,h)
        s=state();req=s.begin("HEAD",F.TARGET,headers(date=format_datetime(NOW-timedelta(seconds=900),usegmt=True)))
        self.assertIs(s._pending,req)

    def test_sequence_commit_bytes_source_and_budgets_are_strict(self):
        for method in ("GET","PUT"):
            with self.assertRaises(F.FixtureError):state().begin(method,F.TARGET,headers(method))
        s=state();req=s.begin("HEAD",F.TARGET,headers());wire=s.response(req)
        with self.assertRaises(F.FixtureError):s.begin("HEAD",F.TARGET,headers())
        for n in (True,0,len(wire)-1):
            with self.assertRaises(F.FixtureError):s.commit(req,n)
        s.commit(req,len(wire));self.assertEqual(len(s.events),1)
        with self.assertRaises(F.FixtureError):s.commit(req,len(wire))
        for attr,value in (("_body",b"changed"),("requests",128),("response_bytes",524288)):
            s=state();setattr(s,attr,value)
            with self.assertRaises(F.FixtureError):complete(s)
        s=state("denial");complete(s,key=WRONG)
        with self.assertRaises(F.FixtureError):complete(s,key=WRONG)

    def test_parser_rejects_duplicate_headers_unowned_routes_bodies_and_aliases(self):
        obj,_=server(state())
        def wire(h=None,target=F.TARGET):
            pairs=list((h or headers()).items())
            return ("HEAD "+target+" HTTP/1.1\r\n"+"".join(k+": "+v+"\r\n" for k,v in pairs)+"\r\n").encode()
        self.assertEqual(obj._parse(io.BytesIO(wire()))[1],F.TARGET)
        for raw in (wire().replace(b"\r\n\r\n",b"\r\nHost: 127.0.0.1:1234\r\n\r\n"),wire(dict(headers(),host="other")),
                    wire(dict(headers(),**{"content-length":"1"})),wire(dict(headers(),**{"transfer-encoding":"chunked"})),
                    wire(target="//syntheticaccount/synthetic-container/nested%2Fspace%20name.txt"),b"X"*8193):
            with self.assertRaises(F.FixtureError):obj._parse(io.BytesIO(raw))

    def test_actual_worker_commits_after_return_and_before_successor_admission(self):
        for failed in (False,True):
            s=state();s.lock=threading.Lock()  # Non-reentrant fake detects a held state lock at send.
            obj,sock=server(s);obj._parse=Mock(return_value=("HEAD",F.TARGET,headers()))
            sock.makefile.return_value=io.BytesIO();trace=[]
            original=s.commit
            def send(wire):
                trace.append("visible_before_return")
                self.assertFalse(obj._dispatch_lock.acquire(blocking=False));self.assertEqual(s.events,[])
                self.assertTrue(s.lock.acquire(blocking=False));s.lock.release()
                if failed:raise OSError("PRIVATE-CANARY")
                trace.append("returned")
            def commit(*args):
                self.assertFalse(obj._dispatch_lock.acquire(blocking=False));trace.append("commit");original(*args)
            sock.sendall.side_effect=send;s.commit=commit
            with patch.object(F.select,"select",return_value=([],[],[])):
                obj._worker(sock)
            self.assertEqual(trace,["visible_before_return"] if failed else ["visible_before_return","returned","commit"])
            self.assertEqual(len(s.events),0 if failed else 1);self.assertNotIn(sock,obj.sockets)
            self.assertTrue(obj._dispatch_lock.acquire(blocking=False));obj._dispatch_lock.release()
            if failed:self.assertEqual(s.errors,["connection_failed"])
            else:
                s.commit=original
                complete(s)  # The sequential successor now reaches begin.
            self.assertNotIn("PRIVATE-CANARY",json.dumps(s.snapshot()))

    def test_waiters_obey_original_deadline_stop_and_lock_ownership(self):
        for mode in ("expired","stopped","unowned"):
            obj,sock=server(state());obj._dispatch_lock.acquire()
            if mode=="expired":obj.sockets[sock]=F.time.monotonic()-1
            if mode=="stopped":obj.stopping.set()
            if mode=="unowned":obj.sockets.clear()
            with self.assertRaises(F.FixtureError):obj._acquire_dispatch(sock)
            self.assertFalse(obj._dispatch_lock.acquire(blocking=False));obj._dispatch_lock.release()
        obj,sock=server(state());obj._dispatch_lock=Mock();obj._dispatch_lock.acquire.return_value=True
        before=obj.sockets[sock];obj._acquire_dispatch(sock)
        self.assertLessEqual(obj._dispatch_lock.acquire.call_args.kwargs["timeout"],0.05)
        self.assertEqual(obj.sockets[sock],before)

    def test_request_deadline_starts_before_worker_scheduling(self):
        obj,sock=server(state());obj.sockets.clear();obj.deadline=160
        obj.accepted=0;obj.workers=[];obj.listener=Mock()
        obj.listener.accept.return_value=(sock,("127.0.0.1",12345))
        worker=Mock();worker.start.side_effect=lambda:obj.stopping.set()
        with patch.object(F.time,"monotonic",return_value=100),patch.object(F.threading,"Thread",return_value=worker):
            obj._accept()
        self.assertEqual(obj.sockets[sock],103);self.assertEqual(obj.workers,[worker])
        obj.stopping.clear();obj._parse=Mock()
        with patch.object(F.time,"monotonic",return_value=104):obj._worker(sock)
        obj._parse.assert_not_called();sock.sendall.assert_not_called()
        self.assertEqual(obj.state.events,[]);self.assertEqual(obj.state.errors,["request_timeout"])
        self.assertNotIn(sock,obj.sockets)
        # A fully delivered response returning after that same deadline earns no commit.
        s=state();obj,sock=server(s);obj.deadline=160;obj.sockets[sock]=103
        obj._parse=Mock(return_value=("HEAD",F.TARGET,headers()));sock.makefile.return_value=io.BytesIO()
        clock=Mock(return_value=100);sock.sendall.side_effect=lambda wire:setattr(clock,"return_value",104)
        with patch.object(F.time,"monotonic",clock),patch.object(F.select,"select",return_value=([],[],[])):
            obj._worker(sock)
        sock.sendall.assert_called_once();self.assertEqual(s.events,[])
        self.assertEqual(s.errors,["request_timeout"]);self.assertNotIn(sock,obj.sockets)

    def test_close_is_once_only_and_failure_cannot_be_retried_to_pass(self):
        obj,_=server(state())
        with patch.object(F._http._Server,"close",side_effect=F.FixtureError("cleanup_failed")) as close:
            for _ in range(2):
                with self.assertRaises(F.FixtureError):obj.close()
            close.assert_called_once()
        obj,_=server(state());obj.cleanup_complete=True
        with patch.object(F._http._Server,"close") as close:
            obj.close();obj.close();close.assert_called_once()


if __name__=="__main__":unittest.main()
