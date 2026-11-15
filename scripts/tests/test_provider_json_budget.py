"""Rejection ordering oracles for bounded JSON APIs; no sockets or accounts."""
import io
import http.client
from pathlib import Path
import sys
import time
from types import SimpleNamespace
import unittest

LAB = Path(__file__).resolve().parents[1] / "provider-lab"
sys.path.insert(0, str(LAB))
try:
    import fixture_quatrix as Q
    import fixture_opendrive as O
    import fixture_fichier as F
    import fixture_putio as P
finally:
    sys.path.pop(0)

CASES = (
    ("quatrix", Q.QuatrixHandler, lambda: Q.QuatrixState("synthetic", "wrong"), "127.0.0.1:4242"),
    ("opendrive", O.OpenDriveHandler, lambda: O.OpenDriveState("synthetic-user", "synthetic-password"), "dev.opendrive.com"),
    ("fichier", F.FichierHandler, lambda: F.FichierState("synthetic"), "api.1fichier.com"),
    ("putio", P.PutioHandler, lambda: P.PutioState("synthetic"), "api.put.io"),
)

class JsonBudgetOrderingTests(unittest.TestCase):
    def handler(self, cls, make_state, authority, *, length=11, body=b'{"path":""}'):
        h = object.__new__(cls)
        state = make_state()
        state.request_limit = 0
        h.server = SimpleNamespace(state=state, authority=authority)
        h.command, h.path = "POST", "/synthetic"
        h.raw_requestline = b"POST /synthetic HTTP/1.1\r\n"
        headers = ("Host: " + authority + "\r\nContent-Type: application/json\r\nContent-Length: "
                   + str(length) + "\r\n\r\n").encode()
        h.headers = http.client.parse_headers(io.BytesIO(headers))
        h.rfile = io.BytesIO(body)
        h.close_connection = False
        observations = []
        h.json_reply = lambda status, value: observations.append((status, h.rfile.tell()))
        return h, state, observations

    def test_valid_bounded_body_is_consumed_before_budget_reply(self):
        for name, cls, factory, authority in CASES:
            for exhausted_by in ("requests", "lifetime"):
                with self.subTest(provider=name, exhausted_by=exhausted_by):
                    h, state, replies = self.handler(cls, factory, authority)
                    if exhausted_by == "lifetime":
                        state.request_limit = 100
                        state.deadline = time.monotonic() - 1
                    self.assertIsNone(h.wire())
                    self.assertEqual(replies, [(429, 11)])
                    self.assertTrue(state.budget_exceeded)
                    self.assertEqual((state.requests, state.payload_bytes, state.authenticated), (1, 0, 0))
                    self.assertEqual(state.events, [])

    def test_over_budget_does_not_relax_framing_or_read_oversized_body(self):
        for name, cls, factory, authority in CASES:
            with self.subTest(provider=name):
                h, state, replies = self.handler(cls, factory, authority, length=4097)
                self.assertIsNone(h.wire())
                self.assertEqual(replies, [(400, 0)])
                self.assertTrue(state.budget_exceeded)
                self.assertEqual((state.payload_bytes, state.authenticated, state.unexpected), (0, 0, 1))

    def test_partial_over_budget_body_cannot_be_called_a_clean_429_exchange(self):
        for name, cls, factory, authority in CASES:
            with self.subTest(provider=name):
                h, state, replies = self.handler(cls, factory, authority, body=b'{"')
                self.assertIsNone(h.wire())
                self.assertEqual(replies, [(400, 2)])
                self.assertTrue(state.budget_exceeded)
                self.assertEqual((state.payload_bytes, state.authenticated), (0, 0))

    def test_expired_body_socket_closes_without_a_reply(self):
        class ExpiredBody(io.BytesIO):
            def read(self, *args):
                raise TimeoutError("synthetic deadline")
        for name, cls, factory, authority in CASES:
            with self.subTest(provider=name):
                h, state, replies = self.handler(cls, factory, authority)
                h.rfile = ExpiredBody(b'{"path":""}')
                self.assertIsNone(h.wire())
                self.assertEqual(replies, [])
                self.assertTrue(h.close_connection)
                self.assertTrue(state.budget_exceeded)
                self.assertEqual((state.payload_bytes, state.authenticated), (0, 0))

if __name__ == "__main__":
    unittest.main()
