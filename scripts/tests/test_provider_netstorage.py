"""Literal NetStorage signing/XML wire oracles; no native runtime or account."""
import base64
import copy
import hashlib
import hmac
import http.client
import json
from pathlib import Path
import socket
import sys
import time
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).parents[1] / "provider-lab"))
try:
    import fixture_servers as F
finally:
    sys.path.pop(0)

KEY = "synthetic-secret+/=not-base64"
WRONG = "wrong-synthetic-secret+/=not-base64"
ROOT = "/123456/synthetic"
STAT = "version=1&action=stat&implicit=yes&format=xml&encoding=utf-8&slash=both"
LIST = "version=1&action=list&mtime_all=yes&format=xml&encoding=utf-8&end=%2F123456%2Fsynthetic0"
DOWNLOAD = "version=1&action=download"
DELETE = "version=1&action=delete"
PAYLOADS = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
            "nested/bytes.bin": bytes(range(256)) * 8, "nested/space name.txt": b"Nested synthetic payload.\n"}


def signed(target, action, data, key=KEY):
    message = (data + target + "\nx-akamai-acs-action:" + action + "\n").encode("ascii")
    return base64.b64encode(hmac.new(key.encode("ascii"), message, hashlib.sha256).digest()).decode("ascii")


def fields(name, full=False):
    return {"type": "file", "name": "123456/synthetic/" + name if full else name,
            "size": str(len(PAYLOADS[name])), "mtime": "1704067200", "md5": hashlib.md5(PAYLOADS[name]).hexdigest()}


class NetStorageServerTests(unittest.TestCase):
    def start(self, mode="normal"):
        self.state = F.NetStorageState(KEY, WRONG, mode)
        self.port = self.enterContext(F.serve("netstorage", self.state))
        self.nonce = 0

    def request(self, target=ROOT, action=STAT, *, method="GET", key=KEY, data=None,
                signature=None, extra=(), omitted=(), body=b""):
        self.nonce += 1
        if data is None:
            data = f"5, 0.0.0.0, 0.0.0.0, {int(time.time())}, {self.nonce},synthetic-account"
        if signature is None:
            signature = signed(target, action, data, key)
        client = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            client.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
            for name, value in (("Host", f"127.0.0.1:{self.port}"), ("Content-Length", str(len(body))),
                                ("X-Akamai-ACS-Action", action), ("X-Akamai-ACS-Auth-Data", data),
                                ("X-Akamai-ACS-Auth-Sign", signature)):
                if name not in omitted:
                    client.putheader(name, value)
            for name, value in extra:
                client.putheader(name, value)
            client.endheaders(body)
            response = client.getresponse()
            return response.status, dict(response.getheaders()), response.read(65537)
        finally:
            client.close()

    def root_stat(self):
        status, headers, body = self.request()
        self.assertEqual(status, 200)
        self.assertNotIn("Location", headers)
        parsed = ET.fromstring(body)
        self.assertEqual((parsed.tag, parsed.attrib), ("stat", {"directory": ROOT}))
        self.assertEqual([dict(n.attrib) for n in parsed], [{"type": "dir", "name": "synthetic", "mtime": "1704067200"}])

    def member_stat(self, name):
        status, headers, body = self.request(ROOT + "/" + name.replace(" ", "%20"))
        self.assertEqual(status, 200)
        self.assertNotIn("Location", headers)
        parsed = ET.fromstring(body)
        self.assertEqual((parsed.tag, parsed.attrib), ("stat", {"directory": ROOT}))
        self.assertEqual([dict(n.attrib) for n in parsed], [fields(name)])

    def test_independent_dotnet_hmac_vector_requires_raw_secret_uri_action_and_newlines(self):
        data = "5, 0.0.0.0, 0.0.0.0, 1704067200, 42,synthetic-account"
        target = ROOT + "/nested/space%20name.txt"
        expected = "KnQrB3dHMuVP5K9Dw/7ixQ0JnzhGoXaNaawi6sMfEyE="
        self.assertEqual(signed(target, DOWNLOAD, data), expected)
        self.assertEqual(F.netstorage_signature(KEY, data, target, DOWNLOAD), expected)
        for raw in (target.replace("%20", " "), target.replace("/nested/", "%2Fnested%2F"),
                    target.replace("/nested/", "%2fnested%2f"), target + "?", target + "/"):
            self.assertNotEqual(F.netstorage_signature(KEY, data, raw, DOWNLOAD), expected)
        self.assertNotEqual(F.netstorage_signature(KEY, data, target, DOWNLOAD.upper()), expected)
        self.assertNotEqual(F.netstorage_signature(KEY, data.replace(",synthetic", ", synthetic"), target, DOWNLOAD), expected)

    def test_full_listing_uses_cp_prefixed_names_complete_metadata_and_no_resume(self):
        self.start()
        self.root_stat()
        status, headers, body = self.request(ROOT + "/", LIST)
        self.assertEqual(status, 200)
        self.assertNotIn("Location", headers)
        parsed = ET.fromstring(body)
        self.assertEqual((parsed.tag, parsed.attrib), ("list", {}))
        self.assertEqual([dict(n.attrib) for n in parsed],
                         [{"type": "dir", "name": "123456/synthetic/", "mtime": "1704067200"},
                          {"type": "dir", "name": "123456/synthetic/nested/", "mtime": "1704067200"}]
                         + [fields(name, True) for name in sorted(PAYLOADS)])
        self.assertTrue(all(n.tag == "file" for n in parsed))
        self.assertEqual(self.state.events, [("root_stat", ""), ("listing", "")])
        self.assertEqual((self.state.authenticated, self.state.payload_bytes), (2, 0))

    def test_all_three_members_require_positive_stat_and_independent_download_hash(self):
        for name, payload in PAYLOADS.items():
            with self.subTest(name=name), F.serve("netstorage", state := F.NetStorageState(KEY, WRONG)) as port:
                self.state, self.port, self.nonce = state, port, 0
                self.root_stat()
                self.member_stat(name)
                status, headers, body = self.request(ROOT + "/" + name.replace(" ", "%20"), DOWNLOAD)
                self.assertEqual((status, body), (200, payload))
                self.assertEqual(hashlib.sha256(body).hexdigest(), hashlib.sha256(payload).hexdigest())
                self.assertNotIn("Location", headers)
                self.assertEqual(state.events, [("root_stat", ""), ("member_stat", name), ("content", name)])
                self.assertEqual((state.authenticated, state.payload_bytes), (3, len(payload)))
            self.assertTrue(state.cleanup_complete)
            self.assertFalse(state.sockets)

    def test_wrong_secret_requires_exact_rejected_root_then_leaf_without_positive_metadata(self):
        self.start("wrong_secret")
        for target in (ROOT, ROOT + "/README-synthetic.txt"):
            status, _, body = self.request(target, key=WRONG)
            self.assertEqual((status, body), (403, b"Synthetic authentication denied"))
        self.assertEqual(self.state.events, [("auth_denied", ""), ("auth_denied", "README-synthetic.txt")])
        self.assertEqual((self.state.auth_denied, self.state.authenticated, self.state.payload_bytes), (2, 0, 0))

    def test_missing_is_signed_leaf_404_after_root_not_empty_xml_or_listing_failure(self):
        self.start()
        self.root_stat()
        status, _, body = self.request(ROOT + "/missing-synthetic-object.bin")
        self.assertEqual((status, body), (404, b"Synthetic object missing"))
        self.assertEqual(self.state.events, [("root_stat", ""), ("file_missing", "missing-synthetic-object.bin")])
        self.assertEqual((self.state.authenticated, self.state.missing, self.state.payload_bytes), (2, 1, 0))

    def test_content_denial_is_known_signed_member_after_two_positive_metadata_calls(self):
        self.start("member_denied")
        self.root_stat()
        self.member_stat("README-synthetic.txt")
        status, _, body = self.request(ROOT + "/README-synthetic.txt", DOWNLOAD)
        self.assertEqual((status, body), (403, b"Synthetic member denied"))
        self.assertEqual(self.state.events, [("root_stat", ""), ("member_stat", "README-synthetic.txt"),
                                            ("content_denied", "README-synthetic.txt")])
        self.assertEqual((self.state.member_denied, self.state.payload_bytes, self.state.rejected_payload_bytes), (1, 0, 0))

    def test_signed_direct_post_delete_is_fixture_guard_only_and_preserves_source(self):
        self.start()
        original = copy.deepcopy(self.state.metadata)
        self.root_stat()
        self.member_stat("README-synthetic.txt")
        status, _, body = self.request(ROOT + "/README-synthetic.txt", DELETE, method="POST")
        self.assertEqual((status, json.loads(body)), (405, {"status": "fixture_read_only"}))
        self.assertEqual(self.state.rejected_mutations, 1)
        self.assertEqual(self.state.metadata, original)
        self.assertEqual(self.state.files, PAYLOADS)
        self.assertEqual(self.state.unexpected, 0)

    def test_signature_substitution_unknown_key_and_malformed_base64_cannot_count_auth_rejection(self):
        self.start("wrong_secret")
        self.state.request_limit = self.state.connection_limit = 64
        values = ["", "not-base64", "A" * 44, "=" * 44, base64.b64encode(b"x" * 31).decode()]
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(self.request(signature=value)[0], 400)
        self.assertEqual(self.request(key="other-synthetic-secret")[0], 400)
        self.assertEqual(self.request(key=KEY)[0], 400)
        self.assertEqual((self.state.auth_denied, self.state.authenticated), (0, 0))

    def test_auth_data_syntax_nonce_range_freshness_and_account_are_strict(self):
        self.start()
        self.state.request_limit = self.state.connection_limit = 64
        base = f"5, 0.0.0.0, 0.0.0.0, {int(time.time())}, 42,synthetic-account"
        values = [base.replace("5,", "4,", 1), base.replace(",synthetic", ", synthetic"), base.replace("42,", "042,"),
                  base.replace("42,", "-1,"), base.replace("42,", str(2**63) + ","), base.replace("synthetic-account", "other"),
                  base.replace("0.0.0.0", "127.0.0.1", 1), base.replace(str(int(time.time())), "1704067200"),
                  base.replace(str(int(time.time())), str(int(time.time()) + 3600))]
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(self.request(data=value)[0], 400)
        self.assertEqual(self.state.authenticated, 0)

    def test_replayed_data_and_missing_metadata_or_terminal_replays_fail_closed(self):
        self.start()
        data = f"5, 0.0.0.0, 0.0.0.0, {int(time.time())}, 99,synthetic-account"
        self.assertEqual(self.request(ROOT + "/README-synthetic.txt", DOWNLOAD)[0], 400)
        self.assertEqual(self.request(data=data)[0], 200)
        self.assertEqual(self.request(ROOT + "/README-synthetic.txt", data=data)[0], 400)
        self.member_stat("README-synthetic.txt")
        self.assertEqual(self.request(ROOT + "/README-synthetic.txt", DOWNLOAD)[0], 200)
        self.assertEqual(self.request(ROOT + "/README-synthetic.txt", DOWNLOAD)[0], 400)

    def test_raw_target_action_method_and_host_are_separately_enforced(self):
        self.start()
        self.state.request_limit = self.state.connection_limit = 64
        targets = [ROOT + "/", ROOT + "?", ROOT + "?x=1", ROOT + "#x", ROOT.replace("/123456/", "/654321/"),
                   ROOT.replace("/synthetic", "/%73ynthetic"), ROOT + "/../README-synthetic.txt", ROOT + "//README-synthetic.txt",
                   ROOT + "/nested%2fbytes.bin", ROOT + "/nested%2Fbytes.bin", ROOT + "/nested/space+name.txt", "http://127.0.0.1" + ROOT]
        for target in targets:
            with self.subTest(target=target):
                self.assertEqual(self.request(target)[0], 400)
        for action in (STAT + "&extra=yes", STAT.replace("stat", "Stat"), LIST, DELETE, DOWNLOAD,
                       LIST.replace("%2F", "%2f"), STAT.replace("&", "&amp;")):
            self.assertEqual(self.request(action=action)[0], 400)
        for method in ("POST", "DELETE", "PUT", "HEAD", "PATCH", "OPTIONS", "PROPFIND"):
            self.assertEqual(self.request(method=method)[0], 400)
        self.assertEqual(self.request(omitted=["Host"], extra=[("Host", "external.invalid")])[0], 400)
        self.assertEqual(self.state.authenticated, 0)

    def test_unknown_duplicate_credential_encoding_range_and_nonempty_body_rejected(self):
        self.start()
        self.state.request_limit = self.state.connection_limit = 64
        for pair in (("Authorization", "Basic synthetic"), ("Cookie", "x=1"), ("Proxy-Authorization", "Basic synthetic"),
                     ("Transfer-Encoding", "chunked"), ("Content-Encoding", "gzip"), ("Range", "bytes=0-1"),
                     ("X-Unknown", "x"), ("Host", "duplicate.invalid"), ("X-Akamai-ACS-Action", STAT), ("Content-Length", "0")):
            self.assertEqual(self.request(extra=[pair])[0], 400)
        for name in ("Host", "X-Akamai-ACS-Action", "X-Akamai-ACS-Auth-Data", "X-Akamai-ACS-Auth-Sign"):
            self.assertEqual(self.request(omitted=[name])[0], 400)
        self.assertEqual(self.request(body=b"x")[0], 400)
        self.assertEqual(self.state.authenticated, 0)

    def test_limits_expired_idle_connections_and_owned_cleanup(self):
        for key, value in (("request_limit", 0), ("byte_limit", 1), ("deadline", time.monotonic() - 1)):
            with self.subTest(key=key), F.serve("netstorage", state := F.NetStorageState(KEY, WRONG)) as port:
                self.state, self.port, self.nonce = state, port, 0
                setattr(state, key, value)
                try:
                    self.assertEqual(self.request()[0], 429)
                except (OSError, http.client.HTTPException):
                    self.assertEqual(key, "deadline")
            self.assertTrue(state.budget_exceeded)
            self.assertTrue(state.cleanup_complete)
            self.assertFalse(state.sockets)
        state = F.NetStorageState(KEY, WRONG)
        state.request_timeout = 0.05
        with F.serve("netstorage", state) as port:
            conn = socket.create_connection(("127.0.0.1", port), timeout=2)
            try:
                self.assertEqual(conn.recv(1), b"")
            finally:
                conn.close()
        self.assertTrue(state.budget_exceeded)
        self.assertTrue(state.cleanup_complete)
        self.assertFalse(state.sockets)
        with socket.socket() as probe:
            self.assertNotEqual(probe.connect_ex(("127.0.0.1", port)), 0)

    def test_connection_admission_and_unknown_mode_or_bad_secrets_fail_closed(self):
        self.start()
        self.state.connection_limit = 0
        with self.assertRaises((OSError, http.client.HTTPException)):
            self.request()
        self.assertTrue(self.state.budget_exceeded)
        for args in ((KEY, WRONG, "redirect"), (KEY, KEY), ("", WRONG), (KEY, None), ("x" * 129, WRONG)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                F.NetStorageState(*args)


if __name__ == "__main__":
    unittest.main()
