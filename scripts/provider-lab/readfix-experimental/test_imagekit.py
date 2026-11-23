import importlib.util
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
import base64
import hashlib
import hmac
import http.client
import json
import threading
import time
import urllib.parse

ROOT = Path(__file__).resolve().parent
sys.path[:0] = [str(ROOT), str(ROOT / "foundation" if (ROOT / "foundation").is_dir() else ROOT.parent)]
from fixture_imagekit import ImageKitState, ImageKitHandler, API, CONTENT, UPDATED
from fixture_read_api import ReadFixture


class WireTests(unittest.TestCase):
    def setUp(self):
        self.state = ImageKitState("synthetic-test-key")

    def request(self, authority, target, headers=None, method="GET"):
        server = ReadFixture(self.state, ImageKitHandler)
        server.transport = SimpleNamespace(_server_name=authority)
        thread = threading.Thread(target=server.handle_request)
        thread.start()
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        try:
            connection.request(method, target, headers={"Host": authority, **(headers or {})})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()
            thread.join(5)
            server.server_close()
            self.assertFalse(thread.is_alive())

    def api(self, query, key=None, extra=""):
        token = self.state.password if key is None else key
        target = "/v2/files?" + urllib.parse.urlencode(query) + extra
        return self.request(API, target, {"Authorization": "Basic " + base64.b64encode((token + ":").encode()).decode()})

    def query(self, kind="file", name=None, parent="/"):
        return {"skip": "0", "limit": "1" if name else "100", "path": parent,
                "searchQuery": 'type = "' + kind + '"' + (' AND name = ' + json.dumps(name) if name else "")}

    def content(self, name="README-synthetic.txt", signature=None, headers=None):
        name = urllib.parse.quote(name, safe="/")
        query = urllib.parse.urlencode(sorted({"tr": "orig-true", "updatedAt": UPDATED}.items()))
        expires = str(int(time.time()))
        sign = hmac.new(self.state.password.encode(), (name + "?" + query + expires).encode(), hashlib.sha1).hexdigest()
        return self.request(CONTENT, "/" + name + "?" + query + "&ik-t=" + expires + "&ik-s=" + (sign if signature is None else signature), headers)

    def test_file_and_folder_listings(self):
        for kind in ("file", "folder"):
            code, payload = self.api(self.query(kind))
            self.assertEqual(code, 200)
            rows = json.loads(payload)
            self.assertTrue(rows)
            self.assertTrue(all(row["type"] == kind for row in rows))

    def test_nested_metadata_and_missing_file(self):
        name = next(n for n in self.state.files if n.startswith("nested/"))
        code, payload = self.api(self.query(name=name.split("/")[-1], parent="/nested/"))
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(payload)[0]["filePath"], "/" + name)
        code, payload = self.api(self.query(name="missing.txt"))
        self.assertEqual((code, json.loads(payload)), (200, []))
        self.assertEqual(self.state.missing, 1)

    def test_wrong_key_is_rejected(self):
        self.assertEqual(self.api(self.query(), key="wrong")[0], 403)
        self.assertEqual(self.state.denied, 1)

    def test_duplicate_query_is_rejected(self):
        self.assertEqual(self.api(self.query(), extra="&skip=0")[0], 400)
        self.assertEqual(self.state.unexpected, 1)

    def test_content_requires_signature_and_no_authorization(self):
        self.assertEqual(self.content(signature="0" * 40)[0], 400)
        self.assertEqual(self.content(headers={"Authorization": "Basic unexpected"})[0], 400)
        self.assertEqual(self.state.signed_reads, 0)

    def test_content_full_partial_and_ignored_range(self):
        body = self.state.files["README-synthetic.txt"]
        self.assertEqual(self.content(), (200, body))
        self.assertEqual(self.content(headers={"Range": "bytes=3-13"}), (206, body[3:14]))
        self.state.mode = "ignored_range"
        self.assertEqual(self.content(headers={"Range": "bytes=3-13"}), (200, body))

    def test_space_name_is_canonical_and_signed(self):
        self.assertEqual(self.content(name="nested/space name.txt"),
                         (200, self.state.files["nested/space name.txt"]))

    def test_denial_delivers_same_valid_payload(self):
        self.state.mode = "read_denied"
        self.assertEqual(self.content(), (403, self.state.files["README-synthetic.txt"]))
        self.assertEqual(self.state.read_denied, 1)


if __name__ == "__main__":
    unittest.main()
