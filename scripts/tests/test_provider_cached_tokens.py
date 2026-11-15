"""Independent cached-token wire cases for Shade and ShareFile."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
import urllib.parse

from test_provider_read_api import WireCase, PAYLOADS

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "provider-lab"))
try:
    import fixture_shade as S
    import fixture_sharefile as F
finally:
    sys.path.pop(0)

TOKEN = "synthetic-independent-token"


class ShadeWireTests(WireCase):
    def setUp(self):
        self.state = S.ShadeState(TOKEN)
        self.port = self.enterContext(S.serve_shade(self.state))

    def get(self, route, name="", authorization="Bearer " + TOKEN):
        return self.request("GET", "/synthetic-drive/fs/" + route + "?path=" + urllib.parse.quote(name, safe=""),
                            authorization=authorization)

    def test_directory_and_metadata_match_literal_corpus(self):
        for name, paths in (("", ["/README-synthetic.txt", "/nested"]), ("nested", ["/nested/bytes.bin", "/nested/space name.txt"])):
            status, _, raw = self.get("listdir", name)
            self.assertEqual(status, 200)
            self.assertEqual([v["path"] for v in json.loads(raw)], paths)
        for i, (name, data) in enumerate(PAYLOADS.items(), 301):
            status, _, raw = self.get("attr", name)
            self.assertEqual((status, json.loads(raw)), (200, {
                "type": "file", "path": "/" + name, "ino": i, "mtime": 1704067200000,
                "ctime": 1704067200000, "size": len(data), "draft": False,
                "hash": hashlib.md5(data).hexdigest()}))

    def test_direct_content_has_exact_bytes_without_redirects(self):
        for name, body in PAYLOADS.items():
            status, headers, raw = self.get("download", name)
            self.assertEqual((status, raw), (200, body))
            self.assertNotIn("Location", headers)
        self.assertEqual(self.state.payload_bytes, sum(map(len, PAYLOADS.values())))

    def test_missing_token_and_known_content_denials_are_distinct(self):
        self.assertEqual(self.get("attr", "absent-synthetic.txt")[0], 404)
        self.assertEqual(self.get("attr", "", "Bearer wrong")[0], 401)
        self.assertEqual(self.get("download", "README-synthetic.txt", None)[0], 401)
        self.state.mode = "read_denied"
        self.assertEqual(self.get("download", "README-synthetic.txt")[0], 403)
        self.assertEqual((self.state.missing, self.state.denied, self.state.read_denied, self.state.payload_bytes), (1, 2, 1, 0))

    def test_native_delete_route_is_only_a_write_guard(self):
        status, _, raw = self.request("POST", "/synthetic-drive/fs/delete?path=README-synthetic.txt", authorization="Bearer " + TOKEN)
        self.assertEqual((status, json.loads(raw)), (405, {"error": "synthetic fixture is read-only"}))
        self.assertEqual(self.state.rejected_mutations, 1)
        self.assertEqual(self.state.files, PAYLOADS)

    def test_unknown_drive_exchange_ranges_and_path_aliases_fail(self):
        for route in ("/other-drive/fs/attr?path=", "/workspaces/drives/synthetic-drive/shade-fs-token",
                      "/synthetic-drive/fs/attr?path=..%2Foutside", "/synthetic-drive/fs/listdir?path=nested%2F",
                      "/synthetic-drive/fs/attr?path=&path=nested", "/synthetic-drive/fs/download?path=nested%252Fbytes.bin"):
            self.assertEqual(self.request("GET", route, authorization="Bearer " + TOKEN)[0], 400)
        self.assertEqual(self.request("GET", "/synthetic-drive/fs/download?path=README-synthetic.txt",
                                     authorization="Bearer " + TOKEN, headers=(("Range", "bytes=0-1"),))[0], 400)
        self.assertEqual(self.state.payload_bytes, 0)


class ShareFileWireTests(WireCase):
    def setUp(self):
        self.state = F.ShareFileState(TOKEN)
        self.port = self.enterContext(F.serve_sharefile(self.state))

    def get(self, route, query=None, authorization="Bearer " + TOKEN):
        query = {"$select": "odata.count,FileCount,Name,FileName,CreationDate,IsHidden,FileSizeBytes,odata.type,Id,Hash,ClientModifiedDate"} if query is None else query
        return self.request("GET", "/sf/v3/" + route + "?" + urllib.parse.urlencode(query), authorization=authorization)

    def test_root_nested_and_item_metadata_match_literal_inventory(self):
        for identity, values in (("100", [("README-synthetic.txt", "301"), ("nested", "200")]),
                                 ("200", [("bytes.bin", "302"), ("space name.txt", "303")])):
            status, _, raw = self.get("Items(" + identity + ")/Children")
            result = json.loads(raw)
            self.assertEqual((status, result["odata.count"]), (200, 2))
            self.assertEqual([(v["Name"], v["Id"]) for v in result["value"]], values)
        for i, (name, body) in enumerate(PAYLOADS.items(), 301):
            status, _, raw = self.get(f"Items({i})")
            self.assertEqual((status, json.loads(raw)), (200, {
                "FileCount": 0, "Name": name.rsplit("/", 1)[-1], "FileName": name.rsplit("/", 1)[-1],
                "CreationDate": "2024-01-01T00:00:00Z", "ClientModifiedDate": "2024-01-01T00:00:00Z",
                "IsHidden": False, "FileSizeBytes": len(body), "odata.type": "ShareFile.Api.Models.File",
                "Id": str(i), "Hash": hashlib.md5(body).hexdigest()}))

    def test_by_path_metadata_and_missing_members_are_distinct(self):
        select = "odata.count,FileCount,Name,FileName,CreationDate,IsHidden,FileSizeBytes,odata.type,Id,Hash,ClientModifiedDate"
        status, _, raw = self.get("Items(100)/ByPath", {"$select": select, "path": "/nested/space name.txt"})
        self.assertEqual((status, json.loads(raw)["Id"]), (200, "303"))
        status, _, raw = self.get("Items(200)/ByPath", {"$select": select, "path": "/absent-synthetic.txt"})
        self.assertEqual((status, json.loads(raw)["code"]), (404, "404"))
        self.assertEqual(self.state.missing, 1)

    def test_links_are_owned_authorities_and_require_prior_issue(self):
        self.assertEqual(self.request("GET", "/content/301", authorization="Bearer " + TOKEN)[0], 400)
        for i, body in enumerate(PAYLOADS.values(), 301):
            status, _, raw = self.get(f"Items({i})/Download", {"redirect": "false"})
            self.assertEqual((status, json.loads(raw)), (200, {
                "DownloadToken": "synthetic-link", "DownloadUrl": f"http://127.0.0.1:{self.port}/content/{i}"}))
            self.assertEqual(self.request("GET", f"/content/{i}", authorization="Bearer " + TOKEN)[::2], (200, body))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_token_rejection_and_content_denial_never_return_source(self):
        for token in (None, "Bearer wrong"):
            status, headers, _ = self.get("Items(100)/Children", authorization=token)
            self.assertEqual(status, 401)
            self.assertNotIn("WWW-Authenticate", headers)
        self.get("Items(301)/Download", {"redirect": "false"})
        self.state.mode = "read_denied"
        self.assertEqual(self.request("GET", "/content/301", authorization="Bearer " + TOKEN)[0], 403)
        self.assertEqual((self.state.denied, self.state.read_denied, self.state.payload_bytes), (2, 1, 0))

    def test_only_reviewed_delete_parameters_reach_the_guard(self):
        target = "/sf/v3/Items(301)?singleversion=false&forceSync=true"
        status, _, raw = self.request("DELETE", target, authorization="Bearer " + TOKEN)
        self.assertEqual((status, json.loads(raw)), (405, {"error": "synthetic fixture is read-only"}))
        self.assertEqual(self.request("DELETE", "/sf/v3/Items(301)", authorization="Bearer " + TOKEN)[0], 400)
        self.assertEqual(self.request("DELETE", target.replace("false", "true"), authorization="Bearer " + TOKEN)[0], 400)
        self.assertEqual((self.state.rejected_mutations, self.state.payload_bytes), (1, 0))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_unreviewed_queries_renewal_and_cross_provider_routes_fail(self):
        for route in ("/sf/v3/Items(100)/Children?$select=Name", "/sf/v3/Items(301)/Download?redirect=true",
                      "/sf/v3/Items(100)/Upload2", "/oauth/token", "/synthetic-drive/fs/attr?path=",
                      "/content/301?extra=true"):
            self.assertEqual(self.request("GET", route, authorization="Bearer " + TOKEN)[0], 400)
        self.assertEqual(self.state.payload_bytes, 0)


if __name__ == "__main__":
    unittest.main()
