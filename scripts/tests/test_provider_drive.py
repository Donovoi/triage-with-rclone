"""Independent Google Drive wire oracles; no vendor or native acceptance."""
import urllib.parse
import hashlib
import http.client
import json
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
    import fixture_drive as C
    import fixture_tls as T
finally:
    sys.path.pop(0)

NAME = "www.googleapis.com"
API = "/drive/v3/files"
SECRET = "synthetic-secret"
PAYLOADS = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
            "nested/bytes.bin": bytes(range(256)) * 8, "nested/space name.txt": b"Nested synthetic payload.\n"}
FIELDS = "id,name,size,md5Checksum,sha1Checksum,sha256Checksum,trashed,explicitlyTrashed,modifiedTime,createdTime,mimeType,parents,webViewLink,shortcutDetails,exportLinks,resourceKey"
LIST_FIELDS = "files(" + FIELDS + "),nextPageToken,incompleteSearch"
FOLDER = "application/vnd.google-apps.folder"
BROWSER = "synthetic-agent"
IDS = {"": "synthetic-root", "nested": "synthetic-nested", "README-synthetic.txt": "file-1801",
       "nested/bytes.bin": "file-1802", "nested/space name.txt": "file-1803"}

class DriveWireTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.state = C.DriveState(SECRET)
        # Wire tests use ephemeral IP TLS, so they also run on Windows without
        # DNS/privileged ports. The contained native probe owns fixed-host TLS.
        self.certificates = self.enterContext(T.FixtureCertificates.create(self.root))
        self.transport = self.enterContext(T.BoundedHttpsServer(self.certificates, C.DriveHandler, state=self.state))

    def request(self, method, path, data=None, auth="Bearer " + SECRET, headers=(), raw_body=None, host=NAME, user_agent=BROWSER):
        body = raw_body if raw_body is not None else json.dumps(data).encode() if data is not None else b""
        client = http.client.HTTPSConnection("127.0.0.1", self.transport.port, timeout=3,
                                             context=self.certificates.client_context())
        try:
            client.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            client.putheader("Host", host)
            if user_agent is not None:
                client.putheader("User-Agent", user_agent)
            if auth is not None:
                client.putheader("Authorization", auth)
            if body:
                client.putheader("Content-Length", str(len(body)))
                client.putheader("Content-Type", "application/json")
            for k, v in headers:
                client.putheader(k, v)
            client.endheaders(body)
            response = client.getresponse()
            return response.status, dict(response.getheaders()), response.read(65537)
        finally:
            client.close()





    def query(self, directory="", title="", kind="all"):
        q = "trashed=false and ('" + IDS[directory] + "' in parents)"
        if title:
            q += " and (name='" + title + "')"
        if kind == "directories":
            q += " and (mimeType='" + FOLDER + "' or mimeType='application/vnd.google-apps.shortcut')"
        elif kind == "files":
            q += " and mimeType!='" + FOLDER + "'"
        return {"alt": "json", "prettyPrint": "false", "pageSize": "1000", "supportsAllDrives": "true",
                "includeItemsFromAllDrives": "true", "fields": LIST_FIELDS, "q": q}

    def listing(self, directory="", title="", kind="all", **kwargs):
        return self.request("GET", API + "?" + urllib.parse.urlencode(self.query(directory, title, kind)), **kwargs)

    def meta(self, name="", **kwargs):
        query = {"alt": "json", "prettyPrint": "false", "supportsAllDrives": "true", "fields": FIELDS}
        return self.request("GET", API + "/" + IDS[name] + "?" + urllib.parse.urlencode(query), **kwargs)

    def content(self, name="README-synthetic.txt", observe=True, **kwargs):
        if observe:
            self.assertEqual(self.meta(name)[0], 200)
        return self.request("GET", API + "/" + IDS[name] + "?alt=media", **kwargs)

    def test_saved_bearer_identity_is_exact_without_refresh_fallback(self):
        for auth in (None, "", "OAuth " + SECRET, "Bearer wrong", "bearer " + SECRET):
            status, _, raw = self.listing(auth=auth)
            self.assertEqual((status, json.loads(raw)["error"]["code"]), (401, 401))
            self.assertEqual(json.loads(raw)["error"]["errors"][0]["reason"], "authError")
        self.assertEqual((self.state.denied, self.state.payload_bytes, self.state.observed), (5, 0, set()))

    def test_complete_inventories_and_independent_three_hash_metadata(self):
        # Literal digests obtained with OpenSSL from the three independent bytes.
        hashes = {
            "README-synthetic.txt": ("f9ac90560b9929242009ee0c24c9e5d8", "1ec3b3f6066fc5a95bbdd77582db2aab6a3b5cd4",
                                     "1e901527b93ae84dc9d95a8aa76bbc12d7d77dbf8ab449333c172cfc909c639e"),
            "nested/bytes.bin": ("1576a94d6cb334dd126cb1c27f19e0f2", "f10ccfde60c17db26e7d85d35665c7661dbbeb2c",
                                 "10fc3c51a152e90e5b90319b601d92ccf37290ef53c35ff92507687d8a911a08"),
            "nested/space name.txt": ("371d24ba264bcaac3332a3ed564a93f8", "e5f3513d82c1077ee498c25b7ce3500d392bf801",
                                      "e019c52fe70badce27affda5e408659399ff764985f07104029a42ade38125bd")}
        def metadata(name):
            item = {"id": IDS[name], "name": name.rsplit("/", 1)[-1] if name else "synthetic-root",
                    "mimeType": "application/octet-stream" if name in PAYLOADS else FOLDER,
                    "parents": [IDS["nested" if name.startswith("nested/") else ""]] if name else [],
                    "trashed": False, "explicitlyTrashed": False,
                    "modifiedTime": "2024-01-01T00:00:00Z", "createdTime": "2024-01-01T00:00:00Z"}
            if name in PAYLOADS:
                md5, sha1, sha256 = hashes[name]
                item.update(size=str(len(PAYLOADS[name])), md5Checksum=md5, sha1Checksum=sha1, sha256Checksum=sha256)
            return item
        for name in IDS:
            self.assertEqual(self.meta(name)[0], 200)
            self.assertEqual(json.loads(self.meta(name)[2]), metadata(name))
        for directory, names in (("", ["README-synthetic.txt", "nested"]), ("nested", ["nested/bytes.bin", "nested/space name.txt"])):
            status, _, raw = self.listing(directory)
            self.assertEqual((status, json.loads(raw)), (200, {"kind": "drive#fileList", "incompleteSearch": False,
                                                              "files": [metadata(name) for name in names]}))
        self.assertEqual(self.state.observed, set(PAYLOADS))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_exact_name_parent_and_type_predicates_are_applied(self):
        cases = [("", "nested", "directories", ["synthetic-nested"]),
                 ("", "nested", "files", []), ("", "README-synthetic.txt", "directories", []),
                 ("", "README-synthetic.txt", "files", ["file-1801"]),
                 ("nested", "space name.txt", "files", ["file-1803"]),
                 ("nested", "nested", "directories", []), ("", "", "directories", ["synthetic-nested"]),
                 ("nested", "", "files", ["file-1802", "file-1803"])]
        for directory, title, kind, ids in cases:
            status, _, raw = self.listing(directory, title, kind)
            self.assertEqual(status, 200)
            self.assertEqual([item["id"] for item in json.loads(raw)["files"]], ids)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_missing_selection_is_empty_complete_and_never_fabricates_an_item(self):
        for kind in ("all", "files", "directories"):
            status, _, raw = self.listing(title="absent-synthetic.txt", kind=kind)
            self.assertEqual((status, json.loads(raw)), (200, {"kind": "drive#fileList", "incompleteSearch": False, "files": []}))
        self.assertEqual((self.state.missing, self.state.observed, self.state.payload_bytes), (3, set(), 0))

    def test_content_requires_prior_observation_and_the_saved_token(self):
        self.assertEqual(self.content(observe=False)[0], 400)
        self.assertEqual(self.state.payload_bytes, 0)
        self.assertEqual(self.listing()[0], 200)
        for auth in (None, "", "Bearer wrong"):
            self.assertEqual(self.content(observe=False, auth=auth)[0], 401)
        self.assertEqual(self.state.payload_bytes, 0)
        self.assertEqual(self.content(observe=False)[::2], (200, PAYLOADS["README-synthetic.txt"]))

    def test_three_literal_downloads_preserve_sources(self):
        for name, payload in PAYLOADS.items():
            self.assertEqual(self.content(name)[::2], (200, payload))
        self.assertEqual(self.state.payload_bytes, 2136)
        self.assertEqual(self.state.files, PAYLOADS)
        self.assertEqual(sorted(name for event, name in self.state.events if event == "content"), sorted(PAYLOADS))

    def test_denied_media_and_direct_guard_do_not_supply_native_write_evidence(self):
        self.assertEqual(self.meta("README-synthetic.txt")[0], 200)
        self.state.mode = "read_denied"
        status, _, raw = self.content(observe=False)
        self.assertEqual((status, json.loads(raw)["error"]["code"], json.loads(raw)["error"]["errors"][0]["reason"]),
                         (403, 403, "forbidden"))
        self.state.mode = "normal"
        self.assertEqual(self.request("DELETE", API + "/file-1801?alt=media")[0], 405)
        self.assertEqual(self.request("DELETE", API + "/file-1801")[0], 400)
        self.assertEqual((self.state.read_denied, self.state.rejected_mutations, self.state.payload_bytes), (1, 1, 0))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_list_controls_are_closed_and_continuations_cannot_be_ignored(self):
        original = self.query()
        for key, value in (("pageSize", "1"), ("supportsAllDrives", "false"), ("includeItemsFromAllDrives", "false"),
                           ("fields", "files(id)"), ("alt", "media"), ("prettyPrint", "true"),
                           ("pageToken", "synthetic-next"), ("driveId", "unreviewed"), ("corpora", "allDrives"),
                           ("spaces", "appDataFolder"), ("access_token", SECRET)):
            query = dict(original);query[key] = value
            self.assertEqual(self.request("GET", API + "?" + urllib.parse.urlencode(query))[0], 400)
        for key in original:
            query = dict(original);del query[key]
            self.assertEqual(self.request("GET", API + "?" + urllib.parse.urlencode(query))[0], 400)
        self.assertEqual(self.state.observed, set())

    def test_search_predicates_cannot_broaden_scope_or_trash_and_type_rules(self):
        for expression in ("", "'synthetic-root' in parents", "trashed=true and ('synthetic-root' in parents)",
                           "trashed=false", "trashed=false and ('foreign' in parents)",
                           "trashed=false and ('synthetic-root' in parents or 'foreign' in parents)",
                           "trashed=false and ('synthetic-root' in parents) and (name contains 'README')",
                           "trashed=false and ('synthetic-root' in parents) and (name='readme-synthetic.txt')",
                           "trashed=false and ('synthetic-root' in parents) or sharedWithMe=true"):
            query = self.query();query["q"] = expression
            self.assertEqual(self.request("GET", API + "?" + urllib.parse.urlencode(query))[0], 400)
        self.assertEqual((self.state.observed, self.state.payload_bytes), (set(), 0))

    def test_duplicates_invalid_encoding_and_metadata_extra_queries_are_rejected(self):
        path = API + "?" + urllib.parse.urlencode(self.query())
        for suffix in ("&q=duplicate", "&pageSize=1000", "&bad=%ff", "&bad=%GG", "&bad=%00"):
            self.assertEqual(self.request("GET", path + suffix)[0], 400)
        for path in (API + "/synthetic-root?fields=id", API + "/file-1801?alt=media&prettyPrint=false",
                     API + "/file-1801?alt=media&acknowledgeAbuse=true", API + "/file-1801?alt=media&access_token=x"):
            self.assertEqual(self.request("GET", path)[0], 400)
        self.assertEqual(self.state.observed, set())

    def test_grants_exports_shortcuts_changes_shared_drives_and_mutations_are_outside_scope(self):
        for method, path in (("POST", "/token"), ("GET", "/authorize"), ("GET", "/drive/v3/about"),
                             ("GET", "/drive/v3/changes"), ("GET", "/drive/v3/drives"),
                             ("GET", API + "/root"), ("GET", API + "/file-1801/export"),
                             ("GET", API + "/shortcut-id"), ("POST", API), ("PUT", API + "/file-1801"),
                             ("HEAD", API + "/file-1801?alt=media"), ("GET", "https://elsewhere.invalid/")):
            self.assertEqual(self.request(method, path)[0], 400)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_path_and_header_scope_is_exact(self):
        for path in ("/drive/v2/files", API + "//file-1801", API + "/../file-1801", API + "/%66ile-1801",
                     API + "/file-1801/", API + "/file%2D1801", API + "/foreign"):
            self.assertEqual(self.request("GET", path)[0], 400)
        target = API + "?" + urllib.parse.urlencode(self.query())
        for host in ("127.0.0.1", NAME + ":443", NAME + ".", "WWW.googleapis.com"):
            self.assertEqual(self.request("GET", target, host=host)[0], 400)
        for headers in ((("Host", NAME),), (("Authorization", "Bearer " + SECRET),), (("Cookie", "x"),),
                        (("X-Goog-Drive-Resource-Keys", "x"),), (("Content-Length", "00"),),
                        (("Transfer-Encoding", "chunked"),), (("Range", "bytes=0-1"),)):
            self.assertEqual(self.request("GET", target, headers=headers)[0], 400)
        self.assertEqual(self.request("GET", target, raw_body=b"x")[0], 400)
        self.assertEqual(self.state.observed, set())

    def test_content_ranges_are_bounded(self):
        status, headers, raw = self.content("nested/bytes.bin", headers=(("Range", "bytes=256-511"),))
        self.assertEqual((status, headers["Content-Range"], raw), (206, "bytes 256-511/2048", bytes(range(256))))
        for value in ("bytes=0--1", "bytes=-1", "bytes=2048-", "bytes=2-1", "bytes=0-1,3-4"):
            self.assertEqual(self.content("nested/bytes.bin", headers=(("Range", value),))[0], 416)
        self.assertEqual(self.state.files, PAYLOADS)

    def test_request_and_response_budgets_prevent_success(self):
        self.state.request_limit = 1
        self.assertEqual(self.meta()[0], 200)
        self.assertEqual(self.meta()[0], 429)
        self.assertTrue(self.state.budget_exceeded)
        self.state.request_limit = 10;self.state.byte_limit = 1
        self.assertEqual(self.meta()[0], 429)

    def test_tls_deadline_stops_partial_headers(self):
        timer = threading.Timer
        with T.FixtureCertificates.create(self.root) as certificates, patch.object(
                T.threading, "Timer", side_effect=lambda delay, callback: timer(delay + 0.3, callback)):
            with T.BoundedHttpsServer(certificates, C.DriveHandler, state=C.DriveState(SECRET),
                    limits=T.TlsLimits(request_seconds=0.15)) as transport:
                with socket.create_connection(("127.0.0.1", transport.port), timeout=2) as raw:
                    with certificates.client_context().wrap_socket(raw, server_hostname="127.0.0.1") as client:
                        client.sendall(("GET " + API + " HTTP/1.1\r\nHost: " + NAME).encode())
                        self.assertEqual(client.recv(1), b"")
            self.assertIn("tls_request_deadline", transport.snapshot()["failure_codes"])
            self.assertTrue(transport.cleanup_complete)
        self.assertTrue(certificates.cleanup_complete)

class DriveAuthorityTests(unittest.TestCase):
    def test_reviewed_name_has_its_own_exact_sni_and_san(self):
        with tempfile.TemporaryDirectory() as directory:
            with T.FixtureCertificates.create(Path(directory).resolve(), server_name=NAME) as certificates:
                from cryptography import x509
                leaf = x509.load_pem_x509_certificate((certificates.directory / "leaf.pem").read_bytes())
                self.assertEqual(list(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value), [x509.DNSName(NAME)])
        self.assertIsNone(T._drive_sni(None, NAME, None))
        for name in (None, "", "fixture.pcloud.com", "api.cloudinary.com", "127.0.0.1", NAME + ".", NAME + ":443"):
            self.assertEqual(T._drive_sni(None, name, None), ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)
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
