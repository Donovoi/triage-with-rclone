"""Independent Dropbox wire oracles; no vendor or native acceptance."""
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
    import fixture_dropbox as C
    import fixture_tls as T
finally:
    sys.path.pop(0)

NAME = "api.dropboxapi.com"
CONTENT = "content.dropboxapi.com"
API = "/2/files/"
SECRET = "synthetic-secret"
ROOT = "/synthetic-root"
PAYLOADS = {"README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
            "nested/bytes.bin": bytes(range(256)) * 8, "nested/space name.txt": b"Nested synthetic payload.\n"}
IDS = {"": "id:synthetic-root", "nested": "id:synthetic-nested", "README-synthetic.txt": "id:file2001",
       "nested/bytes.bin": "id:file2002", "nested/space name.txt": "id:file2003"}
HASHES = {"README-synthetic.txt": "823087158a15f5a994832b798520fd354c1ab2ed34987f47e2b073288fc9bcc4",
          "nested/bytes.bin": "d5b3931c2c1fb7a97e894feba5e2d7a8a7e0da594296aec3c4aba8f8cbf9a988",
          "nested/space name.txt": "b179a633d780a37c142aea9f1c64179e20e491eec17576325244266d96e0dccc"}

class DropboxWireTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.state = C.DropboxState(SECRET)
        self.certificates = self.enterContext(T.FixtureCertificates.create(self.root))
        self.transport = self.enterContext(T.BoundedHttpsServer(self.certificates, C.DropboxHandler, state=self.state))

    def request(self, method, path, data=None, auth="Bearer " + SECRET, headers=(), raw_body=None,
                host=NAME, content_type="application/json"):
        body = raw_body if raw_body is not None else json.dumps(data).encode() if data is not None else b""
        client = http.client.HTTPSConnection("127.0.0.1", self.transport.port, timeout=3,
                                             context=self.certificates.client_context())
        try:
            client.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            client.putheader("Host", host)
            if auth is not None:
                client.putheader("Authorization", auth)
            if content_type is not None:
                client.putheader("Content-Type", content_type)
            if body:
                client.putheader("Content-Length", str(len(body)))
            for key, value in headers:
                client.putheader(key, value)
            client.endheaders(body)
            response = client.getresponse()
            return response.status, dict(response.getheaders()), response.read(65537)
        finally:
            client.close()

    def meta_data(self, name=""):
        return {"path": ROOT + ("/" + name if name else ""), "include_media_info": False,
                "include_deleted": False, "include_has_explicit_shared_members": False}

    def listing_data(self, name=""):
        return {"path": ROOT + ("/" + name if name else ""), "recursive": False, "include_media_info": False,
                "include_deleted": False, "include_has_explicit_shared_members": False,
                "include_mounted_folders": True, "limit": 1000, "include_non_downloadable_files": True,
                "include_restorable_info": False}

    def meta(self, name="", **kwargs):
        return self.request("POST", API + "get_metadata", self.meta_data(name), **kwargs)

    def listing(self, name="", **kwargs):
        return self.request("POST", API + "list_folder", self.listing_data(name), **kwargs)

    def content(self, name="README-synthetic.txt", observe=True, headers=(), **kwargs):
        if observe:
            self.assertEqual(self.meta(name)[0], 200)
        return self.request("POST", API + "download", host=CONTENT, content_type="application/octet-stream",
                            headers=(("Dropbox-API-Arg", json.dumps({"path": IDS[name]})), *headers), **kwargs)

    def metadata(self, name):
        path = ROOT + ("/" + name if name else "")
        item = {".tag": "file" if name in PAYLOADS else "folder", "id": IDS[name],
                "name": name.rsplit("/", 1)[-1] if name else "synthetic-root",
                "path_lower": path.lower(), "path_display": path}
        if name in PAYLOADS:
            item.update(size=len(PAYLOADS[name]), client_modified="2024-01-01T00:00:00Z",
                        server_modified="2024-01-01T00:00:00Z", rev="synthetic-revision",
                        is_downloadable=True, content_hash=HASHES[name])
        return item

    def test_saved_bearer_is_exact_for_rpc_and_content_without_renewal(self):
        for auth in (None, "", "OAuth " + SECRET, "Bearer wrong", "bearer " + SECRET):
            status, _, raw = self.meta(auth=auth)
            self.assertEqual((status, json.loads(raw)), (401, {"error_summary": "invalid_access_token/",
                                                             "error": {".tag": "invalid_access_token"}}))
        self.assertEqual((self.state.denied, self.state.observed, self.state.payload_bytes), (5, set(), 0))
        self.assertEqual(self.meta("README-synthetic.txt")[0], 200)
        self.assertEqual(self.content(observe=False, auth=None)[0], 401)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_tagged_metadata_complete_inventories_and_independent_hash_oracles(self):
        for name in IDS:
            status, _, raw = self.meta(name)
            self.assertEqual((status, json.loads(raw)), (200, self.metadata(name)))
        for folder, names in (("", ["README-synthetic.txt", "nested"]), ("nested", ["nested/bytes.bin", "nested/space name.txt"])):
            status, _, raw = self.listing(folder)
            self.assertEqual((status, json.loads(raw)), (200, {"entries": [self.metadata(name) for name in names],
                                                              "cursor": "synthetic-complete-cursor", "has_more": False}))
        self.assertEqual(self.state.observed, set(PAYLOADS))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_content_hash_uses_binary_blocks_and_correct_empty_boundary_behavior(self):
        vectors = [(b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                   (b"x", "0a325ca303eb3014c43ae004970f343634db176fa1697bcc8c9efac94626488d"),
                   (b"x" * 4194303, "fb129a5bb012945cae8a89f0e79aec4943df2683cee962903295134cdc4dfdd6"),
                   (b"x" * 4194304, "7cb1633b75c3caf1295e18a48aeb3f8bd7f74c5bafa25b4211433cfb2de6de12"),
                   (b"x" * 4194305, "656e7e27f7d0459e319264cdccb61f6667e8e964f8e763c332f35d36ee1cb924")]
        for body, digest in vectors:
            self.assertEqual(C.content_hash(body), digest)

    def test_content_requires_observed_id_and_carries_exact_result_metadata(self):
        self.assertEqual(self.content(observe=False)[0], 400)
        self.assertEqual(self.state.payload_bytes, 0)
        self.assertEqual(self.listing()[0], 200)
        status, headers, raw = self.content(observe=False)
        self.assertEqual((status, raw), (200, PAYLOADS["README-synthetic.txt"]))
        self.assertEqual(json.loads(headers["Dropbox-API-Result"]), self.metadata("README-synthetic.txt"))
        for data in ({"path": ROOT + "/README-synthetic.txt"}, {"path": "id:foreign"},
                     {"path": "id:file2001", "rev": "synthetic"}, {"path": "id:synthetic-root"}):
            self.assertEqual(self.request("POST", API + "download", host=CONTENT, content_type="application/octet-stream",
                             headers=(("Dropbox-API-Arg", json.dumps(data)),))[0], 400)

    def test_three_literal_downloads_preserve_sources(self):
        for name, payload in PAYLOADS.items():
            self.assertEqual(self.content(name)[::2], (200, payload))
        self.assertEqual(self.state.payload_bytes, 2136)
        self.assertEqual(self.state.files, PAYLOADS)

    def test_missing_metadata_and_listing_return_typed_not_found(self):
        for call in (self.meta, self.listing):
            status, _, raw = call("absent-synthetic.txt")
            self.assertEqual((status, json.loads(raw)), (409, {"error_summary": "path/not_found/",
                    "error": {".tag": "path", "path": {".tag": "not_found"}}}))
        self.assertEqual((self.state.missing, self.state.observed, self.state.payload_bytes), (2, set(), 0))

    def test_restricted_content_denial_and_direct_guard_preserve_sources(self):
        self.assertEqual(self.meta("README-synthetic.txt")[0], 200)
        self.state.mode = "read_denied"
        status, _, raw = self.content(observe=False)
        self.assertEqual((status, json.loads(raw)), (409, {"error_summary": "path/restricted_content/",
                "error": {".tag": "path", "path": {".tag": "restricted_content"}}}))
        self.state.mode = "normal"
        self.assertEqual(self.request("DELETE", API + "download", host=CONTENT, content_type="application/octet-stream",
                                     headers=(("Dropbox-API-Arg", '{"path":"id:file2001"}'),))[0], 405)
        self.assertEqual((self.state.read_denied, self.state.rejected_mutations, self.state.payload_bytes), (1, 1, 0))
        self.assertEqual(self.state.files, PAYLOADS)

    def test_rpc_flags_and_types_cannot_widen_scope_or_silently_change_listing(self):
        original = self.listing_data()
        for key, value in (("recursive", True), ("include_deleted", True), ("include_mounted_folders", False),
                           ("include_media_info", True), ("include_has_explicit_shared_members", True),
                           ("include_non_downloadable_files", False), ("include_restorable_info", True),
                           ("limit", 1), ("limit", 1000.0), ("recursive", 0), ("cursor", "next"),
                           ("shared_link", {}), ("include_property_groups", {})):
            data = dict(original);data[key] = value
            self.assertEqual(self.request("POST", API + "list_folder", data)[0], 400)
        for key in original:
            data = dict(original);del data[key]
            self.assertEqual(self.request("POST", API + "list_folder", data)[0], 400)
        for key, value in (("include_deleted", True), ("include_media_info", 0), ("include_has_explicit_shared_members", True)):
            data = self.meta_data();data[key] = value
            self.assertEqual(self.request("POST", API + "get_metadata", data)[0], 400)
        self.assertEqual(self.state.observed, set())

    def test_exact_source_paths_reject_account_root_traversal_and_case_aliases(self):
        for name in ("", "/", "/foreign", ROOT + "/", ROOT + "/../README-synthetic.txt",
                     ROOT + "/nested//bytes.bin", ROOT + "/nested%2Fbytes.bin", ROOT + "/readme-synthetic.txt",
                     ROOT + "/nested/space%20name.txt", "id:file2001"):
            data = self.meta_data();data["path"] = name
            self.assertEqual(self.request("POST", API + "get_metadata", data)[0], 400)
        self.assertEqual(self.state.observed, set())

    def test_api_and_content_authorities_cannot_be_crossed(self):
        self.assertEqual(self.meta(host=CONTENT)[0], 400)
        self.assertEqual(self.request("POST", API + "download", host=NAME, content_type="application/octet-stream",
                        headers=(("Dropbox-API-Arg", '{"path":"id:file2001"}'),))[0], 400)
        with patch.object(self.transport, "_server_name", CONTENT):
            self.assertEqual(self.meta()[0], 400)
        self.assertEqual(self.meta("README-synthetic.txt")[0], 200)
        with patch.object(self.transport, "_server_name", NAME):
            self.assertEqual(self.content(observe=False)[0], 400)
        self.assertEqual(self.state.payload_bytes, 0)

    def test_namespace_impersonation_cookie_duplicate_and_framing_headers_fail(self):
        for key in ("Dropbox-API-Path-Root", "Dropbox-API-Select-User", "Dropbox-API-Select-Admin", "Cookie",
                    "Dropbox-API-Arg", "Range"):
            self.assertEqual(self.meta(headers=((key, "synthetic"),))[0], 400)
        for host in (NAME + ":443", NAME + ".", "API.dropboxapi.com", "127.0.0.1"):
            self.assertEqual(self.meta(host=host)[0], 400)
        for headers in ((("Host", NAME),), (("Authorization", "Bearer " + SECRET),),
                        (("Content-Length", "4097"),), (("Transfer-Encoding", "chunked"),)):
            self.assertEqual(self.meta(headers=headers)[0], 400)
        for content_type in (None, "text/plain", "application/json; charset=utf-8"):
            self.assertEqual(self.meta(content_type=content_type)[0], 400)
        self.assertEqual(self.state.observed, set())

    def test_duplicate_and_nonobject_json_are_rejected_in_body_and_header(self):
        for body in (b'{"path":"x","path":"x"}', b'[]', b'null', b'{"path":', b'\xff'):
            self.assertEqual(self.request("POST", API + "get_metadata", raw_body=body)[0], 400)
        for value in ('{"path":"id:file2001","path":"id:file2001"}', '[]', 'null', '{"path":', ''):
            self.assertEqual(self.request("POST", API + "download", host=CONTENT, content_type="application/octet-stream",
                             headers=(("Dropbox-API-Arg", value),))[0], 400)
        self.assertEqual(self.state.observed, set())

    def test_grants_continuations_exports_teams_changes_and_writes_are_outside_scope(self):
        for path in ("/oauth2/token", "/oauth2/authorize", "/2/users/get_current_account",
                     API + "list_folder/continue", API + "list_folder/longpoll", API + "export",
                     API + "get_temporary_link", API + "upload", API + "delete_v2", "/2/team/members/get_info",
                     "/2/sharing/list_folders", API + "get_metadata?access_token=x"):
            self.assertEqual(self.request("POST", path, {"path": ROOT})[0], 400)
        for method in ("GET", "HEAD", "PUT", "DELETE"):
            self.assertEqual(self.request(method, API + "get_metadata", self.meta_data())[0], 400)
        self.assertEqual((self.state.payload_bytes, self.state.rejected_mutations), (0, 0))

    def test_ranges_require_content_route_and_are_bounded(self):
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

    def test_tls_deadline_stops_partial_headers_and_rpc_json(self):
        timer = threading.Timer
        for partial in ("POST /2/files/get_metadata HTTP/1.1\r\nHost: " + NAME,
                        "POST /2/files/get_metadata HTTP/1.1\r\nHost: " + NAME +
                        "\r\nContent-Type: application/json\r\nContent-Length: 200\r\n\r\n{"):
            with T.FixtureCertificates.create(self.root) as certificates, patch.object(
                    T.threading, "Timer", side_effect=lambda delay, callback: timer(delay + 0.3, callback)):
                with T.BoundedHttpsServer(certificates, C.DropboxHandler, state=C.DropboxState(SECRET),
                        limits=T.TlsLimits(request_seconds=0.15)) as transport:
                    with socket.create_connection(("127.0.0.1", transport.port), timeout=2) as raw:
                        with certificates.client_context().wrap_socket(raw, server_hostname="127.0.0.1") as client:
                            client.sendall(partial.encode())
                            self.assertEqual(client.recv(1), b"")
                self.assertIn("tls_request_deadline", transport.snapshot()["failure_codes"])
                self.assertTrue(transport.cleanup_complete)
            self.assertTrue(certificates.cleanup_complete)

class DropboxAuthorityTests(unittest.TestCase):
    def test_each_authority_has_distinct_exact_sni_and_single_name_certificate(self):
        from cryptography import x509
        for name, callback in ((NAME, T._dropbox_api_sni), (CONTENT, T._dropbox_content_sni)):
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

class DropboxPairCleanupTests(unittest.TestCase):
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
        state = C.DropboxState(SECRET)
        with patch.object(C.FixtureCertificates, "create", side_effect=create), patch.object(C, "BoundedHttpsServer", transport), \
             patch.object(C, "listeners_closed", return_value=True):
            with self.assertRaisesRegex(RuntimeError, "synthetic_start_failed"):
                with C.serve_dropbox(Path("/synthetic"), state):
                    self.fail("startup must fail")
        self.assertEqual([name for event, name in events if event == "closed"], [CONTENT, NAME])
        self.assertTrue(all(t.cleanup_complete for t in transports))
        self.assertTrue(all(c.cleanup_complete for c in certificates))
        self.assertTrue(state.cleanup_complete)

    def test_failed_content_cleanup_is_not_hidden_by_successful_api_cleanup(self):
        create, transport, certificates, transports, events = self.pair(fail_close=True)
        state = C.DropboxState(SECRET)
        with patch.object(C.FixtureCertificates, "create", side_effect=create), patch.object(C, "BoundedHttpsServer", transport), \
             patch.object(C, "listeners_closed", return_value=True):
            with self.assertRaisesRegex(RuntimeError, "dropbox_cleanup_failed"):
                with C.serve_dropbox(Path("/synthetic"), state):
                    pass
        self.assertEqual([name for event, name in events if event == "closed"], [CONTENT, NAME])
        self.assertTrue(all(c.cleanup_complete for c in certificates))
        self.assertFalse(state.cleanup_complete)

if __name__ == "__main__":
    unittest.main()
