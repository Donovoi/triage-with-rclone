"""Mocked public metadata transport/lifetime tests; no live network/processes."""
import contextlib
from email.message import Message
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import urllib.error

SPEC = importlib.util.spec_from_file_location("jdk_metadata_test_module", Path(__file__).with_name("jdk_metadata.py"))
j = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = j
SPEC.loader.exec_module(j)
TOKEN = "SYNTHETIC_TOKEN_CANARY_NOT_AN_ACCOUNT"
SIGNED_URL = "https://production.cloudfront.docker.com/public-config?signature=SIGNED_QUERY_CANARY"


class Response:
    def __init__(self, url, data=b"public metadata", status=200, headers=()):
        self.url, self.status, self.stream = url, status, io.BytesIO(data)
        self.headers = Message()
        for name, value in headers:
            self.headers[name] = value

    def geturl(self):
        return self.url

    def read1(self, size):
        return self.stream.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.stream.close()


def redirect(url, target=SIGNED_URL, status=307):
    headers = Message()
    headers["Location"] = target
    return urllib.error.HTTPError(url, status, "PRIVATE_REDIRECT_CANARY", headers, io.BytesIO(b"PRIVATE_BODY_CANARY"))


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.stack = contextlib.ExitStack()
        self.stack.enter_context(mock.patch.object(subprocess, "Popen", side_effect=AssertionError("native_forbidden")))
        self.stack.enter_context(mock.patch.object(j.multiprocessing, "get_context", side_effect=AssertionError("worker_forbidden")))
        self.stack.enter_context(mock.patch.object(j.urllib.request.OpenerDirector, "open", side_effect=AssertionError("network_forbidden")))

    def tearDown(self):
        self.stack.close()
        self.temp.cleanup()

    def error(self, code, fn, *args, **kwargs):
        with self.assertRaises(j.MetadataError) as caught:
            fn(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_fixed_published_metadata_hashes_no_layers(self):
        self.assertEqual(len(j.FILES), 3)
        self.assertEqual([item[2] for item in j.FILES], [
            "e1c09a9ee23feb81f94016547826c1e694086cd927356fb57fccc312fcc32f85",
            "d0e6e16acb7f941e5206d99ec38e5bba18545c43462541958f84b22e0fc006e8",
            "109562d9f45342ba0a5dbd16a35f20d96d7c667367b2e151c998ca57aa252fbf"])
        self.assertTrue(j.FILES[2][1].endswith("/17/jdk/ubuntu/noble/Dockerfile"))
        self.assertIn("scope=repository:library/eclipse-temurin:pull", j.TOKEN_URL)

    def test_host_guard_rejects_unhosted_root_and_wrong_platform(self):
        env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux"}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(j.platform, "system", return_value="Linux"), \
                mock.patch.object(j.platform, "machine", return_value="x86_64"), mock.patch.object(j.os, "getuid", return_value=1001, create=True):
            j.hosted_guard()
            for field in env:
                with self.subTest(field=field), mock.patch.dict(os.environ, {field: "wrong"}):
                    self.error("metadata_host_invalid", j.hosted_guard)
            with mock.patch.object(j.os, "getuid", return_value=0):
                self.error("metadata_host_invalid", j.hosted_guard)

    def test_token_exact_ascii_header_safe_pair_and_types(self):
        self.assertEqual(j.parse_token(json.dumps({"token": TOKEN, "access_token": TOKEN, "expires_in": 300}).encode()), TOKEN)
        bad = [{}, {"token": "short"}, {"token": TOKEN + "\r\nX: leak"},
               {"token": TOKEN, "access_token": "other"}, {"token": TOKEN, "expires_in": True},
               {"token": TOKEN, "refresh_token": "unapproved"}, {"token": TOKEN, "issued_at": {}}]
        for value in bad:
            with self.subTest(value=value):
                self.error("metadata_auth_invalid", j.parse_token, json.dumps(value).encode())
        self.error("metadata_auth_invalid", j.parse_token, b'{"token":"one","token":"two"}')

    def test_token_sent_only_to_two_exact_registry_urls(self):
        for url in (j.TOKEN_URL, j.FILES[2][1]):
            opener = mock.Mock()
            self.error("metadata_auth_invalid", j.get_bytes, opener, url, 100, float("inf"), token=TOKEN)
            opener.open.assert_not_called()
        for url in (j.FILES[0][1], j.FILES[1][1]):
            opener = mock.Mock()
            opener.open.return_value = Response(url)
            self.assertEqual(j.get_bytes(opener, url, 100, float("inf"), token=TOKEN), b"public metadata")
            self.assertEqual(opener.open.call_args.args[0].get_header("Authorization"), "Bearer " + TOKEN)
            self.assertEqual(opener.open.call_args.kwargs, {"timeout": 15})

    def test_unknown_url_blocked_before_request(self):
        opener = mock.Mock()
        self.error("metadata_response_invalid", j.get_bytes, opener, "https://unreviewed.invalid/", 100, float("inf"))
        opener.open.assert_not_called()

    def test_config_single_cdn_hop_strips_all_auth_and_does_not_export_query(self):
        original = redirect(j.FILES[1][1])
        opener = mock.Mock()
        opener.open.side_effect = [original, Response(SIGNED_URL)]
        result = j.get_bytes(opener, j.FILES[1][1], 100, float("inf"), token=TOKEN)
        self.assertEqual(result, b"public metadata")
        requests = [call.args[0] for call in opener.open.call_args_list]
        self.assertEqual(requests[0].get_header("Authorization"), "Bearer " + TOKEN)
        self.assertIsNone(requests[1].get_header("Authorization"))
        self.assertEqual(requests[1].header_items(), [("Accept-encoding", "identity")])
        self.assertEqual(requests[1].full_url, SIGNED_URL)
        self.assertTrue(original.fp.closed)
        self.assertIsNone(j.NoRedirect().redirect_request(None, None, 307, "", {}, SIGNED_URL))

    def test_all_other_redirects_and_second_hop_reject(self):
        for url in (j.TOKEN_URL, j.FILES[0][1], j.FILES[2][1]):
            opener = mock.Mock()
            opener.open.side_effect = redirect(url)
            self.error("metadata_redirect_rejected", j.get_bytes, opener, url, 100, float("inf"))
            self.assertEqual(opener.open.call_count, 1)
        opener = mock.Mock()
        opener.open.side_effect = [redirect(j.FILES[1][1]), redirect(SIGNED_URL)]
        self.error("metadata_redirect_rejected", j.get_bytes, opener, j.FILES[1][1], 100, float("inf"), token=TOKEN)
        self.assertEqual(opener.open.call_count, 2)

    def test_redirect_authority_port_userinfo_fragment_controls_and_length_reject(self):
        targets = ["http://production.cloudfront.docker.com/file", "https://production.cloudfront.docker.com:444/file",
                   "https://user@production.cloudfront.docker.com/file", "https://production.cloudfront.docker.com/file#fragment",
                   "https://production.cloudfront.docker.com.evil.invalid/file", "https://production.cloudfront.docker.com./file",
                   "//production.cloudfront.docker.com/file", "https://[malformed/file",
                   SIGNED_URL + "\nHeader: injected", SIGNED_URL + "x" * 8192]
        for target in targets:
            with self.subTest(target=target[:80]):
                headers = Message(); headers["Location"] = target
                self.error("metadata_redirect_rejected", j.config_redirect, j.FILES[1][1], 307, headers)
        headers = Message(); headers["Location"] = SIGNED_URL; headers["Location"] = SIGNED_URL
        self.error("metadata_redirect_rejected", j.config_redirect, j.FILES[1][1], 307, headers)
        headers = Message(); headers["Location"] = SIGNED_URL
        self.error("metadata_redirect_rejected", j.config_redirect, j.FILES[1][1], 302, headers)

    def test_response_encoding_length_limit_and_non200_reject(self):
        url = j.FILES[0][1]
        cases = [Response(url, status=206), Response(url + "?changed"), Response(url, headers=[("Content-Encoding", "gzip")]),
                 Response(url, headers=[("Content-Length", "0")]), Response(url, headers=[("Content-Length", "99")]),
                 Response(url, headers=[("Content-Length", "15"), ("Content-Length", "15")]), Response(url, data=b"")]
        for index, response in enumerate(cases):
            opener = mock.Mock(); opener.open.return_value = response
            with self.subTest(index=index):
                self.error("metadata_response_invalid", j.get_bytes, opener, url, 100, float("inf"))
        opener = mock.Mock(); opener.open.return_value = Response(url)
        self.error("metadata_response_invalid", j.get_bytes, opener, url, 2, float("inf"))

    def synthetic_files(self):
        payloads = [b'{"synthetic":"manifest"}', b'{"synthetic":"config"}', b"public source PUBLIC_EMAIL_CANARY\n"]
        files = tuple((name, url, hashlib.sha256(data).hexdigest(), limit)
                      for (name, url, _, limit), data in zip(j.FILES, payloads))
        return files, payloads

    def test_worker_uses_explicit_trust_store_no_proxies_and_keeps_token_only_in_memory(self):
        files, payloads = self.synthetic_files()
        with mock.patch.object(j, "FILES", files), mock.patch.dict(os.environ, {"HTTPS_PROXY": "PROXY_CANARY", "SSL_CERT_FILE": "CA_CANARY"}), \
                mock.patch.object(j.ssl, "create_default_context") as tls, mock.patch.object(j.urllib.request, "build_opener") as opener, \
                mock.patch.object(j, "get_bytes", side_effect=[json.dumps({"token": TOKEN}).encode(), *payloads]) as fetch:
            j.fetch_worker(str(self.root))
        tls.assert_called_once_with(cafile="/etc/ssl/certs/ca-certificates.crt")
        self.assertEqual(opener.call_args.args[0].proxies, {})
        self.assertEqual(fetch.call_count, 4)
        self.assertEqual([call.args[1] for call in fetch.call_args_list], [j.TOKEN_URL, *[item[1] for item in files]])
        self.assertEqual([call.kwargs.get("token") for call in fetch.call_args_list], [None, TOKEN, TOKEN, None])
        self.assertEqual(sorted(path.name for path in self.root.iterdir()), sorted([item[0] for item in files] + ["status.json"]))
        for path in self.root.iterdir():
            self.assertNotIn(TOKEN.encode(), path.read_bytes())

    def test_worker_hash_mismatch_never_saves_unverified_file(self):
        with mock.patch.object(j.ssl, "create_default_context"), mock.patch.object(j.urllib.request, "build_opener"), \
                mock.patch.object(j, "get_bytes", side_effect=[json.dumps({"token": TOKEN}).encode(), b"not pinned"]):
            j.fetch_worker(str(self.root))
        self.assertEqual(json.loads((self.root / "status.json").read_bytes()), {"error": "metadata_hash_mismatch"})
        self.assertEqual([path.name for path in self.root.iterdir()], ["status.json"])

    def test_worker_exception_and_status_write_fault_never_print_raw_details(self):
        with mock.patch.object(j.ssl, "create_default_context", side_effect=RuntimeError("PRIVATE_TOKEN_URL_CANARY")):
            j.fetch_worker(str(self.root))
        self.assertEqual(json.loads((self.root / "status.json").read_bytes()), {"error": "metadata_fetch_failed"})
        with mock.patch.object(j.ssl, "create_default_context", side_effect=RuntimeError("PRIVATE_TOKEN_URL_CANARY")), \
                mock.patch.object(j, "write_new", side_effect=OSError("PRIVATE_PATH_CANARY")), mock.patch.object(sys, "stderr", io.StringIO()) as stderr:
            with self.assertRaises(SystemExit) as caught:
                j.fetch_worker(str(self.root))
        self.assertEqual(caught.exception.code, 1)
        self.assertEqual(stderr.getvalue(), "")

    def test_watchdog_stops_trickling_worker_without_retry(self):
        process = mock.Mock(exitcode=None)
        process.is_alive.side_effect = [True, True, False, False]
        context = mock.Mock(); context.Process.return_value = process
        cleanup = {"children_stopped": True}
        with mock.patch.object(j.multiprocessing, "get_context", return_value=context) as get:
            self.error("metadata_timeout", j.run_worker, self.root, cleanup)
        get.assert_called_once_with("fork")
        self.assertEqual(process.join.call_args_list, [mock.call(90), mock.call(3)])
        process.terminate.assert_called_once()
        self.assertTrue(cleanup["children_stopped"])

    def test_unreaped_worker_cleanup_stays_false(self):
        process = mock.Mock(exitcode=None); process.is_alive.return_value = True
        context = mock.Mock(); context.Process.return_value = process
        cleanup = {"children_stopped": True}
        with mock.patch.object(j.multiprocessing, "get_context", return_value=context):
            self.error("metadata_children_cleanup_failed", j.run_worker, self.root, cleanup)
        process.terminate.assert_called_once(); process.kill.assert_called_once()
        self.assertFalse(cleanup["children_stopped"])

    @contextlib.contextmanager
    def scenario(self, *, error=None, unreaped=False, cleanup_error=False):
        files, payloads = self.synthetic_files()
        original_mkdtemp = tempfile.mkdtemp
        def worker(root, cleanup):
            if unreaped:
                cleanup["children_stopped"] = False
                raise j.MetadataError("metadata_children_cleanup_failed")
            if error:
                raise error
            for item, data in zip(files, payloads):
                j.write_new(root / item[0], data)
        with contextlib.ExitStack() as patches:
            patches.enter_context(mock.patch.object(j, "FILES", files))
            patches.enter_context(mock.patch.object(j, "hosted_guard"))
            patches.enter_context(mock.patch.object(j.os, "getuid", return_value=self.root.lstat().st_uid, create=True))
            patches.enter_context(mock.patch.object(j.stat, "S_IMODE", return_value=0o700))
            patches.enter_context(mock.patch.object(j.tempfile, "mkdtemp", side_effect=lambda prefix, dir: original_mkdtemp(prefix=prefix, dir=self.root)))
            patches.enter_context(mock.patch.object(j, "run_worker", side_effect=worker))
            if cleanup_error:
                patches.enter_context(mock.patch.object(j, "remove_owned", side_effect=OSError("PRIVATE_CLEANUP_CANARY")))
            yield j.JdkMetadataLease()

    def test_paths_only_available_after_all_hashes_and_before_cleanup(self):
        with self.scenario() as lease:
            self.error("metadata_path_invalid", lambda: lease.paths)
            with lease:
                self.assertEqual([path.name for path in lease.paths], [item[0] for item in j.FILES])
                self.assertFalse(lease.report["success"])
                self.assertEqual(len(j.verified_files(lease.root)), 3)
            self.assertFalse(lease.root.exists())
            self.assertTrue(lease.report["success"])
            self.error("metadata_path_invalid", lambda: lease.paths)
            self.error("metadata_lease_reused", lease.__enter__)
            result = json.dumps(lease.report)
            for prohibited in ("CANARY", "https://", "Authorization", "Bearer", "Dockerfile contents"):
                self.assertNotIn(prohibited, result)
            self.assertFalse(lease.report["ledger_eligible"])
            self.assertFalse(lease.report["images_pulled"])
            self.assertFalse(lease.report["runtime_executed"])

    def test_metadata_mutation_blocks_success_but_cleans(self):
        with self.scenario() as lease:
            with self.assertRaisesRegex(j.MetadataError, "metadata_hash_mismatch"):
                with lease:
                    lease.paths[0].write_bytes(b"changed")
            self.assertFalse(lease.report["success"])
            self.assertFalse(lease.root.exists())

    def test_source_mutation_blocks_success(self):
        with self.scenario() as lease, mock.patch.object(j, "source_hash", side_effect=["a" * 64, "b" * 64]):
            with self.assertRaisesRegex(j.MetadataError, "metadata_source_changed"):
                with lease:
                    pass
            self.assertFalse(lease.report["success"])

    def test_acquisition_plus_cleanup_failure_keep_both_static_errors(self):
        with self.scenario(error=j.MetadataError("metadata_timeout"), cleanup_error=True) as lease:
            self.error("metadata_timeout", lease.__enter__)
            self.assertEqual(lease.report["errors"], ["metadata_timeout", "metadata_temporary_cleanup_failed"])
            self.assertNotIn("CANARY", json.dumps(lease.report))

    def test_unreaped_child_prevents_temp_deletion(self):
        with self.scenario(unreaped=True) as lease:
            self.error("metadata_children_cleanup_failed", lease.__enter__)
            self.assertTrue(lease.root.exists())
            self.assertFalse(lease.report["cleanup"]["temporary_removed"])

    def test_consumer_error_is_not_exported(self):
        with self.scenario() as lease:
            with self.assertRaisesRegex(RuntimeError, "PRIVATE_CONSUMER_CANARY"):
                with lease:
                    raise RuntimeError("PRIVATE_CONSUMER_CANARY")
            self.assertFalse(lease.report["success"])
            self.assertFalse(lease.root.exists())
            self.assertEqual(lease.report["errors"], ["metadata_consumer_failed"])
            self.assertNotIn("CANARY", json.dumps(lease.report))

    def test_cli_create_new_sanitized_report_survives_cleanup(self):
        with self.scenario() as lease, mock.patch.object(j, "JdkMetadataLease", return_value=lease):
            path = self.root / "metadata-report.json"
            self.assertEqual(j.main(["--report", str(path)]), 0)
            self.assertFalse(lease.root.exists())
            self.assertTrue(json.loads(path.read_bytes())["success"])
            with mock.patch.object(sys, "stderr", io.StringIO()) as stderr:
                self.assertEqual(j.main(["--report", str(path)]), 1)
                self.assertEqual(stderr.getvalue(), "report_create_failed\n")


if __name__ == "__main__":
    unittest.main()
