"""Mocked bootstrap tests: no network, GPG, Maven, Java or container execution."""
import contextlib
from email.message import Message
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

SOURCE = Path(__file__).with_name("verify_bootstrap.py")
if not SOURCE.is_file():
    SOURCE = Path(__file__).resolve().parents[1] / "provider-lab" / "hdfs-bootstrap" / "verify_bootstrap.py"
spec = importlib.util.spec_from_file_location("hdfs_bootstrap_candidate", SOURCE)
v = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = v
spec.loader.exec_module(v)

FPR = "84789D24DF77A32433CE1F079EB80E92EB2135B1"
VALID = ("[GNUPG:] NEWSIG\n[GNUPG:] KEY_CONSIDERED " + FPR + " 0\n"
         "[GNUPG:] GOODSIG 9EB80E92EB2135B1 PRIVATE_NAME_CANARY\n"
         "[GNUPG:] VALIDSIG " + FPR + " 2026-05-13 1778708341 0 4 0 1 10 00 " + FPR + "\n"
         "[GNUPG:] TRUST_UNDEFINED 0 pgp\n").encode()
IMPORTED = ("[GNUPG:] IMPORT_OK 1 " + FPR + "\n").encode()


class Response:
    def __init__(self, body=b"public bytes", url=None, status=200, headers=()):
        self.body = io.BytesIO(body)
        self.status = status
        self.url = url or v.BASE
        self.headers = Message()
        for name, value in headers:
            self.headers[name] = value

    def geturl(self):
        return self.url

    def read1(self, size):
        return self.body.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.stack = contextlib.ExitStack()
        self.stack.enter_context(mock.patch.object(v.subprocess, "Popen", side_effect=AssertionError("native_forbidden")))
        self.stack.enter_context(mock.patch.object(v.multiprocessing, "get_context", side_effect=AssertionError("process_forbidden")))
        self.stack.enter_context(mock.patch.object(v.urllib.request.OpenerDirector, "open", side_effect=AssertionError("network_forbidden")))
        self.stack.enter_context(mock.patch.object(v.signal, "SIGKILL", 9, create=True))

    def tearDown(self):
        self.stack.close()
        self.temp.cleanup()

    def error(self, code, call, *args):
        with self.assertRaises(v.Failure) as caught:
            call(*args)
        self.assertEqual(caught.exception.code, code)

    def test_reviewed_pins_and_sources_are_literal(self):
        self.assertEqual(v.VERSION, "3.9.16")
        self.assertEqual(v.FINGERPRINT, FPR)
        self.assertEqual(v.INPUTS["keys"][1], "https://downloads.apache.org/maven/KEYS")
        self.assertEqual(v.INPUTS["keys"][4], "1e53a10e6b65c64ae0f5a241c8ef289c7578f1109d8a78512dff7de2b29117b3")
        self.assertEqual(v.INPUTS["signature"][4], "a034782f2cab6a037143d3e4a703804a9280fcbb28b0b97a5ea8dae79ebcba39")
        self.assertEqual(v.INPUTS["archive"][4], "831a8591fe20c8243b1dbe7d71e3244f31d1665b0804b2e825e38cbbe5ce0cafb8338851f90780735568773e0a6cd07bbec107cda0b896b008b861075358b6f6")

    def test_host_guard_requires_all_hosted_linux_conditions(self):
        env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux"}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(v.platform, "system", return_value="Linux"), \
                mock.patch.object(v.platform, "machine", return_value="x86_64"), mock.patch.object(v.os, "getuid", return_value=1001, create=True):
            v.hosted_guard()
            for name in env:
                with self.subTest(name=name), mock.patch.dict(os.environ, {name: "wrong"}):
                    self.error("host_not_supported", v.hosted_guard)
            with mock.patch.object(v.os, "getuid", return_value=0):
                self.error("host_not_supported", v.hosted_guard)
            with mock.patch.object(v.platform, "machine", return_value="aarch64"):
                self.error("host_not_supported", v.hosted_guard)

    def test_worker_ignores_proxy_and_ca_environment(self):
        with mock.patch.dict(os.environ, {"HTTPS_PROXY": "PRIVATE_PROXY_CANARY", "SSL_CERT_FILE": "PRIVATE_CA_CANARY"}), \
                mock.patch.object(v.ssl, "create_default_context") as tls, \
                mock.patch.object(v.urllib.request, "build_opener") as opener, \
                mock.patch.object(v, "fetch_one") as fetch:
            v.download_worker(str(self.root))
        tls.assert_called_once_with(cafile="/etc/ssl/certs/ca-certificates.crt")
        handlers = opener.call_args.args
        self.assertEqual(handlers[0].proxies, {})
        self.assertIsInstance(handlers[1], v.NoRedirect)
        self.assertEqual(fetch.call_count, 3)
        self.assertEqual([call.args[1] for call in fetch.call_args_list], list(v.INPUTS.values()))
        self.assertEqual(json.loads((self.root / "fetch-status.json").read_text()), {"error": None})

    def test_redirects_are_rejected_including_same_host(self):
        for url in (v.BASE + "?other", "http://downloads.apache.org/file", "https://other.invalid/file"):
            with self.subTest(url=url):
                self.error("download_invalid", v.NoRedirect().redirect_request, None, None, 302, "", {}, url)

    def test_worker_status_write_fault_exits_without_private_exception(self):
        with mock.patch.object(v.ssl, "create_default_context"), \
                mock.patch.object(v.urllib.request, "build_opener"), mock.patch.object(v, "fetch_one"), \
                mock.patch.object(Path, "open", side_effect=OSError("PRIVATE_WORKER_PATH_CANARY")), \
                mock.patch.object(sys, "stderr", io.StringIO()) as stderr:
            with self.assertRaises(SystemExit) as caught:
                v.download_worker(str(self.root))
        self.assertEqual(caught.exception.code, 1)
        self.assertEqual(stderr.getvalue(), "")
        self.assertTrue(caught.exception.__suppress_context__)

    def test_download_exact_bytes_size_length_and_private_create_new(self):
        response = Response(headers=[("Content-Length", "12")])
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(v.time, "monotonic", return_value=0):
            v.fetch_one(self.root, v.INPUTS["archive"], opener, 1)
        self.assertEqual((self.root / "maven.tar.gz").read_bytes(), b"public bytes")
        self.assertEqual(opener.open.call_args.kwargs, {"timeout": 20})
        self.assertEqual(opener.open.call_args.args[0].get_header("Accept-encoding"), "identity")
        opener.open.return_value = Response()
        with self.assertRaises(FileExistsError), mock.patch.object(v.time, "monotonic", return_value=0):
            v.fetch_one(self.root, v.INPUTS["archive"], opener, 1)

    def test_download_rejects_status_encoding_redirect_length_and_oversize(self):
        cases = [Response(status=206), Response(url=v.BASE + "/alias"),
                 Response(headers=[("Content-Encoding", "gzip")]),
                 Response(headers=[("Content-Length", "0")]),
                 Response(headers=[("Content-Length", "12"), ("Content-Length", "12")]),
                 Response(headers=[("Content-Length", "13")]), Response(body=b"")]
        for index, response in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory(dir=self.root) as sub, \
                    mock.patch.object(v.time, "monotonic", return_value=0):
                opener = mock.Mock()
                opener.open.return_value = response
                self.error("download_invalid", v.fetch_one, Path(sub), v.INPUTS["archive"], opener, 1)
        opener = mock.Mock()
        opener.open.return_value = Response()
        with mock.patch.object(v.time, "monotonic", return_value=0):
            self.error("download_invalid", v.fetch_one, self.root, ("small", v.BASE, 4, "sha256", ""), opener, 1)
        self.assertLessEqual((self.root / "small").stat().st_size, 4)

    def test_absolute_worker_deadline_is_not_a_read_inactivity_timeout(self):
        opener = mock.Mock()
        opener.open.return_value = Response()
        with mock.patch.object(v.time, "monotonic", side_effect=[0, 241]):
            self.error("download_timeout", v.fetch_one, self.root, v.INPUTS["archive"], opener, 240)
        self.assertEqual((self.root / "maven.tar.gz").stat().st_size, 0)

    def test_parent_watchdog_terminates_trickling_worker_and_reaps(self):
        process = mock.Mock(exitcode=None)
        process.is_alive.side_effect = [True, True, False, False]
        context = mock.Mock()
        context.Process.return_value = process
        activity = {"children_stopped": True}
        with mock.patch.object(v.multiprocessing, "get_context", return_value=context) as get:
            self.error("download_timeout", v.download_inputs, self.root, activity)
        get.assert_called_once_with("fork")
        self.assertEqual(context.Process.call_args.kwargs["target"], v.download_worker)
        self.assertTrue(context.Process.call_args.kwargs["daemon"])
        self.assertEqual(process.join.call_args_list, [mock.call(240), mock.call(3)])
        process.terminate.assert_called_once()
        process.close.assert_called_once()
        self.assertTrue(activity["children_stopped"])

    def test_parent_escalation_and_failed_reap_remain_failure(self):
        process = mock.Mock()
        process.is_alive.return_value = True
        activity = {"children_stopped": False}
        self.error("children_cleanup_failed", v.stop_worker, process, activity)
        process.terminate.assert_called_once()
        process.kill.assert_called_once()
        self.assertFalse(activity["children_stopped"])

    def test_parent_accepts_only_zero_worker_exit_and_closed_status(self):
        process = mock.Mock(exitcode=0)
        process.is_alive.return_value = False
        context = mock.Mock()
        context.Process.return_value = process
        status = self.root / "fetch-status.json"
        with mock.patch.object(v.multiprocessing, "get_context", return_value=context):
            status.write_text('{"error":null}', encoding="ascii")
            activity = {"children_stopped": True}
            v.download_inputs(self.root, activity)
            status.write_text('{"error":null,"ignored":true}', encoding="ascii")
            self.error("download_worker_failed", v.download_inputs, self.root, activity)
            process.exitcode = 1
            self.error("download_worker_failed", v.download_inputs, self.root, activity)

    def test_hashes_are_computed_from_file_bytes_not_worker_status(self):
        data = b"independent public test bytes\n"
        spec = ("sample", "https://downloads.apache.org/sample", 1024, "sha512", hashlib.sha512(data).hexdigest())
        (self.root / "sample").write_bytes(data)
        with mock.patch.object(v, "INPUTS", {"archive": spec}):
            result = v.verify_hashes(self.root)
            self.assertEqual(result["archive"]["sha256"], hashlib.sha256(data).hexdigest())
            (self.root / "sample").write_bytes(b"altered")
            self.error("checksum_mismatch", v.verify_hashes, self.root)

    def test_literal_valid_signature_and_benign_notation(self):
        v.verify_status(VALID)
        v.verify_status(VALID + b"[GNUPG:] NOTATION_NAME manu\n[GNUPG:] NOTATION_DATA private metadata\n")

    def test_signature_failure_revocation_expiry_missing_and_unknown_are_rejected(self):
        for status in ("BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "KEYEXPIRED", "SIGEXPIRED",
                       "KEYREVOKED", "NO_PUBKEY", "NODATA", "FAILURE", "ERROR", "TRUST_NEVER", "FUTURE_STATUS"):
            with self.subTest(status=status):
                self.error("signature_invalid", v.verify_status, VALID + ("[GNUPG:] " + status + " canary\n").encode())

    def test_signer_primary_algorithm_and_signature_count_are_exact(self):
        valid_line = next(line for line in VALID.splitlines() if b"VALIDSIG" in line)
        cases = [VALID.replace(valid_line + b"\n", b""), VALID + valid_line + b"\n",
                 VALID.replace(b" 10 00 ", b" 8 00 "), VALID.replace(b" 0 4 0 ", b" 1 4 0 "),
                 VALID.replace(b" " + FPR.encode() + b"\n", b" " + b"A" * 40 + b"\n"),
                 VALID.replace(b"VALIDSIG " + FPR.encode(), b"VALIDSIG " + b"A" * 40),
                 VALID.replace(b"GOODSIG 9EB80E92EB2135B1", b"GOODSIG 0000000000000000")]
        for index, data in enumerate(cases):
            with self.subTest(index=index):
                self.error("signature_invalid", v.verify_status, data)
        self.error("gpg_status_invalid", v.verify_status, b"raw stderr name\n" + VALID)

    def test_import_only_pinned_keys_then_detached_verify(self):
        with mock.patch.object(v, "run_gpg", side_effect=[IMPORTED, VALID]) as command:
            v.signature_check(self.root, {"children_stopped": True})
        self.assertEqual(command.call_args_list[0].args[2], ["--import", str(self.root / "maven-KEYS.txt")])
        self.assertEqual(command.call_args_list[1].args[2], ["--verify", str(self.root / "maven.tar.gz.asc"), str(self.root / "maven.tar.gz")])

    def test_missing_publisher_import_prevents_verify(self):
        with mock.patch.object(v, "run_gpg", return_value=b"[GNUPG:] IMPORT_RES 0 0\n") as command:
            self.error("gpg_import_failed", v.signature_check, self.root, {"children_stopped": True})
        self.assertEqual(command.call_count, 1)

    def gpg(self, result=0, poll=0, status=VALID):
        process = mock.Mock(pid=12345)
        process.poll.return_value = poll
        process.wait.return_value = result
        def spawn(command, **kwargs):
            kwargs["stdout"].write(status)
            kwargs["stdout"].flush()
            kwargs["stderr"].write(b"PRIVATE_NAME_EMAIL_PATH_CANARY")
            kwargs["stderr"].flush()
            return process
        return process, spawn

    def test_gpg_fixed_binary_private_environment_no_network_and_bounded_logs(self):
        process, spawn = self.gpg()
        activity = {"children_stopped": True}
        with mock.patch.object(v, "regular", return_value=SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o755)), \
                mock.patch.object(v.subprocess, "Popen", side_effect=spawn) as popen, \
                mock.patch.object(v.os, "killpg", side_effect=ProcessLookupError, create=True):
            output = v.run_gpg(self.root, "verify", ["--verify", "signature", "archive"], activity)
        self.assertEqual(output, VALID)
        argv = popen.call_args.args[0]
        self.assertEqual(argv[:2], ["/usr/bin/gpg", "--no-options"])
        for value in ("--no-autostart", "--disable-dirmngr", "--no-auto-key-retrieve", "--no-auto-key-import"):
            self.assertIn(value, argv)
        self.assertEqual(argv[argv.index("--auto-key-locate") + 1], "clear")
        opts = popen.call_args.kwargs
        self.assertEqual(set(opts["env"]), {"PATH", "HOME", "GNUPGHOME", "LANG", "LC_ALL"})
        self.assertEqual(opts["env"]["HOME"], str(self.root))
        self.assertIs(opts["preexec_fn"], v.limit_gpg_files)
        self.assertTrue(opts["start_new_session"])
        self.assertTrue(activity["children_stopped"])
        process.wait.assert_called_once_with(timeout=3)

    def test_gpg_nonzero_even_valid_status_is_failure(self):
        _, spawn = self.gpg(result=1)
        with mock.patch.object(v, "regular", return_value=SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o755)), \
                mock.patch.object(v.subprocess, "Popen", side_effect=spawn), \
                mock.patch.object(v.os, "killpg", side_effect=ProcessLookupError, create=True):
            self.error("signature_invalid", v.run_gpg, self.root, "verify", [], {"children_stopped": True})

    def test_gpg_timeout_stops_owned_group(self):
        process, spawn = self.gpg(poll=None)
        with mock.patch.object(v, "regular", return_value=SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o755)), \
                mock.patch.object(v.subprocess, "Popen", side_effect=spawn), \
                mock.patch.object(v.os, "killpg", side_effect=ProcessLookupError, create=True) as kill, \
                mock.patch.object(v.time, "monotonic", side_effect=[0, 46, 46]):
            self.error("gpg_timeout", v.run_gpg, self.root, "verify", [], {"children_stopped": True})
        self.assertEqual(kill.call_args_list[0].args[0], 12345)
        process.wait.assert_called_once_with(timeout=3)

    def test_gpg_output_limit_is_enforced_even_on_zero_exit(self):
        _, spawn = self.gpg(status=b"x" * v.LOG_LIMIT)
        with mock.patch.object(v, "regular", return_value=SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o755)), \
                mock.patch.object(v.subprocess, "Popen", side_effect=spawn), \
                mock.patch.object(v.os, "killpg", side_effect=ProcessLookupError, create=True):
            self.error("gpg_output_limit", v.run_gpg, self.root, "verify", [], {"children_stopped": True})

    def test_gpg_reap_does_not_hide_remaining_group(self):
        _, spawn = self.gpg()
        activity = {"children_stopped": True}
        with mock.patch.object(v, "regular", return_value=SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o755)), \
                mock.patch.object(v.subprocess, "Popen", side_effect=spawn), \
                mock.patch.object(v.os, "killpg", return_value=None, create=True), \
                mock.patch.object(v.time, "monotonic", side_effect=[0, 0, 4]):
            self.error("children_cleanup_failed", v.run_gpg, self.root, "verify", [], activity)
        self.assertFalse(activity["children_stopped"])

    def scenario(self, *, failure=None, cleanup_failure=False, child_failure=False, source_change=False):
        scratch = self.root / "owned"
        scratch.mkdir()
        patches = contextlib.ExitStack()
        patches.enter_context(mock.patch.object(v, "hosted_guard"))
        patches.enter_context(mock.patch.object(v.os, "getuid", return_value=scratch.lstat().st_uid, create=True))
        patches.enter_context(mock.patch.object(v.stat, "S_IMODE", return_value=0o700))
        patches.enter_context(mock.patch.object(v.tempfile, "mkdtemp", return_value=str(scratch)))
        patches.enter_context(mock.patch.object(v, "download_inputs", side_effect=failure))
        patches.enter_context(mock.patch.object(v, "verify_hashes", return_value={"archive": {"sha256": "a" * 64}}))
        def signature(_, activity):
            if child_failure:
                activity["children_stopped"] = False
        patches.enter_context(mock.patch.object(v, "signature_check", side_effect=signature))
        if source_change:
            patches.enter_context(mock.patch.object(v, "digest", side_effect=["a" * 64, "b" * 64]))
        if cleanup_failure:
            patches.enter_context(mock.patch.object(v, "remove_owned", side_effect=PermissionError("PRIVATE_PATH_CANARY")))
        with patches:
            result = v.run()
        return result, scratch

    def test_nominal_result_requires_cleanup_and_is_not_ledger_evidence(self):
        result, scratch = self.scenario()
        self.assertTrue(result["success"])
        self.assertFalse(result["ledger_eligible"])
        self.assertEqual(result["scope"], "hdfs_bootstrap_integrity_verification")
        self.assertFalse(scratch.exists())
        self.assertTrue(all(result["checks"].values()))
        self.assertEqual(set(result), {"schema_version", "scope", "ledger_eligible", "started_utc", "finished_utc",
                                      "duration_seconds", "source_sha256", "maven_version", "publisher_fingerprint",
                                      "publisher_trust_scope", "inputs", "checks", "cleanup", "success", "errors"})

    def test_primary_plus_cleanup_failure_preserve_both_static_causes(self):
        result, _ = self.scenario(failure=v.Failure("download_timeout"), cleanup_failure=True)
        self.assertEqual(result["errors"], ["download_timeout", "temporary_cleanup_failed"])
        self.assertFalse(result["success"])
        self.assertFalse(result["checks"]["signature_verified"])
        self.assertNotIn("CANARY", json.dumps(result))

    def test_successful_verification_cannot_hide_failed_cleanup(self):
        result, _ = self.scenario(cleanup_failure=True)
        self.assertTrue(all(result["checks"].values()))
        self.assertFalse(result["success"])
        self.assertEqual(result["errors"], ["temporary_cleanup_failed"])

    def test_unreaped_child_blocks_success(self):
        result, scratch = self.scenario(child_failure=True)
        self.assertFalse(result["success"])
        self.assertIn("children_cleanup_failed", result["errors"])
        self.assertIn("temporary_cleanup_failed", result["errors"])
        self.assertTrue(scratch.exists())

    def test_source_mutation_blocks_success(self):
        result, _ = self.scenario(source_change=True)
        self.assertFalse(result["success"])
        self.assertEqual(result["errors"], ["source_changed"])

    def test_payload_rehash_after_signature_blocks_changed_inputs(self):
        # Exercise orchestration with independent before/after hash observations.
        original = v.verify_hashes
        calls = []
        def mutate(*_):
            calls.append(None)
            return {"archive": {"sha256": ("a" if len(calls) == 1 else "b") * 64}}
        scratch = self.root / "owned-rehash"
        scratch.mkdir()
        with mock.patch.object(v, "hosted_guard"), \
                mock.patch.object(v.os, "getuid", return_value=scratch.lstat().st_uid, create=True), \
                mock.patch.object(v.stat, "S_IMODE", return_value=0o700), \
                mock.patch.object(v.tempfile, "mkdtemp", return_value=str(scratch)), \
                mock.patch.object(v, "download_inputs"), mock.patch.object(v, "signature_check"), \
                mock.patch.object(v, "verify_hashes", side_effect=mutate):
            result = v.run()
        self.assertIs(v.verify_hashes, original)
        self.assertEqual(result["errors"], ["checksum_mismatch"])
        self.assertFalse(result["success"])
        self.assertFalse(scratch.exists())

    def test_raw_exception_canary_not_exported(self):
        result, _ = self.scenario(failure=RuntimeError("PRIVATE_NAME_EMAIL_PATH_CANARY"))
        self.assertEqual(result["errors"], ["verification_failed"])
        self.assertNotIn("CANARY", json.dumps(result))

    def test_cleanup_rejects_replaced_root_identity(self):
        scratch = self.root / "owned"
        scratch.mkdir()
        self.error("temporary_cleanup_failed", v.remove_owned, scratch, (-1, -1))
        self.assertTrue(scratch.exists())

    def test_cli_create_new_report_retained_and_does_not_overwrite(self):
        output = self.root / "sanitized.json"
        report = {"success": False, "errors": ["host_not_supported"], "ledger_eligible": False}
        with mock.patch.object(v, "run", return_value=report) as run:
            self.assertEqual(v.main(["--report", str(output)]), 1)
            self.assertEqual(json.loads(output.read_text()), report)
            with mock.patch.object(sys, "stderr", io.StringIO()) as stderr:
                self.assertEqual(v.main(["--report", str(output)]), 1)
                self.assertEqual(stderr.getvalue(), "report_create_failed\n")
            self.assertEqual(run.call_count, 1)
        self.assertEqual(json.loads(output.read_text()), report)

    def test_relative_report_rejected_before_any_action(self):
        with mock.patch.object(v, "run") as run, mock.patch.object(sys, "stderr", io.StringIO()):
            self.assertEqual(v.main(["--report", "relative.json"]), 1)
        run.assert_not_called()

    def test_report_write_failure_only_emits_static_code(self):
        output = self.root / "report.json"
        with mock.patch.object(v, "run", return_value={"success": True}), \
                mock.patch.object(v.os, "fsync", side_effect=OSError("PRIVATE_REPORT_PATH_CANARY")), \
                mock.patch.object(sys, "stderr", io.StringIO()) as stderr:
            self.assertEqual(v.main(["--report", str(output)]), 1)
        self.assertEqual(stderr.getvalue(), "report_write_failed\n")


if __name__ == "__main__":
    unittest.main()
