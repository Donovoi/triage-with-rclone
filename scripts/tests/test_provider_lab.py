"""Account-free fixture/harness regressions; native rclone requires explicit lab CLI."""

import ftplib
import hashlib
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest import mock


LAB_ROOT = Path(__file__).parents[1] / "provider-lab"
sys.path.insert(0, str(LAB_ROOT))
try:
    import fixture_servers as FIXTURES
    import run_lab as LAB
finally:
    sys.path.pop(0)


class ProviderLabTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_environment_excludes_credentials_proxy_agent_and_socket_activation(self):
        with mock.patch.dict(os.environ, {"RCLONE_CONFIG": "private", "AWS_SECRET_ACCESS_KEY": "private",
                                          "HTTPS_PROXY": "private", "SSH_AUTH_SOCK": "private",
                                          "LISTEN_FDS": "3", "PATH": "private"}):
            env = LAB.isolated_environment(self.root)
        for key in ("RCLONE_CONFIG", "AWS_SECRET_ACCESS_KEY", "HTTPS_PROXY", "SSH_AUTH_SOCK", "LISTEN_FDS", "PATH"):
            self.assertNotIn(key, env)
        self.assertEqual(env["HOME"], str(self.root))
        self.assertEqual(env["AWS_EC2_METADATA_DISABLED"], "true")

    def test_explicit_absolute_runtime_must_match_platform_pin_before_execution(self):
        binary = self.root / "synthetic-runtime"
        binary.write_bytes(b"not executable; hashing test only")
        key = "RCLONE_EXE_SHA256" if sys.platform == "win32" else "RCLONE_LINUX_EXE_SHA256"
        manifest = self.root / "manifest"
        manifest.write_text(f"RCLONE_VERSION=1.2.3\n{key}={LAB.digest(binary)}\n")
        resolved, identity, _ = LAB.verified_runtime(binary, manifest)
        self.assertEqual(resolved, binary.resolve())
        self.assertEqual(identity["version"], "1.2.3")
        with self.assertRaisesRegex(LAB.LabError, "absolute_runtime"):
            LAB.verified_runtime(Path("synthetic-runtime"), manifest)
        binary.write_bytes(b"altered")
        with self.assertRaisesRegex(LAB.LabError, "runtime_hash_mismatch"):
            LAB.verified_runtime(binary, manifest)

    def test_duplicate_manifest_pin_is_rejected(self):
        binary = self.root / "synthetic"
        binary.write_bytes(b"test")
        manifest = self.root / "manifest"
        manifest.write_text("RCLONE_VERSION=1.2.3\nRCLONE_VERSION=1.2.4\n")
        with self.assertRaisesRegex(LAB.LabError, "invalid_runtime_manifest"):
            LAB.verified_runtime(binary, manifest)

    def test_harness_hash_binds_names_contents_and_both_modules(self):
        for name in LAB.HARNESS_FILES:
            (self.root / name).write_bytes(b"initial")
        before = LAB.compute_harness_sha256(self.root)
        (self.root / "fixture_servers.py").write_bytes(b"changed")
        self.assertNotEqual(before, LAB.compute_harness_sha256(self.root))
        (self.root / "run_lab.py").unlink()
        with self.assertRaises(FileNotFoundError):
            LAB.compute_harness_sha256(self.root)

    def test_fixture_manifest_has_independent_fixed_payload_hashes(self):
        manifest = LAB.fixture_manifest()
        self.assertEqual(len(manifest), 3)
        self.assertEqual([row["path"] for row in manifest], sorted(FIXTURES.FILES))
        for row in manifest:
            self.assertEqual(row["sha256"], hashlib.sha256(FIXTURES.FILES[row["path"]]).hexdigest())
        expected = hashlib.sha256(json.dumps(manifest, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(LAB.fixture_manifest_sha256(), expected)

    def test_report_publication_is_create_new_without_partial_or_leftover_temp(self):
        path = self.root / "receipt.json"
        LAB.atomic_report(path, {"synthetic": True})
        before = path.read_bytes()
        with self.assertRaises(LAB.LabError):
            LAB.atomic_report(path, {"synthetic": False})
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(list(self.root.iterdir()), [path])

    def test_report_concurrent_claim_cannot_be_replaced(self):
        path = self.root / "receipt.json"
        real_link = os.link

        def raced_link(source, destination):
            Path(destination).write_text("other writer")
            return real_link(source, destination)

        with mock.patch.object(LAB.os, "link", side_effect=raced_link):
            with self.assertRaises(FileExistsError):
                LAB.atomic_report(path, {"synthetic": True})
        self.assertEqual(path.read_text(), "other writer")
        self.assertEqual(list(self.root.iterdir()), [path])

    def test_protocol_paths_reject_traversal_without_touching_filesystem(self):
        for value in ("/../private", "/%2e%2e/private", "/dir/../private", "/x\\private", "/%00"):
            with self.assertRaises(ValueError):
                FIXTURES.safe_path(value)
        self.assertEqual(FIXTURES.safe_path("/nested/space%20name.txt"), "nested/space name.txt")

    def test_source_preservation_detects_added_file_and_payload_corruption(self):
        source = self.root / "source"
        LAB.prepare_files(source)
        self.assertTrue(LAB.source_unchanged(source))
        extra = source / "unexpected"
        extra.write_bytes(b"new")
        self.assertFalse(LAB.source_unchanged(source))
        extra.unlink()
        (source / "README-synthetic.txt").write_bytes(b"corrupt")
        self.assertFalse(LAB.source_unchanged(source))

    def test_served_source_snapshot_cannot_change_with_mutable_fixture_mapping(self):
        expected = LAB.fixture_manifest()
        state = FIXTURES.State("synthetic", "synthetic-pass")
        self.assertIsNot(state.files, FIXTURES.FILES)
        self.assertTrue(LAB.served_source_unchanged(state, expected))
        state.files["README-synthetic.txt"] = b"corrupt"
        with mock.patch.dict(FIXTURES.FILES, {"README-synthetic.txt": b"corrupt"}):
            self.assertFalse(LAB.served_source_unchanged(state, expected))
        state.files = dict(FIXTURES.FILES)
        state.files["unexpected"] = b"added"
        self.assertFalse(LAB.served_source_unchanged(state, expected))
        del state.files["unexpected"]
        del state.files["README-synthetic.txt"]
        self.assertFalse(LAB.served_source_unchanged(state, expected))

    def test_generated_config_refuses_line_injection(self):
        with self.assertRaises(LAB.LabError):
            LAB.config_file(self.root, "config", {"url": "synthetic\n[Other]"})
        self.assertFalse((self.root / "config").exists())

    def test_http_rejects_wrong_auth_and_serves_no_payload(self):
        state = FIXTURES.State("synthetic", "synthetic-pass")
        with FIXTURES.serve("http", state) as port:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            connection.request("GET", "/README-synthetic.txt", headers={"Authorization": "Basic wrong"})
            response = connection.getresponse()
            self.assertEqual(response.status, 401)
            self.assertEqual(response.read(), b"")
            connection.close()
            self.assertEqual(state.denied, 1)
            self.assertEqual(state.payload_bytes, 0)
        self.assertTrue(LAB.listener_closed(port))

    def test_webdav_metadata_and_download_are_independent_of_rclone(self):
        import base64
        state = FIXTURES.State("synthetic", "synthetic-pass")
        headers = {"Authorization": "Basic " + base64.b64encode(b"synthetic:synthetic-pass").decode()}
        with FIXTURES.serve("webdav", state) as port:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            connection.request("PROPFIND", "/", headers=dict(headers, Depth="1"))
            response = connection.getresponse()
            self.assertEqual(response.status, 207)
            self.assertIn(b"/nested/", response.read())
            connection.close()
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            connection.request("GET", "/nested/bytes.bin", headers=headers)
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read(), FIXTURES.FILES["nested/bytes.bin"])
            connection.close()
            expected = LAB.fixture_manifest()
            FIXTURES.probe_write_rejection("webdav", port, state)
            self.assertEqual(state.rejected_mutations, 1)
            self.assertTrue(LAB.served_source_unchanged(state, expected))
        self.assertTrue(LAB.listener_closed(port))

    def test_ftp_auth_read_data_binding_and_active_mode_refusal(self):
        state = FIXTURES.State("synthetic", "synthetic-pass")
        with FIXTURES.serve("ftp", state) as port:
            client = ftplib.FTP()
            client.connect("127.0.0.1", port, timeout=3)
            with self.assertRaises(ftplib.error_perm):
                client.login("synthetic", "wrong")
            self.assertEqual(state.denied, 1)
            self.assertEqual(state.payload_bytes, 0)
            client.login("synthetic", "synthetic-pass")
            self.assertIn("type=file;", client.sendcmd("MLST README-synthetic.txt"))
            self.assertIn("type=dir;", client.sendcmd("MLST nested"))
            with self.assertRaises(ftplib.error_perm):
                client.sendcmd("PORT 127,0,0,1,1,1")
            with self.assertRaises(ftplib.error_perm):
                client.sendcmd("EPRT |1|127.0.0.1|1000|")
            address, _ = ftplib.parse227(client.sendcmd("PASV"))
            self.assertEqual(address, "127.0.0.1")
            output = io.BytesIO()
            client.retrbinary("RETR README-synthetic.txt", output.write)
            self.assertEqual(output.getvalue(), FIXTURES.FILES["README-synthetic.txt"])
            listing = []
            client.retrlines("LIST README-synthetic.txt", listing.append)
            self.assertEqual(len(listing), 1)
            self.assertIn("README-synthetic.txt", listing[0])
            client.quit()
            expected = LAB.fixture_manifest()
            FIXTURES.probe_write_rejection("ftp", port, state)
            self.assertEqual(state.rejected_mutations, 1)
            self.assertTrue(LAB.served_source_unchanged(state, expected))
        self.assertTrue(LAB.listener_closed(port))

    def test_sftp_pins_owned_public_files_not_network_tofu(self):
        cache = self.root / "cache"
        keys = cache / "serve-sftp"
        keys.mkdir(parents=True)
        for name, algorithm in (("id_rsa", "ssh-rsa"), ("id_ecdsa", "ecdsa-sha2-nistp256"), ("id_ed25519", "ssh-ed25519")):
            (keys / (name + ".pub")).write_text(algorithm + " c3ludGhldGlj\n")
        runtime = mock.Mock(cache=cache)
        path = LAB.pin_sftp_key(runtime, 12345, self.root)
        lines = path.read_text().splitlines()
        self.assertEqual(len(lines), 3)
        self.assertTrue(all(line.startswith("[127.0.0.1]:12345 ") for line in lines))

    def test_wrong_auth_exit_without_server_rejection_cannot_pass(self):
        runtime = mock.Mock()
        runtime.run.return_value = (1, b"", b"unrelated startup error")
        row = {"capabilities": {}}
        with self.assertRaisesRegex(LAB.LabError, "bad_auth_not_observed"):
            LAB.common_checks(runtime, self.root, None, "bad", "Synthetic:", row,
                              auth_marker=(b"signaturedoesnotmatch",))
        self.assertNotIn("authentication_rejection", row["capabilities"])

    def test_wrong_auth_data_is_always_a_failure(self):
        runtime = mock.Mock()
        runtime.run.return_value = (1, b"leaked synthetic payload", b"accessdenied")
        with self.assertRaisesRegex(LAB.LabError, "bad_auth_returned_data"):
            LAB.common_checks(runtime, self.root, None, "bad", "Synthetic:", {"capabilities": {}},
                              auth_marker=(b"accessdenied",))

    def test_absent_object_stat_accepts_only_error_or_virtual_directory_not_file(self):
        self.assertTrue(LAB.stat_has_no_file(3, b""))
        self.assertTrue(LAB.stat_has_no_file(0, b'{"IsDir":true}'))
        self.assertFalse(LAB.stat_has_no_file(0, b'{"IsDir":false,"Size":0}'))
        self.assertFalse(LAB.stat_has_no_file(0, b'{"IsDir":"true"}'))
        self.assertFalse(LAB.stat_has_no_file(0, b'{}'))
        self.assertFalse(LAB.stat_has_no_file(0, b'not json'))

    def test_timeout_kills_and_reaps_exact_owned_process(self):
        runtime = object.__new__(LAB.Runtime)
        process = mock.Mock()
        process.poll.return_value = None
        stdout, stderr = self.root / "out", self.root / "err"
        stdout.write_bytes(b"")
        stderr.write_bytes(b"")
        runtime.start = mock.Mock(return_value=(process, stdout, stderr))
        with mock.patch.object(LAB.time, "monotonic", side_effect=[0, 21]):
            with self.assertRaisesRegex(LAB.LabError, "child_timeout"):
                runtime.run(["synthetic"])
        process.terminate.assert_called_once()
        process.wait.assert_called_once_with(3)

    def test_output_limit_kills_and_reaps_exact_owned_process(self):
        runtime = object.__new__(LAB.Runtime)
        process = mock.Mock()
        process.poll.return_value = None
        stdout, stderr = self.root / "out", self.root / "err"
        stdout.write_bytes(b"x" * 65)
        stderr.write_bytes(b"")
        runtime.start = mock.Mock(return_value=(process, stdout, stderr))
        with mock.patch.object(LAB, "MAX_OUTPUT", 64):
            with self.assertRaisesRegex(LAB.LabError, "child_output_limit"):
                runtime.run(["synthetic"])
        process.terminate.assert_called_once()
        process.wait.assert_called_once_with(3)

    def test_existing_report_is_refused_before_any_runtime_process(self):
        report = self.root / "existing.json"
        report.write_text("original")
        with mock.patch.object(LAB, "verified_runtime") as verify:
            with self.assertRaisesRegex(LAB.LabError, "new_absolute_report_required"):
                LAB.run_lab(self.root / "not-a-runtime", report)
        verify.assert_not_called()
        self.assertEqual(report.read_text(), "original")


if __name__ == "__main__":
    unittest.main()
