"""Account-free fixture/harness regressions; native rclone requires explicit lab CLI."""

import ftplib
import base64
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
import zipfile
import zlib


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

    def sftp_options(self):
        blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))
        known = self.root / "known_hosts"
        known.write_text("[127.0.0.1]:12345 ssh-ed25519 " + base64.b64encode(blob).decode() + "\n")
        return {"type": "sftp", "host": "127.0.0.1", "port": "12345", "user": "synthetic",
                "pass": "synthetic-obscured", "known_hosts_file": str(known),
                "key_use_agent": "false", "disable_hashcheck": "true", "shell_type": "none"}

    def test_sftp_mismatch_is_valid_wire_key_for_same_host_without_changing_pin(self):
        options = self.sftp_options()
        known = Path(options["known_hosts_file"])
        original = known.read_bytes()
        mismatch = LAB.mismatched_sftp_key(known, 12345, self.root)
        entries = mismatch.read_text().splitlines()
        self.assertEqual(len(entries), 1)
        host, algorithm, key = entries[0].split()
        self.assertEqual((host, algorithm), ("[127.0.0.1]:12345", "ssh-ed25519"))
        changed = base64.b64decode(key, validate=True)
        expected = base64.b64decode(original.split()[2], validate=True)
        self.assertEqual(len(changed), 51)
        self.assertEqual(changed[:-1], expected[:-1])
        self.assertNotEqual(changed[-1], expected[-1])
        self.assertEqual(known.read_bytes(), original)

    def test_sftp_mismatch_refuses_missing_or_malformed_owned_key(self):
        known = self.root / "known_hosts"
        for value in ("", "[127.0.0.1]:9999 ssh-ed25519 c3ludGhldGlj\n",
                      "[127.0.0.1]:12345 ssh-ed25519 invalid*\n",
                      "[127.0.0.1]:12345 ssh-ed25519 c3ludGhldGlj\n"):
            with self.subTest(value=value):
                known.write_text(value)
                with self.assertRaises(LAB.LabError):
                    LAB.mismatched_sftp_key(known, 12345, self.root)
                self.assertFalse((self.root / "mismatched_known_hosts").exists())

    def test_sftp_host_key_rejection_keeps_correct_credentials_and_checks_read_and_copy(self):
        options = self.sftp_options()
        runtime = mock.Mock()
        runtime.run.return_value = (1, b"", b"ssh: handshake failed: knownhosts: key mismatch")
        row = {"capabilities": {}}
        LAB.sftp_host_key_check(runtime, self.root, options, "Synthetic:", row)
        self.assertEqual(row["capabilities"], {"host_key_rejection": "passed"})
        self.assertEqual(runtime.run.call_count, 2)
        config = self.root / "mismatched-host.conf"
        expected = dict(options, known_hosts_file=str(self.root / "mismatched_known_hosts"))
        self.assertEqual(config.read_text(), "[Synthetic]\n" + "".join(f"{key} = {value}\n" for key, value in expected.items()))
        calls = runtime.run.call_args_list
        self.assertEqual(calls[0].args, (["cat", "Synthetic:README-synthetic.txt"], config))
        self.assertEqual(calls[1].args, (["copyto", "Synthetic:README-synthetic.txt",
                                        str(self.root / "host-key-mismatch-must-not-exist")], config))

    def test_sftp_host_key_verdict_rejects_unrelated_failure_success_or_payload(self):
        cases = ((1, b"", b"unrelated startup error"),
                 (1, b"", b"knownhosts: key is unknown"),
                 (1, b"", b"unable to authenticate"),
                 (0, b"", b"knownhosts: key mismatch"),
                 (1, b"fixture bytes", b"knownhosts: key mismatch"))
        for result in cases:
            with self.subTest(result=result), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                known = root / "known_hosts"
                known.write_text("synthetic")
                runtime = mock.Mock()
                runtime.run.return_value = result
                row = {"capabilities": {}}
                with mock.patch.object(LAB, "mismatched_sftp_key", return_value=root / "wrong-key"):
                    with self.assertRaises(LAB.LabError):
                        LAB.sftp_host_key_check(runtime, root, {"port": "12345", "known_hosts_file": str(known)},
                                                "Synthetic:", row)
                self.assertNotIn("host_key_rejection", row["capabilities"])

    def test_sftp_host_key_verdict_rejects_partial_destination(self):
        options = self.sftp_options()
        runtime = mock.Mock()

        def result(args, config):
            if args[0] == "copyto":
                Path(args[-1]).write_bytes(b"partial")
            return 1, b"", b"knownhosts: key mismatch"

        runtime.run.side_effect = result
        row = {"capabilities": {}}
        with self.assertRaisesRegex(LAB.LabError, "host_key_mismatch_returned_data"):
            LAB.sftp_host_key_check(runtime, self.root, options, "Synthetic:", row)
        self.assertNotIn("host_key_rejection", row["capabilities"])

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

    def archive_entries(self):
        return [{"Path": name, "IsDir": False, "Size": len(body),
                 "Hashes": {"crc32": f"{zlib.crc32(body):08x}"}} for name, body in FIXTURES.FILES.items()] + [
                     {"Path": "nested", "IsDir": True, "Size": -1}]

    def test_archive_zip_is_deterministic_and_matches_independent_payloads(self):
        first = LAB.archive_zip(dict(FIXTURES.FILES))
        second = LAB.archive_zip(dict(reversed(list(FIXTURES.FILES.items()))))
        self.assertEqual(first, second)
        with zipfile.ZipFile(io.BytesIO(first)) as archive:
            self.assertEqual(archive.namelist(), sorted([*FIXTURES.FILES, "nested/"]))
            for entry in archive.infolist():
                self.assertEqual(entry.date_time, (2024, 1, 1, 0, 0, 0))
                self.assertEqual(entry.compress_type, zipfile.ZIP_STORED)
                self.assertEqual(entry.create_system, 3)
                if not entry.is_dir():
                    expected = FIXTURES.FILES[entry.filename]
                    self.assertEqual(archive.read(entry), expected)
                    self.assertEqual(entry.CRC, zlib.crc32(expected))

    def test_archive_corruption_retains_metadata_but_fails_member_crc(self):
        original = LAB.archive_zip(FIXTURES.FILES)
        corrupt = LAB.corrupt_archive_member(original, "README-synthetic.txt")
        self.assertEqual(sum(left != right for left, right in zip(original, corrupt)), 1)
        with zipfile.ZipFile(io.BytesIO(original)) as good, zipfile.ZipFile(io.BytesIO(corrupt)) as bad:
            self.assertEqual([(entry.filename, entry.CRC, entry.file_size) for entry in good.infolist()],
                             [(entry.filename, entry.CRC, entry.file_size) for entry in bad.infolist()])
            with self.assertRaisesRegex(zipfile.BadZipFile, "CRC"):
                bad.read("README-synthetic.txt")
            self.assertEqual(bad.read("nested/space name.txt"), FIXTURES.FILES["nested/space name.txt"])
        with self.assertRaises(zipfile.BadZipFile):
            zipfile.ZipFile(io.BytesIO(original[:-22]))

    def test_archive_inventory_rejects_wrong_crc_size_type_duplicates_and_extra_files(self):
        entries = self.archive_entries()
        LAB.archive_inventory(json.dumps(entries).encode(), FIXTURES.FILES)
        cases = [entries[:-1], entries + [entries[0]], entries[:-1] + [entries[0]]]
        for field, value in (("Hashes", {"crc32": "00000000"}), ("Size", -1), ("Size", True),
                             ("IsDir", True), ("Path", "unexpected.txt")):
            changed = [dict(entry) for entry in entries]
            changed[0][field] = value
            cases.append(changed)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(LAB.LabError):
                LAB.archive_inventory(json.dumps(value).encode(), FIXTURES.FILES)

    def synthetic_archive_runtime(self, corrupt_result=None):
        runtime = mock.Mock()

        def result(args, config):
            if args[0] == "lsjson":
                if config.name == "truncated.conf":
                    return 1, b"", b"zip: not a valid zip file"
                return 0, json.dumps(self.archive_entries()).encode(), b""
            self.assertEqual(args[:3], ["rc", "--loopback", "operations/copyfile"])
            options = dict(argument.split("=", 1) for argument in args[3:])
            if options["dstFs"] == "Synthetic:":
                return 1, b"", b"read only file system"
            destination = Path(options["dstFs"]) / options["dstRemote"]
            if config.name == "corrupt.conf":
                if corrupt_result is not None:
                    return corrupt_result(destination)
                return 1, b"", b"zip: checksum error"
            name = options["srcRemote"]
            if name not in FIXTURES.FILES:
                return 1, b"", b"is not a regular file" if name == "nested" else b"object not found"
            destination.write_bytes(FIXTURES.FILES[name])
            return 0, b"{}", b""

        runtime.run.side_effect = result
        return runtime

    def test_archive_fixture_attests_all_capabilities_using_file_only_copy(self):
        runtime = self.synthetic_archive_runtime()
        row = LAB.run_backend(runtime, "archive", self.root / "archive")
        self.assertEqual(row["fixture_kind"], "local")
        self.assertEqual(row["errors"], [])
        self.assertEqual(row["capabilities"]["authentication_rejection"], "not_applicable")
        self.assertTrue(all(value == "passed" for key, value in row["capabilities"].items()
                            if key != "authentication_rejection"))
        self.assertTrue(all(call.args[0][0] in ("lsjson", "rc") for call in runtime.run.call_args_list))

    def test_archive_corruption_requires_crc_error_and_absent_destination(self):
        cases = ((1, b"", b"unrelated failure"), (0, b"", b"zip: checksum error"))
        for index, value in enumerate(cases):
            runtime = self.synthetic_archive_runtime(lambda destination: value)
            row = LAB.run_backend(runtime, "archive", self.root / str(index))
            self.assertNotEqual(row["capabilities"]["corrupt_member_rejection"], "passed")
            self.assertTrue(row["errors"])

        def leaves_partial(destination):
            destination.write_bytes(b"unaccepted partial bytes")
            return 1, b"", b"zip: checksum error"

        row = LAB.run_backend(self.synthetic_archive_runtime(leaves_partial), "archive", self.root / "partial")
        self.assertIn("corrupt_archive_member_accepted", row["errors"])

    def test_archive_preservation_detects_container_or_config_change_even_after_error(self):
        for filename, error in (("original.zip", "archive_container_changed"),
                                ("original.conf", "archive_config_changed")):
            root = self.root / filename
            runtime = mock.Mock()

            def mutate(args, config):
                (root / filename).write_bytes(b"changed")
                return 1, b"", b"unrelated listing failure"

            runtime.run.side_effect = mutate
            row = LAB.run_backend(runtime, "archive", root)
            self.assertIn(error, row["errors"])
            self.assertNotEqual(row["capabilities"]["source_preservation"], "passed")
            self.assertNotEqual(row["capabilities"]["config_preservation"], "passed")

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
