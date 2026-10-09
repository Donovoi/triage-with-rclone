"""Offline driver contract checks: fake processes/services, inert local files."""
from contextlib import contextmanager, ExitStack
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlencode


SOURCE = Path(__file__).resolve().parents[1] / "provider-lab/pcloud-oauth/probe.py"
probe = types.ModuleType("pcloud_oauth_probe_under_test")
probe.__file__ = str(SOURCE)
exec(compile(SOURCE.read_bytes(), str(SOURCE), "exec"), probe.__dict__)
QUESTION = {"State": "*oauth-islocal,,,", "Option": {"Name": "config_is_local", "Default": True, "Type": "bool"},
            "Error": "", "Result": ""}
TERMINAL = {"State": "", "Option": None, "Error": "", "Result": ""}
STATE = "AAECAwQFBgcICQoLDA0ODw"
README = b"Synthetic provider protocol fixture. No account or user data.\n"
CHECK_NAMES = {"environment", "tls_authority_bound", "authority_preserved", "version_binding", "initial_config_question", "callback_ownership", "authorize",
               "token_exchange", "config_persisted", "fresh_child_read", "source_preserved",
               "post_auth_config_preserved", "request_sequence"}


def json_bytes(value):
    return json.dumps(value, separators=(",", ":")).encode()


def manifest_bytes(version, sha):
    return ("# synthetic test manifest\nRCLONE_VERSION=" + version + "\nRCLONE_EXE_SHA256=" + "1" * 64
            + "\nRCLONE_WINDOWS_ZIP_SHA256=" + "2" * 64 + "\nRCLONE_LINUX_ZIP_SHA256=" + "3" * 64
            + "\nRCLONE_LINUX_EXE_SHA256=" + sha + "\n").encode()


def write_config(path, values):
    path.write_text("[Synthetic]\n" + "".join(key + " = " + value + "\n" for key, value in values.items()), encoding="utf-8")


class PureProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="oauth-probe-unit-")
        self.root = Path(self.temp.name).resolve()

    def tearDown(self):
        self.temp.cleanup()

    def plain_regular(self, path, private=False):
        return self.original_regular(path)

    def test_import_has_no_native_tls_network_or_filesystem_mutation(self):
        namespace = {"__file__": str(SOURCE), "__name__": "synthetic_import_only"}
        with patch("subprocess.Popen", side_effect=AssertionError("native forbidden")), \
                patch("socket.socket", side_effect=AssertionError("socket forbidden")), \
                patch("tempfile.mkdtemp", side_effect=AssertionError("creation forbidden")):
            exec(compile(SOURCE.read_bytes(), str(SOURCE), "exec"), namespace)
        self.assertNotIn("fixture_oauth", namespace)
        self.assertNotIn("cryptography", namespace)

    def test_strict_json_rejects_duplicates_nonfinite_invalid_and_oversized(self):
        self.assertEqual(probe.strict_json(b'{"a":{"b":1}}'), {"a": {"b": 1}})
        for value in (b'{"a":1,"a":2}', b'{"a":{"b":1,"b":2}}', b'{"a":NaN}', b'{"a":Infinity}',
                      b'\xff', b'{', b' ' * (2 * 1024 * 1024 + 1), True, None):
            with self.subTest(kind=type(value).__name__), self.assertRaises(probe.ProbeError):
                probe.strict_json(value)

    def test_manifest_binds_newer_version_and_all_exact_pins(self):
        path = self.root / "manifest.env"
        good = manifest_bytes("9.8.7", "a" * 64)
        path.write_bytes(good)
        self.assertEqual(probe.pins(path), ("9.8.7", "a" * 64))
        for bad in (good + b"RCLONE_VERSION=9.8.7\n", good.replace(b"9.8.7", b"09.8.7"),
                    good.replace(b"9.8.7", b"9.8"), good.replace(b"a" * 64, b"A" * 64),
                    good.replace(b"a" * 64, b"a" * 63), good + b"UNEXPECTED=value\n", b"# missing\n", b"x" * 4097):
            path.write_bytes(bad)
            with self.assertRaises(probe.ProbeError):
                probe.pins(path)

    def test_literal_three_file_manifest_matches_established_serialization(self):
        expected_files = {
            "README-synthetic.txt": b"Synthetic provider protocol fixture. No account or user data.\n",
            "nested/space name.txt": b"Nested synthetic payload.\n",
            "nested/bytes.bin": bytes(range(256)) * 8,
        }
        expected_manifest = (
            b'[{"path":"README-synthetic.txt","size":62,"sha256":"1e901527b93ae84dc9d95a8aa76bbc12d7d77dbf8ab449333c172cfc909c639e"},'
            b'{"path":"nested/bytes.bin","size":2048,"sha256":"10fc3c51a152e90e5b90319b601d92ccf37290ef53c35ff92507687d8a911a08"},'
            b'{"path":"nested/space name.txt","size":26,"sha256":"e019c52fe70badce27affda5e408659399ff764985f07104029a42ade38125bd"}]'
        )
        known = "c990bbd4909b227aae4c70d26f9da5534740a2eb10337ced47977f915fa617be"
        self.assertEqual(probe.FILES, expected_files)
        for entry in json.loads(expected_manifest):
            body = expected_files[entry["path"]]
            self.assertEqual(len(body), entry["size"])
            self.assertEqual(hashlib.sha256(body).hexdigest(), entry["sha256"])
        self.assertEqual(hashlib.sha256(expected_manifest).hexdigest(), known)
        self.assertEqual(probe.MANIFEST_SHA, known)
        self.assertEqual(probe.fixture_manifest_sha256(), known)
        self.assertEqual(probe.MEMBER, "README-synthetic.txt")
        self.assertEqual(len(probe.FILES[probe.MEMBER]), 62)
        self.assertEqual(probe.MEMBER_SHA, "1e901527b93ae84dc9d95a8aa76bbc12d7d77dbf8ab449333c172cfc909c639e")
        # The established manifest preserves path,size,sha256 key order. Generic
        # sorted-key JSON is a different digest despite equivalent parsed data.
        sorted_encoding = json.dumps(json.loads(expected_manifest), sort_keys=True, separators=(",", ":")).encode()
        self.assertNotEqual(hashlib.sha256(sorted_encoding).hexdigest(), known)
        changed = dict(expected_files)
        changed["nested/space name.txt"] += b"changed"
        with patch.object(probe, "FILES", changed):
            self.assertNotEqual(probe.fixture_manifest_sha256(), known)

    def test_initial_question_and_terminal_are_typed_closed_oracles(self):
        self.assertEqual(probe.question(json_bytes(QUESTION)), "*oauth-islocal,,,")
        probe.terminal(json_bytes(TERMINAL))
        cases = []
        for key, value in (("State", "*oauth-do,,,"), ("Error", "synthetic failure"), ("Result", "true"), ("extra", 1)):
            cases.append(dict(QUESTION, **{key: value}))
        for key, value in (("Name", "config_token"), ("Default", 1), ("Default", "true"), ("Type", "string")):
            altered = copy.deepcopy(QUESTION)
            altered["Option"][key] = value
            cases.append(altered)
        for value in cases:
            with self.assertRaises(probe.ProbeError):
                probe.question(json_bytes(value))
        for value in (dict(TERMINAL, Option={}), dict(TERMINAL, State="pending"), dict(TERMINAL, Error="error"),
                      dict(TERMINAL, extra=True), [], None):
            with self.assertRaises(probe.ProbeError):
                probe.terminal(json_bytes(value))

    def test_config_scope_token_and_original_bytes_are_bound(self):
        path = self.root / "synthetic.conf"
        options = {"type": "pcloud", "client_id": "synthetic-client", "client_secret": "synthetic-secret",
                   "hostname": "127.0.0.1:1234", "root_folder_id": "d100"}
        token = {"access_token": "synthetic-token", "token_type": "bearer", "expiry": "0001-01-01T00:00:00Z"}
        values = dict(options, token=json.dumps(token))
        self.original_regular = probe.regular
        with patch.object(probe, "regular", side_effect=self.plain_regular):
            write_config(path, values)
            self.assertEqual(probe.check_saved_config(path, options, "synthetic-token"), path.read_bytes())
            for key, replacement in (("access_token", "wrong"), ("token_type", "Bearer"),
                                     ("expiry", "2026-01-01T00:00:00Z"), ("refresh_token", "synthetic-refresh")):
                write_config(path, dict(options, token=json.dumps(dict(token, **{key: replacement}))))
                with self.assertRaises(probe.ProbeError):
                    probe.check_saved_config(path, options, "synthetic-token")
            for changed in (dict(values, hostname="api.pcloud.com"), dict(values, config_auth_no_browser="true"),
                            dict(values, password="unexpected"), options):
                write_config(path, changed)
                with self.assertRaises(probe.ProbeError):
                    probe.check_saved_config(path, options, "synthetic-token")
            for text in ("[Other]\ntype=pcloud\n", "[DEFAULT]\nx=1\n[Synthetic]\ntype=pcloud\n",
                         "[Synthetic]\ntype=pcloud\ntype=other\n", "[Synthetic]\ntype=first\n second\n"):
                path.write_text(text)
                with self.assertRaises(probe.ProbeError):
                    probe.config_values(path)

    def test_acquisition_requires_one_regular_exact_hash_member(self):
        destination = self.root / "output"
        destination.mkdir()
        file = destination / "README-synthetic.txt"
        file.write_bytes(README)
        probe.output_matches(destination)
        for body in (README[:-1], b"x" * 62):
            file.write_bytes(body)
            with self.assertRaises(probe.ProbeError):
                probe.output_matches(destination)
        file.write_bytes(README)
        extra = destination / "unexpected"
        extra.write_bytes(b"x")
        with self.assertRaises(probe.ProbeError):
            probe.output_matches(destination)

    def test_location_exact_authority_fields_no_duplicate_or_fragment(self):
        expected = {"code": "synthetic-code", "state": STATE}
        query = urlencode(expected)
        self.assertEqual(probe.validate_location("https://127.0.0.1:1234/auth?" + query,
                         "https", "127.0.0.1:1234", "/auth", expected), "/auth?" + query)
        for value in ("http://127.0.0.1:1234/auth?" + query, "https://localhost:1234/auth?" + query,
                      "https://127.0.0.1:1235/auth?" + query, "https://user@127.0.0.1:1234/auth?" + query,
                      "https://127.0.0.1:1234/auth?" + query + "#x", "https://127.0.0.1:1234/auth?" + query + "&state=" + STATE,
                      "https://127.0.0.1:1234/auth?" + query + "&extra=1", "https://127.0.0.1:1234/auth?state=%GG",
                      "https://127.0.0.1:1234/auth?" + query + "\r\n", "https://127.0.0.1:1234/other?" + query):
            with self.subTest(kind=value.split("?", 1)[0]), self.assertRaises((probe.ProbeError, ValueError)):
                probe.validate_location(value, "https", "127.0.0.1:1234", "/auth", expected)

    def test_callback_owner_requires_unique_ipv4_loopback_and_child_fd(self):
        path = Mock()
        path.is_symlink.return_value = True
        with patch.object(probe, "Path") as paths, patch.object(probe.os, "readlink", return_value="socket:[42]"):
            paths.return_value.iterdir.return_value = [path]
            with patch.object(probe, "listeners", return_value=([("0100007F:D1B2", "42")], [])):
                self.assertTrue(probe.callback_owner(123))
            for entries in (([("00000000:D1B2", "42")], []), ([("0100007F:D1B2", "42"), ("0100007F:D1B2", "43")], []),
                            ([], [("0" * 32 + ":D1B2", "42")]), ([("0100007F:D1B2", "43")], [])):
                with patch.object(probe, "listeners", return_value=entries), self.assertRaises(probe.ProbeError):
                    probe.callback_owner(123)
            with patch.object(probe, "listeners", return_value=([], [])):
                self.assertFalse(probe.callback_owner(123))

    def test_callback_log_requires_full_canonical_state_url(self):
        record = {"out": self.root / "out", "err": self.root / "err", "process": Mock(pid=123)}
        record["process"].poll.return_value = None
        record["out"].write_bytes(b"")
        native = Mock()
        good = ("NOTICE: Go to http://127.0.0.1:53682/auth?state=" + STATE + "\n").encode()
        with patch.object(probe, "callback_owner", return_value=True), patch.object(probe.time, "sleep"):
            record["err"].write_bytes(good)
            self.assertEqual(probe.wait_callback(native, record), STATE)
            for suffix in ("=", "&extra=1", "#fragment"):
                record["err"].write_bytes(good.rstrip() + suffix.encode() + b"\n")
                native.check.side_effect = [None, probe.ProbeError("bounded_stop")]
                with self.assertRaises(probe.ProbeError):
                    probe.wait_callback(native, record)
            for body in (good.replace(STATE.encode(), (STATE[:-1] + "x").encode()),
                         good + b"http://127.0.0.1:53682/auth?state=AAAAAAAAAAAAAAAAAAAAAA\n"):
                record["err"].write_bytes(body)
                native.check.side_effect = [None, probe.ProbeError("bounded_stop")]
                with self.assertRaises(probe.ProbeError):
                    probe.wait_callback(native, record)

    def test_http_response_requires_complete_bounded_single_location(self):
        connection = Mock()
        response = Mock(status=307)
        connection.getresponse.return_value = response
        with patch.object(probe.http.client, "HTTPConnection", return_value=connection) as constructor:
            response.getheaders.return_value = [("Content-Length", "2"), ("Location", "http://localhost:53682/")]
            response.read.return_value = b"ok"
            self.assertEqual(probe.request(53682, "/auth?state=" + STATE, "127.0.0.1:53682"),
                             (307, "http://localhost:53682/", b"ok"))
            constructor.assert_called_with("127.0.0.1", 53682, timeout=3)
            for headers, body in (([("Content-Length", "3")], b"ok"), ([("Content-Length", "2"), ("Content-Length", "2")], b"ok"),
                                  ([("Location", "one"), ("Location", "two")], b"ok"), ([("X-Too-Long", "x" * 8192)], b"ok"),
                                  ([], b"x" * 65537)):
                response.getheaders.return_value, response.read.return_value = headers, body
                with self.assertRaises(probe.ProbeError):
                    probe.request(53682, "/", "localhost:53682")
            self.assertEqual(connection.close.call_count, 6)

    def test_native_start_uses_scrubbed_environment_group_and_fixed_limits(self):
        native = object.__new__(probe.Native)
        native.binary, native.root, native.records = self.root / "inert", self.root, []
        native.config, native.env, native.deadline = self.root / "synthetic.conf", {"HOME": "owned"}, time.monotonic() + 60
        process = Mock(pid=123)
        process.poll.return_value = None
        with patch.object(probe.subprocess, "Popen", return_value=process) as launch, \
                patch.object(probe, "proc_identity", return_value=(10, 10001, 123)):
            record = native.start(["version"], ["--ca-cert", "owned-ca"], notice=True)
        args, kwargs = launch.call_args
        self.assertEqual(args[0][0], str(native.binary))
        self.assertEqual(args[0][-3:], ["--ca-cert", "owned-ca", "version"])
        self.assertTrue(kwargs["start_new_session"])
        self.assertEqual(kwargs["env"], {"HOME": "owned"})
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(record["identity"], (10, 10001, 123))
        record["out"].write_bytes(b"x" * (2 * 1024 * 1024 + 1))
        with self.assertRaisesRegex(probe.ProbeError, "child_output_limit"):
            native.check(record)
        record["out"].write_bytes(b"")
        record["deadline"] = time.monotonic() - 1
        with self.assertRaisesRegex(probe.ProbeError, "child_deadline"):
            native.check(record)
        native.records = [{}, {}, {}, {}]
        with self.assertRaisesRegex(probe.ProbeError, "native_budget_exceeded"):
            native.start(["version"])

    def test_native_cleanup_verifies_identity_and_reaps_after_kill(self):
        native = object.__new__(probe.Native)
        process = Mock(pid=123)
        process.poll.side_effect = [None, 0]
        process.wait.side_effect = [subprocess.TimeoutExpired("synthetic", 3), 0, 0]
        native.records = [{"process": process, "identity": (10, 10001, 123)}]
        with patch.object(probe, "proc_identity", return_value=(10, 10001, 123)), \
                patch.object(probe.os, "killpg", create=True) as kill, patch.object(probe.signal, "SIGKILL", 9, create=True):
            self.assertTrue(native.close())
            self.assertEqual(kill.call_args_list[0].args, (123, signal.SIGTERM))
            self.assertEqual(kill.call_args_list[1].args, (123, 9))
        process.poll.side_effect = None
        process.poll.return_value = None
        with patch.object(probe, "proc_identity", return_value=(11, 10001, 123)), \
                patch.object(probe.os, "killpg", create=True) as kill:
            self.assertFalse(native.close())
            kill.assert_not_called()

    def test_native_finish_checks_output_and_deadline_until_reaped(self):
        native = object.__new__(probe.Native)
        process = Mock(returncode=0)
        process.poll.side_effect = [None, 0]
        out, err = self.root / "child.out", self.root / "child.err"
        out.write_bytes(b"synthetic output")
        err.write_bytes(b"synthetic private diagnostic")
        record = {"out": out, "err": err, "process": process, "deadline": time.monotonic() + 20}
        with patch.object(probe.time, "sleep"):
            self.assertEqual(native.finish(record), (0, b"synthetic output", b"synthetic private diagnostic"))
        process.wait.assert_called_once_with()
        process.poll.side_effect = [None]
        record["deadline"] = time.monotonic() - 1
        with self.assertRaisesRegex(probe.ProbeError, "child_deadline"):
            native.finish(record)


class FakeState:
    def __init__(self, files, client_id, client_secret, code, token, wrong_token):
        self.files, self.client_id, self.client_secret = files, client_id, client_secret
        self.code, self.token, self.wrong_token = code, token, wrong_token
        self.events, self.requests, self.payload_bytes, self.authenticated = [], 0, 0, 0
        self.authorize_requests = self.token_requests = 0
        self.token_issued = self.cleanup_complete = False
        self.unexpected = self.auth_denied = self.member_denied = self.rejected_mutations = self.rejected_payload_bytes = 0
        self.budget_exceeded = False
        self.bound = None
        self.preserved = True

    def bind_state(self, value):
        if self.bound is not None:
            raise AssertionError("state bound twice")
        self.bound = value

    def source_preserved(self):
        return self.preserved


class FakeFixture:
    host, port = "fixture.pcloud.com", 443

    def __init__(self, owner, state):
        self.owner, self.state, self.cleanup_complete = owner, state, False

    def rclone_ca_args(self):
        return ["--ca-cert", "synthetic-owned-ca"]

    def client_context(self):
        return self

    def snapshot(self):
        return {"certificate_cleanup": True, "transport": {"cleanup_complete": True, "active_connections": 0,
            "active_workers": 0, "active_timers": 0,
            "failure_codes": ["synthetic_tls_failure"] if self.owner.failure == "transport" else []}}


class FakeNative:
    def __init__(self, owner, binary, root):
        self.owner, self.binary, self.root, self.records = owner, binary, root, []
        self.config = root / "synthetic.conf"
        self.config.write_bytes(b"")
        self.options = None

    def run(self, args, ca_args=()):
        self.records.append(list(args))
        if args == ["version"]:
            return 0, b"rclone v9.8.6\n" if self.owner.failure == "version" else b"rclone v9.8.7\n", b""
        if args[:4] == ["config", "create", "Synthetic", "pcloud"]:
            self.options = {"type": "pcloud"}
            self.options.update(arg.split("=", 1) for arg in args[4:] if "=" in arg and not arg.startswith("config_"))
            write_config(self.config, self.options)
            value = copy.deepcopy(QUESTION)
            if self.owner.failure == "question": value["Option"]["Default"] = 1
            return 0, json_bytes(value), b""
        self.owner.assertEqual(args[:3], ["rc", "--loopback", "operations/copyfile"])
        values = dict(arg.split("=", 1) for arg in args[3:])
        self.owner.assertEqual(values["srcFs"], "Synthetic:")
        self.owner.assertEqual(values["srcRemote"], "README-synthetic.txt")
        self.owner.assertEqual(values["dstRemote"], "README-synthetic.txt")
        destination = Path(values["dstFs"])
        (destination / "README-synthetic.txt").write_bytes(b"x" * 62 if self.owner.failure == "bytes" else README)
        if self.owner.failure == "extra": (destination / "unexpected.txt").write_bytes(b"extra")
        if self.owner.failure == "config_bytes": self.config.write_bytes(self.config.read_bytes() + b"# changed\n")
        state = self.owner.state
        state.events.extend([("root_list", ""), ("checksum", "README-synthetic.txt"),
                             ("link", "README-synthetic.txt"), ("content", "README-synthetic.txt")])
        state.requests += 4
        state.payload_bytes, state.authenticated = 62, 4
        if self.owner.failure == "source": state.preserved = False
        return 0, b"{}\n", b""

    def start(self, args, ca_args=(), notice=False):
        self.owner.assertEqual(args, ["config", "update", "Synthetic", "--continue", "--state", "*oauth-islocal,,,",
                                     "--result", "true", "config_auth_no_browser=true"])
        self.owner.assertTrue(notice)
        self.records.append(list(args))
        return {"synthetic": True}

    def finish(self, record):
        token = {"access_token": self.owner.state.token, "token_type": "bearer", "expiry": "0001-01-01T00:00:00Z"}
        if self.owner.failure == "token": token["refresh_token"] = "unexpected"
        write_config(self.config, dict(self.options, token=json.dumps(token)))
        return 0, json_bytes(TERMINAL), b""

    def close(self):
        self.owner.closed += 1
        return self.owner.failure != "children"


class ProbeOrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="oauth-probe-fake-")
        self.root = Path(self.temp.name).resolve()
        self.base, self.work = self.root / "image", self.root / "work"
        self.base.mkdir()
        self.work.mkdir()
        self.binary, self.manifest = self.base / "rclone", self.base / "rclone-version.env"
        self.binary.write_bytes(b"synthetic inert fixture binary, never executed")
        self.manifest.write_bytes(manifest_bytes("9.8.7", hashlib.sha256(self.binary.read_bytes()).hexdigest()))
        self.failure = None
        self.state = self.fixture = self.native = None
        self.closed = self.requests = 0
        self.old_regular = probe.regular

    def tearDown(self):
        self.temp.cleanup()

    @contextmanager
    def service(self, root, state):
        self.state, self.fixture = state, FakeFixture(self, state)
        try:
            yield self.fixture
        finally:
            self.fixture.cleanup_complete = state.cleanup_complete = True

    def make_native(self, binary, root):
        self.native = FakeNative(self, binary, root)
        return self.native

    def request(self, port, path, host, context=None):
        self.requests += 1
        state = self.state
        if self.requests == 1:
            self.assertIsNone(state.bound, "bind_state must follow validation of /auth307")
            self.assertEqual((port, host, path), (53682, "127.0.0.1:53682", "/auth?state=" + STATE))
            values = {"access_type": "offline", "client_id": state.client_id, "redirect_uri": "http://localhost:53682/",
                      "response_type": "code", "state": STATE}
            authority = "external.invalid" if self.failure == "authority" else "fixture.pcloud.com"
            return 307, "https://" + authority + "/oauth2/authorize?" + urlencode(sorted(values.items())), b"redirect"
        if self.requests == 2:
            self.assertEqual(state.bound, STATE)
            self.assertEqual((port, host), (443, "fixture.pcloud.com"))
            state.events.append(("authorize", ""))
            state.requests += 1
            state.authorize_requests = 1
            values = {"code": state.code, "state": STATE, "locationid": "1", "hostname": "fixture.pcloud.com"}
            return 302, "http://localhost:53682/?" + urlencode(sorted(values.items())), b"redirect"
        self.assertEqual((port, host), (53682, "localhost:53682"))
        self.assertIsNone(context)
        state.events.append(("token", ""))
        state.requests += 1
        state.token_issued, state.token_requests = True, 1
        return 200, None, b"<html>synthetic success</html>"

    def execute(self, failure=None):
        self.failure = failure
        module = types.SimpleNamespace(OAuthState=FakeState, serve_oauth=self.service)
        original_sys_path = list(sys.path)
        with ExitStack() as stack:
            stack.enter_context(patch.object(probe, "BASE", self.base))
            stack.enter_context(patch.object(probe, "WORK", self.work))
            stack.enter_context(patch.object(probe, "UID", self.root.stat().st_uid))
            stack.enter_context(patch.object(probe, "environment_checks"))
            stack.enter_context(patch.object(probe, "authority_environment", return_value=("fixed", b"0\n")))
            stack.enter_context(patch.object(probe, "fixture_authority"))
            stack.enter_context(patch.object(probe, "Native", side_effect=self.make_native))
            stack.enter_context(patch.object(probe, "regular", side_effect=lambda path, private=False: self.old_regular(path)))
            stack.enter_context(patch.object(probe, "wait_callback", return_value=STATE))
            stack.enter_context(patch.object(probe, "request", side_effect=self.request))
            stack.enter_context(patch.object(probe, "listeners", return_value=([("synthetic", "1")], []) if failure == "listeners" else ([], [])))
            stack.enter_context(patch.object(probe.sys, "platform", "linux"))
            stack.enter_context(patch.object(probe.platform, "machine", return_value="x86_64"))
            stack.enter_context(patch.object(probe.os, "getuid", return_value=10001, create=True))
            stack.enter_context(patch.object(probe.os, "getgid", return_value=10001, create=True))
            stack.enter_context(patch.dict(sys.modules, {"fixture_oauth": module, "cryptography": types.SimpleNamespace(__version__="50.0.2")}))
            stack.enter_context(patch("subprocess.Popen", side_effect=AssertionError("native forbidden")))
            stack.enter_context(patch("socket.socket", side_effect=AssertionError("listener forbidden")))
            try:
                return probe.run(self.binary, self.manifest)
            finally:
                sys.path[:] = original_sys_path

    def test_complete_fake_chain_is_fresh_bounded_and_feasibility_only(self):
        report = self.execute()
        self.assertTrue(report["success"], report["errors"])
        self.assertIs(report["ledger_eligible"], False)
        self.assertEqual(report["scope"], "pcloud_oauth_callback_feasibility")
        self.assertEqual(set(report["checks"]), CHECK_NAMES)
        self.assertTrue(all(report["checks"].values()))
        self.assertTrue(all(report["cleanup"].values()))
        self.assertEqual(report["observations"], {"native_commands": 4, "http_transactions": 8, "callback_requests": 2, "https_requests": 6})
        self.assertEqual(self.closed, 1)
        self.assertEqual(list(self.work.iterdir()), [])
        self.assertRegex(report["started_utc"], r"\.\d{6}Z$")
        self.assertRegex(report["finished_utc"], r"\.\d{6}Z$")
        public = json.dumps(report)
        for value in (self.state.client_id, self.state.client_secret, self.state.code, self.state.token, self.state.wrong_token, STATE):
            self.assertNotIn(value, public)

    def test_initial_question_and_authority_fail_before_token(self):
        for failure in ("question", "authority"):
            with self.subTest(failure=failure):
                self.requests = self.closed = 0
                report = self.execute(failure)
                self.assertFalse(report["success"])
                self.assertFalse(report["checks"]["token_exchange"])
                self.assertFalse(self.state.token_issued)
                self.assertTrue(all(report["cleanup"].values()))
                self.assertEqual(list(self.work.iterdir()), [])

    def test_bad_persistence_wrong_bytes_extra_file_or_late_change_fail(self):
        for failure in ("token", "bytes", "extra", "config_bytes", "source"):
            with self.subTest(failure=failure):
                self.requests = self.closed = 0
                report = self.execute(failure)
                self.assertFalse(report["success"])
                self.assertTrue(report["errors"])
                self.assertTrue(report["cleanup"]["children_stopped"])
                self.assertEqual(report["cleanup"]["temporary_removed"], failure != "source")
                self.assertEqual(bool(list(self.work.iterdir())), failure == "source")

    def test_transport_or_listener_failure_retains_owned_temporary_root(self):
        for failure in ("transport", "listeners"):
            with self.subTest(failure=failure):
                self.requests = self.closed = 0
                report = self.execute(failure)
                self.assertFalse(report["success"])
                if failure == "listeners":
                    self.assertFalse(report["cleanup"]["listeners_closed"])
                else:
                    self.assertIn("fixture_cleanup_failed", report["errors"])
                self.assertFalse(report["cleanup"]["temporary_removed"])
                self.assertTrue(list(self.work.iterdir()))

    def test_observed_native_version_mismatch_stops_before_authentication(self):
        report = self.execute("version")
        self.assertFalse(report["success"])
        self.assertIn("runtime_version_mismatch", report["errors"])
        self.assertFalse(report["checks"]["version_binding"])
        self.assertIsNone(self.state)
        self.assertEqual(report["observations"], {"native_commands": 1, "http_transactions": 0, "callback_requests": 0, "https_requests": 0})
        self.assertTrue(all(report["cleanup"].values()))

    def test_live_child_cleanup_failure_preserves_private_work_until_container_removal(self):
        report = self.execute("children")
        self.assertFalse(report["success"])
        self.assertFalse(report["cleanup"]["children_stopped"])
        self.assertFalse(report["cleanup"]["temporary_removed"])
        self.assertTrue(list(self.work.iterdir()))


if __name__ == "__main__":
    unittest.main()
