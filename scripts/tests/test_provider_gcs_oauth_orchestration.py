"""Full orchestration with scripted process/HTTP boundaries; never opens a socket.

The real driver, Native process wrapper, config parser, expiry/cancellation,
verdicts, supervisor, source staging and owned cleanup execute. Only external
process, transport and Linux identity observations are substituted. Literal
transcripts below are intentionally independent of the producer's case maps.
"""
import base64
from contextlib import contextmanager, ExitStack
import copy
from datetime import datetime, timezone
from email.message import Message
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode

LAB = Path(__file__).resolve().parents[1] / "provider-lab"
ROOT = LAB / "gcs-oauth"
sys.path.insert(0, str(LAB))


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


F = load("gcs_orchestration_fixture", "fixture_oauth.py")
P = load("gcs_orchestration_probe", "probe.py")
S = load("gcs_orchestration_supervisor", "run_container.py")
STAMP = "2026-10-09T00:00:00Z"
MEMBER = "README-synthetic.txt"
PAYLOAD = b"Synthetic provider protocol fixture. No account or user data.\n"
STATE = "AAAAAAAAAAAAAAAAAAAAAA"
ALT = "AQEBAQEBAQEBAQEBAQEBAQ"
CASES = ("positive", "wrong_state", "blank_state", "consent_denied", "invalid_code",
         "wrong_client_secret", "callback_cancel", "refresh", "refresh_denied", "refresh_cancel")
TRANSCRIPTS = {
    "positive": ["authorize", "code_basic", "code_grant", "metadata", "content"],
    "wrong_state": ["authorize"], "blank_state": ["authorize"], "consent_denied": ["authorize"],
    "invalid_code": ["authorize", "code_basic", "code_denied"],
    "wrong_client_secret": ["authorize", "code_basic", "code_denied"], "callback_cancel": [],
    "refresh": ["authorize", "code_basic", "code_grant", "refresh_basic", "refresh_grant", "metadata", "content"],
    "refresh_denied": ["authorize", "code_basic", "code_grant", "refresh_basic", "refresh_denied"],
    "refresh_cancel": ["authorize", "code_basic", "code_grant", "refresh_basic", "refresh_held"],
}


class ScriptedProcess:
    def __init__(self, owner, pid, out, err):
        self.owner, self.pid, self.out, self.err = owner, pid, out, err
        self.returncode = None

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired("synthetic-process", timeout)
        return self.returncode

    def complete(self, code=0, output=b"", error=b""):
        self.out.write_bytes(output)
        self.err.write_bytes(error)
        self.returncode = code


class DriverHarness:
    def __init__(self, base, fault=None, fault_mode=None):
        self.base, self._fault, self.fault_mode = Path(base), fault, fault_mode
        self.work = self.base / "work"
        self.work.mkdir()
        self.binary = self.base / "synthetic-runtime"
        self.binary.write_bytes(b"non-executable generated test data")
        self.sha = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.wall, self.mono = 1704067200.0, 1000.0
        self.processes, self.states, self.config_snapshots, self.commands, self.signals = {}, [], [], [], []
        self.state = self.callback = self.config = None
        self.options = None
        self.seed = 0

    @property
    def fault(self):
        return self._fault if self.fault_mode is None or self.state is not None and self.state.mode == self.fault_mode else None

    def sleep(self, duration):
        self.wall += duration
        self.mono += duration

    def credential(self, size):
        if size == 16:
            self.seed = 0
            return ALT
        value = chr(ord("a") + self.seed) * 32
        self.seed += 1
        return value

    def regular(self, path, private=False):
        # Linux ownership observation only; bytes/parser/hash checks stay real.
        path = Path(path)
        info = path.stat()
        assert path.is_absolute() and path.is_file() and not path.is_symlink()
        return types.SimpleNamespace(st_uid=0 if path == self.binary else 10001,
                                     st_size=info.st_size, st_nlink=info.st_nlink, st_mode=info.st_mode)

    def remove(self, root, identity):
        assert root.parent == self.work and (root.stat().st_dev, root.stat().st_ino) == identity
        shutil.rmtree(root)
        return not any(self.work.iterdir())

    @contextmanager
    def serve(self, root, value):
        self.state = value
        self.states.append(value)
        value.deadline = self.mono + 60
        self.current_root = root
        fixture = types.SimpleNamespace(host="127.0.0.1:12345", port=12345, cleanup_complete=False,
            rclone_ca_args=lambda: ["--ca-cert", str(root / "synthetic-ca.pem")], client_context=lambda: "owned-ca",
            snapshot=lambda: {"transport": {"failure_codes": ["synthetic_failed_join"] if self.fault == "transport_error" else []}})

        class HeldResponse:
            def wait(inner, timeout):
                return True  # Script an outstanding response without a real thread.

            def set(inner):
                assert self.copy_process.returncode is not None, "held response released before process reap"
                value.hold_completed = True

        value.release_hold = HeldResponse()
        try:
            yield fixture
        finally:
            if self.config is not None:
                self.config_snapshots.append(self.config.read_bytes())
            fixture.cleanup_complete = value.cleanup_complete = self.fault != "fixture_cleanup"

    def wire(self, method, target, body=b"", auth=None):
        # Real handler and state machine, in-memory framing and response streams.
        h = object.__new__(F.OAuthHandler)
        h.server = types.SimpleNamespace(state=self.state, server_address=("127.0.0.1", 12345))
        h._counted, h.command, h.path = False, method, target
        h.raw_requestline = (method + " " + target + " HTTP/1.1\r\n").encode("ascii")
        h.headers = Message()
        h.headers["Host"] = "127.0.0.1:12345"
        if auth is not None:
            h.headers["Authorization"] = auth
        if method == "POST":
            h.headers["Content-Length"], h.headers["Content-Type"] = str(len(body)), "application/x-www-form-urlencoded"
        h.rfile, h.wfile = io.BytesIO(body), io.BytesIO()
        headers = {}
        h.status = None
        h.send_response = lambda status: setattr(h, "status", status)
        h.send_header = lambda key, value: headers.__setitem__(key.lower(), value)
        h.end_headers = lambda: None
        h.dispatch()
        if self.state.mode == "refresh_cancel" and self.state.phase == "held":
            self.state.hold_completed = False  # Remains pending until the driver cancels/reaps.
        return h.status, headers.get("location"), h.wfile.getvalue()

    def exchange(self, refresh=False):
        secret = "i" * 32 if self.state.mode == "wrong_client_secret" else "b" * 32
        fields = ({"grant_type": "refresh_token", "refresh_token": "e" * 32} if refresh else
                  {"grant_type": "authorization_code", "code": "h" * 32 if self.state.mode == "invalid_code" else "c" * 32,
                   "redirect_uri": "http://127.0.0.1:53682/"})
        if self.fault not in ("omit_basic", "omit_refresh_basic") or self.fault == "omit_refresh_basic" and not refresh:
            status, _, _ = self.wire("POST", "/oauth/token", urlencode(sorted(fields.items())).encode(),
                "Basic " + base64.b64encode(("a" * 32 + ":" + secret).encode()).decode())
            assert status == 400
        if self.fault == "omit_exchange" and not refresh or self.fault == "omit_refresh" and refresh:
            return None
        fields.update(client_id="a" * 32, client_secret=secret)
        status, _, raw = self.wire("POST", "/oauth/token", urlencode(sorted(fields.items())).encode())
        return json.loads(raw) if status is not None else None

    def write_config(self, token=None):
        options = self.options.copy()
        if self.fault == "mutated_option" and token:
            options["env_auth"] = "true"
        if token is not None:
            options["token"] = json.dumps(token, separators=(",", ":"))
        self.config.write_text("[Synthetic]\n" + "".join(key + " = " + value + "\n" for key, value in options.items()), encoding="utf-8", newline="\n")

    def persist(self, issued, refresh=False):
        if issued is None or "access_token" not in issued or self.fault == "omit_persistence":
            return
        seconds = issued["expires_in"]
        saved = {**issued, "expiry": datetime.fromtimestamp(self.wall + seconds, timezone.utc).isoformat().replace("+00:00", "Z")}
        if self.fault == "stale_replacement" and refresh:
            saved["access_token"] = "d" * 32
        if self.fault == "wrong_expiry":
            saved["expiry"] = "2030-01-01T00:00:00Z"
        self.write_config(saved)

    def popen(self, command, **kwargs):
        assert kwargs["start_new_session"] is True and kwargs["stdin"] == subprocess.DEVNULL
        assert set(kwargs["env"]) == {"PATH", "HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "TMPDIR", "LANG", "LC_ALL"}
        assert not any("no-check-certificate" in word or "insecure" in word for word in command)
        pid = 100 + len(self.processes)
        child = ScriptedProcess(self, pid, Path(kwargs["stdout"].name), Path(kwargs["stderr"].name))
        self.processes[pid] = child
        self.config = Path(command[command.index("--config") + 1])
        offset = next(i for i, value in enumerate(command) if value in ("version", "config", "rc"))
        args = command[offset:]
        self.commands.append(args)
        if args == ["version"]:
            child.complete(output=b"rclone v1.75.1\n")
        elif args[:4] == ["config", "create", "Synthetic", "google cloud storage"]:
            self.options = {"type": "google cloud storage", **dict(word.split("=", 1) for word in args[5:] if word != "config_auth_no_browser=true")}
            assert self.options["env_auth"] == self.options["anonymous"] == self.options["client_credentials"] == "false"
            assert self.options["service_account_file"] == self.options["service_account_credentials"] == ""
            assert "access_token" not in self.options
            self.write_config()
            child.complete(output=b'{"State":"*oauth-islocal,,,","Option":{"Name":"config_is_local","Default":true,"Type":"bool"},"Error":"","Result":""}')
        elif args[:3] == ["config", "update", "Synthetic"]:
            assert args[3:] == ["--continue", "--state", "*oauth-islocal,,,", "--result", "true", "config_auth_no_browser=true"]
            self.callback = child
            child.err.write_bytes(("http://127.0.0.1:53682/auth?state=" + STATE + "\n").encode())
        elif args[:3] == ["rc", "--loopback", "operations/copyfile"]:
            self.copy_process = child
            params = dict(word.split("=", 1) for word in args[3:])
            assert params == {"srcFs": "Synthetic:synthetic-bucket",
                              "srcRemote": "another-object" if self.fault == "denial_launch_drift" else MEMBER,
                              "dstFs": str(self.current_root / "output"), "dstRemote": MEMBER}
            self.copy(child, params)
        else:
            raise AssertionError("unexpected scripted command")
        return child

    def request(self, port, path, host, context=None):
        if port == 12345:
            assert host == "127.0.0.1:12345" and context == "owned-ca"
            if self.fault == "omit_authorize":
                return 302, "http://127.0.0.1:53682/?code=" + "c" * 32 + "&state=" + ALT, b"synthetic redirect"
            return self.wire("GET", path)
        assert port == 53682 and context is None
        if path.startswith("/auth?"):
            assert path == "/auth?state=" + STATE and host == "127.0.0.1:53682"
            # Literal oracle from pinned GCS storageConfig -> oauthutil.RedirectURL;
            # deliberately independent of the probe/fixture callback constants.
            fields = {"access_type": "offline", "client_id": "a" * 32, "redirect_uri": "http://127.0.0.1:53682/",
                      "response_type": "code", "scope": "https://www.googleapis.com/auth/devstorage.read_write", "state": STATE}
            if self.fault == "callback_hostname_alias":
                fields["redirect_uri"] = "http://localhost:53682/"
            elif self.fault == "callback_wrong_port":
                fields["redirect_uri"] = "http://127.0.0.1:53683/"
            elif self.fault == "authorize_missing_field":
                del fields["access_type"]
            elif self.fault == "authorize_extra_field":
                fields["extra"] = "1"
            authority = "outside.invalid" if self.fault == "redirect_escape" else "127.0.0.1:12345"
            query = urlencode(sorted(fields.items()))
            if self.fault == "authorize_duplicate_field":
                query += "&state=" + STATE
            return 307, "https://" + authority + "/oauth/authorize?" + query, b"redirect"
        assert host == "127.0.0.1:53682"
        values = parse_qs(path.partition("?")[2], keep_blank_values=True)
        mode = self.state.mode
        if mode in ("wrong_state", "blank_state"):
            got = ALT if mode == "wrong_state" else ""
            assert values["state"] == [got]
            error = 'Error: Auth state doesn\'t match\nCode: ""\nDescription: Expecting "' + STATE + '" got "' + got + '"'
        elif mode == "consent_denied":
            error = "No code returned by remote server: access_denied: synthetic consent denied"
        else:
            issued = self.exchange()
            if mode in ("invalid_code", "wrong_client_secret"):
                error = 'oauth2: "' + ("invalid_client" if mode == "wrong_client_secret" else "invalid_grant") + '" "synthetic grant rejected"'
            else:
                self.persist(issued)
                self.callback.complete(output=b'{"State":"","Option":null,"Error":"","Result":""}')
                return 200, None, b"synthetic success"
        if self.fault == "denial_mutates_config":
            self.config.write_text(self.config.read_text() + "env_auth = true\n")
        if self.fault == "generic_denial":
            error = "unrelated network failure"
        self.callback.complete(1, error=error.encode())
        return (400 if mode in ("wrong_state", "blank_state", "consent_denied") else 200), None, b"synthetic denial"

    def copy(self, child, params):
        mode = self.state.mode
        if self.fault == "refresh_never_reached":
            child.complete(1, b"{}")
            return
        if mode.startswith("refresh"):
            stored = json.loads(P.config_values(self.config)["token"])
            assert self.wall > datetime.fromisoformat(stored["expiry"].replace("Z", "+00:00")).timestamp()
            issued = self.exchange(refresh=True)
            if mode == "refresh_cancel":
                return
            if mode == "refresh_denied":
                error = {"error": "loopback: call failed: invalid_grant: maybe token expired? - reconnect",
                         "path": "operations/copyfile", "status": 500}
                if self.fault == "denial_extra_input":
                    error["input"] = params
                if self.fault == "denial_wrong_path":
                    error["path"] = "operations/list"
                if self.fault == "denial_wrong_status":
                    error["status"] = 400
                if self.fault == "wrong_denial_cause":
                    error["error"] = "unrelated network failure"
                if self.fault == "wrong_denial_origin":
                    error["error"] = "unrelated: invalid_grant: maybe token expired?"
                if self.fault == "denial_writes_payload":
                    (Path(params["dstFs"]) / MEMBER).write_bytes(PAYLOAD)
                if self.fault == "denial_mutates_config":
                    self.persist({"access_token": "f" * 32, "refresh_token": "g" * 32, "token_type": "Bearer", "expires_in": 300}, True)
                child.complete(1, json.dumps(error).encode())
                return
            self.persist(issued, refresh=True)
        token = "f" * 32 if mode == "refresh" else "d" * 32
        raw = PAYLOAD
        if self.fault != "omit_read":
            status, _, _ = self.wire("GET", "/storage/v1/b/synthetic-bucket/o/README-synthetic.txt?alt=json&prettyPrint=false", auth="Bearer " + token)
            status, _, raw = self.wire("GET", "/media/README-synthetic.txt", auth="Bearer " + token)
            if status != 200:
                child.complete(1, b"{}")
                return
        if self.fault == "bad_payload":
            raw += b"changed"
        (Path(params["dstFs"]) / MEMBER).write_bytes(raw)
        child.complete(output=b"{}")

    def kill(self, pid, sig):
        self.signals.append((pid, sig))
        if self.fault == "unreaped":
            return
        self.processes[pid].returncode = 0 if self.fault == "cancel_zero_exit" else -15

    @contextmanager
    def active(self):
        module = types.SimpleNamespace(OAuthState=F.OAuthState, serve_oauth=self.serve,
            SCOPE="https://www.googleapis.com/auth/devstorage.read_write", REFRESH_MODES=frozenset(("refresh", "refresh_denied", "refresh_cancel")))
        with ExitStack() as stack:
            def use(target, name, **kwargs):
                return stack.enter_context(patch.object(target, name, **kwargs))
            stack.enter_context(patch.dict(sys.modules, {"fixture_oauth": module, "cryptography": types.SimpleNamespace(__version__="50.0.2")}))
            use(socket, "socket", side_effect=AssertionError("real socket forbidden"))
            use(P, "WORK", new=self.work)
            use(P, "environment_checks", return_value=None)
            use(P, "regular", side_effect=self.regular)
            use(P, "pins", return_value=("1.75.1", self.sha))
            use(P, "request", side_effect=self.request)
            use(P, "callback_owner", side_effect=lambda pid: self.processes[pid] is self.callback and self.callback.poll() is None)
            use(P, "proc_identity", side_effect=lambda pid: (7, 10001, pid))
            use(P, "listeners", return_value=([("owned", "socket")], []) if self.fault == "listener_left" else ([], []))
            use(P, "remove_owned", side_effect=self.remove)
            use(P, "utc_now", return_value=STAMP)
            use(P.subprocess, "Popen", side_effect=self.popen)
            if self.fault == "denial_launch_drift":
                original_start = P.Native.start
                def changed_start(native, arguments, ca_args=(), notice=False):
                    if arguments[:3] == ['rc', '--loopback', 'operations/copyfile']:
                        arguments = [*arguments]
                        arguments[4] = 'srcRemote=another-object'
                    return original_start(native, arguments, ca_args, notice)
                use(P.Native, "start", new=changed_start)
            use(P.sys, "platform", new="linux")
            use(P.os, "getuid", return_value=10001, create=True)
            use(P.os, "getgid", return_value=10001, create=True)
            use(P.os, "killpg", side_effect=self.kill, create=True)
            use(P.os, "O_NOFOLLOW", new=getattr(P.os, "O_NOFOLLOW", 0), create=True)
            use(P.signal, "SIGKILL", new=9, create=True)
            use(P.platform, "machine", return_value="x86_64")
            use(P.platform, "python_version", return_value="3.12.15")
            use(P.secrets, "token_urlsafe", side_effect=self.credential)
            use(P.time, "time", side_effect=lambda: self.wall)
            use(P.time, "monotonic", side_effect=lambda: self.mono)
            use(P.time, "sleep", side_effect=self.sleep)
            yield

    def case(self, mode):
        with self.active():
            return P.run_case(self.binary, self.base / "unused-manifest", mode)

    def suite(self):
        with self.active():
            return P.run(self.binary, self.base / "unused-manifest")


class DriverOrchestrationTests(unittest.TestCase):
    def test_authorize_query_drift_fails_before_https_and_reaps_owned_child(self):
        for fault in ("callback_hostname_alias", "callback_wrong_port", "authorize_missing_field",
                      "authorize_extra_field", "authorize_duplicate_field"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                h = DriverHarness(directory, fault)
                result = h.case("positive")
                self.assertFalse(result["success"])
                self.assertEqual(result["errors"], ["url_query_mismatch"])
                self.assertEqual(result["observations"], {"native_commands": 3, "callback_requests": 1,
                                                        "https_requests": 0, "http_transactions": 1})
                self.assertFalse(result["checks"]["authorize"])
                self.assertFalse(result["checks"]["token_exchange"])
                self.assertEqual(h.states[0].events, [])
                self.assertFalse(h.states[0].token_issued)
                self.assertTrue(all(result["cleanup"].values()))
                self.assertTrue(all(child.poll() is not None for child in h.processes.values()))
                self.assertFalse(any(h.work.iterdir()))

    def test_suite_stops_after_real_failed_case_and_reaps_its_children(self):
        with tempfile.TemporaryDirectory() as directory:
            h = DriverHarness(directory, "generic_denial", fault_mode="invalid_code")
            suite = h.suite()
            self.assertFalse(suite["success"])
            self.assertEqual([row["name"] for row in suite["cases"]], list(CASES[:5]))
            self.assertTrue(all(row["report"]["success"] for row in suite["cases"][:-1]))
            self.assertEqual(suite["cases"][-1]["report"]["errors"], ["expected_auth_denial_absent"])
            self.assertEqual(len(h.commands), 16)
            self.assertTrue(all(child.poll() is not None for child in h.processes.values()))
            self.assertFalse(any(h.work.iterdir()))

    def test_all_ten_cases_follow_independent_transcripts_and_config_states(self):
        with tempfile.TemporaryDirectory() as directory:
            h = DriverHarness(directory)
            suite = h.suite()
            self.assertTrue(suite["success"], [(row["name"], row["report"]["errors"]) for row in suite["cases"]])
            self.assertFalse(suite["ledger_eligible"])
            self.assertEqual([row["name"] for row in suite["cases"]], list(CASES))
            self.assertEqual(len(h.states), 10)
            for mode, state, raw in zip(CASES, h.states, h.config_snapshots):
                self.assertEqual(state.events, [(event, MEMBER if event in ("metadata", "content") else "") for event in TRANSCRIPTS[mode]])
                self.assertEqual(state.requests, len(TRANSCRIPTS[mode]))
                text = raw.decode()
                if mode in ("positive", "refresh", "refresh_denied", "refresh_cancel"):
                    token = json.loads(next(line.split(" = ", 1)[1] for line in text.splitlines() if line.startswith("token = ")))
                    self.assertEqual(token["access_token"], ("f" if mode == "refresh" else "d") * 32)
                    self.assertEqual(token["refresh_token"], ("g" if mode == "refresh" else "e") * 32)
                else:
                    self.assertNotIn("token = ", text)
                self.assertIn("env_auth = false\n", text)
                self.assertTrue(state.cleanup_complete)
            self.assertEqual(len(h.commands), 34)
            self.assertEqual(len(h.signals), 2)
            self.assertFalse(any(h.work.iterdir()))
            rendered = json.dumps(suite)
            for credential in [letter * 32 for letter in "abcdefghi"] + [STATE, ALT]:
                self.assertNotIn(credential, rendered)

    def test_required_exchange_read_refresh_or_cancel_cannot_be_omitted(self):
        for mode, fault, cause in (("positive", "omit_exchange", "code_exchange_failed"),
                ("positive", "omit_read", "request_sequence_mismatch"), ("positive", "omit_basic", "code_exchange_failed"),
                ("positive", "omit_persistence", "non_token_config_changed"),
                ("wrong_state", "omit_authorize", "request_sequence_mismatch"),
                ("refresh", "omit_refresh", "synthetic_read_failed"), ("refresh", "omit_refresh_basic", "synthetic_read_failed"),
                ("callback_cancel", "cancel_zero_exit", "cancellation_exit_mismatch"),
                ("refresh_cancel", "cancel_zero_exit", "cancellation_exit_mismatch"),
                ("refresh_cancel", "refresh_never_reached", "refresh_not_reached")):
            with self.subTest(mode=mode, fault=fault), tempfile.TemporaryDirectory() as directory:
                result = DriverHarness(directory, fault).case(mode)
                self.assertFalse(result["success"])
                self.assertEqual(result["errors"], [cause])

    def test_wrong_config_payload_or_denial_binding_never_passes(self):
        for mode, fault, cause in (("positive", "mutated_option", "non_token_config_changed"),
                ("positive", "wrong_expiry", "token_expiry_unbound"), ("positive", "bad_payload", "acquisition_hash_mismatch"),
                ("refresh", "stale_replacement", "persisted_token_mismatch"),
                ("wrong_state", "denial_mutates_config", "failed_auth_config_changed"),
                ("refresh_denied", "denial_mutates_config", "credential_changed_unexpectedly"),
                ("refresh_denied", "denial_writes_payload", "negative_read_or_output"),
                ("refresh_denied", "denial_extra_input", "refresh_denial_result"),
                ("refresh_denied", "denial_wrong_path", "refresh_denial_result"),
                ("refresh_denied", "denial_wrong_status", "refresh_denial_result"),
                ("refresh_denied", "denial_launch_drift", "copy_request_mismatch"),
                ("refresh_denied", "wrong_denial_cause", "refresh_denial_result"),
                ("refresh_denied", "wrong_denial_origin", "refresh_denial_result"),
                ("invalid_code", "generic_denial", "expected_auth_denial_absent"),
                ("positive", "redirect_escape", "location_authority_mismatch")):
            with self.subTest(mode=mode, fault=fault), tempfile.TemporaryDirectory() as directory:
                h = DriverHarness(directory, fault)
                result = h.case(mode)
                self.assertFalse(result["success"], fault)
                self.assertEqual(result["errors"], [cause])
                self.assertTrue(all(result["cleanup"].values()))
                self.assertTrue(all(child.poll() is not None for child in h.processes.values()))
                self.assertFalse(any(h.work.iterdir()))

    def test_cleanup_uncertainty_retains_root_and_fails_even_after_valid_flow(self):
        for mode, fault in (("positive", "fixture_cleanup"), ("positive", "transport_error"),
                            ("positive", "listener_left"), ("callback_cancel", "unreaped")):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                h = DriverHarness(directory, fault)
                result = h.case(mode)
                self.assertFalse(result["success"])
                self.assertFalse(result["cleanup"]["temporary_removed"])
                self.assertTrue(any(h.work.iterdir()))


class DockerScript:
    """Daemon/CLI boundary with independent literal inspect responses."""
    def __init__(self, root, suite, fault=None):
        self.root, self.make_suite, self.fault = root, suite, fault
        self.commands_stopped, self.pending, self.build_phase, self.last_stderr = True, None, None, b""
        self.calls, self.images, self.containers = [], False, False
        self.image, self.container = "sha256:" + "b" * 64, "c" * 64
        self.run_id = "1" * 32
        self.name, self.tag = "triage-gcs-oauth-" + self.run_id, "triage-gcs-oauth-fixture:" + self.run_id
        self.lock = S.read_lock()
        self.source_digest = S.canonical_hash(S.source_hashes())
        self.started, self.name_inspections = False, 0

    def image_config(self):
        return {"Id": self.image, "Architecture": "amd64", "Os": "linux", "Config": {
            "Labels": {"org.openai.triage.fixture-id": self.run_id, "org.openai.triage.fixture-kind": "gcs-oauth-probe",
                       "org.openai.triage.fixture-source-sha256": self.source_digest},
            "User": "10001:10001", "Entrypoint": ["/opt/fixture/venv/bin/python"],
            "Cmd": ["/opt/fixture/scripts/provider-lab/gcs-oauth/probe.py", "--rclone", "/opt/fixture/rclone",
                    "--manifest", "/opt/fixture/rclone-version.env"], "WorkingDir": "/work",
            "Env": ["LANG=C.UTF-8", "HOME=/work"]}}

    def container_config(self, target):
        config = copy.deepcopy(self.image_config()["Config"])
        value = {"Id": self.container, "Image": self.image, "Config": config, "Mounts": [],
            "State": {"Running": False, "Status": "exited" if self.started else "created", "ExitCode": 0,
                      "OOMKilled": False, "Error": ""},
            "NetworkSettings": {"Networks": {"none": {}}},
            "HostConfig": {"NetworkMode": "none", "ReadonlyRootfs": True, "Privileged": False,
                "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges"], "CgroupnsMode": "private",
                "IpcMode": "private", "Init": True, "Memory": 536870912, "NanoCpus": 1000000000, "PidsLimit": 64,
                "Tmpfs": {"/work": "rw,nosuid,nodev,noexec,size=32m,mode=0700,uid=10001,gid=10001"}}}
        if self.fault == "unsafe_network":
            value["HostConfig"]["NetworkMode"] = "bridge"
        if self.fault == "wrong_container_identity" and self.started and target == self.container:
            value["Id"] = "d" * 64
        if self.fault == "cleanup_wrong_owner" and self.name_inspections == 2:
            value["Config"]["Labels"]["org.openai.triage.fixture-id"] = "2" * 32
        return value

    def inspect(self, kind, target):
        self.calls.append(("inspect", kind, target))
        if kind == "image" and target == self.lock["base_image"]:
            return {"Id": self.lock["base_config_digest"], "Architecture": "amd64", "Os": "linux"}
        if kind == "image":
            assert target in (self.image, self.tag)
            return self.image_config() if self.images else None
        assert kind == "container" and target in (self.name, self.container)
        if target == self.name:
            self.name_inspections += 1
        return self.container_config(target) if self.containers else None

    def run(self, args, **kwargs):
        self.calls.append(tuple(args))
        if args == ["info", "--format", "{{json .}}"]:
            if self.fault == "preflight_failed":
                raise S.SupervisorError("docker_operation_failed")
            return 0, b'{"OSType":"linux","Architecture":"amd64"}'
        if args[:2] == ["image", "pull"]:
            assert args == ["image", "pull", "--quiet", "--platform", "linux/amd64", self.lock["base_image"]]
            return 0, b""
        if args[0] == "build":
            assert args[args.index("--tag") + 1] == self.tag
            context = Path(args[-1])
            manifest = json.loads((context / "source-manifest.json").read_text())
            assert manifest == S.source_hashes()
            assert (context / "Dockerfile").read_bytes() == (ROOT / "Dockerfile").read_bytes()
            Path(args[args.index("--iidfile") + 1]).write_text(self.image, encoding="ascii")
            self.images = True
            self.build_phase = "manifest"
            return 0, b""
        if args[0] == "create":
            assert args[args.index("--network") + 1] == "none"
            assert args[args.index("--name") + 1] == self.name
            assert "--mount" not in args and "--publish" not in args
            self.containers = True
            return 0, self.container.encode()
        if args == ["start", "--attach", self.container]:
            assert kwargs == {"timeout": 360, "allow_failure": True, "output_limit": 262144}
            self.started = True
            suite = self.make_suite()
            if self.fault == "malformed_receipt":
                return 0, b'{"schema_version":1,"schema_version":1}'
            if self.fault == "mismatched_pin":
                suite["cases"][7]["report"]["runtime"]["rclone_sha256"] = "0" * 64
            elif self.fault == "omitted_case":
                suite["cases"].pop()
            elif self.fault == "omitted_refresh_check":
                del suite["cases"][7]["report"]["checks"]["replacement_persisted"]
            elif self.fault == "forged_cleanup":
                suite["cases"][-1]["report"]["cleanup"]["children_stopped"] = False
            elif self.fault == "qualified_receipt":
                suite["ledger_eligible"] = True
            elif self.fault == "secret_receipt_field":
                suite["cases"][0]["report"]["token"] = "synthetic-private-token"
            elif self.fault == "native_stderr":
                self.last_stderr = b"synthetic private output"
            return 0, (json.dumps(suite, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if args == ["rm", "--force", self.container]:
            if self.fault == "cleanup_unreaped":
                self.commands_stopped = False
                self.pending = {"child": object(), "identity": (1, 10001, 100)}
                raise S.SupervisorError("docker_command_reap_unproved")
            self.containers = False
            return 0, b""
        if args == ["image", "rm", self.image]:
            self.images = False
            return 0, b""
        raise AssertionError("unplanned daemon action")


class SupervisorOrchestrationTests(unittest.TestCase):
    def execute(self, directory, fault=None, lifecycle=False):
        base = Path(directory)
        child_base = base / "child"
        child_base.mkdir()
        driver = DriverHarness(child_base)
        root = base / "triage-gcs-oauth-synthetic"
        root.mkdir()
        docker = DockerScript(root, driver.suite, fault)
        identity = {"version": "1.75.1", "sha256": driver.sha}
        report_path = base / "report.json"
        with ExitStack() as stack:
            stack.enter_context(patch.dict(S.os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}))
            stack.enter_context(patch.object(S.sys, "platform", "linux"))
            stack.enter_context(patch.object(S, "utc_now", return_value=STAMP))
            stack.enter_context(patch.object(S, "runtime_identity", return_value=identity))
            stack.enter_context(patch.object(S.uuid, "uuid4", return_value=types.SimpleNamespace(hex="1" * 32)))
            stack.enter_context(patch.object(S, "Docker", return_value=docker))
            # Only the supervisor allocation is fixed. Inner driver allocations
            # use the real tempfile function in the generated test work root.
            original_mkdtemp = tempfile.mkdtemp
            stack.enter_context(patch.object(S.tempfile, "mkdtemp", side_effect=lambda *args, **kwargs:
                str(root) if kwargs.get("prefix") == "triage-gcs-oauth-" else original_mkdtemp(*args, **kwargs)))
            stack.enter_context(patch.object(socket, "socket", side_effect=AssertionError("real socket forbidden")))
            stack.enter_context(patch.object(subprocess, "Popen", side_effect=AssertionError("real process forbidden")))
            result = S.run(driver.binary, report_path, lifecycle=lifecycle)
        self.assertEqual(json.loads(report_path.read_text()), result)
        if not lifecycle:
            self.assertFalse(result["ledger_eligible"])
        return result, docker, root

    def test_explicit_qualification_runs_real_orchestration_and_preserves_failed_cleanup(self):
        for fault in (None, "preflight_failed", "unsafe_network", "cleanup_unreaped", "cleanup_wrong_owner", "native_stderr"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                result, docker, root = self.execute(directory, fault, lifecycle=True)
                self.assertEqual(result["schema_version"], 6)
                native = result["native_evidence"]
                self.assertEqual(native["scope"], "gcs_oauth_lifecycle_qualified_supervision")
                self.assertIs(native["ledger_eligible"], False)
                self.assertEqual(result["success"], fault is None)
                self.assertEqual(result["backends"][0]["capabilities"], dict.fromkeys(
                    ("authentication", "refresh", "renewal_denial", "cancellation_cleanup"),
                    "passed" if fault is None else "failed"))
                if fault in ("preflight_failed", "unsafe_network"):
                    self.assertIsNone(native["probe"])
                    self.assertFalse(docker.started)
                if fault in ("cleanup_unreaped", "cleanup_wrong_owner"):
                    self.assertTrue(root.exists())
                    self.assertFalse(result["cleanup_passed"])
                elif fault is None:
                    self.assertFalse(root.exists())
                    self.assertEqual(len(native["probe"]["cases"]), 10)
                    self.assertTrue(result["cleanup_passed"])
                self.assertNotIn("synthetic private output", json.dumps(result))

    def test_full_supervisor_runs_validated_ten_case_suite_then_owned_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            result, docker, root = self.execute(directory)
            self.assertTrue(result["success"], result["errors"])
            self.assertTrue(all(result["cleanup"].values()))
            self.assertEqual([row["name"] for row in result["probe"]["cases"]], list(CASES))
            self.assertEqual(result["stage"], "completed")
            self.assertFalse(root.exists())
            self.assertFalse(docker.images or docker.containers)
            self.assertIn(("rm", "--force", docker.container), docker.calls)
            self.assertIn(("image", "rm", docker.image), docker.calls)

    def test_malformed_mismatched_incomplete_or_qualified_receipt_never_passes(self):
        for fault, cause in (("malformed_receipt", "duplicate_json_key"), ("mismatched_pin", "probe_runtime_mismatch"),
                ("omitted_case", "suite_success_contradiction"), ("omitted_refresh_check", "probe_boolean_contract_invalid"),
                ("forged_cleanup", "probe_success_contradiction"), ("qualified_receipt", "suite_scope_mismatch"),
                ("secret_receipt_field", "probe_schema_mismatch"), ("native_stderr", "oauth_probe_failed")):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                result, docker, root = self.execute(directory, fault)
                self.assertFalse(result["success"])
                self.assertEqual(result["errors"], [cause])
                self.assertTrue(all(result["cleanup"].values()))
                self.assertFalse(root.exists())
                self.assertNotIn("synthetic-private-token", json.dumps(result))
                self.assertNotIn("synthetic private output", json.dumps(result))

    def test_isolation_and_identity_mismatch_stop_before_qualification(self):
        for fault in ("unsafe_network", "wrong_container_identity"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                result, docker, _ = self.execute(directory, fault)
                self.assertFalse(result["success"])
                self.assertEqual(result["errors"], ["container_isolation_mismatch" if fault == "unsafe_network" else "container_final_state_invalid"])
                if fault == "unsafe_network":
                    self.assertFalse(docker.started)

    def test_unreaped_cleanup_or_changed_owner_retains_source_context(self):
        for fault in ("cleanup_unreaped", "cleanup_wrong_owner"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                result, docker, root = self.execute(directory, fault)
                self.assertFalse(result["success"])
                self.assertFalse(result["cleanup"]["temporary_removed"])
                self.assertTrue(root.exists())
                if fault == "cleanup_unreaped":
                    self.assertFalse(result["cleanup"]["commands_stopped"])
                else:
                    self.assertNotIn(("rm", "--force", docker.container), docker.calls)
                self.assertNotIn(("image", "rm", docker.image), docker.calls)


if __name__ == "__main__":
    unittest.main()
