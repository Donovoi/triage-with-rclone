"""Independent finite probe transcript; no Docker, Java, rclone or network.

The fake implements only the reviewed Docker.call boundary (including its
nonzero-exit handling). All acquisition bytes, JSON and process observations
come from synthetic literals, not the producer's sample/oracle helpers.
"""
from contextlib import ExitStack
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import container_fixture as F


CONTAINER = "4" * 64
PRIVATE = b"PRIVATE_SYNTHETIC_DIAGNOSTIC_CANARY"
CONFIG_HASH = "c" * 64
SAMPLES = {
    "README.txt": b"HDFS synthetic fixture\n",
    "empty.bin": b"",
    "large/cancel.bin": bytes(range(256)) * 8192,
    "nested/alpha.txt": b"alpha\n",
    "nested/deeper/data.bin": bytes(range(256)),
    "nested/space name.txt": b"space name\n",
    "private/owner-only.txt": b"private synthetic bytes\n",
    "unicode/utf8.txt": b"caf\xc3\xa9\n",
}
PORTS = {"namenode_rpc": 19000, "datanode_data": 19001, "datanode_ipc": 19002,
         "namenode_http": 19003, "datanode_http": 19004, "datanode_internal_http": 19005}
CHECKS = {"listing", "modification_times", "download_hash", "wrong_expected_hash_rejection",
          "missing_source_path_rejection", "simple_permission_denial", "cancellation",
          "cancelled_child_stopped", "partial_download_removed", "source_preservation",
          "configuration_preservation", "java_exited", "listeners_closed"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("ascii")


def oracle(phase):
    return {
        "schema_version": 1, "scope": "hdfs_simple_fixture", "phase": phase,
        "ledger_eligible": False, "authentication_verified": False,
        "authentication_mode": "SIMPLE", "success": True, "source_preserved": True,
        "configuration_preserved": True, "api_shutdown_complete": phase == "final",
        "owner": "fixture-owner", "root": "/synthetic", "mtime_ms": 1704067200000,
        "ports": PORTS.copy(), "configuration_sha256": CONFIG_HASH, "errors": [],
        "files": [{"path": path, "size": len(data), "sha256": sha(data),
                   "mode": "0600" if path == "private/owner-only.txt" else "0644"}
                  for path, data in sorted(SAMPLES.items())],
    }


def listeners(ports):
    header = b"  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
    rows = [f" {i}: 0100007F:{port:04X} 00000000:0000 0A 0 0 0 0 0 0\n".encode("ascii")
            for i, port in enumerate(ports)]
    # cat emits the second table's header even when it has no entries.
    return header + b"".join(rows) + header


def transcript():
    rows = [("ready", 0, encode(oracle("ready")), b""),
            ("initial_listeners", 0, listeners(range(19000, 19006)), b""),
            ("version", 0, b"rclone v1.75.1\nos/version: synthetic\n", b""),
            ("listing", 0, encode([{"Path": path, "Size": len(data), "IsDir": False,
                                    "ModTime": "2024-01-01T00:00:00Z"}
                                    for path, data in SAMPLES.items()]), b"")]
    rows.extend(("read:" + path, 0, data, b"") for path, data in sorted(SAMPLES.items()))
    rows.extend([
        ("missing", 3, b"", b"Failed to create file system: directory not found\n"),
        ("denied", 1, b"", b"failed to open source object: Permission denied\n"),
        ("cancel", 0, b"124 65536\n", PRIVATE),
        ("no_child", 0, b"", b""),
        ("remove_partial", 0, b"", b""),
        ("shutdown", 0, b"", b""),
        ("java_exit", 0, b"0\n", b""),
        ("final", 0, encode(oracle("final")), b""),
        ("final_listeners", 0, listeners([]), b""),
        ("exit", 0, b"", b""),
        ("wait", 0, b"0\n", b""),
    ])
    return rows


class TranscriptDocker:
    def __init__(self, test, root, changes=None):
        self.test, self.root = test, root
        self.rows = transcript()
        self.calls = []
        for label, changed in (changes or {}).items():
            index = next(i for i, row in enumerate(self.rows) if row[0] == label)
            old = self.rows[index]
            self.rows[index] = (label, *changed(old[1:])) if callable(changed) else (label, *changed)

    def assert_rclone(self, args, verb, path, user="fixture-owner"):
        self.test.assertEqual(args[:2], ["/usr/bin/env", "-i"])
        self.test.assertIn("/opt/hdfs/rclone", args)
        self.test.assertEqual(args[args.index("--config") + 1], "/dev/null")
        self.test.assertEqual(args[args.index("--hdfs-namenode") + 1], "127.0.0.1:19000")
        self.test.assertEqual(args[args.index("--hdfs-username") + 1], user)
        index = args.index(verb)
        self.test.assertEqual(args[index + 1], ":hdfs:/synthetic" + ("/" + path if path else ""))
        self.test.assertNotIn("--hdfs-service-principal-name", args)

    def call(self, args, **kwargs):
        self.test.assertLess(len(self.calls), len(self.rows), "unexpected extra Docker call")
        label, code, data, error = self.rows[len(self.calls)]
        self.calls.append((label, list(args), dict(kwargs)))
        if label == "wait":
            self.test.assertEqual(args, ["wait", CONTAINER])
        else:
            self.test.assertEqual(args[:2], ["exec", CONTAINER])
            command = args[2:]
            if label in {"ready", "java_exit"}:
                self.test.assertEqual(command[:2], ["/bin/sh", "-c"])
                path = "/work/output/ready.json" if label == "ready" else "/work/java-exit"
                self.test.assertIn("cat " + path, command[2])
                self.test.assertIn("while", command[2])
            elif label in {"initial_listeners", "final_listeners"}:
                self.test.assertEqual(command, ["/bin/cat", "/proc/net/tcp", "/proc/net/tcp6"])
            elif label == "version":
                self.test.assertEqual(command, ["/usr/bin/env", "-i", "/opt/hdfs/rclone", "version"])
            elif label == "listing":
                self.assert_rclone(command, "lsjson", "")
                self.test.assertEqual(command[-2:], ["--recursive", "--files-only"])
            elif label.startswith("read:"):
                self.assert_rclone(command, "cat", label[5:])
                self.test.assertEqual(kwargs["limit"], max(1, len(SAMPLES[label[5:]]) + 1))
            elif label == "missing":
                self.assert_rclone(command, "cat", "missing-synthetic-file")
            elif label == "denied":
                self.assert_rclone(command, "cat", "private/owner-only.txt", user="fixture-other")
            elif label == "cancel":
                self.test.assertEqual(command[:2], ["/bin/sh", "-c"])
                self.test.assertEqual(command[3], "hdfs-cancel")
                for fragment in ('/usr/bin/timeout --signal=INT --kill-after=3s 8s "$@"',
                                 'child=$!', 'wait "$child"', 'observed=$size',
                                 'printf \'%s %s\\n\' "$code" "$observed"'):
                    self.test.assertIn(fragment, command[2])
                self.assert_rclone(command[4:], "copyto", "large/cancel.bin")
                self.test.assertEqual(command[-6:], ["/work/download/cancel.bin", "--inplace", "--buffer-size", "0", "--bwlimit", "32k"])
                self.test.assertEqual(kwargs["timeout"], 16)
                self.test.assertEqual(kwargs["limit"], 128)
            elif label == "no_child":
                self.test.assertEqual(command[:2], ["/bin/sh", "-c"])
                self.test.assertIn('/proc/[0-9]*/comm', command[2])
                self.test.assertIn('!= rclone ] || exit 1', command[2])
            elif label == "remove_partial":
                self.test.assertEqual(command, ["/bin/rm", "-f", "--", "/work/download/cancel.bin"])
            elif label == "shutdown":
                self.test.assertEqual(command, ["/bin/sh", "-c", "set -eu; test ! -e /work/download/cancel.bin; set -C; printf 'shutdown\\n' > /work/shutdown"])
            elif label == "final":
                self.test.assertEqual(command, ["/bin/cat", "/work/output/final.json"])
            elif label == "exit":
                self.test.assertEqual(command, ["/bin/sh", "-c", "set -C; printf 'exit\\n' > /work/exit"])
            else:
                raise AssertionError("unreviewed mock command")
        if label in {"missing", "denied"}:
            self.test.assertIs(kwargs.get("allow_failure"), True)
        elif kwargs.get("allow_failure"):
            raise AssertionError("unexpected failure allowance")
        out = self.root / f"{len(self.calls):02}.out"
        err = self.root / f"{len(self.calls):02}.err"
        out.write_bytes(data); err.write_bytes(error)
        if code != 0 and not kwargs.get("allow_failure", False):
            raise F.D.DiscoveryError("command_failed")
        return F.D.Result(code, out, err)


class ProbeContractTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.stack.enter_context(patch.object(F, "RCLONE_VERSION", "1.75.1"))
        self.stack.enter_context(patch.object(F.D.subprocess, "Popen", side_effect=AssertionError("native forbidden")))
        self.stack.enter_context(patch.object(F.urllib.request, "build_opener", side_effect=AssertionError("network forbidden")))
        self.index = 0

    def run_probe(self, changes=None):
        self.index += 1
        root = self.root / str(self.index); root.mkdir()
        fake = TranscriptDocker(self, root, changes)
        return fake, lambda: F.probe(fake, CONTAINER)

    def reject(self, changes, code, last):
        fake, invoke = self.run_probe(changes)
        with self.assertRaises((F.FixtureError, F.D.DiscoveryError)) as raised:
            invoke()
        self.assertEqual(raised.exception.code, code)
        self.assertNotIn(PRIVATE.decode(), str(raised.exception))
        self.assertEqual(fake.calls[-1][0], last)
        self.assertNotIn("wait", [row[0] for row in fake.calls])

    def test_success_consumes_complete_independent_transcript(self):
        fake, invoke = self.run_probe()
        result = invoke()
        self.assertEqual(len(fake.calls), 23)
        self.assertEqual([row[0] for row in fake.calls], [row[0] for row in transcript()])
        self.assertEqual(result["checks"], dict.fromkeys(CHECKS, True))
        self.assertEqual(result["samples"], [{"path": path, "size": len(data), "sha256": sha(data)}
                                              for path, data in sorted(SAMPLES.items())])
        self.assertEqual(result["configuration_sha256"], CONFIG_HASH)
        self.assertEqual(result["listeners"], list(range(19000, 19006)))
        self.assertNotIn(PRIVATE.decode(), json.dumps(result))
        self.assertNotIn("authentication_rejection", result["checks"])

    def test_wrong_sample_bytes_same_length_reject_before_negative_cases(self):
        self.reject({"read:README.txt": (0, b"XDFS synthetic fixture\n", b"")}, "sample_mismatch", "read:README.txt")

    def test_short_extra_and_nonempty_empty_file_reject(self):
        for label, data in [("read:README.txt", b"HDFS"),
                            ("read:README.txt", SAMPLES["README.txt"] + b"x"),
                            ("read:empty.bin", b"x")]:
            with self.subTest(label=label, size=len(data)):
                self.reject({label: (0, data, b"")}, "sample_mismatch", label)

    def test_missing_timeout_permission_or_stdout_never_counts(self):
        for code, data, error in [(1, b"", b"i/o timeout"), (1, b"", b"permission denied"),
                                  (3, b"unexpected", b"object not found"), (0, b"", b"directory not found")]:
            with self.subTest(code=code, data=bool(data), error=error):
                self.reject({"missing": (code, data, error)}, "negative_case_failed", "missing")

    def test_permission_denial_requires_error_no_stdout_and_nonzero(self):
        for code, data, error in [(1, b"private bytes", b"Permission denied"),
                                  (0, b"", b"Permission denied"), (1, b"", b"object not found"),
                                  (1, b"", b"timeout")]:
            with self.subTest(code=code, data=bool(data), error=error):
                self.reject({"denied": (code, data, error)}, "negative_case_failed", "denied")

    def test_wrong_cancel_exit_is_not_cancellation(self):
        for code in (0, 1, 137, 143):
            with self.subTest(code=code):
                self.reject({"cancel": (0, f"{code} 65536\n".encode(), PRIVATE)}, "negative_case_failed", "cancel")
        self.reject({"cancel": (1, b"124 65536\n", PRIVATE)}, "command_failed", "cancel")

    def test_cancel_requires_real_bounded_partial(self):
        for data in (b"124 0\n", b"124 2097152\n", b"124 2097153\n", b"124 -1\n",
                     b"124 65536", b"124 not a size\n", b"124 65536\nextra\n"):
            with self.subTest(data=data):
                self.reject({"cancel": (0, data, b"")}, "negative_case_failed", "cancel")

    def test_lingering_cancelled_child_and_failed_partial_removal_stop_sequence(self):
        for label in ("no_child", "remove_partial", "shutdown"):
            with self.subTest(label=label):
                self.reject({label: (1, b"", PRIVATE)}, "command_failed", label)

    def test_changed_final_source_and_config_cannot_pass(self):
        for mutate in (lambda value: value.update(source_preserved=False),
                       lambda value: value.update(configuration_preserved=False),
                       lambda value: value.update(configuration_sha256="d" * 64),
                       lambda value: value["files"][0].update(sha256="0" * 64),
                       lambda value: value.update(api_shutdown_complete=False)):
            changed = oracle("final"); mutate(changed)
            self.reject({"final": (0, encode(changed), b"")}, "oracle_invalid", "final")

    def test_failed_java_exit_blocks_final_success_oracle(self):
        for data in (b"1\n", b"124\n", b"0", b"0\nextra\n"):
            with self.subTest(data=data):
                self.reject({"java_exit": (0, data, b"")}, "shutdown_failed", "java_exit")

    def test_lingering_listener_after_final_oracle_rejects(self):
        self.reject({"final_listeners": (0, listeners([19004]), b"")}, "shutdown_failed", "final_listeners")

    def test_initial_extra_or_wildcard_listener_rejects(self):
        self.reject({"initial_listeners": (0, listeners(range(19000, 19007)), b"")}, "listeners_invalid", "initial_listeners")
        self.reject({"initial_listeners": (0, listeners(range(19000, 19006)).replace(b"0100007F", b"00000000"), b"")},
                    "listeners_invalid", "initial_listeners")

    def test_malformed_listing_cannot_substitute_for_complete_inventory(self):
        listing = [{"Path": path, "Size": len(data), "IsDir": False,
                    "ModTime": "2024-01-01T00:00:00Z"} for path, data in SAMPLES.items()]
        for mutate in (lambda value: value.pop(),
                       lambda value: value.__setitem__(1, copy.deepcopy(value[0])),
                       lambda value: value[0].update(Size=True),
                       lambda value: value[0].update(Path="../outside"),
                       lambda value: value[0].update(IsDir=True)):
            changed = copy.deepcopy(listing); mutate(changed)
            self.reject({"listing": (0, encode(changed), b"")}, "listing_invalid", "listing")

    def test_wrong_naive_or_truncated_precision_modtime_rejects(self):
        for stamp in ("2024-01-02T00:00:00Z", "2024-01-01T00:00:00", "2024-01-01T00:00:00.000000001Z",
                      "2024-01-01 00:00:00Z", "2024-01-01T00:00:00+11:00"):
            listing = [{"Path": path, "Size": len(data), "IsDir": False,
                        "ModTime": stamp} for path, data in SAMPLES.items()]
            with self.subTest(stamp=stamp):
                self.reject({"listing": (0, encode(listing), b"")}, "listing_invalid", "listing")

    def test_container_nonzero_exit_cannot_return_passed_probe(self):
        fake, invoke = self.run_probe({"wait": (0, b"1\n", b"")})
        with self.assertRaisesRegex(F.FixtureError, "shutdown_failed"):
            invoke()
        self.assertEqual(fake.calls[-1][0], "wait")


if __name__ == "__main__":
    unittest.main()
