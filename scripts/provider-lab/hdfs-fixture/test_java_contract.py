"""Data/source contract tests only: these do not compile or execute Java/Hadoop.

The first hosted Java 17 compilation (-proc:none), API compatibility, daemon
startup, actual bindings and shutdown remain separate required native gates.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import unittest


SOURCE = Path(__file__).with_name("HdfsFixture.java")
EXPECTED = {
    "README.txt": (b"HDFS synthetic fixture\n", "9293366f2746b721a729318f2914a68c791d2689b950e8d5f406b0b008d09737"),
    "empty.bin": (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    "large/cancel.bin": (bytes(range(256)) * 8192, "91d3beb88a9b2f778a6c44a1c53b63d3c79931845a9aef84b3fb414610bd1938"),
    "nested/alpha.txt": (b"alpha\n", "b6a98d9ce9a2d9149288fa3df42d377c3e42737afdcdaf714e33c0a100b51060"),
    "nested/deeper/data.bin": (bytes(range(256)), "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880"),
    "nested/space name.txt": (b"space name\n", "446f72dd97ede3ad34e1f6b48da1bc18e84b2f86566c0ef38acf68e62b7386be"),
    "private/owner-only.txt": (b"private synthetic bytes\n", "f98e6b370c0c2c57791cabfeabef0fc0b8b8f05a5e687b74021eecf1ee4d6383"),
    "unicode/utf8.txt": (b"caf\xc3\xa9\n", "7b49b9e063bd91a4f9252b413261f5557b9c570aa61516989499f64a62dbcdd6"),
}


def declared_samples(source: str) -> dict[str, bytes]:
    """Interpret only the two closed literal forms used in samples(), not Java."""
    result = {}
    rows = re.findall(r'files\.put\("([^"\n]+)", (hex\("[0-9a-f]*"\)|sequence\([0-9]+\))\);', source)
    if len(rows) != 8 or source.count("files.put(") != 8:
        raise ValueError("sample_contract")
    for path, literal in rows:
        if path in result or path.startswith("/") or any(x in {"", ".", ".."} for x in path.split("/")):
            raise ValueError("sample_path")
        if literal.startswith("hex("):
            value = bytes.fromhex(literal[5:-2])
        else:
            length = int(literal[9:-1])
            if length not in {256, 2097152}:
                raise ValueError("sample_bound")
            value = bytes(range(256)) * (length // 256)
        result[path] = value
    return result


class JavaContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = SOURCE.read_bytes()
        cls.source = cls.raw.decode("ascii")

    def test_eight_independent_payloads_and_sha256_oracle(self):
        actual = declared_samples(self.source)
        self.assertEqual(set(actual), set(EXPECTED))
        for name, (value, digest) in EXPECTED.items():
            with self.subTest(name=name):
                self.assertEqual(actual[name], value)
                self.assertEqual(hashlib.sha256(actual[name]).hexdigest(), digest)
        self.assertEqual(sum(map(len, actual.values())), 2097478)

    def test_empty_and_real_cancellation_payload_are_distinct(self):
        actual = declared_samples(self.source)
        self.assertEqual(actual["empty.bin"], b"")
        self.assertEqual(len(actual["large/cancel.bin"]), 2 * 1024 * 1024)
        self.assertEqual(actual["large/cancel.bin"][:512], bytes(range(256)) * 2)
        # Four seconds at32KiB/s cannot finish the2MiB cancellation payload.
        self.assertGreater(len(actual["large/cancel.bin"]), 4 * 32768)

    def test_sample_parser_refuses_alias_duplicate_and_arbitrary_generator(self):
        for old, new in [("nested/alpha.txt", "nested/../alpha.txt"),
                         ("empty.bin", "README.txt"),
                         ("sequence(2097152)", "sequence(2097153)"),
                         ("sequence(256)", "remoteBytes()")]:
            with self.subTest(new=new), self.assertRaises(ValueError):
                declared_samples(self.source.replace(old, new))

    def test_exact_loopback_port_configuration_and_http_presence(self):
        config = dict(re.findall(r'conf\.set\("([^"\n]+)", "([^"\n]*)"\);', self.source))
        expected = {
            "fs.defaultFS": "hdfs://127.0.0.1:19000",
            "dfs.namenode.rpc-address": "127.0.0.1:19000",
            "dfs.namenode.rpc-bind-host": "127.0.0.1",
            "dfs.datanode.address": "127.0.0.1:19001",
            "dfs.datanode.ipc.address": "127.0.0.1:19002",
            "dfs.namenode.http-address": "127.0.0.1:19003",
            "dfs.namenode.http-bind-host": "127.0.0.1",
            "dfs.datanode.http.address": "127.0.0.1:19004",
            "dfs.datanode.http.internal-proxy.port": "19005",
            "dfs.http.policy": "HTTP_ONLY",
            "dfs.datanode.hostname": "127.0.0.1",
        }
        self.assertEqual({key: config[key] for key in expected}, expected)
        self.assertNotIn("dfs.webhdfs.enabled", config)
        self.assertIn('listeners().equals(PORTS)', self.source)
        self.assertIn('local[0].equals("0100007F")', self.source)
        self.assertIn('node.getIpAddr().equals("127.0.0.1")', self.source)
        self.assertIn('"java.net.preferIPv4Stack"', self.source)

    def test_simple_identity_cannot_claim_authentication_or_ledger_credit(self):
        self.assertIn('conf.set("hadoop.security.authentication", "simple")', self.source)
        self.assertIn('conf.set("dfs.permissions.enabled", "true")', self.source)
        self.assertIn('UserGroupInformation.createRemoteUser(OWNER)', self.source)
        self.assertIn('private static final String OWNER = "fixture-owner"', self.source)
        self.assertIn('path.equals("private/owner-only.txt") ? 0600 : 0644', self.source)
        self.assertIn(r'\"authentication_verified\":false', self.source)
        self.assertIn(r'\"ledger_eligible\":false', self.source)
        self.assertNotIn(r'\"authentication_verified\":true', self.source)

    def test_fresh_storage_and_actual_reformat_guard(self):
        self.assertIn('Files.createDirectory(path,', self.source)
        self.assertNotIn('Files.createDirectories(', self.source)
        self.assertIn('conf.set("dfs.reformat.disabled", "true")', self.source)
        self.assertNotIn('conf.set("dfs.namenode.reformat.disabled"', self.source)
        self.assertIn('new HdfsConfiguration(false)', self.source)
        for child in ("name", "edits", "data", "tmp", "http", "native"):
            self.assertIn('"' + child + '"', self.source)

    def test_no_forced_safemode_or_test_jars(self):
        self.assertIn('HdfsConstants.SafeModeAction.SAFEMODE_GET', self.source)
        self.assertNotIn('SAFEMODE_LEAVE', self.source)
        imports = re.findall(r'^import ([^;]+);', self.source, re.M)
        self.assertFalse(any(x.startswith(("org.junit", "org.mockito")) or "MiniDFS" in x for x in imports))
        self.assertIn('new NameNode(conf)', self.source)
        self.assertIn('DataNode.createDataNode(new String[0], conf)', self.source)

    def test_native_and_network_dependencies_are_not_silently_pruned(self):
        self.assertIn('System.setProperty("io.netty.native.workdir",', self.source)
        self.assertNotIn('System.loadLibrary(', self.source)
        self.assertNotIn('Runtime.getRuntime().exec(', self.source)
        self.assertNotIn('new ProcessBuilder(', self.source)
        self.assertNotIn('setAccessible(', self.source)
        self.assertIn('conf.set("dfs.client.read.shortcircuit", "false")', self.source)

    def test_source_oracle_checks_inventory_bytes_permissions_and_times(self):
        for guard in ['foundFiles.equals(files.keySet())', 'foundDirs.equals(expectedDirs)',
                      'child.getLen() == expected.length', 'child.getOwner().equals(OWNER)',
                      'child.getPermission().toShort() == mode(relative)',
                      'child.getModificationTime() == MTIME_MS', 'child.getAccessTime() == MTIME_MS',
                      'Arrays.equals(actual, expected)', 'sha256(actual).equals(sha256(expected))',
                      'child.getReplication() == 1', '!child.isSymlink()']:
            self.assertIn(guard, self.source)
        self.assertIn('input.readNBytes(expected.length + 1)', self.source)
        self.assertIn('files = new TreeMap<>()', self.source)

    def test_bounded_fixed_shutdown_file_and_preservation_before_close(self):
        self.assertIn('WORK.resolve("shutdown")', self.source)
        self.assertIn('Files.size(SHUTDOWN) == 9', self.source)
        self.assertIn('"shutdown\\n".getBytes(StandardCharsets.US_ASCII)', self.source)
        self.assertIn('System.nanoTime() < deadline', self.source)
        main = self.source[self.source.index('public static void main('):]
        self.assertLess(main.index('waitForShutdown(deadline)'), main.index('topology(nn, dn, fs); verifySource'))
        self.assertLess(main.index('verifySource(fs, files); preserved = true'), main.index('fs.close()'))
        self.assertLess(main.index('fs.close()'), main.index('dn.shutdown()'))
        self.assertLess(main.index('dn.shutdown()'), main.index('nn.stop()'))
        self.assertLess(main.index('nn.stop()'), main.index('publish("final.json"'))

    def test_reports_only_publish_complete_owned_create_new_files(self):
        publish = self.source[self.source.index('private static void publish('):self.source.index('private static void waitForShutdown(')]
        self.assertIn('outputIdentity.equals(Files.readAttributes', publish)
        self.assertIn('StandardOpenOption.CREATE_NEW', publish)
        self.assertIn('channel.force(true)', publish)
        self.assertIn('Files.move(pending, target);', publish)
        self.assertNotIn('StandardCopyOption.REPLACE_EXISTING', publish)
        self.assertLess(publish.index('channel.force(true)'), publish.index('Files.move('))
        self.assertIn('MAX_REPORT_BYTES = 16384', self.source)

    def test_static_failures_and_distinct_api_shutdown_boundary(self):
        self.assertNotIn('.printStackTrace(', self.source)
        self.assertNotIn('.getMessage()', self.source)
        self.assertNotIn('System.out.', self.source)
        self.assertIn('errors.add(stage)', self.source)
        self.assertIn('closed = false; errors.add("datanode_shutdown_failed")', self.source)
        self.assertIn('closed = false; errors.add("namenode_shutdown_failed")', self.source)
        self.assertIn('api_shutdown_complete', self.source)
        self.assertIn('parent must enforce a 240s JVM deadline', self.source)
        self.assertNotIn('"cleanup_passed"', self.source)

    def test_java17_source_encoding_and_no_preview_constructs(self):
        self.assertNotIn(b"\r", self.raw)
        self.assertIn('compile with javac -proc:none', self.source)
        self.assertIn('Runtime.version().feature() == 17', self.source)
        self.assertNotIn('Thread.ofVirtual(', self.source)


if __name__ == "__main__":
    unittest.main()
