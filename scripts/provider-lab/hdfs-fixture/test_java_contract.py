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
        # Eight seconds at32KiB/s cannot finish the2MiB cancellation payload.
        self.assertGreater(len(actual["large/cancel.bin"]), 8 * 32768)

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
        self.assertIn('closed = false; recordFailure(errors, "datanode_shutdown_failed", failure)', self.source)
        self.assertIn('closed = false; recordFailure(errors, "namenode_shutdown_failed", failure)', self.source)
        self.assertIn('api_shutdown_complete', self.source)
        self.assertIn('parent must enforce a 240s JVM deadline', self.source)
        self.assertNotIn('"cleanup_passed"', self.source)

    def test_assertion_codes_are_closed_and_cover_every_require_literal(self):
        declaration = re.search(r'REQUIRE_CODES = Set\.of\((.*?)\);', self.source, re.S).group(1)
        codes = re.findall(r'"([a-z0-9_]+)"', declaration)
        self.assertEqual(len(codes), len(set(codes)))
        used = set(re.findall(r'require\(.*?"([a-z0-9_]+)"\);', self.source, re.S))
        self.assertEqual(set(codes), used)
        self.assertEqual(len(codes), 42)
        for canary in ("PRIVATE_SYNTHETIC_CANARY", "/private/synthetic/file", "source_scope extra",
                       "prefix_source_scope", "source_scope\n", "unclassified"):
            self.assertNotIn(canary, codes)
        self.assertIn('throw new FixtureFailure(code)', self.source)
        self.assertIn('REQUIRE_CODES.contains(code) ? code : "unclassified"', self.source)

    def test_throwable_classes_map_only_to_finite_categories(self):
        reason = self.source[self.source.index('private static String failureReason('):
                             self.source.index('private static void recordFailure(')]
        self.assertEqual(set(re.findall(r'"([a-z_]+)"', reason)),
                         {"unclassified", "missing_class", "resource_failure", "invalid_config",
                          "linkage_failure", "file_missing", "http_webapp_missing", "io_failure",
                          "exit_requested", "halt_requested"})
        expected = {
            "ClassNotFoundException || current instanceof NoClassDefFoundError": ("missing_class", "0"),
            "OutOfMemoryError || current instanceof StackOverflowError": ("resource_failure", "1"),
            "IllegalArgumentException": ("invalid_config", "2"),
            "LinkageError": ("linkage_failure", "3"),
            "FileNotFoundException": ("file_missing", "4"),
            "IOException": ("io_failure", "5"),
        }
        actual = {types: (category, rank) for types, category, rank in re.findall(
            r'if \(current instanceof ([^\n]+?)\) \{\s+category = "([a-z_]+)"; rank = ([0-9]+);', reason)}
        self.assertEqual(actual, expected)
        self.assertIn('if (rank < selectedRank)', reason)

    def test_webapp_marker_is_exact_subtype_gated_bounded_and_private(self):
        marker = self.source[self.source.index('private static boolean missingWebAppResource('):
                             self.source.index('private static String failureReason(')]
        self.assertIn('missingWebAppResource(FileNotFoundException failure)', marker)
        self.assertIn('i < frames.length && i < 32', marker)
        self.assertEqual(re.findall(r'getClassName\(\)\.equals\("([^"]+)"\)', marker),
                         ['org.apache.hadoop.http.HttpServer2'])
        self.assertEqual(re.findall(r'getMethodName\(\)\.equals\("([^"]+)"\)', marker),
                         ['getWebAppsPath'])
        self.assertIn('&& frames[i].getMethodName()', marker)
        self.assertIn('catch (Throwable ignored) { return false; }', marker)
        self.assertEqual(self.source.count('missingWebAppResource((FileNotFoundException) current)'), 1)
        reason = self.source[self.source.index('private static String failureReason('):
                             self.source.index('private static void recordFailure(')]
        subtype = reason[reason.index('current instanceof FileNotFoundException'):
                         reason.index('current instanceof IOException')]
        self.assertIn('category = "file_missing"', subtype)
        self.assertIn('if (missingWebAppResource((FileNotFoundException) current)) category = "http_webapp_missing"', subtype)
        for forbidden in ('.getMessage(', '.toString(', '.getFileName(', '.getLineNumber(',
                          '.startsWith(', '.contains(', 'System.out', 'errors.add('):
            self.assertNotIn(forbidden, marker)

    def test_startup_stages_bind_exact_api_boundaries_without_configuration_changes(self):
        main = self.source[self.source.index('public static void main('):]
        startup = main[main.index('stage = "startup_failed"'):main.index('stage = "seed_failed"')]
        sections = re.split(r'stage = "([a-z_]+)";', startup)[1:]
        blocks = dict(zip(sections[::2], sections[1::2]))
        expected = ['startup_failed', 'format_failed', 'namenode_start_failed',
                    'datanode_start_failed', 'client_start_failed', 'readiness_failed']
        self.assertEqual(sections[::2], expected)
        self.assertIn('Configuration conf = configuration()', blocks['startup_failed'])
        self.assertIn('UserGroupInformation.setLoginUser(', blocks['startup_failed'])
        self.assertEqual(blocks['format_failed'].strip(), 'NameNode.format(conf);')
        self.assertEqual(blocks['namenode_start_failed'].strip(), 'nn = new NameNode(conf);')
        self.assertEqual(blocks['datanode_start_failed'].strip(),
                         'dn = DataNode.createDataNode(new String[0], conf);\n'
                         '      require(dn != null, "datanode_missing");')
        self.assertEqual(blocks['client_start_failed'].strip(),
                         'fs = new DistributedFileSystem(); fs.initialize(URI.create("hdfs://127.0.0.1:19000"), conf);')
        self.assertEqual(blocks['readiness_failed'].strip(), 'ready(nn, dn, fs);')
        self.assertIn('new HdfsConfiguration(false)', self.source)
        self.assertIn('conf.set("dfs.reformat.disabled", "true")', self.source)

    def test_webapp_scaffolding_has_independent_exact_five_file_oracle(self):
        resources = self.source[self.source.index('private static void verifyWebAppResources('):
                                self.source.index('private static Configuration configuration(')]
        descriptor = (b'<?xml version="1.0" encoding="UTF-8"?>\n'
                      b'<web-app xmlns="http://java.sun.com/xml/ns/j2ee" version="2.4"></web-app>\n')
        index = b'<!doctype html><title>Synthetic fixture</title><p>Protocol test only.</p>\n'
        payloads = {'hdfs/WEB-INF/web.xml': descriptor, 'datanode/WEB-INF/web.xml': descriptor,
                    'hdfs/index.html': index, 'datanode/index.html': index,
                    'static/fixture.txt': b'Protocol test resources only.\n'}
        rows = re.findall(r'"([^"]+)", new WebAppFile\(([0-9]+), "([0-9a-f]{64})"\)', resources)
        self.assertEqual(len(rows), 5)
        self.assertEqual({path: (int(size), digest) for path, size, digest in rows},
                         {path: (len(data), hashlib.sha256(data).hexdigest())
                          for path, data in payloads.items()})
        self.assertIn('Set.of("", "hdfs", "hdfs/WEB-INF", "datanode", "datanode/WEB-INF", "static")', resources)
        self.assertIn('foundFiles.equals(files.keySet()) && foundDirs.equals(directories)', resources)
        self.assertIn('Fixture-only scaffolding, not vendor UI', resources)

    def test_webapp_files_are_fixed_readonly_root_owned_no_links_and_bounded(self):
        resources = self.source[self.source.index('private static void verifyWebAppResources('):
                                self.source.index('private static Configuration configuration(')]
        for guard in ('Path.of("/opt/hdfs/classes/webapps")',
                      'ancestor = ancestor.getParent()', '!Files.isSymbolicLink(ancestor)',
                      'Files.isDirectory(ancestor, NOFOLLOW)', '!Files.isSymbolicLink(path)',
                      'Files.isRegularFile(path, NOFOLLOW)', 'Files.newInputStream(path, NOFOLLOW)',
                      'Files.getAttribute(path, "unix:uid", NOFOLLOW)).intValue() == 0',
                      'Files.getAttribute(path, "unix:gid", NOFOLLOW)).intValue() == 0',
                      'Files.getPosixFilePermissions(path, NOFOLLOW).equals(',
                      'directory ? "r-xr-xr-x" : "r--r--r--"', '++observed <= 11',
                      'pending.size() < 11', 'directories.contains(relative)',
                      'files.containsKey(relative)', 'Files.size(path) == expected.size()',
                      'input.readNBytes(4097)', 'bytes.length == expected.size()',
                      'sha256(bytes).equals(expected.sha256())'):
            self.assertIn(guard, resources)
        self.assertNotIn('Files.write', resources)
        self.assertNotIn('Files.create', resources)
        self.assertNotIn('setPosixFilePermissions', resources)

    def test_webapp_classloader_identity_and_safe_failure_before_startup(self):
        resources = self.source[self.source.index('private static void verifyWebAppResources('):
                                self.source.index('private static Configuration configuration(')]
        for guard in ('List.of("hdfs", "datanode", "static")',
                      'HdfsFixture.class.getClassLoader().getResource("webapps/" + name)',
                      'resource != null && resource.getProtocol().equals("file")',
                      'resource.getAuthority() == null || resource.getAuthority().isEmpty()',
                      'resource.getQuery() == null && resource.getRef() == null',
                      'Path.of(resource.toURI()).equals(root.resolve(name))'):
            self.assertIn(guard, resources)
        self.assertIn('catch (Exception ignored)', resources)
        self.assertIn('throw new FixtureFailure("webapp_resources_invalid")', resources)
        self.assertNotIn('.normalize()', resources)
        self.assertNotIn('.getMessage(', resources)
        main = self.source[self.source.index('public static void main('):]
        self.assertIn('environment(args);\n      stage = "webapp_resources_failed";\n'
                      '      verifyWebAppResources();\n      stage = "startup_failed";', main)
        self.assertLess(main.index('verifyWebAppResources()'), main.index('NameNode.format(conf)'))

    def test_cause_inspection_is_bounded_and_does_not_parse_private_messages(self):
        reason = self.source[self.source.index('private static String failureReason('):
                             self.source.index('private static void recordFailure(')]
        self.assertIn('current != null && depth < 8', reason)
        self.assertIn('current instanceof FixtureFailure own && REQUIRE_CODES.contains(own.code)', reason)
        self.assertIn('try { current = current.getCause(); }', reason)
        self.assertIn('catch (Throwable ignored) { return "unclassified"; }', reason)
        for forbidden in ('.getMessage(', '.getLocalizedMessage(', '.getClass(', '.toString(', '.getStackTrace('):
            self.assertNotIn(forbidden, reason)

    def test_diagnostics_preserve_primary_stage_and_cleanup_attempts(self):
        record = self.source[self.source.index('private static void recordFailure('):
                             self.source.index('private static void checkExitRequests(')]
        self.assertLess(record.index('errors.add(stage)'), record.index('failureReason(failure)'))
        self.assertIn('if (!errors.contains(reason)) errors.add(reason)', record)
        main = self.source[self.source.index('public static void main('):]
        self.assertIn('recordFailure(errors, stage, failure)', main)
        for stage in ('client_close_failed', 'datanode_shutdown_failed', 'namenode_shutdown_failed',
                      'termination_requested', 'final_report_failed'):
            self.assertIn('recordFailure(errors, "' + stage + '", failure)', main)
        self.assertNotIn('errors.clear()', main)

    def test_exit_interception_is_before_daemons_and_sticky_requests_fail(self):
        main = self.source[self.source.index('public static void main('):]
        for enable in ('ExitUtil.disableSystemExit()', 'ExitUtil.disableSystemHalt()'):
            self.assertLess(main.index(enable), main.index('NameNode.format(conf)'))
        self.assertIn('require(!ExitUtil.terminateCalled(), "exit_requested")', self.source)
        self.assertIn('require(!ExitUtil.haltCalled(), "halt_requested")', self.source)
        self.assertLess(main.index('checkExitRequests()'), main.index('publish("ready.json"'))
        self.assertLess(main.rindex('checkExitRequests()'), main.index('publish("final.json"'))
        self.assertNotIn('resetFirstExitException', self.source)
        self.assertNotIn('resetFirstHaltException', self.source)
        self.assertIn('if (!errors.isEmpty()) System.exit(1)', main)

    def test_java17_source_encoding_and_no_preview_constructs(self):
        self.assertNotIn(b"\r", self.raw)
        self.assertIn('compile with javac -proc:none', self.source)
        self.assertIn('Runtime.version().feature() == 17', self.source)
        self.assertNotIn('Thread.ofVirtual(', self.source)


if __name__ == "__main__":
    unittest.main()
