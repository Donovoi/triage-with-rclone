/* Isolated ticket feasibility probe. Requires the reviewed hosted Linux
 * container, fixed Kerby 2.1.2 classpath, UID/GID10001, network=none,
 * -Djava.net.preferIPv4Stack=true, private /work tmpfs, and an outer watchdog/reap.
 * NameNode-only Kerberos RPC feasibility; no transfer/provider/application/vendor credit.
 * Ownership/cache/containment helpers adapted from the existing ticket probe.
 * HTTP is loopback-only SPNEGO scaffolding; no HTTP/TLS authentication claim.
 * API/source references: apache/directory-kerby tag kerby-all-2.1.2:
 * SimpleKdcServer; client/{KrbClientBase,request/KdcRequest};
 * server/{preauth/builtin/EncTsPreauth,request/AsRequest,request/TicketIssuer};
 * crypto/enc/KeKiEnc; ccache/{CredentialCache,CredCacheOutputStream,Credential}.
 */
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.net.Socket;
import java.net.ServerSocket;
import java.net.SocketTimeoutException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hdfs.HdfsConfiguration;
import org.apache.hadoop.hdfs.DistributedFileSystem;
import org.apache.hadoop.hdfs.server.namenode.NameNode;
import org.apache.hadoop.hdfs.protocol.HdfsConstants.SafeModeAction;
import org.apache.hadoop.fs.permission.FsPermission;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.util.ExitUtil;
import org.apache.hadoop.util.GcTimeMonitor;
import org.apache.hadoop.util.concurrent.SubjectInheritingThread;
import org.apache.hadoop.hdfs.server.common.Util;
import org.apache.hadoop.hdfs.web.URLConnectionFactory;
import org.apache.hadoop.ipc.protobuf.RpcHeaderProtos.RpcResponseHeaderProto;
import org.apache.hadoop.ipc.protobuf.RpcHeaderProtos.RpcResponseHeaderProto.RpcStatusProto;
import org.apache.hadoop.ipc.protobuf.RpcHeaderProtos.RpcResponseHeaderProto.RpcErrorCodeProto;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.NetworkInterface;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.kerby.KOptions;
import org.apache.hadoop.metrics2.MetricsException;
import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbClient;
import org.apache.kerby.kerberos.kerb.client.KrbConfig;
import org.apache.kerby.kerberos.kerb.client.KrbConfigKey;
import org.apache.kerby.kerberos.kerb.client.KrbKdcOption;
import org.apache.kerby.kerberos.kerb.client.KrbOption;
import org.apache.kerby.kerberos.kerb.server.KdcConfig;
import org.apache.kerby.kerberos.kerb.server.KdcConfigKey;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.apache.kerby.kerberos.kerb.ccache.CredentialCache;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;

public final class HdfsKerberosRpcProbe {
    private static final Path WORK = Path.of("/work");
    private static final Path ROOT = WORK.resolve("kerberos-rpc-probe");
    private static final Path CONF = ROOT.resolve("krb5.conf");
    private static final Path CACHE = ROOT.resolve("reader.ccache");
    private static final Path KEYTAB = ROOT.resolve("service.keytab");
    private static final Path HTTP_KEYTAB = ROOT.resolve("http.keytab");
    private static final String MEMBER = "/synthetic/empty";
    private static final String DENIAL = "SIMPLE authentication is not enabled.  Available:[TOKEN, KERBEROS]";
    private static final String EXCEPTION = "org.apache.hadoop.security.AccessControlException";
    private static final List<Process> CHILDREN = new ArrayList<>();
    private static Set<Long> processBaseline;
    private static String wireHex = "";
    private static String rcloneWireHex = "";
    private static Relay relay;
    private static String stage = "environment";
    private static long controlDeadline;
    private static NameNode namenode;
    private static DistributedFileSystem filesystem;
    private static UserGroupInformation owner;
    private static final List<UserGroupInformation> OWNERS = new java.util.concurrent.CopyOnWriteArrayList<>();
    private static String ownerPrincipal;
    private static InetSocketAddress endpoint;
    private static long memberMtime = -1, memberAtime = -1;
    private static String memberGroup, configurationDigest;
    private static String diagnosticCategory = "none", diagnosticOrigin = "none";
    private static final List<String> THREAD_CATEGORIES = List.of("probe_task", "jdk_process_reaper", "jdk_timer",
        "jdk_executor", "jdk_cleaner", "hadoop_metrics", "hadoop_rpc", "hadoop_fs", "hadoop_namenode",
        "hadoop_blockmanagement", "hadoop_util", "jetty", "kerby", "other");
    private static Map<String, Integer> remainingThreads;
    // These are first-observed intervals, never creation/ownership evidence.
    private static final List<String> THREAD_PHASES = List.of("kdc", "owner_login", "format", "namenode",
        "filesystem", "reader", "controls", "shutdown", "unattributed");
    private static final Map<Thread, String> THREAD_ORIGINS = new java.util.IdentityHashMap<>();
    private static final Set<String> OBSERVED_PHASES = new java.util.HashSet<>();
    private static boolean threadObservationIncomplete;
    private static Map<String, Integer> remainingThreadIntervals;
    private static Map<String, Map<String, Integer>> remainingThreadMatrix;
    private static final List<String> TIMER_KINDS = List.of("namenode_metrics", "rpc_idle", "snapshot_gc", "shell_timeout", "ssl_store", "unknown");
    private static Map<String, Integer> remainingTimerKinds;
    private enum OwnedCleanupState {
        not_attempted, observation_incomplete, services_not_stopped, scan_failed,
        missing, ambiguous, preexisting, unobserved, late, not_daemon, deadline,
        shutdown_failed, still_alive, terminated
    }
    private static OwnedCleanupState gcCleanup = OwnedCleanupState.not_attempted;
    private static OwnedCleanupState statisticsCleanup = OwnedCleanupState.not_attempted;
    private static OwnedCleanupState sslCleanup = OwnedCleanupState.not_attempted;
    private static OwnedCleanupState sslCaptureFailure = OwnedCleanupState.not_attempted;
    private static URLConnectionFactory formatSslFactory;
    private static Thread formatSslThread;
    private static final LinkOption NOFOLLOW = LinkOption.NOFOLLOW_LINKS;
    private static final int PORT = 19006, MAX_BYTES = 65536, LIFETIME_SECONDS = 120;
    private static final String CONF_PROPERTY = "java.security.krb5.conf";
    private static final AtomicBoolean BACKGROUND_FAILURE = new AtomicBoolean();
    private static final List<Thread> TASKS = new java.util.concurrent.CopyOnWriteArrayList<>();
    private static final Map<Path, FileState> OWNED_FILES = new LinkedHashMap<>();
    private static final Map<String, Boolean> CHECKS = new LinkedHashMap<>();
    private static final Map<String, Boolean> CLEANUP = new LinkedHashMap<>();
    private static Object workKey, rootKey;
    private static boolean rootCreated, rootOwned;
    private static long deadline;
    private static int observedLifetime, cacheBytes;

    private enum Code {
        environment_invalid, path_invalid, source_changed, unexpected_files,
        listener_mismatch, configuration_invalid, deadline_exceeded,
        positive_ticket_failed, wrong_password_failure_mismatch, wrong_principal_not_rejected,
        cache_invalid, ticket_time_mismatch, ticket_flags_mismatch,
        background_failure, io_failure, krb_failure, interrupted, unclassified,
        cleanup_failed, namenode_failed, child_failed, child_output_invalid, wire_invalid,
        rclone_positive_failed, rclone_denial_mismatch, rclone_denial_exit_zero, rclone_denial_output_invalid,
        source_invalid, relay_invalid,
        child_descendant_found, child_reap_failed, child_streams_alive, child_process_drift,
        rclone_version_nonzero, rclone_version_stderr, rclone_version_mismatch
    }
    private static final class Failure extends Exception {
        final Code code;
        Failure(Code value) { super(value.name()); code = value; }
        Failure(Code value, Throwable cause) { super(value.name(), cause); code = value; }
    }
    private static void need(boolean value, Code code) throws Failure {
        if (!value) throw new Failure(code);
    }
    private static byte[] readBound(Path path, int maximum) throws Exception {
        try (var in = Files.newInputStream(path, NOFOLLOW)) {
            byte[] bytes = in.readNBytes(maximum + 1);
            need(bytes.length <= maximum, Code.path_invalid);
            return bytes;
        }
    }
    private static Object directory(Path path, boolean privateOwner) throws Exception {
        BasicFileAttributes a = Files.readAttributes(path, BasicFileAttributes.class, NOFOLLOW);
        need(a.isDirectory() && !a.isSymbolicLink() && a.fileKey() != null, Code.path_invalid);
        if (privateOwner) {
            need(((Number) Files.getAttribute(path, "unix:uid", NOFOLLOW)).intValue() == 10001
                && ((Number) Files.getAttribute(path, "unix:gid", NOFOLLOW)).intValue() == 10001
                && (((Number) Files.getAttribute(path, "unix:mode", NOFOLLOW)).intValue() & 07777) == 0700,
                Code.path_invalid);
        }
        return a.fileKey();
    }
    private static void guardRoot() throws Exception {
        need(workKey.equals(directory(WORK, true)) && rootKey.equals(directory(ROOT, true)), Code.source_changed);
    }
    private static final class FileState {
        final Object key;
        final byte[] digest;
        final int size;
        FileState(Path path) throws Exception {
            BasicFileAttributes a = Files.readAttributes(path, BasicFileAttributes.class, NOFOLLOW);
            need(a.isRegularFile() && !a.isSymbolicLink() && a.fileKey() != null && a.size() <= MAX_BYTES
                && ((Number) Files.getAttribute(path, "unix:nlink", NOFOLLOW)).intValue() == 1
                && ((Number) Files.getAttribute(path, "unix:uid", NOFOLLOW)).intValue() == 10001
                && (((Number) Files.getAttribute(path, "unix:mode", NOFOLLOW)).intValue() & 07777) == 0600,
                Code.path_invalid);
            key = a.fileKey();
            byte[] bytes = readBound(path, MAX_BYTES); size = bytes.length;
            digest = MessageDigest.getInstance("SHA-256").digest(bytes);
            Arrays.fill(bytes, (byte) 0);
            BasicFileAttributes b = Files.readAttributes(path, BasicFileAttributes.class, NOFOLLOW);
            need(key.equals(b.fileKey()) && a.size() == size && b.size() == size
                && a.lastModifiedTime().equals(b.lastModifiedTime()), Code.source_changed);
        }
        void verify(Path path) throws Exception {
            FileState current = new FileState(path);
            need(key.equals(current.key) && size == current.size
                && MessageDigest.isEqual(digest, current.digest), Code.source_changed);
        }
    }
    private static void inventory() throws Exception {
        guardRoot();
        Set<Path> actual = new HashSet<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(ROOT)) {
            for (Path path : stream) { need(actual.size() < 4, Code.unexpected_files); actual.add(path); }
        }
        need(actual.equals(OWNED_FILES.keySet()), Code.unexpected_files);
        for (var entry : OWNED_FILES.entrySet()) entry.getValue().verify(entry.getKey());
    }
    private static void environment(String[] args) throws Exception {
        need(args.length == 0 && "Linux".equals(System.getProperty("os.name"))
            && "true".equals(System.getProperty("java.net.preferIPv4Stack")), Code.environment_invalid);
        for (String key : List.of("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "KRB5_CONFIG",
                "KRB5CCNAME", "KRB5_KTNAME")) need(System.getenv(key) == null, Code.environment_invalid);
        need(System.getProperty(CONF_PROPERTY) == null, Code.environment_invalid);
        String status = new String(readBound(Path.of("/proc/self/status"), MAX_BYTES), StandardCharsets.US_ASCII);
        Map<String, String> fields = new LinkedHashMap<>();
        for (String line : status.split("\n")) {
            int colon = line.indexOf(':');
            if (colon > 0) fields.put(line.substring(0, colon), line.substring(colon + 1).trim());
        }
        for (String key : List.of("Uid", "Gid")) need("10001 10001 10001 10001".equals(
            fields.getOrDefault(key, "").replaceAll("\\s+", " ")), Code.environment_invalid);
        for (String key : List.of("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
            need(fields.getOrDefault(key, "").matches("0{16}"), Code.environment_invalid);
        need("1".equals(fields.get("NoNewPrivs")) && "2".equals(fields.get("Seccomp")), Code.environment_invalid);
        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces(); int count = 0;
        while (interfaces.hasMoreElements()) {
            NetworkInterface iface = interfaces.nextElement(); count++;
            need("lo".equals(iface.getName()) && iface.isLoopback(), Code.environment_invalid);
            var addresses = iface.getInetAddresses();
            while (addresses.hasMoreElements()) need(addresses.nextElement().isLoopbackAddress(), Code.environment_invalid);
        }
        need(count == 1, Code.environment_invalid);
        directory(Path.of("/"), false); workKey = directory(WORK, true);
        listeners(false);
    }
    private static void listeners(boolean running) throws Exception {
        Set<String> found = new HashSet<>();
        for (String table : List.of("tcp", "tcp6", "udp", "udp6")) {
            String data = new String(readBound(Path.of("/proc/net/" + table), MAX_BYTES), StandardCharsets.US_ASCII);
            String[] lines = data.split("\n"); need(lines.length <= 128, Code.listener_mismatch);
            for (int i = 1; i < lines.length; i++) {
                String[] fields = lines[i].trim().split("\\s+");
                need(fields.length >= 4, Code.listener_mismatch);
                if (table.startsWith("udp") || fields[3].equals("0A"))
                    need(found.add(table + ":" + fields[1]), Code.listener_mismatch);
            }
        }
        Set<String> expected = new HashSet<>();
        if (running) {
            expected.add("tcp:0100007F:4A3E");
            if (namenode != null) expected.addAll(Set.of("tcp:0100007F:4A38", "tcp:0100007F:4A3B"));
            if (relay != null) expected.add("tcp:0100007F:4A3F");
        }
        need(found.equals(expected), Code.listener_mismatch);
    }
    private static <T> T bounded(Callable<T> call, int seconds, long until) throws Exception {
        long remaining = Math.min(TimeUnit.SECONDS.toNanos(seconds), until - System.nanoTime());
        need(remaining > 0, Code.deadline_exceeded);
        FutureTask<T> task = new FutureTask<>(call);
        Thread thread = new Thread(task, "synthetic-ticket-task"); thread.setDaemon(true); TASKS.add(thread);
        thread.start();
        try { return task.get(remaining, TimeUnit.NANOSECONDS); }
        catch (TimeoutException e) { task.cancel(true); throw new Failure(Code.deadline_exceeded); }
        catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception) throw (Exception) cause;
            // Retain the cause only in memory for closed diagnostic projection.
            throw new Failure(Code.unclassified, cause);
        } finally { thread.join(200); }
    }
    private static String random(SecureRandom source, int count) {
        byte[] bytes = new byte[count]; source.nextBytes(bytes);
        String result = java.util.HexFormat.of().formatHex(bytes); Arrays.fill(bytes, (byte) 0); return result;
    }
    private static KOptions options(String principal, String password) {
        KOptions out = new KOptions();
        out.add(KrbOption.CLIENT_PRINCIPAL, principal); out.add(KrbOption.USE_PASSWD, true);
        out.add(KrbOption.USER_PASSWD, password); out.add(KrbOption.LIFE_TIME, LIFETIME_SECONDS);
        out.add(KrbOption.RENEWABLE_TIME, 0);
        out.add(KrbKdcOption.RENEWABLE, false); out.add(KrbKdcOption.RENEWABLE_OK, false);
        out.add(KrbKdcOption.FORWARDABLE, false); out.add(KrbKdcOption.PROXIABLE, false);
        return out;
    }
    private static final class LimitedBuffer extends ByteArrayOutputStream {
        @Override public synchronized void write(int value) {
            if (count >= MAX_BYTES) throw new IllegalStateException(); super.write(value);
        }
        @Override public synchronized void write(byte[] data, int offset, int length) {
            if (length < 0 || length > MAX_BYTES - count) throw new IllegalStateException();
            super.write(data, offset, length);
        }
        void erase() { Arrays.fill(buf, (byte) 0); reset(); }
    }
    private static int u16(ByteBuffer data) { return Short.toUnsignedInt(data.getShort()); }
    private static long u32(ByteBuffer data) { return Integer.toUnsignedLong(data.getInt()); }
    private static byte[] counted(ByteBuffer data, int limit) throws Exception {
        long length = u32(data); need(length <= limit && length <= data.remaining(), Code.cache_invalid);
        byte[] bytes = new byte[(int) length]; data.get(bytes); return bytes;
    }
    private static void principal(ByteBuffer data, String realm, List<String> components, int type) throws Exception {
        need(u32(data) == type && u32(data) == components.size(), Code.cache_invalid);
        need(Arrays.equals(counted(data, 256), realm.getBytes(StandardCharsets.US_ASCII)), Code.cache_invalid);
        for (String component : components)
            need(Arrays.equals(counted(data, 256), component.getBytes(StandardCharsets.US_ASCII)), Code.cache_invalid);
    }
    private static void inspectCache(byte[] bytes, String realm, String reader, long before, long after) throws Exception {
        // Independent minimal FILEv3 parser; no Kerby cache reader or service ticket.
        need(bytes.length > 100 && bytes.length <= MAX_BYTES, Code.cache_invalid);
        ByteBuffer data = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN);
        need(u16(data) == 0x0503, Code.cache_invalid);
        principal(data, realm, List.of(reader), 1); principal(data, realm, List.of(reader), 1);
        principal(data, realm, List.of("krbtgt", realm), 2);
        need(u16(data) == 17 && u16(data) == 17, Code.cache_invalid);
        byte[] key = counted(data, 32); need(key.length == 16, Code.cache_invalid); Arrays.fill(key, (byte) 0);
        long auth = u32(data), start = u32(data), end = u32(data), renew = u32(data);
        long effectiveStart = start == 0 ? auth : start;
        need(auth >= before && auth <= after && effectiveStart == auth && renew == 0
            && end >= before + LIFETIME_SECONDS && end <= after + LIFETIME_SECONDS
            && end - effectiveStart >= 110 && end - effectiveStart <= LIFETIME_SECONDS, Code.ticket_time_mismatch);
        observedLifetime = (int) (end - effectiveStart);
        need(Byte.toUnsignedInt(data.get()) == 0, Code.cache_invalid);
        long flags = u32(data);
        need(flags == 0x00600000L, Code.ticket_flags_mismatch); // INITIAL | PRE_AUTH only.
        need(u32(data) == 0 && u32(data) == 0, Code.cache_invalid); // no addresses/authdata
        need(counted(data, MAX_BYTES).length > 0 && counted(data, MAX_BYTES).length == 0
            && !data.hasRemaining(), Code.cache_invalid); // exactly one TGT
    }
    private static void publishCache(byte[] bytes) throws Exception {
        guardRoot();
        try (FileChannel channel = FileChannel.open(CACHE,
                Set.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW, NOFOLLOW),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) {
            ByteBuffer buffer = ByteBuffer.wrap(bytes); while (buffer.hasRemaining()) channel.write(buffer);
            channel.force(true);
        }
        OWNED_FILES.put(CACHE, new FileState(CACHE));
        need(MessageDigest.isEqual(OWNED_FILES.get(CACHE).digest,
            MessageDigest.getInstance("SHA-256").digest(bytes)), Code.source_changed);
        cacheBytes = bytes.length; inventory();
    }
    private static void constrainConfig(SimpleKdcServer server, KrbConfig clientConfig, String realm) throws Exception {
        server.setWorkDir(ROOT.toFile()); server.setKdcRealm(realm); server.setKdcHost("127.0.0.1");
        server.setKdcTcpPort(PORT); server.setAllowTcp(true); server.setAllowUdp(false);
        KdcConfig cfg = server.getKdcConfig();
        cfg.setBoolean(KdcConfigKey.KRB_DEBUG, false); cfg.setBoolean(KdcConfigKey.PREAUTH_REQUIRED, true);
        cfg.setBoolean(KdcConfigKey.PA_ENC_TIMESTAMP_REQUIRED, true); cfg.setBoolean(KdcConfigKey.ALLOW_TOKEN_PREAUTH, false);
        cfg.setBoolean(KdcConfigKey.EMPTY_ADDRESSES_ALLOWED, true); cfg.setBoolean(KdcConfigKey.RENEWABLE_ALLOWED, false);
        cfg.setBoolean(KdcConfigKey.FORWARDABLE_ALLOWED, false); cfg.setBoolean(KdcConfigKey.PROXIABLE_ALLOWED, false);
        cfg.setBoolean(KdcConfigKey.POSTDATED_ALLOWED, false);
        cfg.setLong(KdcConfigKey.ALLOWABLE_CLOCKSKEW, 5L);
        cfg.setLong(KdcConfigKey.MINIMUM_TICKET_LIFETIME, 1L);
        cfg.setLong(KdcConfigKey.MAXIMUM_TICKET_LIFETIME, 120L);
        cfg.setLong(KdcConfigKey.MAXIMUM_RENEWABLE_LIFETIME, 0L);
        cfg.setString(KdcConfigKey.ENCRYPTION_TYPES, "aes128-cts-hmac-sha1-96");
        clientConfig.setBoolean(KrbConfigKey.KRB_DEBUG, false);
        clientConfig.setBoolean(KrbConfigKey.DNS_LOOKUP_KDC, false); clientConfig.setBoolean(KrbConfigKey.DNS_LOOKUP_REALM, false);
        clientConfig.setBoolean(KrbConfigKey.ALLOW_WEAK_CRYPTO, false);
        clientConfig.setString(KrbConfigKey.PERMITTED_ENCTYPES, "aes128-cts-hmac-sha1-96");
        clientConfig.setString(KrbConfigKey.DEFAULT_TKT_ENCTYPES, "aes128-cts-hmac-sha1-96");
        clientConfig.setString(KrbConfigKey.DEFAULT_TGS_ENCTYPES, "aes128-cts-hmac-sha1-96");
        server.getKrbClient().setTimeout(5000); // Tagged KrbNetwork uses milliseconds, not seconds.
        need(server.getKdcSetting().allowTcp() && !server.getKdcSetting().allowUdp()
            && server.getKdcSetting().getKdcTcpPort() == PORT
            && "127.0.0.1".equals(server.getKdcSetting().getKdcHost()), Code.configuration_invalid);
    }
    private static void replaceGeneratedConfig(String realm) throws Exception {
        guardRoot();
        BasicFileAttributes before = Files.readAttributes(CONF, BasicFileAttributes.class, NOFOLLOW);
        need(before.isRegularFile() && !before.isSymbolicLink() && before.size() <= MAX_BYTES
            && ((Number) Files.getAttribute(CONF, "unix:nlink", NOFOLLOW)).intValue() == 1, Code.path_invalid);
        Files.setPosixFilePermissions(CONF, PosixFilePermissions.fromString("rw-------"));
        // SimpleKdcServer's template says localhost; replace only its owned file
        // before client init. No system config or environment is modified.
        String content = "[libdefaults]\n default_realm = " + realm
            + "\n dns_lookup_kdc = false\n dns_lookup_realm = false\n rdns = false\n udp_preference_limit = 1\n"
            + "[realms]\n " + realm + " = {\n  kdc = 127.0.0.1:19006\n }\n";
        try (FileChannel channel = FileChannel.open(CONF, StandardOpenOption.WRITE, NOFOLLOW)) {
            channel.truncate(0); ByteBuffer data = StandardCharsets.US_ASCII.encode(content);
            while (data.hasRemaining()) channel.write(data); channel.force(true);
        }
        OWNED_FILES.put(CONF, new FileState(CONF));
        need(before.fileKey().equals(OWNED_FILES.get(CONF).key)
            && CONF.toString().equals(System.getProperty(CONF_PROPERTY)), Code.source_changed);
        inventory();
    }
    private static Set<Long> threadIds() {
        Set<Long> ids = new HashSet<>();
        for (Thread thread : Thread.getAllStackTraces().keySet()) if (thread.isAlive()) ids.add(thread.getId());
        return ids;
    }
    private static String originFrame(StackTraceElement frame) {
        // Closed markers only; class names, method names and messages never leave this process.
        return switch (frame.getClassName()) {
            case "org.apache.hadoop.hdfs.server.namenode.NameNode" -> switch (frame.getMethodName()) {
                case "<init>" -> "namenode_constructor";
                case "initialize" -> "namenode_initialize";
                case "loginAsNameNodeUser" -> "namenode_login";
                case "format" -> "namenode_format";
                default -> null;
            };
            case "org.apache.hadoop.hdfs.server.namenode.NameNodeHttpServer" -> "namenode_http";
            case "org.apache.hadoop.http.HttpServer2", "org.apache.hadoop.http.HttpServer2$Builder" -> "hadoop_http";
            case "org.apache.hadoop.metrics2.lib.DefaultMetricsSystem",
                 "org.apache.hadoop.metrics2.impl.MetricsSystemImpl" -> "hadoop_metrics";
            case "org.apache.hadoop.security.authentication.server.KerberosAuthenticationHandler",
                 "org.apache.hadoop.security.authentication.server.AuthenticationFilter" -> "http_authentication";
            case "org.apache.hadoop.security.UserGroupInformation" -> "ugi";
            case "org.apache.hadoop.hdfs.server.blockmanagement.BlockManager" -> "block_manager";
            case "org.apache.hadoop.hdfs.server.namenode.FSNamesystem" -> "namesystem";
            default -> null;
        };
    }
    private static void projectFailure(Throwable failure) {
        // Same finite type approach as the existing SIMPLE fixture, extended to
        // secure NameNode startup. Do not guess a cause from a generic code.
        String selected = "unclassified", origin = "none";
        int selectedRank = 99;
        Set<Throwable> seen = java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>());
        try {
            for (int depth = 0; failure != null && depth < 8 && seen.add(failure); depth++, failure = failure.getCause()) {
                String category = "unclassified"; int rank = 99;
                if (failure instanceof ExitUtil.ExitException) { category = "exit_requested"; rank = 0; }
                else if (failure instanceof ExitUtil.HaltException) { category = "halt_requested"; rank = 0; }
                else if (failure instanceof ClassNotFoundException || failure instanceof NoClassDefFoundError) {
                    category = "missing_class"; rank = 1;
                } else if (failure instanceof OutOfMemoryError || failure instanceof StackOverflowError) {
                    category = "resource_failure"; rank = 2;
                } else if (failure instanceof IllegalArgumentException) { category = "invalid_config"; rank = 3; }
                else if (failure instanceof LinkageError) { category = "linkage_failure"; rank = 4; }
                else if (failure instanceof MetricsException) { category = "metrics_failure"; rank = 5; }
                else if (failure instanceof NullPointerException) { category = "null_state"; rank = 6; }
                else if (failure instanceof IllegalStateException) { category = "illegal_state"; rank = 7; }
                else if (failure instanceof UnsupportedOperationException) { category = "unsupported_operation"; rank = 8; }
                else if (failure instanceof SecurityException) { category = "security_failure"; rank = 9; }
                else if (failure instanceof KrbException) { category = "krb_failure"; rank = 10; }
                else if (failure instanceof FileNotFoundException) { category = "file_missing"; rank = 11; }
                else if (failure instanceof IOException) { category = "io_failure"; rank = 12; }
                else if (failure instanceof InterruptedException) { category = "interrupted"; rank = 13; }
                else if (failure instanceof Failure own && own.code != Code.unclassified) { category = "assertion"; rank = 14; }
                if (rank < selectedRank) { selected = category; selectedRank = rank; }
                StackTraceElement[] frames = failure.getStackTrace();
                for (int i = 0; i < frames.length && i < 32; i++) {
                    String marker = originFrame(frames[i]);
                    if (marker != null) { origin = marker; break; }
                }
            }
            diagnosticCategory = selected; diagnosticOrigin = origin;
        } catch (Throwable ignored) { diagnosticCategory = "unclassified"; diagnosticOrigin = "none"; }
    }
    private static String threadCategory(Thread thread) {
        if (TASKS.contains(thread)) return "probe_task";
        String selected = "other"; int selectedRank = 99;
        try {
            StackTraceElement[] frames = thread.getStackTrace();
            for (int i = 0; i < frames.length && i < 32; i++) {
                String name = frames[i].getClassName(), category = "other"; int rank = 99;
                if (name.startsWith("org.apache.hadoop.metrics2.")) { category = "hadoop_metrics"; rank = 0; }
                else if (name.startsWith("org.apache.hadoop.ipc.")) { category = "hadoop_rpc"; rank = 1; }
                else if (name.startsWith("org.eclipse.jetty.")) { category = "jetty"; rank = 2; }
                else if (name.startsWith("org.apache.kerby.")) { category = "kerby"; rank = 3; }
                else if (name.startsWith("org.apache.hadoop.fs.")) { category = "hadoop_fs"; rank = 4; }
                else if (name.startsWith("org.apache.hadoop.hdfs.server.namenode.")) { category = "hadoop_namenode"; rank = 5; }
                else if (name.startsWith("org.apache.hadoop.hdfs.server.blockmanagement.")) { category = "hadoop_blockmanagement"; rank = 6; }
                else if (name.startsWith("org.apache.hadoop.util.")) { category = "hadoop_util"; rank = 7; }
                else if (name.equals("jdk.internal.ref.CleanerImpl")) { category = "jdk_cleaner"; rank = 8; }
                else if (name.equals("java.lang.ProcessHandleImpl")) { category = "jdk_process_reaper"; rank = 9; }
                else if (name.equals("java.util.TimerThread")) { category = "jdk_timer"; rank = 10; }
                else if (name.startsWith("java.util.concurrent.")) { category = "jdk_executor"; rank = 11; }
                if (rank < selectedRank) { selected = category; selectedRank = rank; }
            }
        } catch (Throwable ignored) { return "other"; }
        return selected;
    }
    private static String timerKind(Thread thread) {
        // Exact names from pinned source; diagnostic hints only, never ownership.
        // No raw thread name leaves this process; unknown timers remain failures.
        String name = thread.getName();
        if (name.equals("Timer for 'NameNode' metrics system")) return "namenode_metrics";
        if (name.equals("IPC Server idle connection scanner for port 19000")) return "rpc_idle";
        if (name.equals("SnapshotDeletionGc")) return "snapshot_gc";
        if (name.equals("Shell command timeout")) return "shell_timeout";
        if (name.equals("SSL Certificates Store Monitor")) return "ssl_store";
        return "unknown";
    }
    private static void observeThreads(String phase, Set<Long> baseline) {
        try {
            need(THREAD_PHASES.subList(0, 8).contains(phase) && OBSERVED_PHASES.add(phase)
                && OBSERVED_PHASES.size() <= 8, Code.cleanup_failed);
            int live = 0;
            for (Thread thread : Thread.getAllStackTraces().keySet()) {
                if (!thread.isAlive() || baseline.contains(thread.getId())) continue;
                need(++live <= 128, Code.cleanup_failed);
                if (!THREAD_ORIGINS.containsKey(thread)) {
                    need(THREAD_ORIGINS.size() < 1024, Code.cleanup_failed);
                    THREAD_ORIGINS.put(thread, phase);
                }
            }
        } catch (Throwable ignored) { threadObservationIncomplete = true; }
    }
    private static boolean threadObservationsComplete() {
        return !threadObservationIncomplete && OBSERVED_PHASES.size() == 8;
    }
    private static Map<String, Integer> remainingThreadCounts(Set<Long> baseline) throws Exception {
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (String category : THREAD_CATEGORIES) counts.put(category, 0);
        Map<String, Integer> intervals = new LinkedHashMap<>();
        for (String phase : THREAD_PHASES) intervals.put(phase, 0);
        Map<String, Integer> timers = new LinkedHashMap<>();
        for (String kind : TIMER_KINDS) timers.put(kind, 0);
        Map<String, Map<String, Integer>> matrix = new LinkedHashMap<>();
        for (String category : THREAD_CATEGORIES) {
            Map<String, Integer> row = new LinkedHashMap<>();
            for (String phase : THREAD_PHASES) row.put(phase, 0);
            matrix.put(category, row);
        }
        int total = 0;
        for (Thread thread : Thread.getAllStackTraces().keySet()) {
            if (!thread.isAlive() || baseline.contains(thread.getId())) continue;
            need(++total <= 128, Code.cleanup_failed);
            String category = threadCategory(thread); counts.put(category, counts.get(category) + 1);
            if (category.equals("jdk_timer")) {
                String kind = timerKind(thread); timers.put(kind, timers.get(kind) + 1);
            }
            String phase = threadObservationsComplete() ? THREAD_ORIGINS.getOrDefault(thread, "unattributed") : "unattributed";
            intervals.put(phase, intervals.get(phase) + 1);
            Map<String, Integer> row = matrix.get(category); row.put(phase, row.get(phase) + 1);
        }
        need(intervals.values().stream().mapToInt(Integer::intValue).sum() == total, Code.cleanup_failed);
        for (String category : THREAD_CATEGORIES) {
            need(matrix.get(category).values().stream().mapToInt(Integer::intValue).sum() == counts.get(category), Code.cleanup_failed);
        }
        for (String phase : THREAD_PHASES) {
            need(matrix.values().stream().mapToInt(row -> row.get(phase)).sum() == intervals.get(phase), Code.cleanup_failed);
        }
        remainingThreadIntervals = intervals;
        remainingThreadMatrix = matrix;
        need(timers.values().stream().mapToInt(Integer::intValue).sum() == counts.get("jdk_timer"), Code.cleanup_failed);
        remainingTimerKinds = timers;
        return counts;
    }
    private static boolean statisticsCleanerFrame(Thread thread) {
        StackTraceElement[] frames = thread.getStackTrace();
        for (int i = 0; i < frames.length && i < 32; i++) {
            if (frames[i].getClassName().equals("org.apache.hadoop.fs.FileSystem$Statistics$StatisticsDataReferenceCleaner")
                && frames[i].getMethodName().equals("run")) return true;
        }
        return false;
    }
    private static OwnedCleanupState stopOwnedHelper(boolean gc, Set<Long> baseline, long until) {
        // Private disposable JVM only: stop no shared/preexisting or ambiguous helper.
        // All owned users must have closed before the process-wide statistics
        // cleaner can use its pinned interrupt-and-exit lifecycle.
        if (!threadObservationsComplete()) return OwnedCleanupState.observation_incomplete;
        if (!List.of("children_reaped", "relay_closed", "filesystem_closed", "namenode_stop_returned",
            "owner_logged_out", "kdc_stop_returned").stream().allMatch(k -> Boolean.TRUE.equals(CLEANUP.get(k))))
            return OwnedCleanupState.services_not_stopped;
        Thread target = null;
        try {
            int live = 0;
            for (Thread thread : Thread.getAllStackTraces().keySet()) {
                if (!thread.isAlive()) continue;
                if (++live > 128) return OwnedCleanupState.scan_failed;
                if (System.nanoTime() >= until) return OwnedCleanupState.deadline;
                boolean matches = gc ? thread.getClass() == GcTimeMonitor.class
                    : thread.getClass() == SubjectInheritingThread.class && statisticsCleanerFrame(thread);
                if (!matches) continue;
                if (target != null) return OwnedCleanupState.ambiguous;
                target = thread;
            }
            if (target == null) return OwnedCleanupState.missing;
            if (baseline.contains(target.getId())) return OwnedCleanupState.preexisting;
            if (!THREAD_ORIGINS.containsKey(target)) return OwnedCleanupState.unobserved;
            if (!THREAD_ORIGINS.get(target).equals(gc ? "namenode" : "filesystem")) return OwnedCleanupState.late;
            if (!target.isDaemon()) return OwnedCleanupState.not_daemon;
        } catch (Throwable ignored) { return OwnedCleanupState.scan_failed; }
        try {
            if (System.nanoTime() >= until) return OwnedCleanupState.deadline;
            if (gc) ((GcTimeMonitor) target).shutdown();
            // Both exact pinned work loops explicitly return on interruption.
            target.interrupt();
            long remaining = until - System.nanoTime();
            if (remaining <= 0) return OwnedCleanupState.deadline;
            target.join(remaining / 1_000_000L, (int)(remaining % 1_000_000L));
            return target.isAlive() ? OwnedCleanupState.still_alive : OwnedCleanupState.terminated;
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt(); return OwnedCleanupState.shutdown_failed;
        } catch (Throwable ignored) { return OwnedCleanupState.shutdown_failed; }
    }
    private static OwnedCleanupState inspectFormatSslTimer(Set<Long> baseline, long until, boolean capture) {
        // NameNode.format has already initialized Util through namespace URI conversion.
        // Match the timer privately, retaining its exact object before any later service.
        if (threadObservationIncomplete || !OBSERVED_PHASES.contains("format"))
            return OwnedCleanupState.observation_incomplete;
        if (formatSslFactory == null || formatSslFactory.getClass() != URLConnectionFactory.class)
            return OwnedCleanupState.missing;
        Thread target = null;
        try {
            int live = 0;
            for (Thread thread : Thread.getAllStackTraces().keySet()) {
                if (!thread.isAlive()) continue;
                if (++live > 128) return OwnedCleanupState.scan_failed;
                if (System.nanoTime() >= until) return OwnedCleanupState.deadline;
                if (!thread.getName().equals("SSL Certificates Store Monitor")) continue;
                if (!thread.getClass().getName().equals("java.util.TimerThread")) return OwnedCleanupState.scan_failed;
                if (target != null) return OwnedCleanupState.ambiguous;
                target = thread;
            }
            if (target == null) return OwnedCleanupState.missing;
            if (baseline.contains(target.getId())) return OwnedCleanupState.preexisting;
            if (!THREAD_ORIGINS.containsKey(target)) return OwnedCleanupState.unobserved;
            if (!THREAD_ORIGINS.get(target).equals("format")) return OwnedCleanupState.late;
            if (!target.isDaemon()) return OwnedCleanupState.not_daemon;
            if (capture) {
                if (formatSslThread != null) return OwnedCleanupState.ambiguous;
                formatSslThread = target;
            } else if (target != formatSslThread) return OwnedCleanupState.unobserved;
            return null;
        } catch (Throwable ignored) { return OwnedCleanupState.scan_failed; }
    }
    private static OwnedCleanupState stopOwnedFormatSsl(Set<Long> baseline, long until) {
        if (sslCaptureFailure != null) return sslCaptureFailure;
        if (!threadObservationsComplete()) return OwnedCleanupState.observation_incomplete;
        if (!List.of("children_reaped", "relay_closed", "filesystem_closed", "namenode_stop_returned",
            "owner_logged_out", "kdc_stop_returned").stream().allMatch(k -> Boolean.TRUE.equals(CLEANUP.get(k))))
            return OwnedCleanupState.services_not_stopped;
        OwnedCleanupState invalid = inspectFormatSslTimer(baseline, until, false);
        if (invalid != null) return invalid;
        try {
            if (System.nanoTime() >= until) return OwnedCleanupState.deadline;
            // Public lifecycle of this retained process-local factory; never interrupt a TimerThread.
            formatSslFactory.destroy();
            long remaining = until - System.nanoTime();
            if (remaining <= 0) return OwnedCleanupState.deadline;
            formatSslThread.join(remaining / 1_000_000L, (int)(remaining % 1_000_000L));
            return formatSslThread.isAlive() ? OwnedCleanupState.still_alive : OwnedCleanupState.terminated;
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt(); return OwnedCleanupState.shutdown_failed;
        } catch (Throwable ignored) { return OwnedCleanupState.shutdown_failed; }
    }
    private static void cleanup(SimpleKdcServer server, Set<Long> baseline) {
        boolean stopped = server == null;
        try {
            // A partial cache must not prevent network shutdown. Verify only
            // the root/config path that SimpleKdcServer.stop itself may delete.
            if (server != null) {
                guardRoot();
                if (OWNED_FILES.containsKey(CONF)) OWNED_FILES.get(CONF).verify(CONF);
                else need(!Files.exists(CONF, NOFOLLOW), Code.source_changed);
            }
            if (server != null) bounded(() -> { server.stop(); return null; }, 5,
                System.nanoTime() + TimeUnit.SECONDS.toNanos(5));
            stopped = true;
        } catch (Throwable ignored) { stopped = false; }
        CLEANUP.put("kdc_stop_returned", stopped);
        observeThreads("shutdown", baseline);
        boolean threadsClean = false;
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
        gcCleanup = stopOwnedHelper(true, baseline, until);
        CLEANUP.put("gc_monitor_reaped", gcCleanup == OwnedCleanupState.terminated);
        statisticsCleanup = stopOwnedHelper(false, baseline, until);
        CLEANUP.put("fs_statistics_cleaner_reaped", statisticsCleanup == OwnedCleanupState.terminated);
        sslCleanup = stopOwnedFormatSsl(baseline, until);
        CLEANUP.put("format_ssl_timer_reaped", sslCleanup == OwnedCleanupState.terminated);
        do {
            try { remainingThreads = remainingThreadCounts(baseline); }
            catch (Throwable ignored) { remainingThreads = null; remainingThreadIntervals = null; remainingThreadMatrix = null; remainingTimerKinds = null; break; }
            // Every residual thread still fails cleanup, including JDK/unknown categories.
            threadsClean = remainingThreads.values().stream().allMatch(count -> count == 0)
                && TASKS.stream().noneMatch(Thread::isAlive);
            if (threadsClean) break;
            try { Thread.sleep(25); } catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
        } while (System.nanoTime() < until);
        CLEANUP.put("threads_terminated", threadsClean);
        boolean noListeners = false;
        try { listeners(false); noListeners = true; } catch (Throwable ignored) { }
        CLEANUP.put("listeners_absent", noListeners);
        boolean removed = !rootCreated;
        if (rootOwned && stopped && threadsClean && noListeners && List.of("children_reaped", "relay_closed", "filesystem_closed", "namenode_stop_returned", "owner_logged_out", "gc_monitor_reaped", "fs_statistics_cleaner_reaped", "format_ssl_timer_reaped").stream().allMatch(k -> Boolean.TRUE.equals(CLEANUP.get(k)))) {
            try {
                guardRoot();
                // stop() removes its config. No unknown/replaced file is deleted.
                if (!Files.exists(CONF, NOFOLLOW)) OWNED_FILES.remove(CONF);
                inventory();
                for (var entry : OWNED_FILES.entrySet()) {
                    guardRoot(); entry.getValue().verify(entry.getKey()); Files.delete(entry.getKey());
                }
                try (DirectoryStream<Path> stream = Files.newDirectoryStream(ROOT)) {
                    need(!stream.iterator().hasNext(), Code.unexpected_files);
                }
                guardRoot(); Files.delete(ROOT); removed = !Files.exists(ROOT, NOFOLLOW);
            } catch (Throwable ignored) { removed = false; }
        }
        CLEANUP.put("private_material_removed", removed);
        // Only this process property was set by SimpleKdcServer, and it was
        // required absent at entry. Never change an unexpected replacement.
        boolean restored = false;
        String value = System.getProperty(CONF_PROPERTY);
        if (value == null) restored = true;
        else if (CONF.toString().equals(value)) { System.clearProperty(CONF_PROPERTY); restored = true; }
        CLEANUP.put("process_property_restored", restored);
        CLEANUP.put("cleanup_completed", true);
    }
    private static String boolMap(Map<String, Boolean> values) {
        StringBuilder out = new StringBuilder("{");
        for (var entry : values.entrySet()) {
            if (out.length() > 1) out.append(','); out.append('"').append(entry.getKey()).append("\":").append(entry.getValue());
        }
        return out.append('}').toString();
    }
    private static String threadCountsJson(Map<String, Integer> values, List<String> keys) {
        if (values == null) return "null";
        StringBuilder out = new StringBuilder("{");
        for (String category : keys) {
            if (out.length() > 1) out.append(',');
            out.append('"').append(category).append("\":").append(values.get(category));
        }
        return out.append('}').toString();
    }
    private static String threadMatrixJson() {
        if (remainingThreadMatrix == null) return "null";
        StringBuilder out = new StringBuilder("{");
        for (String category : THREAD_CATEGORIES) {
            if (out.length() > 1) out.append(',');
            out.append('"').append(category).append("\":")
                .append(threadCountsJson(remainingThreadMatrix.get(category), THREAD_PHASES));
        }
        return out.append('}').toString();
    }

    private static Set<Long> processIds() {
        Set<Long> result = new HashSet<>();
        ProcessHandle.allProcesses().forEach(p -> result.add(p.pid())); return result;
    }
    private static byte[] fatalFrame(DataInputStream input) throws Exception {
        int length = input.readInt(); need(length > 0 && length <= 4096, Code.wire_invalid);
        byte[] response = input.readNBytes(length);
        need(response.length == length, Code.wire_invalid);
        ByteArrayInputStream frame = new ByteArrayInputStream(response);
        RpcResponseHeaderProto header = RpcResponseHeaderProto.parseDelimitedFrom(frame);
        need(header != null && frame.available() == 0 && header.getUnknownFields().asMap().isEmpty()
            && header.getCallId() == -1 && header.getServerIpcVersionNum() == 9
            && header.getStatus() == RpcStatusProto.FATAL
            && header.getErrorDetail() == RpcErrorCodeProto.FATAL_UNAUTHORIZED
            && header.getExceptionClassName().equals(EXCEPTION) && header.getErrorMsg().equals(DENIAL), Code.wire_invalid);
        return ByteBuffer.allocate(4 + length).putInt(length).put(response).array();
    }
    private static final class Relay {
        final ServerSocket listener = new ServerSocket();
        final List<Thread> sessions = new java.util.concurrent.CopyOnWriteArrayList<>();
        final List<Socket> sockets = new java.util.concurrent.CopyOnWriteArrayList<>();
        final AtomicBoolean failed = new AtomicBoolean();
        final int[] counts = new int[3];
        volatile boolean running = true;
        int phase = -1, noneHeaders, fatalResponses, unexpected;
        Thread acceptor;
        Relay() throws Exception {
            try {
            listener.bind(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127,0,0,1}), 19007), 4);
            listener.setSoTimeout(200);
            acceptor = new Thread(() -> {
                while (running) {
                    try {
                        Socket incoming = listener.accept(); sockets.add(incoming);
                        int ownedPhase;
                        synchronized (this) {
                            ownedPhase = phase;
                            if (ownedPhase < 0 || ownedPhase > 2 || counts[ownedPhase] >= 4) {
                                unexpected++; incoming.close(); failed.set(true);
                                running = false; listener.close(); break;
                            }
                            counts[ownedPhase]++;
                        }
                        Thread session = new Thread(() -> serve(incoming, ownedPhase), "owned-rpc-relay-session");
                        session.setDaemon(true); sessions.add(session); TASKS.add(session); session.start();
                    } catch (SocketTimeoutException ignored) { }
                    catch (Throwable error) { if (running) failed.set(true); break; }
                }
            }, "owned-rpc-relay-acceptor");
            acceptor.setDaemon(true); TASKS.add(acceptor); acceptor.start();
            } catch (Exception failure) {
                running = false; listener.close(); throw failure;
            }
        }
        synchronized void begin(int value) throws Exception {
            need(!failed.get() && phase == -1 && value >= 0 && value <= 2 && counts[value] == 0
                && sessions.stream().noneMatch(Thread::isAlive), Code.relay_invalid);
            phase = value;
        }
        void end(int value) throws Exception {
            long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
            for (Thread session : sessions) {
                long left = until - System.nanoTime(); need(left > 0, Code.relay_invalid);
                session.join(Math.max(1, TimeUnit.NANOSECONDS.toMillis(left)));
            }
            synchronized (this) {
                need(phase == value && counts[value] > 0 && !failed.get()
                    && sessions.stream().noneMatch(Thread::isAlive), Code.relay_invalid);
                phase = -1;
            }
        }
        private void pump(Socket source, Socket destination, AtomicBoolean closing) throws Exception {
            byte[] buffer = new byte[4096]; int total = 0;
            try {
                while (!closing.get()) {
                    need(System.nanoTime() < controlDeadline, Code.deadline_exceeded);
                    int count = source.getInputStream().read(buffer);
                    if (count == -1) { destination.shutdownOutput(); return; }
                    total += count; need(total <= 131072, Code.relay_invalid);
                    destination.getOutputStream().write(buffer, 0, count);
                    destination.getOutputStream().flush();
                }
            } finally { Arrays.fill(buffer, (byte)0); }
        }
        private void serve(Socket incoming, int ownedPhase) {
            Socket upstream = new Socket(); sockets.add(upstream);
            AtomicBoolean closing = new AtomicBoolean(), uploadFailed = new AtomicBoolean();
            Thread upload = null; boolean captured = false;
            try {
                incoming.setSoTimeout(5000);
                byte[] header = incoming.getInputStream().readNBytes(7);
                byte auth = ownedPhase == 1 ? (byte)0 : (byte)0xdf;
                need(Arrays.equals(header, new byte[]{'h','r','p','c',9,0,auth}), Code.relay_invalid);
                synchronized (this) { need(phase == ownedPhase, Code.relay_invalid); if (ownedPhase == 1) noneHeaders++; }
                upstream.connect(endpoint, 2000); upstream.setSoTimeout(5000);
                need(upstream.getPort() == 19000 && upstream.getInetAddress().isLoopbackAddress(), Code.relay_invalid);
                upstream.getOutputStream().write(header); upstream.getOutputStream().flush();
                upload = new Thread(() -> {
                    try { pump(incoming, upstream, closing); }
                    catch (Throwable error) { if (!closing.get()) uploadFailed.set(true); }
                }, "owned-rpc-relay-upload");
                upload.setDaemon(true); TASKS.add(upload); upload.start();
                if (ownedPhase == 1) {
                    DataInputStream input = new DataInputStream(upstream.getInputStream());
                    byte[] response = fatalFrame(input);
                    // Forward exactly the response received, including its length prefix.
                    incoming.getOutputStream().write(response); incoming.getOutputStream().flush();
                    need(input.read() == -1, Code.relay_invalid);
                    String encoded = java.util.HexFormat.of().formatHex(response);
                    synchronized (this) {
                        need(phase == ownedPhase && (rcloneWireHex.isEmpty() || rcloneWireHex.equals(encoded)), Code.relay_invalid);
                        rcloneWireHex = encoded; fatalResponses++;
                    }
                    captured = true; Arrays.fill(response, (byte)0);
                } else {
                    // SASL/credential bytes are forwarded in fixed buffers and never exported.
                    pump(upstream, incoming, closing);
                }
            } catch (Throwable error) { failed.set(true); }
            finally {
                closing.set(true);
                try { incoming.close(); } catch (IOException ignored) { failed.set(true); }
                try { upstream.close(); } catch (IOException ignored) { failed.set(true); }
                try { if (upload != null) upload.join(1000); } catch (InterruptedException error) { failed.set(true); }
                if (upload != null && upload.isAlive() || uploadFailed.get() && !captured) failed.set(true);
            }
        }
        boolean stop() {
            running = false;
            try { listener.close(); } catch (IOException ignored) { failed.set(true); }
            for (Socket socket : sockets) try { socket.close(); } catch (IOException ignored) { failed.set(true); }
            long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(4);
            List<Thread> threads = new ArrayList<>(sessions); threads.add(acceptor);
            for (Thread thread : threads) {
                try { thread.join(Math.max(1, TimeUnit.NANOSECONDS.toMillis(until - System.nanoTime()))); }
                catch (InterruptedException ignored) { Thread.currentThread().interrupt(); return false; }
            }
            return listener.isClosed() && sockets.stream().allMatch(Socket::isClosed)
                && threads.stream().noneMatch(Thread::isAlive);
        }
        synchronized String json() {
            return "{\"before_connections\":" + counts[0] + ",\"negative_connections\":" + counts[1]
                + ",\"after_connections\":" + counts[2] + ",\"none_headers\":" + noneHeaders
                + ",\"fatal_responses\":" + fatalResponses + ",\"unexpected_connections\":" + unexpected
                + ",\"bytes_forwarded_unchanged\":" + !failed.get() + "}";
        }
    }
    private static byte[] childRead(java.io.InputStream input) throws Exception {
        try (input) {
            byte[] data = input.readNBytes(16385);
            need(data.length <= 16384, Code.child_output_invalid); return data;
        }
    }
    private static final class Result {
        final int code; final byte[] out, err;
        Result(int c, byte[] o, byte[] e) { code = c; out = o; err = e; }
    }
    private static Result child(List<String> command, Map<String, String> environment) throws Exception {
        need(System.nanoTime() < controlDeadline, Code.deadline_exceeded);
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.environment().clear(); builder.environment().putAll(environment);
        builder.directory(WORK.toFile());
        Process process = builder.start(); CHILDREN.add(process);
        process.getOutputStream().close();
        FutureTask<byte[]> stdout = new FutureTask<>(() -> childRead(process.getInputStream()));
        FutureTask<byte[]> stderr = new FutureTask<>(() -> childRead(process.getErrorStream()));
        Thread out = new Thread(stdout, "owned-rclone-stdout"), err = new Thread(stderr, "owned-rclone-stderr");
        out.setDaemon(true); err.setDaemon(true); TASKS.add(out); TASKS.add(err); out.start(); err.start();
        try {
            long remaining = Math.min(TimeUnit.SECONDS.toNanos(12), controlDeadline - System.nanoTime());
            need(remaining > 0 && process.waitFor(remaining, TimeUnit.NANOSECONDS), Code.deadline_exceeded);
            need(process.descendants().findAny().isEmpty(), Code.child_descendant_found);
            return new Result(process.exitValue(), stdout.get(1, TimeUnit.SECONDS), stderr.get(1, TimeUnit.SECONDS));
        } finally {
            if (process.isAlive()) process.destroyForcibly();
            need(process.waitFor(3, TimeUnit.SECONDS), Code.child_reap_failed);
            process.getInputStream().close(); process.getErrorStream().close();
            out.join(1000); err.join(1000);
            need(!out.isAlive() && !err.isAlive(), Code.child_streams_alive);
        }
    }
    private static Result rclone(String reader, boolean authenticated) throws Exception {
        List<String> command = new ArrayList<>(List.of("/opt/rpc/rclone", "lsjson", ":hdfs:" + MEMBER,
            "--config", "/dev/null", "--hdfs-namenode", "127.0.0.1:19007", "--hdfs-username", reader,
            "--log-level", "ERROR", "--retries", "1", "--low-level-retries", "1",
            "--contimeout", "3s", "--timeout", "8s", "--disable", "ListR"));
        Map<String, String> env = new LinkedHashMap<>();
        env.put("HOME", "/work/home"); env.put("PATH", "/usr/bin:/bin"); env.put("LANG", "C"); env.put("LC_ALL", "C");
        if (authenticated) {
            command.addAll(List.of("--hdfs-service-principal-name", "hdfs/127.0.0.1",
                "--hdfs-data-transfer-protection", "privacy"));
            env.put("KRB5_CONFIG", CONF.toString()); env.put("KRB5CCNAME", "FILE:" + CACHE);
        }
        return child(command, env);
    }
    private static void positive(String reader, int phase) throws Exception {
        relay.begin(phase); Result result = rclone(reader, true); relay.end(phase);
        need(result.code == 0 && result.err.length == 0
            && new String(result.out, StandardCharsets.US_ASCII).trim().matches("\\[\\s*\\]"),
            Code.rclone_positive_failed);
        inventory(); topology();
    }
    private static boolean emptyNegativeListing(byte[] stdout) {
        // Pinned lsjson prints '[' before ListJSON and returns on error before
        // printing ']'. This finite prefix contains no item and is not auth proof.
        String output = new String(stdout, StandardCharsets.US_ASCII);
        return output.matches("(?:|\\[\\n|\\[\\n\\]\\n)");
    }
    private static void negative(String reader) throws Exception {
        relay.begin(1); Result result = rclone(reader, false); relay.end(1);
        // Pinned Go transport checks callId=-1 before status, discarding the fatal
        // category. Stderr is not an oracle. Require the actual NONE connections'
        // unchanged fatal wire response; empty serialization never grants credit.
        need(result.code != 0, Code.rclone_denial_exit_zero);
        need(emptyNegativeListing(result.out), Code.rclone_denial_output_invalid);
        need(relay.counts[1] > 0 && relay.noneHeaders == relay.counts[1]
            && relay.fatalResponses == relay.counts[1] && !rcloneWireHex.isEmpty(), Code.rclone_denial_mismatch);
        inventory(); topology();
    }
    private static void wireOracle() throws Exception {
        topology();
        try (Socket socket = new Socket()) {
            socket.connect(endpoint, 2000); socket.setSoTimeout(2000);
            need(socket.getInetAddress().equals(InetAddress.getByAddress(new byte[]{127,0,0,1}))
                && socket.getPort() == 19000, Code.wire_invalid);
            socket.getOutputStream().write(new byte[]{'h','r','p','c',9,0,0});
            socket.getOutputStream().flush();
            DataInputStream input = new DataInputStream(socket.getInputStream());
            byte[] response = fatalFrame(input);
            need(input.read() == -1, Code.wire_invalid);
            wireHex = java.util.HexFormat.of().formatHex(response);
            need(wireHex.equals(rcloneWireHex), Code.wire_invalid);
        }
    }
    private static Configuration configuration(String realm, String reader) {
        Configuration conf = new HdfsConfiguration(false);
        conf.set("fs.defaultFS", "hdfs://127.0.0.1:19000");
        conf.set("dfs.namenode.rpc-address", "127.0.0.1:19000");
        conf.set("dfs.namenode.rpc-bind-host", "127.0.0.1");
        conf.set("dfs.namenode.http-address", "127.0.0.1:19003");
        conf.set("dfs.namenode.http-bind-host", "127.0.0.1");
        conf.set("dfs.http.policy", "HTTP_ONLY");
        conf.set("hadoop.security.authentication", "kerberos");
        // No defaults are loaded: secure HttpServer2 requires an explicit type.
        // Its separate AuthFilter reads this prefix, not the dfs.web.* keys
        // used below by the internal SPNEGO filter. Both use the owned HTTP key.
        conf.set("hadoop.http.authentication.type", "kerberos");
        conf.set("hadoop.http.authentication.kerberos.principal", "HTTP/127.0.0.1@" + realm);
        conf.set("hadoop.http.authentication.kerberos.keytab", HTTP_KEYTAB.toString());
        // BlockManager requires tokens during secure NameNode formatting,
        // even when this experiment never starts a DataNode or transfers bytes.
        conf.set("dfs.block.access.token.enable", "true");
        conf.set("hadoop.security.authorization", "true");
        conf.set("hadoop.kerberos.keytab.login.autorenewal.enabled", "false");
        conf.set("ipc.client.fallback-to-simple-auth-allowed", "false");
        conf.set("hadoop.rpc.protection", "authentication");
        conf.set("dfs.namenode.kerberos.principal", "hdfs/127.0.0.1@" + realm);
        conf.set("dfs.namenode.keytab.file", KEYTAB.toString());
        conf.set("dfs.namenode.kerberos.internal.spnego.principal", "HTTP/127.0.0.1@" + realm);
        conf.set("dfs.web.authentication.kerberos.principal", "HTTP/127.0.0.1@" + realm);
        conf.set("dfs.web.authentication.kerberos.keytab", HTTP_KEYTAB.toString());
        conf.set("dfs.web.authentication.simple.anonymous.allowed", "false");
        conf.set("hadoop.user.group.static.mapping.overrides", "hdfs=fixture-group;" + reader + "=reader-group");
        conf.set("dfs.permissions.enabled", "true");
        conf.set("dfs.reformat.disabled", "true");
        conf.set("dfs.replication", "1");
        conf.set("dfs.namenode.safemode.min.datanodes", "0");
        conf.set("dfs.namenode.safemode.extension", "0");
        conf.set("dfs.namenode.accesstime.precision", "0");
        conf.set("dfs.client.read.shortcircuit", "false");
        conf.set("dfs.domain.socket.path", "");
        conf.set("dfs.client.socket-timeout", "5000");
        conf.set("ipc.client.connect.timeout", "3000");
        conf.set("ipc.client.connect.max.retries", "0");
        conf.set("ipc.client.connect.max.retries.on.timeouts", "0");
        conf.set("ipc.client.rpc-timeout.ms", "5000");
        conf.set("dfs.namenode.name.dir", WORK.resolve("state/name").toUri().toString());
        conf.set("dfs.namenode.edits.dir", WORK.resolve("state/edits").toUri().toString());
        conf.set("hadoop.tmp.dir", WORK.resolve("state/tmp").toString());
        conf.set("hadoop.http.temp.dir", WORK.resolve("state/http").toString());
        return conf;
    }
    private static void topology() throws Exception {
        need(namenode != null && endpoint != null && namenode.getNameNodeAddress().equals(endpoint)
            && endpoint.getPort() == 19000 && endpoint.getAddress().getHostAddress().equals("127.0.0.1")
            && namenode.getHttpAddress().getPort() == 19003
            && namenode.getHttpAddress().getAddress().getHostAddress().equals("127.0.0.1")
            && namenode.getHttpsAddress() == null && namenode.getAuxiliaryNameNodeAddresses().isEmpty()
            && UserGroupInformation.isSecurityEnabled(), Code.namenode_failed);
        listeners(true);
        need(processIds().equals(processBaseline), Code.child_process_drift);
        need(ExitUtil.getFirstExitException() == null && ExitUtil.getFirstHaltException() == null, Code.namenode_failed);
    }
    private static void verifyMember() throws Exception {
        org.apache.hadoop.fs.Path path = new org.apache.hadoop.fs.Path(MEMBER);
        var info = filesystem.getFileStatus(path);
        need(info.isDirectory() && info.getLen() == 0 && info.getOwner().equals("hdfs")
            && info.getPermission().toShort() == 0755 && filesystem.listStatus(path).length == 0,
            Code.source_invalid);
        if (memberMtime < 0) {
            memberMtime = info.getModificationTime(); memberAtime = info.getAccessTime(); memberGroup = info.getGroup();
        } else {
            need(info.getModificationTime() == memberMtime && info.getAccessTime() == memberAtime
                && info.getGroup().equals(memberGroup), Code.source_invalid);
        }
    }
    private static String configurationDigest() throws Exception {
        Map<String, String> settings = new java.util.TreeMap<>();
        for (Map.Entry<String, String> entry : namenode.getConf()) settings.put(entry.getKey(), entry.getValue());
        StringBuilder text = new StringBuilder();
        for (var entry : settings.entrySet()) text.append(entry.getKey().length()).append(':').append(entry.getKey())
            .append(entry.getValue().length()).append(':').append(entry.getValue());
        return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
            .digest(text.toString().getBytes(StandardCharsets.UTF_8)));
    }
    private static void exportKey(SimpleKdcServer server, String principal, Path path) throws Exception {
        guardRoot(); need(!Files.exists(path, NOFOLLOW), Code.path_invalid);
        server.createPrincipal(principal); server.exportPrincipal(principal, path.toFile());
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        OWNED_FILES.put(path, new FileState(path)); inventory();
    }
    private static void rememberOwner() throws Exception {
        // format() and initialize() each call SecurityUtil.login and replace UGI.
        // Retain every owned Subject so all private login credentials are logged out.
        UserGroupInformation current = UserGroupInformation.getLoginUser();
        need(current.getUserName().equals(ownerPrincipal) && current.isFromKeytab()
            && current.hasKerberosCredentials(), Code.namenode_failed);
        if (!OWNERS.contains(current)) OWNERS.add(current);
        owner = current;
    }
    private static void stopServices() {
        boolean children = true;
        for (Process child : CHILDREN) {
            try {
                if (child.isAlive()) child.destroyForcibly();
                children &= child.waitFor(3, TimeUnit.SECONDS);
            } catch (Throwable ignored) { children = false; }
        }
        CLEANUP.put("children_reaped", children && (processBaseline == null || processIds().equals(processBaseline)));
        boolean relayClosed = relay == null;
        try { if (relay != null) relayClosed = relay.stop(); } catch (Throwable ignored) { relayClosed = false; }
        CLEANUP.put("relay_closed", relayClosed);
        boolean closed = true;
        try { if (filesystem != null) bounded(() -> { filesystem.close(); return null; }, 5,
            System.nanoTime() + TimeUnit.SECONDS.toNanos(5)); } catch (Throwable ignored) { closed = false; }
        CLEANUP.put("filesystem_closed", closed);
        boolean stopped = true;
        try { if (namenode != null) bounded(() -> { namenode.stop(); return null; }, 8,
            System.nanoTime() + TimeUnit.SECONDS.toNanos(8)); } catch (Throwable ignored) { stopped = false; }
        CLEANUP.put("namenode_stop_returned", stopped);
        boolean loggedOut = true;
        for (UserGroupInformation login : OWNERS) {
            try { bounded(() -> { login.logoutUserFromKeytab(); return null; }, 3,
                System.nanoTime() + TimeUnit.SECONDS.toNanos(3)); } catch (Throwable ignored) { loggedOut = false; }
        }
        CLEANUP.put("owner_logged_out", loggedOut);
    }
    public static void main(String[] args) {
        PrintStream report = System.out;
        System.setOut(new PrintStream(OutputStream.nullOutputStream()));
        System.setErr(new PrintStream(OutputStream.nullOutputStream()));
        Thread.setDefaultUncaughtExceptionHandler((thread, error) -> BACKGROUND_FAILURE.set(true));
        for (String name : List.of("environment", "endpoint_settings", "positive_tgt", "file_cache_v3",
                "nonrenewable", "secure_namenode", "listing_before", "rclone_auth_boundary_rejection",
                "wire_auth_boundary_rejection", "listing_after", "source_preserved", "cache_preserved")) CHECKS.put(name, false);
        for (String name : List.of("children_reaped", "relay_closed", "filesystem_closed", "namenode_stop_returned", "owner_logged_out",
                "gc_monitor_reaped", "fs_statistics_cleaner_reaped", "format_ssl_timer_reaped",
                "kdc_stop_returned", "threads_terminated", "listeners_absent", "private_material_removed",
                "process_property_restored", "cleanup_completed")) CLEANUP.put(name, false);
        Set<Long> baseline = threadIds(); SimpleKdcServer server = null; Code error = null;
        deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(90);
        byte[] serialized = null;
        try {
            environment(args); processBaseline = processIds(); CHECKS.put("environment", true);
            // Prime only the JDK child reaper before the service-thread baseline.
            // The version child uses the same pinned binary and bounded supervisor.
            controlDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(12);
            stage = "rclone_version";
            Result version = child(List.of("/opt/rpc/rclone", "version", "--config", "/dev/null", "--log-level", "ERROR"),
                Map.of("HOME", "/work/home", "PATH", "/usr/bin:/bin", "LANG", "C", "LC_ALL", "C"));
            need(version.code == 0, Code.rclone_version_nonzero);
            need(version.err.length == 0, Code.rclone_version_stderr);
            need(new String(version.out, StandardCharsets.US_ASCII).startsWith("rclone v1.75.2\n"), Code.rclone_version_mismatch);
            need(processIds().equals(processBaseline), Code.child_process_drift);
            baseline = threadIds();
            Files.createDirectory(ROOT, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
            rootCreated = true; rootKey = directory(ROOT, true); rootOwned = true; guardRoot();
            SecureRandom random = new SecureRandom();
            String realm = "SYNTHETIC" + random(random, 12).toUpperCase(java.util.Locale.ROOT) + ".INVALID";
            String reader = "reader" + random(random, 12), password = random(random, 32);
            KrbConfig clientConfig = new KrbConfig(); server = new SimpleKdcServer(clientConfig);
            constrainConfig(server, clientConfig, realm); final SimpleKdcServer ownedServer = server;
            stage = "kdc_init"; bounded(() -> { ownedServer.init(); return null; }, 10, deadline);
            replaceGeneratedConfig(realm);
            stage = "principals";
            server.createPrincipal(reader + "@" + realm, password);
            exportKey(server, "hdfs/127.0.0.1@" + realm, KEYTAB);
            exportKey(server, "HTTP/127.0.0.1@" + realm, HTTP_KEYTAB);
            stage = "kdc_start"; bounded(() -> { ownedServer.start(); return null; }, 10, deadline);
            listeners(true); CHECKS.put("endpoint_settings", true);
            observeThreads("kdc", baseline);
            ExitUtil.disableSystemExit(); ExitUtil.disableSystemHalt();
            Configuration conf = configuration(realm, reader);
            UserGroupInformation.setConfiguration(conf);
            ownerPrincipal = "hdfs/127.0.0.1@" + realm;
            stage = "owner_login";
            bounded(() -> { UserGroupInformation.loginUserFromKeytab(ownerPrincipal, KEYTAB.toString());
                rememberOwner(); return null; }, 10, deadline);
            need(owner != null && owner.hasKerberosCredentials() && owner.isFromKeytab(), Code.namenode_failed);
            observeThreads("owner_login", baseline);
            stage = "format"; bounded(() -> {
                try { NameNode.format(conf); formatSslFactory = Util.connectionFactory; }
                finally { rememberOwner(); } return null; }, 15, deadline);
            observeThreads("format", baseline);
            sslCaptureFailure = inspectFormatSslTimer(baseline, deadline, true);
            stage = "namenode_start"; bounded(() -> {
                try { namenode = new NameNode(conf); } finally { rememberOwner(); } return null; }, 30, deadline);
            endpoint = namenode.getNameNodeAddress(); topology(); CHECKS.put("secure_namenode", true);
            observeThreads("namenode", baseline);
            stage = "relay_start"; relay = new Relay(); topology();
            stage = "seed"; bounded(() -> {
                filesystem = new DistributedFileSystem(); filesystem.initialize(URI.create("hdfs://127.0.0.1:19000"), conf);
                filesystem.setSafeMode(SafeModeAction.SAFEMODE_LEAVE);
                need(filesystem.mkdirs(new org.apache.hadoop.fs.Path(MEMBER), new FsPermission((short)0755)), Code.source_invalid);
                verifyMember(); return null; }, 10, deadline);
            observeThreads("filesystem", baseline);
            configurationDigest = configurationDigest();
            stage = "reader_tgt";
            KrbClient client = server.getKrbClient(); long before = System.currentTimeMillis() / 1000;
            TgtTicket tgt = bounded(() -> client.requestTgt(options(reader + "@" + realm, password)), 10, deadline);
            long after = System.currentTimeMillis() / 1000;
            need(tgt != null && !BACKGROUND_FAILURE.get(), Code.positive_ticket_failed); CHECKS.put("positive_tgt", true);
            LimitedBuffer buffer = new LimitedBuffer();
            try { new CredentialCache(tgt).store(buffer); serialized = buffer.toByteArray(); } finally { buffer.erase(); }
            inspectCache(serialized, realm, reader, before, after); publishCache(serialized);
            CHECKS.put("file_cache_v3", true); CHECKS.put("nonrenewable", true);
            observeThreads("reader", baseline);
            controlDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
            stage = "listing_before"; positive(reader, 0); CHECKS.put("listing_before", true);
            stage = "rclone_none"; negative(reader); CHECKS.put("rclone_auth_boundary_rejection", true);
            stage = "wire_none"; wireOracle(); CHECKS.put("wire_auth_boundary_rejection", true);
            stage = "listing_after"; positive(reader, 2); CHECKS.put("listing_after", true);
            stage = "preservation"; bounded(() -> { verifyMember(); return null; }, 5, controlDeadline);
            need(configurationDigest.equals(configurationDigest()), Code.source_invalid);
            CHECKS.put("source_preserved", true);
            inventory(); topology(); need(!BACKGROUND_FAILURE.get(), Code.background_failure);
            CHECKS.put("cache_preserved", true); stage = "completed";
        } catch (Throwable failure) {
            if (failure instanceof Failure owned) error = owned.code;
            else if (failure instanceof KrbException) error = Code.krb_failure;
            else if (failure instanceof IOException) error = Code.io_failure;
            else if (failure instanceof InterruptedException) { Thread.currentThread().interrupt(); error = Code.interrupted; }
            else error = Code.unclassified;
            projectFailure(failure);
        }
        finally {
            observeThreads("controls", baseline);
            if (serialized != null) Arrays.fill(serialized, (byte) 0);
            try { stopServices(); } catch (Throwable ignored) { CLEANUP.put("cleanup_completed", false); }
            try { cleanup(server, baseline); } catch (Throwable ignored) { CLEANUP.put("cleanup_completed", false); }
            finally { THREAD_ORIGINS.clear(); }
        }
        boolean clean = CLEANUP.values().stream().allMatch(Boolean.TRUE::equals);
        if (!clean && error == null) error = Code.cleanup_failed;
        if (!threadObservationsComplete() && error == null) error = Code.cleanup_failed;
        if (BACKGROUND_FAILURE.get() && error == null) error = Code.background_failure;
        boolean success = error == null && CHECKS.values().stream().allMatch(Boolean.TRUE::equals) && clean;
        report.println("{\"schema_version\":1,\"scope\":\"hdfs_kerberos_rpc_feasibility\",\"success\":" + success
            + ",\"expected_kerby_version\":\"2.1.2\",\"runtime_binding_required\":true,\"checks\":" + boolMap(CHECKS)
            + ",\"cleanup\":" + boolMap(CLEANUP) + ",\"cache_bytes\":" + cacheBytes
            + ",\"observed_lifetime_seconds\":" + observedLifetime + ",\"stage\":\"" + stage + "\",\"wire_hex\":\"" + wireHex + "\",\"error\":"
            + (error == null ? "null" : "\"" + error.name() + "\"")
            + ",\"diagnostic\":{\"category\":\"" + diagnosticCategory + "\",\"origin\":\"" + diagnosticOrigin + "\"}"
            + ",\"remaining_threads\":" + threadCountsJson(remainingThreads, THREAD_CATEGORIES)
            + ",\"thread_observation_complete\":" + threadObservationsComplete()
            + ",\"remaining_thread_intervals\":" + threadCountsJson(remainingThreadIntervals, THREAD_PHASES)
            + ",\"remaining_thread_matrix\":" + threadMatrixJson()
            + ",\"remaining_timer_kinds\":" + threadCountsJson(remainingTimerKinds, TIMER_KINDS)
            + ",\"owned_thread_cleanup\":{\"gc_monitor\":\"" + gcCleanup.name()
            + "\",\"fs_statistics_cleaner\":\"" + statisticsCleanup.name()
            + "\",\"format_ssl_timer\":\"" + sslCleanup.name() + "\"}"
            + ",\"rclone_wire_hex\":\"" + rcloneWireHex + "\",\"relay\":" + (relay == null ? "null" : relay.json())
            + ",\"ledger_eligible\":false,\"authentication_verified\":false,\"hdfs_authenticated\":false"
            + ",\"renewal_verified\":false,\"daemon_accepted\":false,\"provider_accepted\":false"
            + ",\"application_accepted\":false,\"vendor_accepted\":false,\"vulnerability_audited\":false}");
        report.flush(); System.exit(success ? 0 : 1);
    }
}
