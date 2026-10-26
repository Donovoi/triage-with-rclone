/* Source-only transfer experiment: one secure DataNode, synthetic private credentials, no acceptance. */
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

public final class HdfsKerberosTransferProbe {
    private static final Path WORK = Path.of("/work");
    private static final Path ROOT = WORK.resolve("private");
    private static final Path CONF = ROOT.resolve("krb5.conf");
    private static final Path CACHE = ROOT.resolve("reader.ccache");
    private static final Path KEYTAB = ROOT.resolve("service.keytab");
    private static final Path HTTP_KEYTAB = ROOT.resolve("http.keytab");
    private static final String MEMBER = "/synthetic";
    private static final String DENIAL = "SIMPLE authentication is not enabled.  Available:[TOKEN, KERBEROS]";
    private static final String EXCEPTION = "org.apache.hadoop.security.AccessControlException";
    private static final List<Process> CHILDREN = new ArrayList<>();
    private static Set<Long> processBaseline;
    private static String wireHex = "";
    private static String rcloneWireHex = "";
    private static Relay relay;
    private static String stage = "environment";
    private static long controlDeadline, totalDeadline, cleanupDeadline, materialDeadline;
    private static long ioDeadline() { return Math.min(totalDeadline, materialDeadline > 0 ? materialDeadline : cleanupDeadline > 0 ? cleanupDeadline : controlDeadline); }
    private static org.apache.hadoop.hdfs.server.datanode.DataNode datanode;
    private static boolean namenodeAttempted, datanodeAttempted, ownerCaptureComplete = true;
    private static Thread datanodeSslThread;
    private static boolean datanodeSslCaptured;
    private static final Path TLS = WORK.resolve("private-tls"), RESOURCES = WORK.resolve("tls-resources"), ACQUIRED = WORK.resolve("acquired");
    private static final Path PASSWORD = TLS.resolve("password"), STORE = TLS.resolve("server.p12"), TRUST = TLS.resolve("trust.p12"), SSL_XML = RESOURCES.resolve("owned-ssl-server.xml");
    private static final Map<Path, Object> PRIVATE_DIRS = new LinkedHashMap<>();
    private static final String[] NAMES = {"empty.bin", "nested/space name.bin", "payload.bin"};
    private static final int[] SIZES = {0, 4096, 1052673};
    private static final String[] HASHES = {"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "c8f5d0341d54d951a71b136e6e2afcb14d11ed8489a7ae126a8fee0df6ecf193", "ac6f8d639b2e2c683c08d7deae690d1b6120bd74bc80a39a895481450082c571"};
    private static final String[] PHASE_NAMES = {"inventory_before", "empty", "small", "missing", "before", "negative", "after", "inventory_after"};
    private static final Map<String, String> SOURCE_METADATA = new LinkedHashMap<>();
    private static int acquiredBytes;
    private static String dnUuid;
    private static javax.net.ssl.SSLContext tlsContext;
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
    private static final List<String> THREAD_PHASES = List.of("tls", "kdc", "owner_login", "format", "namenode",
        "filesystem", "datanode", "reader", "controls", "shutdown", "unattributed");
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
        source_invalid, relay_invalid, tls_invalid, datanode_failed, missing_path_mismatch, acquisition_invalid,
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
        final Object key; final byte[] digest; final int size;
        FileState(Path path) throws Exception {
            BasicFileAttributes a = Files.readAttributes(path, BasicFileAttributes.class, NOFOLLOW);
            int maximum = path.getParent().equals(ACQUIRED) ? 1052674 : MAX_BYTES;
            need(a.isRegularFile() && !a.isSymbolicLink() && a.fileKey() != null && a.size() <= maximum
                && ((Number)Files.getAttribute(path, "unix:nlink", NOFOLLOW)).intValue() == 1
                && ((Number)Files.getAttribute(path, "unix:uid", NOFOLLOW)).intValue() == 10001
                && (((Number)Files.getAttribute(path, "unix:mode", NOFOLLOW)).intValue() & 07777) == 0600, Code.path_invalid);
            key = a.fileKey(); MessageDigest hash = MessageDigest.getInstance("SHA-256"); int total = 0;
            byte[] buffer = new byte[4096];
            try (var input = Files.newInputStream(path, NOFOLLOW)) {
                int n; while ((n = input.read(buffer)) != -1) {
                    need(System.nanoTime() < ioDeadline() && (total += n) <= maximum, Code.path_invalid);
                    hash.update(buffer, 0, n);
                }
            } finally { Arrays.fill(buffer, (byte)0); }
            size = total; digest = hash.digest();
            BasicFileAttributes b = Files.readAttributes(path, BasicFileAttributes.class, NOFOLLOW);
            need(key.equals(b.fileKey()) && a.size() == size && b.size() == size
                && a.lastModifiedTime().equals(b.lastModifiedTime()), Code.source_changed);
        }
        void verify(Path path) throws Exception {
            FileState current = new FileState(path);
            need(key.equals(current.key) && size == current.size && MessageDigest.isEqual(digest, current.digest), Code.source_changed);
        }
    }
    private static void inventory() throws Exception {
        guardRoot(); Set<Path> actual = new HashSet<>();
        for (var dir : PRIVATE_DIRS.entrySet()) {
            need(dir.getValue().equals(directory(dir.getKey(), true)), Code.source_changed);
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir.getKey())) {
                for (Path path : stream) { need(actual.size() < 16, Code.unexpected_files); actual.add(path); }
            }
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
        List<ServerSocket> reservations = new ArrayList<>();
        try {
            for (int port = 19000; port <= 19007; port++) {
                ServerSocket socket = new ServerSocket(); reservations.add(socket);
                socket.bind(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127,0,0,1}), port), 1);
            }
        } finally { for (ServerSocket socket : reservations) socket.close(); }
        need(reservations.size() == 8 && reservations.stream().allMatch(ServerSocket::isClosed), Code.listener_mismatch);
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
            if (datanode != null) expected.addAll(Set.of("tcp:0100007F:4A39", "tcp:0100007F:4A3A", "tcp:0100007F:4A3C", "tcp:0100007F:4A3D"));
        }
        need(found.equals(expected), Code.listener_mismatch);
    }
    private static <T> T bounded(Callable<T> call, int seconds, long until) throws Exception {
        final long taskUntil = Math.min(until, System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds));
        need(taskUntil - System.nanoTime() > 0, Code.deadline_exceeded);
        FutureTask<T> task = new FutureTask<>(call);
        Thread thread = new Thread(task, "synthetic-ticket-task"); thread.setDaemon(true); TASKS.add(thread);
        T result;
        try {
            thread.start();
            // Thread startup consumes the original budget, never a fresh timeout.
            long remaining = taskUntil - System.nanoTime();
            need(remaining > 0, Code.deadline_exceeded);
            result = task.get(remaining, TimeUnit.NANOSECONDS);
            need(System.nanoTime() < taskUntil, Code.deadline_exceeded);
        } catch (TimeoutException e) { task.cancel(true); throw new Failure(Code.deadline_exceeded); }
        catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception) throw (Exception) cause;
            // Retain the cause only in memory for closed diagnostic projection.
            throw new Failure(Code.unclassified, cause);
        } finally {
            // Covers startup-budget exhaustion, interruption, and all owned failures.
            if (!task.isDone()) task.cancel(true);
            long left = Math.min(TimeUnit.MILLISECONDS.toNanos(200), taskUntil - System.nanoTime());
            if (left > 0) thread.join(left / 1_000_000L, (int)(left % 1_000_000L));
        }
        need(System.nanoTime() < taskUntil, Code.deadline_exceeded);
        return result;
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
            need(THREAD_PHASES.subList(0, 10).contains(phase) && OBSERVED_PHASES.add(phase)
                && OBSERVED_PHASES.size() <= 10, Code.cleanup_failed);
            int live = 0;
            for (Thread thread : Thread.getAllStackTraces().keySet()) {
                if (!thread.isAlive() || baseline.contains(thread.getId())) continue;
                need(++live <= 128, Code.cleanup_failed);
                if (!THREAD_ORIGINS.containsKey(thread)) {
                    need(THREAD_ORIGINS.size() < 1280, Code.cleanup_failed);
                    THREAD_ORIGINS.put(thread, phase);
                }
            }
        } catch (Throwable ignored) { threadObservationIncomplete = true; }
    }
    private static boolean threadObservationsComplete() {
        return !threadObservationIncomplete && OBSERVED_PHASES.size() == 10;
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
        if (!List.of("children_reaped", "relay_closed", "filesystem_closed", "namenode_stop_returned", "datanode_stop_returned", "datanode_ssl_timer_reaped",
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
        if (!List.of("children_reaped", "relay_closed", "filesystem_closed", "namenode_stop_returned", "datanode_stop_returned", "datanode_ssl_timer_reaped",
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
            if (server != null) bounded(() -> { server.stop(); return null; }, 3, cleanupDeadline);
            stopped = true;
        } catch (Throwable ignored) { stopped = false; }
        CLEANUP.put("kdc_stop_returned", stopped);
        observeThreads("shutdown", baseline);
        boolean threadsClean = false;
        long until = Math.min(cleanupDeadline, System.nanoTime() + TimeUnit.SECONDS.toNanos(3));
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
        if (rootOwned && stopped && threadsClean && noListeners && List.of("children_reaped", "relay_closed", "filesystem_closed", "namenode_stop_returned", "owner_logged_out", "gc_monitor_reaped", "fs_statistics_cleaner_reaped", "format_ssl_timer_reaped", "datanode_stop_returned", "datanode_ssl_timer_reaped").stream().allMatch(k -> Boolean.TRUE.equals(CLEANUP.get(k)))) {
            try {
                materialDeadline = cap(2); guardRoot();
                // stop() removes its config. No unknown/replaced file is deleted.
                if (!Files.exists(CONF, NOFOLLOW)) OWNED_FILES.remove(CONF);
                inventory();
                for (var entry : OWNED_FILES.entrySet()) {
                    guardRoot(); need(System.nanoTime() < materialDeadline, Code.deadline_exceeded);
                    entry.getValue().verify(entry.getKey()); Files.delete(entry.getKey());
                }
                for (Path path : PRIVATE_DIRS.keySet()) {
                    need(System.nanoTime() < materialDeadline, Code.deadline_exceeded);
                    need(PRIVATE_DIRS.get(path).equals(directory(path, true)), Code.source_changed);
                    try (DirectoryStream<Path> stream = Files.newDirectoryStream(path)) {
                        need(!stream.iterator().hasNext(), Code.unexpected_files);
                    }
                    Files.delete(path);
                }
                removed = System.nanoTime() < materialDeadline && PRIVATE_DIRS.keySet().stream().noneMatch(p -> Files.exists(p, NOFOLLOW));
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
        final int[] counts = new int[8];
        volatile boolean running = true;
        int phase = -1, nextPhase, noneHeaders, fatalResponses, unexpected;
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
                            if (ownedPhase < 0 || ownedPhase > 7 || counts[ownedPhase] >= 1) {
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
            need(!failed.get() && phase == -1 && value == nextPhase && value >= 0 && value <= 7 && counts[value] == 0
                && sessions.stream().noneMatch(Thread::isAlive), Code.relay_invalid);
            phase = value;
        }
        void end(int value) throws Exception {
            long until = Math.min(controlDeadline, System.nanoTime() + TimeUnit.SECONDS.toNanos(3));
            for (Thread session : sessions) {
                long left = until - System.nanoTime(); need(left > 0, Code.relay_invalid);
                session.join(Math.max(1, TimeUnit.NANOSECONDS.toMillis(left)));
            }
            synchronized (this) {
                need(phase == value && counts[value] == 1 && !failed.get()
                    && sessions.stream().noneMatch(Thread::isAlive), Code.relay_invalid);
                phase = -1; nextPhase++;
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
                byte auth = ownedPhase == 5 ? (byte)0 : (byte)0xdf;
                need(Arrays.equals(header, new byte[]{'h','r','p','c',9,0,auth}), Code.relay_invalid);
                synchronized (this) { need(phase == ownedPhase, Code.relay_invalid); if (ownedPhase == 5) noneHeaders++; }
                upstream.connect(endpoint, 2000); upstream.setSoTimeout(5000);
                need(upstream.getPort() == 19000 && upstream.getInetAddress().isLoopbackAddress(), Code.relay_invalid);
                upstream.getOutputStream().write(header); upstream.getOutputStream().flush();
                upload = new Thread(() -> {
                    try { pump(incoming, upstream, closing); }
                    catch (Throwable error) { if (!closing.get()) uploadFailed.set(true); }
                }, "owned-rpc-relay-upload");
                upload.setDaemon(true); TASKS.add(upload); upload.start();
                if (ownedPhase == 5) {
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
                try { long left = Math.min(TimeUnit.SECONDS.toNanos(1), controlDeadline - System.nanoTime()); if (upload != null && left > 0) upload.join(left / 1_000_000L, (int)(left % 1_000_000L)); } catch (InterruptedException error) { failed.set(true); }
                if (upload != null && upload.isAlive() || uploadFailed.get() && !captured) failed.set(true);
            }
        }
        boolean stop(long until) {
            running = false;
            try { listener.close(); } catch (IOException ignored) { failed.set(true); }
            for (Socket socket : sockets) try { socket.close(); } catch (IOException ignored) { failed.set(true); }
            List<Thread> threads = new ArrayList<>(sessions); threads.add(acceptor);
            for (Thread thread : threads) {
                try { long left = until - System.nanoTime(); if (left <= 0) return false; thread.join(left / 1_000_000L, (int)(left % 1_000_000L)); }
                catch (InterruptedException ignored) { Thread.currentThread().interrupt(); return false; }
            }
            return listener.isClosed() && sockets.stream().allMatch(Socket::isClosed)
                && threads.stream().noneMatch(Thread::isAlive);
        }
        synchronized String json() {
            StringBuilder text=new StringBuilder("{\"phase_connections\":{");
            for(int i=0;i<8;i++) { if(i>0)text.append(','); text.append('"').append(PHASE_NAMES[i]).append("\":").append(counts[i]); }
            return text + "},\"none_headers\":"+noneHeaders+",\"fatal_responses\":"+fatalResponses
                +",\"unexpected_connections\":"+unexpected+",\"bytes_forwarded_unchanged\":"+!failed.get()+"}";
        }
    }
    private static byte[] childRead(java.io.InputStream input) throws Exception {
        try(input) { byte[] data=input.readNBytes(16385); need(data.length<=16384, Code.child_output_invalid); return data; }
    }
    private static final class Result {
        final int code; final byte[] out,err;
        Result(int c,byte[] o,byte[] e) {code=c;out=o;err=e;}
    }
    private static final class StreamWitness {
        final int size; final byte[] digest;
        StreamWitness(int n, byte[] h) {size=n;digest=h;}
    }
    private static Result child(List<String> command, Map<String,String> env) throws Exception {
        return child(command,env,null,0);
    }
    private static Result child(List<String> command, Map<String,String> env, Path target, int expected) throws Exception {
        need(System.nanoTime()<controlDeadline && CHILDREN.size()<10, Code.deadline_exceeded);
        need(target==null || target.getParent().equals(ACQUIRED) && expected>=0 && expected<=1052673, Code.acquisition_invalid);
        FileState initial=null;
        if(target!=null) { privateBytes(target,new byte[0]); initial=OWNED_FILES.get(target); }
        final FileState original=initial;
        ProcessBuilder builder=new ProcessBuilder(command); builder.environment().clear(); builder.environment().putAll(env); builder.directory(WORK.toFile());
        Process process=builder.start(); CHILDREN.add(process); process.getOutputStream().close();
        FutureTask<byte[]> stdout=new FutureTask<>(()-> target==null ? childRead(process.getInputStream()) : new byte[0]);
        FutureTask<StreamWitness> streamed=new FutureTask<>(()-> {
            MessageDigest digest=MessageDigest.getInstance("SHA-256"); int total=0; byte[] buffer=new byte[4096];
            try(var input=process.getInputStream(); var output=FileChannel.open(target, StandardOpenOption.WRITE, NOFOLLOW)) {
                need(original.key.equals(Files.readAttributes(target,BasicFileAttributes.class,NOFOLLOW).fileKey()),Code.source_changed);
                while(true) {
                    need(System.nanoTime()<controlDeadline,Code.deadline_exceeded);
                    int n=input.read(buffer,0,Math.min(buffer.length, expected-total+1)); if(n==-1)break;
                    // Read at most expected+1, but never retain the overflow byte.
                    need(total+n<=expected,Code.acquisition_invalid); total+=n;digest.update(buffer,0,n);
                    ByteBuffer bytes=ByteBuffer.wrap(buffer,0,n);while(bytes.hasRemaining())output.write(bytes);
                } output.force(true);
                return new StreamWitness(total,digest.digest());
            } finally {Arrays.fill(buffer,(byte)0);}
        });
        FutureTask<byte[]> stderr=new FutureTask<>(()->childRead(process.getErrorStream()));
        Thread out=new Thread(target==null?stdout:streamed,"owned-rclone-stdout"),err=new Thread(stderr,"owned-rclone-stderr");
        out.setDaemon(true);err.setDaemon(true);TASKS.add(out);TASKS.add(err);out.start();err.start();
        try {
            long until=Math.min(controlDeadline,System.nanoTime()+TimeUnit.SECONDS.toNanos(12));
            while(process.isAlive()) {
                need(System.nanoTime()<until,Code.deadline_exceeded);
                if(stderr.isDone())stderr.get();
                if(target==null && stdout.isDone())stdout.get();
                if(target!=null && streamed.isDone())streamed.get();
                process.waitFor(Math.min(TimeUnit.MILLISECONDS.toNanos(25),Math.max(1,until-System.nanoTime())),TimeUnit.NANOSECONDS);
            }
            need(process.descendants().findAny().isEmpty(),Code.child_descendant_found);
            byte[] stderrBytes=stderr.get(Math.max(1,until-System.nanoTime()),TimeUnit.NANOSECONDS);
            byte[] stdoutBytes=target==null?stdout.get(Math.max(1,until-System.nanoTime()),TimeUnit.NANOSECONDS):new byte[0];
            if(target!=null) {
                StreamWitness observed=streamed.get(Math.max(1,until-System.nanoTime()),TimeUnit.NANOSECONDS);
                FileState independentlyRead=new FileState(target);
                need(original.key.equals(independentlyRead.key) && observed.size==independentlyRead.size
                    && MessageDigest.isEqual(observed.digest,independentlyRead.digest),Code.acquisition_invalid);
                OWNED_FILES.put(target,independentlyRead);
            }
            return new Result(process.exitValue(),stdoutBytes,stderrBytes);
        } finally {
            if(process.isAlive())process.destroyForcibly();
            long until=Math.min(controlDeadline,System.nanoTime()+TimeUnit.SECONDS.toNanos(3));
            need(process.waitFor(Math.max(1,until-System.nanoTime()),TimeUnit.NANOSECONDS),Code.child_reap_failed);
            process.getInputStream().close();process.getErrorStream().close();
            for(Thread thread:List.of(out,err)) {long left=until-System.nanoTime();if(left>0)thread.join(left/1_000_000L,(int)(left%1_000_000L));}
            need(!out.isAlive()&&!err.isAlive(),Code.child_streams_alive);
        }
    }
    private static Map<String,String> plainEnvironment() {
        return Map.of("HOME","/work/home","PATH","/usr/bin:/bin","LANG","C","LC_ALL","C");
    }
    private static Result rclone(String reader, int phase, String member, boolean listing, boolean authenticated, int expected) throws Exception {
        need(phase>=0&&phase<8,Code.relay_invalid); List<String> command=new ArrayList<>(List.of("/opt/transfer/rclone",
            listing?"lsjson":"cat",":hdfs:"+MEMBER+(member.isEmpty()?"":"/"+member),"--config","/dev/null",
            "--hdfs-namenode","127.0.0.1:19007","--hdfs-username",reader,"--log-level","ERROR","--use-json-log",
            "--retries","1","--low-level-retries","1","--contimeout","3s","--timeout","8s","--disable","ListR",
            "--buffer-size","0","--checkers","1","--transfers","1","--stats","0"));
        if(listing)command.addAll(List.of("--recursive","--files-only"));
        Map<String,String> env=new LinkedHashMap<>(plainEnvironment());
        if(authenticated) {
            command.addAll(List.of("--hdfs-service-principal-name","hdfs/127.0.0.1","--hdfs-data-transfer-protection","privacy"));
            env.put("KRB5_CONFIG",CONF.toString());env.put("KRB5CCNAME","FILE:"+CACHE);
        }
        relay.begin(phase); Result result=child(command,env,listing?null:ACQUIRED.resolve("phase-"+phase+".bin"),expected);relay.end(phase);
        return result;
    }
    private static com.fasterxml.jackson.databind.ObjectMapper jsonMapper() {
        return new com.fasterxml.jackson.databind.ObjectMapper()
            .enable(com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    }
    private static void listing(String reader,int phase) throws Exception {
        Result result=rclone(reader,phase,"",true,true,0);need(result.code==0&&result.err.length==0,Code.rclone_positive_failed);
        var rows=jsonMapper().readTree(result.out);need(rows.isArray()&&rows.size()==3,Code.source_invalid); Set<String> found=new HashSet<>();
        for(var row:rows) {
            need(row.isObject()&&row.has("Path")&&row.get("Path").isTextual(),Code.source_invalid);
            String path=row.get("Path").asText();int i=List.of(NAMES).indexOf(path);
            need(i>=0&&found.add(path)&&row.get("Size").isIntegralNumber()&&row.get("Size").asLong()==SIZES[i]
                &&row.get("IsDir").isBoolean()&&!row.get("IsDir").asBoolean()
                &&row.get("Name").isTextual()&&row.get("Name").asText().equals(path.substring(path.lastIndexOf('/')+1))
                &&java.time.Instant.parse(row.get("ModTime").asText()).toEpochMilli()==1704067200000L,Code.source_invalid);
            var names=row.fieldNames();while(names.hasNext())need(Set.of("Path","Name","Size","MimeType","ModTime","IsDir").contains(names.next()),Code.source_invalid);
        }
        inventory();topology();
    }
    private static void acquire(String reader,int phase,int index) throws Exception {
        Result result=rclone(reader,phase,NAMES[index],false,true,SIZES[index]);
        FileState file=OWNED_FILES.get(ACQUIRED.resolve("phase-"+phase+".bin"));
        need(result.code==0&&result.err.length==0&&file.size==SIZES[index]
            &&java.util.HexFormat.of().formatHex(file.digest).equals(HASHES[index]),Code.acquisition_invalid);
        need(acquiredBytes+file.size<=2109442,Code.acquisition_invalid);inventory();topology();acquiredBytes+=file.size;
    }
    private static void missing(String reader) throws Exception {
        Result result=rclone(reader,3,"missing-synthetic.bin",false,true,0);
        need(result.code!=0&&OWNED_FILES.get(ACQUIRED.resolve("phase-3.bin")).size==0,Code.missing_path_mismatch);
        // Pinned Cat -> ListFn -> List -> ensureDirectory maps absent path to ErrorDirNotFound.
        // JSON logging removes timestamp/text-prefix ambiguity; no generic error is accepted.
        var error=jsonMapper().readTree(result.err);
        need(error.isObject()&&error.size()==6&&error.path("level").isTextual()&&error.path("level").asText().equals("error")
            &&error.path("msg").asText().equals("error listing: directory not found")
            &&error.path("object").isTextual()&&error.path("object").asText().isEmpty()
            &&error.path("objectType").asText().equals("string")&&error.path("source").isTextual()
            &&error.path("time").isTextual(),Code.missing_path_mismatch);
        bounded(()->{need(!filesystem.exists(sourcePath("missing-synthetic.bin")),Code.missing_path_mismatch);return null;},3,controlDeadline);
        inventory();topology();
    }
    private static void negative(String reader) throws Exception {
        Result result=rclone(reader,5,NAMES[2],false,false,0);
        need(result.code!=0,Code.rclone_denial_exit_zero);
        need(OWNED_FILES.get(ACQUIRED.resolve("phase-5.bin")).size==0,Code.rclone_denial_output_invalid);
        need(relay.counts[5]==1&&relay.noneHeaders==1&&relay.fatalResponses==1&&!rcloneWireHex.isEmpty(),Code.rclone_denial_mismatch);
        inventory();topology();
    }
    private static String acquisitionsJson() {
        StringBuilder text=new StringBuilder("{");
        for(int phase=1;phase<=6;phase++) {
            if(phase>1)text.append(',');text.append('"').append(PHASE_NAMES[phase]).append("\":");
            FileState value=OWNED_FILES.get(ACQUIRED.resolve("phase-"+phase+".bin"));
            if(value==null)text.append("null");
            else {
                String hash=java.util.HexFormat.of().formatHex(value.digest);
                text.append("{\"bytes\":").append(value.size).append(",\"sha256\":\"")
                    .append(List.of(HASHES).contains(hash)?hash:"mismatch").append("\"}");
            }
        }
        return text.append('}').toString();
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
        conf.set("dfs.http.policy", "HTTPS_ONLY");
        conf.set("dfs.namenode.https-address", "127.0.0.1:19003");
        conf.set("dfs.namenode.https-bind-host", "127.0.0.1");
        conf.set("dfs.datanode.address", "127.0.0.1:19001");
        conf.set("dfs.datanode.ipc.address", "127.0.0.1:19002");
        conf.set("dfs.datanode.http.address", "127.0.0.1:19004");
        conf.set("dfs.datanode.https.address", "127.0.0.1:19004");
        conf.set("dfs.datanode.http.internal-proxy.port", "19005");
        conf.set("dfs.datanode.hostname", "127.0.0.1");
        conf.set("dfs.datanode.kerberos.principal", "hdfs/127.0.0.1@" + realm);
        conf.set("dfs.datanode.keytab.file", KEYTAB.toString());
        conf.set("dfs.data.transfer.protection", "privacy");
        conf.set("dfs.encrypt.data.transfer", "false");
        conf.set("ignore.secure.ports.for.testing", "false");
        conf.set("dfs.blocksize", "1048576");
        conf.set("dfs.datanode.max.locked.memory", "0");
        conf.set("dfs.client.use.datanode.hostname", "false");
        conf.set("dfs.datanode.use.datanode.hostname", "false");
        conf.set("dfs.datanode.data.dir", WORK.resolve("state/data").toUri().toString());
        conf.set("dfs.https.server.keystore.resource", "owned-ssl-server.xml");
        conf.set("hadoop.ssl.server.conf", "owned-ssl-server.xml");
        conf.set("dfs.client.https.need-auth", "false");
        conf.set("hadoop.ssl.require.client.cert", "false");

        conf.set("hadoop.security.authentication", "kerberos");
        // No defaults are loaded: secure HttpServer2 requires an explicit type.
        // Its separate AuthFilter reads this prefix, not the dfs.web.* keys
        // used below by the internal SPNEGO filter. Both use the owned HTTP key.
        conf.set("hadoop.http.authentication.type", "kerberos");
        conf.set("hadoop.http.authentication.kerberos.principal", "HTTP/127.0.0.1@" + realm);
        conf.set("hadoop.http.authentication.kerberos.keytab", HTTP_KEYTAB.toString());
        // BlockManager requires tokens during secure NameNode formatting;
        // this sibling also requires them for secure DataNode byte transfers.
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
            && namenode.getHttpAddress() == null && namenode.getHttpsAddress().getPort() == 19003
            && namenode.getHttpsAddress().getAddress().getHostAddress().equals("127.0.0.1")
            && namenode.getAuxiliaryNameNodeAddresses().isEmpty() && UserGroupInformation.isSecurityEnabled(), Code.namenode_failed);
        if (datanode != null) {
            var dn = datanode.getDnConf(); var resolver = dn.getTrustedChannelResolver();
            need(datanode.getXferAddress().getPort() == 19001 && datanode.getXferAddress().getAddress().getHostAddress().equals("127.0.0.1")
                && datanode.getIpcPort() == 19002 && datanode.getInfoPort() == 0 && datanode.getInfoSecurePort() == 19004
                && !dn.getIgnoreSecurePortsForTesting() && !dn.getEncryptDataTransfer() && dn.getSaslPropsResolver() != null
                && "auth-conf".equals(dn.getSaslPropsResolver().getServerProperties(InetAddress.getByName("127.0.0.1")).get(javax.security.sasl.Sasl.QOP))
                && resolver != null && resolver.getClass() == org.apache.hadoop.hdfs.protocol.datatransfer.TrustedChannelResolver.class
                && !resolver.isTrusted() && !resolver.isTrusted(InetAddress.getByName("127.0.0.1")), Code.datanode_failed);
            for (Configuration conf : List.of(namenode.getConf(), datanode.getConf())) {
                need("HTTPS_ONLY".equals(conf.get("dfs.http.policy")) && "kerberos".equals(conf.get("hadoop.security.authentication"))
                    && conf.getBoolean("dfs.block.access.token.enable", false) && "privacy".equals(conf.get("dfs.data.transfer.protection"))
                    && !conf.getBoolean("ignore.secure.ports.for.testing", true)
                    && conf.get("dfs.datanode.ignore.secure.ports.for.testing") == null
                    && !conf.getBoolean("ipc.client.fallback-to-simple-auth-allowed", true)
                    && !conf.getBoolean("dfs.client.read.shortcircuit", true) && "".equals(conf.get("dfs.domain.socket.path"))
                    && "owned-ssl-server.xml".equals(conf.get("dfs.https.server.keystore.resource"))
                    && "owned-ssl-server.xml".equals(conf.get("hadoop.ssl.server.conf")), Code.configuration_invalid);
            }
        }
        listeners(true); need(processIds().equals(processBaseline), Code.child_process_drift);
        need(ExitUtil.getFirstExitException() == null && ExitUtil.getFirstHaltException() == null, Code.namenode_failed);
    }
    private static org.apache.hadoop.fs.Path sourcePath(String name) { return new org.apache.hadoop.fs.Path(MEMBER + "/" + name); }
    private static void registered() throws Exception {
        var nodes = filesystem.getDataNodeStats(org.apache.hadoop.hdfs.protocol.HdfsConstants.DatanodeReportType.LIVE);
        need(nodes.length == 1 && nodes[0].getCapacity() > 0 && nodes[0].getDatanodeUuid().equals(datanode.getDatanodeUuid())
            && nodes[0].getIpAddr().equals("127.0.0.1") && nodes[0].getXferPort() == 19001 && nodes[0].getIpcPort() == 19002
            && nodes[0].getInfoSecurePort() == 19004, Code.datanode_failed);
        if (dnUuid == null) dnUuid = nodes[0].getDatanodeUuid();
        need(dnUuid.equals(nodes[0].getDatanodeUuid()), Code.datanode_failed);
    }
    private static void seed() throws Exception {
        while (true) {
            need(System.nanoTime() < deadline, Code.deadline_exceeded);
            var nodes = filesystem.getDataNodeStats(org.apache.hadoop.hdfs.protocol.HdfsConstants.DatanodeReportType.LIVE);
            need(nodes.length <= 1, Code.datanode_failed);
            if (nodes.length == 1 && nodes[0].getCapacity() > 0) break;
            Thread.sleep(50);
        }
        registered(); filesystem.setSafeMode(SafeModeAction.SAFEMODE_LEAVE);
        need(filesystem.mkdirs(new org.apache.hadoop.fs.Path(MEMBER + "/nested"), new FsPermission((short)0755)), Code.source_invalid);
        byte[] data = new byte[4096]; for (int i=0; i<data.length; i++) data[i]=(byte)i;
        for (int i=0; i<NAMES.length; i++) {
            var path = sourcePath(NAMES[i]); need(!filesystem.exists(path), Code.source_invalid);
            try (var output = filesystem.create(path, new FsPermission((short)0644), false, 4096, (short)1, 1048576, null)) {
                for (int offset=0; offset<SIZES[i]; offset+=data.length) {
                    need(System.nanoTime() < deadline, Code.deadline_exceeded);
                    output.write(data, 0, Math.min(data.length, SIZES[i]-offset));
                }
                output.hsync();
            }
            filesystem.setTimes(path, 1704067200000L, 1704067200000L);
        }
        Arrays.fill(data, (byte)0);
        filesystem.setPermission(new org.apache.hadoop.fs.Path(MEMBER), new FsPermission((short)0755));
        for (String dir : List.of(MEMBER, MEMBER + "/nested")) filesystem.setTimes(new org.apache.hadoop.fs.Path(dir), 1704067200000L, 1704067200000L);
    }
    private static void verifyMember() throws Exception {
        registered(); Set<String> found = new HashSet<>(); var iterator = filesystem.listFiles(new org.apache.hadoop.fs.Path(MEMBER), true);
        while (iterator.hasNext()) { var entry = iterator.next(); need(found.size() < 3 && found.add(entry.getPath().toUri().getPath()), Code.source_invalid); }
        need(found.equals(Set.of(MEMBER+"/"+NAMES[0], MEMBER+"/"+NAMES[1], MEMBER+"/"+NAMES[2])), Code.source_invalid);
        var rootRows = filesystem.listStatus(new org.apache.hadoop.fs.Path(MEMBER));
        var nestedRows = filesystem.listStatus(sourcePath("nested"));
        need(rootRows.length == 3 && nestedRows.length == 1 && !filesystem.exists(sourcePath("missing-synthetic.bin")), Code.source_invalid);
        List<String> paths = new ArrayList<>(List.of("", "nested")); paths.addAll(List.of(NAMES));
        for (String name : paths) {
            var path = name.isEmpty() ? new org.apache.hadoop.fs.Path(MEMBER) : sourcePath(name); var info=filesystem.getFileStatus(path);
            boolean dir = name.isEmpty() || name.equals("nested");
            need(!info.isSymlink() && info.isDirectory() == dir && info.getOwner().equals("hdfs")
                && info.getPermission().toShort() == (dir ? 0755 : 0644) && info.getModificationTime() == 1704067200000L, Code.source_invalid);
            String metadata = info.getOwner()+":"+info.getGroup()+":"+info.getPermission().toShort()+":"+info.getLen()+":"+info.getModificationTime()+":"+info.getAccessTime()+":"+info.getReplication();
            if (!SOURCE_METADATA.containsKey(name)) SOURCE_METADATA.put(name, metadata);
            need(SOURCE_METADATA.get(name).equals(metadata), Code.source_invalid);
            if (dir) continue;
            int index=List.of(NAMES).indexOf(name); need(info.getLen()==SIZES[index] && info.getReplication()==1 && info.getBlockSize()==1048576, Code.source_invalid);
            MessageDigest digest=MessageDigest.getInstance("SHA-256"); byte[] buffer=new byte[4096]; int count=0;
            try (var input=filesystem.open(path, 4096)) {
                int n; while((n=input.read(buffer))!=-1) {
                    need(System.nanoTime()<totalDeadline && count+n<=SIZES[index], Code.source_invalid);
                    for(int k=0;k<n;k++) need(buffer[k]==(byte)(count+k), Code.source_invalid);
                    count+=n; digest.update(buffer,0,n);
                }
            } finally { Arrays.fill(buffer,(byte)0); }
            need(count==SIZES[index] && java.util.HexFormat.of().formatHex(digest.digest()).equals(HASHES[index]), Code.source_invalid);
            var blocks=filesystem.getFileBlockLocations(info,0,info.getLen());
            need(blocks.length==(index==2?2:index==1?1:0), Code.source_invalid); long length=0;
            for(var block:blocks) {
                need(!block.isCorrupt() && block.getOffset()==length && Arrays.equals(block.getNames(),new String[]{"127.0.0.1:19001"}), Code.source_invalid);
                length+=block.getLength();
            }
            need(length==info.getLen(), Code.source_invalid);
        }
    }

    private static String configurationDigest() throws Exception {
        Map<String, String> settings = new java.util.TreeMap<>();
        for (Map.Entry<String, String> entry : namenode.getConf()) settings.put("nn:" + entry.getKey(), entry.getValue());
        for (Map.Entry<String, String> entry : datanode.getConf()) settings.put("dn:" + entry.getKey(), entry.getValue());
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
        try {
            UserGroupInformation current = UserGroupInformation.getLoginUser();
            need(current.getUserName().equals(ownerPrincipal) && current.isFromKeytab()
                && current.hasKerberosCredentials(), Code.namenode_failed);
            if (!OWNERS.contains(current)) { need(OWNERS.size() < 4, Code.namenode_failed); OWNERS.add(current); }
            owner = current;
        } catch (Throwable failure) {
            ownerCaptureComplete = false;
            if (failure instanceof Exception exception) throw exception;
            throw new Failure(Code.namenode_failed, failure);
        }
    }
    private static long cap(int seconds) { return Math.min(cleanupDeadline, System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds)); }
    private static void stopServices() {
        long until = cap(4); boolean children = true;
        for (Process child : CHILDREN) {
            try {
                if (child.isAlive()) child.destroyForcibly();
                long left = until - System.nanoTime();
                children &= left > 0 && child.waitFor(left, TimeUnit.NANOSECONDS);
            } catch (Throwable ignored) { children = false; }
        }
        CLEANUP.put("children_reaped", children && (processBaseline == null || processIds().equals(processBaseline)));
        boolean relayClosed = relay == null;
        try { if (relay != null) relayClosed = relay.stop(until); } catch (Throwable ignored) { relayClosed = false; }
        CLEANUP.put("relay_closed", relayClosed);
        boolean closed = true;
        try { if (filesystem != null) bounded(() -> { filesystem.close(); return null; }, 3, cleanupDeadline); }
        catch (Throwable ignored) { closed = false; }
        CLEANUP.put("filesystem_closed", closed);
        // A partial constructor or failed return cannot claim a stopped object.
        boolean dnStopped = !datanodeAttempted; long dnUntil = cap(35);
        try { if (datanode != null) { bounded(() -> { datanode.shutdown(); return null; }, 35, dnUntil); dnStopped = true; } }
        catch (Throwable ignored) { dnStopped = false; }
        CLEANUP.put("datanode_stop_returned", dnStopped);
        // Public DataNode.shutdown -> DatanodeHttpServer.close -> SSLFactory.destroy.
        // No reflection, cancellation or interruption of a timer. Exact retained identity only.
        boolean dnSslStopped = !datanodeAttempted;
        if (dnStopped && datanodeSslCaptured && datanodeSslThread != null) {
            try {
                long left = Math.min(TimeUnit.MILLISECONDS.toNanos(250), dnUntil - System.nanoTime());
                if (left > 0) datanodeSslThread.join(left / 1_000_000L, (int)(left % 1_000_000L));
                dnSslStopped = !datanodeSslThread.isAlive();
            } catch (Throwable ignored) { dnSslStopped = false; }
        }
        CLEANUP.put("datanode_ssl_timer_reaped", dnSslStopped);
        boolean stopped = !namenodeAttempted;
        try { if (namenode != null) { bounded(() -> { namenode.stop(); return null; }, 7, cleanupDeadline); stopped = true; } }
        catch (Throwable ignored) { stopped = false; }
        CLEANUP.put("namenode_stop_returned", stopped);
        boolean loggedOut = ownerCaptureComplete; long logoutUntil = cap(3);
        for (UserGroupInformation login : OWNERS) {
            try { bounded(() -> { login.logoutUserFromKeytab(); return null; }, 3, logoutUntil); }
            catch (Throwable ignored) { loggedOut = false; }
        }
        CLEANUP.put("owner_logged_out", loggedOut);
    }

    public static void main(String[] args) {
        PrintStream report = System.out;
        System.setOut(new PrintStream(OutputStream.nullOutputStream()));
        System.setErr(new PrintStream(OutputStream.nullOutputStream()));
        Thread.setDefaultUncaughtExceptionHandler((thread, error) -> BACKGROUND_FAILURE.set(true));
        for (String name : List.of("environment", "endpoint_settings", "positive_tgt", "file_cache_v3",
                "nonrenewable", "secure_namenode", "secure_datanode", "tls_material", "tls_endpoints", "registered_datanode", "seed_hashes", "listing_before", "empty_acquired", "small_acquired", "missing_path_rejected", "payload_before", "payload_after", "rclone_auth_boundary_rejection",
                "wire_auth_boundary_rejection", "listing_after", "source_preserved", "cache_preserved")) CHECKS.put(name, false);
        for (String name : List.of("children_reaped", "relay_closed", "filesystem_closed", "namenode_stop_returned", "owner_logged_out",
                "datanode_stop_returned", "datanode_ssl_timer_reaped", "gc_monitor_reaped", "fs_statistics_cleaner_reaped", "format_ssl_timer_reaped",
                "kdc_stop_returned", "threads_terminated", "listeners_absent", "private_material_removed",
                "process_property_restored", "cleanup_completed")) CLEANUP.put(name, false);
        Set<Long> baseline = threadIds(); SimpleKdcServer server = null; Code error = null;
        totalDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(185);
        deadline = Math.min(totalDeadline, System.nanoTime() + TimeUnit.SECONDS.toNanos(70));
        byte[] serialized = null;
        try {
            environment(args); processBaseline = processIds(); CHECKS.put("environment", true);
            // Prime only the JDK child reaper before the service-thread baseline.
            // The version child uses the same pinned binary and bounded supervisor.
            controlDeadline = deadline;
            stage = "rclone_version";
            Result version = child(List.of("/opt/transfer/rclone", "version", "--config", "/dev/null", "--log-level", "ERROR"),
                Map.of("HOME", "/work/home", "PATH", "/usr/bin:/bin", "LANG", "C", "LC_ALL", "C"));
            need(version.code == 0, Code.rclone_version_nonzero);
            need(version.err.length == 0, Code.rclone_version_stderr);
            need(new String(version.out, StandardCharsets.US_ASCII).startsWith("rclone v1.75.2\n"), Code.rclone_version_mismatch);
            need(processIds().equals(processBaseline), Code.child_process_drift);
            baseline = threadIds();
            Files.createDirectory(ROOT, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
            rootCreated = true; rootKey = directory(ROOT, true); rootOwned = true; PRIVATE_DIRS.put(ROOT, rootKey);
            for (Path path : List.of(TLS, RESOURCES, ACQUIRED)) { Files.createDirectory(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))); PRIVATE_DIRS.put(path, directory(path, true)); }
            guardRoot(); stage = "tls"; makeTls(); CHECKS.put("tls_material", true); observeThreads("tls", baseline);
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
            stage = "namenode_start"; namenodeAttempted = true; bounded(() -> {
                try { namenode = new NameNode(conf); } finally { rememberOwner(); } return null; }, 30, deadline);
            endpoint = namenode.getNameNodeAddress(); topology(); CHECKS.put("secure_namenode", true);
            observeThreads("namenode", baseline);
            stage = "relay_start"; relay = new Relay(); topology();
            stage = "filesystem"; bounded(() -> {
                filesystem = new DistributedFileSystem(); filesystem.initialize(URI.create("hdfs://127.0.0.1:19000"), conf);
                return null; }, 5, deadline);
            observeThreads("filesystem", baseline);
            stage = "datanode_start"; datanodeAttempted = true;
            bounded(() -> { try { datanode = org.apache.hadoop.hdfs.server.datanode.DataNode.createDataNode(new String[0], conf, null); }
                finally { rememberOwner(); } return null; }, 35, deadline);
            need(datanode != null, Code.datanode_failed); observeThreads("datanode", baseline);
            captureDatanodeSsl(baseline); topology(); CHECKS.put("secure_datanode", true);
            stage = "tls_endpoints"; verifyTlsEndpoint(19003); verifyTlsEndpoint(19004); CHECKS.put("tls_endpoints", true);
            stage = "seed"; bounded(() -> { seed(); verifyMember(); return null; }, 20, deadline);
            CHECKS.put("registered_datanode", true); CHECKS.put("seed_hashes", true);
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
            controlDeadline = Math.min(totalDeadline - TimeUnit.SECONDS.toNanos(60), System.nanoTime() + TimeUnit.SECONDS.toNanos(55));
            stage = "listing_before"; listing(reader, 0); CHECKS.put("listing_before", true);
            stage = "empty"; acquire(reader, 1, 0); CHECKS.put("empty_acquired", true);
            stage = "small"; acquire(reader, 2, 1); CHECKS.put("small_acquired", true);
            stage = "missing"; missing(reader); CHECKS.put("missing_path_rejected", true);
            stage = "payload_before"; acquire(reader, 4, 2); CHECKS.put("payload_before", true);
            stage = "rclone_none"; negative(reader); CHECKS.put("rclone_auth_boundary_rejection", true);
            stage = "wire_none"; bounded(() -> { wireOracle(); return null; }, 3, controlDeadline); CHECKS.put("wire_auth_boundary_rejection", true);
            stage = "payload_after"; acquire(reader, 6, 2); CHECKS.put("payload_after", true);
            stage = "listing_after"; listing(reader, 7); CHECKS.put("listing_after", true);
            need(acquiredBytes == 2109442, Code.acquisition_invalid);
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
            cleanupDeadline = Math.min(totalDeadline, System.nanoTime() + TimeUnit.SECONDS.toNanos(60));
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
        report.println("{\"schema_version\":1,\"scope\":\"hdfs_kerberos_transfer_feasibility\",\"success\":" + success
            + ",\"expected_kerby_version\":\"2.1.2\",\"runtime_binding_required\":true,\"checks\":" + boolMap(CHECKS)
            + ",\"cleanup\":" + boolMap(CLEANUP) + ",\"cache_bytes\":" + cacheBytes
            + ",\"child_count\":" + CHILDREN.size() + ",\"acquired_bytes\":" + acquiredBytes + ",\"acquisitions\":" + acquisitionsJson()
            + ",\"missing_category\":\"" + (Boolean.TRUE.equals(CHECKS.get("missing_path_rejected")) ? "directory_not_found" : "not_observed") + "\""
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
    private static void privateBytes(Path path, byte[] data) throws Exception {
        need(data.length <= MAX_BYTES && PRIVATE_DIRS.containsKey(path.getParent()), Code.path_invalid);
        need(PRIVATE_DIRS.get(path.getParent()).equals(directory(path.getParent(), true)), Code.source_changed);
        try (var channel = FileChannel.open(path, Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, NOFOLLOW),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) {
            ByteBuffer buffer = ByteBuffer.wrap(data); while (buffer.hasRemaining()) channel.write(buffer); channel.force(true);
        }
        OWNED_FILES.put(path, new FileState(path));
    }
    private static void makeTls() throws Exception {
        char[] password = random(new SecureRandom(), 40).toCharArray();
        byte[] passwordBytes = (new String(password) + "\n").getBytes(StandardCharsets.US_ASCII);
        try {
            privateBytes(PASSWORD, passwordBytes);
            need(!Files.exists(STORE, NOFOLLOW), Code.path_invalid);
            // Exact pinned keytool supports file modifiers; argv has paths, never private values.
            Result keytool = child(List.of("/opt/java/openjdk/bin/keytool", "-genkeypair", "-noprompt", "-alias", "owned",
                "-keyalg", "RSA", "-keysize", "2048", "-sigalg", "SHA256withRSA", "-validity", "1",
                "-dname", "CN=127.0.0.1", "-ext", "SAN=ip:127.0.0.1", "-storetype", "PKCS12",
                "-keystore", STORE.toString(), "-storepass:file", PASSWORD.toString(), "-keypass:file", PASSWORD.toString()), plainEnvironment());
            need(keytool.code == 0, Code.tls_invalid);
            Arrays.fill(keytool.out, (byte)0); Arrays.fill(keytool.err, (byte)0);
            OWNED_FILES.put(STORE, new FileState(STORE));
            java.security.KeyStore store = java.security.KeyStore.getInstance("PKCS12");
            try (var input = Files.newInputStream(STORE, NOFOLLOW)) { store.load(input, password); }
            need(store.size() == 1 && store.isKeyEntry("owned"), Code.tls_invalid);
            var cert = (java.security.cert.X509Certificate) store.getCertificate("owned"); cert.checkValidity();
            need(cert.getPublicKey() instanceof java.security.interfaces.RSAPublicKey
                && ((java.security.interfaces.RSAPublicKey)cert.getPublicKey()).getModulus().bitLength() == 2048
                && cert.getSigAlgName().equalsIgnoreCase("SHA256withRSA")
                && cert.getNotAfter().getTime() - cert.getNotBefore().getTime() == 86400000L
                && cert.getSubjectAlternativeNames().size() == 1
                && cert.getSubjectAlternativeNames().contains(List.of(7, "127.0.0.1")), Code.tls_invalid);
            java.security.KeyStore trust = java.security.KeyStore.getInstance("PKCS12"); trust.load(null, password);
            trust.setCertificateEntry("owned", cert);
            LimitedBuffer buffer = new LimitedBuffer();
            try { trust.store(buffer, password); privateBytes(TRUST, buffer.toByteArray()); } finally { buffer.erase(); }
            Configuration ssl = new Configuration(false);
            ssl.set("ssl.server.keystore.type", "PKCS12"); ssl.set("ssl.server.keystore.location", STORE.toString());
            ssl.set("ssl.server.keystore.password", new String(password)); ssl.set("ssl.server.keystore.keypassword", new String(password));
            ssl.set("ssl.server.truststore.type", "PKCS12"); ssl.set("ssl.server.truststore.location", TRUST.toString());
            ssl.set("ssl.server.truststore.password", new String(password)); ssl.set("hadoop.ssl.require.client.cert", "false");
            LimitedBuffer xml = new LimitedBuffer();
            try { ssl.writeXml(xml); privateBytes(SSL_XML, xml.toByteArray()); } finally { xml.erase(); }
            // Relative resource resolves only this one private XML after immutable classes/JARs.
            var urls = HdfsKerberosTransferProbe.class.getClassLoader().getResources("owned-ssl-server.xml");
            need(urls.hasMoreElements() && urls.nextElement().toURI().equals(SSL_XML.toUri()) && !urls.hasMoreElements(), Code.tls_invalid);
            var tm = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm()); tm.init(trust);
            tlsContext = javax.net.ssl.SSLContext.getInstance("TLS"); tlsContext.init(null, tm.getTrustManagers(), null);
            inventory();
        } finally { Arrays.fill(password, '\0'); Arrays.fill(passwordBytes, (byte)0); }
    }
    private static void verifyTlsEndpoint(int port) throws Exception {
        need(port == 19003 || port == 19004, Code.tls_invalid);
        bounded(() -> {
            try (var socket = (javax.net.ssl.SSLSocket) tlsContext.getSocketFactory().createSocket()) {
                socket.connect(new InetSocketAddress("127.0.0.1", port), 2000); socket.setSoTimeout(3000);
                var params = socket.getSSLParameters(); params.setEndpointIdentificationAlgorithm("HTTPS"); socket.setSSLParameters(params);
                socket.startHandshake(); need(socket.getSession().getPeerCertificates().length == 1, Code.tls_invalid);
            } return null;
        }, 3, deadline);
    }
    private static void captureDatanodeSsl(Set<Long> baseline) throws Exception {
        need(!threadObservationIncomplete && OBSERVED_PHASES.contains("datanode") && formatSslThread != null
            && formatSslThread.isAlive() && sslCaptureFailure == null && datanode != null, Code.cleanup_failed);
        int seen = 0;
        for (Thread thread : Thread.getAllStackTraces().keySet()) {
            if (!thread.isAlive()) continue;
            need(++seen <= 128, Code.cleanup_failed);
            if (!thread.getName().equals("SSL Certificates Store Monitor") || thread == formatSslThread) continue;
            need(datanodeSslThread == null && thread.getClass().getName().equals("java.util.TimerThread")
                && !baseline.contains(thread.getId()) && "datanode".equals(THREAD_ORIGINS.get(thread)) && thread.isDaemon(), Code.cleanup_failed);
            datanodeSslThread = thread;
        }
        need(datanodeSslThread != null, Code.cleanup_failed); datanodeSslCaptured = true;
    }

}
