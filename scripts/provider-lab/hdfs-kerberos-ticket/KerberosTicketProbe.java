/* Isolated ticket feasibility probe. Requires the reviewed hosted Linux
 * container, fixed Kerby 2.1.2 classpath, UID/GID10001, network=none,
 * -Djava.net.preferIPv4Stack=true, private /work tmpfs, and an outer watchdog/reap.
 * No HDFS, rclone, renewal, application, vendor, or dependency-audit credit.
 * API/source references: apache/directory-kerby tag kerby-all-2.1.2:
 * SimpleKdcServer; client/{KrbClientBase,request/KdcRequest};
 * server/{preauth/builtin/EncTsPreauth,request/AsRequest,request/TicketIssuer};
 * crypto/enc/KeKiEnc; ccache/{CredentialCache,CredCacheOutputStream,Credential}.
 */
import java.io.ByteArrayOutputStream;
import java.io.IOException;
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

public final class KerberosTicketProbe {
    private static final Path WORK = Path.of("/work");
    private static final Path ROOT = WORK.resolve("kerberos-ticket-probe");
    private static final Path CONF = ROOT.resolve("krb5.conf");
    private static final Path CACHE = ROOT.resolve("reader.ccache");
    private static final LinkOption NOFOLLOW = LinkOption.NOFOLLOW_LINKS;
    private static final int PORT = 19006, MAX_BYTES = 65536, LIFETIME_SECONDS = 120;
    private static final String CONF_PROPERTY = "java.security.krb5.conf";
    private static final AtomicBoolean BACKGROUND_FAILURE = new AtomicBoolean();
    private static final List<Thread> TASKS = new ArrayList<>();
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
        cleanup_failed
    }
    private static final class Failure extends Exception {
        final Code code;
        Failure(Code value) { super(value.name()); code = value; }
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
            for (Path path : stream) { need(actual.size() < 2, Code.unexpected_files); actual.add(path); }
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
        need(found.equals(running ? Set.of("tcp:0100007F:4A3E") : Set.of()), Code.listener_mismatch);
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
            throw new Failure(Code.unclassified);
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
    private static boolean typed(Throwable error, KrbErrorCode expected) {
        Set<Throwable> seen = java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>());
        for (int i = 0; error != null && i < 8 && seen.add(error); i++, error = error.getCause())
            if (error instanceof KrbException && ((KrbException) error).getKrbErrorCode() == expected) return true;
        return false;
    }
    private static void denial(KrbClient client, String principal, String password,
                               KrbErrorCode expected, Code failure) throws Exception {
        boolean rejected = false;
        try { bounded(() -> client.requestTgt(options(principal, password)), 10, deadline); }
        catch (KrbException error) { rejected = typed(error, expected); }
        need(rejected, failure); inventory(); listeners(true);
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
        boolean threadsClean = false;
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
        do {
            Set<Long> remaining = threadIds(); remaining.removeAll(baseline);
            threadsClean = remaining.isEmpty() && TASKS.stream().noneMatch(Thread::isAlive);
            if (threadsClean) break;
            try { Thread.sleep(25); } catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
        } while (System.nanoTime() < until);
        CLEANUP.put("threads_terminated", threadsClean);
        boolean noListeners = false;
        try { listeners(false); noListeners = true; } catch (Throwable ignored) { }
        CLEANUP.put("listeners_absent", noListeners);
        boolean removed = !rootCreated;
        if (rootOwned && stopped && threadsClean && noListeners) {
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
    public static void main(String[] args) {
        PrintStream report = System.out;
        System.setOut(new PrintStream(OutputStream.nullOutputStream()));
        System.setErr(new PrintStream(OutputStream.nullOutputStream()));
        Thread.setDefaultUncaughtExceptionHandler((thread, error) -> BACKGROUND_FAILURE.set(true));
        for (String name : List.of("environment", "endpoint_settings", "positive_tgt", "file_cache_v3",
                "nonrenewable", "client_request_failed_with_integrity_error", "wrong_principal_denied", "cache_preserved")) CHECKS.put(name, false);
        for (String name : List.of("kdc_stop_returned", "threads_terminated", "listeners_absent",
                "private_material_removed", "process_property_restored", "cleanup_completed")) CLEANUP.put(name, false);
        Set<Long> baseline = threadIds(); SimpleKdcServer server = null; Code error = null;
        deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(45);
        byte[] serialized = null;
        try {
            environment(args); CHECKS.put("environment", true);
            Files.createDirectory(ROOT, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
            rootCreated = true;
            rootKey = directory(ROOT, true); rootOwned = true; guardRoot();
            SecureRandom random = new SecureRandom();
            String realm = "SYNTHETIC" + random(random, 12).toUpperCase(java.util.Locale.ROOT) + ".INVALID";
            String reader = "reader" + random(random, 12), unknown = "missing" + random(random, 12);
            String password = random(random, 32), wrongPassword = random(random, 32);
            need(!password.equals(wrongPassword), Code.configuration_invalid);
            KrbConfig clientConfig = new KrbConfig(); server = new SimpleKdcServer(clientConfig);
            constrainConfig(server, clientConfig, realm); final SimpleKdcServer ownedServer = server;
            bounded(() -> { ownedServer.init(); return null; }, 10, deadline);
            replaceGeneratedConfig(realm);
            server.createPrincipal(reader + "@" + realm, password);
            bounded(() -> { ownedServer.start(); return null; }, 10, deadline);
            listeners(true); CHECKS.put("endpoint_settings", true);
            KrbClient client = server.getKrbClient();
            long before = System.currentTimeMillis() / 1000;
            TgtTicket tgt = bounded(() -> client.requestTgt(options(reader + "@" + realm, password)), 10, deadline);
            long after = System.currentTimeMillis() / 1000;
            need(tgt != null && !BACKGROUND_FAILURE.get(), Code.positive_ticket_failed);
            CHECKS.put("positive_tgt", true);
            LimitedBuffer buffer = new LimitedBuffer();
            try { new CredentialCache(tgt).store(buffer); serialized = buffer.toByteArray(); }
            finally { buffer.erase(); }
            inspectCache(serialized, realm, reader, before, after); publishCache(serialized);
            CHECKS.put("file_cache_v3", true); CHECKS.put("nonrenewable", true);
            // BAD_INTEGRITY can also come from local AS-REP decryption. This
            // checks client failure; it does not prove a server rejection.
            denial(client, reader + "@" + realm, wrongPassword,
                   KrbErrorCode.KRB_AP_ERR_BAD_INTEGRITY, Code.wrong_password_failure_mismatch);
            CHECKS.put("client_request_failed_with_integrity_error", true);
            denial(client, unknown + "@" + realm, password,
                   KrbErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN, Code.wrong_principal_not_rejected);
            CHECKS.put("wrong_principal_denied", true);
            inventory(); listeners(true); need(!BACKGROUND_FAILURE.get(), Code.background_failure);
            CHECKS.put("cache_preserved", true);
        } catch (Failure failure) { error = failure.code; }
        catch (KrbException failure) { error = Code.krb_failure; }
        catch (IOException failure) { error = Code.io_failure; }
        catch (InterruptedException failure) { Thread.currentThread().interrupt(); error = Code.interrupted; }
        catch (Throwable failure) { error = Code.unclassified; }
        finally {
            if (serialized != null) Arrays.fill(serialized, (byte) 0);
            try { cleanup(server, baseline); }
            catch (Throwable ignored) { CLEANUP.put("cleanup_completed", false); }
        }
        boolean clean = CLEANUP.values().stream().allMatch(Boolean.TRUE::equals);
        if (!clean && error == null) error = Code.cleanup_failed;
        if (BACKGROUND_FAILURE.get() && error == null) error = Code.background_failure;
        boolean success = error == null && CHECKS.values().stream().allMatch(Boolean.TRUE::equals) && clean
            && !BACKGROUND_FAILURE.get();
        report.println("{\"schema_version\":1,\"scope\":\"kerby_ticket_feasibility\",\"success\":" + success
            + ",\"expected_kerby_version\":\"2.1.2\",\"runtime_binding_required\":true,\"checks\":" + boolMap(CHECKS)
            + ",\"cleanup\":" + boolMap(CLEANUP) + ",\"cache_bytes\":" + cacheBytes
            + ",\"observed_lifetime_seconds\":" + observedLifetime + ",\"error\":"
            + (error == null ? "null" : "\"" + error.name() + "\"")
            + ",\"ledger_eligible\":false,\"authentication_verified\":false,\"hdfs_authenticated\":false"
            + ",\"renewal_verified\":false,\"daemon_accepted\":false,\"provider_accepted\":false"
            + ",\"application_accepted\":false,\"vendor_accepted\":false,\"vulnerability_audited\":false}");
        report.flush(); System.exit(success ? 0 : 1);
    }
}
