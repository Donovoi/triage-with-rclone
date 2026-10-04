/* Fixed Kerby 2.1.2 roles for the reviewed network-none hosted fixture.
 * Separate serve/ticket processes; no host configuration or provider credit.
 * Reuses the PR60 FILEv3 parser and bounded ticket operation. New keytab export
 * uses tagged LocalKadmin.getPrincipal, AdminHelper.exportToKeytab and
 * Keytab.store(OutputStream), then our exclusive private-file publication.
 * SimpleKdcServer.stop deletes its owned krb5.conf; all other auth material
 * remains for the coordinator after every consumer process has been reaped.
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
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.AdminHelper;
import org.apache.kerby.kerberos.kerb.ccache.CredentialCache;
import org.apache.kerby.kerberos.kerb.client.KrbClient;
import org.apache.kerby.kerberos.kerb.client.KrbConfig;
import org.apache.kerby.kerberos.kerb.client.KrbConfigKey;
import org.apache.kerby.kerberos.kerb.client.KrbKdcOption;
import org.apache.kerby.kerberos.kerb.client.KrbOption;
import org.apache.kerby.kerberos.kerb.keytab.Keytab;
import org.apache.kerby.kerberos.kerb.server.KdcConfig;
import org.apache.kerby.kerberos.kerb.server.KdcConfigKey;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;

public final class SecureKdc {
    private static final Path WORK = Path.of("/work"), ROOT = WORK.resolve("secure");
    private static final Path AUTH = ROOT.resolve("auth"), CONF = AUTH.resolve("krb5.conf");
    private static final Path CACHE = AUTH.resolve("reader.ccache"), STOP = ROOT.resolve("stop-kdc");
    private static final LinkOption NOFOLLOW = LinkOption.NOFOLLOW_LINKS;
    private static final int PORT = 19006, MAX_BYTES = 65536, READER_LIFETIME = 120;
    private static final String CONF_PROPERTY = "java.security.krb5.conf";
    private static final Set<String> MATERIAL_NAMES = Set.of("realm", "krb5.conf", "nn.keytab", "dn.keytab",
        "http.keytab", "reader.password", "rclone.conf", "simple.conf");
    private static final Set<Integer> ALL_PORTS = Set.of(19000,19001,19002,19003,19004,19005,19006);
    private static final AtomicBoolean BACKGROUND_FAILURE = new AtomicBoolean();
    private static final List<Thread> TASKS = new ArrayList<>();
    private static final Map<Path, FileState> MATERIAL = new LinkedHashMap<>();
    private static final Map<String, Boolean> CHECKS = new LinkedHashMap<>(), CLEANUP = new LinkedHashMap<>();
    private static Object workKey, rootKey, authKey;
    private static long deadline;
    private static int observedLifetime, cacheBytes;
    private static boolean authOwned;

    private enum Code {
        arguments_invalid, environment_invalid, path_invalid, source_changed, unexpected_files,
        listener_mismatch, configuration_invalid, deadline_exceeded, material_invalid,
        positive_ticket_failed, cache_invalid, ticket_time_mismatch, ticket_flags_mismatch,
        stop_invalid, background_failure, io_failure, krb_failure, interrupted, unclassified,
        cleanup_failed, publication_failed
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
            need(bytes.length <= maximum, Code.path_invalid); return bytes;
        }
    }
    private static Object directory(Path path, boolean privateOwner) throws Exception {
        BasicFileAttributes a = Files.readAttributes(path, BasicFileAttributes.class, NOFOLLOW);
        need(a.isDirectory() && !a.isSymbolicLink() && a.fileKey() != null, Code.path_invalid);
        if (privateOwner) need(((Number) Files.getAttribute(path, "unix:uid", NOFOLLOW)).intValue() == 10001
            && ((Number) Files.getAttribute(path, "unix:gid", NOFOLLOW)).intValue() == 10001
            && (((Number) Files.getAttribute(path, "unix:mode", NOFOLLOW)).intValue() & 07777) == 0700,
            Code.path_invalid);
        return a.fileKey();
    }
    private static void guardRoot() throws Exception {
        need(workKey != null && rootKey != null && workKey.equals(directory(WORK, true))
            && rootKey.equals(directory(ROOT, true)), Code.source_changed);
    }
    private static void guardAuth() throws Exception {
        guardRoot(); need(authOwned && authKey.equals(directory(AUTH, true)), Code.source_changed);
    }
    private static final class FileState {
        final Object key; final byte[] digest; final int size;
        FileState(Path path) throws Exception {
            BasicFileAttributes a = Files.readAttributes(path, BasicFileAttributes.class, NOFOLLOW);
            need(a.isRegularFile() && !a.isSymbolicLink() && a.fileKey() != null && a.size() <= MAX_BYTES
                && ((Number) Files.getAttribute(path, "unix:nlink", NOFOLLOW)).intValue() == 1
                && ((Number) Files.getAttribute(path, "unix:uid", NOFOLLOW)).intValue() == 10001
                && ((Number) Files.getAttribute(path, "unix:gid", NOFOLLOW)).intValue() == 10001
                && (((Number) Files.getAttribute(path, "unix:mode", NOFOLLOW)).intValue() & 07777) == 0600,
                Code.path_invalid);
            key = a.fileKey(); byte[] bytes = readBound(path, MAX_BYTES); size = bytes.length;
            digest = MessageDigest.getInstance("SHA-256").digest(bytes); Arrays.fill(bytes, (byte)0);
            BasicFileAttributes b = Files.readAttributes(path, BasicFileAttributes.class, NOFOLLOW);
            need(key.equals(b.fileKey()) && a.size() == size && b.size() == size
                && a.lastModifiedTime().equals(b.lastModifiedTime()), Code.source_changed);
        }
        void verify(Path path) throws Exception {
            FileState b = new FileState(path);
            need(key.equals(b.key) && size == b.size && MessageDigest.isEqual(digest,b.digest), Code.source_changed);
        }
    }
    private static byte[] verifiedBytes(Path path) throws Exception {
        guardAuth(); FileState before = new FileState(path); byte[] bytes = readBound(path, MAX_BYTES);
        before.verify(path); need(bytes.length == before.size && MessageDigest.isEqual(before.digest,
            MessageDigest.getInstance("SHA-256").digest(bytes)), Code.source_changed); return bytes;
    }
    private static void writeNew(Path path, byte[] bytes) throws Exception {
        guardRoot(); need(bytes.length <= MAX_BYTES, Code.path_invalid);
        if (path.getParent().equals(AUTH)) guardAuth();
        else need(path.getParent().equals(ROOT), Code.path_invalid);
        try (FileChannel channel = FileChannel.open(path,
            Set.of(StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW, NOFOLLOW),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) {
            ByteBuffer data = ByteBuffer.wrap(bytes); while(data.hasRemaining()) channel.write(data); channel.force(true);
        }
        FileState written = new FileState(path);
        need(written.size == bytes.length && MessageDigest.isEqual(written.digest,
            MessageDigest.getInstance("SHA-256").digest(bytes)), Code.source_changed);
        if (path.getParent().equals(AUTH)) MATERIAL.put(path,written);
    }
    private static void materialInventory(boolean allowCache, boolean configRemoved) throws Exception {
        guardAuth(); Set<String> actual = new HashSet<>(), expected = new HashSet<>(MATERIAL_NAMES);
        if(configRemoved) expected.remove("krb5.conf");
        try(DirectoryStream<Path> stream=Files.newDirectoryStream(AUTH)) {
            for(Path path:stream) { need(actual.size()<9,Code.unexpected_files); actual.add(path.getFileName().toString()); }
        }
        if(allowCache && actual.contains("reader.ccache")) {
            FileState cache = new FileState(CACHE); need(cache.size>100,Code.cache_invalid); expected.add("reader.ccache");
        }
        need(actual.equals(expected),Code.unexpected_files);
        for(var entry:MATERIAL.entrySet()) {
            if(configRemoved && entry.getKey().equals(CONF)) continue;
            entry.getValue().verify(entry.getKey());
        }
    }
    private static void environment(String[] args) throws Exception {
        need(args.length==1 && Set.of("serve","ticket").contains(args[0]),Code.arguments_invalid);
        need("Linux".equals(System.getProperty("os.name"))
            && "true".equals(System.getProperty("java.net.preferIPv4Stack")),Code.environment_invalid);
        for(String key:List.of("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","KRB5_CONFIG","KRB5CCNAME","KRB5_KTNAME"))
            need(System.getenv(key)==null,Code.environment_invalid);
        need(System.getProperty(CONF_PROPERTY)==null,Code.environment_invalid);
        String status=new String(readBound(Path.of("/proc/self/status"),MAX_BYTES),StandardCharsets.US_ASCII);
        Map<String,String> fields=new LinkedHashMap<>();
        for(String line:status.split("\n")) { int colon=line.indexOf(':'); if(colon>0) fields.put(line.substring(0,colon),line.substring(colon+1).trim()); }
        for(String key:List.of("Uid","Gid")) need("10001 10001 10001 10001".equals(fields.getOrDefault(key,"").replaceAll("\\s+"," ")),Code.environment_invalid);
        for(String key:List.of("CapInh","CapPrm","CapEff","CapBnd","CapAmb")) need(fields.getOrDefault(key,"").matches("0{16}"),Code.environment_invalid);
        need("1".equals(fields.get("NoNewPrivs")) && "2".equals(fields.get("Seccomp")),Code.environment_invalid);
        Enumeration<NetworkInterface> interfaces=NetworkInterface.getNetworkInterfaces(); int count=0;
        while(interfaces.hasMoreElements()) { var iface=interfaces.nextElement(); count++;
            need("lo".equals(iface.getName()) && iface.isLoopback(),Code.environment_invalid);
            var addresses=iface.getInetAddresses(); while(addresses.hasMoreElements()) need(addresses.nextElement().isLoopbackAddress(),Code.environment_invalid);
        }
        need(count==1,Code.environment_invalid); directory(Path.of("/"),false);
        workKey=directory(WORK,true); rootKey=directory(ROOT,true); guardRoot();
        need(!Files.exists(STOP,NOFOLLOW),Code.stop_invalid);
        listeners(args[0].equals("serve") ? Set.of() : ALL_PORTS);
    }
    private static void listeners(Set<Integer> expected) throws Exception {
        Set<Integer> found=new HashSet<>();
        for(String table:List.of("tcp","tcp6","udp","udp6")) {
            String[] lines=new String(readBound(Path.of("/proc/net/"+table),MAX_BYTES),StandardCharsets.US_ASCII).split("\n");
            need(lines.length<=256,Code.listener_mismatch);
            for(int i=1;i<lines.length;i++) {
                String[] fields=lines[i].trim().split("\\s+"); need(fields.length>=4,Code.listener_mismatch);
                if(table.startsWith("udp") || fields[3].equals("0A")) {
                    need(table.equals("tcp") && fields[1].matches("0100007F:[A-F0-9]{4}"),Code.listener_mismatch);
                    need(found.add(Integer.parseInt(fields[1].substring(9),16)),Code.listener_mismatch);
                }
            }
        }
        need(found.equals(expected),Code.listener_mismatch);
    }
    private static <T> T bounded(Callable<T> call,int seconds,long until) throws Exception {
        long remaining=Math.min(TimeUnit.SECONDS.toNanos(seconds),until-System.nanoTime()); need(remaining>0,Code.deadline_exceeded);
        FutureTask<T> task=new FutureTask<>(call); Thread thread=new Thread(task,"synthetic-kdc-task");
        thread.setDaemon(true); TASKS.add(thread); thread.start();
        try { return task.get(remaining,TimeUnit.NANOSECONDS); }
        catch(TimeoutException e) { task.cancel(true); throw new Failure(Code.deadline_exceeded); }
        catch(ExecutionException e) { if(e.getCause() instanceof Exception) throw (Exception)e.getCause(); throw new Failure(Code.unclassified); }
        finally { thread.join(200); }
    }
    private static Set<Long> threadIds() {
        Set<Long> ids=new HashSet<>(); for(Thread thread:Thread.getAllStackTraces().keySet()) if(thread.isAlive()) ids.add(thread.getId()); return ids;
    }
    private static boolean threadsGone(Set<Long> baseline) {
        long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);
        do { Set<Long> remaining=threadIds(); remaining.removeAll(baseline);
            if(remaining.isEmpty() && TASKS.stream().noneMatch(Thread::isAlive)) return true;
            try { Thread.sleep(25); } catch(InterruptedException e) { Thread.currentThread().interrupt(); return false; }
        } while(System.nanoTime()<until); return false;
    }
    private static String random(SecureRandom source,int count) {
        byte[] bytes=new byte[count]; source.nextBytes(bytes); String value=java.util.HexFormat.of().formatHex(bytes); Arrays.fill(bytes,(byte)0); return value;
    }
    private static void clientConfig(KrbConfig cfg) {
        cfg.setBoolean(KrbConfigKey.KRB_DEBUG,false); cfg.setBoolean(KrbConfigKey.DNS_LOOKUP_KDC,false);
        cfg.setBoolean(KrbConfigKey.DNS_LOOKUP_REALM,false); cfg.setBoolean(KrbConfigKey.ALLOW_WEAK_CRYPTO,false);
        for(KrbConfigKey key:List.of(KrbConfigKey.PERMITTED_ENCTYPES,KrbConfigKey.DEFAULT_TKT_ENCTYPES,KrbConfigKey.DEFAULT_TGS_ENCTYPES))
            cfg.setString(key,"aes128-cts-hmac-sha1-96");
    }
    private static void configure(SimpleKdcServer server,KrbConfig client,String realm) throws Exception {
        server.setWorkDir(AUTH.toFile()); server.setKdcRealm(realm); server.setKdcHost("127.0.0.1");
        server.setKdcTcpPort(PORT); server.setAllowTcp(true); server.setAllowUdp(false);
        KdcConfig cfg=server.getKdcConfig(); cfg.setBoolean(KdcConfigKey.KRB_DEBUG,false);
        cfg.setBoolean(KdcConfigKey.PREAUTH_REQUIRED,true); cfg.setBoolean(KdcConfigKey.PA_ENC_TIMESTAMP_REQUIRED,true);
        cfg.setBoolean(KdcConfigKey.ALLOW_TOKEN_PREAUTH,false); cfg.setBoolean(KdcConfigKey.EMPTY_ADDRESSES_ALLOWED,true);
        cfg.setBoolean(KdcConfigKey.RENEWABLE_ALLOWED,false); cfg.setBoolean(KdcConfigKey.FORWARDABLE_ALLOWED,false);
        cfg.setBoolean(KdcConfigKey.PROXIABLE_ALLOWED,false); cfg.setBoolean(KdcConfigKey.POSTDATED_ALLOWED,false);
        cfg.setLong(KdcConfigKey.ALLOWABLE_CLOCKSKEW,5L); cfg.setLong(KdcConfigKey.MINIMUM_TICKET_LIFETIME,1L);
        // Daemon AS/TGS requests may use up to600s. Reader explicitly asks120s;
        // only its parsed actual ticket times substantiate the reader lifetime.
        cfg.setLong(KdcConfigKey.MAXIMUM_TICKET_LIFETIME,600L); cfg.setLong(KdcConfigKey.MAXIMUM_RENEWABLE_LIFETIME,0L);
        cfg.setString(KdcConfigKey.ENCRYPTION_TYPES,"aes128-cts-hmac-sha1-96"); clientConfig(client);
        server.getKrbClient().setTimeout(5000);
        need(server.getKdcSetting().allowTcp() && !server.getKdcSetting().allowUdp()
            && server.getKdcSetting().getKdcTcpPort()==PORT && "127.0.0.1".equals(server.getKdcSetting().getKdcHost()),Code.configuration_invalid);
    }
    private static byte[] confBytes(String realm) {
        return ("[libdefaults]\n default_realm = "+realm+"\n dns_lookup_kdc = false\n dns_lookup_realm = false\n"
            +" rdns = false\n udp_preference_limit = 1\n forwardable = false\n proxiable = false\n"
            +" ticket_lifetime = 600\n renew_lifetime = 0\n permitted_enctypes = aes128-cts-hmac-sha1-96\n"
            +" default_tkt_enctypes = aes128-cts-hmac-sha1-96\n default_tgs_enctypes = aes128-cts-hmac-sha1-96\n"
            +"[realms]\n "+realm+" = {\n  kdc = 127.0.0.1:19006\n }\n").getBytes(StandardCharsets.US_ASCII);
    }
    private static byte[] rcloneBytes(String realm,boolean secure) {
        // gokrb5 v8.4.4 GetServiceTicket splits only on '/'; it resolves the realm separately.
        return ("[test]\ntype = hdfs\nnamenode = 127.0.0.1:19000\n"+(secure
            ? "service_principal_name = nn/127.0.0.1\ndata_transfer_protection = privacy\n"
            : "username = reader\n")).getBytes(StandardCharsets.US_ASCII);
    }
    private static void replaceGeneratedConfig(String realm) throws Exception {
        guardAuth(); BasicFileAttributes before=Files.readAttributes(CONF,BasicFileAttributes.class,NOFOLLOW);
        need(before.isRegularFile() && !before.isSymbolicLink() && before.fileKey()!=null && before.size()<=MAX_BYTES
            && ((Number)Files.getAttribute(CONF,"unix:nlink",NOFOLLOW)).intValue()==1,Code.path_invalid);
        Files.setPosixFilePermissions(CONF,PosixFilePermissions.fromString("rw-------"));
        try(FileChannel out=FileChannel.open(CONF,StandardOpenOption.WRITE,NOFOLLOW)) {
            out.truncate(0); ByteBuffer bytes=ByteBuffer.wrap(confBytes(realm)); while(bytes.hasRemaining()) out.write(bytes); out.force(true);
        }
        FileState current=new FileState(CONF); MATERIAL.put(CONF,current);
        need(before.fileKey().equals(current.key) && CONF.toString().equals(System.getProperty(CONF_PROPERTY))
            && MessageDigest.isEqual(current.digest,MessageDigest.getInstance("SHA-256").digest(confBytes(realm))),Code.source_changed);
    }
    private static final class LimitedBuffer extends ByteArrayOutputStream {
        @Override public synchronized void write(int value) { if(count>=MAX_BYTES) throw new IllegalStateException(); super.write(value); }
        @Override public synchronized void write(byte[] data,int offset,int length) {
            if(length<0 || length>MAX_BYTES-count) throw new IllegalStateException(); super.write(data,offset,length);
        }
        void erase() { Arrays.fill(buf,(byte)0); reset(); }
    }
    private static void serviceKeytab(SimpleKdcServer server,String principal,String filename) throws Exception {
        server.createPrincipal(principal); var identity=server.getKadmin().getPrincipal(principal);
        need(identity!=null,Code.material_invalid); Keytab keytab=new Keytab(); AdminHelper.exportToKeytab(keytab,identity);
        need(keytab.getPrincipals().size()==1 && principal.equals(keytab.getPrincipals().get(0).getName()),Code.material_invalid);
        LimitedBuffer buffer=new LimitedBuffer(); byte[] bytes=null;
        try { keytab.store(buffer); bytes=buffer.toByteArray(); need(bytes.length>16,Code.material_invalid); writeNew(AUTH.resolve(filename),bytes); }
        finally { buffer.erase(); if(bytes!=null) Arrays.fill(bytes,(byte)0); }
    }
    private static void material(SimpleKdcServer server,String realm) throws Exception {
        replaceGeneratedConfig(realm); writeNew(AUTH.resolve("realm"),(realm+"\n").getBytes(StandardCharsets.US_ASCII));
        serviceKeytab(server,"nn/127.0.0.1@"+realm,"nn.keytab"); serviceKeytab(server,"dn/127.0.0.1@"+realm,"dn.keytab");
        serviceKeytab(server,"HTTP/127.0.0.1@"+realm,"http.keytab");
        String password=random(new SecureRandom(),32); server.createPrincipal("reader@"+realm,password);
        writeNew(AUTH.resolve("reader.password"),(password+"\n").getBytes(StandardCharsets.US_ASCII));
        writeNew(AUTH.resolve("rclone.conf"),rcloneBytes(realm,true)); writeNew(AUTH.resolve("simple.conf"),rcloneBytes(realm,false));
        materialInventory(false,false);
    }
    private static String loadMaterial() throws Exception {
        authKey=directory(AUTH,true); authOwned=true;
        for(String name:MATERIAL_NAMES) MATERIAL.put(AUTH.resolve(name),new FileState(AUTH.resolve(name)));
        materialInventory(false,false);
        String text=new String(verifiedBytes(AUTH.resolve("realm")),StandardCharsets.US_ASCII);
        need(text.matches("SYNTHETIC[A-F0-9]{24}\\.INVALID\n"),Code.material_invalid); String realm=text.substring(0,text.length()-1);
        need(Arrays.equals(verifiedBytes(CONF),confBytes(realm))
            && Arrays.equals(verifiedBytes(AUTH.resolve("rclone.conf")),rcloneBytes(realm,true))
            && Arrays.equals(verifiedBytes(AUTH.resolve("simple.conf")),rcloneBytes(realm,false)),Code.configuration_invalid);
        return realm;
    }
    private static KOptions options(String principal,String password) {
        KOptions out=new KOptions(); out.add(KrbOption.CLIENT_PRINCIPAL,principal); out.add(KrbOption.USE_PASSWD,true);
        out.add(KrbOption.USER_PASSWD,password); out.add(KrbOption.LIFE_TIME,READER_LIFETIME); out.add(KrbOption.RENEWABLE_TIME,0);
        out.add(KrbKdcOption.RENEWABLE,false); out.add(KrbKdcOption.RENEWABLE_OK,false);
        out.add(KrbKdcOption.FORWARDABLE,false); out.add(KrbKdcOption.PROXIABLE,false); return out;
    }
    private static int u16(ByteBuffer data) { return Short.toUnsignedInt(data.getShort()); }
    private static long u32(ByteBuffer data) { return Integer.toUnsignedLong(data.getInt()); }
    private static byte[] counted(ByteBuffer data,int limit) throws Exception {
        long length=u32(data); need(length<=limit && length<=data.remaining(),Code.cache_invalid);
        byte[] bytes=new byte[(int)length]; data.get(bytes); return bytes;
    }
    private static void principal(ByteBuffer data,String realm,List<String> components,int type) throws Exception {
        need(u32(data)==type && u32(data)==components.size(),Code.cache_invalid);
        need(Arrays.equals(counted(data,256),realm.getBytes(StandardCharsets.US_ASCII)),Code.cache_invalid);
        for(String component:components) need(Arrays.equals(counted(data,256),component.getBytes(StandardCharsets.US_ASCII)),Code.cache_invalid);
    }
    private static void inspectCache(byte[] bytes,String realm,long before,long after) throws Exception {
        need(bytes.length>100 && bytes.length<=MAX_BYTES,Code.cache_invalid);
        ByteBuffer data=ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN); need(u16(data)==0x0503,Code.cache_invalid);
        principal(data,realm,List.of("reader"),1); principal(data,realm,List.of("reader"),1);
        principal(data,realm,List.of("krbtgt",realm),2); need(u16(data)==17 && u16(data)==17,Code.cache_invalid);
        byte[] key=counted(data,32); need(key.length==16,Code.cache_invalid); Arrays.fill(key,(byte)0);
        long auth=u32(data),start=u32(data),end=u32(data),renew=u32(data),effectiveStart=start==0?auth:start;
        need(auth>=before && auth<=after && effectiveStart==auth && renew==0
            && end>=before+READER_LIFETIME && end<=after+READER_LIFETIME
            && end-effectiveStart>=110 && end-effectiveStart<=READER_LIFETIME,Code.ticket_time_mismatch);
        observedLifetime=(int)(end-effectiveStart); need(Byte.toUnsignedInt(data.get())==0,Code.cache_invalid);
        need(u32(data)==0x00600000L,Code.ticket_flags_mismatch);
        need(u32(data)==0 && u32(data)==0,Code.cache_invalid);
        need(counted(data,MAX_BYTES).length>0 && counted(data,MAX_BYTES).length==0 && !data.hasRemaining(),Code.cache_invalid);
    }
    private static void ticket() throws Exception {
        String realm=loadMaterial(); CHECKS.put("endpoint_settings",true);
        byte[] passwordBytes=verifiedBytes(AUTH.resolve("reader.password")),serialized=null;
        try {
            String password=new String(passwordBytes,StandardCharsets.US_ASCII);
            need(password.matches("[a-f0-9]{64}\n"),Code.material_invalid); password=password.substring(0,password.length()-1);
            KrbConfig cfg=new KrbConfig(); clientConfig(cfg); KrbClient client=new KrbClient(cfg);
            client.setKdcRealm(realm); client.setKdcHost("127.0.0.1"); client.setKdcTcpPort(PORT);
            client.setAllowTcp(true); client.setAllowUdp(false); client.setTimeout(5000);
            bounded(()->{client.init();return null;},5,deadline);
            final String secret=password; long before=System.currentTimeMillis()/1000;
            TgtTicket tgt=bounded(()->client.requestTgt(options("reader@"+realm,secret)),10,deadline);
            long after=System.currentTimeMillis()/1000; need(tgt!=null,Code.positive_ticket_failed); CHECKS.put("positive_tgt",true);
            LimitedBuffer buffer=new LimitedBuffer();
            try { new CredentialCache(tgt).store(buffer); serialized=buffer.toByteArray(); } finally { buffer.erase(); }
            inspectCache(serialized,realm,before,after); CHECKS.put("file_cache_v3",true); CHECKS.put("nonrenewable",true);
            writeNew(CACHE,serialized); cacheBytes=serialized.length;
            materialInventory(true,false); listeners(ALL_PORTS); CHECKS.put("cache_preserved",true);
            CHECKS.put("configuration_preserved",true);
            need(!BACKGROUND_FAILURE.get(),Code.background_failure);
        } finally { Arrays.fill(passwordBytes,(byte)0); if(serialized!=null) Arrays.fill(serialized,(byte)0); }
    }
    private static void waitStop() throws Exception {
        while(!Files.exists(STOP,NOFOLLOW)) {
            guardRoot(); need(!BACKGROUND_FAILURE.get(),Code.background_failure);
            need(System.nanoTime()<deadline,Code.deadline_exceeded); Thread.sleep(50);
        }
        guardRoot(); FileState stop=new FileState(STOP); need(stop.size==0,Code.stop_invalid); stop.verify(STOP);
        listeners(Set.of(PORT)); materialInventory(true,false); CHECKS.put("configuration_preserved",true);
    }
    private static void shutdown(SimpleKdcServer server,Set<Long> baseline) {
        boolean stopped=server==null,removed=false;
        if(server!=null) try {
            guardAuth(); if(MATERIAL.containsKey(CONF)) MATERIAL.get(CONF).verify(CONF);
            else need(!Files.exists(CONF,NOFOLLOW),Code.source_changed);
            bounded(()->{server.stop();return null;},5,System.nanoTime()+TimeUnit.SECONDS.toNanos(5)); stopped=true;
            guardAuth(); removed=!Files.exists(CONF,NOFOLLOW);
            if(removed && MATERIAL.size()>=MATERIAL_NAMES.size()) materialInventory(true,true);
        } catch(Throwable ignored) { stopped=false; }
        CLEANUP.put("kdc_stop_returned",stopped); CLEANUP.put("known_config_removed",removed);
        CLEANUP.put("threads_terminated",threadsGone(baseline));
        try { listeners(Set.of()); CLEANUP.put("listeners_absent",true); } catch(Throwable ignored) { }
        String value=System.getProperty(CONF_PROPERTY); boolean restored=value==null;
        if(CONF.toString().equals(value)) { System.clearProperty(CONF_PROPERTY); restored=true; }
        CLEANUP.put("process_property_restored",restored);
    }
    private static String boolMap(Map<String,Boolean> values) {
        StringBuilder out=new StringBuilder("{"); for(var entry:values.entrySet()) {
            if(out.length()>1) out.append(','); out.append('"').append(entry.getKey()).append("\":").append(entry.getValue());
        } return out.append('}').toString();
    }
    private static void publish(String role,String phase,boolean success,Code error) throws Exception {
        guardRoot(); String file=role.equals("ticket")?"ticket-final.json":"kdc-"+phase+".json";
        need(Set.of("kdc-ready.json","kdc-final.json","ticket-final.json").contains(file),Code.publication_failed);
        String json="{\"schema_version\":1,\"scope\":\"secure_hdfs_kdc_feasibility\",\"role\":\""+role
            +"\",\"phase\":\""+phase+"\",\"success\":"+success+",\"expected_kerby_version\":\"2.1.2\",\"checks\":"+boolMap(CHECKS)
            +",\"cleanup\":"+(phase.equals("ready")?"{}":boolMap(CLEANUP))+",\"cache_bytes\":"+cacheBytes
            +",\"observed_lifetime_seconds\":"+observedLifetime+",\"errors\":"+(error==null?"[]":"[\""+error.name()+"\"]")
            +",\"ledger_eligible\":false,\"authentication_verified\":false,\"hdfs_authenticated\":false,\"renewal_verified\":false"
            +",\"daemon_accepted\":false,\"provider_accepted\":false,\"application_accepted\":false,\"vendor_accepted\":false,\"vulnerability_audited\":false}\n";
        Path pending=ROOT.resolve("."+file+".pending"),target=ROOT.resolve(file); writeNew(pending,json.getBytes(StandardCharsets.US_ASCII));
        FileState state=new FileState(pending); guardRoot(); state.verify(pending); need(!Files.exists(target,NOFOLLOW),Code.publication_failed);
        Files.move(pending,target); state.verify(target); guardRoot();
    }
    public static void main(String[] args) {
        System.setOut(new PrintStream(OutputStream.nullOutputStream())); System.setErr(new PrintStream(OutputStream.nullOutputStream()));
        Thread.setDefaultUncaughtExceptionHandler((thread,error)->BACKGROUND_FAILURE.set(true));
        String role=args.length==1 && args[0].equals("ticket")?"ticket":"serve";
        List<String> names=role.equals("serve")?List.of("environment","endpoint_settings","material_ready","configuration_preserved")
            :List.of("environment","endpoint_settings","positive_tgt","file_cache_v3","nonrenewable","cache_preserved","configuration_preserved");
        for(String name:names) CHECKS.put(name,false);
        for(String name:role.equals("serve")?List.of("kdc_stop_returned","listeners_absent","threads_terminated","process_property_restored","known_config_removed")
            :List.of("threads_terminated")) CLEANUP.put(name,false);
        Set<Long> baseline=threadIds(); SimpleKdcServer server=null; Code error=null;
        deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(role.equals("serve")?360:30);
        try {
            environment(args); CHECKS.put("environment",true);
            if(role.equals("ticket")) ticket();
            else {
                Files.createDirectory(AUTH,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
                authKey=directory(AUTH,true); authOwned=true; guardAuth();
                String realm="SYNTHETIC"+random(new SecureRandom(),12).toUpperCase(java.util.Locale.ROOT)+".INVALID";
                KrbConfig cfg=new KrbConfig(); server=new SimpleKdcServer(cfg); configure(server,cfg,realm);
                final SimpleKdcServer owned=server; bounded(()->{owned.init();return null;},10,deadline);
                material(server,realm); CHECKS.put("material_ready",true);
                bounded(()->{owned.start();return null;},10,deadline); listeners(Set.of(PORT)); CHECKS.put("endpoint_settings",true);
                materialInventory(false,false); CHECKS.put("configuration_preserved",true); need(!BACKGROUND_FAILURE.get(),Code.background_failure);
                publish(role,"ready",true,null); CHECKS.put("configuration_preserved",false); waitStop();
            }
        } catch(Failure e) { error=e.code; }
        catch(KrbException e) { error=Code.krb_failure; }
        catch(IOException e) { error=Code.io_failure; }
        catch(InterruptedException e) { Thread.currentThread().interrupt(); error=Code.interrupted; }
        catch(Throwable e) { error=Code.unclassified; }
        finally {
            if(role.equals("serve")) shutdown(server,baseline);
            else CLEANUP.put("threads_terminated",threadsGone(baseline));
        }
        if(BACKGROUND_FAILURE.get() && error==null) error=Code.background_failure;
        boolean clean=CLEANUP.values().stream().allMatch(Boolean.TRUE::equals);
        if(!clean && error==null) error=Code.cleanup_failed;
        boolean success=error==null && CHECKS.values().stream().allMatch(Boolean.TRUE::equals) && clean;
        try { publish(role,"final",success,error); } catch(Throwable ignored) { success=false; }
        System.exit(success?0:1);
    }
}
