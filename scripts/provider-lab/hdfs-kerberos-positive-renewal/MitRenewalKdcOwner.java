/* Contained MIT KDC owner. Native execution belongs only in the isolated hosted
 * fixture. This class does not grant rclone renewal or provider acceptance. */
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.TimeUnit;

public final class MitRenewalKdcOwner implements AutoCloseable {
    static final Path ROOT = Path.of("/work/mit-kdc");
    static final Path TEMPLATE = Path.of("/opt/rpc/mit-kdc-plan-template.json");
    static final String TEMPLATE_SHA = "c6910dfbfa5e909e921010fe3c7f1c9d2df0e7cda4b36fda84db608d0a94ee06";
    static final LinkOption NOFOLLOW = LinkOption.NOFOLLOW_LINKS;
    static final Set<PosixFilePermission> PRIVATE_DIR = PosixFilePermissions.fromString("rwx------");
    static final Set<PosixFilePermission> PRIVATE_FILE = PosixFilePermissions.fromString("rw-------");
    static final Set<String> ENV_KEYS = Set.of("HOME","TMPDIR","PATH","LANG","LC_ALL","LD_LIBRARY_PATH",
        "KRB5_CONFIG","KRB5_KDC_PROFILE","KRB5CCNAME","KRB5_KTNAME","KRB5_CLIENT_KTNAME","KRB5RCACHEDIR");
    static final List<String> LABELS = List.of("database_create","reader_create","hdfs_create","hdfs_export","http_create","http_export");
    static final Set<String> BASE_LIBRARIES = Set.of("libc.so.6","libresolv.so.2","ld-linux-x86-64.so.2");
    static final Set<String> PRIVATE_LIBRARIES = Set.of("libcom_err.so.2","libevent-2.1.so.7","libgssapi_krb5.so.2",
        "libgssrpc.so.4","libk5crypto.so.3","libkadm5srv_mit.so.12","libkdb5.so.10","libkeyutils.so.1",
        "libkrb5.so.3","libkrb5support.so.0","libss.so.2","libverto-libevent.so.1","libverto.so.1");
    public enum Code { plan_invalid, environment_invalid, path_invalid, file_changed, file_bound,
        setup_nonzero, child_failed, output_bound, child_descendant, deadline, listener_mismatch,
        module_mismatch, interrupted, cleanup_failed }
    public static final class Failure extends Exception {
        public final Code code;
        Failure(Code value) { super(value.name()); code=value; }
    }
    static void need(boolean value, Code code) throws Failure { if(!value) throw new Failure(code); }
    static String hash(byte[] value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
    }
    static byte[] boundedFile(Path file, int maximum) throws Exception {
        BasicFileAttributes before=Files.readAttributes(file,BasicFileAttributes.class,NOFOLLOW);
        need(before.isRegularFile() && before.fileKey()!=null && before.size()<=maximum,Code.file_bound);
        byte[] result;
        try(InputStream input=Files.newInputStream(file,NOFOLLOW)) { result=input.readNBytes(maximum+1); }
        BasicFileAttributes after=Files.readAttributes(file,BasicFileAttributes.class,NOFOLLOW);
        need(result.length<=maximum && before.fileKey().equals(after.fileKey()) && before.size()==after.size()
            && before.lastModifiedTime().equals(after.lastModifiedTime()),Code.file_changed);
        return result;
    }
    static Path procPath(long pid,String name) throws Exception {
        need(pid>0 && Set.of("maps","tcp","tcp6","udp","udp6").contains(name),Code.path_invalid);
        return Path.of("/proc/"+pid+(name.equals("maps")?"/maps":"/net/"+name));
    }
    byte[] ownedProc(String name) throws Exception {
        need(kdc!=null && kdc.process.isAlive(),Code.child_failed);
        Path file=procPath(kdc.process.pid(),name);
        int maximum=name.equals("maps")?1048576:262144;
        BasicFileAttributes attributes=Files.readAttributes(file,BasicFileAttributes.class,NOFOLLOW);
        need(attributes.isRegularFile() && attributes.fileKey()!=null,Code.file_bound);
        // procfs synthesizes metadata and contents. Bind the fixed path to the
        // retained live child and bound the read; do not require stable mtimes.
        byte[] result;
        try(InputStream input=Files.newInputStream(file,NOFOLLOW)) { result=input.readNBytes(maximum+1); }
        need(result.length<=maximum,Code.file_bound);
        need(kdc.process.isAlive(),Code.child_failed);
        return result;
    }
    static String hex(SecureRandom random, int bytes) {
        byte[] value=new byte[bytes]; random.nextBytes(value);
        try { return HexFormat.of().formatHex(value); } finally { Arrays.fill(value,(byte)0); }
    }
    static JsonNode render(byte[] raw,String realmToken,String readerToken,String master,String readerSecret) throws Exception {
        need(raw!=null && raw.length<=16384 && hash(raw).equals(TEMPLATE_SHA),Code.plan_invalid);
        need(realmToken!=null && realmToken.matches("[a-f0-9]{12}") && readerToken!=null
            && readerToken.matches("[a-f0-9]{12}") && master!=null && master.matches("[a-f0-9]{32}")
            && readerSecret!=null && readerSecret.matches("[a-f0-9]{32}") && !master.equals(readerSecret),Code.plan_invalid);
        String rendered=new String(raw,StandardCharsets.US_ASCII)
            .replace("__REALM__","SYNTHETIC"+realmToken.toUpperCase(Locale.ROOT)+".INVALID")
            .replace("__READER__","reader"+readerToken).replace("__MASTER_SECRET__",master)
            .replace("__READER_SECRET__",readerSecret);
        need(!rendered.contains("__") && rendered.length()<=16384,Code.plan_invalid);
        ObjectMapper mapper=new ObjectMapper();
        mapper.enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
        mapper.enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
        return mapper.readTree(rendered);
    }
    final JsonNode plan;
    final String readerSecret;
    final List<Child> children=new ArrayList<>();
    final Map<Path,Object> identities=new LinkedHashMap<>();
    final Map<Path,String> immutable=new LinkedHashMap<>();
    final Set<Path> directories=new LinkedHashSet<>();
    final long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(180);
    Child kdc;
    boolean rootOwned, prepared, started, modulesVerified, listenerVerified, cleanupComplete;
    boolean forced, descendantsSeen, streamFailure;
    int setupCompleted;
    String stage="constructed";
    static JsonNode selectPolicy(JsonNode base,String policy) throws Exception {
        need("strict5".equals(policy)||"default300".equals(policy),Code.plan_invalid);
        need(base!=null && base.isObject() && base.path("files").isObject(),Code.plan_invalid);
        JsonNode out=base.deepCopy();
        var files=(com.fasterxml.jackson.databind.node.ObjectNode)out.path("files");
        String before=" clockskew = 5\n",after=" clockskew = "+("strict5".equals(policy)?5:300)+"\n";
        for(String name:List.of("/work/mit-kdc/krb5.conf","/work/mit-kdc/reader-krb5.conf")) {
            JsonNode node=files.get(name);need(node!=null && node.isTextual(),Code.plan_invalid);
            String text=node.asText();int first=text.indexOf(before);
            need(first>=0 && first==text.lastIndexOf(before),Code.plan_invalid);
            files.put(name,text.substring(0,first)+after+text.substring(first+before.length()));
        }
        return out;
    }
    static boolean rejectsPolicy(JsonNode base,String policy) throws Exception {
        try {selectPolicy(base,policy);return false;}
        catch(Failure failure){need(failure.code==Code.plan_invalid,Code.plan_invalid);return true;}
    }
    static int checkPolicies(byte[] raw) throws Exception {
        JsonNode base=render(raw,"111111111111","222222222222","33333333333333333333333333333333","44444444444444444444444444444444");
        int checked=0;need(selectPolicy(base,"strict5").equals(base),Code.plan_invalid);checked++;
        JsonNode selected=selectPolicy(base,"default300");
        var restored=(com.fasterxml.jackson.databind.node.ObjectNode)selected.path("files");
        for(String name:List.of("/work/mit-kdc/krb5.conf","/work/mit-kdc/reader-krb5.conf")) {
            String text=restored.path(name).asText();need(text.contains(" clockskew = 300\n"),Code.plan_invalid);
            restored.put(name,text.replace(" clockskew = 300\n"," clockskew = 5\n"));
        }
        need(selected.equals(base),Code.plan_invalid);checked++;
        for(String policy:new String[]{null,"","strict6","default301"}) {need(rejectsPolicy(base,policy),Code.plan_invalid);checked++;}
        for(int mutation=0;mutation<3;mutation++) {
            JsonNode changed=base.deepCopy();var files=(com.fasterxml.jackson.databind.node.ObjectNode)changed.path("files");
            String key="/work/mit-kdc/krb5.conf",text=files.path(key).asText();
            if(mutation==0)files.put(key,text.replace(" clockskew = 5\n",""));
            else if(mutation==1)files.put(key,text+" clockskew = 5\n");
            else files.put(key,5);
            need(rejectsPolicy(changed,"default300"),Code.plan_invalid);checked++;
        }
        need(checked==9,Code.plan_invalid);return checked;
    }
    final String clockPolicy;
    final int clockSkewSeconds,policyVectors;
    public boolean verifyClockPolicy() throws Exception {
        need(prepared && rootOwned,Code.plan_invalid);rootGuard();snapshot();
        for(Path file:List.of(clientConfig(),readerConfig())) {
            need(identities.get(file).equals(privatePath(file,false)),Code.file_changed);
            byte[] raw=boundedFile(file,16384);
            need(hash(raw).equals(immutable.get(file))
                && new String(raw,StandardCharsets.US_ASCII).equals(plan.path("files").path(file.toString()).asText())
                && new String(raw,StandardCharsets.US_ASCII).contains(" clockskew = "+clockSkewSeconds+"\n"),Code.file_changed);
        }
        return true;
    }
    public MitRenewalKdcOwner(String policy) throws Exception {
        need("strict5".equals(policy)||"default300".equals(policy),Code.plan_invalid);
        clockPolicy=policy;clockSkewSeconds=policy.equals("strict5")?5:300;
        byte[] raw=boundedFile(TEMPLATE,16384);policyVectors=checkPolicies(raw);
        SecureRandom random=new SecureRandom();
        String master=hex(random,16);readerSecret=hex(random,16);
        plan=selectPolicy(render(raw,hex(random,6),hex(random,6),master,readerSecret),policy);
    }
    public String realm() { return plan.path("realm").asText(); }
    public String reader() { return plan.path("reader").asText(); }
    public String readerPassword() { return readerSecret; }
    public Path clientConfig() { return ROOT.resolve("krb5.conf"); }
    public Path readerConfig() { return ROOT.resolve("reader-krb5.conf"); }
    public Path serviceKeytab() { return ROOT.resolve("hdfs.keytab"); }
    public Path httpKeytab() { return ROOT.resolve("http.keytab"); }

    static Object privatePath(Path file,boolean directory) throws Exception {
        BasicFileAttributes attrs=Files.readAttributes(file,BasicFileAttributes.class,NOFOLLOW);
        need(attrs.fileKey()!=null && (directory?attrs.isDirectory():attrs.isRegularFile()),Code.path_invalid);
        need(((Number)Files.getAttribute(file,"unix:uid",NOFOLLOW)).intValue()==10001
            && ((Number)Files.getAttribute(file,"unix:gid",NOFOLLOW)).intValue()==10001,Code.path_invalid);
        Set<PosixFilePermission> permissions=Files.getPosixFilePermissions(file,NOFOLLOW);
        need(directory?permissions.equals(PRIVATE_DIR):permissions.equals(PRIVATE_FILE),Code.path_invalid);
        if(!directory) need(((Number)Files.getAttribute(file,"unix:nlink",NOFOLLOW)).intValue()==1,Code.path_invalid);
        return attrs.fileKey();
    }
    void rootGuard() throws Exception {
        need(rootOwned && identities.get(ROOT).equals(privatePath(ROOT,true)),Code.file_changed);
        need(ROOT.getParent().equals(Path.of("/work")) && ROOT.toRealPath().equals(ROOT),Code.path_invalid);
    }
    public void prepare() throws Exception {
        need(!prepared && !rootOwned && children.isEmpty(),Code.plan_invalid);
        stage="environment";
        need(System.getProperty("os.name").equals("Linux"),Code.environment_invalid);
        privatePath(Path.of("/work"),true);
        need(Path.of("/work").toRealPath().equals(Path.of("/work")),Code.path_invalid);
        for(JsonNode row:plan.path("directories")) {
            Path file=Path.of(row.asText());
            need(file.equals(ROOT) || file.getParent().equals(ROOT),Code.plan_invalid);
            if(rootOwned) rootGuard();
            Files.createDirectory(file,PosixFilePermissions.asFileAttribute(PRIVATE_DIR));
            Object key=privatePath(file,true); identities.put(file,key); directories.add(file);
            if(file.equals(ROOT)) rootOwned=true;
        }
        Iterator<Map.Entry<String,JsonNode>> files=plan.path("files").fields();
        while(files.hasNext()) {
            rootGuard(); Map.Entry<String,JsonNode> row=files.next(); Path file=Path.of(row.getKey());
            need(file.getParent().equals(ROOT) && row.getValue().isTextual(),Code.plan_invalid);
            byte[] raw=row.getValue().asText().getBytes(StandardCharsets.US_ASCII);
            try(FileChannel output=FileChannel.open(file,Set.of(StandardOpenOption.WRITE,StandardOpenOption.CREATE_NEW,NOFOLLOW),
                    PosixFilePermissions.asFileAttribute(PRIVATE_FILE))) {
                ByteBuffer buffer=ByteBuffer.wrap(raw); while(buffer.hasRemaining()) output.write(buffer);
            }
            identities.put(file,privatePath(file,false)); immutable.put(file,hash(raw));
        }
        snapshot();
        JsonNode setup=plan.path("setup"); need(setup.isArray() && setup.size()==6,Code.plan_invalid);
        for(int i=0;i<setup.size();i++) {
            JsonNode row=setup.get(i); stage=LABELS.get(i);
            need(row.path("label").asText().equals(stage),Code.plan_invalid);
            Child child=launch(row,false);
            try {
                long until=Math.min(deadline,System.nanoTime()+TimeUnit.SECONDS.toNanos(10));
                while(child.process.isAlive()) { child.check(); need(System.nanoTime()<until,Code.deadline); Thread.sleep(20); }
                child.finish(false);
                need(child.process.exitValue()==0,Code.setup_nonzero);
                need(!child.failed(),Code.child_failed);
            } finally { child.finish(true); }
            snapshot(); setupCompleted++;
        }
        prepared=true; stage="prepared";
    }
    public void start() throws Exception {
        need(prepared && !started && kdc==null && setupCompleted==6,Code.plan_invalid);
        rootGuard(); snapshot(); stage="kdc_start";
        kdc=launch(plan.path("foreground"),true);
        long until=Math.min(deadline,System.nanoTime()+TimeUnit.SECONDS.toNanos(10));
        while(true) {
            kdc.check(); need(kdc.process.isAlive() && System.nanoTime()<until,Code.deadline);
            if(ownedListener(false)) break;
            Thread.sleep(20);
        }
        verifyModules(); listenerVerified=true; started=true; stage="running";
    }
    public void healthy() throws Exception {
        need(started && kdc!=null && kdc.process.isAlive() && System.nanoTime()<deadline,Code.child_failed);
        kdc.check(); rootGuard(); snapshot(); ownedListener(true);
    }
    Child launch(JsonNode row,boolean foreground) throws Exception {
        need(System.nanoTime()<deadline && children.size()<7,Code.deadline);
        List<String> argv=new ArrayList<>(); for(JsonNode arg:row.path("argv")) {
            need(arg.isTextual() && arg.asText().length()<=256 && !arg.asText().contains("\n"),Code.plan_invalid); argv.add(arg.asText());
        }
        String executable=foreground?"/opt/mit/bin/krb5kdc":children.isEmpty()?"/opt/mit/bin/kdb5_util":"/opt/mit/bin/kadmin.local";
        need(!argv.isEmpty() && argv.get(0).equals(executable),Code.plan_invalid);
        if(foreground) need(argv.equals(List.of(executable,"-n","-r",realm())),Code.plan_invalid);
        Set<String> keys=new HashSet<>(); row.path("environment").fieldNames().forEachRemaining(keys::add);
        need(keys.equals(ENV_KEYS),Code.plan_invalid);
        ProcessBuilder builder=new ProcessBuilder(argv).directory(ROOT.toFile());
        builder.environment().clear();
        for(String key:keys) { JsonNode value=row.path("environment").path(key); need(value.isTextual(),Code.plan_invalid); builder.environment().put(key,value.asText()); }
        need(builder.environment().get("LD_LIBRARY_PATH").equals("/opt/mit/lib")
            && builder.environment().get("KRB5_CONFIG").equals(ROOT+"/krb5.conf")
            && builder.environment().get("KRB5_KDC_PROFILE").equals(ROOT+"/kdc.conf"),Code.plan_invalid);
        byte[] input=row.path("stdin").asText().getBytes(StandardCharsets.US_ASCII);
        need(input.length<=66,Code.plan_invalid);
        Child child=new Child(builder.start(),input); children.add(child); child.begin(); return child;
    }
    void snapshot() throws Exception {
        rootGuard(); int count=0; long total=0;
        try(var walk=Files.walk(ROOT,3)) {
            for(Path file:walk.limit(65).toList()) {
                need(++count<=64 && file.normalize().equals(file) && file.startsWith(ROOT),Code.file_bound);
                BasicFileAttributes attrs=Files.readAttributes(file,BasicFileAttributes.class,NOFOLLOW);
                boolean directory=attrs.isDirectory();
                if(directory) need(directories.contains(file),Code.path_invalid);
                else { need(file.getFileName().toString().matches("[A-Za-z0-9._-]{1,128}"),Code.path_invalid); total+=attrs.size(); }
                need(attrs.size()<=8*1024*1024 && total<=16*1024*1024,Code.file_bound);
                Object key=privatePath(file,directory),old=identities.putIfAbsent(file,key);
                need(old==null || old.equals(key),Code.file_changed);
                if(immutable.containsKey(file)) need(hash(boundedFile(file,16384)).equals(immutable.get(file)),Code.file_changed);
            }
        }
        for(Path file:immutable.keySet()) need(Files.exists(file,NOFOLLOW),Code.file_changed);
    }
    Set<String> socketInodes() throws Exception {
        Set<String> result=new HashSet<>();
        try(var entries=Files.list(Path.of("/proc/"+kdc.process.pid()+"/fd"))) {
            List<Path> paths=entries.limit(129).toList(); need(paths.size()<=128,Code.file_bound);
            for(Path file:paths) {
                String target;
                try { target=Files.readSymbolicLink(file).toString(); }
                catch(NoSuchFileException missing) { continue; }
                if(target.matches("socket:\\[[0-9]+\\]")) result.add(target.substring(8,target.length()-1));
            }
        }
        return result;
    }
    static boolean validateOwnedSocket(String table,String[] row) throws Exception {
        need(table.equals("tcp") && row.length>=10 && row[7].equals("10001")
            && row[1].equals("0100007F:49C8"),Code.listener_mismatch);
        boolean listening=row[3].equals("0A");
        need(listening?row[2].equals("00000000:0000"):row[2].matches("0100007F:[0-9A-F]{4}"),Code.listener_mismatch);
        return listening;
    }
    boolean ownedListener(boolean required) throws Exception {
        Set<String> inodes=socketInodes(); int tcp=0;
        for(String table:List.of("tcp","tcp6","udp","udp6")) {
            String data=new String(ownedProc(table),StandardCharsets.US_ASCII);
            for(String line:data.split("\n")) {
                String[] row=line.trim().split("\\s+");
                if(row.length<10 || !inodes.contains(row[9])) continue;
                if(validateOwnedSocket(table,row)) tcp++;
            }
        }
        need(tcp<=1 && (!required || tcp==1),Code.listener_mismatch); return tcp==1;
    }
    static boolean allowedMappedFile(String file) {
        if(file==null || !file.startsWith("/") || file.endsWith("/") || file.contains("(deleted)")) return false;
        String name=Path.of(file).getFileName().toString();
        return file.equals("/opt/mit/bin/krb5kdc") || file.equals("/opt/mit/lib/krb5/plugins/kdb/db2.so")
            || PRIVATE_LIBRARIES.contains(name) && file.equals("/opt/mit/lib/"+name)
            || BASE_LIBRARIES.contains(name) && file.equals("/usr/lib/x86_64-linux-gnu/"+name);
    }
    void verifyModules() throws Exception {
        String maps=new String(ownedProc("maps"),StandardCharsets.US_ASCII);
        Set<String> mapped=new HashSet<>();
        for(String line:maps.split("\n")) {
            String[] row=line.trim().split("\\s+",6); if(row.length<6 || !row[5].startsWith("/")) continue;
            String file=row[5];need(allowedMappedFile(file),Code.module_mismatch);mapped.add(file);
        }
        need(mapped.contains("/opt/mit/lib/krb5/plugins/kdb/db2.so")
            && mapped.contains("/opt/mit/lib/libverto-libevent.so.1"),Code.module_mismatch);
        modulesVerified=true;
    }
    final class Child {
        final Process process; final byte[] input; final Drain stdout,stderr;
        final List<ProcessHandle> descendants=new ArrayList<>();
        final Thread outThread,errThread,inputThread;
        volatile boolean inputFailed; boolean finished;
        Child(Process value,byte[] bytes) {
            process=value; input=bytes; stdout=new Drain(process.getInputStream()); stderr=new Drain(process.getErrorStream());
            outThread=new Thread(stdout,"owned-mit-stdout"); errThread=new Thread(stderr,"owned-mit-stderr");
            inputThread=new Thread(()->{ try(var output=process.getOutputStream()) { output.write(input); output.flush(); }
                catch(Exception error) { inputFailed=true; } finally { Arrays.fill(input,(byte)0); } },"owned-mit-stdin");
            for(Thread thread:List.of(outThread,errThread,inputThread)) thread.setDaemon(true);
        }
        void begin() { outThread.start(); errThread.start(); inputThread.start(); }
        void capture() throws Exception {
            List<ProcessHandle> now=process.descendants().limit(17).toList();
            for(ProcessHandle handle:now) if(!descendants.contains(handle)) descendants.add(handle);
            if(!now.isEmpty()) descendantsSeen=true;
            need(now.size()<=16 && descendants.size()<=32,Code.child_descendant);
        }
        void check() throws Exception {
            capture(); need(descendants.isEmpty(),Code.child_descendant);
            need(!stdout.overflow && !stderr.overflow,Code.output_bound);
            need(!stdout.failed && !stderr.failed && !inputFailed,Code.child_failed);
        }
        boolean failed() { return stdout.failed || stderr.failed || stdout.overflow || stderr.overflow || inputFailed || !descendants.isEmpty(); }
        void finish(boolean terminate) throws Exception {
            if(finished) return;
            boolean interrupted=Thread.interrupted(); boolean clean=true;
            try {
                try { capture(); } catch(Exception error) { clean=false; }
                // Process.destroy() also closes Java's pipe streams. Signal
                // through the retained handle so drainers can observe EOF.
                if(process.isAlive() && terminate) process.toHandle().destroy();
                for(ProcessHandle handle:descendants) if(handle.isAlive()) handle.destroy();
                long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);
                while(process.isAlive() || descendants.stream().anyMatch(ProcessHandle::isAlive)) {
                    if(System.nanoTime()>=until) break;
                    try { Thread.sleep(20); } catch(InterruptedException error) { interrupted=true; }
                }
                if(process.isAlive()) { forced=true; process.toHandle().destroyForcibly(); }
                for(ProcessHandle handle:descendants) if(handle.isAlive()) { forced=true; handle.destroyForcibly(); }
                until=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);
                while(process.isAlive() || descendants.stream().anyMatch(ProcessHandle::isAlive)) {
                    if(System.nanoTime()>=until) { clean=false; break; }
                    try { Thread.sleep(20); } catch(InterruptedException error) { interrupted=true; }
                }
                try { process.getOutputStream().close(); } catch(Exception error) { clean=false; }
                long joinUntil=System.nanoTime()+TimeUnit.SECONDS.toNanos(2);
                for(Thread thread:List.of(inputThread,outThread,errThread)) {
                    long millis=TimeUnit.NANOSECONDS.toMillis(joinUntil-System.nanoTime());
                    if(millis>0) try { thread.join(millis); } catch(InterruptedException error) { interrupted=true; }
                }
                try { process.getInputStream().close(); process.getErrorStream().close(); } catch(Exception error) { clean=false; }
                for(Thread thread:List.of(inputThread,outThread,errThread)) clean &= !thread.isAlive();
                Arrays.fill(input,(byte)0); finished=clean && !process.isAlive();
                streamFailure |= failed(); need(finished,Code.cleanup_failed);
            } finally { if(interrupted) Thread.currentThread().interrupt(); }
        }
    }
    static final class Drain implements Runnable {
        final InputStream input; volatile boolean overflow,failed; volatile int bytes;
        Drain(InputStream stream) { input=stream; }
        public void run() {
            byte[] buffer=new byte[4096];
            try(input) { int count; while((count=input.read(buffer))!=-1) {
                bytes+=count; if(bytes>65536) { overflow=true; break; }
            } } catch(Exception error) { failed=true; }
            finally { Arrays.fill(buffer,(byte)0); }
        }
    }
    public Map<String,Object> projection() {
        return Map.ofEntries(Map.entry("stage",stage),Map.entry("setup_completed",setupCompleted),
            Map.entry("children",children.size()),Map.entry("children_reaped",children.stream().allMatch(c->c.finished && !c.process.isAlive())),
            Map.entry("streams_reaped",children.stream().allMatch(c->!c.outThread.isAlive() && !c.errThread.isAlive() && !c.inputThread.isAlive())),
            Map.entry("modules_verified",modulesVerified),Map.entry("listener_verified",listenerVerified),
            Map.entry("forced",forced),Map.entry("descendants_seen",descendantsSeen),Map.entry("stream_failure",streamFailure),
            Map.entry("private_material_removed",cleanupComplete),Map.entry("native_qualified",false),Map.entry("renewal_verified",false));
    }
    @Override public void close() throws Exception {
        if(cleanupComplete) return;
        boolean clean=true;
        for(int i=children.size()-1;i>=0;i--) try { children.get(i).finish(true); } catch(Exception error) { clean=false; }
        need(clean && children.stream().allMatch(c->c.finished && !c.process.isAlive()),Code.cleanup_failed);
        if(rootOwned) {
            snapshot();
            List<Path> paths;
            try(var walk=Files.walk(ROOT,3)) { paths=walk.limit(65).sorted(Comparator.reverseOrder()).toList(); }
            need(paths.size()<=64,Code.file_bound);
            for(Path file:paths) {
                rootGuard(); boolean directory=directories.contains(file);
                need(identities.get(file).equals(privatePath(file,directory)),Code.file_changed);
                Files.delete(file);
            }
            rootOwned=false;
        }
        cleanupComplete=true; stage="closed";
    }
}
