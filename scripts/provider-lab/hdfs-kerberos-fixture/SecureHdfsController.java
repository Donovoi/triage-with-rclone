/* Source-only integrated secure-HDFS feasibility controller.
 * Runs only in the reviewed network-none, nonroot, pinned-JDK container.
 * No provider/application/authentication/renewal acceptance is awarded here.
 */
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

public final class SecureHdfsController {
    private static final Path WORK = Path.of("/work"), ROOT = WORK.resolve("secure");
    private static final Path OPT = Path.of("/opt/secure"), JDK = Path.of("/opt/java/openjdk");
    private static final Path TLS = ROOT.resolve("tls"), AUTH = ROOT.resolve("auth");
    private static final Path PASSWORD = TLS.resolve("store.pass"), FINAL = WORK.resolve("secure-final.json");
    private static final LinkOption N = LinkOption.NOFOLLOW_LINKS;
    private static final int JSON_LIMIT = 65536, MATERIAL_LIMIT = 2 * 1024 * 1024, LOG_LIMIT = 262144;
    private static final Set<Integer> PORTS = Set.of(19000,19001,19002,19003,19004,19005,19006);
    private static final List<String> CLAIMS = List.of("ledger_eligible", "authentication_verified", "hdfs_authenticated",
        "renewal_verified", "daemon_accepted", "provider_accepted", "application_accepted", "vendor_accepted", "vulnerability_audited");
    private static final List<String> READY_CHECKS = List.of("environment", "private_runtime", "tls_material", "kdc_ready",
        "format_complete", "nn_ready", "dn_ready", "listeners_exact", "https_verified", "https_wrong_host_rejected",
        "https_wrong_ca_rejected", "seed_verified", "ticket_ready", "simple_rpc_rejected");
    private static final List<String> CLEANUP_KEYS = List.of("dn_stopped", "nn_stopped", "kdc_stopped", "processes_reaped",
        "listeners_absent", "private_material_removed", "no_forced_termination");
    private static final Map<String,Boolean> CHECKS = new LinkedHashMap<>(), CLEANUP = new LinkedHashMap<>();
    private static final Set<String> ERRORS = new LinkedHashSet<>();
    private static final List<Child> CHILDREN = new ArrayList<>();
    private static final Map<Long,ProcessHandle> DESCENDANTS = new LinkedHashMap<>();
    private static final Map<Path,Snapshot> MATERIAL = new LinkedHashMap<>();
    private static final Map<String,String> ROLE_CONFIGURATIONS = new LinkedHashMap<>();
    private static final AtomicBoolean OUTPUT_FAILURE = new AtomicBoolean(), FORCED = new AtomicBoolean();
    private static Object workKey, rootKey;
    private static boolean rootCreated, readyPublished;
    private static long deadline, startedMillis;
    private static int keytoolNumber;
    private static String classpath;
    private static char[] storePassword;

    private enum Code {
        environment_invalid, path_invalid, input_changed, classpath_invalid, arguments_invalid,
        deadline_exceeded, child_start_failed, child_failed, child_timeout, output_failed,
        output_limit, receipt_invalid, listener_mismatch, tls_generation_failed, tls_material_invalid,
        tls_verification_failed, tls_negative_mismatch, kdc_start_failed, format_failed,
        nn_start_failed, dn_start_failed, seed_failed, ticket_failed, stop_invalid,
        source_verification_failed, role_stop_failed, forced_termination, process_cleanup_failed,
        private_cleanup_failed, report_failed, simple_rpc_rejection_failed, io_failure, interrupted, unclassified,
        role_environment_failed, role_material_failed, role_configuration_failed, role_login_failed,
        role_format_failed, role_format_preexisting, role_format_incomplete, role_source_failed,
        role_service_start_failed, role_cleanup_failed, role_preservation_failed, role_report_failed,
        role_invalid_config, role_io_failure, role_file_missing, role_security_failure,
        role_illegal_state, role_null_state, role_missing_class, role_linkage_failure,
        role_resource_failure, role_exit_requested, role_halt_requested, role_unclassified,
        role_keytab_unreadable, role_login_exception, role_socket_timeout, role_connection_failed,
        role_kerberos_failure, role_kerberos_client_unknown, role_kerberos_server_unknown,
        role_kerberos_policy_rejected, role_kerberos_etype_unsupported, role_kerberos_preauth_failed,
        role_kerberos_preauth_required, role_kerberos_integrity_failed, role_kerberos_clock_skew,
        role_kerberos_message_modified, role_kerberos_generic_error, role_kerberos_asn_identifier
    }
    private static final class Failure extends Exception {
        final Code code;
        Failure(Code code) { super(code.name()); this.code = code; }
    }
    private static void need(boolean value, Code code) throws Failure { if (!value) throw new Failure(code); }
    private static void record(Throwable error, Code stage) {
        ERRORS.add(stage.name());
        if (error instanceof Failure) ERRORS.add(((Failure) error).code.name());
        else if (error instanceof InterruptedException) { ERRORS.add(Code.interrupted.name()); Thread.interrupted(); }
        else if (error instanceof IOException) ERRORS.add(Code.io_failure.name());
        else ERRORS.add(Code.unclassified.name());
    }
    private static byte[] read(Path path, int limit) throws Exception {
        try (InputStream in = Files.newInputStream(path, N)) {
            byte[] bytes = in.readNBytes(limit + 1);
            need(bytes.length <= limit, Code.path_invalid); return bytes;
        }
    }
    private static int unix(Path p, String name) throws Exception {
        return ((Number) Files.getAttribute(p, "unix:" + name, N)).intValue();
    }
    private static Object directory(Path p, boolean owned) throws Exception {
        BasicFileAttributes a = Files.readAttributes(p, BasicFileAttributes.class, N);
        need(a.isDirectory() && !a.isSymbolicLink() && a.fileKey() != null, Code.path_invalid);
        if (owned) need(unix(p,"uid") == 10001 && unix(p,"gid") == 10001 && (unix(p,"mode") & 07777) == 0700, Code.path_invalid);
        else need(unix(p,"uid") == 0 && (unix(p,"mode") & 0022) == 0, Code.classpath_invalid);
        return a.fileKey();
    }
    private static void regular(Path p, int limit, boolean owned) throws Exception {
        BasicFileAttributes a = Files.readAttributes(p, BasicFileAttributes.class, N);
        need(a.isRegularFile() && !a.isSymbolicLink() && a.fileKey() != null && a.size() <= limit
            && unix(p,"nlink") == 1, Code.path_invalid);
        if (owned) need(unix(p,"uid") == 10001 && unix(p,"gid") == 10001 && (unix(p,"mode") & 07777) == 0600, Code.path_invalid);
        else need(unix(p,"uid") == 0 && (unix(p,"mode") & 0022) == 0, Code.classpath_invalid);
    }
    private static void guard() throws Exception {
        need(workKey != null && workKey.equals(directory(WORK,true)), Code.input_changed);
        if (rootCreated) need(rootKey.equals(directory(ROOT,true)), Code.input_changed);
    }
    private static void mkdir(Path p) throws Exception {
        need(p.normalize().startsWith(ROOT) && !Files.exists(p,N), Code.path_invalid);
        Files.createDirectory(p, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        if (p.equals(ROOT)) {
            // Retain ownership immediately after successful exclusive creation,
            // so a later validation failure still attempts scoped cleanup.
            rootCreated=true;
            rootKey=Files.readAttributes(p,BasicFileAttributes.class,N).fileKey();
        }
        directory(p,true);
    }
    private static void writeNew(Path p, byte[] bytes) throws Exception {
        guard(); need(p.normalize().equals(p) && (p.getParent().startsWith(ROOT)
            || p.equals(WORK.resolve(".secure-final.json.pending"))), Code.path_invalid);
        try (FileChannel channel = FileChannel.open(p, Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, N),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) {
            ByteBuffer buffer = ByteBuffer.wrap(bytes); while (buffer.hasRemaining()) channel.write(buffer); channel.force(true);
        }
        regular(p, Math.max(JSON_LIMIT, bytes.length), true);
    }
    private static void publish(Path p, String value) throws Exception {
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        need(bytes.length <= JSON_LIMIT && !Files.exists(p,N), Code.report_failed);
        Path pending = p.resolveSibling("." + p.getFileName() + ".pending");
        writeNew(pending,bytes); guard(); Files.move(pending,p); regular(p,JSON_LIMIT,true);
    }
    private static final class Snapshot {
        final Object key; final long size; final byte[] hash;
        Snapshot(Path p) throws Exception {
            regular(p,MATERIAL_LIMIT,true);
            BasicFileAttributes before = Files.readAttributes(p,BasicFileAttributes.class,N);
            key = before.fileKey(); byte[] bytes = read(p,MATERIAL_LIMIT); size = bytes.length;
            hash = MessageDigest.getInstance("SHA-256").digest(bytes); Arrays.fill(bytes,(byte)0);
            BasicFileAttributes after = Files.readAttributes(p,BasicFileAttributes.class,N);
            need(key.equals(after.fileKey()) && before.size()==size && after.size()==size
                && before.lastModifiedTime().equals(after.lastModifiedTime()),Code.input_changed);
        }
        void verify(Path p) throws Exception {
            Snapshot current = new Snapshot(p);
            need(key.equals(current.key) && size==current.size && MessageDigest.isEqual(hash,current.hash),Code.input_changed);
        }
    }
    private static void remember(Path p) throws Exception { need(!MATERIAL.containsKey(p),Code.input_changed); MATERIAL.put(p,new Snapshot(p)); }
    private static void preserve(boolean afterKdcStop) throws Exception {
        guard();
        for (var entry:MATERIAL.entrySet()) {
            if (afterKdcStop && entry.getKey().equals(AUTH.resolve("krb5.conf"))) need(!Files.exists(entry.getKey(),N),Code.input_changed);
            else entry.getValue().verify(entry.getKey());
        }
    }
    private static void environment(String[] args) throws Exception {
        // Establish the only permissible final-report parent before other
        // preflights. No report may be written into an unvalidated /work.
        workKey=directory(WORK,true);
        need(Files.getFileStore(WORK).type().equals("tmpfs"),Code.path_invalid);
        need(args.length==0,Code.arguments_invalid);
        need("Linux".equals(System.getProperty("os.name")) && Runtime.version().feature()==17
            && "true".equals(System.getProperty("java.net.preferIPv4Stack")),Code.environment_invalid);
        for(String name:List.of("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","KRB5_CONFIG","KRB5CCNAME","KRB5_KTNAME"))
            need(System.getenv(name)==null,Code.environment_invalid);
        need(System.getProperty("java.security.krb5.conf")==null,Code.environment_invalid);
        Map<String,String> fields=new LinkedHashMap<>();
        for(String line:new String(read(Path.of("/proc/self/status"),JSON_LIMIT),StandardCharsets.US_ASCII).split("\n")) {
            int i=line.indexOf(':'); if(i>0) fields.put(line.substring(0,i),line.substring(i+1).trim());
        }
        for(String name:List.of("Uid","Gid")) need("10001 10001 10001 10001".equals(fields.getOrDefault(name,"").replaceAll("\\s+"," ")),Code.environment_invalid);
        for(String name:List.of("CapInh","CapPrm","CapEff","CapBnd","CapAmb")) need(fields.getOrDefault(name,"").matches("0{16}"),Code.environment_invalid);
        need("1".equals(fields.get("NoNewPrivs")) && "2".equals(fields.get("Seccomp")) && "0077".equals(fields.get("Umask")),Code.environment_invalid);
        int count=0; Enumeration<NetworkInterface> all=NetworkInterface.getNetworkInterfaces();
        while(all.hasMoreElements()) { NetworkInterface n=all.nextElement(); count++; need(n.getName().equals("lo")&&n.isLoopback(),Code.environment_invalid);
            var addresses=n.getInetAddresses(); while(addresses.hasMoreElements()) need(addresses.nextElement().isLoopbackAddress(),Code.environment_invalid); }
        need(count==1,Code.environment_invalid);
        need(!Files.exists(ROOT,N) && !Files.exists(FINAL,N)
            && !Files.exists(WORK.resolve(".secure-final.json.pending"),N),Code.path_invalid);
        listeners(Set.of());
        regular(OPT.resolve("classpath"),32768,false);
        String cp=new String(read(OPT.resolve("classpath"),32768),StandardCharsets.US_ASCII);
        need(cp.endsWith("\n") && !cp.contains("\r") && cp.indexOf('\n')==cp.length()-1,Code.classpath_invalid);
        classpath=cp.substring(0,cp.length()-1); String[] entries=classpath.split(":",-1);
        need(entries.length==143 && entries[0].equals("/opt/secure/classes"),Code.classpath_invalid);
        directory(OPT,false); directory(OPT.resolve("classes"),false); directory(OPT.resolve("jars"),false);
        for(int i=1;i<entries.length;i++) { need(entries[i].equals(String.format(java.util.Locale.ROOT,"/opt/secure/jars/%03d.jar",i-1)),Code.classpath_invalid);
            regular(Path.of(entries[i]),128*1024*1024,false); }
        for(String role:List.of("SecureHdfsController","SecureKdc","SecureHdfsRoles")) regular(OPT.resolve("classes").resolve(role+".class"),MATERIAL_LIMIT,false);
        need(Files.isExecutable(JDK.resolve("bin/java")) && Files.isExecutable(JDK.resolve("bin/keytool")),Code.environment_invalid);
        CHECKS.put("environment",true);
    }
    private static void listeners(Set<Integer> expected) throws Exception {
        Set<Integer> found=new HashSet<>();
        for(String table:List.of("tcp","tcp6","udp","udp6")) {
            String[] lines=new String(read(Path.of("/proc/net/"+table),262144),StandardCharsets.US_ASCII).split("\n");
            need(lines.length<=1024,Code.listener_mismatch);
            for(int i=1;i<lines.length;i++) {
                String[] fields=lines[i].trim().split("\\s+"); need(fields.length>=4,Code.listener_mismatch);
                if(table.startsWith("udp") || fields[3].equals("0A")) {
                    need(table.equals("tcp") && fields[1].matches("0100007F:[0-9A-F]{4}"),Code.listener_mismatch);
                    int port=Integer.parseInt(fields[1].substring(9),16); need(found.add(port),Code.listener_mismatch);
                }
            }
        }
        need(found.equals(expected),Code.listener_mismatch);
    }
    private static final class Child {
        final String label; final Process process; final List<Thread> pumps=new ArrayList<>(); final boolean service;
        boolean expectedStop;
        Child(String label,Process process,boolean service) { this.label=label; this.process=process; this.service=service; }
    }
    private static void pump(Child child,InputStream input,Path output) throws Exception {
        OutputStream sink=Files.newOutputStream(output,StandardOpenOption.WRITE,N);
        Thread thread=new Thread(()->{
            try(input;sink) {
                byte[] buffer=new byte[4096]; int total=0,n;
                while((n=input.read(buffer))!=-1) {
                    if(n>LOG_LIMIT-total) { OUTPUT_FAILURE.set(true); FORCED.set(true); child.process.destroy(); break; }
                    sink.write(buffer,0,n); total+=n;
                }
            } catch(Throwable ignored) { OUTPUT_FAILURE.set(true); }
        },"secure-log-"+child.label+"-"+child.pumps.size());
        thread.setDaemon(true); child.pumps.add(thread); thread.start();
    }
    private static Child start(String label,List<String> command,boolean service) throws Exception {
        guard(); need(label.matches("[a-z0-9-]{1,40}") && CHILDREN.stream().noneMatch(c->c.label.equals(label)),Code.child_start_failed);
        Path out=ROOT.resolve("logs/"+label+".out"),err=ROOT.resolve("logs/"+label+".err");
        writeNew(out,new byte[0]); writeNew(err,new byte[0]);
        ProcessBuilder builder=new ProcessBuilder(command); builder.directory(ROOT.toFile());
        Map<String,String> env=builder.environment(); env.clear(); env.put("HOME",ROOT.resolve("home").toString());
        env.put("PATH",JDK.resolve("bin")+":/usr/bin:/bin"); env.put("LANG","C"); env.put("LC_ALL","C"); env.put("JAVA_HOME",JDK.toString());
        Child child=new Child(label,builder.start(),service); CHILDREN.add(child);
        child.process.getOutputStream().close(); pump(child,child.process.getInputStream(),out); pump(child,child.process.getErrorStream(),err);
        return child;
    }
    private static void monitor() throws Exception {
        need(System.nanoTime()<deadline,Code.deadline_exceeded); need(!OUTPUT_FAILURE.get(),Code.output_failed); guard();
        for(Child child:CHILDREN) {
            child.process.descendants().forEach(p->DESCENDANTS.putIfAbsent(p.pid(),p));
            if(child.service&&!child.expectedStop) need(child.process.isAlive(),Code.child_failed);
        }
    }
    private static void joinPumps(Child child) throws Exception {
        for(Thread thread:child.pumps) { thread.join(2000); need(!thread.isAlive(),Code.output_failed); }
    }
    private static void finishPumps(Child child) throws Exception {
        joinPumps(child);
        need(!OUTPUT_FAILURE.get(),Code.output_failed);
    }
    private static void waitExit(Child child,int seconds) throws Exception {
        long end=Math.min(deadline,System.nanoTime()+TimeUnit.SECONDS.toNanos(seconds));
        while(child.process.isAlive()) { monitor(); need(System.nanoTime()<end,Code.child_timeout); child.process.waitFor(100,TimeUnit.MILLISECONDS); }
        finishPumps(child); need(child.process.exitValue()==0,Code.child_failed);
    }
    private static List<String> javaCommand(String klass,String role) throws Exception {
        String cp=classpath;
        if(klass.equals("SecureHdfsRoles")) cp=ROOT.resolve(role.equals("dn")?"dn/resources":"nn/resources")+":"+cp;
        int heap=role.equals("nn")||role.equals("dn")?512:256;
        List<String> command=new ArrayList<>(List.of(JDK.resolve("bin/java").toString(),"-Xmx"+heap+"m","-XX:ActiveProcessorCount=2",
            "-Djava.net.preferIPv4Stack=true","-Djava.io.tmpdir="+ROOT.resolve("tmp"),"-Duser.home="+ROOT.resolve("home"),
            "-cp",cp));
        if(klass.equals("SecureHdfsRoles"))command.add("-Djava.security.krb5.conf="+AUTH.resolve("krb5.conf"));
        command.add(klass);command.add(role);return command;
    }
    private static Child javaRole(String klass,String role,boolean service) throws Exception { return start(role,javaCommand(klass,role),service); }
    private static void rejectStartupFinal(Child child) throws Exception {
        need(CHILDREN.contains(child)&&child.service&&!child.expectedStop,Code.child_start_failed);
        Path finalPath=switch(child.label) {
            case "serve" -> ROOT.resolve("kdc-final.json");
            case "nn" -> ROOT.resolve("nn-final.json");
            case "dn" -> ROOT.resolve("dn-final.json");
            default -> throw new Failure(Code.child_start_failed);
        };
        guard();
        if(!Files.exists(finalPath,N))return;
        // A constructor may be caught and a final receipt published while
        // library threads keep this exact owned JVM alive. Read only its fixed
        // closed receipt to retain finite failure diagnostics; never treat a
        // final receipt (even success=true) as startup/readiness proof.
        if(child.label.equals("serve"))kdcReceipt("serve","final");
        else roleReceipt(child.label,"final");
        throw new Failure(Code.child_failed);
    }
    private static void waitReady(Child child,String name,int seconds) throws Exception {
        String expected=switch(child.label) {
            case "serve" -> "kdc-ready.json";
            case "nn" -> "nn-ready.json";
            case "dn" -> "dn-ready.json";
            default -> throw new Failure(Code.child_start_failed);
        };
        need(name.equals(expected),Code.child_start_failed);
        Path p=ROOT.resolve(name); long end=Math.min(deadline,System.nanoTime()+TimeUnit.SECONDS.toNanos(seconds));
        while(true) {
            rejectStartupFinal(child);monitor();need(child.process.isAlive(),Code.child_failed);
            if(Files.exists(p,N)) { regular(p,JSON_LIMIT,true);rejectStartupFinal(child);return; }
            need(System.nanoTime()<end,Code.child_timeout);Thread.sleep(50);
        }
    }
    private static void keytool(String... args) throws Exception {
        List<String> command=new ArrayList<>(); command.add(JDK.resolve("bin/keytool").toString()); command.add("-J-Xmx128m");
        command.addAll(List.of(args)); Child child=start(String.format(java.util.Locale.ROOT,"keytool-%02d",keytoolNumber++),command,false); waitExit(child,20);
    }
    private static String p(String name) { return TLS.resolve(name).toString(); }
    private static void genCa(String file,String alias,String cn) throws Exception {
        keytool("-genkeypair","-alias",alias,"-keystore",p(file),"-storetype","PKCS12","-storepass:file",PASSWORD.toString(),
            "-keypass:file",PASSWORD.toString(),"-dname","CN="+cn,"-keyalg","RSA","-keysize","2048","-sigalg","SHA256withRSA",
            "-validity","1","-ext","BC:critical=ca:true,pathlen:0","-ext","KU:critical=keyCertSign,cRLSign");
    }
    private static void tlsMaterial() throws Exception {
        byte[] random=new byte[32]; new SecureRandom().nextBytes(random); String password=HexFormat.of().formatHex(random); Arrays.fill(random,(byte)0);
        storePassword=password.toCharArray(); writeNew(PASSWORD,(password+"\n").getBytes(StandardCharsets.US_ASCII));
        genCa("ca.p12","ca","Synthetic HDFS CA"); genCa("wrong-ca.p12","wrong-ca","Unrelated Synthetic CA");
        keytool("-exportcert","-alias","ca","-keystore",p("ca.p12"),"-storepass:file",PASSWORD.toString(),"-file",p("ca.der"));
        keytool("-exportcert","-alias","wrong-ca","-keystore",p("wrong-ca.p12"),"-storepass:file",PASSWORD.toString(),"-file",p("wrong-ca.der"));
        for(String role:List.of("nn","dn")) {
            keytool("-genkeypair","-alias",role,"-keystore",p(role+".p12"),"-storetype","PKCS12","-storepass:file",PASSWORD.toString(),
                "-keypass:file",PASSWORD.toString(),"-dname","CN=Synthetic "+role,"-keyalg","RSA","-keysize","2048","-sigalg","SHA256withRSA","-validity","1");
            keytool("-certreq","-alias",role,"-keystore",p(role+".p12"),"-storepass:file",PASSWORD.toString(),
                "-keypass:file",PASSWORD.toString(),"-file",p(role+".csr"));
            keytool("-gencert","-alias","ca","-keystore",p("ca.p12"),"-storepass:file",PASSWORD.toString(),"-keypass:file",PASSWORD.toString(),
                "-infile",p(role+".csr"),"-outfile",p(role+".der"),"-validity","1","-ext","BC:critical=ca:false",
                "-ext","KU:critical=digitalSignature,keyEncipherment","-ext","EKU=serverAuth","-ext","SAN=IP:127.0.0.1");
            keytool("-importcert","-noprompt","-alias","ca","-keystore",p(role+".p12"),"-storepass:file",PASSWORD.toString(),"-file",p("ca.der"));
            keytool("-importcert","-noprompt","-alias",role,"-keystore",p(role+".p12"),"-storepass:file",PASSWORD.toString(),
                "-keypass:file",PASSWORD.toString(),"-file",p(role+".der"));
        }
        for(String prefix:List.of("","wrong-")) keytool("-importcert","-noprompt","-alias",prefix+"ca","-keystore",p(prefix+"trust.p12"),
            "-storetype","PKCS12","-storepass:file",PASSWORD.toString(),"-file",p(prefix+"ca.der"));
        X509Certificate ca=certificate(loadStore("ca.p12"),"ca"),wrong=certificate(loadStore("wrong-ca.p12"),"wrong-ca");
        verifyCa(ca); verifyCa(wrong); need(!Arrays.equals(ca.getEncoded(),wrong.getEncoded()),Code.tls_material_invalid);
        verifyTrust(loadStore("trust.p12"),"ca",ca); verifyTrust(loadStore("wrong-trust.p12"),"wrong-ca",wrong);
        for(String role:List.of("nn","dn")) {
            KeyStore store=loadStore(role+".p12"); need(Collections.list(store.aliases()).size()==2&&store.isKeyEntry(role)&&store.isCertificateEntry("ca"),Code.tls_material_invalid);
            var chain=store.getCertificateChain(role); need(chain!=null&&chain.length==2&&Arrays.equals(chain[1].getEncoded(),ca.getEncoded()),Code.tls_material_invalid);
            X509Certificate leaf=certificate(store,role); leaf.verify(ca.getPublicKey()); verifyLeaf(leaf);
            Map<String,String> ssl=new LinkedHashMap<>();
            ssl.put("ssl.server.keystore.location",p(role+".p12")); ssl.put("ssl.server.keystore.type","PKCS12");
            ssl.put("ssl.server.keystore.password",password); ssl.put("ssl.server.keystore.keypassword",password);
            ssl.put("ssl.server.truststore.location",p("trust.p12")); ssl.put("ssl.server.truststore.type","PKCS12"); ssl.put("ssl.server.truststore.password",password);
            StringBuilder xml=new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration>\n");
            for(var item:ssl.entrySet()) xml.append("<property><name>").append(escapeXml(item.getKey())).append("</name><value>")
                .append(escapeXml(item.getValue())).append("</value></property>\n");
            xml.append("</configuration>\n"); Path resource=ROOT.resolve(role+"/resources/ssl-server.xml"); writeNew(resource,xml.toString().getBytes(StandardCharsets.UTF_8)); remember(resource);
        }
        try(DirectoryStream<Path> entries=Files.newDirectoryStream(TLS)) { for(Path file:entries) remember(file); }
        CHECKS.put("tls_material",true);
    }
    private static String escapeXml(String value) { return value.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;").replace("'","&apos;"); }
    private static KeyStore loadStore(String file) throws Exception {
        Path path=TLS.resolve(file); regular(path,MATERIAL_LIMIT,true); KeyStore store=KeyStore.getInstance("PKCS12");
        try(InputStream in=Files.newInputStream(path,N)) { store.load(in,storePassword); } return store;
    }
    private static X509Certificate certificate(KeyStore store,String alias) throws Exception {
        need(store.getCertificate(alias) instanceof X509Certificate,Code.tls_material_invalid); return (X509Certificate)store.getCertificate(alias);
    }
    private static void validity(X509Certificate cert) throws Exception {
        cert.checkValidity(); need(cert.getNotBefore().getTime()>=startedMillis-60000 && cert.getNotAfter().getTime()-cert.getNotBefore().getTime()<=TimeUnit.HOURS.toMillis(25)
            && cert.getExtensionValue("1.3.6.1.5.5.7.1.1")==null && cert.getExtensionValue("2.5.29.31")==null,Code.tls_material_invalid);
    }
    private static void verifyCa(X509Certificate ca) throws Exception {
        validity(ca); ca.verify(ca.getPublicKey()); need(ca.getBasicConstraints()==0 && ca.getSubjectX500Principal().equals(ca.getIssuerX500Principal()),Code.tls_material_invalid);
        boolean[] usage=ca.getKeyUsage(); need(usage!=null&&usage.length>6&&usage[5]&&usage[6],Code.tls_material_invalid);
    }
    private static void verifyLeaf(X509Certificate leaf) throws Exception {
        validity(leaf); need(leaf.getBasicConstraints()==-1&&List.of("1.3.6.1.5.5.7.3.1").equals(leaf.getExtendedKeyUsage()),Code.tls_material_invalid);
        boolean[] usage=leaf.getKeyUsage(); need(usage!=null&&usage.length>2&&usage[0]&&usage[2],Code.tls_material_invalid);
        Collection<List<?>> sans=leaf.getSubjectAlternativeNames(); need(sans!=null&&sans.size()==1,Code.tls_material_invalid);
        List<?> san=sans.iterator().next(); need(san.size()==2&&Integer.valueOf(7).equals(san.get(0))&&"127.0.0.1".equals(san.get(1)),Code.tls_material_invalid);
    }
    private static void verifyTrust(KeyStore store,String alias,X509Certificate cert) throws Exception {
        need(Collections.list(store.aliases()).equals(List.of(alias)) && store.isCertificateEntry(alias)
            && Arrays.equals(store.getCertificate(alias).getEncoded(),cert.getEncoded()),Code.tls_material_invalid);
    }
    private static SSLContext context(String trust) throws Exception {
        TrustManagerFactory factory=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); factory.init(loadStore(trust));
        SSLContext context=SSLContext.getInstance("TLS"); context.init(null,factory.getTrustManagers(),new SecureRandom()); return context;
    }
    private static void handshake(SSLContext context,int port,String host,X509Certificate expected) throws Exception {
        try(Socket transport=new Socket()) {
            transport.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127,0,0,1}),port),3000); transport.setSoTimeout(3000);
            try(SSLSocket socket=(SSLSocket)context.getSocketFactory().createSocket(transport,host,port,true)) {
                socket.setSoTimeout(3000); SSLParameters parameters=socket.getSSLParameters(); parameters.setEndpointIdentificationAlgorithm("HTTPS");
                parameters.setServerNames(Collections.emptyList()); socket.setSSLParameters(parameters);
                need("HTTPS".equals(socket.getSSLParameters().getEndpointIdentificationAlgorithm()),Code.tls_verification_failed);
                socket.startHandshake(); var chain=socket.getSession().getPeerCertificates();
                need(chain.length==2 && chain[0] instanceof X509Certificate && Arrays.equals(chain[0].getEncoded(),expected.getEncoded()),Code.tls_verification_failed);
                verifyLeaf((X509Certificate)chain[0]);
            }
        }
    }
    private static boolean certificateFailure(SSLHandshakeException e) {
        Set<Throwable> seen=Collections.newSetFromMap(new java.util.IdentityHashMap<>());
        for(Throwable t=e; t!=null&&seen.size()<12&&seen.add(t); t=t.getCause()) if(t instanceof CertificateException) return true;
        return false;
    }
    private static void rejectTls(SSLContext context,int port,String host,X509Certificate expected) throws Exception {
        boolean denied=false;
        try { handshake(context,port,host,expected); } catch(SSLHandshakeException error) { denied=certificateFailure(error); }
        need(denied,Code.tls_negative_mismatch);
    }
    private static void verifyHttps() throws Exception {
        SSLContext trust=context("trust.p12"),wrong=context("wrong-trust.p12");
        for(String role:List.of("nn","dn")) {
            monitor(); int port=role.equals("nn")?19003:19004; X509Certificate expected=certificate(loadStore(role+".p12"),role);
            handshake(trust,port,"127.0.0.1",expected); rejectTls(trust,port,"synthetic.invalid",expected); rejectTls(wrong,port,"127.0.0.1",expected);
        }
        CHECKS.put("https_verified",true); CHECKS.put("https_wrong_host_rejected",true); CHECKS.put("https_wrong_ca_rejected",true);
    }

    /* Tagged Hadoop 3.5.0: RpcConstants (header/version/-1 call ID),
       Server.initializeAuthContext(NONE), doSaslReply(Exception), setupResponse,
       and RpcHeader.proto. This observes the server rejection independently of
       the Go client's sequence-number error; it is not correlated to that call.
       Sources: https://github.com/apache/hadoop/tree/rel/release-3.5.0/
       hadoop-common-project/hadoop-common/src/main/{java/org/apache/hadoop/ipc,proto}
       No RPC operation, credentials, DNS or filesystem path is sent. */
    private static byte[] socketBytes(Socket socket,int length,long end) throws Exception {
        need(length>=0&&length<=8192,Code.simple_rpc_rejection_failed);byte[] bytes=new byte[length];int offset=0;
        while(offset<length) {
            long left=end-System.nanoTime();need(left>0,Code.simple_rpc_rejection_failed);
            socket.setSoTimeout((int)Math.max(1,Math.min(3000,TimeUnit.NANOSECONDS.toMillis(left))));
            int count=socket.getInputStream().read(bytes,offset,length-offset);need(count>0,Code.simple_rpc_rejection_failed);offset+=count;
        }return bytes;
    }
    private static long varint(ByteBuffer bytes) throws Exception {
        long value=0;for(int i=0;i<9;i++) {
            need(bytes.hasRemaining(),Code.simple_rpc_rejection_failed);int b=bytes.get()&255;value|=(long)(b&127)<<(i*7);
            if((b&128)==0){need(i==0||b!=0,Code.simple_rpc_rejection_failed);return value;}
        }throw new Failure(Code.simple_rpc_rejection_failed);
    }
    private static void simpleRpcRejection() throws Exception {
        monitor();long end=Math.min(deadline,System.nanoTime()+TimeUnit.SECONDS.toNanos(6));
        try(Socket socket=new Socket()) {
            socket.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127,0,0,1}),19000),2000);
            socket.getOutputStream().write(new byte[]{'h','r','p','c',9,0,0});socket.getOutputStream().flush();
            int length=ByteBuffer.wrap(socketBytes(socket,4,end)).getInt();need(length>0&&length<=8192,Code.simple_rpc_rejection_failed);
            ByteBuffer frame=ByteBuffer.wrap(socketBytes(socket,length,end));long headerLength=varint(frame);
            need(headerLength==frame.remaining(),Code.simple_rpc_rejection_failed);
            Map<Integer,Object> values=new LinkedHashMap<>();
            while(frame.hasRemaining()) {
                long tag=varint(frame);int field=(int)(tag>>>3),wire=(int)(tag&7);
                need(tag<=72&&field>=1&&field<=9&&!values.containsKey(field),Code.simple_rpc_rejection_failed);
                if(Set.of(1,2,3,6,8,9).contains(field)) {
                    need(wire==0,Code.simple_rpc_rejection_failed);long value=varint(frame);
                    need(field==9||value<=0xffffffffL,Code.simple_rpc_rejection_failed);values.put(field,value);
                } else {
                    need(wire==2,Code.simple_rpc_rejection_failed);long size=varint(frame);
                    need(size<=4096&&size<=frame.remaining(),Code.simple_rpc_rejection_failed);byte[] bytes=new byte[(int)size];frame.get(bytes);
                    if(field==7){need(bytes.length==0,Code.simple_rpc_rejection_failed);values.put(field,"");}
                    else values.put(field,StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString());
                }
            }
            Set<Integer> required=Set.of(1,2,3,4,5,6,7,8);
            need(values.keySet().equals(required)||values.keySet().equals(plusIntegers(required,9)),Code.simple_rpc_rejection_failed);
            need(Long.valueOf(0xffffffffL).equals(values.get(1))&&Long.valueOf(2).equals(values.get(2))
                &&Long.valueOf(9).equals(values.get(3))&&Long.valueOf(15).equals(values.get(6))&&Long.valueOf(1).equals(values.get(8))
                &&"org.apache.hadoop.security.AccessControlException".equals(values.get(4))
                &&values.get(5) instanceof String&&((String)values.get(5)).matches(
                    "SIMPLE authentication is not enabled\\.  Available:\\[(TOKEN, )?KERBEROS\\]"),Code.simple_rpc_rejection_failed);
            long left=end-System.nanoTime();need(left>0,Code.simple_rpc_rejection_failed);
            socket.setSoTimeout((int)Math.max(1,Math.min(3000,TimeUnit.NANOSECONDS.toMillis(left))));
            need(socket.getInputStream().read()==-1,Code.simple_rpc_rejection_failed);
        }
        monitor();listeners(PORTS);CHECKS.put("simple_rpc_rejected",true);
    }
    private static Set<Integer> plusIntegers(Set<Integer> base,int value){Set<Integer> result=new HashSet<>(base);result.add(value);return result;}

    /* Closed JSON reader: no dependencies, duplicate keys/floats/UTF8 errors,
       non-finite values, excessive nesting and oversized documents rejected. */
    private static final class Json {
        final String s; int i, count;
        Json(byte[] bytes) throws Exception { s=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString(); }
        void ws() { while(i<s.length()&&" \r\n\t".indexOf(s.charAt(i))>=0)i++; }
        Object value(int depth) throws Exception {
            ws(); need(depth<12&&++count<4096&&i<s.length(),Code.receipt_invalid); char c=s.charAt(i);
            if(c=='{') { i++; Map<String,Object> m=new LinkedHashMap<>(); ws(); if(i<s.length()&&s.charAt(i)=='}'){i++;return m;}
                while(true){ws();need(i<s.length()&&s.charAt(i)=='"',Code.receipt_invalid);String k=string();ws();need(i<s.length()&&s.charAt(i++)==':',Code.receipt_invalid);
                    need(!m.containsKey(k),Code.receipt_invalid);m.put(k,value(depth+1));ws();need(i<s.length(),Code.receipt_invalid);char end=s.charAt(i++);if(end=='}')return m;need(end==',',Code.receipt_invalid);} }
            if(c=='[') { i++; List<Object> a=new ArrayList<>();ws();if(i<s.length()&&s.charAt(i)==']'){i++;return a;}
                while(true){a.add(value(depth+1));ws();need(i<s.length(),Code.receipt_invalid);char end=s.charAt(i++);if(end==']')return a;need(end==',',Code.receipt_invalid);} }
            if(c=='"') return string();
            for(String literal:List.of("true","false","null")) if(s.startsWith(literal,i)){i+=literal.length();return literal.equals("null")?null:Boolean.valueOf(literal);}
            int start=i;if(c=='-')i++;need(i<s.length()&&Character.isDigit(s.charAt(i)),Code.receipt_invalid);
            if(s.charAt(i)=='0')i++;else while(i<s.length()&&s.charAt(i)>='0'&&s.charAt(i)<='9')i++;
            need(i-start<=19,Code.receipt_invalid);try{return Long.valueOf(s.substring(start,i));}catch(NumberFormatException e){throw new Failure(Code.receipt_invalid);}
        }
        String string() throws Exception {
            need(s.charAt(i++)=='"',Code.receipt_invalid);StringBuilder out=new StringBuilder();
            while(i<s.length()){char c=s.charAt(i++);if(c=='"'){need(out.length()<=4096,Code.receipt_invalid);return out.toString();}
                need(c>=32,Code.receipt_invalid);if(c=='\\'){need(i<s.length(),Code.receipt_invalid);char e=s.charAt(i++);
                    if(e=='u'){need(i+4<=s.length(),Code.receipt_invalid);String hex=s.substring(i,i+4);need(hex.matches("[0-9a-fA-F]{4}"),Code.receipt_invalid);out.append((char)Integer.parseInt(hex,16));i+=4;}
                    else {int index="\"\\/bfnrt".indexOf(e);need(index>=0,Code.receipt_invalid);out.append("\"\\/\b\f\n\r\t".charAt(index));}}
                else out.append(c);
            } throw new Failure(Code.receipt_invalid);
        }
    }
    @SuppressWarnings("unchecked") private static Map<String,Object> object(Object value) throws Exception { need(value instanceof Map,Code.receipt_invalid);return (Map<String,Object>)value; }
    private static Map<String,Object> receipt(String name) throws Exception {
        Path p=ROOT.resolve(name);regular(p,JSON_LIMIT,true);Json parser=new Json(read(p,JSON_LIMIT));Map<String,Object> value=object(parser.value(0));parser.ws();need(parser.i==parser.s.length(),Code.receipt_invalid);return value;
    }
    private static void trueMap(Object value,Set<String> keys) throws Exception { Map<String,Object> map=object(value);need(map.keySet().equals(keys)&&map.values().stream().allMatch(Boolean.TRUE::equals),Code.receipt_invalid); }
    private static void falseClaims(Map<String,Object> report,boolean publisher) throws Exception {
        for(String name:CLAIMS)need(Boolean.FALSE.equals(report.get(name)),Code.receipt_invalid);
        if(publisher)need(Boolean.FALSE.equals(report.get("publisher_audit_completed")),Code.receipt_invalid);
    }
    private static Set<String> plus(Set<String> base,String... names) { Set<String> result=new HashSet<>(base);result.addAll(List.of(names));return result; }
    private static Set<String> roleChecks(String role) {
        Set<String> checks=new HashSet<>(Set.of("environment","material_paths","secure_configuration","keytab_login","configuration_preserved"));
        if(role.equals("format"))checks.add("fresh_format");else checks.add("bound_service_addresses");
        if(role.equals("seed")||role.equals("verify"))checks.add("source_preserved");return checks;
    }
    private static void classifyRoleFailure(Map<String,Object> report,String role) throws Exception {
        // Called only after the exact public envelope and every false claim
        // were checked. This never promotes a failed receipt to acceptance.
        Map<String,Object> checks=object(report.get("checks"));
        need(checks.keySet().equals(roleChecks(role))&&checks.values().stream().allMatch(v->v instanceof Boolean)
            &&report.get("api_shutdown_complete") instanceof Boolean,Code.receipt_invalid);
        Object digest=report.get("configuration_sha256");
        need(digest==null||(digest instanceof String&&((String)digest).matches("[a-f0-9]{64}")),Code.receipt_invalid);
        Object files=report.get("files");
        need(files==null||((role.equals("seed")||role.equals("verify"))&&expectedManifest().equals(files)),Code.receipt_invalid);
        need(report.get("errors") instanceof List<?>,Code.receipt_invalid);
        List<?> errors=(List<?>)report.get("errors");need(!errors.isEmpty()&&errors.size()<=16,Code.receipt_invalid);
        Set<String> seen=new HashSet<>();
        for(Object value:errors)need(value instanceof String&&((String)value).length()<=64&&seen.add((String)value),Code.receipt_invalid);
        // No valueOf, interpolated prefix, exception message, path or arbitrary
        // child string can reach ERRORS. Only these literal enum values leave
        // the private role boundary, even for an unknown/malicious child code.
        for(Object value:errors) {
            Code code=switch((String)value) {
                case "arguments_invalid","environment_failed","environment_invalid" -> Code.role_environment_failed;
                case "material_failed","material_invalid","material_changed","root_identity_changed" -> Code.role_material_failed;
                case "configuration_failed","configuration_changed","secure_configuration_invalid","ssl_resource_invalid",
                     "webapp_resources_failed","webapp_resources_invalid" -> Code.role_configuration_failed;
                case "login_failed","keytab_login_invalid" -> Code.role_login_failed;
                case "keytab_unreadable" -> Code.role_keytab_unreadable;
                case "login_exception" -> Code.role_login_exception;
                case "socket_timeout" -> Code.role_socket_timeout;
                case "connection_failed" -> Code.role_connection_failed;
                case "kerberos_failure" -> Code.role_kerberos_failure;
                case "kerberos_client_unknown" -> Code.role_kerberos_client_unknown;
                case "kerberos_server_unknown" -> Code.role_kerberos_server_unknown;
                case "kerberos_policy_rejected" -> Code.role_kerberos_policy_rejected;
                case "kerberos_etype_unsupported" -> Code.role_kerberos_etype_unsupported;
                case "kerberos_preauth_failed" -> Code.role_kerberos_preauth_failed;
                case "kerberos_preauth_required" -> Code.role_kerberos_preauth_required;
                case "kerberos_integrity_failed" -> Code.role_kerberos_integrity_failed;
                case "kerberos_clock_skew" -> Code.role_kerberos_clock_skew;
                case "kerberos_message_modified" -> Code.role_kerberos_message_modified;
                case "kerberos_generic_error" -> Code.role_kerberos_generic_error;
                case "kerberos_asn_identifier" -> Code.role_kerberos_asn_identifier;
                case "format_failed" -> Code.role_format_failed;
                case "format_preexisting" -> Code.role_format_preexisting;
                case "format_incomplete" -> Code.role_format_incomplete;
                case "source_failed","source_preexisting","source_scope","source_inventory_bound","source_duplicate",
                     "source_inventory_changed","source_metadata_changed","source_bytes_changed","missing_member_present","mkdir_failed" -> Code.role_source_failed;
                case "namenode_start_failed","datanode_start_failed","client_start_failed","startup_timeout",
                     "extra_service","endpoint_mismatch","datanode_not_ready" -> Code.role_service_start_failed;
                case "stop_failed","shutdown_invalid","shutdown_preexisting","shutdown_timeout","client_close_failed",
                     "datanode_close_failed","namenode_close_failed","login_close_failed","constructor_cleanup_unconfirmed" -> Code.role_cleanup_failed;
                case "preservation_failed" -> Code.role_preservation_failed;
                case "report_failed","report_invalid","report_preexisting" -> Code.role_report_failed;
                case "invalid_config" -> Code.role_invalid_config;
                case "io_failure" -> Code.role_io_failure;
                case "file_missing" -> Code.role_file_missing;
                case "security_failure" -> Code.role_security_failure;
                case "illegal_state" -> Code.role_illegal_state;
                case "null_state" -> Code.role_null_state;
                case "missing_class" -> Code.role_missing_class;
                case "linkage_failure" -> Code.role_linkage_failure;
                case "resource_failure" -> Code.role_resource_failure;
                case "exit_requested" -> Code.role_exit_requested;
                case "halt_requested" -> Code.role_halt_requested;
                default -> Code.role_unclassified;
            };
            ERRORS.add(code.name());
        }
    }
    private static void commonReceipt(Map<String,Object> report,String scope,String role,String phase,Set<String> keys,boolean publisher) throws Exception {
        Set<String> expected=plus(keys,CLAIMS.toArray(String[]::new));if(publisher)expected.add("publisher_audit_completed");
        need(report.keySet().equals(expected)&&Long.valueOf(1).equals(report.get("schema_version"))&&scope.equals(report.get("scope"))
            &&role.equals(report.get("role"))&&phase.equals(report.get("phase")),Code.receipt_invalid);falseClaims(report,publisher);
        if(publisher&&Boolean.FALSE.equals(report.get("success")))classifyRoleFailure(report,role);
        need(Boolean.TRUE.equals(report.get("success"))&&List.of().equals(report.get("errors")),Code.receipt_invalid);
    }
    private static void roleReceipt(String role,String phase) throws Exception {
        Map<String,Object> report=receipt(role+"-"+phase+".json");
        commonReceipt(report,"secure_hdfs_role_feasibility",role,phase,Set.of("schema_version","scope","role","phase","success","checks","configuration_sha256","files","api_shutdown_complete","errors"),true);
        trueMap(report.get("checks"),roleChecks(role));
        need(report.get("configuration_sha256") instanceof String&&((String)report.get("configuration_sha256")).matches("[a-f0-9]{64}"),Code.receipt_invalid);
        String binding=role.equals("verify")?"seed":role;
        String digest=(String)report.get("configuration_sha256");
        if(ROLE_CONFIGURATIONS.containsKey(binding))need(ROLE_CONFIGURATIONS.get(binding).equals(digest),Code.input_changed);
        else ROLE_CONFIGURATIONS.put(binding,digest);
        need(Boolean.valueOf(phase.equals("final")).equals(report.get("api_shutdown_complete")),Code.receipt_invalid);
        if(role.equals("seed")||role.equals("verify")) need(expectedManifest().equals(report.get("files")),Code.receipt_invalid);
        else need(report.get("files")==null,Code.receipt_invalid);
    }
    private static void kdcReceipt(String role,String phase) throws Exception {
        Map<String,Object> report=receipt((role.equals("serve")?"kdc":"ticket")+"-"+phase+".json");
        commonReceipt(report,"secure_hdfs_kdc_feasibility",role,phase,Set.of("schema_version","scope","role","phase","success","expected_kerby_version","checks","cleanup","cache_bytes","observed_lifetime_seconds","errors"),false);
        need("2.1.2".equals(report.get("expected_kerby_version")),Code.receipt_invalid);
        if(role.equals("serve")) {
            trueMap(report.get("checks"),Set.of("environment","endpoint_settings","material_ready","configuration_preserved"));
            trueMap(report.get("cleanup"),phase.equals("ready")?Set.of():Set.of("kdc_stop_returned","listeners_absent","threads_terminated","process_property_restored","known_config_removed"));
            need(Long.valueOf(0).equals(report.get("cache_bytes"))&&Long.valueOf(0).equals(report.get("observed_lifetime_seconds")),Code.receipt_invalid);
        } else {
            trueMap(report.get("checks"),Set.of("environment","endpoint_settings","positive_tgt","file_cache_v3","nonrenewable","cache_preserved","configuration_preserved"));
            trueMap(report.get("cleanup"),Set.of("threads_terminated"));
            need(report.get("cache_bytes") instanceof Long&&(Long)report.get("cache_bytes")>0&&(Long)report.get("cache_bytes")<=65536
                &&report.get("observed_lifetime_seconds") instanceof Long&&(Long)report.get("observed_lifetime_seconds")>=110&&(Long)report.get("observed_lifetime_seconds")<=120,Code.receipt_invalid);
        }
    }
    private static List<Object> expectedManifest() throws Exception {
        Map<String,byte[]> samples=new TreeMap<>();
        samples.put("README.txt",HexFormat.of().parseHex("484446532073796e74686574696320666978747572650a"));samples.put("empty.bin",new byte[0]);
        samples.put("nested/alpha.txt",HexFormat.of().parseHex("616c7068610a"));samples.put("nested/space name.txt",HexFormat.of().parseHex("7370616365206e616d650a"));
        samples.put("unicode/utf8.txt",HexFormat.of().parseHex("636166c3a90a"));samples.put("private/owner-only.txt",HexFormat.of().parseHex("707269766174652073796e7468657469632062797465730a"));
        for(var entry:Map.of("nested/deeper/data.bin",256,"large/cancel.bin",2097152).entrySet()){byte[] bytes=new byte[entry.getValue()];for(int i=0;i<bytes.length;i++)bytes[i]=(byte)(i&255);samples.put(entry.getKey(),bytes);}
        List<Object> result=new ArrayList<>();for(var entry:samples.entrySet())result.add(Map.of("path",entry.getKey(),"size",(long)entry.getValue().length,
            "sha256",HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(entry.getValue())),"mode",entry.getKey().startsWith("private/")?"0600":"0644",
            "mtime_ms",1704067200000L));return result;
    }
    private static void rememberAuth() throws Exception {
        directory(AUTH,true);Set<String> names=new HashSet<>();try(DirectoryStream<Path> stream=Files.newDirectoryStream(AUTH)){for(Path path:stream)names.add(path.getFileName().toString());}
        Set<String> expected=Set.of("realm","krb5.conf","nn.keytab","dn.keytab","http.keytab","reader.password","rclone.conf","simple.conf");
        need(names.equals(expected),Code.input_changed);
        for(String name:expected)remember(AUTH.resolve(name));
    }
    private static boolean stopRequested() throws Exception {
        Path p=ROOT.resolve("stop");if(!Files.exists(p,N))return false;regular(p,0,true);need(Files.size(p)==0,Code.stop_invalid);return true;
    }
    private static Child child(String label) { return CHILDREN.stream().filter(c->c.label.equals(label)).findFirst().orElse(null); }
    private static void stopService(String label,String marker,String receiptRole) throws Exception {
        Child c=child(label);if(c==null)return;guard();c.expectedStop=true;
        if(c.process.isAlive())writeNew(ROOT.resolve(marker),new byte[0]);
        long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(12);
        while(c.process.isAlive()&&System.nanoTime()<end)c.process.waitFor(100,TimeUnit.MILLISECONDS);
        need(!c.process.isAlive(),Code.role_stop_failed);finishPumps(c);need(c.process.exitValue()==0,Code.role_stop_failed);
        if(receiptRole.equals("serve"))kdcReceipt("serve","final");else roleReceipt(receiptRole,"final");
    }
    private static void terminate(Child c) {
        if(!c.process.isAlive())return;FORCED.set(true);ERRORS.add(Code.forced_termination.name());
        try { c.process.descendants().forEach(p->DESCENDANTS.putIfAbsent(p.pid(),p)); c.process.destroy();
            if(!c.process.waitFor(1500,TimeUnit.MILLISECONDS)){c.process.destroyForcibly();c.process.waitFor(2000,TimeUnit.MILLISECONDS);} }
        catch(Throwable ignored){ERRORS.add(Code.process_cleanup_failed.name());}
    }
    private static void removeOwnedRoot() throws Exception {
        guard();List<Path> paths=new ArrayList<>();Map<Path,Object> identities=new LinkedHashMap<>();long[] bytes={0};
        Files.walkFileTree(ROOT,Set.of(),24,new SimpleFileVisitor<Path>() {
            private void add(Path path,BasicFileAttributes a) throws IOException {
                try {
                    need(path.normalize().startsWith(ROOT)&&!a.isSymbolicLink()&&a.fileKey()!=null&&paths.size()<8192,Code.private_cleanup_failed);
                    need(unix(path,"uid")==10001&&unix(path,"gid")==10001,Code.private_cleanup_failed);
                    if(!a.isDirectory())need(a.isRegularFile()&&unix(path,"nlink")==1,Code.private_cleanup_failed);
                    bytes[0]+=a.isRegularFile()?a.size():0;need(bytes[0]<=512L*1024*1024,Code.private_cleanup_failed);
                    paths.add(path);identities.put(path,a.fileKey());
                }catch(Exception error){throw new IOException("owned_cleanup_guard");}
            }
            @Override public FileVisitResult preVisitDirectory(Path p,BasicFileAttributes a)throws IOException{add(p,a);return FileVisitResult.CONTINUE;}
            @Override public FileVisitResult visitFile(Path p,BasicFileAttributes a)throws IOException{add(p,a);return FileVisitResult.CONTINUE;}
        });
        Collections.reverse(paths);
        for(Path path:paths){guard();need(identities.get(path).equals(Files.readAttributes(path,BasicFileAttributes.class,N).fileKey()),Code.input_changed);Files.delete(path);}
        rootCreated=false;need(!Files.exists(ROOT,N),Code.private_cleanup_failed);
    }
    private static void cleanup() {
        for(String key:CLEANUP_KEYS)CLEANUP.put(key,false);
        for(Child c:CHILDREN)if(!c.service)terminate(c);
        for(String role:List.of("dn","nn","serve")) {
            String key=role.equals("serve")?"kdc":role;
            try { stopService(role,"stop-"+key,role);CLEANUP.put(key+"_stopped",true); }
            catch(Throwable error){record(error,Code.role_stop_failed);Child c=child(role);if(c!=null)terminate(c);}
        }
        for(Child c:CHILDREN)terminate(c);
        for(ProcessHandle p:DESCENDANTS.values())if(p.isAlive()) {
            FORCED.set(true);ERRORS.add(Code.forced_termination.name());try{p.destroy();p.onExit().get(1,TimeUnit.SECONDS);}catch(Throwable ignored){try{p.destroyForcibly();p.onExit().get(2,TimeUnit.SECONDS);}catch(Throwable ignoredAgain){}}
        }
        boolean processes=CHILDREN.stream().noneMatch(c->c.process.isAlive())&&DESCENDANTS.values().stream().noneMatch(ProcessHandle::isAlive);
        // Output overflow remains a failure, but does not pretend an exited,
        // reaped process is alive or prevent safe private-file removal.
        for(Child c:CHILDREN)try{joinPumps(c);}catch(Throwable error){record(error,Code.output_failed);processes=false;}
        if(OUTPUT_FAILURE.get())ERRORS.add(Code.output_failed.name());
        CLEANUP.put("processes_reaped",processes);boolean absent=false;
        try{listeners(Set.of());absent=true;}catch(Throwable error){record(error,Code.listener_mismatch);}CLEANUP.put("listeners_absent",absent);
        if(processes&&absent) {
            if(Boolean.TRUE.equals(CLEANUP.get("kdc_stopped"))&&MATERIAL.containsKey(AUTH.resolve("krb5.conf")))
                try{preserve(true);}catch(Throwable error){record(error,Code.input_changed);}
            try{if(rootCreated)removeOwnedRoot();CLEANUP.put("private_material_removed",!Files.exists(ROOT,N));}
            catch(Throwable error){record(error,Code.private_cleanup_failed);}
        }
        CLEANUP.put("no_forced_termination",!FORCED.get());
        if(storePassword!=null)Arrays.fill(storePassword,'\0');
    }
    private static String quote(String text) { return "\""+text+"\""; }
    private static String booleans(Map<String,Boolean> values) { List<String> rows=new ArrayList<>();for(var entry:values.entrySet())rows.add(quote(entry.getKey())+":"+entry.getValue());return "{"+String.join(",",rows)+"}"; }
    private static String report(String phase,boolean success) {
        StringBuilder text=new StringBuilder("{\"schema_version\":1,\"scope\":\"secure_hdfs_controller_feasibility\",\"phase\":").append(quote(phase))
            .append(",\"success\":").append(success).append(",\"checks\":").append(booleans(CHECKS)).append(",\"cleanup\":").append(phase.equals("ready")?"{}":booleans(CLEANUP));
        text.append(",\"errors\":[");boolean first=true;for(String error:ERRORS){if(!first)text.append(',');text.append(quote(error));first=false;}text.append(']');
        for(String claim:CLAIMS)text.append(',').append(quote(claim)).append(":false");return text.append("}\n").toString();
    }
    public static void main(String[] args) {
        for(String check:READY_CHECKS)CHECKS.put(check,false);
        startedMillis=System.currentTimeMillis();deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(240);Code stage=Code.environment_invalid;
        try {
            environment(args);stage=Code.path_invalid;mkdir(ROOT);
            for(String name:List.of("tls","logs","home","tmp","nn","dn"))mkdir(ROOT.resolve(name));
            for(String role:List.of("nn","dn"))for(String name:List.of("data","tmp","http","resources"))mkdir(ROOT.resolve(role+"/"+name));
            CHECKS.put("private_runtime",true);stage=Code.tls_generation_failed;tlsMaterial();
            stage=Code.kdc_start_failed;Child kdc=javaRole("SecureKdc","serve",true);waitReady(kdc,"kdc-ready.json",25);kdcReceipt("serve","ready");listeners(Set.of(19006));rememberAuth();CHECKS.put("kdc_ready",true);
            stage=Code.format_failed;Child format=javaRole("SecureHdfsRoles","format",false);waitExit(format,30);roleReceipt("format","final");CHECKS.put("format_complete",true);
            stage=Code.nn_start_failed;Child nn=javaRole("SecureHdfsRoles","nn",true);waitReady(nn,"nn-ready.json",45);roleReceipt("nn","ready");listeners(Set.of(19000,19003,19006));CHECKS.put("nn_ready",true);
            stage=Code.dn_start_failed;Child dn=javaRole("SecureHdfsRoles","dn",true);waitReady(dn,"dn-ready.json",45);roleReceipt("dn","ready");listeners(PORTS);CHECKS.put("dn_ready",true);CHECKS.put("listeners_exact",true);
            stage=Code.tls_verification_failed;verifyHttps();
            stage=Code.seed_failed;Child seed=javaRole("SecureHdfsRoles","seed",false);waitExit(seed,35);roleReceipt("seed","final");CHECKS.put("seed_verified",true);
            stage=Code.simple_rpc_rejection_failed;simpleRpcRejection();
            stage=Code.ticket_failed;Child ticket=javaRole("SecureKdc","ticket",false);waitExit(ticket,30);kdcReceipt("ticket","final");remember(AUTH.resolve("reader.ccache"));CHECKS.put("ticket_ready",true);
            preserve(false);listeners(PORTS);monitor();stage=Code.report_failed;publish(ROOT.resolve("ready.json"),report("ready",true));readyPublished=true;
            stage=Code.stop_invalid;while(!stopRequested()){monitor();listeners(PORTS);Thread.sleep(100);}
            CHECKS.put("stop_requested",true);stage=Code.source_verification_failed;preserve(false);
            Child verify=javaRole("SecureHdfsRoles","verify",false);waitExit(verify,35);roleReceipt("verify","final");preserve(false);CHECKS.put("source_verified",true);
        } catch(Throwable error) { record(error,stage); }
        finally {
            CHECKS.putIfAbsent("stop_requested",false);CHECKS.putIfAbsent("source_verified",false);
            try{cleanup();}catch(Throwable error){record(error,Code.process_cleanup_failed);}
        }
        boolean success=readyPublished&&ERRORS.isEmpty()&&CHECKS.values().stream().allMatch(Boolean.TRUE::equals)
            &&CLEANUP.size()==CLEANUP_KEYS.size()&&CLEANUP.values().stream().allMatch(Boolean.TRUE::equals);
        try{publish(FINAL,report("final",success));}catch(Throwable ignored){success=false;}
        System.exit(success?0:1);
    }
}
