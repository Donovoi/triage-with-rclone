/*
 * Source-only integrated feasibility candidate. Java 17, javac -proc:none.
 * Normal Hadoop 3.5.0 APIs; one role per JVM. No MiniDFS/test JARs or
 * colocated metrics/login workaround. HTTP/WebHDFS handlers remain present.
 * Primary API contracts: apache/hadoop rel/release-3.5.0 NameNode.java,
 * DataNode.java, UserGroupInformation.java, DFSUtil.java and SSLFactory.java.
 * The coordinator must bound/reap each JVM and independently inspect all
 * listeners. API shutdown returning is NOT process or listener absence.
 * Raw Hadoop/JDK output is private. This class publishes fixed fields only.
 */
import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KeyTab;
import javax.security.auth.login.LoginException;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.permission.FsPermission;
import org.apache.hadoop.hdfs.DistributedFileSystem;
import org.apache.hadoop.hdfs.HdfsConfiguration;
import org.apache.hadoop.hdfs.protocol.DatanodeInfo;
import org.apache.hadoop.hdfs.protocol.HdfsConstants;
import org.apache.hadoop.hdfs.server.datanode.DataNode;
import org.apache.hadoop.hdfs.server.namenode.NameNode;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.util.ExitUtil;
import org.apache.hadoop.util.VersionInfo;

public final class SecureHdfsRoles {
  private static final Path ROOT = Path.of("/work/secure");
  private static final LinkOption[] NOFOLLOW = {LinkOption.NOFOLLOW_LINKS};
  private static final Set<String> ROLES = Set.of("format", "nn", "dn", "seed", "verify");
  private static final long MTIME_MS = 1704067200000L;
  private static final int START_SECONDS = 60;
  private static final int ROLE_SECONDS = 240;
  private static final String REMOTE_ROOT = "/synthetic";
  private static Object rootIdentity;
  private static Object parentIdentity;
  private static final Set<String> ASSERTIONS = Set.of(
      "arguments_invalid", "environment_invalid", "material_invalid", "material_changed",
      "root_identity_changed", "secure_configuration_invalid", "configuration_changed",
      "ssl_resource_invalid", "webapp_resources_invalid", "keytab_login_invalid", "keytab_unreadable",
      "format_preexisting", "format_incomplete", "endpoint_mismatch", "extra_service",
      "datanode_not_ready", "startup_timeout", "shutdown_invalid", "shutdown_preexisting",
      "shutdown_timeout", "source_preexisting", "mkdir_failed", "source_scope",
      "source_inventory_bound", "source_duplicate", "source_inventory_changed",
      "source_metadata_changed", "source_bytes_changed", "missing_member_present",
      "report_invalid", "report_preexisting", "exit_requested", "halt_requested");
  private static final class RoleFailure extends IOException {
    final String code;
    RoleFailure(String code) { super("role_assertion"); this.code = ASSERTIONS.contains(code) ? code : "unclassified"; }
  }
  private static void require(boolean condition, String code) throws RoleFailure {
    if (!condition) throw new RoleFailure(code);
  }
  private static String kerberosReason(Throwable failure) {
    // Exact OpenJDK17 KrbException.getMessage contract, not a search through
    // arbitrary exception text: a known description/code must start the whole
    // message, optionally followed by " - " and nonempty detail. The detail is
    // inspected only for bounds/control characters and is never retained or
    // published. No sun.* imports, reflection, module exports or debug logs.
    // https://github.com/openjdk/jdk17u/blob/jdk-17.0.20.1%2B1/src/java.security.jgss/share/classes/sun/security/krb5/KrbException.java#L109
    String message;
    try { message = failure.getMessage(); } catch (Throwable ignored) { return "kerberos_failure"; }
    if (message == null || message.length() > 2048 || message.chars().anyMatch(Character::isISOControl)) return "kerberos_failure";
    Map<String, String> headers = Map.ofEntries(
        Map.entry("Client not found in Kerberos database (6)", "kerberos_client_unknown"),
        Map.entry("Server not found in Kerberos database (7)", "kerberos_server_unknown"),
        Map.entry("KDC policy rejects request (12)", "kerberos_policy_rejected"),
        Map.entry("KDC has no support for encryption type (14)", "kerberos_etype_unsupported"),
        Map.entry("Pre-authentication information was invalid (24)", "kerberos_preauth_failed"),
        Map.entry("Additional pre-authentication required (25)", "kerberos_preauth_required"),
        Map.entry("Integrity check on decrypted field failed (31)", "kerberos_integrity_failed"),
        Map.entry("Clock skew too great (37)", "kerberos_clock_skew"),
        Map.entry("Message stream modified (41)", "kerberos_message_modified"),
        Map.entry("Generic error (description in e-text) (60)", "kerberos_generic_error"),
        Map.entry("Identifier doesn't match expected value (906)", "kerberos_asn_identifier"));
    for (Map.Entry<String, String> entry : headers.entrySet()) {
      String header = entry.getKey();
      if (message.equals(header) || (message.startsWith(header + " - ") && message.length() > header.length() + 3)) return entry.getValue();
    }
    return "kerberos_failure";
  }
  private static String reason(Throwable failure) {
    String result = "unclassified", kerberos = null, network = null;
    int kerberosPriority = 0; boolean loginException = false;
    for (int depth = 0; failure != null && depth < 8; depth++) {
      if (failure instanceof RoleFailure own) return own.code;
      if (failure instanceof ExitUtil.ExitException) return "exit_requested";
      if (failure instanceof ExitUtil.HaltException) return "halt_requested";
      if (failure instanceof LoginException) loginException = true;
      if (failure instanceof SocketTimeoutException && network == null) network = "socket_timeout";
      if (failure instanceof ConnectException && network == null) network = "connection_failed";
      String className = failure.getClass().getName();
      if (className.equals("sun.security.krb5.KrbException") || className.equals("sun.security.krb5.Asn1Exception")) {
        String candidate = kerberosReason(failure);
        int priority = candidate.equals("kerberos_failure") ? 1 : className.equals("sun.security.krb5.KrbException") ? 3 : 2;
        // An outer, recognized Kerberos code outranks a nested ASN.1 parsing
        // fallback. A LoginException never hides its more specific cause.
        if (priority > kerberosPriority) { kerberos = candidate; kerberosPriority = priority; }
      }
      if (failure instanceof ClassNotFoundException || failure instanceof NoClassDefFoundError) result = "missing_class";
      else if (failure instanceof LinkageError) result = "linkage_failure";
      else if (failure instanceof OutOfMemoryError || failure instanceof StackOverflowError) result = "resource_failure";
      else if (failure instanceof FileNotFoundException) result = "file_missing";
      else if (failure instanceof SecurityException) result = "security_failure";
      else if (failure instanceof IllegalArgumentException) result = "invalid_config";
      else if (failure instanceof NullPointerException) result = "null_state";
      else if (failure instanceof IllegalStateException) result = "illegal_state";
      else if (failure instanceof IOException && result.equals("unclassified")) result = "io_failure";
      try { failure = failure.getCause(); } catch (Throwable ignored) { return "unclassified"; }
    }
    if (kerberosPriority >= 2) return kerberos;
    if (network != null) return network;
    if (kerberos != null) return kerberos;
    if (loginException) return "login_exception";
    return result;
  }
  private static void addError(List<String> errors, String code) {
    if (!errors.contains(code) && errors.size() < 16) errors.add(code);
  }
  private static void appendStartupOrigins(List<String> errors, Throwable failure) {
    // Context only, never a root-cause or acceptance assertion. Hadoop 3.5.0
    // wraps HTTP startup exceptions; Jetty 9.4.58 MultiException also retains
    // failures as suppressed exceptions. Inspect only this bounded graph and
    // exact tagged method pairs. No messages, paths, line numbers or raw frames
    // are copied to the receipt, and diagnostics cannot replace the failure.
    try {
      Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
      ArrayDeque<Throwable> pending = new ArrayDeque<>();
      Set<String> origins = new TreeSet<>();
      if (failure != null) { seen.add(failure); pending.add(failure); }
      while (!pending.isEmpty()) {
        Throwable current = pending.removeFirst();
        StackTraceElement[] frames = current.getStackTrace();
        for (int index = 0; index < Math.min(32, frames.length); index++) {
          StackTraceElement frame = frames[index];
          String method = frame.getMethodName();
          String origin = switch (frame.getClassName()) {
            case "org.apache.hadoop.http.HttpServer2$Builder" ->
                method.equals("loadSSLConfiguration") ? "origin_http_ssl_configuration" : null;
            case "org.apache.hadoop.http.HttpServer2" -> switch (method) {
              case "initSpnego" -> "origin_http_spnego";
              case "start" -> "origin_http_start";
              default -> null;
            };
            case "org.eclipse.jetty.util.ssl.SslContextFactory" ->
                method.equals("load") || method.equals("doStart") ? "origin_jetty_ssl_start" : null;
            case "org.apache.hadoop.security.authentication.server.KerberosAuthenticationHandler" ->
                method.equals("init") ? "origin_kerberos_auth_init" : null;
            case "org.apache.hadoop.hdfs.server.namenode.FSNamesystem" ->
                method.equals("loadFromDisk") ? "origin_namespace_load" : null;
            case "org.apache.hadoop.hdfs.server.namenode.NameNodeRpcServer" ->
                method.equals("<init>") ? "origin_rpc_constructor" : null;
            default -> null;
          };
          if (origin != null && origins.size() < 7) origins.add(origin);
        }
        Throwable cause = current.getCause();
        if (cause != null && seen.size() < 8 && seen.add(cause)) pending.addLast(cause);
        Throwable[] suppressed = current.getSuppressed();
        for (int index = 0; index < Math.min(8, suppressed.length) && seen.size() < 8; index++) {
          Throwable sibling = suppressed[index];
          if (sibling != null && seen.add(sibling)) pending.addLast(sibling);
        }
      }
      for (String origin : origins) addError(errors, origin);
    } catch (Throwable ignored) { /* Existing finite failure remains authoritative. */ }
  }
  private static String sha256(byte[] bytes) throws Exception {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
  }
  private static long unix(Path path, String field) throws IOException {
    return ((Number) Files.getAttribute(path, "unix:" + field, NOFOLLOW)).longValue();
  }
  private static BasicFileAttributes attrs(Path path) throws IOException {
    return Files.readAttributes(path, BasicFileAttributes.class, NOFOLLOW);
  }
  private static boolean same(BasicFileAttributes before, BasicFileAttributes after) {
    return before.fileKey() != null && before.fileKey().equals(after.fileKey())
        && before.size() == after.size() && before.lastModifiedTime().equals(after.lastModifiedTime())
        && before.isRegularFile() == after.isRegularFile() && before.isDirectory() == after.isDirectory();
  }
  private static void privatePath(Path path, boolean directory) throws Exception {
    require(path.isAbsolute() && path.normalize().equals(path) && path.startsWith(ROOT), "material_invalid");
    for (Path ancestor = path.getParent(); ancestor != null && ancestor.startsWith(ROOT); ancestor = ancestor.getParent()) {
      require(Files.isDirectory(ancestor, NOFOLLOW) && !Files.isSymbolicLink(ancestor)
          && unix(ancestor, "uid") == 10001 && unix(ancestor, "gid") == 10001
          && (unix(ancestor, "mode") & 07777) == 0700, "material_invalid");
    }
    require(!Files.isSymbolicLink(path) && unix(path, "uid") == 10001 && unix(path, "gid") == 10001
        && (unix(path, "mode") & 07777) == (directory ? 0700 : 0600)
        && (directory ? Files.isDirectory(path, NOFOLLOW) : Files.isRegularFile(path, NOFOLLOW) && unix(path, "nlink") == 1),
        "material_invalid");
  }
  private static void rootGuard() throws Exception {
    require(rootIdentity != null && parentIdentity != null && !Files.isSymbolicLink(ROOT.getParent())
        && Files.isDirectory(ROOT.getParent(), NOFOLLOW) && parentIdentity.equals(attrs(ROOT.getParent()).fileKey())
        && !Files.isSymbolicLink(ROOT) && Files.isDirectory(ROOT, NOFOLLOW)
        && rootIdentity.equals(attrs(ROOT).fileKey()), "root_identity_changed");
    privatePath(ROOT, true);
  }
  private static byte[] privateRead(Path path, int maximum) throws Exception {
    rootGuard(); privatePath(path, false);
    BasicFileAttributes before = attrs(path);
    require(before.size() <= maximum, "material_invalid");
    byte[] bytes;
    try (InputStream input = Files.newInputStream(path, NOFOLLOW)) { bytes = input.readNBytes(maximum + 1); }
    require(bytes.length == before.size() && bytes.length <= maximum && same(before, attrs(path)), "material_changed");
    privatePath(path, false); rootGuard();
    return bytes;
  }
  private static void environment() throws Exception {
    require(System.getProperty("os.name", "").equals("Linux") && Runtime.version().feature() == 17
        && VersionInfo.getVersion().equals("3.5.0")
        && System.getProperty("java.net.preferIPv4Stack", "").equals("true")
        && System.getProperty("java.security.krb5.conf", "").equals(ROOT.resolve("auth/krb5.conf").toString()),
        "environment_invalid");
    byte[] status;
    try (InputStream input = Files.newInputStream(Path.of("/proc/self/status"))) { status = input.readNBytes(32769); }
    require(status.length <= 32768, "environment_invalid");
    String text = new String(status, StandardCharsets.US_ASCII);
    require(Pattern.compile("(?m)^Uid:\\s+10001\\s+10001\\s+10001\\s+10001$").matcher(text).find()
        && Pattern.compile("(?m)^Gid:\\s+10001\\s+10001\\s+10001\\s+10001$").matcher(text).find(), "environment_invalid");
    for (Path path = ROOT; path != null; path = path.getParent())
      require(Files.isDirectory(path, NOFOLLOW) && !Files.isSymbolicLink(path), "environment_invalid");
    privatePath(ROOT, true);
    rootIdentity = attrs(ROOT).fileKey(); parentIdentity = attrs(ROOT.getParent()).fileKey(); rootGuard();
  }
  private static List<Element> elements(Element parent) throws Exception {
    List<Element> result = new ArrayList<>();
    for (Node node = parent.getFirstChild(); node != null; node = node.getNextSibling()) {
      if (node.getNodeType() == Node.TEXT_NODE && node.getTextContent().isBlank()) continue;
      require(node instanceof Element && !node.hasAttributes(), "ssl_resource_invalid");
      result.add((Element) node);
    }
    return result;
  }
  private static String leaf(Element element) throws Exception {
    require(!element.hasAttributes() && element.getChildNodes().getLength() == 1
        && element.getFirstChild().getNodeType() == Node.TEXT_NODE, "ssl_resource_invalid");
    return element.getTextContent();
  }
  private static void uniqueResource(String name, Path expected) throws Exception {
    Enumeration<URL> found = SecureHdfsRoles.class.getClassLoader().getResources(name);
    require(found.hasMoreElements(), "ssl_resource_invalid");
    URL url = found.nextElement();
    require(!found.hasMoreElements() && url.getProtocol().equals("file")
        && (url.getAuthority() == null || url.getAuthority().isEmpty())
        && url.getQuery() == null && url.getRef() == null && Path.of(url.toURI()).equals(expected), "ssl_resource_invalid");
  }
  private static void sslResource(String service, String password, byte[] xml) throws Exception {
    Path resource = ROOT.resolve(service + "/resources/ssl-server.xml");
    uniqueResource("ssl-server.xml", resource);
    try (var children = Files.newDirectoryStream(resource.getParent())) {
      int count = 0;
      for (Path child : children) { require(++count == 1 && child.equals(resource), "ssl_resource_invalid"); }
      require(count == 1, "ssl_resource_invalid");
    }
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
    factory.setXIncludeAware(false); factory.setExpandEntityReferences(false);
    var builder = factory.newDocumentBuilder();
    builder.setErrorHandler(new org.xml.sax.helpers.DefaultHandler() {
      @Override public void error(org.xml.sax.SAXParseException e) throws org.xml.sax.SAXException { throw e; }
      @Override public void fatalError(org.xml.sax.SAXParseException e) throws org.xml.sax.SAXException { throw e; }
    });
    Element document = builder.parse(new ByteArrayInputStream(xml)).getDocumentElement();
    require(document.getTagName().equals("configuration") && !document.hasAttributes(), "ssl_resource_invalid");
    Map<String, String> actual = new TreeMap<>();
    for (Element property : elements(document)) {
      require(property.getTagName().equals("property"), "ssl_resource_invalid");
      List<Element> fields = elements(property);
      require(fields.size() == 2 && fields.get(0).getTagName().equals("name")
          && fields.get(1).getTagName().equals("value"), "ssl_resource_invalid");
      require(actual.put(leaf(fields.get(0)), leaf(fields.get(1))) == null, "ssl_resource_invalid");
    }
    Map<String, String> expected = Map.of(
        "ssl.server.keystore.location", ROOT.resolve("tls/" + service + ".p12").toString(),
        "ssl.server.keystore.type", "PKCS12", "ssl.server.keystore.password", password,
        "ssl.server.keystore.keypassword", password, "ssl.server.truststore.location", ROOT.resolve("tls/trust.p12").toString(),
        "ssl.server.truststore.type", "PKCS12", "ssl.server.truststore.password", password);
    require(actual.equals(expected), "ssl_resource_invalid");
  }
  private record Material(String realm, Map<Path, String> hashes, Map<Path, Object> identities) {}
  private static Material material(String service) throws Exception {
    Map<Path, String> hashes = new TreeMap<>();
    Map<Path, byte[]> contents = new TreeMap<>(); Map<Path, Object> identities = new TreeMap<>();
    for (String relative : List.of("auth/realm", "auth/krb5.conf", "auth/nn.keytab", "auth/dn.keytab", "auth/http.keytab",
        "tls/nn.p12", "tls/dn.p12", "tls/trust.p12", "tls/store.pass", service + "/resources/ssl-server.xml")) {
      Path path = ROOT.resolve(relative); byte[] bytes = privateRead(path, 65536);
      require(bytes.length > 0, "material_invalid"); hashes.put(path, sha256(bytes)); contents.put(path, bytes);
      Object identity = attrs(path).fileKey(); require(identity != null, "material_invalid"); identities.put(path, identity);
    }
    String realm = new String(contents.get(ROOT.resolve("auth/realm")), StandardCharsets.US_ASCII);
    String password = new String(contents.get(ROOT.resolve("tls/store.pass")), StandardCharsets.US_ASCII);
    require(realm.matches("SYNTHETIC[0-9A-F]{24}\\.INVALID\\n") && password.matches("[0-9a-f]{64}\\n"), "material_invalid");
    byte[] xml = contents.get(ROOT.resolve(service + "/resources/ssl-server.xml"));
    require(xml.length <= 16384, "ssl_resource_invalid"); sslResource(service, password.substring(0, 64), xml);
    for (String name : List.of("nn/data", "nn/tmp", "nn/http", "dn/data", "dn/tmp", "dn/http")) privatePath(ROOT.resolve(name), true);
    Material result = new Material(realm.substring(0, realm.length() - 1), Collections.unmodifiableMap(hashes), Collections.unmodifiableMap(identities));
    unchanged(result); return result;
  }
  private static void keytabReadable(String service, String realm) throws Exception {
    // Local parsing only. This does not prove the KDC accepts the key, and must
    // never set keytab_login or any authentication/coverage claim.
    Path path = ROOT.resolve("auth/" + service + ".keytab");
    KerberosKey[] keys = null; boolean readable = false, destroyed = true;
    try {
      privatePath(path, false);
      String name = service + "/127.0.0.1@" + realm;
      KerberosPrincipal expected = new KerberosPrincipal(name);
      require(expected.getName().equals(name), "keytab_unreadable");
      KeyTab tab = KeyTab.getInstance(expected, path.toFile());
      keys = tab.getKeys(expected);
      require(keys != null && keys.length > 0 && keys.length <= 16, "keytab_unreadable");
      boolean aes128 = false;
      for (KerberosKey key : keys) {
        require(key != null && !key.isDestroyed() && expected.equals(key.getPrincipal()), "keytab_unreadable");
        if (key.getKeyType() == 17) {
          byte[] encoded = key.getEncoded();
          try { require(encoded != null && encoded.length == 16, "keytab_unreadable"); aes128 = true; }
          finally { if (encoded != null) Arrays.fill(encoded, (byte) 0); }
        }
      }
      privatePath(path, false); readable = aes128;
    } catch (Exception ignored) { readable = false; }
    finally {
      if (keys != null) for (KerberosKey key : keys) if (key != null) {
        try { key.destroy(); if (!key.isDestroyed()) destroyed = false; }
        catch (Exception ignored) { destroyed = false; }
      }
    }
    require(readable && destroyed, "keytab_unreadable");
  }
  private static void unchanged(Material material) throws Exception {
    for (Map.Entry<Path, String> entry : material.hashes().entrySet()) {
      require(material.identities().get(entry.getKey()).equals(attrs(entry.getKey()).fileKey()), "material_changed");
      require(sha256(privateRead(entry.getKey(), 65536)).equals(entry.getValue())
          && material.identities().get(entry.getKey()).equals(attrs(entry.getKey()).fileKey()), "material_changed");
    }
  }
  private record WebAppFile(int size, String sha256) {}
  private static void verifyWebAppResources() throws Exception {
    // Fixture-only scaffolding, not vendor UI. The parent binds these immutable
    // image files to its reviewed build context; hashes here are independent.
    Path root = Path.of("/opt/secure/classes/webapps");
    Map<String, WebAppFile> files = Map.of(
        "hdfs/WEB-INF/web.xml", new WebAppFile(113, "6d0d825985f36b71b961bcf21a33c0f21d5b732bd571962549585287071c48a9"),
        "datanode/WEB-INF/web.xml", new WebAppFile(113, "6d0d825985f36b71b961bcf21a33c0f21d5b732bd571962549585287071c48a9"),
        "hdfs/index.html", new WebAppFile(74, "c91ab4f8efeb470f733249fa2077f6cdfa2a0b185092bb6cd7ef94a6f1500c5e"),
        "datanode/index.html", new WebAppFile(74, "c91ab4f8efeb470f733249fa2077f6cdfa2a0b185092bb6cd7ef94a6f1500c5e"),
        "static/fixture.txt", new WebAppFile(30, "a934e6055b850ef89bab9e02e895da2d13ad073d49e8054a59a5bdee4d7b04af"));
    Set<String> directories = Set.of("", "hdfs", "hdfs/WEB-INF", "datanode", "datanode/WEB-INF", "static");
    try {
      for (Path ancestor = root; ancestor != null; ancestor = ancestor.getParent())
        require(Files.isDirectory(ancestor, NOFOLLOW) && !Files.isSymbolicLink(ancestor),
            "webapp_resources_invalid");
      for (String name : List.of("hdfs", "datanode", "static")) {
        URL resource = SecureHdfsRoles.class.getClassLoader().getResource("webapps/" + name);
        require(resource != null && resource.getProtocol().equals("file")
            && (resource.getAuthority() == null || resource.getAuthority().isEmpty())
            && resource.getQuery() == null && resource.getRef() == null
            && Path.of(resource.toURI()).equals(root.resolve(name)), "webapp_resources_invalid");
      }
      Set<String> foundFiles = new HashSet<>(), foundDirs = new HashSet<>();
      ArrayDeque<Path> pending = new ArrayDeque<>(); pending.add(root);
      int observed = 0;
      while (!pending.isEmpty()) {
        Path path = pending.remove();
        require(++observed <= 11 && !Files.isSymbolicLink(path), "webapp_resources_invalid");
        String relative = root.relativize(path).toString();
        boolean directory = Files.isDirectory(path, NOFOLLOW);
        require(((Number) Files.getAttribute(path, "unix:uid", NOFOLLOW)).intValue() == 0
            && ((Number) Files.getAttribute(path, "unix:gid", NOFOLLOW)).intValue() == 0
            && Files.getPosixFilePermissions(path, NOFOLLOW).equals(PosixFilePermissions.fromString(
                directory ? "r-xr-xr-x" : "r--r--r--")), "webapp_resources_invalid");
        if (directory) {
          require(directories.contains(relative) && foundDirs.add(relative), "webapp_resources_invalid");
          try (var children = Files.newDirectoryStream(path)) {
            for (Path child : children) {
              require(pending.size() < 11, "webapp_resources_invalid");
              pending.add(child);
            }
          }
        } else {
          require(Files.isRegularFile(path, NOFOLLOW) && files.containsKey(relative)
              && foundFiles.add(relative), "webapp_resources_invalid");
          WebAppFile expected = files.get(relative);
          require(expected.size() <= 4096 && Files.size(path) == expected.size(), "webapp_resources_invalid");
          byte[] bytes;
          try (InputStream input = Files.newInputStream(path, NOFOLLOW)) { bytes = input.readNBytes(4097); }
          require(bytes.length == expected.size() && sha256(bytes).equals(expected.sha256()),
              "webapp_resources_invalid");
        }
      }
      require(foundFiles.equals(files.keySet()) && foundDirs.equals(directories), "webapp_resources_invalid");
    } catch (Exception ignored) {
      throw new RoleFailure("webapp_resources_invalid");
    }
  }

  private static Map<String, String> settings(String service, String realm) {
    Map<String, String> value = new TreeMap<>();
    value.put("fs.defaultFS", "hdfs://127.0.0.1:19000");
    value.put("fs.hdfs.impl", "org.apache.hadoop.hdfs.DistributedFileSystem");
    value.put("dfs.namenode.rpc-address", "127.0.0.1:19000");
    value.put("dfs.namenode.rpc-bind-host", "127.0.0.1");
    value.put("dfs.datanode.address", "127.0.0.1:19001");
    value.put("dfs.datanode.ipc.address", "127.0.0.1:19002");
    value.put("dfs.namenode.https-address", "127.0.0.1:19003");
    value.put("dfs.namenode.https-bind-host", "127.0.0.1");
    value.put("dfs.namenode.http-address", "127.0.0.1:19003");
    value.put("dfs.namenode.http-bind-host", "127.0.0.1");
    value.put("dfs.datanode.https.address", "127.0.0.1:19004");
    value.put("dfs.datanode.http.address", "127.0.0.1:19004");
    value.put("dfs.datanode.http.internal-proxy.port", "19005");
    value.put("dfs.datanode.hostname", "127.0.0.1");
    value.put("dfs.client.use.datanode.hostname", "false");
    value.put("dfs.datanode.use.datanode.hostname", "false");
    value.put("dfs.http.policy", "HTTPS_ONLY");
    value.put("hadoop.security.authentication", "kerberos");
    // Defaults are disabled; secure HttpServer2 requires an explicit authentication type.
    value.put("hadoop.http.authentication.type", "kerberos");
    value.put("hadoop.security.authorization", "false");
    value.put("hadoop.rpc.protection", "authentication");
    value.put("ipc.client.fallback-to-simple-auth-allowed", "false");
    value.put("dfs.block.access.token.enable", "true");
    value.put("dfs.data.transfer.protection", "privacy");
    value.put("dfs.trustedchannel.resolver.class", "org.apache.hadoop.hdfs.protocol.datatransfer.TrustedChannelResolver");
    value.put("ignore.secure.ports.for.testing", "false");
    value.put("dfs.namenode.kerberos.principal", "nn/127.0.0.1@" + realm);
    value.put("dfs.namenode.keytab.file", ROOT.resolve("auth/nn.keytab").toString());
    value.put("dfs.datanode.kerberos.principal", "dn/127.0.0.1@" + realm);
    value.put("dfs.datanode.keytab.file", ROOT.resolve("auth/dn.keytab").toString());
    value.put("dfs.namenode.kerberos.internal.spnego.principal", "HTTP/127.0.0.1@" + realm);
    value.put("dfs.web.authentication.kerberos.principal", "HTTP/127.0.0.1@" + realm);
    value.put("dfs.web.authentication.kerberos.keytab", ROOT.resolve("auth/http.keytab").toString());
    StringBuilder rules = new StringBuilder();
    for (String role : List.of("nn", "dn", "HTTP"))
      rules.append("RULE:[2:$1/$2@$0](").append(Pattern.quote(role + "/127.0.0.1@" + realm)).append(")s/.*/").append(role).append("/ ");
    rules.append("RULE:[1:$1@$0](").append(Pattern.quote("reader@" + realm)).append(")s/.*/reader/");
    value.put("hadoop.security.auth_to_local", rules.toString());
    value.put("hadoop.security.auth_to_local.mechanism", "hadoop");
    value.put("hadoop.user.group.static.mapping.overrides", "nn=fixture-services;dn=fixture-services;HTTP=fixture-http;reader=fixture-readers");
    value.put("dfs.permissions.superusergroup", "fixture-supergroup");
    value.put("dfs.permissions.enabled", "true");
    value.put("dfs.reformat.disabled", "true");
    value.put("dfs.replication", "1");
    value.put("dfs.namenode.safemode.min.datanodes", "1");
    value.put("dfs.namenode.safemode.extension", "0");
    value.put("dfs.namenode.accesstime.precision", "0");
    value.put("dfs.client.read.shortcircuit", "false");
    value.put("dfs.domain.socket.path", "");
    value.put("dfs.datanode.max.locked.memory", "0");
    value.put("dfs.blocksize", "1048576");
    value.put("dfs.client.socket-timeout", "10000");
    value.put("ipc.client.connect.timeout", "5000");
    value.put("ipc.client.connect.max.retries", "0");
    value.put("ipc.client.connect.max.retries.on.timeouts", "0");
    value.put("ipc.client.rpc-timeout.ms", "10000");
    value.put("dfs.namenode.name.dir", ROOT.resolve("nn/data").toUri().toString());
    value.put("dfs.namenode.edits.dir", ROOT.resolve("nn/data").toUri().toString());
    value.put("dfs.datanode.data.dir", ROOT.resolve("dn/data").toUri().toString());
    value.put("hadoop.tmp.dir", ROOT.resolve(service + "/tmp").toString());
    value.put("hadoop.http.temp.dir", ROOT.resolve(service + "/http").toString());
    value.put("dfs.https.server.keystore.resource", "ssl-server.xml");
    value.put("hadoop.ssl.server.conf", "ssl-server.xml");
    value.put("hadoop.ssl.hostname.verifier", "DEFAULT");
    value.put("hadoop.ssl.require.client.cert", "false");
    return value;
  }
  private static Configuration configuration(Map<String, String> values) {
    Configuration conf = new HdfsConfiguration(false);
    for (Map.Entry<String, String> entry : values.entrySet()) conf.set(entry.getKey(), entry.getValue());
    return conf;
  }
  private static String configurationHash(Configuration conf, Map<String, String> values, Material material) throws Exception {
    // Bound contract is every explicit setting and every immutable input. No
    // claim that Hadoop's internal, dynamically added configuration is static.
    StringBuilder text = new StringBuilder();
    for (Map.Entry<String, String> entry : values.entrySet()) {
      require(entry.getValue().equals(conf.get(entry.getKey())), "configuration_changed");
      text.append(entry.getKey().length()).append(':').append(entry.getKey())
          .append(entry.getValue().length()).append(':').append(entry.getValue());
    }
    for (Map.Entry<Path, String> entry : material.hashes().entrySet())
      text.append(ROOT.relativize(entry.getKey())).append(':').append(entry.getValue()).append('\n');
    return sha256(text.toString().getBytes(StandardCharsets.UTF_8));
  }
  private static UserGroupInformation loginProof(String service, String realm) throws Exception {
    UserGroupInformation user = UserGroupInformation.getLoginUser();
    require(UserGroupInformation.isSecurityEnabled() && user.hasKerberosCredentials() && user.isFromKeytab()
        && user.getAuthenticationMethod() == UserGroupInformation.AuthenticationMethod.KERBEROS
        && user.getUserName().equals(service + "/127.0.0.1@" + realm)
        && user.getShortUserName().equals(service), "keytab_login_invalid");
    return user;
  }
  private static void exitRequests() throws Exception {
    require(!ExitUtil.terminateCalled(), "exit_requested"); require(!ExitUtil.haltCalled(), "halt_requested");
  }
  private static void address(InetSocketAddress actual, int port) throws Exception {
    require(actual != null && actual.getAddress() != null && actual.getAddress().getHostAddress().equals("127.0.0.1")
        && actual.getPort() == port, "endpoint_mismatch");
  }
  private static void nnAddresses(NameNode nn) throws Exception {
    address(nn.getNameNodeAddress(), 19000); address(nn.getHttpsAddress(), 19003);
    require(nn.getHttpAddress() == null && nn.getAuxiliaryNameNodeAddresses().isEmpty(), "extra_service");
  }
  private static void dnAddresses(DataNode dn) throws Exception {
    address(dn.getXferAddress(), 19001);
    require(dn.getIpcPort() == 19002 && dn.getInfoSecurePort() == 19004, "endpoint_mismatch");
    // The coordinator separately checks every actual listening socket,
    // including internal Jetty's localhost:19005 and absence of cleartext
    // external HTTP. getInfoPort() retains a configured default under HTTPS_ONLY.
  }
  private static void clientTopology(DistributedFileSystem fs) throws Exception {
    DatanodeInfo[] nodes = fs.getDataNodeStats(HdfsConstants.DatanodeReportType.ALL);
    require(nodes.length == 1 && nodes[0].getCapacity() > 0 && nodes[0].getRemaining() > 0, "datanode_not_ready");
    DatanodeInfo node = nodes[0];
    require(node.getIpAddr().equals("127.0.0.1") && node.getHostName().equals("127.0.0.1")
        && node.getXferPort() == 19001 && node.getIpcPort() == 19002 && node.getInfoSecurePort() == 19004, "endpoint_mismatch");
  }
  private static void clientReady(DistributedFileSystem fs) throws Exception {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(START_SECONDS);
    while (true) {
      exitRequests();
      DatanodeInfo[] live = fs.getDataNodeStats(HdfsConstants.DatanodeReportType.LIVE);
      if (live.length == 1 && live[0].getCapacity() > 0 && !fs.setSafeMode(HdfsConstants.SafeModeAction.SAFEMODE_GET)) break;
      require(System.nanoTime() < deadline, "startup_timeout"); Thread.sleep(100);
    }
    clientTopology(fs);
  }
  private static Map<String, byte[]> samples() {
    Map<String, byte[]> files = new TreeMap<>();
    files.put("README.txt", HexFormat.of().parseHex("484446532073796e74686574696320666978747572650a"));
    files.put("empty.bin", new byte[0]); files.put("nested/alpha.txt", HexFormat.of().parseHex("616c7068610a"));
    files.put("nested/space name.txt", HexFormat.of().parseHex("7370616365206e616d650a"));
    byte[] binary = new byte[256]; for (int i = 0; i < binary.length; i++) binary[i] = (byte) i;
    files.put("nested/deeper/data.bin", binary); files.put("unicode/utf8.txt", HexFormat.of().parseHex("636166c3a90a"));
    files.put("private/owner-only.txt", HexFormat.of().parseHex("707269766174652073796e7468657469632062797465730a"));
    byte[] large = new byte[2 * 1024 * 1024]; for (int i = 0; i < large.length; i++) large[i] = (byte) i;
    files.put("large/cancel.bin", large); return files;
  }
  private static short mode(String path) { return (short) (path.equals("private/owner-only.txt") ? 0600 : 0644); }
  private static org.apache.hadoop.fs.Path remote(String relative) {
    return new org.apache.hadoop.fs.Path(REMOTE_ROOT + (relative.isEmpty() ? "" : "/" + relative));
  }
  private static Set<String> directories(Map<String, byte[]> files) {
    Set<String> result = new TreeSet<>(); result.add("");
    for (String file : files.keySet()) {
      int slash = file.lastIndexOf('/');
      while (slash >= 0) { result.add(file.substring(0, slash)); slash = file.lastIndexOf('/', slash - 1); }
    }
    return result;
  }
  private static void seed(DistributedFileSystem fs, Map<String, byte[]> files) throws Exception {
    require(!fs.exists(remote("")), "source_preexisting");
    for (String dir : directories(files)) {
      require(fs.mkdirs(remote(dir), new FsPermission((short) 0755)), "mkdir_failed");
      fs.setPermission(remote(dir), new FsPermission((short) 0755));
    }
    for (Map.Entry<String, byte[]> entry : files.entrySet()) {
      try (FSDataOutputStream out = fs.create(remote(entry.getKey()), false)) { out.write(entry.getValue()); }
      fs.setPermission(remote(entry.getKey()), new FsPermission(mode(entry.getKey())));
      fs.setOwner(remote(entry.getKey()), "reader", "fixture-readers");
      fs.setTimes(remote(entry.getKey()), MTIME_MS, MTIME_MS);
    }
    for (String dir : directories(files)) {
      fs.setOwner(remote(dir), "reader", "fixture-readers"); fs.setTimes(remote(dir), MTIME_MS, MTIME_MS);
    }
  }
  private static void verifySource(DistributedFileSystem fs, Map<String, byte[]> files) throws Exception {
    Set<String> dirs = directories(files), foundDirs = new TreeSet<>(), foundFiles = new TreeSet<>();
    ArrayDeque<String> pending = new ArrayDeque<>(); pending.add(""); int observed = 0;
    while (!pending.isEmpty()) {
      String relativeDir = pending.remove(); FileStatus directory = fs.getFileStatus(remote(relativeDir));
      require(directory.isDirectory() && !directory.isSymlink() && directory.getPermission().toShort() == 0755
          && directory.getOwner().equals("reader") && directory.getGroup().equals("fixture-readers")
          && directory.getModificationTime() == MTIME_MS, "source_metadata_changed");
      require(foundDirs.add(relativeDir), "source_duplicate");
      FileStatus[] children = fs.listStatus(remote(relativeDir)); require(children.length <= 16, "source_inventory_bound");
      for (FileStatus child : children) {
        require(++observed <= 32 && !child.isSymlink(), "source_inventory_bound");
        URI uri = child.getPath().toUri(); String full = uri.getPath();
        require("hdfs".equals(uri.getScheme()) && "127.0.0.1:19000".equals(uri.getAuthority())
            && full.startsWith(REMOTE_ROOT + "/"), "source_scope");
        String relative = full.substring(REMOTE_ROOT.length() + 1);
        if (child.isDirectory()) { require(dirs.contains(relative), "source_inventory_changed"); pending.add(relative); }
        else {
          require(child.isFile() && files.containsKey(relative) && foundFiles.add(relative), "source_inventory_changed");
          byte[] expected = files.get(relative);
          require(child.getLen() == expected.length && child.getOwner().equals("reader") && child.getGroup().equals("fixture-readers")
              && child.getPermission().toShort() == mode(relative) && child.getModificationTime() == MTIME_MS
              && child.getAccessTime() == MTIME_MS && child.getReplication() == 1, "source_metadata_changed");
          byte[] actual; try (InputStream input = fs.open(remote(relative))) { actual = input.readNBytes(expected.length + 1); }
          require(Arrays.equals(actual, expected) && sha256(actual).equals(sha256(expected)), "source_bytes_changed");
        }
      }
    }
    require(foundFiles.equals(files.keySet()) && foundDirs.equals(dirs), "source_inventory_changed");
    require(!fs.exists(remote("missing-synthetic.bin")), "missing_member_present");
  }
  private static String quoted(String value) {
    // Called only on static labels, fixed sample paths or a SHA256, never raw input.
    return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
  }
  private static String manifest(Map<String, byte[]> files) throws Exception {
    List<String> rows = new ArrayList<>();
    for (Map.Entry<String, byte[]> entry : files.entrySet()) rows.add("{\"path\":" + quoted(entry.getKey())
        + ",\"size\":" + entry.getValue().length + ",\"sha256\":" + quoted(sha256(entry.getValue()))
        + ",\"mode\":" + quoted(mode(entry.getKey()) == 0600 ? "0600" : "0644") + ",\"mtime_ms\":" + MTIME_MS + "}");
    return "[" + String.join(",", rows) + "]";
  }
  private static Map<String, Boolean> checks(String role) {
    Map<String, Boolean> result = new LinkedHashMap<>();
    for (String key : List.of("environment", "material_paths", "secure_configuration", "keytab_login", "configuration_preserved")) result.put(key, false);
    if (role.equals("format")) result.put("fresh_format", false); else result.put("bound_service_addresses", false);
    if (role.equals("seed") || role.equals("verify")) result.put("source_preserved", false);
    return result;
  }
  private static String report(String role, String phase, Map<String, Boolean> checks, String configHash,
      String files, boolean closed, List<String> errors) {
    boolean success = !checks.containsValue(false) && errors.isEmpty() && (phase.equals("ready") || closed);
    List<String> fields = new ArrayList<>(), codes = new ArrayList<>();
    for (Map.Entry<String, Boolean> check : checks.entrySet()) fields.add(quoted(check.getKey()) + ":" + check.getValue());
    for (String error : errors) codes.add(quoted(error));
    return "{\"schema_version\":1,\"scope\":\"secure_hdfs_role_feasibility\",\"role\":" + quoted(role)
        + ",\"phase\":" + quoted(phase) + ",\"success\":" + success + ",\"checks\":{" + String.join(",", fields)
        + "},\"configuration_sha256\":" + (configHash == null ? "null" : quoted(configHash)) + ",\"files\":" + files
        + ",\"api_shutdown_complete\":" + closed + ",\"errors\":[" + String.join(",", codes) + "]"
        + ",\"ledger_eligible\":false,\"authentication_verified\":false,\"hdfs_authenticated\":false,\"renewal_verified\":false"
        + ",\"daemon_accepted\":false,\"provider_accepted\":false,\"application_accepted\":false,\"vendor_accepted\":false"
        + ",\"vulnerability_audited\":false,\"publisher_audit_completed\":false}\n";
  }
  private static void publish(String role, String phase, String report) throws Exception {
    rootGuard(); require(ROLES.contains(role) && Set.of("ready", "final").contains(phase), "report_invalid");
    byte[] bytes = report.getBytes(StandardCharsets.UTF_8); require(bytes.length <= 16384, "report_invalid");
    Path target = ROOT.resolve(role + "-" + phase + ".json"), pending = ROOT.resolve(role + "-" + phase + ".pending");
    require(!Files.exists(target, NOFOLLOW) && !Files.exists(pending, NOFOLLOW), "report_preexisting");
    try (FileChannel channel = FileChannel.open(pending, Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) {
      ByteBuffer buffer = ByteBuffer.wrap(bytes); while (buffer.hasRemaining()) channel.write(buffer); channel.force(true);
    }
    privatePath(pending, false); rootGuard();
    // Same-filesystem Linux rename publishes a fully closed file. No REPLACE,
    // and no ATOMIC_MOVE option whose specified target-exists behavior varies.
    Files.move(pending, target);
  }
  private static void waitForStop(String service, long deadline) throws Exception {
    Path stop = ROOT.resolve("stop-" + service);
    while (true) {
      rootGuard(); exitRequests();
      if (Files.exists(stop, NOFOLLOW)) { require(privateRead(stop, 0).length == 0, "shutdown_invalid"); return; }
      require(System.nanoTime() < deadline, "shutdown_timeout"); Thread.sleep(100);
    }
  }
  private static void emptyDirectory(Path path) throws Exception {
    privatePath(path, true);
    try (var children = Files.newDirectoryStream(path)) { require(!children.iterator().hasNext(), "format_preexisting"); }
  }

  public static void main(String[] args) {
    // Invalid CLI has no output-path authority. The parent treats absent report as failure.
    if (args.length != 1 || !ROLES.contains(args[0])) return;
    String role = args[0], service = role.equals("dn") ? "dn" : "nn";
    Map<String, Boolean> checks = checks(role); List<String> errors = new ArrayList<>();
    NameNode nn = null; DataNode dn = null; DistributedFileSystem fs = null;
    Configuration conf = null; Map<String, String> values = null; Material material = null;
    UserGroupInformation login = null; String configHash = null, files = "null", stage = "environment_failed";
    boolean closed = true, constructorPending = false;
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(ROLE_SECONDS);
    try {
      environment(); checks.put("environment", true);
      stage = "material_failed"; material = material(service); checks.put("material_paths", true);
      require(!Files.exists(ROOT.resolve("stop-" + service), NOFOLLOW), "shutdown_preexisting");
      stage = "configuration_failed"; values = settings(service, material.realm()); conf = configuration(values);
      UserGroupInformation.setConfiguration(conf); require(UserGroupInformation.isSecurityEnabled(), "secure_configuration_invalid");
      configHash = configurationHash(conf, values, material); checks.put("secure_configuration", true);
      ExitUtil.disableSystemExit(); ExitUtil.disableSystemHalt();
      stage = "login_failed"; keytabReadable(service, material.realm()); unchanged(material);
      if (role.equals("format") || role.equals("seed") || role.equals("verify")) {
        stage = "login_failed";
        UserGroupInformation.loginUserFromKeytab("nn/127.0.0.1@" + material.realm(), ROOT.resolve("auth/nn.keytab").toString());
        login = loginProof("nn", material.realm()); checks.put("keytab_login", true);
      }
      if (role.equals("format")) {
        stage = "format_failed"; emptyDirectory(ROOT.resolve("nn/data")); NameNode.format(conf);
        require(Files.isRegularFile(ROOT.resolve("nn/data/current/VERSION"), NOFOLLOW), "format_incomplete");
        login = loginProof("nn", material.realm()); checks.put("fresh_format", true);
      } else if (role.equals("nn")) {
        stage = "webapp_resources_failed"; verifyWebAppResources();
        stage = "namenode_start_failed"; constructorPending = true; nn = new NameNode(conf); constructorPending = false;
        login = loginProof("nn", material.realm());
        checks.put("keytab_login", true); nnAddresses(nn); checks.put("bound_service_addresses", true);
      } else if (role.equals("dn")) {
        stage = "webapp_resources_failed"; verifyWebAppResources();
        stage = "datanode_start_failed"; constructorPending = true; dn = DataNode.createDataNode(new String[0], conf);
        require(dn != null, "datanode_not_ready"); login = loginProof("dn", material.realm()); checks.put("keytab_login", true);
        constructorPending = false;
        long start = System.nanoTime() + TimeUnit.SECONDS.toNanos(START_SECONDS);
        while (!dn.isDatanodeFullyStarted()) { exitRequests(); require(System.nanoTime() < start, "startup_timeout"); Thread.sleep(100); }
        dnAddresses(dn); checks.put("bound_service_addresses", true);
      } else {
        stage = "client_start_failed";
        constructorPending = true;
        FileSystem client = FileSystem.newInstance(URI.create("hdfs://127.0.0.1:19000"), conf);
        if (!(client instanceof DistributedFileSystem)) { client.close(); throw new RoleFailure("secure_configuration_invalid"); }
        fs = (DistributedFileSystem) client; constructorPending = false;
        clientReady(fs); checks.put("bound_service_addresses", true);
        Map<String, byte[]> expected = samples(); stage = "source_failed";
        if (role.equals("seed")) seed(fs, expected);
        verifySource(fs, expected); checks.put("source_preserved", true); files = manifest(expected);
      }
      stage = "preservation_failed"; unchanged(material);
      require(configHash.equals(configurationHash(conf, values, material)), "configuration_changed");
      checks.put("configuration_preserved", true); exitRequests();
      if (role.equals("nn") || role.equals("dn")) {
        stage = "report_failed"; publish(role, "ready", report(role, "ready", checks, configHash, files, false, errors));
        stage = "stop_failed"; waitForStop(service, deadline);
        stage = "preservation_failed"; checks.put("configuration_preserved", false); unchanged(material);
        require(configHash.equals(configurationHash(conf, values, material)), "configuration_changed");
        if (nn != null) nnAddresses(nn); if (dn != null) dnAddresses(dn);
        login = loginProof(service, material.realm()); checks.put("configuration_preserved", true);
      }
    } catch (Throwable failure) { addError(errors, stage); addError(errors, reason(failure)); appendStartupOrigins(errors, failure); }
    finally {
      if (constructorPending) { closed = false; addError(errors, "constructor_cleanup_unconfirmed"); }
      if (fs != null) try { fs.close(); } catch (Throwable failure) { closed = false; addError(errors, "client_close_failed"); addError(errors, reason(failure)); }
      if (dn != null) try { dn.shutdown(); } catch (Throwable failure) { closed = false; addError(errors, "datanode_close_failed"); addError(errors, reason(failure)); }
      if (nn != null) try { nn.stop(); nn.join(); } catch (Throwable failure) { closed = false; addError(errors, "namenode_close_failed"); addError(errors, reason(failure)); }
      // Only an observed login has a cleanup API handle. An unreturned
      // constructor is explicitly unconfirmed and must be reaped by parent.
      if (login != null) try {
        login.logoutUserFromKeytab();
      } catch (Throwable failure) { closed = false; addError(errors, "login_close_failed"); addError(errors, reason(failure)); }
      try {
        exitRequests();
        if (material != null && conf != null && configHash != null) {
          unchanged(material); require(configHash.equals(configurationHash(conf, values, material)), "configuration_changed");
        }
      } catch (Throwable failure) { checks.put("configuration_preserved", false); addError(errors, "preservation_failed"); addError(errors, reason(failure)); }
      try { publish(role, "final", report(role, "final", checks, configHash, files, closed, errors)); }
      catch (Throwable ignored) { /* No raw fallback output; missing final is failure. */ }
    }
    // Do not call System.exit: a returning API must not hide live owned threads.
    // Parent requires successful final, normal process exit and listener absence.
  }
}
