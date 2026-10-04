/*
 * Isolated, synthetic SIMPLE fixture. Java 17; compile with javac -proc:none.
 * Normal Hadoop 3.5.0 JAR APIs only. No MiniDFSCluster or test JARs.
 * Source contract: apache/hadoop dbcc7cd797100e6b32cd84f85b53a5193a5f9af0:
 * hadoop-hdfs/.../server/namenode/NameNode.java (format/new/stop),
 * hadoop-hdfs/.../server/datanode/DataNode.java (createDataNode/shutdown),
 * hadoop-hdfs/.../server/datanode/web/DatanodeHttpServer.java (internal HTTP),
 * hadoop-hdfs-client/.../hdfs/DistributedFileSystem.java (normal client API).
 * HTTP/WebHDFS services ARE present, confined to loopback and network-none.
 * SIMPLE asserts a user name; permission denial is not authentication proof.
 * The parent must enforce a 240s JVM deadline, reap it and verify listener
 * absence. Hadoop shutdown APIs can block and Netty shutdown is asynchronous.
 */
import java.io.InputStream;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.permission.FsPermission;
import org.apache.hadoop.hdfs.DistributedFileSystem;
import org.apache.hadoop.hdfs.HdfsConfiguration;
import org.apache.hadoop.hdfs.protocol.DatanodeInfo;
import org.apache.hadoop.hdfs.protocol.HdfsConstants;
import org.apache.hadoop.hdfs.server.datanode.DataNode;
import org.apache.hadoop.hdfs.server.namenode.NameNode;
import org.apache.hadoop.metrics2.MetricsException;
import org.apache.hadoop.metrics2.lib.DefaultMetricsSystem;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.util.ExitUtil;
import org.apache.hadoop.util.VersionInfo;

public final class HdfsFixture {
  private static final Path WORK = Path.of("/work");
  private static final Path STATE = WORK.resolve("state");
  private static final Path OUTPUT = WORK.resolve("output");
  private static final Path SHUTDOWN = WORK.resolve("shutdown");
  private static final String OWNER = "fixture-owner";
  private static final String ROOT = "/synthetic";
  private static final long MTIME_MS = 1704067200000L;
  private static final int STARTUP_SECONDS = 90;
  private static final int LIFETIME_SECONDS = 220;
  private static final int MAX_REPORT_BYTES = 16384;
  private static final Set<Integer> PORTS = Set.of(19000, 19001, 19002, 19003, 19004, 19005);
  private static final LinkOption[] NOFOLLOW = {LinkOption.NOFOLLOW_LINKS};
  private static Object outputIdentity;
  // Only our typed assertions can supply these codes. Never parse messages
  // from Hadoop/JDK exceptions, even when they resemble a known assertion.
  private static final Set<String> REQUIRE_CODES = Set.of(
      "advertised_endpoint_mismatch", "arguments_invalid", "configuration_changed",
      "datanode_missing", "datanode_not_ready", "directory_changed", "endpoint_mismatch",
      "environment_invalid", "extra_service", "hadoop_version_invalid", "ipv4_required",
      "java_version_invalid", "listener_duplicate", "listener_inventory_bound",
      "listener_inventory_invalid", "listener_not_loopback", "listener_set_mismatch",
      "missing_member_present", "mkdir_failed", "output_identity_changed",
      "output_identity_unavailable", "report_bound", "shutdown_invalid", "shutdown_preexisting",
      "shutdown_timeout", "simple_required", "source_bytes_changed", "source_duplicate",
      "source_inventory_bound", "source_inventory_changed", "source_metadata_changed",
      "source_preexisting", "source_scope", "startup_timeout", "unexpected_directory",
      "unexpected_file", "work_invalid", "work_owner_invalid", "work_permissions_invalid",
      "exit_requested", "halt_requested", "webapp_resources_invalid");
  private static final class FixtureFailure extends IOException {
    private final String code;
    FixtureFailure(String code) {
      super("fixture_assertion");
      this.code = REQUIRE_CODES.contains(code) ? code : "unclassified";
    }
  }

  private static boolean missingWebAppResource(FileNotFoundException failure) {
    // Pinned HttpServer2.getWebAppsPath throws this subtype for unavailable
    // webapp resources. Inspect only this exact marker; never expose a frame.
    try {
      StackTraceElement[] frames = failure.getStackTrace();
      for (int i = 0; i < frames.length && i < 32; i++) {
        if (frames[i].getClassName().equals("org.apache.hadoop.http.HttpServer2")
            && frames[i].getMethodName().equals("getWebAppsPath")) return true;
      }
    } catch (Throwable ignored) { return false; }
    return false;
  }
  private static String failureReason(Throwable failure) {
    String selected = "unclassified";
    int selectedRank = 11;
    Throwable current = failure;
    // A cycle or unexpectedly deep chain cannot make inspection unbounded.
    for (int depth = 0; current != null && depth < 8; depth++) {
      if (current instanceof FixtureFailure own && REQUIRE_CODES.contains(own.code)) return own.code;
      if (current instanceof ExitUtil.ExitException) return "exit_requested";
      if (current instanceof ExitUtil.HaltException) return "halt_requested";
      String category = "unclassified";
      int rank = 11;
      if (current instanceof ClassNotFoundException || current instanceof NoClassDefFoundError) {
        category = "missing_class"; rank = 0;
      } else if (current instanceof OutOfMemoryError || current instanceof StackOverflowError) {
        category = "resource_failure"; rank = 1;
      } else if (current instanceof IllegalArgumentException) {
        category = "invalid_config"; rank = 2;
      } else if (current instanceof LinkageError) {
        category = "linkage_failure"; rank = 3;
      } else if (current instanceof MetricsException) {
        category = "metrics_failure"; rank = 4;
      } else if (current instanceof NullPointerException) {
        category = "null_state"; rank = 5;
      } else if (current instanceof IllegalStateException) {
        category = "illegal_state"; rank = 6;
      } else if (current instanceof UnsupportedOperationException) {
        category = "unsupported_operation"; rank = 7;
      } else if (current instanceof SecurityException) {
        category = "security_failure"; rank = 8;
      } else if (current instanceof FileNotFoundException) {
        category = "file_missing"; rank = 9;
        if (missingWebAppResource((FileNotFoundException) current)) category = "http_webapp_missing";
      } else if (current instanceof IOException) {
        category = "io_failure"; rank = 10;
      }
      if (rank < selectedRank) { selected = category; selectedRank = rank; }
      try { current = current.getCause(); }
      catch (Throwable ignored) { return "unclassified"; }
    }
    return selected;
  }
  private static String dataNodeOriginFrame(StackTraceElement frame) {
    // Exact methods on the pinned normal-JAR startup path, not arbitrary names.
    return switch (frame.getClassName()) {
      case "org.apache.hadoop.hdfs.server.datanode.DataNode" -> switch (frame.getMethodName()) {
        case "<init>" -> "origin_datanode_constructor";
        case "instantiateDataNode" -> "origin_datanode_instantiate";
        case "makeInstance" -> "origin_datanode_make_instance";
        case "startDataNode" -> "origin_datanode_start";
        case "initDataXceiver" -> "origin_datanode_xceiver";
        default -> null;
      };
      case "org.apache.hadoop.hdfs.server.datanode.DNConf" -> switch (frame.getMethodName()) {
        case "<init>" -> "origin_datanode_config";
        default -> null;
      };
      case "org.apache.hadoop.hdfs.server.datanode.web.DatanodeHttpServer" -> switch (frame.getMethodName()) {
        case "<init>" -> "origin_datanode_http";
        case "getFilterHandlers" -> "origin_datanode_http_filters";
        default -> null;
      };
      default -> null;
    };
  }
  private static String dataNodeOrigin(Throwable failure) {
    String selected = null;
    Throwable current = failure;
    try {
      for (int depth = 0; current != null && depth < 8; depth++) {
        StackTraceElement[] frames = current.getStackTrace();
        for (int i = 0; i < frames.length && i < 32; i++) {
          String marker = dataNodeOriginFrame(frames[i]);
          if (marker != null) { selected = marker; break; }
        }
        // A bounded deeper cause can replace a generic wrapper's origin.
        current = current.getCause();
      }
    } catch (Throwable ignored) { return null; }
    return selected;
  }
  private static void recordFailure(List<String> errors, String stage, Throwable failure) {
    errors.add(stage);
    String reason = failureReason(failure);
    if (!errors.contains(reason)) errors.add(reason);
    if (stage.equals("datanode_start_failed")) {
      String origin = dataNodeOrigin(failure);
      if (origin != null && !errors.contains(origin)) errors.add(origin);
    }
  }
  private static void checkExitRequests() throws IOException {
    require(!ExitUtil.terminateCalled(), "exit_requested");
    require(!ExitUtil.haltCalled(), "halt_requested");
  }

  // Literal bytes are the independent oracle; HDFS metadata never defines it.
  private static Map<String, byte[]> samples() {
    Map<String, byte[]> files = new TreeMap<>();
    files.put("README.txt", hex("484446532073796e74686574696320666978747572650a"));
    files.put("empty.bin", hex(""));
    files.put("nested/alpha.txt", hex("616c7068610a"));
    files.put("nested/space name.txt", hex("7370616365206e616d650a"));
    files.put("nested/deeper/data.bin", sequence(256));
    files.put("unicode/utf8.txt", hex("636166c3a90a"));
    files.put("private/owner-only.txt", hex("707269766174652073796e7468657469632062797465730a"));
    files.put("large/cancel.bin", sequence(2097152));
    return files;
  }

  private static byte[] hex(String value) { return HexFormat.of().parseHex(value); }
  private static byte[] sequence(int length) {
    byte[] value = new byte[length];
    for (int i = 0; i < length; i++) value[i] = (byte) (i & 255);
    return value;
  }
  private static String sha256(byte[] value) throws Exception {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
  }
  private static short mode(String path) {
    return (short) (path.equals("private/owner-only.txt") ? 0600 : 0644);
  }
  private static String quoted(String value) {
    // Only controlled fixture strings/hex/static errors reach this serializer.
    if (!value.matches("[A-Za-z0-9_./ :\\-]*")) throw new IllegalArgumentException("json_value");
    return "\"" + value + "\"";
  }
  private static void require(boolean condition, String code) throws IOException {
    if (!condition) throw new FixtureFailure(code);
  }

  private static void privateDirectory(Path path) throws IOException {
    Files.createDirectory(path, PosixFilePermissions.asFileAttribute(
        PosixFilePermissions.fromString("rwx------")));
  }
  private static void environment(String[] args) throws Exception {
    require(args.length == 0, "arguments_invalid");
    require(System.getProperty("os.name").equals("Linux"), "environment_invalid");
    require(Runtime.version().feature() == 17, "java_version_invalid");
    require(Boolean.getBoolean("java.net.preferIPv4Stack"), "ipv4_required");
    require(VersionInfo.getVersion().equals("3.5.0"), "hadoop_version_invalid");
    require(Files.isDirectory(WORK, NOFOLLOW) && !Files.isSymbolicLink(WORK), "work_invalid");
    require(((Number) Files.getAttribute(WORK, "unix:uid", NOFOLLOW)).intValue() == 10001,
        "work_owner_invalid");
    require(((Number) Files.getAttribute(WORK, "unix:gid", NOFOLLOW)).intValue() == 10001,
        "work_owner_invalid");
    require(Files.getPosixFilePermissions(WORK, NOFOLLOW)
        .equals(PosixFilePermissions.fromString("rwx------")), "work_permissions_invalid");
    require(!Files.exists(SHUTDOWN, NOFOLLOW), "shutdown_preexisting");
    privateDirectory(STATE);
    privateDirectory(OUTPUT);
    outputIdentity = Files.readAttributes(OUTPUT, BasicFileAttributes.class, NOFOLLOW).fileKey();
    require(outputIdentity != null, "output_identity_unavailable");
    for (String child : List.of("name", "edits", "data", "tmp", "http", "native"))
      privateDirectory(STATE.resolve(child));
    System.setProperty("java.io.tmpdir", STATE.resolve("tmp").toString());
    System.setProperty("io.netty.native.workdir", STATE.resolve("native").toString());
  }

  private record WebAppFile(int size, String sha256) {}
  private static void verifyWebAppResources() throws Exception {
    // Fixture-only scaffolding, not vendor UI. The parent binds these immutable
    // image files to its reviewed build context; hashes here are independent.
    Path root = Path.of("/opt/hdfs/classes/webapps");
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
        URL resource = HdfsFixture.class.getClassLoader().getResource("webapps/" + name);
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
      throw new FixtureFailure("webapp_resources_invalid");
    }
  }

  private static Configuration configuration() {
    // No default/site resources from an ambient HADOOP_CONF_DIR/classpath.
    Configuration conf = new HdfsConfiguration(false);
    conf.set("fs.defaultFS", "hdfs://127.0.0.1:19000");
    conf.set("dfs.namenode.rpc-address", "127.0.0.1:19000");
    conf.set("dfs.namenode.rpc-bind-host", "127.0.0.1");
    conf.set("dfs.datanode.address", "127.0.0.1:19001");
    conf.set("dfs.datanode.ipc.address", "127.0.0.1:19002");
    conf.set("dfs.namenode.http-address", "127.0.0.1:19003");
    conf.set("dfs.namenode.http-bind-host", "127.0.0.1");
    conf.set("dfs.datanode.http.address", "127.0.0.1:19004");
    conf.set("dfs.datanode.http.internal-proxy.port", "19005");
    conf.set("dfs.http.policy", "HTTP_ONLY");
    conf.set("dfs.datanode.hostname", "127.0.0.1");
    conf.set("dfs.client.use.datanode.hostname", "false");
    conf.set("dfs.datanode.use.datanode.hostname", "false");
    conf.set("hadoop.security.authentication", "simple");
    conf.set("hadoop.security.authorization", "false");
    conf.set("hadoop.user.group.static.mapping.overrides",
        "fixture-owner=fixture-group;fixture-other=fixture-other-group");
    conf.set("dfs.permissions.enabled", "true");
    conf.set("dfs.reformat.disabled", "true");
    conf.set("dfs.replication", "1");
    conf.set("dfs.namenode.safemode.min.datanodes", "1");
    conf.set("dfs.namenode.safemode.extension", "0");
    conf.set("dfs.namenode.accesstime.precision", "0");
    conf.set("dfs.client.read.shortcircuit", "false");
    conf.set("dfs.domain.socket.path", "");
    conf.set("dfs.datanode.max.locked.memory", "0");
    conf.set("dfs.blocksize", "1048576");
    conf.set("dfs.client.socket-timeout", "10000");
    conf.set("ipc.client.connect.timeout", "5000");
    conf.set("ipc.client.connect.max.retries", "0");
    conf.set("ipc.client.connect.max.retries.on.timeouts", "0");
    conf.set("ipc.client.rpc-timeout.ms", "10000");
    conf.set("dfs.namenode.name.dir", STATE.resolve("name").toUri().toString());
    conf.set("dfs.namenode.edits.dir", STATE.resolve("edits").toUri().toString());
    conf.set("dfs.datanode.data.dir", STATE.resolve("data").toUri().toString());
    conf.set("hadoop.tmp.dir", STATE.resolve("tmp").toString());
    conf.set("hadoop.http.temp.dir", STATE.resolve("http").toString());
    return conf;
  }

  private static String configurationHash(Configuration conf) throws Exception {
    Map<String, String> values = new TreeMap<>();
    for (Map.Entry<String, String> value : conf) values.put(value.getKey(), value.getValue());
    StringBuilder framed = new StringBuilder();
    for (Map.Entry<String, String> value : values.entrySet())
      framed.append(value.getKey().length()).append(':').append(value.getKey())
          .append(value.getValue().length()).append(':').append(value.getValue());
    return sha256(framed.toString().getBytes(StandardCharsets.UTF_8));
  }
  private static void address(InetSocketAddress actual, int port) throws IOException {
    require(actual != null && actual.getAddress() != null
        && actual.getAddress().getHostAddress().equals("127.0.0.1")
        && actual.getPort() == port, "endpoint_mismatch");
  }
  private static Set<Integer> listeners() throws Exception {
    Set<Integer> ports = new HashSet<>();
    for (String name : List.of("tcp", "tcp6")) {
      Path path = Path.of("/proc/net/" + name);
      byte[] bytes;
      try (InputStream stream = Files.newInputStream(path)) { bytes = stream.readNBytes(262145); }
      require(bytes.length <= 262144, "listener_inventory_bound");
      String[] lines = new String(bytes, StandardCharsets.US_ASCII).split("\n");
      require(lines.length > 0 && lines.length <= 1024, "listener_inventory_bound");
      for (int index = 1; index < lines.length; index++) {
        String[] fields = lines[index].trim().split("\\s+");
        require(fields.length >= 10, "listener_inventory_invalid");
        if (!fields[3].equals("0A")) continue;
        String[] local = fields[1].split(":");
        require(name.equals("tcp") && local.length == 2 && local[0].equals("0100007F"),
            "listener_not_loopback");
        int port = Integer.parseInt(local[1], 16);
        require(ports.add(port), "listener_duplicate");
      }
    }
    return ports;
  }
  private static void topology(NameNode nn, DataNode dn, DistributedFileSystem fs) throws Exception {
    checkExitRequests();
    address(nn.getNameNodeAddress(), 19000);
    address(nn.getHttpAddress(), 19003);
    address(dn.getXferAddress(), 19001);
    require(dn.getIpcPort() == 19002 && dn.getInfoPort() == 19004, "endpoint_mismatch");
    require(nn.getHttpsAddress() == null && nn.getAuxiliaryNameNodeAddresses().isEmpty(),
        "extra_service");
    DatanodeInfo[] nodes = fs.getDataNodeStats(HdfsConstants.DatanodeReportType.ALL);
    require(nodes.length == 1 && nodes[0].getCapacity() > 0 && nodes[0].getRemaining() > 0,
        "datanode_not_ready");
    DatanodeInfo node = nodes[0];
    require(node.getIpAddr().equals("127.0.0.1") && node.getHostName().equals("127.0.0.1")
        && node.getXferPort() == 19001 && node.getIpcPort() == 19002
        && node.getInfoPort() == 19004, "advertised_endpoint_mismatch");
    require(listeners().equals(PORTS), "listener_set_mismatch");
  }
  private static void ready(NameNode nn, DataNode dn, DistributedFileSystem fs) throws Exception {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(STARTUP_SECONDS);
    while (true) {
      DatanodeInfo[] live = fs.getDataNodeStats(HdfsConstants.DatanodeReportType.LIVE);
      if (live.length == 1 && live[0].getCapacity() > 0
          && !fs.setSafeMode(HdfsConstants.SafeModeAction.SAFEMODE_GET)) break;
      require(System.nanoTime() < deadline, "startup_timeout");
      Thread.sleep(100);
    }
    topology(nn, dn, fs);
  }
  private static org.apache.hadoop.fs.Path remote(String relative) {
    return new org.apache.hadoop.fs.Path(ROOT + (relative.isEmpty() ? "" : "/" + relative));
  }
  private static Set<String> directories(Map<String, byte[]> files) {
    Set<String> dirs = new TreeSet<>();
    dirs.add("");
    for (String file : files.keySet()) {
      int slash = file.lastIndexOf('/');
      while (slash >= 0) { dirs.add(file.substring(0, slash)); slash = file.lastIndexOf('/', slash - 1); }
    }
    return dirs;
  }
  private static void seed(DistributedFileSystem fs, Map<String, byte[]> files) throws Exception {
    require(!fs.exists(remote("")), "source_preexisting");
    for (String dir : directories(files)) {
      require(fs.mkdirs(remote(dir), new FsPermission((short) 0755)), "mkdir_failed");
      fs.setPermission(remote(dir), new FsPermission((short) 0755));
    }
    for (Map.Entry<String, byte[]> entry : files.entrySet()) {
      try (FSDataOutputStream out = fs.create(remote(entry.getKey()), false)) {
        out.write(entry.getValue());
      }
      fs.setPermission(remote(entry.getKey()), new FsPermission(mode(entry.getKey())));
      fs.setTimes(remote(entry.getKey()), MTIME_MS, MTIME_MS);
    }
    for (String dir : directories(files)) fs.setTimes(remote(dir), MTIME_MS, MTIME_MS);
  }
  private static void verifySource(DistributedFileSystem fs, Map<String, byte[]> files) throws Exception {
    Set<String> expectedDirs = directories(files), foundFiles = new TreeSet<>(), foundDirs = new TreeSet<>();
    ArrayDeque<String> pending = new ArrayDeque<>(); pending.add("");
    int observed = 0;
    while (!pending.isEmpty()) {
      String relativeDir = pending.remove();
      FileStatus directory = fs.getFileStatus(remote(relativeDir));
      require(directory.isDirectory() && !directory.isSymlink()
          && directory.getPermission().toShort() == 0755
          && directory.getOwner().equals(OWNER) && directory.getModificationTime() == MTIME_MS,
          "directory_changed");
      require(foundDirs.add(relativeDir), "source_duplicate");
      FileStatus[] children = fs.listStatus(remote(relativeDir));
      require(children.length <= 16, "source_inventory_bound");
      for (FileStatus child : children) {
        require(++observed <= 32 && !child.isSymlink(), "source_inventory_bound");
        String full = child.getPath().toUri().getPath();
        require(full.startsWith(ROOT + "/"), "source_scope");
        String relative = full.substring(ROOT.length() + 1);
        if (child.isDirectory()) {
          require(expectedDirs.contains(relative), "unexpected_directory");
          pending.add(relative);
        } else {
          require(child.isFile() && files.containsKey(relative) && foundFiles.add(relative), "unexpected_file");
          byte[] expected = files.get(relative);
          require(child.getLen() == expected.length && child.getOwner().equals(OWNER)
              && child.getPermission().toShort() == mode(relative)
              && child.getModificationTime() == MTIME_MS && child.getAccessTime() == MTIME_MS
              && child.getReplication() == 1, "source_metadata_changed");
          byte[] actual;
          try (InputStream input = fs.open(remote(relative))) { actual = input.readNBytes(expected.length + 1); }
          require(Arrays.equals(actual, expected) && sha256(actual).equals(sha256(expected)), "source_bytes_changed");
        }
      }
    }
    require(foundFiles.equals(files.keySet()) && foundDirs.equals(expectedDirs), "source_inventory_changed");
    require(!fs.exists(remote("missing-synthetic.bin")), "missing_member_present");
  }
  private static String manifest(Map<String, byte[]> files) throws Exception {
    List<String> rows = new ArrayList<>();
    for (Map.Entry<String, byte[]> entry : files.entrySet())
      rows.add("{\"path\":" + quoted(entry.getKey()) + ",\"size\":" + entry.getValue().length
          + ",\"sha256\":" + quoted(sha256(entry.getValue())) + ",\"mode\":"
          + quoted(mode(entry.getKey()) == 0600 ? "0600" : "0644") + "}");
    return "[" + String.join(",", rows) + "]";
  }
  private static String report(String phase, boolean preserved, boolean configPreserved,
      boolean closed, String configHash, List<String> errors, Map<String, byte[]> files) throws Exception {
    List<String> codes = new ArrayList<>(); for (String error : errors) codes.add(quoted(error));
    boolean success = preserved && configPreserved && errors.isEmpty() && (phase.equals("ready") || closed);
    return "{\"schema_version\":1,\"scope\":\"hdfs_simple_fixture\",\"phase\":" + quoted(phase)
        + ",\"ledger_eligible\":false,\"authentication_verified\":false,\"authentication_mode\":\"SIMPLE\""
        + ",\"success\":" + success + ",\"source_preserved\":" + preserved
        + ",\"configuration_preserved\":" + configPreserved + ",\"api_shutdown_complete\":" + closed
        + ",\"owner\":" + quoted(OWNER) + ",\"root\":" + quoted(ROOT) + ",\"mtime_ms\":" + MTIME_MS
        + ",\"ports\":{\"namenode_rpc\":19000,\"datanode_data\":19001,\"datanode_ipc\":19002,"
        + "\"namenode_http\":19003,\"datanode_http\":19004,\"datanode_internal_http\":19005}"
        + ",\"files\":" + manifest(files) + ",\"configuration_sha256\":"
        + (configHash == null ? "null" : quoted(configHash)) + ",\"errors\":[" + String.join(",", codes) + "]}\n";
  }
  private static void publish(String name, String report) throws Exception {
    byte[] bytes = report.getBytes(StandardCharsets.UTF_8);
    require(bytes.length <= MAX_REPORT_BYTES, "report_bound");
    require(outputIdentity != null && Files.isDirectory(OUTPUT, NOFOLLOW)
        && outputIdentity.equals(Files.readAttributes(OUTPUT, BasicFileAttributes.class, NOFOLLOW).fileKey()),
        "output_identity_changed");
    Path target = OUTPUT.resolve(name), pending = OUTPUT.resolve(name + ".pending");
    try (FileChannel channel = FileChannel.open(pending, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
      ByteBuffer buffer = ByteBuffer.wrap(bytes);
      while (buffer.hasRemaining()) channel.write(buffer);
      channel.force(true);
    }
    // Same-filesystem Linux rename publishes a complete file. ATOMIC_MOVE is
    // deliberately omitted: its specified target-existing behavior may replace.
    Files.move(pending, target); // same owned directory; no replace-existing option
  }
  private static void waitForShutdown(long deadline) throws Exception {
    while (!Files.exists(SHUTDOWN, NOFOLLOW)) {
      checkExitRequests();
      require(System.nanoTime() < deadline, "shutdown_timeout");
      Thread.sleep(100);
    }
    require(Files.isRegularFile(SHUTDOWN, NOFOLLOW) && !Files.isSymbolicLink(SHUTDOWN)
        && Files.size(SHUTDOWN) == 9, "shutdown_invalid");
    require(Arrays.equals(Files.readAllBytes(SHUTDOWN), "shutdown\n".getBytes(StandardCharsets.US_ASCII)),
        "shutdown_invalid");
  }
  public static void main(String[] args) {
    NameNode nn = null; DataNode dn = null; DistributedFileSystem fs = null;
    Map<String, byte[]> files = samples(); List<String> errors = new ArrayList<>();
    boolean preserved = false, configPreserved = false, closed = true;
    String configHash = null; String stage = "environment_failed";
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(LIFETIME_SECONDS);
    try {
      environment(args);
      stage = "webapp_resources_failed";
      verifyWebAppResources();
      stage = "startup_failed";
      // Pinned common-JAR embedding API; intercepted exits still fail evidence.
      ExitUtil.disableSystemExit();
      ExitUtil.disableSystemHalt();
      // Co-located normal daemons need unique metrics source/MBean names and
      // shared metrics lifecycle accounting; filesystem security is unchanged.
      DefaultMetricsSystem.setMiniClusterMode(true);
      Configuration conf = configuration();
      UserGroupInformation.setConfiguration(conf);
      UserGroupInformation.setLoginUser(UserGroupInformation.createRemoteUser(OWNER));
      require(!UserGroupInformation.isSecurityEnabled(), "simple_required");
      // dfs.reformat.disabled overrides the public format API's force defaults.
      stage = "format_failed";
      NameNode.format(conf);
      stage = "namenode_start_failed";
      nn = new NameNode(conf);
      stage = "datanode_start_failed";
      dn = DataNode.createDataNode(new String[0], conf);
      require(dn != null, "datanode_missing");
      stage = "client_start_failed";
      fs = new DistributedFileSystem(); fs.initialize(URI.create("hdfs://127.0.0.1:19000"), conf);
      stage = "readiness_failed";
      ready(nn, dn, fs);
      stage = "seed_failed";
      seed(fs, files); verifySource(fs, files);
      configHash = configurationHash(conf);
      stage = "ready_report_failed";
      checkExitRequests();
      publish("ready.json", report("ready", true, true, false, configHash, errors, files));
      stage = "shutdown_request_failed";
      waitForShutdown(deadline);
      stage = "source_preservation_failed";
      topology(nn, dn, fs); verifySource(fs, files); preserved = true;
      stage = "configuration_preservation_failed";
      configPreserved = configHash.equals(configurationHash(conf));
      require(configPreserved, "configuration_changed");
    } catch (Throwable failure) {
      // No exception/path/log text in the public finite result.
      recordFailure(errors, stage, failure);
    } finally {
      try { if (fs != null) fs.close(); }
      catch (Throwable failure) { closed = false; recordFailure(errors, "client_close_failed", failure); }
      try { if (dn != null) dn.shutdown(); }
      catch (Throwable failure) { closed = false; recordFailure(errors, "datanode_shutdown_failed", failure); }
      try { if (nn != null) nn.stop(); }
      catch (Throwable failure) { closed = false; recordFailure(errors, "namenode_shutdown_failed", failure); }
      try { checkExitRequests(); }
      catch (Throwable failure) { closed = false; recordFailure(errors, "termination_requested", failure); }
      try { publish("final.json", report("final", preserved, configPreserved, closed, configHash, errors, files)); }
      catch (Throwable failure) { recordFailure(errors, "final_report_failed", failure); }
    }
    if (!errors.isEmpty()) System.exit(1);
  }
}
