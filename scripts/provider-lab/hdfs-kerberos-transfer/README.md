# Contained HDFS Kerberos transfer experiment

This sibling experiment adds one secure DataNode and known-byte acquisition to
the separately preserved NameNode RPC experiment. It is a feasibility probe, not
provider, application, vendor, cancellation, renewal, or security acceptance.
Every acceptance and ledger flag remains false, including after a hosted pass.
No native result is implied by the pure tests.

The only dependency profile is `kerberos-remediation`: the existing immutable
142-JAR runtime descriptor in `hdfs-kerberos-rpc/runtime-classpath-remediation.json`
and `hdfs-discovery/artifact-lock-kerberos-remediation.json`. The descriptor SHA-256
is `e701b0047f1198614bd590954e8efd15bf05af51b98cc62b2d9298cd721663e7`, ordered
entry SHA-256 `92533297bdae9e77befdc0c381f25850a08becac726c026ab70bd3a68b90b2a7`,
and lock SHA-256 `80184076d64194810cae394fbc6d8b00e86717c9479d6176f828b042dcd41df1`.
There are 73,478,410 runtime bytes. Four Jetty advisory matches remain. The
corrected graph selects Commons IO 2.22.0; its verified online inventory still
requires fresh offline replay, RPC and transfer validation. Earlier remediation
results bind older hashes and do not qualify this corrected transfer runtime.
The original SIMPLE and Kerberos graphs remain unchanged.

The workflow checks out the exact PR head with read-only contents permission and
no persisted credentials. The container is network-none, UID/GID 10001, read-only
root, all capabilities dropped, no new privileges, no mounts or host ports,
128 PIDs, 2 CPUs, 2 GiB, and one 128 MiB private `/work` tmpfs. Public dependency
downloads remain digest/size pinned and isolated from the credential-bearing run.
The pinned Temurin JDK image, Hadoop 3.5.0, Kerby 2.1.2 and rclone 1.75.2 identities
are recorded in the supervisor and receipt.

The fixture configures `AES/CTR/NoPadding` as the supported data-transfer cipher
option requested by the pinned privacy client. Both service configurations are
checked; privacy and block tokens remain required. NameNode and DataNode handler
pools have two workers each, the extra volume reserve is 4 MiB, and the seed
client socket cache is disabled. These fixture settings keep the original
container limits; they do not enlarge the resource or timeout budgets.

The disposable fixture shares one JVM between its two daemons. It captures the
public Hadoop metrics mini-cluster mode before format/start, requires the prior
value to be false, enables and verifies the mode, and retains it through the
owned DataNode and NameNode stop attempts. A `finally` step restores and verifies
the captured value under the unchanged cleanup deadline. The receipt exports
eight finite transition booleans, an enable check, and an explicit restoration
cleanup predicate. Failed capture, preexisting mode, failed enable, late or
failed restoration cannot receive cleanup credit, even if a later restore works.
No metrics sources are unregistered and no additional global shutdown is called.

Pinned Hadoop uses this mode for multiple daemons sharing its metrics singleton.
It also changes duplicate MBean naming and repeated-initialization reference
counting. This fixture retains direct NameNode construction (which bypasses the
NameNode factory's explicit metrics initialize call) and the existing owned
shutdown order. DataNode instantiation explicitly initializes metrics; both
daemon stop paths call their own metrics shutdown. Inspection of the format,
FSNamesystem and BlockManager paths found no extra explicit initialize call.
This is bounded source accounting, not native proof of final reference counts:
all existing residual-thread, timer, listener and stop predicates remain required.

SSL timer capture exports two closed diagnostic states. The format state reports
the existing capture result. The DataNode state records the first false ownership
predicate through a primitive Boolean identity helper: each original expression
is evaluated once, in the same short-circuit order, and the same assertion still
throws `cleanup_failed`. A `checking` state denotes incomplete evaluation rather
than a known failed predicate. Both states must be `captured` before a successful
receipt; capture alone never substitutes for later stop and cleanup evidence.
No thread names, identities, stacks or private exception text are exported.

Eight IPv4 loopback ports are preflighted and checked as an exact listener set:
19000 NameNode RPC, 19001 DataNode SASL transfer, 19002 DataNode IPC, 19003 NameNode
HTTPS, 19004 DataNode HTTPS, 19005 DataNode's private internal HTTP proxy, 19006
synthetic TCP KDC, and 19007 byte-preserving RPC relay. No UDP/IPv6 listener or
port drift is accepted. `HTTPS_ONLY`, block tokens, SASL privacy, no trusted
channel bypass, and `ignore.secure.ports.for.testing=false` are mandatory.
The similarly named `dfs.datanode.ignore.secure.ports.for.testing` is rejected.

The one native TLS preparation child is the pinned JDK's keytool. Its fixed argv
uses `-storepass:file` and `-keypass:file` with one private password-file path;
password values never enter argv or exported logs. OpenJDK tag
`jdk-17.0.20.1+1`, commit `c35a8d5a87559ad2734f1023bb321176c13c7ba0`,
`sun/security/tools/keytool/Main.java:536-595` and
`sun/security/tools/KeyStoreUtil.java:140-189` implement these modifiers. It creates
one one-day RSA-2048/SHA256 certificate with IP SAN 127.0.0.1. Java creates the
single-certificate PKCS12 truststore without a second native child.

NameNode's `DFSUtil.loadSslConfiguration` and DataNode's `SSLFactory` independently
load the same owned relative `owned-ssl-server.xml`. The writable classpath tail
contains exactly this XML, after immutable classes/JARs; it contains no classes,
JARs, keys, or unrelated resources. Both HTTPS endpoints must complete a bounded
JDK TLS handshake using only the owned truststore and HTTPS endpoint identification.
This is local TLS fixture proof, not vendor TLS or HTTP authentication acceptance.

The Java owner seeds three files below `/synthetic`, replication 1, block size
1 MiB, mode 0644, directories 0755, fixed mtime/atime, and byte `i % 256`:

| File | Bytes | SHA-256 |
|---|---:|---|
| `empty.bin` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `nested/space name.bin` | 4096 | `c8f5d0341d54d951a71b136e6e2afcb14d11ed8489a7ae126a8fee0df6ecf193` |
| `payload.bin` | 1052673 | `ac6f8d639b2e2c683c08d7deae690d1b6120bd74bc80a39a895481450082c571` |

One registered live DataNode with positive capacity and the captured UUID must
own every reported block; payload.bin must span exactly two blocks. Independent
Java reads compare every byte and digest before and after the rclone controls.
Source metadata, effective NameNode/DataNode settings, and private file identities
and hashes must remain unchanged. Mutable NameNode/DataNode storage is excluded
from whole-storage identity claims and disappears with the owned container.

Ten fixed phases use the same relay endpoint, with exactly one connection per
phase and no reconnect credit: inventory before, empty acquisition, small
acquisition, missing path, payload before, same-reader NONE denial, payload after,
RC checksum, RC missing object, inventory after. Authentication uses a fresh nonrenewable FILEv3 TGT. The NONE
phase has no Kerberos environment or service principal option and must produce
zero payload bytes, nonzero exit, the actual NONE header and exact unchanged
FATAL_UNAUTHORIZED/SIMPLE-disabled/KERBEROS-offered response. A separate direct
wire oracle must agree. Suppressed rclone stderr is not authentication proof.

Pinned rclone `cat` treats a missing target as a directory: NewFs ignores the
initial failed Stat, and Cat -> ListFn -> List -> ensureDirectory maps absence to
ErrorDirNotFound. The missing phase therefore requires one exact JSON
`error listing: directory not found` record, nonzero exit, zero payload bytes, and
an independent Java absence witness. It does **not** claim object-not-found
coverage. Permission, cache/KDC, timeout, or dead-endpoint failures are rejected.

The separate object controls use `rclone rc --loopback operations/hashsumfile`
with `fs=:hdfs:/synthetic`, `hashType=SHA-256`, and `download=true`. Loopback calls
the method in-process without an RC listener. First, the existing 4096-byte leaf
must return the independent seed SHA-256 through this same route, with zero exit
and empty stderr. Only then may the missing leaf receive credit: nonzero exit,
the exact closed JSON object containing `loopback: call failed: object not found`,
the exact method path and integral status 500, plus a fresh Java absence witness.
The directory rejection remains a distinct check. RC stdout is bounded JSON,
separate from acquired file bytes; the successful acquisition total is unchanged.

`HdfsTransferJson.java` holds the JSON controls and finite diagnostic classifier.
Both Java sources are independently size-bounded to 128 KiB, SHA-256 pinned,
included in the context checksums, explicitly compiled with annotation processing
and implicit compilation disabled, and rechecked before cleanup. The same JVM
checks valid JSON controls and 23 malformed or misleading alternatives, including
duplicate keys, trailing values, wrong digest, wrong method, permission/directory
errors, and nonintegral or out-of-range status. Native success requires these checks as well as
the actual paired rclone calls.

The reviewed child count is twelve: one version child, one TLS keytool child,
and ten sequential rclone controls. The two added controls share the existing
55-second control deadline; no concurrency, PID, memory, listener, output, or
outer timeout limit is increased.

Acquisition stdout streams in 4096-byte buffers to CREATE_NEW, identity-checked
0600 files. Each stream reads at most expected+1 bytes and never stores overflow;
its digest/length is independently checked by rereading the owned file. Stderr and
listing stdout each remain capped at 16 KiB. Total successful acquired bytes are
2,109,442. No payload, keytab, password, ticket, raw log, or SASL capture is exported.
Only fixed checks, finite diagnostics, known-fixture digests/counts, and source
bindings appear in the at-most-64-KiB final receipt.

Failed image builds retain only up to eight fixed compiler error categories and
bounded source line/column pairs. Build output, source symbols, and arbitrary
error text stay private and are removed with the raw run evidence. A nonzero
build cannot start the fixture or grant success.

The sibling budget is 185 seconds inside the JVM: startup 70, controls 55, cleanup
60, with one 195-second outer attach limit. Cleanup shares four seconds across
children/relay, three each for filesystem close and seed lease-renewer shutdown,
35 for owned DataNode shutdown and
its retained SSL timer, three for the retained replica-loading pool, seven for
NameNode stop, three across all retained login
Subjects, three for KDC stop, and the unchanged three-second owned-helper/residual
proof, with two seconds for private material. Every step is capped by the same
cleanup deadline. A partial constructor, timeout,
ambiguous/missing/preexisting/late identity, failed shutdown, residual thread,
or listener fails cleanup; no framework or baseline exception is granted.

DataNode.shutdown calls DatanodeHttpServer.close, which destroys its own
SSLFactory. This second timer is captured separately after DataNode construction
and must disappear through that public lifecycle. The earlier exact format
`Util.connectionFactory` and timer are retained before DataNode initialization;
only its public destroy method is used after all users close. The existing exact
GC monitor/statistics-cleaner guards remain. Ten snapshots retain at most 1280
Thread identities; live residual count is capped at 128. First-observed intervals
are diagnostics, not creation ownership proof. Every residual still fails.

Normal Hadoop block-pool shutdown removes its JVM shutdown hook without stopping
the replica-loading pool shared within the process. This disposable fixture retains the
exact pool from its only owned DataNode volume and block-pool slice, checks the
volume path and dataset identity, excludes the common pool and preexisting
workers using an immutable baseline, and releases the volume reference. After
owned users and the DataNode stop, it calls that retained pool's public graceful
shutdown and requires termination under the cleanup deadline.
`replica_pool_stopped` is required before private material can be removed. No
thread-name match, global pool reset, or arbitrary thread interruption grants
cleanup credit.

The fixture uses fixed certificate and truststore files. It sets the literal
`ssl.{0}.stores.reload.interval` option to zero and verifies it in the NameNode
topology check. Pinned Hadoop 3.5.0 HttpServer2 otherwise creates an optional
certificate-file monitor after the server has copied the builder's empty monitor
reference, leaving public stop unable to cancel that monitor. Zero suppresses
only this optional NameNode HTTPS reload timer. HTTPS, key/trust configuration,
endpoint certificate validation, and both retained SSLFactory timer lifecycles
remain required. SSLFactory uses the separate mode-resolved
`ssl.client.stores.reload.interval` and `ssl.server.stores.reload.interval` keys;
neither is changed. Live certificate reload/rotation is unverified. The prior
`wrong_interval` receipt did not identify its native timer owner; this correction
addresses the independently proven source lifecycle defect and still requires
all unchanged native identity and cleanup gates.

The initial seed/verification task exports a closed `seed_checkpoint` operation
and file role (`none`, `empty`, `small`, `payload`, or `unknown`). It records the
last entered operation group, not an inner exception cause or completed control.
Directory setup includes data-buffer preparation; metadata and listing groups
include their existing assertions. An immutable pair is published through one
volatile reference. The main failure handler snapshots that pair before error
classification and cleanup, so later worker activity cannot change the failure
record. Normal resource closing has its own checkpoint; a body exception retains
the body checkpoint and the existing suppressed-close behavior. Later source
preservation does not overwrite the initial seed checkpoint. `complete` is set
inside the existing bounded task after both seed and independent verification;
all original success, byte, authentication and cleanup predicates remain decisive.
No paths, exception text, stacks or private material are exported. Unknown roles
and incomplete checkpoints cannot support successful seed controls.

Run the pure suite with:

```
python -I -S -B scripts/provider-lab/hdfs-kerberos-transfer/run_pure_tests.py
```

It installs process/network audit denial before candidate imports. Fake Docker,
transport and malformed-receipt tests verify strict failure and cleanup handling;
Java lexical/source checks are not compilation or native qualification. Hosted
review must still establish compilation, exact runtime controls, service/child/
listener/private material cleanup and outer container/image/context cleanup.
Application integration, real vendor behavior, cancellation/renewal, independent
negotiated-QOP observation, and a DataNode block-token negative remain separate.
