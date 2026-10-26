# Contained HDFS Kerberos RPC experiment

This source-only experiment prepares a hosted NameNode interoperability check.
It does not earn provider, application, vendor, download or full HDFS protocol
coverage. Those claims remain false even if a hosted run succeeds. No DataNode,
file payload, host credential, external KDC or vendor account is used.

The workflow checks out the exact PR head, prepares the existing public pinned
inputs, compiles with `javac -proc:none -implicit:none` without a network, and
runs one unprivileged network-none container. It uses the existing Kerberos
142-JAR classpath, Hadoop 3.5.0, Kerby 2.1.2, the pinned JDK 17 image, and rclone
1.75.2. No additional runtime dependency is introduced. Dependency pinning is
integrity evidence; the existing lock still has advisory work pending.

The default `kerberos` profile preserves that original graph and workflow.
The separate remediation workflow selects `--profile kerberos-remediation`,
using `runtime-classpath-remediation.json` and
`hdfs-discovery/artifact-lock-kerberos-remediation.json`. Its 142 JARs total
73,104,651 bytes, with ordered runtime SHA256
`74206f7ff8e05475fd310648003cd570c620e92cf670ee1965c66b96eb3ba15d`.
The supervisor and owned downloader both require the same closed profile and
exact runtime/lock bytes; no custom paths or fallback graph are accepted.
Receipts identify the selected profile, runtime file, ordered rows and lock.

This graph includes Commons IO 2.22.0 to supply the method required by
Commons Configuration 2.15.1. Its online inventory is verified; fresh offline
replay and exact-head RPC validation are still required after this pin update.
Earlier remediation replay/RPC results bind the earlier hashes and cannot
qualify this corrected graph. Four Jetty advisory matches and incomplete dependency
semantics remain; all security, provider, application, vendor and ledger
acceptance flags remain false. The Java probe and all service/resource bounds
are identical between the two profiles.

The fixed loopback services are NameNode RPC `19000`, NameNode HTTP/SPNEGO
scaffolding `19003`, synthetic TCP KDC `19006`, and owned relay `19007`. All
three rclone operations use the same relay endpoint and reader. The HTTP
scaffolding follows the pinned NameNode `HTTP_ONLY` API path and is never used
as an authentication or TLS test. Secure DataNode HTTPS remains future work.

The owner creates `/synthetic/empty` and issues a nonrenewable, 120-second
FILEv3 reader TGT after startup. Within 60 seconds, rclone must list exactly an
empty directory using Kerberos, fail a fresh username-only listing, then list
the same directory successfully using Kerberos again. The owner independently
checks the directory type, length, owner, permissions, group, timestamps and
empty contents before and after; configuration and private credential hashes
must remain unchanged.

The negative test deliberately does not trust stderr. In pinned
`colinmarc/hdfs` commit `13d9368869e6f7f0a8db9d92e52c2ab54dae483e`,
`internal/rpc/transport.go` compares call IDs before inspecting status. Hadoop
returns authorization failure on call ID `-1`, so this client can return an
unexpected-sequence error before constructing `NamenodeError`.
`internal/rpc/error.go` omits the remote message from its printed error, and
`error.go` can map AccessControlException to ordinary permission denial.
Rclone's `NewFs` also ignores its initial failed Stat. Generic permission,
transport, KDC and local-cache errors therefore cannot establish this result.

Instead, the relay attributes each actual negative connection to the active
rclone operation, checks its exact `hrpc/9/0/NONE` header, and forwards the
server's bytes unchanged. It requires one bounded fatal frame, EOF, call ID
`-1`, RPC version 9, `FATAL_UNAUTHORIZED`, the exact AccessControlException,
and `SIMPLE authentication is not enabled.  Available:[TOKEN, KERBEROS]`.
An independent direct socket oracle obtains the same response from the owned
NameNode endpoint. The Python supervisor independently parses both captures.
Only finite categories, counts and booleans are published; Kerberos payloads,
ticket bytes, principals, keytabs, stderr and raw frame bytes are never uploaded.

Each phase permits at most four relay connections; any idle or extra connection
fails and closes the listener. Handshakes, frames, stream bytes, child output,
socket deadlines and overall execution are bounded. All children, relay sockets
and threads, Hadoop clients, NameNode, owned UGI logins, KDC and listeners must
stop. Credential deletion verifies directory/file identity and content first.
NameNode storage remains private tmpfs until outer container removal. The outer
supervisor separately verifies removal of the exact owned container, derived
image, build context and raw outputs. Shared base images and build cache are
explicit exclusions on the disposable hosted runner.

Run only the pure checks locally:

```text
python -I -S -B scripts/provider-lab/hdfs-kerberos-rpc/run_pure_tests.py
```

The runner installs process/network denial before importing candidate code.
These tests exercise the Python framing/report/ownership contracts with inert
bytes and fake Docker responses. Java checks inspect source, not bytecode.
Java API compatibility, real listener/thread cleanup, SPNEGO/NameNode startup,
Kerberos interoperability, relay timing and actual pinned-rclone behavior still
require reviewed hosted execution. A timeout, malformed response, source drift,
partial cleanup or unexpected connection fails closed; do not relax pins,
permissions or failure classification to turn it into a passing result.
