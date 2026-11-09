# Contained HDFS cache-expiry experiment

This separate experiment tests a genuinely issued, nonrenewable reader TGT through expiry and an explicit synthetic cache replacement. It is preparation until its exact source revision passes the hosted native run. It does not establish successful ticket renewal, same-client reconnect, cancellation, application integration, vendor behavior, or provider acceptance.

The fixture derives from the contained RPC probe and retains its pinned JDK, 142-JAR runtime, rclone 1.75.2, network-none container, 60-second control window, memory/CPU/PID limits, and owned cleanup checks. The new workflow explicitly selects the remediation dependency profile. No runtime pin changes, host credentials, external KDC, DataNode, payload download, or private cloud account are involved.

The owned KDC issues a ten-second FILEv3 TGT. An independent cache parser checks its principal, encryption type, flags, times and shape, then compares the stored ticket bytes and expiry with the actual KDC-issued ticket object. The fixture does not edit cache timestamps to simulate expiry.

Four rclone operations use fresh processes and the same fixed NameNode relay, reader and cache path:

1. List the empty owned directory before expiry.
2. Reject username-only authentication, retaining the existing independently parsed NONE/fatal response control.
3. Wait past the issued expiry under a monotonic deadline, then require a nonzero authenticated listing result with the source-specific no-valid-session diagnostic. Every observed connection in this phase must carry a Kerberos header; a NONE header fails the fixture.
4. After the expired process has exited and all its readers and relay threads have ended, retain the original cache at a second owned path, issue and publish a distinct fresh TGT at the original cache path, and require a new process to list successfully.

The version check plus these operations permits at most five owned child processes. The original cache remains identity- and hash-checked at its archived path until cleanup. The working synthetic credential directory permits one additional owned file. Unknown/replaced paths never become cleanup targets.

The expiry diagnostic is combined with actual issued-ticket binding, elapsed expiry, unchanged endpoint/source configuration, Kerberos-only phase attribution, and successful controls before and after. It is a client cache-expiry result, not proof of a KDC rejection. Raw stderr, cache bytes, principals, keys and ticket bytes are never publishable. Only closed categories, counts, booleans and bounded relative times enter the receipt.

The distinction follows the pinned [rclone HDFS constructor](https://github.com/rclone/rclone/blob/v1.75.2/backend/hdfs/fs.go), [gokrb5 CCache client](https://github.com/jcmturner/gokrb5/blob/v8.4.4/v8/client/client.go), and [session refresh path](https://github.com/jcmturner/gokrb5/blob/v8.4.4/v8/client/session.go). External cache replacement with a new client must not be reported as automatic TGT renewal. The independent service-ticket renewal/fallback and retained-client reconnect cases remain outstanding.

Only pure guarded checks may run locally:

```text
python -I -S -B scripts/provider-lab/hdfs-kerberos-cache-expiry/run_pure_tests.py
```

Native execution is restricted to the explicit hosted workflow. Existing transfer/protocol evidence and its six-capability boundary remain unchanged.

Cleanup receipts also classify remaining Hadoop RPC threads into three fixed
categories: client request sender, client connection, or other. A separate
snapshot at cleanup entry can show a transient sender while the final snapshot
still requires zero residual threads. These categories and first-observed
intervals are diagnostics, not ownership proofs or cleanup exemptions. No raw
thread names, addresses, or stacks are published.

The owner filesystem used to seed the empty directory closes before the reader
TGT is issued. A second owned filesystem verifies the preserved directory after
the reader controls. Both handles remain tracked and share the original bounded
filesystem cleanup deadline. This avoids keeping a setup RPC connection idle
through the intentional expiry wait. It does not test retained-client reconnect
or establish the exact cause of an earlier intermittent RPC cleanup residual.
