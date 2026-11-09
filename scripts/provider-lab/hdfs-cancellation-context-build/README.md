# Contained HDFS cancellation candidate builds

This source-only profile qualifies the build and unit-test boundary of a proposed HDFS listing cancellation patch. It does not qualify application cancellation, a provider, or any production binary. Native execution is restricted to the automatic isolated pull-request workflow; local checks are guarded Python only.

## Patch and build boundary

The pinned rclone v1.75.2 backend currently ignores the listing context in its HDFS metadata and directory RPCs. The HDFS v2.4.0 RPC request mutex also prevents cancellation from interrupting a held response. The seven-file overlay propagates the listing context, admits queued requests with a context-aware mutex, dials with the request context, and closes only the connection owned by a cancelled operation. A started cancellation callback is joined before the request lock is released. Cancellation invalidates a partially consumed stream and leaves ordinary failover behavior in place.

Existing APIs delegate with a background context. Initial client construction, file transfer operations, lease renewal, Kerberos KDC traffic, and other operation contexts are outside this qualification. These tests use controlled net.Pipe transports; they do not establish end-to-end Kerberos or rclone job behavior, race-detector cleanliness, or behavior of arbitrary custom net.Conn implementations.

The profile reuses the unchanged 1,137-asset offline lock, bundle verifier, pinned Go 1.26.10 toolchain, and container support from the qualified full-rclone build profile. It verifies the HDFS archive, every original patch source, all seven overlay identities, and the HDFS license before building. The baseline binary is built before applying the rclone backend overlay. The patched binary replaces only HDFS v2.4.0 with the verified local source; gokrb5 remains v8.4.4 without the separate renewal patch. The full compiled module graphs and 13 version/build checks per rclone binary must pass.

## Native checks

The hosted build compiles the complete original and patched rclone binaries and a dedicated internal/rpc test binary. The unprivileged, network-disabled runtime runs exactly eleven named tests covering queued admission, pre-cancellation, expired deadlines, held reads, blocked writes, dial and handshake cancellation, callback lifetime, callback joining, ordinary errors, and fresh-connection recovery. The recovery fixture consumes both the RPC header and connection-context packet.

The inspector accepts only the eleven ordered RUN/PASS pairs, terminal PASS, zero exit, and empty stderr. Fourteen native parser controls reject omitted, repeated, reordered, unknown, skipped, failed, malformed, or unsuccessful output. A closed diagnostic object can retain finite failed-test names and stage without retaining raw output. Python validates types, bounds, names, source bindings, binary identities, and all false acceptance fields again.

The runtime has no network, a read-only root, UID/GID 10001, no capabilities, no-new-privileges, private IPC/cgroup namespace, 128 PIDs, 2 GiB memory, two CPUs, and a 32 MiB noexec tmpfs. Tests have a 30-second internal and 40-second outer deadline; the complete runtime has a 90-second bound. The build is offline with a 600-second bound. Only a sanitized JSON result is uploaded. Owned containers, images, build context, and raw evidence must be removed; shared base image and build cache are explicitly excluded from cleanup claims.

## Local checks and remaining acceptance

Run the guarded contracts with:

```text
python -I -S -B scripts/provider-lab/hdfs-cancellation-context-build/run_guarded_tests.py
```

The guard denies network, subprocesses, exec/spawn, and native library loading. It does not run Go, rclone, Docker, or a JVM.

Passing this profile is only a prerequisite for a separate retained-backend experiment. That experiment must show the patched rclone job finishes as cancelled while its own response remains held, preserve an unrelated active request, and recover an authenticated listing on a fresh stream. Existing stop-acknowledgement and release-after-cancellation observations remain diagnostic evidence only. Production pins and provider/application/vendor/security acceptance remain unchanged.
