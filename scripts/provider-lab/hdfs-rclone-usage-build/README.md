# Full rclone Kerberos candidate builds

This hosted experiment builds the complete rclone v1.75.2 entry point twice with Go 1.26.10 and the published rclone dependency graph. The original candidate uses published dependencies. The patched candidate adds one explicit local replacement for gokrb5 v8.4.4, containing the two context-specific authenticator changes from the adjacent hdfs-gokrb-usage fixture.

Both candidates retain all upstream backend and command imports. They use distinct experiment version strings, and the production rclone version/download pins remain unchanged. The runner checks each binary's digest, embedded Go/module information, disabled CGO, platform, trimmed paths and absence of VCS metadata. It then checks the actual version command in the contained runtime. Both compiled dependency lists must match except for the explicit gokrb5 replacement, including rclone's x/crypto v0.57.0, x/net v0.60.0 and HDFS v2.4.0.

This is a build and binary-identity prerequisite. It does not contact a KDC, prove service renewal, qualify any provider/application/vendor path or audit vulnerabilities. The next retained-client test must demonstrate the actual renewed ticket and subsequent authenticated HDFS RPC, with the existing expiry, cache and cleanup barriers.

## Inputs and containment

The signed upstream v1.75.2 tag resolves to commit be8d6044eacb843b74d335db0c5fbe09222031fe. Its Go module archive matches the saved upstream go.mod and go.sum. The lock contains 334 source ZIPs, 468 module files, 334 version metadata files and one toolchain archive: 507,477,878 bytes. Exact sizes and SHA-256 bind all downloads; published Go Hash1 values bind the source ZIPs and module files. Module paths use Go's case escaping in the download cache. Archive processing is bounded to 100,000 members and 2 GiB expanded data across the graph, with no traversal, links or special files.

Host work is limited to guarded Python contracts, passive downloads/archive processing and the existing bounded Docker supervisor. Native builds and runs occur only inside the pinned Linux image with no network. The compiler cannot change toolchains, contact a module proxy or run CGO. Original source and patch provenance are recorded separately; the replacement is visible in binary build information.

Transient timeouts, connection interruptions and HTTP 429/500/502/503/504 receive at most three attempts per asset with one- and two-second backoffs. The overall 570-second download deadline and 512 MiB transferred-byte cap include retries. Partial files restart with fresh hashes; checksum, length, archive, authorization and other permanent failures remain fatal. The download worker has a 600-second kill/reap bound; image compilation has a separate 600-second bound. Runtime checks have 10-second child deadlines and a 45-second outer bound, with UID 10001, read-only root, no capabilities, no new privileges, private namespaces, 128 PIDs, 2 GiB RAM, 2 CPUs and a private 32 MiB tmpfs. Version-output files are size-limited. Owned containers, images, contexts and raw command output are removed and verified; shared base-image/build caches are explicitly excluded.

Only a bounded JSON report is retained. Asset-worker diagnostics contain a closed phase, asset ordinal, completed count, error category and HTTP status; they exclude raw exception text and redirect URLs. Candidate binaries are not published or installed. Their source dependencies retain their upstream licenses; the rclone license is included as COPYING-rclone.

Run only the pure contracts locally:

    python -I -S -B scripts/provider-lab/hdfs-rclone-usage-build/run_guarded_tests.py

Native execution belongs to the automatic hosted pull-request workflow.
