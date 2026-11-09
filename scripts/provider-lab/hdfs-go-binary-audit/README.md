# Isolated Go binary advisory observations

This automatic pull-request experiment rebuilds the qualified original and HDFS-context-patched rclone v1.75.2 binaries, then observes them with unmodified govulncheck v1.9.0 and an immutable Go vulnerability database snapshot. Native compilation and execution occur only in owned hosted containers with no network, a read-only root, UID 10001, no capabilities, private namespaces, bounded resources, and an owned work tmpfs.

The foundation gate binds both binary hashes, all 242 compiled dependency identities per binary, and the existing native context tests. The scanner wrapper binds analyzer source and compiled dependencies, target hashes before and after execution, process completion, and bounded stdout/stderr. Analyzer source version is recorded separately from its local embedded development version and CLI version.

Admission requires complete metadata and nonempty extracted symbols before interpreting a real scan. Independent native controls cover a synthetic affected symbol, a synthetic unaffected symbol, and the scanner's empty-symbol fallback using a separate artificial database. A separately built stripped original binary must retain matching module metadata while failing symbol admission. Synthetic observations never count as evidence about the real binaries.

The snapshot contains 4,789 advisory records and 4,792 byte-preserved files. Its source archive, deterministic bundle, indexes, record projections, and emitted advisory multiplicities are bound. The expected 361 emitted OSV messages (334 unique IDs) are database retrieval observations before vulnerability applicability filtering; they are not counts of vulnerabilities.

The public result contains validated metadata, finding levels, control outcomes, closed failure categories, and cleanup evidence. Raw native streams and build context are removed only after owned processes, containers, and the image are gone. Shared base images and build cache are outside that cleanup scope.

This experiment does not establish source-call reachability, exploitability, a complete vulnerability audit, or provider/application/vendor acceptance. Local main-module development versions and the local HDFS replacement require separate upstream advisory review. Publisher advisories absent from the curated snapshot also remain separate. Production dependencies, provider schedules, credentials, and VM operations are unchanged.

Public upstream licenses and data attribution are retained in the COPYING and NOTICE files. Source archive hashes and Go module h1 sums are checked; this experiment does not independently authenticate a SumDB signed tree head.
