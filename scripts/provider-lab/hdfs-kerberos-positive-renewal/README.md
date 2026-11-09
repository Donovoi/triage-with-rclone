# Retained MIT/HDFS renewal experiment

This hosted-only fixture connects the independently qualified full rclone build prerequisite to the owned MIT KDC and retained HDFS client. It is an experiment, with every provider, application, vendor, and vulnerability acceptance flag false. A passing parser or build does not establish runtime renewal.

The matrix runs original and context-patched rclone v1.75.2 binaries against renewable and nonrenewable short service tickets. It keeps one rclone daemon, its backend identity, and the original credential cache across actual service expiry, proves a fresh cache read is unavailable, cuts one owned RPC connection, and observes a bounded reconnect plus repeated listings. The patched renewable case must produce one authenticated renewal response with no fallback acquisition. The original renewable control must produce the usage-11/error-31 rejection followed by an ordinary usage-7 acquisition. Nonrenewable cases must acquire an ordinary ticket.

The observer binds each TGS authenticator to its original ticket/session key and request checksum. It binds the decrypted reply to the nonce, identities, ticket times, renewable horizon, flags, and new key. It then binds the initial and fresh HDFS GSS/AP requests to the expected original and returned tickets, verifies the service authenticator under usage 11, observes the bounded SASL state sequence, and matches the exact empty listing response. RPC frames are forwarded unchanged. The established RPC parser has 85 managed vectors; authenticator, response, and service-AP mutation controls must pass during native execution.

The wrapper reuses digest-bound preparation workers from the complete rclone build and MIT prerequisite. Separate owned temporary roots preserve each worker's admitted path rules. Public source/module archives, Maven JARs, and MIT packages remain pinned and verified. Go and Java compilation run only in the pinned hosted image with networking disabled. Each of five runtime containers (binary identity and four cases) has no network, read-only root, UID/GID 10001, all capabilities dropped, no added privileges, 128 PIDs, 2 GiB memory, two CPUs, and a 128 MiB private tmpfs. Java cases have a 180-second child timeout and a separate 195-second supervisor bound.

The retained MIT owner remains unchanged. Its exact child identity is the only process added to the original process baseline; all owned children, streams, threads, listeners, private files, containers, image, contexts, and raw logs must be accounted for and cleaned. Only closed, bounded JSON diagnostics are uploaded. Raw tickets, keys, RPC frames, KDC logs, dependency redirect URLs, and candidate binaries are never published.

Run pure checks with:

    python -I -S -B scripts/provider-lab/hdfs-kerberos-positive-renewal/run_guarded_tests.py

The audit hook rejects network, subprocess, native library loading, exec, and spawn attempts. Native qualification is performed only by the automatic pull-request workflow; there is no manual-dispatch entry point. Inspect the exact-head sanitized artifact independently before granting any further acceptance.
