# Isolated retained HDFS context cancellation

This experimental profile compares the qualified original and context-patched full rclone binaries with renewable and nonrenewable Kerby service tickets. It contributes no provider, application, vendor, renewal, or vulnerability-audit acceptance. Production source and dependency pins are unchanged.

## What the native run must establish

The fixture retains one authenticated rclone daemon and its HDFS backend cache entry. It first exercises service-ticket expiry, an unreadable original cache, an owned forced disconnect, and bounded reconnect using the retained TGT. The KDC relay classifies the existing renewal/fallback exchange; a continuous zero-exchange phase covers repeated listing, cancellation, and subsequent connection recovery.

Each of the four cases then performs these controls:

1. Hold the complete matching empty-directory response for an identified async listing. Observe its job unfinished three times over at least 500 ms. Start a second identified job and observe both unfinished before cancelling the queued job.
2. While the first response remains held, require the patched queued job to terminate with context cancellation and the original queued job to remain unfinished. Require the active job and stream to remain intact. Release that first response, then require the active job to succeed and the queued job to finish with context cancellation.
3. Hold a second complete matching response and cancel its identified job. Require the patched job to terminate while the response remains held. Only then may exact-stream clean client EOF authorize disposal of the held bytes. The response pump erases those bytes and acknowledges disposal before the old relay session must retire. For the original binary, require the job to remain unfinished until the response is forwarded.
4. Require successful first and repeated listings from the same daemon/cache entry. For the patched binary, require exactly one distinct authenticated recovery connection and the old session to be closed. A background lease may establish that new connection, so its admission is armed before job/stop without closing or releasing the old response.

The integration's timing observations are behavioral evidence. Direct entry into context-aware mutex admission is separately exercised by the pinned native unit test, which waits for context Done evaluation while another request owns the lock. Neither result constitutes application-wide cancellation acceptance or a race-detector qualification.

## Boundaries

Automatic pull-request qualification uses the pinned public Go/module asset lock and 142-jar remediation runtime. All Go/JVM compilation and execution happens in owned offline Linux containers: non-root, read-only root, no network or host mounts, dropped capabilities, no-new-privileges, private IPC/cgroup namespaces, 128 PIDs, 2 GiB RAM, two CPUs, and a 128 MiB private noexec work tmpfs. Identity is bounded to 90 seconds; each Java case has a 180-second timeout plus bounded supervisor allowance. Go compilation retains its 600-second bound.

The supervisor validates the 11 native context controls and 14 native parser controls, full module graph, and exact binary digests from the previously qualified foundation. It pins all Java and Python inputs and verifies unchanged sources after execution. The Java fixture has four child processes, a single retained daemon, at most 96 RC requests and 128 RC connections, bounded frames, and finite output categories. It executes 85 RPC parser, 42 job parser, and 44 held-response state controls per case.

Raw ticket, credential, frame and command output remains private and is removed after owned processes and containers are stopped. Only sanitized reports are uploaded. A failed cleanup prevents success. The original profile and all earlier evidence remain separate.

## Pure checks

Run `python -I -S -B scripts/provider-lab/hdfs-kerberos-context-cancellation/run_guarded_tests.py`. The runner installs a process/network/native-loading audit denial before candidate imports. These synthetic receipt and isolation controls do not execute the native target or establish native success.

The workflow has no manual dispatch, schedule, credentials, provider smoke dispatch, VM changes, or private provider access. Its first hosted qualification is pending.
