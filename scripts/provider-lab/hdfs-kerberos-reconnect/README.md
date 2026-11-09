# Contained HDFS retained-client reconnect experiment

This separate hosted fixture keeps one pinned rclone daemon alive through real service-ticket expiry and an explicitly owned NameNode connection loss. The existing service-cache and transfer fixtures remain unchanged. Both renewable and nonrenewable service tickets are tested beside a genuinely issued, still-valid TGT.

The initial RC listing creates exactly one cached HDFS backend. The fixture then removes read permission from its private synthetic CCache and requires a fresh rclone process to fail to read it. The retained daemon must still list successfully after the actual service ticket expires, on its original authenticated connection with no KDC exchange. This read barrier distinguishes retained state from reconstructing a backend from the cache file.

The fixture arms its KDC observation before closing only the owned initial NameNode relay connection. It records at most three listing outcomes, with a six-second wait after a failure to cover the pinned five-second NameNode backoff. Recovery requires a new Kerberos header and an ordinary TGS acquisition using the originally issued TGT. The renewable case additionally requires renewal denial before fallback. A final listing must reuse the recovered session without another KDC exchange.

The pinned HDFS client also sends background lease-renewal calls every second. These may trigger reconnection. The receipt distinguishes a successful first observed listing from success after a failed listing; it never claims transparent recovery within a particular call. Successful service-ticket renewal and cancellation are separate scopes.

RC uses a private authenticated loopback listener on port 19009, bounded HTTP and strict JSON parsing, and no published port. Requests, responses and synthetic credentials remain private. The native parser self-check covers JSON shape, duplicate/trailing tokens and finite error categories. Receipt fields contain only closed categories, booleans and bounded counts.

Bounds: four child processes, one retained daemon, five private root files, 16 RC requests and 48 connection attempts, 8192-byte request/header bounds, 16384-byte response/stream bounds, 60 seconds for controls, two GB container memory, 128 container PIDs, network none, and the existing bounded NameNode/KDC relays. Every process, stream, socket and thread is retained for cleanup.

Cleanup first reaps the daemon and control sockets, restores the original cache permissions under inode/owner checks, then applies the existing service shutdown and private-material deletion gates. Full cache bytes, source contents and source metadata are rechecked after restoration. The shared base image and build cache remain excluded from removal claims.

No provider, application, vendor, vulnerability, cancellation or successful-renewal acceptance is granted. Native qualification requires both complete case receipts and independent artifact/source verification.

The concurrent daemon and fresh-cache negative child can add a JDK process-reaper worker. Its pinned cached-pool idle lifetime is 60 seconds, so cleanup permits up to 65 seconds of passive waiting after the original three-second owned-helper shutdown budget. Every residual thread still fails cleanup and prevents private-material deletion. No JDK worker is interrupted, reclassified as exempt, or added to the baseline.

The unauthenticated RC check sends an empty request body and still requires a complete bounded 401 response and EOF. RC IO failures expose only a finite transport stage, never raw messages.
