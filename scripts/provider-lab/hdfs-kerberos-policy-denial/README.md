# Contained HDFS KDC policy-denial experiment

This separate fixture tests revocation of an exclusively owned synthetic reader while its original nonrenewable TGT remains valid. The renewable and nonrenewable service-ticket cases use the same original cache before expiry, during denial, and after restoration. Existing fixtures and runtime pins are unchanged.

Each case requires a cached-ticket positive listing before genuine service-ticket expiry and the paired NONE-authentication wire rejection. After expiry, the probe snapshots the exact in-memory KDC backend and every identity, retaining object identity and binding principal fields, key version, flags, lock state, creation/expiry times, key types, key versions and key bytes. Only the reader's disabled flag may change. Snapshot data and hashes stay private.

With the reader disabled, a fresh rclone process must fail without listing an item. The NameNode relay requires a Kerberos header, and the KDC relay must observe an ordinary request presenting the original TGT followed by KDC_ERR_CLIENT_REVOKED (18). Stderr is not the authentication oracle. In the renewable case, the preceding service-ticket renewal request and its separate denial remain visible in the finite trace.

After the owned child and relay exchanges end, the probe restores only the same retained reader, verifies all original identity state, and runs a fresh positive listing with the unchanged cache. Ordinary acquisition must produce a fresh service ticket. The renewable case separately records denied renewal followed by ordinary acquisition. Successful renewal is not claimed.

Cleanup repeats the identity restoration check before stopping the KDC. Failed or uncertain restoration cannot qualify or permit private-material deletion. Owned service shutdown still runs on failure. The original source, cache, process, socket, listener and zero-residual-thread gates remain required.

An unfinished relay phase blocks policy mutation while the relay is live. After failure, restoration may proceed only when its active count is zero, every exchange worker has ended, shutdown was requested, the listener and all sockets are closed, and every relay thread has ended. The last phase remains unchanged for diagnostics. A required native self-check covers normal between-phase operation, all four stopped phase values, incomplete shutdown, live workers, nonzero counts and invalid phases.

The private KDC relay on port 19008 forwards bounded frames unchanged; the issuer and owner use port 19006 and the NameNode relay uses 19007. Reports contain only fixed categories, counts and booleans. No raw identities, keys, tickets, messages or error text are published.

Bounds: five child processes, five private root files, 60 seconds for controls, at most eight identities and 65,536 total snapshot bytes, four KDC connections per phase, 65,536 bytes per KDC message, one MB aggregate KDC traffic, 128 container PIDs and two GB memory. The container has no network. Shared base-image and build-cache removal are excluded from cleanup claims.

Provider, application, vendor, successful-renewal and vulnerability acceptance remain false. This fixture does not qualify retained-client cancellation or private-provider admission.
