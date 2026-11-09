# Contained HDFS service-ticket cache experiment

This separate fixture tests genuinely issued short-lived service tickets with a still-valid, nonrenewable TGT. It preserves one original cache containing both tickets throughout the controls. The pinned runtime graph and existing RPC, transfer, and cache-expiry fixtures are unchanged.

The workflow runs two explicit cases: renewable and nonrenewable service tickets. Each requires a successful cached-ticket listing before actual service expiry with no KDC exchange, the existing paired NONE-authentication wire rejection, and two successful fresh rclone processes after service expiry. Both post-expiry operations must use new TGS acquisition from the original TGT. The renewable case additionally requires an observed RENEW request presenting the original service ticket, its KDC rejection, and then ordinary TGS acquisition in that order. This qualifies fallback after denied renewal, not successful renewal.

A private TCP relay on loopback port 19008 sees only the rclone child configuration. The issuer and owner clients use the direct KDC on port 19006; the separate NameNode relay uses 19007. The trace records only fixed message, phase, ticket-identity, and outcome categories. It compares issued ticket bytes privately, forwards complete bounded frames unchanged, checks malformed-frame/request controls, and never publishes tickets, keys, identities, addresses, error text, or raw messages.

The independent cache parser binds both records to actual issued keys, ticket bytes, times, flags, and principals. It never creates expiry by editing cache metadata. The setup owner filesystem closes before ticket issuance; a second tracked owner filesystem performs the preservation check. Both remain covered by the shared cleanup deadline.

Bounds remain explicit: five child processes, five private root files, 60 seconds for controls, 128 container PIDs, two GB container memory, network none, four KDC connections per phase, 65,536 bytes per KDC message, and one MB of aggregate KDC traffic. Every socket and thread stays owned and must close; any residual fails qualification. The outer receipt excludes the shared base image and build cache from removal claims.

All application, vendor, provider, renewal, and vulnerability-acceptance flags remain false. This fixture does not qualify successful service-ticket renewal, a retained client's reconnect behavior, cancellation, or private provider admission.
