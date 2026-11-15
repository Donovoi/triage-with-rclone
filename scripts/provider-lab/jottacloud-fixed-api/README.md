# Jottacloud saved-token Archive read protocol

Run inside a disposable Linux VM with Docker:

~~~sh
python -B scripts/provider-lab/jottacloud-fixed-api/run_container.py --rclone /absolute/path/to/verified/rclone --protocol-evidence --report /absolute/new/path/jottacloud-read-protocol.json
~~~

Pinned rclone 1.75.2 uses configVersion=1, a saved unexpired Bearer token,
default Jotta/Archive and Synthetic:synthetic-root/. No endpoint override or
real account is used. The customer API stays at api.jottacloud.com on
127.0.0.1:443; the file API stays at jfs.jottacloud.com on 127.0.0.2:443.
Each listener has its own private CA, exact SNI, single-name certificate and
route/Host binding. The native client receives both CA roots.

GET /account/v1/customer returns only the synthetic internal username.
The exact /jfs/synthetic-user/Jotta/Archive/synthetic-root scope supports
directory XML, currentRevision object XML, mode=liststream recursive XML with
checked folder/file counts, and observed-path mode=bin content. Classic
timestamps include the Jottacloud -T separator; stream timestamps use RFC3339.
Known MD5 values have independent OpenSSL oracles in the wire tests. The native
probe checks both ordinary and recursive streaming listings and validates
downloaded bytes independently using SHA-256.

Wrong saved tokens fail. Missing paths return XML HTTP404. The HTTP403 content
response contains the exact expected file bytes, so matching length and hashes
cannot conceal a missing HTTP status check. Native rejection must leave no
accepted output. A direct DELETE guard is tested separately; it does not
qualify native writes. Configuration, served files and metadata must remain
unchanged, and both listeners must close even if startup fails partway.

A fresh network-none Linux container enforces nonroot identity, read-only root,
no capabilities or host mounts/ports, private namespaces, bounded resources and
private noexec tmpfs. Schema-25 jottacloud_saved_token_folder_read_v1 binds the
current 36-file source closure, pinned runtime/dependencies, native
output/timing, nine read capabilities and cleanup. Ephemeral private material
is removed; the shared build cache and pinned public base image remain.

Both combined Linux and provider-smoke gates require 46 reviewed profiles with
the same-run receipt. Raw feasibility/schema-1 evidence cannot qualify this
mode. Fifty wire/authority/cleanup, container and evidence regressions run
without Docker or fixed DNS/ports. The 26 portable fixtures remain unchanged.

This qualifies synthetic saved-token Archive reads. Initial grant, refresh,
legacy authentication, custom brand/device/mountpoint discovery, trash,
pagination/throttling, native writes and application/live-provider acceptance
remain unverified. Existing renewal and session-review obligations remain.
The background token-renewal helper is not exercised by these unexpired-token
reads.

Sources: [pinned rclone Jottacloud backend](https://github.com/rclone/rclone/tree/v1.75.2/backend/jottacloud),
[pinned REST client](https://github.com/rclone/rclone/blob/v1.75.2/lib/rest/rest.go)
and [token-renewal helper](https://github.com/rclone/rclone/blob/v1.75.2/lib/oauthutil/renew.go).
