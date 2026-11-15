# FileLu configured-key scoped read protocol

Run inside a disposable Linux VM with Docker:

~~~sh
python -B scripts/provider-lab/filelu-fixed-api/run_container.py --rclone /absolute/path/to/verified/rclone --protocol-evidence --report /absolute/new/path/filelu-read-protocol.json
~~~

The pinned rclone 1.75.2 path uses a configured Rclone key at filelu.com/rclone
and an explicit synthetic-root/ source prefix. Folder inventories expose only
the approved root and its nested child. Exact-name selection obtains the file
code, followed by info2 metadata and a private direct link. Wire oracles cover
numeric inventory sizes, string info2 sizes, file_code versus filecode spelling,
folder identities, names and independent MD5 metadata values. The native backend
advertises an empty supported-hash set; this default remains unchanged.
Independent SHA-256 values verify three downloaded payloads.

The configured root is deliberate: the pinned constructor recognizes candidate
files only when the root has both a container and path. Account-root file
behavior is not qualified. Known file and absent-directory probes return the
documented Folder not found response; they cannot become fabricated folders.
The final inventory check uses the same explicit root.

API requests require the exact key query and reject Authorization/Cookie headers.
Observed file identities must precede metadata and direct links. Private content
GETs omit the key and reject query credentials or forwarded headers. Native
content requests require HTTP200 and apply offset/count locally; separate
fixture range tests do not establish native HTTP Range transmission.
Wrong keys, missing objects and denied reads cannot create an accepted
destination. A direct private-link DELETE guard preserves sources without
qualifying native writes. Source/config preservation and owned cleanup are
mandatory.

A fresh network-none Linux container maps only filelu.com to loopback. Exact
SNI/Host and a private CA contain requests. Nonroot identity, read-only root,
no capabilities or host mounts/ports, private namespaces, bounded resources
and private noexec tmpfs are enforced. Schema-19
filelu_configured_key_root_read_v1 binds the current 30-file source closure,
pinned runtime/dependencies, native output/timing, nine capabilities and cleanup.
Generated keys are ephemeral; the shared build cache and pinned public base
image remain.

Both combined Linux and provider-smoke gates require 40 reviewed profiles and
the same-run receipt. Raw feasibility/schema-1 rows cannot qualify this mode;
the 26 portable experiments remain unchanged. Forty-seven FileLu wire/TLS,
container and receipt tests run without Docker or fixed DNS/ports.

Only local-protocol coverage is qualified. Existing static-credential
application/vendor obligations and their applicability settings remain
unchanged. Account-root file behavior, login/account and paid-tier eligibility,
key rotation, pagination, case-folding/name encoding, native HTTP Range,
native mutations, real CDN and application/live-provider acceptance remain
unverified.

Source: [pinned rclone FileLu](https://github.com/rclone/rclone/tree/v1.75.2/backend/filelu).
