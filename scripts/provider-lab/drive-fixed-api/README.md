# Google Drive saved-token folder read protocol

Run inside a disposable Linux VM with Docker:

~~~sh
python -B scripts/provider-lab/drive-fixed-api/run_container.py --rclone /absolute/path/to/verified/rclone --protocol-evidence --report /absolute/new/path/drive-read-protocol.json
~~~

The pinned rclone 1.75.2 and Google API client v0.293.0 path uses a saved unexpired
OAuth bearer token and an explicitly configured synthetic root_folder_id.
Only www.googleapis.com is mapped to private loopback TLS. No browser grant,
token renewal, service account or account-root lookup is performed.

The fixture admits the exact native Files.List fields, page size, flags and
finite folder/name/type predicates. Trash, parent and item-type restrictions
cannot be dropped or widened. Both small inventories are complete first pages
without continuation or incomplete search. Missing-name queries return empty
complete selections; directories are never fabricated as files.

Blob metadata includes string-encoded sizes, parent identity, timestamps and
three independent OpenSSL MD5/SHA1/SHA256 oracles. Three known-byte downloads
verify native acquisition. Media reads require prior identity observation and
the saved bearer token; wrong tokens, denied reads and bounded ranges have
dedicated wire tests. The direct DELETE media guard preserves sources without
qualifying native writes. Config/source preservation and cleanup are mandatory.

A fresh network-none Linux container enforces nonroot identity, read-only root,
no capabilities or host mounts/ports, private namespaces, bounded resources and
private noexec tmpfs. Schema-21 drive_saved_token_folder_read_v1 binds the current
32-file source closure, pinned runtime/dependencies, native output/timing, nine
capabilities and cleanup. Generated keys are ephemeral; the shared build cache
and pinned public base image remain.

Both combined Linux and provider-smoke gates require 42 reviewed profiles and
the same-run receipt. Raw feasibility/schema-1 rows cannot qualify this mode;
the 26 portable experiments remain unchanged. Forty-seven Google Drive wire/TLS,
container and receipt tests run without Docker or fixed DNS/ports.

Only local-protocol coverage is qualified. Existing application/vendor renewal
requirements and unresolved session applicability review remain. OAuth grants
and refresh, service accounts, account-root discovery, shared drives, Docs
exports/imports, shortcuts, resource keys, change polling, pagination, native
writes and application/live-provider acceptance remain unverified.

Sources: [pinned rclone Drive](https://github.com/rclone/rclone/tree/v1.75.2/backend/drive)
and [Google API client v0.293.0](https://github.com/googleapis/google-api-go-client/blob/v0.293.0/drive/v3/drive-gen.go).
