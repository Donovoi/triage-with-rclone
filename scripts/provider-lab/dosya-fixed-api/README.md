# Dosya API-key workspace read protocol

Run inside a disposable Linux VM with Docker:

~~~sh
python -B scripts/provider-lab/dosya-fixed-api/run_container.py --rclone /absolute/path/to/verified/rclone --protocol-evidence --report /absolute/new/path/dosya-read-protocol.json
~~~

Pinned rclone 1.76.0 uses a saved API key and explicit workspace_id. The ordinary
api.dosya.dev authority resolves only to private 127.0.0.1:443. Exact SNI,
a single-name certificate, private CA and route/Host binding preserve TLS
verification. The fixture does not discover or create workspaces.

GET /api/files requires the selected workspace, per_page=500, page=1,
sort=name and dir=asc. Root requests omit folder_id; nested requests use the
known folder identity. Complete file/folder inventories include numeric sizes
and timestamps, nullable parents and SHA-256 content_hash metadata.
Native lsjson hash values and downloaded bytes must match independently known
SHA-256 values. Missing-name rejection uses these complete inventories.

Only a previously listed file can obtain a download link from
/api/files/{id}/download. That request requires the exact X-Dosya-Workspace
hint and API bearer. Its HTTP302 issues a private content URL with a fresh
signature. Content requests must omit both Authorization and the workspace
hint, and must use the issued signature. Both native cat and copy reject
HTTP403 containing the identical expected bytes. Wrong-key rejection,
source/config preservation and listener cleanup are required.
The direct DELETE guard does not qualify native writes.

Schema-28 dosya_api_key_workspace_read_v1 binds the 39-file source closure,
pinned runtime/dependencies, native output/timing, nine capabilities and
containment/cleanup. The container has no network, host mounts/ports or
capabilities; it runs as nonroot with a read-only root, private namespaces,
bounded resources and private noexec tmpfs. Private temporary material is
removed; the pinned public base image and shared build cache remain.

Both combined Linux and provider-smoke gates require 49 reviewed profiles and
the same-run Dosya receipt. Forty-eight wire, authority, containment and
evidence regressions run without Docker or fixed DNS/ports. Raw feasibility
evidence cannot qualify this mode. The 26 portable fixtures remain unchanged.

This qualifies synthetic API-key workspace reads. Workspace discovery,
pagination/throttling, uploads including multipart hash availability, native
writes and application/live-provider acceptance remain unverified. The
existing credential-renewal applicability and independent session-review
obligation remain.

Sources: [pinned backend](https://github.com/rclone/rclone/blob/v1.76.0/backend/dosya/dosya.go),
[pinned API client](https://github.com/rclone/rclone/blob/v1.76.0/backend/dosya/dosya_api.go)
and [wire types](https://github.com/rclone/rclone/blob/v1.76.0/backend/dosya/api/types.go).
