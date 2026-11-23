# kDrive saved-token folder read protocol

Run inside a disposable Linux VM with Docker:

~~~sh
python -B scripts/provider-lab/kdrive-fixed-api/run_container.py --rclone /absolute/path/to/verified/rclone --protocol-evidence --report /absolute/new/path/kdrive-read-protocol.json
~~~

Pinned rclone 1.76.0 uses a saved OAuth bearer with future expiry, an explicit
drive_id and numeric root_folder_id. The ordinary api.infomaniak.com authority
resolves only to private 127.0.0.1:443. Exact SNI, a single-name certificate,
private CA and route/Host binding preserve TLS verification.

Version-3 file inventories require limit=1000 and with=path,hash. Recursive
inventories additionally require depth=unlimited and return each descendant
once. Explicit nested-root listings exclude siblings. Complete results contain
an empty cursor, has_more=false, numeric identities/sizes/timestamps and
single-chunk xxh3: metadata. Native lsjson hashes match independently computed
libxxhash values over literal payloads. Downloaded bytes receive independent
SHA-256 checks.

Name lookups require the selected parent and exact with fields. Missing members
return HTTP404/object_not_found. Version-2 downloads require an observed file
identity and the saved bearer. API-version changes, alternate drives, guessed
IDs, ambiguous queries, malformed framing and out-of-bounds ranges are rejected.
Both native cat and copy reject HTTP403 containing identical expected bytes.
Wrong-token rejection, source/config preservation and listener cleanup are
mandatory. The direct DELETE guard does not qualify native writes.

Schema-29 kdrive_saved_token_folder_read_v1 binds the current 40-file source
closure, pinned runtime/dependencies, native output/timing, nine capabilities
and containment/cleanup. The container has no network, host mounts/ports or
capabilities; it runs as nonroot with a read-only root, private namespaces,
bounded resources and private noexec tmpfs. Private temporary material is
removed; the pinned public base image and shared build cache remain.

Both combined Linux and provider-smoke gates require 50 reviewed profiles and
the same-run kDrive receipt. Fifty wire, authority, containment and evidence
regressions run without Docker or fixed DNS/ports. Raw feasibility evidence
cannot qualify this mode. The 26 portable fixtures remain unchanged.

This qualifies synthetic saved-token folder reads. OAuth login/refresh,
account/drive discovery, private/common-folder discovery, pagination/throttling,
nested multipart hash encodings, native writes and application/live-provider
acceptance remain unverified. Independent renewal and session-review
obligations remain.

Sources: [pinned backend](https://github.com/rclone/rclone/blob/v1.76.0/backend/kdrive/kdrive.go)
and [wire types](https://github.com/rclone/rclone/blob/v1.76.0/backend/kdrive/api/types.go).
