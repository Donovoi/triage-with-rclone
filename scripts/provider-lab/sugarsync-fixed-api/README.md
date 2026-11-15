# SugarSync saved-authorization folder read protocol

Run inside a disposable Linux VM with Docker:

~~~sh
python -B scripts/provider-lab/sugarsync-fixed-api/run_container.py --rclone /absolute/path/to/verified/rclone --protocol-evidence --report /absolute/new/path/sugarsync-read-protocol.json
~~~

Pinned rclone 1.75.2 uses a saved authorization URI, future authorization_expiry,
cached user URI and explicit root_id folder URI. The latter is the supported
backend setting at the ordinary api.sugarsync.com authority. The profile avoids
account-wide /user discovery and initial app authorization. An unused synthetic
refresh URI is present, but renewal is not exercised.

The API authority resolves only to private 127.0.0.1:443. An exact SNI,
single-name certificate, private CA, route/Host binding and native CA setting
preserve TLS verification. Authorization is the exact saved URI with no Bearer
prefix. GET /folder/{known-ID}/contents requires max=500 and start=0.
Complete collectionContents XML includes start/end/hasMore, displayName, ref,
sizes, timestamps and fileData links. Native missing-name rejection uses these
complete inventories; no missing object is fabricated.

GET /file/{observed-ID}/data requires an identity previously returned in a
listing. Known payloads and bounded ranges are checked. Native downloads have
independent SHA-256 validation; the backend advertises no remote hashes.
HTTP403 deliberately contains the identical expected object bytes, so native
rejection cannot be attributed to size or hash mismatch. Wrong-authorization
rejection, source/config preservation and listener cleanup are mandatory.
The direct DELETE guard does not qualify native writes.

A fresh network-none Linux container enforces nonroot identity, read-only root,
no capabilities or host mounts/ports, private namespaces, bounded resources and
private noexec tmpfs. Schema-26 sugarsync_saved_authorization_folder_read_v1
binds the current 37-file source closure, pinned runtime/dependencies, native
output/timing, nine read capabilities and cleanup. Ephemeral private material
is removed; the shared build cache and pinned public base image remain.

Both combined Linux and provider-smoke gates require 47 reviewed profiles with
the same-run receipt. Raw feasibility/schema-1 evidence cannot qualify this
mode. Forty-eight wire/authority, container and evidence regressions run
without Docker or fixed DNS/ports. The 26 portable fixtures remain unchanged.

This qualifies synthetic saved-authorization folder reads. Initial password/app
authorization, renewal, account-wide discovery, continuation/throttling, native
writes and application/live-provider acceptance remain unverified. Existing
renewal and session-review obligations remain.

Sources: [pinned rclone SugarSync backend](https://github.com/rclone/rclone/tree/v1.75.2/backend/sugarsync)
and [pinned REST client](https://github.com/rclone/rclone/blob/v1.75.2/lib/rest/rest.go).
