# Zoho saved-token folder read protocol

Run inside a disposable Linux VM with Docker:

~~~sh
python -B scripts/provider-lab/zoho-fixed-api/run_container.py --rclone /absolute/path/to/verified/rclone --protocol-evidence --report /absolute/new/path/zoho-read-protocol.json
~~~

The pinned rclone 1.75.2 uses a saved unexpired Zoho-oauthtoken, explicit
root_folder_id and region eu. Metadata requests go to workdrive.zoho.eu on
127.0.0.1:443; downloads go to download.zoho.eu on 127.0.0.2:443. Each listener
has an exact SNI, a single-name certificate, its own private CA and route/Host
binding. The native client receives both CA roots. Only reviewed content
authorities select the second private loopback address.

GET /api/v1/files/{folder-ID}/files requires Accept application/vnd.api+json,
page[limit]=1000 and page[next]=0. Complete root and nested inventories carry
typed attributes, sizes, millisecond timestamps and links.cursor.has_next=false.
No continuation, foreign folder, metadata/discovery endpoint or broadened root
is accepted. Native missing-name rejection uses the complete inventories;
the fixture does not fabricate an absent object or an invented missing API call.

GET /v1/workdrive/download/{file-ID} requires an observed identity and retained
Zoho-oauthtoken. Known bytes and bounded ranges are checked; native downloads
have independent SHA-256 checks. The backend advertises no remote hashes.
The 403 denial body has the advertised object length, so a size mismatch cannot
mask failure to check HTTP status. Wrong-token rejection, source/config
preservation and cleanup of both listeners are mandatory, including second
listener startup failure. A direct DELETE download guard does not qualify
native writes.

A fresh network-none Linux container enforces nonroot identity, read-only root,
no capabilities or host mounts/ports, private namespaces, bounded resources and
private noexec tmpfs. Schema-24 zoho_saved_token_folder_read_v1 binds the current
35-file source closure, pinned runtime/dependencies, native output/timing, nine
read capabilities and cleanup. Ephemeral private material is removed; the
shared build cache and pinned public base image remain.

Both combined Linux and provider-smoke gates require 45 reviewed profiles with
the same-run receipt. Raw feasibility/schema-1 evidence cannot qualify this
mode. Fifty wire/authority/cleanup, container and evidence regressions run
without Docker or fixed DNS/ports. The 26 portable fixtures remain unchanged.

Only synthetic saved-token folder reads are qualified. Existing application,
vendor, renewal and session-review obligations remain. OAuth login/refresh,
account/private-space/team discovery, entitlement/editions, other regions,
pagination, throttling/session reauthentication, native writes and
application/live-provider acceptance remain unverified.

Sources: [pinned rclone Zoho backend](https://github.com/rclone/rclone/tree/v1.75.2/backend/zoho)
and [pinned REST client](https://github.com/rclone/rclone/blob/v1.75.2/lib/rest/rest.go).
