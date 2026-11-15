# Dropbox saved-token folder read protocol

Run inside a disposable Linux VM with Docker:

~~~sh
python -B scripts/provider-lab/dropbox-fixed-api/run_container.py --rclone /absolute/path/to/verified/rclone --protocol-evidence --report /absolute/new/path/dropbox-read-protocol.json
~~~

The pinned rclone 1.75.2 and Dropbox SDK v6.4.0 path uses a saved unexpired OAuth
bearer token and an explicit synthetic-root/ source prefix. API RPCs use
api.dropboxapi.com on 127.0.0.1:443; content downloads use content.dropboxapi.com
on 127.0.0.2:443. Each listener has its own exact SNI, single-name certificate,
private CA and route/Host checks. The native client receives both CA roots.
Only the reviewed content authority selects the second loopback address.

The fixture requires exact typed JSON flags for list_folder/get_metadata,
complete small inventories without continuation, tagged file/folder metadata,
path_lower/path_display, timestamps, integer sizes and downloadable files.
Downloads POST an observed file ID in Dropbox-API-Arg, retain the bearer token,
and return exact metadata in Dropbox-API-Result. Missing paths return typed
HTTP 409 not_found; restricted_content denial follows the pinned nonretryable
native path. Unsupported account roots, trailing-root aliases, scope changes,
credential headers, duplicate JSON, pagination and methods are rejected.

Independent OpenSSL content-hash oracles match native DropboxHash for the three
known payloads, empty input, one byte and either side of the 4 MiB block boundary.
Native downloads are independently checked by SHA-256. Wire ranges are bounded.
The direct DELETE download guard does not qualify native writes. Config/source
preservation and cleanup of both listeners, transports and certificate sets are
mandatory, including failure while starting the second listener.

A fresh network-none Linux container enforces nonroot identity, read-only root,
no capabilities or host mounts/ports, private namespaces, bounded resources and
private noexec tmpfs. Schema-22 dropbox_saved_token_folder_read_v1 binds the current
33-file source closure, pinned runtime/dependencies, native output/timing, nine
capabilities and cleanup. Generated keys are ephemeral; the shared build cache
and pinned public base image remain.

Both combined Linux and provider-smoke gates require 43 reviewed profiles and
the same-run receipt. Raw feasibility/schema-1 rows cannot qualify this mode;
the 26 portable experiments remain unchanged. Fifty Dropbox wire/TLS, container
and receipt regressions run without Docker or fixed DNS/ports. The shared JSON
budget-ordering suite also covers bounded RPC-body consumption before rejection.

Only local-protocol coverage is qualified. Application/vendor renewal obligations
and unresolved session applicability review remain. Grants/refresh, legacy token
migration, account-root discovery, app-folder/full-account/team eligibility,
namespaces/impersonation/shared modes, Paper exports, change polling, pagination,
native writes and application/live-provider acceptance remain unverified.

Sources: [pinned rclone Dropbox](https://github.com/rclone/rclone/tree/v1.75.2/backend/dropbox),
[Dropbox SDK v6.4.0](https://github.com/dropbox/dropbox-sdk-go-unofficial/tree/v6.4.0/v6/dropbox)
and [Dropbox content hash](https://docs.dropboxapi.com/dropbox-api/docs/technical-reference/content-hash).
