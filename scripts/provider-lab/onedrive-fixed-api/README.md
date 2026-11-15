# OneDrive business-drive saved OAuth read protocol

Run inside a disposable Linux VM with Docker:

~~~sh
python -B scripts/provider-lab/onedrive-fixed-api/run_container.py --rclone /absolute/path/to/verified/rclone --protocol-evidence --report /absolute/new/path/onedrive-read-protocol.json
~~~

The pinned rclone 1.75.2 path uses saved unexpired OAuth Bearer credentials for
a configured synthetic business drive at graph.microsoft.com. Root discovery,
normalized drive/item IDs, colon path metadata, complete small inventories with
$top=1000, file/folder facets, timestamps and sizes have independent wire oracles.
The native nested-directory candidate probe returns itemNotFound for the absent
nested/nested child; it cannot alias the existing parent folder.

Default QuickXorHash values remain enabled. Three literal base64 metadata
oracles were calculated independently using Microsoft's bit-level algorithm,
checked against 70 pinned reference vectors and cross-checked with native
hashsum. Separate payload SHA-256 oracles verify the three native downloads.

Authenticated Graph content requests return a private 302 link only for an
observed file. The redirected client must omit Authorization, Cookie and Prefer;
query credentials and malware overrides are rejected. Issued-link downloads
enforce range bounds. Wrong credentials, missing objects and denied content
cannot create an accepted destination. The direct issued-link DELETE guard
does not qualify native mutations. Source/config preservation and owned
cleanup are mandatory.

A fresh network-none Linux container maps only graph.microsoft.com to loopback.
Exact SNI/Host checks and a private CA contain requests. Nonroot identity,
read-only root, no capabilities or host mounts/ports, private namespaces,
bounded resources and private noexec tmpfs are enforced.
Schema-18 onedrive_saved_token_read_v1 binds the current 30-file source closure,
pinned runtime/dependencies, native output/timing, nine capabilities and cleanup.
Generated credentials are ephemeral; the shared build cache and pinned public
base image remain.

Both combined Linux and provider-smoke gates require 40 reviewed profiles and
the same-run receipt. Raw feasibility/schema-1 rows cannot qualify this mode;
the 26 portable experiments remain unchanged. Forty-eight OneDrive wire/TLS,
container and receipt tests run without Docker or fixed DNS/ports.

Only local-protocol coverage is qualified. Existing application/vendor and
lifecycle obligations remain unchanged. Personal/shared drive variants,
grant/refresh and token replacement, tenant_url/sovereign regions, malware
overrides and OneNote, case-folding/name encoding, continuation/delta,
native writes, real CDN and application/live-provider acceptance remain
unverified.

Sources: [pinned rclone OneDrive](https://github.com/rclone/rclone/tree/v1.75.2/backend/onedrive)
and [Microsoft QuickXorHash algorithm](https://learn.microsoft.com/en-us/onedrive/developer/code-snippets/quickxorhash?view=odsp-graph-online).
