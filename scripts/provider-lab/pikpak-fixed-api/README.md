# PikPak saved-token folder read protocol

Run inside a disposable Linux VM with Docker:

~~~sh
python -B scripts/provider-lab/pikpak-fixed-api/run_container.py --rclone /absolute/path/to/verified/rclone --protocol-evidence --report /absolute/new/path/pikpak-read-protocol.json
~~~

Pinned rclone 1.76.0 uses a saved OAuth bearer, an unexpired saved captcha token,
a fixed device identity and an explicit root_folder_id. The ordinary
api-drive.mypikpak.com authority resolves only to private 127.0.0.1:443. An exact
SNI, single-name certificate, private CA and route/Host binding preserve TLS
verification. An unused synthetic refresh token is present; renewal is not
exercised. No password login or captcha-solving service is involved.

GET /drive/v1/files requires exact parent, kind, complete-phase and non-trashed
filters, the expected page size and an empty continuation token. Complete
inventories include folder/file kinds, IDs, parent IDs, string sizes,
timestamps and MD5 metadata. Missing-name rejection uses those inventories.
File metadata must refer to a previously listed identity; only an issued
application/octet-stream link can supply bytes. Download requests retain the
OAuth bearer but omit API-only client/device/captcha headers.

Three native downloads receive independent SHA-256 checks. Native cat and
copy must both reject HTTP403 even when the response contains the identical
expected object bytes and MD5. This control reproduced acceptance by rclone
1.75.2; the upstream HTTP-status fix in 1.76.0 makes both commands reject it.
Wrong-bearer rejection, source/config preservation and listener cleanup are
mandatory. The direct DELETE guard does not qualify native writes.

A fresh network-none Linux container enforces nonroot identity, a read-only
root, no capabilities or host mounts/ports, private namespaces, bounded
resources and private noexec tmpfs. Schema-27 pikpak_saved_token_folder_read_v1
binds the current 38-file source closure, pinned runtime/dependencies, native
output/timing, nine read capabilities and cleanup. Ephemeral private material
is removed; the shared build cache and pinned public base image remain.

Both combined Linux and provider-smoke gates require 48 reviewed profiles with
the same-run receipt. Raw feasibility/schema-1 evidence cannot qualify this
mode. Wire, authority, containment and evidence mutation tests run without
Docker or fixed DNS/ports. The 26 portable fixtures remain unchanged.

This qualifies synthetic saved-token folder reads. Initial login, captcha
solving, OAuth/captcha renewal, account-wide discovery, continuation/throttling,
native writes and application/live-provider acceptance remain unverified.
Existing renewal and session-review obligations remain.

Sources: [pinned PikPak backend](https://github.com/rclone/rclone/tree/v1.76.0/backend/pikpak)
and [upstream HTTP-status fix](https://github.com/rclone/rclone/commit/c9f491800b7d424be89976b2a45493ce56825094).
