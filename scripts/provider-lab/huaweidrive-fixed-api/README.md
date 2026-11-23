# Huawei Drive saved-token folder read protocol

Run inside a disposable Linux VM with Docker:

~~~sh
python -B scripts/provider-lab/huaweidrive-fixed-api/run_container.py --rclone /absolute/path/to/verified/rclone --protocol-evidence --report /absolute/new/path/huaweidrive-read-protocol.json
~~~

Pinned rclone 1.76.0 uses a saved OAuth bearer with future expiry and an explicit
synthetic root_folder_id. The normal driveapis.cloud.huawei.com.cn authority
resolves only to private 127.0.0.1:443, with a single-name certificate and exact
SNI/Host/address binding.

GET /drive/v1/about?fields=domain returns the global authority. Folder listing
uses GET /drive/v1/files with fields=*, containers=drive, pageSize=1000 and the
exact selected-parent queryParam. Root and nested inventories remain distinct.
Metadata includes numeric sizes, independent SHA-256 hashes, timestamps,
parent arrays, folder MIME type and unrecycled state. Complete inventories
have empty nextPageToken.

GET /drive/v1/files/{observed-id}?form=content requires the saved bearer and
exact query. Three payloads receive independent SHA-256 checks. Native cat
and copy must reject HTTP403 even when its body equals the expected bytes.
Wrong-token and missing-name rejection, source/config preservation and
listener cleanup are mandatory. The direct DELETE guard does not qualify
native writes.

Schema-31 huaweidrive_saved_token_folder_read_v1 binds the current 42-file
source closure, pinned runtime/dependencies, native output/timing, nine
capabilities and containment/cleanup. The container has no network, host
mounts/ports or capabilities; it runs as nonroot with a read-only root,
private namespaces, bounded resources and private noexec tmpfs. Private
temporary material is removed; the pinned public base image and shared build
cache remain.

Both combined Linux and provider-smoke gates require 52 reviewed profiles and
the same-run Huawei Drive receipt. Forty-eight provider regressions cover
wire, containment and evidence substitution without Docker or fixed DNS/ports.
Raw feasibility evidence cannot qualify this mode.

OAuth login/refresh, root autodiscovery, regional authority switching,
pagination, throttling, native empty-object handling, uploads, native writes
and application/live-provider acceptance remain unverified. Independent
renewal and session-review obligations remain.

Sources: [pinned backend](https://github.com/rclone/rclone/blob/v1.76.0/backend/huaweidrive/huaweidrive.go)
and [wire types](https://github.com/rclone/rclone/blob/v1.76.0/backend/huaweidrive/api/types.go).
