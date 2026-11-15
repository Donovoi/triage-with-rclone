# Google Photos saved-token album read protocol

Run inside a disposable Linux VM with Docker:

~~~sh
python -B scripts/provider-lab/gphotos-fixed-api/run_container.py --rclone /absolute/path/to/verified/rclone --protocol-evidence --report /absolute/new/path/gphotos-read-protocol.json
~~~

Pinned rclone 1.76.0 uses a saved OAuth bearer with future expiry, an explicit
synthetic client ID, read_only=true and read_size=true. Its selected remote is
album/Synthetic. The normal photoslibrary.googleapis.com and
lh3.googleusercontent.com authorities resolve only to private 127.0.0.1:443
and 127.0.0.2:443 respectively. Each has its own single-name certificate,
exact SNI/Host/address binding and private CA.

GET /v1/albums requires pageSize=50 and returns a complete album inventory
with string media counts and empty nextPageToken. Root and nested albums have
distinct IDs and path-like titles. POST /v1/mediaItems:search requires a
previously observed album ID, numeric pageSize=100, no continuation or filters,
and duplicate-free JSON. Media inventories preserve selected-album scope,
filenames and creation times.

Each media item issues a private content baseUrl with a fresh signature.
Native HEAD obtains the known size and GET downloads the issued URL with the
image suffix =d. Both retain the saved bearer and must use the content
authority. Three literal opaque payloads receive independent SHA-256 checks.
They exercise protocol transport only: no media decoding, image quality,
full-resolution or EXIF preservation claim is made. Native cat and copy must
reject HTTP403 even when its body equals the expected bytes. Wrong-token and
missing-name rejection, source/config preservation and listener cleanup are
mandatory. The direct DELETE guard does not qualify native writes.

Schema-30 gphotos_saved_token_album_read_v1 binds the current 41-file source
closure, pinned runtime/dependencies, native output/timing, nine capabilities
and containment/cleanup. The container has no network, host mounts/ports or
capabilities; it runs as nonroot with a read-only root, private namespaces,
bounded resources and private noexec tmpfs. Private temporary material is
removed; the pinned public base image and shared build cache remain.

Both combined Linux and provider-smoke gates require 51 reviewed profiles and
the same-run Google Photos receipt. Fifty-two provider regressions cover wire,
separate authorities, containment and evidence substitution without Docker or
fixed DNS/ports. Raw feasibility evidence cannot qualify this mode.

The current backend limits access to app-created media. This synthetic profile
does not prove an actual app-created upload grant or access to a live library.
OAuth login/refresh, non-app-created library access, shared albums,
date/feature filters, pagination, duplicate filenames, videos, native writes,
media fidelity and application/live-provider acceptance remain unverified.
Independent renewal and session-review obligations remain.

Sources: [pinned backend](https://github.com/rclone/rclone/blob/v1.76.0/backend/googlephotos/googlephotos.go),
[virtual album layout](https://github.com/rclone/rclone/blob/v1.76.0/backend/googlephotos/pattern.go)
and [wire types](https://github.com/rclone/rclone/blob/v1.76.0/backend/googlephotos/api/types.go).
