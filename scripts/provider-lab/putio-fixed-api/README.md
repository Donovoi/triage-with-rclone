# Put.io saved OAuth-token read protocol

Run inside a disposable Linux VM with Docker:

~~~sh
python -B scripts/provider-lab/putio-fixed-api/run_container.py \
  --rclone /absolute/path/to/verified/rclone --protocol-evidence \
  --report /absolute/new/path/putio-read-protocol.json
~~~

The pinned rclone 1.75.2 backend and go-putio SDK use https://api.put.io.
A fresh network-none container maps only that authority to loopback, with exact
SNI/Host checks, a fresh private CA and port 443. The native API uses a saved,
unexpired OAuth Bearer token; no grant, refresh or validation endpoint is supplied.

Root and nested inventories each require a second page, with a freshly issued
cursor and strict JSON continuation. Native completion requires every issued
cursor to be consumed. Metadata uses numeric file/folder IDs, independently
checked CRC32 values, sizes, MIME directory types and SDK-compatible timestamps.
Exact child lookup handles encoded spaces and missing objects.

The API issues private download URLs only for observed files. Native downloads
use the separate base HTTP client: the fixture rejects any Authorization header
on content GETs. Three literal payloads have independent SHA-256 oracles; denied
reads leave no accepted destination. A direct authenticated fixture DELETE guard
preserves source data and does not qualify native mutation support. Wire tests
cover unknown/replayed cursors, wrong-token cursor preservation, unreturned pages,
unissued content links, forwarded Bearer tokens, JSON/framing/authority failures,
bounded ranges, budgets and deterministic TLS request deadlines.

The supervisor enforces nonroot identity, read-only root, no capabilities or host
mounts/ports, private namespaces, bounded resources and private noexec tmpfs.
Schema-14 putio_saved_token_read_v1 binds the current 30-file source closure,
pinned runtime/dependencies, exact native output/timing, all nine capabilities
and owned cleanup. Private keys, generated tokens, cursors and download links
stay ephemeral. Shared build cache and the pinned public base image remain;
raw transcripts are never published.

Both combined Linux and provider-smoke gates require 40 reviewed profiles and
the same-run named receipt. Raw feasibility and historical schema-1 rows cannot
qualify this profile; the 26 portable experiments remain unchanged. Forty-seven
wire, TLS, container, workflow and receipt tests run without Docker or fixed
port/DNS requirements on the unit-test platforms.

Only local-protocol coverage is qualified. Existing application/vendor,
credential-renewal review and connection-session requirements are preserved.
OAuth authorization/refresh, token replacement, account queries, native writes,
real tunnel/CDN origins and Windows application/live-provider acceptance remain
unverified.

Sources: [rclone Put.io v1.75.2](https://github.com/rclone/rclone/tree/v1.75.2/backend/putio)
and [pinned go-putio SDK](https://github.com/putdotio/go-putio/tree/16d982cac2b8cbae19cc4dd129dacee91f8c1447/putio).
