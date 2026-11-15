# Premiumize saved OAuth-token read protocol

Run inside a disposable Linux VM with Docker:

~~~sh
python -B scripts/provider-lab/premiumizeme-fixed-api/run_container.py \
  --rclone /absolute/path/to/verified/rclone --protocol-evidence \
  --report /absolute/new/path/premiumizeme-read-protocol.json
~~~

The pinned rclone 1.75.2 backend uses https://www.premiumize.me/api.
A fresh network-none container maps only that authority to loopback. Exact
SNI/Host checks, a fresh private CA and port 443 contain synthetic token requests.
The native path loads an unexpired saved OAuth Bearer token; no grant or refresh
endpoint is supplied. API-key queries are rejected so the alternate key path
cannot accidentally satisfy this test.

The independent API supplies complete root/nested folder inventories, string
file/folder IDs, integer timestamps, sizes, MIME types and private absolute
content links. Exact-name lookup occurs in the native client. No invented
missing-name endpoint or missing-request counter supplies evidence. Three
literal payloads have independent SHA-256 download oracles. Wrong tokens,
unissued links, malformed queries/routes/headers/framing, metadata ranges,
invalid content ranges and expired connections fail closed. Denied downloads
leave no accepted destination. A direct authenticated fixture DELETE guard
preserves the source; native mutation support is outside scope.

The supervisor enforces nonroot identity, read-only root, no capabilities or host
mounts/ports, private namespaces, bounded resources and private noexec tmpfs.
Schema-13 premiumizeme_saved_token_read_v1 binds the current 30-file source
closure, pinned runtime/dependencies, exact native output/timing, all nine
capabilities and owned cleanup. Private keys, generated tokens and content
links stay ephemeral. Shared build cache and the pinned public base image remain.
Raw transcripts are never published.

Both combined Linux and provider-smoke gates require 40 reviewed profiles and
the same-run named receipt. Raw feasibility and historical schema-1 rows cannot
qualify the saved-token profile; the 26 portable experiments remain unchanged.
Forty-four wire, TLS, container, workflow and receipt tests run on the unit-test
platforms without Docker or fixed port/DNS requirements.

Only local-protocol coverage is qualified. Application/vendor, credential-renewal
and connection-session requirements are preserved. OAuth authorization/refresh,
API-key mode, token replacement, account queries, native mutations, real CDN
origins and Windows application/live-provider acceptance remain unverified.

Source: [rclone Premiumize v1.75.2](https://github.com/rclone/rclone/tree/v1.75.2/backend/premiumizeme).
