# Linkbox saved web-token read protocol

Run inside a disposable Linux VM with Docker:

~~~sh
python -B scripts/provider-lab/linkbox-fixed-api/run_container.py \
  --rclone /absolute/path/to/verified/rclone --protocol-evidence \
  --report /absolute/new/path/linkbox-read-protocol.json
~~~

The pinned rclone 1.75.2 read path uses the saved web_token at
https://www.linkbox.to/api/file/my_file_list/web. The required email/password
fields contain synthetic unused values; the password is obscured by the native
runtime. No login endpoint is supplied and the public API token is not used for
reads. A wrong saved web token receives HTTP 401, without exercising password
login or token refresh.

The independent API validates exact query credentials, folder IDs and fixed
first-page controls. Complete root/nested inventories carry numeric IDs,
parent IDs, item IDs, integer timestamps, sizes, MIME/file types and private
absolute content links. Native exact-name selection happens client-side; there
is no invented missing-name endpoint. Three literal payloads have independent
SHA-256 download oracles.

Native downloads use the separate CDN client. The fixture requires the pinned
browser User-Agent and rejects forwarded Authorization, Cookie or token query
fields on content GETs. Links must first be issued by an authenticated inventory.
This checks the actual HTTP/1 read contract; it does not prove behavior against
real CDN bot protection or independently qualify HTTP/2 behavior. Denied reads
leave no accepted destination. A direct query-authenticated fixture DELETE guard
preserves source data and does not qualify native mutation support.

A fresh network-none container maps only www.linkbox.to to loopback. Exact
SNI/Host checks and a private CA contain synthetic requests. The supervisor
enforces nonroot identity, read-only root, no capabilities or host mounts/ports,
private namespaces, bounded resources and private noexec tmpfs. Schema-15
linkbox_saved_web_token_read_v1 binds the current 28-file source closure,
runtime/dependency pins, exact native output/timing, nine capabilities and
owned cleanup. Generated credentials, keys and URLs remain ephemeral; the
shared build cache and pinned public base image remain.

Both combined Linux and provider-smoke gates require 38 reviewed profiles and
the same-run named receipt. Raw feasibility/schema-1 rows remain ineligible;
the 26 portable experiments remain unchanged. Forty-five wire, TLS, container,
workflow and receipt tests run without Docker or fixed port/DNS requirements
on the unit-test platforms.

Only local-protocol coverage is qualified. Existing application/vendor and
lifecycle obligations remain unchanged. Password login, web-token renewal or
replacement, public API token modes, account queries, full-page pagination,
native mutations, real CDN origins and Windows application/live-provider
acceptance remain unverified.

Source: [rclone Linkbox v1.75.2](https://github.com/rclone/rclone/tree/v1.75.2/backend/linkbox).
