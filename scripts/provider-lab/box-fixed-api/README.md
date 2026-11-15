# Box saved OAuth-token read protocol

Run inside a disposable Linux VM with Docker:

~~~sh
python -B scripts/provider-lab/box-fixed-api/run_container.py \
  --rclone /absolute/path/to/verified/rclone --protocol-evidence \
  --report /absolute/new/path/box-read-protocol.json
~~~

The pinned rclone 1.75.2 path uses saved unexpired OAuth Bearer credentials at
api.box.com/2.0. The fixture provides complete small active-item inventories
with exact requested fields, limit=1000 and usemarker=true; no continuation
marker is returned. IDs, SHA1 values, timestamps, sizes and names have independent
wire oracles. Three literal payload SHA-256 oracles verify native downloads.

Read-side object lookup uses OPTIONS /2.0/files/content/ with JSON name and
parent.id. The pinned native reader omits size. Existing files return the exact
409 item_name_in_use conflict object needed to discover their IDs, followed by
GET metadata. The absent-synthetic.txt probe returns a successful no-conflict
response; its synthetic upload fields are unused and no upload is performed.
Malformed/duplicate JSON, upload sizes, wrong parents, alternate fields,
pagination and impersonation are rejected. Admitted JSON is consumed within
the existing size/deadline bounds before a request-budget 429 is sent.

Metadata/content requires a previously observed known identity and Bearer
credentials. Wrong credentials, missing objects and denied reads cannot create
an accepted destination. The direct fixture DELETE guard preserves source data
and does not qualify native mutations. Configuration and source preservation,
bounded TLS deadlines and all owned cleanup are mandatory.

A fresh network-none container maps only api.box.com to loopback. Exact
SNI/Host checks and a private CA contain requests. Nonroot identity, read-only
root, no capabilities or host mounts/ports, private namespaces, bounded
resources and private noexec tmpfs are enforced. Schema-17 box_saved_token_read_v1
binds the current 31-file source closure, pinned runtime/dependencies, exact
native output/timing, nine capabilities and cleanup. Generated credentials are
ephemeral; the shared build cache and pinned public base image remain.

Both combined Linux and provider-smoke gates require 41 reviewed profiles and
the same-run receipt. Raw feasibility/schema-1 rows cannot qualify this mode;
the 26 portable experiments remain unchanged. Forty-six Box wire/TLS, container
and receipt tests run without Docker or fixed DNS/ports. The shared JSON budget
suite also covers Box OPTIONS, including rejection ordering and partial bodies.

Only local-protocol coverage is qualified. Existing application/vendor and
lifecycle obligations remain unchanged. OAuth grants/refresh, token replacement,
primary access-token mode, JWT, impersonation/owned filters, case-folding/name
encoding, marker continuation, native mutations, real content redirects and
application/live-provider acceptance remain unverified.

Source: [rclone Box v1.75.2](https://github.com/rclone/rclone/tree/v1.75.2/backend/box).
