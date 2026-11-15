# Yandex saved OAuth-token read protocol

Run inside a disposable Linux VM with Docker:

~~~sh
python -B scripts/provider-lab/yandex-fixed-api/run_container.py \
  --rclone /absolute/path/to/verified/rclone --protocol-evidence \
  --report /absolute/new/path/yandex-read-protocol.json
~~~

The pinned rclone 1.75.2 path uses cloud-api.yandex.com/v1/disk with
Authorization: OAuth credentials. An unexpired saved token is configured with
token_type OAuth up front, preserving the config instead of invoking its
legacy token-type upgrade. The native constructor requires a nonempty refresh
token; this fixture supplies an unused synthetic value and no refresh endpoint.

Independent metadata and complete small root/nested inventories cover disk:/
paths, file/directory types, RFC3339 timestamps, sizes and literal MD5 oracles.
The native constructor probes a candidate file root with one trailing slash;
that exact metadata form resolves to the same file. The absent-synthetic.txt
stat, root-candidate and directory probes return DiskNotFoundError. Unknown
routes and unreviewed pagination/fields/sort options remain rejected.

Native download URLs are private, fresh random links issued only after file
metadata or inventory observation. The same OAuth client supplies credentials
on content GETs. Three literal payload SHA-256 oracles verify acquisitions;
wrong credentials, missing objects and denied reads cannot produce an accepted
destination. Source/config preservation and all owned cleanup are required.
The direct fixture DELETE guard does not qualify native mutations.

A fresh network-none container maps only cloud-api.yandex.com to loopback.
Exact SNI/Host checks and a private CA contain requests. The supervisor enforces
nonroot identity, a read-only root, no capabilities or host mounts/ports,
private namespaces, bounded resources and private noexec tmpfs. Schema-16
yandex_saved_token_read_v1 binds the current 28-file source closure, pinned
runtime/dependencies, exact native output/timing, nine capabilities and cleanup.
Generated credentials and links remain ephemeral. Shared build cache and the
pinned public base image remain.

Both combined Linux and provider-smoke gates require 38 reviewed profiles and
the same-run receipt. Raw feasibility/schema-1 rows cannot qualify this mode.
The 26 portable experiments remain unchanged. Forty-six wire/TLS, container
and evidence tests run without Docker or fixed DNS/ports on the unit platforms.

Only local-protocol coverage is qualified. Application/vendor and lifecycle
obligations remain unchanged. OAuth grants/refresh, config upgrades, token
replacement, custom modification properties, full-page pagination, native
mutations, real download origins and application/live-provider acceptance
remain unverified.

Source: [rclone Yandex v1.75.2](https://github.com/rclone/rclone/tree/v1.75.2/backend/yandex).
