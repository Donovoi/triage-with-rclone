# Mail.ru saved-token M1 folder read protocol

Run inside a disposable Linux VM with Docker:

~~~sh
python -B scripts/provider-lab/mailru-fixed-api/run_container.py --rclone /absolute/path/to/verified/rclone --protocol-evidence --report /absolute/new/path/mailru-read-protocol.json
~~~

Pinned rclone 1.76.0 uses a saved OAuth token with future expiry and a saved
refresh token, without a password. The token uses native compact JSON and
second-resolution UTC expiry so the backend preserves the config byte for byte.
Initial authentication, token refresh and password reauthorization are excluded.

The normal cloud.mail.ru and dispatcher.cloud.mail.ru authorities resolve only
to private 127.0.0.1:443 and 127.0.0.2:443. The dispatcher issues a private URL
under synthetic-content.mailru.invalid at 127.0.0.3:443 with a fresh prefix.
All three authorities have distinct certificates, exact SNI/Host/address
bindings and private CAs. No live account or vendor endpoint is contacted.

POST /api/m1/folder uses query access_token, offset=0, limit=2147483647 and an
exact form-encoded home. Complete inventories retain root/nested scope, numeric
sizes, timestamps, folder counts and independent Mailru hashes. GET /api/m1/file
accepts the two source-defined metadata paths: the trimmed NewFs root and the
absolute NewObject path. It returns explicit HTTP404 for missing names.

The public GET /d dispatcher accepts no token or extra query. Content requires
its issued prefix, an observed file, exact encoded path, client_id=cloud-win and
a query token. Authorization and Cookie headers are rejected on every authority.
Three native downloads receive independent SHA-256 checks; native metadata
hashes must match literal Mailru vectors. Both native cat and copy reject
HTTP403 containing the expected bytes. Wrong-token and missing-name rejection,
source/config preservation and cleanup are mandatory. The direct DELETE guard
does not qualify native writes.

Schema-32 mailru_saved_token_folder_read_v1 binds the current 43-file source
closure, pinned runtime/dependencies, native output/timing, nine capabilities,
containment and cleanup. The container has no network, host mounts/ports or
capabilities. It runs as nonroot with a read-only root, private namespaces,
bounded resources and private noexec tmpfs. Owned temporary material is removed;
the pinned public base image and shared build cache remain.

Both combined Linux and provider-smoke gates require 53 reviewed profiles and
the same-run Mail.ru receipt. Fifty-one provider regressions cover wire,
three distinct authorities, containment and evidence substitution without Docker
or fixed DNS/ports. Raw feasibility evidence cannot qualify this mode.

Initial login, refresh, password reauthorization, binary listing, dispatcher
failover, throttling, uploads, native writes and application/live-provider
acceptance remain unverified. Independent renewal/session-review obligations
remain.

Sources: [pinned backend](https://github.com/rclone/rclone/blob/v1.76.0/backend/mailru/mailru.go),
[M1 wire types](https://github.com/rclone/rclone/blob/v1.76.0/backend/mailru/api/m1.go)
and [Mailru hash](https://github.com/rclone/rclone/blob/v1.76.0/backend/mailru/mrhash/mrhash.go).
