# Uloz.to password-session folder read protocol

Run inside a disposable Linux VM with Docker:

~~~sh
python -B scripts/provider-lab/ulozto-fixed-api/run_container.py --rclone /absolute/path/to/verified/rclone --protocol-evidence --report /absolute/new/path/ulozto-read-protocol.json
~~~

Pinned rclone 1.76.0 sends an application token and synthetic account password
to PUT /v6/session, then uses the returned fresh session token. The root folder
is explicitly configured. This tests initial synthetic login; it does not
qualify real account eligibility, expired-session reauthentication or renewal.

The normal apis.uloz.to authority resolves only to private 127.0.0.1:443.
A fresh signed content URL first redirects through that API to an issued
synthetic-content.ulozto.invalid URL at 127.0.0.2:443. Both authorities have
distinct certificates, exact SNI/Host/address bindings and private CAs.
No live account or vendor endpoint is contacted.

Complete v9 folder and v8 file inventories retain root/nested scope, numeric
sizes and timestamps. Name-filtered metadata stays within its selected folder.
Every authenticated API call requires the exact application token and an
actually issued session. Download links require an observed file and return
fresh path nonces and signatures. Content accepts only a bound issued session
at the API, followed by the observed redirect at the content authority.
The redirected request must strip both application and session credentials;
Authorization and Cookie headers are also forbidden.

Three native downloads receive independent SHA-256 checks. Both native cat
and copy reject HTTP403 containing the expected bytes. Wrong application token,
wrong password and missing-name rejection, source/config preservation and
cleanup are mandatory. The direct DELETE guard does not qualify native writes.

Schema-33 ulozto_password_session_folder_read_v1 binds the current 44-file source
closure, pinned runtime/dependencies, native output/timing, nine capabilities,
containment and cleanup. The container has no network, host mounts/ports or
capabilities. It runs as nonroot with a read-only root, private namespaces,
bounded resources and private noexec tmpfs. Owned temporary material is removed;
the pinned public base image and shared build cache remain.

Both combined Linux and provider-smoke gates require 54 reviewed profiles and
the same-run Uloz.to receipt. Fifty-one provider regressions cover wire, two
distinct authorities, containment and evidence substitution without Docker or
fixed DNS/ports. Raw feasibility evidence cannot qualify this mode.

Real account login, expired-session reauthentication, root discovery,
pagination, duplicate names, custom-description hashes, uploads, native writes
and application/live-provider acceptance remain unverified. Independent
credential-renewal/session-review obligations remain.

Sources: [pinned backend](https://github.com/rclone/rclone/blob/v1.76.0/backend/ulozto/ulozto.go)
and [wire types](https://github.com/rclone/rclone/blob/v1.76.0/backend/ulozto/api/types.go).
