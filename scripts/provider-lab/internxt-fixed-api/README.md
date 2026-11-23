# Internxt saved-JWT rotation and encrypted folder reads

Run inside a disposable Linux VM with Docker:

~~~sh
python -B scripts/provider-lab/internxt-fixed-api/run_container.py --rclone /absolute/path/to/verified/rclone --protocol-evidence --report /absolute/new/path/internxt-read-protocol.json
~~~

Pinned rclone 1.76.0 starts with a synthetic saved JWT and a public test mnemonic.
Each native command must call GET /drive/users/cli/refresh, adopt the newly
issued JWT, and persist exactly its access token, Bearer type and bound future
expiry. Every non-token configuration field and the rejected configuration
remain unchanged. This mode permits that precise token update; it does not
claim that the token file stays byte-for-byte unchanged.

The normal gateway.internxt.com authority resolves to 127.0.0.1:443 and issues
single-shard URLs on synthetic-content.internxt.invalid at 127.0.0.2:443.
Distinct private certificates enforce exact SNI, Host and address bindings.
The SDK metadata-refresh client uses its own Go TLS transport, so native
children receive a private SSL_CERT_FILE bundle as well as rclone CA arguments.
The environment is restored and the owned bundle removed after the test.
No provider endpoint or account is used.

Complete root and nested inventories preserve names, extensions, IDs, sizes
and timestamps. Existence queries distinguish missing files. A shard URL
requires an observed file and a fresh nonce bound to its ID; content requests
must carry no provider credentials. The fixture independently derives
BIP39/PBKDF2-SHA512, SHA512 bucket/file keys and AES-256-CTR ciphertext. Native
copy and cat recover three independently SHA256-checked plaintext payloads,
and an unaligned range must return exact bytes. The SDK validates its shard
hash on full reads; this profile makes no claim of hash validation on ranges.

Both native cat and copy must reject HTTP403 containing otherwise valid
ciphertext. Wrong-token and missing-file rejection, unchanged plaintext
sources, exact token rotation and configuration invariants, containment and
cleanup are required. The direct DELETE guard does not qualify native writes.

Schema-35 internxt_saved_jwt_rotation_folder_read_v1 binds the current 46-file
source closure, pinned runtime and dependencies, native output and timing,
all nine capabilities, containment and cleanup. The container has no network,
host mounts, exposed ports or capabilities. It runs as nonroot with a read-only
root, private namespaces, bounded resources and private noexec tmpfs.
Owned temporary material is removed; pinned public base images and shared
build caches remain.

Both Linux and provider-smoke gates require 56 reviewed profiles and the
same-run Internxt receipt. Fifty-one provider regressions cover wire contracts,
two authority boundaries, containment and evidence substitution. Raw
feasibility reports cannot qualify this mode.

Password login, 2FA, real account eligibility, expired-token refresh/relogin,
pagination, multishard files, uploads, native writes and application/live
provider acceptance remain unverified. Independent credential and session
review obligations remain.

Sources: [rclone authentication](https://github.com/rclone/rclone/blob/v1.76.0/backend/internxt/auth.go),
[SDK refresh](https://github.com/internxt/rclone-adapter/blob/v0.1.0/auth/access.go),
[encrypted reads](https://github.com/internxt/rclone-adapter/blob/v0.1.0/buckets/download.go),
and [key derivation](https://github.com/internxt/rclone-adapter/blob/v0.1.0/buckets/encrypt.go).
