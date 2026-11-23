# iCloud Drive saved-cookie folder read protocol

Run inside a disposable Linux VM with Docker:

~~~sh
python -B scripts/provider-lab/iclouddrive-fixed-api/run_container.py --rclone /absolute/path/to/verified/rclone --protocol-evidence --report /absolute/new/path/iclouddrive-read-protocol.json
~~~

Pinned rclone 1.76.0 uses a saved synthetic cookie plus trust token in non-ADP
mode. Its first native listing must discover service endpoints through
POST /setup/ws/1/validate. Subsequent commands reuse the native service cache;
the fixture requires exactly one validation exchange. No password or real
account is used.

The normal setup.icloud.com authority resolves only to private 127.0.0.1:443.
It issues synthetic-drive.icloud.invalid and synthetic-docs.icloud.invalid
service URLs at 127.0.0.2:443 and 127.0.0.3:443. The document service issues
fresh synthetic-content.icloud.invalid URLs at 127.0.0.4:443. All four
authorities have distinct certificates, exact SNI/Host/address bindings and
private CAs. No vendor endpoint is contacted.

Complete folder inventories retain root/nested scope, exact IDs, split
names/extensions, numeric sizes and timestamps. Inventory requests require
the reviewed JSON shape and false partialData/includeHierarchy flags.
Validation has an empty body; document metadata GETs carry the native JSON
null body. Download links require an observed file and fresh nonce bound to
its document ID. The native content request deliberately includes the exact
saved cookie; this profile makes no credential-stripping claim.

Three native downloads receive independent SHA-256 checks. Both native cat
and copy reject HTTP403 containing the expected bytes. Wrong-cookie rejection
after initial service discovery, missing-name rejection, byte-exact config
and source preservation, and cleanup are mandatory. The direct DELETE guard
does not qualify native writes.

Schema-34 iclouddrive_saved_cookie_folder_read_v1 binds the current 45-file
source closure, pinned runtime/dependencies, native output/timing, nine
capabilities, containment and cleanup. The container has no network, host
mounts/ports or capabilities. It runs as nonroot with a read-only root, private
namespaces, bounded resources and private noexec tmpfs. Owned temporary
material, including the service cache, is removed; the pinned public base
image and shared build cache remain.

Both combined Linux and provider-smoke gates require 55 reviewed profiles
and the same-run iCloud Drive receipt. Fifty-one provider regressions cover
wire, four distinct authorities, containment and evidence substitution
without Docker or fixed DNS/ports. Raw feasibility evidence cannot qualify
this mode.

SRP/password login, real account eligibility, 2FA, ADP/PCS, expired sessions
and trust, 401/421/423 reauthentication, pagination, uploads, native writes
and application/live-provider acceptance remain unverified. Independent
credential-renewal/session-review obligations remain.

Sources: [pinned client](https://github.com/rclone/rclone/blob/v1.76.0/backend/iclouddrive/api/client.go),
[session](https://github.com/rclone/rclone/blob/v1.76.0/backend/iclouddrive/api/session.go),
and [drive protocol](https://github.com/rclone/rclone/blob/v1.76.0/backend/iclouddrive/api/drive.go).
