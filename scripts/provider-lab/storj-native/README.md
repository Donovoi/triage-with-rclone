# Native Storj and Tardigrade saved-grant reads

This isolated Linux/amd64 fixture runs the official pinned Storj test network:
one satellite, four storage nodes and a disposable PostgreSQL database. It
exercises the pinned, unmodified rclone executable separately with both
configuration types, `storj` and `tardigrade`. It does not use the S3 gateway.

Run all commands inside a disposable Linux VM. Docker, Git and Python 3.12+
are required. No host database, vendor account or provider credentials are used.

```sh
git clone --no-checkout https://github.com/storj/storj.git /absolute/new/storj-source
git -C /absolute/new/storj-source checkout --detach b2fe6e00c07c42711217c1c60c283d5e000b18ba
python -B scripts/provider-lab/storj-native/build_fixture.py \
  --source /absolute/new/storj-source --output /absolute/new/storj-build
python -B scripts/provider-lab/storj-native/run_container.py \
  --build /absolute/new/storj-build --rclone /absolute/path/to/verified/rclone \
  --report /absolute/new/storj-native-protocol.json
```

The build verifies the complete source archive, pins the Go compiler image,
uses the upstream go.mod/go.sum without editing them, and limits the compiler
to 1.5 CPUs, 3 GiB RAM and 384 processes. Only this build phase has network
access to download public modules. The compiler runs as the caller's
unprivileged UID, with a read-only root filesystem, an owned writable build
directory and no capabilities. Its container and scratch directory must be
removed. A cold build takes several minutes.

The runtime image pins PostgreSQL and copies the resulting test binary,
verified rclone binary and 99 pinned upstream email/error resources.
The runtime container has no external network, no host mounts or published
ports, a read-only root filesystem, UID/GID 999, no capabilities, no privilege
escalation, private IPC/cgroup namespaces, and bounded CPU/RAM/process/tmpfs
resources. Database files, synthetic grants, test identities and downloaded
payloads exist only in disposable tmpfs. Build caches and pinned public base
images are shared daemon resources; the fixture never prunes them.

The fixture removes the test network's development peer-CA whitelist so that
the ordinary native Uplink client can connect. It retains Storj node-ID TLS
verification and server-side API-key/macaroon authorization. This is not a
TLS verification bypass.

Each backend performs the same 22 native commands:

- Complete recursive inventories before and after reads/rejected writes, and
  a listing using a grant that permits listing but forbids downloads.
- Full cat and copy-to-local reads of four independently known payloads:
  a 62-byte text file, 26-byte nested file with a space, 2,048-byte binary file
  and deterministic 1 MiB binary file. Every result is compared byte for byte.
- Unaligned ranges from an inline object and the storage-node object.
- Rejection of a validly encoded grant with an unregistered root API key,
  and a separate correctly signed grant with an expired time window.
- Cat/copy denial for both inline and storage-node files using the list-only
  grant; no denied bytes or destination file may be accepted.
- A strict missing-file copy using --error-on-no-transfer, with no output file.
- Native delete and upload rejection under the read-only grant.

The metabase must show three inline segments and at least one remote segment
with at least two storage-node pieces. The test compares every source object
after both backend sequences and checks every configuration byte after every
child command. Commands have independent deadlines. The Go test must complete
without failures or skips, and removal of the runtime container, image,
private logs and generated context is mandatory.

The missing-file contract uses strict copy semantics. Storj's virtual
directory-prefix behavior means cat of a missing prefix can return no bytes
with exit zero, and lsjson --stat can describe a virtual directory. Neither
command is presented as a strict missing-object rejection oracle.

Schema 36, mode storj_saved_access_grant_native_read_v1, binds seven harness
files, the four-payload manifest, exact runtime, compiler/source/resource
provenance, all 44 ordered native commands, the independent backend rows,
containment and cleanup. The coverage importer rejects missing/mutated checks,
source changes, stale evidence, wrong runtime/platform, substituted aliases,
failed permission checks and incomplete cleanup. CI and Provider Smoke import
only the same-run sanitized artifact into their 58-provider Linux gates.

This is synthetic native protocol coverage. Live account eligibility, API-key
and passphrase setup, grant derivation/persistence, revocation, external grant
replacement, transport reconnection, application acceptance, large/multi-segment
objects, production erasure-code policies and live Storj acceptance remain
unverified. Existing application/vendor/session-review obligations remain.

Sources: [rclone backend](https://github.com/rclone/rclone/blob/v1.76.0/backend/storj/fs.go),
[rclone reads](https://github.com/rclone/rclone/blob/v1.76.0/backend/storj/object.go),
[Storj test network](https://github.com/storj/storj/tree/b2fe6e00c07c42711217c1c60c283d5e000b18ba/private/testplanet)
and [the pinned build inputs](pins.json).
