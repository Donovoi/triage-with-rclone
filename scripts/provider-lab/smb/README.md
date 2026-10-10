# Isolated Samba NTLM protocol fixture

This fixture tests the pinned Linux rclone binary against an independent Samba
server. `--protocol-evidence` emits the closed schema-3 `smb_samba_ntlm_read_v1`
contract for the Linux/amd64 local protocol ledger. Its seven capabilities cover
listing, independent download hashes, wrong-password and missing-object rejection,
source/config preservation and cleanup. It does not establish Windows behavior,
application acceptance, a hosted SMB provider, Kerberos, connection recovery,
renewal, cancellation or write denial.

The default invocation still produces feasibility evidence with
`ledger_eligible: false`; those earlier receipts remain rejected by the ledger.
The protocol option requires a new native run, with UTC timing around execution
and cleanup. There is no command to convert an old receipt. Schema 3 includes the
closed native observations and binds the current five-file harness, four native
source hashes, Debian lock/base, immutable image ID, Samba and rclone identities,
shared three-file manifest, platform, isolation and both cleanup layers. The
importer recomputes expected source and manifest identities independently. These
are reports from trusted runs, not cryptographic execution attestations.

The CI supervisor runs only on a disposable GitHub-hosted Linux runner. It builds
the official Debian image at an immutable amd64 digest and installs the complete
hash-locked package closure from authenticated fixed Debian snapshots. Package
versions, dependency choices, provenance, support dates, and known limitations
are recorded in `build-lock.json`. Review and refresh that snapshot before a
later acceptance batch; this image does not receive automatic security fixes.
Rclone uses the repository's sole `rclone-version.env` pin set. Both image build
and probe startup verify that manifest against the executable and image metadata,
so the normal runtime updater can advance it without editing duplicate pins.

Build-time setup creates one synthetic local account and a fresh random password.
The password travels through private stdin and stays inside the unpublished
image. No real account or cloud credential is involved. The build requires
network access for the pinned image and packages; the test container has
`--network none`, a read-only root, UID/GID 10001, all capabilities dropped, no new
privileges, no host mounts, no published ports, and one private 32 MiB tmpfs.
It is limited to one CPU, 512 MiB RAM, and 64 processes. The supervisor checks
the actual container settings before starting it and again after it exits.

Within the container the driver checks identity, mounts, processes, and loopback
network isolation before starting a foreground Samba server on port 15445. The
same server must support a full listing and independent hash-checked acquisition
of three synthetic files, reject a wrong password, repeat the successful reads,
and reject a missing object. Source files, client configuration, and immutable
credential seed must remain unchanged. The driver then stops its children,
checks that listeners closed, and removes its private temporary contents.

Only a closed, sanitized JSON result is exported. The supervisor removes its
uniquely labeled container, image tag, and private build context. It does not
prune shared Docker caches or base images; the disposable runner's teardown
discards those. Images, cache, seed credentials, and raw logs are never uploaded.
Build timeout or unavailable snapshots fail the experiment without a mirror,
credential, or privilege fallback. The public report includes only fixed stage
markers and diagnostic codes for failures.

CI combines the new SMB receipt only with the same run's Linux baseline,
FileFabric renewal, IA LOW, pCloud authentication and GCS OAuth lifecycle receipts,
and requires twenty-one complete local protocol profiles. The Windows gate
requires eighteen complete profiles plus the GCS static-token mode; SMB, pCloud
authentication and GCS OAuth lifecycle remain unverified on Windows. Internet
Archive requires both its anonymous and protected LOW modes. A profile qualifies
only when its current receipts pass. The scheduled Linux provider workflow
requires the same complete profiles.

The Python tests use mocks and local temporary files and do not start Docker,
Samba, rclone, or a service. Native execution requires the isolated CI job.
