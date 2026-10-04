# Isolated Samba feasibility probe

This experiment tests the pinned Linux rclone binary against an independent Samba
server. Its report explicitly sets `ledger_eligible: false`. A successful run
does not establish production application acceptance, a hosted SMB provider,
Kerberos, renewal, cancellation, or complete SMB coverage.

The CI supervisor runs only on a disposable GitHub-hosted Linux runner. It builds
the official Debian image at an immutable amd64 digest and installs the complete
hash-locked package closure from authenticated fixed Debian snapshots. Package
versions, dependency choices, provenance, support dates, and known limitations
are recorded in `build-lock.json`. Review and refresh that snapshot before a
later acceptance batch; this image does not receive automatic security fixes.

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

The Python tests use mocks and local temporary files and do not start Docker,
Samba, rclone, or a service. Native feasibility requires the isolated CI job.
