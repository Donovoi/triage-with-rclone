# Cloudinary fixed-authority read protocol

Run this only inside a disposable Linux VM with Docker. The supervisor accepts
Linux Docker directly, including a dedicated local VM and GitHub-hosted Linux.
No browser, vendor account, real API key, user files or host trust changes are used.

~~~sh
python -B scripts/provider-lab/cloudinary-fixed-api/run_container.py \
  --rclone /absolute/path/to/verified/rclone --protocol-evidence \
  --report /absolute/new/path/cloudinary-fixed-api.json
~~~

The pinned rclone 1.75.2 Cloudinary backend sets upload_prefix on a configuration
copy that the Admin SDK does not use. The experiment therefore preserves the
native api.cloudinary.com authority and maps it to loopback only inside a fresh
network-none container. The service uses a fresh private CA, a single DNS SAN,
exact SNI/Host checks and port 443. Each native child receives only that CA and a
private synthetic configuration. The PC and VM host DNS and certificate stores
are not modified.

The container is nonroot, read-only, capability-free, has no host mounts or
published ports, and has bounded CPU, memory, process count, requests, bytes and
runtime. Its only writable directory is private noexec tmpfs. The pinned binary
executes from the read-only image. Both the supervisor and probe verify isolation
and source/runtime bindings. Cleanup checks remove the owned container, image,
processes, listeners, TLS material and temporary files. Shared daemon build cache
and the pinned public base image are retained; they contain no generated keys or
private account data. Images and raw process transcripts are never published.

The independent service exercises raw-asset folder listing, exact stat/search,
three literal downloads with independently computed sizes/hashes, missing
objects, wrong Basic credentials, denied reads, configuration preservation and
source preservation. Search errors in this native backend become object-not-found;
the negative probe additionally requires the server-observed 401 and no accepted
file. Public content requests must not carry the Admin credential and must use
previously issued links.

The write check is a direct synthetic fixture guard, not native uploader/delete
coverage. Media transformations, pagination, eventual consistency, real CDN
origins/redirects, uploads, token lifecycle and the Windows application are outside
this protocol. The explicit --protocol-evidence option emits closed schema-8
cloudinary_static_credentials_raw_read_v1 evidence. Its validator requires the
current source/runtime hashes, exact dependency pins, native probe, namespace
checks, cleanup and freshness before it can satisfy only the local-protocol tier.
Application/vendor requirements and lifecycle applicability remain unchanged.

Without that option, the default feasibility receipt remains ledger-ineligible.
Historical feasibility receipts and schema-1 rows cannot count as this mode.
Cloudinary stays outside the 26 portable experiments; the combined Linux and
provider-smoke gates require 38 protocol profiles. Forty-three wire, authority,
supervisor and receipt regressions run on both supported unit-test platforms
without fixed DNS or port 443.

Sources: the pinned [rclone backend](https://github.com/rclone/rclone/blob/v1.75.2/backend/cloudinary/cloudinary.go)
and [Cloudinary Go SDK v2.16.0](https://github.com/cloudinary/cloudinary-go/tree/v2.16.0).
