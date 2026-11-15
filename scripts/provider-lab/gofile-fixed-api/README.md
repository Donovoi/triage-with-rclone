# GoFile configured-token read protocol

Run only inside a disposable Linux VM with Docker:

~~~sh
python -B scripts/provider-lab/gofile-fixed-api/run_container.py \
  --rclone /absolute/path/to/verified/rclone --protocol-evidence \
  --report /absolute/new/path/gofile-fixed-api-feasibility.json
~~~

The pinned rclone 1.75.2 backend fixes its API at https://api.gofile.io.
A fresh network-none container maps only that authority to loopback. Exact
SNI/Host checks, a fresh private CA and port 443 protect the synthetic token
requests. No account, browser, user files or host DNS/trust changes are used.

A configured token, account ID and root folder ID avoid account bootstrap and
configuration updates. The independent API implements single-page root/nested
inventories, recursive trees, exact-name lookup, metadata and issued content
links for three literal files. Independent sizes, MD5 values and downloaded
SHA-256 values bind reads to known bytes. Wrong bearer credentials, missing
objects and authenticated read denial produce no output file. A direct synthetic
DELETE guard preserves source data; native mutation endpoints are outside scope.

Malformed methods, routes, headers, framing, pagination/depth queries, ranges
and deadlines fail closed. The native flow verifies two complete recursive
inventories, exact downloads, negative cases, unchanged metadata/configuration
and stopped children/listeners. Container checks enforce nonroot identity,
read-only root, no capabilities/host mounts/published ports, private namespaces,
bounded resources and private noexec tmpfs.

Source/runtime/dependency bindings and namespace checks surround native
execution. Cleanup verifies owned container/image and temporary-file removal.
Shared build cache and the pinned public base image remain; synthetic credentials
and private TLS material exist only in ephemeral tmpfs. Published receipts contain
no raw transcripts.

The explicit --protocol-evidence option emits closed schema-10
gofile_configured_token_read_v1 evidence. The importer recomputes the current
22-file source closure and runtime bindings, and validates isolation, dependencies,
native probe, timestamps, exact output, all nine capabilities and cleanup before
accepting only the Linux local-protocol tier. Both combined Linux and provider-smoke
gates require 31 profiles; GoFile remains outside the 26 portable experiments.

Without that option, feasibility receipts remain ledger-ineligible. Historical
feasibility and schema-1 rows cannot satisfy this mode. Application/vendor
requirements and lifecycle applicability remain unchanged. Account creation and
discovery, explicit token replacement, real content-host redirects, pagination
beyond one page, native writes and Windows application behavior remain unverified.
Forty-four wire, TLS, container, workflow and receipt regressions run without Docker
or fixed port/DNS requirements on the unit-test platforms.

Source: [rclone GoFile v1.75.2](https://github.com/rclone/rclone/tree/v1.75.2/backend/gofile).
