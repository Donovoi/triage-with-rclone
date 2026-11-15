# Drime configured-token read protocol

Run only inside a disposable Linux VM with Docker:

~~~sh
python -B scripts/provider-lab/drime-fixed-api/run_container.py \
  --rclone /absolute/path/to/verified/rclone --protocol-evidence \
  --report /absolute/new/path/drime-fixed-api-feasibility.json
~~~

The pinned rclone 1.75.2 backend fixes its API at https://app.drime.cloud/api/v1.
A fresh network-none container maps only that authority to loopback. Exact
SNI/Host checks, a fresh private CA and port 443 protect synthetic token requests.
No account, browser, user files or host DNS/trust changes are used.

An explicit token and root folder ID exercise single-page configured reads.
Independent inventories bind numeric folder/file IDs, names, sizes, timestamps
and issued relative content links. The native runner verifies root/nested
listing, client-side exact-name selection and three literal downloads against
independent SHA-256 values. Wrong credentials, missing objects and denied reads
produce no output file. The API has no name lookup parameter: native missing
stat/copy checks use the complete inventory, without inventing a server-side
missing-name event. A direct synthetic DELETE guard preserves source data;
native mutation endpoints are outside scope.

Malformed methods, routes, headers, framing, pagination/workspace queries,
ranges and expired requests fail closed. The native flow verifies unchanged
metadata/configuration and stopped children/listeners. The supervisor enforces
nonroot identity, read-only root, no capabilities/host mounts/published ports,
private namespaces, bounded resources and private noexec tmpfs.

Source/runtime/dependency bindings and namespace checks surround native execution.
Cleanup verifies owned container/image and temporary-file removal. Shared build
cache and the pinned public base image remain; synthetic credentials and private
TLS material exist only in ephemeral tmpfs. No raw transcripts are published.

The explicit --protocol-evidence option emits closed schema-11
drime_configured_token_read_v1 evidence. The importer recomputes the current
29-file source closure and runtime bindings, and validates isolation, dependencies,
native probe, timestamps, exact output, all nine capabilities and cleanup before
accepting only the Linux local-protocol tier. Both combined Linux and provider-smoke
gates require 39 profiles; Drime remains outside the 26 portable experiments.

Without that option, feasibility receipts remain ledger-ineligible. Historical
feasibility and schema-1 rows cannot satisfy this mode. Application/vendor
requirements and lifecycle applicability remain unchanged. Account discovery,
explicit token replacement, workspace selection, pagination beyond one page,
native writes and Windows application/live-provider acceptance remain unverified.
Forty-four wire, TLS, container, workflow and receipt regressions run without Docker
or fixed port/DNS requirements on the unit-test platforms.

Source: [rclone Drime v1.75.2](https://github.com/rclone/rclone/tree/v1.75.2/backend/drime).
