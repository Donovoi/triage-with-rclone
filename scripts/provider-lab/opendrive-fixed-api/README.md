# OpenDrive configured-session read protocol

Run only inside a disposable Linux VM with Docker:

~~~sh
python -B scripts/provider-lab/opendrive-fixed-api/run_container.py \
  --rclone /absolute/path/to/verified/rclone --protocol-evidence \
  --report /absolute/new/path/opendrive-fixed-api.json
~~~

The pinned rclone 1.75.2 backend fixes its API at
https://dev.opendrive.com/api/v1. This profile keeps that authority and maps it to
loopback only in a fresh network-none container. Exact SNI/Host checks, a fresh
private CA and port 443 protect the synthetic session exchange. No real account,
browser, user files or host DNS/trust changes are used.

The independent fixture checks JSON username/password login, unique issued
sessions, root and nested folder inventories, exact-name lookup, file metadata
and three literal downloads. Sizes, MD5 values and downloaded SHA-256 values
come from independent byte oracles. Wrong credentials and unknown sessions are
rejected; missing objects produce no file; authenticated read denial and the
direct fixture DELETE guard preserve source data and private configurations.
Malformed bodies, duplicate fields, ambiguous framing, routes, query strings,
ranges and expired requests fail closed.

The nonroot container has a read-only root, no capabilities or host mounts,
private namespaces, no network interfaces beyond loopback, no published ports,
bounded resources and private noexec tmpfs. Source/runtime/dependency bindings
and namespace checks run before and after the native probe. Cleanup verifies
owned container/image removal, closed listeners, stopped children and removed
temporary files. Shared build cache and the pinned public base image remain;
runtime credentials, session IDs and private TLS material are generated only
inside ephemeral tmpfs. Raw transcripts and images are never published.

The explicit --protocol-evidence option emits closed schema-9
opendrive_configured_session_read_v1 evidence. The importer recomputes current
source/runtime bindings and validates isolation, dependencies, native probe,
timestamps, exact output, all nine capabilities and cleanup before accepting only
the Linux local-protocol tier. The combined Linux and provider-smoke gates now
require 38 profiles; OpenDrive remains outside the 26 portable experiments.

Without that option, feasibility receipts remain ledger-ineligible. Historical
feasibility and schema-1 rows cannot satisfy this mode. Application/vendor
requirements, credential-renewal applicability and unresolved connection/session
reauthentication are preserved. Session expiry, transparent reauthentication,
real account policies, service consistency, pagination, native writes and the
Windows application remain outside this profile. Forty-four wire, TLS, container,
workflow and receipt regressions run without Docker or fixed port/DNS requirements
on the unit-test platforms.

Source: [rclone OpenDrive v1.75.2](https://github.com/rclone/rclone/tree/v1.75.2/backend/opendrive).
