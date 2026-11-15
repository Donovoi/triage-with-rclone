# 1Fichier configured-key read protocol

Run only inside a disposable Linux VM with Docker:

~~~sh
python -B scripts/provider-lab/fichier-fixed-api/run_container.py \
  --rclone /absolute/path/to/verified/rclone --protocol-evidence \
  --report /absolute/new/path/fichier-read-protocol.json
~~~

The pinned rclone 1.75.2 backend fixes its API at https://api.1fichier.com/v1.
A fresh network-none container maps only that authority to loopback. Exact
SNI/Host checks, a fresh private CA and port 443 protect synthetic key requests.
No real account, browser, user files or host DNS/trust changes are used.

The independent API checks Bearer credentials, strict JSON folder/file inventory,
metadata and download-link requests. Three literal payloads have independent
SHA-256 download oracles and Whirlpool checksum values computed with OpenSSL
3.5.5's legacy provider. Native rclone downloads use four freshly issued links:
three successful reads and one denied read. Every link is consumed exactly once.
Wire regressions additionally reject unknown/replayed links and prove that wrong
credentials cannot consume a valid link. This is not broader session recovery.

Missing-object stat/copy checks select names from complete inventories; there is
no invented missing-name endpoint. A direct authenticated fixture file/rm.cgi
guard preserves source data. Native writes are outside scope. Malformed methods,
routes, JSON fields/types, duplicate keys, headers, framing, queries, ranges and
expired bodies fail closed.

The supervisor enforces nonroot identity, read-only root, no capabilities or host
mounts/ports, private namespaces, bounded resources and private noexec tmpfs.
It binds the current 30-file source closure, pinned runtime/dependencies, exact
native output/timing, all nine capabilities and owned cleanup. Private keys,
API credentials and issued links remain ephemeral. Shared build cache and the
pinned public base image remain; raw transcripts are never published.

Schema-12 fichier_configured_key_read_v1 qualifies only the Linux local-protocol
tier. Both combined Linux and provider-smoke gates require 40 reviewed profiles.
Without --protocol-evidence, raw feasibility receipts remain ledger-ineligible;
historical feasibility and schema-1 rows cannot satisfy this profile. The 26
portable experiments remain unchanged.

Application/vendor requirements and lifecycle applicability remain unchanged.
Shared-folder/password/CDN modes, explicit API-key replacement, live content
origins, expiry recovery, native writes and Windows application/live-provider
acceptance remain unverified. Forty-six wire, TLS, container, workflow and
receipt regressions run without Docker or fixed port/DNS requirements on the
unit-test platforms.

Source: [rclone 1Fichier v1.75.2](https://github.com/rclone/rclone/tree/v1.75.2/backend/fichier).
