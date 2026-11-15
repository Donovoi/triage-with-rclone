# Oracle Object Storage configured-user bucket reads

Run inside a disposable Linux VM with Docker:

~~~sh
python -B scripts/provider-lab/oos-fixed-api/run_container.py --rclone /absolute/path/to/verified/rclone --protocol-evidence --report /absolute/new/path/oos-read-protocol.json
~~~

The pinned rclone 1.75.2 and OCI Go SDK v65.121.0 use the canonical config type
oracleobjectstorage (the application's selectable prefix is oos). This profile
uses user_principal_auth, an explicit OCI config/profile, ephemeral RSA-2048 keys,
and a configured synthetic namespace and bucket in us-ashburn-1. It preserves the
default objectstorage.us-ashburn-1.oraclecloud.com authority; private DNS, TLS
with a single-name certificate, exact SNI and Host checks bind it to loopback.

The independent verifier requires RSA PKCS1v15 SHA256 with the SDK's exact
version, signed-header order and key ID. The signed request-target includes the
escaped path and exact raw query order. Canonical UTC Date is bounded to five
minutes. Four literal OpenSSL-generated vectors independently verify signing
messages and signatures. Wrong keys, key IDs, methods, hosts, changed query
order, stale dates, unsupported headers and alternate signature formats fail.

The fixture accepts complete first-page ListObjects responses with exact
fields, limit, prefix and optional delimiter; it does not enumerate account
buckets. HEAD returns known sizes, Content-MD5, ETag, storage tier and timestamps.
GET requires an observed object identity, returns known bytes with bounded
ranges, and rejects reads in denial mode. Bodyless SDK calls require its observed
application/json Content-Type. Missing objects and directory candidates return
404; wrong-key 401 and read-denial 403 responses are required. Three native
downloads are independently checked with SHA-256. The pinned rclone listing MD5
decode branch appears inverted, so listing-hash correctness is not claimed.

The native probe verifies all nine read capabilities, source/config/key
preservation and cleanup. The direct signed DELETE guard does not qualify native
writes. A fresh network-none Linux container enforces nonroot identity,
read-only root, no capabilities or host mounts/ports, private namespaces,
bounded resources and private noexec tmpfs. Schema-23
oos_user_principal_bucket_read_v1 binds the current 34-file source closure, pinned
runtime/dependencies, native output/timing and cleanup. Generated private keys
are disposable; only a synthetic public key and signatures appear in test
oracles. The shared build cache and pinned public base image remain.

Both combined Linux and provider-smoke gates require 44 reviewed profiles and
the same-run receipt. Raw feasibility/schema-1 results cannot qualify this mode.
Forty-nine wire/TLS, container and receipt regressions run without Docker or fixed
DNS/ports. The 26 portable protocol fixtures remain unchanged.

Only synthetic local-protocol coverage is qualified. Application/vendor and
unresolved renewal/session obligations remain. Instance/resource/workload
principals, security-token files, environment discovery, IAM eligibility,
anonymous access, account-wide discovery, other regions/realms, pagination,
native writes and application/live-provider acceptance remain unverified.

Sources: [pinned rclone backend](https://github.com/rclone/rclone/tree/v1.75.2/backend/oracleobjectstorage),
[OCI SDK v65.121.0](https://github.com/oracle/oci-go-sdk/tree/v65.121.0)
and [Oracle request signing](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm).
