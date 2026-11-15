# QingStor configured-key bucket read protocol

Run inside a disposable Linux VM with Docker:

~~~sh
python -B scripts/provider-lab/qingstor-fixed-api/run_container.py --rclone /absolute/path/to/verified/rclone --protocol-evidence --report /absolute/new/path/qingstor-read-protocol.json
~~~

The pinned rclone 1.75.2 and QingStor SDK v3.2.0 path uses a configured access-key
pair, default pek3a regional endpoint and explicit synthetic bucket. TLS SNI
is exactly pek3a.qingstor.com; the SDK's HTTP Host includes :443. The fixture
requires a fresh canonical UTC Date and QS HMAC-SHA256 signature over method,
empty Content-MD5/Type fields, Date and escaped resource path. Four independent
OpenSSL vectors cover bucket GET, object HEAD, an escaped space and DELETE.

The SDK does not sign listing delimiter/limit/prefix controls, so the fixture
validates their scope independently. Native recursive listing uses an empty
delimiter; separate native checks verify nonrecursive root/nested inventories.
All inventories are complete first pages with has_more=false, exact limit=1000
and no continuation. Directory candidates and the actual missing object receive
real missing-key responses, never fabricated file metadata.

HEAD/listing metadata exposes independently checked MD5 ETags, sizes, timestamps,
MIME types and unencrypted objects. Three payload SHA-256 oracles verify native
reads. Known identity observation precedes signed downloads; range bounds,
wrong-key rejection and denied reads are checked. A direct signed DELETE guard
preserves source data without qualifying native writes. Source/config
preservation and owned cleanup are mandatory.

A fresh network-none Linux container maps only pek3a.qingstor.com to loopback.
Exact TLS/Host checks and a private CA contain requests. Nonroot identity,
read-only root, no capabilities or host mounts/ports, private namespaces,
bounded resources and private noexec tmpfs are enforced. Schema-20
qingstor_configured_key_bucket_read_v1 binds the current 31-file source closure,
pinned runtime/dependencies, native output/timing, nine capabilities and cleanup.
Generated keys are ephemeral; the shared build cache and pinned public base
image remain.

Both combined Linux and provider-smoke gates require 41 reviewed profiles and
the same-run receipt. Raw feasibility/schema-1 rows cannot qualify this mode;
the 26 portable experiments remain unchanged. Forty-eight QingStor wire/TLS,
container and receipt tests run without Docker or fixed DNS/ports.

Only local-protocol coverage is qualified. Existing application/vendor
requirements and unresolved refresh/session applicability reviews remain.
IAM/environment/config fallback, temporary tokens, key rotation, account-wide
bucket enumeration, other regions, continuation, multipart/SSE/other
subresources, native writes and application/live-provider acceptance remain
unverified.

Sources: [pinned rclone QingStor](https://github.com/rclone/rclone/tree/v1.75.2/backend/qingstor)
and [QingStor SDK v3.2.0](https://github.com/yunify/qingstor-sdk-go/tree/v3.2.0).
