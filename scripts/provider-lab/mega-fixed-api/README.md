# Mega saved-session encrypted reads

This Linux-only synthetic profile exercises the unmodified, hash-pinned rclone 1.76.0 Mega backend. It is protocol coverage, not application or live-provider acceptance. It uses public synthetic data and ephemeral session values; no account is provisioned.

The independent Python fixture implements the saved `session_id` + `master_key` branch at the normal `g.api.mega.co.nz` authority. The pinned SDK is `t3rm1n4l/go-mega` commit `c6acd6a5bd041dbec42aa4e0f650dc2ea82d2857` (`v0.0.0-20260717075258-c6acd6a5bd04`). Python's cryptography library independently constructs wrapped node keys, AES-CBC encrypted names, AES-CTR file ciphertext and folded CBC file MACs. The SDK is not used to generate expected bytes.

A network-none container maps the API to 127.0.0.1 and the issued `synthetic-content.mega.invalid` authority to 127.0.0.2. Each uses its own private certificate, exact SNI/Host binding and port 443. Rclone keeps ordinary TLS verification enabled and receives the owned CA certificates. There is no API override, host trust-store modification, credential mount, published port or runtime Internet access.

Native checks require complete recursive/root/nested listings, exact downloads and `cat` for all three independently hashed payloads, an unaligned plaintext range, wrong-session rejection, missing-object rejection and byte-exact configuration preservation. Denied reads return HTTP 403 with the **same valid ciphertext**; both native `cat` and copy must fail without accepted output. The SDK makes two chunk attempts per denied command, so the fixture requires four denial observations. A direct HTTP DELETE checks the fixture write guard; it does not qualify native writes. Source preservation and complete child/listener/certificate/container/image/temporary-file cleanup are mandatory.

The SDK fires its startup event before requesting the discovered event-wait URL. The fixture supplies that URL on the API authority and uses HTTP/1.1 connection reuse, preventing a fresh TLS handshake from racing the exit of short native commands. Wait URLs are fresh, single-use and credential-free; the wait ends on peer disconnect or a bounded timeout. No TLS failures are ignored. The transport still enforces its absolute request, connection and lifetime budgets.

```sh
python -B scripts/provider-lab/mega-fixed-api/run_container.py \
  --rclone /absolute/path/to/verified/rclone \
  --protocol-evidence --report /absolute/path/to/mega-read-protocol.json
```

Schema 37 binds the receipt to the exact 47-file source closure, dependency lock, pinned rclone executable, container image, independent payload manifest, native capabilities and cleanup. Raw schema-1 feasibility results cannot satisfy the ledger. CI and provider smoke require this receipt along with all other reviewed profiles; missing, stale, skipped or failed evidence cannot count as passing.

Password login, 2FA, session renewal/recovery/revocation, real account eligibility, shared nodes, multi-chunk files, corrupted-file rejection, event synchronization and native writes remain unverified. Existing application, vendor and independent session-review obligations remain in the policy.
