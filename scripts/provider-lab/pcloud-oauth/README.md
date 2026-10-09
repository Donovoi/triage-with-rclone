# pCloud OAuth protocol tests

This Linux/amd64 experiment exercises the pinned rclone backend through a fresh
OAuth callback, an independent authorization-code exchange, exact persisted
config validation, and a synthetic read by a new child process. It uses generated
credentials and a private loopback HTTPS authority. No pCloud account is accessed.
The fixed `fixture.pcloud.com` name maps only to `127.0.0.1` inside the isolated
container. Its generated certificate has that DNS SAN and requires exact SNI;
token and API requests use the same authority with normal certificate checks.

The positive contract requires four native commands and eight HTTP transactions:
two callback requests and six fixture requests. The acquired README must match an
independently specified SHA256, all three source files must remain unchanged, and
owned processes, listeners and temporary files must be removed. Callback state,
redirect authority, duplicate parameters, token form and saved config are checked
independently. HTTP redirects are never followed automatically.

Run only through the reviewed GitHub-hosted Linux container supervisor:

```bash
python -B scripts/provider-lab/pcloud-oauth/run_container.py \
  --rclone "$RUNNER_TEMP/rclone-pcloud-oauth" \
  --report "$RUNNER_TEMP/pcloud-oauth-feasibility.json"
```

Download the verified runtime first with `scripts/download-rclone.sh --linux`.
The root runtime manifest supplies its version and binary hash. The build uses an
immutable Python base and hash-locked certificate dependencies. It copies only
the reviewed source closure and the verified binary. The runtime container has
no network, published ports or host mounts; it runs as UID/GID 10001 with a
read-only root, bounded private tmpfs, no capabilities and bounded resource use.
The supervisor permits exactly that one hosts mapping and verifies container
isolation, image/source identity and cleanup. The existing unprivileged-port
threshold must permit port 443, and the fixture must bind it as UID 10001 with
no capabilities. Failure does not trigger a port, privilege or sysctl fallback.
Only this Linux fixed-port profile enables `SO_REUSEADDR` for sequential cases;
`SO_REUSEPORT` is disabled, and a live listener remains a bind failure. Each case
still requires complete listener and worker cleanup. Failed or unconfirmed
fixture construction or cleanup retains private material for container removal.
Do not run the inner probe or build/run this fixture on a production host.

The default sanitized JSON is explicitly `ledger_eligible: false`. CI retains it
separately for 14 days and never submits it to `provider_coverage.py`. A positive
result does not establish negative callback/token cases, renewal, revocation,
interactive cancellation, regional behavior, application acceptance or vendor
acceptance. This receipt alone leaves the local protocol tier partial. The pinned
1.75.2 backend rejects blank state and non-pCloud callback hostnames; the positive
experiment alone does not test those denials. The network-none namespace remains
a required boundary. Earlier IP-and-port callback receipts cannot qualify the
new source-bound authority and case contracts.

Offline probe/supervisor tests use mocked child processes and temporary files;
the separate HTTPS server tests establish fixture behavior. Neither substitutes
for the native container run. Build logs, child output, generated credentials,
image layers and caches are not public evidence artifacts.

## Fresh authentication evidence

The separate `--authentication-evidence` option runs a new eight-case suite and
emits schema 5 only after validating its supervised native result. It cannot
convert the default feasibility receipt or historical output into evidence.

The suite repeats the positive control, then verifies wrong nonempty state,
blank state, an invalid callback hostname, consent denial, invalid code, wrong
client secret and cancellation while awaiting
the callback. Each case uses a fresh config and fixture. Token denials must match
the exact Basic request followed by form authentication, with no token issuance,
saved token or API read. Generic malformed-request refusals do not qualify.
State and hostname rejection must make no token or API requests and must leave
the entire initial config unchanged, including its authority. Cancellation must terminate and reap the owned waiting process after verifying
its listener and process identity. It does not establish application cancellation.

A successful suite requires twenty-five native commands, fourteen callback requests
and sixteen fixture HTTPS requests. Its 103 checks include binding and preserving
the authority in every case. Negative cases preserve the exact pre-auth config
and source bytes. Every case cleans its resources before the next; a failure
stops the suite and retains an explicitly failed ordered prefix. Runtime/source
identity and chronological bounds are checked for each nested case.

Schema 5 contributes only `authentication` to the Linux/amd64 local protocol tier.
The existing saved-token fixture must independently supply the other ten required
capabilities. The importer rejects wrong identities, unknown fields, expired or
future receipts and inconsistent success. Missing cases and failed cleanup cannot
earn a pass; valid failed observations remain failures even alongside another
passing receipt. The suite runs
under the same isolation constraints, with a 240-second outer execution limit;
the default positive experiment retains its 90-second limit. Shared daemon build
cache is not pruned, and no image or cache is uploaded.

The shared TLS and pCloud handler changes preserve other fixtures' default IP
certificate and ephemeral port. They change the pCloud saved-token and GCS source
closures, so those receipts also require fresh evidence; old hashes are not
grandfathered. Unit mocks do not prove DNS, SNI or the non-root port-443 native run.
