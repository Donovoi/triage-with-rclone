# pCloud OAuth protocol tests

This Linux/amd64 experiment exercises the pinned rclone backend through a fresh
OAuth callback, an independent authorization-code exchange, exact persisted
config validation, and a synthetic read by a new child process. It uses generated
credentials and a private loopback HTTPS authority. No pCloud account is accessed.

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
The supervisor verifies container isolation, image/source identity and cleanup.
Do not run the inner probe or build/run this fixture on a production host.

The default sanitized JSON is explicitly `ledger_eligible: false`. CI retains it
separately for 14 days and never submits it to `provider_coverage.py`. A positive
result does not establish negative callback/token cases, renewal, revocation,
interactive cancellation, regional behavior, application acceptance or vendor
acceptance. This receipt alone leaves the local protocol tier partial. In particular,
the upstream backend permits blank callback state and can derive its token host
from callback input; this positive experiment does not prove those paths safe.
The network-none namespace is a required boundary.

Offline probe/supervisor tests use mocked child processes and temporary files;
the separate HTTPS server tests establish fixture behavior. Neither substitutes
for the native container run. Build logs, child output, generated credentials,
image layers and caches are not public evidence artifacts.

## Fresh authentication evidence

The separate `--authentication-evidence` option runs a new six-case suite and
emits schema 5 only after validating its supervised native result. It cannot
convert the default feasibility receipt or historical output into evidence.

The suite repeats the positive control, then verifies wrong nonempty state,
consent denial, invalid code, wrong client secret and cancellation while awaiting
the callback. Each case uses a fresh config and fixture. Token denials must match
the exact Basic request followed by form authentication, with no token issuance,
saved token or API read. Generic malformed-request refusals do not qualify.
Cancellation must terminate and reap the owned waiting process after verifying
its listener and process identity. It does not establish application cancellation.

A successful suite requires nineteen native commands, ten callback requests and
fourteen fixture HTTPS requests. Negative cases preserve the exact pre-auth config
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
