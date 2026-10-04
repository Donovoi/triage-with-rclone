# pCloud OAuth callback feasibility

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

The sanitized JSON is explicitly `ledger_eligible: false`. CI retains it
separately for 14 days and never submits it to `provider_coverage.py`. A positive
result does not establish negative callback/token cases, renewal, revocation,
interactive cancellation, regional behavior, application acceptance or vendor
acceptance. The existing pCloud local protocol tier stays partial. In particular,
the upstream backend permits blank callback state and can derive its token host
from callback input; this positive experiment does not prove those paths safe.
The network-none namespace is a required boundary.

Offline probe/supervisor tests use mocked child processes and temporary files;
the separate HTTPS server tests establish fixture behavior. Neither substitutes
for the native container run. Build logs, child output, generated credentials,
image layers and caches are not public evidence artifacts.
