# GCS OAuth lifecycle experiment

This is an **unqualified source draft** for pinned rclone 1.75.1. No hosted native
run has validated it. Every receipt remains `ledger_eligible: false`; existing
GCS coverage policy and static-token evidence are unchanged.

The ten fresh-config cases are: positive callback/code exchange and README read;
wrong state; blank state; consent denial; invalid code; wrong client secret;
callback-wait cancellation; actual expiry followed by refresh, replacement-token
read and persistence; denied refresh; and cancellation of an observed held refresh.

The fixture generates every credential. Authorization, token and storage URLs
use one owned loopback HTTPS authority with a generated CA explicitly trusted by
the child. Certificate verification is never disabled. The callback listener is
owned by the exact child on `127.0.0.1:53682`; the driver validates redirects and
delivers the synthetic callback without opening a browser or following redirects.
Only metadata and content for `synthetic-bucket/README-synthetic.txt` are served.
The independent existing SHA256 oracle and all three source payloads are retained.

GCS uses rclone's `devstorage.read_write` scope. This fixture permits no write
operation; it does not represent read-only consent. `access_token` is omitted to
avoid the static-token bypass. Service-account fields are empty, anonymous and
environment authentication are disabled, and the child receives no ambient
credentials. Pinned GCS can fall back to ADC after OAuth-client construction
failure, so the network-none container is a required boundary, not optional.

Renewal cases receive a genuine synthetic grant with `expires_in: 1`; the driver
waits until the saved wall-clock expiry passes without editing the credential.
The subsequent acquisition child must refresh and use the returned replacement
token. A successful refresh must persist precisely the issued token pair/expiry,
with all non-token options unchanged. Negative cases preserve their pre-attempt
config bytes and have no accepted destination or storage payload. This does not
test expiry inside an already-running long-lived storage connection.

Cancellation is an owned-process SIGTERM/reap observation, not an application
Ctrl+C claim. Held refresh returns no token; its handler is released only after
the child is reaped. Cleanup failure is sticky. Raw child output, callback state,
codes, tokens and private paths never enter the sanitized report.

The container supervisor is adapted from the reviewed pCloud supervisor: exact
source closure/runtime hash, immutable base, locked certificate dependencies,
UID/GID 10001, network none, no capabilities, no host mounts or published ports,
read-only root, private bounded tmpfs, finite process/output/time limits and owned
container/image cleanup. Run it only after source review in the dedicated hosted
Linux workflow; do not launch the inner probe or a container on a production host.

The CI workflow has a manual `gcs_oauth_experiment` option, off by default.
It requires the exact `expected_sha` and waits for both platform test jobs and
the Python dependency audit. The hosted job runs this supervisor command once:

```bash
python -B scripts/provider-lab/gcs-oauth/run_container.py \
  --rclone "$RUNNER_TEMP/rclone-gcs-oauth" \
  --report "$RUNNER_TEMP/gcs-oauth-experiment.json"
```

The runtime must first be prepared by the repository's verified Linux downloader.
Mocked checks can run without sockets or native processes:

```bash
python -B -m unittest discover -s scripts/tests -p 'test_provider_gcs_oauth*.py'
```

Local validation: 33 component/pure checks and nine full mocked orchestration
checks pass. The orchestration suite traverses all ten driver cases and the
supervisor's staging, validation, reporting and cleanup using scripted external
boundaries. It checks independent transcripts/config states and injected missing
stages, wrong tokens/options, denial request mismatches, failed cancellation,
uncertain cleanup and malformed receipts. It exposed and fixed a denied-refresh
verdict that did not bind the returned RC input to the exact copy request.

Twelve hosted-only adversarial HTTP/TLS test methods pass on Linux. The first
Windows run failed its final cleanup-verification check in every method; that
failure remains under investigation. The tests skip outside a GitHub-hosted
runner. These component results do not establish native rclone compatibility.
Remaining gates are review, passing wire tests on both hosts, then bounded hosted
native validation of request shapes, config serialization, error causes, timing
and cleanup. Before ledger integration, define a separate strict lifecycle
receipt mode and importer tests. Do not convert historical static-token receipts
into OAuth evidence.

Service-account JWT, ADC, workload identity, IAM, real Google consent/MFA,
application/vendor acceptance and connection/session reauthentication remain
separate unverified requirements.

Pinned references:

- [GCS authentication branches and custom storage endpoint](https://github.com/rclone/rclone/blob/v1.75.1/backend/googlecloudstorage/googlecloudstorage.go#L510-L580)
- [GCS OAuth configuration and scope](https://github.com/rclone/rclone/blob/v1.75.1/backend/googlecloudstorage/googlecloudstorage.go#L58-L85)
- [Callback checks](https://github.com/rclone/rclone/blob/v1.75.1/lib/oauthutil/oauthutil.go#L983-L1041)
- [Refresh and token persistence](https://github.com/rclone/rclone/blob/v1.75.1/lib/oauthutil/oauthutil.go#L289-L357)
- [Basic/form probing and refresh-token handling](https://github.com/golang/oauth2/blob/v0.36.0/internal/token.go#L199-L239)
