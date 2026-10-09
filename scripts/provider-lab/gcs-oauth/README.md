# GCS OAuth lifecycle

The default command runs an unqualified synthetic experiment and emits schema 1
with `ledger_eligible: false`. Historical experiment receipts remain ineligible.
The [complete experiment](https://github.com/Donovoi/triage-with-rclone/actions/runs/37904440577)
at `d55b124` passed ten cases, 115 checks and all cleanup checks; it is not a
qualified lifecycle receipt. Qualification requires its own fresh hosted run;
the historical experiment cannot supply that evidence.

Use `--lifecycle-evidence` for a fresh schema-6 `gcs_oauth_lifecycle_v1` receipt.
The hosted Linux supervisor checks the pinned runtime, nine source files, image
and dependency locks, network-none isolation, bounded processes and owned cleanup.
The importer requires all ten ordered cases and their exact observations: 34
native commands, 18 callback requests and 31 HTTPS requests. A failed run remains
failed even if another receipt passes. Only an ordered prefix ending in a failed
case may omit later cases.

The cases cover fresh callback/exchange/persistence and an independently hashed
read; wrong or blank callback state; denied consent; invalid code/client secret;
callback cancellation; actual token expiry followed by refresh and replacement
read; denied refresh; and cancellation during a held refresh. Expiry must pass
on the wall clock without editing the saved token. The loopback RC denial has
exactly `error`, `path` and `status`, and its launched request is bound separately.

Lifecycle evidence contributes only authentication, refresh, renewal denial and
owned-process cancellation cleanup. Full GCS local qualification also requires
the separate eight-check static-token inventory/config-preservation mode.
Windows retains that complete baseline gate and reports lifecycle as unverified;
combined Linux and nightly ledgers require both modes from the same workflow run.

No real Google consent/IAM, revocation, session reauthentication, service-account
JWT, ADC, workload identity, application or vendor acceptance is claimed. The
runtime uses only synthetic credentials, explicit CA trust and owned loopback
services inside a nonroot container with no network, host mounts or published
ports. Raw configuration, credentials, transcripts and images are never artifacts.

Pure/mock qualification tests can run locally; hosted wire tests and native
experiments must remain on the reviewed hosted runners. Do not launch the probe,
rclone or Docker on a production host.

Pinned source references:

- [GCS OAuth configuration](https://github.com/rclone/rclone/blob/v1.75.1/backend/googlecloudstorage/googlecloudstorage.go)
- [Callback, refresh and persistence](https://github.com/rclone/rclone/blob/v1.75.1/lib/oauthutil/oauthutil.go)
- [Loopback RC error envelope](https://github.com/rclone/rclone/blob/v1.75.1/cmd/rc/rc.go)
- [Token exchange and refresh](https://github.com/golang/oauth2/blob/v0.36.0/internal/token.go)
