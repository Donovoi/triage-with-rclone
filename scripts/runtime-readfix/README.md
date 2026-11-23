# Experimental rclone read-status regressions

The pinned official rclone 1.76.0 and its SDKs accept some unsuccessful HTTP responses as readable file data. This directory reproduces four provider defects, applies narrowly scoped fixes, and builds a distinctly named experimental runtime: `v1.76.0-triage-readfix.2`.

This recipe does **not** change the application's pinned runtime, downloaders, release artifacts, provider ledger, or acceptance requirements. A passing regression or cross-compilation is not native provider, Windows application, credential lifecycle, or live vendor acceptance.

| Provider | Reproduced failure | Fix and positive checks |
| --- | --- | --- |
| Files.com | Accepts HTTP 403/404/500 bodies; full and empty reads send `bytes=0--1` | Reject unsuccessful status before exposing the body; close it; send a valid range for full and partial reads and no range for empty files |
| ImageKit | Accepts HTTP 403/404/500 bodies; ignores a cancelled context | Backport the upstream download client/context/status fix; retain full, partial and ignored-range HTTP 200 behavior |
| Filen | `DownloadFileChunk` accepts HTTP 206/403/404/500 as a complete chunk; a root-level file produces a literal `.` parent and cannot be listed by the SDK | Require HTTP 200 and close every response; normalize the parent of a root-level file to the empty remote root; retain nested file lookup |
| Proton Drive | `GetBlock` exposes HTTP 206/403/404/500 raw bodies | Require HTTP 200 and close rejected bodies; preserve valid block reads and the existing authentication path |

All denial tests supply the same otherwise valid raw body as the success case. Files.com and ImageKit tests invoke the actual rclone backend against local HTTP servers. Filen and Proton status tests invoke their pinned SDK methods with in-process HTTP transports. A separate Filen constructor regression uses an owned HTTPS server through a CONNECT proxy that dials only that server. Its temporary TLS verification override is confined to the unit test and restored afterward; native provider fixtures must still verify their private CA. The Filen constructor test decrypts synthetic metadata; these regressions do not exercise encrypted file contents or a vendor account. Files.com ignored-range fallback is outside this patch.

The ImageKit patch is a backport of the corresponding backend changes in upstream [rclone source at 2a13b4e](https://github.com/rclone/rclone/blob/2a13b4ee0a1e816fc76a5567643f13b16f8594c1/backend/imagekit/imagekit.go). The other four patches address the independently reproduced failures in the locked rclone/SDK versions.

## Reproduce in a disposable Linux VM

Use Go 1.27.4, Python 3.12+, Git and a C compiler for the race detector. The workflow downloads and checks the Go archive against `build-lock.json`. Use a fresh work directory. The source checkout and writable SDK copies belong to that directory; the shared Go module cache is never patched.

```bash
python3 -B -m unittest discover -s scripts/runtime-readfix -p 'test_*.py'
python3 -B scripts/runtime-readfix/build.py prepare \
  --work-root /tmp/triage-readfix --go /opt/go/bin/go
python3 -B scripts/runtime-readfix/build.py check \
  --work-root /tmp/triage-readfix --go /opt/go/bin/go
for platform in linux-amd64 windows-amd64 windows-386 windows-arm64; do
  python3 -B scripts/runtime-readfix/build.py build \
    --work-root /tmp/triage-readfix --go /opt/go/bin/go --platform "$platform"
done
```

Preparation fetches the exact rclone commit and verifies the Go modules, then copies only the two SDKs needing patches. An optional `--source-repo /path/to/local/mirror` uses the same commit from a local Git mirror. Preparation may access the network. Subsequent commands disable Go module/toolchain downloads; run them in the VM's private network namespace for kernel-enforced network isolation. Only local synthetic server connections are needed for tests.

The check stage parses Go's JSON test events. It requires every named top-level regression and package to fail before patching, and every one to pass after patching and with `-race`. Compile failures, missing tests, and skips cannot satisfy that proof. Patch, original source, patched source, and test hashes are checked. The complete prepared source tree is also hashed, including the owned SDK copies, so changes to other files or newly added files fail validation. Original rclone module manifests stay unchanged; the alternative manifest uses relative replacements for owned SDK copies.

Each build runs twice from different absolute source roots with `-trimpath`, disabled VCS stamping, and CGO disabled. Both executable hashes must match. The receipt binds the recipe files, source commit, Go version, complete source-tree identity, platform, executable hash and size. Linux ELF and each Windows PE machine type are checked. Only the Linux executable is run; the Windows results are cross-build checks.

Outputs remain under the work directory. The experimental workflow retains logs and JSON receipts for 14 days; it publishes no executable or release. Production activation requires separately reviewed distribution pins, native provider evidence, application validation, and the normal complete CI gates.
