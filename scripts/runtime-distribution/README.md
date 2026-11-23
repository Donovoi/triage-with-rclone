# Verified experimental runtime archives

This packager turns the pinned readfix recipe into four deterministic ZIP files:
Linux amd64 and Windows x64, x86, and ARM64. It does not publish a release, replace
the application runtime, or qualify a provider for live-account acceptance.

Run after the recipe and all four native experiments have succeeded:

```sh
python3 -B scripts/runtime-distribution/package.py \
  --work-root /path/to/verified-readfix \
  --native-report /path/to/native-readfix/report.json \
  --output /path/to/new-distribution-directory
```

The output directory must be new and outside this checkout. The packager requires
the current source tree and recipe, all six failing-before/passing-after
regressions and their passing race runs, four matching reproducible builds, and
the current native-provider report with passing checks and complete cleanup.
Binary hashes, sizes, architectures, distinct patched version, toolchain, source
inventory, and execution scope must match. Windows execution remains unverified;
those builds are cross-compiled.

Each archive contains the runtime executable, its source provenance, the pinned
build lock and five patches, and the runtime and modified SDK copyright notices.
Stored ZIP entries have a fixed timestamp, order, and permissions. Packaging runs
twice and requires identical archive hashes, CRCs, member inventories, and member
hashes. Input modification times, host permissions, and zlib versions cannot
change the archive bytes.

`distribution.json` records each archive and executable hash and size.
`SHA256SUMS` lists the archives. The `repeat/` directory holds the second copies
for local comparison; CI uploads only the first copies and the two manifests.

The experimental workflow runs the packaging tests, builds and exercises the
runtime, then retains verified archives as a separate 14-day Actions artifact.
These are experimental artifacts; the application's official upstream runtime
pin and download locations remain unchanged.
