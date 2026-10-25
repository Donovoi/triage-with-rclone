# Local calamine security backport

This is a modified copy of the published **calamine 0.36.1** library. It is a local path dependency, not a new or patched crates.io release. The upstream package version stays 0.36.1 and publication is disabled.

Source package: `calamine-0.36.1.crate` from crates.io, SHA-256 `5fa68281b1a76b54a62156474adb06bb380a67e07dd60656e3217152b42183f3`.

Upstream release: [`0a24c2a9f1e38c0932c1299e633270dc730db505`](https://github.com/tafia/calamine/tree/0a24c2a9f1e38c0932c1299e633270dc730db505).

Backported fix: [`c15fefe995e890da206b58542b4e45190f564f30`](https://github.com/tafia/calamine/commit/c15fefe995e890da206b58542b4e45190f564f30). This changes the ZIP dependency from 8.6 to 9.0 and handles the fallible ZIP entry-name APIs in `src/ods.rs`, `src/utils.rs`, `src/xlsb/mod.rs`, and `src/xlsx/mod.rs`. All eight Rust-source patch hunks were applied by exact context match. Other upstream commits after the release were not included; quick-xml remains 0.41 and all calamine features remain unchanged.

The copy retains the complete library source, its included changelog, upstream README, and the unmodified MIT license and copyright notice. Upstream CI files, examples, benchmark, package lockfile and registry metadata are omitted. The published package already excludes its external test fixtures. Library unit-test source remains present; this copy does not claim that the full upstream standalone tests or documentation examples are runnable without those fixtures.

The local Cargo manifest removes the omitted example/benchmark targets and optional author/contact metadata, replaces the generated-manifest heading, and adds `publish = false`. Build scripts and automatic target discovery remain disabled as in the published package. Other dependency constraints and feature flags are unchanged.

Remove this local copy when an official calamine release supports a ZIP version that passes the project's dependency audit. Switch back to the registry dependency, regenerate the real lockfile, and rerun spreadsheet import/export checks and required platform checks. Do not remove or suppress security advisories to make the audit pass.
