# Isolated gokrb5 authenticator-usage regression

This experiment compiles the published gokrb5 v8.4.4 source and its published dependency graph with a pinned Go 1.26.10 toolchain. It compares five synthetic constructor cases in three variants:

| Case | Published source | Context fix | Deliberate global change |
| --- | --- | --- | --- |
| TGT ordinary TGS, AES-128 | 7 | 7 | 7 |
| Service renewal, AES-128 | 11 | 7 | 7 |
| Service renewal, AES-256 | 11 | 7 | 7 |
| Ordinary HDFS AP, AES-128 | 11 | 11 | 7 |
| Ordinary HTTP AP, AES-128 | 11 | 11 | 7 |

The minimal patch selects usage 7 in TGSReq.setPAData. NewAPReq retains its existing default selection, including usage 11 for service authentication. The intentionally overbroad variant forces usage 7 for every AP request and must fail the two ordinary-service requirements. A passing experiment requires the exact three distinct patterns, canonical authenticators and ticket bindings, request-body checksums using usage 6, and rejection of wrong keys, corrupted ciphertext, wrong usage and changed request bodies.

This is a constructor regression. It does not contact a KDC, run rclone, prove successful service renewal, qualify any provider or audit vulnerabilities. The original gokrb5 dependency graph includes older modules and is not rclone's full current dependency graph. The production rclone pin and application are unchanged. Later qualification must bind a patched rclone build to its own dependency graph and actual service-renewal lifecycle.

## Boundaries

The workflow runs automatically on relevant pull requests with read-only permissions, pinned actions and no secrets. Host work is limited to guarded Python tests, public pinned downloads, passive archive processing and the existing bounded Docker supervisor. Go and compiled probes execute only in a pinned Linux image; builds and runs have no network. CGO, toolchain switching, telemetry, ambient Go configuration and dependency lookup are disabled.

The lock contains 16 source ZIPs, 54 module files, 16 version metadata files and one Go toolchain archive. Exact size and SHA-256 bind every download; published Go Hash1 values bind source ZIPs and module files. Archives reject traversal, links, special files and excessive expansion. Download processing has an owned 300-second worker and explicit kill/reap handling. Container execution is limited to 45 seconds, with a separate 10-second limit for each variant, read-only root, UID 10001, private namespaces, no capabilities, no new privileges, 128 PIDs, 2 GiB RAM, 2 CPUs and a 32 MiB private tmpfs. All owned containers, images, contexts and raw command output are removed and checked. Shared base-image and build caches are explicitly excluded from cleanup.

Only a bounded, closed-schema JSON report is retained. It contains source hashes, image identities, dependency versions/checksums, finite constructor observations and cleanup results. Synthetic keys, authenticators and ticket bytes are never reported.

## Local checks

Run only the pure contracts locally:

    python -I -S -B scripts/provider-lab/hdfs-gokrb-usage/run_guarded_tests.py

Native execution belongs to the automatic hosted workflow. Do not invoke the container runner on an analyst workstation.

The two patched Go files derive from gokrb5 v8.4.4 under the accompanying Apache-2.0 license. Original archive and source hashes are recorded in assets-lock.json.
