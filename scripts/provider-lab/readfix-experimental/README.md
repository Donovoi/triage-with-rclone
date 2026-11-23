# Experimental native reads for the four remaining backends

These tests exercise actual rclone backend code with the hash-bound `v1.76.0-triage-readfix.2` experimental runtime. They do not change the application runtime or the provider acceptance ledger. The maintained official-runtime profiles remain 59 of 63 selectable providers; these four experiments are additional synthetic coverage with an explicitly different runtime.

| Backend | Native commands | Exercised behavior |
| --- | ---: | --- |
| Files.com | 19 | Configured API key, metadata and direct links, complete and partial plaintext reads, wrong key and missing object rejection, HTTP denial with valid data, native delete rejection |
| ImageKit | 21 | Private API key and signed download URLs, root/nested metadata, encoded spaces, complete/partial/ignored-range reads, wrong key/missing object rejection, HTTP denial with valid data, native delete rejection |
| Filen | 25 | Saved v2 account, encrypted metadata and one-chunk AES-GCM file reads, root/nested files, plaintext ranges, wrong API/master keys, missing files, valid ciphertext under HTTP denial, tampered authentication tag, direct fixture mutation guard |
| Proton Drive | 26 | Saved session, user/address/share/folder/file key hierarchy, signed names and attributes, file session keys, encrypted blocks and detached signatures, root/nested reads and ranges, wrong credentials/key, missing files, HTTP denial, ciphertext/hash/signature tampering, direct fixture mutation guard |

Expected plaintext sizes and SHA-256 hashes come from the shared three-file synthetic manifest. The Proton generator uses the pinned OpenPGP library to construct fresh fixture keys and ciphertext; it does not call the backend being tested or derive expected plaintext from a download. Native tamper checks reach both `cat` and exact-object copy paths, observe the modified response on the fixture server, and require no accepted output.

Each provider runs as UID 10001 in its own read-only container, with no network interfaces except loopback, no capabilities, no privilege escalation, a 512 MiB memory limit, one CPU, 96 processes, and a private temporary filesystem. Fixed API names resolve only inside that container. Filen, ImageKit, and Proton verify fresh private CAs and exact SNI/Host authorities. No host DNS or certificate store is changed. Proton needs up to 512 bounded TLS connections because each fresh native command reconstructs its saved-session key hierarchy; active connections remain capped at four and request/lifetime deadlines remain enforced.

The controller verifies the complete prepared source tree, all six baseline/fixed/race regression outcomes, the recipe identity, executable architecture and hash, and the reproducible Linux build receipt before execution. It builds the Proton generator twice in different directories and requires identical binaries. Docker inputs use the digest-pinned Python base and hash-locked dependencies already maintained by the provider lab. Reports bind the copied fixture source hashes, generator hash, container image, and runtime identity. A missing command, skipped capability, missing denial witness, TLS error, active worker, runtime mismatch, or failed cleanup rejects the result.

Successful configurations remain byte-identical. Proton intentionally clears its four saved credential fields after an invalid session or key; the probe requires exactly those changes and preserves every other option. All fixture source bytes, ciphertext, and metadata remain unchanged. Generated account material and private certificates stay in the container's temporary filesystem and are destroyed with the container. Retained artifacts contain sanitized receipts and logs, not keys, configuration files, or binaries.

## Running in a disposable Linux VM

First prepare, check, and build Linux with the [experimental runtime recipe](../../runtime-readfix/README.md). Then use its exact work root and pinned Go toolchain:

```sh
python3 -B scripts/provider-lab/readfix-experimental/run.py   --work-root /path/to/experimental-readfix   --go /path/to/go/bin/go   --output /path/to/new-native-results
```

The output directory must not exist and must be outside the repository. A resource-managed VM can additionally pass `--cgroup-parent triage-lab.slice`; the slice must already exist. The controller creates owned containers and removes them by the exact returned IDs. It retains source/build material inside the new output directory for review.

Wire and receipt tests use the lab's pinned Python dependencies:

```sh
python3 -B -m unittest discover -s scripts/provider-lab/readfix-experimental -p 'test_*.py'
```

The experimental GitHub workflow runs these tests, all runtime regressions, four reproducible target builds, and all four native experiments. Windows builds are cross-compilation checks; these native fixtures currently run on Linux.

## Limits

No live vendor account, first login, 2FA, renewal, recovery, revocation, or Windows application acceptance is claimed. Filen does not cover legacy metadata, multi-chunk data, or its optional BLAKE3 metadata. Proton covers v4 keys and pre-crypto-refresh file content, not v6/AEAD formats, multi-block files, revision history, or sharing. Filen and Proton mutation tests invoke the fixture guard directly, not backend writes. Neither the experimental runtime nor passing synthetic tests qualifies a provider against the application's official runtime.

The pinned backend and SDK sources are identified by the runtime recipe. Proton wire structures additionally follow [Proton-API-Bridge v1.0.5](https://github.com/rclone/Proton-API-Bridge/tree/9d772d08d663a66cedbcbef759dd764cce7c8def) and [go-proton-api v1.0.4](https://github.com/rclone/go-proton-api/tree/4e6ddcf7354cbb9f766580bd60823f50e9af61d7).
