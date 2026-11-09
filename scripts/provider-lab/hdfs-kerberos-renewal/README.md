# MIT KDC prerequisite for the HDFS renewal experiment

This fixture prepares a contained MIT Kerberos KDC for a future retained-rclone
service-ticket renewal experiment. Its bootstrap checks ticket issuance,
authentication rejection, and cleanup. It does not run rclone, attempt renewal,
or grant provider, application, vendor, or vulnerability-audit acceptance.

The existing Kerby policy-denial fixture remains separate. A renewable MIT
service ticket requires a renewable TGT; this fixture requests a 120-second TGT
with a 180-second renewal window, followed by a 10-second HDFS service ticket
with a 60-second renewal window. Those values make later service expiry
observable while the original TGT remains valid. Bootstrap success alone does
not demonstrate the later renewal behavior.

## Inputs and containment

`mit-runtime-lock.json` pins 15 Ubuntu packages and 32 selected regular members
by size and SHA-256. Acquisition verifies each complete archive before bounded
passive parsing. The fixture copies only the selected executable/library bytes
and license notices; it does not install packages or run maintainer scripts.
The KDC needs only the pinned image's C library, resolver library, and loader
outside those selected members. Actual mapped files are checked at startup.

The Java client uses the existing 142-JAR `kerberos-remediation` graph. The
Temurin base image, supporting Python helpers, classpath order, package lock,
Java sources, and plan template are bound into the result. Image construction
verifies input checksums before compilation and runs with networking disabled.

Native work is admitted only by the automatic hosted pull-request workflow
`.github/workflows/hdfs-kerberos-renewal.yml`. The container has no external
network or published ports, runs as UID/GID 10001, drops all capabilities, and
uses a read-only root filesystem with a private, bounded `/work` tmpfs.
Synthetic realm/principal/password material is generated inside that container.
The KDC listens only on the owned IPv4 loopback TCP port 18888. The fixture does
not use private provider credentials or browser databases.

The process owner retains every setup child and the foreground KDC, drains
bounded output, applies deadlines, rejects descendants, and verifies process
and stream termination before removing private material. Forced termination or
stream failures prevent success. Outer cleanup checks the exact owned container
and image before removal; shared base images and build caches are excluded.

## Checks and retained evidence

The guarded Python suite covers archive bounds, member selection, deterministic
configuration, acquisition failures, container admission, compiler-error
projection, and result validation. It denies network and native execution:

```text
python -I -S -B scripts/provider-lab/hdfs-kerberos-renewal/run_guarded_tests.py
```

The hosted Java bootstrap first checks pure owner contracts, then requires:

- A renewable TGT and a short-lived renewable HDFS service ticket.
- Typed rejection of a wrong password and an absent principal.
- A successful fresh TGT request after those rejections.
- Reaped request tasks, new threads, owned processes, and private files.

Only the sanitized `mit-kdc-bootstrap-experiment.json` is uploaded. It includes
closed result fields, input hashes, bounded stage/error labels, cleanup
predicates, and compiler categories with fixed source names and line numbers.
Raw command output, package archives, credentials, keytabs, and KDC databases
are not evidence artifacts. Failures remain failures even when cleanup passes.

The bootstrap's native compatibility and lifecycle behavior still require
hosted qualification. Later renewal acceptance must retain the same rclone
process/backend, observe actual service expiry, distinguish a RENEW request
carrying the original service ticket from ordinary TGS fallback, verify a fresh
reply and ticket bounds, and complete a new NameNode RPC. This prerequisite
does not satisfy any of those later acceptance conditions.
