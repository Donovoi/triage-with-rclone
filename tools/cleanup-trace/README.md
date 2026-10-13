# Original runtime cleanup diagnostic

This default-off developer feature observes the original runtime removal in one
existing Windows ARM64 CLI regression. It does not fix cleanup, identify a holder,
or count as application/provider acceptance. Normal CI and release features are
unchanged. Do not run it on a working PC.

The manual-only **Original Windows runtime cleanup trace** workflow requires the
exact reviewed commit. It builds with `runtime-cleanup-trace`, binds the tested
application/runtime SHA-256, and invokes only
`cli_imported_listing_empty_remote_publishes_explicit_empty_csv_schema` once.
Compile-only Cargo JSON selects exactly the CLI binary and `cli_acquisition`
harness from this package's ARM64 release output with the trace feature. The
workflow invokes that harness directly with the fixed selector and `--exact`;
it does not rebuild or enumerate tests before execution. CLI, runtime, harness
and build-record hashes must remain unchanged. The validator requires one
completed, non-ignored named test with a result matching the actual native exit.
The additional closed `execution` object binds the harness, build-record and
stdout hashes; the previous validator invocation and record remain readable.

Raw build/test output stays private. Selection reads at most 16 MiB of Cargo JSON;
validation reads at most 4 MiB from each test stream. These are post-exit read
bounds, not disk-growth limits or process-cleanup guarantees. Only the bounded,
closed Python-validated JSON is printed. No raw log is uploaded.
The original test exit still controls failure even when its trace is valid.
The existing empty-listing test forwards only a bounded trace line on app success;
on failure its unchanged assertion already reports stderr privately. There is
no retry or artifact publication. A successful instrumented cleanup is
`not_reproduced`, never evidence of a fix. An unavailable trace fails the job.

Registration uses the existing extraction file handle before child launch. The
trace keeps no additional file or directory handle across removal. The hook runs
only after the existing directory identity/security checks and root-pin release;
it calls the original `remove_dir_all` once and returns the original result.
Existing residue inspection and failure retention remain in place. A read-only
surviving-leaf metadata comparison may run after failure; it cannot authorize
another deletion. File identity, size and write time must still match registration.

The trace accepts only named TDH properties for classic FileIo versions 2/3 with
64-bit headers. It retains at most 128 exact-path Create events, 8,192 OpEnd events,
50,000 callbacks, and sixteen 64 KiB buffers. Exact NT path, actual removing
thread, and QPC interval bind each matching Create/OpEnd pair. Sequential IRP reuse
is permitted; overlap, orphaned/reordered/duplicate ends, foreign-thread reuse,
loss, overflow and unsupported metadata are unavailable. These are collection
bounds, not a Windows attempt-count guarantee.

Correlation failure reports only the first rejected model gate: no selected
start, start ordering, defensive start/end overlap, missing or multiple matching
ends, end callback ordering, an end before its start, an unowned end, or
foreign-thread IRP reuse. These are closed reasons in the existing `reason`
field; no identifiers, paths, timestamps or raw events are exposed. They remain
`unavailable` with null counts and cannot qualify attribution. Predicates and
their order are unchanged. The old `correlation_missing_or_ambiguous` reason is
still accepted for historical records; it cannot be refined retroactively.
Absence of a selected start does not identify a decoder, path, thread or timing
cause. The original correlation gates, session cleanup and retry behavior are unchanged.

Schema 2 adds a diagnostic-only `ownership` object for `correlation_end_multiple`;
it is null for other reasons. Historical schemas 1 and 2 remain readable. The original
model, main counts and status are unchanged: even an observed sequential reuse
chain leaves the trace unavailable. No supplemental field can qualify attribution.

The supplemental collector reserves 8,192 combined begin/end entries, independently
of the original caps. It observes named IrpPtr properties for documented classic
FileIo Create, SimpleOp, ReadWrite, Info and DirEnum starts, plus the original
OperationEnd values. Selected Creates reuse original decoded values; other paths
are never retained. Version 2/3, 64-bit headers and exact eight-byte nonzero pointers
are required. Known name-only events supply no beginnings. Unknown opcodes,
unsupported metadata, allocation/entry limits, loss, uncertain order/window or
teardown leave the witness unavailable with null observations. No extra provider,
thread, lock, handle or wait is introduced; additional TDH decoding changes observer
overhead and cannot be assumed timing-neutral.

Analysis uses the selected IRP from the first multiple-end interval rejected by
the original model. Every relevant end must remain in the observed stream. Strict
callback/QPC order and a closed alternating begin/end chain can show sequential
reuse across non-selected Creates or other operations. An extra end without an
observed begin remains unexplained, not a proven duplicate. Overlapping beginnings
or an incomplete chain retain observed start/end totals but null pair attribution.
The entire observed pre-window prefix must also establish a closed boundary;
an earlier orphan end, overlapping begin or remaining open begin leaves it unknown.
An available supplemental collection does not mean available main correlation.
No identifiers, paths or raw events are emitted; the existing 4,096-byte record cap
and cleanup/time limits remain in force. File-object or holder attribution is not
attempted. See Microsoft [FileIo classes](https://learn.microsoft.com/en-us/windows/win32/etw/fileio)
and [OperationEnd](https://learn.microsoft.com/en-us/windows/win32/etw/fileio-opend).

Schema 3 adds `ownership.rejection`: the first unsupported opcode's numeric
`opcode`, `version` and `header_flags`, or null for other ownership results.
These are unattributed FileIo header values already present at the rejection,
not a file, process, thread or IRP identity. No property query or guessed schema
support is added. The first error retains its own metadata; later events cannot
replace it. Teardown, loss, budget and window overrides still suppress the header.
Unsupported events remain unavailable with null counts and pattern. The record
bound, original correlation, removal and cleanup gates are unchanged. A future
observed header can guide an official version-specific schema lookup; it cannot
refine historical unavailable records or establish a lock holder.

Pure Rust checks can compile an entry point containing only `model.rs` and
`ownership.rs`; neither imports or starts the native collector. The Python tests
also validate the closed supplemental schema and unchanged unavailable outcome.
Compile-only Windows checks do not establish native event delivery or ownership.

Only a failed original OS32 removal together with a bound sharing-violation open
can produce `observed`. A successful open followed by OS32 remains unattributed:
this implementation does not decode disposition events or discover the holder.
Schema rejection describes unattributed FileIo metadata, not the target file.
No path, PID/TID, IRP, handle, event payload or exception text enters the record.

One fixed session is acquired or refused on collision. No existing session is
adopted, no rights are changed, and the owned handle is stopped once. Qualification
requires separately confirmed absence, bounded/zero-loss statistics, ProcessTrace
completion, CloseTrace success and consumer-thread join. Callback storage survives
uncertainty. Native trace control has no caller-supplied timeout; the workflow
deadline is not a cleanup certificate. A killed process may leave uncertainty.
Instrumentation changes timing, and runtime/schema support remains unqualified
until a separately reviewed hosted run. Relative FileIo paths and a delayed write
timestamp may conservatively prevent identity/correlation proof.

The TDH decoder/session allocation is adapted from the reviewed PR80 calibration
source at commit `0fae6a88f1ec0508ec2ad7806df7f2f45b7474be`, source SHA-256
`028ab40a77fb88dec275e102dae5bb65167b3a719f84eeee67552f9d18564faf`.
That tool and its separate owned-failure-directory issue are unchanged. The new
library has its own lockfile, model, output schema and validator. Pure tests cover
correlation, original-result preservation and all independent report gates; they
do not execute ETW, rclone or the application.

Primary semantics: [Rust removal implementation](https://github.com/rust-lang/rust/blob/1.95.0/library/std/src/sys/fs/windows/remove_dir_all.rs),
[FileIo Create](https://learn.microsoft.com/en-us/windows/win32/etw/fileio-create),
[FileIo OpEnd](https://learn.microsoft.com/en-us/windows/win32/etw/fileio-opend),
[session control](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracew).
