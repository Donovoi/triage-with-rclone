# Original runtime cleanup diagnostic

This default-off developer feature observes the original runtime removal in one
existing Windows ARM64 CLI regression. It does not fix cleanup, identify a holder,
or count as application/provider acceptance. Normal CI and release features are
unchanged. Do not run it on a working PC.

The manual-only **Original Windows runtime cleanup trace** workflow requires the
exact reviewed commit. It builds with `runtime-cleanup-trace`, binds the tested
application/runtime SHA-256, and invokes the affected listing test once. Its raw
output stays private. Only the bounded, closed Python-validated JSON is printed.
The original test exit still controls failure even when its trace is valid.
There is no retry or artifact publication. A successful instrumented cleanup is
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
cause. Native collection, session cleanup, bounds and retry behavior are unchanged.

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
