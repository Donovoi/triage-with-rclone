# Original runtime cleanup diagnostic

The current capture contract is trace schema4,
`capture_contract: "window_end_admission_v1"`. Schemas1–3 remain readable as
historical all-lifetime end capture and cannot acquire this marker. No old
unavailable trace is promoted or replayed under the new contract. This remains
diagnostic evidence, not a cleanup fix, holder attribution or provider result.

The original before/after QPC readings are published once through separately
shared atomics (Release). The callback reads after then before (Acquire), once
each; delayed visibility is uncertainty, not permission to wait or resample.
Every successfully decoded end passes the existing schema/TDH checks. Ends
strictly outside the visible window may be omitted with checked counts/extrema;
every in-window end and every IRP/status remain in callback order. Before is
unknown: omitted timestamps must later prove strictly below the actual before.
After is unknown: retain conservatively, with no later eviction or overflow
recovery. The end hard cap8192, actual reserved capacity, start cap128,
callback cap50000 and independent ownership cap8192 remain unchanged.

Successful omitted ends are handed to ownership directly, exactly once, using
the same decode and original callback ordinal. The separate ownership stream
also includes begins/creates and may remain unavailable for its own capacity,
schema, ordering or prefix reason; it supplies no original counts. The new
admission decodes before deciding retention, so schema failure can precede the
capacity reason at a point where the historical vector was already full.

The admission owner is consumed only after stopped/absent/completed/closed/
joined, started/settings, lossless and bounded evidence is true. Uncertain
shutdown retains the existing callback-storage lifetime behavior. Known loss
or bounds uncertainty skips proof/correlation: final assignments retain their
cleanup, loss, bounds, identity and clock order, but can now report STOP-only
loss/bounds rather than an uncomputed historical correlation failure. Those
records have no provisional counts. The original removal runs once and its
original result is returned even if publication or proof fails.

Schema4 requires the exact marker and closed admission reasons. Finish-only
reasons additionally require all nine collection flags true; mixed callback/
publication failures do not borrow that implication. No QPC value, IRP, raw
event, ordinal, path or omitted record is exported. The trace remains bounded
to4096 bytes and supplemental TDH output to8192 bytes.

The isolated workflow first runs the24 named pure admission tests with an
exact-count check, alongside the existing model/schema tests and output checks,
before runtime preparation or the unchanged one native observation. Private
source preparation has only compiled Rust tests, not executed them. Sequential
pure tests cannot establish live atomic delivery, complete drain or a native
fix. Arc adds one fixed setup allocation under Rust's existing allocation
policy; only end reservation failure is explicitly fallible here, not every
possible allocation in the diagnostic.

The current manual target is the exact ARM64 CLI regression
`cli_preserves_remote_identity_and_original_config`. Historical empty-listing
and library artifact/validator modes remain readable. In library mode the
legacy `--application-sha256` argument still must equal the test-harness hash
and is not emitted as a CLI application hash. The new `--cli-acquisition` mode
instead requires the actual CLI application hash and a distinct harness hash.

This default-off developer feature observes the original runtime removal in one
existing Windows ARM64 acquisition regression. It does not fix cleanup, identify a holder,
or count as application/provider acceptance. Normal CI and release features are
unchanged. Do not run it on a working PC.

The manual-only **Original Windows runtime cleanup trace** workflow requires the
exact reviewed commit. It builds with `runtime-cleanup-trace`, binds the tested
application/harness/runtime SHA-256, and invokes only the selected acquisition
test once. Compile-only Cargo JSON selects exactly the `rclone-triage` application
and `cli_acquisition` integration harness from this package's ARM64 release
output with the trace feature and a final successful build record. The
workflow first invokes its fixed `cleanup_diagnostics::tests::` pure-only filter,
requires all five named forwarding unit tests to pass, then invokes the single
acquisition test directly with the fixed selector and `--exact`;
it does not rebuild or enumerate tests before execution. The fixture's existing
compile-time application path, two-remote queue, inherited-environment isolation
and assertions remain unchanged. No library-only dynamic-provider setting is
borrowed: this CLI fixture removes inherited `RCLONE_*` variables.
Runtime, application, harness, build record and source bindings must remain
unchanged. A private pre-build record binds the commit/tree and application-entry
and integration-test source hashes; clean tracked source and exact revision are
checked around the build/test. The validator requires one
completed, non-ignored named test with a result matching the actual native exit.
The closed `execution` object binds those identities and the private stdout
hash. The separate schema result names the same acquisition test and actual
application, never a library executable. Missing/partial/mixed-mode bindings fail.
The pure filter performs only in-memory byte projection and fake-writer checks;
it cannot launch the application or trace. Both harness invocations share the
existing three-minute observation step. Local preparation can compile these
tests without executing the application, collector or integration harness.

Raw build/test output stays private. Selection reads at most 16 MiB of Cargo JSON;
validation reads at most 4 MiB from each test stream. These are post-exit read
bounds, not disk-growth limits or process-cleanup guarantees. Only the bounded,
closed Python-validated JSON is printed. No raw log is uploaded.
The original test exit still controls failure even when its trace is valid.
The selected test captures child stderr. A feature-only success-path forwarder
copies each unique bounded trace/schema record to the private harness stderr;
missing, duplicate or oversized records are not selected or truncated. Selection
is independent, so missing/invalid schema output does not erase a valid original
trace; the unchanged validator preserves that trace and fails the schema gate. Failure
already prints the captured stderr through the original assertion, so it is not
forwarded again. Writer failure is best effort and cannot change that assertion.
The independent Python validator still owns record semantics. No application
invocation, fixture, assertion or cleanup operation changes, and there is no
retry or artifact publication. A successful instrumented cleanup is
`not_reproduced`, never evidence of a fix. An unavailable trace fails the job.
This isolated test does not reproduce the earlier full-suite ordering. If the
failure does not recur it proves only that this instrumented invocation passed;
it cannot identify the earlier holder. Schema1168, unknown events or ambiguous
ends stay unavailable. No Restart Manager or other holder-discovery API is added.

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

## Finite unavailable budget reasons

The original rejecting branches now emit distinct fixed reasons. Historical
`budget_exceeded` records remain readable and cannot be refined retrospectively.
Every reason below still means `unavailable`; none identifies a lock holder,
qualifies cleanup/provider coverage, changes a limit or permits another attempt.

| Reason | What the existing branch establishes |
|---|---|
| `start_reservation_failed` | The existing fallible reservation for the target-start buffer failed. No allocator subcause is reported. |
| `end_reservation_failed` | The existing fallible reservation for the end-record buffer failed. No allocator subcause is reported. |
| `end_capacity_reached` | The end buffer was already at `MAX_ENDS` when the next opcode-76 event reached its capacity check, before its properties were decoded. This is not a target-file end count. |
| `target_start_capacity_reached` | The start buffer was already at `MAX_STARTS` after the existing exact target-path check. |
| `callback_limit_exceeded` | The existing callback counter exceeded 50,000, before the consume/filter call. This is not a relevant-event count. |
| `initial_session_bounds_unverified` | After a successful initial session query and the unchanged settings check, its buffer-bounds predicate was false. The particular failed field is unknown. |
| `final_bounds_proof_unverified` | The accumulated bounds proof was false at the existing final rejection, with no earlier retained reason. Its particular subcause remains unknown. |

The bounds predicate checks `BufferSize` 4–64, minimum buffers 2–16, maximum
buffers at least the minimum and at most 16, and allocated buffer count at most
16. When the existing owned-session stop executes, the final proof combines the
initial predicate with successful stop status and the stop-returned predicate;
it is not a standalone observation of a final
buffer excess. The validator rejects either of these two new bounds reasons
when `bounded=true`; legacy and capacity/reservation reasons retain their
previous bounds behavior. Existing cleanup and event-loss reasons retain their original
precedence. Duration validation is separate (`clock_unavailable`), not a newly
inferred budget category. First-error handling, allocation/callback/storage
caps, decoding, filtering, TDH lookup, removal, teardown, schema fields and exact
test invocation are unchanged. Separate TDH 1168 evidence cannot identify one
of these reasons in an older generic record.

## Separate installed-schema observation

On the first existing supplemental `UnsupportedOpcode` rejection, after retaining
that original error, the same callback may call `TdhGetEventInformation` exactly
once into an already allocated, aligned 64 KiB buffer. There is no size probe,
resize, retry, second lookup, payload decoder or pointer retained after callback.
Allocation failure is diagnostic-only and does not alter the original collector.
Other original decoder failures are not broadened into a new capture route.

The parser uses pinned windows-sys 0.61.2 SDK structures and `offset_of`, not
handwritten payload offsets. It requires returned provider and full descriptor
identity, documented XML/WBEM decoding source, at most 16 flat descriptors,
bounded offsets/terminators and ASCII schema identifiers of at most 64 characters.
Unknown flags, structures, maps, tags, custom schema, out-of-array count/length
references, malformed names and identity disagreement remain unavailable.
Descriptors contain only schema names and numeric types/flags/count/length
metadata; these values are not interpreted as event data. No process/thread/IRP
identity, path, raw schema, message template or event payload is retained or
printed. An available schema does not tie this unattributed FileIo event to our
runtime or a holder. Opcode acceptance and correlation remain unchanged.

The existing `runtime_cleanup_trace` record and its 4,096-byte limit are unchanged.
A separate `runtime_cleanup_schema` record is at most 8 KiB. After existing trace
shutdown, loss, bounds, session configuration, stop/absence, consumer closure,
join or operation-window uncertainty suppresses usable schema metadata. Missing
or malformed metadata cannot become available. No unsupported event and
allocation failure without a TDH call remain distinct from a failed TDH status.
Original failure and cleanup precedence is unchanged when metadata succeeds.

Library and closed acquisition modes write a separate create-only private schema result,
binding the exact original-trace SHA256, commit, harness, build record and runtime;
the acquisition mode additionally binds the actual application and source hashes,
then prints its bounded sanitized representation. It never merges schema fields
into original counts or reasons. Existing test/step supervision is unchanged:
TDH has no timeout parameter, so one-call and byte bounds are not an API latency
guarantee. Callback overhead/resource lookup can perturb timing. Uncertain
shutdown or missing output remains unavailable, never a cleanup certificate.

Source preparation runs guarded Python contracts and compiles the three Rust
schema-parser cases without executing them or the native collector. The manual
hosted workflow separately runs only the fixed `schema_metadata::tests` filter
with a strict exit check before its single diagnostic invocation. An isolated
successful target is not reproduction or disproof of the earlier suite failure.
Missing or malformed supplemental metadata preserves the independently validated
original trace, emits a separate closed validation failure, and returns nonzero.
Official references: [TDH lookup](https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhgeteventinformation),
[TRACE_EVENT_INFO](https://learn.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-trace_event_info),
[EVENT_PROPERTY_INFO](https://learn.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-event_property_info),
and [EVENT_HEADER](https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header).

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
