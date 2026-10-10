# Windows file-operation calibration

This developer tool checks whether a hosted Windows ARM64 runner can report both
the start and result of one deliberately denied file open. It helps prepare an
investigation of intermittent Windows cleanup failures. It does not identify the
cause of those failures or count as a provider test.

## Where it runs

Use the **Windows FileIo calibration** workflow. A PR changing this tool runs the
workflow against its merge commit. A manual run requires the exact reviewed commit.
The job records the tested commit and helper executable SHA-256. It runs the Rust
correlation tests and Python output tests before building and running the helper
once. An unavailable result fails the job; it must be investigated before another run.

Do not run the helper on a working PC. Its architecture and GitHub-hosted runner
checks are a guard, not proof that a machine is isolated. The production app and
rclone are not part of this test.

## What it does

1. Create a new temporary directory and one empty file. Keep their original
   handles open, verify their identities, and deny delete sharing on both.
2. Start one named, real-time FileIo trace using existing permissions. Refuse a
   session collision. Never adopt or stop another session or change privileges.
3. Try one DELETE-access open, without deleting anything. Require a sharing
   violation and matching FileIo Create/OpEnd records within the measured interval.
4. Stop the owned session once, verify its absence and zero loss counters, and
   wait for the consumer to finish. Keep callback storage alive until it is closed.
5. Recheck the original handles, delete the owned file and directory through
   those handles, and verify absence. Unknown identity or cleanup fails the test.

Trace buffers are capped at 16 of 64 KiB. Event storage and callback counts are
bounded. Other paths are discarded; raw events, paths, process IDs and stderr are
not published. The output validator accepts only the finite result schema.

Schema 5 includes `queried_session_settings`: null until the owned session query
succeeds, otherwise exactly three unsigned 32-bit values: `enable_flags`,
`log_mode`, and `clock_selector`. Requested values are `0x16000000`,
`0x12400100`, and `1` respectively. At the existing equality gate, a difference
still stops before the consumer or probe with `session_configuration_mismatch`.
Cleanup uncertainty can still override that reason. The settings only explain
the gate; they do not establish usable event delivery.

`schema_rejection` is null unless the consumer returns a first schema rejection.
The single latched record contains only `attribution: "unattributed_fileio"`, a
closed `stage` and `property` selector, opcode (64 or 76), version (u8), header
flags (u16), and nullable TDH status/size (u32). The header gate precedes thread
and path filtering: even a sharing violation from the probe does not bind this
diagnostic to the owned file. It can describe unrelated FileIo traffic.

| Stage | Recorded query information |
| --- | --- |
| `version`, `header_flags` | No property, TDH status or size |
| `tdh_size` | Known property and failed size-query status; size is null |
| `property_bound` | Known property, successful query status and rejected size |
| `tdh_read` | Known property, failed read status and successfully queried size |
| `numeric_width`, `path_encoding` | Known property, successful read status and queried size |
| `correlation_shape` | `IrpPtr` or `ShareAccess`; no TDH status or size |

Property selectors are limited to `TTID`, `IrpPtr`, `NtStatus`, `OpenPath` and
`ShareAccess`, constrained by opcode and stage. No property values, paths, IDs,
IRP values, payloads or arbitrary property names enter the record. The final
shape check retains only the already inspected Create header alongside its
existing correlation state. A rejection stops decoding as before; no additional
TDH calls are made. Loss and cleanup errors retain their existing precedence.
An incomplete consumer cannot certify that no rejection occurred. The validator
requires a diagnostic for `schema_unavailable`, rejects a diagnostic with any
success/pair claim, and retains the 2 KiB output limit.

Schema 5 supports exactly classic FileIo versions 2 and 3 under the existing
64-bit-header requirement. Named TDH lookups must return these exact widths:

| Event/property selector | Version 2 | Version 3 |
| --- | --- | --- |
| Create `TTID` | Pointer, 8 bytes | u32, 4 bytes |
| Create/OpEnd `IrpPtr` | Pointer, 8 bytes | Pointer, 8 bytes |
| Create `ShareAccess` / OpEnd `NtStatus` | u32, 4 bytes | u32, 4 bytes |
| Create `OpenPath` | Bounded, null-terminated UTF-16 | Same encoding and bound |

The [Microsoft v2 MOF](https://learn.microsoft.com/en-us/windows/win32/etw/fileio-create)
qualifies TTID as a pointer. Microsoft's
[TraceEvent Create parser](https://github.com/microsoft/perfview/blob/main/src/TraceEvent/Parsers/KernelTraceEventParser.cs#L5605-L5742)
distinguishes classic v2/v3 layouts and reads v3 TTID as u32; its
[OpEnd parser](https://github.com/microsoft/perfview/blob/main/src/TraceEvent/Parsers/KernelTraceEventParser.cs#L6221-L6242)
retains pointer IRP and u32 status fields beyond v2. These implementations support
the expected widths, but do not establish which property names the hosted TDH
metadata will resolve. The helper still requires the existing named lookups to
succeed, then validates sizes and encoding; missing metadata or any mismatch is
unavailable. It uses no payload offsets, fallback names, extra property queries,
unknown versions or additional bitness. All correlation, loss, budget, session
and cleanup gates remain unchanged.

Windows trace control calls have no caller-supplied timeout. The workflow's time
limit is an outer bound, not evidence that tracing or cleanup finished. A missing
result, lost events, unsupported schema or uncertain cleanup cannot pass.

## First hosted result

[PR80 calibration run 38025537018, job 114135484634](https://github.com/Donovoi/triage-with-rclone/actions/runs/38025537018/job/114135484634)
tested merge `c18dd9213bd677b6794ef66dc8280d074a66a0f5` from head
`6ece1115154bb172410088299048aaedff095c26`; helper SHA-256 was
`c139193bcc4f88ce6eb6344a27e669af043203d489237bbb968deeeff53abf1a`.
Its schema-2 result was unavailable before the consumer or probe: the session
started within budget, recorded zero loss, stopped with verified absence, and
the owned file and directory were cleaned. Source and the result identify the
returned-session-settings equality gate, but that schema did not record which
setting differed. This was one cleanly stopped unavailable calibration, with no
operation-pair or provider evidence. Schema 3 exposes only those missing settings;
the strict gate, permissions, single probe and cleanup contract are unchanged.

The next [run 38025957517](https://github.com/Donovoi/triage-with-rclone/actions/runs/38025957517)
at head `0fb4893e9abddcd73b05a97fb52b20e1aab2ef2e`, tested merge
`b0f7e966194d4d1651c4be9766a831799160f2c8`, reported only one difference:
mode `0x12400100` instead of `0x12000100`. Its helper SHA-256 was
`ea02ba468fa55179e8e334c9cd88ec9feebaef45a644a2a619586214d763ef80`.
The added bit is `EVENT_TRACE_STOP_ON_HYBRID_SHUTDOWN`. Microsoft's
[logging-mode contract](https://learn.microsoft.com/en-us/windows/win32/etw/logging-mode-constants)
states that ETW chooses a shutdown default when neither shutdown mode is requested.
The helper now requests the stop-on-shutdown mode explicitly and still requires an
exact returned match. It does not accept unknown mode bits or request persistence.
This second unavailable run also verified session stop and owned-file cleanup
before any consumer or probe. It provides no operation-pair or provider evidence.

The [run 38026166705, job 114137351565](https://github.com/Donovoi/triage-with-rclone/actions/runs/38026166705/job/114137351565)
at head `b9d1c88d68f2b0779cf7e7cb5ae407959bd2eb32` reached the single probe and
reported a sharing violation. Queried settings matched, the consumer completed,
buffers remained bounded and lossless, and session stop, identities and cleanup
were verified. It remained unavailable with `schema_unavailable` and no pair.
Schema 3 did not expose the rejected record's version, flags, property or TDH
status, so none is established by that run. Schema 4 supplies only that missing
diagnostic; it does not accept additional event versions or property widths.
This unavailable calibration provides no provider or cleanup-cause evidence.

The schema-4 [run 38027091425, attempt 1, job 114140125431](https://github.com/Donovoi/triage-with-rclone/actions/runs/38027091425/job/114140125431)
tested merge `60b1e4fe992500e394a2167935f3edd9f941d04d`; helper SHA-256 was
`b7a417e95f51ff059ba657efdced7e67d31d9e1308d83d1096d40ed62d10cfee`.
Its 22 Python and four Rust tests passed. The single probe returned sharing
violation 32; the consumer completed, buffers were bounded and lossless, and
session stop, original identities and owned cleanup were verified. The result
remained `schema_unavailable`, with no pair: its first rejection was Create
opcode 64, version 3, flags 832 (`0x340`), at the version gate before any property
query. It was explicitly `unattributed_fileio`; it establishes neither an owned
Create record nor an OpEnd version or TDH property metadata. Schema 5 permits the
narrow v2/v3 decoding attempt described above. This observation supplies no
operation-pair, provider or cleanup-cause acceptance.

## Checks during development

`python -B test_pure.py` checks the output contract without native or network calls.
The compile-only commands `cargo check --locked --all-targets` and
`cargo clippy --locked --all-targets -- -D warnings` require a Windows Rust target.
On other build hosts, install that target's standard library and add
`--target aarch64-pc-windows-msvc` to match the workflow. These commands compile
without running the helper or tests. Native tests and the helper itself belong
in the isolated hosted workflow.

API references: [StartTraceW](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracew),
[ControlTraceW](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracew),
[ProcessTrace](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-processtrace),
[CloseTrace](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-closetrace),
[FileIo Create](https://learn.microsoft.com/en-us/windows/win32/etw/fileio-create),
[FileIo OpEnd](https://learn.microsoft.com/en-us/windows/win32/etw/fileio-opend).
