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

Schema 3 includes `queried_session_settings`: null until the owned session query
succeeds, otherwise exactly three unsigned 32-bit values: `enable_flags`,
`log_mode`, and `clock_selector`. Requested values remain `0x16000000`,
`0x12000100`, and `1` respectively. At the existing equality gate, a difference
still stops before the consumer or probe with `session_configuration_mismatch`.
Cleanup uncertainty can still override that reason. The settings only explain
the gate; they do not establish usable event delivery.

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

## Checks during development

`python -B test_pure.py` checks the output contract without native or network calls.
`cargo check --locked --all-targets` and `cargo clippy --locked --all-targets -- -D warnings`
compile the Windows code and tests without running them. Native tests and the
helper itself belong in the isolated hosted workflow.

API references: [StartTraceW](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracew),
[ControlTraceW](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracew),
[ProcessTrace](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-processtrace),
[CloseTrace](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-closetrace),
[FileIo Create](https://learn.microsoft.com/en-us/windows/win32/etw/fileio-create),
[FileIo OpEnd](https://learn.microsoft.com/en-us/windows/win32/etw/fileio-opend).
