"""Failure-only projection of a bounded private libtest log; never prints raw text."""
import json
import re
import sys
from pathlib import Path

MAX_LOG = 262144
MAX_OUTPUT = 4096
NAMES = frozenset({
    "stable_snapshots_repeat_but_regressions_and_changes_reject",
    "invalid_missing_and_mismatched_bounds_are_unavailable",
    "delayed_before_requires_strict_omission_proof_including_equal_boundary",
    "all_irps_statuses_and_inclusive_boundaries_keep_callback_order",
    "invalid_timestamps_are_sticky_even_outside_window",
    "hard_cap_and_unknown_after_overflow_never_recover_or_evict",
    "reservation_failure_is_unavailable_without_a_partial_admission_owner",
    "actual_zero_capacity_and_injected_small_capacity_reject_without_allocation",
    "outside_omission_at_full_capacity_does_not_evict_any_retained_candidate",
    "handoff_keeps_omitted_and_rejected_decoded_values_without_ownership_claim",
    "inconsistent_omission_summaries_and_missing_retained_record_are_unavailable",
    "actual_correlator_reasons_reuse_status_and_order_are_preserved",
    "equal_window_and_max_saturation_preserve_actual_correlator_behavior",
    "over_old_lifetime_cap_is_new_admission_not_equivalent_old_acceptance",
    "exhaustive_small_complete_streams_match_the_actual_unchanged_correlator",
    "publication_is_once_but_stable_snapshot_reads_repeat",
    "invalid_publication_never_changes_an_existing_bound",
    "publication_failure_does_not_repeat_or_replace_original_result",
    "every_capture_gate_keeps_unqualified_owner_intact",
    "complete_proof_consumes_once_and_binds_the_final_snapshot",
    "omitted_end_handoff_preserves_ownership_prefix_uncertainty",
    "ownership_budget_stays_independent_of_successful_omission",
    "stop_only_loss_and_bounds_skip_even_a_failing_pending_proof",
    "closed_reason_mapping_and_capture_marker_are_exact",
})


def summarize(raw, cargo_exit):
    if type(cargo_exit) is not int or not -(2**31) <= cargo_exit < 2**31 or cargo_exit == 0:
        raise ValueError("failure_exit_required")
    value = dict(schema=1, scope="admission_tests_failure", cargo_exit=cargo_exit,
                 status="unavailable", reason="read_failed", failed_tests=None)
    if raw is None:
        return value
    if type(raw) is not bytes:
        raise ValueError("bytes_required")
    if not 0 < len(raw) <= MAX_LOG:
        value["reason"] = "log_bound"
        return value
    try:
        lines = raw.decode("utf-8-sig", errors="strict").splitlines()
    except UnicodeError:
        value["reason"] = "log_encoding"
        return value
    cases, summaries, running = {}, [], []
    for line in lines:
        if line.startswith("running "):
            running.append(line)
        elif line.startswith("test result:"):
            summaries.append(line)
        elif line.startswith("test "):
            match = re.fullmatch(r"test admission::tests::([a-z0-9_]+) \.\.\. (ok|FAILED)", line)
            if match is None or match[1] not in NAMES or match[1] in cases:
                value["reason"] = "case_unrecognized_or_duplicate"
                return value
            cases[match[1]] = match[2]
    if running != ["running 24 tests"] or set(cases) != NAMES or len(summaries) != 1:
        value["reason"] = "incomplete_or_ambiguous"
        return value
    match = re.fullmatch(r"test result: FAILED\. ([0-9]{1,2}) passed; ([0-9]{1,2}) failed; 0 ignored; "
                         r"0 measured; [0-9]{1,6} filtered out; finished in [0-9]{1,6}(?:\.[0-9]{1,9})?s", summaries[0])
    failed = sorted(name for name in NAMES if cases[name] == "FAILED")
    if match is None or not failed or (int(match[1]), int(match[2])) != (24-len(failed), len(failed)):
        value["reason"] = "summary_inconsistent"
        return value
    value.update(status="complete_failure", reason="none", failed_tests=failed)
    return value


def main(argv=None):
    # All exceptional paths are silent. The workflow has already saved/printed
    # the original Cargo exit and retains its original throw regardless of us.
    try:
        args = list(sys.argv[1:] if argv is None else argv)
        if len(args) != 4 or args[0] != "--log" or args[2] != "--cargo-exit":
            return 2
        if re.fullmatch(r"-?(0|[1-9][0-9]{0,9})", args[3]) is None:
            return 2
        cargo_exit = int(args[3])
        summarize(None, cargo_exit)  # Reject success/invalid exits before I/O.
        try:
            with Path(args[1]).open("rb") as stream:
                raw = stream.read(MAX_LOG + 1)
        except (OSError, ValueError):
            raw = None
        value = summarize(raw, cargo_exit)
        encoded = "admission_test_failure=" + json.dumps(value, sort_keys=True, separators=(",", ":"))
        if len(encoded.encode("ascii")) + 1 > MAX_OUTPUT:
            return 2
        print(encoded)
        return 0
    except BaseException:
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
