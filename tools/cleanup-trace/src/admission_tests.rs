use super::*;
use crate::model::{correlate, Start};

fn bounds(before: i64, after: i64) -> Snapshot {
    Snapshot {
        before: Some(before),
        after: Some(after),
    }
}

fn end(qpc: i64, irp: u64) -> End {
    End {
        qpc,
        irp,
        status: 0,
    }
}

fn start(qpc: i64, irp: u64) -> Start {
    Start {
        qpc,
        irp,
        tid: 3,
        share: 7,
    }
}

fn triples(ends: &[End]) -> Vec<(i64, u64, u32)> {
    ends.iter()
        .map(|end| (end.qpc, end.irp, end.status))
        .collect()
}

fn project(ends: &[End], unknown_after: bool) -> ProvenEnds {
    let mut admission = Admission::new().unwrap();
    let snapshot = if unknown_after {
        Snapshot {
            before: Some(2),
            after: None,
        }
    } else {
        bounds(2, 5)
    };
    for end in ends {
        assert!(!matches!(
            admission.decoded_end(*end, snapshot).decision,
            Decision::Rejected(_)
        ));
    }
    admission.observe(bounds(2, 5)).unwrap();
    admission.finish(2, 5).unwrap()
}

#[test]
fn stable_snapshots_repeat_but_regressions_and_changes_reject() {
    let mut admission = Admission::new().unwrap();
    admission.observe(Snapshot::default()).unwrap();
    admission.observe(Snapshot::default()).unwrap();
    admission
        .observe(Snapshot {
            before: Some(2),
            after: None,
        })
        .unwrap();
    admission
        .observe(Snapshot {
            before: Some(2),
            after: None,
        })
        .unwrap();
    admission.observe(bounds(2, 5)).unwrap();
    admission.observe(bounds(2, 5)).unwrap();
    assert!(admission.finish(2, 5).is_ok());
    for snapshot in [
        Snapshot::default(),
        Snapshot {
            before: Some(2),
            after: None,
        },
    ] {
        let mut admission = Admission::new().unwrap();
        admission.observe(bounds(2, 5)).unwrap();
        assert_eq!(admission.observe(snapshot), Err(Reason::BoundsRegressed));
    }
    for snapshot in [bounds(1, 5), bounds(2, 6)] {
        let mut admission = Admission::new().unwrap();
        admission.observe(bounds(2, 5)).unwrap();
        assert_eq!(admission.observe(snapshot), Err(Reason::BoundsChanged));
    }
}

#[test]
fn invalid_missing_and_mismatched_bounds_are_unavailable() {
    for snapshot in [
        bounds(0, 5),
        bounds(2, 1),
        Snapshot {
            before: None,
            after: Some(5),
        },
    ] {
        let mut admission = Admission::new().unwrap();
        assert_eq!(admission.observe(snapshot), Err(Reason::InvalidBounds));
    }
    assert_eq!(
        Admission::new().unwrap().finish(2, 5).unwrap_err(),
        Reason::BoundsUnpublished
    );
    for (before, after) in [(1, 5), (2, 6)] {
        let mut admission = Admission::new().unwrap();
        admission.observe(bounds(2, 5)).unwrap();
        assert_eq!(
            admission.finish(before, after).unwrap_err(),
            Reason::BoundsMismatch
        );
    }
}

#[test]
fn delayed_before_requires_strict_omission_proof_including_equal_boundary() {
    for (qpc, expected) in [
        (1, None),
        (2, Some(Reason::UnpublishedOmissionUnproved)),
        (6, Some(Reason::UnpublishedOmissionUnproved)),
    ] {
        let mut admission = Admission::new().unwrap();
        assert_eq!(
            admission
                .decoded_end(end(qpc, 7), Snapshot::default())
                .decision,
            Decision::OmittedBeforePublication
        );
        admission.observe(bounds(2, 5)).unwrap();
        assert_eq!(admission.finish(2, 5).err(), expected);
    }
    let mut admission = Admission::new().unwrap();
    admission.decoded_end(end(6, 7), Snapshot::default());
    admission.decoded_end(end(1, 7), Snapshot::default());
    admission.observe(bounds(2, 5)).unwrap();
    assert_eq!(
        admission.finish(2, 5).unwrap_err(),
        Reason::UnpublishedOmissionUnproved
    );
}

#[test]
fn all_irps_statuses_and_inclusive_boundaries_keep_callback_order() {
    let ends = [
        end(6, 7),
        End {
            qpc: 5,
            irp: 0,
            status: 99,
        },
        end(2, 99),
        End {
            qpc: 4,
            irp: 7,
            status: 0xc0000043,
        },
        end(1, 7),
        end(3, 8),
    ];
    let proof = project(&ends, false);
    assert_eq!(
        triples(proof.as_slice()),
        triples(&[ends[1], ends[2], ends[3], ends[5]])
    );
    let proof = project(&ends, true);
    assert_eq!(
        triples(proof.as_slice()),
        triples(&[ends[0], ends[1], ends[2], ends[3], ends[5]])
    );
}

#[test]
fn invalid_timestamps_are_sticky_even_outside_window() {
    for qpc in [0, -1, i64::MIN] {
        let mut admission = Admission::new().unwrap();
        assert_eq!(
            admission.decoded_end(end(qpc, 0), bounds(2, 5)).decision,
            Decision::Rejected(Reason::InvalidTimestamp)
        );
        assert_eq!(
            admission.observe(bounds(2, 5)),
            Err(Reason::InvalidTimestamp)
        );
        assert_eq!(
            admission.finish(2, 5).unwrap_err(),
            Reason::InvalidTimestamp
        );
    }
}

#[test]
fn hard_cap_and_unknown_after_overflow_never_recover_or_evict() {
    let mut admission = Admission::new().unwrap();
    let snapshot = Snapshot {
        before: Some(2),
        after: None,
    };
    for _ in 0..MAX_ENDS {
        assert_eq!(
            admission.decoded_end(end(100, 7), snapshot).decision,
            Decision::Retained
        );
    }
    assert_eq!(
        admission.decoded_end(end(100, 7), snapshot).decision,
        Decision::Rejected(Reason::EndCapacityReached)
    );
    assert_eq!(
        admission.observe(bounds(2, 5)),
        Err(Reason::EndCapacityReached)
    );
    assert_eq!(admission.ends.len(), MAX_ENDS);
    assert_eq!(
        admission.finish(2, 5).unwrap_err(),
        Reason::EndCapacityReached
    );
    let mut exact = Admission::new().unwrap();
    for _ in 0..MAX_ENDS {
        exact.decoded_end(end(4, 7), bounds(2, 5));
    }
    assert_eq!(exact.finish(2, 5).unwrap().as_slice().len(), MAX_ENDS);
}

#[test]
fn reservation_failure_is_unavailable_without_a_partial_admission_owner() {
    // Deterministic layout overflow, not a claim that allocator exhaustion was
    // induced or that this compile-only test has executed on this host.
    assert!(matches!(
        Admission::reserve_ends(usize::MAX),
        Err(Reason::ReservationUnavailable)
    ));
}

#[test]
fn actual_zero_capacity_and_injected_small_capacity_reject_without_allocation() {
    let mut zero = Admission::from_reserved(Vec::new());
    assert_eq!(zero.ends.capacity(), 0);
    assert_eq!(
        zero.decoded_end(end(4, 7), bounds(2, 5)).decision,
        Decision::Rejected(Reason::EndCapacityReached)
    );
    let mut limited = Admission::new().unwrap();
    limited.injected_capacity = 2;
    let allocated = limited.ends.capacity();
    for _ in 0..2 {
        assert_eq!(
            limited.decoded_end(end(4, 7), bounds(2, 5)).decision,
            Decision::Retained
        );
    }
    assert_eq!(
        limited.decoded_end(end(4, 7), bounds(2, 5)).decision,
        Decision::Rejected(Reason::EndCapacityReached)
    );
    assert_eq!(limited.ends.capacity(), allocated);
    assert_eq!(limited.ends.len(), 2);
}

#[test]
fn outside_omission_at_full_capacity_does_not_evict_any_retained_candidate() {
    let mut admission = Admission::new().unwrap();
    for _ in 0..MAX_ENDS {
        admission.decoded_end(
            end(100, 7),
            Snapshot {
                before: Some(2),
                after: None,
            },
        );
    }
    let handoff = admission.decoded_end(end(101, 7), bounds(2, 5));
    assert_eq!(handoff.decision, Decision::OmittedAfter);
    assert_eq!(admission.finish(2, 5).unwrap().as_slice().len(), MAX_ENDS);
}

#[test]
fn handoff_keeps_omitted_and_rejected_decoded_values_without_ownership_claim() {
    let mut admission = Admission::new().unwrap();
    let stream = [
        end(1, 7),
        End {
            qpc: 6,
            irp: 0,
            status: 99,
        },
        end(4, 8),
    ];
    for end in stream {
        let handoff = admission.decoded_end(end, bounds(2, 5));
        assert_eq!(
            (handoff.end.qpc, handoff.end.irp, handoff.end.status),
            (end.qpc, end.irp, end.status)
        );
    }
    assert_eq!(
        triples(admission.finish(2, 5).unwrap().as_slice()),
        triples(&[stream[2]])
    );
    let mut admission = Admission::from_reserved(Vec::new());
    let handoff = admission.decoded_end(end(4, 7), bounds(2, 5));
    assert_eq!(
        handoff.decision,
        Decision::Rejected(Reason::EndCapacityReached)
    );
    assert_eq!(handoff.end.irp, 7);
}

#[test]
fn inconsistent_omission_summaries_and_missing_retained_record_are_unavailable() {
    let mut admission = Admission::new().unwrap();
    admission.decoded_end(end(4, 7), bounds(2, 5));
    admission.ends.clear();
    assert_eq!(
        admission.finish(2, 5).unwrap_err(),
        Reason::OmissionAccountingUnavailable
    );
    for extremum in [None, Some(0)] {
        let mut admission = Admission::new().unwrap();
        admission.decoded_end(end(1, 7), Snapshot::default());
        admission.unpublished.extremum = extremum;
        admission.observe(bounds(2, 5)).unwrap();
        assert_eq!(
            admission.finish(2, 5).unwrap_err(),
            Reason::OmissionSummaryUnavailable
        );
    }
    let mut admission = Admission::new().unwrap();
    admission.decoded = u32::MAX;
    assert_eq!(
        admission.decoded_end(end(4, 7), bounds(2, 5)).decision,
        Decision::Rejected(Reason::OmissionAccountingUnavailable)
    );
}

#[test]
fn actual_correlator_reasons_reuse_status_and_order_are_preserved() {
    let cases = [
        (vec![start(3, 7)], vec![], "correlation_end_missing"),
        (
            vec![start(3, 7)],
            vec![end(4, 7), end(4, 7)],
            "correlation_end_multiple",
        ),
        (
            vec![start(2, 7), start(4, 8)],
            vec![end(5, 8), end(3, 7)],
            "correlation_end_order",
        ),
        (
            vec![start(3, 7)],
            vec![end(4, 7), end(2, 7)],
            "correlation_end_before_start",
        ),
        (
            vec![start(2, 7), start(4, 8)],
            vec![end(3, 7), end(5, 8), end(5, 7)],
            "correlation_end_unowned",
        ),
        (
            vec![
                start(3, 7),
                Start {
                    tid: 4,
                    ..start(3, 7)
                },
            ],
            vec![end(4, 7)],
            "correlation_cross_thread_reuse",
        ),
        (
            vec![start(3, 7), start(3, 8)],
            vec![],
            "correlation_start_order",
        ),
        (vec![start(3, 0)], vec![end(4, 0)], "schema_unavailable"),
    ];
    for (starts, middle, reason) in cases {
        let mut ends = vec![end(1, 7)];
        ends.extend(middle);
        ends.push(end(6, 7));
        let proof = project(&ends, false);
        assert_eq!(correlate(&starts, &ends, 2, 5, 3), Err(reason));
        assert_eq!(correlate(&starts, proof.as_slice(), 2, 5, 3), Err(reason));
    }
    let starts = [start(2, 7), start(4, 7)];
    let ends = [
        end(1, 7),
        end(2, 7),
        End {
            qpc: 5,
            irp: 7,
            status: 0xc0000043,
        },
        end(6, 7),
    ];
    let proof = project(&ends, false);
    let counts = correlate(&starts, proof.as_slice(), 2, 5, 3).unwrap();
    assert_eq!(
        (
            counts.attempts,
            counts.successful,
            counts.sharing,
            counts.other
        ),
        (2, 1, 1, 0)
    );
}

#[test]
fn equal_window_and_max_saturation_preserve_actual_correlator_behavior() {
    for qpc in [2, i64::MAX] {
        let mut admission = Admission::new().unwrap();
        admission.decoded_end(end(qpc, 7), bounds(qpc, qpc));
        let proof = admission.finish(qpc, qpc).unwrap();
        let result = correlate(&[start(qpc, 7)], proof.as_slice(), qpc, qpc, 3);
        if qpc == i64::MAX {
            assert_eq!(result, Err("correlation_end_missing"));
        } else {
            assert_eq!(result.unwrap().attempts, 1);
        }
    }
}

#[test]
fn over_old_lifetime_cap_is_new_admission_not_equivalent_old_acceptance() {
    let ends = vec![end(1, 9); MAX_ENDS + 1];
    let proof = project(&ends, false);
    assert!(proof.as_slice().is_empty());
    assert_eq!(
        correlate(&[start(3, 7)], &ends, 2, 5, 3),
        Err("budget_exceeded")
    );
    assert_eq!(
        correlate(&[start(3, 7)], proof.as_slice(), 2, 5, 3),
        Err("correlation_end_missing")
    );
}

#[test]
fn exhaustive_small_complete_streams_match_the_actual_unchanged_correlator() {
    let alphabet: Vec<_> = (1..=6).flat_map(|qpc| [end(qpc, 0), end(qpc, 7)]).collect();
    let starts = [
        vec![],
        vec![start(3, 7)],
        vec![start(2, 7), start(4, 7)],
        vec![
            start(3, 7),
            Start {
                tid: 4,
                ..start(3, 7)
            },
        ],
        vec![start(4, 7), start(2, 7)],
        vec![start(3, 0)],
    ];
    let mut comparisons = 0;
    for length in 0..=3_u32 {
        for mut code in 0..12_usize.pow(length) {
            let mut ends = Vec::new();
            for _ in 0..length {
                ends.push(alphabet[code % 12]);
                code /= 12;
            }
            for unknown_after in [false, true] {
                let proof = project(&ends, unknown_after);
                assert_eq!(
                    triples(
                        &proof
                            .as_slice()
                            .iter()
                            .copied()
                            .filter(|e| 2 <= e.qpc && e.qpc <= 5)
                            .collect::<Vec<_>>()
                    ),
                    triples(
                        &ends
                            .iter()
                            .copied()
                            .filter(|e| 2 <= e.qpc && e.qpc <= 5)
                            .collect::<Vec<_>>()
                    )
                );
                for starts in &starts {
                    assert_eq!(
                        correlate(starts, &ends, 2, 5, 3),
                        correlate(starts, proof.as_slice(), 2, 5, 3)
                    );
                    comparisons += 1;
                }
            }
        }
    }
    assert_eq!(comparisons, 22620);
}

fn complete_gate() -> CaptureGate {
    CaptureGate {
        drained: true,
        started: true,
        settings: true,
        lossless: true,
        bounded: true,
    }
}

#[test]
fn publication_is_once_but_stable_snapshot_reads_repeat() {
    let published = PublishedBounds::default();
    assert_eq!(published.snapshot(), Snapshot::default());
    published.publish_before(2).unwrap();
    assert_eq!(
        published.snapshot(),
        Snapshot {
            before: Some(2),
            after: None
        }
    );
    published.publish_after(5).unwrap();
    let mut admission = Admission::new().unwrap();
    for _ in 0..3 {
        admission.observe(published.snapshot()).unwrap();
    }
    assert_eq!(published.publish_before(2), Err(Reason::BoundsChanged));
    assert_eq!(published.publish_after(5), Err(Reason::BoundsChanged));
    assert_eq!(published.snapshot(), bounds(2, 5));
    assert!(admission.finish(2, 5).is_ok());
}

#[test]
fn invalid_publication_never_changes_an_existing_bound() {
    let published = PublishedBounds::default();
    assert_eq!(published.publish_before(0), Err(Reason::InvalidBounds));
    assert_eq!(published.publish_after(5), Err(Reason::InvalidBounds));
    assert_eq!(published.snapshot(), Snapshot::default());
    published.publish_before(5).unwrap();
    assert_eq!(published.publish_after(4), Err(Reason::InvalidBounds));
    published.publish_after(5).unwrap();
    assert_eq!(published.publish_before(6), Err(Reason::BoundsChanged));
    assert_eq!(published.publish_after(6), Err(Reason::BoundsChanged));
    assert_eq!(published.snapshot(), bounds(5, 5));
}

#[test]
fn publication_failure_does_not_repeat_or_replace_original_result() {
    use std::{cell::Cell, io};
    let published = PublishedBounds::default();
    published.publish_before(2).unwrap();
    assert!(published.publish_before(2).is_err());
    let calls = Cell::new(0);
    let result = crate::model::original_then(
        || {
            calls.set(calls.get() + 1);
            Err(io::Error::from_raw_os_error(32))
        },
        |original| {
            assert_eq!(original.as_ref().unwrap_err().raw_os_error(), Some(32));
            published.publish_after(5).unwrap();
            assert!(published.publish_after(5).is_err());
        },
    );
    assert_eq!(calls.get(), 1);
    assert_eq!(result.unwrap_err().raw_os_error(), Some(32));
}

#[test]
fn every_capture_gate_keeps_unqualified_owner_intact() {
    for selector in 0..5 {
        let mut gate = complete_gate();
        match selector {
            0 => gate.drained = false,
            1 => gate.started = false,
            2 => gate.settings = false,
            3 => gate.lossless = false,
            _ => gate.bounded = false,
        }
        let mut state = Admission::new().unwrap();
        state.decoded_end(end(4, 7), bounds(2, 5));
        let mut owner = Some(state);
        assert!(prove_if_complete(&mut owner, bounds(2, 5), 2, 5, gate).is_none());
        assert_eq!(triples(&owner.as_ref().unwrap().ends), vec![(4, 7, 0)]);
    }
}

#[test]
fn complete_proof_consumes_once_and_binds_the_final_snapshot() {
    let mut state = Admission::new().unwrap();
    state.decoded_end(end(4, 7), bounds(2, 5));
    let mut owner = Some(state);
    assert_eq!(
        prove_if_complete(&mut owner, bounds(2, 5), 2, 5, complete_gate())
            .unwrap()
            .unwrap()
            .as_slice()
            .len(),
        1
    );
    assert!(owner.is_none());
    assert_eq!(
        prove_if_complete(&mut owner, bounds(2, 5), 2, 5, complete_gate())
            .unwrap()
            .unwrap_err(),
        Reason::OmissionAccountingUnavailable
    );
    let mut owner = Some(Admission::new().unwrap());
    assert_eq!(
        prove_if_complete(&mut owner, bounds(2, 5), 2, 6, complete_gate())
            .unwrap()
            .unwrap_err(),
        Reason::BoundsMismatch
    );
    assert!(owner.is_none());
}

#[test]
fn omitted_end_handoff_preserves_ownership_prefix_uncertainty() {
    use crate::ownership::{Buffer, Event, Kind, Reason as OwnershipReason, Report};
    let mut admission = Admission::new().unwrap();
    let mut ownership = Buffer::default();
    ownership.reserve();
    for (index, input) in [end(1, 7), end(4, 7), end(4, 7)].into_iter().enumerate() {
        let handoff = admission.decoded_end(input, bounds(2, 5));
        assert!(!matches!(handoff.decision, Decision::Rejected(_)));
        ownership.push(Event {
            ordinal: index as u32 + 1,
            qpc: handoff.end.qpc,
            irp: handoff.end.irp,
            kind: Kind::End,
        });
    }
    let proof = admission.finish(2, 5).unwrap();
    assert_eq!(proof.as_slice().len(), 2);
    assert_eq!(
        correlate(&[start(3, 7)], proof.as_slice(), 2, 5, 3),
        Err("correlation_end_multiple")
    );
    assert!(matches!(
        ownership.report(
            &[start(3, 7)],
            proof.as_slice(),
            Ok((2, 5, 3)),
            Some("correlation_end_multiple")
        ),
        Report::Unavailable(OwnershipReason::Window)
    ));
}

#[test]
fn ownership_budget_stays_independent_of_successful_omission() {
    use crate::ownership::{Buffer, Event, Kind, Reason as OwnershipReason, Report, MAX_EVENTS};
    let mut admission = Admission::new().unwrap();
    let mut ownership = Buffer::default();
    ownership.reserve();
    for ordinal in 1..=(MAX_EVENTS as u32 + 1) {
        let handoff = admission.decoded_end(end(1, 9), bounds(2, 5));
        assert_eq!(handoff.decision, Decision::OmittedBefore);
        ownership.push(Event {
            ordinal,
            qpc: handoff.end.qpc,
            irp: handoff.end.irp,
            kind: Kind::End,
        });
    }
    let proof = admission.finish(2, 5).unwrap();
    assert!(proof.as_slice().is_empty());
    assert!(matches!(
        ownership.report(
            &[],
            proof.as_slice(),
            Ok((2, 5, 3)),
            Some("correlation_end_multiple")
        ),
        Report::Unavailable(OwnershipReason::Budget)
    ));
}

#[test]
fn stop_only_loss_and_bounds_skip_even_a_failing_pending_proof() {
    for (lossless, bounded) in [(false, true), (true, false), (false, false)] {
        let mut state = Admission::new().unwrap();
        state.decoded_end(end(2, 7), Snapshot::default());
        let mut owner = Some(state);
        let gate = CaptureGate {
            lossless,
            bounded,
            ..complete_gate()
        };
        assert!(prove_if_complete(&mut owner, bounds(2, 5), 2, 5, gate).is_none());
        assert!(owner.is_some());
        // The existing final native assignments own loss/bounds precedence;
        // no provisional omission or correlator result exists in this branch.
    }
}

#[test]
fn closed_reason_mapping_and_capture_marker_are_exact() {
    let pairs = [
        (Reason::ReservationUnavailable, "end_reservation_failed"),
        (Reason::InvalidBounds, "end_bounds_invalid"),
        (Reason::BoundsRegressed, "end_bounds_regressed"),
        (Reason::BoundsChanged, "end_bounds_changed"),
        (Reason::BoundsUnpublished, "end_bounds_unpublished"),
        (Reason::BoundsMismatch, "end_bounds_mismatch"),
        (Reason::InvalidTimestamp, "end_timestamp_invalid"),
        (
            Reason::OmissionSummaryUnavailable,
            "end_omission_summary_unavailable",
        ),
        (
            Reason::OmissionAccountingUnavailable,
            "end_omission_accounting_unavailable",
        ),
        (
            Reason::UnpublishedOmissionUnproved,
            "end_unpublished_omission_unproved",
        ),
        (Reason::PreOmissionUnproved, "end_pre_omission_unproved"),
        (Reason::PostOmissionUnproved, "end_post_omission_unproved"),
        (Reason::EndCapacityReached, "end_capacity_reached"),
    ];
    for (reason, label) in pairs {
        assert_eq!(reason.label(), label);
    }
    assert_eq!(CAPTURE_CONTRACT, "window_end_admission_v1");
}
