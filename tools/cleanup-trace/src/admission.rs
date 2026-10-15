//! Omission-proof admission and original-bound publication. No native calls.
//! `finish` consumes this state only after a caller-established complete drain.
use crate::model::{End, MAX_ENDS};
use std::sync::atomic::{AtomicI64, Ordering};

pub const CAPTURE_CONTRACT: &str = "window_end_admission_v1";

/// One writer publishes the original clock readings. Shared separately from the
/// callback's mutable Collector. No clock call, loop or callback allocation.
#[derive(Default)]
pub struct PublishedBounds {
    before: AtomicI64,
    after: AtomicI64,
}

impl PublishedBounds {
    pub fn publish_before(&self, value: i64) -> Result<(), Reason> {
        if value <= 0 {
            return Err(Reason::InvalidBounds);
        }
        self.before
            .compare_exchange(0, value, Ordering::Release, Ordering::Relaxed)
            .map(|_| ())
            .map_err(|_| Reason::BoundsChanged)
    }

    pub fn publish_after(&self, value: i64) -> Result<(), Reason> {
        let before = self.before.load(Ordering::Acquire);
        if before <= 0 || value < before {
            return Err(Reason::InvalidBounds);
        }
        self.after
            .compare_exchange(0, value, Ordering::Release, Ordering::Relaxed)
            .map(|_| ())
            .map_err(|_| Reason::BoundsChanged)
    }

    pub fn snapshot(&self) -> Snapshot {
        // Seeing after's Release also publishes the preceding before value.
        // The opposite order could manufacture after-present/before-absent.
        let after = self.after.load(Ordering::Acquire);
        let before = self.before.load(Ordering::Acquire);
        Snapshot {
            before: (before != 0).then_some(before),
            after: (after != 0).then_some(after),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub before: Option<i64>,
    pub after: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    ReservationUnavailable,
    InvalidBounds,
    BoundsRegressed,
    BoundsChanged,
    BoundsUnpublished,
    BoundsMismatch,
    InvalidTimestamp,
    OmissionSummaryUnavailable,
    OmissionAccountingUnavailable,
    UnpublishedOmissionUnproved,
    PreOmissionUnproved,
    PostOmissionUnproved,
    EndCapacityReached,
}

impl Reason {
    pub fn label(self) -> &'static str {
        match self {
            Self::ReservationUnavailable => "end_reservation_failed",
            Self::InvalidBounds => "end_bounds_invalid",
            Self::BoundsRegressed => "end_bounds_regressed",
            Self::BoundsChanged => "end_bounds_changed",
            Self::BoundsUnpublished => "end_bounds_unpublished",
            Self::BoundsMismatch => "end_bounds_mismatch",
            Self::InvalidTimestamp => "end_timestamp_invalid",
            Self::OmissionSummaryUnavailable => "end_omission_summary_unavailable",
            Self::OmissionAccountingUnavailable => "end_omission_accounting_unavailable",
            Self::UnpublishedOmissionUnproved => "end_unpublished_omission_unproved",
            Self::PreOmissionUnproved => "end_pre_omission_unproved",
            Self::PostOmissionUnproved => "end_post_omission_unproved",
            Self::EndCapacityReached => "end_capacity_reached",
        }
    }
}

#[derive(Clone, Copy)]
pub struct CaptureGate {
    pub drained: bool,
    pub started: bool,
    pub settings: bool,
    pub lossless: bool,
    pub bounded: bool,
}

impl CaptureGate {
    pub fn complete(self) -> bool {
        self.drained && self.started && self.settings && self.lossless && self.bounded
    }
}

/// Caller proves native drain/lifetime; booleans are not themselves native proof.
/// A false gate never takes or drops the owner. In particular STOP-only loss or
/// bounds uncertainty must not produce provisional correlation counts.
pub fn prove_if_complete(
    owner: &mut Option<Admission>,
    snapshot: Snapshot,
    before: i64,
    after: i64,
    gate: CaptureGate,
) -> Option<Result<ProvenEnds, Reason>> {
    if !gate.complete() {
        return None;
    }
    let Some(mut state) = owner.take() else {
        return Some(Err(Reason::OmissionAccountingUnavailable));
    };
    Some(
        state
            .observe(snapshot)
            .and_then(|()| state.finish(before, after)),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Retained,
    OmittedBeforePublication,
    OmittedBefore,
    OmittedAfter,
    Rejected(Reason),
}

/// The caller already decoded this End once. Ownership must receive this value,
/// including omitted ends, with its original callback ordinal. Returning it is
/// not proof that a future native caller actually performed that handoff.
#[derive(Clone, Copy, Debug)]
pub struct DecodedEndHandoff {
    pub end: End,
    pub decision: Decision,
}

#[derive(Debug, Default)]
struct Omitted {
    count: u32,
    extremum: Option<i64>,
}

impl Omitted {
    fn record(&mut self, qpc: i64, maximum: bool) -> Result<(), Reason> {
        self.count = self
            .count
            .checked_add(1)
            .ok_or(Reason::OmissionAccountingUnavailable)?;
        self.extremum =
            Some(self.extremum.map_or(
                qpc,
                |old| {
                    if maximum {
                        old.max(qpc)
                    } else {
                        old.min(qpc)
                    }
                },
            ));
        Ok(())
    }

    fn valid(&self) -> bool {
        (self.count == 0) == self.extremum.is_none() && self.extremum.is_none_or(|qpc| qpc > 0)
    }
}

#[derive(Debug)]
pub struct ProvenEnds {
    ends: Vec<End>,
}

impl ProvenEnds {
    pub fn as_slice(&self) -> &[End] {
        &self.ends
    }
}

#[derive(Debug)]
pub struct Admission {
    observed: Snapshot,
    unpublished: Omitted,
    pre: Omitted,
    post: Omitted,
    decoded: u32,
    ends: Vec<End>,
    error: Option<Reason>,
    #[cfg(test)]
    injected_capacity: usize,
}

impl Admission {
    pub fn new() -> Result<Self, Reason> {
        Ok(Self::from_reserved(Self::reserve_ends(MAX_ENDS)?))
    }

    // The only production caller requests MAX_ENDS. Kept separate so a pure
    // deterministic capacity-overflow test can exercise reservation rejection.
    fn reserve_ends(requested: usize) -> Result<Vec<End>, Reason> {
        let mut ends = Vec::new();
        ends.try_reserve_exact(requested)
            .map_err(|_| Reason::ReservationUnavailable)?;
        Ok(ends)
    }

    fn from_reserved(ends: Vec<End>) -> Self {
        Self {
            observed: Snapshot::default(),
            unpublished: Omitted::default(),
            pre: Omitted::default(),
            post: Omitted::default(),
            decoded: 0,
            ends,
            error: None,
            #[cfg(test)]
            injected_capacity: MAX_ENDS,
        }
    }

    fn reject(&mut self, reason: Reason) -> Reason {
        *self.error.get_or_insert(reason)
    }

    /// Repeated identical observations are normal. Publication itself remains
    /// one-time; missing previously visible or changed nonzero bounds reject.
    pub fn observe(&mut self, snapshot: Snapshot) -> Result<(), Reason> {
        if let Some(reason) = self.error {
            return Err(reason);
        }
        if snapshot.before.is_some_and(|value| value <= 0)
            || snapshot
                .after
                .is_some_and(|after| snapshot.before.is_none_or(|before| after < before))
        {
            return Err(self.reject(Reason::InvalidBounds));
        }
        for (old, new) in [
            (self.observed.before, snapshot.before),
            (self.observed.after, snapshot.after),
        ] {
            if old.is_some() && new.is_none() {
                return Err(self.reject(Reason::BoundsRegressed));
            }
            if old.is_some() && new.is_some() && old != new {
                return Err(self.reject(Reason::BoundsChanged));
            }
        }
        self.observed = snapshot;
        Ok(())
    }

    fn capacity(&self) -> usize {
        #[cfg(test)]
        {
            self.ends.capacity().min(self.injected_capacity)
        }
        #[cfg(not(test))]
        {
            self.ends.capacity()
        }
    }

    fn admit(&mut self, end: End, snapshot: Snapshot) -> Result<Decision, Reason> {
        self.observe(snapshot)?;
        self.decoded = self
            .decoded
            .checked_add(1)
            .ok_or(Reason::OmissionAccountingUnavailable)?;
        if end.qpc <= 0 {
            return Err(Reason::InvalidTimestamp);
        }
        let Some(before) = snapshot.before else {
            self.unpublished.record(end.qpc, true)?;
            return Ok(Decision::OmittedBeforePublication);
        };
        if end.qpc < before {
            self.pre.record(end.qpc, true)?;
            return Ok(Decision::OmittedBefore);
        }
        if snapshot.after.is_some_and(|after| end.qpc > after) {
            self.post.record(end.qpc, false)?;
            return Ok(Decision::OmittedAfter);
        }
        // No callback allocation, cap increase, ring overwrite or later eviction.
        if self.ends.len() >= MAX_ENDS || self.ends.len() >= self.capacity() {
            return Err(Reason::EndCapacityReached);
        }
        self.ends.push(end);
        Ok(Decision::Retained)
    }

    pub fn decoded_end(&mut self, end: End, snapshot: Snapshot) -> DecodedEndHandoff {
        let decision = match self.admit(end, snapshot) {
            Ok(decision) => decision,
            Err(reason) => Decision::Rejected(self.reject(reason)),
        };
        DecodedEndHandoff { end, decision }
    }

    pub fn finish(mut self, before: i64, after: i64) -> Result<ProvenEnds, Reason> {
        if let Some(reason) = self.error {
            return Err(reason);
        }
        if before <= 0 || after < before {
            return Err(Reason::InvalidBounds);
        }
        if self.observed.before.is_none() || self.observed.after.is_none() {
            return Err(Reason::BoundsUnpublished);
        }
        if self.observed
            != (Snapshot {
                before: Some(before),
                after: Some(after),
            })
        {
            return Err(Reason::BoundsMismatch);
        }
        if !self.unpublished.valid() || !self.pre.valid() || !self.post.valid() {
            return Err(Reason::OmissionSummaryUnavailable);
        }
        let accounted = self.ends.len() as u64
            + u64::from(self.unpublished.count)
            + u64::from(self.pre.count)
            + u64::from(self.post.count);
        if accounted != u64::from(self.decoded) {
            return Err(Reason::OmissionAccountingUnavailable);
        }
        if self.unpublished.extremum.is_some_and(|qpc| qpc >= before) {
            return Err(Reason::UnpublishedOmissionUnproved);
        }
        if self.pre.extremum.is_some_and(|qpc| qpc >= before) {
            return Err(Reason::PreOmissionUnproved);
        }
        if self.post.extremum.is_some_and(|qpc| qpc <= after) {
            return Err(Reason::PostOmissionUnproved);
        }
        Ok(ProvenEnds {
            ends: std::mem::take(&mut self.ends),
        })
    }
}

#[cfg(test)]
#[path = "admission_tests.rs"]
mod tests;
