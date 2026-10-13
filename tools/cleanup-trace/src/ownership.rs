//! Supplemental observations only. No native calls, paths or acceptance authority.
use crate::model::{self, End, Start};
pub const MAX_EVENTS: usize = 8192;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Reason {
    Schema,
    UnsupportedOpcode,
    EventLoss,
    Budget,
    Order,
    Teardown,
    Window,
}
impl Reason {
    fn label(self) -> &'static str {
        match self {
            Self::Schema => "schema",
            Self::UnsupportedOpcode => "unsupported_opcode",
            Self::EventLoss => "event_loss",
            Self::Budget => "budget",
            Self::Order => "order",
            Self::Teardown => "teardown",
            Self::Window => "window",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kind {
    Create,
    Other,
    End,
}
/// Only documented classic FileIo classes. No raw-layout assumptions.
pub fn kind(opcode: u8, version: u8, flags: u16) -> Result<Option<Kind>, Reason> {
    if !matches!(version, 2 | 3) || flags & 0x40 == 0 || flags & 0x20 != 0 {
        return Err(Reason::Schema);
    }
    match opcode {
        0 | 32 | 35 | 36 => Ok(None), // Name-only events, not operation beginnings.
        64 => Ok(Some(Kind::Create)),
        65 | 66 | 67 | 68 | 69 | 70 | 71 | 72 | 73 | 74 | 75 | 77 => Ok(Some(Kind::Other)),
        76 => Ok(Some(Kind::End)),
        _ => Err(Reason::UnsupportedOpcode),
    }
}
/// Fakeable TDH boundary: one size query, exact pointer width, at most one read.
pub fn read_irp(
    size: impl FnOnce() -> Result<u32, ()>,
    read: impl FnOnce(&mut [u8; 8]) -> Result<(), ()>,
) -> Result<u64, Reason> {
    if size().map_err(|_| Reason::Schema)? != 8 {
        return Err(Reason::Schema);
    }
    let mut bytes = [0; 8];
    read(&mut bytes).map_err(|_| Reason::Schema)?;
    let irp = u64::from_le_bytes(bytes);
    if irp == 0 {
        Err(Reason::Schema)
    } else {
        Ok(irp)
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Event {
    pub ordinal: u32,
    pub qpc: i64,
    pub irp: u64,
    pub kind: Kind,
}
#[derive(Default)]
pub struct Buffer {
    events: Vec<Event>,
    error: Option<Reason>,
}
impl Buffer {
    pub fn reserve(&mut self) {
        if self.events.try_reserve_exact(MAX_EVENTS).is_err() {
            self.reject(Reason::Budget);
        }
    }
    pub fn active(&self) -> bool {
        self.error.is_none()
    }
    pub fn reject(&mut self, reason: Reason) {
        self.error.get_or_insert(reason);
    }
    pub fn push(&mut self, event: Event) {
        if !self.active() {
            return;
        }
        if self.events.len() == MAX_EVENTS || self.events.len() == self.events.capacity() {
            self.reject(Reason::Budget);
        } else if event.irp == 0 {
            self.reject(Reason::Schema);
        } else if event.qpc <= 0 {
            self.reject(Reason::Window);
        } else if event.ordinal == 0
            || self
                .events
                .last()
                .is_some_and(|last| event.ordinal <= last.ordinal)
        {
            self.reject(Reason::Order);
        } else {
            self.events.push(event);
        }
    }
    pub fn report(
        &self,
        starts: &[Start],
        ends: &[End],
        window: Result<(i64, i64, u64), &'static str>,
        original_reason: Option<&'static str>,
    ) -> Report {
        if let Some(reason) = self.error {
            return Report::Unavailable(reason);
        }
        let Ok((before, after, tid)) = window else {
            return Report::Unavailable(Reason::Window);
        };
        // Reuse the original call's failure. No second correlator call or temporary
        // heap collections: only bounded iterator scans of the reserved stream.
        if original_reason != Some("correlation_end_multiple")
            || before <= 0
            || after < before
            || tid == 0
            || starts.len() > model::MAX_STARTS
            || ends.len() > model::MAX_ENDS
        {
            return Report::Unavailable(Reason::Window);
        }
        let chosen = || {
            starts
                .iter()
                .filter(|s| s.tid == tid && before <= s.qpc && s.qpc <= after)
        };
        let mut selected = chosen().peekable();
        let mut anchor = None;
        while let Some(start) = selected.next() {
            let next = selected.peek().map_or(after.saturating_add(1), |s| s.qpc);
            if ends
                .iter()
                .filter(|e| {
                    e.irp == start.irp && start.qpc <= e.qpc && e.qpc < next && e.qpc <= after
                })
                .count()
                > 1
            {
                anchor = Some(start);
                break;
            }
        }
        let Some(anchor) = anchor else {
            return Report::Unavailable(Reason::Window);
        };
        let same = || self.events.iter().filter(|e| e.irp == anchor.irp);
        if same()
            .zip(same().skip(1))
            .any(|(first, second)| first.qpc >= second.qpc)
        {
            return Report::Unavailable(Reason::Order);
        }
        let events = || same().filter(|e| before <= e.qpc && e.qpc <= after);
        if events()
            .filter(|e| e.qpc == anchor.qpc && e.kind == Kind::Create)
            .count()
            != 1
        {
            return Report::Unavailable(Reason::Window);
        }
        // Cross-check the entire relevant end stream; never drop an unexplained end.
        let retained = || events().filter(|e| e.kind == Kind::End).map(|e| e.qpc);
        let original = ends
            .iter()
            .filter(|e| e.irp == anchor.irp && before <= e.qpc && e.qpc <= after)
            .map(|e| e.qpc);
        if !retained().eq(original) {
            return Report::Unavailable(Reason::Window);
        }
        // The full observed prefix must establish a closed boundary. Looking
        // only at its last End would hide an earlier overlapping/orphan owner.
        let mut prior_open = false;
        for event in same().filter(|e| e.qpc < before) {
            if event.kind == Kind::End {
                if !prior_open {
                    return Report::Unavailable(Reason::Window);
                }
                prior_open = false;
            } else if prior_open {
                return Report::Unavailable(Reason::Window);
            } else {
                prior_open = true;
            }
        }
        if prior_open
            || (events().next_back().is_some_and(|e| e.kind != Kind::End)
                && same()
                    .find(|e| e.qpc > after)
                    .is_some_and(|e| e.kind == Kind::End))
        {
            return Report::Unavailable(Reason::Window);
        }
        let start_count = events().filter(|e| e.kind != Kind::End).count() as u32;
        let end_count = retained().count() as u32;
        let anomaly = |pattern| Report::Observed {
            pattern,
            starts: start_count,
            ends: end_count,
            pairs: None,
        };
        let mut open: Option<&Event> = None;
        let mut pairs = Pairs::default();
        for event in events() {
            if event.kind == Kind::End {
                let Some(start) = open.take() else {
                    return anomaly(Pattern::ExtraEnd);
                };
                pairs.complete += 1;
                if start.kind == Kind::Other {
                    pairs.other += 1;
                } else if !chosen().any(|s| s.irp == start.irp && s.qpc == start.qpc) {
                    pairs.nonselected_create += 1;
                }
            } else if open.replace(event).is_some() {
                return anomaly(Pattern::Overlap);
            }
        }
        if open.is_some() {
            return anomaly(Pattern::Incomplete);
        }
        if pairs.nonselected_create + pairs.other == 0 {
            return Report::Unavailable(Reason::Window);
        }
        Report::Observed {
            pattern: Pattern::Sequential,
            starts: start_count,
            ends: end_count,
            pairs: Some(pairs),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    fn report(
        buffer: &Buffer,
        starts: &[Start],
        ends: &[End],
        window: Result<(i64, i64, u64), &'static str>,
    ) -> Report {
        let reason = window.ok().and_then(|(before, after, tid)| {
            model::correlate(starts, ends, before, after, tid).err()
        });
        buffer.report(starts, ends, window, reason)
    }
    fn fixture(kinds: &[Kind]) -> (Buffer, Vec<Start>, Vec<End>, i64) {
        let mut buffer = Buffer::default();
        buffer.reserve();
        let starts = vec![Start {
            qpc: 2,
            irp: 7,
            tid: 3,
            share: 7,
        }];
        let mut ends = Vec::new();
        for (index, &kind) in kinds.iter().enumerate() {
            let qpc = index as i64 + 2;
            buffer.push(Event {
                ordinal: index as u32 + 1,
                qpc,
                irp: 7,
                kind,
            });
            if kind == Kind::End {
                ends.push(End {
                    qpc,
                    irp: 7,
                    status: 0,
                });
            }
        }
        (buffer, starts, ends, kinds.len() as i64 + 2)
    }
    fn pattern(kinds: &[Kind], expected: Pattern) {
        let (buffer, starts, ends, after) = fixture(kinds);
        assert_eq!(
            model::correlate(&starts, &ends, 1, after, 3),
            Err("correlation_end_multiple")
        );
        let Report::Observed {
            pattern,
            starts: count,
            ends: end_count,
            pairs,
        } = report(&buffer, &starts, &ends, Ok((1, after, 3)))
        else {
            panic!("observation missing")
        };
        assert_eq!(pattern, expected);
        assert_eq!(count + end_count, kinds.len() as u32);
        assert_eq!(pairs.is_some(), expected == Pattern::Sequential);
        assert_eq!(
            model::correlate(&starts, &ends, 1, after, 3),
            Err("correlation_end_multiple")
        );
    }
    #[test]
    fn observed_chains_never_change_original_multiple_end_result() {
        use Kind::*;
        pattern(&[Create, End, Other, End], Pattern::Sequential);
        pattern(&[Create, End, Create, End], Pattern::Sequential);
        pattern(&[Create, End, End], Pattern::ExtraEnd);
        pattern(&[Create, Other, End, End], Pattern::Overlap);
        pattern(&[Create, End, Other, End, Other], Pattern::Incomplete);
    }
    #[test]
    fn cross_thread_target_create_is_not_a_selected_owner() {
        use Kind::*;
        let (buffer, mut starts, ends, after) = fixture(&[Create, End, Create, End]);
        starts.push(Start {
            qpc: 4,
            irp: 7,
            tid: 9,
            share: 7,
        });
        assert_eq!(
            report(&buffer, &starts, &ends, Ok((1, after, 3))),
            Report::Observed {
                pattern: Pattern::Sequential,
                starts: 2,
                ends: 2,
                pairs: Some(Pairs {
                    complete: 2,
                    nonselected_create: 1,
                    other: 0
                }),
            }
        );
    }
    #[test]
    fn supported_schema_table_is_closed_and_name_events_need_no_pointer() {
        for version in [2, 3] {
            for opcode in 0..=255 {
                let result = kind(opcode, version, 0x40);
                match opcode {
                    0 | 32 | 35 | 36 => assert_eq!(result, Ok(None)),
                    64 => assert_eq!(result, Ok(Some(Kind::Create))),
                    65 | 66 | 67 | 68 | 69 | 70 | 71 | 72 | 73 | 74 | 75 | 77 => {
                        assert_eq!(result, Ok(Some(Kind::Other)))
                    }
                    76 => assert_eq!(result, Ok(Some(Kind::End))),
                    _ => assert_eq!(result, Err(Reason::UnsupportedOpcode)),
                }
            }
        }
        for version in [0, 1, 4, 255] {
            assert_eq!(kind(64, version, 0x40), Err(Reason::Schema));
        }
        for flags in [0, 0x20, 0x60] {
            assert_eq!(kind(64, 3, flags), Err(Reason::Schema));
        }
    }
    #[test]
    fn fake_tdh_requires_exact_size_then_one_read_and_preserves_unknown() {
        for size in [Err(()), Ok(0), Ok(4), Ok(7), Ok(9), Ok(u32::MAX)] {
            let reads = Cell::new(0);
            assert_eq!(
                read_irp(
                    || size,
                    |_| {
                        reads.set(reads.get() + 1);
                        Ok(())
                    }
                ),
                Err(Reason::Schema)
            );
            assert_eq!(reads.get(), 0);
        }
        let operations = RefCell::new(Vec::new());
        assert_eq!(
            read_irp(
                || {
                    operations.borrow_mut().push("size");
                    Ok(8)
                },
                |out| {
                    operations.borrow_mut().push("read");
                    *out = 7u64.to_le_bytes();
                    Ok(())
                }
            ),
            Ok(7)
        );
        assert_eq!(*operations.borrow(), vec!["size", "read"]);
        assert_eq!(read_irp(|| Ok(8), |_| Err(())), Err(Reason::Schema));
        assert_eq!(read_irp(|| Ok(8), |_| Ok(())), Err(Reason::Schema));
    }
    #[test]
    fn loss_schema_budget_and_teardown_keep_every_field_unknown() {
        use Kind::*;
        for reason in [
            Reason::Schema,
            Reason::UnsupportedOpcode,
            Reason::EventLoss,
            Reason::Budget,
            Reason::Order,
            Reason::Teardown,
            Reason::Window,
        ] {
            let (mut buffer, starts, ends, after) = fixture(&[Create, End, Other, End]);
            let length = buffer.events.len();
            buffer.reject(reason);
            buffer.reject(Reason::Schema);
            buffer.push(Event {
                ordinal: 5,
                qpc: 7,
                irp: 7,
                kind: End,
            });
            assert_eq!(buffer.events.len(), length);
            let report = report(&buffer, &starts, &ends, Ok((1, after, 3)));
            assert_eq!(report, Report::Unavailable(reason));
            assert_eq!(report.json().matches("null").count(), 6);
        }
    }
    #[test]
    fn capacity_is_combined_fixed_and_never_truncates_or_evicts() {
        let mut buffer = Buffer::default();
        buffer.reserve();
        for index in 0..MAX_EVENTS {
            buffer.push(Event {
                ordinal: index as u32 + 1,
                qpc: index as i64 + 1,
                irp: 7,
                kind: Kind::Create,
            });
        }
        assert!(buffer.active());
        buffer.push(Event {
            ordinal: MAX_EVENTS as u32 + 1,
            qpc: 9000,
            irp: 7,
            kind: Kind::End,
        });
        assert_eq!(buffer.error, Some(Reason::Budget));
        assert_eq!(buffer.events.len(), MAX_EVENTS);
        assert_eq!(buffer.events[0].ordinal, 1);
        let mut unreserved = Buffer::default();
        unreserved.push(Event {
            ordinal: 1,
            qpc: 1,
            irp: 7,
            kind: Kind::Create,
        });
        assert_eq!(unreserved.error, Some(Reason::Budget));
    }
    #[test]
    fn malformed_pointer_clock_or_callback_order_is_unknown() {
        for (ordinal, qpc, irp, reason) in [
            (1, 1, 0, Reason::Schema),
            (1, 0, 7, Reason::Window),
            (0, 1, 7, Reason::Order),
        ] {
            let mut buffer = Buffer::default();
            buffer.reserve();
            buffer.push(Event {
                ordinal,
                qpc,
                irp,
                kind: Kind::Create,
            });
            assert_eq!(buffer.error, Some(reason));
        }
        let (mut buffer, _, _, _) = fixture(&[Kind::Create]);
        buffer.push(Event {
            ordinal: 1,
            qpc: 9,
            irp: 7,
            kind: Kind::End,
        });
        assert_eq!(buffer.error, Some(Reason::Order));
    }
    #[test]
    fn qpc_ties_reordering_and_uncertain_window_are_not_sorted_away() {
        use Kind::*;
        for qpc in [2, 1] {
            let (mut buffer, starts, ends, after) = fixture(&[Create, End, Other, End]);
            buffer.events[1].qpc = qpc;
            assert_eq!(
                report(&buffer, &starts, &ends, Ok((1, after, 3))),
                Report::Unavailable(Reason::Order)
            );
        }
        let (buffer, starts, ends, after) = fixture(&[Create, End, Other, End]);
        for window in [
            Err("clock_unavailable"),
            Ok((0, after, 3)),
            Ok((1, after, 0)),
            Ok((after, 1, 3)),
        ] {
            assert_eq!(
                report(&buffer, &starts, &ends, window),
                Report::Unavailable(Reason::Window)
            );
        }
    }
    #[test]
    fn boundary_crossing_and_missing_cached_end_cannot_disappear() {
        use Kind::*;
        let (mut buffer, starts, ends, after) = fixture(&[Create, End, Other, End]);
        buffer.events.insert(
            0,
            Event {
                ordinal: 1,
                qpc: 1,
                irp: 7,
                kind: Other,
            },
        );
        for (index, event) in buffer.events.iter_mut().enumerate() {
            event.ordinal = index as u32 + 1;
        }
        assert_eq!(
            report(&buffer, &starts, &ends, Ok((2, after, 3))),
            Report::Unavailable(Reason::Window)
        );
        let (buffer, starts, ends, _) = fixture(&[Create, End, Other, End, Other, End]);
        assert_eq!(
            report(&buffer, &starts, &ends, Ok((1, 6, 3))),
            Report::Unavailable(Reason::Window)
        );
        let (mut buffer, starts, ends, after) = fixture(&[Create, End, Other, End]);
        buffer.events.pop();
        assert_eq!(
            report(&buffer, &starts, &ends, Ok((1, after, 3))),
            Report::Unavailable(Reason::Window)
        );
    }
    #[test]
    fn no_multiple_failure_means_no_supplemental_interpretation() {
        let (buffer, starts, ends, after) = fixture(&[Kind::Create, Kind::End]);
        assert!(model::correlate(&starts, &ends, 1, after, 3).is_ok());
        assert_eq!(
            report(&buffer, &starts, &ends, Ok((1, after, 3))),
            Report::Unavailable(Reason::Window)
        );
    }
    #[test]
    fn pre_window_boundary_requires_fully_closed_observed_prefix() {
        use Kind::*;
        for (prefix, closed) in [
            (vec![Other, Other, End], false),
            (vec![End], false),
            (vec![Other, End, End], false),
            (vec![Other], false),
            (vec![Other, End], true),
            (vec![Other, End, Create, End], true),
        ] {
            let offset = prefix.len();
            let kinds: Vec<_> = prefix
                .into_iter()
                .chain([Create, End, Other, End])
                .collect();
            let (buffer, mut starts, ends, after) = fixture(&kinds);
            let before = offset as i64 + 2;
            starts[0].qpc = before;
            let result = report(&buffer, &starts, &ends, Ok((before, after, 3)));
            if closed {
                assert!(matches!(
                    result,
                    Report::Observed {
                        pattern: Pattern::Sequential,
                        ..
                    }
                ));
            } else {
                assert_eq!(result, Report::Unavailable(Reason::Window));
            }
            assert_eq!(
                model::correlate(&starts, &ends, before, after, 3),
                Err("correlation_end_multiple")
            );
        }
    }
    #[test]
    fn serialized_report_is_finite_and_contains_no_identifiers() {
        let report = Report::Observed {
            pattern: Pattern::Sequential,
            starts: 4096,
            ends: 4096,
            pairs: Some(Pairs {
                complete: 4096,
                nonselected_create: 4094,
                other: 1,
            }),
        };
        let text = report.json();
        assert!(text.len() < 512);
        for forbidden in ["qpc", "ordinal", "irp", "tid", "path", "PRIVATE"] {
            assert!(!text.contains(forbidden));
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Pattern {
    Sequential,
    ExtraEnd,
    Overlap,
    Incomplete,
}
impl Pattern {
    fn label(self) -> &'static str {
        match self {
            Self::Sequential => "sequential_reuse",
            Self::ExtraEnd => "extra_end_without_observed_begin",
            Self::Overlap => "overlapping_begins",
            Self::Incomplete => "incomplete",
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Pairs {
    pub complete: u32,
    pub nonselected_create: u32,
    pub other: u32,
}
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Report {
    Unavailable(Reason),
    Observed {
        pattern: Pattern,
        starts: u32,
        ends: u32,
        pairs: Option<Pairs>,
    },
}
impl Report {
    pub fn json(self) -> String {
        match self {
            Self::Unavailable(reason) => format!(
                "{{\"availability\":\"unavailable\",\"reason\":\"{}\",\"pattern\":null,\"starts\":null,\"ends\":null,\"complete_pairs\":null,\"nonselected_create_pairs\":null,\"other_operation_pairs\":null}}", reason.label()),
            Self::Observed { pattern, starts, ends, pairs } => {
                let count = |value: Option<u32>| value.map_or_else(|| "null".into(), |v| v.to_string());
                format!("{{\"availability\":\"available\",\"reason\":\"none\",\"pattern\":\"{}\",\"starts\":{},\"ends\":{},\"complete_pairs\":{},\"nonselected_create_pairs\":{},\"other_operation_pairs\":{}}}",
                    pattern.label(), starts, ends, count(pairs.map(|p| p.complete)),
                    count(pairs.map(|p| p.nonselected_create)), count(pairs.map(|p| p.other)))
            }
        }
    }
}
