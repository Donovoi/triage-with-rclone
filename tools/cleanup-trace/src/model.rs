//! Pure correlation. Exact paths are already filtered by the decoder.
// No native calls and no user-controlled text is returned.
pub const MAX_STARTS: usize = 128;
pub const MAX_ENDS: usize = 8192;
/// Native callback allocations must outlive every uncertain close, including a
/// late Consumer queued in a channel after the controller's bounded receive.
pub struct CallbackStorage<T> {
    value: Option<Box<T>>,
    may_drop: bool,
}
impl<T> CallbackStorage<T> {
    pub fn new(value: T) -> Self {
        Self {
            value: Some(Box::new(value)),
            may_drop: false,
        }
    }
    pub fn allow_drop(&mut self) {
        self.may_drop = true;
    }
}
impl<T> std::ops::Deref for CallbackStorage<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.value.as_deref().unwrap()
    }
}
impl<T> std::ops::DerefMut for CallbackStorage<T> {
    fn deref_mut(&mut self) -> &mut T {
        self.value.as_deref_mut().unwrap()
    }
}
impl<T> Drop for CallbackStorage<T> {
    fn drop(&mut self) {
        if !self.may_drop {
            if let Some(value) = self.value.take() {
                let _ = Box::leak(value);
            }
        }
    }
}
/// Diagnostics receive a borrow and cannot replace the original operation result.
pub fn original_then(
    remove: impl FnOnce() -> std::io::Result<()>,
    diagnose: impl FnOnce(&std::io::Result<()>),
) -> std::io::Result<()> {
    let result = remove();
    diagnose(&result);
    result
}
#[derive(Clone, Copy, Debug)]
pub struct Start {
    pub qpc: i64,
    pub irp: u64,
    pub tid: u64,
    pub share: u32,
}
#[derive(Clone, Copy, Debug)]
pub struct End {
    pub qpc: i64,
    pub irp: u64,
    pub status: u32,
}
#[derive(Default, Debug, PartialEq)]
pub struct Counts {
    pub attempts: u32,
    pub successful: u32,
    pub sharing: u32,
    pub other: u32,
}
pub fn correlate(
    starts: &[Start],
    ends: &[End],
    before: i64,
    after: i64,
    tid: u64,
) -> Result<Counts, &'static str> {
    if before <= 0 || after < before || tid == 0 {
        return Err("clock_unavailable");
    }
    if starts.len() > MAX_STARTS || ends.len() > MAX_ENDS {
        return Err("budget_exceeded");
    }
    let chosen: Vec<_> = starts
        .iter()
        .filter(|s| s.tid == tid && before <= s.qpc && s.qpc <= after)
        .collect();
    if chosen.is_empty() {
        return Err("correlation_missing_or_ambiguous");
    }
    // Do not sort away callback ordering anomalies. Sequential IRP reuse is allowed
    // only after the previous matching end and before the next matching start.
    if chosen.windows(2).any(|x| x[0].qpc >= x[1].qpc) {
        return Err("correlation_missing_or_ambiguous");
    }
    let mut count = Counts::default();
    let mut last_end = None;
    let mut used = Vec::new();
    for (i, start) in chosen.iter().enumerate() {
        if start.irp == 0 || start.share != 7 {
            return Err("schema_unavailable");
        }
        if last_end.is_some_and(|end| start.qpc <= end) {
            return Err("correlation_missing_or_ambiguous");
        }
        let next = chosen.get(i + 1).map_or(after.saturating_add(1), |s| s.qpc);
        let matches: Vec<_> = ends
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                e.irp == start.irp && start.qpc <= e.qpc && e.qpc < next && e.qpc <= after
            })
            .collect();
        if matches.len() != 1 {
            return Err("correlation_missing_or_ambiguous");
        }
        let (index, end) = matches[0];
        if used.last().is_some_and(|previous| index <= *previous) {
            return Err("correlation_missing_or_ambiguous");
        }
        used.push(index);
        // Any end for this IRP inside the operation must belong to exactly one
        // such interval. An end before the start cannot be silently discarded.
        if ends.iter().any(|e| {
            e.irp == start.irp
                && before <= e.qpc
                && e.qpc < start.qpc
                && !chosen[..i]
                    .iter()
                    .any(|prior| prior.irp == e.irp && prior.qpc <= e.qpc)
        }) {
            return Err("correlation_missing_or_ambiguous");
        }
        last_end = Some(end.qpc);
        count.attempts += 1;
        match end.status {
            0 => count.successful += 1,
            0xc0000043 => count.sharing += 1,
            _ => count.other += 1,
        }
    }
    // Every end for a selected IRP in the operation must have exactly one owner.
    // Unrelated-thread reuse or an orphan later end is uncertainty, not a match.
    if ends.iter().enumerate().any(|(i, e)| {
        before <= e.qpc
            && e.qpc <= after
            && chosen.iter().any(|s| s.irp == e.irp)
            && !used.contains(&i)
    }) || starts.iter().any(|s| {
        before <= s.qpc
            && s.qpc <= after
            && s.tid != tid
            && chosen.iter().any(|selected| selected.irp == s.irp)
    }) {
        return Err("correlation_missing_or_ambiguous");
    }
    Ok(count)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn s(qpc: i64, irp: u64) -> Start {
        Start {
            qpc,
            irp,
            tid: 3,
            share: 7,
        }
    }
    fn e(qpc: i64, irp: u64, status: u32) -> End {
        End { qpc, irp, status }
    }
    #[test]
    fn late_queued_callback_storage_survives_uncertain_close() {
        use std::{cell::Cell, rc::Rc, sync::mpsc};
        struct CountDrop(Rc<Cell<usize>>);
        impl Drop for CountDrop {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        let count = Rc::new(Cell::new(0));
        let (tx, rx) = mpsc::sync_channel(1);
        // Simulate a successful late send after both receiver deadlines elapsed.
        assert!(tx
            .send(CallbackStorage::new(CountDrop(count.clone())))
            .is_ok());
        drop(rx);
        assert_eq!(count.get(), 0);
        let mut closed = CallbackStorage::new(CountDrop(count.clone()));
        closed.allow_drop();
        drop(closed);
        assert_eq!(count.get(), 1);
    }
    #[test]
    fn original_runs_once_and_diagnostic_write_failure_preserves_error() {
        use std::{
            cell::Cell,
            io::{self, Write},
        };
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("synthetic"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let calls = Cell::new(0);
        let result = original_then(
            || {
                calls.set(calls.get() + 1);
                Err(io::Error::from_raw_os_error(32))
            },
            |result| {
                assert_eq!(result.as_ref().unwrap_err().raw_os_error(), Some(32));
                let _ = writeln!(Broken, "finite unavailable record");
            },
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(result.unwrap_err().raw_os_error(), Some(32));
        assert!(original_then(
            || Ok(()),
            |_| {
                let _ = writeln!(Broken, "finite");
            }
        )
        .is_ok());
    }
    #[test]
    fn sequential_reuse_and_mixed_statuses() {
        assert_eq!(
            correlate(
                &[s(2, 7), s(4, 7), s(6, 8)],
                &[e(3, 7, 0xc0000043), e(5, 7, 0), e(7, 8, 1)],
                1,
                8,
                3
            ),
            Ok(Counts {
                attempts: 3,
                successful: 1,
                sharing: 1,
                other: 1
            })
        );
    }
    #[test]
    fn ambiguous_missing_overlap_and_reorder_refused() {
        for (ss, ee) in [
            (vec![s(2, 7)], vec![]),
            (vec![s(2, 7)], vec![e(3, 7, 0), e(4, 7, 0)]),
            (vec![s(2, 7), s(3, 8)], vec![e(4, 7, 0), e(5, 8, 0)]),
            (vec![s(4, 7), s(2, 8)], vec![e(5, 7, 0), e(3, 8, 0)]),
            (vec![s(3, 7)], vec![e(2, 7, 0), e(4, 7, 0)]),
            (vec![s(2, 7), s(4, 8)], vec![e(5, 8, 0), e(3, 7, 0)]),
            (
                vec![s(2, 7), s(4, 8)],
                vec![e(3, 7, 0), e(5, 8, 0), e(6, 7, 0)],
            ),
        ] {
            assert!(correlate(&ss, &ee, 1, 8, 3).is_err());
        }
    }
    #[test]
    fn thread_window_schema_and_capacity_are_strict() {
        assert!(correlate(&[s(2, 7)], &[e(3, 7, 0)], 1, 8, 4).is_err());
        assert!(correlate(&[s(2, 7)], &[e(9, 7, 0)], 1, 8, 3).is_err());
        assert!(correlate(&[s(0, 7)], &[e(3, 7, 0)], 1, 8, 3).is_err());
        let mut wrong = s(2, 7);
        wrong.share = 3;
        assert!(correlate(&[wrong], &[e(3, 7, 0)], 1, 8, 3).is_err());
        assert!(correlate(&vec![s(2, 7); 129], &[], 1, 8, 3).is_err());
        let mut unrelated = s(6, 7);
        unrelated.tid = 4;
        assert!(correlate(&[s(2, 7), unrelated], &[e(3, 7, 0)], 1, 8, 3).is_err());
    }
}
