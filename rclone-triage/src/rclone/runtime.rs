//! Per-extraction spawn gate. A lease is not an exit certificate until completed.

use std::io;
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
struct State {
    sealed: bool,
    uncertain: bool,
    active: usize,
}

#[derive(Debug, Default)]
pub(crate) struct RuntimeTracker(Mutex<State>);

impl RuntimeTracker {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub(crate) fn reserve(self: &Arc<Self>) -> io::Result<RuntimeLease> {
        let mut state = self.0.lock().map_err(|error| {
            error.into_inner().uncertain = true;
            io::Error::other("runtime_state_poisoned")
        })?;
        if state.sealed || state.uncertain {
            return Err(io::Error::other("runtime_spawn_gate_closed"));
        }
        state.active = state
            .active
            .checked_add(1)
            .ok_or_else(|| io::Error::other("runtime_lease_limit"))?;
        Ok(RuntimeLease {
            tracker: self.clone(),
            completed: false,
        })
    }

    /// Serialize cleanup with reservation, not merely with the eventual spawn.
    pub(crate) fn seal(&self) -> io::Result<()> {
        let mut state = self.0.lock().unwrap_or_else(|error| {
            let mut state = error.into_inner();
            state.uncertain = true;
            state
        });
        state.sealed = true;
        if state.uncertain || state.active != 0 {
            state.uncertain = true;
            return Err(io::Error::other("runtime_children_unconfirmed"));
        }
        Ok(())
    }

    pub(crate) fn retain(&self) {
        let mut state = self.0.lock().unwrap_or_else(|error| error.into_inner());
        state.uncertain = true;
        state.sealed = true;
    }

    fn release(&self, completed: bool) {
        let mut state = self.0.lock().unwrap_or_else(|error| {
            let mut state = error.into_inner();
            state.uncertain = true;
            state
        });
        state.uncertain |= !completed;
        if state.active == 0 {
            state.uncertain = true;
        } else {
            state.active -= 1;
        }
    }
}

pub(crate) struct RuntimeLease {
    tracker: Arc<RuntimeTracker>,
    completed: bool,
}

impl RuntimeLease {
    /// Also used when Command::spawn failed: there never was a child to reap.
    pub(crate) fn complete(mut self) {
        self.completed = true;
    }
}

impl Drop for RuntimeLease {
    fn drop(&mut self) {
        self.tracker.release(self.completed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealing_rejects_future_spawns_and_active_cleanup_is_sticky() {
        let tracker = RuntimeTracker::new();
        let lease = tracker.reserve().unwrap();
        assert!(tracker.seal().is_err());
        lease.complete();
        assert!(tracker.seal().is_err());
        assert!(tracker.reserve().is_err());
        let clean = RuntimeTracker::new();
        clean.reserve().unwrap().complete();
        clean.seal().unwrap();
        assert!(clean.reserve().is_err());
    }

    #[test]
    fn unconfirmed_drop_or_poison_never_becomes_clean() {
        let tracker = RuntimeTracker::new();
        drop(tracker.reserve().unwrap());
        assert!(tracker.seal().is_err());
        let tracker = RuntimeTracker::new();
        let other = tracker.clone();
        let _ = std::panic::catch_unwind(move || {
            let _locked = other.0.lock().unwrap();
            panic!("synthetic state failure");
        });
        assert!(tracker.reserve().is_err());
        assert!(tracker.seal().is_err());
    }

    #[test]
    fn cleanup_and_spawn_reservation_are_one_atomic_admission_decision() {
        let tracker = RuntimeTracker::new();
        let gate = Arc::new(std::sync::Barrier::new(2));
        let (attempted, seen) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let other = tracker.clone();
        let other_gate = gate.clone();
        let worker = std::thread::spawn(move || {
            other_gate.wait();
            let reservation = other.reserve();
            attempted.send(reservation.is_ok()).unwrap();
            released.recv().unwrap();
            if let Ok(lease) = reservation {
                lease.complete();
            }
        });
        gate.wait();
        let sealed = tracker.seal();
        let reserved = seen.recv().unwrap();
        assert_eq!(sealed.is_ok(), !reserved);
        release.send(()).unwrap();
        worker.join().unwrap();
        assert!(tracker.reserve().is_err());
        assert_eq!(tracker.seal().is_ok(), !reserved);
    }
}
