//! Explicit runtime finalization and bounded UI worker completion.

use crate::embedded::ExtractedBinary;
use anyhow::{Context, Result};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub(crate) use crate::rclone::lifecycle::{cleanup_runtime, cleanup_uncertain, complete};

/// A synchronous flow either transfers ownership or explicitly finalizes it.
pub(crate) struct RuntimeSlot(Option<ExtractedBinary>);
impl std::ops::Deref for RuntimeSlot {
    type Target = ExtractedBinary;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("Runtime already transferred")
    }
}
impl RuntimeSlot {
    pub(crate) fn take(&mut self) -> Result<ExtractedBinary> {
        self.0.take().context("Runtime already transferred")
    }
}

pub(crate) fn with_runtime<T>(
    binary: ExtractedBinary,
    operation: impl FnOnce(&mut RuntimeSlot) -> Result<T>,
) -> Result<T> {
    let mut owner = RuntimeSlot(Some(binary));
    let result = operation(&mut owner);
    let cleanup = match owner.0.as_mut() {
        Some(binary) => cleanup_runtime(binary),
        None => Ok(()),
    };
    complete(result, cleanup)
}

pub(crate) const WORKER_TIMEOUT: Duration = Duration::from_secs(30);

/// A timed-out worker keeps its captured runtime; callers must retain config state.
pub(crate) fn join_worker<T>(handle: JoinHandle<T>) -> Result<T> {
    join_worker_for(handle, WORKER_TIMEOUT)
}

fn join_worker_for<T>(handle: JoinHandle<T>, timeout: Duration) -> Result<T> {
    let deadline = Instant::now() + timeout;
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            anyhow::bail!("Worker shutdown could not be confirmed; owned resources retained");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    handle
        .join()
        .map_err(|_| anyhow::anyhow!("Worker panicked; shutdown is uncertain"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn operation_and_cleanup_failures_both_survive() {
        let error = complete::<()>(
            Err(anyhow::anyhow!("operation sentinel")),
            Err(anyhow::anyhow!("cleanup sentinel")),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("operation sentinel"));
        assert!(format!("{error:#}").contains("cleanup sentinel"));
        assert!(complete(Ok(()), Err(anyhow::anyhow!("cleanup sentinel"))).is_err());
    }
    #[test]
    fn typed_cleanup_uncertainty_survives_an_operation_error_context() {
        let failure: anyhow::Error =
            crate::rclone::lifecycle::uncertain(anyhow::anyhow!("cleanup sentinel"));
        let error =
            complete::<()>(Err(anyhow::anyhow!("original operation")), Err(failure)).unwrap_err();
        assert!(cleanup_uncertain(&error));
        assert!(format!("{error:#}").contains("original operation"));
        assert!(!cleanup_uncertain(&anyhow::anyhow!(
            "ordinary operation error"
        )));
    }

    #[test]
    fn terminal_report_and_worker_failures_are_all_retained() {
        let postprocessing = Err(anyhow::anyhow!("report write sentinel"));
        let operation = complete::<()>(Err(anyhow::anyhow!("terminal sentinel")), postprocessing);
        let worker = Err(crate::rclone::lifecycle::uncertain(anyhow::anyhow!(
            "worker cleanup sentinel"
        )));
        let error = complete(operation, worker).unwrap_err();
        let rendered = format!("{error:#}");
        for cause in [
            "terminal sentinel",
            "report write sentinel",
            "worker cleanup sentinel",
        ] {
            assert!(rendered.contains(cause));
        }
        assert!(cleanup_uncertain(&error));
    }

    #[test]
    fn unfinished_worker_retains_its_owner_after_bounded_join() {
        let (release, wait) = std::sync::mpsc::channel();
        let (dropped, observed) = std::sync::mpsc::channel();
        struct Owner(std::sync::mpsc::Sender<()>);
        impl Drop for Owner {
            fn drop(&mut self) {
                let _ = self.0.send(());
            }
        }
        let handle = std::thread::spawn(move || {
            let _owner = Owner(dropped);
            wait.recv().unwrap();
        });
        assert!(join_worker_for(handle, Duration::ZERO).is_err());
        assert!(observed.try_recv().is_err());
        release.send(()).unwrap();
        observed.recv_timeout(Duration::from_secs(2)).unwrap();
    }
}
