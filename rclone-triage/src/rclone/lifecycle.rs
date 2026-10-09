//! Typed resource finalization shared by backends and their callers.

use crate::embedded::ExtractedBinary;
use anyhow::Result;

#[derive(Debug)]
struct CleanupContext(anyhow::Error);
impl std::fmt::Display for CleanupContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Resource cleanup also failed: {:#}", self.0)
    }
}

/// A failed finalization cannot establish that resources are safe to replace.
#[derive(Debug)]
struct CleanupUncertain(anyhow::Error);
impl std::fmt::Display for CleanupUncertain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Resource finalization is uncertain: {:#}", self.0)
    }
}
impl std::error::Error for CleanupUncertain {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

pub(crate) fn uncertain(error: anyhow::Error) -> anyhow::Error {
    if cleanup_uncertain(&error) {
        error
    } else {
        CleanupUncertain(error).into()
    }
}

pub(crate) fn cleanup_runtime(binary: &mut ExtractedBinary) -> Result<()> {
    binary.cleanup().map_err(uncertain)
}

pub(crate) fn cleanup_uncertain(error: &anyhow::Error) -> bool {
    error.downcast_ref::<CleanupUncertain>().is_some()
        || error.chain().any(|cause| cause.is::<CleanupUncertain>())
}

/// Preserve both failures and their uncertainty even through multiple combinations.
/// An ordinary operation/report failure is not evidence of incomplete cleanup.
pub(crate) fn complete<T>(operation: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (operation, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(operation), Err(cleanup)) => {
            let retained = cleanup_uncertain(&operation) || cleanup_uncertain(&cleanup);
            let error = operation.context(CleanupContext(cleanup));
            Err(if retained { uncertain(error) } else { error })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_startup_or_persistence_failure_does_not_imply_uncertain_cleanup() {
        for operation in ["startup rejected", "manifest write failed"] {
            let error = complete::<()>(Err(anyhow::anyhow!(operation)), Ok(())).unwrap_err();
            assert!(!cleanup_uncertain(&error));
            assert_eq!(error.to_string(), operation);
        }
        let error = complete::<()>(
            Err(anyhow::anyhow!("terminal failed")),
            Err(anyhow::anyhow!("manifest failed")),
        )
        .unwrap_err();
        assert!(!cleanup_uncertain(&error));
        assert!(format!("{error:#}").contains("terminal failed"));
        assert!(format!("{error:#}").contains("manifest failed"));
    }

    #[test]
    fn nested_operation_and_cleanup_failures_keep_uncertainty_and_all_causes() {
        for uncertain_first in [false, true] {
            let operation = Err(anyhow::anyhow!("operation sentinel"));
            let cleanup = Err(uncertain(anyhow::anyhow!("child drain sentinel")));
            let first = complete::<()>(operation, cleanup);
            let error = if uncertain_first {
                complete(first, Err(anyhow::anyhow!("report sentinel")))
            } else {
                complete(Err(anyhow::anyhow!("report sentinel")), first)
            }
            .unwrap_err()
            .context("outer operation context");
            assert!(cleanup_uncertain(&error));
            for expected in [
                "operation sentinel",
                "child drain sentinel",
                "report sentinel",
            ] {
                assert!(format!("{error:#}").contains(expected));
            }
        }
    }
}
