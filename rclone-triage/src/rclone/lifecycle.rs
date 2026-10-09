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
    finish_runtime_cleanup(binary.cleanup(), &mut std::io::stderr().lock())
}

fn finish_runtime_cleanup(result: Result<()>, writer: &mut impl std::io::Write) -> Result<()> {
    result.map_err(|error| {
        crate::embedded::write_runtime_cleanup_diagnostic(
            writer,
            crate::embedded::runtime_cleanup_diagnostic(&error),
        );
        uncertain(error)
    })
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
    fn cleanup_success_emits_nothing() {
        let mut written = Vec::new();
        finish_runtime_cleanup(Ok(()), &mut written).unwrap();
        assert!(written.is_empty());
    }

    #[test]
    fn cleanup_failure_emits_only_finite_fields_and_preserves_the_error_chain() {
        for already_uncertain in [false, true] {
            let original = anyhow::Error::new(std::io::Error::other("private-canary/path"))
                .context("private-context-canary");
            let original = if already_uncertain {
                uncertain(original)
            } else {
                original
            };
            let mut written = Vec::new();
            let error = finish_runtime_cleanup(Err(original), &mut written).unwrap_err();
            assert_eq!(written, b"runtime_cleanup_diagnostic={\"stage\":\"identity\",\"kind\":\"other\",\"os_code\":null}\n");
            assert!(written.len() <= 113);
            assert!(cleanup_uncertain(&error));
            assert_eq!(error.root_cause().to_string(), "private-canary/path");
            assert!(error.chain().any(|cause| cause.is::<std::io::Error>()));
            assert!(format!("{error:#}").contains("private-context-canary"));
            assert_eq!(
                error
                    .chain()
                    .filter(|cause| cause.is::<CleanupUncertain>())
                    .count(),
                1
            );
        }
    }

    #[test]
    fn diagnostic_writer_failure_cannot_replace_cleanup_failure() {
        struct FailedWriter;
        impl std::io::Write for FailedWriter {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("private-writer-canary"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("private-flush-canary"))
            }
        }
        let original = anyhow::Error::new(std::io::Error::from_raw_os_error(32));
        let error = finish_runtime_cleanup(Err(original), &mut FailedWriter).unwrap_err();
        assert!(cleanup_uncertain(&error));
        let source = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<std::io::Error>())
            .unwrap();
        assert_eq!(source.raw_os_error(), Some(32));
        assert!(!format!("{error:#}").contains("writer-canary"));
    }

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
