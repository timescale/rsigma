use crate::exit_code;

use super::server::DaemonConfig;

impl DaemonConfig {
    /// Whether this run reads events from stdin, the only input that ends on
    /// its own and can therefore run as a batch.
    pub(crate) fn reads_stdin(&self) -> bool {
        matches!(self.input.as_str(), "stdin" | "stdin://")
    }
}

/// Refuse to start a stdin run whose stored state cannot be restored. Nothing
/// has been written to the database at this point, so the stored snapshot is
/// left untouched for inspection or for a later `--clear-state` run.
pub(crate) fn exit_unrestorable(store: &'static str, reason: &str) -> ! {
    tracing::error!(
        store,
        reason,
        "Stored state cannot be restored; pass --clear-state to start fresh"
    );
    std::process::exit(exit_code::CONFIG_ERROR);
}

/// Why a stdin batch run did not complete cleanly.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct BatchFailures {
    /// A signal or the API server stopped the run before stdin ended.
    pub interrupted: bool,
    /// The stdin reader stopped on a read error instead of at end of input.
    pub input_read_error: bool,
    /// Entries that reached neither a sink nor the DLQ.
    pub undelivered: u64,
    /// The final state save returned an error.
    pub state_save_failed: bool,
}

impl BatchFailures {
    pub(crate) fn is_clean(&self) -> bool {
        !self.interrupted
            && !self.input_read_error
            && self.undelivered == 0
            && !self.state_save_failed
    }

    pub(crate) fn exit_code(&self) -> i32 {
        if self.is_clean() {
            exit_code::SUCCESS
        } else {
            exit_code::RUNTIME_ERROR
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_batch_exits_zero() {
        assert_eq!(BatchFailures::default().exit_code(), exit_code::SUCCESS);
    }

    #[test]
    fn each_failure_exits_with_a_runtime_error() {
        let cases = [
            BatchFailures {
                interrupted: true,
                ..BatchFailures::default()
            },
            BatchFailures {
                input_read_error: true,
                ..BatchFailures::default()
            },
            BatchFailures {
                undelivered: 1,
                ..BatchFailures::default()
            },
            BatchFailures {
                state_save_failed: true,
                ..BatchFailures::default()
            },
        ];
        for failures in cases {
            assert_eq!(failures.exit_code(), exit_code::RUNTIME_ERROR);
        }
    }
}
