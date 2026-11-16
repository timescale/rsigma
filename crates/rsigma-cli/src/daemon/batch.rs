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
