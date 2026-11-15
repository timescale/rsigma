//! Errors raised while resolving a named ruleset.

use std::path::PathBuf;

use thiserror::Error;

/// A failure while resolving a ruleset. Every variant maps to a configuration
/// error (exit 3) at the CLI, except source parse errors, which follow each
/// command's existing policy.
#[derive(Debug, Error)]
pub enum RulesetError {
    #[error("invalid ruleset: {}", .0.join("; "))]
    InvalidSpec(Vec<String>),
    #[error("source path does not exist: {}", .0.display())]
    MissingSource(PathBuf),
    #[error("cannot read {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("path escapes the confined root: {}", .0.display())]
    Confinement(PathBuf),
    #[error("{0}")]
    Selector(String),
    #[error("correlation dependencies could not be resolved: {}", .0.join("; "))]
    Dependency(Vec<String>),
    #[error("{0}")]
    Duplicate(String),
    #[error("{0}")]
    Overlay(String),
    #[error("stale overlays: {}", .0.join("; "))]
    StaleOverlay(Vec<String>),
}

impl RulesetError {
    /// Prefix a message with the ruleset name, for variants that carry only a
    /// path or a message.
    pub(crate) fn named(self, name: &str) -> Self {
        match self {
            Self::MissingSource(path) => Self::Selector(format!(
                "ruleset '{name}': source path does not exist: {}",
                path.display()
            )),
            Self::Io { path, source } => Self::Selector(format!(
                "ruleset '{name}': cannot read {}: {source}",
                path.display()
            )),
            Self::Confinement(path) => Self::Selector(format!(
                "ruleset '{name}': path escapes the confined root: {}",
                path.display()
            )),
            other => other,
        }
    }
}
