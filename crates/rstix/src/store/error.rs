//! Store errors.

use std::path::Path;

/// Errors from the STIX object store.
#[non_exhaustive]
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StoreError {
    /// Internal lock poisoned.
    #[error("store lock poisoned")]
    LockPoisoned,
    /// Query parameters are invalid.
    #[error("invalid store query: {0}")]
    InvalidQuery(String),
    /// Filesystem operation failed.
    #[error("I/O error at {path}: {message}")]
    Io {
        /// Path involved in the failure.
        path: String,
        /// OS error message.
        message: String,
    },
    /// JSON serialization or deserialization failed.
    #[error("JSON error: {0}")]
    Json(String),
}

impl StoreError {
    pub(crate) fn io(path: impl AsRef<Path>, err: std::io::Error) -> Self {
        Self::Io {
            path: path.as_ref().display().to_string(),
            message: err.to_string(),
        }
    }
}
