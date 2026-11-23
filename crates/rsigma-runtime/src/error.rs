/// Errors from the rsigma runtime (streaming I/O, processing, engine operations).
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    /// I/O error (stdin read, file write, etc.)
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON serialization error in a sink.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    /// A permanent delivery failure that must not be retried (for example a
    /// 4xx from a webhook target whose rendered body will not heal on retry).
    /// The async delivery layer routes these straight to the DLQ instead of
    /// applying the retry/backoff schedule.
    #[error("permanent delivery failure: {0}")]
    Permanent(String),
}

impl RuntimeError {
    /// An equivalent error for another delivery that failed for the same
    /// reason: same variant (a serialization error becomes I/O), kind, and
    /// message.
    pub(crate) fn duplicate(&self) -> RuntimeError {
        match self {
            RuntimeError::Io(err) => {
                RuntimeError::Io(std::io::Error::new(err.kind(), err.to_string()))
            }
            RuntimeError::Serialization(err) => {
                RuntimeError::Io(std::io::Error::other(err.to_string()))
            }
            RuntimeError::Permanent(message) => RuntimeError::Permanent(message.clone()),
        }
    }
}
