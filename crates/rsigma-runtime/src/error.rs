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
