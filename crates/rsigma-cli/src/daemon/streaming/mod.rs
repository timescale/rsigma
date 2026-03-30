mod file_sink;
#[cfg(feature = "daemon-nats")]
mod nats_sink;
#[cfg(feature = "daemon-nats")]
mod nats_source;
mod stdin_source;
mod stdout_sink;

pub use file_sink::FileSink;
#[cfg(feature = "daemon-nats")]
pub use nats_sink::NatsSink;
#[cfg(feature = "daemon-nats")]
pub use nats_source::NatsSource;
pub use stdin_source::StdinSource;
pub use stdout_sink::StdoutSink;

use rsigma_eval::ProcessResult;

/// Errors from streaming sources and sinks.
#[derive(Debug)]
pub enum StreamingError {
    /// I/O error (stdin read, file write, etc.)
    Io(std::io::Error),
    /// JSON serialization error in a sink.
    Serialization(serde_json::Error),
}

impl std::fmt::Display for StreamingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamingError::Io(e) => write!(f, "I/O error: {e}"),
            StreamingError::Serialization(e) => write!(f, "serialization error: {e}"),
        }
    }
}

impl std::error::Error for StreamingError {}

impl From<std::io::Error> for StreamingError {
    fn from(e: std::io::Error) -> Self {
        StreamingError::Io(e)
    }
}

impl From<serde_json::Error> for StreamingError {
    fn from(e: serde_json::Error) -> Self {
        StreamingError::Serialization(e)
    }
}

/// Contract for event input adapters.
///
/// Each source reads events from a specific input (stdin, HTTP, NATS) and
/// yields raw JSON strings. Sources are used as concrete types (not `dyn`),
/// so `async fn` is valid without object-safety concerns.
pub trait EventSource: Send + 'static {
    /// Receive the next event as a raw JSON string.
    /// Returns `None` when the source is exhausted or shutting down.
    fn recv(&mut self) -> impl std::future::Future<Output = Option<String>> + Send;
}

/// Enum dispatch for output adapters.
///
/// Uses enum dispatch instead of `dyn Trait` because:
/// - Async trait methods are not object-safe
/// - `FanOut(Vec<Sink>)` requires a sized, concrete type
pub enum Sink {
    /// Write NDJSON to stdout.
    Stdout(StdoutSink),
    /// Append NDJSON to a file.
    File(FileSink),
    /// Publish NDJSON to a NATS subject.
    #[cfg(feature = "daemon-nats")]
    Nats(NatsSink),
    /// Fan out to multiple sinks.
    FanOut(Vec<Sink>),
}

impl Sink {
    /// Serialize and deliver a ProcessResult to this sink.
    ///
    /// Synchronous sinks (Stdout, File) use `block_in_place` to avoid blocking
    /// the Tokio runtime. Uses `Box::pin` for the FanOut case to handle
    /// recursive async.
    pub fn send<'a>(
        &'a mut self,
        result: &'a ProcessResult,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), StreamingError>> + Send + 'a>>
    {
        Box::pin(async move {
            match self {
                Sink::Stdout(s) => {
                    let s = &*s;
                    let result = result;
                    tokio::task::block_in_place(|| s.send(result))
                }
                Sink::File(s) => {
                    let s = &mut *s;
                    let result = result;
                    tokio::task::block_in_place(|| s.send(result))
                }
                #[cfg(feature = "daemon-nats")]
                Sink::Nats(s) => s.send(result).await,
                Sink::FanOut(sinks) => {
                    for sink in sinks {
                        sink.send(result).await?;
                    }
                    Ok(())
                }
            }
        })
    }
}

/// Spawn an EventSource as a tokio task wired to a shared event channel.
///
/// The source reads events in a loop via `recv()` and forwards them to
/// `event_tx`. When the source is exhausted or the channel is closed,
/// the task completes.
pub fn spawn_source<S: EventSource>(
    mut source: S,
    event_tx: tokio::sync::mpsc::Sender<String>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(line) = source.recv().await {
            if event_tx.send(line).await.is_err() {
                tracing::debug!("Event channel closed, source shutting down");
                break;
            }
        }
    })
}
