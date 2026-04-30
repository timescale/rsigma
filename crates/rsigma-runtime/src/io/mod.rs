mod file;
#[cfg(feature = "nats")]
pub mod nats_config;
#[cfg(feature = "nats")]
mod nats_sink;
#[cfg(feature = "nats")]
mod nats_source;
mod stdin;
mod stdout;

pub use file::FileSink;
#[cfg(feature = "nats")]
pub use nats_config::NatsConnectConfig;
#[cfg(feature = "nats")]
pub use nats_sink::NatsSink;
#[cfg(feature = "nats")]
pub use nats_source::{NatsSource, ReplayPolicy};
pub use stdin::StdinSource;
pub use stdout::StdoutSink;

use std::sync::Arc;

use rsigma_eval::ProcessResult;

use crate::error::RuntimeError;
use crate::metrics::MetricsHook;

/// Opaque acknowledgment handle returned alongside each event.
///
/// For NATS JetStream sources, calling `ack()` confirms message delivery to the
/// server. For stdin/HTTP sources, ack is a no-op. This enum avoids dynamic
/// dispatch and mirrors the `Sink` enum pattern.
pub enum AckToken {
    /// No acknowledgment needed (stdin, HTTP).
    Noop,
    /// NATS JetStream message that must be acked after processing.
    #[cfg(feature = "nats")]
    Nats(Box<async_nats::jetstream::Message>),
}

impl AckToken {
    /// Acknowledge the event. For NATS, this confirms delivery to the server.
    pub async fn ack(self) {
        match self {
            AckToken::Noop => {}
            #[cfg(feature = "nats")]
            AckToken::Nats(msg) => {
                if let Err(e) = msg.ack().await {
                    tracing::warn!(error = %e, "Failed to ack NATS message");
                }
            }
        }
    }
}

/// An event payload bundled with its acknowledgment token.
///
/// Sources produce `RawEvent`s; the engine extracts `payload` for processing
/// and forwards `ack_token` through the pipeline so it can be acked after the
/// sink successfully delivers.
pub struct RawEvent {
    pub payload: String,
    pub ack_token: AckToken,
}

/// Contract for event input adapters.
///
/// Each source reads events from a specific input (stdin, HTTP, NATS) and
/// yields `RawEvent`s containing the raw payload and an acknowledgment token.
/// Sources are used as concrete types (not `dyn`), so `async fn` is valid
/// without object-safety concerns.
pub trait EventSource: Send + 'static {
    /// Receive the next event with its ack token.
    /// Returns `None` when the source is exhausted or shutting down.
    fn recv(&mut self) -> impl std::future::Future<Output = Option<RawEvent>> + Send;
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
    /// Publish NDJSON to a NATS JetStream subject.
    #[cfg(feature = "nats")]
    Nats(Box<NatsSink>),
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
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + 'a>>
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
                #[cfg(feature = "nats")]
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

    /// Write a pre-serialized JSON string directly to this sink.
    pub fn send_raw<'a>(
        &'a mut self,
        json: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + 'a>>
    {
        Box::pin(async move {
            match self {
                Sink::Stdout(s) => tokio::task::block_in_place(|| s.send_raw(json)),
                Sink::File(s) => tokio::task::block_in_place(|| s.send_raw(json)),
                #[cfg(feature = "nats")]
                Sink::Nats(s) => s.send_raw(json).await,
                Sink::FanOut(sinks) => {
                    for sink in sinks {
                        sink.send_raw(json).await?;
                    }
                    Ok(())
                }
            }
        })
    }
}

/// Spawn an EventSource as a tokio task wired to a shared event channel.
///
/// The source reads events in a loop via `recv()` and forwards `RawEvent`s to
/// `event_tx`. When the source is exhausted or the channel is closed,
/// the task completes. Tracks input queue depth and back-pressure metrics
/// via the provided `MetricsHook`.
pub fn spawn_source<S: EventSource>(
    mut source: S,
    event_tx: tokio::sync::mpsc::Sender<RawEvent>,
    metrics: Option<Arc<dyn MetricsHook>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(raw_event) = source.recv().await {
            if let Some(ref m) = metrics {
                match event_tx.try_send(raw_event) {
                    Ok(()) => {
                        m.on_input_queue_depth_change(1);
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Full(raw_event)) => {
                        m.on_back_pressure();
                        m.on_input_queue_depth_change(1);
                        if event_tx.send(raw_event).await.is_err() {
                            tracing::debug!("Event channel closed, source shutting down");
                            break;
                        }
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        tracing::debug!("Event channel closed, source shutting down");
                        break;
                    }
                }
            } else if event_tx.send(raw_event).await.is_err() {
                tracing::debug!("Event channel closed, source shutting down");
                break;
            }
        }
    })
}
