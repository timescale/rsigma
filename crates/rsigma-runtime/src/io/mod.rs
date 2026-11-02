mod delivery;
mod file;
mod lines;
#[cfg(feature = "nats")]
pub mod nats_config;
#[cfg(feature = "nats")]
mod nats_sink;
#[cfg(feature = "nats")]
mod nats_source;
#[cfg(feature = "otlp")]
pub mod otlp;
mod stdin;
mod stdout;
#[cfg(all(unix, feature = "uds"))]
mod unix;
#[cfg(all(unix, feature = "uds"))]
mod unix_sink;
#[cfg(all(unix, feature = "uds"))]
mod unix_source;
pub mod webhook;

pub use delivery::{
    DeliveryConfig, DeliveryContext, DeliveryFailure, DeliverySink, Dispatcher, OnFull,
};
pub use file::FileSink;
#[cfg(feature = "nats")]
pub use nats_config::NatsConnectConfig;
#[cfg(feature = "nats")]
pub use nats_sink::NatsSink;
#[cfg(feature = "nats")]
pub use nats_source::{NatsSource, ReplayPolicy};
pub use stdin::StdinSource;
pub use stdout::StdoutSink;
#[cfg(all(unix, feature = "uds"))]
pub use unix::{UnixSocketGuard, bind_unix_listener, parse_unix_scheme};
#[cfg(all(unix, feature = "uds"))]
pub use unix_sink::UnixSocketSink;
#[cfg(all(unix, feature = "uds"))]
pub use unix_source::UnixSocketSource;

use std::cell::Cell;
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use rsigma_eval::{EvaluationResult, ProcessResult};

use crate::error::RuntimeError;
use crate::metrics::MetricsHook;

/// Wire format a line-oriented sink serializes findings into.
///
/// Selected per sink with the `format` query parameter on an output spec
/// (`file:///findings.ndjson?format=ocsf`). Transport-independent: every
/// line sink (stdout, file, NATS, unix socket) accepts every format, while
/// OTLP has its own log-record mapping and webhooks render from templates.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SinkFormat {
    /// rsigma-native NDJSON, one result object per line.
    #[default]
    Ndjson,
    /// OCSF Detection Finding (class 2004) JSON, one finding per line.
    Ocsf,
}

impl SinkFormat {
    /// Lowercase wire name, as written in a sink spec and in logs.
    pub fn as_str(self) -> &'static str {
        match self {
            SinkFormat::Ndjson => "ndjson",
            SinkFormat::Ocsf => "ocsf",
        }
    }
}

/// Serialize one result in the sink's format.
///
/// `pretty` applies to both formats; only stdout sets it today.
pub(crate) fn serialize_result(
    result: &EvaluationResult,
    format: SinkFormat,
    pretty: bool,
    delivery: Option<(&DeliveryContext, usize)>,
) -> Result<String, RuntimeError> {
    match format {
        SinkFormat::Ndjson => Ok(if pretty {
            serde_json::to_string_pretty(result)?
        } else {
            serde_json::to_string(result)?
        }),
        SinkFormat::Ocsf => {
            let finding = match delivery {
                Some((ctx, index)) => {
                    let source = DeliveryFindingSource::new(ctx, index);
                    crate::ocsf::detection_finding_with(result, &source)
                }
                None => crate::ocsf::detection_finding(result),
            };
            Ok(if pretty {
                serde_json::to_string_pretty(&finding)?
            } else {
                serde_json::to_string(&finding)?
            })
        }
    }
}

/// Stable finding identity and timestamp derived from one dispatched result.
///
/// A fresh instance is created for each result and sink, but every instance
/// starts from the same delivery context and result index. That makes the two
/// generated OCSF identifiers and the timestamp identical across fan-out and
/// across retries of the same queued item.
struct DeliveryFindingSource<'a> {
    ctx: &'a DeliveryContext,
    index: usize,
    minted: Cell<u8>,
}

impl<'a> DeliveryFindingSource<'a> {
    fn new(ctx: &'a DeliveryContext, index: usize) -> Self {
        Self {
            ctx,
            index,
            minted: Cell::new(0),
        }
    }
}

impl crate::ocsf::FindingSource for DeliveryFindingSource<'_> {
    fn now_ms(&self) -> i64 {
        self.ctx
            .first_attempt()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .try_into()
            .unwrap_or(i64::MAX)
    }

    fn uid(&self) -> String {
        let sequence = self.minted.get();
        self.minted.set(sequence.saturating_add(1));
        format!("{}_{:04}_{sequence}", self.ctx.id_base(), self.index)
    }
}

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

    /// Extract the NATS JetStream stream sequence and published timestamp.
    ///
    /// Returns `None` for non-NATS tokens or if message info parsing fails.
    /// The tuple is `(stream_sequence, published_unix_timestamp_secs)`.
    #[cfg(feature = "nats")]
    pub fn nats_stream_position(&self) -> Option<(u64, i64)> {
        match self {
            AckToken::Noop => None,
            AckToken::Nats(msg) => msg
                .info()
                .ok()
                .map(|info| (info.stream_sequence, info.published.unix_timestamp())),
        }
    }
}

/// A pre-serialized native incident line plus an optional NATS subject override.
///
/// The alert pipeline produces structured `IncidentResult`s; the sink task
/// pairs its NDJSON representation with the configured subject override so the
/// delivery layer can route it without depending on alert-pipeline types.
pub struct IncidentEnvelope {
    /// The serialized incident NDJSON line.
    pub json: String,
    /// Optional NATS subject override for incident consumers.
    pub nats_subject: Option<String>,
}

impl IncidentEnvelope {
    /// Build an envelope from the native NDJSON line.
    pub fn new(json: String, nats_subject: Option<String>) -> Self {
        IncidentEnvelope { json, nats_subject }
    }
}

/// Pre-serialized incident lines keyed by sink format.
///
/// This wrapper leaves [`IncidentEnvelope`] source-compatible for downstream
/// callers while allowing the daemon to provide additional wire formats.
pub struct FormattedIncidentEnvelope {
    native: IncidentEnvelope,
    lines: Vec<(SinkFormat, String)>,
}

impl FormattedIncidentEnvelope {
    /// Wrap a native incident before adding alternate serializations.
    pub fn new(native: IncidentEnvelope) -> Self {
        Self {
            lines: vec![(SinkFormat::Ndjson, native.json.clone())],
            native,
        }
    }

    /// Add the line for another format, replacing any line already held for it.
    #[must_use]
    pub fn with_line(mut self, format: SinkFormat, json: String) -> Self {
        if format == SinkFormat::Ndjson {
            self.native.json = json.clone();
        }
        match self.lines.iter_mut().find(|(f, _)| *f == format) {
            Some((_, existing)) => *existing = json,
            None => self.lines.push((format, json)),
        }
        self
    }

    /// The line for `format`, falling back to the always-present NDJSON line
    /// when the sink task did not serialize that format.
    pub fn line(&self, format: SinkFormat) -> &str {
        self.lines
            .iter()
            .find(|(f, _)| *f == format)
            .map_or(self.native.json.as_str(), |(_, json)| json.as_str())
    }

    /// The native envelope, including its optional NATS subject override.
    pub fn native(&self) -> &IncidentEnvelope {
        &self.native
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

/// Run a synchronous sink write from async code.
///
/// On a multi-threaded Tokio runtime this goes through `block_in_place`, so
/// the worker's other tasks move to another thread while the write blocks.
/// `block_in_place` panics on a current-thread runtime, which has no other
/// worker to hand tasks to, so there (and outside any runtime) the write runs
/// inline.
fn blocking_write<R>(write: impl FnOnce() -> R) -> R {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(write)
        }
        _ => write(),
    }
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
    /// Export results to an OpenTelemetry collector via OTLP.
    #[cfg(feature = "otlp")]
    Otlp(Box<otlp::OtlpSink>),
    /// Render and POST a templated HTTP request per result.
    Webhook(Box<webhook::WebhookSink>),
    /// Write NDJSON to a Unix domain socket (client connection).
    #[cfg(all(unix, feature = "uds"))]
    Unix(Box<UnixSocketSink>),
    /// Fan out to multiple sinks.
    FanOut(Vec<Sink>),
}

impl Sink {
    /// Serialize and deliver a ProcessResult to this sink.
    ///
    /// Synchronous sinks (Stdout, File) write through `blocking_write` to
    /// avoid stalling a multi-threaded Tokio runtime. Uses `Box::pin` for the
    /// FanOut case to handle recursive async.
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
                    blocking_write(|| s.send(result))
                }
                Sink::File(s) => {
                    let s = &mut *s;
                    let result = result;
                    blocking_write(|| s.send(result))
                }
                #[cfg(feature = "nats")]
                Sink::Nats(s) => s.send(result).await,
                #[cfg(feature = "otlp")]
                Sink::Otlp(s) => s.send(result).await,
                // The delivery layer drives webhooks through `DeliverySink`
                // with a per-item context; this direct path is a completeness
                // fallback, so it mints a one-shot context.
                Sink::Webhook(s) => s.send(result, &DeliveryContext::new()).await,
                #[cfg(all(unix, feature = "uds"))]
                Sink::Unix(s) => s.send(result).await,
                Sink::FanOut(sinks) => {
                    for (idx, sink) in sinks.iter_mut().enumerate() {
                        if let Err(e) = sink.send(result).await {
                            tracing::warn!(
                                sink_index = idx,
                                sink_type = sink.kind_label(),
                                error = %e,
                                "Fan-out child sink failed",
                            );
                            return Err(e);
                        }
                    }
                    Ok(())
                }
            }
        })
    }

    pub(crate) fn send_with_context<'a>(
        &'a mut self,
        result: &'a ProcessResult,
        ctx: &'a DeliveryContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + 'a>>
    {
        Box::pin(async move {
            match self {
                Sink::Stdout(s) => blocking_write(|| s.send_with_context(result, ctx)),
                Sink::File(s) => blocking_write(|| s.send_with_context(result, ctx)),
                #[cfg(feature = "nats")]
                Sink::Nats(s) => s.send_with_context(result, ctx).await,
                #[cfg(feature = "otlp")]
                Sink::Otlp(s) => s.send(result).await,
                Sink::Webhook(s) => s.send(result, ctx).await,
                #[cfg(all(unix, feature = "uds"))]
                Sink::Unix(s) => s.send_with_context(result, ctx).await,
                Sink::FanOut(sinks) => {
                    for (idx, sink) in sinks.iter_mut().enumerate() {
                        if let Err(e) = sink.send_with_context(result, ctx).await {
                            tracing::warn!(
                                sink_index = idx,
                                sink_type = sink.kind_label(),
                                error = %e,
                                "Fan-out child sink failed",
                            );
                            return Err(e);
                        }
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
                Sink::Stdout(s) => blocking_write(|| s.send_raw(json)),
                Sink::File(s) => blocking_write(|| s.send_raw(json)),
                #[cfg(feature = "nats")]
                Sink::Nats(s) => s.send_raw(json).await,
                #[cfg(feature = "otlp")]
                Sink::Otlp(s) => s.send_raw(json).await,
                // A webhook renders from structured results, not a
                // pre-serialized JSON line, so a raw send is a no-op. The
                // delivery path always uses `send`, so this is never hit on
                // the webhook hot path.
                Sink::Webhook(_) => Ok(()),
                #[cfg(all(unix, feature = "uds"))]
                Sink::Unix(s) => s.send_raw(json).await,
                Sink::FanOut(sinks) => {
                    for (idx, sink) in sinks.iter_mut().enumerate() {
                        if let Err(e) = sink.send_raw(json).await {
                            tracing::warn!(
                                sink_index = idx,
                                sink_type = sink.kind_label(),
                                error = %e,
                                "Fan-out child sink failed (raw)",
                            );
                            return Err(e);
                        }
                    }
                    Ok(())
                }
            }
        })
    }

    /// Deliver a pre-serialized incident line to this sink.
    ///
    /// Stdout/file write the line inline; NATS publishes to the per-incident
    /// subject override when set, else the sink's configured subject. OTLP
    /// sinks no-op, since incidents are not OTLP log records. Webhooks post
    /// only when declared `kind: incident`.
    pub fn send_incident<'a>(
        &'a mut self,
        env: &'a IncidentEnvelope,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + 'a>>
    {
        Box::pin(async move {
            match self {
                Sink::Stdout(s) => blocking_write(|| s.send_raw(&env.json)),
                Sink::File(s) => blocking_write(|| s.send_raw(&env.json)),
                #[cfg(feature = "nats")]
                Sink::Nats(s) => {
                    s.send_incident(&env.json, env.nats_subject.as_deref())
                        .await
                }
                #[cfg(feature = "otlp")]
                Sink::Otlp(_) => Ok(()),
                Sink::Webhook(s) => s.send_incident(&env.json, &DeliveryContext::new()).await,
                #[cfg(all(unix, feature = "uds"))]
                Sink::Unix(s) => s.send_raw(&env.json).await,
                Sink::FanOut(sinks) => {
                    for (idx, sink) in sinks.iter_mut().enumerate() {
                        if let Err(e) = sink.send_incident(env).await {
                            tracing::warn!(
                                sink_index = idx,
                                sink_type = sink.kind_label(),
                                error = %e,
                                "Fan-out child sink failed (incident)",
                            );
                            return Err(e);
                        }
                    }
                    Ok(())
                }
            }
        })
    }

    /// Deliver an incident using the serialization selected by each sink.
    pub fn send_formatted_incident<'a>(
        &'a mut self,
        env: &'a FormattedIncidentEnvelope,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), RuntimeError>> + Send + 'a>>
    {
        Box::pin(async move {
            match self {
                Sink::Stdout(s) => blocking_write(|| s.send_raw(env.line(s.format()))),
                Sink::File(s) => blocking_write(|| s.send_raw(env.line(s.format()))),
                #[cfg(feature = "nats")]
                Sink::Nats(s) => {
                    s.send_incident(env.line(s.format()), env.native().nats_subject.as_deref())
                        .await
                }
                #[cfg(feature = "otlp")]
                Sink::Otlp(_) => Ok(()),
                Sink::Webhook(s) => {
                    s.send_incident(&env.native().json, &DeliveryContext::new())
                        .await
                }
                #[cfg(all(unix, feature = "uds"))]
                Sink::Unix(s) => s.send_raw(env.line(s.format())).await,
                Sink::FanOut(sinks) => {
                    for (idx, sink) in sinks.iter_mut().enumerate() {
                        if let Err(e) = sink.send_formatted_incident(env).await {
                            tracing::warn!(
                                sink_index = idx,
                                sink_type = sink.kind_label(),
                                error = %e,
                                "Fan-out child sink failed (incident)",
                            );
                            return Err(e);
                        }
                    }
                    Ok(())
                }
            }
        })
    }

    /// The wire format this sink serializes into, for line-oriented sinks.
    ///
    /// `None` for sinks that own their encoding (OTLP log records, templated
    /// webhook bodies) and for a `FanOut`, whose leaves each carry their own.
    pub fn format(&self) -> Option<SinkFormat> {
        match self {
            Sink::Stdout(s) => Some(s.format()),
            Sink::File(s) => Some(s.format()),
            #[cfg(feature = "nats")]
            Sink::Nats(s) => Some(s.format()),
            #[cfg(feature = "otlp")]
            Sink::Otlp(_) => None,
            Sink::Webhook(_) => None,
            #[cfg(all(unix, feature = "uds"))]
            Sink::Unix(s) => Some(s.format()),
            Sink::FanOut(_) => None,
        }
    }

    /// Short label for the sink variant, used in structured logs and per-sink
    /// delivery metrics.
    pub(crate) fn kind_label(&self) -> &'static str {
        match self {
            Sink::Stdout(_) => "stdout",
            Sink::File(_) => "file",
            #[cfg(feature = "nats")]
            Sink::Nats(_) => "nats",
            #[cfg(feature = "otlp")]
            Sink::Otlp(_) => "otlp",
            // The webhook id (leaked to `&'static`) so its shared per-sink
            // series maps one-to-one to the `rsigma_webhook_*` series.
            Sink::Webhook(s) => s.label(),
            #[cfg(all(unix, feature = "uds"))]
            Sink::Unix(_) => "unix",
            Sink::FanOut(_) => "fanout",
        }
    }

    /// Flatten a (possibly nested) `FanOut` into its leaf sinks.
    ///
    /// The delivery layer runs one worker per leaf, so fan-out is realized by
    /// the dispatcher rather than by a `FanOut` variant on the hot path.
    pub fn into_leaves(self) -> Vec<Sink> {
        match self {
            Sink::FanOut(sinks) => sinks.into_iter().flat_map(Sink::into_leaves).collect(),
            leaf => vec![leaf],
        }
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
                        tracing::warn!("Input channel full, backpressure applied");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ocsf::FindingSource;

    #[test]
    fn envelope_falls_back_to_the_native_line() {
        let env = FormattedIncidentEnvelope::new(IncidentEnvelope::new(
            "{\"incident_id\":\"i-1\"}".to_string(),
            None,
        ));
        assert_eq!(env.line(SinkFormat::Ndjson), "{\"incident_id\":\"i-1\"}");
        assert_eq!(
            env.line(SinkFormat::Ocsf),
            "{\"incident_id\":\"i-1\"}",
            "a sink whose format was not serialized still gets the native line",
        );
    }

    #[test]
    fn envelope_serves_each_format_its_own_line() {
        let env = FormattedIncidentEnvelope::new(IncidentEnvelope::new(
            "native".to_string(),
            Some("incidents".to_string()),
        ))
        .with_line(SinkFormat::Ocsf, "finding".to_string());
        assert_eq!(env.line(SinkFormat::Ndjson), "native");
        assert_eq!(env.line(SinkFormat::Ocsf), "finding");
        assert_eq!(env.native().nats_subject.as_deref(), Some("incidents"));
    }

    #[test]
    fn with_line_replaces_an_existing_format() {
        let env = FormattedIncidentEnvelope::new(IncidentEnvelope::new("native".to_string(), None))
            .with_line(SinkFormat::Ocsf, "first".to_string())
            .with_line(SinkFormat::Ocsf, "second".to_string());
        assert_eq!(env.line(SinkFormat::Ocsf), "second");
        assert_eq!(env.line(SinkFormat::Ndjson), "native");

        let native =
            FormattedIncidentEnvelope::new(IncidentEnvelope::new("first".to_string(), None))
                .with_line(SinkFormat::Ndjson, "second".to_string());
        assert_eq!(native.line(SinkFormat::Ndjson), "second");
        assert_eq!(native.native().json, "second");
    }

    #[test]
    fn native_envelope_keeps_its_public_struct_literal() {
        let env = IncidentEnvelope {
            json: "native".to_string(),
            nats_subject: None,
        };
        assert_eq!(env.json, "native");
    }

    #[test]
    fn delivery_finding_source_is_stable_for_the_same_result() {
        let ctx = DeliveryContext::new();
        let first = DeliveryFindingSource::new(&ctx, 2);
        let second = DeliveryFindingSource::new(&ctx, 2);

        assert_eq!(first.now_ms(), second.now_ms());
        assert_eq!(first.uid(), second.uid());
        assert_eq!(first.uid(), second.uid());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn file_sink_writes_on_a_current_thread_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.ndjson");
        let mut sink = Sink::File(file::FileSink::open(&path).unwrap());

        sink.send(&Vec::new()).await.unwrap();
        sink.send_with_context(&Vec::new(), &DeliveryContext::new())
            .await
            .unwrap();
        sink.send_raw("{\"a\":1}").await.unwrap();
        sink.send_incident(&IncidentEnvelope::new("{\"b\":2}".to_string(), None))
            .await
            .unwrap();

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{\"a\":1}\n{\"b\":2}\n"
        );
    }
}
