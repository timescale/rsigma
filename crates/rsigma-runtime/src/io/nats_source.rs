use std::sync::Arc;

use async_nats::jetstream;
use async_nats::jetstream::AckKind;
use async_nats::jetstream::consumer::DeliverPolicy;
use tokio_stream::StreamExt;

use super::line_framer::MAX_LINE_BYTES;
use super::nats_config::NatsConnectConfig;
use super::{AckToken, EventSource, RawEvent};
use crate::metrics::MetricsHook;

/// Derive a NATS-safe name by combining a prefix with the subject.
/// Replaces characters not allowed in NATS stream/consumer names (`.`, `>`, `*`)
/// with dashes and strips trailing dashes.
pub(crate) fn derive_nats_name(prefix: &str, subject: &str) -> String {
    let sanitized: String = subject
        .chars()
        .map(|c| match c {
            '.' | '>' | '*' => '-',
            _ => c,
        })
        .collect();
    format!("{}-{}", prefix, sanitized.trim_end_matches('-'))
}

/// Controls where the NATS consumer starts reading from in the stream.
#[derive(Debug, Clone, Default)]
pub enum ReplayPolicy {
    /// Resume from the last acked position (durable consumer default).
    #[default]
    Resume,
    /// Start from a specific stream sequence number.
    FromSequence(u64),
    /// Start from a specific timestamp (ISO 8601).
    FromTime(time::OffsetDateTime),
    /// Start from the latest message, skipping history.
    Latest,
}

/// NATS JetStream consumer that yields events.
///
/// Uses at-least-once delivery: messages are held until the downstream
/// pipeline (engine + sink) confirms successful processing, then acked
/// via the `AckToken`. If the daemon crashes before ack, NATS redelivers
/// the message after `ack_wait` expires.
///
/// A message that carries no event is settled here, so it never holds the
/// consumer's ack window: an empty or whitespace-only payload is acked, and
/// one larger than [`MAX_LINE_BYTES`](super::MAX_LINE_BYTES) is terminated so
/// the server stops redelivering it. A payload that is not valid UTF-8 is
/// passed on with each invalid sequence replaced by U+FFFD.
pub struct NatsSource {
    messages: jetstream::consumer::pull::Stream,
    metrics: Option<Arc<dyn MetricsHook>>,
}

impl NatsSource {
    /// Connect to NATS and subscribe to a JetStream stream via pull consumer.
    ///
    /// Uses `NatsConnectConfig` for authentication and TLS settings.
    /// `subject` is the subject filter (e.g. "hel.events.>").
    /// `replay` controls where the consumer starts reading from.
    /// `consumer_group` overrides the auto-derived consumer name so multiple
    /// daemon instances can share a single durable consumer for load balancing.
    pub async fn connect(
        config: &NatsConnectConfig,
        subject: &str,
        replay: &ReplayPolicy,
        consumer_group: Option<&str>,
    ) -> Result<Self, async_nats::Error> {
        let client = config.connect().await?;
        let jetstream = jetstream::new(client);

        let stream_name = derive_nats_name("rsigma", subject);
        let consumer_name = match consumer_group {
            Some(group) => group.to_string(),
            None => derive_nats_name("rsigma-daemon", subject),
        };

        let stream = jetstream
            .get_or_create_stream(jetstream::stream::Config {
                name: stream_name,
                subjects: vec![subject.to_string()],
                ..Default::default()
            })
            .await?;

        let deliver_policy = match replay {
            ReplayPolicy::Resume => DeliverPolicy::All,
            ReplayPolicy::FromSequence(seq) => DeliverPolicy::ByStartSequence {
                start_sequence: *seq,
            },
            ReplayPolicy::FromTime(time) => DeliverPolicy::ByStartTime { start_time: *time },
            ReplayPolicy::Latest => DeliverPolicy::Last,
        };

        let consumer = stream
            .get_or_create_consumer(
                &consumer_name,
                jetstream::consumer::pull::Config {
                    durable_name: Some(consumer_name.clone()),
                    filter_subject: subject.to_string(),
                    deliver_policy,
                    ..Default::default()
                },
            )
            .await?;

        let messages = consumer.messages().await?;

        Ok(NatsSource {
            messages,
            metrics: None,
        })
    }

    /// Report skipped messages and payloads that are not valid UTF-8 through
    /// `metrics`.
    #[must_use]
    pub fn with_metrics(mut self, metrics: Option<Arc<dyn MetricsHook>>) -> Self {
        self.metrics = metrics;
        self
    }

    fn dropped(&self, reason: &'static str) {
        if let Some(m) = &self.metrics {
            m.on_input_dropped("nats", reason);
        }
    }
}

/// Decode a message payload, replacing invalid UTF-8. The flag is set when
/// the payload was not valid UTF-8.
fn decode_payload(payload: &[u8]) -> (String, bool) {
    match std::str::from_utf8(payload) {
        Ok(text) => (text.to_owned(), false),
        Err(_) => (String::from_utf8_lossy(payload).into_owned(), true),
    }
}

impl EventSource for NatsSource {
    async fn recv(&mut self) -> Option<RawEvent> {
        loop {
            match self.messages.next().await {
                Some(Ok(msg)) => {
                    if msg.payload.len() > MAX_LINE_BYTES {
                        tracing::warn!(
                            bytes = msg.payload.len(),
                            max_bytes = MAX_LINE_BYTES,
                            subject = %msg.subject,
                            "Terminating an over-long NATS message"
                        );
                        if let Err(e) = msg.ack_with(AckKind::Term).await {
                            tracing::warn!(error = %e, "Failed to terminate NATS message");
                        }
                        self.dropped("too_long");
                        continue;
                    }
                    let (payload, invalid_utf8) = decode_payload(&msg.payload);
                    if payload.trim().is_empty() {
                        if let Err(e) = msg.ack().await {
                            tracing::warn!(error = %e, "Failed to ack blank NATS message");
                        }
                        self.dropped("blank");
                        continue;
                    }
                    if invalid_utf8 && let Some(m) = &self.metrics {
                        m.on_input_invalid_utf8("nats");
                    }
                    return Some(RawEvent {
                        payload,
                        ack_token: AckToken::Nats(Box::new(msg)),
                        tenant: None,
                    });
                }
                Some(Err(e)) => {
                    tracing::warn!(error = %e, "NATS message error");
                    continue;
                }
                None => {
                    tracing::debug!("NATS stream ended");
                    return None;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_decode_lossily_and_flag_invalid_utf8() {
        assert_eq!(
            decode_payload(b"{\"a\":1}"),
            ("{\"a\":1}".to_string(), false)
        );
        assert_eq!(
            decode_payload(b"{\"a\":\"\xff\"}"),
            ("{\"a\":\"\u{fffd}\"}".to_string(), true)
        );
    }
}
