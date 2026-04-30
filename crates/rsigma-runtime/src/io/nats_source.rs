use async_nats::jetstream;
use async_nats::jetstream::consumer::DeliverPolicy;
use tokio_stream::StreamExt;

use super::nats_config::NatsConnectConfig;
use super::{AckToken, EventSource, RawEvent};

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
pub struct NatsSource {
    messages: jetstream::consumer::pull::Stream,
}

impl NatsSource {
    /// Connect to NATS and subscribe to a JetStream stream via pull consumer.
    ///
    /// Uses `NatsConnectConfig` for authentication and TLS settings.
    /// `subject` is the subject filter (e.g. "hel.events.>").
    /// `replay` controls where the consumer starts reading from.
    pub async fn connect(
        config: &NatsConnectConfig,
        subject: &str,
        replay: &ReplayPolicy,
    ) -> Result<Self, async_nats::Error> {
        let client = config.connect().await?;
        let jetstream = jetstream::new(client);

        let stream_name = derive_nats_name("rsigma", subject);
        let consumer_name = derive_nats_name("rsigma-daemon", subject);

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

        Ok(NatsSource { messages })
    }
}

impl EventSource for NatsSource {
    async fn recv(&mut self) -> Option<RawEvent> {
        loop {
            match self.messages.next().await {
                Some(Ok(msg)) => {
                    let payload = String::from_utf8_lossy(&msg.payload).to_string();
                    if !payload.trim().is_empty() {
                        return Some(RawEvent {
                            payload,
                            ack_token: AckToken::Nats(Box::new(msg)),
                        });
                    }
                }
                Some(Err(e)) => {
                    tracing::warn!(error = %e, "NATS message error");
                    continue;
                }
                None => return None,
            }
        }
    }
}
