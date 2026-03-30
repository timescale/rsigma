use async_nats::jetstream;
use tokio_stream::StreamExt;

use super::EventSource;

/// Derive a NATS-safe name by combining a prefix with the subject.
/// Replaces characters not allowed in NATS stream/consumer names (`.`, `>`, `*`)
/// with dashes and strips trailing dashes.
fn derive_nats_name(prefix: &str, subject: &str) -> String {
    let sanitized: String = subject
        .chars()
        .map(|c| match c {
            '.' | '>' | '*' => '-',
            _ => c,
        })
        .collect();
    format!("{}-{}", prefix, sanitized.trim_end_matches('-'))
}

/// NATS JetStream consumer that yields events as JSON strings.
///
/// Uses at-most-once delivery: messages are acked immediately on receive,
/// before the engine processes them. If the daemon crashes between ack and
/// processing, the event is lost. At-least-once delivery requires a feedback
/// channel from engine to source (deferred to Level 2).
pub struct NatsSource {
    messages: jetstream::consumer::pull::Stream,
}

impl NatsSource {
    /// Connect to NATS and subscribe to a JetStream stream via pull consumer.
    ///
    /// `url` is the NATS server URL (e.g. "nats://localhost:4222").
    /// `subject` is the subject filter (e.g. "hel.events.>").
    pub async fn connect(url: &str, subject: &str) -> Result<Self, async_nats::Error> {
        let client = async_nats::connect(url).await?;
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

        let consumer = stream
            .get_or_create_consumer(
                &consumer_name,
                jetstream::consumer::pull::Config {
                    durable_name: Some(consumer_name.clone()),
                    filter_subject: subject.to_string(),
                    ..Default::default()
                },
            )
            .await?;

        let messages = consumer.messages().await?;

        Ok(NatsSource { messages })
    }
}

impl EventSource for NatsSource {
    async fn recv(&mut self) -> Option<String> {
        loop {
            match self.messages.next().await {
                Some(Ok(msg)) => {
                    let payload = String::from_utf8_lossy(&msg.payload).to_string();
                    if let Err(e) = msg.ack().await {
                        tracing::warn!(error = %e, "Failed to ack NATS message");
                    }
                    if !payload.trim().is_empty() {
                        return Some(payload);
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
