use async_nats::jetstream;
use async_nats::subject::Subject;

use rsigma_eval::ProcessResult;

use crate::error::RuntimeError;

use super::nats_config::NatsConnectConfig;
use super::nats_source::derive_nats_name;

/// Publishes ProcessResult as NDJSON to a NATS JetStream subject.
///
/// Uses JetStream `publish` with publish-ack confirmation to guarantee that the
/// NATS server has persisted each message. This completes the at-least-once
/// guarantee end-to-end: the source acks only after this sink's JetStream
/// publish is confirmed.
pub struct NatsSink {
    jetstream: jetstream::Context,
    subject: Subject,
}

impl NatsSink {
    /// Connect to NATS and prepare to publish to a JetStream subject.
    ///
    /// Creates or reuses the JetStream stream for the given subject, then
    /// publishes via `jetstream::Context::publish` for server-confirmed delivery.
    pub async fn connect(
        config: &NatsConnectConfig,
        subject: &str,
    ) -> Result<Self, async_nats::Error> {
        let client = config.connect().await?;
        let js = jetstream::new(client);

        let stream_name = derive_nats_name("rsigma", subject);

        js.get_or_create_stream(jetstream::stream::Config {
            name: stream_name,
            subjects: vec![subject.to_string()],
            ..Default::default()
        })
        .await?;

        Ok(NatsSink {
            jetstream: js,
            subject: Subject::from(subject),
        })
    }

    /// Serialize and publish a ProcessResult to the configured JetStream subject.
    ///
    /// Each message is published with publish-ack: the call blocks until the
    /// server confirms persistence, or returns an error on failure.
    pub async fn send(&self, result: &ProcessResult) -> Result<(), RuntimeError> {
        if result.detections.is_empty() && result.correlations.is_empty() {
            return Ok(());
        }

        for m in &result.detections {
            let json = serde_json::to_string(m)?;
            self.jetstream
                .publish(self.subject.clone(), json.into())
                .await
                .map_err(|e| RuntimeError::Io(std::io::Error::other(e)))?
                .await
                .map_err(|e| RuntimeError::Io(std::io::Error::other(e)))?;
        }

        for m in &result.correlations {
            let json = serde_json::to_string(m)?;
            self.jetstream
                .publish(self.subject.clone(), json.into())
                .await
                .map_err(|e| RuntimeError::Io(std::io::Error::other(e)))?
                .await
                .map_err(|e| RuntimeError::Io(std::io::Error::other(e)))?;
        }

        Ok(())
    }

    /// Publish a pre-serialized JSON string directly to the JetStream subject.
    pub async fn send_raw(&self, json: &str) -> Result<(), RuntimeError> {
        self.jetstream
            .publish(self.subject.clone(), json.to_string().into())
            .await
            .map_err(|e| RuntimeError::Io(std::io::Error::other(e)))?
            .await
            .map_err(|e| RuntimeError::Io(std::io::Error::other(e)))?;
        Ok(())
    }
}
