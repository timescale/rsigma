use std::time::Duration;

use rdkafka::producer::{FutureProducer, FutureRecord};

use rsigma_eval::ProcessResult;

use crate::error::RuntimeError;

use super::kafka_config::KafkaConnectConfig;

/// Publishes ProcessResult as NDJSON to a Kafka topic.
///
/// Uses `FutureProducer` with delivery confirmation to guarantee that the broker
/// has acknowledged each message. This completes the at-least-once guarantee
/// end-to-end: the source commits its offset only after this sink's produce is
/// confirmed.
pub struct KafkaSink {
    producer: FutureProducer,
    topic: String,
}

impl KafkaSink {
    /// Connect to Kafka and prepare to publish to a topic.
    ///
    /// Configures `acks=all` for durability and a 5-second delivery timeout.
    pub fn connect(
        config: &KafkaConnectConfig,
        topic: &str,
    ) -> Result<Self, rdkafka::error::KafkaError> {
        let mut client_config = config.to_client_config();
        client_config.set("message.timeout.ms", "5000");
        client_config.set("acks", "all");

        let producer: FutureProducer = client_config.create()?;

        Ok(KafkaSink {
            producer,
            topic: topic.to_string(),
        })
    }

    /// Serialize and publish a ProcessResult to the configured Kafka topic.
    ///
    /// Each message is produced with delivery confirmation: the call awaits
    /// until the broker acknowledges persistence, or returns an error on failure.
    pub async fn send(&self, result: &ProcessResult) -> Result<(), RuntimeError> {
        if result.is_empty() {
            return Ok(());
        }

        let mut published = 0_usize;
        for m in result {
            let json = serde_json::to_string(m)?;
            self.publish_one(&json).await?;
            published += 1;
        }

        tracing::debug!(
            topic = %self.topic,
            messages = published,
            "Kafka messages produced",
        );
        Ok(())
    }

    /// Publish a pre-serialized JSON string directly to the Kafka topic.
    pub async fn send_raw(&self, json: &str) -> Result<(), RuntimeError> {
        self.publish_one(json).await?;
        tracing::debug!(topic = %self.topic, "Kafka message produced (raw)");
        Ok(())
    }

    async fn publish_one(&self, json: &str) -> Result<(), RuntimeError> {
        let record = FutureRecord::to(&self.topic).payload(json);
        self.producer
            .send(record, Duration::from_secs(5))
            .await
            .map_err(|(e, _)| {
                tracing::warn!(topic = %self.topic, error = %e, "Kafka produce failed");
                RuntimeError::Io(std::io::Error::other(e))
            })?;
        Ok(())
    }
}
