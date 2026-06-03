use std::sync::Arc;

use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::message::Message;
use rdkafka::TopicPartitionList;

use super::kafka_config::KafkaConnectConfig;
use super::{AckToken, EventSource, KafkaAckData, RawEvent};

/// Kafka consumer that yields events from one or more topics.
///
/// Uses at-least-once delivery: offsets are committed only after the downstream
/// pipeline (engine + sink) confirms successful processing via `AckToken::ack()`.
/// If the daemon crashes before ack, Kafka redelivers the message on next startup.
pub struct KafkaSource {
    consumer: Arc<StreamConsumer>,
}

impl KafkaSource {
    /// Connect to Kafka and subscribe to topics.
    ///
    /// Topics starting with `^` are treated as regex patterns by librdkafka,
    /// enabling multi-tenant fan-in (e.g. `^tenant-.*`).
    pub fn connect(
        config: &KafkaConnectConfig,
        topics: &[String],
    ) -> Result<Self, rdkafka::error::KafkaError> {
        let client_config = config.to_client_config();
        let consumer: StreamConsumer = client_config.create()?;

        let topic_refs: Vec<&str> = topics.iter().map(|t| t.as_str()).collect();
        consumer.subscribe(&topic_refs)?;

        Ok(KafkaSource {
            consumer: Arc::new(consumer),
        })
    }
}

impl EventSource for KafkaSource {
    async fn recv(&mut self) -> Option<RawEvent> {
        loop {
            match self.consumer.recv().await {
                Ok(msg) => {
                    let payload = match msg.payload_view::<str>() {
                        Some(Ok(text)) => text.to_string(),
                        Some(Err(_)) => {
                            tracing::warn!(
                                topic = msg.topic(),
                                partition = msg.partition(),
                                offset = msg.offset(),
                                "Kafka message payload is not valid UTF-8, skipping",
                            );
                            continue;
                        }
                        None => continue,
                    };

                    if payload.trim().is_empty() {
                        continue;
                    }

                    let mut tpl = TopicPartitionList::new();
                    tpl.add_partition_offset(
                        msg.topic(),
                        msg.partition(),
                        rdkafka::Offset::Offset(msg.offset() + 1),
                    )
                    .ok();

                    let ack_data = KafkaAckData {
                        consumer: Arc::clone(&self.consumer),
                        offsets: tpl,
                    };

                    return Some(RawEvent {
                        payload,
                        ack_token: AckToken::Kafka(ack_data),
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Kafka consumer error");
                    continue;
                }
            }
        }
    }
}
