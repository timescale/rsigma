use async_nats::{Client, subject::Subject};

use rsigma_eval::ProcessResult;

use super::StreamingError;

/// Publishes ProcessResult as NDJSON to a NATS subject.
pub struct NatsSink {
    client: Client,
    subject: Subject,
}

impl NatsSink {
    /// Connect to NATS and prepare to publish to `subject`.
    pub async fn connect(url: &str, subject: &str) -> Result<Self, async_nats::Error> {
        let client = async_nats::connect(url).await?;
        Ok(NatsSink {
            client,
            subject: Subject::from(subject),
        })
    }

    /// Serialize and publish a ProcessResult to the configured NATS subject.
    pub async fn send(&self, result: &ProcessResult) -> Result<(), StreamingError> {
        if result.detections.is_empty() && result.correlations.is_empty() {
            return Ok(());
        }

        for m in &result.detections {
            let json = serde_json::to_string(m)?;
            self.client
                .publish(self.subject.clone(), json.into())
                .await
                .map_err(|e| StreamingError::Io(std::io::Error::other(e)))?;
        }

        for m in &result.correlations {
            let json = serde_json::to_string(m)?;
            self.client
                .publish(self.subject.clone(), json.into())
                .await
                .map_err(|e| StreamingError::Io(std::io::Error::other(e)))?;
        }

        Ok(())
    }
}
