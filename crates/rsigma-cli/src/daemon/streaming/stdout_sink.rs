use std::io::Write;

use rsigma_eval::ProcessResult;

use super::StreamingError;

/// Serializes ProcessResult to NDJSON and writes to stdout.
pub struct StdoutSink {
    pretty: bool,
}

impl StdoutSink {
    pub fn new(pretty: bool) -> Self {
        StdoutSink { pretty }
    }

    /// Serialize and write a ProcessResult to stdout.
    pub fn send(&self, result: &ProcessResult) -> Result<(), StreamingError> {
        if result.detections.is_empty() && result.correlations.is_empty() {
            return Ok(());
        }

        let stdout = std::io::stdout();
        let mut out = stdout.lock();

        for m in &result.detections {
            let json = if self.pretty {
                serde_json::to_string_pretty(m)?
            } else {
                serde_json::to_string(m)?
            };
            writeln!(out, "{json}")?;
        }

        for m in &result.correlations {
            let json = if self.pretty {
                serde_json::to_string_pretty(m)?
            } else {
                serde_json::to_string(m)?
            };
            writeln!(out, "{json}")?;
        }

        Ok(())
    }
}
