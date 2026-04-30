use std::io::Write;

use rsigma_eval::ProcessResult;

use crate::error::RuntimeError;

/// Serializes ProcessResult to NDJSON and writes to stdout.
pub struct StdoutSink {
    pretty: bool,
}

impl StdoutSink {
    pub fn new(pretty: bool) -> Self {
        StdoutSink { pretty }
    }

    /// Serialize and write a ProcessResult to stdout.
    pub fn send(&self, result: &ProcessResult) -> Result<(), RuntimeError> {
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

    /// Write a pre-serialized JSON string directly to stdout.
    pub fn send_raw(&self, json: &str) -> Result<(), RuntimeError> {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        writeln!(out, "{json}")?;
        Ok(())
    }
}
