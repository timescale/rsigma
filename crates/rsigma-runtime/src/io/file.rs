use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;

use rsigma_eval::ProcessResult;

use crate::error::RuntimeError;

/// Appends ProcessResult as NDJSON to a file with buffered writes.
pub struct FileSink {
    writer: BufWriter<File>,
}

impl FileSink {
    /// Open (or create) the file at `path` for appending.
    pub fn open(path: &Path) -> Result<Self, RuntimeError> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(FileSink {
            writer: BufWriter::new(file),
        })
    }

    /// Serialize and append a ProcessResult to the file.
    pub fn send(&mut self, result: &ProcessResult) -> Result<(), RuntimeError> {
        if result.detections.is_empty() && result.correlations.is_empty() {
            return Ok(());
        }

        for m in &result.detections {
            let json = serde_json::to_string(m)?;
            writeln!(self.writer, "{json}")?;
        }

        for m in &result.correlations {
            let json = serde_json::to_string(m)?;
            writeln!(self.writer, "{json}")?;
        }

        self.writer.flush()?;
        Ok(())
    }

    /// Write a pre-serialized JSON string directly to the file.
    pub fn send_raw(&mut self, json: &str) -> Result<(), RuntimeError> {
        writeln!(self.writer, "{json}")?;
        self.writer.flush()?;
        Ok(())
    }
}
