use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;

use rsigma_eval::ProcessResult;

use super::StreamingError;

/// Appends ProcessResult as NDJSON to a file with buffered writes.
pub struct FileSink {
    writer: BufWriter<File>,
}

impl FileSink {
    /// Open (or create) the file at `path` for appending.
    pub fn open(path: &Path) -> Result<Self, StreamingError> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(FileSink {
            writer: BufWriter::new(file),
        })
    }

    /// Serialize and append a ProcessResult to the file.
    pub fn send(&mut self, result: &ProcessResult) -> Result<(), StreamingError> {
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
}
