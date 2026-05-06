//! EVTX (Windows Event Log) file reader.
//!
//! Opens a `.evtx` file and yields each record as a [`serde_json::Value`],
//! bypassing the line-oriented [`parse_line`](super::parse_line) API since
//! EVTX is a binary format.

use std::fs::File;
use std::path::Path;

use evtx::{EvtxParser, ParserSettings};
use serde_json::Value;

/// Error returned by [`EvtxFileReader`] operations.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct EvtxError(#[from] evtx::err::EvtxError);

/// Reader for `.evtx` (Windows Event Log) files.
///
/// Wraps [`evtx::EvtxParser`] and provides an iterator over records as
/// `serde_json::Value`. Records that fail to deserialize are yielded as
/// `Err` values so the caller can decide whether to skip or abort.
pub struct EvtxFileReader {
    parser: EvtxParser<File>,
}

impl EvtxFileReader {
    /// Open an EVTX file for reading.
    ///
    /// Validates the EVTX header on open. Uses single-threaded parsing
    /// (records are consumed sequentially by the eval loop).
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvtxError> {
        let settings = ParserSettings::default().num_threads(1);
        let parser = EvtxParser::from_path(path)?.with_configuration(settings);
        Ok(Self { parser })
    }

    /// Return an iterator of `Result<Value, EvtxError>` over all records.
    ///
    /// Each item is the JSON representation of one EVTX record (the
    /// `SerializedEvtxRecord::data` field).
    pub fn records(&mut self) -> impl Iterator<Item = Result<Value, EvtxError>> + '_ {
        self.parser
            .records_json_value()
            .map(|r| r.map(|rec| rec.data).map_err(EvtxError::from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_nonexistent_returns_error() {
        let result = EvtxFileReader::open("/nonexistent/file.evtx");
        assert!(result.is_err());
    }
}
