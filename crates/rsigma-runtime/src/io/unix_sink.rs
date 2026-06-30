//! `unix://` output sink: forward NDJSON detections and incidents to a
//! collector listening on a Unix domain socket.
//!
//! Dials the socket as a client and reconnects once on a write failure before
//! surfacing the error (which the daemon routes to the DLQ, like any other
//! sink failure).

use std::path::{Path, PathBuf};

use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

use rsigma_eval::ProcessResult;

use crate::error::RuntimeError;

/// Writes NDJSON to a Unix domain socket, reconnecting on transient failures.
pub struct UnixSocketSink {
    path: PathBuf,
    stream: Option<UnixStream>,
}

impl UnixSocketSink {
    /// Connect to the collector socket at `path`.
    pub async fn connect(path: &Path) -> std::io::Result<Self> {
        let stream = UnixStream::connect(path).await?;
        Ok(Self {
            path: path.to_path_buf(),
            stream: Some(stream),
        })
    }

    /// Serialize and deliver each entry of a `ProcessResult` as one NDJSON line.
    pub async fn send(&mut self, result: &ProcessResult) -> Result<(), RuntimeError> {
        if result.is_empty() {
            return Ok(());
        }
        for m in result {
            let json = serde_json::to_string(m)?;
            self.write_line(&json).await?;
        }
        Ok(())
    }

    /// Write a pre-serialized JSON line directly to the socket.
    pub async fn send_raw(&mut self, json: &str) -> Result<(), RuntimeError> {
        self.write_line(json).await
    }

    /// Write one line, reconnecting once if the socket has gone away.
    async fn write_line(&mut self, json: &str) -> Result<(), RuntimeError> {
        if self.try_write(json).await.is_err() {
            // Drop the dead stream and try a single reconnect; a second
            // failure surfaces to the caller (and the DLQ).
            self.stream = None;
            self.try_write(json).await?;
        }
        Ok(())
    }

    async fn try_write(&mut self, json: &str) -> Result<(), RuntimeError> {
        let stream = match self.stream.as_mut() {
            Some(stream) => stream,
            None => {
                let stream = UnixStream::connect(&self.path).await?;
                self.stream.insert(stream)
            }
        };
        stream.write_all(json.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::UnixListener;

    #[tokio::test]
    async fn writes_ndjson_lines_to_collector() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("collector.sock");
        let listener = UnixListener::bind(&path).unwrap();

        let accept = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut lines = BufReader::new(stream).lines();
            let mut out = Vec::new();
            while let Some(line) = lines.next_line().await.unwrap() {
                out.push(line);
                if out.len() == 2 {
                    break;
                }
            }
            out
        });

        let mut sink = UnixSocketSink::connect(&path).await.unwrap();
        sink.send_raw("{\"a\":1}").await.unwrap();
        sink.send_raw("{\"b\":2}").await.unwrap();

        let received = accept.await.unwrap();
        assert_eq!(
            received,
            vec!["{\"a\":1}".to_string(), "{\"b\":2}".to_string()]
        );
    }
}
