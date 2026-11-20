//! `unix://` output sink: forward NDJSON detections and incidents to a
//! collector listening on a Unix domain socket.
//!
//! Dials the socket as a client and reconnects once on a write failure before
//! surfacing the error (which the daemon routes to the DLQ, like any other
//! sink failure). A connection that failed mid-write is dropped, and the lines
//! it fully carried are not sent again, neither on the reconnect nor when the
//! delivery layer retries the result.

use std::path::{Path, PathBuf};

use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

use rsigma_eval::{ProcessResult, TenantId};

use crate::error::RuntimeError;
use crate::io::lines::{LineBatch, ResumePoint};
use crate::io::{DeliveryContext, SinkFormat, serialize_result};

/// Writes one line per result to a Unix domain socket, reconnecting on
/// transient failures.
pub struct UnixSocketSink {
    path: PathBuf,
    stream: Option<UnixStream>,
    format: SinkFormat,
    ocsf: crate::ocsf::OcsfOptions,
    resume: ResumePoint,
    tenant_filter: Option<TenantId>,
}

impl UnixSocketSink {
    /// Connect to the collector socket at `path`.
    pub async fn connect(path: &Path) -> std::io::Result<Self> {
        let stream = UnixStream::connect(path).await?;
        Ok(Self {
            path: path.to_path_buf(),
            stream: Some(stream),
            format: SinkFormat::default(),
            ocsf: crate::ocsf::OcsfOptions::default(),
            resume: ResumePoint::default(),
            tenant_filter: None,
        })
    }

    /// Only deliver results of `tenant`.
    #[must_use]
    pub fn with_tenant_filter(mut self, tenant: Option<TenantId>) -> Self {
        self.tenant_filter = tenant;
        self
    }

    /// Select the wire format this sink serializes results into.
    #[must_use]
    pub fn with_format(mut self, format: SinkFormat) -> Self {
        self.format = format;
        self
    }

    #[must_use]
    pub fn with_ocsf_options(mut self, ocsf: crate::ocsf::OcsfOptions) -> Self {
        self.ocsf = ocsf;
        self
    }

    /// The wire format this sink serializes results into.
    pub fn format(&self) -> SinkFormat {
        self.format
    }

    pub fn ocsf_options(&self) -> &crate::ocsf::OcsfOptions {
        &self.ocsf
    }

    /// Serialize and deliver each entry of a `ProcessResult` as one line.
    pub async fn send(&mut self, result: &ProcessResult) -> Result<(), RuntimeError> {
        self.send_inner(result, None).await
    }

    pub(crate) async fn send_with_context(
        &mut self,
        result: &ProcessResult,
        ctx: &DeliveryContext,
    ) -> Result<(), RuntimeError> {
        self.send_inner(result, Some(ctx)).await
    }

    async fn send_inner(
        &mut self,
        result: &ProcessResult,
        ctx: Option<&DeliveryContext>,
    ) -> Result<(), RuntimeError> {
        let filtered: Vec<(usize, &rsigma_eval::EvaluationResult)> = result
            .iter()
            .enumerate()
            .filter(|(_, m)| {
                self.tenant_filter
                    .as_ref()
                    .is_none_or(|t| m.header.tenant_id.as_ref() == Some(t))
            })
            .collect();
        if filtered.is_empty() {
            return Ok(());
        }
        let start = self.resume.start(ctx);
        let mut batch = LineBatch::default();
        for (original_index, m) in filtered.iter().skip(start) {
            batch.push(&serialize_result(
                m,
                self.format,
                false,
                ctx.map(|ctx| (ctx, *original_index)),
                &self.ocsf,
            )?);
        }
        match self.write_batch(&batch).await {
            Ok(()) => {
                self.resume.clear();
                Ok(())
            }
            Err((lines, err)) => {
                self.resume.record(ctx, start + lines);
                Err(err)
            }
        }
    }

    /// Write a pre-serialized JSON line directly to the socket.
    pub async fn send_raw(&mut self, json: &str) -> Result<(), RuntimeError> {
        let mut batch = LineBatch::default();
        batch.push(json);
        self.write_batch(&batch).await.map_err(|(_, err)| err)
    }

    /// Write a pre-serialized line when it belongs to `tenant`.
    pub async fn send_raw_for_tenant(
        &mut self,
        json: &str,
        tenant: Option<&TenantId>,
    ) -> Result<(), RuntimeError> {
        if let Some(filter) = &self.tenant_filter
            && tenant != Some(filter)
        {
            return Ok(());
        }
        self.send_raw(json).await
    }

    /// Write `batch`, reconnecting once if the socket has gone away. A failure
    /// reports how many whole lines were written.
    async fn write_batch(&mut self, batch: &LineBatch) -> Result<(), (usize, RuntimeError)> {
        let done = match self.try_write(batch.bytes()).await {
            Ok(()) => return Ok(()),
            Err((written, _)) => batch.complete_lines(written),
        };
        // Try a single reconnect from the first line the dead stream did not
        // fully carry; a second failure surfaces to the caller (and the DLQ).
        let from = batch.line_start(done);
        self.try_write(&batch.bytes()[from..])
            .await
            .map_err(|(written, err)| (batch.complete_lines(from + written), err))
    }

    /// Write `bytes` on the current connection, dialing one if there is none.
    /// On failure the connection is dropped, and the error carries how many
    /// bytes it accepted.
    async fn try_write(&mut self, bytes: &[u8]) -> Result<(), (usize, RuntimeError)> {
        let stream = match self.stream.as_mut() {
            Some(stream) => stream,
            None => {
                let stream = UnixStream::connect(&self.path)
                    .await
                    .map_err(|err| (0, err.into()))?;
                self.stream.insert(stream)
            }
        };
        let mut written = 0;
        let mut outcome = Ok(());
        while written < bytes.len() {
            match stream.write(&bytes[written..]).await {
                Ok(0) => {
                    outcome = Err(std::io::ErrorKind::WriteZero.into());
                    break;
                }
                Ok(n) => written += n,
                Err(err) => {
                    outcome = Err(err);
                    break;
                }
            }
        }
        if outcome.is_ok() {
            outcome = stream.flush().await;
        }
        outcome.map_err(|err| {
            self.stream = None;
            (written, err.into())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::UnixListener;

    #[tokio::test]
    async fn dropped_connection_is_replaced_without_repeating_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("collector.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();

        let collector = tokio::spawn(async move {
            let (first, _) = listener.accept().await.unwrap();
            let mut first = BufReader::new(first).lines();
            let before = first.next_line().await.unwrap().unwrap();
            drop(first);
            closed_tx.send(()).unwrap();

            let (second, _) = listener.accept().await.unwrap();
            let mut second = BufReader::new(second).lines();
            let mut after = Vec::new();
            while let Some(line) = second.next_line().await.unwrap() {
                after.push(line);
            }
            (before, after)
        });

        let mut sink = UnixSocketSink::connect(&path).await.unwrap();
        sink.send_raw("{\"n\":0}").await.unwrap();
        closed_rx.await.unwrap();
        sink.send_raw("{\"n\":1}").await.unwrap();
        sink.send_raw("{\"n\":2}").await.unwrap();
        drop(sink);

        let (before, after) = collector.await.unwrap();
        assert_eq!(before, "{\"n\":0}");
        assert_eq!(after, ["{\"n\":1}", "{\"n\":2}"]);
    }

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
