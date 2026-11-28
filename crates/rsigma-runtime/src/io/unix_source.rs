//! `unix://` event source: accept newline-delimited events over a Unix domain
//! socket.
//!
//! Modeled on [`StdinSource`](super::StdinSource) but fed by an accept loop, so
//! co-located log shippers (rsyslog `omuxsock`, syslog-ng `unix-stream`,
//! Vector, Fluent Bit) can connect concurrently. Each line becomes one
//! [`RawEvent`]; acks are a no-op (a raw stream has no per-message ack).

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use tokio::io::AsyncReadExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

use super::line_framer::{FramedLine, LineFramer, MAX_LINE_BYTES};
use super::unix::{UnixSocketGuard, bind_unix_listener};
use super::{AckToken, EventSource, RawEvent};
use crate::log_throttle::WarnThrottle;
use crate::metrics::MetricsHook;

/// Channel capacity between the socket readers and the engine. Bounded so a
/// slow pipeline back-pressures the readers (which stop draining their
/// sockets) instead of buffering unboundedly.
const CHANNEL_CAPACITY: usize = 1024;

/// Bytes a connection reader asks for in one read.
const READ_BUFFER_BYTES: usize = 64 * 1024;

/// Reads events from a Unix domain socket, one record per line.
///
/// Lines are cut by a [`LineFramer`]: a line longer than [`MAX_LINE_BYTES`]
/// is dropped, and bytes that are not valid UTF-8 are replaced with U+FFFD.
pub struct UnixSocketSource {
    rx: mpsc::Receiver<String>,
    /// Unlinks the socket file when the source is dropped (daemon shutdown).
    _guard: UnixSocketGuard,
}

impl UnixSocketSource {
    /// Bind the socket at `path` and start accepting connections.
    pub async fn bind(path: &Path) -> std::io::Result<Self> {
        Self::bind_with_metrics(path, None).await
    }

    /// Like [`bind`](Self::bind), reporting dropped lines and lines that are
    /// not valid UTF-8 through `metrics`.
    pub async fn bind_with_metrics(
        path: &Path,
        metrics: Option<Arc<dyn MetricsHook>>,
    ) -> std::io::Result<Self> {
        let (listener, guard) = bind_unix_listener(path).await?;
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        tokio::spawn(accept_loop(listener, tx, metrics));
        Ok(Self { rx, _guard: guard })
    }
}

/// Accept connections, spawning one reader task per connection. Ends when every
/// reader has dropped the shared sender (the channel receiver closed on
/// shutdown) or is aborted with the daemon.
async fn accept_loop(
    listener: UnixListener,
    tx: mpsc::Sender<String>,
    metrics: Option<Arc<dyn MetricsHook>>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                tokio::spawn(read_connection(stream, tx.clone(), metrics.clone()));
            }
            Err(e) => {
                tracing::warn!(error = %e, "unix socket accept failed");
                // Brief backoff so a persistent accept error does not spin.
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

/// Read newline-delimited records from one connection, forwarding each to the
/// engine. A line still incomplete when the connection fails is dropped; one
/// that ends at a clean end of stream without a newline is forwarded.
async fn read_connection(
    mut stream: UnixStream,
    tx: mpsc::Sender<String>,
    metrics: Option<Arc<dyn MetricsHook>>,
) {
    let mut buf = vec![0u8; READ_BUFFER_BYTES];
    let mut framer = LineFramer::default();
    let mut lines = Vec::new();
    let mut too_long_log = WarnThrottle::default();
    loop {
        let n = match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(error = %e, "unix socket read failed");
                return;
            }
        };
        framer.push(&buf[..n], &mut |line| lines.push(line));
        if !forward(&mut lines, &tx, metrics.as_deref(), &mut too_long_log).await {
            return;
        }
    }
    framer.finish(&mut |line| lines.push(line));
    forward(&mut lines, &tx, metrics.as_deref(), &mut too_long_log).await;
}

/// Send each framed line to the engine and count the dropped ones. `false`
/// once the receiver is gone (daemon shutdown).
async fn forward(
    lines: &mut Vec<FramedLine>,
    tx: &mpsc::Sender<String>,
    metrics: Option<&dyn MetricsHook>,
    too_long_log: &mut WarnThrottle,
) -> bool {
    for line in lines.drain(..) {
        match line {
            FramedLine::Line { text, invalid_utf8 } => {
                if invalid_utf8 && let Some(m) = metrics {
                    m.on_input_invalid_utf8("unix");
                }
                if tx.send(text).await.is_err() {
                    return false;
                }
            }
            FramedLine::TooLong => {
                if let Some(m) = metrics {
                    m.on_input_dropped("unix", "too_long");
                }
                if let Some(n) = too_long_log.record(Instant::now()) {
                    tracing::warn!(
                        max_bytes = MAX_LINE_BYTES,
                        dropped = n,
                        "Dropping over-long unix socket lines"
                    );
                }
            }
        }
    }
    true
}

impl EventSource for UnixSocketSource {
    async fn recv(&mut self) -> Option<RawEvent> {
        loop {
            match self.rx.recv().await {
                Some(line) if !line.trim().is_empty() => {
                    return Some(RawEvent {
                        payload: line,
                        ack_token: AckToken::Noop,
                        tenant: None,
                    });
                }
                Some(_) => continue,
                None => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn round_trips_newline_delimited_events() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ingest.sock");

        let mut source = UnixSocketSource::bind(&path).await.unwrap();

        let mut client = UnixStream::connect(&path).await.unwrap();
        client
            .write_all(b"{\"a\":1}\n   \n{\"b\":2}\n")
            .await
            .unwrap();
        client.flush().await.unwrap();

        let first = source.recv().await.unwrap();
        assert_eq!(first.payload, "{\"a\":1}");
        // The blank line is skipped.
        let second = source.recv().await.unwrap();
        assert_eq!(second.payload, "{\"b\":2}");
    }

    #[tokio::test]
    async fn drops_over_long_lines_but_keeps_the_next() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ingest.sock");

        let mut source = UnixSocketSource::bind(&path).await.unwrap();

        let mut client = UnixStream::connect(&path).await.unwrap();
        let huge = vec![b'x'; MAX_LINE_BYTES + 10];
        client.write_all(&huge).await.unwrap();
        client.write_all(b"\n{\"ok\":true}\n").await.unwrap();
        client.flush().await.unwrap();

        let event = source.recv().await.unwrap();
        assert_eq!(event.payload, "{\"ok\":true}");
    }

    #[tokio::test]
    async fn invalid_utf8_is_replaced_and_later_lines_still_arrive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ingest.sock");

        let mut source = UnixSocketSource::bind(&path).await.unwrap();

        let mut client = UnixStream::connect(&path).await.unwrap();
        client
            .write_all(b"{\"a\":\"\xff\"}\n{\"b\":2}\n")
            .await
            .unwrap();
        client.flush().await.unwrap();

        assert_eq!(source.recv().await.unwrap().payload, "{\"a\":\"\u{fffd}\"}");
        assert_eq!(source.recv().await.unwrap().payload, "{\"b\":2}");
    }
}
