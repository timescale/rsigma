//! `unix://` event source: accept newline-delimited events over a Unix domain
//! socket.
//!
//! Modeled on [`StdinSource`](super::StdinSource) but fed by an accept loop, so
//! co-located log shippers (rsyslog `omuxsock`, syslog-ng `unix-stream`,
//! Vector, Fluent Bit) can connect concurrently. Each line becomes one
//! [`RawEvent`]; acks are a no-op (a raw stream has no per-message ack).

use std::path::Path;

use tokio::io::AsyncReadExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

use super::unix::{UnixSocketGuard, bind_unix_listener};
use super::{AckToken, EventSource, RawEvent};

/// Maximum length of a single newline-delimited line. Mirrors the daemon's
/// HTTP ingest cap so a client that never sends a newline cannot exhaust
/// memory; longer lines are dropped with a warning.
const MAX_LINE_BYTES: usize = 1024 * 1024;

/// Channel capacity between the socket readers and the engine. Bounded so a
/// slow pipeline back-pressures the readers (which stop draining their
/// sockets) instead of buffering unboundedly.
const CHANNEL_CAPACITY: usize = 1024;

/// Reads events from a Unix domain socket, one record per line.
pub struct UnixSocketSource {
    rx: mpsc::Receiver<String>,
    /// Unlinks the socket file when the source is dropped (daemon shutdown).
    _guard: UnixSocketGuard,
}

impl UnixSocketSource {
    /// Bind the socket at `path` and start accepting connections.
    pub async fn bind(path: &Path) -> std::io::Result<Self> {
        let (listener, guard) = bind_unix_listener(path).await?;
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        tokio::spawn(accept_loop(listener, tx));
        Ok(Self { rx, _guard: guard })
    }
}

/// Accept connections, spawning one reader task per connection. Ends when every
/// reader has dropped the shared sender (the channel receiver closed on
/// shutdown) or is aborted with the daemon.
async fn accept_loop(listener: UnixListener, tx: mpsc::Sender<String>) {
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                tokio::spawn(read_connection(stream, tx.clone()));
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
/// engine. Bounds each line to `MAX_LINE_BYTES`, discarding longer ones.
async fn read_connection(mut stream: UnixStream, tx: mpsc::Sender<String>) {
    let mut line: Vec<u8> = Vec::with_capacity(256);
    let mut chunk = [0u8; 8192];
    // True while discarding the tail of an over-long line.
    let mut discarding = false;

    loop {
        let n = match stream.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(error = %e, "unix socket read failed");
                break;
            }
        };
        for &byte in &chunk[..n] {
            if byte == b'\n' {
                if discarding {
                    discarding = false;
                } else if !line.is_empty() {
                    let decoded = take_line(&mut line);
                    if tx.send(decoded).await.is_err() {
                        return; // receiver gone: shutting down
                    }
                }
                line.clear();
            } else if discarding {
                continue;
            } else if line.len() >= MAX_LINE_BYTES {
                tracing::warn!(
                    max_bytes = MAX_LINE_BYTES,
                    "dropping over-long unix socket line"
                );
                discarding = true;
                line.clear();
            } else {
                line.push(byte);
            }
        }
    }

    // Flush a trailing line that ended at EOF without a newline.
    if !discarding && !line.is_empty() {
        let _ = tx.send(take_line(&mut line)).await;
    }
}

/// Decode the accumulated bytes (minus a trailing CR) as UTF-8, returning an
/// empty string for invalid UTF-8 (skipped downstream).
fn take_line(line: &mut Vec<u8>) -> String {
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    match std::str::from_utf8(line) {
        Ok(s) => s.to_string(),
        Err(_) => {
            tracing::warn!("dropping non-UTF-8 line on unix socket");
            String::new()
        }
    }
}

impl EventSource for UnixSocketSource {
    async fn recv(&mut self) -> Option<RawEvent> {
        loop {
            match self.rx.recv().await {
                Some(line) if !line.trim().is_empty() => {
                    return Some(RawEvent {
                        payload: line,
                        ack_token: AckToken::Noop,
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
}
