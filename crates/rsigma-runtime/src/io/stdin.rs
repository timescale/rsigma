use std::io::BufRead;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::mpsc;

use super::{AckToken, EventSource, RawEvent};

/// Whether the stdin reader stopped on a read error instead of end of input.
#[derive(Debug, Clone, Default)]
pub struct StdinReadStatus(Arc<AtomicBool>);

impl StdinReadStatus {
    /// True once the reader has stopped on an I/O error or a line that is
    /// not valid UTF-8. Final once the source has reported end of input.
    pub fn failed(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Reads events from stdin, one per line.
///
/// Reading happens on a dedicated OS thread (`std::thread`) that forwards
/// each line over a bounded channel, rather than via `tokio::io::stdin()`.
/// `tokio::io::stdin()` is implemented with an ordinary blocking read on a
/// runtime-managed thread that cannot be cancelled; when no input is pending,
/// that read parks until the next line or EOF and the Tokio runtime waits for
/// it during shutdown. That makes the daemon hang on Ctrl+C / SIGTERM until
/// more input arrives (see the `tokio::io::stdin` docs). Because a plain
/// `std::thread` is not a runtime blocking task, the runtime does not wait for
/// it at shutdown, so the daemon exits promptly even with an idle stdin.
pub struct StdinSource {
    rx: mpsc::Receiver<String>,
    status: StdinReadStatus,
}

impl Default for StdinSource {
    fn default() -> Self {
        Self::new()
    }
}

impl StdinSource {
    pub fn new() -> Self {
        // Bounded so a slow pipeline back-pressures the reader thread (which
        // then stops draining the OS stdin buffer) instead of buffering
        // unboundedly.
        let (tx, rx) = mpsc::channel(1024);
        let status = StdinReadStatus::default();
        let thread_status = status.clone();
        std::thread::Builder::new()
            .name("rsigma-stdin".to_string())
            .spawn(move || {
                let stdin = std::io::stdin();
                read_lines(stdin.lock(), &tx, &thread_status);
            })
            .expect("failed to spawn stdin reader thread");
        StdinSource { rx, status }
    }

    /// Take this before handing the source to [`spawn_source`](super::spawn_source).
    pub fn read_status(&self) -> StdinReadStatus {
        self.status.clone()
    }
}

fn read_lines(reader: impl BufRead, tx: &mpsc::Sender<String>, status: &StdinReadStatus) {
    for line in reader.lines() {
        match line {
            // `blocking_send` only errors when the receiver is dropped, i.e.
            // the daemon is shutting down; stop reading so the thread can
            // exit.
            Ok(line) => {
                if tx.blocking_send(line).is_err() {
                    break;
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "Error reading stdin");
                status.0.store(true, Ordering::Release);
                break;
            }
        }
    }
}

impl EventSource for StdinSource {
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
    use std::io::Cursor;

    use super::*;

    #[test]
    fn read_error_is_reported() {
        let (tx, mut rx) = mpsc::channel(8);
        let status = StdinReadStatus::default();
        read_lines(
            Cursor::new(b"{\"a\":1}\n\xff\xfe\n{\"b\":2}\n"),
            &tx,
            &status,
        );
        assert_eq!(rx.try_recv().unwrap(), "{\"a\":1}");
        assert!(rx.try_recv().is_err());
        assert!(status.failed());
    }

    #[test]
    fn clean_input_is_not_a_failure() {
        let (tx, mut rx) = mpsc::channel(8);
        let status = StdinReadStatus::default();
        read_lines(Cursor::new(b"{\"a\":1}\n{\"b\":2}\n"), &tx, &status);
        assert_eq!(rx.try_recv().unwrap(), "{\"a\":1}");
        assert_eq!(rx.try_recv().unwrap(), "{\"b\":2}");
        assert!(rx.try_recv().is_err());
        assert!(!status.failed());
    }
}
