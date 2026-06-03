use std::io::BufRead;

use tokio::sync::mpsc;

use super::{AckToken, EventSource, RawEvent};

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
        std::thread::Builder::new()
            .name("rsigma-stdin".to_string())
            .spawn(move || {
                let stdin = std::io::stdin();
                for line in stdin.lock().lines() {
                    match line {
                        // `blocking_send` only errors when the receiver is
                        // dropped, i.e. the daemon is shutting down; stop
                        // reading so the thread can exit.
                        Ok(line) => {
                            if tx.blocking_send(line).is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Error reading stdin");
                            break;
                        }
                    }
                }
            })
            .expect("failed to spawn stdin reader thread");
        StdinSource { rx }
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
                    });
                }
                Some(_) => continue,
                None => return None,
            }
        }
    }
}
