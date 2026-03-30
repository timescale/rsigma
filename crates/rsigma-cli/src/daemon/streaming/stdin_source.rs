use std::io::BufRead;

use tokio::sync::mpsc;

use super::EventSource;

/// Reads JSON events from stdin, one per line.
///
/// Spawns a blocking thread internally to read from stdin. The async
/// `recv()` reads from the internal channel, bridging the sync-to-async
/// boundary.
pub struct StdinSource {
    rx: mpsc::Receiver<String>,
}

impl StdinSource {
    /// Create a new StdinSource and spawn its blocking reader thread.
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(10_000);
        tokio::task::spawn_blocking(move || {
            let stdin = std::io::stdin();
            let reader = stdin.lock();
            for line in reader.lines() {
                match line {
                    Ok(line) if !line.trim().is_empty() => {
                        if tx.blocking_send(line).is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!(error = %e, "Error reading stdin");
                        break;
                    }
                }
            }
            tracing::info!("stdin closed");
        });
        StdinSource { rx }
    }
}

impl EventSource for StdinSource {
    async fn recv(&mut self) -> Option<String> {
        self.rx.recv().await
    }
}
