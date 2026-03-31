use tokio::io::{AsyncBufReadExt, BufReader};

use super::EventSource;

/// Reads JSON events from stdin, one per line.
///
/// Uses `tokio::io::stdin()` with `AsyncBufReadExt::lines()` for fully async
/// reading without a background blocking thread.
pub struct StdinSource {
    lines: tokio::io::Lines<BufReader<tokio::io::Stdin>>,
}

impl StdinSource {
    pub fn new() -> Self {
        let stdin = tokio::io::stdin();
        let lines = BufReader::new(stdin).lines();
        StdinSource { lines }
    }
}

impl EventSource for StdinSource {
    async fn recv(&mut self) -> Option<String> {
        loop {
            match self.lines.next_line().await {
                Ok(Some(line)) if !line.trim().is_empty() => return Some(line),
                Ok(Some(_)) => continue,
                Ok(None) => return None,
                Err(e) => {
                    tracing::warn!(error = %e, "Error reading stdin");
                    return None;
                }
            }
        }
    }
}
