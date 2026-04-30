use tokio::io::{AsyncBufReadExt, BufReader};

use super::{AckToken, EventSource, RawEvent};

/// Reads events from stdin, one per line.
///
/// Uses `tokio::io::stdin()` with `AsyncBufReadExt::lines()` for fully async
/// reading without a background blocking thread.
pub struct StdinSource {
    lines: tokio::io::Lines<BufReader<tokio::io::Stdin>>,
}

impl Default for StdinSource {
    fn default() -> Self {
        Self::new()
    }
}

impl StdinSource {
    pub fn new() -> Self {
        let stdin = tokio::io::stdin();
        let lines = BufReader::new(stdin).lines();
        StdinSource { lines }
    }
}

impl EventSource for StdinSource {
    async fn recv(&mut self) -> Option<RawEvent> {
        loop {
            match self.lines.next_line().await {
                Ok(Some(line)) if !line.trim().is_empty() => {
                    return Some(RawEvent {
                        payload: line,
                        ack_token: AckToken::Noop,
                    });
                }
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
