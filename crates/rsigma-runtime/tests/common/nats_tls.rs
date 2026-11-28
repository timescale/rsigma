//! Fake NATS servers for the connection tests.
//!
//! [`tls_required_server`] only greets: its INFO requires TLS, then it closes
//! the connection, so a client that upgrades fails its handshake. For the
//! tests that a TLS upgrade returns an error instead of panicking.
//!
//! [`plain_recording_server`] offers no TLS, completes the handshake, and
//! records every byte its clients send, so a test can tell which credentials
//! and subscriptions reached it.

#![allow(dead_code)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A plain NATS server and what its clients sent it.
pub struct RecordingServer {
    pub url: String,
    received: Arc<Mutex<Vec<u8>>>,
    connections: Arc<Mutex<usize>>,
}

impl RecordingServer {
    /// Every byte any client sent, in arrival order.
    pub fn received(&self) -> String {
        String::from_utf8_lossy(&self.received.lock().unwrap()).into_owned()
    }

    /// How many clients connected.
    pub fn connections(&self) -> usize {
        *self.connections.lock().unwrap()
    }

    /// Wait until a client sent `needle`, failing the test after 10 seconds.
    pub async fn wait_for(&self, needle: &str) {
        let waited = tokio::time::timeout(Duration::from_secs(10), async {
            while !self.received().contains(needle) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(
            waited.is_ok(),
            "no client sent {needle:?}; got {:?}",
            self.received()
        );
    }

    /// Wait until at least one client connected, then give it a moment to
    /// send whatever it was going to.
    pub async fn wait_for_connection(&self) {
        let waited = tokio::time::timeout(Duration::from_secs(10), async {
            while self.connections() == 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(waited.is_ok(), "no client connected");
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

/// Listen on 127.0.0.1 as a NATS server without TLS that answers `PING`
/// and records what clients send.
pub async fn plain_recording_server() -> RecordingServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(Mutex::new(Vec::new()));
    let connections = Arc::new(Mutex::new(0));
    let (log, count) = (received.clone(), connections.clone());
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            *count.lock().unwrap() += 1;
            let log = log.clone();
            tokio::spawn(async move {
                let info = format!(
                    "INFO {{\"server_id\":\"test\",\"version\":\"2.10.0\",\"host\":\"127.0.0.1\",\
                     \"port\":{port},\"max_payload\":1048576,\"proto\":1,\"headers\":true}}\r\n"
                );
                if socket.write_all(info.as_bytes()).await.is_err() {
                    return;
                }
                let mut buffer = [0u8; 4096];
                let mut pending = String::new();
                while let Ok(read) = socket.read(&mut buffer).await {
                    if read == 0 {
                        break;
                    }
                    log.lock().unwrap().extend_from_slice(&buffer[..read]);
                    pending.push_str(&String::from_utf8_lossy(&buffer[..read]));
                    while let Some(end) = pending.find("\r\n") {
                        let line: String = pending.drain(..end + 2).collect();
                        if line.starts_with("PING") && socket.write_all(b"PONG\r\n").await.is_err()
                        {
                            return;
                        }
                    }
                }
            });
        }
    });
    RecordingServer {
        url: format!("nats://127.0.0.1:{port}"),
        received,
        connections,
    }
}

/// Listen on 127.0.0.1 and greet every client this way; the server's URL.
pub async fn tls_required_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let info = format!(
                "INFO {{\"server_id\":\"test\",\"version\":\"2.10.0\",\"host\":\"127.0.0.1\",\
                 \"port\":{port},\"max_payload\":1048576,\"proto\":1,\"tls_required\":true}}\r\n"
            );
            let _ = socket.write_all(info.as_bytes()).await;
        }
    });
    format!("nats://127.0.0.1:{port}")
}
