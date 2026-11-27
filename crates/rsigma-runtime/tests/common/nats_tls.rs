//! A NATS server that only greets: its INFO requires TLS, then it closes the
//! connection, so a client that upgrades fails its handshake. For the tests
//! that a TLS upgrade returns an error instead of panicking.

#![allow(dead_code)]

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

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
