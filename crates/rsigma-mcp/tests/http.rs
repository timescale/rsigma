//! Integration tests for the Streamable HTTP transport and bearer auth.
//!
//! Only compiled with the `http` feature (which the workspace `--all-features`
//! gate enables).
#![cfg(feature = "http")]

use std::time::Duration;

use rmcp::ServiceExt;
use rmcp::transport::StreamableHttpClientTransport;
use rsigma_mcp::RsigmaMcp;

/// Install a process-default rustls crypto provider. Under `--all-features`
/// both aws-lc-rs and ring are in the dependency graph, so rustls has no
/// unambiguous default and the reqwest client the rmcp transport builds would
/// otherwise panic with "No provider set". Idempotent.
fn ensure_crypto_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Bind an ephemeral port and spawn the MCP HTTP server on it, returning the
/// bound address once it is listening.
async fn spawn_server(auth: Option<String>) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = rsigma_mcp::serve_http(RsigmaMcp::default(), listener, auth).await;
    });
    // Give the spawned server a moment to start accepting.
    tokio::time::sleep(Duration::from_millis(100)).await;
    addr
}

#[tokio::test]
async fn http_tools_list_round_trip() {
    ensure_crypto_provider();
    let addr = spawn_server(None).await;
    let transport = StreamableHttpClientTransport::from_uri(format!("http://{addr}/mcp"));
    let client = ().serve(transport).await.expect("client connect");

    let tools = client.list_all_tools().await.expect("list tools");
    assert_eq!(tools.len(), 11, "expected 11 tools over HTTP");

    client.cancel().await.ok();
}

#[tokio::test]
async fn http_bearer_auth_401_and_200() {
    ensure_crypto_provider();
    let token = "s3cr3t-token";
    let addr = spawn_server(Some(token.to_string())).await;
    let url = format!("http://{addr}/mcp");
    let http = reqwest::Client::new();

    let init_body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#;

    // No token -> the bearer middleware rejects before the MCP service.
    let resp = http
        .post(&url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(init_body)
        .send()
        .await
        .expect("request sends");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Correct token -> request passes the middleware (the MCP service handles
    // it; the status is no longer 401).
    let resp = http
        .post(&url)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(init_body)
        .send()
        .await
        .expect("request sends");
    assert_ne!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "request with a valid token must not be 401"
    );
    assert!(
        resp.status().is_success(),
        "request with a valid token should be handled: got {}",
        resp.status()
    );
}
