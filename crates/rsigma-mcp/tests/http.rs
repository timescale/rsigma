//! Integration tests for the Streamable HTTP transport and bearer auth.
//!
//! Only compiled with the `http` feature (which the workspace `--all-features`
//! gate enables).
#![cfg(feature = "http")]

use std::time::Duration;

use rmcp::ServiceExt;
use rmcp::transport::StreamableHttpClientTransport;
use rsigma_mcp::{AllowedHosts, HttpOptions, RsigmaMcp};

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

const INIT_BODY: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#;

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

/// [`HttpOptions`] with `auth_token` and `allowed_hosts` set.
fn options(auth_token: Option<&str>, allowed_hosts: AllowedHosts) -> HttpOptions {
    let mut options = HttpOptions::default();
    options.auth_token = auth_token.map(String::from);
    options.allowed_hosts = allowed_hosts;
    options
}

/// Like [`spawn_server`], with explicit [`HttpOptions`].
async fn spawn_server_with(options: HttpOptions) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = rsigma_mcp::serve_http_with(RsigmaMcp::default(), listener, options).await;
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
    assert_eq!(tools.len(), 15, "expected 15 tools over HTTP");
    assert!(tools.iter().any(|tool| tool.name == "tune_rules"));

    client.cancel().await.ok();
}

#[tokio::test]
async fn http_bearer_auth_401_and_200() {
    ensure_crypto_provider();
    let token = "s3cr3t-token";
    let addr = spawn_server(Some(token.to_string())).await;
    let url = format!("http://{addr}/mcp");
    let http = reqwest::Client::new();

    let init_body = INIT_BODY;

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

/// POST an `initialize` request to `addr` with the given `Host` header.
async fn initialize_with_host(addr: std::net::SocketAddr, host: &str) -> reqwest::StatusCode {
    reqwest::Client::new()
        .post(format!("http://{addr}/mcp"))
        .header("host", host)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(INIT_BODY)
        .send()
        .await
        .expect("request sends")
        .status()
}

/// POST an `initialize` request to `addr`, with `Origin: origin` when given.
async fn initialize_with_origin(
    addr: std::net::SocketAddr,
    origin: Option<&str>,
) -> reqwest::StatusCode {
    let mut request = reqwest::Client::new()
        .post(format!("http://{addr}/mcp"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(INIT_BODY);
    if let Some(origin) = origin {
        request = request.header("origin", origin);
    }
    request.send().await.expect("request sends").status()
}

#[tokio::test]
async fn http_rejects_a_cross_site_origin_by_default() {
    ensure_crypto_provider();
    let addr = spawn_server_with(HttpOptions::default()).await;
    assert_eq!(
        initialize_with_origin(addr, Some("https://evil.example")).await,
        reqwest::StatusCode::FORBIDDEN
    );
    assert!(initialize_with_origin(addr, None).await.is_success());
    for origin in [
        "http://localhost:6274",
        "http://127.0.0.1:3000",
        "https://[::1]",
    ] {
        assert!(
            initialize_with_origin(addr, Some(origin))
                .await
                .is_success(),
            "{origin} must be accepted"
        );
    }
}

#[tokio::test]
async fn http_accepts_origins_of_the_allowed_hosts() {
    ensure_crypto_provider();
    let addr = spawn_server_with(options(
        None,
        AllowedHosts::List(vec![
            "127.0.0.1".to_string(),
            "app.example.com:8443".to_string(),
        ]),
    ))
    .await;
    assert!(
        initialize_with_origin(addr, Some("https://app.example.com:8443"))
            .await
            .is_success()
    );
    for origin in ["https://app.example.com", "http://localhost:6274"] {
        assert_eq!(
            initialize_with_origin(addr, Some(origin)).await,
            reqwest::StatusCode::FORBIDDEN,
            "{origin} must be refused"
        );
    }
}

#[tokio::test]
async fn http_empty_host_list_means_loopback() {
    ensure_crypto_provider();
    let addr = spawn_server_with(options(None, AllowedHosts::List(Vec::new()))).await;
    assert_eq!(
        initialize_with_host(addr, "mcp.example.com").await,
        reqwest::StatusCode::FORBIDDEN
    );
    assert_eq!(
        initialize_with_origin(addr, Some("https://evil.example")).await,
        reqwest::StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn http_rejects_a_remote_host_by_default() {
    ensure_crypto_provider();
    let addr = spawn_server_with(HttpOptions::default()).await;
    assert_eq!(
        initialize_with_host(addr, "mcp.example.com").await,
        reqwest::StatusCode::FORBIDDEN
    );
    let local = format!("localhost:{}", addr.port());
    assert!(initialize_with_host(addr, &local).await.is_success());
}

#[tokio::test]
async fn http_accepts_an_allowed_host() {
    ensure_crypto_provider();
    let addr = spawn_server_with(options(
        None,
        AllowedHosts::List(vec!["mcp.example.com".to_string()]),
    ))
    .await;
    assert!(
        initialize_with_host(addr, "mcp.example.com")
            .await
            .is_success()
    );
    assert_eq!(
        initialize_with_host(addr, "other.example.com").await,
        reqwest::StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn http_any_host_still_requires_the_token() {
    ensure_crypto_provider();
    let addr = spawn_server_with(options(Some("s3cr3t-token"), AllowedHosts::Any)).await;
    assert_eq!(
        initialize_with_host(addr, "mcp.example.com").await,
        reqwest::StatusCode::UNAUTHORIZED
    );
    let status = reqwest::Client::new()
        .post(format!("http://{addr}/mcp"))
        .header("host", "mcp.example.com")
        .header("authorization", "Bearer s3cr3t-token")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(INIT_BODY)
        .send()
        .await
        .expect("request sends")
        .status();
    assert!(status.is_success(), "got {status}");
}
