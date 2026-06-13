//! Streamable HTTP transport for the MCP server.
//!
//! Mounts the rmcp [`StreamableHttpService`] on an axum router at `/mcp`, with
//! optional static bearer-token authentication enforced as a middleware layer.
//! TLS termination is the caller's responsibility (the CLI reuses the daemon's
//! rustls listener); this module produces the router and a plaintext serve
//! helper.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header::AUTHORIZATION};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use rmcp::transport::streamable_http_server::StreamableHttpService;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;

use crate::RsigmaMcp;

/// Build the axum router exposing the MCP service at `/mcp`.
///
/// When `auth_token` is `Some`, every request must carry a matching
/// `Authorization: Bearer <token>` header or receive `401 Unauthorized`.
pub fn http_router(handler: RsigmaMcp, auth_token: Option<String>) -> Router {
    let service = StreamableHttpService::new(
        move || Ok(handler.clone()),
        Arc::new(LocalSessionManager::default()),
        Default::default(),
    );

    let mut router = Router::new().nest_service("/mcp", service);
    if let Some(token) = auth_token {
        router = router.layer(middleware::from_fn_with_state(Arc::new(token), bearer_auth));
    }
    router
}

/// Serve the MCP HTTP router on `listener` (plaintext). The caller owns the
/// tokio runtime; for TLS, build [`http_router`] and serve it over a
/// TLS-terminating [`axum::serve::Listener`] instead.
pub async fn serve_http(
    handler: RsigmaMcp,
    listener: tokio::net::TcpListener,
    auth_token: Option<String>,
) -> anyhow::Result<()> {
    let router = http_router(handler, auth_token);
    axum::serve(listener, router).await?;
    Ok(())
}

/// Bearer-token auth middleware. Compares the presented token to the configured
/// one in constant time and returns `401` on any mismatch or absence.
async fn bearer_auth(
    State(expected): State<Arc<String>>,
    request: Request,
    next: Next,
) -> Response {
    let authorized = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|t| constant_time_eq(t.as_bytes(), expected.as_bytes()))
        .unwrap_or(false);

    if authorized {
        next.run(request).await
    } else {
        (StatusCode::UNAUTHORIZED, "missing or invalid bearer token").into_response()
    }
}

/// Constant-time byte comparison so token checks do not leak the matched prefix
/// length via timing. (The overall length is not secret for a bearer token.)
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::constant_time_eq;

    #[test]
    fn constant_time_eq_matches() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secrey"));
        assert!(!constant_time_eq(b"secret", b"secretx"));
        assert!(!constant_time_eq(b"", b"x"));
    }
}
