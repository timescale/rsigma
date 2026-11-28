//! Streamable HTTP transport for the MCP server.
//!
//! Mounts the rmcp [`StreamableHttpService`] on an axum router at `/mcp`, with
//! optional static bearer-token authentication enforced as a middleware layer,
//! and `Host` and `Origin` header validation against DNS rebinding and
//! cross-origin browser requests (the rules of [`rsigma_runtime::http_guard`],
//! shared with the daemon API). TLS termination is the
//! caller's responsibility (the CLI reuses the daemon's rustls listener); this
//! module produces the router and a plaintext serve helper.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::http::header::{AUTHORIZATION, HOST, ORIGIN};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};

use rsigma_runtime::HostGuard;
pub use rsigma_runtime::http_guard::LOOPBACK_HOSTS;
pub use rsigma_runtime::http_server::ServeLimits;

use crate::RsigmaMcp;

/// Which `Host` header values the MCP endpoint accepts. Any other host gets
/// `403 Forbidden`, which stops a DNS-rebinding page from reaching a server
/// bound to a local address. A request carrying an `Origin` header must also
/// name one of these hosts over `http` or `https`, so a web page on another
/// site cannot drive the endpoint through the user's browser.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum AllowedHosts {
    /// [`LOOPBACK_HOSTS`], on any port.
    #[default]
    Loopback,
    /// Exactly these host names or `host:port` authorities. A host without a
    /// port matches any port. An empty list means [`Loopback`](Self::Loopback).
    List(Vec<String>),
    /// Every host. A request with an `Origin` header must still come from the
    /// site it addresses (the origin names the request's own `Host`). Only
    /// appropriate when bearer auth guards the endpoint.
    Any,
}

/// Options for [`http_router_with`] and [`serve_http_with`]. Start from
/// [`HttpOptions::default`] and set the fields you need.
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct HttpOptions {
    /// When `Some`, every request must carry a matching
    /// `Authorization: Bearer <token>` header or receive `401 Unauthorized`.
    pub auth_token: Option<String>,
    /// Accepted `Host` header values.
    pub allowed_hosts: AllowedHosts,
    /// Connection cap and read timeouts applied by [`serve_http_with`].
    pub limits: ServeLimits,
}

/// Build the axum router exposing the MCP service at `/mcp`.
///
/// When `auth_token` is `Some`, every request must carry a matching
/// `Authorization: Bearer <token>` header or receive `401 Unauthorized`. Only
/// loopback `Host` headers are accepted; use [`http_router_with`] to change
/// that.
pub fn http_router(handler: RsigmaMcp, auth_token: Option<String>) -> Router {
    http_router_with(
        handler,
        HttpOptions {
            auth_token,
            ..Default::default()
        },
    )
}

/// Build the axum router exposing the MCP service at `/mcp` with `options`.
pub fn http_router_with(handler: RsigmaMcp, options: HttpOptions) -> Router {
    let config = StreamableHttpServerConfig::default()
        .disable_allowed_hosts()
        .disable_allowed_origins();
    let service = StreamableHttpService::new(
        move || Ok(handler.clone()),
        Arc::new(LocalSessionManager::default()),
        config,
    );

    let mut router = Router::new().nest_service("/mcp", service);
    if let Some(token) = options.auth_token {
        router = router.layer(middleware::from_fn_with_state(Arc::new(token), bearer_auth));
    }
    let guard = host_guard(options.allowed_hosts);
    router.layer(middleware::from_fn_with_state(Arc::new(guard), check_host))
}

/// The [`HostGuard`] for `hosts`. Entries that do not parse as a host name,
/// IP address, or `host:port` are skipped with a warning.
fn host_guard(hosts: AllowedHosts) -> HostGuard {
    match hosts {
        AllowedHosts::Loopback => HostGuard::loopback(),
        AllowedHosts::Any => HostGuard::any(),
        AllowedHosts::List(hosts) => {
            let valid: Vec<String> = hosts
                .into_iter()
                .filter(|host| {
                    let ok = HostGuard::new([host]).is_ok();
                    if !ok {
                        tracing::warn!(host = %host, "ignoring an allowed host that does not parse");
                    }
                    ok
                })
                .collect();
            HostGuard::new(valid).unwrap_or_default()
        }
    }
}

/// Refuse requests whose `Host` or `Origin` the guard does not accept, before
/// authentication and before the MCP service reads the body.
async fn check_host(State(guard): State<Arc<HostGuard>>, request: Request, next: Next) -> Response {
    let headers = request.headers();
    let verdict = guard.check(
        headers.get(HOST).map(|v| v.as_bytes()),
        request.uri().authority().map(|a| a.as_str()),
        headers.get(ORIGIN).map(|v| v.as_bytes()),
    );
    match verdict {
        Ok(()) => next.run(request).await,
        Err(rejection) => {
            tracing::warn!(reason = %rejection, "rejected an MCP HTTP request");
            let status = StatusCode::from_u16(rejection.status()).unwrap_or(StatusCode::FORBIDDEN);
            (status, rejection.message()).into_response()
        }
    }
}

/// Serve the MCP HTTP router on `listener` (plaintext). The caller owns the
/// tokio runtime; for TLS, build [`http_router`] and serve it over a
/// TLS-terminating [`axum::serve::Listener`] instead.
pub async fn serve_http(
    handler: RsigmaMcp,
    listener: tokio::net::TcpListener,
    auth_token: Option<String>,
) -> anyhow::Result<()> {
    serve_http_with(
        handler,
        listener,
        HttpOptions {
            auth_token,
            ..Default::default()
        },
    )
    .await
}

/// Serve the MCP HTTP router built by [`http_router_with`] on `listener`
/// (plaintext), with the connection cap and read timeouts of
/// [`HttpOptions::limits`]. Runs until the task is dropped.
pub async fn serve_http_with(
    handler: RsigmaMcp,
    listener: tokio::net::TcpListener,
    options: HttpOptions,
) -> anyhow::Result<()> {
    let limits = options.limits;
    rsigma_runtime::http_server::serve(
        listener,
        http_router_with(handler, options),
        limits,
        std::future::pending(),
    )
    .await;
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
