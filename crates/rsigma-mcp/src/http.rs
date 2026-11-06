//! Streamable HTTP transport for the MCP server.
//!
//! Mounts the rmcp [`StreamableHttpService`] on an axum router at `/mcp`, with
//! optional static bearer-token authentication enforced as a middleware layer,
//! and `Host` and `Origin` header validation against DNS rebinding and
//! cross-origin browser requests. TLS termination is the
//! caller's responsibility (the CLI reuses the daemon's rustls listener); this
//! module produces the router and a plaintext serve helper.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header::AUTHORIZATION};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};

use crate::RsigmaMcp;

/// The host names [`AllowedHosts::Loopback`] accepts, on any port.
pub const LOOPBACK_HOSTS: [&str; 3] = ["localhost", "127.0.0.1", "::1"];

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
    /// Every host and origin. Only appropriate when bearer auth guards the
    /// endpoint.
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
    let config = StreamableHttpServerConfig::default();
    let hosts = match options.allowed_hosts {
        AllowedHosts::Loopback => Some(LOOPBACK_HOSTS.map(String::from).to_vec()),
        AllowedHosts::List(hosts) if hosts.is_empty() => {
            Some(LOOPBACK_HOSTS.map(String::from).to_vec())
        }
        AllowedHosts::List(hosts) => Some(hosts),
        AllowedHosts::Any => None,
    };
    let config = match hosts {
        Some(hosts) => config
            .with_allowed_origins(allowed_origins(&hosts))
            .with_allowed_hosts(hosts),
        None => config.disable_allowed_hosts().disable_allowed_origins(),
    };
    let service = StreamableHttpService::new(
        move || Ok(handler.clone()),
        Arc::new(LocalSessionManager::default()),
        config,
    );

    let mut router = Router::new().nest_service("/mcp", service);
    if let Some(token) = options.auth_token {
        router = router.layer(middleware::from_fn_with_state(Arc::new(token), bearer_auth));
    }
    router
}

/// The `Origin` values matching `hosts`: each host over `http` and `https`, on
/// its listed port or, without one, on any port.
fn allowed_origins(hosts: &[String]) -> Vec<String> {
    hosts
        .iter()
        .flat_map(|host| {
            let authority = if host.parse::<std::net::Ipv6Addr>().is_ok() {
                format!("[{host}]:*")
            } else if axum::http::uri::Authority::try_from(host.as_str())
                .is_ok_and(|a| a.port_u16().is_some())
            {
                host.clone()
            } else {
                format!("{host}:*")
            };
            ["http", "https"].map(|scheme| format!("{scheme}://{authority}"))
        })
        .collect()
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
/// (plaintext).
pub async fn serve_http_with(
    handler: RsigmaMcp,
    listener: tokio::net::TcpListener,
    options: HttpOptions,
) -> anyhow::Result<()> {
    axum::serve(listener, http_router_with(handler, options)).await?;
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
    use super::{allowed_origins, constant_time_eq};

    #[test]
    fn allowed_origins_cover_both_schemes_and_bracket_ipv6() {
        let hosts = ["localhost", "::1", "[::1]:3000", "mcp.example.com:8443"].map(String::from);
        assert_eq!(
            allowed_origins(&hosts),
            [
                "http://localhost:*",
                "https://localhost:*",
                "http://[::1]:*",
                "https://[::1]:*",
                "http://[::1]:3000",
                "https://[::1]:3000",
                "http://mcp.example.com:8443",
                "https://mcp.example.com:8443",
            ]
        );
    }

    #[test]
    fn constant_time_eq_matches() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secrey"));
        assert!(!constant_time_eq(b"secret", b"secretx"));
        assert!(!constant_time_eq(b"", b"x"));
    }
}
