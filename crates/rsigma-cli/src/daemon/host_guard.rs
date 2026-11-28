//! `Host` and `Origin` validation for the daemon API on a TCP listener.
//!
//! Without it, a web page the operator opens could send a cross-origin
//! `text/plain` POST to an unauthenticated loopback daemon (no CORS preflight
//! is needed for that), or rebind its own name to `127.0.0.1` and read the
//! API. The middleware wraps the whole router, OTLP included, so it runs
//! before authentication, routing, and body buffering.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::header::{HOST, ORIGIN};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use rsigma_runtime::HostGuard;

/// Liveness and readiness probes skip the check. They expose nothing and
/// stay open without credentials too, and orchestrators probe them by pod
/// address, which is rarely an allowed host.
fn is_probe(request: &Request) -> bool {
    matches!(*request.method(), Method::GET | Method::HEAD)
        && matches!(request.uri().path(), "/healthz" | "/readyz")
}

pub(crate) async fn check_host(
    State(guard): State<Arc<HostGuard>>,
    request: Request,
    next: Next,
) -> Response {
    if is_probe(&request) {
        return next.run(request).await;
    }
    let headers = request.headers();
    let verdict = guard.check(
        headers.get(HOST).map(|v| v.as_bytes()),
        request.uri().authority().map(|a| a.as_str()),
        headers.get(ORIGIN).map(|v| v.as_bytes()),
    );
    match verdict {
        Ok(()) => next.run(request).await,
        Err(rejection) => {
            tracing::warn!(
                reason = %rejection,
                host = ?request.headers().get(HOST),
                origin = ?request.headers().get(ORIGIN),
                path = %request.uri().path(),
                "Rejected an API request"
            );
            let status = StatusCode::from_u16(rejection.status()).unwrap_or(StatusCode::FORBIDDEN);
            let body = serde_json::json!({ "error": rejection.message() });
            (status, axum::Json(body)).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::routing::{get, post};
    use tower::ServiceExt;

    fn app(guard: HostGuard) -> Router {
        Router::new()
            .route("/healthz", get(|| async { "ok" }))
            .route("/api/v1/events", post(|| async { "accepted" }))
            .layer(axum::middleware::from_fn_with_state(
                Arc::new(guard),
                check_host,
            ))
    }

    async fn status(guard: HostGuard, method: &str, path: &str, headers: &[(&str, &str)]) -> u16 {
        let mut request = Request::builder().method(method).uri(path);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        app(guard)
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
            .as_u16()
    }

    #[tokio::test]
    async fn foreign_host_and_origin_are_refused_before_the_handler() {
        let guard = HostGuard::loopback();
        let post = "POST";
        let path = "/api/v1/events";
        assert_eq!(
            status(guard.clone(), post, path, &[("host", "evil.example")]).await,
            403
        );
        assert_eq!(
            status(
                guard.clone(),
                post,
                path,
                &[
                    ("host", "127.0.0.1:9090"),
                    ("origin", "https://evil.example")
                ]
            )
            .await,
            403
        );
        assert_eq!(status(guard.clone(), post, path, &[]).await, 400);
        for host in ["localhost:9090", "127.0.0.1:9090", "[::1]:9090"] {
            assert_eq!(
                status(guard.clone(), post, path, &[("host", host)]).await,
                200
            );
        }
    }

    #[tokio::test]
    async fn probes_skip_the_host_check() {
        let guard = HostGuard::loopback();
        assert_eq!(
            status(
                guard.clone(),
                "GET",
                "/healthz",
                &[("host", "10.1.2.3:9090")]
            )
            .await,
            200
        );
        assert_eq!(
            status(guard, "POST", "/healthz", &[("host", "10.1.2.3:9090")]).await,
            403
        );
    }
}
