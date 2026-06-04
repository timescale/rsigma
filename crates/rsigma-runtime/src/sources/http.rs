//! HTTP source resolver: fetches data from HTTP endpoints.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use rsigma_eval::pipeline::sources::{DataFormat, ExtractExpr};

use super::extract::apply_extract;
use super::file::parse_data;
use super::{MAX_SOURCE_RESPONSE_BYTES, ResolvedValue, SourceError, SourceErrorKind};

/// Process-wide shared HTTP client for source fetches. Built lazily on first
/// use and reused for every subsequent call so refresh storms (e.g. a
/// dynamic-source pipeline pulling several feeds every 30 seconds) amortize
/// TLS handshakes, connection pooling, and DNS resolution. Per-call timeouts
/// are applied via [`reqwest::RequestBuilder::timeout`] so a shared client is
/// safe even when callers want different timeouts.
static DEFAULT_HTTP_SOURCE_CLIENT: OnceLock<Arc<reqwest::Client>> = OnceLock::new();

const DEFAULT_SOURCE_TIMEOUT: Duration = Duration::from_secs(30);

/// Return the process-wide HTTP client used by source resolution.
///
/// The first call constructs the client; subsequent calls return the same
/// `Arc<reqwest::Client>`. The client is wired to the
/// [`default_egress_policy`](crate::egress::default_egress_policy) via a
/// custom DNS resolver so a Sigma rule that points the daemon at a cloud
/// metadata endpoint cannot exfiltrate IAM credentials.
///
/// Errors building the client are surfaced as `SourceError` rather than
/// panicking so callers can fail-soft on broken TLS setups instead of
/// crashing the daemon.
pub fn shared_http_source_client() -> Result<Arc<reqwest::Client>, SourceError> {
    if let Some(client) = DEFAULT_HTTP_SOURCE_CLIENT.get() {
        return Ok(client.clone());
    }
    let resolver =
        crate::egress::EgressFilteredResolver::new(crate::egress::default_egress_policy())
            .into_dns_resolver();
    let built = reqwest::Client::builder()
        .dns_resolver(resolver)
        .build()
        .map(Arc::new)
        .map_err(|e| SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::Fetch(format!("failed to build HTTP client: {e}")),
        })?;
    // Other threads may have raced us; whichever insert wins is fine.
    Ok(DEFAULT_HTTP_SOURCE_CLIENT.get_or_init(|| built).clone())
}

/// Resolve an HTTP source by fetching the URL and parsing the response.
pub async fn resolve_http(
    url: &str,
    method: Option<&str>,
    headers: &HashMap<String, String>,
    format: DataFormat,
    extract_expr: Option<&ExtractExpr>,
    timeout: Option<Duration>,
) -> Result<ResolvedValue, SourceError> {
    resolve_http_with_limit(
        url,
        method,
        headers,
        format,
        extract_expr,
        timeout,
        MAX_SOURCE_RESPONSE_BYTES,
    )
    .await
}

/// Inner implementation with a configurable size limit (for testing).
pub(crate) async fn resolve_http_with_limit(
    url: &str,
    method: Option<&str>,
    headers: &HashMap<String, String>,
    format: DataFormat,
    extract_expr: Option<&ExtractExpr>,
    timeout: Option<Duration>,
    max_bytes: usize,
) -> Result<ResolvedValue, SourceError> {
    let client = shared_http_source_client()?;

    let method_str = method.unwrap_or("GET");
    let reqwest_method = method_str
        .parse::<reqwest::Method>()
        .map_err(|e| SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::Fetch(format!("invalid HTTP method '{method_str}': {e}")),
        })?;

    let mut request = client
        .request(reqwest_method, url)
        .timeout(timeout.unwrap_or(DEFAULT_SOURCE_TIMEOUT));

    for (key, value) in headers {
        let expanded_value = expand_env_vars(value);
        request = request.header(key.as_str(), expanded_value);
    }

    let response = request.send().await.map_err(|e| {
        if e.is_timeout() {
            SourceError {
                source_id: String::new(),
                kind: SourceErrorKind::Timeout,
            }
        } else {
            SourceError {
                source_id: String::new(),
                kind: SourceErrorKind::Fetch(format!("HTTP request failed: {e}")),
            }
        }
    })?;

    let status = response.status();
    if !status.is_success() {
        let body = read_body_capped(response, max_bytes)
            .await
            .unwrap_or_default();
        return Err(SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::Fetch(format!("HTTP {status}: {}", body.trim())),
        });
    }

    if let Some(content_length) = response.content_length()
        && content_length as usize > max_bytes
    {
        return Err(SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::ResourceLimit(format!(
                "HTTP response Content-Length ({content_length} bytes) exceeds {max_bytes} byte limit"
            )),
        });
    }

    let body = read_body_capped(response, max_bytes).await?;

    let parsed = parse_data(&body, format)?;

    let data = if let Some(expr) = extract_expr {
        apply_extract(&parsed, expr)?
    } else {
        parsed
    };

    Ok(ResolvedValue {
        data,
        resolved_at: Instant::now(),
        from_cache: false,
    })
}

/// Read a response body in chunks, enforcing a maximum byte cap.
async fn read_body_capped(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<String, SourceError> {
    let mut buf = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| SourceError {
        source_id: String::new(),
        kind: SourceErrorKind::Fetch(format!("failed to read response chunk: {e}")),
    })? {
        if buf.len() + chunk.len() > max_bytes {
            return Err(SourceError {
                source_id: String::new(),
                kind: SourceErrorKind::ResourceLimit(format!(
                    "HTTP response body exceeds {max_bytes} byte limit"
                )),
            });
        }
        buf.extend_from_slice(&chunk);
    }
    String::from_utf8(buf).map_err(|e| SourceError {
        source_id: String::new(),
        kind: SourceErrorKind::Parse(format!("response body is not valid UTF-8: {e}")),
    })
}

/// Expand `${ENV_VAR}` references in a string with environment variable values.
fn expand_env_vars(s: &str) -> String {
    let re = regex::Regex::new(r"\$\{([A-Z_][A-Z0-9_]*)\}").unwrap();
    re.replace_all(s, |caps: &regex::Captures| {
        let var_name = caps.get(1).unwrap().as_str();
        std::env::var(var_name).unwrap_or_default()
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_http_source_client_is_arc_stable() {
        // Two calls return the same underlying Arc so source refresh
        // storms reuse the same connection pool.
        let a = shared_http_source_client().expect("first build");
        let b = shared_http_source_client().expect("second call");
        assert!(
            Arc::ptr_eq(&a, &b),
            "shared HTTP source client must be process-wide stable"
        );
    }
}
