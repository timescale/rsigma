//! HTTP source resolver: fetches data from HTTP endpoints.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rsigma_eval::pipeline::sources::{DataFormat, ExtractExpr};

use super::extract::apply_extract;
use super::file::parse_data;
use super::{ResolvedValue, SourceError, SourceErrorKind};

/// Resolve an HTTP source by fetching the URL and parsing the response.
pub async fn resolve_http(
    url: &str,
    method: Option<&str>,
    headers: &HashMap<String, String>,
    format: DataFormat,
    extract_expr: Option<&ExtractExpr>,
    timeout: Option<Duration>,
) -> Result<ResolvedValue, SourceError> {
    let client = reqwest::Client::builder()
        .timeout(timeout.unwrap_or(Duration::from_secs(30)))
        .build()
        .map_err(|e| SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::Fetch(format!("failed to build HTTP client: {e}")),
        })?;

    let method_str = method.unwrap_or("GET");
    let reqwest_method = method_str
        .parse::<reqwest::Method>()
        .map_err(|e| SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::Fetch(format!("invalid HTTP method '{method_str}': {e}")),
        })?;

    let mut request = client.request(reqwest_method, url);

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
        let body = response.text().await.unwrap_or_default();
        return Err(SourceError {
            source_id: String::new(),
            kind: SourceErrorKind::Fetch(format!("HTTP {status}: {}", body.trim())),
        });
    }

    let body = response.text().await.map_err(|e| SourceError {
        source_id: String::new(),
        kind: SourceErrorKind::Fetch(format!("failed to read response body: {e}")),
    })?;

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

/// Expand `${ENV_VAR}` references in a string with environment variable values.
fn expand_env_vars(s: &str) -> String {
    let re = regex::Regex::new(r"\$\{([A-Z_][A-Z0-9_]*)\}").unwrap();
    re.replace_all(s, |caps: &regex::Captures| {
        let var_name = caps.get(1).unwrap().as_str();
        std::env::var(var_name).unwrap_or_default()
    })
    .to_string()
}
