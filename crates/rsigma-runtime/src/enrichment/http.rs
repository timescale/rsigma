//! `HttpEnricher`: per-result HTTP fetch with optional response cache.
//!
//! Builds a [`reqwest::Request`] from a template-expanded URL, optional
//! template-expanded headers, and an optional template-expanded body.
//! The response is parsed as JSON; if an `extract` expression is set,
//! it is applied via [`crate::sources::extract::apply_extract`] using
//! the existing dynamic-pipelines extractor stack (jq / jsonpath / cel)
//! so operators learn one mental model, not two.
//!
//! Optional in-memory response cache via [`super::http_cache::HttpResponseCache`]
//! keyed on `(method, url, body_hash)` with configurable TTL. Mandatory
//! in practice for rate-limited APIs (VirusTotal: 4 req/min free tier).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use rsigma_eval::EvaluationResult;
use rsigma_eval::pipeline::sources::ExtractExpr;
use serde_json::Value;

use super::{
    EnrichError, EnrichErrorKind, Enricher, EnricherKind, OnError, Scope,
    http_cache::{CacheKey, CacheOutcome, HttpResponseCache},
    inject_enrichment,
    template::render_template,
};
use crate::metrics::{MetricsHook, NoopMetrics};

/// One HTTP enricher instance.
///
/// Constructed by the daemon config loader. The `Arc<reqwest::Client>`
/// is shared across all HTTP enrichers in the same daemon process so
/// connection pooling works at the process level rather than per-config-block.
pub struct HttpEnricher {
    id: String,
    kind: EnricherKind,
    inject_field: String,
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Option<String>,
    timeout: Duration,
    on_error: OnError,
    scope: Scope,
    extract: Option<ExtractExpr>,
    client: HttpEnricherClient,
    cache: HttpResponseCache,
    metrics: Arc<dyn MetricsHook>,
}

/// Opaque handle around a process-wide `reqwest::Client`. Constructed by
/// [`build_default_http_client`] and passed by [`Arc`] to every
/// [`HttpEnricher`] so connection pooling works at the daemon level.
///
/// Wrapping the `reqwest::Client` keeps `reqwest` an internal dependency
/// of `rsigma-runtime` so consumer crates (e.g. `rsigma-cli`) do not
/// need a direct dep just to wire enrichers together.
#[derive(Clone)]
pub struct HttpEnricherClient(Arc<reqwest::Client>);

impl HttpEnricherClient {
    /// Wrap an existing `reqwest::Client`. Useful for tests that want to
    /// stub out the client (e.g. a `wiremock`-backed tower stack).
    pub fn from_reqwest(client: Arc<reqwest::Client>) -> Self {
        Self(client)
    }
    /// Access the inner client. Crate-private so external code goes
    /// through the wrapper.
    fn inner(&self) -> &reqwest::Client {
        &self.0
    }
}

/// Build the default shared HTTP client used by the daemon's enrichment
/// pipeline. All HTTP enrichers in the same daemon process share one
/// client to amortize TLS handshakes and DNS resolution.
pub fn build_default_http_client() -> Result<HttpEnricherClient, String> {
    reqwest::Client::builder()
        .build()
        .map(|c| HttpEnricherClient(Arc::new(c)))
        .map_err(|e| format!("reqwest client build failed: {e}"))
}

impl HttpEnricher {
    /// Build a new enricher.
    ///
    /// `client` is shared at the process level. `cache` may be a
    /// disabled cache ([`HttpResponseCache::new(Duration::from_secs(0))`])
    /// when `cache_ttl` is unset; the lookup path treats that as "always
    /// miss".
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        kind: EnricherKind,
        inject_field: String,
        method: String,
        url: String,
        headers: Vec<(String, String)>,
        body: Option<String>,
        timeout: Duration,
        on_error: OnError,
        scope: Scope,
        extract: Option<ExtractExpr>,
        client: HttpEnricherClient,
        cache: HttpResponseCache,
    ) -> Self {
        Self {
            id,
            kind,
            inject_field,
            method: method.to_ascii_uppercase(),
            url,
            headers,
            body,
            timeout,
            on_error,
            scope,
            extract,
            client,
            cache,
            metrics: Arc::new(NoopMetrics),
        }
    }

    /// Replace the metrics hook this enricher reports cache events into.
    ///
    /// Pre-registers the three HTTP-cache counter label sets for this
    /// enricher's `id` so `rsigma_enrichment_http_cache_{hits,misses,
    /// expirations}_total{...}` are emitted on `/metrics` from the
    /// first scrape, even before the enricher has run.
    pub fn with_metrics(mut self, metrics: Arc<dyn MetricsHook>) -> Self {
        metrics.register_http_enricher_cache(&self.id);
        self.metrics = metrics;
        self
    }

    /// Read-only view of the response cache. Used by the metrics layer
    /// to expose cache hit/miss/expiration counters.
    pub fn cache(&self) -> &HttpResponseCache {
        &self.cache
    }
}

#[async_trait]
impl Enricher for HttpEnricher {
    fn kind(&self) -> EnricherKind {
        self.kind
    }
    fn id(&self) -> &str {
        &self.id
    }
    fn inject_field(&self) -> &str {
        &self.inject_field
    }
    fn timeout(&self) -> Duration {
        self.timeout
    }
    fn scope(&self) -> &Scope {
        &self.scope
    }
    fn on_error(&self) -> OnError {
        self.on_error
    }

    async fn enrich(&self, result: &mut EvaluationResult) -> Result<(), EnrichError> {
        let url = render_template(&self.url, result);
        let body = self.body.as_ref().map(|b| render_template(b, result));

        let cache_key = CacheKey::new(&self.method, &url, body.as_deref().map(str::as_bytes));
        let (outcome, cached) = self.cache.lookup(&cache_key);
        match outcome {
            CacheOutcome::Hit => self.metrics.on_enrichment_http_cache_hit(&self.id),
            CacheOutcome::Miss => self.metrics.on_enrichment_http_cache_miss(&self.id),
            CacheOutcome::Expired => {
                self.metrics.on_enrichment_http_cache_expiration(&self.id);
                self.metrics.on_enrichment_http_cache_miss(&self.id);
            }
        }
        if let Some(cached_value) = cached {
            let extracted = self.maybe_extract(&cached_value)?;
            inject_enrichment(result, &self.inject_field, extracted);
            return Ok(());
        }

        let mut header_map = HeaderMap::with_capacity(self.headers.len());
        for (name, value_template) in &self.headers {
            let rendered = render_template(value_template, result);
            let header_name = HeaderName::from_bytes(name.as_bytes()).map_err(|e| EnrichError {
                enricher_id: self.id.clone(),
                kind: EnrichErrorKind::Fetch(format!("invalid header name '{name}': {e}")),
            })?;
            let header_value = HeaderValue::from_str(&rendered).map_err(|e| EnrichError {
                enricher_id: self.id.clone(),
                kind: EnrichErrorKind::Fetch(format!("invalid header value for '{name}': {e}")),
            })?;
            header_map.insert(header_name, header_value);
        }

        let method =
            reqwest::Method::from_bytes(self.method.as_bytes()).map_err(|e| EnrichError {
                enricher_id: self.id.clone(),
                kind: EnrichErrorKind::Fetch(format!("invalid method '{}': {e}", self.method)),
            })?;

        let mut req = self
            .client
            .inner()
            .request(method, &url)
            .headers(header_map);
        if let Some(b) = &body {
            req = req.body(b.clone());
        }
        let resp = req.send().await.map_err(|e| EnrichError {
            enricher_id: self.id.clone(),
            kind: if e.is_timeout() {
                EnrichErrorKind::Timeout
            } else {
                EnrichErrorKind::Fetch(format!("{e}"))
            },
        })?;

        let status = resp.status();
        if !status.is_success() {
            return Err(EnrichError {
                enricher_id: self.id.clone(),
                kind: EnrichErrorKind::Fetch(format!("HTTP {status}")),
            });
        }

        let bytes = resp.bytes().await.map_err(|e| EnrichError {
            enricher_id: self.id.clone(),
            kind: EnrichErrorKind::Fetch(format!("body read: {e}")),
        })?;
        let parsed: Value = serde_json::from_slice(&bytes).map_err(|e| EnrichError {
            enricher_id: self.id.clone(),
            kind: EnrichErrorKind::Parse(format!("JSON: {e}")),
        })?;

        // Cache the parsed value before extract: a different enricher
        // sharing the same URL with a different `extract` benefits from
        // the cached upstream JSON.
        self.cache.insert(cache_key, parsed.clone());

        let extracted = self.maybe_extract(&parsed)?;
        inject_enrichment(result, &self.inject_field, extracted);
        Ok(())
    }
}

impl HttpEnricher {
    /// Apply the configured `extract` expression to `value`. Returns the
    /// raw value untouched when no extract is configured.
    fn maybe_extract(&self, value: &Value) -> Result<Value, EnrichError> {
        match &self.extract {
            None => Ok(value.clone()),
            Some(expr) => {
                crate::sources::extract::apply_extract(value, expr).map_err(|e| EnrichError {
                    enricher_id: self.id.clone(),
                    kind: EnrichErrorKind::Extract(format!("{}", e.kind)),
                })
            }
        }
    }
}
