//! `LookupEnricher`: pull a value from the dynamic-pipelines
//! [`SourceCache`](crate::sources::SourceCache) and inject it (optionally
//! after applying an [`ExtractExpr`] for slicing).
//!
//! Zero-network-cost path for anything already loaded as a dynamic
//! source. The enricher takes a `source_id`, an optional extract
//! expression, and an optional `default` value. The flow is:
//!
//! 1. Look up `source_id` in the shared `Arc<SourceCache>`.
//! 2. **Cache miss** → if `default` is configured, inject it and return
//!    `Ok`; otherwise return `EnrichErrorKind::Fetch("cache miss")` so
//!    the pipeline applies the configured `on_error` policy.
//! 3. **Cache hit** + no extract → inject the cached value verbatim.
//! 4. **Cache hit** + extract:
//!     - `null` extract result → same as "no extract match"; if
//!       `default` is set, inject it; otherwise apply `on_error`.
//!     - extract evaluation failed → return
//!       `EnrichErrorKind::Extract(...)`; the pipeline applies
//!       `on_error`.
//!     - non-null extract result → inject the extracted value.
//!
//! `default` therefore overrides `on_error` for the cache-miss /
//! no-extract-match cases only; outright extractor failures still apply
//! `on_error` (so a malformed extract expression doesn't silently mask
//! data quality issues behind the default value).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rsigma_eval::EvaluationResult;
use rsigma_eval::pipeline::sources::ExtractExpr;
use serde_json::Value;

use super::{
    EnrichError, EnrichErrorKind, Enricher, EnricherKind, OnError, Scope, inject_enrichment,
    template::render_template,
};
use crate::sources::SourceCache;
use crate::sources::extract::apply_extract;

/// One lookup enricher instance.
pub struct LookupEnricher {
    id: String,
    kind: EnricherKind,
    inject_field: String,
    source_id: String,
    extract: Option<ExtractExpr>,
    default: Option<Value>,
    timeout: Duration,
    on_error: OnError,
    scope: Scope,
    cache: Arc<SourceCache>,
}

impl LookupEnricher {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        kind: EnricherKind,
        inject_field: String,
        source_id: String,
        extract: Option<ExtractExpr>,
        default: Option<Value>,
        timeout: Duration,
        on_error: OnError,
        scope: Scope,
        cache: Arc<SourceCache>,
    ) -> Self {
        Self {
            id,
            kind,
            inject_field,
            source_id,
            extract,
            default,
            timeout,
            on_error,
            scope,
            cache,
        }
    }

    /// Render any `${detection.*}` / `${correlation.*}` references inside
    /// the configured extract expression against the current result.
    /// Returns the (possibly cloned) expression with literal text where
    /// templates were.
    fn render_extract(&self, result: &EvaluationResult) -> Option<ExtractExpr> {
        let original = self.extract.as_ref()?;
        let (lang, raw) = match original {
            ExtractExpr::Jq(s) => ("jq", s),
            ExtractExpr::JsonPath(s) => ("jsonpath", s),
            ExtractExpr::Cel(s) => ("cel", s),
        };
        let rendered = render_template(raw, result);
        Some(match lang {
            "jq" => ExtractExpr::Jq(rendered),
            "jsonpath" => ExtractExpr::JsonPath(rendered),
            "cel" => ExtractExpr::Cel(rendered),
            // The match above is exhaustive; keep the arm for the
            // compiler's benefit if `ExtractExpr` ever grows a new
            // variant.
            _ => return None,
        })
    }
}

#[async_trait]
impl Enricher for LookupEnricher {
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
        let cached = self.cache.get(&self.source_id);

        let cached_value = match cached {
            Some(v) => v,
            None => {
                if let Some(d) = &self.default {
                    inject_enrichment(result, &self.inject_field, d.clone());
                    return Ok(());
                }
                return Err(EnrichError {
                    enricher_id: self.id.clone(),
                    kind: EnrichErrorKind::Fetch(format!(
                        "cache miss for source '{}'",
                        self.source_id
                    )),
                });
            }
        };

        let extracted = match self.render_extract(result) {
            None => cached_value.clone(),
            Some(expr) => apply_extract(&cached_value, &expr).map_err(|e| EnrichError {
                enricher_id: self.id.clone(),
                kind: EnrichErrorKind::Extract(format!("{}", e.kind)),
            })?,
        };

        if extracted.is_null() {
            if let Some(d) = &self.default {
                inject_enrichment(result, &self.inject_field, d.clone());
                return Ok(());
            }
            return Err(EnrichError {
                enricher_id: self.id.clone(),
                kind: EnrichErrorKind::Fetch(format!(
                    "no extract match for source '{}'",
                    self.source_id
                )),
            });
        }
        inject_enrichment(result, &self.inject_field, extracted);
        Ok(())
    }
}
