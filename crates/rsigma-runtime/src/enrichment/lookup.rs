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
//!    `Ok`; otherwise return `EnrichErrorKind::Miss("cache miss")` so
//!    the pipeline applies the configured `on_error` policy.
//! 3. **Cache hit** + no extract → inject the cached value verbatim.
//! 4. **Cache hit** + extract:
//!     - `null` extract result → same as "no extract match"; if
//!       `default` is set, inject it; otherwise return
//!       `EnrichErrorKind::Miss(...)` and apply `on_error`.
//!     - extract evaluation failed → return
//!       `EnrichErrorKind::Extract(...)`; the pipeline applies
//!       `on_error`.
//!     - non-null extract result → inject the extracted value.
//!
//! `default` therefore overrides `on_error` for the cache-miss /
//! no-extract-match cases only; outright extractor failures still apply
//! `on_error` (so a malformed extract expression doesn't silently mask
//! data quality issues behind the default value).
//!
//! `${detection.*}` and `${correlation.*}` references in the extract are
//! bound as string values the program reads, never pasted into its text,
//! and the program is compiled once, when the enricher is built.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rsigma_eval::EvaluationResult;
use rsigma_eval::pipeline::sources::ExtractExpr;
use serde_json::Value;

use super::extract::EnricherExtract;
use super::{
    EnrichError, EnrichErrorKind, Enricher, EnricherKind, OnError, Scope, inject_enrichment,
};
use crate::sources::SourceCache;

/// One lookup enricher instance.
pub struct LookupEnricher {
    id: String,
    kind: EnricherKind,
    inject_field: String,
    source_id: String,
    extract: Option<EnricherExtract>,
    default: Option<Value>,
    timeout: Duration,
    on_error: OnError,
    on_miss: OnError,
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
            extract: extract.map(|expr| EnricherExtract::new(&expr, true)),
            default,
            timeout,
            on_error,
            on_miss: on_error,
            scope,
            cache,
        }
    }

    /// Set the policy applied when this enricher finds no data
    /// ([`EnrichErrorKind::Miss`]). Defaults to the `on_error` policy.
    pub fn with_on_miss(mut self, on_miss: OnError) -> Self {
        self.on_miss = on_miss;
        self
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
    fn on_miss(&self) -> OnError {
        self.on_miss
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
                    kind: EnrichErrorKind::Miss(format!(
                        "cache miss for source '{}'",
                        self.source_id
                    )),
                });
            }
        };

        let extracted = match &self.extract {
            None => cached_value,
            Some(extract) => {
                extract
                    .apply(&self.id, cached_value, result, self.timeout)
                    .await?
            }
        };

        if extracted.is_null() {
            if let Some(d) = &self.default {
                inject_enrichment(result, &self.inject_field, d.clone());
                return Ok(());
            }
            return Err(EnrichError {
                enricher_id: self.id.clone(),
                kind: EnrichErrorKind::Miss(format!(
                    "no extract match for source '{}'",
                    self.source_id
                )),
            });
        }
        inject_enrichment(result, &self.inject_field, extracted);
        Ok(())
    }
}
