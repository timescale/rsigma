//! Wraps `DefaultSourceResolver` with Prometheus instrumentation.

use std::sync::Arc;
use std::time::Instant;

use rsigma_eval::pipeline::sources::{DynamicSource, SourceType};
use rsigma_runtime::sources::{ResolvedValue, SourceError, SourceResolver};
use tracing::Instrument;

use super::metrics::Metrics;

/// A source resolver that delegates to [`rsigma_runtime::DefaultSourceResolver`]
/// and records Prometheus metrics for each resolution attempt.
pub struct InstrumentedResolver {
    inner: rsigma_runtime::DefaultSourceResolver,
    metrics: Arc<Metrics>,
}

impl InstrumentedResolver {
    pub fn new(metrics: Arc<Metrics>) -> Self {
        Self {
            inner: rsigma_runtime::DefaultSourceResolver::new(),
            metrics,
        }
    }

    /// Access the underlying cache for invalidation operations.
    pub fn cache(&self) -> &rsigma_runtime::sources::cache::SourceCache {
        self.inner.cache()
    }

    /// Borrow the shared `Arc<SourceCache>` so other consumers (the
    /// enrichment pipeline's `lookup` enrichers) can read from the
    /// same cache the resolver writes into.
    pub fn arc_cache(&self) -> std::sync::Arc<rsigma_runtime::sources::cache::SourceCache> {
        self.inner.arc_cache()
    }
}

#[async_trait::async_trait]
impl SourceResolver for InstrumentedResolver {
    async fn resolve(&self, source: &DynamicSource) -> Result<ResolvedValue, SourceError> {
        let source_type_label = source_type_label(&source.source_type);
        self.metrics
            .source_resolves_total
            .with_label_values(&[source.id.as_str(), source_type_label])
            .inc();

        let span = tracing::debug_span!(
            "resolve_source",
            source_id = %source.id,
            source_type = source_type_label,
        );

        // Use Instrument rather than .enter() because the inner resolve can do
        // long-running async work (HTTP, command, file IO); .enter() across
        // .await produces confused span nesting on the multi-threaded runtime.
        async move {
            let start = Instant::now();
            let result = self.inner.resolve(source).await;
            let elapsed = start.elapsed();

            self.metrics
                .source_resolve_latency
                .observe(elapsed.as_secs_f64());

            match &result {
                Ok(value) => {
                    if value.from_cache {
                        self.metrics.source_cache_hits.inc();
                    }
                    self.metrics
                        .source_last_resolved
                        .with_label_values(&[source.id.as_str()])
                        .set(
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs_f64(),
                        );
                    tracing::debug!(
                        cache_hit = value.from_cache,
                        duration_ms = elapsed.as_millis() as u64,
                        "Source resolved",
                    );
                }
                Err(e) => {
                    let error_kind = match &e.kind {
                        rsigma_runtime::SourceErrorKind::Fetch(_) => "Fetch",
                        rsigma_runtime::SourceErrorKind::Parse(_) => "Parse",
                        rsigma_runtime::SourceErrorKind::Extract(_) => "Extract",
                        rsigma_runtime::SourceErrorKind::Timeout => "Timeout",
                        rsigma_runtime::SourceErrorKind::ResourceLimit(_) => "ResourceLimit",
                    };
                    self.metrics
                        .source_resolve_errors
                        .with_label_values(&[source.id.as_str(), error_kind])
                        .inc();
                    tracing::warn!(
                        error_kind,
                        error = %e,
                        duration_ms = elapsed.as_millis() as u64,
                        "Source resolution failed",
                    );
                }
            }

            result
        }
        .instrument(span)
        .await
    }
}

fn source_type_label(st: &SourceType) -> &'static str {
    match st {
        SourceType::File { .. } => "file",
        SourceType::Command { .. } => "command",
        SourceType::Http { .. } => "http",
        SourceType::Nats { .. } => "nats",
    }
}
