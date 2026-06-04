//! Post-evaluation enrichment for the rsigma daemon.
//!
//! Enrichment runs in the daemon's sink task, after `Engine::evaluate()` has
//! produced a [`ProcessResult`](rsigma_eval::ProcessResult) (a flat
//! `Vec<EvaluationResult>`) and before that result is serialized to a sink.
//! Each enricher inspects an [`EvaluationResult`], optionally fetches
//! context (HTTP, command, source cache, pure template), and writes the
//! result into `result.header.enrichments` under a configured
//! `inject_field`.
//!
//! # Architecture
//!
//! A single [`Enricher`] trait covers every primitive (`template`, `lookup`,
//! `http`, `command`) and any bespoke Rust-coded enrichers. Each enricher
//! declares an [`EnricherKind`] at config time; the [`EnrichmentPipeline`]
//! filters results by that declared kind against the
//! [`EvaluationResult::body`] variant before invoking `enrich()`. There are no
//! parallel `DetectionEnricher` / `CorrelationEnricher` traits and no separate
//! context types; enrichers consume `&mut EvaluationResult` directly and
//! match on `result.body` for kind-specific fields.
//!
//! # Concurrency
//!
//! Results within a single sink batch are enriched concurrently with bounded
//! concurrency via a single [`tokio::sync::Semaphore`] owned by the pipeline.
//! Within a single result the enricher chain runs sequentially (so later
//! enrichers can depend on earlier ones via `${detection.enrichments.*}` in a
//! follow-up implementation; for this initial cut the chain is linear and
//! enrichers are independent).
//!
//! # Errors
//!
//! Failures are scoped per enricher and do not abort the chain by default;
//! the per-enricher `on_error` policy ([`OnError`]) decides whether to
//! `skip` the field, inject a JSON `null` for it, or `drop` the entire
//! result before serialization. Timeouts are enforced via
//! [`tokio::time::timeout`] using each enricher's [`Enricher::timeout`].

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rsigma_eval::{EvaluationResult, ResultBody};
use tokio::sync::Semaphore;

use crate::metrics::{MetricsHook, NoopMetrics};

mod command;
mod http;
pub mod http_cache;
mod lookup;
mod scope;
mod template;
#[cfg(test)]
mod tests;

pub use command::{CommandEnricher, OutputFormat};
pub use http::{
    DEFAULT_ENRICHER_MAX_RESPONSE_BYTES, HttpEnricher, HttpEnricherClient,
    build_default_http_client,
};
pub use http_cache::{CacheKey, CacheOutcome, HttpResponseCache};
pub use lookup::LookupEnricher;
pub use scope::Scope;
pub use template::{TemplateEnricher, TemplateError, validate_template_namespace};

/// The kind of [`EvaluationResult`] an [`Enricher`] applies to.
///
/// Fixed at config load. Used for two things:
/// 1. **Template-namespace validation at config load**: a `Detection` enricher
///    may only reference `${detection.*}`; a `Correlation` enricher may only
///    reference `${correlation.*}`. Cross-namespace references fail fast at
///    startup.
/// 2. **Runtime gating in [`EnrichmentPipeline::run`]**: enrichers whose
///    declared kind does not match `result.body`'s variant are skipped before
///    [`Enricher::enrich`] is invoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EnricherKind {
    /// Applies to detection results ([`ResultBody::Detection`]).
    Detection,
    /// Applies to correlation results ([`ResultBody::Correlation`]).
    Correlation,
}

impl EnricherKind {
    /// String label used in metrics, logs, and config errors.
    pub fn as_str(&self) -> &'static str {
        match self {
            EnricherKind::Detection => "detection",
            EnricherKind::Correlation => "correlation",
        }
    }

    /// Returns true if this kind matches the given result body variant.
    pub fn matches(&self, body: &ResultBody) -> bool {
        matches!(
            (self, body),
            (EnricherKind::Detection, ResultBody::Detection(_))
                | (EnricherKind::Correlation, ResultBody::Correlation(_))
        )
    }
}

/// Behavior when an enricher fails (timeout, fetch error, parse error, …).
///
/// Applied per enricher. Defaults to [`OnError::Skip`] so a single failed
/// enrichment never breaks the result stream.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OnError {
    /// Deliver the result unenriched for this field. Default. Logs a warning.
    #[default]
    Skip,
    /// Inject `null` under `inject_field` so downstream consumers see a
    /// "we tried" marker rather than missing-field ambiguity.
    Null,
    /// Suppress the result entirely before serialization. Useful for
    /// dedup / pre-filter style enrichers that intentionally drop matches
    /// based on external context.
    Drop,
}

/// A typed enrichment failure attributed to a specific enricher.
#[derive(Debug, Clone)]
pub struct EnrichError {
    /// Stable ID of the enricher that produced the error.
    pub enricher_id: String,
    /// Categorized failure kind.
    pub kind: EnrichErrorKind,
}

impl std::fmt::Display for EnrichError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "enricher '{}': {}", self.enricher_id, self.kind)
    }
}

impl std::error::Error for EnrichError {}

/// Categorized enrichment failure.
#[derive(Debug, Clone)]
pub enum EnrichErrorKind {
    /// The per-enricher timeout elapsed before [`Enricher::enrich`] returned.
    Timeout,
    /// External fetch failed (HTTP non-2xx, connection refused, command exit
    /// status non-zero, etc.).
    Fetch(String),
    /// External response could not be parsed (e.g. invalid JSON).
    Parse(String),
    /// Extract expression (jq / jsonpath / cel) failed during evaluation.
    Extract(String),
    /// Template rendering failed at runtime (missing variable in a strict
    /// resolver, invalid expansion, …). The config-load-time validator
    /// catches namespace violations earlier.
    TemplateRender(String),
}

impl std::fmt::Display for EnrichErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrichErrorKind::Timeout => write!(f, "timeout"),
            EnrichErrorKind::Fetch(m) => write!(f, "fetch failed: {m}"),
            EnrichErrorKind::Parse(m) => write!(f, "parse failed: {m}"),
            EnrichErrorKind::Extract(m) => write!(f, "extract failed: {m}"),
            EnrichErrorKind::TemplateRender(m) => write!(f, "template render failed: {m}"),
        }
    }
}

/// Trait implemented by every enrichment primitive (`template`, `lookup`,
/// `http`, `command`) and by any bespoke Rust-coded named enricher
/// registered via [`register_builtin`].
///
/// Implementations read shared rule metadata from [`EvaluationResult::header`]
/// and dispatch on `result.body` for kind-specific fields. The pipeline
/// guarantees that `result.body` matches `self.kind()` before calling
/// `enrich()`, so implementations may rely on the matching variant
/// (e.g. via [`EvaluationResult::as_detection`] /
/// [`EvaluationResult::as_correlation`]).
///
/// `enrich` is async to accommodate I/O-bound primitives (HTTP, command).
/// Pure transformations (`template`) still implement `enrich` as `async fn`
/// even though they perform no I/O.
#[async_trait]
pub trait Enricher: Send + Sync {
    /// The kind of result this enricher applies to. Fixed at config load.
    fn kind(&self) -> EnricherKind;

    /// Stable identifier for this enricher instance. Used as a metric label
    /// and in structured log fields. Conventionally something like
    /// `asset_lookup_det` or `enrich_hash_virustotal`.
    fn id(&self) -> &str;

    /// Field name under [`RuleHeader::enrichments`](rsigma_eval::RuleHeader::enrichments)
    /// that this enricher writes to.
    fn inject_field(&self) -> &str;

    /// Per-enricher timeout. The pipeline wraps each `enrich()` call in
    /// [`tokio::time::timeout`] using this value. Defaults to 5 seconds.
    fn timeout(&self) -> Duration {
        Duration::from_secs(5)
    }

    /// Optional scope filter. Applied after the kind-vs-body filter and
    /// before `enrich()` runs. Default is [`Scope::default`] (always fires).
    fn scope(&self) -> &Scope;

    /// Behavior when this enricher fails (timeout, fetch error, …).
    /// Defaults to [`OnError::Skip`].
    fn on_error(&self) -> OnError {
        OnError::Skip
    }

    /// Run the enrichment.
    ///
    /// Implementations write into [`RuleHeader::enrichments`](rsigma_eval::RuleHeader::enrichments)
    /// under the configured [`Self::inject_field`]. The pipeline initializes
    /// the map (`None` → `Some(empty)`) before invoking the first enricher
    /// for a given result, so implementations can `unwrap` the map safely.
    async fn enrich(&self, result: &mut EvaluationResult) -> Result<(), EnrichError>;
}

/// Outcome of running a single enricher against a single result.
///
/// Returned internally by [`EnrichmentPipeline::run_one`] so the pipeline
/// driver can decide whether to drop the entire result, log, or continue.
enum EnrichOutcome {
    /// Enricher ran and (possibly) wrote into `enrichments`.
    Ok,
    /// Enricher errored or timed out and `on_error: skip` applied.
    Skip,
    /// Enricher errored or timed out and `on_error: null` applied; the
    /// pipeline injected `null` under `inject_field`.
    Null,
    /// Enricher errored or timed out and `on_error: drop` applied; the
    /// pipeline must remove this result from the output vec.
    Drop,
    /// Enricher was filtered out (kind or scope mismatch) before running.
    Filtered,
}

/// Execution surface for a configured set of enrichers.
///
/// One pipeline owns one `Vec<Box<dyn Enricher>>` plus a shared
/// [`Semaphore`] that bounds the number of in-flight enrichments across
/// all results in a batch.
///
/// The pipeline is constructed by the daemon config layer
/// (`crates/rsigma-cli/src/daemon/enrichment/config.rs`) and held inside
/// the daemon's sink task. Each [`ProcessResult`](rsigma_eval::ProcessResult)
/// (a `Vec<EvaluationResult>`) flows through [`EnrichmentPipeline::run`]
/// before it is serialized.
pub struct EnrichmentPipeline {
    enrichers: Vec<Box<dyn Enricher>>,
    semaphore: Arc<Semaphore>,
    metrics: Arc<dyn MetricsHook>,
}

impl std::fmt::Debug for EnrichmentPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrichmentPipeline")
            .field("enrichers", &self.enrichers.len())
            .field("permits", &self.semaphore.available_permits())
            .finish()
    }
}

impl EnrichmentPipeline {
    /// Build a pipeline from a list of configured enrichers.
    ///
    /// `max_concurrent_enrichments` bounds the number of results that can
    /// be enriched in parallel; defaults to 16 if zero is passed.
    /// Metrics default to a no-op sink; call [`Self::with_metrics`] to
    /// route counters and latency histograms into a real
    /// [`MetricsHook`] implementation.
    pub fn new(enrichers: Vec<Box<dyn Enricher>>, max_concurrent_enrichments: usize) -> Self {
        let permits = if max_concurrent_enrichments == 0 {
            16
        } else {
            max_concurrent_enrichments
        };
        Self {
            enrichers,
            semaphore: Arc::new(Semaphore::new(permits)),
            metrics: Arc::new(NoopMetrics),
        }
    }

    /// Replace the metrics hook this pipeline reports into. The daemon
    /// passes its Prometheus-backed `Metrics` here; library consumers
    /// can pass any [`MetricsHook`] implementation.
    ///
    /// Pre-registers `(enricher_id, kind)` for every configured
    /// enricher so `rsigma_enrichment_total{...}` and
    /// `rsigma_enrichment_duration_seconds{...}` are emitted on
    /// `/metrics` from the first scrape, even before any enricher has
    /// fired.
    pub fn with_metrics(mut self, metrics: Arc<dyn MetricsHook>) -> Self {
        for enricher in &self.enrichers {
            metrics.register_enricher(enricher.id(), enricher.kind().as_str());
        }
        self.metrics = metrics;
        self
    }

    /// Returns true if no enrichers are configured.
    ///
    /// The daemon sink task uses this to skip enrichment work entirely
    /// (no permit acquisition, no per-result loop) when no enrichers are
    /// configured.
    pub fn is_empty(&self) -> bool {
        self.enrichers.is_empty()
    }

    /// Number of configured enrichers (across both kinds).
    pub fn len(&self) -> usize {
        self.enrichers.len()
    }

    /// Iterate over the configured enrichers (read-only view, used for
    /// reload-diff logging and tests).
    pub fn enrichers(&self) -> impl Iterator<Item = &dyn Enricher> {
        self.enrichers.iter().map(|e| &**e)
    }

    /// Run every applicable enricher against each result in `results`.
    ///
    /// For each result the pipeline:
    /// 1. Acquires a global semaphore permit (bounded concurrency).
    /// 2. Iterates the configured enricher list.
    /// 3. Skips enrichers whose [`EnricherKind`] does not match the
    ///    result's body variant.
    /// 4. Skips enrichers whose [`Scope`] excludes this result.
    /// 5. Wraps each remaining `enrich()` call in
    ///    [`tokio::time::timeout`] using the enricher's timeout.
    /// 6. On error, applies the enricher's [`OnError`] policy.
    /// 7. If any enricher in the chain returns the internal `Drop`
    ///    outcome (via an enricher whose [`OnError`] policy is set
    ///    to [`OnError::Drop`]), the result is removed from the
    ///    output.
    ///
    /// The pipeline initializes `result.header.enrichments` to
    /// `Some(empty)` lazily on first successful injection, so the
    /// `skip_serializing_if = "Option::is_none"` contract on
    /// `RuleHeader::enrichments` is preserved when no enricher writes.
    ///
    /// Currently sequential per result; concurrent across results would
    /// require splitting `results` into chunks across futures and is left
    /// for a follow-up tuning pass once we have realistic throughput
    /// numbers from the integration tests.
    pub async fn run(&self, results: &mut Vec<EvaluationResult>) {
        if self.enrichers.is_empty() || results.is_empty() {
            return;
        }

        // Single-pass enrichment with drop bookkeeping.
        //
        // We cannot use `Vec::retain_mut` together with `.await` (the
        // closure must be sync), so we collect drop indices first and
        // apply them in a single linear pass at the end.
        let mut drop_indices: Vec<usize> = Vec::new();

        for (idx, result) in results.iter_mut().enumerate() {
            let permit = self.semaphore.clone().acquire_owned().await.ok();
            if permit.is_none() {
                // Semaphore closed (only happens at shutdown). Drain
                // remaining results unenriched rather than blocking.
                tracing::debug!("Enrichment semaphore closed, draining remaining results");
                return;
            }
            let _permit = permit.unwrap();

            let mut should_drop = false;
            for enricher in &self.enrichers {
                match Self::run_one(enricher.as_ref(), result, self.metrics.as_ref()).await {
                    EnrichOutcome::Drop => {
                        should_drop = true;
                        break;
                    }
                    EnrichOutcome::Ok
                    | EnrichOutcome::Skip
                    | EnrichOutcome::Null
                    | EnrichOutcome::Filtered => {}
                }
            }
            if should_drop {
                drop_indices.push(idx);
            }
        }

        if !drop_indices.is_empty() {
            // Remove from the back so earlier indices stay valid.
            for idx in drop_indices.into_iter().rev() {
                results.swap_remove(idx);
            }
        }
    }

    /// Run a single enricher against a single result, applying the
    /// kind-vs-body filter, scope filter, timeout, and on_error policy.
    /// Records `rsigma_enrichment_total{enricher_id, kind, status}` and
    /// `rsigma_enrichment_duration_seconds{enricher_id, kind}` via the
    /// configured `MetricsHook` for every non-filtered call.
    async fn run_one(
        enricher: &dyn Enricher,
        result: &mut EvaluationResult,
        metrics: &dyn MetricsHook,
    ) -> EnrichOutcome {
        if !enricher.kind().matches(&result.body) {
            return EnrichOutcome::Filtered;
        }
        if !enricher.scope().matches(result) {
            return EnrichOutcome::Filtered;
        }

        let inject_field = enricher.inject_field().to_string();
        let timeout = enricher.timeout();
        let id = enricher.id().to_string();
        let kind_label = enricher.kind().as_str();
        let on_error = enricher.on_error();

        metrics.on_enrichment_queue_depth_change(1);
        let started = std::time::Instant::now();
        let outcome = tokio::time::timeout(timeout, enricher.enrich(result)).await;
        let elapsed = started.elapsed().as_secs_f64();
        metrics.on_enrichment_queue_depth_change(-1);

        let err = match outcome {
            Ok(Ok(())) => {
                metrics.on_enrichment_completed(&id, kind_label, "success", elapsed);
                return EnrichOutcome::Ok;
            }
            Ok(Err(e)) => e,
            Err(_) => EnrichError {
                enricher_id: id.clone(),
                kind: EnrichErrorKind::Timeout,
            },
        };

        let is_timeout = matches!(err.kind, EnrichErrorKind::Timeout);
        match on_error {
            OnError::Skip => {
                tracing::warn!(
                    enricher_id = %id,
                    kind = %kind_label,
                    error = %err,
                    "Enricher failed, skipping"
                );
                metrics.on_enrichment_completed(
                    &id,
                    kind_label,
                    if is_timeout { "timeout" } else { "skip" },
                    elapsed,
                );
                EnrichOutcome::Skip
            }
            OnError::Null => {
                tracing::warn!(
                    enricher_id = %id,
                    kind = %kind_label,
                    error = %err,
                    "Enricher failed, injecting null"
                );
                let map = result
                    .header
                    .enrichments
                    .get_or_insert_with(serde_json::Map::new);
                map.insert(inject_field, serde_json::Value::Null);
                metrics.on_enrichment_completed(
                    &id,
                    kind_label,
                    if is_timeout { "timeout" } else { "error" },
                    elapsed,
                );
                EnrichOutcome::Null
            }
            OnError::Drop => {
                tracing::warn!(
                    enricher_id = %id,
                    kind = %kind_label,
                    error = %err,
                    "Enricher failed, dropping result"
                );
                metrics.on_enrichment_completed(&id, kind_label, "drop", elapsed);
                EnrichOutcome::Drop
            }
        }
    }
}

impl Default for EnrichmentPipeline {
    fn default() -> Self {
        Self::new(Vec::new(), 16)
    }
}

impl Clone for EnrichmentPipeline {
    fn clone(&self) -> Self {
        // Boxes of `dyn Enricher` are not `Clone`, so a true deep clone
        // is not possible here. The hot-reload path always rebuilds the
        // pipeline from config rather than cloning, but `Clone` is
        // useful for tests and for `ArcSwap` adapter code that wants a
        // throwaway snapshot. Returning an empty pipeline that shares
        // the metrics hook is the safest behaviour: a misuse degrades
        // to "no enrichment" rather than panicking or silently
        // double-counting.
        Self {
            enrichers: Vec::new(),
            semaphore: Arc::clone(&self.semaphore),
            metrics: Arc::clone(&self.metrics),
        }
    }
}

/// Helper for [`Enricher::enrich`] implementations: write `value` into
/// `result.header.enrichments` under `inject_field`, allocating the map
/// if it was previously `None`.
pub fn inject_enrichment(
    result: &mut EvaluationResult,
    inject_field: &str,
    value: serde_json::Value,
) {
    let map = result
        .header
        .enrichments
        .get_or_insert_with(serde_json::Map::new);
    map.insert(inject_field.to_string(), value);
}

// ---------------------------------------------------------------------------
// Bespoke enricher registration
// ---------------------------------------------------------------------------

/// Factory function signature used by [`register_builtin`].
///
/// External crates that ship a bespoke enricher type register a
/// `Box<dyn Fn(&serde_json::Value) -> Result<Box<dyn Enricher>, String>>`
/// so the daemon config layer can construct the enricher from its YAML
/// config block at startup. The `serde_json::Value` argument is the raw
/// enricher-config block (after `kind` / `id` / `type` fields are
/// extracted by the loader).
pub type EnricherFactory =
    Arc<dyn Fn(&serde_json::Value) -> Result<Box<dyn Enricher>, String> + Send + Sync>;

/// Process-wide registry of bespoke enricher factories keyed by `type`.
///
/// External crates call [`register_builtin`] once at startup (typically
/// in their `lib.rs` via `ctor` or an explicit init function) to wire a
/// new `type: <name>` value into the daemon's config loader. Generic
/// primitives (`template`, `lookup`, `http`, `command`) are not in this
/// registry; they are constructed directly by the loader.
///
/// The registry is global and append-only — registering the same name
/// twice is an error. Concurrent reads are lock-free via [`std::sync::OnceLock`]
/// at the outer level and a [`std::sync::RwLock`] at the inner level for the
/// (rare) `register_builtin` writes.
fn registry() -> &'static std::sync::RwLock<std::collections::HashMap<String, EnricherFactory>> {
    use std::sync::OnceLock;
    static REGISTRY: OnceLock<
        std::sync::RwLock<std::collections::HashMap<String, EnricherFactory>>,
    > = OnceLock::new();
    REGISTRY.get_or_init(|| std::sync::RwLock::new(std::collections::HashMap::new()))
}

/// Register a bespoke enricher factory under `type: <name>`.
///
/// Returns an error if `name` is already registered (registration is
/// process-global and append-only) or if `name` collides with a built-in
/// primitive type (`template`, `lookup`, `http`, `command`).
///
/// External crates call this once at startup before the daemon loads its
/// config. After config load, the registry is read-only in practice.
pub fn register_builtin(name: &str, factory: EnricherFactory) -> Result<(), String> {
    if matches!(name, "template" | "lookup" | "http" | "command") {
        return Err(format!(
            "cannot register '{name}': name is reserved for a built-in primitive"
        ));
    }
    let reg = registry();
    let mut guard = reg
        .write()
        .map_err(|_| "enricher registry poisoned".to_string())?;
    if guard.contains_key(name) {
        return Err(format!("enricher type '{name}' is already registered"));
    }
    guard.insert(name.to_string(), factory);
    Ok(())
}

/// Look up a registered bespoke enricher factory by `type` name.
///
/// Returns `None` if `name` is not registered. The daemon config loader
/// uses this to construct bespoke enrichers; missing names are surfaced
/// to the operator as a clear startup error.
pub fn lookup_builtin(name: &str) -> Option<EnricherFactory> {
    let reg = registry();
    let guard = reg.read().ok()?;
    guard.get(name).cloned()
}

/// Clear the bespoke enricher registry. **Test-only**: used by unit tests
/// that need to register / re-register the same name. Not exposed to
/// downstream crates.
#[cfg(test)]
pub(crate) fn clear_builtin_registry() {
    if let Ok(mut guard) = registry().write() {
        guard.clear();
    }
}
