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
//! `http`, `command`, `stix` when `stix-enrich` is enabled, `mmdb` when
//! `mmdb-enrich` is enabled, and `dns` when `dns-enrich` is enabled) and any
//! bespoke Rust-coded enrichers. Each enricher
//! declares an [`EnricherKind`] at config time; the [`EnrichmentPipeline`]
//! filters results by that declared kind against the
//! [`EvaluationResult::body`] variant before invoking `enrich()`. There are no
//! parallel `DetectionEnricher` / `CorrelationEnricher` traits and no separate
//! context types; enrichers consume `&mut EvaluationResult` directly and
//! match on `result.body` for kind-specific fields.
//!
//! # Concurrency
//!
//! Results are enriched concurrently, within a batch and across concurrent
//! [`EnrichmentPipeline::run`] calls, bounded by one [`tokio::sync::Semaphore`]
//! owned by the pipeline (`max_concurrent_enrichments` permits, one per result
//! being enriched). Within a single result the enricher chain runs in order.
//! Output order is preserved.
//!
//! # Shared requests and the failure cache
//!
//! An enricher that names a [`request_key`](Enricher::request_key) for a
//! result makes each distinct request once at a time: results whose request
//! is already in flight wait for it and take its outcome. When the request
//! times out or fails to fetch, the pipeline also remembers the failure for
//! that enricher and key for the failure cache TTL (60 seconds by default)
//! and applies it to later results with the same key without calling the
//! enricher, so a dead upstream costs one timeout per key instead of one per
//! detection.
//!
//! # Errors
//!
//! Failures are scoped per enricher and do not abort the chain by default;
//! the per-enricher `on_error` policy ([`OnError`]) decides whether to
//! `skip` the field, inject a JSON `null` for it, or `drop` the entire
//! result before serialization. Timeouts are enforced via
//! [`tokio::time::timeout`] using each enricher's [`Enricher::timeout`].
//!
//! A miss ([`EnrichErrorKind::Miss`]) applies the separate `on_miss` policy
//! ([`Enricher::on_miss`]), which falls back to `on_error`, and reports
//! `status="miss"` unless it drops the result.
//!
//! A miss logs at debug level. Every other failure logs a warning at most
//! once per 10 seconds per enricher id; the next warning carries a
//! `suppressed` count of the failures in between.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use parking_lot::Mutex;
use rsigma_eval::{EvaluationResult, ResultBody};
use tokio::sync::Semaphore;

use crate::log_throttle::WarnThrottle;
use crate::metrics::{MetricsHook, NoopMetrics};

mod command;
mod command_argv;
pub mod config;
#[cfg(feature = "dns-enrich")]
mod dns;
mod extract;
mod http;
pub mod http_cache;
mod lookup;
#[cfg(feature = "mmdb-enrich")]
mod mmdb;
#[cfg(feature = "stix-enrich")]
mod stix;
mod template;
#[cfg(test)]
mod tests;

pub use crate::scope::Scope;
pub use command::{CommandEnricher, OutputFormat};
#[cfg(feature = "dns-enrich")]
pub use dns::{DnsEnricher, DnsRecordType, DnsResolverConfig, SUPPORTED_DNS_RECORD_TYPES};
pub(crate) use http::validate_header_names;
pub use http::{
    DEFAULT_ENRICHER_MAX_RESPONSE_BYTES, HttpEnricher, HttpEnricherClient,
    build_default_http_client,
};
pub use http_cache::{CacheKey, CacheOutcome, HttpResponseCache};
pub use lookup::LookupEnricher;
#[cfg(feature = "mmdb-enrich")]
pub use mmdb::{MmdbDatabase, MmdbEnricher, MmdbFields, MmdbLookupError};
#[cfg(feature = "stix-enrich")]
pub use stix::{StixEnricher, StixEnricherQuery};
#[cfg(any(feature = "mmdb-enrich", feature = "dns-enrich", test))]
pub(crate) use template::empty_key_message;
pub use template::{
    TemplateEnricher, TemplateError, env_references, render_template, render_template_json,
    render_template_url, render_webhook_body, validate_template_namespace,
    validate_url_tenant_position,
};
pub(crate) use template::{
    references_detection_payload, render_enricher_template, render_enricher_template_json,
    render_enricher_template_url, render_template_json_with_ocsf, sanitize_header_value,
    validate_webhook_body_template,
};

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
    /// Deliver the result unenriched for this field. Default.
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
#[non_exhaustive]
pub enum EnrichErrorKind {
    /// The lookup ran and found no data for this key (no MMDB record, no DNS
    /// records, a source cache miss, an extract that matched nothing, …).
    /// Returned only when no `default` is configured.
    Miss(String),
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
            EnrichErrorKind::Miss(m) => write!(f, "no match: {m}"),
            EnrichErrorKind::Timeout => write!(f, "timeout"),
            EnrichErrorKind::Fetch(m) => write!(f, "fetch failed: {m}"),
            EnrichErrorKind::Parse(m) => write!(f, "parse failed: {m}"),
            EnrichErrorKind::Extract(m) => write!(f, "extract failed: {m}"),
            EnrichErrorKind::TemplateRender(m) => write!(f, "template render failed: {m}"),
        }
    }
}

/// Trait implemented by every enrichment primitive (`template`, `lookup`,
/// `http`, `command`, `stix`, `mmdb`, `dns`) and by any bespoke Rust-coded named
/// enricher registered via [`register_builtin`].
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

    /// Behavior when this enricher finds no data for a result (it returned
    /// [`EnrichErrorKind::Miss`]). Defaults to [`Self::on_error`].
    fn on_miss(&self) -> OnError {
        self.on_error()
    }

    /// The identity of the external call this enricher would make for
    /// `result` (for example the rendered URL, DNS name, or command line), or
    /// `None` when the enricher does no external I/O.
    ///
    /// Two results with the same key must get the same outcome: the same
    /// value under [`Self::inject_field`] or the same error. When this returns
    /// `Some`, a result whose request is already in flight takes that call's
    /// outcome instead of making it again, and a timeout or fetch failure is
    /// remembered for the pipeline's failure cache TTL so later results with
    /// the same key fail the same way without a call. Defaults to `None`.
    fn request_key(&self, _result: &EvaluationResult) -> Option<String> {
        None
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
    /// Enricher missed, errored, or timed out and a `skip` policy applied.
    Skip,
    /// Enricher missed, errored, or timed out and a `null` policy applied;
    /// the pipeline injected `null` under `inject_field`.
    Null,
    /// Enricher missed, errored, or timed out and a `drop` policy applied;
    /// the pipeline must remove this result from the output vec.
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
    max_concurrent: usize,
    metrics: Arc<dyn MetricsHook>,
    needs_event: bool,
    failure_logs: Arc<FailureLogs>,
    failure_cache: Option<Arc<FailureCache>>,
    in_flight: Arc<InFlight>,
}

/// What a finished call produced for its request: the value written under
/// `inject_field` (if any), or the failure.
type SharedOutcome = Result<Option<serde_json::Value>, EnrichErrorKind>;

/// Calls in progress, keyed like [`FailureCache`]. A result whose request is
/// already being made waits for that call and takes its outcome instead of
/// making the same call again.
#[derive(Default)]
struct InFlight {
    calls: Mutex<HashMap<[u8; 32], tokio::sync::watch::Receiver<Option<SharedOutcome>>>>,
}

enum Flight {
    /// This result makes the call and publishes the outcome.
    Leader(FlightGuard),
    /// Another result is making the call.
    Follower(tokio::sync::watch::Receiver<Option<SharedOutcome>>),
}

impl InFlight {
    fn join(self: &Arc<Self>, key: [u8; 32]) -> Flight {
        let mut calls = self.calls.lock();
        if let Some(rx) = calls.get(&key) {
            return Flight::Follower(rx.clone());
        }
        let (tx, rx) = tokio::sync::watch::channel(None);
        calls.insert(key, rx);
        Flight::Leader(FlightGuard {
            in_flight: Arc::clone(self),
            key,
            tx,
        })
    }
}

/// Removes the in-flight entry when the leading call ends, whether it
/// published an outcome or was cancelled.
struct FlightGuard {
    in_flight: Arc<InFlight>,
    key: [u8; 32],
    tx: tokio::sync::watch::Sender<Option<SharedOutcome>>,
}

impl FlightGuard {
    fn publish(self, outcome: SharedOutcome) {
        self.tx.send_replace(Some(outcome));
    }
}

impl Drop for FlightGuard {
    fn drop(&mut self) {
        let mut calls = self.in_flight.calls.lock();
        if calls
            .get(&self.key)
            .is_some_and(|rx| rx.same_channel(&self.tx.subscribe()))
        {
            calls.remove(&self.key);
        }
    }
}

/// Wait for the leading call's outcome. `None` when the leader went away
/// without one, in which case the caller makes the call itself.
async fn wait_for_leader(
    mut rx: tokio::sync::watch::Receiver<Option<SharedOutcome>>,
) -> Option<SharedOutcome> {
    loop {
        if let Some(outcome) = rx.borrow_and_update().clone() {
            return Some(outcome);
        }
        if rx.changed().await.is_err() {
            return rx.borrow().clone();
        }
    }
}

/// Default for [`EnrichmentPipeline::with_failure_cache_ttl`].
pub const DEFAULT_FAILURE_CACHE_TTL: Duration = Duration::from_secs(60);

/// Most failures the cache remembers at once. Past this, new failures are
/// not cached until old ones expire.
const MAX_FAILURE_CACHE_ENTRIES: usize = 10_000;

/// Recent timeouts and fetch failures, keyed by a digest of the enricher id
/// and its [`Enricher::request_key`].
struct FailureCache {
    ttl: Duration,
    entries: Mutex<HashMap<[u8; 32], (Instant, EnrichErrorKind)>>,
}

impl FailureCache {
    fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn digest(enricher_id: &str, key: &str) -> [u8; 32] {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(enricher_id.as_bytes());
        hasher.update([0]);
        hasher.update(key.as_bytes());
        hasher.finalize().into()
    }

    /// The cached failure for `key`, if it has not expired.
    fn get(&self, key: &[u8; 32], now: Instant) -> Option<EnrichErrorKind> {
        let mut entries = self.entries.lock();
        match entries.get(key) {
            Some((expires, kind)) if *expires > now => Some(kind.clone()),
            Some(_) => {
                entries.remove(key);
                None
            }
            None => None,
        }
    }

    fn insert(&self, key: [u8; 32], kind: EnrichErrorKind, now: Instant) {
        let mut entries = self.entries.lock();
        if entries.len() >= MAX_FAILURE_CACHE_ENTRIES {
            entries.retain(|_, (expires, _)| *expires > now);
            if entries.len() >= MAX_FAILURE_CACHE_ENTRIES {
                return;
            }
        }
        entries.insert(key, (now + self.ttl, kind));
    }
}

/// Rate limits the failure warnings of each enricher id.
#[derive(Default)]
struct FailureLogs {
    throttles: Mutex<HashMap<String, WarnThrottle>>,
}

impl FailureLogs {
    /// Count one failure of `enricher_id`. Returns the failures the warning
    /// should cover, or `None` when the warning is deferred.
    fn record(&self, enricher_id: &str, now: Instant) -> Option<u64> {
        let mut throttles = self.throttles.lock();
        match throttles.get_mut(enricher_id) {
            Some(throttle) => throttle.record(now),
            None => throttles
                .entry(enricher_id.to_string())
                .or_default()
                .record(now),
        }
    }
}

impl Drop for FailureLogs {
    fn drop(&mut self) {
        for (enricher_id, throttle) in self.throttles.get_mut().iter_mut() {
            let suppressed = throttle.take_pending();
            if suppressed > 0 {
                tracing::warn!(
                    enricher_id = %enricher_id,
                    suppressed,
                    "Enricher failures suppressed since the last warning"
                );
            }
        }
    }
}

impl std::fmt::Debug for EnrichmentPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrichmentPipeline")
            .field("enrichers", &self.enrichers.len())
            .field("permits", &self.semaphore.available_permits())
            .field("max_concurrent", &self.max_concurrent)
            .field("needs_event", &self.needs_event)
            .field(
                "failure_cache_ttl",
                &self.failure_cache.as_ref().map(|c| c.ttl),
            )
            .finish()
    }
}

impl EnrichmentPipeline {
    /// Build a pipeline from a list of configured enrichers.
    ///
    /// `max_concurrent_enrichments` bounds the number of results that can
    /// be enriched in parallel; defaults to 16 if zero is passed. The
    /// failure cache starts at [`DEFAULT_FAILURE_CACHE_TTL`].
    /// Metrics default to a no-op sink; call [`Self::with_metrics`] to
    /// route counters and latency histograms into a real
    /// [`MetricsHook`] implementation.
    ///
    /// A pipeline built here reports [`needs_event`](Self::needs_event) as
    /// `false`, because the boxed enrichers do not expose their templates.
    pub fn new(enrichers: Vec<Box<dyn Enricher>>, max_concurrent_enrichments: usize) -> Self {
        let permits = if max_concurrent_enrichments == 0 {
            16
        } else {
            max_concurrent_enrichments
        };
        Self {
            enrichers,
            semaphore: Arc::new(Semaphore::new(permits)),
            max_concurrent: permits,
            metrics: Arc::new(NoopMetrics),
            needs_event: false,
            failure_logs: Arc::default(),
            failure_cache: Some(Arc::new(FailureCache::new(DEFAULT_FAILURE_CACHE_TTL))),
            in_flight: Arc::default(),
        }
    }

    /// How long a timeout or fetch failure is remembered per enricher and
    /// [`request_key`](Enricher::request_key). Zero turns the
    /// failure cache off.
    pub fn with_failure_cache_ttl(mut self, ttl: Duration) -> Self {
        self.failure_cache = (!ttl.is_zero()).then(|| Arc::new(FailureCache::new(ttl)));
        self
    }

    /// The number of results this pipeline enriches at once.
    pub fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }

    /// Whether any configured enricher reads a detection payload that the
    /// engine must retain on the result.
    ///
    /// True when a rendered template references `${detection.fields.*}`,
    /// `${detection.event.*}`, or bare `${detection.event}`. Those references
    /// resolve only when the engine retains the event on the result.
    ///
    /// A caller that builds its own engine passes this to
    /// [`RuntimeEngine::set_include_event`](crate::RuntimeEngine::set_include_event)
    /// (or [`LogProcessor::set_include_event`](crate::LogProcessor::set_include_event)),
    /// and, unless it wants events delivered, removes them after
    /// [`run`](Self::run) with
    /// [`strip_auto_retained_event`](crate::strip_auto_retained_event).
    ///
    /// Only [`build_enrichers`](crate::build_enrichers) and
    /// [`build_enrichers_full`](crate::build_enrichers_full) compute this
    /// flag, from each entry's
    /// [`rendered_fields`](crate::EnricherConfig::rendered_fields). A pipeline
    /// assembled with [`new`](Self::new) always reports `false`, so a caller
    /// whose hand-built enrichers render those references turns retention on
    /// itself with `set_include_event(true)`.
    pub fn needs_event(&self) -> bool {
        self.needs_event
    }

    pub(crate) fn set_needs_event(&mut self, needs_event: bool) {
        self.needs_event = needs_event;
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
    /// Results are enriched concurrently. For each result the pipeline:
    /// 1. Acquires a semaphore permit (bounded concurrency shared by every
    ///    `run` call on this pipeline).
    /// 2. Iterates the configured enricher list in order.
    /// 3. Skips enrichers whose [`EnricherKind`] does not match the
    ///    result's body variant.
    /// 4. Skips enrichers whose [`Scope`] excludes this result.
    /// 5. Applies a cached failure for the enricher's
    ///    [`request_key`](Enricher::request_key) without calling
    ///    it, or wraps the `enrich()` call in [`tokio::time::timeout`] using
    ///    the enricher's timeout.
    /// 6. On a miss, applies the enricher's [`Enricher::on_miss`] policy, and
    ///    on any other error its [`Enricher::on_error`] policy.
    /// 7. If any enricher in the chain returns the internal `Drop`
    ///    outcome (via an enricher whose [`OnError`] policy is set
    ///    to [`OnError::Drop`]), the result is removed from the
    ///    output.
    ///
    /// The surviving results keep their order. The pipeline initializes
    /// `result.header.enrichments` to `Some(empty)` lazily on first
    /// successful injection, so the `skip_serializing_if = "Option::is_none"`
    /// contract on `RuleHeader::enrichments` is preserved when no enricher
    /// writes.
    pub async fn run(&self, results: &mut Vec<EvaluationResult>) {
        if self.enrichers.is_empty() || results.is_empty() {
            return;
        }

        // A fixed set of workers pulls results from a shared queue, so a slow
        // result holds up only its own worker and the batch costs no
        // allocation per result.
        let workers = self.max_concurrent.min(results.len());
        let queue = Mutex::new(results.iter_mut().enumerate());
        let dropped = futures_util::future::join_all((0..workers).map(|_| async {
            let mut dropped = Vec::new();
            loop {
                let Some((idx, result)) = queue.lock().next() else {
                    break;
                };
                if self.enrich_one(result).await {
                    dropped.push(idx);
                }
            }
            dropped
        }))
        .await;
        let mut dropped: Vec<usize> = dropped.into_iter().flatten().collect();
        if !dropped.is_empty() {
            dropped.sort_unstable();
            let mut next = dropped.into_iter().peekable();
            let mut idx = 0;
            results.retain(|_| {
                let keep = next.peek() != Some(&idx);
                if !keep {
                    next.next();
                }
                idx += 1;
                keep
            });
        }
    }

    /// Run the enricher chain on one result. Returns true when the result
    /// must be dropped.
    async fn enrich_one(&self, result: &mut EvaluationResult) -> bool {
        let Ok(_permit) = self.semaphore.acquire().await else {
            tracing::debug!("Enrichment semaphore closed, delivering the result unenriched");
            return false;
        };
        for enricher in &self.enrichers {
            if let EnrichOutcome::Drop = self.run_one(enricher.as_ref(), result).await {
                return true;
            }
        }
        false
    }

    /// Run a single enricher against a single result, applying the
    /// kind-vs-body filter, scope filter, timeout, and on_miss or on_error
    /// policy.
    /// Records `rsigma_enrichment_total{enricher_id, kind, status}` and
    /// `rsigma_enrichment_duration_seconds{enricher_id, kind}` via the
    /// configured `MetricsHook` for every non-filtered call.
    async fn run_one(
        &self,
        enricher: &dyn Enricher,
        result: &mut EvaluationResult,
    ) -> EnrichOutcome {
        let metrics = self.metrics.as_ref();
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

        let request = enricher
            .request_key(result)
            .map(|key| FailureCache::digest(&id, &key));
        let started = Instant::now();
        let mut leader = None;
        let mut answered = None;
        if let Some(key) = request {
            answered = self
                .failure_cache
                .as_ref()
                .and_then(|cache| cache.get(&key, started))
                .map(Err);
            if answered.is_none() {
                match self.in_flight.join(key) {
                    Flight::Leader(guard) => leader = Some(guard),
                    Flight::Follower(rx) => answered = wait_for_leader(rx).await,
                }
            }
        }

        let (err, elapsed) = match answered {
            Some(Ok(value)) => {
                metrics.on_enrichment_short_circuit(&id);
                if let Some(value) = value {
                    inject_enrichment(result, &inject_field, value);
                }
                let elapsed = started.elapsed().as_secs_f64();
                metrics.on_enrichment_completed(&id, kind_label, "success", elapsed);
                return EnrichOutcome::Ok;
            }
            Some(Err(kind)) => {
                metrics.on_enrichment_short_circuit(&id);
                let err = EnrichError {
                    enricher_id: id.clone(),
                    kind,
                };
                (err, started.elapsed().as_secs_f64())
            }
            None => {
                metrics.on_enrichment_queue_depth_change(1);
                let outcome = tokio::time::timeout(timeout, enricher.enrich(result)).await;
                let elapsed = started.elapsed().as_secs_f64();
                metrics.on_enrichment_queue_depth_change(-1);

                let err = match outcome {
                    Ok(Ok(())) => {
                        if let Some(leader) = leader {
                            let injected = result
                                .header
                                .enrichments
                                .as_ref()
                                .and_then(|map| map.get(&inject_field))
                                .cloned();
                            leader.publish(Ok(injected));
                        }
                        metrics.on_enrichment_completed(&id, kind_label, "success", elapsed);
                        return EnrichOutcome::Ok;
                    }
                    Ok(Err(e)) => e,
                    Err(_) => EnrichError {
                        enricher_id: id.clone(),
                        kind: EnrichErrorKind::Timeout,
                    },
                };
                if let (Some(key), Some(cache)) = (request, &self.failure_cache)
                    && matches!(
                        err.kind,
                        EnrichErrorKind::Timeout | EnrichErrorKind::Fetch(_)
                    )
                {
                    cache.insert(key, err.kind.clone(), Instant::now());
                }
                if let Some(leader) = leader {
                    leader.publish(Err(err.kind.clone()));
                }
                (err, elapsed)
            }
        };

        let is_timeout = matches!(err.kind, EnrichErrorKind::Timeout);
        let is_miss = matches!(err.kind, EnrichErrorKind::Miss(_));
        let policy = if is_miss {
            enricher.on_miss()
        } else {
            enricher.on_error()
        };
        let status = |fallback: &'static str| {
            if is_miss {
                "miss"
            } else if is_timeout {
                "timeout"
            } else {
                fallback
            }
        };
        let warn = if is_miss {
            tracing::debug!(
                enricher_id = %id,
                kind = %kind_label,
                error = %err,
                "Enricher found no data"
            );
            None
        } else {
            self.failure_logs.record(&id, Instant::now())
        };
        match policy {
            OnError::Skip => {
                if let Some(failures) = warn {
                    tracing::warn!(
                        enricher_id = %id,
                        kind = %kind_label,
                        error = %err,
                        suppressed = failures - 1,
                        "Enricher failed, skipping"
                    );
                }
                metrics.on_enrichment_completed(&id, kind_label, status("skip"), elapsed);
                EnrichOutcome::Skip
            }
            OnError::Null => {
                if let Some(failures) = warn {
                    tracing::warn!(
                        enricher_id = %id,
                        kind = %kind_label,
                        error = %err,
                        suppressed = failures - 1,
                        "Enricher failed, injecting null"
                    );
                }
                let map = result
                    .header
                    .enrichments
                    .get_or_insert_with(serde_json::Map::new);
                map.insert(inject_field, serde_json::Value::Null);
                metrics.on_enrichment_completed(&id, kind_label, status("error"), elapsed);
                EnrichOutcome::Null
            }
            OnError::Drop => {
                if let Some(failures) = warn {
                    tracing::warn!(
                        enricher_id = %id,
                        kind = %kind_label,
                        error = %err,
                        suppressed = failures - 1,
                        "Enricher failed, dropping result"
                    );
                }
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
            max_concurrent: self.max_concurrent,
            metrics: Arc::clone(&self.metrics),
            needs_event: self.needs_event,
            failure_logs: Arc::clone(&self.failure_logs),
            failure_cache: self.failure_cache.clone(),
            in_flight: Arc::default(),
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
    if matches!(
        name,
        "template" | "lookup" | "http" | "command" | "stix" | "mmdb" | "dns"
    ) {
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
