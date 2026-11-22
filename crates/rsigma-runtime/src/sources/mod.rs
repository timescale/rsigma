//! Dynamic source resolution for Sigma pipelines.
//!
//! This module provides the [`SourceResolver`] trait and a [`DefaultSourceResolver`]
//! implementation that fetches data from file, command, HTTP, and NATS sources
//! declared in a pipeline's `sources` section.

pub mod cache;
pub mod command;
pub mod extract;
pub mod file;
pub mod http;
pub mod include;
#[cfg(feature = "nats")]
pub mod nats;
pub mod refresh;
pub mod registry;
#[cfg(feature = "stix-source")]
pub mod stix;
#[cfg(feature = "stix-source")]
pub(crate) mod taxii;
pub mod template;
pub mod watchlist;

use std::time::{Duration, Instant};

use rsigma_eval::pipeline::sources::{DataFormat, DynamicSource, ErrorPolicy, SourceType};

/// Maximum size of a source response body (HTTP, command stdout, NATS payload).
pub const MAX_SOURCE_RESPONSE_BYTES: usize = 10 * 1024 * 1024; // 10 MB

/// Minimum allowed refresh interval to prevent hot CPU loops.
pub const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

pub use cache::SourceCache;
pub use template::TemplateExpander;
pub use watchlist::{
    AddSummary, RemoveSummary, ReplaceSummary, WatchlistError, WatchlistItem, WatchlistRegistry,
    WatchlistRestore, WatchlistRow,
};

/// The result of successfully resolving a dynamic source.
#[derive(Debug, Clone)]
pub struct ResolvedValue {
    /// The resolved data as a YAML value (can be scalar, sequence, or mapping).
    pub data: serde_json::Value,
    /// When this value was resolved.
    pub resolved_at: Instant,
    /// Whether this value was served from cache rather than freshly fetched.
    pub from_cache: bool,
}

/// An error that occurred while resolving a dynamic source.
#[derive(Debug, Clone)]
pub struct SourceError {
    /// The source ID that failed.
    pub source_id: String,
    /// What went wrong.
    pub kind: SourceErrorKind,
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "source '{}': {}", self.source_id, self.kind)
    }
}

impl std::error::Error for SourceError {}

/// The kind of error that occurred during source resolution.
#[derive(Debug, Clone)]
pub enum SourceErrorKind {
    /// Failed to fetch/read the source data.
    Fetch(String),
    /// Failed to parse the fetched data into the expected format.
    Parse(String),
    /// The `extract` expression failed or returned no data.
    Extract(String),
    /// The fetch exceeded the configured timeout.
    Timeout,
    /// The response exceeded the maximum allowed size.
    ResourceLimit(String),
}

impl std::fmt::Display for SourceErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fetch(msg) => write!(f, "fetch failed: {msg}"),
            Self::Parse(msg) => write!(f, "parse failed: {msg}"),
            Self::Extract(msg) => write!(f, "extract failed: {msg}"),
            Self::Timeout => write!(f, "timed out"),
            Self::ResourceLimit(msg) => write!(f, "resource limit exceeded: {msg}"),
        }
    }
}

/// Trait for resolving dynamic pipeline sources.
///
/// Implementations fetch data from external sources (files, commands, HTTP, NATS)
/// and return it as a JSON value that can be injected into the pipeline.
#[async_trait::async_trait]
pub trait SourceResolver: Send + Sync {
    /// Resolve a single dynamic source, returning the fetched data.
    async fn resolve(&self, source: &DynamicSource) -> Result<ResolvedValue, SourceError>;

    /// The value last stored for `source_id`, if any.
    ///
    /// A cache-first rebuild uses this so a refresh does not fetch every
    /// source again. The default returns nothing.
    fn cached(&self, source_id: &str) -> Option<serde_json::Value> {
        let _ = source_id;
        None
    }

    /// Remember `value` as the current data for `source_id`.
    ///
    /// Push updates call this so later cache-first rebuilds and lookup
    /// enrichers see the payload. The default discards it.
    fn store_cached(&self, source_id: &str, value: serde_json::Value) {
        let _ = (source_id, value);
    }
}

/// Default source resolver that dispatches to file, command, and HTTP resolvers.
pub struct DefaultSourceResolver {
    cache: std::sync::Arc<SourceCache>,
    watchlists: Option<std::sync::Arc<WatchlistRegistry>>,
    metrics: Option<std::sync::Arc<dyn crate::MetricsHook>>,
    /// Clock used when a STIX source is resolved. Unset uses the wall clock.
    #[cfg(feature = "stix-source")]
    stix_now: Option<rstix::core::StixTimestamp>,
    #[cfg(feature = "stix-source")]
    taxii: std::sync::Mutex<taxii::TaxiiSources>,
}

impl DefaultSourceResolver {
    /// Create a new resolver with an in-memory cache.
    pub fn new() -> Self {
        Self {
            cache: std::sync::Arc::new(SourceCache::new()),
            watchlists: None,
            metrics: None,
            #[cfg(feature = "stix-source")]
            stix_now: None,
            #[cfg(feature = "stix-source")]
            taxii: std::sync::Mutex::new(taxii::TaxiiSources::default()),
        }
    }

    /// Create a new resolver with the given cache.
    pub fn with_cache(cache: SourceCache) -> Self {
        Self {
            cache: std::sync::Arc::new(cache),
            watchlists: None,
            metrics: None,
            #[cfg(feature = "stix-source")]
            stix_now: None,
            #[cfg(feature = "stix-source")]
            taxii: std::sync::Mutex::new(taxii::TaxiiSources::default()),
        }
    }

    /// Create a new resolver that shares an existing `Arc<SourceCache>`
    /// with another consumer (e.g. the daemon's enrichment pipeline,
    /// which reads from the same cache for `lookup` enrichers).
    pub fn with_arc_cache(cache: std::sync::Arc<SourceCache>) -> Self {
        Self {
            cache,
            watchlists: None,
            metrics: None,
            #[cfg(feature = "stix-source")]
            stix_now: None,
            #[cfg(feature = "stix-source")]
            taxii: std::sync::Mutex::new(taxii::TaxiiSources::default()),
        }
    }

    /// Read TAXII credentials and build clients for `sources`.
    ///
    /// A missing environment variable is an error that names the variable.
    /// Without the `stix-source` feature, a `type: taxii` source is rejected.
    pub fn prepare_taxii(&mut self, sources: &[DynamicSource]) -> Result<(), SourceError> {
        self.prepare_taxii_with(sources, crate::default_egress_policy(), false)
    }

    /// [`prepare_taxii`](Self::prepare_taxii) with an explicit egress policy.
    ///
    /// `allow_insecure_http` is for tests. Source YAML has no such field.
    #[doc(hidden)]
    pub fn prepare_taxii_with(
        &mut self,
        sources: &[DynamicSource],
        policy: crate::EgressPolicy,
        allow_insecure_http: bool,
    ) -> Result<(), SourceError> {
        #[cfg(feature = "stix-source")]
        {
            let mut taxii = self.taxii.lock().unwrap_or_else(|err| err.into_inner());
            taxii.prepare(sources, policy, allow_insecure_http)
        }
        #[cfg(not(feature = "stix-source"))]
        {
            let _ = (policy, allow_insecure_http);
            if let Some(source) = sources
                .iter()
                .find(|source| matches!(source.source_type, SourceType::Taxii { .. }))
            {
                return Err(SourceError {
                    source_id: source.id.clone(),
                    kind: SourceErrorKind::Fetch(
                        "TAXII source requires the stix-source feature".into(),
                    ),
                });
            }
            Ok(())
        }
    }

    /// Resolve STIX lifecycle checks at `now` instead of the wall clock.
    #[cfg(feature = "stix-source")]
    pub fn with_stix_clock(mut self, now: rstix::core::StixTimestamp) -> Self {
        self.stix_now = Some(now);
        self
    }

    #[cfg(feature = "stix-source")]
    fn stix_now(&self) -> rstix::core::StixTimestamp {
        self.stix_now
            .clone()
            .unwrap_or_else(rstix::core::StixTimestamp::now)
    }

    /// Record source metrics through `metrics`.
    pub fn with_metrics(mut self, metrics: std::sync::Arc<dyn crate::MetricsHook>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Resolve `type: watchlist` sources from `registry`.
    ///
    /// Without a registry those sources resolve to an empty list.
    pub fn with_watchlists(mut self, registry: std::sync::Arc<WatchlistRegistry>) -> Self {
        self.set_watchlists(registry);
        self
    }

    /// Attach a watchlist registry after the resolver already exists.
    pub fn set_watchlists(&mut self, registry: std::sync::Arc<WatchlistRegistry>) {
        self.watchlists = Some(registry);
    }

    /// Get a reference to the cache (for inspection/testing).
    pub fn cache(&self) -> &SourceCache {
        &self.cache
    }

    /// Borrow the shared `Arc<SourceCache>` so other components (e.g.
    /// the daemon's enrichment pipeline) can read from the same cache.
    pub fn arc_cache(&self) -> std::sync::Arc<SourceCache> {
        self.cache.clone()
    }

    async fn resolve_file_source(
        &self,
        source_id: &str,
        path: &std::path::Path,
        format: DataFormat,
        extract: Option<&rsigma_eval::pipeline::sources::ExtractExpr>,
        stix: Option<&rsigma_eval::pipeline::sources::StixOptions>,
    ) -> Result<ResolvedValue, SourceError> {
        #[cfg(feature = "stix-source")]
        if format == DataFormat::Stix {
            let contents = tokio::fs::read_to_string(path)
                .await
                .map_err(|e| SourceError {
                    source_id: String::new(),
                    kind: SourceErrorKind::Fetch(format!("failed to read {}: {e}", path.display())),
                })?;
            let options = stix
                .cloned()
                .unwrap_or_else(rsigma_eval::pipeline::sources::StixOptions::all);
            let built = stix::build(&contents, &options, &self.stix_now())?;
            return Ok(self.finish_stix(source_id, built));
        } else {
            let _ = (source_id, stix);
        }
        #[cfg(not(feature = "stix-source"))]
        let _ = (source_id, stix);
        file::resolve_file(path, format, extract).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn resolve_http_source(
        &self,
        source_id: &str,
        url: &str,
        method: Option<&str>,
        headers: &std::collections::HashMap<String, String>,
        body: Option<&str>,
        format: DataFormat,
        extract: Option<&rsigma_eval::pipeline::sources::ExtractExpr>,
        timeout: Option<Duration>,
        stix: Option<&rsigma_eval::pipeline::sources::StixOptions>,
        max_body_size: usize,
    ) -> Result<ResolvedValue, SourceError> {
        #[cfg(feature = "stix-source")]
        if format == DataFormat::Stix {
            let options = stix
                .cloned()
                .unwrap_or_else(rsigma_eval::pipeline::sources::StixOptions::all);
            let now = self.stix_now();
            let id = source_id.to_owned();
            let metrics = self.metrics.clone();
            return http::resolve_http_with_limit(
                url,
                method,
                headers,
                body,
                extract,
                timeout,
                max_body_size,
                move |text| {
                    let built = stix::build(text, &options, &now)?;
                    if let Some(metrics) = &metrics {
                        stix::observe(metrics.as_ref(), &id, &built);
                    }
                    Ok(built.value)
                },
            )
            .await;
        } else {
            let _ = (source_id, stix);
        }
        #[cfg(not(feature = "stix-source"))]
        let _ = (source_id, stix);
        http::resolve_http_with_limit(
            url,
            method,
            headers,
            body,
            extract,
            timeout,
            max_body_size,
            |text| file::parse_data(text, format),
        )
        .await
    }

    async fn resolve_taxii(&self, source: &DynamicSource) -> Result<ResolvedValue, SourceError> {
        #[cfg(not(feature = "stix-source"))]
        {
            let _ = source;
            return Err(SourceError {
                source_id: String::new(),
                kind: SourceErrorKind::Fetch(
                    "TAXII source requires the stix-source feature".into(),
                ),
            });
        }
        #[cfg(feature = "stix-source")]
        {
            let (prepared, previous) = {
                let mut taxii = self.taxii.lock().unwrap_or_else(|err| err.into_inner());
                taxii.take_poll(&source.id)?
            };
            let (state, built) = taxii::poll(&prepared, previous, &self.stix_now()).await;
            self.taxii
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .commit(&source.id, state);
            Ok(self.finish_stix(&source.id, built?))
        }
    }

    #[cfg(feature = "stix-source")]
    fn finish_stix(&self, source_id: &str, built: stix::StixBuild) -> ResolvedValue {
        if let Some(metrics) = &self.metrics {
            stix::observe(metrics.as_ref(), source_id, &built);
        }
        ResolvedValue {
            data: built.value,
            resolved_at: Instant::now(),
            from_cache: false,
        }
    }
}

impl Default for DefaultSourceResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl SourceResolver for DefaultSourceResolver {
    fn cached(&self, source_id: &str) -> Option<serde_json::Value> {
        self.cache.get(source_id)
    }

    fn store_cached(&self, source_id: &str, value: serde_json::Value) {
        self.cache.store(source_id, &value);
    }

    async fn resolve(&self, source: &DynamicSource) -> Result<ResolvedValue, SourceError> {
        let result = match &source.source_type {
            SourceType::File {
                path,
                format,
                extract,
                stix,
            } => {
                self.resolve_file_source(&source.id, path, *format, extract.as_ref(), stix.as_ref())
                    .await
            }
            SourceType::Command {
                command,
                format,
                extract,
                max_stdout,
            } => {
                command::resolve_command_with_limit(
                    command,
                    *format,
                    extract.as_ref(),
                    source.timeout,
                    max_stdout.unwrap_or(MAX_SOURCE_RESPONSE_BYTES),
                )
                .await
            }
            SourceType::Http {
                url,
                method,
                headers,
                body,
                format,
                extract,
                stix,
                max_body_size,
            } => {
                self.resolve_http_source(
                    &source.id,
                    url,
                    method.as_deref(),
                    headers,
                    body.as_deref(),
                    *format,
                    extract.as_ref(),
                    source.timeout,
                    stix.as_ref(),
                    max_body_size.unwrap_or(MAX_SOURCE_RESPONSE_BYTES),
                )
                .await
            }
            #[cfg(feature = "nats")]
            SourceType::Nats {
                url,
                subject,
                format,
                extract,
            } => nats::resolve_nats_initial(url, subject, *format, extract.as_ref()).await,
            #[cfg(not(feature = "nats"))]
            SourceType::Nats { .. } => {
                return Err(SourceError {
                    source_id: source.id.clone(),
                    kind: SourceErrorKind::Fetch("NATS source requires the 'nats' feature".into()),
                });
            }
            SourceType::Taxii { .. } => self.resolve_taxii(source).await,
            SourceType::Watchlist { .. } => {
                let data = self
                    .watchlists
                    .as_ref()
                    .and_then(|registry| registry.values(&source.id, watchlist::now_utc()).ok())
                    .map(|values| {
                        serde_json::Value::Array(
                            values.into_iter().map(serde_json::Value::String).collect(),
                        )
                    })
                    .unwrap_or_else(|| serde_json::json!([]));
                Ok(ResolvedValue {
                    data,
                    resolved_at: Instant::now(),
                    from_cache: false,
                })
            }
        };

        match result {
            Ok(value) => {
                tracing::debug!(source_id = %source.id, "Source fetched successfully");
                self.cache.store(&source.id, &value.data);
                Ok(value)
            }
            Err(mut err) => {
                err.source_id = source.id.clone();
                match source.on_error {
                    ErrorPolicy::UseCached => {
                        if let Some(cached) = self.cache.get(&source.id) {
                            tracing::warn!(
                                source_id = %source.id,
                                error = %err,
                                "Source resolution failed, using cached value"
                            );
                            Ok(ResolvedValue {
                                data: cached,
                                resolved_at: Instant::now(),
                                from_cache: true,
                            })
                        } else {
                            Err(err)
                        }
                    }
                    ErrorPolicy::UseDefault => {
                        if let Some(default) = &source.default {
                            tracing::warn!(
                                source_id = %source.id,
                                error = %err,
                                "Source resolution failed, using default value"
                            );
                            let json_default = yaml_value_to_json(default);
                            Ok(ResolvedValue {
                                data: json_default,
                                resolved_at: Instant::now(),
                                from_cache: false,
                            })
                        } else {
                            Err(err)
                        }
                    }
                    ErrorPolicy::Fail => Err(err),
                }
            }
        }
    }
}

/// Resolve sources from the cache, fetching only the ones with no cached value.
///
/// A hit is returned as stored. A miss calls [`SourceResolver::resolve`],
/// which stores the fetched value. Optional sources that fail become JSON null.
pub async fn resolve_all_cache_first(
    resolver: &dyn SourceResolver,
    sources: &[DynamicSource],
) -> Result<std::collections::HashMap<String, serde_json::Value>, SourceError> {
    let mut resolved = std::collections::HashMap::new();
    for source in sources {
        if let Some(cached) = resolver.cached(&source.id) {
            resolved.insert(source.id.clone(), cached);
            continue;
        }
        match resolver.resolve(source).await {
            Ok(value) => {
                resolved.insert(source.id.clone(), value.data);
            }
            Err(e) => {
                if source.required {
                    return Err(e);
                }
                tracing::warn!(
                    source_id = %source.id,
                    error = %e,
                    "Optional source has no cached value and failed to resolve, using null"
                );
                resolved.insert(source.id.clone(), serde_json::Value::Null);
            }
        }
    }
    Ok(resolved)
}

/// Resolve all sources in a pipeline, returning a map of source_id -> resolved data.
///
/// Applies error policies: `use_cached`, `use_default`, or `fail`.
/// Required sources with `Fail` policy propagate errors immediately.
/// Optional sources (required=false) that fail are logged and skipped
/// with a Null fallback value.
pub async fn resolve_all(
    resolver: &dyn SourceResolver,
    sources: &[DynamicSource],
) -> Result<std::collections::HashMap<String, serde_json::Value>, SourceError> {
    resolve_all_with_state(resolver, sources, None).await
}

/// Like [`resolve_all`] but also updates a
/// [`PipelineState`](rsigma_eval::pipeline::state::PipelineState) with
/// source resolution status.
pub async fn resolve_all_with_state(
    resolver: &dyn SourceResolver,
    sources: &[DynamicSource],
    mut state: Option<&mut rsigma_eval::pipeline::state::PipelineState>,
) -> Result<std::collections::HashMap<String, serde_json::Value>, SourceError> {
    let mut resolved = std::collections::HashMap::new();
    for source in sources {
        match resolver.resolve(source).await {
            Ok(value) => {
                resolved.insert(source.id.clone(), value.data);
                if let Some(s) = state.as_deref_mut() {
                    s.mark_source_resolved(&source.id);
                }
            }
            Err(e) => {
                if let Some(s) = state.as_deref_mut() {
                    s.mark_source_failed(&source.id);
                }
                if source.required {
                    return Err(e);
                }
                tracing::warn!(
                    source_id = %source.id,
                    error = %e,
                    "Optional source resolution failed, using null"
                );
                resolved.insert(source.id.clone(), serde_json::Value::Null);
            }
        }
    }
    Ok(resolved)
}

/// Convert a `yaml_serde::Value` to a `serde_json::Value`.
pub fn yaml_value_to_json(yaml: &yaml_serde::Value) -> serde_json::Value {
    match yaml {
        yaml_serde::Value::Null => serde_json::Value::Null,
        yaml_serde::Value::Bool(b) => serde_json::Value::Bool(*b),
        yaml_serde::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                serde_json::Value::Number(i.into())
            } else if let Some(u) = n.as_u64() {
                serde_json::Value::Number(u.into())
            } else if let Some(f) = n.as_f64() {
                serde_json::json!(f)
            } else {
                serde_json::Value::Null
            }
        }
        yaml_serde::Value::String(s) => serde_json::Value::String(s.clone()),
        yaml_serde::Value::Sequence(seq) => {
            serde_json::Value::Array(seq.iter().map(yaml_value_to_json).collect())
        }
        yaml_serde::Value::Mapping(map) => {
            let obj = map
                .iter()
                .map(|(k, v)| {
                    let key = match k {
                        yaml_serde::Value::String(s) => s.clone(),
                        other => format!("{other:?}"),
                    };
                    (key, yaml_value_to_json(v))
                })
                .collect();
            serde_json::Value::Object(obj)
        }
        yaml_serde::Value::Tagged(tagged) => yaml_value_to_json(&tagged.value),
    }
}
