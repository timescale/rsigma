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
pub mod template;

use std::time::{Duration, Instant};

use rsigma_eval::pipeline::sources::{DynamicSource, ErrorPolicy, SourceType};

/// Maximum size of a source response body (HTTP, command stdout, NATS payload).
pub const MAX_SOURCE_RESPONSE_BYTES: usize = 10 * 1024 * 1024; // 10 MB

/// Minimum allowed refresh interval to prevent hot CPU loops.
pub const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

pub use cache::SourceCache;
pub use template::TemplateExpander;

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
}

/// Default source resolver that dispatches to file, command, and HTTP resolvers.
pub struct DefaultSourceResolver {
    cache: std::sync::Arc<SourceCache>,
}

impl DefaultSourceResolver {
    /// Create a new resolver with an in-memory cache.
    pub fn new() -> Self {
        Self {
            cache: std::sync::Arc::new(SourceCache::new()),
        }
    }

    /// Create a new resolver with the given cache.
    pub fn with_cache(cache: SourceCache) -> Self {
        Self {
            cache: std::sync::Arc::new(cache),
        }
    }

    /// Create a new resolver that shares an existing `Arc<SourceCache>`
    /// with another consumer (e.g. the daemon's enrichment pipeline,
    /// which reads from the same cache for `lookup` enrichers).
    pub fn with_arc_cache(cache: std::sync::Arc<SourceCache>) -> Self {
        Self { cache }
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
}

impl Default for DefaultSourceResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl SourceResolver for DefaultSourceResolver {
    async fn resolve(&self, source: &DynamicSource) -> Result<ResolvedValue, SourceError> {
        let result = match &source.source_type {
            SourceType::File {
                path,
                format,
                extract,
            } => file::resolve_file(path, *format, extract.as_ref()).await,
            SourceType::Command {
                command,
                format,
                extract,
            } => command::resolve_command(command, *format, extract.as_ref(), source.timeout).await,
            SourceType::Http {
                url,
                method,
                headers,
                body,
                format,
                extract,
            } => {
                http::resolve_http(
                    url,
                    method.as_deref(),
                    headers,
                    body.as_deref(),
                    *format,
                    extract.as_ref(),
                    source.timeout,
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
