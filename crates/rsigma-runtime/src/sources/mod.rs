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
#[cfg(feature = "nats")]
pub mod nats;
pub mod refresh;
pub mod template;

use std::time::Instant;

use rsigma_eval::pipeline::sources::{DynamicSource, ErrorPolicy, SourceType};

pub use cache::SourceCache;
pub use template::TemplateExpander;

/// The result of successfully resolving a dynamic source.
#[derive(Debug, Clone)]
pub struct ResolvedValue {
    /// The resolved data as a YAML value (can be scalar, sequence, or mapping).
    pub data: serde_json::Value,
    /// When this value was resolved.
    pub resolved_at: Instant,
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
}

impl std::fmt::Display for SourceErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fetch(msg) => write!(f, "fetch failed: {msg}"),
            Self::Parse(msg) => write!(f, "parse failed: {msg}"),
            Self::Extract(msg) => write!(f, "extract failed: {msg}"),
            Self::Timeout => write!(f, "timed out"),
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
    cache: SourceCache,
}

impl DefaultSourceResolver {
    /// Create a new resolver with an in-memory cache.
    pub fn new() -> Self {
        Self {
            cache: SourceCache::new(),
        }
    }

    /// Create a new resolver with the given cache.
    pub fn with_cache(cache: SourceCache) -> Self {
        Self { cache }
    }

    /// Get a reference to the cache (for inspection/testing).
    pub fn cache(&self) -> &SourceCache {
        &self.cache
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
            SourceType::File { path, format } => file::resolve_file(path, *format, None).await,
            SourceType::Command {
                command,
                format,
                extract: extract_expr,
            } => command::resolve_command(command, *format, extract_expr.as_deref()).await,
            SourceType::Http {
                url,
                method,
                headers,
                format,
                extract: extract_expr,
            } => {
                http::resolve_http(
                    url,
                    method.as_deref(),
                    headers,
                    *format,
                    extract_expr.as_deref(),
                    source.timeout,
                )
                .await
            }
            #[cfg(feature = "nats")]
            SourceType::Nats {
                url,
                subject,
                format,
                extract: extract_expr,
            } => nats::resolve_nats_initial(url, subject, *format, extract_expr.as_deref()).await,
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
/// On `fail`, returns the first error encountered.
pub async fn resolve_all(
    resolver: &dyn SourceResolver,
    sources: &[DynamicSource],
) -> Result<std::collections::HashMap<String, serde_json::Value>, SourceError> {
    let mut resolved = std::collections::HashMap::new();
    for source in sources {
        let value = resolver.resolve(source).await?;
        resolved.insert(source.id.clone(), value.data);
    }
    Ok(resolved)
}

/// Convert a `serde_yaml::Value` to a `serde_json::Value`.
pub fn yaml_value_to_json(yaml: &serde_yaml::Value) -> serde_json::Value {
    match yaml {
        serde_yaml::Value::Null => serde_json::Value::Null,
        serde_yaml::Value::Bool(b) => serde_json::Value::Bool(*b),
        serde_yaml::Value::Number(n) => {
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
        serde_yaml::Value::String(s) => serde_json::Value::String(s.clone()),
        serde_yaml::Value::Sequence(seq) => {
            serde_json::Value::Array(seq.iter().map(yaml_value_to_json).collect())
        }
        serde_yaml::Value::Mapping(map) => {
            let obj = map
                .iter()
                .map(|(k, v)| {
                    let key = match k {
                        serde_yaml::Value::String(s) => s.clone(),
                        other => format!("{other:?}"),
                    };
                    (key, yaml_value_to_json(v))
                })
                .collect();
            serde_json::Value::Object(obj)
        }
        serde_yaml::Value::Tagged(tagged) => yaml_value_to_json(&tagged.value),
    }
}
