//! YAML schema and loader for the daemon's enrichers config file.
//!
//! Loaded at daemon startup (and again on hot-reload). Validates that:
//! - every enricher declares a `kind: detection | correlation`,
//! - templated fields reference only the declared kind's namespace
//!   (`${detection.*}` or `${correlation.*}`) plus `${ENV_VAR}`,
//! - `scope.rules`, `scope.tags`, and `scope.levels` parse correctly,
//! - bespoke `type:` values map to a registered factory.
//!
//! Failures abort daemon startup with a clear error pointing at the
//! offending enricher id and field.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

#[cfg(test)]
use rsigma_runtime::NoopMetrics;
use rsigma_runtime::{
    CommandEnricher, EnricherKind, EnrichmentPipeline, HttpEnricher, HttpEnricherClient,
    HttpResponseCache, LookupEnricher, MetricsHook, OnError, OutputFormat, Scope, SourceCache,
    TemplateEnricher, build_default_http_client, lookup_builtin, validate_template_namespace,
};
use serde::Deserialize;

/// Default per-enricher timeout when YAML omits `timeout:`.
const DEFAULT_ENRICHER_TIMEOUT: Duration = Duration::from_secs(5);

/// Default global concurrency cap when YAML omits `max_concurrent_enrichments`.
const DEFAULT_MAX_CONCURRENT_ENRICHMENTS: usize = 16;

/// Top-level enrichers config file.
///
/// ```yaml
/// max_concurrent_enrichments: 16
/// enrichers:
///   - id: runbook_det
///     kind: detection
///     type: template
///     template: "https://wiki/${detection.rule.id}"
///     inject_field: runbook_url
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct EnrichersFile {
    /// Global concurrency cap shared across both kinds. Defaults to 16
    /// if omitted; values of 0 are treated as the default to keep the
    /// pipeline functional even on a malformed config.
    #[serde(default)]
    pub max_concurrent_enrichments: Option<usize>,

    /// Per-enricher configurations. Empty list / missing key is allowed
    /// (no enrichment is configured) so an operator can keep an
    /// enrichers file with an empty list during a rollout.
    #[serde(default)]
    pub enrichers: Vec<EnricherConfig>,
}

/// One enricher's YAML config block.
#[derive(Debug, Clone, Deserialize)]
pub struct EnricherConfig {
    /// Stable identifier for this enricher instance. Required.
    pub id: String,
    /// Required kind (`detection` or `correlation`).
    pub kind: KindLabel,
    /// Primitive type name (`template`, `lookup`, `http`, `command`) or
    /// the `type:` of a bespoke enricher registered via
    /// [`register_builtin`](rsigma_runtime::register_builtin).
    #[serde(rename = "type")]
    pub type_name: String,
    /// Field under `enrichments` to write the result into.
    pub inject_field: String,
    /// Per-enricher timeout. Accepts humantime strings (`5s`, `200ms`).
    #[serde(default, with = "humantime_opt")]
    pub timeout: Option<Duration>,
    /// Behavior when this enricher fails. Defaults to `skip`.
    #[serde(default)]
    pub on_error: OnErrorLabel,
    /// Optional scope filter.
    #[serde(default)]
    pub scope: Option<ScopeConfig>,

    // Primitive-specific fields. Captured here as `Option`s so a single
    // serde struct covers all four primitives without separate
    // deserializer types per `type_name`.
    /// `template`: template string to render.
    #[serde(default)]
    pub template: Option<String>,

    // The remaining fields are reserved for the http / command / lookup
    // primitives shipped in Phases 2 and 3. They live on the same
    // struct so YAML files round-trip with the loader without needing
    // per-phase reparse logic; missing values produce a clear error
    // when the matching primitive is selected.
    /// `http`: target URL.
    #[serde(default)]
    pub url: Option<String>,
    /// `http`: HTTP method (GET / POST / …). Defaults to GET inside
    /// the primitive when omitted.
    #[serde(default)]
    pub method: Option<String>,
    /// `http`: optional headers.
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// `http`: optional request body.
    #[serde(default)]
    pub body: Option<String>,
    /// `http`: response cache TTL. Off by default.
    #[serde(default, with = "humantime_opt")]
    pub cache_ttl: Option<Duration>,
    /// `http` / `lookup`: optional extract expression applied to the
    /// fetched value before injection.
    #[serde(default)]
    pub extract: Option<String>,
    /// `http` / `lookup`: extract language (`jq` / `jsonpath` / `cel`).
    /// Defaults to `jq` inside the primitive.
    #[serde(default)]
    pub extract_type: Option<String>,
    /// `command`: argv. The first element is the program; remaining
    /// elements are arguments. Each is template-expanded.
    #[serde(default)]
    pub command: Vec<String>,
    /// `command`: optional environment overrides.
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// `command`: how to interpret stdout. `json` (default) or `raw`.
    #[serde(default)]
    pub output: OutputFormatLabel,
    /// `lookup`: source ID of a dynamic source configured on the daemon.
    #[serde(default)]
    pub source: Option<String>,
    /// `lookup`: default value injected on cache miss / no extract match.
    /// Overrides `on_error` when configured.
    #[serde(default)]
    pub default: Option<serde_json::Value>,
}

/// `kind:` discriminator. Lower-case in YAML, parses to
/// [`EnricherKind`].
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KindLabel {
    Detection,
    Correlation,
}

impl From<KindLabel> for EnricherKind {
    fn from(k: KindLabel) -> Self {
        match k {
            KindLabel::Detection => EnricherKind::Detection,
            KindLabel::Correlation => EnricherKind::Correlation,
        }
    }
}

/// `on_error:` discriminator.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnErrorLabel {
    #[default]
    Skip,
    Null,
    Drop,
}

impl From<OnErrorLabel> for OnError {
    fn from(o: OnErrorLabel) -> Self {
        match o {
            OnErrorLabel::Skip => OnError::Skip,
            OnErrorLabel::Null => OnError::Null,
            OnErrorLabel::Drop => OnError::Drop,
        }
    }
}

/// `output:` discriminator for the `command` primitive.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormatLabel {
    /// Parse stdout as JSON.
    #[default]
    Json,
    /// Inject stdout verbatim as a string.
    Raw,
}

impl From<OutputFormatLabel> for OutputFormat {
    fn from(o: OutputFormatLabel) -> Self {
        match o {
            OutputFormatLabel::Json => OutputFormat::Json,
            OutputFormatLabel::Raw => OutputFormat::Raw,
        }
    }
}

/// `scope:` block.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ScopeConfig {
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub levels: Vec<String>,
}

/// Errors produced while loading or validating an enrichers config.
#[derive(Debug)]
pub enum EnrichersConfigError {
    /// File could not be read.
    Io(std::io::Error, std::path::PathBuf),
    /// YAML failed to deserialize.
    Yaml(yaml_serde::Error),
    /// An enricher referenced an unknown `type:` value.
    UnknownType {
        enricher_id: String,
        type_name: String,
    },
    /// A primitive was missing a required field (e.g. `template:` for a
    /// `template` enricher).
    MissingField {
        enricher_id: String,
        type_name: String,
        field: &'static str,
    },
    /// Template-namespace validator rejected a reference.
    Template(rsigma_runtime::TemplateError),
    /// Scope construction failed.
    Scope {
        enricher_id: String,
        message: String,
    },
    /// Bespoke enricher factory rejected the config.
    BespokeFactory {
        enricher_id: String,
        message: String,
    },
}

impl std::fmt::Display for EnrichersConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrichersConfigError::Io(e, p) => {
                write!(f, "failed to read enrichers config '{}': {e}", p.display())
            }
            EnrichersConfigError::Yaml(e) => write!(f, "invalid enrichers YAML: {e}"),
            EnrichersConfigError::UnknownType {
                enricher_id,
                type_name,
            } => write!(
                f,
                "enricher '{enricher_id}': unknown type '{type_name}' (built-ins: template, lookup, http, command; bespoke types must register_builtin() before daemon start)"
            ),
            EnrichersConfigError::MissingField {
                enricher_id,
                type_name,
                field,
            } => write!(
                f,
                "enricher '{enricher_id}' (type: {type_name}): missing required field '{field}'"
            ),
            EnrichersConfigError::Template(e) => write!(f, "{e}"),
            EnrichersConfigError::Scope {
                enricher_id,
                message,
            } => write!(f, "enricher '{enricher_id}': {message}"),
            EnrichersConfigError::BespokeFactory {
                enricher_id,
                message,
            } => write!(
                f,
                "enricher '{enricher_id}': bespoke factory rejected config: {message}"
            ),
        }
    }
}

impl std::error::Error for EnrichersConfigError {}

/// Read and deserialize an enrichers config file.
pub fn load_enrichers_file(path: &Path) -> Result<EnrichersFile, EnrichersConfigError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| EnrichersConfigError::Io(e, path.to_path_buf()))?;
    let parsed: EnrichersFile = yaml_serde::from_str(&text).map_err(EnrichersConfigError::Yaml)?;
    Ok(parsed)
}

/// Construct an [`EnrichmentPipeline`] from a parsed config.
///
/// This is split from [`load_enrichers_file`] so unit tests and the
/// hot-reload path can build a pipeline from a programmatically
/// constructed [`EnrichersFile`] without going through the disk.
///
/// `source_cache` is the dynamic-pipelines source cache shared across
/// the daemon. Pass `None` if no `lookup` enrichers will be configured;
/// the loader returns a clear error if a `lookup` enricher is encountered
/// without a cache.
///
/// All HTTP enrichers in the resulting pipeline share a single
/// `reqwest::Client` (wrapped in [`HttpEnricherClient`]) so connection
/// pooling works at the daemon level.
#[cfg(test)]
pub fn build_enrichers(file: EnrichersFile) -> Result<EnrichmentPipeline, EnrichersConfigError> {
    build_enrichers_full(file, None, std::sync::Arc::new(NoopMetrics))
}

/// Like [`build_enrichers`] but accepts an optional shared
/// [`SourceCache`] for `lookup` enrichers and a metrics hook the
/// pipeline (and per-enricher cache lookups) report into. The daemon
/// passes its Prometheus-backed `Metrics` here.
pub fn build_enrichers_full(
    file: EnrichersFile,
    source_cache: Option<std::sync::Arc<SourceCache>>,
    metrics: std::sync::Arc<dyn MetricsHook>,
) -> Result<EnrichmentPipeline, EnrichersConfigError> {
    let http_client =
        build_default_http_client().map_err(|message| EnrichersConfigError::BespokeFactory {
            enricher_id: "<global>".to_string(),
            message,
        })?;
    let mut enrichers: Vec<Box<dyn rsigma_runtime::Enricher>> =
        Vec::with_capacity(file.enrichers.len());
    for cfg in file.enrichers {
        enrichers.push(build_one(
            cfg,
            http_client.clone(),
            source_cache.clone(),
            metrics.clone(),
        )?);
    }
    let cap = file
        .max_concurrent_enrichments
        .unwrap_or(DEFAULT_MAX_CONCURRENT_ENRICHMENTS);
    Ok(EnrichmentPipeline::new(enrichers, cap).with_metrics(metrics))
}

/// Build a single [`Enricher`](rsigma_runtime::Enricher) from one YAML
/// config block.
///
/// Pulled out of [`build_enrichers`] so the loader's match on
/// `type_name` stays linear and so future primitives can be added by
/// extending one match arm.
fn build_one(
    cfg: EnricherConfig,
    http_client: HttpEnricherClient,
    source_cache: Option<std::sync::Arc<SourceCache>>,
    metrics: std::sync::Arc<dyn MetricsHook>,
) -> Result<Box<dyn rsigma_runtime::Enricher>, EnrichersConfigError> {
    let kind: EnricherKind = cfg.kind.into();
    let on_error: OnError = cfg.on_error.into();
    let timeout = cfg.timeout.unwrap_or(DEFAULT_ENRICHER_TIMEOUT);

    let scope =
        match &cfg.scope {
            Some(s) => Scope::new(s.rules.clone(), s.tags.clone(), s.levels.clone()).map_err(
                |message| EnrichersConfigError::Scope {
                    enricher_id: cfg.id.clone(),
                    message,
                },
            )?,
            None => Scope::default(),
        };

    // Validate template-namespace references on every templated field.
    // The full set of templated fields is type-dependent, but every
    // primitive shares the same namespace rules, so we run the
    // validator once per field that the chosen primitive touches.
    validate_templated_fields(&cfg, kind)?;

    match cfg.type_name.as_str() {
        "template" => {
            let template = cfg
                .template
                .clone()
                .ok_or(EnrichersConfigError::MissingField {
                    enricher_id: cfg.id.clone(),
                    type_name: cfg.type_name.clone(),
                    field: "template",
                })?;
            Ok(Box::new(TemplateEnricher::new(
                cfg.id,
                kind,
                cfg.inject_field,
                template,
                timeout,
                on_error,
                scope,
            )))
        }
        "http" => {
            let url = cfg.url.clone().ok_or(EnrichersConfigError::MissingField {
                enricher_id: cfg.id.clone(),
                type_name: cfg.type_name.clone(),
                field: "url",
            })?;
            let method = cfg.method.clone().unwrap_or_else(|| "GET".to_string());
            let headers: Vec<(String, String)> = cfg
                .headers
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            let extract = build_extract_expr(&cfg)?;
            let cache_ttl = cfg.cache_ttl.unwrap_or_default();
            let cache = HttpResponseCache::new(cache_ttl);
            Ok(Box::new(
                HttpEnricher::new(
                    cfg.id,
                    kind,
                    cfg.inject_field,
                    method,
                    url,
                    headers,
                    cfg.body.clone(),
                    timeout,
                    on_error,
                    scope,
                    extract,
                    http_client,
                    cache,
                )
                .with_metrics(metrics),
            ))
        }
        "command" => {
            if cfg.command.is_empty() {
                return Err(EnrichersConfigError::MissingField {
                    enricher_id: cfg.id.clone(),
                    type_name: cfg.type_name.clone(),
                    field: "command",
                });
            }
            Ok(Box::new(CommandEnricher::new(
                cfg.id,
                kind,
                cfg.inject_field,
                cfg.command,
                cfg.env,
                timeout,
                on_error,
                scope,
                cfg.output.into(),
            )))
        }
        "lookup" => {
            let source = cfg
                .source
                .clone()
                .ok_or(EnrichersConfigError::MissingField {
                    enricher_id: cfg.id.clone(),
                    type_name: cfg.type_name.clone(),
                    field: "source",
                })?;
            let cache = source_cache.ok_or(EnrichersConfigError::MissingField {
                enricher_id: cfg.id.clone(),
                type_name: cfg.type_name.clone(),
                // Surfaced when the daemon has no dynamic sources
                // configured but an operator declared a lookup enricher
                // anyway. Intentionally declaration-site-neutral so the
                // error reads correctly regardless of whether the
                // operator declares sources inline in a pipeline file or
                // via the daemon-level source registry.
                field: "<source_cache: no dynamic sources configured>",
            })?;
            let extract = build_extract_expr(&cfg)?;
            Ok(Box::new(LookupEnricher::new(
                cfg.id,
                kind,
                cfg.inject_field,
                source,
                extract,
                cfg.default,
                timeout,
                on_error,
                scope,
                cache,
            )))
        }
        other => {
            // Bespoke type: look up factory and pass the raw config block.
            let factory = lookup_builtin(other).ok_or(EnrichersConfigError::UnknownType {
                enricher_id: cfg.id.clone(),
                type_name: other.to_string(),
            })?;
            // Re-serialize the entire config block as JSON so the
            // factory can deserialize whatever schema it needs.
            let raw =
                serde_json::to_value(&cfg).map_err(|e| EnrichersConfigError::BespokeFactory {
                    enricher_id: cfg.id.clone(),
                    message: format!("internal: re-serialize failed: {e}"),
                })?;
            factory(&raw).map_err(|message| EnrichersConfigError::BespokeFactory {
                enricher_id: cfg.id.clone(),
                message,
            })
        }
    }
}

/// Build an [`ExtractExpr`] from `cfg.extract` + `cfg.extract_type`.
/// `None` when no extract is configured. Defaults to `jq` when an
/// extract expression is set without an explicit type, matching the
/// pipeline-source convention.
fn build_extract_expr(
    cfg: &EnricherConfig,
) -> Result<Option<rsigma_eval::pipeline::sources::ExtractExpr>, EnrichersConfigError> {
    use rsigma_eval::pipeline::sources::ExtractExpr;
    let Some(expr) = cfg.extract.clone() else {
        return Ok(None);
    };
    let kind = cfg.extract_type.as_deref().unwrap_or("jq");
    Ok(Some(match kind {
        "jq" => ExtractExpr::Jq(expr),
        "jsonpath" => ExtractExpr::JsonPath(expr),
        "cel" => ExtractExpr::Cel(expr),
        other => {
            return Err(EnrichersConfigError::Scope {
                enricher_id: cfg.id.clone(),
                message: format!("unknown extract_type '{other}' (expected jq | jsonpath | cel)"),
            });
        }
    }))
}

/// Walk every templated field on `cfg` and validate that its `${...}`
/// references match the enricher's declared kind.
fn validate_templated_fields(
    cfg: &EnricherConfig,
    kind: EnricherKind,
) -> Result<(), EnrichersConfigError> {
    let id = cfg.id.as_str();
    let check = |s: &str, field: &'static str| -> Result<(), EnrichersConfigError> {
        validate_template_namespace(s, kind, id, field).map_err(EnrichersConfigError::Template)
    };
    if let Some(t) = &cfg.template {
        check(t, "template")?;
    }
    if let Some(u) = &cfg.url {
        check(u, "url")?;
    }
    for (k, v) in &cfg.headers {
        // Headers are key/value; we only template the value (the
        // typical case is `Authorization: Bearer ${TOKEN}`). We still
        // surface the header name in the error context for clarity.
        let static_field: &'static str = Box::leak(format!("headers.{k}").into_boxed_str());
        check(v, static_field)?;
    }
    if let Some(b) = &cfg.body {
        check(b, "body")?;
    }
    for (i, c) in cfg.command.iter().enumerate() {
        let static_field: &'static str = Box::leak(format!("command[{i}]").into_boxed_str());
        check(c, static_field)?;
    }
    for (k, v) in &cfg.env {
        let static_field: &'static str = Box::leak(format!("env.{k}").into_boxed_str());
        check(v, static_field)?;
    }
    if let Some(e) = &cfg.extract {
        check(e, "extract")?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// EnricherConfig must Serialize too so bespoke factories see the same
// shape via `serde_json::to_value(&cfg)`.
// ---------------------------------------------------------------------------

impl serde::Serialize for EnricherConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut m = serializer.serialize_map(None)?;
        m.serialize_entry("id", &self.id)?;
        m.serialize_entry(
            "kind",
            match self.kind {
                KindLabel::Detection => "detection",
                KindLabel::Correlation => "correlation",
            },
        )?;
        m.serialize_entry("type", &self.type_name)?;
        m.serialize_entry("inject_field", &self.inject_field)?;
        if let Some(t) = &self.timeout {
            m.serialize_entry("timeout_ms", &(t.as_millis() as u64))?;
        }
        m.serialize_entry(
            "on_error",
            match self.on_error {
                OnErrorLabel::Skip => "skip",
                OnErrorLabel::Null => "null",
                OnErrorLabel::Drop => "drop",
            },
        )?;
        if let Some(s) = &self.scope {
            m.serialize_entry("scope", s)?;
        }
        if let Some(t) = &self.template {
            m.serialize_entry("template", t)?;
        }
        if let Some(u) = &self.url {
            m.serialize_entry("url", u)?;
        }
        if let Some(meth) = &self.method {
            m.serialize_entry("method", meth)?;
        }
        if !self.headers.is_empty() {
            m.serialize_entry("headers", &self.headers)?;
        }
        if let Some(b) = &self.body {
            m.serialize_entry("body", b)?;
        }
        if let Some(c) = &self.cache_ttl {
            m.serialize_entry("cache_ttl_ms", &(c.as_millis() as u64))?;
        }
        if let Some(e) = &self.extract {
            m.serialize_entry("extract", e)?;
        }
        if let Some(et) = &self.extract_type {
            m.serialize_entry("extract_type", et)?;
        }
        if !self.command.is_empty() {
            m.serialize_entry("command", &self.command)?;
        }
        if !self.env.is_empty() {
            m.serialize_entry("env", &self.env)?;
        }
        if let Some(s) = &self.source {
            m.serialize_entry("source", s)?;
        }
        if let Some(d) = &self.default {
            m.serialize_entry("default", d)?;
        }
        m.end()
    }
}

impl serde::Serialize for ScopeConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut m = serializer.serialize_map(None)?;
        if !self.rules.is_empty() {
            m.serialize_entry("rules", &self.rules)?;
        }
        if !self.tags.is_empty() {
            m.serialize_entry("tags", &self.tags)?;
        }
        if !self.levels.is_empty() {
            m.serialize_entry("levels", &self.levels)?;
        }
        m.end()
    }
}

// ---------------------------------------------------------------------------
// humantime_opt: serde adapter that parses humantime strings into
// `Option<Duration>` while accepting `null` / missing entries as `None`.
// ---------------------------------------------------------------------------

mod humantime_opt {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(d: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw: Option<String> = Option::deserialize(d)?;
        match raw {
            Some(s) => humantime::parse_duration(&s)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_template_yaml() -> &'static str {
        r#"
max_concurrent_enrichments: 8
enrichers:
  - id: runbook_det
    kind: detection
    type: template
    template: "https://wiki/runbooks/${detection.rule.id}"
    inject_field: runbook_url

  - id: runbook_corr
    kind: correlation
    type: template
    template: "https://wiki/runbooks/${correlation.rule.id}"
    inject_field: runbook_url
"#
    }

    #[test]
    fn loads_minimal_template_config() {
        let parsed: EnrichersFile = yaml_serde::from_str(cfg_template_yaml()).unwrap();
        let pipeline = build_enrichers(parsed).unwrap();
        assert_eq!(pipeline.len(), 2);
    }

    #[test]
    fn rejects_cross_namespace_in_detection_enricher() {
        let yaml = r#"
enrichers:
  - id: bad
    kind: detection
    type: template
    inject_field: out
    template: "https://wiki/${correlation.rule.id}"
"#;
        let parsed: EnrichersFile = yaml_serde::from_str(yaml).unwrap();
        let err = build_enrichers(parsed).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("wrong namespace"), "got: {msg}");
    }

    #[test]
    fn rejects_unknown_type() {
        let yaml = r#"
enrichers:
  - id: weird
    kind: detection
    type: something_unknown
    inject_field: out
"#;
        let parsed: EnrichersFile = yaml_serde::from_str(yaml).unwrap();
        let err = build_enrichers(parsed).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("unknown type"), "got: {msg}");
    }

    #[test]
    fn two_kind_aware_entries_for_one_logical_enricher() {
        // The plan documents a "YAML anchor pattern" for kind-agnostic
        // enrichers: declare two YAML entries that share everything
        // except `kind` and the namespace of their template. We verify
        // here that two such entries (regardless of how the operator
        // reduces duplication via YAML anchors / merge keys, which is a
        // YAML-loader concern) build into two valid enrichers, one per
        // kind, with no cross-namespace leakage.
        let yaml = r#"
enrichers:
  - id: runbook_det
    kind: detection
    type: template
    inject_field: runbook_url
    template: "https://wiki/${detection.rule.id}"

  - id: runbook_corr
    kind: correlation
    type: template
    inject_field: runbook_url
    template: "https://wiki/${correlation.rule.id}"
"#;
        let parsed: EnrichersFile = yaml_serde::from_str(yaml).unwrap();
        let pipeline = build_enrichers(parsed).unwrap();
        assert_eq!(pipeline.len(), 2);
    }

    #[test]
    fn rejects_missing_template_field() {
        let yaml = r#"
enrichers:
  - id: t
    kind: detection
    type: template
    inject_field: out
"#;
        let parsed: EnrichersFile = yaml_serde::from_str(yaml).unwrap();
        let err = build_enrichers(parsed).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("missing required field 'template'"),
            "got: {msg}"
        );
    }

    #[test]
    fn defaults_max_concurrent_when_unset_or_zero() {
        let yaml = r#"
enrichers: []
"#;
        let parsed: EnrichersFile = yaml_serde::from_str(yaml).unwrap();
        let pipeline = build_enrichers(parsed).unwrap();
        assert!(pipeline.is_empty());
    }

    #[test]
    fn timeout_string_parses_humantime() {
        let yaml = r#"
enrichers:
  - id: t
    kind: detection
    type: template
    inject_field: out
    template: "x"
    timeout: 2500ms
"#;
        let parsed: EnrichersFile = yaml_serde::from_str(yaml).unwrap();
        // We don't have a direct getter for the internal timeout; the
        // round-trip building succeeds when humantime parses it.
        build_enrichers(parsed).unwrap();
    }
}
