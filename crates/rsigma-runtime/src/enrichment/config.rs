//! YAML schema and loader for an enrichers config file.
//!
//! Loaded by the daemon at startup (and again on hot-reload) and by the MCP
//! server's `evaluate_events` tool. Validates that:
//! - every enricher declares a `kind: detection | correlation`,
//! - templated fields reference only the declared kind's namespace
//!   (`${detection.*}` or `${correlation.*}`) plus `${ENV_VAR}`,
//! - `scope.rules`, `scope.tags`, and `scope.levels` parse correctly,
//! - bespoke `type:` values map to a registered factory.
//!
//! Failures abort with a clear error pointing at the offending enricher id and
//! field. This lives in `rsigma-runtime` (rather than the CLI) so every
//! in-process consumer of the enrichment pipeline shares one loader.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use rsigma_eval::TenantId;

#[cfg(feature = "dns-enrich")]
use super::dns::{
    DEFAULT_DNS_CACHE_MAX_ENTRIES, DEFAULT_DNS_CACHE_TTL, DEFAULT_DNS_NEGATIVE_CACHE_TTL,
};
#[cfg(feature = "mmdb-enrich")]
use super::mmdb::DEFAULT_MMDB_CHECK_INTERVAL;
use crate::{
    CommandEnricher, EnricherKind, EnrichmentPipeline, HttpEnricher, HttpEnricherClient,
    HttpResponseCache, LookupEnricher, MetricsHook, NoopMetrics, OnError, OutputFormat, Scope,
    SourceCache, TemplateEnricher, build_default_http_client, lookup_builtin,
    validate_template_namespace,
};
#[cfg(feature = "dns-enrich")]
use crate::{DnsEnricher, DnsRecordType, DnsResolverConfig};
#[cfg(feature = "mmdb-enrich")]
use crate::{MmdbDatabase, MmdbEnricher, MmdbFields};
#[cfg(feature = "stix-enrich")]
use crate::{StixEnricher, StixEnricherQuery};
#[cfg(feature = "stix-enrich")]
use rstix::core::StixObjectKind;
#[cfg(feature = "stix-enrich")]
use rstix::store::StixStore;

/// Shared resources some enricher primitives require at construction time.
#[derive(Clone, Default)]
pub struct EnricherResources {
    /// Dynamic-pipelines source cache for `lookup` enrichers.
    pub source_cache: Option<std::sync::Arc<SourceCache>>,
    /// Local STIX store for `stix` enrichers (`stix-enrich` feature).
    #[cfg(feature = "stix-enrich")]
    pub stix_store: Option<std::sync::Arc<dyn StixStore>>,
}

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
#[serde(deny_unknown_fields)]
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
#[non_exhaustive]
pub struct EnricherConfig {
    /// Stable identifier for this enricher instance. Required.
    pub id: String,
    /// Required kind (`detection` or `correlation`).
    pub kind: KindLabel,
    /// Primitive type name (`template`, `lookup`, `http`, `command`, `stix`,
    /// `mmdb`, `dns`) or the `type:` of a bespoke enricher registered via
    /// [`register_builtin`](crate::register_builtin).
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
    /// `lookup`, `http`, `stix`, `mmdb`, and `dns`: behavior when the
    /// enricher finds no data. Defaults to `on_error`. Cannot be combined
    /// with `default`, which always handles a miss.
    #[serde(default, deserialize_with = "present_on_miss")]
    pub on_miss: Option<OnErrorLabel>,
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
    // primitives. They live on the same struct so YAML files round-trip
    // with the loader without needing per-phase reparse logic; missing
    // values produce a clear error when the matching primitive is selected.
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
    /// `http` response cache TTL, or `dns` positive-answer TTL cap. Off by
    /// default on `http`; the `dns` default is 5 minutes.
    #[serde(default, with = "humantime_opt")]
    pub cache_ttl: Option<Duration>,
    /// `http` / `lookup` / `dns`: optional extract expression applied to the
    /// fetched value before injection.
    #[serde(default)]
    pub extract: Option<String>,
    /// `http` / `lookup` / `dns`: extract language (`jq` / `jsonpath` /
    /// `cel`). Defaults to `jq` inside the primitive.
    #[serde(default)]
    pub extract_type: Option<String>,
    /// `command`: argv. The first element is the program; remaining
    /// elements are arguments. Each is template-expanded.
    #[serde(default)]
    pub command: Vec<String>,
    /// `command`: optional environment overrides.
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// `command`: how to interpret stdout. `json` (the default when unset)
    /// or `raw`.
    #[serde(default)]
    pub output: Option<OutputFormatLabel>,
    /// `lookup`: source ID of a dynamic source configured on the daemon.
    #[serde(default)]
    pub source: Option<String>,
    /// `lookup`, `http`, `stix`, `mmdb`, and `dns`: value injected on a miss
    /// (a source cache miss, an extract that matched nothing, no store
    /// objects, no record, no DNS records, or an HTTP status listed in
    /// `miss_status`), and for an `http` result that is `null`.
    /// Overrides `on_error` for misses only. Writing `default: null`
    /// injects `null` on a miss (`Some(Value::Null)`); omitting `default`
    /// (`None`) applies `on_miss`, or `on_error` when `on_miss` is absent.
    #[serde(default, deserialize_with = "present_value")]
    pub default: Option<serde_json::Value>,
    /// `http`: response statuses (each in `300..=599`) that are misses
    /// rather than failures. Empty treats no status as a miss.
    #[serde(default)]
    pub miss_status: Vec<u16>,

    /// `stix`: template-expanded STIX id for a direct store lookup.
    #[serde(default)]
    pub stix_id: Option<String>,
    /// `stix`: template-expanded substring for [`rstix::store::StixQuery::text_search`].
    #[serde(default)]
    pub text_search: Option<String>,
    /// `stix`: derive `text_search` from the first `attack.t*` technique tag.
    #[serde(default)]
    pub attack_technique: bool,
    /// `stix`: optional STIX type names (for example `indicator`).
    #[serde(default)]
    pub type_filter: Vec<String>,
    /// `stix`: maximum objects to inject (default **1**).
    #[serde(default)]
    pub max_results: Option<usize>,

    /// `mmdb`: path to an operator-supplied MaxMind DB file.
    #[serde(default)]
    pub db_path: Option<PathBuf>,
    /// `mmdb` / `dns`: template-expanded key (an IP address for `mmdb`, a
    /// name or IP address for `dns`).
    #[serde(default)]
    pub key: Option<String>,
    /// `mmdb`: optional dotted record paths to project into the injected
    /// object. Numeric segments are array indexes.
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
    /// `mmdb`: memory-map the database instead of reading it into memory.
    /// Requires the `mmdb-mmap` feature. The file must be replaced by
    /// renaming a new file over it, never rewritten in place. Entries that
    /// share a `db_path` must agree on it.
    #[serde(default)]
    pub mmap: bool,

    /// `dns`: required record type. One of the supported data types or the
    /// `IP` pseudo-type, case-insensitive.
    #[serde(default)]
    pub record_type: Option<String>,
    /// `dns`: optional nameservers (`IP` or `IP:port`). Empty uses the
    /// system resolver.
    #[serde(default)]
    pub nameservers: Vec<String>,
    /// `dns`: cap on negative (NXDOMAIN and NODATA) TTLs. Defaults to 1
    /// minute.
    #[serde(default, with = "humantime_opt")]
    pub negative_cache_ttl: Option<Duration>,
    /// `dns`: maximum number of cached responses. Defaults to 10000.
    #[serde(default)]
    pub cache_max_entries: Option<u64>,

    /// Keys the built-in schema does not recognize, kept as written so
    /// bespoke factories registered through
    /// [`register_builtin`](crate::register_builtin) receive them. The
    /// built-in types reject any key here with
    /// [`EnrichersConfigError::UnknownField`].
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// Deserialize a key that is present as `Some`, `null` included, so an
/// explicit `null` differs from an absent key.
fn present_value<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<serde_json::Value>, D::Error> {
    serde_json::Value::deserialize(d).map(Some)
}

/// Deserialize `on_miss` as `Some` whenever it is written, so `on_miss: null`
/// is the `null` policy rather than an absent key.
fn present_on_miss<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<OnErrorLabel>, D::Error> {
    OnErrorLabel::deserialize(d).map(Some)
}

/// Keys every enricher type accepts.
const COMMON_KEYS: &[&str] = &[
    "id",
    "kind",
    "type",
    "inject_field",
    "timeout",
    "on_error",
    "scope",
];

/// Type-specific keys each built-in type accepts, or `None` for a bespoke
/// type, which owns its schema.
fn type_keys(type_name: &str) -> Option<&'static [&'static str]> {
    Some(match type_name {
        "template" => &["template"],
        "lookup" => &["source", "extract", "extract_type", "default", "on_miss"],
        "http" => &[
            "url",
            "method",
            "headers",
            "body",
            "cache_ttl",
            "extract",
            "extract_type",
            "default",
            "miss_status",
            "on_miss",
        ],
        "command" => &["command", "env", "output"],
        "stix" => &[
            "stix_id",
            "text_search",
            "attack_technique",
            "type_filter",
            "max_results",
            "extract",
            "extract_type",
            "default",
            "on_miss",
        ],
        "mmdb" => &["db_path", "key", "fields", "default", "on_miss", "mmap"],
        "dns" => &[
            "key",
            "record_type",
            "nameservers",
            "cache_ttl",
            "negative_cache_ttl",
            "cache_max_entries",
            "extract",
            "extract_type",
            "default",
            "on_miss",
        ],
        _ => return None,
    })
}

impl EnricherConfig {
    /// Type-specific keys that are set, in field order. A key set to its
    /// empty value (`headers: {}`, `attack_technique: false`,
    /// `miss_status: []`, `mmap: false`) counts as absent. `default` counts
    /// as present whenever it is written, `default: null` included.
    fn present_keys(&self) -> Vec<&'static str> {
        let mut keys = Vec::new();
        let mut push = |set: bool, key: &'static str| {
            if set {
                keys.push(key);
            }
        };
        push(self.template.is_some(), "template");
        push(self.url.is_some(), "url");
        push(self.method.is_some(), "method");
        push(!self.headers.is_empty(), "headers");
        push(self.body.is_some(), "body");
        push(self.cache_ttl.is_some(), "cache_ttl");
        push(self.extract.is_some(), "extract");
        push(self.extract_type.is_some(), "extract_type");
        push(!self.command.is_empty(), "command");
        push(!self.env.is_empty(), "env");
        push(self.output.is_some(), "output");
        push(self.source.is_some(), "source");
        push(self.default.is_some(), "default");
        push(!self.miss_status.is_empty(), "miss_status");
        push(self.on_miss.is_some(), "on_miss");
        push(self.stix_id.is_some(), "stix_id");
        push(self.text_search.is_some(), "text_search");
        push(self.attack_technique, "attack_technique");
        push(!self.type_filter.is_empty(), "type_filter");
        push(self.max_results.is_some(), "max_results");
        push(self.db_path.is_some(), "db_path");
        push(self.key.is_some(), "key");
        push(!self.fields.is_empty(), "fields");
        push(self.mmap, "mmap");
        push(self.record_type.is_some(), "record_type");
        push(!self.nameservers.is_empty(), "nameservers");
        push(self.negative_cache_ttl.is_some(), "negative_cache_ttl");
        push(self.cache_max_entries.is_some(), "cache_max_entries");
        keys
    }

    /// Every string field this enricher's primitive renders as a template.
    ///
    /// Bespoke types expose every templated field, because the runtime cannot
    /// know which one their factory reads.
    pub fn rendered_fields(&self) -> impl Iterator<Item = &str> + '_ {
        let mut fields: Vec<&str> = Vec::new();
        match self.type_name.as_str() {
            "template" => fields.extend(self.template.as_deref()),
            "lookup" => fields.extend(self.extract.as_deref()),
            "stix" => {
                fields.extend(self.stix_id.as_deref());
                fields.extend(self.text_search.as_deref());
                fields.extend(self.extract.as_deref());
            }
            "http" => {
                fields.extend(self.url.as_deref());
                fields.extend(self.body.as_deref());
                fields.extend(self.headers.values().map(String::as_str));
            }
            "command" => {
                fields.extend(self.command.iter().map(String::as_str));
                fields.extend(self.env.values().map(String::as_str));
            }
            "mmdb" | "dns" => fields.extend(self.key.as_deref()),
            _ => {
                fields.extend(self.template.as_deref());
                fields.extend(self.url.as_deref());
                fields.extend(self.headers.values().map(String::as_str));
                fields.extend(self.body.as_deref());
                fields.extend(self.extract.as_deref());
                fields.extend(self.command.iter().map(String::as_str));
                fields.extend(self.env.values().map(String::as_str));
                fields.extend(self.stix_id.as_deref());
                fields.extend(self.text_search.as_deref());
                fields.extend(self.key.as_deref());
            }
        }
        fields.into_iter()
    }
}

/// Whether an enricher entry reads a detection payload the engine must retain.
fn config_needs_event(cfg: &EnricherConfig) -> bool {
    cfg.rendered_fields()
        .any(super::references_detection_payload)
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

/// `on_error:` and `on_miss:` discriminator.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnErrorLabel {
    #[default]
    Skip,
    Null,
    Drop,
}

impl OnErrorLabel {
    fn as_str(self) -> &'static str {
        match self {
            OnErrorLabel::Skip => "skip",
            OnErrorLabel::Null => "null",
            OnErrorLabel::Drop => "drop",
        }
    }
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
#[serde(deny_unknown_fields)]
pub struct ScopeConfig {
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub levels: Vec<String>,
    #[serde(default)]
    pub tenants: Vec<String>,
}

/// Errors produced while loading or validating an enrichers config.
#[derive(Debug)]
#[non_exhaustive]
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
    /// A built-in enricher set a key that no enricher type accepts.
    UnknownField {
        enricher_id: String,
        type_name: String,
        field: String,
        /// The common keys followed by the type's keys.
        supported: Vec<&'static str>,
    },
    /// A built-in enricher set a key that belongs to another type.
    InapplicableField {
        enricher_id: String,
        type_name: String,
        field: &'static str,
        /// The common keys followed by the type's keys.
        supported: Vec<&'static str>,
    },
    /// Template-namespace validator rejected a reference.
    Template(crate::TemplateError),
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
    /// An `mmdb` database could not be opened.
    Database {
        enricher_id: String,
        path: PathBuf,
        message: String,
    },
    /// A key holds a value the enricher cannot use, or a combination of
    /// keys has no effect.
    InvalidValue {
        enricher_id: String,
        field: &'static str,
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
                "enricher '{enricher_id}': unknown type '{type_name}' (built-ins: template, lookup, http, command{STIX_BUILTIN}{MMDB_BUILTIN}{DNS_BUILTIN}; bespoke types must register_builtin() before daemon start)",
                STIX_BUILTIN = if cfg!(feature = "stix-enrich") {
                    ", stix"
                } else {
                    ""
                },
                MMDB_BUILTIN = if cfg!(feature = "mmdb-enrich") {
                    ", mmdb"
                } else {
                    ""
                },
                DNS_BUILTIN = if cfg!(feature = "dns-enrich") {
                    ", dns"
                } else {
                    ""
                }
            ),
            EnrichersConfigError::MissingField {
                enricher_id,
                type_name,
                field,
            } => write!(
                f,
                "enricher '{enricher_id}' (type: {type_name}): missing required field '{field}'"
            ),
            EnrichersConfigError::UnknownField {
                enricher_id,
                type_name,
                field,
                supported,
            } => write!(
                f,
                "enricher '{enricher_id}' (type: {type_name}): unknown field '{field}' (supported: {})",
                supported.join(", ")
            ),
            EnrichersConfigError::InapplicableField {
                enricher_id,
                type_name,
                field,
                supported,
            } => write!(
                f,
                "enricher '{enricher_id}' (type: {type_name}): field '{field}' does not apply to type '{type_name}' (supported: {})",
                supported.join(", ")
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
            EnrichersConfigError::Database {
                enricher_id,
                path,
                message,
            } => write!(
                f,
                "enricher '{enricher_id}': cannot open database '{}': {message}",
                path.display()
            ),
            EnrichersConfigError::InvalidValue {
                enricher_id,
                field,
                message,
            } => write!(f, "enricher '{enricher_id}': invalid '{field}': {message}"),
        }
    }
}

impl std::error::Error for EnrichersConfigError {}

/// Read, deserialize, and validate an enrichers config file with
/// [`parse_enrichers_config`].
pub fn load_enrichers_file(path: &Path) -> Result<EnrichersFile, EnrichersConfigError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| EnrichersConfigError::Io(e, path.to_path_buf()))?;
    parse_enrichers_config(&text)
}

/// Parse an enrichers config and run every check that needs no I/O.
///
/// Rejects malformed YAML, unknown top-level and `scope` keys, enricher
/// keys that are unknown or do not apply to the entry's `type:`, template
/// references outside the entry's `kind:` namespace, invalid scopes, and
/// unknown `extract_type` values. It does not open databases, build HTTP
/// clients, or resolve sources. [`build_enrichers`] runs the same checks
/// before building each enricher.
pub fn parse_enrichers_config(text: &str) -> Result<EnrichersFile, EnrichersConfigError> {
    let parsed: EnrichersFile = yaml_serde::from_str(text).map_err(EnrichersConfigError::Yaml)?;
    for cfg in &parsed.enrichers {
        validate_entry(cfg)?;
        build_extract_expr(cfg)?;
    }
    Ok(parsed)
}

/// Construct an [`EnrichmentPipeline`] from a parsed config with default
/// (no-op) metrics and no source cache.
///
/// This is split from [`load_enrichers_file`] so unit tests and in-process
/// consumers can build a pipeline from a programmatically constructed
/// [`EnrichersFile`] without going through the disk. `lookup` enrichers require
/// a source cache and will error here; use [`build_enrichers_full`] to provide
/// one.
pub fn build_enrichers(file: EnrichersFile) -> Result<EnrichmentPipeline, EnrichersConfigError> {
    build_enrichers_full(
        file,
        EnricherResources::default(),
        std::sync::Arc::new(NoopMetrics),
    )
}

/// Like [`build_enrichers`] but accepts an optional shared [`SourceCache`] for
/// `lookup` enrichers and a metrics hook the pipeline (and per-enricher cache
/// lookups) report into. The daemon passes its Prometheus-backed `Metrics`
/// here.
///
/// All HTTP enrichers in the resulting pipeline share a single
/// `reqwest::Client` (wrapped in [`HttpEnricherClient`]) so connection
/// pooling works at the process level.
pub fn build_enrichers_full(
    file: EnrichersFile,
    resources: EnricherResources,
    metrics: std::sync::Arc<dyn MetricsHook>,
) -> Result<EnrichmentPipeline, EnrichersConfigError> {
    let http_client =
        build_default_http_client().map_err(|message| EnrichersConfigError::BespokeFactory {
            enricher_id: "<global>".to_string(),
            message,
        })?;
    let mut ctx = BuildContext {
        http_client,
        resources: &resources,
        metrics: metrics.clone(),
        #[cfg(feature = "mmdb-enrich")]
        mmdb_databases: HashMap::new(),
    };
    let needs_event = file.enrichers.iter().any(config_needs_event);
    let mut enrichers: Vec<Box<dyn crate::Enricher>> = Vec::with_capacity(file.enrichers.len());
    for cfg in file.enrichers {
        enrichers.push(build_one(cfg, &mut ctx)?);
    }
    let cap = file
        .max_concurrent_enrichments
        .unwrap_or(DEFAULT_MAX_CONCURRENT_ENRICHMENTS);
    let mut pipeline = EnrichmentPipeline::new(enrichers, cap).with_metrics(metrics);
    pipeline.set_needs_event(needs_event);
    Ok(pipeline)
}

/// State shared by every [`build_one`] call in one
/// [`build_enrichers_full`] invocation.
struct BuildContext<'a> {
    http_client: HttpEnricherClient,
    resources: &'a EnricherResources,
    metrics: std::sync::Arc<dyn MetricsHook>,
    /// Databases opened during this build, keyed by canonical path, so
    /// several enricher entries for one file share a single reader.
    #[cfg(feature = "mmdb-enrich")]
    mmdb_databases: HashMap<PathBuf, OpenedMmdb>,
}

/// A database opened during one build, with the entry that opened it.
#[cfg(feature = "mmdb-enrich")]
struct OpenedMmdb {
    db: std::sync::Arc<MmdbDatabase>,
    enricher_id: String,
    mmap: bool,
}

/// Run the checks on one config block that need no I/O: its scope,
/// template-namespace references, and keys. Returns the parsed kind and
/// scope.
fn validate_entry(cfg: &EnricherConfig) -> Result<(EnricherKind, Scope), EnrichersConfigError> {
    let kind: EnricherKind = cfg.kind.into();

    let scope = match &cfg.scope {
        Some(s) => {
            let tenants = s
                .tenants
                .iter()
                .map(|tenant| TenantId::new(tenant))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| EnrichersConfigError::Scope {
                    enricher_id: cfg.id.clone(),
                    message: error.to_string(),
                })?;
            Scope::new(s.rules.clone(), s.tags.clone(), s.levels.clone())
                .map_err(|message| EnrichersConfigError::Scope {
                    enricher_id: cfg.id.clone(),
                    message,
                })?
                .with_tenants(tenants)
        }
        None => Scope::default(),
    };

    // Validate template-namespace references on every templated field.
    // The full set of templated fields is type-dependent, but every
    // primitive shares the same namespace rules, so we run the
    // validator once per field that the chosen primitive touches.
    validate_templated_fields(cfg, kind)?;
    validate_keys(cfg)?;
    validate_values(cfg)?;
    Ok((kind, scope))
}

/// Reject key values that pass deserialization but cannot be used.
fn validate_values(cfg: &EnricherConfig) -> Result<(), EnrichersConfigError> {
    if let Some(status) = cfg
        .miss_status
        .iter()
        .find(|status| !(300..=599).contains(*status))
    {
        return Err(EnrichersConfigError::InvalidValue {
            enricher_id: cfg.id.clone(),
            field: "miss_status",
            message: format!("status {status} is outside 300..=599"),
        });
    }
    if cfg.on_miss.is_some() && cfg.default.is_some() {
        return Err(EnrichersConfigError::InvalidValue {
            enricher_id: cfg.id.clone(),
            field: "on_miss",
            message: "has no effect when 'default' is set".to_string(),
        });
    }
    Ok(())
}

/// Reject keys a built-in type does not accept. Runs before type dispatch
/// so the error is the same whether or not the type's feature is compiled
/// in.
fn validate_keys(cfg: &EnricherConfig) -> Result<(), EnrichersConfigError> {
    let Some(keys) = type_keys(&cfg.type_name) else {
        return Ok(());
    };
    let supported = || COMMON_KEYS.iter().chain(keys).copied().collect();
    if let Some(field) = cfg.extra.keys().next() {
        return Err(EnrichersConfigError::UnknownField {
            enricher_id: cfg.id.clone(),
            type_name: cfg.type_name.clone(),
            field: field.clone(),
            supported: supported(),
        });
    }
    if let Some(field) = cfg.present_keys().into_iter().find(|k| !keys.contains(k)) {
        return Err(EnrichersConfigError::InapplicableField {
            enricher_id: cfg.id.clone(),
            type_name: cfg.type_name.clone(),
            field,
            supported: supported(),
        });
    }
    Ok(())
}

/// Build a single [`Enricher`](crate::Enricher) from one YAML config block.
///
/// Pulled out of `build_enrichers_full` so the loader's match on
/// `type_name` stays linear and so future primitives can be added by
/// extending one match arm.
fn build_one(
    cfg: EnricherConfig,
    ctx: &mut BuildContext<'_>,
) -> Result<Box<dyn crate::Enricher>, EnrichersConfigError> {
    let (kind, scope) = validate_entry(&cfg)?;
    let on_error: OnError = cfg.on_error.into();
    let on_miss: OnError = cfg.on_miss.map_or(on_error, Into::into);
    let timeout = cfg.timeout.unwrap_or(DEFAULT_ENRICHER_TIMEOUT);

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
            let default = cfg.default.clone();
            let miss_status = cfg.miss_status.clone();
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
                    ctx.http_client.clone(),
                    cache,
                )
                .with_default(default)
                .with_miss_status(miss_status)
                .with_on_miss(on_miss)
                .with_metrics(ctx.metrics.clone()),
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
                cfg.output.unwrap_or_default().into(),
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
            let cache =
                ctx.resources
                    .source_cache
                    .clone()
                    .ok_or(EnrichersConfigError::MissingField {
                        enricher_id: cfg.id.clone(),
                        type_name: cfg.type_name.clone(),
                        field: "<source_cache: no dynamic sources configured; \
                            pass --source <file> to the daemon to declare sources>",
                    })?;
            let extract = build_extract_expr(&cfg)?;
            Ok(Box::new(
                LookupEnricher::new(
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
                )
                .with_on_miss(on_miss),
            ))
        }
        #[cfg(feature = "stix-enrich")]
        "stix" => {
            let store =
                ctx.resources
                    .stix_store
                    .clone()
                    .ok_or(EnrichersConfigError::MissingField {
                        enricher_id: cfg.id.clone(),
                        type_name: cfg.type_name.clone(),
                        field: "<stix_store: no STIX store configured; \
                        pass --stix-store <dir> to the daemon (same layout as taxii sync --store)>",
                    })?;
            if cfg.stix_id.is_none() && cfg.text_search.is_none() && !cfg.attack_technique {
                return Err(EnrichersConfigError::MissingField {
                    enricher_id: cfg.id.clone(),
                    type_name: cfg.type_name.clone(),
                    field: "stix_id | text_search | attack_technique",
                });
            }
            let type_filter = parse_stix_type_filter(&cfg)?;
            let extract = build_extract_expr(&cfg)?;
            let query = StixEnricherQuery {
                stix_id: cfg.stix_id.clone(),
                text_search: cfg.text_search.clone(),
                attack_technique: cfg.attack_technique,
                type_filter,
                max_results: cfg.max_results.unwrap_or(1).max(1),
            };
            Ok(Box::new(
                StixEnricher::new(
                    cfg.id,
                    kind,
                    cfg.inject_field,
                    query,
                    extract,
                    cfg.default,
                    timeout,
                    on_error,
                    scope,
                    store,
                )
                .with_on_miss(on_miss),
            ))
        }
        #[cfg(not(feature = "stix-enrich"))]
        "stix" => Err(EnrichersConfigError::BespokeFactory {
            enricher_id: cfg.id.clone(),
            message: "stix enricher requires the stix-enrich feature".into(),
        }),
        #[cfg(feature = "mmdb-enrich")]
        "mmdb" => {
            let db_path = cfg
                .db_path
                .clone()
                .ok_or(EnrichersConfigError::MissingField {
                    enricher_id: cfg.id.clone(),
                    type_name: cfg.type_name.clone(),
                    field: "db_path",
                })?;
            let key = cfg.key.clone().ok_or(EnrichersConfigError::MissingField {
                enricher_id: cfg.id.clone(),
                type_name: cfg.type_name.clone(),
                field: "key",
            })?;
            let fields = if cfg.fields.is_empty() {
                None
            } else {
                Some(MmdbFields::parse(&cfg.fields).map_err(|message| {
                    EnrichersConfigError::Scope {
                        enricher_id: cfg.id.clone(),
                        message,
                    }
                })?)
            };
            if cfg.mmap && !cfg!(feature = "mmdb-mmap") {
                return Err(EnrichersConfigError::InvalidValue {
                    enricher_id: cfg.id.clone(),
                    field: "mmap",
                    message: "mmap: true requires the mmdb-mmap feature".to_string(),
                });
            }
            let db = open_mmdb_database(ctx, &cfg.id, &db_path, cfg.mmap)?;
            Ok(Box::new(
                MmdbEnricher::new(
                    cfg.id,
                    kind,
                    cfg.inject_field,
                    key,
                    fields,
                    cfg.default,
                    timeout,
                    on_error,
                    scope,
                    db,
                )
                .with_on_miss(on_miss)
                .with_metrics(std::sync::Arc::clone(&ctx.metrics)),
            ))
        }
        #[cfg(not(feature = "mmdb-enrich"))]
        "mmdb" => Err(EnrichersConfigError::BespokeFactory {
            enricher_id: cfg.id.clone(),
            message: "mmdb enricher requires the mmdb-enrich feature".into(),
        }),
        #[cfg(feature = "dns-enrich")]
        "dns" => {
            let key = cfg.key.clone().ok_or(EnrichersConfigError::MissingField {
                enricher_id: cfg.id.clone(),
                type_name: cfg.type_name.clone(),
                field: "key",
            })?;
            let record_type_raw =
                cfg.record_type
                    .clone()
                    .ok_or(EnrichersConfigError::MissingField {
                        enricher_id: cfg.id.clone(),
                        type_name: cfg.type_name.clone(),
                        field: "record_type",
                    })?;
            let record_type = DnsRecordType::parse(&record_type_raw).map_err(|message| {
                EnrichersConfigError::Scope {
                    enricher_id: cfg.id.clone(),
                    message,
                }
            })?;
            let nameservers = cfg
                .nameservers
                .iter()
                .map(|raw| DnsResolverConfig::parse_nameserver(raw))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|message| EnrichersConfigError::Scope {
                    enricher_id: cfg.id.clone(),
                    message,
                })?;
            let cache_max_entries = cfg
                .cache_max_entries
                .unwrap_or(DEFAULT_DNS_CACHE_MAX_ENTRIES);
            if cache_max_entries == 0 {
                return Err(EnrichersConfigError::Scope {
                    enricher_id: cfg.id.clone(),
                    message: "cache_max_entries must be greater than 0".into(),
                });
            }
            let resolver = DnsResolverConfig {
                nameservers,
                timeout,
                cache_ttl: cfg.cache_ttl.unwrap_or(DEFAULT_DNS_CACHE_TTL),
                negative_cache_ttl: cfg
                    .negative_cache_ttl
                    .unwrap_or(DEFAULT_DNS_NEGATIVE_CACHE_TTL),
                cache_max_entries,
            };
            let extract = build_extract_expr(&cfg)?;
            let enricher = DnsEnricher::new(
                cfg.id.clone(),
                kind,
                cfg.inject_field,
                key,
                record_type,
                extract,
                cfg.default,
                timeout,
                on_error,
                scope,
                resolver,
            )
            .map_err(|message| EnrichersConfigError::Scope {
                enricher_id: cfg.id.clone(),
                message,
            })?
            .with_on_miss(on_miss)
            .with_metrics(std::sync::Arc::clone(&ctx.metrics));
            Ok(Box::new(enricher))
        }
        #[cfg(not(feature = "dns-enrich"))]
        "dns" => Err(EnrichersConfigError::BespokeFactory {
            enricher_id: cfg.id.clone(),
            message: "dns enricher requires the dns-enrich feature".into(),
        }),
        other => {
            // Bespoke type: look up factory and pass the raw config block.
            let factory = lookup_builtin(other).ok_or(EnrichersConfigError::UnknownType {
                enricher_id: cfg.id.clone(),
                type_name: other.to_string(),
            })?;
            // Re-serialize the entire config block, custom keys included,
            // as JSON so the factory can deserialize whatever schema it
            // needs.
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

/// Open an MMDB database, reusing one already opened in this build. Entries
/// that share a database must agree on `mmap`.
#[cfg(feature = "mmdb-enrich")]
fn open_mmdb_database(
    ctx: &mut BuildContext<'_>,
    enricher_id: &str,
    db_path: &Path,
    mmap: bool,
) -> Result<std::sync::Arc<MmdbDatabase>, EnrichersConfigError> {
    let key = std::fs::canonicalize(db_path).unwrap_or_else(|_| db_path.to_path_buf());
    if let Some(opened) = ctx.mmdb_databases.get(&key) {
        if opened.mmap != mmap {
            return Err(EnrichersConfigError::InvalidValue {
                enricher_id: enricher_id.to_string(),
                field: "mmap",
                message: format!(
                    "enricher '{}' opens '{}' with mmap: {}, and entries that share a database must agree",
                    opened.enricher_id,
                    db_path.display(),
                    opened.mmap
                ),
            });
        }
        return Ok(std::sync::Arc::clone(&opened.db));
    }
    let db = std::sync::Arc::new(
        MmdbDatabase::open_file(db_path, DEFAULT_MMDB_CHECK_INTERVAL, mmap)
            .map_err(|message| EnrichersConfigError::Database {
                enricher_id: enricher_id.to_string(),
                path: db_path.to_path_buf(),
                message,
            })?
            .with_metrics(
                std::sync::Arc::clone(&ctx.metrics),
                db_path.display().to_string(),
            ),
    );
    ctx.mmdb_databases.insert(
        key,
        OpenedMmdb {
            db: std::sync::Arc::clone(&db),
            enricher_id: enricher_id.to_string(),
            mmap,
        },
    );
    Ok(db)
}

/// Build an [`ExtractExpr`](rsigma_eval::pipeline::sources::ExtractExpr)
/// from `cfg.extract` + `cfg.extract_type`. `None` when no extract is
/// configured. Defaults to `jq` when an extract expression is set
/// without an explicit type, matching the pipeline-source convention.
#[cfg(feature = "stix-enrich")]
fn parse_stix_type_filter(
    cfg: &EnricherConfig,
) -> Result<Vec<StixObjectKind>, EnrichersConfigError> {
    cfg.type_filter
        .iter()
        .map(|type_name| {
            StixObjectKind::from_type_str(type_name).ok_or_else(|| EnrichersConfigError::Scope {
                enricher_id: cfg.id.clone(),
                message: format!(
                    "unknown STIX type '{type_name}' in type_filter (custom x_* types cannot be filtered; omit type_filter and rely on text_search)"
                ),
            })
        })
        .collect()
}

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
        crate::validate_url_tenant_position(u).map_err(|message| EnrichersConfigError::Scope {
            enricher_id: id.to_string(),
            message,
        })?;
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
    if let Some(id) = &cfg.stix_id {
        check(id, "stix_id")?;
    }
    if let Some(search) = &cfg.text_search {
        check(search, "text_search")?;
    }
    if let Some(key) = &cfg.key {
        check(key, "key")?;
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
        m.serialize_entry("on_error", self.on_error.as_str())?;
        if let Some(on_miss) = self.on_miss {
            m.serialize_entry("on_miss", on_miss.as_str())?;
        }
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
        if let Some(t) = &self.negative_cache_ttl {
            m.serialize_entry("negative_cache_ttl_ms", &(t.as_millis() as u64))?;
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
        if let Some(output) = &self.output {
            m.serialize_entry(
                "output",
                match output {
                    OutputFormatLabel::Json => "json",
                    OutputFormatLabel::Raw => "raw",
                },
            )?;
        }
        if let Some(s) = &self.source {
            m.serialize_entry("source", s)?;
        }
        if let Some(d) = &self.default {
            m.serialize_entry("default", d)?;
        }
        if !self.miss_status.is_empty() {
            m.serialize_entry("miss_status", &self.miss_status)?;
        }
        if let Some(id) = &self.stix_id {
            m.serialize_entry("stix_id", id)?;
        }
        if let Some(search) = &self.text_search {
            m.serialize_entry("text_search", search)?;
        }
        if self.attack_technique {
            m.serialize_entry("attack_technique", &self.attack_technique)?;
        }
        if !self.type_filter.is_empty() {
            m.serialize_entry("type_filter", &self.type_filter)?;
        }
        if let Some(max) = &self.max_results {
            m.serialize_entry("max_results", max)?;
        }
        if let Some(path) = &self.db_path {
            m.serialize_entry("db_path", path)?;
        }
        if let Some(key) = &self.key {
            m.serialize_entry("key", key)?;
        }
        if !self.fields.is_empty() {
            m.serialize_entry("fields", &self.fields)?;
        }
        if self.mmap {
            m.serialize_entry("mmap", &self.mmap)?;
        }
        if let Some(record_type) = &self.record_type {
            m.serialize_entry("record_type", record_type)?;
        }
        if !self.nameservers.is_empty() {
            m.serialize_entry("nameservers", &self.nameservers)?;
        }
        if let Some(max) = &self.cache_max_entries {
            m.serialize_entry("cache_max_entries", max)?;
        }
        for (k, v) in &self.extra {
            m.serialize_entry(k, v)?;
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
                .map_err(|e| serde::de::Error::custom(format_args!("invalid duration {s:?}: {e}"))),
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
    fn rejects_ocsf_reference_in_an_enricher() {
        let yaml = r#"
enrichers:
  - id: bad
    kind: detection
    type: http
    inject_field: out
    url: "https://intel.example/lookup"
    method: POST
    body: '{"finding": ${detection.ocsf}}'
"#;
        let parsed: EnrichersFile = yaml_serde::from_str(yaml).unwrap();
        let err = build_enrichers(parsed).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("only valid as a whole JSON value in a webhook body"),
            "got: {msg}"
        );
        assert!(msg.contains("field 'body'"), "got: {msg}");
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

    #[cfg(feature = "stix-enrich")]
    #[test]
    fn stix_enricher_requires_store() {
        let yaml = r#"
enrichers:
  - id: intel
    kind: detection
    type: stix
    inject_field: stix
    text_search: "${detection.fields.Hash}"
"#;
        let parsed: EnrichersFile = yaml_serde::from_str(yaml).unwrap();
        let err = build_enrichers(parsed).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("stix_store"), "got: {msg}");
    }

    #[cfg(feature = "stix-enrich")]
    #[test]
    fn stix_enricher_requires_query_mode() {
        use rstix::store::MemoryStore;

        let yaml = r#"
enrichers:
  - id: intel
    kind: detection
    type: stix
    inject_field: stix
"#;
        let parsed: EnrichersFile = yaml_serde::from_str(yaml).unwrap();
        let store = std::sync::Arc::new(MemoryStore::new());
        let err = build_enrichers_full(
            parsed,
            EnricherResources {
                stix_store: Some(store),
                ..EnricherResources::default()
            },
            std::sync::Arc::new(NoopMetrics),
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("stix_id | text_search | attack_technique"),
            "got: {msg}"
        );
    }

    #[cfg(feature = "mmdb-enrich")]
    fn mmdb_fixture(name: &str) -> String {
        format!("{}/tests/fixtures/mmdb/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    #[cfg(feature = "mmdb-enrich")]
    #[test]
    fn mmdb_enricher_requires_db_path() {
        let yaml = r#"
enrichers:
  - id: geo
    kind: detection
    type: mmdb
    inject_field: geo
    key: "${detection.fields.SourceIp}"
"#;
        let parsed: EnrichersFile = yaml_serde::from_str(yaml).unwrap();
        let err = build_enrichers(parsed).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("missing required field 'db_path'"),
            "got: {msg}"
        );
    }

    #[cfg(feature = "mmdb-enrich")]
    #[test]
    fn mmdb_enricher_requires_key() {
        let yaml = format!(
            r#"
enrichers:
  - id: geo
    kind: detection
    type: mmdb
    inject_field: geo
    db_path: {}
"#,
            mmdb_fixture("city-test.mmdb")
        );
        let parsed: EnrichersFile = yaml_serde::from_str(&yaml).unwrap();
        let err = build_enrichers(parsed).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("missing required field 'key'"), "got: {msg}");
    }

    #[cfg(feature = "mmdb-enrich")]
    #[test]
    fn mmdb_enricher_rejects_missing_database() {
        let yaml = r#"
enrichers:
  - id: geo
    kind: detection
    type: mmdb
    inject_field: geo
    db_path: /definitely/not/here.mmdb
    key: "${detection.fields.SourceIp}"
"#;
        let parsed: EnrichersFile = yaml_serde::from_str(yaml).unwrap();
        let err = build_enrichers(parsed).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("cannot open database '/definitely/not/here.mmdb'"),
            "got: {msg}"
        );
    }

    #[cfg(feature = "mmdb-enrich")]
    #[test]
    fn mmdb_enricher_rejects_bad_field_path() {
        let yaml = format!(
            r#"
enrichers:
  - id: geo
    kind: detection
    type: mmdb
    inject_field: geo
    db_path: {}
    key: "${{detection.fields.SourceIp}}"
    fields:
      country: country..iso_code
"#,
            mmdb_fixture("city-test.mmdb")
        );
        let parsed: EnrichersFile = yaml_serde::from_str(&yaml).unwrap();
        let err = build_enrichers(parsed).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("empty segment"), "got: {msg}");
    }

    #[cfg(feature = "mmdb-enrich")]
    #[test]
    fn mmdb_enricher_rejects_cross_namespace_key() {
        let yaml = format!(
            r#"
enrichers:
  - id: geo
    kind: detection
    type: mmdb
    inject_field: geo
    db_path: {}
    key: "${{correlation.group_key.SourceIp}}"
"#,
            mmdb_fixture("city-test.mmdb")
        );
        let parsed: EnrichersFile = yaml_serde::from_str(&yaml).unwrap();
        let err = build_enrichers(parsed).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("wrong namespace"), "got: {msg}");
    }

    #[cfg(feature = "mmdb-enrich")]
    #[test]
    fn mmdb_databases_are_shared_within_one_build() {
        let resources = EnricherResources::default();
        let mut ctx = BuildContext {
            http_client: build_default_http_client().unwrap(),
            resources: &resources,
            metrics: std::sync::Arc::new(NoopMetrics),
            mmdb_databases: HashMap::new(),
        };
        let path = PathBuf::from(mmdb_fixture("city-test.mmdb"));
        let respelled = PathBuf::from(format!(
            "{}/tests/fixtures/./mmdb/../mmdb/city-test.mmdb",
            env!("CARGO_MANIFEST_DIR")
        ));
        let a = open_mmdb_database(&mut ctx, "a", &path, false).unwrap();
        let b = open_mmdb_database(&mut ctx, "b", &path, false).unwrap();
        let c = open_mmdb_database(&mut ctx, "c", &respelled, false).unwrap();
        assert!(std::sync::Arc::ptr_eq(&a, &b));
        assert!(std::sync::Arc::ptr_eq(&a, &c));
    }

    #[cfg(feature = "mmdb-enrich")]
    fn two_mmdb_entries(first_mmap: bool, second_mmap: bool) -> String {
        let path = mmdb_fixture("city-test.mmdb");
        let mut yaml = String::from("enrichers:\n");
        for (id, mmap) in [("geo_a", first_mmap), ("geo_b", second_mmap)] {
            yaml.push_str(&format!(
                "  - id: {id}\n    kind: detection\n    type: mmdb\n    inject_field: {id}\n    db_path: {path}\n    key: \"${{detection.fields.SourceIp}}\"\n    mmap: {mmap}\n"
            ));
        }
        yaml
    }

    #[cfg(feature = "mmdb-mmap")]
    #[test]
    fn mmdb_entries_on_one_database_must_agree_on_mmap() {
        for (first, second) in [(false, true), (true, false)] {
            let err = build_err(&two_mmdb_entries(first, second));
            match &err {
                EnrichersConfigError::InvalidValue {
                    enricher_id, field, ..
                } => {
                    assert_eq!(enricher_id, "geo_b");
                    assert_eq!(*field, "mmap");
                }
                other => panic!("expected InvalidValue, got {other}"),
            }
            let msg = err.to_string();
            assert!(
                msg.contains("enricher 'geo_b'")
                    && msg.contains("enricher 'geo_a'")
                    && msg.contains(&format!("mmap: {first}")),
                "got: {msg}"
            );
        }
        for mmap in [false, true] {
            let parsed: EnrichersFile =
                yaml_serde::from_str(&two_mmdb_entries(mmap, mmap)).unwrap();
            assert_eq!(build_enrichers(parsed).unwrap().len(), 2);
        }
    }

    #[cfg(all(feature = "mmdb-enrich", not(feature = "mmdb-mmap")))]
    #[test]
    fn mmap_requires_the_mmdb_mmap_feature() {
        let err = build_err(&two_mmdb_entries(true, true));
        assert!(
            matches!(
                err,
                EnrichersConfigError::InvalidValue { field: "mmap", .. }
            ),
            "got: {err}"
        );
        assert_eq!(
            err.to_string(),
            "enricher 'geo_a': invalid 'mmap': mmap: true requires the mmdb-mmap feature"
        );
        parse_enrichers_config(&two_mmdb_entries(true, true))
            .expect("the feature is checked when the database is opened");
    }

    #[cfg(not(feature = "mmdb-mmap"))]
    #[test]
    fn key_error_precedes_missing_mmap_feature() {
        let err = build_err(&entry_yaml(
            "mmdb",
            "db_path: x.mmdb\nkey: \"1.2.3.4\"\nmmap: true\nurl: \"https://example.com/\"",
        ));
        assert!(
            matches!(
                err,
                EnrichersConfigError::InapplicableField { field: "url", .. }
            ),
            "got: {err}"
        );
    }

    #[test]
    fn mmap_applies_only_to_mmdb() {
        let err = build_err(&entry_yaml("dns", "key: x\nrecord_type: A\nmmap: true"));
        assert!(
            matches!(
                err,
                EnrichersConfigError::InapplicableField { field: "mmap", .. }
            ),
            "got: {err}"
        );
        parse_enrichers_config(&entry_yaml("dns", "key: x\nrecord_type: A\nmmap: false"))
            .expect("mmap: false counts as absent");
    }

    #[test]
    fn mmap_is_serialized_for_bespoke_factories() {
        let cfg = first_entry(&entry_yaml("passive_dns", "mmap: true"));
        let raw = serde_json::to_value(&cfg).unwrap();
        assert_eq!(raw["mmap"], true);
        let cfg = first_entry(&entry_yaml("passive_dns", "mmap: false"));
        let raw = serde_json::to_value(&cfg).unwrap();
        assert_eq!(raw.get("mmap"), None);
    }

    #[cfg(not(feature = "mmdb-enrich"))]
    #[test]
    fn mmdb_enricher_requires_the_feature() {
        let yaml = r#"
enrichers:
  - id: geo
    kind: detection
    type: mmdb
    inject_field: geo
    db_path: /tmp/city.mmdb
    key: "${detection.fields.SourceIp}"
"#;
        let parsed: EnrichersFile = yaml_serde::from_str(yaml).unwrap();
        let err = build_enrichers(parsed).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("requires the mmdb-enrich feature"),
            "got: {msg}"
        );
    }

    #[cfg(feature = "dns-enrich")]
    fn dns_yaml(extra: &str) -> String {
        format!(
            r#"
enrichers:
  - id: resolve
    kind: detection
    type: dns
    inject_field: ips
    key: "${{detection.fields.Domain}}"
{extra}"#
        )
    }

    #[cfg(feature = "dns-enrich")]
    #[test]
    fn dns_enricher_requires_key() {
        let yaml = r#"
enrichers:
  - id: resolve
    kind: detection
    type: dns
    inject_field: ips
    record_type: A
"#;
        let parsed: EnrichersFile = yaml_serde::from_str(yaml).unwrap();
        let err = build_enrichers(parsed).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("missing required field 'key'"), "got: {msg}");
    }

    #[cfg(feature = "dns-enrich")]
    #[test]
    fn dns_enricher_requires_record_type() {
        let yaml = r#"
enrichers:
  - id: resolve
    kind: detection
    type: dns
    inject_field: ips
    key: "${detection.fields.Domain}"
"#;
        let parsed: EnrichersFile = yaml_serde::from_str(yaml).unwrap();
        let err = build_enrichers(parsed).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("missing required field 'record_type'"),
            "got: {msg}"
        );
    }

    #[cfg(feature = "dns-enrich")]
    #[test]
    fn dns_enricher_rejects_unsupported_record_type() {
        let yaml = dns_yaml("    record_type: RRSIG\n");
        let parsed: EnrichersFile = yaml_serde::from_str(&yaml).unwrap();
        let err = build_enrichers(parsed).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("unsupported record_type"), "got: {msg}");
        assert!(msg.contains("supported: IP"), "got: {msg}");
    }

    #[cfg(feature = "dns-enrich")]
    #[test]
    fn dns_enricher_rejects_bad_nameserver() {
        let yaml = dns_yaml("    record_type: A\n    nameservers: [resolver.example.com]\n");
        let parsed: EnrichersFile = yaml_serde::from_str(&yaml).unwrap();
        let err = build_enrichers(parsed).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("invalid nameserver"), "got: {msg}");
    }

    #[cfg(feature = "dns-enrich")]
    #[test]
    fn dns_enricher_rejects_zero_cache_max_entries() {
        let yaml = dns_yaml("    record_type: A\n    cache_max_entries: 0\n");
        let parsed: EnrichersFile = yaml_serde::from_str(&yaml).unwrap();
        let err = build_enrichers(parsed).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("cache_max_entries must be greater than 0"),
            "got: {msg}"
        );
    }

    #[cfg(feature = "dns-enrich")]
    #[test]
    fn dns_enricher_rejects_cross_namespace_key() {
        let yaml = r#"
enrichers:
  - id: resolve
    kind: detection
    type: dns
    inject_field: ips
    key: "${correlation.group_key.Domain}"
    record_type: A
"#;
        let parsed: EnrichersFile = yaml_serde::from_str(yaml).unwrap();
        let err = build_enrichers(parsed).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("wrong namespace"), "got: {msg}");
    }

    #[cfg(feature = "dns-enrich")]
    #[test]
    fn dns_enricher_builds_with_explicit_nameserver() {
        let yaml = dns_yaml("    record_type: A\n    nameservers: [\"127.0.0.1:5353\"]\n");
        let parsed: EnrichersFile = yaml_serde::from_str(&yaml).unwrap();
        let pipeline = build_enrichers(parsed).unwrap();
        assert_eq!(pipeline.len(), 1);
    }

    #[cfg(not(feature = "dns-enrich"))]
    #[test]
    fn dns_enricher_requires_the_feature() {
        let yaml = r#"
enrichers:
  - id: resolve
    kind: detection
    type: dns
    inject_field: ips
    key: "${detection.fields.Domain}"
    record_type: A
"#;
        let parsed: EnrichersFile = yaml_serde::from_str(yaml).unwrap();
        let err = build_enrichers(parsed).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("requires the dns-enrich feature"),
            "got: {msg}"
        );
    }

    /// One entry with the given `type:` and extra YAML lines, indented
    /// under the entry.
    fn entry_yaml(type_name: &str, extra: &str) -> String {
        let mut yaml = format!(
            "enrichers:\n  - id: e\n    kind: detection\n    type: {type_name}\n    inject_field: out\n"
        );
        for line in extra.lines() {
            yaml.push_str("    ");
            yaml.push_str(line);
            yaml.push('\n');
        }
        yaml
    }

    fn first_entry(yaml: &str) -> EnricherConfig {
        let parsed: EnrichersFile = yaml_serde::from_str(yaml).unwrap();
        parsed.enrichers.into_iter().next().unwrap()
    }

    fn build_err(yaml: &str) -> EnrichersConfigError {
        let parsed: EnrichersFile = yaml_serde::from_str(yaml).unwrap();
        match build_enrichers(parsed) {
            Ok(_) => panic!("expected an error for:\n{yaml}"),
            Err(e) => e,
        }
    }

    #[test]
    fn rejects_unknown_key() {
        let err = build_err(&entry_yaml("lookup", "source: users\ndefualt: {}"));
        let msg = err.to_string();
        match err {
            EnrichersConfigError::UnknownField {
                field, supported, ..
            } => {
                assert_eq!(field, "defualt");
                assert!(supported.contains(&"default"));
            }
            other => panic!("expected UnknownField, got {other}"),
        }
        assert!(
            msg.contains("unknown field 'defualt'") && msg.contains("default"),
            "got: {msg}"
        );
    }

    #[test]
    fn rejects_key_from_another_type() {
        let cases = [
            (
                "http",
                "url: \"https://example.com/\"\nfields: { a: b }",
                "fields",
            ),
            (
                "mmdb",
                "db_path: x.mmdb\nkey: \"1.2.3.4\"\nurl: \"https://example.com/\"",
                "url",
            ),
            (
                "command",
                "command: [\"true\"]\ntemplate: \"x\"",
                "template",
            ),
            ("template", "template: \"x\"\ndefault: 1", "default"),
            ("command", "command: [\"true\"]\ndefault: null", "default"),
        ];
        for (type_name, extra, field) in cases {
            let err = build_err(&entry_yaml(type_name, extra));
            let msg = err.to_string();
            match err {
                EnrichersConfigError::InapplicableField { field: f, .. } => {
                    assert_eq!(f, field, "type {type_name}");
                }
                other => panic!("type {type_name}: expected InapplicableField, got {other}"),
            }
            assert!(
                msg.contains(&format!(
                    "field '{field}' does not apply to type '{type_name}'"
                )),
                "got: {msg}"
            );
        }
    }

    #[test]
    fn empty_values_count_as_absent() {
        let cases = [
            ("template", "template: \"x\"\nheaders: {}"),
            (
                "http",
                "url: \"https://example.com/\"\nattack_technique: false",
            ),
        ];
        for (type_name, extra) in cases {
            let parsed: EnrichersFile =
                yaml_serde::from_str(&entry_yaml(type_name, extra)).unwrap();
            build_enrichers(parsed).unwrap_or_else(|e| panic!("type {type_name} should load: {e}"));
        }
    }

    #[cfg(not(feature = "stix-enrich"))]
    #[test]
    fn key_error_precedes_missing_stix_feature() {
        let err = build_err(&entry_yaml(
            "stix",
            "stix_id: x\nurl: \"https://example.com/\"",
        ));
        assert!(
            matches!(
                err,
                EnrichersConfigError::InapplicableField { field: "url", .. }
            ),
            "got: {err}"
        );
    }

    #[test]
    fn key_error_precedes_opening_the_mmdb_database() {
        let err = build_err(&entry_yaml(
            "mmdb",
            "db_path: /nonexistent/does-not-exist.mmdb\nkey: \"1.2.3.4\"\nmethod: GET",
        ));
        assert!(
            matches!(
                err,
                EnrichersConfigError::InapplicableField {
                    field: "method",
                    ..
                }
            ),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_unknown_scope_and_top_level_keys() {
        let scope = entry_yaml("template", "template: \"x\"\nscope:\n  tag: [\"attack.*\"]");
        let err = yaml_serde::from_str::<EnrichersFile>(&scope).unwrap_err();
        assert!(
            err.to_string().contains("unknown field `tag`"),
            "got: {err}"
        );

        let top = "enricher:\n  - id: e\n";
        let err = yaml_serde::from_str::<EnrichersFile>(top).unwrap_err();
        assert!(
            err.to_string().contains("unknown field `enricher`"),
            "got: {err}"
        );
    }

    #[test]
    fn invalid_duration_names_the_value() {
        let err = yaml_serde::from_str::<EnrichersFile>(&entry_yaml(
            "template",
            "template: \"x\"\ntimeout: banana",
        ))
        .unwrap_err();
        assert!(
            err.to_string().contains("invalid duration \"banana\""),
            "got: {err}"
        );
    }

    /// One entry per built-in type with every key its type accepts.
    fn complete_entries() -> Vec<(&'static str, &'static str)> {
        vec![
            ("template", "template: \"x\""),
            (
                "lookup",
                "source: users\nextract: \".name\"\nextract_type: jq\ndefault: unknown\non_miss: skip",
            ),
            (
                "http",
                "url: \"https://example.com/${detection.rule.id}\"\nmethod: POST\nheaders: { X-Token: abc }\nbody: \"{}\"\ncache_ttl: 1m\nextract: \".a\"\nextract_type: jq\ndefault: {}\nmiss_status: [404]\non_miss: skip",
            ),
            (
                "command",
                "command: [\"echo\", \"${detection.rule.id}\"]\nenv: { A: b }\noutput: raw",
            ),
            (
                "stix",
                "stix_id: indicator--1\ntext_search: x\nattack_technique: true\ntype_filter: [indicator]\nmax_results: 2\nextract: \".id\"\nextract_type: jq\ndefault: none\non_miss: skip",
            ),
            (
                "mmdb",
                "db_path: x.mmdb\nkey: \"1.2.3.4\"\nfields: { country: country.iso_code }\ndefault: {}\non_miss: skip\nmmap: true",
            ),
            (
                "dns",
                "key: example.com\nrecord_type: A\nnameservers: [\"1.1.1.1\"]\ncache_ttl: 1m\nnegative_cache_ttl: 10s\ncache_max_entries: 10\nextract: \".[0]\"\nextract_type: jq\ndefault: []\non_miss: skip",
            ),
        ]
    }

    /// A complete entry without `on_miss`, which cannot be combined with the
    /// entry's `default`, so the entry passes every load check.
    fn loadable(extra: &str) -> String {
        extra
            .lines()
            .filter(|line| !line.starts_with("on_miss:"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn complete_entries_pass_key_validation() {
        for (type_name, extra) in complete_entries() {
            let cfg = first_entry(&entry_yaml(type_name, extra));
            validate_keys(&cfg).unwrap_or_else(|e| panic!("type {type_name}: {e}"));
            let mut present = cfg.present_keys();
            present.sort_unstable();
            let mut accepted = type_keys(type_name).unwrap().to_vec();
            accepted.sort_unstable();
            assert_eq!(
                present, accepted,
                "type {type_name} sets every key it accepts"
            );
        }
    }

    #[test]
    fn complete_template_http_and_command_entries_build() {
        for (type_name, extra) in complete_entries() {
            if matches!(type_name, "template" | "http" | "command") {
                let parsed: EnrichersFile =
                    yaml_serde::from_str(&entry_yaml(type_name, &loadable(extra))).unwrap();
                build_enrichers(parsed).unwrap_or_else(|e| panic!("type {type_name}: {e}"));
            }
        }
    }

    #[test]
    fn key_tables_match_the_config_fields() {
        let all_keys = "template: x\nurl: x\nmethod: x\nheaders: { a: b }\nbody: x\ncache_ttl: 1s\nextract: x\nextract_type: jq\ncommand: [x]\nenv: { a: b }\noutput: json\nsource: x\ndefault: x\nmiss_status: [404]\non_miss: skip\nstix_id: x\ntext_search: x\nattack_technique: true\ntype_filter: [x]\nmax_results: 1\ndb_path: x\nkey: x\nfields: { a: b }\nmmap: true\nrecord_type: A\nnameservers: [x]\nnegative_cache_ttl: 1s\ncache_max_entries: 1";
        let cfg = first_entry(&entry_yaml("template", all_keys));
        assert!(cfg.extra.is_empty(), "unexpected extra: {:?}", cfg.extra);

        let mut present = cfg.present_keys();
        present.sort_unstable();
        let mut tabled: Vec<&str> = [
            "template", "lookup", "http", "command", "stix", "mmdb", "dns",
        ]
        .iter()
        .flat_map(|t| type_keys(t).unwrap().iter().copied())
        .collect();
        tabled.sort_unstable();
        tabled.dedup();
        assert_eq!(present, tabled);
        for key in COMMON_KEYS {
            assert!(
                !tabled.contains(key),
                "{key} is both common and type-specific"
            );
        }
    }

    #[test]
    fn parse_enrichers_config_accepts_every_builtin_without_resources() {
        assert_eq!(
            parse_enrichers_config(cfg_template_yaml())
                .unwrap()
                .enrichers
                .len(),
            2
        );
        let mut yaml = String::from("enrichers:\n");
        for (i, (type_name, extra)) in complete_entries().into_iter().enumerate() {
            yaml.push_str(&format!(
                "  - id: e{i}\n    kind: detection\n    type: {type_name}\n    inject_field: out{i}\n"
            ));
            for line in loadable(extra).lines() {
                yaml.push_str(&format!("    {line}\n"));
            }
        }
        let parsed = parse_enrichers_config(&yaml).unwrap();
        assert_eq!(parsed.enrichers.len(), 7);
    }

    #[test]
    fn parse_enrichers_config_matches_build_errors() {
        let cases = [
            entry_yaml("lookup", "source: users\ndefualt: {}"),
            entry_yaml("http", "url: \"https://example.com/\"\nfields: { a: b }"),
            entry_yaml("template", "template: \"x\"\ndefault: 1"),
            entry_yaml("template", "template: \"${correlation.rule.id}\""),
            entry_yaml(
                "http",
                "url: \"https://example.com/\"\nextract: x\nextract_type: xpath",
            ),
            entry_yaml("template", "template: \"x\"\nscope:\n  levels: [loud]"),
        ];
        for yaml in &cases {
            let parsed = parse_enrichers_config(yaml).unwrap_err();
            let built = build_err(yaml);
            assert_eq!(
                std::mem::discriminant(&parsed),
                std::mem::discriminant(&built),
                "parse: {parsed}, build: {built}"
            );
            assert_eq!(parsed.to_string(), built.to_string());
        }
        assert!(matches!(
            parse_enrichers_config(&entry_yaml(
                "template",
                "template: \"x\"\nscope:\n  tag: []"
            )),
            Err(EnrichersConfigError::Yaml(_))
        ));
    }

    #[test]
    fn explicit_null_default_differs_from_absent_default() {
        assert_eq!(
            first_entry(&entry_yaml("lookup", "source: x")).default,
            None
        );
        for null in ["default: null", "default: ~", "default:"] {
            assert_eq!(
                first_entry(&entry_yaml("lookup", &format!("source: x\n{null}"))).default,
                Some(serde_json::Value::Null),
                "{null}"
            );
        }
        assert_eq!(
            first_entry(&entry_yaml("lookup", "source: x\ndefault: {}")).default,
            Some(serde_json::json!({}))
        );
    }

    #[test]
    fn explicit_null_default_is_serialized_for_bespoke_factories() {
        let cfg = first_entry(&entry_yaml("passive_dns", "default: null"));
        let raw = serde_json::to_value(&cfg).unwrap();
        assert_eq!(raw.get("default"), Some(&serde_json::Value::Null));
        let cfg = first_entry(&entry_yaml("passive_dns", "url: x"));
        let raw = serde_json::to_value(&cfg).unwrap();
        assert_eq!(raw.get("default"), None);
    }

    #[test]
    fn miss_status_outside_the_redirect_and_error_range_is_rejected() {
        for status in ["200", "99", "600", "65535"] {
            let yaml = entry_yaml(
                "http",
                &format!("url: \"https://example.com/\"\nmiss_status: [404, {status}]"),
            );
            let built = build_err(&yaml);
            match &built {
                EnrichersConfigError::InvalidValue {
                    enricher_id, field, ..
                } => {
                    assert_eq!(enricher_id, "e");
                    assert_eq!(*field, "miss_status");
                }
                other => panic!("miss_status {status}: expected InvalidValue, got {other}"),
            }
            assert_eq!(
                built.to_string(),
                format!(
                    "enricher 'e': invalid 'miss_status': status {status} is outside 300..=599"
                )
            );
            let parsed = parse_enrichers_config(&yaml).unwrap_err();
            assert_eq!(parsed.to_string(), built.to_string());
        }
    }

    #[test]
    fn miss_status_must_be_a_list_of_integers() {
        for value in ["[\"x\"]", "[-1]", "[70000]", "404"] {
            let yaml = entry_yaml(
                "http",
                &format!("url: \"https://example.com/\"\nmiss_status: {value}"),
            );
            assert!(
                matches!(
                    parse_enrichers_config(&yaml),
                    Err(EnrichersConfigError::Yaml(_))
                ),
                "miss_status: {value}"
            );
        }
    }

    #[test]
    fn miss_status_applies_only_to_http() {
        let err = build_err(&entry_yaml("lookup", "source: users\nmiss_status: [404]"));
        assert!(
            matches!(
                err,
                EnrichersConfigError::InapplicableField {
                    field: "miss_status",
                    ..
                }
            ),
            "got {err}"
        );
        let parsed = parse_enrichers_config(&entry_yaml(
            "dns",
            "key: x\nrecord_type: A\nmiss_status: []",
        ));
        assert!(parsed.is_ok(), "an empty miss_status counts as absent");
    }

    #[test]
    fn miss_status_is_serialized_for_bespoke_factories() {
        let cfg = first_entry(&entry_yaml("passive_dns", "miss_status: [404, 410]"));
        let raw = serde_json::to_value(&cfg).unwrap();
        assert_eq!(raw["miss_status"], serde_json::json!([404, 410]));
    }

    fn http_entry(extra: &str) -> String {
        entry_yaml("http", &format!("url: \"https://example.com/\"\n{extra}"))
    }

    fn built_policies(yaml: &str) -> (OnError, OnError) {
        let parsed: EnrichersFile = yaml_serde::from_str(yaml).unwrap();
        let pipeline = build_enrichers(parsed).unwrap();
        let enricher = pipeline.enrichers().next().unwrap();
        (enricher.on_error(), enricher.on_miss())
    }

    #[test]
    fn absent_on_miss_follows_on_error() {
        for (label, policy) in [
            ("skip", OnError::Skip),
            ("null", OnError::Null),
            ("drop", OnError::Drop),
        ] {
            assert_eq!(
                built_policies(&http_entry(&format!("on_error: {label}"))),
                (policy, policy)
            );
        }
    }

    #[test]
    fn on_miss_values_parse() {
        for (label, policy) in [
            ("skip", OnError::Skip),
            ("null", OnError::Null),
            ("drop", OnError::Drop),
        ] {
            assert_eq!(
                built_policies(&http_entry(&format!("on_error: drop\non_miss: {label}"))),
                (OnError::Drop, policy)
            );
        }
        assert!(matches!(
            parse_enrichers_config(&http_entry("on_miss: ignore")),
            Err(EnrichersConfigError::Yaml(_))
        ));
    }

    #[test]
    fn on_miss_applies_only_to_lookup_types() {
        for (type_name, extra) in [
            ("command", "command: [\"true\"]\non_miss: skip"),
            ("template", "template: \"x\"\non_miss: skip"),
        ] {
            let err = build_err(&entry_yaml(type_name, extra));
            assert!(
                matches!(
                    err,
                    EnrichersConfigError::InapplicableField {
                        field: "on_miss",
                        ..
                    }
                ),
                "type {type_name}: got {err}"
            );
        }
        for (type_name, extra) in [
            ("lookup", "source: users\non_miss: null"),
            ("http", "url: \"https://example.com/\"\non_miss: null"),
            ("stix", "text_search: x\non_miss: null"),
            ("mmdb", "db_path: x.mmdb\nkey: \"1.2.3.4\"\non_miss: null"),
            ("dns", "key: x\nrecord_type: A\non_miss: null"),
        ] {
            parse_enrichers_config(&entry_yaml(type_name, extra))
                .unwrap_or_else(|e| panic!("type {type_name}: {e}"));
        }
    }

    #[test]
    fn on_miss_with_default_is_rejected() {
        for default in ["default: null", "default: unknown", "default: {}"] {
            let yaml = http_entry(&format!("{default}\non_miss: skip"));
            let built = build_err(&yaml);
            assert!(
                matches!(
                    built,
                    EnrichersConfigError::InvalidValue {
                        field: "on_miss",
                        ..
                    }
                ),
                "{default}: got {built}"
            );
            assert_eq!(
                built.to_string(),
                "enricher 'e': invalid 'on_miss': has no effect when 'default' is set"
            );
            let parsed = parse_enrichers_config(&yaml).unwrap_err();
            assert_eq!(parsed.to_string(), built.to_string());
        }
    }

    #[test]
    fn on_miss_is_serialized_for_bespoke_factories() {
        let cfg = first_entry(&entry_yaml("passive_dns", "on_error: drop\non_miss: null"));
        let raw = serde_json::to_value(&cfg).unwrap();
        assert_eq!(raw["on_error"], "drop");
        assert_eq!(raw["on_miss"], "null");
        let cfg = first_entry(&entry_yaml("passive_dns", "on_error: drop"));
        let raw = serde_json::to_value(&cfg).unwrap();
        assert_eq!(raw.get("on_miss"), None);
    }

    #[test]
    fn bespoke_types_get_the_value_checks() {
        for (extra, field) in [
            ("default: null\non_miss: skip", "on_miss"),
            ("miss_status: [200]", "miss_status"),
        ] {
            let err = parse_enrichers_config(&entry_yaml("passive_dns", extra)).unwrap_err();
            assert!(
                matches!(&err, EnrichersConfigError::InvalidValue { field: f, .. } if *f == field),
                "{extra}: got {err}"
            );
        }
    }

    #[test]
    fn bespoke_type_keeps_unknown_keys() {
        let cfg = first_entry(&entry_yaml("passive_dns", "api_key_env: KEY\nurl: x"));
        validate_keys(&cfg).unwrap();
        assert_eq!(cfg.extra.len(), 1);
        assert_eq!(cfg.extra["api_key_env"], "KEY");
    }
}
