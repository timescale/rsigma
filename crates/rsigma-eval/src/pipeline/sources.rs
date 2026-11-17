//! Dynamic source declarations and template references for dynamic Sigma pipelines.
//!
//! This module defines the types for declaring external data sources in a pipeline
//! YAML (`sources` section) and for tracking `${source.*}` template references
//! found throughout the pipeline.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;

// =============================================================================
// Dynamic source declaration
// =============================================================================

/// A dynamic source declared in the pipeline's `sources` section.
///
/// Each source describes how to fetch external data that can be referenced
/// by `${source.<id>}` expressions anywhere in the pipeline YAML.
#[derive(Debug, Clone, PartialEq)]
pub struct DynamicSource {
    /// Unique identifier for this source, referenced in `${source.<id>}` expressions.
    pub id: String,
    /// The type-specific configuration for fetching data.
    pub source_type: SourceType,
    /// How often the source data should be refreshed.
    pub refresh: RefreshPolicy,
    /// Maximum time to wait for a fetch to complete.
    pub timeout: Option<Duration>,
    /// What to do when a fetch fails.
    pub on_error: ErrorPolicy,
    /// Whether the daemon must resolve this source before processing events.
    pub required: bool,
    /// Fallback value if the source cannot be resolved.
    pub default: Option<yaml_serde::Value>,
}

/// Type-specific configuration for a dynamic source.
#[derive(Debug, Clone, PartialEq)]
pub enum SourceType {
    /// Fetch data from an HTTP endpoint.
    Http {
        url: String,
        method: Option<String>,
        headers: HashMap<String, String>,
        /// Optional request body sent verbatim after `${VAR}` expansion. When
        /// set and `method` is unset, the request defaults to `POST`. Pairs
        /// with query APIs that require a body (GraphQL, `_search`, TheHive 5's
        /// `/api/v1/query`).
        body: Option<String>,
        format: DataFormat,
        extract: Option<ExtractExpr>,
    },
    /// Run a local command and capture its stdout.
    Command {
        command: Vec<String>,
        format: DataFormat,
        extract: Option<ExtractExpr>,
    },
    /// Read data from a local file.
    File {
        path: PathBuf,
        format: DataFormat,
        extract: Option<ExtractExpr>,
    },
    /// Subscribe to a NATS subject for push-based updates.
    Nats {
        url: String,
        subject: String,
        format: DataFormat,
        extract: Option<ExtractExpr>,
    },
    /// Indicators pushed over the HTTP API. Nothing is fetched.
    ///
    /// `max_indicators` and `max_value_length` bound the set. `default_ttl`
    /// applies when a push names no expiry of its own; `None` means pushed
    /// indicators stay until they are deleted.
    Watchlist {
        max_indicators: usize,
        max_value_length: usize,
        default_ttl: Option<Duration>,
    },
}

/// An extraction expression applied to source data after parsing.
///
/// Supports two syntax forms in YAML:
/// - Plain string: always jq (the common case): `extract: ".emails[]"`
/// - Structured object: explicit language: `extract: { expr: "$.emails[*]", type: jsonpath }`
#[derive(Debug, Clone, PartialEq)]
pub enum ExtractExpr {
    /// A jq expression (default). Evaluated via jaq.
    Jq(String),
    /// A JSONPath expression. Evaluated via serde_json_path.
    JsonPath(String),
    /// A CEL (Common Expression Language) expression. Evaluated via cel-interpreter.
    Cel(String),
}

/// How often a source should be refreshed.
#[derive(Debug, Clone, PartialEq)]
pub enum RefreshPolicy {
    /// Fetch at startup only, never refresh.
    Once,
    /// Re-fetch on a fixed interval.
    Interval(Duration),
    /// Watch the file for changes (file sources only).
    Watch,
    /// Value updated on each incoming NATS message (NATS sources only).
    Push,
    /// Fetch at startup, then only when explicitly triggered via API/signal.
    OnDemand,
}

/// What to do when a source fetch fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorPolicy {
    /// Use the last successfully fetched value.
    UseCached,
    /// Fail the pipeline load (at startup: exit; at runtime: keep previous state).
    Fail,
    /// Fall back to the declared `default` value.
    UseDefault,
}

/// The format of data returned by a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataFormat {
    /// JSON (parsed with serde_json).
    Json,
    /// YAML (parsed with yaml_serde).
    Yaml,
    /// One value per line.
    Lines,
    /// Comma-separated values.
    Csv,
}

// =============================================================================
// Source references (detected during parsing)
// =============================================================================

/// A `${source.*}` template reference found in the pipeline YAML.
#[derive(Debug, Clone, PartialEq)]
pub struct SourceRef {
    /// The source ID (first path segment after `source.`).
    pub source_id: String,
    /// Optional dot-path into the source data (e.g., `field_mapping` in `${source.env_config.field_mapping}`).
    pub sub_path: Option<String>,
    /// Where in the pipeline this reference appears.
    pub location: RefLocation,
    /// The raw template string as it appeared in the YAML.
    pub raw_template: String,
}

/// Whether `id` can be declared as a dynamic source id: one or more ASCII
/// letters, digits, `_`, or `-`. These are exactly the ids a
/// `${source.<id>}` template can name.
pub fn is_valid_source_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// One `${source.<id>}` or `${source.<id>.<sub_path>}` template found by
/// [`scan_source_templates`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceTemplate<'a> {
    /// The whole template, from `${` to `}`.
    pub raw: &'a str,
    /// Byte offset of `raw` in the scanned text.
    pub start: usize,
    /// The referenced source id.
    pub source_id: &'a str,
    /// The dot-path into the source data, if any.
    pub sub_path: Option<&'a str>,
}

/// Find every `${source.*}` template in `text`, left to right.
///
/// This is the single grammar for source references: pipeline parsing uses it
/// to record [`SourceRef`]s and the runtime uses it to expand them.
pub fn scan_source_templates(text: &str) -> impl Iterator<Item = SourceTemplate<'_>> {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\$\{source\.([A-Za-z0-9_-]+)(?:\.([A-Za-z0-9_.]+))?\}")
            .expect("source template regex is valid")
    });
    RE.captures_iter(text).map(|caps| {
        let whole = caps.get(0).expect("group 0 always participates");
        SourceTemplate {
            raw: whole.as_str(),
            start: whole.start(),
            source_id: caps.get(1).expect("the id group is required").as_str(),
            sub_path: caps.get(2).map(|m| m.as_str()),
        }
    })
}

/// Where in the pipeline a source reference appears.
#[derive(Debug, Clone, PartialEq)]
pub enum RefLocation {
    /// In the `vars` section, under the given variable name.
    Var { var_name: String },
    /// In a transformation's field value.
    TransformationField {
        transform_index: usize,
        field_name: String,
    },
    /// An `include` directive in the transformations list.
    Include { transform_index: usize },
}

// =============================================================================
// Source status (for PipelineState tracking)
// =============================================================================

/// Resolution status of a dynamic source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceStatus {
    /// Source has not been resolved yet.
    Pending,
    /// Source was successfully resolved.
    Resolved,
    /// Source resolution failed.
    Failed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_source_ids() {
        for id in ["ip_blocklist", "threat-intel", "1st_feed", "A9", "_", "-"] {
            assert!(is_valid_source_id(id), "{id}");
        }
        for id in ["", "bad.id", "has space", "café", "a/b", "${x}"] {
            assert!(!is_valid_source_id(id), "{id}");
        }
    }

    #[test]
    fn scan_finds_templates_with_offsets() {
        let text = "a ${source.threat-intel.ips.0} b ${source.1st_feed} ${source.bad id}";
        let found: Vec<_> = scan_source_templates(text).collect();
        assert_eq!(
            found,
            [
                SourceTemplate {
                    raw: "${source.threat-intel.ips.0}",
                    start: 2,
                    source_id: "threat-intel",
                    sub_path: Some("ips.0"),
                },
                SourceTemplate {
                    raw: "${source.1st_feed}",
                    start: 33,
                    source_id: "1st_feed",
                    sub_path: None,
                },
            ]
        );
        for t in &found {
            assert_eq!(&text[t.start..t.start + t.raw.len()], t.raw);
        }
    }
}
