//! Dynamic source declarations and template references for dynamic Sigma pipelines.
//!
//! This module defines the types for declaring external data sources in a pipeline
//! YAML (`sources` section) and for tracking `${source.*}` template references
//! found throughout the pipeline.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

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
    pub default: Option<serde_yaml::Value>,
}

/// Type-specific configuration for a dynamic source.
#[derive(Debug, Clone, PartialEq)]
pub enum SourceType {
    /// Fetch data from an HTTP endpoint.
    Http {
        url: String,
        method: Option<String>,
        headers: HashMap<String, String>,
        format: DataFormat,
        extract: Option<String>,
    },
    /// Run a local command and capture its stdout.
    Command {
        command: Vec<String>,
        format: DataFormat,
        extract: Option<String>,
    },
    /// Read data from a local file.
    File { path: PathBuf, format: DataFormat },
    /// Subscribe to a NATS subject for push-based updates.
    Nats {
        url: String,
        subject: String,
        format: DataFormat,
        extract: Option<String>,
    },
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
    /// YAML (parsed with serde_yaml).
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
