//! YAML schema and loader for the alert-pipeline config file.
//!
//! Loaded by the daemon at startup and again on hot-reload. Validation runs at
//! build time and fails with an error pointing at the offending field (a bad
//! selector names the selector; a bad scope reports the scope message), so the
//! daemon refuses to start on a malformed config rather than silently
//! mismatching at runtime.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::Scope;

use super::AlertPipeline;
use super::dedup::DedupConfig;
use super::selector::{Selector, SelectorParseError};

/// Default re-emit cadence: `0` means pure suppression (no re-emits, only a
/// resolved summary on expiry).
const DEFAULT_REPEAT_INTERVAL: Duration = Duration::from_secs(0);

/// Default idle timeout after which an active alert resolves.
const DEFAULT_RESOLVE_TIMEOUT: Duration = Duration::from_secs(3600);

/// Top-level alert-pipeline config file.
///
/// ```yaml
/// strip_event: false
/// scope:
///   levels: [high, critical]
/// dedup:
///   fingerprint:
///     - rule
///     - match.SourceIp
///   repeat_interval: 1h
///   resolve_timeout: 30m
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AlertPipelineFile {
    /// Retain the event for selector resolution but drop raw event payloads
    /// before sink delivery.
    #[serde(default)]
    pub strip_event: bool,
    /// Restrict which results the layer acts on. Out-of-scope results pass
    /// through untouched.
    #[serde(default)]
    pub scope: Option<ScopeConfig>,
    /// Fingerprint deduplication. Omitted means no dedup.
    #[serde(default)]
    pub dedup: Option<DedupFile>,
}

/// `scope:` block, mirroring the enrichers config.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ScopeConfig {
    /// Rule-id exact matches or rule-title globs.
    #[serde(default)]
    pub rules: Vec<String>,
    /// Tag exact matches or `prefix.*` wildcards.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Severity levels.
    #[serde(default)]
    pub levels: Vec<String>,
}

/// `dedup:` block.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DedupFile {
    /// Selectors hashed (with the rule identity) into the fingerprint.
    #[serde(default)]
    pub fingerprint: Vec<String>,
    /// Re-emit cadence (humantime, e.g. `1h`). `0` / omitted means pure
    /// suppression.
    #[serde(default, with = "humantime_opt")]
    pub repeat_interval: Option<Duration>,
    /// Idle timeout after which an active alert resolves (humantime).
    #[serde(default, with = "humantime_opt")]
    pub resolve_timeout: Option<Duration>,
}

/// Errors produced while loading or validating an alert-pipeline config.
#[derive(Debug)]
pub enum AlertPipelineConfigError {
    /// File could not be read.
    Io(std::io::Error, PathBuf),
    /// YAML failed to deserialize.
    Yaml(yaml_serde::Error),
    /// A fingerprint selector failed to parse.
    Selector(SelectorParseError),
    /// Scope construction failed.
    Scope(String),
    /// `dedup` was configured with an empty `fingerprint` list.
    EmptyFingerprint,
}

impl std::fmt::Display for AlertPipelineConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertPipelineConfigError::Io(e, p) => {
                write!(
                    f,
                    "failed to read alert-pipeline config '{}': {e}",
                    p.display()
                )
            }
            AlertPipelineConfigError::Yaml(e) => write!(f, "invalid alert-pipeline YAML: {e}"),
            AlertPipelineConfigError::Selector(e) => write!(f, "dedup.fingerprint: {e}"),
            AlertPipelineConfigError::Scope(message) => write!(f, "scope: {message}"),
            AlertPipelineConfigError::EmptyFingerprint => write!(
                f,
                "dedup is configured but dedup.fingerprint is empty; list at least one selector"
            ),
        }
    }
}

impl std::error::Error for AlertPipelineConfigError {}

/// Read and deserialize an alert-pipeline config file.
pub fn load_alert_pipeline_file(
    path: &Path,
) -> Result<AlertPipelineFile, AlertPipelineConfigError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| AlertPipelineConfigError::Io(e, path.to_path_buf()))?;
    yaml_serde::from_str(&text).map_err(AlertPipelineConfigError::Yaml)
}

/// Parse and validate an alert-pipeline config from a YAML string.
///
/// Convenience over [`load_alert_pipeline_file`] for in-memory inputs (tests
/// and fuzzing): deserializes then runs the same validation [`build_alert_pipeline`]
/// performs.
pub fn parse_alert_pipeline_config(text: &str) -> Result<AlertPipeline, AlertPipelineConfigError> {
    let file: AlertPipelineFile =
        yaml_serde::from_str(text).map_err(AlertPipelineConfigError::Yaml)?;
    build_alert_pipeline(file)
}

/// Validate a parsed file into a runnable [`AlertPipeline`].
pub fn build_alert_pipeline(
    file: AlertPipelineFile,
) -> Result<AlertPipeline, AlertPipelineConfigError> {
    let scope = match file.scope {
        Some(s) => {
            Scope::new(s.rules, s.tags, s.levels).map_err(AlertPipelineConfigError::Scope)?
        }
        None => Scope::default(),
    };

    let dedup = match file.dedup {
        Some(d) => {
            let mut fingerprint = Vec::with_capacity(d.fingerprint.len());
            for raw in &d.fingerprint {
                fingerprint.push(Selector::parse(raw).map_err(AlertPipelineConfigError::Selector)?);
            }
            if fingerprint.is_empty() {
                return Err(AlertPipelineConfigError::EmptyFingerprint);
            }
            Some(DedupConfig {
                fingerprint,
                repeat_interval: d.repeat_interval.unwrap_or(DEFAULT_REPEAT_INTERVAL),
                resolve_timeout: d.resolve_timeout.unwrap_or(DEFAULT_RESOLVE_TIMEOUT),
            })
        }
        None => None,
    };

    Ok(AlertPipeline::new(scope, file.strip_event, dedup))
}

/// humantime serde adapter for `Option<Duration>`, accepting `null` / missing.
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

    #[test]
    fn empty_file_builds_a_noop_pipeline() {
        let file: AlertPipelineFile = yaml_serde::from_str("{}").unwrap();
        let pipeline = build_alert_pipeline(file).unwrap();
        assert!(pipeline.is_noop());
    }

    #[test]
    fn full_dedup_config_parses() {
        let yaml = r#"
strip_event: true
scope:
  levels: [high, critical]
dedup:
  fingerprint:
    - rule
    - match.SourceIp
  repeat_interval: 1h
  resolve_timeout: 30m
"#;
        let file: AlertPipelineFile = yaml_serde::from_str(yaml).unwrap();
        let pipeline = build_alert_pipeline(file).unwrap();
        assert!(!pipeline.is_noop());
    }

    #[test]
    fn bad_selector_points_at_the_field() {
        let yaml = r#"
dedup:
  fingerprint:
    - bogus.field
"#;
        let file: AlertPipelineFile = yaml_serde::from_str(yaml).unwrap();
        let err = build_alert_pipeline(file).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("dedup.fingerprint"), "got: {msg}");
        assert!(msg.contains("bogus.field"), "got: {msg}");
    }

    #[test]
    fn empty_fingerprint_is_rejected() {
        let yaml = r#"
dedup:
  fingerprint: []
"#;
        let file: AlertPipelineFile = yaml_serde::from_str(yaml).unwrap();
        let err = build_alert_pipeline(file).unwrap_err();
        assert!(matches!(err, AlertPipelineConfigError::EmptyFingerprint));
    }

    #[test]
    fn bad_scope_glob_is_rejected() {
        let yaml = r#"
scope:
  rules:
    - "[unclosed"
dedup:
  fingerprint: [rule]
"#;
        let file: AlertPipelineFile = yaml_serde::from_str(yaml).unwrap();
        let err = build_alert_pipeline(file).unwrap_err();
        assert!(matches!(err, AlertPipelineConfigError::Scope(_)));
    }
}
