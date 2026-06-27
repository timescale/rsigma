//! YAML schema and loader for the risk config file.
//!
//! Loaded by the daemon at startup and again on hot-reload. Validation runs at
//! build time and fails with an error pointing at the offending field (a bad
//! object selector names the selector; a bad scope reports the scope message),
//! so the daemon refuses to start on a malformed config rather than silently
//! mismatching at runtime.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use rsigma_parser::Level;

use crate::Scope;
use crate::selector::{Selector, SelectorParseError};

use super::RiskLayer;
use super::accumulator::{IncidentConfig, RiskCaps};
use super::incident::IncludeMode;
use super::object::ObjectSelector;
use super::score::{Reducer, ScoreConfig};

/// Top-level risk config file.
///
/// ```yaml
/// scope:
///   levels: [low, medium, high, critical]
/// score:
///   tag_scores:
///     "attack.*": 10
///     crown-jewel: 50
///   tag_reducer: sum
///   level_scores:
///     high: 40
///     critical: 80
///   default_score: 1
/// objects:
///   - type: user
///     selector: enrichment.user
///   - type: src_ip
///     selector: match.SourceIp
/// emit_risk_events: false
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RiskFile {
    /// Retain the event for selector resolution but drop raw event payloads
    /// before sink delivery.
    #[serde(default)]
    pub strip_event: bool,
    /// Restrict which results the layer acts on. Out-of-scope results pass
    /// through untouched.
    #[serde(default)]
    pub scope: Option<ScopeConfig>,
    /// Risk-score sourcing.
    #[serde(default)]
    pub score: ScoreFile,
    /// Risk-object (entity) selectors. At least one is required.
    #[serde(default)]
    pub objects: Vec<ObjectFile>,
    /// Emit a compact risk event per `(detection, risk object)` pair.
    #[serde(default)]
    pub emit_risk_events: bool,
    /// Optional NATS subject override for emitted risk events.
    #[serde(default)]
    pub nats_subject: Option<String>,
    /// Per-entity risk-incident accumulator. Omitted means annotation only.
    #[serde(default)]
    pub incident: Option<IncidentFile>,
}

/// `incident:` block.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct IncidentFile {
    /// Accumulation window (humantime, e.g. `24h`). Defaults to 24h.
    #[serde(default, with = "humantime_opt")]
    pub window: Option<Duration>,
    /// Score threshold (window risk sum). At least one threshold is required.
    #[serde(default)]
    pub score_threshold: Option<i64>,
    /// Distinct-tactic threshold. At least one threshold is required.
    #[serde(default)]
    pub tactic_count_threshold: Option<u64>,
    /// Per-entity cooldown after a fire (humantime). Defaults to 1h.
    #[serde(default, with = "humantime_opt")]
    pub cooldown: Option<Duration>,
    /// How much contributing detail to embed in an incident.
    #[serde(default)]
    pub include: IncludeLabel,
    /// Optional NATS subject override for emitted incidents.
    #[serde(default)]
    pub nats_subject: Option<String>,
    /// Growth bounds.
    #[serde(default)]
    pub caps: Option<RiskCapsFile>,
}

/// `incident.include` label.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncludeLabel {
    /// Lightweight references only (default).
    #[default]
    Refs,
    /// Full (event-stripped) contributing results.
    Results,
}

/// `incident.caps:` block.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RiskCapsFile {
    #[serde(default)]
    pub max_open_entities: Option<usize>,
    #[serde(default)]
    pub max_sources_per_entity: Option<usize>,
    #[serde(default)]
    pub max_results_per_incident: Option<usize>,
}

/// `scope:` block, mirroring the alert-pipeline config.
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

/// `score:` block.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ScoreFile {
    /// Custom-attribute key carrying an explicit per-rule score. Defaults to
    /// `rsigma.risk_score`.
    #[serde(default)]
    pub attribute: Option<String>,
    /// Tag patterns and their scores (exact tag or a `prefix.*` wildcard).
    #[serde(default)]
    pub tag_scores: HashMap<String, i64>,
    /// How multiple matching tag scores combine.
    #[serde(default)]
    pub tag_reducer: ReducerLabel,
    /// Per-severity scores.
    #[serde(default)]
    pub level_scores: HashMap<Level, i64>,
    /// Fallback score when nothing else applies.
    #[serde(default)]
    pub default_score: i64,
}

/// `score.tag_reducer` label.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReducerLabel {
    /// Add every matching tag score (default).
    #[default]
    Sum,
    /// Take the highest matching tag score.
    Max,
}

/// `objects:` entry.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ObjectFile {
    /// The risk-object type, e.g. `user`, `host`, `src_ip`.
    #[serde(rename = "type")]
    pub object_type: String,
    /// The field selector resolving the entity value.
    pub selector: String,
}

/// Errors produced while loading or validating a risk config.
#[derive(Debug)]
pub enum RiskConfigError {
    /// File could not be read.
    Io(std::io::Error, PathBuf),
    /// YAML failed to deserialize.
    Yaml(yaml_serde::Error),
    /// Scope construction failed.
    Scope(String),
    /// An object selector failed to parse.
    ObjectSelector(SelectorParseError),
    /// An `objects` entry had an empty `type`.
    EmptyObjectType,
    /// No `objects` were configured; the layer would have no entities to score.
    NoObjects,
    /// An `incident` block set neither `score_threshold` nor
    /// `tactic_count_threshold`.
    NoThreshold,
}

impl std::fmt::Display for RiskConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskConfigError::Io(e, p) => {
                write!(f, "failed to read risk config '{}': {e}", p.display())
            }
            RiskConfigError::Yaml(e) => write!(f, "invalid risk YAML: {e}"),
            RiskConfigError::Scope(message) => write!(f, "scope: {message}"),
            RiskConfigError::ObjectSelector(e) => write!(f, "objects.selector: {e}"),
            RiskConfigError::EmptyObjectType => {
                write!(f, "objects: each entry requires a non-empty `type`")
            }
            RiskConfigError::NoObjects => write!(
                f,
                "objects is empty; list at least one risk-object selector"
            ),
            RiskConfigError::NoThreshold => write!(
                f,
                "incident is configured but neither score_threshold nor \
                 tactic_count_threshold is set; set at least one"
            ),
        }
    }
}

impl std::error::Error for RiskConfigError {}

/// Read and deserialize a risk config file.
pub fn load_risk_file(path: &Path) -> Result<RiskFile, RiskConfigError> {
    let text =
        std::fs::read_to_string(path).map_err(|e| RiskConfigError::Io(e, path.to_path_buf()))?;
    yaml_serde::from_str(&text).map_err(RiskConfigError::Yaml)
}

/// Parse and validate a risk config from a YAML string.
///
/// Convenience over [`load_risk_file`] for in-memory inputs (tests and
/// fuzzing): deserializes then runs the same validation [`build_risk_layer`]
/// performs.
pub fn parse_risk_config(text: &str) -> Result<RiskLayer, RiskConfigError> {
    let file: RiskFile = yaml_serde::from_str(text).map_err(RiskConfigError::Yaml)?;
    build_risk_layer(file)
}

/// Validate a parsed file into a runnable [`RiskLayer`].
pub fn build_risk_layer(file: RiskFile) -> Result<RiskLayer, RiskConfigError> {
    let scope = match file.scope {
        Some(s) => Scope::new(s.rules, s.tags, s.levels).map_err(RiskConfigError::Scope)?,
        None => Scope::default(),
    };

    let reducer = match file.score.tag_reducer {
        ReducerLabel::Sum => Reducer::Sum,
        ReducerLabel::Max => Reducer::Max,
    };
    let score = ScoreConfig::new(
        file.score.attribute,
        file.score.tag_scores,
        reducer,
        file.score.level_scores,
        file.score.default_score,
    );

    if file.objects.is_empty() {
        return Err(RiskConfigError::NoObjects);
    }
    let mut objects = Vec::with_capacity(file.objects.len());
    for obj in file.objects {
        if obj.object_type.trim().is_empty() {
            return Err(RiskConfigError::EmptyObjectType);
        }
        let selector = Selector::parse(&obj.selector).map_err(RiskConfigError::ObjectSelector)?;
        objects.push(ObjectSelector {
            object_type: obj.object_type,
            selector,
        });
    }

    let incident = match file.incident {
        Some(i) => Some(build_incident_config(i)?),
        None => None,
    };

    Ok(RiskLayer::new(
        scope,
        file.strip_event,
        score,
        objects,
        file.emit_risk_events,
        file.nats_subject,
        incident,
    ))
}

/// Default accumulation window when `incident.window` is omitted.
const DEFAULT_WINDOW: Duration = Duration::from_secs(24 * 3600);
/// Default per-entity cooldown when `incident.cooldown` is omitted.
const DEFAULT_COOLDOWN: Duration = Duration::from_secs(3600);

/// Validate an `incident:` block into an [`IncidentConfig`].
fn build_incident_config(file: IncidentFile) -> Result<IncidentConfig, RiskConfigError> {
    if file.score_threshold.is_none() && file.tactic_count_threshold.is_none() {
        return Err(RiskConfigError::NoThreshold);
    }
    let include = match file.include {
        IncludeLabel::Refs => IncludeMode::Refs,
        IncludeLabel::Results => IncludeMode::Results,
    };
    let caps_file = file.caps.unwrap_or_default();
    let defaults = RiskCaps::default();
    let caps = RiskCaps {
        max_open_entities: caps_file
            .max_open_entities
            .unwrap_or(defaults.max_open_entities),
        max_sources_per_entity: caps_file
            .max_sources_per_entity
            .unwrap_or(defaults.max_sources_per_entity),
        max_results_per_incident: caps_file
            .max_results_per_incident
            .unwrap_or(defaults.max_results_per_incident),
    };
    Ok(IncidentConfig {
        window: file.window.unwrap_or(DEFAULT_WINDOW),
        score_threshold: file.score_threshold,
        tactic_count_threshold: file.tactic_count_threshold,
        cooldown: file.cooldown.unwrap_or(DEFAULT_COOLDOWN),
        include,
        nats_subject: file.nats_subject,
        caps,
    })
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
    fn minimal_config_builds() {
        let yaml = "objects:\n  - type: user\n    selector: enrichment.user\n";
        parse_risk_config(yaml).unwrap();
    }

    #[test]
    fn empty_objects_is_rejected() {
        let err = parse_risk_config("score:\n  default_score: 5\n").unwrap_err();
        assert!(matches!(err, RiskConfigError::NoObjects));
    }

    #[test]
    fn bad_object_selector_points_at_the_field() {
        let yaml = "objects:\n  - type: user\n    selector: bogus.field\n";
        let err = parse_risk_config(yaml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("objects.selector"), "got: {msg}");
        assert!(msg.contains("bogus.field"), "got: {msg}");
    }

    #[test]
    fn empty_object_type_is_rejected() {
        let yaml = "objects:\n  - type: \"\"\n    selector: enrichment.user\n";
        let err = parse_risk_config(yaml).unwrap_err();
        assert!(matches!(err, RiskConfigError::EmptyObjectType));
    }

    #[test]
    fn full_config_parses() {
        let yaml = r#"
strip_event: true
scope:
  levels: [low, medium, high, critical]
score:
  tag_scores:
    "attack.*": 10
    crown-jewel: 50
  tag_reducer: max
  level_scores:
    high: 40
    critical: 80
  default_score: 1
objects:
  - type: user
    selector: enrichment.user
  - type: src_ip
    selector: match.SourceIp
emit_risk_events: true
nats_subject: risk.events
"#;
        parse_risk_config(yaml).unwrap();
    }

    #[test]
    fn bad_scope_glob_is_rejected() {
        let yaml = "scope:\n  rules: [\"[unclosed\"]\nobjects:\n  - type: user\n    selector: enrichment.user\n";
        let err = parse_risk_config(yaml).unwrap_err();
        assert!(matches!(err, RiskConfigError::Scope(_)));
    }
}
