//! YAML schema and loader for the alert-pipeline config file.
//!
//! Loaded by the daemon at startup and again on hot-reload. Validation runs at
//! build time and fails with an error pointing at the offending field (a bad
//! selector names the selector; a bad scope reports the scope message), so the
//! daemon refuses to start on a malformed config rather than silently
//! mismatching at runtime.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::Scope;

use super::AlertPipeline;
use super::dedup::DedupConfig;
use super::grouping::{Caps, GroupConfig, GroupMode, IncludeMode};
use super::inhibit::{InhibitConfig, InhibitRule};
use super::matcher::{MatcherError, MatcherSet, MatcherSpec};
use super::selector::{Selector, SelectorParseError};
use super::silence::{Silence, SilenceError, SilenceOrigin, SilenceSpec};

/// Default re-emit cadence: `0` means pure suppression (no re-emits, only a
/// resolved summary on expiry).
const DEFAULT_REPEAT_INTERVAL: Duration = Duration::from_secs(0);

/// Default idle timeout after which an active alert resolves.
const DEFAULT_RESOLVE_TIMEOUT: Duration = Duration::from_secs(3600);

/// Default incident batching delay before the first emission.
const DEFAULT_GROUP_WAIT: Duration = Duration::from_secs(30);

/// Default minimum delay before emitting an updated incident.
const DEFAULT_GROUP_INTERVAL: Duration = Duration::from_secs(300);

/// Default window a source alert stays active for inhibition.
const DEFAULT_INHIBIT_DURATION: Duration = Duration::from_secs(300);

/// Default ceiling on concurrently-active dedup alerts. Once full, further
/// first-fires pass through un-deduped instead of growing the store, bounding
/// memory under a high-cardinality fingerprint.
const DEFAULT_MAX_ACTIVE_ALERTS: usize = 100_000;

/// Default ceiling on dynamic (API-created) silences, bounding the admin
/// surface against unbounded silence creation.
pub const DEFAULT_MAX_DYNAMIC_SILENCES: usize = 1_000;

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
    /// Incident grouping. Omitted means no grouping.
    #[serde(default)]
    pub group: Option<GroupFile>,
    /// Static silences seeded at load and re-seeded on hot-reload. Dynamic
    /// silences created over the API are independent of this list.
    #[serde(default)]
    pub silences: Vec<SilenceSpec>,
    /// Ceiling on concurrently-tracked dynamic (API) silences. Creation past
    /// this many is rejected with `429`. Defaults to 1000.
    #[serde(default)]
    pub max_silences: Option<usize>,
    /// Inhibition rules. An active source mutes matching targets.
    #[serde(default)]
    pub inhibit_rules: Vec<InhibitRuleFile>,
}

/// `inhibit_rules:` entry.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct InhibitRuleFile {
    /// Stable name (used as the metric label); defaults to `inhibit_rule_<i>`.
    #[serde(default)]
    pub name: Option<String>,
    /// Matchers a source alert must satisfy.
    #[serde(default)]
    pub source_match: Vec<MatcherSpec>,
    /// Matchers a target alert must satisfy.
    #[serde(default)]
    pub target_match: Vec<MatcherSpec>,
    /// Selectors whose values must match between source and target.
    #[serde(default)]
    pub equal: Vec<String>,
    /// How long a source remains active after last seen (humantime).
    #[serde(default, with = "humantime_opt")]
    pub duration: Option<Duration>,
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
    /// Ceiling on concurrently-active alerts. Past this, first-fires pass
    /// through un-deduped (bounds memory under high-cardinality fingerprints).
    /// Defaults to 100000.
    #[serde(default)]
    pub max_active_alerts: Option<usize>,
}

/// Grouping mode label.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupModeLabel {
    /// Group by equality on the `by` selectors (default).
    #[default]
    GroupBy,
    /// Union-find over `entities` selector values.
    EntityGraph,
}

/// Contributing-result include label.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncludeLabel {
    /// Lightweight references only (default).
    #[default]
    Refs,
    /// Full (event-stripped) contributing results.
    Results,
}

/// `group.caps:` block.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CapsFile {
    #[serde(default)]
    pub max_open_incidents: Option<usize>,
    #[serde(default)]
    pub max_entities_per_incident: Option<usize>,
    #[serde(default)]
    pub max_results_per_incident: Option<usize>,
    #[serde(default)]
    pub max_value_cardinality: Option<u64>,
}

/// `group:` block.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct GroupFile {
    #[serde(default)]
    pub mode: GroupModeLabel,
    /// `group_by` mode: selectors forming the group key.
    #[serde(default)]
    pub by: Vec<String>,
    /// `entity_graph` mode: selectors forming join edges.
    #[serde(default)]
    pub entities: Vec<String>,
    #[serde(default, with = "humantime_opt")]
    pub group_wait: Option<Duration>,
    #[serde(default, with = "humantime_opt")]
    pub group_interval: Option<Duration>,
    #[serde(default, with = "humantime_opt")]
    pub repeat_interval: Option<Duration>,
    #[serde(default, with = "humantime_opt")]
    pub resolve_timeout: Option<Duration>,
    #[serde(default)]
    pub include: IncludeLabel,
    #[serde(default)]
    pub caps: Option<CapsFile>,
    /// `entity_graph` values that never form a join edge.
    #[serde(default)]
    pub stop_values: Vec<String>,
    /// Optional NATS subject override for emitted incidents.
    #[serde(default)]
    pub nats_subject: Option<String>,
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
    /// A grouping selector failed to parse.
    GroupSelector(SelectorParseError),
    /// `group.mode: group_by` with an empty `by` list.
    EmptyGroupBy,
    /// `group.mode: entity_graph` with an empty `entities` list.
    EmptyEntities,
    /// A static silence failed to build.
    Silence(SilenceError),
    /// An inhibit-rule matcher failed to compile.
    InhibitMatcher(MatcherError),
    /// An inhibit-rule `equal` selector failed to parse.
    InhibitSelector(SelectorParseError),
    /// An inhibit rule has an empty `source_match` or `target_match`.
    EmptyInhibitMatch,
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
            AlertPipelineConfigError::GroupSelector(e) => write!(f, "group: {e}"),
            AlertPipelineConfigError::EmptyGroupBy => write!(
                f,
                "group.mode is group_by but group.by is empty; list at least one selector"
            ),
            AlertPipelineConfigError::EmptyEntities => write!(
                f,
                "group.mode is entity_graph but group.entities is empty; list at least one selector"
            ),
            AlertPipelineConfigError::Silence(e) => write!(f, "silences: {e}"),
            AlertPipelineConfigError::InhibitMatcher(e) => write!(f, "inhibit_rules: {e}"),
            AlertPipelineConfigError::InhibitSelector(e) => write!(f, "inhibit_rules.equal: {e}"),
            AlertPipelineConfigError::EmptyInhibitMatch => write!(
                f,
                "an inhibit rule requires a non-empty source_match and target_match"
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
                max_active_alerts: d.max_active_alerts.unwrap_or(DEFAULT_MAX_ACTIVE_ALERTS),
            })
        }
        None => None,
    };

    let group = match file.group {
        Some(g) => Some(build_group(g)?),
        None => None,
    };

    let mut static_silences = Vec::with_capacity(file.silences.len());
    for spec in file.silences {
        static_silences.push(
            Silence::build(spec, SilenceOrigin::Static)
                .map_err(AlertPipelineConfigError::Silence)?,
        );
    }

    let inhibit = if file.inhibit_rules.is_empty() {
        None
    } else {
        Some(build_inhibit(file.inhibit_rules)?)
    };

    let max_silences = file.max_silences.unwrap_or(DEFAULT_MAX_DYNAMIC_SILENCES);

    Ok(AlertPipeline::new(
        scope,
        file.strip_event,
        dedup,
        group,
        static_silences,
        inhibit,
        max_silences,
    ))
}

/// Validate the `inhibit_rules:` list into an [`InhibitConfig`].
fn build_inhibit(rules: Vec<InhibitRuleFile>) -> Result<InhibitConfig, AlertPipelineConfigError> {
    let mut out = Vec::with_capacity(rules.len());
    for (i, rule) in rules.into_iter().enumerate() {
        if rule.source_match.is_empty() || rule.target_match.is_empty() {
            return Err(AlertPipelineConfigError::EmptyInhibitMatch);
        }
        let source_match = MatcherSet::compile(&rule.source_match)
            .map_err(AlertPipelineConfigError::InhibitMatcher)?;
        let target_match = MatcherSet::compile(&rule.target_match)
            .map_err(AlertPipelineConfigError::InhibitMatcher)?;
        let mut equal = Vec::with_capacity(rule.equal.len());
        for raw in &rule.equal {
            equal.push(Selector::parse(raw).map_err(AlertPipelineConfigError::InhibitSelector)?);
        }
        out.push(InhibitRule {
            name: rule.name.unwrap_or_else(|| format!("inhibit_rule_{i}")),
            source_match,
            target_match,
            equal,
            duration: rule.duration.unwrap_or(DEFAULT_INHIBIT_DURATION),
        });
    }
    Ok(InhibitConfig { rules: out })
}

/// Validate a `group:` block into a [`GroupConfig`].
fn build_group(g: GroupFile) -> Result<GroupConfig, AlertPipelineConfigError> {
    let mode = match g.mode {
        GroupModeLabel::GroupBy => GroupMode::GroupBy,
        GroupModeLabel::EntityGraph => GroupMode::EntityGraph,
    };
    let parse = |raw: &str| Selector::parse(raw).map_err(AlertPipelineConfigError::GroupSelector);
    let by =
        g.by.iter()
            .map(|s| parse(s))
            .collect::<Result<Vec<_>, _>>()?;
    let entities = g
        .entities
        .iter()
        .map(|s| parse(s))
        .collect::<Result<Vec<_>, _>>()?;
    match mode {
        GroupMode::GroupBy if by.is_empty() => return Err(AlertPipelineConfigError::EmptyGroupBy),
        GroupMode::EntityGraph if entities.is_empty() => {
            return Err(AlertPipelineConfigError::EmptyEntities);
        }
        _ => {}
    }
    let include = match g.include {
        IncludeLabel::Refs => IncludeMode::Refs,
        IncludeLabel::Results => IncludeMode::Results,
    };
    let caps_file = g.caps.unwrap_or_default();
    let defaults = Caps::default();
    let caps = Caps {
        max_open_incidents: caps_file
            .max_open_incidents
            .unwrap_or(defaults.max_open_incidents),
        max_entities_per_incident: caps_file
            .max_entities_per_incident
            .unwrap_or(defaults.max_entities_per_incident),
        max_results_per_incident: caps_file
            .max_results_per_incident
            .unwrap_or(defaults.max_results_per_incident),
        max_value_cardinality: caps_file
            .max_value_cardinality
            .unwrap_or(defaults.max_value_cardinality),
    };
    Ok(GroupConfig {
        mode,
        by,
        entities,
        group_wait: g.group_wait.unwrap_or(DEFAULT_GROUP_WAIT),
        group_interval: g.group_interval.unwrap_or(DEFAULT_GROUP_INTERVAL),
        repeat_interval: g.repeat_interval.unwrap_or(DEFAULT_REPEAT_INTERVAL),
        resolve_timeout: g.resolve_timeout.unwrap_or(DEFAULT_RESOLVE_TIMEOUT),
        include,
        caps,
        stop_values: g.stop_values.into_iter().collect::<BTreeSet<_>>(),
        nats_subject: g.nats_subject,
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
    fn empty_file_builds() {
        let file: AlertPipelineFile = yaml_serde::from_str("{}").unwrap();
        build_alert_pipeline(file).unwrap();
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
        build_alert_pipeline(file).unwrap();
    }

    #[test]
    fn static_silence_parses() {
        let yaml = r#"
silences:
  - matchers:
      - selector: rule
        op: "="
        value: noisy-rule
    comment: maintenance
"#;
        let file: AlertPipelineFile = yaml_serde::from_str(yaml).unwrap();
        let pipeline = build_alert_pipeline(file).unwrap();
        assert_eq!(pipeline.static_silences().len(), 1);
    }

    #[test]
    fn static_silence_without_matchers_is_rejected() {
        let yaml = r#"
silences:
  - comment: bad
"#;
        let file: AlertPipelineFile = yaml_serde::from_str(yaml).unwrap();
        assert!(build_alert_pipeline(file).is_err());
    }

    #[test]
    fn inhibit_rule_parses() {
        let yaml = r#"
inhibit_rules:
  - name: crit-inhibits-high
    source_match:
      - selector: level
        op: "="
        value: critical
    target_match:
      - selector: level
        op: "="
        value: high
    equal: [match.SourceIp]
    duration: 5m
"#;
        let file: AlertPipelineFile = yaml_serde::from_str(yaml).unwrap();
        build_alert_pipeline(file).unwrap();
    }

    #[test]
    fn inhibit_rule_without_matchers_is_rejected() {
        let yaml = r#"
inhibit_rules:
  - equal: [match.SourceIp]
"#;
        let file: AlertPipelineFile = yaml_serde::from_str(yaml).unwrap();
        assert!(build_alert_pipeline(file).is_err());
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
