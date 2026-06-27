//! Field-selector namespace shared by the post-engine sink layers.
//!
//! A [`Selector`] resolves a single value out of an [`EvaluationResult`] across
//! six namespaces. It is consumed by the alert pipeline (fingerprints, group-by,
//! matchers) and the risk layer (risk-object extraction), so both reason about
//! the result the same way:
//!
//! - `rule` — the rule id, falling back to the rule title.
//! - `level` — the severity, lowercased (`high`, `critical`, ...).
//! - `event.<path>` — a dotted path into the retained event JSON. Resolves to
//!   nothing unless the event was retained (`--include-event` or per-rule
//!   `rsigma.include_event`).
//! - `match.<field>` — the value of a matched field (detection results only).
//! - `enrichment.<path>` — a dotted path into `header.enrichments`.
//! - `correlation.group_key.<field>` — a group-by value (correlation results
//!   only).
//!
//! A selector that resolves to nothing yields `None`; the fingerprint treats
//! that as an explicit null marker, and entity extraction contributes nothing.

use rsigma_eval::{EvaluationResult, ResultBody};
use serde_json::Value;

/// A parsed field selector over the [`EvaluationResult`] namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    /// `rule`: the rule id, falling back to the rule title.
    Rule,
    /// `level`: the severity, lowercased.
    Level,
    /// `event.<path>`: a dotted path into the retained event JSON.
    Event(Vec<String>),
    /// `match.<field>`: a matched field value (detection only).
    Match(String),
    /// `enrichment.<path>`: a dotted path into `header.enrichments`.
    Enrichment(Vec<String>),
    /// `correlation.group_key.<field>`: a group-by value (correlation only).
    CorrelationGroupKey(String),
}

/// A selector string that failed to parse, naming the offending selector so
/// config validation can point the operator at the exact line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectorParseError {
    /// The raw selector string as written in the config.
    pub selector: String,
    /// Why it failed.
    pub message: String,
}

impl std::fmt::Display for SelectorParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid selector '{}': {}", self.selector, self.message)
    }
}

impl std::error::Error for SelectorParseError {}

impl Selector {
    /// Parse a selector string. Returns a [`SelectorParseError`] naming the
    /// offending selector on an unknown namespace or an empty path.
    pub fn parse(raw: &str) -> Result<Self, SelectorParseError> {
        let s = raw.trim();
        let err = |message: &str| SelectorParseError {
            selector: raw.to_string(),
            message: message.to_string(),
        };

        if s == "rule" {
            return Ok(Selector::Rule);
        }
        if s == "level" {
            return Ok(Selector::Level);
        }
        if let Some(rest) = s.strip_prefix("correlation.group_key.") {
            if rest.is_empty() {
                return Err(err("empty correlation.group_key field"));
            }
            return Ok(Selector::CorrelationGroupKey(rest.to_string()));
        }
        if let Some(rest) = s.strip_prefix("event.") {
            let path = split_path(rest);
            if path.is_empty() {
                return Err(err("empty event path"));
            }
            return Ok(Selector::Event(path));
        }
        if let Some(rest) = s.strip_prefix("match.") {
            if rest.is_empty() {
                return Err(err("empty match field"));
            }
            return Ok(Selector::Match(rest.to_string()));
        }
        if let Some(rest) = s.strip_prefix("enrichment.") {
            let path = split_path(rest);
            if path.is_empty() {
                return Err(err("empty enrichment key"));
            }
            return Ok(Selector::Enrichment(path));
        }

        Err(err(
            "unknown namespace (expected rule, level, event.<path>, match.<field>, \
             enrichment.<key>, or correlation.group_key.<field>)",
        ))
    }

    /// The canonical string form of this selector. Round-trips [`Selector::parse`].
    pub fn as_str(&self) -> String {
        match self {
            Selector::Rule => "rule".to_string(),
            Selector::Level => "level".to_string(),
            Selector::Event(path) => format!("event.{}", path.join(".")),
            Selector::Match(field) => format!("match.{field}"),
            Selector::Enrichment(path) => format!("enrichment.{}", path.join(".")),
            Selector::CorrelationGroupKey(field) => format!("correlation.group_key.{field}"),
        }
    }

    /// Resolve this selector against a result. Returns `None` when the value
    /// is absent (missing field, wrong result kind, or no retained event).
    pub fn resolve(&self, result: &EvaluationResult) -> Option<Value> {
        match self {
            Selector::Rule => Some(Value::String(
                result
                    .header
                    .rule_id
                    .clone()
                    .unwrap_or_else(|| result.header.rule_title.clone()),
            )),
            Selector::Level => result
                .header
                .level
                .and_then(|l| serde_json::to_value(l).ok())
                .filter(|v| !v.is_null()),
            Selector::Event(path) => {
                let event = match &result.body {
                    ResultBody::Detection(d) => d.event.as_ref()?,
                    ResultBody::Correlation(_) => return None,
                };
                dig(event, path).cloned()
            }
            Selector::Match(field) => match &result.body {
                ResultBody::Detection(d) => d
                    .matched_fields
                    .iter()
                    .find(|m| m.field == *field)
                    .map(|m| m.value.clone()),
                ResultBody::Correlation(_) => None,
            },
            Selector::Enrichment(path) => {
                let map = result.header.enrichments.as_ref()?;
                let (first, rest) = path.split_first()?;
                let mut cur = map.get(first)?;
                for seg in rest {
                    cur = cur.get(seg)?;
                }
                Some(cur.clone())
            }
            Selector::CorrelationGroupKey(field) => match &result.body {
                ResultBody::Correlation(c) => c
                    .group_key
                    .iter()
                    .find(|(k, _)| k == field)
                    .map(|(_, v)| Value::String(v.clone())),
                ResultBody::Detection(_) => None,
            },
        }
    }
}

/// Split a dotted path, dropping empty segments.
fn split_path(s: &str) -> Vec<String> {
    s.split('.')
        .filter(|seg| !seg.is_empty())
        .map(|seg| seg.to_string())
        .collect()
}

/// Walk a dotted path into a JSON value.
fn dig<'a>(value: &'a Value, path: &[String]) -> Option<&'a Value> {
    let mut cur = value;
    for seg in path {
        cur = cur.get(seg)?;
    }
    Some(cur)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_eval::{
        CorrelationBody, DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader,
    };
    use rsigma_parser::{CorrelationType, Level};
    use std::collections::HashMap;
    use std::sync::Arc;

    fn detection() -> EvaluationResult {
        EvaluationResult {
            header: RuleHeader {
                rule_title: "Suspicious PowerShell".to_string(),
                rule_id: Some("rule-1".to_string()),
                level: Some(Level::High),
                tags: vec!["attack.t1059".to_string()],
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: Some(
                    serde_json::json!({"geo": {"country": "US"}, "host": "dc01"})
                        .as_object()
                        .unwrap()
                        .clone(),
                ),
            },
            body: ResultBody::Detection(DetectionBody {
                matched_selections: vec!["sel".to_string()],
                matched_fields: vec![FieldMatch::new("SourceIp", serde_json::json!("10.0.0.5"))],
                event: Some(serde_json::json!({"host": {"name": "dc01"}, "pid": 42})),
            }),
        }
    }

    fn correlation() -> EvaluationResult {
        EvaluationResult {
            header: RuleHeader {
                rule_title: "SSH brute force".to_string(),
                rule_id: None,
                level: Some(Level::Critical),
                tags: vec![],
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
            },
            body: ResultBody::Correlation(CorrelationBody {
                correlation_type: CorrelationType::EventCount,
                group_key: vec![("SourceIp".to_string(), "203.0.113.4".to_string())],
                aggregated_value: 73.0,
                timespan_secs: 300,
                events: None,
                event_refs: None,
            }),
        }
    }

    #[test]
    fn parse_round_trips_every_namespace() {
        for raw in [
            "rule",
            "level",
            "event.host.name",
            "match.SourceIp",
            "enrichment.geo.country",
            "correlation.group_key.SourceIp",
        ] {
            let sel = Selector::parse(raw).unwrap();
            assert_eq!(sel.as_str(), raw);
        }
    }

    #[test]
    fn parse_rejects_unknown_namespace() {
        let err = Selector::parse("bogus.field").unwrap_err();
        assert_eq!(err.selector, "bogus.field");
        assert!(err.message.contains("unknown namespace"));
    }

    #[test]
    fn parse_rejects_empty_paths() {
        assert!(Selector::parse("event.").is_err());
        assert!(Selector::parse("match.").is_err());
        assert!(Selector::parse("enrichment.").is_err());
        assert!(Selector::parse("correlation.group_key.").is_err());
    }

    #[test]
    fn resolve_rule_prefers_id_then_title() {
        assert_eq!(
            Selector::Rule.resolve(&detection()),
            Some(Value::String("rule-1".to_string()))
        );
        assert_eq!(
            Selector::Rule.resolve(&correlation()),
            Some(Value::String("SSH brute force".to_string()))
        );
    }

    #[test]
    fn resolve_level_lowercases() {
        assert_eq!(
            Selector::Level.resolve(&detection()),
            Some(Value::String("high".to_string()))
        );
    }

    #[test]
    fn resolve_event_path() {
        let sel = Selector::parse("event.host.name").unwrap();
        assert_eq!(sel.resolve(&detection()), Some(serde_json::json!("dc01")));
        // Missing path resolves to None.
        assert_eq!(
            Selector::parse("event.nope").unwrap().resolve(&detection()),
            None
        );
        // Correlation has no detection event.
        assert_eq!(sel.resolve(&correlation()), None);
    }

    #[test]
    fn resolve_match_field() {
        let sel = Selector::parse("match.SourceIp").unwrap();
        assert_eq!(
            sel.resolve(&detection()),
            Some(serde_json::json!("10.0.0.5"))
        );
        assert_eq!(sel.resolve(&correlation()), None);
    }

    #[test]
    fn resolve_enrichment_path() {
        let sel = Selector::parse("enrichment.geo.country").unwrap();
        assert_eq!(sel.resolve(&detection()), Some(serde_json::json!("US")));
        assert_eq!(
            Selector::parse("enrichment.host")
                .unwrap()
                .resolve(&detection()),
            Some(serde_json::json!("dc01"))
        );
        assert_eq!(sel.resolve(&correlation()), None);
    }

    #[test]
    fn resolve_correlation_group_key() {
        let sel = Selector::parse("correlation.group_key.SourceIp").unwrap();
        assert_eq!(
            sel.resolve(&correlation()),
            Some(serde_json::json!("203.0.113.4"))
        );
        assert_eq!(sel.resolve(&detection()), None);
    }
}
