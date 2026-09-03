//! Embedded rule exemplars under `rsigma.exemplars`.
//!
//! Exemplars are machine-verifiable example events carried on a Sigma rule
//! as a custom attribute. Detection rules use a single `event` mapping;
//! correlation rules use a timestamped `events` sequence. The engine never
//! interprets these values at match time; they are documentation plus a
//! closed verification recipe for `rule test`.

use std::collections::HashMap;
use std::fmt;

use serde::Serialize;
use yaml_serde::Value;

use crate::ast::{CorrelationRule, FilterRule, SigmaRule};
use crate::value::Timespan;

/// The custom-attribute key that carries embedded exemplars.
pub const EXEMPLARS_KEY: &str = "rsigma.exemplars";

/// Allowed keys on one exemplar entry.
const ENTRY_KEYS: &[&str] = &["name", "expect", "event", "events"];

/// Allowed keys on one timed correlation event.
const TIMED_KEYS: &[&str] = &["offset", "event"];

/// Which kind of Sigma document an exemplar list is attached to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExemplarRuleKind {
    /// A stateless detection rule (`event:` payload).
    Detection,
    /// A stateful correlation rule (`events:` payload).
    Correlation,
    /// A filter rule (must not carry exemplars).
    Filter,
}

/// Whether the exemplar is expected to match the target rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Expect {
    /// The target rule should produce a result.
    Match,
    /// The target rule should not produce a result.
    NoMatch,
}

impl Expect {
    /// Parse `match` / `no-match`.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "match" => Some(Self::Match),
            "no-match" => Some(Self::NoMatch),
            _ => None,
        }
    }

    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Match => "match",
            Self::NoMatch => "no-match",
        }
    }
}

impl fmt::Display for Expect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One timed event in a correlation exemplar sequence.
#[derive(Debug, Clone, PartialEq)]
pub struct TimedEvent {
    /// Offset from the deterministic base timestamp.
    pub offset: Timespan,
    /// Event body as a YAML mapping.
    pub event: Value,
}

/// The payload of one exemplar.
#[derive(Debug, Clone, PartialEq)]
pub enum ExemplarPayload {
    /// A single event for a detection rule.
    Event(Value),
    /// A timestamped sequence for a correlation rule.
    Sequence(Vec<TimedEvent>),
}

/// One extracted exemplar.
#[derive(Debug, Clone, PartialEq)]
pub struct Exemplar {
    /// Display name (explicit `name` or the 0-based index as a string).
    pub name: String,
    /// 0-based index in the source list.
    pub index: usize,
    /// Expected outcome.
    pub expect: Expect,
    /// Event or event sequence.
    pub payload: ExemplarPayload,
}

/// A structural problem in an exemplar list or entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExemplarShapeError {
    /// JSON-pointer path of the offending node.
    pub path: String,
    /// Human-readable description.
    pub message: String,
}

impl fmt::Display for ExemplarShapeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

impl ExemplarShapeError {
    /// True when the error is a payload/kind mismatch rather than a structural one.
    pub fn is_wrong_rule_kind(&self) -> bool {
        self.message.contains("must use 'event'")
            || self.message.contains("must use 'events'")
            || self.message.contains("filter rules must not")
    }
}

/// Extract exemplars from a detection rule.
pub fn exemplars(rule: &SigmaRule) -> Result<Vec<Exemplar>, Vec<ExemplarShapeError>> {
    exemplars_from_attrs(&rule.custom_attributes, ExemplarRuleKind::Detection)
}

/// Extract exemplars from a correlation rule.
pub fn correlation_exemplars(
    rule: &CorrelationRule,
) -> Result<Vec<Exemplar>, Vec<ExemplarShapeError>> {
    exemplars_from_attrs(&rule.custom_attributes, ExemplarRuleKind::Correlation)
}

/// Extract exemplars from a filter rule (always empty or an error).
pub fn filter_exemplars(rule: &FilterRule) -> Result<Vec<Exemplar>, Vec<ExemplarShapeError>> {
    exemplars_from_attrs(&rule.custom_attributes, ExemplarRuleKind::Filter)
}

/// Extract exemplars from a winning `custom_attributes` map.
pub fn exemplars_from_attrs(
    attrs: &HashMap<String, Value>,
    kind: ExemplarRuleKind,
) -> Result<Vec<Exemplar>, Vec<ExemplarShapeError>> {
    let Some(value) = attrs.get(EXEMPLARS_KEY) else {
        return Ok(Vec::new());
    };
    parse_exemplars(value, kind, format!("/custom_attributes/{EXEMPLARS_KEY}"))
}

/// Count structurally valid `expect: match` exemplars on a parsed attribute map.
pub fn match_exemplar_count(attrs: &HashMap<String, Value>) -> usize {
    match exemplars_from_attrs(attrs, ExemplarRuleKind::Detection) {
        Ok(list) => list.iter().filter(|e| e.expect == Expect::Match).count(),
        Err(_) => 0,
    }
}

/// Count structurally valid `expect: match` exemplars on a JSON attribute map.
pub fn match_exemplar_count_json(attrs: &HashMap<String, serde_json::Value>) -> usize {
    let Some(value) = attrs.get(EXEMPLARS_KEY) else {
        return 0;
    };
    let Ok(yaml) = yaml_serde::to_value(value) else {
        return 0;
    };
    match parse_exemplars(
        &yaml,
        ExemplarRuleKind::Detection,
        EXEMPLARS_KEY.to_string(),
    ) {
        Ok(list) => list.iter().filter(|e| e.expect == Expect::Match).count(),
        Err(_) => 0,
    }
}

/// Every raw `rsigma.exemplars` value on a YAML mapping, from both the nested
/// `custom_attributes:` map and a top-level dotted key, with its JSON-pointer.
pub fn raw_exemplar_values(m: &yaml_serde::Mapping) -> Vec<(String, &Value)> {
    let mut out = Vec::new();
    if let Some(ca) = m
        .get(val_key("custom_attributes"))
        .and_then(|v| v.as_mapping())
        && let Some(v) = mapping_get(ca, EXEMPLARS_KEY)
    {
        out.push((format!("/custom_attributes/{EXEMPLARS_KEY}"), v));
    }
    if let Some(v) = mapping_get(m, EXEMPLARS_KEY) {
        out.push((format!("/{EXEMPLARS_KEY}"), v));
    }
    out
}

/// The winning raw exemplar value, matching parser precedence (nested wins).
pub fn raw_winning_exemplars(m: &yaml_serde::Mapping) -> Option<&Value> {
    if let Some(ca) = m
        .get(val_key("custom_attributes"))
        .and_then(|v| v.as_mapping())
        && let Some(v) = mapping_get(ca, EXEMPLARS_KEY)
    {
        return Some(v);
    }
    mapping_get(m, EXEMPLARS_KEY)
}

/// Count structurally valid `expect: match` exemplars on the winning raw value.
pub fn raw_match_exemplar_count(m: &yaml_serde::Mapping) -> usize {
    let Some(value) = raw_winning_exemplars(m) else {
        return 0;
    };
    match parse_exemplars(
        value,
        ExemplarRuleKind::Detection,
        EXEMPLARS_KEY.to_string(),
    ) {
        Ok(list) => list.iter().filter(|e| e.expect == Expect::Match).count(),
        Err(_) => 0,
    }
}

/// Parse a raw exemplar YAML value with kind-specific payload rules.
pub fn parse_exemplars(
    value: &Value,
    kind: ExemplarRuleKind,
    path: String,
) -> Result<Vec<Exemplar>, Vec<ExemplarShapeError>> {
    let mut errors = Vec::new();
    let Some(seq) = value.as_sequence() else {
        return Err(vec![err(
            path,
            "rsigma.exemplars must be a sequence of mappings",
        )]);
    };
    if seq.is_empty() {
        return Err(vec![err(path, "rsigma.exemplars must not be empty")]);
    }
    if kind == ExemplarRuleKind::Filter {
        errors.push(err(
            path.clone(),
            "filter rules must not carry rsigma.exemplars",
        ));
        return Err(errors);
    }

    let mut seen_names: Vec<String> = Vec::new();
    let mut exemplars = Vec::new();
    for (index, item) in seq.iter().enumerate() {
        let item_path = format!("{path}/{index}");
        match parse_entry(item, kind, index, &item_path, &mut seen_names) {
            Ok(exemplar) => exemplars.push(exemplar),
            Err(mut item_errors) => errors.append(&mut item_errors),
        }
    }
    if errors.is_empty() {
        Ok(exemplars)
    } else {
        Err(errors)
    }
}

fn parse_entry(
    item: &Value,
    kind: ExemplarRuleKind,
    index: usize,
    path: &str,
    seen_names: &mut Vec<String>,
) -> Result<Exemplar, Vec<ExemplarShapeError>> {
    let mut errors = Vec::new();
    let Some(map) = item.as_mapping() else {
        return Err(vec![err(
            path.to_string(),
            "each exemplar must be a mapping",
        )]);
    };

    for key in map.keys() {
        let Some(ks) = key.as_str() else { continue };
        if !ENTRY_KEYS.contains(&ks) {
            errors.push(err(
                format!("{path}/{ks}"),
                format!("unknown exemplar key '{ks}'"),
            ));
        }
    }

    let name = match mapping_get(map, "name") {
        None => index.to_string(),
        Some(Value::String(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                errors.push(err(
                    format!("{path}/name"),
                    "exemplar name must not be blank",
                ));
                index.to_string()
            } else {
                if seen_names.iter().any(|n| n == trimmed) {
                    errors.push(err(
                        format!("{path}/name"),
                        format!("duplicate exemplar name '{trimmed}'"),
                    ));
                } else {
                    seen_names.push(trimmed.to_string());
                }
                trimmed.to_string()
            }
        }
        Some(_) => {
            errors.push(err(
                format!("{path}/name"),
                "exemplar name must be a string",
            ));
            index.to_string()
        }
    };

    let expect = match mapping_get(map, "expect") {
        None => {
            errors.push(err(format!("{path}/expect"), "missing 'expect'"));
            Expect::Match
        }
        Some(Value::String(s)) => match Expect::parse(s) {
            Some(e) => e,
            None => {
                errors.push(err(
                    format!("{path}/expect"),
                    format!("invalid expect '{s}'; expected match or no-match"),
                ));
                Expect::Match
            }
        },
        Some(_) => {
            errors.push(err(
                format!("{path}/expect"),
                "expect must be 'match' or 'no-match'",
            ));
            Expect::Match
        }
    };

    let has_event = mapping_get(map, "event").is_some();
    let has_events = mapping_get(map, "events").is_some();
    let payload = match (has_event, has_events, kind) {
        (true, true, _) => {
            errors.push(err(
                path.to_string(),
                "exemplar must have exactly one of 'event' or 'events'",
            ));
            ExemplarPayload::Event(Value::Null)
        }
        (false, false, _) => {
            errors.push(err(
                path.to_string(),
                "exemplar must have exactly one of 'event' or 'events'",
            ));
            ExemplarPayload::Event(Value::Null)
        }
        (true, false, ExemplarRuleKind::Correlation) => {
            errors.push(err(
                format!("{path}/event"),
                "correlation exemplars must use 'events'",
            ));
            ExemplarPayload::Event(Value::Null)
        }
        (false, true, ExemplarRuleKind::Detection) => {
            errors.push(err(
                format!("{path}/events"),
                "detection exemplars must use 'event'",
            ));
            ExemplarPayload::Event(Value::Null)
        }
        (true, false, ExemplarRuleKind::Detection) => {
            match parse_event_mapping(mapping_get(map, "event").expect("event present"), path) {
                Ok(event) => ExemplarPayload::Event(event),
                Err(e) => {
                    errors.push(e);
                    ExemplarPayload::Event(Value::Null)
                }
            }
        }
        (false, true, ExemplarRuleKind::Correlation) => {
            match parse_sequence(mapping_get(map, "events").expect("events present"), path) {
                Ok(seq) => ExemplarPayload::Sequence(seq),
                Err(mut seq_errors) => {
                    errors.append(&mut seq_errors);
                    ExemplarPayload::Sequence(Vec::new())
                }
            }
        }
        (_, _, ExemplarRuleKind::Filter) => ExemplarPayload::Event(Value::Null),
    };

    if errors.is_empty() {
        Ok(Exemplar {
            name,
            index,
            expect,
            payload,
        })
    } else {
        Err(errors)
    }
}

fn parse_event_mapping(value: &Value, path: &str) -> Result<Value, ExemplarShapeError> {
    match value {
        Value::Mapping(_) => Ok(value.clone()),
        _ => Err(err(format!("{path}/event"), "event must be a mapping")),
    }
}

fn parse_sequence(value: &Value, path: &str) -> Result<Vec<TimedEvent>, Vec<ExemplarShapeError>> {
    let Some(seq) = value.as_sequence() else {
        return Err(vec![err(
            format!("{path}/events"),
            "events must be a sequence of mappings",
        )]);
    };
    if seq.is_empty() {
        return Err(vec![err(
            format!("{path}/events"),
            "events must not be empty",
        )]);
    }

    let mut errors = Vec::new();
    let mut events = Vec::new();
    let mut prev_secs: Option<u64> = None;
    for (index, item) in seq.iter().enumerate() {
        let item_path = format!("{path}/events/{index}");
        match parse_timed_event(item, &item_path) {
            Ok(event) => {
                if let Some(prev) = prev_secs
                    && event.offset.seconds < prev
                {
                    errors.push(err(
                        format!("{item_path}/offset"),
                        "offsets must be non-decreasing",
                    ));
                }
                prev_secs = Some(event.offset.seconds);
                events.push(event);
            }
            Err(mut item_errors) => errors.append(&mut item_errors),
        }
    }
    if errors.is_empty() {
        Ok(events)
    } else {
        Err(errors)
    }
}

fn parse_timed_event(item: &Value, path: &str) -> Result<TimedEvent, Vec<ExemplarShapeError>> {
    let mut errors = Vec::new();
    let Some(map) = item.as_mapping() else {
        return Err(vec![err(
            path.to_string(),
            "each timed event must be a mapping",
        )]);
    };
    for key in map.keys() {
        let Some(ks) = key.as_str() else { continue };
        if !TIMED_KEYS.contains(&ks) {
            errors.push(err(
                format!("{path}/{ks}"),
                format!("unknown timed-event key '{ks}'"),
            ));
        }
    }

    let offset = match mapping_get(map, "offset") {
        None => {
            errors.push(err(format!("{path}/offset"), "missing 'offset'"));
            None
        }
        Some(Value::String(s)) => match Timespan::parse(s) {
            Ok(ts) => Some(ts),
            Err(_) => {
                errors.push(err(
                    format!("{path}/offset"),
                    format!("invalid timespan '{s}'"),
                ));
                None
            }
        },
        Some(Value::Number(n)) if n.as_u64() == Some(0) => Timespan::parse("0s").ok(),
        Some(_) => {
            errors.push(err(
                format!("{path}/offset"),
                "offset must be a duration string such as 0s or 30s",
            ));
            None
        }
    };

    let event = match mapping_get(map, "event") {
        None => {
            errors.push(err(format!("{path}/event"), "missing 'event'"));
            None
        }
        Some(Value::Mapping(_)) => Some(mapping_get(map, "event").expect("event").clone()),
        Some(_) => {
            errors.push(err(format!("{path}/event"), "event must be a mapping"));
            None
        }
    };

    match (offset, event, errors.is_empty()) {
        (Some(offset), Some(event), true) => Ok(TimedEvent { offset, event }),
        _ => Err(errors),
    }
}

fn err(path: impl Into<String>, message: impl Into<String>) -> ExemplarShapeError {
    ExemplarShapeError {
        path: path.into(),
        message: message.into(),
    }
}

fn val_key(s: &str) -> Value {
    Value::String(s.to_string())
}

fn mapping_get<'a>(m: &'a yaml_serde::Mapping, key: &str) -> Option<&'a Value> {
    m.get(val_key(key)).or_else(|| {
        m.iter()
            .find_map(|(k, v)| (k.as_str() == Some(key)).then_some(v))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_sigma_yaml;

    fn rule(yaml: &str) -> SigmaRule {
        parse_sigma_yaml(yaml).unwrap().rules.pop().unwrap()
    }

    fn corr(yaml: &str) -> CorrelationRule {
        parse_sigma_yaml(yaml).unwrap().correlations.pop().unwrap()
    }

    const DETECTION: &str = r#"
title: Whoami
id: 11111111-2222-3333-4444-555555555555
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
custom_attributes:
    rsigma.exemplars:
        - name: whoami fires
          expect: match
          event:
              CommandLine: whoami /all
        - name: benign hostname
          expect: no-match
          event:
              CommandLine: hostname
"#;

    const CORRELATION: &str = r#"
title: Login
id: login-rule
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
---
title: Burst
correlation:
    type: event_count
    rules: [login-rule]
    group-by: [User]
    timespan: 1m
    condition: { gte: 2 }
custom_attributes:
    rsigma.exemplars:
        - name: burst of failures
          expect: match
          events:
              - offset: 0s
                event: { EventType: login, User: alice }
              - offset: 30s
                event: { EventType: login, User: alice }
"#;

    #[test]
    fn extracts_detection_exemplars() {
        let list = exemplars(&rule(DETECTION)).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "whoami fires");
        assert_eq!(list[0].expect, Expect::Match);
        assert!(matches!(list[0].payload, ExemplarPayload::Event(_)));
        assert_eq!(list[1].expect, Expect::NoMatch);
        assert_eq!(match_exemplar_count(&rule(DETECTION).custom_attributes), 1);
    }

    #[test]
    fn extracts_correlation_exemplars() {
        let list = correlation_exemplars(&corr(CORRELATION)).unwrap();
        assert_eq!(list.len(), 1);
        match &list[0].payload {
            ExemplarPayload::Sequence(events) => {
                assert_eq!(events.len(), 2);
                assert_eq!(events[0].offset.original, "0s");
                assert_eq!(events[1].offset.seconds, 30);
            }
            other => panic!("expected sequence, got {other:?}"),
        }
    }

    #[test]
    fn nested_custom_attributes_win_over_top_level() {
        let parsed = rule(
            r#"
title: Precedence
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
rsigma.exemplars:
    - expect: match
      event: { field: top }
custom_attributes:
    rsigma.exemplars:
        - name: nested
          expect: no-match
          event: { field: nested }
"#,
        );
        let list = exemplars(&parsed).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "nested");
        assert_eq!(list[0].expect, Expect::NoMatch);
    }

    #[test]
    fn global_action_inherits_exemplars() {
        let collection = parse_sigma_yaml(
            r#"
action: global
custom_attributes:
    rsigma.exemplars:
        - expect: match
          event: { field: value }
---
title: Inherited
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
"#,
        )
        .unwrap();
        let list = exemplars(&collection.rules[0]).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].expect, Expect::Match);
    }

    #[test]
    fn rejects_empty_list() {
        let parsed = rule(
            r#"
title: Empty
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
custom_attributes:
    rsigma.exemplars: []
"#,
        );
        let err = exemplars(&parsed).unwrap_err();
        assert!(err.iter().any(|e| e.message.contains("must not be empty")));
    }

    #[test]
    fn rejects_detection_events_payload() {
        let parsed = rule(
            r#"
title: Wrong kind
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
custom_attributes:
    rsigma.exemplars:
        - expect: match
          events:
              - offset: 0s
                event: { field: value }
"#,
        );
        let err = exemplars(&parsed).unwrap_err();
        assert!(err.iter().any(|e| e.message.contains("must use 'event'")));
    }

    #[test]
    fn rejects_decreasing_offsets() {
        let err = correlation_exemplars(&corr(
            r#"
title: Login
id: login-rule
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
---
title: Burst
correlation:
    type: event_count
    rules: [login-rule]
    group-by: [User]
    timespan: 1m
    condition: { gte: 2 }
custom_attributes:
    rsigma.exemplars:
        - expect: match
          events:
              - offset: 30s
                event: { EventType: login }
              - offset: 10s
                event: { EventType: login }
"#,
        ))
        .unwrap_err();
        assert!(err.iter().any(|e| e.message.contains("non-decreasing")));
    }

    #[test]
    fn filter_exemplars_are_rejected() {
        let filter = parse_sigma_yaml(
            r#"
title: Exclude
logsource:
    category: test
filter:
    rules: []
    selection:
        field: skip
    condition: selection
custom_attributes:
    rsigma.exemplars:
        - expect: match
          event: { field: skip }
"#,
        )
        .unwrap()
        .filters
        .pop()
        .unwrap();
        let err = filter_exemplars(&filter).unwrap_err();
        assert!(
            err.iter()
                .any(|e| e.message.contains("filter rules must not"))
        );
    }

    #[test]
    fn raw_helper_sees_both_placements() {
        let value: Value = yaml_serde::from_str(
            r#"
title: Both
rsigma.exemplars:
    - expect: match
      event: { a: 1 }
custom_attributes:
    rsigma.exemplars:
        - expect: no-match
          event: { a: 2 }
"#,
        )
        .unwrap();
        let m = value.as_mapping().unwrap();
        assert_eq!(raw_exemplar_values(m).len(), 2);
        let winning = raw_winning_exemplars(m).unwrap();
        assert!(
            winning.as_sequence().unwrap()[0]
                .as_mapping()
                .unwrap()
                .get(val_key("expect"))
                .unwrap()
                .as_str()
                .unwrap()
                .contains("no-match")
        );
    }

    #[test]
    fn malformed_exemplars_do_not_count_as_ads_validation() {
        let parsed = rule(
            r#"
title: Bad
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
custom_attributes:
    rsigma.exemplars: not-a-list
"#,
        );
        assert_eq!(match_exemplar_count(&parsed.custom_attributes), 0);
    }
}
