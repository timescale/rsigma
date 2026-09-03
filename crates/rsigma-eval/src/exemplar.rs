//! Replay embedded `rsigma.exemplars` against their host rules.

use std::collections::HashMap;
use std::fmt;

use rsigma_parser::{
    Exemplar, ExemplarErrorKind, ExemplarPayload, ExemplarRuleKind, ExemplarShapeError, Expect,
    SigmaCollection, SigmaRule, correlation_exemplars, exemplars, filter_exemplars,
};
use serde::Serialize;

use crate::compiler::yaml_to_json;
use crate::correlation_engine::{CorrelationConfig, CorrelationEngine};
use crate::engine::Engine;
use crate::error::EvalError;
use crate::event::JsonEvent;
use crate::pipeline::Pipeline;
use crate::result::EvaluationResult;

/// Deterministic base timestamp for correlation exemplar offsets.
const BASE_TIMESTAMP: i64 = 1_700_000_000;

/// One asserted exemplar outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExemplarResult {
    /// Rule `id`, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Rule title.
    pub rule_title: String,
    /// Detection or correlation.
    pub rule_kind: ExemplarRuleKind,
    /// 0-based index in the source list.
    pub index: usize,
    /// Display name.
    pub name: String,
    /// Expected outcome.
    pub expect: Expect,
    /// Observed outcome.
    pub actual: Expect,
    /// Whether `actual` matches `expect`.
    pub passed: bool,
    /// Why the assertion failed. Absent on passing exemplars.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<String>,
}

/// A detection or correlation rule that carried no exemplars.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MissingExemplars {
    /// Rule `id`, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Rule title.
    pub rule_title: String,
    /// Detection or correlation.
    pub rule_kind: ExemplarRuleKind,
}

/// Report of every asserted exemplar plus rules with none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExemplarReport {
    /// Caller-supplied source label (path or `inline`).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub source: String,
    /// Per-exemplar outcomes, in collection then list order.
    pub results: Vec<ExemplarResult>,
    /// Detection and correlation rules that carried no exemplars.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub missing: Vec<MissingExemplars>,
}

impl ExemplarReport {
    /// True when every asserted exemplar passed.
    pub fn all_passed(&self) -> bool {
        self.results.iter().all(|r| r.passed)
    }

    /// Failed assertions.
    pub fn failures(&self) -> impl Iterator<Item = &ExemplarResult> {
        self.results.iter().filter(|r| !r.passed)
    }
}

/// Configuration or compilation failure that aborts the run.
#[derive(Debug)]
pub enum ExemplarRunError {
    /// Structurally invalid exemplars on a named rule.
    Shape {
        /// Rule title or id used in the diagnostic.
        rule: String,
        /// Parser shape errors.
        errors: Vec<ExemplarShapeError>,
    },
    /// Title fallback is not unique in the collection.
    AmbiguousTitle(String),
    /// A correlation referenced a rule that is not in the collection.
    Reference(String),
    /// A rule or pipeline failed to compile.
    Compile(EvalError),
}

impl fmt::Display for ExemplarRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Shape { rule, errors } => {
                write!(f, "invalid exemplars on '{rule}': ")?;
                let messages: Vec<String> = errors.iter().map(ToString::to_string).collect();
                f.write_str(&messages.join("; "))
            }
            Self::AmbiguousTitle(title) => {
                write!(
                    f,
                    "ambiguous rule title '{title}': add an id or make the title unique"
                )
            }
            Self::Reference(msg) => f.write_str(msg),
            Self::Compile(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ExemplarRunError {}

impl From<EvalError> for ExemplarRunError {
    fn from(err: EvalError) -> Self {
        match err {
            EvalError::UnknownRuleRef(r) => Self::Reference(format!("unknown rule reference: {r}")),
            other => Self::Compile(other),
        }
    }
}

/// Replay every embedded exemplar in `collection` with fresh engine state.
pub fn run_exemplars(
    collection: &SigmaCollection,
    pipelines: &[Pipeline],
) -> Result<ExemplarReport, ExemplarRunError> {
    let titles = title_counts(collection);
    let mut results = Vec::new();
    let mut missing = Vec::new();

    for rule in &collection.rules {
        let identity = TargetIdentity {
            id: rule.id.clone(),
            title: rule.title.clone(),
            kind: ExemplarRuleKind::Detection,
        };
        let list = exemplars(rule).map_err(|errors| ExemplarRunError::Shape {
            rule: identity.label(),
            errors,
        })?;
        if list.is_empty() {
            missing.push(identity.to_missing());
            continue;
        }
        identity.require_unique(&titles)?;
        for exemplar in list {
            results.push(run_detection(
                collection, rule, &identity, &exemplar, pipelines,
            )?);
        }
    }

    for rule in &collection.correlations {
        let identity = TargetIdentity {
            id: rule.id.clone(),
            title: rule.title.clone(),
            kind: ExemplarRuleKind::Correlation,
        };
        let list = correlation_exemplars(rule).map_err(|errors| ExemplarRunError::Shape {
            rule: identity.label(),
            errors,
        })?;
        if list.is_empty() {
            missing.push(identity.to_missing());
            continue;
        }
        identity.require_unique(&titles)?;
        for exemplar in list {
            results.push(run_correlation(
                collection, &identity, &exemplar, pipelines,
            )?);
        }
    }

    for rule in &collection.filters {
        if let Err(errors) = filter_exemplars(rule) {
            return Err(ExemplarRunError::Shape {
                rule: rule.id.clone().unwrap_or_else(|| rule.title.clone()),
                errors,
            });
        }
    }

    Ok(ExemplarReport {
        source: String::new(),
        results,
        missing,
    })
}

struct TargetIdentity {
    id: Option<String>,
    title: String,
    kind: ExemplarRuleKind,
}

impl TargetIdentity {
    fn label(&self) -> String {
        self.id.clone().unwrap_or_else(|| self.title.clone())
    }

    fn require_unique(&self, titles: &HashMap<String, usize>) -> Result<(), ExemplarRunError> {
        if self.id.is_some() {
            return Ok(());
        }
        if titles.get(&self.title).copied().unwrap_or(0) > 1 {
            return Err(ExemplarRunError::AmbiguousTitle(self.title.clone()));
        }
        Ok(())
    }

    fn to_missing(&self) -> MissingExemplars {
        MissingExemplars {
            rule_id: self.id.clone(),
            rule_title: self.title.clone(),
            rule_kind: self.kind,
        }
    }

    fn matches(&self, result: &EvaluationResult) -> bool {
        let kind_ok = match self.kind {
            ExemplarRuleKind::Detection => result.is_detection(),
            ExemplarRuleKind::Correlation => result.is_correlation(),
            ExemplarRuleKind::Filter => false,
        };
        if !kind_ok {
            return false;
        }
        match &self.id {
            Some(id) => result.header.rule_id.as_deref() == Some(id.as_str()),
            None => result.header.rule_title == self.title,
        }
    }
}

fn title_counts(collection: &SigmaCollection) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for title in collection
        .rules
        .iter()
        .map(|r| r.title.as_str())
        .chain(collection.correlations.iter().map(|r| r.title.as_str()))
    {
        *counts.entry(title.to_string()).or_insert(0) += 1;
    }
    counts
}

fn run_detection(
    collection: &SigmaCollection,
    rule: &SigmaRule,
    identity: &TargetIdentity,
    exemplar: &Exemplar,
    pipelines: &[Pipeline],
) -> Result<ExemplarResult, ExemplarRunError> {
    let ExemplarPayload::Event(event) = &exemplar.payload else {
        return Err(ExemplarRunError::Shape {
            rule: identity.label(),
            errors: vec![ExemplarShapeError {
                path: format!("/custom_attributes/rsigma.exemplars/{}", exemplar.index),
                message: "detection exemplars must use 'event'".to_string(),
                kind: ExemplarErrorKind::WrongRuleKind,
            }],
        });
    };
    let synthetic = SigmaCollection {
        rules: vec![rule.clone()],
        correlations: Vec::new(),
        filters: collection.filters.clone(),
        errors: Vec::new(),
    };
    let mut engine = Engine::new();
    if pipelines.is_empty() {
        engine.add_collection(&synthetic)?;
    } else {
        engine.add_collection_with_pipelines(&synthetic, pipelines)?;
    }
    let json = yaml_to_json(event);
    let je = JsonEvent::borrow(&json);
    let matches = engine.evaluate(&je);
    let fired = matches.iter().any(|r| identity.matches(r));
    let diagnostic = match (fired, exemplar.expect) {
        (true, Expect::NoMatch) => Some("the rule matched the event".to_string()),
        (false, Expect::Match) => Some("the rule did not match the event".to_string()),
        _ => None,
    };
    Ok(outcome(identity, exemplar, fired, diagnostic))
}

fn run_correlation(
    collection: &SigmaCollection,
    identity: &TargetIdentity,
    exemplar: &Exemplar,
    pipelines: &[Pipeline],
) -> Result<ExemplarResult, ExemplarRunError> {
    let ExemplarPayload::Sequence(events) = &exemplar.payload else {
        return Err(ExemplarRunError::Shape {
            rule: identity.label(),
            errors: vec![ExemplarShapeError {
                path: format!("/custom_attributes/rsigma.exemplars/{}", exemplar.index),
                message: "correlation exemplars must use 'events'".to_string(),
                kind: ExemplarErrorKind::WrongRuleKind,
            }],
        });
    };
    let mut engine = CorrelationEngine::new(CorrelationConfig::default());
    for pipeline in pipelines {
        engine.add_pipeline(pipeline.clone());
    }
    engine.add_collection(collection)?;
    let owned: Vec<serde_json::Value> = events.iter().map(|e| yaml_to_json(&e.event)).collect();
    let mut first_fire: Option<(usize, String)> = None;
    for (index, (timed, json)) in events.iter().zip(owned.iter()).enumerate() {
        let je = JsonEvent::borrow(json);
        let ts = BASE_TIMESTAMP.saturating_add(timed.offset.seconds as i64);
        let results = engine.process_event_at(&je, ts);
        if first_fire.is_none() && results.iter().any(|r| identity.matches(r)) {
            first_fire = Some((index, timed.offset.original.clone()));
        }
    }
    let fired = first_fire.is_some();
    let diagnostic = match (first_fire, exemplar.expect) {
        (Some((index, offset)), Expect::NoMatch) => Some(format!(
            "the correlation fired at event index {index} (offset {offset})"
        )),
        (None, Expect::Match) => Some(format!(
            "the correlation never fired across {} events",
            events.len()
        )),
        _ => None,
    };
    Ok(outcome(identity, exemplar, fired, diagnostic))
}

fn outcome(
    identity: &TargetIdentity,
    exemplar: &Exemplar,
    fired: bool,
    diagnostic: Option<String>,
) -> ExemplarResult {
    let actual = if fired {
        Expect::Match
    } else {
        Expect::NoMatch
    };
    ExemplarResult {
        rule_id: identity.id.clone(),
        rule_title: identity.title.clone(),
        rule_kind: identity.kind,
        index: exemplar.index,
        name: exemplar.name.clone(),
        expect: exemplar.expect,
        actual,
        passed: actual == exemplar.expect,
        diagnostic,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_parser::parse_sigma_yaml;

    fn collection(yaml: &str) -> SigmaCollection {
        parse_sigma_yaml(yaml).unwrap()
    }

    fn run(yaml: &str) -> ExemplarReport {
        run_exemplars(&collection(yaml), &[]).expect("run")
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

    #[test]
    fn detection_match_and_no_match() {
        let report = run(DETECTION);
        assert!(report.all_passed());
        assert_eq!(report.results.len(), 2);
        assert_eq!(report.results[0].actual, Expect::Match);
        assert_eq!(report.results[1].actual, Expect::NoMatch);
        assert!(report.missing.is_empty());
    }

    #[test]
    fn failed_assertion_is_not_a_run_error() {
        let yaml = r#"
title: Whoami
id: 11111111-2222-3333-4444-555555555555
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
custom_attributes:
    rsigma.exemplars:
        - expect: match
          event:
              CommandLine: hostname
"#;
        let report = run(yaml);
        assert!(!report.all_passed());
        assert_eq!(report.results[0].actual, Expect::NoMatch);
        assert_eq!(
            report.results[0].diagnostic.as_deref(),
            Some("the rule did not match the event")
        );
    }

    #[test]
    fn passing_exemplars_carry_no_diagnostic() {
        let report = run(DETECTION);
        assert!(report.results.iter().all(|r| r.diagnostic.is_none()));
    }

    #[test]
    fn failed_correlation_no_match_names_the_firing_event() {
        let yaml = r#"
title: Login
id: login-rule
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
---
title: Many Logins
correlation:
    type: event_count
    rules:
        - login-rule
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 2
custom_attributes:
    rsigma.exemplars:
        - expect: no-match
          events:
              - offset: 0s
                event: { EventType: login, User: alice }
              - offset: 30s
                event: { EventType: login, User: alice }
"#;
        let report = run(yaml);
        assert!(!report.all_passed());
        assert_eq!(
            report.results[0].diagnostic.as_deref(),
            Some("the correlation fired at event index 1 (offset 30s)")
        );
    }

    #[test]
    fn suppression_and_reset_do_not_mask_the_first_fire() {
        let yaml = r#"
title: Login
id: login-rule
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
---
title: Many Logins
correlation:
    type: event_count
    rules:
        - login-rule
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 2
custom_attributes:
    rsigma.suppress: 5m
    rsigma.action: reset
    rsigma.exemplars:
        - name: fires despite suppression
          expect: match
          events:
              - offset: 0s
                event: { EventType: login, User: alice }
              - offset: 1s
                event: { EventType: login, User: alice }
              - offset: 2s
                event: { EventType: login, User: alice }
              - offset: 3s
                event: { EventType: login, User: alice }
        - name: single event stays quiet
          expect: no-match
          events:
              - offset: 0s
                event: { EventType: login, User: bob }
"#;
        let report = run(yaml);
        assert!(report.all_passed(), "{report:?}");
        assert_eq!(report.results.len(), 2);
    }

    #[test]
    fn filter_excludes_matching_event() {
        let yaml = r#"
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
        - name: alice fires
          expect: match
          event:
              CommandLine: whoami /all
              User: alice
        - name: system filtered
          expect: no-match
          event:
              CommandLine: whoami /all
              User: SYSTEM
---
title: Exclude SYSTEM
logsource:
    category: process_creation
    product: windows
filter:
    rules:
        - 11111111-2222-3333-4444-555555555555
    selection:
        User: SYSTEM
    condition: not selection
"#;
        let report = run(yaml);
        assert!(report.all_passed(), "{report:?}");
    }

    #[test]
    fn pipeline_rewrites_rule_fields() {
        let yaml = r#"
title: Whoami
id: 11111111-2222-3333-4444-555555555555
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
custom_attributes:
    rsigma.exemplars:
        - expect: match
          event:
              process.command_line: whoami /all
"#;
        let pipeline = crate::parse_pipeline(
            r#"
name: map
priority: 10
transformations:
  - type: field_name_mapping
    mapping:
        CommandLine: process.command_line
"#,
        )
        .unwrap();
        let report = run_exemplars(&collection(yaml), &[pipeline]).unwrap();
        assert!(report.all_passed(), "{report:?}");
    }

    #[test]
    fn event_count_correlation() {
        let yaml = r#"
title: Login
id: login-rule
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
---
title: Many Logins
id: many-logins
correlation:
    type: event_count
    rules:
        - login-rule
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 3
custom_attributes:
    rsigma.exemplars:
        - name: burst
          expect: match
          events:
              - offset: 0s
                event: { EventType: login, User: alice }
              - offset: 1s
                event: { EventType: login, User: alice }
              - offset: 2s
                event: { EventType: login, User: alice }
        - name: too few
          expect: no-match
          events:
              - offset: 0s
                event: { EventType: login, User: bob }
              - offset: 1s
                event: { EventType: login, User: bob }
"#;
        let report = run(yaml);
        assert!(report.all_passed(), "{report:?}");
        assert_eq!(report.missing.len(), 1);
        assert_eq!(report.missing[0].rule_title, "Login");
    }

    #[test]
    fn value_count_correlation() {
        let yaml = r#"
title: Login
id: login-rule
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
---
title: Distinct Hosts
correlation:
    type: value_count
    rules:
        - login-rule
    group-by:
        - User
    timespan: 60s
    condition:
        field: Host
        gte: 2
custom_attributes:
    rsigma.exemplars:
        - expect: match
          events:
              - offset: 0s
                event: { EventType: login, User: alice, Host: a }
              - offset: 1s
                event: { EventType: login, User: alice, Host: b }
"#;
        let report = run(yaml);
        assert!(report.all_passed(), "{report:?}");
    }

    #[test]
    fn temporal_correlation() {
        let yaml = r#"
title: Failed
id: failed-login
logsource:
    category: auth
detection:
    selection:
        EventType: failed
    condition: selection
---
title: Success
id: success-login
logsource:
    category: auth
detection:
    selection:
        EventType: success
    condition: selection
---
title: Fail then success
correlation:
    type: temporal
    rules:
        - failed-login
        - success-login
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 2
custom_attributes:
    rsigma.exemplars:
        - expect: match
          events:
              - offset: 0s
                event: { EventType: failed, User: alice }
              - offset: 10s
                event: { EventType: success, User: alice }
        - expect: no-match
          events:
              - offset: 0s
                event: { EventType: failed, User: bob }
"#;
        let report = run(yaml);
        assert!(report.all_passed(), "{report:?}");
    }

    #[test]
    fn exemplars_do_not_share_state() {
        let yaml = r#"
title: Login
id: login-rule
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
---
title: Many Logins
correlation:
    type: event_count
    rules:
        - login-rule
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 3
custom_attributes:
    rsigma.exemplars:
        - name: first burst
          expect: match
          events:
              - offset: 0s
                event: { EventType: login, User: alice }
              - offset: 1s
                event: { EventType: login, User: alice }
              - offset: 2s
                event: { EventType: login, User: alice }
        - name: second burst
          expect: match
          events:
              - offset: 0s
                event: { EventType: login, User: alice }
              - offset: 1s
                event: { EventType: login, User: alice }
              - offset: 2s
                event: { EventType: login, User: alice }
"#;
        let report = run(yaml);
        assert!(report.all_passed(), "{report:?}");
        assert_eq!(report.results.len(), 2);
    }

    #[test]
    fn unrelated_detection_matches_do_not_count() {
        let yaml = r#"
title: Login
id: login-rule
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
---
title: Also login
id: also-login
logsource:
    category: auth
detection:
    selection:
        EventType: login
    condition: selection
---
title: Many Logins
id: many-logins
correlation:
    type: event_count
    rules:
        - login-rule
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 2
custom_attributes:
    rsigma.exemplars:
        - expect: match
          events:
              - offset: 0s
                event: { EventType: login, User: alice }
              - offset: 1s
                event: { EventType: login, User: alice }
"#;
        let report = run(yaml);
        assert!(report.all_passed(), "{report:?}");
        assert_eq!(report.results[0].rule_id.as_deref(), Some("many-logins"));
    }

    #[test]
    fn missing_correlation_ref_is_config_error() {
        let yaml = r#"
title: Many Logins
correlation:
    type: event_count
    rules:
        - missing-rule
    timespan: 60s
    condition:
        gte: 2
custom_attributes:
    rsigma.exemplars:
        - expect: match
          events:
              - offset: 0s
                event: { EventType: login }
              - offset: 1s
                event: { EventType: login }
"#;
        let err = run_exemplars(&collection(yaml), &[]).unwrap_err();
        assert!(matches!(err, ExemplarRunError::Reference(_)), "{err}");
    }

    #[test]
    fn duplicate_titles_without_id_are_rejected() {
        let yaml = r#"
title: Dup
logsource:
    category: test
detection:
    selection:
        field: a
    condition: selection
custom_attributes:
    rsigma.exemplars:
        - expect: match
          event:
              field: a
---
title: Dup
logsource:
    category: test
detection:
    selection:
        field: b
    condition: selection
"#;
        let err = run_exemplars(&collection(yaml), &[]).unwrap_err();
        assert!(matches!(err, ExemplarRunError::AmbiguousTitle(_)), "{err}");
    }

    #[test]
    fn malformed_exemplars_are_rejected() {
        let yaml = r#"
title: Whoami
logsource:
    category: test
detection:
    selection:
        field: value
    condition: selection
custom_attributes:
    rsigma.exemplars:
        - expect: banana
          event:
              field: value
"#;
        let err = run_exemplars(&collection(yaml), &[]).unwrap_err();
        assert!(matches!(err, ExemplarRunError::Shape { .. }), "{err}");
    }

    #[test]
    fn filter_exemplars_are_rejected() {
        let yaml = r#"
title: F
logsource:
    category: test
filter:
    selection:
        User: SYSTEM
    condition: selection
custom_attributes:
    rsigma.exemplars:
        - expect: match
          event:
              User: SYSTEM
"#;
        let err = run_exemplars(&collection(yaml), &[]).unwrap_err();
        assert!(matches!(err, ExemplarRunError::Shape { .. }), "{err}");
    }
}
