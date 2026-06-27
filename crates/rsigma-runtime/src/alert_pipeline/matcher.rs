//! Matcher engine shared by silencing and inhibition.
//!
//! A matcher is `selector <op> value`, where the left-hand side reuses the
//! field-selector namespace and `<op>` is one of the Alertmanager operators:
//! `=` (equals), `!=` (not equals), `=~` (regex match), `!~` (regex no-match).
//! Regex operators compile to anchored patterns. A [`MatcherSet`] ANDs its
//! matchers. A selector that resolves to nothing is treated as the empty
//! string, matching Alertmanager's absent-label semantics.

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use rsigma_eval::EvaluationResult;

use crate::selector::{Selector, SelectorParseError};

/// Matcher operator label, as written in config and over the API.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
pub enum MatchOp {
    /// `=`: the resolved value equals `value`.
    #[default]
    #[serde(rename = "=")]
    Eq,
    /// `!=`: the resolved value does not equal `value`.
    #[serde(rename = "!=")]
    Ne,
    /// `=~`: the resolved value matches the `value` regex.
    #[serde(rename = "=~")]
    ReMatch,
    /// `!~`: the resolved value does not match the `value` regex.
    #[serde(rename = "!~")]
    ReNotMatch,
}

/// One matcher as written in config / the API (serializable both ways).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MatcherSpec {
    /// Left-hand selector (e.g. `match.SourceIp`, `rule`, `level`).
    pub selector: String,
    /// Operator. Defaults to `=`.
    #[serde(default)]
    pub op: MatchOp,
    /// Right-hand literal (for `=`/`!=`) or regex (for `=~`/`!~`).
    pub value: String,
}

/// A failure to parse or compile a matcher, naming the offending selector or
/// regex.
#[derive(Debug, Clone)]
pub enum MatcherError {
    /// The selector failed to parse.
    Selector(SelectorParseError),
    /// The regex failed to compile.
    Regex { value: String, message: String },
}

impl std::fmt::Display for MatcherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MatcherError::Selector(e) => write!(f, "{e}"),
            MatcherError::Regex { value, message } => {
                write!(f, "invalid matcher regex '{value}': {message}")
            }
        }
    }
}

impl std::error::Error for MatcherError {}

/// A compiled matcher.
#[derive(Debug, Clone)]
pub struct Matcher {
    selector: Selector,
    op: MatchOp,
    value: String,
    regex: Option<Regex>,
}

impl Matcher {
    /// Compile a matcher from its spec.
    pub fn compile(spec: &MatcherSpec) -> Result<Self, MatcherError> {
        let selector = Selector::parse(&spec.selector).map_err(MatcherError::Selector)?;
        let regex = match spec.op {
            MatchOp::ReMatch | MatchOp::ReNotMatch => {
                // Anchor like Alertmanager so `=~ "foo"` is a full match.
                let anchored = format!("^(?:{})$", spec.value);
                Some(Regex::new(&anchored).map_err(|e| MatcherError::Regex {
                    value: spec.value.clone(),
                    message: e.to_string(),
                })?)
            }
            MatchOp::Eq | MatchOp::Ne => None,
        };
        Ok(Matcher {
            selector,
            op: spec.op,
            value: spec.value.clone(),
            regex,
        })
    }

    /// Recover the spec form for serialization (the GET views).
    pub fn to_spec(&self) -> MatcherSpec {
        MatcherSpec {
            selector: self.selector.as_str(),
            op: self.op,
            value: self.value.clone(),
        }
    }

    /// True when this matcher matches the result.
    fn matches(&self, result: &EvaluationResult) -> bool {
        let resolved = self
            .selector
            .resolve(result)
            .map(value_to_string)
            .unwrap_or_default();
        match self.op {
            MatchOp::Eq => resolved == self.value,
            MatchOp::Ne => resolved != self.value,
            MatchOp::ReMatch => self.regex.as_ref().is_some_and(|r| r.is_match(&resolved)),
            MatchOp::ReNotMatch => self.regex.as_ref().is_some_and(|r| !r.is_match(&resolved)),
        }
    }
}

/// A conjunction of matchers. Empty sets match nothing (a silence with no
/// matchers is rejected at build time, so this only guards against misuse).
#[derive(Debug, Clone, Default)]
pub struct MatcherSet {
    matchers: Vec<Matcher>,
}

impl MatcherSet {
    /// Compile a matcher set from specs. Errors name the offending matcher.
    pub fn compile(specs: &[MatcherSpec]) -> Result<Self, MatcherError> {
        let matchers = specs
            .iter()
            .map(Matcher::compile)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(MatcherSet { matchers })
    }

    /// True when the set is empty.
    pub fn is_empty(&self) -> bool {
        self.matchers.is_empty()
    }

    /// True when every matcher matches the result (AND). An empty set never
    /// matches, so it cannot accidentally mute everything.
    pub fn matches(&self, result: &EvaluationResult) -> bool {
        !self.matchers.is_empty() && self.matchers.iter().all(|m| m.matches(result))
    }

    /// The spec form of every matcher, for serialization.
    pub fn to_specs(&self) -> Vec<MatcherSpec> {
        self.matchers.iter().map(Matcher::to_spec).collect()
    }
}

/// Canonical string form of a resolved value, for comparison.
fn value_to_string(value: Value) -> String {
    match value {
        Value::String(s) => s,
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsigma_eval::{DetectionBody, EvaluationResult, FieldMatch, ResultBody, RuleHeader};
    use rsigma_parser::Level;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn detection(ip: &str, level: Level) -> EvaluationResult {
        EvaluationResult {
            header: RuleHeader {
                rule_title: "t".to_string(),
                rule_id: Some("rule-1".to_string()),
                level: Some(level),
                tags: vec![],
                custom_attributes: Arc::new(HashMap::new()),
                enrichments: None,
            },
            body: ResultBody::Detection(DetectionBody {
                matched_selections: vec![],
                matched_fields: vec![FieldMatch::new("SourceIp", serde_json::json!(ip))],
                event: None,
            }),
        }
    }

    fn spec(selector: &str, op: MatchOp, value: &str) -> MatcherSpec {
        MatcherSpec {
            selector: selector.to_string(),
            op,
            value: value.to_string(),
        }
    }

    #[test]
    fn eq_and_ne() {
        let m = Matcher::compile(&spec("match.SourceIp", MatchOp::Eq, "10.0.0.1")).unwrap();
        assert!(m.matches(&detection("10.0.0.1", Level::High)));
        assert!(!m.matches(&detection("10.0.0.2", Level::High)));
        let n = Matcher::compile(&spec("match.SourceIp", MatchOp::Ne, "10.0.0.1")).unwrap();
        assert!(!n.matches(&detection("10.0.0.1", Level::High)));
        assert!(n.matches(&detection("10.0.0.2", Level::High)));
    }

    #[test]
    fn regex_is_anchored() {
        let m =
            Matcher::compile(&spec("match.SourceIp", MatchOp::ReMatch, r"10\.0\.0\.\d+")).unwrap();
        assert!(m.matches(&detection("10.0.0.5", Level::High)));
        // Anchored: a partial match on a longer string does not match.
        assert!(!m.matches(&detection("10.0.0.5x", Level::High)));
    }

    #[test]
    fn set_ands_matchers() {
        let set = MatcherSet::compile(&[
            spec("match.SourceIp", MatchOp::Eq, "10.0.0.1"),
            spec("level", MatchOp::Eq, "high"),
        ])
        .unwrap();
        assert!(set.matches(&detection("10.0.0.1", Level::High)));
        assert!(!set.matches(&detection("10.0.0.1", Level::Low)));
        assert!(!set.matches(&detection("10.0.0.2", Level::High)));
    }

    #[test]
    fn empty_set_never_matches() {
        let set = MatcherSet::default();
        assert!(!set.matches(&detection("10.0.0.1", Level::High)));
    }

    #[test]
    fn bad_regex_is_rejected() {
        let err = Matcher::compile(&spec("rule", MatchOp::ReMatch, "(")).unwrap_err();
        assert!(matches!(err, MatcherError::Regex { .. }));
    }
}
