//! Data-aware "explain" trace for a single rule against a single event.
//!
//! Static tooling (validate, lint, LSP) answers "is this rule well-formed?"
//! It cannot answer "given this event, why did the rule not match?" because it
//! has no event data. [`explain_rule`] fills that gap: it walks the compiled
//! condition tree against one event and records, for every node and field,
//! whether it matched and why not.
//!
//! Unlike the production evaluator in [`crate::compiler`], the recording
//! evaluator never short-circuits (`all`/`any` would hide failing branches)
//! and never consults the bloom pre-filter (an optimization that would mask
//! the real reason). It is a parallel, read-only path: the optimized hot path
//! is untouched.
//!
//! The verdict can never disagree with the production engine: every per-node
//! `matched` boolean is computed from the same eval primitives the engine
//! uses, so `explain_rule(rule, event).matched == evaluate_rule(rule,
//! event).is_some()` holds (pinned by a property test).

use std::collections::HashMap;

use serde::Serialize;
use serde_json::Value;

use rsigma_parser::{ConditionExpr, Quantifier};

use crate::compiler::{
    CompiledDetection, CompiledDetectionItem, CompiledRule, eval_detection_item_no_bloom,
    eval_detection_no_bloom,
};
use crate::event::{Event, EventValue};
use crate::matcher::CompiledMatcher;
use crate::result::MatcherKind;

/// A structured explanation of why a rule did or did not match an event.
#[derive(Debug, Clone, Serialize)]
pub struct RuleExplanation {
    /// Title of the explained rule.
    pub rule_title: String,
    /// Rule id, when the rule declares one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// The overall verdict: `true` iff the production engine would match.
    pub matched: bool,
    /// One trace per condition expression on the rule (a rule matches if any
    /// condition matches).
    pub conditions: Vec<ConditionTrace>,
}

/// A node in the explained condition tree, mirroring
/// [`ConditionExpr`].
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConditionTrace {
    /// A named selection reference (`selection`), with its detection trace.
    Selection {
        name: String,
        matched: bool,
        detection: DetectionTrace,
    },
    /// `a and b and ...`.
    And {
        matched: bool,
        children: Vec<ConditionTrace>,
    },
    /// `a or b or ...`.
    Or {
        matched: bool,
        children: Vec<ConditionTrace>,
    },
    /// `not a`.
    Not {
        matched: bool,
        child: Box<ConditionTrace>,
    },
    /// A quantified selector such as `1 of selection_*` or `all of them`.
    Quantified {
        /// The quantifier as written: `any`, `all`, or a count.
        quantifier: String,
        matched: bool,
        /// How many matching selections were required.
        need: u64,
        /// How many matching selections actually matched.
        got: u64,
        /// Per-selection detail for every selection the pattern matched.
        branches: Vec<SelectionBranch>,
    },
}

impl ConditionTrace {
    /// The verdict recorded for this node.
    pub fn matched(&self) -> bool {
        match self {
            ConditionTrace::Selection { matched, .. }
            | ConditionTrace::And { matched, .. }
            | ConditionTrace::Or { matched, .. }
            | ConditionTrace::Not { matched, .. }
            | ConditionTrace::Quantified { matched, .. } => *matched,
        }
    }
}

/// One selection inside a quantified selector trace.
#[derive(Debug, Clone, Serialize)]
pub struct SelectionBranch {
    pub name: String,
    pub matched: bool,
    pub detection: DetectionTrace,
}

/// A node in the explained detection tree, mirroring
/// [`CompiledDetection`].
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DetectionTrace {
    /// Every item must match (a YAML mapping).
    AllOf {
        matched: bool,
        items: Vec<ItemTrace>,
    },
    /// Any sub-detection may match (a YAML list of mappings).
    AnyOf {
        matched: bool,
        branches: Vec<DetectionTrace>,
    },
    /// All sub-detections must match (a mapping mixing plain and array blocks).
    And {
        matched: bool,
        branches: Vec<DetectionTrace>,
    },
    /// Keyword detection: match a value across all event fields.
    Keywords { matched: bool, item: ItemTrace },
    /// An opaque detection (array object-scope or extended conditional body)
    /// whose verdict is recorded without descending per-member.
    Other { kind: String, matched: bool },
}

impl DetectionTrace {
    /// The verdict recorded for this node.
    pub fn matched(&self) -> bool {
        match self {
            DetectionTrace::AllOf { matched, .. }
            | DetectionTrace::AnyOf { matched, .. }
            | DetectionTrace::And { matched, .. }
            | DetectionTrace::Keywords { matched, .. }
            | DetectionTrace::Other { matched, .. } => *matched,
        }
    }
}

/// A single field-or-keyword leaf in a detection trace.
#[derive(Debug, Clone, Serialize)]
pub struct ItemTrace {
    /// The field name tested (`None` for keyword items).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// The kind of matcher applied.
    pub matcher: MatcherKind,
    /// The pattern the matcher tested against, when meaningful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// The event value at `field`, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<Value>,
    /// Whether this leaf matched.
    pub matched: bool,
    /// The reason for the verdict.
    pub reason: MatchReason,
}

/// Why a single leaf matched or did not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchReason {
    /// The leaf matched.
    Matched,
    /// The field is not present in the event.
    FieldAbsent,
    /// The field is present but the value does not satisfy the matcher.
    ValueMismatch,
    /// The field is present and matches except for letter case.
    CaseMismatch,
    /// An existence assertion (`|exists`) was not satisfied.
    Existence,
    /// A keyword item found no matching string anywhere in the event.
    NoKeywordMatch,
}

/// Explain why `rule` did or did not match `event`.
///
/// Visits every branch of the condition tree (no short-circuit, no bloom) and
/// returns a [`RuleExplanation`] whose `matched` field equals the production
/// verdict for the same rule and event.
pub fn explain_rule(rule: &CompiledRule, event: &impl Event) -> RuleExplanation {
    let conditions: Vec<ConditionTrace> = rule
        .conditions
        .iter()
        .map(|c| explain_condition(c, &rule.detections, event))
        .collect();
    let matched = conditions.iter().any(ConditionTrace::matched);
    RuleExplanation {
        rule_title: rule.title.clone(),
        rule_id: rule.id.clone(),
        matched,
        conditions,
    }
}

fn explain_condition(
    expr: &ConditionExpr,
    detections: &HashMap<String, CompiledDetection>,
    event: &impl Event,
) -> ConditionTrace {
    match expr {
        ConditionExpr::Identifier(name) => {
            let detection = match detections.get(name) {
                Some(det) => explain_detection(det, event),
                // `compile_rule` validates identifier references, so this arm
                // is unreachable for a compiled rule; recorded as a non-match.
                None => DetectionTrace::Other {
                    kind: "unknown selection".to_string(),
                    matched: false,
                },
            };
            ConditionTrace::Selection {
                name: name.clone(),
                matched: detection.matched(),
                detection,
            }
        }
        ConditionExpr::And(exprs) => {
            let children: Vec<ConditionTrace> = exprs
                .iter()
                .map(|e| explain_condition(e, detections, event))
                .collect();
            let matched = children.iter().all(ConditionTrace::matched);
            ConditionTrace::And { matched, children }
        }
        ConditionExpr::Or(exprs) => {
            let children: Vec<ConditionTrace> = exprs
                .iter()
                .map(|e| explain_condition(e, detections, event))
                .collect();
            let matched = children.iter().any(ConditionTrace::matched);
            ConditionTrace::Or { matched, children }
        }
        ConditionExpr::Not(inner) => {
            let child = explain_condition(inner, detections, event);
            let matched = !child.matched();
            ConditionTrace::Not {
                matched,
                child: Box::new(child),
            }
        }
        ConditionExpr::Selector {
            quantifier,
            pattern,
        } => {
            // Sort for deterministic output (detections is a HashMap).
            let mut names: Vec<&String> = detections
                .keys()
                .filter(|n| pattern.matches_detection_name(n))
                .collect();
            names.sort();

            let branches: Vec<SelectionBranch> = names
                .iter()
                .map(|name| {
                    let detection = detections
                        .get(*name)
                        .map(|det| explain_detection(det, event))
                        .unwrap_or(DetectionTrace::Other {
                            kind: "unknown selection".to_string(),
                            matched: false,
                        });
                    SelectionBranch {
                        name: (*name).clone(),
                        matched: detection.matched(),
                        detection,
                    }
                })
                .collect();

            let got = branches.iter().filter(|b| b.matched).count() as u64;
            let total = branches.len() as u64;
            let (quant_str, need, matched) = match quantifier {
                Quantifier::Any => ("any".to_string(), 1, got >= 1),
                Quantifier::All => ("all".to_string(), total, got == total),
                Quantifier::Count(n) => (n.to_string(), *n, got >= *n),
            };
            ConditionTrace::Quantified {
                quantifier: quant_str,
                matched,
                need,
                got,
                branches,
            }
        }
    }
}

fn explain_detection(detection: &CompiledDetection, event: &impl Event) -> DetectionTrace {
    match detection {
        CompiledDetection::AllOf(items) => {
            let items: Vec<ItemTrace> = items.iter().map(|i| explain_item(i, event)).collect();
            let matched = items.iter().all(|i| i.matched);
            DetectionTrace::AllOf { matched, items }
        }
        CompiledDetection::AnyOf(dets) => {
            let branches: Vec<DetectionTrace> =
                dets.iter().map(|d| explain_detection(d, event)).collect();
            let matched = branches.iter().any(DetectionTrace::matched);
            DetectionTrace::AnyOf { matched, branches }
        }
        CompiledDetection::And(dets) => {
            let branches: Vec<DetectionTrace> =
                dets.iter().map(|d| explain_detection(d, event)).collect();
            let matched = branches.iter().all(DetectionTrace::matched);
            DetectionTrace::And { matched, branches }
        }
        CompiledDetection::Keywords(matcher) => {
            let matched = matcher.matches_keyword(event);
            let desc = matcher.describe();
            let item = ItemTrace {
                field: None,
                matcher: desc.kind,
                pattern: desc.pattern,
                actual: None,
                matched,
                reason: if matched {
                    MatchReason::Matched
                } else {
                    MatchReason::NoKeywordMatch
                },
            };
            DetectionTrace::Keywords { matched, item }
        }
        // Array object-scope and extended conditional bodies evaluate
        // per-member; the verdict is recorded via the real evaluator without
        // descending, so the trace can never disagree with the engine.
        CompiledDetection::ArrayMatch {
            field, quantifier, ..
        } => DetectionTrace::Other {
            kind: format!("array_match {field:?} {quantifier:?}"),
            matched: eval_detection_no_bloom(detection, event),
        },
        CompiledDetection::Conditional { .. } => DetectionTrace::Other {
            kind: "conditional".to_string(),
            matched: eval_detection_no_bloom(detection, event),
        },
    }
}

fn explain_item(item: &CompiledDetectionItem, event: &impl Event) -> ItemTrace {
    let desc = item.matcher.describe();
    let matched = eval_detection_item_no_bloom(item, event);

    // Existence assertion (`|exists`): the matcher is structural.
    if item.exists.is_some() {
        let actual = item
            .field
            .as_deref()
            .and_then(|f| event.get_field(f))
            .map(|v| v.to_json());
        return ItemTrace {
            field: item.field.clone(),
            matcher: MatcherKind::Exists,
            pattern: desc.pattern,
            actual,
            matched,
            reason: if matched {
                MatchReason::Matched
            } else {
                MatchReason::Existence
            },
        };
    }

    match &item.field {
        Some(field) => {
            let value = event.get_field(field);
            let reason = if matched {
                MatchReason::Matched
            } else {
                match &value {
                    None => MatchReason::FieldAbsent,
                    Some(v) => {
                        if case_only_mismatch(&item.matcher, v) {
                            MatchReason::CaseMismatch
                        } else {
                            MatchReason::ValueMismatch
                        }
                    }
                }
            };
            ItemTrace {
                field: Some(field.clone()),
                matcher: desc.kind,
                pattern: desc.pattern,
                actual: value.map(|v| v.to_json()),
                matched,
                reason,
            }
        }
        // A keyword item embedded inside an `AllOf` mapping.
        None => ItemTrace {
            field: None,
            matcher: desc.kind,
            pattern: desc.pattern,
            actual: None,
            matched,
            reason: if matched {
                MatchReason::Matched
            } else {
                MatchReason::NoKeywordMatch
            },
        },
    }
}

/// Heuristic: would a case-sensitive string matcher have matched if case were
/// ignored? Used only to label a failed leaf as [`MatchReason::CaseMismatch`]
/// rather than [`MatchReason::ValueMismatch`]; the verdict itself comes from
/// the real matcher, so a mislabel never changes correctness.
fn case_only_mismatch(matcher: &CompiledMatcher, actual: &EventValue) -> bool {
    let Some(actual) = actual.as_str() else {
        return false;
    };
    let actual = actual.to_lowercase();
    let (pattern, kind) = match matcher {
        CompiledMatcher::Exact {
            value,
            case_insensitive: false,
        } => (value, CaseKind::Exact),
        CompiledMatcher::Contains {
            value,
            case_insensitive: false,
        } => (value, CaseKind::Contains),
        CompiledMatcher::StartsWith {
            value,
            case_insensitive: false,
        } => (value, CaseKind::StartsWith),
        CompiledMatcher::EndsWith {
            value,
            case_insensitive: false,
        } => (value, CaseKind::EndsWith),
        _ => return false,
    };
    let pattern = pattern.to_lowercase();
    match kind {
        CaseKind::Exact => actual == pattern,
        CaseKind::Contains => actual.contains(&pattern),
        CaseKind::StartsWith => actual.starts_with(&pattern),
        CaseKind::EndsWith => actual.ends_with(&pattern),
    }
}

enum CaseKind {
    Exact,
    Contains,
    StartsWith,
    EndsWith,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::compile_rule;
    use crate::evaluate_rule;
    use crate::event::JsonEvent;
    use proptest::prelude::*;
    use rsigma_parser::parse_sigma_yaml;
    use serde_json::json;

    fn compile(yaml: &str) -> CompiledRule {
        let coll = parse_sigma_yaml(yaml).expect("parse");
        compile_rule(&coll.rules[0]).expect("compile")
    }

    /// Find the first `ItemTrace` in a single-condition explanation, drilling
    /// through the selection's detection.
    fn first_item(exp: &RuleExplanation) -> &ItemTrace {
        match &exp.conditions[0] {
            ConditionTrace::Selection { detection, .. } => match detection {
                DetectionTrace::AllOf { items, .. } => &items[0],
                other => panic!("unexpected detection: {other:?}"),
            },
            other => panic!("unexpected condition: {other:?}"),
        }
    }

    const RULE_ENDSWITH: &str = r#"
title: Powershell
id: rule-endswith
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|endswith: '\powershell.exe'
    condition: selection
"#;

    #[test]
    fn matched_leaf_reports_matched() {
        let rule = compile(RULE_ENDSWITH);
        let v = json!({"CommandLine": "C:\\Windows\\System32\\powershell.exe"});
        let exp = explain_rule(&rule, &JsonEvent::borrow(&v));
        assert!(exp.matched);
        assert_eq!(exp.rule_id.as_deref(), Some("rule-endswith"));
        let item = first_item(&exp);
        assert!(item.matched);
        assert_eq!(item.reason, MatchReason::Matched);
        assert_eq!(item.matcher, MatcherKind::EndsWith);
    }

    #[test]
    fn absent_field_reports_field_absent() {
        let rule = compile(RULE_ENDSWITH);
        let v = json!({"Image": "x"});
        let exp = explain_rule(&rule, &JsonEvent::borrow(&v));
        assert!(!exp.matched);
        let item = first_item(&exp);
        assert!(!item.matched);
        assert_eq!(item.reason, MatchReason::FieldAbsent);
        assert!(item.actual.is_none());
    }

    #[test]
    fn value_present_but_wrong_reports_value_mismatch() {
        let rule = compile(RULE_ENDSWITH);
        let v = json!({"CommandLine": "C:\\Windows\\System32\\cmd.exe"});
        let exp = explain_rule(&rule, &JsonEvent::borrow(&v));
        assert!(!exp.matched);
        let item = first_item(&exp);
        assert_eq!(item.reason, MatchReason::ValueMismatch);
        assert_eq!(item.actual, Some(json!("C:\\Windows\\System32\\cmd.exe")));
    }

    #[test]
    fn case_only_difference_reports_case_mismatch() {
        let rule = compile(
            r#"
title: Cased
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|endswith|cased: '\powershell.exe'
    condition: selection
"#,
        );
        let v = json!({"CommandLine": "C:\\Windows\\System32\\POWERSHELL.EXE"});
        let exp = explain_rule(&rule, &JsonEvent::borrow(&v));
        assert!(!exp.matched);
        let item = first_item(&exp);
        assert_eq!(item.reason, MatchReason::CaseMismatch);
    }

    #[test]
    fn numeric_mismatch_reports_value_mismatch() {
        let rule = compile(
            r#"
title: Count
logsource:
    category: test
detection:
    selection:
        Count|gt: 5
    condition: selection
"#,
        );
        let v = json!({"Count": 3});
        let exp = explain_rule(&rule, &JsonEvent::borrow(&v));
        assert!(!exp.matched);
        let item = first_item(&exp);
        assert_eq!(item.matcher, MatcherKind::Numeric);
        assert_eq!(item.reason, MatchReason::ValueMismatch);
    }

    #[test]
    fn negation_inverts_verdict() {
        let rule = compile(
            r#"
title: Not Filter
logsource:
    category: test
detection:
    selection:
        EventID: 1
    filter:
        User: SYSTEM
    condition: selection and not filter
"#,
        );
        // selection matches, filter matches -> `not filter` is false -> no match.
        let v = json!({"EventID": 1, "User": "SYSTEM"});
        let exp = explain_rule(&rule, &JsonEvent::borrow(&v));
        assert!(!exp.matched);
        // selection matches, filter does not -> `not filter` true -> match.
        let v2 = json!({"EventID": 1, "User": "alice"});
        let exp2 = explain_rule(&rule, &JsonEvent::borrow(&v2));
        assert!(exp2.matched);
        match &exp2.conditions[0] {
            ConditionTrace::And { children, .. } => {
                assert!(matches!(
                    children[1],
                    ConditionTrace::Not { matched: true, .. }
                ));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn quantified_selector_collapses_to_or_at_lower() {
        // `1 of selection_*` collapses to Or over matching names at lower time,
        // so explain walks a selector-free Or tree rather than Quantified.
        let rule = compile(
            r#"
title: One Of
logsource:
    category: test
detection:
    selection_a:
        CommandLine|contains: powershell
    selection_b:
        CommandLine|contains: whoami
    condition: 1 of selection_*
"#,
        );
        let v = json!({"CommandLine": "run powershell now"});
        let exp = explain_rule(&rule, &JsonEvent::borrow(&v));
        assert!(exp.matched);
        match &exp.conditions[0] {
            ConditionTrace::Or {
                matched: true,
                children,
            } => {
                assert_eq!(children.len(), 2);
                assert!(children.iter().any(|c| matches!(
                    c,
                    ConditionTrace::Selection {
                        name,
                        matched: true,
                        ..
                    } if name == "selection_a"
                )));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn keyword_detection_traces_keyword_leaf() {
        let rule = compile(
            r#"
title: Keywords
logsource:
    category: test
detection:
    keywords:
        - whoami
        - mimikatz
    condition: keywords
"#,
        );
        let hit = json!({"msg": "user ran whoami"});
        let exp = explain_rule(&rule, &JsonEvent::borrow(&hit));
        assert!(exp.matched);
        let miss = json!({"msg": "nothing here"});
        let exp_miss = explain_rule(&rule, &JsonEvent::borrow(&miss));
        assert!(!exp_miss.matched);
        match &exp_miss.conditions[0] {
            ConditionTrace::Selection { detection, .. } => match detection {
                DetectionTrace::Keywords { item, .. } => {
                    assert_eq!(item.reason, MatchReason::NoKeywordMatch);
                    assert_eq!(item.matcher, MatcherKind::OneOf);
                }
                other => panic!("unexpected: {other:?}"),
            },
            other => panic!("unexpected: {other:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // Verdict equivalence: the explain trace can never disagree with the engine.
    // -------------------------------------------------------------------------

    fn sample_rules() -> Vec<CompiledRule> {
        [
            RULE_ENDSWITH,
            r#"
title: And Not
logsource: {category: test}
detection:
    selection:
        EventID: 1
    filter:
        User: SYSTEM
    condition: selection and not filter
"#,
            r#"
title: One Of
logsource: {category: test}
detection:
    selection_a:
        CommandLine|contains: powershell
    selection_b:
        CommandLine|contains: whoami
    condition: 1 of selection_*
"#,
            r#"
title: All Of
logsource: {category: test}
detection:
    selection_a:
        CommandLine|contains: powershell
    selection_b:
        User: SYSTEM
    condition: all of selection_*
"#,
            r#"
title: Numeric
logsource: {category: test}
detection:
    selection:
        Count|gt: 5
    condition: selection
"#,
            r#"
title: Exists
logsource: {category: test}
detection:
    selection:
        User|exists: true
    condition: selection
"#,
            r#"
title: Keywords
logsource: {category: test}
detection:
    keywords:
        - whoami
        - powershell
    condition: keywords
"#,
        ]
        .iter()
        .map(|y| compile(y))
        .collect()
    }

    fn arb_event() -> impl Strategy<Value = serde_json::Value> {
        let cmd = prop::option::of(prop::sample::select(vec![
            "C:\\Windows\\System32\\powershell.exe",
            "powershell.exe -enc AAAA",
            "cmd.exe /c whoami",
            "PowerShell.EXE",
            "explorer.exe",
        ]));
        let user = prop::option::of(prop::sample::select(vec!["SYSTEM", "alice", "root"]));
        let eid = prop::option::of(prop::sample::select(vec![1i64, 2, 4688]));
        let count = prop::option::of(0i64..10);
        (cmd, user, eid, count).prop_map(|(cmd, user, eid, count)| {
            let mut m = serde_json::Map::new();
            if let Some(c) = cmd {
                m.insert("CommandLine".into(), json!(c));
            }
            if let Some(u) = user {
                m.insert("User".into(), json!(u));
            }
            if let Some(e) = eid {
                m.insert("EventID".into(), json!(e));
            }
            if let Some(c) = count {
                m.insert("Count".into(), json!(c));
            }
            serde_json::Value::Object(m)
        })
    }

    proptest! {
        #[test]
        fn explain_verdict_equals_engine_verdict(event in arb_event()) {
            let rules = sample_rules();
            let je = JsonEvent::borrow(&event);
            for rule in &rules {
                let explained = explain_rule(rule, &je).matched;
                let engine = evaluate_rule(rule, &je).is_some();
                prop_assert_eq!(
                    explained, engine,
                    "explain/engine disagree on rule {:?} for event {}",
                    rule.title, event
                );
            }
        }
    }
}
