//! Lowering: parser AST → HIR.
//!
//! Walks metadata, detections, and conditions after static pipeline transforms.
//! Selectors collapse here into [`IrCondition`] trees with no `Selector` variant.
//! Modifier interpretation lives in [`mod_ctx`] / [`value`].

mod helpers;
mod mod_ctx;
mod value;

use std::collections::HashMap;

use rsigma_parser::{
    ConditionExpr, CorrelationRule, Detection, DetectionItem, FilterRule, Quantifier, SigmaRule,
    SigmaValue,
};

use crate::error::IrError;
use crate::{
    IrCondition, IrCorrelation, IrDetection, IrDetectionItem, IrFilter, IrMatcher, IrRule,
    IrRuleMetadata, SurfaceSpec,
};

use helpers::{Result, yaml_to_json_map};
use mod_ctx::{ModCtx, validate_modifiers};
use value::{lower_value, lower_value_keywords};

/// Options controlling the lowering strictness.
#[derive(Debug, Clone, Default)]
pub struct LowerOptions {
    /// When false (default), reject string values that still contain
    /// `${source.*}` placeholders. When true, preserve them as
    /// `IrValue::DynamicSourceRef` (deferred specialization path).
    pub permissive_placeholders: bool,
}

/// Lower a single parsed `SigmaRule` into its HIR form.
pub fn lower_rule(rule: &SigmaRule, opts: &LowerOptions) -> Result<IrRule> {
    let mut detections = HashMap::new();
    for (name, detection) in &rule.detection.named {
        detections.insert(name.clone(), lower_detection(detection, opts)?);
    }

    let detection_names: Vec<String> = detections.keys().cloned().collect();
    let mut conditions = Vec::with_capacity(rule.detection.conditions.len());
    for condition in &rule.detection.conditions {
        conditions.push(lower_condition(condition, &detection_names)?);
    }

    Ok(IrRule {
        metadata: metadata_from_rule(rule),
        logsource: rule.logsource.clone(),
        sigma_version: rule.sigma_version,
        detections,
        conditions,
    })
}

/// Lower a parsed detection into `IrDetection`.
pub fn lower_detection(detection: &Detection, opts: &LowerOptions) -> Result<IrDetection> {
    match detection {
        Detection::AllOf(items) => {
            if items.is_empty() {
                return Err(IrError::InvalidModifiers(
                    "AllOf detection must not be empty (vacuous truth)".into(),
                ));
            }
            let lowered: Result<Vec<_>> = items
                .iter()
                .map(|item| lower_detection_item(item, opts))
                .collect();
            Ok(IrDetection::AllOf(lowered?))
        }
        Detection::AnyOf(dets) => {
            if dets.is_empty() {
                return Err(IrError::InvalidModifiers(
                    "AnyOf detection must not be empty (would never match)".into(),
                ));
            }
            let lowered: Result<Vec<_>> = dets.iter().map(|d| lower_detection(d, opts)).collect();
            Ok(IrDetection::AnyOf(lowered?))
        }
        Detection::ArrayMatch {
            field,
            quantifier,
            body,
        } => {
            let compiled_body = lower_detection(body, opts)?;
            Ok(IrDetection::ArrayMatch {
                field: field.clone(),
                quantifier: *quantifier,
                body: Box::new(compiled_body),
            })
        }
        Detection::And(dets) => {
            if dets.is_empty() {
                return Err(IrError::InvalidModifiers(
                    "And detection must not be empty".into(),
                ));
            }
            let lowered: Result<Vec<_>> = dets.iter().map(|d| lower_detection(d, opts)).collect();
            Ok(IrDetection::And(lowered?))
        }
        Detection::Conditional { named, condition } => {
            if named.is_empty() {
                return Err(IrError::InvalidModifiers(
                    "Conditional detection must have at least one named sub-selection".into(),
                ));
            }
            let mut lowered_named = HashMap::new();
            for (k, d) in named {
                lowered_named.insert(k.clone(), lower_detection(d, opts)?);
            }
            let names: Vec<String> = lowered_named.keys().cloned().collect();
            let lowered_cond = lower_condition(condition, &names)?;
            Ok(IrDetection::Conditional {
                named: lowered_named,
                condition: lowered_cond,
            })
        }
        Detection::Keywords(values) => {
            let matchers: Result<Vec<IrMatcher>> =
                values.iter().map(lower_value_keywords).collect();
            let matchers = matchers?;
            let matcher = match matchers.len() {
                0 => {
                    return Err(IrError::InvalidModifiers(
                        "Keywords detection must not be empty".into(),
                    ));
                }
                1 => matchers.into_iter().next().unwrap(),
                _ => IrMatcher::AnyOf(matchers),
            };
            Ok(IrDetection::Keywords(matcher))
        }
    }
}

/// Lower a detection item — absorbs modifier interpretation.
pub fn lower_detection_item(item: &DetectionItem, opts: &LowerOptions) -> Result<IrDetectionItem> {
    if !opts.permissive_placeholders {
        for v in &item.values {
            reject_placeholders(v)?;
        }
    }

    let ctx = ModCtx::from_modifiers(&item.field.modifiers);
    validate_modifiers(&ctx, &item.field.modifiers)?;

    let surface = Some(SurfaceSpec {
        field: item.field.name.clone(),
        modifiers: item.field.modifiers.clone(),
        values: item.values.clone(),
    });

    if ctx.exists {
        let expect = match item.values.first() {
            Some(SigmaValue::Bool(b)) => *b,
            Some(SigmaValue::String(s)) => match s.as_plain().as_deref() {
                Some("true") | Some("yes") => true,
                Some("false") | Some("no") => false,
                _ => true,
            },
            _ => true,
        };
        return Ok(IrDetectionItem {
            field: item.field.name.clone(),
            matcher: IrMatcher::Exists(expect),
            exists: Some(expect),
            surface,
        });
    }

    if ctx.all && item.values.len() <= 1 {
        return Err(IrError::InvalidModifiers(
            "|all modifier requires more than one value".to_string(),
        ));
    }

    let matchers: Result<Vec<IrMatcher>> =
        item.values.iter().map(|v| lower_value(v, &ctx)).collect();
    let matchers = matchers?;

    let combined = if ctx.all {
        if matchers.len() == 1 {
            matchers.into_iter().next().unwrap()
        } else {
            IrMatcher::AllOf(matchers)
        }
    } else if matchers.len() == 1 {
        matchers.into_iter().next().unwrap()
    } else {
        IrMatcher::AnyOf(matchers)
    };

    Ok(IrDetectionItem {
        field: item.field.name.clone(),
        matcher: combined,
        exists: None,
        surface,
    })
}

/// Lower a condition expression tree — collapses selectors into identifiers.
pub fn lower_condition(expr: &ConditionExpr, detection_names: &[String]) -> Result<IrCondition> {
    match expr {
        ConditionExpr::Identifier(name) => {
            if !detection_names.iter().any(|n| n == name) {
                return Err(IrError::UnknownDetection(name.clone()));
            }
            Ok(IrCondition::Detection(name.clone()))
        }
        ConditionExpr::And(exprs) => {
            let lowered: Result<Vec<_>> = exprs
                .iter()
                .map(|e| lower_condition(e, detection_names))
                .collect();
            Ok(IrCondition::And(lowered?))
        }
        ConditionExpr::Or(exprs) => {
            let lowered: Result<Vec<_>> = exprs
                .iter()
                .map(|e| lower_condition(e, detection_names))
                .collect();
            Ok(IrCondition::Or(lowered?))
        }
        ConditionExpr::Not(inner) => Ok(IrCondition::Not(Box::new(lower_condition(
            inner,
            detection_names,
        )?))),
        ConditionExpr::Selector {
            quantifier,
            pattern,
        } => {
            let mut matching: Vec<String> = detection_names
                .iter()
                .filter(|name| pattern.matches_detection_name(name))
                .cloned()
                .collect();
            // Deterministic HIR: sort matched names alphabetically.
            matching.sort();
            Ok(collapse_selector(quantifier.clone(), matching))
        }
    }
}

/// Collapse a selector into And/Or/Detection only.
///
/// - `any` / `1` → `Or` over matching names (empty `Or` is false)
/// - `all` → `And` over matching names (empty `And` is vacuous true)
/// - `N of` → combinatorial expansion of "at least N" as `Or` of `And`s
fn collapse_selector(quantifier: Quantifier, matching: Vec<String>) -> IrCondition {
    match quantifier {
        Quantifier::Any => {
            if matching.len() == 1 {
                IrCondition::Detection(matching.into_iter().next().unwrap())
            } else {
                IrCondition::Or(matching.into_iter().map(IrCondition::Detection).collect())
            }
        }
        Quantifier::All => {
            if matching.len() == 1 {
                IrCondition::Detection(matching.into_iter().next().unwrap())
            } else {
                IrCondition::And(matching.into_iter().map(IrCondition::Detection).collect())
            }
        }
        Quantifier::Count(n) => collapse_count(n, matching),
    }
}

fn collapse_count(n: u64, matching: Vec<String>) -> IrCondition {
    if n == 0 {
        // match_count >= 0 is always true
        return IrCondition::And(vec![]);
    }
    if matching.is_empty() || n as usize > matching.len() {
        // Impossible to satisfy
        return IrCondition::Or(vec![]);
    }
    if n == 1 {
        return collapse_selector(Quantifier::Any, matching);
    }
    if n as usize == matching.len() {
        return collapse_selector(Quantifier::All, matching);
    }

    // At least n of k: Or over all combinations of size n, each as And.
    let combos = combinations(&matching, n as usize);
    let arms: Vec<IrCondition> = combos
        .into_iter()
        .map(|combo| {
            if combo.len() == 1 {
                IrCondition::Detection(combo.into_iter().next().unwrap())
            } else {
                IrCondition::And(combo.into_iter().map(IrCondition::Detection).collect())
            }
        })
        .collect();
    if arms.len() == 1 {
        arms.into_iter().next().unwrap()
    } else {
        IrCondition::Or(arms)
    }
}

fn combinations(items: &[String], k: usize) -> Vec<Vec<String>> {
    fn rec(
        items: &[String],
        k: usize,
        start: usize,
        path: &mut Vec<String>,
        out: &mut Vec<Vec<String>>,
    ) {
        if path.len() == k {
            out.push(path.clone());
            return;
        }
        for i in start..items.len() {
            path.push(items[i].clone());
            rec(items, k, i + 1, path, out);
            path.pop();
        }
    }
    let mut out = Vec::new();
    if k == 0 || k > items.len() {
        return out;
    }
    rec(items, k, 0, &mut Vec::new(), &mut out);
    out
}

/// Lower a correlation rule into `IrCorrelation`.
pub fn lower_correlation(corr: &CorrelationRule) -> Result<IrCorrelation> {
    Ok(IrCorrelation {
        metadata: metadata_from_correlation(corr),
        sigma_version: corr.sigma_version,
        correlation_type: corr.correlation_type,
        rules: corr.rules.clone(),
        group_by: corr.group_by.clone(),
        timespan: corr.timespan.clone(),
        window: corr.window,
        gap: corr.gap.clone(),
        condition: corr.condition.clone(),
        aliases: corr.aliases.clone(),
        generate: corr.generate,
    })
}

/// Lower a filter rule into `IrFilter`.
pub fn lower_filter(filter: &FilterRule, opts: &LowerOptions) -> Result<IrFilter> {
    let mut detections = HashMap::new();
    for (name, detection) in &filter.detection.named {
        detections.insert(name.clone(), lower_detection(detection, opts)?);
    }
    let detection_names: Vec<String> = detections.keys().cloned().collect();
    let mut conditions = Vec::with_capacity(filter.detection.conditions.len());
    for condition in &filter.detection.conditions {
        conditions.push(lower_condition(condition, &detection_names)?);
    }
    Ok(IrFilter {
        metadata: metadata_from_filter(filter),
        sigma_version: filter.sigma_version,
        rules: filter.rules.clone(),
        logsource: filter.logsource.clone(),
        detections,
        conditions,
    })
}

fn reject_placeholders(value: &SigmaValue) -> Result<()> {
    if let SigmaValue::String(s) = value {
        let text = s.as_plain().unwrap_or_else(|| s.original.clone());
        if text.contains("${source.") {
            return Err(IrError::Lowering(format!(
                "unresolved source placeholder in detection value: {text}"
            )));
        }
    }
    Ok(())
}

fn metadata_from_rule(rule: &SigmaRule) -> IrRuleMetadata {
    IrRuleMetadata {
        title: rule.title.clone(),
        id: rule.id.clone(),
        name: rule.name.clone(),
        level: rule.level,
        tags: rule.tags.clone(),
        status: rule.status,
        description: rule.description.clone(),
        author: rule.author.clone(),
        date: rule.date.clone(),
        modified: rule.modified.clone(),
        references: rule.references.clone(),
        falsepositives: rule.falsepositives.clone(),
        fields: rule.fields.clone(),
        related: rule.related.clone(),
        license: rule.license.clone(),
        taxonomy: rule.taxonomy.clone(),
        scope: rule.scope.clone(),
        custom_attributes: yaml_to_json_map(&rule.custom_attributes),
        schema_affinity: None,
    }
}

fn metadata_from_correlation(corr: &CorrelationRule) -> IrRuleMetadata {
    IrRuleMetadata {
        title: corr.title.clone(),
        id: corr.id.clone(),
        name: corr.name.clone(),
        level: corr.level,
        tags: corr.tags.clone(),
        status: corr.status,
        description: corr.description.clone(),
        author: corr.author.clone(),
        date: corr.date.clone(),
        modified: corr.modified.clone(),
        references: corr.references.clone(),
        falsepositives: corr.falsepositives.clone(),
        fields: corr.fields.clone(),
        related: corr.related.clone(),
        license: corr.license.clone(),
        taxonomy: corr.taxonomy.clone(),
        scope: corr.scope.clone(),
        custom_attributes: yaml_to_json_map(&corr.custom_attributes),
        schema_affinity: None,
    }
}

fn metadata_from_filter(filter: &FilterRule) -> IrRuleMetadata {
    IrRuleMetadata {
        title: filter.title.clone(),
        id: filter.id.clone(),
        name: filter.name.clone(),
        level: filter.level,
        tags: filter.tags.clone(),
        status: filter.status,
        description: filter.description.clone(),
        author: filter.author.clone(),
        date: filter.date.clone(),
        modified: filter.modified.clone(),
        references: filter.references.clone(),
        falsepositives: filter.falsepositives.clone(),
        fields: filter.fields.clone(),
        related: filter.related.clone(),
        license: filter.license.clone(),
        taxonomy: filter.taxonomy.clone(),
        scope: filter.scope.clone(),
        custom_attributes: yaml_to_json_map(&filter.custom_attributes),
        schema_affinity: None,
    }
}

#[cfg(test)]
mod combinations_tests {
    use super::combinations;

    #[test]
    fn combinations_of_size_two() {
        let items = ["a", "b", "c"].map(String::from).to_vec();
        let got = combinations(&items, 2);
        let expected: Vec<Vec<String>> = vec![
            vec!["a".into(), "b".into()],
            vec!["a".into(), "c".into()],
            vec!["b".into(), "c".into()],
        ];
        assert_eq!(got, expected);
    }
}
