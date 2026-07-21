//! Raising: HIR → parser AST.
//!
//! [`raise_rule`] is the inverse of [`lower_rule`](crate::lower_rule): it turns
//! an [`IrRule`] back into a [`SigmaRule`] so it can be emitted as Sigma YAML
//! (via [`rsigma_parser::emit_rule_yaml`]). Where lowering absorbs modifier
//! interpretation into explicit [`IrMatcher`] variants, raising reconstructs the
//! `field|modifier` surface those variants imply.
//!
//! Raising is faithful for every matcher and detection shape the lowering
//! produces: `lower_rule` then `raise_rule` yields a rule that lowers again to
//! the same HIR. It is the pivot the reverse converter uses to turn a
//! frontend-built [`IrRule`] into an idiomatic Sigma rule.
//!
//! Two constructs have no single-item Sigma spelling and are handled explicitly:
//! a `Not` matcher (from `|neq`) re-attaches the `neq` modifier to its inner
//! leaf, and a numeric [`IrNumber::DynamicSourceRef`] cannot become a static
//! value and is rejected.

use rsigma_parser::{
    ConditionExpr, Detection, DetectionItem, Detections, FieldSpec, Modifier, SigmaRule,
    SigmaString, SigmaValue, SpecialChar, StringPart,
};

use crate::error::IrError;
use crate::{
    IrCondition, IrDetection, IrDetectionItem, IrEncoding, IrExpandPart, IrMatcher, IrNumber,
    IrPattern, IrPatternPart, IrRule, IrStrOp, IrTimePart,
};

type Result<T> = std::result::Result<T, IrError>;

/// Options controlling how an [`IrRule`] is raised to a [`SigmaRule`].
#[derive(Debug, Clone)]
pub struct RaiseOptions {
    /// Emit the rule's `custom_attributes` back as top-level keys. Defaults to
    /// `true`; disable to produce a metadata-clean skeleton.
    pub include_custom_attributes: bool,
}

impl Default for RaiseOptions {
    fn default() -> Self {
        RaiseOptions {
            include_custom_attributes: true,
        }
    }
}

/// Reconstruct a parser [`SigmaString`] from a faithful [`IrPattern`].
///
/// The literal segments and wildcards round-trip exactly; the `original` field
/// is a plain concatenation, which downstream emission re-escapes from `parts`.
pub fn ir_pattern_to_sigma(pattern: &IrPattern) -> SigmaString {
    let mut original = String::new();
    let parts = pattern
        .parts
        .iter()
        .map(|part| match part {
            IrPatternPart::Literal(text) => {
                original.push_str(text);
                StringPart::Plain(text.clone())
            }
            IrPatternPart::WildcardMulti => {
                original.push('*');
                StringPart::Special(SpecialChar::WildcardMulti)
            }
            IrPatternPart::WildcardSingle => {
                original.push('?');
                StringPart::Special(SpecialChar::WildcardSingle)
            }
        })
        .collect();
    SigmaString { parts, original }
}

/// Raise an [`IrRule`] back to a [`SigmaRule`].
pub fn raise_rule(rule: &IrRule, opts: &RaiseOptions) -> Result<SigmaRule> {
    let mut named = std::collections::HashMap::new();
    for (name, detection) in &rule.detections {
        named.insert(name.clone(), raise_detection(detection)?);
    }

    let conditions: Vec<ConditionExpr> = rule.conditions.iter().map(raise_condition).collect();
    let condition_strings = conditions.iter().map(|c| c.to_string()).collect();

    let meta = &rule.metadata;
    let custom_attributes = if opts.include_custom_attributes {
        meta.custom_attributes
            .iter()
            .map(|(k, v)| (k.clone(), json_to_yaml(v)))
            .collect()
    } else {
        std::collections::HashMap::new()
    };

    Ok(SigmaRule {
        title: meta.title.clone(),
        logsource: rule.logsource.clone(),
        detection: Detections {
            named,
            conditions,
            condition_strings,
            timeframe: None,
        },
        sigma_version: rule.sigma_version,
        id: meta.id.clone(),
        name: meta.name.clone(),
        related: meta.related.clone(),
        taxonomy: meta.taxonomy.clone(),
        status: meta.status,
        description: meta.description.clone(),
        license: meta.license.clone(),
        author: meta.author.clone(),
        references: meta.references.clone(),
        date: meta.date.clone(),
        modified: meta.modified.clone(),
        fields: meta.fields.clone(),
        falsepositives: meta.falsepositives.clone(),
        level: meta.level,
        tags: meta.tags.clone(),
        scope: meta.scope.clone(),
        custom_attributes,
    })
}

// =============================================================================
// Detections and conditions
// =============================================================================

fn raise_condition(condition: &IrCondition) -> ConditionExpr {
    match condition {
        IrCondition::Detection(name) => ConditionExpr::Identifier(name.clone()),
        IrCondition::And(parts) => ConditionExpr::And(parts.iter().map(raise_condition).collect()),
        IrCondition::Or(parts) => ConditionExpr::Or(parts.iter().map(raise_condition).collect()),
        IrCondition::Not(inner) => ConditionExpr::Not(Box::new(raise_condition(inner))),
        IrCondition::Selector {
            quantifier,
            pattern,
        } => ConditionExpr::Selector {
            quantifier: quantifier.clone(),
            pattern: pattern.clone(),
        },
    }
}

fn raise_detection(detection: &IrDetection) -> Result<Detection> {
    match detection {
        IrDetection::AllOf(items) => Ok(Detection::AllOf(
            items
                .iter()
                .map(raise_detection_item)
                .collect::<Result<Vec<_>>>()?,
        )),
        IrDetection::AnyOf(dets) => Ok(Detection::AnyOf(
            dets.iter()
                .map(raise_detection)
                .collect::<Result<Vec<_>>>()?,
        )),
        IrDetection::And(dets) => Ok(Detection::And(
            dets.iter()
                .map(raise_detection)
                .collect::<Result<Vec<_>>>()?,
        )),
        IrDetection::Keywords(matcher) => Ok(Detection::Keywords(raise_keywords(matcher)?)),
        IrDetection::ArrayMatch {
            field,
            quantifier,
            body,
        } => Ok(Detection::ArrayMatch {
            field: field.clone(),
            quantifier: *quantifier,
            body: Box::new(raise_detection(body)?),
        }),
        IrDetection::Conditional { named, condition } => {
            let mut raised = std::collections::HashMap::new();
            for (name, det) in named {
                raised.insert(name.clone(), raise_detection(det)?);
            }
            Ok(Detection::Conditional {
                named: raised,
                condition: raise_condition(condition),
            })
        }
    }
}

fn raise_detection_item(item: &IrDetectionItem) -> Result<DetectionItem> {
    let (modifiers, values) = raise_matcher(&item.matcher)?;
    Ok(DetectionItem {
        field: FieldSpec::new(item.field.clone(), modifiers),
        values,
    })
}

/// Extract the value list from a keyword detection matcher (a single leaf or an
/// `AnyOf` of leaves).
fn raise_keywords(matcher: &IrMatcher) -> Result<Vec<SigmaValue>> {
    match matcher {
        IrMatcher::AnyOf(subs) => subs.iter().map(keyword_value).collect(),
        single => Ok(vec![keyword_value(single)?]),
    }
}

fn keyword_value(matcher: &IrMatcher) -> Result<SigmaValue> {
    match matcher {
        IrMatcher::Str { pattern, .. } => Ok(SigmaValue::String(ir_pattern_to_sigma(pattern))),
        IrMatcher::NumericEq(n) => number_value(n),
        IrMatcher::BoolEq(b) => Ok(SigmaValue::Bool(*b)),
        IrMatcher::Null => Ok(SigmaValue::Null),
        other => Err(IrError::Lowering(format!(
            "cannot raise keyword matcher: {other:?}"
        ))),
    }
}

// =============================================================================
// Matchers → (modifiers, values)
// =============================================================================

/// Reconstruct the `field` modifiers and values a matcher implies. The modifiers
/// are shared across every value (Sigma detection items are homogeneous).
fn raise_matcher(matcher: &IrMatcher) -> Result<(Vec<Modifier>, Vec<SigmaValue>)> {
    match matcher {
        IrMatcher::Str {
            op,
            pattern,
            case_insensitive,
        } => {
            let mut modifiers = op_modifiers(*op);
            if !case_insensitive {
                modifiers.push(Modifier::Cased);
            }
            Ok((
                modifiers,
                vec![SigmaValue::String(ir_pattern_to_sigma(pattern))],
            ))
        }
        IrMatcher::Encoded {
            encodings,
            op,
            value,
            case_insensitive,
        } => {
            let mut modifiers: Vec<Modifier> =
                encodings.iter().map(|e| encoding_modifier(*e)).collect();
            modifiers.extend(op_modifiers(*op));
            if !case_insensitive {
                modifiers.push(Modifier::Cased);
            }
            Ok((
                modifiers,
                vec![SigmaValue::String(SigmaString::from_raw(value))],
            ))
        }
        IrMatcher::Regex {
            pattern,
            case_insensitive,
            multiline,
            dotall,
            cased,
        } => {
            let mut modifiers = vec![Modifier::Re];
            if *case_insensitive {
                modifiers.push(Modifier::IgnoreCase);
            }
            if *multiline {
                modifiers.push(Modifier::Multiline);
            }
            if *dotall {
                modifiers.push(Modifier::DotAll);
            }
            if *cased {
                modifiers.push(Modifier::Cased);
            }
            Ok((
                modifiers,
                vec![SigmaValue::String(SigmaString::from_raw(pattern))],
            ))
        }
        IrMatcher::Cidr { network } => Ok((
            vec![Modifier::Cidr],
            vec![SigmaValue::String(SigmaString::from_raw(network))],
        )),
        IrMatcher::NumericEq(n) => Ok((vec![], vec![number_value(n)?])),
        IrMatcher::NumericGt(n) => Ok((vec![Modifier::Gt], vec![number_value(n)?])),
        IrMatcher::NumericGte(n) => Ok((vec![Modifier::Gte], vec![number_value(n)?])),
        IrMatcher::NumericLt(n) => Ok((vec![Modifier::Lt], vec![number_value(n)?])),
        IrMatcher::NumericLte(n) => Ok((vec![Modifier::Lte], vec![number_value(n)?])),
        IrMatcher::Exists(expect) => Ok((vec![Modifier::Exists], vec![SigmaValue::Bool(*expect)])),
        IrMatcher::FieldRef {
            field,
            case_insensitive,
        } => {
            let mut modifiers = vec![Modifier::FieldRef];
            if !case_insensitive {
                modifiers.push(Modifier::Cased);
            }
            Ok((
                modifiers,
                vec![SigmaValue::String(SigmaString::from_raw(field))],
            ))
        }
        IrMatcher::Null => Ok((vec![], vec![SigmaValue::Null])),
        IrMatcher::BoolEq(b) => Ok((vec![], vec![SigmaValue::Bool(*b)])),
        IrMatcher::Expand {
            template,
            case_insensitive,
        } => {
            let mut modifiers = vec![Modifier::Expand];
            if !case_insensitive {
                modifiers.push(Modifier::Cased);
            }
            Ok((
                modifiers,
                vec![SigmaValue::String(SigmaString::from_raw(&expand_source(
                    template,
                )))],
            ))
        }
        IrMatcher::TimestampPart { part, inner } => {
            let mut modifiers = vec![time_modifier(*part)];
            let (inner_modifiers, values) = raise_matcher(inner)?;
            modifiers.extend(inner_modifiers);
            Ok((modifiers, values))
        }
        IrMatcher::Not(inner) => {
            let (mut modifiers, values) = raise_matcher(inner)?;
            modifiers.push(Modifier::Neq);
            Ok((modifiers, values))
        }
        IrMatcher::AnyOf(subs) => raise_value_list(subs, false),
        IrMatcher::AllOf(subs) => raise_value_list(subs, true),
    }
}

/// Collapse an `AnyOf`/`AllOf` of homogeneous leaves into one item's value list.
/// `all` appends the `|all` linking modifier (AND across values).
fn raise_value_list(subs: &[IrMatcher], all: bool) -> Result<(Vec<Modifier>, Vec<SigmaValue>)> {
    let mut shared: Option<Vec<Modifier>> = None;
    let mut values = Vec::with_capacity(subs.len());
    for sub in subs {
        let (modifiers, mut sub_values) = raise_matcher(sub)?;
        if sub_values.len() != 1 {
            return Err(IrError::Lowering(
                "cannot raise a nested value list to a single detection item".into(),
            ));
        }
        match &shared {
            None => shared = Some(modifiers),
            Some(prev) if *prev == modifiers => {}
            Some(_) => {
                return Err(IrError::Lowering(
                    "cannot raise a heterogeneous value list to a single detection item".into(),
                ));
            }
        }
        values.append(&mut sub_values);
    }
    let mut modifiers = shared.unwrap_or_default();
    if all {
        modifiers.push(Modifier::All);
    }
    Ok((modifiers, values))
}

fn op_modifiers(op: IrStrOp) -> Vec<Modifier> {
    match op {
        IrStrOp::Exact => vec![],
        IrStrOp::Contains => vec![Modifier::Contains],
        IrStrOp::StartsWith => vec![Modifier::StartsWith],
        IrStrOp::EndsWith => vec![Modifier::EndsWith],
    }
}

fn encoding_modifier(encoding: IrEncoding) -> Modifier {
    match encoding {
        IrEncoding::Wide => Modifier::Wide,
        IrEncoding::Utf16 => Modifier::Utf16,
        IrEncoding::Utf16Be => Modifier::Utf16be,
        IrEncoding::Base64 => Modifier::Base64,
        IrEncoding::Base64Offset => Modifier::Base64Offset,
        IrEncoding::Windash => Modifier::WindAsh,
    }
}

fn time_modifier(part: IrTimePart) -> Modifier {
    match part {
        IrTimePart::Minute => Modifier::Minute,
        IrTimePart::Hour => Modifier::Hour,
        IrTimePart::Day => Modifier::Day,
        IrTimePart::Week => Modifier::Week,
        IrTimePart::Month => Modifier::Month,
        IrTimePart::Year => Modifier::Year,
    }
}

fn number_value(number: &IrNumber) -> Result<SigmaValue> {
    match number {
        IrNumber::Literal(f) => {
            if f.fract() == 0.0 && *f >= i64::MIN as f64 && *f <= i64::MAX as f64 {
                Ok(SigmaValue::Integer(*f as i64))
            } else {
                Ok(SigmaValue::Float(*f))
            }
        }
        IrNumber::DynamicSourceRef { source_id, .. } => Err(IrError::Lowering(format!(
            "cannot raise a dynamic source reference (${{source.{source_id}}}) to a static value"
        ))),
    }
}

fn expand_source(template: &[IrExpandPart]) -> String {
    let mut out = String::new();
    for part in template {
        match part {
            IrExpandPart::Literal(text) => out.push_str(text),
            IrExpandPart::Placeholder(name) => {
                out.push('%');
                out.push_str(name);
                out.push('%');
            }
        }
    }
    out
}

/// Convert a `serde_json::Value` (how the HIR stores custom attributes) back
/// into a `yaml_serde::Value`. JSON is valid YAML, so re-parsing its text yields
/// the equivalent value without depending on the yaml_serde constructor surface.
fn json_to_yaml(value: &serde_json::Value) -> yaml_serde::Value {
    let text = serde_json::to_string(value).unwrap_or_else(|_| "null".to_string());
    yaml_serde::from_str(&text).unwrap_or(yaml_serde::Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LowerOptions, lower_rule};
    use rsigma_parser::parse_sigma_yaml;

    /// `parse → lower → raise → lower` must reproduce the original HIR for the
    /// given rule (the faithful round-trip through the parser AST).
    fn assert_hir_round_trips(yaml: &str) {
        let collection = parse_sigma_yaml(yaml).expect("input parses");
        let rule = &collection.rules[0];
        let hir = lower_rule(rule, &LowerOptions::default()).expect("lowers");

        let raised = raise_rule(&hir, &RaiseOptions::default()).expect("raises");
        let relowered = lower_rule(&raised, &LowerOptions::default()).expect("re-lowers");

        assert_eq!(hir, relowered, "HIR changed across raise:\n{yaml}");
    }

    #[test]
    fn round_trips_string_operators() {
        assert_hir_round_trips(
            "title: T\nlogsource:\n    product: windows\ndetection:\n    selection:\n        Image|endswith: '\\\\cmd.exe'\n        CommandLine|contains: whoami\n        User|startswith: adm\n        Path: 'C:\\\\Windows'\n    condition: selection\n",
        );
    }

    #[test]
    fn round_trips_case_sensitive_and_value_lists() {
        assert_hir_round_trips(
            "title: T\nlogsource:\n    product: windows\ndetection:\n    selection:\n        User|cased: Admin\n        Image|endswith:\n            - '\\\\a.exe'\n            - '\\\\b.exe'\n        Cmd|contains|all:\n            - foo\n            - bar\n    condition: selection\n",
        );
    }

    #[test]
    fn round_trips_typed_and_special_matchers() {
        assert_hir_round_trips(
            "title: T\nlogsource:\n    product: net\ndetection:\n    selection:\n        Port|gt: 1024\n        Ratio: 0.5\n        Enabled: true\n        Extra: null\n        Src|cidr: 10.0.0.0/8\n        Pattern|re: 'ab.*c'\n        Peer|fieldref: DestinationIp\n        Field|exists: true\n    condition: selection\n",
        );
    }

    #[test]
    fn round_trips_encodings_and_neq_and_keywords() {
        assert_hir_round_trips(
            "title: T\nlogsource:\n    product: windows\ndetection:\n    selection:\n        CommandLine|base64offset|contains: 'IEX'\n        Name|windash|contains: '-enc'\n        Status|neq: disabled\n    keywords:\n        - mimikatz\n        - 4688\n    condition: selection and keywords\n",
        );
    }

    #[test]
    fn round_trips_selector_and_anyof_selections() {
        assert_hir_round_trips(
            "title: T\nlogsource:\n    category: test\ndetection:\n    selection_a:\n        Image|endswith: '\\\\a.exe'\n    selection_b:\n        Image|endswith: '\\\\b.exe'\n    filter:\n        - User: system\n        - User: network\n    condition: 1 of selection_* and not filter\n",
        );
    }

    #[test]
    fn round_trips_through_yaml_emission() {
        // The full reverse pivot: parse → lower → raise → emit → parse → lower
        // must land on the same HIR.
        let yaml = "title: T\nlogsource:\n    product: windows\ndetection:\n    selection:\n        Image|endswith: '\\\\cmd.exe'\n        CommandLine|contains: whoami\n    condition: selection\nlevel: high\n";
        let collection = parse_sigma_yaml(yaml).unwrap();
        let hir = lower_rule(&collection.rules[0], &LowerOptions::default()).unwrap();
        let raised = raise_rule(&hir, &RaiseOptions::default()).unwrap();
        let emitted = rsigma_parser::emit_rule_yaml(&raised);
        let reparsed = parse_sigma_yaml(&emitted).expect("emitted YAML parses");
        let relowered = lower_rule(&reparsed.rules[0], &LowerOptions::default()).unwrap();
        assert_eq!(hir, relowered, "HIR changed across emit:\n{emitted}");
    }
}
