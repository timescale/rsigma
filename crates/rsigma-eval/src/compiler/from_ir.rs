//! Compile HIR (`IrRule`) into physical [`CompiledRule`] form.
//!
//! This is the second half of the IR-backed compile path:
//! `lower_rule` (rsigma-ir) → [`compile_to_compiled`] → matcher optimizer.

use std::collections::HashMap;
use std::sync::Arc;

use rsigma_ir::{
    IrCondition, IrDetection, IrDetectionItem, IrEncoding, IrExpandPart, IrMatcher, IrNumber,
    IrPattern, IrPatternPart, IrRule, IrStrOp, IrTimePart,
};
use rsigma_parser::value::{SigmaString, SpecialChar, StringPart};
use rsigma_parser::{ConditionExpr, Modifier, SigmaValue};

use crate::error::{EvalError, Result};
use crate::matcher::{CompiledMatcher, ExpandPart, TimePart};

use super::helpers::build_regex;
use super::optimizer;
use super::{
    CompiledDetection, CompiledDetectionItem, CompiledRule, ModCtx, compile_sigma_string,
    compile_string_value, compile_value,
};

/// Compile an [`IrRule`] into a physical [`CompiledRule`] ready for evaluation.
pub fn compile_to_compiled(ir: &IrRule) -> Result<CompiledRule> {
    let mut detections = HashMap::new();
    for (name, detection) in &ir.detections {
        detections.insert(name.clone(), compile_ir_detection(detection)?);
    }

    let conditions: Vec<ConditionExpr> = ir.conditions.iter().map(ir_condition_to_expr).collect();

    let include_event = ir
        .metadata
        .custom_attributes
        .get("rsigma.include_event")
        .and_then(|v| v.as_str())
        == Some("true");

    Ok(CompiledRule {
        title: ir.metadata.title.clone(),
        id: ir.metadata.id.clone(),
        level: ir.metadata.level,
        tags: ir.metadata.tags.clone(),
        logsource: ir.logsource.clone(),
        detections,
        conditions,
        include_event,
        custom_attributes: Arc::new(ir.metadata.custom_attributes.clone()),
    })
}

fn compile_ir_detection(detection: &IrDetection) -> Result<CompiledDetection> {
    match detection {
        IrDetection::AllOf(items) => {
            if items.is_empty() {
                return Err(EvalError::InvalidModifiers(
                    "AllOf detection must not be empty (vacuous truth)".into(),
                ));
            }
            let compiled: Result<Vec<_>> = items.iter().map(compile_ir_detection_item).collect();
            Ok(CompiledDetection::AllOf(compiled?))
        }
        IrDetection::AnyOf(dets) => {
            if dets.is_empty() {
                return Err(EvalError::InvalidModifiers(
                    "AnyOf detection must not be empty (would never match)".into(),
                ));
            }
            let compiled: Result<Vec<_>> = dets.iter().map(compile_ir_detection).collect();
            Ok(CompiledDetection::AnyOf(compiled?))
        }
        IrDetection::ArrayMatch {
            field,
            quantifier,
            body,
        } => Ok(CompiledDetection::ArrayMatch {
            field: field.clone(),
            quantifier: *quantifier,
            body: Box::new(compile_ir_detection(body)?),
        }),
        IrDetection::And(dets) => {
            if dets.is_empty() {
                return Err(EvalError::InvalidModifiers(
                    "And detection must not be empty".into(),
                ));
            }
            let compiled: Result<Vec<_>> = dets.iter().map(compile_ir_detection).collect();
            Ok(CompiledDetection::And(compiled?))
        }
        IrDetection::Conditional { named, condition } => {
            if named.is_empty() {
                return Err(EvalError::InvalidModifiers(
                    "Conditional detection must have at least one named sub-selection".into(),
                ));
            }
            let compiled: Result<HashMap<String, CompiledDetection>> = named
                .iter()
                .map(|(k, d)| Ok((k.clone(), compile_ir_detection(d)?)))
                .collect();
            Ok(CompiledDetection::Conditional {
                named: compiled?,
                condition: ir_condition_to_expr(condition),
            })
        }
        IrDetection::Keywords(matcher) => {
            let compiled = compile_ir_matcher(matcher)?;
            // Keywords are OR-semantics; apply AnyOf optimizer when present.
            let matcher = match compiled {
                CompiledMatcher::AnyOf(ms) => optimizer::optimize_any_of(ms),
                other => other,
            };
            Ok(CompiledDetection::Keywords(matcher))
        }
    }
}

fn compile_ir_detection_item(item: &IrDetectionItem) -> Result<CompiledDetectionItem> {
    let matcher = compile_ir_matcher(&item.matcher)?;
    let bloom_eligible =
        item.field.is_some() && crate::engine::bloom_index::is_positive_substring_matcher(&matcher);

    Ok(CompiledDetectionItem {
        field: item.field.clone(),
        matcher,
        exists: item.exists,
        bloom_eligible,
    })
}

fn compile_ir_matcher(matcher: &IrMatcher) -> Result<CompiledMatcher> {
    match matcher {
        IrMatcher::Str {
            op,
            pattern,
            case_insensitive,
        } => {
            let ctx = str_modctx(*op, *case_insensitive, &[]);
            if pattern.is_plain() {
                compile_string_value(&pattern.as_plain().unwrap_or_default(), &ctx)
            } else {
                compile_sigma_string(&sigma_from_pattern(pattern), &ctx)
            }
        }
        IrMatcher::Encoded {
            encodings,
            op,
            value,
            case_insensitive,
        } => {
            // Replay the encoding chain through the proven value compiler by
            // reconstructing the equivalent modifier context and plain value.
            let ctx = str_modctx(*op, *case_insensitive, encodings);
            compile_value(&SigmaValue::String(sigma_plain(value)), &ctx)
        }
        IrMatcher::Regex {
            pattern,
            case_insensitive,
            multiline,
            dotall,
            // `cased` only informs convert's operator choice; eval regex case
            // sensitivity is the `|i` flag (`case_insensitive`).
            cased: _,
        } => Ok(CompiledMatcher::Regex(build_regex(
            pattern,
            *case_insensitive,
            *multiline,
            *dotall,
        )?)),
        IrMatcher::Cidr { network } => {
            let net: ipnet::IpNet = network.parse().map_err(EvalError::InvalidCidr)?;
            Ok(CompiledMatcher::Cidr(net))
        }
        IrMatcher::NumericEq(n) => Ok(CompiledMatcher::NumericEq(ir_number_literal(n)?)),
        IrMatcher::NumericGt(n) => Ok(CompiledMatcher::NumericGt(ir_number_literal(n)?)),
        IrMatcher::NumericGte(n) => Ok(CompiledMatcher::NumericGte(ir_number_literal(n)?)),
        IrMatcher::NumericLt(n) => Ok(CompiledMatcher::NumericLt(ir_number_literal(n)?)),
        IrMatcher::NumericLte(n) => Ok(CompiledMatcher::NumericLte(ir_number_literal(n)?)),
        IrMatcher::Exists(b) => Ok(CompiledMatcher::Exists(*b)),
        IrMatcher::FieldRef {
            field,
            case_insensitive,
        } => Ok(CompiledMatcher::FieldRef {
            field: field.clone(),
            case_insensitive: *case_insensitive,
        }),
        IrMatcher::Null => Ok(CompiledMatcher::Null),
        IrMatcher::BoolEq(b) => Ok(CompiledMatcher::BoolEq(*b)),
        IrMatcher::Expand {
            template,
            case_insensitive,
        } => Ok(CompiledMatcher::Expand {
            template: template.iter().map(ir_expand_part).collect(),
            case_insensitive: *case_insensitive,
        }),
        IrMatcher::TimestampPart { part, inner } => Ok(CompiledMatcher::TimestampPart {
            part: ir_time_part(*part),
            inner: Box::new(compile_ir_matcher(inner)?),
        }),
        IrMatcher::Not(inner) => Ok(CompiledMatcher::Not(Box::new(compile_ir_matcher(inner)?))),
        IrMatcher::AnyOf(ms) => {
            let compiled: Result<Vec<_>> = ms.iter().map(compile_ir_matcher).collect();
            Ok(optimizer::optimize_any_of(compiled?))
        }
        IrMatcher::AllOf(ms) => {
            let compiled: Result<Vec<_>> = ms.iter().map(compile_ir_matcher).collect();
            Ok(CompiledMatcher::AllOf(compiled?))
        }
    }
}

/// Reconstruct the modifier context for a string/encoded matcher so the proven
/// value compilers produce byte-identical `CompiledMatcher`s.
fn str_modctx(op: IrStrOp, case_insensitive: bool, encodings: &[IrEncoding]) -> ModCtx {
    let mut mods: Vec<Modifier> = Vec::new();
    match op {
        IrStrOp::Exact => {}
        IrStrOp::Contains => mods.push(Modifier::Contains),
        IrStrOp::StartsWith => mods.push(Modifier::StartsWith),
        IrStrOp::EndsWith => mods.push(Modifier::EndsWith),
    }
    if !case_insensitive {
        mods.push(Modifier::Cased);
    }
    for e in encodings {
        mods.push(match e {
            IrEncoding::Wide => Modifier::Wide,
            IrEncoding::Utf16 => Modifier::Utf16,
            IrEncoding::Utf16Be => Modifier::Utf16be,
            IrEncoding::Base64 => Modifier::Base64,
            IrEncoding::Base64Offset => Modifier::Base64Offset,
            IrEncoding::Windash => Modifier::WindAsh,
        });
    }
    ModCtx::from_modifiers(&mods)
}

fn sigma_plain(s: &str) -> SigmaString {
    SigmaString {
        parts: vec![StringPart::Plain(s.to_string())],
        original: s.to_string(),
    }
}

fn sigma_from_pattern(pattern: &IrPattern) -> SigmaString {
    let mut original = String::new();
    let parts = pattern
        .parts
        .iter()
        .map(|p| match p {
            IrPatternPart::Literal(t) => {
                original.push_str(t);
                StringPart::Plain(t.clone())
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

fn ir_condition_to_expr(cond: &IrCondition) -> ConditionExpr {
    match cond {
        IrCondition::Detection(name) => ConditionExpr::Identifier(name.clone()),
        IrCondition::And(exprs) => {
            ConditionExpr::And(exprs.iter().map(ir_condition_to_expr).collect())
        }
        IrCondition::Or(exprs) => {
            ConditionExpr::Or(exprs.iter().map(ir_condition_to_expr).collect())
        }
        IrCondition::Not(inner) => ConditionExpr::Not(Box::new(ir_condition_to_expr(inner))),
        IrCondition::Selector {
            quantifier,
            pattern,
        } => ConditionExpr::Selector {
            quantifier: quantifier.clone(),
            pattern: pattern.clone(),
        },
    }
}

fn ir_number_literal(n: &IrNumber) -> Result<f64> {
    match n {
        IrNumber::Literal(v) => Ok(*v),
        IrNumber::DynamicSourceRef { source_id, .. } => Err(EvalError::IncompatibleValue(format!(
            "unresolved dynamic source reference '{source_id}' cannot be compiled; \
             specialize the IR first"
        ))),
    }
}

fn ir_expand_part(part: &IrExpandPart) -> ExpandPart {
    match part {
        IrExpandPart::Literal(s) => ExpandPart::Literal(s.clone()),
        IrExpandPart::Placeholder(s) => ExpandPart::Placeholder(s.clone()),
    }
}

fn ir_time_part(part: IrTimePart) -> TimePart {
    match part {
        IrTimePart::Minute => TimePart::Minute,
        IrTimePart::Hour => TimePart::Hour,
        IrTimePart::Day => TimePart::Day,
        IrTimePart::Week => TimePart::Week,
        IrTimePart::Month => TimePart::Month,
        IrTimePart::Year => TimePart::Year,
    }
}
